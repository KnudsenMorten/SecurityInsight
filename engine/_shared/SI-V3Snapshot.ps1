#Requires -Version 5.1
<#
    SI v3 -- READING THE CURRENT v3 SNAPSHOT. One place, because the trap is one trap.

    🪤 FINDING #83, AND IT HAS NOW BITTEN THREE TIMES IN THREE DIFFERENT FILES.
    `arg_max` THEN filter is NOT the same query as filter THEN `arg_max`. Both editions write the
    profile tables; v2.2 emits no `SI_` columns at all. So `summarize max(CollectionTime)` over the
    raw table frequently selects a v2.2 snapshot, every v3 column reads empty, and the run reports a
    smaller estate with no error anywhere. **Measured on the same data: 40 assets vs 238.**
    It bit the CMDB driver, then the asset-properties engine. A connector built the naive way syncs 40
    of 238 assets and looks perfectly healthy.

    🔑 WHY THIS FILE EXISTS RATHER THAN A FOURTH COPY OF THE QUERY. The correlation engine, the
    asset-properties add-on and the CMDB connector all ask the SAME question -- "give me the current
    v3 snapshot, with the identity columns" -- and each answering it privately is exactly how
    SI-AssetIdentity.ps1's own header describes the identity mess it was created to end: three files
    independently answering one question and disagreeing. The clause ORDER is the fact being shared;
    what each caller projects is its own business.

    🔒 IT ADDS NOTHING TO THE PRODUCTION PATH. This is a new file in engine/_shared/; the profilers and
    Risk Analysis dot-source SI-AssetIdentity.ps1 and are untouched by it. Nothing here runs unless an
    engine asks for a snapshot.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }

function Get-SIV3SnapshotKql {
    <#
        The current v3 snapshot of one profile table, projecting the columns the caller names.

          -TableName  SI_Endpoint_Profile_CL | SI_Identity_Profile_CL | SI_Azure_Profile_CL
          -Column     extra columns to project, each read through column_ifexists
          -RowLimit   diagnostics only

        `SI_AssetId` and `SI_AssetName` are always projected -- they are the identity contract, and a
        caller that did not ask for them still needs them to be able to join anything.

        🔴 THE `where` IS INSIDE THE `let`, SO IT PROVABLY PRECEDES THE `summarize`. Writing it as two
        statements would work equally well and would be one edit away from being reordered by someone
        who did not know why. The shape encodes the rule.

        🪤 EVERY COLUMN GOES THROUGH `column_ifexists`. The four profile schemas do NOT carry the same
        columns -- identity has no AzureResourceId, public-ip has almost none of them -- and a plain
        `project` against a missing column fails the WHOLE query rather than degrading to "this engine
        does not know that". A dead run and an empty column are very different failures.

        📌 The v3 test is `isnotempty(SI_AssetId)` -- the thing v2.2 does not emit, so its presence IS
        a version test.
        ⚠️ **The ORIGINAL reason given here was "because the four PROFILE tables carry no version
        stamp", and that is no longer true.** V3-6 added the stamp, and from 2026-08-31 it carries an
        edition marker (`2.2.460+v3`), so a `SolutionVersion endswith "+v3"` filter is now available
        here too. `SI_AssetId` is KEPT deliberately: it is the identity contract, it is proven across
        every v3 engine, and it works on rows written before the marker existed -- which a version
        filter does not. Two correct tests are fine; a stale justification for one of them is not.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TableName,
        [Parameter()][string[]]$Column = @(),
        [Parameter()][int]$RowLimit = 0,
        # Lower-case the projected extra columns. Identifier joins are case-insensitive in practice
        # (an MDE id is hex, an ARM path is case-preserving but case-insensitive), and normalising in
        # the query beats every caller remembering to.
        [Parameter()][switch]$LowerCaseColumns
    )

    $proj = New-Object System.Collections.ArrayList
    [void]$proj.Add('    SI_AssetId   = tostring(column_ifexists("SI_AssetId", ""))')
    [void]$proj.Add('    SI_AssetName = tostring(column_ifexists("SI_AssetName", ""))')
    foreach ($c in @($Column)) {
        if ([string]::IsNullOrWhiteSpace($c)) { continue }
        if ($c -eq 'SI_AssetId' -or $c -eq 'SI_AssetName') { continue }
        if ($LowerCaseColumns) {
            [void]$proj.Add(('    {0} = tolower(tostring(column_ifexists("{0}", "")))' -f $c))
        } else {
            [void]$proj.Add(('    {0} = tostring(column_ifexists("{0}", ""))' -f $c))
        }
    }

    $kql = @(
        ('let v3 = {0} | where isnotempty(tostring(column_ifexists("SI_AssetId", "")));' -f $TableName)
        'let snap = toscalar(v3 | summarize max(CollectionTime));'
        'v3'
        '| where CollectionTime == snap'
        '| project'
        ($proj.ToArray() -join ",`n")
    )
    if ($RowLimit -gt 0) { $kql += ('| take {0}' -f $RowLimit) }
    ($kql -join "`n")
}

function Get-SIV3ObjectMapKql {
    <#
        `SI_CorrelationId` and `SI_IdSource` per `SI_AssetId`, from the correlation map.

        📌 This join is the whole of finding #89's first half: `SI_CorrelationId` is on NO profile
        table. It lives only in `SI_ObjectMap_CL`, keyed on `SI_AssetId`. A connector that expects to
        find it on the row skips 100% of assets while reporting a clean run -- measured, 144 of 144
        Skipped, which reads exactly like a healthy conservative connector.

        🔴 `SI_IdSource` IS NOT OPTIONAL. It states whether the id is `ledger` (minted once and stored,
        durable for the life of the asset) or `derived-provisional` (today's seed, which MOVES when
        group membership changes). `SI-ObjectLedgerStore.ps1` puts the consequence plainly: *"a
        connector is already forbidden from creating CIs from those."* Dropping this column is how that
        rule stops being enforceable.

        Both values are taken in ONE `summarize`. The map emits one row per
        (correlation id, member, identifier type), so every row for a given `SI_AssetId` carries the
        same pair -- taking them in two `take_any` calls would permit a combination that never
        co-occurred on any row.
    #>
    [CmdletBinding()]
    param([Parameter()][int]$RowLimit = 0)
    $kql = @(
        'let snap = toscalar(SI_ObjectMap_CL | summarize max(CollectionTime));'
        'SI_ObjectMap_CL'
        '| where CollectionTime == snap'
        '| project SI_AssetId = tostring(column_ifexists("SI_AssetId", "")),'
        '          SI_CorrelationId = tostring(column_ifexists("SI_CorrelationId", "")),'
        '          SI_IdSource = tostring(column_ifexists("SI_IdSource", ""))'
        '| where isnotempty(SI_AssetId) and isnotempty(SI_CorrelationId)'
        '| summarize SI_CorrelationId = take_any(SI_CorrelationId), SI_IdSource = take_any(SI_IdSource) by SI_AssetId'
    )
    if ($RowLimit -gt 0) { $kql += ('| take {0}' -f $RowLimit) }
    ($kql -join "`n")
}

# =====================================================================================================================
#  UPLINK-FIX (customer G 2026-10-07): AN EMPTY CORRELATION MAP ON A FIRST RUN IS "NOT YET", NOT A REFUSAL
# =====================================================================================================================
# A new install's first flow: asset correlation writes SI_ObjectMap_CL for the FIRST time, and a brand-new Log Analytics
# table answers its first rows minutes later. The CMDB connector (16:34Z, 35 s after correlation ended) and the
# vulnerability close-loop (16:35Z) read it empty and REFUSED with a critical guard: two fix requests and a support
# ticket for a state that is expected and fixes itself. The rule now:
#   * the map is empty, it has NEVER had a row, and asset correlation ended within the last hour -> wait for it (poll);
#   * still empty, never had a row                              -> 'pending': nothing written, a WARNING, no refusal;
#   * empty, but it HAD rows (or that cannot be told)           -> 'missing': the refusal stays (the guard's real case).
function Get-SIV3ObjectMapEverKql {
    <# Has the correlation map EVER had a row (the whole retention)? One row, column n. #>
    'SI_ObjectMap_CL | take 1 | count | project n = Count'
}

function Get-SIV3CorrelationRecentKql {
    <# Did asset correlation (the engine or the flow's step) end well in the last -Minutes? One row, column n. #>
    param([int]$Minutes = 60)
    @(
        ('SI_RunHealth_CL | where TimeGenerated > ago({0}m)' -f $Minutes)
        "| where Phase == 'End' and ExitReason in ('success', 'success-partial')"
        # the correlation engine under its job name, its short name, or the flow's step of it
        "| where Engine endswith 'correlation'"
        '| count | project n = Count'
    ) -join "`n"
}

function Resolve-SIV3CorrelationMap {
    <#
        The correlation map for a connector, with the first-run rule above. Returns @{ State = ready | pending | missing;
        Rows; Reason; WaitedSeconds }.
          -Read   { } -> the map rows (the caller's own read; a table that does not exist yet reads as empty)
          -Count  { param($Kql, $Table) } -> rows with a column n (a table that does not exist yet reads as empty)
          -WaitSeconds / -PollSeconds   how long to wait for a map that correlation has just written (default 15 / 1 min)
          -Sleep  { param($Seconds) } (tests)   -Log { param($Level, $Message) }
        A count that cannot be read is NOT taken as "never had a row": the safe direction is 'missing' (the refusal).
    #>
    param([Parameter(Mandatory)][scriptblock]$Read, [Parameter(Mandatory)][scriptblock]$Count,
          [int]$WaitSeconds = 900, [int]$PollSeconds = 60, [scriptblock]$Sleep, [scriptblock]$Log)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Log) { $Log = { param($l, $m) } }
    $n = { param($kql, $table) try { $r = @(& $Count $kql $table | ForEach-Object { $_ } | Where-Object { $_ })[0]; if ($r) { [long]$r.n } else { 0L } } catch { -1L } }
    $rows = @(& $Read | ForEach-Object { $_ } | Where-Object { $_ })
    if ($rows.Count) { return [pscustomobject]@{ State = 'ready'; Rows = $rows; Reason = ''; WaitedSeconds = 0 } }
    $ever = & $n (Get-SIV3ObjectMapEverKql) 'SI_ObjectMap_CL'
    if ($ever -ne 0) {
        return [pscustomobject]@{ State = 'missing'; Rows = @(); WaitedSeconds = 0
            Reason = $(if ($ever -lt 0) { 'the correlation map (SI_ObjectMap_CL) is empty, and whether it ever had results could not be read' } else { 'the correlation map (SI_ObjectMap_CL) is empty, although it had results before' }) }
    }
    $waited = 0
    $recent = & $n (Get-SIV3CorrelationRecentKql) 'SI_RunHealth_CL'
    if ($recent -gt 0 -and $WaitSeconds -gt 0) {
        & $Log 'INFO' ('the correlation map (SI_ObjectMap_CL) has no rows yet, and asset correlation has just written its first results -- waiting up to {0} min for Log Analytics to answer them' -f [Math]::Ceiling($WaitSeconds / 60))
        while ($waited -lt $WaitSeconds) {
            $step = [Math]::Max(1, [Math]::Min($PollSeconds, $WaitSeconds - $waited))
            & $Sleep $step; $waited += $step
            $rows = @(& $Read | ForEach-Object { $_ } | Where-Object { $_ })
            if ($rows.Count) {
                & $Log 'OK' ('the correlation map answered after {0} s ({1} asset(s))' -f $waited, $rows.Count)
                return [pscustomobject]@{ State = 'ready'; Rows = $rows; Reason = ''; WaitedSeconds = $waited }
            }
        }
    }
    [pscustomobject]@{ State = 'pending'; Rows = @(); WaitedSeconds = $waited
        Reason = $(if ($recent -gt 0) { ('the correlation map (SI_ObjectMap_CL) has no results yet: asset correlation wrote its first ones, and Log Analytics did not answer them within {0} min (a new install) -- nothing was written; the next run uses them' -f [Math]::Ceiling($waited / 60)) }
                   else { 'the correlation map (SI_ObjectMap_CL) has no results yet (asset correlation has not run on this install) -- nothing was written; the next run after asset correlation uses them' }) }
}

function Get-SIV3AssetPropertiesKql {
    <#
        The current snapshot of `SI_AssetProperties_CL` -- the optional wide payload (3.6b).

        🔒 THE CMDB CONNECTOR MUST TOLERATE THIS TABLE NOT EXISTING. The add-on is opt-in, and
        scenario 1 does not use it at all. A caller runs this inside its own try/catch and treats a
        failure as "no wide payloads", never as a failed run -- otherwise enabling a scenario-1
        connector would require an add-on that scenario 1 has no use for.

        📌 One row per (asset, source system) by design, so a server that is both an MDE machine and an
        ARM resource contributes two. The caller picks which source's vocabulary to project from,
        rather than the collector deciding it here by overwriting.
    #>
    [CmdletBinding()]
    param([Parameter()][int]$RowLimit = 0)
    # #412 ONE PULL PER SOURCE: each profiler (endpoint / identity / azure) publishes its own sources with its OWN
    # CollectionTime, so the current snapshot is the newest one PER (profiler, source) -- "the table's newest
    # CollectionTime" would be the last profiler's sources only.
    $kql = @(
        'let src = SI_AssetProperties_CL | extend _key = strcat(tostring(column_ifexists("Engine", "")), "|", tostring(column_ifexists("SourceSystem", "")));'
        'src'
        '| join kind=inner (src | summarize _snap = max(CollectionTime) by _key) on _key'
        '| where CollectionTime == _snap'
        '| project SI_AssetId = tostring(column_ifexists("SI_AssetId", "")),'
        '          SourceSystem = tostring(column_ifexists("SourceSystem", "")),'
        '          Properties = tostring(column_ifexists("Properties", "")),'
        '          PropertiesDropped = tobool(column_ifexists("PropertiesDropped", false))'
        '| where isnotempty(SI_AssetId)'
        # 🔴 A row whose payload was replaced by the oversize marker carries NO usable metadata, and
        # projecting it would fill CI columns from a marker object. Excluded here so no consumer has
        # to remember -- the asset then simply gets the narrow set, which is the correct outcome.
        '| where PropertiesDropped != true'
    )
    if ($RowLimit -gt 0) { $kql += ('| take {0}' -f $RowLimit) }
    ($kql -join "`n")
}

# ---------------------------------------------------------------------------------------------------
# Workspace ARM id -> the customer (workspace) GUID the query API wants.
#
# 🔒 A THIRD NAME FOR THE SAME LOOKUP, AND THAT IS DELIBERATE. asset-correlation and asset-properties
# each keep a private copy under their own name, because a library that redefines a function another
# engine already loaded changes that engine's behaviour by being present -- one fact, two spellings is
# a trap in code as much as in data, and the cure here is distinct names rather than a shared one that
# silently shadows. New engines use THIS one; the existing two are left alone precisely because they
# work and sit near production paths.
# ---------------------------------------------------------------------------------------------------
$script:_SIV3WsCache = @{}

function Resolve-SIV3WorkspaceId {
    param([string]$WorkspaceResourceId = [string]$global:SI_WorkspaceResourceId)

    if ($script:_SIV3WsCache.ContainsKey($WorkspaceResourceId)) { return $script:_SIV3WsCache[$WorkspaceResourceId] }

    if ($WorkspaceResourceId -notmatch '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[Mm]icrosoft\.[Oo]perational[Ii]nsights/workspaces/([^/]+)') {
        throw "SI v3: invalid WorkspaceResourceId -- $WorkspaceResourceId"
    }
    $subId = $matches[1]; $rgName = $matches[2]; $wsName = $matches[3]

    # Restore the caller's subscription afterwards. Az context on this machine is shared state, and
    # leaving it moved is how a later step deploys to the wrong subscription -- which has already
    # happened here in four tools at once.
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

    $script:_SIV3WsCache[$WorkspaceResourceId] = $custId
    $custId
}
