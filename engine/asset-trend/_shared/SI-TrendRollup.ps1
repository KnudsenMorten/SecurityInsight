#Requires -Version 5.1
<#
    SI v3 Phase 7 -- LONG-TERM TREND, and the calendar-bucketed rate views.

    DESIGN: docs/REQUIREMENTS.md §60.4b (a narrow table, not a second store) and §47.5c (rate over
    time -- "closed per week").

    🔑 PHASE 7 IS NOT A DASHBOARD PROGRAMME. §47.5c checked before building and found the dashboards,
    the score timeline, TopMovers, PeriodComparison, SnapshotDiff's Closed/ClosedCount and AgingAnalysis
    all ALREADY WRITTEN. Exactly two things were missing, and this file is both:

      1. §60.4b  Trend needs HISTORY, and the wide profile tables keep ~30 days. The answer is not a
                 second store -- it is a second TABLE in the store the data already lives in. A narrow
                 daily rollup, ingested through the DCR path SI already uses, with extended retention on
                 THAT TABLE ONLY. Multi-year trend paying per-GB-month on kilobytes/day instead of on
                 174 columns. Trend does not need rows, it needs AGGREGATES.
      2. §47.5c  "Per week" appears nowhere in the product except email scheduling. There is no
                 rate-over-time bucketing at all.

    🔴 AND THE SECOND ONE IS NOT `bin(TimeGenerated, 7d)`. SI's data model is SNAPSHOTS AT IRREGULAR
    INTERVALS -- nightly runs get missed, Summary and Detailed run separately, and a week may hold five
    snapshots or none. Summing snapshot-to-snapshot diffs per week DOUBLE-COUNTS FLAPPING: a finding
    that closes Tuesday, reopens Wednesday and closes Friday contributes TWO closures to a summed view
    while the estate ended the week with ONE thing closed.
    ✅ The correct definition is a per-week SET DIFFERENCE -- closed-in-week = present in the FIRST
    snapshot of the week, absent from the LAST. That is a different computation from summing diffs, and
    it is the one that matches what a CIO thinks the number means.

    NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12).
#>

$script:SITrendTable = 'SI_Trend'
$script:SITrendDcr   = 'dcr-si-trend'

# 🔒 SAME SCOPE ALWAYS, OR THE TREND MEASURES ITSELF (operator, 2026-08-31:
# *"same scope always so we can track progress"* / *"this la has both v3 and v2.2 runs"*).
#
# 🔴 One workspace carries BOTH editions, and they run different report sets. A comparison that
# spans them measures WHICH EDITION RAN, not what changed in the estate -- the first live weekly
# read did exactly that and reported ~1,250-1,550 findings opened per week on an estate of 593.
# So every trend query pins the edition, and a snapshot from the other edition is simply not in
# the series. A week that then has no snapshot renders as a GAP, which is the honest outcome:
# nothing was measured on this scope that week.
#
# 📌 The marker is a SUFFIX on SolutionVersion, not a VERSION bump -- the VERSION file is the
# customer-sync contract and must not move for v3 work. See Invoke-RiskAnalysis.ps1's edition block.
# 🪤 Historical rows written before the marker existed carry no suffix and are therefore EXCLUDED.
# That is deliberate: they are genuinely of unknown edition, and guessing is what produced the
# impossible numbers. Clean history accumulates from the first marked run onward.
$script:SITrendEditionFilter = '| where tostring(column_ifexists("SolutionVersion", "")) endswith "+v3"'
function Get-SITrendEditionFilter { $script:SITrendEditionFilter }

# 🔒 THE RETENTION THIS TABLE EXISTS FOR. §60.4b's whole argument is per-table retention: the wide
# profile tables stay at the workspace default and this one is kept for years, because it is narrow
# enough that retention stops being the expensive question. Declared here so the number is reviewable
# rather than buried in whoever provisioned the workspace.
#
# 🔒 OPERATOR DECISION 2026-08-31: ONE YEAR, NOT SEVEN. *"i dont want to save longer"*.
# The design argued for multi-year because a narrow table makes retention cheap -- but "cheap" is not
# the same as "wanted", and storage the customer did not ask for is still storage they pay for.
# 365 days still outlives the profile tables comfortably (the internal workspace defaults to 90) and
# covers the full year-over-year comparison the trend view is actually for.
#
# 🪤 THIS READ 2555 (7 x 365) BEFORE THAT, AND AZURE REFUSES THAT VALUE OUTRIGHT.
#   InvalidParameter -- "The value beyond two years is restricted to full years. Allowed values are:
#   [4-730], 1095, 1460, 1826, 2191, 2556, 2922, 3288, 3653, 4018, 4383"
# The engine printed that number to the customer as an instruction on every run, so the instruction
# could not be followed. It was declared, reviewed, and never once executed -- the same shape as every
# declared-but-never-wired defect here, except this one lived in customer-facing output.
# 🔑 KEEP BOTH SETTINGS EVEN THOUGH THEY ARE NOW EQUAL. Interactive retention caps at 730 days and any
# excess becomes long-term (archive), readable only via a search job. At 365 there is no archive tier
# at all -- everything stays directly queryable -- but the command still takes both parameters, and a
# future change to either number has to stay inside that rule.
$script:SITrendRetentionDays            = 365  # total, verified applied live
$script:SITrendInteractiveRetentionDays = 365  # all of it stays interactively queryable

function Get-SITrendTableName { $script:SITrendTable }
function Get-SITrendRetentionDays { $script:SITrendRetentionDays }
function Get-SITrendInteractiveRetentionDays { $script:SITrendInteractiveRetentionDays }

# Azure access (Set-SITrendTableRetention): plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function Get-SITrendRetentionPlan {
    <#
        PURE. What to do with the trend table's retention, from what the table has now.
        Never LOWERS a value: a customer who already keeps the table longer keeps that. Returns
        @{ Action = 'keep' | 'set'; RetentionInDays; TotalRetentionInDays }.
    #>
    param([int]$CurrentRetentionInDays = 0, [int]$CurrentTotalRetentionInDays = 0,
          [int]$WantedRetentionInDays = (Get-SITrendInteractiveRetentionDays), [int]$WantedTotalRetentionInDays = (Get-SITrendRetentionDays))
    $ret   = [Math]::Max($CurrentRetentionInDays, $WantedRetentionInDays)
    $total = [Math]::Max([Math]::Max($CurrentTotalRetentionInDays, $WantedTotalRetentionInDays), $ret)
    $action = if ($ret -eq $CurrentRetentionInDays -and $total -eq $CurrentTotalRetentionInDays) { 'keep' } else { 'set' }
    @{ Action = $action; RetentionInDays = $ret; TotalRetentionInDays = $total }
}

function Set-SITrendTableRetention {
    <#
        Sets the trend table's retention in the workspace when this identity has the right to; the table's whole
        purpose is to outlive the profile tables, and it does not inherit that by itself. Until now the run printed
        a command for the customer to run by hand. Never throws and never fails the run: returns
        @{ Outcome = 'set' | 'kept' | 'failed'; RetentionInDays; TotalRetentionInDays; Reason }.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$TableName)
    $t = ($TableName -replace '_CL$', '') + '_CL'
    $path = ('{0}/tables/{1}?api-version=2022-10-01' -f $WorkspaceResourceId.TrimEnd('/'), $t)
    try {
        $get = Invoke-SIAzRestMethod -Path $path -Method GET -ErrorAction Stop
        if (-not $get -or [int]$get.StatusCode -ne 200) {
            return @{ Outcome = 'failed'; Reason = ('the table could not be read (HTTP {0})' -f $(if ($get) { [int]$get.StatusCode } else { 0 })) }
        }
        $p = ($get.Content | ConvertFrom-Json -ErrorAction Stop).properties
        $curRet   = 0; if ($null -ne $p.retentionInDays)      { $curRet   = [int]$p.retentionInDays }
        $curTotal = 0; if ($null -ne $p.totalRetentionInDays) { $curTotal = [int]$p.totalRetentionInDays }
        $plan = Get-SITrendRetentionPlan -CurrentRetentionInDays $curRet -CurrentTotalRetentionInDays $curTotal
        if ($plan.Action -eq 'keep') {
            return @{ Outcome = 'kept'; RetentionInDays = $curRet; TotalRetentionInDays = $curTotal; Reason = 'already at or above the intended retention' }
        }
        $body = @{ properties = @{ retentionInDays = $plan.RetentionInDays; totalRetentionInDays = $plan.TotalRetentionInDays } } | ConvertTo-Json -Depth 4 -Compress
        $set = Invoke-SIAzRestMethod -Path $path -Method PATCH -Payload $body -ErrorAction Stop
        if ($set -and [int]$set.StatusCode -ge 200 -and [int]$set.StatusCode -lt 300) {
            return @{ Outcome = 'set'; RetentionInDays = $plan.RetentionInDays; TotalRetentionInDays = $plan.TotalRetentionInDays; Reason = '' }
        }
        return @{ Outcome = 'failed'; Reason = ('the change was refused (HTTP {0}) -- this identity needs write access to the workspace' -f $(if ($set) { [int]$set.StatusCode } else { 0 })) }
    } catch {
        return @{ Outcome = 'failed'; Reason = $_.Exception.Message }
    }
}

function Get-SITrendRollupKql {
    <#
        ONE DAY'S SNAPSHOT, from the RA Summary (or Detailed) table -- the rows the rollup is computed from.

        🔑 AGGREGATES, NOT ROWS -- IN THE TABLE THIS FEEDS. The whole point of §60.4b is that the trend
        table holds numbers small enough to keep for years: one row per (day, dimension, value), a
        long/narrow shape, so a new dimension is new ROWS, never a schema change and never a migration
        on ~30 customers. The aggregation itself is `ConvertTo-SITrendRollup`.

        🔴 #303 -- WHY THE QUERY RETURNS THE SNAPSHOT AND NOT THE AGGREGATE. "Assets" was
        `dcount(ConfigurationId)`, which counts distinct FINDING TYPES (every CVE finding carries the id
        `CVE`), not assets -- the `SI_AssetId` / `AssetId` / `ConfigurationId` family again (#83, #96, #97).
        At the Summary grain a row aggregates N assets and its scalar `AssetId` is one representative
        (#97), so the asset set of a row is its `ImpactedAssetIds` list, falling back to the scalar only
        where a row carries no list. The union per dimension is counted in PowerShell, so it is exact and
        proven offline on a fixture (SIv3-TrendRollup.Tests.ps1).

        🪤 The snapshot is chosen AFTER the edition filter, never before -- finding #83, which has bitten
        in four places. Both editions write these tables and v2.2 emits no `SI_` columns.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$TableName = 'SI_RiskAnalysis_Summary_CL',
        [Parameter()][int]$LookbackDays = 1
    )

    @"
let src = $TableName | where TimeGenerated > ago(${LookbackDays}d)
$($script:SITrendEditionFilter);
let snap = toscalar(src | summarize max(CollectionTime));
let cur = src | where CollectionTime == snap;
cur
| project SecuritySeverity = tostring(column_ifexists("SecuritySeverity", "")),
          CriticalityTier  = tostring(column_ifexists("CriticalityTier", "")),
          SecurityDomain   = tostring(column_ifexists("SecurityDomain", "")),
          SI_ExemptionId   = tostring(column_ifexists("SI_ExemptionId", "")),
          RiskScoreTotal   = todouble(column_ifexists("RiskScoreTotal", 0.0)),
          ImpactedAssetIds = tostring(column_ifexists("ImpactedAssetIds", "")),
          AssetId          = tostring(column_ifexists("AssetId", "")),
          SI_AssetId       = tostring(column_ifexists("SI_AssetId", ""))
"@
}

function Get-SITrendRowAssetIds {
    <#
        #303 -- the ASSETS one Risk Analysis row stands for. A Summary row aggregates every asset a finding
        hits, so its asset set is `ImpactedAssetIds` (a JSON array; a one-element list can arrive as a
        bare string -- #82). Only a row with no list at all falls back to its scalar `AssetId`, then
        `SI_AssetId` (a Detailed row is one asset). `ConfigurationId` is the FINDING, never the asset.
    #>
    param([Parameter(Mandatory)]$Row)
    $ids = New-Object System.Collections.Generic.List[string]
    $p = $Row.PSObject.Properties['ImpactedAssetIds']
    if ($p -and $null -ne $p.Value) {
        if ($p.Value -is [string]) {
            $raw = $p.Value.Trim()
            if ($raw.StartsWith('[')) {
                try {
                    $parsed = ConvertFrom-Json -InputObject $raw -ErrorAction Stop  # PS 5.1 emits a JSON array as ONE object: enumerate the variable
                    foreach ($v in @($parsed)) { $s = ([string]$v).Trim(); if ($s) { [void]$ids.Add($s) } }
                } catch { }
            } elseif ($raw) {
                $s = $raw.Trim('"').Trim(); if ($s) { [void]$ids.Add($s) }
            }
        } else {
            foreach ($v in @($p.Value)) { $s = ([string]$v).Trim(); if ($s) { [void]$ids.Add($s) } }
        }
    }
    if ($ids.Count -eq 0) {
        foreach ($n in 'AssetId', 'SI_AssetId') {
            $q = $Row.PSObject.Properties[$n]
            if ($q -and $null -ne $q.Value -and ([string]$q.Value).Trim()) { [void]$ids.Add(([string]$q.Value).Trim()); break }
        }
    }
    $ids.ToArray()
}

function ConvertTo-SITrendDimensionValue {
    <#
        One dimension value (severity / tier / domain) as text, or '' when the row has none. Log Analytics returns an
        EMPTY dynamic value as the text "{}" (or "[]", "null"), while the rows Risk Analysis passes in memory carry the
        empty object itself, which reads as ''. The scheduled trend job therefore added a tier value "{}" (3 findings)
        that Risk Analysis' own trend row did not. Both paths now read an empty value as empty.
    #>
    param([AllowNull()]$Value)
    $emptyText = @('', '{}', '[]', 'null', '@{}')
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) {
        if ($emptyText -contains $Value.Trim()) { return '' }
        return $Value
    }
    $base = if ($Value -is [System.Management.Automation.PSObject]) { $Value.PSObject.BaseObject } else { $Value }
    if ($base -is [System.Collections.IDictionary]) { if ($base.Count -eq 0) { return '' } }
    elseif ($base -is [System.Management.Automation.PSCustomObject]) { if (@($Value.PSObject.Properties).Count -eq 0) { return '' } }
    elseif ($base -is [System.Collections.IEnumerable]) {
        # an array / list: empty when no element holds a value
        $any = $false
        foreach ($e in $base) { if ((ConvertTo-SITrendDimensionValue $e) -ne '') { $any = $true; break } }
        if (-not $any) { return '' }
    }
    $s = [string]$Value
    if ($emptyText -contains $s.Trim()) { return '' }
    $s
}

function ConvertTo-SITrendRollup {
    <#
        The day's aggregate, one row per (Dimension, DimensionValue): global / severity / tier / domain,
        and #264's "<dimension>-counted" twin of each over the rows WITHOUT an exemption mark
        (SI_ExemptionId) -- new ROWS, never a schema change. A row with an empty dimension value adds
        nothing to that dimension.

        Findings   = the snapshot's rows in the group.
        Assets     = DISTINCT ASSETS those rows hit (#303) -- the union of each row's asset ids, never the
                     number of finding types.
        ScoreTotal = the sum of RiskScoreTotal.
    #>
    param([Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$Rows)
    $state = New-SITrendRollupState
    Add-SITrendRollupRows -State $state -Rows $Rows
    Complete-SITrendRollup -State $state
}

function New-SITrendRollupState {
    <# #639 lane 4: the rollup built a PART at a time (Add-SITrendRollupRows, then Complete-SITrendRollup) -- the snapshot's
       rows are never all held; what is kept is one entry per (dimension, value) with its distinct asset ids. #>
    @{ Groups = @{}; Keys = (New-Object System.Collections.Generic.List[string]) }
}

function Add-SITrendRollupRows {
    <# The rows of one part into the rollup state (New-SITrendRollupState). The same rule as ConvertTo-SITrendRollup. #>
    param([Parameter(Mandatory)][hashtable]$State, [AllowNull()][AllowEmptyCollection()][object[]]$Rows)
    $groups = $State.Groups
    $keys = $State.Keys
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $ids = @(Get-SITrendRowAssetIds -Row $r)
        $score = 0.0
        $sp = $r.PSObject.Properties['RiskScoreTotal']
        if ($sp -and $null -ne $sp.Value -and [string]$sp.Value -ne '') { try { $score = [double]$sp.Value } catch { $score = 0.0 } }
        $pairs = @(@('global', 'all'), @('severity', (ConvertTo-SITrendDimensionValue $r.SecuritySeverity)),
                   @('tier', (ConvertTo-SITrendDimensionValue $r.CriticalityTier)), @('domain', (ConvertTo-SITrendDimensionValue $r.SecurityDomain)))
        $suffixes = @('')
        if ([string]::IsNullOrEmpty([string]$r.SI_ExemptionId)) { $suffixes = @('', '-counted') }
        foreach ($sfx in $suffixes) {
            foreach ($pair in $pairs) {
                $dim = $pair[0] + $sfx; $val = $pair[1]
                if ([string]::IsNullOrEmpty($val)) { continue }
                $k = $dim + [char]31 + $val
                if (-not $groups.ContainsKey($k)) {
                    $groups[$k] = @{ Dimension = $dim; DimensionValue = $val; Findings = 0; ScoreTotal = 0.0
                                     Assets = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)) }
                    [void]$keys.Add($k)
                }
                $g = $groups[$k]
                $g.Findings = $g.Findings + 1
                $g.ScoreTotal = $g.ScoreTotal + $score
                foreach ($i in $ids) { [void]$g.Assets.Add($i) }
            }
        }
    }
}

function Complete-SITrendRollup {
    <# The rollup rows from the state every part was added to: Dimension, DimensionValue, Findings, Assets, ScoreTotal. #>
    param([Parameter(Mandatory)][hashtable]$State)
    $groups = $State.Groups
    $keys = $State.Keys
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $keys) {
        $g = $groups[$k]
        [void]$out.Add([pscustomobject]@{ Dimension = $g.Dimension; DimensionValue = $g.DimensionValue; Findings = [int]$g.Findings
                                          Assets = [int]$g.Assets.Count; ScoreTotal = [double]$g.ScoreTotal })
    }
    $out.ToArray() | Sort-Object -Property Dimension, DimensionValue
}

function Get-SIWeeklyRateKql {
    <#
        CLOSED / OPENED / NET PER CALENDAR WEEK, as a SET DIFFERENCE -- §47.5c.

        🔴 THIS IS THE COMPUTATION THE WHOLE SECTION IS ABOUT, and the naive version is wrong in a way
        that flatters. Summing snapshot-to-snapshot diffs inside a week double-counts a finding that
        flaps: closed Tuesday, reopened Wednesday, closed Friday sums to TWO closures while the estate
        ended the week having closed ONE thing. So:

            closed-in-week = present in the week's FIRST snapshot AND absent from its LAST
            opened-in-week = absent from the FIRST AND present in the LAST

        Everything in between is flapping, and flapping is not throughput.

        🔴 A WEEK WITH NO SNAPSHOT IS A GAP, NOT A ZERO. `HasData` is emitted per week so a surface can
        render the difference. A missed run and a quiet week produce identical numbers otherwise, which
        is C14's failure mode wearing a chart -- and "we closed nothing" is a very different
        conversation from "we did not measure".

        🔴 AND THE SET DIFFERENCE IS TAKEN ONLY OVER ASSETS BOTH SNAPSHOTS EXAMINED. This was found by
        running it: June and July reported ~1,250-1,550 findings OPENED per week on an estate that
        holds 593 findings in total. The cause was not the arithmetic. Measured on the live workspace,
        the first snapshot of one week covered 19 assets and the last covered 64 -- so 45 assets were
        simply not looked at the first time, and every finding on them counted as "opened". Restricting
        to the 14 assets present in both turned that week into 18 opened / 29 closed, which is a real
        number. **A finding can only be said to have opened or closed if its asset was examined both
        times; anything else measures what was scanned, not what changed.**
        🔑 SO THE DENOMINATOR TRAVELS WITH THE NUMBER. `ComparedAssets` and `ObservedAssets` are emitted
        per week because the comparable population is routinely a FRACTION of the estate (11-14 of
        58-65 on the internal workspace). A throughput figure computed over a fifth of the estate and
        presented as the whole is the same class of defect as the one above, just quieter -- so the
        surface states what it compared, the way the rule check states how many rule files it examined.

        📌 The finding key is `ConfigurationId`, which identifies the FINDING, not the asset. Audit #25
        exists because those two were confused once already.

        🔒 EVERY AFFECTED ASSET, NOT ONE PER ROW (operator, 2026-10-05). The asset axis used to be the
        scalar `AssetId`, which on a Summary row is ONE representative of the group (#97): a CVE on 3
        assets counted once, both as a finding opened or closed and as a compared asset. The unit is now
        one finding ON one asset -- (ConfigurationId, asset) -- over every asset a row stands for, taken by
        `Get-SITrendRowAssetIds` (the same rule as the daily rollup, #303). That rule parses a JSON array
        that may arrive as a bare string (#82), so the query returns the week's first and last snapshot
        ROWS and `ConvertTo-SIWeeklyRate` takes the set difference here, rather than a second copy of the
        rule in KQL drifting from the first.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$TableName = 'SI_RiskAnalysis_Summary_CL',
        [Parameter()][int]$Weeks = 12
    )

    @"
let lookback = ${Weeks} * 7d;
let src = $TableName
    | where TimeGenerated > ago(lookback)
    $($script:SITrendEditionFilter)
    | extend Week  = startofweek(CollectionTime),
             Key   = tostring(column_ifexists("ConfigurationId", ""))
    | where isnotempty(Key);
// The first and last SNAPSHOT of each week -- not the first and last row.
let bounds = src | summarize FirstSnap = min(CollectionTime), LastSnap = max(CollectionTime), Snapshots = dcount(CollectionTime) by Week;
// Every week in the window, so a week with NO snapshot still produces a row (RowKind "week").
let allWeeks = range W from startofweek(ago(lookback)) to startofweek(now()) step 7d
    | project Week = W, RowKind = "week", Snapshots = 0;
// The rows of each week's first and last snapshot. Flags are ints, never bools: Log Analytics returns
// a bool as the STRING "False", which PowerShell 5.1 casts to true.
let edgeRows = src
    | join kind=inner (bounds) on Week
    | where CollectionTime == FirstSnap or CollectionTime == LastSnap
    | project Week, RowKind = "row", Snapshots,
              IsFirst = toint(CollectionTime == FirstSnap), IsLast = toint(CollectionTime == LastSnap), Key,
              ImpactedAssetIds = tostring(column_ifexists("ImpactedAssetIds", "")),
              AssetId          = tostring(column_ifexists("AssetId", "")),
              SI_AssetId       = tostring(column_ifexists("SI_AssetId", ""))
    | distinct Week, RowKind, Snapshots, IsFirst, IsLast, Key, ImpactedAssetIds, AssetId, SI_AssetId;
union allWeeks, edgeRows
| order by Week asc
"@
}

function ConvertTo-SIWeeklyRate {
    <#
        THE SET DIFFERENCE PER WEEK, over the rows Get-SIWeeklyRateKql returns. One output row per week:
        Week, HasData, Snapshots, Opened, Closed, Net, ComparedAssets, ObservedAssets -- the shape the
        query used to return, so the caller and the stored rows do not change.

        The unit is one finding on one asset: (ConfigurationId, asset), every asset a row stands for
        (`Get-SITrendRowAssetIds`). A CVE on 3 assets that appears in a week counts 3 opened; closed on 2
        of them the next week counts 2 closed, 1 still open.

            ObservedAssets = distinct assets in the week's LAST snapshot
            ComparedAssets = distinct assets in BOTH the first and the last snapshot
            Closed         = pairs in the first, not the last, on a compared asset
            Opened         = pairs in the last, not the first, on a compared asset

        Every rule of the header holds unchanged: only assets both snapshots examined are compared; a
        week with no snapshot is a gap (HasData false, everything null but Snapshots = 0); one snapshot
        or nothing comparable is UNKNOWN (Opened/Closed/Net null), never 0.
        📌 A row with no asset id at all (an estate-level finding) is still compared -- when both
        snapshots carry estate-level rows -- but is not an asset and never adds to an asset count.
    #>
    param([Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$Rows)
    $state = New-SIWeeklyRateState
    Add-SIWeeklyRateRows -State $state -Rows $Rows
    Complete-SIWeeklyRate -State $state
}

function New-SIWeeklyRateState {
    <# #639 lane 4: the weekly view built a PART at a time (Add-SIWeeklyRateRows, then Complete-SIWeeklyRate) -- the rows are
       never all held; what is kept per week is its first / last snapshot's asset and (finding, asset) sets. #>
    @{ Weeks = @{}; Order = (New-Object System.Collections.Generic.List[string]) }
}

function Add-SIWeeklyRateRows {
    <# The rows of one part into the weekly state (New-SIWeeklyRateState). The same rule as ConvertTo-SIWeeklyRate. #>
    param([Parameter(Mandatory)][hashtable]$State, [AllowNull()][AllowEmptyCollection()][object[]]$Rows)
    $estate = [string][char]30   # internal marker for "no asset"; never counted as an asset
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    $weeks = $State.Weeks
    $order = $State.Order
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $wv = $r.Week
        $wUtc = if ($wv -is [datetime]) { $wv.ToUniversalTime() } else {
            [datetime]::Parse([string]$wv, [System.Globalization.CultureInfo]::InvariantCulture,
                ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)) }
        $wk = $wUtc.ToString('yyyy-MM-ddTHH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture)
        if (-not $weeks.ContainsKey($wk)) {
            $weeks[$wk] = @{ Week = $wUtc; Snapshots = 0
                FirstAssets = (New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)); LastAssets = (New-Object 'System.Collections.Generic.HashSet[string]' ($cmp))
                FirstPairs  = (New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)); LastPairs  = (New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)) }
            [void]$order.Add($wk)
        }
        $w = $weeks[$wk]
        $sp = $r.PSObject.Properties['Snapshots']
        if ($sp -and $null -ne $sp.Value -and [string]$sp.Value -ne '') { $n = [int]$sp.Value; if ($n -gt $w.Snapshots) { $w.Snapshots = $n } }
        $kp = $r.PSObject.Properties['RowKind']
        if ($kp -and [string]$kp.Value -eq 'week') { continue }
        $key = ([string]$r.Key).Trim()
        if (-not $key) { continue }
        $isFirst = $false; $isLast = $false
        $fp = $r.PSObject.Properties['IsFirst']; if ($fp -and $null -ne $fp.Value -and [string]$fp.Value -ne '') { $isFirst = ([int]$fp.Value) -ne 0 }
        $lp = $r.PSObject.Properties['IsLast'];  if ($lp -and $null -ne $lp.Value -and [string]$lp.Value -ne '') { $isLast  = ([int]$lp.Value) -ne 0 }
        $ids = @(Get-SITrendRowAssetIds -Row $r)
        if ($ids.Count -eq 0) { $ids = @($estate) }
        foreach ($a in $ids) {
            $pair = $key + [char]31 + $a
            if ($isFirst) { [void]$w.FirstAssets.Add($a); [void]$w.FirstPairs.Add($pair) }
            if ($isLast)  { [void]$w.LastAssets.Add($a);  [void]$w.LastPairs.Add($pair) }
        }
    }
}

function Complete-SIWeeklyRate {
    <# One row per week from the state every part was added to (the shape ConvertTo-SIWeeklyRate returns). #>
    param([Parameter(Mandatory)][hashtable]$State)
    $estate = [string][char]30
    $cmp = [System.StringComparer]::OrdinalIgnoreCase
    $weeks = $State.Weeks
    $order = $State.Order
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($wk in ($order | Sort-Object)) {
        $w = $weeks[$wk]
        $hasData = $w.Snapshots -gt 0
        $common = New-Object 'System.Collections.Generic.HashSet[string]' ($cmp)
        foreach ($a in $w.FirstAssets) { if ($w.LastAssets.Contains($a)) { [void]$common.Add($a) } }
        $compared = @($common | Where-Object { $_ -ne $estate }).Count
        $observed = @($w.LastAssets | Where-Object { $_ -ne $estate }).Count
        $closed = 0; $opened = 0
        foreach ($p in $w.FirstPairs) { $a = $p.Substring($p.IndexOf([char]31) + 1); if ($common.Contains($a) -and -not $w.LastPairs.Contains($p)) { $closed++ } }
        foreach ($p in $w.LastPairs)  { $a = $p.Substring($p.IndexOf([char]31) + 1); if ($common.Contains($a) -and -not $w.FirstPairs.Contains($p)) { $opened++ } }
        # Nothing comparable, or a single snapshot, is UNKNOWN -- not a measured quiet week.
        $comparable = $hasData -and $compared -gt 0 -and $w.Snapshots -gt 1
        [void]$out.Add([pscustomobject]@{
            Week           = $w.Week
            HasData        = $hasData
            Snapshots      = [int]$w.Snapshots
            Opened         = $(if ($comparable) { [int]$opened } else { $null })
            Closed         = $(if ($comparable) { [int]$closed } else { $null })
            Net            = $(if ($comparable) { [int]($opened - $closed) } else { $null })
            ComparedAssets = $(if ($hasData) { [int]$compared } else { $null })
            ObservedAssets = $(if ($hasData) { [int]$observed } else { $null })
        })
    }
    $out.ToArray()
}

function New-SITrendRow {
    <#
        One rollup row. Long/narrow on purpose -- see Get-SITrendRollupKql.

        `SolutionVersion` is stamped because v2.2 and v3 share this workspace and a trend line that
        silently mixes editions is worse than no trend line (#83's family).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Dimension,
        [Parameter(Mandatory)][AllowEmptyString()][string]$DimensionValue,
        [Parameter()][int]$Findings = 0,
        [Parameter()][int]$Assets = 0,
        [Parameter()][double]$ScoreTotal = 0,
        [Parameter()][string]$SourceTable = '',
        [Parameter()][string]$SolutionVersion = ''
    )
    [pscustomobject]@{
        CollectionTime  = $CollectionTime
        SI_RunId        = [string]$RunId
        Dimension       = [string]$Dimension
        DimensionValue  = [string]$DimensionValue
        Findings        = [int]$Findings
        Assets          = [int]$Assets
        ScoreTotal      = [double]$ScoreTotal
        SourceTable     = [string]$SourceTable
        SolutionVersion = [string]$SolutionVersion
    }
}

# 🔴 HOW MANY WEEKS THE ENGINE CAN RECOMPUTE, AND WHY IT IS NOT THE WINDOW THE GUI SHOWS.
# The weekly rate is derived from the RA source table, which retains ~90 days. So a run can only ever
# recompute ~13 weeks -- asking it for 52 returns 39 empty weeks, which would render as 39 measurement
# gaps that never happened. 12 weeks sits inside 90 days with margin.
# 🔑 THE 365-DAY VIEW IS ASSEMBLED FROM STORED ROWS, NOT RECOMPUTED. Each week is written while it is
# still inside the RA window and then frozen; the trend table keeps it for a year. A reader therefore
# takes the LAST WRITTEN value per week (arg_max over CollectionTime), never the newest snapshot alone
# -- the newest snapshot only knows the last ~13 weeks, and reading it alone silently truncates the
# year to a quarter while looking completely healthy.
$script:SITrendWeeklyComputeWeeks = 12
function Get-SITrendWeeklyComputeWeeks { $script:SITrendWeeklyComputeWeeks }

function New-SITrendWeeklyRows {
    <#
        Encode one week of the rate view as narrow rollup rows.

        🔑 NO SCHEMA CHANGE. The obvious move is to add Opened/Closed/Net columns, but this table is
        bound by the same rule as the profile tables: a new column is a schema change, it needs the
        ~25-minute ingest wait, and SCHEMA-1 makes it a per-customer approval. The long/narrow shape
        already carries an arbitrary number of measures -- one row per (Dimension, DimensionValue) --
        so a week is three rows and the table shape never moves.

        🔴 A GAP IS NOT A ZERO, and that has to survive the round trip. A week with no snapshot emits
        ONLY the snapshots row (value 0) and NO opened/closed rows, so a reader can tell "we measured
        and nothing closed" (opened/closed present, 0) from "we never measured" (absent). Emitting
        0/0/0 for an unmeasured week would collapse exactly the distinction the view exists for.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][datetime]$Week,
        [Parameter(Mandatory)][bool]$HasData,
        [Parameter()][int]$Snapshots = 0,
        [Parameter()][int]$Opened = 0,
        [Parameter()][int]$Closed = 0,
        # 🔑 THE DENOMINATOR. The comparable population is routinely a fraction of the estate, so a
        # week's throughput is meaningless without it -- see Get-SIWeeklyRateKql's header.
        [Parameter()][int]$ComparedAssets = 0,
        [Parameter()][int]$ObservedAssets = 0,
        [Parameter()][string]$SourceTable = '',
        [Parameter()][string]$SolutionVersion = ''
    )
    # Invariant format: the week key is read back by a GUI that must not depend on the host's locale.
    $key = $Week.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $mk = {
        param($dim, $val)
        New-SITrendRow -CollectionTime $CollectionTime -RunId $RunId -Dimension $dim -DimensionValue $key `
            -Findings $val -SourceTable $SourceTable -SolutionVersion $SolutionVersion
    }
    $out = New-Object System.Collections.ArrayList
    [void]$out.Add((& $mk 'weekly-snapshots' $Snapshots))
    if ($HasData) {
        # The denominator is written even when nothing was comparable -- that IS the finding for such
        # a week, and a reader who cannot see it has no way to know the week is not simply quiet.
        [void]$out.Add((& $mk 'weekly-compared-assets' $ComparedAssets))
        [void]$out.Add((& $mk 'weekly-observed-assets' $ObservedAssets))
        # Opened/closed need TWO distinct snapshots (#135). With one, the first and last snapshot are the
        # same run, the set difference is trivially empty, and "0 opened, 0 closed" would be published
        # as a MEASURED quiet week -- the KQL already returns null for exactly this case (Comparable
        # requires Snapshots > 1), and the caller turned that null into 0. Gated here on the same rule.
        if ($ComparedAssets -gt 0 -and $Snapshots -gt 1) {
            [void]$out.Add((& $mk 'weekly-opened' $Opened))
            [void]$out.Add((& $mk 'weekly-closed' $Closed))
        }
    }
    # 🪤 ,@() would hand the caller an array CONTAINING an array -- paid for four times already here.
    $out.ToArray()
}

function Write-SITrendReport {
    <#
        What the rollup captured, and the one number that says whether it is trustworthy.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows)

    $info = { param($m) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m } }
    $warn = { param($m) if (Get-Command -Name Write-SIWarn -ErrorAction SilentlyContinue) { Write-SIWarn $m } else { Write-Warning $m } }

    $rows = @($Rows)
    if ($rows.Count -eq 0) {
        & $warn '   [trend] 0 rollup rows -- nothing to publish. The source snapshot was empty, which is NOT the same as an estate with no findings; check that Risk Analysis has run.'
        return
    }

    $global = @($rows | Where-Object { $_.Dimension -eq 'global' })
    if ($global.Count -gt 0) {
        & $info ("   [trend] global: {0} finding(s), {1} asset(s), score {2:N0}" -f $global[0].Findings, $global[0].Assets, $global[0].ScoreTotal)
    }
    foreach ($d in @('severity','tier','domain')) {
        $set = @($rows | Where-Object { $_.Dimension -eq $d })
        if ($set.Count -gt 0) {
            & $info ("   [trend] {0,-9} {1} value(s): {2}" -f $d, $set.Count,
                (( $set | Sort-Object -Property @{E={[int]$_.Findings};Descending=$true} | Select-Object -First 5 |
                   ForEach-Object { '{0}={1}' -f $_.DimensionValue, $_.Findings }) -join ', '))
        }
    }
    # 🔑 One row per dimension value per day. If this number is large the table is no longer narrow,
    # which is the one assumption §60.4b's retention argument rests on.
    # Printed BEFORE the weekly rows are added (Invoke-SITrend step 2), so it counts the rollup rows only -- it said
    # "row(s) this run" and the run then posted 15-17 more.
    & $info ("   [trend] {0} rollup row(s) -- the table stays narrow by design; the retention argument rests on that. The weekly rows are added next." -f $rows.Count)
}

function Get-SITrendHistoryKql {
    <#
        WHAT THE GUI READS: the stored trend history over a long window.

        🔴 PER-KEY arg_max, NEVER "the latest snapshot". The rollup dimensions (global/severity/tier/
        domain) are rewritten every run, so for those the newest snapshot IS the answer -- but the
        weekly rows can only be recomputed while their week is still inside the RA source's ~90-day
        retention. Reading the newest snapshot alone therefore returns ~13 weeks and silently truncates
        a year to a quarter: no error, no gap, and a chart that looks entirely healthy.

        Taking the LAST WRITTEN row per (Dimension, DimensionValue) assembles the full window from rows
        written when each week was fresh. That is the only reason the one-year view exists at all, and
        it is why the engine persists the weekly rows on EVERY run rather than only when printing them.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][string]$TableName = 'SI_Trend_CL',
        [Parameter()][int]$Days = 365
    )

    @"
$TableName
| where TimeGenerated > ago(${Days}d)
| summarize arg_max(CollectionTime, Findings, Assets, ScoreTotal, SolutionVersion) by Dimension, DimensionValue
| project CollectionTime, Dimension, DimensionValue, Findings, Assets, ScoreTotal, SolutionVersion
| order by Dimension asc, DimensionValue asc
"@
}
