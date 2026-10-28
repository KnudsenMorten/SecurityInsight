#Requires -Version 5.1
<#
    #742 -- RISK ANALYSIS SCALES OUT ON QUEUE WORKERS, NOT ONLY UP (owner 2026-10-17: "if we can do scale out with keda use
    that also, instead of just scale up" / "if la writes can be paralized both using ps 7 batches parrallels and more
    containers"). A large tenant's Detailed run took 12 h 9 m in ONE job, report after report.

    The SAME mechanics as the collection engines' producer + workers (engine/_shared/SI-CollectParts.ps1 -- the manifest
    and the part markers; engine/asset-profiling/storage/WorkerQueue.ps1 -- the queue, the short lease renewed by a
    heartbeat, the poison queue):

      PRODUCER  (the existing Risk Analysis job) begins the run's collection in SQL as before, plans the run -- one work item
                per report of the template, in template order, each with the ordinal the single job would give it -- loads
                what more than one report shares ONCE (the run's Defender recommendation list, #673), writes the MANIFEST and
                queues the items. It waits for every item's MARKER (done or failed, with progress lines), reads each item's
                HAND-OVER (what the report loop knew about the report: its counts, verdicts, notes, failures, lost buckets,
                columns, ...) into its own state, and then runs everything that must stay ONE unit exactly as before: the
                run-level guards, the cross-report steps, the Log Analytics post (the whole run ONCE, from SQL, exactly as
                the single job posts it), the verdicts-final marker, the completion, the workbook, the AI summary and the mail.
      WORKERS   (caj-si-raworker-<grain>, queue-scaled, the producer's size) take an item, attach to the run's collection and
                run that report exactly as the single job does (query, scoring, rows + verdict to SQL), and write the
                hand-over and the marker. A worker NEVER posts to Log Analytics: a worker that dies mid-report and the retry
                of its report can then never leave a row there twice. A worker drains the queue (the start-up is paid once). A worker that dies leaves its item to the queue (the lease);
                an item handed out more than MaxDequeue times is parked and marked FAILED with the cause -- the report is
                then NOT COMPLETE, never silent. A retried item replaces what an earlier attempt wrote (the report's rows
                are removed when it starts, as in the single job).
      ONE METHOD for every size: a small tenant's run is the same items, taken by one worker. Without a worker job (no
      managed identity, KEDA switched off) the producer runs the worker in its own container, as a child process.

    Storage (the install's state container, as the collection's): collect/ra-<grain>/<runId>/manifest.json, parts/part-NNNNN.json
    (the item markers), handover/item-NNNNN.json, started/item-NNNNN.json, closed.json, run.lock. Every function that
    touches storage takes the -Store seam of SI-CollectParts.ps1 (Read / Write / List / Claim, + Remove here).
    PowerShell 5.1 safe: no ternary, no null-conditional.
#>

# Container-scope rule (2026-10-16, the 2105 lesson): this file loads every function it calls, by its own path.
if (-not (Get-Command -Name New-SICollectManifest -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-CollectParts.ps1')) }
if (-not (Get-Command -Name Get-SINextWorkItem -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'asset-profiling', 'storage', 'WorkerQueue.ps1')) }
if (-not (Get-Command -Name Get-RAHandoffContradiction -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'RA-ProfileAugment.ps1')) }
if (-not (Get-Command -Name Get-RAReportSuccessorMap -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'RA-ReportHandoff.ps1')) }

$script:RAScaleOut = @{
    MaxDequeue        = 3          # an item that ended its worker this many times is parked (the report NOT COMPLETE)
    StartGraceMinutes = 15         # no item started this long after queueing -> the producer runs a worker itself
    PollSeconds       = 20
    ProgressSeconds   = 300
    SeqStride         = 1000000000000   # each report's rows are numbered from Ordinal x this (RaSeq is a BIGINT)
    LockTtlSeconds    = 900
    StaleHours        = 48         # a manifest older than this is a run that is over
}
function Test-RAScaleOutWanted {
    <#
        PURE. Whether THIS run is a producer that hands its reports to workers. -Setting: SI_RA_ScaleOut (on/off; the job's
        SI_RA_SCALE_OUT, set by setup when the worker job exists). The result must be in SQL (the workers write there), a
        storage account must hold the queue and the markers, and a dry run never scales out. Detailed only for now (#742
        increment 1). Returns @{ On; Why }.
    #>
    param([AllowNull()]$Setting, [ValidateSet('Detailed', 'Summary')][string]$Grain = 'Detailed', [bool]$StreamOn = $false, [bool]$WhatIf = $false,
          [AllowEmptyString()][string]$StorageAccount = '')
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    $o = { param($on, $why) [pscustomobject]@{ On = [bool]$on; Why = [string]$why } }
    if ($s -notin 'on', 'true', '1', 'yes') { return (& $o $false 'the reports run one after another in this job (no workers set up for it)') }
    if ($Grain -ne 'Detailed') { return (& $o $false 'the Summary reports run in this job (workers take the Detailed reports)') }
    if ($WhatIf) { return (& $o $false 'a dry run keeps the reports in this job') }
    if (-not $StreamOn) { return (& $o $false 'the workers write the result to the database, and this run keeps it in memory -- the reports run in this job') }
    if (-not "$StorageAccount".Trim()) { return (& $o $false 'no storage account for the work queue -- the reports run in this job') }
    & $o $true 'the reports are handed to queue workers'
}

function Get-RAScaleOutQueueName {
    <# PURE. The work queue of a grain: what the producer writes, the workers read and the scaler counts. #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain = 'Detailed')
    'si-ra-{0}-items' -f $Grain.ToLowerInvariant()
}

function Get-RAScaleOutEngine {
    <# PURE. The folder name of a grain's runs in the state container. #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain = 'Detailed')
    'ra-{0}' -f $Grain.ToLowerInvariant()
}

function Get-RAScaleOutWorkerJobName {
    <# PURE. The worker job of a grain -- 32 characters at most (a Container Apps job name), outside the caj-si-ra-<name>
       namespace of the extra report jobs. #>
    param([ValidateSet('Detailed', 'Summary')][string]$Grain = 'Detailed')
    'caj-si-raworker-{0}' -f $Grain.ToLowerInvariant()
}

function Get-RAScaleOutRunId {
    <# PURE. The run's id in the state container: its collection time (unique per collection; the database refuses a second). #>
    param([Parameter(Mandatory)][string]$TimeText)
    'ct-' + (($TimeText -replace '[^0-9]', ''))
}

function Get-RAScaleOutPath {
    <# PURE. Where a run's hand-over / started mark / closed mark / lock lives (manifest and markers: Get-SICollectPath). #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          # #831 B: 'partial' = what one PART of a split report found (its slices are in the database); 'finish' = the claim of
          # the part that puts the report together (-Item = the report's ORDINAL)
          [Parameter(Mandatory)][ValidateSet('handover', 'started', 'closed', 'lock', 'partial', 'finish')][string]$Kind, [int]$Item = -1)
    $base = 'collect/{0}/{1}' -f $Engine.ToLowerInvariant(), $RunId
    switch ($Kind) {
        'closed' { return "$base/closed.json" }
        'lock'   { return "$base/run.lock" }
        'finish' { return ('{0}/finish/report-{1:D5}.json' -f $base, $Item) }
        default  { return ('{0}/{1}/item-{2:D5}.json' -f $base, $Kind, $Item) }
    }
}

function Get-RAScaleOutSeqBase {
    <# PURE. The first write number of a report's rows: Ordinal x stride. The rows keep the single job's order (report order,
       then write order) while every worker numbers its own report's rows without asking anyone. #>
    param([Parameter(Mandatory)][int]$Ordinal, [long]$Stride = $script:RAScaleOut.SeqStride)
    [long]$Ordinal * $Stride
}

function Get-RAScaleOutSplitCount {
    <#
        PURE. #831 B -- HOW MANY WORK ITEMS ONE REPORT IS SPLIT INTO (by ranges of its query slices). Measured at a large
        install 2026-10-20: four workers emptied the queue in 50 minutes and ONE worker ran the last report alone for 4 h 46 m,
        because a work item was a whole report. The rule is derived from what the run remembers, never a fixed size:
          * -RunBuckets: the query slices the whole run is expected to ask (every report's remembered count, 1 for a report
            without one); -Workers: how many workers may run at once (SI_RA_WORKERS);
          * a fair share of the run is RunBuckets / Workers slices per worker; a report larger than that share would on its own
            outlast the other workers, so it is split into ceil(Buckets / share) items -- never more than the workers (each
            would wait for one) and never an item of fewer than 2 slices (the first slice of a report can carry its whole
            result, #401, and must have a second one beside it);
          * one worker (or none: the producer's own worker) = never split -- splitting would only add each item's start.
        Returns the item count (1 = the report runs as one item, as before #831).
    #>
    param([int]$Buckets, [long]$RunBuckets = 0, [int]$Workers = 0)
    if ($Workers -le 1 -or $Buckets -lt 4) { return 1 }
    if ($RunBuckets -lt $Buckets) { $RunBuckets = $Buckets }
    $share = [long][Math]::Ceiling($RunBuckets / [double]$Workers)
    $k = [int][Math]::Ceiling($Buckets / [double][Math]::Max(1L, $share))
    $k = [Math]::Min($k, $Workers)
    $k = [Math]::Min($k, [int][Math]::Floor($Buckets / 2))
    [Math]::Max(1, $k)
}

function Get-RAScaleOutCostSplitCount {
    <#
        PURE. #873 B -- HOW MANY PARTS ONE REPORT IS SPLIT INTO, BY ITS MEASURED WORK. Get-RAScaleOutSplitCount counts query
        slices, and a slice of the CVE report (~17,000 rows) is not a slice of a small report (a few rows): at the largest
        install (1.39 M rows, the CVE report 1.1 M of them, ~64 slices among ~100 small-report slices) it made 2 parts for 4
        workers -- two workers emptied the small reports and sat idle while two ran the CVE report for hours.
          * -Cost: the rows the report returned at its last run; -RunCost: the measured rows of every report of the run;
          * a fair share is RunCost / Workers; a report larger than that share is split into ceil(Cost / share) parts --
            never more than the workers, never a part of fewer than 2 slices (a report's first slice can carry its whole
            result, #401), never fewer than 1;
          * one worker, a report of fewer than 4 slices, or no measurement (Cost 0): the slice rule (Get-RAScaleOutSplitCount).
        Which slices a part asks and how its rows are numbered is unchanged (Get-RAScaleOutSplitRange / -SplitSeqBase): only
        how many parts. Returns the part count.
    #>
    param([int]$Buckets, [long]$Cost = 0, [long]$RunCost = 0, [int]$Workers = 0)
    if ($Workers -le 1 -or $Buckets -lt 4) { return 1 }
    if ($Cost -le 0) { return (Get-RAScaleOutSplitCount -Buckets $Buckets -RunBuckets 0 -Workers $Workers) }
    if ($RunCost -lt $Cost) { $RunCost = $Cost }
    $share = [double]$RunCost / [double]$Workers
    $k = [int][Math]::Ceiling([double]$Cost / [Math]::Max(1.0, $share))
    $k = [Math]::Min($k, $Workers)
    $k = [Math]::Min($k, [int][Math]::Floor($Buckets / 2))
    [Math]::Max(1, $k)
}

function Get-RAScaleOutMeasuredRows {
    <#
        PURE. #873 B: the rows a report returned at its newest run that measured any (the bucket history, cfg.RaBucketHistory:
        report name -> rows, newest first; ResultRows = what its slices returned). 0 = not measured -- the report is then split
        by its slices as before. A run that ended incomplete still measured the rows it got; it can only make the share smaller.
    #>
    param([hashtable]$History = @{}, [Parameter(Mandatory)][string]$Report)
    if ($null -eq $History -or -not $History.ContainsKey($Report)) { return 0L }
    foreach ($h in @($History[$Report])) {
        if ($null -eq $h) { continue }
        $v = $null; if ($h.PSObject.Properties['ResultRows']) { $v = $h.ResultRows }
        if ($null -eq $v -or $v -is [System.DBNull]) { continue }
        $d = 0.0
        $txt = $(if ($v -is [string]) { $v } else { [System.Convert]::ToString($v, [System.Globalization.CultureInfo]::InvariantCulture) })
        if ([double]::TryParse($txt, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and $d -ge 1) { return [long][Math]::Floor($d) }
    }
    0L
}

function Get-RAScaleOutSplitRange {
    <# PURE. #831 B: the query slices [From, To) part -Part of -Parts covers of a report asked in -Buckets slices (contiguous,
       in slice order, every slice in exactly one part, the parts' sizes differ by one at most). #>
    param([int]$Part, [int]$Parts, [int]$Buckets)
    if ($Parts -lt 1) { $Parts = 1 }
    [pscustomobject]@{ From = [int][Math]::Floor($Part * $Buckets / [double]$Parts); To = [int][Math]::Floor(($Part + 1) * $Buckets / [double]$Parts) }
}

function Get-RAScaleOutSplitSeqBase {
    <#
        PURE. #831 B: the first write number of ONE PART of a split report in one of its three bands. The single job writes a
        report's rows in this order: every slice of the main pass in slice order, then the slices retried late (throttling),
        then the smaller slices of the sub-slice pass. A split report's numbers keep that order: the report's range
        (Ordinal x stride, as an unsplit report) is cut into 3 x Parts slots -- the main pass of part 0, 1, ..., then the late
        retries of part 0, 1, ..., then the sub-slices of part 0, 1, ... -- so the final order (score, report, write order) is
        the single job's. -Band main | late | sub.
    #>
    param([Parameter(Mandatory)][int]$Ordinal, [int]$Part = 0, [int]$Parts = 1, [ValidateSet('main', 'late', 'sub')][string]$Band = 'main', [long]$Stride = $script:RAScaleOut.SeqStride)
    if ($Parts -lt 1) { $Parts = 1 }
    $w = [long][Math]::Floor($Stride / (3.0 * $Parts))
    $slot = switch ($Band) { 'main' { $Part } 'late' { $Parts + $Part } default { 2 * $Parts + $Part } }
    ([long]$Ordinal * $Stride) + ([long]$slot * $w)
}

function Get-RAScaleOutSplitSeqRanges {
    <# PURE. #831 B: the write numbers [From, To) ONE part of a split report may write -- its three bands. What a retried
       part removes when it starts (its own rows only, never another part's). #>
    param([Parameter(Mandatory)][int]$Ordinal, [int]$Part = 0, [int]$Parts = 1, [long]$Stride = $script:RAScaleOut.SeqStride)
    if ($Parts -lt 1) { $Parts = 1 }
    $w = [long][Math]::Floor($Stride / (3.0 * $Parts))
    @(foreach ($b in 'main', 'late', 'sub') { $f = Get-RAScaleOutSplitSeqBase -Ordinal $Ordinal -Part $Part -Parts $Parts -Band $b -Stride $Stride; [pscustomobject]@{ From = $f; To = ($f + $w) } })
}

function Test-RAScaleOutSplittable {
    <#
        PURE. #831 B: whether a report MAY be split into parts -- only where the single job asks it in query slices whose count
        is remembered: the query carries the slice block, the report does not switch slicing off and is not set to one slice,
        the bucket counts are learned (AutoBucketCount), the report is not staged (a Summary report's groups are combined over
        all its slices at once), and the on-demand bucket proof is off (it compares the whole report in one process).
    #>
    param([string]$Name, [AllowEmptyString()][string]$Query = '', $UseBucketFilter = $null, $BucketCount = $null, [bool]$AutoBucket = $true, [bool]$Proof = $false)
    if (-not $AutoBucket -or $Proof) { return $false }
    if ([string]$Name -like '*_Summary*') { return $false }
    if ($null -ne $UseBucketFilter -and -not [bool]$UseBucketFilter) { return $false }
    if ($null -ne $BucketCount -and [string]$BucketCount -ne '' -and [int]$BucketCount -eq 1) { return $false }
    # the slice block the report loop replaces (Invoke-RiskAnalysis.ps1 Test-QueryHasBucketFilterBlock: the same two marks)
    ([string]$Query).IndexOf('//__BUCKET_FILTER_BEGIN__') -ge 0 -and ([string]$Query).IndexOf('//__BUCKET_FILTER_END__') -ge 0
}

function Get-RAScaleOutRememberedBuckets {
    <# PURE. #831 B: the query slices a report is remembered to need -- the largest count kept for it under any query
       fingerprint ('<Report>|<hash>' in the bucket counts, cfg.RaBucketState / the AutoBucket cache); 0 = none remembered. #>
    param([hashtable]$Cache = @{}, [Parameter(Mandatory)][string]$Report)
    if ($null -eq $Cache) { return 0 }
    $prefix = $Report + '|'
    $best = 0
    foreach ($k in @($Cache.Keys)) {
        $ks = [string]$k
        if ($ks.StartsWith('__') -or -not $ks.StartsWith($prefix)) { continue }
        $v = 0
        if ([int]::TryParse([string]$Cache[$k], [ref]$v) -and $v -gt $best) { $best = $v }
    }
    $best
}

function New-RAScaleOutPlan {
    <#
        PURE. The run's work items: one per report of the template that has a definition, in template order, numbered as the
        single job numbers them (its ordinal: 1, 2, ... over the reports that reach the database; a report with no
        definition gets none -- the single job skips it the same way and the end of the run names it NOT COMPLETE).
        -Reports: @(@{ Name; HasEntry; Buckets (remembered query slices, 0 = none); Splittable }).
        #831 B: with -Workers > 1 a splittable report whose remembered count is large against the run (Get-RAScaleOutSplitCount)
        becomes several items, one per range of its slices, all with the report's ordinal. A report without remembered state
        is one item, as before. Returns @(@{ Item; Report; Ordinal; Part; Parts; Buckets; From; To }) -- Parts 1 / Buckets 0
        for a report that runs as one item.
    #>
    param([AllowEmptyCollection()][object[]]$Reports = @(), [int]$Workers = 0)
    $out = New-Object System.Collections.Generic.List[object]
    $ord = 0
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Reports)) {
        if ($null -eq $r) { continue }
        $n = [string]$r.Name
        if (-not $n.Trim() -or -not [bool]$r.HasEntry) { continue }
        $ord++
        # a report named twice in a template runs twice in the single job (and keeps the second); here once
        if (-not $seen.Add($n)) { continue }
        $b = 0; if ($r.PSObject.Properties['Buckets'] -and $null -ne $r.Buckets) { $b = [int]$r.Buckets }
        $sp = $false; if ($r.PSObject.Properties['Splittable']) { $sp = [bool]$r.Splittable }
        # #873 B: the rows the report returned at its last run (0 = not measured)
        $rw = 0L; if ($r.PSObject.Properties['Rows'] -and $null -ne $r.Rows) { $rw = [long][Math]::Max(0L, [long]$r.Rows) }
        $kept.Add([pscustomobject]@{ Name = $n; Ordinal = $ord; Buckets = $b; Splittable = $sp; Rows = $rw })
    }
    $runBuckets = 0L; foreach ($k in $kept) { $runBuckets += [long][Math]::Max(1, [int]$k.Buckets) }
    $runRows = 0L; foreach ($k in $kept) { $runRows += [long]$k.Rows }
    foreach ($k in $kept) {
        $parts = 1
        if ($k.Splittable -and [int]$k.Buckets -gt 0) {
            # #873 B: a report whose rows were measured is split by its share of the run's measured rows (the work of a
            # Detailed report grows with its rows: scoring, the stored form, the write); without a measurement, by its
            # slices as before (#831 B). The parts and their slice ranges are made the same way either way.
            if ([long]$k.Rows -gt 0) { $parts = Get-RAScaleOutCostSplitCount -Buckets ([int]$k.Buckets) -Cost ([long]$k.Rows) -RunCost $runRows -Workers $Workers }
            else { $parts = Get-RAScaleOutSplitCount -Buckets ([int]$k.Buckets) -RunBuckets $runBuckets -Workers $Workers }
        }
        for ($p = 0; $p -lt $parts; $p++) {
            if ($parts -gt 1) { $rg = Get-RAScaleOutSplitRange -Part $p -Parts $parts -Buckets ([int]$k.Buckets); $nb = [int]$k.Buckets; $f = $rg.From; $t = $rg.To }
            else { $nb = 0; $f = 0; $t = 0 }
            # Size: the query slices this item asks (its range; a whole report: its remembered count, 1 when none) -- the queue
            # hands out the largest first (Publish-RAScaleOutItems); the ordinals and write numbers do not depend on it
            $sz = $(if ($parts -gt 1) { $t - $f } else { [Math]::Max(1, [int]$k.Buckets) })
            $out.Add([pscustomobject]@{ Item = $out.Count; Report = $k.Name; Ordinal = $k.Ordinal; Part = $p; Parts = $parts; Buckets = $nb; From = $f; To = $t; Size = $sz })
        }
    }
    $out.ToArray()
}

function New-RAScaleOutManifest {
    <#
        PURE. The producer's manifest: SI-CollectParts' manifest (Parts = the items) plus what every worker needs to run its
        report as part of THIS run -- the collection in SQL, the run's ids, the items, the Defender recommendation list's
        state (#673: loaded once by the producer), and the producer's host (for the log: the producer posts the rows).
    #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain, [Parameter(Mandatory)][string]$TimeText,
          [Parameter(Mandatory)][datetime]$CollectionTime, [int]$CollectionId = 0, [string]$RunKey = '', [string]$HealthRunId = '',
          [string]$Template = '', [AllowEmptyCollection()][object[]]$Items = @(), $Defender = $null, $HostInfo = $null,
          [datetime]$Now = [datetime]::UtcNow, [string]$ProducerExecution = '')
    $runId = Get-RAScaleOutRunId -TimeText $TimeText
    $m = New-SICollectManifest -Engine (Get-RAScaleOutEngine -Grain $Grain) -RunId $runId -CollectionTime $CollectionTime -Parts ([Math]::Max(0, @($Items).Count)) -Now $Now -ProducerExecution $ProducerExecution
    $m['Grain'] = $Grain; $m['TimeText'] = $TimeText; $m['CollectionId'] = $CollectionId; $m['RunKey'] = $RunKey; $m['HealthRunId'] = $HealthRunId
    $m['Template'] = $Template
    $m['Items'] = @(@($Items) | ForEach-Object {
        $pp = 0; $pn = 1; $pb = 0; $pf = 0; $pt = 0
        if ($_.PSObject.Properties['Parts'] -and [int]$_.Parts -gt 1) { $pp = [int]$_.Part; $pn = [int]$_.Parts; $pb = [int]$_.Buckets; $pf = [int]$_.From; $pt = [int]$_.To }
        $sz = 1; if ($_.PSObject.Properties['Size'] -and [int]$_.Size -gt 0) { $sz = [int]$_.Size }
        [ordered]@{ Item = [int]$_.Item; Report = [string]$_.Report; Ordinal = [int]$_.Ordinal; Part = $pp; Parts = $pn; Buckets = $pb; From = $pf; To = $pt; Size = $sz } })
    $d = [ordered]@{ State = 'none'; Error = ''; Keys = 0L; Pages = 0 }
    if ($Defender) { foreach ($k in 'State', 'Error', 'Keys', 'Pages') { $v = $null; if ($Defender -is [System.Collections.IDictionary]) { $v = $Defender[$k] } elseif ($Defender.PSObject.Properties[$k]) { $v = $Defender.$k }; if ($null -ne $v) { $d[$k] = $v } } }
    $m['Defender'] = $d
    $h = [ordered]@{ Name = ''; Fqdn = ''; User = '' }
    if ($HostInfo) { foreach ($k in 'Name', 'Fqdn', 'User') { $v = $null; if ($HostInfo -is [System.Collections.IDictionary]) { $v = $HostInfo[$k] } elseif ($HostInfo.PSObject.Properties[$k]) { $v = $HostInfo.$k }; if ($null -ne $v) { $h[$k] = [string]$v } } }
    $m['Host'] = $h
    $m
}

function Test-RAScaleOutNeedsDefenderKeys {
    <# PURE. #673: the run's Defender recommendation list is loaded once by the producer when plan B (or its comparison) is on
       and a report of the plan carries the hand-off markers -- never by two workers at once (each load clears the list). #>
    param([AllowEmptyCollection()][string[]]$Queries = @(), [bool]$InEngine = $true, [bool]$Compare = $false)
    if (-not $InEngine -and -not $Compare) { return $false }
    foreach ($q in @($Queries)) { if ([string]$q -and ([string]$q).IndexOf('//__SI_DFC_ANTIJOIN_BEGIN__') -ge 0) { return $true } }
    $false
}

# ------------------------------------------------------------------------------------------------------------------
#  STORE
# ------------------------------------------------------------------------------------------------------------------

function New-RAScaleOutBlobStore {
    <# SI-CollectParts' store over the install's state container, with Remove (the lock is released by removing it). #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistate')
    $s = New-SICollectBlobStore -Account $Account -Container $Container
    $acc = $Account; $con = $Container
    # Remove-SIBlob travels INTO the closure as a value: the block runs long after this function returned, from wherever the
    # caller is, and a name looked up at call time only works by load order (the same rule as Get-SIConnectorDefaultSecretReader).
    # (loaded into THIS scope when the job has not loaded it -- the value captured below outlives the scope)
    if (-not (Get-Command -Name Remove-SIBlob -CommandType Function -ErrorAction SilentlyContinue)) {
        $azRest = [System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-AzRest.ps1')
        if (Test-Path -LiteralPath $azRest) { . $azRest }
    }
    $rmFn = ${function:Remove-SIBlob}
    $rm =if ($rmFn) { { param($Path) & $rmFn -Account $acc -Container $con -Blob $Path }.GetNewClosure() }
          else { { param($Path) throw ('the state store cannot remove {0}: Remove-SIBlob is not loaded in this job (engine\_shared\SI-AzRest.ps1)' -f $Path) }.GetNewClosure() }
    $s | Add-Member -NotePropertyName Remove -NotePropertyValue $rm -Force
    $s
}

function ConvertTo-RAScaleOutHashtable {
    <# PURE. A parsed JSON object (PSCustomObject, PS 5.1 and 7) as nested hashtables / arrays. #>
    param($InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { $h = @{}; foreach ($k in @($InputObject.Keys)) { $h[[string]$k] = ConvertTo-RAScaleOutHashtable $InputObject[$k] }; return $h }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) { $h = @{}; foreach ($p in $InputObject.PSObject.Properties) { $h[$p.Name] = ConvertTo-RAScaleOutHashtable $p.Value }; return $h }
    if ($InputObject -is [string]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable]) { $l = New-Object System.Collections.Generic.List[object]; foreach ($e in $InputObject) { $l.Add((ConvertTo-RAScaleOutHashtable $e)) }; return , $l.ToArray() }
    $InputObject
}

function ConvertFrom-RAScaleOutJsonToken {
    param($Token)
    if ($null -eq $Token) { return $null }
    if ($Token -is [Newtonsoft.Json.Linq.JObject]) { $h = @{}; foreach ($p in $Token.Properties()) { $h[$p.Name] = ConvertFrom-RAScaleOutJsonToken $p.Value }; return $h }
    if ($Token -is [Newtonsoft.Json.Linq.JArray]) { $l = New-Object System.Collections.Generic.List[object]; foreach ($e in $Token.Children()) { $l.Add((ConvertFrom-RAScaleOutJsonToken $e)) }; return , $l.ToArray() }
    if ($Token -is [Newtonsoft.Json.Linq.JValue]) { return $Token.ToObject([object]) }
    [string]$Token
}

function ConvertFrom-RAScaleOutJson {
    <# PURE. JSON text -> nested hashtables / arrays, every text kept AS TEXT (PowerShell 7's ConvertFrom-Json turns a text
       that looks like a date into a [datetime] -- a collection time or a time text must come back exactly as written). #>
    param([Parameter(Mandatory)][string]$Text)
    if (-not ('Newtonsoft.Json.JsonConvert' -as [type])) { try { $null = ConvertFrom-Json -InputObject '{}' } catch { } }
    if ('Newtonsoft.Json.Linq.JToken' -as [type]) {
        $sr = New-Object System.IO.StringReader($Text)
        $jr = New-Object Newtonsoft.Json.JsonTextReader($sr)
        $jr.DateParseHandling = [Newtonsoft.Json.DateParseHandling]::None
        try { return (ConvertFrom-RAScaleOutJsonToken ([Newtonsoft.Json.Linq.JToken]::ReadFrom($jr))) } finally { $jr.Close() }
    }
    ConvertTo-RAScaleOutHashtable ($Text | ConvertFrom-Json)   # Windows PowerShell 5.1 leaves dates as text
}

function Read-RAScaleOutJson {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Path)
    $t = & $Store.Read $Path
    if ([string]::IsNullOrWhiteSpace([string]$t)) { return $null }
    ConvertFrom-RAScaleOutJson -Text ([string]$t)
}

function Write-RAScaleOutManifest {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Manifest)
    Write-SICollectManifest -Store $Store -Manifest $Manifest
}

function Read-RAScaleOutManifest {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    Read-RAScaleOutJson -Store $Store -Path (Get-SICollectPath -Engine $Engine -RunId $RunId)
}

function Test-RAScaleOutRunClosed {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    -not [string]::IsNullOrWhiteSpace([string](& $Store.Read (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind closed)))
}

function Test-RAScaleOutRunLive {
    <#
        #882 -- A WORKER OF A RUN THAT IS OVER WRITES NOTHING (live 2026-10-22, internal: the pipeline closed the Detailed step
        Interrupted at 09:40Z; its queue worker went on querying until 10:30 and wrote the remembered slice count the next run
        used). Asked before a worker writes anything shared (the remembered slice counts, their history, its hand-over) and
        at every query slice. FAIL CLOSED: the run is live only when this can be shown --
          * the run is not CLOSED in the state store (its producer finished it, a later producer closed it, or the pipeline
            ended the step: Close-SICollectRunsOf);
          * its manifest is still there;
          * -CollectionState (optional) { } -> the run's collection's state in the database: it must still be 'Loading'
            (a run whose collection was completed, failed or removed is over).
        A check that cannot be made (storage or the database not reachable) is NOT live. Returns @{ Live; Why }.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [scriptblock]$CollectionState)
    $o = { param($l, $w) [pscustomobject]@{ Live = [bool]$l; Why = [string]$w } }
    try {
        $c = & $Store.Read (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind closed)
        if (-not [string]::IsNullOrWhiteSpace([string]$c)) {
            $why = ''
            try { $j = ConvertFrom-RAScaleOutJson -Text ([string]$c); if ($j -and $j['Why']) { $why = [string]$j['Why'] } } catch { }
            return (& $o $false ('the run {0} is closed{1}' -f $RunId, $(if ($why) { ' (' + $why + ')' } else { '' })))
        }
        $m = & $Store.Read (Get-SICollectPath -Engine $Engine -RunId $RunId)
        if ([string]::IsNullOrWhiteSpace([string]$m)) { return (& $o $false ('the run {0} has no manifest any more' -f $RunId)) }
        if ($CollectionState) {
            $st = [string](& $CollectionState)
            if ($st -ne 'Loading') { return (& $o $false ('the run''s collection is not loading any more ({0})' -f $(if ($st) { $st } else { 'completed or removed' }))) }
        }
    } catch {
        return (& $o $false ('whether the run {0} is still the live one could not be checked ({1}) -- a worker writes nothing it cannot show is its live run''s' -f $RunId, $_.Exception.Message))
    }
    & $o $true ''
}

function Close-RAScaleOutRun {
    <# The run is over: a straggling message of it is discarded by any worker that takes it. Never throws. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [string]$Why = 'the run is over', [datetime]$Now = [datetime]::UtcNow)
    try { & $Store.Write (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind closed) (ConvertTo-Json -InputObject ([ordered]@{ ClosedUtc = $Now.ToUniversalTime().ToString('o'); Why = $Why }) -Compress); $true } catch { $false }
}

function Close-RAScaleOutEarlierRuns {
    <# A new producer closes every earlier run of the grain that was never closed (its producer stopped): their messages
       are then discarded, never run into a collection nobody completes. Returns the run ids closed. Never throws. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    $closed = New-Object System.Collections.Generic.List[string]
    try {
        $prefix = 'collect/{0}/' -f $Engine.ToLowerInvariant()
        $runs = @{}
        foreach ($p in @(& $Store.List $prefix)) {
            if (-not $p) { continue }
            $rest = ([string]$p).Substring($prefix.Length)
            $id = ($rest -split '/', 2)[0]
            if (-not $id -or $id -eq $RunId) { continue }
            if (-not $runs.ContainsKey($id)) { $runs[$id] = @{ Manifest = $false; Closed = $false } }
            if ($rest -eq "$id/manifest.json") { $runs[$id].Manifest = $true }
            if ($rest -eq "$id/closed.json") { $runs[$id].Closed = $true }
        }
        foreach ($id in @($runs.Keys | Sort-Object)) {
            if ($runs[$id].Manifest -and -not $runs[$id].Closed) {
                if (Close-RAScaleOutRun -Store $Store -Engine $Engine -RunId $id -Why ('a later run ({0}) started; this run''s producer did not finish' -f $RunId)) { $closed.Add($id) }
            }
        }
    } catch { }
    $closed.ToArray()
}

# ------------------------------------------------------------------------------------------------------------------
#  PRODUCER
# ------------------------------------------------------------------------------------------------------------------

function Publish-RAScaleOutItems {
    <# Queues one message per item of the manifest. Returns the messages queued. -Enqueue: a seam (param($Payload)).
       #831: LARGEST FIRST -- by the query slices each item asks (its Size: a part's range, a whole report's remembered
       count), ties in plan order -- so a big report, or the parts of a split one, starts at once instead of last. Only the
       order the workers TAKE the items changes: every item keeps its ordinal and write numbers, so the result's order in
       the database is the single job's. #>
    param([Parameter(Mandatory)]$Manifest, $Context, [string]$QueueName, [scriptblock]$Enqueue)
    if (-not $Enqueue) { Initialize-SIQueue -Context $Context -QueueName $QueueName | Out-Null }
    $n = 0
    $sizeOf = { param($x) $s = $x['Size']; if ($null -eq $s -or [int]$s -lt 1) { 1 } else { [int]$s } }
    foreach ($it in @(@($Manifest.Items) | Sort-Object -Property @{ Expression = { & $sizeOf $_ }; Descending = $true }, @{ Expression = { [int]$_['Item'] }; Ascending = $true })) {
        $payload = @{ RunId = [string]$Manifest.RunId; Engine = [string]$Manifest.Engine; Item = [int]$it.Item; Report = [string]$it.Report; Ordinal = [int]$it.Ordinal
                      ShardIndex = [int]$it.Item; ShardCount = [int]$Manifest.Parts; CollectionTime = [string]$Manifest.TimeText }
        # #831 B: one part of a split report -- which slices it runs
        if ($null -ne $it['Parts'] -and [int]$it['Parts'] -gt 1) { foreach ($k in 'Part', 'Parts', 'Buckets', 'From', 'To') { $payload[$k] = [int]$it[$k] } }
        if ($Enqueue) { & $Enqueue $payload } else { Add-SIWorkItem -Context $Context -QueueName $QueueName -Payload $payload }
        $n++
    }
    $n
}

function Get-RAScaleOutStarted {
    <# The items a worker has started (their started marks), item -> worker. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Manifest)
    $out = @{}
    $prefix = 'collect/{0}/{1}/started/' -f ([string]$Manifest.Engine).ToLowerInvariant(), [string]$Manifest.RunId
    foreach ($p in @(& $Store.List $prefix)) {
        if (-not $p) { continue }
        if ([string]$p -match 'item-(\d+)\.json$') {
            $w = ''
            try { $j = Read-RAScaleOutJson -Store $Store -Path ([string]$p); if ($j) { $w = [string]$j['Worker'] } } catch { }
            $out[[int]$Matches[1]] = $w
        }
    }
    $out
}

function Format-RAScaleOutProgress {
    <# PURE. One progress line: done / failed / started / waiting of the run's items. #>
    param([int]$Items, [int]$Done, [int]$Failed, [int]$Started)
    $running = [Math]::Max(0, $Started - $Done - $Failed)
    $waiting = [Math]::Max(0, $Items - $Done - $Failed - $running)
    '[scale-out] {0} of {1} report(s) done{2}, {3} running, {4} waiting for a worker' -f $Done, $Items, $(if ($Failed) { ', {0} failed' -f $Failed } else { '' }), $running, $waiting
}

function Wait-RAScaleOutItems {
    <#
        The producer waits until every item has its marker (done or failed). Progress every -ProgressSeconds. -LocalWorker
        (param()) runs a worker in this container and returns when it has drained the queue:
          -UseKeda $false  the local worker is the worker: run at once, and again while items are left without a marker
                           (a crashed attempt's item comes back to the queue after its lease: the next run waits for
                           -LeaseSeconds after the last one ended), at most -MaxLocalRuns times;
          -UseKeda $true   the queue-scaled workers take the items; if NONE has started an item -StartGraceMinutes after the
                           queueing, the local worker runs (said), then the wait goes on.
        -TimeoutMinutes 0 = no give-up on elapsed time (as the collection's step). Returns @{ State; Markers; Text }.
        Seams: -Sleep (param($Seconds)), -Now (scriptblock), -Log (param($Level, $Text)).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Manifest, [scriptblock]$LocalWorker, [bool]$UseKeda = $true,
          [int]$StartGraceMinutes = $script:RAScaleOut.StartGraceMinutes, [int]$TimeoutMinutes = 0, [int]$PollSeconds = $script:RAScaleOut.PollSeconds,
          [int]$ProgressSeconds = $script:RAScaleOut.ProgressSeconds, [int]$MaxLocalRuns = ($script:RAScaleOut.MaxDequeue + 1), [int]$LeaseSeconds = 660,
          [scriptblock]$Sleep, [scriptblock]$Now, [scriptblock]$Log)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    if (-not $Now) { $Now = { [datetime]::UtcNow } }
    if (-not $Log) { $Log = { param($l, $t) Write-Host $t } }
    $engine = [string]$Manifest.Engine; $runId = [string]$Manifest.RunId; $n = [int]$Manifest.Parts
    $t0 = & $Now
    $lastProgress = [datetime]::MinValue
    $localRuns = 0; $graceUsed = $false; $nextLocalAt = [datetime]::MinValue
    while ($true) {
        $markers = @(Read-SICollectPartMarkers -Store $Store -Engine $engine -RunId $runId)
        $prog = Get-SICollectProgress -Manifest ([pscustomobject]@{ Parts = $n; WrittenUtc = $t0.ToString('o') }) -Markers $markers -Now (& $Now) -TimeoutMinutes $TimeoutMinutes
        $done = [int]$prog.Done; $failed = @($prog.Failed).Count
        if ($prog.State -in 'succeeded', 'failed', 'incomplete') {
            & $Log 'INFO' (Format-RAScaleOutProgress -Items $n -Done $done -Failed $failed -Started ($done + $failed))
            return [pscustomobject]@{ State = [string]$prog.State; Markers = $markers; Text = [string]$prog.Text; LocalRuns = $localRuns }
        }
        $started = Get-RAScaleOutStarted -Store $Store -Manifest $Manifest
        $nowT = & $Now
        if (($nowT - $lastProgress).TotalSeconds -ge $ProgressSeconds) {
            & $Log 'INFO' (Format-RAScaleOutProgress -Items $n -Done $done -Failed $failed -Started $started.Count)
            $lastProgress = $nowT
        }
        $runLocal = $false
        if ($LocalWorker) {
            if (-not $UseKeda -and $localRuns -lt $MaxLocalRuns -and $nowT -ge $nextLocalAt) { $runLocal = $true }
            elseif ($UseKeda -and -not $graceUsed -and $started.Count -eq 0 -and ($nowT - $t0).TotalMinutes -ge $StartGraceMinutes) {
                & $Log 'WARN' ('[scale-out] no worker has started a report {0} minute(s) after they were queued -- this job runs a worker itself, so the run does not wait' -f $StartGraceMinutes)
                $graceUsed = $true; $runLocal = $true
            }
        }
        if ($runLocal) {
            $localRuns++
            if (-not $UseKeda) { & $Log 'INFO' ('[scale-out] this job runs the worker itself (run {0}) -- no queue-scaled worker job is set up for this install' -f $localRuns) }
            try { & $LocalWorker } catch { & $Log 'WARN' ('[scale-out] the worker in this job ended with an error: {0}' -f $_.Exception.Message) }
            # a report its run could not finish comes back to the queue when its hold ends -- the next run waits for that
            $nextLocalAt = (& $Now).AddSeconds($LeaseSeconds)
            continue
        }
        if (-not $UseKeda -and $LocalWorker -and $localRuns -ge $MaxLocalRuns) {
            # the local worker ran as often as an item may be handed out; what is still without a marker never will be
            & $Log 'WARN' '[scale-out] the worker in this job ran as often as a report may be tried; the reports still open are NOT COMPLETE'
            return [pscustomobject]@{ State = 'incomplete'; Markers = $markers; Text = ('the worker in this job ran {0} time(s) and {1} report(s) are still open' -f $localRuns, ($n - $done - $failed)); LocalRuns = $localRuns }
        }
        & $Sleep $PollSeconds
    }
}

function Read-RAScaleOutHandovers {
    <# item -> the hand-over its worker wrote (hashtables), for every item that has one. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Manifest)
    $out = @{}
    foreach ($it in @($Manifest.Items)) {
        $p = Get-RAScaleOutPath -Engine ([string]$Manifest.Engine) -RunId ([string]$Manifest.RunId) -Kind handover -Item ([int]$it.Item)
        try { $h = Read-RAScaleOutJson -Store $Store -Path $p; if ($null -ne $h) { $out[[int]$it.Item] = $h } } catch { }
    }
    $out
}

function Get-RAScaleOutItemFailures {
    <#
        PURE. The reports the producer must call NOT COMPLETE because their ITEM did not deliver: a failed marker (its cause),
        no marker (the wait ended), or a done marker without a readable hand-over. -Markers: the part markers; -Handovers:
        item -> hand-over. Returns @(@{ Report; Why }).
    #>
    # #831 B: a split report is ONE report over several items -- it fails ONCE, with the first cause in part order; and when
    # every part finished but no part put the report together (its full hand-over), it is NOT COMPLETE too
    param([Parameter(Mandatory)]$Manifest, [AllowEmptyCollection()][object[]]$Markers = @(), [hashtable]$Handovers = @{})
    $byItem = @{}
    foreach ($m in @($Markers)) { if ($null -ne $m -and $null -ne $m.Part) { $byItem[[int]$m.Part] = $m } }
    $out = New-Object System.Collections.Generic.List[object]
    $order = New-Object System.Collections.Generic.List[string]
    $items = @{}
    foreach ($it in @($Manifest.Items)) { $r = [string]$it.Report; if (-not $items.ContainsKey($r)) { $items[$r] = New-Object System.Collections.Generic.List[object]; $order.Add($r) }; $items[$r].Add($it) }
    foreach ($r in $order) {
        $why = ''; $split = ($items[$r].Count -gt 1); $whole = $false
        foreach ($it in $items[$r]) {
            $i = [int]$it.Item
            $pre = ''; $pn = ''; if ($split) { $pn = 'part {0} of {1}' -f ([int]$it.Part + 1), $items[$r].Count; $pre = $pn + ': ' }
            if (-not $byItem.ContainsKey($i)) { if (-not $why) { $why = $(if ($split) { 'its work item ({0}) was not finished by a worker in this run' -f $pn } else { 'its work item was not finished by a worker in this run' }) }; continue }
            $m = $byItem[$i]
            if ([string]$m.State -eq 'failed') { if (-not $why) { $why = ('its work item failed: {0}{1}' -f $pre, $(if ([string]$m.Reason) { [string]$m.Reason } else { 'no reason was given' })) }; continue }
            if (-not $Handovers.ContainsKey($i)) { if (-not $why) { $why = ('{0}its worker finished, but what it found could not be read back' -f $pre) }; continue }
            if (@($Handovers[$i]['Reports']) -contains $r) { $whole = $true }
        }
        if (-not $why -and $split -and -not $whole) { $why = ('its {0} parts finished, but none of them put the report together' -f $items[$r].Count) }
        if ($why) { $out.Add([pscustomobject]@{ Report = $r; Why = $why }) }
    }
    $out.ToArray()
}

# ------------------------------------------------------------------------------------------------------------------
#  #831 A -- HOW MANY ITEMS OF THE RUN ARE STILL OPEN (the free Defender budget of the last workers)
# ------------------------------------------------------------------------------------------------------------------

function Get-RAScaleOutOpenItems {
    <#
        The run's items that have no marker yet -- ONE listing of the run's markers (what the run already records; no new
        shared state, no lease and no heartbeat read: a worker whose heartbeat cannot renew is still counted while its item
        is open). At most that many workers can still be running an item of the run, so a worker that divides the budget by
        it never asks more than the whole budget with the others (Get-RAPartsInParallelShare). -1 when it cannot be told.
    #>
    param($Store, $Manifest)
    try {
        if ($null -eq $Store -or $null -eq $Manifest) { return -1 }
        $n = [int]$Manifest['Parts']; $eng = [string]$Manifest['Engine']; $run = [string]$Manifest['RunId']
        if ($n -le 0 -or -not $eng -or -not $run) { return -1 }
        $prefix = 'collect/{0}/{1}/parts/' -f $eng.ToLowerInvariant(), $run
        $done = @(@(& $Store.List $prefix) | Where-Object { [string]$_ -match 'part-\d+\.json$' }).Count
        [Math]::Max(0, $n - $done)
    } catch { -1 }
}

# ------------------------------------------------------------------------------------------------------------------
#  #831 B -- ONE REPORT IN SEVERAL PARTS: what each part found, and the part that puts the report together
# ------------------------------------------------------------------------------------------------------------------

function Get-RAScaleOutSiblings {
    <# PURE. The items of the run's manifest that are parts of -Report, in part order. #>
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$Report)
    @(@($Manifest['Items']) | Where-Object { $null -ne $_ -and [string]$_['Report'] -eq $Report } | Sort-Object { [int]$_['Part'] })
}

function New-RAScaleOutPartial {
    <#
        PURE over -State. What ONE part of a split report found, for the part that puts the report together: the entries it
        added to the run's lists (since -Mark), its stream entry (rows retrieved, the per-slice accounts, the columns and date
        columns), the report's row count, column fill, retry answers and start time in this process, its lost slices
        (-BucketLoss), why it found nothing applicable, and -Evidence: what the bucket learning needs of its slices (splits,
        busy slices, late retries, the measure) and how it ended (Complete: a slice returned the whole report, #401;
        CannotFit / Failed: the report cannot be in this run).
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][hashtable]$Mark, [Parameter(Mandatory)][string]$Report, [int]$Item = 0, [int]$Part = 0, [int]$Parts = 1,
          $Entry = $null, [AllowEmptyCollection()][string[]]$BucketLoss = @(), [hashtable]$Evidence = @{}, [string]$NotApplicableWhy = '', [string]$Worker = '')
    $lists = [ordered]@{}
    foreach ($k in 'Failures', 'BucketLossRun', 'Jumps', 'Attempted', 'PublishFailures', 'IngestRefused', 'NotDelivered', 'IngestNotes') {
        $lists[$k] = @(foreach ($x in @(Get-RAScaleOutSince -List $State[$k] -From ([int]$Mark[$k]))) { ConvertTo-RAScaleOutPlain $x })
    }
    $one = { param($k) $t = $State[$k]; if ($null -ne $t -and $t -is [System.Collections.IDictionary] -and $t.Contains($Report)) { ConvertTo-RAScaleOutPlain $t[$Report] } else { $null } }
    $note = & $one 'Notes'
    $st = [ordered]@{ Retrieved = 0L; Account = [ordered]@{}; Columns = @(); DateCols = @() }
    if ($null -ne $Entry) {
        $st.Retrieved = [long]$Entry.Retrieved
        $st.Account = ConvertTo-RAScaleOutPlain $Entry.Account
        $st.Columns = @($Entry.Columns)
        $st.DateCols = @($Entry.DateCols)
    }
    [ordered]@{ Schema = 1; Item = $Item; Part = $Part; Parts = $Parts; Report = $Report; Worker = $Worker; WrittenUtc = [datetime]::UtcNow.ToString('o')
                Lists = $lists; Stream = $st; RowCount = (& $one 'RowCounts'); ColumnFill = (& $one 'ColumnFill'); Retries = (& $one 'Retries')
                StartedUtc = $(if ($note -and $note['StartedUtc']) { [string]$note['StartedUtc'] } else { '' })
                BucketLoss = @($BucketLoss | Where-Object { $_ }); NotApplicableWhy = [string]$NotApplicableWhy; Evidence = (ConvertTo-RAScaleOutPlain $Evidence) }
}

function Write-RAScaleOutPartial {
    <# This part's slices are in the database and what it found is kept: the part is DONE (a retry of it does not run its
       slices again). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)]$Partial)
    & $Store.Write (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind partial -Item ([int]$Partial['Item'])) (ConvertTo-Json -InputObject $Partial -Compress -Depth 12)
}

function Read-RAScaleOutPartial {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][int]$Item)
    try { Read-RAScaleOutJson -Store $Store -Path (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind partial -Item $Item) } catch { $null }
}

function Request-RAScaleOutFinish {
    <#
        Called by a part right after its own partial is written. The LAST part to finish puts the report together: when every
        part's partial is there, the part claims the report (a create-only blob, so exactly one does it; the retry of the
        part that claimed it may claim it again). Never a wait: a part whose siblings are still running ends its item, and
        one of them finishes the report. Returns @{ Finisher; Partials (item -> partial, part order); Missing; Why }.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][int]$Ordinal,
          [Parameter(Mandatory)][int]$Item, [Parameter(Mandatory)][int[]]$Siblings, [string]$Worker = '')
    $parts = [ordered]@{}; $missing = 0
    foreach ($s in @($Siblings)) { $p = Read-RAScaleOutPartial -Store $Store -Engine $Engine -RunId $RunId -Item ([int]$s); if ($null -eq $p) { $missing++ } else { $parts[[string]$s] = $p } }
    if ($missing -gt 0) { return [pscustomobject]@{ Finisher = $false; Partials = $null; Missing = $missing; Why = ('{0} other part(s) of the report are still running -- the last one puts the report together' -f $missing) } }
    $path = Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind finish -Item $Ordinal
    $mine = $false
    if (& $Store.Claim $path (ConvertTo-Json -InputObject ([ordered]@{ Item = $Item; Worker = $Worker; ClaimedUtc = [datetime]::UtcNow.ToString('o') }) -Compress)) { $mine = $true }
    else { $c = $null; try { $c = Read-RAScaleOutJson -Store $Store -Path $path } catch { }; if ($c -and [int]$c['Item'] -eq $Item) { $mine = $true } }
    if (-not $mine) { return [pscustomobject]@{ Finisher = $false; Partials = $null; Missing = 0; Why = 'another part puts the report together' } }
    [pscustomobject]@{ Finisher = $true; Partials = $parts; Missing = 0; Why = '' }
}

function Merge-RAScaleOutMeasure {
    <# PURE. The bucket learning's measure of a report (Reset-AutoBucketMeasure's fields) over its parts: counts added, the
       largest values kept. #>
    param([AllowEmptyCollection()][object[]]$Measures = @())
    $m = [ordered]@{ ResultRows = 0L; MaxBucketRows = 0L; MaxBucketBytes = 0L; MaxRequestBytes = 0L; SplitRows = 0L; SplitBytes = 0L; MaxFixedBytes = 0L; Slices = 0; MaxBucketSeconds = 0.0 }
    foreach ($x in @($Measures)) {
        if ($null -eq $x) { continue }
        $g = { param($k) if ($x -is [System.Collections.IDictionary]) { $x[$k] } elseif ($x.PSObject.Properties[$k]) { $x.$k } else { $null } }
        foreach ($k in 'ResultRows', 'SplitRows', 'SplitBytes') { $m[$k] = [long]$m[$k] + [long](& $g $k) }
        $m['Slices'] = [int]$m['Slices'] + [int](& $g 'Slices')
        foreach ($k in 'MaxBucketRows', 'MaxBucketBytes', 'MaxRequestBytes', 'MaxFixedBytes') { $v = [long](& $g $k); if ($v -gt [long]$m[$k]) { $m[$k] = $v } }
        $s = [double](& $g 'MaxBucketSeconds'); if ($s -gt [double]$m['MaxBucketSeconds']) { $m['MaxBucketSeconds'] = $s }
    }
    [pscustomobject]$m
}

function Merge-RAScaleOutPartials {
    <#
        PURE. The parts of ONE split report as the single job's one run of it (-Partials: item -> partial, any order; sorted by
        part here). Returns @{ Problem; CannotFit; Failed; Complete; Drop (items whose rows go: another part's slice returned
        the whole report); Retrieved; Account; Columns; DateCols; RowCount; ColumnFill; Retries; StartedUtc; NotApplicableWhy;
        BucketLoss; Lists; Evidence }:
          * counts and accounts added up, columns in part order (first seen), lost slices in part order, the lists' entries
            in part order (a report name in Attempted once);
          * the bucket learning: a split used anywhere, the split buckets and busy slices and late retries added, the finest
            working count, every split bucket's own answer, the measure (Merge-RAScaleOutMeasure);
          * #401: when part 1 returned the whole report in one slice, it IS the report -- the other parts' rows go (Drop);
            a later part that did so while part 1 did not = Problem (the report is not complete, never doubled);
          * a part that could not fit / failed = Problem (the report is not in this run).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Partials)
    $ps = @(@($Partials.Values) | Where-Object { $null -ne $_ } | Sort-Object { [int]$_['Part'] })
    $ev = { param($p, $k) $e = $p['Evidence']; if ($null -ne $e -and $e -is [System.Collections.IDictionary] -and $e.Contains($k)) { $e[$k] } else { $null } }
    $o = [ordered]@{ Problem = ''; CannotFit = ''; Failed = ''; Complete = $false; Drop = @(); Retrieved = 0L; Account = @{}; Columns = @(); DateCols = @(); RowCount = 0; ColumnFill = $null
                     Retries = $null; StartedUtc = ''; NotApplicableWhy = ''; BucketLoss = @(); Lists = [ordered]@{}; Evidence = $null }
    foreach ($p in $ps) {
        if (-not $o.CannotFit -and [string](& $ev $p 'CannotFit')) { $o.CannotFit = [string](& $ev $p 'CannotFit') }
        if (-not $o.Failed -and [string](& $ev $p 'Failed')) { $o.Failed = [string](& $ev $p 'Failed') }
    }
    $kept = $ps
    if ($ps.Count -and [bool](& $ev $ps[0] 'Complete')) {
        $o.Complete = $true; $kept = @($ps[0]); $o.Drop = @($ps | Select-Object -Skip 1 | ForEach-Object { [int]$_['Item'] })
    } elseif (@($ps | Where-Object { [bool](& $ev $_ 'Complete') }).Count) {
        $o.Problem = 'a later part of the report returned its whole result in one query slice and the first part did not -- the parts do not add up to the report'
    }
    if ($o.CannotFit) { $o.Problem = [string]$o.CannotFit } elseif ($o.Failed -and -not $o.Problem) { $o.Problem = [string]$o.Failed }
    $cols = $null; $dates = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $loss = New-Object System.Collections.Generic.List[string]
    $measures = New-Object System.Collections.Generic.List[object]
    $slices = [ordered]@{}
    $e2 = [ordered]@{ SplitUsed = $false; SplitBuckets = 0; SplitWorking = 0; BusySlices = 0; Deferred = 0; MemSplit = 0; SplitSlices = $slices; Measure = $null }
    foreach ($p in $kept) {
        $s = $p['Stream']
        if ($s) {
            $o.Retrieved = [long]$o.Retrieved + [long]$s['Retrieved']
            if ($s['Account'] -is [System.Collections.IDictionary]) { foreach ($k in @($s['Account'].Keys)) { $o.Account[[string]$k] = $s['Account'][$k] } }
            $cols = Merge-RAScaleOutColumns -Into $cols -Add @($s['Columns'] | Where-Object { $_ }) -TraceCols @()
            foreach ($c in @($s['DateCols'])) { if ($c) { [void]$dates.Add([string]$c) } }
        }
        if ($null -ne $p['RowCount']) { $o.RowCount = [int]$o.RowCount + [int]$p['RowCount'] }
        if ($p['ColumnFill'] -is [System.Collections.IDictionary]) {
            if ($null -eq $o.ColumnFill) { $o.ColumnFill = @{} }
            foreach ($k in @($p['ColumnFill'].Keys)) { $o.ColumnFill[[string]$k] = [long]$o.ColumnFill[[string]$k] + [long]$p['ColumnFill'][$k] }
        }
        if ($p['Retries'] -is [System.Collections.IDictionary]) {
            if ($null -eq $o.Retries) { $o.Retries = @{} }
            foreach ($k in @($p['Retries'].Keys)) { $o.Retries[[string]$k] = [long]$o.Retries[[string]$k] + [long]$p['Retries'][$k] }
        }
        foreach ($x in @($p['BucketLoss'])) { if ($x) { $loss.Add([string]$x) } }
        if (-not $o.NotApplicableWhy -and [string]$p['NotApplicableWhy']) { $o.NotApplicableWhy = [string]$p['NotApplicableWhy'] }
        if ([bool](& $ev $p 'SplitUsed')) { $e2.SplitUsed = $true }
        foreach ($k in 'SplitBuckets', 'BusySlices', 'Deferred', 'MemSplit') { $e2[$k] = [int]$e2[$k] + [int](& $ev $p $k) }
        if ([int](& $ev $p 'SplitWorking') -gt [int]$e2.SplitWorking) { $e2.SplitWorking = [int](& $ev $p 'SplitWorking') }
        $sl = & $ev $p 'SplitSlices'
        if ($sl -is [System.Collections.IDictionary]) { foreach ($k in @($sl.Keys)) { $slices[[string]$k] = $sl[$k] } }
        $measures.Add((& $ev $p 'Measure'))
    }
    # the start of the report: its earliest part
    foreach ($p in $ps) {
        $t = [string]$p['StartedUtc']; if (-not $t) { continue }
        if (-not $o.StartedUtc) { $o.StartedUtc = $t; continue }
        $a = [datetime]::MinValue; $b = [datetime]::MinValue
        if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$a) -and
            [datetime]::TryParse([string]$o.StartedUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$b) -and $a.ToUniversalTime() -lt $b.ToUniversalTime()) { $o.StartedUtc = $t }
    }
    # every part's list entries in part order (the dropped parts' too: what a part did is never hidden), a report attempted once
    foreach ($k in 'Failures', 'BucketLossRun', 'Jumps', 'Attempted', 'PublishFailures', 'IngestRefused', 'NotDelivered', 'IngestNotes') {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($p in $ps) { if ($p['Lists']) { foreach ($x in @($p['Lists'][$k])) { if ($null -eq $x) { continue }; if ($k -eq 'Attempted' -and $l.Contains([string]$x)) { continue }; $l.Add($x) } } }
        $o.Lists[$k] = $l.ToArray()
    }
    $o.Columns = $(if ($null -eq $cols) { @() } else { @($cols) })
    $o.DateCols = @($dates)
    $o.BucketLoss = $loss.ToArray()
    $e2.Measure = Merge-RAScaleOutMeasure -Measures $measures.ToArray()
    $o.Evidence = [pscustomobject]$e2
    [pscustomobject]$o
}

# ------------------------------------------------------------------------------------------------------------------
#  THE HAND-OVER: what the report loop knew about a report, from the worker to the producer
# ------------------------------------------------------------------------------------------------------------------

function Get-RAScaleOutListCount {
    # (.Count, never @($List): @() around a List[object] throws "Argument types do not match")
    param($List) if ($null -eq $List) { return 0 }; if ($List -is [System.Collections.ICollection]) { return [int]$List.Count }; @($List).Count
}

function Start-RAScaleOutItemState {
    <# The mark an item's hand-over is measured from: the lengths of the run's lists and the run's counters before the item. #>
    param([Parameter(Mandatory)][hashtable]$State, [hashtable]$Counters = @{})
    $m = @{}
    foreach ($k in 'Failures', 'BucketLossRun', 'Jumps', 'Attempted', 'PublishFailures', 'IngestRefused', 'NotDelivered', 'IngestNotes') { $m[$k] = Get-RAScaleOutListCount $State[$k] }
    foreach ($k in @($Counters.Keys)) { $m['C:' + $k] = [double]$Counters[$k] }
    $m
}

function Get-RAScaleOutSince {
    <# PURE. The entries of a list added since -From (its length at the mark). #>
    param($List, [int]$From = 0)
    # (the entries one by one into the pipeline: a caller collects them with @(...))
    if ($null -eq $List) { return }
    $i = 0
    foreach ($e in $List) { if ($i -ge $From) { $e }; $i++ }
}

function ConvertTo-RAScaleOutPlain {
    <# PURE. A value made safe for the hand-over's JSON: dates as round-trip text, hashtables / objects as plain maps. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [System.Collections.IDictionary]) { $o = [ordered]@{}; foreach ($k in @($Value.Keys)) { $o[[string]$k] = ConvertTo-RAScaleOutPlain $Value[$k] }; return $o }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { $o = [ordered]@{}; foreach ($p in $Value.PSObject.Properties) { $o[$p.Name] = ConvertTo-RAScaleOutPlain $p.Value }; return $o }
    if ($Value -is [System.Collections.IEnumerable]) { return , @(foreach ($e in $Value) { ConvertTo-RAScaleOutPlain $e }) }
    $Value
}

function New-RAScaleOutHandover {
    <#
        PURE over -State. What the producer needs of ONE item's reports to finish the run as the single job would: per report
        its row count, column fill, verdict, note, query fingerprint, retry answers, the stream's report entry (ordinal,
        columns, date columns, rows retrieved), hand-off verdicts (#674) and Defender comparison (#673); and the entries the
        item added to the run's lists (failures, lost buckets, bucket jumps, attempted reports, Log Analytics failures and
        notes), the counters it moved (exempted not counted, disabled-filtered reports, illegal names) and the report's
        columns in first-seen order. -Reports: the item's report names.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)][hashtable]$Mark, [hashtable]$Counters = @{},
          # #831 B: @() for a part of a split report that did not put the report together -- it hands over only its counters,
          # columns, KQL types and (-NoLists: they went into its partial) no list entries
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Reports, [int]$Item = 0, [string[]]$FinalDesiredColumns = @(), [string]$Worker = '',
          # the result in the database could not be kept whole by this worker (its stream's Broken) -- the run cannot complete
          [string]$Broken = '', [switch]$NoLists, [string[]]$NoCounters = @(),
          # #877: the reports this worker HELD BACK (their rows of this run could not be removed): @{ Report; Ordinal; Cause } each
          [AllowEmptyCollection()][object[]]$Held = @())
    $per = [ordered]@{}
    foreach ($r in @($Reports)) {
        $e = [ordered]@{}
        foreach ($k in 'RowCounts', 'ColumnFill', 'StatusDone', 'Notes', 'QueryHash', 'Retries', 'EmptyGivers', 'DfcCompare') {
            $t = $State[$k]
            if ($null -ne $t -and $t -is [System.Collections.IDictionary] -and $t.Contains($r)) { $e[$k] = ConvertTo-RAScaleOutPlain $t[$r] }
        }
        $st = $State['Stream']
        if ($null -ne $st -and $st.Reports -and $st.Reports.Contains($r)) {
            $sr = $st.Reports[$r]
            $e['Stream'] = [ordered]@{ Ordinal = [int]$sr.Ordinal; Columns = @($sr.Columns); DateCols = @($sr.DateCols); Retrieved = [long]$sr.Retrieved; Staged = [bool]$sr.Staged
                                      StageCols = $(if ($sr.StageCols) { @($sr.StageCols) } else { @() }); Pages = [int]$sr.Pages }
        }
        $per[$r] = $e
    }
    $lists = [ordered]@{}
    foreach ($k in 'Failures', 'BucketLossRun', 'Jumps', 'Attempted', 'PublishFailures', 'IngestRefused', 'NotDelivered', 'IngestNotes') {
        if ($NoLists) { $lists[$k] = @(); continue }
        $lists[$k] = @(foreach ($x in @(Get-RAScaleOutSince -List $State[$k] -From ([int]$Mark[$k]))) { ConvertTo-RAScaleOutPlain $x })
    }
    $ctr = [ordered]@{}
    foreach ($k in @($Counters.Keys)) { if (@($NoCounters) -contains [string]$k) { $ctr[$k] = 0.0; continue }; $ctr[$k] = [double]$Counters[$k] - [double]$Mark['C:' + $k] }
    # the KQL column types the queries declared (the workbook's one-type-per-column decision, #242) -- order-free
    $kt = [ordered]@{}
    if ($null -ne $State['KqlTypes']) { foreach ($k in @($State['KqlTypes'].Keys)) { $kt[[string]$k] = [string]$State['KqlTypes'][$k] } }
    [ordered]@{ Schema = 1; Item = $Item; Reports = @($Reports); Worker = $Worker; WrittenUtc = [datetime]::UtcNow.ToString('o')
                PerReport = $per; Lists = $lists; Counters = $ctr; FinalDesiredColumns = @($FinalDesiredColumns | Where-Object { $_ })
                KqlTypes = $kt; Broken = $Broken
                Held = @(foreach ($x in @($Held)) { if ($null -ne $x -and [string]$x.Report) { [ordered]@{ Report = [string]$x.Report; Ordinal = [int]$x.Ordinal; Cause = [string]$x.Cause } } }) }
}

function Merge-RAScaleOutColumns {
    <# PURE. The run's report columns as the single job unions them: first-seen order, case-insensitive, the trace columns
       last (Invoke-RAReportRows -- the union across reports). -Into: the columns so far ($null = none). #>
    param([AllowNull()][string[]]$Into, [AllowEmptyCollection()][string[]]$Add = @(), [string[]]$TraceCols = @('CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID'))
    if (-not @($Add).Count) { return $Into }
    if ($null -eq $Into -or -not @($Into).Count) { return @($Add) }
    $merged = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Into) { if ($seen.Add($c)) { [void]$merged.Add($c) } }
    foreach ($c in $Add) { if ($seen.Add($c)) { [void]$merged.Add($c) } }
    foreach ($t in $TraceCols) { for ($i = $merged.Count - 1; $i -ge 0; $i--) { if ([string]::Equals($merged[$i], $t, [System.StringComparison]::OrdinalIgnoreCase)) { $merged.RemoveAt($i) } } }
    foreach ($t in $TraceCols) { [void]$merged.Add($t) }
    $merged.ToArray()
}

function ConvertFrom-RAScaleOutNote {
    <# PURE. A report note back from the hand-over: its times as [datetime] again. #>
    param($Note)
    $h = @{}
    if ($null -eq $Note) { return $h }
    foreach ($k in @($Note.Keys)) {
        $v = $Note[$k]
        if ($k -in 'StartedUtc', 'EndedUtc' -and $v -is [string]) { $d = [datetime]::MinValue; if ([datetime]::TryParse($v, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$d)) { $v = $d.ToUniversalTime() } }
        $h[$k] = $v
    }
    $h
}

function Merge-RAScaleOutHandovers {
    <#
        Applies the workers' hand-overs to the producer's run state (-State: the live collections the report loop fills), in
        the ORDER the single job ran the reports (ordinal), so every list and union reads as if one process had run them.
        Returns @{ Counters (summed); FinalDesiredColumns; StreamReports (name -> entry, for the stream); Reports (names
        merged, in order); Broken }.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [Parameter(Mandatory)]$Manifest, [hashtable]$Handovers = @{})
    $ord = @{}; foreach ($it in @($Manifest.Items)) { $ord[[int]$it.Item] = [int]$it.Ordinal }
    # the single job's order: the report's ordinal, then (#831 B, the parts of a split report) the item
    $order = @($Handovers.Keys | Sort-Object { [int]$ord[[int]$_] }, { [int]$_ })
    $ctr = @{}; $cols = $null; $streamReports = [ordered]@{}; $names = New-Object System.Collections.Generic.List[string]; $broken = New-Object System.Collections.Generic.List[string]
    $held = New-Object System.Collections.Generic.List[object]
    $ensureHash = { param($k) if ($null -eq $State[$k]) { $State[$k] = @{} } }
    foreach ($i in $order) {
        $h = $Handovers[$i]
        foreach ($r in @($h['Reports'])) {
            $names.Add([string]$r)
            $e = $h['PerReport'][[string]$r]
            if ($null -eq $e) { continue }
            if ($e.ContainsKey('RowCounts')) { & $ensureHash 'RowCounts'; $State['RowCounts'][[string]$r] = [int]$e['RowCounts'] }
            if ($e.ContainsKey('ColumnFill')) { & $ensureHash 'ColumnFill'; $cf = @{}; foreach ($k in @($e['ColumnFill'].Keys)) { $cf[$k] = [long]$e['ColumnFill'][$k] }; $State['ColumnFill'][[string]$r] = $cf }
            if ($e.ContainsKey('StatusDone')) { & $ensureHash 'StatusDone'; $State['StatusDone'][[string]$r] = [string]$e['StatusDone'] }
            if ($e.ContainsKey('Notes')) { & $ensureHash 'Notes'; $State['Notes'][[string]$r] = ConvertFrom-RAScaleOutNote $e['Notes'] }
            if ($e.ContainsKey('QueryHash')) { & $ensureHash 'QueryHash'; $State['QueryHash'][[string]$r] = [string]$e['QueryHash'] }
            if ($e.ContainsKey('Retries')) { & $ensureHash 'Retries'; $rt = @{}; foreach ($k in @($e['Retries'].Keys)) { $rt[$k] = [long]$e['Retries'][$k] }; $State['Retries'][[string]$r] = $rt }
            if ($e.ContainsKey('DfcCompare')) { & $ensureHash 'DfcCompare'; $State['DfcCompare'][[string]$r] = $e['DfcCompare'] }
            if ($e.ContainsKey('Stream')) { $streamReports[[string]$r] = $e['Stream'] }
        }
        $l = $h['Lists']
        if ($l) {
            foreach ($f in @($l['Failures'])) { if ($f -and $null -ne $State['Failures']) { [void]$State['Failures'].Add(@{ Report = [string]$f['Report']; Why = [string]$f['Why'] }) } }
            foreach ($x in @($l['BucketLossRun'])) { if ($x -and $null -ne $State['BucketLossRun']) { [void]$State['BucketLossRun'].Add([string]$x) } }
            foreach ($x in @($l['Jumps'])) { if ($null -ne $x -and $null -ne $State['Jumps']) { [void]$State['Jumps'].Add([pscustomobject]$x) } }
            # (a report attempted once: the parts of a split report that could not hand theirs to a finisher name it too)
            foreach ($x in @($l['Attempted'])) { if ($x -and $null -ne $State['Attempted'] -and -not $State['Attempted'].Contains([string]$x)) { [void]$State['Attempted'].Add([string]$x) } }
            foreach ($k in 'PublishFailures', 'IngestRefused', 'NotDelivered') { foreach ($x in @($l[$k])) { if ($x -and $null -ne $State[$k]) { [void]$State[$k].Add([string]$x) } } }
            foreach ($x in @($l['IngestNotes'])) { if ($null -ne $x -and $null -ne $State['IngestNotes']) { [void]$State['IngestNotes'].Add([pscustomobject]@{ Table = [string]$x['Table']; Columns = @($x['Columns']); Message = [string]$x['Message']; Kind = $(if ($x['Kind']) { [string]$x['Kind'] } else { 'incomplete' }) }) } }
        }
        if ($h['Counters']) { foreach ($k in @($h['Counters'].Keys)) { $ctr[$k] = [double]$ctr[$k] + [double]$h['Counters'][$k] } }
        $cols = Merge-RAScaleOutColumns -Into $cols -Add @($h['FinalDesiredColumns'])
        if ([string]$h['Broken']) { $broken.Add([string]$h['Broken']) }
        # #877: the reports the item held back (a hand-over from before has none)
        foreach ($x in @($h['Held'])) { if ($null -ne $x -and [string]$x.Report) { $held.Add([pscustomobject]@{ Report = [string]$x.Report; Ordinal = [int]$x.Ordinal; Cause = [string]$x.Cause }) } }
    }
    # hand-off verdicts (#674) and the KQL column types are order-free: every giver of every item, every type
    foreach ($i in $order) {
        foreach ($r in @($Handovers[$i]['Reports'])) {
            $e = $Handovers[$i]['PerReport'][[string]$r]
            if ($e -and $e.ContainsKey('EmptyGivers')) { & $ensureHash 'EmptyGivers'; $State['EmptyGivers'][[string]$r] = [string]$e['EmptyGivers'] }
        }
        $kt = $Handovers[$i]['KqlTypes']
        if ($kt -and $null -ne $State['KqlTypes']) {
            foreach ($k in @($kt.Keys)) { $prev = $null; if ($State['KqlTypes'].TryGetValue($k, [ref]$prev)) { if ($prev -ne [string]$kt[$k]) { $State['KqlTypes'][$k] = 'mixed' } } else { $State['KqlTypes'][$k] = [string]$kt[$k] } }
        }
    }
    [pscustomobject]@{ Counters = $ctr; FinalDesiredColumns = $cols; StreamReports = $streamReports; Reports = $names.ToArray(); Broken = $broken.ToArray(); Held = $held.ToArray() }
}

function Get-RAScaleOutHandoffContradictions {
    <#
        PURE. #674 across workers: a giver whose hand-off list read empty is NOT COMPLETE when a receiving report found rows
        LATER in the run -- in the single job's order (ordinal): only a receiver that ran after the giver. Each giver once.
        -EmptyGivers: giver -> why it looked right; -Retrieved: report -> rows retrieved; -Ordinals: report -> ordinal.
    #>
    param([hashtable]$EmptyGivers = @{}, [hashtable]$Retrieved = @{}, [hashtable]$Ordinals = @{}, [hashtable]$Successors)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $EmptyGivers -or $EmptyGivers.Count -eq 0) { return @() }
    $left = @{}; foreach ($k in @($EmptyGivers.Keys)) { $left[$k] = $EmptyGivers[$k] }
    foreach ($recv in @($Retrieved.Keys | Sort-Object { [int]$Ordinals[$_] })) {
        $rows = [long]$Retrieved[$recv]
        if ($rows -le 0) { continue }
        $before = @{}; foreach ($g in @($left.Keys)) { if ([int]$Ordinals[$g] -lt [int]$Ordinals[$recv]) { $before[$g] = $left[$g] } }
        if ($before.Count -eq 0) { continue }
        foreach ($c in @(Get-RAHandoffContradiction -ReportName ([string]$recv) -Retrieved $rows -EmptyGivers $before -Successors $Successors)) {
            $out.Add([pscustomobject]@{ Report = [string]$c.Report; Why = [string]$c.Why })
            $left.Remove([string]$c.Report)
        }
    }
    $out.ToArray()
}

# ------------------------------------------------------------------------------------------------------------------
#  WORKER
# ------------------------------------------------------------------------------------------------------------------

function Write-RAScaleOutItemResult {
    <# The item is finished: its hand-over FIRST, then its marker (the producer reads a marker only with its hand-over
       already there). -State done | failed. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][int]$Item,
          $Handover, [ValidateSet('done', 'failed')][string]$State = 'done', [string]$Reason = '', [long]$Rows = 0, [string]$Worker = '')
    if ($null -ne $Handover) { & $Store.Write (Get-RAScaleOutPath -Engine $Engine -RunId $RunId -Kind handover -Item $Item) (ConvertTo-Json -InputObject $Handover -Compress -Depth 12) }
    Write-SICollectPartMarker -Store $Store -Engine $Engine -RunId $RunId -Marker (New-SICollectPartMarker -Part $Item -State $State -Rows $Rows -Reason $Reason -Worker $Worker)
}

function Receive-RAScaleOutItem {
    <#
        The next work item for this worker. Returns @{ Kind; Message; Payload; Manifest; Beat; Why }:
          item        a report to run: the message is held (a heartbeat renews the hold while this process lives -- a hold the
                      queue refuses ends the process, so a report is never written by two workers), its started mark written
          empty       nothing (left) to do
          other-run   the next message belongs to another run than -ExpectedRunId: put back at once; this worker stops
        Discarded on the way (the message completed): a run that is closed or older than StaleHours, an item already marked.
        Parked: an item handed out more than -MaxDequeue times -- '<queue>-poison' keeps its text, its FAILED marker says why.
        -NoBeat: no heartbeat (tests); -SignInLibraries: the sign-in files the heartbeat's thread loads (managed identity).
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$QueueName, [Parameter(Mandatory)]$Store, [string]$ExpectedRunId = '',
          [int]$MaxDequeue = $script:RAScaleOut.MaxDequeue, [int]$LeaseSeconds = 600, [string]$Worker = '', [switch]$NoBeat, [string[]]$SignInLibraries = @(), [hashtable]$Auth = $null,
          [datetime]$Now = [datetime]::UtcNow, [int]$StaleHours = $script:RAScaleOut.StaleHours, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $t) Write-Host $t } }
    $o = { param($k, $m, $p, $man, $b, $w) [pscustomobject]@{ Kind = $k; Message = $m; Payload = $p; Manifest = $man; Beat = $b; Why = [string]$w } }
    while ($true) {
        $msg = Get-SINextWorkItem -Context $Context -QueueName $QueueName -VisibilityTimeoutSeconds $LeaseSeconds
        if (-not $msg) { return (& $o 'empty' $null $null $null $null 'the queue is empty') }
        $p = $msg.Payload
        $runId = [string]$p.RunId; $engine = [string]$p.Engine; $item = [int]$p.Item
        if ($ExpectedRunId -and $runId -ne $ExpectedRunId) {
            $null = Update-SIWorkItemLease -Context $Context -QueueName $QueueName -Id ([string]$msg.Id) -PopReceipt ([string]$msg.PopReceipt) -VisibilityTimeoutSeconds 0 -RawText ([string]$msg.RawText)
            return (& $o 'other-run' $null $p $null $null ('the next report belongs to another run ({0})' -f $runId))
        }
        $man = $null
        $closed = $false
        try { $man = Read-RAScaleOutManifest -Store $Store -Engine $engine -RunId $runId; $closed = Test-RAScaleOutRunClosed -Store $Store -Engine $engine -RunId $runId }
        catch {
            # #882: a storage read that FAILED is not "the run is over" -- the message goes back to the queue at once (never
            # removed: its report would never run and never get a marker) and this worker stops
            $null = Update-SIWorkItemLease -Context $Context -QueueName $QueueName -Id ([string]$msg.Id) -PopReceipt ([string]$msg.PopReceipt) -VisibilityTimeoutSeconds 0 -RawText ([string]$msg.RawText)
            return (& $o 'other-run' $null $p $null $null ('the run''s state could not be read ({0}) -- the report goes back to the queue' -f $_.Exception.Message))
        }
        # #882 (A6): a run is over when it is CLOSED (its producer finished it, a later producer closed it, the pipeline ended
        # its step: Close-SICollectRunsOf) or its manifest is gone -- never by its age: a run of 50 million objects may take
        # longer than any fixed number of hours, and its remaining reports were dropped without a marker (-StaleHours is kept
        # for callers that pass it and no longer used)
        if (-not $man -or $closed) {
            & $Log 'INFO' ('[scale-out] report {0} of run {1}: that run is over -- the message is removed, nothing is run' -f $p.Report, $runId)
            Complete-SIWorkItem -Context $Context -QueueName $QueueName -Id $msg.Id -PopReceipt $msg.PopReceipt
            continue
        }
        $existing = @(Read-SICollectPartMarkers -Store $Store -Engine $engine -RunId $runId | Where-Object { $null -ne $_ -and [int]$_.Part -eq $item })
        if ($existing.Count) {
            & $Log 'INFO' ('[scale-out] report {0}: already finished by a worker -- the message is removed' -f $p.Report)
            Complete-SIWorkItem -Context $Context -QueueName $QueueName -Id $msg.Id -PopReceipt $msg.PopReceipt
            continue
        }
        if ([int]$msg.DequeueCount -gt $MaxDequeue) {
            $why = 'its worker stopped {0} time(s) while running it (out of memory, or the job ended it) -- parked for a re-run once the cause is fixed' -f ([int]$msg.DequeueCount - 1)
            $null = Move-SIWorkItemToPoison -Context $Context -QueueName $QueueName -WorkItem $msg -Reason $why
            Write-SICollectPartMarker -Store $Store -Engine $engine -RunId $runId -Marker (New-SICollectPartMarker -Part $item -State failed -Reason $why -Worker $Worker)
            & $Log 'WARN' ('[scale-out] report {0} is NOT COMPLETE in this run: {1}' -f $p.Report, $why)
            continue
        }
        $beat = $null
        if (-not $NoBeat) {
            # #831 (internal 2026-10-20: every renewal failed "No sign-in is configured for Azure access over REST"): the heartbeat
            # runs in its OWN runspace, which does not see the sign-in this process recorded -- it is handed over explicitly, as
            # the collection worker does (container/Start-SIInContainer.ps1, -Auth $beatAuth)
            $beatAuth = $Auth
            if ($null -eq $beatAuth -and (Get-Command -Name Resolve-SIAzRestAuth -ErrorAction SilentlyContinue)) { try { $beatAuth = Resolve-SIAzRestAuth } catch { $beatAuth = $null } }
            $beat = Start-SIWorkItemLeaseBeat -Context $Context -QueueName $QueueName -WorkItem $msg -LeaseSeconds $LeaseSeconds -BeatSeconds ([Math]::Max(30, [int]($LeaseSeconds / 5))) `
                        -What ('report {0}' -f $p.Report) -ExitOnLost -SignInLibraries $SignInLibraries -Auth $beatAuth
            if ($beat -and $beat.Lost) { continue }
            if ($null -eq $beat) {
                # NO HEARTBEAT (as the collection worker): the report is held with ONE longer lease, and the line says why --
                # a report that runs longer than it may be taken by a second worker (its rows are removed and written again)
                $fb = [int](Get-SIWorkItemFallbackLeaseSeconds)
                $envLease = 0; if ([int]::TryParse([string][Environment]::GetEnvironmentVariable('SI_QUEUE_LEASE_SECONDS'), [ref]$envLease) -and $envLease -gt 0) { $fb = [Math]::Min($fb, $envLease) }
                $long = Update-SIWorkItemLease -Context $Context -QueueName $QueueName -Id ([string]$msg.Id) -PopReceipt ([string]$msg.PopReceipt) -VisibilityTimeoutSeconds $fb -RawText ([string]$msg.RawText)
                if ($long.Ok) { $msg.PopReceipt = [string]$long.PopReceipt }
                elseif ($long.Lost) { continue }
                & $Log 'WARN' ('[scale-out] report {0}: the heartbeat that renews the hold on it could not be started ({1}) -- it is held for {2} minutes at a time instead' -f $p.Report, [string](Get-SIWorkItemLeaseBeatStartError), [int]($fb / 60))
            }
        }
        try { & $Store.Write (Get-RAScaleOutPath -Engine $engine -RunId $runId -Kind started -Item $item) (ConvertTo-Json -InputObject ([ordered]@{ Worker = $Worker; StartedUtc = [datetime]::UtcNow.ToString('o'); Attempt = [int]$msg.DequeueCount }) -Compress) } catch { }
        return (& $o 'item' $msg $p $man $beat '')
    }
}

function Complete-RAScaleOutItem {
    <# The item's message is removed with the NEWEST receipt (the heartbeat renewed it); its heartbeat ends first. Never throws. #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$QueueName, [Parameter(Mandatory)]$Received)
    $receipt = [string]$Received.Message.PopReceipt
    if ($Received.Beat) { $s = Stop-SIWorkItemLeaseBeat -Beat $Received.Beat; if ($s -and $s.PopReceipt) { $receipt = [string]$s.PopReceipt } }
    try { Complete-SIWorkItem -Context $Context -QueueName $QueueName -Id ([string]$Received.Message.Id) -PopReceipt $receipt; $true }
    catch { Write-Warning ('[scale-out] the finished report''s message could not be removed ({0}) -- a worker that takes it again sees it finished and removes it' -f $_.Exception.Message); $false }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE RUN'S LOCK: one worker at a time keeps its bucket counts in the install's shared file (each save is a
#  read-modify-write of the whole file -- two at once could lose one's counts).
# ------------------------------------------------------------------------------------------------------------------

function Enter-RAScaleOutLock {
    <# Takes the lock (a create-only blob with its owner and expiry). A lock past its expiry is taken over. Waits up to
       -WaitSeconds; then goes on without it, said once.
       Returns the owner token, or '' when it went on without the lock. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Path, [string]$Owner = ([guid]::NewGuid().ToString('N')), [int]$TtlSeconds = $script:RAScaleOut.LockTtlSeconds,
          [int]$WaitSeconds = 1200, [scriptblock]$Sleep, [scriptblock]$Now)
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Milliseconds ([int]($s * 1000)) } }
    if (-not $Now) { $Now = { [datetime]::UtcNow } }
    $start = & $Now
    while ($true) {
        $t = & $Now
        $body = ConvertTo-Json -InputObject ([ordered]@{ Owner = $Owner; Until = $t.AddSeconds($TtlSeconds).ToString('o') }) -Compress
        if (& $Store.Claim $Path $body) { return $Owner }
        $cur = $null; try { $cur = Read-RAScaleOutJson -Store $Store -Path $Path } catch { }
        if ($cur -and $cur['Until']) {
            $u = [datetime]::MaxValue
            if ([datetime]::TryParse([string]$cur['Until'], [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$u) -and $u -lt $t.ToUniversalTime()) {
                if ($Store.PSObject.Properties['Remove']) { try { & $Store.Remove $Path } catch { } }
                continue
            }
        }
        if (($t - $start).TotalSeconds -ge $WaitSeconds) {
            Write-Warning ('the run''s lock was not free for {0} seconds -- this worker goes on without it' -f $WaitSeconds)
            return ''
        }
        & $Sleep 2
    }
}

function Exit-RAScaleOutLock {
    <# Releases the lock -- only when this owner holds it. Never throws. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Path, [string]$Owner)
    if (-not $Owner) { return }
    try {
        $cur = Read-RAScaleOutJson -Store $Store -Path $Path
        if ($cur -and [string]$cur['Owner'] -eq $Owner -and $Store.PSObject.Properties['Remove']) { & $Store.Remove $Path }
    } catch { }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE BUCKET COUNTS OF AN INSTALL WITHOUT THE PRO SETTINGS DATABASE (a file kept in the storage account)
# ------------------------------------------------------------------------------------------------------------------

function Merge-RAScaleOutBucketCache {
    <#
        PURE. A worker keeps the counts IT learned without undoing another worker's: the stored file, with every key of the
        worker's own reports ('<Report>|<hash>', and their '__confirmed' stamps) taken from the worker's copy. A key of a
        report this worker did not run is never touched. Returns the merged cache.
    #>
    param([hashtable]$Stored = @{}, [hashtable]$Local = @{}, [string[]]$Reports = @())
    if ($null -eq $Stored) { $Stored = @{} }; if ($null -eq $Local) { $Local = @{} }
    $mine = { param($k) $n = ([string]$k -split '\|', 2)[0]; @($Reports) -contains $n }
    $out = @{}
    foreach ($k in @($Stored.Keys)) { if ([string]$k -ne '__confirmed' -and -not (& $mine $k)) { $out[$k] = $Stored[$k] } }
    foreach ($k in @($Local.Keys)) { if ([string]$k -ne '__confirmed' -and -not ([string]$k).StartsWith('__') -and (& $mine $k)) { $out[$k] = $Local[$k] } }
    foreach ($k in @($Stored.Keys)) { if (([string]$k).StartsWith('__') -and [string]$k -ne '__confirmed' -and -not $out.ContainsKey($k)) { $out[$k] = $Stored[$k] } }
    $conf = @{}
    if ($Stored['__confirmed'] -is [System.Collections.IDictionary]) { foreach ($k in @($Stored['__confirmed'].Keys)) { if (-not (& $mine $k)) { $conf[$k] = $Stored['__confirmed'][$k] } } }
    if ($Local['__confirmed'] -is [System.Collections.IDictionary]) { foreach ($k in @($Local['__confirmed'].Keys)) { if (& $mine $k) { $conf[$k] = $Local['__confirmed'][$k] } } }
    if ($conf.Count) { $out['__confirmed'] = $conf }
    $out
}
