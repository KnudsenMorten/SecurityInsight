#Requires -Version 5.1
<#
    THE RECORDS OF A RUN COLLECTED IN PARTS (#475). A provider record is assembled from parts captured in different stages
    -- most of them in Discover (the provider objects), the rest in Collect, Enrich and Output (sign-ins, software, rule
    hits, the logon tier). When a run is collected in parts, Discover and every part are separate processes, so no single
    one holds a whole record. Ring 1, 2026-10-08: a discovery process that never reached Output dropped its records
    (Entra 1,726 / Exposure Graph 7,296 / Azure 494 -> 0), and the parts published Collect-stage halves without a key.

    So in a run collected in parts, nobody publishes as it goes. Each process SAVES what it captured to the state store,
    split into BUCKETS by the record id (provider|type|key; the same hash the parts use, as many buckets as parts):

      collect/<engine>/<runId>/records/<who>/bucket-NNNNN-CCCCC.json      who = discover | part-NNNNN, CCCCC = the chunk

    and after the last part one process takes the buckets one at a time: every saved half of a record merged (a part
    captured later replaces the same part captured earlier; the engines that captured it unioned; a provider's pull is
    complete only when it was complete in every process), published once (Publish-SIRecords: Log Analytics + the
    database), and let go before the next bucket. Its memory is one bucket.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

function ConvertTo-SIRecordHandover {
    <#
        PURE. The capture state -> @{ Pulls = [...]; Buckets = @{ <n> = [ records ] } }. A record keeps its parts as JSON
        text (a part set as an object -- the rule-index parts -- is written as JSON here).
    #>
    param($State = $global:SIRecordCaptureState, [Parameter(Mandatory)][int]$Buckets)
    $out = @{}
    if ($null -eq $State) { return [pscustomobject]@{ Pulls = @(); Buckets = $out } }
    foreach ($e in $State.Records.GetEnumerator()) {
        $b = Get-SICollectPartIndex -Key ([string]$e.Key) -Parts $Buckets
        if (-not $out.ContainsKey($b)) { $out[$b] = New-Object System.Collections.Generic.List[object] }
        $out[$b].Add((ConvertTo-SIRecordHandoverItem -Id ([string]$e.Key) -Record $e.Value))
    }
    [pscustomobject]@{ Pulls = @(Get-SIRecordHandoverPulls -State $State); Buckets = $out }
}

function ConvertTo-SIRecordHandoverItem {
    <# PURE. One captured record as it is kept: its parts as JSON text (a part set as an object is written as JSON here). #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)]$Record)
    $parts = [ordered]@{}
    foreach ($k in @($Record.Parts.Keys)) {
        $v = $Record.Parts[$k]
        if ($null -ne $v -and $v -is [psobject] -and $v.PSObject.Properties['SIJson'] -and @($v.PSObject.Properties).Count -eq 1) { $parts[$k] = [string]$v.SIJson }
        else { $parts[$k] = (ConvertTo-Json -InputObject $v -Compress -Depth 20) }
    }
    [ordered]@{ Id = $Id; Provider = $Record.Provider; RecordType = $Record.RecordType; Key = $Record.Key; ResourceType = $Record.ResourceType; Engines = @($Record.Engines); Parts = $parts }
}

function Get-SIRecordHandoverPulls {
    param($State)
    if ($null -eq $State) { return }
    foreach ($p in @($State.Pulls.Values)) { [pscustomobject]@{ Provider = [string]$p.Provider; Complete = [bool]$p.Complete; Error = [string]$p.Error } }
}

function Get-SIRecordHandoverPath {
    <# PURE. Where one process's chunk of one bucket of records is kept (a bucket is written in chunks, #475). #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$Who, [int]$Bucket = -1, [int]$Chunk = 0)
    $base = 'collect/{0}/{1}/records' -f $Engine.ToLowerInvariant(), $RunId
    if ($Bucket -lt 0) { return "$base/" }
    '{0}/{1}/bucket-{2:D5}-{3:D5}.json' -f $base, $Who, $Bucket, $Chunk
}

function Save-SIRecordHandover {
    <#
        This process's captured records -> the state store, each bucket in CHUNKS of -ChunkSize records (+ the pulls in every
        file), and the capture is cleared. customer H 2026-10-08: one file per bucket serialised a third of 23,000 identities and
        73,000 graph nodes in one go, on top of what discovery held, and ran out of memory -- a chunk is written as soon as it
        is full, so one write never holds more than one chunk's text. Returns the number of records saved. Throws on a
        failed write: a run whose records are not kept is not whole, and the caller fails the part.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)][string]$Who, [Parameter(Mandatory)][int]$Buckets, $State = $global:SIRecordCaptureState,
          [int]$ChunkSize = 2000)
    if ($null -eq $State) { return 0 }
    # Azure child resources: a child's link on another child (a public IP on a network interface) moves to the record above
    # BEFORE the records are split into buckets (the two records may land in different buckets)
    if (Get-Command -Name Resolve-SIRecordChildren -ErrorAction SilentlyContinue) { $null = Resolve-SIRecordChildren -State $State }
    # #721: a capture that STREAMED (the discover phase) is handed over from its stream, never from memory
    if ($State.PSObject.Properties['Stream'] -and $null -ne $State.Stream) {
        return (Save-SIRecordHandoverStream -Store $Store -Engine $Engine -RunId $RunId -Who $Who -Buckets $Buckets -State $State -ChunkSize $ChunkSize)
    }
    $pulls = @(Get-SIRecordHandoverPulls -State $State)
    $open = @{}; $next = @{}
    $n = 0
    $flush = {
        param([int]$B)
        $list = $open[$B]
        if ($null -eq $list -or $list.Count -eq 0) { return }
        $c = 0; if ($next.ContainsKey($B)) { $c = [int]$next[$B] }
        $doc = [ordered]@{ Schema = 1; Who = $Who; Pulls = $pulls; Records = $list.ToArray() }
        & $Store.Write (Get-SIRecordHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Bucket $B -Chunk $c) (ConvertTo-Json -InputObject $doc -Compress -Depth 8)
        $next[$B] = $c + 1
        $list.Clear()
    }
    foreach ($e in $State.Records.GetEnumerator()) {
        $b = Get-SICollectPartIndex -Key ([string]$e.Key) -Parts $Buckets
        if (-not $open.ContainsKey($b)) { $open[$b] = New-Object System.Collections.Generic.List[object] }
        $open[$b].Add((ConvertTo-SIRecordHandoverItem -Id ([string]$e.Key) -Record $e.Value))
        $n++
        if ($open[$b].Count -ge $ChunkSize) { & $flush $b }
    }
    foreach ($b in @($open.Keys)) { & $flush $b }
    # a process whose records are all handed over keeps none (and publishes none)
    $State.Records.Clear()
    $n
}

function Get-SIRecordStreamLineId {
    <# PURE. The record id of one stream line ({"Id":"...", ...}) without parsing the rest of the line. #>
    param([Parameter(Mandatory)][string]$Line)
    $m = [regex]::Match($Line, '^\{"Id":"((?:[^"\\]|\\.)*)"')
    if (-not $m.Success) { return [string](ConvertFrom-Json -InputObject $Line).Id }
    $v = $m.Groups[1].Value
    if ($v.IndexOf('\') -ge 0) { $v = [string](ConvertFrom-Json -InputObject ('"' + $v + '"')) }
    $v
}

function Save-SIRecordHandoverStream {
    <#
        #721 -- the hand-over of a capture that STREAMED (the discover phase): every line of the local record stream, then the
        records still held (none in the producer), into the run's buckets -- in that order, the order they were captured -- and
        each bucket written to the state store in chunks of -ChunkSize items, exactly as Save-SIRecordHandover writes them.
        Memory: one line, then one chunk. The lines go to one local, compressed file per bucket first (the bucket count is
        known only now, from how many were captured); every local file is removed afterwards. Returns the items handed over.
        #727 the Azure lines go to local GROUP files first (a resource and its child resources together) and are folded one
        group file at a time -- every Azure record then goes to its bucket as ONE item, the record the in-memory fold made.
        Throws on a failed write (the caller fails the run: a run whose records are not kept is not whole).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)][string]$Who, [Parameter(Mandatory)][int]$Buckets, [Parameter(Mandatory)]$State, [int]$ChunkSize = 2000)
    $s = $State.Stream
    $pulls = @(Get-SIRecordHandoverPulls -State $State)
    $head = '{"Schema":1,"Who":' + (ConvertTo-Json -InputObject $Who -Compress) + ',"Pulls":' + (ConvertTo-Json -InputObject @($pulls) -Compress -Depth 4) + ',"Records":['
    $enc = New-Object System.Text.UTF8Encoding($false)
    $dir = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-handover-{0}' -f [guid]::NewGuid().ToString('N')))
    $null = [IO.Directory]::CreateDirectory($dir)
    $writers = @{}
    $n = 0L
    try {
        $s.Writer.Dispose()
        $toBucket = {
            param([string]$Id, [string]$Line)
            $b = Get-SICollectPartIndex -Key $Id -Parts $Buckets
            $w = $writers[$b]
            if ($null -eq $w) {
                $fs = [IO.File]::Create([IO.Path]::Combine($dir, ('b{0:D5}.jsonl.gz' -f $b)))
                $w = New-Object System.IO.StreamWriter((New-Object System.IO.Compression.GZipStream($fs, [System.IO.Compression.CompressionLevel]::Fastest)), $enc)
                $writers[$b] = $w
            }
            $w.WriteLine($Line)
        }
        # #727 THE AZURE RECORDS: a line of an Azure record goes to a local file by its GROUP (the record and every child
        # resource listed on it -- Stream.Groups), so a parent and its children meet in one file. ~10,000 lines per group file,
        # as many files as that takes: one group file is what is held at a time when the children are folded below.
        $groups = $null; $gw = @{}; $gn = 1
        if ($s.PSObject.Properties['Groups'] -and $null -ne $s.Groups) {
            # the fold below needs SI-AzureChildren.ps1 (loaded by SI-RecordCapture.ps1) IN THE CALLER'S SCOPE -- the container's
            # hand-over runs in its own (2105 live). Missing = the hand-over fails here; it never hands over unfolded children.
            if (-not (Get-Command -Name Resolve-SIRecordChildren -ErrorAction SilentlyContinue)) {
                throw 'the record hand-over cannot fold the Azure child resources: Resolve-SIRecordChildren is not loaded in this scope (dot-source engine/data-model/SI-RecordCapture.ps1 before Save-SIRecordHandover)'
            }
            $groups = $s.Groups
            $gn = [int][Math]::Max(1, [Math]::Ceiling([double]$s.AzureLines / 10000.0))
        }
        $in = New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream([IO.File]::OpenRead($s.Path), [System.IO.Compression.CompressionMode]::Decompress)), $enc)
        try {
            while ($null -ne ($line = $in.ReadLine())) {
                if (-not $line) { continue }
                $lid = Get-SIRecordStreamLineId -Line $line
                if ($null -ne $groups -and $lid.StartsWith('azure|', [StringComparison]::OrdinalIgnoreCase)) {
                    $g = Get-SICollectPartIndex -Key ($groups.Find($lid.Substring($lid.IndexOf('|', 6) + 1))) -Parts $gn
                    $w = $gw[$g]
                    if ($null -eq $w) {
                        $w = New-Object System.IO.StreamWriter((New-Object System.IO.Compression.GZipStream([IO.File]::Create([IO.Path]::Combine($dir, ('g{0:D5}.jsonl.gz' -f $g))), [System.IO.Compression.CompressionLevel]::Fastest)), $enc)
                        $gw[$g] = $w
                    }
                    $w.WriteLine($line)
                    continue
                }
                & $toBucket $lid $line
                $n++
            }
        } finally { $in.Dispose() }
        foreach ($e in @($State.Records.GetEnumerator())) {
            & $toBucket ([string]$e.Key) (ConvertTo-Json -InputObject (ConvertTo-SIRecordHandoverItem -Id ([string]$e.Key) -Record $e.Value) -Compress -Depth 4)
            $n++
        }
        # one group file at a time: its lines merged into records exactly as the capture built them (a later part wins, the
        # engines unioned), a child resource that was captured before its parent folded into it (Resolve-SIRecordChildren),
        # then every record into its bucket -- one item each, as the held Azure records were
        foreach ($g in @($gw.Keys)) { $gw[$g].Dispose() }
        foreach ($g in @($gw.Keys | Sort-Object)) {
            $items = New-Object System.Collections.Generic.List[object]
            $r = New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream([IO.File]::OpenRead([IO.Path]::Combine($dir, ('g{0:D5}.jsonl.gz' -f $g))), [System.IO.Compression.CompressionMode]::Decompress)), $enc)
            try { while ($null -ne ($line = $r.ReadLine())) { if ($line) { $items.Add((ConvertFrom-Json -InputObject $line)) } } } finally { $r.Dispose() }
            $merged = Merge-SIRecordHandover -Documents @([pscustomobject]@{ Who = 'discover'; Pulls = @(); Records = $items.ToArray() })
            $items = $null
            $null = Resolve-SIRecordChildren -State $merged
            foreach ($e in $merged.Records.GetEnumerator()) {
                & $toBucket ([string]$e.Key) (ConvertTo-Json -InputObject (ConvertTo-SIRecordHandoverItem -Id ([string]$e.Key) -Record $e.Value) -Compress -Depth 4)
                $n++
            }
            $merged = $null
            try { [IO.File]::Delete([IO.Path]::Combine($dir, ('g{0:D5}.jsonl.gz' -f $g))) } catch { }
        }
        foreach ($b in @($writers.Keys)) { $writers[$b].Dispose() }
        foreach ($b in @($writers.Keys | Sort-Object)) {
            $r = New-Object System.IO.StreamReader((New-Object System.IO.Compression.GZipStream([IO.File]::OpenRead([IO.Path]::Combine($dir, ('b{0:D5}.jsonl.gz' -f $b))), [System.IO.Compression.CompressionMode]::Decompress)), $enc)
            try {
                $c = 0; $k = 0; $sb = New-Object System.Text.StringBuilder
                $flush = {
                    [void]$sb.Append(']}')
                    & $Store.Write (Get-SIRecordHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Bucket $b -Chunk $c) $sb.ToString()
                    $c++; $k = 0; [void]$sb.Clear()
                }
                while ($null -ne ($line = $r.ReadLine())) {
                    if (-not $line) { continue }
                    if ($k -eq 0) { [void]$sb.Append($head) } else { [void]$sb.Append(',') }
                    [void]$sb.Append($line); $k++
                    if ($k -ge $ChunkSize) { . $flush }
                }
                if ($k -gt 0) { . $flush }
            } finally { $r.Dispose() }
        }
    } finally {
        foreach ($w in @($writers.Values)) { try { $w.Dispose() } catch { } }
        foreach ($w in @($gw.Values)) { try { $w.Dispose() } catch { } }
        try { [IO.Directory]::Delete($dir, $true) } catch { }
        if (Get-Command -Name Stop-SIRecordCaptureStream -ErrorAction SilentlyContinue) { Stop-SIRecordCaptureStream -State $State }
        else { $State.Stream = $null }
    }
    # a process whose records are all handed over keeps none (and publishes none)
    $State.Records.Clear()
    $n
}

function Test-SIRecordScopeJsonIn {
    <# PURE. Does a 'si_scope' part (its JSON text) say IN scope? #>
    param([AllowNull()][AllowEmptyString()][string]$Json)
    return ([string]$Json -match '"in_scope"\s*:\s*true')
}

function Merge-SIRecordHandover {
    <#
        PURE. The saved documents of ONE bucket (any order of processes) -> a capture state (Records + Pulls) as
        Add-SIRecordPart would have built it in one process: the same part captured twice -> the later document's wins
        (discover first, then the parts in order); engines unioned; a pull complete only when complete everywhere.
    #>
    param([AllowEmptyCollection()][object[]]$Documents = @(),
          # merge INTO this state (one file at a time -- the caller orders discover first); none = a new state
          $Into)
    $state = $Into
    if ($null -eq $state) {
        $state = [pscustomobject]@{
            Engine  = ''
            Records = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
            Pulls   = @{}
        }
    }
    $ordered = @($Documents | Where-Object { $_ } | Sort-Object @{ Expression = { if ([string]$_.Who -eq 'discover') { '0' } else { '1' + [string]$_.Who } } })
    foreach ($d in $ordered) {
        foreach ($p in @($d.Pulls)) {
            if ($null -eq $p) { continue }
            $k = ([string]$p.Provider).ToLowerInvariant()
            $prev = $state.Pulls[$k]
            $complete = [bool]$p.Complete; $err = [string]$p.Error
            if ($prev) { $complete = $complete -and [bool]$prev.Complete; if (-not $err) { $err = [string]$prev.Error } }
            $state.Pulls[$k] = [pscustomobject]@{ Provider = $k; Complete = $complete; Error = $err }
        }
        foreach ($r in @($d.Records)) {
            if ($null -eq $r) { continue }
            $id = [string]$r.Id
            $rec = $null
            if (-not $state.Records.TryGetValue($id, [ref]$rec)) {
                $rec = [pscustomobject]@{ Provider = [string]$r.Provider; RecordType = [string]$r.RecordType; Key = [string]$r.Key; ResourceType = ''
                    Parts = [ordered]@{}; Engines = New-Object 'System.Collections.Generic.HashSet[string]' }
                $state.Records[$id] = $rec
            }
            if ([string]$r.ResourceType) { $rec.ResourceType = [string]$r.ResourceType }
            foreach ($e in @($r.Engines)) { if ($e) { [void]$rec.Engines.Add([string]$e) } }
            if ($r.Parts) {
                foreach ($pp in $r.Parts.PSObject.Properties) {
                    # CIs follow the collection scope: IN SCOPE WINS across parts, as within one -- a record one part kept
                    # in scope is never marked out of scope by another part, whichever document comes later
                    if ($pp.Name -eq 'si_scope' -and $rec.Parts.Contains('si_scope') -and (Test-SIRecordScopeJsonIn ([string]$rec.Parts['si_scope'].SIJson))) { continue }
                    $rec.Parts[$pp.Name] = [pscustomobject]@{ SIJson = [string]$pp.Value }
                }
            }
        }
    }
    $state
}

# Parts a process ATTACHES to a record another process captured (the profile's look-ups, the logon tier, the rule-index hits,
# the scope mark). A part of a run collected in parts keeps them without the record (Add-SIRecordPartsFromProfileRows
# -InParts); a merged record that has ONLY such parts was never captured from its provider and is not published.
$script:SIRecordAttachedParts = @('profile', 'logon', 'software', 'parentTags', 'egQueryRules', 'si_scope', 'diag')

function Remove-SIRecordHandoverOrphans {
    <# PURE. Drops from a merged capture state every record made only of attached parts (an Azure child resource's part,
       'child|<id>', is attached too: a parent that was never captured is not published). Returns how many were dropped. #>
    param($State)
    if ($null -eq $State -or $null -eq $State.Records) { return 0 }
    $drop = New-Object System.Collections.Generic.List[string]
    foreach ($e in $State.Records.GetEnumerator()) {
        $own = @(@($e.Value.Parts.Keys) | Where-Object { $script:SIRecordAttachedParts -notcontains [string]$_ -and -not ([string]$_).StartsWith('child|') })
        if ($own.Count -eq 0) { $drop.Add([string]$e.Key) }
    }
    foreach ($k in $drop) { [void]$State.Records.Remove($k) }
    $drop.Count
}

function Get-SIRecordBucketCount {
    <#
        PURE. How many buckets a run's records go into (#475): ~-PerBucket records each, never fewer than the run's parts,
        at most -Max. The buckets are what the last step publishes in parallel; with one bucket per part, a large tenant's
        96,551 records were three buckets of 32,000 -- nothing to spread. Discovery decides it (it holds most records) and
        every process of the run uses the same number.
    #>
    # -Max: the bucket file names hold five digits. #727 (owner 2026-10-16: "tenants can have millions of azure obj"): the
    # count grows with the records -- ~5,000 each at every size (it stopped at 500 buckets: 10,000 per bucket at 5 million)
    param([long]$Records, [int]$Parts = 1, [int]$PerBucket = 5000, [int]$Max = 99999)
    $b = [Math]::Max(1, $Parts)
    if ($Records -gt 0 -and $PerBucket -gt 0) { $b = [Math]::Max($b, [int][Math]::Ceiling($Records / [double]$PerBucket)) }
    [int][Math]::Min($Max, $b)
}

function Publish-SIRecordHandover {
    <#
        After the last part: every bucket merged and published once (Publish-SIRecords), one bucket at a time. Returns
        @{ Buckets; Records; Failed; SqlFailed; ExportFailed; Closed }. A bucket that cannot be read or published is said
        and counted; the others go on.
        -Slice k -Slices N: only the buckets b with b mod N = k -- N processes publish one run's records in parallel.
        THE DATABASE DOES NOT DEPEND ON LOG ANALYTICS here either, and each is counted on its own:
          Failed        buckets whose records did not all reach the DATABASE (unreadable, the write failed, the publish
                        gave up) -- the run's collection is then left "not complete" (Closed = $false);
          ExportFailed  batches whose optional COPY to Log Analytics (SI_LaExport) failed -- never a failed bucket: those
                        records are in the database, and the collection is closed there.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)]$RunContext, [scriptblock]$SqlInvoke, [int]$Slice = 0, [int]$Slices = 1,
          # #720: parts of this run that FAILED (their objects' records are not in the buckets) -- the records that are there
          # are published, but the collection is NOT closed as complete: the failed parts' records keep their last good
          # state (unknown, never read as removed)
          [int]$PartsFailed = 0,
          # #874: one of SEVERAL processes publishing the run at once -- this process writes its buckets but does NOT close
          # the collection: the result carries its close (Close: pins, feeds, failures) and the process that started them
          # closes the whole collection ONCE (Invoke-SIRecordsInProcesses) -- judged by the asset-drop guard as a whole
          [switch]$DeferClose)
    $prefix = Get-SIRecordHandoverPath -Engine $Engine -RunId $RunId -Who 'x'
    $byBucket = @{}
    if ($Slices -lt 1) { $Slices = 1 }
    foreach ($path in @(& $Store.List $prefix)) {
        if ($path -match '/bucket-(\d{5})(-\d{5})?\.json$') {
            $b = [int]$matches[1]
            if (($b % $Slices) -ne $Slice) { continue }
            if (-not $byBucket.ContainsKey($b)) { $byBucket[$b] = New-Object System.Collections.Generic.List[string] }
            $byBucket[$b].Add([string]$path)
        }
    }
    $total = 0; $failed = 0; $sqlFailed = 0; $exportFailed = 0; $closed = $null
    # ONE feed close for the whole run (SI-RecordSql.ps1): the buckets are one collection -- it counts as complete only when
    # every bucket of this process was published; a run that stops half-way leaves it "not complete" (nothing turns 'not seen')
    $runClose = $null
    try {
        if (-not (Get-Command -Name New-SIRecordFeedClose -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecordSql.ps1') }
        $runClose = New-SIRecordFeedClose -Engine $Engine
        # N processes publish this collection at once, each closing its own slice: a slice that closes first counts a feed
        # before the others have written their part -- the asset-drop guard does not judge it (never a false hold).
        # #874: a slice whose close is deferred is closed with the others by its starter, which judges the whole collection.
        if ($Slices -gt 1 -and -not $DeferClose) { $runClose | Add-Member -NotePropertyName Judge -NotePropertyValue $false -Force }
    } catch { $runClose = $null }
    if ($PartsFailed -gt 0) {
        if ($runClose) { $runClose.Failed = [int]$runClose.Failed + $PartsFailed }
        Write-Warning ('records: {0} part(s) of run {1} failed -- the records of the other parts are published, but this collection is NOT complete: the failed parts'' objects keep their last good state (unknown, not gone).' -f $PartsFailed, $RunId)
    }
    foreach ($b in @($byBucket.Keys | Sort-Object)) {
        try {
            # one file at a time, discovery's first (the later process's part wins): only one chunk is parsed at once
            $merged = $null
            $paths = @($byBucket[$b] | Sort-Object @{ Expression = { if ($_ -match '/records/discover/') { '0' + $_ } else { '1' + $_ } } })
            foreach ($path in $paths) {
                $txt = & $Store.Read $path
                if (-not $txt) { continue }
                $merged = Merge-SIRecordHandover -Documents @($txt | ConvertFrom-Json) -Into $merged
                $txt = $null
            }
            if ($null -eq $merged) { continue }
            $null = Remove-SIRecordHandoverOrphans -State $merged
            $global:SIRecordCaptureState = $merged
            $global:SIRecordCaptureState.Engine = $Engine.ToLowerInvariant()
            $merged = $null
            $pa = @{ RunContext = $RunContext; Engine = $Engine.ToLowerInvariant() }
            if ($SqlInvoke) { $pa['SqlInvoke'] = $SqlInvoke }
            if ($runClose) { $pa['FeedClose'] = $runClose }
            # what happened to this bucket, each output on its own (Publish-SIRecords never throws: it says it here)
            $what = @{}
            $pa['Outcome'] = $what
            $pa['What'] = ('bucket {0}' -f $b)
            $res = Publish-SIRecords @pa
            # THE RECORDS THE DATABASE TOOK (record-deadlock, 2026-10-26): Publish-SIRecords' Records is the count of the
            # optional copy to Log Analytics (SI_LaExport) -- 0 when that copy is off, so every slice said "0 record(s)
            # published" though its buckets were written. The database's count (Outcome Sql) is the one that is published.
            if ($what.ContainsKey('Sql')) { $total += [int]$what['Sql'] } elseif ($res) { $total += [int]$res.Records }
            $exportFailed += [int]$what['ExportFailed']
            if ([string]$what['State'] -eq 'failed' -or [int]$what['SqlFailed'] -gt 0) {
                # the database did not get every record of this bucket: a failed bucket (the publish has already counted it on
                # the run's close, so the collection stays "not complete")
                $failed++; $sqlFailed += [int]$what['SqlFailed']
                Write-Warning ('records: bucket {0} of run {1} did not reach the database in full -- {2}. Those records keep their last good state (unknown, not gone).' -f $b, $RunId,
                    $(if ([string]$what['Error']) { [string]$what['Error'] } else { '{0} record(s) could not be written' -f [int]$what['SqlFailed'] }))
            }
        } catch {
            $failed++
            if ($runClose) { $runClose.Failed = [int]$runClose.Failed + 1 }
            Write-Warning ('records: bucket {0} of run {1} could not be published -- {2}. Those records are missing from this collection (unknown, not gone).' -f $b, $RunId, $_.Exception.Message)
        } finally { $global:SIRecordCaptureState = $null; [System.GC]::Collect() }
    }
    if ($DeferClose) {
        # #874: the starter closes the collection with every process's close -- this one hands its own over
        Write-SIRecordHandoverExportWarning -ExportFailed $exportFailed -RunId $RunId
        return [pscustomobject]@{ Buckets = $byBucket.Count; Records = $total; Failed = $failed; SqlFailed = $sqlFailed; ExportFailed = $exportFailed; Closed = $null
                                  Close = (ConvertTo-SIRecordFeedCloseData -Close $runClose) }
    }
    if ($runClose -and ($runClose.Pins.Count -gt 0 -or [int]$runClose.Failed -gt 0)) {
        $closeSql = $SqlInvoke
        if (-not $closeSql -and (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { $closeSql = New-SIRecordSqlInvoke }
        $ct = [datetime]::UtcNow; if ($RunContext -and $RunContext.CollectionTime) { $ct = [datetime]$RunContext.CollectionTime }
        if ($closeSql) { $closeRes = Complete-SIRecordFeeds -Close $runClose -Invoke $closeSql -CollectionTime $ct; $closed = -not [bool]$closeRes.Held }
    }
    Write-SIRecordHandoverExportWarning -ExportFailed $exportFailed -RunId $RunId
    [pscustomobject]@{ Buckets = $byBucket.Count; Records = $total; Failed = $failed; SqlFailed = $sqlFailed; ExportFailed = $exportFailed; Closed = $closed }
}

function Write-SIRecordHandoverExportWarning {
    param([int]$ExportFailed, [string]$RunId)
    if ($ExportFailed -gt 0) {
        Write-Warning ('records: the copy to Log Analytics (SI_LaExport) failed for {0} batch(es) of run {1} -- the records are in the database; only the copy is missing.' -f $ExportFailed, $RunId)
    }
}

# =====================================================================================================================
#  #874 -- ONE RUN'S RECORDS PUBLISHED BY SEVERAL PROCESSES AT ONCE, CLOSED ONCE
# =====================================================================================================================
# MEASURED (ring 2, 2026-10-20/21, the install with 153,000 users and 1.9 million Exposure Graph identities): the run's
# 2.5 million records were 506 buckets, published by ONE process one bucket at a time -- ~74 s a bucket, 10.4 hours, while
# the database was at ~31 % (data reads) and the job's other 3 CPUs idle. The worker of a queue-driven run now publishes
# them as a scheduled collection job already did: one records process per CPU, as the memory allows (each the buckets
# b mod N = k). Every process writes; NONE closes: each hands its close (pins, feeds, failures) back, and the starter closes
# the collection ONCE with all of them -- so the asset-drop guard still judges the whole collection, and a process that
# failed or died leaves the collection "not complete" (nothing it did not reach is shown as gone), never complete.

function ConvertTo-SIRecordFeedCloseData {
    <# PURE. A feed close (New-SIRecordFeedClose) as plain data that survives JSON: Engine, Pins, Feeds, Incomplete, Failed, PinFeed. #>
    param($Close)
    if ($null -eq $Close) { return $null }
    $pf = [ordered]@{}
    if ($Close.PSObject.Properties['PinFeed'] -and $Close.PinFeed) { foreach ($k in @($Close.PinFeed.Keys)) { $pf[[string]$k] = [string]$Close.PinFeed[$k] } }
    [ordered]@{ Engine = [string]$Close.Engine; Pins = @($Close.Pins | ForEach-Object { [string]$_ }); Feeds = @(@($Close.Feeds.Keys) | ForEach-Object { [string]$_ })
                Incomplete = @(@($Close.Incomplete.Keys) | ForEach-Object { [string]$_ }); Failed = [int]$Close.Failed; PinFeed = $pf }
}

function Merge-SIRecordFeedCloses {
    <#
        PURE. The closes of every process that published one collection (ConvertTo-SIRecordFeedCloseData, read back from
        JSON) -> ONE feed close (New-SIRecordFeedClose shape). -Missing: processes that handed no close back (they died or
        failed before the end) -- each counts as a failure, so the collection is never closed as complete without them.
    #>
    param([string]$Engine = '', [AllowEmptyCollection()][object[]]$Closes = @(), [int]$Missing = 0)
    $c = [pscustomobject]@{ Engine = ([string]$Engine).Trim().ToLowerInvariant(); Pins = (New-Object System.Collections.Generic.List[string])
                            Feeds = @{}; Incomplete = @{}; Failed = [Math]::Max(0, $Missing); PinFeed = @{} }
    foreach ($x in @($Closes)) {
        if ($null -eq $x) { continue }
        foreach ($p in @($x.Pins)) { if ($p) { $c.Pins.Add([string]$p) } }
        foreach ($f in @($x.Feeds)) { if ($f) { $c.Feeds[[string]$f] = $true } }
        foreach ($f in @($x.Incomplete)) { if ($f) { $c.Incomplete[[string]$f] = $true } }
        $c.Failed = [int]$c.Failed + [int]$x.Failed
        if ($x.PinFeed) {
            if ($x.PinFeed -is [System.Collections.IDictionary]) { foreach ($k in @($x.PinFeed.Keys)) { $c.PinFeed[[string]$k] = [string]$x.PinFeed[$k] } }
            else { foreach ($pp in $x.PinFeed.PSObject.Properties) { $c.PinFeed[[string]$pp.Name] = [string]$pp.Value } }
        }
    }
    $c
}

function Get-SIRecordsProcessCount {
    <#
        PURE. How many records processes publish one run's buckets at once: one per CPU, as many as the free memory holds
        (-PerProcessBytes each), never more than the buckets, at least one. -FreeBytes < 0 = not known (CPUs decide).
        -Override (SI_COLLECT_RECORDS_PARALLEL, when set >= 1) decides instead, never more than the buckets.
    #>
    param([int]$Buckets, [int]$Processors = 1, [long]$FreeBytes = -1, [long]$PerProcessBytes = 1GB, [int]$Override = 0)
    if ($Buckets -lt 1) { return 1 }
    if ($Override -ge 1) { return [int][Math]::Max(1, [Math]::Min($Override, $Buckets)) }
    $n = [Math]::Max(1, $Processors)
    if ($FreeBytes -ge 0 -and $PerProcessBytes -gt 0) { $n = [Math]::Min($n, [Math]::Max(1, [int][Math]::Floor($FreeBytes / [double]$PerProcessBytes))) }
    [int][Math]::Max(1, [Math]::Min($n, $Buckets))
}

function Get-SIRecordsProcessFreeBytes {
    <# The memory this host can still give records processes: the limit .NET sees (a container's memory limit) minus what this
       process holds now. -1 when it cannot be read (Windows PowerShell 5.1). #>
    try {
        [System.GC]::Collect()
        $limit = [long][System.GC]::GetGCMemoryInfo().TotalAvailableMemoryBytes
        $used = [long][System.Diagnostics.Process]::GetCurrentProcess().WorkingSet64
        if ($limit -le 0) { return -1 }
        [long][Math]::Max(0, $limit - $used)
    } catch { -1 }
}

function Invoke-SIRecordsInProcesses {
    <#
        Publishes one run's record buckets in -Processes processes at once and closes the collection ONCE.
        -Script        the entry point every records process runs (container\Start-SIInContainer.ps1, SI_COLLECT_PHASE = records)
        -Environment   the records processes' settings (SI_COLLECT_PHASE, SI_COLLECT_ENGINE_RUN, SI_COLLECTION_TIME, ...);
                       each process gets its slice (SI_COLLECT_RECORDS_SLICE k/N), the run's ingest lock file and its result
                       file (SI_COLLECT_RECORDS_RESULT_FILE) on top
        -Start         test seam { param($Script, [hashtable]$Vars) } -> an object with WaitForExit() and ExitCode
        -Complete      test seam { param($Close, $CollectionTime) } -> @{ Held } (default: Complete-SIRecordFeeds on the database)
        Returns @{ Processes; Buckets; Records; Failed; ExportFailed; Closed; ExitCode }: Failed counts the buckets that did not
        reach the database plus every process that handed nothing back. Never throws for a failing process.
    #>
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][hashtable]$Environment, [int]$Processes = 2,
          [string]$Engine = '', [datetime]$CollectionTime = [datetime]::UtcNow, [scriptblock]$Start, [scriptblock]$Complete)
    if ($Processes -lt 1) { $Processes = 1 }
    if (-not $Start) {
        $Start = {
            param($Script, [hashtable]$Vars)
            $psi = New-Object System.Diagnostics.ProcessStartInfo 'pwsh'
            $psi.Arguments = ('-NoProfile -File "{0}"' -f $Script)
            $psi.UseShellExecute = $false          # the process's lines go to the job's log
            foreach ($key in $Vars.Keys) { $psi.Environment[[string]$key] = [string]$Vars[$key] }
            [System.Diagnostics.Process]::Start($psi)
        }
    }
    $tmp = [IO.Path]::GetTempPath(); $tag = [guid]::NewGuid().ToString('N')
    $lockFile = [IO.Path]::Combine($tmp, ('si-ingest-{0}.lock' -f $tag))
    $procs = New-Object System.Collections.Generic.List[object]
    $files = New-Object System.Collections.Generic.List[string]
    for ($k = 0; $k -lt $Processes; $k++) {
        $resFile = [IO.Path]::Combine($tmp, ('si-records-{0}-{1}.json' -f $tag, $k))
        $files.Add($resFile)
        $vars = @{}
        foreach ($key in $Environment.Keys) { $vars[[string]$key] = [string]$Environment[$key] }
        $vars['SI_COLLECT_RECORDS_SLICE'] = ('{0}/{1}' -f $k, $Processes)
        $vars['SI_INGEST_LOCK_FILE'] = $lockFile
        $vars['SI_COLLECT_RECORDS_RESULT_FILE'] = $resFile
        $p = $null
        try { $p = & $Start $Script $vars } catch { Write-Warning ('[parts] records process {0} of {1} could not be started: {2}' -f ($k + 1), $Processes, $_.Exception.Message) }
        $procs.Add($p)
    }
    $exit = 0
    for ($k = 0; $k -lt $procs.Count; $k++) {
        $p = $procs[$k]
        if ($null -eq $p) { $exit = 1; continue }
        try { $p.WaitForExit() } catch { }
        if ([int]$p.ExitCode -ne 0) { $exit = [int]$p.ExitCode; Write-Warning ('[parts] records process {0} of {1} ended with exit {2}' -f ($k + 1), $Processes, [int]$p.ExitCode) }
    }
    try { if ([IO.File]::Exists($lockFile)) { [IO.File]::Delete($lockFile) } } catch { }
    $buckets = 0; $records = 0L; $failed = 0; $exportFailed = 0; $missing = 0
    $closes = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $r = $null
        try { if ([IO.File]::Exists($f)) { $r = [IO.File]::ReadAllText($f) | ConvertFrom-Json } } catch { $r = $null }
        try { if ([IO.File]::Exists($f)) { [IO.File]::Delete($f) } } catch { }
        if ($null -eq $r -or -not $r.PSObject.Properties['Close']) { $missing++; continue }
        $buckets += [int]$r.Buckets; $records += [long]$r.Records; $failed += [int]$r.Failed; $exportFailed += [int]$r.ExportFailed
        $closes.Add($r.Close)
    }
    if ($missing -gt 0) {
        Write-Warning ('[parts] {0} of {1} records process(es) handed no result back -- their buckets are counted as not published, and the collection is NOT closed as complete (what they did not reach keeps its last good state).' -f $missing, $Processes)
    }
    $close = Merge-SIRecordFeedCloses -Engine $Engine -Closes $closes.ToArray() -Missing $missing
    $closed = $null
    try {
        if ($close.Pins.Count -gt 0 -or [int]$close.Failed -gt 0) {
            $cr = $null
            if ($Complete) { $cr = & $Complete $close $CollectionTime }
            else {
                if (-not (Get-Command -Name Complete-SIRecordFeeds -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecordSql.ps1') }
                $sql = New-SIRecordSqlInvoke
                if ($sql) { $cr = Complete-SIRecordFeeds -Close $close -Invoke $sql -CollectionTime $CollectionTime }
                else { Write-Warning '[parts] the run''s records could not be closed: no database is configured here.' }
            }
            if ($cr) { $closed = -not [bool]$cr.Held }
        }
    } catch { Write-Warning ('[parts] the run''s records could not be closed -- {0}. The collection counts as not complete.' -f $_.Exception.Message); $closed = $false }
    [pscustomobject]@{ Processes = $Processes; Buckets = $buckets; Records = $records; Failed = ($failed + $missing); ExportFailed = $exportFailed; Closed = $closed; ExitCode = $exit }
}
