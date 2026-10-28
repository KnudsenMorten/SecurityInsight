#Requires -Version 5.1
<#
    THE COLLECT STAGE IN PARTS (#475, operator 2026-10-08: "in my opinion the collection phase is whre it makes sense to
    scale via keda" / "i propose we have keda enabled by desin so it can automatically trigger it if enabled").

    One code path for every tenant size:
      PRODUCER  discovers ONCE, streaming: every page of objects goes straight into its PART (a stable hash of the
                object's key), so its memory is one page, never the tenant. It decides the part count for THIS run from
                what it found (Get-SICollectPartCount) and writes the MANIFEST: engine, run id, collection time, parts.
      WORKERS   one per part (KEDA scales them from the queue; a VM, or a container without a managed identity, runs the
                parts one after another in one process). A worker reads ONLY its part and ends with a MARKER:
                done, or failed with the reason.
      PIPELINE  the Collect step is the producer; it ends when the manifest's parts are all marked (Get-SICollectProgress):
                every part done = succeeded; any part failed = failed, the parts named; a part not marked by the timeout =
                incomplete -- never a quietly smaller collection.

    Storage: <account>/sistate/collect/<engine>/<runId>/manifest.json and .../parts/part-NNNNN.json. Every function that
    touches storage takes a -Store seam: @{ Read = { param($Path) <text or $null> }; Write = { param($Path, $Text) }; List =
    { param($Prefix) <paths> } } -- tests pass an in-memory one. PowerShell 5.1: no ?. / ??, no ternary.
#>

# #639 (working rule 5): NO ceiling on the part count -- it follows the measured size. ObjectsPerPart is what one part holds
# when nothing was measured; ReferenceBytesPerObject is the object size that number was set for, so a MEASURED object size
# (-BytesPerObject) keeps a part at the same bytes: bigger objects -> fewer per part -> more parts. (The old ceiling of 500
# parts put 100,000 objects in a part at 50 million objects -- ten times the memory the part was sized for.)
$script:SICollectParts = @{ ObjectsPerPart = 10000; ReferenceBytesPerObject = 8KB }

function Get-SICollectPartIndex {
    <# PURE. The part an object belongs to: the first 8 hex digits of SHA-256(lower-case key) mod Parts -- the same hash the
       engines already shard by (Invoke-Discover), so one object is always in one part. #>
    param([AllowEmptyString()][string]$Key, [Parameter(Mandatory)][int]$Parts)
    if ($Parts -le 1) { return 0 }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(([string]$Key).ToLowerInvariant()))) -replace '-', '').Substring(0, 8) }
    finally { $sha.Dispose() }
    [int]([Convert]::ToInt64($h, 16) % $Parts)
}

function Get-SICollectPartCount {
    <#
        PURE. Parts for this run, from what was MEASURED: -Objects found, and (when known) -BytesPerObject, the measured size
        of one object (e.g. a page's bytes / its objects). A part holds ~ObjectsPerPart objects of the reference size; a
        measured size scales that (objects per part = ObjectsPerPart x reference / measured, at least 1). At least 1 part,
        and NO upper bound (working rule 5): 50 million objects are 5,000 parts, each the size a part was sized for.
        -MaxParts is accepted for older callers and ignored.
    #>
    param([long]$Objects, [int]$ObjectsPerPart = 0, [double]$BytesPerObject = 0, [int]$MaxParts = 0)
    if ($ObjectsPerPart -le 0) { $ObjectsPerPart = [int]$script:SICollectParts.ObjectsPerPart }
    if ($ObjectsPerPart -le 0) { $ObjectsPerPart = 10000 }
    if ($Objects -le 0) { return 1 }
    $per = [double]$ObjectsPerPart
    $ref = [double]$script:SICollectParts.ReferenceBytesPerObject
    if ($BytesPerObject -gt 0 -and $ref -gt 0) { $per = [Math]::Max(1.0, [Math]::Floor($ObjectsPerPart * $ref / $BytesPerObject)) }
    $n = [Math]::Ceiling($Objects / $per)
    if ($n -gt [int]::MaxValue) { $n = [int]::MaxValue }
    [int][Math]::Max(1, $n)
}

function Get-SICollectPath {
    <# PURE. Where a run's manifest / part marker lives in the install's state container. #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [int]$Part = -1,
          # the run's records marker (records.json) or the claim of the worker that publishes them (records.claim)
          [ValidateSet('', 'records', 'claim')][string]$Kind = '')
    $base = 'collect/{0}/{1}' -f $Engine.ToLowerInvariant(), $RunId
    if ($Kind -eq 'records') { return "$base/records.json" }
    if ($Kind -eq 'claim') { return "$base/records.claim" }
    if ($Part -lt 0) { return "$base/manifest.json" }
    '{0}/parts/part-{1:D5}.json' -f $base, $Part
}

function New-SICollectManifest {
    <# PURE. The manifest a producer writes once it has put every object into its part. #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][datetime]$CollectionTime,
          [Parameter(Mandatory)][int]$Parts, [long]$Objects = 0, [datetime]$Now = [datetime]::UtcNow, [string]$ProducerExecution = '',
          # the records are handed over (SI-RecordHandover.ps1) under the ENGINE run id and published once after the last
          # part -- the step then ends only when that is done
          [string]$EngineRunId = '', [switch]$RecordsHandover,
          # how many buckets the run's records go into (Get-SIRecordBucketCount, decided by discovery); every worker hands its
          # records over into the same buckets. 0 = a manifest from before that: one bucket per part
          [int]$RecordBuckets = 0)
    [ordered]@{ Schema = 1; Engine = $Engine.ToLowerInvariant(); RunId = $RunId; CollectionTime = $CollectionTime.ToUniversalTime().ToString('o')
        Parts = $Parts; Objects = $Objects; WrittenUtc = $Now.ToUniversalTime().ToString('o'); ProducerExecution = $ProducerExecution
        EngineRunId = $EngineRunId; RecordsHandover = [bool]$RecordsHandover; RecordBuckets = [Math]::Max(0, $RecordBuckets) }
}

function New-SICollectPartMarker {
    <# PURE. A worker's end-of-part record: done (with its row count) or failed (with the reason). #>
    param([Parameter(Mandatory)][int]$Part, [Parameter(Mandatory)][ValidateSet('done', 'failed')][string]$State,
          [long]$Rows = 0, [string]$Reason = '', [string]$Worker = '', [datetime]$Now = [datetime]::UtcNow)
    [ordered]@{ Part = $Part; State = $State; Rows = $Rows; Reason = $Reason; Worker = $Worker; EndedUtc = $Now.ToUniversalTime().ToString('o') }
}

function Write-SICollectManifest {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Manifest)
    & $Store.Write (Get-SICollectPath -Engine $Manifest.Engine -RunId $Manifest.RunId) (ConvertTo-Json -InputObject $Manifest -Compress -Depth 4)
}

function Write-SICollectPartMarker {
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)]$Marker)
    & $Store.Write (Get-SICollectPath -Engine $Engine -RunId $RunId -Part ([int]$Marker.Part)) (ConvertTo-Json -InputObject $Marker -Compress -Depth 4)
}

function New-SICollectRecordsMarker {
    <# PURE. The end of a run's records: done (published, with counts) or failed (with the reason). #>
    param([Parameter(Mandatory)][ValidateSet('done', 'failed')][string]$State, [long]$Records = 0, [int]$Buckets = 0, [int]$FailedBuckets = 0,
          [string]$Reason = '', [string]$Worker = '', [datetime]$Now = [datetime]::UtcNow)
    [ordered]@{ State = $State; Records = $Records; Buckets = $Buckets; FailedBuckets = $FailedBuckets; Reason = $Reason; Worker = $Worker; EndedUtc = $Now.ToUniversalTime().ToString('o') }
}

function Read-SICollectRecordsMarker {
    <# The run's records marker, or $null (not published yet). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    $t = & $Store.Read (Get-SICollectPath -Engine $Engine -RunId $RunId -Kind records)
    if ([string]::IsNullOrWhiteSpace([string]$t)) { return $null }
    $t | ConvertFrom-Json
}

function Invoke-SICollectRecordsIfLast {
    <#
        #475 -- KEDA: the LAST worker publishes the run's records. Every worker calls this after it has marked its part
        (done or failed). When every part of the manifest is marked, the worker CLAIMS the run (a create-only blob: exactly
        one claimant wins, also when two finish at once), runs -Publish { -> @{ Records; Buckets; Failed } } and writes the
        records marker -- failed (with the reason) when the publish threw or a bucket failed. Returns 'published', 'failed',
        'not-last' (parts still open), 'claimed-elsewhere', or 'no-handover' (a manifest from before the hand-over).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)][scriptblock]$Publish, [string]$Worker = '')
    $m = Read-SICollectManifest -Store $Store -Engine $Engine -RunId $RunId
    if ($null -eq $m -or -not ($m.PSObject.Properties['RecordsHandover'] -and [bool]$m.RecordsHandover)) { return 'no-handover' }
    $seen = @{}; $failedParts = @{}
    foreach ($k in @(Read-SICollectPartMarkers -Store $Store -Engine $Engine -RunId $RunId)) {
        if ($null -ne $k -and $null -ne $k.Part) { $seen[[int]$k.Part] = $true; if ([string]$k.State -eq 'failed') { $failedParts[[int]$k.Part] = $true } }
    }
    for ($i = 0; $i -lt [int]$m.Parts; $i++) { if (-not $seen.ContainsKey($i)) { return 'not-last' } }
    $claim = ConvertTo-Json -InputObject ([ordered]@{ Worker = $Worker; ClaimedUtc = [datetime]::UtcNow.ToString('o') }) -Compress
    if (-not (& $Store.Claim (Get-SICollectPath -Engine $Engine -RunId $RunId -Kind claim) $claim)) { return 'claimed-elsewhere' }
    $marker = $null
    try {
        # #720: the number of FAILED parts goes to -Publish (its first argument) -- the records of a run with a failed part
        # are published, but the collection is never closed as complete (Publish-SIRecordHandover -PartsFailed): the failed
        # part's objects keep their last good state, they are unknown, never read as removed. (The step itself already
        # fails on the failed part's marker -- Get-SICollectProgress.)
        $r = & $Publish ([int]$failedParts.Count)
        if ($r -and [int]$r.Failed -gt 0) {
            $marker = New-SICollectRecordsMarker -State failed -Records ([long]$r.Records) -Buckets ([int]$r.Buckets) -FailedBuckets ([int]$r.Failed) -Worker $Worker `
                -Reason ('{0} of {1} record bucket(s) could not be published -- those records are missing from this collection' -f [int]$r.Failed, [int]$r.Buckets)
        } else {
            $recs = 0L; $bks = 0; if ($r) { $recs = [long]$r.Records; $bks = [int]$r.Buckets }
            $marker = New-SICollectRecordsMarker -State done -Records $recs -Buckets $bks -Worker $Worker
        }
    } catch {
        $marker = New-SICollectRecordsMarker -State failed -Worker $Worker -Reason ('the records could not be published: {0}' -f $_.Exception.Message)
    }
    & $Store.Write (Get-SICollectPath -Engine $Engine -RunId $RunId -Kind records) (ConvertTo-Json -InputObject $marker -Compress -Depth 4)
    if ($marker.State -eq 'done') { 'published' } else { 'failed' }
}

function Read-SICollectManifest {
    <# The manifest of a run, or $null (not written yet). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    $t = & $Store.Read (Get-SICollectPath -Engine $Engine -RunId $RunId)
    if ([string]::IsNullOrWhiteSpace([string]$t)) { return $null }
    $t | ConvertFrom-Json
}

function Read-SICollectPartMarkers {
    <# Every part marker of a run that exists (plain output). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    $prefix = ((Get-SICollectPath -Engine $Engine -RunId $RunId) -replace 'manifest\.json$', 'parts/')
    foreach ($p in @(& $Store.List $prefix)) {
        if (-not $p) { continue }
        $t = & $Store.Read $p
        if ([string]::IsNullOrWhiteSpace([string]$t)) { continue }
        try { $t | ConvertFrom-Json } catch { }
    }
}

function New-SICollectBlobStore {
    <# The state store over the install's storage account (<account>/sistate/<path>), signed in as the job (OAuth). #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistate')
    if (-not (Get-Command -Name Get-SIBlobContent -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AzRest.ps1') }
    $acc = $Account; $con = $Container
    # The three blob functions travel INTO the store as values: its blocks are called long after this function returned,
    # from wherever the caller is -- a name looked up at call time is whatever that scope can see (a GetNewClosure() block
    # runs in its own scope). Missing ones are named in a plain throw at the first call.
    $getFn = ${function:Get-SIBlobContent}; $setFn = ${function:Set-SIBlobContent}; $listFn = ${function:Get-SIBlobList}
    $missing = @(@(@{ N = 'Get-SIBlobContent'; F = $getFn }, @{ N = 'Set-SIBlobContent'; F = $setFn }, @{ N = 'Get-SIBlobList'; F = $listFn }) | Where-Object { -not $_.F } | ForEach-Object { $_.N }) -join ', '
    if ($missing) {
        $fail = { param($Path, $Text) throw ("the state store cannot be read or written in this job ({0} not loaded from engine\_shared\SI-AzRest.ps1)" -f $missing) }.GetNewClosure()
        return [pscustomobject]@{ Read = $fail; Write = $fail; List = $fail; Claim = $fail }
    }
    [pscustomobject]@{
        # -AllowMissing: a marker that is not there yet (the records marker, a part, closed.json) is $null -- not an error
        # raised and logged on every poll
        Read  = { param($Path) try { $b = & $getFn -Account $acc -Container $con -Blob $Path -AllowMissing; if (-not $b -or $b.Length -eq 0) { $null } else { [Text.Encoding]::UTF8.GetString($b) } } catch { if ("$($_.Exception.Message)" -match '404|BlobNotFound|ContainerNotFound|not found') { $null } else { throw } } }.GetNewClosure()
        Write = { param($Path, $Text) $null = & $setFn -Account $acc -Container $con -Blob $Path -Bytes ([Text.Encoding]::UTF8.GetBytes([string]$Text)) -ContentType 'application/json' }.GetNewClosure()
        List  = { param($Prefix) try { @(& $listFn -Account $acc -Container $con -Prefix $Prefix | ForEach-Object { $_.Name }) } catch { if ("$($_.Exception.Message)" -match '404|ContainerNotFound|not found') { @() } else { throw } } }.GetNewClosure()
        # create-only: $true for the one writer that created it, $false when it already exists (409 / 412)
        Claim = { param($Path, $Text) try { $null = & $setFn -Account $acc -Container $con -Blob $Path -Bytes ([Text.Encoding]::UTF8.GetBytes([string]$Text)) -ContentType 'application/json' -IfNoneMatch; $true } catch { if ("$($_.Exception.Message)" -match '409|412|BlobAlreadyExists|ConditionNotMet') { $false } else { throw } } }.GetNewClosure()
    }
}

function Get-SICollectProgress {
    <#
        PURE. Where a Collect step stands: the manifest + the part markers -> @{ State; Parts; Done; Failed; Missing; Text }.
          State  waiting     no manifest yet (the producer is still discovering)
                 running     parts still open, within the timeout
                 succeeded   every part done
                 failed      every part marked, one or more failed (they are named)
                 incomplete  parts still unmarked after -TimeoutMinutes since the manifest -- never quietly smaller
        A failed part ends the step as soon as nothing is still running (no wait for the timeout).
    #>
    param([AllowNull()]$Manifest, [AllowEmptyCollection()][object[]]$Markers = @(), [datetime]$Now = [datetime]::UtcNow, [int]$TimeoutMinutes = 180,
          # the run's records marker (Read-SICollectRecordsMarker): waited for when the manifest says RecordsHandover
          [AllowNull()]$Records)
    if ($null -eq $Manifest) { return [pscustomobject]@{ State = 'waiting'; Parts = 0; Done = 0; Failed = @(); Missing = @(); Text = 'discovering -- the parts are not written yet' } }
    $n = [int]$Manifest.Parts
    $byPart = @{}
    foreach ($m in @($Markers)) { if ($null -ne $m -and $null -ne $m.Part -and [int]$m.Part -ge 0 -and [int]$m.Part -lt $n) { $byPart[[int]$m.Part] = $m } }
    $done = @($byPart.Values | Where-Object { $_.State -eq 'done' }).Count
    $failed = @($byPart.Values | Where-Object { $_.State -eq 'failed' } | Sort-Object { [int]$_.Part })
    $missing = @(0..($n - 1) | Where-Object { -not $byPart.ContainsKey($_) })
    $failText = (@($failed | ForEach-Object { 'part {0}: {1}' -f ([int]$_.Part + 1), $(if ($_.Reason) { $_.Reason } else { 'no reason given' }) })) -join '; '
    $handover = [bool]($Manifest.PSObject.Properties['RecordsHandover'] -and [bool]$Manifest.RecordsHandover)
    $since = $null; try { $since = [datetime]::Parse([string]$Manifest.WrittenUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } catch { }
    # -TimeoutMinutes 0 (what the pipeline passes since 2026-10-13): no give-up on elapsed time -- never 'incomplete'
    $timedOut = [bool]($TimeoutMinutes -gt 0 -and $since -and ($Now.ToUniversalTime() - $since).TotalMinutes -gt $TimeoutMinutes)
    if ($missing.Count -eq 0 -and $handover) {
        # every part is marked; the step ends when the last worker has published the run's records
        if ($null -eq $Records) {
            if ($timedOut) {
                return [pscustomobject]@{ State = 'incomplete'; Parts = $n; Done = $done; Failed = $failed; Missing = @()
                    Text = ('{0} of {1} part(s) done, but the records were not published after {2} minutes -- the collection is INCOMPLETE{3}' -f $done, $n, $TimeoutMinutes, $(if ($failText) { '; ' + $failText } else { '' })) }
            }
            return [pscustomobject]@{ State = 'running'; Parts = $n; Done = $done; Failed = $failed; Missing = @(); Text = ('{0} of {1} part(s) done -- publishing the records' -f $done, $n) }
        }
        if ([string]$Records.State -eq 'failed') {
            return [pscustomobject]@{ State = 'failed'; Parts = $n; Done = $done; Failed = $failed; Missing = @()
                Text = ('{0} of {1} part(s) done; {2}{3}' -f $done, $n, [string]$Records.Reason, $(if ($failText) { '; ' + $failText } else { '' })) }
        }
    }
    if ($missing.Count -eq 0) {
        if ($failed.Count) { return [pscustomobject]@{ State = 'failed'; Parts = $n; Done = $done; Failed = $failed; Missing = @(); Text = ('{0} of {1} part(s) done, {2} failed -- {3}' -f $done, $n, $failed.Count, $failText) } }
        return [pscustomobject]@{ State = 'succeeded'; Parts = $n; Done = $done; Failed = @(); Missing = @(); Text = ('all {0} part(s) done' -f $n) }
    }
    if ($timedOut) {
        $miss = (@($missing | Select-Object -First 10 | ForEach-Object { $_ + 1 })) -join ', '
        return [pscustomobject]@{ State = 'incomplete'; Parts = $n; Done = $done; Failed = $failed; Missing = $missing
            Text = ('{0} of {1} part(s) done; part(s) {2}{3} not finished after {4} minutes -- the collection is INCOMPLETE{5}' -f $done, $n, $miss, $(if ($missing.Count -gt 10) { ' ...' } else { '' }), $TimeoutMinutes, $(if ($failText) { '; ' + $failText } else { '' })) }
    }
    [pscustomobject]@{ State = 'running'; Parts = $n; Done = $done; Failed = $failed; Missing = $missing
        Text = ('{0} of {1} part(s) done{2}' -f $done, $n, $(if ($failed.Count) { ', {0} failed' -f $failed.Count } else { '' })) }
}

# #720 (live 2026-10-16, the large ring-1 install: 195,524 devices in 16 parts) -- "[producer] the parts could not be
# queued: OutOfMemoryException", six times, while the run-health END said "success": the engine wrote its END before the
# container handed the parts over, and the hand-over's failure only set the exit code. A hand-over that fails now ENDS THE
# RUN NOT COMPLETE: a second END record (error, with the out-of-memory class si-col-0501 when it was memory -- the update's
# size rule reads it and raises the job one band), and every part the workers will never get is marked failed, so the
# pipeline ends the step at once and the last worker's records never close the collection as complete.
function Get-SICollectHandoverFailure {
    <#
        PURE. What a failed hand-over means. -Where: producer (the parts could not be queued), discover (a discovery child
        could not hand its run to the parts), part (a part's records were not handed over). -ErrorText: the exception's
        message. -Parts / -Queued: how many parts the run has and how many messages went out before the failure;
        -ManifestWritten: the pipeline already follows the run (then the parts not queued get a FAILED marker).
        Returns @{ OutOfMemory; Code ('si-col-0501' or ''); ExitReason ('error'); Text; FailParts (part indexes) }.
    #>
    param([Parameter(Mandatory)][string]$Engine, [AllowEmptyString()][string]$ErrorText = '',
          [Parameter(Mandatory)][ValidateSet('producer', 'discover', 'part')][string]$Where,
          [int]$Parts = 0, [int]$Queued = 0, [int]$Part = -1, [switch]$ManifestWritten)
    $err = ("$ErrorText" -replace '\s+', ' ').Trim()
    if ($err.Length -gt 400) { $err = $err.Substring(0, 397) + '...' }
    $oom = [bool]($err -match '(?i)OutOfMemory|out of memory|Insufficient memory|si-col-0501')
    $code = if ($oom) { 'si-col-0501' } else { '' }
    $why = if ($oom) { 'si-col-0501: out of memory' } else { 'the hand-over failed' }
    $e = $Engine.ToLowerInvariant()
    $what = switch ($Where) {
        'producer' { 'The parts of this {0} collection could not be handed to its workers' -f $e }
        'discover' { 'The discovered {0} run could not be handed to its parts' -f $e }
        'part'     { 'Part {0} of this {1} collection could not hand its records over' -f $(if ($Part -ge 0) { $Part + 1 } else { '?' }), $e }
    }
    $text = '{0} ({1}) -- this {2} collection is NOT COMPLETE and stays on its last good collection; nothing in it is read as removed: {3}' -f $what, $why, $e, $(if ($err) { $err } else { 'no reason was given' })
    $fail = @()
    if ($Where -eq 'producer' -and $ManifestWritten -and $Parts -gt 0) {
        $from = [Math]::Max(0, [Math]::Min($Queued, $Parts))
        if ($from -lt $Parts) { $fail = @($from..($Parts - 1)) }
    }
    [pscustomobject]@{ OutOfMemory = $oom; Code = $code; ExitReason = 'error'; Text = $text; FailParts = $fail }
}

function Write-SICollectHandoverFailure {
    <#
        The parts a failed hand-over leaves without a worker (-Failure.FailParts) get a FAILED marker with the reason, so
        the pipeline's step ends failed at once and the last worker's records are published without closing the collection.
        -RunId: the manifest's run (the producer's execution).
        When that leaves every part marked (nothing was queued, or the queued workers have all finished already) no worker
        is left to end the run's records: this process takes the run's records claim and writes a FAILED records marker with
        the reason (Invoke-SICollectRecordsIfLast) -- nothing is published, the collection stays on its last good state and
        the step ends failed instead of waiting for ever. Never throws: @{ Written; Records ('' | failed | not-last |
        claimed-elsewhere | no-handover); Why }.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId,
          [Parameter(Mandatory)]$Failure, [string]$Worker = '')
    $n = 0; $why = ''; $rec = ''
    foreach ($i in @($Failure.FailParts)) {
        try {
            Write-SICollectPartMarker -Store $Store -Engine $Engine -RunId $RunId -Marker (New-SICollectPartMarker -Part ([int]$i) -State failed -Reason ([string]$Failure.Text) -Worker $Worker)
            $n++
        } catch { if (-not $why) { $why = $_.Exception.Message } }
    }
    if ($n -gt 0) {
        $reason = [string]$Failure.Text
        try { $rec = [string](Invoke-SICollectRecordsIfLast -Store $Store -Engine $Engine -RunId $RunId -Worker $Worker -Publish { param($PartsFailed) throw $reason }) }
        catch { if (-not $why) { $why = $_.Exception.Message } }
    }
    [pscustomobject]@{ Written = $n; Records = $rec; Why = $why }
}

function Close-SICollectRunsOf {
    <#
        #882 -- A STEP THE PIPELINE ENDED LEAVES NO RUN BEHIND FOR ITS WORKERS (live 2026-10-22, internal: the pipeline closed
        the Detailed Risk Analysis step Interrupted at 09:40Z, and a queue worker of it went on querying until 10:30 and wrote
        the remembered slice count the next run used). The pipeline marks the runs of the step's producer CLOSED in the state
        store (collect/<engine>/<runId>/closed.json, the mark the Risk Analysis queue workers read: RA-ScaleOut.ps1): a
        worker then discards every message of that run and writes nothing for it, also a worker the queue scaler starts later.
        Which runs: those whose manifest names -ProducerExecution (the step's own execution -- exact); without it, those
        written at or after -SinceUtc (5 minutes earlier, the clocks' slack); with neither, none (never every run).
        A run already closed is left as it is. Never throws: @{ Closed (run ids); Why ('' or what could not be done) }.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [AllowEmptyString()][string]$ProducerExecution = '',
          $SinceUtc = $null, [string]$Why = 'the pipeline ended this step', [datetime]$Now = [datetime]::UtcNow)
    $closed = New-Object System.Collections.Generic.List[string]
    $err = ''
    $exec = ([string]$ProducerExecution).Trim()
    $since = $null; if ($SinceUtc) { try { $since = ([datetime]$SinceUtc).ToUniversalTime().AddMinutes(-5) } catch { $since = $null } }
    if (-not $exec -and $null -eq $since) { return [pscustomobject]@{ Closed = @(); Why = 'neither the producer''s execution nor the step''s start is known -- no run is closed' } }
    try {
        $prefix = 'collect/{0}/' -f $Engine.ToLowerInvariant()
        $runs = @{}
        foreach ($p in @(& $Store.List $prefix)) {
            if (-not $p) { continue }
            $rest = ([string]$p).Substring([Math]::Min($prefix.Length, ([string]$p).Length))
            $id = ($rest -split '/', 2)[0]
            if (-not $id) { continue }
            if (-not $runs.ContainsKey($id)) { $runs[$id] = @{ Manifest = $false; Closed = $false } }
            if ($rest -eq "$id/manifest.json") { $runs[$id].Manifest = $true }
            if ($rest -eq "$id/closed.json") { $runs[$id].Closed = $true }
        }
        foreach ($id in @($runs.Keys | Sort-Object)) {
            if (-not $runs[$id].Manifest -or $runs[$id].Closed) { continue }
            $m = $null
            try { $t = & $Store.Read ('{0}{1}/manifest.json' -f $prefix, $id); if (-not [string]::IsNullOrWhiteSpace([string]$t)) { $m = $t | ConvertFrom-Json } } catch { $m = $null }
            if ($null -eq $m) { continue }
            $mine = $false
            $pe = if ($m.PSObject.Properties['ProducerExecution']) { ([string]$m.ProducerExecution).Trim() } else { '' }
            if ($exec) { $mine = ($pe -and [string]::Equals($pe, $exec, [System.StringComparison]::OrdinalIgnoreCase)) }
            elseif ($m.PSObject.Properties['WrittenUtc'] -and $m.WrittenUtc) {
                # (PowerShell 7's ConvertFrom-Json already reads an ISO text as a [datetime])
                if ($m.WrittenUtc -is [datetime]) { $mine = (([datetime]$m.WrittenUtc).ToUniversalTime() -ge $since) }
                else {
                    $w = [datetime]::MinValue
                    if ([datetime]::TryParse([string]$m.WrittenUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$w)) { $mine = ($w -ge $since) }
                }
            }
            if (-not $mine) { continue }
            & $Store.Write ('{0}{1}/closed.json' -f $prefix, $id) (ConvertTo-Json -InputObject ([ordered]@{ ClosedUtc = $Now.ToUniversalTime().ToString('o'); Why = $Why }) -Compress)
            $closed.Add($id)
        }
    } catch { $err = [string]$_.Exception.Message }
    [pscustomobject]@{ Closed = $closed.ToArray(); Why = $err }
}
