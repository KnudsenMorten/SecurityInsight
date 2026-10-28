#Requires -Version 5.1
<#
    #721 -- THE PRODUCER STREAMS ITS RECORDS, FOR EVERY TENANT (owner 2026-10-16: "we must use same method across all cust" /
    "hw can be diff but code and methods the same, like streaming no matter size").

    The large ring-2 tenant (2026-10-16): 1,565,906 Exposure Graph user nodes (most of them AD-only accounts, kept as AD
    identity records) and 195,524 endpoint assets -- the identity and endpoint producers held EVERY captured record in
    memory until the hand-over, and the endpoint producer ran out of memory handing them over ("the parts could not be
    queued: OutOfMemoryException"). What these keep true (offline):
      1. the SAME method at every size: in the discover phase every captured part is written to the local record stream and
         let go -- a 13-record tenant and a 5,000-record tenant alike; since #727 the Azure records too (nothing is held:
         SIv3-AzureRecordStream.Tests.ps1 covers the Azure fold);
      2. EQUIVALENCE: the stream hands over exactly the records the in-memory capture handed over -- after the merge every
         record has the same provider, type, key, resource type, engines and parts (the later part wins, as before), and
         the run's pulls are the same; small and larger sets through the same path;
      3. discovery's read-backs see a streamed record: the context parts (Entra / Defender for Identity ids are remembered,
         not the records), the service principal owners, Intune "not licensed";
      4. GUARD: nothing in identity / endpoint discovery or the hand-over picks an in-memory method by the size of the tenant
         or the number of records.
    PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{
            Data  = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure()
        }
    }
    # one deterministic capture sequence: several providers, parts added later to the same record, a part replaced,
    # resource types, an Azure record (streamed too since #727) -- the calls a discovery makes
    function script:Invoke-Capture([int]$N) {
        for ($i = 0; $i -lt $N; $i++) {
            Add-SIRecordPart -Provider entra -RecordType user -Key ("U{0:D6}" -f $i) -Part user -Object ([pscustomobject]@{ id = "u$i"; upn = "user$i@x.example"; n = $i })
            if ($i % 3 -eq 0) { Add-SIRecordPart -Provider mdi -RecordType user -Key ("u{0:D6}" -f $i) -Part identity -Object @{ IsServiceAccount = $false; i = $i } }
            Add-SIRecordPart -Provider eg -RecordType user -Key "node-$i" -Part node -Object ([pscustomobject]@{ NodeId = "node-$i"; SIIdentitySource = 'ad'; NodeProperties = @{ rawData = @{ accountSid = "S-1-5-21-1-2-3-$i"; pad = ('p' * ($i % 50)) } } })
            if ($i % 4 -eq 0) { Add-SIRecordPart -Provider mde -RecordType device -Key ('{0:x40}' -f $i) -Part machine -Object @{ id = $i; lastSeen = '2026-10-15T00:00:00Z' } }
            if ($i % 7 -eq 0) { Add-SIRecordPart -Provider azure -RecordType azure_resource -Key "kv$i" -Part resource -Object @{ id = $i } -ResourceType 'microsoft.keyvault/vaults' }
        }
        # later in the run: more parts on the same records, and a part captured again (the newer read wins)
        for ($i = 0; $i -lt $N; $i += 2) {
            Add-SIRecordPart -Provider entra -RecordType user -Key ("u{0:D6}" -f $i) -Part registration -Object @{ isMfaRegistered = ($i % 4 -eq 0) }
            Add-SIRecordPart -Provider eg -RecordType user -Key "NODE-$i" -Part node -Object ([pscustomobject]@{ NodeId = "node-$i"; SIIdentitySource = 'ad'; second = $true })
        }
        if ($N -gt 5) { Add-SIRecordPart -Provider mde -RecordType device -Key ('{0:x40}' -f 4) -Part machine -Object @{ id = 4 } -ResourceType 'windows' }
        Set-SIRecordPull -Provider entra -Complete $true
        Set-SIRecordPull -Provider eg -Complete $false -ErrorText 'bucket 3 of 9 failed'
    }
    # the records as the last step merges them: id -> a canonical text of everything a record carries
    function script:Get-Merged($Store, [int]$Buckets) {
        $out = @{}; $pulls = @{}
        for ($b = 0; $b -lt $Buckets; $b++) {
            $paths = @($Store.Data.Keys | Where-Object { $_ -match ('/bucket-{0:D5}-\d{{5}}\.json$' -f $b) } | Sort-Object)
            $m = $null
            foreach ($p in $paths) { $m = Merge-SIRecordHandover -Documents @($Store.Data[$p] | ConvertFrom-Json) -Into $m }
            if ($null -eq $m) { continue }
            foreach ($e in $m.Records.GetEnumerator()) {
                $r = $e.Value
                $parts = (@($r.Parts.Keys | Sort-Object) | ForEach-Object { '{0}={1}' -f $_, [string]$r.Parts[$_].SIJson }) -join ';'
                $out[[string]$e.Key] = '{0}|{1}|{2}|{3}|{4}|{5}' -f $r.Provider, $r.RecordType, $r.Key, $r.ResourceType, ((@($r.Engines) | Sort-Object) -join ','), $parts
            }
            foreach ($p in $m.Pulls.Values) { $pulls[[string]$p.Provider] = '{0}:{1}' -f $p.Complete, $p.Error }
        }
        [pscustomobject]@{ Records = $out; Pulls = $pulls }
    }
    function script:Invoke-Both([int]$N, [int]$Buckets) {
        # in memory (the hand-over of a part / the old producer)
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        Invoke-Capture $N
        $a = MemStore; $na = Save-SIRecordHandover -Store $a -Engine identity -RunId r -Who discover -Buckets $Buckets -ChunkSize 97
        # streamed (the discover phase)
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $s = Start-SIRecordCaptureStream
        Invoke-Capture $N
        $held = $global:SIRecordCaptureState.Records.Count
        $items = $s.Items
        $b = MemStore; $nb = Save-SIRecordHandover -Store $b -Engine identity -RunId r -Who discover -Buckets $Buckets -ChunkSize 97
        [pscustomobject]@{ Memory = (Get-Merged $a $Buckets); Stream = (Get-Merged $b $Buckets); Held = $held; Items = $items; StreamPath = $s.Path; StoreA = $a; StoreB = $b; NA = $na; NB = $nb }
    }
}

AfterAll { $null = Reset-SIRecordCapture -Clear }

Describe '1+2. one method at every size, and the stream hands over exactly the in-memory records' {
    It 'a <Name> set: the same records, parts, engines, resource types and pulls -- nothing was held' -TestCases @(
        @{ Name = 'tiny (13 calls)'; N = 3; Buckets = 1 }
        @{ Name = 'small'; N = 40; Buckets = 3 }
        @{ Name = 'larger'; N = 1500; Buckets = 7 }
    ) {
        $r = Invoke-Both -N $N -Buckets $Buckets
        $r.Memory.Records.Count | Should -BeGreaterThan 0
        @($r.Stream.Records.Keys | Sort-Object) | Should -Be @($r.Memory.Records.Keys | Sort-Object)
        foreach ($k in $r.Memory.Records.Keys) { $r.Stream.Records[$k] | Should -Be $r.Memory.Records[$k] -Because "record $k" }
        foreach ($k in $r.Memory.Pulls.Keys) { $r.Stream.Pulls[$k] | Should -Be $r.Memory.Pulls[$k] -Because "pull $k" }
        # streamed: nothing was held while capturing -- the Azure records too (#727), every part went to the stream
        $r.Held | Should -Be 0
        $r.Items | Should -BeGreaterThan $r.Memory.Records.Count -Because 'a record captured in several calls is several items'
        # the stream's file is gone after the hand-over, and the capture holds nothing
        Test-Path -LiteralPath $r.StreamPath | Should -BeFalse
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
        $global:SIRecordCaptureState.Stream | Should -BeNullOrEmpty
    }
    It 'the later part wins across the stream, exactly as in memory (a node captured twice, a machine re-read)' {
        $r = Invoke-Both -N 12 -Buckets 2
        $r.Stream.Records['eg|user|node-2'] | Should -Match 'second'
        $r.Stream.Records['eg|user|node-1'] | Should -Not -Match 'second'
        $r.Stream.Records[('mde|device|{0:x40}' -f 4)] | Should -Match '\|windows\|'
    }
    It 'records captured before the stream started go into it first, in their order' {
        $null = Reset-SIRecordCapture -Engine 'endpoint' -Clear
        Add-SIRecordPart -Provider mde -RecordType device -Key 'm1' -Part machine -Object @{ v = 1 }
        $s = Start-SIRecordCaptureStream
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
        $s.Items | Should -Be 1
        Add-SIRecordPart -Provider mde -RecordType device -Key 'm1' -Part machine -Object @{ v = 2 }
        $st = MemStore
        $null = Save-SIRecordHandover -Store $st -Engine endpoint -RunId r -Who discover -Buckets 1
        (Get-Merged $st 1).Records['mde|device|m1'] | Should -Match '"v":2'
    }
    It 'the bucket count comes from what was captured -- held records + streamed items' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $null = Start-SIRecordCaptureStream
        Invoke-Capture 10
        Get-SIRecordCaptureCount | Should -Be ($global:SIRecordCaptureState.Records.Count + $global:SIRecordCaptureState.Stream.Items)
        Stop-SIRecordCaptureStream
    }
    It 'a stream line''s id is read without parsing the line, escaped ids too' {
        Get-SIRecordStreamLineId -Line '{"Id":"eg|user|node-1","Provider":"eg"}' | Should -Be 'eg|user|node-1'
        Get-SIRecordStreamLineId -Line '{"Id":"ad|user|a\"b\\c","Provider":"ad"}' | Should -Be 'ad|user|a"b\c'
    }
}

Describe '3. discovery''s read-backs see streamed records' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIEntraContext.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    }
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $null = Start-SIRecordCaptureStream
        Add-SIRecordPart -Provider entra -RecordType user -Key 'U1' -Part user -Object @{ id = 'u1' }
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key 'S1' -Part sp -Object @{ id = 's1' }
        Add-SIRecordPart -Provider mdi -RecordType user -Key 'U1' -Part identity -Object @{ x = 1 }
        Add-SIRecordPart -Provider eg -RecordType user -Key 'n1' -Part node -Object @{ x = 1 }
    }
    AfterEach { Stop-SIRecordCaptureStream }
    It 'the Entra / Defender for Identity ids are remembered (the records are not held); other providers'' ids are not kept' {
        $global:SIRecordCaptureState.Records.Count | Should -Be 0
        Test-SIRecordCaptured -Id 'entra|user|u1' | Should -BeTrue
        Test-SIRecordCaptured -Id 'ENTRA|USER|U1' | Should -BeTrue
        Test-SIRecordCaptured -Id 'entra|user|u2' | Should -BeFalse
        @(Get-SIRecordCapturedKeys -Provider entra -RecordType user) | Should -Be @('u1')
        @(Get-SIRecordCapturedKeys -Provider mdi -RecordType user) | Should -Be @('u1')
        @(Get-SIEntraCapturedIds -RecordType 'service_principal') | Should -Be @('s1')
        $global:SIRecordCaptureState.Stream.Ids.Count | Should -Be 3 -Because 'eg ids are never asked for again -- not kept'
    }
    It 'a context part reaches a streamed record, and never makes a new one' {
        Add-SIEntraContextPart -RecordType user -Id 'U1' -Part 'manager' -Object @{ id = 'm' } | Should -BeTrue
        Add-SIEntraContextPart -RecordType user -Id 'U9' -Part 'manager' -Object @{ id = 'm' } | Should -BeFalse
        $st = MemStore
        $null = Save-SIRecordHandover -Store $st -Engine identity -RunId r -Who discover -Buckets 1
        $m = (Get-Merged $st 1).Records
        $m['entra|user|u1'] | Should -Match 'manager='
        $m['entra|user|u1'] | Should -Match 'user='
        $m.ContainsKey('entra|user|u9') | Should -BeFalse
    }
    It 'the service principal owners reach a streamed service principal' {
        Mock Get-SISpOwnerCounts { [pscustomobject]@{ Read = $true; Counts = @{ 's1' = 2; 's9' = 1 }; Owners = @{} } }
        Invoke-SISpOwnerCapture -Token 't' | Should -Be 1
    }
    It 'Intune "not licensed" reaches every streamed Entra device (the reader asks the capture, held or streamed)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIIntuneContext.ps1'))
        $src | Should -Match ([regex]::Escape("foreach (`$dk in @(Get-SIRecordCapturedKeys -Provider 'entra' -RecordType 'device'))"))
        $src | Should -Match ([regex]::Escape("Add-SIRecordPart -Provider 'entra' -RecordType 'device' -Key `$dk -Part 'intuneState'"))
    }
}

Describe '4. GUARD: one method -- no size decides in-memory or streamed' {
    BeforeAll {
        $script:Read = { param($rel) [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) }
    }
    It 'the discover phase starts the record stream on the PHASE alone (every engine, every tenant)' {
        $d = & $script:Read 'engine\asset-profiling\stages\Invoke-Discover.ps1'
        $d | Should -Match ([regex]::Escape("if (`$RunContext.PSObject.Properties['Phase'] -and [string]`$RunContext.Phase -eq 'discover' -and (Get-Command -Name Start-SIRecordCaptureStream -ErrorAction SilentlyContinue)) {"))
        $i = $d.IndexOf('$null = Start-SIRecordCaptureStream'); $j = $d.IndexOf('$sources = @(')
        ($i -gt 0 -and $i -lt $j) | Should -BeTrue -Because 'the stream starts before any source reads'
    }
    It 'a captured part streams on the stream being open -- every provider, the Azure records too (#727); no count, no size' {
        $c = & $script:Read 'engine\data-model\SI-RecordCapture.ps1'
        $c | Should -Match ([regex]::Escape("if (`$cs.PSObject.Properties['Stream'] -and `$null -ne `$cs.Stream) {"))
        $c | Should -Not -Match 'SIRecordStreamInMemory' -Because 'no provider is kept in memory any more'
    }
    It 'the hand-over takes the stream whenever there is one' {
        $h = & $script:Read 'engine\data-model\SI-RecordHandover.ps1'
        $h | Should -Match ([regex]::Escape("if (`$State.PSObject.Properties['Stream'] -and `$null -ne `$State.Stream) {"))
    }
    It 'no record or object COUNT selects a method in discovery, the stream or the hand-over' -TestCases @(
        @{ f = 'engine\data-model\SI-RecordCapture.ps1' }
        @{ f = 'engine\data-model\SI-RecordHandover.ps1' }
        @{ f = 'engine\asset-profiling\stages\Invoke-Discover.ps1' }
        @{ f = 'engine\asset-profiling\shared\SI-DiscoverStream.ps1' }
    ) {
        $code = (& $script:Read $f) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }
        # a branch on a count of records / objects / assets against a size, deciding where things are kept
        $hits = @($code | Where-Object { $_ -match '\bif\s*\(.*(Records\.Count|Items|\$streamObjects|\$assets\.Count|RecordCount|AssetCount)\s*-(gt|ge|lt|le)\s*\$?(?!0\b|1\b)\w' })
        $hits | Should -BeNullOrEmpty
        $code -join "`n" | Should -Not -Match 'SI_RecordStream(Threshold|Min|Max)|StreamAbove|InMemoryBelow'
    }
    It 'the producer''s bucket count reads the capture count (held + streamed), never a copy of every key' {
        $s = & $script:Read 'container\Start-SIInContainer.ps1'
        $s | Should -Not -Match ([regex]::Escape('@($global:SIRecordCaptureState.Records.Keys).Count'))
        ([regex]::Matches($s, [regex]::Escape('Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount)'))).Count | Should -Be 2
    }
    It 'every container hand-over loads the capture functions in its own scope before it counts and hands over (2105 live: "Get-SIRecordCaptureCount is not recognized")' {
        # the engine loads SI-RecordCapture.ps1 in ITS scope; the container's producer / discovery hand-over runs in the container
        # script's scope and must load it there too -- the count AND the stream's close (Save-SIRecordHandover calls it when present)
        $lines = (& $script:Read 'container\Start-SIInContainer.ps1') -split "`r?`n"
        $calls = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Get-SIRecordCaptureCount' -and $lines[$i] -notmatch '^\s*#') { $i } })
        $calls.Count | Should -Be 2
        foreach ($c in $calls) {
            $from = [Math]::Max(0, $c - 12)
            $window = $lines[$from..$c] -join "`n"
            $window | Should -Match ([regex]::Escape('. /app/engine/data-model/SI-RecordCapture.ps1')) -Because "line $($c + 1) counts the capture"
            $window | Should -Match ([regex]::Escape('. /app/engine/data-model/SI-RecordHandover.ps1'))
        }
    }
    It 'every container hand-over loads, in its own scope, what the streamed Azure fold calls (#727): the capture (and through it SI-AzureChildren), the parts'' hash, the hand-over' {
        # Save-SIRecordHandover of a streamed capture routes the Azure lines by group (Get-SICollectPartIndex, SI-CollectParts.ps1),
        # merges each group file (Merge-SIRecordHandover) and folds it (Resolve-SIRecordChildren, SI-AzureChildren.ps1, loaded by
        # SI-RecordCapture.ps1) -- all from the CONTAINER's scope, not the engine's
        $lines = (& $script:Read 'container\Start-SIInContainer.ps1') -split "`r?`n"
        $calls = @(for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match 'Save-SIRecordHandover\s' -and $lines[$i] -notmatch '^\s*#') { $i } })
        $calls.Count | Should -Be 2
        foreach ($c in $calls) {
            $window = $lines[([Math]::Max(0, $c - 25))..$c] -join "`n"
            foreach ($f in 'engine/_shared/SI-CollectParts.ps1', 'engine/data-model/SI-RecordCapture.ps1', 'engine/data-model/SI-RecordHandover.ps1') {
                $window | Should -Match ([regex]::Escape(". /app/$f")) -Because "line $($c + 1) hands the records over"
            }
        }
        # SI-RecordCapture.ps1 loads the fold at FILE level (a dot-source inside a function would not outlive it)
        $rc = (& $script:Read 'engine\data-model\SI-RecordCapture.ps1') -split "`r?`n"
        @($rc | Where-Object { $_ -match "^\. \(Join-Path \`$PSScriptRoot 'SI-AzureChildren\.ps1'\)" }).Count | Should -Be 1
        # and the hand-over refuses to hand over unfolded children when the fold is missing from the caller's scope
        (& $script:Read 'engine\data-model\SI-RecordHandover.ps1') | Should -Match 'Resolve-SIRecordChildren is not loaded in this scope'
    }
    It 'the Exposure Graph identity index is let go after the sources, before the parts are routed (the measured peak)' {
        $d = & $script:Read 'engine\asset-profiling\stages\Invoke-Discover.ps1'
        $i = $d.IndexOf("`$script:_SICache.Remove('EgIdentitiesMap')")
        $j = $d.IndexOf('$streamDone = Complete-SIDiscoverStream -Stream $global:SI_DiscoverStream')
        $k = $d.IndexOf('foreach ($pair in $sources) {')
        ($k -gt 0 -and $i -gt $k -and $j -gt $i) | Should -BeTrue
    }
    It 'a raw discovery bucket is routed row by row, never read whole' {
        $s = & $script:Read 'engine\asset-profiling\shared\SI-DiscoverStream.ps1'
        $s | Should -Match ([regex]::Escape("Read-SIDiscoverStreamPart -Stream `$Stream -Stage 'DiscoverRaw' -Part `$b -OnRecord `$route"))
        $b = & $script:Read 'engine\asset-profiling\storage\StagingBlob.ps1'
        $b | Should -Match ([regex]::Escape('if ($OnRecord) { & $OnRecord ($line | ConvertFrom-Json); continue }'))
    }
}
