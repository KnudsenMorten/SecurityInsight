#Requires -Version 5.1
<#
    THE COLLECT STAGE IN PARTS (engine/_shared/SI-CollectParts.ps1, #475 -- KEDA by design for the Collect stage).

      * PART: one object is always in one part (a stable hash of its key, case-insensitive), spread evenly; one part = 0.
      * COUNT: the producer decides the parts per run from what it found -- ~10,000 objects each (scaled by a measured object
        size), at least 1, NO upper bound (#639: millions of assets; the old ceiling of 500 is gone).
      * MANIFEST + MARKERS: written to and read from the state store at fixed paths; a marker outside the manifest's parts
        is ignored.
      * PROGRESS: no manifest = waiting (discovering); open parts = running; all done = succeeded; all marked with one or
        more failed = failed, the parts NAMED; parts unmarked after the timeout = INCOMPLETE -- never quietly smaller.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    function script:New-MemStore {
        $docs = @{}
        [pscustomobject]@{
            Docs  = $docs
            Read  = { param($p) if ($docs.ContainsKey($p)) { $docs[$p] } else { $null } }.GetNewClosure()
            Write = { param($p, $t) $docs[$p] = $t }.GetNewClosure()
            List  = { param($pre) @($docs.Keys | Where-Object { $_.StartsWith($pre) } | Sort-Object) }.GetNewClosure()
        }
    }
    $script:T0 = [datetime]'2026-10-08T20:00:00Z'
}

Describe 'which part an object is in' {
    It 'is stable, case-insensitive, and the only part when there is one' {
        $a = Get-SICollectPartIndex -Key 'User-ABC' -Parts 52
        Get-SICollectPartIndex -Key 'user-abc' -Parts 52 | Should -Be $a
        $a | Should -BeGreaterOrEqual 0; $a | Should -BeLessThan 52
        Get-SICollectPartIndex -Key 'anything' -Parts 1 | Should -Be 0
    }
    It 'spreads objects evenly over the parts' {
        $counts = @{}
        foreach ($i in 1..5000) { $p = Get-SICollectPartIndex -Key ([guid]::NewGuid().ToString()) -Parts 10; $counts[$p] = 1 + [int]$counts[$p] }
        $counts.Keys.Count | Should -Be 10
        foreach ($k in $counts.Keys) { $counts[$k] | Should -BeGreaterThan 350; $counts[$k] | Should -BeLessThan 650 }
    }
}

Describe 'how many parts' {
    It '~10,000 objects a part, at least 1, and NO ceiling (#639): 50 million objects are 5,000 parts, not 500' {
        Get-SICollectPartCount -Objects 0 | Should -Be 1
        Get-SICollectPartCount -Objects 129 | Should -Be 1
        Get-SICollectPartCount -Objects 27835 | Should -Be 3
        Get-SICollectPartCount -Objects 512000 | Should -Be 52
        Get-SICollectPartCount -Objects 50000000 | Should -Be 5000
        Get-SICollectPartCount -Objects 50000000 -MaxParts 500 | Should -Be 5000 -Because 'an older caller''s ceiling is ignored'
    }
    It 'the part count follows the MEASURED object size: twice the reference size, twice the parts; half, half' {
        Get-SICollectPartCount -Objects 512000 -BytesPerObject 8192 | Should -Be 52 -Because 'the reference size: as unmeasured'
        Get-SICollectPartCount -Objects 512000 -BytesPerObject 16384 | Should -Be 103
        Get-SICollectPartCount -Objects 512000 -BytesPerObject 4096 | Should -Be 26
        Get-SICollectPartCount -Objects 3 -BytesPerObject 1e12 | Should -Be 3 -Because 'never fewer than one object a part'
    }
    It 'the shared file carries no part ceiling any more' {
        $f = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1'))
        $f | Should -Not -Match 'MaxParts\s*=\s*[1-9]'
        $f | Should -Not -Match '\[Math\]::Min\(\$MaxParts'
    }
}

Describe 'the manifest and the part markers in the state store' {
    It 'are written and read back at fixed paths; a marker outside the manifest is ignored by the progress' {
        $s = New-MemStore
        Write-SICollectManifest -Store $s -Manifest (New-SICollectManifest -Engine Identity -RunId 'r1' -CollectionTime $script:T0 -Parts 3 -Objects 27835 -Now $script:T0)
        $s.Docs.ContainsKey('collect/identity/r1/manifest.json') | Should -BeTrue
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'r1' -Marker (New-SICollectPartMarker -Part 0 -State done -Rows 9200 -Now $script:T0)
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'r1' -Marker (New-SICollectPartMarker -Part 7 -State done -Now $script:T0)
        $s.Docs.ContainsKey('collect/identity/r1/parts/part-00000.json') | Should -BeTrue
        $m = Read-SICollectManifest -Store $s -Engine identity -RunId 'r1'
        ([int]$m.Parts, [long]$m.Objects) | Should -Be @(3, 27835)
        $mk = @(Read-SICollectPartMarkers -Store $s -Engine identity -RunId 'r1')
        $mk.Count | Should -Be 2
        $p = Get-SICollectProgress -Manifest $m -Markers $mk -Now $script:T0.AddMinutes(5)
        ($p.State, $p.Done, $p.Missing.Count) | Should -Be @('running', 1, 2)
        Read-SICollectManifest -Store $s -Engine identity -RunId 'nope' | Should -BeNullOrEmpty
    }
}

Describe 'the Collect step''s state for the pipeline' {
    BeforeAll { $script:M = [pscustomobject](New-SICollectManifest -Engine identity -RunId 'r' -CollectionTime $script:T0 -Parts 3 -Now $script:T0) }
    It 'waiting while there is no manifest' {
        (Get-SICollectProgress -Manifest $null).State | Should -Be 'waiting'
    }
    It 'succeeded when every part is done' {
        $mk = @(0, 1, 2 | ForEach-Object { [pscustomobject](New-SICollectPartMarker -Part $_ -State done) })
        $p = Get-SICollectProgress -Manifest $script:M -Markers $mk -Now $script:T0.AddMinutes(30)
        ($p.State, $p.Done) | Should -Be @('succeeded', 3)
    }
    It 'failed, the part named with its reason, as soon as every part is marked' {
        $mk = @([pscustomobject](New-SICollectPartMarker -Part 0 -State done), [pscustomobject](New-SICollectPartMarker -Part 1 -State failed -Reason 'Graph 403 on /users'), [pscustomobject](New-SICollectPartMarker -Part 2 -State done))
        $p = Get-SICollectProgress -Manifest $script:M -Markers $mk -Now $script:T0.AddMinutes(10)
        $p.State | Should -Be 'failed'
        $p.Text | Should -Match 'part 2: Graph 403 on /users'
    }
    It 'running while parts are open within the timeout; INCOMPLETE after it, the missing parts named' {
        $mk = @([pscustomobject](New-SICollectPartMarker -Part 0 -State done))
        (Get-SICollectProgress -Manifest $script:M -Markers $mk -Now $script:T0.AddMinutes(60) -TimeoutMinutes 180).State | Should -Be 'running'
        $p = Get-SICollectProgress -Manifest $script:M -Markers $mk -Now $script:T0.AddMinutes(181) -TimeoutMinutes 180
        $p.State | Should -Be 'incomplete'
        $p.Text | Should -Match 'part\(s\) 2, 3 not finished after 180 minutes -- the collection is INCOMPLETE'
    }
    It 'NO GIVE-UP ON ELAPSED TIME (owner 2026-10-13): with -TimeoutMinutes 0 -- what the pipeline passes -- open parts are waited for however long it takes; a failed part still ends the wait' {
        $mk = @([pscustomobject](New-SICollectPartMarker -Part 0 -State done))
        foreach ($min in 181, 1620, 20000) {
            $p = Get-SICollectProgress -Manifest $script:M -Markers $mk -Now $script:T0.AddMinutes($min) -TimeoutMinutes 0
            $p.State | Should -Be 'running' -Because "after $min minutes the parts are still waited for"
            @($p.Missing).Count | Should -Be 2
        }
        # a part that failed its worker 5 times is parked with a FAILED marker: once every part is marked, the step ends
        $all = @([pscustomobject](New-SICollectPartMarker -Part 0 -State done), [pscustomobject](New-SICollectPartMarker -Part 1 -State failed -Reason 'handed out 6 times without completing -- parked for re-queue'), [pscustomobject](New-SICollectPartMarker -Part 2 -State done))
        $f = Get-SICollectProgress -Manifest $script:M -Markers $all -Now $script:T0.AddMinutes(20000) -TimeoutMinutes 0
        $f.State | Should -Be 'failed'; $f.Text | Should -Match 'part 2: handed out 6 times without completing'
        # WIRING: the pipeline's wait for the parts passes 0
        $flow = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1'))
        $flow | Should -Match ([regex]::Escape('-Now (& $this.NowFn) -TimeoutMinutes 0 -Records $rm'))
        $flow | Should -Not -Match ([regex]::Escape('-TimeoutMinutes ([int]$this.PartsWait($k))'))
    }
}

Describe 'the pipeline follows a KEDA engine''s parts (Add-SIJobFlowCollectParts)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
        function script:New-FakeInner {
            $log = New-Object System.Collections.Generic.List[string]
            $status = @{}
            New-SIJobFlowSeams -Fields @{ Log = $log; Status = $status } -Methods @{
                Start = { param($Job) $this.Log.Add("start $Job"); "$Job-exec1" }
                Poll  = { param($Job, $Execution) $this.Log.Add("poll $Job"); if ($this.Status.ContainsKey($Job)) { $this.Status[$Job] } else { 'Running' } }
                Stop  = { param($Job, $Execution) $this.Log.Add("stop $Job") }
                List  = { @('caj-si-identity-producer', 'caj-si-identity-worker', 'caj-si-azure') }
            }
        }
    }
    It 'an engine with a producer: the step starts the producer; any other job is unchanged' {
        $in = New-FakeInner; $s = New-MemStore
        $w = Add-SIJobFlowCollectParts -Seams $in -Store $s -ProducerJobs @('caj-si-identity-producer')
        $w.Start('identity') | Should -Be 'identity-producer-exec1'
        $w.Start('azure') | Should -Be 'azure-exec1'
        @($in.Log) | Should -Be @('start identity-producer', 'start azure')
    }
    It 'runs while the producer runs; then follows the manifest: running, succeeded' {
        $in = New-FakeInner; $s = New-MemStore
        $w = Add-SIJobFlowCollectParts -Seams $in -Store $s -ProducerJobs @('caj-si-identity-producer') -Now { $script:T0.AddMinutes(10) }
        $w.Poll('identity', 'run1') | Should -Be 'Running'
        $in.Status['identity-producer'] = 'Succeeded'
        Write-SICollectManifest -Store $s -Manifest (New-SICollectManifest -Engine identity -RunId 'run1' -CollectionTime $script:T0 -Parts 2 -Now $script:T0)
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'run1' -Marker (New-SICollectPartMarker -Part 0 -State done)
        $w.Poll('identity', 'run1') | Should -Be 'Running'
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'run1' -Marker (New-SICollectPartMarker -Part 1 -State done)
        $w.Poll('identity', 'run1') | Should -Be 'Succeeded'
    }
    It 'a failed part, a producer that wrote no manifest, and a failed producer all end the step failed -- with the reason' {
        $in = New-FakeInner; $s = New-MemStore
        $in.Status['identity-producer'] = 'Succeeded'
        $w = Add-SIJobFlowCollectParts -Seams $in -Store $s -ProducerJobs @('caj-si-identity-producer') -Now { $script:T0.AddMinutes(10) }
        $r = $w.Poll('identity', 'nomanifest')
        ($r.Status, $r.Error) | Should -Be @('Failed', 'the producer ended without writing the list of parts -- the collection did not start')
        Write-SICollectManifest -Store $s -Manifest (New-SICollectManifest -Engine identity -RunId 'run2' -CollectionTime $script:T0 -Parts 2 -Now $script:T0)
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'run2' -Marker (New-SICollectPartMarker -Part 0 -State done)
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'run2' -Marker (New-SICollectPartMarker -Part 1 -State failed -Reason 'out of memory')
        $f = $w.Poll('identity', 'run2')
        $f.Status | Should -Be 'Failed'; $f.Error | Should -Match 'part 2: out of memory'
        $in.Status['identity-producer'] = 'Failed'
        $w.Poll('identity', 'run2') | Should -Be 'Failed'
    }
    It 'the runner takes a failed collection''s reason into the step (parts-failed), and the runner and container are wired' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1'))
        $src | Should -Match ([regex]::Escape("if (`$statusError) { `$st.ErrorClass = 'parts-failed'; `$st.Error = `$statusError }"))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')) | Should -Match 'Add-SIJobFlowCollectParts -Seams \$seams'
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match 'New-SICollectPartMarker -Part \$shardIndex -State done'
        $c | Should -Match 'New-SICollectPartMarker -Part \(\[int\]\$msg\.Payload\.ShardIndex\) -State failed'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Invoke-ShardProducer.ps1')) | Should -Match 'Write-SICollectManifest -Store \$collectStore'
    }
}

Describe 'the producer discovers into parts, a worker reads its part (Write-SIDiscoverParts, -Phase)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\StagingBlob.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')
    }
    It 'every discovered object lands in exactly one part, and a part''s reader gets only its own objects' {
        $global:SI_SingleProcess = $false
        $ctx = New-SIStorageContext -Mock
        $null = Initialize-SIStagingContainer -Context $ctx -ContainerName 'sistaging'
        $rc = [pscustomobject]@{ StorageContext = $ctx; StagingContainer = 'sistaging'; RunId = 'run-x'; Phase = 'discover' }
        $assets = foreach ($i in 1..25000) { @{ NormalizedKey = "user-$i"; AssetId = "entra-user:$i" } }
        $parts = Write-SIDiscoverParts -RunContext $rc -Assets @($assets) -ShardSize 2000
        $parts | Should -Be 3
        $seen = 0
        foreach ($p in 0..($parts - 1)) {
            $mine = @(Read-SIStageShards -Context $ctx -ContainerName 'sistaging' -RunId 'run-x' -Stage 'Discover' -ReplicaIndex $p)
            $seen += $mine.Count
            foreach ($a in ($mine | Select-Object -First 20)) { Get-SICollectPartIndex -Key ([string]$a.NormalizedKey) -Parts $parts | Should -Be $p }
        }
        $seen | Should -Be 25000
    }
    It 'the engine runs Schedule + Discover as the producer, and the rest on its part as a worker, under the producer''s run id' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $src | Should -Match ([regex]::Escape("if (`$Phase -eq 'discover') { `$__st = @('Schedule', 'Discover') }"))
        $src | Should -Match ([regex]::Escape("elseif (`$Phase -eq 'parts') { `$__st = @(`$__st | Where-Object { `$_ -notin 'Schedule', 'Discover' }) }"))
        $src | Should -Match ([regex]::Escape("`$runId = if (`$Phase -eq 'parts' -and `"`$RunId`".Trim())"))
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')) | Should -Match 'Write-SIDiscoverParts -RunContext \$RunContext'
    }
    It 'the container: a producer with SI_PRODUCER_DISCOVERS discovers, then writes the manifest and one message per part; a parts message runs the worker from Collect' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match "GetEnvironmentVariable\('SI_PRODUCER_DISCOVERS'\) -eq '1'"
        $c | Should -Match ([regex]::Escape("if (`$producerDiscovers -or `$collectChild -eq 'discover') { `$orchArgs['Phase'] = 'discover'"))
        $c | Should -Match ([regex]::Escape("`$orchArgs['Phase'] = 'parts'; `$orchArgs['RunId'] = `$collectEngineRun"))
        $c | Should -Match "RunId = \`$collectKey; EngineRunId = \`$ri\.RunId; Phase = 'parts'"
        # the manifest is keyed by the producer's EXECUTION -- what the pipeline polls by
        $c | Should -Match ([regex]::Escape('$collectKey = if ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME)'))
    }
}

Describe 'a scheduled job collects in parts, one after another, each part in its own process' {
    BeforeAll { $script:Entry = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) }
    It 'is OPT-IN (SI_COLLECT_IN_PARTS = on) for identity, endpoint and Azure on a scheduled job only -- never a KEDA worker, a producer, a child or a sharded job' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape("`$collectInParts = (-not `$useQueue -and -not `$producerDiscovers -and -not `$collectChild -and `$shardCount -le 1 -and"))
        $e | Should -Match ([regex]::Escape("`$engine -in @('identity', 'endpoint', 'azure')"))
        # off by default until the discovery process hands its records to the parts (ring 1 2026-10-08: the records
        # captured in Discover were dropped -- Entra, Exposure Graph and Azure records went to 0)
        $e | Should -Match ([regex]::Escape("(Get-OptionalEnv 'SI_COLLECT_IN_PARTS' 'off')"))
        $e | Should -Match ([regex]::Escape("-in @('on', 'true', '1', 'yes')"))
    }
    It 'discovers once in a child, then runs every part in a child of its own, all with one collection time' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape("& `$runChild @{ SI_COLLECT_PHASE = 'discover'; SI_COLLECT_INFO_FILE = `$infoFile; SI_COLLECTION_TIME = `$partsCt.ToString('o') }"))
        $e | Should -Match ([regex]::Escape("for (`$p = 0; `$p -lt `$parts; `$p++)"))
        $e | Should -Match ([regex]::Escape("SI_COLLECT_PHASE = 'parts'; SI_COLLECT_PART = `$p; SI_COLLECT_PARTS = `$parts; SI_COLLECT_RECORD_BUCKETS = `$recordBuckets; SI_COLLECT_ENGINE_RUN = [string]`$info.RunId; SI_COLLECTION_TIME = `$partsCt.ToString('o')"))
        # the child's output goes to the log, never into the exit code; the env of one child never leaks into the next
        $e | Should -Match ([regex]::Escape('& pwsh -NoProfile -File $selfScript | Out-Host; $LASTEXITCODE'))
        $e | Should -Match ([regex]::Escape('finally { foreach ($k in $Vars.Keys) { [Environment]::SetEnvironmentVariable($k, $null) } }'))
    }
    It 'runs a child as the phase it was given: discover hands its run over, a part reads its part of that run' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape("if (`$producerDiscovers -or `$collectChild -eq 'discover') { `$orchArgs['Phase'] = 'discover'"))
        $e | Should -Match ([regex]::Escape("`$collectEngineRun = [string](Get-OptionalEnv 'SI_COLLECT_ENGINE_RUN' '')"))
        $e | Should -Match ([regex]::Escape("`$shardIndex       = [int](Get-OptionalEnv 'SI_COLLECT_PART' 0)"))
        $e | Should -Match ([regex]::Escape("elseif (`$collectPhase -eq 'parts' -and `$collectEngineRun) { `$orchArgs['Phase'] = 'parts'"))
        # handed over only after a clean discovery
        $i = $e.IndexOf("if (`$collectChild -eq 'discover' -and (`$orchExit -eq 0 -or `$null -eq `$orchExit))")
        $i | Should -BeGreaterThan 0
        $e.IndexOf('SI_COLLECT_INFO_FILE', $i) | Should -BeGreaterThan $i
    }
    It 'skips the execution guard in a child (its parent already passed it)' {
        $script:Entry | Should -Match ([regex]::Escape("-ne '1' -and -not (Get-OptionalEnv 'SI_COLLECT_PHASE' `$null)) {"))
    }
    It 'says a failed part, runs the others, and ends the run failed -- those objects are unknown, not gone' {
        $e = $script:Entry
        $e | Should -Match 'the other parts go on'
        $e | Should -Match 'INCOMPLETE for those objects; they are unknown, not gone'
        $e | Should -Match ([regex]::Escape("no part was collected this run"))
    }
}
