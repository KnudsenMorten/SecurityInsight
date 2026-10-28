#Requires -Version 5.1
<#
    THE IDENTITY COLLECTION OF A LARGE TENANT IS SCALED OUT, NOT SERIAL (ring 2, 2026-10-21: 153,000 users and 1.9 million
    Exposure Graph identities took 8-19 hours). Measured from the run's own log lines: 10.4 hours were ONE process publishing
    the run's 506 record buckets one at a time (74 s each, the database at ~31 %, 3 of the worker's 4 CPUs idle), 5 hours
    were the users' sign-in methods read one $batch request at a time (~2.5 s each). What these keep true:
      1. RECORDS     the last worker of a queue-driven run publishes the buckets in several processes at once (one per CPU,
                     as the free memory allows; never more than the buckets), each the buckets b mod N = k; no process
                     closes the collection -- each hands its close back and the starter closes it ONCE, so the asset-drop
                     guard judges the whole collection; a process that hands nothing back leaves it NOT complete
      2. SIGN-IN     the sign-in methods read sends several $batch requests at once: one more after a wave Microsoft
         METHODS     answered without a 429, half after a throttled one (never below one); a throttled wave's Retry-After
                     is waited ONCE for the wave, never once per request; the pace is said in one line
      3. STEP ROWS   a step row of a run that has ENDED is never left Starting / Running / Waiting: every wake-up of the
                     runner closes them with the reason (never the run that is going on, never the lock)
    Offline: the processes, Graph and the database are fakes behind seams; no tenant is touched. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    # script-scope stubs (never global): the lines the code under test says
    $script:Info = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
    function script:Write-SIWarn { param($Message) }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-AuthMethodsRead.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-21T02:00:00', [DateTimeKind]::Utc)
    function script:JItems([string]$j) { $a = ConvertFrom-Json -InputObject $j; @($a | ForEach-Object { $_ }) }
    # a database seam that records every statement and answers the write's and the close's one row
    function script:Seam {
        $script:Calls = New-Object System.Collections.Generic.List[object]
        {
            param($Sql, $Params, $Mode)
            $script:Calls.Add(@{ Sql = $Sql; Params = $Params; Mode = $Mode })
            if ($Params.ContainsKey('r')) { return [pscustomobject]@{ Seen = @(JItems $Params.r).Count; Changed = 0; Identifiers = 0 } }
            if ($Params.ContainsKey('k')) { return [pscustomobject]@{ Closed = @(JItems $Params.k).Count; Feeds = @(JItems $Params.f).Count } }
            [pscustomobject]@{ Properties = 0; Added = 0; NewContext = 0 }
        }
    }
    function script:Get-Closes { @($script:Calls | Where-Object { $_.Params.ContainsKey('k') }) }
    function script:Get-DropChecks { @($script:Calls | Where-Object { $_.Params.ContainsKey('h') }) }
    function script:MemStore {
        $m = @{}
        [pscustomobject]@{ Data = $m
            Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
            Read  = { param($Path) $m[$Path] }.GetNewClosure()
            List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure() }
    }
    # a run's records handed over into 4 buckets (60 users)
    function script:New-HandedRun([string]$RunId) {
        $s = MemStore
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..60) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i" } }
        Set-SIRecordPull -Provider entra -Complete $true
        $null = Save-SIRecordHandover -Store $s -Engine identity -RunId $RunId -Who 'discover' -Buckets 4
        $s
    }
    $script:Entry = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
}

Describe 'records: one run published by several processes at once, closed once' {
    It 'how many processes: one per CPU, as many as the free memory holds, never more than the buckets, at least one' {
        Get-SIRecordsProcessCount -Buckets 506 -Processors 4 -FreeBytes (5GB) | Should -Be 4
        Get-SIRecordsProcessCount -Buckets 506 -Processors 4 -FreeBytes (2.5GB) | Should -Be 2 -Because 'the memory decides when it holds fewer'
        Get-SIRecordsProcessCount -Buckets 506 -Processors 4 -FreeBytes (100MB) | Should -Be 1
        Get-SIRecordsProcessCount -Buckets 506 -Processors 16 -FreeBytes -1 | Should -Be 16 -Because 'no fixed upper number: the host decides'
        Get-SIRecordsProcessCount -Buckets 3 -Processors 4 -FreeBytes (8GB) | Should -Be 3
        Get-SIRecordsProcessCount -Buckets 0 -Processors 4 | Should -Be 1
        Get-SIRecordsProcessCount -Buckets 506 -Processors 4 -FreeBytes (8GB) -Override 2 | Should -Be 2
        Get-SIRecordsProcessCount -Buckets 3 -Processors 4 -Override 9 | Should -Be 3
    }
    It 'a deferred publish writes its buckets and does NOT close the collection -- it hands its close back' {
        $s = New-HandedRun 'd1'
        $seam = Seam
        $res = @(Publish-SIRecordHandover -Store $s -Engine identity -RunId 'd1' -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'd1' }) -SqlInvoke $seam -Slice 0 -Slices 2 -DeferClose 3>$null 6>$null)[-1]
        $res.Failed | Should -Be 0
        @(Get-Closes).Count | Should -Be 0
        $res.Closed | Should -BeNullOrEmpty
        @($res.Close.Pins).Count | Should -BeGreaterThan 0
        @($res.Close.Feeds) | Should -Contain 'entra|user'
    }
    It 'CONTROL: a slice that closes itself is not judged by the asset-drop guard (it sees only its part)' {
        $s = New-HandedRun 'd2'
        $seam = Seam
        $null = Publish-SIRecordHandover -Store $s -Engine identity -RunId 'd2' -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'd2' }) -SqlInvoke $seam -Slice 0 -Slices 2 3>$null 6>$null
        @(Get-Closes).Count | Should -Be 1
        @(Get-DropChecks).Count | Should -Be 0
    }
    It 'the deferred closes of every slice, merged through JSON, close the collection ONCE with every pin -- and the guard judges it whole' {
        $s = New-HandedRun 'd3'
        $seam = Seam
        $ctx = [pscustomobject]@{ CollectionTime = $script:Now; RunId = 'd3' }
        $a = @(Publish-SIRecordHandover -Store $s -Engine identity -RunId 'd3' -RunContext $ctx -SqlInvoke $seam -Slice 0 -Slices 2 -DeferClose 3>$null 6>$null)[-1]
        $b = @(Publish-SIRecordHandover -Store $s -Engine identity -RunId 'd3' -RunContext $ctx -SqlInvoke $seam -Slice 1 -Slices 2 -DeferClose 3>$null 6>$null)[-1]
        # together every bucket the hand-over wrote, none twice
        $saved = @($s.Data.Keys | Where-Object { $_ -match '/bucket-(\d{5})' } | ForEach-Object { [regex]::Match($_, '/bucket-(\d{5})').Groups[1].Value } | Sort-Object -Unique).Count
        ([int]$a.Buckets + [int]$b.Buckets) | Should -Be $saved -Because ('the two slices'' buckets together are every bucket saved (a {0}, b {1})' -f $a.Buckets, $b.Buckets)
        $closes = @($a.Close, $b.Close) | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 6 -Compress | ConvertFrom-Json }
        $m = Merge-SIRecordFeedCloses -Engine identity -Closes $closes
        $m.Pins.Count | Should -Be (@($a.Close.Pins).Count + @($b.Close.Pins).Count) -Because 'the merged close holds every slice''s pins'
        $m.Failed | Should -Be 0
        $m.PSObject.Properties['Judge'] | Should -BeNullOrEmpty -Because 'the merged close is the whole collection'
        $cr = Complete-SIRecordFeeds -Close $m -Invoke $seam -CollectionTime $script:Now 3>$null 6>$null
        $cr.Held | Should -BeFalse
        @(Get-Closes).Count | Should -Be 1 -Because 'the collection is closed once'
        $k = [string]@(Get-Closes)[0].Params.k
        foreach ($pin in $m.Pins) { $k | Should -Match ([regex]::Escape(('"{0}"' -f $pin))) -Because 'the one close carries every pin' }
        @(Get-DropChecks).Count | Should -Be 1 -Because 'the asset-drop guard judges the whole collection once'
    }
    It 'a process that handed nothing back counts as a failure: the merged close is never complete without it' {
        $m = Merge-SIRecordFeedCloses -Engine identity -Closes @([pscustomobject]@{ Pins = @('a'); Feeds = @('entra|user'); Incomplete = @(); Failed = 0; PinFeed = [pscustomobject]@{ a = 'entra|user' } }) -Missing 1
        $m.Failed | Should -Be 1
        $m.PinFeed['a'] | Should -Be 'entra|user'
        $seam = Seam
        (Complete-SIRecordFeeds -Close $m -Invoke $seam -CollectionTime $script:Now 3>$null 6>$null).Held | Should -BeTrue
        @(Get-Closes).Count | Should -Be 0
    }

    Context 'Invoke-SIRecordsInProcesses (the processes and the close are fakes)' {
        BeforeEach {
            $script:Started = New-Object System.Collections.Generic.List[object]
            $script:Completed = New-Object System.Collections.Generic.List[object]
            $script:Dead = @()
            # a records process: writes its result file (its buckets, its close), unless it is one of $script:Dead
            $script:FakeStart = {
                param($Script, [hashtable]$Vars)
                $script:Started.Add($Vars)
                $k = [int](([string]$Vars['SI_COLLECT_RECORDS_SLICE'] -split '/')[0])
                $code = 0
                if ($script:Dead -contains $k) { $code = 137 } else {
                    $r = [ordered]@{ Buckets = 2; Records = 100; Failed = 0; ExportFailed = 0
                                     Close = [ordered]@{ Engine = 'identity'; Pins = @("pin-$k"); Feeds = @('entra|user'); Incomplete = @(); Failed = 0; PinFeed = @{ "pin-$k" = 'entra|user' } } }
                    [IO.File]::WriteAllText([string]$Vars['SI_COLLECT_RECORDS_RESULT_FILE'], (ConvertTo-Json -InputObject $r -Depth 6 -Compress))
                }
                $p = [pscustomobject]@{ ExitCode = $code }
                $p | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { }
                $p
            }
            $script:FakeComplete = { param($Close, $Ct) $script:Completed.Add($Close); [pscustomobject]@{ Held = ([int]$Close.Failed -gt 0) } }
        }
        It 'starts N processes, each its slice, the SAME ingest lock and its OWN result file, with the run''s settings' {
            $r = Invoke-SIRecordsInProcesses -Script 'entry.ps1' -Environment @{ SI_COLLECT_PHASE = 'records'; SI_TRIGGER_FROM_QUEUE = '0' } -Processes 3 -Engine identity -CollectionTime $script:Now -Start $script:FakeStart -Complete $script:FakeComplete
            $script:Started.Count | Should -Be 3
            @($script:Started | ForEach-Object { $_['SI_COLLECT_RECORDS_SLICE'] }) | Should -Be @('0/3', '1/3', '2/3')
            @($script:Started | ForEach-Object { $_['SI_INGEST_LOCK_FILE'] } | Select-Object -Unique).Count | Should -Be 1
            @($script:Started | ForEach-Object { $_['SI_COLLECT_RECORDS_RESULT_FILE'] } | Select-Object -Unique).Count | Should -Be 3
            @($script:Started | ForEach-Object { $_['SI_TRIGGER_FROM_QUEUE'] } | Select-Object -Unique) | Should -Be @('0')
            ($r.Processes, $r.Buckets, $r.Records, $r.Failed, $r.Closed, $r.ExitCode) | Should -Be @(3, 6, 300, 0, $true, 0)
            $script:Completed.Count | Should -Be 1 -Because 'the collection is closed ONCE'
            @($script:Completed[0].Pins) | Should -Be @('pin-0', 'pin-1', 'pin-2')
            foreach ($v in $script:Started) { [IO.File]::Exists([string]$v['SI_COLLECT_RECORDS_RESULT_FILE']) | Should -BeFalse -Because 'the result files are removed' }
        }
        It 'a process that dies: its buckets are a failure, the exit code is kept, and the collection is NOT closed complete' {
            $script:Dead = @(1)
            $r = Invoke-SIRecordsInProcesses -Script 'entry.ps1' -Environment @{ SI_COLLECT_PHASE = 'records' } -Processes 3 -Engine identity -CollectionTime $script:Now -Start $script:FakeStart -Complete $script:FakeComplete 3>$null
            $r.Failed | Should -Be 1
            $r.ExitCode | Should -Be 137
            $r.Closed | Should -BeFalse
            [int]$script:Completed[0].Failed | Should -BeGreaterThan 0
        }
        It 'a process that cannot be started is a failure too, never silent' {
            $boom = { param($Script, [hashtable]$Vars) throw 'pwsh not found' }
            $r = Invoke-SIRecordsInProcesses -Script 'entry.ps1' -Environment @{} -Processes 2 -Start $boom -Complete $script:FakeComplete 3>$null
            $r.Failed | Should -Be 2
            $r.ExitCode | Should -Not -Be 0
        }
    }

    It 'WIRING: the last worker of a queue-driven run publishes in several processes when the host allows, never through the queue' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape('$siEntryScript = $PSCommandPath'))
        $e | Should -Match '(?s)\$finishKedaRecords = \{.{0,3000}Read-SICollectManifest -Store \$recStore -Engine \$recEngineName -RunId \$RecCollectKey.{0,600}Get-SIRecordsProcessCount -Buckets \$recBuckets -Processors \(\[Environment\]::ProcessorCount\) -FreeBytes \(Get-SIRecordsProcessFreeBytes\)'
        $e | Should -Match ([regex]::Escape("`$recEnv = @{ SI_TRIGGER_FROM_QUEUE = '0'; SI_COLLECT_PHASE = 'records'"))
        $e | Should -Match ([regex]::Escape('$recPar = Invoke-SIRecordsInProcesses -Script $siEntryScript -Environment $recEnv -Processes $recProcs -Engine $recEngineName -CollectionTime $recCt'))
        $e | Should -Match ([regex]::Escape('[pscustomobject]@{ Records = $recPar.Records; Buckets = [Math]::Max([int]$recPar.Buckets, $recBuckets); Failed = [int]$recPar.Failed }'))
        # one process: as before, and it still publishes the full asset metadata itself (the first records process does otherwise)
        $e | Should -Match '(?s)if \(\$recProcs -le 1\) \{\s+Publish-SIRecordHandover -Store \$recStore .{0,600}\$null = & \$publishAssetPropsHandover \$RecEngineRun \$recCt'
    }
    It 'WIRING: a records process started by another hands its result and its close back instead of closing' {
        $e = $script:Entry
        $e | Should -Match ([regex]::Escape("`$recResultFile = [string](Get-OptionalEnv 'SI_COLLECT_RECORDS_RESULT_FILE' '')"))
        $e | Should -Match ([regex]::Escape('-DeferClose:([bool]$recResultFile)'))
        $e | Should -Match '(?s)if \(\$recResultFile\) \{\s+\[IO\.File\]::WriteAllText\(\$recResultFile.{0,300}Close = \$res\.Close'
        # the guard of a scheduled job (not the queue) is skipped for it, as for every child of a run
        $e | Should -Match ([regex]::Escape("-not (Get-OptionalEnv 'SI_COLLECT_PHASE' `$null)"))
    }
}

Describe 'sign-in methods: several $batch requests at once, adapted to what Microsoft takes' {
    BeforeEach {
        Reset-SIEntraAuthMethodsState
        $global:SIRecordCaptureState = $null
        $script:Widths = New-Object System.Collections.Generic.List[int]
        $script:Sleeps = New-Object System.Collections.Generic.List[int]
        $script:Waves = 0
        $script:ThrottleWave = @()   # wave numbers (1-based) whose requests answer 429
        $script:ThrottleAll = $false # every request of a throttled wave (else only the first)
        $script:Sleep = { param($Seconds) $script:Sleeps.Add([int]$Seconds) }
        $script:PostMany = {
            param([string[]]$Bodies)
            $script:Waves++
            $script:Widths.Add(@($Bodies).Count)
            $i = 0
            , @(foreach ($b in $Bodies) {
                $i++
                if ($script:ThrottleWave -contains $script:Waves -and ($script:ThrottleAll -or $i -eq 1)) {
                    [pscustomobject]@{ Response = $null; Status = 429; RetryAfter = 9; Error = 'Too Many Requests' }; continue
                }
                $reqs = @(($b | ConvertFrom-Json).requests)
                [pscustomobject]@{ Status = 200; RetryAfter = $null; Error = ''
                    Response = [pscustomobject]@{ responses = @(foreach ($r in $reqs) { [pscustomobject]@{ id = [string]$r.id; status = 200; headers = $null
                        body = [pscustomobject]@{ value = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' }) } } }) } }
            })
        }
        function script:Users([int]$N) { @(1..$N | ForEach-Object { [pscustomobject]@{ id = ('u{0:D4}' -f $_); userPrincipalName = "u$_@contoso.test"; userType = 'Member' } }) }
    }
    AfterAll { $global:SIRecordCaptureState = $null }

    It 'a clean wave lets the next one send one more request: 200 users = 10 requests in waves of 1, 2, 3, 4' {
        $map = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 200) -PostMany $script:PostMany -Sleep $script:Sleep
        $map.Count | Should -Be 200
        @($script:Widths) | Should -Be @(1, 2, 3, 4)
        $script:Sleeps.Count | Should -Be 0
        $st = Get-SIEntraAuthMethodsState
        ($st.Requests, $st.MaxConcurrency, $st.ThrottledWaves, $st.Complete) | Should -Be @(10, 4, 0, $true)
    }
    It 'the pace carries over from page to page (a streamed discovery calls once per page)' {
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 60) -PostMany $script:PostMany -Sleep $script:Sleep
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 80) -PostMany $script:PostMany -Sleep $script:Sleep
        # page 1: 3 requests (1, 2); page 2 starts at 3 at once (then the 1 left)
        @($script:Widths) | Should -Be @(1, 2, 3, 1)
    }
    It 'a throttled wave halves the next and its Retry-After is waited ONCE for the wave, never once per request' {
        $script:ThrottleWave = @(4); $script:ThrottleAll = $true
        $map = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 400) -PostMany $script:PostMany -Sleep $script:Sleep
        # waves 1,2,3 clean (6 requests); wave 4 sends 4 and all are throttled -> one wait of 9 s, the next wave sends 2
        @($script:Widths)[0..4] | Should -Be @(1, 2, 3, 4, 2)
        @($script:Sleeps | Where-Object { $_ -eq 9 }).Count | Should -Be 1 -Because 'four throttled requests in one wave are one wait'
        $map.Count | Should -Be 400 -Because 'the throttled users are asked again in the next round'
        $st = Get-SIEntraAuthMethodsState
        $st.Throttled | Should -BeTrue
        $st.ThrottledWaves | Should -Be 1
        $st.Complete | Should -BeTrue
    }
    It 'never below one request at a time' {
        $st = [pscustomobject]@{ Concurrency = 1; ThrottledWaves = 0 }
        Update-SIAuthMethodConcurrency -State $st -Throttled $true | Should -Be 1
        Update-SIAuthMethodConcurrency -State $st -Throttled $false | Should -Be 2
        Update-SIAuthMethodConcurrency -State $st -Throttled $false | Should -Be 3
        Update-SIAuthMethodConcurrency -State $st -Throttled $true | Should -Be 1
        $st.ThrottledWaves | Should -Be 2
    }
    It 'the pace is said in one plain line before the outcome line' {
        $script:ThrottleWave = @(2)
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 100) -PostMany $script:PostMany -Sleep $script:Sleep
        $script:Info.Clear()
        Write-SIEntraAuthMethodsOutcome
        $script:Info.Count | Should -Be 2
        $script:Info[0] | Should -Match 'request\(s\) of 20 users, up to \d+ at once; Microsoft asked to slow down 1 time\(s\)'
        $script:Info[1] | Should -Match 'sign-in methods read for 100 users'
        $script:Info[0] | Should -Not -Match '#\d'
    }
    It 'THE DEFAULT PATH (no seam) reads every user when a wave sends 2+ requests (live 2026-10-22: only the first 20 were read)' {
        # the real default $PostMany, with only the HTTP sender replaced by one that answers like it: ONE array of outcomes
        # (defined in THIS block's scope, the nearest one the default sender's call resolves from -- a script: function is
        # farther than the file's own definition and is never reached)
        $sendBody = $script:PostMany
        function Invoke-SIAuthMethodBatchRequests { param([string]$Token, [string[]]$Bodies = @(), [int]$TimeoutSeconds = 100) & $sendBody $Bodies }
        $map = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 200) -Sleep $script:Sleep
        $map.Count | Should -Be 200 -Because 'every user of every wave is read, not only the first request of 20'
        @($script:Widths) | Should -Be @(1, 2, 3, 4)
        $st = Get-SIEntraAuthMethodsState
        ($st.Read, $st.Complete) | Should -Be @(200, $true)
    }
    It 'WIRING: a sign-in-method read that stops part-way is never reported complete (the discovery marks it and warns)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
        $src | Should -Match ([regex]::Escape('try { $got = Get-SIEntraPasswordlessByUser -Token $token -Users $sel }'))
        $src | Should -Match ([regex]::Escape('if ($st) { $st.Complete = $false; $st.Error = [string]$_.Exception.Message }'))
        $src | Should -Match 'Write-SIWarn \(''\[perms\] the sign-in-method read stopped part-way'
    }
    It 'WIRING: without a seam the requests of a wave are all sent before any answer is awaited (REST / .NET only)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-AuthMethodsRead.ps1'))
        $src | Should -Match ([regex]::Escape('$PostMany = { param([string[]]$Bodies) Invoke-SIAuthMethodBatchRequests -Token $Token -Bodies $Bodies }'))
        $i = $src.IndexOf('$tasks.Add($client.SendAsync($req))'); $j = $src.IndexOf('$resp = $t.GetAwaiter().GetResult()')
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
        $src | Should -Not -Match 'Invoke-MgGraph|Import-Module'
    }
    It 'the batch sender never throws and answers one outcome per body (a body it could not send is "no answer")' {
        $o = Invoke-SIAuthMethodBatchRequests -Token 't' -Bodies @()
        @($o).Count | Should -Be 0
    }
}

Describe 'step rows of runs that have ended are closed by the runner' {
    It 'the statement closes ONLY open rows of ENDED runs: Starting / Running -> Interrupted at the run''s end, Waiting -> Skipped, with the reason' {
        $t = Get-SIJobFlowSqlText 'CloseEndedRunSteps'
        $t | Should -Match ([regex]::Escape("WHERE r.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') AND s.State IN (N'Starting', N'Running', N'Waiting')"))
        $t | Should -Match ([regex]::Escape("State = CASE WHEN s.State = N'Waiting' THEN N'Skipped' ELSE N'Interrupted' END"))
        $t | Should -Match ([regex]::Escape('COALESCE(s.EndedUtc, r.EndedUtc, SYSUTCDATETIME())'))
        $t | Should -Match 'closed: the run ended'
        $t | Should -Match 'not run: the run ended'
        $t | Should -Match "WHEN r\.State = N'Cancelled' THEN N'cancelled'"
        $t | Should -Not -Match 'UPDATE cfg\.FlowRun|PipelineLock|DELETE'
        $t | Should -Match 'SELECT @@ROWCOUNT AS Closed'
    }
    It 'the store answers how many it closed and forgets what it remembered as saved' {
        $script:Sql = New-Object System.Collections.Generic.List[string]
        $inv = { param($Sql, $Params, $Mode) $script:Sql.Add([string]$Sql); if ($Sql -match 'AS Closed') { , @(@{ Closed = 2 }) } }
        $store = New-SIJobFlowSqlStore -Invoke $inv
        $store.Seen['x|1'] = 'sig'
        $store.CloseEndedRunSteps() | Should -Be 2
        $store.Seen.Count | Should -Be 0
        $inv0 = { param($Sql, $Params, $Mode) , @(@{ Closed = 0 }) }
        (New-SIJobFlowSqlStore -Invoke $inv0).CloseEndedRunSteps() | Should -Be 0
    }
    It 'WIRING: every wake-up closes them before the pipeline runs, and a failing close never stops the wake-up' {
        $r = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $i = $r.IndexOf('$runStore.CloseEndedRunSteps()'); $j = $r.IndexOf('$drain = Invoke-SIPipelineDrain')
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
        $r | Should -Match ([regex]::Escape("if (`$runStore -and `$runStore.PSObject.Methods['CloseEndedRunSteps']) {"))
        $r | Should -Match '(?s)\$runStore\.CloseEndedRunSteps\(\).{0,400}\} catch \{ & \$say ''WARN'''
    }
}
