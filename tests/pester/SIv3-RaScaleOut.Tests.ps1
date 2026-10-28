#Requires -Version 5.1
<#
    #742 -- RISK ANALYSIS ON QUEUE WORKERS (engine/risk-analysis/_shared/RA-ScaleOut.ps1): the producer plans one work item per
    report, queues them and waits; workers run them and hand back what the report loop knew; the producer finishes the run.
    What these tests keep true (offline, the in-memory queue and state store):
      * the plan numbers the reports as the single job does (only reports with a definition; template order); each report's
        rows are numbered from its own base; the queue / job names agree between the engine and setup;
      * a worker takes an item and holds it; a closed or stale run's message is removed without running; an item already
        marked is removed; an item handed out more than MaxDequeue times is PARKED and marked FAILED with the cause; another
        run's message is put back;
      * the producer waits until every item is marked (progress), runs a worker itself when none started after the grace,
        and -- without a worker job -- runs its own worker, again after a crashed attempt's lease;
      * an item that failed / was never finished / has no hand-over = that report NOT COMPLETE with the cause, never silent;
      * the hand-over survives JSON (dates, lists, maps) and merges into the run's state in the single job's order: lists,
        counters, the column union with the trace columns last, the stream's report entries, the KQL types;
      * #674 across workers: a giver is NOT COMPLETE only when a receiver that ran AFTER it found rows;
      * a hand-over carries no Log Analytics delivery: a worker never posts (the producer posts the whole run once, from SQL);
      * the run's lock is exclusive, a stale one is taken over, only its owner releases it;
      * a worker keeps only its own reports' bucket counts in the file of an install without the Pro settings database;
      * a date-looking text in the manifest comes back as text.
    PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScaleOut.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    function script:New-MemStore {
        $docs = [hashtable]::Synchronized(@{})
        [pscustomobject]@{
            Docs   = $docs
            Read   = { param($p) if ($docs.ContainsKey($p)) { $docs[$p] } else { $null } }.GetNewClosure()
            Write  = { param($p, $t) $docs[$p] = $t }.GetNewClosure()
            List   = { param($pre) @($docs.Keys | Where-Object { $_.StartsWith($pre) } | Sort-Object) }.GetNewClosure()
            Claim  = { param($p, $t) [System.Threading.Monitor]::Enter($docs.SyncRoot); try { if ($docs.ContainsKey($p)) { $false } else { $docs[$p] = $t; $true } } finally { [System.Threading.Monitor]::Exit($docs.SyncRoot) } }.GetNewClosure()
            Remove = { param($p) $docs.Remove($p) }.GetNewClosure()
        }
    }
    $script:T0 = [datetime]'2026-10-17T06:00:00Z'
    function script:New-Plan { New-RAScaleOutPlan -Reports @(
        [pscustomobject]@{ Name = 'A_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Missing_Detailed'; HasEntry = $false },
        [pscustomobject]@{ Name = 'Azure_Recommendations_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Azure_DefenderRecommendations_Detailed'; HasEntry = $true }) }
    function script:New-Man([object[]]$Plan = @(New-Plan)) {
        New-RAScaleOutManifest -Grain Detailed -TimeText '2026-10-17T06:00:00.000' -CollectionTime $script:T0 -CollectionId 41 -RunKey 'Detailed|2026-10-17T06:00:00.000' `
            -HealthRunId 'h1' -Template 'RiskAnalysis_Detailed' -Items $Plan -Defender @{ State = 'loaded'; Keys = 12; Pages = 1 } -HostInfo @{ Name = 'prod-host'; Fqdn = 'prod-host.local'; User = 'container' } -Now $script:T0
    }
}

Describe 'the plan, the numbering and the names' {
    It 'one item per report WITH a definition, numbered as the single job numbers them' {
        $p = @(New-Plan)
        $p.Count | Should -Be 3
        ($p | ForEach-Object { '{0}:{1}:{2}' -f $_.Item, $_.Report, $_.Ordinal }) -join ' ' | Should -Be '0:A_Detailed:1 1:Azure_Recommendations_Detailed:2 2:Azure_DefenderRecommendations_Detailed:3'
    }
    It 'each report numbers its rows from its own base -- the single job''s order kept (report, then write order)' {
        (Get-RAScaleOutSeqBase -Ordinal 1) | Should -BeLessThan (Get-RAScaleOutSeqBase -Ordinal 2)
        (Get-RAScaleOutSeqBase -Ordinal 2) - (Get-RAScaleOutSeqBase -Ordinal 1) | Should -Be 1000000000000
        (Get-RAScaleOutSeqBase -Ordinal 900) | Should -BeOfType [long]
    }
    It 'the engine and setup name the same queue and the same worker job (32 characters at most, outside caj-si-ra-<name>)' {
        Get-RAScaleOutQueueName -Grain Detailed | Should -Be (Get-SIRaScaleOutQueueName -Grain Detailed)
        Get-RAScaleOutWorkerJobName -Grain Detailed | Should -Be (Get-SIRaWorkerJobName -Grain Detailed)
        (Get-SIRaWorkerJobName -Grain Detailed).Length | Should -BeLessOrEqual 32
        (Get-SIRaWorkerJobName -Grain Summary).Length | Should -BeLessOrEqual 32
        Get-SIRaWorkerJobName -Grain Detailed | Should -Not -Match '^(?i)caj-si-(risk-analysis|risk-analysis-detailed|ra-[a-z0-9-]+)$'
    }
    It 'the manifest carries the collection, the items, the Defender list''s state and the producer''s host' {
        $m = New-Man
        ($m.Engine, $m.RunId, $m.Parts, $m.CollectionId, $m.TimeText) | Should -Be @('ra-detailed', 'ct-20261017060000000', 3, 41, '2026-10-17T06:00:00.000')
        $m.Defender.State | Should -Be 'loaded'; $m.Host.Name | Should -Be 'prod-host'
        @($m.Items).Count | Should -Be 3
    }
    It 'a date-looking text comes back from the store AS TEXT (the collection time text and the run time)' {
        $s = New-MemStore; $m = New-Man; $m['RaCollectionTime'] = ([datetime]'2026-10-17T06:00:00Z').ToUniversalTime().ToString('o')
        Write-RAScaleOutManifest -Store $s -Manifest $m
        $r = Read-RAScaleOutManifest -Store $s -Engine 'ra-detailed' -RunId $m.RunId
        $r['TimeText'] | Should -BeOfType [string]; $r['TimeText'] | Should -Be '2026-10-17T06:00:00.000'
        $r['RaCollectionTime'] | Should -BeOfType [string]
        [datetime]::Parse($r['RaCollectionTime'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).Ticks | Should -Be ([datetime]'2026-10-17T06:00:00Z').ToUniversalTime().Ticks
        @($r['Items']).Count | Should -Be 3
    }
    It 'scale-out only where it can work: on, Detailed, the result in SQL, a storage account, not a dry run' {
        (Test-RAScaleOutWanted -Setting 'on' -Grain Detailed -StreamOn $true -StorageAccount 'st').On | Should -BeTrue
        (Test-RAScaleOutWanted -Setting $null -Grain Detailed -StreamOn $true -StorageAccount 'st').On | Should -BeFalse
        (Test-RAScaleOutWanted -Setting 'on' -Grain Summary -StreamOn $true -StorageAccount 'st').On | Should -BeFalse
        (Test-RAScaleOutWanted -Setting 'on' -Grain Detailed -StreamOn $false -StorageAccount 'st').On | Should -BeFalse
        (Test-RAScaleOutWanted -Setting 'on' -Grain Detailed -StreamOn $true -StorageAccount '').On | Should -BeFalse
        (Test-RAScaleOutWanted -Setting 'on' -Grain Detailed -StreamOn $true -StorageAccount 'st' -WhatIf $true).On | Should -BeFalse
    }
    It 'the Defender list is loaded by the producer only when a report of the plan needs it and plan B is on' {
        Test-RAScaleOutNeedsDefenderKeys -Queries @('x', "a`n//__SI_DFC_ANTIJOIN_BEGIN__`nb") | Should -BeTrue
        Test-RAScaleOutNeedsDefenderKeys -Queries @('x') | Should -BeFalse
        Test-RAScaleOutNeedsDefenderKeys -Queries @("//__SI_DFC_ANTIJOIN_BEGIN__") -InEngine $false -Compare $false | Should -BeFalse
    }
}

Describe 'a worker takes its report' {
    BeforeEach {
        $script:ctx = New-SIStorageContext -Mock; $script:q = Get-RAScaleOutQueueName -Grain Detailed
        $script:st = New-MemStore; $script:m = New-Man
        $script:m['WrittenUtc'] = [datetime]::UtcNow.ToString('o')
        Write-RAScaleOutManifest -Store $script:st -Manifest $script:m
        $null = Publish-RAScaleOutItems -Manifest $script:m -Context $script:ctx -QueueName $script:q
        $script:log = New-Object System.Collections.Generic.List[string]
        $script:L = { param($l, $t) $script:log.Add(('{0} {1}' -f $l, $t)) }
    }
    It 'takes the first item, writes its started mark, and the queue holds it' {
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Worker 'w1' -Log $script:L
        ($r.Kind, [string]$r.Payload.Report, [int]$r.Payload.Ordinal) | Should -Be @('item', 'A_Detailed', 1)
        $script:st.Docs.ContainsKey('collect/ra-detailed/ct-20261017060000000/started/item-00000.json') | Should -BeTrue
        $r2 = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Worker 'w2' -Log $script:L
        [string]$r2.Payload.Report | Should -Be 'Azure_Recommendations_Detailed' -Because 'the held item is hidden from the second worker'
        Complete-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Received $r | Should -BeTrue
        @($script:ctx.MockState.Queues[$script:q]).Count | Should -Be 2
    }
    It 'a closed run''s message is removed and nothing is run' {
        $null = Close-RAScaleOutRun -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L
        $r.Kind | Should -Be 'empty'
        @($script:ctx.MockState.Queues[$script:q]).Count | Should -Be 0
        ($script:log -join "`n") | Should -Match 'that run is over'
    }
    It '#882: an OLD run that is not closed is NOT over -- a long run keeps its reports (never dropped by age)' {
        $script:m['WrittenUtc'] = [datetime]::UtcNow.AddHours(-49).ToString('o'); Write-RAScaleOutManifest -Store $script:st -Manifest $script:m
        (Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L).Kind | Should -Be 'item'
    }
    It '#882: a storage read that fails puts the message BACK and stops the worker (never removed)' {
        $bad = [pscustomobject]@{ Read = { param($p) throw 'storage down' }; Write = { param($p, $t) }; List = { param($p) @() } }
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $bad -NoBeat -Log $script:L
        $r.Kind | Should -Be 'other-run'
        $r.Why | Should -Match 'could not be read'
        @($script:ctx.MockState.Queues[$script:q]).Count | Should -Be 3 -Because 'every message is still in the queue'
    }
    It 'an item already marked (an earlier attempt finished it) is removed, the next one is taken' {
        Write-RAScaleOutItemResult -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId -Item 0 -Handover @{ Reports = @('A_Detailed') } -State done
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L
        [string]$r.Payload.Report | Should -Be 'Azure_Recommendations_Detailed'
    }
    It 'an item that ended its worker more than MaxDequeue times is PARKED and marked FAILED with the cause' {
        $script:ctx.MockState['Now'] = [datetime]::UtcNow
        for ($i = 0; $i -lt 3; $i++) {
            $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L -MaxDequeue 3
            [string]$r.Payload.Report | Should -Be 'A_Detailed'
            # the worker dies: nothing is completed; its hold ends
            $script:ctx.MockState['Now'] = ([datetime]$script:ctx.MockState['Now']).AddMinutes(11)
            foreach ($x in @($script:ctx.MockState.Queues[$script:q])) { if ([string]($x.Payload | ConvertFrom-Json).Report -ne 'A_Detailed') { $x.VisibleAt = ([datetime]$script:ctx.MockState['Now']).AddHours(1) } }
        }
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L -MaxDequeue 3
        $r.Kind | Should -Be 'empty'
        $mk = @(Read-SICollectPartMarkers -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId)
        $mk.Count | Should -Be 1; $mk[0].State | Should -Be 'failed'; [int]$mk[0].Part | Should -Be 0
        $mk[0].Reason | Should -Match 'stopped 3 time\(s\) while running it'
        @($script:ctx.MockState.Queues[$script:q + '-poison']).Count | Should -Be 1
    }
    It 'another run''s message is put back at once; this worker stops' {
        $r = Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -ExpectedRunId 'ct-other' -Log $script:L
        $r.Kind | Should -Be 'other-run'
        (Receive-RAScaleOutItem -Context $script:ctx -QueueName $script:q -Store $script:st -NoBeat -Log $script:L).Kind | Should -Be 'item' -Because 'it is visible again'
    }
    It 'a new producer closes an earlier run whose producer never finished' {
        $st = New-MemStore
        $old = New-RAScaleOutManifest -Grain Detailed -TimeText '2026-10-16T06:00:00.000' -CollectionTime $script:T0.AddDays(-1) -Items @(New-Plan)
        Write-RAScaleOutManifest -Store $st -Manifest $old
        $done = New-RAScaleOutManifest -Grain Detailed -TimeText '2026-10-15T06:00:00.000' -CollectionTime $script:T0.AddDays(-2) -Items @(New-Plan)
        Write-RAScaleOutManifest -Store $st -Manifest $done; $null = Close-RAScaleOutRun -Store $st -Engine 'ra-detailed' -RunId $done.RunId
        @(Close-RAScaleOutEarlierRuns -Store $st -Engine 'ra-detailed' -RunId 'ct-20261017060000000') | Should -Be @($old.RunId)
        Test-RAScaleOutRunClosed -Store $st -Engine 'ra-detailed' -RunId $old.RunId | Should -BeTrue
    }
}

Describe 'the producer waits for every item' {
    BeforeEach {
        $script:st = New-MemStore; $script:m = New-Man
        $script:now = $script:T0; $script:N = { $script:now }; $script:S = { param($s) $script:now = $script:now.AddSeconds($s) }
        $script:log = New-Object System.Collections.Generic.List[string]; $script:L = { param($l, $t) $script:log.Add($t) }
        $script:mark = { param($i, $st) Write-SICollectPartMarker -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId -Marker (New-SICollectPartMarker -Part $i -State $st -Reason $(if ($st -eq 'failed') { 'boom' } else { '' })) }
    }
    It 'with workers: waits, says how far it is, ends when every item is marked' {
        $script:polls = 0
        $script:S = { param($s) $script:now = $script:now.AddSeconds($s); $script:polls++; if ($script:polls -eq 2) { & $script:mark 0 done; & $script:mark 1 done }; if ($script:polls -eq 4) { & $script:mark 2 done } }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker { throw 'not expected' } -Sleep $script:S -Now $script:N -Log $script:L -ProgressSeconds 0
        $w.State | Should -Be 'succeeded'
        ($script:log -join "`n") | Should -Match '3 of 3 report\(s\) done'
        ($script:log -join "`n") | Should -Match '0 of 3 report\(s\) done, 0 running, 3 waiting for a worker'
    }
    It 'with workers: none started after the grace -> this job runs a worker itself (said), once' {
        $script:local = 0
        $lw = { $script:local++; foreach ($i in 0..2) { & $script:mark $i done } }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker $lw -StartGraceMinutes 15 -Sleep $script:S -Now $script:N -Log $script:L
        ($w.State, $script:local) | Should -Be @('succeeded', 1)
        ($script:log -join "`n") | Should -Match 'no worker has started a report 15 minute\(s\) after they were queued'
    }
    It 'with workers: a started item keeps the producer waiting (no worker of its own)' {
        & $script:st.Write (Get-RAScaleOutPath -Engine 'ra-detailed' -RunId $script:m.RunId -Kind started -Item 0) '{"Worker":"w1"}'
        $script:polls = 0
        $script:S = { param($s) $script:now = $script:now.AddMinutes(10); $script:polls++; if ($script:polls -eq 5) { foreach ($i in 0..2) { & $script:mark $i done } } }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $true -LocalWorker { throw 'the producer must not run a worker while one works' } -Sleep $script:S -Now $script:N -Log $script:L
        $w.State | Should -Be 'succeeded'
    }
    It 'without a worker job: the producer''s own worker runs at once, and again after a crashed attempt''s lease' {
        $script:runs = New-Object System.Collections.Generic.List[datetime]
        $lw = { $script:runs.Add($script:now); if ($script:runs.Count -eq 1) { & $script:mark 0 done } else { & $script:mark 1 done; & $script:mark 2 done } }
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $false -LocalWorker $lw -LeaseSeconds 660 -Sleep $script:S -Now $script:N -Log $script:L
        $w.State | Should -Be 'succeeded'
        $script:runs.Count | Should -Be 2
        ($script:runs[1] - $script:runs[0]).TotalSeconds | Should -BeGreaterOrEqual 660
    }
    It 'without a worker job: after MaxLocalRuns the reports still open are left -- their items are not finished' {
        $w = Wait-RAScaleOutItems -Store $script:st -Manifest $script:m -UseKeda $false -LocalWorker { } -LeaseSeconds 0 -MaxLocalRuns 2 -Sleep $script:S -Now $script:N -Log $script:L
        $w.State | Should -Be 'incomplete'
        $f = @(Get-RAScaleOutItemFailures -Manifest $script:m -Markers @($w.Markers) -Handovers @{})
        $f.Count | Should -Be 3
        $f[0].Why | Should -Match 'not finished by a worker'
    }
    It 'a failed item, a missing marker and a missing hand-over each name their report NOT COMPLETE with the cause' {
        & $script:mark 0 failed; & $script:mark 1 done
        $mk = @(Read-SICollectPartMarkers -Store $script:st -Engine 'ra-detailed' -RunId $script:m.RunId)
        $f = @(Get-RAScaleOutItemFailures -Manifest $script:m -Markers $mk -Handovers @{})
        ($f | ForEach-Object { '{0}={1}' -f $_.Report, $_.Why }) -join ' | ' | Should -Be ('A_Detailed=its work item failed: boom | Azure_Recommendations_Detailed=its worker finished, but what it found could not be read back | ' +
            'Azure_DefenderRecommendations_Detailed=its work item was not finished by a worker in this run')
    }
}

Describe 'the hand-over: what the report loop knew, from the worker to the producer' {
    BeforeAll {
        function script:New-State {
            $s = @{ RowCounts = @{}; ColumnFill = @{}; StatusDone = @{}; Notes = @{}; QueryHash = @{}; Retries = @{}; EmptyGivers = @{}; DfcCompare = @{}
                    KqlTypes = (New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase))
                    Stream = @{ Reports = [ordered]@{}; Illegal = 0L }
                    Failures = (New-Object System.Collections.Generic.List[object]); BucketLossRun = (New-Object System.Collections.Generic.List[string])
                    Jumps = (New-Object System.Collections.Generic.List[object]); Attempted = (New-Object System.Collections.Generic.List[string])
                    PublishFailures = (New-Object System.Collections.Generic.List[string]); IngestRefused = (New-Object System.Collections.Generic.List[string])
                    NotDelivered = (New-Object System.Collections.Generic.List[string]); IngestNotes = (New-Object System.Collections.Generic.List[object]) }
            $s
        }
        # one worker runs report $Name (as the report loop fills the run's state) and hands it over
        function script:Run-Report($State, [string]$Name, [int]$Ord, [int]$Rows, [string]$Status, [string[]]$Cols, [int]$Item, [switch]$Lose) {
            $mark = Start-RAScaleOutItemState -State $State -Counters @{ ExemptedNotCounted = 0; Illegal = [double]$State.Stream.Illegal }
            $State.Attempted.Add($Name)
            $State.RowCounts[$Name] = $Rows
            $State.ColumnFill[$Name] = @{ '__rows' = [long]$Rows; 'AssetName' = [long]$Rows }
            $State.StatusDone[$Name] = $Status
            $State.Notes[$Name] = @{ StartedUtc = [datetime]'2026-10-17T06:01:00Z'; EndedUtc = [datetime]'2026-10-17T06:05:00Z'; State = $Status; Rows = [long]$Rows }
            $State.QueryHash[$Name] = ('h-' + $Name)
            $State.KqlTypes['Score' + $Ord] = 'real'; $State.KqlTypes['Shared'] = $(if ($Ord -eq 1) { 'int' } else { 'string' })
            if ($Lose) { $State.BucketLossRun.Add(('{0} :: bucket 2/4: query failed' -f $Name)); $State.Failures.Add(@{ Report = $Name; Why = 'not complete: lost' }) }
            $State.Jumps.Add([pscustomobject]@{ Report = $Name; From = 2; To = 16 })
            $e = @{ Ordinal = $Ord; Columns = (New-Object System.Collections.Generic.List[string]); DateCols = (New-Object 'System.Collections.Generic.HashSet[string]'); Retrieved = [long]$Rows; Staged = $false; StageCols = $null; Pages = 0 }
            foreach ($c in $Cols) { $e.Columns.Add($c) }; [void]$e.DateCols.Add('LastSeen')
            $State.Stream.Reports[$Name] = $e
            $State.Stream.Illegal = [long]$State.Stream.Illegal + 1
            $h = New-RAScaleOutHandover -State $State -Mark $mark -Counters @{ ExemptedNotCounted = 3; Illegal = [double]$State.Stream.Illegal } -Reports @($Name) -Item $Item `
                    -FinalDesiredColumns $Cols
            ConvertFrom-RAScaleOutJson -Text (ConvertTo-Json -InputObject $h -Compress -Depth 12)
        }
    }
    It 'merged in the single job''s order: lists, counters, the column union (trace columns last), stream entries, KQL types, notes as dates' {
        $m = New-Man
        $w1 = New-State; $w2 = New-State      # two workers; item 2 ran first, on another worker
        $h2 = Run-Report $w2 'Azure_DefenderRecommendations_Detailed' 3 40 'Complete' @('AssetName', 'Zeta', 'CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID') 2
        $h0 = Run-Report $w1 'A_Detailed' 1 10 'NotComplete' @('AssetName', 'Alpha', 'CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID') 0 -Lose
        $h1 = Run-Report $w1 'Azure_Recommendations_Detailed' 2 0 'Complete' @('assetname', 'Beta', 'CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID') 1
        $prod = New-State
        $r = Merge-RAScaleOutHandovers -State $prod -Manifest $m -Handovers @{ 2 = $h2; 0 = $h0; 1 = $h1 }
        $prod.Attempted.ToArray() | Should -Be @('A_Detailed', 'Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Detailed')
        $r.Reports | Should -Be @('A_Detailed', 'Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Detailed')
        $prod.RowCounts['Azure_DefenderRecommendations_Detailed'] | Should -Be 40
        $prod.ColumnFill['A_Detailed']['AssetName'] | Should -Be 10
        $prod.StatusDone['A_Detailed'] | Should -Be 'NotComplete'
        $prod.Notes['A_Detailed']['StartedUtc'] | Should -BeOfType [datetime]
        $prod.Notes['A_Detailed']['EndedUtc'].ToUniversalTime() | Should -Be ([datetime]'2026-10-17T06:05:00Z').ToUniversalTime()
        $prod.BucketLossRun.ToArray() | Should -Be @('A_Detailed :: bucket 2/4: query failed')
        @($prod.Failures | ForEach-Object { $_.Report }) | Should -Be @('A_Detailed')
        @($prod.Jumps | ForEach-Object { $_.Report }) | Should -Be @('A_Detailed', 'Azure_Recommendations_Detailed', 'Azure_DefenderRecommendations_Detailed')
        $r.Counters['ExemptedNotCounted'] | Should -Be 9
        $r.Counters['Illegal'] | Should -Be 3
        $r.FinalDesiredColumns | Should -Be @('AssetName', 'Alpha', 'Beta', 'Zeta', 'CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')
        $r.StreamReports['Azure_DefenderRecommendations_Detailed']['Ordinal'] | Should -Be 3
        @($r.StreamReports['A_Detailed']['Columns']) | Should -Contain 'Alpha'
        @($r.StreamReports['A_Detailed']['DateCols']) | Should -Be @('LastSeen')
        $prod.KqlTypes['Shared'] | Should -Be 'mixed'; $prod.KqlTypes['Score3'] | Should -Be 'real'
        $r.PSObject.Properties['La'] | Should -BeNullOrEmpty -Because 'a worker never posts to Log Analytics -- nothing about a post is handed over'
        $h0.ContainsKey('La') | Should -BeFalse
    }
    It 'the column union equals the single job''s: the same union whatever worker ran which report' {
        $a = @('X', 'TraceName', 'TraceID'); $b = @('Y', 'x', 'TraceName', 'TraceID'); $c = @('Z', 'TraceName', 'TraceID')
        $one = Merge-RAScaleOutColumns -Into (Merge-RAScaleOutColumns -Into (Merge-RAScaleOutColumns -Into $null -Add $a) -Add $b) -Add $c
        $one | Should -Be @('X', 'Y', 'Z', 'CollectionTime', 'SolutionVersion', 'TraceName', 'TraceID')
    }
}

Describe '#674 across workers -- in the single job''s order' {
    It 'a giver is NOT COMPLETE only when its receiver ran after it and found rows' {
        $g = @{ 'Azure_Recommendations_Detailed' = 'its list was empty' }
        $ord = @{ 'Azure_Recommendations_Detailed' = 2; 'Azure_DefenderRecommendations_Detailed' = 3 }
        $c = @(Get-RAScaleOutHandoffContradictions -EmptyGivers $g -Retrieved @{ 'Azure_DefenderRecommendations_Detailed' = 7 } -Ordinals $ord)
        $c.Count | Should -Be 1; $c[0].Report | Should -Be 'Azure_Recommendations_Detailed'
        $c[0].Why | Should -Match 'found 7 row\(s\) later in this run'
        @(Get-RAScaleOutHandoffContradictions -EmptyGivers $g -Retrieved @{ 'Azure_DefenderRecommendations_Detailed' = 0 } -Ordinals $ord).Count | Should -Be 0
        $rev = @{ 'Azure_Recommendations_Detailed' = 5; 'Azure_DefenderRecommendations_Detailed' = 3 }
        @(Get-RAScaleOutHandoffContradictions -EmptyGivers $g -Retrieved @{ 'Azure_DefenderRecommendations_Detailed' = 7 } -Ordinals $rev).Count | Should -Be 0 -Because 'the receiver ran BEFORE the giver -- as in the single job, no contradiction'
    }
}

Describe 'the run''s lock' {
    It 'is exclusive; a second taker waits; a lock past its time is taken over; only its owner releases it' {
        $s = New-MemStore; $p = Get-RAScaleOutPath -Engine 'ra-detailed' -RunId 'r' -Kind lock; $p | Should -Be 'collect/ra-detailed/r/run.lock'
        $now = [datetime]'2026-10-17T06:00:00Z'; $N = { $now }.GetNewClosure()
        $a = Enter-RAScaleOutLock -Store $s -Path $p -Owner 'A' -TtlSeconds 60 -Now $N -Sleep { }
        $a | Should -Be 'A'
        $b = Enter-RAScaleOutLock -Store $s -Path $p -Owner 'B' -TtlSeconds 60 -WaitSeconds 0 -Now $N -Sleep { } 3>$null
        $b | Should -Be '' -Because 'A holds it; B goes on without it after its wait, said'
        Exit-RAScaleOutLock -Store $s -Path $p -Owner 'B'
        $s.Docs.ContainsKey($p) | Should -BeTrue -Because 'B is not the owner'
        $later = { [datetime]'2026-10-17T06:05:00Z' }
        Enter-RAScaleOutLock -Store $s -Path $p -Owner 'C' -TtlSeconds 60 -Now $later -Sleep { } | Should -Be 'C' -Because 'A''s lock ran out'
        Exit-RAScaleOutLock -Store $s -Path $p -Owner 'C'
        $s.Docs.ContainsKey($p) | Should -BeFalse
    }
}

Describe 'the bucket counts of an install without the Pro settings database' {
    It 'a worker keeps only its own reports'' counts, on the stored copy' {
        $stored = @{ 'A|h1' = 4; 'B|h2' = 8; '__confirmed' = @{ 'A|h1' = 't1'; 'B|h2' = 't2' } }
        $local = @{ 'A|h1' = 99; 'B|h2' = 16; 'B|h3' = 2; '__confirmed' = @{ 'A|h1' = 'x'; 'B|h2' = 't9' } }
        $m = Merge-RAScaleOutBucketCache -Stored $stored -Local $local -Reports @('B')
        ($m['A|h1'], $m['B|h2'], $m['B|h3']) | Should -Be @(4, 16, 2)
        ($m['__confirmed']['A|h1'], $m['__confirmed']['B|h2']) | Should -Be @('t1', 't9')
    }
}

Describe '#831 B -- a big report in several parts: the plan' {
    It 'the split count comes from the run''s remembered slices and the worker count -- never a fixed size' {
        Get-RAScaleOutSplitCount -Buckets 256 -RunBuckets 356 -Workers 1 | Should -Be 1 -Because 'one worker (or the producer''s own): never split'
        Get-RAScaleOutSplitCount -Buckets 3 -RunBuckets 3 -Workers 4 | Should -Be 1 -Because 'a part has at least 2 slices'
        Get-RAScaleOutSplitCount -Buckets 256 -RunBuckets 356 -Workers 4 | Should -Be 3 -Because 'the measured case: 256 slices against a fair share of 89'
        Get-RAScaleOutSplitCount -Buckets 64 -RunBuckets 64 -Workers 4 | Should -Be 4 -Because 'the only report of the run: every worker'
        Get-RAScaleOutSplitCount -Buckets 8 -RunBuckets 400 -Workers 4 | Should -Be 1 -Because 'a small report against the run: one item'
        Get-RAScaleOutSplitCount -Buckets 8 -RunBuckets 8 -Workers 30 | Should -Be 4 -Because 'never a part of fewer than 2 slices'
        foreach ($n in 1..80) { foreach ($w in 1..8) { foreach ($t in @($n, ($n * 2), ($n + 37))) {
            $k = Get-RAScaleOutSplitCount -Buckets $n -RunBuckets $t -Workers $w
            $k | Should -BeLessOrEqual ([Math]::Max(1, $w)); if ($k -gt 1) { [Math]::Floor($n / $k) | Should -BeGreaterOrEqual 2 }
        } } }
    }
    It 'a split report becomes items over contiguous slice ranges with ONE ordinal; the other reports keep theirs; a report without remembered state is one item' {
        $p = @(New-RAScaleOutPlan -Workers 4 -Reports @(
            [pscustomobject]@{ Name = 'Small_Detailed'; HasEntry = $true; Buckets = 4; Splittable = $true },
            [pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 256; Splittable = $true },
            [pscustomobject]@{ Name = 'New_Detailed'; HasEntry = $true; Buckets = 0; Splittable = $true },
            [pscustomobject]@{ Name = 'NoSlice_Detailed'; HasEntry = $true; Buckets = 512; Splittable = $false }))
        @($p | Where-Object { $_.Report -eq 'Big_Detailed' }).Count | Should -BeGreaterThan 1
        ($p | ForEach-Object { $_.Item }) -join ',' | Should -Be ((0..($p.Count - 1)) -join ',')
        @($p | Where-Object { $_.Report -eq 'Big_Detailed' } | ForEach-Object { $_.Ordinal } | Select-Object -Unique) | Should -Be @(2)
        @($p | Where-Object { $_.Report -eq 'New_Detailed' }).Count | Should -Be 1 -Because 'no remembered state: one item, as today'
        @($p | Where-Object { $_.Report -eq 'NoSlice_Detailed' }).Count | Should -Be 1
        ($p | Where-Object { $_.Report -eq 'NoSlice_Detailed' }).Ordinal | Should -Be 4
        $big = @($p | Where-Object { $_.Report -eq 'Big_Detailed' } | Sort-Object Part)
        $big[0].From | Should -Be 0; $big[-1].To | Should -Be 256
        for ($i = 1; $i -lt $big.Count; $i++) { $big[$i].From | Should -Be $big[$i - 1].To }
        @($big | Where-Object { $_.Buckets -ne 256 -or $_.Parts -ne $big.Count }).Count | Should -Be 0
        @(New-RAScaleOutPlan -Workers 1 -Reports @([pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 256; Splittable = $true })).Count | Should -Be 1
    }
    It 'each part numbers its rows in its own bands: every main slice, then every late retry, then the sub-slices -- the single job''s order; no band overlaps' {
        $ord = 7; $np = 3; $base = Get-RAScaleOutSeqBase -Ordinal $ord
        $seq = @(foreach ($b in 'main', 'late', 'sub') { foreach ($pi in 0..($np - 1)) { Get-RAScaleOutSplitSeqBase -Ordinal $ord -Part $pi -Parts $np -Band $b } })
        ($seq | Sort-Object) -join ',' | Should -Be ($seq -join ',') -Because 'main of part 1, 2, 3, then late of part 1, 2, 3, then sub'
        $seq[0] | Should -Be $base
        $rg = @(foreach ($pi in 0..($np - 1)) { Get-RAScaleOutSplitSeqRanges -Ordinal $ord -Part $pi -Parts $np })
        $all = @($rg | Sort-Object From)
        for ($i = 1; $i -lt $all.Count; $i++) { $all[$i].From | Should -BeGreaterOrEqual $all[$i - 1].To }
        $all[-1].To | Should -BeLessOrEqual (Get-RAScaleOutSeqBase -Ordinal ($ord + 1)) -Because 'inside the report''s own range'
        ($all[0].To - $all[0].From) | Should -BeGreaterThan 1000000000 -Because 'room for any report'
    }
    It 'only a report the single job asks in remembered slices may be split' {
        $q = "x`n//__BUCKET_FILTER_BEGIN__`n| where true`n//__BUCKET_FILTER_END__"
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query $q | Should -BeTrue
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query 'x | take 1' | Should -BeFalse
        Test-RAScaleOutSplittable -Name 'A_Summary' -Query $q | Should -BeFalse -Because 'a staged report combines its groups over all slices'
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query $q -UseBucketFilter $false | Should -BeFalse
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query $q -BucketCount 1 | Should -BeFalse
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query $q -AutoBucket $false | Should -BeFalse
        Test-RAScaleOutSplittable -Name 'A_Detailed' -Query $q -Proof $true | Should -BeFalse
        Get-RAScaleOutRememberedBuckets -Report 'A_Detailed' -Cache @{ 'A_Detailed|1' = 64; 'A_Detailed|2' = 128; 'A_Detailed_X|3' = 999; '__confirmed' = @{ 'A_Detailed|1' = 't' } } | Should -Be 128
        Get-RAScaleOutRememberedBuckets -Report 'B_Detailed' -Cache @{ 'A_Detailed|1' = 64 } | Should -Be 0
    }
    It 'the queue hands out the LARGEST items first (a big report and the parts of a split one at once); ordinals and write numbers unchanged' {
        $plan = @(New-RAScaleOutPlan -Workers 4 -Reports @(
            [pscustomobject]@{ Name = 'Small_Detailed'; HasEntry = $true; Buckets = 2; Splittable = $true },
            [pscustomobject]@{ Name = 'NoState_Detailed'; HasEntry = $true },
            [pscustomobject]@{ Name = 'Mid_Detailed'; HasEntry = $true; Buckets = 12; Splittable = $false },
            [pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 256; Splittable = $true }))
        $m = New-Man -Plan $plan
        $sent = New-Object System.Collections.Generic.List[object]
        $null = Publish-RAScaleOutItems -Manifest $m -Enqueue { param($p) $sent.Add($p) }.GetNewClosure()
        $sent.Count | Should -Be $plan.Count
        $sizes = @($sent | ForEach-Object { $it = $plan[[int]$_.Item]; [int]$it.Size })
        ($sizes -join ',') | Should -Be ((@($sizes | Sort-Object -Descending)) -join ',') -Because 'largest first'
        @($sent | Select-Object -First (@($plan | Where-Object { $_.Report -eq 'Big_Detailed' }).Count) | ForEach-Object { $_.Report } | Select-Object -Unique) | Should -Be @('Big_Detailed') -Because 'the big report''s parts start first'
        @($sent | Select-Object -Last 2 | ForEach-Object { $_.Report }) | Should -Be @('Small_Detailed', 'NoState_Detailed') -Because 'then the smaller ones, the report without remembered state last'
        # nothing that decides the result's order changed: each item's ordinal is the plan's (the single job's numbering)
        foreach ($s in $sent) { [int]$s.Ordinal | Should -Be ([int]$plan[[int]$s.Item].Ordinal) }
        @($m.Items | ForEach-Object { [int]$_['Item'] }) | Should -Be @(0..($plan.Count - 1)) -Because 'the manifest keeps the plan order'
    }
    It 'the manifest and the queue carry each part''s slices; a whole report''s item stays as before' {
        $plan = @(New-RAScaleOutPlan -Workers 2 -Reports @([pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 16; Splittable = $true }, [pscustomobject]@{ Name = 'B_Detailed'; HasEntry = $true }))
        $m = New-Man -Plan $plan
        $s = New-MemStore; Write-RAScaleOutManifest -Store $s -Manifest $m
        $r = Read-RAScaleOutManifest -Store $s -Engine 'ra-detailed' -RunId $m.RunId
        @(Get-RAScaleOutSiblings -Manifest $r -Report 'Big_Detailed' | ForEach-Object { '{0}:{1}-{2}/{3}' -f $_['Part'], $_['From'], $_['To'], $_['Buckets'] }) | Should -Be @('0:0-8/16', '1:8-16/16')
        $sent = New-Object System.Collections.Generic.List[object]
        $null = Publish-RAScaleOutItems -Manifest $m -Enqueue { param($p) $sent.Add($p) }.GetNewClosure()
        ($sent[1].Part, $sent[1].Parts, $sent[1].From, $sent[1].To, $sent[1].Buckets) | Should -Be @(1, 2, 8, 16, 16)
        $sent[2].ContainsKey('Parts') | Should -BeFalse -Because 'a whole report''s message is unchanged'
    }
}

Describe '#831 B -- the parts of one report put together as one job' {
    BeforeAll {
        function script:New-Part([int]$Item, [int]$Part, [long]$Rows, [hashtable]$Ev = @{}, [string[]]$Loss = @(), [string[]]$Cols = @('A', 'B')) {
            $st = @{ RowCounts = @{ 'Big_Detailed' = [int]$Rows }; ColumnFill = @{ 'Big_Detailed' = @{ A = [long]$Rows; B = 1L } }; Notes = @{ 'Big_Detailed' = @{ StartedUtc = ([datetime]'2026-10-17T06:00:00Z').AddMinutes(10 - $Part).ToUniversalTime() } }
                     Retries = @{ 'Big_Detailed' = @{ '429' = 1L } }
                     Failures = (New-Object System.Collections.Generic.List[object]); Attempted = (New-Object System.Collections.Generic.List[string]); Jumps = (New-Object System.Collections.Generic.List[object])
                     BucketLossRun = (New-Object System.Collections.Generic.List[string]); PublishFailures = (New-Object System.Collections.Generic.List[string]); IngestRefused = (New-Object System.Collections.Generic.List[string])
                     NotDelivered = (New-Object System.Collections.Generic.List[string]); IngestNotes = (New-Object System.Collections.Generic.List[object]) }
            $mark = Start-RAScaleOutItemState -State $st
            $st.Attempted.Add('Big_Detailed')
            $entry = @{ Retrieved = $Rows; Account = @{ ('{0}/8' -f ($Part + 1)) = @{ In = $Rows; Written = $Rows } }; Columns = $Cols; DateCols = @('LastSeen') }
            $e = @{ Measure = [pscustomobject]@{ ResultRows = $Rows; MaxBucketRows = (10 * ($Part + 1)); Slices = 4; MaxBucketSeconds = (5.0 + $Part) } }
            foreach ($k in @($Ev.Keys)) { $e[$k] = $Ev[$k] }
            $p = New-RAScaleOutPartial -State $st -Mark $mark -Report 'Big_Detailed' -Item $Item -Part $Part -Parts 3 -Entry $entry -BucketLoss $Loss -Evidence $e -Worker "w$Part"
            ConvertFrom-RAScaleOutJson -Text (ConvertTo-Json -InputObject $p -Compress -Depth 12)
        }
    }
    It 'the LAST part to finish puts the report together -- exactly one, never a wait; the retry of that part may again' {
        $s = New-MemStore; $sib = @(4, 5, 6)
        Write-RAScaleOutPartial -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Partial (New-Part 5 1 10)
        $r = Request-RAScaleOutFinish -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Ordinal 2 -Item 5 -Siblings $sib
        ($r.Finisher, $r.Missing) | Should -Be @($false, 2)
        Write-RAScaleOutPartial -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Partial (New-Part 4 0 20)
        (Request-RAScaleOutFinish -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Ordinal 2 -Item 4 -Siblings $sib).Finisher | Should -BeFalse
        Write-RAScaleOutPartial -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Partial (New-Part 6 2 30)
        $last = Request-RAScaleOutFinish -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Ordinal 2 -Item 6 -Siblings $sib
        $last.Finisher | Should -BeTrue; @($last.Partials.Keys) | Should -Be @('4', '5', '6')
        (Request-RAScaleOutFinish -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Ordinal 2 -Item 4 -Siblings $sib).Finisher | Should -BeFalse -Because 'both saw every part: the claim decides'
        (Request-RAScaleOutFinish -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -Ordinal 2 -Item 6 -Siblings $sib).Finisher | Should -BeTrue -Because 'the retry of the part that claimed it'
    }
    It 'merged: rows, accounts, row count, column fill, retries added; columns, lost slices and list entries in part order; the report attempted once; the earliest start; one bucket learning' {
        $ps = [ordered]@{ '6' = (New-Part 6 2 30 -Loss @('bucket 7/8: lost') -Cols @('C', 'A')); '4' = (New-Part 4 0 20 -Ev @{ SplitUsed = $true; SplitBuckets = 1; SplitWorking = 32; SplitSlices = @{ 1 = @{ Rows = 5; Bytes = 9; Seconds = 1.5; TooLarge = $true; Lost = $false } } } -Loss @('bucket 2/8: lost'))
                          '5' = (New-Part 5 1 10 -Ev @{ BusySlices = 2; Deferred = 1; SplitBuckets = 1; SplitWorking = 16; SplitSlices = @{ 3 = @{ Rows = 2; Bytes = 3; Seconds = 0.5; TooLarge = $false; Lost = $false } } }) }
        $m = Merge-RAScaleOutPartials -Partials $ps
        $m.Problem | Should -Be ''
        ($m.Retrieved, $m.RowCount, $m.ColumnFill['A'], $m.ColumnFill['B'], $m.Retries['429']) | Should -Be @(60, 60, 60, 3, 3)
        @($m.Account.Keys | Sort-Object) | Should -Be @('1/8', '2/8', '3/8')
        $m.Columns | Should -Be @('A', 'B', 'C')
        $m.BucketLoss | Should -Be @('bucket 2/8: lost', 'bucket 7/8: lost')
        @($m.Lists['Attempted']) | Should -Be @('Big_Detailed')
        [datetime]::Parse($m.StartedUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime() | Should -Be ([datetime]'2026-10-17T06:08:00Z').ToUniversalTime()
        ($m.Evidence.SplitUsed, $m.Evidence.SplitBuckets, $m.Evidence.SplitWorking, $m.Evidence.BusySlices, $m.Evidence.Deferred) | Should -Be @($true, 2, 32, 2, 1)
        @($m.Evidence.SplitSlices.Keys | Sort-Object) | Should -Be @('1', '3')
        ($m.Evidence.Measure.ResultRows, $m.Evidence.Measure.MaxBucketRows, $m.Evidence.Measure.Slices, $m.Evidence.Measure.MaxBucketSeconds) | Should -Be @(60, 30, 12, 7.0)
    }
    It '#401: the first part returned the whole report in one slice -- it IS the report, the others'' rows go; a later part doing so alone = NOT COMPLETE; a part that cannot fit = NOT COMPLETE' {
        $m = Merge-RAScaleOutPartials -Partials ([ordered]@{ '4' = (New-Part 4 0 20 -Ev @{ Complete = $true }); '5' = (New-Part 5 1 20 -Ev @{ Complete = $true }); '6' = (New-Part 6 2 3) })
        ($m.Problem, $m.Complete, $m.Retrieved) | Should -Be @('', $true, 20)
        $m.Drop | Should -Be @(5, 6)
        (Merge-RAScaleOutPartials -Partials ([ordered]@{ '4' = (New-Part 4 0 2); '5' = (New-Part 5 1 20 -Ev @{ Complete = $true }) })).Problem | Should -Match 'do not add up'
        $c = Merge-RAScaleOutPartials -Partials ([ordered]@{ '4' = (New-Part 4 0 2); '5' = (New-Part 5 1 0 -Ev @{ CannotFit = 'the lookup is too large' }) })
        ($c.Problem, $c.CannotFit) | Should -Be @('the lookup is too large', 'the lookup is too large')
    }
    It 'the producer: a split report is complete only with every part marked and one part''s full hand-over; any other case is NOT COMPLETE ONCE, with the cause' {
        $plan = @(New-RAScaleOutPlan -Workers 4 -Reports @([pscustomobject]@{ Name = 'A_Detailed'; HasEntry = $true }, [pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 12; Splittable = $true }))
        $m = New-Man -Plan $plan
        $mk = { param($i, $st, $why) [pscustomobject]@{ Part = $i; State = $st; Reason = $why } }
        $stub = @{ Reports = @(); PerReport = @{} }; $full = @{ Reports = @('Big_Detailed'); PerReport = @{} }; $a = @{ Reports = @('A_Detailed'); PerReport = @{} }
        $n = $plan.Count
        $allDone = @(0..($n - 1) | ForEach-Object { & $mk $_ 'done' '' })
        $hv = @{ 0 = $a }; for ($i = 1; $i -lt $n; $i++) { $hv[$i] = $stub }; $hv[$n - 2] = $full
        @(Get-RAScaleOutItemFailures -Manifest $m -Markers $allDone -Handovers $hv).Count | Should -Be 0
        $hv2 = @{ 0 = $a }; for ($i = 1; $i -lt $n; $i++) { $hv2[$i] = $stub }
        $f = @(Get-RAScaleOutItemFailures -Manifest $m -Markers $allDone -Handovers $hv2)
        $f.Count | Should -Be 1; $f[0].Why | Should -Match 'none of them put the report together'
        $mk2 = @($allDone | ForEach-Object { if ($_.Part -ge 1 -and $_.Part -le 2) { & $mk $_.Part 'failed' 'the worker ran out of memory' } else { $_ } })
        $f2 = @(Get-RAScaleOutItemFailures -Manifest $m -Markers $mk2 -Handovers $hv2)
        $f2.Count | Should -Be 1 -Because 'one report, named once'
        $f2[0].Why | Should -Match '^its work item failed: part 1 of \d+: the worker ran out of memory'
        $f3 = @(Get-RAScaleOutItemFailures -Manifest $m -Markers @($allDone | Where-Object { $_.Part -ne 2 }) -Handovers $hv)
        ($f3.Count, $f3[0].Report) | Should -Be @(1, 'Big_Detailed')
    }
    It 'the producer merges a part''s stub as nothing of the report (its counters and columns only), in the single job''s order' {
        $plan = @(New-RAScaleOutPlan -Workers 2 -Reports @([pscustomobject]@{ Name = 'Big_Detailed'; HasEntry = $true; Buckets = 8; Splittable = $true }, [pscustomobject]@{ Name = 'Z_Detailed'; HasEntry = $true }))
        $m = New-Man -Plan $plan
        $mk = { param($reps, $c, $cols, $att) @{ Reports = @($reps); PerReport = @{}; Lists = @{ Attempted = @($att) }; Counters = @{ Illegal = $c }; FinalDesiredColumns = @($cols); KqlTypes = @{} } }
        $hv = @{ 2 = (& $mk @('Z_Detailed') 1 @('Z1') 'Z_Detailed'); 1 = (& $mk @('Big_Detailed') 2 @('B', 'C') 'Big_Detailed'); 0 = (& $mk @() 4 @('A', 'B') @()) }
        $st = @{ Attempted = (New-Object System.Collections.Generic.List[string]) }
        $mg = Merge-RAScaleOutHandovers -State $st -Manifest $m -Handovers $hv
        $mg.Reports | Should -Be @('Big_Detailed', 'Z_Detailed')
        $mg.Counters['Illegal'] | Should -Be 7
        @($mg.FinalDesiredColumns | Select-Object -First 4) | Should -Be @('A', 'B', 'C', 'Z1') -Because 'part order inside the report, then the next report'
        $st.Attempted.ToArray() | Should -Be @('Big_Detailed', 'Z_Detailed')
    }
}

Describe '#831 A -- the run''s open items, and the heartbeat''s sign-in' {
    It 'the open items are read from ONE listing of the run''s markers (no lease, no heartbeat); not known = -1' {
        $s = New-MemStore; $m = New-Man
        Get-RAScaleOutOpenItems -Store $s -Manifest $m | Should -Be 3
        Write-SICollectPartMarker -Store $s -Engine 'ra-detailed' -RunId $m.RunId -Marker (New-SICollectPartMarker -Part 1 -State done)
        Get-RAScaleOutOpenItems -Store $s -Manifest $m | Should -Be 2
        Write-SICollectPartMarker -Store $s -Engine 'ra-detailed' -RunId $m.RunId -Marker (New-SICollectPartMarker -Part 0 -State failed -Reason 'x')
        Get-RAScaleOutOpenItems -Store $s -Manifest $m | Should -Be 1 -Because 'a failed item is not open either'
        Get-RAScaleOutOpenItems -Store $null -Manifest $m | Should -Be -1
        $bad = [pscustomobject]@{ List = { throw 'the store is down' } }
        Get-RAScaleOutOpenItems -Store $bad -Manifest $m | Should -Be -1
    }
    It 'the heartbeat that holds a report gets THIS process''s sign-in (its own runspace does not see it -- internal 2026-10-20: every renewal failed "No sign-in is configured")' {
        if (-not (Get-Command -Name Resolve-SIAzRestAuth -ErrorAction SilentlyContinue)) { function script:Resolve-SIAzRestAuth { $null } }
        Mock Resolve-SIAzRestAuth { @{ Mode = 'ManagedIdentity'; ClientId = 'mi-1' } }
        Mock Start-SIWorkItemLeaseBeat { $null }
        Mock Get-SIWorkItemFallbackLeaseSeconds { 7500 }
        $ctx = New-SIStorageContext -Mock; $q = Get-RAScaleOutQueueName -Grain Detailed
        $st = New-MemStore; $m = New-Man; $m['WrittenUtc'] = [datetime]::UtcNow.ToString('o')
        Write-RAScaleOutManifest -Store $st -Manifest $m
        $null = Publish-RAScaleOutItems -Manifest $m -Context $ctx -QueueName $q
        $r = Receive-RAScaleOutItem -Context $ctx -QueueName $q -Store $st -Worker 'w1' -Log { param($l, $t) }
        $r.Kind | Should -Be 'item'
        Should -Invoke Start-SIWorkItemLeaseBeat -Times 1 -Exactly -ParameterFilter { $null -ne $Auth -and $Auth.Mode -eq 'ManagedIdentity' -and $Auth.ClientId -eq 'mi-1' }
        $null = Receive-RAScaleOutItem -Context $ctx -QueueName $q -Store $st -Worker 'w2' -Auth @{ Mode = 'Certificate'; AppId = 'a' } -Log { param($l, $t) }
        Should -Invoke Start-SIWorkItemLeaseBeat -Times 1 -Exactly -ParameterFilter { $null -ne $Auth -and $Auth.Mode -eq 'Certificate' } -Because 'an explicit sign-in is passed as given'
    }
}
