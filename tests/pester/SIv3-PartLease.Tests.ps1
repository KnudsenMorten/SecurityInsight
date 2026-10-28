#Requires -Version 5.1
<#
    THE HOLD ON A COLLECTION PART IS SHORT AND RENEWED (2026-10-13).

    A queue worker used to take its part with a lease as long as the worker job's run limit and never renew it. With a run
    limit of 7 days a worker killed mid-part (out of memory, a platform restart) locked its part for 7 days. Now:
      * the part is taken for a SHORT lease (10 minutes) and a heartbeat on its own thread renews it while the worker lives
        (engine/asset-profiling/storage/WorkerQueue.ps1: Update-SIWorkItemLease, Start- / Stop-SIWorkItemLeaseBeat);
      * a worker that stops renewing -- it died -- gives the part back within one lease;
      * a renewal the queue REFUSES (another worker holds the part, or it is gone) means the part is LOST: the worker stops
        that part and says so, and never marks it done -- so a part is not written twice;
      * a renewal that merely fails (network, sign-in) is tried again; the worker goes on;
      * a part handed out more than 5 times is still parked (unchanged).

    Offline: the Mock queue (in memory, with the real queue's leases and receipts) and the REST call behind the HTTP seam.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')
    $script:Q = 'si-identity-shards'
    function script:New-PartQueue([int]$Parts = 1) {
        $ctx = New-SIStorageContext -Mock
        Initialize-SIQueue -Context $ctx -QueueName $script:Q | Out-Null
        for ($i = 0; $i -lt $Parts; $i++) { Add-SIWorkItem -Context $ctx -QueueName $script:Q -Payload @{ ShardIndex = $i; ShardCount = $Parts; RunId = 'run-1' } }
        $ctx
    }
    # a clock the test moves (the queue's own time); only for tests without a heartbeat thread
    function script:Set-QueueClock($Ctx, [datetime]$At) { $Ctx.MockState['Now'] = $At }
    $script:T0 = [datetime]::new(2026, 10, 13, 8, 0, 0, [DateTimeKind]::Utc)
}

Describe 'the lease on a part: short, renewed, and given back by a worker that stops renewing' {
    It 'the lease is 10 minutes and the beat 2 minutes -- five beats per lease' {
        Get-SIWorkItemLeaseSeconds | Should -Be 600
        Get-SIWorkItemBeatSeconds | Should -Be 120
        (Get-Command Get-SINextWorkItem).Parameters['VisibilityTimeoutSeconds'] | Should -Not -BeNullOrEmpty
    }
    It 'a part that is held is hidden from the other workers; A WORKER THAT STOPS RENEWING (it died) gives the part back after one lease, and the next worker gets it as hand-out 2' {
        $ctx = New-PartQueue; Set-QueueClock $ctx $script:T0
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600
        $a.DequeueCount | Should -Be 1
        Get-SINextWorkItem -Context $ctx -QueueName $script:Q | Should -BeNullOrEmpty -Because 'the part is held'
        Set-QueueClock $ctx $script:T0.AddSeconds(599)
        Get-SINextWorkItem -Context $ctx -QueueName $script:Q | Should -BeNullOrEmpty -Because 'still within the lease'
        # the worker died: nothing renewed the hold. One lease later the part is visible again.
        Set-QueueClock $ctx $script:T0.AddSeconds(600)
        $b = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600
        $b | Should -Not -BeNullOrEmpty -Because 'ten minutes, not the worker job''s run limit of days'
        $b.Id | Should -Be $a.Id; $b.DequeueCount | Should -Be 2; $b.PopReceipt | Should -Not -Be $a.PopReceipt
    }
    It 'A LIVE WORKER RUNNING LONGER THAN ONE LEASE KEEPS ITS PART: every renewal moves the lease on and gives a new receipt; the delete at the end needs the newest' {
        $ctx = New-PartQueue; Set-QueueClock $ctx $script:T0
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600
        $receipt = [string]$a.PopReceipt
        # two hours of work, a renewal every two minutes
        for ($min = 2; $min -le 120; $min += 2) {
            Set-QueueClock $ctx $script:T0.AddMinutes($min)
            $r = Update-SIWorkItemLease -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt $receipt -VisibilityTimeoutSeconds 600 -RawText $a.RawText
            $r.Ok | Should -BeTrue; $r.Lost | Should -BeFalse
            $r.PopReceipt | Should -Not -Be $receipt -Because 'a renewal gives a new receipt'
            $receipt = [string]$r.PopReceipt
            Get-SINextWorkItem -Context $ctx -QueueName $script:Q | Should -BeNullOrEmpty -Because "after $min minutes the part is still this worker's"
        }
        { Complete-SIWorkItem -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt ([string]$a.PopReceipt) } | Should -Throw '*PopReceiptMismatch*' -Because 'the first receipt is no longer valid'
        Complete-SIWorkItem -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt $receipt
        @($ctx.MockState.Queues[$script:Q]).Count | Should -Be 0 -Because 'released at the end: the part is done and gone'
    }
    It 'A LOST LEASE: the part was handed to another worker -> the renewal says LOST (not "try again"), and so does a part that is gone' {
        $ctx = New-PartQueue; Set-QueueClock $ctx $script:T0
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600
        Set-QueueClock $ctx $script:T0.AddMinutes(11)                       # this worker stood still past its lease
        $b = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600
        $b.DequeueCount | Should -Be 2
        $r = Update-SIWorkItemLease -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt ([string]$a.PopReceipt)
        $r.Ok | Should -BeFalse; $r.Lost | Should -BeTrue; $r.Why | Should -Be 'another worker holds the message now'
        # the worker that holds it now is not disturbed
        (Update-SIWorkItemLease -Context $ctx -QueueName $script:Q -Id $b.Id -PopReceipt ([string]$b.PopReceipt)).Ok | Should -BeTrue
        # a part that is gone (done by the other worker, or parked)
        $gone = Update-SIWorkItemLease -Context $ctx -QueueName $script:Q -Id 'no-such-message' -PopReceipt 'x'
        $gone.Lost | Should -BeTrue; $gone.Why | Should -Be 'the message is no longer in the queue'
        # NEGATIVE: a renewal that merely fails is NOT a lost part
        $ctx.MockState['RenewFails'] = 'HTTP 503: the queue is busy'
        $f = Update-SIWorkItemLease -Context $ctx -QueueName $script:Q -Id $b.Id -PopReceipt ([string]$b.PopReceipt)
        $f.Ok | Should -BeFalse; $f.Lost | Should -BeFalse; $f.Why | Should -Match '503'
    }
    It 'a part handed out more than 5 times is still parked (the rule is unchanged, and it is what ends a part whose worker dies every time)' {
        $ctx = New-PartQueue; $at = $script:T0
        $m = $null
        foreach ($n in 1..6) { Set-QueueClock $ctx $at; $m = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 600; $m.DequeueCount | Should -Be $n; $at = $at.AddSeconds(600) }
        $m.DequeueCount | Should -BeGreaterThan 5
        $p = Move-SIWorkItemToPoison -Context $ctx -QueueName $script:Q -WorkItem $m -Reason 'handed out 6 times without completing'
        @($ctx.MockState.Queues[$script:Q]).Count | Should -Be 0
        @($ctx.MockState.Queues[$p]).Count | Should -Be 1
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match "SI_QUEUE_MAX_DEQUEUE' 5"
        $src | Should -Match '\$msg\.DequeueCount -gt \$maxDequeue'
    }
}

Describe 'the heartbeat: its own thread renews the hold while the worker''s thread is busy' {
    It 'a worker busy in ONE long call for several leases keeps its part, and the receipt at the end deletes it' {
        $ctx = New-PartQueue
        # a lease of 8 s (not shorter: the test VM runs many suites at once and a thread can stand still for a second or two)
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 8
        $beat = Start-SIWorkItemLeaseBeat -Context $ctx -QueueName $script:Q -WorkItem $a -LeaseSeconds 8 -BeatMs 300 -What 'part 1 of 1' -Quiet
        $beat | Should -Not -BeNullOrEmpty -Because 'the heartbeat starts and its first renewal succeeds'
        try {
            [int]$beat.Renewals | Should -BeGreaterOrEqual 1 -Because 'the first renewal is made at once, before the part is worked on'
            Start-Sleep -Seconds 20                                            # the worker's own thread: one call, 2.5 leases long
            Get-SINextWorkItem -Context $ctx -QueueName $script:Q | Should -BeNullOrEmpty -Because 'the heartbeat kept the hold although this thread did nothing for it'
            [int]$beat.Renewals | Should -BeGreaterThan 5
        } finally { $end = Stop-SIWorkItemLeaseBeat -Beat $beat }
        $end.Lost | Should -BeFalse; $end.Settled | Should -BeTrue
        $end.PopReceipt | Should -Not -Be ([string]$a.PopReceipt)
        Complete-SIWorkItem -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt $end.PopReceipt
        @($ctx.MockState.Queues[$script:Q]).Count | Should -Be 0
    }
    It 'a worker that dies: its heartbeat ends with it, and the part is visible again within one lease' {
        $ctx = New-PartQueue
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 8
        $beat = Start-SIWorkItemLeaseBeat -Context $ctx -QueueName $script:Q -WorkItem $a -LeaseSeconds 8 -BeatMs 300 -Quiet
        $beat | Should -Not -BeNullOrEmpty
        Start-Sleep -Milliseconds 700                                          # a beat or two
        $null = Stop-SIWorkItemLeaseBeat -Beat $beat                           # the process is gone: nothing renews any more
        Get-SINextWorkItem -Context $ctx -QueueName $script:Q | Should -BeNullOrEmpty -Because 'the last renewal still holds'
        Start-Sleep -Milliseconds 8600
        $b = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 8
        $b | Should -Not -BeNullOrEmpty -Because 'one lease after the last beat the part is free'
        $b.DequeueCount | Should -Be 2
    }
    It 'A LOST LEASE stops the part: the heartbeat marks it lost, says so in plain words and stops beating; the worker never deletes or marks the part' {
        $ctx = New-PartQueue
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 2
        $beat = Start-SIWorkItemLeaseBeat -Context $ctx -QueueName $script:Q -WorkItem $a -LeaseSeconds 2 -BeatMs 300 -What 'part 1 of 1' -Quiet
        $beat | Should -Not -BeNullOrEmpty
        # another worker takes the part (as after a lapse): the item gets its receipt
        $item = @($ctx.MockState.Queues[$script:Q])[0]
        $item.PopReceipt = 'held-by-the-other-worker'
        $deadline = [datetime]::UtcNow.AddSeconds(10)
        while (-not $beat.Lost -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $end = Stop-SIWorkItemLeaseBeat -Beat $beat
        $end.Lost | Should -BeTrue; $end.Why | Should -Be 'another worker holds the message now'
        @($beat.Lines)[-1] | Should -Be 'part 1 of 1: this worker no longer holds the part (another worker holds the message now) -- it stops here, so the part is not written twice. The worker that holds it now finishes it.'
        $item.PopReceipt | Should -Be 'held-by-the-other-worker' -Because 'the other worker''s hold is not touched'
        { Complete-SIWorkItem -Context $ctx -QueueName $script:Q -Id $a.Id -PopReceipt $end.PopReceipt } | Should -Throw '*PopReceiptMismatch*'
        @($ctx.MockState.Queues[$script:Q]).Count | Should -Be 1 -Because 'the part stays with the worker that holds it'
    }
    It 'a renewal that fails is said once and tried again -- the worker goes on, the part is not lost; NEGATIVE: a heartbeat whose first renewal fails does not start (the caller holds the part the old way)' {
        $ctx = New-PartQueue
        $a = Get-SINextWorkItem -Context $ctx -QueueName $script:Q -VisibilityTimeoutSeconds 30
        $beat = Start-SIWorkItemLeaseBeat -Context $ctx -QueueName $script:Q -WorkItem $a -LeaseSeconds 30 -BeatMs 200 -What 'part 1 of 1' -Quiet
        $beat | Should -Not -BeNullOrEmpty
        $ctx.MockState['RenewFails'] = 'HTTP 503: the queue is busy'
        $deadline = [datetime]::UtcNow.AddSeconds(10)
        while ([int]$beat.Failures -lt 3 -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        [int]$beat.Failures | Should -BeGreaterOrEqual 3
        $beat.Lost | Should -BeFalse
        @($beat.Lines | Where-Object { $_ -match 'could not be renewed' }).Count | Should -BeLessThan ([int]$beat.Failures) -Because 'said at the first failure, then only at every fifth'
        @($beat.Lines)[0] | Should -Match '^part 1 of 1: the hold on the part could not be renewed \(HTTP 503: the queue is busy\) -- trying again in 0 s; the worker goes on$'
        $ctx.MockState.Remove('RenewFails')
        $deadline = [datetime]::UtcNow.AddSeconds(10)
        while ([int]$beat.Failures -ne 0 -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $end = Stop-SIWorkItemLeaseBeat -Beat $beat
        $end.Failures | Should -Be 0 -Because 'the next renewal that works clears it'; $end.Lost | Should -BeFalse
        # NEGATIVE: the first renewal fails
        $ctx2 = New-PartQueue
        $m2 = Get-SINextWorkItem -Context $ctx2 -QueueName $script:Q -VisibilityTimeoutSeconds 30
        $ctx2.MockState['RenewFails'] = 'no sign-in'
        Start-SIWorkItemLeaseBeat -Context $ctx2 -QueueName $script:Q -WorkItem $m2 -LeaseSeconds 30 -BeatMs 200 -Quiet -ReadySeconds 20 | Should -BeNullOrEmpty
        Get-SIWorkItemLeaseBeatStartError | Should -Be 'its first renewal failed: no sign-in' -Because 'the caller''s line says why'
        Stop-SIWorkItemLeaseBeat -Beat $null | Should -BeNullOrEmpty
    }
}

Describe 'THE HEARTBEAT IN A CONTAINER: its own thread starts empty and must sign in by itself (the first live collection, 2026-10-13: no heartbeat started in any container)' {
    # The REAL code path -- a storage context that is not the Mock, the renewal over REST, the token of a managed identity --
    # in the heartbeat's own runspace, which loads only what the product gives it. The fake Azure (tests\fixtures\
    # SIPartLeaseFakeAzure.ps1) is loaded there last: it answers the HTTP seam and the identity endpoint's hook.
    BeforeAll {
        $script:Fake = Join-Path $script:SIRoot 'tests\fixtures\SIPartLeaseFakeAzure.ps1'
        $script:RealCtx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'stsi'; AzContext = $null; MockState = $null }
        $script:Item = [pscustomobject]@{ Id = 'msg-1'; PopReceipt = 'receipt-0'; RawText = '{"ShardIndex":0,"ShardCount":1}'; DequeueCount = 1 }
        $script:Identity = @{ Mode = 'ManagedIdentity'; ClientId = '11111111-2222-3333-4444-555555555555' }
        $script:SavedLog = [Environment]::GetEnvironmentVariable('SI_TEST_PARTLEASE_LOG')
    }
    BeforeEach {
        $script:Log = Join-Path $TestDrive ('calls-{0}.log' -f [guid]::NewGuid().ToString('N'))
        [Environment]::SetEnvironmentVariable('SI_TEST_PARTLEASE_LOG', $script:Log)
    }
    AfterAll { [Environment]::SetEnvironmentVariable('SI_TEST_PARTLEASE_LOG', $script:SavedLog) }
    It 'what the thread loads: the queue code, and the sign-in file the ENTRY POINT hands it -- a container that signs in with its managed identity hands over the managed-identity sign-in it loaded for its own thread' {
        $script:MiFile = Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1'
        @(Get-SIWorkItemLeaseBeatLibraries) | Should -Be @((Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')) -Because 'the engine code names no sign-in file itself (a VM never has the managed-identity one)'
        @(Get-SIWorkItemLeaseBeatLibraries -SignIn @($script:MiFile)) | Should -Be @((Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1'), $script:MiFile)
        Test-Path -LiteralPath $script:MiFile | Should -BeTrue
        # WIRING: the entry point loads that file for its own thread, and hands the same file to the heartbeat when it signs in with the managed identity
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match ([regex]::Escape('. /app/auth/SI-ManagedIdentity.ps1'))
        $src | Should -Match ([regex]::Escape('$beatSignIn = @(); if ($global:SI_UseManagedIdentity) { $beatSignIn = @(''/app/auth/SI-ManagedIdentity.ps1'') }'))
        $src | Should -Match ([regex]::Escape('-Auth $beatAuth -SignInLibraries $beatSignIn -What $partWhat -ExitOnLost'))
    }
    It 'THE CAUSE, REPRODUCED: a thread that loads only the queue code cannot sign in as a managed identity -- no heartbeat, and the reason is said in plain words' {
        $beat = Start-SIWorkItemLeaseBeat -Context $script:RealCtx -QueueName 'si-identity-shards' -WorkItem $script:Item -LeaseSeconds 600 -BeatMs 300 -Auth $script:Identity -Quiet -ReadySeconds 60 `
                    -SignInLibraries @($script:Fake)
        $beat | Should -BeNullOrEmpty -Because 'this is what every container did on 2026-10-13'
        Get-SIWorkItemLeaseBeatStartError | Should -Match '^its first renewal failed: .*the managed-identity sign-in helper is not loaded in this run'
        (Test-Path -LiteralPath $script:Log) | Should -BeFalse -Because 'it never got as far as the queue'
    }
    It 'THE FIX: handed the managed-identity sign-in, as the container''s entry point hands it, the heartbeat starts and renews the hold on the real queue path' {
        $beat = Start-SIWorkItemLeaseBeat -Context $script:RealCtx -QueueName 'si-identity-shards' -WorkItem $script:Item -LeaseSeconds 600 -BeatMs 300 -Auth $script:Identity -Quiet -ReadySeconds 60 `
                    -SignInLibraries @((Join-Path $script:SIRoot 'auth\SI-ManagedIdentity.ps1'), $script:Fake)
        $beat | Should -Not -BeNullOrEmpty -Because ('the heartbeat starts: ' + (Get-SIWorkItemLeaseBeatStartError))
        Get-SIWorkItemLeaseBeatStartError | Should -Be ''
        $deadline = [datetime]::UtcNow.AddSeconds(20)
        while ([int]$beat.Renewals -lt 3 -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $end = Stop-SIWorkItemLeaseBeat -Beat $beat
        $end.Renewals | Should -BeGreaterOrEqual 3; $end.Lost | Should -BeFalse; $end.Failures | Should -Be 0
        $end.PopReceipt | Should -Be ('receipt-{0}' -f $end.Renewals) -Because 'the newest receipt, the one the delete at the end needs'
        $calls = @([IO.File]::ReadAllLines($script:Log))
        $calls.Count | Should -Be $end.Renewals
        $calls[0] | Should -Match '^PUT https://stsi\.queue\.core\.windows\.net/si-identity-shards/messages/msg-1\?popreceipt=receipt-0&visibilitytimeout=600 \| Bearer identity-token \| <QueueMessage><MessageText>'
        $calls[1] | Should -Match 'popreceipt=receipt-1&visibilitytimeout=600' -Because 'every renewal is made with the receipt the one before it gave'
        $calls[2] | Should -Match 'popreceipt=receipt-2&'
    }
    It 'NEGATIVE: no sign-in handed to the thread at all -> no heartbeat, and the reason names the missing sign-in; a file the thread cannot load is named' {
        $beat = Start-SIWorkItemLeaseBeat -Context $script:RealCtx -QueueName 'si-identity-shards' -WorkItem $script:Item -BeatMs 300 -Quiet -ReadySeconds 60 `
                    -Libraries @(Get-SIWorkItemLeaseBeatLibraries)
        $beat | Should -BeNullOrEmpty
        Get-SIWorkItemLeaseBeatStartError | Should -Match '^its first renewal failed: .*No sign-in is configured'
        $missing = Join-Path $TestDrive 'not-there.ps1'
        Start-SIWorkItemLeaseBeat -Context $script:RealCtx -QueueName 'q' -WorkItem $script:Item -BeatMs 300 -Auth $script:Identity -Quiet -ReadySeconds 60 -Libraries @($missing) | Should -BeNullOrEmpty
        Get-SIWorkItemLeaseBeatStartError | Should -Match 'the heartbeat could not load its code \(.*not-there\.ps1\)'
    }
    It 'WITHOUT A HEARTBEAT the part is NOT held for the job''s run limit: one lease of 2 hours 5 minutes, and the worker''s line says why the heartbeat did not start' {
        Get-SIWorkItemFallbackLeaseSeconds | Should -Be 7500
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match ([regex]::Escape('$leaseSeconds = [Math]::Min($leaseSeconds, [int](Get-SIWorkItemFallbackLeaseSeconds))'))
        $min = $src.IndexOf('$leaseSeconds = [Math]::Min($leaseSeconds, [int](Get-SIWorkItemFallbackLeaseSeconds))')
        $use = $src.IndexOf('-VisibilityTimeoutSeconds $leaseSeconds -RawText ([string]$msg.RawText)')
        $min | Should -BeGreaterThan 0; $min | Should -BeLessThan $use -Because 'the lease is cut before it is taken'
        $src | Should -Match ([regex]::Escape('$beatWhy = [string](Get-SIWorkItemLeaseBeatStartError)'))
        $src | Should -Match ([regex]::Escape("could not be started -- {1}. The part is held with one lease of {2} minutes instead{3}; a worker that dies keeps it that long.' -f `$partWhat, `$beatWhy, [int](`$leaseSeconds / 60)"))
        # 7 days from setup (SI_QUEUE_LEASE_SECONDS = 604800) becomes 125 minutes; a shorter one from setup stays
        [Math]::Min(604800, [int](Get-SIWorkItemFallbackLeaseSeconds)) / 60 | Should -Be 125
        [Math]::Min(3900, [int](Get-SIWorkItemFallbackLeaseSeconds)) | Should -Be 3900
    }
}

Describe 'the renewal over REST: the storage queue''s Update Message' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
        $script:SavedTp = $global:SI_TokenProvider
        $global:SI_TokenProvider = { param($Resource) 'test-token' }
    }
    AfterAll { $global:SI_TokenProvider = $script:SavedTp }
    It 'PUT .../messages/<id>?popreceipt=..&visibilitytimeout=600 with the message text unchanged; the answer''s x-ms-popreceipt is the new receipt' {
        $script:Sent = $null
        Mock Invoke-SIAzRestHttp { $script:Sent = [pscustomobject]@{ Method = $Method; Uri = $Uri; Body = [string]$Body; Headers = $Headers; ContentType = $ContentType }
            [pscustomobject]@{ StatusCode = 204; Content = ''; Bytes = $null; Headers = @{ 'x-ms-popreceipt' = 'receipt-2'; 'x-ms-time-next-visible' = 'x' }; RetryAfter = $null } }
        $r = Update-SIQueueMessage -Account 'stsi' -Queue 'si-identity-shards' -MessageId 'm1' -PopReceipt 'rec/1+a=' -VisibilityTimeoutSeconds 600 -Text '{"ShardIndex":2,"a":"<b>"}'
        $r.Ok | Should -BeTrue; $r.Lost | Should -BeFalse; $r.PopReceipt | Should -Be 'receipt-2'
        $script:Sent.Method | Should -Be 'PUT'
        $script:Sent.Uri | Should -Be 'https://stsi.queue.core.windows.net/si-identity-shards/messages/m1?popreceipt=rec%2F1%2Ba%3D&visibilitytimeout=600'
        # the same encoding the message was sent with (Send-SIQueueMessage), so the text a later worker reads is unchanged
        $script:Sent.Body | Should -Be ('<QueueMessage><MessageText>{0}</MessageText></QueueMessage>' -f [System.Security.SecurityElement]::Escape('{"ShardIndex":2,"a":"<b>"}'))
        $script:Sent.Body | Should -Match '&lt;b&gt;'
        $script:Sent.Headers['Authorization'] | Should -Be 'Bearer test-token'
        $script:Sent.Headers['x-ms-version'] | Should -Not -BeNullOrEmpty
    }
    It 'LOST: 404 (the message is gone) and 400 PopReceiptMismatch (another worker holds it); anything else is "not known, try again" -- and nothing throws' {
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 404; Content = '<Error><Code>MessageNotFound</Code></Error>'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        $g = Update-SIQueueMessage -Account 'stsi' -Queue 'q' -MessageId 'm1' -PopReceipt 'r' -VisibilityTimeoutSeconds 600
        $g.Lost | Should -BeTrue; $g.Why | Should -Be 'the message is no longer in the queue'
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 400; Content = '<Error><Code>PopReceiptMismatch</Code><Message>The specified pop receipt did not match the pop receipt for a dequeued message.</Message></Error>'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        $m = Update-SIQueueMessage -Account 'stsi' -Queue 'q' -MessageId 'm1' -PopReceipt 'r' -VisibilityTimeoutSeconds 600
        $m.Lost | Should -BeTrue; $m.Why | Should -Be 'another worker holds the message now'
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 400; Content = '<Error><Code>InvalidQueryParameterValue</Code></Error>'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        $o = Update-SIQueueMessage -Account 'stsi' -Queue 'q' -MessageId 'm1' -PopReceipt 'r' -VisibilityTimeoutSeconds 600
        $o.Ok | Should -BeFalse; $o.Lost | Should -BeFalse -Because 'a refused request that does not say the part is held elsewhere is not a lost part'; $o.Why | Should -Match '^HTTP 400'
        Mock Invoke-SIAzRestHttp { [pscustomobject]@{ StatusCode = 403; Content = 'AuthorizationPermissionMismatch'; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        $f = Update-SIQueueMessage -Account 'stsi' -Queue 'q' -MessageId 'm1' -PopReceipt 'r' -VisibilityTimeoutSeconds 600
        $f.Ok | Should -BeFalse; $f.Lost | Should -BeFalse; $f.Why | Should -Match '403'
    }
}

Describe 'WIRING: the queue worker holds its part with the heartbeat' {
    BeforeAll { $script:Src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) }
    It 'the part is taken with the short lease, the heartbeat starts before the engine runs and ends before the part is deleted with the NEWEST receipt' {
        $script:Src | Should -Match ([regex]::Escape('Get-SINextWorkItem -Context $kctx -QueueName $queueName -VisibilityTimeoutSeconds $partLeaseSeconds'))
        $start = $script:Src.IndexOf('$partBeat = Start-SIWorkItemLeaseBeat')
        $run = $script:Src.IndexOf('& $orchestrator @orchArgs')
        $stop = $script:Src.IndexOf('$beatEnd = Stop-SIWorkItemLeaseBeat -Beat $partBeat')
        $del = $script:Src.IndexOf('Complete-SIWorkItem -Context $kctx -QueueName $queueName -Id $queueMessageId -PopReceipt $queueMessageReceipt')
        $start | Should -BeGreaterThan 0; $start | Should -BeLessThan $run
        $stop | Should -BeGreaterThan $run; $stop | Should -BeLessThan $del
        $script:Src | Should -Match ([regex]::Escape('if ($beatEnd.PopReceipt) { $queueMessageReceipt = [string]$beatEnd.PopReceipt }'))
        $script:Src | Should -Match '-What \$partWhat -ExitOnLost'
    }
    It 'a lost part is never marked done: the worker''s exit is set before the block that deletes the message and writes the DONE marker; without a heartbeat the long lease from setup is the fallback' {
        $lost = $script:Src.IndexOf('if ($orchExit -eq 0 -or $null -eq $orchExit) { $orchExit = 4 }')
        $done = $script:Src.IndexOf('-Marker (New-SICollectPartMarker -Part $shardIndex -State done')
        $lost | Should -BeGreaterThan 0; $lost | Should -BeLessThan $done
        $script:Src | Should -Match ([regex]::Escape('-VisibilityTimeoutSeconds $leaseSeconds -RawText ([string]$msg.RawText)'))
        $script:Src | Should -Match "SI_QUEUE_LEASE_SECONDS' 3900"
    }
}
