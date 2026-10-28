#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- worker coordination (Azure Storage Queue).

    One queue per stage. Orchestrator enqueues shard work-items; collector
    workers dequeue with a visibility timeout (lease), do the work, then
    delete the message.

    THE HOLD ON A PART IS SHORT AND RENEWED (2026-10-13). A worker takes a part for a SHORT lease (10 minutes) and a
    heartbeat on its own thread renews it every 2 minutes for as long as the worker process lives
    (Start-SIWorkItemLeaseBeat). A worker that dies -- out of memory, a platform restart -- stops renewing, and its part
    is back in the queue within one lease. Before, the lease was as long as the worker job's run limit and never renewed:
    with a run limit of days, a killed worker locked its part for days.
    A renewal the queue REFUSES (the part is held by another worker now, or it is gone) means this worker has lost the
    part: it stops at once and says so, so the part is never written twice. A renewal that merely fails (network,
    sign-in) is tried again on the next beat. A part handed out more than 5 times is still parked (Move-SIWorkItemToPoison).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

# this file, for the heartbeat's own thread (it loads it again there)
$script:SIWorkerQueueFile = Join-Path $PSScriptRoot 'WorkerQueue.ps1'
# WHAT THE HEARTBEAT'S THREAD LOADS. It is a second runspace: it starts EMPTY -- nothing the worker's entry point loaded is
# there. It must be able to sign in by itself, in every way a worker signs in:
#   a certificate / a secret -- SI-AzRest.ps1 (loaded with this file) loads what it needs by its own path.
#   a managed identity -- its sign-in (Get-SIManagedIdentityToken) is in a file of its own that ONLY THE ENTRY POINT
#                         loads (the engines never load it themselves: a VM never has it). So the entry point HANDS that
#                         file to the heartbeat: Start-SIWorkItemLeaseBeat -SignInLibraries. Without it the first renewal
#                         failed with "the managed-identity sign-in helper is not loaded in this run" and NO heartbeat
#                         started in any container (the first live collection, 2026-10-13).
$script:SIWorkItemLeaseBeatStartError = ''
function Get-SIWorkItemLeaseBeatLibraries {
    <# The files the heartbeat's thread loads, in order: this file (with SI-AzRest.ps1 and the storage context), then the
       sign-in files the worker's entry point hands over (-SignIn). #>
    param([string[]]$SignIn = @())
    # $PSScriptRoot here is this file's folder, wherever the function was dot-sourced into
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add((Join-Path $PSScriptRoot 'WorkerQueue.ps1'))
    foreach ($f in @($SignIn)) { if ("$f".Trim()) { $l.Add([string]$f) } }
    $l.ToArray()
}
function Get-SIWorkItemLeaseBeatStartError {
    <# Why the last Start-SIWorkItemLeaseBeat gave no heartbeat, in plain words ('' when it started). #>
    [string](Get-Variable -Name SIWorkItemLeaseBeatStartError -Scope Script -ValueOnly -ErrorAction Ignore)
}
# the ONE long lease a worker takes when its heartbeat cannot be started: 2 hours 5 minutes -- what a worker held its part
# with before the heartbeat existed (never the job's run limit, which is days now)
function Get-SIWorkItemFallbackLeaseSeconds { 7500 }
# the short lease on a part and how often it is renewed: five beats per lease
function Get-SIWorkItemLeaseSeconds { 600 }
function Get-SIWorkItemBeatSeconds { 120 }

function Get-SIMockQueueNow {
    <# The clock of a Mock queue: $Context.MockState.Now (a time a test sets, or a scriptblock) or the real time. #>
    param([Parameter(Mandatory)][object]$Context)
    $n = $Context.MockState['Now']
    if ($n -is [datetime]) { return $n.ToUniversalTime() }
    if ($n -is [scriptblock]) { return ([datetime](& $n)).ToUniversalTime() }
    [datetime]::UtcNow
}

function Initialize-SIQueue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName
    )

    if ($Context.Mode -eq 'Mock') {
        if (-not $Context.MockState.Queues.ContainsKey($QueueName)) {
            $Context.MockState.Queues[$QueueName] = New-Object System.Collections.ArrayList
        }
        return $QueueName
    }

    $existing = Get-SIAzStorageQueue -Name $QueueName -Context $Context.AzContext -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-SIAzStorageQueue -Name $QueueName -Context $Context.AzContext | Out-Null
    }
    return $QueueName
}

function Add-SIWorkItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        [Parameter(Mandatory)][hashtable]$Payload
    )

    $json = $Payload | ConvertTo-Json -Compress -Depth 6

    if ($Context.Mode -eq 'Mock') {
        [void]$Context.MockState.Queues[$QueueName].Add(@{
            Id      = [guid]::NewGuid().ToString()
            Payload = $json
            PopReceipt = [guid]::NewGuid().ToString()
            DequeueCount = 0
            VisibleAt = [datetime]::MinValue
        })
        return
    }

    # Az.Storage 9+ exposes Azure.Storage.Queues.QueueClient (the v12 SDK).
    # The legacy CloudQueue path is gone in this version, so we use the
    # modern client directly.
    $queue = Get-SIAzStorageQueue -Name $QueueName -Context $Context.AzContext
    $queue.QueueClient.SendMessage($json) | Out-Null
}

function Get-SINextWorkItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        # A SHORT lease: the worker renews it while it lives (Start-SIWorkItemLeaseBeat), so a worker that dies gives its
        # part back within one lease. (It used to be as long as the worker's run limit -- 7500 s, then hours and days --
        # because nothing renewed it: a shorter one let a second worker take a part that was still being written.)
        [int]$VisibilityTimeoutSeconds = 600
    )

    if ($Context.Mode -eq 'Mock') {
        # as the real queue: a handed-out item stays in the queue, hidden until its lease ends, with a new receipt
        $list = $Context.MockState.Queues[$QueueName]
        $now = Get-SIMockQueueNow -Context $Context
        $item = $null
        foreach ($i in @($list)) { if (-not $i.ContainsKey('VisibleAt') -or [datetime]$i.VisibleAt -le $now) { $item = $i; break } }
        if ($null -eq $item) { return $null }
        $item.DequeueCount = $(if ($item.ContainsKey('DequeueCount')) { [int]$item.DequeueCount + 1 } else { 1 })
        $item.PopReceipt = [guid]::NewGuid().ToString()
        $item.VisibleAt = $now.AddSeconds($VisibilityTimeoutSeconds)
        return [pscustomobject]@{
            Id           = $item.Id
            PopReceipt   = $item.PopReceipt
            Payload      = ($item.Payload | ConvertFrom-Json)
            RawText      = [string]$item.Payload
            DequeueCount = [int]$item.DequeueCount
        }
    }

    $queue = Get-SIAzStorageQueue -Name $QueueName -Context $Context.AzContext
    $resp  = $queue.QueueClient.ReceiveMessage([TimeSpan]::FromSeconds($VisibilityTimeoutSeconds))
    if ($null -eq $resp -or $null -eq $resp.Value) { return $null }
    $msg = $resp.Value
    [pscustomobject]@{
        Id           = $msg.MessageId
        PopReceipt   = $msg.PopReceipt
        Payload      = ($msg.MessageText | ConvertFrom-Json)
        RawText      = [string]$msg.MessageText
        # How many times this message has been handed out, this receipt included. A shard that
        # crashes its worker every time would otherwise be retried for ever (Move-SIWorkItemToPoison).
        DequeueCount = [int]$msg.DequeueCount
    }
}

function Update-SIWorkItemLease {
    <#
        RENEW the hold on a part this worker took: hidden from the other workers for -VisibilityTimeoutSeconds from now.
        NEVER THROWS. @{ Ok; Lost; PopReceipt; Why }:
          Ok    the hold is renewed -- PopReceipt is the NEW receipt (the old one is no longer valid; the delete at the
                end needs the newest)
          Lost  the queue refused: another worker holds the part now, or it is gone. This worker must stop that part.
          else  not known (network, sign-in): try again on the next beat.
        -RawText: the message text as it was received (it goes back unchanged). -Auth: the identity, for a second thread.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$PopReceipt,
        [int]$VisibilityTimeoutSeconds = 600,
        [AllowEmptyString()][string]$RawText = '',
        [hashtable]$Auth
    )
    try {
        if ($Context.Mode -eq 'Mock') {
            $fail = $Context.MockState['RenewFails']
            if ($fail) { return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = [string]$fail } }
            $item = $null
            foreach ($i in @($Context.MockState.Queues[$QueueName])) { if ([string]$i.Id -eq $Id) { $item = $i; break } }
            if ($null -eq $item) { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'the message is no longer in the queue' } }
            if ([string]$item.PopReceipt -ne $PopReceipt) { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'another worker holds the message now' } }
            $item.PopReceipt = [guid]::NewGuid().ToString()
            $item.VisibleAt = (Get-SIMockQueueNow -Context $Context).AddSeconds($VisibilityTimeoutSeconds)
            return [pscustomobject]@{ Ok = $true; Lost = $false; PopReceipt = [string]$item.PopReceipt; Why = '' }
        }
        return (Update-SIQueueMessage -Account ([string]$Context.AccountName) -Queue $QueueName -MessageId $Id -PopReceipt $PopReceipt -VisibilityTimeoutSeconds $VisibilityTimeoutSeconds -Text $RawText -Auth $Auth)
    } catch {
        return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = [string]$_.Exception.Message }
    }
}

# The heartbeat's loop, run on its own thread (a second runspace): it loads this file there, renews the hold at once (so
# the worker knows the heartbeat works before it starts the part) and then on every beat. It never throws.
$script:SIWorkItemLeaseLoopText = @'
param($b)
$loading = ''
try { foreach ($lib in @($b.Libraries)) { $loading = [string]$lib; . $loading } }
catch { $b.LastError = ('the heartbeat could not load its code ({0}): {1}' -f $loading, [string]$_.Exception.Message); $b.Ready.Set(); return }
$first = $true
while ($first -or -not $b.Wake.Wait([int]$b.BeatMs)) {
    try {
        $r = Update-SIWorkItemLease -Context $b.Context -QueueName ([string]$b.QueueName) -Id ([string]$b.Id) -PopReceipt ([string]$b.PopReceipt) `
                -VisibilityTimeoutSeconds ([int]$b.LeaseSeconds) -RawText ([string]$b.RawText) -Auth $b.Auth
        if ($r.Ok) {
            $b.PopReceipt = [string]$r.PopReceipt; $b.LastOkTicks = [datetime]::UtcNow.Ticks; $b.Renewals = [int]$b.Renewals + 1; $b.Failures = 0
        } elseif ($r.Lost) {
            $b.Lost = $true; $b.Why = [string]$r.Why
            $line = ('{0}: this worker no longer holds the part ({1}) -- it stops here, so the part is not written twice. The worker that holds it now finishes it.' -f [string]$b.What, [string]$r.Why)
            [void]$b.Lines.Add($line)
            if ($b.Console) { [Console]::Out.WriteLine('WARNING: [trigger] ' + $line); [Console]::Out.Flush() }
            if ($first) { $b.Ready.Set() }
            if ($b.ExitOnLost) { [Environment]::Exit([int]$b.ExitCode) }
            break
        } else {
            $b.Failures = [int]$b.Failures + 1; $b.LastError = [string]$r.Why
            if ([int]$b.Failures -eq 1 -or ([int]$b.Failures % 5) -eq 0) {
                $line = ('{0}: the hold on the part could not be renewed ({1}) -- trying again in {2} s; the worker goes on' -f [string]$b.What, [string]$r.Why, [int]([int]$b.BeatMs / 1000))
                [void]$b.Lines.Add($line)
                if ($b.Console) { [Console]::Out.WriteLine('WARNING: [trigger] ' + $line) }
            }
        }
    } catch { $b.Failures = [int]$b.Failures + 1; $b.LastError = [string]$_.Exception.Message }
    if ($first) { $first = $false; $b.Ready.Set() }
}
'@

function Start-SIWorkItemLeaseBeat {
    <#
        Starts the heartbeat that keeps this worker's hold on ONE part (-WorkItem, as Get-SINextWorkItem gave it): a second
        thread renews the lease (-LeaseSeconds) every -BeatSeconds, whatever the worker's own thread is doing -- one long
        call does not let the hold lapse. The first renewal is made at once and waited for (-ReadySeconds).
        Returns the beat (a synchronised table: PopReceipt = the newest receipt, Lost, Renewals, Failures, Lines), or
        $null when the heartbeat could not be started or its first renewal did not succeed -- the caller then holds the
        part with one longer lease, and Get-SIWorkItemLeaseBeatStartError says WHY in plain words.
        -ExitOnLost: a lost part ENDS THIS PROCESS with -ExitCode (the worker's own thread cannot be interrupted any other
        way); without it the caller reads .Lost (tests). -What: the words the lines start with ('part 3 of 8').
        -SignInLibraries: the sign-in files the worker's ENTRY POINT loaded for its own thread and the heartbeat's thread
        needs too (a container: the managed-identity sign-in). -Libraries: everything the thread loads (tests).
    #>
    param([Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$QueueName, [Parameter(Mandatory)]$WorkItem,
          [int]$LeaseSeconds = (Get-SIWorkItemLeaseSeconds), [int]$BeatSeconds = (Get-SIWorkItemBeatSeconds), [int]$BeatMs = 0,
          [hashtable]$Auth, [string]$What = 'the part', [switch]$ExitOnLost, [int]$ExitCode = 4, [switch]$Quiet, [int]$ReadySeconds = 90,
          [string[]]$SignInLibraries = @(), [string[]]$Libraries)
    $b = $null
    $script:SIWorkItemLeaseBeatStartError = ''
    if (-not $PSBoundParameters.ContainsKey('Libraries')) { $Libraries = @(Get-SIWorkItemLeaseBeatLibraries -SignIn $SignInLibraries) }
    try {
        if ($BeatMs -le 0) { $BeatMs = [Math]::Max(1, $BeatSeconds) * 1000 }
        $b = [hashtable]::Synchronized(@{
            Libraries = @($Libraries); Context = $Context; QueueName = $QueueName; Id = [string]$WorkItem.Id; PopReceipt = [string]$WorkItem.PopReceipt
            RawText = [string]$WorkItem.RawText; LeaseSeconds = $LeaseSeconds; BeatMs = $BeatMs; Auth = $Auth; What = $What
            ExitOnLost = [bool]$ExitOnLost; ExitCode = $ExitCode; Console = (-not $Quiet)
            Lost = $false; Why = ''; Renewals = 0; Failures = 0; LastError = ''; LastOkTicks = [long]0
            Lines = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            Wake = (New-Object System.Threading.ManualResetEventSlim($false)); Ready = (New-Object System.Threading.ManualResetEventSlim($false)) })
        $ps = [powershell]::Create()
        $null = $ps.AddScript($script:SIWorkItemLeaseLoopText).AddArgument($b)
        $b['PowerShell'] = $ps
        $b['Handle'] = $ps.BeginInvoke()
        $ready = $b.Ready.Wait([Math]::Max(1, $ReadySeconds) * 1000)
        if ($b.Lost) { return $b }                      # the caller reads .Lost (with -ExitOnLost the process has ended)
        if ([int]$b.Renewals -lt 1) {
            $why = ([string]$b.LastError -replace '\s+', ' ').Trim()
            if (-not $ready) { $why = ('its first renewal gave no answer within {0} s{1}' -f $ReadySeconds, $(if ($why) { ' (' + $why + ')' } else { '' })) }
            elseif (-not $why) { $why = 'its first renewal did not succeed and gave no reason' }
            else { $why = 'its first renewal failed: ' + $why }
            if ($why.Length -gt 400) { $why = $why.Substring(0, 397) + '...' }
            $script:SIWorkItemLeaseBeatStartError = $why
            $null = Stop-SIWorkItemLeaseBeat -Beat $b -WaitSeconds 10
            return $null
        }
        return $b
    } catch {
        $script:SIWorkItemLeaseBeatStartError = ('its thread could not be started: {0}' -f [string]$_.Exception.Message)
        if ($b) { try { $null = Stop-SIWorkItemLeaseBeat -Beat $b -WaitSeconds 10 } catch { } }
        return $null
    }
}

function Stop-SIWorkItemLeaseBeat {
    <#
        Ends a heartbeat (Start-SIWorkItemLeaseBeat) and waits for a renewal that is under way, so the receipt it answers
        with is the newest. Returns @{ PopReceipt; Lost; Why; Renewals; Failures; Settled } -- Settled = $false when the
        heartbeat's thread did not end in time (the receipt may then be stale). Never throws; $null = nothing to end.
    #>
    param($Beat, [int]$WaitSeconds = 75)
    if ($null -eq $Beat) { return $null }
    $settled = $false
    try { $Beat.Wake.Set() } catch { }
    try { if ($Beat.Handle -and $Beat.Handle.AsyncWaitHandle.WaitOne([Math]::Max(1, $WaitSeconds) * 1000)) { $settled = $true; $null = $Beat.PowerShell.EndInvoke($Beat.Handle) } } catch { }
    try { if ($settled) { $Beat.PowerShell.Dispose() } } catch { }
    [pscustomobject]@{ PopReceipt = [string]$Beat.PopReceipt; Lost = [bool]$Beat.Lost; Why = [string]$Beat.Why; Renewals = [int]$Beat.Renewals; Failures = [int]$Beat.Failures; Settled = $settled }
}

function Move-SIWorkItemToPoison {
    <#
        Park a work item that keeps failing in '<queue>-poison' and remove it from the work queue.
        Parked, not dropped: the original message text is kept verbatim (plus why and when), so the
        shard can be re-queued once the cause is fixed. The poison copy is written BEFORE the original
        is deleted -- if the write fails, the original stays on the queue and nothing is lost.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        [Parameter(Mandatory)][object]$WorkItem,
        [string]$Reason = 'exceeded the maximum number of attempts'
    )
    $poisonName = '{0}-poison' -f $QueueName
    Initialize-SIQueue -Context $Context -QueueName $poisonName | Out-Null
    Add-SIWorkItem -Context $Context -QueueName $poisonName -Payload @{
        OriginalQueue = $QueueName
        OriginalText  = [string]$WorkItem.RawText
        DequeueCount  = [int]$WorkItem.DequeueCount
        Reason        = $Reason
        ParkedAtUtc   = [datetime]::UtcNow.ToString('o')
    }
    Complete-SIWorkItem -Context $Context -QueueName $QueueName -Id $WorkItem.Id -PopReceipt $WorkItem.PopReceipt
    return $poisonName
}

function Complete-SIWorkItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$PopReceipt
    )

    if ($Context.Mode -eq 'Mock') {
        # as the real queue: the item is removed with the receipt of the worker that holds it; a stale receipt is refused
        $list = $Context.MockState.Queues[$QueueName]
        $item = $null
        foreach ($i in @($list)) { if ([string]$i.Id -eq $Id) { $item = $i; break } }
        if ($null -eq $item) { return }
        if ([string]$item.PopReceipt -ne $PopReceipt) { throw 'PopReceiptMismatch: the message is held with another receipt' }
        [void]$list.Remove($item)
        return
    }

    $queue = Get-SIAzStorageQueue -Name $QueueName -Context $Context.AzContext
    $queue.QueueClient.DeleteMessage($Id, $PopReceipt) | Out-Null
}
