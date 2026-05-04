#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- worker coordination (Azure Storage Queue).

    One queue per stage. Orchestrator enqueues shard work-items; collector
    workers dequeue with a visibility timeout (lease), do the work, then
    delete the message. Crashed workers' messages reappear after the lease
    expires (default 5 min).
#>

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

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

    $existing = Get-AzStorageQueue -Name $QueueName -Context $Context.AzContext -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-AzStorageQueue -Name $QueueName -Context $Context.AzContext | Out-Null
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
        })
        return
    }

    # Az.Storage 9+ exposes Azure.Storage.Queues.QueueClient (the v12 SDK).
    # The legacy CloudQueue path is gone in this version, so we use the
    # modern client directly.
    $queue = Get-AzStorageQueue -Name $QueueName -Context $Context.AzContext
    $queue.QueueClient.SendMessage($json) | Out-Null
}

function Get-SINextWorkItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$QueueName,
        # bumped from 300 -> 1800. Heavy collection shards (10k+
        # assets) routinely run 10-20 minutes; a 5-min visibility lease was
        # causing duplicate execution when the message reappeared on the queue
        # before the original worker finished.
        [int]$VisibilityTimeoutSeconds = 1800
    )

    if ($Context.Mode -eq 'Mock') {
        $list = $Context.MockState.Queues[$QueueName]
        if ($list.Count -eq 0) { return $null }
        $item = $list[0]
        $list.RemoveAt(0)
        return [pscustomobject]@{
            Id         = $item.Id
            PopReceipt = $item.PopReceipt
            Payload    = ($item.Payload | ConvertFrom-Json)
        }
    }

    $queue = Get-AzStorageQueue -Name $QueueName -Context $Context.AzContext
    $resp  = $queue.QueueClient.ReceiveMessage([TimeSpan]::FromSeconds($VisibilityTimeoutSeconds))
    if ($null -eq $resp -or $null -eq $resp.Value) { return $null }
    $msg = $resp.Value
    [pscustomobject]@{
        Id         = $msg.MessageId
        PopReceipt = $msg.PopReceipt
        Payload    = ($msg.MessageText | ConvertFrom-Json)
    }
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
        # Mock dequeue already removed the item; nothing to delete.
        return
    }

    $queue = Get-AzStorageQueue -Name $QueueName -Context $Context.AzContext
    $queue.QueueClient.DeleteMessage($Id, $PopReceipt) | Out-Null
}

