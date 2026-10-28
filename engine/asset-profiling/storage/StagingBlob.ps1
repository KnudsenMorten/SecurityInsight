#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- stage payload staging (Azure Blob, JSONL shards).

    Layout:
      staging/{runId}/{stage}/shard-NNN.jsonl

    Each collector worker writes its own shard -> zero write contention.
    Lifecycle policy on the storage account auto-deletes blobs older than
    7 days.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

. (Join-Path $PSScriptRoot 'StorageContext.ps1')

# in-process stage cache. In VM mode (single replica) the
# blob round-trip between every stage is pure overhead -- the next stage
# runs in the SAME process so it can read records from memory directly.
# Container mode (parallel replicas) bypasses this cache because each
# replica is a separate process and only sees its own writes.
# Triggered by $global:SI_SingleProcess = $true (set by VM-mode launcher).
if (-not (Get-Variable -Name SIStageCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SIStageCache = @{}    # key "<runid>|<stage>" -> @(records...)
}

function Test-SISingleProcessMode {
    [bool]$global:SI_SingleProcess
}

function Initialize-SIStagingContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [string]$ContainerName = 'sistaging'
    )

    if ($Context.Mode -eq 'Mock') {
        if (-not $Context.MockState.Blobs.ContainsKey($ContainerName)) {
            $Context.MockState.Blobs[$ContainerName] = @{}
        }
        return $ContainerName
    }

    $existing = Get-SIAzStorageContainer -Name $ContainerName -Context $Context.AzContext -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-SIAzStorageContainer -Name $ContainerName -Context $Context.AzContext -Permission Off | Out-Null
    }
    return $ContainerName
}

function Write-SIStageShard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][ValidateSet('Discover','Collect','Enrich','Classify','DiscoverRaw','DiscoverRouted')][string]$Stage,
        [Parameter(Mandatory)][int]$ShardIndex,
        [Parameter(Mandatory)][object[]]$Records,
        # replica namespace -- container parallelism>1 had multiple
        # replicas all writing 'shard-00000.jsonl' (collision -> data loss).
        # Default 0 = VM mode + single-replica container. Container parallelism
        # passes its CONTAINER_APP_JOB_REPLICA_INDEX so each replica's blobs
        # land under their own prefix.
        [int]$ReplicaIndex = 0
    )

    $blobName = 'staging/{0}/{1}/replica-{2:D3}/shard-{3:D5}.jsonl' -f $RunId, $Stage, $ReplicaIndex, $ShardIndex

    # VM-mode fast path. Single-process means the next stage
    # reads from this same process -- skip JSON serialization + blob upload
    # entirely. ~10-30x faster on 800-asset runs.
    if (Test-SISingleProcessMode) {
        # Keyed by BLOB NAME inside the stage, so a re-write of the same shard REPLACES it -- exactly what
        # the blob path does (an upload overwrites). It used to APPEND to one list per stage, so Profile
        # and Reconcile re-writing the Classify shard duplicated every record: 2 -> 4 -> 8 by Output.
        $cacheKey = '{0}|{1}' -f $RunId, $Stage
        if (-not $script:SIStageCache.ContainsKey($cacheKey)) {
            $script:SIStageCache[$cacheKey] = New-Object System.Collections.Specialized.OrderedDictionary
        }
        $list = New-Object System.Collections.ArrayList
        foreach ($r in $Records) { [void]$list.Add($r) }
        $script:SIStageCache[$cacheKey][$blobName] = $list
        return $blobName
    }

    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $Records) {
        [void]$sb.AppendLine(($r | ConvertTo-Json -Compress -Depth 8))
    }
    $jsonl = $sb.ToString()

    if ($Context.Mode -eq 'Mock') {
        $Context.MockState.Blobs[$ContainerName][$blobName] = $jsonl
        return $blobName
    }

    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        [System.IO.File]::WriteAllText($tmp, $jsonl, [System.Text.Encoding]::UTF8)
        Set-SIAzStorageBlobContent -Container $ContainerName -File $tmp -Blob $blobName -Context $Context.AzContext -Force -Verbose:$false | Out-Null
    }
    finally {
        Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
        $ProgressPreference = $prevProgress
    }
    return $blobName
}

function Read-SIStageShards {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Context,
        [Parameter(Mandatory)][string]$ContainerName,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][ValidateSet('Discover','Collect','Enrich','Classify','DiscoverRaw','DiscoverRouted')][string]$Stage,
        # per-replica reads. When >=0, narrows the prefix to that
        # replica's blobs only -- prevents 10x duplicate work in container
        # parallelism mode where each replica was reading every other replica's
        # output. Default -1 = read all replicas (single-replica + post-mortem
        # operator queries via Show-SIAICache use this).
        [int]$ReplicaIndex = -1,
        # #721: each record is handed to -OnRecord as it is read and NOT kept (the caller routes it on); returns nothing
        [scriptblock]$OnRecord
    )

    # VM-mode fast path -- pull records straight from in-process cache.
    if (Test-SISingleProcessMode) {
        $cacheKey = '{0}|{1}' -f $RunId, $Stage
        if ($script:SIStageCache.ContainsKey($cacheKey)) {
            # Same replica filter as the blob path below, applied to the cached blob names.
            $replicaPrefix = if ($ReplicaIndex -ge 0) { 'staging/{0}/{1}/replica-{2:D3}/' -f $RunId, $Stage, $ReplicaIndex } else { '' }
            $arr = New-Object System.Collections.ArrayList
            foreach ($bn in @($script:SIStageCache[$cacheKey].Keys)) {
                if ($replicaPrefix -and -not ([string]$bn).StartsWith($replicaPrefix)) { continue }
                foreach ($r in $script:SIStageCache[$cacheKey][$bn]) { if ($OnRecord) { & $OnRecord $r } else { [void]$arr.Add($r) } }
            }
            if ($OnRecord) { return }
            Write-SIInfo ('reading {0} {1}-stage records from in-process cache' -f $arr.Count, $Stage)
            return $arr.ToArray()
        }
        # Cache miss -- shouldn't happen in steady-state pipeline, but fall through
        # to blob read so we don't return empty just because the cache was cleared.
    }

    $prefix = if ($ReplicaIndex -ge 0) {
        'staging/{0}/{1}/replica-{2:D3}/' -f $RunId, $Stage, $ReplicaIndex
    } else {
        'staging/{0}/{1}/' -f $RunId, $Stage
    }

    if ($Context.Mode -eq 'Mock') {
        $records = New-Object System.Collections.ArrayList
        $matching = $Context.MockState.Blobs[$ContainerName].Keys | Where-Object { $_ -like "$prefix*" }
        foreach ($k in $matching) {
            foreach ($line in ($Context.MockState.Blobs[$ContainerName][$k] -split "`r?`n")) {
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                if ($OnRecord) { & $OnRecord ($line | ConvertFrom-Json) } else { [void]$records.Add(($line | ConvertFrom-Json)) }
            }
        }
        if ($OnRecord) { return }
        return $records.ToArray()
    }

    $records = New-Object System.Collections.ArrayList
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $blobs = @(Get-SIAzStorageBlob -Container $ContainerName -Prefix $prefix -Context $Context.AzContext -Verbose:$false)
        if ($blobs.Count -gt 0) {
            Write-SIInfo ('reading {0} {1}-stage shard blob(s) ...' -f $blobs.Count, $Stage)
        }
        foreach ($b in $blobs) {
            $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
            try {
                Get-SIAzStorageBlobContent -Container $ContainerName -Blob $b.Name -Destination $tmp -Context $Context.AzContext -Force -Verbose:$false | Out-Null
                foreach ($line in [System.IO.File]::ReadLines($tmp)) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    if ($OnRecord) { & $OnRecord ($line | ConvertFrom-Json); continue }
                    [void]$records.Add(($line | ConvertFrom-Json))
                }
            }
            finally {
                Remove-Item -Path $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        $ProgressPreference = $prevProgress
    }
    if ($OnRecord) { return }
    return $records.ToArray()
}

