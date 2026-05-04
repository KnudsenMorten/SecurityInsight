#Requires -Version 7.0
<#
    Producer entrypoint for the KEDA queue-driven worker pattern.

    Runs in the cron-triggered Container App Job 'caj-si-{engine}-producer'.
    Mints a single CollectionTime + pushes one message per shard onto the
    'si-{engine}-shards' queue. KEDA polls that queue and spins up worker
    replicas based on backlog -- idle = 0 replicas, billing = vCPU-seconds
    actually consumed.

    Required env vars (same SET as Start-SIInContainer.ps1, minus OpenAI
    which the worker needs but the producer doesn't):
      SI_ENGINE                -- 'endpoint' | 'identity' | 'azure'
      SI_STORAGE_ACCOUNT       -- queue host
      SI_STORAGE_KEY           -- only when not in UAMI mode
      SI_UAMI_CLIENTID         -- when in UAMI mode (preferred)
      SI_SHARD_COUNT           -- number of shards to enqueue (== worker
                                  parallelism cap)

    Worker side: each replica reads ONE message, extracts ShardIndex +
    ShardCount + CollectionTime, runs the full pipeline for that shard,
    then deletes the message on success.
#>

$ErrorActionPreference = 'Stop'

function Get-RequiredEnv {
    param([Parameter(Mandatory)][string]$Name)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { throw "Required env var $Name is missing" }
    return $v
}

function Get-OptionalEnv {
    param([string]$Name, $Default = $null)
    $v = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v
}

$engine     = Get-RequiredEnv 'SI_ENGINE'
$shardCount = [int](Get-OptionalEnv 'SI_SHARD_COUNT' 1)
if ($shardCount -lt 1) { $shardCount = 1 }

$global:SI_StorageAccount = Get-RequiredEnv 'SI_STORAGE_ACCOUNT'
$global:SI_UAMI_ClientId   = Get-OptionalEnv 'SI_UAMI_CLIENTID' $null

# Connect-AzAccount -- queues access needs context regardless of OAuth/Key.
$subId = ($global:SI_WorkspaceResourceId -split '/')[2]
if ($global:SI_UAMI_ClientId) {
    Connect-AzAccount -Identity -AccountId $global:SI_UAMI_ClientId | Out-Null
} else {
    $secure = ConvertTo-SecureString (Get-RequiredEnv 'SI_GRAPH_SECRET') -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential((Get-RequiredEnv 'SI_GRAPH_APPID'), $secure)
    Connect-AzAccount -ServicePrincipal -Tenant (Get-RequiredEnv 'SI_GRAPH_TENANTID') -Credential $cred | Out-Null
}

. /app/v2.2/engine/asset-profiling/storage/StorageContext.ps1
. /app/v2.2/engine/asset-profiling/storage/WorkerQueue.ps1

# Storage context: prefer OAuth via UAMI; fall back to shared key.
if ($global:SI_UAMI_ClientId) {
    $ctx = New-SIStorageContext -AccountName $global:SI_StorageAccount -UseOAuth
} else {
    $ctx = New-SIStorageContext -AccountName $global:SI_StorageAccount -AccountKey (Get-RequiredEnv 'SI_STORAGE_KEY')
}

$queueName = ('si-{0}-shards' -f $engine)
Initialize-SIQueue -Context $ctx -QueueName $queueName | Out-Null

# CollectionTime: ONE value, stamped onto every shard message. All workers
# inherit and emit it on every classified row -- KQL's
# "where CollectionTime == max(CollectionTime)" then returns the full set
# from this one execution.
$now = [datetime]::UtcNow
$collectionTime = [datetime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0, [DateTimeKind]::Utc)
$collectionTimeStr = $collectionTime.ToString('o')

Write-Host '======================================================================'
Write-Host (' SecurityInsight v2.2 Producer -- engine={0}  CollectionTime={1}' -f $engine, $collectionTimeStr)
Write-Host (' shards: {0}  -- queue: {1}' -f $shardCount, $queueName)
Write-Host '======================================================================'

for ($i = 0; $i -lt $shardCount; $i++) {
    $payload = @{
        ShardIndex     = $i
        ShardCount     = $shardCount
        CollectionTime = $collectionTimeStr
        EnqueuedAt     = ([datetime]::UtcNow.ToString('o'))
    }
    Add-SIWorkItem -Context $ctx -QueueName $queueName -Payload $payload
    Write-Host ('  -> shard {0}/{1} enqueued' -f ($i+1), $shardCount)
}

Write-Host ('Done. {0} messages on {1}. KEDA will scale workers within ~30s.' -f $shardCount, $queueName)
