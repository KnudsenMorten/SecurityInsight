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

$global:SI_StorageAccount      = Get-RequiredEnv 'SI_STORAGE_ACCOUNT'
$global:SI_WorkspaceResourceId = Get-RequiredEnv 'SI_WORKSPACE_RESOURCEID'
$global:SI_UAMI_ClientId       = Get-OptionalEnv 'SI_UAMI_CLIENTID' $null

# Connect-AzAccount -- queues access needs context regardless of OAuth/Key.
$subId = ($global:SI_WorkspaceResourceId -split '/')[2]
if ($global:SI_UAMI_ClientId) {
    Connect-AzAccount -Identity -AccountId $global:SI_UAMI_ClientId -Subscription $subId | Out-Null
} else {
    # v2.3 single-SPN model. SI_SPN_* are the primary env names;
    # SI_GRAPH_* fall back for legacy callers still pinned to preview-25 bootstrap.
    $appId    = Get-OptionalEnv 'SI_SPN_APPID'    (Get-OptionalEnv 'SI_GRAPH_APPID')
    $secret   = Get-OptionalEnv 'SI_SPN_SECRET'   (Get-OptionalEnv 'SI_GRAPH_SECRET')
    $tenantId = Get-OptionalEnv 'SI_SPN_TENANTID' (Get-OptionalEnv 'SI_GRAPH_TENANTID')
    if (-not $appId -or -not $secret -or -not $tenantId) { throw "Producer requires SI_SPN_APPID + SI_SPN_SECRET + SI_SPN_TENANTID (or SI_GRAPH_* legacy aliases)" }
    $secureStr = ConvertTo-SecureString $secret -AsPlainText -Force
    $cred      = New-Object System.Management.Automation.PSCredential($appId, $secureStr)
    Connect-AzAccount -ServicePrincipal -Tenant $tenantId -Credential $cred -Subscription $subId | Out-Null
}

. /app/engine/asset-profiling/storage/StorageContext.ps1
. /app/engine/asset-profiling/storage/WorkerQueue.ps1

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
