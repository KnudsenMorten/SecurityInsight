#Requires -Version 7.0
<#
    Container entrypoint for the SecurityInsight v2.2 orchestrator.

    Reads configuration from environment variables (Container App Job
    secrets are surfaced as env vars), populates the matching $global:*
    names the engine code expects, then dispatches to Invoke-SIEngineRun.ps1.

    Required env vars:
      SI_ENGINE                   -- 'endpoint' or 'identity'
      SI_STORAGE_ACCOUNT          -- v2.2 transient-state storage account
      SI_STORAGE_KEY              -- storage account key (Container App secret)
      SI_GRAPH_APPID              -- Graph SPN app id
      SI_GRAPH_SECRET             -- Graph SPN secret (Container App secret)
      SI_GRAPH_TENANTID           -- Entra tenant id

      SI_LOGINGEST_APPID          -- LogIngest SPN app id
      SI_LOGINGEST_SECRET         -- LogIngest SPN secret (Container App secret)
      SI_LOGINGEST_TENANTID       -- Entra tenant id (often same as Graph tenant)
      SI_LOGINGEST_OBJECTID       -- LogIngest SPN object id (for DCR perms)

      SI_WORKSPACE_RESOURCEID     -- target Log Analytics workspace
      SI_DCE_NAME                 -- Data Collection Endpoint name
      SI_DCR_RESOURCEGROUP        -- DCR resource group

      OPENAI_APIKEY               -- Azure OpenAI key (Container App secret)
      OPENAI_ENDPOINT             -- Azure OpenAI endpoint
      OPENAI_DEPLOYMENT           -- deployment name
      OPENAI_APIVERSION           -- API version
      MAX_AI_SPEND_PER_RUN        -- USD ceiling per run (default 4)

    Optional:
      SI_ASSET_LIMIT              -- if set + > 0, slice discovery to N assets
      SI_SINKS                    -- comma-separated, default 'JSON,Excel,LA'
#>

$ErrorActionPreference = 'Stop'

# ----------- SI_ROLE dispatcher ---------------------------------------
# Container App Job '--command' / '--args' overrides are unreliable in az CLI
# (argparse nargs='+' chokes on leading-dash PowerShell flags). Instead, every
# job in the v2.2 fleet uses the default ENTRYPOINT (this script) and dispatches
# on $env:SI_ROLE. SI_ROLE defaults to 'worker' so legacy single-job-per-engine
# (non-KEDA) deployments keep working unchanged.
$siRole = [Environment]::GetEnvironmentVariable('SI_ROLE')
if ($siRole) {
    switch ($siRole.ToLowerInvariant()) {
        'producer' {
            $producerScript = '/app/container/Invoke-ShardProducer.ps1'
            Write-Host "[SI_ROLE=producer] dispatching to $producerScript" -ForegroundColor Cyan
            & pwsh -NoProfile -File $producerScript
            exit $LASTEXITCODE
        }
        'ra' {
            $raScript = '/app/container/Start-RiskAnalysisInContainer.ps1'
            Write-Host "[SI_ROLE=ra] dispatching to $raScript" -ForegroundColor Cyan
            & pwsh -NoProfile -File $raScript
            exit $LASTEXITCODE
        }
        'worker' {
            # Engine-aware dispatch within the worker role. Most engines
            # (endpoint/identity/azure/publicip) go through Invoke-SIEngineRun.
            # privilege-tier-classifier has its own orchestrator (different
            # input/output shape -- no per-asset profiling pipeline).
            $engineEnv = [Environment]::GetEnvironmentVariable('SI_ENGINE')
            if ($engineEnv -eq 'privilege-tier-classifier') {
                $classifierScript = '/app/engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1'
                Write-Host "[SI_ROLE=worker SI_ENGINE=privilege-tier-classifier] dispatching to $classifierScript" -ForegroundColor Cyan
                . '/app/config/SecurityInsight.custom.ps1'   # hydrate engine globals (same VM-launcher parity)
                $global:SI_CustomConfigPath = '/app/config/SecurityInsight.custom.ps1'
                # In-process call (NOT `& pwsh -File`) -- child pwsh would lose
                # all the $global:* state we just hydrated from custom.ps1.
                & $classifierScript
                exit $LASTEXITCODE
            }
            # else: fall through to legacy worker path below (Invoke-SIEngineRun)
        }
        default  { throw "Unknown SI_ROLE '$siRole' -- expected one of: worker | producer | ra" }
    }
}

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

# Engine + sinks
$engine     = Get-RequiredEnv 'SI_ENGINE'
$assetLimit = [int](Get-OptionalEnv 'SI_ASSET_LIMIT' 0)
$sinksCsv   = Get-OptionalEnv 'SI_SINKS' 'JSON,Excel,LA'
$sinks      = $sinksCsv.Split(',') | ForEach-Object { $_.Trim() }

# Storage (for v2.2 fingerprint cache + staging + queues)
$global:SI_StorageAccount = Get-RequiredEnv 'SI_STORAGE_ACCOUNT'

# SPN-secret is the only supported auth path. UAMI path is
# kept behind $global:SI_PreferUami for legacy single-tenant deployments.
# Container env vars: SI_SPN_APPID / SECRET / TENANTID / OBJECTID
# (single SPN handles BOTH Graph reads AND LA ingest).
$global:SI_SPN_AppId    = Get-RequiredEnv 'SI_SPN_APPID'
$global:SI_SPN_Secret   = Get-RequiredEnv 'SI_SPN_SECRET'
$global:SI_SPN_TenantId = Get-RequiredEnv 'SI_SPN_TENANTID'
$global:SI_SPN_ObjectId = Get-RequiredEnv 'SI_SPN_OBJECTID'

# Backwards-compat aliases for 25 callers (Get-SIGraphToken's
# older path, Stage Output's older path, etc.). New code reads SI_SPN_*
# directly but old code paths still work via these aliases.
$global:SI_Graph_AppId        = $global:SI_SPN_AppId
$global:SI_Graph_Secret       = $global:SI_SPN_Secret
$global:SI_Graph_TenantId     = $global:SI_SPN_TenantId
$global:SI_LogIngest_AppId    = $global:SI_SPN_AppId
$global:SI_LogIngest_Secret   = $global:SI_SPN_Secret
$global:SI_LogIngest_TenantId = $global:SI_SPN_TenantId
$global:SI_LogIngest_ObjectId = $global:SI_SPN_ObjectId

# Storage: shared key always (SPN-secret mode doesn't OAuth).
$global:SI_StorageKey = Get-RequiredEnv 'SI_STORAGE_KEY'
$useStorageOAuth = $false

# Optional UAMI override (legacy / single-tenant). Off by default.
$global:SI_UAMI_ClientId = Get-OptionalEnv 'SI_UAMI_CLIENTID' $null
$global:SI_PreferUami    = (Get-OptionalEnv 'SI_PREFER_UAMI' '0') -in '1','true','True','yes'

if ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) {
    Write-Host ('[auth] $SI_PreferUami=1 + SI_UAMI_CLIENTID set -- UAMI path enabled (legacy mode).')
} else {
    Write-Host '[auth] SPN-secret mode.'
}

# Workspace + DCE/DCR target
$global:SI_WorkspaceResourceId = Get-RequiredEnv 'SI_WORKSPACE_RESOURCEID'
$global:SI_DceName             = Get-RequiredEnv 'SI_DCE_NAME'
$global:SI_DcrResourceGroup    = Get-RequiredEnv 'SI_DCR_RESOURCEGROUP'

# OpenAI for Stage Classify
$global:OpenAI_apiKey     = Get-RequiredEnv 'OPENAI_APIKEY'
$global:OpenAI_endpoint   = Get-RequiredEnv 'OPENAI_ENDPOINT'
$global:OpenAI_deployment = Get-RequiredEnv 'OPENAI_DEPLOYMENT'
$global:OpenAI_apiVersion = Get-RequiredEnv 'OPENAI_APIVERSION'
$global:MaxAiSpendPerRun  = [double](Get-OptionalEnv 'MAX_AI_SPEND_PER_RUN' '4')

# Connect-AzAccount -- needed by Az.Storage / Az.Monitor / Az.ResourceGraph
# cmdlets called by Stage Output + Stage Discover.
$subId = ($global:SI_WorkspaceResourceId -split '/')[2]
if ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) {
    Connect-AzAccount -Identity -AccountId $global:SI_UAMI_ClientId -Subscription $subId | Out-Null
} else {
    $secure = ConvertTo-SecureString $global:SI_SPN_Secret -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential($global:SI_SPN_AppId, $secure)
    Connect-AzAccount -ServicePrincipal -Tenant $global:SI_SPN_TenantId -Credential $cred -Subscription $subId | Out-Null
}

Write-Host '======================================================================'
Write-Host (' SecurityInsight v2.2 in container -- engine={0}  ts={1}' -f $engine, ([datetime]::UtcNow.ToString('o')))
Write-Host '======================================================================'

# Sharding mode: SCHEDULED (default) vs KEDA-event-driven.
#
# Scheduled: Container Apps Job sets CONTAINER_APP_JOB_REPLICA_INDEX (0..N-1)
#            automatically when --parallelism > 1. SI_SHARD_COUNT matches
#            --parallelism (set by Bootstrap).
#
# KEDA event-driven: SI_TRIGGER_FROM_QUEUE=1 tells the worker to read its
# shard descriptor (ShardIndex, ShardCount, CollectionTime) from the
# 'si-{engine}-shards' queue. Each worker replica processes exactly ONE
# message and exits, so KEDA's queue-length scaler matches replica count
# to backlog naturally.
$useQueue   = (Get-OptionalEnv 'SI_TRIGGER_FROM_QUEUE' '0') -eq '1'
$shardCount = [int](Get-OptionalEnv 'SI_SHARD_COUNT' 1)
$shardIndex = [int](Get-OptionalEnv 'CONTAINER_APP_JOB_REPLICA_INDEX' 0)
$queueMessageId    = $null
$queueMessageReceipt = $null
$queueName         = $null

if ($useQueue) {
    Write-Host '[trigger] KEDA event mode -- pulling shard descriptor from queue.'
    . /app/engine/asset-profiling/storage/StorageContext.ps1
    . /app/engine/asset-profiling/storage/WorkerQueue.ps1
    if ($global:SI_UAMI_ClientId) {
        $kctx = New-SIStorageContext -AccountName $global:SI_StorageAccount -UseOAuth
    } else {
        $kctx = New-SIStorageContext -AccountName $global:SI_StorageAccount -AccountKey $global:SI_StorageKey
    }
    $queueName = ('si-{0}-shards' -f $engine)
    Initialize-SIQueue -Context $kctx -QueueName $queueName | Out-Null

    $msg = Get-SINextWorkItem -Context $kctx -QueueName $queueName -VisibilityTimeoutSeconds 1800
    if (-not $msg) {
        Write-Host '[trigger] queue empty -- nothing to do, exiting cleanly.'
        exit 0
    }
    $queueMessageId    = $msg.Id
    $queueMessageReceipt = $msg.PopReceipt
    $shardIndex        = [int]$msg.Payload.ShardIndex
    $shardCount        = [int]$msg.Payload.ShardCount
    $collectionFromMsg = $msg.Payload.CollectionTime
    [Environment]::SetEnvironmentVariable('SI_COLLECTION_TIME', $collectionFromMsg)
    Write-Host ('[trigger] shard {0}/{1}  CollectionTime={2}' -f ($shardIndex+1), $shardCount, $collectionFromMsg)
}

# Cross-shard CollectionTime sync. Three sources, in priority:
#   1. SI_COLLECTION_TIME -- producer (KEDA pattern) sets per execution; all
#      worker replicas read the same value. ISO-8601 UTC.
#   2. CONTAINER_APP_JOB_EXECUTION_NAME present + parseable timestamp prefix
#      (Azure auto-injects this; identical across replicas of one execution).
#      Currently the name doesn't embed a timestamp, so we skip this and let
#      the orchestrator floor-to-minute internally.
#   3. Orchestrator's own floor-to-minute fallback (set inside the script).
$collectionTime = $null
$ctRaw = Get-OptionalEnv 'SI_COLLECTION_TIME' $null
if ($ctRaw) {
    try {
        $collectionTime = [datetime]::Parse($ctRaw, $null,
                            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor `
                            [System.Globalization.DateTimeStyles]::AssumeUniversal)
        Write-Host ('[collection] inherited SI_COLLECTION_TIME={0:o} (cross-shard sync)' -f $collectionTime)
    } catch {
        Write-Warning ('[collection] SI_COLLECTION_TIME unparseable ({0}) -- orchestrator will floor-to-minute' -f $ctRaw)
    }
}

# v2.3 -- dot-source customer custom.ps1 BEFORE invoking the engine.
# The engine reads ~30 $global:SI_* settings (RA report templates, sink lists,
# AssetLimit, AI flags, KV pulls, etc) that the VM launcher gets via custom.ps1.
# Without this dot-source, the container worker had a different global state
# than the VM launcher and the engine threw on missing -Path values mid-pipeline.
# COPY . /app/ in the Dockerfile means the customer's config/SecurityInsight.custom.ps1
# is at /app/config/SecurityInsight.custom.ps1 already.
$customCfg = '/app/config/SecurityInsight.custom.ps1'
if (Test-Path -LiteralPath $customCfg) {
    Write-Host ('[config] dot-sourcing {0} (VM-launcher parity)' -f $customCfg) -ForegroundColor Cyan
    . $customCfg
    # Also pin SI_CustomConfigPath so Invoke-SIEngineRun.ps1's auto-derive
    # (3x Split-Path from $PSScriptRoot) doesn't fall off /app/'s root in
    # the flattened container layout (no v2.2/ prefix).
    $global:SI_CustomConfigPath = $customCfg
} else {
    Write-Warning ('[config] {0} NOT FOUND -- engine will run with env-only globals (may throw on missing Path)' -f $customCfg)
}

$orchestrator = '/app/engine/asset-profiling/Invoke-SIEngineRun.ps1'
$orchArgs = @{
    Engine             = $engine
    StorageAccountName = $global:SI_StorageAccount
    Sinks              = $sinks
    AssetLimit         = $assetLimit
    ShardCount         = $shardCount
    ShardIndex         = $shardIndex
}
if ($collectionTime) { $orchArgs['CollectionTime'] = $collectionTime }
if ((Get-OptionalEnv 'SI_FORCE_FULL_RUN' '0') -in '1','true','True','yes') {
    $orchArgs['ForceFullRun'] = $true
    Write-Host '[trigger] SI_FORCE_FULL_RUN=1 -- bypassing fingerprint cache for this execution'
}
if ($useStorageOAuth) {
    $orchArgs['UseStorageOAuth'] = $true
} else {
    $orchArgs['StorageAccountKey'] = $global:SI_StorageKey
}

$orchExit = 0
try {
    & $orchestrator @orchArgs
    $orchExit = $LASTEXITCODE
} catch {
    Write-Warning ('orchestrator threw: {0}' -f $_.Exception.Message)
    if ($_.InvocationInfo) { Write-Warning ('  at: {0}' -f $_.InvocationInfo.PositionMessage.Trim()) }
    if ($_.ScriptStackTrace) { Write-Warning ('  stack:'); $_.ScriptStackTrace -split "`n" | ForEach-Object { Write-Warning ('    {0}' -f $_) } }
    $orchExit = 1
}

# KEDA mode: delete the queue message ONLY on clean orchestrator exit.
# Failures leave the message visible after VisibilityTimeout expires so
# KEDA spins up a fresh worker to retry. Container App Job's
# replica-retry-limit handles immediate retry within the same execution.
if ($useQueue -and $queueMessageId -and ($orchExit -eq 0 -or $null -eq $orchExit)) {
    try {
        Complete-SIWorkItem -Context $kctx -QueueName $queueName -Id $queueMessageId -PopReceipt $queueMessageReceipt
        Write-Host ('[trigger] shard message deleted (success).')
    } catch {
        Write-Warning ('[trigger] could not delete shard message: {0}' -f $_.Exception.Message)
    }
}
if ($orchExit -gt 0) { exit $orchExit }
