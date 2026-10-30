#Requires -Version 7.0
<#
    Container entrypoint for the SecurityInsight v2.2 orchestrator.

    Reads configuration from environment variables (Container App Job
    secrets are surfaced as env vars), populates the matching $global:*
    names the engine code expects, then dispatches to Invoke-SIEngineRun.ps1.

    Required env vars:
      SI_ENGINE                   -- 'endpoint' or 'identity'
      SI_STORAGE_ACCOUNT          -- v2.2 transient-state storage account (reached with the job's identity)
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

    Sign-in (#209), first that applies:
      SI_UAMI_CLIENTID (+ the job's IDENTITY_ENDPOINT)  -- the job's user-assigned managed identity
      SI_SPN_CERT_PFX_B64 (+ SI_SPN_APPID/TENANTID)     -- the SPN by certificate (Key Vault reference)
      SI_SPN_SECRET (+ SI_SPN_APPID/TENANTID/OBJECTID)  -- the SPN by client secret (Community default)

    Optional (each wins only when present; absent, the VM setting SI_AssetLimit_<Engine> / SI_Sinks_<Engine> /
    SI_ForceFullRun_<Engine> applies, then the VM default):
      SI_ASSET_LIMIT              -- if set + > 0, slice discovery to N assets
      SI_SINKS                    -- comma-separated, default 'JSON,Excel,LA'
      SI_FORCE_FULL_RUN           -- '1' bypasses the fingerprint cache for one execution
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }

$ErrorActionPreference = 'Stop'

# ---- #55.1: run transcripts on the container host ----
# The transcript helper has been default-on since v2.2.312 and 15 VM launchers
# call it -- no container entrypoint ever did, so the host recommended for large
# tenants was the only one that left no forensic record. Both helpers are
# dot-sourced before the SI_ROLE dispatcher so every branch below can reach them.
#
# One transcript per PROCESS, started by whichever script does the actual work:
# the 'producer' and 'ra' branches below hand off to a child pwsh that starts its
# own, so starting one here as well would produce two files for one run, the
# outer one a duplicate of the inner.
. /app/launcher/_lib/Start-LauncherTranscript.ps1
. /app/launcher/_lib/Publish-LauncherTranscript.ps1
# How settings, storage mode, AI and the directly-dispatched engines are decided (pure; #170/#184/#185).
. /app/container/_shared/SI-ContainerConfig.ps1
# The install's customisation files restored from its storage account (Community; no licence needed).
. /app/container/_shared/SI-ContainerRunState.ps1

# ----------- SI_ROLE dispatcher ---------------------------------------
# Container App Job '--command' / '--args' overrides are unreliable in az CLI
# (argparse nargs='+' chokes on leading-dash PowerShell flags). Instead, every
# job in the v2.2 fleet uses the default ENTRYPOINT (this script) and dispatches
# on $env:SI_ROLE. SI_ROLE defaults to 'worker' so legacy single-job-per-engine
# (non-KEDA) deployments keep working unchanged.
$producerDiscovers  = $false   # #475: a producer that discovers into parts (SI_PRODUCER_DISCOVERS=1)
$dispatchClassifier = $false
$dispatchDirect     = $false   # asset-trend + the Pro engines (#170): dispatched below, once hydrated + connected
$siRole = [Environment]::GetEnvironmentVariable('SI_ROLE')
if ($siRole) {
    switch ($siRole.ToLowerInvariant()) {
        'producer' {
            if ([string][Environment]::GetEnvironmentVariable('SI_PRODUCER_DISCOVERS') -eq '1') {
                # #475: the producer DISCOVERS (once, into parts) and queues one message per part -- it runs the engine
                # below in its 'discover' phase, then writes the manifest and the messages
                $producerDiscovers = $true
                Write-Host '[SI_ROLE=producer] discovering into parts' -ForegroundColor Cyan
            } else {
                $producerScript = '/app/container/Invoke-ShardProducer.ps1'
                Write-Host "[SI_ROLE=producer] dispatching to $producerScript" -ForegroundColor Cyan
                & pwsh -NoProfile -File $producerScript
                exit $LASTEXITCODE
            }
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
            # THE CLASSIFIER USED TO BE DISPATCHED RIGHT HERE -- before a single env var had been
            # hydrated and before Connect-AzAccount -- so it died on "Missing SPN globals" on every
            # run. It is now only MARKED here and dispatched below, after the credentials, workspace,
            # OpenAI settings and the Az connection exist (search: $dispatchClassifier).
            $engineEnv = [Environment]::GetEnvironmentVariable('SI_ENGINE')
            if ($engineEnv -eq 'privilege-tier-classifier') {
                $dispatchClassifier = $true
                # Notes on the dispatch below, kept with the decision they explain:
                # 🔴 AN UNGUARDED DOT-SOURCE OF /app/config/SecurityInsight.custom.ps1 STOOD HERE, AND
                # IT MADE THIS ENGINE UNABLE TO START AT ALL. `.dockerignore` excludes `**/config/` and
                # `**/*.custom.ps1` deliberately -- they carry real tenant values and must never be
                # baked into a shared image -- so the file cannot exist here, and with
                # $ErrorActionPreference = 'Stop' (line 37) the dot-source was fatal, not degrading.
                # PROVEN in the real image 2026-09-08, run cb4:
                #   "The term '/app/config/SecurityInsight.custom.ps1' is not recognized"
                #   Container failed during run: acb_step_0.
                # privilege-tier-classifier is one of the seven engines Bootstrap-ContainerAppJob.ps1
                # provisions by default, so this was a hard failure hiding behind an image nobody had
                # ever built. See #111.
                #
                # 🔒 IT IS NOT REPLACED, because loading that file here would be WORSE than absent, not
                # better. The container is deliberately its OWN config layer: it hydrates the globals
                # it needs from env vars above. A customer config or defaults layer loaded here would,
                # at the second site below, override the very credentials the env vars just supplied.
                # "VM-launcher parity" was the wrong goal for this path.
            }
            # #170: trend and the Pro engines have their own entry scripts, dispatched below exactly like the
            # classifier -- after the credentials, workspace and Az connection exist.
            # #236: asset tagging (Pro) too -- report only unless SI_Pro_AssetTagging_Apply is on, under its own identity.
            # #269: the daily job flow (caj-si-flow) is dispatched the same way -- it starts the other jobs through ARM.
            elseif ($engineEnv -in 'asset-trend', 'asset-correlation', 'asset-properties', 'asset-cmdb', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'asset-tagging', 'asset-cmdb-sql', 'flow', 'config-backup', 'verification') {
                $dispatchDirect = $true
            }
            # #718: the hourly status report to Invardia (caj-si-heartbeat), on its own timer outside the pipeline.
            elseif ($engineEnv -eq 'heartbeat') {
                $dispatchDirect = $true
            }
            # #235: the template publish job (caj-si-templates), started by the web app with the accepted fingerprint.
            elseif ($engineEnv -eq 'templates-publish') {
                $dispatchDirect = $true
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

# Started here -- the earliest point the engine name is known, so the transcript
# also captures the auth and config work below, which is where a container run
# most often dies. Anything that throws BEFORE the sign-in succeeds cannot
# be published either way (no credentials to upload with); everything after it is
# covered by the orchestrator's own try/catch and the publish at the end.
Start-SILauncherTranscript -Engine $engine -Flavour container -RepoRoot '/app' | Out-Null

# The engine's own VM launcher defaults (launcher/<engine>/LauncherConfig.defaults.ps1) FIRST, as on a VM -- the
# customer's settings below override them. They carry no tenant value and no credential, and nothing in them decides the
# storage mode or the sign-in (both are stated from this job's own env vars below). Without them a container lacked
# e.g. the publicip table name (SI_PublicIP_Profile) and the Shodan defaults every VM run has.
$engineDefaults = Get-SIContainerEngineDefaultsPath -Engine $engine -Root '/app'
if ($engineDefaults) { . $engineDefaults }

# #170/#187: the customer's NON-SECRET settings that Bootstrap passed as SI_CFG_<name> -- the config AND this engine's
# own LauncherConfig.custom.ps1. Applied before the credentials and targets this script hydrates from its own env vars
# below, so those still win.
$cfgImport = Import-SIConfigFromEnv
if (@($cfgImport.Applied).Count) { Write-Host ('[config] {0} setting(s) from the customer config: {1}' -f @($cfgImport.Applied).Count, (@($cfgImport.Applied) -join ', ')) }
if (@($cfgImport.Refused).Count) { Write-Warning ('[config] refused (secret-looking or container-owned, never passed this way): {0}' -f (@($cfgImport.Refused) -join ', ')) }

# Storage (for v2.2 fingerprint cache + staging + queues)
$global:SI_StorageAccount = Get-RequiredEnv 'SI_STORAGE_ACCOUNT'

# ---- Sign-in (#209): managed identity > certificate (PFX from Key Vault) > client secret ----
# The job's MANAGED IDENTITY when it has one (IDENTITY_ENDPOINT) and Bootstrap named it (SI_UAMI_CLIENTID) --
# as PIM's containers do. Otherwise the SPN by CERTIFICATE when the job carries its PFX as a Key Vault
# reference (SI_SPN_CERT_PFX_B64), exactly as the SI updater receives its own. Otherwise the SPN by client
# SECRET -- unchanged, and it stays: it is the Community default (SI_SPN_APPID / SECRET / TENANTID / OBJECTID,
# one SPN for Graph reads AND LA ingest).
. /app/auth/SI-ManagedIdentity.ps1
$siAuth = Resolve-SIContainerAuthMode
$siCertPfxPath = $null
switch ($siAuth.Mode) {
    'ManagedIdentity' {
        $global:SI_UseManagedIdentity = $true                    # THE switch every token site checks
        $global:SI_UAMI_ClientId      = $siAuth.ClientId
        $global:SI_PreferUami         = $true                    # the existing log-ingest switch, same decision
        $global:SI_SPN_AppId          = $siAuth.ClientId         # the identity's app id, for the engines' bookkeeping
        $global:SI_SPN_Secret         = $null
        $global:SI_SPN_TenantId       = Get-OptionalEnv 'SI_SPN_TENANTID' $null
        $global:SI_SPN_ObjectId       = Get-OptionalEnv 'SI_SPN_OBJECTID' $null
    }
    'Certificate' {
        $global:SI_SPN_AppId    = Get-RequiredEnv 'SI_SPN_APPID'
        $global:SI_SPN_Secret   = $null
        $global:SI_SPN_TenantId = Get-RequiredEnv 'SI_SPN_TENANTID'
        $global:SI_SPN_ObjectId = Get-RequiredEnv 'SI_SPN_OBJECTID'
        $siCert = Import-SIContainerCertificate -PfxBase64 (Get-RequiredEnv 'SI_SPN_CERT_PFX_B64') -Password (Get-OptionalEnv 'SI_SPN_CERT_PASSWORD' '')
        $global:SI_SPN_CertThumbprint    = $siCert.Thumbprint
        $global:SI_SPN_CertStoreLocation = 'CurrentUser'         # the only store a Linux container has
        $siCertPfxPath = $siCert.PfxPath
    }
    'Secret' {
        $global:SI_SPN_AppId    = Get-RequiredEnv 'SI_SPN_APPID'
        $global:SI_SPN_Secret   = Get-RequiredEnv 'SI_SPN_SECRET'
        $global:SI_SPN_TenantId = Get-RequiredEnv 'SI_SPN_TENANTID'
        $global:SI_SPN_ObjectId = Get-RequiredEnv 'SI_SPN_OBJECTID'
    }
    default { throw ('[auth] cannot sign in: {0}' -f $siAuth.Reason) }
}
Write-Host ('[auth] signing in as {0}' -f $siAuth.Reason)

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

# Storage: reached ONLY with the signed-in identity (the job's managed identity, or the app identity),
# which holds the Storage Blob / Queue / Table Data Contributor roles on the account (setup grants them).
Write-Host '[storage] signed-in identity'

# Optional UAMI override (legacy / single-tenant). Off by default. Secret mode only -- the managed identity
# mode above already decided the identity (#209), and the certificate mode must not be overridden by it.
if ($siAuth.Mode -eq 'Secret') {
    $global:SI_UAMI_ClientId = Get-OptionalEnv 'SI_UAMI_CLIENTID' $null
    $global:SI_PreferUami    = (Get-OptionalEnv 'SI_PREFER_UAMI' '0') -in '1','true','True','yes'

    if ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) {
        Write-Host ('[auth] $SI_PreferUami=1 + SI_UAMI_CLIENTID set -- UAMI path enabled (legacy mode).')
    } else {
        Write-Host '[auth] SPN-secret mode.'
    }
}

# Workspace + DCE/DCR target
$global:SI_WorkspaceResourceId = Get-RequiredEnv 'SI_WORKSPACE_RESOURCEID'
$global:SI_DceName             = Get-RequiredEnv 'SI_DCE_NAME'
$global:SI_DcrResourceGroup    = Get-RequiredEnv 'SI_DCR_RESOURCEGROUP'

# OpenAI for Stage Classify (#184): OPTIONAL. It used to be required -- so a customer without Azure OpenAI
# could not deploy container hosting at all -- while AI could never actually be switched on here (nothing
# mapped SI_EnableAI_*). Now: configured only when all four are present; ON only when also asked for
# (SI_ENABLE_AI=1, or SI_EnableAI_<engine> passed through from the customer's config).
$openAi = @{ apiKey = (Get-OptionalEnv 'OPENAI_APIKEY'); endpoint = (Get-OptionalEnv 'OPENAI_ENDPOINT')
             deployment = (Get-OptionalEnv 'OPENAI_DEPLOYMENT'); apiVersion = (Get-OptionalEnv 'OPENAI_APIVERSION') }
$aiAsked = ((Get-OptionalEnv 'SI_ENABLE_AI' '0') -in '1', 'true', 'True', 'yes') -or
           [bool](Get-Variable -Name ("SI_EnableAI_{0}" -f $engine) -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
$ai = Resolve-SIContainerAi -OpenAi $openAi -Requested $aiAsked
if ($ai.Configured) {
    $global:OpenAI_apiKey     = $openAi.apiKey
    $global:OpenAI_endpoint   = $openAi.endpoint
    $global:OpenAI_deployment = $openAi.deployment
    $global:OpenAI_apiVersion = $openAi.apiVersion
}
Set-Variable -Name ("SI_EnableAI_{0}" -f $engine) -Scope Global -Value ([bool]$ai.Enabled)   # stated, never inferred
Write-Host ('[ai] {0}' -f $ai.Reason)
$global:MaxAiSpendPerRun  = [double](Get-OptionalEnv 'MAX_AI_SPEND_PER_RUN' '4')

# Shodan (#185): the paid entitlement arrives as a Key Vault-referenced secret. Without it the publicip
# engine says so in one line and publishes without Shodan fields -- never silently.
$shodanKey = Get-OptionalEnv 'SHODAN_API_KEY' $null
if ($shodanKey) { $global:SI_Shodan_ApiKey = $shodanKey }
elseif ($engine -eq 'publicip') { Write-Warning '[shodan] no SHODAN_API_KEY on this job -- public IPs are collected WITHOUT Shodan enrichment (Shodan fields stay empty).' }

# SecurityInsight Pro licence (#170): a Key Vault-referenced secret. Absent = Community: the Pro engines
# refuse with one line and publish nothing, exactly as on a VM.
$licence = Get-OptionalEnv 'SI_LICENSE' $null
if ($licence) { $global:SI_License = $licence }

# The SMTP password for the close-loop daily mail (close-loop-mail): a Key Vault-referenced secret, as the Risk Analysis
# entrypoint receives it. It never travels as a plain setting; the relay's other settings arrive as SI_CFG_*.
$smtpPassword = Get-OptionalEnv 'SMTP_PASSWORD' $null
if ($smtpPassword) { $global:SMTPPassword = $smtpPassword }

# Sign in (recorded; every REST call -- storage, Log Analytics, Resource Graph, ingestion -- mints its token as this
# identity when it needs one). No PowerShell module is involved.
$subId = ($global:SI_WorkspaceResourceId -split '/')[2]
if ($siAuth.Mode -eq 'ManagedIdentity') {
    # #209: with the identity recorded, every token the run asks for is minted as the identity.
    Connect-SIAzAccount -Identity -AccountId $global:SI_UAMI_ClientId -Subscription $subId | Out-Null
} elseif ($siAuth.Mode -eq 'Certificate') {
    # #209: by the PFX FILE -- a Linux container has no Cert: drive to look a thumbprint up in.
    $siCertArgs = @{ ServicePrincipal = $true; ApplicationId = $global:SI_SPN_AppId; Tenant = $global:SI_SPN_TenantId
                     CertificatePath = $siCertPfxPath; Subscription = $subId }
    $siCertPw = Get-OptionalEnv 'SI_SPN_CERT_PASSWORD' $null
    if ($siCertPw) { $siCertArgs['CertificatePassword'] = (ConvertTo-SecureString $siCertPw -AsPlainText -Force) }
    Connect-SIAzAccount @siCertArgs | Out-Null
} elseif ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) {
    Connect-SIAzAccount -Identity -AccountId $global:SI_UAMI_ClientId -Subscription $subId | Out-Null
} else {
    $secure = ConvertTo-SecureString $global:SI_SPN_Secret -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential($global:SI_SPN_AppId, $secure)
    Connect-SIAzAccount -ServicePrincipal -Tenant $global:SI_SPN_TenantId -Credential $cred -Subscription $subId | Out-Null
}
# #209: log ingestion mints its own tokens over REST -- the managed identity at the job's identity endpoint, a
# certificate from the X509 store -- so a Container Apps job (no metadata endpoint, no Cert: drive) needs nothing more.

# #281: the Log Analytics target every run-health record, rule and endpoint lookup uses -- the subscription above all,
# which nothing in a container set before (live 2026-10-05: every profiler and flow run lost its run-health record).
# Before the execution guard below, which can already send one.
$siIngest = Initialize-SIContainerIngestGlobals
if (-not $siIngest.SubscriptionId) { Write-Warning '[ingest] no subscription found for the Log Analytics workspace (SI_WORKSPACE_RESOURCEID) -- run-health records cannot be saved.' }

# SCHED-1.1 (#269): THE EXECUTION GUARD. A job's own cron fires on the clock, whatever its last run is doing; a second
# execution of the same job while the first is still running starts nothing -- it says so, records "skipped" in run
# health, and ends successfully. Not for KEDA workers (their parallel executions are the design). A check that cannot be
# made (no Reader on the job, ARM unreachable) is said and the run goes on -- the guard never blocks a run on its own failure.
$guardJob = [Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_NAME'); $guardExec = [Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME')
$guardSub = Get-OptionalEnv 'SI_JOBS_SUBSCRIPTIONID' (Get-OptionalEnv 'SI_FLOW_SUBSCRIPTIONID' $null); $guardRg = Get-OptionalEnv 'SI_JOBS_RESOURCEGROUP' (Get-OptionalEnv 'SI_FLOW_RESOURCEGROUP' $null)

# #931: the values a person's start carries (Run now, a template release, a mail-only run, who started it) arrive as a
# start request in the Pro database, never as a start override (Azure Container Apps: an override needs jobs/write). Claimed
# BEFORE the guard below, which reads them; handed back when this execution does nothing, so the next one takes it.
# The database seam is loaded inside the call only (Invoke-SIJobStartRequestIsolated): nothing it brings may reach the engine.
$startRequest = @{ Claimed = $false }; $startRequestGuard = $null
if ($global:SI_ProSqlServer -and $global:SI_ProSqlDatabase -and $guardJob -and $guardExec -and (Get-OptionalEnv 'SI_TRIGGER_FROM_QUEUE' '0') -ne '1' -and -not (Get-OptionalEnv 'SI_COLLECT_PHASE' $null)) {
    try {
        $startRequestGuard = Join-Path $PSScriptRoot '../engine/_shared/SI-Guard.ps1'
        . (Join-Path $PSScriptRoot '../engine/_shared/SI-JobStartRequest.ps1')
        $startRequest = Invoke-SIJobStartRequestIsolated -GuardPath $startRequestGuard -Job ([string]$guardJob) -Execution ([string]$guardExec)
        if ($startRequest.Line) { Write-Host $startRequest.Line }
    } catch { Write-Warning ('[start-request] the start request could not be read ({0}) -- the run goes on as configured' -f $_.Exception.Message) }
}
function Undo-SIStartRequestClaim {
    if ($script:startRequest.Claimed) { $null = Invoke-SIJobStartRequestIsolated -GuardPath $script:startRequestGuard -RequestId $script:startRequest.RequestId -Execution ([string]$script:guardExec) }
}
if ($guardJob -and $guardExec -and $guardSub -and $guardRg -and (Get-OptionalEnv 'SI_TRIGGER_FROM_QUEUE' '0') -ne '1' -and -not (Get-OptionalEnv 'SI_COLLECT_PHASE' $null)) {
    $guardOther = $null
    try {
        $guardList = @(Invoke-SIArm -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}/executions' -f $guardSub, $guardRg, $guardJob) -ApiVersion '2025-07-01' -List)
        $guardOther = Get-SIJobExecutionOverlap -Executions $guardList -Self $guardExec
    } catch { Write-Warning ('[guard] could not check for a running execution of {0} ({1}) -- the run goes on' -f $guardJob, $_.Exception.Message) }
    # A flow execution that carries a request (Run now) is never dropped by the guard: the runner's lock queues it.
    # #946: a cancel of the running run (SI_FLOW_CANCEL) is a request too -- it is meant for the run the other execution holds.
    $guardFlowAsk = Test-SIFlowGuardRequest
    $guardFlowRequest = [bool]$guardFlowAsk.Request
    $guardDecision = Get-SIExecutionGuardDecision -Engine $engine -Job $guardJob -Other $guardOther -Self $guardExec -FlowRequest:$guardFlowRequest -FlowCancel:([bool]$guardFlowAsk.Cancel)
    if ($guardDecision.Action -eq 'Run' -and $guardDecision.Message) { Write-Host $guardDecision.Message }
    # #277 (live, ring 1 2026-10-05): the flow runner wakes every 5 minutes -- a wake-up during a flow run is normal
    # operation, not a guard: one INFO line, no row, no guard event, no telemetry, no warning.
    if ($guardDecision.Action -eq 'FlowBusy') { Write-Host $guardDecision.Message; Undo-SIStartRequestClaim; exit 0 }
    if ($guardDecision.Action -eq 'Skip') {
        Write-Host $guardDecision.Message -ForegroundColor Yellow
        Undo-SIStartRequestClaim
        try {
            if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { . '/app/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1' }
            Send-SIRunHealthRow -Phase End -ExitReason 'skipped' -ErrorMessage ('skipped: previous still running ({0})' -f $guardOther.name) -NoTelemetry `
                -RunContext ([pscustomobject]@{ RunId = $guardExec; Engine = $engine; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow })
            # #277: mailed and reported (once a day while it keeps happening)
            if (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue) { $null = Send-SIGuardEvent -GuardId 'job.execution.previous-running' -Outcome 'skipped' -Engine $engine -Subject $guardJob -RunId $guardExec -Detail ('{0} was started while its previous run ({1}, started {2}) was still running, so this run did nothing.' -f $guardJob, $guardOther.name, $guardOther.properties.startTime) }
        } catch { }
        exit 0
    }
}

# The engine checks its OWN permissions (engine/_shared/SI-PermissionCheck.ps1, catalog config/permissions.locked.json):
# the roles in its own API tokens and one read of its Azure permissions now; its Pro database access when the settings
# layer below signs in. The result travels on the run-health END record (PermissionGaps) to Get Started > Permissions.
# Never stops the run: a check that cannot be made is "not checked".
try { . (Join-Path $PSScriptRoot '../engine/_shared/SI-PermissionCheck.ps1'); $null = Invoke-SIPermissionSelfCheck -Engine $engine }
catch { Write-Warning ('[permissions] the permission check could not run: {0}' -f $_.Exception.Message) }

# #211 (2): SecurityInsight Pro keeps every setting in its database, and Pro is container-only -- so containers load that
# layer too, as launcher Layer 5b does on a VM. Only where the Pro module is present AND a Pro database is configured;
# a settings database that cannot be read (or an invalid row) STOPS the run, as on a VM.
$proSettingsModule = '/app/engine/pro-settings/SI-ProSettings.ps1'
if ((Test-Path -LiteralPath $proSettingsModule) -and $global:SI_ProSqlServer -and $global:SI_ProSqlDatabase) {
    try {
        . $proSettingsModule
        # The container owns its sign-in, targets and platform switches: the database never overrides them.
        $proLayer = Invoke-SIProSettingsLayer -Engine (Get-SIProSettingsEngineName -ContainerEngine $engine) -ExcludeNames $script:SIConfigProtected
        Write-Host ('[pro-settings] loaded from {0} (settings version {1})' -f $proLayer.Store, $global:SI_ProSettingsVersion)
        if (@($global:SI_ProSettingsSkipped).Count) { Write-Host ('[pro-settings] not applied here (container-owned): {0}' -f (@($global:SI_ProSettingsSkipped) -join ', ')) }
    } catch {
        Write-Host ('[pro-settings] {0}' -f $_.Exception.Message) -ForegroundColor Red
        Publish-SILauncherTranscript -Engine $engine -Context (New-SIRunLogStorageContext) | Out-Null
        # UPLINK-FIX (customer G 2026-10-07): the install is not finished (the jobs exist before the identity's database
        # user) -- nothing ran, a warning was recorded; the execution is not a failure
        if ($global:SI_ProSettingsInstallPending) { Write-Host '[pro-settings] the install is not finished yet -- this run did nothing; the next one after the install runs normally.'; exit 0 }
        # asset tagging's own identity has no Pro database user (installs before the fix): a warning, never a failed run
        if ($global:SI_ProSettingsTaggingNoAccess) { Write-Host '[pro-settings] asset tagging cannot read its settings yet -- this run did nothing; the run record above says how to give its identity read access (once, as the SQL server''s Entra admin).'; exit 0 }
        exit 1
    }
} else {
    # No settings database: the install's customisation files (CMDB.csv, enrichment rules, schema overlays, decision
    # files) that setup shared to its storage account go where a VM has them. No licence needed.
    $overlay = Restore-SIContainerOverlay -AccountName ([string]$global:SI_StorageAccount) -TargetRoot '/app'
    if (@($overlay.Applied).Count) { Write-Host ('[customisation] {0} file(s) from the install: {1}' -f @($overlay.Applied).Count, (@($overlay.Applied) -join ', ')) }
    if (@($overlay.Skipped).Count) { Write-Warning ('[customisation] not used (not a customisation file): {0}' -f (@($overlay.Skipped) -join ', ')) }
}

# NO OVERLAP (2026-10-25): a SCHEDULED collection never runs beside the pipeline (engine/_shared/SI-CollectionRunGate.ps1).
# Only the own execution of a Collect-stage job (a producer, or the one job of an engine collected without queue scaling)
# -- never a queue worker, never a collect child. The pipeline's own collection step always runs. While a pipeline run
# holds the install: SKIP when the run collects this job itself, WAIT (no cap; the job's run limit counts) when it does not.
# A state that cannot be read = the collection runs as before.
if ($global:SI_ProSqlServer -and $global:SI_ProSqlDatabase) {
    try {
        . (Join-Path $PSScriptRoot '../engine/_shared/SI-CollectionRunGate.ps1')
        $gateKeys = @(Get-SICollectionRunGateKeys -MapPath (Join-Path $PSScriptRoot '../config/job-flow.locked.json'))
        if (Test-SICollectionRunGateApplies -JobName ([string]$guardJob) -Execution ([string]$guardExec) -FromQueue ((Get-OptionalEnv 'SI_TRIGGER_FROM_QUEUE' '0') -eq '1') -CollectPhase ([string](Get-OptionalEnv 'SI_COLLECT_PHASE' '')) -CollectKeys $gateKeys) {
            if (-not (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-Guard.ps1') }
            $gateInvoke = Get-SIGuardProInvoke
            # the job's own run limit: this execution's start + the job's replica timeout (not known = said so, the wait goes on)
            $gateDeadline = $null
            if ($guardSub -and $guardRg) {
                try {
                    $gateJobArm = Invoke-SIArm -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $guardSub, $guardRg, $guardJob) -ApiVersion '2025-07-01'
                    $gateLimit = 0; [void][int]::TryParse([string]$gateJobArm.properties.configuration.replicaTimeout, [ref]$gateLimit)
                    $gateMine = @(@($guardList) | Where-Object { $_ -and [string]$_.name -eq [string]$guardExec })[0]
                    $gateStart = if ($gateMine -and $gateMine.properties.startTime) { [datetime]$gateMine.properties.startTime } else { [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime() }
                    $gateDeadline = Get-SICollectionRunGateDeadline -StartedUtc $gateStart -LimitSeconds $gateLimit
                } catch { $gateDeadline = $null }
            }
            # #947: A WAITING UPDATE GOES FIRST -- the updater's wait mark (tag si-update-waits on the updater job, the same mark
            # the pipeline runner obeys); the updater job's name from the install record, else today's name. Unreadable = no hold.
            $gateUpdateWaits = $null
            if ($guardSub -and $guardRg) {
                $gateUpdateWaits = {
                    if (-not (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-InstallNames.ps1') }
                    $updName = Get-SIInstallName -Role updater -Record (Read-SIInstallNamesRecord -Store ([pscustomobject]@{ Invoke = $gateInvoke }))
                    $updJob = Invoke-SIArm -Path ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $guardSub, $guardRg, $updName) -ApiVersion '2025-07-01' -AllowNotFound
                    if (-not $updJob -or -not $updJob.tags -or -not $updJob.tags.PSObject.Properties['si-update-waits']) { return $null }
                    ConvertFrom-SICollectionUpdateWaitsTag -Value ([string]$updJob.tags.'si-update-waits')
                }
            }
            $gate = Invoke-SICollectionRunGate -Invoke $gateInvoke -Job (Get-SICollectionRunGateJobKey $guardJob) -Self ([string]$guardExec) -DeadlineUtc $gateDeadline `
                        -Log { param($l, $m) if ($l -eq 'WARN') { Write-Warning $m } else { Write-Host $m } } -UpdateWaits $gateUpdateWaits
            if ($gate.Action -in @('Skip', 'Limit')) {
                try {
                    if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { . '/app/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1' }
                    Send-SIRunHealthRow -Phase End -ExitReason 'skipped' -ErrorMessage ('skipped: {0}' -f $gate.Reason) -NoTelemetry `
                        -RunContext ([pscustomobject]@{ RunId = $guardExec; Engine = $engine; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow })
                } catch { }
                try { Publish-SILauncherTranscript -Engine $engine -Context (New-SIRunLogStorageContext) | Out-Null } catch { }
                Undo-SIStartRequestClaim
                exit 0
            }
        }
    } catch { Write-Warning ('[no-overlap] whether a pipeline run is going could not be checked ({0}) -- the collection runs as before' -f $_.Exception.Message) }
}

# #276: no dry run from the job's settings (SI_WHATIF=1 on one execution asks for one), the retired Power BI line, and the
# one-time notices after an upgrade -- the same safety layer a VM launcher runs (engine/_shared/SI-FirstRun.ps1).
try { . /app/engine/_shared/SI-FirstRun.ps1; $null = Invoke-SIContainerRunSafety -Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) } catch { Write-Verbose $_.Exception.Message }

# The build this image was made from (BUILD.json, stamped by Bootstrap-ContainerAppJob.ps1 at image build time; never git at run time).
. (Join-Path $PSScriptRoot '../engine/_shared/SI-BuildInfo.ps1')
$siBuild = Read-SIBuildInfo -SolutionRoot (Split-Path -Parent $PSScriptRoot)
Write-Host '======================================================================'
Write-Host (' SecurityInsight {0} in container -- engine={1}  ts={2}' -f (Format-SIBuildLine $siBuild), $engine, ([datetime]::UtcNow.ToString('o')))
Write-Host '======================================================================'

# ---- privilege-tier-classifier: dispatched HERE, once everything it needs exists ----
# The transcript was already started above under this engine's name. In-process call (NOT
# `& pwsh -File`) -- a child pwsh would lose the $global:* state hydrated from the env vars.
if ($dispatchClassifier) {
    $classifierScript = '/app/engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1'
    Write-Host "[SI_ROLE=worker SI_ENGINE=privilege-tier-classifier] dispatching to $classifierScript" -ForegroundColor Cyan
    $clsExit = 0
    try {
        & $classifierScript
        if ($LASTEXITCODE) { $clsExit = $LASTEXITCODE }
    } catch {
        Write-Warning ('classifier threw: {0}' -f $_.Exception.Message)
        $clsExit = 1
    }
    Publish-SILauncherTranscript -Engine 'privilege-tier-classifier' -Context (New-SIRunLogStorageContext) | Out-Null
    exit $clsExit
}

# ---- asset-trend + the Pro engines (#170): dispatched HERE, like the classifier ----------------------
# Parameters resolved from the settings exactly as each engine's VM launcher resolves them.
if ($dispatchDirect) {
    $globalsNow = @{}
    foreach ($v in (Get-Variable -Scope Global)) { $globalsNow[$v.Name] = $v.Value }
    $d = Get-SIContainerEngineDispatch -Engine $engine -Globals $globalsNow
    $directExit = 0
    if ($d.Skip) {
        Write-Host ('[{0}] {1} -- nothing to do.' -f $engine, $d.Skip)
    } else {
        $script = Join-Path '/app' $d.Script
        Write-Host ("[SI_ROLE=worker SI_ENGINE={0}] dispatching to {1} {2}" -f $engine, $script, (($d.Args.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ')) -ForegroundColor Cyan
        try {
            $argsForEngine = $d.Args
            & $script @argsForEngine
            if ($LASTEXITCODE) { $directExit = $LASTEXITCODE }
        } catch {
            Write-Warning ('{0} threw: {1}' -f $engine, $_.Exception.Message)
            $directExit = 1
        }
    }
    Publish-SILauncherTranscript -Engine $engine -Context (New-SIRunLogStorageContext) | Out-Null
    exit $directExit
}

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
$collectRunId = ''; $collectPhase = ''; $collectEngineRun = ''
# FULL ASSET METADATA OF A RUN COLLECTED IN PARTS (2026-10-11). Discovery (the producer) keeps the whole objects, the parts
# build the profile rows: each hands its half over and the run's LAST step publishes the run's full metadata ONCE, with
# the run's CollectionTime (engine/asset-properties/_shared/SI-AssetPropertiesHandover.ps1). Both never throw: a failure is
# said, and the profiles and records are unaffected. At the security level (or in the Community copy) they do nothing.
$saveDiscoverAssetProps = {
    param([string]$EngineRunId)
    try {
        if (-not $global:SIFullAssetPropertiesState -or [string]$global:SIFullAssetPropertiesState.Level -ne 'full') { return }
        . /app/engine/_shared/SI-CollectParts.ps1
        . /app/engine/asset-profiling/shared/SI-FullAssetProperties.ps1
        $n = Save-SIFullAssetPropertiesDiscoverHandover -Engine ([string]$engine) -RunId $EngineRunId
        if ($null -ne $n) { Write-Host ('[parts] {0}: {1} full asset metadata object(s) from discovery handed over' -f $engine, $n) }
    } catch { Write-Warning ('[parts] {0}: the full asset metadata from discovery could not be handed over -- {1}. This run publishes none; the profiles are unaffected.' -f $engine, $_.Exception.Message) }
}
$publishAssetPropsHandover = {
    param([string]$EngineRunId, [datetime]$RunCollectionTime)
    try {
        $proHandover = '/app/engine/asset-properties/_shared/SI-AssetPropertiesProfiler.ps1'
        if (-not (Test-Path -LiteralPath $proHandover)) { return }
        . /app/engine/_shared/SI-CollectParts.ps1
        . $proHandover
        $null = Invoke-SIAssetPropsHandoverPublish -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine ([string]$engine) -RunId $EngineRunId -CollectionTime $RunCollectionTime
    } catch { Write-Warning ('[parts] {0}: the run''s full asset metadata could not be published -- {1}' -f $engine, $_.Exception.Message) }
}
$useQueue   =(Get-OptionalEnv 'SI_TRIGGER_FROM_QUEUE' '0') -eq '1'
$siEntryScript = $PSCommandPath   # this entry point: the records processes of a run (#874) run it again
# #475 -- KEDA: every worker, once its part is marked (done or failed), checks whether it was the LAST; the last one
# claims the run and publishes the records that the producer and every part handed over -- each record once, whole.
# Never throws: a records publish that fails is written to the run's records marker, and the pipeline's step fails on it.
$finishKedaRecords = {
    param([string]$RecCollectKey, [string]$RecEngineRun, [string]$RecCollectionTime)
    if (-not $RecCollectKey -or -not $RecEngineRun) { return }
    $recPhase = [Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE')
    try {
        . /app/engine/_shared/SI-CollectParts.ps1
        . /app/engine/data-model/SI-RecordCapture.ps1
        . /app/engine/data-model/SI-RecordHandover.ps1
        $recStore = New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)
        $recCt = [datetime]::UtcNow
        if ($RecCollectionTime) { try { $recCt = [datetime]::Parse($RecCollectionTime, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
        $recEngineName = [string]$engine
        # publishing, not handing over: Publish-SIRecords hands over while this process says it is a part
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'records')
        $recState = Invoke-SICollectRecordsIfLast -Store $recStore -Engine $recEngineName -RunId $RecCollectKey -Worker ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME) -Publish {
            # #720: a run with a failed part publishes what it has, never closing the collection as complete
            param([int]$PartsFailed)
            # #874 (ring 2, 2026-10-20): ONE process published 506 buckets one at a time -- 10.4 hours, 3 of the worker's 4
            # CPUs idle. The claimed last worker now publishes them as a scheduled collection job does: one records process
            # per CPU as the free memory allows (each the buckets b mod N = k), and closes the collection ONCE itself.
            $recBuckets = 0; $recParts = 0
            try { $recM = Read-SICollectManifest -Store $recStore -Engine $recEngineName -RunId $RecCollectKey; if ($recM) { $recBuckets = [int]$recM.RecordBuckets; $recParts = [int]$recM.Parts } } catch { }
            if ($recBuckets -lt 1) { $recBuckets = [Math]::Max(1, $recParts) }
            $global:SIRecordCaptureState = $null; [System.GC]::Collect()   # this worker's own part is done: its memory is let go first
            $recProcs = Get-SIRecordsProcessCount -Buckets $recBuckets -Processors ([Environment]::ProcessorCount) -FreeBytes (Get-SIRecordsProcessFreeBytes) `
                -Override ([int](Get-OptionalEnv 'SI_COLLECT_RECORDS_PARALLEL' 0))
            if ($recProcs -le 1) {
                Publish-SIRecordHandover -Store $recStore -Engine $recEngineName -RunId $RecEngineRun -RunContext ([pscustomobject]@{ CollectionTime = $recCt; RunId = $RecEngineRun }) -PartsFailed $PartsFailed
                # the run's full asset metadata, once, by the same claimed last worker (never throws, never changes the records' result)
                $null = & $publishAssetPropsHandover $RecEngineRun $recCt
            } else {
                Write-Host ('[parts] {0}: the last part -- publishing the run''s records ({1} bucket(s)) in {2} processes at once' -f $recEngineName, $recBuckets, $recProcs)
                # the records processes run this entry point WITHOUT the queue (SI_TRIGGER_FROM_QUEUE = 0): they take no part;
                # the first of them also publishes the run's full asset metadata (as the in-job run's first records process does)
                $recEnv = @{ SI_TRIGGER_FROM_QUEUE = '0'; SI_COLLECT_PHASE = 'records'; SI_COLLECT_PARTS = [Math]::Max(1, $recParts); SI_COLLECT_RECORD_BUCKETS = $recBuckets
                             SI_COLLECT_ENGINE_RUN = $RecEngineRun; SI_COLLECTION_TIME = $recCt.ToString('o'); SI_COLLECT_PARTS_FAILED = $PartsFailed }
                $recPar = Invoke-SIRecordsInProcesses -Script $siEntryScript -Environment $recEnv -Processes $recProcs -Engine $recEngineName -CollectionTime $recCt
                Write-Host ('[parts] {0}: {1} record(s) from {2} bucket(s) published by {3} processes{4}' -f $recEngineName, $recPar.Records, $recPar.Buckets, $recPar.Processes, $(if ($recPar.Failed) { (', {0} bucket(s) failed' -f $recPar.Failed) } else { '' }))
                [pscustomobject]@{ Records = $recPar.Records; Buckets = [Math]::Max([int]$recPar.Buckets, $recBuckets); Failed = [int]$recPar.Failed }
            }
        }
        switch ($recState) {
            'published' { Write-Host ('[parts] {0}: the last part -- the run''s records published' -f $recEngineName) }
            'failed' { Write-Warning ('[parts] {0}: the last part -- the run''s records were NOT all published (see the run''s records marker)' -f $recEngineName) }
            default { }
        }
        # the ONE report of the job to Invardia for a run in parts: the execution that published the records knows the whole
        # result (the producer and the parts do not report an ok of their own). Whole = every part done and every record
        # published: ok, with every step of the run (StepsOk). Records that could not be published: failed, step 'records'.
        # A run with a failed part says nothing more here -- that part's own report stands. Never fails the worker.
        if ($recState -in @('published', 'failed')) {
            try {
                if (-not (Get-Command -Name Send-SITelemetryRunEnd -ErrorAction SilentlyContinue)) { . '/app/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1' }
                $recFailedParts = @(@(Read-SICollectPartMarkers -Store $recStore -Engine $recEngineName -RunId $RecCollectKey) | Where-Object { $_ -and [string]$_.State -eq 'failed' }).Count
                $recReport = Get-SICollectRunReport -Engine $recEngineName -RecordsState $recState -FailedParts $recFailedParts -RunId $RecEngineRun -StartedAt $recCt
                if ($recReport) { $null = Send-SITelemetryRunEnd -RunContext $recReport.RunContext -ExitReason $recReport.ExitReason -ErrorMessage $recReport.Message }
            } catch { Write-Warning ('[parts] the run''s report to Invardia could not be sent: {0}' -f $_.Exception.Message) }
        }
    } catch {
        Write-Warning ('[parts] the run''s records could not be checked or published: {0}' -f $_.Exception.Message)
    } finally { [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', $recPhase) }
}
# #720: A HAND-OVER THAT FAILED AFTER THE ENGINE ENDED. The engine writes its run-health END ("success") before this entry
# point hands the run on (the producer's queue, a discovery child's run, a part's records), so a hand-over that fails must
# say so itself: a second END record of the same run -- error, NOT COMPLETE, the out-of-memory class si-col-0501 when it was
# memory (the update's size rule reads it: one band up) -- and the run's report to Invardia. -Failure: Get-SICollectHandoverFailure.
# Never throws: a record that cannot be written is one warning (the exit code still fails the execution).
$endRunNotComplete = {
    param($Failure, [string]$RunId, $CollectionTime, [int]$Shard = 0, [int]$Shards = 1)
    try {
        # what the run held is let go first: an out-of-memory hand-over could not build the record otherwise (#702)
        $global:SIRecordCaptureState = $null; $global:SI_DiscoverStream = $null
        [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
        if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { . '/app/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1' }
        $ctx = [pscustomobject]@{ RunId = $(if ($RunId) { $RunId } else { [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME }); Engine = [string]$engine
            ShardIndex = $Shard; ShardCount = [Math]::Max(1, $Shards); CollectionTime = $(if ($CollectionTime) { $CollectionTime } else { [datetime]::UtcNow })
            StartedAt = [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime(); FailedStep = 'handover' }
        Send-SIRunHealthRow -RunContext $ctx -Phase End -AssetCount -1 -ExitReason ([string]$Failure.ExitReason) -ErrorMessage ([string]$Failure.Text)
        Write-Warning ('[run] {0}' -f [string]$Failure.Text)
    } catch { Write-Warning ('[run] the run could not be recorded as not complete ({0}) -- {1}' -f $_.Exception.Message, [string]$Failure.Text) }
}
$shardCount = [int](Get-OptionalEnv 'SI_SHARD_COUNT' 1)
$shardIndex = [int](Get-OptionalEnv 'CONTAINER_APP_JOB_REPLICA_INDEX' 0)
$queueMessageId    = $null
$queueMessageReceipt = $null
$queueName         = $null

if ($useQueue) {
    Write-Host '[trigger] KEDA event mode -- pulling shard descriptor from queue.'
    . /app/engine/asset-profiling/storage/StorageContext.ps1
    . /app/engine/asset-profiling/storage/WorkerQueue.ps1
    $kctx = New-SIStorageContext -AccountName $global:SI_StorageAccount
    $queueName = ('si-{0}-shards' -f $engine)
    Initialize-SIQueue -Context $kctx -QueueName $queueName | Out-Null

    # THE HOLD ON A PART IS SHORT AND RENEWED (2026-10-13): the part is taken for 10 minutes and a heartbeat on its own
    # thread renews that every 2 minutes while this process lives (WorkerQueue.ps1, Start-SIWorkItemLeaseBeat, started
    # below once the part is known to be worked on). A worker that dies stops renewing and its part is back in the queue
    # within 10 minutes -- it used to stay locked for the worker job's whole run limit (hours, then days).
    # SI_QUEUE_LEASE_SECONDS (the job's run limit + 5 minutes, set by setup) is only the fallback when the heartbeat cannot
    # be started, and never more than 2 hours 5 minutes of it is used (Get-SIWorkItemFallbackLeaseSeconds, below).
    $leaseSeconds = [int](Get-OptionalEnv 'SI_QUEUE_LEASE_SECONDS' 3900)
    # a storage queue refuses a lease longer than 7 days
    if ($leaseSeconds -gt 604800) { $leaseSeconds = 604800 }
    $partLeaseSeconds = [int](Get-OptionalEnv 'SI_QUEUE_PART_LEASE_SECONDS' (Get-SIWorkItemLeaseSeconds))
    if ($partLeaseSeconds -lt 120) { $partLeaseSeconds = 120 }; if ($partLeaseSeconds -gt 3600) { $partLeaseSeconds = 3600 }
    $partBeat = $null
    $msg = Get-SINextWorkItem -Context $kctx -QueueName $queueName -VisibilityTimeoutSeconds $partLeaseSeconds
    if (-not $msg) {
        Write-Host '[trigger] queue empty -- nothing to do, exiting cleanly.'
        exit 0
    }
    # A shard that has failed its worker this many times will fail the next one too. It is PARKED in
    # '<queue>-poison' with its original text (re-queue it once the cause is fixed), not retried for
    # ever and not dropped. The run is marked failed so the missing shard is visible.
    $maxDequeue = [int](Get-OptionalEnv 'SI_QUEUE_MAX_DEQUEUE' 5)
    if ($msg.DequeueCount -gt $maxDequeue) {
        $poison = Move-SIWorkItemToPoison -Context $kctx -QueueName $queueName -WorkItem $msg `
                    -Reason ('handed out {0} times without completing' -f $msg.DequeueCount)
        Write-Warning ('[trigger] shard {0}/{1} failed {2} times -- parked in queue {3} for re-queue once the cause is fixed. This run is INCOMPLETE for that shard.' -f `
            ([int]$msg.Payload.ShardIndex + 1), [int]$msg.Payload.ShardCount, $msg.DequeueCount, $poison)
        # #475: the pipeline learns it now, by the part's FAILED marker -- not only when its wait runs out
        if ($msg.Payload.PSObject.Properties['RunId'] -and $msg.Payload.RunId) {
            try {
                . /app/engine/_shared/SI-CollectParts.ps1
                Write-SICollectPartMarker -Store (New-SICollectBlobStore -Account $global:SI_StorageAccount) -Engine $engine -RunId ([string]$msg.Payload.RunId) `
                    -Marker (New-SICollectPartMarker -Part ([int]$msg.Payload.ShardIndex) -State failed -Reason ('handed out {0} times without completing -- parked for re-queue' -f $msg.DequeueCount) -Worker ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME))
            } catch { Write-Warning ('[trigger] the part''s failed marker could not be written: {0}' -f $_.Exception.Message) }
            # the other parts' records are still published when this failed part was the last one marked
            if ($msg.Payload.PSObject.Properties['EngineRunId'] -and $msg.Payload.EngineRunId) {
                & $finishKedaRecords ([string]$msg.Payload.RunId) ([string]$msg.Payload.EngineRunId) ([string]$msg.Payload.CollectionTime)
            }
        }
        Publish-SILauncherTranscript -Engine $engine -Context $kctx | Out-Null
        exit 3
    }
    $queueMessageId    = $msg.Id
    $queueMessageReceipt = $msg.PopReceipt
    $shardIndex        = [int]$msg.Payload.ShardIndex
    $shardCount        = [int]$msg.Payload.ShardCount
    $collectionFromMsg = $msg.Payload.CollectionTime
    $collectRunId      = if ($msg.Payload.PSObject.Properties['RunId']) { [string]$msg.Payload.RunId } else { '' }
    $collectPhase      = if ($msg.Payload.PSObject.Properties['Phase']) { [string]$msg.Payload.Phase } else { '' }
    $collectEngineRun  = if ($msg.Payload.PSObject.Properties['EngineRunId']) { [string]$msg.Payload.EngineRunId } else { '' }
    [Environment]::SetEnvironmentVariable('SI_COLLECTION_TIME', $collectionFromMsg)
    Write-Host ('[trigger] shard {0}/{1}  CollectionTime={2}' -f ($shardIndex+1), $shardCount, $collectionFromMsg)
    # the heartbeat that keeps this worker's hold on the part. A part the queue says this worker no longer holds ENDS THIS
    # PROCESS (exit 4) from the heartbeat's own thread -- the worker's thread cannot be interrupted any other way, and a
    # part must never be written by two workers.
    $partWhat = 'part {0} of {1}' -f ($shardIndex + 1), $shardCount
    $beatAuth = $null; try { $beatAuth = Resolve-SIAzRestAuth } catch { $beatAuth = $null }
    # The heartbeat's thread starts EMPTY: it has nothing this entry point loaded. A worker that signs in with its managed
    # identity must hand it the managed-identity sign-in this script loaded above (line ". /app/auth/SI-ManagedIdentity.ps1")
    # -- without it the thread's first renewal failed ("the managed-identity sign-in helper is not loaded in this run") and
    # no heartbeat started in any container (the first live collection, 2026-10-13).
    $beatSignIn = @(); if ($global:SI_UseManagedIdentity) { $beatSignIn = @('/app/auth/SI-ManagedIdentity.ps1') }
    $partBeat = Start-SIWorkItemLeaseBeat -Context $kctx -QueueName $queueName -WorkItem $msg -LeaseSeconds $partLeaseSeconds `
                    -BeatSeconds ([Math]::Max(30, [int]($partLeaseSeconds / 5))) -Auth $beatAuth -SignInLibraries $beatSignIn -What $partWhat -ExitOnLost
    if ($partBeat -and $partBeat.Lost) {
        Write-Warning ('[trigger] {0}: another worker took the part before this one started on it -- nothing was collected here.' -f $partWhat)
        exit 4
    }
    if ($partBeat) {
        Write-Host ('[trigger] {0}: held for {1} minutes at a time, renewed every {2} s while this worker lives' -f $partWhat, [int]($partLeaseSeconds / 60), [int]($partBeat.BeatMs / 1000))
    } else {
        # NO HEARTBEAT: the part is held with ONE lease of 2 hours 5 minutes -- what a worker held its part with before the
        # heartbeat existed -- and the line says WHY the heartbeat did not start. NEVER the job's run limit (7 days since
        # 2026-10-13: a worker that died then kept its part locked for a week -- every worker, on the first live
        # collection, because the heartbeat's thread could not sign in). A part that takes longer than this lease may be
        # handed to a second worker: its records are stored under the part's own number and merged by record id, and the
        # part has one DONE marker, so the second worker's work is spent twice but the run's records are not doubled; a
        # part handed out more than SI_QUEUE_MAX_DEQUEUE times is parked.
        $beatWhy = [string](Get-SIWorkItemLeaseBeatStartError); if (-not $beatWhy) { $beatWhy = 'no reason was given' }
        $leaseSeconds = [Math]::Min($leaseSeconds, [int](Get-SIWorkItemFallbackLeaseSeconds))
        $long = Update-SIWorkItemLease -Context $kctx -QueueName $queueName -Id ([string]$msg.Id) -PopReceipt ([string]$msg.PopReceipt) -VisibilityTimeoutSeconds $leaseSeconds -RawText ([string]$msg.RawText)
        if ($long.Ok) { $queueMessageReceipt = [string]$long.PopReceipt }
        elseif ($long.Lost) { Write-Warning ('[trigger] {0}: another worker holds the part ({1}) -- nothing was collected here.' -f $partWhat, $long.Why); exit 4 }
        Write-Warning ('[trigger] {0}: the heartbeat that renews the hold on the part could not be started -- {1}. The part is held with one lease of {2} minutes instead{3}; a worker that dies keeps it that long.' -f $partWhat, $beatWhy, [int]($leaseSeconds / 60), $(if ($long.Ok) { '' } else { ' (that lease could not be set either: ' + [string]$long.Why + ' -- the part may be handed to a second worker after ' + [int]($partLeaseSeconds / 60) + ' minutes)' }))
    }
    # #475: a worker on a part of a producer's run hands its records over (Publish-SIRecords reads these), exactly as a
    # part of a run collected in one job does; the last worker publishes them all (below)
    if ($collectPhase -eq 'parts' -and $collectEngineRun) {
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts')
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PART', [string]$shardIndex)
        [Environment]::SetEnvironmentVariable('SI_COLLECT_PARTS', [string]$shardCount)
        [Environment]::SetEnvironmentVariable('SI_COLLECT_ENGINE_RUN', $collectEngineRun)
        # the producer's record bucket count -- the worker hands over into the same buckets (a message from before it: one per part)
        if ($msg.Payload.PSObject.Properties['RecordBuckets'] -and [int]$msg.Payload.RecordBuckets -ge 1) {
            [Environment]::SetEnvironmentVariable('SI_COLLECT_RECORD_BUCKETS', [string][int]$msg.Payload.RecordBuckets)
        }
    }
}

# #475: COLLECT IN PARTS, ONE AFTER ANOTHER -- a scheduled collection job (no queue) runs the engine as child processes of
# this one: DISCOVER once into parts (~10,000 objects each, the same parts a KEDA producer writes), then EACH PART in its
# own process. A finished process gives back all its memory, so the job's peak is one part, not the tenant (customer H,
# 2026-10-08: 27,800 identity objects ran out of memory at 8 GiB, the largest a consumption job has). A small tenant is
# one part. OPT-IN (SI_COLLECT_IN_PARTS = on) until the discovery process hands its provider records to the parts: most
# records are captured during Discover, and a discovery child that never reaches Output dropped them (ring 1 2026-10-08:
# Entra 1,726 / Exposure Graph 7,296 / Azure 494 records -> 0; the Defender records that remained had no key).
$collectChild = [string](Get-OptionalEnv 'SI_COLLECT_PHASE' '')
if ($collectChild -eq 'parts') {
    $collectPhase     = 'parts'
    $collectEngineRun = [string](Get-OptionalEnv 'SI_COLLECT_ENGINE_RUN' '')
    $shardIndex       = [int](Get-OptionalEnv 'SI_COLLECT_PART' 0)
    $shardCount       = [int](Get-OptionalEnv 'SI_COLLECT_PARTS' 1)
    Write-Host ('[parts] part {0} of {1} (run {2})' -f ($shardIndex + 1), $shardCount, $collectEngineRun)
}
$collectInParts = (-not $useQueue -and -not $producerDiscovers -and -not $collectChild -and $shardCount -le 1 -and
                   $engine -in @('identity', 'endpoint', 'azure') -and
                   ([string](Get-OptionalEnv 'SI_COLLECT_IN_PARTS' 'off')).Trim().ToLowerInvariant() -in @('on', 'true', '1', 'yes'))
if ($collectInParts) {
    $partsCt = [datetime]::UtcNow
    $ctEnv = Get-OptionalEnv 'SI_COLLECTION_TIME' $null
    if ($ctEnv) { try { $partsCt = [datetime]::Parse($ctEnv, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) } catch { } }
    $partsCt = [datetime]::SpecifyKind($partsCt.AddTicks(-($partsCt.Ticks % [TimeSpan]::TicksPerMinute)), [DateTimeKind]::Utc)   # every part: one CollectionTime
    $infoFile = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-collect-{0}-{1}.json' -f $engine, [guid]::NewGuid().ToString('N')))
    $selfScript = $PSCommandPath
    $runChild = {
        param([hashtable]$Vars)
        foreach ($k in $Vars.Keys) { [Environment]::SetEnvironmentVariable($k, [string]$Vars[$k]) }
        # the child's lines go to the console (the job's log), never into the exit code
        try { & pwsh -NoProfile -File $selfScript | Out-Host; $LASTEXITCODE }
        finally { foreach ($k in $Vars.Keys) { [Environment]::SetEnvironmentVariable($k, $null) } }
    }
    Write-Host ('[parts] {0}: discovering into parts, then each part in its own process' -f $engine)
    $dExit = & $runChild @{ SI_COLLECT_PHASE = 'discover'; SI_COLLECT_INFO_FILE = $infoFile; SI_COLLECTION_TIME = $partsCt.ToString('o') }
    if ($dExit -ne 0 -or -not (Test-Path -LiteralPath $infoFile)) {
        Write-Warning ('[parts] {0}: discovery did not finish (exit {1}) -- no part was collected this run.' -f $engine, $dExit)
        exit $(if ($dExit -gt 0) { $dExit } else { 1 })
    }
    $info = Get-Content -LiteralPath $infoFile -Raw | ConvertFrom-Json
    $parts = [Math]::Max(1, [int]$info.Parts)
    # the run's record buckets, as discovery decided them (#475); an older discovery: one per part
    $recordBuckets = $parts
    if ($info.PSObject.Properties['RecordBuckets'] -and [int]$info.RecordBuckets -ge 1) { $recordBuckets = [int]$info.RecordBuckets }
    Write-Host ('[parts] {0}: {1} part(s) to collect, the records in {2} bucket(s) (run {3})' -f $engine, $parts, $recordBuckets, $info.RunId)
    $failedParts = New-Object System.Collections.Generic.List[int]
    for ($p = 0; $p -lt $parts; $p++) {
        $pExit = & $runChild @{ SI_COLLECT_PHASE = 'parts'; SI_COLLECT_PART = $p; SI_COLLECT_PARTS = $parts; SI_COLLECT_RECORD_BUCKETS = $recordBuckets; SI_COLLECT_ENGINE_RUN = [string]$info.RunId; SI_COLLECTION_TIME = $partsCt.ToString('o') }
        if ($pExit -ne 0) { $failedParts.Add($p + 1); Write-Warning ('[parts] {0}: part {1} of {2} failed (exit {3}) -- the other parts go on.' -f $engine, ($p + 1), $parts, $pExit) }
    }
    Remove-Item -LiteralPath $infoFile -Force -ErrorAction SilentlyContinue
    # the run's records: discovery and every part handed theirs over; records processes merge and publish each once --
    # IN PARALLEL, one per CPU (#475: customer H's 96,551 records in one process outran the job's hour), each taking the
    # buckets b mod N = its slice; one at a time updates the table / rule (SI_INGEST_LOCK_FILE). #874: as many as the CPUs
    # and the free memory allow (Get-SIRecordsProcessCount), and the collection is closed ONCE by this process with every
    # records process's close -- the asset-drop guard judges the whole collection (Invoke-SIRecordsInProcesses)
    . /app/engine/_shared/SI-CollectParts.ps1
    . /app/engine/data-model/SI-RecordCapture.ps1
    . /app/engine/data-model/SI-RecordHandover.ps1
    $recProcs = Get-SIRecordsProcessCount -Buckets $recordBuckets -Processors ([Environment]::ProcessorCount) -FreeBytes (Get-SIRecordsProcessFreeBytes) `
        -Override ([int](Get-OptionalEnv 'SI_COLLECT_RECORDS_PARALLEL' 0))
    $recBase = @{ SI_COLLECT_PHASE = 'records'; SI_COLLECT_PARTS = $parts; SI_COLLECT_RECORD_BUCKETS = $recordBuckets; SI_COLLECT_ENGINE_RUN = [string]$info.RunId; SI_COLLECTION_TIME = $partsCt.ToString('o')
                  # #720: a failed part's objects have no records here -- the collection is published but never closed as complete
                  SI_COLLECT_PARTS_FAILED = $failedParts.Count }
    if ($recProcs -le 1) {
        $recBase['SI_COLLECT_RECORDS_SLICE'] = '0/1'
        $rExit = & $runChild $recBase
    } else {
        Write-Host ('[parts] {0}: publishing the records in {1} processes at once' -f $engine, $recProcs)
        $recPar = Invoke-SIRecordsInProcesses -Script $selfScript -Environment $recBase -Processes $recProcs -Engine $engine -CollectionTime $partsCt
        Write-Host ('[parts] {0}: {1} record(s) from {2} bucket(s) published by {3} processes{4}' -f $engine, $recPar.Records, $recPar.Buckets, $recPar.Processes, $(if ($recPar.Failed) { (', {0} bucket(s) failed' -f $recPar.Failed) } else { '' }))
        $rExit = 0
        if ([int]$recPar.Failed -gt 0 -or [int]$recPar.ExitCode -ne 0) { $rExit = 1 }
    }
    if ($rExit -ne 0) { Write-Warning ('[parts] {0}: the run''s records were not all published (exit {1}) -- the profiles are; the missing records are unknown, not gone.' -f $engine, $rExit) }
    if ($failedParts.Count -gt 0) {
        Write-Warning ('[parts] {0}: {1} of {2} part(s) failed ({3}) -- this run is INCOMPLETE for those objects; they are unknown, not gone.' -f $engine, $failedParts.Count, $parts, ($failedParts -join ', '))
        exit 1
    }
    if ($rExit -ne 0) { exit 1 }
    Write-Host ('[parts] {0}: all {1} part(s) collected, the records published.' -f $engine, $parts)
    exit 0
}

# #475: the RECORDS child of a run collected in parts -- every bucket the discovery and the parts handed over, merged and
# published once (the database; + the optional copy to Log Analytics, which the database never waits for), one bucket at a time.
if ($collectChild -eq 'records') {
    try {
        . /app/engine/_shared/SI-CollectParts.ps1
        . /app/engine/data-model/SI-RecordCapture.ps1
        . /app/engine/data-model/SI-RecordHandover.ps1
        $recRun = [string](Get-OptionalEnv 'SI_COLLECT_ENGINE_RUN' '')
        $recCt = [datetime]::Parse([string](Get-OptionalEnv 'SI_COLLECTION_TIME' ([datetime]::UtcNow.ToString('o'))), $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        # this process's slice of the buckets ("k/N"; none = all of them)
        $slice = 0; $slices = 1
        $sl = [string](Get-OptionalEnv 'SI_COLLECT_RECORDS_SLICE' '0/1')
        if ($sl -match '^(\d+)/(\d+)$' -and [int]$matches[2] -ge 1) { $slice = [int]$matches[1]; $slices = [int]$matches[2] }
        # #874: one of several records processes of the run (Invoke-SIRecordsInProcesses): it writes its buckets, hands its
        # result and its close back in this file, and the process that started it closes the whole collection once
        $recResultFile = [string](Get-OptionalEnv 'SI_COLLECT_RECORDS_RESULT_FILE' '')
        $res = Publish-SIRecordHandover -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine $engine -RunId $recRun `
            -RunContext ([pscustomobject]@{ CollectionTime = $recCt; RunId = $recRun }) -Slice $slice -Slices $slices -PartsFailed ([int](Get-OptionalEnv 'SI_COLLECT_PARTS_FAILED' 0)) `
            -DeferClose:([bool]$recResultFile)
        if ($recResultFile) {
            [IO.File]::WriteAllText($recResultFile, (ConvertTo-Json -InputObject ([ordered]@{ Buckets = [int]$res.Buckets; Records = [long]$res.Records; Failed = [int]$res.Failed
                ExportFailed = [int]$res.ExportFailed; Close = $res.Close }) -Compress -Depth 6))
        }
        Write-Host ('[parts] {0}: {1} record(s) published from {2} bucket(s){3}{4}' -f $engine, $res.Records, $res.Buckets, $(if ($slices -gt 1) { (' (slice {0} of {1})' -f ($slice + 1), $slices) } else { '' }), $(if ($res.Failed) { (', {0} bucket(s) failed' -f $res.Failed) } else { '' }))
        # the run's full asset metadata, once: by the first records process only (the others publish records slices)
        if ($slice -eq 0) { $null = & $publishAssetPropsHandover $recRun $recCt }
        # The database and Log Analytics are judged apart. A bucket that did not reach the DATABASE fails this process (the
        # collection is then not complete). The optional copy to Log Analytics (SI_LaExport) failing does not: the records
        # are in the database and the collection is closed there -- it is said, and the process ends well.
        if ($res.PSObject.Properties['ExportFailed'] -and [int]$res.ExportFailed -gt 0) {
            Write-Warning ('[parts] {0}: the copy of the records to Log Analytics failed for {1} batch(es) -- the records are in the database.' -f $engine, [int]$res.ExportFailed)
        }
        if ($res.Failed -gt 0) { exit 1 }
        exit 0
    } catch {
        Write-Warning ('[parts] {0}: the run''s records could not be published -- {1}' -f $engine, $_.Exception.Message)
        exit 1
    }
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

# 🔴 A GUARDED DOT-SOURCE OF /app/config/SecurityInsight.custom.ps1 STOOD HERE, WITH A COMMENT
# ASSERTING THAT `COPY . /app/` PUT THE FILE THERE. It does not, and it must not: `.dockerignore`
# excludes `**/config/` and `**/*.custom.ps1` on purpose, because they carry real tenant values and a
# container image is a shared artifact. MEASURED inside the built image 2026-09-08: `config_dir=False`,
# `custom_ps1=0`. So the Test-Path was ALWAYS false, the dot-source was unreachable, and the `else`
# branch -- a Write-Warning saying the engine "may throw on missing Path" -- was the only path taken,
# on every run, for ever. A warning that fires every single time teaches operators to ignore warnings.
#
# 🔒 REMOVED RATHER THAN REPAIRED, and the reason matters more than the removal. Restoring it would be
# actively harmful in two independent ways:
#   It ran AFTER the env-var hydration above, so a customer file would have OVERRIDDEN the SPN
#   credentials, workspace and storage account the Container App Job just supplied. The layering
#   was upside down for this host.
# "VM-launcher parity" was the wrong goal here: the container is its own configuration layer by
# design, and env vars are that layer. See #111.
#
# 📌 SI_CustomConfigPath is deliberately left unset. Invoke-SIEngineRun.ps1 derives a candidate path
# and "skips silently when nothing is found", which is the correct behaviour here -- there is nothing
# to find, by design.

$orchestrator = '/app/engine/asset-profiling/Invoke-SIEngineRun.ps1'
# What to collect and where to send it: the VM launcher's per-engine settings (SI_AssetLimit_<Engine>, SI_Sinks_<Engine>,
# SI_ForceFullRun_<Engine> -- from the config, the engine's launcher config or the Pro settings database), unless this
# job's own SI_ASSET_LIMIT / SI_SINKS / SI_FORCE_FULL_RUN is present.
$globalsForRun = @{}
foreach ($v in (Get-Variable -Scope Global)) { $globalsForRun[$v.Name] = $v.Value }
$runOpts = Resolve-SIContainerRunOptions -Engine $engine -Globals $globalsForRun
$orchArgs = @{
    Engine             = $engine
    StorageAccountName = $global:SI_StorageAccount
    Sinks              = $runOpts.Sinks
    AssetLimit         = $runOpts.AssetLimit
    ShardCount         = $shardCount
    ShardIndex         = $shardIndex
}
if ($runOpts.Source.AssetLimit -ne 'default' -or $runOpts.Source.Sinks -ne 'default') {
    Write-Host ('[run] sinks {0} ({1}); asset limit {2} ({3})' -f ($runOpts.Sinks -join ','), $runOpts.Source.Sinks, $runOpts.AssetLimit, $runOpts.Source.AssetLimit)
}
if ($collectionTime) { $orchArgs['CollectionTime'] = $collectionTime }
# #475: the producer discovers into parts; a worker whose message says 'parts' runs from Collect on its part of the
# producer's run (a message from the older producer carries no phase: the worker runs the whole engine, as before)
if ($producerDiscovers -or $collectChild -eq 'discover') { $orchArgs['Phase'] = 'discover'; $orchArgs['ShardCount'] = 1; $orchArgs['ShardIndex'] = 0 }
elseif ($collectPhase -eq 'parts' -and $collectEngineRun) { $orchArgs['Phase'] = 'parts'; $orchArgs['RunId'] = $collectEngineRun }
if ($runOpts.ForceFullRun) {
    $orchArgs['ForceFullRun'] = $true
    Write-Host ('[trigger] full run ({0}) -- bypassing fingerprint cache for this execution' -f $runOpts.Source.ForceFullRun)
}
# The resolver above decided (env > engine > tenant-wide, #257). The orchestrator also falls back to the tenant-wide
# global, so it is set to the decision: a job's SI_FORCE_FULL_RUN=0 then really means an incremental run.
$global:SI_ForceFullRun = [bool]$runOpts.ForceFullRun

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

# #475: a part whose records were not handed over is a failed part (the run's records would be quietly smaller) -- in
# the in-job run and on a KEDA worker alike; before the KEDA success block, so such a part is never marked done
if ($collectChild -eq 'parts' -and $global:SI_RecordHandoverFailed) {
    Write-Warning ('[parts] part {0}: its records were not handed over -- {1}' -f ($shardIndex + 1), $global:SI_RecordHandoverFailed)
    $orchExit = 1
    # #720: the engine's END said "success" for this part -- the part's own record says it is not complete
    try {
        if (-not (Get-Command -Name Get-SICollectHandoverFailure -ErrorAction SilentlyContinue)) { . /app/engine/_shared/SI-CollectParts.ps1 }
        $hf = Get-SICollectHandoverFailure -Engine $engine -ErrorText ([string]$global:SI_RecordHandoverFailed) -Where part -Part $shardIndex
        & $endRunNotComplete $hf $collectEngineRun $collectionTime $shardIndex $shardCount
    } catch { Write-Warning ('[parts] the failed part could not be recorded: {0}' -f $_.Exception.Message) }
}

# The heartbeat ends here: the part is finished or it failed. Its newest receipt is the one the delete needs. A part this
# worker no longer holds is never marked done (with -ExitOnLost the heartbeat has ended the process already; this covers
# the moment between its last beat and now).
if ($useQueue -and $partBeat) {
    $beatEnd = Stop-SIWorkItemLeaseBeat -Beat $partBeat
    if ($beatEnd) {
        if ($beatEnd.PopReceipt) { $queueMessageReceipt = [string]$beatEnd.PopReceipt }
        if ($beatEnd.Lost) {
            Write-Warning ('[trigger] part {0} of {1}: this worker no longer holds the part ({2}) -- it is not marked done here; the worker that holds it now finishes it.' -f ($shardIndex + 1), $shardCount, $beatEnd.Why)
            if ($orchExit -eq 0 -or $null -eq $orchExit) { $orchExit = 4 }
        }
    }
}

# KEDA mode: delete the queue message ONLY on clean orchestrator exit.
# A failed part keeps its message: it is visible again when the short lease
# ends (no heartbeat renews it any more) and KEDA starts a fresh worker for
# it; after SI_QUEUE_MAX_DEQUEUE hand-outs it is parked (above).
if ($useQueue -and $queueMessageId -and ($orchExit -eq 0 -or $null -eq $orchExit)) {
    try {
        Complete-SIWorkItem -Context $kctx -QueueName $queueName -Id $queueMessageId -PopReceipt $queueMessageReceipt
        Write-Host ('[trigger] shard message deleted (success).')
    } catch {
        Write-Warning ('[trigger] could not delete shard message: {0}' -f $_.Exception.Message)
    }
    # #475: the part's DONE marker -- the pipeline's Collect step ends when every part of the manifest has one
    if ($collectRunId) {
        # #720: the done marker is tried twice; still not written, the execution ends failed (exit 1) so it is seen -- the
        # message is gone already, so the pipeline would otherwise wait for this part with nothing saying why
        $doneWritten = $false; $doneWhy = ''
        foreach ($attempt in 1, 2) {
            try {
                . /app/engine/_shared/SI-CollectParts.ps1
                Write-SICollectPartMarker -Store (New-SICollectBlobStore -Account $global:SI_StorageAccount) -Engine $engine -RunId $collectRunId `
                    -Marker (New-SICollectPartMarker -Part $shardIndex -State done -Worker ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME))
                $doneWritten = $true; break
            } catch { $doneWhy = $_.Exception.Message; if ($attempt -eq 1) { [System.GC]::Collect(); Start-Sleep -Seconds 5 } }
        }
        if (-not $doneWritten) {
            Write-Warning ('[trigger] the part''s done marker could not be written: {0} -- the pipeline does not see this part as done; this execution ends failed so it is seen.' -f $doneWhy)
            $orchExit = 1
        }
        & $finishKedaRecords $collectRunId $collectEngineRun ([string]$collectionFromMsg)
    }
}

# #475 -- the producer that discovered into parts: the MANIFEST (the pipeline follows it) and one queue message per part
# (KEDA scales the workers on them). Only after a clean discovery: a failed one queues nothing, and the pipeline sees the
# producer's failure.
if ($producerDiscovers -and ($orchExit -eq 0 -or $null -eq $orchExit)) {
    # #720: how far the hand-over got -- a failure after the manifest marks the parts no worker will get as failed
    $pParts = 0; $pQueued = 0; $pManifest = $false; $pKey = ''; $pCt = $null; $pStore = $null
    try {
        $ri = $global:SI_CollectRunInfo
        if (-not $ri -or -not $ri.RunId) { throw 'the engine did not report its run' }
        $parts = [Math]::Max(1, [int]$ri.Parts)
        . /app/engine/_shared/SI-CollectParts.ps1
        . /app/engine/asset-profiling/storage/StorageContext.ps1
        . /app/engine/asset-profiling/storage/WorkerQueue.ps1
        $ct = if ($ri.CollectionTime) { ([datetime]$ri.CollectionTime).ToUniversalTime() } else { [datetime]::UtcNow }
        # the manifest and the part markers are keyed by this EXECUTION (the pipeline started it and polls it by name);
        # the engine's own run id -- where the parts are staged -- travels in every message as EngineRunId
        $collectKey = if ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME) { [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME } else { [string]$ri.RunId }
        $pParts = $parts; $pKey = $collectKey; $pCt = $ct
        # the records discovery captured go to the parts' buckets first -- under the ENGINE run id, where the workers hand
        # theirs over too; the last worker publishes them all
        # the capture's functions in THIS scope (the engine loaded them in its own): the count and the stream's close, which the
        # hand-over needs to read the streamed records whole (2105 live: "Get-SIRecordCaptureCount is not recognized")
        . /app/engine/data-model/SI-RecordCapture.ps1
        . /app/engine/data-model/SI-RecordHandover.ps1
        # the run's record bucket count (~5,000 records each, at least the parts): discovery decides it, the manifest and
        # every message carry it, and every worker hands its records over into the same buckets
        $recordBuckets = 1
        if ($global:SIRecordCaptureState) { $recordBuckets = Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount) -Parts $parts }   # #721: held + streamed
        else { $recordBuckets = [Math]::Max(1, $parts) }
        $handed = Save-SIRecordHandover -Store (New-SICollectBlobStore -Account $global:SI_StorageAccount) -Engine $engine -RunId ([string]$ri.RunId) -Who 'discover' -Buckets $recordBuckets
        Write-Host ('[producer] {0} record(s) from discovery handed over into {1} bucket(s)' -f $handed, $recordBuckets)
        # full asset metadata (SI_AssetProperties = full): the objects discovery kept go over too -- the last worker publishes
        # the run's full metadata once (SI-AssetPropertiesHandover.ps1). Without it nothing was ever published in queue mode.
        & $saveDiscoverAssetProps ([string]$ri.RunId)
        $pStore = New-SICollectBlobStore -Account $global:SI_StorageAccount
        Write-SICollectManifest -Store $pStore -Manifest (New-SICollectManifest -Engine $engine -RunId $collectKey -CollectionTime $ct -Parts $parts -ProducerExecution $collectKey -EngineRunId ([string]$ri.RunId) -RecordsHandover -RecordBuckets $recordBuckets)
        $pManifest = $true
        $pctx = New-SIStorageContext -AccountName $global:SI_StorageAccount
        $pq = ('si-{0}-shards' -f $engine)
        Initialize-SIQueue -Context $pctx -QueueName $pq | Out-Null
        for ($i = 0; $i -lt $parts; $i++) {
            Add-SIWorkItem -Context $pctx -QueueName $pq -Payload @{ ShardIndex = $i; ShardCount = $parts; CollectionTime = $ct.ToString('o'); RunId = $collectKey; EngineRunId = $ri.RunId; Phase = 'parts'; RecordBuckets = $recordBuckets; EnqueuedAt = ([datetime]::UtcNow.ToString('o')) }
            $pQueued = $i + 1
        }
        Write-Host ('[producer] {0} part(s) queued on {1} (run {2})' -f $parts, $pq, $ri.RunId)
    } catch {
        $pErr = $_.Exception.Message
        Write-Warning ('[producer] the parts could not be queued: {0}' -f $pErr)
        $orchExit = 1
        # #720: NOT COMPLETE, said where the run's health and the pipeline read it -- never "success" over a lost hand-over
        try {
            if (-not (Get-Command -Name Get-SICollectHandoverFailure -ErrorAction SilentlyContinue)) { . /app/engine/_shared/SI-CollectParts.ps1 }
            $pFail = Get-SICollectHandoverFailure -Engine $engine -ErrorText $pErr -Where producer -Parts $pParts -Queued $pQueued -ManifestWritten:$pManifest
            if (@($pFail.FailParts).Count -gt 0 -and $pStore -and $pKey) {
                $pw = Write-SICollectHandoverFailure -Store $pStore -Engine $engine -RunId $pKey -Failure $pFail -Worker ([string]$env:CONTAINER_APP_JOB_EXECUTION_NAME)
                Write-Warning ('[producer] {0} of {1} part(s) were not queued and are marked failed{2}' -f $pw.Written, $pParts, $(if ($pw.Why) { ' (not all: ' + $pw.Why + ')' } else { '' }))
            }
            & $endRunNotComplete $pFail $(if ($ri -and $ri.RunId) { [string]$ri.RunId } else { '' }) $pCt
        } catch { Write-Warning ('[producer] the failed hand-over could not be recorded: {0}' -f $_.Exception.Message) }
    }
}


# #475: a discovery child of a job that collects in parts hands its run (id, parts, collection time) to its parent
if ($collectChild -eq 'discover' -and ($orchExit -eq 0 -or $null -eq $orchExit)) {
    try {
        $ri = $global:SI_CollectRunInfo
        if (-not $ri -or -not $ri.RunId) { throw 'the engine did not report its run' }
        # the records discovery captured go to the parts' buckets first (the run's last step publishes them with the rest)
        . /app/engine/_shared/SI-CollectParts.ps1
        . /app/engine/data-model/SI-RecordCapture.ps1   # the count and the stream's close in THIS scope (see the producer above)
        . /app/engine/data-model/SI-RecordHandover.ps1
        # the run's record buckets: ~5,000 records each, at least one per part (#475) -- every process of the run uses it
        $recordBuckets = Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount) -Parts ([Math]::Max(1, [int]$ri.Parts))   # #721: held + streamed
        $handed = Save-SIRecordHandover -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine $engine -RunId ([string]$ri.RunId) `
            -Who 'discover' -Buckets $recordBuckets
        Write-Host ('[parts] {0}: {1} record(s) from discovery handed over' -f $engine, $handed)
        & $saveDiscoverAssetProps ([string]$ri.RunId)
        [IO.File]::WriteAllText([string](Get-OptionalEnv 'SI_COLLECT_INFO_FILE' ''), (ConvertTo-Json -InputObject ([ordered]@{ RunId = [string]$ri.RunId; Parts = [int]$ri.Parts; RecordBuckets = $recordBuckets }) -Compress))
    } catch {
        $dErr = $_.Exception.Message
        Write-Warning ('[parts] the discovered run could not be handed over: {0}' -f $dErr)
        $orchExit = 1
        # #720: the engine's END said "success" -- the run's own record says it is not complete (no part runs: the parent stops)
        try {
            if (-not (Get-Command -Name Get-SICollectHandoverFailure -ErrorAction SilentlyContinue)) { . /app/engine/_shared/SI-CollectParts.ps1 }
            $dFail = Get-SICollectHandoverFailure -Engine $engine -ErrorText $dErr -Where discover
            & $endRunNotComplete $dFail $(if ($ri -and $ri.RunId) { [string]$ri.RunId } else { '' }) $collectionTime
        } catch { Write-Warning ('[parts] the failed hand-over could not be recorded: {0}' -f $_.Exception.Message) }
    }
}

# #55.1(b) -- the run log follows the run output to the staging container. This
# runs on BOTH outcomes: a failed orchestrator was caught above and set $orchExit
# rather than terminating, and its transcript is the one worth keeping. In KEDA
# mode $kctx already exists for the shard queue, so reuse it rather than building
# a second context for the same account.
$runLogCtx = if ($useQueue -and $kctx) { $kctx } else { New-SIRunLogStorageContext }
Publish-SILauncherTranscript -Engine $engine -Context $runLogCtx | Out-Null

if ($orchExit -gt 0) { exit $orchExit }
