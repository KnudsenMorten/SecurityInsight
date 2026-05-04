#Requires -Version 5.1
#Requires -Modules Az.Accounts, Az.Resources
<#
    SecurityInsight v2.2 -- one-shot Azure Container Apps Job bootstrap.

    Provisions the production runtime for the orchestrator:
      * Azure Container Registry (ACR) -- holds the orchestrator image
      * Builds the image server-side via `az acr build` (no local Docker)
      * Container Apps Environment (CAE) -- managed Kubernetes-backed runtime
      * Container App Job per engine -- runs the orchestrator on schedule

    Idempotent: each step checks if the resource exists and reuses it.

    Pre-requisites:
      * Az PowerShell modules + az CLI installed locally
      * Customer's config/SecurityInsight.custom.ps1 already populated
        with SI_StorageAccount/Key, SI_Graph_*, SI_LogIngest_*,
        SI_WorkspaceResourceId, SI_DceName, SI_DcrResourceGroup, OpenAI_*
      * az login already done

    Schedule trigger uses cron (UTC). Default schedule: daily at 04:00 UTC
    for endpoint, 04:30 UTC for identity. Override via $ScheduleEndpoint
    / $ScheduleIdentity.
#>

[CmdletBinding()]
param(
    # every parameter has a default. Customers don't need to
    # pass any args -- the cmdlet runs as `.\Bootstrap-ContainerAppJob.ps1`
    # if they prefer.
    #
    # Layered resolution (last word wins):
    #   1. param-block default (shipping)
    #   2. $global:SI_Bootstrap_<ParamName> / $global:SI_RiskAnalysis_<Suffix> in
    #      config/SecurityInsight.custom.ps1
    #   3. -<ParamName> on the CLI
    [Parameter()][string]$ResourceGroupName  = 'rg-securityinsight',
    [Parameter()][string]$Location           = 'westeurope',
    [Parameter()][string]$AcrName            = 'acrsecurityinsight',
    [Parameter()][string]$EnvName            = 'cae-securityinsight',
    [Parameter()][string]$ImageTag           = 'latest',
    [Parameter()][string[]]$Engines               = @('endpoint','identity','azure','schema-discovery','risk-analysis'),
    [Parameter()][string]$ScheduleEndpoint        = '0 4 * * *',     # 04:00 UTC daily
    [Parameter()][string]$ScheduleIdentity        = '30 4 * * *',    # 04:30 UTC daily
    [Parameter()][string]$ScheduleAzure           = '0 5 * * *',     # 05:00 UTC daily
    [Parameter()][string]$ScheduleSchemaDiscovery = '0 3 * * 0',     # 03:00 UTC every Sunday
    [Parameter()][string]$ScheduleRiskAnalysis    = '0 6 * * *',     # 06:00 UTC daily (after collection)
    [Parameter()][int]$ParallelismEndpoint        = 1,
    [Parameter()][int]$ParallelismIdentity        = 1,
    [Parameter()][int]$ParallelismAzure           = 1,
    [Parameter()][int]$ParallelismSchemaDiscovery = 1,
    # Risk Analysis is a single-container report build -- no parallelism. Heavy
    # tenants stay under the Defender 30k-row ceiling via dynamic bucketing
    # inside the one container, not by sharding across containers.
    [Parameter()][int]$ParallelismRiskAnalysis    = 1,
    # RA-specific knobs. Engine reads these via env vars; see
    # container/Start-RiskAnalysisInContainer.ps1 for the full surface.
    [Parameter()][string]$RiskAnalysisReportTemplate    = 'RiskAnalysis_Summary_Bucket',
    [Parameter()][string]$RiskAnalysisMode              = 'Summary',          # Summary | Detailed
    # ExportDestination defaults to $null at the param layer; the
    # post-load resolver derives a default from $global:SI_StorageAccount +
    # the canonical 'sistaging' container ('sistaging/risk-analysis/<prefix>/'),
    # so RA reports land in the same storage account as collection-stage shards.
    [Parameter()][string]$RiskAnalysisExportDestination = $null,
    [Parameter()][string]$RiskAnalysisExportContainer   = 'sistaging',
    [Parameter()][string]$RiskAnalysisExportPrefix      = 'risk-analysis',
    [Parameter()][switch]$RiskAnalysisSendToLogAnalytics,
    [Parameter()][switch]$RiskAnalysisBuildSummaryByAI,
    [Parameter()][switch]$SkipImageBuild,
    [Parameter()][switch]$TriggerNowAfter,
    [Parameter()][switch]$UseManagedIdentity,                    # provision UAMI per engine + assign to Job

    # KEDA queue-driven workers: idle = 0 replicas, scale-up = #queue-msgs.
    # When set, each engine gets TWO Container App Jobs:
    #   * caj-si-{engine}-producer  -- cron-triggered, pushes N shard
    #     messages onto si-{engine}-shards queue once per schedule.
    #   * caj-si-{engine}-worker    -- event-triggered (KEDA azure-queue
    #     scaler), each replica pops one message and runs that shard.
    # When NOT set: legacy single-job-per-engine schedule trigger (today).
    [Parameter()][switch]$UseKEDA,
    [Parameter()][int]$KedaMaxReplicas      = 30                 # cap on concurrent worker replicas (Consumption profile soft-cap)
)

$ErrorActionPreference = 'Stop'

# Snapshot CLI-bound params at script scope BEFORE entering any function.
# Inside a function, $PSBoundParameters refers to the function's bound params,
# not the caller's. Same pattern the launchers use.
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $true }

# Load customer config -- bootstrap pulls secrets from here to wire into the Job
$customFile = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\config\SecurityInsight.custom.ps1'
if (-not (Test-Path $customFile)) { throw "$customFile not found -- run Bootstrap-Auth.ps1 first" }
. $customFile

# layered-config resolver. CLI explicit > $global:SI_Bootstrap_*
# / $global:SI_RiskAnalysis_* (custom file) > shipping default. After this
# block, the param-block locals carry the effective values.
function _Apply-CustomDefault {
    param(
        [Parameter(Mandatory)][string]$ParamName,
        [Parameter(Mandatory)][string]$GlobalName
    )
    if ($cliBound.ContainsKey($ParamName)) { return }                    # CLI wins
    $g = Get-Variable -Name $GlobalName -ValueOnly -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $g) { return }
    if ($g -is [string] -and [string]::IsNullOrWhiteSpace($g)) { return }
    Set-Variable -Name $ParamName -Value $g -Scope Script
}

# Bootstrap-wide knobs (one custom-file global per param, SI_Bootstrap_<Name>).
_Apply-CustomDefault -ParamName 'ResourceGroupName'        -GlobalName 'SI_Bootstrap_ResourceGroupName'
_Apply-CustomDefault -ParamName 'Location'                 -GlobalName 'SI_Bootstrap_Location'
_Apply-CustomDefault -ParamName 'AcrName'                  -GlobalName 'SI_Bootstrap_AcrName'
_Apply-CustomDefault -ParamName 'EnvName'                  -GlobalName 'SI_Bootstrap_EnvName'
_Apply-CustomDefault -ParamName 'ImageTag'                 -GlobalName 'SI_Bootstrap_ImageTag'
_Apply-CustomDefault -ParamName 'Engines'                  -GlobalName 'SI_Bootstrap_Engines'
_Apply-CustomDefault -ParamName 'ScheduleEndpoint'         -GlobalName 'SI_Bootstrap_ScheduleEndpoint'
_Apply-CustomDefault -ParamName 'ScheduleIdentity'         -GlobalName 'SI_Bootstrap_ScheduleIdentity'
_Apply-CustomDefault -ParamName 'ScheduleAzure'            -GlobalName 'SI_Bootstrap_ScheduleAzure'
_Apply-CustomDefault -ParamName 'ScheduleSchemaDiscovery'  -GlobalName 'SI_Bootstrap_ScheduleSchemaDiscovery'
_Apply-CustomDefault -ParamName 'ScheduleRiskAnalysis'     -GlobalName 'SI_Bootstrap_ScheduleRiskAnalysis'
_Apply-CustomDefault -ParamName 'ParallelismEndpoint'      -GlobalName 'SI_Bootstrap_ParallelismEndpoint'
_Apply-CustomDefault -ParamName 'ParallelismIdentity'      -GlobalName 'SI_Bootstrap_ParallelismIdentity'
_Apply-CustomDefault -ParamName 'ParallelismAzure'         -GlobalName 'SI_Bootstrap_ParallelismAzure'
_Apply-CustomDefault -ParamName 'ParallelismSchemaDiscovery' -GlobalName 'SI_Bootstrap_ParallelismSchemaDiscovery'
_Apply-CustomDefault -ParamName 'ParallelismRiskAnalysis'  -GlobalName 'SI_Bootstrap_ParallelismRiskAnalysis'
_Apply-CustomDefault -ParamName 'KedaMaxReplicas'          -GlobalName 'SI_Bootstrap_KedaMaxReplicas'

# RA-specific knobs (custom-file globals named SI_RiskAnalysis_<Suffix> --
# matches the existing $global:SI_RiskAnalysis_* convention used in
# LAUNCHERS/SecurityInsight_RiskAnalysis/LauncherConfig.defaults.ps1).
_Apply-CustomDefault -ParamName 'RiskAnalysisReportTemplate'    -GlobalName 'SI_RiskAnalysis_ReportTemplate'
_Apply-CustomDefault -ParamName 'RiskAnalysisMode'              -GlobalName 'SI_RiskAnalysis_Mode'
_Apply-CustomDefault -ParamName 'RiskAnalysisExportDestination' -GlobalName 'SI_RiskAnalysis_ExportDestination'
_Apply-CustomDefault -ParamName 'RiskAnalysisExportContainer'   -GlobalName 'SI_RiskAnalysis_ExportContainer'
_Apply-CustomDefault -ParamName 'RiskAnalysisExportPrefix'      -GlobalName 'SI_RiskAnalysis_ExportPrefix'

# Switches: PowerShell switches default to $false unless -Switch passed. The
# resolver pattern is slightly different -- a custom-file bool overrides only
# when the CLI didn't bind the switch.
function _Apply-CustomSwitch {
    param([Parameter(Mandatory)][string]$ParamName, [Parameter(Mandatory)][string]$GlobalName)
    if ($cliBound.ContainsKey($ParamName)) { return }
    $g = Get-Variable -Name $GlobalName -ValueOnly -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $g) { return }
    Set-Variable -Name $ParamName -Value ([switch][bool]$g) -Scope Script
}
_Apply-CustomSwitch -ParamName 'RiskAnalysisSendToLogAnalytics' -GlobalName 'SI_RiskAnalysis_SendToLogAnalytics'
_Apply-CustomSwitch -ParamName 'RiskAnalysisBuildSummaryByAI'   -GlobalName 'SI_RiskAnalysis_BuildSummaryByAI'
_Apply-CustomSwitch -ParamName 'SkipImageBuild'                 -GlobalName 'SI_Bootstrap_SkipImageBuild'
_Apply-CustomSwitch -ParamName 'TriggerNowAfter'                -GlobalName 'SI_Bootstrap_TriggerNowAfter'
_Apply-CustomSwitch -ParamName 'UseManagedIdentity'             -GlobalName 'SI_Bootstrap_UseManagedIdentity'
_Apply-CustomSwitch -ParamName 'UseKEDA'                        -GlobalName 'SI_Bootstrap_UseKEDA'

# Auto-derive RA ExportDestination from the v2.2 staging storage account
#. The customer's config already populates $global:SI_StorageAccount;
# we just compose the canonical URL: https://<acct>.blob.core.windows.net/sistaging/risk-analysis/.
# Customer can still override via -RiskAnalysisExportDestination on the CLI
# OR $global:SI_RiskAnalysis_ExportDestination in the custom file (above
# resolver runs first, so an explicit value wins).
if ([string]::IsNullOrWhiteSpace($RiskAnalysisExportDestination) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_StorageAccount)) {
    $prefixSegment = $RiskAnalysisExportPrefix.Trim('/')
    $RiskAnalysisExportDestination = if ([string]::IsNullOrWhiteSpace($prefixSegment)) {
        ('https://{0}.blob.core.windows.net/{1}/' -f $global:SI_StorageAccount, $RiskAnalysisExportContainer)
    } else {
        ('https://{0}.blob.core.windows.net/{1}/{2}/' -f $global:SI_StorageAccount, $RiskAnalysisExportContainer, $prefixSegment)
    }
    Write-Host ('[risk-analysis] auto-derived ExportDestination = {0}' -f $RiskAnalysisExportDestination)
    Write-Host '             (override via -RiskAnalysisExportDestination or $global:SI_RiskAnalysis_ExportDestination in custom file)'
}

# single-SPN model (SI_SPN_*). Backwards-compat fallback to
# legacy SI_Graph_* / SI_LogIngest_* names.
$reqGlobals = @(
    'SI_StorageAccount','SI_StorageKey',
    'SI_WorkspaceResourceId','SI_DceName','SI_DcrResourceGroup',
    'OpenAI_apiKey','OpenAI_endpoint','OpenAI_deployment','OpenAI_apiVersion'
)
$spnRequired = @('SI_SPN_AppId','SI_SPN_Secret','SI_SPN_TenantId','SI_SPN_ObjectId')
$haveNewSpn = $true
foreach ($n in $spnRequired) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $n -ValueOnly -Scope Global -ErrorAction SilentlyContinue))) { $haveNewSpn = $false; break }
}
if (-not $haveNewSpn) {
    # Fall back to legacy names. If those are also missing, fail with clear message.
    $reqGlobals += @('SI_Graph_AppId','SI_Graph_Secret','SI_Graph_TenantId',
                     'SI_LogIngest_AppId','SI_LogIngest_Secret','SI_LogIngest_TenantId','SI_LogIngest_ObjectId')
} else {
    $reqGlobals += $spnRequired
}
foreach ($req in $reqGlobals) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $req -ValueOnly -Scope Global -ErrorAction SilentlyContinue))) {
        throw "Required global `$global:$req is empty in $customFile (run Bootstrap-Auth.ps1 first to populate from KV)"
    }
}

# Resolve effective SPN values (new names win, legacy fallback).
$spnAppId    = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_Graph_AppId }
$spnSecret   = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_Graph_Secret }
$spnTenantId = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_Graph_TenantId }
$spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }

$subId = (Get-AzContext).Subscription.Id

Write-Host ''
Write-Host '=== SecurityInsight v2.2 Container App Job bootstrap ==='
Write-Host ('  Subscription : {0}' -f $subId)
Write-Host ('  RG           : {0}' -f $ResourceGroupName)
Write-Host ('  Location     : {0}' -f $Location)
Write-Host ('  ACR          : {0}' -f $AcrName)
Write-Host ('  CAE          : {0}' -f $EnvName)
Write-Host ('  Engines      : {0}' -f ($Engines -join ', '))
Write-Host ''

# ---- 1. ACR ----
# az CLI prints ResourceNotFound to stderr; under strict ErrorActionPreference
# that's treated as a terminating error. Switch to Continue around az calls
# and key off $LASTEXITCODE manually.
function Invoke-AzJson { param([Parameter(Mandatory)][string[]]$AzArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        $out = & az @AzArgs 2>$null
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($out -join ''))) { return $null }
    return ($out -join "`n" | ConvertFrom-Json -ErrorAction SilentlyContinue)
}
function Invoke-Az { param([Parameter(Mandatory)][string[]]$AzArgs, [switch]$AllowFailure)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & az @AzArgs 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) {
        throw ('az ' + ($AzArgs -join ' ') + ' failed: ' + ($out -join "`n"))
    }
    return $out
}

# ---- 0. Resource provider registrations ----
# Required for Container Apps. The containerapp extension's auto-register
# path has a Python bug on older az versions; do it ourselves.
Write-Host '[0/5] Ensuring resource providers are registered ...'
foreach ($rp in @('Microsoft.App','Microsoft.OperationalInsights','Microsoft.ContainerRegistry','Microsoft.Insights')) {
    $state = (Invoke-Az @('provider','show','--namespace',$rp,'--query','registrationState','-o','tsv')).Trim()
    if ($state -ne 'Registered') {
        Write-Host ('       Registering {0} ...' -f $rp)
        Invoke-Az @('provider','register','--namespace',$rp,'--wait','--output','none') | Out-Null
    }
    Write-Host ('       {0,-35} {1}' -f $rp, 'Registered')
}

Write-Host '[1/5] Ensuring Azure Container Registry ...'
$acr = Invoke-AzJson @('acr','show','--name',$AcrName,'--resource-group',$ResourceGroupName)
if (-not $acr) {
    Write-Host '       Creating ACR (Basic SKU, ~$5/mo) ...'
    Invoke-Az @('acr','create','--name',$AcrName,'--resource-group',$ResourceGroupName,'--location',$Location,'--sku','Basic','--admin-enabled','true','--output','none') | Out-Null
    $acr = Invoke-AzJson @('acr','show','--name',$AcrName,'--resource-group',$ResourceGroupName)
}
Write-Host ('       loginServer = {0}' -f $acr.loginServer)

# ---- 2. Image build ----
$image = ('{0}/si-orchestrator:{1}' -f $acr.loginServer, $ImageTag)
if ($SkipImageBuild) {
    Write-Host '[2/5] Skipping image build (-SkipImageBuild).'
} else {
    Write-Host ('[2/5] Building image via ACR Tasks: {0} ...' -f $image)
    # Build context is SOLUTIONS/SecurityInsight/. Dockerfile lives at
    # container/Dockerfile relative to that context; whole tree (engine, auth,
    # launcher, setup, etc.) gets copied verbatim into /app/.
    Push-Location 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight'
    try {
        # --no-wait queues the build server-side and returns immediately.
        # The CLI's log-streaming path crashes on Windows (colorama / non-tty
        # stdout); --no-wait sidesteps that. Then poll task list-runs until
        # the build completes (Succeeded / Failed).
        Invoke-Az @('acr','build','--registry',$AcrName,'--image',('si-orchestrator:{0}' -f $ImageTag),'--file','container/Dockerfile','--no-wait','.','--output','none') | Out-Null
        Write-Host '       build queued -- polling for completion ...'
        $deadline = (Get-Date).AddMinutes(15)
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 30
            $latest = Invoke-AzJson @('acr','task','list-runs','--registry',$AcrName,'--top','1')
            if (-not $latest) { continue }
            $r = $latest[0]
            Write-Host ('         {0} -- {1}' -f $r.runId, $r.status)
            if ($r.status -in 'Succeeded','Failed','Cancelled','Error') { break }
        }
        if ($r.status -ne 'Succeeded') { throw ('image build did not succeed: ' + $r.status) }
    } finally {
        Pop-Location
    }
    Write-Host '       build OK.'
}

# ---- 3. Container Apps Environment ----
Write-Host '[3/5] Ensuring Container Apps Environment ...'
$cae = Invoke-AzJson @('containerapp','env','show','--name',$EnvName,'--resource-group',$ResourceGroupName)
if (-not $cae) {
    Write-Host '       Creating CAE (Consumption profile, ~$0 idle) ...'
    Invoke-Az @('containerapp','env','create','--name',$EnvName,'--resource-group',$ResourceGroupName,'--location',$Location,'--output','none') | Out-Null
}
Write-Host '       OK.'

# ---- 4. Container App Jobs (one per engine) ----
$acrCreds = Invoke-AzJson @('acr','credential','show','--name',$AcrName)
$acrUser  = $acrCreds.username
$acrPass  = $acrCreds.passwords[0].value

foreach ($engine in $Engines) {
    # Risk Analysis is a different beast (report build, not collection). Compute
    # the flag up-front so it can gate job naming + KEDA decisions consistently.
    $isRiskAnalysis = ($engine -eq 'risk-analysis')

    # KEDA mode creates two jobs per engine; legacy + RA mode create one. RA
    # never participates in KEDA even when -UseKEDA is passed -- it's a single-
    # container report build, not a per-asset shard workload.
    $producerName = ('caj-si-{0}-producer' -f $engine)
    $workerName   = ('caj-si-{0}-worker' -f $engine)
    $jobName      = if ($UseKEDA -and -not $isRiskAnalysis) { $workerName } else { ('caj-si-{0}' -f $engine) }
    $schedule    = switch ($engine) {
        'identity'         { $ScheduleIdentity }
        'azure'            { $ScheduleAzure }
        'schema-discovery' { $ScheduleSchemaDiscovery }
        'risk-analysis'    { $ScheduleRiskAnalysis }
        default            { $ScheduleEndpoint }
    }
    $parallelism = switch ($engine) {
        'identity'         { $ParallelismIdentity }
        'azure'            { $ParallelismAzure }
        'schema-discovery' { $ParallelismSchemaDiscovery }
        'risk-analysis'    { $ParallelismRiskAnalysis }
        default            { $ParallelismEndpoint }
    }
    # (Note: $isRiskAnalysis was computed at the top of the loop body so
    # $jobName resolution above could honour it. Behavioural notes:
    #   * uses a different entrypoint (Start-RiskAnalysisInContainer.ps1)
    #   * runs longer (more KQL round-trips) -- bigger replica timeout
    #   * needs more memory (Excel build can hold the whole dataset) -- 4GiB
    #   * does NOT support sharding (single replica; bucketing handles scale inside)
    #   * does NOT participate in KEDA queue scaling)

    # ---- 4a. Provision UAMI + grant roles ----
    $uamiClientId = $null
    if ($UseManagedIdentity) {
        $uamiName = ('uami-si-{0}' -f $engine)
        Write-Host ('       Ensuring UAMI {0} ...' -f $uamiName)
        $uami = Invoke-AzJson @('identity','show','--name',$uamiName,'--resource-group',$ResourceGroupName)
        if (-not $uami) {
            Invoke-Az @('identity','create','--name',$uamiName,'--resource-group',$ResourceGroupName,'--location',$Location,'--output','none') | Out-Null
            $uami = Invoke-AzJson @('identity','show','--name',$uamiName,'--resource-group',$ResourceGroupName)
        }
        $uamiClientId   = $uami.clientId
        $uamiPrincipalId = $uami.principalId
        $uamiResourceId  = $uami.id
        Write-Host ('         clientId   = {0}' -f $uamiClientId)
        Write-Host ('         principal  = {0}' -f $uamiPrincipalId)

        # Grant Monitoring Metrics Publisher on the DCR RG (for DCR ingest)
        $dcrRgScope = ('/subscriptions/{0}/resourceGroups/{1}' -f $subId, $global:SI_DcrResourceGroup)
        $existingMmp = Invoke-AzJson @('role','assignment','list','--assignee',$uamiPrincipalId,'--scope',$dcrRgScope,'--role','Monitoring Metrics Publisher')
        if (-not $existingMmp) {
            Write-Host '         granting Monitoring Metrics Publisher on rg-dce-securityinsight ...'
            Invoke-Az @('role','assignment','create','--assignee-object-id',$uamiPrincipalId,'--assignee-principal-type','ServicePrincipal','--role','Monitoring Metrics Publisher','--scope',$dcrRgScope,'--output','none') -AllowFailure | Out-Null
        }

        # Grant Storage Blob / Table / Queue Data Contributor on the v2.2
        # storage account so the container can use OAuth for fingerprint
        # cache + staging blobs + worker queues -- removes the storage key
        # secret from container env vars.
        $stgScope = (Invoke-AzJson @('storage','account','show','--name',$global:SI_StorageAccount,'--query','id','-o','json'))
        if ($stgScope) {
            foreach ($role in @('Storage Blob Data Contributor','Storage Table Data Contributor','Storage Queue Data Contributor')) {
                $existing = Invoke-AzJson @('role','assignment','list','--assignee',$uamiPrincipalId,'--scope',$stgScope,'--role',$role)
                if (-not $existing) {
                    Write-Host ('         granting {0} on {1} ...' -f $role, $global:SI_StorageAccount)
                    Invoke-Az @('role','assignment','create','--assignee-object-id',$uamiPrincipalId,'--assignee-principal-type','ServicePrincipal','--role',$role,'--scope',$stgScope,'--output','none') -AllowFailure | Out-Null
                }
            }
        }

        # Azure engine needs Reader on every visible subscription so Search-AzGraph
        # can enumerate resources. Grant at the subscription level for the current
        # context's sub; multi-sub customers should extend manually or pass
        # -SubscriptionIds to the discovery connector via $global:SI_AzureResourceSubscriptions.
        if ($engine -eq 'azure') {
            $subScope = ('/subscriptions/{0}' -f $subId)
            $existingReader = Invoke-AzJson @('role','assignment','list','--assignee',$uamiPrincipalId,'--scope',$subScope,'--role','Reader')
            if (-not $existingReader) {
                Write-Host ('         granting Reader on subscription {0} (azure engine) ...' -f $subId)
                Invoke-Az @('role','assignment','create','--assignee-object-id',$uamiPrincipalId,'--assignee-principal-type','ServicePrincipal','--role','Reader','--scope',$subScope,'--output','none') -AllowFailure | Out-Null
            }
        }

        # Grant Microsoft Graph app roles (ThreatHunting.Read.All + Device.Read.All
        # + User.Read.All + Application.Read.All). Done via Graph REST since
        # az CLI doesn't have first-class commands for app-role assignment.
        Write-Host '         granting Microsoft Graph app roles ...'
        $graphTokenObj = Invoke-AzJson @('account','get-access-token','--resource','https://graph.microsoft.com')
        $graphSpResp   = Invoke-RestMethod -Method Get `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" `
            -Headers @{ Authorization = ('Bearer ' + $graphTokenObj.accessToken) }
        $graphSpId = $graphSpResp.value[0].id
        $existingAssignments = (Invoke-RestMethod -Method Get `
            -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$uamiPrincipalId/appRoleAssignments" `
            -Headers @{ Authorization = ('Bearer ' + $graphTokenObj.accessToken) }).value
        foreach ($roleName in @('ThreatHunting.Read.All','Device.Read.All','User.Read.All','Application.Read.All')) {
            $role = $graphSpResp.value[0].appRoles | Where-Object { $_.value -eq $roleName }
            if (-not $role) { continue }
            if ($existingAssignments | Where-Object { $_.appRoleId -eq $role.id }) {
                Write-Host ('           {0,-25} already granted' -f $roleName)
                continue
            }
            try {
                $body = @{ principalId = $uamiPrincipalId; resourceId = $graphSpId; appRoleId = $role.id } | ConvertTo-Json -Compress
                Invoke-RestMethod -Method Post `
                    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$uamiPrincipalId/appRoleAssignments" `
                    -Headers @{ Authorization = ('Bearer ' + $graphTokenObj.accessToken); 'Content-Type' = 'application/json' } `
                    -Body $body | Out-Null
                Write-Host ('           {0,-25} granted' -f $roleName)
            } catch {
                Write-Warning ('           {0,-25} grant failed -- {1}' -f $roleName, $_.Exception.Message)
            }
        }
    }

    Write-Host ('[4/5] Ensuring Container App Job {0} (cron: "{1}") ...' -f $jobName, $schedule)

    $existing = Invoke-AzJson @('containerapp','job','show','--name',$jobName,'--resource-group',$ResourceGroupName)
    $verb = if ($existing) { 'update' } else { 'create' }

    $maxAi = if ($global:MaxAiSpendPerRun) { $global:MaxAiSpendPerRun } else { 4 }

    # SPN-secret is the only path. Single SPN secret
    # (si-spn-secret) replaces 25's si-graph-secret +
    # si-logingest-secret. UAMI path is now opt-in (-UseManagedIdentity
    # flag) for legacy single-tenant deployments.
    $secretArgs = @(
        ('openai-apikey={0}'  -f $global:OpenAI_apiKey),
        ('si-storage-key={0}' -f $global:SI_StorageKey)
    )
    $envArgs = @(
        "SI_ENGINE=$engine",
        "SI_SHARD_COUNT=$parallelism",
        "SI_STORAGE_ACCOUNT=$($global:SI_StorageAccount)",
        "SI_STORAGE_KEY=secretref:si-storage-key",
        "SI_WORKSPACE_RESOURCEID=$($global:SI_WorkspaceResourceId)",
        "SI_DCE_NAME=$($global:SI_DceName)",
        "SI_DCR_RESOURCEGROUP=$($global:SI_DcrResourceGroup)",
        'OPENAI_APIKEY=secretref:openai-apikey',
        "OPENAI_ENDPOINT=$($global:OpenAI_endpoint)",
        "OPENAI_DEPLOYMENT=$($global:OpenAI_deployment)",
        "OPENAI_APIVERSION=$($global:OpenAI_apiVersion)",
        ('MAX_AI_SPEND_PER_RUN={0}' -f $maxAi)
    )

    if ($UseKEDA -and -not $isRiskAnalysis) {
        # Worker reads its shard descriptor from the queue (NOT from
        # CONTAINER_APP_JOB_REPLICA_INDEX which doesn't apply to event jobs).
        # RA never participates in KEDA so it skips this env var even when
        # -UseKEDA was passed for the collection engines.
        $envArgs += @('SI_TRIGGER_FROM_QUEUE=1')
    }

    if ($UseManagedIdentity) {
        Write-Warning ('  -UseManagedIdentity is opt-in legacy mode. default is SPN-secret. UAMI machinery still creates UAMI + RBAC; container will use SPN unless SI_PREFER_UAMI=1.')
        $envArgs += @("SI_UAMI_CLIENTID=$uamiClientId", 'SI_PREFER_UAMI=1')
    }

    # Single SPN secret + env vars.
    $secretArgs += @(('si-spn-secret={0}' -f $spnSecret))
    $envArgs += @(
        "SI_SPN_APPID=$spnAppId",
        'SI_SPN_SECRET=secretref:si-spn-secret',
        "SI_SPN_TENANTID=$spnTenantId",
        "SI_SPN_OBJECTID=$spnObjectId"
    )

    # Risk Analysis env vars: the RA entrypoint
    # (Start-RiskAnalysisInContainer.ps1) reads SI_RA_* to populate the
    # RA engine's $global:* surface. KEDA does not apply here -- RA is a
    # single-container report build by design.
    if ($isRiskAnalysis) {
        $envArgs += @(
            "SI_RA_REPORT_TEMPLATE=$RiskAnalysisReportTemplate",
            "SI_RA_MODE=$RiskAnalysisMode",
            ('SI_RA_SEND_TO_LOG_ANALYTICS={0}' -f ([int][bool]$RiskAnalysisSendToLogAnalytics)),
            ('SI_RA_BUILD_SUMMARY_BY_AI={0}'   -f ([int][bool]$RiskAnalysisBuildSummaryByAI))
        )
        if (-not [string]::IsNullOrWhiteSpace($RiskAnalysisExportDestination)) {
            $envArgs += @("SI_RA_EXPORT_DESTINATION=$RiskAnalysisExportDestination")
        }
        # No else-warn: the post-load resolver auto-derives a default from
        # $global:SI_StorageAccount + sistaging container, and the container
        # entrypoint repeats the same derivation if env is unset, so the
        # destination is effectively never empty.
    }

    # Risk Analysis is always schedule-triggered + single-replica + bigger box.
    # Force-skip KEDA path for RA even if -UseKEDA was passed (RA doesn't shard).
    $effectiveUseKEDA = ($UseKEDA -and -not $isRiskAnalysis)

    # In KEDA mode the worker job is event-triggered with a queue scaler.
    # --replica-completion-count 1: each replica is one work-item.
    # --parallelism is the per-execution cap; KEDA polls and starts one
    # execution per <queueLength> messages above 0.
    $createArgs = if ($effectiveUseKEDA) {
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Event',
            '--replica-timeout','3600',
            '--replica-retry-limit','1',
            '--replica-completion-count','1',
            '--parallelism','1',
            '--min-executions','0',
            '--max-executions',"$KedaMaxReplicas",
            '--polling-interval','30',
            '--scale-rule-name','si-shards-queue',
            '--scale-rule-type','azure-queue',
            '--scale-rule-metadata',
                ('queueName=si-{0}-shards' -f $engine),
                ('accountName={0}' -f $global:SI_StorageAccount),
                'queueLength=1',
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--registry-username',$acrUser,
            '--registry-password',$acrPass,
            '--cpu','1.0',
            '--memory','2.0Gi',
            '--output','none'
        )
    } elseif ($isRiskAnalysis) {
        # RA: bigger box, longer timeout, custom entrypoint that wraps
        # SCRIPTS/SecurityInsight_RiskAnalysis.ps1 instead of the collection
        # orchestrator. Single replica -- bucketing scales inside.
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Schedule',
            '--replica-timeout','7200',
            '--replica-retry-limit','1',
            '--replica-completion-count','1',
            '--parallelism','1',
            '--cron-expression',$schedule,
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--registry-username',$acrUser,
            '--registry-password',$acrPass,
            '--cpu','2.0',
            '--memory','4.0Gi',
            '--command','pwsh','-NoProfile','-File','/app/container/Start-RiskAnalysisInContainer.ps1',
            '--output','none'
        )
    } else {
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Schedule',
            '--replica-timeout','3600',
            '--replica-retry-limit','1',
            '--replica-completion-count',"$parallelism",
            '--parallelism',"$parallelism",
            '--cron-expression',$schedule,
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--registry-username',$acrUser,
            '--registry-password',$acrPass,
            '--cpu','1.0',
            '--memory','2.0Gi',
            '--output','none'
        )
    }
    if ($UseManagedIdentity) {
        $createArgs += @('--mi-user-assigned',$uamiResourceId)
    }
    $createArgs += @('--secrets'); $createArgs += $secretArgs
    $createArgs += @('--env-vars'); $createArgs += $envArgs

    # az containerapp job UPDATE doesn't accept bare --secrets/
    # --env-vars (those are create-only). Use:
    #   - 'containerapp job secret set --secrets ...'  for secrets
    #   - 'containerapp job update --replace-env-vars ...' for env vars
    # Image + cron go on the bare update.
    $updateArgs = @(
        'containerapp','job','update',
        '--name',$jobName,
        '--resource-group',$ResourceGroupName,
        '--image',$image,
        '--cron-expression',$schedule,
        '--replace-env-vars'
    )
    $updateArgs += $envArgs
    $updateArgs += @('--output','none')

    if ($verb -eq 'create') {
        Invoke-Az -AzArgs $createArgs | Out-Null
        if ($UseManagedIdentity) {
            # Identity must be re-assigned post-create on some az versions
            Invoke-Az @('containerapp','job','identity','assign','--name',$jobName,'--resource-group',$ResourceGroupName,'--user-assigned',$uamiResourceId,'--output','none') -AllowFailure | Out-Null
        }
    } else {
        # Update secrets first (they're referenced by env vars via secretref:)
        if ($secretArgs.Count -gt 0) {
            $secretSetArgs = @('containerapp','job','secret','set','--name',$jobName,'--resource-group',$ResourceGroupName,'--secrets')
            $secretSetArgs += $secretArgs
            $secretSetArgs += @('--output','none')
            Invoke-Az -AzArgs $secretSetArgs -AllowFailure | Out-Null
        }
        Invoke-Az -AzArgs $updateArgs | Out-Null
        if ($UseManagedIdentity) {
            Invoke-Az @('containerapp','job','identity','assign','--name',$jobName,'--resource-group',$ResourceGroupName,'--user-assigned',$uamiResourceId,'--output','none') -AllowFailure | Out-Null
        }
    }
    Write-Host ('       {0}d.' -f $verb)

    if ($TriggerNowAfter) {
        Write-Host ('       triggering manual run ...')
        az containerapp job start --name $jobName --resource-group $ResourceGroupName | Out-Null
        Write-Host ('       triggered. Stream logs with:  az containerapp job logs show --name {0} --resource-group {1} --container {0} --follow' -f $jobName, $ResourceGroupName)
    }

    # ---- 4b. Producer job (KEDA mode only; never for Risk Analysis) ----
    # Cron-triggered, single replica, runs Invoke-ShardProducer.ps1 instead
    # of the default entrypoint. Pushes N shard messages onto the queue;
    # KEDA then scales the worker job to drain.
    if ($effectiveUseKEDA) {
        Write-Host ('       Ensuring producer job {0} (cron: "{1}") ...' -f $producerName, $schedule)

        $producerEnvArgs = @(
            "SI_ENGINE=$engine",
            "SI_SHARD_COUNT=$parallelism",
            "SI_STORAGE_ACCOUNT=$($global:SI_StorageAccount)",
            "SI_WORKSPACE_RESOURCEID=$($global:SI_WorkspaceResourceId)"
        )
        $producerSecretArgs = @()
        if ($UseManagedIdentity) {
            $producerEnvArgs += @("SI_UAMI_CLIENTID=$uamiClientId")
        } else {
            # unify producer on the SI_SPN_* secret model, matching the
            # worker. Previously the producer still used the legacy
            # SI_Graph_*/SI_LogIngest_* split, so a SI_SPN_*-only customer would get
            # "secret not set" failures only on KEDA deployments.
            $producerSecretArgs += @(
                ('si-storage-key={0}' -f $global:SI_StorageKey),
                ('si-spn-secret={0}'  -f $spnSecret)
            )
            $producerEnvArgs += @(
                'SI_STORAGE_KEY=secretref:si-storage-key',
                "SI_SPN_APPID=$spnAppId",
                'SI_SPN_SECRET=secretref:si-spn-secret',
                "SI_SPN_TENANTID=$spnTenantId",
                "SI_SPN_OBJECTID=$spnObjectId"
            )
        }

        $producerExisting = Invoke-AzJson @('containerapp','job','show','--name',$producerName,'--resource-group',$ResourceGroupName)
        $producerVerb = if ($producerExisting) { 'update' } else { 'create' }

        $producerCreateArgs = @(
            'containerapp','job','create',
            '--name',$producerName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Schedule',
            '--replica-timeout','600',
            '--replica-retry-limit','1',
            '--replica-completion-count','1',
            '--parallelism','1',
            '--cron-expression',$schedule,
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--registry-username',$acrUser,
            '--registry-password',$acrPass,
            '--cpu','0.25',
            '--memory','0.5Gi',
            '--command','pwsh','-NoProfile','-File','/app/container/Invoke-ShardProducer.ps1',
            '--output','none'
        )
        # producer update mirrors worker pattern -- bare --secrets and
        # --env-vars are create-only; updates need 'secret set' + --replace-env-vars.
        $producerUpdateArgs = @(
            'containerapp','job','update',
            '--name',$producerName,
            '--resource-group',$ResourceGroupName,
            '--image',$image,
            '--cron-expression',$schedule,
            '--replace-env-vars'
        )
        $producerUpdateArgs += $producerEnvArgs
        $producerUpdateArgs += @('--output','none')
        if ($UseManagedIdentity) { $producerCreateArgs += @('--mi-user-assigned',$uamiResourceId) }
        if ($producerSecretArgs.Count -gt 0) { $producerCreateArgs += @('--secrets'); $producerCreateArgs += $producerSecretArgs }
        $producerCreateArgs += @('--env-vars'); $producerCreateArgs += $producerEnvArgs

        if ($producerVerb -eq 'create') {
            Invoke-Az -AzArgs $producerCreateArgs | Out-Null
            if ($UseManagedIdentity) {
                Invoke-Az @('containerapp','job','identity','assign','--name',$producerName,'--resource-group',$ResourceGroupName,'--user-assigned',$uamiResourceId,'--output','none') -AllowFailure | Out-Null
            }
        } else {
            Invoke-Az -AzArgs $producerUpdateArgs | Out-Null
        }
        Write-Host ('       {0}d producer.' -f $producerVerb)
    }
}

Write-Host ''
Write-Host '[5/5] Done.'
Write-Host ''
Write-Host 'Manual trigger any engine:'
Write-Host ('  az containerapp job start --name caj-si-<engine> --resource-group {0}' -f $ResourceGroupName)
Write-Host 'Tail latest execution logs:'
Write-Host ('  az containerapp job execution list --name caj-si-<engine> --resource-group {0} --query ''[0].name'' -o tsv | %{{ az containerapp job logs show --name caj-si-<engine> --resource-group {0} --execution $_ }}' -f $ResourceGroupName)
