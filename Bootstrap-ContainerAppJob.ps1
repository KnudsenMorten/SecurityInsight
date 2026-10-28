#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- one-shot Azure Container Apps Job bootstrap.

    Provisions the production runtime for the orchestrator:
      * Azure Container Registry (ACR) -- holds the orchestrator image
      * Builds the image IN the registry (ACR Tasks over ARM REST: setup\_shared\SI-AcrBuild.ps1 -- no Docker, no az CLI)
      * Container Apps Environment (CAE) -- managed Kubernetes-backed runtime
      * Container App Job per engine -- runs the orchestrator on schedule

    Idempotent: each step checks if the resource exists and reuses it.

    Pre-requisites:
      * NOTHING installed: no az CLI, no PowerShell module (#521 / #305). Every Azure call is ARM / data-plane REST
        (setup\_shared\SI-SetupAzure.ps1 + SI-SetupArm.ps1), signed in by setup itself.
      * Customer's config/SecurityInsight.custom.ps1 already populated
        with SI_StorageAccount/Key, SI_Graph_*, SI_LogIngest_*,
        SI_WorkspaceResourceId, SI_DceName, SI_DcrResourceGroup, OpenAI_*
      * a sign-in: the guided install's, the Invardia support session's tokens, Azure Cloud Shell or the browser (asked here)

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
    # LOCKED: the name defaults below (resource group, registry, environment, identity) are what every earlier release
    # created. A re-run against an install whose config does not name them relies on them, so they stay as they are.
    # NEW installs get rg-si-<ring>-<edition>-ca names from setup, which passes them here and saves them in the config.
    [Parameter()][string]$ResourceGroupName  = 'rg-securityinsight',
    # v2.2.356 -- no implicit westeurope default. Pass -Location explicitly
    # OR set $global:SI_Bootstrap_Location / $global:SI_Location in
    # config/SecurityInsight.custom.ps1. Solution is used worldwide.
    [Parameter()][string]$Location           = '',
    [Parameter()][string]$AcrName            = 'acrsecurityinsight',
    [Parameter()][string]$EnvName            = 'cae-securityinsight',
    [Parameter()][string]$ImageTag           = 'latest',
    [Parameter()][string[]]$Engines               = @('endpoint','identity','azure','publicip','privilege-tier-classifier','risk-analysis','risk-analysis-detailed'),
    [Parameter()][string]$ScheduleEndpoint            = '0 4 * * *',     # 04:00 UTC daily
    [Parameter()][string]$ScheduleIdentity            = '30 4 * * *',    # 04:30 UTC daily
    [Parameter()][string]$ScheduleAzure               = '0 5 * * *',     # 05:00 UTC daily
    # The privilege-tier classifier builds the tier catalog the profilers read, so it runs well BEFORE them; publicip
    # reads the endpoint and Azure profiles, so it runs AFTER them. Both used to fall back to the endpoint schedule.
    [Parameter()][string]$ScheduleClassifier          = '0 1 * * *',     # 01:00 UTC -- three hours before the profilers
    [Parameter()][string]$SchedulePublicIp            = '15 5 * * *',    # 05:15 UTC -- after endpoint + azure
    [Parameter()][string]$ScheduleSchemaDiscovery     = '0 3 * * 0',     # 03:00 UTC every Sunday
    [Parameter()][string]$ScheduleRiskAnalysis        = '0 6 * * *',     # 06:00 UTC daily Summary (after collection)
    [Parameter()][string]$ScheduleRiskAnalysisDetailed = '0 8 * * *',    # 08:00 UTC daily Detailed (2h after Summary)
    # #170. The ORDER is load-bearing: profilers -> correlation/properties -> risk-analysis -> cmdb, trend.
    # Trend rolls up what Risk Analysis published; before RA it would stamp yesterday's numbers with today.
    [Parameter()][string]$ScheduleCorrelation         = '30 5 * * *',    # 05:30 UTC -- after the profilers, before RA
    [Parameter()][string]$ScheduleAssetProperties     = '45 5 * * *',    # 05:45 UTC -- after the profilers
    [Parameter()][string]$ScheduleCmdb                = '0 7 * * *',     # 07:00 UTC -- after correlation + RA Summary
    [Parameter()][string]$ScheduleTrend               = '0 9 * * *',     # 09:00 UTC -- after RA Detailed
    # #216: closes only on a Detailed snapshot whose Risk Analysis run recorded success -- so well after RA Detailed
    # starts. A run that finds it still incomplete opens and updates, and closes nothing; the next day catches up.
    [Parameter()][string]$ScheduleVulnerabilities     = '0 10 * * *',    # 10:00 UTC -- the close-loop
    # Pro data backend: copies the complete Risk Analysis collection to SQL and recomputes the close-loop statistics,
    # so it runs after RA Detailed AND after the close-loop.
    [Parameter()][string]$ScheduleDataSync            = '30 10 * * *',   # 10:30 UTC -- the data backend sync (the close-loop mail follows)
    # The close-loop's daily mail. Empty = derived from Mail_CloseLoop_Daily_SendTimeUtc (HH:mm, UTC; default 10:45 --
    # after the close-loop and the data sync). A time changed later in the web app takes effect when this is re-run.
    [Parameter()][string]$ScheduleCloseLoopMail       = '',
    # #236: asset tagging (Pro) -- after the profilers (endpoint 04:00, identity 04:30, azure 05:00), so its rules see
    # this morning's assets. Report only unless SI_Pro_AssetTagging_Apply is on.
    [Parameter()][string]$ScheduleAssetTagging        = '50 5 * * *',    # 05:50 UTC -- after the profilers
    # #269: the ServiceNow VULNERABILITY connector's own job (caj-si-asset-vulns-servicenow), after the SQL connector's.
    [Parameter()][string]$ScheduleVulnerabilitiesServiceNow = '15 10 * * *', # 10:15 UTC -- in schedules mode
    # #404 (CONFIG-1.3): the daily configuration backup (caj-si-config-backup) -- its OWN timer, never a step of the pipeline:
    # after the working day, before the 23:30 pipeline, never at the 23:00 update. A time of day never overlaps (SCHED-1.1).
    [Parameter()][string]$ScheduleConfigBackup        = '0 18 * * *',    # 18:00 UTC
    # #718: the hourly status report to Invardia (caj-si-heartbeat) -- its OWN timer, never a step of the pipeline, so the
    # install reports every hour whether or not a pipeline runs (a long report no longer looks like a stopped install).
    # #723: every 15 minutes -- each tick asks Invardia for the "update now" signal; the full report still goes once an hour
    [Parameter()][string]$ScheduleHeartbeat           = '7,22,37,52 * * * *',     # every 15 minutes, from 7 past the hour
    # #685: the verification service (caj-si-verification) -- the last step of the Deliver stage; in flow mode the job has no
    # timer (Manual, this one remembered), in schedules mode it runs on it: after the data sync and the daily mail.
    [Parameter()][string]$ScheduleVerification        = '0 11 * * *',    # 11:00 UTC -- the map's defaultCron (config\job-flow.locked.json)
    # #269: THE DAILY JOB FLOW. 'flow' = ONE start time (caj-si-flow, -ScheduleFlow) and the jobs run one after the other,
    # each starting when the one before it has ended -- the jobs of the flow have no timer of their own (Manual; their
    # timer is remembered in the si-disabled-cron tag). 'schedules' = every job on its own timer, as before. Empty = a NEW
    # install gets the flow, an EXISTING install keeps its timers (switch it on Operations > Jobs, or with
    # setup\Switch-SIJobOrchestration.ps1 -- previewed and reversible). Setup never changes an existing job's trigger.
    [Parameter()][string]$JobOrchestration = '',
    # SCHED-1.1: caj-si-flow's cron only WAKES the runner; the runner starts the flow when it is due -- at the flow's start
    # time (Operations > Jobs; default 01:00 UTC, never while the previous run is running), or every N after the previous run FINISHED.
    [Parameter()][string]$ScheduleFlow                = '*/5 * * * *',   # the runner's wake-up
    # #269: the ServiceNow jobs exist only where ServiceNow is used. Setup does not read the Pro database, so a
    # connector kept only there is named here (or by SI_Bootstrap_ServiceNowCmdb / SI_Bootstrap_ServiceNowVulnerabilities).
    [Parameter()][switch]$ServiceNowCmdb,
    [Parameter()][switch]$ServiceNowVulnerabilities,
    # #271: the SQL CMDB connector -- after correlation (05:30) and asset properties (05:45), into the Pro database.
    [Parameter()][string]$ScheduleCmdbSql             = '55 5 * * *',    # 05:55 UTC -- the CI table in the Pro database
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
    [Parameter()][string]$RiskAnalysisReportTemplate    = 'RiskAnalysis_Summary',
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
    # #250: a Pro install installs its default templates (template pack 1.0) at the end, when the Pro database is configured.
    # The guided install does that in its own step (as the person installing) and passes this.
    [Parameter()][switch]$SkipTemplateInstall,
    [Parameter()][switch]$TriggerNowAfter,
    # ---- How the engine jobs sign in (#209): managed identity > certificate > client secret ----
    # DEFAULT (operator 2026-10-07): a MANAGED IDENTITY -- every engine job signs in as ONE user-assigned identity
    #   (-ManagedIdentityName, created here if missing), as the guided install does. No secret is needed or passed.
    #   Its grants are printed as a plan and applied only with -GrantIdentityRoles.
    #   An EXISTING install whose config carries an SPN client secret (and no SI_AuthMethod) keeps the secret: nothing
    #   changes under it by itself; the run says so and how to move (Resolve-SIBootstrapAuthChoice).
    # -UseManagedIdentity: the managed identity, said explicitly (also SI_AuthMethod = 'ManagedIdentity').
    # -UseClientSecret: the SPN by client SECRET -- a supported, explicit choice (also SI_AuthMethod = 'Secret').
    # -CertificateKeyVaultName + -CertificateSecretName: the SPN by CERTIFICATE -- the job carries the PFX as a
    #   Key Vault REFERENCE (never read here), resolved by the same identity, as Install-SIUpdaterJob.ps1 does.
    [Parameter()][switch]$UseManagedIdentity,
    [Parameter()][switch]$UseClientSecret,
    [Parameter()][string]$ManagedIdentityName      = 'uami-securityinsight',
    [Parameter()][string]$CertificateKeyVaultName  = '',
    [Parameter()][string]$CertificateSecretName    = '',
    [Parameter()][string[]]$IdentityReaderScopes   = @(),        # default: the current subscription
    [Parameter()][switch]$GrantIdentityRoles,
    # #236: the asset-tagging job runs under its OWN user-assigned identity, never the collection identity above
    # (which stays read only). Created here when the job is deployed. Its write grants (Defender Machine.ReadWrite.All,
    # Tag Contributor at -TaggingScopes, Entra custom security attribute assignment) are OPT-IN: printed as a plan, and
    # applied only with -GrantTaggingRoles. Without them the job can only report.
    [Parameter()][string]$TaggingIdentityName      = 'uami-securityinsight-tagging',
    [Parameter()][string[]]$TaggingScopes          = @(),        # where Azure tags may be written; default: the reader scopes
    [Parameter()][switch]$GrantTaggingRoles,
    # #185: the Shodan key (a paid entitlement) reaches the publicip job as a Key Vault REFERENCE, resolved by the
    # job's identity when it starts -- the value is never read here. Default vault: SI_KeyVaultName. Without a vault,
    # a key value set in the config is passed as before.
    [Parameter()][string]$ShodanKeyVaultName       = '',
    [Parameter()][string]$ShodanSecretName         = 'SI-Shodan-ApiKey',
    # #215: the Azure OpenAI KEY the same way -- a Key Vault reference resolved by the job's identity (setup cannot read
    # the value). The endpoint, deployment and API version are plain settings from the config. Default vault: the
    # Shodan vault, then SI_KeyVaultName.
    [Parameter()][string]$OpenAIKeyVaultName       = '',
    [Parameter()][string]$OpenAIApiKeySecretName   = 'OpenAI-ApiKey',
    # #218: the SMTP PASSWORD for the Risk Analysis mail the same way -- only when the config switches RA mail on with
    # authenticated SMTP. The server, port, user and from-address are plain settings from the config. Default vault: the
    # OpenAI vault (then the Shodan vault, then SI_KeyVaultName).
    [Parameter()][string]$SmtpKeyVaultName         = '',
    [Parameter()][string]$SmtpPasswordSecretName   = 'SI-Smtp-Password',

    # KEDA queue-driven workers: idle = 0 replicas, scale-up = #queue-msgs.
    # When set, each engine gets TWO Container App Jobs:
    #   * caj-si-{engine}-producer  -- cron-triggered, pushes N shard
    #     messages onto si-{engine}-shards queue once per schedule.
    #   * caj-si-{engine}-worker    -- event-triggered (KEDA azure-queue
    #     scaler), each replica pops one message and runs that shard.
    # When NOT set: legacy single-job-per-engine schedule trigger (today).
    [Parameter()][switch]$UseKEDA,
    [Parameter()][int]$KedaMaxReplicas      = 30,                # cap on concurrent worker replicas (Consumption profile soft-cap)
    # The subscription to work in. Given, it wins over every config value and global (the guided install passes its own
    # answer: live 2026-10-06 a session's ring-1 SI_AzSubscriptionId was used instead). Empty: the config decides, as before.
    [Parameter()][string]$SubscriptionId = '',
    # The config file to read (and to save the container hosting in). Given, ONLY that file is used -- no fallback to
    # the working folder. The guided install passes the file it wrote for this install. Empty: config\SecurityInsight.custom.ps1.
    [Parameter()][string]$ConfigPath = '',
    # #681 (private networking, an option of the guided install): a NEW Container Apps environment is created in this subnet
    # of the customer's virtual network (delegated to Microsoft.App/environments); -EnvironmentInternal: with no public
    # address (the web app is then reachable from the customer's network only). Empty: as before, no virtual network.
    [Parameter()][string]$InfrastructureSubnetId = '',
    [Parameter()][switch]$EnvironmentInternal
)

$ErrorActionPreference = 'Stop'

# Snapshot CLI-bound params at script scope BEFORE entering any function.
# Inside a function, $PSBoundParameters refers to the function's bound params,
# not the caller's. Same pattern the launchers use.
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $true }

# Load customer config -- bootstrap pulls secrets from here to wire into the Job.
# Resolved relative to this script's location so it works wherever the repo is
# checked out (C:\SecurityInsight for end users, C:\SCRIPTS\AutomateIT\... for
# the upstream dev tree). Falls back to CWD\config\SecurityInsight.custom.ps1
# for invocations from other directories.
$customFile = Join-Path $PSScriptRoot 'config\SecurityInsight.custom.ps1'
if ($ConfigPath) {
    if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "The config file '$ConfigPath' (-ConfigPath) was not found." }
    $customFile = $ConfigPath
} elseif (-not (Test-Path $customFile)) {
    $cwdFallback = Join-Path (Get-Location) 'config\SecurityInsight.custom.ps1'
    if (Test-Path $cwdFallback) {
        $customFile = $cwdFallback
    } else {
        throw "$customFile not found -- run the Setup Wizard's Phase 3 (or Bootstrap-Auth.ps1) first to generate config\SecurityInsight.custom.ps1"
    }
}
# #170/#187: remember WHICH settings the customer's config sets -- those (the non-secret ones) are passed to
# every job as SI_CFG_<name>, so a container honours the same settings a VM does.
$globalsBeforeConfig = @{}; foreach ($v in (Get-Variable -Scope Global)) { $globalsBeforeConfig[$v.Name] = $true }
. $customFile
$configSetNames = @(Get-Variable -Scope Global | Where-Object { -not $globalsBeforeConfig.ContainsKey($_.Name) } | ForEach-Object { $_.Name })
. (Join-Path $PSScriptRoot 'container\_shared\SI-ContainerConfig.ps1')
# #294: ALSO every setting the file assigns, read from the file itself -- when this session had loaded the config already
# (a deploy that imported the settings into the Pro database first), no global "appeared" above and NOTHING went to the
# jobs: they ran on default names, without the Pro settings database (ring 1, 2026-10-04/05).
$configSetNames = @(@($configSetNames) + @(Get-SIConfigFileSettingNames -Path $customFile) | Where-Object { $_ } | Select-Object -Unique)

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
# v2.2.356 -- fall back to $global:SI_Location (the solution-wide location) when
# the bootstrap-specific override isn't set, then throw clearly when neither is.
# No implicit westeurope default -- solution is used worldwide.
if ([string]::IsNullOrWhiteSpace($Location) -and $global:SI_Location) { $Location = [string]$global:SI_Location }
if ([string]::IsNullOrWhiteSpace($Location)) {
    throw "Location is not set. Pass -Location <azure-region>, or set `$global:SI_Bootstrap_Location (preferred for container infra) or `$global:SI_Location (solution-wide) in config\SecurityInsight.custom.ps1. Examples: westeurope, eastus, eastus2, southcentralus, australiaeast, southeastasia."
}
_Apply-CustomDefault -ParamName 'AcrName'                  -GlobalName 'SI_Bootstrap_AcrName'
_Apply-CustomDefault -ParamName 'EnvName'                  -GlobalName 'SI_Bootstrap_EnvName'
_Apply-CustomDefault -ParamName 'ImageTag'                 -GlobalName 'SI_Bootstrap_ImageTag'
_Apply-CustomDefault -ParamName 'Engines'                  -GlobalName 'SI_Bootstrap_Engines'
# #170: trend runs in containers too, and the Pro engines are added wherever their code is present (the
# Community copy does not carry it, so a Community install never gets a job it cannot run). Only when the
# engine list was NOT chosen explicitly (CLI or SI_Bootstrap_Engines) -- an explicit list is obeyed as given.
if (-not $cliBound.ContainsKey('Engines') -and -not $global:SI_Bootstrap_Engines) {
    $Engines = @($Engines) + @('asset-trend')
    # #412: asset-properties is no longer a job -- the profilers publish the full asset metadata themselves.
    foreach ($pro in 'asset-correlation', 'asset-cmdb') {
        if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "engine\$pro")) { $Engines += $pro }
    }
    # #216: the vulnerability close-loop is its own job; its code lives in the asset-cmdb engine folder.
    # #269: two jobs -- the SQL connector (caj-si-asset-vulnerabilities) and the ServiceNow connector
    # (caj-si-asset-vulns-servicenow, only where ServiceNow is configured -- Select-SIBootstrapServiceNowEngines below).
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\asset-cmdb\Invoke-SIVulnLoop.ps1')) { $Engines += @('asset-vulnerabilities', 'asset-vulnerabilities-servicenow') }
    # The Pro data backend sync (Risk Analysis collections -> the Pro database) is its own job where its code exists.
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-data\Invoke-SIDataSync.ps1')) { $Engines += 'asset-datasync' }
    # #271: the SQL CMDB connector, for a Pro install with a Pro database (its CI table lives there).
    if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\asset-cmdb\Invoke-SICmdbSql.ps1')) -and (($global:SI_ProSqlServer -and $global:SI_ProSqlDatabase) -or ($global:SI_Pro_DataSqlServer -and $global:SI_Pro_DataSqlDatabase))) { $Engines += 'asset-cmdb-sql' }
    # The close-loop's daily mail is its own job; its code lives in the asset-cmdb engine folder, beside the close-loop.
    if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\asset-cmdb\Invoke-SICloseLoopMail.ps1')) { $Engines += 'close-loop-mail' }
    # #236: asset tagging as a container job (Community edition and Pro, #750 (2)) -- where the settings layer exists, because the job's
    # rules come from the Pro templates (SI_ProAssetTaggingPath). Report only until SI_Pro_AssetTagging_Apply is on.
    if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\SI-ProSettings.ps1')) -and
        (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\asset-tagging\Invoke-SIAssetTaggingJob.ps1'))) { $Engines += 'asset-tagging' }
    $Engines = @($Engines | Select-Object -Unique)
}
# #235/#250: the template release job (caj-si-templates) -- MANUAL trigger only; the web app starts it after an Admin
# accepted a template release, with the accepted fingerprint. It is INFRASTRUCTURE, not an engine choice, so a Pro install
# (the Pro settings layer and its publish script exist) ALWAYS gets it -- also with an explicit engine list: the guided
# install passes one, and until 2026-10-04 its installs never got the job (the Template releases page then said the job
# "is not one of this installation's jobs").
if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\SI-ProSettings.ps1')) -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'setup\Publish-SITemplates.ps1')) -and @($Engines) -notcontains 'templates-publish') {
    $Engines = @($Engines) + @('templates-publish')
}
# #269: the daily job flow (caj-si-flow) is INFRASTRUCTURE like the template job: every install gets it, also with an
# explicit engine list. In flow mode it is the one timer; in schedules mode it waits (Manual) until someone switches.
if (@($Engines) -notcontains 'flow') { $Engines = @($Engines) + @('flow') }
# #404 (CONFIG-1.3): the daily configuration backup (caj-si-config-backup) is INFRASTRUCTURE like the template job: a Pro
# install (the Pro settings layer exists) gets it whatever the engine list; it skips itself, saying why, without a Pro database.
if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\Invoke-SIConfigBackup.ps1')) -and @($Engines) -notcontains 'config-backup') {
    $Engines = @($Engines) + @('config-backup')
}
# #685: the verification service (caj-si-verification: the data-collection gaps, and the CR2 data health check it runs in
# its finally block) is INFRASTRUCTURE like the configuration backup: a Pro install (the Pro settings layer and the
# verification engine exist) gets it whatever the engine list -- until 2026-10-15 no setup created it, so it never ran at
# any install. It skips itself, saying why, without a Pro database. An existing install gets it from the update
# (setup\_shared\SI-MissingJobs.ps1).
if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\SI-ProSettings.ps1')) -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine/verification/Invoke-SIVerification.ps1')) -and @($Engines) -notcontains 'verification') {
    $Engines = @($Engines) + @('verification')
}
# #718: the hourly status report to Invardia (caj-si-heartbeat) is INFRASTRUCTURE like the configuration backup: a Pro
# install (the Pro settings layer and the heartbeat engine exist) gets it whatever the engine list. An anonymous install
# sends nothing from it. An existing install gets it from the update (setup\_shared\SI-MissingJobs.ps1).
if ((Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\SI-ProSettings.ps1')) -and
    (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine/heartbeat/Invoke-SIHeartbeat.ps1')) -and @($Engines) -notcontains 'heartbeat') {
    $Engines = @($Engines) + @('heartbeat')
}
# #412: asset-properties is RETIRED as a job -- with SI_AssetProperties = 'full' the endpoint, identity and azure profilers
# read each source once and publish the full asset metadata themselves. An explicit list that still names it (an older
# SI_Bootstrap_Engines) does not create it; a job an earlier Bootstrap created is left alone (it ends at once, said) and
# can be removed by hand: az containerapp job delete -n caj-si-asset-properties -g <resource group>.
if (@($Engines) -contains 'asset-properties') {
    Write-Host '[INFO] asset-properties is retired (the profilers publish the full asset metadata themselves) -- no job is created for it.' -ForegroundColor Gray
    $Engines = @($Engines | Where-Object { $_ -ne 'asset-properties' })
}
_Apply-CustomDefault -ParamName 'ScheduleEndpoint'         -GlobalName 'SI_Bootstrap_ScheduleEndpoint'
_Apply-CustomDefault -ParamName 'ScheduleIdentity'         -GlobalName 'SI_Bootstrap_ScheduleIdentity'
_Apply-CustomDefault -ParamName 'ScheduleAzure'            -GlobalName 'SI_Bootstrap_ScheduleAzure'
_Apply-CustomDefault -ParamName 'ScheduleClassifier'       -GlobalName 'SI_Bootstrap_ScheduleClassifier'
_Apply-CustomDefault -ParamName 'SchedulePublicIp'         -GlobalName 'SI_Bootstrap_SchedulePublicIp'
_Apply-CustomDefault -ParamName 'ScheduleSchemaDiscovery'  -GlobalName 'SI_Bootstrap_ScheduleSchemaDiscovery'
_Apply-CustomDefault -ParamName 'ScheduleRiskAnalysis'         -GlobalName 'SI_Bootstrap_ScheduleRiskAnalysis'
_Apply-CustomDefault -ParamName 'ScheduleRiskAnalysisDetailed' -GlobalName 'SI_Bootstrap_ScheduleRiskAnalysisDetailed'
# #257: documented in the reference since #170, never read -- the trend job always ran at 09:00 UTC.
_Apply-CustomDefault -ParamName 'ScheduleTrend'            -GlobalName 'SI_Bootstrap_ScheduleTrend'
_Apply-CustomDefault -ParamName 'ParallelismEndpoint'      -GlobalName 'SI_Bootstrap_ParallelismEndpoint'
_Apply-CustomDefault -ParamName 'ParallelismIdentity'      -GlobalName 'SI_Bootstrap_ParallelismIdentity'
_Apply-CustomDefault -ParamName 'ParallelismAzure'         -GlobalName 'SI_Bootstrap_ParallelismAzure'
_Apply-CustomDefault -ParamName 'ParallelismSchemaDiscovery' -GlobalName 'SI_Bootstrap_ParallelismSchemaDiscovery'
_Apply-CustomDefault -ParamName 'ParallelismRiskAnalysis'  -GlobalName 'SI_Bootstrap_ParallelismRiskAnalysis'
_Apply-CustomDefault -ParamName 'KedaMaxReplicas'          -GlobalName 'SI_Bootstrap_KedaMaxReplicas'
_Apply-CustomDefault -ParamName 'ManagedIdentityName'      -GlobalName 'SI_Bootstrap_ManagedIdentityName'
_Apply-CustomDefault -ParamName 'CertificateKeyVaultName'  -GlobalName 'SI_Bootstrap_CertificateKeyVaultName'
_Apply-CustomDefault -ParamName 'CertificateSecretName'    -GlobalName 'SI_Bootstrap_CertificateSecretName'
_Apply-CustomDefault -ParamName 'IdentityReaderScopes'     -GlobalName 'SI_Bootstrap_IdentityReaderScopes'
_Apply-CustomDefault -ParamName 'ShodanKeyVaultName'       -GlobalName 'SI_Bootstrap_ShodanKeyVaultName'
_Apply-CustomDefault -ParamName 'ShodanSecretName'         -GlobalName 'SI_Bootstrap_ShodanSecretName'
if ([string]::IsNullOrWhiteSpace($ShodanKeyVaultName) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_KeyVaultName)) { $ShodanKeyVaultName = [string]$global:SI_KeyVaultName }
_Apply-CustomDefault -ParamName 'OpenAIKeyVaultName'       -GlobalName 'SI_Bootstrap_OpenAIKeyVaultName'
_Apply-CustomDefault -ParamName 'OpenAIApiKeySecretName'   -GlobalName 'SI_Bootstrap_OpenAIApiKeySecretName'
if ([string]::IsNullOrWhiteSpace($OpenAIKeyVaultName)) { $OpenAIKeyVaultName = $ShodanKeyVaultName }
_Apply-CustomDefault -ParamName 'SmtpKeyVaultName'         -GlobalName 'SI_Bootstrap_SmtpKeyVaultName'
_Apply-CustomDefault -ParamName 'SmtpPasswordSecretName'   -GlobalName 'SI_Bootstrap_SmtpPasswordSecretName'
if ([string]::IsNullOrWhiteSpace($SmtpKeyVaultName)) { $SmtpKeyVaultName = $OpenAIKeyVaultName }
# The close-loop daily mail's job runs at the time its setting names (Get-SICloseLoopMailSchedule), unless a schedule
# is given explicitly.
_Apply-CustomDefault -ParamName 'ScheduleCloseLoopMail'    -GlobalName 'SI_Bootstrap_ScheduleCloseLoopMail'
_Apply-CustomDefault -ParamName 'ScheduleAssetTagging'     -GlobalName 'SI_Bootstrap_ScheduleAssetTagging'
_Apply-CustomDefault -ParamName 'ScheduleVulnerabilitiesServiceNow' -GlobalName 'SI_Bootstrap_ScheduleVulnerabilitiesServiceNow'
_Apply-CustomDefault -ParamName 'ScheduleFlow'             -GlobalName 'SI_Bootstrap_ScheduleFlow'
_Apply-CustomDefault -ParamName 'ScheduleConfigBackup'     -GlobalName 'SI_Bootstrap_ScheduleConfigBackup'
_Apply-CustomDefault -ParamName 'ScheduleVerification'     -GlobalName 'SI_Bootstrap_ScheduleVerification'
# #269: SI_JobOrchestration (flow | schedules) is the setting; SI_Bootstrap_JobOrchestration also works.
_Apply-CustomDefault -ParamName 'JobOrchestration'         -GlobalName 'SI_Bootstrap_JobOrchestration'
if (-not $cliBound.ContainsKey('JobOrchestration') -and -not $JobOrchestration -and [string]$global:SI_JobOrchestration) { $JobOrchestration = ([string]$global:SI_JobOrchestration).Trim().ToLowerInvariant() }
_Apply-CustomDefault -ParamName 'ScheduleCmdbSql'          -GlobalName 'SI_Bootstrap_ScheduleCmdbSql'
_Apply-CustomDefault -ParamName 'TaggingIdentityName'      -GlobalName 'SI_Bootstrap_TaggingIdentityName'
_Apply-CustomDefault -ParamName 'TaggingScopes'            -GlobalName 'SI_Bootstrap_TaggingScopes'
$clMail = Get-SIContainerCloseLoopMailPlan -Globals @{
    Mail_CloseLoop_Daily_SendMail = $global:Mail_CloseLoop_Daily_SendMail; Mail_CloseLoop_Daily_SendTimeUtc = $global:Mail_CloseLoop_Daily_SendTimeUtc
    SmtpServer = $global:SmtpServer; Mail_SendAnonymous = $global:Mail_SendAnonymous }
if ([string]::IsNullOrWhiteSpace($ScheduleCloseLoopMail)) {
    $ScheduleCloseLoopMail = $clMail.Schedule.Cron
    if ($clMail.Schedule.Note) { Write-Warning ('[mail] {0}' -f $clMail.Schedule.Note) }
}

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
# Whether setup DECIDED these two (the switch, or SI_RiskAnalysis_* in the config). Not decided = the job carries no
# env var for it, and the container honours the customer's own setting -- or the VM default: Log Analytics ON, AI off.
# (Before, the job always carried both, as 0 unless asked: a container never sent Risk Analysis to Log Analytics by
# default, and a customer who had switched either on in the config was overruled.)
$raSendToLaForJobs = if ($cliBound.ContainsKey('RiskAnalysisSendToLogAnalytics') -or $null -ne $global:SI_RiskAnalysis_SendToLogAnalytics) { [bool]$RiskAnalysisSendToLogAnalytics } else { $null }
$raBuildAiForJobs  = if ($cliBound.ContainsKey('RiskAnalysisBuildSummaryByAI') -or $null -ne $global:SI_RiskAnalysis_BuildSummaryByAI) { [bool]$RiskAnalysisBuildSummaryByAI } else { $null }
_Apply-CustomSwitch -ParamName 'SkipImageBuild'                 -GlobalName 'SI_Bootstrap_SkipImageBuild'
_Apply-CustomSwitch -ParamName 'TriggerNowAfter'                -GlobalName 'SI_Bootstrap_TriggerNowAfter'
_Apply-CustomSwitch -ParamName 'UseManagedIdentity'             -GlobalName 'SI_Bootstrap_UseManagedIdentity'
_Apply-CustomSwitch -ParamName 'UseClientSecret'                -GlobalName 'SI_Bootstrap_UseClientSecret'
# UseKEDA: resolved below with the sign-in (Resolve-SIBootstrapKedaChoice) -- on by design, SI_Bootstrap_UseKEDA = $false opts out
_Apply-CustomSwitch -ParamName 'GrantIdentityRoles'             -GlobalName 'SI_Bootstrap_GrantIdentityRoles'
_Apply-CustomSwitch -ParamName 'GrantTaggingRoles'              -GlobalName 'SI_Bootstrap_GrantTaggingRoles'

# #209: how the jobs sign in. Half a certificate setting throws here, before anything is created.
# Default (2026-10-07): the managed identity -- unless the config carries an SPN client secret, which an existing
# install keeps (Resolve-SIBootstrapAuthChoice). A secret stays a supported, explicit choice: -UseClientSecret.
$authChoice = Resolve-SIBootstrapAuthChoice -UseManagedIdentity ([bool]$UseManagedIdentity) `
                -CertificateKeyVaultName $CertificateKeyVaultName -CertificateSecretName $CertificateSecretName `
                -UseClientSecret ([bool]$UseClientSecret) -ConfiguredMethod ([string]$global:SI_AuthMethod) `
                -HasConfiguredSecret ([bool](@($global:SI_SPN_Secret, $global:SI_Graph_Secret, $global:SI_SPN_KvSecretName) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }))
$authMode = $authChoice.Mode
Write-Host ('[sign-in] the jobs sign in with {0} -- {1}' -f $(switch ($authMode) { 'ManagedIdentity' { 'a managed identity' } 'Certificate' { 'the SPN by certificate' } default { 'the SPN by client secret' } }), $authChoice.Reason)
if ($authChoice.Default -and $authMode -eq 'Secret') {
    Write-Host '[sign-in] Kept as it is. A managed identity is the default for new installs: to move these jobs to one, run again with -UseManagedIdentity -GrantIdentityRoles (no secret to store or rotate).'
}
# #475 -- QUEUE SCALING BY DESIGN (operator 2026-10-08: "KEDA by design"; DESIGN.md 13): identity, endpoint and Azure run
# as a producer + queue-scaled workers unless this install opts out (-UseKEDA:$false / SI_Bootstrap_UseKEDA = $false). The
# scaler signs in as the jobs' managed identity ("use managed identity"): an install that merely carries a client secret
# moves to the managed identity with its grants (below, after the secret settings are checked -- so a move that cannot get
# its grants falls back to exactly what the jobs have); an EXPLICIT -UseKEDA with a chosen secret is refused, as before.
$kedaChoice = Resolve-SIBootstrapKedaChoice -CliBound ($cliBound.ContainsKey('UseKEDA')) -CliValue ([bool]$UseKEDA) `
                -Configured (Get-Variable -Name 'SI_Bootstrap_UseKEDA' -ValueOnly -Scope Global -ErrorAction SilentlyContinue) `
                -AuthMode $authMode -AuthDefault ([bool]$authChoice.Default)
if ($kedaChoice.Refuse) { throw $kedaChoice.Message }
Write-Host $kedaChoice.Message
$UseKEDA = [switch][bool]$kedaChoice.Keda
$kedaMovesToIdentity = [bool]$kedaChoice.MoveToManagedIdentity

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
# The jobs reach storage only with their identity (Storage Blob / Queue / Table Data Contributor on the account);
# Azure OpenAI is optional -- without it they run without AI classification.
$reqGlobals = @(
    'SI_StorageAccount',
    'SI_WorkspaceResourceId','SI_DceName','SI_DcrResourceGroup'
)
# #215: the endpoint / deployment / API version decide whether the install HAS Azure OpenAI; the key may be a Key
# Vault reference (resolved below), so its value is not required here.
$haveOpenAiSettings = -not (@('OpenAI_endpoint','OpenAI_deployment','OpenAI_apiVersion') |
    Where-Object { [string]::IsNullOrWhiteSpace((Get-Variable -Name $_ -ValueOnly -Scope Global -ErrorAction SilentlyContinue)) })
$shodanForJobs = @($global:SI_Shodan_ApiKey, $global:SHODAN_ApiKey | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) | Select-Object -First 1
# The customer's non-secret settings for every job (#170/#187). Secret-looking and container-owned names are
# refused by Get-SIConfigEnvArgs; bootstrap's own SI_Bootstrap_* knobs and very large values are not passed.
$cfgNames = @($configSetNames | Where-Object { $_ -notlike 'SI_Bootstrap_*' })
$cfgGlobals = @{}; foreach ($n in $cfgNames) { $cfgGlobals[$n] = Get-Variable -Name $n -ValueOnly -Scope Global -ErrorAction SilentlyContinue }
# Settings that no longer exist (Get-SIRetiredSettingNames) are skipped without a word: a value left in a config is not used.
$retiredSettings = @(Get-SIRetiredSettingNames)
$cfgPass = Get-SIConfigEnvArgs -Names $cfgNames -Globals $cfgGlobals -Ignore $retiredSettings
$cfgEnvArgs = @($cfgPass.EnvArgs | Where-Object { $_.Length -le 4096 })
$cfgTooLarge = @($cfgPass.EnvArgs | Where-Object { $_.Length -gt 4096 } | ForEach-Object { ($_ -split '=', 2)[0] })
Write-Host ('[config] {0} setting(s) from {1} go to every job{2}' -f $cfgEnvArgs.Count, (Split-Path -Leaf $customFile), $(if (@($cfgPass.Refused).Count) { "; NOT passed (secrets travel only as secrets): $(@($cfgPass.Refused) -join ', ')" } else { '' }))
if ($cfgTooLarge.Count) { Write-Warning ('[config] too large for an environment variable, not passed: {0}' -f ($cfgTooLarge -join ', ')) }

# The classifier only with Azure OpenAI (without it every role would become Tier 99 and replace the shipped catalog).
$engineSel = Select-SIBootstrapEngines -Engines $Engines -HaveOpenAi ([bool]$haveOpenAiSettings)
$Engines = @($engineSel.Engines)
if ($engineSel.Note) { Write-Host ('[engines] {0}' -f $engineSel.Note) -ForegroundColor Yellow }

# Every Risk Analysis job: Summary and Detailed with the customer's default templates (RiskAnalysis_ReportTemplate_Default_*,
# as the VM launcher honours them), plus any extra report jobs in SI_Bootstrap_RiskAnalysisJobs.
$bootGlobals = @{}
foreach ($v in (Get-Variable -Scope Global)) { $bootGlobals[$v.Name] = $v.Value }

# The tenant's size, ONCE (Microsoft Graph $count): the collection jobs are sized for it (Get-SITenantSizedJobResources --
# customer H 2026-10-08: 22,705 users + 5,097 groups ran the identity job out of memory at the default). Not readable =
# the defaults, said once; a size the customer set (SI_Bootstrap_Memory_<Engine>) always wins.
# (read after the sign-in below, over Microsoft Graph REST -- Get-SITenantDirectoryCounts)
$script:SITenantCounts = $null
$raSummaryTemplateExplicit = $cliBound.ContainsKey('RiskAnalysisReportTemplate') -or -not [string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_ReportTemplate)
$raPlan = Get-SIRiskAnalysisJobPlan -Engines $Engines -Globals $bootGlobals `
    -SummaryTemplate $(if ($raSummaryTemplateExplicit) { $RiskAnalysisReportTemplate } else { '' }) -SummaryMode $RiskAnalysisMode `
    -ScheduleSummary $ScheduleRiskAnalysis -ScheduleDetailed $ScheduleRiskAnalysisDetailed
foreach ($why in @($raPlan.Refused)) { Write-Warning ('[risk-analysis] not deployed: {0}' -f $why) }
$raJobs = @{}
foreach ($j in @($raPlan.Jobs)) { $raJobs[$j.Engine] = $j; if ($Engines -notcontains $j.Engine) { $Engines = @($Engines) + @($j.Engine) } }

# Each engine's own launcher\<engine>\LauncherConfig.custom.ps1 -- on a VM it overrides the config for that engine
# only. Read in isolation, passed to that engine's job(s) only, on top of the config's settings. Secrets are refused.
$engineCfgArgs = @{}
foreach ($folder in @($Engines | ForEach-Object { Get-SIContainerEngineLauncherFolder -Engine $_ } | Where-Object { $_ } | Select-Object -Unique)) {
    $lcPath = Join-Path $PSScriptRoot ('launcher\{0}\LauncherConfig.custom.ps1' -f $folder)
    if (-not (Test-Path -LiteralPath $lcPath)) { continue }
    $lc = Read-SILauncherCustomSettings -Path $lcPath
    foreach ($e in @($lc.Errors)) { Write-Warning ('[config] launcher\{0}\LauncherConfig.custom.ps1: {1}' -f $folder, $e) }
    $lcPass = Get-SIConfigEnvArgs -Names @($lc.Settings.Keys) -Globals $lc.Settings -Ignore $retiredSettings
    $engineCfgArgs[$folder] = @($lcPass.EnvArgs | Where-Object { $_.Length -le 4096 })
    Write-Host ('[config] {0} setting(s) from launcher\{1}\LauncherConfig.custom.ps1 go to its job(s){2}' -f @($engineCfgArgs[$folder]).Count, $folder, $(if (@($lcPass.Refused).Count) { "; NOT passed (secrets travel only as secrets): $(@($lcPass.Refused) -join ', ')" } else { '' }))
}
# #209: what the config must carry depends on the sign-in. Secret: exactly as before. Certificate: the SPN's
# ids, no secret. Managed identity: nothing (the identity is Bootstrap's own).
$spnRequired = @(Get-SIBootstrapRequiredSpnGlobals -Mode $authMode)
$haveNewSpn = $true
foreach ($n in $spnRequired) {
    if ([string]::IsNullOrWhiteSpace((Get-Variable -Name $n -ValueOnly -Scope Global -ErrorAction SilentlyContinue))) { $haveNewSpn = $false; break }
}
if (-not $haveNewSpn -and $authMode -ne 'Secret') {
    $reqGlobals += $spnRequired      # no legacy-name fallback: those names carry SECRETS
} elseif (-not $haveNewSpn) {
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

# #475: queue scaling moves a secret-signed install to the managed identity, its grants applied (as -UseManagedIdentity
# -GrantIdentityRoles). The secret settings were checked above, so if a grant cannot be made the jobs stay exactly as they are.
if ($kedaMovesToIdentity) {
    $authMode = 'ManagedIdentity'
    $GrantIdentityRoles = [switch]$true
}

# ONE subscription for every call. Measured 2026-10-02: this read the sign-in's subscription while the resource calls ran
# against another default -- the saved hosting and the resources would have disagreed. The install's own config decides;
# the sign-in's subscription is the last resort, and every ARM call below names the subscription in its path.
. (Join-Path $PSScriptRoot 'setup\_shared\SI-ContainerUpdate.ps1')
# #521: no az CLI and no PowerShell module -- every Azure call below is ARM / data-plane REST through setup's own sign-in
# (setup\_shared\SI-SetupAzure.ps1), the resources through setup\_shared\SI-SetupArm.ps1, the image build through
# setup\_shared\SI-AcrBuild.ps1.
. ([IO.Path]::Combine($PSScriptRoot, 'setup', '_shared', 'SI-SetupAzure.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, 'setup', '_shared', 'SI-AcrBuild.ps1'))
$azCtx = $null
try { $azCtx = Get-SISetupAzureContext } catch { }
# ONE connect path (#524 / #521): nobody signed in in this process (the guided install signs in before it runs this) =
# setup signs in itself -- the Invardia support session's tokens, Azure Cloud Shell, or the browser. Never an az login.
if (-not $azCtx -or -not $azCtx.Account) {
    $signIn = @{}
    if ($SubscriptionId) { $signIn['SubscriptionId'] = $SubscriptionId }
    $tidHint = @([string]$global:SI_SPN_TenantId, [string]$global:SI_Graph_TenantId | Where-Object { $_ }) | Select-Object -First 1
    if ($tidHint) { $signIn['TenantId'] = $tidHint }
    $azCtx = Connect-SISetupAzure @signIn
}
$azCtxSubId = if ($azCtx -and $azCtx.Subscription) { [string]$azCtx.Subscription.Id } else { '' }
$azCtxTenantId = if ($azCtx -and $azCtx.Tenant) { [string]$azCtx.Tenant.Id } else { '' }
$subPick = Resolve-SIBootstrapSubscription -Globals @{
    SI_Bootstrap_SubscriptionId = $global:SI_Bootstrap_SubscriptionId; SI_AzSubscriptionId = $global:SI_AzSubscriptionId
    SI_WorkspaceResourceId = $global:SI_WorkspaceResourceId } -ContextSubscriptionId $azCtxSubId -Explicit $SubscriptionId
if (-not $subPick.SubscriptionId) { throw 'No subscription: set SI_AzSubscriptionId (or SI_Bootstrap_SubscriptionId) in config\SecurityInsight.custom.ps1, or sign in to Azure first.' }
$subId = $subPick.SubscriptionId
$script:SIBootstrapSubscriptionId = $subId
if ($azCtxSubId -ne $subId) { $null = Set-SIAzContext -Subscription $subId }
# #209: a managed-identity install may have no SPN in its config at all; the tenant is the sign-in's.
if ($authMode -eq 'ManagedIdentity' -and [string]::IsNullOrWhiteSpace([string]$spnTenantId)) { $spnTenantId = $azCtxTenantId }

# The tenant's size, ONCE (Microsoft Graph $count, REST): the collection jobs are sized for it (Get-SITenantSizedJobResources
# -- customer H 2026-10-08: 22,705 users + 5,097 groups ran the identity job out of memory at the default). Not readable =
# the defaults, said once; a size the customer set (SI_Bootstrap_Memory_<Engine>) always wins.
$script:SITenantCounts = Get-SITenantDirectoryCounts
if ($script:SITenantCounts) {
    Write-Host ('[size] this tenant: {0:N0} users, {1:N0} groups, {2:N0} service principals, {3:N0} devices -- the collection jobs are sized for it' -f $script:SITenantCounts.Users, $script:SITenantCounts.Groups, $script:SITenantCounts.ServicePrincipals, $script:SITenantCounts.Devices)
} else { Write-Host '[size] the tenant''s size could not be read (no directory read right for this sign-in) -- the jobs get the default sizes' -ForegroundColor DarkYellow }
# ...and kept on every job as tags (si-tenant-users=..., Get-SITenantSizeTags): the update's size rule reads them when its own
# identity cannot read the directory and the records do not say (a collection that wrote 0 users). None read: no tags, and
# a job keeps the ones an earlier setup wrote (tags are merged on update).
$siSizeTags = @(Get-SITenantSizeTags -Counts $script:SITenantCounts)

Write-Host ''
Write-Host '=== SecurityInsight v2.2 Container App Job bootstrap ==='
Write-Host ('  Subscription : {0}  (from {1})' -f $subId, $subPick.Source)
Write-Host ('  RG           : {0}' -f $ResourceGroupName)
Write-Host ('  Location     : {0}' -f $Location)
Write-Host ('  ACR          : {0}' -f $AcrName)
Write-Host ('  CAE          : {0}' -f $EnvName)
Write-Host ('  Engines      : {0}' -f ($Engines -join ', '))
Write-Host ('  Sign-in      : {0}' -f $(switch ($authMode) {
    'ManagedIdentity' { "managed identity '$ManagedIdentityName' (no secret)" }
    'Certificate'     { "SPN $spnAppId by certificate (Key Vault $CertificateKeyVaultName / $CertificateSecretName)" }
    default           { "SPN $spnAppId by client secret" } }))
Write-Host ''

# ---- 0. Resource provider registrations ----
# Required for Container Apps. Registering is a SUBSCRIPTION action (#223): setup running with rights on the SI resource
# group only cannot do it -- that is a one-time customer task, not a reason to stop before the first resource.
Write-Host '[0/5] Ensuring resource providers are registered ...'
foreach ($rp in @('Microsoft.App','Microsoft.OperationalInsights','Microsoft.ContainerRegistry','Microsoft.Insights','Microsoft.ManagedIdentity')) {   # #564: + ManagedIdentity (the runtime identity is created here)
    $p = Get-SIResourceProvider -ProviderNamespace $rp -SubscriptionId $subId -ErrorAction SilentlyContinue
    $state = if ($p) { [string]$p.RegistrationState } else { '' }
    if ($state -ne 'Registered') {
        Write-Host ('       Registering {0} ...' -f $rp)
        $registered = $false
        try {
            $null = Register-SIResourceProvider -ProviderNamespace $rp -SubscriptionId $subId
            # registration finishes in the background: wait for it (minutes at most) before the first resource of the provider
            for ($w = 0; $w -lt 30; $w++) {
                $p = Get-SIResourceProvider -ProviderNamespace $rp -SubscriptionId $subId -ErrorAction SilentlyContinue
                if ($p -and [string]$p.RegistrationState -eq 'Registered') { $registered = $true; break }
                Start-Sleep -Seconds 10
            }
        } catch { $registered = $false }
        if (-not $registered) {
            Write-Warning ("{0} is not registered and this identity cannot register it (a subscription action). CUSTOMER TASK, once: register the resource provider {0} on subscription {1} (Azure portal: the subscription > Resource providers > {0} > Register)." -f $rp, $subId)
            Write-Host ('       {0,-35} {1}' -f $rp, 'NOT registered (customer task)')
            continue
        }
    }
    Write-Host ('       {0,-35} {1}' -f $rp, 'Registered')
}

# ---- 1. ACR ----
Write-Host '[1/5] Ensuring Azure Container Registry ...'
$acr = Get-SIContainerRegistry -ResourceGroupName $ResourceGroupName -Name $AcrName -SubscriptionId $subId
if (-not $acr) {
    Write-Host '       Creating ACR (Basic SKU, ~$5/mo) ...'
    $acr = New-SIContainerRegistry -ResourceGroupName $ResourceGroupName -Name $AcrName -Location $Location -Sku 'Basic' -AdminEnabled $true -SubscriptionId $subId
}
if (-not $acr) { throw ("could not create or read the container registry '{0}' in '{1}'." -f $AcrName, $ResourceGroupName) }
Write-Host ('       loginServer = {0}' -f $acr.loginServer)

# ---- 2. Image build ----
$image = ('{0}/si-orchestrator:{1}' -f $acr.loginServer, $ImageTag)
# The build identity, computed ONCE here (git in a source tree, else the BUILD.json the package carries) and stamped into
# the image as /app/BUILD.json -- the job banners, run health and telemetry read it; nothing asks git at run time.
# It also tags every job (si-build), so the job itself says which build it runs.
. (Join-Path $PSScriptRoot 'engine\_shared\SI-BuildInfo.ps1')
$siBuild = Get-SIBuildInfo -SolutionRoot $PSScriptRoot
$siBuildTag = ('si-build={0}{1}' -f $siBuild.display, $(if ($siBuild.shortCommit) { '+' + $siBuild.shortCommit } else { '' }))
Write-Host ('       build: {0}' -f (Format-SIBuildLine $siBuild))
if ($SkipImageBuild) {
    Write-Host '[2/5] Skipping image build (-SkipImageBuild).'
} else {
    Write-Host ('[2/5] Building image via ACR Tasks: {0} ...' -f $image)
    # Build context is this script's own folder -- the solution root (container/Dockerfile does COPY . /app/). It is packed
    # here with the .dockerignore honoured (customer config never leaves the install), uploaded, and the REGISTRY builds it
    # (setup\_shared\SI-AcrBuild.ps1 -- the four ARM calls `az acr build` made). .NET reads long paths: no short-path copy.
    # BUILD.json at the build context's root lands at /app/BUILD.json (COPY . /app/); git ignores it in a source tree.
    if ($siBuild.source -eq 'git') { $null = Write-SIBuildInfo -Info $siBuild -Path (Join-Path $PSScriptRoot 'BUILD.json') }
    $build = Invoke-SIAcrRestBuild -SubscriptionId $subId -ResourceGroup $ResourceGroupName -RegistryName $AcrName -SourcePath $PSScriptRoot `
        -ImageNames @(('si-orchestrator:{0}' -f $ImageTag)) -DockerFilePath 'container/Dockerfile' -TimeoutSeconds 900 `
        -OnPoll { param($s) Write-Host ('         build -- {0}' -f $s) }
    Write-Host ('       build {0}: {1} file(s), {2:N0} bytes uploaded, {3} s' -f $build.RunId, $build.Files, $build.Bytes, $build.Seconds)
    if (-not $build.Ok) { throw ('image build did not succeed: ' + $build.Status) }
    Write-Host '       build OK.'
}

# ---- 3. Container Apps Environment ----
Write-Host '[3/5] Ensuring Container Apps Environment ...'
# An environment that EXISTS is not fine because it exists: Azure can leave a new one Failed and never repairs it (a
# customer install, 2026-10-13 -- the next run went on with the Failed one). Initialize-SIManagedEnvironment reads its
# state: ready = as it is; still being made = waited for; Failed and EMPTY = removed and created again (once per run);
# Failed with jobs or apps in it = nothing removed, it stops and says so.
# #220: logs leave through Azure Monitor into THIS install's SI workspace (the diagnostic setting below). Created
# without a destination, Azure makes a stray "workspace-rg..." workspace and every job's console log lands there --
# measured 2026-10-03; the internal tenant carried three such orphans from earlier environments.
$cae = Initialize-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $EnvName -Location $Location -SubscriptionId $subId -InfrastructureSubnetId $InfrastructureSubnetId -Internal:$EnvironmentInternal
if (-not $cae) { throw ("could not create or read the Container Apps environment '{0}' in '{1}'." -f $EnvName, $ResourceGroupName) }
# #220: an environment that logs through Azure Monitor gets the diagnostic setting into the SI workspace (idempotent PUT).
if ($cae -and [string]$cae.properties.appLogsConfiguration.destination -eq 'azure-monitor' -and $global:SI_WorkspaceResourceId) {
    Set-SIEnvironmentLogSetting -EnvironmentId ([string]$cae.id) -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId)
    Write-Host ('       logs: console + system -> {0} (diagnostic setting si-environment-logs)' -f ($global:SI_WorkspaceResourceId -split '/')[-1])
} elseif ($cae -and [string]$cae.properties.appLogsConfiguration.destination -eq 'log-analytics') {
    Write-Host ('       logs: the environment writes to Log Analytics workspace {0} directly (set when it was created).' -f [string]$cae.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)
}
Write-Host '       OK.'

# ---- 3b. The jobs' identity + its grants (#209) ----
# Managed identity: ONE user-assigned identity for every engine job -- the identity IS the engine, so it holds the
# engine's grants. Certificate: the same kind of identity, used ONLY to resolve the PFX's Key Vault reference.
# Grants are a PLAN: printed with what is present or missing, applied only with -GrantIdentityRoles.
function Invoke-SIIdentityGrantPlan {
    param([object[]]$Plan, [Parameter(Mandatory)][string]$PrincipalId, [switch]$Apply)
    $missing = 0
    # #223: setup may run with rights on the SI resource group ONLY (the Invardia Support app: Contributor + a
    # conditioned RBAC Administrator there). A grant it cannot make is not a failure of setup -- it is a one-time
    # CUSTOMER task, printed at the end as a ready-to-run command.
    $script:SICustomerTasks = New-Object System.Collections.Generic.List[string]
    $rgPrefix = ('/subscriptions/{0}/resourceGroups/{1}/' -f $script:SIBootstrapSubscriptionId, $ResourceGroupName).ToLowerInvariant()
    Write-Host ('       Grants the identity needs ({0}):' -f $(if ($Apply) { 'applying, -GrantIdentityRoles' } else { 'checking only -- pass -GrantIdentityRoles to apply' }))
    foreach ($g in @($Plan | Where-Object { $_.Kind -eq 'AzureRole' })) {
        $have = $false
        try { $have = [bool](Test-SIRoleAssignmentPresent -ObjectId $PrincipalId -Scope $g.Scope -RoleDefinitionName $g.Role) } catch { $have = $false }
        $state = if ($have) { 'present' } elseif ($Apply) {
            # Microsoft.Authorization PUT with a new GUID, the principal type stated (a new identity has not replicated yet)
            $ok = $true
            try { $null = New-SIRoleAssignment -ObjectId $PrincipalId -Scope $g.Scope -RoleDefinitionName $g.Role -PrincipalType ServicePrincipal }
            catch { $ok = ([string]$_.Exception.Message -match '(?i)RoleAssignmentExists|already exists') }
            if ($ok) { 'granted' } else { $missing++; 'FAILED' }
        } else { $missing++; 'MISSING' }
        Write-Host ('         [{0,-7}] {1,-32} on {2}' -f $state, $g.Role, $g.Scope)
        if ($state -in 'FAILED', 'MISSING') {
            $where = if (($g.Scope.ToLowerInvariant() + '/').StartsWith($rgPrefix)) { 'inside the SI resource group' } else { 'OUTSIDE the SI resource group' }
            $script:SICustomerTasks.Add(('# {0} ({1})' -f $g.Why, $where))
            # #564: a portal path, never an az command (a customer has no az CLI)
            $script:SICustomerTasks.Add(('# Azure role "{1}" on "{2}" for the managed identity {0} -- Azure portal: open the scope > Access control (IAM) > Add > Add role assignment > {1} > Managed identity' -f $PrincipalId, $g.Role, $g.Scope))
        }
    }
    $appRoles = @($Plan | Where-Object { $_.Kind -eq 'AppRole' })
    if ($appRoles.Count) {
        # Microsoft Graph over setup's own REST sign-in (Invoke-SIAzRestRequest -Audience Graph): the token is the sign-in's
        $graph = { param([string]$Method, [string]$Uri, $Body)
            $r = Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Audience Graph -Body $(if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 5 -Compress } else { $null }) -What 'Microsoft Graph'
            if ($r -and "$($r.Content)".Trim()) { $r.Content | ConvertFrom-Json } }
        $assigned = @()
        try { $assigned = @((& $graph 'GET' "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" $null).value) } catch { }
        foreach ($grp in ($appRoles | Group-Object ResourceAppId)) {
            $res = $null; $looked = $false
            try { $res = @((& $graph 'GET' "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($grp.Name)'" $null).value)[0]; $looked = $true } catch { }
            foreach ($g in $grp.Group) {
                $role = if ($res) { @($res.appRoles | Where-Object { $_.value -eq $g.Role })[0] } else { $null }
                # The API is not in this tenant at all (e.g. no Defender for Endpoint: no WindowsDefenderATP service
                # principal): nothing to grant and nothing to read -- not a missing grant (live 2026-10-06, Community rehearsal).
                $state = if ($looked -and -not $res) { 'ABSENT' }
                         elseif (-not $role) { $missing++; 'UNKNOWN' }
                         elseif ($assigned | Where-Object { $_.appRoleId -eq $role.id -and $_.resourceId -eq $res.id }) { 'present' }
                         elseif ($Apply) {
                             try {
                                 $__siRes = $res; $__siRole = $role; $null = Invoke-SIRetryNotThereYet -Waits @(10, 20, 30) -Action {
                                     & $graph 'POST' "https://graph.microsoft.com/v1.0/servicePrincipals/$PrincipalId/appRoleAssignments" @{ principalId = $PrincipalId; resourceId = $__siRes.id; appRoleId = $__siRole.id } }
                                 # (the retry above: an identity made a minute ago answers "not found" on its own id for a
                                 # moment -- only that answer is tried again, about a minute; a refusal stops at once)
                                 'granted'
                             } catch {
                                 if ("$($_.Exception.Message)" -match '(?i)already exists') { 'present' }
                                 else { $missing++; Write-Host ('           not granted: {0}' -f ("$($_.Exception.Message)" -replace '\s+', ' ')) -ForegroundColor DarkYellow; 'FAILED' }
                             }
                         } else { $missing++; 'MISSING' }
                Write-Host ('         [{0,-7}] {1,-40} ({2}){3}' -f $state, $g.Role, $g.Resource, $(if ($state -eq 'ABSENT') { ' -- not in this tenant: nothing to grant' } else { '' }))
                if ($state -in 'FAILED', 'MISSING', 'UNKNOWN') {
                    $script:SICustomerTasks.Add(('# API permission {0} on {1} for the jobs'' identity (needs AppRoleAssignment.ReadWrite.All, or an admin: Entra admin center -> Enterprise applications -> the identity -> Permissions)' -f $g.Role, $g.Resource))
                }
            }
        }
    }
    if ($missing -gt 0) {
        Write-Warning ('{0} grant(s) are missing. The jobs fail on what is missing -- re-run with -GrantIdentityRoles (needs rights to assign roles and app permissions), or make them as one-time customer tasks (listed below).' -f $missing)
        Write-Host ''
        Write-Host '       CUSTOMER TASKS -- one-time, by someone with rights there (setup did not have them):' -ForegroundColor Yellow
        foreach ($t in $script:SICustomerTasks) { Write-Host ('         {0}' -f $t) -ForegroundColor Yellow }
        Write-Host ''
    }
    return $missing
}

function Remove-SIBootstrapReplacedJob {
    <# #475: one job the chosen layout replaces. Removed only when it exists in this resource group AND SI's setup created
       it (its si-build tag); anything else is left alone and said. A failed removal is said with the command. #>
    param([Parameter(Mandatory)][string]$Name)
    $j = $null
    try { $j = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $script:SIBootstrapSubscriptionId } catch { $j = $null }
    if (-not $j) { return }
    if (-not (Test-SIBootstrapJobIsSI -Job $j)) {
        Write-Warning ('[{0}] left in place: SecurityInsight''s setup did not create it (no si-build tag). If it runs SecurityInsight beside the new layout, remove it yourself.' -f $Name)
        return
    }
    $removed = $true; $why = ''
    try { Remove-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $script:SIBootstrapSubscriptionId } catch { $removed = $false; $why = $_.Exception.Message }
    if ($removed) { Write-Host ('       {0}: replaced by the new job layout -- removed.' -f $Name) }
    else { Write-Warning ('[{0}] could not be removed ({2}) -- it would run beside the new layout. Remove it: Azure portal > resource group {1} > {0} > Delete.' -f $Name, $ResourceGroupName, $why) }
}

# The secret NAMES a vault holds (never a value), read once per vault: a job references a Key Vault secret only when it
# is there (Resolve-SIJobKeyVaultSecret) -- Container Apps refuses the whole job over a reference to a missing secret
# (live 2026-10-06: no Shodan key in a new install's vault, and caj-si-publicip was never created). $null = the names
# could not be read from here. The object wrapper keeps an EMPTY vault apart from an unreadable one.
$script:SIVaultSecretNames = @{}
function Get-SIBootstrapVaultSecretNames { param([string]$VaultName)
    if ([string]::IsNullOrWhiteSpace($VaultName)) { return $null }
    $k = $VaultName.ToLowerInvariant()
    if (-not $script:SIVaultSecretNames.ContainsKey($k)) {
        $r = Get-SIKeyVaultSecretNames -VaultName $VaultName
        $script:SIVaultSecretNames[$k] = if ($null -ne $r) { ,([string[]]@($r | Where-Object { $_ })) } else { $null }
    }
    $n = $script:SIVaultSecretNames[$k]
    if ($null -eq $n) { return $null }
    return ,$n
}
function Write-SIJobSecretNote { param($Plan, [string]$JobName)
    if ($Plan -and $Plan.Message) { Write-Warning ('[{0}] {1}' -f $JobName, $Plan.Message) }
}

$jobIdentity = $null
$certVault   = $null
$shodanVault = $null
$openAiVault = $null
$smtpVault   = $null
$licenceVault = $null
# The engines that need the Pro licence (#170; asset tagging #236). #718: the hourly status report reads it to report as
# the Pro install it is (identified); it never refuses without one -- it then sends nothing.
$licensedEngines = @('asset-correlation', 'asset-properties', 'asset-cmdb', 'asset-vulnerabilities', 'asset-vulnerabilities-servicenow', 'asset-datasync', 'close-loop-mail', 'asset-tagging', 'asset-cmdb-sql', 'verification', 'heartbeat')
# #218: Risk Analysis mail, decided from the customer's own config.
$raMail = Get-SIContainerRaMailPlan -Globals $cfgGlobals
if ($authMode -ne 'Secret') {
    Write-Host ('[3b] Ensuring the jobs'' identity {0} ...' -f $ManagedIdentityName)
    $jobIdentity = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $ManagedIdentityName -Location $Location -SubscriptionId $subId
    if (-not $jobIdentity) { throw "could not create or read the user-assigned identity '$ManagedIdentityName' in '$ResourceGroupName'." }
    Write-Host ('       clientId  = {0}' -f $jobIdentity.clientId)
    Write-Host ('       principal = {0}' -f $jobIdentity.principalId)
    if ($authMode -eq 'Certificate') {
        $certVault = Get-SIKeyVaultArm -Name $CertificateKeyVaultName -SubscriptionId $subId
        if (-not $certVault) { throw "Key Vault '$CertificateKeyVaultName' was not found (or is not readable from here)." }
        # The certificate is REQUIRED: absent = one clear failure now, not a job Container Apps refuses. Unknown
        # (the names cannot be listed from here) = referenced unchecked, as before.
        $certPlan = Resolve-SIJobKeyVaultSecret -Alias 'si-spn-cert' -VaultName $CertificateKeyVaultName -VaultUri ([string]$certVault.properties.vaultUri) `
            -SecretName $CertificateSecretName -IdentityResourceId ([string]$jobIdentity.id) -Required -Feature 'the SPN certificate (-CertificateSecretName)' `
            -VaultSecretNames (Get-SIBootstrapVaultSecretNames -VaultName $CertificateKeyVaultName)
        Write-SIJobSecretNote -Plan $certPlan -JobName 'jobs'
    }
    # #185: the vault holding the Shodan key, for the publicip job's Key Vault reference.
    if ($Engines -contains 'publicip' -and -not [string]::IsNullOrWhiteSpace($ShodanKeyVaultName)) {
        $shodanVault = Get-SIKeyVaultArm -Name $ShodanKeyVaultName -SubscriptionId $subId
        if (-not $shodanVault) { Write-Warning ("Key Vault '{0}' (the Shodan key) was not found or is not readable from here -- publicip runs without Shodan unless a key value is configured." -f $ShodanKeyVaultName) }
    }
    # #215: the vault holding the Azure OpenAI key, when the install has Azure OpenAI configured.
    if ($haveOpenAiSettings -and -not [string]::IsNullOrWhiteSpace($OpenAIKeyVaultName)) {
        $openAiVault = if ($shodanVault -and $OpenAIKeyVaultName -eq $ShodanKeyVaultName) { $shodanVault } else { Get-SIKeyVaultArm -Name $OpenAIKeyVaultName -SubscriptionId $subId }
        if (-not $openAiVault) { Write-Warning ("Key Vault '{0}' (the Azure OpenAI key) was not found or is not readable from here -- the jobs run without AI unless a key value is configured." -f $OpenAIKeyVaultName) }
    }
    # #218: the vault holding the SMTP password, when the config switches Risk Analysis mail on with authenticated SMTP.
    # ...and when the close-loop daily mail job is deployed against an authenticated relay.
    if (($raMail.NeedsPassword -or ($Engines -contains 'close-loop-mail' -and $clMail.NeedsPassword)) -and -not [string]::IsNullOrWhiteSpace($SmtpKeyVaultName)) {
        $smtpVault = if ($openAiVault -and $SmtpKeyVaultName -eq $OpenAIKeyVaultName) { $openAiVault }
                     elseif ($shodanVault -and $SmtpKeyVaultName -eq $ShodanKeyVaultName) { $shodanVault }
                     else { Get-SIKeyVaultArm -Name $SmtpKeyVaultName -SubscriptionId $subId }
        if (-not $smtpVault) { Write-Warning ("Key Vault '{0}' (the SMTP password) was not found or is not readable from here." -f $SmtpKeyVaultName) }
    }
    # The install's own vault, where Set-SILicense keeps SI-License: the Pro engines read the licence from it at run
    # time, so a renewed or replaced licence is in force on the next run. (Before, the job carried a COPY of the licence
    # taken at setup -- a later licence change never reached it; found live 2026-10-03.)
    if (@($Engines | Where-Object { $licensedEngines -contains $_ }).Count -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_KeyVaultName)) {
        $kvName = [string]$global:SI_KeyVaultName
        $licenceVault = if ($shodanVault -and $kvName -eq $ShodanKeyVaultName) { $shodanVault }
                        elseif ($openAiVault -and $kvName -eq $OpenAIKeyVaultName) { $openAiVault }
                        elseif ($smtpVault -and $kvName -eq $SmtpKeyVaultName) { $smtpVault }
                        else { Get-SIKeyVaultArm -Name $kvName -SubscriptionId $subId }
        if (-not $licenceVault) { Write-Warning ("Key Vault '{0}' (the SecurityInsight licence) was not found or is not readable from here -- the Pro jobs get the licence configured here, if any." -f $kvName) }
    }
    $readerScopes = @($IdentityReaderScopes | Where-Object { $_ })
    if (-not $readerScopes.Count) { $readerScopes = @("/subscriptions/$subId") }
    $dcrSub = if ($SubscriptionId) { $subId } elseif ($global:SI_AzSubscriptionId) { [string]$global:SI_AzSubscriptionId } else { ($global:SI_WorkspaceResourceId -split '/')[2] }
    # The storage account: the managed identity's data roles, and -- with queue scaling -- the scaler's queue read.
    $stgId  = if ($authMode -eq 'ManagedIdentity' -or $UseKEDA) { [string](Get-SIStorageAccountArm -Name ([string]$global:SI_StorageAccount) -SubscriptionId $subId).id } else { $null }
    $grantPlan = Get-SIContainerIdentityGrantPlan -Mode $authMode -ReaderScopes $readerScopes `
        -DcrResourceGroupId ('/subscriptions/{0}/resourceGroups/{1}' -f $dcrSub, $global:SI_DcrResourceGroup) `
        -WorkspaceResourceId $global:SI_WorkspaceResourceId -DefenderWorkspaceResourceId ([string]$global:SI_DefenderWorkspaceResourceId) `
        -StorageAccountId ([string]$stgId) -KeyVaultId $(if ($certVault) { [string]$certVault.id } else { '' }) `
        -AcrRegistryId $(if ($authMode -eq 'ManagedIdentity' -and $acr) { [string]$acr.id } else { '' }) `
        -ShodanKeyVaultId $(if ($shodanVault) { [string]$shodanVault.id } else { '' }) `
        -OpenAIKeyVaultId $(if ($openAiVault) { [string]$openAiVault.id } else { '' }) `
        -SmtpKeyVaultId $(if ($smtpVault) { [string]$smtpVault.id } else { '' }) `
        -LicenceKeyVaultId $(if ($licenceVault) { [string]$licenceVault.id } else { '' }) -KedaQueueScaler:([bool]$UseKEDA)
    # #269: the daily job flow (caj-si-flow) runs as this identity and STARTS the other jobs -- the web app's grant on the
    # jobs' resource group, nothing wider. It starts jobs and reads their executions; the one thing it changes is the run
    # limit of a job that was stopped at that limit, so the step can be started again in the same run (self-healing).
    if (@($Engines) -contains 'flow') {
        $grantPlan = @($grantPlan) + @([pscustomobject]@{ Kind = 'AzureRole'; Role = 'Container Apps Jobs Contributor'
            Scope = ('/subscriptions/{0}/resourceGroups/{1}' -f $subId, $ResourceGroupName); Why = 'the daily job flow (caj-si-flow) starts each job of the flow and follows it to its end' })
    }
    $grantMissing = Invoke-SIIdentityGrantPlan -Plan $grantPlan -PrincipalId $jobIdentity.principalId -Apply:$GrantIdentityRoles
    if ($kedaMovesToIdentity -and [int]$grantMissing -gt 0) {
        # no half-switched install: the jobs keep the client secret and their scheduled layout until every grant is there
        Write-Warning ('[parts] the move to the managed identity is NOT made: {0} grant(s) could not be made here (listed above with the command that makes each). The jobs keep the client secret and run as scheduled jobs; make the grants, then run setup again.' -f [int]$grantMissing)
        $authMode = 'Secret'
        $UseKEDA = [switch]$false
        $kedaMovesToIdentity = $false
    } elseif ($kedaMovesToIdentity) {
        Write-Host '[parts] the jobs now sign in as the managed identity (every grant is in place); the client secret is no longer used by them.'
    }
    if ($authMode -eq 'ManagedIdentity') {
        Write-Host '       Not granted here, on purpose:'
        Write-Host '         * creating a NEW DCR / table on a first run needs Monitoring Contributor on the DCR resource group and'
        Write-Host '           Log Analytics Contributor on the workspace -- or create them once with the setup SPN.'
        Write-Host '         * Pro identity ledger (SQL): CREATE USER [<identity name>] FROM EXTERNAL PROVIDER in the ledger database.'
        if ($Engines -contains 'asset-vulnerabilities' -and [string]$global:SI_VulnSync_Target -eq 'Sql') {
            # WITH SID = the client id, TYPE = E: the server needs no directory identity (FROM EXTERNAL PROVIDER does).
            $vn = [string]$jobIdentity.name
            $vsid = '0x' + ((([guid][string]$jobIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            Write-Host ('         * vulnerability close-loop (SQL): run once in {0}:' -f [string]$global:SI_VulnSync_SqlDatabase)
            Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $vn, $vsid)
            Write-Host ('             ALTER ROLE db_datareader ADD MEMBER [{0}]; ALTER ROLE db_datawriter ADD MEMBER [{0}];' -f $vn)
        }
        if (($Engines -contains 'asset-datasync' -or $Engines -contains 'asset-cmdb-sql') -and [string]$global:SI_ProSqlDatabase) {
            # The data backend writes sidata.* and reads vuln.* in the Pro database (setup\Initialize-SIDataSql.ps1 creates the tables);
            # the SQL CMDB connector (#271) writes cmdbsync.* there with the same two roles.
            $dn = [string]$jobIdentity.name
            $dsid = '0x' + ((([guid][string]$jobIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            Write-Host ('         * Pro data backend (SQL): run once in {0} (skip CREATE USER if the identity already exists there):' -f [string]$global:SI_ProSqlDatabase)
            Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $dn, $dsid)
            # #672: the engine's least-privilege role si_engine, never db_datareader / db_datawriter on the whole database
            Write-Host ('             then the role and its grants: . .\engine\pro-settings\SI-EngineGrants.ps1; Get-SIEngineGrantSql -UserName ''{0}''  (run its output)' -f $dn)
        }
        if ($Engines -contains 'templates-publish' -and [string]$global:SI_ProSqlDatabase) {
            # The template publish job writes cfg.Template / cfg.TemplateRevision / cfg.InstallState / cfg.ChangeLog.
            $tn = [string]$jobIdentity.name
            $tsid = '0x' + ((([guid][string]$jobIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            Write-Host ('         * template releases (SQL): run once in {0} (skip CREATE USER if the identity already exists there):' -f [string]$global:SI_ProSqlDatabase)
            Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $tn, $tsid)
            # #672: the engine's least-privilege role si_engine, never db_datareader / db_datawriter on the whole database
            Write-Host ('             then the role and its grants: . .\engine\pro-settings\SI-EngineGrants.ps1; Get-SIEngineGrantSql -UserName ''{0}''  (run its output)' -f $tn)
        }
        if ($Engines -contains 'close-loop-mail' -and [string]$global:SI_VulnSync_SqlDatabase) {
            # The daily mail only READS the close-loop's tables (and the data backend's tiers / daily statistics there).
            $mn = [string]$jobIdentity.name
            $msid = '0x' + ((([guid][string]$jobIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            Write-Host ('         * close-loop daily mail (SQL, read only): run once in {0} (skip CREATE USER if the identity already exists there):' -f [string]$global:SI_VulnSync_SqlDatabase)
            Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $mn, $msid)
            Write-Host ('             ALTER ROLE db_datareader ADD MEMBER [{0}];' -f $mn)
        }
        if ($Engines -contains 'close-loop-mail' -and [string]$global:SI_ProSqlDatabase) {
            # #252: the same job sends the exemption mails -- it reads cfg.* and writes ONLY the exemption mail outbox.
            $en = [string]$jobIdentity.name
            $esid = '0x' + ((([guid][string]$jobIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
            Write-Host ('         * exemption mails (SQL): run once in {0} (skip CREATE USER if the identity already exists there):' -f [string]$global:SI_ProSqlDatabase)
            Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $en, $esid)
            Write-Host ('             ALTER ROLE db_datareader ADD MEMBER [{0}]; GRANT INSERT, UPDATE ON cfg.ExemptionMail TO [{0}];' -f $en)
            # #258: it also sends the department sign-in mails and blanks each one it sent (the sign-in outbox)
            Write-Host ('             GRANT UPDATE ON cfg.SignInMail TO [{0}];' -f $en)
            # #291: and the scheduled management summaries (their outbox)
            Write-Host ('             GRANT UPDATE ON cfg.ReportMail TO [{0}];' -f $en)
            # #260: the mails it sends are on the audit trail -- INSERT + SELECT only, never UPDATE / DELETE on it
            Write-Host ('             ALTER ROLE si_audit_writer ADD MEMBER [{0}];' -f $en)
        }
    }
}
$jobAuth = Get-SIContainerJobAuthArgs -Mode $authMode -SpnAppId $spnAppId -SpnSecret $spnSecret -SpnTenantId $spnTenantId -SpnObjectId $spnObjectId `
    -IdentityClientId $(if ($jobIdentity) { [string]$jobIdentity.clientId }) -IdentityPrincipalId $(if ($jobIdentity) { [string]$jobIdentity.principalId }) `
    -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) `
    -KeyVaultUri $(if ($certVault) { [string]$certVault.properties.vaultUri }) -CertificateSecretName $CertificateSecretName

# ---- 3c. Asset tagging's OWN identity (#236) ----
# The asset-tagging job is the one job that WRITES to the tenant, so it never runs as the collection identity (which
# stays read only, whatever the sign-in mode of the other jobs). It gets its own user-assigned identity and its own
# grant plan (Get-SIAssetTaggingIdentityGrantPlan). The write grants are OPT-IN (-GrantTaggingRoles); without them the
# plan is printed and the job can only report. The job also reads its rules from the Pro settings database.
$taggingIdentity = $null
$taggingAuth     = $null
$taggingRegistryArgs = @()
if ($Engines -contains 'asset-tagging') {
    Write-Host ('[3c] Ensuring asset tagging''s own identity {0} (never the collection identity) ...' -f $TaggingIdentityName)
    if ($authMode -ne 'Secret' -and $TaggingIdentityName -eq $ManagedIdentityName) {
        throw "-TaggingIdentityName must not be the collection identity '$ManagedIdentityName': the collection identity stays read only."
    }
    $taggingIdentity = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $TaggingIdentityName -Location $Location -SubscriptionId $subId
    if (-not $taggingIdentity) { throw "could not create or read the asset-tagging identity '$TaggingIdentityName' in '$ResourceGroupName'." }
    Write-Host ('       clientId  = {0}' -f $taggingIdentity.clientId)
    Write-Host ('       principal = {0}' -f $taggingIdentity.principalId)
    $tagReaderScopes = @($IdentityReaderScopes | Where-Object { $_ })
    if (-not $tagReaderScopes.Count) { $tagReaderScopes = @("/subscriptions/$subId") }
    $tagDcrSub = if ($SubscriptionId) { $subId } elseif ($global:SI_AzSubscriptionId) { [string]$global:SI_AzSubscriptionId } else { ($global:SI_WorkspaceResourceId -split '/')[2] }
    $tagStgId  = [string](Get-SIStorageAccountArm -Name ([string]$global:SI_StorageAccount) -SubscriptionId $subId).id
    $taggingPlan = Get-SIAssetTaggingIdentityGrantPlan -ReaderScopes $tagReaderScopes -TaggingScopes @($TaggingScopes | Where-Object { $_ }) `
        -DcrResourceGroupId ('/subscriptions/{0}/resourceGroups/{1}' -f $tagDcrSub, $global:SI_DcrResourceGroup) `
        -WorkspaceResourceId $global:SI_WorkspaceResourceId -StorageAccountId ([string]$tagStgId) -AcrRegistryId $(if ($acr) { [string]$acr.id } else { '' }) `
        -LicenceKeyVaultId $(if ($licenceVault) { [string]$licenceVault.id } else { '' })
    if (-not $GrantTaggingRoles) {
        Write-Host '       Writes are OFF: what the job needs to run and report is granted; the WRITE grants below are only checked. Pass -GrantTaggingRoles to grant them, then turn the Pro setting' -ForegroundColor Yellow
        Write-Host '       SI_Pro_AssetTagging_Apply on to let the job write. Until both, the job reports what it WOULD tag.' -ForegroundColor Yellow
    }
    # What the job needs to RUN (its licence, the rules' reads, its activity rows, its run log) is always granted -- without
    # it every run stops before it reports anything (fix request 85bd728f); the WRITES only with -GrantTaggingRoles.
    $null = Invoke-SIIdentityGrantPlan -Plan @($taggingPlan | Where-Object { -not $_.Write }) -PrincipalId $taggingIdentity.principalId -Apply
    $null = Invoke-SIIdentityGrantPlan -Plan @($taggingPlan | Where-Object { $_.Write }) -PrincipalId $taggingIdentity.principalId -Apply:$GrantTaggingRoles
    if ([string]$global:SI_ProSqlDatabase) {
        $tn = [string]$taggingIdentity.name
        $tsid = '0x' + ((([guid][string]$taggingIdentity.clientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
        Write-Host ('       * asset tagging reads its rules from the Pro settings database: run once in {0} (skip CREATE USER if it exists):' -f [string]$global:SI_ProSqlDatabase)
        Write-Host ('             CREATE USER [{0}] WITH SID = {1}, TYPE = E;' -f $tn, $tsid)
        Write-Host ('             ALTER ROLE db_datareader ADD MEMBER [{0}];' -f $tn)
    }
    $tagTenant = if ($spnTenantId) { [string]$spnTenantId } else { $azCtxTenantId }
    $taggingAuth = Get-SIContainerJobAuthArgs -Mode ManagedIdentity -SpnTenantId $tagTenant `
        -IdentityClientId ([string]$taggingIdentity.clientId) -IdentityPrincipalId ([string]$taggingIdentity.principalId) -IdentityResourceId ([string]$taggingIdentity.id)
    $taggingRegistryArgs = Get-SIRegistryPullArgs -Mode ManagedIdentity -IdentityResourceId ([string]$taggingIdentity.id) -AcrName $AcrName
}

# ---- 3d. The install's customisation files, for the jobs ----
# CMDB.csv, custom Risk Analysis queries, exclusions, enrichment rules, schema overlays, decision files: the image never
# carries them (a shared artifact must not hold a tenant's files), so they go to the 'sioverlay' container of the install's
# storage account and every job restores them at start. Community needs no licence for this. A Pro install with the
# settings database keeps its configuration there instead. A failure here never stops setup.
. (Join-Path $PSScriptRoot 'container\_shared\SI-ContainerRunState.ps1')
if ($global:SI_ProSqlServer -and $global:SI_ProSqlDatabase -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'engine\pro-settings\SI-ProSettings.ps1'))) {
    Write-Host '[3d] Customisation files: this install keeps its configuration in the Pro settings database -- nothing to share.'
} else {
    Write-Host '[3d] Sharing the install''s customisation files with the jobs ...'
    # blob data plane over REST (the update's REST seam, setup\_shared\SI-UpdateRest.ps1), as setup's own sign-in (Storage Blob
    # Data Contributor on the account) -- no az, no key
    $overlayPub = Publish-SIContainerOverlay -Root $PSScriptRoot -AccountName ([string]$global:SI_StorageAccount) -Rest (New-SIUpdateRestSeam)
    if (@($overlayPub.Failed).Count) { Write-Warning ('       {0}' -f $overlayPub.Message) } else { Write-Host ('       {0}' -f $overlayPub.Message) }
}

# ---- 4. Container App Jobs (one per engine) ----
# How the jobs pull the image. A managed-identity install pulls AS the identity (AcrPull, in the grant plan) -- no
# registry password anywhere. Otherwise the registry's admin credentials, as before. Measured 2026-10-02: a registry
# with admin access DISABLED (the secure setting) made `passwords[0]` a null-index crash with no explanation.
$registryAuthArgs = Get-SIRegistryPullArgs -Mode $authMode -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) `
    -AdminCredential $(if ($authMode -ne 'ManagedIdentity') { Get-SIContainerRegistryCredential -RegistryId ([string]$acr.id) }) -AcrName $AcrName

# ---- 4.0 (#269) The daily job flow and the ServiceNow jobs ----
# The jobs that exist already: an EXISTING install keeps its timers until someone switches (Operations > Jobs or
# setup\Switch-SIJobOrchestration.ps1); a NEW install runs as one flow. Setup never changes an existing job's trigger.
. (Join-Path $PSScriptRoot 'engine\_shared\SI-JobFlow.ps1')
$flowMap = Get-SIJobFlowMap
$existingJobObjects = @(Get-SIContainerAppJobList -ResourceGroupName $ResourceGroupName -SubscriptionId $subId | Where-Object { $_ })
$existingJobs = @($existingJobObjects | ForEach-Object { [string]$_.name })
# the existing jobs' triggers decide too: an install that stopped half-way (its pipeline jobs Manual, caj-si-flow not made yet)
# is completed as the pipeline -- never left with caj-si-flow Manual and no job on a timer ("neither mode", nothing runs)
$orch = Get-SIJobOrchestrationMode -Explicit $JobOrchestration -ExistingInstall ([bool]@($existingJobs | Where-Object { $_ -like 'caj-si-*' -and $_ -ne 'caj-si-updater' }).Count) `
            -ExistingJobs @(ConvertTo-SIJobFlowTriggerList -ArmJobs $existingJobObjects) -Map $flowMap
Write-Host ('[4/5] Jobs run as: {0} -- {1}' -f $(if ($orch.Mode -eq 'flow') { ('ONE PIPELINE -- Collect, Correlate, Deliver (caj-si-flow wakes "{0}" and starts the pipeline when it is due -- default daily 19:00 in the local time of the install''s Azure region (Danish time when the region is not known), after the 18:30 update, SI_Pipeline_StartTime / SI_Pipeline_TimeZone, changed on Operations > Jobs); each stage and each job starts when the one before it has ended' -f $ScheduleFlow) } else { 'each job on its own timer' }), $orch.Why)
if ($orch.Mode -eq 'schedules' -and @($existingJobs).Count) { Write-Host '       (recommended: switch to the flow -- Operations > Jobs, or .\setup\Switch-SIJobOrchestration.ps1 -Mode flow)' -ForegroundColor Yellow }
if ($JobOrchestration -and @($existingJobs).Count -and $orch.Mode -eq 'flow') { Write-Host '       existing jobs keep their trigger here -- .\setup\Switch-SIJobOrchestration.ps1 -Mode flow -Apply moves them into the flow (previewed, reversible).' -ForegroundColor Yellow }
$snowPlan = Get-SIServiceNowJobPlan -Globals $bootGlobals -Cmdb ([bool]$ServiceNowCmdb) -Vulnerabilities ([bool]$ServiceNowVulnerabilities)
$snowSel = Select-SIBootstrapServiceNowEngines -Engines $Engines -Plan $snowPlan -ExistingJobs $existingJobs
$Engines = @($snowSel.Engines)
foreach ($sk in @($snowSel.Skipped)) { Write-Host ('       {0,-34} skipped -- {1}' -f (Get-SIBootstrapJobName -Engine $sk.Engine), $sk.Why) -ForegroundColor DarkGray }
if ($authMode -eq 'Secret' -and @($Engines) -contains 'flow') {
    Write-Host ('       CUSTOMER TASK (the flow signs in as the SPN here): give the app {0} "Container Apps Jobs Contributor" on resource group {2} (Azure portal: Resource groups > {2} > Access control (IAM) > Add > Add role assignment; subscription {1})' -f $spnAppId, $subId, $ResourceGroupName) -ForegroundColor Yellow
}
# #269: department / governance / task / exemption mails run in the mail job -- a Pro install without it sends none.
if (@($Engines | Where-Object { $licensedEngines -contains $_ }).Count -and @($Engines) -notcontains 'close-loop-mail') {
    Write-Warning '[mail] this Pro install gets no mail job (caj-si-close-loop-mail): department, governance, task and exemption mails will not be sent. Add close-loop-mail to the engine list (-Engines / SI_Bootstrap_Engines) and run setup again.'
}

foreach ($engine in $Engines) {
    # Risk Analysis is a different beast (report build, not collection). Compute
    # the flag up-front so it can gate job naming + KEDA decisions consistently.
    # 'risk-analysis-detailed' is a second RA-class job; same entrypoint + env
    # surface, but $SI_RA_MODE=Detailed and a separate cron schedule.
    # Extra report jobs (SI_Bootstrap_RiskAnalysisJobs, engine 'ra-<name>') are Risk Analysis jobs too -- $raJobs holds
    # each one's mode, template and schedule (Get-SIRiskAnalysisJobPlan).
    $isRiskAnalysis         = $raJobs.ContainsKey($engine) -or ($engine -eq 'risk-analysis' -or $engine -eq 'risk-analysis-detailed')
    $isRiskAnalysisDetailed = ($engine -eq 'risk-analysis-detailed')
    $raJob                  = if ($raJobs.ContainsKey($engine)) { $raJobs[$engine] } else { $null }
    $raScale                = $null   # #742: decided with the job's sign-in, below
    # #236: asset tagging signs in as its OWN identity and pulls as it; every other job as the collection sign-in.
    $isAssetTagging = ($engine -eq 'asset-tagging')
    $engAuth     = if ($isAssetTagging) { $taggingAuth } else { $jobAuth }
    $engAuthMode = if ($isAssetTagging) { 'ManagedIdentity' } else { $authMode }
    $engRegistry = if ($isAssetTagging) { $taggingRegistryArgs } else { $registryAuthArgs }
    # #235: the template publish job is MANUAL only -- the web app starts it with the accepted fingerprint; never KEDA, no cron.
    $isManualOnly = ($engine -eq 'templates-publish')

    # Container App Jobs name max 32 chars. Engine names longer than ~18 chars
    # need a shortened alias for the job-name slot (the SI_ENGINE env var still
    # carries the full name for the dispatcher / orchestrator validset).
    $engineNameShort = switch ($engine) {
        'privilege-tier-classifier' { 'ptc' }
        'schema-discovery'          { 'schema' }
        'templates-publish'         { 'templates' }
        # #269: the ServiceNow vulnerability connector's job (a job name is at most 32 characters)
        'asset-vulnerabilities-servicenow' { 'asset-vulns-servicenow' }
        default                     { if ($raJob) { $raJob.JobShort } else { $engine } }
    }

    # KEDA mode creates two jobs per engine; legacy + RA mode create one. RA
    # never participates in KEDA even when -UseKEDA is passed -- it's a single-
    # container report build, not a per-asset shard workload.
    $producerName = ('caj-si-{0}-producer' -f $engineNameShort)
    $workerName   = ('caj-si-{0}-worker' -f $engineNameShort)
    # #236: asset tagging is one run over the rules, not a shard workload -- never KEDA (caj-si-asset-tagging).
    # #269: the flow runner is one run that starts the others -- never KEDA (caj-si-flow).
    $isFlow = ($engine -eq 'flow')
    # #475: queue scaling for the engines that discover into parts (Test-SIKedaPartsEngine); every other job stays one
    # scheduled job, also when queue scaling is on
    $engineKeda   = ([bool]$UseKEDA -and (Test-SIKedaPartsEngine $engine))
    $jobName      = if ($engineKeda -and -not $isRiskAnalysis -and -not $isAssetTagging -and -not $isManualOnly -and -not $isFlow) { $workerName } else { ('caj-si-{0}' -f $engineNameShort) }
    $schedule    = switch ($engine) {
        'identity'                { $ScheduleIdentity }
        'azure'                   { $ScheduleAzure }
        'privilege-tier-classifier' { $ScheduleClassifier }
        'publicip'                { $SchedulePublicIp }
        'schema-discovery'        { $ScheduleSchemaDiscovery }
        'risk-analysis'           { $ScheduleRiskAnalysis }
        'risk-analysis-detailed'  { $ScheduleRiskAnalysisDetailed }
        'asset-correlation'       { $ScheduleCorrelation }
        'asset-properties'        { $ScheduleAssetProperties }
        'asset-cmdb'              { $ScheduleCmdb }
        'asset-trend'             { $ScheduleTrend }
        'asset-vulnerabilities'   { $ScheduleVulnerabilities }
        'asset-datasync'          { $ScheduleDataSync }
        'asset-cmdb-sql'          { $ScheduleCmdbSql }
        'close-loop-mail'         { $ScheduleCloseLoopMail }
        'asset-tagging'           { $ScheduleAssetTagging }
        'asset-vulnerabilities-servicenow' { $ScheduleVulnerabilitiesServiceNow }
        'flow'                    { $ScheduleFlow }
        'config-backup'           { $ScheduleConfigBackup }
        'verification'            { $ScheduleVerification }
        'heartbeat'               { $ScheduleHeartbeat }
        default                  { if ($raJob) { $raJob.Cron } else { $ScheduleEndpoint } }
    }
    $parallelism = switch ($engine) {
        'identity'         { $ParallelismIdentity }
        'azure'            { $ParallelismAzure }
        'schema-discovery' { $ParallelismSchemaDiscovery }
        'risk-analysis'    { $ParallelismRiskAnalysis }
        # #685: the verification service is one run over the whole install (its results replace the previous run's) --
        # never sharded, whatever the endpoint parallelism is
        'verification'     { 1 }
        # #718: one status report per hour -- never sharded
        'heartbeat'        { 1 }
        default           { $ParallelismEndpoint }
    }
    # (Note: $isRiskAnalysis was computed at the top of the loop body so
    # $jobName resolution above could honour it. Behavioural notes:
    #   * uses a different entrypoint (Start-RiskAnalysisInContainer.ps1)
    #   * runs longer (more KQL round-trips) -- bigger replica timeout
    #   * needs more memory (Excel build can hold the whole dataset) -- 4GiB
    #   * does NOT support sharding (single replica; bucketing handles scale inside)
    #   * does NOT participate in KEDA queue scaling)

    # ---- 4a. (#209) The jobs' identity is ensured ONCE, above (3b) -- not one identity per engine. ----

    $existing = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $jobName -SubscriptionId $subId
    $verb = if ($existing) { 'update' } else { 'create' }
    # #269: a NEW job's trigger follows the orchestration mode (Get-SIBootstrapTriggerPlan); an EXISTING job keeps the
    # trigger it has -- a job the web app moved into the flow (Manual) is never put back on a timer by setup.
    $trigPlan = Get-SIBootstrapTriggerPlan -Engine $engine -Mode $orch.Mode -Cron $schedule -Map $flowMap
    $existingManual = ($existing -and [string]$existing.properties.configuration.triggerType -eq 'Manual')
    $triggerNote = if ($isManualOnly) { 'manual trigger only' }
                   elseif ($existingManual) { 'manual trigger kept (in the flow, or disabled)' }
                   elseif (-not $existing -and $trigPlan.Trigger -eq 'Manual') { $(if ($isFlow) { 'waits -- schedules mode' } else { 'in the flow' }) + (' (timer "{0}" remembered)' -f $schedule) }
                   else { 'cron: "' + $schedule + '"' }
    Write-Host ('[4/5] Ensuring Container App Job {0} ({1}) ...' -f $jobName, $triggerNote)

    $maxAi = if ($global:MaxAiSpendPerRun) { $global:MaxAiSpendPerRun } else { 4 }

    # Sign-in env + secrets come from $jobAuth (#209, below): SPN secret by default, managed identity or
    # certificate when asked for.
    $secretArgs = @()
    $jobEnv = Get-SIBootstrapJobEnvArgs -Engine $engine -SubscriptionId $subId -ResourceGroup $ResourceGroupName
    $envArgs = @(
        "SI_ENGINE=$($jobEnv.SiEngine)",
        "SI_SHARD_COUNT=$parallelism",
        "SI_STORAGE_ACCOUNT=$($global:SI_StorageAccount)",
        "SI_WORKSPACE_RESOURCEID=$($global:SI_WorkspaceResourceId)",
        "SI_DCE_NAME=$($global:SI_DceName)",
        "SI_DCR_RESOURCEGROUP=$($global:SI_DcrResourceGroup)",
        ('MAX_AI_SPEND_PER_RUN={0}' -f $maxAi)
    )
    # #269: what makes this job the job it is beyond SI_ENGINE (the vulnerability connector it drives; where the flow's jobs are)
    $envArgs += @($jobEnv.EnvArgs)
    # SCHED-1.1: every job can find its own executions -- a second execution while the first runs starts nothing
    $envArgs += @(Get-SIBootstrapJobGuardEnvArgs -SubscriptionId $subId -ResourceGroup $ResourceGroupName)
    # The config's settings, with this engine's own LauncherConfig.custom.ps1 winning name by name (as on a VM).
    $engFolder = Get-SIContainerEngineLauncherFolder -Engine $engine
    # Assign first: the helper returns its array with `return , $a`, and @( ) around that call wraps it -- an EMPTY list
    # (a Pro install keeps its settings in SQL) then became one '' element and `az` refused the job (2026-10-04, r1-pro-ca).
    $cfgMerged = Merge-SIConfigEnvArgs -Base $cfgEnvArgs -Override $(if ($engFolder -and $engineCfgArgs.ContainsKey($engFolder)) { @($engineCfgArgs[$engFolder]) } else { @() })
    $envArgs += @($cfgMerged | Where-Object { $_ })
    # #184: each optional part only when configured.
    # #215: the key as a Key Vault reference when a vault + identity are known, else the configured value, else no AI.
    # 2026-10-06: a Key Vault reference only when the vault HOLDS the secret (Resolve-SIJobKeyVaultSecret) -- an optional
    # secret that is not there is left out, and the job is still created.
    $openAiSecret = if ($haveOpenAiSettings) {
        $aiPlan = Resolve-SIJobKeyVaultSecret -Alias 'openai-apikey' -VaultName $OpenAIKeyVaultName -VaultUri $(if ($openAiVault) { [string]$openAiVault.properties.vaultUri }) `
            -SecretName $OpenAIApiKeySecretName -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) -Value ([string]$global:OpenAI_apiKey) `
            -VaultSecretNames $(if ($openAiVault) { Get-SIBootstrapVaultSecretNames -VaultName $OpenAIKeyVaultName }) -Feature 'Azure OpenAI (AI summaries)'
        Write-SIJobSecretNote -Plan $aiPlan -JobName $jobName
        $aiPlan.SecretArg
    }
    if ($openAiSecret) {
        $secretArgs += @($openAiSecret)
        $envArgs    += @('OPENAI_APIKEY=secretref:openai-apikey',
                         "OPENAI_ENDPOINT=$($global:OpenAI_endpoint)",
                         "OPENAI_DEPLOYMENT=$($global:OpenAI_deployment)",
                         "OPENAI_APIVERSION=$($global:OpenAI_apiVersion)")
    }
    # #185: the Shodan key (a paid entitlement) reaches the publicip job as a secret -- it never did before,
    # so a container publicip run published empty Shodan fields while reporting success.
    if ($engine -eq 'publicip') {
        # Preferred: a Key Vault REFERENCE resolved by the job's identity (live 2026-10-02: setup could not read the
        # value -- the config's Key Vault pull needs a platform context setup does not have -- so the job got none).
        # 2026-10-06: Shodan is an optional paid entitlement -- a new install's vault has no key, and a reference to it made
        # Container Apps refuse the whole job. Referenced only when the vault holds it; else the job runs without Shodan.
        $shodanPlan = Resolve-SIJobKeyVaultSecret -Alias 'shodan-key' -VaultName $ShodanKeyVaultName -VaultUri $(if ($shodanVault) { [string]$shodanVault.properties.vaultUri }) `
            -SecretName $ShodanSecretName -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) -Value $shodanForJobs `
            -VaultSecretNames $(if ($shodanVault) { Get-SIBootstrapVaultSecretNames -VaultName $ShodanKeyVaultName }) -Feature 'Shodan'
        Write-SIJobSecretNote -Plan $shodanPlan -JobName $jobName
        $shodanSecret = $shodanPlan.SecretArg
        if ($shodanSecret) {
            $secretArgs += @($shodanSecret)
            $envArgs    += @('SHODAN_API_KEY=secretref:shodan-key')
        }
    }
    # #218: the SMTP password reaches the Risk Analysis jobs as a secret when the config switches their mail on. Without
    # it the engine refuses to start ("SMTP PRE-FLIGHT FAILED") -- so say so here, at setup, not at 06:00 on day one.
    if ($isRiskAnalysis -and $raMail.NeedsPassword) {
        $smtpSecret = (Resolve-SIJobKeyVaultSecret -Alias 'smtp-password' -VaultName $SmtpKeyVaultName -VaultUri $(if ($smtpVault) { [string]$smtpVault.properties.vaultUri }) `
            -SecretName $SmtpPasswordSecretName -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) -Value ([string]$global:SMTPPassword) `
            -VaultSecretNames $(if ($smtpVault) { Get-SIBootstrapVaultSecretNames -VaultName $SmtpKeyVaultName }) -Feature 'the SMTP password').SecretArg
        if ($smtpSecret) {
            $secretArgs += @($smtpSecret)
            $envArgs    += @('SMTP_PASSWORD=secretref:smtp-password')
        } else {
            Write-Warning ("[mail] Risk Analysis mail is ON in the config, but no SMTP password reaches {0}: store it in Key Vault secret '{1}' (vault '{2}', -SmtpKeyVaultName) and re-run, or switch the mail off. Until then the run refuses to start." -f $engine, $SmtpPasswordSecretName, $SmtpKeyVaultName)
        }
    }
    # The close-loop daily mail job gets the SMTP password the same way when its relay is authenticated. Setup does not
    # read the Pro settings database, so the mail may be switched on there later: the password is wired whenever the relay
    # needs one, and the warning below is given only when the config itself switches the mail on.
    # Review B1 (2026-10-22): the data sync too -- it sends the Risk Analysis Detailed mail with its stored Protection Score
    # (engine\_shared\data-sql\SI-RaMailOutbox.ps1). An existing install gets it from the update (Invoke-SIJobSecretBorrow).
    if ($engine -in @('close-loop-mail', 'asset-datasync') -and ($clMail.NeedsPassword -or ($engine -eq 'asset-datasync' -and $raMail.NeedsPassword))) {
        $smtpSecret = (Resolve-SIJobKeyVaultSecret -Alias 'smtp-password' -VaultName $SmtpKeyVaultName -VaultUri $(if ($smtpVault) { [string]$smtpVault.properties.vaultUri }) `
            -SecretName $SmtpPasswordSecretName -IdentityResourceId $(if ($jobIdentity) { [string]$jobIdentity.id }) -Value ([string]$global:SMTPPassword) `
            -VaultSecretNames $(if ($smtpVault) { Get-SIBootstrapVaultSecretNames -VaultName $SmtpKeyVaultName }) -Feature 'the SMTP password').SecretArg
        if ($smtpSecret) {
            $secretArgs += @($smtpSecret)
            $envArgs    += @('SMTP_PASSWORD=secretref:smtp-password')
        } elseif ($clMail.Wanted) {
            Write-Warning ("[mail] the close-loop daily mail is ON in the config, but no SMTP password reaches {0}: store it in Key Vault secret '{1}' (vault '{2}', -SmtpKeyVaultName) and re-run, or switch the mail off. Until then the mail run fails." -f $engine, $SmtpPasswordSecretName, $SmtpKeyVaultName)
        }
    }
    # #170: the Pro licence reaches the Pro engines as a secret. Absent = they refuse with one line.
    # #236: asset tagging too -- it reads its rules from the Pro settings database, a licensed feature.
    # With the install's vault known, NO copy: the engine reads SI-License from the vault when the job starts (the
    # identity holds Key Vault Secrets User there -- the grant plan above), so the licence in force is always the current
    # one. Only an install without a vault still gets the configured licence as a job secret.
    if ($licensedEngines -contains $engine -and -not $licenceVault -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_License)) {
        $secretArgs += @(('si-license={0}' -f $global:SI_License))
        $envArgs    += @('SI_LICENSE=secretref:si-license')
    }

    if ($engineKeda -and -not $isRiskAnalysis -and -not $isAssetTagging -and -not $isManualOnly) {
        # Worker reads its shard descriptor from the queue (NOT from
        # CONTAINER_APP_JOB_REPLICA_INDEX which doesn't apply to event jobs).
        # RA never participates in KEDA so it skips this env var even when
        # -UseKEDA was passed for the collection engines.
        $envArgs += @('SI_TRIGGER_FROM_QUEUE=1')
    }

    # #209: how this job signs in -- Get-SIContainerJobAuthArgs (container\_shared\SI-ContainerConfig.ps1).
    # Secret: the single SPN secret (si-spn-secret) + SI_SPN_* env, exactly as before. Managed identity: no
    # secret at all, SI_UAMI_CLIENTID. Certificate: the PFX as a Key Vault reference (si-spn-cert).
    # #236: the asset-tagging job carries ITS OWN identity's sign-in ($engAuth), never the collection one.
    $secretArgs += @($engAuth.SecretArgs)
    $envArgs    += @($engAuth.EnvArgs)

    # SI_ROLE drives the entrypoint dispatcher in Start-SIInContainer.ps1.
    # 'ra' for risk-analysis, 'worker' for all collection-engine job-instances
    # (matches the default ENTRYPOINT path). Producer jobs get 'producer'
    # injected separately further below.
    $envArgs += @( if ($isRiskAnalysis) { 'SI_ROLE=ra' } else { 'SI_ROLE=worker' } )

    # Risk Analysis env vars: the RA entrypoint
    # (Start-RiskAnalysisInContainer.ps1) reads SI_RA_* to populate the
    # RA engine's $global:* surface. KEDA does not apply here -- RA is a
    # single-container report build by design.
    if ($isRiskAnalysis) {
        # Mode, template and schedule per job from the plan (Get-SIRiskAnalysisJobPlan): the Summary job, the Detailed job
        # with the customer's default Detailed template, and any extra report jobs. Log Analytics / AI summary only when
        # setup decided them ($null = the container honours the customer's setting, or the VM default).
        $raModeForJob     = if ($raJob) { $raJob.Mode }     elseif ($isRiskAnalysisDetailed) { 'Detailed' } else { $RiskAnalysisMode }
        $raTemplateForJob = if ($raJob) { $raJob.Template } elseif ($isRiskAnalysisDetailed) { 'RiskAnalysis_Detailed' } else { $RiskAnalysisReportTemplate }
        $envArgs += @(Get-SIRaJobEnvArgs -Template $raTemplateForJob -Mode $raModeForJob -SendToLogAnalytics $raSendToLaForJobs `
            -BuildSummaryByAI $raBuildAiForJobs -ExportDestination $RiskAnalysisExportDestination)
        # #742: the workers are ON by default (owner 2026-10-18; SI_Bootstrap_RaScaleOut = $false switches them off): with queue
        # scaling and the managed identity, the Detailed job is the PRODUCER of a queue-scaled worker job (4c below): it plans one
        # work item per report and the workers run them in parallel (container\_shared\SI-ContainerConfig.ps1)
        $raScale = Resolve-SIRaScaleOutChoice -Engine $engine -Keda ([bool]$UseKEDA) -IdentityResourceId ([string]$engAuth.IdentityResourceId) `
                       -StorageAccount ([string]$global:SI_StorageAccount) -Globals $bootGlobals
        if ($raScale.On) { $envArgs += @(Get-SIRaProducerScaleOutEnvArgs -Grain $raScale.Grain -Workers (Get-SIRaWorkerMaxExecutions -Globals $bootGlobals)) }
        # No else-warn: the post-load resolver auto-derives a default from
        # $global:SI_StorageAccount + sistaging container, and the container
        # entrypoint repeats the same derivation if env is unset, so the
        # destination is effectively never empty.
    }

    # Risk Analysis is always schedule-triggered + single-replica + bigger box.
    # Force-skip KEDA path for RA even if -UseKEDA was passed (RA doesn't shard).
    $effectiveUseKEDA = ($engineKeda -and -not $isRiskAnalysis -and -not $isAssetTagging -and -not $isManualOnly -and -not $isFlow)

    # Replica timeout, CPU and memory: SI_Bootstrap_ReplicaTimeout_<Engine> / _Cpu_<Engine> / _Memory_<Engine> when set,
    # else the sizes every earlier release used for this kind of job (Get-SIContainerJobResources).
    $jobKind = 'Schedule'
    if ($isManualOnly -eq $true)     { $jobKind = 'Manual' }
    if ($isRiskAnalysis -eq $true)   { $jobKind = 'RiskAnalysis' }
    if ($effectiveUseKEDA -eq $true) { $jobKind = 'Keda' }
    $jobRes  = Get-SIContainerJobResources -Engine $engine -Kind $jobKind -Globals $bootGlobals -TenantCounts $script:SITenantCounts
    foreach ($note in @($jobRes.Notes)) { Write-Warning ('[{0}] {1}' -f $jobName, $note) }
    # #269: the flow runner waits for every step inside its own execution, so it never ends before a step does: 7 days, the
    # longest a job's run limit can be set to (Get-SIFlowJobReplicaTimeout) -- unless SI_Bootstrap_ReplicaTimeout_Flow
    # says otherwise. Every update raises an existing install's pipeline job to it (setup/_shared/SI-JobSizing.ps1).
    if ($isFlow -and -not $bootGlobals.ContainsKey('SI_Bootstrap_ReplicaTimeout_Flow')) { $jobRes.ReplicaTimeout = Get-SIFlowJobReplicaTimeout }
    # Running setup again on a job that EXISTS never lowers it: the larger of this and what the job has now is written (an
    # update may have raised its size after an out-of-memory run; the run limit is the longest Azure takes either way). A value the customer set still wins, also downwards.
    if ($existing) {
        $kept = @($jobRes.Notes).Count
        $jobRes = Get-SIJobResourcesNeverLower -Resources $jobRes -ExistingJob $existing -Engine $engine -Globals $bootGlobals
        foreach ($note in @(@($jobRes.Notes) | Select-Object -Skip $kept)) { Write-Host ('       [{0}] {1}' -f $jobName, $note) }
    }
    # A KEDA worker's shard lease must outlive its replica, or a second worker takes a shard still being processed.
    if ($effectiveUseKEDA) { $envArgs += @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout $jobRes.ReplicaTimeout) }

    # In KEDA mode the worker job is event-triggered with a queue scaler.
    # --replica-completion-count 1: each replica is one work-item.
    # --parallelism is the per-execution cap; KEDA polls and starts one
    # execution per <queueLength> messages above 0.
    $createArgs = if ($effectiveUseKEDA) {
        # #519: one definition of the worker (container\_shared\SI-ContainerConfig.ps1) -- the update that moves an existing
        # install to queue scaling creates the same job
        @(Get-SIKedaWorkerCreateArgs -Name $jobName -ResourceGroup $ResourceGroupName -Environment $EnvName -Image $image `
            -LoginServer $acr.loginServer -ReplicaTimeout $jobRes.ReplicaTimeout -Cpu $jobRes.Cpu -Memory $jobRes.Memory -MaxExecutions $KedaMaxReplicas `
            -Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId))
    } elseif ($isRiskAnalysis) {
        # RA: bigger box, longer timeout, custom entrypoint that wraps
        # SCRIPTS/SecurityInsight_RiskAnalysis.ps1 instead of the collection
        # orchestrator. Single replica -- bucketing scales inside.
        # Retry limit 0 (2026-10-16): a failed Risk Analysis run is never restarted by Azure as a whole new run -- the
        # pipeline decides (every update sets the same on an existing job: Invoke-SIEngineJobRetryLimit).
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Schedule',
            '--replica-timeout',"$($jobRes.ReplicaTimeout)",
            '--replica-retry-limit','0',
            '--replica-completion-count','1',
            '--parallelism','1',
            '--cron-expression',$schedule,
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--cpu',$jobRes.Cpu,
            '--memory',$jobRes.Memory,
            '--output','none'
        )
    } elseif ($isManualOnly) {
        # #235: caj-si-templates runs only when the web app starts it (Review & commit of a template release); no cron.
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Manual',
            '--replica-timeout',"$($jobRes.ReplicaTimeout)",
            '--replica-retry-limit','0',
            '--replica-completion-count','1',
            '--parallelism','1',
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--cpu',$jobRes.Cpu,
            '--memory',$jobRes.Memory,
            '--output','none'
        )
    } else {
        # Retry limit 0 for every engine job (2026-10-23, Get-SIJobRetryLimitArg): the pipeline decides what runs again,
        # never Azure inside the same execution. The runner (caj-si-flow) and the jobs that are no step keep 1.
        @(
            'containerapp','job','create',
            '--name',$jobName,
            '--resource-group',$ResourceGroupName,
            '--environment',$EnvName,
            '--trigger-type','Schedule',
            '--replica-timeout',"$($jobRes.ReplicaTimeout)",
            '--replica-retry-limit',(Get-SIJobRetryLimitArg -Name $jobName),
            '--replica-completion-count',"$parallelism",
            '--parallelism',"$parallelism",
            '--cron-expression',$schedule,
            '--image',$image,
            '--registry-server',$acr.loginServer,
            '--cpu',$jobRes.Cpu,
            '--memory',$jobRes.Memory,
            '--output','none'
        )
    }
    # #269: a new job of the flow (flow mode) -- or caj-si-flow itself in schedules mode -- is created Manual with its
    # timer remembered, exactly as "Disable" leaves a job, so leaving the flow restores the timer.
    if (-not $effectiveUseKEDA -and -not $isManualOnly -and $trigPlan.Trigger -eq 'Manual') {
        $createArgs = ConvertTo-SIManualCreateArgs -CreateArgs $createArgs -RememberCron $trigPlan.RememberCron
    }
    $createArgs += @('--tags', $siBuildTag) + $siSizeTags
    $createArgs += $engRegistry
    if ($engAuth.IdentityResourceId) {
        $createArgs += @('--mi-user-assigned',$engAuth.IdentityResourceId)
    }
    # #209: a managed-identity job may carry no secret at all -- then there is no --secrets to pass.
    if ($secretArgs.Count -gt 0) { $createArgs += @('--secrets'); $createArgs += $secretArgs }
    $createArgs += @('--env-vars'); $createArgs += $envArgs

    # The job is written over ARM (setup\_shared\SI-SetupArm.ps1), never through az:
    #   CREATE = the whole Microsoft.App/jobs resource from these create arguments (ConvertFrom-SIJobCreateArgs, the same
    #            translation the update uses), identity and registry in the body -- one PUT.
    #   UPDATE = READ-MODIFY-WRITE: the job read whole with its secret values (listSecrets), then image, timer (not for a
    #            manual-only job, and a job the flow made Manual keeps no timer), size, si-build tag, the queue scale rule,
    #            the environment REPLACED, the secrets set and the retired ones dropped, the identity added and -- for a
    #            managed-identity job -- the registry pulled as it; written back in ONE PUT. The container's command / args
    #            / probes stay exactly as they are (an empty command would make Container Apps exec an empty binary).
    $removeSecrets = New-Object System.Collections.Generic.List[string]
    if ($verb -eq 'update') {
        # #209: a job moved OFF the client secret drops the old si-spn-secret -- the credential this mode exists to retire.
        if ($engAuthMode -ne 'Secret') {
            $haveJobSecrets = @($existing.properties.configuration.secrets | Where-Object { $_ } | ForEach-Object { [string]$_.name })
            if ($haveJobSecrets -contains 'si-spn-secret') { $removeSecrets.Add('si-spn-secret'); Write-Host '       removing the client secret (si-spn-secret) from the job' }
        }
        # A secret an older setup gave the job that nothing uses any more (the environment is replaced in the same write).
        foreach ($old in @(Get-SIRetiredJobSecretNames -Job $existing)) { if (-not $removeSecrets.Contains([string]$old)) { $removeSecrets.Add([string]$old) } }
        # An optional secret (Shodan / Azure OpenAI / SMTP) this run did not wire -- a dangling Key Vault reference would make
        # every later change to the job fail (2026-10-06).
        foreach ($old in @(Get-SIUnwiredOptionalJobSecretNames -Job $existing -SecretArgs $secretArgs)) {
            if (-not $removeSecrets.Contains([string]$old)) { $removeSecrets.Add([string]$old); Write-Host ('       removing the unused optional secret {0} from the job' -f $old) }
        }
    }

    try {
        if ($verb -eq 'create') {
            $null = New-SIContainerAppJobFromArgs -CreateArgs $createArgs -Location $Location -EnvironmentId ([string]$cae.id) -SubscriptionId $subId
        } else {
            $upd = @{ ResourceGroupName = $ResourceGroupName; Name = $jobName; SubscriptionId = $subId; Job = $existing
                      Image = $image; ReplicaTimeout = [int]$jobRes.ReplicaTimeout; Cpu = [string]$jobRes.Cpu; Memory = [string]$jobRes.Memory
                      Tags = @($siBuildTag) + $siSizeTags; Env = @($envArgs); SetSecrets = @($secretArgs); RemoveSecrets = $removeSecrets.ToArray() }
            # a manual-only job has no schedule to set (and must never get one)
            # #269: and a job the flow runs (Manual) keeps no timer -- its remembered one is the web app's to restore
            if (-not $isManualOnly -and -not $existingManual) { $upd['Cron'] = $schedule }
            # A KEDA worker gets the same queue scale rule on every run of setup -- an older worker, whose scaler had no
            # sign-in, now signs in as the jobs' managed identity.
            if ($effectiveUseKEDA) {
                $upd['ScaleRule'] = ConvertFrom-SIScaleRuleArgs -ScaleArgs @(Get-SIKedaQueueScaleArgs -Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId))
            }
            # #209: the identity is on the job in the same write as a Key Vault-referenced secret it resolves
            if ($engAuth.IdentityResourceId) { $upd['AddIdentity'] = [string]$engAuth.IdentityResourceId }
            # A job moved to the managed identity also PULLS as it (the registry's admin password may be disabled).
            if ($engAuthMode -eq 'ManagedIdentity' -and $engAuth.IdentityResourceId) { $upd['RegistryServer'] = [string]$acr.loginServer; $upd['RegistryIdentity'] = [string]$engAuth.IdentityResourceId }
            $null = Update-SIContainerAppJob @upd
        }
    } catch {
        # the environment and secret VALUES are never in the message (customer A 2026-10-08: the settings dump made a failed step unreadable)
        throw ('{0} of Container Apps job {1} failed: {2}' -f $(if ($verb -eq 'create') { 'Creating' } else { 'Updating' }), $jobName, $_.Exception.Message)
    }
    Write-Host ('       {0}d.' -f $verb)

    if ($TriggerNowAfter) {
        Write-Host ('       triggering manual run ...')
        $null = Start-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $jobName -SubscriptionId $subId
        Write-Host ('       triggered. Follow it in the Azure portal (job {0} > Execution history) or in the SI workspace (ContainerAppConsoleLogs_CL).' -f $jobName)
    }

    # ---- 4c. (#742) The Risk Analysis WORKER job: event-triggered on the grain's work queue (the KEDA queue scaler, signed
    # in as the jobs' managed identity), the producer's image, sign-in, settings and size; up to SI_Bootstrap_RaMaxWorkers
    # at once (default 4). ON BY DEFAULT where it can run (owner 2026-10-18: "pls dont turn off things that improve time"):
    # queue scaling on and the managed identity. Where it cannot run (queue scaling off, no identity, no storage account)
    # nothing changes and one line says why. SI_Bootstrap_RaScaleOut = $false (the customer's choice) = no worker job: one
    # that exists from before is removed (only a job SI's setup made), and the Risk Analysis job runs its reports itself.
    if ($isRiskAnalysis -and $raScale -and $raScale.Grain) {
        $raWorkerName = Get-SIRaWorkerJobName -Grain $raScale.Grain
        if ($raScale.On) {
            $raWorkerQueue = Get-SIRaScaleOutQueueName -Grain $raScale.Grain
            $raWorkerMax = Get-SIRaWorkerMaxExecutions -Globals $bootGlobals
            Write-Host ('       Ensuring Risk Analysis worker job {0} (queue {1}, up to {2} at once) ...' -f $raWorkerName, $raWorkerQueue, $raWorkerMax)
            $raWorkerEnv = @(Get-SIRaWorkerEnvArgs -EnvArgs $envArgs -ReplicaTimeout ([int]$jobRes.ReplicaTimeout) -Workers $raWorkerMax)
            $raWorkerExisting = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $raWorkerName -SubscriptionId $subId
            $raWorkerArgs = @(Get-SIKedaWorkerCreateArgs -Name $raWorkerName -ResourceGroup $ResourceGroupName -Environment $EnvName -Image $image `
                -LoginServer $acr.loginServer -ReplicaTimeout $jobRes.ReplicaTimeout -Cpu $jobRes.Cpu -Memory $jobRes.Memory -MaxExecutions $raWorkerMax `
                -Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId) -QueueName $raWorkerQueue)
            $raWorkerArgs += @('--tags', $siBuildTag) + $siSizeTags
            $raWorkerArgs += $engRegistry
            $raWorkerArgs += @('--mi-user-assigned', [string]$engAuth.IdentityResourceId)
            if ($secretArgs.Count -gt 0) { $raWorkerArgs += @('--secrets'); $raWorkerArgs += $secretArgs }
            $raWorkerArgs += @('--env-vars'); $raWorkerArgs += $raWorkerEnv
            try {
                if (-not $raWorkerExisting) {
                    $null = New-SIContainerAppJobFromArgs -CreateArgs $raWorkerArgs -Location $Location -EnvironmentId ([string]$cae.id) -SubscriptionId $subId
                } else {
                    $wupd = @{ ResourceGroupName = $ResourceGroupName; Name = $raWorkerName; SubscriptionId = $subId; Job = $raWorkerExisting
                               Image = $image; ReplicaTimeout = [int]$jobRes.ReplicaTimeout; Cpu = [string]$jobRes.Cpu; Memory = [string]$jobRes.Memory
                               Tags = @($siBuildTag) + $siSizeTags; Env = @($raWorkerEnv); SetSecrets = @($secretArgs)
                               RemoveSecrets = @(Get-SIRetiredJobSecretNames -Job $raWorkerExisting | ForEach-Object { [string]$_ })
                               ScaleRule = (ConvertFrom-SIScaleRuleArgs -ScaleArgs @(Get-SIKedaQueueScaleArgs -Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId) -QueueName $raWorkerQueue))
                               AddIdentity = [string]$engAuth.IdentityResourceId }
                    if ($engAuthMode -eq 'ManagedIdentity') { $wupd['RegistryServer'] = [string]$acr.loginServer; $wupd['RegistryIdentity'] = [string]$engAuth.IdentityResourceId }
                    $null = Update-SIContainerAppJob @wupd
                }
            } catch {
                throw ('{0} of Container Apps job {1} failed: {2}' -f $(if ($raWorkerExisting) { 'Updating' } else { 'Creating' }), $raWorkerName, $_.Exception.Message)
            }
            Write-Host ('       {0} worker.' -f $(if ($raWorkerExisting) { 'updated' } else { 'created' }))
        } else {
            Write-Host ('       {0}: {1}' -f $raWorkerName, $raScale.Reason)
            # only the customer's own off removes a worker; where the workers cannot run, nothing is changed
            if ($raScale.SwitchedOff) { Remove-SIBootstrapReplacedJob -Name $raWorkerName }
        }
    }

    # ---- 4b. Producer job (KEDA mode only; never for Risk Analysis) ----
    # Cron-triggered, single replica, runs Invoke-ShardProducer.ps1 instead
    # of the default entrypoint. Pushes N shard messages onto the queue;
    # KEDA then scales the worker job to drain.
    if ($effectiveUseKEDA) {
        Write-Host ('       Ensuring producer job {0} (cron: "{1}") ...' -f $producerName, $schedule)

        # #475: the producer DISCOVERS once into parts (SI_PRODUCER_DISCOVERS=1), writes the manifest and one message per
        # part, and hands discovery's records over -- it runs the engine, so it carries the worker's whole environment and
        # secrets (configuration, sign-in, licence, guard), without the worker's queue-only settings, as role 'producer'.
        # #519: the producer's environment and job are defined once (container\_shared\SI-ContainerConfig.ps1)
        $producerEnvArgs = @(Get-SIKedaProducerEnvArgs -EnvArgs $envArgs -Parallelism $parallelism)
        $producerSecretArgs = @($secretArgs)

        $producerExisting = Get-SIContainerAppJob -ResourceGroupName $ResourceGroupName -Name $producerName -SubscriptionId $subId
        $producerVerb = if ($producerExisting) { 'update' } else { 'create' }

        $producerCreateArgs = @(Get-SIKedaProducerCreateArgs -Name $producerName -ResourceGroup $ResourceGroupName -Environment $EnvName `
            -Cron $schedule -Image $image -LoginServer $acr.loginServer -Cpu ([string]$jobRes.Cpu) -Memory ([string]$jobRes.Memory) -ReplicaTimeout ([int]$jobRes.ReplicaTimeout))
        $producerCreateArgs += @('--tags', $siBuildTag) + $siSizeTags
        $producerCreateArgs += $registryAuthArgs
        if ($jobAuth.IdentityResourceId) { $producerCreateArgs += @('--mi-user-assigned',$jobAuth.IdentityResourceId) }
        if ($producerSecretArgs.Count -gt 0) { $producerCreateArgs += @('--secrets'); $producerCreateArgs += $producerSecretArgs }
        $producerCreateArgs += @('--env-vars'); $producerCreateArgs += $producerEnvArgs

        try {
            if ($producerVerb -eq 'create') {
                $null = New-SIContainerAppJobFromArgs -CreateArgs $producerCreateArgs -Location $Location -EnvironmentId ([string]$cae.id) -SubscriptionId $subId
            } else {
                # the producer update mirrors the worker's: READ-MODIFY-WRITE, the command / args kept as they are
                $pupd = @{ ResourceGroupName = $ResourceGroupName; Name = $producerName; SubscriptionId = $subId; Job = $producerExisting
                           Image = $image; Cron = $schedule; Env = @($producerEnvArgs); Tags = @($siBuildTag) + $siSizeTags
                           RemoveSecrets = @(Get-SIRetiredJobSecretNames -Job $producerExisting | ForEach-Object { [string]$_ }) }
                if ($jobAuth.IdentityResourceId) { $pupd['AddIdentity'] = [string]$jobAuth.IdentityResourceId }
                # #209: a producer moving to the certificate needs its Key Vault reference set (secret mode keeps the
                # update exactly as it was).
                if ($authMode -ne 'Secret' -and $producerSecretArgs.Count -gt 0) { $pupd['SetSecrets'] = @($producerSecretArgs) }
                $null = Update-SIContainerAppJob @pupd
            }
        } catch {
            throw ('{0} of Container Apps job {1} failed: {2}' -f $(if ($producerVerb -eq 'create') { 'Creating' } else { 'Updating' }), $producerName, $_.Exception.Message)
        }
        Write-Host ('       {0}d producer.' -f $producerVerb)
    }
    # #475: the layout this run chose replaces the engine's other layout -- its scheduled job when producer + worker now
    # exist, or its producer + worker when queue scaling is off: removed (only jobs SI's setup created), so the two never
    # run side by side. A re-run finds nothing left to remove.
    foreach ($replaced in @(Get-SIBootstrapReplacedJobs -Engine $engine -Keda ([bool]$effectiveUseKEDA))) {
        Remove-SIBootstrapReplacedJob -Name $replaced
    }
}

# THE PIPELINE RUNNER ON ITS SCHEDULE (one install's caj-si-flow was left Manual and never ran): an install that runs as the
# pipeline gets caj-si-flow on its wake-up timer here too -- the same step the update runs (Invoke-SIFlowRunnerSchedule,
# engine\_shared\SI-JobFlow.ps1): only a runner WITHOUT its timer, only to its schedule, one read-modify-write, read back. A
# runner on its timer, or an install whose jobs run on their own timers, is left exactly as it is. Never fails setup.
if ($orch.Mode -eq 'flow' -and @($Engines) -contains 'flow') {
    try {
        $frRest = {
            param([string]$Method, [string]$Uri, $Body, $Resource, $Headers)
            try {
                $a = @{ Method = $Method; Uri = $Uri; MaxAttempts = 3; What = 'the pipeline runner' }
                if ($null -ne $Body) { $a.Body = $Body }
                $r = Invoke-SIAzRestRequest @a
                [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$r.Content }
            } catch { [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
        }
        $frJobs = @(Get-SIContainerAppJobList -ResourceGroupName $ResourceGroupName -SubscriptionId $subId | Where-Object { $_ })
        $fr = Invoke-SIFlowRunnerSchedule -Rest $frRest -SubscriptionId $subId -ResourceGroup $ResourceGroupName -Jobs $frJobs -Map $flowMap
        if ($fr.State -eq 'failed') { Write-Warning ($fr.Line -replace 'the update goes on; the next update tries again', 'setup goes on; the next update puts it on its schedule') }
        elseif ($fr.State -eq 'patched') { Write-Host ('       {0}' -f $fr.Line) }
    } catch { Write-Warning ('the pipeline runner''s schedule was not checked ({0}) -- setup goes on; the next update checks it.' -f $_.Exception.Message) }
}

# SECURITY BASELINE, new installs only while SI_SECURITY_BASELINE_NEW_INSTALL is on (setup\_shared\SI-SecurityBaseline.ps1,
# default OFF until a fresh test install proves it): the registry's admin user -- a password that can replace the image
# every job runs -- is turned off when every job and app pulls as its managed identity, and read back. A job that still
# pulls with the password keeps it on, named. Never fails setup. An existing install gets it from setup\Set-SISecurityBaseline.ps1.
. (Join-Path $PSScriptRoot 'setup\_shared\SI-SecurityBaseline.ps1')
if ((Test-SISecurityBaselineNewInstall) -and $acr -and [string]$acr.id) {
    try {
        $blArm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } }
        $blRg = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App' -f $subId, $ResourceGroupName
        $blPull = @(Get-SIBaselineArmList -Arm $blArm -Path ('{0}/jobs?api-version={1}' -f $blRg, $script:SIBaselineAppApi)) + @(Get-SIBaselineArmList -Arm $blArm -Path ('{0}/containerApps?api-version={1}' -f $blRg, $script:SIBaselineAppApi))
        $blReg = & $blArm 'GET' ('{0}?api-version={1}' -f [string]$acr.id, $script:SIBaselineAcrApi) $null
        $blDecision = Get-SIRegistryAdminDecision -Registry $blReg -Apps $blPull
        if ($blDecision.Action -eq 'off') { Write-Host ('       registry password: {0}' -f (Set-SIRegistryAdmin -Arm $blArm -RegistryId ([string]$acr.id) -Enabled $false).Line) }
        else { Write-Host ('       registry password: {0}' -f $blDecision.Reason) }
    } catch { Write-Warning ('the registry''s admin user was not turned off ({0}) -- setup goes on; setup\Set-SISecurityBaseline.ps1 turns it off later.' -f $_.Exception.Message) }
}

Write-Host ''
Write-Host '[5/5] Done.'
Write-Host ''

# Save where the containers live (#166). The update hook that runs after every sync
# (setup\Invoke-SIContainerUpdate.ps1) finds the container hosting ONLY through these values in the
# config; without them it reports "no container hosting" and the jobs never move to a new version.
. (Join-Path $PSScriptRoot 'setup\_shared\SI-ContainerUpdate.ps1')
$siConfig = if ($ConfigPath) { $customFile } else { Join-Path $PSScriptRoot 'config\SecurityInsight.custom.ps1' }
if (Test-Path -LiteralPath $siConfig) {
    $saved = Save-SIContainerHostingConfig -ConfigPath $siConfig -SubscriptionId $subId -ResourceGroupName $ResourceGroupName `
        -AcrName $AcrName -EnvName $EnvName -Location $Location
    Write-Host ('Container hosting saved in config\SecurityInsight.custom.ps1 ({0}) -- updates will find it.' -f $(if ($saved.Changed) { 'written' } else { 'unchanged' }))
} else {
    Write-Host 'No config\SecurityInsight.custom.ps1 yet. Add these lines to it so updates can find the containers:' -ForegroundColor Yellow
    Write-Host (Get-SIContainerHostingBlock -SubscriptionId $subId -ResourceGroupName $ResourceGroupName -AcrName $AcrName -EnvName $EnvName -Location $Location)
}
# Both editions run these containers; say how THIS install gets new releases (PIM's deploy says the same).
$updaterJob = if (Test-Path -LiteralPath $siConfig) { Get-SIContainerHostingValue -Text ([IO.File]::ReadAllText($siConfig)) -Name 'SI_Bootstrap_UpdaterJob' } else { '' }
Write-Host ''
Get-SIContainerUpdateGuidance -UpdaterJob $updaterJob | ForEach-Object { Write-Host $_ }
# #250: Pro -- the default templates, installed as template pack 1.0 (the schema, names and CMDB ownership as
# configuration, the pack staged and recorded). Best effort here: the next update run does the same.
if (-not $SkipTemplateInstall -and @($Engines) -contains 'templates-publish' -and [string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    Write-Host ''
    Write-Host '[Pro] Installing the default templates (template pack 1.0) in the Pro database ...'
    try {
        $tplRes = & (Join-Path $PSScriptRoot 'setup\Publish-SITemplates.ps1') -InstallDefault -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
        Write-Host ('[Pro] Default templates: {0}' -f $(if ($tplRes) { $tplRes.Reason } else { 'done' }))
    } catch {
        Write-Warning ('[Pro] The default templates were not installed from here: {0} -- the next update run installs them, or run .\setup\Publish-SITemplates.ps1 -InstallDefault as an identity that may change the Pro database.' -f $_.Exception.Message)
    }
}
# #308: Pro -- the install's update ring, recorded in the Pro database so the web app shows it before any updater run.
# SI_UpdateRing (setting / config) wins; else the ring in the resource-group name (never over a ring already recorded).
# The guided install records it in its own step, as the person installing (it passes -SkipTemplateInstall).
if (-not $SkipTemplateInstall -and [string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'setup\Set-SIInstallRing.ps1'))) {
    try {
        $ringRes = & (Join-Path $PSScriptRoot 'setup\Set-SIInstallRing.ps1') -ResourceGroupName $ResourceGroupName -SetBy 'bootstrap' -PassThru | Select-Object -Last 1
        if ($ringRes -and $null -eq $ringRes.Ring) { Write-Host '[Pro] Update ring: not known here -- set SI_UpdateRing (0-3) on the Settings page, or run .\setup\Set-SIInstallRing.ps1 -Ring <0-3>.' -ForegroundColor Yellow }
    } catch {
        Write-Warning ('[Pro] The update ring was not recorded from here: {0} -- run .\setup\Set-SIInstallRing.ps1 -Ring <0-3> as an identity that may change the Pro database.' -f $_.Exception.Message)
    }
}
# Pro -- the tenant's own name (Entra organization, read through Microsoft Graph as setup's sign-in), recorded in
# the Pro database so the web app's header shows TENANT by name. Never typed by hand; never fails the bootstrap.
if (-not $SkipTemplateInstall -and [string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase -and (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'setup\Set-SIInstallTenant.ps1'))) {
    try {
        $tenantRes = & (Join-Path $PSScriptRoot 'setup\Set-SIInstallTenant.ps1') -SetBy 'bootstrap' -PassThru | Select-Object -Last 1
        if ($tenantRes -and -not $tenantRes.Written) { Write-Host ('[Pro] Tenant name: {0}' -f $tenantRes.Reason) -ForegroundColor Yellow }
    } catch {
        Write-Warning ('[Pro] The tenant name was not recorded from here: {0} -- run .\setup\Set-SIInstallTenant.ps1 as an identity that may change the Pro database.' -f $_.Exception.Message)
    }
}
Write-Host ''
Write-Host ('Start any job now: Operations > Jobs in the web app (Pro), or the Azure portal: resource group {0} > caj-si-<engine> > Run now.' -f $ResourceGroupName)
Write-Host 'Its log: the job''s Execution history in the portal, or ContainerAppConsoleLogs_CL in the SI workspace.'
