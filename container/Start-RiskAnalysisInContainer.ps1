#Requires -Version 7.0
<#
    Container entrypoint for the SecurityInsight v2.2 Risk Analysis report
    builder.

    Wraps SCRIPTS/SecurityInsight_RiskAnalysis.ps1 the same way
    Start-SIInContainer.ps1 wraps the collection orchestrator: read env vars
    that the Container App Job sets via secrets, populate the matching
    $global:* names the script reads, then dispatch.

    Cloud-native I/O: the script writes its XLSX + JSON to the container's
    ephemeral filesystem, then Phase 3 (built into the engine) uploads both
    to the Azure Storage container at $global:ExportDestination.

    Required env vars:
      SI_SPN_APPID / SECRET / TENANTID         -- SPN for Graph + LA reads
      SI_WORKSPACE_RESOURCEID                  -- target Log Analytics workspace
      SI_RA_EXPORT_DESTINATION                 -- https://<acct>.blob.core.windows.net/<container>/[<prefix>/]
                                                  (engine appends backup-then-overwrite logic)

    Optional env vars. Each one wins ONLY when present; absent, the customer's setting (SI_CFG_*) applies, and
    absent both, the VM launcher's default (launcher/risk-analysis/LauncherConfig.defaults.ps1, loaded first):
      SI_RA_REPORT_TEMPLATE                    -- default 'RiskAnalysis_<mode>'
                                                  ('RiskAnalysis_Summary' or 'RiskAnalysis_Detailed')
      SI_RA_MODE                               -- 'Summary' | 'Detailed'; must agree with the template
                                                  (a Summary/Detailed template decides the mode)
      SI_RA_BUILD_SUMMARY_BY_AI                -- '0'/'1' (VM default off)
      SI_RA_SEND_TO_LOG_ANALYTICS              -- '0'/'1' (VM default ON; routes Summary -> SI_RiskAnalysis_Summary_CL,
                                                  Detailed -> SI_RiskAnalysis_Detailed_CL via DCR)
      SI_RA_SEND_MAIL / SI_RA_TABLE_SUMMARY / SI_RA_TABLE_DETAILED / SI_RA_AUTO_BUCKET / SI_RA_AUTO_BUCKET_MAX /
      SI_RA_AUTO_BUCKET_CACHE                  -- the same rule (VM defaults: mail off, SI_RiskAnalysis_Summary /
                                                  _Detailed, bucketing on, cap 131072, cache on)
      SI_RA_SETTINGS_PATH                      -- default '/app/engine/risk-analysis' (the v2.2 catalog)
      OPENAI_APIKEY / ENDPOINT / DEPLOYMENT / APIVERSION
                                               -- only required when SI_RA_BUILD_SUMMARY_BY_AI=1

    NOT required (RA reads these from env if present, else falls back):
      SMTP_PASSWORD                            -- the SMTP password, as a Key Vault-referenced secret, set by
                                                  Bootstrap only when the config switches Risk Analysis mail ON
                                                  (the server / port / user / from-address travel with the settings)
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }

$ErrorActionPreference = 'Stop'

# ---- #55.1: run transcripts on the container host (see Start-SIInContainer.ps1) ----
. /app/launcher/_lib/Start-LauncherTranscript.ps1
. /app/launcher/_lib/Publish-LauncherTranscript.ps1

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

# ---- Auth (#209): managed identity > certificate (PFX from Key Vault) > client secret ----
# Same decision as Start-SIInContainer.ps1. The secret path is unchanged (the Community default).
. /app/container/_shared/SI-ContainerConfig.ps1
. /app/container/_shared/SI-ContainerRunState.ps1
. /app/auth/SI-ManagedIdentity.ps1

# The VM launcher's own defaults for Risk Analysis (launcher/risk-analysis/LauncherConfig.defaults.ps1) FIRST -- the
# customer's settings below override them, exactly as on a VM. Without them a container ran on the entry point's own
# fallbacks (no Log Analytics, a 1024 bucket cap) instead of the defaults every VM run has.
$raDefaults = Get-SIContainerEngineDefaultsPath -Engine 'risk-analysis' -Root '/app'
if ($raDefaults) { . $raDefaults }

# #170/#187: the customer's NON-SECRET settings that Bootstrap passed as SI_CFG_<name> -- applied FIRST, exactly as
# Start-SIInContainer.ps1 does, so every credential and target this script hydrates from its own env vars below
# still wins. Live 2026-10-02: this entry point never imported them, so Risk Analysis in a container ignored the
# customer's config (it posted run health to the default rule instead of the configured one, and could never see
# the Pro database settings).
$cfgImport = Import-SIConfigFromEnv
if (@($cfgImport.Applied).Count) { Write-Host ('[config] {0} setting(s) from the customer config: {1}' -f @($cfgImport.Applied).Count, (@($cfgImport.Applied) -join ', ')) }
if (@($cfgImport.Refused).Count) { Write-Warning ('[config] refused (secret-looking or container-owned, never passed this way): {0}' -f (@($cfgImport.Refused) -join ', ')) }

$siAuth = Resolve-SIContainerAuthMode
$siCertPfxPath = $null
switch ($siAuth.Mode) {
    'ManagedIdentity' {
        $global:SI_UseManagedIdentity = $true
        $global:SI_UAMI_ClientId      = $siAuth.ClientId
        $global:SI_PreferUami         = $true
        # RA calls the identity "SpnClientId" -- it is passed as -AzAppId and looked up for the DCR grants.
        $global:SpnClientId     = $siAuth.ClientId
        $global:SpnTenantId     = Get-OptionalEnv 'SI_SPN_TENANTID' $null
        $global:SI_SPN_AppId    = $siAuth.ClientId
        $global:SI_SPN_TenantId = $global:SpnTenantId
    }
    'Certificate' {
        $global:SpnTenantId = Get-RequiredEnv 'SI_SPN_TENANTID'
        $global:SpnClientId = Get-RequiredEnv 'SI_SPN_APPID'
        $siCert = Import-SIContainerCertificate -PfxBase64 (Get-RequiredEnv 'SI_SPN_CERT_PFX_B64') -Password (Get-OptionalEnv 'SI_SPN_CERT_PASSWORD' '')
        $global:SpnCertificateThumbprint = $siCert.Thumbprint
        $global:SI_SPN_CertThumbprint    = $siCert.Thumbprint
        $global:SI_SPN_CertStoreLocation = 'CurrentUser'
        $siCertPfxPath = $siCert.PfxPath
    }
    'Secret' {
        $global:SpnTenantId     = Get-RequiredEnv 'SI_SPN_TENANTID'
        $global:SpnClientId     = Get-RequiredEnv 'SI_SPN_APPID'
        $global:SpnClientSecret = Get-RequiredEnv 'SI_SPN_SECRET'
    }
    default { throw ('[auth] cannot sign in: {0}' -f $siAuth.Reason) }
}
Write-Host ('[auth] signing in as {0}' -f $siAuth.Reason)

# Aliases the RA script reads in some code paths.
$global:AzureTenantId = $global:SpnTenantId

# Workspace: the engine ingests Summary/Detailed rows into this LA workspace
# when SI_RA_SEND_TO_LOG_ANALYTICS=1. RG/DCE/DCR resolve from the workspace
# resource id + the canonical SecurityInsight layout.
$global:SI_WorkspaceResourceId = Get-RequiredEnv 'SI_WORKSPACE_RESOURCEID'
$global:WorkspaceName          = ($global:SI_WorkspaceResourceId -split '/')[-1]
$global:WorkspaceResourceGroup = ($global:SI_WorkspaceResourceId -split '/')[4]
# The install's storage account: the customisation files and the bucket cache are kept there between runs.
$raStorageAccount = Get-OptionalEnv 'SI_STORAGE_ACCOUNT' $null
# ...and the engine reads it as $global:SI_StorageAccount: the executive view the web app shows, the shared Risk Score KPI
# and the AI summary cache the other report reuses are all mirrored to that account. Without it every one of them stayed
# "local file only" in a container that is gone when the run ends (found live 2026-10-05: an empty management summary).
if ($raStorageAccount -and -not $global:SI_StorageAccount) { $global:SI_StorageAccount = $raStorageAccount }

# DCE/DCR for the Phase 2 LA ingest (only used when SI_RA_SEND_TO_LOG_ANALYTICS=1).
$global:DceName                                = Get-OptionalEnv 'SI_DCE_NAME'             $null
$global:DcrResourceGroup                       = Get-OptionalEnv 'SI_DCR_RESOURCEGROUP'    $null
# The job's own Risk Analysis env vars (table names, Log Analytics, mail, AI summary, bucketing) win ONLY when present:
# an absent one leaves the customer's setting -- or the VM default loaded above -- in force. They used to be applied
# with fallbacks of their own, which overwrote the customer's config on every run (Log Analytics off, bucket cap 1024).
$raEnv = Get-SIContainerRaEnvOverrides
foreach ($k in $raEnv.Keys) { Set-Variable -Name $k -Scope Global -Value $raEnv[$k] }
# Backstops for a missing defaults file: the same values the VM launcher ships.
if ([string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_TableName_Summary))  { $global:SI_RiskAnalysis_TableName_Summary  = 'SI_RiskAnalysis_Summary' }
if ([string]::IsNullOrWhiteSpace([string]$global:SI_RiskAnalysis_TableName_Detailed)) { $global:SI_RiskAnalysis_TableName_Detailed = 'SI_RiskAnalysis_Detailed' }
# #830: the copy of the report rows to Log Analytics is an optional output, OFF by default (the defaults file says so too)
if ($null -eq $global:SendToLogAnalytics) { $global:SendToLogAnalytics = $false }
$global:SendToLogAnalytics = Test-SITruthy $global:SendToLogAnalytics
# The run-health record (Send-SIRunHealthRow) reads the SI_* names the collection entry point sets. Without them the
# Risk Analysis container finished its whole run and recorded NOTHING (live 2026-10-02: "Run-health record not saved:
# SI_WorkspaceResourceId, SI_DceName or SI_DcrResourceGroup is not set") -- and the vulnerability close-loop only closes
# after a Risk Analysis run recorded as complete. A value the customer config already supplied is kept.
if (-not $global:SI_DceName)          { $global:SI_DceName          = $global:DceName }
if (-not $global:SI_DcrResourceGroup) { $global:SI_DcrResourceGroup = $global:DcrResourceGroup }
if (-not $global:SI_AzSubscriptionId) { $global:SI_AzSubscriptionId = ($global:SI_WorkspaceResourceId -split '/')[2] }
if (-not $global:SI_DceResourceGroup) { $global:SI_DceResourceGroup = $global:SI_DcrResourceGroup }

# Catalog location -- v2.2/engine/risk-analysis/ inside the image.
$global:SettingsPath = Get-OptionalEnv 'SI_RA_SETTINGS_PATH' '/app/risk-analysis-detection'

# Report template + mode -- ONE decision, not two. The mode is not a label: it selects the Log
# Analytics table, the DCR and the mail lane. Set independently (the VM launchers' #39 defect, on the
# container path), SI_RA_REPORT_TEMPLATE=RiskAnalysis_Detailed with SI_RA_MODE unset ingested Detailed
# rows into the Summary table, and an unrecognised SI_RA_MODE silently became Summary.
function Resolve-SIContainerRaMode {
    param([string]$Template, [string]$Mode)
    $tplMode = $null
    if (-not [string]::IsNullOrWhiteSpace($Template)) {
        if ($Template -match '(?i)detailed')    { $tplMode = 'Detailed' }
        elseif ($Template -match '(?i)summary') { $tplMode = 'Summary' }
    }
    $modeNorm = $null
    if (-not [string]::IsNullOrWhiteSpace($Mode)) {
        if     ($Mode.Trim() -ieq 'Summary')  { $modeNorm = 'Summary' }
        elseif ($Mode.Trim() -ieq 'Detailed') { $modeNorm = 'Detailed' }
        else { throw ("SI_RA_MODE='{0}' is not a run mode -- use Summary or Detailed. (It selects the Log Analytics table, so it is not guessed.)" -f $Mode) }
    }
    if ($tplMode -and $modeNorm -and $tplMode -ne $modeNorm) {
        throw ("Contradictory settings: SI_RA_REPORT_TEMPLATE='{0}' is a {1} template but SI_RA_MODE='{2}'. The mode selects the Log Analytics table and DCR, so this would ingest {1} rows into the {2} table. Set one or the other." -f $Template, $tplMode, $modeNorm)
    }
    # The template is the more specific statement of intent; a custom template with no grain in its
    # name keeps the stated mode (default Summary).
    $final = if ($tplMode) { $tplMode } elseif ($modeNorm) { $modeNorm } else { 'Summary' }
    $tpl = if (-not [string]::IsNullOrWhiteSpace($Template)) { $Template.Trim() } else { 'RiskAnalysis_{0}' -f $final }
    [pscustomobject]@{ Template = $tpl; Mode = $final; Summary = ($final -eq 'Summary'); Detailed = ($final -eq 'Detailed') }
}

$__ra = Resolve-SIContainerRaMode -Template (Get-OptionalEnv 'SI_RA_REPORT_TEMPLATE' $null) -Mode (Get-OptionalEnv 'SI_RA_MODE' $null)
$global:ReportTemplate = $__ra.Template
$mode                  = $__ra.Mode
$global:Summary        = $__ra.Summary
$global:Detailed       = $__ra.Detailed

# Mail: SI_RA_SEND_MAIL when the job sets it (applied above), else the customer's own setting; off when neither says.
$global:SendMail = Test-SITruthy $global:SendMail
# #218: when the customer's config switches the mail ON (RiskAnalysis_*_SendMail, passed with the other settings),
# the SMTP password arrives as a Key Vault-referenced secret -- it never travels as a plain setting. Without it the
# engine's SMTP pre-flight refuses to start, and says which credential is missing.
$smtpPassword = Get-OptionalEnv 'SMTP_PASSWORD' $null
if ($smtpPassword) { $global:SMTPPassword = $smtpPassword }

# AI summary: SI_RA_BUILD_SUMMARY_BY_AI when the job sets it, else the customer's own setting; off when neither says.
$global:BuildSummaryByAI = Test-SITruthy $global:BuildSummaryByAI
if ($global:BuildSummaryByAI) {
    if ($raEnv.Contains('BuildSummaryByAI')) {
        # Asked for by setup itself: Azure OpenAI must reach the job, or the run stops and says which part is missing.
        $global:OpenAI_apiKey     = Get-RequiredEnv 'OPENAI_APIKEY'
        $global:OpenAI_endpoint   = Get-RequiredEnv 'OPENAI_ENDPOINT'
        $global:OpenAI_deployment = Get-RequiredEnv 'OPENAI_DEPLOYMENT'
        $global:OpenAI_apiVersion = Get-RequiredEnv 'OPENAI_APIVERSION'
    } else {
        $aiParts = @{ apiKey = (Get-OptionalEnv 'OPENAI_APIKEY'); endpoint = (Get-OptionalEnv 'OPENAI_ENDPOINT')
                      deployment = (Get-OptionalEnv 'OPENAI_DEPLOYMENT'); apiVersion = (Get-OptionalEnv 'OPENAI_APIVERSION') }
        $aiState = Resolve-SIContainerAi -OpenAi $aiParts -Requested $true
        if ($aiState.Enabled) {
            $global:OpenAI_apiKey = $aiParts.apiKey; $global:OpenAI_endpoint = $aiParts.endpoint
            $global:OpenAI_deployment = $aiParts.deployment; $global:OpenAI_apiVersion = $aiParts.apiVersion
        } else {
            Write-Warning ('[ai] the AI summary is on in the configuration, but Azure OpenAI does not reach this job -- the report is built without it. {0}' -f $aiState.Reason)
            $global:BuildSummaryByAI = $false
        }
    }
}

# Cloud-native output: blob URL is the canonical destination. The engine
# still writes the XLSX/JSON to the container fs first (ephemeral), then
# Phase 3 uploads + backup-then-overwrites at the destination.
#
# if SI_RA_EXPORT_DESTINATION is unset, derive a sensible
# default from SI_STORAGE_ACCOUNT + the canonical 'sistaging' container.
# Bootstrap-ContainerAppJob.ps1 normally sets the env var explicitly, but
# this fallback means a manually-launched container also publishes correctly
# without extra env wiring.
$global:ExportDestination = Get-OptionalEnv 'SI_RA_EXPORT_DESTINATION' $null
if ([string]::IsNullOrWhiteSpace($global:ExportDestination)) {
    $stgAccount = Get-OptionalEnv 'SI_STORAGE_ACCOUNT' $null
    if (-not [string]::IsNullOrWhiteSpace($stgAccount)) {
        $exportContainer = Get-OptionalEnv 'SI_RA_EXPORT_CONTAINER' 'sistaging'
        $exportPrefix    = (Get-OptionalEnv 'SI_RA_EXPORT_PREFIX' 'risk-analysis').Trim('/')
        $global:ExportDestination = if ([string]::IsNullOrWhiteSpace($exportPrefix)) {
            ('https://{0}.blob.core.windows.net/{1}/' -f $stgAccount, $exportContainer)
        } else {
            ('https://{0}.blob.core.windows.net/{1}/{2}/' -f $stgAccount, $exportContainer, $exportPrefix)
        }
        Write-Host ('[export] auto-derived ExportDestination = {0}' -f $global:ExportDestination)
    } else {
        Write-Warning 'SI_RA_EXPORT_DESTINATION not set and SI_STORAGE_ACCOUNT also empty -- XLSX/JSON will be written to the container fs only and lost when the replica exits.'
    }
}

# Bucketing -- UseQueryBucketing / DefaultBucketCount / BucketPlaceholderToken are hardcoded constants inside the
# engine. The AutoBucket* knobs come from the customer's settings or the VM defaults (131072), and SI_RA_AUTO_BUCKET* on
# the job wins only when present (applied above). Backstops for a missing defaults file:
if ($null -eq $global:AutoBucketCount) { $global:AutoBucketCount = $true }
if ($null -eq $global:AutoBucketCache) { $global:AutoBucketCache = $true }
if ($null -eq $global:AutoBucketMax -or "$($global:AutoBucketMax)" -notmatch '^\d+$') { $global:AutoBucketMax = 131072 }
$global:AutoBucketCount = Test-SITruthy $global:AutoBucketCount
$global:AutoBucketCache = Test-SITruthy $global:AutoBucketCache
$global:AutoBucketMax   = [int]"$($global:AutoBucketMax)"

# #742 -- THE REPORTS ON QUEUE WORKERS (engine/risk-analysis/_shared/RA-ScaleOut.ps1). This job is either the run's producer
# (SI_RA_SCALE_OUT = on, set by setup on the Risk Analysis job when its worker job exists -- SI_RA_WORKER_JOB names it) or a
# WORKER (SI_RA_SCALEOUT_ROLE = worker: caj-si-raworker-<grain>, or the producer's own child when no worker job exists). A worker
# takes reports from the queue and runs them as part of its producer's run; the producer finishes the run.
$raWorker = ((Get-OptionalEnv 'SI_RA_SCALEOUT_ROLE' '').Trim().ToLowerInvariant() -eq 'worker')
$global:SI_RA_ScaleOutRole = if ($raWorker) { 'worker' } else { '' }
$raScaleOut = Get-OptionalEnv 'SI_RA_SCALE_OUT' $null
if ($null -ne $raScaleOut) { $global:SI_RA_ScaleOut = $raScaleOut }
$global:SI_RA_WorkerJob = Get-OptionalEnv 'SI_RA_WORKER_JOB' ''
$global:SI_RA_ScaleOutEntryPoint = $PSCommandPath
# the heartbeat that holds a worker's report runs on its own thread -- it signs in with the identity this entry point loaded
$global:SI_RA_BeatSignIn = @(); if ($siAuth.Mode -eq 'ManagedIdentity') { $global:SI_RA_BeatSignIn = @('/app/auth/SI-ManagedIdentity.ps1') }

# Started before the banner so the banner lands INSIDE the transcript -- it is the
# run header an operator reads first. -Template mirrors what the VM launchers pass,
# so a container log and a VM log for the same report have the same file name shape.
Start-SILauncherTranscript -Engine 'risk-analysis' -Flavour container -RepoRoot '/app' `
    -Template $(if ($raWorker) { '{0}-worker' -f $global:ReportTemplate } else { $global:ReportTemplate }) | Out-Null

# The build this image was made from (BUILD.json, stamped by Bootstrap-ContainerAppJob.ps1 at image build time; never git at run time).
. (Join-Path $PSScriptRoot '../engine/_shared/SI-BuildInfo.ps1')
$siBuild = Read-SIBuildInfo -SolutionRoot (Split-Path -Parent $PSScriptRoot)
Write-Host '======================================================================'
Write-Host (' SecurityInsight {0} Risk Analysis in container -- ts={1}' -f (Format-SIBuildLine $siBuild), ([datetime]::UtcNow.ToString('o')))
Write-Host ('  ReportTemplate    = {0}' -f $global:ReportTemplate)
Write-Host ('  Mode              = {0}' -f $mode)
Write-Host ('  SettingsPath      = {0}' -f $global:SettingsPath)
Write-Host ('  WorkspaceName     = {0}' -f $global:WorkspaceName)
Write-Host ('  ExportDestination = {0}' -f ($(if ($global:ExportDestination) { $global:ExportDestination } else { '<unset>' })))
Write-Host ('  SendToLA          = {0}' -f $global:SendToLogAnalytics)
Write-Host ('  BuildSummaryByAI  = {0}' -f $global:BuildSummaryByAI)
if ($raWorker) { Write-Host '  Role              = queue worker (runs reports of its producer''s run)' }
elseif (Test-SITruthy $global:SI_RA_ScaleOut) { Write-Host ('  Role              = producer (the reports go to queue workers{0})' -f $(if ($global:SI_RA_WorkerJob) { ': ' + $global:SI_RA_WorkerJob } else { ' in this job' })) }
Write-Host '======================================================================'

# 🔴 THE SAME DEAD BRANCH AS Start-SIInContainer.ps1 STOOD HERE, and it covered the other two of the
# seven container engines (risk-analysis, risk-analysis-detailed). `.dockerignore` excludes
# `**/config/` and `**/*.custom.ps1` deliberately -- real tenant values must never be baked into a
# shared image -- so the Test-Path was always false and the `else` warning was the only path taken, on
# every run. MEASURED in the built image 2026-09-08: `config_dir=False`, `custom_ps1=0`.
#
# 🔒 REMOVED, NOT REPAIRED. It sat AFTER the env-var hydration above, so a customer file would have
# overridden the credentials and workspace the Container App Job supplied. The container is its own
# configuration layer by design; env vars are that layer. See #111.
# 📌 SI_CustomConfigPath is left unset on purpose -- the engine skips silently when it finds no custom
# file, which is the correct outcome when there is deliberately nothing to find.

# Sign in (recorded, over REST) -- the engine's "community auth" branch does this too,
# but doing it up-front means a credential failure aborts before we touch
# any catalog files.
$subId  = ($global:SI_WorkspaceResourceId -split '/')[2]
if ($siAuth.Mode -eq 'ManagedIdentity') {
    Connect-SIAzAccount -Identity -AccountId $global:SI_UAMI_ClientId -Subscription $subId -WarningAction SilentlyContinue | Out-Null
} elseif ($siAuth.Mode -eq 'Certificate') {
    $siCertArgs = @{ ServicePrincipal = $true; ApplicationId = $global:SpnClientId; Tenant = $global:SpnTenantId
                     CertificatePath = $siCertPfxPath; Subscription = $subId; WarningAction = 'SilentlyContinue' }
    $siCertPw = Get-OptionalEnv 'SI_SPN_CERT_PASSWORD' $null
    if ($siCertPw) { $siCertArgs['CertificatePassword'] = (ConvertTo-SecureString $siCertPw -AsPlainText -Force) }
    Connect-SIAzAccount @siCertArgs | Out-Null
} else {
    $secure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $cred   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secure)
    Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -Subscription $subId -WarningAction SilentlyContinue | Out-Null
}
# #209: log ingestion mints its own tokens over REST (identity endpoint / X509 store) -- nothing to install here.

# #281: the run-health record signs in with the SI_SPN_* names; this entry point kept the identity only as Spn*, so the
# record went out with an EMPTY app id and the ingest module silently created no rule (live 2026-10-05: "the data
# collection rule 'dcr-si-run-health' was not found"). The same mapping the collection entry point runs.
$siIngest = Initialize-SIContainerIngestGlobals
if (-not $siIngest.SubscriptionId) { Write-Warning '[ingest] no subscription found for the Log Analytics workspace (SI_WORKSPACE_RESOURCEID) -- run-health records cannot be saved.' }

# Engine lives outside v2.2/ -- the Dockerfile build context now includes
# SCRIPTS/ so /app/SCRIPTS/SecurityInsight_RiskAnalysis.ps1 is present.
$engineScript = '/app/engine/risk-analysis/Invoke-RiskAnalysis.ps1'
if (-not (Test-Path -LiteralPath $engineScript)) {
    throw "RA engine not found at $engineScript -- check Dockerfile COPY paths."
}

# AutomationFramework=$false steers the engine into the "community" auth
# branch (line 2341+), which expects $global:Spn* to be already populated --
# which we did above. No legacy AutomateITPS module pull needed.
$global:AutomationFramework = $false

# The engine checks its OWN permissions (engine/_shared/SI-PermissionCheck.ps1), exactly as the collection entry point does;
# the result travels on the run-health END record (PermissionGaps). Never stops the run.
try { . (Join-Path $PSScriptRoot '../engine/_shared/SI-PermissionCheck.ps1'); $null = Invoke-SIPermissionSelfCheck -Engine 'risk-analysis' }
catch { Write-Warning ('[permissions] the permission check could not run: {0}' -f $_.Exception.Message) }

# #211 (2): the Pro settings database, as launcher Layer 5b does on a VM (exclusions / weights reach Risk Analysis through
# SI_ProRaSettingsPath, #211 (1)). Only with the Pro module present AND a Pro database configured; a failure stops the run.
$proSettingsModule = '/app/engine/pro-settings/SI-ProSettings.ps1'
if ((Test-Path -LiteralPath $proSettingsModule) -and $global:SI_ProSqlServer -and $global:SI_ProSqlDatabase) {
    try {
        . $proSettingsModule
        # The container owns its sign-in, targets and platform switches: the database never overrides them.
        $proLayer = Invoke-SIProSettingsLayer -Engine 'risk-analysis' -ExcludeNames $script:SIConfigProtected
        Write-Host ('[pro-settings] loaded from {0} (settings version {1})' -f $proLayer.Store, $global:SI_ProSettingsVersion)
        if (@($global:SI_ProSettingsSkipped).Count) { Write-Host ('[pro-settings] not applied here (container-owned): {0}' -f (@($global:SI_ProSettingsSkipped) -join ', ')) }
    } catch {
        Write-Host ('[pro-settings] {0}' -f $_.Exception.Message) -ForegroundColor Red
        Publish-SILauncherTranscript -Engine 'risk-analysis' -Context (New-SIRunLogStorageContext) | Out-Null
        # UPLINK-FIX: the install is not finished (the identity's database user comes later) -- nothing ran; not a failure
        if ($global:SI_ProSettingsInstallPending) { Write-Host '[pro-settings] the install is not finished yet -- this run did nothing; the next one after the install runs normally.'; exit 0 }
        exit 1
    }
} else {
    # No settings database: the install's customisation files (custom queries, exclusions, weights...) that setup shared
    # to its storage account go where a VM has them. No licence needed.
    $overlay = Restore-SIContainerOverlay -AccountName $raStorageAccount -TargetRoot '/app'
    if (@($overlay.Applied).Count) { Write-Host ('[customisation] {0} file(s) from the install: {1}' -f @($overlay.Applied).Count, (@($overlay.Applied) -join ', ')) }
    if (@($overlay.Skipped).Count) { Write-Warning ('[customisation] not used (not a customisation file): {0}' -f (@($overlay.Skipped) -join ', ')) }
}

# #276: no dry run from the job's settings (SI_WHATIF=1 on one execution asks for one), the retired Power BI line, and the
# one-time notices after an upgrade -- the same safety layer a VM launcher runs (engine/_shared/SI-FirstRun.ps1).
# (#742: a queue worker skips it -- its producer, the run, did it; a one-time notice is said once, by the run)
if (-not $raWorker) { try { . /app/engine/_shared/SI-FirstRun.ps1; $null = Invoke-SIContainerRunSafety -Engine 'risk-analysis' -StorageAccount ([string]$raStorageAccount) } catch { Write-Verbose $_.Exception.Message } }

# The bucket counts earlier runs discovered (the VM keeps them on disk; a container's disk does not outlive the run).
# #640: with the Pro database the counts live THERE only -- the engine reads and writes them itself. The counts an install
# kept in its storage account before are handed over ONCE (imported into the database by the engine) and never used again.
$bucketCachePath = $null
$global:SI_RaBucketImportCache = $null
$bucketInDatabase = [bool]($global:SI_ProSettingsStore -and $global:SI_ProSettingsStore.Invoke)
if ($bucketInDatabase) {
    if ($global:AutoBucketCache) {
        try {
            . (Join-Path $PSScriptRoot '../engine/risk-analysis/_shared/RA-BucketStore.ps1')
            if ((Test-SIRaBucketTables -Invoke $global:SI_ProSettingsStore.Invoke) -and -not (Test-SIRaBucketImported -Invoke $global:SI_ProSettingsStore.Invoke -Template $global:ReportTemplate)) {
                $imp = Get-SIRaAutoBucketCacheForImport -AccountName $raStorageAccount -Template $global:ReportTemplate
                $global:SI_RaBucketImportCache = if ($imp -is [hashtable]) { $imp } else { @{} }
                Write-Host ('[bucketing] the counts learned before are imported into the database once ({0} found)' -f @($global:SI_RaBucketImportCache.Keys | Where-Object { -not ([string]$_).StartsWith('__') }).Count)
            }
        } catch { Write-Warning ('[bucketing] the one-time import of the earlier counts was not prepared: {0}' -f $_.Exception.Message) }
    }
} elseif ($global:AutoBucketCache -and -not $global:ResetCache) {
    $bucketCachePath = Get-SIRaAutoBucketCacheLocalPath -SettingsPath $global:SettingsPath
    if ((Restore-SIRaAutoBucketCache -AccountName $raStorageAccount -LocalPath $bucketCachePath -Template $global:ReportTemplate) -eq 'storage') {
        Write-Host '[bucketing] bucket counts from earlier runs loaded'
    }
} elseif ($global:AutoBucketCache) {
    $bucketCachePath = Get-SIRaAutoBucketCacheLocalPath -SettingsPath $global:SettingsPath
}

# The previous run's per-report finding counts and column fill, so the completeness check can compare this run with it
# (a container's disk does not outlive the run; without this every run is the "first" and a report that lost most of
# its findings is never noticed).
if ((Restore-SIRaGuardHistory -AccountName $raStorageAccount -SettingsPath $global:SettingsPath -Template $global:ReportTemplate) -gt 0) {
    Write-Host '[completeness] the previous run''s report counts loaded'
}

$global:SI_RA_ScaleOutRan = $false
$global:SI_RA_ScaleOutReportsRun = New-Object System.Collections.Generic.List[string]
$global:SI_RA_ScaleOutRunOver = ''
& $engineScript
$raExit = $LASTEXITCODE

# #742: a worker keeps only the counts of the reports IT ran, on the copy in storage (under the run's lock -- workers finish
# at the same time); a producer that handed its reports to workers learned no count, so it writes none over theirs.
# #882: a worker that stopped because its run is over (Assert-RAScaleOutWorkerLive) keeps NO count -- fail closed
if ($raWorker -and "$($global:SI_RA_ScaleOutRunOver)".Trim()) { Write-Warning ('[bucketing] the counts of this worker are not kept: {0}' -f $global:SI_RA_ScaleOutRunOver) }
if ($bucketCachePath -and -not ($raWorker -and "$($global:SI_RA_ScaleOutRunOver)".Trim())) {
    if ($raWorker) {
        if ($global:SI_RA_ScaleOutReportsRun.Count -and (Test-Path -LiteralPath $bucketCachePath) -and $global:SI_RA_ScaleOutLockPath) {
            try {
                . /app/engine/risk-analysis/_shared/RA-ScaleOut.ps1
                $bcStore = New-RAScaleOutBlobStore -Account $raStorageAccount
                $bcOwner = Enter-RAScaleOutLock -Store $bcStore -Path ([string]$global:SI_RA_ScaleOutLockPath) -WaitSeconds 300
                try {
                    $bcTmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('si-ra-bucketcache-{0}.json' -f [guid]::NewGuid().ToString('N')))
                    $bcStored = @{}
                    if ((Restore-SIRaAutoBucketCache -AccountName $raStorageAccount -LocalPath $bcTmp -Template $global:ReportTemplate) -eq 'storage' -and (Test-Path -LiteralPath $bcTmp)) { $bcStored = ConvertFrom-RAScaleOutJson -Text ([IO.File]::ReadAllText($bcTmp)) }
                    $bcLocal = ConvertFrom-RAScaleOutJson -Text ([IO.File]::ReadAllText($bucketCachePath))
                    $bcMerged = Merge-RAScaleOutBucketCache -Stored $bcStored -Local $bcLocal -Reports @($global:SI_RA_ScaleOutReportsRun)
                    [IO.File]::WriteAllText($bucketCachePath, (ConvertTo-Json -InputObject $bcMerged -Depth 6))
                    $null = Save-SIRaAutoBucketCache -AccountName $raStorageAccount -LocalPath $bucketCachePath -Template $global:ReportTemplate
                    Remove-Item -LiteralPath $bcTmp -Force -ErrorAction SilentlyContinue
                } finally { Exit-RAScaleOutLock -Store $bcStore -Path ([string]$global:SI_RA_ScaleOutLockPath) -Owner $bcOwner }
            } catch { Write-Warning ('[bucketing] the counts of the reports this worker ran were not kept: {0}' -f $_.Exception.Message) }
        }
    } elseif (-not $global:SI_RA_ScaleOutRan) { $null = Save-SIRaAutoBucketCache -AccountName $raStorageAccount -LocalPath $bucketCachePath -Template $global:ReportTemplate }
}
# the completeness history is the run's (the producer's guards wrote it); a worker never writes it
if (-not $raWorker) { $null = Save-SIRaGuardHistory -AccountName $raStorageAccount -SettingsPath $global:SettingsPath -Template $global:ReportTemplate }

# #55.1(b). RA's own Phase 3 already publishes the XLSX/JSON to this account; the
# run log now lands beside them instead of dying with the replica.
Publish-SILauncherTranscript -Engine 'risk-analysis' -Context (New-SIRunLogStorageContext) | Out-Null

exit $raExit
