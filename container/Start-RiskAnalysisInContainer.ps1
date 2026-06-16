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

    Optional env vars (all have engine defaults):
      SI_RA_REPORT_TEMPLATE                    -- default 'RiskAnalysis_Summary'
                                                  (or 'RiskAnalysis_Detailed_Bucket')
      SI_RA_MODE                               -- 'Summary' | 'Detailed' (sets the matching bool)
      SI_RA_BUILD_SUMMARY_BY_AI                -- '0'/'1' (default 0)
      SI_RA_SEND_TO_LOG_ANALYTICS              -- '0'/'1' (default 0; routes Summary -> SI_RiskAnalysis_Summary_CL,
                                                  Detailed -> SI_RiskAnalysis_Detailed_CL via DCR)
      SI_RA_SETTINGS_PATH                      -- default '/app/engine/risk-analysis' (the v2.2 catalog)
      OPENAI_APIKEY / ENDPOINT / DEPLOYMENT / APIVERSION
                                               -- only required when SI_RA_BUILD_SUMMARY_BY_AI=1

    NOT required (RA reads these from env if present, else falls back):
      SMTP_*                                   -- mail delivery is OFF by default in container mode
                                                  (containers should publish to storage; humans pull from there)
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

# ---- Auth: SPN-secret (same single-SPN model as Start-SIInContainer.ps1) ----
$global:SpnTenantId     = Get-RequiredEnv 'SI_SPN_TENANTID'
$global:SpnClientId     = Get-RequiredEnv 'SI_SPN_APPID'
$global:SpnClientSecret = Get-RequiredEnv 'SI_SPN_SECRET'

# Aliases the RA script reads in some code paths.
$global:AzureTenantId = $global:SpnTenantId

# Workspace: the engine ingests Summary/Detailed rows into this LA workspace
# when SI_RA_SEND_TO_LOG_ANALYTICS=1. RG/DCE/DCR resolve from the workspace
# resource id + the canonical SecurityInsight layout.
$global:SI_WorkspaceResourceId = Get-RequiredEnv 'SI_WORKSPACE_RESOURCEID'
$global:WorkspaceName          = ($global:SI_WorkspaceResourceId -split '/')[-1]
$global:WorkspaceResourceGroup = ($global:SI_WorkspaceResourceId -split '/')[4]

# DCE/DCR for the Phase 2 LA ingest (only used when SI_RA_SEND_TO_LOG_ANALYTICS=1).
$global:DceName                                = Get-OptionalEnv 'SI_DCE_NAME'             $null
$global:DcrResourceGroup                       = Get-OptionalEnv 'SI_DCR_RESOURCEGROUP'    $null
$global:SI_RiskAnalysis_TableName_Summary      = Get-OptionalEnv 'SI_RA_TABLE_SUMMARY'    'SI_RiskAnalysis_Summary'
$global:SI_RiskAnalysis_TableName_Detailed     = Get-OptionalEnv 'SI_RA_TABLE_DETAILED'   'SI_RiskAnalysis_Detailed'
$global:SendToLogAnalytics                     = (Get-OptionalEnv 'SI_RA_SEND_TO_LOG_ANALYTICS' '0') -in '1','true','True','yes'

# Catalog location -- v2.2/engine/risk-analysis/ inside the image.
$global:SettingsPath = Get-OptionalEnv 'SI_RA_SETTINGS_PATH' '/app/risk-analysis-detection'

# Report template + mode.
$global:ReportTemplate = Get-OptionalEnv 'SI_RA_REPORT_TEMPLATE' 'RiskAnalysis_Summary'
$mode = Get-OptionalEnv 'SI_RA_MODE' 'Summary'
switch ($mode) {
    'Summary'  { $global:Summary = $true; $global:Detailed = $false }
    'Detailed' { $global:Summary = $false; $global:Detailed = $true }
    default    { $global:Summary = $true; $global:Detailed = $false }
}

# Mail off in container by default -- containers publish to blob; humans pull.
$global:SendMail = (Get-OptionalEnv 'SI_RA_SEND_MAIL' '0') -in '1','true','True','yes'

# AI summary off by default; flip on with SI_RA_BUILD_SUMMARY_BY_AI=1.
$global:BuildSummaryByAI = (Get-OptionalEnv 'SI_RA_BUILD_SUMMARY_BY_AI' '0') -in '1','true','True','yes'
if ($global:BuildSummaryByAI) {
    $global:OpenAI_apiKey     = Get-RequiredEnv 'OPENAI_APIKEY'
    $global:OpenAI_endpoint   = Get-RequiredEnv 'OPENAI_ENDPOINT'
    $global:OpenAI_deployment = Get-RequiredEnv 'OPENAI_DEPLOYMENT'
    $global:OpenAI_apiVersion = Get-RequiredEnv 'OPENAI_APIVERSION'
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

# Bucketing -- UseQueryBucketing / DefaultBucketCount / BucketPlaceholderToken
# are now hardcoded constants inside the engine; only AutoBucket* knobs remain
# overridable via env for deployments that need to pin behaviour.
$global:AutoBucketCount    = (Get-OptionalEnv 'SI_RA_AUTO_BUCKET'      '1') -in '1','true','True','yes'
$global:AutoBucketMax      = [int](Get-OptionalEnv 'SI_RA_AUTO_BUCKET_MAX' '1024')
$global:AutoBucketCache    = (Get-OptionalEnv 'SI_RA_AUTO_BUCKET_CACHE' '1') -in '1','true','True','yes'

Write-Host '======================================================================'
Write-Host (' SecurityInsight v2.2 Risk Analysis in container -- ts={0}' -f ([datetime]::UtcNow.ToString('o')))
Write-Host ('  ReportTemplate    = {0}' -f $global:ReportTemplate)
Write-Host ('  Mode              = {0}' -f $mode)
Write-Host ('  SettingsPath      = {0}' -f $global:SettingsPath)
Write-Host ('  WorkspaceName     = {0}' -f $global:WorkspaceName)
Write-Host ('  ExportDestination = {0}' -f ($(if ($global:ExportDestination) { $global:ExportDestination } else { '<unset>' })))
Write-Host ('  SendToLA          = {0}' -f $global:SendToLogAnalytics)
Write-Host ('  BuildSummaryByAI  = {0}' -f $global:BuildSummaryByAI)
Write-Host '======================================================================'

# v2.3 -- dot-source customer custom.ps1 + pin SI_CustomConfigPath so the
# engine's auto-derive (3x Split-Path from $PSScriptRoot) doesn't fall off
# /app/'s root in the flattened container layout (no v2.2/ prefix).
# Same fix that Start-SIInContainer.ps1 applies for the profiler engines.
$customCfg = '/app/config/SecurityInsight.custom.ps1'
if (Test-Path -LiteralPath $customCfg) {
    Write-Host ('[config] dot-sourcing {0} (VM-launcher parity)' -f $customCfg) -ForegroundColor Cyan
    . $customCfg
    $global:SI_CustomConfigPath = $customCfg
} else {
    Write-Warning ('[config] {0} NOT FOUND -- engine may throw on missing -Path' -f $customCfg)
}

# Connect-AzAccount -- the engine's "community auth" branch does this too,
# but doing it up-front means a credential failure aborts before we touch
# any catalog files.
$secure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
$cred   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secure)
$subId  = ($global:SI_WorkspaceResourceId -split '/')[2]
Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -Subscription $subId -WarningAction SilentlyContinue | Out-Null

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

& $engineScript
exit $LASTEXITCODE
