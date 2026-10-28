#Requires -Version 5.1
<#
.SYNOPSIS
    Proves a SecurityInsight Pro management deployment from INSIDE its Container Apps environment (so it works with
    internal ingress too, where a machine outside the environment cannot reach the apps). -Ingress says which ingress
    the deployment is expected to have (Deploy-SIManagement.ps1 -Ingress); a mismatch stops the proof. PLAN BY
    DEFAULT; -Apply runs it.

.DESCRIPTION
    -Apply: builds the probe image (deploy\probe) in the registry, creates a one-off MANUAL Container Apps job in the
    same environment on the WEB app's managed identity, starts it, prints its console result, and deletes the job
    (-KeepJob keeps it). The probe checks:
      * /healthz of both apps returns "ok";
      * an unauthenticated page request redirects to Entra sign-in for this app and this host; a static asset too;
      * the MCP endpoint returns 401 without a token and with a malformed one;
      * with -McpViewerToken / -McpAdminToken (access tokens for api://<client id> carrying ONLY that app role):
        initialize, tools/list (settings_read only for Admin) and one real top_risks call;
      * with -ChatQuestion: one real question through the chat service, against the real Azure OpenAI deployment,
        as the web app's identity, with the web app's own Identity / Estate / Chat settings -- the answer and every
        tool call are printed.
    Tokens are passed as job SECRETS, never printed, and the job is deleted at the end.

    NO az CLI, NO PowerShell module (owner 2026-10-10): the reads, the image build (the registry's own build over ARM),
    the job (Microsoft.App api 2025-07-01: one PUT of the whole job, POST start, GET the execution, DELETE) all go through
    SecurityInsight's own REST layer (SI-ManagementArm.ps1), as setup's sign-in. The job's console output is read from
    the environment's Log Analytics workspace over the Log Analytics REST API (the web app's Estate__WorkspaceId, or
    -WorkspaceId) -- the signed-in identity needs "Log Analytics Reader" there; the log arrives after an ingestion delay.

.EXAMPLE
    .\Test-SIManagementDeployment.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -RegistryName <acr> -EnvironmentName <cae> `
        -ChatQuestion 'Which assets carry the most risk right now?' -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$RegistryName,
    [Parameter(Mandatory)][string]$EnvironmentName,
    [string]$AppName = 'ca-si-management',
    [string]$McpAppName = 'ca-si-mcp',
    [string]$IdentityName = 'uami-si-management',
    [string]$JobName = 'caj-si-mgmt-probe',
    [string]$ImageTag = ('{0}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')),
    [switch]$SkipBuild,
    [string]$McpViewerToken = '',
    [string]$McpAdminToken = '',
    [string]$ChatQuestion = '',
    [int]$TimeoutSeconds = 600,
    [ValidateSet('Internal', 'External')][string]$Ingress = 'Internal',
    # the Log Analytics workspace (customer id) the environment's console logs go to; default: the web app's Estate__WorkspaceId
    [string]$WorkspaceId = '',
    [switch]$KeepJob,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

$managementRoot = Split-Path -Parent $PSScriptRoot
$image = 'si-management-probe:{0}' -f $ImageTag
$mode = if ($Apply) { 'APPLY' } else { 'PLAN (nothing is changed; add -Apply)' }

# #521: the REST layer (setup's one sign-in, ARM, the registry build, Log Analytics) -- no az CLI, no module
. (Join-Path $PSScriptRoot 'SI-ManagementArm.ps1')
$appApi = Get-SIManagementAppApi
$rgPath = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
$jobPath = '{0}/providers/Microsoft.App/jobs/{1}' -f $rgPath, $JobName

function Write-Step([string]$Text) { Write-Host ''; Write-Host ('== ' + $Text) -ForegroundColor Cyan }
function Write-Call([string]$Method, [string]$Path) { Write-Host ('  {0} {1}' -f $Method.ToUpperInvariant(), $Path) -ForegroundColor DarkGray }

Write-Host ('SecurityInsight Pro management -- deployment probe {0}' -f $mode) -ForegroundColor White
$null = Connect-SIManagementRest -SubscriptionId $SubscriptionId

# ---------------------------------------------------------------------------------------------------------------
Write-Step '1. What is deployed'
Write-Call 'GET' (Get-SIManagementContainerAppPath $SubscriptionId $ResourceGroup $AppName)
$webApp = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $AppName
Write-Call 'GET' (Get-SIManagementContainerAppPath $SubscriptionId $ResourceGroup $McpAppName)
$mcpApp = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $McpAppName
Write-Call 'GET' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $rgPath, $IdentityName)
$identity = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name $IdentityName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
Write-Call 'GET' ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}' -f $rgPath, $RegistryName)
$registry = Get-SIContainerRegistry -ResourceGroupName $ResourceGroup -Name $RegistryName -SubscriptionId $SubscriptionId
if (-not ($webApp -and $mcpApp -and $identity -and $registry)) { throw 'Lookups returned nothing (the sign-in has no access, or the apps do not exist).' }
foreach ($a in @($webApp, $mcpApp)) {
    $ext = [bool](Get-SIManagementProp $a @('properties', 'configuration', 'ingress', 'external'))
    if ($ext -ne ($Ingress -eq 'External')) { throw ('{0} has {1} ingress, -Ingress {2} was expected.' -f $a.name, $(if ($ext) { 'EXTERNAL' } else { 'internal' }), $Ingress) }
    Write-Host ('  {0}: https://{1} (ingress {2}, revision {3})' -f $a.name, (Get-SIManagementProp $a @('properties', 'configuration', 'ingress', 'fqdn')), $(if ($ext) { 'external' } else { 'internal' }), (Get-SIManagementProp $a @('properties', 'latestRevisionName')))
}
$webEnv = @{}
$first = @(@(Get-SIManagementProp $webApp @('properties', 'template', 'containers')) | Where-Object { $_ }) | Select-Object -First 1
foreach ($e in @(Get-SIManagementProp $first @('env'))) { if ($e -and $e.PSObject.Properties.Name -contains 'value') { $webEnv[[string]$e.name] = [string]$e.value } }
$probeEnv = @(
    ('PROBE_WEB_URL=https://{0}' -f (Get-SIManagementProp $webApp @('properties', 'configuration', 'ingress', 'fqdn'))),
    ('PROBE_MCP_URL=https://{0}' -f (Get-SIManagementProp $mcpApp @('properties', 'configuration', 'ingress', 'fqdn'))),
    ('PROBE_TENANT_ID={0}' -f $webEnv['AzureAd__TenantId']),
    ('PROBE_CLIENT_ID={0}' -f $webEnv['AzureAd__ClientId'])
)
# the chat runs with the web app's OWN data settings and identity
foreach ($k in @($webEnv.Keys | Sort-Object)) { if ($k -like 'Identity__*' -or $k -like 'Estate__*' -or $k -like 'Chat__*' -or $k -eq 'AZURE_CLIENT_ID') { $probeEnv += ('{0}={1}' -f $k, $webEnv[$k]) } }
if ($ChatQuestion) { $probeEnv += ('PROBE_CHAT_QUESTION={0}' -f $ChatQuestion) }
$secrets = @()
if ($McpViewerToken) { $secrets += ('viewer-token={0}' -f $McpViewerToken); $probeEnv += 'PROBE_MCP_TOKEN_VIEWER=secretref:viewer-token' }
if ($McpAdminToken) { $secrets += ('admin-token={0}' -f $McpAdminToken); $probeEnv += 'PROBE_MCP_TOKEN_ADMIN=secretref:admin-token' }
if (-not $WorkspaceId) { $WorkspaceId = [string]$webEnv['Estate__WorkspaceId'] }

# ---------------------------------------------------------------------------------------------------------------
Write-Step '2. Build the probe image'
if ($SkipBuild) { Write-Host ('  -SkipBuild: reusing {0}' -f $image) }
else {
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ('si-mgmt-probe-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    Write-Call 'POST' ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}/listBuildSourceUploadUrl + upload + scheduleRun  ({2})' -f $rgPath, $RegistryName, $image)
    if ($Apply) {
        try {
            foreach ($pair in @(@('src\SI.Management.Core', 'pro-management\src\SI.Management.Core'), @('deploy\probe', 'pro-management\deploy\probe'))) {
                $from = Join-Path $managementRoot $pair[0]
                foreach ($f in @(Get-ChildItem -LiteralPath $from -Recurse -File)) {
                    $rel = $f.FullName.Substring($from.Length).TrimStart('\', '/')
                    if ($rel -match '(^|[\\/])(bin|obj)[\\/]') { continue }
                    $dest = Join-Path (Join-Path $stage $pair[1]) $rel
                    $dir = Split-Path -Parent $dest
                    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
                    Copy-Item -LiteralPath $f.FullName -Destination $dest
                }
            }
            $r = Invoke-SIAcrRestBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -SourcePath $stage `
                    -ImageNames @($image) -DockerFilePath 'pro-management/deploy/probe/Dockerfile' -OnPoll { param($s) Write-Host ('    build: {0}' -f $s) -ForegroundColor DarkGray }
            if (-not $r.Ok) { throw ('The probe image build did not succeed (run {0}: {1}).' -f $r.RunId, $r.Status) }
        } finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step '3. Run the probe as a one-off job in the environment'
$caeId = '{0}/providers/Microsoft.App/managedEnvironments/{1}' -f $rgPath, $EnvironmentName
Write-Call 'PUT' ('{0}  (api {1}: Manual trigger, no retry, the web identity; {2} secret(s), never printed)' -f $jobPath, $appApi, $secrets.Count)
Write-Call 'POST' ('{0}/start' -f $jobPath)
$result = $null
$text = ''
if ($Apply) {
    try {
        $location = [string]$webApp.location
        $body = New-SIManagementProbeJobBody -Name $JobName -Location $location -EnvironmentId $caeId -Image ('{0}/{1}' -f $registry.loginServer, $image) `
                    -RegistryServer ([string]$registry.loginServer) -IdentityId ([string]$identity.Id) -Env $probeEnv -Secrets $secrets -ReplicaTimeout ($TimeoutSeconds + 300)
        $null = Invoke-SIManagementArmWrite -Method PUT -Path $jobPath -Body $body
        $exec = Invoke-SIArm -Method POST -Path ($jobPath + '/start') -ApiVersion $appApi
        $execName = [string](Get-SIManagementProp $exec @('name'))
        if (-not $execName -and (Get-SIManagementProp $exec @('id'))) { $execName = ([string]$exec.id -split '/')[-1] }
        Write-Host ('  execution {0}; waiting for it to end and for PROBE-SUMMARY in the workspace log (up to {1} s)' -f $execName, $TimeoutSeconds)
        if (-not $WorkspaceId) { throw 'No workspace to read the probe''s log from: the web app has no Estate__WorkspaceId -- pass -WorkspaceId.' }
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        $status = ''
        do {
            Start-Sleep -Seconds 20
            try { $status = [string](Get-SIManagementProp (Invoke-SIArm -Path ('{0}/executions/{1}' -f $jobPath, $execName) -ApiVersion $appApi -AllowNotFound) @('properties', 'status')) } catch { $status = '' }
            # the console lines arrive in Log Analytics after an ingestion delay; a refused query is shown, not swallowed
            try { $text = (@(Get-SIManagementJobExecutionLog -WorkspaceId $WorkspaceId -Execution $execName) -join "`n") }
            catch { $text = ('(the workspace log could not be read: {0})' -f $_.Exception.Message) }
            if ($text -match 'PROBE-SUMMARY') { $result = $text; break }
        } while ((Get-Date) -lt $deadline)
        if (-not $result) { throw ('No PROBE-SUMMARY within {0} s (execution {1}: {2}). Last log:{3}{4}' -f $TimeoutSeconds, $execName, $status, "`n", $text) }
        Write-Host ''
        $printing = $false
        foreach ($l in @($result -split "`n")) {
            # a line may be wrapped as JSON ({"Log": ...}); keep the probe's own text
            $t = $l
            try { $j = $l | ConvertFrom-Json -ErrorAction Stop; if ($j.PSObject.Properties.Name -contains 'Log') { $t = $j.Log } } catch { }
            if ($t -match 'CHAT-ANSWER-BEGIN') { $printing = $true }
            if ($printing -or $t -match 'PROBE|CHAT-') { Write-Host ('  ' + $t) }
            if ($t -match 'CHAT-ANSWER-END') { $printing = $false }
        }
    } finally {
        if ($KeepJob) { Write-Host ('  -KeepJob: {0} left in place' -f $JobName) }
        else {
            Write-Call 'DELETE' $jobPath
            try { $null = Invoke-SIArm -Method DELETE -Path $jobPath -ApiVersion $appApi -AllowNotFound } catch { Write-Warning ('The probe job {0} could not be deleted: {1}' -f $JobName, $_.Exception.Message) }
        }
    }
}

if (-not $Apply) { Write-Host ''; Write-Host 'Plan only -- nothing was changed. Re-run with -Apply to run the probe.' -ForegroundColor Yellow }
elseif ($result -notmatch 'PROBE-SUMMARY pass=\d+ fail=0') { throw 'The probe reported failures (see above).' }
