#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the SecurityInsight Pro management web app AND its MCP server as two Container Apps, each on its own
    user-assigned managed identity -- with INTERNAL ingress (default) or, with -Ingress External, PUBLIC ingress
    protected by Entra sign-in (operator decision 2026-10-03: public ingress + Entra Conditional Access).

.DESCRIPTION
    PLAN BY DEFAULT: prints every step and every Azure call (method + resource), changes nothing. -Apply runs them.

    NO az CLI, NO PowerShell module (owner 2026-10-10): every call is ARM / data-plane / Microsoft Graph REST through
    SecurityInsight's own REST layer (SI-ManagementArm.ps1 over setup\_shared\SI-SetupAzure.ps1 + SI-SetupArm.ps1), as
    whoever setup signed in as: the guided install's sign-in, an Invardia support session's tokens, a person (Cloud Shell or
    the browser) or an app with a certificate. An existing sign-in of this process is reused.

    Two apps, because the code is two processes with two authentication models: the web app (SI.Management.Web) signs
    users in with an ID token and a cookie; the MCP server (SI.Management.Mcp) validates a bearer access token on every
    request. Both read the estate through SI.Management.Core; the web app's chat calls the same tools in-process, so
    the web app never calls the MCP server and needs no credential for it.

    What -Apply does, in the customer's subscription (every call names -SubscriptionId explicitly):
      1. stages a clean build context (source + the settings catalog; no bin\, obj\ or custom config) and builds both
         images IN the customer's registry (the registry's own build over ARM: upload slot, upload, scheduleRun, poll)
         -- no local Docker needed (-SkipBuild reuses -ImageTag);
      2. creates (or reuses) two user-assigned managed identities -- the web app's and the MCP server's -- and grants
         each AcrPull on the registry (the registry's admin user is never used);
      3. with -WorkspaceResourceId: "Log Analytics Reader" on the workspace for both identities;
         with -ChatResourceId: "Cognitive Services OpenAI User" on the Azure OpenAI resource for the web app's identity;
      4. creates or updates both Container Apps (Microsoft.App api 2025-07-01) in an EXISTING Container Apps environment:
         -Ingress (Internal | External) on port 8080, session affinity on the web app (its pending changes and sign-in
         cookie stay on one replica), the identity attached (registry pull + data), and the app settings. No secret is
         set anywhere. An existing app is changed READ-MODIFY-WRITE: read whole, the identity / registry / ingress / image /
         settings applied, the WHOLE template written back (a template PATCH replaces the container array).
         External = reachable from the internet: every route of the web app requires Entra sign-in + an app role
         (only /healthz is anonymous) and the MCP server requires an Entra bearer token. The CUSTOMER's control is
         Entra Conditional Access on the "SecurityInsight Management" enterprise application (require MFA,
         compliant device, named locations). Magic links (off by default) bypass Conditional Access by design;
      4b. with -JobsResourceGroup: the Jobs page's settings and, for the web identity, "Container Apps Jobs
         Contributor" on that resource group (list, start, change schedule, enable / disable the SI jobs). The jobs'
         console logs are read from the workspace with the "Log Analytics Reader" grant of step 3; with -UpdaterJobName
         also Jobs__UpdaterJob, the install's own updater job (CR5, #655 step 2; the web app's default is today's name);
      4c. with -MagicLinkKeyVaultId: "Key Vault Secrets User" on that vault for the web identity (the magic-link
         signing key; magic links stay OFF until SIWeb_MagicLinksEnabled is set on the Settings page);
      5. with -SqlAllowAzureServices: the SQL server's "Allow Azure services" rule. An environment without a virtual
         network has no fixed egress address (its outbound list is the region's shared pool), so per-IP rules cannot
         work; the better fix is a VNet-integrated environment + a private endpoint;
      6. with -GrantSql: the database users, as the CALLER (who must be the server's Entra admin), by the identities'
         client ids (no directory lookup by the server is needed):
           web identity: db_datareader + INSERT/UPDATE/DELETE on cfg.Setting and cfg.Document + INSERT/UPDATE on
                         cfg.Exemption (when it exists) + INSERT on cfg.ChangeLog (the Settings page, the documents
                         editor, exemptions, tier pins, job audit rows, magic-link nonces; nothing beyond read on
                         vuln and sidata);
           MCP identity: db_datareader only (its tools are read-only), DENIED SELECT on cfg.WebKeyRing (the web app's
                         sign-in keys).

    What it does NOT do: the Entra app registration -- that is New-SIManagementAppRegistration.ps1 (run it before this
    script for the client id, and after it with -Fqdn for the redirect URI).

.EXAMPLE
    .\Deploy-SIManagement.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -RegistryName <acr> -EnvironmentName <cae> `
        -TenantId <tenant> -SignInClientId <app-reg-client-id> -SqlServer <server>.database.windows.net -SqlDatabase <db> `
        -WorkspaceId <workspace customerId> -WorkspaceResourceId <workspace ARM id> `
        -ChatEndpoint https://<aoai>.openai.azure.com/ -ChatDeployment <deployment> -ChatResourceId <aoai ARM id> `
        -SqlAllowAzureServices -GrantSql
    Plan only. Add -Apply to make the changes.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$RegistryName,
    # the Container Apps environment, by name in -ResourceGroup. It must exist unless -CreateEnvironment is given.
    [Parameter(Mandatory)][string]$EnvironmentName,
    # create the environment when it does not exist: consumption, no virtual network, logs to Azure Monitor plus a
    # diagnostic setting (console + system logs) into -WorkspaceResourceId
    [switch]$CreateEnvironment,
    [string]$Location = 'westeurope',
    [string]$DiagnosticSettingName = 'si-environment-logs',
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    # the client id of the Entra app registration (sign-in for the web app, token audience for the MCP server)
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$SignInClientId,
    [Parameter(Mandatory)][string]$SqlServer,
    [Parameter(Mandatory)][string]$SqlDatabase,
    # the Log Analytics workspace (customerId GUID) the dashboards read; empty = the dashboards say "not configured"
    [string]$WorkspaceId = '',
    # its ARM resource id: grants "Log Analytics Reader" to both identities
    [string]$WorkspaceResourceId = '',
    # the customer's Azure OpenAI for the chat (token auth only); empty = the chat says "not configured"
    [string]$ChatEndpoint = '',
    [string]$ChatDeployment = '',
    # its ARM resource id: grants "Cognitive Services OpenAI User" to the web app's identity
    [string]$ChatResourceId = '',
    [string]$AppName = 'ca-si-management',
    [string]$IdentityName = 'uami-si-management',
    [string]$ImageName = 'si-management',
    [string]$McpAppName = 'ca-si-mcp',
    [string]$McpIdentityName = 'uami-si-mcp',
    [string]$McpImageName = 'si-management-mcp',
    [switch]$NoMcp,
    [string]$ImageTag = ('{0}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')),
    [switch]$SkipBuild,
    # the web app's size: 2 CPU / 4 GiB (owner 2026-10-18: "reduce web app to 2cpus 4 gb ram" -- 7 days of telemetry: the web
    # app used at most 0.1 CPU / 0.5 GiB of its 4 CPU / 8 GiB). Every update sets an existing install's web app to the same size
    # (setup\_shared\SI-JobSizing.ps1 Invoke-SIWebAppSize: raises a smaller one, lowers the earlier 4 CPU / 8 GiB, keeps any other
    # size the customer chose; SI_Bootstrap_WebAppCpu / SI_Bootstrap_WebAppMemory win). With the sign-in front sidecar
    # (0.25 CPU / 0.5 GiB) the app is 2.25 CPU / 4.5 GiB. Earlier: 1 CPU / 2 GiB (2026-10-11), 4 CPU / 8 GiB (2026-10-12).
    # The MCP server: -McpCpu / -McpMemory.
    [string]$Cpu = '2.0',      # the same as the update's size
    [string]$Memory = '4Gi',
    [string]$McpCpu = '0.5',
    [string]$McpMemory = '1Gi',
    # Internal = reachable only from the environment's network; External = public, protected by Entra sign-in and the
    # customer's Conditional Access (the operator's decision for Pro, 2026-10-03)
    [ValidateSet('Internal', 'External')][string]$Ingress = 'Internal',
    # the resource group of the SI engine jobs (Container Apps jobs) the Jobs page manages; empty = the page says
    # "not configured"
    [string]$JobsResourceGroup = '',
    # only jobs whose name starts with this are shown and can be changed
    [string]$JobsNamePrefix = '',
    # CR5 (#655 step 2): the install's own updater job, set on the web app as Jobs__UpdaterJob (with -JobsResourceGroup);
    # empty = not set, the web app uses today's name (caj-si-updater) -- exactly as before
    [string]$UpdaterJobName = '',
    # CR8 (framework 12.11f item 1): the web app gets START-ONLY rights on the jobs -- "Container Apps Jobs Reader" on the
    # jobs' resource group (list) and "Container Apps Jobs Operator" on each named SecurityInsight job (caj-si-*: start / stop),
    # never Jobs Contributor; its trigger changes become requests the pipeline runner applies (Jobs__ChangeMode=request).
    # Default: OFF until a fresh test install proves it -- on with this switch or SI_SECURITY_BASELINE_NEW_INSTALL=1
    # (setup\_shared\SI-SecurityBaseline.ps1). Existing installs: setup\Set-SISecurityBaseline.ps1 (Support app).
    [switch]$JobsStartOnly,
    # ARM id of the Key Vault holding the magic-link key: grants the web identity "Key Vault Secrets User"
    [string]$MagicLinkKeyVaultId = '',
    # adds the SQL server's "Allow Azure services" rule (see step 5 for why per-IP rules do not work without a VNet)
    [switch]$SqlAllowAzureServices,
    [switch]$GrantSql,
    # CR7 (framework 12.11g): put the web app behind the ONE shared sign-in front (FRAMEWORK/signin-front at the version
    # pro-management\signin-front.pin.json pins) -- step 4d, SI-ManagementSigninFront.ps1. Default OFF: the web app signs
    # users in itself exactly as before. A web app already behind the front keeps it on a re-deploy without this switch.
    [switch]$SigninFront,
    # with -SigninFront: leave the app registration's client secrets (default: deleted once the switch reads back)
    [switch]$KeepClientSecrets,
    # #852: the install's Key Vault (its name) -- the shared sign-in front's store is made with the database users (step 6b,
    # as the caller: the key signin-front-dp, the web identity's right on that key only, its schema signin, CREATE TABLE),
    # so the front 1.3.0 finds everything when the update moves the web app behind it. '' = not made here.
    [string]$SigninStoreKeyVaultName = '',
    # plan without any Azure lookup and without signing in (an existing identity / registry / app shows as a placeholder)
    [switch]$NoLookup,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

# The tenants this machine must never deploy to (another company's; the retired test tenants).
# the refused tenants: an internal list (internal\SI-RefusedTenants.ps1 -- publish strips it, so the public copy names none)
$refusedList = [IO.Path]::Combine($PSScriptRoot, 'internal', 'SI-RefusedTenants.ps1')
$refused = @(if (Test-Path -LiteralPath $refusedList) { & $refusedList })
if ($refused -contains $TenantId.ToLowerInvariant()) { throw "Tenant $TenantId is refused for SecurityInsight deployments." }

$managementRoot = Split-Path -Parent $PSScriptRoot           # ...\SecurityInsight\pro-management
$siRoot = Split-Path -Parent $managementRoot                  # ...\SecurityInsight
$catalog = Join-Path $siRoot 'config\settings.catalog.locked.json'
$image = '{0}:{1}' -f $ImageName, $ImageTag
$mcpImage = '{0}:{1}' -f $McpImageName, $ImageTag
$mode = if ($Apply) { 'APPLY' } else { 'PLAN (nothing is changed; add -Apply)' }
$script:newGrant = $false

# #521: the REST layer (setup's one sign-in, ARM, the registry build) -- no az CLI, no module
. (Join-Path $PSScriptRoot 'SI-ManagementArm.ps1')
. (Join-Path $siRoot 'setup\_shared\SI-SecurityBaseline.ps1')
$jobsStartOnly = [bool]$JobsStartOnly -or (Test-SISecurityBaselineNewInstall)
$appApi = Get-SIManagementAppApi
$rgPath = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup

function Write-Step([string]$Text) { Write-Host ''; Write-Host ('== ' + $Text) -ForegroundColor Cyan }

function Get-SIManagementLinkedConfigFiles([Parameter(Mandatory)][string]$SourceRoot) {
    # the file names under SecurityInsight\config\ that any project below -SourceRoot links (Include="..\..\..\config\X")
    $names = foreach ($p in @(Get-ChildItem -LiteralPath $SourceRoot -Recurse -Filter '*.csproj' -File)) {
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($p.FullName), 'Include="(?:\.\.[\\/])+config[\\/]([^"\\/]+)"')) { $m.Groups[1].Value }
    }
    @($names | Sort-Object -Unique)
}

function Write-SIManagementBuildStamp {
    # the build identity of -SolutionRoot (engine\_shared\SI-BuildInfo.ps1: git in a source tree, else its BUILD.json),
    # written to <Stage>\BUILD.json -- the file the Dockerfile copies and the csproj links next to the app
    param([Parameter(Mandatory)][string]$SolutionRoot, [Parameter(Mandatory)][string]$Stage)
    . ([IO.Path]::Combine($SolutionRoot, 'engine', '_shared', 'SI-BuildInfo.ps1'))
    $info = Get-SIBuildInfo -SolutionRoot $SolutionRoot
    $null = Write-SIBuildInfo -Info $info -Path (Join-Path $Stage 'BUILD.json')
    Write-Host ('  build: {0}' -f (Format-SIBuildLine $info))
    $info
}

$script:lookups = -not ($NoLookup -and -not $Apply)
function Write-Call([string]$Method, [string]$Path) {
    <# Every Azure call is printed (method + resource, never a body or a token) before it runs. #>
    Write-Host ('  {0} {1}' -f $Method.ToUpperInvariant(), ($Path -replace '^https://management\.azure\.com', '')) -ForegroundColor DarkGray
}

function Grant-Role {
    <# An Azure role assignment, made only when it is not already there (so a re-run adds nothing). #>
    param([string]$PrincipalId, [string]$Role, [string]$Scope)
    $put = '{0}/providers/Microsoft.Authorization/roleAssignments/<new guid>  ({1} for {2})' -f $Scope, $Role, $PrincipalId
    if ($PrincipalId -like '<*' -or $Scope -like '<*') { Write-Call 'PUT' $put; return }
    if ($script:lookups) {
        Write-Call 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter=principalId eq ''{1}''' -f $Scope, $PrincipalId)
        if (Test-SIRoleAssignmentPresent -ObjectId $PrincipalId -Scope $Scope -RoleDefinitionName $Role) {
            Write-Host ('  {0} on {1}: already granted' -f $Role, ($Scope -split '/')[-1]); return
        }
    }
    Write-Call 'PUT' $put
    if (-not $Apply) { return }
    $null = New-SIRoleAssignment -ObjectId $PrincipalId -Scope $Scope -RoleDefinitionName $Role -PrincipalType ServicePrincipal
    $script:newGrant = $true
}

function Get-Identity([string]$Name) {
    Write-Call 'GET' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $rgPath, $Name)
    $id = $null
    if ($script:lookups) { $id = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name $Name -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue }
    if ($id) { Write-Host ('  {0} exists -- reused' -f $Name) }
    else {
        Write-Call 'PUT' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $rgPath, $Name)
        if ($Apply) { $id = New-SIUserAssignedIdentity -ResourceGroupName $ResourceGroup -Name $Name -Location $script:location -SubscriptionId $SubscriptionId }
    }
    if ($id) { return [pscustomobject]@{ Name = $Name; Id = [string]$id.Id; ClientId = [string]$id.ClientId; PrincipalId = [string]$id.PrincipalId } }
    return [pscustomobject]@{ Name = $Name; Id = "<$Name resource id>"; ClientId = "<$Name client id>"; PrincipalId = "<$Name principal id>" }
}

function Set-ContainerApp {
    <# Creates or updates one Container App with -Ingress (internal or external). Returns the app (null in plan mode). #>
    param([string]$Name, [string]$FullImage, $Identity, [string[]]$Settings, [switch]$Sticky, [string]$Cpu = $script:Cpu, [string]$Memory = $script:Memory)
    $path = Get-SIManagementContainerAppPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
    $external = ($Ingress -eq 'External')
    Write-Call 'GET' $path
    $existing = $null
    if ($script:lookups) { $existing = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name }
    if ($existing) {
        # A Container App cannot move between environments, and its name is unique per resource group: an app of this
        # name in ANOTHER environment would otherwise be "updated in place" there, silently missing the target.
        $envOf = [string](Get-SIManagementProp $existing @('properties', 'managedEnvironmentId'))
        if (-not $envOf) { $envOf = [string](Get-SIManagementProp $existing @('properties', 'environmentId')) }
        if (-not $envOf.EndsWith('/managedEnvironments/' + $EnvironmentName, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw ('{0} already exists in environment {1}, not {2}. A Container App cannot move: delete it (the Azure portal, or DELETE {3}) and re-run.' -f $Name, ($envOf -split '/')[-1], $EnvironmentName, $path)
        }
    }
    $app = $null
    # #564 THE SECURITY ORDER: written INTERNAL first (an app that is already external and wanted external stays so); the
    # sign-in is verified on what runs; only then external, read back, and an anonymous request must be refused.
    $stageExternal = Get-SIManagementStageExternal -Existing $existing -WantExternal $external
    if (-not $existing) {
        Write-Call 'PUT' ('{0}  (api {1}: {2} ingress first, port 8080, identity, registry, settings)' -f $path, $appApi, $(if ($stageExternal) { 'external' } else { 'internal' }))
        if ($Apply) {
            $body = New-SIManagementContainerAppBody -Name $Name -Location $script:location -EnvironmentId $caeId -Image $FullImage -RegistryServer $loginServer `
                        -IdentityId $Identity.Id -External $stageExternal -Settings $Settings -Sticky:$Sticky -Cpu $Cpu -Memory $Memory -WorkloadProfileName $script:workloadProfile
            $app = Invoke-SIManagementArmWrite -Method PUT -Path $path -Body $body
        }
    } else {
        Write-Host ('  {0} exists -- updated in place (read-modify-write)' -f $Name)
        Write-Call 'PATCH' ('{0}  (api {1}: identity, registry, {2} ingress first, image, settings; the whole template)' -f $path, $appApi, $(if ($stageExternal) { 'external' } else { 'internal' }))
        if ($Apply) {
            $body = Merge-SIManagementContainerAppUpdate -App $existing -IdentityId $Identity.Id -RegistryServer $loginServer -External $stageExternal `
                        -Sticky:$Sticky -Image $FullImage -SetEnv $Settings
            if ($body) { $app = Invoke-SIManagementArmWrite -Method PATCH -Path $path -Body $body }
            else { $app = $existing }
        }
    }
    if ($app) {
        # the sign-in, verified on the app as Azure has it (read back) -- BEFORE anything is opened to the internet
        $app = Get-SIManagementContainerApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $Name
        $sign = Test-SIManagementSignInConfigured -App $app -TenantId $TenantId -SignInClientId $SignInClientId
        $isExternal = [bool](Get-SIManagementProp $app @('properties', 'configuration', 'ingress', 'external'))
        if (-not $sign.Ok) {
            # never public without a verified sign-in: an external app is closed again, and nothing is opened
            # the close's RESULT is kept: the message says what is true, never "internal" on a close that failed
            $after = 'It is kept INTERNAL.'
            if ($isExternal) { $after = Get-SIManagementClosedText -CloseError (Close-SIManagementAppIngress -Path $path) -Path $path }
            throw ('{0}: its Entra sign-in could not be verified ({1}). {2} Run the deploy again once the app is provisioned.' -f $Name, $sign.Why, $after)
        }
        Write-Host ('  {0}: Entra sign-in verified on the running app (tenant {1}, client {2})' -f $Name, $TenantId, $SignInClientId)
        if ($external -and -not $isExternal) {
            Write-Call 'PATCH' ('{0}  (ingress external -- only now that the sign-in is verified)' -f $path)
            $app = Set-SIManagementIngressExternal -Path $path -External $true
        } elseif (-not $external -and $isExternal) {
            # converge: -Ingress Internal asked, the app is external -- closed and read back (never a stop)
            Write-Call 'PATCH' ('{0}  (ingress internal, as asked)' -f $path)
            $app = Set-SIManagementIngressExternal -Path $path -External $false
        }
        if ($external) {
            $f = [string](Get-SIManagementProp $app @('properties', 'configuration', 'ingress', 'fqdn'))
            if ($f) {
                $probe = Test-SIManagementAnonymousRefused -Fqdn $f -Kind $(if ($Sticky) { 'web' } else { 'mcp' })
                if ($probe.Refused -eq $false) {
                    $closed = Get-SIManagementClosedText -CloseError (Close-SIManagementAppIngress -Path $path) -Path $path
                    throw ('{0} answered an anonymous request at {1} with HTTP {2} (no sign-in). {3} Contact Invardia support with this message.' -f $Name, $probe.Url, $probe.StatusCode, $closed)
                }
                if ($null -eq $probe.Refused) { Write-Warning ('{0}: the anonymous check of {1} could not be made yet (last answer: {2}; the address may still be coming up) -- the app stays open because the sign-in itself was verified on the app. Open {1} in a private browser window: it must ask you to sign in.' -f $Name, $probe.Url, $(if ($probe.StatusCode) { 'HTTP ' + $probe.StatusCode } else { 'none' })) }
                else { Write-Host ('  {0}: an anonymous request is refused (HTTP {1}) -- external ingress verified' -f $Name, $probe.StatusCode) }
            }
        }
    }
    return $app
}

function Get-AppFqdn($App, [string]$Name) {
    $f = [string](Get-SIManagementProp $App @('properties', 'configuration', 'ingress', 'fqdn'))
    if ($f) { return $f }
    if ($Ingress -eq 'External') { return ('{0}.<environment-domain>' -f $Name) }
    return ('{0}.internal.<environment-domain>' -f $Name)
}

Write-Host ('SecurityInsight Pro management -- deploy {0}' -f $mode) -ForegroundColor White
Write-Host ('  subscription {0} / resource group {1}' -f $SubscriptionId, $ResourceGroup)
Write-Host ('  registry {0}; environment {1}; tag {2}' -f $RegistryName, $EnvironmentName, $ImageTag)
Write-Host ('  web: app {0}, identity {1}, image {2}' -f $AppName, $IdentityName, $image)
if (-not $NoMcp) { Write-Host ('  mcp: app {0}, identity {1}, image {2}' -f $McpAppName, $McpIdentityName, $mcpImage) }
if (-not (Test-Path -LiteralPath $catalog)) { throw "The settings catalog is missing: $catalog" }

# The sign-in: setup's own REST sign-in (an existing one in this process is reused). -NoLookup plans without one.
if ($script:lookups) { $null = Connect-SIManagementRest -TenantId $TenantId -SubscriptionId $SubscriptionId }
else { Write-Host '  (-NoLookup: no sign-in, no lookup -- the plan shows placeholders)' -ForegroundColor Yellow }
$script:location = $Location
if ($script:lookups) {
    $rgObj = Get-SIResourceGroupArm -Name $ResourceGroup -SubscriptionId $SubscriptionId
    if ($rgObj -and [string]$rgObj.location) { $script:location = [string]$rgObj.location }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step ('0. The Container Apps environment {0}' -f $EnvironmentName)
$caeId = '{0}/providers/Microsoft.App/managedEnvironments/{1}' -f $rgPath, $EnvironmentName
$script:workloadProfile = ''
Write-Call 'GET' $caeId
$cae = $null
if ($script:lookups) { $cae = Invoke-SIArm -Path $caeId -ApiVersion $appApi -AllowNotFound }
if ($cae) { Write-Host '  exists -- reused' }
elseif (-not $CreateEnvironment) {
    if ($Apply -or -not $NoLookup) { throw ('Environment {0} does not exist in {1}. Create it, or add -CreateEnvironment.' -f $EnvironmentName, $ResourceGroup) }
} else {
    if (-not $WorkspaceResourceId) { throw '-CreateEnvironment needs -WorkspaceResourceId (the environment''s logs go there).' }
    # consumption workload profile, no virtual network; logs leave through Azure Monitor (the diagnostic setting below),
    # so no workspace key is ever handed to the environment
    Write-Call 'PUT' ('{0}  (api {1}: Consumption workload profile, logs to Azure Monitor)' -f $caeId, $appApi)
    Write-Host ('  diagnostic setting {0}: ContainerAppConsoleLogs + ContainerAppSystemLogs -> {1}' -f $DiagnosticSettingName, ($WorkspaceResourceId -split '/')[-1])
    Write-Call 'PUT' ('{0}/providers/Microsoft.Insights/diagnosticSettings/{1}' -f $caeId, $DiagnosticSettingName)
    if ($Apply) {
        $null = Invoke-SIArm -Method PUT -Path $caeId -ApiVersion $appApi -Body (Get-SIManagedEnvironmentBody -Location $script:location)
        $cae = Wait-SIArmResourceReady -Path $caeId -ApiVersion $appApi -TimeoutSec 1800 -PollSec 15 -What ('the Container Apps environment {0}' -f $EnvironmentName)
        $body = @{ properties = @{ workspaceId = $WorkspaceResourceId; logs = @(
                    @{ category = 'ContainerAppConsoleLogs'; enabled = $true },
                    @{ category = 'ContainerAppSystemLogs'; enabled = $true }) } }
        $null = Invoke-SIArm -Method PUT -Path ('{0}/providers/Microsoft.Insights/diagnosticSettings/{1}' -f $caeId, $DiagnosticSettingName) -ApiVersion '2021-05-01-preview' -Body $body
    }
}
if ($cae) {
    $script:workloadProfile = Get-SIManagementConsumptionProfile -Environment $cae
    if ([string]$cae.location) { $script:location = [string]$cae.location }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step '1. Build the images in the registry (the registry''s own build over ARM) from a staged, clean context'
if ($SkipBuild) { Write-Host ('  -SkipBuild: reusing tag {0}' -f $ImageTag) }
else {
    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ('si-mgmt-build-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    Write-Host ('  stage: {0}' -f $stage)
    Write-Host '    VERSION, BUILD.json, config\settings.catalog.locked.json, config\audit-actions.locked.json, pro-management\Dockerfile(.mcp), pro-management\src\** (without bin\ and obj\)'
    if ($Apply) {
        New-Item -ItemType Directory -Path (Join-Path $stage 'config') -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $stage 'pro-management') -Force | Out-Null
        Copy-Item -LiteralPath $catalog -Destination (Join-Path $stage 'config\settings.catalog.locked.json')
        # every other shipped config file a project links (the audit actions, the guard catalog, ...): read from the csproj
        # files themselves, so a newly linked file can never be missing from the image build again
        foreach ($name in @(Get-SIManagementLinkedConfigFiles -SourceRoot (Join-Path $managementRoot 'src'))) {
            if ($name -eq 'settings.catalog.locked.json') { continue }
            Copy-Item -LiteralPath (Join-Path $siRoot ('config\' + $name)) -Destination (Join-Path $stage ('config\' + $name))
        }
        # the release the web app's header + footer show (its csproj stamps VERSION into the assembly)
        Copy-Item -LiteralPath (Join-Path $siRoot 'VERSION') -Destination (Join-Path $stage 'VERSION')
        # the build this image is (BUILD.json), computed ONCE here and staged explicitly: the Dockerfile copies it and the
        # csproj links it next to the app -- the header + footer show its version ("3.0.0-rc.12"), /about its commit
        $null = Write-SIManagementBuildStamp -SolutionRoot $siRoot -Stage $stage
        Copy-Item -LiteralPath (Join-Path $managementRoot 'Dockerfile') -Destination (Join-Path $stage 'pro-management\Dockerfile')
        Copy-Item -LiteralPath (Join-Path $managementRoot 'Dockerfile.mcp') -Destination (Join-Path $stage 'pro-management\Dockerfile.mcp')
        $srcRoot = Join-Path $managementRoot 'src'
        foreach ($f in @(Get-ChildItem -LiteralPath $srcRoot -Recurse -File)) {
            $rel = $f.FullName.Substring($srcRoot.Length).TrimStart('\', '/')
            if ($rel -match '(^|[\\/])(bin|obj)[\\/]') { continue }
            $dest = Join-Path (Join-Path $stage 'pro-management\src') $rel
            $dir = Split-Path -Parent $dest
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Copy-Item -LiteralPath $f.FullName -Destination $dest
        }
    }
    $builds = @(@{ Image = $image; Dockerfile = 'pro-management/Dockerfile' })
    if (-not $NoMcp) { $builds += @{ Image = $mcpImage; Dockerfile = 'pro-management/Dockerfile.mcp' } }
    try {
        foreach ($bld in $builds) {
            Write-Call 'POST' ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}/listBuildSourceUploadUrl + upload + scheduleRun  ({2} from {3})' -f $rgPath, $RegistryName, $bld.Image, $bld.Dockerfile)
            if (-not $Apply) { continue }
            # image names are registry-relative; the stage is packed and uploaded by setup\_shared\SI-AcrBuild.ps1
            $r = Invoke-SIAcrRestBuild -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -RegistryName $RegistryName -SourcePath $stage `
                    -ImageNames @($bld.Image) -DockerFilePath $bld.Dockerfile -OnPoll { param($s) Write-Host ('    build: {0}' -f $s) -ForegroundColor DarkGray }
            if (-not $r.Ok) { throw ('The image build of {0} did not succeed (run {1}: {2}). The run''s log is in the registry (Services > Tasks > Runs).' -f $bld.Image, $r.RunId, $r.Status) }
            Write-Host ('  built {0} (run {1}, {2} s)' -f $bld.Image, $r.RunId, $r.Seconds)
        }
    } finally {
        # a scanner may still hold a file of the stage for a moment: a leftover temp folder is not worth failing a deploy
        if ($Apply -and (Test-Path -LiteralPath $stage)) {
            Start-Sleep -Seconds 2
            Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $stage) { Write-Warning ('Could not remove the build stage {0}; delete it later.' -f $stage) }
        }
    }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step '2. User-assigned managed identities + AcrPull'
$webId = Get-Identity $IdentityName
$mcpId = if ($NoMcp) { $null } else { Get-Identity $McpIdentityName }
Write-Call 'GET' ('{0}/providers/Microsoft.ContainerRegistry/registries/{1}' -f $rgPath, $RegistryName)
$registry = $null
if ($script:lookups) { $registry = Get-SIContainerRegistry -ResourceGroupName $ResourceGroup -Name $RegistryName -SubscriptionId $SubscriptionId }
$registryId = if ($registry) { [string]$registry.id } else { '<registry resource id>' }
$loginServer = if ($registry -and [string]$registry.loginServer) { [string]$registry.loginServer } else { ('{0}.azurecr.io' -f $RegistryName) }
$identities = @($webId) + @($(if ($mcpId) { $mcpId }))
foreach ($i in $identities) { Grant-Role -PrincipalId $i.PrincipalId -Role 'AcrPull' -Scope $registryId }

# ---------------------------------------------------------------------------------------------------------------
Write-Step '3. Data access roles (Log Analytics Reader; Cognitive Services OpenAI User)'
if ($WorkspaceResourceId) { foreach ($i in $identities) { Grant-Role -PrincipalId $i.PrincipalId -Role 'Log Analytics Reader' -Scope $WorkspaceResourceId } }
else { Write-Host '  -WorkspaceResourceId not given: grant "Log Analytics Reader" on the workspace to both identities yourself.' -ForegroundColor Yellow }
if ($ChatResourceId) { Grant-Role -PrincipalId $webId.PrincipalId -Role 'Cognitive Services OpenAI User' -Scope $ChatResourceId }
elseif ($ChatEndpoint) { Write-Host '  -ChatResourceId not given: grant "Cognitive Services OpenAI User" on the Azure OpenAI resource to the web identity yourself.' -ForegroundColor Yellow }
if ($Apply -and $script:newGrant) {
    # a fresh AcrPull is not seen by the registry at once; the first image pull would fail without the wait
    Write-Host '  new role assignments: waiting 60 s for them to propagate'
    Start-Sleep -Seconds 60
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step ('4. Container Apps: {0} ingress, the identity, the app settings' -f $Ingress.ToLowerInvariant())
if ($Ingress -eq 'External') {
    Write-Host '  EXTERNAL ingress: the apps are reachable from the internet. Protection = Entra sign-in + app roles on every route' -ForegroundColor Yellow
    Write-Host '  (web) and an Entra bearer token (MCP). Add the customer''s Conditional Access policy on the enterprise application' -ForegroundColor Yellow
    Write-Host '  "SecurityInsight" (earlier "SecurityInsight Management") (MFA, compliant device, named locations) before people use it.' -ForegroundColor Yellow
}
function New-Settings($Identity, [switch]$Web) {
    $s = @(
        'AzureAd__Instance=https://login.microsoftonline.com/',
        ('AzureAd__TenantId={0}' -f $TenantId),
        ('AzureAd__ClientId={0}' -f $SignInClientId),
        'Identity__Mode=ManagedIdentity',
        ('Identity__ManagedIdentityClientId={0}' -f $Identity.ClientId),
        ('Estate__SqlServer={0}' -f $SqlServer),
        ('Estate__SqlDatabase={0}' -f $SqlDatabase),
        ('AZURE_CLIENT_ID={0}' -f $Identity.ClientId)
    )
    if ($Web) { $s += 'AzureAd__CallbackPath=/signin-oidc' }
    if ($WorkspaceId) { $s += ('Estate__WorkspaceId={0}' -f $WorkspaceId) }
    if ($Web -and $ChatEndpoint -and $ChatDeployment) { $s += @(('Chat__Endpoint={0}' -f $ChatEndpoint), ('Chat__Deployment={0}' -f $ChatDeployment)) }
    if ($Web -and $JobsResourceGroup) {
        $s += @(('Jobs__SubscriptionId={0}' -f $SubscriptionId), ('Jobs__ResourceGroup={0}' -f $JobsResourceGroup))
        if ($JobsNamePrefix) { $s += ('Jobs__NamePrefix={0}' -f $JobsNamePrefix) }
        if ("$UpdaterJobName".Trim()) { $s += ('Jobs__UpdaterJob={0}' -f "$UpdaterJobName".Trim()) }
        if ($jobsStartOnly) { $s += 'Jobs__ChangeMode=request' }
    }
    return $s
}
$webApp = Set-ContainerApp -Name $AppName -FullImage ('{0}/{1}' -f $loginServer, $image) -Identity $webId -Settings (New-Settings $webId -Web) -Sticky -Cpu $Cpu -Memory $Memory
$fqdn = Get-AppFqdn $webApp $AppName
$mcpApp = $null; $mcpFqdn = $null
if (-not $NoMcp) {
    $mcpApp = Set-ContainerApp -Name $McpAppName -FullImage ('{0}/{1}' -f $loginServer, $mcpImage) -Identity $mcpId -Settings (New-Settings $mcpId) -Cpu $McpCpu -Memory $McpMemory
    $mcpFqdn = Get-AppFqdn $mcpApp $McpAppName
}

# #443 (a): the "Set up mail" click flow's sign-in credential -- turned on ONLY when the app registration's federated
# credential for the web identity was read back (Set-SIManagementSignInCredential.ps1; New-SIManagementAppRegistration.ps1
# -WebIdentityPrincipalId creates it). A first install has none yet: the guided install runs the guard again after it.
Write-Step '4a. The web app''s sign-in credential for Set up mail (only with the federated credential)'
if ($Apply -and $webApp) {
    & (Join-Path $PSScriptRoot 'Set-SIManagementSignInCredential.ps1') -TenantId $TenantId -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup `
        -SignInClientId $SignInClientId -AppName $AppName -IdentityName $IdentityName -Apply | Out-Null
} else { Write-Host '  (plan) Set-SIManagementSignInCredential.ps1 decides after the deploy' }

# CR7 (framework 12.11g): the ONE shared sign-in front -- only with -SigninFront (default OFF: nothing of this runs)
Write-Step '4d. The shared sign-in front (only with -SigninFront)'
if ($SigninFront) {
    . (Join-Path $PSScriptRoot 'SI-ManagementSigninFront.ps1')
    if ($script:lookups -and ($Apply -or $webApp)) {
        $null = Invoke-SISigninFrontCutover -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TenantId $TenantId -SignInClientId $SignInClientId `
                    -RegistryName $RegistryName -AppName $AppName -IdentityName $IdentityName -SIRoot $siRoot -KeepClientSecrets:$KeepClientSecrets -Apply:$Apply `
                    -KeyVaultName $SigninStoreKeyVaultName -SqlServer $SqlServer -SqlDatabase $SqlDatabase `
                    -Log { param($m) Write-Host ('  ' + $m) }
    } else {
        $pinF = Get-SISigninFrontPin -SIRoot $siRoot
        $srcF = Resolve-SISigninFrontSource -SIRoot $siRoot -Pin $pinF
        Write-Host ('  (plan) {0} {1}: {2}' -f $pinF.component, $pinF.version, $(if ($srcF.Ok) { 'source at ' + $srcF.Path } else { 'NOT usable here -- ' + $srcF.Why }))
        Write-Host '  (plan) federated credential for the web identity -> the front''s image built in the registry -> the front as the second container, the web app on 127.0.0.1 -> read back -> Easy Auth off -> the old client secrets deleted'
    }
} else { Write-Host '  -SigninFront not given: the web app signs users in itself (unchanged).' }

# ---------------------------------------------------------------------------------------------------------------
Write-Step $(if ($jobsStartOnly) { '4b. The Jobs page: START-ONLY (Jobs Reader on the jobs'' resource group, Jobs Operator on each named job)' } else { '4b. The Jobs page (Container Apps Jobs Contributor on the jobs'' resource group)' })
if ($JobsResourceGroup) {
    $jobsScope = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $JobsResourceGroup
    if ($jobsStartOnly) {
        # CR8: list the jobs, start / stop the named ones -- never change one (a trigger change is a request the pipeline
        # runner applies). A job an update adds later gets its Operator role from the security cut-over / the next setup run.
        Grant-Role -PrincipalId $webId.PrincipalId -Role 'Container Apps Jobs Reader' -Scope $jobsScope
        $named = @()
        if ($script:lookups) { $named = @(Get-SIArmResource -ResourceType 'Microsoft.App/jobs' -ResourceGroupName $JobsResourceGroup -SubscriptionId $SubscriptionId | Where-Object { [string]$_.Name -like 'caj-si-*' }) }
        if (-not $named.Count) { Write-Host '  (no caj-si-* job found yet -- run this again after the jobs exist, or the security cut-over adds them)' -ForegroundColor Yellow }
        foreach ($j in $named) { Grant-Role -PrincipalId $webId.PrincipalId -Role 'Container Apps Jobs Operator' -Scope ([string]$j.Id) }
    }
    else { Grant-Role -PrincipalId $webId.PrincipalId -Role 'Container Apps Jobs Contributor' -Scope $jobsScope }
} else { Write-Host '  -JobsResourceGroup not given: the Jobs page says "not configured".' -ForegroundColor Yellow }

Write-Step '4c. The magic-link key (Key Vault Secrets User)'
if ($MagicLinkKeyVaultId) { Grant-Role -PrincipalId $webId.PrincipalId -Role 'Key Vault Secrets User' -Scope $MagicLinkKeyVaultId }
else { Write-Host '  -MagicLinkKeyVaultId not given: magic links cannot be enabled (they are off by default).' }

Write-Step '5. SQL server firewall for the apps'' outbound addresses'
$sqlName = ($SqlServer -split '\.')[0]
# An environment WITHOUT a virtual network has no fixed egress address: an app's `outboundIpAddresses` is the region's
# whole shared pool (300+ addresses), so per-IP firewall rules are both unworkable and no narrower in effect. The
# choices are a VNet-integrated environment + a private endpoint (preferred), or the server's "Allow Azure services"
# rule -- which still requires an Entra token the database accepts, but admits connections from any Azure address.
if ($SqlAllowAzureServices) {
    Write-Host '  "Allow Azure services" (AllowAllWindowsAzureIps, 0.0.0.0) -- prefer a VNet environment + private endpoint where possible' -ForegroundColor Yellow
    Write-Call 'PUT' ('{0}/providers/Microsoft.Sql/servers/{1}/firewallRules/AllowAllWindowsAzureIps' -f $rgPath, $sqlName)
    if ($Apply) { $null = Set-SISqlFirewallRule -ResourceGroupName $ResourceGroup -ServerName $sqlName -Name 'AllowAllWindowsAzureIps' -StartIpAddress '0.0.0.0' -EndIpAddress '0.0.0.0' -SubscriptionId $SubscriptionId }
} else { Write-Host '  -SqlAllowAzureServices not given: the apps reach the server only if its network rules already allow them.' -ForegroundColor Yellow }

# ---------------------------------------------------------------------------------------------------------------
Write-Step '6. Database users for the identities (run as the caller -- the server''s Entra admin)'
# The grants (one list, shared with the product updater, which re-applies them after a release's schema): SI-ManagementGrants.ps1
. (Join-Path $PSScriptRoot 'SI-ManagementGrants.ps1')
function Get-UserSql($Identity, [switch]$Writer) { Get-SIManagementUserSql -Identity $Identity -Writer:$Writer }
$batches = @(Get-UserSql $webId -Writer)
if ($mcpId) { $batches += (Get-UserSql $mcpId) }
foreach ($b in $batches) { Write-Host (($b -split "`n" | ForEach-Object { '    ' + $_.TrimEnd() }) -join "`n") -ForegroundColor DarkGray }
if ($GrantSql -and $Apply) {
    # the caller's Azure SQL token: a guided install hands its own sign-in in ($global:SI_InstallTokenProvider, asked
    # first by Get-SIManagementToken); otherwise setup's own sign-in. Never az.
    # opened with a bounded retry on "Login failed" / 40615 only (a new token each time): the firewall rule above and the
    # server's administrator may have changed a moment ago
    $cn = Open-SISqlConnectionRetry -Server $SqlServer -Database $SqlDatabase -Token { param([bool]$Fresh) Get-SIManagementToken -Resource 'https://database.windows.net/' }
    try {
        foreach ($b in $batches) { $cmd = $cn.CreateCommand(); $cmd.CommandText = $b; [void]$cmd.ExecuteNonQuery() }
        Write-Host ('  {0} user(s) granted' -f $batches.Count)
    } finally { $cn.Dispose() }
} elseif (-not $GrantSql) { Write-Host '  -GrantSql not given: run the T-SQL above as the server''s Entra admin.' -ForegroundColor Yellow }

# #852: the shared sign-in front's store, made as the caller with the database users -- a new install has everything the
# front 1.3.0 needs before the update moves the web app behind it (the update's step 9g then finds nothing missing)
Write-Step '6b. The sign-in front''s store (only with -SigninStoreKeyVaultName)'
if ("$SigninStoreKeyVaultName".Trim() -and $GrantSql -and $Apply) {
    . (Join-Path $PSScriptRoot 'SI-ManagementSigninFront.ps1')
    $ss = Invoke-SISigninFrontStoreAsCaller -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -KeyVaultName "$SigninStoreKeyVaultName".Trim() `
              -SqlServer $SqlServer -SqlDatabase $SqlDatabase -Identity ([pscustomobject]@{ ClientId = [string]$webId.ClientId; PrincipalId = [string]$webId.PrincipalId; Name = $IdentityName }) -Apply
    foreach ($l in @($ss.Lines)) { Write-Host ('  ' + $l) }
    # never stops the install: the web app signs users in itself until the update moves it behind the front, and the
    # update's step 9g (or setup\Set-SISigninFront.ps1 -Apply) makes what is missing
    if (-not $ss.Ok) { Write-Warning ('The sign-in front''s store was not made: {0}. The update makes it when it can; else run setup\Set-SISigninFront.ps1 -Apply.' -f $ss.Why) }
} elseif ("$SigninStoreKeyVaultName".Trim()) { Write-Host ('  (plan) the key signin-front-dp in {0}, the web identity''s right on that key only, its schema signin and CREATE TABLE -- made with -GrantSql -Apply' -f $SigninStoreKeyVaultName) }
else { Write-Host '  -SigninStoreKeyVaultName not given: the update makes the store when it can (step 9g).' }

# ---------------------------------------------------------------------------------------------------------------
Write-Step 'The Entra app registration (New-SIManagementAppRegistration.ps1)'
Write-Host ('  Register the web app''s redirect URI on client id {0}:' -f $SignInClientId)
Write-Host ('    .\New-SIManagementAppRegistration.ps1 -TenantId {0} -Fqdn {1} -Apply' -f $TenantId, $fqdn)
if (-not $NoMcp) { Write-Host ('  MCP clients ask for a token for api://{0}/.default and need the Admin or Viewer app role.' -f $SignInClientId) }

Write-Host ''
if ($Apply) {
    Write-Host ('Done. Web: https://{0}' -f $fqdn) -ForegroundColor Green
    if ($mcpFqdn) { Write-Host ('      MCP: https://{0}/mcp' -f $mcpFqdn) -ForegroundColor Green }
    if ($Ingress -eq 'External') { Write-Host '  (external ingress: public, Entra sign-in on every route -- add Conditional Access on the enterprise app)' }
    else { Write-Host '  (internal ingress: reachable only from the environment''s network)' }
}
else { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply to make these changes.' -ForegroundColor Yellow }

[pscustomobject]@{
    WebFqdn = $fqdn; McpFqdn = $mcpFqdn
    WebIdentity = $webId; McpIdentity = $mcpId
}
