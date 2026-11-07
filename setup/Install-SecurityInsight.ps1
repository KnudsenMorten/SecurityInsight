<#
.SYNOPSIS
    Installs SecurityInsight with ONE command: every setting is a parameter -- unattended, step by step, with the status
    of every step reported as it happens.

.DESCRIPTION
    Runs in Azure Cloud Shell (PowerShell 7) as the person signed in there, and on Windows PowerShell 7 / 5.1.

    Every setting of the install is a parameter of this command (one per question of the guided install; what you leave
    out keeps its default), so a whole install is one command line with your values. No licence is needed to install:
    the whole environment is deployed -- engine jobs, database, web app and updater -- with the paid features off. You
    then sign in to the web app and add the SecurityInsight Pro licence there; nothing else is run again.

      1. Checks first, changes nothing: the sign-in, the tenant and subscription, your permissions, the resource
         providers, that the names are free and that the region accepts the database.
      2. Installs, one step at a time, with the product's own proven setup scripts: resource group, workspace, data
         collection endpoint, storage, Key Vault, the container registry and image, the Container Apps environment,
         SecurityInsight's managed identity and its grants, the engine jobs, the database, its tables, templates and
         settings, the web app and the updater -- then the Invardia Support access, the first run and a health check.
      3. Reports every step to -Reporter as it starts and ends. Nothing secret is ever reported.

    The answers are kept in the install's state folder, so the same install continues with -Resume alone.

    What your account cannot grant (read access outside the resource group, the read-only API permissions, support
    access) does not stop the install: the step ends as a warning with the exact command for the person who can, and
    the install completes. Only a problem nothing can work around stops it -- run the same command again with -Resume
    and it continues from that step.

    The keys a feature needs (Azure OpenAI, Shodan, the SMTP password) are never parameters. When the feature is on you
    are asked for them here, and they go straight to the install's Key Vault; without a console they are left for later,
    with the command to add them.

.PARAMETER TenantId
    The tenant SecurityInsight assesses (GUID). Required (with -SubscriptionId); every other setting has a default.
.PARAMETER SubscriptionId
    The subscription for SecurityInsight's own resources (GUID). Required.
.PARAMETER Location
    The Azure region (default westeurope).
.PARAMETER ResourceGroup
    The resource group, created when it does not exist (default rg-si; an install that already runs keeps its own).
.PARAMETER Owner
    The resource group's 'owner' tag: a team or mailbox (default empty).
.PARAMETER Hosting
    Where SecurityInsight runs: container (Azure Container Apps jobs; the only choice).
.PARAMETER ViaSupportApp
    Invardia staff only: the same install, run inside a Connect-InvardiaSupport session for this tenant -- it signs in with
    the session (no browser, no person), so the web app's administrators come from -WebAppAdmins. Refused outside such a
    session or for another tenant.
.PARAMETER WorkspaceMode
    new (default: a dedicated Log Analytics workspace) or existing (with -WorkspaceId).
.PARAMETER WorkspaceName
    The new workspace's name (default log-si).
.PARAMETER WorkspaceId
    With -WorkspaceMode existing: the workspace's resource id.
.PARAMETER SecurityWorkspaceId
    The Microsoft Sentinel / Defender workspace (resource id, optional) Risk Analysis reads.
.PARAMETER CollectionScope
    What SecurityInsight reads in Azure: subscription (default), managementGroup (with -ManagementGroupId) or tenantRoot.
.PARAMETER ManagementGroupId
    The management group, with -CollectionScope managementGroup.
.PARAMETER AiClassification
    Switch: AI classification and summaries with your own Azure OpenAI (-OpenAiEndpoint, -OpenAiDeployment; the key is
    asked for in the shell).
.PARAMETER OpenAiEndpoint
    With -AiClassification: https://<name>.openai.azure.com/
.PARAMETER OpenAiDeployment
    With -AiClassification: the deployment name.
.PARAMETER Shodan
    Switch: Shodan enrichment of public IP addresses (the key is asked for in the shell).
.PARAMETER RunHourUtc
    The daily run's UTC hour, 0-20 (default 4).
.PARAMETER PipelineStartTime
    HH:mm the daily pipeline starts (default 19:00 in the region's local time).
.PARAMETER PipelineTimeZone
    The time zone of -PipelineStartTime, e.g. Europe/Copenhagen (default: this machine's).
.PARAMETER MailMode
    sharedMailbox (default), smtp or none.
.PARAMETER MailFrom
    With sharedMailbox: the mailbox SecurityInsight sends as (default SecurityInsight@<your sign-in domain>).
.PARAMETER MailboxCreate
    With sharedMailbox: create the mailbox when it does not exist ($true, the default; -MailboxCreate $false = it must exist).
.PARAMETER MailTo
    Who receives the reports (default: you). A list, or one text with commas.
.PARAMETER SmtpServer
    With -MailMode smtp: the SMTP server.
.PARAMETER SmtpPort
    With -MailMode smtp: the port (default 587).
.PARAMETER SmtpUser
    With -MailMode smtp: the user (empty = anonymous relay; the password is asked for in the shell).
.PARAMETER SmtpFrom
    With -MailMode smtp: the sender address.
.PARAMETER SqlLocation
    The database's region (default swedencentral).
.PARAMETER SqlAdminGroupId
    The Entra group (object id) that administers the database (default: you).
.PARAMETER WebApp
    Install the web app ($true, the default; -WebApp $false = no web app).
.PARAMETER WebAppAccess
    external (default: from the internet behind Entra sign-in) or internal (from your network only).
.PARAMETER WebAppAdmins
    The web app's administrators (UPNs). Required when the install runs as an application.
.PARAMETER AssetTaggingWrites
    Switch: grant asset tagging the rights to write tags (writing is still switched on in the web app).
.PARAMETER UpdateRing
    The release ring this install follows: 1, 2 or 3 (default 3, broad). Recorded at install, also without a licence.
.PARAMETER ServiceNowUrl
    https://<instance>.service-now.com (optional).
.PARAMETER PrivateNetwork
    Switch: SecurityInsight in a virtual network only, with private endpoints (give -VnetId, or -VnetAddressPrefix for its
    own network).
.PARAMETER VnetId
    With -PrivateNetwork: your virtual network's resource id (same region; Network Contributor on it).
.PARAMETER VnetAddressPrefix
    With -PrivateNetwork and no -VnetId: a free address range for SecurityInsight's own network, e.g. 10.0.24.0/24.
.PARAMETER VnetName
    The name of SecurityInsight's own network (default vnet-si).
.PARAMETER AppsSubnetName
    The container environment's subnet (default snet-si-apps; at least /27).
.PARAMETER AppsSubnetPrefix
    Its address range, only when the subnet is created.
.PARAMETER EndpointsSubnetName
    The private endpoints' subnet (default snet-si-endpoints; a /28 is enough).
.PARAMETER EndpointsSubnetPrefix
    Its address range, only when the subnet is created.
.PARAMETER PrivateDnsZonesResourceGroupId
    The resource group (resource id) of your central private DNS zones (optional: used, never written to).
.PARAMETER HubVnetId
    Your hub virtual network's resource id (optional): makes the network hand-off list exact.
.PARAMETER LinkZonesToHub
    Switch: SecurityInsight links its web app's DNS zone to the hub itself (needs Network Contributor on the hub).
.PARAMETER PeerToHub
    Switch: SecurityInsight peers its network with the hub in both directions (needs Network Contributor on both).
.PARAMETER ReturnRouteRanges
    With -HubVnetId: the address ranges your people browse from, e.g. '10.0.0.0/16,10.2.0.0/16' (optional). With
    -ReturnRouteNextHop, SecurityInsight's own network gets the route table rt-si on its apps subnet (each range -> your
    firewall) so replies find their way back; on your own network the route is on the network hand-off list.
.PARAMETER ReturnRouteNextHop
    With -ReturnRouteRanges: your hub firewall's private IP, e.g. 10.1.0.4 (the next hop of the return route).
.PARAMETER CustomerManagedKeys
    Switch: encrypt the database, storage and (with -CmkLogAnalytics) Log Analytics with your own key.
.PARAMETER CmkKeyVaultId
    The Key Vault (resource id) that holds the key (default: SecurityInsight's own).
.PARAMETER CmkKeyName
    The key's name (default si-data).
.PARAMETER CmkLogAnalytics
    off (default), cluster-existing (with -LogAnalyticsClusterId) or cluster-new.
.PARAMETER LogAnalyticsClusterId
    With -CmkLogAnalytics cluster-existing: your Log Analytics cluster's resource id.
.PARAMETER SupportAppId
    The Invardia Support app's client id in your tenant (optional; empty = no support access).
.PARAMETER SupportAccess
    troubleshoot (default) or setup.
.PARAMETER InstallId
    The install's name (default securityinsight): its state folder ~/clouddrive/invardia/<installId> keeps the answers,
    so the install continues with -Resume alone.
.PARAMETER ConfigPath
    Kept for compatibility only: a file with the answers, keyed as in setup\install-parameters.json. A parameter given
    wins over it. Not needed: every setting is a parameter.
.PARAMETER LicencePath
    Optional, not needed: without it the whole environment is installed with the paid features off; add the licence in
    the web app afterwards.
.PARAMETER Reporter
    { param($event) ... } -- called at the start and end of every step. The event: installId, seq, step {id, title},
    state (started | ok | warning | failed | skipped | completed), at, durationMs, message, action {text, command},
    detail (at most 8 KB); 'completed' also carries outputs.
.PARAMETER PreflightOnly
    Run the checks only. Nothing is created, changed or written.
.PARAMETER Resume
    Continue an install that stopped: the steps already done are skipped, with the answers of its first run (a parameter
    given now changes that one answer).
.PARAMETER StatePath
    The folder for the install's state file. Default: ~/clouddrive/invardia/<installId> (kept by Cloud Shell).

.OUTPUTS
    Exit code: 0 installed (warnings included), 1 a step failed, 2 a check failed, 3 the settings are not valid.

.EXAMPLE
    Invoke-WebRequest https://github.com/KnudsenMorten/SecurityInsight/releases/latest/download/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # the install as a person runs it, in two lines: line 1 downloads the small launcher (SecurityInsight Pro and the trial:
    # from https://invardia.com/support/si/Install-SecurityInsight.ps1), line 2 runs it; it downloads the release, checks it
    # and runs THIS installer from it with the same parameters. Every other setting has its default.
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # the same quickest install, run from an unpacked release: every other setting has its default
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -TenantId '00000000-0000-0000-0000-000000000001' -SubscriptionId '00000000-0000-0000-0000-000000000002' -Location 'westeurope' -MailTo 'secops@contoso.com' -PrivateNetwork -VnetId '/subscriptions/00000000-0000-0000-0000-000000000004/resourceGroups/rg-network-spoke/providers/Microsoft.Network/virtualNetworks/vnet-spoke-security' -AppsSubnetName 'snet-si-apps' -AppsSubnetPrefix '10.0.24.0/27' -EndpointsSubnetName 'snet-si-endpoints' -EndpointsSubnetPrefix '10.0.24.32/28' -HubVnetId '/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/rg-network-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' -WebAppAccess internal
    # a private-network install as ONE command: in your existing virtual network, the web app reachable from your network
    # only. No licence on the line: SecurityInsight Pro deploys everything and runs nothing until the licence is assigned
    # to the installation; then it takes its licence and install key and starts by itself.
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -Resume
    # continue an install that stopped, with the answers of its first run
.EXAMPLE
    ./setup/Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -PreflightOnly
    # the checks only: nothing is created, changed or written
.EXAMPLE
    Import-Module ./setup/Install-SecurityInsight.psd1
    Install-SecurityInsight -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Reporter { param($e) $e | ConvertTo-Json -Compress -Depth 6 } -StatePath ./state
    # the same install as a command; the exit code is in $LASTEXITCODE

.LINK
    https://invardia.com/docs/si/scripts/Install-SecurityInsight/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Back-compat only (Invardia's bootstrap): a file with the answers. A parameter given below wins over it.
    [string]$ConfigPath,
    # EVERY answer is a parameter (owner 2026-11-02: one command line, no answer file): one per key of
    # setup\install-parameters.json, named as the key in PascalCase. The script writes them as config.json in the install's
    # state folder itself, so -Resume alone finds them again. bool answers: default false = [switch], default true = [bool].
    # The one secret key (installKey) is never a parameter: it never belongs on a command line.
    [string]$TenantId,
    [string]$SubscriptionId,
    [string]$Location,
    [string]$ResourceGroup,
    [string]$Owner,
    [ValidateSet('container')][string]$Hosting,
    [ValidateSet('new', 'existing')][string]$WorkspaceMode,
    [string]$WorkspaceName,
    [string]$WorkspaceId,
    [string]$SecurityWorkspaceId,
    [ValidateSet('subscription', 'managementGroup', 'tenantRoot')][string]$CollectionScope,
    [string]$ManagementGroupId,
    [switch]$AiClassification,
    [string]$OpenAiEndpoint,
    [string]$OpenAiDeployment,
    [switch]$Shodan,
    [ValidateRange(0, 20)][int]$RunHourUtc,
    [string]$PipelineStartTime,
    [string]$PipelineTimeZone,
    [ValidateSet('sharedMailbox', 'smtp', 'none')][string]$MailMode,
    [string]$MailFrom,
    [bool]$MailboxCreate,
    [string[]]$MailTo,
    [string]$SmtpServer,
    [ValidateRange(1, 65535)][int]$SmtpPort,
    [string]$SmtpUser,
    [string]$SmtpFrom,
    [string]$SqlLocation,
    [string]$SqlAdminGroupId,
    [bool]$WebApp,
    [ValidateSet('external', 'internal')][string]$WebAppAccess,
    [string[]]$WebAppAdmins,
    [switch]$AssetTaggingWrites,
    [ValidateSet(1, 2, 3)][int]$UpdateRing,
    [string]$ServiceNowUrl,
    [switch]$PrivateNetwork,
    [string]$VnetId,
    [string]$VnetAddressPrefix,
    [string]$VnetName,
    [string]$AppsSubnetName,
    [string]$AppsSubnetPrefix,
    [string]$EndpointsSubnetName,
    [string]$EndpointsSubnetPrefix,
    [string]$PrivateDnsZonesResourceGroupId,
    [string]$HubVnetId,
    [switch]$LinkZonesToHub,
    [switch]$PeerToHub,
    [string]$ReturnRouteRanges,
    [string]$ReturnRouteNextHop,
    [switch]$CustomerManagedKeys,
    [string]$CmkKeyVaultId,
    [string]$CmkKeyName,
    [ValidateSet('off', 'cluster-existing', 'cluster-new')][string]$CmkLogAnalytics,
    [string]$LogAnalyticsClusterId,
    [string]$SupportAppId,
    [ValidateSet('troubleshoot', 'setup')][string]$SupportAccess,
    # Invardia staff: run inside a Connect-InvardiaSupport session (the existing support-session sign-in, Invardia DESIGN ch 8)
    [switch]$ViaSupportApp,
    [string]$InstallId = 'securityinsight',
    [string]$LicencePath,
    [scriptblock]$Reporter,
    [switch]$PreflightOnly,
    [switch]$Resume,
    [string]$StatePath,
    # Tests only: replacements for the calls that leave this process (Az, AzCli, Graph, Sql, Token, Script, ...).
    [Parameter(DontShow)][System.Collections.IDictionary]$Seams,
    # Tests only: where the install's config file is written (default: config\SecurityInsight.custom.ps1 of this copy).
    [Parameter(DontShow)][string]$SIConfigPath
)

# THE EDITION STAMP (framework INSTALL-1): 'community' in the repository, the package and the GitHub copy; the copy SI hands to
# Invardia for https://invardia.com/support/si/ says 'pro'. One constant line -- nothing else in the file differs.
$siEditionStamp = 'community'
#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Install-SecurityInsight' -Quiet:([bool]$PSBoundParameters.ContainsKey('Seams'))
if ($WhatIfPreference) { $PreflightOnly = [switch]$true }   # -WhatIf = the checks only: nothing is created, changed or written
try {
$ErrorActionPreference = 'Stop'
# PowerShell hands a script parameter "~/x.json" over as the literal text; .NET then reads "<cwd>/~/x.json" (found on the
# first live install, 2026-10-04, Cloud Shell). Resolve ~ and relative paths against PowerShell's own location here.
foreach ($pn in 'ConfigPath', 'LicencePath', 'StatePath') {
    $pv = Get-Variable -Name $pn -ValueOnly
    if ("$pv".Trim()) { Set-Variable -Name $pn -Value $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("$pv".Trim()) }
}
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstall.ps1'))
# The database and web app steps: in BOTH versions (owner 2026-10-18)
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstallData.ps1'))
# The paid steps (the licence, the v2.2 CMDB migration) ship only in the Pro package.
$proSteps = [IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-GuidedInstallPro.ps1')
if (Test-Path -LiteralPath $proSteps) { . $proSteps }

if ($ViaSupportApp) {
    $supState = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
    if (-not $supState) { Write-Host 'With -ViaSupportApp, run the install inside a Connect-InvardiaSupport session for this tenant.' -ForegroundColor Red; exit 3 }
    if ("$TenantId".Trim() -and "$($supState.TenantId)".Trim() -ne "$TenantId".Trim()) { Write-Host ('The support session is for tenant {0}, not for -TenantId {1}: connect the session to this tenant first.' -f $supState.TenantId, $TenantId) -ForegroundColor Red; exit 3 }
}
# Every answer given as a parameter is written as config.json in the state folder (a given parameter wins over -ConfigPath
# and over the answers of an earlier run); -ConfigPath alone is used as it is.
$direct = Resolve-SIInstallDirectConfig -Bound $PSBoundParameters -InstallId $InstallId -StatePath $StatePath -PreflightOnly:$PreflightOnly -Resume:$Resume `
    -ConfigPath $ConfigPath -SpecPath ([IO.Path]::Combine($siRoot, 'setup', 'install-parameters.json'))
if (-not $direct.Ok) { Write-Host $direct.Message -ForegroundColor Red; exit 3 }
$ConfigPath = $direct.ConfigPath
if ($direct.Message) { Write-Host $direct.Message }
# a bundle's install key (from a -ConfigPath file merged with parameters) stays in memory: never in the state folder's copy
$keyArg = @{}; if ($direct.InstallKey) { $keyArg.InstallKey = $direct.InstallKey }

$code = Invoke-SIGuidedInstall -SIRoot $siRoot -ConfigPath $ConfigPath -LicencePath $LicencePath -Reporter $Reporter `
    -PreflightOnly:$PreflightOnly -Resume:$Resume -StatePath $StatePath -Seams $Seams -SIConfigPath $SIConfigPath -Edition $siEditionStamp @keyArg
$keyArg = $null; $direct = $null
exit ([int]$code)
} finally { Stop-SIScriptRun -Run $siRun }
