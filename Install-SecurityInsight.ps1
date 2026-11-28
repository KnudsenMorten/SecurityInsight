<#
.SYNOPSIS
    Installs SecurityInsight with two lines: line 1 downloads this one small file, line 2 runs it with every setting as a
    parameter. It downloads the SecurityInsight package, checks it and runs its installer with your parameters.

.DESCRIPTION
    The ONE file a person downloads to install SecurityInsight (framework INSTALL-1). Runs in Azure Cloud Shell
    (PowerShell 7) and in PowerShell 7 or Windows PowerShell 5.1 on Windows. It needs no PowerShell module.

    The edition comes with this file, never with a parameter. The copy in the public SecurityInsight repository (and on its
    GitHub releases) installs SecurityInsight Community; the copy Invardia hands out at https://invardia.com/support/si/
    installs SecurityInsight Pro. Both copies take the SAME steps and install the release Invardia has signed for your
    update ring -- never a newer one; only where the package is downloaded from differs:

      1. Signs you in to Azure for -TenantId: in Azure Cloud Shell with no prompt, on a workstation in your browser (the
         same sign-in the installer uses; no device code). The installer started in step 5 takes this sign-in over, so you
         sign in ONCE.
      2. Asks Invardia for the release of your update ring (-UpdateRing; without it ring 3). Pro: the SecurityInsight Pro
         package, with that sign-in (Invardia hands it out only to a signed-in admin of a tenant that has an Invardia
         environment with SecurityInsight; no licence is needed: the install deploys with every job parked until the licence
         is assigned). Community: the signed Community release of the ring (no account needed). A refusal stops here with
         Invardia's reason (exit 3); there is no other source.
      3. Checks Invardia's answer exactly as SecurityInsight's updater checks an update: the manifest's signature against
         Invardia's update-signing keys that come with this file, then downloads the package into a NEW, empty folder in
         the temp folder (securityinsight-release-<version>-<random>) and checks its size and SHA-256 against the signed
         manifest. Pro downloads the Pro package from Invardia; Community downloads the public release zip the signed
         manifest names. -Version is not used: both install the release Invardia serves to the ring.
      4. Checks the zip (it opens, it holds setup/Install-SecurityInsight.ps1, its VERSION is the package's) and unpacks it.
      5. Runs the full installer, setup/Install-SecurityInsight.ps1, FROM that folder with exactly the parameters you gave,
         and ends with its exit code.

    After a successful install the downloaded folder is removed (-KeepDownload keeps it). After a stop it is kept, and
    -Resume uses it again (a small note remembers where it is: ~/clouddrive/invardia/securityinsight-launcher.json in
    Azure Cloud Shell, else .invardia/securityinsight-launcher.json in your user profile). When the folder is gone (a new
    Cloud Shell session), -Resume downloads the package again -- the install keeps its own progress in its state folder,
    so it still continues where it stopped.

    Nothing secret is a parameter, and this file writes no secret anywhere: the keys a feature needs are asked for by the
    installer and go straight to the install's Key Vault.

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
    session or for another tenant, before anything is downloaded.
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
    Who receives the reports: only the addresses given here (a list, or one text with commas). Not given: no one yet -- the people are chosen in Get Started (Who gets the reports); the person installing is never added by default.
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
.PARAMETER ConnectToInvardia
    Switch: Connect this install to Invardia: health reports + updates on request. Off by default for the Community edition
    (nothing that identifies the install is sent); a Pro install is always connected. Changed later with SI_Invardia_Connect.
.PARAMETER AssetTaggingWrites
    Switch: grant asset tagging the rights to write tags (writing is still switched on in the web app).
.PARAMETER UpdateRing
    The release ring this install follows: 1, 2 or 3 (default 3, broad). Recorded at install, also without a licence.
    The launcher installs the release Invardia serves to this ring (Pro and Community alike).
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
    { param($event) ... } -- called at the start and end of every step of the installer (its help has the event's fields).
.PARAMETER PreflightOnly
    Run the checks only. Nothing is created, changed or written (the release is still downloaded to the temp folder).
.PARAMETER Resume
    Continue an install that stopped: the release downloaded before is used again (when it is still there), and the
    installer skips the steps already done, with the answers of its first run (a parameter given now changes that one).
.PARAMETER StatePath
    The folder for the install's state file. Default: ~/clouddrive/invardia/<installId> (kept by Cloud Shell).
.PARAMETER Version
    Not used: kept so that older install lines still run. Both editions install the release Invardia serves to the
    install's update ring (-UpdateRing).
.PARAMETER KeepDownload
    Keep the downloaded release folder after a successful install (it is always kept after a stop, for -Resume).

.OUTPUTS
    Exit code: the installer's -- 0 installed (warnings included), 1 a step failed (fix it and run again with -Resume),
    2 a check failed, 3 the settings are not valid. 3 also when Invardia cannot be read or refuses the release of the
    ring, or a check of the download fails (nothing was installed).

.EXAMPLE
    Invoke-WebRequest https://invardia.com/support/si/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # SecurityInsight Pro (and the trial), the quickest install: every other setting has its default
.EXAMPLE
    Invoke-WebRequest https://github.com/KnudsenMorten/SecurityInsight/releases/latest/download/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # SecurityInsight Community, the quickest install: line 1 from the latest public release on GitHub, the same line 2
.EXAMPLE
    Invoke-WebRequest https://invardia.com/support/si/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '00000000-0000-0000-0000-000000000001' -SubscriptionId '00000000-0000-0000-0000-000000000002' -Location 'westeurope' -MailTo 'secops@contoso.com' -PrivateNetwork -VnetId '/subscriptions/00000000-0000-0000-0000-000000000004/resourceGroups/rg-network-spoke/providers/Microsoft.Network/virtualNetworks/vnet-spoke-security' -AppsSubnetName 'snet-si-apps' -AppsSubnetPrefix '10.0.24.0/27' -EndpointsSubnetName 'snet-si-endpoints' -EndpointsSubnetPrefix '10.0.24.32/28' -HubVnetId '/subscriptions/00000000-0000-0000-0000-000000000005/resourceGroups/rg-network-hub/providers/Microsoft.Network/virtualNetworks/vnet-hub' -WebAppAccess internal
    # a private-network install as two lines: line 2 carries only the settings that change
.EXAMPLE
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -PreflightOnly
    # the checks only: the release is downloaded to the temp folder, nothing is created, changed or written in Azure
.EXAMPLE
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Resume
    # continue an install that stopped, with the release and the answers of its first run (the same line 2 + -Resume)
.NOTES
    Requirements:
      PowerShell 7 (Azure Cloud Shell) or Windows PowerShell 5.1. No PowerShell module.
      Role: Owner (or Contributor + User Access Administrator) -- on the subscription SecurityInsight is installed in
      Role: Privileged Role Administrator (or Global Administrator) -- optional -- on the tenant
      Hosts: both editions: invardia.com (the signed release of the ring), login.microsoftonline.com and
        management.azure.com (the sign-in). SecurityInsight Community also: github.com, objects.githubusercontent.com,
        release-assets.githubusercontent.com (the public release zip the signed manifest names). Then the installer's:
        login.microsoftonline.com, management.azure.com, graph.microsoft.com and the install's own Azure resources (the
        full list is on the documentation page)

    Reads: the release of the ring at invardia.com (Pro: the Pro package route, with your sign-in; Community: the Community
    release of the ring, anonymous) and the zip it names. Writes: a new folder in the temp folder (the zip and its unpacked
    files; the sign-in and package-check code the launcher carries is written there too and removed when it ends) and the
    small note with that folder's path; everything else is the installer's. Nothing is written to disk about the sign-in.

.LINK
    https://invardia.com/docs/si/scripts/Install-SecurityInsight/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # ---- EXACTLY the full installer's parameters (setup\Install-SecurityInsight.ps1), passed through unchanged. ----
    # tests\pester\SIv3-InstallLauncher.Tests.ps1 fails when the two sets differ in a name, a type, a validation or a default.

    [string]$ConfigPath,
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
    [switch]$ConnectToInvardia,
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
    [switch]$ViaSupportApp,
    [string]$InstallId = 'securityinsight',
    [string]$LicencePath,
    [scriptblock]$Reporter,
    [switch]$PreflightOnly,
    [switch]$Resume,
    [string]$StatePath,
    [Parameter(DontShow)][System.Collections.IDictionary]$Seams,
    [Parameter(DontShow)][string]$SIConfigPath,
    # ---- this launcher's own ----

    # not used (older install lines still run): both editions install the release Invardia serves to the update ring
    [string]$Version,
    # keep the downloaded release folder after a successful install
    [switch]$KeepDownload,
    # Tests only: Download { param($Url, $OutFile) }, RunInstaller { param($Path, $Arguments) } -> exit code, TempRoot,
    # NoteDir, SignIn { param($TenantId, $SubscriptionId) } -> @{ TenantId; Account; Token }, GetPackage { param($Url, $Token) } ->
    # @{ Status; Body; Error }, TrustedKeys { } -> the update-signing keys, CodeRoot (the package root its code is loaded from),
    # RestHttp (replaces the REST layer's one HTTP call, Invoke-SIAzRestHttp, under the real sign-in)
    [Parameter(DontShow)][System.Collections.IDictionary]$LauncherSeams
)
#Requires -Version 5.1
# THE CHANNEL (framework INSTALL-1): 'community' in the repository and the GitHub copy; the copy handed to Invardia for
# https://invardia.com/support/si/ says 'pro' (release\Build-SISupportScripts.ps1 Set-SIInstallLauncherStamp). One line.
$script:SIInstallChannel = 'community'
# the release version this copy was built with (stamped by the build; empty in the repository)
$__siLauncherVersion = '3.1.56'
# THE CODE THE LAUNCHER USES (both editions, framework PRO-COMMUNITY-SAME): SecurityInsight's own setup sign-in
# (setup/_shared/SI-SetupAzure.ps1 and what it loads) and its updater's package check (engine/_shared/SI-InvardiaUpdate.ps1
# with its update-signing keys). release\Build-SISupportScripts.ps1 EMBEDS them below this line in the copy handed to
# Invardia, and release\Publish-SICommunityInstaller.ps1 in the copy on the public release -- readable, each file SHA-256 checked when it is written out -- so the published launcher stays ONE file.
# Empty in the repository: there the launcher uses the files of the package it stands in.
$__siLauncherFiles = [ordered]@{}
$__siLauncherFiles['setup/_shared/SI-SetupAzure.ps1'] = @{ Sha256 = 'e6b94dca00cc6690c83f8973cf840d2a83c57fe16e92df5fb64122060c43d8ef'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight SETUP -- Azure with NO PowerShell modules: native REST, ARM and .NET only.
|
|    Dot-source this ONE file at the top of a setup script (setup\, setup\ConfigWizard\backend\, Bootstrap-*, Setup-*):
|
|        . (Join-Path $PSScriptRoot 'setup\_shared\SI-SetupAzure.ps1')      # from the solution root
|        . (Join-Path $PSScriptRoot '_shared\SI-SetupAzure.ps1')            # from setup\
|        Connect-SISetupAzure -TenantId $tid -SubscriptionId $sub           # a person, or an app (see below)
|
|    It loads the engine's REST layer (engine/_shared/SI-AzRest.ps1: Invoke-SIArm, Resource Graph, Key Vault secrets,
|    storage data plane, the *-SIAz* REST twins), switches this process to REST (SI_AzureAccess_Engine = 'Rest'), adds the
|    sign-in of a PERSON (SI-SetupSignIn.ps1: Azure Cloud Shell token endpoint, or the browser with code + PKCE), and adds
|    what setup needs that the engines never did: Key Vault vaults and certificates, resource providers, deleting a role
|    assignment, typed ARM reads (resources, VMs, managed identities, SQL, Azure OpenAI, tenants, Log Analytics tables)
|    and storage management (tables, containers and queues through ARM, the lifecycle policy, name availability --
|    never an account key).
|
|    Every call goes through Invoke-SIAzRestHttp (the engine's one HTTP seam), so the offline tests run it against a fake.
|
|    INSIDE AN INVARDIA SUPPORT SESSION (owner 2026-10-12) setup signs in to NOTHING itself: Connect-SISetupAzure and
|    Get-SISetupAzureContext answer from the session (engine/_shared/SI-AzRest.ps1, Get-SISupportSession -- the one place
|    that detects it), and every call goes through the session's recording command, so each change is in the
|    environment's audit log. A subscription the session does not name is refused.
|    PS 5.1 safe; pwsh 7 on Windows, Linux (Azure Cloud Shell) and macOS.
|#>
|
|# NO Set-StrictMode here -- it leaks into the caller's scope.
|
|$__siSetupAzureRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
|. ([IO.Path]::Combine($__siSetupAzureRoot, 'engine', '_shared', 'SI-AzRest.ps1'))
|. ([IO.Path]::Combine($__siSetupAzureRoot, 'engine', '_shared', 'SI-LogIngest.ps1'))
|. ([IO.Path]::Combine($__siSetupAzureRoot, 'auth', 'Find-SICertificate.ps1'))
|. ([IO.Path]::Combine($__siSetupAzureRoot, 'auth', 'SI-ManagedIdentity.ps1'))
|. ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupSignIn.ps1'))
|Remove-Variable -Name __siSetupAzureRoot -ErrorAction SilentlyContinue
|
|# Setup never loads an Az module: every *-SIAz* wrapper takes its REST twin, and log ingestion its REST path.
|$global:SI_AzureAccess_Engine = 'Rest'
|$global:SI_LogIngest_Engine   = 'Rest'
|
|function Get-SIAzureToken {
|    <#
|        THE token function of the REST layer, as setup needs it: a signed-in PERSON (Connect-SISetupUser) is answered
|        from the setup sign-in; an app or a managed identity exactly as engine/_shared/SI-AzRest.ps1 does. Defined here,
|        after that file, so every REST helper -- Invoke-SIArm, the *-SIAz* twins, Key Vault, storage, Graph -- runs as
|        whoever signed in.
|    #>
|    param(
|        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
|        [string]$Resource,
|        [hashtable]$Auth,
|        [switch]$ForceRefresh
|    )
|    if (-not $Resource) { $Resource = Get-SIAzureAudience -Audience $Audience }
|    if (-not $Auth) {
|        # an Invardia Support session in the shell is setup's sign-in (never a person's or an app's beside it)
|        $null = Sync-SISupportConnection -TakeOver
|        $st = Get-SIAzRestState
|        if ($st.Connection -is [hashtable] -and $st.Connection.Mode -eq 'User') { $Auth = $st.Connection }
|    }
|    if ($Auth -and $Auth.Mode -eq 'User') { return (Get-SISetupUserToken -Resource $Resource -ForceRefresh:$ForceRefresh) }
|    # the engine's own hook ($global:SI_TokenProvider), exactly as engine/_shared/SI-AzRest.ps1 consults it
|    if (-not $Auth) {
|        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
|        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
|    }
|    Initialize-SIAzRestHelpers
|    if (-not $Auth) { $Auth = Resolve-SIAzRestAuth }
|    return (Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$ForceRefresh)
|}
|# published globally too: a child script that loads only the engine file still finds the setup sign-in
|Set-Item -Path 'function:global:Get-SIAzureToken' -Value ${function:Get-SIAzureToken}
|
|# =====================================================================================================================
|#  Sign-in: one entry point for a person, an app or a managed identity
|# =====================================================================================================================
|
|function Connect-SISetupAzure {
|    <#
|        Signs this PowerShell process in to Azure for setup. No module, no Connect-AzAccount.
|          -ApplicationId + -CertificateThumbprint   an app with a certificate (LocalMachine\My or CurrentUser\My)
|          -ApplicationId + -ClientSecret            an app with a client secret (string or SecureString)
|          -Identity [-ManagedIdentityClientId]      this host's managed identity
|          (none of these)                           a PERSON: Azure Cloud Shell, else the browser (-UserSignIn)
|        AN INVARDIA SUPPORT SESSION open in this shell IS the sign-in: nothing is signed in here (no browser, no
|        certificate, no token request) -- the context is the session's: its tenant, and -SubscriptionId when the session
|        names it, else its first subscription. A subscription or tenant the session does not name is refused, and so is
|        -ApplicationId / -Identity (a sign-in beside the session would not be recorded there). One plain line says so.
|        ONE connect path (#524): an existing Azure session of this process (Connect-AzAccount, az login) is never used.
|        An existing sign-in in this process is REUSED (same tenant) unless -Force. -SubscriptionId selects the
|        subscription every following call works in. The app/identity is proven by asking for an ARM token at once, so a
|        wrong secret or certificate fails here, not three steps later. Returns Get-SISetupAzureContext.
|    #>
|    [CmdletBinding()]
|    param(
|        [string]$TenantId,
|        [string]$SubscriptionId,
|        [string]$ApplicationId,
|        [string]$CertificateThumbprint,
|        $ClientSecret,
|        [switch]$Identity,
|        [string]$ManagedIdentityClientId,
|        [ValidateSet('Auto', 'CloudShell', 'Browser')][string]$UserSignIn = 'Auto',
|        [string]$LoginHint,
|        [int]$TimeoutSec = 300,
|        [switch]$Force
|    )
|    $st = Get-SIAzRestState
|    $app = ($ApplicationId -and ($CertificateThumbprint -or $ClientSecret))
|    $sess = Get-SISupportSession
|    if ($sess) {
|        $name = Get-SISupportSessionName $sess
|        if ($app -or $Identity) {
|            $who = if ($Identity) { 'a managed identity' } else { 'the app {0}' -f $ApplicationId }
|            throw ('An Invardia Support session for {0} is open in this PowerShell session: SecurityInsight setup works through it, so every change is recorded there. Signing in here as {1} would not be recorded -- refused. Run the same command without the sign-in parameters, or end the session first (Disconnect-InvardiaSupport).' -f $name, $who)
|        }
|        if ($TenantId -and $TenantId -ne $sess.TenantId) {
|            throw ('The Invardia Support session for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f $name, $sess.TenantId, $TenantId)
|        }
|        if ($SubscriptionId) { Assert-SISupportSubscription -SubscriptionId $SubscriptionId -Session $sess }
|        if (Test-SISetupUserSignedIn) { Disconnect-SISetupUser }
|        return (Get-SISetupAzureContext -SubscriptionId $SubscriptionId)
|    }
|    $null = Sync-SISupportConnection   # a Support sign-in whose session was closed is dropped
|    $existing = $st.Connection
|    $reuse = (-not $Force) -and ($existing -is [hashtable]) -and (-not $app) -and (-not $Identity) -and
|             ((-not $TenantId) -or ([string]$existing.TenantId -eq $TenantId) -or ($existing.Mode -eq 'ManagedIdentity'))
|    # 2026-11-03 (a customer install, a second run in one window): a person's connection left by an earlier run whose sign-in this run does
|    # not hold is NEVER reused -- the person is signed in again (else Get-SISetupAzureContext answers $null and the install
|    # stops "not signed in")
|    if ($reuse -and [string]$existing.Mode -eq 'User' -and -not $existing['IsApp'] -and -not (Test-SISetupUserSignedIn)) { $reuse = $false; $st.Connection = $null }
|    if (-not $reuse) {
|        if ($app -or $Identity) {
|            if (Test-SISetupUserSignedIn) { Disconnect-SISetupUser }
|            $c = @{}
|            if ($Identity) {
|                $c['Identity'] = $true
|                if ($ManagedIdentityClientId) { $c['AccountId'] = $ManagedIdentityClientId }
|            } elseif ($CertificateThumbprint) {
|                $c['ServicePrincipal'] = $true; $c['ApplicationId'] = $ApplicationId; $c['CertificateThumbprint'] = $CertificateThumbprint; $c['Tenant'] = $TenantId
|            } else {
|                $sec = if ($ClientSecret -is [System.Security.SecureString]) { $ClientSecret } else { ConvertTo-SISecureString -Text ([string]$ClientSecret) }
|                $c['ServicePrincipal'] = $true; $c['Credential'] = New-Object System.Management.Automation.PSCredential($ApplicationId, $sec); $c['Tenant'] = $TenantId
|            }
|            if ($SubscriptionId) { $c['Subscription'] = $SubscriptionId }
|            $null = Connect-SIAzAccountRest @c
|            if ($global:SI_LogIngestRunCache -is [hashtable]) { $global:SI_LogIngestRunCache.Tokens = @{} }
|            try { $null = Get-SIAzureToken -Audience Arm -ForceRefresh }
|            catch {
|                $st.Connection = $null
|                $who = if ($Identity) { 'the managed identity of this host' } else { 'app {0}' -f $ApplicationId }
|                throw ('Signing in to Azure as {0} failed: {1}' -f $who, $_.Exception.Message)
|            }
|        } elseif ([string](Get-Variable -Scope Global -Name SI_AuthMethod -ValueOnly -ErrorAction Ignore) -eq 'AzContext') {
|            # #524: the retired sign-in mode "AzContext" (borrow this process's Azure session) is refused -- never a silent fallback
|            throw ('SI_AuthMethod = AzContext (use the current Azure session of this PowerShell process) is no longer supported: setup signs in itself -- a person (Azure Cloud Shell or the browser), or an app with -ApplicationId and -CertificateThumbprint or -ClientSecret, or -Identity. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
|        } else {
|            $u = Connect-SISetupUser -TenantId $TenantId -Method $UserSignIn -LoginHint $LoginHint -TimeoutSec $TimeoutSec
|            # #876: a sign-in handed over by the installation page may be an APPLICATION's (IsApp): it is then a service
|            # principal for every check that asks who installs -- its object id is the service principal's
|            $isApp = [bool]($u.PSObject.Properties['IsApp'] -and $u.IsApp)
|            $st.Connection = @{ Mode = 'User'; AppId = $u.Account; TenantId = $u.TenantId; ObjectId = $u.ObjectId; Method = $u.Method; IsApp = $isApp }
|            $st.TenantId = $u.TenantId
|            $st.SubscriptionId = $null
|            $st.Cache = @{}
|        }
|    }
|    if ($SubscriptionId) { $st.SubscriptionId = $SubscriptionId }
|    return (Get-SISetupAzureContext)
|}
|
|function ConvertTo-SISecureString {
|    param([string]$Text)
|    $s = New-Object System.Security.SecureString
|    foreach ($ch in ([string]$Text).ToCharArray()) { $s.AppendChar($ch) }
|    $s.MakeReadOnly()
|    return $s
|}
|
|function Get-SISetupAzureContext {
|    <#
|        Who this process is signed in as -- the shape setup read from Get-AzContext: Account.Id / .Type ('User',
|        'ServicePrincipal', 'ManagedService'), Account.ObjectId, Tenant.Id, Subscription.Id / .Name, SignInMethod.
|        $null when nobody is signed in.
|        In an Invardia Support session the context IS the session's (SignInMethod 'Support', read from the session -- no
|        sign-in and no token request): its tenant, and -SubscriptionId when the session names it, else the install's
|        configured subscription, else the session's first. THROWS only what a Support session refuses: a subscription it
|        does not name, another tenant than the configured one, a session without its recording command.
|        -SubscriptionId selects the subscription the following calls work in (as Connect-SISetupAzure -SubscriptionId).
|    #>
|    param([string]$SubscriptionId)
|    $st = Get-SIAzRestState
|    $sess = Sync-SISupportConnection -TakeOver
|    $c = $st.Connection
|    if (-not ($c -is [hashtable])) {
|        # an app configured through the SI_SPN_* globals counts as signed in (the engines' own rule)
|        try { $c = Resolve-SIAzRestAuth } catch { return $null }
|    }
|    # 2026-11-03 (an install run twice in ONE PowerShell window, the second from a newer package): a person's connection left
|    # by the earlier run while this run holds no sign-in of that person (its tokens live with the earlier run) is NOT a
|    # sign-in -- $null, so the install signs the person in again instead of failing at its first Azure call
|    if (-not $sess -and [string]$c.Mode -eq 'User' -and -not $c['IsApp'] -and (Get-Command -Name Test-SISetupUserSignedIn -ErrorAction Ignore) -and -not (Test-SISetupUserSignedIn)) { return $null }
|    if ($SubscriptionId) {
|        if ($sess) { Assert-SISupportSubscription -SubscriptionId $SubscriptionId -Session $sess }
|        $st.SubscriptionId = $SubscriptionId
|    }
|    $type = switch ([string]$c.Mode) { 'User' { $(if ($c['IsApp']) { 'ServicePrincipal' } else { 'User' }) } 'ManagedIdentity' { 'ManagedService' } default { 'ServicePrincipal' } }
|    $id = switch ([string]$c.Mode) { 'ManagedIdentity' { $(if ($c.ClientId) { [string]$c.ClientId } else { 'MSI' }) } default { [string]$c.AppId } }
|    $tid = [string]$st.TenantId
|    if (-not $tid) { $tid = [string]$c.TenantId }
|    if (-not $tid -and $c.Mode -ne 'User') { try { $tid = Get-SIAzRestTenantId } catch { } }
|    $sub = $null
|    try { $sub = Get-SIAzRestSubscriptionId } catch { }
|    if ($sess -and $sub) {
|        Assert-SISupportSubscription -SubscriptionId $sub -Session $sess
|        # the session already knows its first subscription's name: no call for it
|        if ($sess.SubscriptionName -and ([string]$sub).Trim().ToLowerInvariant() -eq $sess.SubscriptionId -and -not $st.Cache.ContainsKey('subname|' + $sub)) { $st.Cache['subname|' + $sub] = [string]$sess.SubscriptionName }
|    }
|    $subName = $sub
|    if ($sub) {
|        $k = 'subname|' + $sub
|        if ($st.Cache.ContainsKey($k)) { $subName = $st.Cache[$k] }
|        else {
|            try { $s = Invoke-SIArm -Path ('/subscriptions/' + $sub) -ApiVersion '2022-12-01' -AllowNotFound; if ($s -and $s.displayName) { $subName = [string]$s.displayName } } catch { }
|            $st.Cache[$k] = $subName
|        }
|    }
|    return [pscustomobject]@{
|        PSTypeName   = 'SI.Setup.AzureContext'
|        Name         = ('{0} ({1})' -f $subName, $id)
|        Account      = [pscustomobject]@{ Id = $id; Type = $type; ObjectId = $(if ($c.ObjectId) { [string]$c.ObjectId } else { $null }) }
|        Tenant       = [pscustomobject]@{ Id = $tid; TenantId = $tid }
|        Subscription = $(if ($sub) { [pscustomobject]@{ Id = $sub; SubscriptionId = $sub; Name = $subName; TenantId = $tid } } else { $null })
|        SignInMethod = $(if ($c.Mode -eq 'User') { [string]$c.Method } else { [string]$c.Mode })
|    }
|}
|
|function Disconnect-SISetupAzure {
|    Disconnect-SISetupUser
|    Disconnect-SIAzAccountRest
|}
|
|function Get-SISetupSignedInObjectId {
|    <# The object id of whoever is signed in: the person (from their token), else the app's service principal. #>
|    $st = Get-SIAzRestState
|    $c = $st.Connection
|    if ($c -is [hashtable] -and $c.ObjectId) { return [string]$c.ObjectId }
|    try {
|        $claims = ConvertFrom-SIJwtPayload (Get-SIAzureToken -Audience Arm)
|        if ($claims -and $claims.oid) { return [string]$claims.oid }
|    } catch { }
|    return $null
|}
|
|function ConvertTo-SISetupGuid {
|    <# PURE. One id in ONE form for comparing: [guid]::TryParse -- '{GUID}', upper case, spaces around all read as the same
|       lower-case 'D' form; anything that is not a GUID (a display name, '') = ''. #>
|    param([AllowNull()][AllowEmptyString()][string]$Id)
|    $g = [guid]::Empty
|    if ([guid]::TryParse(("$Id").Trim(), [ref]$g) -and $g -ne [guid]::Empty) { return $g.ToString('D') }
|    ''
|}
|
|function Get-SISetupSupportAppIds {
|    <#
|        PURE over its inputs. EVERY Invardia Support app client id this setup can know, normalised (ConvertTo-SISetupGuid),
|        once each: -SupportAppId (the install answer supportAppId, framework 4.1a; several allowed), -SessionAppId (the open
|        Invardia Support session's AppId), -RecordedAppId (the install's recorded Support app, cfg.InstallState 'SupportApp',
|        where the caller could read it), -ConfigAppId ($global:SI_SupportAppId where a configuration sets it; none does
|        today). Invardia's naming standard carries no Support app id that SI ships (framework/naming-standard.json role
|        support-app names no app id), so there is no fifth source. Anything that is not a GUID is never an id.
|    #>
|    param([AllowEmptyCollection()][string[]]$SupportAppId = @(), [AllowEmptyString()][string]$SessionAppId = '',
|          [AllowEmptyCollection()][string[]]$RecordedAppId = @(), [AllowEmptyString()][string]$ConfigAppId = '')
|    # one id per output object (callers wrap the call in @()); none = no output
|    @(@($SupportAppId) + @($SessionAppId) + @($RecordedAppId) + @($ConfigAppId) | ForEach-Object { ConvertTo-SISetupGuid $_ } | Where-Object { $_ } | Select-Object -Unique)
|}
|
|function Resolve-SISetupEngineGrantee {
|    <#
|        PURE. May setup give the ENGINE's runtime roles to this grantee? Framework RIGHTS-1 / ROOT-RIGHTS-1 point 4: the
|        Support app's rights are Invardia's -- a product never gives it the engine's roles (found 2026-11-27 at three
|        installs: the Support app ran setup and got the engine's storage, Key Vault and monitoring data roles as "the SPN").
|        Told by CLIENT ID only (-SupportAppIds, Get-SISetupSupportAppIds), never by a display name. FAILS CLOSED:
|          * the caller is an application whose client id is a Support app id, and its object id is NOT known -> refused
|            (the grantee may be the caller);
|          * the grantee IS the caller (object ids equal) and the caller's client id is a Support app id -> refused;
|          * the grantee is NOT the caller and is an app (-GranteePrincipalType ServicePrincipal): its client id from Graph
|            (-GranteeAppId, -GranteeLookup 'ok') -> refused when it is a Support app id; a lookup that failed
|            (-GranteeLookup 'failed') -> refused, never granted on a guess;
|          * a person or a group as grantee (User / Group) is never the Support app; no Support app id known = nothing to
|            compare with -> allowed.
|        Returns @{ Allow ($true|$false); Why (the line to say when refused, '' when allowed) }.
|    #>
|    param([AllowEmptyString()][string]$GranteeObjectId = '', [string]$GranteePrincipalType = 'ServicePrincipal',
|          [AllowEmptyString()][string]$GranteeAppId = '', [ValidateSet('ok', 'failed', 'skipped')][string]$GranteeLookup = 'skipped',
|          [AllowEmptyString()][string]$CallerObjectId = '', [AllowEmptyString()][string]$CallerAppId = '',
|          [AllowEmptyString()][string]$CallerType = '', [AllowEmptyCollection()][string[]]$SupportAppIds = @())
|    $ok = [pscustomobject]@{ Allow = $true; Why = '' }
|    $no = { param($w) [pscustomobject]@{ Allow = $false; Why = $w } }
|    $ids = @($SupportAppIds | ForEach-Object { ConvertTo-SISetupGuid $_ } | Where-Object { $_ })
|    if (-not $ids.Count) { return $ok }
|    $g = ConvertTo-SISetupGuid $GranteeObjectId; $c = ConvertTo-SISetupGuid $CallerObjectId; $ca = ConvertTo-SISetupGuid $CallerAppId
|    $callerIsSupport = ("$CallerType".Trim() -ne 'User') -and $ca -and ($ids -contains $ca)
|    if ($callerIsSupport -and -not $c) { return (& $no ("the caller is the Invardia Support app (client {0}) and its object id could not be read, so the grantee may be the Support app itself" -f $ca)) }
|    if ($g -and $c -and $g -eq $c) {
|        if ($callerIsSupport) { return (& $no ("the grantee is the caller, the Invardia Support app (client {0})" -f $ca)) }
|        return $ok
|    }
|    if ("$GranteePrincipalType".Trim() -in 'User', 'Group') { return $ok }
|    if ($GranteeLookup -eq 'failed') { return (& $no ("the grantee {0} is not the caller and its application could not be read from Microsoft Graph, so it cannot be told from the Invardia Support app" -f $GranteeObjectId)) }
|    $ga = ConvertTo-SISetupGuid $GranteeAppId
|    if ($ga -and $ids -contains $ga) { return (& $no ("the grantee {0} is the Invardia Support app (client {1})" -f $GranteeObjectId, $ga)) }
|    if ($GranteeLookup -ne 'ok') { return (& $no ("the grantee {0} is not the caller and its application was not read, so it cannot be told from the Invardia Support app" -f $GranteeObjectId)) }
|    $ok
|}
|
|# =====================================================================================================================
|#  Small ARM helpers
|# =====================================================================================================================
|
|function Get-SISetupSubscriptionId {
|    param([string]$SubscriptionId)
|    if ($SubscriptionId) { return $SubscriptionId }
|    $s = Get-SIAzRestSubscriptionId
|    if (-not $s) { throw 'No Azure subscription is selected. Pass the subscription id (or sign in with access to one) and run the same command again.' }
|    return $s
|}
|
|function Get-SIArmResourceGroupFromId {
|    param([string]$Id)
|    if ([string]$Id -match '/resourceGroups/([^/]+)/') { return $Matches[1] }
|    return $null
|}
|
|# =====================================================================================================================
|#  (2) Key Vault: vaults (ARM) and certificates (data plane)
|# =====================================================================================================================
|
|function ConvertTo-SIKeyVaultObject {
|    param($V)
|    [pscustomobject]@{
|        VaultName                 = [string]$V.name
|        ResourceId                = [string]$V.id
|        ResourceGroupName         = (Get-SIArmResourceGroupFromId $V.id)
|        Location                  = [string]$V.location
|        VaultUri                  = [string]$V.properties.vaultUri
|        TenantId                  = [string]$V.properties.tenantId
|        Sku                       = [string]$V.properties.sku.name
|        EnableRbacAuthorization   = [bool]$V.properties.enableRbacAuthorization
|        EnableSoftDelete          = [bool]$V.properties.enableSoftDelete
|        EnablePurgeProtection     = [bool]$V.properties.enablePurgeProtection
|        PublicNetworkAccess       = [string]$V.properties.publicNetworkAccess
|        ProvisioningState         = [string]$V.properties.provisioningState
|        Tags                      = $V.tags
|    }
|}
|
|function Get-SIKeyVault {
|    <#
|        A Key Vault by name, the way Get-AzKeyVault found it: in -ResourceGroupName, else anywhere in the subscription.
|        -InRemovedState -Location: the soft-deleted vault of that name (DeletionDate, ScheduledPurgeDate). Not found is a
|        non-terminating error (so -ErrorAction SilentlyContinue gives $null), as for the cmdlet.
|    #>
|    [CmdletBinding()]
|    param([Alias('Name')][string]$VaultName, [string]$ResourceGroupName, [switch]$InRemovedState, [string]$Location, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    if ($InRemovedState) {
|        if (-not $Location) { throw 'Get-SIKeyVault -InRemovedState needs -Location.' }
|        $d = Invoke-SIArm -Path ("/subscriptions/$sub/providers/Microsoft.KeyVault/locations/$Location/deletedVaults/$VaultName") -ApiVersion '2023-07-01' -AllowNotFound
|        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("No deleted Key Vault '{0}' in {1}." -f $VaultName, $Location) -Target $VaultName; return }
|        return [pscustomobject]@{
|            VaultName = [string]$d.name; Id = [string]$d.id; Location = [string]$d.properties.location; ResourceId = [string]$d.properties.vaultId
|            DeletionDate = $d.properties.deletionDate; ScheduledPurgeDate = $d.properties.scheduledPurgeDate; EnablePurgeProtection = [bool]$d.properties.purgeProtectionEnabled
|        }
|    }
|    if ($VaultName -and $ResourceGroupName) {
|        $v = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName") -ApiVersion '2023-07-01' -AllowNotFound
|        if (-not $v) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Key Vault '{0}' was not found in resource group '{1}'." -f $VaultName, $ResourceGroupName) -Target $VaultName; return }
|        return (ConvertTo-SIKeyVaultObject $v)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults" } else { "/subscriptions/$sub/providers/Microsoft.KeyVault/vaults" }
|    $found = $false
|    foreach ($v in @(Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -List)) {
|        if ($VaultName -and [string]$v.name -ne $VaultName) { continue }
|        $found = $true
|        ConvertTo-SIKeyVaultObject $v
|    }
|    if ($VaultName -and -not $found) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Key Vault '{0}' was not found in subscription {1}." -f $VaultName, $sub) -Target $VaultName }
|}
|
|function New-SIKeyVault {
|    <# Creates (PUT) a Key Vault: soft delete on, Azure RBAC authorization by default, and waits until it is ready. #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][Alias('Name')][string]$VaultName,
|        [Parameter(Mandatory)][string]$ResourceGroupName,
|        [Parameter(Mandatory)][string]$Location,
|        [ValidateSet('standard', 'premium', 'Standard', 'Premium')][string]$Sku = 'standard',
|        [bool]$EnableRbacAuthorization = $true,
|        [switch]$EnablePurgeProtection,
|        [int]$SoftDeleteRetentionInDays = 90,
|        [hashtable]$Tag,
|        [string]$SubscriptionId,
|        [string]$TenantId,
|        # #866 (a private install; owner: "we will not allow fw option or exceptions"): 'Disabled' CREATES the vault with no
|        # public access at all (its firewall Deny, trusted Microsoft services allowed) -- a policy that refuses a public
|        # vault never sees one. Empty: Azure's default, as before.
|        [ValidateSet('', 'Disabled')][string]$PublicNetworkAccess = ''
|    )
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    if (-not $TenantId) { $TenantId = Get-SIAzRestTenantId }
|    $props = [ordered]@{
|        tenantId                  = $TenantId
|        sku                       = @{ family = 'A'; name = $Sku.ToLowerInvariant() }
|        enableRbacAuthorization   = $EnableRbacAuthorization
|        enableSoftDelete          = $true
|        softDeleteRetentionInDays = $SoftDeleteRetentionInDays
|        accessPolicies            = @()
|    }
|    if ($EnablePurgeProtection) { $props['enablePurgeProtection'] = $true }
|    if ($PublicNetworkAccess -eq 'Disabled') {
|        $props['publicNetworkAccess'] = 'Disabled'
|        $props['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() }
|    }
|    $body = [ordered]@{ location = $Location; properties = $props }
|    if ($Tag) { $body['tags'] = $Tag }
|    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
|    $v = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-07-01' -Body $body
|    for ($i = 0; $i -lt 30 -and $v -and [string]$v.properties.provisioningState -and [string]$v.properties.provisioningState -notin 'Succeeded', 'Failed'; $i++) {
|        Start-Sleep -Seconds 5
|        $v = Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -AllowNotFound
|    }
|    if (-not $v) { throw ("The Key Vault '{0}' was requested but did not appear." -f $VaultName) }
|    return (ConvertTo-SIKeyVaultObject $v)
|}
|
|# ---------------------------------------------------------------------------------------------------------------------
|#  FRAMEWORK INSTALLER RULE 11 -- the install's Key Vault network shape, set and READ BACK every run.
|#  Rule 11 (framework REQUIREMENTS, installer rules, 3 Nov): "a PRIVATE install's Key Vault: publicNetworkAccess Disabled +
|#  networkAcls { defaultAction Deny, bypass AzureServices, no ipRules, no virtualNetworkRules } ... bypass AzureServices is
|#  REQUIRED: ARM key / secret operations ... are refused with ForbiddenByConnection under bypass None ... ENFORCE IT EVERY
|#  RUN: a re-install RECOVERS a soft-deleted vault (purge protection), and a recover IGNORES networkAcls (it comes back with
|#  bypass None) - so set the vault to this shape and READ IT BACK before any key / secret step, whether the vault was made,
|#  recovered or found." Rule 11 names only the private shape; a PUBLIC install takes the one part that is not about being
|#  private -- bypass AzureServices -- and nothing else is changed (its public access and firewall stay the customer's).
|# ---------------------------------------------------------------------------------------------------------------------
|
|function Get-SIKeyVaultNetworkShape {
|    <# PURE. The network settings of a vault as ARM returns it (PSCustomObject or hashtable): PublicNetworkAccess,
|       DefaultAction, Bypass, IpRules, VirtualNetworkRules (the rule lists, empty when there are none). #>
|    param($Vault)
|    $get = { param($o, [string]$n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
|    $props = & $get $Vault 'properties'
|    $acl = & $get $props 'networkAcls'
|    [pscustomobject]@{
|        PublicNetworkAccess = [string](& $get $props 'publicNetworkAccess')
|        DefaultAction       = [string](& $get $acl 'defaultAction')
|        Bypass              = [string](& $get $acl 'bypass')
|        IpRules             = @(@(& $get $acl 'ipRules') | Where-Object { $null -ne $_ })
|        VirtualNetworkRules = @(@(& $get $acl 'virtualNetworkRules') | Where-Object { $null -ne $_ })
|    }
|}
|
|function Get-SIKeyVaultRule11Patch {
|    <# PURE. The PATCH body that brings -Vault to the rule-11 shape -- ONLY what differs -- or $null when it has it.
|         -Private  publicNetworkAccess Disabled + networkAcls { Deny, AzureServices, no IP rules, no network rules }
|         public    a vault open to all networks (default action Allow, or no firewall at all) already lets trusted Microsoft
|                   services in: nothing to set -- Azure does not keep a bypass on a vault without a firewall, so asking for
|                   one can never read back. Only a vault whose firewall DENIES gets bypass AzureServices; its default action
|                   and rules are kept, publicNetworkAccess is not touched -- a public install never opens or closes a vault. #>
|    param($Vault, [switch]$Private)
|    $s = Get-SIKeyVaultNetworkShape -Vault $Vault
|    $p = [ordered]@{}
|    if ($Private) {
|        if ($s.PublicNetworkAccess -ne 'Disabled') { $p['publicNetworkAccess'] = 'Disabled' }
|        if ($s.DefaultAction -ne 'Deny' -or $s.Bypass -ne 'AzureServices' -or $s.IpRules.Count -or $s.VirtualNetworkRules.Count) {
|            $p['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() }
|        }
|    } elseif ($s.DefaultAction -eq 'Deny' -and $s.Bypass -ne 'AzureServices') {
|        $p['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'
|                                        ipRules = @($s.IpRules); virtualNetworkRules = @($s.VirtualNetworkRules) }
|    }
|    if (-not $p.Count) { return $null }
|    [ordered]@{ properties = $p }
|}
|
|function Test-SIKeyVaultRule11Shape {
|    <# PURE. Does -Vault read back in the rule-11 shape (private or public, as above)? #>
|    param($Vault, [switch]$Private)
|    [bool]($Vault -and $null -eq (Get-SIKeyVaultRule11Patch -Vault $Vault -Private:$Private))
|}
|
|function Get-SIKeyVaultShapeText {
|    <# PURE. One line for the log: public access, default action, bypass, rule counts. #>
|    param($Vault)
|    $s = Get-SIKeyVaultNetworkShape -Vault $Vault
|    'publicNetworkAccess {0}, defaultAction {1}, bypass {2}, ipRules {3}, virtualNetworkRules {4}' -f $(if ($s.PublicNetworkAccess) { $s.PublicNetworkAccess } else { '(not set)' }),
|        $(if ($s.DefaultAction) { $s.DefaultAction } else { '(not set)' }), $(if ($s.Bypass) { $s.Bypass } else { '(not set)' }), $s.IpRules.Count, $s.VirtualNetworkRules.Count
|}
|
|function Set-SIKeyVaultRule11 {
|    <# Sets the vault to the rule-11 shape (PATCH, only what differs) and READS IT BACK. Throws plainly when it does not read
|       back in that shape -- nothing writes a key or secret to it before it does. Returns Changed, Shape (the read-back line),
|       Vault (the read-back vault as Get-SIKeyVault returns it). #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$ResourceGroupName, [string]$SubscriptionId,
|          [switch]$Private, [int]$Tries = 12, [int]$PauseSeconds = 5)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.KeyVault/vaults/$VaultName"
|    $have = Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -AllowNotFound
|    if (-not $have) { throw ("The Key Vault '{0}' was not found in resource group '{1}' -- its network shape (framework installer rule 11) cannot be set." -f $VaultName, $ResourceGroupName) }
|    $patch = Get-SIKeyVaultRule11Patch -Vault $have -Private:$Private
|    $back = $have
|    if ($patch) {
|        $null = Invoke-SIArm -Method PATCH -Path $path -ApiVersion '2023-07-01' -Body $patch
|        for ($i = 1; $i -le $Tries; $i++) {
|            $back = Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -AllowNotFound
|            if (Test-SIKeyVaultRule11Shape -Vault $back -Private:$Private) { break }
|            if ($i -lt $Tries) { Start-Sleep -Seconds $PauseSeconds }
|        }
|    }
|    if (-not (Test-SIKeyVaultRule11Shape -Vault $back -Private:$Private)) {
|        # Framework rule 17: the advice names ONLY the one setting that is missing -- never "set the networking", which on
|        # a public install invites "selected networks" and locks the jobs out of their own vault.
|        throw ("The Key Vault '{0}' does not read back in the shape it must have ({1}); it reads: {2}. Nothing writes a key or secret to it until it does -- run the same command again; if it stays like this, {3}, change nothing else there, and run again." -f $VaultName,
|            $(if ($Private) { 'public access Disabled, firewall Deny, trusted Microsoft services allowed (bypass AzureServices), no IP or network rules' } else { 'trusted Microsoft services allowed (bypass AzureServices)' }), (Get-SIKeyVaultShapeText -Vault $back),
|            $(if ($Private) { "in the Azure portal (Key vaults > $VaultName > Networking) choose 'Disable public access' and tick 'Allow trusted Microsoft services to bypass this firewall'" } else { "in the Azure portal (Key vaults > $VaultName > Networking > Exceptions) tick only 'Allow trusted Microsoft services to bypass this firewall'" }))
|    }
|    [pscustomobject]@{ Changed = [bool]$patch; Shape = (Get-SIKeyVaultShapeText -Vault $back); Vault = (ConvertTo-SIKeyVaultObject $back) }
|}
|
|function Get-SIKeyVaultEnsureAction {
|    <# PURE. What the install does with its vault: 'found' (it is there), 'recover' (absent, but soft-deleted in the install's
|       location FROM THE INSTALL'S OWN resource group -- a re-install; with purge protection it can neither be purged nor
|       made again under that name), 'create' (also when the deleted vault was another resource group's: the create then
|       fails with Azure's own "exists in deleted state", as before -- another install's vault is never taken over). #>
|    param($Found, $Deleted, [string]$ResourceGroupName)
|    if ($Found) { return 'found' }
|    if ($Deleted) {
|        $rg = if ([string]$Deleted.ResourceId -match '(?i)/resourceGroups/([^/]+)/') { $Matches[1] } else { '' }
|        if (-not $rg -or -not $ResourceGroupName -or $rg -eq $ResourceGroupName) { return 'recover' }
|    }
|    'create'
|}
|
|function Get-SIKeyVaultRecoverBody {
|    <# PURE. The PUT body that RECOVERS a soft-deleted vault (properties.createMode 'recover'; Azure restores its settings --
|       but NOT its networkAcls, hence Set-SIKeyVaultRule11 right after). tenantId and sku are required by the schema. #>
|    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$TenantId, [string]$Sku = 'standard')
|    [ordered]@{ location = $Location; properties = [ordered]@{ tenantId = $TenantId; sku = [ordered]@{ family = 'A'; name = $Sku.ToLowerInvariant() }; createMode = 'recover' } }
|}
|
|function Restore-SIKeyVault {
|    <# RECOVERS the soft-deleted vault -Deleted (Get-SIKeyVault -InRemovedState) into the resource group it was deleted from
|       (or -ResourceGroupName when that is not known), and waits until it is ready. Returns it as Get-SIKeyVault does. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)]$Deleted, [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Location,
|          [string]$SubscriptionId, [string]$TenantId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    if (-not $TenantId) { $TenantId = Get-SIAzRestTenantId }
|    $rg = Get-SIArmResourceGroupFromId ([string]$Deleted.ResourceId)
|    if (-not $rg) { $rg = $ResourceGroupName }
|    $name = [string]$Deleted.VaultName
|    $path = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.KeyVault/vaults/$name"
|    $v = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-07-01' -Body (Get-SIKeyVaultRecoverBody -Location $Location -TenantId $TenantId)
|    for ($i = 0; $i -lt 30 -and (-not $v -or ([string]$v.properties.provisioningState -and [string]$v.properties.provisioningState -notin 'Succeeded', 'Failed')); $i++) {
|        Start-Sleep -Seconds 5
|        $v = Invoke-SIArm -Path $path -ApiVersion '2023-07-01' -AllowNotFound
|    }
|    if (-not $v) { throw ("The soft-deleted Key Vault '{0}' was recovered but did not appear." -f $name) }
|    return (ConvertTo-SIKeyVaultObject $v)
|}
|
|function Initialize-SIKeyVault {
|    <# The install's vault, FOUND, RECOVERED or CREATED -- and in every case set to the rule-11 shape and READ BACK before
|       anything writes a key or secret to it. -PublicNetworkAccess 'Disabled' = a private install (created private from
|       birth, converged to the private shape); '' = a public one. Returns Action (found | recovered | created), Vault,
|       Changed (the shape had to be set), Shape (the read-back line), Deleted (what was recovered). #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Location,
|          [string]$SubscriptionId, [string]$TenantId, [switch]$EnablePurgeProtection,
|          [ValidateSet('', 'Disabled')][string]$PublicNetworkAccess = '', [int]$PauseSeconds = 5)
|    $isPrivate = ($PublicNetworkAccess -eq 'Disabled')
|    $kv = Get-SIKeyVault -VaultName $VaultName -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
|    $deleted = $null
|    if (-not $kv) { $deleted = Get-SIKeyVault -VaultName $VaultName -InRemovedState -Location $Location -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue }
|    $action = Get-SIKeyVaultEnsureAction -Found $kv -Deleted $deleted -ResourceGroupName $ResourceGroupName
|    switch ($action) {
|        'create' {
|            # Azure RBAC authorization (not access policies); a private install is private from birth (no public moment)
|            $kv = New-SIKeyVault -VaultName $VaultName -ResourceGroupName $ResourceGroupName -Location $Location -SubscriptionId $SubscriptionId -TenantId $TenantId -EnableRbacAuthorization $true -EnablePurgeProtection:$EnablePurgeProtection -PublicNetworkAccess $PublicNetworkAccess
|            $action = 'created'
|        }
|        'recover' { $kv = Restore-SIKeyVault -Deleted $deleted -ResourceGroupName $ResourceGroupName -Location $Location -SubscriptionId $SubscriptionId -TenantId $TenantId; $action = 'recovered' }
|    }
|    $rg = if ([string]$kv.ResourceGroupName) { [string]$kv.ResourceGroupName } else { $ResourceGroupName }
|    $c = Set-SIKeyVaultRule11 -VaultName $VaultName -ResourceGroupName $rg -SubscriptionId $SubscriptionId -Private:$isPrivate -PauseSeconds $PauseSeconds
|    # the vault's own facts (RBAC, purge protection) from the create / recover answer; its network from the read-back
|    $out = $c.Vault
|    if (-not [string]$out.VaultUri -and $kv) { $out = $kv }
|    [pscustomobject]@{ Action = $action; Vault = $out; Changed = $c.Changed; Shape = $c.Shape; Deleted = $deleted }
|}
|
|function Test-SIKeyVaultNameAvailability {
|    <# Microsoft.KeyVault checkNameAvailability: NameAvailable, Reason, Message. #>
|    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $r = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/Microsoft.KeyVault/checkNameAvailability") -ApiVersion '2022-07-01' -Body @{ name = $Name; type = 'Microsoft.KeyVault/vaults' }
|    return [pscustomobject]@{ NameAvailable = [bool]$r.nameAvailable; Reason = [string]$r.reason; Message = [string]$r.message }
|}
|
|function ConvertFrom-SIBase64UrlToHex {
|    param([string]$Text)
|    if (-not $Text) { return $null }
|    $p = $Text.Replace('-', '+').Replace('_', '/')
|    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
|    return (([Convert]::FromBase64String($p) | ForEach-Object { $_.ToString('X2') }) -join '')
|}
|
|function ConvertTo-SIKeyVaultCertificateObject {
|    param($J, [string]$VaultName, [string]$Name)
|    $x = $null
|    if ($J.cer) { try { $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String([string]$J.cer)) } catch { } }
|    $thumb = if ($x) { [string]$x.Thumbprint } else { ConvertFrom-SIBase64UrlToHex ([string]$J.x5t) }
|    $exp = $null
|    if ($J.attributes -and $J.attributes.exp) { try { $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$J.attributes.exp).UtcDateTime } catch { } }
|    [pscustomobject]@{
|        VaultName = $VaultName; Name = $Name; Id = [string]$J.id; SecretId = [string]$J.sid; KeyId = [string]$J.kid
|        Thumbprint = $thumb; Certificate = $x; Enabled = $(if ($J.attributes) { [bool]$J.attributes.enabled } else { $null }); Expires = $exp
|    }
|}
|
|function Get-SIKeyVaultCertificate {
|    <# One certificate (current version) from a vault's data plane; $null (non-terminating error) when absent. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name)
|    $uri = 'https://{0}.vault.azure.net/certificates/{1}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
|    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -What ("Key Vault certificate '{0}' in '{1}'" -f $Name, $VaultName)
|    if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The certificate '{0}' was not found in Key Vault '{1}'." -f $Name, $VaultName) -Target $Name; return }
|    return (ConvertTo-SIKeyVaultCertificateObject -J ($r.Content | ConvertFrom-Json) -VaultName $VaultName -Name $Name)
|}
|
|function Import-SIKeyVaultCertificate {
|    <# Imports a PFX (-FilePath or -CertificateBytes, optional -Password) into a vault as certificate -Name. #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][string]$VaultName,
|        [Parameter(Mandatory)][string]$Name,
|        [string]$FilePath,
|        [byte[]]$CertificateBytes,
|        $Password
|    )
|    if (-not $CertificateBytes) {
|        if (-not $FilePath) { throw 'Import-SIKeyVaultCertificate needs -FilePath or -CertificateBytes.' }
|        $CertificateBytes = [System.IO.File]::ReadAllBytes($FilePath)
|    }
|    $pw = if ($Password -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $Password).Password } else { [string]$Password }
|    $body = [ordered]@{ value = [Convert]::ToBase64String($CertificateBytes); policy = @{ secret_props = @{ contentType = 'application/x-pkcs12' } } }
|    if ($pw) { $body['pwd'] = $pw }
|    $uri = 'https://{0}.vault.azure.net/certificates/{1}/import?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
|    $r = Invoke-SIAzRestRequest -Method POST -Uri $uri -Audience KeyVault -Body ($body | ConvertTo-Json -Depth 5 -Compress) -What ("Importing certificate '{0}' into Key Vault '{1}'" -f $Name, $VaultName)
|    return (ConvertTo-SIKeyVaultCertificateObject -J ($r.Content | ConvertFrom-Json) -VaultName $VaultName -Name $Name)
|}
|
|# =====================================================================================================================
|#  (3) Resource providers
|# =====================================================================================================================
|
|function Get-SIResourceProvider {
|    <# A resource provider's registration in the subscription: ProviderNamespace, RegistrationState, ResourceTypes. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ProviderNamespace, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $p = Invoke-SIArm -Path ("/subscriptions/$sub/providers/$ProviderNamespace") -ApiVersion '2021-04-01' -AllowNotFound
|    if (-not $p) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The resource provider '{0}' was not found." -f $ProviderNamespace) -Target $ProviderNamespace; return }
|    return [pscustomobject]@{ ProviderNamespace = [string]$p.namespace; RegistrationState = [string]$p.registrationState; ResourceTypes = @($p.resourceTypes); Id = [string]$p.id }
|}
|
|function Get-SISetupResourceProviderList {
|    <#
|        PURE. #564: EVERY resource provider a SecurityInsight install WRITES to -- the guided install checks and registers
|        these before the first resource. Container Apps (Microsoft.App), the registry, the workspace, diagnostic settings and
|        data collection (Microsoft.Insights), the managed identities, the Key Vault, the storage account; Pro adds Azure SQL.
|        Microsoft.Network is NOT listed: SecurityInsight creates no network resource (no virtual network, private endpoint
|        or public IP; the Container Apps environment is a consumption one without a virtual network).
|    #>
|    param([switch]$Pro)
|    $l = @('Microsoft.App', 'Microsoft.OperationalInsights', 'Microsoft.Insights', 'Microsoft.ContainerRegistry', 'Microsoft.ManagedIdentity', 'Microsoft.KeyVault', 'Microsoft.Storage')
|    if ($Pro) { $l += 'Microsoft.Sql' }
|    $l
|}
|
|function Register-SIResourceProvider {
|    <# Registers a resource provider in the subscription (idempotent; Azure finishes it in the background). #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ProviderNamespace, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $p = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/$ProviderNamespace/register") -ApiVersion '2021-04-01'
|    return [pscustomobject]@{ ProviderNamespace = $ProviderNamespace; RegistrationState = $(if ($p) { [string]$p.registrationState } else { 'Registering' }) }
|}
|
|function Get-SIArmApiVersion {
|    <# The newest non-preview api-version ARM offers for -ResourceType ('Microsoft.Sql/servers', 'Microsoft.Sql/servers/databases'). Cached. #>
|    param([Parameter(Mandatory)][string]$ResourceType, [string]$SubscriptionId)
|    $st = Get-SIAzRestState
|    $key = 'apiver|' + $ResourceType.ToLowerInvariant()
|    if ($st.Cache.ContainsKey($key)) { return $st.Cache[$key] }
|    $ns, $rest = $ResourceType -split '/', 2
|    $p = Get-SIResourceProvider -ProviderNamespace $ns -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
|    $rt = @($p.ResourceTypes | Where-Object { [string]$_.resourceType -eq $rest }) | Select-Object -First 1
|    $v = @(@($rt.apiVersions) | Where-Object { $_ -and $_ -notmatch 'preview' } | Sort-Object -Descending) | Select-Object -First 1
|    if (-not $v) { $v = @(@($rt.apiVersions) | Sort-Object -Descending) | Select-Object -First 1 }
|    if (-not $v) { throw ("Azure does not offer the resource type '{0}' in this subscription." -f $ResourceType) }
|    $st.Cache[$key] = [string]$v
|    return [string]$v
|}
|
|# =====================================================================================================================
|#  (4) Role assignments: delete, and "what does this principal hold, through its groups too"
|# =====================================================================================================================
|
|function Remove-SIRoleAssignment {
|    <#
|        Deletes a role assignment: -RoleAssignmentId, or every assignment of -RoleDefinitionName to -ObjectId exactly at
|        -Scope. Returns what was removed. Absent = nothing to do (idempotent).
|    #>
|    [CmdletBinding()]
|    param([string]$RoleAssignmentId, [string]$ObjectId, [string]$RoleDefinitionName, [string]$Scope)
|    $ids = @()
|    if ($RoleAssignmentId) { $ids = @($RoleAssignmentId) }
|    else {
|        if (-not ($ObjectId -and $RoleDefinitionName -and $Scope)) { throw 'Remove-SIRoleAssignment needs -RoleAssignmentId, or -ObjectId with -RoleDefinitionName and -Scope.' }
|        $ids = @(Get-SIAzRoleAssignmentRest -ObjectId $ObjectId -Scope $Scope -RoleDefinitionName $RoleDefinitionName |
|                 Where-Object { ([string]$_.Scope).TrimEnd('/') -ieq $Scope.TrimEnd('/') } | ForEach-Object { [string]$_.RoleAssignmentId })
|    }
|    foreach ($id in $ids) {
|        $null = Invoke-SIArm -Method DELETE -Path $id -ApiVersion '2022-04-01' -AllowNotFound
|        [pscustomobject]@{ RoleAssignmentId = $id; ObjectId = $ObjectId; RoleDefinitionName = $RoleDefinitionName; Scope = $Scope }
|    }
|}
|
|function New-SIRoleAssignment {
|    <#
|        Assigns -RoleDefinitionName to -ObjectId at -Scope, with the principal's type stated (-PrincipalType, default
|        ServicePrincipal) -- what New-AzRoleAssignment -ObjectType did: ARM then accepts a principal that was created
|        seconds ago and has not replicated yet. Same output shape as New-SIAzRoleAssignment.
|    #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][string]$ObjectId,
|        [Parameter(Mandatory)][string]$Scope,
|        [Parameter(Mandatory)][string]$RoleDefinitionName,
|        [ValidateSet('ServicePrincipal', 'User', 'Group', 'ForeignGroup', 'Device')][string]$PrincipalType = 'ServicePrincipal'
|    )
|    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
|    $def = @(Get-SIAzRestRoleDefinitions -Scope $subScope | Where-Object { [string]$_.properties.roleName -eq $RoleDefinitionName }) | Select-Object -First 1
|    if (-not $def) { throw ("The role definition '{0}' was not found at scope '{1}'." -f $RoleDefinitionName, $subScope) }
|    $body = @{ properties = @{ roleDefinitionId = [string]$def.id; principalId = $ObjectId; principalType = $PrincipalType } }
|    $a = Invoke-SIArm -Method PUT -Path ($Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments/' + [guid]::NewGuid().ToString()) -ApiVersion '2022-04-01' -Body $body
|    return [pscustomobject]@{ RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = $Scope; RoleDefinitionName = $RoleDefinitionName; RoleDefinitionId = [string]$def.name; ObjectId = $ObjectId; ObjectType = $PrincipalType }
|}
|
|function Get-SIRoleAssignmentAssignedTo {
|    <#
|        The role assignments that apply to -ObjectId at or above -Scope, INCLUDING those it holds through a group
|        (ARM's assignedTo() filter -- what Get-AzRoleAssignment -ExpandPrincipalGroups returned). Same object shape as
|        Get-SIAzRoleAssignment.
|    #>
|    param([Parameter(Mandatory)][string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName)
|    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SISetupSubscriptionId) }
|    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments?$filter=' + [uri]::EscapeDataString(("assignedTo('{0}')" -f $ObjectId))
|    $items = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
|    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
|    $defs = @{}
|    foreach ($d in @(Get-SIAzRestRoleDefinitions -Scope $subScope)) { $defs[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName }
|    foreach ($a in $items) {
|        $rdId = ([string]$a.properties.roleDefinitionId -split '/')[-1]
|        $rdName = $defs[$rdId.ToLowerInvariant()]
|        if ($RoleDefinitionName -and $rdName -ne $RoleDefinitionName) { continue }
|        [pscustomobject]@{
|            RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = [string]$a.properties.scope
|            RoleDefinitionName = $rdName; RoleDefinitionId = $rdId; ObjectId = [string]$a.properties.principalId; ObjectType = [string]$a.properties.principalType
|        }
|    }
|}
|
|# =====================================================================================================================
|#  (5) Typed ARM reads
|# =====================================================================================================================
|
|function Get-SIArmResource {
|    <#
|        One resource by -ResourceId (api-version given, or the newest ARM offers for its type), or every resource of
|        -ResourceType (and -Name / -ResourceGroupName) in the subscription -- what Get-AzResource did. Objects carry
|        ResourceId, Id, Name, ResourceGroupName, ResourceType, Location, Tags, Properties, Identity.
|    #>
|    [CmdletBinding()]
|    param([string]$ResourceId, [string]$ResourceType, [string]$Name, [string]$ResourceGroupName, [string]$ApiVersion, [string]$SubscriptionId)
|    $conv = {
|        param($R)
|        [pscustomobject]@{
|            ResourceId = [string]$R.id; Id = [string]$R.id; Name = [string]$R.name; ResourceGroupName = (Get-SIArmResourceGroupFromId $R.id)
|            ResourceType = [string]$R.type; Type = [string]$R.type; Location = [string]$R.location; Tags = $R.tags; Kind = [string]$R.kind
|            Sku = $R.sku; Properties = $R.properties; Identity = $R.identity
|        }
|    }
|    if ($ResourceId) {
|        if (-not $ApiVersion) {
|            $t = if ($ResourceId -match '/providers/([^/]+)/(.+)$') {
|                $segs = $Matches[2] -split '/'
|                $Matches[1] + '/' + ((0..($segs.Count - 1) | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { $segs[$_] }) -join '/')
|            } else { $null }
|            if (-not $t) { throw ("Not an Azure resource id: {0}" -f $ResourceId) }
|            $ApiVersion = Get-SIArmApiVersion -ResourceType $t
|        }
|        $r = Invoke-SIArm -Path $ResourceId -ApiVersion $ApiVersion -AllowNotFound
|        if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The resource '{0}' was not found." -f $ResourceId) -Target $ResourceId; return }
|        return (& $conv $r)
|    }
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $f = @()
|    if ($ResourceType) { $f += ("resourceType eq '{0}'" -f $ResourceType) }
|    if ($Name) { $f += ("name eq '{0}'" -f $Name) }
|    $base = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/resources" } else { "/subscriptions/$sub/resources" }
|    if ($f.Count) { $base += '?$filter=' + [uri]::EscapeDataString(($f -join ' and ')) }
|    foreach ($r in @(Invoke-SIArm -Path $base -ApiVersion '2021-04-01' -List)) {
|        if ($Name -and [string]$r.name -ne $Name) { continue }
|        & $conv $r
|    }
|}
|
|function Get-SIVirtualMachine {
|    <# A VM: Name, Id, ResourceGroupName, Location, Identity (type, principalId, userAssignedIdentities), VmId. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $v = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Compute/virtualMachines/$Name") -ApiVersion '2023-09-01' -AllowNotFound
|    if (-not $v) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The virtual machine '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|    [pscustomobject]@{ Name = [string]$v.name; Id = [string]$v.id; ResourceGroupName = $ResourceGroupName; Location = [string]$v.location; VmId = [string]$v.properties.vmId; Identity = $v.identity; Tags = $v.tags }
|}
|
|function Get-SIUserAssignedIdentity {
|    <# A user-assigned managed identity: Name, Id, ClientId, PrincipalId, TenantId, Location. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $u = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name") -ApiVersion '2023-01-31' -AllowNotFound
|    if (-not $u) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The managed identity '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|    [pscustomobject]@{
|        Name = [string]$u.name; Id = [string]$u.id; ResourceGroupName = $ResourceGroupName; Location = [string]$u.location
|        ClientId = [string]$u.properties.clientId; PrincipalId = [string]$u.properties.principalId; TenantId = [string]$u.properties.tenantId
|    }
|}
|
|function New-SIUserAssignedIdentity {
|    <# Creates (or returns) a user-assigned managed identity. Idempotent: an existing one is returned unchanged. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Location,
|          [string]$SubscriptionId, [hashtable]$Tag)
|    $have = Get-SIUserAssignedIdentity -ResourceGroupName $ResourceGroupName -Name $Name -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
|    if ($have) { return $have }
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $body = @{ location = $Location }
|    if ($Tag -and $Tag.Count) { $body.tags = $Tag }
|    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name"
|    # The create's own answer carries the two ids; a read right after it can still say "not found", or come without them.
|    # So: the answer first, then the identity re-read (6 x 5 s) until BOTH ids are there -- and a clear stop when they
|    # never come: everything after this (role assignments, the jobs' sign-in) needs them.
|    $u = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-01-31' -Body $body
|    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
|    for ($i = 0; $i -lt 6; $i++) {
|        if ($u -and $u.properties -and [string]$u.properties.clientId -and [string]$u.properties.principalId) { break }
|        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
|        $u = Invoke-SIArm -Path $path -ApiVersion '2023-01-31' -AllowNotFound
|    }
|    if (-not $u -or -not $u.properties -or -not [string]$u.properties.clientId -or -not [string]$u.properties.principalId) {
|        throw ("The managed identity '{0}' was created in resource group '{1}', but Azure does not show its client id and principal id yet -- run the same command again in a minute." -f $Name, $ResourceGroupName)
|    }
|    [pscustomobject]@{
|        Name = [string]$u.name; Id = [string]$u.id; ResourceGroupName = $ResourceGroupName; Location = [string]$u.location
|        ClientId = [string]$u.properties.clientId; PrincipalId = [string]$u.properties.principalId; TenantId = [string]$u.properties.tenantId
|    }
|}
|
|function Get-SIVmIdentityPatchBody {
|    <#
|        PURE. The 'identity' body that ADDS a user-assigned identity to a VM and keeps every identity it already has: a
|        system-assigned identity stays (type 'SystemAssigned, UserAssigned'), other user-assigned ones stay listed.
|        Returns $null when the identity is already attached (nothing to change).
|    #>
|    param([AllowNull()]$CurrentIdentity, [Parameter(Mandatory)][string]$IdentityResourceId)
|    $type = if ($CurrentIdentity -and $CurrentIdentity.PSObject.Properties['type']) { [string]$CurrentIdentity.type } else { '' }
|    $ids = [ordered]@{}
|    if ($CurrentIdentity -and $CurrentIdentity.PSObject.Properties['userAssignedIdentities'] -and $CurrentIdentity.userAssignedIdentities) {
|        foreach ($p in $CurrentIdentity.userAssignedIdentities.PSObject.Properties) { $ids[$p.Name] = @{} }
|    }
|    if (@($ids.Keys | Where-Object { "$_" -ieq $IdentityResourceId }).Count) { return $null }
|    $ids[$IdentityResourceId] = @{}
|    $newType = if ($type -match '(?i)SystemAssigned') { 'SystemAssigned, UserAssigned' } else { 'UserAssigned' }
|    @{ identity = @{ type = $newType; userAssignedIdentities = $ids } }
|}
|
|function Add-SIVmUserAssignedIdentity {
|    <# Attaches a user-assigned identity to an Azure VM, keeping the identities it has. Returns $true when it changed. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$VmName,
|          [Parameter(Mandatory)][string]$IdentityResourceId, [string]$SubscriptionId)
|    $vm = Get-SIVirtualMachine -ResourceGroupName $ResourceGroupName -Name $VmName -SubscriptionId $SubscriptionId -ErrorAction Stop
|    $body = Get-SIVmIdentityPatchBody -CurrentIdentity $vm.Identity -IdentityResourceId $IdentityResourceId
|    if (-not $body) { return $false }
|    $null = Invoke-SIArm -Method PATCH -Path $vm.Id -ApiVersion '2023-09-01' -Body $body
|    $true
|}
|
|function Get-SISqlServer {
|    <# Azure SQL logical servers: ServerName, ResourceId, ResourceGroupName, Location, FullyQualifiedDomainName, Administrators. #>
|    [CmdletBinding()]
|    param([string]$ResourceGroupName, [string]$ServerName, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $conv = {
|        param($S)
|        [pscustomobject]@{
|            ServerName = [string]$S.name; ResourceId = [string]$S.id; ResourceGroupName = (Get-SIArmResourceGroupFromId $S.id); Location = [string]$S.location
|            FullyQualifiedDomainName = [string]$S.properties.fullyQualifiedDomainName; Administrators = $S.properties.administrators
|            PublicNetworkAccess = [string]$S.properties.publicNetworkAccess; Tags = $S.tags
|        }
|    }
|    if ($ResourceGroupName -and $ServerName) {
|        $s = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName") -ApiVersion '2021-11-01' -AllowNotFound
|        if (-not $s) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The SQL server '{0}' was not found in resource group '{1}'." -f $ServerName, $ResourceGroupName) -Target $ServerName; return }
|        return (& $conv $s)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers" } else { "/subscriptions/$sub/providers/Microsoft.Sql/servers" }
|    foreach ($s in @(Invoke-SIArm -Path $path -ApiVersion '2021-11-01' -List)) { if (-not $ServerName -or [string]$s.name -eq $ServerName) { & $conv $s } }
|}
|
|function Get-SISqlDatabase {
|    <# Databases of an Azure SQL server: DatabaseName, ResourceId, ServerName, Status, SkuName. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$ServerName, [string]$DatabaseName, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $base = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Sql/servers/$ServerName/databases"
|    $conv = { param($D) [pscustomobject]@{ DatabaseName = [string]$D.name; ResourceId = [string]$D.id; ServerName = $ServerName; ResourceGroupName = $ResourceGroupName; Location = [string]$D.location; Status = [string]$D.properties.status; SkuName = [string]$D.sku.name } }
|    if ($DatabaseName) {
|        $d = Invoke-SIArm -Path ($base + '/' + $DatabaseName) -ApiVersion '2021-11-01' -AllowNotFound
|        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The database '{0}' was not found on SQL server '{1}'." -f $DatabaseName, $ServerName) -Target $DatabaseName; return }
|        return (& $conv $d)
|    }
|    foreach ($d in @(Invoke-SIArm -Path $base -ApiVersion '2021-11-01' -List)) { & $conv $d }
|}
|
|function Get-SICognitiveServicesAccount {
|    <# Azure OpenAI / Cognitive Services accounts: AccountName, Id, ResourceGroupName, Kind, Endpoint, Location. #>
|    [CmdletBinding()]
|    param([string]$ResourceGroupName, [string]$Name, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $conv = { param($A) [pscustomobject]@{ AccountName = [string]$A.name; Id = [string]$A.id; ResourceGroupName = (Get-SIArmResourceGroupFromId $A.id); Kind = [string]$A.kind; Location = [string]$A.location; Endpoint = [string]$A.properties.endpoint; Sku = [string]$A.sku.name } }
|    if ($ResourceGroupName -and $Name) {
|        $a = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts/$Name") -ApiVersion '2023-05-01' -AllowNotFound
|        if (-not $a) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Azure AI account '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|        return (& $conv $a)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.CognitiveServices/accounts" } else { "/subscriptions/$sub/providers/Microsoft.CognitiveServices/accounts" }
|    foreach ($a in @(Invoke-SIArm -Path $path -ApiVersion '2023-05-01' -List)) { if (-not $Name -or [string]$a.name -eq $Name) { & $conv $a } }
|}
|
|function Get-SITenant {
|    <# The tenants the signed-in account can see: Id, TenantId, Name, DefaultDomain, Domains. -TenantId picks one. #>
|    [CmdletBinding()]
|    param([string]$TenantId)
|    $found = $false
|    foreach ($t in @(Invoke-SIArm -Path '/tenants' -ApiVersion '2022-12-01' -List)) {
|        if ($TenantId -and [string]$t.tenantId -ne $TenantId) { continue }
|        $found = $true
|        [pscustomobject]@{ Id = [string]$t.tenantId; TenantId = [string]$t.tenantId; Name = [string]$t.displayName; DefaultDomain = [string]$t.defaultDomain; Domains = @($t.domains); TenantCategory = [string]$t.tenantCategory }
|    }
|    if ($TenantId -and -not $found) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The tenant '{0}' is not visible to the signed-in account." -f $TenantId) -Target $TenantId }
|}
|
|function Get-SILogAnalyticsTable {
|    <# One Log Analytics table (or all): Name, Id, Plan, RetentionInDays, TotalRetentionInDays, Schema (columns). #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$WorkspaceName, [string]$TableName, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $base = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables"
|    $conv = { param($T) [pscustomobject]@{ Name = [string]$T.name; Id = [string]$T.id; Plan = [string]$T.properties.plan; RetentionInDays = $T.properties.retentionInDays; TotalRetentionInDays = $T.properties.totalRetentionInDays; Schema = $T.properties.schema; ProvisioningState = [string]$T.properties.provisioningState } }
|    if ($TableName) {
|        $t = Invoke-SIArm -Path ($base + '/' + $TableName) -ApiVersion '2022-10-01' -AllowNotFound
|        if (-not $t) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The table '{0}' was not found in workspace '{1}'." -f $TableName, $WorkspaceName) -Target $TableName; return }
|        return (& $conv $t)
|    }
|    foreach ($t in @(Invoke-SIArm -Path $base -ApiVersion '2022-10-01' -List)) { & $conv $t }
|}
|
|# =====================================================================================================================
|#  (7) Storage management through ARM (no data-plane role and no account key needed)
|# =====================================================================================================================
|
|function Get-SIStorageArmChildPath {
|    param([string]$SubscriptionId, [string]$ResourceGroupName, [string]$AccountName, [ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [string]$Name)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $svc = switch ($Kind) { 'Table' { 'tableServices/default/tables' } 'Container' { 'blobServices/default/containers' } 'Queue' { 'queueServices/default/queues' } }
|    return ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}/{3}/{4}' -f $sub, $ResourceGroupName, $AccountName, $svc, $Name)
|}
|
|function Get-SIStorageArmChild {
|    <# A table / blob container / queue of a storage account, read through ARM; non-terminating not-found. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName,
|          [Parameter(Mandatory)][ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $p = Get-SIStorageArmChildPath -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Kind $Kind -Name $Name
|    $r = Invoke-SIArm -Path $p -ApiVersion '2023-01-01' -AllowNotFound
|    if (-not $r) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The {0} '{1}' was not found in storage account '{2}'." -f $Kind.ToLowerInvariant(), $Name, $AccountName) -Target $Name; return }
|    return [pscustomobject]@{ Name = [string]$r.name; Id = [string]$r.id; Kind = $Kind; Properties = $r.properties }
|}
|
|function New-SIStorageArmChild {
|    <# Creates (PUT, idempotent) a table / private blob container / queue through ARM. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName,
|          [Parameter(Mandatory)][ValidateSet('Table', 'Container', 'Queue')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $p = Get-SIStorageArmChildPath -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Kind $Kind -Name $Name
|    $body = if ($Kind -eq 'Container') { @{ properties = @{ publicAccess = 'None' } } } else { @{ properties = @{} } }
|    $r = Invoke-SIArm -Method PUT -Path $p -ApiVersion '2023-01-01' -Body $body
|    return [pscustomobject]@{ Name = $(if ($r) { [string]$r.name } else { $Name }); Id = $(if ($r) { [string]$r.id } else { $p }); Kind = $Kind }
|}
|
|function Get-SIStorageLifecyclePolicy {
|    <# The account's lifecycle management policy: .Rules (the raw ARM rules: name, enabled, type, definition); $null when there is none. #>
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $p = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$AccountName/managementPolicies/default") -ApiVersion '2023-01-01' -AllowNotFound
|    if (-not $p) { return $null }
|    return [pscustomobject]@{ Id = [string]$p.id; Rules = @($p.properties.policy.rules | Where-Object { $_ }); LastModifiedTime = $p.properties.lastModifiedTime }
|}
|
|function Set-SIStorageLifecyclePolicy {
|    <# REPLACES the account's lifecycle policy with -Rules (raw ARM rule objects). Callers merge, see New-SIStorageLifecycleDeleteRule. #>
|    param([Parameter(Mandatory)][string]$ResourceGroupName, [Parameter(Mandatory)][string]$AccountName, [Parameter(Mandatory)][object[]]$Rules, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $p = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$AccountName/managementPolicies/default") -ApiVersion '2023-01-01' `
|             -Body @{ properties = @{ policy = @{ rules = @($Rules) } } }
|    return [pscustomobject]@{ Id = [string]$p.id; Rules = @($p.properties.policy.rules | Where-Object { $_ }) }
|}
|
|function New-SIStorageLifecycleDeleteRule {
|    <# PURE. A lifecycle rule that deletes block blobs under -PrefixMatch N days after their last modification. #>
|    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$PrefixMatch, [Parameter(Mandatory)][int]$DaysAfterModification)
|    return [ordered]@{
|        enabled    = $true
|        name       = $Name
|        type       = 'Lifecycle'
|        definition = [ordered]@{
|            actions = @{ baseBlob = @{ delete = @{ daysAfterModificationGreaterThan = $DaysAfterModification } } }
|            filters = [ordered]@{ blobTypes = @('blockBlob'); prefixMatch = @($PrefixMatch) }
|        }
|    }
|}
|
|function Get-SIStorageLifecycleRuleDeleteDays {
|    <# PURE. The delete-after-modification days of a raw lifecycle rule ($null when it has none). #>
|    param($Rule)
|    try { return $Rule.definition.actions.baseBlob.delete.daysAfterModificationGreaterThan } catch { return $null }
|}
|
|function Test-SIStorageAccountNameAvailability {
|    <# Microsoft.Storage checkNameAvailability: NameAvailable, Reason, Message. #>
|    param([Parameter(Mandatory)][string]$Name, [string]$SubscriptionId)
|    $sub = Get-SISetupSubscriptionId -SubscriptionId $SubscriptionId
|    $r = Invoke-SIArm -Method POST -Path ("/subscriptions/$sub/providers/Microsoft.Storage/checkNameAvailability") -ApiVersion '2023-01-01' -Body @{ name = $Name; type = 'Microsoft.Storage/storageAccounts' }
|    return [pscustomobject]@{ NameAvailable = [bool]$r.nameAvailable; Reason = [string]$r.reason; Message = [string]$r.message }
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-AzRest.ps1'] = @{ Sha256 = '0ca211c9c692f9ef44f2cec4d69e7c06842fe88a30f02cf9e2238a5e21e3b05a'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- Azure over plain REST, without the Az.* PowerShell modules (REQUIREMENTS 9.3, decision 2:
|    "no PS module dependencies ... go pure REST").
|
|    SecurityInsight runs with NO PowerShell modules: every Azure call is plain REST with tokens from SecurityInsight's
|    own sign-in (managed identity, certificate client assertion, client secret -- the run's decision). There is no
|    switch and no module path: no Az module is loaded, installed or needed anywhere in the runtime.
|
|    The call sites keep the familiar names with 'SIAz' in place of 'Az' (Invoke-SIAzOperationalInsightsQuery,
|    Search-SIAzGraph, ...). Each wrapper takes the arguments the call sites pass and does the job over REST (its *Rest
|    twin), returning objects with the properties the call sites read. Connect-SIAzAccount only RECORDS which identity to
|    sign in as; each REST call mints its token when it needs one.
|    The REST building blocks are public and usable directly:
|        Get-SIAzureToken -Audience Arm|LaQuery|Storage|KeyVault|Graph      one token function per audience
|        Invoke-SILaQuery                                                   Log Analytics data plane (api.loganalytics.io)
|        Invoke-SIArm                                                       ARM GET/PUT/PATCH/DELETE, list with nextLink
|        Search-SIResourceGraph                                             Resource Graph, every page ($skipToken)
|        Get-SIKeyVaultSecretValue                                          one secret, as plain text
|        Get-SIBlobContent / Set-SIBlobContent / Get-SIBlobList / ...       blob data plane (OAuth, x-ms-version)
|        Send-SIQueueMessage / Receive-SIQueueMessage / Remove-SIQueueMessage
|        Get-SITableEntity / Set-SITableEntity                              table data plane (upsert)
|
|    HTTP: every call of this file goes through Invoke-SIAzRestHttp. Token requests (client secret) go through
|    SI-LogIngest.ps1's Invoke-SILogIngestHttp -- the same HttpWebRequest shape; tests mock both seams.
|    Token hook: $global:SI_TokenProvider = { param($Resource) ... } (a scriptblock returning a bearer token) is consulted
|    first by Get-SIAzureToken and Get-SILogIngestToken when set -- for a host with its own sign-in, e.g. setup.
|
|    Retry rule (CLAUDE.md working rule 4): 429 / 408 / 5xx / no response -> wait (Retry-After when sent) and retry
|    in-run; 401 once -> refresh the token and repeat once; any other 4xx -> FAIL FAST with the service's own body.
|
|    PS 5.1 safe (no ?. / ??, no RSA.ImportFromPem); works on pwsh 7 and in a Linux container (no Cert: drive needed).
|    Ships in both editions and never references a Pro path.
|#>
|
|# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.
|
|# #730: the streaming Log Analytics reader (Invoke-SILaQuery reads Risk Analysis' answers with it; compiled on first use)
|if (-not (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore)) {
|    $__siLaStream = [System.IO.Path]::Combine($PSScriptRoot, 'SI-LaStreamRead.ps1')
|    if ([System.IO.File]::Exists($__siLaStream)) { . $__siLaStream }
|}
|
|# ONE connect path (#524, owner 2026-10-09 "modern single connect only"): SecurityInsight's own REST token client --
|# managed identity, certificate, client secret (and, in setup, a person's own sign-in). The old sign-in mode "AzContext"
|# (#413: borrow the current Azure / Invardia Support session of the process) and its file SI-AzSession.ps1 are gone.
|#
|# ONE TOKEN SOURCE more for that same path (#524, owner 2026-10-09 via Invardia: "support installs use TOKENS, never the
|# secret"): in a shell where Invardia's Connect-InvardiaSupport is open, its function Get-InvardiaSupportToken -Resource <r>
|# returns a bearer token as the customer's Invardia support app (cached by Invardia, tid + appid verified there). SI takes
|# EVERY token from it -- Mode 'Support' -- and still checks each token's tenant against the tenant it works in. No session
|# state is read (only the token), no Az / Graph cmdlet is called. Outside a support session nothing changes.
|#
|# THE SESSION ITSELF IS USED (owner 2026-10-12: a change in an environment is made inside its Invardia Support session, so
|# it is recorded in that environment's audit log). Get-SISupportSession is the ONE place that says whether a session is
|# open: Invardia's $global:InvardiaSupportState names a tenant AND its recording command Invoke-InvardiaSupportRequest is
|# in the shell. With a session, who SecurityInsight works as (tenant, app, subscriptions) is read from it -- no sign-in of
|# SecurityInsight's own and no token request -- and every HTTP call goes through the recording command (Invoke-SISupportHttp).
|
|function Get-SISupportedSignInText {
|    <# PURE. The sign-ins SecurityInsight supports, for an error message. #>
|    'a managed identity (SI_AuthMethod = ManagedIdentity), an app with a certificate (SI_SPN_AppId + SI_SPN_TenantId + SI_SPN_CertThumbprint), an app with a client secret (SI_SPN_AppId + SI_SPN_TenantId + SI_SPN_Secret), or the tokens of an Invardia support session (Get-InvardiaSupportToken). An Azure session of this PowerShell process (Connect-AzAccount, az login) is never used'
|}
|
|function Get-SISupportSession {
|    <#
|        THE ONE PLACE that says whether an Invardia Support session is open in this PowerShell session, and what it names.
|        Open = Invardia's $global:InvardiaSupportState is a hashtable that names a tenant AND its recording command
|        Invoke-InvardiaSupportRequest is here (Test-Path Function: -- never Get-Command, which can load a module).
|        $null when there is none (Disconnect-InvardiaSupport empties the state). Never guessed: a state WITHOUT the
|        recording command is said and stops the caller -- nothing could be recorded.
|        Returns TenantId, AppId, Environment (the handle), EnvironmentId, SessionId, Subscriptions (lower case; the ones the
|        environment names), SubscriptionId (the first of them, '' when it names none), SubscriptionName.
|    #>
|    $s = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
|    if (-not ($s -is [hashtable])) { return $null }
|    $tid = [string]$s['TenantId']
|    if ([string]::IsNullOrWhiteSpace($tid)) { return $null }
|    if (-not (Test-Path -LiteralPath 'Function:\Invoke-InvardiaSupportRequest')) {
|        throw ('An Invardia Support session is noted in this PowerShell session (tenant {0}), but its recording command Invoke-InvardiaSupportRequest is not here, so nothing SecurityInsight does could be recorded. Nothing was done. Open the session again (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>''), or end it (Disconnect-InvardiaSupport) and work with your own sign-in.' -f $tid)
|    }
|    $subs = @(@($s['Subscriptions']) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
|    $first = ''
|    if ($subs.Count) { $first = [string]$subs[0] }
|    return [pscustomobject]@{
|        TenantId = $tid.Trim(); AppId = [string]$s['AppId']; Environment = [string]$s['Environment']; EnvironmentId = [string]$s['EnvironmentId']
|        SessionId = [string]$s['SessionId']; Subscriptions = [string[]]$subs; SubscriptionId = $first; SubscriptionName = [string]$s['SubscriptionName']
|    }
|}
|
|function Get-SISupportSessionName {
|    <# PURE. How a Support session is named in a message: its environment handle, else its tenant. #>
|    param($Session)
|    if ($Session -and [string]$Session.Environment) { return [string]$Session.Environment }
|    if ($Session) { return ('tenant {0}' -f $Session.TenantId) }
|    return ''
|}
|
|function Assert-SISupportSubscription {
|    <# In a Support session only a subscription the environment names is worked in: any other is REFUSED (throws). A session
|       whose environment names no subscription refuses none (Invardia's own rule). No session = nothing to check. #>
|    param([string]$SubscriptionId, $Session)
|    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { return }
|    if (-not $Session) { $Session = Get-SISupportSession }
|    if (-not $Session) { return }
|    $named = @($Session.Subscriptions)
|    if ($named.Count -and $named -notcontains $SubscriptionId.Trim().ToLowerInvariant()) {
|        throw ('Subscription {0} is not one the Invardia Support session for {1} names ({2}) -- refused, nothing was done there. Use a subscription of this environment, or open the Support session of the environment that owns {0}.' -f $SubscriptionId, (Get-SISupportSessionName $Session), ($named -join ', '))
|    }
|}
|
|function Test-SISupportTokenSource {
|    <# Is an Invardia Support session open in this shell? (Get-SISupportSession decides -- the one place.) #>
|    return [bool](Get-SISupportSession)
|}
|
|function Get-SISupportExpectedTenantId {
|    <# The tenant SI works in, which the Support session must be for: -TenantId, else the configured one. Empty = the
|       session's own. #>
|    param([string]$TenantId)
|    if ($TenantId) { return $TenantId }
|    return [string](Get-SIAzRestValue 'SI_SPN_TenantId', 'SpnTenantId', 'AzureTenantId', 'TenantId')
|}
|
|function Get-SISupportToken {
|    <#
|        A bearer token for -Resource from the Invardia Support session; its 'tid' must be -TenantId (refused otherwise).
|        ONLY for what has no HTTP request the recording command can send -- the SQL sign-in of a database step, the
|        container registry's own token exchange, reading who the Support app is from its token. Invardia records that the
|        token was issued; what is done with it is not recorded. Every HTTP call goes through Invoke-SISupportHttp instead
|        and asks for no token here.
|    #>
|    param([Parameter(Mandatory)][string]$Resource, [string]$TenantId, [switch]$ForceRefresh)
|    if (-not (Get-SISupportSession)) { throw 'No Invardia Support session is open in this PowerShell session (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>'').' }
|    if (-not (Test-Path -LiteralPath 'Function:\Get-InvardiaSupportToken')) { throw ('The Invardia Support session in this PowerShell session has no token command (Get-InvardiaSupportToken), so no token for {0} can be taken from it. Open the session again (Connect-InvardiaSupport).' -f $Resource) }
|    $p = @{ Resource = $Resource.TrimEnd('/') }
|    if ($ForceRefresh) { $p['ForceRefresh'] = $true }
|    $tok = [string](Get-InvardiaSupportToken @p)
|    if ([string]::IsNullOrWhiteSpace($tok)) { throw ('The Invardia support session returned no token for {0}.' -f $Resource) }
|    $c = ConvertFrom-SIJwtPayload $tok
|    if (-not $c -or -not [string]$c.tid) { throw ('The Invardia support token for {0} could not be read (no tenant in it) -- refused.' -f $Resource) }
|    if ($TenantId -and [string]$c.tid -ne $TenantId) {
|        throw ('The Invardia support token for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f $Resource, $c.tid, $TenantId)
|    }
|    return $tok
|}
|
|function Get-SISupportAuth {
|    <# The Auth hashtable of the Invardia Support session: Mode 'Support', app + tenant + first subscription read from the
|       SESSION (Get-SISupportSession) -- no token is asked for. Refused when the session is for another tenant than
|       -TenantId / the configured one. ObjectId is not known here (Get-SISetupSignedInObjectId finds it when asked). #>
|    param([string]$TenantId)
|    $sess = Get-SISupportSession
|    if (-not $sess) { throw 'No Invardia Support session is open in this PowerShell session (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>'').' }
|    $want = Get-SISupportExpectedTenantId -TenantId $TenantId
|    if ($want -and $want -ne $sess.TenantId) {
|        throw ('The Invardia Support session for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f (Get-SISupportSessionName $sess), $sess.TenantId, $want)
|    }
|    return @{ Mode = 'Support'; AppId = [string]$sess.AppId; TenantId = [string]$sess.TenantId; ObjectId = $null; SubscriptionId = [string]$sess.SubscriptionId
|              Environment = [string]$sess.Environment; EnvironmentId = [string]$sess.EnvironmentId; SessionId = [string]$sess.SessionId }
|}
|
|function Sync-SISupportConnection {
|    <#
|        Keeps the recorded sign-in of this process in step with the Invardia Support session, and returns the session
|        ($null = none):
|          * no session, but the recorded sign-in is a Support one  -> the session was closed: the sign-in is dropped
|          * a session and no recorded sign-in (or one of ANOTHER session) -> the session becomes the sign-in
|          * a session and a recorded sign-in of SecurityInsight's own -> kept, unless -TakeOver (setup: a Support session
|            in the shell always wins there -- setup never works beside it with a sign-in of its own)
|        Says ONE plain line the first time a session is used. Throws what Get-SISupportSession / Get-SISupportAuth refuse.
|    #>
|    param([switch]$TakeOver)
|    $sess = Get-SISupportSession
|    $st = Get-SIAzRestState
|    $c = $st.Connection
|    $isSupport = ($c -is [hashtable]) -and ([string]$c.Mode -eq 'Support')
|    if (-not $sess) {
|        if ($isSupport) { $st.Connection = $null; $st.TenantId = $null; $st.SubscriptionId = $null; $st.Cache = @{} }
|        return $null
|    }
|    $same = $isSupport -and ([string]$c.TenantId -eq $sess.TenantId) -and ([string]$c.SessionId -eq $sess.SessionId) -and ([string]$c.EnvironmentId -eq $sess.EnvironmentId)
|    if ($same) { return $sess }
|    if (($c -is [hashtable]) -and -not $isSupport -and -not $TakeOver) { return $sess }
|    $st.Connection = Get-SISupportAuth
|    $st.TenantId = [string]$sess.TenantId
|    $st.Cache = @{}
|    if ($st.SubscriptionId -and @($sess.Subscriptions).Count -and @($sess.Subscriptions) -notcontains ([string]$st.SubscriptionId).Trim().ToLowerInvariant()) { $st.SubscriptionId = $null }
|    $key = '{0}|{1}|{2}' -f $sess.TenantId, $sess.EnvironmentId, $sess.SessionId
|    if ([string]$st['SupportSaid'] -ne $key) {
|        $st['SupportSaid'] = $key
|        Write-Host ('using the Invardia Support session for {0} -- every change is recorded there' -f (Get-SISupportSessionName $sess))
|    }
|    return $sess
|}
|
|function Test-SISupportRecorderPresent {
|    <# #548: is an Invardia Support session, with its RECORDING wrapper, open in this shell? (Get-SISupportSession decides.) #>
|    return [bool](Get-SISupportSession)
|}
|
|function Test-SISupportRequestRoute {
|    <#
|        #548 (Invardia, 2026-10-10: every Support app action is recorded in the customer's audit log): does a request for
|        -Audience, as -Auth (none = the run's own sign-in), go through Invardia's recording wrapper? Yes when a Support
|        session is open (Get-SISupportSession) AND the call is made as the support session (Mode 'Support' -- the recorded
|        sign-in, or no recorded sign-in at all) AND no host token provider ($global:SI_TokenProvider) answers instead.
|        Every audience SecurityInsight signs in to: Arm, Graph, Log Analytics, Storage, Exchange Online's admin API, Key
|        Vault and Azure Monitor -- on any host (a host the wrapper does not know by itself gets its token audience named,
|        Get-SISupportTokenResource). A URL that is none of these (-Audience Other: another service with its own key) is
|        not a call as the support app and never goes through it. -Uri is accepted for callers that pass it.
|    #>
|    param([string]$Audience = 'Arm', [hashtable]$Auth, [string]$Uri)
|    if ($Audience -notin 'Arm', 'Graph', 'LaQuery', 'Storage', 'Exchange', 'KeyVault', 'Monitor') { return $false }
|    if ($Auth) {
|        if ([string]$Auth.Mode -ne 'Support') { return $false }
|        return [bool](Get-SISupportSession)
|    }
|    $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
|    if ($tp -is [scriptblock]) { return $false }
|    # a caller that loaded only part of this file (a script's own fakes, a lifted function) has no state helpers -- and no
|    # support session either
|    if (-not (Test-Path -LiteralPath 'Function:\Get-SIAzRestState')) { return $false }
|    if (-not (Test-Path -LiteralPath 'Function:\Sync-SISupportConnection')) { return $false }
|    if (-not (Sync-SISupportConnection)) { return $false }
|    $c = (Get-SIAzRestState).Connection
|    return (($c -is [hashtable]) -and ([string]$c.Mode -eq 'Support'))
|}
|
|function Get-SISupportTokenResource {
|    <# PURE. The token audience to NAME to the recording wrapper for a request it cannot name from the URL's host by
|       itself: a Key Vault or Azure Monitor URL on another host than <vault>.vault.azure.net /
|       <endpoint>.ingest.monitor.azure.com. '' = the wrapper names it (Arm, Graph, Log Analytics, Storage, Exchange). #>
|    param([string]$Audience, [string]$Uri)
|    $h = ''
|    try { $h = ([uri]$Uri).Host } catch { $h = '' }
|    if ($Audience -eq 'KeyVault' -and $h -notmatch '(?i)\.vault\.azure\.net$') { return 'https://vault.azure.net' }
|    if ($Audience -eq 'Monitor' -and $h -notmatch '(?i)\.ingest\.monitor\.azure\.com$') { return 'https://monitor.azure.com' }
|    return ''
|}
|
|function Test-SISupportReadOnlyPost {
|    <#
|        PURE. Is this POST a READ (recorded as a read, not as a change)? Only the POSTs known to change nothing:
|          ARM    Resource Graph (/providers/Microsoft.ResourceGraph/resources), a provider's checkNameAvailability, a
|                 workspace query (.../workspaces/<name>/query, /api/query)
|          Log Analytics   /v1/workspaces/<id>/query
|          Graph  getByIds, getMemberObjects, getMemberGroups, checkMemberObjects, checkMemberGroups, security/runHuntingQuery
|                 (a KQL hunting query), and a $batch whose
|                 requests are ALL GET
|        Anything else -- and anything not understood -- is a CHANGE. A GET / HEAD is a read by its method (not asked here).
|    #>
|    param([string]$Method, [string]$Uri, $Body)
|    if (([string]$Method).ToUpperInvariant() -ne 'POST') { return $false }
|    $u = $null
|    try { $u = [uri]$Uri } catch { return $false }
|    if (-not $u -or -not $u.IsAbsoluteUri) { return $false }
|    $h = $u.Host.ToLowerInvariant(); $p = $u.AbsolutePath
|    if ($h -match '^management\.(azure\.com|core\.windows\.net)$') {
|        if ($p -match '(?i)^/providers/Microsoft\.ResourceGraph/resources/?$') { return $true }
|        if ($p -match '(?i)/providers/[^/]+/checkNameAvailability/?$') { return $true }
|        if ($p -match '(?i)/providers/Microsoft\.OperationalInsights/workspaces/[^/]+/(api/)?query/?$') { return $true }
|        return $false
|    }
|    if ($h -eq 'api.loganalytics.io' -or $h -eq 'api.loganalytics.azure.com') { return [bool]($p -match '(?i)^/v1/workspaces/[^/]+/query/?$') }
|    if ($h -eq 'graph.microsoft.com') {
|        if ($p -match '(?i)/(getByIds|getMemberObjects|getMemberGroups|checkMemberObjects|checkMemberGroups)/?$') { return $true }
|        # Defender advanced hunting: a KQL query, which can only read
|        if ($p -match '(?i)^/(v1\.0|beta)/security/runHuntingQuery/?$') { return $true }
|        if ($p -match '(?i)^/(v1\.0|beta)/\$batch/?$') {
|            try {
|                $text = ''
|                if ($Body -is [byte[]]) { $text = [System.Text.Encoding]::UTF8.GetString($Body) } else { $text = [string]$Body }
|                $reqs = @(($text | ConvertFrom-Json).requests | Where-Object { $null -ne $_ })
|                if (-not $reqs.Count) { return $false }
|                return (-not @($reqs | Where-Object { ([string]$_.method).ToUpperInvariant() -ne 'GET' }).Count)
|            } catch { return $false }
|        }
|        return $false
|    }
|    return $false
|}
|
|function Test-SISupportBodyIsText {
|    <# PURE. Can -Body go through Invardia's recording wrapper? Yes for every body: the wrapper sends a [byte[]] body
|       unchanged (Invardia, 2026-10-10). Kept as the one place to say otherwise. #>
|    param($Body, [string]$ContentType)
|    return $true
|}
|
|function Invoke-SISupportHttp {
|    <#
|        #548: ONE HTTP exchange through Invardia's recording wrapper, in the shape of Invoke-SIAzRestHttp (StatusCode,
|        Content, Bytes, Headers, RetryAfter) so Invoke-SIAzRestRequest's retry and error rules stay exactly as they are
|        (an HTTP status >= 400 becomes SecurityInsight's own error there). The wrapper adds the support app's token: an
|        Authorization header of the caller is dropped. No answer = StatusCode 0 (retried like any network failure); a
|        refusal to record the action in the customer's audit log is RETHROWN (fail-closed: the action was not made).
|        A GET / HEAD is a read by its method; a POST that only reads (Test-SISupportReadOnlyPost) is sent -ReadOnly;
|        everything else is recorded as a change. An Azure Resource Manager URL of a subscription the session's environment
|        does not name is REFUSED before anything is sent (Assert-SISupportSubscription). -Audience names the token audience
|        for a host the wrapper does not know (Get-SISupportTokenResource); -TimeoutSec is passed on.
|    #>
|    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [switch]$AsBytes,
|          [string]$Audience, [int]$TimeoutSec = 0)
|    $sess = Get-SISupportSession
|    if (-not $sess) { throw 'No Invardia support session is open in this PowerShell session, so this request cannot be sent through it.' }
|    $target = $null
|    try { $target = [uri]$Uri } catch { $target = $null }
|    if ($target -and $target.IsAbsoluteUri -and $target.Host -match '(?i)^management\.(azure\.com|core\.windows\.net)$' -and
|        $target.AbsolutePath -match '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)') {
|        Assert-SISupportSubscription -SubscriptionId $Matches[1] -Session $sess
|    }
|    $h = @{}
|    if ($Headers) { foreach ($k in @($Headers.Keys)) { if ([string]$k -ine 'Authorization' -and [string]$k -ine 'Content-Type') { $h[[string]$k] = $Headers[$k] } elseif ([string]$k -ieq 'Content-Type' -and -not $ContentType) { $ContentType = [string]$Headers[$k] } } }
|    $p = @{ Method = $Method.ToUpperInvariant(); Uri = $Uri }
|    if ($h.Count) { $p.Headers = $h }
|    if ($null -ne $Body) {
|        # bytes go unchanged (a source package upload). NOT $(if ...): a subexpression ENUMERATES the byte array into an
|        # object[] -- the wrapper then sent it as JSON numbers instead of the file
|        if ($Body -is [byte[]]) { $p.Body = $Body } else { $p.Body = [string]$Body }
|        if ($ContentType) { $p.ContentType = $ContentType }
|    }
|    $o = $null
|    if ($AsBytes) { $p.AsBytes = $true }   # the raw answer as ContentBytes (a download)
|    if (Test-SISupportReadOnlyPost -Method $Method -Uri $Uri -Body $Body) { $p.ReadOnly = $true }   # a POST that only reads
|    if ($TimeoutSec -gt 0) { $p.TimeoutSec = $TimeoutSec }
|    $tokenResource = Get-SISupportTokenResource -Audience $Audience -Uri $Uri
|    if ($tokenResource) { $p.TokenResource = $tokenResource }
|    try { $o = Invoke-InvardiaSupportRequest @p }
|    catch {
|        $m = [string]$_.Exception.Message
|        if ($m -match '(?i)audit log|fail-closed|could not be recorded|No Invardia support session') { throw }
|        return [pscustomobject]@{ StatusCode = 0; Content = $m; Bytes = $null; Headers = @{}; RetryAfter = $null }
|    }
|    $hh = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
|    if ($o -and $o.Headers) {
|        try {
|            if ($o.Headers -is [System.Collections.IDictionary]) { foreach ($k in @($o.Headers.Keys)) { $hh[[string]$k] = (@($o.Headers[$k]) | ForEach-Object { [string]$_ }) -join ',' } }
|            else { foreach ($k in @($o.Headers.AllKeys)) { $hh[[string]$k] = [string]$o.Headers[$k] } }
|        } catch { }
|    }
|    $text = if ($o) { [string]$o.Content } else { '' }
|    # the raw answer as [byte[]] -- assigned in statements, never through $( ... ), which would enumerate it into object[]
|    [byte[]]$raw = $null
|    if ($AsBytes) {
|        if ($o -and $o.PSObject.Properties['ContentBytes'] -and $o.ContentBytes) { $raw = [byte[]]$o.ContentBytes } else { $raw = [System.Text.Encoding]::UTF8.GetBytes($text) }
|    }
|    $out = [pscustomobject]@{
|        StatusCode = $(if ($o) { [int]$o.StatusCode } else { 0 }); Content = $(if ($AsBytes) { '' } else { $text })
|        Bytes = $null; Headers = $hh; RetryAfter = [string]$hh['Retry-After']
|    }
|    $out.Bytes = $raw
|    $out
|}
|
|function Invoke-SIRestMethod {
|    <#
|        #548: the drop-in for Invoke-RestMethod that setup's own Graph / ARM calls use (-Method, -Uri, -Headers with the
|        caller's bearer token, -Body, -ContentType): inside an Invardia support session the call goes through the recording
|        wrapper (the caller's Authorization header is dropped -- the wrapper signs as the support app); otherwise exactly
|        Invoke-RestMethod. Throws on HTTP >= 400 like Invoke-RestMethod, with the service's answer in the message; returns
|        the parsed JSON (or the text when it is not JSON).
|    #>
|    [CmdletBinding()]   # -ErrorAction and the other common parameters, as Invoke-RestMethod callers pass them
|    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 120)
|    $host_ = ([uri]$Uri).Host
|    $aud = if ($host_ -eq 'graph.microsoft.com') { 'Graph' } elseif ($host_ -match '^management\.(azure\.com|core\.windows\.net)$') { 'Arm' } elseif ($host_ -eq 'api.loganalytics.io') { 'LaQuery' } elseif ($host_ -eq 'outlook.office365.com') { 'Exchange' } else { 'Other' }
|    # this function is published GLOBALLY: a caller that never loaded this file (a script run on its own, a test with its
|    # own fakes) has no routing helpers -- and then no support session either: plain Invoke-RestMethod
|    if ((Test-Path -LiteralPath 'Function:\Test-SISupportRequestRoute') -and (Test-SISupportRequestRoute -Audience $aud)) {
|        $b = $Body
|        if ($null -ne $b -and -not ($b -is [string]) -and -not ($b -is [byte[]])) { $b = ConvertTo-Json -InputObject $b -Depth 30 -Compress }
|        $ct = if ($ContentType) { $ContentType } elseif ($null -ne $b) { 'application/json' } else { '' }
|        $r = Invoke-SISupportHttp -Method $Method -Uri $Uri -Headers $Headers -Body $b -ContentType $ct -Audience $aud -TimeoutSec $TimeoutSec
|        $code = [int]$r.StatusCode
|        if ($code -lt 200 -or $code -ge 300) {
|            throw (New-SIAzRestError -Message ('{0} {1} failed. HTTP Status: {2} ({3}) Response: {4}' -f $Method.ToUpperInvariant(), ($Uri -replace '\?.*$', ''), $code, (Get-SIAzRestStatusName $code), $r.Content) -Response $r)
|        }
|        $t = [string]$r.Content
|        if (-not $t.Trim()) { return $null }
|        try { return ($t | ConvertFrom-Json) } catch { return $t }
|    }
|    $a = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop'; TimeoutSec = $TimeoutSec }
|    if ($Headers) { $a.Headers = $Headers }
|    if ($null -ne $Body) { $a.Body = $Body }
|    if ($ContentType) { $a.ContentType = $ContentType }
|    Invoke-RestMethod @a
|}
|# published globally: a product script the install runs (in this process) finds it even when it loaded only part of the layer
|Set-Item -Path 'function:global:Invoke-SIRestMethod' -Value ${function:Invoke-SIRestMethod}
|
|# =====================================================================================================================
|#  The wrapper map, shared state
|# =====================================================================================================================
|
|function Get-SIAzRestWrapperMap {
|    <# wrapper -> the Az cmdlet it replaces -> its REST twin, as data. The wiring tests read it. #>
|    $m = [ordered]@{}
|    foreach ($az in @(
|        'Connect-AzAccount', 'Disconnect-AzAccount', 'Disable-AzContextAutosave', 'Get-AzContext', 'Set-AzContext',
|        'Get-AzAccessToken', 'Get-AzSubscription', 'Invoke-AzRestMethod',
|        'Invoke-AzOperationalInsightsQuery', 'Get-AzOperationalInsightsWorkspace', 'New-AzOperationalInsightsWorkspace',
|        'Search-AzGraph', 'Get-AzKeyVaultSecret', 'Set-AzKeyVaultSecret',
|        'Get-AzResourceGroup', 'New-AzResourceGroup', 'Get-AzRoleAssignment', 'New-AzRoleAssignment', 'Get-AzRoleDefinition',
|        'Get-AzTag', 'Update-AzTag', 'Get-AzADServicePrincipal',
|        'Get-AzDataCollectionEndpoint', 'New-AzDataCollectionEndpoint', 'Get-AzDataCollectionRule',
|        'New-AzStorageContext', 'Get-AzStorageAccount', 'New-AzStorageAccount',
|        'Get-AzStorageContainer', 'New-AzStorageContainer', 'Get-AzStorageBlob', 'Get-AzStorageBlobContent',
|        'Set-AzStorageBlobContent', 'Remove-AzStorageBlob', 'Start-AzStorageBlobCopy',
|        'Get-AzStorageQueue', 'New-AzStorageQueue')) {
|        $w = $az -replace '-Az', '-SIAz'
|        $m[$w] = @{ Replaces = $az; Rest = ($w + 'Rest') }
|    }
|    return $m
|}
|
|function Get-SIAzRestState {
|    <# Per-process state: the recorded sign-in, the current subscription, token / lookup caches. Global because this
|       file is dot-sourced at different depths by different engines. #>
|    # StrictMode-safe: an unset global is read through Get-Variable, never directly (a caller may run Set-StrictMode).
|    if (-not ((Get-Variable -Scope Global -Name SI_AzRestState -ValueOnly -ErrorAction Ignore) -is [hashtable])) {
|        $global:SI_AzRestState = @{ Connection = $null; SubscriptionId = $null; TenantId = $null; Cache = @{} }
|    }
|    return $global:SI_AzRestState
|}
|
|function Initialize-SIAzRestHelpers {
|    <# The token functions (SI-LogIngest.ps1), the KQL error reader (SI-KqlError.ps1) and the certificate helpers
|       (auth/Find-SICertificate.ps1). Loaded on first need; only what is MISSING is loaded and published globally, so a
|       caller's own copy or a test's mock is never replaced. #>
|    $want = @(
|        @{ Path = (Join-Path $PSScriptRoot 'SI-LogIngest.ps1'); Fns = @('Get-SILogIngestToken', 'Invoke-SILogIngestHttp', 'Get-SILogIngestRunCache', 'Get-SILogIngestRetryDelay', 'Initialize-SILogIngestAuthHelpers') }
|        @{ Path = (Join-Path $PSScriptRoot 'SI-KqlError.ps1');   Fns = @('Get-SIKqlErrorText', 'Get-SIKqlErrorSummary', 'Test-SIKqlTableMissing') }
|        @{ Path = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Find-SICertificate.ps1'); Fns = @('Get-SICertificateClientToken', 'Get-SICertificateFromStore', 'Test-SICertDriveAvailable') }
|    )
|    foreach ($w in $want) {
|        $missing = @($w.Fns | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
|        if ($missing.Count -eq 0) { continue }
|        if (-not (Test-Path -LiteralPath $w.Path)) { continue }
|        . $w.Path
|        foreach ($n in $missing) {
|            $f = Get-Command -Name $n -CommandType Function -ErrorAction Ignore
|            if ($f) { Set-Item -Path ("function:global:{0}" -f $n) -Value $f.ScriptBlock }
|        }
|    }
|}
|
|# =====================================================================================================================
|#  HTTP seam, sign-in, tokens
|# =====================================================================================================================
|
|function Remove-SIAzRestCaughtError {
|    <# Takes a HANDLED error record back out of $global:Error (newest entries only). PS 5.1 safe. #>
|    param($Record)
|    if ($null -eq $Record) { return }
|    $errs = $global:Error
|    for ($i = 0; $i -lt [Math]::Min(3, $errs.Count); $i++) {
|        $e = $errs[$i]
|        if ([object]::ReferenceEquals($e, $Record) -or ($e -is [System.Management.Automation.ErrorRecord] -and $Record -is [System.Management.Automation.ErrorRecord] -and [object]::ReferenceEquals($e.Exception, $Record.Exception))) {
|            $errs.RemoveAt($i); return
|        }
|    }
|}
|
|function Invoke-SIAzRestHttp {
|    <#
|        THE ONE HTTP SEAM of this file (tests Mock it). Never throws on an HTTP status: returns
|        @{ StatusCode; Content; Bytes; Headers; RetryAfter }. A network failure (no response) is StatusCode 0.
|        HttpWebRequest, not Invoke-WebRequest: the 4xx body and headers read the same way on PS 5.1 and pwsh 7.
|        -AsBytes keeps the body as bytes (blob downloads); Content is then ''.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$Method,
|        [Parameter(Mandatory)][string]$Uri,
|        [hashtable]$Headers,
|        $Body,
|        [string]$ContentType,
|        [int]$TimeoutSec = 300,
|        [switch]$AsBytes,
|        # A 2xx body read AS IT ARRIVES (SI-LaStreamRead.ps1): { param([IO.Stream]$Stream) <the parsed answer> } -- the body
|        # is never held whole; the answer is returned as .Parsed (Content '', Bytes $null). Any other status: as without it.
|        [scriptblock]$ReadStream
|    )
|    if ($PSVersionTable.PSEdition -ne 'Core') {
|        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
|    }
|    $req = [System.Net.HttpWebRequest]::Create($Uri)
|    $req.Method = $Method.ToUpperInvariant()
|    $req.Timeout = $TimeoutSec * 1000
|    $req.ReadWriteTimeout = $TimeoutSec * 1000
|    $req.Accept = 'application/json'
|    if ($Headers) {
|        foreach ($k in $Headers.Keys) {
|            if ($k -eq 'Content-Type') { $req.ContentType = [string]$Headers[$k] }
|            elseif ($k -eq 'Accept')   { $req.Accept = [string]$Headers[$k] }
|            else { $req.Headers[$k] = [string]$Headers[$k] }
|        }
|    }
|    if ($ContentType) { $req.ContentType = $ContentType }
|    if ($null -ne $Body) {
|        # statements, never `= if (...) { $Body }`: an if-expression ENUMERATES a byte array into object[] (one boxed object
|        # per byte) -- a build context of tens of MB became gigabytes and the updater ran out of memory
|        [byte[]]$bytes = $null
|        if ($Body -is [byte[]]) { $bytes = $Body } else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body) }
|        $req.ContentLength = $bytes.Length
|        # A connection that fails while the BODY is sent (connect, DNS, reset) is "no answer" (StatusCode 0), which the caller
|        # retries -- for a request that is safe to send again (PUT / PATCH / DELETE / MERGE: idempotent, as an ARM or table PUT
|        # is). A POST that failed here is thrown as before: it is not repeated blindly. (The sweep of 2026-10-22: this threw
|        # past every retry loop on blob, table and ARM writes.)
|        try {
|            $s = $req.GetRequestStream()
|            try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Close() }
|        } catch {
|            if ($req.Method -eq 'POST') { throw }
|            return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; Bytes = $null; Headers = @{}; RetryAfter = $null }
|        }
|    } elseif ($req.Method -in 'POST', 'PUT', 'PATCH', 'MERGE') {
|        $req.ContentLength = 0
|    }
|    $resp = $null
|    try { $resp = $req.GetResponse() }
|    catch {
|        $we = $_.Exception
|        while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
|        if ($we -and $we.Response) {
|            $resp = $we.Response
|            # An HTTP status is an ANSWER, returned to the caller (who decides whether a 404 is "not there" or a failure)
|            # -- not an error of this process. PowerShell still records the caught exception in $Error, and setup shows
|            # every new $Error entry: each "does it exist?" probe printed "(404) Not Found" (live 2026-10-06). Drop it.
|            Remove-SIAzRestCaughtError -Record $_
|        }
|        else { return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; Bytes = $null; Headers = @{}; RetryAfter = $null } }
|    }
|    try {
|        $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
|        foreach ($k in $resp.Headers.AllKeys) { $h[$k] = [string]$resp.Headers[$k] }
|        $text = ''; $raw = $null
|        $rs = $resp.GetResponseStream()
|        # AZHANG-1: a body that stops arriving times out too (not only the wait for the headers) -- where the stream supports it
|        if ($rs -and $rs.CanTimeout) { try { $rs.ReadTimeout = $TimeoutSec * 1000 } catch { } }
|        $sc = [int]$resp.StatusCode
|        if ($rs -and $ReadStream -and $sc -ge 200 -and $sc -lt 300) {
|            $parsed = $null
|            try { $parsed = & $ReadStream $rs } finally { $rs.Close() }
|            return [pscustomobject]@{ StatusCode = $sc; Content = ''; Bytes = $null; Headers = $h; RetryAfter = [string]$h['Retry-After']; Parsed = $parsed }
|        }
|        if ($rs) {
|            # #639: the body is read ONCE into an array of its own length when the service says how long it is -- not into a
|            # growing buffer that is then copied again (a large answer was held two or three times before it was parsed)
|            try {
|                $len = [long]$resp.ContentLength
|                if ($len -gt 0 -and $len -lt [int]::MaxValue) {
|                    $raw = [byte[]]::new([int]$len); $off = 0
|                    while ($off -lt $len) { $n = $rs.Read($raw, $off, [int]($len - $off)); if ($n -le 0) { break }; $off += $n }
|                    if ($off -lt $len) { $part = [byte[]]::new($off); [Array]::Copy($raw, $part, $off); $raw = $part; $part = $null }
|                } else {
|                    $ms = New-Object System.IO.MemoryStream
|                    $rs.CopyTo($ms); $raw = $ms.ToArray(); $ms.Dispose(); $ms = $null
|                }
|            } catch {
|                # AZHANG-1: the body stopped arriving (read time-out / connection lost mid-body) = no answer -> the caller's retry rule
|                $ioe = $_.Exception
|                while ($ioe -and -not ($ioe -is [System.IO.IOException] -or $ioe -is [System.Net.WebException] -or $ioe -is [System.TimeoutException] -or $ioe -is [System.OperationCanceledException])) { $ioe = $ioe.InnerException }
|                if (-not $ioe) { throw }
|                return [pscustomobject]@{ StatusCode = 0; Content = ('the answer stopped arriving: ' + [string]$_.Exception.Message); Bytes = $null; Headers = $h; RetryAfter = $null }
|            } finally { $rs.Close() }
|            if (-not $AsBytes) { $text = [System.Text.Encoding]::UTF8.GetString($raw); $raw = $null }
|        }
|        return [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Content = $text; Bytes = $raw; Headers = $h; RetryAfter = [string]$h['Retry-After'] }
|    } finally { $resp.Close() }
|}
|
|function Get-SIAzRestValue {
|    <# The first non-empty global of -Names. #>
|    param([string[]]$Names)
|    foreach ($n in $Names) {
|        $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction Ignore
|        if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
|    }
|    return $null
|}
|
|function Resolve-SIAzRestAuth {
|    <#
|        WHO this run signs in as, for the REST path:
|          1. what Connect-SIAzAccount recorded in this process (the launcher / container entry point decided)
|          1b. an Invardia Support session open in this shell (Mode 'Support', read from the session)
|          2. the run's managed-identity switch (SI_UseManagedIdentity / UseManagedIdentity, #222)
|          3. an SPN certificate   (SI_SPN_AppId | SpnClientId | HighPriv_* + SI_SPN_CertThumbprint | SpnCertificateThumbprint)
|          4. an SPN client secret (SI_SPN_Secret | SpnClientSecret | HighPriv_*)
|        Certificate before secret, as everywhere in SecurityInsight. Returns the Auth hashtable Get-SILogIngestToken
|        takes. Throws when nothing is configured -- the REST path never falls back to an Az session.
|    #>
|    # An Invardia Support session in this shell: it IS the sign-in when nothing else was recorded (and a Support sign-in
|    # whose session was closed is dropped) -- Sync-SISupportConnection, read from the session, no token asked for.
|    $null = Sync-SISupportConnection
|    $st = Get-SIAzRestState
|    if ($st.Connection -is [hashtable]) { return $st.Connection }
|    # #524: the retired sign-in mode "AzContext" (borrow this process's Azure session) is refused by name
|    if ([string](Get-Variable -Scope Global -Name SI_AuthMethod -ValueOnly -ErrorAction Ignore) -eq 'AzContext') {
|        throw ('SI_AuthMethod = AzContext (use the current Azure session of this PowerShell process) is no longer supported: SecurityInsight signs in itself. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
|    }
|    if ([bool](Get-Variable -Scope Global -Name SI_UseManagedIdentity -ValueOnly -ErrorAction Ignore) -or [bool](Get-Variable -Scope Global -Name UseManagedIdentity -ValueOnly -ErrorAction Ignore)) {
|        return @{ Mode = 'ManagedIdentity'; ClientId = [string](Get-SIAzRestValue 'SI_UAMI_ClientId', 'SI_ManagedIdentityClientId') }
|    }
|    $tid   = Get-SIAzRestValue 'SI_SPN_TenantId', 'SpnTenantId', 'HighPriv_Modern_TenantID', 'AzureTenantId', 'TenantId'
|    $app   = Get-SIAzRestValue 'SI_SPN_AppId', 'SpnClientId', 'HighPriv_Modern_ApplicationID_Azure'
|    $thumb = Get-SIAzRestValue 'SI_SPN_CertThumbprint', 'SpnCertificateThumbprint', 'HighPriv_Modern_CertificateThumbprint_Azure'
|    $sec   = Get-SIAzRestValue 'SI_SPN_Secret', 'SpnClientSecret', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_ApplicationSecret_Azure'
|    if ($app -and $thumb -and $tid) { return @{ Mode = 'Certificate'; AppId = $app; TenantId = $tid; Thumbprint = ($thumb -replace '\s', '') } }
|    if ($app -and $sec -and $tid)   { return @{ Mode = 'Secret'; AppId = $app; TenantId = $tid; Secret = $sec } }
|    throw ('No sign-in is configured for Azure access over REST. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
|}
|
|function Get-SIAzureAudience {
|    <# The token resource of each audience the REST path talks to. #>
|    param([Parameter(Mandatory)][ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience)
|    switch ($Audience) {
|        'Arm'      { 'https://management.azure.com/' }
|        'LaQuery'  { 'https://api.loganalytics.io/' }
|        'Storage'  { 'https://storage.azure.com/' }
|        'KeyVault' { 'https://vault.azure.net/' }
|        'Graph'    { 'https://graph.microsoft.com/' }
|        'Monitor'  { 'https://monitor.azure.com/' }
|    }
|}
|
|function Get-SIAzureToken {
|    <#
|        ONE token function for every audience: a bearer token as the identity Resolve-SIAzRestAuth names, minted by
|        Get-SILogIngestToken (managed identity endpoint / certificate client assertion / client secret), cached per
|        identity + audience until 5 minutes before expiry. -Audience or a raw -Resource; -Auth overrides the identity.
|    #>
|    param(
|        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
|        [string]$Resource,
|        [hashtable]$Auth,
|        [switch]$ForceRefresh
|    )
|    if (-not $Resource) { $Resource = Get-SIAzureAudience -Audience $Audience }
|    # A host that signs in its own way (setup, a test) can supply tokens: $global:SI_TokenProvider = { param($Resource) <token> }.
|    # Consulted first, only when no explicit -Auth was passed; an empty answer falls through to SecurityInsight's own sign-in.
|    if (-not $Auth) {
|        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
|        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
|    }
|    Initialize-SIAzRestHelpers
|    if (-not $Auth) { $Auth = Resolve-SIAzRestAuth }
|    return (Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$ForceRefresh)
|}
|
|function ConvertFrom-SIJwtPayload {
|    <# PURE. The claims of a JWT (no signature check -- only used to read tid / exp / appid of our own token). #>
|    param([string]$Token)
|    $parts = ([string]$Token) -split '\.'
|    if ($parts.Count -lt 2) { return $null }
|    $p = $parts[1].Replace('-', '+').Replace('_', '/')
|    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
|    try { return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
|}
|
|function New-SIAzRestError {
|    <# An exception carrying the service's response (Response.StatusCode / Content / Headers), so the existing readers
|       (Get-SIKqlErrorText, the ledger's 412 match, ...) find what the service said. #>
|    param([string]$Message, $Response)
|    $ex = New-Object System.Exception($Message)
|    if ($Response) {
|        $r = [pscustomobject]@{ StatusCode = [int]$Response.StatusCode; Content = [string]$Response.Content; Headers = $Response.Headers }
|        Add-Member -InputObject $ex -NotePropertyName Response -NotePropertyValue $r -Force
|    }
|    return $ex
|}
|
|function Get-SIAzRestStatusName {
|    param([int]$Code)
|    if ($Code -le 0) { return 'NoResponse' }
|    try { return [string][System.Net.HttpStatusCode]$Code } catch { return [string]$Code }
|}
|
|function Invoke-SIAzRestRequest {
|    <#
|        One authenticated REST call with the retry rule:
|          429 / 408 / 5xx / no response -> PLATFORM: wait (Retry-After when sent) and retry in-run
|          401 once                      -> refresh the token, repeat once
|          404 with -AllowNotFound       -> $null
|          any other 4xx                 -> FAIL FAST with the body
|        Returns the response (StatusCode / Content / Bytes / Headers).
|    #>
|    param(
|        [string]$Method = 'GET',
|        [Parameter(Mandatory)][string]$Uri,
|        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
|        $Body,
|        [string]$ContentType = 'application/json',
|        [hashtable]$Headers,
|        [switch]$AllowNotFound,
|        [int[]]$AllowStatus = @(),
|        [switch]$AsBytes,
|        [int]$TimeoutSec = 300,
|        [int]$MaxAttempts = 6,
|        [string]$What = 'Azure request',
|        [hashtable]$Auth,  # another identity than the run's (the platform sign-in reads its Key Vault as the bootstrap identity)
|        # a 2xx body read as it arrives (Invoke-SIAzRestHttp -ReadStream); not through an Invardia support session, whose
|        # recording wrapper hands the answer back whole
|        [scriptblock]$ReadStream,
|        # AZHANG-1: { param($Code, $WaitSeconds, $Attempt, $MaxAttempts, $What) } called BEFORE each platform retry waits, so a
|        # caller can SAY it (the retries were Write-Verbose only: a run that retried a hung read for half an hour printed nothing)
|        [scriptblock]$OnRetry
|    )
|    $refreshed = $false; $force = $false
|    # #548: inside an Invardia support session every call SecurityInsight makes as the support app goes through Invardia's
|    # RECORDING wrapper (Invoke-InvardiaSupportRequest: the customer's audit log, fail-closed) -- never a raw token + HTTP.
|    # Every body and every answer goes through the wrapper: a binary body is sent unchanged, a binary answer (a download)
|    # comes back as its ContentBytes (Invardia, 2026-10-10).
|    $viaSupport = (Test-SISupportBodyIsText -Body $Body -ContentType $ContentType) -and (Test-SISupportRequestRoute -Audience $Audience -Auth $Auth -Uri $Uri)
|    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
|        if ($viaSupport) {
|            $h = @{}
|            if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
|            $r = Invoke-SISupportHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -AsBytes:$AsBytes -Audience $Audience -TimeoutSec $TimeoutSec
|        } else {
|            $token = Get-SIAzureToken -Audience $Audience -Auth $Auth -ForceRefresh:$force
|            $force = $false
|            $h = @{ 'Authorization' = ('Bearer ' + $token) }
|            if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
|            if ($ReadStream) { $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec -AsBytes:$AsBytes -ReadStream $ReadStream }
|            else { $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec -AsBytes:$AsBytes }
|        }
|        $code = [int]$r.StatusCode
|        if ($code -ge 200 -and $code -lt 300) { return $r }
|        if ($AllowStatus -contains $code) { return $r }
|        if ($code -eq 404 -and $AllowNotFound) { return $null }
|        if ($code -eq 401 -and -not $refreshed) { $refreshed = $true; $force = $true; continue }
|        $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
|        if ($transient -and $attempt -lt $MaxAttempts) {
|            Initialize-SIAzRestHelpers
|            $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
|            Write-Verbose ("{0}: HTTP {1}, retrying in {2}s (attempt {3}/{4})" -f $What, $code, $wait, $attempt, $MaxAttempts)
|            if ($OnRetry) { try { $null = & $OnRetry $code $wait $attempt $MaxAttempts $What } catch { } }
|            Start-Sleep -Seconds $wait
|            continue
|        }
|        $body = [string]$r.Content
|        if ($AsBytes -and $r.Bytes) { try { $body = [System.Text.Encoding]::UTF8.GetString($r.Bytes) } catch { } }
|        $errCode = ''
|        if ($r.Headers -and $r.Headers['x-ms-error-code']) { $errCode = ' ' + [string]$r.Headers['x-ms-error-code'] }
|        $resp = [pscustomobject]@{ StatusCode = $code; Content = $body; Headers = $r.Headers }
|        throw (New-SIAzRestError -Message ("{0} failed. HTTP Status: {1} ({2}){3} Response: {4}" -f $What, $code, (Get-SIAzRestStatusName $code), $errCode, $body) -Response $resp)
|    }
|    throw ("{0} failed after {1} attempts." -f $What, $MaxAttempts)
|}
|
|# =====================================================================================================================
|#  ARM, Resource Graph, Key Vault, Log Analytics
|# =====================================================================================================================
|
|function Test-SIArmBusyError {
|    <# PURE. #564: an ARM refusal that means "another operation on this resource is still running" (HTTP 409
|       OperationInProgress and its per-service names) -- a wait, not a failure. A plain 409 Conflict ("already exists") is NOT. #>
|    param([AllowEmptyString()][string]$Message)
|    [bool]("$Message" -match '(?i)\w*OperationInProgress|operation is (still )?in progress|another operation is (in progress|ongoing|running)|active provisioning operation|is currently being (updated|provisioned)')
|}
|
|function Invoke-SIArmWriteBusyRetry {
|    <#
|        #564 (PIM's install at customer I, 2026-10-10): ONE ARM write (PUT / PATCH / POST / DELETE) with a BOUNDED wait for a busy
|        resource: a write seconds after another change to the same resource is refused "409 OperationInProgress". Waits
|        $global:SI_ArmBusyWaits (default 6 x 20 s) between attempts, RE-READS the resource before each retry (PUT / PATCH /
|        DELETE: what Azure has now), and after a write that had to wait READS IT BACK until it is provisioned (about 60 s).
|        Any other failure is rethrown at once WITH ITS OWN ERROR; the last busy failure is rethrown after the last wait.
|        NOT a closure (a GetNewClosure() block cannot see the functions this file defines). $global:SI_ArmBusySleep
|        { param($Seconds) } is the test seam for the waits. Returns the response (Invoke-SIAzRestRequest's shape).
|    #>
|    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Uri, $Json, [switch]$AllowNotFound, [string]$What = 'Azure Resource Manager write')
|    $waits = @(20, 20, 20, 20, 20, 20)
|    $gw = Get-Variable -Scope Global -Name SI_ArmBusyWaits -ValueOnly -ErrorAction Ignore
|    if ($null -ne $gw) { $waits = @($gw | ForEach-Object { [int]$_ }) }
|    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
|    $verb = $Method.ToUpperInvariant()
|    $resourceUri = if ($verb -in 'PUT', 'PATCH', 'DELETE') { $Uri } else { $null }
|    $try = 0; $waited = $false
|    while ($true) {
|        try { $r = Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Body $Json -AllowNotFound:$AllowNotFound -What $What; break }
|        catch {
|            if (-not (Test-SIArmBusyError -Message ([string]$_.Exception.Message)) -or $try -ge $waits.Count) { throw }
|            $w = [int]$waits[$try]; $try++; $waited = $true
|            Write-Host ('       Azure is still busy with another change to {0} -- waiting {1} s, then trying again ({2}/{3}) ...' -f (($Uri -replace '\?.*$', '') -split '/')[-1], $w, $try, $waits.Count) -ForegroundColor DarkYellow
|            if ($w -gt 0) { if ($sleep -is [scriptblock]) { & $sleep $w } else { Start-Sleep -Seconds $w } }
|            # re-read before the retry: what Azure has now (never fails the write -- the retry decides)
|            if ($resourceUri) { try { $null = Invoke-SIAzRestRequest -Method GET -Uri $resourceUri -AllowNotFound -What ('Reading ' + $What) } catch { } }
|        }
|    }
|    if ($waited -and $verb -in 'PUT', 'PATCH') {
|        # read back: the write that waited is followed until Azure has provisioned it (bounded, about 60 s)
|        for ($i = 0; $i -lt 6; $i++) {
|            $back = $null
|            try { $back = Invoke-SIAzRestRequest -Method GET -Uri $resourceUri -AllowNotFound -What ('Reading back ' + $What) } catch { break }
|            $ps = ''
|            try { $ps = [string](($back.Content | ConvertFrom-Json).properties.provisioningState) } catch { $ps = '' }
|            if (-not $ps -or $ps -in 'Succeeded', 'Failed', 'Canceled', 'Cancelled') { break }
|            if ($sleep -is [scriptblock]) { & $sleep 10 } else { Start-Sleep -Seconds 10 }
|        }
|    }
|    $r
|}
|
|function Invoke-SIArm {
|    <#
|        Azure Resource Manager. -Path is '/subscriptions/...' (or a full https:// URL, e.g. a nextLink); -ApiVersion is
|        appended when the path has none. Returns the parsed body ($null for a 404 with -AllowNotFound).
|        -List returns every item of a list, following nextLink.
|    #>
|    param(
|        [string]$Method = 'GET',
|        [Parameter(Mandatory)][string]$Path,
|        [string]$ApiVersion,
|        $Body,
|        [switch]$AllowNotFound,
|        [switch]$List
|    )
|    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
|    if ($ApiVersion -and $uri -notmatch '[?&]api-version=') { $uri += $(if ($uri -match '\?') { '&' } else { '?' }) + 'api-version=' + $ApiVersion }
|    $json = if ($null -ne $Body -and -not ($Body -is [string])) { $Body | ConvertTo-Json -Depth 50 -Compress } else { $Body }
|    # #564 (PIM's install at customer I, 2026-10-10): an ARM POST ACTION with no body (listSecrets, listCredentials, listKeys,
|    # sharedKeys, a revision restart, a provider register) sends '{}' -- an empty body with a JSON content type was
|    # refused with HTTP 415.
|    if ($Method.ToUpperInvariant() -eq 'POST' -and ($null -eq $json -or ([string]$json) -eq '')) { $json = '{}' }
|    $what = 'Azure Resource Manager {0} {1}' -f $Method, ($uri -replace '\?.*$', '')
|    if (-not $List) {
|        if ($Method.ToUpperInvariant() -eq 'GET') { $r = Invoke-SIAzRestRequest -Method $Method -Uri $uri -Body $json -AllowNotFound:$AllowNotFound -What $what }
|        else { $r = Invoke-SIArmWriteBusyRetry -Method $Method -Uri $uri -Json $json -AllowNotFound:$AllowNotFound -What $what }
|        if (-not $r -or [string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
|        return ($r.Content | ConvertFrom-Json)
|    }
|    $items = [System.Collections.Generic.List[object]]::new()
|    $next = $uri
|    while ($next) {
|        $r = Invoke-SIAzRestRequest -Method 'GET' -Uri $next -AllowNotFound:$AllowNotFound -What $what
|        if (-not $r) { break }
|        $page = $r.Content | ConvertFrom-Json
|        foreach ($v in @($page.value)) { if ($null -ne $v) { [void]$items.Add($v) } }
|        $next = [string]$page.nextLink
|    }
|    return $items.ToArray()
|}
|
|function Search-SIResourceGraph {
|    <# Resource Graph: EVERY row of -Query, following $skipToken. -Subscription / -ManagementGroup scope it; neither =
|       every subscription the identity can read (as Search-AzGraph without them). #>
|    param(
|        [Parameter(Mandatory)][string]$Query,
|        [string[]]$Subscription,
|        [string[]]$ManagementGroup,
|        [int]$PageSize = 1000
|    )
|    $rows = [System.Collections.Generic.List[object]]::new()
|    $skip = $null
|    do {
|        $page = Invoke-SIResourceGraphPage -Query $Query -Subscription $Subscription -ManagementGroup $ManagementGroup -First $PageSize -SkipToken $skip
|        foreach ($d in @($page.Data)) { if ($null -ne $d) { [void]$rows.Add($d) } }
|        $skip = [string]$page.SkipToken
|    } while ($skip)
|    return $rows.ToArray()
|}
|
|function Invoke-SIResourceGraphPage {
|    <# ONE Resource Graph page: @{ Data; SkipToken; TotalRecords }. #>
|    param([string]$Query, [string[]]$Subscription, [string[]]$ManagementGroup, [int]$First = 1000, [int]$Skip = 0, [string]$SkipToken,
|          # AZHANG-1: a shorter wait + fewer attempts + a retry line, for a pager that retries the page itself (Invoke-SIArgPaged)
|          [int]$TimeoutSec = 300, [int]$MaxAttempts = 6, [scriptblock]$OnRetry)
|    # AZHANG-1: inside Invoke-SIArgPaged (which retries the page itself) the page takes the pager's options -- read from its
|    # scope ($SIArgPageOptions), so a caller (or a test stub of Search-SIAzGraph) passes nothing new
|    $ambient = Get-Variable -Name SIArgPageOptions -ValueOnly -ErrorAction Ignore
|    if ($ambient -is [hashtable]) {
|        if (-not $PSBoundParameters.ContainsKey('TimeoutSec') -and $ambient['TimeoutSec']) { $TimeoutSec = [int]$ambient['TimeoutSec'] }
|        if (-not $PSBoundParameters.ContainsKey('MaxAttempts') -and $ambient['MaxAttempts']) { $MaxAttempts = [int]$ambient['MaxAttempts'] }
|        if (-not $OnRetry -and $ambient['OnRetry'] -is [scriptblock]) { $OnRetry = $ambient['OnRetry'] }
|    }
|    $opt = [ordered]@{ resultFormat = 'objectArray'; '$top' = $First }
|    if ($Skip -gt 0) { $opt['$skip'] = $Skip }
|    if ($SkipToken) { $opt['$skipToken'] = $SkipToken }
|    $body = [ordered]@{ query = $Query; options = $opt }
|    $subs = @(@($Subscription) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
|    $mgs  = @(@($ManagementGroup) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
|    if ($subs.Count) { $body['subscriptions'] = [string[]]$subs }
|    if ($mgs.Count) { $body['managementGroups'] = [string[]]$mgs }
|    $r = Invoke-SIAzRestRequest -Method POST -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' `
|             -Body ($body | ConvertTo-Json -Depth 10 -Compress) -What 'Resource Graph query' -TimeoutSec $TimeoutSec -MaxAttempts $MaxAttempts -OnRetry $OnRetry
|    $j = $r.Content | ConvertFrom-Json
|    $tok = $null
|    if ($j.PSObject.Properties['$skipToken']) { $tok = [string]$j.'$skipToken' }
|    return [pscustomobject]@{ Data = @($j.data); SkipToken = $tok; TotalRecords = $j.totalRecords }
|}
|
|function Get-SIKeyVaultSecretValue {
|    <# One Key Vault secret as plain text; $null when the secret does not exist. #>
|    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name, [string]$Version, [hashtable]$Auth)
|    $j = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name -Version $Version -Auth $Auth
|    if (-not $j) { return $null }
|    return [string]$j.value
|}
|
|function Get-SIKeyVaultSecretRaw {
|    param([string]$VaultName, [string]$Name, [string]$Version, [hashtable]$Auth)
|    $v = if ($Version) { '/' + $Version } else { '' }
|    $uri = 'https://{0}.vault.azure.net/secrets/{1}{2}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name), $v
|    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -Auth $Auth -What ("Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
|    if (-not $r) { return $null }
|    return ($r.Content | ConvertFrom-Json)
|}
|
|function ConvertTo-SIAzLaCellString {
|    <# One Log Analytics cell, as Az.OperationalInsights hands it to callers: TEXT. Strings and dates stay as the
|       service sent them, numbers keep their JSON spelling, booleans are 'true' / 'false', null stays null, nested
|       values are JSON text. #>
|    param($Value)
|    if ($null -eq $Value) { return $null }
|    if ($Value -is [string]) { return $Value }
|    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
|    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.FFFFFFFZ', [System.Globalization.CultureInfo]::InvariantCulture) }
|    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
|    return (ConvertTo-Json -InputObject $Value -Depth 20 -Compress)
|}
|
|function ConvertFrom-SILaQueryJson {
|    <#
|        The Log Analytics query response -> @{ Tables = @( @{ Name; Columns = @(@{name;type}); Rows = @(@(cells as text)) } ); Error }.
|        pwsh 7: System.Text.Json, so a date stays the exact text the service sent (ConvertFrom-Json would turn it into a
|        local DateTime). Windows PowerShell 5.1: ConvertFrom-Json, which leaves dates as text.
|    #>
|    param([Parameter(Mandatory)][string]$Json)
|    $tables = [System.Collections.Generic.List[object]]::new()
|    $err = $null
|    if ($PSVersionTable.PSEdition -eq 'Core') {
|        $doc = [System.Text.Json.JsonDocument]::Parse($Json)
|        try {
|            $root = $doc.RootElement
|            $tEl = [System.Text.Json.JsonElement]::new()
|            if ($root.TryGetProperty('tables', [ref]$tEl)) {
|                foreach ($t in $tEl.EnumerateArray()) {
|                    $cols = [System.Collections.Generic.List[object]]::new()
|                    foreach ($c in $t.GetProperty('columns').EnumerateArray()) {
|                        $ty = [System.Text.Json.JsonElement]::new(); $tyS = ''
|                        if ($c.TryGetProperty('type', [ref]$ty)) { $tyS = $ty.GetString() }
|                        [void]$cols.Add([pscustomobject]@{ name = $c.GetProperty('name').GetString(); type = $tyS })
|                    }
|                    $rows = [System.Collections.Generic.List[object]]::new()
|                    foreach ($row in $t.GetProperty('rows').EnumerateArray()) {
|                        $cells = [System.Collections.Generic.List[object]]::new()
|                        foreach ($cell in $row.EnumerateArray()) {
|                            switch ($cell.ValueKind.ToString()) {
|                                'String' { [void]$cells.Add($cell.GetString()) }
|                                'Null'   { [void]$cells.Add($null) }
|                                'True'   { [void]$cells.Add('true') }
|                                'False'  { [void]$cells.Add('false') }
|                                default  { [void]$cells.Add($cell.GetRawText()) }
|                            }
|                        }
|                        [void]$rows.Add($cells.ToArray())
|                    }
|                    $nm = [System.Text.Json.JsonElement]::new(); $nmS = ''
|                    if ($t.TryGetProperty('name', [ref]$nm)) { $nmS = $nm.GetString() }
|                    [void]$tables.Add([pscustomobject]@{ Name = $nmS; Columns = $cols.ToArray(); Rows = $rows.ToArray() })
|                }
|            }
|            $eEl = [System.Text.Json.JsonElement]::new()
|            if ($root.TryGetProperty('error', [ref]$eEl) -and $eEl.ValueKind.ToString() -ne 'Null') { $err = ($eEl.GetRawText() | ConvertFrom-Json) }
|        } finally { $doc.Dispose() }
|    } else {
|        $j = $Json | ConvertFrom-Json
|        foreach ($t in @($j.tables)) {
|            if ($null -eq $t) { continue }
|            $rows = [System.Collections.Generic.List[object]]::new()
|            foreach ($row in @($t.rows)) {
|                $cells = [System.Collections.Generic.List[object]]::new()
|                foreach ($cell in @($row)) { [void]$cells.Add((ConvertTo-SIAzLaCellString $cell)) }
|                [void]$rows.Add($cells.ToArray())
|            }
|            [void]$tables.Add([pscustomobject]@{ Name = [string]$t.name; Columns = @($t.columns); Rows = $rows.ToArray() })
|        }
|        if ($j.PSObject.Properties['error'] -and $j.error) { $err = $j.error }
|    }
|    return [pscustomobject]@{ Tables = $tables.ToArray(); Error = $err }
|}
|
|function Get-SILaCompactRowType {
|    <#
|        #711. A .NET class for one column list: one public text property per column, in the column order, built from the
|        row's values in one call (new(string[])). Built once per column list and process (Add-Type, pwsh 7 / .NET 8+) and
|        reused. $null when it cannot be built -- a column name that is not a plain identifier, two names that differ only in
|        case (PowerShell reads properties without case), Windows PowerShell -- and the caller keeps PSCustomObject rows.
|    #>
|    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
|    if ($PSVersionTable.PSEdition -ne 'Core' -or $Names.Count -eq 0) { return $null }
|    if ($null -eq $script:SILaCompactRowTypes) { $script:SILaCompactRowTypes = @{} }
|    $key = ($Names -join "`n")
|    if ($script:SILaCompactRowTypes.ContainsKey($key)) { return $script:SILaCompactRowTypes[$key] }
|    $type = $null
|    try {
|        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
|        foreach ($n in $Names) { if ($n -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or -not $seen.Add($n)) { throw ('not a plain column name: {0}' -f $n) } }
|        $sha = [System.Security.Cryptography.SHA256]::Create()
|        try { $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key))) -replace '-', '').Substring(0, 20) } finally { $sha.Dispose() }
|        $cls = 'R' + $h
|        $full = 'SecurityInsight.LaRows.' + $cls
|        $type = $full -as [type]
|        if ($null -eq $type) {
|            $sb = New-Object System.Text.StringBuilder
|            [void]$sb.Append('namespace SecurityInsight.LaRows { public sealed class ').Append($cls).Append(' { ')
|            foreach ($n in $Names) { [void]$sb.Append('public string @').Append($n).Append(' { get; set; } ') }
|            [void]$sb.Append('public ').Append($cls).Append('(string[] v) { ')
|            for ($i = 0; $i -lt $Names.Count; $i++) { [void]$sb.Append('this.@').Append($Names[$i]).Append(' = v[').Append($i).Append(']; ') }
|            [void]$sb.Append('} } }')
|            Add-Type -TypeDefinition $sb.ToString() -Language CSharp -ErrorAction Stop
|            $type = $full -as [type]
|        }
|    } catch { $type = $null }
|    $script:SILaCompactRowTypes[$key] = $type
|    return $type
|}
|
|function ConvertFrom-SILaQueryRows {
|    <#
|        The Log Analytics query response AS THE BYTES THE SERVICE SENT -> @{ Rows; Error }: the primary table's rows, one
|        object per row, one TEXT property per column -- the same rows Invoke-SILaQuery hands out as .Results.
|        For large answers (Invoke-SILaQuery -RowsOnly): the bytes are parsed where they are. The answer is never also held
|        as one text (twice its size), as a second copy of every table, or as a list of cells per row -- on a large install
|        those copies together ran a job out of memory. pwsh 7 only (System.Text.Json).
|    #>
|    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
|    $rows = [System.Collections.Generic.List[object]]::new()
|    $cols = [System.Collections.Generic.List[object]]::new()
|    $err = $null
|    $doc = [System.Text.Json.JsonDocument]::Parse([System.ReadOnlyMemory[byte]]::new($Bytes))
|    try {
|        $root = $doc.RootElement
|        $tEl = [System.Text.Json.JsonElement]::new()
|        if ($root.TryGetProperty('tables', [ref]$tEl)) {
|            # the table named PrimaryResult, else the first one -- as .Results has always been chosen
|            $have = $false
|            $pick = [System.Text.Json.JsonElement]::new()
|            foreach ($t in $tEl.EnumerateArray()) {
|                $nm = [System.Text.Json.JsonElement]::new(); $nmS = ''
|                if ($t.TryGetProperty('name', [ref]$nm)) { $nmS = [string]$nm.GetString() }
|                if (-not $have) { $pick = $t; $have = $true }
|                if ($nmS -eq 'PrimaryResult') { $pick = $t; break }
|            }
|            if ($have) {
|                $names = [System.Collections.Generic.List[string]]::new()
|                foreach ($c in $pick.GetProperty('columns').EnumerateArray()) {
|                    $names.Add([string]$c.GetProperty('name').GetString())
|                    $ty = [System.Text.Json.JsonElement]::new(); $tyS = $null
|                    if ($c.TryGetProperty('type', [ref]$ty)) { $tyS = $ty.GetString() }
|                    $cols.Add([pscustomobject]@{ name = $names[$names.Count - 1]; type = $tyS })
|                }
|                $nCols = $names.Count
|                # #711: a caller that keeps the rows for long (Risk Analysis' lookups) asks for COMPACT rows -- one small
|                # .NET object per row with one text property per column (Get-SILaCompactRowType), not a PSCustomObject
|                # (measured on the test VM: ~6 KB per row of 11 columns as a PSCustomObject). Read the same way by
|                # every reader ($row.Col, $row.PSObject.Properties['Col'].Value). Not available -> the rows as always.
|                $compactType = $null
|                if ([bool]$global:SI_LaCompactRows) { $compactType = Get-SILaCompactRowType -Names $names.ToArray() }
|                if ($null -ne $compactType) {
|                    # a short value that repeats (a tier, a flag, an empty text, a short factor list) is held once per read
|                    $pool = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
|                    foreach ($row in $pick.GetProperty('rows').EnumerateArray()) {
|                        # a null cell is left as the array's own null (assigning $null to a [string] element would make it '')
|                        $vals = [string[]]::new($nCols)
|                        $i = 0
|                        foreach ($cell in $row.EnumerateArray()) {
|                            if ($i -ge $nCols) { break }
|                            $kind = $cell.ValueKind.ToString()
|                            if ($kind -ne 'Null') {
|                                $s = if ($kind -eq 'String') { $cell.GetString() } elseif ($kind -eq 'True') { 'true' } elseif ($kind -eq 'False') { 'false' } else { $cell.GetRawText() }
|                                if ($s.Length -le 32) { $p0 = $null; if ($pool.TryGetValue($s, [ref]$p0)) { $s = $p0 } else { $pool[$s] = $s } }
|                                $vals[$i] = $s
|                            }
|                            $i++
|                        }
|                        [void]$rows.Add($compactType::new($vals))
|                    }
|                    $nCols = -1
|                }
|                if ($nCols -ge 0) {
|                foreach ($row in $pick.GetProperty('rows').EnumerateArray()) {
|                    $o = [ordered]@{}
|                    $i = 0
|                    foreach ($cell in $row.EnumerateArray()) {
|                        if ($i -ge $nCols) { break }
|                        $name = $names[$i]
|                        $kind = $cell.ValueKind.ToString()
|                        if ($kind -eq 'String') { $o[$name] = $cell.GetString() }
|                        elseif ($kind -eq 'Null') { $o[$name] = $null }
|                        elseif ($kind -eq 'True') { $o[$name] = 'true' }
|                        elseif ($kind -eq 'False') { $o[$name] = 'false' }
|                        else { $o[$name] = $cell.GetRawText() }
|                        $i++
|                    }
|                    # a row shorter than its columns: the missing ones are empty, as before
|                    for (; $i -lt $nCols; $i++) { $o[$names[$i]] = $null }
|                    [void]$rows.Add([pscustomobject]$o)
|                }
|                }
|            }
|        }
|        $eEl = [System.Text.Json.JsonElement]::new()
|        if ($root.TryGetProperty('error', [ref]$eEl) -and $eEl.ValueKind.ToString() -ne 'Null') { $err = ($eEl.GetRawText() | ConvertFrom-Json) }
|    } finally { $doc.Dispose() }
|    return [pscustomobject]@{ Rows = $rows.ToArray(); Columns = $cols.ToArray(); Error = $err }
|}
|
|function Get-SILaServiceRowLimit {
|    <# The most rows ONE Log Analytics query answer carries (the service's own limit). An answer holding exactly that many
|       rows cannot be told from an answer the service cut there. $global:SI_LaServiceRowLimit overrides it (tests). #>
|    $v = 0L
|    try { $v = [long]$global:SI_LaServiceRowLimit } catch { $v = 0L }
|    if ($v -gt 0) { return $v }
|    return 500000L
|}
|
|function Get-SILaPartialVerdict {
|    <#
|        PURE. What a Log Analytics partial answer (the "error" object beside the rows of an HTTP 200 answer) says, read from
|        its LEAVES (the innermost error objects -- the outer ones are generic). Returns @{ Kind; Code; Detail; Tables }:
|          Unresolved  every leaf is "Failed to resolve table or column expression named 'SI_..._CL'": a `union isfuzzy=true`
|                      leg over a SecurityInsight table this workspace does not have yet. The answer IS the whole result (the
|                      missing table has no rows) -- the one partial answer that is not a cut one.
|          Limit       a leaf names a limit (rows / size / time / memory): the answer is CUT; a smaller read fixes it.
|          Other       anything else: the answer is short, and a smaller read does not fix it.
|        The same reading as Risk Analysis' own (RA-LaPartedRead.ps1 Get-RALaPartialVerdict); kept here so every reader of
|        Log Analytics refuses a cut answer, not only Risk Analysis.
|        -MayBeMissing (2026-10-23): other tables the CALLER names that this workspace may not have (the capability probe's
|        SecurityIncident / SecurityAlert in a workspace without Sentinel): a leaf that cannot resolve one of them is
|        Unresolved too -- the answer is whole, the table has no rows. Only the tables named; never any other.
|    #>
|    param([AllowNull()][object]$ErrorObject, [string[]]$MayBeMissing = @())
|    $leaves = New-Object System.Collections.Generic.List[string]
|    $all = New-Object System.Collections.Generic.List[string]
|    $codes = New-Object System.Collections.Generic.List[string]
|    $get = {
|        param($o, $n)
|        if ($null -eq $o) { return $null }
|        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }
|        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value }; return $null
|    }
|    $stack = New-Object System.Collections.Stack
|    if ($null -ne $ErrorObject -and $ErrorObject -isnot [string]) { $stack.Push($ErrorObject) }
|    $visited = 0
|    while ($stack.Count -gt 0 -and $visited -lt 256) {
|        $o = $stack.Pop(); $visited++
|        if ($null -eq $o -or $o -is [string]) { continue }
|        $m = [string](& $get $o 'message'); $c = [string](& $get $o 'code')
|        if ($c -and $codes.Count -lt 3 -and -not $codes.Contains($c)) { $codes.Add($c) }
|        if ($m) { $all.Add($m) }
|        $children = New-Object System.Collections.Generic.List[object]
|        $ie = & $get $o 'innererror'; if ($null -ne $ie -and $ie -isnot [string]) { $children.Add($ie) }
|        $ds = & $get $o 'details'
|        if ($null -ne $ds) { foreach ($d in @($ds)) { if ($null -ne $d -and $d -isnot [string]) { $children.Add($d) } } }
|        if ($children.Count -eq 0) { if ($m) { $leaves.Add($m) } }
|        else { for ($i = $children.Count - 1; $i -ge 0; $i--) { $stack.Push($children[$i]) } }
|    }
|    if ($null -ne $ErrorObject -and $ErrorObject -is [string]) { $leaves.Add([string]$ErrorObject); $all.Add([string]$ErrorObject) }
|    $generic = '^(There were some errors when processing your query\.?|Something went wrong processing your query on the server\.?)$'
|    $specific = @($all | Where-Object { $_ -notmatch $generic } | Select-Object -Unique)
|    $detail = (@($specific) -join '; ')
|    if (-not $detail) { $detail = (@($all | Select-Object -Unique) -join '; ') }
|    if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + '...' }
|    $code = (@($codes) -join '/')
|    # a 'union' leaf says "table expression", a 'where' leaf "table or column expression" (both: the table is not there)
|    $rx = "Failed to resolve table (?:or column )?expression named '(?<t>[A-Za-z0-9_]+)'"
|    $okMissing = { param($t) ($t -match '^SI_[A-Za-z0-9_]+_CL$') -or (@($MayBeMissing | Where-Object { $_ -and [string]$_ -ieq $t }).Count -gt 0) }
|    $tables = New-Object System.Collections.Generic.List[string]
|    $leafSpecific = @($leaves | Where-Object { $_ -notmatch $generic })
|    $allResolve = ($leafSpecific.Count -gt 0)
|    foreach ($l in $leafSpecific) {
|        $mm = [regex]::Match($l, $rx)
|        if (-not $mm.Success -or -not (& $okMissing $mm.Groups['t'].Value)) { $allResolve = $false; break }
|        if (-not $tables.Contains($mm.Groups['t'].Value)) { $tables.Add($mm.Groups['t'].Value) }
|    }
|    if ($allResolve) { return @{ Kind = 'Unresolved'; Code = $code; Detail = $detail; Tables = $tables.ToArray() } }
|    $limitRx = '(?i)limit|exceeded|too large|E_QUERY_RESULT_SET_TOO_LARGE|timed out|timeout|E_RUNAWAY|out of memory|memory|truncat|cancell?ed|preempted'
|    if (@($all | Where-Object { $_ -match $limitRx }).Count -gt 0) { return @{ Kind = 'Limit'; Code = $code; Detail = $detail; Tables = @() } }
|    return @{ Kind = 'Other'; Code = $code; Detail = $detail; Tables = @() }
|}
|
|function Test-SILaAnswerWhole {
|    <#
|        PURE. Is a Log Analytics answer the WHOLE result? -ErrorObject: the partial-error object beside the rows; -Rows: how
|        many rows the answer held. Returns @{ Whole; Kind; Code; Detail; Tables; Rows }:
|          no error and fewer rows than the service's own row limit   -> whole
|          an Unresolved partial error (a missing SI table in a fuzzy union)  -> whole (the missing table has no rows)
|          a Limit / Other partial error                              -> NOT whole
|          no error, but exactly as many rows as the service's limit  -> NOT whole (Limit): it cannot be told from a cut answer
|    #>
|    # -MayBeMissing: as Get-SILaPartialVerdict (the tables the caller names that the workspace may not have)
|    param([AllowNull()][object]$ErrorObject, [long]$Rows = 0, [string[]]$MayBeMissing = @())
|    if ($null -ne $ErrorObject) {
|        $v = Get-SILaPartialVerdict -ErrorObject $ErrorObject -MayBeMissing $MayBeMissing
|        return @{ Whole = ($v.Kind -eq 'Unresolved'); Kind = $v.Kind; Code = $v.Code; Detail = $v.Detail; Tables = $v.Tables; Rows = $Rows }
|    }
|    $cap = Get-SILaServiceRowLimit
|    if ($Rows -ge $cap) {
|        $d = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, 'the answer holds {0:N0} rows, the most one answer carries (the service''s limit of {1:N0} rows) -- it cannot be told from a cut answer', $Rows, $cap)
|        return @{ Whole = $false; Kind = 'Limit'; Code = 'RowLimit'; Detail = $d; Tables = @(); Rows = $Rows }
|    }
|    return @{ Whole = $true; Kind = ''; Code = ''; Detail = ''; Tables = @(); Rows = $Rows }
|}
|
|function New-SILaCutAnswerError {
|    <#
|        The error a refused cut answer becomes (Invoke-SILaQuery without -AllowPartial). An ErrorRecord whose exception
|        carries the service's own words three ways, so every classifier that reads a failed query finds them:
|          * the message: "Log Analytics returned a PARTIAL answer (<code>: <detail>) -- ..."; a Limit also says "Query
|            execution has exceeded the allowed limits" (the text Risk Analysis' bucket logic makes a slice smaller on);
|          * Exception.Response.Content and ErrorDetails: the error object as JSON (Get-SIKqlErrorText -> the data sync's
|            "too large" check, Test-SIDataResponseTooLarge, cuts that page in two);
|          * Exception.Data: SILaPartial / SIRALaPartial = the kind, SIRALaPartialRows = the rows the short answer held (Risk
|            Analysis' parted reader measures with them).
|    #>
|    param([Parameter(Mandatory)][hashtable]$Verdict, [AllowNull()][object]$ErrorObject, [string]$WorkspaceId = '')
|    $msg = if ($Verdict.Kind -eq 'Limit') {
|        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- Query execution has exceeded the allowed limits; the rows it returned are not the whole result and were not used" -f $Verdict.Code, $Verdict.Detail
|    } else {
|        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- the rows it returned are not the whole result and were not used" -f $Verdict.Code, $Verdict.Detail
|    }
|    $json = ''
|    if ($null -ne $ErrorObject) { try { $json = ConvertTo-Json -InputObject ([pscustomobject]@{ error = $ErrorObject }) -Depth 12 -Compress } catch { $json = [string]$ErrorObject } }
|    else { $json = ConvertTo-Json -InputObject ([pscustomobject]@{ error = [pscustomobject]@{ code = [string]$Verdict.Code; message = [string]$Verdict.Detail } }) -Depth 4 -Compress }
|    $ex = New-SIAzRestError -Message $msg -Response ([pscustomobject]@{ StatusCode = 200; Content = $json; Headers = @{} })
|    $ex.Data['SILaPartial'] = [string]$Verdict.Kind
|    $ex.Data['SIRALaPartial'] = [string]$Verdict.Kind
|    $ex.Data['SIRALaPartialRows'] = [long]$Verdict.Rows
|    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'SILaQueryPartial', [System.Management.Automation.ErrorCategory]::LimitsExceeded, $WorkspaceId)
|    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($json)
|    return $er
|}
|
|function Test-SILaCutAnswerError {
|    <# PURE. Was this failure a cut answer Invoke-SILaQuery refused (New-SILaCutAnswerError)? -Kind: only that kind. #>
|    param([AllowNull()][object]$Err, [string]$Kind = '')
|    $ex = $null
|    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
|    while ($null -ne $ex) {
|        if ($ex.Data -and $ex.Data.Contains('SILaPartial')) { return ((-not $Kind) -or ([string]$ex.Data['SILaPartial'] -eq $Kind)) }
|        $ex = $ex.InnerException
|    }
|    return $false
|}
|
|function Invoke-SILaQuery {
|    <#
|        A KQL query on the Log Analytics DATA PLANE: POST https://api.loganalytics.io/v1/workspaces/{id}/query. Not the
|        ARM /api/query route, which hides the semantic error behind a generic one.
|        Returns the shape Invoke-AzOperationalInsightsQuery returns and every caller reads:
|            .Results   the primary table's rows, one object per row, one TEXT property per column (as Az hands them)
|            .Columns   the primary table's columns (name / type) -- what the workbooks type their columns from
|            .Tables    ONE entry: the primary table's Name and Columns, NO rows (RowsOmitted). The rows are in .Results only;
|                       the answer is never held a second time as tables beside them (#639). No caller reads table rows.
|            .Error     the partial-error object (or $null) -- only ever set beside rows that ARE the whole result (a missing SI
|                       table in a fuzzy union), or with -AllowPartial
|            .RowCount  the rows the answer held (with -OnPage: the rows handed to it)
|        A CUT ANSWER IS REFUSED (#639, working rule 4). Log Analytics answers HTTP 200 with the rows it got to AND an error
|        object when it stopped early (a result over its row / size limit, a part that timed out); an answer with exactly as
|        many rows as the service's own row limit cannot be told from one cut there. Such an answer THROWS
|        (New-SILaCutAnswerError: the service's words, the kind, the rows it held) -- a cut answer is never handed out as
|        whole. -AllowPartial: the caller reads .Error itself and decides (the rows and the error come back as before, and
|        .Partial says the kind). A read that pages (its query keys the rows) catches the "too large" refusal and reads that
|        page again in smaller pages -- the refusal carries the same words the cut answer did.
|        -OnPage { param($Rows) }: the rows are handed on a PAGE at a time as they arrive (about -PageBytes of answer each,
|        the size measured from the answer's own bytes) and never collected -- memory is one page, whatever the size of the
|        answer. .Results is then empty. The pages are PROVISIONAL until this call returns: a cut answer (said at the END of
|        the answer) or a read that fails half-way throws AFTER pages were handed on, so a caller stages the pages and keeps
|        them only when the call returned. Without the streaming reader (Windows PowerShell, or it cannot be built) the
|        answer is read the older way and then handed on in pages of the same size.
|        THE LEAN READ IS THE DEFAULT (#639): on pwsh 7 the answer arrives as bytes and its rows are read from those bytes
|        (ConvertFrom-SILaQueryRows) -- never also held as one text (twice its size) or as a list of cells per row. The same
|        rows and the same text values as before. Windows PowerShell (no System.Text.Json) reads the text, as always.
|        -WorkspaceId is the workspace's customer id (GUID). -Wait = server timeout in seconds (Prefer: wait=N).
|        -RowsOnly is kept for the callers that name it; it is what every read does now.
|        A refused query throws with the service's own code and message, e.g.
|            "Operation returned an invalid status code 'BadRequest' -- BadArgumentError/SemanticError/SEM0100: ..."
|        and carries the body in Exception.Response.Content and ErrorDetails -- what SI-KqlError.ps1 reads.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$WorkspaceId,
|        [Parameter(Mandatory)][string]$Query,
|        [int]$Wait = 0,
|        [timespan]$Timespan = [timespan]::Zero,
|        [int]$MaxAttempts = 4,
|        [switch]$RowsOnly,
|        # the caller reads .Error itself and decides what a cut answer means (never the default)
|        [switch]$AllowPartial,
|        # the rows a page at a time, never collected (see above)
|        [scriptblock]$OnPage,
|        [long]$PageBytes = 4MB
|    )
|    Initialize-SIAzRestHelpers
|    if ($OnPage) {
|        return (Invoke-SILaQueryPaged -WorkspaceId $WorkspaceId -Query $Query -Wait $Wait -Timespan $Timespan -MaxAttempts $MaxAttempts -AllowPartial:$AllowPartial -OnPage $OnPage -PageBytes $PageBytes)
|    }
|    $uri = 'https://api.loganalytics.io/v1/workspaces/{0}/query' -f $WorkspaceId.Trim()
|    $body = [ordered]@{ query = $Query }
|    if ($Timespan -gt [timespan]::Zero) { $body['timespan'] = [System.Xml.XmlConvert]::ToString($Timespan) }
|    $headers = @{}
|    $timeout = 300
|    # #882 (A4): Log Analytics stops a query at 3 minutes unless asked to wait -- every query asks for its maximum (10 minutes)
|    if ($Wait -le 0) { $Wait = 600 }
|    if ($Wait -gt 0) { $headers['Prefer'] = ('wait={0}' -f $Wait); $timeout = $Wait + 60 }
|    # the answer as bytes wherever it can be read from them (pwsh 7) -- the lean read is the default (#639)
|    $asBytes = ([bool]$RowsOnly -or $PSVersionTable.PSEdition -eq 'Core')
|    # #730: Risk Analysis' reads (its lookups -- SI_LaCompactRows -- and its Log Analytics answers -- SI_LaStreamRows) are
|    # read AS THEY ARRIVE (SI-LaStreamRead.ps1): the same rows, the answer never held whole. Everything else reads as before.
|    $readStream = $null
|    if ($PSVersionTable.PSEdition -eq 'Core' -and ([bool]$global:SI_LaCompactRows -or [bool]$global:SI_LaStreamRows) -and
|        (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore)) {
|        if (Get-SILaStreamReaderType) {
|            $__lsCompact = [bool]$global:SI_LaCompactRows
|            # (no closure: it runs inside this call, so $__lsCompact is seen; a closure would not see this file's functions)
|            # #836: a failed stream read answers a marker -- read again below the older way, never an error of the query
|            $readStream = { param($s) Read-SILaQueryStreamSafe -Stream $s -Compact:$__lsCompact }
|        } else {
|            # #836: never silent -- one line on the run log says the older read is used and why
|            Write-SILaStreamFallback -Once -Reason ([string]$global:SI_LaStreamReaderOff)
|        }
|    }
|    $rq = @{ Method = 'POST'; Uri = $uri; Audience = 'LaQuery'; Body = ($body | ConvertTo-Json -Compress -Depth 5); Headers = $headers
|             TimeoutSec = $timeout; MaxAttempts = $MaxAttempts; AllowStatus = @(400, 403, 404, 409, 413, 422); What = 'Log Analytics query'; AsBytes = $asBytes }
|    if ($readStream) { $rq['ReadStream'] = $readStream }
|    $r = Invoke-SIAzRestRequest @rq
|    if ($readStream -and $r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and $r.Parsed.PSObject.Properties['SILaStreamFailed']) {
|        # #836: the stream read of this answer failed -- the same query again, read the older way (data first), and said
|        Write-SILaStreamFallback -Reason ('reading this answer as it arrived failed (' + [string]$r.Parsed.SILaStreamFailed + '), so it was read again')
|        $r = $null
|        [void]$rq.Remove('ReadStream')
|        $r = Invoke-SIAzRestRequest @rq
|    }
|    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and [int]$r.StatusCode -lt 400) {
|        $streamed = $r.Parsed
|        $r = $null
|        return (Complete-SILaQueryAnswer -Results $streamed.Rows -Columns $streamed.Columns -QueryError $streamed.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
|    }
|    $code = [int]$r.StatusCode
|    # A refusal (always small) is read as text, as is every answer on Windows PowerShell (no System.Text.Json there); an
|    # answer on pwsh 7 is parsed from its bytes below.
|    $content = [string]$r.Content
|    $hasBytes = ($asBytes -and $null -ne $r.Bytes -and $r.Bytes.Length -gt 0)
|    $lean = ($hasBytes -and $code -lt 400 -and $PSVersionTable.PSEdition -eq 'Core')
|    if ($hasBytes -and -not $lean) { $content = [System.Text.Encoding]::UTF8.GetString($r.Bytes) }
|    if ($code -ge 400) { throw (New-SILaQueryRefusedError -Code $code -Content $content -Headers $r.Headers -WorkspaceId $WorkspaceId) }
|    if ($lean) {
|        # a plain statement, never through $( ... ): a subexpression would enumerate the byte array into object[]
|        [byte[]]$answer = $r.Bytes
|        $r = $null
|        $leanAnswer = ConvertFrom-SILaQueryRows -Bytes $answer
|        $answer = $null
|        return (Complete-SILaQueryAnswer -Results $leanAnswer.Rows -Columns $leanAnswer.Columns -QueryError $leanAnswer.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
|    }
|    $parsed = ConvertFrom-SILaQueryJson -Json $content
|    $content = $null
|    $results = [System.Collections.Generic.List[object]]::new()
|    $first = @($parsed.Tables | Where-Object { $_.Name -eq 'PrimaryResult' }) + @($parsed.Tables) | Select-Object -First 1
|    $cols = @()
|    if ($first) {
|        $names = @($first.Columns | ForEach-Object { [string]$_.name })
|        $cols = @($first.Columns | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; type = $(if ($_.PSObject.Properties['type']) { [string]$_.type } else { $null }) } })
|        foreach ($row in $first.Rows) {
|            $o = [ordered]@{}
|            for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $row[$i] }
|            [void]$results.Add([pscustomobject]$o)
|        }
|    }
|    $err = $parsed.Error
|    $parsed = $null; $first = $null
|    return (Complete-SILaQueryAnswer -Results $results.ToArray() -Columns $cols -QueryError $err -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
|}
|
|function New-SILaQueryRefusedError {
|    <# The error a refused query (HTTP 4xx) becomes: the service's own code and message, the body for SI-KqlError. #>
|    param([int]$Code, [AllowNull()][AllowEmptyString()][string]$Content, $Headers, [string]$WorkspaceId = '')
|    $base = "Operation returned an invalid status code '{0}'" -f (Get-SIAzRestStatusName $Code)
|    $resp = [pscustomobject]@{ StatusCode = $Code; Content = $Content; Headers = $Headers }
|    $probe = New-SIAzRestError -Message $base -Response $resp
|    $msg = Get-SIKqlErrorSummary -ErrorRecord $probe
|    if ($msg -eq $base) {
|        # no innererror chain: the top-level error code + message
|        try { $e = ($Content | ConvertFrom-Json).error; if ($e) { $msg = ('{0} -- {1}: {2}' -f $base, [string]$e.code, [string]$e.message) } } catch { }
|    }
|    $ex = New-SIAzRestError -Message $msg -Response $resp
|    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'SILaQueryFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $WorkspaceId)
|    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($Content)
|    $er
|}
|
|function Complete-SILaQueryAnswer {
|    <#
|        The end of every Invoke-SILaQuery read: a cut answer (Test-SILaAnswerWhole) THROWS (New-SILaCutAnswerError) unless
|        -AllowPartial; otherwise the answer (New-SILaQueryAnswer), with .Partial = the kind of a partial answer handed out
|        under -AllowPartial ('' when whole).
|    #>
|    param([AllowNull()][AllowEmptyCollection()][object[]]$Results = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Columns = @(), $QueryError,
|          [switch]$AllowPartial, [string]$WorkspaceId = '', [long]$RowCount = -1)
|    $n = $RowCount
|    if ($n -lt 0) { $n = 0L; if ($null -ne $Results) { $n = [long]$Results.Count } }
|    $v = Test-SILaAnswerWhole -ErrorObject $QueryError -Rows $n
|    if (-not $v.Whole -and -not $AllowPartial) { throw (New-SILaCutAnswerError -Verdict $v -ErrorObject $QueryError -WorkspaceId $WorkspaceId) }
|    $a = New-SILaQueryAnswer -Results $Results -Columns $Columns -QueryError $QueryError
|    $kind = ''; if (-not $v.Whole) { $kind = [string]$v.Kind }
|    $a | Add-Member -NotePropertyName Partial -NotePropertyValue $kind -Force
|    $a | Add-Member -NotePropertyName RowCount -NotePropertyValue $n -Force
|    $a
|}
|
|function Invoke-SILaQueryPaged {
|    <#
|        Invoke-SILaQuery -OnPage: the rows handed on a page at a time, never collected (see Invoke-SILaQuery). The streaming
|        reader (SI-LaStreamRead.ps1) delivers each page as soon as about -PageBytes of the answer's own bytes are in; the
|        compact rows of $global:SI_LaCompactRows apply. A cut answer is refused at the end, after the pages (they are
|        provisional until this returns). A stream read that fails BEFORE any page was handed on is read again the older way;
|        one that fails AFTER a page was handed on throws (handing the pages on again would hand some rows twice).
|        Without the streaming reader: the older read, then the rows in pages of the same measured size.
|        Returns the answer shape with no rows in .Results; .RowCount = the rows handed on, .Pages = the pages.
|    #>
|    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Query, [int]$Wait = 0,
|          [timespan]$Timespan = [timespan]::Zero, [int]$MaxAttempts = 4, [switch]$AllowPartial,
|          [Parameter(Mandatory)][scriptblock]$OnPage, [long]$PageBytes = 4MB)
|    if ($PageBytes -lt 1KB) { $PageBytes = 1KB }
|    $uri = 'https://api.loganalytics.io/v1/workspaces/{0}/query' -f $WorkspaceId.Trim()
|    $body = [ordered]@{ query = $Query }
|    if ($Timespan -gt [timespan]::Zero) { $body['timespan'] = [System.Xml.XmlConvert]::ToString($Timespan) }
|    $headers = @{}
|    $timeout = 300
|    # #882 (A4): Log Analytics stops a query at 3 minutes unless asked to wait -- every query asks for its maximum (10 minutes)
|    if ($Wait -le 0) { $Wait = 600 }
|    if ($Wait -gt 0) { $headers['Prefer'] = ('wait={0}' -f $Wait); $timeout = $Wait + 60 }
|    $rq = @{ Method = 'POST'; Uri = $uri; Audience = 'LaQuery'; Body = ($body | ConvertTo-Json -Compress -Depth 5); Headers = $headers
|             TimeoutSec = $timeout; MaxAttempts = $MaxAttempts; AllowStatus = @(400, 403, 404, 409, 413, 422); What = 'Log Analytics query'
|             AsBytes = ($PSVersionTable.PSEdition -eq 'Core') }
|    $streamable = ($PSVersionTable.PSEdition -eq 'Core' -and (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore) -and (Get-SILaStreamReaderType))
|    $state = @{ Pages = 0; Rows = 0L }
|    if ($streamable) {
|        $__lpCompact = [bool]$global:SI_LaCompactRows
|        $__lpOn = $OnPage; $__lpBytes = $PageBytes; $__lpState = $state
|        $rq['ReadStream'] = { param($s) Read-SILaQueryStreamSafe -Stream $s -Compact:$__lpCompact -OnPage $__lpOn -PageBytes $__lpBytes -PageState $__lpState }
|    } elseif ($PSVersionTable.PSEdition -eq 'Core') {
|        Write-SILaStreamFallback -Once -Reason ([string]$global:SI_LaStreamReaderOff)
|    }
|    $r = Invoke-SIAzRestRequest @rq
|    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and $r.Parsed.PSObject.Properties['SILaStreamFailed']) {
|        if ([int]$state.Pages -gt 0) {
|            throw ('Log Analytics: the answer could not be read to its end ({0}) after {1} page(s) had been handed on -- the read is not whole and its pages must not be used' -f [string]$r.Parsed.SILaStreamFailed, $state.Pages)
|        }
|        Write-SILaStreamFallback -Reason ('reading this answer as it arrived failed (' + [string]$r.Parsed.SILaStreamFailed + '), so it was read again')
|        $r = $null
|        [void]$rq.Remove('ReadStream')
|        $r = Invoke-SIAzRestRequest @rq
|    }
|    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and [int]$r.StatusCode -lt 400) {
|        $p = $r.Parsed; $r = $null
|        $a = Complete-SILaQueryAnswer -Results @() -Columns $p.Columns -QueryError $p.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId -RowCount ([long]$p.RowCount)
|        $a | Add-Member -NotePropertyName Pages -NotePropertyValue ([int]$p.Pages) -Force
|        return $a
|    }
|    # the older read (no streaming reader, or read again): the same refusal of a 4xx and of a cut answer, then the pages
|    [void]$rq.Remove('ReadStream')
|    if ($null -eq $r) { $r = Invoke-SIAzRestRequest @rq }
|    $code = [int]$r.StatusCode
|    $content = [string]$r.Content
|    if ($null -ne $r.Bytes -and $r.Bytes.Length -gt 0 -and ($code -ge 400 -or $PSVersionTable.PSEdition -ne 'Core')) { $content = [System.Text.Encoding]::UTF8.GetString($r.Bytes) }
|    if ($code -ge 400) { throw (New-SILaQueryRefusedError -Code $code -Content $content -Headers $r.Headers -WorkspaceId $WorkspaceId) }
|    $lean = $null
|    if ($null -ne $r.Bytes -and $r.Bytes.Length -gt 0 -and $PSVersionTable.PSEdition -eq 'Core') {
|        [byte[]]$bytes = $r.Bytes
|        $total = [long]$bytes.Length
|        $r = $null
|        $lean = ConvertFrom-SILaQueryRows -Bytes $bytes
|        $bytes = $null
|    } else {
|        $total = [long][System.Text.Encoding]::UTF8.GetByteCount($content)
|        $parsed = ConvertFrom-SILaQueryJson -Json $content
|        $content = $null
|        $first = @($parsed.Tables | Where-Object { $_.Name -eq 'PrimaryResult' }) + @($parsed.Tables) | Select-Object -First 1
|        $rowsL = [System.Collections.Generic.List[object]]::new(); $colsL = @()
|        if ($first) {
|            $names = @($first.Columns | ForEach-Object { [string]$_.name })
|            $colsL = @($first.Columns | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; type = $(if ($_.PSObject.Properties['type']) { [string]$_.type } else { $null }) } })
|            foreach ($row in $first.Rows) { $o = [ordered]@{}; for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $row[$i] }; [void]$rowsL.Add([pscustomobject]$o) }
|        }
|        $lean = [pscustomobject]@{ Rows = $rowsL.ToArray(); Columns = $colsL; Error = $parsed.Error }
|        $parsed = $null; $first = $null
|    }
|    $all = @($lean.Rows); $n = $all.Count
|    # a cut answer is refused BEFORE a page is handed on (the whole answer is in hand on this path)
|    $v = Test-SILaAnswerWhole -ErrorObject $lean.Error -Rows $n
|    if (-not $v.Whole -and -not $AllowPartial) { throw (New-SILaCutAnswerError -Verdict $v -ErrorObject $lean.Error -WorkspaceId $WorkspaceId) }
|    # pages of about -PageBytes of the answer: the measured bytes per row of this answer decide the rows per page
|    $per = $n
|    if ($n -gt 0 -and $total -gt $PageBytes) { $per = [int][Math]::Max(1, [Math]::Floor($n * ([double]$PageBytes / [double]$total))) }
|    $pages = 0
|    for ($i = 0; $i -lt $n; $i += [Math]::Max(1, $per)) {
|        $len = [Math]::Min([Math]::Max(1, $per), $n - $i)
|        $pg = [object[]]::new($len); [Array]::Copy($all, $i, $pg, 0, $len)
|        $null = & $OnPage $pg
|        $pages++
|        for ($k = $i; $k -lt $i + $len; $k++) { $all[$k] = $null }
|    }
|    $a = Complete-SILaQueryAnswer -Results @() -Columns $lean.Columns -QueryError $lean.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId -RowCount ([long]$n)
|    $a | Add-Member -NotePropertyName Pages -NotePropertyValue $pages -Force
|    $a
|}
|
|function New-SILaQueryAnswer {
|    <#
|        PURE. The one shape Invoke-SILaQuery answers (#639): .Results (the rows), .Columns (name / type), .Tables = the
|        primary table's SCHEMA only (Name, Columns, no rows -- RowsOmitted), .Error. The rows are never held twice.
|    #>
|    param([AllowNull()][AllowEmptyCollection()][object[]]$Results = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Columns = @(), $QueryError)
|    $c = @($Columns | Where-Object { $null -ne $_ })
|    $schema = [pscustomobject]@{ Name = 'PrimaryResult'; Columns = $c; Rows = @(); RowsOmitted = $true }
|    # plain statements: an if used as a value would unroll the rows (one row would come back as that row, not a list)
|    $rows = $Results
|    if ($null -eq $rows) { $rows = [object[]]@() }
|    [pscustomobject]@{ Results = $rows; Columns = $c; Tables = @($schema); Error = $QueryError; Statistics = $null; Render = $null }
|}
|
|# =====================================================================================================================
|#  Storage data plane: blob, queue, table (OAuth bearer, x-ms-version)
|# =====================================================================================================================
|
|function Get-SIStorageApiVersion { '2021-08-06' }
|
|function Get-SIStorageUri {
|    param([Parameter(Mandatory)][string]$Account, [ValidateSet('blob', 'queue', 'table')][string]$Service = 'blob', [string]$Path = '', [string]$Query = '')
|    $p = (($Path -split '/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
|    $u = 'https://{0}.{1}.core.windows.net/{2}' -f $Account, $Service, $p
|    if ($Query) { $u += '?' + $Query }
|    return $u
|}
|
|function Invoke-SIStorageRequest {
|    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers, [switch]$AllowNotFound, [int[]]$AllowStatus = @(), [switch]$AsBytes, [string]$What = 'Azure Storage request')
|    $h = @{ 'x-ms-version' = (Get-SIStorageApiVersion); 'x-ms-date' = [datetime]::UtcNow.ToString('R') }
|    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
|    if (-not $ContentType) { $ContentType = 'application/octet-stream' }
|    return (Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Audience Storage -Body $Body -ContentType $ContentType -Headers $h -AllowNotFound:$AllowNotFound -AllowStatus $AllowStatus -AsBytes:$AsBytes -What $What)
|}
|
|function ConvertTo-SIStorageDate {
|    param([string]$Text)
|    $d = [DateTimeOffset]::MinValue
|    if ($Text -and [DateTimeOffset]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
|    return $null
|}
|
|function Get-SIBlobProperties {
|    <# HEAD of one blob: @{ Name; Length; LastModified; ETag; ContentType } or $null when it does not exist. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob)
|    $r = Invoke-SIStorageRequest -Method HEAD -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AllowNotFound -What ("Blob '{0}/{1}'" -f $Container, $Blob)
|    if (-not $r) { return $null }
|    $len = 0L; [void][long]::TryParse([string]$r.Headers['Content-Length'], [ref]$len)
|    return [pscustomobject]@{ Name = $Blob; Container = $Container; Length = $len; LastModified = (ConvertTo-SIStorageDate $r.Headers['Last-Modified']); ETag = [string]$r.Headers['ETag']; ContentType = [string]$r.Headers['Content-Type'] }
|}
|
|function Get-SIBlobList {
|    <# Every blob in -Container under -Prefix (List Blobs, following the marker). #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [string]$Prefix)
|    $out = [System.Collections.Generic.List[object]]::new()
|    $marker = $null
|    do {
|        $q = 'restype=container&comp=list&maxresults=5000'
|        if ($Prefix) { $q += '&prefix=' + [uri]::EscapeDataString($Prefix) }
|        if ($marker) { $q += '&marker=' + [uri]::EscapeDataString($marker) }
|        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query $q) -Headers @{ Accept = 'application/xml' } -What ("List blobs in '{0}'" -f $Container)
|        # The listing is XML (EnumerationResults). A cast `[xml]$text` that fails puts the WHOLE listing (up to 5,000 blobs)
|        # into its error text -- customer B 2026-10-15: "Cannot convert value "<?xml ... EnumerationResults ..." to type
|        # System.Xml.XmlDocument. Error: OutOfMemoryException" as the run's end text. Parsed here; a failure says what failed
|        # and why, in one short line, never the payload.
|        $x = New-Object System.Xml.XmlDocument
|        try { $x.LoadXml((([string]$r.Content) -replace '^\uFEFF', '')) }
|        catch {
|            $why = $_.Exception.Message; if ($_.Exception.InnerException) { $why = $_.Exception.InnerException.Message }
|            if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
|            throw ("The blob list of '{0}' (prefix '{1}') could not be read: {2}" -f $Container, $Prefix, $why)
|        }
|        foreach ($b in @($x.EnumerationResults.Blobs.Blob)) {
|            if ($null -eq $b) { continue }
|            $len = 0L; [void][long]::TryParse([string]$b.Properties.'Content-Length', [ref]$len)
|            [void]$out.Add([pscustomobject]@{ Name = [string]$b.Name; Container = $Container; Length = $len; LastModified = (ConvertTo-SIStorageDate ([string]$b.Properties.'Last-Modified')); ETag = [string]$b.Properties.Etag; ContentType = [string]$b.Properties.'Content-Type' })
|        }
|        $marker = [string]$x.EnumerationResults.NextMarker
|    } while ($marker)
|    return $out.ToArray()
|}
|
|function Get-SIBlobContent {
|    <# Download one blob: the bytes, or -Destination writes them to a file (returns the path). -AllowMissing: a blob that
|       does not exist (404) returns $null -- no error is raised or logged (2026-10-23: the pipeline's poll of a run's
|       records marker logged a TerminatingError 404 every 30 s, hiding the real errors). #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob, [string]$Destination, [switch]$AllowMissing)
|    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AsBytes -AllowNotFound:$AllowMissing -What ("Download blob '{0}/{1}'" -f $Container, $Blob)
|    if ($AllowMissing -and $null -eq $r) { return $null }
|    # PLAIN statements, never `$bytes = if (...) { [byte[]]... }`: an `if` used as a value sends the array through the
|    # pipeline ONE BYTE AT A TIME into an object[] -- about 30 times the blob's size in memory. A new customer install
|    # 2026-10-12: the Azure collection's 13,562 assets made one large part, and reading it back ended in
|    # "System.OutOfMemoryException" on a job with 4 GiB and again with 8 GiB.
|    $bytes = $r.Bytes
|    if ($null -eq $bytes) { $bytes = [byte[]]::new(0) }
|    if (-not $Destination) { return ,$bytes }
|    [System.IO.File]::WriteAllBytes($Destination, $bytes)
|    return $Destination
|}
|
|function Set-SIBlobContent {
|    <# Upload one block blob (create or overwrite) from -File or -Bytes. -IfMatchETag makes it conditional (412 when
|       another writer got there first); -IfNoneMatch creates it only when it does not exist yet (409 / 412 when it does --
|       a claim exactly one writer wins). Returns the new ETag. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob,
|          [string]$File, [byte[]]$Bytes, [string]$IfMatchETag, [string]$ContentType = 'application/octet-stream', [switch]$IfNoneMatch)
|    if ($File) { $Bytes = [System.IO.File]::ReadAllBytes($File) }
|    if ($null -eq $Bytes) { $Bytes = [byte[]]@() }
|    $h = @{ 'x-ms-blob-type' = 'BlockBlob' }
|    if ($IfMatchETag) { $h['If-Match'] = $IfMatchETag }
|    if ($IfNoneMatch) { $h['If-None-Match'] = '*' }
|    $r = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -Body $Bytes -ContentType $ContentType -Headers $h -What ("Upload blob '{0}/{1}'" -f $Container, $Blob)
|    return [string]$r.Headers['ETag']
|}
|
|function Remove-SIBlob {
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob)
|    $null = Invoke-SIStorageRequest -Method DELETE -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AllowNotFound -What ("Delete blob '{0}/{1}'" -f $Container, $Blob)
|}
|
|function Test-SIBlobContainer {
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container)
|    $r = Invoke-SIStorageRequest -Method HEAD -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query 'restype=container') -AllowNotFound -What ("Container '{0}'" -f $Container)
|    if (-not $r) { return $null }
|    return [pscustomobject]@{ Name = $Container; LastModified = (ConvertTo-SIStorageDate $r.Headers['Last-Modified']); ETag = [string]$r.Headers['ETag'] }
|}
|
|function New-SIBlobContainer {
|    <# Create a private container; an existing one is not an error. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container)
|    $null = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query 'restype=container') -AllowStatus @(409) -What ("Create container '{0}'" -f $Container)
|    return [pscustomobject]@{ Name = $Container }
|}
|
|function Test-SIQueue {
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue)
|    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Service queue -Path $Queue -Query 'comp=metadata') -AllowNotFound -What ("Queue '{0}'" -f $Queue)
|    return [bool]$r
|}
|
|function New-SIQueue {
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue)
|    $null = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Service queue -Path $Queue) -AllowStatus @(409) -What ("Create queue '{0}'" -f $Queue)
|}
|
|function Send-SIQueueMessage {
|    <# Put one message. The text is sent as-is (XML-escaped), the encoding the Az.Storage 9 queue client uses. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
|    $body = '<QueueMessage><MessageText>{0}</MessageText></QueueMessage>' -f [System.Security.SecurityElement]::Escape($Text)
|    $r = Invoke-SIStorageRequest -Method POST -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages")) -Body $body -ContentType 'application/xml' -What ("Send to queue '{0}'" -f $Queue)
|    $x = [xml]($r.Content -replace '^\uFEFF', '')
|    return [pscustomobject]@{ MessageId = [string]$x.QueueMessagesList.QueueMessage.MessageId; PopReceipt = [string]$x.QueueMessagesList.QueueMessage.PopReceipt }
|}
|
|function Receive-SIQueueMessage {
|    <# Lease one message for -VisibilityTimeoutSeconds: @{ MessageId; PopReceipt; MessageText; DequeueCount } or $null
|       when the queue is empty. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [int]$VisibilityTimeoutSeconds = 30)
|    $q = 'numofmessages=1&visibilitytimeout={0}' -f $VisibilityTimeoutSeconds
|    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages") -Query $q) -Headers @{ Accept = 'application/xml' } -What ("Receive from queue '{0}'" -f $Queue)
|    $x = [xml]($r.Content -replace '^\uFEFF', '')
|    $m = @($x.QueueMessagesList.QueueMessage) | Where-Object { $_ } | Select-Object -First 1
|    if (-not $m) { return $null }
|    return [pscustomobject]@{ MessageId = [string]$m.MessageId; PopReceipt = [string]$m.PopReceipt; MessageText = [string]$m.MessageText; DequeueCount = [int]$m.DequeueCount }
|}
|
|function Update-SIQueueMessage {
|    <#
|        RENEW the hold on one leased message: its visibility timeout is set to -VisibilityTimeoutSeconds from now (Update
|        Message). The message text goes back unchanged (-Text: as it was received). NEVER THROWS -- the answer says which:
|          @{ Ok = $true;  PopReceipt = <the NEW receipt: the old one is no longer valid> }
|          @{ Ok = $false; Lost = $true;  Why }   the message is gone (404) or another worker holds it (400 PopReceiptMismatch)
|          @{ Ok = $false; Lost = $false; Why }   anything else (network, sign-in, a 5xx): not known -- try again
|        Short timeouts and two attempts: this is called from a heartbeat, which must not hang on one request.
|        -Auth: the identity to sign in as (a second thread has no sign-in of its own; Resolve-SIAzRestAuth's answer).
|    #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][string]$MessageId, [Parameter(Mandatory)][string]$PopReceipt,
|          [Parameter(Mandatory)][int]$VisibilityTimeoutSeconds, [AllowEmptyString()][string]$Text = '', [hashtable]$Auth, [int]$TimeoutSec = 30)
|    try {
|        $q = 'popreceipt={0}&visibilitytimeout={1}' -f [uri]::EscapeDataString($PopReceipt), $VisibilityTimeoutSeconds
|        $body = '<QueueMessage><MessageText>{0}</MessageText></QueueMessage>' -f [System.Security.SecurityElement]::Escape($Text)
|        $h = @{ 'x-ms-version' = (Get-SIStorageApiVersion); 'x-ms-date' = [datetime]::UtcNow.ToString('R') }
|        $r = Invoke-SIAzRestRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages/$MessageId") -Query $q) -Audience Storage -Body $body `
|                -ContentType 'application/xml' -Headers $h -AllowStatus @(400, 404) -TimeoutSec $TimeoutSec -MaxAttempts 2 -Auth $Auth -What ("Renew the hold on a message of queue '{0}'" -f $Queue)
|        $code = 0; try { $code = [int]$r.StatusCode } catch { }
|        if ($code -ge 200 -and $code -lt 300) {
|            $new = [string]$r.Headers['x-ms-popreceipt']
|            if (-not $new) { return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = 'the queue answered without a new receipt' } }
|            return [pscustomobject]@{ Ok = $true; Lost = $false; PopReceipt = $new; Why = '' }
|        }
|        if ($code -eq 404) { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'the message is no longer in the queue' } }
|        $said = [string]$r.Content; try { if ($r.Headers -and $r.Headers['x-ms-error-code']) { $said += ' ' + [string]$r.Headers['x-ms-error-code'] } } catch { }
|        if ($code -eq 400 -and $said -match '(?i)PopReceiptMismatch|MessageNotFound') { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'another worker holds the message now' } }
|        return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = ('HTTP {0}: {1}' -f $code, (([string]$r.Content -replace '\s+', ' ').Trim() -replace '^(.{200}).*$', '$1...')) }
|    } catch {
|        return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = [string]$_.Exception.Message }
|    }
|}
|
|function Remove-SIQueueMessage {
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][string]$MessageId, [Parameter(Mandatory)][string]$PopReceipt)
|    $q = 'popreceipt=' + [uri]::EscapeDataString($PopReceipt)
|    $null = Invoke-SIStorageRequest -Method DELETE -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages/$MessageId") -Query $q) -AllowNotFound -What ("Delete from queue '{0}'" -f $Queue)
|}
|
|function Get-SITableEntity {
|    <# One table entity (PartitionKey + RowKey) or $null; without -RowKey, every entity of the partition (following the
|       continuation headers). #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey, [string]$RowKey)
|    $h = @{ Accept = 'application/json;odata=nometadata' }
|    $esc = { param($s) ([string]$s).Replace("'", "''") }
|    if ($RowKey) {
|        $path = "{0}(PartitionKey='{1}',RowKey='{2}')" -f $Table, [uri]::EscapeDataString((& $esc $PartitionKey)), [uri]::EscapeDataString((& $esc $RowKey))
|        $r = Invoke-SIStorageRequest -Method GET -Uri ('https://{0}.table.core.windows.net/{1}' -f $Account, $path) -Headers $h -ContentType 'application/json' -AllowNotFound -What ("Table '{0}' entity" -f $Table)
|        if (-not $r) { return $null }
|        return ($r.Content | ConvertFrom-Json)
|    }
|    $out = [System.Collections.Generic.List[object]]::new()
|    $filter = [uri]::EscapeDataString(("PartitionKey eq '{0}'" -f (& $esc $PartitionKey)))
|    $np = $null; $nr = $null
|    do {
|        $q = '$filter=' + $filter
|        if ($np) { $q += '&NextPartitionKey=' + [uri]::EscapeDataString($np) }
|        if ($nr) { $q += '&NextRowKey=' + [uri]::EscapeDataString($nr) }
|        $r = Invoke-SIStorageRequest -Method GET -Uri ('https://{0}.table.core.windows.net/{1}()?{2}' -f $Account, $Table, $q) -Headers $h -ContentType 'application/json' -What ("Table '{0}' query" -f $Table)
|        foreach ($e in @(($r.Content | ConvertFrom-Json).value)) { if ($e) { [void]$out.Add($e) } }
|        $np = [string]$r.Headers['x-ms-continuation-NextPartitionKey']; $nr = [string]$r.Headers['x-ms-continuation-NextRowKey']
|    } while ($np)
|    return $out.ToArray()
|}
|
|function Set-SITableEntity {
|    <# UPSERT one entity (Insert Or Replace; -Merge = Insert Or Merge). -Entity is a hashtable of properties. #>
|    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey,
|          [Parameter(Mandatory)][string]$RowKey, [hashtable]$Entity = @{}, [switch]$Merge)
|    $e = [ordered]@{ PartitionKey = $PartitionKey; RowKey = $RowKey }
|    foreach ($k in $Entity.Keys) { if ($k -notin 'PartitionKey', 'RowKey') { $e[$k] = $Entity[$k] } }
|    $esc = { param($s) ([string]$s).Replace("'", "''") }
|    $path = "{0}(PartitionKey='{1}',RowKey='{2}')" -f $Table, [uri]::EscapeDataString((& $esc $PartitionKey)), [uri]::EscapeDataString((& $esc $RowKey))
|    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($e | ConvertTo-Json -Depth 5 -Compress))
|    $null = Invoke-SIStorageRequest -Method $(if ($Merge) { 'MERGE' } else { 'PUT' }) -Uri ('https://{0}.table.core.windows.net/{1}' -f $Account, $path) -Body $bytes `
|                -ContentType 'application/json' -Headers @{ Accept = 'application/json;odata=nometadata' } -What ("Table '{0}' upsert" -f $Table)
|}
|
|# =====================================================================================================================
|#  The wrappers -- each forwards to its REST twin below
|# =====================================================================================================================
|# Each declares the parameters SecurityInsight's call sites use, UNTYPED except switches, and forwards @PSBoundParameters
|# -- never @args (measured: @args splits -Name:$value into a switch plus a positional value).
|function Connect-SIAzAccount {
|    [CmdletBinding()]
|    param([switch]$Identity, $AccountId, [switch]$ServicePrincipal, $ApplicationId, $CertificateThumbprint,
|          $CertificatePath, $CertificatePassword, $Credential,
|          [Alias('TenantId')]$Tenant, [Alias('SubscriptionId')]$Subscription, $Scope)
|    return (Connect-SIAzAccountRest @PSBoundParameters)
|}
|function Disconnect-SIAzAccount {
|    [CmdletBinding()] param($Scope)
|    return (Disconnect-SIAzAccountRest @PSBoundParameters)
|}
|function Disable-SIAzContextAutosave {
|    [CmdletBinding()] param($Scope)
|    return (Disable-SIAzContextAutosaveRest @PSBoundParameters)
|}
|function Get-SIAzContext {
|    [CmdletBinding()] param()
|    return (Get-SIAzContextRest @PSBoundParameters)
|}
|function Set-SIAzContext {
|    [CmdletBinding()]
|    param([Alias('SubscriptionId', 'SubscriptionName')]$Subscription, [Alias('TenantId', 'Domain')]$Tenant, $Context, $Scope)
|    return (Set-SIAzContextRest @PSBoundParameters)
|}
|function Get-SIAzAccessToken {
|    [CmdletBinding()] param($ResourceUrl, $TenantId)
|    return (Get-SIAzAccessTokenRest @PSBoundParameters)
|}
|function Get-SIAzSubscription {
|    [CmdletBinding()] param($TenantId, $SubscriptionId)
|    return (Get-SIAzSubscriptionRest @PSBoundParameters)
|}
|function Invoke-SIAzRestMethod {
|    [CmdletBinding()] param($Path, $Method, $Payload)
|    return (Invoke-SIAzRestMethodRest @PSBoundParameters)
|}
|function Invoke-SIAzOperationalInsightsQuery {
|    # -AllowPartial: the caller reads .Error itself (Invoke-SILaQuery refuses a cut answer otherwise); -OnPage / -PageBytes:
|    # the rows a page at a time (Invoke-SILaQuery)
|    [CmdletBinding()] param($WorkspaceId, $Query, $Wait, $Timespan, [switch]$AllowPartial, [scriptblock]$OnPage, [long]$PageBytes)
|    return (Invoke-SIAzOperationalInsightsQueryRest @PSBoundParameters)
|}
|function Get-SIAzOperationalInsightsWorkspace {
|    [CmdletBinding()] param($ResourceGroupName, $Name)
|    return (Get-SIAzOperationalInsightsWorkspaceRest @PSBoundParameters)
|}
|function New-SIAzOperationalInsightsWorkspace {
|    [CmdletBinding()] param($ResourceGroupName, $Name, $Location, $Sku, $RetentionInDays)
|    return (New-SIAzOperationalInsightsWorkspaceRest @PSBoundParameters)
|}
|function Search-SIAzGraph {
|    [CmdletBinding()] param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
|    return ,(Search-SIAzGraphRest @PSBoundParameters)   # one page object, not its rows
|}
|function Get-SIAzKeyVaultSecret {
|    [CmdletBinding()] param($VaultName, $Name, [switch]$AsPlainText)
|    return (Get-SIAzKeyVaultSecretRest @PSBoundParameters)
|}
|function Set-SIAzKeyVaultSecret {
|    [CmdletBinding()] param($VaultName, $Name, $SecretValue, $ContentType)
|    return (Set-SIAzKeyVaultSecretRest @PSBoundParameters)
|}
|function Get-SIAzResourceGroup {
|    [CmdletBinding()] param($Name)
|    return (Get-SIAzResourceGroupRest @PSBoundParameters)
|}
|function New-SIAzResourceGroup {
|    [CmdletBinding()] param($Name, $Location, $Tag)
|    return (New-SIAzResourceGroupRest @PSBoundParameters)
|}
|function Get-SIAzRoleAssignment {
|    [CmdletBinding()] param($ObjectId, $Scope, $RoleDefinitionName)
|    return (Get-SIAzRoleAssignmentRest @PSBoundParameters)
|}
|function New-SIAzRoleAssignment {
|    [CmdletBinding()] param($ObjectId, $Scope, $RoleDefinitionName, $Description)
|    return (New-SIAzRoleAssignmentRest @PSBoundParameters)
|}
|function Get-SIAzRoleDefinition {
|    [CmdletBinding()] param([switch]$Custom, $Name, $Scope)
|    return (Get-SIAzRoleDefinitionRest @PSBoundParameters)
|}
|function Get-SIAzTag {
|    [CmdletBinding()] param($ResourceId)
|    return (Get-SIAzTagRest @PSBoundParameters)
|}
|function Update-SIAzTag {
|    [CmdletBinding()] param($ResourceId, $Tag, $Operation)
|    return (Update-SIAzTagRest @PSBoundParameters)
|}
|function Get-SIAzADServicePrincipal {
|    [CmdletBinding()] param($ApplicationId, $ObjectId)
|    return (Get-SIAzADServicePrincipalRest @PSBoundParameters)
|}
|function Get-SIAzDataCollectionEndpoint {
|    [CmdletBinding()] param($Name, $ResourceGroupName)
|    return (Get-SIAzDataCollectionEndpointRest @PSBoundParameters)
|}
|function New-SIAzDataCollectionEndpoint {
|    [CmdletBinding()] param($Name, $ResourceGroupName, $Location, $NetworkAclsPublicNetworkAccess)
|    return (New-SIAzDataCollectionEndpointRest @PSBoundParameters)
|}
|function Get-SIAzDataCollectionRule {
|    [CmdletBinding()] param($Name, $ResourceGroupName)
|    return (Get-SIAzDataCollectionRuleRest @PSBoundParameters)
|}
|function New-SIAzStorageContext {
|    [CmdletBinding()] param($StorageAccountName, [switch]$UseConnectedAccount)
|    return (New-SIAzStorageContextRest @PSBoundParameters)
|}
|function Get-SIAzStorageAccount {
|    [CmdletBinding()] param($ResourceGroupName, $Name)
|    return (Get-SIAzStorageAccountRest @PSBoundParameters)
|}
|function New-SIAzStorageAccount {
|    [CmdletBinding()]
|    param($ResourceGroupName, $Name, $Location, $SkuName, $Kind, $EnableHttpsTrafficOnly,
|          $MinimumTlsVersion, $AllowBlobPublicAccess, $PublicNetworkAccess)
|    return (New-SIAzStorageAccountRest @PSBoundParameters)
|}
|function Get-SIAzStorageContainer {
|    [CmdletBinding()] param($Name, $Context)
|    return (Get-SIAzStorageContainerRest @PSBoundParameters)
|}
|function New-SIAzStorageContainer {
|    [CmdletBinding()] param($Name, $Context, $Permission)
|    return (New-SIAzStorageContainerRest @PSBoundParameters)
|}
|function Get-SIAzStorageBlob {
|    [CmdletBinding()] param($Container, $Blob, $Prefix, $Context)
|    return (Get-SIAzStorageBlobRest @PSBoundParameters)
|}
|function Get-SIAzStorageBlobContent {
|    [CmdletBinding()] param($Container, $Blob, $CloudBlob, $Destination, $Context, [switch]$Force)
|    return (Get-SIAzStorageBlobContentRest @PSBoundParameters)
|}
|function Set-SIAzStorageBlobContent {
|    [CmdletBinding()] param($File, $Container, $Blob, $Context, [switch]$Force)
|    return (Set-SIAzStorageBlobContentRest @PSBoundParameters)
|}
|function Remove-SIAzStorageBlob {
|    [CmdletBinding()] param($Container, $Blob, $Context, [switch]$Force)
|    return (Remove-SIAzStorageBlobRest @PSBoundParameters)
|}
|function Start-SIAzStorageBlobCopy {
|    [CmdletBinding()] param($SrcContainer, $SrcBlob, $DestContainer, $DestBlob, $Context, [switch]$Force)
|    return (Start-SIAzStorageBlobCopyRest @PSBoundParameters)
|}
|function Get-SIAzStorageQueue {
|    [CmdletBinding()] param($Name, $Context)
|    return (Get-SIAzStorageQueueRest @PSBoundParameters)
|}
|function New-SIAzStorageQueue {
|    [CmdletBinding()] param($Name, $Context)
|    return (New-SIAzStorageQueueRest @PSBoundParameters)
|}
|
|function Set-SIAzStorageBlobContentIfMatch {
|    <# The ledger's CONDITIONAL write (only when the blob still has -IfMatchETag): PUT with If-Match. A lost race fails
|       with '412 ConditionNotMet'. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob,
|          [Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$IfMatchETag)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    $null = Set-SIBlobContent -Account $acct -Container $Container -Blob $Blob -File $File -IfMatchETag $IfMatchETag
|}
|# =====================================================================================================================
|#  The REST twins -- what each wrapper does with no Az module
|# =====================================================================================================================
|
|function Write-SIAzRestNotFound {
|    <# A lookup that found nothing, the way the Az cmdlet reports it: a NON-terminating error, so -ErrorAction
|       SilentlyContinue yields $null and -ErrorAction Stop throws. #>
|    param([Parameter(Mandatory)]$Cmdlet, [Parameter(Mandatory)][string]$Message, [string]$Target)
|    $er = New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception($Message)), 'SIAzRestNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $Target)
|    $Cmdlet.WriteError($er)
|}
|
|function Get-SIAzRestSubscriptionId {
|    <# The current subscription: Set-SIAzContext / Connect -Subscription, else the install's workspace subscription,
|       else the first enabled subscription the identity sees (what Connect-AzAccount selects). #>
|    param([switch]$NoLookup)
|    $st = Get-SIAzRestState
|    if ($st.SubscriptionId) { return [string]$st.SubscriptionId }
|    $s = [string](Get-SIAzRestValue 'SI_AzSubscriptionId')
|    if (-not $s -and [string](Get-SIAzRestValue 'SI_WorkspaceResourceId') -match '/subscriptions/([^/]+)/') { $s = $Matches[1] }
|    if (-not $s) { $s = [string](Get-SIAzRestValue 'SubscriptionId') }
|    # in an Invardia Support session, the first subscription the environment names
|    if (-not $s) { $sess = Get-SISupportSession; if ($sess -and $sess.SubscriptionId) { $s = [string]$sess.SubscriptionId } }
|    if (-not $s -and -not $NoLookup) {
|        try {
|            $first = @(Invoke-SIArm -Path '/subscriptions' -ApiVersion '2022-12-01' -List | Where-Object { [string]$_.state -eq 'Enabled' }) | Select-Object -First 1
|            if ($first) { $s = [string]$first.subscriptionId }
|        } catch { }
|    }
|    if ($s) { $st.SubscriptionId = $s }
|    return $s
|}
|
|function Get-SIAzRestTenantId {
|    $st = Get-SIAzRestState
|    if ($st.TenantId) { return [string]$st.TenantId }
|    $a = Resolve-SIAzRestAuth
|    $t = [string]$a.TenantId
|    if (-not $t) {
|        # a managed identity knows its tenant: read it from its own ARM token
|        try { $c = ConvertFrom-SIJwtPayload (Get-SIAzureToken -Audience Arm); if ($c) { $t = [string]$c.tid } } catch { }
|    }
|    if ($t) { $st.TenantId = $t }
|    return $t
|}
|
|function Connect-SIAzAccountRest {
|    <# RECORDS the identity; no sign-in happens here (each REST call mints its token when it needs one). #>
|    [CmdletBinding()]
|    param([switch]$Identity, [string]$AccountId, [switch]$ServicePrincipal, [string]$ApplicationId, [string]$CertificateThumbprint,
|          [string]$CertificatePath, [securestring]$CertificatePassword, [pscredential]$Credential,
|          [Alias('TenantId')][string]$Tenant, [Alias('SubscriptionId')][string]$Subscription, [string]$Scope)
|    $st = Get-SIAzRestState
|    $conn = $null
|    if ($Identity) {
|        $cid = if ($AccountId) { $AccountId } else { [string](Get-SIAzRestValue 'SI_UAMI_ClientId', 'SI_ManagedIdentityClientId') }
|        $conn = @{ Mode = 'ManagedIdentity'; ClientId = $cid }
|    } elseif ($Credential) {
|        $conn = @{ Mode = 'Secret'; AppId = [string]$Credential.UserName; TenantId = $Tenant; Secret = $Credential.GetNetworkCredential().Password }
|    } elseif ($CertificateThumbprint -or $CertificatePath) {
|        $thumb = $CertificateThumbprint
|        if ($CertificatePath) {
|            # the PFX the container wrote: the token signer looks a certificate up by thumbprint in the X509 store, so
|            # it goes into CurrentUser\My (the only store a Linux container has) unless it is already there
|            $pw = if ($CertificatePassword) { [System.Net.NetworkCredential]::new('', $CertificatePassword).Password } else { '' }
|            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
|            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.IO.File]::ReadAllBytes($CertificatePath), $pw, $flags)
|            $thumb = [string]$cert.Thumbprint
|            Initialize-SIAzRestHelpers
|            if (-not (Get-SICertificateFromStore -Thumbprint $thumb)) {
|                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
|                try { $store.Open('ReadWrite'); $store.Add($cert) } finally { $store.Close() }
|            }
|        }
|        $conn = @{ Mode = 'Certificate'; AppId = $ApplicationId; TenantId = $Tenant; Thumbprint = ($thumb -replace '\s', '') }
|    } else {
|        throw 'Connect-SIAzAccount (REST): name the identity -- -Identity, -Credential, or -ApplicationId with -CertificateThumbprint / -CertificatePath.'
|    }
|    $st.Connection = $conn
|    $st.TenantId = if ($Tenant) { $Tenant } else { $null }
|    $st.SubscriptionId = if ($Subscription) { $Subscription } else { $null }
|    $st.Cache = @{}
|    return (Get-SIAzContextRest)
|}
|
|function Disconnect-SIAzAccountRest {
|    [CmdletBinding()] param([string]$Scope)
|    $st = Get-SIAzRestState
|    $st.Connection = $null; $st.SubscriptionId = $null; $st.TenantId = $null; $st.Cache = @{}
|    $rc = Get-Variable -Scope Global -Name SI_LogIngestRunCache -ValueOnly -ErrorAction Ignore
|    if ($rc -is [hashtable]) { $rc.Tokens = @{} }
|}
|
|function Disable-SIAzContextAutosaveRest { [CmdletBinding()] param([string]$Scope) }
|
|function Get-SIAzContextRest {
|    <# The context object the call sites read (Subscription.Id / .Name, Tenant.Id, Account.Id / .Type), or $null when
|       no identity is configured. #>
|    [CmdletBinding()] param()
|    try { $a = Resolve-SIAzRestAuth } catch { return $null }
|    $sub = Get-SIAzRestSubscriptionId
|    $tid = Get-SIAzRestTenantId
|    $acct = switch ($a.Mode) { 'ManagedIdentity' { [pscustomobject]@{ Id = $(if ($a.ClientId) { $a.ClientId } else { 'MSI' }); Type = 'ManagedService' } } default { [pscustomobject]@{ Id = $a.AppId; Type = 'ServicePrincipal' } } }
|    return [pscustomobject]@{
|        PSTypeName   = 'SI.AzRest.Context'
|        Name         = ('{0} ({1})' -f $sub, $acct.Id)
|        Account      = $acct
|        Subscription = $(if ($sub) { [pscustomobject]@{ Id = $sub; SubscriptionId = $sub; Name = $sub; TenantId = $tid; ExtendedProperties = @{} } } else { $null })
|        Tenant       = [pscustomobject]@{ Id = $tid; TenantId = $tid }
|        Environment  = [pscustomobject]@{ Name = 'AzureCloud' }
|    }
|}
|
|function Set-SIAzContextRest {
|    [CmdletBinding()]
|    param([Alias('SubscriptionId', 'SubscriptionName')][string]$Subscription, [Alias('TenantId', 'Domain')][string]$Tenant, [object]$Context, [string]$Scope)
|    $st = Get-SIAzRestState
|    if ($Context -and $Context.Subscription) { $Subscription = [string]$Context.Subscription.Id }
|    if ($Subscription) { $st.SubscriptionId = $Subscription }
|    if ($Tenant) { $st.TenantId = $Tenant }
|    return (Get-SIAzContextRest)
|}
|
|function Get-SIAzAccessTokenRest {
|    [CmdletBinding()] param([string]$ResourceUrl, [string]$TenantId)
|    $res = if ($ResourceUrl) { $ResourceUrl } else { 'https://management.azure.com/' }
|    $tok = Get-SIAzureToken -Resource $res
|    $c = ConvertFrom-SIJwtPayload $tok
|    $exp = [DateTimeOffset]::UtcNow.AddMinutes(45)
|    if ($c -and $c.exp) { try { $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$c.exp) } catch { } }
|    return [pscustomobject]@{ Token = $tok; ExpiresOn = $exp; Type = 'Bearer'; TenantId = $(if ($c) { [string]$c.tid } else { $null }); UserId = $(if ($c) { [string]$c.appid } else { $null }) }
|}
|
|function Get-SIAzSubscriptionRest {
|    [CmdletBinding()] param([string]$TenantId, [string]$SubscriptionId)
|    foreach ($s in @(Invoke-SIArm -Path '/subscriptions' -ApiVersion '2022-12-01' -List)) {
|        if ($TenantId -and [string]$s.tenantId -and [string]$s.tenantId -ne $TenantId) { continue }
|        if ($SubscriptionId -and [string]$s.subscriptionId -ne $SubscriptionId) { continue }
|        [pscustomobject]@{ Id = [string]$s.subscriptionId; SubscriptionId = [string]$s.subscriptionId; Name = [string]$s.displayName; State = [string]$s.state; TenantId = [string]$s.tenantId; HomeTenantId = [string]$s.tenantId }
|    }
|}
|
|function Invoke-SIAzRestMethodRest {
|    <# As Invoke-AzRestMethod: never throws on an HTTP status; returns StatusCode / Content / Headers / Method. #>
|    [CmdletBinding()] param([string]$Path, [string]$Method = 'GET', [string]$Payload)
|    if (-not $Method) { $Method = 'GET' }
|    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
|    $body = if ($Payload) { $Payload } else { $null }
|    # #564: a POST action with no body sends '{}' (an empty JSON body was refused with HTTP 415)
|    if ($Method.ToUpperInvariant() -eq 'POST' -and $null -eq $body) { $body = '{}' }
|    # #548: inside an Invardia support session through the recording wrapper, never a raw token
|    if (Test-SISupportRequestRoute -Audience Arm) { $r = Invoke-SISupportHttp -Method $Method -Uri $uri -Body $body -ContentType 'application/json' -Audience Arm }
|    else {
|        $tok = Get-SIAzureToken -Audience Arm
|        $r = Invoke-SIAzRestHttp -Method $Method -Uri $uri -Headers @{ Authorization = ('Bearer ' + $tok) } -Body $body -ContentType 'application/json'
|    }
|    return [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Content = [string]$r.Content; Headers = $r.Headers; Method = $Method.ToUpperInvariant() }
|}
|
|function Invoke-SIAzOperationalInsightsQueryRest {
|    [CmdletBinding()] param([string]$WorkspaceId, [string]$Query, [int]$Wait, [timespan]$Timespan, [switch]$AllowPartial, [scriptblock]$OnPage, [long]$PageBytes)
|    $p = @{ WorkspaceId = $WorkspaceId; Query = $Query }
|    if ($PSBoundParameters.ContainsKey('Wait')) { $p['Wait'] = $Wait }
|    if ($PSBoundParameters.ContainsKey('Timespan')) { $p['Timespan'] = $Timespan }
|    if ($AllowPartial) { $p['AllowPartial'] = $true }
|    if ($OnPage) { $p['OnPage'] = $OnPage }
|    if ($PSBoundParameters.ContainsKey('PageBytes') -and $PageBytes -gt 0) { $p['PageBytes'] = $PageBytes }
|    return (Invoke-SILaQuery @p)
|}
|
|function ConvertTo-SIAzWorkspaceObject {
|    param($Ws)
|    $cid = [guid]::Empty
|    [void][guid]::TryParse([string]$Ws.properties.customerId, [ref]$cid)
|    $rg = if ([string]$Ws.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
|    [pscustomobject]@{
|        Name = [string]$Ws.name; ResourceId = [string]$Ws.id; ResourceGroupName = $rg; Location = [string]$Ws.location
|        CustomerId = $cid; Sku = [string]$Ws.properties.sku.name; RetentionInDays = $Ws.properties.retentionInDays
|        ProvisioningState = [string]$Ws.properties.provisioningState; Tags = $Ws.tags
|    }
|}
|
|function Get-SIAzOperationalInsightsWorkspaceRest {
|    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name)
|    $sub = Get-SIAzRestSubscriptionId
|    if ($ResourceGroupName -and $Name) {
|        $ws = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$Name") -ApiVersion '2022-10-01' -AllowNotFound
|        if (-not $ws) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Log Analytics workspace '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|        return (ConvertTo-SIAzWorkspaceObject $ws)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces" } else { "/subscriptions/$sub/providers/Microsoft.OperationalInsights/workspaces" }
|    foreach ($w in @(Invoke-SIArm -Path $path -ApiVersion '2022-10-01' -List)) {
|        if ($Name -and [string]$w.name -ne $Name) { continue }
|        ConvertTo-SIAzWorkspaceObject $w
|    }
|}
|
|function New-SIAzOperationalInsightsWorkspaceRest {
|    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name, [string]$Location, [string]$Sku = 'PerGB2018', [int]$RetentionInDays = 30)
|    if (-not $Sku) { $Sku = 'PerGB2018' }
|    $sub = Get-SIAzRestSubscriptionId
|    $body = @{ location = $Location; properties = @{ sku = @{ name = $Sku } } }
|    if ($PSBoundParameters.ContainsKey('RetentionInDays')) { $body.properties['retentionInDays'] = $RetentionInDays }
|    $wsPath = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$Name"
|    $ws = Invoke-SIArm -Method PUT -Path $wsPath -ApiVersion '2022-10-01' -Body $body
|    # the create is asynchronous (its answer can be empty, or a workspace still being made): wait until the workspace is
|    # THERE and provisioned -- its id and customer id are used right after this returns. Not ready in time = a clear stop.
|    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
|    $state = ''
|    for ($i = 0; $i -lt 60; $i++) {
|        $state = if ($ws -and $ws.properties) { [string]$ws.properties.provisioningState } else { '' }
|        if ($ws -and [string]$ws.id -and ($state -eq 'Succeeded' -or -not $state)) { return (ConvertTo-SIAzWorkspaceObject $ws) }
|        if ($state -in 'Failed', 'Canceled') { throw ("The Log Analytics workspace '{0}' was not created: Azure reports it {1} -- see the activity log of resource group '{2}' for its reason." -f $Name, $state, $ResourceGroupName) }
|        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
|        $ws = Invoke-SIArm -Path $wsPath -ApiVersion '2022-10-01' -AllowNotFound
|    }
|    throw ("The Log Analytics workspace '{0}' is not ready 5 minutes after it was created (Azure shows: {1})." -f $Name, $(if ($state) { $state } else { 'not there yet' }))
|}
|
|function New-SIAzGraphPage {
|    <# A page shaped like Search-AzGraph's response: enumerates as the rows, with .Data and .SkipToken. #>
|    param([object[]]$Rows, [string]$SkipToken)
|    $list = [System.Collections.Generic.List[object]]::new()
|    foreach ($r in @($Rows)) { if ($null -ne $r) { [void]$list.Add($r) } }
|    Add-Member -InputObject $list -NotePropertyName Data -NotePropertyValue $list.ToArray() -Force
|    Add-Member -InputObject $list -NotePropertyName SkipToken -NotePropertyValue $(if ($SkipToken) { $SkipToken } else { $null }) -Force
|    return ,$list
|}
|
|function Search-SIAzGraphRest {
|    [CmdletBinding()] param([string]$Query, [int]$First = 100, [int]$Skip, [string[]]$Subscription, [string[]]$ManagementGroup, [string]$SkipToken)
|    if (-not $PSBoundParameters.ContainsKey('First') -or $First -le 0) { $First = 100 }
|    $page = Invoke-SIResourceGraphPage -Query $Query -Subscription $Subscription -ManagementGroup $ManagementGroup -First $First -Skip $Skip -SkipToken $SkipToken
|    $p = New-SIAzGraphPage -Rows $page.Data -SkipToken $page.SkipToken
|    return ,$p
|}
|
|function Get-SIAzKeyVaultSecretRest {
|    [CmdletBinding()] param([string]$VaultName, [string]$Name, [switch]$AsPlainText)
|    $j = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name
|    if (-not $j) { return }
|    if ($AsPlainText) { return [string]$j.value }
|    $sec = New-Object System.Security.SecureString
|    foreach ($ch in ([string]$j.value).ToCharArray()) { $sec.AppendChar($ch) }
|    $sec.MakeReadOnly()
|    return [pscustomobject]@{ VaultName = $VaultName; Name = $Name; Id = [string]$j.id; SecretValue = $sec; ContentType = [string]$j.contentType; Enabled = $j.attributes.enabled; Tags = $j.tags }
|}
|
|function Set-SIAzKeyVaultSecretRest {
|    <# PUT secrets/{name}: a new version of the secret. -SecretValue is a SecureString (as for the cmdlet) or plain text. #>
|    [CmdletBinding()] param([string]$VaultName, [string]$Name, $SecretValue, [string]$ContentType)
|    $plain = if ($SecretValue -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $SecretValue).Password } else { [string]$SecretValue }
|    $body = @{ value = $plain }
|    if ($ContentType) { $body.contentType = $ContentType }
|    $uri = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
|    $r = Invoke-SIAzRestRequest -Method PUT -Uri $uri -Audience KeyVault -Body ($body | ConvertTo-Json -Compress) -What ("Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
|    $j = $r.Content | ConvertFrom-Json
|    return [pscustomobject]@{ VaultName = $VaultName; Name = $Name; Id = [string]$j.id; ContentType = [string]$j.contentType; Enabled = $j.attributes.enabled }
|}
|
|function ConvertTo-SIAzResourceGroupObject {
|    param($Rg)
|    [pscustomobject]@{ ResourceGroupName = [string]$Rg.name; Location = [string]$Rg.location; ResourceId = [string]$Rg.id; ProvisioningState = [string]$Rg.properties.provisioningState; Tags = $Rg.tags }
|}
|
|function Get-SIAzResourceGroupRest {
|    [CmdletBinding()] param([string]$Name)
|    $sub = Get-SIAzRestSubscriptionId
|    if ($Name) {
|        $rg = Invoke-SIArm -Path ("/subscriptions/$sub/resourcegroups/$Name") -ApiVersion '2021-04-01' -AllowNotFound
|        if (-not $rg) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Provided resource group '{0}' does not exist." -f $Name) -Target $Name; return }
|        return (ConvertTo-SIAzResourceGroupObject $rg)
|    }
|    foreach ($rg in @(Invoke-SIArm -Path ("/subscriptions/$sub/resourcegroups") -ApiVersion '2021-04-01' -List)) { ConvertTo-SIAzResourceGroupObject $rg }
|}
|
|function New-SIAzResourceGroupRest {
|    [CmdletBinding()] param([string]$Name, [string]$Location, [hashtable]$Tag)
|    $sub = Get-SIAzRestSubscriptionId
|    $body = @{ location = $Location }
|    if ($Tag) { $body['tags'] = $Tag }
|    $rg = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourcegroups/$Name") -ApiVersion '2021-04-01' -Body $body
|    return (ConvertTo-SIAzResourceGroupObject $rg)
|}
|
|function Get-SIAzRestRoleDefinitions {
|    <# Role definitions visible at -Scope (built-in + custom), cached per scope for the run. #>
|    param([string]$Scope, [switch]$CustomOnly)
|    $st = Get-SIAzRestState
|    $key = 'roledefs|' + $Scope.ToLowerInvariant() + '|' + [string][bool]$CustomOnly
|    if ($st.Cache.ContainsKey($key)) { return $st.Cache[$key] }
|    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleDefinitions'
|    if ($CustomOnly) { $path += '?$filter=' + [uri]::EscapeDataString("type eq 'CustomRole'") }
|    $defs = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
|    $st.Cache[$key] = $defs
|    return $defs
|}
|
|function Get-SIAzRestRoleDefinitionNames {
|    <#
|        The role NAME of every role definition visible at -Scope, by its id (lowercase): @{ <id> = <roleName> }. For the
|        role-assignment read, which needs only the name. Built-in roles are the same at every scope: they are read ONCE per
|        run and kept as names only; a scope's custom roles are read per scope, names only. The full definitions (every
|        permission of ~800 built-in roles) are never kept. customer B 2026-10-15: the identity producer read the role
|        assignments of 1,195 subscriptions and kept the WHOLE definition list of every one of them (Get-SIAzRestRoleDefinitions
|        caches per scope) -- the process ran out of memory in its sixth minute and every read after that failed.
|        -Fetch (tests): { param($Path) } -> the ARM rows of that list.
|    #>
|    param([Parameter(Mandatory)][string]$Scope, [scriptblock]$Fetch)
|    $st = Get-SIAzRestState
|    $read = { param($p) if ($Fetch) { @(& $Fetch $p) } else { @(Invoke-SIArm -Path $p -ApiVersion '2022-04-01' -List) } }
|    $base = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleDefinitions?$filter='
|    $bk = 'roledefnames|builtin'
|    if (-not $st.Cache.ContainsKey($bk)) {
|        $m = @{}
|        foreach ($d in (& $read ($base + [uri]::EscapeDataString("type eq 'BuiltInRole'")))) { if ($d -and $d.name) { $m[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName } }
|        $st.Cache[$bk] = $m
|    }
|    $ck = 'roledefnames|custom|' + $Scope.ToLowerInvariant()
|    if (-not $st.Cache.ContainsKey($ck)) {
|        $m = @{}
|        foreach ($d in (& $read ($base + [uri]::EscapeDataString("type eq 'CustomRole'")))) { if ($d -and $d.name) { $m[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName } }
|        $st.Cache[$ck] = $m
|    }
|    [pscustomobject]@{ BuiltIn = $st.Cache[$bk]; Custom = $st.Cache[$ck] }
|}
|
|function ConvertTo-SIAzRoleDefinitionObject {
|    param($D)
|    $perm = @($D.properties.permissions) | Select-Object -First 1
|    [pscustomobject]@{
|        Name = [string]$D.properties.roleName; Id = [string]$D.name; IsCustom = ([string]$D.properties.type -eq 'CustomRole')
|        Description = [string]$D.properties.description
|        Actions = @($perm.actions); NotActions = @($perm.notActions); DataActions = @($perm.dataActions); NotDataActions = @($perm.notDataActions)
|        AssignableScopes = @($D.properties.assignableScopes)
|    }
|}
|
|function Get-SIAzRoleDefinitionRest {
|    [CmdletBinding()] param([switch]$Custom, [string]$Name, [string]$Scope)
|    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SIAzRestSubscriptionId) }
|    $out = @(Get-SIAzRestRoleDefinitions -Scope $Scope -CustomOnly:$Custom | ForEach-Object { ConvertTo-SIAzRoleDefinitionObject $_ })
|    if ($Name) { $out = @($out | Where-Object { $_.Name -eq $Name }) }
|    return $out
|}
|
|function Resolve-SIAzRestPrincipalNames {
|    <# DisplayName per object id, best effort (Microsoft Graph directoryObjects/getByIds). Empty on any failure: a name
|       is informational, never a reason to fail the read. #>
|    param([string[]]$Ids)
|    $map = @{}
|    $ids = @($Ids | Where-Object { $_ } | Select-Object -Unique)
|    for ($i = 0; $i -lt $ids.Count; $i += 1000) {
|        $chunk = @($ids[$i..([Math]::Min($i + 999, $ids.Count - 1))])
|        try {
|            $r = Invoke-SIAzRestRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -Audience Graph `
|                     -Body (@{ ids = $chunk } | ConvertTo-Json -Compress) -What 'Microsoft Graph getByIds' -MaxAttempts 3
|            foreach ($o in @(($r.Content | ConvertFrom-Json).value)) { if ($o.id) { $map[[string]$o.id] = [string]$o.displayName } }
|        } catch { Write-Verbose ('principal names not resolved: {0}' -f $_.Exception.Message) }
|    }
|    return $map
|}
|
|function Get-SIAzRoleAssignmentRest {
|    [CmdletBinding()] param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName)
|    $explicitScope = [bool]$Scope
|    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SIAzRestSubscriptionId) }
|    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments'
|    if ($ObjectId) { $path += '?$filter=' + [uri]::EscapeDataString(("principalId eq '{0}'" -f $ObjectId)) }
|    elseif ($explicitScope) { $path += '?$filter=' + [uri]::EscapeDataString('atScope()') }
|    $items = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
|    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
|    # names only, built-ins read once per run (Get-SIAzRestRoleDefinitionNames) -- never the whole definition list per scope
|    $defs = Get-SIAzRestRoleDefinitionNames -Scope $subScope
|    $names = Resolve-SIAzRestPrincipalNames -Ids @($items | ForEach-Object { [string]$_.properties.principalId })
|    foreach ($a in $items) {
|        $rdId = ([string]$a.properties.roleDefinitionId -split '/')[-1]
|        $rdKey = $rdId.ToLowerInvariant()
|        $rdName = if ($defs.BuiltIn.ContainsKey($rdKey)) { $defs.BuiltIn[$rdKey] } else { $defs.Custom[$rdKey] }
|        if ($RoleDefinitionName -and $rdName -ne $RoleDefinitionName) { continue }
|        $oid = [string]$a.properties.principalId
|        [pscustomobject]@{
|            RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = [string]$a.properties.scope
|            DisplayName = $(if ($names.ContainsKey($oid)) { $names[$oid] } else { $null }); SignInName = $null
|            RoleDefinitionName = $rdName; RoleDefinitionId = $rdId; ObjectId = $oid; ObjectType = [string]$a.properties.principalType
|            CanDelegate = $false; Condition = $a.properties.condition; Description = [string]$a.properties.description; CreatedOn = $a.properties.createdOn
|        }
|    }
|}
|
|function New-SIAzRoleAssignmentRest {
|    # -Description (optional): stored on the assignment itself -- who gave it and why survives on Azure's side, so a later
|    # run can find an assignment it gave even when its own record of that is gone
|    [CmdletBinding()] param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName, [string]$Description)
|    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
|    $def = @(Get-SIAzRestRoleDefinitions -Scope $subScope | Where-Object { [string]$_.properties.roleName -eq $RoleDefinitionName }) | Select-Object -First 1
|    if (-not $def) { throw ("The role definition '{0}' was not found at scope '{1}'." -f $RoleDefinitionName, $subScope) }
|    $name = [guid]::NewGuid().ToString()
|    $body = @{ properties = @{ roleDefinitionId = [string]$def.id; principalId = $ObjectId } }
|    if ("$Description".Trim()) { $body.properties['description'] = "$Description".Trim() }
|    $a = Invoke-SIArm -Method PUT -Path ($Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments/' + $name) -ApiVersion '2022-04-01' -Body $body
|    return [pscustomobject]@{ RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = $Scope; RoleDefinitionName = $RoleDefinitionName; RoleDefinitionId = [string]$def.name; ObjectId = $ObjectId; ObjectType = [string]$a.properties.principalType }
|}
|
|function Get-SIAzTagRest {
|    [CmdletBinding()] param([string]$ResourceId)
|    $t = Invoke-SIArm -Path ($ResourceId.TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -ApiVersion '2021-04-01'
|    $h = @{}
|    if ($t -and $t.properties -and $t.properties.tags) { foreach ($p in $t.properties.tags.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
|    return [pscustomobject]@{ Id = [string]$t.id; Name = 'default'; Properties = [pscustomobject]@{ TagsProperty = $h } }
|}
|
|function Update-SIAzTagRest {
|    [CmdletBinding()] param([string]$ResourceId, [hashtable]$Tag, [string]$Operation = 'Merge')
|    if (-not $Operation) { $Operation = 'Merge' }
|    $t = Invoke-SIArm -Method PATCH -Path ($ResourceId.TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -ApiVersion '2021-04-01' -Body @{ operation = $Operation; properties = @{ tags = $Tag } }
|    $h = @{}
|    if ($t -and $t.properties -and $t.properties.tags) { foreach ($p in $t.properties.tags.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
|    return [pscustomobject]@{ Id = [string]$t.id; Name = 'default'; Properties = [pscustomobject]@{ TagsProperty = $h } }
|}
|
|function Get-SIAzADServicePrincipalRest {
|    [CmdletBinding()] param([string]$ApplicationId, [string]$ObjectId)
|    $uri = if ($ObjectId) { 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=id,appId,displayName,servicePrincipalNames' -f $ObjectId }
|           else { 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter={0}&$select=id,appId,displayName,servicePrincipalNames' -f [uri]::EscapeDataString(("appId eq '{0}'" -f $ApplicationId)) }
|    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience Graph -AllowNotFound -What 'Microsoft Graph service principal'
|    if (-not $r) { return }
|    $j = $r.Content | ConvertFrom-Json
|    $items = if ($j.PSObject.Properties['value']) { @($j.value) } else { @($j) }
|    foreach ($s in $items) { if ($s) { [pscustomobject]@{ Id = [string]$s.id; AppId = [string]$s.appId; DisplayName = [string]$s.displayName; ServicePrincipalName = @($s.servicePrincipalNames) } } }
|}
|
|function ConvertTo-SIAzDceObject {
|    param($D)
|    [pscustomobject]@{
|        Name = [string]$D.name; Id = [string]$D.id; Location = [string]$D.location
|        LogIngestionEndpoint = [string]$D.properties.logsIngestion.endpoint; ConfigurationAccessEndpoint = [string]$D.properties.configurationAccess.endpoint
|        NetworkAclsPublicNetworkAccess = [string]$D.properties.networkAcls.publicNetworkAccess; ProvisioningState = [string]$D.properties.provisioningState
|    }
|}
|
|function Get-SIAzDataCollectionEndpointRest {
|    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName)
|    $sub = Get-SIAzRestSubscriptionId
|    if ($Name -and $ResourceGroupName) {
|        $d = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$Name") -ApiVersion '2022-06-01' -AllowNotFound
|        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The data collection endpoint '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|        return (ConvertTo-SIAzDceObject $d)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints" } else { "/subscriptions/$sub/providers/Microsoft.Insights/dataCollectionEndpoints" }
|    foreach ($d in @(Invoke-SIArm -Path $path -ApiVersion '2022-06-01' -List)) { if (-not $Name -or [string]$d.name -eq $Name) { ConvertTo-SIAzDceObject $d } }
|}
|
|function New-SIAzDataCollectionEndpointRest {
|    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName, [string]$Location, [string]$NetworkAclsPublicNetworkAccess = 'Enabled')
|    if (-not $NetworkAclsPublicNetworkAccess) { $NetworkAclsPublicNetworkAccess = 'Enabled' }
|    $sub = Get-SIAzRestSubscriptionId
|    $d = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$Name") -ApiVersion '2022-06-01' `
|             -Body @{ location = $Location; properties = @{ networkAcls = @{ publicNetworkAccess = $NetworkAclsPublicNetworkAccess } } }
|    return (ConvertTo-SIAzDceObject $d)
|}
|
|function Get-SIAzDataCollectionRuleRest {
|    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName)
|    $sub = Get-SIAzRestSubscriptionId
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionRules" } else { "/subscriptions/$sub/providers/Microsoft.Insights/dataCollectionRules" }
|    foreach ($d in @(Invoke-SIArm -Path $path -ApiVersion '2022-06-01' -List)) {
|        if ($Name -and [string]$d.name -ne $Name) { continue }
|        [pscustomobject]@{ Name = [string]$d.name; Id = [string]$d.id; Location = [string]$d.location; ImmutableId = [string]$d.properties.immutableId; DataCollectionEndpointId = [string]$d.properties.dataCollectionEndpointId }
|    }
|}
|
|function New-SIAzStorageContextRest {
|    <# The storage "context" the REST path needs: the account name (and its endpoints). Every call
|       signs in with the run's identity (OAuth); there is no account-key form. #>
|    [CmdletBinding()] param([string]$StorageAccountName, [switch]$UseConnectedAccount)
|    return [pscustomobject]@{
|        PSTypeName = 'SI.AzRest.StorageContext'; SIRest = $true; StorageAccountName = $StorageAccountName
|        BlobEndPoint = ('https://{0}.blob.core.windows.net/' -f $StorageAccountName)
|        QueueEndPoint = ('https://{0}.queue.core.windows.net/' -f $StorageAccountName)
|        TableEndPoint = ('https://{0}.table.core.windows.net/' -f $StorageAccountName)
|    }
|}
|
|function Get-SIAzRestStorageAccountName {
|    param($Context)
|    if ($null -eq $Context) { throw 'No storage context was given.' }
|    $n = [string]$Context.StorageAccountName
|    if (-not $n) { throw 'The storage context does not name a storage account.' }
|    return $n
|}
|
|function ConvertTo-SIAzStorageAccountObject {
|    param($S)
|    $rg = if ([string]$S.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
|    [pscustomobject]@{
|        StorageAccountName = [string]$S.name; ResourceGroupName = $rg; Id = [string]$S.id; Location = [string]$S.location
|        Kind = [string]$S.kind; Sku = $S.sku; PrimaryEndpoints = $S.properties.primaryEndpoints; ProvisioningState = [string]$S.properties.provisioningState
|        Context = (New-SIAzStorageContextRest -StorageAccountName ([string]$S.name) -UseConnectedAccount)
|    }
|}
|
|function Get-SIAzStorageAccountRest {
|    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name)
|    $sub = Get-SIAzRestSubscriptionId
|    if ($ResourceGroupName -and $Name) {
|        $s = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Name") -ApiVersion '2023-01-01' -AllowNotFound
|        if (-not $s) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The storage account '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
|        return (ConvertTo-SIAzStorageAccountObject $s)
|    }
|    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts" } else { "/subscriptions/$sub/providers/Microsoft.Storage/storageAccounts" }
|    foreach ($s in @(Invoke-SIArm -Path $path -ApiVersion '2023-01-01' -List)) { if (-not $Name -or [string]$s.name -eq $Name) { ConvertTo-SIAzStorageAccountObject $s } }
|}
|
|function Get-SIStorageAccountCreateProperties {
|    <#
|        PURE. The properties EVERY storage account SecurityInsight creates gets: shared-key access OFF (no account key
|        and no key-signed SAS works -- a user-delegation SAS still does), Entra ID the default in the portal, HTTPS only,
|        TLS 1.2 at least, no public blob access. Every SecurityInsight host reaches its storage with its own identity
|        (Storage Blob / Queue / Table Data roles), so nothing needs a key. An EXISTING account is never changed here;
|        setup\Set-SIStorageSharedKey.ps1 -Disable switches one off after checking nothing still uses a key.
|    #>
|    return @{
|        supportsHttpsTrafficOnly     = $true
|        allowBlobPublicAccess        = $false
|        allowSharedKeyAccess         = $false
|        defaultToOAuthAuthentication = $true
|        minimumTlsVersion            = 'TLS1_2'
|    }
|}
|
|function New-SIAzStorageAccountRest {
|    [CmdletBinding()]
|    param([string]$ResourceGroupName, [string]$Name, [string]$Location, [string]$SkuName, [string]$Kind, [bool]$EnableHttpsTrafficOnly = $true,
|          [string]$MinimumTlsVersion, [bool]$AllowBlobPublicAccess = $false,
|          # #866 (a private install): 'Disabled' CREATES the account with no public access -- only its private endpoints
|          [ValidateSet('', 'Disabled')][string]$PublicNetworkAccess = '')
|    $sub = Get-SIAzRestSubscriptionId
|    # -EnableHttpsTrafficOnly / -MinimumTlsVersion / -AllowBlobPublicAccess keep the Az cmdlet's shape, but a NEW
|    # account is always created locked down (Get-SIStorageAccountCreateProperties): no caller can weaken it.
|    $props = Get-SIStorageAccountCreateProperties
|    if ($PublicNetworkAccess -eq 'Disabled') { $props['publicNetworkAccess'] = 'Disabled' }
|    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Name"
|    $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-01-01' -Body @{ location = $Location; sku = @{ name = $SkuName }; kind = $Kind; properties = $props }
|    # the create is asynchronous: wait until the account is THERE AND PROVISIONED (10 minutes at most) -- what follows
|    # (its roles, its containers) is refused "operation in progress" on an account Azure is still making. A "not found"
|    # in between is "not yet"; an account that is not ready in time is a clear stop, never handed on as if it were.
|    $s = $null; $state = ''
|    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
|    for ($i = 0; $i -lt 120; $i++) {
|        $s = Invoke-SIArm -Path $path -ApiVersion '2023-01-01' -AllowNotFound
|        $state = if ($s -and $s.properties) { [string]$s.properties.provisioningState } else { '' }
|        if ($s -and ($state -eq 'Succeeded' -or -not $state)) { return (ConvertTo-SIAzStorageAccountObject $s) }
|        if ($state -in 'Failed', 'Canceled') { throw ("The storage account '{0}' was not created: Azure reports it {1} -- see the activity log of resource group '{2}' for its reason." -f $Name, $state, $ResourceGroupName) }
|        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
|    }
|    if (-not $s) { throw ("The storage account '{0}' was requested but did not appear." -f $Name) }
|    throw ("The storage account '{0}' is not ready 10 minutes after it was created (Azure shows: {1})." -f $Name, $(if ($state) { $state } else { 'no state' }))
|}
|
|function Get-SIAzStorageContainerRest {
|    [CmdletBinding()] param([string]$Name, [object]$Context)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    $c = Test-SIBlobContainer -Account $acct -Container $Name
|    if (-not $c) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find the container '{0}' (ContainerNotFound)." -f $Name) -Target $Name; return }
|    return $c
|}
|
|function New-SIAzStorageContainerRest {
|    [CmdletBinding()] param([string]$Name, [object]$Context, [string]$Permission)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    return (New-SIBlobContainer -Account $acct -Container $Name)
|}
|
|function ConvertTo-SIAzBlobObject {
|    <# A blob shaped like Get-AzStorageBlob's: Name / Length / LastModified / ETag, and the ICloudBlob members the call
|       sites read (Name, Container.Name, Properties.ETag / LastModified / Length). #>
|    param($B, [string]$Account)
|    $cloud = [pscustomobject]@{
|        Name = $B.Name; SIAccount = $Account
|        Container = [pscustomobject]@{ Name = $B.Container }
|        Properties = [pscustomobject]@{ ETag = $B.ETag; LastModified = $B.LastModified; Length = $B.Length; ContentType = $B.ContentType }
|    }
|    [pscustomobject]@{ Name = $B.Name; Length = $B.Length; LastModified = $B.LastModified; ETag = $B.ETag; ContentType = $B.ContentType; BlobType = 'BlockBlob'; ICloudBlob = $cloud }
|}
|
|function Get-SIAzStorageBlobRest {
|    [CmdletBinding()] param([string]$Container, [string]$Blob, [string]$Prefix, [object]$Context)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    if ($Blob) {
|        $b = Get-SIBlobProperties -Account $acct -Container $Container -Blob $Blob
|        if (-not $b) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find blob '{0}' in container '{1}' (BlobNotFound)." -f $Blob, $Container) -Target $Blob; return }
|        return (ConvertTo-SIAzBlobObject $b $acct)
|    }
|    foreach ($b in @(Get-SIBlobList -Account $acct -Container $Container -Prefix $Prefix)) { ConvertTo-SIAzBlobObject $b $acct }
|}
|
|function Get-SIAzStorageBlobContentRest {
|    [CmdletBinding()] param([string]$Container, [string]$Blob, [object]$CloudBlob, [string]$Destination, [object]$Context, [switch]$Force)
|    if ($CloudBlob) { $Blob = [string]$CloudBlob.Name; $Container = [string]$CloudBlob.Container.Name }
|    $acct = if ($Context) { Get-SIAzRestStorageAccountName -Context $Context } else { [string]$CloudBlob.SIAccount }
|    $target = $Destination
|    if (-not $target) { $target = (Get-Location).Path }
|    if (Test-Path -LiteralPath $target -PathType Container) { $target = [System.IO.Path]::Combine($target, ($Blob -replace '/', [System.IO.Path]::DirectorySeparatorChar)) }
|    $dir = Split-Path -Parent $target
|    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
|    $null = Get-SIBlobContent -Account $acct -Container $Container -Blob $Blob -Destination $target
|    $b = Get-SIBlobProperties -Account $acct -Container $Container -Blob $Blob
|    if ($b) { return (ConvertTo-SIAzBlobObject $b $acct) }
|}
|
|function Set-SIAzStorageBlobContentRest {
|    [CmdletBinding()] param([string]$File, [string]$Container, [string]$Blob, [object]$Context, [switch]$Force)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    if (-not $Blob) { $Blob = Split-Path -Leaf $File }
|    $etag = Set-SIBlobContent -Account $acct -Container $Container -Blob $Blob -File $File
|    $len = (Get-Item -LiteralPath $File).Length
|    return (ConvertTo-SIAzBlobObject ([pscustomobject]@{ Name = $Blob; Container = $Container; Length = $len; LastModified = [DateTimeOffset]::UtcNow; ETag = $etag; ContentType = 'application/octet-stream' }) $acct)
|}
|
|function Remove-SIAzStorageBlobRest {
|    [CmdletBinding()] param([string]$Container, [string]$Blob, [object]$Context, [switch]$Force)
|    Remove-SIBlob -Account (Get-SIAzRestStorageAccountName -Context $Context) -Container $Container -Blob $Blob
|}
|
|function Start-SIAzStorageBlobCopyRest {
|    <# A copy within the account: download and upload (the files SI copies are small exports), so no SAS and no
|       copy-source authorization is needed. #>
|    [CmdletBinding()] param([string]$SrcContainer, [string]$SrcBlob, [string]$DestContainer, [string]$DestBlob, [object]$Context, [switch]$Force)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    $bytes = Get-SIBlobContent -Account $acct -Container $SrcContainer -Blob $SrcBlob
|    $null = Set-SIBlobContent -Account $acct -Container $DestContainer -Blob $DestBlob -Bytes $bytes
|    return [pscustomobject]@{ Name = $DestBlob; Container = $DestContainer }
|}
|
|function New-SIAzQueueObject {
|    <# A queue shaped like Get-AzStorageQueue's: .QueueClient with SendMessage / ReceiveMessage / DeleteMessage, as the
|       worker queue calls them. #>
|    param([string]$Account, [string]$Name)
|    $client = [pscustomobject]@{ Name = $Name; SIAccount = $Account }
|    $client | Add-Member -MemberType ScriptMethod -Name SendMessage -Value { param($Text) Send-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -Text ([string]$Text) }
|    $client | Add-Member -MemberType ScriptMethod -Name ReceiveMessage -Value {
|        param($VisibilityTimeout)
|        $secs = if ($VisibilityTimeout -is [timespan]) { [int]$VisibilityTimeout.TotalSeconds } elseif ($VisibilityTimeout) { [int]$VisibilityTimeout } else { 30 }
|        [pscustomobject]@{ Value = (Receive-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -VisibilityTimeoutSeconds $secs) }
|    }
|    $client | Add-Member -MemberType ScriptMethod -Name DeleteMessage -Value { param($Id, $PopReceipt) Remove-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -MessageId ([string]$Id) -PopReceipt ([string]$PopReceipt) }
|    return [pscustomobject]@{ Name = $Name; QueueClient = $client }
|}
|
|function Get-SIAzStorageQueueRest {
|    [CmdletBinding()] param([string]$Name, [object]$Context)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    if (-not (Test-SIQueue -Account $acct -Queue $Name)) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find queue '{0}' (QueueNotFound)." -f $Name) -Target $Name; return }
|    return (New-SIAzQueueObject -Account $acct -Name $Name)
|}
|
|function New-SIAzStorageQueueRest {
|    [CmdletBinding()] param([string]$Name, [object]$Context)
|    $acct = Get-SIAzRestStorageAccountName -Context $Context
|    New-SIQueue -Account $acct -Queue $Name
|    return (New-SIAzQueueObject -Account $acct -Name $Name)
|}
|
|# #639 lane 4: a read in parts when one answer cannot carry it (Read-SILaParts) -- for every reader of a large result.
|# Loaded LAST: it reads through this file's Invoke-SIAzOperationalInsightsQuery (and loads this file itself when it is
|# dot-sourced alone, guarded on Invoke-SIArm -- defined by now, so never twice).
|if (-not (Get-Command -Name Read-SILaParts -ErrorAction Ignore)) {
|    $__siLaParts = [System.IO.Path]::Combine($PSScriptRoot, 'SI-LaParts.ps1')
|    if ([System.IO.File]::Exists($__siLaParts)) { . $__siLaParts }
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-LaStreamRead.ps1'] = @{ Sha256 = '76262967b7a09e5713b4687cf62f9267864ddcc0f3f11e678958f17226738511'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- A LOG ANALYTICS ANSWER READ AS IT ARRIVES, NEVER HELD WHOLE (Risk Analysis' lookups and answers;
|    owner rule "same method, all sizes; stream always").
|
|    The lean read (#639, SI-AzRest.ps1 ConvertFrom-SILaQueryRows) reads the answer's BYTES into one array of their full
|    length, parses them into a JsonDocument (an index of every token beside them), and only then builds the rows -- so
|    while a lookup is read the process holds the whole answer about three times (bytes + index + rows). A Risk Analysis
|    lookup at a large install is a tenant-sized answer (the identity CI lookup of a 153,000-user tenant: every key of every
|    identity), read in parts of up to the service's own answer limit; the large install's Risk Analysis job ran out of
|    memory on 2 CPU / 4 GiB (#730).
|
|    Here the response stream is read through a small buffer: each ROW is parsed when its bytes are in, turned into the row
|    object at once, and its bytes are let go. Only the rows are held -- the same rows the lean read builds: the same
|    columns in the same order, the same TEXT values (strings as sent, numbers in the service's own spelling, true / false,
|    null stays null, a nested value as its raw JSON text), the table named PrimaryResult else the first, the column list
|    (name / type) and the partial-error object. Compact rows (SI_LaCompactRows, Get-SILaCompactRowType) when the caller
|    asks for them, PSCustomObject rows otherwise.
|
|    pwsh 7 only (System.Text.Json's Utf8JsonReader, compiled once per process with Add-Type). Windows PowerShell, or a
|    process where the reader cannot be compiled: Get-SILaStreamReaderType answers $null and the caller keeps the lean read.
|
|    #836 (found 2026-10-20): NOTHING HERE LIVES ONLY IN THIS FILE'S SCRIPT SCOPE. A function reads $script: of its CALLER's
|    script, and in a container the entry point (container\Start-SIInContainer.ps1) dot-sources SI-AzRest.ps1 -> this file
|    in ITS scope while every engine runs as its own script and skips reloading it -- so a $script: source was $null there,
|    Add-Type failed, the failure was swallowed and no container engine ever streamed. The C# source comes from a FUNCTION
|    (Get-SILaStreamReaderSource), the compiled type is found by its name, and the state a run must share (the reader is off
|    and why, the last read's numbers) is $global:. The older read stays the fallback, but it is never silent: one plain line
|    on the run log says the older read is used and why (Write-SILaStreamFallback).
|#>
|
|function Get-SILaStreamReaderSource {
|    <# The reader's C# source. A FUNCTION, never a $script: variable (#836): callable from any script's scope. #>
|    @'
|using System;
|using System.Collections.Generic;
|using System.IO;
|using System.Management.Automation;
|using System.Reflection;
|using System.Text;
|using System.Text.Json;
|
|namespace SecurityInsight.LaStream
|{
|    public sealed class LaStreamAnswer
|    {
|        public object[] Rows { get; set; }
|        public string[] ColumnNames { get; set; }
|        public string[] ColumnTypes { get; set; }
|        public string ErrorJson { get; set; }
|        public long BytesRead { get; set; }
|        public int LargestBuffer { get; set; }
|        // with a page callback: the rows handed on and in how many pages (Rows is then empty)
|        public long RowsDelivered { get; set; }
|        public int Pages { get; set; }
|    }
|
|    // the caller's own page callback failed -- not a fault of the reader or of the answer
|    public sealed class LaStreamPageException : Exception
|    {
|        public LaStreamPageException(Exception inner) : base("the page callback failed: " + (inner == null ? "" : inner.Message), inner) { }
|    }
|
|    public static class LaStreamReader
|    {
|        // the rows handed on a page at a time: the table being handed on, the answer bytes of the rows waiting, the totals
|        private sealed class PageSink
|        {
|            public Action<object[]> On;
|            public long Limit;
|            public long Bytes;
|            public object Table;
|            public bool FromNonPrimary;
|            public long Rows;
|            public int Pages;
|        }
|
|        private static void Flush(PageSink sink, List<object> rows)
|        {
|            if (sink == null || rows == null || rows.Count == 0) { if (sink != null) sink.Bytes = 0; return; }
|            object[] page = rows.ToArray();
|            rows.Clear();
|            sink.Bytes = 0;
|            try { sink.On(page); }
|            catch (Exception e) { throw new LaStreamPageException(e); }
|            sink.Rows += page.Length;
|            sink.Pages++;
|        }
|
|        public static LaStreamAnswer Read(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor)
|        {
|            return Read(stream, compact, compactCtorFor, bufferSize, plainRowFor, null, 0);
|        }
|
|        // onPage: the primary table's rows are handed on a page at a time (about pageBytes of the answer each) and never
|        // collected; the answer's Rows is then empty, RowsDelivered / Pages say what was handed on
|        public static LaStreamAnswer Read(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor, Action<object[]> onPage, long pageBytes)
|        {
|            PageSink sink = onPage == null ? null : new PageSink { On = onPage, Limit = Math.Max(1024, pageBytes) };
|            return ReadCore(stream, compact, compactCtorFor, bufferSize, plainRowFor, sink);
|        }
|
|        private enum Ctx { Root, Tables, Table, Columns, Rows, Done }
|
|        private sealed class TableAcc
|        {
|            public int Index;
|            public string Name = "";
|            public List<string> Names = new List<string>();
|            public List<string> Types = new List<string>();
|            public bool ColumnsDone;
|            public bool Keep = true;
|            public ConstructorInfo Ctor;
|            public bool CtorAsked;
|            public Dictionary<string, string> Pool;
|            public List<object> Rows = new List<object>();
|            public List<string[]> Early;   // rows met before the column list (kept as values, built at the end)
|            public Func<string[], string[], object> Plain;   // names that differ only in case: the row is built as the lean read builds it
|            public bool PlainChecked;
|        }
|
|        private static LaStreamAnswer ReadCore(Stream stream, bool compact, Func<string[], ConstructorInfo> compactCtorFor, int bufferSize, Func<string[], string[], object> plainRowFor, PageSink sink)
|        {
|            if (stream == null) throw new ArgumentNullException("stream");
|            byte[] buf = new byte[Math.Max(1024, bufferSize)];
|            int filled = 0, start = 0;
|            bool final = false;
|            long total = 0;
|            int largest = buf.Length;
|            JsonReaderState state = new JsonReaderState();
|            var stack = new List<Ctx>();
|            string prop = null;
|            TableAcc cur = null, first = null, primary = null;
|            int tableCount = 0;
|            string errorJson = null;
|            bool bomChecked = false;
|
|            while (true)
|            {
|                // fill: keep what is not consumed, grow only when one unit does not fit
|                if (start > 0) { Buffer.BlockCopy(buf, start, buf, 0, filled - start); filled -= start; start = 0; }
|                if (!final)
|                {
|                    if (filled == buf.Length)
|                    {
|                        var bigger = new byte[buf.Length * 2]; Buffer.BlockCopy(buf, 0, bigger, 0, filled); buf = bigger;
|                        if (buf.Length > largest) largest = buf.Length;
|                    }
|                    int n = stream.Read(buf, filled, buf.Length - filled);
|                    if (n <= 0) final = true; else { filled += n; total += n; }
|                    if (!bomChecked && (filled >= 3 || final))
|                    {
|                        bomChecked = true;
|                        if (filled >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) start = 3;
|                    }
|                    if (!final && filled < buf.Length && n > 0) continue;   // read until the buffer is full or the stream ends
|                }
|
|                var reader = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, start, filled - start), final, state);
|                bool more = false;
|                while (true)
|                {
|                    JsonReaderState before = reader.CurrentState;
|                    long beforeAt = reader.BytesConsumed;
|                    if (!reader.Read()) { more = true; break; }
|                    JsonTokenType tt = reader.TokenType;
|                    Ctx ctx = stack.Count == 0 ? Ctx.Root : stack[stack.Count - 1];
|                    if (stack.Count == 0)
|                    {
|                        if (tt == JsonTokenType.StartObject) { stack.Add(Ctx.Root); continue; }
|                        throw new JsonException("the Log Analytics answer is not a JSON object");
|                    }
|                    if (tt == JsonTokenType.PropertyName) { prop = reader.GetString(); continue; }
|
|                    // a UNIT: a value that is read whole (a row, a column, the error, anything skipped) -- its bytes must all be
|                    // in the buffer; when they are not, everything goes back to before its first token and more is read
|                    bool container = (tt == JsonTokenType.StartObject || tt == JsonTokenType.StartArray);
|                    switch (ctx)
|                    {
|                        case Ctx.Root:
|                            if (tt == JsonTokenType.EndObject) { stack[stack.Count - 1] = Ctx.Done; continue; }
|                            if (prop == "tables" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Tables); prop = null; continue; }
|                            {
|                                int us = start + (int)reader.TokenStartIndex;
|                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                                int ue = start + (int)reader.BytesConsumed;
|                                if (prop == "error")
|                                {
|                                    errorJson = (tt == JsonTokenType.Null) ? null : Encoding.UTF8.GetString(buf, us, ue - us);
|                                }
|                                prop = null;
|                                continue;
|                            }
|                        case Ctx.Tables:
|                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); continue; }
|                            if (tt == JsonTokenType.StartObject)
|                            {
|                                cur = new TableAcc { Index = tableCount++, Plain = plainRowFor };
|                                // a later table's rows are kept only while no PrimaryResult was found before it
|                                cur.Keep = (primary == null);
|                                if (compact) cur.Pool = new Dictionary<string, string>(StringComparer.Ordinal);
|                                stack.Add(Ctx.Table); prop = null; continue;
|                            }
|                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                            continue;
|                        case Ctx.Table:
|                            if (tt == JsonTokenType.EndObject)
|                            {
|                                stack.RemoveAt(stack.Count - 1);
|                                FinishTable(cur, compact, compactCtorFor);
|                                if (sink != null && object.ReferenceEquals(sink.Table, cur)) Flush(sink, cur.Rows);
|                                if (cur.Index == 0) first = cur;
|                                if (primary == null && cur.Name == "PrimaryResult") { primary = cur; if (first != null && first != cur) first.Rows = null; }
|                                else if (cur.Index != 0) cur.Rows = null;
|                                cur = null; prop = null; continue;
|                            }
|                            if (prop == "name" && !container)
|                            {
|                                cur.Name = (tt == JsonTokenType.String) ? (reader.GetString() ?? "") : "";
|                                prop = null; continue;
|                            }
|                            if (prop == "columns" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Columns); prop = null; continue; }
|                            if (prop == "rows" && tt == JsonTokenType.StartArray) { stack.Add(Ctx.Rows); prop = null; continue; }
|                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                            prop = null; continue;
|                        case Ctx.Columns:
|                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); cur.ColumnsDone = true; continue; }
|                            {
|                                int us = start + (int)reader.TokenStartIndex;
|                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                                int ue = start + (int)reader.BytesConsumed;
|                                if (tt == JsonTokenType.StartObject) ReadColumn(buf, us, ue - us, cur);
|                                continue;
|                            }
|                        case Ctx.Rows:
|                            if (tt == JsonTokenType.EndArray) { stack.RemoveAt(stack.Count - 1); continue; }
|                            {
|                                int us = start + (int)reader.TokenStartIndex;
|                                if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                                int ue = start + (int)reader.BytesConsumed;
|                                if (tt == JsonTokenType.StartArray && cur.Keep)
|                                {
|                                    if (sink == null) AddRow(buf, us, ue - us, cur, compact, compactCtorFor);
|                                    else if (SinkTakes(sink, cur))
|                                    {
|                                        AddRow(buf, us, ue - us, cur, compact, compactCtorFor);
|                                        sink.Bytes += (ue - us);
|                                        if (sink.Bytes >= sink.Limit) Flush(sink, cur.Rows);
|                                    }
|                                }
|                                continue;
|                            }
|                        default:
|                            if (container && !reader.TrySkip()) { state = before; start += (int)beforeAt; more = true; goto Refill; }
|                            continue;
|                    }
|                }
|                state = reader.CurrentState;
|                start += (int)reader.BytesConsumed;
|            Refill:
|                if (final)
|                {
|                    if (stack.Count == 0 || stack[0] != Ctx.Done) throw new JsonException("the Log Analytics answer ended before it was complete");
|                    break;
|                }
|                if (!more) continue;
|            }
|
|            TableAcc pick = primary ?? first;
|            var ans = new LaStreamAnswer { ErrorJson = errorJson, BytesRead = total, LargestBuffer = largest };
|            if (sink != null) { ans.RowsDelivered = sink.Rows; ans.Pages = sink.Pages; }
|            if (pick != null)
|            {
|                ans.Rows = (pick.Rows == null || sink != null) ? new object[0] : pick.Rows.ToArray();
|                ans.ColumnNames = pick.Names.ToArray();
|                ans.ColumnTypes = pick.Types.ToArray();
|            }
|            else { ans.Rows = new object[0]; ans.ColumnNames = new string[0]; ans.ColumnTypes = new string[0]; }
|            return ans;
|        }
|
|        // with a page callback: does this table's row go to the pages? The table named PrimaryResult, else the first table --
|        // as the whole read picks it. A PrimaryResult that comes after another table's rows were handed on cannot be read in
|        // pages (those rows are gone): the read fails, never a wrong set handed on.
|        private static bool SinkTakes(PageSink sink, TableAcc cur)
|        {
|            if (object.ReferenceEquals(sink.Table, cur)) return true;
|            if (sink.Table == null)
|            {
|                if (cur.Name == "PrimaryResult" || cur.Index == 0) { sink.Table = cur; sink.FromNonPrimary = (cur.Name != "PrimaryResult"); return true; }
|                return false;
|            }
|            if (cur.Name == "PrimaryResult" && sink.FromNonPrimary)
|            {
|                if (sink.Rows > 0) throw new InvalidOperationException("the Log Analytics answer names its primary table after another table whose rows were already handed on -- it cannot be read in pages");
|                ((TableAcc)sink.Table).Rows.Clear();
|                sink.Table = cur; sink.FromNonPrimary = false; sink.Bytes = 0;
|                return true;
|            }
|            return false;
|        }
|
|        private static void ReadColumn(byte[] buf, int off, int len, TableAcc t)
|        {
|            var r = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, off, len), true, new JsonReaderState());
|            r.Read();   // StartObject
|            string name = null, type = null; bool hasName = false;
|            while (r.Read())
|            {
|                if (r.TokenType == JsonTokenType.EndObject && r.CurrentDepth == 0) break;
|                if (r.TokenType != JsonTokenType.PropertyName) continue;
|                string p = r.GetString();
|                r.Read();
|                if (r.TokenType == JsonTokenType.StartObject || r.TokenType == JsonTokenType.StartArray) { r.Skip(); continue; }
|                if (p == "name") { name = (r.TokenType == JsonTokenType.String || r.TokenType == JsonTokenType.Null) ? r.GetString() : Encoding.UTF8.GetString(r.ValueSpan.ToArray()); hasName = true; }
|                else if (p == "type") { type = (r.TokenType == JsonTokenType.String || r.TokenType == JsonTokenType.Null) ? r.GetString() : Encoding.UTF8.GetString(r.ValueSpan.ToArray()); }
|            }
|            if (!hasName) throw new KeyNotFoundException("a column of the Log Analytics answer has no name");
|            t.Names.Add(name); t.Types.Add(type);
|        }
|
|        private static string[] ReadCells(byte[] buf, int off, int len, int nCols, Dictionary<string, string> pool)
|        {
|            var r = new Utf8JsonReader(new ReadOnlySpan<byte>(buf, off, len), true, new JsonReaderState());
|            r.Read();   // StartArray
|            var cells = nCols >= 0 ? new string[nCols] : null;
|            var open = nCols < 0 ? new List<string>() : null;
|            int i = 0;
|            while (r.Read())
|            {
|                if (r.TokenType == JsonTokenType.EndArray && r.CurrentDepth == 0) break;
|                string s;
|                switch (r.TokenType)
|                {
|                    case JsonTokenType.String: s = r.GetString(); break;
|                    case JsonTokenType.Null: s = null; break;
|                    case JsonTokenType.True: s = "true"; break;
|                    case JsonTokenType.False: s = "false"; break;
|                    case JsonTokenType.StartObject:
|                    case JsonTokenType.StartArray:
|                        {
|                            int ts = (int)r.TokenStartIndex;
|                            r.Skip();
|                            s = Encoding.UTF8.GetString(buf, off + ts, (int)r.BytesConsumed - ts);
|                            break;
|                        }
|                    default: s = Encoding.UTF8.GetString(r.ValueSpan.ToArray()); break;
|                }
|                if (s != null && pool != null && s.Length <= 32)
|                {
|                    string p0;
|                    if (pool.TryGetValue(s, out p0)) s = p0; else pool[s] = s;
|                }
|                if (open != null) open.Add(s);
|                else if (i < nCols) cells[i] = s;
|                i++;
|            }
|            return open != null ? open.ToArray() : cells;
|        }
|
|        private static object MakeRow(string[] cells, TableAcc t)
|        {
|            if (t.Ctor != null) return t.Ctor.Invoke(new object[] { cells });
|            if (!t.PlainChecked)
|            {
|                t.PlainChecked = true;
|                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase); bool dup = false;
|                foreach (var nm in t.Names) { if (nm != null && !seen.Add(nm)) { dup = true; break; } }
|                if (!dup) t.Plain = null;
|            }
|            if (t.Plain != null) return t.Plain(t.Names.ToArray(), cells);
|            var o = new PSObject();
|            int n = t.Names.Count;
|            for (int i = 0; i < n; i++)
|            {
|                string v = i < cells.Length ? cells[i] : null;
|                var existing = o.Properties[t.Names[i]];
|                if (existing != null) existing.Value = v; else o.Properties.Add(new PSNoteProperty(t.Names[i], v));
|            }
|            return o;
|        }
|
|        private static void AddRow(byte[] buf, int off, int len, TableAcc t, bool compact, Func<string[], ConstructorInfo> compactCtorFor)
|        {
|            if (!t.ColumnsDone && t.Names.Count == 0)
|            {
|                if (t.Early == null) t.Early = new List<string[]>();
|                t.Early.Add(ReadCells(buf, off, len, -1, null));
|                return;
|            }
|            if (compact && !t.CtorAsked) { MakeRowPrepare(t, compactCtorFor); }
|            var cells = ReadCells(buf, off, len, t.Names.Count, t.Ctor != null ? t.Pool : null);
|            t.Rows.Add(MakeRow(cells, t));
|        }
|
|        private static void MakeRowPrepare(TableAcc t, Func<string[], ConstructorInfo> compactCtorFor)
|        {
|            // the compact type for these columns, asked once; none -> PSCustomObject rows without pooling, as the lean read
|            t.CtorAsked = true;
|            if (compactCtorFor != null) t.Ctor = compactCtorFor(t.Names.ToArray());
|            if (t.Ctor == null) t.Pool = null;
|        }
|
|        private static void FinishTable(TableAcc t, bool compact, Func<string[], ConstructorInfo> compactCtorFor)
|        {
|            if (t.Early == null) return;
|            if (!t.Keep) { t.Early = null; return; }
|            var built = new List<object>(t.Early.Count + t.Rows.Count);
|            if (compact && !t.CtorAsked) MakeRowPrepare(t, compactCtorFor);
|            int n = t.Names.Count;
|            foreach (var raw in t.Early)
|            {
|                var cells = new string[n];
|                for (int i = 0; i < n && i < raw.Length; i++) cells[i] = raw[i];
|                built.Add(MakeRow(cells, t));
|            }
|            built.AddRange(t.Rows);
|            t.Rows = built; t.Early = null;
|        }
|    }
|}
|'@
|}
|
|function Get-SILaStreamReaderType {
|    <# The compiled reader ([SecurityInsight.LaStream.LaStreamReader]), built once per process; $null where it cannot be
|       (Windows PowerShell, or a compile that fails -- the caller then keeps the lean read). Scope-independent (#836): the
|       compiled type is found by its NAME (a type is per process), the source comes from a function, and a compile that
|       failed is remembered for the whole process in $global:SI_LaStreamReaderOff (its reason) -- tried once, not per read. #>
|    if ($PSVersionTable.PSEdition -ne 'Core') { return $null }
|    # off for this process (it could not be built, or it failed on an answer -- Read-SILaQueryStreamSafe): the older read
|    if ($global:SI_LaStreamReaderOff) { return $null }
|    $t = 'SecurityInsight.LaStream.LaStreamReader' -as [type]
|    if ($null -ne $t) { return $t }
|    try {
|        $src = Get-SILaStreamReaderSource
|        if ([string]::IsNullOrWhiteSpace([string]$src)) { throw 'its source is empty' }
|        Add-Type -TypeDefinition $src -Language CSharp -ErrorAction Stop
|        $t = 'SecurityInsight.LaStream.LaStreamReader' -as [type]
|        if ($null -eq $t) { throw 'the compiled type was not found' }
|        return $t
|    } catch {
|        $global:SI_LaStreamReaderOff = 'the reader could not be built in this process: ' + (Get-SILaStreamShortReason $_.Exception.Message)
|        return $null
|    }
|}
|
|function Get-SILaStreamShortReason {
|    <# PURE. The first line of an error text, at most 300 characters (a compiler error lists every line it refused). #>
|    param([AllowNull()][AllowEmptyString()][string]$Text)
|    $s = ([string]$Text -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1)
|    if (-not $s) { return 'no reason given' }
|    $s = $s.Trim()
|    if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + ' ...' }
|    return $s
|}
|
|function Write-SILaStreamFallback {
|    <#
|        #836: the older read is used instead of the streaming one -- ONE plain line on the run log (the transcript) saying
|        so and why. -Once: said once per process for that reason (the reader cannot be built: every later read is the
|        older one too, and saying it per read would flood the log). Without -Once (one read whose stream failed and was
|        read again the older way) it is said every time it happens. The results are the same either way.
|    #>
|    param([AllowNull()][AllowEmptyString()][string]$Reason, [switch]$Once)
|    if ([string]::IsNullOrWhiteSpace($Reason)) { $Reason = 'the streaming reader is not available in this process' }
|    if ($Once) {
|        if ($null -eq $global:SI_LaStreamFallbackSaid) { $global:SI_LaStreamFallbackSaid = @{} }
|        if ($global:SI_LaStreamFallbackSaid.ContainsKey($Reason)) { return }
|        $global:SI_LaStreamFallbackSaid[$Reason] = $true
|    }
|    Write-Host ('Log Analytics answers are read the older way (whole, then parsed) instead of as they arrive -- {0}. The rows are the same; the read uses more memory.' -f $Reason) -ForegroundColor DarkYellow
|}
|
|function Read-SILaQueryStreamSafe {
|    <#
|        #836: ConvertFrom-SILaQueryStream for Invoke-SILaQuery's -ReadStream -- DATA FIRST: a read that fails (the reader
|        throws, the answer is not valid JSON, the connection drops mid-answer) is NOT an error of the query: it answers a
|        marker (.SILaStreamFailed = why) and Invoke-SILaQuery reads the same query again the older way and says so in one
|        line. A failure that is not the network's (IOException / a socket error) turns streaming off for the rest of the
|        process ($global:SI_LaStreamReaderOff) so a reader fault never doubles every read.
|    #>
|    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [switch]$Compact,
|          # the rows a page at a time (ConvertFrom-SILaQueryStream -OnPage); -PageState counts the pages handed on so far
|          [scriptblock]$OnPage, [long]$PageBytes = 4MB, [hashtable]$PageState)
|    try {
|        if ($OnPage) { return (ConvertFrom-SILaQueryStream -Stream $Stream -Compact:$Compact -OnPage $OnPage -PageBytes $PageBytes -PageState $PageState) }
|        return (ConvertFrom-SILaQueryStream -Stream $Stream -Compact:$Compact)
|    }
|    catch {
|        $ex = $_.Exception
|        # the CALLER's page callback failed (a page could not be stored): its own failure, passed on as it is -- never a
|        # reader fault, never read again
|        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
|            if ($e.GetType().FullName -eq 'SecurityInsight.LaStream.LaStreamPageException') {
|                $cause = $e.InnerException
|                while ($cause -is [System.Management.Automation.MethodInvocationException] -and $null -ne $cause.InnerException) { $cause = $cause.InnerException }
|                if ($cause -is [System.Management.Automation.RuntimeException] -and $cause.ErrorRecord) { throw $cause.ErrorRecord }
|                if ($null -ne $cause) { throw $cause }
|                throw $e
|            }
|        }
|        $net = $false
|        for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
|            if ($e -is [System.IO.IOException] -or $e -is [System.Net.WebException] -or $e -is [System.Net.Sockets.SocketException]) { $net = $true; break }
|        }
|        $inner = $ex; while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
|        $why = Get-SILaStreamShortReason $inner.Message
|        if (-not $net) { $global:SI_LaStreamReaderOff = 'the streaming reader failed on an answer: ' + $why }
|        return [pscustomobject]@{ SILaStreamFailed = $why; Network = $net }
|    }
|}
|
|function ConvertFrom-SILaQueryStream {
|    <#
|        The Log Analytics query response READ FROM ITS STREAM -> @{ Rows; Columns; Error } -- the shape and the rows of
|        ConvertFrom-SILaQueryRows (SI-AzRest.ps1), without the answer ever being held whole. -Compact: compact rows
|        (Get-SILaCompactRowType) where a compact type can be built for the columns; PSCustomObject rows otherwise.
|        -BufferBytes: the first buffer (it grows only when one row does not fit). Throws on an answer that is not valid
|        JSON or ends early (as the lean read does).
|        -OnPage { param($Rows) }: FOR EVERY READER, not only Risk Analysis -- the primary table's rows are handed on a page
|        at a time, as soon as about -PageBytes of the answer's own bytes are in, and are never collected: memory is one
|        page. .Rows is then empty; .RowCount / .Pages say what was handed on; -PageState (a hashtable) is kept up to date
|        as pages go out (Pages, Rows). The error object (a cut answer) comes at the END of the answer, after the pages: a
|        caller keeps its pages only once the whole read returned (Invoke-SILaQuery -OnPage refuses a cut answer there).
|    #>
|    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [switch]$Compact, [int]$BufferBytes = 65536,
|          [scriptblock]$OnPage, [long]$PageBytes = 4MB, [hashtable]$PageState)
|    $t = Get-SILaStreamReaderType
|    if ($null -eq $t) { throw 'the streaming Log Analytics reader is not available in this process' }
|    $ctorFor = $null
|    if ($Compact) {
|        $ctorFor = [Func[string[], System.Reflection.ConstructorInfo]] {
|            param([string[]]$names)
|            $ct = $null
|            if (Get-Command -Name Get-SILaCompactRowType -ErrorAction SilentlyContinue) { $ct = Get-SILaCompactRowType -Names $names }
|            if ($null -eq $ct) { return $null }
|            return $ct.GetConstructor([type[]]@([string[]]))
|        }
|    }
|    # column names that differ only in case (never in a real answer): the row is built exactly as the lean read builds it
|    # [[string[]]] -- the spelling Windows PowerShell 5.1 can parse too: setup scripts a customer runs there load this file
|    # through SI-AzRest.ps1 (the same type as [Func[string[], string[], object]], which 5.1 refuses as a parse error)
|    $plainFor = [Func[[string[]], [string[]], object]] {
|        param([string[]]$names, [string[]]$cells)
|        $o = [ordered]@{}
|        for ($i = 0; $i -lt $names.Length; $i++) { $o[$names[$i]] = $(if ($i -lt $cells.Length) { $cells[$i] } else { $null }) }
|        [pscustomobject]$o
|    }
|    if ($OnPage) {
|        if ($null -eq $PageState) { $PageState = @{} }
|        $PageState['Pages'] = 0; $PageState['Rows'] = 0L
|        $__psOn = $OnPage; $__psState = $PageState
|        $pageAction = [Action[object[]]] {
|            param([object[]]$page)
|            $null = & $__psOn $page
|            $__psState['Pages'] = [int]$__psState['Pages'] + 1
|            $__psState['Rows'] = [long]$__psState['Rows'] + $page.Length
|        }
|        $a = $t::Read($Stream, [bool]$Compact, $ctorFor, $BufferBytes, $plainFor, $pageAction, [long]$PageBytes)
|    } else {
|        $a = $t::Read($Stream, [bool]$Compact, $ctorFor, $BufferBytes, $plainFor)
|    }
|    $cols = [System.Collections.Generic.List[object]]::new()
|    for ($i = 0; $i -lt $a.ColumnNames.Length; $i++) { $cols.Add([pscustomobject]@{ name = $a.ColumnNames[$i]; type = $a.ColumnTypes[$i] }) }
|    $err = $null
|    if ($null -ne $a.ErrorJson) { $err = ($a.ErrorJson | ConvertFrom-Json) }
|    $count = [long]$a.Rows.Length; if ($OnPage) { $count = [long]$a.RowsDelivered }
|    # (#836: $global:, never $script: -- a function's $script: is its caller's)
|    $global:SI_LaStreamLast = [pscustomobject]@{ BytesRead = $a.BytesRead; LargestBuffer = $a.LargestBuffer; Rows = $count; Pages = [int]$a.Pages }
|    return [pscustomobject]@{ Rows = $a.Rows; Columns = $cols.ToArray(); Error = $err; RowCount = $count; Pages = [int]$a.Pages }
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-LaParts.ps1'] = @{ Sha256 = 'd6068eb409f171257cf45624fee0eea678cadb739bc63f8b366afc3f9b7b1edd'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- a Log Analytics read IN PARTS, so a large install never meets the service's limit on one answer
|    (#639 lane 4, owner 2026-10-21: "memory issues must not be a problem in any step. env must work in millions of assets
|    env"). Loaded by SI-AzRest.ps1, and guarded by every caller, so it loads on its own (tests).
|
|    WHY. One Log Analytics answer carries at most ~500,000 rows / ~64 MB. Invoke-SILaQuery REFUSES an answer the service
|    cut (New-SILaCutAnswerError) -- a cut answer is never taken as whole. A reader whose result can outgrow one answer
|    (a profile snapshot, the correlation map, a customer's rule query) therefore reads in PARTS:
|
|      * The query is first asked AS IT IS -- a small result costs exactly what it cost before (one query, unchanged).
|      * Refused as cut (or too large, or this process ran out of memory on it): the query is MEASURED once (rows and
|        bytes of its result) and read again in that many parts: each part is the query's own result, filtered on a hash
|        of each result row (or of a key the caller names). The parts never overlap and together are every row --
|        whatever the query does, because the filter is applied to its RESULT.
|      * A part still refused is cut in two (only that part; on a hash of its own, so the pieces never overlap); a part
|        far larger than planned cuts every part still to read by the measured factor. The size of a part follows what
|        was measured, never a fixed number (working rule 5).
|      * MEASURED stop, never a cap: a refused part that held NO row at all, twice in a row, is the query's own work
|        hitting a limit (every part repeats it) -- more parts cannot help, and the read fails saying so.
|      * A part that fails for any other reason fails THE READ: what was read is not the whole, so it is UNKNOWN -- never
|        handed out as the result (working rule 4). The caller's own handling of a failed read applies unchanged.
|
|    A query whose rows differ between two runs of it (take / limit / sample) is never cut into parts: its refusal is passed
|    on as it is. The rows of a read in parts come in no particular order.
|
|    PowerShell 5.1-safe: no ternary, no null-conditional. NO Set-StrictMode here (it leaks into the caller's scope).
|    A caller's -Read / -OnRows / -Log block runs INSIDE Read-SILaParts: a variable it reads must not share a name with
|    this function's own (Query, WorkspaceId, Wait, Key, Read, OnRows, What, Log, rows, got, page, queue ...).
|#>
|
|# Azure access: plain REST, no PowerShell modules (SI-AzRest.ps1 loads this file last, so this never loads it twice).
|if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }
|
|function Get-SILaPartFilter {
|    <#
|        PURE. The KQL that keeps ONE part of a query's result: -Cuts = @( @{ Parts; Part } ...) -- the first cut is the
|        planned part ("bucket Part of Parts" of the row's hash); each later cut divides that part again on a hash of its own
|        (the depth in front of the value), so the pieces of a part never overlap and together are that part. -Key: a KQL
|        expression on the result's columns to hash (e.g. 'SI_AssetId'); '' = the whole result row (pack_all()). '' = no cut.
|    #>
|    param([AllowNull()][AllowEmptyCollection()][object[]]$Cuts = @(), [string]$Key = '')
|    $terms = New-Object System.Collections.Generic.List[string]
|    for ($d = 0; $d -lt @($Cuts).Count; $d++) {
|        $parts = [long]$Cuts[$d].Parts; $part = [long]$Cuts[$d].Part
|        if ($parts -lt 1 -or $part -lt 0 -or $part -ge $parts) { throw ('Get-SILaPartFilter: part {0} is outside 0..{1}' -f $part, ($parts - 1)) }
|        if ($parts -eq 1) { continue }
|        if ($d -eq 0) { $terms.Add(('hash(_siPart, {0}) == {1}' -f $parts, $part)) }
|        else { $terms.Add(('hash(strcat("{0}|", _siPart), {1}) == {2}' -f $d, $parts, $part)) }
|    }
|    if ($terms.Count -eq 0) { return '' }
|    $k = 'tostring(pack_all())'
|    if ($Key) { $k = 'tostring({0})' -f $Key }
|    ('| extend _siPart = {0} | where {1} | project-away _siPart' -f $k, ($terms -join ' and '))
|}
|
|function Get-SILaPartQuery {
|    <#
|        PURE. -Query with -Filter after its LAST tabular statement: trailing blank / comment lines and semicolons are taken
|        off first, so the filter follows the result. '' -Filter = the query unchanged.
|    #>
|    param([Parameter(Mandatory)][string]$Query, [AllowEmptyString()][string]$Filter = '')
|    if (-not $Filter) { return $Query }
|    $lines = New-Object System.Collections.Generic.List[string]
|    foreach ($l in ($Query -split "`r?`n")) { $lines.Add($l) }
|    while ($lines.Count -gt 0) {
|        $t = $lines[$lines.Count - 1].Trim()
|        if ($t -eq '' -or $t.StartsWith('//')) { $lines.RemoveAt($lines.Count - 1); continue }
|        if ($t.EndsWith(';')) { $lines[$lines.Count - 1] = $lines[$lines.Count - 1].TrimEnd().TrimEnd(';'); continue }
|        break
|    }
|    (($lines -join "`n") + "`n" + $Filter)
|}
|
|function Get-SILaMeasureQuery {
|    <# PURE. How many rows -Query's result holds and about how many bytes (one small answer: SIRows, SIBytes). #>
|    param([Parameter(Mandatory)][string]$Query)
|    Get-SILaPartQuery -Query $Query -Filter '| summarize SIRows = count(), SIBytes = sum(estimate_data_size(*))'
|}
|
|function Test-SILaQueryPartable {
|    <# PURE. May -Query be read in parts? Not when its rows differ between two runs of it (take / limit / sample): the parts
|       of two runs would not be one result. #>
|    param([AllowEmptyString()][string]$Query)
|    -not ([string]$Query -match '(?im)\|\s*(take|limit|sample|sample-distinct)\b')
|}
|
|function Get-SILaPartFailure {
|    <#
|        PURE. What a failed read of one part says: @{ Cut = $true when a SMALLER part fixes it -- an answer the service cut
|        for a limit (Invoke-SILaQuery's refusal, Risk Analysis' own), an answer refused as too large, or this process out of
|        memory on it; Rows = the rows the short answer held (-1 unknown) }. Anything else: Cut = $false (passed on as it is).
|    #>
|    param([AllowNull()][object]$Err)
|    $ex = $null; $texts = New-Object System.Collections.Generic.List[string]
|    if ($Err -is [System.Management.Automation.ErrorRecord]) {
|        $ex = $Err.Exception
|        if ($Err.ErrorDetails -and $Err.ErrorDetails.Message) { $texts.Add([string]$Err.ErrorDetails.Message) }
|    } elseif ($Err -is [System.Exception]) { $ex = $Err }
|    elseif ($null -ne $Err) { $texts.Add([string]$Err) }
|    $e = $ex
|    while ($null -ne $e) {
|        if ($e -is [System.OutOfMemoryException] -or $e -is [System.InsufficientExecutionStackException]) { return @{ Cut = $true; Rows = -1L; Why = 'too large for this job''s memory' } }
|        if ($e.Data) {
|            foreach ($k in 'SILaPartial', 'SIRALaPartial') {
|                if ($e.Data.Contains($k)) {
|                    $rows = -1L
|                    if ($e.Data.Contains('SIRALaPartialRows')) { try { $rows = [long]$e.Data['SIRALaPartialRows'] } catch { $rows = -1L } }
|                    return @{ Cut = ([string]$e.Data[$k] -eq 'Limit'); Rows = $rows; Why = 'cut by the service''s limit' }
|                }
|            }
|        }
|        $texts.Add([string]$e.Message)
|        try { if ($e.PSObject.Properties['Response'] -and $e.Response -and $e.Response.PSObject.Properties['Content']) { $texts.Add([string]$e.Response.Content) } } catch { }
|        $e = $e.InnerException
|    }
|    $all = ($texts -join ' ')
|    if ($all -match '(?i)E_QUERY_RESULT_SET_TOO_LARGE|ResponsePayloadTooLarge|ResponseSizeError|result set (is )?too large|exceeds? the (maximum )?(response|result) size|response size .*exceed') {
|        return @{ Cut = $true; Rows = -1L; Why = 'too large to read in one answer' }
|    }
|    @{ Cut = $false; Rows = -1L; Why = '' }
|}
|
|function ConvertTo-SILaPartRows {
|    <# PURE. Rows however a reader handed them over -- one array (`, @(rows)`), an array holding that array, or rows on the
|       pipeline -- as ONE flat object[] without nulls. #>
|    param([AllowNull()][object]$Answer)
|    $l = New-Object System.Collections.Generic.List[object]
|    foreach ($x in @($Answer)) {
|        if ($null -eq $x) { continue }
|        if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y) { $l.Add($y) } } } else { $l.Add($x) }
|    }
|    , $l.ToArray()
|}
|
|function Get-SILaPartPlan {
|    <#
|        PURE. How many parts a result of -Rows rows / about -Bytes bytes is read in: each part well under one answer's
|        limits -- at most half the service's own row limit, and -TargetBytes of answer (the JSON answer is -Expansion times
|        the data's own size). At least 2 (the result was refused whole). Follows the measurement; no ceiling.
|    #>
|    param([long]$Rows = -1, [double]$Bytes = -1, [long]$TargetRows = 0, [double]$TargetBytes = 16MB, [double]$Expansion = 2.5)
|    if ($TargetRows -le 0) {
|        $limit = 500000L
|        if (Get-Command -Name Get-SILaServiceRowLimit -ErrorAction SilentlyContinue) { $limit = [long](Get-SILaServiceRowLimit) }
|        $TargetRows = [long][Math]::Max(1, [Math]::Floor($limit / 2))
|    }
|    $n = 2L
|    if ($Rows -gt 0) { $n = [long][Math]::Max($n, [Math]::Ceiling([double]$Rows / [double]$TargetRows)) }
|    if ($Bytes -gt 0 -and $TargetBytes -gt 0) { $n = [long][Math]::Max($n, [Math]::Ceiling(($Bytes * $Expansion) / $TargetBytes)) }
|    $n
|}
|
|function Read-SILaParts {
|    <#
|        ONE Log Analytics read, in parts when one answer cannot carry it (see the header of this file). Every row once.
|          -Query      the KQL (asked as it is first)
|          -Key        a KQL expression on the result's columns that the parts hash on ('' = the whole result row). A key
|                      that is the same for many rows cannot divide them -- '' always can.
|          -Read       { param($Kql) rows } -- the reader (the seam for tests). Default: Invoke-SIAzOperationalInsightsQuery
|                      on -WorkspaceId (with -Wait), its .Results.
|          -OnRows     { param($Rows) } -- each part's rows as soon as that part is read whole (then not collected; memory is
|                      one part). The parts handed on are only the result when this call RETURNS: a later part that fails
|                      throws, and the caller treats the whole read as failed. Without -OnRows the rows are collected.
|          -What       what is read, for the lines it says; -Log { param($Level, $Message) }
|        Returns @{ Rows (without -OnRows); RowCount; Pages; Parts (planned); Cuts }. Throws when the read is not whole.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$Query,
|        [string]$WorkspaceId = '',
|        [int]$Wait = 0,
|        [string]$Key = '',
|        [scriptblock]$Read,
|        [scriptblock]$OnRows,
|        [string]$What = 'the Log Analytics read',
|        [scriptblock]$Log,
|        [long]$TargetRows = 0,
|        [double]$TargetBytes = 16MB,
|        [int]$MaxDepth = 24
|    )
|    if (-not $Read) {
|        if (-not $WorkspaceId) { throw 'Read-SILaParts: -WorkspaceId or -Read is needed' }
|        # (-Wait only when given: the same call the readers made before, so a reader's own stand-in still answers it)
|        $Read = {
|            param($k)
|            $__p = @{ WorkspaceId = $WorkspaceId; Query = $k; ErrorAction = 'Stop' }
|            if ($Wait -gt 0) { $__p['Wait'] = $Wait }
|            $__a = Invoke-SIAzOperationalInsightsQuery @__p
|            if ($__a) { , @($__a.Results) } else { , @() }
|        }
|    }
|    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
|    if ($TargetRows -le 0) {
|        $limit = 500000L
|        if (Get-Command -Name Get-SILaServiceRowLimit -ErrorAction SilentlyContinue) { $limit = [long](Get-SILaServiceRowLimit) }
|        $TargetRows = [long][Math]::Max(1, [Math]::Floor($limit / 2))
|    }
|    $partable = Test-SILaQueryPartable -Query $Query
|    $acc = $null
|    if (-not $OnRows) { $acc = New-Object System.Collections.Generic.List[object] }
|    $queue = New-Object 'System.Collections.Generic.Queue[object]'
|    $queue.Enqueue([pscustomobject]@{ Cuts = @() })
|    $pages = 0L; $rowsRead = 0L; $cutsMade = 0L; $planned = 1L; $measured = $false; $emptyRefusals = 0
|    while ($queue.Count -gt 0) {
|        $page = $queue.Dequeue()
|        $kql = Get-SILaPartQuery -Query $Query -Filter (Get-SILaPartFilter -Cuts @($page.Cuts) -Key $Key)
|        $rows = $null; $fail = $null
|        try {
|            # assigned first: the reader answers ONE array (`, @(rows)`) -- @() around the call would hold it as one row
|            $got = & $Read $kql
|            $rows = ConvertTo-SILaPartRows $got
|            $got = $null
|        } catch {
|            $f = Get-SILaPartFailure -Err $_
|            if (-not $f.Cut -or -not $partable) { throw }
|            $fail = $f; $failErr = $_
|        }
|        if ($fail) {
|            $rows = $null
|            if (@($page.Cuts).Count -ge $MaxDepth) {
|                throw ('{0} is more than Log Analytics can answer: a part cut {1} times is still {2} -- the read is not whole and nothing of it is used' -f $What, @($page.Cuts).Count, $fail.Why)
|            }
|            if ([long]$fail.Rows -eq 0) { $emptyRefusals++ } else { $emptyRefusals = 0 }
|            if ($emptyRefusals -ge 2) {
|                throw ('{0} is more than Log Analytics can answer: a part stopped at the service''s limit before it returned a row, twice, so reading it in more parts cannot make it fit -- the read is not whole and nothing of it is used ({1})' -f $What, (([string]$failErr.Exception.Message -split "`n") | Select-Object -First 1))
|            }
|            if (@($page.Cuts).Count -eq 0 -and -not $measured) {
|                # the whole query was refused: measured ONCE, then read in that many parts
|                $measured = $true
|                $mRows = -1L; $mBytes = -1.0
|                try {
|                    $mr = ConvertTo-SILaPartRows (& $Read (Get-SILaMeasureQuery -Query $Query)); $m = $null; if ($mr.Count -gt 0) { $m = $mr[0] }
|                    if ($m) {
|                        if ($m.PSObject.Properties['SIRows'] -and "$($m.SIRows)" -ne '') { $mRows = [long][double]::Parse([string]$m.SIRows, [Globalization.CultureInfo]::InvariantCulture) }
|                        if ($m.PSObject.Properties['SIBytes'] -and "$($m.SIBytes)" -ne '') { $mBytes = [double]::Parse([string]$m.SIBytes, [Globalization.CultureInfo]::InvariantCulture) }
|                    }
|                } catch { $mRows = -1L; $mBytes = -1.0 }
|                $planned = Get-SILaPartPlan -Rows $mRows -Bytes $mBytes -TargetRows $TargetRows -TargetBytes $TargetBytes
|                for ($p = 0L; $p -lt $planned; $p++) { $queue.Enqueue([pscustomobject]@{ Cuts = @([pscustomobject]@{ Parts = $planned; Part = $p }) }) }
|                $cutsMade++
|                $sizeText = ''
|                if ($mRows -ge 0) { $sizeText = [string]::Format([Globalization.CultureInfo]::InvariantCulture, ' (measured: {0:N0} row(s){1})', $mRows, $(if ($mBytes -ge 0) { [string]::Format([Globalization.CultureInfo]::InvariantCulture, ', about {0:N0} MB', ($mBytes / 1MB)) } else { '' })) }
|                & $Log 'INFO' ('{0} is larger than one Log Analytics answer can carry ({1}) -- it is read in {2} parts{3}; nothing of the short answer is kept' -f $What, $fail.Why, $planned, $sizeText)
|            } else {
|                foreach ($half in 0, 1) { $queue.Enqueue([pscustomobject]@{ Cuts = @($page.Cuts) + @([pscustomobject]@{ Parts = 2L; Part = [long]$half }) }) }
|                $cutsMade++
|                & $Log 'INFO' ('{0}: a part was {1} -- it is read again in two smaller parts' -f $What, $fail.Why)
|            }
|            continue
|        }
|        $emptyRefusals = 0
|        $n = $rows.Count
|        $pages++; $rowsRead += $n
|        if ($OnRows) { $null = & $OnRows $rows } else { $acc.AddRange([object[]]$rows) }
|        $rows = $null
|        # measured, not assumed: a part far larger than planned -> every part still to read is cut by that factor
|        if (@($page.Cuts).Count -gt 0 -and $n -gt (2 * $TargetRows) -and $queue.Count -gt 0) {
|            $factor = [long][Math]::Ceiling([double]$n / [double]$TargetRows)
|            $rest = $queue.ToArray(); $queue.Clear()
|            foreach ($rp in $rest) { for ($piece = 0L; $piece -lt $factor; $piece++) { $queue.Enqueue([pscustomobject]@{ Cuts = @($rp.Cuts) + @([pscustomobject]@{ Parts = $factor; Part = $piece }) }) } }
|            $cutsMade++
|            & $Log 'INFO' ('{0}: its parts are larger than measured -- the {1} part(s) still to read are read as {2}' -f $What, $rest.Count, $queue.Count)
|        }
|    }
|    if ($pages -gt 1) { & $Log 'INFO' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}: read whole in {1} part(s), {2:N0} row(s)', $What, $pages, $rowsRead)) }
|    $out = [ordered]@{ Rows = @(); RowCount = $rowsRead; Pages = $pages; Parts = $planned; Cuts = $cutsMade }
|    if ($acc) { $out.Rows = $acc.ToArray() }
|    [pscustomobject]$out
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-LogIngest.ps1'] = @{ Sha256 = '877c581ac6adda5fa7951afb09db3fefd7fbe77742dfbc686cf9037255224f6f'; Text = @'
|#Requires -Version 5.1
|<#
|    SI -- publish rows to a Log Analytics custom table through the normal DCR path.
|
|    Moved here from engine/asset-correlation/_shared/SI-CorrelationIngest.ps1 because a FREE stage uses
|    it too: the azure profiler's Defender for Cloud recommendations stage publishes with
|    Send-SIObjectMapRows. The correlation engine is part of SecurityInsight Pro and is not in the
|    Community edition, so a free engine must never load a file from its folder. The function names are
|    unchanged, so every caller and test keeps working.
|#>
|
|# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.
|
|# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
|if (-not (Get-Command -Name Invoke-SIArm -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }
|
|function Initialize-SIIngestGlobals {
|    <#
|      Fill the three names the DCR/DCE pinning and the LogIngest role grant need, from what an install
|      actually has (#174). The profiling orchestrator backfills them at its entry; the stages and engines that
|      publish WITHOUT it (trend, Defender recommendations, the Pro engines) did not -- and the CLI setup wrote
|      only the older names -- so pinning was skipped and a new DCR got no LogIngest principal.
|        SI_AzSubscriptionId  <- the subscription in SI_WorkspaceResourceId, else the 2.2.x SubscriptionId
|        SI_DceResourceGroup  <- the 2.2.x DceResourceGroup, else SI_DcrResourceGroup (same RG by default)
|        SI_SPN_ObjectId      <- SpnObjectId, else SI_LogIngest_ObjectId
|      Only EMPTY names are filled; a value the customer set always stands. Never throws.
|    #>
|    if (-not $global:SI_AzSubscriptionId) {
|        if ("$($global:SI_WorkspaceResourceId)" -match '/subscriptions/([^/]+)/') { $global:SI_AzSubscriptionId = $Matches[1] }
|        elseif ($global:SubscriptionId) { $global:SI_AzSubscriptionId = [string]$global:SubscriptionId }
|    }
|    if (-not $global:SI_DceResourceGroup) {
|        # SI_DcrResourceGroup FIRST: the unprefixed DceResourceGroup is ALWAYS set by the solution-wide shared
|        # defaults ('rg-dce-securityinsight'), so after loading it cannot tell a customer value from the default.
|        # The DCE normally lives with the DCRs (the sample: "leave unset, same RG as workspace").
|        if ($global:SI_DcrResourceGroup) { $global:SI_DceResourceGroup = [string]$global:SI_DcrResourceGroup }
|        elseif ($global:DceResourceGroup) { $global:SI_DceResourceGroup = [string]$global:DceResourceGroup }
|    }
|    if (-not $global:SI_SPN_ObjectId) {
|        if ($global:SpnObjectId) { $global:SI_SPN_ObjectId = [string]$global:SpnObjectId }
|        elseif ($global:SI_LogIngest_ObjectId) { $global:SI_SPN_ObjectId = [string]$global:SI_LogIngest_ObjectId }
|    }
|}
|
|function Get-SILogIngestObjectId {
|    <#
|      The object id that gets the ingest role on a new or updated data collection rule: SI_SPN_ObjectId (what setup
|      writes), else the older SI_LogIngest_ObjectId -- the same order Send-SIObjectMapRows, trend, asset properties and
|      the run-health row use. Three output stages passed SI_LogIngest_ObjectId alone, so an install with only
|      SI_SPN_ObjectId got a rule nobody could post to (#257). Empty when neither is set.
|    #>
|    if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_ObjectId)) { return [string]$global:SI_SPN_ObjectId }
|    return [string]$global:SI_LogIngest_ObjectId
|}
|
|function Select-SIIngestTarget {
|    <#
|        #199 -- make the endpoint AzLogDcrIngestPS will use the RIGHT one, before it touches the rule and again
|        before the post. The module resolves the endpoint by NAME ONLY -- the first match in $global:AzDceDetails,
|        or in a tenant-wide Resource Graph query when that cache is empty. Measured 2026-10-01: three endpoints
|        named dce-securityinsight in two subscriptions; a rule created on the right one was re-bound to another
|        one minute later by the engine's own post (#198); four rules on this tenant were bound to the other
|        subscription's endpoint.
|        The endpoint is chosen as follows:
|          - a rule that EXISTS posts through the endpoint it is bound to, when that endpoint has the configured
|            name. Ingestion accepts a post only through the rule's own endpoint, and moving a rule is not an
|            option -- measured 2026-10-01, a re-bound rule was still refused (HTTP 403) more than 10 minutes later.
|          - otherwise (a new rule) this install's endpoint -- subscription + resource group + name -- so the
|            module creates the rule there and not on a same-named endpoint elsewhere.
|          - ONE endpoint of that name anywhere is unambiguous and used (an endpoint outside the rules' resource
|            group has always worked that way). Several and none here: refused, nothing is posted.
|        The DCR cache is narrowed to this install's rule (or, before it exists, cleared of same-named rules
|        elsewhere). An empty cache is built first. Without a subscription id there is nothing to pin to.
|    #>
|    param([hashtable]$AuthParams, [Parameter(Mandatory)][string]$DcrName)
|    $sub = [string]$global:SI_AzSubscriptionId
|    if (-not $sub -or -not $global:SI_DceName) { return }
|    $dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { [string]$global:SI_DcrResourceGroup }
|    $dcrRg = [string]$global:SI_DcrResourceGroup
|    $rebuilt = $false
|    $rebuild = {
|        if ($rebuilt -or -not $AuthParams) { return }
|        try { $global:AzDceDetails = Get-SIDceList @AuthParams -Verbose:$false 4>$null } catch { }
|        try { $global:AzDcrDetails = Get-SIDcrList @AuthParams -Verbose:$false 4>$null } catch { }
|        $rebuilt = $true   # dot-sourced: this IS the function's scope
|    }
|    $findHere = { @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dceRg/*" }) | Select-Object -First 1 }
|    $findRule = { if ($dcrRg) { @($global:AzDcrDetails | Where-Object { $_ -and $_.name -eq $DcrName -and [string]$_.id -like "/subscriptions/$sub/resourceGroups/$dcrRg/*" }) | Select-Object -First 1 } }
|
|    if (-not $global:AzDceDetails) { . $rebuild }
|    $dce = . $findHere
|    $dcr = . $findRule
|    if (-not $dce -or ($dcrRg -and -not $dcr)) { . $rebuild; $dce = . $findHere; $dcr = . $findRule }
|    if (-not $dce) {
|        $same = @($global:AzDceDetails | Where-Object { $_ -and $_.name -eq $global:SI_DceName })
|        if ($same.Count -ne 1) {
|            throw ("Data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}'. {3} endpoint(s) of that name exist elsewhere, so nothing was posted -- set SI_DceResourceGroup to the one this install uses." -f $global:SI_DceName, $dceRg, $sub, $same.Count)
|        }
|        $dce = $same[0]
|    }
|    $bound = if ($dcr -and $dcr.properties) { [string]$dcr.properties.dataCollectionEndpointId } else { '' }
|    if ($bound -and $bound -ne [string]$dce.id) {
|        $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1
|        if (-not $b) { . $rebuild; $b = @($global:AzDceDetails | Where-Object { $_ -and [string]$_.id -eq $bound }) | Select-Object -First 1 }
|        if ($b -and $b.name -eq $global:SI_DceName) {
|            Write-Verbose ("Data collection rule '{0}' is bound to {1}; posting through it." -f $DcrName, $bound)
|            $dce = $b
|        }
|    }
|    $global:AzDceDetails = @($dce)
|    if ($dcr) { $global:AzDcrDetails = @($dcr) }
|    elseif ($global:AzDcrDetails) { $global:AzDcrDetails = @($global:AzDcrDetails | Where-Object { $_ -and $_.name -ne $DcrName }) }
|}
|function Resolve-SICorrelationAuthParams {
|    <#
|        MI > SPN+cert > SPN+secret, resolved into the splat AzLogDcrIngestPS wants.
|        Mirrors Send-SIRunHealthRow deliberately -- see this file's header for why it is not shared.
|    #>
|    $spnAppId     = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_LogIngest_AppId }
|    $spnSecret    = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_LogIngest_Secret }
|    $spnTenantId  = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_LogIngest_TenantId }
|    $spnCertThumb = [string]$global:SI_SPN_CertThumbprint
|
|    # Auto-detect which store actually holds the private key. A thumbprint in the wrong store reads as
|    # "no cert" and falls through to the secret branch, which then fails on a tenant that has no secret.
|    $spnCertStore = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
|                    elseif ($spnCertThumb) {
|                        $clean = $spnCertThumb -replace '\s',''
|                        if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
|                            $resolved = 'LocalMachine'
|                            foreach ($s in 'LocalMachine','CurrentUser') {
|                                $c = Get-ChildItem "Cert:\$s\My" -ErrorAction SilentlyContinue |
|                                     Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
|                                     Select-Object -First 1
|                                if ($c) { $resolved = $s; break }
|                            }
|                            $resolved
|                        } else {
|                            # #209: no Cert: drive (a Linux container) -- read the X509Store instead.
|                            if (-not (Get-Command Get-SICertStoreLocation -ErrorAction Ignore)) {
|                                . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Find-SICertificate.ps1')
|                            }
|                            Get-SICertStoreLocation -Thumbprint $clean
|                        }
|                    } else { 'LocalMachine' }
|
|    $useMi   = $global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace($global:SI_UAMI_ClientId)
|    $useCert = -not $useMi -and -not [string]::IsNullOrWhiteSpace($spnCertThumb)
|
|    if ($useMi) {
|        return @{ UseManagedIdentity = $true; ManagedIdentityClientId = $global:SI_UAMI_ClientId }
|    }
|    if ($useCert) {
|        return @{
|            AzAppId                       = $spnAppId
|            AzAppCertificateThumbprint    = $spnCertThumb
|            AzAppCertificateStoreLocation = $spnCertStore
|            TenantId                      = $spnTenantId
|        }
|    }
|    @{ AzAppId = $spnAppId; AzAppSecret = $spnSecret; TenantId = $spnTenantId }
|}
|
|function Send-SIObjectMapRows {
|    <#
|        Publish the map to SI_ObjectMap_CL through the normal DCR path.
|
|        SQL COMPUTES AND HOLDS, LA PUBLISHES -- and there is no SQL yet, so today this IS the store.
|
|        🔴 CORRECTED 2026-08-13. This header used to say the deterministic seed means "an object's id is
|        recomputed identically every run", and that key-stability memory was "an OPTIMISATION over a
|        correctness property the core already has". THAT WAS WRONG, and believing it is what would ship
|        duplicate CIs. The property the core has is `same INPUT -> same id`. The property a connector
|        needs is `same OBJECT -> same id`. They diverge whenever group membership changes:
|
|          * Measured: adding one member carrying a lower-sorting exposure-graph id moved a group from
|            `exposuregraphnodeid:aaa` to `exposuregraphnodeid:000`. The seed is the ordinally-lowest
|            value of the highest-priority type PRESENT IN THE GROUP, so any arrival or departure moves
|            it.
|          * Departures are routine: the same day, EndpointEG returned 0 rows on a timeout and 51 assets
|            left the snapshot.
|          * Anchors churn independently -- MDE ids rotate, a rebuilt VM gets a new ARM path, a
|            re-enrolled device gets a new AadDeviceId.
|
|        So SQL key-stability is a CORRECTNESS PREREQUISITE before the connector may create CIs, not an
|        optimisation. Publishing to LA without it is fine -- reading a map is harmless. CREATING a
|        ServiceNow CI from an id that can move is not.
|
|        Decided 2026-08-13 (V3-ARCHITECTURE 2.3a): a minted UUIDv5-from-birth-anchor id, stored, with an
|        anchor ledger and a superseded table. Until that exists, ids emitted here are PROVISIONAL and a
|        connector must not create CIs from them.
|
|        NOT best-effort. Unlike the run-health heartbeat, this IS the output -- a swallowed failure
|        would leave consumers reading a stale map while every run reported success.
|    #>
|    param(
|        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
|        [string]$TableName = 'SI_ObjectMap',
|        [string]$DcrName
|    )
|
|    if (@($Rows).Count -eq 0) {
|        Write-Warning 'correlation: nothing to publish -- 0 map rows. Not posting.'
|        return 0
|    }
|    if ([string]::IsNullOrWhiteSpace($DcrName)) {
|        $DcrName = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ObjectMap_DcrName)) {
|            [string]$global:SI_ObjectMap_DcrName
|        } else { 'dcr-si-objectmap' }
|    }
|
|    $savedVerbose = $global:VerbosePreference
|    $global:VerbosePreference = 'SilentlyContinue'
|    $lock = $null
|    try {
|        $authParams = Resolve-SICorrelationAuthParams
|        Initialize-SIIngestGlobals
|        $spnObjectId = if ($global:SI_SPN_ObjectId) { $global:SI_SPN_ObjectId } else { $global:SI_LogIngest_ObjectId }
|
|        # #475 -- A TABLE + RULE ALREADY MADE READY IN THIS PROCESS FOR THESE COLUMNS IS NOT CHECKED AGAIN. The steps below
|        # (endpoint + rule selection twice, the table / rule update with its coverage check, the cache refresh) are several
|        # Azure calls; they ran for every batch, and a run collected in parts posts its records in dozens of batches
|        # (customer H 2026-10-09: 96,551 records). A batch whose columns were all made ready earlier in this process posts
|        # through the same pinned endpoint and rule; a batch with a NEW column takes the full path again.
|        $readyKey = ('{0}|{1}' -f $TableName, $DcrName).ToLowerInvariant()
|        $batchCols = Get-SIObjectMapColumns -Rows @($Rows)
|        # in the run cache (global, like the tokens: this file is dot-sourced at different depths, so $script: differs)
|        $rcache = Get-SILogIngestRunCache
|        if (-not ($rcache.ObjectMapReady -is [hashtable])) { $rcache.ObjectMapReady = @{} }
|        $ready = $rcache.ObjectMapReady[$readyKey]
|        if ($ready -and (Test-SIObjectMapColumnsReady -Ready $ready.Columns -Columns $batchCols)) {
|            $global:AzDceDetails = @($ready.Dce); $global:AzDcrDetails = @($ready.Dcr)
|            $data = @($Rows)
|            $data = Repair-SILogColumnName -Data $data 4>$null
|            $data = Format-SILogRowsToSchema -Data $data 4>$null
|            $null = Send-SILogData -DceName $global:SI_DceName -DcrName $DcrName -Data $data -TableName $TableName @authParams 4>$null
|            return @($data).Count
|        }
|        # several processes of one run publish at once (the records of a run collected in parts): the table / rule update
|        # is done by one at a time (SI_INGEST_LOCK_FILE), so two never update the same rule over each other
|        $lock = Enter-SIIngestLock
|
|        # 🔴 THE WHOLE SET, NOT ONE ROW -- CORRECTED 2026-08-31. `-Data` was
|        # `@($Rows | Select-Object -First 1)`. AzLogDcrIngestPS INFERS the table + DCR column set
|        # from what it is handed, so one row defined the schema for the entire table: a row lacking
|        # an optional field meant that column was never created, and every other row's value for it
|        # was DROPPED AT INGEST, silently, for the life of the table.
|        # 🪤 Nothing errors. The engine reports rows posted, the table exists, and the field is
|        # simply absent -- indistinguishable from "no object had a value".
|        # 📌 The four profilers already got this right (Invoke-Output.ps1's `$schemaSample` is the
|        # FULL dataset, commented "full dataset for type inference"). Only the engines that publish
|        # their own v3 tables carried the shortcut.
|        #
|        # 🔴 AND THIS COMMENT MUST STAY *ABOVE* THE CALL, NOT INSIDE IT (audit #102, 2026-09-02).
|        # It was written between two backtick-continued argument lines, and **a comment TERMINATES a
|        # backtick continuation**: everything after it was dropped, including the `-Data @($Rows)` this
|        # very comment was added to introduce. Correlation then failed at publish on every run --
|        # `missing mandatory parameters: Data AzDcrSetLogIngestApiAppPermissionsDcrLevel
|        # AzLogDcrTableCreateFromReferenceMachine`, which is exactly the arguments that follow it here.
|        # #199 -- pin BEFORE the create/update, not only before the post.
|        Select-SIIngestTarget -AuthParams $authParams -DcrName $DcrName
|        $null = Update-SILogTableSchema `
|            -AzLogWorkspaceResourceId                   $global:SI_WorkspaceResourceId `
|            @authParams `
|            -DceName                                    $global:SI_DceName `
|            -DcrName                                    $DcrName `
|            -DcrResourceGroup                           $global:SI_DcrResourceGroup `
|            -TableName                                  $TableName `
|            -Data                                       @($Rows) `
|            -LogIngestServicePricipleObjectId           $spnObjectId `
|            -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
|            -AzLogDcrTableCreateFromAnyMachine          $true `
|            -AzLogDcrTableCreateFromReferenceMachine    @() 4>$null
|
|        # Re-sync the DCE/DCR cache so a freshly created DCR's immutableId is known before the
|        # name-only lookup inside Post-*. Without it the module falls back to the DCE's location
|        # field as a bogus immutableId and the ingestion API answers 404 'westeurope'.
|        try {
|            $ensureFn = Get-Command -Name 'Ensure-SecurityInsightAzDceDcrCache' -ErrorAction Ignore
|            if ($ensureFn) {
|                & $ensureFn @authParams `
|                    -SubscriptionId   $global:SI_AzSubscriptionId `
|                    -DceResourceGroup $global:SI_DceResourceGroup `
|                    -DcrResourceGroup $global:SI_DcrResourceGroup `
|                    -Force 4>$null
|            }
|        } catch { }
|
|        # 📌 SUPERSEDED 2026-10-01 (#199): Select-SIIngestTarget above now builds and pins the caches BEFORE the
|        # create/update -- the module resolves the endpoint by name inside CheckCreateUpdate too, so pinning only
|        # here was too late. The history below is kept for the BlockCopy lesson.
|        # 🪤 DO NOT PRE-POPULATE THE CACHES HERE. Tried on 2026-08-30, mirroring the profiler's
|        # `$global:AzDceDetails = Get-AzDceListAll @authParams`, on the reasoning that filtering a
|        # cache that does not exist yet would be a silent no-op. It is not a no-op -- by this point
|        # `CheckCreateUpdate-TableDcr-Structure` (called above) has already built both caches, which
|        # is why the DCR pin below has always worked. The rebuild is redundant work, nothing more.
|        # 📌 It was briefly believed to have CAUSED the "BlockCopy ... Object must be an array of
|        # primitives" error that appeared once the 403 was gone. It did not, and the wrong version of
|        # this note lived here for an hour. That error was a real defect in AzLogDcrIngestPS 1.7.1 --
|        # `return $bytes` enumerates the array, so the caller binds object[] and [Buffer]::BlockCopy
|        # rejects it -- which broke the UNCOMPRESSED path for every caller of the module. Fixed
|        # upstream in 1.7.2 (SI finding #81). Removing these lines did not make it go away; only the
|        # module fix did.
|
|        # DCR name-collision guard. One SPN can see same-named DCRs in several subscriptions -- there
|        # are already three DCEs called dce-securityinsight in this tenant -- and the module's name-only
|        # lookup then picks one at random. Pin to (sub + RG + name) before posting.
|        if ($global:AzDcrDetails -and $global:SI_AzSubscriptionId -and $global:SI_DcrResourceGroup) {
|            $picked = @($global:AzDcrDetails | Where-Object {
|                $_.name -eq $DcrName -and
|                $_.id   -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)/*"
|            }) | Select-Object -First 1
|            if ($picked) { $global:AzDcrDetails = @($picked) }
|        }
|
|        # 🔴 AND THE SAME GUARD FOR THE **DCE** -- its absence is why this engine could never publish.
|        # The comment above names the hazard exactly ("three DCEs called dce-securityinsight") and then
|        # pins only the DCR. `Post-*` resolves the DCE by NAME-ONLY against $global:AzDceDetails, so it
|        # could pick an endpoint in a DIFFERENT subscription and post this workspace's DCR immutableId
|        # to it -- which the Log Ingestion API answers with **HTTP 403**.
|        # MEASURED 2026-08-30: three DCEs named `dce-securityinsight` exist across this tenant (one in
|        # the workspace's own subscription, two in a sibling), and every correlation run ended
|        # `[ERROR] Engine failed: Log Ingestion API request failed. HTTP Status: 403` AFTER doing all
|        # of its real work -- 1296 rows read, 1291 objects correlated, ledger updated, 2228 map rows
|        # built -- and losing the lot at the final POST. That is why the handoff records correlation as
|        # "built + run on real data, never published": it was never a correlation defect at all.
|        # 🔑 THE PROFILER ALREADY SOLVES THIS. `Apply-SIDcrScopeFilter` (asset-profiling/stages/
|        # Invoke-Output.ps1) filters BOTH caches to the configured sub + RG, which is exactly why the
|        # four profilers ingest happily while this engine 403s on the same credentials. Operator,
|        # 2026-08-30: *"it must use same auth as the design is using to send data to la in the
|        # profiler"* -- so this mirrors that filter rather than inventing a third variant.
|        # 📌 Same auth params, same scope pin. The DCE RG falls back to the DCR RG, matching the
|        # profiler's own default of 'rg-securityinsight' when SI_DceResourceGroup is unset.
|        $_dceRg = if ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup }
|                  else { [string]$global:SI_DcrResourceGroup }
|        if ($global:AzDceDetails -and $global:SI_AzSubscriptionId -and $_dceRg) {
|            $_pickedDce = @($global:AzDceDetails | Where-Object {
|                $_.id -like "*/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$_dceRg/*"
|            })
|            if ($_pickedDce.Count -gt 0) { $global:AzDceDetails = @($_pickedDce) }
|        }
|
|        # #199 -- again before the post: the cache refresh above narrowed it to this install's endpoint, which is
|        # not the rule's own when the rule is bound elsewhere.
|        Select-SIIngestTarget -AuthParams $authParams -DcrName $DcrName
|        # ready for these columns in this process (#475): the next batch with no new column posts straight away
|        $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|        if ($ready) { foreach ($c in $ready.Columns) { [void]$known.Add($c) } }
|        foreach ($c in $batchCols) { [void]$known.Add($c) }
|        $rcache.ObjectMapReady[$readyKey] = [pscustomobject]@{ Columns = $known; Dce = @($global:AzDceDetails); Dcr = @($global:AzDcrDetails) }
|        Exit-SIIngestLock -Lock $lock; $lock = $null
|        $data = @($Rows)
|        $data = Repair-SILogColumnName -Data $data 4>$null
|        $data = Format-SILogRowsToSchema -Data $data 4>$null
|        $null = Send-SILogData `
|            -DceName   $global:SI_DceName `
|            -DcrName   $DcrName `
|            -Data      $data `
|            -TableName $TableName `
|            @authParams 4>$null
|
|        @($data).Count
|    }
|    finally {
|        if ($lock) { Exit-SIIngestLock -Lock $lock }
|        if ($null -ne $savedVerbose) { $global:VerbosePreference = $savedVerbose }
|    }
|}
|
|function Get-SIObjectMapColumns {
|    <# PURE. Every column name of a batch of rows (PSObject properties or dictionary keys), once. #>
|    param([AllowEmptyCollection()][object[]]$Rows = @())
|    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    foreach ($r in $Rows) {
|        if ($null -eq $r) { continue }
|        if ($r -is [System.Collections.IDictionary]) { foreach ($k in $r.Keys) { [void]$set.Add([string]$k) } }
|        else { foreach ($p in $r.PSObject.Properties) { [void]$set.Add($p.Name) } }
|    }
|    $out = New-Object System.Collections.Generic.List[string]
|    foreach ($c in $set) { $out.Add($c) }
|    , $out.ToArray()
|}
|
|function Test-SIObjectMapColumnsReady {
|    <# PURE. $true when every column of the batch is among the columns already made ready. #>
|    param($Ready, [AllowEmptyCollection()][string[]]$Columns = @())
|    if ($null -eq $Ready) { return $false }
|    foreach ($c in $Columns) { if (-not $Ready.Contains($c)) { return $false } }
|    $true
|}
|
|function Enter-SIIngestLock {
|    <#
|        The cross-process lock of the table / rule update (SI_INGEST_LOCK_FILE, set by a parent that runs several publishing
|        processes at once). No variable = no lock ($null). Waits up to 20 minutes; then goes on without it, said once -- a
|        lock that cannot be taken never stops a publish (the coverage check before every post still guards the rule).
|    #>
|    param([int]$WaitSeconds = 1200)
|    $path = [string][Environment]::GetEnvironmentVariable('SI_INGEST_LOCK_FILE')
|    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
|    $until = [datetime]::UtcNow.AddSeconds($WaitSeconds)
|    while ([datetime]::UtcNow -lt $until) {
|        try { return [System.IO.File]::Open($path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
|        catch { Start-Sleep -Milliseconds 500 }
|    }
|    Write-Warning ('the table update lock ({0}) was not free for {1} seconds -- this process goes on without it' -f $path, $WaitSeconds)
|    $null
|}
|
|function Exit-SIIngestLock {
|    param($Lock)
|    if ($Lock) { try { $Lock.Dispose() } catch { } }
|}
|
|# =====================================================================================================================
|#  LOG INGESTION OVER PLAIN REST -- SecurityInsight needs no PowerShell module (no AzLogDcrIngestPS, no Az.*).
|# =====================================================================================================================
|<#
|    Every SI call site calls the SI wrapper of the job; each wrapper does it over plain REST (its *Rest function):
|
|        SI wrapper                  replaces (AzLogDcrIngestPS)                            SI REST function
|        Get-SIDceList               Get-AzDceListAll                                       Get-SIDceListRest
|        Get-SIDcrList               Get-AzDcrListAll                                       Get-SIDcrListRest
|        Update-SILogTableSchema     CheckCreateUpdate-TableDcr-Structure                   Update-SILogTableSchemaRest
|        Send-SILogData              Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output     Send-SILogDataRest
|        Add-SICollectionTime        Add-CollectionTimeToAllEntriesInArray                  Add-SICollectionTimeRest
|        Add-SIColumnData            Add-ColumnDataToAllEntriesInArray                      Add-SIColumnDataRest
|        Repair-SILogColumnName      ValidateFix-AzLogAnalyticsTableSchemaColumnNames       Repair-SILogColumnNameRest
|        Format-SILogRowsToSchema    Build-DataArrayToAlignWithSchema                       Format-SILogRowsToSchemaRest
|        Get-SILogSchemaArray        Get-ObjectSchemaAsArray                                Get-SILogSchemaRest -As Array
|        Get-SILogSchemaHash         Get-ObjectSchemaAsHash                                 Get-SILogSchemaRest -As Hash
|        Test-SILogTableDcrStatus    Get-AzLogAnalyticsTableAzDataCollectionRuleStatus      Test-SILogTableDcrStatusRest
|        Set-SILogTable              CreateUpdate-AzLogAnalyticsCustomLogTableDcr           Set-SILogTableRest
|        Set-SILogDcr                CreateUpdate-AzDataCollectionRuleLogIngestCustomLog    Set-SILogDcrRest
|
|    The wrappers keep the parameter names and types the call sites were written against, so no call site changed.
|
|    PS 5.1 safe: no ?. / ??, no RSA.ImportFromPem. Works on pwsh 7 / Linux (no Cert: drive needed). Community + Pro:
|    this file never references a Pro path.
|#>
|
|function Get-SILogIngestWrapperMap {
|    <# The wrapper -> replaced function -> REST function table above, as data (the wiring tests read it). #>
|    [ordered]@{
|        'Get-SIDceList'            = @{ Replaces = 'Get-AzDceListAll';                                   Rest = 'Get-SIDceListRest' }
|        'Get-SIDcrList'            = @{ Replaces = 'Get-AzDcrListAll';                                   Rest = 'Get-SIDcrListRest' }
|        'Update-SILogTableSchema'  = @{ Replaces = 'CheckCreateUpdate-TableDcr-Structure';               Rest = 'Update-SILogTableSchemaRest' }
|        'Send-SILogData'           = @{ Replaces = 'Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output'; Rest = 'Send-SILogDataRest' }
|        'Add-SICollectionTime'     = @{ Replaces = 'Add-CollectionTimeToAllEntriesInArray';              Rest = 'Add-SICollectionTimeRest' }
|        'Add-SIColumnData'         = @{ Replaces = 'Add-ColumnDataToAllEntriesInArray';                  Rest = 'Add-SIColumnDataRest' }
|        'Repair-SILogColumnName'   = @{ Replaces = 'ValidateFix-AzLogAnalyticsTableSchemaColumnNames';   Rest = 'Repair-SILogColumnNameRest' }
|        'Format-SILogRowsToSchema' = @{ Replaces = 'Build-DataArrayToAlignWithSchema';                   Rest = 'Format-SILogRowsToSchemaRest' }
|        'Get-SILogSchemaArray'     = @{ Replaces = 'Get-ObjectSchemaAsArray';                            Rest = 'Get-SILogSchemaRest' }
|        'Get-SILogSchemaHash'      = @{ Replaces = 'Get-ObjectSchemaAsHash';                             Rest = 'Get-SILogSchemaRest' }
|        'Test-SILogTableDcrStatus' = @{ Replaces = 'Get-AzLogAnalyticsTableAzDataCollectionRuleStatus';  Rest = 'Test-SILogTableDcrStatusRest' }
|        'Set-SILogTable'           = @{ Replaces = 'CreateUpdate-AzLogAnalyticsCustomLogTableDcr';       Rest = 'Set-SILogTableRest' }
|        'Set-SILogDcr'             = @{ Replaces = 'CreateUpdate-AzDataCollectionRuleLogIngestCustomLog'; Rest = 'Set-SILogDcrRest' }
|    }
|}
|
|# ---- the wrappers ------------------------------------------------------------------------------------------------
|# Each declares the parameters the call sites pass (names + types) and forwards @PSBoundParameters: only what the call
|# site bound, with the value it bound, including -Verbose:$false. NOT `@args`: measured 2026-10-03 on PS 5.1 and 7.6,
|# `@args` splits `-Name:$value` into a bare switch plus a positional value.
|
|function Get-SIDceList {
|    [CmdletBinding()]
|    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    return (Get-SIDceListRest @PSBoundParameters)
|}
|
|function Get-SIDcrList {
|    [CmdletBinding()]
|    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    return (Get-SIDcrListRest @PSBoundParameters)
|}
|
|function Get-SIDcrCreateRefusal {
|    <# PURE. The line of a DCR / table create's captured output in which Azure (or the create itself) REFUSED it -- the
|       Microsoft answer to surface, '' when there is none. A refused create never makes the rule appear, so it is not waited for.
|       'skipping create' / 'already exists in' (a rule of that name in ANOTHER resource group) is a refusal too: the create did nothing. #>
|    param([AllowNull()][AllowEmptyString()][string]$CreateOutput)
|    if ([string]::IsNullOrWhiteSpace($CreateOutput)) { return '' }
|    $re = '(?i)AuthorizationFailed|LinkedAuthorizationFailed|\(Forbidden\)|\b403\b|\(Unauthorized\)|\b401\b|InvalidPayload|InvalidTemplate|InvalidRequestContent|BadRequest|ResourceGroupNotFound|SubscriptionNotFound|WorkspaceNotFound|Step 3 threw|skipping create|already exists in'
|    foreach ($l in ($CreateOutput -split '\r?\n')) { if ($l -match $re) { return $l.Trim() } }
|    ''
|}
|
|function Wait-SIDcrReady {
|    <#
|        Fix request 2a40d950 (owner 2026-10-22: no fixed limits on SI's own work): after the table / rule create, WAIT UNTIL
|        THE RULE IS READY and read it back -- never a fixed number of seconds that gives up while Azure is still making it
|        (it was 240 s). A not-found / no-immutableId answer right after a create means "not yet" (REQUIREMENTS #619). It stops
|        only on EVIDENCE that waiting cannot help, and says Microsoft's answer:
|          * the create's own output carries a refusal (Get-SIDcrCreateRefusal) -- before any wait;
|          * Azure says the rule's provisioning FAILED;
|          * reading the rule is refused (401 / 403 -- the identity may not read it);
|          * the create has RETURNED and two read-backs in a row, spaced by the progress pace (-MaxPauseSeconds), find NO rule
|            at all: the create did nothing, so waiting cannot help (review S1: it polled until the job died). A rule that IS
|            there but still provisioning is waited for without a deadline.
|        Any other failed read is a transient answer: said, and read again. Progress is said on every read (elapsed, what was
|        seen); the first read is at once (a rule that is already there costs no wait); the pause between reads grows from -FirstPauseSeconds to -MaxPauseSeconds (a pace, never a deadline).
|        -Probe { } -> @{ ImmutableId; State } of the rule as SI's own lists see it now ($null = not there yet); it throws
|        when the read fails. -Sleep { param($s) } / -Log { param($m) } are seams. Returns @{ Ready; ImmutableId; Waited; Why }.
|    #>
|    param([Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][scriptblock]$Probe, [AllowNull()][AllowEmptyString()][string]$CreateOutput,
|          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log = { param($m) Write-Host $m },
|          [int]$FirstPauseSeconds = 15, [int]$MaxPauseSeconds = 60, [AllowEmptyString()][string]$Location = '')
|    $refused = Get-SIDcrCreateRefusal -CreateOutput $CreateOutput
|    if ($refused) {
|        # read back ONCE: a refusal of a later part (the table, a role) can come after the rule itself was made -- then it is used
|        $r = $null; try { $r = & $Probe } catch { $r = $null }
|        if ($null -ne $r -and [string]$r.ImmutableId -and [string]$r.ImmutableId -notlike '*location*' -and [string]$r.ImmutableId -ne $Location -and [string]$r.State -notmatch '(?i)^failed$') {
|            & $Log ("DCR '{0}' is ready although the create reported: {1}" -f $DcrName, $refused)
|            return @{ Ready = $true; ImmutableId = [string]$r.ImmutableId; Waited = 0; Why = '' }
|        }
|        return @{ Ready = $false; ImmutableId = ''; Waited = 0; Why = ("the create of DCR '{0}' was refused -- {1}" -f $DcrName, $refused) }
|    }
|    $waited = 0; $pause = [Math]::Max(1, $FirstPauseSeconds); $absent = 0
|    while ($true) {
|        $seen = 'not there yet'
|        try {
|            $r = & $Probe
|            if ($null -ne $r) {
|                $imm = [string]$r.ImmutableId; $st = [string]$r.State
|                if ($st -match '(?i)^failed$') { return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("Azure reports DCR '{0}' with provisioning state Failed" -f $DcrName) } }
|                if ($imm -and $imm -notlike '*location*' -and $imm -ne $Location) { & $Log ("DCR immutableId resolved after {0}s: {1}" -f $waited, $imm); return @{ Ready = $true; ImmutableId = $imm; Waited = $waited; Why = '' } }
|                $seen = $(if ($st) { "there, provisioning state $st, no immutableId yet" } else { 'there, no immutableId yet' })
|                $absent = 0
|            } else {
|                $absent++
|                if ($absent -ge 2) {
|                    $said = @(([string]$CreateOutput) -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
|                    $answer = $(if ($said.Count) { $said[-1] } else { 'nothing (the create returned no output)' })
|                    return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("the rule was not created; Azure answered: {0} -- DCR '{1}' was not found on two read-backs {2}s apart after the create returned" -f $answer, $DcrName, [Math]::Max(1, $MaxPauseSeconds)) }
|                }
|            }
|        } catch {
|            $m = ("$($_.Exception.Message)" -replace '\s+', ' ').Trim()
|            if ($m -match '(?i)\b401\b|\b403\b|AuthorizationFailed|Forbidden|Unauthorized') { return @{ Ready = $false; ImmutableId = ''; Waited = $waited; Why = ("reading DCR '{0}' was refused -- {1}" -f $DcrName, $m) } }
|            $seen = "the read failed ($m) -- read again"
|        }
|        & $Log ("waiting for DCR '{0}' to be ready ({1}s so far; {2}) ..." -f $DcrName, $waited, $seen)
|        # after a read that found no rule at all, the next read is a full progress pace later (the second read-back of the stop rule)
|        $nap = $(if ($absent -ge 1) { [Math]::Max($pause, [Math]::Max(1, $MaxPauseSeconds)) } else { $pause })
|        & $Sleep $nap
|        $waited += $nap
|        $pause = [Math]::Min([Math]::Max(1, $MaxPauseSeconds), $pause * 2)
|    }
|}
|
|function Update-SILogTableSchema {
|    [CmdletBinding()]
|    param([Array]$Data, [string]$AzLogWorkspaceResourceId, [string]$TableName, [string]$DcrName, [string]$DcrResourceGroup, [string]$DceName,
|          [AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel,
|          [boolean]$AzLogDcrTableCreateFromAnyMachine, [string]$SchemaMode, [boolean]$EnableUploadViaLogHub,
|          [AllowEmptyCollection()][array]$AzLogDcrTableCreateFromReferenceMachine,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    # A rule that already feeds ANOTHER table is never repurposed, and columns this call adds to an existing rule are
|    # noted so the post can check that they are stored (Start-SILogDcrWatch / Complete-SILogDcrWatch, below).
|    $watch = Start-SILogDcrWatch -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -Bound $PSBoundParameters
|    # A NEW rule for a table that already exists is declared from the TABLE (its columns, with their types):
|    # Set-SILogDcrRest does this itself.
|    $out = Update-SILogTableSchemaRest @PSBoundParameters
|    # The rule this install posts through must declare EVERY column of the data -- a column it does not declare is
|    # dropped by Azure without an error. Missing ones are added from the table; any still missing refuses the post.
|    # Before Complete-SILogDcrWatch, so columns added here are checked after the post like any other new column.
|    $null = Assert-SILogDcrCoversData -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -DceName $DceName -Data $Data -Bound $PSBoundParameters
|    Complete-SILogDcrWatch -Watch $watch
|    $out
|}
|
|function Send-SILogData {
|    [CmdletBinding()]
|    param([array]$Data, [AllowEmptyString()][string]$DcrName, [AllowEmptyString()][string]$DceName, [string]$TableName,
|          [string]$BatchAmount, [bool]$EnableUploadViaLogHub, [string]$LogHubPath,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation, [string]$TenantId,
|          [Nullable[bool]]$EnableCompression, [Nullable[bool]]$UseManagedIdentity, [string]$ManagedIdentityClientId)
|    $out = Send-SILogDataRest @PSBoundParameters
|    # Columns added to this rule earlier in the run: check that Log Analytics really stores their values.
|    Confirm-SILogNewColumns -DcrName $DcrName -TableName $TableName -Data $Data -Bound $PSBoundParameters
|    $out
|}
|
|function Add-SICollectionTime {
|    [CmdletBinding()]
|    param([Array]$Data)
|    return (Add-SICollectionTimeRest @PSBoundParameters)
|}
|
|function Add-SIColumnData {
|    [CmdletBinding()]
|    param([Array]$Data, [string]$Column1Name, [string]$Column1Data, [string]$Column2Name, [string]$Column2Data, [string]$Column3Name, [string]$Column3Data)
|    return (Add-SIColumnDataRest @PSBoundParameters)
|}
|
|function Repair-SILogColumnName {
|    [CmdletBinding()]
|    param([Array]$Data)
|    return (Repair-SILogColumnNameRest @PSBoundParameters)
|}
|
|function Format-SILogRowsToSchema {
|    [CmdletBinding()]
|    param([Array]$Data)
|    return (Format-SILogRowsToSchemaRest @PSBoundParameters)
|}
|
|function Get-SILogSchemaArray {
|    [CmdletBinding()]
|    param([Array]$Data, [string[]]$ReturnType)
|    return (Get-SILogSchemaRest -As Array @PSBoundParameters)
|}
|
|function Get-SILogSchemaHash {
|    [CmdletBinding()]
|    param([Array]$Data, [string[]]$ReturnType)
|    return (Get-SILogSchemaRest -As Hash @PSBoundParameters)
|}
|
|function Test-SILogTableDcrStatus {
|    [CmdletBinding()]
|    param([string]$AzLogWorkspaceResourceId, [string]$TableName, [string]$DcrName, [array]$SchemaSourceObject,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    return (Test-SILogTableDcrStatusRest @PSBoundParameters)
|}
|
|function Set-SILogTable {
|    [CmdletBinding()]
|    param([string]$TableName, [array]$SchemaSourceObject, [string]$AzLogWorkspaceResourceId, [string]$SchemaMode,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    return (Set-SILogTableRest @PSBoundParameters)
|}
|
|function Set-SILogDcr {
|    [CmdletBinding()]
|    param([array]$SchemaSourceObject, [string]$AzLogWorkspaceResourceId, [string]$DceName, [string]$DcrResourceGroup, [string]$DcrName, [string]$TableName,
|          [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel, [AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [string]$SchemaMode,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation,
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    $watch = Start-SILogDcrWatch -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -WorkspaceResourceId $AzLogWorkspaceResourceId -Bound $PSBoundParameters
|    $out = Set-SILogDcrRest @PSBoundParameters
|    Complete-SILogDcrWatch -Watch $watch
|    $out
|}
|
|# =====================================================================================================================
|#  A RULE IS NEVER REPURPOSED, AND NEW COLUMNS ARE CHECKED -- both engines (these run around the wrappers above)
|#
|#  1. A data collection rule that already feeds ANOTHER table is never changed to feed this one. Measured in the 2.2 ->
|#     3.0 upgrade test: a setup-written 2.2 config named its public-IP rule 'dcr-si-publicip-profile' (feeding the 2.2
|#     public-IP table); 3.0's own default uses the same name for its new table, and the module REWROTE the rule -- the
|#     old flow was gone and the first post failed. Start-SILogDcrWatch refuses before anything is written.
|#  2. Columns added to an EXISTING rule land empty for a while: Azure accepts the post, but drops the new columns'
|#     values until the change has reached the ingestion pipeline (measured: the first 3.0 run after the upgrade wrote
|#     SI_AssetName / SI_AssetId empty on 134 of 134 rows; empty again 4 and 18 minutes after a column was added; filled
|#     hours later). The rule shows the new column at once, so the rule itself is no signal. Complete-SILogDcrWatch
|#     notes what was added; Confirm-SILogNewColumns, after the post, asks Log Analytics whether this run's values were
|#     STORED, and when they were not, the run says so and records it (Get-SILogIngestNotes -> the run's outcome is
|#     success-partial, so nothing downstream reads the snapshot as whole).
|#  Every read here is best effort: a rule that cannot be read is never a reason to stop a publish -- only a rule that IS
|#  read and feeds another table is.
|# =====================================================================================================================
|
|function Get-SILogDcrStreams {
|    <# PURE. The streams an existing rule writes: each data flow's outputStream, else the flow's streams; a rule with
|       no data flows -> its declared streams. #>
|    param([AllowNull()]$Dcr)
|    $out = New-Object System.Collections.Generic.List[string]
|    if ($null -eq $Dcr -or $null -eq $Dcr.properties) { return @() }
|    foreach ($f in @($Dcr.properties.dataFlows)) {
|        if ($null -eq $f) { continue }
|        $names = if ($f.PSObject.Properties['outputStream'] -and $f.outputStream) { @([string]$f.outputStream) } else { @(@($f.streams) | ForEach-Object { [string]$_ }) }
|        foreach ($n in $names) { if ($n -and -not $out.Contains($n)) { [void]$out.Add($n) } }
|    }
|    if ($out.Count -eq 0 -and $Dcr.properties.streamDeclarations) {
|        foreach ($p in $Dcr.properties.streamDeclarations.PSObject.Properties) { [void]$out.Add([string]$p.Name) }
|    }
|    return $out.ToArray()
|}
|
|function Test-SILogDcrFeedsOtherTable {
|    <# PURE. $true when the rule exists, writes at least one stream, and none of its streams is this table's. #>
|    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName)
|    $streams = @(Get-SILogDcrStreams -Dcr $Dcr)
|    if ($streams.Count -eq 0) { return $false }
|    $t = $TableName -replace '_CL$', ''
|    $mine = @(('Custom-' + $t + '_CL'), (Get-SILogStreamName -TableName $t))
|    foreach ($s in $streams) { if ($mine -contains $s) { return $false } }
|    return $true
|}
|
|function Get-SILogDcrStreamColumns {
|    <# PURE. The column names the rule declares for this table's stream (empty when it declares none). #>
|    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName)
|    if ($null -eq $Dcr -or $null -eq $Dcr.properties -or -not $Dcr.properties.streamDeclarations) { return @() }
|    $t = $TableName -replace '_CL$', ''
|    foreach ($s in @(('Custom-' + $t + '_CL'), (Get-SILogStreamName -TableName $t))) {
|        $p = $Dcr.properties.streamDeclarations.PSObject.Properties[$s]
|        if ($p) { return @(@($p.Value.columns) | Where-Object { $_ } | ForEach-Object { [string]$_.name }) }
|    }
|    return @()
|}
|
|function Get-SILogAddedColumns {
|    <# PURE. Columns in -After that -Before did not have. #>
|    param([AllowEmptyCollection()][string[]]$Before = @(), [AllowEmptyCollection()][string[]]$After = @())
|    return @(@($After) | Where-Object { $_ -and (@($Before) -notcontains $_) })
|}
|
|function Get-SILogAlternateDcrName {
|    <# PURE. A distinct, deterministic rule name for this install: '<name>-<resource group>', or '<name>-<8-character
|       hash of the resource group>' when that would pass 60 characters -- the rule the profilers' collision rename
|       already uses, so every run derives the same name. #>
|    param([Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][string]$ResourceGroup)
|    $rgClean = ($ResourceGroup -replace '[^a-zA-Z0-9-]', '-').ToLowerInvariant().Trim('-')
|    $name = "$DcrName-$rgClean"
|    if ($name.Length -gt 60) {
|        $sha = [System.Security.Cryptography.SHA1]::Create()
|        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ResourceGroup.ToLowerInvariant())) } finally { $sha.Dispose() }
|        $name = "$DcrName-" + (([BitConverter]::ToString($h) -replace '-', '').Substring(0, 8).ToLowerInvariant())
|    }
|    return $name
|}
|
|function Get-SILogDcrRepurposeMessage {
|    <# The one sentence a refused rule produces. #>
|    param([string]$DcrName, [string]$ResourceGroup, [string[]]$Streams, [string]$TableName)
|    $feeds = (@($Streams) | ForEach-Object { $_ -replace '^Custom-', '' }) -join ', '
|    ("The data collection rule '{0}' (resource group '{1}') already sends data to {2}. It is left unchanged -- changing it to send {3}_CL would stop the data it carries now. Give {3}_CL a rule of its own: set this table's data collection rule name in config\SecurityInsight.custom.ps1 to a new name (it is created automatically)." -f `
|        $DcrName, $ResourceGroup, $feeds, ($TableName -replace '_CL$', ''))
|}
|
|function Get-SILogDcrState {
|    <#
|        The rule as Azure has it NOW (never from the run cache): Known = $false when it cannot be read (no subscription /
|        resource group configured, or the read failed); else Dcr = the rule, or $null when it does not exist.
|    #>
|    param([string]$DcrName, [string]$DcrResourceGroup, [string]$WorkspaceResourceId, $Bound)
|    $scope = Get-SILogIngestScope -WorkspaceResourceId $WorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
|    if (-not $DcrName -or -not $scope.Subscription -or -not $scope.DcrRg) { return [pscustomobject]@{ Known = $false; Dcr = $null; ResourceGroup = $scope.DcrRg } }
|    try {
|        $auth = Resolve-SILogIngestAuth -Bound $Bound
|        $d = Invoke-SILogArm -Path "/subscriptions/$($scope.Subscription)/resourceGroups/$($scope.DcrRg)/providers/Microsoft.Insights/dataCollectionRules/$DcrName" `
|                 -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -AllowNotFound -NoCache
|        return [pscustomobject]@{ Known = $true; Dcr = $d; ResourceGroup = $scope.DcrRg }
|    } catch {
|        Write-Verbose ("data collection rule '{0}' could not be read before the update: {1}" -f $DcrName, $_.Exception.Message)
|        return [pscustomobject]@{ Known = $false; Dcr = $null; ResourceGroup = $scope.DcrRg }
|    }
|}
|
|function Resolve-SILogDcrNameForTable {
|    <#
|        The rule name this table should post through: -DcrName, unless that rule exists and feeds ANOTHER table -- then
|        Get-SILogAlternateDcrName (when that one is free or already this table's). When the alternate is taken too, the
|        original name is returned and the wrapper refuses it with a clear message. Unknown (cannot be read) -> unchanged.
|        Returns Name + Reason (empty when unchanged).
|    #>
|    param([Parameter(Mandatory)][string]$DcrName, [string]$DcrResourceGroup, [Parameter(Mandatory)][string]$TableName, [string]$WorkspaceResourceId, $Bound)
|    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $Bound
|    if (-not $st.Known -or -not $st.Dcr -or -not (Test-SILogDcrFeedsOtherTable -Dcr $st.Dcr -TableName $TableName)) {
|        return [pscustomobject]@{ Name = $DcrName; Reason = '' }
|    }
|    $alt = Get-SILogAlternateDcrName -DcrName $DcrName -ResourceGroup ([string]$st.ResourceGroup)
|    $st2 = Get-SILogDcrState -DcrName $alt -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $Bound
|    if ($st2.Known -and $st2.Dcr -and (Test-SILogDcrFeedsOtherTable -Dcr $st2.Dcr -TableName $TableName)) {
|        return [pscustomobject]@{ Name = $DcrName; Reason = '' }
|    }
|    $feeds = (@(Get-SILogDcrStreams -Dcr $st.Dcr) | ForEach-Object { $_ -replace '^Custom-', '' }) -join ', '
|    [pscustomobject]@{
|        Name   = $alt
|        Reason = ("the data collection rule '{0}' already sends data to {1} and is left unchanged; {2}_CL uses its own rule '{3}'." -f $DcrName, $feeds, ($TableName -replace '_CL$', ''), $alt)
|    }
|}
|
|function Start-SILogDcrWatch {
|    <# Before a rule is created / updated: refuse a rule that feeds another table; remember the columns it declares. #>
|    param([string]$DcrName, [string]$DcrResourceGroup, [string]$TableName, [string]$WorkspaceResourceId, $Bound)
|    if (-not $DcrName -or -not $TableName) { return $null }
|    $b = @{}; if ($Bound) { foreach ($k in @($Bound.Keys)) { if ($k -notin 'Data', 'SchemaSourceObject') { $b[$k] = $Bound[$k] } } }
|    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
|    if (-not $st.Known) { return $null }
|    if ($st.Dcr -and (Test-SILogDcrFeedsOtherTable -Dcr $st.Dcr -TableName $TableName)) {
|        throw (Get-SILogDcrRepurposeMessage -DcrName $DcrName -ResourceGroup ([string]$st.ResourceGroup) -Streams @(Get-SILogDcrStreams -Dcr $st.Dcr) -TableName $TableName)
|    }
|    [pscustomobject]@{
|        DcrName = $DcrName; DcrResourceGroup = $DcrResourceGroup; TableName = ($TableName -replace '_CL$', ''); WorkspaceResourceId = $WorkspaceResourceId
|        Bound = $b; Existed = [bool]$st.Dcr; Before = @(Get-SILogDcrStreamColumns -Dcr $st.Dcr -TableName $TableName)
|    }
|}
|
|function Complete-SILogDcrWatch {
|    <# After the update: columns an EXISTING rule gained are noted for Confirm-SILogNewColumns. Never throws. #>
|    param($Watch)
|    if (-not $Watch -or -not $Watch.Existed) { return }
|    # The run-health record does not check itself: it is the record a check would report into.
|    if ($Watch.TableName -ieq 'SI_RunHealth') { return }
|    try {
|        $st = Get-SILogDcrState -DcrName $Watch.DcrName -DcrResourceGroup $Watch.DcrResourceGroup -WorkspaceResourceId $Watch.WorkspaceResourceId -Bound $Watch.Bound
|        if (-not $st.Known -or -not $st.Dcr) { return }
|        $added = @(Get-SILogAddedColumns -Before $Watch.Before -After @(Get-SILogDcrStreamColumns -Dcr $st.Dcr -TableName $Watch.TableName))
|        if ($added.Count -eq 0) { return }
|        if (-not ($global:SI_LogIngestNewColumns -is [hashtable])) { $global:SI_LogIngestNewColumns = @{} }
|        $key = $Watch.DcrName.ToLowerInvariant()
|        $ws = if ($Watch.WorkspaceResourceId) { $Watch.WorkspaceResourceId } else { [string]$global:SI_WorkspaceResourceId }
|        if ($global:SI_LogIngestNewColumns.ContainsKey($key)) {
|            $prev = $global:SI_LogIngestNewColumns[$key]
|            $added = @(@($prev.Columns) + @($added) | Select-Object -Unique)
|        }
|        $global:SI_LogIngestNewColumns[$key] = [pscustomobject]@{ Table = $Watch.TableName; Columns = $added; WorkspaceResourceId = $ws; AddedAt = [datetime]::UtcNow }
|    } catch { Write-Verbose ("new-column check skipped: {0}" -f $_.Exception.Message) }
|}
|
|function Get-SILogColumnsWithValues {
|    <# PURE. Of -Columns, those holding a non-empty value in at least one row (only those can be checked). #>
|    param([AllowEmptyCollection()][object[]]$Rows = @(), [AllowEmptyCollection()][string[]]$Columns = @())
|    $out = New-Object System.Collections.Generic.List[string]
|    foreach ($c in @($Columns)) {
|        foreach ($r in @($Rows)) {
|            if ($null -eq $r) { continue }
|            $v = if ($r -is [System.Collections.IDictionary]) { $r[$c] } elseif ($r.PSObject.Properties[$c]) { $r.$c } else { $null }
|            if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { [void]$out.Add($c); break }
|        }
|    }
|    return $out.ToArray()
|}
|
|function Get-SILogRowColumnNames {
|    <# PURE. Every column name the rows carry (first-seen order, TimeGenerated left out: Azure sets it). #>
|    param([AllowEmptyCollection()][object[]]$Rows = @())
|    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    $out = New-Object System.Collections.Generic.List[string]
|    foreach ($r in @($Rows)) {
|        if ($null -eq $r) { continue }
|        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys | ForEach-Object { [string]$_ }) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
|        foreach ($n in $names) { if ($n -and $n -ne 'TimeGenerated' -and $seen.Add($n)) { [void]$out.Add($n) } }
|    }
|    return $out.ToArray()
|}
|
|function Get-SILogRowsCollectionTime {
|    <# PURE. The run's CollectionTime from the first row that carries one, as UTC; $null when no row does. #>
|    param([AllowEmptyCollection()][object[]]$Rows = @())
|    foreach ($r in @($Rows)) {
|        if ($null -eq $r) { continue }
|        $v = if ($r -is [System.Collections.IDictionary]) { $r['CollectionTime'] } elseif ($r.PSObject.Properties['CollectionTime']) { $r.CollectionTime } else { $null }
|        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
|        if ($v -is [datetime]) { if ($v.Kind -eq [DateTimeKind]::Local) { return $v.ToUniversalTime() }; return [datetime]::SpecifyKind($v, [DateTimeKind]::Utc) }
|        $d = [datetime]::MinValue
|        $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
|        if ([datetime]::TryParse([string]$v, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
|    }
|    return $null
|}
|
|function Get-SILogColumnCheckKql {
|    <# PURE. Rows of this run in the table, and how many carry a value in each new column (C0, C1, ... in -Columns order). #>
|    param([Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string[]]$Columns, [AllowNull()]$CollectionTime, [AllowNull()]$PostedSince)
|    $t = ($TableName -replace '_CL$', '') -replace '[^A-Za-z0-9_]', ''
|    $agg = for ($i = 0; $i -lt $Columns.Count; $i++) {
|        'C{0} = countif(isnotempty(tostring(column_ifexists("{1}", ""))))' -f $i, ($Columns[$i] -replace '[^A-Za-z0-9_]', '')
|    }
|    $filter = if ($CollectionTime) {
|        $ct = ([datetime]$CollectionTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
|        "| where TimeGenerated > ago(2d)`n| where CollectionTime between (datetime($ct) - 2s .. datetime($ct) + 2s)"
|    } else {
|        $since = ([datetime]$PostedSince).ToUniversalTime().AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
|        "| where TimeGenerated >= datetime($since)"
|    }
|    "{0}_CL`n{1}`n| summarize Rows = count(), {2}" -f $t, $filter, ($agg -join ', ')
|}
|
|function Get-SILogColumnCheckVerdict {
|    <#
|        PURE. One result row of Get-SILogColumnCheckKql -> Verdict:
|          stored      -- rows arrived and every new column holds values
|          not-stored  -- rows arrived and a new column is empty on all of them (Missing names which)
|          not-landed  -- no row of this run is queryable yet
|    #>
|    param([AllowNull()]$Result, [Parameter(Mandatory)][string[]]$Columns)
|    $get = { param($n) if ($null -eq $Result) { 0 } elseif ($Result -is [System.Collections.IDictionary]) { [long]$Result[$n] } elseif ($Result.PSObject.Properties[$n]) { [long]$Result.$n } else { 0 } }
|    $rows = & $get 'Rows'
|    if ($rows -le 0) { return [pscustomobject]@{ Verdict = 'not-landed'; Rows = 0; Missing = @($Columns) } }
|    $missing = @(for ($i = 0; $i -lt $Columns.Count; $i++) { if ((& $get ('C' + $i)) -le 0) { $Columns[$i] } })
|    if ($missing.Count -gt 0) { return [pscustomobject]@{ Verdict = 'not-stored'; Rows = $rows; Missing = $missing } }
|    [pscustomobject]@{ Verdict = 'stored'; Rows = $rows; Missing = @() }
|}
|
|function Invoke-SILogLaQuery {
|    <# One Log Analytics query as the run's identity (the workspace's id read through ARM). Returns the first table's
|       rows as objects. Throws on failure. #>
|    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$Query, $Bound)
|    $auth = Resolve-SILogIngestAuth -Bound $Bound
|    $ws = Invoke-SILogArm -Path $WorkspaceResourceId -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth
|    $cid = if ($ws -and $ws.properties) { [string]$ws.properties.customerId } else { '' }
|    if (-not $cid) { throw 'the Log Analytics workspace id could not be read' }
|    $r = Invoke-SILogIngestRequest -Method POST -Uri ('https://api.loganalytics.io/v1/workspaces/{0}/query' -f $cid) -Body (@{ query = $Query } | ConvertTo-Json -Compress) `
|             -Resource 'https://api.loganalytics.io/' -Auth $auth -MaxAttempts 3 -What 'Log Analytics query'
|    $j = $r.Content | ConvertFrom-Json
|    $tbl = @($j.tables)[0]
|    if (-not $tbl) { return @() }
|    $names = @(@($tbl.columns) | ForEach-Object { [string]$_.name })
|    foreach ($row in @($tbl.rows)) {
|        $o = [ordered]@{}
|        for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = @($row)[$i] }
|        [pscustomobject]$o
|    }
|}
|
|function Wait-SILogColumnsStored {
|    <#
|        Asks Log Analytics, until this run's rows have arrived, whether the new columns hold their values. Polls at 30 s,
|        then 60 s, then every 120 s; stops as soon as the answer is known (stored, or every row arrived with a column
|        empty) or after -WindowSec (default 900: Azure's ingestion delay is normally seconds to a few minutes, so rows
|        that are still missing after 15 minutes are reported, not waited for). A query that fails ends the check.
|    #>
|    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string[]]$Columns,
|          [AllowNull()]$CollectionTime, [AllowNull()]$PostedSince, [int]$ExpectedRows = 1, $Bound, [int]$WindowSec = 0)
|    if ($WindowSec -le 0) { $WindowSec = 900; $o = 0; if ([int]::TryParse([string]$global:SI_LogIngest_NewColumnCheckSec, [ref]$o) -and $o -gt 0) { $WindowSec = $o } }
|    $kql = Get-SILogColumnCheckKql -TableName $TableName -Columns $Columns -CollectionTime $CollectionTime -PostedSince $PostedSince
|    $waited = 0; $step = 30
|    $last = [pscustomobject]@{ Verdict = 'not-landed'; Rows = 0; Missing = @($Columns) }
|    while ($true) {
|        Start-Sleep -Seconds $step
|        $waited += $step
|        try {
|            $res = @(Invoke-SILogLaQuery -WorkspaceResourceId $WorkspaceResourceId -Query $kql -Bound $Bound)
|            $last = Get-SILogColumnCheckVerdict -Result $(if ($res.Count) { $res[0] } else { $null }) -Columns $Columns
|        } catch {
|            $last = [pscustomobject]@{ Verdict = 'unverified'; Rows = 0; Missing = @($Columns); Detail = $_.Exception.Message }
|            break
|        }
|        if ($last.Verdict -eq 'stored') { break }
|        if ($last.Verdict -eq 'not-stored' -and $last.Rows -ge $ExpectedRows) { break }
|        if ($waited -ge $WindowSec) { break }
|        $step = [Math]::Min(120, $step * 2)
|    }
|    $last | Add-Member -NotePropertyName WaitedSec -NotePropertyValue $waited -Force
|    return $last
|}
|
|function Add-SILogIngestNote {
|    <# Something a publish could not deliver in full, for the run's outcome (Get-SIRunOutcome). #>
|    # -Kind 'column-lag' (#414): only NEW, non-key columns were not stored yet (Azure's propagation delay) -- the rows and
|    # their key columns are there, so a Risk Analysis run says it as a warning and is NOT partial for it.
|    param([Parameter(Mandatory)][string]$Table, [string[]]$Columns = @(), [Parameter(Mandatory)][string]$Message, [string]$Kind = 'incomplete')
|    if (-not ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]])) { $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object] }
|    [void]$global:SI_LogIngestNotes.Add([pscustomobject]@{ Table = $Table; Columns = @($Columns); Message = $Message; Kind = $Kind })
|}
|
|function Get-SILogIngestNoteKind {
|    <#
|        PURE. 'column-lag' when a 'not-stored' verdict misses only non-key columns; else 'incomplete'.
|        #414 / #294: the KEY columns are the ones a row cannot be placed or read without. A new key column that was not
|        stored is a real loss (the data sync refuses such rows); any other new column not stored yet is propagation lag.
|    #>
|    param([string]$Verdict, [string[]]$Missing = @())
|    $keys = @('CollectionTime', 'ConfigurationId', 'AssetId', 'AssetName', 'ReportName', 'SecuritySeverity', 'CriticalityTier', 'RiskScoreTotal', 'SolutionVersion')
|    if ($Verdict -ne 'not-stored' -or -not @($Missing).Count) { return 'incomplete' }
|    foreach ($m in @($Missing)) { if ($keys -contains ([string]$m).Trim()) { return 'incomplete' } }
|    'column-lag'
|}
|
|function Get-SILogIngestNotes {
|    if ($global:SI_LogIngestNotes -is [System.Collections.Generic.List[object]]) { return $global:SI_LogIngestNotes.ToArray() }
|    return @()
|}
|
|function Reset-SILogIngestNotes {
|    <# At the start of a run: notes and pending column checks belong to ONE run. #>
|    $global:SI_LogIngestNotes = New-Object System.Collections.Generic.List[object]
|    $global:SI_LogIngestNewColumns = @{}
|}
|
|function Confirm-SILogNewColumns {
|    <#
|        After a post through a rule that gained columns earlier in this run: were this run's values for them STORED?
|        Not stored (or not confirmable) -> one warning that says what is missing and that the next run fills it, and a
|        note that makes the run's outcome success-partial. Never throws: the rows themselves were posted.
|    #>
|    param([string]$DcrName, [string]$TableName, [AllowNull()][array]$Data, $Bound)
|    if (-not $DcrName -or -not ($global:SI_LogIngestNewColumns -is [hashtable])) { return }
|    $key = $DcrName.ToLowerInvariant()
|    if (-not $global:SI_LogIngestNewColumns.ContainsKey($key)) { return }
|    $chg = $global:SI_LogIngestNewColumns[$key]
|    $global:SI_LogIngestNewColumns.Remove($key)
|    $table = if ($TableName) { $TableName -replace '_CL$', '' } else { [string]$chg.Table }
|    try {
|        $rows = @($Data)
|        $newCols = @(Get-SILogColumnsWithValues -Rows $rows -Columns @($chg.Columns))
|        # ring 1, 2026-10-11 -- a rule CHANGED right before the post can drop values of columns it had already (added by an
|        # earlier run or job inside Azure's propagation window), not only of the columns this run added. So once this run
|        # changed the rule, EVERY column that carries a value in the posted rows is checked; the new ones first.
|        $cols = @(Get-SILogColumnsWithValues -Rows $rows -Columns @(@($newCols) + @(Get-SILogRowColumnNames -Rows $rows) | Select-Object -Unique))
|        if ($newCols.Count -eq 0 -or $cols.Count -eq 0) { return }
|        # #475: the wait (half a minute or more) is spent ONCE per table per process -- a run that posts its records in
|        # dozens of batches gained new columns batch after batch and waited every time (customer H 2026-10-09)
|        $rcache = Get-SILogIngestRunCache
|        if (-not ($rcache.ConfirmedTables -is [hashtable])) { $rcache.ConfirmedTables = @{} }
|        $tk = $table.ToLowerInvariant()
|        if ($rcache.ConfirmedTables.ContainsKey($tk)) {
|            Write-Host (" [INFO] {0}_CL gained {1} more new column(s) ({2}); this run checked the table's new columns once already, so these are not waited for -- the next run stores them in any case." -f $table, $newCols.Count, ($newCols -join ', '))
|            return
|        }
|        $rcache.ConfirmedTables[$tk] = $true
|        $b = @{}; if ($Bound) { foreach ($k in @($Bound.Keys)) { if ($k -ne 'Data') { $b[$k] = $Bound[$k] } } }
|        Write-Host (" [INFO] {0}_CL gained {1} new column(s) in this run ({2}). Azure takes a while to start storing a new column, so this run checks that the values of every column it posted ({3}) arrived ..." -f $table, $newCols.Count, ($newCols -join ', '), $cols.Count)
|        $res = Wait-SILogColumnsStored -WorkspaceResourceId ([string]$chg.WorkspaceResourceId) -TableName $table -Columns $cols `
|                   -CollectionTime (Get-SILogRowsCollectionTime -Rows $rows) -PostedSince ([datetime]::UtcNow.AddSeconds(-60)) -ExpectedRows $rows.Count -Bound $b
|        if ($res.Verdict -eq 'stored') {
|            Write-Host (" [OK]   {0}_CL: the new column(s) hold this run's values." -f $table)
|            return
|        }
|        $msg = switch ($res.Verdict) {
|            'not-stored' { "{0}_CL: the data collection rule was changed in this run and Azure was not yet storing every column when the rows arrived: this run's values for {1} are missing. The rows are there; the next run stores these columns." -f $table, (@($res.Missing) -join ', ') }
|            'not-landed' { "{0}_CL gained new column(s) in this run ({1}) and this run's rows were not queryable within {2} minutes, so it is not known whether those columns were stored." -f $table, ($cols -join ', '), [int]($res.WaitedSec / 60) }
|            default      { "{0}_CL gained new column(s) in this run ({1}) and it could not be checked whether this run's values were stored ({2})." -f $table, ($cols -join ', '), $res.Detail }
|        }
|        Write-Warning $msg
|        # the run's outcome is judged on the columns this run ADDED (as before); a column the rule already had that read
|        # back empty is said (the warning above) but only ever counts as propagation lag
|        $missNew = @(@($res.Missing) | Where-Object { $newCols -contains $_ })
|        $kind = 'column-lag'
|        if ([string]$res.Verdict -ne 'not-stored') { $kind = 'incomplete' }
|        elseif ($missNew.Count -gt 0) { $kind = Get-SILogIngestNoteKind -Verdict 'not-stored' -Missing $missNew }
|        Add-SILogIngestNote -Table $table -Columns $cols -Message $msg -Kind $kind
|    } catch {
|        $msg = ("{0}_CL gained new column(s) in this run and it could not be checked whether this run's values were stored ({1})." -f $table, $_.Exception.Message)
|        Write-Warning $msg
|        Add-SILogIngestNote -Table $table -Message $msg
|    }
|}
|
|# =====================================================================================================================
|#  THE RULE MUST DECLARE EVERY COLUMN OF THE DATA -- both engines (#294)
|#
|#  Azure stores only the columns a data collection rule DECLARES: every other value of a posted row is dropped, and the
|#  post still answers 204. Found live 2026-10-05 on ring 1: a Risk Analysis Detailed run posted 14,624 rows and only
|#  AssetName, AssetId, the report name and 8 more columns arrived -- CollectionTime, ConfigurationId, SecuritySeverity,
|#  CriticalityTier, RiskScoreTotal and SolutionVersion were EMPTY on every row, and the run logged SUCCESS. The chain:
|#    1. the run used the default rule name (its configuration had not reached the job), a rule that did not exist yet;
|#    2. AzLogDcrIngestPS creates a new rule in two steps -- first with the data's FIRST 11 columns, then with all of
|#       them. The second step was refused (InvalidTransformOutput: a column the data reads as an object, the existing
|#       table holds as text), so the rule was left with 11 columns;
|#    3. on the next run the module looked the rule up BY NAME across the tenant, found another install's same-named
|#       rule with every column, concluded nothing was missing, and the rows went through the 11-column rule.
|#  Set-SILogDcrRest stops step 2 (a new rule for an existing table is declared from the TABLE, with its
|#  types); Assert-SILogDcrCoversData stops step 3 for good: after every table/rule update it reads THE rule this install
|#  posts through (in the configured scope, never by name across the tenant), adds from the table any column of the data
|#  the rule does not declare, and REFUSES the post when a column of the data still is not declared.
|# =====================================================================================================================
|
|function Get-SILogBoundAuth {
|    <# The sign-in arguments of a wrapper call (what Set-SILogDcrRest / Resolve-SILogIngestAuth take), nothing else. #>
|    param($Bound)
|    $b = @{}
|    if ($null -eq $Bound) { return $b }
|    foreach ($k in 'AzAppId', 'AzAppSecret', 'AzAppCertificateThumbprint', 'AzAppCertificateStoreLocation', 'UseManagedIdentity', 'ManagedIdentityClientId', 'TenantId') {
|        if ($Bound.ContainsKey($k) -and $null -ne $Bound[$k] -and "$($Bound[$k])" -ne '') { $b[$k] = $Bound[$k] }
|    }
|    $b
|}
|
|function Get-SILogDataColumnNames {
|    <#
|        PURE. The columns a set of rows carries: the union over EVERY row (first-seen order, names compared without
|        letter case), without TimeGenerated and Log Analytics' own standard columns, and only names a Log Analytics
|        column can have (a name the ingest path drops before posting is not a column of the posted data).
|    #>
|    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows = @())
|    $std = @('TimeGenerated', 'TenantId', 'Type', '_ResourceId', '_SubscriptionId', 'SourceSystem', 'MG', 'ManagementGroupName', '_BilledSize', '_IsBillable', '_ItemId', '_TimeReceived')
|    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    $out = New-Object System.Collections.Generic.List[string]
|    foreach ($r in @($Rows)) {
|        if ($null -eq $r) { continue }
|        $names = if ($r -is [System.Collections.IDictionary]) { @($r.Keys) } else { @($r.PSObject.Properties | ForEach-Object { $_.Name }) }
|        foreach ($n in $names) {
|            $s = [string]$n
|            if (-not $s -or $s -notmatch '^[A-Za-z][A-Za-z0-9_]*$' -or ($std -contains $s)) { continue }
|            if ($s.Length -gt 45) { $s = $s.Substring(0, 45) }   # the column name repair cuts a longer name to 45
|            if ($seen.Add($s)) { [void]$out.Add($s) }
|        }
|    }
|    return $out.ToArray()
|}
|
|function Get-SILogNewRuleColumns {
|    <#
|        PURE. The stream declaration of a NEW rule: the table's columns with the table's types when the table exists (then
|        each column of -SchemaSourceObject the table does not have, with its own type); else -SchemaSourceObject.
|        TimeGenerated is never declared (the rule's transform sets it).
|    #>
|    param([AllowNull()]$Table, [AllowNull()][AllowEmptyCollection()][object[]]$SchemaSourceObject = @())
|    $out = New-Object System.Collections.Generic.List[object]
|    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    $add = { param($n, $t) $s = [string]$n; if ($s -and $s -ne 'TimeGenerated' -and $seen.Add($s)) { [void]$out.Add([ordered]@{ name = $s; type = [string]$t }) } }
|    if ($null -ne $Table -and $Table.properties -and $Table.properties.schema) {
|        foreach ($c in @($Table.properties.schema.columns)) { if ($c) { & $add $c.name $c.type } }
|    }
|    foreach ($c in @($SchemaSourceObject)) { if ($c) { & $add $c.name $c.type } }
|    return $out.ToArray()
|}
|
|function Get-SILogDcrCoverageGap {
|    <#
|        PURE. Which of -Columns the rule does NOT declare for this table's stream: Missing (all of them), InTable (those
|        the table has -- the rule can be given them from the table) and NotInTable (those the table does not have).
|    #>
|    param([AllowNull()]$Dcr, [Parameter(Mandatory)][string]$TableName, [AllowEmptyCollection()][string[]]$Columns = @(), [AllowNull()]$Table)
|    $declared = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    foreach ($n in @(Get-SILogDcrStreamColumns -Dcr $Dcr -TableName $TableName)) { [void]$declared.Add([string]$n) }
|    $inTable = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    if ($null -ne $Table -and $Table.properties -and $Table.properties.schema) {
|        foreach ($c in @($Table.properties.schema.columns)) { if ($c) { [void]$inTable.Add([string]$c.name) } }
|    }
|    $missing = @(@($Columns) | Where-Object { $_ -and -not $declared.Contains([string]$_) })
|    [pscustomobject]@{
|        Missing    = $missing
|        InTable    = @($missing | Where-Object { $inTable.Contains([string]$_) })
|        NotInTable = @($missing | Where-Object { -not $inTable.Contains([string]$_) })
|    }
|}
|
|function Assert-SILogDcrCoversData {
|    <#
|        After a table/rule update: THE rule this install posts through (read in the configured scope) must declare every
|        column of -Data. Columns it lacks that the table has are added from the table (Set-SILogDcrRest, additive); a
|        column still not declared after that REFUSES the post -- throws System.IO.InvalidDataException, because Azure
|        would store the rows without it and answer success. Columns the TABLE does not have either are said and noted
|        (the run is partial), not refused: the table update is what failed there, and it says so itself.
|        Nothing is checked when schema management is off for this machine (the same rule the module applies) or the
|        rule cannot be read (said with -Verbose; Known = $false). Returns @{ Verdict; Added; Missing }.
|    #>
|    param([string]$DcrName, [string]$DcrResourceGroup, [string]$TableName, [string]$WorkspaceResourceId, [string]$DceName, [AllowNull()][array]$Data, $Bound)
|    $res = [pscustomobject]@{ Verdict = 'skipped'; Added = @(); Missing = @() }
|    if (-not $DcrName -or -not $TableName) { return $res }
|    if ($Bound) {
|        if ($Bound.ContainsKey('EnableUploadViaLogHub') -and [bool]$Bound['EnableUploadViaLogHub']) { return $res }
|        if ($Bound.ContainsKey('AzLogDcrTableCreateFromAnyMachine') -and -not [bool]$Bound['AzLogDcrTableCreateFromAnyMachine']) {
|            $ref = if ($Bound.ContainsKey('AzLogDcrTableCreateFromReferenceMachine')) { @($Bound['AzLogDcrTableCreateFromReferenceMachine']) } else { @() }
|            if (-not ($env:COMPUTERNAME -and ($ref -contains $env:COMPUTERNAME))) { return $res }
|        }
|    }
|    $cols = @(Get-SILogDataColumnNames -Rows @($Data))
|    if (-not $cols.Count) { return $res }
|    $t = $TableName -replace '_CL$', ''
|    $b = Get-SILogBoundAuth -Bound $Bound
|    $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
|    if (-not $st.Known) { $res.Verdict = 'unknown'; Write-Verbose ("data collection rule '{0}' could not be read -- its columns are not checked" -f $DcrName); return $res }
|    if (-not $st.Dcr) {
|        throw (New-Object System.IO.InvalidDataException(("The data collection rule '{0}' does not exist in resource group '{1}' after the table and rule update, so nothing is posted to {2}_CL." -f $DcrName, $st.ResourceGroup, $t)))
|    }
|    $auth = Resolve-SILogIngestAuth -Bound $b
|    $readTable = { try { Get-SILogTableRest -WorkspaceResourceId $WorkspaceResourceId -TableName $t -Auth $auth -NoCache } catch { $null } }
|    $table = & $readTable
|    $gap = Get-SILogDcrCoverageGap -Dcr $st.Dcr -TableName $t -Columns $cols -Table $table
|    if (-not @($gap.Missing).Count) { $res.Verdict = 'covered'; return $res }
|    if (@($gap.InTable).Count) {
|        Write-Host (" [WARN] the data collection rule '{0}' does not declare {1} column(s) of {2}_CL that this data carries ({3}) -- Azure would drop their values. Adding them to the rule from the table." -f `
|            $DcrName, @($gap.InTable).Count, $t, ((@($gap.InTable) | Select-Object -First 12) -join ', ')) -ForegroundColor Yellow
|        $null = Set-SILogDcrRest -SchemaSourceObject @(@($gap.InTable) | ForEach-Object { @{ name = [string]$_; type = 'string' } }) -AzLogWorkspaceResourceId $WorkspaceResourceId `
|                    -DceName $DceName -DcrResourceGroup ([string]$st.ResourceGroup) -DcrName $DcrName -TableName $t @b
|        $res.Added = @($gap.InTable)
|        $st = Get-SILogDcrState -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -WorkspaceResourceId $WorkspaceResourceId -Bound $b
|        $gap = Get-SILogDcrCoverageGap -Dcr $st.Dcr -TableName $t -Columns $cols -Table $table
|    }
|    $res.Missing = @($gap.Missing)
|    if (@($gap.InTable).Count) {
|        throw (New-Object System.IO.InvalidDataException(("The data collection rule '{0}' does not declare {1} column(s) of {2}_CL that this data carries ({3}) and they could not be added to it. Posting through it would store the rows WITHOUT those values, so nothing is posted." -f `
|            $DcrName, @($gap.InTable).Count, $t, ((@($gap.InTable) | Select-Object -First 20) -join ', '))))
|    }
|    if (@($gap.NotInTable).Count) {
|        $msg = ("{0}_CL does not have {1} column(s) this data carries ({2}), so their values are not stored by this run." -f $t, @($gap.NotInTable).Count, ((@($gap.NotInTable) | Select-Object -First 20) -join ', '))
|        Write-Warning $msg
|        Add-SILogIngestNote -Table $t -Columns @($gap.NotInTable) -Message $msg
|        $res.Verdict = 'partial'
|        return $res
|    }
|    $res.Verdict = 'repaired'
|    return $res
|}
|
|# =====================================================================================================================
|#  REST: run cache, HTTP seam, tokens
|# =====================================================================================================================
|
|function Get-SILogIngestRunCache {
|    <# Per-run (per-process) cache: tokens, ARM reads, DCR ids. Global because this file is dot-sourced at different
|       depths by different engines, and `$script:` would then be a different scope per caller. #>
|    if (-not ($global:SI_LogIngestRunCache -is [hashtable])) {
|        $global:SI_LogIngestRunCache = @{ Tokens = @{}; Arm = @{}; DcrIds = @{} }
|    }
|    return $global:SI_LogIngestRunCache
|}
|
|function Reset-SILogIngestArmCache {
|    <# After any create/update: the next read must see what was just written. #>
|    $c = Get-SILogIngestRunCache
|    $c.Arm = @{}
|}
|
|function Invoke-SILogIngestHttp {
|    <#
|        THE ONE HTTP SEAM. Every REST call in this file goes through here (tests Mock it). Never throws on an HTTP status:
|        returns @{ StatusCode; Content; RetryAfter }. A network failure (no response at all) is StatusCode 0.
|        HttpWebRequest, not Invoke-WebRequest: its error shape is the same on PS 5.1 and pwsh 7, so the body of a 4xx
|        and the Retry-After of a 429 are read the same way on both.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$Method,
|        [Parameter(Mandatory)][string]$Uri,
|        [hashtable]$Headers,
|        $Body,
|        [string]$ContentType,
|        [int]$TimeoutSec = 300
|    )
|    if ($PSVersionTable.PSEdition -ne 'Core') {
|        # Windows PowerShell 5.1 on an older .NET Framework may not offer TLS 1.2 by default; Azure requires it.
|        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
|    }
|    $req = [System.Net.HttpWebRequest]::Create($Uri)
|    $req.Method = $Method.ToUpperInvariant()
|    $req.Timeout = $TimeoutSec * 1000
|    $req.ReadWriteTimeout = $TimeoutSec * 1000
|    $req.Accept = 'application/json'
|    if ($Headers) {
|        foreach ($k in $Headers.Keys) {
|            if ($k -eq 'Content-Type') { $req.ContentType = [string]$Headers[$k] }
|            elseif ($k -eq 'Accept')   { $req.Accept = [string]$Headers[$k] }
|            else { $req.Headers[$k] = [string]$Headers[$k] }
|        }
|    }
|    if ($ContentType) { $req.ContentType = $ContentType }
|    if ($null -ne $Body) {
|        # statements, never `= if (...) { $Body }`: an if-expression enumerates a byte array into object[]
|        [byte[]]$bytes = $null
|        if ($Body -is [byte[]]) { $bytes = $Body } else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body) }
|        $req.ContentLength = $bytes.Length
|        $s = $req.GetRequestStream()
|        try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Close() }
|    } elseif ($req.Method -in 'POST', 'PUT', 'PATCH') {
|        $req.ContentLength = 0
|    }
|    $resp = $null
|    try { $resp = $req.GetResponse() }
|    catch {
|        $we = $_.Exception
|        while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
|        if ($we -and $we.Response) {
|            $resp = $we.Response
|            # An HTTP status is an answer returned to the caller, not an error of this process: take the caught record
|            # back out of $Error (setup shows every new entry -- each probe printed "(404) Not Found", 2026-10-06).
|            if ($global:Error.Count -gt 0 -and [object]::ReferenceEquals($global:Error[0], $_)) { $global:Error.RemoveAt(0) }
|        }
|        else { return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; RetryAfter = $null } }
|    }
|    try {
|        $text = ''
|        $rs = $resp.GetResponseStream()
|        if ($rs) { $sr = New-Object System.IO.StreamReader($rs); try { $text = $sr.ReadToEnd() } finally { $sr.Close() } }
|        return [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Content = $text; RetryAfter = [string]$resp.Headers['Retry-After'] }
|    } finally { $resp.Close() }
|}
|
|function Initialize-SILogIngestAuthHelpers {
|    <# The managed-identity and certificate token helpers live in auth/. Loaded on first need, never at file load. #>
|    # Only what is MISSING is loaded, and only that is published to the global scope (it was dot-sourced inside this
|    # function, so it would vanish on return). Something already visible -- the engine's own copy, a test's mock -- is
|    # never replaced.
|    $authDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth'
|    # The managed-identity helper is NOT loaded here: the run's entry point loads it (the launcher config on a VM / Arc
|    # server, the container entry in a job) -- an engine never does (SIv3-ContainerIdentity). Get-SILogIngestToken
|    # says so when it is missing.
|    $want = @(
|        @{ File = 'Find-SICertificate.ps1'; Fns = @('Get-SICertificateClientToken', 'Get-SICertificateFromStore', 'Test-SICertDriveAvailable') }
|    )
|    foreach ($w in $want) {
|        $missing = @($w.Fns | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
|        if ($missing.Count -eq 0) { continue }
|        $p = Join-Path $authDir $w.File
|        if (-not (Test-Path -LiteralPath $p)) { continue }
|        . $p
|        foreach ($n in $missing) {
|            $f = Get-Command -Name $n -CommandType Function -ErrorAction Ignore
|            if ($f) { Set-Item -Path ("function:global:{0}" -f $n) -Value $f.ScriptBlock }
|        }
|    }
|}
|
|function Resolve-SILogIngestAuth {
|    <#
|        The sign-in the call site handed over (the same splat AzLogDcrIngestPS takes), as one decision:
|          ManagedIdentity -- UseManagedIdentity = $true
|          Certificate     -- AzAppId + AzAppCertificateThumbprint + TenantId
|          Secret          -- AzAppId + AzAppSecret + TenantId
|          then the run's own decision: $global:SI_UseManagedIdentity (#222) -> ManagedIdentity, else the run's own
|          sign-in (Resolve-SIAzRestAuth: what Connect-SIAzAccount recorded, else the configured identity).
|        Same precedence as the module: managed identity, then certificate, then secret.
|    #>
|    param($Bound = @{})   # a hashtable or $PSBoundParameters
|    if ($null -eq $Bound) { $Bound = @{} }
|    $g = { param($k) if ($Bound.ContainsKey($k)) { $Bound[$k] } else { $null } }
|    $mi = & $g 'UseManagedIdentity'
|    if ($null -eq $mi -and $null -ne (Get-Variable -Scope Global -Name UseManagedIdentityDefault -ValueOnly -ErrorAction Ignore)) { $mi = (Get-Variable -Scope Global -Name UseManagedIdentityDefault -ValueOnly -ErrorAction Ignore) }
|    $app = [string](& $g 'AzAppId'); $tid = [string](& $g 'TenantId')
|    $thumb = [string](& $g 'AzAppCertificateThumbprint'); $sec = [string](& $g 'AzAppSecret')
|    if ([bool]$mi) {
|        $cid = [string](& $g 'ManagedIdentityClientId'); if (-not $cid) { $cid = [string](Get-Variable -Scope Global -Name SI_UAMI_ClientId -ValueOnly -ErrorAction Ignore) }
|        return @{ Mode = 'ManagedIdentity'; ClientId = $cid }
|    }
|    if ($app -and $thumb -and $tid) { return @{ Mode = 'Certificate'; AppId = $app; TenantId = $tid; Thumbprint = ($thumb -replace '\s', '') } }
|    if ($app -and $sec -and $tid)   { return @{ Mode = 'Secret'; AppId = $app; TenantId = $tid; Secret = $sec } }
|    if ((Get-Variable -Scope Global -Name SI_UseManagedIdentity -ValueOnly -ErrorAction Ignore) -eq $true) { return @{ Mode = 'ManagedIdentity'; ClientId = [string](Get-Variable -Scope Global -Name SI_UAMI_ClientId -ValueOnly -ErrorAction Ignore) } }
|    return @{ Mode = 'Run' }
|}
|
|function Get-SILogIngestToken {
|    <#
|        A bearer token for -Resource (https://monitor.azure.com/ for ingestion, https://management.azure.com/ for ARM),
|        as the identity -Auth (Resolve-SILogIngestAuth) names:
|          ManagedIdentity -- Get-SIManagedIdentityToken (container / Azure VM / Azure Arc endpoint; its own cache)
|          Certificate     -- Get-SICertificateClientToken (JWT client assertion signed from the X509Store; no Cert: drive)
|          Secret          -- client_credentials with the secret
|          Support         -- the Invardia support session's Get-InvardiaSupportToken (#524; SI-AzRest.ps1 Get-SISupportToken)
|          Run             -- the run's own sign-in (Resolve-SIAzRestAuth, over REST; #524: never an Azure session)
|        Cached per identity + resource until 5 minutes before expiry.
|    #>
|    param([Parameter(Mandatory)][string]$Resource, [hashtable]$Auth, [switch]$ForceRefresh)
|    # the supported token hook (see SI-AzRest.ps1): consulted first when set and no explicit sign-in was handed over
|    if (-not $Auth) {
|        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
|        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
|        $Auth = Resolve-SILogIngestAuth
|    }
|    $res = $Resource.TrimEnd('/') + '/'
|    # #524: the Invardia support session's tokens (Resolve-SIAzRestAuth's Mode 'Support') -- Invardia caches them; the
|    # tenant of each is checked against the one SI works in
|    if ($Auth.Mode -eq 'Support') { return (Get-SISupportToken -Resource $res -TenantId ([string]$Auth.TenantId) -ForceRefresh:$ForceRefresh) }
|    $cache = (Get-SILogIngestRunCache).Tokens
|    $who = switch ($Auth.Mode) { 'Certificate' { $Auth.AppId } 'Secret' { $Auth.AppId } 'ManagedIdentity' { $Auth.ClientId } default { '' } }
|    $key = '{0}|{1}|{2}' -f $Auth.Mode, $who, $res
|    if (-not $ForceRefresh -and $cache.ContainsKey($key) -and $cache[$key].ExpiresAt -gt [datetime]::UtcNow) { return $cache[$key].Token }
|
|    $token = $null; $expiresAt = [datetime]::UtcNow.AddMinutes(45)
|    # A TRANSIENT failure of the token endpoint (the managed-identity endpoint of a container, Entra) is waited out and asked
|    # again, a bounded number of times -- Microsoft's errors (Get-SITransientKind: throttled / timeout / unavailable). Any
|    # other answer (a refused sign-in, a missing certificate) fails at once, as before. The sweep of 2026-10-22: one
|    # IDENTITY_ENDPOINT blip threw through every helper's retry and failed the run.
|    if (-not (Get-Command -Name Get-SITransientKind -ErrorAction Ignore)) { . (Join-Path $PSScriptRoot 'SI-ErrorClass.ps1') }
|    $tokenAttempts = 4
|    for ($tokenTry = 1; $tokenTry -le $tokenAttempts; $tokenTry++) {
|    try {
|    switch ($Auth.Mode) {
|        'ManagedIdentity' {
|            if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction Ignore)) {
|                throw 'Sign-in as a managed identity was asked for, but the managed-identity sign-in helper is not loaded in this run (its entry point loads it: the launcher configuration or the container entry).'
|            }
|            $token = Get-SIManagedIdentityToken -Resource $res -ClientId ([string]$Auth.ClientId) -ForceRefresh:$ForceRefresh
|        }
|        'Certificate' {
|            Initialize-SILogIngestAuthHelpers
|            $token = Get-SICertificateClientToken -TenantId $Auth.TenantId -ClientId $Auth.AppId -Thumbprint $Auth.Thumbprint -Resource $res
|        }
|        'Secret' {
|            $body = 'client_id={0}&scope={1}&client_secret={2}&grant_type=client_credentials' -f `
|                [uri]::EscapeDataString($Auth.AppId), [uri]::EscapeDataString($res.TrimEnd('/') + '/.default'), [uri]::EscapeDataString($Auth.Secret)
|            $r = Invoke-SILogIngestHttp -Method POST -Uri ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $Auth.TenantId) `
|                     -Body $body -ContentType 'application/x-www-form-urlencoded'
|            if ([int]$r.StatusCode -lt 200 -or [int]$r.StatusCode -ge 300) {
|                throw ("Sign-in with the client secret failed for {0}. HTTP Status: {1} Response: {2}" -f $res, $r.StatusCode, $r.Content)
|            }
|            $j = $r.Content | ConvertFrom-Json
|            $token = [string]$j.access_token
|            $secs = 0
|            if ([int]::TryParse([string]$j.expires_in, [ref]$secs) -and $secs -gt 600) { $expiresAt = [datetime]::UtcNow.AddSeconds($secs - 300) }
|        }
|        default {
|            $t = Get-SIAzAccessToken -ResourceUrl $res -ErrorAction Stop
|            $token = if ($t.Token -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $t.Token).Password } else { [string]$t.Token }
|            try { if ($t.ExpiresOn) { $e = ([DateTimeOffset]$t.ExpiresOn).UtcDateTime.AddMinutes(-5); if ($e -lt $expiresAt) { $expiresAt = $e } } } catch { }
|        }
|    }
|    break
|    } catch {
|        $kind = Get-SITransientKind -Message ([string]$_.Exception.Message)
|        if ($kind -eq 'error' -or $tokenTry -ge $tokenAttempts) { throw }
|        $wait = Get-SILogIngestRetryDelay -RetryAfter '' -Attempt $tokenTry
|        Write-Verbose ("The token for {0} ({1} sign-in) was not issued ({2}: {3}) -- asked again in {4} s ({5}/{6})." -f $res, $Auth.Mode, $kind, $_.Exception.Message, $wait, $tokenTry, $tokenAttempts)
|        Start-Sleep -Seconds $wait
|    }
|    }
|    if ([string]::IsNullOrWhiteSpace($token)) { throw ("No access token for {0} ({1} sign-in)." -f $res, $Auth.Mode) }
|    $cache[$key] = @{ Token = $token; ExpiresAt = $expiresAt }
|    return $token
|}
|
|function Get-SILogIngestRetryDelay {
|    <# Seconds to wait before retry -Attempt: the server's Retry-After (seconds or an HTTP date) when it sent one,
|       else exponential (2, 4, 8 ... capped at 60). Never more than 10 minutes: a wait the server asks for had no upper
|       limit, and a run that waits says nothing meanwhile (the retry after it either works or is the answer). #>
|    param([string]$RetryAfter, [int]$Attempt)
|    $s = 0
|    if ($RetryAfter) {
|        if ([int]::TryParse($RetryAfter.Trim(), [ref]$s)) { return [Math]::Min(600, [Math]::Max(1, $s)) }
|        $d = [datetime]::MinValue
|        if ([datetime]::TryParse($RetryAfter, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
|            return [int][Math]::Min(600, [Math]::Max(1, [Math]::Ceiling(($d - [datetime]::UtcNow).TotalSeconds)))
|        }
|    }
|    return [int][Math]::Min(60, [Math]::Pow(2, $Attempt))
|}
|
|function Invoke-SILogIngestRequest {
|    <#
|        One authenticated REST call with the retry rule (CLAUDE.md working rule 4):
|          429 / 408 / 5xx / no response -> PLATFORM: wait (Retry-After when sent) and retry in-run
|          401 once                      -> the token is refreshed and the call repeated once
|          404 with -AllowNotFound       -> $null (a lookup that found nothing)
|          any other 4xx                 -> FAIL FAST, the response body in the error: re-sending an invalid request
|                                           burns time and fails identically
|        Returns the response object (StatusCode / Content).
|    #>
|    param(
|        [string]$Method = 'GET',
|        [Parameter(Mandatory)][string]$Uri,
|        $Body,
|        [string]$ContentType = 'application/json',
|        [hashtable]$Headers,
|        [string]$Resource = 'https://management.azure.com/',
|        [hashtable]$Auth,
|        [switch]$AllowNotFound,
|        [int]$MaxAttempts = 6,
|        [string]$What = 'Azure Resource Manager request'
|    )
|    $refreshed = $false; $forceNext = $false
|    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
|        $token = Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$forceNext
|        $forceNext = $false
|        $h = @{ 'Authorization' = ('Bearer ' + $token) }
|        if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
|        $r = Invoke-SILogIngestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType
|        $code = [int]$r.StatusCode
|        if ($code -ge 200 -and $code -lt 300) { return $r }
|        if ($code -eq 404 -and $AllowNotFound) { return $null }
|        if ($code -eq 401 -and -not $refreshed) { $refreshed = $true; $forceNext = $true; continue }
|        $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
|        if ($transient -and $attempt -lt $MaxAttempts) {
|            $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
|            Write-Verbose ("{0}: HTTP {1}, retrying in {2}s (attempt {3}/{4})" -f $What, $code, $wait, $attempt, $MaxAttempts)
|            # SAID, not only in the verbose stream (which the publish path switches off): a call that got no answer can
|            # have taken 5 minutes already, and six of them in a row were half an hour without one line in the run log
|            if ($code -eq 0 -or $wait -ge 30) {
|                Write-Host (" [INFO] {0}: {1} -- trying again in {2} second(s) (attempt {3} of {4})" -f $What, $(if ($code -eq 0) { 'no answer from Azure' } else { 'Azure answered HTTP {0}' -f $code }), $wait, $attempt, $MaxAttempts)
|            }
|            Start-Sleep -Seconds $wait
|            continue
|        }
|        throw ("{0} failed. HTTP Status: {1} Response: {2}" -f $What, $code, $r.Content)
|    }
|    throw ("{0} failed after {1} attempts." -f $What, $MaxAttempts)
|}
|
|# =====================================================================================================================
|#  REST: ARM reads/writes, scoped lookups
|# =====================================================================================================================
|
|function Get-SILogArmApiVersion {
|    <# ARM api-versions this file uses (a function, not a variable: the file is dot-sourced at different depths). #>
|    param([Parameter(Mandatory)][ValidateSet('Dce', 'Dcr', 'Table', 'Role')][string]$Kind)
|    switch ($Kind) { 'Dce' { '2022-06-01' } 'Dcr' { '2022-06-01' } 'Table' { '2022-10-01' } 'Role' { '2022-04-01' } }
|}
|
|function Invoke-SILogArm {
|    <# ARM call -> parsed JSON (or $null for a 404 with -AllowNotFound). GETs are cached per run; any write clears it. #>
|    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, $Body, [hashtable]$Auth, [switch]$AllowNotFound, [switch]$NoCache)
|    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path + $(if ($Path -match '\?') { '&' } else { '?' }) + 'api-version=' + $ApiVersion }
|    $cache = (Get-SILogIngestRunCache).Arm
|    if ($Method -eq 'GET' -and -not $NoCache -and $cache.ContainsKey($uri)) { return $cache[$uri] }
|    $json = if ($null -ne $Body -and -not ($Body -is [string])) { $Body | ConvertTo-Json -Depth 50 -Compress } else { $Body }
|    $r = Invoke-SILogIngestRequest -Method $Method -Uri $uri -Body $json -Auth $Auth -AllowNotFound:$AllowNotFound -What ('Azure Resource Manager {0} {1}' -f $Method, ($uri -replace '\?.*$', ''))
|    $obj = $null
|    if ($r -and -not [string]::IsNullOrWhiteSpace([string]$r.Content)) { $obj = $r.Content | ConvertFrom-Json }
|    if ($Method -eq 'GET') { if (-not $NoCache) { $cache[$uri] = $obj } } else { Reset-SILogIngestArmCache }
|    return $obj
|}
|
|function Get-SILogArmList {
|    <# Every item of an ARM list, following nextLink. #>
|    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ApiVersion, [hashtable]$Auth)
|    $items = New-Object 'System.Collections.Generic.List[object]'
|    $page = Invoke-SILogArm -Path $Path -ApiVersion $ApiVersion -Auth $Auth
|    while ($page) {
|        foreach ($v in @($page.value)) { if ($null -ne $v) { [void]$items.Add($v) } }
|        if ([string]::IsNullOrWhiteSpace([string]$page.nextLink)) { break }
|        $page = Invoke-SILogArm -Path ([string]$page.nextLink) -ApiVersion $ApiVersion -Auth $Auth
|    }
|    foreach ($i in $items) {
|        # the Resource Graph shape callers already read (subscriptionId / resourceGroup) -- ARM omits them
|        if ([string]$i.id -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)/') {
|            if (-not $i.PSObject.Properties['subscriptionId']) { $i | Add-Member -NotePropertyName subscriptionId -NotePropertyValue $Matches[1] }
|            if (-not $i.PSObject.Properties['resourceGroup'])  { $i | Add-Member -NotePropertyName resourceGroup -NotePropertyValue $Matches[2] }
|        }
|    }
|    return $items.ToArray()   # enumerated, like the module's list; callers wrap in @()
|}
|
|function Get-SILogIngestScope {
|    <#
|        WHERE this install's endpoint and rules live: subscription + resource groups. Lookups are by NAME within this
|        scope, never tenant-wide -- the same name exists in other environments (measured 2026-10-01: three endpoints
|        named dce-securityinsight in two subscriptions).
|          Subscription  -SubscriptionId, else -WorkspaceResourceId's, else SI_AzSubscriptionId, else SI_WorkspaceResourceId's,
|                        else the 2.2.x SubscriptionId (a new rule is created in the workspace's subscription, as the
|                        module did; SI_AzSubscriptionId is filled from the workspace by Initialize-SIIngestGlobals)
|          DcrRg         -DcrResourceGroup, else SI_DcrResourceGroup
|          DceRg         -DceResourceGroup, else SI_DceResourceGroup, else the DCR resource group
|    #>
|    param([string]$SubscriptionId, [string]$WorkspaceResourceId, [string]$DcrResourceGroup, [string]$DceResourceGroup)
|    $sub = $SubscriptionId
|    if (-not $sub -and $WorkspaceResourceId -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
|    if (-not $sub) { $sub = [string]$global:SI_AzSubscriptionId }
|    if (-not $sub -and "$($global:SI_WorkspaceResourceId)" -match '/subscriptions/([^/]+)/') { $sub = $Matches[1] }
|    if (-not $sub) { $sub = [string]$global:SubscriptionId }
|    $dcrRg = if ($DcrResourceGroup) { $DcrResourceGroup } else { [string]$global:SI_DcrResourceGroup }
|    $dceRg = if ($DceResourceGroup) { $DceResourceGroup } elseif ($global:SI_DceResourceGroup) { [string]$global:SI_DceResourceGroup } else { $dcrRg }
|    [pscustomobject]@{ Subscription = $sub; DcrRg = $dcrRg; DceRg = $dceRg }
|}
|
|function Get-SILogScopedList {
|    param([ValidateSet('Dce', 'Dcr')][string]$Kind, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth)
|    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
|        throw ("No subscription is configured for the data collection {0} lookup (SI_AzSubscriptionId / SI_WorkspaceResourceId). It is never read tenant-wide, because the same name exists in other environments." -f $(if ($Kind -eq 'Dce') { 'endpoint' } else { 'rule' }))
|    }
|    $type = if ($Kind -eq 'Dce') { 'dataCollectionEndpoints' } else { 'dataCollectionRules' }
|    $path = if ($ResourceGroup) { "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/$type" }
|            else { "/subscriptions/$SubscriptionId/providers/Microsoft.Insights/$type" }
|    return (Get-SILogArmList -Path $path -ApiVersion (Get-SILogArmApiVersion $Kind) -Auth $Auth)
|}
|
|function Get-SIDceListRest {
|    <# REST twin of Get-AzDceListAll -- but SCOPED: the configured subscription only (never tenant-wide). Same auth
|       arguments as the module; -SubscriptionId / -ResourceGroup narrow further. #>
|    [CmdletBinding()]
|    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup)
|    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
|    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId
|    return (Get-SILogScopedList -Kind Dce -SubscriptionId $scope.Subscription -ResourceGroup $ResourceGroup -Auth $auth)
|}
|
|function Get-SIDcrListRest {
|    <# REST twin of Get-AzDcrListAll -- scoped to the configured subscription, like Get-SIDceListRest. #>
|    [CmdletBinding()]
|    param([string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId, [string]$SubscriptionId, [string]$ResourceGroup)
|    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
|    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId
|    return (Get-SILogScopedList -Kind Dcr -SubscriptionId $scope.Subscription -ResourceGroup $ResourceGroup -Auth $auth)
|}
|
|function Find-SILogResourceByName {
|    <#
|        A DCR or DCE by NAME in the configured scope:
|          resource group known  -> exactly that resource (GET by its id); nothing else is considered
|          resource group absent -> the subscription's list; one match is used, several refuse (the name is ambiguous)
|        -AnyResourceGroupWhenMissing (endpoints only): not in the resource group, but exactly ONE of that name in the
|        subscription -> that one (an endpoint outside the rules' resource group has always worked); several refuse.
|        Returns $null when there is none.
|    #>
|    param([ValidateSet('Dce', 'Dcr')][string]$Kind, [Parameter(Mandatory)][string]$Name, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth, [switch]$AnyResourceGroupWhenMissing)
|    $label = if ($Kind -eq 'Dce') { 'data collection endpoint' } else { 'data collection rule' }
|    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { throw ("No subscription is configured to look up {0} '{1}' in (SI_AzSubscriptionId / SI_WorkspaceResourceId)." -f $label, $Name) }
|    $type = if ($Kind -eq 'Dce') { 'dataCollectionEndpoints' } else { 'dataCollectionRules' }
|    if ($ResourceGroup) {
|        $hit = Invoke-SILogArm -Path "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/$type/$Name" -ApiVersion (Get-SILogArmApiVersion $Kind) -Auth $Auth -AllowNotFound
|        if ($hit -or -not $AnyResourceGroupWhenMissing) { return $hit }
|    }
|    $same = @(Get-SILogScopedList -Kind $Kind -SubscriptionId $SubscriptionId -Auth $Auth | Where-Object { $_ -and $_.name -eq $Name })
|    if ($same.Count -eq 1) { return $same[0] }
|    if ($same.Count -gt 1) {
|        throw ("{0} '{1}' exists {2} times in subscription '{3}'{4}, so nothing was posted -- set the resource group this install uses ({5})." -f `
|            $label, $Name, $same.Count, $SubscriptionId, $(if ($ResourceGroup) { " (none in resource group '$ResourceGroup')" } else { '' }),
|            $(if ($Kind -eq 'Dce') { 'SI_DceResourceGroup' } else { 'SI_DcrResourceGroup' }))
|    }
|    return $null
|}
|
|# =====================================================================================================================
|#  REST: data shape -- exact twins of the module's pre-processing (so 'Rest' declares and posts the same columns)
|# =====================================================================================================================
|
|function Add-SICollectionTimeRest {
|    <#
|        CollectionTime on every row, IDENTICAL across all shards and batches of one run:
|          * a row that already carries a CollectionTime keeps it -- the engines stamp the run's own value upstream
|            ($RunContext.CollectionTime / $global:RA_CollectionTime), and that is the value every shard shares;
|          * a row without one gets this process's run value, minted once and reused by every later call.
|        Same value format as the module ([datetime] from "yyyy-MM-ddTHH:mm:ssK", UTC).
|        DIFFERS FROM THE MODULE ON PURPOSE: Add-CollectionTimeToAllEntriesInArray overwrites every row with the time
|        of THAT call, so a "safety net" call after the upstream stamp replaced the shared run value.
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data)
|    if (-not ($global:SI_LogIngestRunCollectionTime -is [datetime])) {
|        [datetime]$ct = (Get-Date ([datetime]::Now.ToUniversalTime()) -Format 'yyyy-MM-ddTHH:mm:ssK')
|        $global:SI_LogIngestRunCollectionTime = $ct
|    }
|    $out = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($e in $Data) {
|        $p = $e.PSObject.Properties['CollectionTime']
|        if (-not $p -or $null -eq $p.Value -or [string]::IsNullOrWhiteSpace([string]$p.Value)) {
|            $e | Add-Member -MemberType NoteProperty -Name CollectionTime -Value $global:SI_LogIngestRunCollectionTime -Force | Out-Null
|        }
|        [void]$out.Add($e)
|    }
|    return [array]$out.ToArray()
|}
|
|function Add-SIColumnDataRest {
|    <# Twin of Add-ColumnDataToAllEntriesInArray: up to three columns with one value each, on every row. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data, [Parameter(Mandatory)][string]$Column1Name, [Parameter(Mandatory)][AllowEmptyString()][string]$Column1Data,
|          [string]$Column2Name, [string]$Column2Data, [string]$Column3Name, [string]$Column3Data)
|    $out = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($e in $Data) {
|        if ($Column1Name) { $e | Add-Member -MemberType NoteProperty -Name $Column1Name -Value $Column1Data -Force }
|        if ($Column2Name) { $e | Add-Member -MemberType NoteProperty -Name $Column2Name -Value $Column2Data -Force }
|        if ($Column3Name) { $e | Add-Member -MemberType NoteProperty -Name $Column3Name -Value $Column3Data -Force }
|        [void]$out.Add($e)
|    }
|    return [array]$out.ToArray()
|}
|
|function Repair-SILogColumnNameRest {
|    <# Twin of ValidateFix-AzLogAnalyticsTableSchemaColumnNames (1.7.x): prohibited names get '_', ':' '-' '.' are
|       removed, leading '_' trimmed, leading whitespace trimmed, >45 characters cut; renamed columns move to the end
|       of the row with their own values. Rows are rebuilt only when a name needs fixing. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data)
|    $prohibited = @('_ResourceId', 'id', '_ResourceId', '_SubscriptionId', 'TenantId', 'Type', 'UniqueId', 'Title', 'Date')
|    $checked = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    $rename = @{}
|    foreach ($e in $Data) {
|        foreach ($p in $e.PSObject.Properties) {
|            $n = $p.Name
|            if (-not $checked.Add($n)) { continue }
|            if ($n -in $prohibited)     { $rename[$n] = $n + '_' }
|            elseif ($n -like '*:*')     { $rename[$n] = $n.Replace(':', '') }
|            elseif ($n -like '*-*')     { $rename[$n] = $n.Replace('-', '') }
|            elseif ($n -like '*.*')     { $rename[$n] = $n.Replace('.', '') }
|            elseif ($n -like '_*')      { $rename[$n] = $n.TrimStart('_') }
|            elseif ($n -like '* *')     { $rename[$n] = $n.TrimStart() }
|            elseif ($n.Length -gt 45)   { $rename[$n] = $n.Substring(0, 45) }
|        }
|    }
|    if ($rename.Count -eq 0) { return [array]$Data }
|    # #639: only a row that CARRIES a name to fix is rebuilt (a copy of that row); every other row is passed on as it is --
|    # never a copy of the whole post. (Not in place: the caller may still read the row by its own names.)
|    $out = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($row in $Data) {
|        $needs = $false
|        foreach ($p in $row.PSObject.Properties) { if ($rename.ContainsKey($p.Name)) { $needs = $true; break } }
|        if (-not $needs) { [void]$out.Add($row); continue }
|        $rebuilt = [ordered]@{}
|        $moved = New-Object 'System.Collections.Generic.List[object]'
|        foreach ($p in $row.PSObject.Properties) {
|            if ($rename.ContainsKey($p.Name)) { [void]$moved.Add($p) } else { $rebuilt[$p.Name] = $p.Value }
|        }
|        foreach ($p in $moved) { $rebuilt[[string]$rename[$p.Name]] = $p.Value }
|        [void]$out.Add([pscustomobject]$rebuilt)
|    }
|    return [array]$out.ToArray()
|}
|
|function Get-SILogSchemaRest {
|    <#
|        Twin of Get-ObjectSchemaAsArray (-As Array) and Get-ObjectSchemaAsHash (-As Hash): the column list of the
|        WHOLE set, each column's type from the first row that carries it, read the way the module reads it -- the row
|        is round-tripped through JSON and the type taken from Get-Member's definition:
|            int* / real* -> int    long* -> long    guid* -> dynamic    string* -> string    datetime* -> datetime
|            bool* -> boolean       object* / PSCustomObject -> dynamic
|        DIFFERENCES FROM THE MODULE (2026-10-11, both made Log Analytics discard values):
|          * a fractional number is `real` -- the module matched none of its patterns and INHERITED the type of the column
|            read just before it (alphabetically), which is how LastSignInDays became datetime;
|          * an empty (null) value does not decide the type: the first row with a value does, 'dynamic' if none has one.
|        KNOWN TRAP KEPT:
|          * 'int' vs 'long' follows the value's size in the first row that has the column.
|        -ReturnType Table adds TimeGenerated (datetime) first and a description per column; DCR (the default for Array)
|        has name + type only. -As Hash returns hashtables and, like the module, nothing without -ReturnType.
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data, [ValidateSet('Array', 'Hash')][string]$As = 'Array', [ValidateSet('Table', 'DCR')][string[]]$ReturnType)
|    $table = New-Object 'System.Collections.Generic.List[object]'
|    $dcr   = New-Object 'System.Collections.Generic.List[object]'
|    $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    [void]$seen.Add('TimeGenerated')
|    # the module's shapes: Array -> PSCustomObject, Hash -> plain hashtable
|    $mk = { param($n, $t, [switch]$Desc)
|        if ($As -eq 'Hash') { if ($Desc) { @{ name = $n; type = $t; description = '' } } else { @{ name = $n; type = $t } } }
|        elseif ($Desc) { [pscustomobject]@{ name = $n; type = $t; description = '' } }
|        else { [pscustomobject]@{ name = $n; type = $t } }
|    }
|    [void]$table.Add((& $mk 'TimeGenerated' 'datetime' -Desc))
|    # columns seen so far only EMPTY (null): typed from the first row that has a value, 'dynamic' when none has
|    $nullOnly = New-Object 'System.Collections.Generic.List[string]'
|    $nullSet  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    foreach ($entry in $Data) {
|        $hasNew = $false
|        foreach ($p in $entry.PSObject.Properties) { if (-not $seen.Contains($p.Name) -and ($null -ne $p.Value -or -not $nullSet.Contains($p.Name))) { $hasNew = $true; break } }
|        if (-not $hasNew) { continue }
|        $cols = $entry | ConvertTo-Json -Depth 100 | ConvertFrom-Json | Get-Member -MemberType NoteProperty
|        foreach ($c in $cols) {
|            if ($seen.Contains($c.Name)) { continue }
|            $d = [string]$c.Definition
|            # ring 1, 2026-10-11 -- THE TYPE IS DECIDED PER COLUMN, NEVER INHERITED. The module's mapping kept the previous
|            # column's type for a definition it did not know (a double), and Get-Member lists the columns alphabetically,
|            # so LastSignInDays (a double) was declared after LastSignInDateTime: datetime -- and every value of it was then
|            # discarded by Log Analytics. A fractional number is `real`; an empty value waits for a row that has one.
|            $objType = $null
|            if ($d -match '^(?i)(System\.)?Object\s') {   # a null value round-trips as "object <name>=null"
|                if ($nullSet.Add($c.Name)) { [void]$nullOnly.Add($c.Name) }
|                continue
|            }
|            if     ($d -like 'int*')      { $objType = 'int' }
|            elseif ($d -like 'real*')     { $objType = 'int' }
|            elseif ($d -like 'long*')     { $objType = 'long' }
|            elseif ($d -like 'double*' -or $d -like 'decimal*' -or $d -like 'float*' -or $d -like 'single*') { $objType = 'real' }
|            elseif ($d -like 'guid*')     { $objType = 'dynamic' }
|            elseif ($d -like 'string*')   { $objType = 'string' }
|            elseif ($d -like 'datetime*') { $objType = 'datetime' }
|            elseif ($d -like 'bool*')     { $objType = 'boolean' }
|            elseif ($d -like 'object*')   { $objType = 'dynamic' }
|            elseif ($d -like 'System.Management.Automation.PSCustomObject*') { $objType = 'dynamic' }
|            else { $objType = 'dynamic' }
|            [void]$seen.Add($c.Name)
|            [void]$table.Add((& $mk $c.Name $objType -Desc))
|            [void]$dcr.Add((& $mk $c.Name $objType))
|        }
|    }
|    foreach ($n in $nullOnly) {
|        if ($seen.Contains($n)) { continue }
|        [void]$seen.Add($n)
|        [void]$table.Add((& $mk $n 'dynamic' -Desc))
|        [void]$dcr.Add((& $mk $n 'dynamic'))
|    }
|    if ($ReturnType -eq 'Table') { return $table.ToArray() }
|    if ($ReturnType -eq 'DCR' -or $As -eq 'Array') { return $dcr.ToArray() }
|}
|
|function Format-SILogRowsToSchemaRest {
|    <# Twin of Build-DataArrayToAlignWithSchema (1.7.x): every row gets every schema column (missing = $null), in
|       schema order; a property the schema does not list (a literal TimeGenerated) is kept, after them.
|       #639: IN PLACE, never a padded copy of the whole post. A PSCustomObject row is aligned on itself (its properties
|       re-ordered, the missing ones added as $null) -- the same row, the same JSON as the copy made before; a row of another
|       kind (a hashtable, a compact .NET row) is replaced in the array by its aligned copy, one row at a time. The post
|       then serialises a batch at a time (Send-SILogDataRest), so nothing of the post is ever held twice. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data)
|    $schema = Get-SILogSchemaRest -Data $Data -As Array
|    if (@($Data).Count -eq 0) { return $Data }
|    $names = New-Object 'System.Collections.Generic.List[string]'
|    foreach ($c in $schema) { [void]$names.Add([string]$c.name) }
|    $nm = $names.ToArray()
|    for ($i = 0; $i -lt $Data.Count; $i++) { $Data[$i] = Format-SILogRowToNamesInPlace -Row $Data[$i] -Names $nm }
|    return $Data
|}
|
|function Format-SILogRowToNamesInPlace {
|    <# ONE row aligned to -Names (missing = $null, in that order, the other properties after them) -- the row itself when
|       it is a PSCustomObject (its properties re-ordered in place; nothing done when it already is aligned), else its
|       aligned copy (Format-SILogRowsToNames). The JSON of the result equals the JSON of Format-SILogRowsToNames. #>
|    param($Row, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
|    if ($null -eq $Row) { return $Row }
|    if ($Row.PSObject.BaseObject -isnot [System.Management.Automation.PSCustomObject]) {
|        return @(Format-SILogRowsToNames -Data @($Row) -Names $Names)[0]
|    }
|    $props = $Row.PSObject.Properties
|    # already aligned: the names first, in order, every one present -- nothing to do
|    $all = @($props)
|    $aligned = ($all.Count -ge $Names.Count)
|    if ($aligned) { for ($k = 0; $k -lt $Names.Count; $k++) { if ($all[$k].Name -cne $Names[$k] -or $all[$k] -isnot [System.Management.Automation.PSNoteProperty]) { $aligned = $false; break } } }
|    if ($aligned) { return $Row }
|    foreach ($p in $all) { if ($p -isnot [System.Management.Automation.PSNoteProperty]) { return @(Format-SILogRowsToNames -Data @($Row) -Names $Names)[0] } }
|    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
|    foreach ($n in $Names) { [void]$set.Add($n) }
|    # the values, then the properties rebuilt on the same object: the names in order, then the others as they were
|    $vals = @{}
|    $rest = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($p in $all) {
|        if ($set.Contains($p.Name)) { if (-not $vals.ContainsKey($p.Name)) { $vals[$p.Name] = $p } }
|        else { $rest.Add($p) }
|    }
|    foreach ($p in $all) { $props.Remove($p.Name) }
|    foreach ($n in $Names) {
|        $v = $null; if ($vals.ContainsKey($n)) { $v = $vals[$n].Value }
|        $props.Add([System.Management.Automation.PSNoteProperty]::new($n, $v))
|    }
|    foreach ($p in $rest) { $props.Add([System.Management.Automation.PSNoteProperty]::new($p.Name, $p.Value)) }
|    return $Row
|}
|
|function Format-SILogRowsToNames {
|    <# PURE. Format-SILogRowsToSchemaRest's second half: every row gets every column of -Names (missing = $null), in that
|       order; a property not in -Names is kept, after them. Each row on its own -- the names are the whole set's schema, read
|       before (Risk Analysis prepares the rows of one chunk on several cores with it, #744). #>
|    param([Parameter(Mandatory)][AllowEmptyCollection()][Array]$Data, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
|    $out = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($row in $Data) {
|        $props = $row.PSObject.Properties
|        $a = [ordered]@{}
|        foreach ($n in $Names) { $p = $props[$n]; if ($null -ne $p) { $a[$n] = $p.Value } else { $a[$n] = $null } }
|        foreach ($p in $props) { if (-not $a.Contains($p.Name)) { $a[$p.Name] = $p.Value } }
|        [void]$out.Add([pscustomobject]$a)
|    }
|    return $out.ToArray()
|}
|
|# =====================================================================================================================
|#  REST: table + DCR create / update -- ADDITIVE only
|# =====================================================================================================================
|
|function Get-SILogStreamName {
|    <# 'Custom-<table>_CL', cut to 52 characters (the stream name limit) -- the module's rule. #>
|    param([Parameter(Mandatory)][string]$TableName)
|    $s = 'Custom-' + $TableName + '_CL'
|    if ($s.Length -gt 52) { $s = $s.Substring(0, 52) }
|    return $s
|}
|
|function Get-SILogTableRest {
|    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [hashtable]$Auth, [switch]$NoCache)
|    return (Invoke-SILogArm -Path ($WorkspaceResourceId + '/tables/' + $TableName + '_CL') -ApiVersion (Get-SILogArmApiVersion Table) -Auth $Auth -AllowNotFound -NoCache:$NoCache)
|}
|
|function Resolve-SILogDcrForTable {
|    <# The rule this install posts through: the one recorded this run when it was created/updated, else by name in the
|       configured scope (Find-SILogResourceByName). #>
|    param([Parameter(Mandatory)][string]$DcrName, [string]$SubscriptionId, [string]$ResourceGroup, [hashtable]$Auth)
|    $ids = (Get-SILogIngestRunCache).DcrIds
|    $key = $DcrName.ToLowerInvariant()   # the rule created / updated / found THIS run, wherever the caller put it
|    if ($ids.ContainsKey($key)) {
|        $hit = Invoke-SILogArm -Path $ids[$key] -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $Auth -AllowNotFound
|        if ($hit) { return $hit }
|    }
|    return (Find-SILogResourceByName -Kind Dcr -Name $DcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Auth $Auth)
|}
|
|function Test-SILogTableDcrStatusRest {
|    <# Twin of Get-AzLogAnalyticsTableAzDataCollectionRuleStatus: $true when the table or the rule must be created or
|       given columns. The rule is looked up in the configured scope, not by name across the tenant. #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][string]$DcrName,
|          [Parameter(Mandatory)][array]$SchemaSourceObject, [string]$DcrResourceGroup,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
|    $scope = Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
|    $needs = $false
|    $t = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
|    $cols = @(); $std = @()
|    if (-not $t) { $needs = $true }
|    else {
|        $cols = @($t.properties.schema.columns); $std = @($t.properties.schema.standardColumns)
|        foreach ($e in $SchemaSourceObject) {
|            if (-not ($cols | Where-Object { $_.name -eq $e.name }) -and -not ($std | Where-Object { $_.name -eq $e.name })) { $needs = $true }
|        }
|    }
|    $dcr = Resolve-SILogDcrForTable -DcrName $DcrName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DcrRg -Auth $auth
|    if (-not $dcr) { return $true }
|    (Get-SILogIngestRunCache).DcrIds[$DcrName.ToLowerInvariant()] = [string]$dcr.id   # the post uses THIS rule
|    $stream = Get-SILogStreamName -TableName $TableName
|    $dcrCols = @()
|    if ($dcr.properties.streamDeclarations -and $dcr.properties.streamDeclarations.PSObject.Properties[$stream]) { $dcrCols = @($dcr.properties.streamDeclarations.$stream.columns) }
|    $tableCols = @($cols | Where-Object { $_.name -ne 'TimeGenerated' })
|    if ($dcrCols.Count -lt $tableCols.Count) { return $true }
|    foreach ($c in $tableCols) { if (-not ($dcrCols | Where-Object { $_.name -eq $c.name })) { $needs = $true } }
|    return $needs
|}
|
|function Set-SILogTableRest {
|    <#
|        Twin of CreateUpdate-AzLogAnalyticsCustomLogTableDcr, ADDITIVE ONLY:
|          no table   -> PUT it with the schema of the data (TimeGenerated + every column)
|          table      -> the columns it does not have yet are added (PATCH: retention and plan are left as they are); an
|                        existing column is never changed or removed, whatever type the data now suggests
|        A refused write FAILS with Azure's answer. The module's fallback -- DELETE the table and re-create it -- is not
|        copied: it discards data.
|        -SchemaSourceObject: the Table-format schema (Get-SILogSchemaRest -ReturnType Table / Get-ObjectSchemaAsHash).
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$TableName, [Parameter(Mandatory)][array]$SchemaSourceObject, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId,
|          [string]$SchemaMode = 'Merge',
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
|    $table = $TableName + '_CL'
|    if ($table.Length -gt 45) { Write-Error ("ERROR - Reduce length of tablename, as it has a maximum of 45 characters (current length: {0})" -f $table.Length) }
|    $path = $AzLogWorkspaceResourceId + '/tables/' + $table
|    $cur = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
|    $toCol = { param($c) [ordered]@{ name = [string]$c.name; type = [string]$c.type; description = '' } }
|    if (-not $cur) {
|        $columns = @($SchemaSourceObject | ForEach-Object { & $toCol $_ })
|        $null = Invoke-SILogArm -Method PUT -Path $path -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth -Body @{ properties = @{ schema = @{ name = $table; columns = $columns } } }
|        Write-Output ("table {0}: created with {1} column(s)" -f $table, $columns.Count)
|        return
|    }
|    $std = @($cur.properties.schema.standardColumns | ForEach-Object { [string]$_.name })
|    $merged = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($c in @($cur.properties.schema.columns)) { if ($c -and ([string]$c.name -notin $std)) { [void]$merged.Add((& $toCol $c)) } }
|    $added = New-Object 'System.Collections.Generic.List[string]'
|    foreach ($s in $SchemaSourceObject) {
|        if ([string]$s.name -in $std) { continue }
|        if (@($merged | Where-Object { $_.name -eq [string]$s.name }).Count) { continue }
|        [void]$merged.Add((& $toCol $s)); [void]$added.Add([string]$s.name)
|    }
|    if ($added.Count -eq 0) { Write-Output ("table {0}: has every column" -f $table); return }
|    $null = Invoke-SILogArm -Method PATCH -Path $path -ApiVersion (Get-SILogArmApiVersion Table) -Auth $auth -Body @{ properties = @{ schema = @{ name = $table; columns = @($merged.ToArray()) } } }
|    Write-Output ("table {0}: {1} column(s) added ({2})" -f $table, $added.Count, ($added -join ', '))
|}
|
|function Resolve-SILogEndpointForNewRule {
|    <# This install's endpoint, for a NEW rule: by name in SI_DceResourceGroup (else the rules' group) of the
|       subscription; one of that name elsewhere in the subscription is unambiguous; several refuse. #>
|    param([Parameter(Mandatory)][string]$DceName, $Scope, [hashtable]$Auth)
|    $dce = Find-SILogResourceByName -Kind Dce -Name $DceName -SubscriptionId $Scope.Subscription -ResourceGroup $Scope.DceRg -Auth $Auth -AnyResourceGroupWhenMissing
|    if (-not $dce) {
|        throw ("Data collection endpoint '{0}' was not found in resource group '{1}' of subscription '{2}', so nothing was created or posted." -f $DceName, $Scope.DceRg, $Scope.Subscription)
|    }
|    return $dce
|}
|
|function Set-SILogDcrRest {
|    <#
|        Twin of CreateUpdate-AzDataCollectionRuleLogIngestCustomLog, ADDITIVE ONLY:
|          no rule -> PUT one in the configured subscription + resource group, bound to THIS install's endpoint, with the
|                     stream declaration (the data's columns), the workspace destination and the default transform
|          rule    -> the columns the table has and the stream does not are ADDED to the stream declaration; everything
|                     else the rule carries (its endpoint, transform, destinations, other streams) is kept as it is. The
|                     module rebuilt the whole rule instead, re-binding it to the endpoint it found by name (#198).
|        A new rule waits 15 seconds for Azure to settle, as the module did.
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][array]$SchemaSourceObject, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [string]$DceName,
|          [Parameter(Mandatory)][string]$DcrResourceGroup, [Parameter(Mandatory)][string]$DcrName, [Parameter(Mandatory)][string]$TableName,
|          [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel = $false, [AllowEmptyString()][string]$LogIngestServicePricipleObjectId, [string]$SchemaMode = 'Merge',
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    $auth = Resolve-SILogIngestAuth -Bound $PSBoundParameters
|    $scope = Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId -DcrResourceGroup $DcrResourceGroup
|    $stream = Get-SILogStreamName -TableName $TableName
|    $wsName = ($AzLogWorkspaceResourceId -split '/')[-1]
|    $dcrPath = "/subscriptions/$($scope.Subscription)/resourceGroups/$DcrResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DcrName"
|    $ids = (Get-SILogIngestRunCache).DcrIds
|    $key = $DcrName.ToLowerInvariant()
|    $dcr = Invoke-SILogArm -Path $dcrPath -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -AllowNotFound -NoCache
|    $toCol = { param($c) [ordered]@{ name = [string]$c.name; type = [string]$c.type } }
|
|    if (-not $dcr) {
|        $dce = Resolve-SILogEndpointForNewRule -DceName $DceName -Scope $scope -Auth $auth
|        # #294: a new rule for a table that EXISTS declares the table's columns with the TABLE's types (then any column of
|        # the data the table does not have yet). Declared from the data instead, a type that differs from the table's
|        # (a column the data reads as an object, the table holds as text) makes Azure refuse the rule.
|        $tNew = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
|        $cols = @(Get-SILogNewRuleColumns -Table $tNew -SchemaSourceObject $SchemaSourceObject)
|        $body = [ordered]@{
|            location   = [string]$dce.location
|            properties = [ordered]@{
|                dataCollectionEndpointId = [string]$dce.id
|                streamDeclarations       = @{ $stream = @{ columns = $cols } }
|                destinations             = @{ logAnalytics = @(@{ workspaceResourceId = $AzLogWorkspaceResourceId; name = $wsName }) }
|                dataFlows                = @(@{ streams = @($stream); destinations = @($wsName); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream })
|            }
|        }
|        $created = Invoke-SILogArm -Method PUT -Path $dcrPath -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -Body $body
|        $ids[$key] = $dcrPath
|        Write-Output ("data collection rule {0}: created on endpoint {1} with {2} column(s)" -f $DcrName, $dce.id, $cols.Count)
|        if ($AzDcrSetLogIngestApiAppPermissionsDcrLevel -and $LogIngestServicePricipleObjectId) {
|            $roleDef = "/subscriptions/$($scope.Subscription)/providers/Microsoft.Authorization/roleDefinitions/3913510d-42f4-4e42-8a64-420c390055eb"
|            try {
|                $null = Invoke-SILogArm -Method PUT -Path ($dcrPath + '/providers/Microsoft.Authorization/roleAssignments/' + [guid]::NewGuid().ToString()) -ApiVersion (Get-SILogArmApiVersion Role) -Auth $auth `
|                    -Body @{ properties = @{ roleDefinitionId = $roleDef; principalId = $LogIngestServicePricipleObjectId; principalType = 'ServicePrincipal' } }
|            } catch { Write-Warning ("Monitoring Metrics Publisher on {0} was not granted: {1}" -f $DcrName, $_.Exception.Message) }
|        }
|        Start-Sleep -Seconds 15
|        return
|    }
|
|    $ids[$key] = [string]$dcr.id
|    # the columns the stream must carry: the table's (after Set-SILogTableRest), plus Computer/RawData when they are
|    # standard columns of a table migrated from v1 -- the module's rule
|    $t = Get-SILogTableRest -WorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -Auth $auth -NoCache
|    $want = New-Object 'System.Collections.Generic.List[object]'
|    if ($t) {
|        foreach ($c in @($t.properties.schema.columns)) { if ($c -and $c.name -ne 'TimeGenerated') { [void]$want.Add((& $toCol $c)) } }
|        foreach ($n in 'Computer', 'RawData') {
|            if (-not @($want | Where-Object { $_.name -eq $n }).Count -and @($t.properties.schema.standardColumns | Where-Object { $_.name -eq $n }).Count) { [void]$want.Add([ordered]@{ name = $n; type = 'string' }) }
|        }
|    } else {
|        foreach ($c in $SchemaSourceObject) { if ($c.name -ne 'TimeGenerated') { [void]$want.Add((& $toCol $c)) } }
|    }
|    $p = $dcr.properties
|    if (-not $p.streamDeclarations) { $p | Add-Member -NotePropertyName streamDeclarations -NotePropertyValue ([pscustomobject]@{}) -Force }
|    $hasStream = [bool]$p.streamDeclarations.PSObject.Properties[$stream]
|    $have = if ($hasStream) { @($p.streamDeclarations.$stream.columns) } else { @() }
|    $merged = New-Object 'System.Collections.Generic.List[object]'
|    foreach ($c in $have) { if ($c) { [void]$merged.Add((& $toCol $c)) } }
|    $added = New-Object 'System.Collections.Generic.List[string]'
|    foreach ($c in $want) { if (-not @($merged | Where-Object { $_.name -eq $c.name }).Count) { [void]$merged.Add($c); [void]$added.Add([string]$c.name) } }
|    if ($added.Count -eq 0) { Write-Output ("data collection rule {0}: has every column" -f $DcrName); return }
|
|    if ($hasStream) { $p.streamDeclarations.$stream.columns = @($merged.ToArray()) }
|    else {
|        $p.streamDeclarations | Add-Member -NotePropertyName $stream -NotePropertyValue ([pscustomobject]@{ columns = @($merged.ToArray()) })
|        $flows = @($p.dataFlows)
|        if (-not @($flows | Where-Object { @($_.streams) -contains $stream }).Count) {
|            $dest = @($p.destinations.logAnalytics)[0]
|            $p.dataFlows = @($flows) + @([pscustomobject]@{ streams = @($stream); destinations = @([string]$dest.name); transformKql = 'source | extend TimeGenerated = now()'; outputStream = $stream })
|        }
|    }
|    $props = [ordered]@{}
|    foreach ($q in $p.PSObject.Properties) { if ($q.Name -notin 'immutableId', 'provisioningState', 'endpoints', 'metadata') { $props[$q.Name] = $q.Value } }
|    $body = [ordered]@{ location = [string]$dcr.location; properties = $props }
|    if ($dcr.PSObject.Properties['kind'] -and $dcr.kind) { $body['kind'] = $dcr.kind }
|    if ($dcr.PSObject.Properties['tags'] -and $dcr.tags) { $body['tags'] = $dcr.tags }
|    $null = Invoke-SILogArm -Method PUT -Path ([string]$dcr.id) -ApiVersion (Get-SILogArmApiVersion Dcr) -Auth $auth -Body $body
|    Write-Output ("data collection rule {0}: {1} column(s) added to {2} ({3})" -f $DcrName, $added.Count, $stream, ($added -join ', '))
|}
|
|function Update-SILogTableSchemaRest {
|    <#
|        Twin of CheckCreateUpdate-TableDcr-Structure: the table and the rule carry every column of the data (the WHOLE
|        set decides the schema). Same arguments as the module. Additive only (Set-SILogTableRest / Set-SILogDcrRest).
|        A table name with '_' first, '-', ':', '.' or a space is refused as the module refuses it (nothing is done).
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][Array]$Data, [Parameter(Mandatory)][string]$AzLogWorkspaceResourceId, [Parameter(Mandatory)][string]$TableName,
|          [Parameter(Mandatory)][string]$DcrName, [string]$DcrResourceGroup, [string]$DceName,
|          [AllowEmptyString()][AllowEmptyCollection()][string]$LogIngestServicePricipleObjectId, [boolean]$AzDcrSetLogIngestApiAppPermissionsDcrLevel = $false,
|          [boolean]$AzLogDcrTableCreateFromAnyMachine, [string]$SchemaMode = 'Merge', [boolean]$EnableUploadViaLogHub = $false,
|          [AllowEmptyCollection()][array]$AzLogDcrTableCreateFromReferenceMachine,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine',
|          [switch]$UseManagedIdentity, [string]$ManagedIdentityClientId, [string]$TenantId)
|    if ($TableName -like '_*' -or $TableName -like '*-*' -or $TableName -like '*:*' -or $TableName -like '*.*' -or $TableName -like '* *') {
|        Write-Verbose ("ISSUE - Table name [ {0} ] is not a valid Log Analytics table name" -f $TableName)
|        return
|    }
|    if ($EnableUploadViaLogHub) { return }
|    if (-not ($AzLogDcrTableCreateFromAnyMachine -or ($env:COMPUTERNAME -and $env:COMPUTERNAME -in @($AzLogDcrTableCreateFromReferenceMachine)))) { return }
|    if (-not $DcrResourceGroup) { $DcrResourceGroup = (Get-SILogIngestScope -WorkspaceResourceId $AzLogWorkspaceResourceId).DcrRg }
|    $authArgs = @{}
|    foreach ($k in 'AzAppId', 'AzAppSecret', 'AzAppCertificateThumbprint', 'AzAppCertificateStoreLocation', 'UseManagedIdentity', 'ManagedIdentityClientId', 'TenantId') {
|        if ($PSBoundParameters.ContainsKey($k)) { $authArgs[$k] = $PSBoundParameters[$k] }
|    }
|    $schema = Get-SILogSchemaRest -Data $Data -As Array
|    $needs = Test-SILogTableDcrStatusRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -DcrName $DcrName -SchemaSourceObject $schema -DcrResourceGroup $DcrResourceGroup @authArgs
|    if (-not $needs) { Write-Output ("table {0}_CL and rule {1}: every column is declared" -f $TableName, $DcrName); return }
|    Set-SILogTableRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -TableName $TableName -SchemaSourceObject (Get-SILogSchemaRest -Data $Data -As Hash -ReturnType Table) -SchemaMode $SchemaMode @authArgs
|    Set-SILogDcrRest -AzLogWorkspaceResourceId $AzLogWorkspaceResourceId -SchemaSourceObject (Get-SILogSchemaRest -Data $Data -As Hash -ReturnType DCR) `
|        -DceName $DceName -DcrName $DcrName -DcrResourceGroup $DcrResourceGroup -TableName $TableName -SchemaMode $SchemaMode `
|        -LogIngestServicePricipleObjectId $LogIngestServicePricipleObjectId -AzDcrSetLogIngestApiAppPermissionsDcrLevel $AzDcrSetLogIngestApiAppPermissionsDcrLevel @authArgs
|}
|
|# =====================================================================================================================
|#  REST: upload
|# =====================================================================================================================
|
|function ConvertTo-SILogGzip {
|    param([Parameter(Mandatory)][byte[]]$Bytes)
|    $ms = New-Object System.IO.MemoryStream
|    try {
|        $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
|        try { $gz.Write($Bytes, 0, $Bytes.Length) } finally { $gz.Dispose() }
|        return , $ms.ToArray()
|    } finally { $ms.Dispose() }
|}
|
|function Send-SILogIngestBatch {
|    <# Posts rows [List of row JSON bytes] as one JSON array. Measured: when the payload (compressed when -State says
|       so) exceeds the limit, the batch is split in two and each half measured again. #>
|    param([Parameter(Mandatory)]$Rows, [Parameter(Mandatory)][hashtable]$State)
|    $raw = New-Object System.IO.MemoryStream
|    try {
|        $raw.WriteByte(0x5B)
|        for ($i = 0; $i -lt $Rows.Count; $i++) { if ($i -gt 0) { $raw.WriteByte(0x2C) }; $b = $Rows[$i]; $raw.Write($b, 0, $b.Length) }
|        $raw.WriteByte(0x5D)
|        $rawBytes = $raw.ToArray()
|    } finally { $raw.Dispose() }
|    $payload = if ($State.Compress) { ConvertTo-SILogGzip -Bytes $rawBytes } else { $rawBytes }
|    if ($payload.Length -gt $State.MaxBytes) {
|        if ($Rows.Count -eq 1) { throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f $payload.Length, $State.MaxBytes) }
|        $half = [int][Math]::Floor($Rows.Count / 2)
|        $a = New-Object 'System.Collections.Generic.List[byte[]]'; $z = New-Object 'System.Collections.Generic.List[byte[]]'
|        for ($i = 0; $i -lt $Rows.Count; $i++) { if ($i -lt $half) { [void]$a.Add($Rows[$i]) } else { [void]$z.Add($Rows[$i]) } }
|        Send-SILogIngestBatch -Rows $a -State $State
|        Send-SILogIngestBatch -Rows $z -State $State
|        return
|    }
|    if ($State.Compress -and $rawBytes.Length -gt 0) { $State.Ratio = [Math]::Max(0.01, $payload.Length / $rawBytes.Length) }
|    $from = $State.Posted + 1; $to = $State.Posted + $Rows.Count
|    Write-Host ''
|    Write-Host ("  Posting data to LogAnalytics table [ {0}_CL ]" -f $State.Table)
|    Write-Host ("    Rows       : {0}..{1} / {2}" -f $from, $to, $State.Total)
|    Write-Host ("    {0} | {1}" -f $(if ($State.Compress) { 'Compression=ON' } else { 'Compression=OFF' }), $State.AuthText)
|    Write-Host ''
|    $h = @{}
|    if ($State.Compress) { $h['Content-Encoding'] = 'gzip' }
|    $null = Invoke-SILogIngestRequest -Method POST -Uri $State.Uri -Body ([byte[]]$payload) -ContentType 'application/json' -Headers $h `
|        -Resource 'https://monitor.azure.com/' -Auth $State.Auth -What 'Log Ingestion API request'
|    $State.Posted += $Rows.Count
|    $State.Bytes += [long]$rawBytes.Length
|    $State.Batches++
|    Write-Host '  SUCCESS - data uploaded to LogAnalytics' -ForegroundColor Green
|}
|
|# =====================================================================================================================
|#  REST: the PARALLEL SENDER (#738) -- for a caller that posts one large result in many calls (Risk Analysis)
|#
|#  A large install, 2026-10-17: 1,138,554 Risk Analysis rows reached Log Analytics at ~2,200 rows a minute (~8.5 hours). Every post
|#  was made, and waited for, in line with the work that builds the rows: the page read, the preparation, the JSON, then one
|#  POST at a time, each ~half full (the batch split in two whenever the compressed size went over the limit).
|#  A sender changes only HOW the rows travel, never WHICH rows or their JSON (the rows are serialised exactly as before, by
|#  Send-SILogDataRest, in the order given):
|#    * each POST is filled close to the API's limit: the rows are compressed, the compressed size MEASURED, and a batch that
|#      comes out over the limit gives back its last rows to the next batch (no half batches); the compression ratio adapts
|#      from every measurement; a 413 from the service lowers the limit and the batch is split and sent again;
|#    * up to -Degree POSTs are in flight at once (a small fixed number, 4), each on its own worker; a 429 / 408 / 5xx / no
|#      answer is retried by its worker after the service's Retry-After, and a 429 holds EVERY worker until then;
|#    * the endpoint, the rule and the token are resolved once per sender (the token from the run's cache, refreshed on 401);
|#    * the rows confirmed by the service (2xx) are COUNTED; Complete-SILogIngestSender throws when they are fewer than the
|#      rows handed over -- the same verdict as before. A failed post stops the next hand-over at once (the error is the
|#      same text as a failed synchronous post).
|#  Started by the caller (Start-SILogIngestSender -TableName), then every Send-SILogData for that table goes through it;
|#  any other table, and every caller that never starts one, posts synchronously exactly as before.
|# =====================================================================================================================
|
|function Get-SILogIngestSenderWorkerScript {
|    <# The worker: one POST with the retry rule (working rule 4), holding while the service asked every worker to wait. #>
|    @'
|param([string]$Uri, [byte[]]$Body, [hashtable]$Headers, [int]$MaxAttempts, $Gate)
|$notes = New-Object 'System.Collections.Generic.List[string]'
|for ($attempt = 1; ; $attempt++) {
|    while ($true) {
|        $until = [long]$Gate['PauseUntil']; $now = [datetime]::UtcNow.Ticks
|        if ($until -le $now) { break }
|        Start-Sleep -Milliseconds ([int][Math]::Min(60000, [Math]::Ceiling(($until - $now) / 10000.0)) + 1)
|    }
|    $r = Invoke-SILogIngestHttp -Method POST -Uri $Uri -Headers $Headers -Body $Body -ContentType 'application/json'
|    $code = [int]$r.StatusCode
|    if ($code -ge 200 -and $code -lt 300) { return @{ Code = $code; Attempts = $attempt; Content = ''; Notes = $notes.ToArray() } }
|    $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
|    if (-not $transient -or $attempt -ge $MaxAttempts) { return @{ Code = $code; Attempts = $attempt; Content = [string]$r.Content; Notes = $notes.ToArray() } }
|    $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
|    if ($code -eq 429) {
|        [System.Threading.Monitor]::Enter($Gate.SyncRoot)
|        try { $t = [datetime]::UtcNow.AddSeconds($wait).Ticks; if ($t -gt [long]$Gate['PauseUntil']) { $Gate['PauseUntil'] = $t } } finally { [System.Threading.Monitor]::Exit($Gate.SyncRoot) }
|    }
|    if ($code -eq 0 -or $wait -ge 30) {
|        $notes.Add((" [INFO] Log Ingestion API request: {0} -- trying again in {1} second(s) (attempt {2} of {3})" -f $(if ($code -eq 0) { 'no answer from Azure' } else { 'Azure answered HTTP {0}' -f $code }), $wait, $attempt, $MaxAttempts))
|    }
|    [System.Threading.Monitor]::Enter($Gate.SyncRoot)
|    try { $Gate['Retries'] = 1 + [int]$Gate['Retries'] } finally { [System.Threading.Monitor]::Exit($Gate.SyncRoot) }
|    Start-Sleep -Seconds $wait
|}
|'@
|}
|
|function Get-SILogIngestSender {
|    <# The sender started for -TableName in this run ($null when none). #>
|    param([Parameter(Mandatory)][string]$TableName)
|    $c = Get-SILogIngestRunCache
|    if (-not ($c.Senders -is [hashtable])) { return $null }
|    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
|    if ($c.Senders.ContainsKey($k)) { return $c.Senders[$k] }
|    $null
|}
|
|function Get-SILogIngestPostDegree {
|    <# PURE over the setting. POSTs in flight at once: 4 (a small fixed number). SI_LogIngest_ParallelPosts (global) or the
|       environment variable SI_LOGINGEST_PARALLELPOSTS: 1 / 0 / off = one at a time; a number = that many, at most 8. #>
|    param($Setting = $(Get-Variable -Scope Global -Name SI_LogIngest_ParallelPosts -ValueOnly -ErrorAction Ignore), [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_LOGINGEST_PARALLELPOSTS)
|    $s = if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '') { ([string]$Setting).Trim() } elseif ($EnvValue) { $EnvValue.Trim() } else { '' }
|    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
|    $n = 0
|    if ($s -ne '' -and [int]::TryParse($s, [ref]$n)) { if ($n -le 1) { return 1 }; return [Math]::Min(8, $n) }
|    4
|}
|
|function Start-SILogIngestSender {
|    <# Starts the sender for -TableName (see the block above). -Degree: POSTs in flight at once (Get-SILogIngestPostDegree).
|       -MaxPayloadBytes: the API's limit per call; each POST is filled to -Fill of it (measured after compression). #>
|    param([Parameter(Mandatory)][string]$TableName, [int]$Degree = 0, [long]$MaxPayloadBytes = 1MB, [double]$Fill = 0.95, [int]$MaxAttempts = 6)
|    if ($Degree -le 0) { $Degree = Get-SILogIngestPostDegree }
|    $c = Get-SILogIngestRunCache
|    if (-not ($c.Senders -is [hashtable])) { $c.Senders = @{} }
|    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
|    if ($c.Senders.ContainsKey($k)) { Stop-SILogIngestSender -TableName $TableName }
|    $s = @{
|        Table = ($TableName -replace '_CL$', ''); Degree = $Degree; MaxBytes = [long]$MaxPayloadBytes; Fill = $Fill; MaxAttempts = $MaxAttempts
|        Uri = $null; Auth = $null; AuthText = ''; Compress = $true; Ratio = 1.0
|        Pending = (New-Object 'System.Collections.Generic.List[byte[]]'); PendingBytes = 2L
|        InFlight = (New-Object 'System.Collections.Generic.List[object]')
|        Accepted = 0L; Dispatched = 0L; Confirmed = 0L; Bytes = 0L; SentBytes = 0L; Posts = 0; Split413 = 0; MaxSent = 0L
|        Failed = $null; Pool = $null; Gate = [hashtable]::Synchronized(@{ PauseUntil = 0L; Retries = 0 }); Script = (Get-SILogIngestSenderWorkerScript)
|    }
|    if ($Degree -gt 1) {
|        # the worker's environment: the HTTP seam and the retry delay AS THEY ARE in this run (a test's fake service
|        # included), and $SILogSeam (the test seam's shared state, $null in a real run). Never a script block of this
|        # runspace: a worker runs only text it was given.
|        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
|        foreach ($fn in 'Invoke-SILogIngestHttp', 'Get-SILogIngestRetryDelay') {
|            $def = (Get-Command -Name $fn -CommandType Function -ErrorAction Stop).Definition
|            $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $def)))
|        }
|        $seam = Get-Variable -Scope Global -Name SILogSeam -ValueOnly -ErrorAction Ignore
|        $iss.Variables.Add((New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry('SILogSeam', $seam, '')))
|        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Degree, $iss, $Host)
|        $pool.Open()
|        $s.Pool = $pool
|    }
|    $c.Senders[$k] = $s
|    $s
|}
|
|function Send-SILogIngestSenderBatch {
|    <# Hands one payload to a worker (or posts it here when the sender has no workers), waiting first while -Degree are in flight. #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][byte[]]$Payload, [Parameter(Mandatory)][hashtable]$Batch)
|    while ($Sender.InFlight.Count -ge [Math]::Max(1, $Sender.Degree)) { Receive-SILogIngestSenderResults -Sender $Sender -WaitOne }
|    # once a post has failed, nothing more goes out (the run fails; the rows not posted are counted as not confirmed)
|    if ($Sender.Failed) { return }
|    $token = Get-SILogIngestToken -Resource 'https://monitor.azure.com/' -Auth $Sender.Auth -ForceRefresh:([bool]$Batch.Refresh)
|    $h = @{ 'Authorization' = ('Bearer ' + $token) }
|    if ($Sender.Compress) { $h['Content-Encoding'] = 'gzip' }
|    $Batch.Payload = $Payload
|    $Sender.Posts++
|    if ($null -eq $Sender.Pool) {
|        $res = & ([scriptblock]::Create($Sender.Script)) $Sender.Uri $Payload $h $Sender.MaxAttempts $Sender.Gate
|        Complete-SILogIngestSenderBatch -Sender $Sender -Batch $Batch -Result $res
|        return
|    }
|    $ps = [powershell]::Create()
|    $ps.RunspacePool = $Sender.Pool
|    [void]$ps.AddScript($Sender.Script).AddArgument($Sender.Uri).AddArgument($Payload).AddArgument($h).AddArgument($Sender.MaxAttempts).AddArgument($Sender.Gate)
|    $Batch.PS = $ps
|    $Batch.Handle = $ps.BeginInvoke()
|    [void]$Sender.InFlight.Add($Batch)
|}
|
|function Complete-SILogIngestSenderBatch {
|    <# One post's answer: 2xx = its rows confirmed (said as before); 401 = sent once more with a fresh token; 413 = the limit
|       is lowered and the batch split and sent again; anything else = the sender has FAILED (same text as a failed post). #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][hashtable]$Batch, $Result)
|    $r = $Result
|    if ($r -is [System.Collections.IEnumerable] -and -not ($r -is [hashtable])) { $r = @($r | Where-Object { $_ -is [hashtable] }) | Select-Object -Last 1 }
|    if (-not ($r -is [hashtable])) { $r = @{ Code = 0; Content = 'the post''s worker returned no answer'; Notes = @() } }
|    foreach ($n in @($r.Notes)) { if ($n) { Write-Host $n } }
|    $code = [int]$r.Code
|    if ($code -ge 200 -and $code -lt 300) {
|        $Sender.Confirmed += $Batch.Rows.Count
|        $Sender.Bytes += [long]$Batch.Raw
|        $Sender.SentBytes += [long]$Batch.Payload.Length
|        if ($Batch.Payload.Length -gt $Sender.MaxSent) { $Sender.MaxSent = [long]$Batch.Payload.Length }
|        Write-Host ''
|        Write-Host ("  Posting data to LogAnalytics table [ {0}_CL ]" -f $Sender.Table)
|        Write-Host ("    Rows       : {0}..{1} / {2}" -f $Batch.From, ($Batch.From + $Batch.Rows.Count - 1), $Sender.Accepted)
|        Write-Host ("    {0} | {1} | {2:n0} bytes" -f $(if ($Sender.Compress) { 'Compression=ON' } else { 'Compression=OFF' }), $Sender.AuthText, $Batch.Payload.Length)
|        Write-Host ''
|        Write-Host '  SUCCESS - data uploaded to LogAnalytics' -ForegroundColor Green
|        return
|    }
|    if ($code -eq 401 -and -not $Batch.Refresh -and -not $Sender.Failed) {
|        $Batch.Refresh = $true
|        Send-SILogIngestSenderBatch -Sender $Sender -Payload $Batch.Payload -Batch $Batch
|        return
|    }
|    if ($code -eq 413 -and $Batch.Rows.Count -gt 1 -and -not $Sender.Failed) {
|        # the service's own limit is lower than ours: lower it under this payload and send the rows again in two
|        $Sender.MaxBytes = [long][Math]::Max(65536, [Math]::Floor($Batch.Payload.Length * 0.9))
|        $Sender.Split413++
|        $half = [int][Math]::Floor($Batch.Rows.Count / 2)
|        $a = New-Object 'System.Collections.Generic.List[byte[]]'; $z = New-Object 'System.Collections.Generic.List[byte[]]'
|        for ($i = 0; $i -lt $Batch.Rows.Count; $i++) { if ($i -lt $half) { [void]$a.Add($Batch.Rows[$i]) } else { [void]$z.Add($Batch.Rows[$i]) } }
|        $Sender.Dispatched -= $Batch.Rows.Count
|        Send-SILogIngestSenderRows -Sender $Sender -Rows $a -From $Batch.From
|        Send-SILogIngestSenderRows -Sender $Sender -Rows $z -From ($Batch.From + $half)
|        return
|    }
|    if (-not $Sender.Failed) { $Sender.Failed = ("Log Ingestion API request failed. HTTP Status: {0} Response: {1}" -f $code, $r.Content) }
|}
|
|function Receive-SILogIngestSenderResults {
|    <# Collects the answers of the posts that finished; -WaitOne waits for at least one (when any is in flight); -All for all. #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [switch]$WaitOne, [switch]$All)
|    while ($Sender.InFlight.Count -gt 0) {
|        $done = @($Sender.InFlight | Where-Object { $_.Handle.IsCompleted })
|        if ($done.Count -eq 0) {
|            if (-not $WaitOne -and -not $All) { return }
|            $handles = [System.Threading.WaitHandle[]]@($Sender.InFlight | ForEach-Object { $_.Handle.AsyncWaitHandle } | Select-Object -First 64)
|            [void][System.Threading.WaitHandle]::WaitAny($handles, 1000)
|            continue
|        }
|        # out of the list first: answering one post can send another (401, 413) and wait for the workers again
|        foreach ($b in $done) { [void]$Sender.InFlight.Remove($b) }
|        # each answer on its own: one that throws (a token fetch for a 401 resend, a record too large in a 413 split) is the
|        # sender's FIRST error -- every other finished post is still counted and its worker disposed
|        foreach ($b in $done) {
|            $res = $null
|            try { $res = @($b.PS.EndInvoke($b.Handle)) | ForEach-Object { $_.psobject.BaseObject } | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1 }
|            catch { $res = @{ Code = 0; Content = $_.Exception.Message; Notes = @() } }
|            finally { try { $b.PS.Dispose() } catch { }; $b.PS = $null; $b.Handle = $null }
|            try { Complete-SILogIngestSenderBatch -Sender $Sender -Batch $b -Result $res }
|            catch { if (-not $Sender.Failed) { $Sender.Failed = [string]$_.Exception.Message } }
|        }
|        if ($WaitOne -and -not $All) { return }
|    }
|}
|
|function Send-SILogIngestSenderCut {
|    <# Makes ONE post from the rows waiting: compressed and MEASURED; over the limit -> the last rows wait for the next post
|       (as many as the measurement says), never a half-empty post: a post that measures under 60% of the limit is not
|       sent yet (the ratio is learnt from it and the rows keep coming) -- unless -Final (the rows left at the end). #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [switch]$Final)
|    $rows = $Sender.Pending
|    if ($rows.Count -eq 0) { return }
|    $take = $rows.Count
|    $limit = [long][Math]::Floor($Sender.MaxBytes * $Sender.Fill)
|    while ($true) {
|        $raw = New-Object System.IO.MemoryStream
|        try {
|            $raw.WriteByte(0x5B)
|            for ($i = 0; $i -lt $take; $i++) { if ($i -gt 0) { $raw.WriteByte(0x2C) }; $b = $rows[$i]; $raw.Write($b, 0, $b.Length) }
|            $raw.WriteByte(0x5D)
|            $rawBytes = $raw.ToArray()
|        } finally { $raw.Dispose() }
|        $payload = if ($Sender.Compress) { ConvertTo-SILogGzip -Bytes $rawBytes } else { $rawBytes }
|        if ($Sender.Compress -and $rawBytes.Length -gt 0) { $Sender.Ratio = [Math]::Max(0.005, $payload.Length / [double]$rawBytes.Length) }
|        if (-not $Final -and $take -eq $rows.Count -and $payload.Length -lt [long]($limit * 0.6)) { return }   # too empty yet: wait for more rows
|        if ($payload.Length -le $limit -or ($payload.Length -le $Sender.MaxBytes -and $take -eq 1)) { break }
|        if ($take -eq 1) { throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f $payload.Length, $Sender.MaxBytes) }
|        # as many rows as the measured bytes per row allow, a little under (the next post takes the rest)
|        $take = [int][Math]::Max(1, [Math]::Min($take - 1, [Math]::Floor($take * ($limit * 0.98) / [double]$payload.Length)))
|    }
|    $batchRows = $rows.GetRange(0, $take)
|    $rows.RemoveRange(0, $take)
|    $Sender.PendingBytes = 2L; foreach ($b in $rows) { $Sender.PendingBytes += $b.Length + 1 }
|    $from = $Sender.Dispatched + 1
|    $Sender.Dispatched += $take
|    Send-SILogIngestSenderBatch -Sender $Sender -Payload $payload -Batch @{ Rows = $batchRows; Raw = $rawBytes.Length; From = $from; Refresh = $false }
|}
|
|function Send-SILogIngestSenderRows {
|    <# Adds serialised rows to the sender, in order; a post is made each time the rows waiting reach the measured size of a
|       full one. -From: re-sent rows (a 413 split) keep their numbers and go out at once. #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)]$Rows, [long]$From = 0)
|    if ($From -gt 0) {
|        # a split batch: these rows go out as they are (each half measured again), ahead of the rows waiting
|        $keep = $Sender.Pending; $keepBytes = $Sender.PendingBytes
|        $Sender.Pending = New-Object 'System.Collections.Generic.List[byte[]]'; foreach ($b in $Rows) { [void]$Sender.Pending.Add($b) }
|        $saved = $Sender.Dispatched; $Sender.Dispatched = $From - 1
|        while ($Sender.Pending.Count -gt 0) { Send-SILogIngestSenderCut -Sender $Sender -Final }
|        $Sender.Dispatched = $saved + $Rows.Count
|        $Sender.Pending = $keep; $Sender.PendingBytes = $keepBytes
|        return
|    }
|    foreach ($b in $Rows) {
|        if (-not $Sender.Compress -and ($b.Length + 2) -gt $Sender.MaxBytes) {
|            throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f ($b.Length + 2), $Sender.MaxBytes)
|        }
|        # raw-bytes ceiling: the limit itself uncompressed; compressed, the fill level over the measured ratio
|        $ceiling = if ($Sender.Compress) { [long][Math]::Min(64MB, [Math]::Floor($Sender.MaxBytes * $Sender.Fill / $Sender.Ratio)) } else { [long][Math]::Floor($Sender.MaxBytes * $Sender.Fill) }
|        $add = $b.Length + $(if ($Sender.Pending.Count -gt 0) { 1 } else { 0 })
|        if ($Sender.Pending.Count -gt 0 -and ($Sender.PendingBytes + $add) -gt $ceiling) {
|            Send-SILogIngestSenderCut -Sender $Sender
|            if ($Sender.Failed) { throw $Sender.Failed }
|            $add = $b.Length + $(if ($Sender.Pending.Count -gt 0) { 1 } else { 0 })
|        }
|        [void]$Sender.Pending.Add($b); $Sender.PendingBytes += $add
|        $Sender.Accepted++
|    }
|    Receive-SILogIngestSenderResults -Sender $Sender
|    if ($Sender.Failed) { throw $Sender.Failed }
|}
|
|function Sync-SILogIngestSender {
|    <# Every row handed over is posted and answered (the rows waiting go out now). Throws when a post failed. #>
|    param([Parameter(Mandatory)][hashtable]$Sender)
|    while ($Sender.Pending.Count -gt 0 -and -not $Sender.Failed) { Send-SILogIngestSenderCut -Sender $Sender -Final }
|    Receive-SILogIngestSenderResults -Sender $Sender -All
|    if ($Sender.Failed) { throw $Sender.Failed }
|}
|
|function Invoke-SILogIngestGuardHeal {
|    <#
|        #733 (owner 2026-10-17: guards heal themselves): a table whose rows Log Analytics accepted IN FULL clears an earlier
|        "rows not accepted" of that table by itself. Once per table per process (the first full post), so the hot path pays one
|        state read per table, not one per post. Never throws; nothing when the guard code is not loaded.
|    #>
|    param([Parameter(Mandatory)][string]$Table)
|    try {
|        if (-not (Get-Command -Name Invoke-SIGuardHeal -ErrorAction Ignore)) { return }
|        if ($null -eq $script:SILogIngestHealed) { $script:SILogIngestHealed = @{} }
|        $t = $Table.ToLowerInvariant()
|        if ($script:SILogIngestHealed.ContainsKey($t)) { return }
|        $script:SILogIngestHealed[$t] = $true
|        $null = Invoke-SIGuardHeal -Checked @(@{ GuardId = 'ingest.rows.short-count'; Subject = $Table; Detail = ('Log Analytics accepted every row for {0}.' -f $Table) }) -Complete $true
|    } catch { }
|}
|
|function Complete-SILogIngestSender {
|    <#
|        The end of the hand-over: the rows waiting are posted, every post is answered, the workers are closed. The rows the
|        service CONFIRMED are counted against the rows handed over -- fewer throws (and is a guard event), as a short
|        synchronous post did. Returns @{ RowsPosted; RowsHandedOver; Posts; BytesPosted; BytesSent; MaxBytesSent; Retries; Split413 }.
|    #>
|    param([Parameter(Mandatory)][string]$TableName)
|    $s = Get-SILogIngestSender -TableName $TableName
|    if ($null -eq $s) { return $null }
|    try { Sync-SILogIngestSender -Sender $s }
|    finally { Close-SILogIngestSender -TableName $TableName }
|    if ($s.Confirmed -ne $s.Accepted) {
|        if (Get-Command -Name Send-SIGuardEvent -ErrorAction Ignore) { $null = Send-SIGuardEvent -GuardId 'ingest.rows.short-count' -Outcome 'refused' -Subject ($s.Table + '_CL') -Detail ("Log Analytics accepted {0} of {1} row(s) for {2}_CL." -f $s.Confirmed, $s.Accepted, $s.Table) -Values @(@{ Name = 'rowsPosted'; Label = 'Rows accepted'; Measured = [long]$s.Confirmed; Limit = [long]$s.Accepted }, @{ Name = 'rowsGiven'; Label = 'Rows sent'; Measured = [long]$s.Accepted }) -HeldCount ([long]$s.Accepted - [long]$s.Confirmed) }
|        throw ("Posted {0} of {1} row(s) to {2}_CL -- the other rows are UNKNOWN, not posted." -f $s.Confirmed, $s.Accepted, $s.Table)
|    }
|    if ([long]$s.Accepted -gt 0) { Invoke-SILogIngestGuardHeal -Table ($s.Table + '_CL') }
|    [pscustomobject]@{ RowsPosted = $s.Confirmed; RowsHandedOver = $s.Accepted; Posts = $s.Posts; BytesPosted = $s.Bytes; BytesSent = $s.SentBytes; MaxBytesSent = $s.MaxSent; Retries = [int]$s.Gate['Retries']; Split413 = $s.Split413 }
|}
|
|function Send-SILogDataToSender {
|    <#
|        Send-SILogDataRest's rows through a sender: serialised EXACTLY as the synchronous path does (ConvertTo-Json -Depth 100
|        -Compress per row, UTF-8, in the order given) and handed over. Returns the synchronous path's result shape: RowsPosted
|        = the rows handed over (the rows CONFIRMED are counted by Complete-SILogIngestSender), BytesPosted = their JSON bytes.
|        When this run added columns to the rule and their check is due (Confirm-SILogNewColumns, after this call), every row
|        handed over is posted and answered first -- the check reads the rows back from Log Analytics.
|    #>
|    param([Parameter(Mandatory)][hashtable]$Sender, [Parameter(Mandatory)][AllowEmptyCollection()][array]$Data, [string]$DcrName)
|    # #639: handed over a BATCH at a time -- the rows serialised so far are handed to the sender once they fill a post
|    # (its measured size), never the whole post serialised first and held as bytes beside the rows
|    $list = New-Object 'System.Collections.Generic.List[byte[]]'
|    $bytes = 1L; $count = 0L; $listBytes = 0L
|    $fill = 1.0; if ($Sender.ContainsKey('Fill') -and $Sender.Fill) { $fill = [double]$Sender.Fill }
|    $ratio = 1.0; if ($Sender.ContainsKey('Ratio') -and $Sender.Ratio) { $ratio = [double]$Sender.Ratio }
|    $max = 1MB; if ($Sender.ContainsKey('MaxBytes') -and $Sender.MaxBytes) { $max = [long]$Sender.MaxBytes }
|    $handAt = [long][Math]::Max(1, [Math]::Floor($max * $fill))
|    if ($Sender.Compress) { $handAt = [long][Math]::Min(64MB, [Math]::Floor($max * $fill / $ratio)) }
|    foreach ($row in $Data) {
|        $b = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 100 -InputObject $row -Compress))
|        [void]$list.Add($b); $bytes += $b.Length + 1; $listBytes += $b.Length + 1; $count++
|        if ($listBytes -ge $handAt) {
|            Send-SILogIngestSenderRows -Sender $Sender -Rows $list
|            $list = New-Object 'System.Collections.Generic.List[byte[]]'; $listBytes = 0L
|        }
|    }
|    if ($list.Count -gt 0) { Send-SILogIngestSenderRows -Sender $Sender -Rows $list }
|    $list = $null
|    if ($DcrName -and ($global:SI_LogIngestNewColumns -is [hashtable]) -and $global:SI_LogIngestNewColumns.ContainsKey($DcrName.ToLowerInvariant())) {
|        Sync-SILogIngestSender -Sender $Sender
|    }
|    [pscustomobject]@{ StatusCode = 204; RowsPosted = $count; BytesPosted = $bytes; Batches = 0; Table = ($Sender.Table + '_CL'); Stream = '' }
|}
|
|function Stop-SILogIngestSender {
|    <# After a failure: nothing more is posted; the posts in flight are answered (their rows count), the workers closed.
|       Returns the rows the service confirmed (the rows that DID reach Log Analytics). Never throws. #>
|    param([Parameter(Mandatory)][string]$TableName)
|    $s = Get-SILogIngestSender -TableName $TableName
|    if ($null -eq $s) { return 0L }
|    try { $s.Pending.Clear(); Receive-SILogIngestSenderResults -Sender $s -All } catch { }
|    Close-SILogIngestSender -TableName $TableName
|    [long]$s.Confirmed
|}
|
|function Close-SILogIngestSender {
|    param([Parameter(Mandatory)][string]$TableName)
|    $c = Get-SILogIngestRunCache
|    $k = ($TableName -replace '_CL$', '').ToLowerInvariant()
|    if (-not ($c.Senders -is [hashtable]) -or -not $c.Senders.ContainsKey($k)) { return }
|    $s = $c.Senders[$k]
|    foreach ($b in $s.InFlight.ToArray()) { try { if ($b.PS) { $b.PS.Stop(); $b.PS.Dispose() } } catch { } }
|    $s.InFlight.Clear()
|    if ($s.Pool) { try { $s.Pool.Close(); $s.Pool.Dispose() } catch { }; $s.Pool = $null }
|    $c.Senders.Remove($k)
|}
|
|function Send-SILogDataRest {
|    <#
|        Twin of Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output, over plain REST:
|          * the rule is found by NAME in the configured subscription + SI_DcrResourceGroup (or the one created this run);
|          * the post goes through the endpoint the RULE is bound to -- ingestion accepts nothing else (#199);
|          * POST {endpoint}/dataCollectionRules/{immutableId}/streams/Custom-{table}_CL?api-version=2023-01-01;
|          * batches are sized from the MEASURED JSON bytes of the rows (working rule 5: no fixed row counts), each under
|            the 1 MB limit -- compressed when $global:EnableCompressionDefault says so, measured after compression and
|            split again if over;
|          * 429 / 5xx retried in-run with Retry-After; any other 4xx fails at once with the response body;
|          * the rows posted are COUNTED against the rows given -- a shortfall throws, it is never reported as done.
|        Rows are serialised exactly as the module serialised them (ConvertTo-Json -Depth 100 -Compress per row).
|        -BatchAmount is accepted and ignored: a fixed row count is what working rule 5 forbids.
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][AllowEmptyCollection()][array]$Data, [Parameter(Mandatory)][AllowEmptyString()][string]$DcrName,
|          [AllowEmptyString()][string]$DceName, [Parameter(Mandatory)][string]$TableName,
|          [string]$BatchAmount, [bool]$EnableUploadViaLogHub = $false, [string]$LogHubPath,
|          [string]$AzAppId, [string]$AzAppSecret, [string]$AzAppCertificateThumbprint, [string]$AzAppCertificateStoreLocation = 'LocalMachine', [string]$TenantId,
|          [Nullable[bool]]$EnableCompression = $null, [Nullable[bool]]$UseManagedIdentity = $null, [string]$ManagedIdentityClientId,
|          [string]$SubscriptionId, [string]$DcrResourceGroup, [long]$MaxPayloadBytes = 1MB)
|    $total = @($Data).Count
|    if ($total -eq 0) { return }
|    if ($null -eq $EnableCompression) { $EnableCompression = if ($null -ne $global:EnableCompressionDefault) { [bool]$global:EnableCompressionDefault } else { $false } }
|    $bound = @{}; foreach ($k in $PSBoundParameters.Keys) { $bound[$k] = $PSBoundParameters[$k] }
|    $auth = Resolve-SILogIngestAuth -Bound $bound
|    # #738: a sender started for this table takes the rows (in order, serialised exactly as below); its endpoint, rule and
|    # sign-in are resolved on its first call and reused
|    $sender = Get-SILogIngestSender -TableName $TableName
|    if ($sender -and $sender.Uri) {
|        if ([bool]$EnableCompression -ne [bool]$sender.Compress) { $sender = $null }   # never mixed in one sender
|        else { return (Send-SILogDataToSender -Sender $sender -Data $Data -DcrName $DcrName) }
|    }
|    $scope = Get-SILogIngestScope -SubscriptionId $SubscriptionId -DcrResourceGroup $DcrResourceGroup
|
|    $dcr = Resolve-SILogDcrForTable -DcrName $DcrName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DcrRg -Auth $auth
|    if (-not $dcr) { throw ("Data collection rule '{0}' was not found in resource group '{1}' of subscription '{2}', so nothing was posted." -f $DcrName, $scope.DcrRg, $scope.Subscription) }
|    $immutableId = [string]$dcr.properties.immutableId
|    if (-not $immutableId) { throw ("Data collection rule '{0}' has no immutable id yet, so nothing was posted." -f $DcrName) }
|    $stream = Get-SILogStreamName -TableName $TableName
|    if (-not ($dcr.properties.streamDeclarations -and $dcr.properties.streamDeclarations.PSObject.Properties[$stream])) {
|        $first = @(@($dcr.properties.dataFlows)[0].streams)[0]
|        if ($first) { $stream = [string]$first }
|    }
|    $endpoint = $null
|    $boundDce = [string]$dcr.properties.dataCollectionEndpointId
|    if ($boundDce) {
|        $dce = Invoke-SILogArm -Path $boundDce -ApiVersion (Get-SILogArmApiVersion Dce) -Auth $auth -AllowNotFound
|        if ($dce) { $endpoint = [string]$dce.properties.logsIngestion.endpoint }
|    }
|    if (-not $endpoint -and $dcr.properties.endpoints -and $dcr.properties.endpoints.logsIngestion) { $endpoint = [string]$dcr.properties.endpoints.logsIngestion }
|    if (-not $endpoint -and $DceName) {
|        $dce = Find-SILogResourceByName -Kind Dce -Name $DceName -SubscriptionId $scope.Subscription -ResourceGroup $scope.DceRg -Auth $auth -AnyResourceGroupWhenMissing
|        if ($dce) { $endpoint = [string]$dce.properties.logsIngestion.endpoint }
|    }
|    if (-not $endpoint) { throw ("No ingestion endpoint for data collection rule '{0}' (not bound to an endpoint, and '{1}' was not found), so nothing was posted." -f $DcrName, $DceName) }
|
|    $authText = switch ($auth.Mode) { 'ManagedIdentity' { 'Auth=ManagedIdentity' } 'Certificate' { 'Auth=SPN-Cert' } 'Secret' { 'Auth=SPN' } 'Support' { 'Auth=InvardiaSupport' } default { 'Auth=Run' } }
|    $state = @{
|        Uri = ('{0}/dataCollectionRules/{1}/streams/{2}?api-version=2023-01-01' -f $endpoint.TrimEnd('/'), $immutableId, $stream)
|        Auth = $auth; Compress = [bool]$EnableCompression; MaxBytes = $MaxPayloadBytes; Ratio = 1.0
|        Posted = 0; Bytes = 0L; Batches = 0; Total = $total; Table = $TableName; AuthText = $authText
|    }
|    if ($sender) {
|        $sender.Uri = $state.Uri; $sender.Auth = $auth; $sender.AuthText = $authText; $sender.Compress = [bool]$EnableCompression
|        $sender.MaxBytes = [long][Math]::Min([double]$sender.MaxBytes, [double]$MaxPayloadBytes)
|        return (Send-SILogDataToSender -Sender $sender -Data $Data -DcrName $DcrName)
|    }
|    $batch = New-Object 'System.Collections.Generic.List[byte[]]'
|    $batchBytes = 2
|    foreach ($row in $Data) {
|        $b = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -Depth 100 -InputObject $row -Compress))
|        if (-not $state.Compress -and ($b.Length + 2) -gt $MaxPayloadBytes) {
|            throw ("A single record ({0} bytes) is larger than the {1}-byte limit of the Log Ingestion API, so it cannot be posted." -f ($b.Length + 2), $MaxPayloadBytes)
|        }
|        # raw-bytes ceiling: the limit itself uncompressed; compressed, the limit over the measured ratio (90% margin)
|        $ceiling = if ($state.Compress) { [long][Math]::Min(64MB, [Math]::Floor($MaxPayloadBytes / $state.Ratio * 0.9)) } else { $MaxPayloadBytes }
|        $add = $b.Length + $(if ($batch.Count -gt 0) { 1 } else { 0 })
|        if ($batch.Count -gt 0 -and ($batchBytes + $add) -gt $ceiling) {
|            Send-SILogIngestBatch -Rows $batch -State $state
|            $batch = New-Object 'System.Collections.Generic.List[byte[]]'; $batchBytes = 2; $add = $b.Length
|        }
|        [void]$batch.Add($b); $batchBytes += $add
|    }
|    if ($batch.Count -gt 0) { Send-SILogIngestBatch -Rows $batch -State $state }
|    if ($state.Posted -ne $total) {
|        # #277: the short count is a guard trip -- mailed and reported (never instead of the throw)
|        if (Get-Command -Name Send-SIGuardEvent -ErrorAction Ignore) { $null = Send-SIGuardEvent -GuardId 'ingest.rows.short-count' -Outcome 'refused' -Subject ($TableName + '_CL') -Detail ("Log Analytics accepted {0} of {1} row(s) for {2}_CL." -f $state.Posted, $total, $TableName) -Values @(@{ Name = 'rowsPosted'; Label = 'Rows accepted'; Measured = [long]$state.Posted; Limit = [long]$total }, @{ Name = 'rowsGiven'; Label = 'Rows sent'; Measured = [long]$total }) -HeldCount ([long]$total - [long]$state.Posted) }
|        throw ("Posted {0} of {1} row(s) to {2}_CL -- the other rows are UNKNOWN, not posted." -f $state.Posted, $total, $TableName)
|    }
|    if ([long]$total -gt 0) { Invoke-SILogIngestGuardHeal -Table ($TableName + '_CL') }
|    # BytesPosted: the uncompressed JSON bytes of the rows posted -- a caller that posts in parts sizes its next part from it
|    return [pscustomobject]@{ StatusCode = 204; RowsPosted = $state.Posted; BytesPosted = $state.Bytes; Batches = $state.Batches; Table = ($TableName + '_CL'); Stream = $stream }
|}
'@ }
$__siLauncherFiles['auth/Find-SICertificate.ps1'] = @{ Sha256 = '3778fc328c239b499738360e6b4fb31eb3109db39c3a9a9d8f5a02a228ad58d8'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- find the engine SPN's certificate on ANY host, and bring one into a container (#209).
|
|    KEY POINT: THE `Cert:` DRIVE IS A WINDOWS CONVENIENCE; [X509Store] IS THE AUTHORITY. The drive does not exist
|    in a Linux container at all (pwsh on Linux has no certificate provider), and on Windows it can vanish
|    from a PS 5.1 child that inherited a pwsh 7 PSModulePath (framework finding AUTH-1). Five ingest sites
|    looked a thumbprint up through the drive ONLY, so in a container the lookup always "missed", the store
|    location fell back to LocalMachine, and certificate sign-in could not work there at all.
|
|    Every function here uses the drive when it exists -- exactly what the engines did before -- and the
|    X509Store only when it does not, so a Windows VM with its certificate in LocalMachine\My resolves the
|    same certificate, from the same store, as it always has.
|
|    Functions:
|      Get-SICertificateFromStore    -- one thumbprint -> @{ Certificate; StoreLocation } or $null
|      Get-SICertStoreLocation       -- 'LocalMachine' / 'CurrentUser' for the log-ingestion sign-in (default LocalMachine)
|      Get-SICertificateClientToken  -- client_credentials with a certificate-signed assertion (no Cert: drive)
|      Import-SIContainerCertificate -- a base64 PFX (Key Vault reference) -> CurrentUser\My + a PFX file
|
|    PS 5.1 safe: no ?. / ??, no ImportFromPem.
|#>
|
|function Test-SICertDriveAvailable {
|    <# The Windows certificate provider is loaded in this process. A seam for the tests. #>
|    return [bool](Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)
|}
|
|function Get-SICertificateFromStore {
|    <#
|        Find a certificate WITH a private key by thumbprint, LocalMachine first, then CurrentUser -- the order
|        every SI engine already used. Returns @{ Certificate; StoreLocation } or $null.
|
|        -HasCertDrive and -OpenStore are test seams: -OpenStore takes a store location and returns the
|        certificates in its My store.
|    #>
|    param(
|        [Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint,
|        [string[]]$StoreLocations = @('LocalMachine', 'CurrentUser'),
|        [scriptblock]$HasCertDrive,
|        [scriptblock]$OpenStore
|    )
|    $clean = ($Thumbprint -replace '\s', '').ToUpperInvariant()
|    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
|    if (-not $HasCertDrive) { $HasCertDrive = { Test-SICertDriveAvailable } }
|    if (-not $OpenStore) {
|        $OpenStore = {
|            param([string]$Location)
|            $x = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $Location)
|            try {
|                $x.Open('ReadOnly')
|                return @($x.Certificates)
|            } finally { $x.Close() }
|        }
|    }
|    $drive = [bool](& $HasCertDrive)
|    foreach ($loc in $StoreLocations) {
|        $found = $null
|        if ($drive) {
|            $found = Get-ChildItem "Cert:\$loc\My" -ErrorAction SilentlyContinue |
|                     Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
|                     Select-Object -First 1
|        } else {
|            try {
|                $found = @(& $OpenStore $loc | Where-Object { $_ -and $_.Thumbprint -eq $clean -and $_.HasPrivateKey })[0]
|            } catch {
|                Write-Verbose ("certificate store {0}\My unreadable: {1}" -f $loc, $_.Exception.Message)
|            }
|        }
|        if ($found) { return [pscustomobject]@{ Certificate = $found; StoreLocation = $loc } }
|    }
|    return $null
|}
|
|function Get-SICertStoreLocation {
|    <#
|        The store the log-ingestion sign-in should be told to look in. Same answer the five ingest sites computed
|        through the Cert: drive (LocalMachine when nothing is found), now also right where the drive is
|        missing.
|    #>
|    param(
|        [Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint,
|        [scriptblock]$HasCertDrive,
|        [scriptblock]$OpenStore
|    )
|    $hit = Get-SICertificateFromStore -Thumbprint $Thumbprint -HasCertDrive $HasCertDrive -OpenStore $OpenStore
|    if ($hit) { return [string]$hit.StoreLocation }
|    return 'LocalMachine'
|}
|
|function Get-SICertificateClientToken {
|    <#
|        An access token for -Resource via client_credentials with a certificate-signed JWT assertion -- the
|        grant Get-SIGraphToken and the log ingestion already use, without the Cert: drive. Returns the
|        token string. -Invoke is a test seam: { param($Uri, $Body) } returning the token response.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$TenantId,
|        [Parameter(Mandatory)][string]$ClientId,
|        [Parameter(Mandatory)][string]$Thumbprint,
|        [Parameter(Mandatory)][string]$Resource,
|        [scriptblock]$Invoke
|    )
|    $hit = Get-SICertificateFromStore -Thumbprint $Thumbprint
|    if (-not $hit) { throw ("certificate '{0}' was not found with a private key in LocalMachine\My or CurrentUser\My." -f (($Thumbprint -replace '\s', '').ToUpperInvariant())) }
|    $cert = $hit.Certificate
|
|    $scope = if ($Resource -match '/\.default$') { $Resource } else { ($Resource.TrimEnd('/') + '/.default') }
|    $tokenUri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
|    $b64url = { param([byte[]]$Bytes) [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
|    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
|    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (& $b64url $cert.GetCertHash()) } | ConvertTo-Json -Compress
|    $claims = @{ aud = $tokenUri; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = ($now + 600) } | ConvertTo-Json -Compress
|    $enc = [System.Text.Encoding]::UTF8
|    $unsigned = '{0}.{1}' -f (& $b64url $enc.GetBytes($header)), (& $b64url $enc.GetBytes($claims))
|    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
|    if (-not $rsa) { throw ("certificate '{0}' has no usable RSA private key." -f $cert.Thumbprint) }
|    $sig = $rsa.SignData($enc.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
|    $body = @{
|        client_id             = $ClientId
|        scope                 = $scope
|        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
|        client_assertion      = ('{0}.{1}' -f $unsigned, (& $b64url $sig))
|        grant_type            = 'client_credentials'
|    }
|    $resp = if ($Invoke) { & $Invoke $tokenUri $body }
|            # a time limit: without one this call waits for as long as the other side stays silent (PowerShell 7 has no default)
|            else { Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 }
|    if (-not $resp.access_token) { throw 'the token endpoint returned no access_token.' }
|    return [string]$resp.access_token
|}
|
|function Get-SIContainerCertificateKeyFlags {
|    <# PURE. The key flags the container imports the SPN's PFX with: Exportable + PersistKeySet (the store keeps the key for
|       the life of the run). One place, so a test can pin them. #>
|    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
|        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
|}
|
|function Import-SIContainerCertificate {
|    <#
|        CONTAINER ONLY. The SPN's PFX arrives as a Key Vault-referenced secret (base64), exactly as the SI
|        updater receives its own. This puts it where every engine looks:
|          * CurrentUser\My, through [X509Store] (the only certificate store a Linux container has), so
|            Get-SIGraphToken, the ledger and the log ingestion find it by thumbprint;
|          * a PFX file (owner-only), so Connect-SIAzAccount -CertificatePath can sign in with it -- az and
|            the sign-in remember the PATH, not the key, so the file is kept for the life of the run.
|        Returns @{ Thumbprint; PfxPath }. Never prints the certificate or its password.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$PfxBase64,
|        [string]$Password,
|        [string]$Directory = [IO.Path]::GetTempPath(),
|        [switch]$SkipStore,
|        # TESTS ONLY: a Windows test session that cannot persist a private key (no DPAPI master key) imports with
|        # EphemeralKeySet instead. No caller in the product passes it: the container always uses Get-SIContainerCertificateKeyFlags.
|        [Parameter(DontShow)][AllowNull()][Nullable[System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]]$KeyStorageFlags = $null
|    )
|    $bytes = [Convert]::FromBase64String(($PfxBase64 -replace '\s', ''))
|    $flags = if ($null -ne $KeyStorageFlags) { [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]$KeyStorageFlags } else { Get-SIContainerCertificateKeyFlags }
|    # A Key Vault certificate's secret is a password-less PFX; '' opens those on both .NET hosts.
|    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, [string]$Password, $flags)
|    if (-not $cert.HasPrivateKey) { throw 'the SPN certificate (SI_SPN_CERT_PFX_B64) carries no private key.' }
|
|    if (-not $SkipStore) {
|        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
|        try {
|            $store.Open('ReadWrite')
|            $store.Add($cert)
|        } finally { $store.Close() }
|    }
|
|    $pfxPath = Join-Path $Directory ('si-spn-' + [guid]::NewGuid().ToString('N') + '.pfx')
|    [IO.File]::WriteAllBytes($pfxPath, $bytes)
|    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { try { & chmod 600 $pfxPath } catch { } }
|    return [pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint; PfxPath = $pfxPath }
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-ErrorClass.ps1'] = @{ Sha256 = '5576754be24169a27a22507d84eed2163bf93272095e7849aa77b30802205524'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- WHAT KIND OF FAILURE WAS IT: one error class per failed run, for the telemetry `run` record.
|
|    ExitReason says only success / success-partial / error / settings-error. A release-health view needs to tell "a
|    permission is missing" from "the service was throttling" from "the query is broken", without free text (anonymous
|    installs send no error text at all). Get-SIErrorClass maps an error to exactly ONE value of a CLOSED list -- the list
|    agreed with the receiving side; anything not recognised is 'unknown', never a guess.
|
|    It is built on the classifiers SecurityInsight already trusts:
|      * SI-KqlError.ps1 -- what a Log Analytics failure REALLY said (the response body, not "BadRequest") and whether
|        it was a missing table;
|      * working rule 4 / Risk Analysis' bucket classifier -- the recognised PLATFORM prefixes (a cancellation or a
|        service-side entity resolution carries the service's generic "Fix semantic errors" tail and is NOT a query
|        defect), then syntax / semantic / type errors = query defect, then throttle, then timeout / 5xx.
|
|    The order of the checks is the contract (first match wins):
|      settings-error > guard-refused > out-of-memory > Risk Analysis' "all data paths failed" (its last non-lake attempt,
|      Get-SIDataPathAttemptClass) > database-full > licence-invalid > mi-unavailable > sql-login > config-missing > ingest-short-count >
|      table-missing > platform prefix (timeout / 5xx) > kql-query-defect > throttled > ingest-4xx >
|      401 / 403 by service > ai-error > 413 (platform-5xx) > platform-timeout > platform-5xx > unknown.
|    A 401 from Microsoft Graph is graph-401; a 401 from another service means the same thing as its 403 there (access
|    refused) and gets that service's -403 class.
|
|    PURE. No network. PS 5.1 safe.
|#>
|
|if (-not (Get-Command -Name Get-SIKqlErrorText -ErrorAction SilentlyContinue)) {
|    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-KqlError.ps1'))
|}
|if (-not (Get-Command -Name Test-SISqlShapedFailure -ErrorAction SilentlyContinue)) {
|    . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-SqlRetry.ps1'))
|}
|
|# The closed list, exactly as agreed (#226). Get-SIErrorClass returns one of these and nothing else.
|function Get-SIErrorClassesState {
|    <# The value of $script:SIErrorClasses, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
|    if ($null -eq $script:SIErrorClasses) { $script:SIErrorClasses = @(
|    'graph-401', 'graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'sql-login', 'mi-unavailable',
|    'throttled', 'platform-timeout', 'platform-5xx', 'kql-query-defect', 'table-missing', 'ingest-4xx',
|    'ingest-short-count', 'settings-error', 'config-missing', 'licence-invalid', 'ai-error',
|    # UPLINK-FIX (Invardia, 2026-10-07): a run a guard REFUSED (nothing written, by design). The run's message is
|    # '<guard id> refused: <why>' (Get-SIGuardRefusalText) -- its own class, so a refusal never reads as 'unknown'.
|    'guard-refused',
|    # #641 (owner 2026-10-13): a Risk Analysis report that is NOT COMPLETE in its run (its rows do not match what the source
|    # holds, or it is not in the run at all) -- set by Risk Analysis itself, never derived from a message
|    'report-incomplete',
|    # #702 (1) (customer B 2026-10-15): the process ran out of memory. Its own class, never platform-timeout -- a platform
|    # class is retried in-run on the same size, which runs out again; the job-size rule raises the job one band instead.
|    # (Invardia's receiver takes any ^[a-z0-9-]{1,40}$ class -- packages/core/src/uplink.ts.)
|    'out-of-memory',
|    # #904 (a large install 2026-10-26): Azure SQL refused a write because the database reached its maximum size (1105,
|    # 40544, "has reached its size quota"). Its own class -- never 'unknown' -- so a part that failed on it opens a ticket.
|    'database-full',
|    # #913 (the ride test install 2026-10-27): an Azure SQL transient (9001 log not available, 40613 / 40501 / 40197 /
|    # 49918-49920, 4060 during a failover, 10928 / 10929, a reset connection) that did not pass within its bounded retry.
|    # Set by the caller that retried it (the pipeline runner's lock), never derived from a text: not a product defect.
|    'transient-sql',
|    # 3.0.30: the web app's identity has no grant on its Key Vault key (the updater only checks it; setup makes it) -- the
|    # customer's action with the command, never arm-403 (that is a real 403 answer). Set by the caller, never derived from a text.
|    'grant-missing',
|    # 2026-11-20 (Invardia run-monitor gaps, framework 8.16 "every product warning needs a stable code and a known error
|    # class"): two causes SecurityInsight's OWN warnings name, which reached Invardia as 'unknown' --
|    #   upstream-partial   the run was built on a source run that itself ended 'success-partial' (Risk Analysis "built on
|    #                      incomplete profile data", the CMDB sync "partial snapshot --"): the cause is that source run's own
|    #                      warning, this run only says what it did not count because of it
|    #   column-not-ready   Log Analytics had not finished taking a column change SecurityInsight made in the same run (the
|    #                      data collection rule was changed and new columns were not stored yet; a correlation read that
|    #                      waited for a new column and gave up): the next run stores / reads them
|    'upstream-partial',
|    'column-not-ready',
|    'unknown'
|) }
|    , $script:SIErrorClasses
|}
|$script:SIErrorClasses = $null; $null = Get-SIErrorClassesState
|
|# #904: the numbers of Azure SQL's "the database is full" refusal (1105: no space in the filegroup; 40544: the database
|# reached its size quota; 1101: no new page could be allocated)
|function Get-SIDatabaseFullNumbersState {
|    <# The value of $script:SIDatabaseFullNumbers, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
|    if ($null -eq $script:SIDatabaseFullNumbers) { $script:SIDatabaseFullNumbers = @(1105, 40544, 1101) }
|    , $script:SIDatabaseFullNumbers
|}
|$script:SIDatabaseFullNumbers = $null; $null = Get-SIDatabaseFullNumbersState
|
|# Risk Analysis' recognised platform-failure prefixes (RA-GraphHunting.ps1, $script:RAPlatformFailurePrefixes). Read
|# from there when Risk Analysis is loaded, so the two can never disagree; this copy serves every other engine. A test
|# compares the two lists.
|function Get-SIErrorPlatformPrefixesState {
|    <# The value of $script:SIErrorPlatformPrefixes, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
|    if ($null -eq $script:SIErrorPlatformPrefixes) { $script:SIErrorPlatformPrefixes = @(
|    @{ Pattern = 'Query cancelled on creation'; Class = 'platform-timeout' }
|    @{ Pattern = 'ScalarEvaluator\.Evaluate failed'; Class = 'platform-timeout' }
|    @{ Pattern = 'Errors occurred while resolving remote entities'; Class = 'platform-5xx' }
|) }
|    , $script:SIErrorPlatformPrefixes
|}
|$script:SIErrorPlatformPrefixes = $null; $null = Get-SIErrorPlatformPrefixesState
|
|function Get-SIErrorClasses { (Get-SIErrorClassesState) }
|
|function Test-SIDatabaseFullError {
|    <#
|        PURE. #904: did Azure SQL refuse a write because the database is FULL? -Value: an ErrorRecord, an exception (its
|        SqlException numbers and inner exceptions are read) or a text. SQL 1105 / 40544 / 1101, "has reached its size quota",
|        "filegroup is full", "Could not allocate space" / "Could not allocate a new page".
|    #>
|    param([AllowNull()]$Value)
|    if ($null -eq $Value) { return $false }
|    $ex = if ($Value -is [System.Exception]) { $Value } elseif ($Value -is [System.Management.Automation.ErrorRecord]) { $Value.Exception } else { $null }
|    $texts = New-Object System.Collections.Generic.List[string]
|    while ($ex) {
|        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { if ((Get-SIDatabaseFullNumbersState) -contains [int]$er.Number) { return $true } } }
|        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
|    }
|    if (-not $texts.Count) { $texts.Add([string]$Value) }
|    $t = $texts -join ' | '
|    return [bool]($t -match '(?i)has reached its size quota|filegroup is full|Could not allocate (space|a new page)|\b(Error|Msg|Number)[ :=]*(1105|40544)\b|\((1105|40544)\)')
|}
|
|function Get-SITransientKind {
|    <#
|        PURE. THE ONE DECISION of what a failed call or a failure text REALLY was (2026-10-22: a "Connection timed out" to
|        SI's own storage was reported to the owner as "Microsoft throttled this run"):
|          throttled    Microsoft asked us to slow down -- ONLY a real throttling answer: HTTP 429, "Too Many Requests", a
|                       rate limit, SQL 40501 / 10928 / 10929 (the service is busy / resource limit)
|          timeout      no answer in time: HTTP 408 / 504, SQL -2, "timed out" / "timeout" / a cancelled task
|          unavailable  the service could not be reached or failed: HTTP 500 / 502 / 503, no answer at all (status 0 without a
|                       timeout), a reset / refused / closed connection, a host that does not resolve, SQL 40613 / 40197 /
|                       49918-49920 / 10053 / 10054 / 233 / 64
|          error        anything else (a refusal, a bug, a bad request) -- never retried as transient
|        -StatusCode (an HTTP status; 0 = no answer; -1 = not known), -Message (the error text), -SqlNumber (SqlException numbers).
|        SecurityInsight's OWN customer sentence ("Microsoft throttled this run ...") is taken out of the text first, so a
|        re-read log never classifies itself.
|    #>
|    param([int]$StatusCode = -1, [AllowNull()][AllowEmptyString()][string]$Message = '', [AllowNull()][int[]]$SqlNumber = @())
|    $t = ([string]$Message) -replace '(?i)Microsoft throttled this run[^|]*', ''
|    $sql = @($SqlNumber | Where-Object { $null -ne $_ })
|    if ($StatusCode -eq 429 -or @($sql | Where-Object { $_ -in 40501, 10928, 10929 }).Count -gt 0) { return 'throttled' }
|    if ($t -match '(?i)\b429\b|Too ?Many ?Requests|\bthrottl|rate limit|RequestRateTooLarge') { return 'throttled' }
|    if ($StatusCode -in 408, 504 -or $sql -contains -2) { return 'timeout' }
|    if ($t -match '(?i)timed? ?out|timeout|TaskCanceledException|A task was canceled|operation was canceled|\b504\b|Gateway Time-?out|\b408\b') { return 'timeout' }
|    if ($StatusCode -in 500, 502, 503 -or $StatusCode -eq 0 -or @($sql | Where-Object { $_ -in 40613, 40197, 49918, 49919, 49920, 10053, 10054, 233, 64 }).Count -gt 0) { return 'unavailable' }
|    if ($t -match '(?i)\b50[0-3]\b|Internal ?Server ?Error|Bad Gateway|Service ?Unavailable|ServiceUnavailable|temporarily unavailable|is not currently available|forcibly closed|connection (was )?reset|Connection reset by peer|actively refused|No such host is known|Name or service not known|transport-level error|Unable to connect to the remote server') { return 'unavailable' }
|    'error'
|}
|
|function Test-SIOutOfMemoryText {
|    <# PURE. Does a failure text (or an exception / ErrorRecord, read with its inner exceptions) say the process ran out of
|       memory? .NET's OutOfMemoryException (also wrapped: "Exception calling ... : Exception of type
|       'System.OutOfMemoryException' was thrown", "Cannot process argument transformation on parameter 'TimeoutSec'. ..."),
|       Container Apps' OOMKilled, or SecurityInsight's own "out of memory" wording. #702 (1). #>
|    param([AllowNull()]$Value)
|    if ($null -eq $Value) { return $false }
|    $ex = if ($Value -is [System.Exception]) { $Value } elseif ($Value -is [System.Management.Automation.ErrorRecord]) { $Value.Exception } else { $null }
|    while ($ex) { if ($ex -is [System.OutOfMemoryException]) { return $true }; $ex = $ex.InnerException }
|    $t = if ($Value -is [System.Management.Automation.ErrorRecord]) { [string]$Value.Exception } else { [string]$Value }
|    return [bool]($t -match '(?i)OutOfMemoryException|\bOOMKilled\b|\bout of memory\b')
|}
|
|# WHO FIXES IT (framework §8.5 CLOSE-LOOP, Invardia 046): the classes whose fix is the CUSTOMER's configuration -- a
|# permission or consent the install's identity does not have (the five -403 classes), a licence or licensed feature it
|# lacks (licence-invalid), a setting the customer must set (config-missing, settings-error). Everything else -- sign-in
|# and token trouble, a missing table, ingestion, throttling, timeouts, service errors, guard refusals, unknown -- stays a
|# product defect: a class is put here only when its own definition above says the customer's configuration is the cause.
|function Get-SICustomerConfigClassesState {
|    <# The value of $script:SICustomerConfigClasses, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
|    if ($null -eq $script:SICustomerConfigClasses) { $script:SICustomerConfigClasses = @('graph-403', 'defender-403', 'arm-403', 'kv-403', 'storage-403', 'licence-invalid', 'config-missing', 'settings-error', 'grant-missing') }
|    , $script:SICustomerConfigClasses
|}
|$script:SICustomerConfigClasses = $null; $null = Get-SICustomerConfigClassesState
|# #913: the classes that are nobody's fix -- an Azure SQL transient that did not pass within its bounded retry. No FixKind:
|# never a fix request, never a red alert (the next wake-up runs as usual).
|function Get-SINoFixClassesState {
|    <# The value of $script:SINoFixClasses, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
|    if ($null -eq $script:SINoFixClasses) { $script:SINoFixClasses = @('transient-sql') }
|    , $script:SINoFixClasses
|}
|$script:SINoFixClasses = $null; $null = Get-SINoFixClassesState
|
|function Get-SICustomerConfigClasses { (Get-SICustomerConfigClassesState) }
|
|function Get-SIErrorFixKind {
|    <#
|        PURE. The FixKind of a failed report's error class: 'customer-config' for a class on the customer-configuration list,
|        'product-defect' for every other class of the closed list (and anything not on it), '' when there is no class.
|    #>
|    param([AllowEmptyString()][AllowNull()][string]$ErrorClass)
|    $c = "$ErrorClass".Trim().ToLowerInvariant()
|    if (-not $c) { return '' }
|    if ((Get-SINoFixClassesState) -contains $c) { return '' }
|    if ((Get-SICustomerConfigClassesState) -contains $c) { return 'customer-config' }
|    'product-defect'
|}
|
|function Get-SIErrorService {
|    <# PURE. Which service a failure came from, by the host or the wording it carries: graph | defender | arm | kv |
|       storage | sql | ingest | ai | loganalytics | ''. #>
|    param([AllowEmptyString()][string]$Text)
|    $t = [string]$Text
|    if ($t -match '(?i)ingest\.monitor\.azure\.com|Logs Ingestion|log ingestion|dataCollectionRules|\bDCR\b|\bDCE\b|InvalidTransformOutput') { return 'ingest' }
|    if ($t -match '(?i)openai\.azure\.com|\bOpenAI\b|content_filter|context_length_exceeded|DeploymentNotFound|chat/completions') { return 'ai' }
|    if ($t -match '(?i)api\.securitycenter\.microsoft\.com|api\.security\.microsoft\.com|security/runHuntingQuery|advanced hunting|Microsoft Defender|\bMachine\.Read\.All\b|\bThreatHunting\.Read\.All\b') { return 'defender' }
|    if ($t -match '(?i)\.vault\.azure\.net|Key ?Vault|ForbiddenByRbac|ForbiddenByPolicy|secrets get permission|getSecret/action') { return 'kv' }
|    if ($t -match '(?i)\.(blob|table|queue|file|dfs)\.core\.windows\.net|AuthorizationPermissionMismatch|AuthorizationFailure|storage account') { return 'storage' }
|    if ($t -match '(?i)database\.windows\.net|SqlException|SqlClient|\bLogin failed\b') { return 'sql' }
|    if ($t -match '(?i)management\.azure\.com|AuthorizationFailed|Microsoft\.[A-Za-z]+/[A-Za-z]+/[A-Za-z/]*(read|write|action)|\bAzure Resource Manager\b|LinkedAuthorizationFailed') { return 'arm' }
|    if ($t -match '(?i)graph\.microsoft\.com|Authorization_RequestDenied|Microsoft Graph|InvalidAuthenticationToken') { return 'graph' }
|    if ($t -match '(?i)api\.loganalytics|loganalytics\.io|Log Analytics|SEM\d{4}|SYN\d{4}') { return 'loganalytics' }
|    ''
|}
|
|function Get-SIErrorLines {
|    <#
|        PURE. A failed run's own words from its log (a run transcript, a console tail): the error that ENDED it -- the LAST
|        [ERROR] / exception / failed / refused / denied / status-code block (transcript TerminatingError markers and WARNING:
|        lines only when nothing else is there), and the lines after it up to -Max, else -- no such line --
|        the LAST -Max lines that carry text. Transcript headers / footers and the ******** frames are dropped. Never the whole
|        log: the uplink carries a few lines, and the caller redacts them (ConvertTo-AitUplinkRedacted). '' for no text.
|    #>
|    param([AllowNull()][AllowEmptyCollection()][string[]]$Lines = @(), [int]$Max = 8, [int]$MaxChars = 1800)
|    $keep = New-Object System.Collections.Generic.List[string]
|    $inHeader = $false
|    foreach ($raw in @($Lines)) {
|        $l = ([string]$raw).TrimEnd()
|        if (-not $l.Trim()) { continue }
|        if ($l -match '^\*{10,}$') { $inHeader = -not $inHeader; continue }
|        if ($inHeader) { continue }
|        if ($l -match '^(PowerShell|Windows PowerShell) transcript (start|end)|^(Start|End) time: \d{14}|^Transcript started, output file is') { continue }
|        $keep.Add($l.Trim())
|    }
|    if (-not $keep.Count) { return '' }
|    $err = '(?i)\[(ERROR|FAIL(ED)?|FATAL)\]|\bERROR\b|Exception|\bfailed\b|could not|cannot|refused|denied|Forbidden|Unauthorized|Login failed|\b(40[0-9]|429|50[0-4])\b|throttl|timed? ?out'
|    # The error that ENDED the run, not the first one in the log: every error-looking line is a candidate; the
|    # transcript's own "PS>TerminatingError(...)" / ">> TerminatingError(...)" markers (written for an error the code
|    # CAUGHT and went on after) and WARNING: lines count only when the log has no other error line. The LAST such line
|    # is taken, from the start of its block (the error lines right before it), and the lines after it up to -Max.
|    $isErr = { param($s) $s -match $err -and $s -notmatch '(?i)^\s*(VERBOSE|DEBUG)\b|\b0 (failed|errors?)\b' }
|    $isWeak = { param($s) $s -match '(?i)^\s*(PS>|>>\s*)TerminatingError\(|^\s*WARNING:' }
|    $strong = -1; $weak = -1
|    for ($i = 0; $i -lt $keep.Count; $i++) {
|        if (-not (& $isErr $keep[$i])) { continue }
|        if (& $isWeak $keep[$i]) { $weak = $i } else { $strong = $i }
|    }
|    $first = if ($strong -ge 0) { $strong } else { $weak }
|    if ($first -ge 0) {
|        $wantWeak = ($strong -lt 0)
|        while ($first -gt 0 -and (& $isErr $keep[$first - 1]) -and ($wantWeak -or -not (& $isWeak $keep[$first - 1]))) { $first-- }
|    }
|    $pick = if ($first -ge 0) { @($keep.GetRange($first, [Math]::Min($Max, $keep.Count - $first))) } else { @($keep.GetRange([Math]::Max(0, $keep.Count - $Max), [Math]::Min($Max, $keep.Count))) }
|    $t = ($pick -join "`n")
|    if ($t.Length -gt $MaxChars) { $t = $t.Substring(0, $MaxChars) }
|    $t
|}
|
|function Get-SIErrorRecordSummary {
|    <# PURE. The words of a caught error, never empty: its message, else its exception type + error id + where it was
|       raised (an exception thrown without a message reached Invardia as an empty text -- si-trend x5). #>
|    param([AllowNull()]$ErrorRecord)
|    if ($null -eq $ErrorRecord) { return '' }
|    $ex = if ($ErrorRecord -is [System.Exception]) { $ErrorRecord } elseif ($ErrorRecord.PSObject.Properties['Exception']) { $ErrorRecord.Exception } else { $null }
|    $m = if ($ex) { "$($ex.Message)".Trim() } else { "$ErrorRecord".Trim() }
|    if ($m) { return $m }
|    $parts = New-Object System.Collections.Generic.List[string]
|    if ($ex) { $parts.Add($ex.GetType().FullName) }
|    if ($ErrorRecord.PSObject.Properties['FullyQualifiedErrorId'] -and "$($ErrorRecord.FullyQualifiedErrorId)".Trim()) { $parts.Add("id $($ErrorRecord.FullyQualifiedErrorId)") }
|    if ($ErrorRecord.PSObject.Properties['InvocationInfo'] -and $ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.ScriptName) { $parts.Add(('at {0}:{1}' -f (Split-Path -Leaf $ErrorRecord.InvocationInfo.ScriptName), $ErrorRecord.InvocationInfo.ScriptLineNumber)) }
|    if (-not $parts.Count) { return 'an error without a message' }
|    'an error without a message (' + ($parts -join ', ') + ')'
|}
|
|function Get-SIDataPathAttemptClass {
|    <#
|        PURE. SUP-2026-00496. Risk Analysis says ONE warning when every data path of a query failed (Flush-SupersededAttempts,
|        RA-RunProgress.ps1):
|            all data paths failed for this query; attempts: <path>: <words> || <path>: <words> ...
|        in the order the paths were tried (lake, then advanced hunting or Log Analytics direct). The Sentinel data lake is an
|        OPTIONAL path -- not onboarded, or not open to SecurityInsight's identity ("InvalidDatabaseInQuery ... is not
|        available for current user", 401 / 403, TenantNotFound) is a supported state, never a failure by itself. So the class
|        is the LAST attempt that is not the lake, classified with its service (advanced hunting = defender, Log Analytics
|        direct = loganalytics): a platform answer (429 / 5xx / 504 / timeout / 413) is the platform's class, a 400 syntax /
|        semantic answer kql-query-defect, a 401 / 403 on the path that should work that service's access class.
|        Only lake attempts (the shape before 3.1.9, which never listed the last path's answer -- on 3.1.7 that answer was
|        advanced hunting refusing the completeness count for its size, 413): a lake refusal gives platform-5xx (the class a
|        413 gets), any other lake answer its own class. '' when the text is not this warning.
|    #>
|    param([AllowEmptyString()][AllowNull()][string]$Text)
|    $m = [regex]::Match([string]$Text, '(?i)all data paths failed for this query; attempts: ([^\r\n]+)')
|    if (-not $m.Success) { return '' }
|    $atts = New-Object System.Collections.Generic.List[object]
|    foreach ($part in ($m.Groups[1].Value -split ' \|\| ')) {
|        $pm = [regex]::Match($part.Trim(), '^([A-Za-z][A-Za-z-]*): (.*)$')
|        if ($pm.Success) { $atts.Add([pscustomobject]@{ Path = $pm.Groups[1].Value; Words = $pm.Groups[2].Value }) }
|        elseif ($part.Trim()) { $atts.Add([pscustomobject]@{ Path = ''; Words = $part.Trim() }) }
|    }
|    if (-not $atts.Count) { return '' }
|    $real = @($atts | Where-Object { $_.Path -ne 'lake' })
|    if ($real.Count -gt 0) {
|        $last = $real[$real.Count - 1]
|        $hint = switch -Regex ([string]$last.Path) { '^(?i)advanced-hunting|hybrid$' { 'defender' } '^(?i)LA-direct$' { 'loganalytics' } default { '' } }
|        $c = Get-SIErrorClass -Message ([string]$last.Words) -Service $hint
|        return $c
|    }
|    $lake = $atts[$atts.Count - 1]
|    if ([string]$lake.Words -match '(?i)InvalidDatabaseInQuery|not available for current user|TenantNotFound|Tenant not registered|\b40[134]\b|Forbidden|Unauthorized|Not Found|NotFound') { return 'platform-5xx' }
|    Get-SIErrorClass -Message ([string]$lake.Words)
|}
|
|function Get-SIErrorClass {
|    <#
|        PURE. The error class of one failure -- exactly one value of Get-SIErrorClasses.
|          -ErrorRecord  an ErrorRecord or an exception (its message, response body, typed body and inner exceptions are
|                        all read -- Get-SIKqlErrorText)
|          -Message      a text (a run-health ErrorMessage, a log line)
|          -ExitReason   the run's ExitReason: 'settings-error' is its own class whatever the text says
|          -Service      a hint when the caller knows which service it called (graph, defender, arm, kv, storage, sql,
|                        ingest, ai) -- used when the text does not name one
|    #>
|    param([AllowNull()]$ErrorRecord, [AllowEmptyString()][AllowNull()][string]$Message, [AllowEmptyString()][string]$ExitReason, [AllowEmptyString()][string]$Service)
|    if ($ExitReason -eq 'settings-error') { return 'settings-error' }
|    if ("$Message" -match '^[a-z0-9][a-z0-9.-]{0,99} refused: ') { return 'guard-refused' }
|    $parts = New-Object System.Collections.Generic.List[string]
|    if ($null -ne $ErrorRecord) { $parts.Add((Get-SIKqlErrorText -ErrorRecord $ErrorRecord)) }
|    if ($Message) { $parts.Add($Message) }
|    $t = ($parts | Where-Object { $_ }) -join ' | '
|    # #702 (1): out of memory ANYWHERE in the text wins over every service / platform word around it (customer B's
|    # "... parameter 'TimeoutSec'. Exception of type 'System.OutOfMemoryException' was thrown" read as platform-timeout)
|    if ((Test-SIOutOfMemoryText $t) -or ($null -ne $ErrorRecord -and (Test-SIOutOfMemoryText $ErrorRecord))) { return 'out-of-memory' }
|    if ([string]::IsNullOrWhiteSpace($t)) { return 'unknown' }
|    # SUP-2026-00496: Risk Analysis' ONE warning when every data path of a query failed -- the class is the LAST real attempt's
|    $__paths = Get-SIDataPathAttemptClass -Text $t
|    if ($__paths) { return $__paths }
|    # #904: the database is full -- before every service / platform word (its text names SQL and often a timeout)
|    if ((Test-SIDatabaseFullError $t) -or ($null -ne $ErrorRecord -and (Test-SIDatabaseFullError $ErrorRecord))) { return 'database-full' }
|    # 2026-10-29: a temporary Azure SQL error that outlasted SecurityInsight's own retry is TAGGED by the code that retried
|    # it -- its message ends "-- transient-sql" (SI-DataSql.ps1, the pipeline lock); the step's log carries that line, so the
|    # pipeline's report of the step names the platform's class, never a product defect
|    if ($t -match '(?i)--\s*transient-sql\b') { return 'transient-sql' }
|    # The same answer arriving untagged (a statement outside the retry, or a tag that only travels on the exception): a SQL
|    # statement's own failure that the statement retry's test accepts. Nothing is added to that test here: what it does not
|    # know stays unknown and is seen as such.
|    $__sqlErr = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -or $ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $t }
|    if ((Test-SISqlShapedFailure -Text $t -ErrorRecord $ErrorRecord) -and (Test-SISqlStatementTransient -ErrorRecord $__sqlErr)) { return 'transient-sql' }
|    $svc =Get-SIErrorService -Text $t
|    if (-not $svc -and $Service) { $svc = $Service.ToLowerInvariant() }
|
|    # ---- the run's own configuration ----------------------------------------------------------------------------------
|    if ($t -match '(?i)SecurityInsight Pro: .*settings database|in the settings database are not valid|settings documents could not be prepared') { return 'settings-error' }
|    if ($t -match '(?i)\blicen[cs]e\b.*\b(invalid|not valid|expired|signature verification FAILED|tampered|no entitlement|not readable|could not be read|does not include feature|names no SecurityInsight Pro edition|does not list it)\b|no \.(pimlicense|silicense|aitlicense)|not an AutomateIT licence|signature verification FAILED.*licensing key') { return 'licence-invalid' }
|
|    # ---- identity / sign-in -----------------------------------------------------------------------------------------
|    if ($t -match '(?i)ManagedIdentityCredential|No Managed Identity endpoint|169\.254\.169\.254|IDENTITY_ENDPOINT|\bIMDS\b|MSI endpoint|managed identity.*(unavailable|not available|not found|could not|failed|is not loaded)|identity token helper is not loaded') { return 'mi-unavailable' }
|    if ($t -match "(?i)Login failed for user|Cannot open (server|database) .* requested by the login|\b18456\b|token-identified principal") { return 'sql-login' }
|    if ($t -match "(?i)Cannot (bind|validate) argument (to|on) parameter '(Az)?(ApplicationId|AppId|TenantId|ClientId|CertificateThumbprint|Thumbprint|SubscriptionId|VaultName|WorkspaceId|DcrImmutableId|DceUri|ServicePrincipal\w*)' because it is (an empty string|null)|is not (set|configured)|not found in the configuration|the Pro database is not configured|certificate .* was not found") { return 'config-missing' }
|
|    # ---- ingestion --------------------------------------------------------------------------------------------------
|    if ($t -match '(?i)wrote fewer rows than it carried|fewer rows than (were )?(sent|posted|expected)|short count|rows? (were )?(lost|dropped) (at|during) ingest|accepted \d+ of \d+ rows') { return 'ingest-short-count' }
|
|    # ---- SecurityInsight's own sentence for a column Log Analytics has not finished taking (before the query rules: the
|    # correlation's give-up sentence quotes the service's "Failed to resolve scalar expression", which is not a query defect)
|    if ($t -match (Get-SIOwnWarningPatternsState).ColumnNotReady) { return 'column-not-ready' }
|
|    # ---- Log Analytics / advanced hunting: the query and the tables -------------------------------------------------
|    # #876: a 'union' leaf says "table expression", a 'where' leaf "table or column expression" -- both: the table is not there
|    if ($t -match "Failed to resolve table (?:or column )?expression named \\?['""]?([A-Za-z0-9_]+)") {
|        $name = $Matches[1]
|        if ($name -match '(?i)_CL$' -or $t -match '(?i)\btable\b.*(could not be found|does not exist)') { return 'table-missing' }
|    }
|    if ($t -match "(?i)\btable\b[^|]{0,120}\b(could not be found|does not exist)|unknown table|PathNotFoundError|not present in this tenant's advanced hunting schema") { return 'table-missing' }
|    foreach ($p in (Get-SIErrorPlatformPrefixesState)) { if ($t -match $p.Pattern) { return $p.Class } }
|    if ($t -match '(?i)Fix syntax errors in your query|Fix semantic errors in your query|SyntaxError|SemanticError|return types are not compatible|\bSEM\d{4}\b|\bSYN\d{4}\b|Expected: .* in query|Failed to resolve (scalar|table or column|table) expression') { return 'kql-query-defect' }
|
|    # ---- throttling -------------------------------------------------------------------------------------------------
|    # ONE decision (Get-SITransientKind): only a real throttling answer is 'throttled'. A Retry-After header alone is not
|    # (a 503 sends one too); SI's own "Microsoft throttled this run" sentence never classifies itself.
|    if ((Get-SITransientKind -Message $t) -eq 'throttled') { return 'throttled' }
|
|    # ---- status codes, by service -----------------------------------------------------------------------------------
|    $code = $null
|    if ($t -match '(?i)\((4\d\d)\)|status code (?:does not indicate success: )?(4\d\d)\b|\b(4\d\d) \((Bad Request|Unauthorized|Forbidden|Not Found|Request Entity Too Large|Conflict)\)|''(BadRequest|Unauthorized|Forbidden|NotFound|RequestEntityTooLarge)''') {
|        $code = @($Matches[1], $Matches[2], $Matches[3], $Matches[5]) | Where-Object { $_ } | Select-Object -First 1
|    }
|    $named = @{ BadRequest = '400'; Unauthorized = '401'; Forbidden = '403'; NotFound = '404'; RequestEntityTooLarge = '413' }
|    if ($code -and $named.ContainsKey($code)) { $code = $named[$code] }
|    $is401 = ($code -eq '401') -or ($t -match '(?i)\bUnauthorized\b|InvalidAuthenticationToken|token is expired|Lifetime validation failed')
|    $is403 = ($code -eq '403') -or ($t -match '(?i)\bForbidden\b|Authorization_RequestDenied|AuthorizationFailed|AuthorizationPermissionMismatch|Insufficient privileges|does not have authorization|does not have (any of )?the required|is not authorized to perform|ForbiddenByRbac|ForbiddenByPolicy|Access denied')
|    if ($svc -eq 'ingest' -and ($code -match '^4\d\d$' -or $is401 -or $is403 -or $t -match '(?i)InvalidTransformOutput|is not associated with DCR|DCE FQDN')) { return 'ingest-4xx' }
|    if ($is401 -or $is403) {
|        switch ($svc) {
|            'graph'    { if ($is401 -and -not $is403) { return 'graph-401' } else { return 'graph-403' } }
|            'defender' { return 'defender-403' }
|            'arm'      { return 'arm-403' }
|            'kv'       { return 'kv-403' }
|            'storage'  { return 'storage-403' }
|            'sql'      { return 'sql-login' }
|            'ai'       { return 'ai-error' }
|            # SUP-2026-00496: Log Analytics access is Azure RBAC on the workspace -- a refusal there is the ARM class
|            'loganalytics' { if ($is401 -and -not $is403) { return 'graph-401' } else { return 'arm-403' } }
|            default    { if ($is401 -and -not $is403) { return 'graph-401' } }
|        }
|    }
|
|    # ---- AI ---------------------------------------------------------------------------------------------------------
|    if ($svc -eq 'ai') { return 'ai-error' }
|
|    # SUP-2026-00496: a request the service refused for its SIZE (413, the advanced-hunting front end's 1 MB cap). The
|    # engine answers it itself (smaller slices, a count in parts) -- the platform family the too-large 502 is in, never a
|    # query defect and never the customer's. (Ingestion's own 4xx keeps its class above.)
|    if ($svc -ne 'ingest' -and $t -match '(?i)\b413\b|Request Entity Too Large|RequestEntityTooLarge') { return 'platform-5xx' }
|
|    # ---- the platform -----------------------------------------------------------------------------------------------
|    switch (Get-SITransientKind -Message $t) {
|        'timeout'     { return 'platform-timeout' }
|        'unavailable' { return 'platform-5xx' }
|    }
|    # Log Analytics failed on its own side (a PartialError / EngineError answer: "Something went wrong processing your query
|    # on the server", "ExecuteRemoteSubQuery failure ... Unavailable") -- the platform's, never a query defect. Only here,
|    # never in Get-SITransientKind: what is retried in-run stays exactly what it was.
|    if ($t -match (Get-SIOwnWarningPatternsState).LogAnalyticsServerSide) { return 'platform-5xx' }
|
|    # ---- SecurityInsight's OWN warning sentences: they classify only a text nothing above recognised (a real failure named
|    # in the same text always wins -- first match wins) -------------------------------------------------------------------
|    if ($t -match (Get-SIOwnWarningPatternsState).ReportsIncomplete) { return 'report-incomplete' }
|    if ($t -match (Get-SIOwnWarningPatternsState).UpstreamPartial) { return 'upstream-partial' }
|    'unknown'
|}
|
|function Get-SIOwnWarningPatternsState {
|    <#
|        The value of $script:SIOwnWarningPatterns, made on first use in the scope that reads it. The ONE place the sentences
|        SecurityInsight writes itself are recognised (the classifier above and the run fault codes, Resolve-SIRunFaultCode in
|        SI-UplinkCauses.ps1, read the same patterns -- a reworded sentence is one edit here and its tests):
|          UpstreamPartial         Risk Analysis' Get-SIUpstreamOutcome (SI-RunOutcome.ps1) / the CMDB sync's
|                                  Format-SICmdbSqlPartialText (SI-CmdbSqlSync.ps1)
|          ColumnNotReady          the endpoint ingest note 'not-stored' (SI-LogIngest.ps1) / the correlation's settled read
|                                  that gave up (Invoke-SICorrelationSettledRead, SI-CorrelationIngest.ps1)
|          ReportsIncomplete       Format-RAIncompleteReports (RA-RowCountGuard.ps1)
|          LogAnalyticsServerSide  the Log Analytics answer for a failure on its own side
|    #>
|    if ($null -eq $script:SIOwnWarningPatterns) { $script:SIOwnWarningPatterns = [pscustomobject]@{
|        UpstreamPartial        = '(?i)\bbuilt on incomplete profile data\b|\bpartial snapshot -- '
|        UpstreamProfile        = '(?i)\bbuilt on incomplete profile data\b'
|        UpstreamSnapshot       = '(?i)\bpartial snapshot -- '
|        ColumnNotReady         = '(?i)Azure was not yet storing every column when the rows arrived|Log Analytics has not finished adding the new column'
|        ReportsIncomplete      = '(?i)\breport\(s\) incomplete -- their findings are unknown'
|        LogAnalyticsServerSide = '(?i)Something went wrong processing your query on the server|ExecuteRemoteSubQuery failure'
|    } }
|    $script:SIOwnWarningPatterns
|}
|$script:SIOwnWarningPatterns = $null; $null = Get-SIOwnWarningPatternsState
'@ }
$__siLauncherFiles['engine/_shared/SI-KqlError.ps1'] = @{ Sha256 = 'ee8dfba0c796cb9c3a24f592a058e3b1223b4edff9a71df30d7bd65465d14221'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- what a failed Log Analytics query actually said (#221).
|
|    WHY. Az.OperationalInsights throws ErrorResponseException whose MESSAGE is only
|    "Operation returned an invalid status code 'BadRequest'". The reason -- e.g. SEM0100 "Failed to resolve table or
|    column expression named 'SI_PublicIP_Profile_CL'" -- is in the response body (Exception.Response.Content /
|    Exception.Body). Measured 2026-10-03 on 3.4.0 (container) and 3.4.1 (the development machine), PS 5.1 and pwsh 7 alike.
|    Readers that classified on the message therefore never recognised a MISSING table: on a fresh install, where a
|    profile or Risk Analysis table does not exist yet, correlation, trend and the close-loop failed outright.
|
|    A missing table is the ONLY error a reader may treat as "no data here yet". Everything else still fails loudly --
|    a throttle or timeout must never pass as an empty table (#132).
|
|    PS 5.1 safe: no ?. / ??.
|#>
|
|function Get-SIKqlErrorText {
|    <# PURE. Every text a Log Analytics query failure carries: the message, the response body, the typed body, inner
|       exceptions and ErrorDetails -- joined, so a caller can classify on what the service really said. #>
|    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord)
|    if ($null -eq $ErrorRecord) { return '' }
|    $parts = New-Object System.Collections.Generic.List[string]
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
|    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
|        $parts.Add([string]$ErrorRecord.ErrorDetails.Message)
|    }
|    $depth = 0
|    while ($ex -and $depth -lt 5) {
|        $parts.Add([string]$ex.Message)
|        if ($ex.PSObject.Properties['Response'] -and $ex.Response) {
|            $c = $null
|            if ($ex.Response.PSObject.Properties['Content']) { $c = $ex.Response.Content }
|            if ($c) { $parts.Add([string]$c) }
|        }
|        if ($ex.PSObject.Properties['Body'] -and $ex.Body) {
|            try { $parts.Add((ConvertTo-Json -InputObject $ex.Body -Depth 8 -Compress)) } catch { $parts.Add([string]$ex.Body) }
|        }
|        $ex = $ex.InnerException
|        $depth++
|    }
|    return (($parts | Where-Object { $_ }) -join ' | ')
|}
|
|function Get-SIKqlErrorSummary {
|    <# PURE. ONE log-ready line: the exception message plus the service's own error code(s) and the innermost
|       message, e.g. "Operation returned an invalid status code 'BadRequest' -- SemanticError/SEM0100: 'summarize'
|       operator: Failed to resolve scalar expression named 'AssetName'". Without it a query defect logs only
|       "BadRequest", which says nothing about what to fix. The bare message is kept at the front so classifiers that
|       match on it (BadRequest, TaskCanceledException, 502 ...) see exactly what they saw before. #>
|    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord)
|    if ($null -eq $ErrorRecord) { return '' }
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
|    $base = if ($ex -and $ex.PSObject.Properties['Message']) { [string]$ex.Message } else { [string]$ex }
|    $text = Get-SIKqlErrorText -ErrorRecord $ErrorRecord
|    if (-not $text) { return $base }
|    # The Log Analytics body nests the reason: error -> innererror (SemanticError / SyntaxError) -> innererror
|    # (SEM0100 ...). Collect the innererror chain of the first body found; the deepest message is the useful one.
|    $rx = '"innererror"\s*:\s*\{\s*"code"\s*:\s*"([^"]*)"\s*,\s*"message"\s*:\s*"((?:[^"\\]|\\.)*)"'
|    $ms = [regex]::Matches($text, $rx)
|    if ($ms.Count -eq 0) { return $base }
|    $codes = New-Object System.Collections.Generic.List[string]
|    $msg = ''
|    foreach ($m in $ms) {
|        $c = $m.Groups[1].Value
|        if ($codes.Contains($c)) { break }   # a second copy of the same body (typed body / ErrorDetails) starts here
|        $codes.Add($c)
|        $msg = $m.Groups[2].Value
|    }
|    try { $msg = [regex]::Unescape($msg) } catch { }
|    $detail = ('{0}: {1}' -f ($codes -join '/'), $msg)
|    if ($base -and $base.Contains($msg)) { return $base }
|    if (-not $base) { return $detail }
|    return ('{0} -- {1}' -f $base, $detail)
|}
|
|function Test-SIKqlTableMissing {
|    <# PURE. True only when the failure says THIS table does not exist in the workspace. #>
|    param([Parameter(Mandatory)][AllowNull()]$ErrorRecord, [Parameter(Mandatory)][string]$TableName)
|    $t = Get-SIKqlErrorText -ErrorRecord $ErrorRecord
|    if (-not $t) { return $false }
|    $name = [regex]::Escape($TableName)
|    # #876: a 'union' leaf says "table expression", a 'where' leaf "table or column expression" -- both: the table is not there
|    if ($t -match ("Failed to resolve table (?:or column )?expression named \\?['""]?{0}" -f $name)) { return $true }
|    if ($t -match $name -and $t -match '(?i)SEM0100|could not be found|does not exist|unknown table') { return $true }
|    return $false
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-SqlRetry.ps1'] = @{ Sha256 = '6b45df7c956cb7b1d1d37f1a171ef366f153f23d6dc923903db9b1b2fc66a8b0'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- THE ONE SQL CONNECTION RETRY (owner 2026-10-22: "why not use shared everywhere" / "stability is prio
|    also"). Moved here from setup\_shared\SI-SetupArm.ps1 (Open-SISqlConnectionRetry, Test-SISqlNotYetAnswer) and
|    engine\data-model\identity\SI-ObjectLedgerStore.ps1 (Test-SISqlTransientError), so the engine, the updater and setup open
|    a database the same way.
|
|    ONLY THE OPEN IS RETRIED. A statement that may already have run is never sent again by this file: an Open that failed
|    sent nothing.
|
|    PURE except Open-SISqlConnectionRetry's default -Connect (System.Data.SqlClient). PS 5.1 safe. Community + Pro.
|#>
|
|function Test-SISqlTransientError {
|    <#
|        Azure SQL faults worth another attempt at OPENING the connection. Deliberately a short, named list rather than
|        "retry anything": retrying a permission or a syntax error just delays a real failure.
|          40613 database not currently available (a serverless resume, or a failover)
|          40197 / 40501 / 49918 / 49919 / 49920  service busy, throttled or moving
|          4060  cannot open database right now
|          10928 / 10929 resource limits
|        -2 / 258 client timeouts
|        -ErrorRecord: an ErrorRecord or an exception (inner exceptions are read too).
|    #>
|    param([Parameter(Mandatory)]$ErrorRecord)
|    $codes = @(40613, 40197, 40501, 49918, 49919, 49920, 4060, 10928, 10929, -2, 258)
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
|    while ($ex) {
|        if ($ex -is [System.Data.SqlClient.SqlException] -and $codes -contains [int]$ex.Number) { return $true }
|        $ex = $ex.InnerException
|    }
|    $msg = [string]$ErrorRecord
|    if ($ErrorRecord -is [System.Exception]) { $msg = [string]$ErrorRecord.Message }
|    return ($msg -match 'is not currently available|Please retry the connection later|too busy|try again')
|}
|
|function Test-SISqlStatementTransient {
|    <#
|        PURE and SELF-CONTAINED (it travels as a value into connection closures: it calls nothing by name). Is a failed SQL
|        STATEMENT one of Azure SQL's platform answers, so the statement may be run again on a new connection? Live 2026-10-28:
|        one statement of the data sync got 9001 (the log is not available) + 3314 (a rollback during recovery) + "A severe
|        error occurred on the current command" after minutes of a saturated log, and a 52-hour run failed on it.
|          transient: 9001, 3314, 40613, 40501, 40197, 49918 / 49919 / 49920 (not available, busy, moving), 4060 (cannot open
|                     the database during a failover), 10928 / 10929 (resource limits), 1205 (chosen as a deadlock victim),
|                     -2 / 258 (a client timeout), 10053 / 10054 / 233 / 64 (a reset or closed connection), 4083 ("the
|                     connection was recovered and rowcount in the first query is not available": the driver re-made an idle
|                     connection under the statement -- live 2026-11-04, a correlation run's CI build failed on it), "a severe error
|                     occurred on the current command", a transport-level error, a broken pooled connection ("Internal .NET
|                     Framework Data Provider error 6").
|          never:     the database is full (1105 / 40544 / 1101), a query defect (syntax, a type mismatch), a permission -- they
|                     fail on the first attempt.
|        -ErrorRecord: an ErrorRecord, an exception (SqlException numbers and inner exceptions are read) or a text.
|    #>
|    param([AllowNull()]$ErrorRecord)
|    if ($null -eq $ErrorRecord) { return $false }
|    $codes = @(9001, 3314, 40613, 40501, 40197, 49918, 49919, 49920, 4060, 10928, 10929, 1205, -2, 258, 10053, 10054, 233, 64, 4083)
|    $full = @(1105, 40544, 1101)
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
|    $nums = New-Object System.Collections.Generic.List[int]
|    $texts = New-Object System.Collections.Generic.List[string]
|    while ($ex) {
|        if ($ex -is [System.Data.SqlClient.SqlException]) {
|            foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) }
|            $nums.Add([int]$ex.Number)
|        }
|        try { if ($ex.Data -and $ex.Data.Contains('SISqlNumbers')) { foreach ($n in @($ex.Data['SISqlNumbers'])) { $nums.Add([int]$n) } } } catch { }
|        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
|    }
|    if (-not $texts.Count) { $texts.Add([string]$ErrorRecord) }
|    $t = $texts -join ' | '
|    foreach ($n in $nums) { if ($full -contains $n) { return $false } }
|    if ($t -match '(?i)has reached its size quota|could not allocate (a new page|space)') { return $false }
|    foreach ($n in $nums) { if ($codes -contains $n) { return $true } }
|    [bool]($t -match '(?i)a severe error occurred on the current command|transport-level error|connection was forcibly closed|forcibly closed by the remote host|connection reset|Connection reset by peer|broken pipe|Internal \.NET Framework Data Provider error 6|is not currently available|log for database .* is not available|connection was recovered and rowcount|\b(9001|3314|40613|40501|40197|49918|49919|49920|4083)\b')
|}
|
|function Test-SISqlShapedFailure {
|    <#
|        PURE. Is this failure a SQL statement's own: a SqlException in the error's chain, the driver's text ('Exception calling
|        "ExecuteScalar"', the reader, the non-query) or the engine's own 'SQL error <n>'? The words Test-SISqlStatementTransient
|        reads ("connection reset", "is not currently available") also occur in other services' answers, so a text is only held
|        against it when it is SQL's.
|    #>
|    param([AllowNull()][AllowEmptyString()][string]$Text, [AllowNull()]$ErrorRecord)
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
|    while ($ex) { if ($ex -is [System.Data.SqlClient.SqlException]) { return $true }; $ex = $ex.InnerException }
|    [bool]("$Text" -match '(?i)Exception calling "Execute(Scalar|Reader|NonQuery)(Async)?"|\bSQL error -?\d+\b')
|}
|
|function Get-SISqlErrorNumbers {
|    <#
|        PURE. SQL's own error numbers in a failure's chain, distinct and comma-joined ('9001,3314'), '' when it has none. The
|        driver's message does not carry them. For the log and the uplink's Detail only: never the customer-visible reason.
|    #>
|    param([AllowNull()]$ErrorRecord)
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
|    $nums = New-Object System.Collections.Generic.List[int]
|    while ($ex) {
|        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) } }
|        try { if ($ex.Data -and $ex.Data.Contains('SISqlNumbers')) { foreach ($n in @($ex.Data['SISqlNumbers'])) { $nums.Add([int]$n) } } } catch { }
|        $ex = $ex.InnerException
|    }
|    (@($nums | Select-Object -Unique) -join ',')
|}
|
|function Test-SISqlConnectTransient {
|    <#
|        PURE and SELF-CONTAINED (it travels as a value; it calls nothing by name). Did the CONNECTION fail at the network /
|        transport level, before anything was sent -- so opening it again a moment later is safe? Live 2026-11-07 (an install's
|        pipeline runner, its settings read): "A network-related or instance-specific error occurred while establishing a
|        connection to SQL Server ... (provider: TCP Provider, error: 40 - Could not open a connection to SQL Server)" stopped
|        the run; every wake-up after it read the settings fine.
|          transient: SqlException 40 / 53 / 10060 / 10061 / 10065 / 11001 / 1225 / 121 / 4060 / 40613 / 40197 / 40501 /
|                     49918-49920 / -2 / 258 / 233 / 64 / 10053 / 10054, and the texts "network-related or instance-specific",
|                     "Could not open a connection to SQL Server", "error: 40" / "error: 26" / "error: 0" of a provider, "semaphore
|                     timeout", "connection attempt failed", "actively refused", "No such host is known", "server was not found",
|                     and a failed pre-login / TLS handshake ("an error occurred during the pre-login handshake", "SSL Provider,
|                     error: 31" -- live 2026-11-14, a large install's 5-minute wake-up: the connection reached the server, the
|                     TLS handshake at the gateway failed once, the wake-up stopped as settings-error; the next one read fine).
|          never:     a refused sign-in (18456 -- a grant, not the network), a permission, a missing database by name.
|        -ErrorRecord: an ErrorRecord, an exception (SqlException numbers and inner exceptions are read) or a text.
|    #>
|    param([AllowNull()]$ErrorRecord)
|    if ($null -eq $ErrorRecord) { return $false }
|    $codes = @(40, 53, 10060, 10061, 10065, 11001, 1225, 121, 4060, 40613, 40197, 40501, 49918, 49919, 49920, -2, 258, 233, 64, 10053, 10054)
|    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
|    $nums = New-Object System.Collections.Generic.List[int]
|    $texts = New-Object System.Collections.Generic.List[string]
|    while ($ex) {
|        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) }; $nums.Add([int]$ex.Number) }
|        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
|    }
|    if (-not $texts.Count) { $texts.Add([string]$ErrorRecord) }
|    $t = $texts -join ' | '
|    # a refused sign-in is a grant, not the network (4060 "Cannot open database ... The login failed." IS the failover class)
|    if ($nums -contains 18456 -or $t -match '(?i)Login failed for user|\b18456\b') { return $false }
|    foreach ($n in $nums) { if ($codes -contains $n) { return $true } }
|    [bool]($t -match '(?i)network-related or instance-specific error|Could not open a connection to SQL Server|\(provider: [^,]+, error: (0|26|35|40)\b|\(provider: SSL Provider, error: 31\b|error occurred during the pre-login handshake|semaphore timeout|connection attempt failed|actively refused|No such host is known|server was not found or was not accessible|transport-level error|forcibly closed by the remote host|connection was forcibly closed|\b(40613|40197|40501|10060|10061|4060)\b')
|}
|
|function Get-SISqlConnectRetryWaits {
|    <# #1147: the pauses before each new attempt to READ when the connection failed at the network level (Test-SISqlConnectTransient):
|       4 more attempts over about 1.5 minutes -- a short network blip or a gateway that moved passes in seconds. #>
|    @(5, 10, 20, 45)
|}
|
|function Get-SISqlStatementRetryWaits {
|    <# The pauses before each new attempt of a statement that met an Azure SQL platform answer: 6 more attempts over about
|       9 minutes (owner 2026-10-29). A failover or a resume passes in under a minute; a log that recovers after a rollback
|       under load (the live case) takes minutes. A bound on Microsoft's errors, never on SI's own work. #>
|    @(5, 15, 30, 60, 120, 300)
|}
|
|function Test-SISqlNotYetAnswer {
|    <# PURE. Is this the refusal a database gives for a moment after its server's administrator or firewall rule changed:
|       "Login failed" (18456) or "client with IP address ... is not allowed" (40615)? #>
|    param([AllowEmptyString()][AllowNull()][string]$Text)
|    [bool]("$Text" -match '(?i)Login failed|\b18456\b|\b40615\b|is not allowed to access the server')
|}
|
|function Open-SISqlConnectionRetry {
|    <#
|        Opens a database connection with an Entra token, and tries again -- a bounded number of times (Microsoft's errors),
|        with a NEW token each time -- when the database answers
|          * "Login failed" / 18456 / 40615: its administrator or firewall rule was changed a moment ago (Test-SISqlNotYetAnswer);
|          * a transient Azure SQL fault: a failover, a serverless resume, busy, a client timeout (Test-SISqlTransientError);
|          * #1181 a connection that failed at the network level: a name look-up that failed for a moment ("No such host is
|            known"), "network-related or instance-specific", a reset or refused connection (Test-SISqlConnectTransient's rules).
|        Any other failure is thrown at once. Only the OPEN is retried -- nothing has been sent yet.
|          -Token    { param([bool]$Fresh) } -> the access token for https://database.windows.net/ ($Fresh = ask for a new one)
|          -Waits    seconds between tries (default 6 x 20 s)
|          -Connect  { param($Server, $Database, $Token) } -> an OPEN connection (tests; default: System.Data.SqlClient)
|          -ConnectTimeoutSec  the driver's own connect timeout (default 30)
|        Returns the open connection; the caller disposes it.
|    #>
|    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][scriptblock]$Token,
|          [int[]]$Waits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep, [scriptblock]$Connect, [int]$ConnectTimeoutSec = 30)
|    if (-not $Connect) {
|        $cto = $ConnectTimeoutSec
|        $Connect = {
|            param($Server, $Database, $Token)
|            # BUILT, never formatted: a server or database value is always ONE value (a ';' in it never adds a keyword).
|            # Self-contained (no function called by name -- this block travels as a value, see below).
|            $csb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
|            $h = "$Server".Trim(); if ($h.StartsWith('tcp:', [StringComparison]::OrdinalIgnoreCase)) { $h = $h.Substring(4) }
|            $ci = $h.IndexOf(','); if ($ci -ge 0) { $h = $h.Substring(0, $ci) }
|            $csb['Data Source'] = ('tcp:{0},1433' -f $h.Trim()); $csb['Initial Catalog'] = "$Database".Trim()
|            $csb['Encrypt'] = $true; $csb['TrustServerCertificate'] = $false; $csb['Connect Timeout'] = $cto
|            $cn = New-Object System.Data.SqlClient.SqlConnection($csb.ConnectionString)
|            $cn.AccessToken = $Token
|            try { $cn.Open() } catch { $cn.Dispose(); throw }
|            $cn
|        }.GetNewClosure()
|    }
|    $try = 0; $cn = $null
|    while ($true) {
|        $tok = ([string](& $Token ($try -gt 0))).Trim()
|        if (-not $tok) { throw 'the sign-in could not issue an Azure SQL token for the caller.' }
|        try { $cn = & $Connect $Server $Database $tok; break }
|        catch {
|            # SELF-CONTAINED (review 2, S3): the classification is written out here, never called by name -- this function
|            # travels as a value into connection closures (SI-DataSql.ps1) that outlive the scope that loaded this file
|            # (SI-Guard keeps one globally), where Test-SISqlNotYetAnswer / Test-SISqlTransientError are not visible: the
|            # failed open then threw "not recognized", hid the real SQL error and lost the retry. The same rules as those two.
|            $msgText = [string]$_.Exception.Message
|            $notYet = [bool]($msgText -match '(?i)Login failed|\b18456\b|\b40615\b|is not allowed to access the server')
|            $transient = $false
|            if (-not $notYet) {
|                $ex = $_.Exception
|                while ($ex) {
|                    if ($ex -is [System.Data.SqlClient.SqlException] -and @(40613, 40197, 40501, 49918, 49919, 49920, 4060, 10928, 10929, -2, 258) -contains [int]$ex.Number) { $transient = $true; break }
|                    $ex = $ex.InnerException
|                }
|                if (-not $transient) { $transient = [bool]($msgText -match 'is not currently available|Please retry the connection later|too busy|try again') }
|                # #1181 (a large install 2026-11-11: "... (provider: TCP Provider, error: 0 - No such host is known.)" -- a name
|                # look-up that failed for a moment -- ended the prepared view columns): a connection that failed at the NETWORK
|                # level is opened again too -- the same rules as Test-SISqlConnectTransient, written out (this travels as a value).
|                # Nothing was sent. A refused sign-in is the branch above, never this one.
|                if (-not $transient) {
|                    $ex = $_.Exception
|                    while ($ex) {
|                        if ($ex -is [System.Data.SqlClient.SqlException]) {
|                            $netNums = @([int]$ex.Number); foreach ($er in @($ex.Errors)) { $netNums += [int]$er.Number }
|                            foreach ($n in $netNums) { if (@(40, 53, 10060, 10061, 10065, 11001, 1225, 121, 233, 64, 10053, 10054) -contains $n) { $transient = $true } }
|                            if ($transient) { break }
|                        }
|                        $ex = $ex.InnerException
|                    }
|                }
|                if (-not $transient) { $transient = [bool]($msgText -match '(?i)network-related or instance-specific error|Could not open a connection to SQL Server|\(provider: [^,]+, error: (0|26|35|40)\b|\(provider: SSL Provider, error: 31\b|error occurred during the pre-login handshake|semaphore timeout|connection attempt failed|actively refused|No such host is known|server was not found or was not accessible|transport-level error|forcibly closed by the remote host|connection was forcibly closed') }
|            }
|            if ((-not $notYet -and -not $transient) -or $try -ge @($Waits).Count) { throw }
|            $w = [int]@($Waits)[$try]; $try++
|            $why = if ($notYet) { 'does not accept this sign-in yet (its administrator or firewall rule changed a moment ago)' } else { ('is not available for a moment ({0})' -f (([string]$_.Exception.Message -split "`n")[0].Trim())) }
|            Write-Host ('       the database {0} {1} -- waiting {2} s and trying again ({3}/{4}) ...' -f $Database, $why, $w, $try, @($Waits).Count) -ForegroundColor DarkYellow
|            if ($w -gt 0) { if ($Sleep) { & $Sleep $w } else { Start-Sleep -Seconds $w } }
|        }
|    }
|    $cn
|}
|
|function Open-SISqlConnectionStringRetry {
|    <#
|        The same open-with-retry (Open-SISqlConnectionRetry: its rules and its log line) for a worker on ANOTHER thread that
|        holds a ready connection string and the token handed over with its work (SI-DataSql's connection info, #738) -- used
|        with that string as it is. No token = a connection string that signs in by itself (the tests' local server). The
|        handed token cannot be renewed here, so -Waits is short: a worker beside the run never holds the run's end for long.
|        Returns the open connection; the caller disposes it.
|    #>
|    param([Parameter(Mandatory)][string]$ConnectionString, [AllowEmptyString()][AllowNull()][string]$AccessToken = '',
|          [int[]]$Waits = @(2, 5), [scriptblock]$Sleep, [int]$ConnectTimeoutSec = 0)
|    $cs = $ConnectionString; $tk = [string]$AccessToken
|    $b = New-Object System.Data.SqlClient.SqlConnectionStringBuilder($cs)
|    if ($ConnectTimeoutSec -gt 0) { $b['Connect Timeout'] = $ConnectTimeoutSec; $cs = $b.ConnectionString }
|    $connect = {
|        param($Server, $Database, $Token)
|        $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
|        if ($tk) { $cn.AccessToken = $tk }
|        try { $cn.Open() } catch { $cn.Dispose(); throw }
|        $cn
|    }.GetNewClosure()
|    # the token is the handed one (or none); Open-SISqlConnectionRetry only checks that it is not empty -- -Connect uses $tk
|    $token = { param([bool]$Fresh) if ($tk) { $tk } else { 'signs-in-by-itself' } }.GetNewClosure()
|    Open-SISqlConnectionRetry -Server ([string]$b['Data Source']) -Database ([string]$b['Initial Catalog']) -Token $token -Connect $connect -Waits $Waits -Sleep $Sleep
|}
'@ }
$__siLauncherFiles['auth/SI-ManagedIdentity.ps1'] = @{ Sha256 = '8198e8e891fb59de6e58fe9f8b08fe7f3f838586096d36758b85aa0e118f6673'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- sign in with a MANAGED IDENTITY: a container job's (#209), an Azure VM's or an Azure Arc
|    server's (#222).
|
|    WHY. An engine container could only sign in with an SPN client SECRET. Internal installs are certificate
|    only, and Pro is container only, so a certificate-only customer could not run Pro at all. PIM4EntraPS's
|    containers sign in as the job's managed identity; this copies that (PIM: Get-PimManagedIdentityToken).
|    #222 (operator 2026-10-03): the managed identity is the DEFAULT everywhere; an SPN stays supported.
|
|    THE ONE SWITCH. A run uses the managed identity when $global:SI_UseManagedIdentity = $true.
|        $global:SI_UAMI_ClientId = '<client id>'   optional: a USER-assigned identity; empty = the host's
|                                                    system-assigned identity
|    Who sets it: the container entry points (when the job has an identity endpoint), and on a VM the sign-in
|    decision in the config loader (auth/SI-AuthMethod.ps1). When it is off, every function below either is
|    never called or returns "not mine" -- the secret and certificate paths are exactly what they were.
|    The host decides the endpoint (Get-SIManagedIdentityHost): container IDENTITY_ENDPOINT + IDENTITY_HEADER;
|    Azure Arc IDENTITY_ENDPOINT + IMDS_ENDPOINT (401 challenge file); otherwise the Azure VM endpoint.
|
|    Log ingestion keeps its existing switch ($global:SI_PreferUami + SI_UAMI_ClientId -> -UseManagedIdentity on
|    SI's REST ingestion, which mints the token here); the container sets that from the same decision. No second
|    identity switch.
|
|    PS 5.1 safe: no ?. / ??.
|#>
|
|# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
|if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }
|
|$__siFindCert = Join-Path $PSScriptRoot 'Find-SICertificate.ps1'
|if ((Test-Path -LiteralPath $__siFindCert) -and -not (Get-Command Get-SICertificateFromStore -ErrorAction SilentlyContinue)) { . $__siFindCert }
|
|if (-not (Get-Variable -Name SIManagedIdentityTokenCache -Scope Script -ErrorAction SilentlyContinue)) {
|    $script:SIManagedIdentityTokenCache = @{}   # '<clientId>|<resource>' -> @{ Token; ExpiresAt }
|}
|
|function Test-SIUseManagedIdentity {
|    <# THE switch: this run signs in as a managed identity (a container job's, an Azure VM's or an Azure Arc
|       server's -- #222). The client id is optional: empty = the host's SYSTEM-assigned identity. #>
|    return [bool]$global:SI_UseManagedIdentity
|}
|
|function Get-SIManagedIdentityHost {
|    <#
|        PURE (reads env only). Which managed-identity endpoint this host has (#222):
|          Container -- Azure Container Apps / App Service: IDENTITY_ENDPOINT + IDENTITY_HEADER
|          Arc       -- an Azure Arc-enabled server: IDENTITY_ENDPOINT + IMDS_ENDPOINT, no IDENTITY_HEADER (the Arc
|                       agent sets both machine-wide); the token needs a challenge-file handshake
|          AzureVm   -- an Azure VM (and anything else): the instance metadata endpoint 169.254.169.254
|    #>
|    param([scriptblock]$GetEnv)
|    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
|    $ep = [string](& $GetEnv 'IDENTITY_ENDPOINT'); $hd = [string](& $GetEnv 'IDENTITY_HEADER'); $imds = [string](& $GetEnv 'IMDS_ENDPOINT')
|    if ($ep -and $hd) { return 'Container' }
|    if ($ep -and $imds) { return 'Arc' }
|    return 'AzureVm'
|}
|
|function Get-SIManagedIdentityToken {
|    <#
|        A token for -Resource as this host's managed identity (#209 container, #222 Azure VM + Azure Arc):
|          Container -- IDENTITY_ENDPOINT + X-IDENTITY-HEADER, api-version 2019-08-01, client_id when known
|          AzureVm   -- http://169.254.169.254/metadata/identity/oauth2/token, Metadata: true, client_id when known
|          Arc       -- IDENTITY_ENDPOINT (api-version 2020-06-01, Metadata: true): the first call answers 401 with
|                       'WWW-Authenticate: Basic realm=<file>'; the file's content is the secret for the second call.
|                       Reading it needs local Administrators or the 'Hybrid agent extension applications' group. Arc
|                       has the SYSTEM-assigned identity only, so no client_id.
|
|        TRAP: THE client_id IS NOT OPTIONAL IN PRACTICE for a user-assigned identity. PIM4EntraPS measured it: with a
|        user-assigned identity only, the endpoint has nothing to default to and the failure surfaces far away as
|        "Login failed" / 401. So it is always sent when known.
|
|        Cached per identity + resource until 5 minutes before the token's own expiry. -Invoke is a test seam:
|        { param($Uri, $Headers) } returning the endpoint's response (Arc: the @{Status;Body;WwwAuthenticate} shape).
|        -ReadFile is a test seam for the Arc challenge file.
|    #>
|    param(
|        [Parameter(Mandatory)][string]$Resource,
|        [string]$ClientId,
|        [switch]$ForceRefresh,
|        [scriptblock]$Invoke,
|        [scriptblock]$ReadFile
|    )
|    # A guided install's own sign-in wins (live 2026-10-06, an AzContext install on an Azure VM got the VM's IMDS token for
|    # SQL): while $global:SI_InstallTokenProvider is set, the token comes from it and NO identity endpoint is called.
|    $installProvider = Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore
|    # Re-entry = the install's sign-in itself IS this host's managed identity (sign-in mode ManagedIdentity): then, and only
|    # then, the identity endpoint below answers.
|    if (($installProvider -is [scriptblock]) -and -not $global:SI_InstallTokenProviderBusy) {
|        $global:SI_InstallTokenProviderBusy = $true
|        try { $pt = [string](& $installProvider $Resource) } finally { $global:SI_InstallTokenProviderBusy = $false }
|        if ([string]::IsNullOrWhiteSpace($pt)) { throw ("the install's sign-in returned no token for '{0}'." -f $Resource) }
|        return $pt
|    }
|    # SELF-CONTAINED on purpose: it is published to the global scope and may run where this file's other functions are
|    # not visible. The host rule is Get-SIManagedIdentityHost's, repeated here.
|    $endpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')
|    $header   = [Environment]::GetEnvironmentVariable('IDENTITY_HEADER')
|    $imdsEp   = [Environment]::GetEnvironmentVariable('IMDS_ENDPOINT')
|    $hostKind = if ($endpoint -and $header) { 'Container' } elseif ($endpoint -and $imdsEp) { 'Arc' } else { 'AzureVm' }
|    $arcGet = {
|        param([string]$U, [hashtable]$H)
|        $req = [System.Net.HttpWebRequest]::Create($U)
|        $req.Method = 'GET'; $req.Timeout = 60000
|        foreach ($k in $H.Keys) { if ($k -eq 'Authorization') { $req.Headers['Authorization'] = [string]$H[$k] } else { $req.Headers.Add($k, [string]$H[$k]) } }
|        try { $r = $req.GetResponse() }
|        catch [System.Net.WebException] { $r = $_.Exception.Response; if (-not $r) { throw } }
|        try {
|            $sr = New-Object System.IO.StreamReader($r.GetResponseStream()); $b = $sr.ReadToEnd(); $sr.Close()
|            [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $b; WwwAuthenticate = [string]$r.Headers['WWW-Authenticate'] }
|        } finally { $r.Close() }
|    }
|    if ([string]::IsNullOrWhiteSpace($ClientId)) { $ClientId = [string]$global:SI_UAMI_ClientId }
|    # The cache is created HERE, not only when this file loads: when this function runs from another scope, `$script:` is
|    # that scope and the file-level cache does not exist.
|    # Measured live 2026-10-02 (first container run on the identity): "You cannot call a method on a null-valued
|    # expression" on every token, and every Log Analytics post failed.
|    if ($null -eq $script:SIManagedIdentityTokenCache) { $script:SIManagedIdentityTokenCache = @{} }
|    $res = ($Resource -replace '/\.default$', '')
|    $key = '{0}|{1}' -f $ClientId, $res
|    if (-not $ForceRefresh -and $script:SIManagedIdentityTokenCache.ContainsKey($key)) {
|        $c = $script:SIManagedIdentityTokenCache[$key]
|        if ($c.ExpiresAt -gt [datetime]::UtcNow) { return $c.Token }
|    }
|
|    $resp = $null
|    switch ($hostKind) {
|        'Container' {
|            $uri = '{0}?resource={1}&api-version=2019-08-01' -f $endpoint, [uri]::EscapeDataString($res)
|            if (-not [string]::IsNullOrWhiteSpace($ClientId)) { $uri += '&client_id=' + [uri]::EscapeDataString($ClientId) }
|            $headers = @{ 'X-IDENTITY-HEADER' = $header }
|            $resp = if ($Invoke) { & $Invoke $uri $headers }
|                    else { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 60 }
|        }
|        'AzureVm' {
|            $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={0}' -f [uri]::EscapeDataString($res)
|            if (-not [string]::IsNullOrWhiteSpace($ClientId)) { $uri += '&client_id=' + [uri]::EscapeDataString($ClientId) }
|            $headers = @{ 'Metadata' = 'true' }
|            $resp = if ($Invoke) { & $Invoke $uri $headers }
|                    else { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 60 }
|        }
|        'Arc' {
|            $uri = '{0}?api-version=2020-06-01&resource={1}' -f $endpoint, [uri]::EscapeDataString($res)
|            $first = if ($Invoke) { & $Invoke $uri @{ 'Metadata' = 'true' } } else { & $arcGet $uri @{ 'Metadata' = 'true' } }
|            if ([int]$first.Status -ne 401 -or [string]$first.WwwAuthenticate -notmatch '(?i)realm=(.+)$') {
|                throw ("managed identity (Azure Arc): expected a 401 challenge from {0}, got {1}. Is the Arc agent running?" -f $endpoint, $first.Status)
|            }
|            $keyFile = $Matches[1].Trim().Trim('"')
|            $secret = $null
|            try { $secret = if ($ReadFile) { & $ReadFile $keyFile } else { [System.IO.File]::ReadAllText($keyFile) } }
|            catch { throw ("managed identity (Azure Arc): cannot read the challenge file {0} -- the run must be a local Administrator or in the 'Hybrid agent extension applications' group. {1}" -f $keyFile, $_.Exception.Message) }
|            $second = if ($Invoke) { & $Invoke $uri @{ 'Metadata' = 'true'; 'Authorization' = ('Basic ' + $secret) } }
|                      else { & $arcGet $uri @{ 'Metadata' = 'true'; 'Authorization' = ('Basic ' + $secret) } }
|            if ([int]$second.Status -ne 200) { throw ("managed identity (Azure Arc): the identity endpoint refused the token request ({0})." -f $second.Status) }
|            $resp = $second.Body | ConvertFrom-Json
|        }
|    }
|    $token = [string]$resp.access_token
|    if ([string]::IsNullOrWhiteSpace($token)) {
|        throw ("managed identity ({2}): the identity endpoint returned no token for '{0}' (client id {1}). Is that identity assigned to this host / job?" -f $res, $ClientId, $hostKind)
|    }
|
|    $expiresAt = [datetime]::UtcNow.AddMinutes(50)
|    $epoch = 0L
|    if ([long]::TryParse([string]$resp.expires_on, [ref]$epoch) -and $epoch -gt 0) {
|        $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.AddMinutes(-5)
|    } else {
|        $secs = 0
|        if ([int]::TryParse([string]$resp.expires_in, [ref]$secs) -and $secs -gt 600) { $expiresAt = [datetime]::UtcNow.AddSeconds($secs - 300) }
|    }
|    $script:SIManagedIdentityTokenCache[$key] = @{ Token = $token; ExpiresAt = $expiresAt }
|    # #232 -- the licence is checked against the tenant the identity REALLY lives in. A managed identity's token always
|    # comes from its home tenant, whatever the configuration claims, so its 'tid' claim is the proof; a configured tenant
|    # id is not (a copied licence plus an edited config would otherwise pass). Recorded from every real token.
|    try {
|        $seg = $token.Split('.')
|        if ($seg.Count -ge 2) {
|            $p = $seg[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
|            $tid = [string](([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))) | ConvertFrom-Json).tid
|            if ($tid -match '^[0-9a-fA-F-]{36}$') { $global:SI_IdentityTokenTenantId = $tid.ToLowerInvariant() }
|        }
|    } catch { }
|    try { [System.Console]::Out.WriteLine(("  [mi] token for {0} via the {2} identity endpoint (len {1})" -f $res, $token.Length, $hostKind)) } catch { }
|    return $token
|}
|
|function Get-SIAccessToken {
|    <#
|        "A token for resource X as the identity this run uses." The managed identity when the switch is on;
|        otherwise the run's own sign-in (Get-SIAzAccessToken, over REST).
|    #>
|    param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
|    if (Test-SIUseManagedIdentity) { return (Get-SIManagedIdentityToken -Resource $Resource -ForceRefresh:$ForceRefresh) }
|    $t = Get-SIAzAccessToken -ResourceUrl $Resource -ErrorAction Stop
|    if ($t.Token -is [System.Security.SecureString]) { return [System.Net.NetworkCredential]::new('', $t.Token).Password }
|    return [string]$t.Token
|}
'@ }
$__siLauncherFiles['setup/_shared/SI-SetupSignIn.ps1'] = @{ Sha256 = 'f679aeea5410c99712147634239b38093e6d3973996f57bd67db46f4f947596c'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight SETUP -- signing in to Azure with NO PowerShell modules (native REST and .NET only).
|
|    WHO SIGNS IN, AND HOW
|      A person (the guided install, the wizard, Setup-SecurityInsight, Bootstrap-*, Grant-*, Validate-* ...):
|        * Azure Cloud Shell  -- the Cloud Shell token endpoint ($env:MSI_ENDPOINT, else $env:IDENTITY_ENDPOINT). It hands
|                                out tokens for the person who opened Cloud Shell, per resource, with no prompt.
|        * a workstation      -- OAuth 2.0 authorization code + PKCE in the person's own browser, answered on a loopback
|                                listener (System.Net.HttpListener on http://localhost:<free port>/). The client is the
|                                public Azure PowerShell client, so the same consent and the same Microsoft Graph rights
|                                (Directory.AccessAsUser.All) setup always had. NO device code: it is blocked by
|                                Conditional Access in many tenants and is deliberately not offered.
|        Tokens for the other resources (Graph, Key Vault, Storage, Log Analytics, SQL ...) come from the refresh token
|        (browser) or the Cloud Shell endpoint, on first use. EXCEPT Exchange Online (https://outlook.office365.com): its
|        admin API accepts only a token of the Exchange Online PowerShell client (Get-SISignInExchangeClientId), so the first
|        Exchange token is one more browser sign-in with that client (same flow, the account pre-filled), then its own
|        refresh token. Everything is kept IN MEMORY in this PowerShell process --
|        nothing is written to disk.
|      An app (unattended setup, CI): a certificate or a client secret -- recorded by Connect-SIAzAccount (REST), tokens
|        minted by engine/_shared (client assertion / client credentials). A managed identity likewise.
|
|    HOW THE REST LAYER USES IT
|      engine/_shared/SI-AzRest.ps1 asks Get-SIAzureToken for every token. setup/_shared/SI-SetupAzure.ps1 loads that file
|      and then defines Get-SIAzureToken once more, here: a USER sign-in is answered from this file, anything else exactly
|      as the engine does. So Invoke-SIArm, the *-SIAz* REST twins, Key Vault, Graph and storage all run as the signed-in
|      person without knowing it.
|
|    TEST SEAMS: every HTTP call goes through Invoke-SIAzRestHttp (engine); the browser through Open-SISignInBrowser; the
|    loopback wait through Wait-SILoopbackAuthCode. Pure helpers (PKCE pair, authorize URL, redirect parsing) are public.
|
|    PS 5.1 safe (no ?. / ??), pwsh 7 on Windows, Linux (Cloud Shell) and macOS.
|#>
|
|# NO Set-StrictMode here -- it leaks into the caller's scope.
|
|
|function Get-SISignInClientId {
|    <# The public client the browser sign-in uses: $global:SI_SetupSignInClientId (an organisation's own public app
|       registration with an http://localhost redirect) when set, else the Azure PowerShell client. #>
|    $c = "$(Get-Variable -Scope Global -Name SI_SetupSignInClientId -ValueOnly -ErrorAction Ignore)"
|    if ($c.Trim()) { return $c.Trim() }
|    return '1950a258-227b-4e31-a9cf-717495945fc2'
|}
|
|function Get-SISignInExchangeClientId {
|    <# The public client the Exchange Online admin API (https://outlook.office365.com/adminapi/...) is signed in with:
|       "Microsoft Exchange REST API Based Powershell", the client the Exchange Online PowerShell V3 module itself uses
|       (PIM4EntraPS does the same). A delegated token for Exchange must carry Exchange.Manage; the Azure PowerShell client
|       is not consented for it, so Exchange answered its token with 401 Unauthorized (customer ticket 2026-10-15).
|       $global:SI_SetupExchangeClientId overrides it (an organisation's own public app with Exchange.Manage). #>
|    $c = "$(Get-Variable -Scope Global -Name SI_SetupExchangeClientId -ValueOnly -ErrorAction Ignore)"
|    if ($c.Trim()) { return $c.Trim() }
|    return 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
|}
|
|function Test-SISignInExchangeResource {
|    <# PURE. True for the Exchange Online resource (its admin API takes only a token of the Exchange client). #>
|    param([string]$Resource)
|    $r = ("$Resource" -replace '/\.default$', '').TrimEnd('/').ToLowerInvariant()
|    return ($r -eq 'https://outlook.office365.com' -or $r -eq 'https://outlook.office.com')
|}
|
|function Get-SISignInState {
|    <# The in-memory sign-in of this process: the user session (method, tenant, account, refresh token) and its tokens. #>
|    if (-not ((Get-Variable -Scope Global -Name SI_SetupSignInState -ValueOnly -ErrorAction Ignore) -is [hashtable])) {
|        $global:SI_SetupSignInState = @{ Session = $null; Tokens = @{} }
|    }
|    return $global:SI_SetupSignInState
|}
|
|function Test-SICloudShell {
|    <# True in Azure Cloud Shell: the Cloud Shell markers AND a token endpoint. #>
|    $marker = ([string]$env:AZUREPS_HOST_ENVIRONMENT) -like 'cloud-shell*' -or [bool]$env:ACC_CLOUD -or [bool]$env:ACC_TERM_ID
|    return ($marker -and [bool](Get-SICloudShellEndpoint))
|}
|
|function Get-SICloudShellEndpoint {
|    $e = [string]$env:MSI_ENDPOINT
|    if (-not $e.Trim()) { $e = [string]$env:IDENTITY_ENDPOINT }
|    return $e.Trim()
|}
|
|# ---------------------------------------------------------------------------------------------------------------
|# PURE helpers: PKCE, state, the authorize URL, the redirect, token claims
|# ---------------------------------------------------------------------------------------------------------------
|function ConvertTo-SIBase64Url {
|    param([Parameter(Mandatory)][byte[]]$Bytes)
|    return ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
|}
|
|function New-SIRandomBase64Url {
|    param([int]$ByteCount = 32)
|    $b = New-Object byte[] $ByteCount
|    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
|    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
|    return (ConvertTo-SIBase64Url -Bytes $b)
|}
|
|function Get-SIPkceChallenge {
|    <# RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))). #>
|    param([Parameter(Mandatory)][string]$Verifier)
|    $sha = [System.Security.Cryptography.SHA256]::Create()
|    try { $h = $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Verifier)) } finally { $sha.Dispose() }
|    return (ConvertTo-SIBase64Url -Bytes $h)
|}
|
|function New-SIPkcePair {
|    <# A fresh verifier (43 chars from 32 random bytes, inside RFC 7636's 43..128 unreserved set) and its S256 challenge. #>
|    $v = New-SIRandomBase64Url -ByteCount 32
|    return [pscustomobject]@{ Verifier = $v; Challenge = (Get-SIPkceChallenge -Verifier $v); Method = 'S256' }
|}
|
|function Get-SISignInScope {
|    <# The v2 scope of a resource: 'https://graph.microsoft.com/' -> 'https://graph.microsoft.com/.default'. #>
|    param([Parameter(Mandatory)][string]$Resource)
|    $r = ($Resource -replace '/\.default$', '').TrimEnd('/')
|    return ($r + '/.default')
|}
|
|function Get-SIAuthorizeUrl {
|    <# The Microsoft Entra authorize URL for the code + PKCE flow. #>
|    param(
|        [string]$TenantId,
|        [Parameter(Mandatory)][string]$ClientId,
|        [Parameter(Mandatory)][string]$RedirectUri,
|        [Parameter(Mandatory)][string]$Scope,
|        [Parameter(Mandatory)][string]$CodeChallenge,
|        [Parameter(Mandatory)][string]$State,
|        [string]$LoginHint,
|        [string]$Prompt = 'select_account'
|    )
|    $t = if ([string]::IsNullOrWhiteSpace($TenantId)) { 'organizations' } else { $TenantId.Trim() }
|    $q = [ordered]@{
|        client_id             = $ClientId
|        response_type         = 'code'
|        redirect_uri          = $RedirectUri
|        response_mode         = 'query'
|        scope                 = $Scope
|        state                 = $State
|        code_challenge        = $CodeChallenge
|        code_challenge_method = 'S256'
|    }
|    if ($Prompt) { $q['prompt'] = $Prompt }
|    if ($LoginHint) { $q['login_hint'] = $LoginHint }
|    $pairs = foreach ($k in $q.Keys) { '{0}={1}' -f $k, [uri]::EscapeDataString([string]$q[$k]) }
|    return ('https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize?{1}' -f [uri]::EscapeDataString($t), ($pairs -join '&'))
|}
|
|function ConvertFrom-SIQueryString {
|    <# '?a=1&b=x%20y' -> @{ a = '1'; b = 'x y' } (case-insensitive keys). #>
|    param([string]$Query)
|    $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
|    $q = ([string]$Query).TrimStart('?')
|    foreach ($p in ($q -split '&')) {
|        if (-not $p) { continue }
|        $i = $p.IndexOf('=')
|        $k = if ($i -ge 0) { $p.Substring(0, $i) } else { $p }
|        $v = if ($i -ge 0) { $p.Substring($i + 1) } else { '' }
|        $h[[uri]::UnescapeDataString($k.Replace('+', ' '))] = [uri]::UnescapeDataString($v.Replace('+', ' '))
|    }
|    return $h
|}
|
|function Resolve-SIAuthRedirect {
|    <#
|        The browser's redirect back to the loopback listener -> the authorization code. Throws in customer language when
|        Entra returned an error, when the state does not match (a response this sign-in did not ask for), or when no
|        code came back.
|    #>
|    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [Parameter(Mandatory)][string]$ExpectedState)
|    $q = ConvertFrom-SIQueryString -Query $Query
|    if ($q['error']) {
|        $d = [string]$q['error_description']
|        throw ("The Microsoft sign-in did not complete: {0}{1}" -f $q['error'], $(if ($d) { ' -- ' + $d } else { '' }))
|    }
|    if ([string]$q['state'] -ne $ExpectedState) {
|        throw 'The sign-in answer did not belong to this sign-in (the state value does not match). Nothing was signed in; run the same command again.'
|    }
|    if (-not $q['code']) { throw 'The sign-in answer carried no authorization code. Run the same command again.' }
|    return [string]$q['code']
|}
|
|function ConvertFrom-SISignInJwt {
|    <# The claims of a JWT (no signature check -- only read to learn the tenant, the account and the expiry). #>
|    param([string]$Token)
|    $parts = ([string]$Token) -split '\.'
|    if ($parts.Count -lt 2) { return $null }
|    $p = $parts[1].Replace('-', '+').Replace('_', '/')
|    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
|    try { return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
|}
|
|function Get-SISignInAccountName {
|    param($Claims)
|    if (-not $Claims) { return $null }
|    foreach ($n in 'upn', 'preferred_username', 'unique_name', 'email', 'oid') {
|        if ($Claims.PSObject.Properties[$n] -and [string]$Claims.$n) { return [string]$Claims.$n }
|    }
|    return $null
|}
|
|function Get-SITokenExpiry {
|    <# When a token response expires (5 minutes early): expires_in (seconds) or expires_on (unix seconds / a date). #>
|    param($Response)
|    $now = [datetime]::UtcNow
|    $s = 0
|    if ($Response.PSObject.Properties['expires_in'] -and [int]::TryParse([string]$Response.expires_in, [ref]$s) -and $s -gt 0) {
|        return $now.AddSeconds([Math]::Max(60, $s - 300))
|    }
|    if ($Response.PSObject.Properties['expires_on']) {
|        $l = 0L
|        if ([long]::TryParse([string]$Response.expires_on, [ref]$l) -and $l -gt 0) {
|            return ([DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime.AddMinutes(-5))
|        }
|        $d = [datetime]::MinValue
|        if ([datetime]::TryParse([string]$Response.expires_on, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
|            return $d.AddMinutes(-5)
|        }
|    }
|    return $now.AddMinutes(30)
|}
|
|# ---------------------------------------------------------------------------------------------------------------
|# HANDED-OVER TOKENS (#876, owner 2026-10-21 "test trial with support app today"): Invardia's bootstrap may hand the
|# install the access tokens it already holds, in $env:SI_HANDOFF_TOKENS -- the same shape as PIM_HANDOFF_TOKENS:
|#   { "https://management.azure.com/": { "access_token": "...", "expires_on": <unix seconds> },
|#     "https://graph.microsoft.com/": {...}, "https://database.windows.net/": {...} }
|# With them the install signs in to NOTHING itself: no browser, no Cloud Shell endpoint, no app sign-in. The tokens may be
|# a person's (delegated) or an application's (the Invardia Support app: idtyp app, no scp) -- the claims say which, and an
|# application's object id (oid) IS its service principal's. Every token must be for the SAME tenant (and for the install's
|# tenant when one is named): one for another tenant refuses the whole hand-over. Read ONCE, kept in memory only
|# ($global:SI_SetupHandoff), and the variable is removed from the environment so no later process inherits it. No refresh
|# token crosses over, so a token cannot be renewed: when one is about to run out the install STOPS with one plain line
|# and resumes from that step with a fresh hand-over. An Invardia Support session open in the same shell wins over the
|# hand-over (its calls are recorded in the customer's audit log and its tokens are renewed by the session).
|# ---------------------------------------------------------------------------------------------------------------
|$script:SIHandoffMinMinutes = 2
|
|function Get-SIHandoffResourceKey {
|    <# PURE. The comparison key of a token audience: 'https://graph.microsoft.com' and '.../' and '.../.default' are one. #>
|    param([string]$Resource)
|    return ((("$Resource".Trim()) -replace '/\.default$', '').TrimEnd('/') + '/').ToLowerInvariant()
|}
|
|function Get-SIHandoffExpiredText {
|    <# PURE. The one line said when a handed-over token runs out (the install resumes from the step it stopped at). #>
|    param([string]$Resource)
|    $what = if ("$Resource".Trim()) { ' (for {0})' -f (Get-SIHandoffResourceKey $Resource).TrimEnd('/') } else { '' }
|    'The hand-over sign-in{0} has expired -- restart the install with a fresh code from the installation page (the install resumes where it stopped).' -f $what
|}
|
|function Import-SIHandoffTokens {
|    <#
|        PURE given -Json and -NowUtc. Reads the bootstrap's hand-over JSON. Returns
|          @{ Present; Ok; Reason; TenantId; IsApp; ObjectId; AppId; Account; Tokens = @{ <resource key> = @{ Token; ExpiresAt } } }
|        Present = something was handed over. Ok = it can be used (at least an Azure Resource Manager token, every token for
|        one tenant -- -TenantId when given -- and every token of one kind: all a person's or all one application's).
|        Reason (when not Ok) never contains token text. ExpiresAt = the earlier of expires_on and the token's own exp.
|    #>
|    param([AllowEmptyString()][string]$Json, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow)
|    $out = @{ Present = $false; Ok = $false; Reason = ''; TenantId = ''; IsApp = $false; ObjectId = ''; AppId = ''; Account = ''; Tokens = @{} }
|    if (-not "$Json".Trim()) { return $out }
|    $out.Present = $true
|    $o = $null
|    try { $o = "$Json" | ConvertFrom-Json } catch { $out.Reason = 'the hand-over could not be read (it is not JSON)'; return $out }
|    $tids = @(); $kinds = @(); $oids = @()
|    foreach ($p in @($o.PSObject.Properties)) {
|        $v = $p.Value; $tok = ''; $exp = $null
|        if ($v -is [string]) { $tok = $v }
|        elseif ($null -ne $v -and $v.PSObject.Properties['access_token']) { $tok = [string]$v.access_token; if ($v.PSObject.Properties['expires_on']) { $exp = $v.expires_on } }
|        if (-not $tok.Trim()) { continue }
|        $c = ConvertFrom-SISignInJwt $tok
|        if (-not $c -or -not $c.PSObject.Properties['tid'] -or -not [string]$c.tid) { $out.Reason = ('the token handed over for {0} cannot be read (no tenant in it)' -f $p.Name); return $out }
|        $tid = ([string]$c.tid).Trim().ToLowerInvariant()
|        if ("$TenantId".Trim() -and $tid -ne "$TenantId".Trim().ToLowerInvariant()) {
|            $out.Reason = ('the token handed over for {0} is for tenant {1}, not this installation''s tenant {2}' -f $p.Name, $tid, "$TenantId".Trim()); return $out
|        }
|        $isApp = ([string]$(if ($c.PSObject.Properties['idtyp']) { $c.idtyp } else { '' }) -eq 'app') -or -not ($c.PSObject.Properties['scp'] -and [string]$c.scp)
|        # the expiry: the earlier of what the bootstrap says and the token's own exp claim
|        $ends = @()
|        $l = 0L
|        if ($null -ne $exp -and [long]::TryParse([string]$exp, [ref]$l) -and $l -gt 0) { $ends += [DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime }
|        if ($c.PSObject.Properties['exp'] -and [long]::TryParse([string]$c.exp, [ref]$l) -and $l -gt 0) { $ends += [DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime }
|        if (-not $ends.Count) { $out.Reason = ('the token handed over for {0} carries no expiry' -f $p.Name); return $out }
|        $out.Tokens[(Get-SIHandoffResourceKey $p.Name)] = @{ Token = $tok; ExpiresAt = (@($ends | Sort-Object) | Select-Object -First 1) }
|        $tids += $tid; $kinds += $isApp; $oids += ([string]$(if ($c.PSObject.Properties['oid']) { $c.oid } else { '' })).ToLowerInvariant()
|        if (-not $out.AppId -and $c.PSObject.Properties['appid']) { $out.AppId = [string]$c.appid }
|        if (-not $out.AppId -and $c.PSObject.Properties['azp']) { $out.AppId = [string]$c.azp }
|        if (-not $out.Account -and -not $isApp) { $out.Account = [string](Get-SISignInAccountName $c) }
|    }
|    if (-not $out.Tokens.Count) { $out.Reason = 'the hand-over holds no token'; return $out }
|    if (@($tids | Select-Object -Unique).Count -gt 1) { $out.Reason = ('the tokens handed over are for different tenants ({0})' -f ((@($tids | Select-Object -Unique)) -join ', ')); $out.Tokens = @{}; return $out }
|    if (@($kinds | Select-Object -Unique).Count -gt 1 -or @($oids | Where-Object { $_ } | Select-Object -Unique).Count -gt 1) {
|        $out.Reason = 'the tokens handed over are not all for the same identity'; $out.Tokens = @{}; return $out
|    }
|    if (-not $out.Tokens.ContainsKey('https://management.azure.com/')) { $out.Reason = 'the hand-over holds no Azure Resource Manager token'; $out.Tokens = @{}; return $out }
|    $out.TenantId = [string]$tids[0]; $out.IsApp = [bool]$kinds[0]
|    $out.ObjectId = [string](@($oids | Where-Object { $_ }) | Select-Object -First 1)
|    if ($out.IsApp) { $out.Account = $out.AppId }
|    $out.Ok = $true
|    return $out
|}
|
|function Get-SISetupHandoff {
|    <#
|        The hand-over of this process ($global:SI_SetupHandoff), read from $env:SI_HANDOFF_TOKENS the first time it is asked
|        for (then removed from the environment). $null when nothing was handed over. -TenantId: the install's tenant (a
|        hand-over for another tenant THROWS -- never used, never silently replaced by another sign-in).
|    #>
|    param([string]$TenantId)
|    $h = Get-Variable -Scope Global -Name SI_SetupHandoff -ValueOnly -ErrorAction Ignore
|    if (-not ($h -is [hashtable])) {
|        $json = [string][Environment]::GetEnvironmentVariable('SI_HANDOFF_TOKENS')
|        if (-not $json.Trim()) { return $null }
|        $h = Import-SIHandoffTokens -Json $json -TenantId $TenantId
|        [Environment]::SetEnvironmentVariable('SI_HANDOFF_TOKENS', $null)
|        Remove-Item -Path 'env:SI_HANDOFF_TOKENS' -ErrorAction SilentlyContinue
|        $global:SI_SetupHandoff = $h
|    }
|    if (-not $h.Present) { return $null }
|    if (-not $h.Ok) { throw ('The sign-in handed over by the installation page cannot be used: {0}. Nothing was changed. Restart the install with a fresh code from the installation page.' -f $h.Reason) }
|    if ("$TenantId".Trim() -and $h.TenantId -and $h.TenantId -ne "$TenantId".Trim().ToLowerInvariant()) {
|        throw ('The sign-in handed over by the installation page is for tenant {0}, not this installation''s tenant {1}. Nothing was changed. Restart the install from the installation page of tenant {1}.' -f $h.TenantId, "$TenantId".Trim())
|    }
|    return $h
|}
|
|function Test-SISetupHandoffPresent {
|    <# Was a sign-in handed over to this process (and not refused)? Never throws. #>
|    try { return [bool](Get-SISetupHandoff) } catch { return $false }
|}
|
|function Get-SISetupHandoffStatus {
|    <#
|        PURE given -NowUtc. Which handed-over tokens are usable for at least -MinMinutes more: @{ Expired = @(<resource>);
|        Missing = @(<resource>) } over -Resources. Used before each install step, so a step never starts on a token that
|        runs out under it.
|    #>
|    param([Parameter(Mandatory)][hashtable]$Handoff, [string[]]$Resources = @('https://management.azure.com/'), [datetime]$NowUtc = [datetime]::UtcNow, [int]$MinMinutes = $script:SIHandoffMinMinutes)
|    $exp = @(); $miss = @()
|    foreach ($r in $Resources) {
|        $k = Get-SIHandoffResourceKey $r
|        if (-not $Handoff.Tokens.ContainsKey($k)) { $miss += $k; continue }
|        if ($Handoff.Tokens[$k].ExpiresAt -le $NowUtc.AddMinutes($MinMinutes)) { $exp += $k }
|    }
|    @{ Expired = $exp; Missing = $miss }
|}
|
|# ---------------------------------------------------------------------------------------------------------------
|# The loopback listener and the browser
|# ---------------------------------------------------------------------------------------------------------------
|function Get-SIFreeLoopbackPort {
|    <# A free TCP port on the loopback interface (the OS picks it). #>
|    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
|    try { $l.Start(); return ([System.Net.IPEndPoint]$l.LocalEndpoint).Port } finally { $l.Stop() }
|}
|
|function Get-SISignInEdgePath {
|    <# The Microsoft Edge executable on Windows ($null when absent): the sign-in opens InPrivate in it. #>
|    foreach ($b in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
|        if (-not "$b".Trim()) { continue }
|        $p = [IO.Path]::Combine($b, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
|        if (Test-Path -LiteralPath $p) { return $p }
|    }
|    $null
|}
|
|function Open-SISignInBrowser {
|    <#
|        Opens the sign-in page. Never throws: the URL is always printed as well.
|        #564 (PIM's install at customer I, 2026-10-10): a normal browser window opens the DEFAULT profile, whose saved account signs in
|        silently -- the person never sees a credential prompt and lands in the wrong tenant. On Windows the page opens in an
|        Edge InPrivate window (no saved account, the sign-in form always appears); without Edge, the default browser.
|        SI_SIGNIN_BROWSER=none: nothing is opened -- the person pastes the printed address into the right browser profile.
|    #>
|    param([Parameter(Mandatory)][string]$Url)
|    if ("$env:SI_SIGNIN_BROWSER".Trim().ToLowerInvariant() -eq 'none') { return $false }
|    try {
|        if ($PSVersionTable.PSEdition -ne 'Core' -or $IsWindows) {
|            $edge = Get-SISignInEdgePath
|            if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--inprivate', '--new-window', $Url) | Out-Null; return $true }
|            Start-Process -FilePath $Url | Out-Null; return $true
|        }
|        if ($IsMacOS) { & open $Url 2>$null | Out-Null; return $true }
|        & xdg-open $Url 2>$null | Out-Null
|        return $true
|    } catch { return $false }
|}
|
|function Wait-SILoopbackAuthCode {
|    <#
|        Listens on http://localhost:<Port>/ (the loopback interface only) for the browser's redirect, answers it with a
|        short page, and returns the request's query string. -Listener is a test seam (an HttpListener the test drives).
|    #>
|    param([Parameter(Mandatory)][int]$Port, [int]$TimeoutSec = 300, $Listener)
|    $own = $false
|    if (-not $Listener) {
|        $Listener = New-Object System.Net.HttpListener
|        $Listener.Prefixes.Add(('http://localhost:{0}/' -f $Port))
|        $Listener.Start()
|        $own = $true
|    }
|    try {
|        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
|        while ($true) {
|            $task = $Listener.GetContextAsync()
|            $left = [int][Math]::Max(1, ($deadline - [datetime]::UtcNow).TotalMilliseconds)
|            if (-not $task.Wait($left)) {
|                throw ('No answer from the browser sign-in within {0} seconds. Run the same command again and complete the sign-in in the browser window that opens.' -f $TimeoutSec)
|            }
|            $ctx = $task.Result
|            $query = [string]$ctx.Request.Url.Query
|            $isAnswer = ($query -match '(^|[?&])(code|error)=')
|            $html = if ($isAnswer) {
|                '<!doctype html><html><head><meta charset="utf-8"><title>SecurityInsight sign-in</title></head><body style="font-family:Segoe UI,Arial,sans-serif;margin:40px"><h2>SecurityInsight</h2><p>The sign-in is complete. You can close this window and return to PowerShell.</p></body></html>'
|            } else { '<!doctype html><html><body></body></html>' }
|            $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
|            try {
|                $ctx.Response.StatusCode = 200
|                $ctx.Response.ContentType = 'text/html; charset=utf-8'
|                $ctx.Response.ContentLength64 = $bytes.Length
|                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
|            } finally { $ctx.Response.OutputStream.Close(); $ctx.Response.Close() }
|            if ($isAnswer) { return $query }
|            # a favicon or a probe: keep listening for the real redirect
|        }
|    } finally {
|        if ($own) { try { $Listener.Stop(); $Listener.Close() } catch { } }
|    }
|}
|
|# ---------------------------------------------------------------------------------------------------------------
|# Token endpoints
|# ---------------------------------------------------------------------------------------------------------------
|function Invoke-SISignInTokenRequest {
|    <# POST to the Entra v2 token endpoint of -TenantId with -Form. Returns the parsed response; throws Entra's own
|       error text (AADSTS...) in a customer sentence. #>
|    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][System.Collections.IDictionary]$Form, [string]$What = 'Sign-in')
|    $pairs = foreach ($k in $Form.Keys) { '{0}={1}' -f $k, [uri]::EscapeDataString([string]$Form[$k]) }
|    $uri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f [uri]::EscapeDataString($TenantId)
|    $r = Invoke-SIAzRestHttp -Method POST -Uri $uri -Body ($pairs -join '&') -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60
|    $code = [int]$r.StatusCode
|    $j = $null; try { $j = ([string]$r.Content) | ConvertFrom-Json } catch { }
|    if ($code -lt 200 -or $code -ge 300 -or -not $j -or -not $j.access_token) {
|        $msg = if ($j -and $j.error_description) { ([string]$j.error_description -split "`r?`n")[0] } elseif ($code -eq 0) { [string]$r.Content } else { [string]$r.Content }
|        throw ('{0} failed (HTTP {1}): {2}' -f $What, $code, $msg)
|    }
|    return $j
|}
|
|function Get-SICloudShellToken {
|    <# A token for -Resource from the Azure Cloud Shell token endpoint: the person who opened Cloud Shell. #>
|    param([Parameter(Mandatory)][string]$Resource)
|    $ep = Get-SICloudShellEndpoint
|    if (-not $ep) { throw 'This is not Azure Cloud Shell: no Cloud Shell token endpoint (MSI_ENDPOINT) is set.' }
|    $res = ($Resource -replace '/\.default$', '').TrimEnd('/') + '/'
|    $r = Invoke-SIAzRestHttp -Method POST -Uri $ep -Headers @{ Metadata = 'true' } -Body ('resource=' + [uri]::EscapeDataString($res)) `
|             -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60
|    $j = $null; try { $j = ([string]$r.Content) | ConvertFrom-Json } catch { }
|    if ([int]$r.StatusCode -lt 200 -or [int]$r.StatusCode -ge 300 -or -not $j -or -not $j.access_token) {
|        throw ('Azure Cloud Shell did not hand out a token for {0} (HTTP {1}): {2}. Close and reopen Cloud Shell, then run the same command again.' -f $res, $r.StatusCode, $r.Content)
|    }
|    return [pscustomobject]@{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
|}
|
|# ---------------------------------------------------------------------------------------------------------------
|# The user session
|# ---------------------------------------------------------------------------------------------------------------
|function Send-SISignInNotice {
|    <#
|        #564: says "waiting: sign-in required for <resource> in tenant <t>" BEFORE a browser window opens -- on the console
|        and to the host's progress feed: $global:SI_SignInNotify = { param($Resource, $TenantId) ... } (the guided install
|        registers it and posts the line as an event, so the status page shows WHY the install waits). Never throws.
|    #>
|    param([Parameter(Mandatory)][string]$Resource, [string]$TenantId)
|    $t = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { 'your organisation' }
|    Write-Host ('waiting: sign-in required for {0} in tenant {1}' -f $Resource, $t) -ForegroundColor Yellow
|    $n = Get-Variable -Scope Global -Name SI_SignInNotify -ValueOnly -ErrorAction Ignore
|    if ($n -is [scriptblock]) { try { & $n $Resource $TenantId } catch { } }
|}
|
|function Assert-SISignInTenant {
|    <# PURE apart from throwing. #564: a token whose tid is not the target tenant (a wrong browser profile or account) is
|       refused before any call is made with it. No target tenant (or not a tenant id) = nothing to compare. #>
|    param([AllowEmptyString()][string]$Token, [string]$TenantId, [string]$Where = 'the browser')
|    if (-not "$TenantId".Trim() -or "$TenantId" -notmatch '^[0-9a-fA-F-]{36}$') { return }
|    $c = ConvertFrom-SISignInJwt $Token
|    $tid = if ($c -and $c.PSObject.Properties['tid']) { [string]$c.tid } else { '' }
|    if ($tid -and $tid -ne $TenantId) {
|        throw ('You signed in to tenant {0} in {1}, but this installation is for tenant {2}. Sign in with an account of tenant {2} (open the address in the browser profile of an admin of that tenant), then run the same command again.' -f $tid, $Where, $TenantId)
|    }
|}
|
|function Test-SISignInInteractive {
|    <# Can this session open a browser for a person? (A seam: tests fake it -- a gate run over SSH is never interactive.) #>
|    $interactive = $true
|    try { $interactive = [Environment]::UserInteractive } catch { }
|    [bool]$interactive
|}
|
|function Invoke-SIBrowserCodeSignIn {
|    <#
|        ONE browser sign-in (authorization code + PKCE on a loopback listener) for -Resource with the public client
|        -ClientId. Returns Entra's token response (access_token, refresh_token, expires_in). The account must belong to
|        -TenantId (#564). -Prompt '' with a -LoginHint lets the browser reuse the person's sign-in (no account picker).
|    #>
|    param(
|        [string]$TenantId,
|        [Parameter(Mandatory)][string]$ClientId,
|        [Parameter(Mandatory)][string]$Resource,
|        [string]$LoginHint,
|        [string]$Prompt = 'select_account',
|        [string]$What = 'Azure Resource Manager',
|        [string]$Title = 'Sign in to Azure in your browser.',
|        [string]$FailText = 'The Azure sign-in',
|        [int]$TimeoutSec = 300
|    )
|    $pkce = New-SIPkcePair
|    $state = New-SIRandomBase64Url -ByteCount 16
|    $port = Get-SIFreeLoopbackPort
|    $redirect = 'http://localhost:{0}/' -f $port
|    $scope = (Get-SISignInScope -Resource $Resource) + ' offline_access openid profile'
|    $url = Get-SIAuthorizeUrl -TenantId $TenantId -ClientId $ClientId -RedirectUri $redirect -Scope $scope -CodeChallenge $pkce.Challenge -State $state -LoginHint $LoginHint -Prompt $Prompt
|    # #564: the reason for the wait is said BEFORE any window opens; the address is always printed
|    Send-SISignInNotice -Resource $What -TenantId $TenantId
|    $who = if ($TenantId) { 'an admin of tenant ' + $TenantId } else { 'the admin who installs' }
|    Write-Host ''
|    Write-Host ('{0} If no window opens, or it opens in the wrong profile or account, open this address in the browser profile of {1}:' -f $Title, $who) -ForegroundColor Cyan
|    Write-Host ('  {0}' -f $url)
|    $null = Open-SISignInBrowser -Url $url
|    $query = Wait-SILoopbackAuthCode -Port $port -TimeoutSec $TimeoutSec
|    $code = Resolve-SIAuthRedirect -Query $query -ExpectedState $state
|    $authTenant = if ($TenantId) { $TenantId } else { 'organizations' }
|    $j = Invoke-SISignInTokenRequest -TenantId $authTenant -What $FailText -Form ([ordered]@{
|        client_id     = $ClientId
|        grant_type    = 'authorization_code'
|        code          = $code
|        redirect_uri  = $redirect
|        code_verifier = $pkce.Verifier
|        scope         = $scope
|    })
|    # #564: the account must belong to the TARGET tenant -- refused here, before any call uses the token
|    Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId $TenantId -Where 'the browser'
|    return $j
|}
|
|function Connect-SISetupUser {
|    <#
|        Signs a PERSON in for setup and records the session in this process (memory only).
|          -Method Auto       Cloud Shell when this is Cloud Shell, else the browser (code + PKCE on a loopback listener)
|          -Method CloudShell the Cloud Shell token endpoint
|          -Method Browser    the browser
|        -TenantId: the tenant to sign in to (the browser signs in there; Cloud Shell must already be in it).
|        Returns the session: Method, TenantId, Account, ObjectId.
|    #>
|    param(
|        [string]$TenantId,
|        [ValidateSet('Auto', 'CloudShell', 'Browser', 'Handoff')][string]$Method = 'Auto',
|        [string]$LoginHint,
|        [int]$TimeoutSec = 300,
|        [string]$ClientId
|    )
|    # #876: a sign-in handed over by the installation page answers first -- nothing is signed in here
|    $ho = $null
|    if ($Method -in 'Auto', 'Handoff') { $ho = Get-SISetupHandoff -TenantId $TenantId }
|    if ($Method -eq 'Handoff' -and -not $ho) { throw 'No sign-in was handed over to this PowerShell session (SI_HANDOFF_TOKENS is not set).' }
|    if ($ho) { $Method = 'Handoff' }
|    if ($Method -eq 'Auto') { $Method = if (Test-SICloudShell) { 'CloudShell' } else { 'Browser' } }
|    $st = Get-SISignInState
|    $st.Tokens = @{}
|    $st['Exchange'] = $null
|    $arm = 'https://management.azure.com/'
|    if ($Method -eq 'Handoff') {
|        $armTok = $ho.Tokens[$arm]
|        if ($armTok.ExpiresAt -le [datetime]::UtcNow.AddMinutes($script:SIHandoffMinMinutes)) { throw (Get-SIHandoffExpiredText -Resource $arm) }
|        $st.Session = @{ Method = 'Handoff'; TenantId = $ho.TenantId; Account = $ho.Account; ObjectId = $ho.ObjectId; IsApp = [bool]$ho.IsApp; AppId = $ho.AppId; RefreshToken = $null; ClientId = $null }
|        foreach ($k in @($ho.Tokens.Keys)) { $st.Tokens[$k] = @{ Token = $ho.Tokens[$k].Token; ExpiresAt = $ho.Tokens[$k].ExpiresAt } }
|        Write-Host ('Using the sign-in handed over by the installation page: {0} {1} (tenant {2}) -- no sign-in here.' -f $(if ($ho.IsApp) { 'the application' } else { 'the account' }), $ho.Account, $ho.TenantId) -ForegroundColor Green
|        return [pscustomobject]@{ Method = 'Handoff'; TenantId = $ho.TenantId; Account = $ho.Account; ObjectId = $ho.ObjectId; IsApp = [bool]$ho.IsApp }
|    }
|    if ($Method -eq 'CloudShell') {
|        $t = Get-SICloudShellToken -Resource $arm
|        $c = ConvertFrom-SISignInJwt $t.Token
|        $tid = if ($c) { [string]$c.tid } else { '' }
|        if ($TenantId -and $tid -and $tid -ne $TenantId) {
|            throw ("Azure Cloud Shell is signed in to tenant {0}, but this needs tenant {1}. Switch directory in the Azure portal (Settings > Directories), reopen Cloud Shell, then run the same command again." -f $tid, $TenantId)
|        }
|        $st.Session = @{ Method = 'CloudShell'; TenantId = $tid; Account = (Get-SISignInAccountName $c); ObjectId = $(if ($c) { [string]$c.oid } else { '' }); RefreshToken = $null; ClientId = $null }
|        $st.Tokens[$arm] = @{ Token = $t.Token; ExpiresAt = $t.ExpiresAt }
|    } else {
|        if (Test-SICloudShell) {
|            # #564: Cloud Shell has its own token endpoint (-Method CloudShell / Auto); a localhost answer cannot reach it
|            throw 'Azure Cloud Shell cannot take the browser sign-in''s answer (it goes to localhost on your own machine). In Cloud Shell setup signs in through Cloud Shell itself: run the same command without asking for the browser sign-in.'
|        }
|        if (-not (Test-SISignInInteractive)) {
|            throw 'A person has to sign in for this step, and this PowerShell session cannot open a browser. Run it in an interactive session or in Azure Cloud Shell, or sign in with an app (certificate or client secret).'
|        }
|        if (-not $ClientId) { $ClientId = Get-SISignInClientId }
|        $j = Invoke-SIBrowserCodeSignIn -TenantId $TenantId -ClientId $ClientId -Resource $arm -LoginHint $LoginHint -TimeoutSec $TimeoutSec
|        $c = ConvertFrom-SISignInJwt ([string]$j.access_token)
|        $tid = if ($c -and $c.tid) { [string]$c.tid } else { $TenantId }
|        $st.Session = @{ Method = 'Browser'; TenantId = $tid; Account = (Get-SISignInAccountName $c); ObjectId = $(if ($c) { [string]$c.oid } else { '' }); RefreshToken = [string]$j.refresh_token; ClientId = $ClientId }
|        $st.Tokens[$arm] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
|    }
|    Write-Host ('Signed in to Azure as {0} (tenant {1}, {2}).' -f $st.Session.Account, $st.Session.TenantId, $(if ($st.Session.Method -eq 'CloudShell') { 'Azure Cloud Shell' } else { 'browser sign-in' })) -ForegroundColor Green
|    return [pscustomobject]@{ Method = $st.Session.Method; TenantId = $st.Session.TenantId; Account = $st.Session.Account; ObjectId = $st.Session.ObjectId }
|}
|
|function Test-SISetupUserSignedIn {
|    $st = Get-SISignInState
|    return ($st.Session -is [hashtable])
|}
|
|function Get-SISetupUserToken {
|    <# A token for -Resource as the signed-in person: memory cache, else the Cloud Shell endpoint or the refresh token. #>
|    param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
|    $st = Get-SISignInState
|    $s = $st.Session
|    if (-not ($s -is [hashtable])) { throw 'No one is signed in to Azure in this PowerShell session. Run the same command again to sign in.' }
|    $res = ($Resource -replace '/\.default$', '').TrimEnd('/') + '/'
|    if ($s.Method -eq 'Handoff') {
|        # #876: a handed-over token cannot be renewed here (no refresh token crosses over): one that is about to run out
|        # stops the step with one plain line, and the install resumes from that step with a fresh hand-over
|        $k = Get-SIHandoffResourceKey $res
|        $hit = $null
|        foreach ($tk in @($st.Tokens.Keys)) { if ((Get-SIHandoffResourceKey $tk) -eq $k) { $hit = $st.Tokens[$tk]; break } }
|        if (-not $hit) {
|            throw ('The sign-in handed over by the installation page holds no token for {0}, which this step needs. Nothing more was changed. Restart the install with a hand-over that includes {0} (the install resumes where it stopped).' -f $k.TrimEnd('/'))
|        }
|        if ($hit.ExpiresAt -le [datetime]::UtcNow.AddMinutes($script:SIHandoffMinMinutes)) { $global:SI_SetupHandoffExpired = $k; throw (Get-SIHandoffExpiredText -Resource $k) }
|        return [string]$hit.Token
|    }
|    if (-not $ForceRefresh -and $st.Tokens.ContainsKey($res) -and $st.Tokens[$res].ExpiresAt -gt [datetime]::UtcNow) { return [string]$st.Tokens[$res].Token }
|    if ($s.Method -eq 'CloudShell') {
|        $t = Get-SICloudShellToken -Resource $res
|        $st.Tokens[$res] = @{ Token = $t.Token; ExpiresAt = $t.ExpiresAt }
|        return $t.Token
|    }
|    if (Test-SISignInExchangeResource -Resource $res) {
|        # Exchange Online takes only a token of its own client (Exchange.Manage): its own refresh token, and the first time
|        # one more browser sign-in -- the same account pre-filled, so the browser normally signs straight in.
|        $xc = Get-SISignInExchangeClientId
|        $x = $st['Exchange']
|        $j = $null
|        if ($x -is [hashtable] -and $x.RefreshToken -and $x.ClientId -eq $xc) {
|            try {
|                $j = Invoke-SISignInTokenRequest -TenantId $s.TenantId -What 'Getting a token for Exchange Online' -Form ([ordered]@{
|                    client_id = $xc; grant_type = 'refresh_token'; refresh_token = $x.RefreshToken; scope = (Get-SISignInScope -Resource $res) + ' offline_access' })
|            } catch { $j = $null }
|        }
|        if (-not $j) {
|            if (-not (Test-SISignInInteractive)) { throw 'Exchange Online needs its own sign-in in the browser, and this PowerShell session cannot open a browser. Run it in an interactive PowerShell window.' }
|            $j = Invoke-SIBrowserCodeSignIn -TenantId $s.TenantId -ClientId $xc -Resource $res -LoginHint ([string]$s.Account) -Prompt '' `
|                     -What 'Exchange Online' -Title 'Sign in once more, for Exchange Online (it accepts only its own sign-in; your account is filled in).' -FailText 'The Exchange Online sign-in'
|        }
|        $st['Exchange'] = @{ ClientId = $xc; RefreshToken = $(if ($j.refresh_token) { [string]$j.refresh_token } elseif ($x -is [hashtable]) { $x.RefreshToken } else { $null }) }
|        Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId ([string]$s.TenantId) -Where 'the token for Exchange Online'
|        $st.Tokens[$res] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
|        return [string]$j.access_token
|    }
|    if (-not $s.RefreshToken) { throw 'The Azure sign-in has expired. Run the same command again to sign in.' }
|    $j = Invoke-SISignInTokenRequest -TenantId $s.TenantId -What ('Getting a token for {0}' -f $res) -Form ([ordered]@{
|        client_id     = $s.ClientId
|        grant_type    = 'refresh_token'
|        refresh_token = $s.RefreshToken
|        scope         = (Get-SISignInScope -Resource $res) + ' offline_access'
|    })
|    if ($j.refresh_token) { $s.RefreshToken = [string]$j.refresh_token }   # Entra rotates it
|    Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId ([string]$s.TenantId) -Where ('the token for ' + $res)
|    $st.Tokens[$res] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
|    return [string]$j.access_token
|}
|
|function Disconnect-SISetupUser {
|    $st = Get-SISignInState
|    $st.Session = $null
|    $st.Tokens = @{}
|    $st['Exchange'] = $null
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-InvardiaUpdate.ps1'] = @{ Sha256 = 'b17b367fb6072bf40d18031a5b7633a72ea3695e19aa8eadf62b2fa8ad2bd641'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- UPDATES FROM INVARDIA (#240). The client side of Invardia's frozen update contract v1 (owner
|    2026-10-04: "licence + install key"). ONE client for both editions (framework PRO-COMMUNITY-SAME, 2026-11-11): an install
|    with a licence asks the install route below; a Community install without one asks Invardia's anonymous Community route
|    (container/updater/_shared/SI-UpdaterCommunity.ps1) -- the same signed-manifest checks, the same trusted keys.
|
|    THE INSTALL KEY IS CLAIMED AUTOMATICALLY (Invardia owner decision 2026-10-04 -- nobody hands one out):
|      POST <base>/api/install-keys/claim  { product, tenantId (the 'tid' of the identity's own token), licence }
|        201 { key, environment, telemetryEnabled, uplink{...}, updates{ endpoint, header } } -> stored in the Key Vault
|        403 licence (reason) | 409 keyExists / tenantBelongsToAnotherCompany (reported, NEVER claimed again in a loop) | 422
|      at install (unless the guided install's bundle carries installKey -- then that is stored and nothing is claimed) and
|      when the updater starts with no key stored. The manifest is then asked for at the returned updates.endpoint, with
|      the key in updates.header; the frozen URLs below are the defaults.
|
|    PULL (each update run, for kind 'code' and kind 'templates'):
|      POST <base>/api/updates/securityinsight/manifest   body { kind, licence: <the licence file text>, ring: 0-3 }
|           header X-Invardia-Install-Key: inv-...      (the install key -- read from the install's Key Vault)
|           header X-Invardia-Install-Id: <guid>        (Invardia S16: the install's LASTING id, SI-InstallId -- only when the
|                                                        install has one; never the anonymous telemetry id, never made up here)
|        200 { manifest, manifestB64, signature, keyId, downloadUrl }
|        204 nothing released for this install's ring + kind     401 the install key     403 the licence (reason)
|        404 product   422 invalid request (fields; 'ring' when the pull carries none)   429 slow down (Retry-After)
|    THE RING IS SECURITYINSIGHT'S (framework UPDATE-1.7, operator 2026-10-06: "Solution (si, pim) decides WHAT version and
|      WHICH Ring to release in updates, Invardia relays only"): the pull carries this environment's OWN ring -- the updater's
|      SI_UPDATER_RING, else the ring recorded for the install (cfg.InstallState 'Ring', #308). With no ring known, NO pull is
|      made and the result says why (Action 'off'). Invardia answers with what SI released to that ring.
|    VERIFY before anything is used:
|      * the signature: RS256 (RSASSA-PKCS1-v1_5, SHA-256) over the base64-DECODED manifest bytes (UPDATE-1.2), against the TRUSTED
|        public keys EMBEDDED in this release (engine/_shared/SI-InvardiaUpdateKeys.json), chosen by keyId. A key list
|        fetched at run time is never trusted on its own. An EMPTY list refuses every manifest, and says so;
|      * the manifest is the one asked for (product securityinsight, the kind) and well formed;
|      * its sequence is not LOWER than the one this install applied for that kind (no replay of an old, validly signed
|        manifest);
|      * the SIGNED ring is the ring this environment asked for (UPDATE-1.7) -- a manifest for another ring, or none, is refused;
|      * manualStep set = HOLD: shown, never applied automatically, until the admin accepts that exact sequence.
|    DOWNLOAD: GET downloadUrl (a 15-minute token for that one file) -> the file; its size AND SHA-256 must equal the
|      signed manifest's, else it is deleted and refused.
|
|    🔒 THE INSTALL KEY IS A SECRET. It travels only in the X-Invardia-Install-Key header; it is never printed, never
|    logged, never put in a result, and every text this file returns is scrubbed of it. The download URL's token is
|    withheld from everything printed as well. Updates work even when telemetry is switched off.
|
|    🔒 NEVER THROWS. A network failure, a 4xx / 5xx or a refused manifest becomes a RESULT with an Action and a Reason,
|    so an update run that calls this is never failed by it. Every call that leaves the process goes through -Seams, so
|    the contract test runs offline. PS 5.1 safe.
|#>
|
|# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.
|
|# Invardia S16: the install's lasting id (SI-InstallId) as X-Invardia-Install-Id on the manifest pull
|if (-not (Get-Command -Name ConvertTo-SIInvardiaInstallId -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaInstallId.ps1')) }
|
|$script:SIInvardiaUpdateProduct      = 'securityinsight'
|$script:SIInvardiaUpdateDefaultBase   = 'https://invardia.com'
|$script:SIInvardiaUpdateKeyHeader     = 'X-Invardia-Install-Key'
|$script:SIInvardiaUpdateSecretKey     = 'SI-Invardia-InstallKey'
|$script:SIInvardiaUpdateSecretState   = 'SI-Update-State'
|$script:SIInvardiaUpdateSecretLicence = 'SI-License'
|$script:SIInvardiaUpdateKinds         = @('code', 'templates')
|$script:SIInvardiaUpdateKeysFile      = [IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaUpdateKeys.json')
|
|# =====================================================================================================================
|#  Pure helpers
|# =====================================================================================================================
|function Get-SIInvardiaUpdateBaseUrl {
|    <# Where Invardia is: -BaseUrl, else $global:SI_InvardiaUpdate_BaseUrl, else $env:SI_UPDATER_INVARDIA_BASE_URL, else
|       https://invardia.com. HTTPS only (the install key travels in a header). No trailing slash. Throws on http://. #>
|    param([string]$BaseUrl)
|    $u = @($BaseUrl, [string]$global:SI_InvardiaUpdate_BaseUrl, [string]$env:SI_UPDATER_INVARDIA_BASE_URL) | Where-Object { "$_".Trim() } | Select-Object -First 1
|    if (-not $u) { $u = $script:SIInvardiaUpdateDefaultBase }
|    $u = "$u".Trim().TrimEnd('/')
|    if ($u -notmatch '^https://[^/\s]+') { throw ("the update address must be an https:// URL, not '{0}'" -f $u) }
|    $u
|}
|
|function Get-SIInvardiaManifestUri {
|    param([Parameter(Mandatory)][string]$BaseUrl)
|    '{0}/api/updates/{1}/manifest' -f $BaseUrl.TrimEnd('/'), $script:SIInvardiaUpdateProduct
|}
|
|function Test-SIInvardiaInstallKeyFormat {
|    <# PURE. An Invardia install key: 'inv-' and at least 8 more visible characters. Never echoes the value. #>
|    param([AllowNull()][AllowEmptyString()][string]$InstallKey)
|    ("$InstallKey".Trim() -match '^inv-[^\s]{8,}$')
|}
|
|function Hide-SIInvardiaSecret {
|    <#
|        PURE. Text with the secrets withheld: every URL query (the download token, a SAS) dropped, anything shaped like an
|        install key (inv-...) masked, and each literal -Secret replaced. Everything this file returns passes through here.
|    #>
|    param([AllowNull()][AllowEmptyString()][string]$Text, [string[]]$Secret)
|    if ([string]::IsNullOrEmpty($Text)) { return $Text }
|    $t = $Text
|    foreach ($s in @($Secret | Where-Object { "$_".Length -ge 4 })) { $t = $t.Replace([string]$s, '<withheld>') }
|    $t = $t -replace '(https?://[^\s?"'']+)\?[^\s"'']*', '$1?<token withheld>'
|    $t = $t -replace '\binv-[^\s"'',;]+', 'inv-<withheld>'
|    $t
|}
|
|function New-SIInvardiaManifestBody {
|    <# PURE. The pull's JSON body: { kind, licence, ring } -- the licence is the licence FILE TEXT, as installed; the ring is
|       this environment's own (UPDATE-1.7: SI decides the ring; Invardia answers 422 without it). #>
|    param([Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind, [Parameter(Mandatory)][string]$Licence,
|          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
|    ([ordered]@{ kind = $Kind; licence = $Licence; ring = $Ring }) | ConvertTo-Json -Compress
|}
|
|function ConvertTo-SIInvardiaPullRing {
|    <# PURE. This environment's update ring as the pull sends it: 0..3 (number, '1', 'r1', 'ring 1'), else -1 (none / not a ring). #>
|    param([AllowNull()]$Value)
|    if ($null -eq $Value -or $Value -is [bool]) { return -1 }
|    $t = ("$Value").Trim().ToLowerInvariant() -replace '^(ring\s*|r)', ''
|    $n = 0
|    if (-not [int]::TryParse($t, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return -1 }
|    if ($n -lt 0 -or $n -gt 3) { return -1 }
|    $n
|}
|
|function Test-SIInvardiaReleaseOfVersion {
|    <#
|        PURE. Does a release named -Released carry the code whose VERSION file says -Archive? Equal, or a BUILD of it:
|        '<VERSION>.<build number>' (e.g. 3.0.0.202610061530). Ring 1 takes every build of the same VERSION, and Invardia
|        keeps a version immutable, so each build is released under its own number (Publish-SIRelease.ps1 -Build).
|    #>
|    param([AllowEmptyString()][string]$Released, [AllowEmptyString()][string]$Archive)
|    $r = "$Released".Trim(); $a = "$Archive".Trim()
|    if (-not $r -or -not $a) { return $false }
|    ($r -eq $a) -or ($r -match ('^' + [regex]::Escape($a) + '\.\d{1,14}$'))
|}
|
|function Get-SIInvardiaNoRingReason {
|    <# PURE. Why no Pro pull is made when this environment has no update ring (UPDATE-1.7), in plain words. #>
|    param([AllowNull()]$Ring)
|    $what = if ($null -ne $Ring -and "$Ring".Trim()) { "'$Ring' is not 0, 1, 2 or 3" } else { 'none is set' }
|    "this environment has no update ring ($what) -- SecurityInsight decides which ring an environment is in, so no update is asked for until one is set: SI_UPDATER_RING on the updater job (setup\Install-SIUpdaterJob.ps1 -UpdateRing <0-3>), or setup\Set-SIInstallRing.ps1 -Ring <0-3> / 'Update ring' on the Settings page"
|}
|
|function ConvertFrom-SIInvardiaBase64 {
|    <# PURE. Bytes from base64 OR base64url (padding optional). $null when it is neither. #>
|    param([AllowNull()][AllowEmptyString()][string]$Text)
|    $s = "$Text".Trim()
|    if (-not $s) { return $null }
|    $s = $s.Replace('-', '+').Replace('_', '/')
|    while ($s.Length % 4) { $s += '=' }
|    try { return , [Convert]::FromBase64String($s) } catch { return $null }
|}
|
|function Read-SIInvardiaDer {
|    <# PURE. One DER TLV at -Offset: @{ Tag; Start (of the value); Length; Next }. Throws on a malformed length. #>
|    param([Parameter(Mandatory)][byte[]]$Bytes, [int]$Offset = 0)
|    $tag = $Bytes[$Offset]; $i = $Offset + 1
|    $len = [int]$Bytes[$i]; $i++
|    if ($len -band 0x80) {
|        $n = $len -band 0x7F
|        if ($n -lt 1 -or $n -gt 4) { throw 'unsupported DER length' }
|        $len = 0
|        for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + [int]$Bytes[$i]; $i++ }
|    }
|    if ($i + $len -gt $Bytes.Length) { throw 'truncated DER' }
|    [pscustomobject]@{ Tag = $tag; Start = $i; Length = $len; Next = ($i + $len) }
|}
|
|function Get-SIInvardiaDerInteger {
|    param([byte[]]$Bytes, $Tlv)
|    if ($Tlv.Tag -ne 0x02) { throw 'expected a DER INTEGER' }
|    $start = $Tlv.Start; $len = $Tlv.Length
|    while ($len -gt 1 -and $Bytes[$start] -eq 0) { $start++; $len-- }   # the sign byte is not part of the number
|    $out = New-Object byte[] $len
|    [Array]::Copy($Bytes, $start, $out, 0, $len)
|    , $out
|}
|
|function ConvertFrom-SIInvardiaPublicKeyPem {
|    <#
|        PURE. RSAParameters (Modulus, Exponent) from a PEM public key: 'BEGIN PUBLIC KEY' (SubjectPublicKeyInfo) or
|        'BEGIN RSA PUBLIC KEY' (PKCS#1). Parsed by hand: Windows PowerShell 5.1 has no ImportFromPem. Throws when unreadable.
|    #>
|    param([Parameter(Mandatory)][string]$Pem)
|    $body = ($Pem -replace '-----[A-Z ]+-----', '' -replace '\s', '')
|    $der = [Convert]::FromBase64String($body)
|    $top = Read-SIInvardiaDer -Bytes $der -Offset 0
|    if ($top.Tag -ne 0x30) { throw 'not a DER SEQUENCE' }
|    $first = Read-SIInvardiaDer -Bytes $der -Offset $top.Start
|    if ($first.Tag -eq 0x30) {
|        # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, RSAPublicKey } }
|        $bits = Read-SIInvardiaDer -Bytes $der -Offset $first.Next
|        if ($bits.Tag -ne 0x03) { throw 'expected a BIT STRING' }
|        $rsaSeq = Read-SIInvardiaDer -Bytes $der -Offset ($bits.Start + 1)
|    } else {
|        $rsaSeq = $top
|    }
|    if ($rsaSeq.Tag -ne 0x30) { throw 'expected an RSAPublicKey SEQUENCE' }
|    $n = Read-SIInvardiaDer -Bytes $der -Offset $rsaSeq.Start
|    $e = Read-SIInvardiaDer -Bytes $der -Offset $n.Next
|    $p = New-Object System.Security.Cryptography.RSAParameters
|    $p.Modulus = Get-SIInvardiaDerInteger -Bytes $der -Tlv $n
|    $p.Exponent = Get-SIInvardiaDerInteger -Bytes $der -Tlv $e
|    $p
|}
|
|function ConvertFrom-SIInvardiaKeyEntry {
|    <#
|        PURE. One trusted-key entry -> @{ KeyId; Parameters (RSAParameters); Thumbprint; KeySize; Subject; NotAfter }. Accepts
|        { keyId, certificateB64 [, thumbprint -- must match] } (Invardia's public certificate, base64 DER), { keyId, jwk: { kty RSA,
|        n, e } } (the shape GET /api/updates/keys returns), { keyId, publicKeyPem } or { keyId, modulus, exponent }.
|        Throws with the reason when the entry is unusable.
|    #>
|    param([Parameter(Mandatory)]$Entry)
|    $id = "$($Entry.keyId)".Trim()
|    if (-not $id) { throw 'an entry has no keyId' }
|    $p = New-Object System.Security.Cryptography.RSAParameters
|    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] -and "$($o.$n)".Trim() }
|    $thumb = ''
|    if (& $has $Entry 'certificateB64') {
|        # Invardia's public CERTIFICATE (base64 DER): its RSA public key, and its thumbprint must be the one recorded with it.
|        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String(("$($Entry.certificateB64)" -replace '\s', '')))
|        $thumb = $cert.Thumbprint.ToUpperInvariant()
|        if ((& $has $Entry 'thumbprint') -and ("$($Entry.thumbprint)" -replace '\s', '').ToUpperInvariant() -ne $thumb) { throw ("key '{0}': the certificate's thumbprint {1} is not the one recorded with it" -f $id, $thumb) }
|        $rk = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
|        if (-not $rk) { throw ("key '{0}': the certificate carries no RSA public key" -f $id) }
|        $p = $rk.ExportParameters($false)
|    } elseif (& $has $Entry 'jwk') {
|        $j = $Entry.jwk
|        if ((& $has $j 'kty') -and "$($j.kty)" -ne 'RSA') { throw ("key '{0}' is not an RSA key" -f $id) }
|        $p.Modulus = ConvertFrom-SIInvardiaBase64 "$($j.n)"; $p.Exponent = ConvertFrom-SIInvardiaBase64 "$($j.e)"
|    } elseif (& $has $Entry 'publicKeyPem') {
|        $p = ConvertFrom-SIInvardiaPublicKeyPem -Pem "$($Entry.publicKeyPem)"
|    } elseif ((& $has $Entry 'modulus') -and (& $has $Entry 'exponent')) {
|        $p.Modulus = ConvertFrom-SIInvardiaBase64 "$($Entry.modulus)"; $p.Exponent = ConvertFrom-SIInvardiaBase64 "$($Entry.exponent)"
|    } else { throw ("key '{0}' has no jwk, publicKeyPem or modulus/exponent" -f $id) }
|    if (-not $p.Modulus -or -not $p.Exponent -or $p.Modulus.Length -lt 256) { throw ("key '{0}' is not a usable RSA public key of at least 2048 bits" -f $id) }
|    [pscustomobject]@{ KeyId = $id; Parameters = $p; Thumbprint = $thumb; KeySize = ($p.Modulus.Length * 8)
|                       Subject = $(if (& $has $Entry 'subject') { "$($Entry.subject)" } else { '' }); NotAfter = $(if (& $has $Entry 'notAfter') { $na = $Entry.notAfter; if ($na -is [datetime]) { $na.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { "$na" } } else { '' }) }
|}
|
|function Get-SIInvardiaTrustedKeys {
|    <#
|        The trusted update-signing keys EMBEDDED in this release (-Path, default SI-InvardiaUpdateKeys.json next to this file).
|        Returns @{ Keys; Problems }. An unreadable file or entry is a problem, never a trusted key. Never throws.
|    #>
|    param([string]$Path = $script:SIInvardiaUpdateKeysFile)
|    $keys = New-Object System.Collections.Generic.List[object]
|    $problems = New-Object System.Collections.Generic.List[string]
|    try {
|        if (-not (Test-Path -LiteralPath $Path)) { $problems.Add('the trusted update-signing key list is not in this release') }
|        else {
|            $doc = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
|            foreach ($e in @($doc.keys | Where-Object { $_ })) {
|                try { $keys.Add((ConvertFrom-SIInvardiaKeyEntry -Entry $e)) } catch { $problems.Add($_.Exception.Message) }
|            }
|        }
|    } catch { $problems.Add(('the trusted update-signing key list cannot be read: {0}' -f $_.Exception.Message)) }
|    [pscustomobject]@{ Keys = $keys.ToArray(); Problems = $problems.ToArray() }
|}
|
|function Test-SIInvardiaManifestSignature {
|    <#
|        PURE. The signature over the base64-DECODED manifest bytes (RS256, UPDATE-1.2), against the trusted key named by keyId. Then the
|        manifest is decoded FROM manifestB64 -- the unsigned 'manifest' object in the answer is never used.
|        Returns @{ Ok; Reason; Manifest }. Never throws.
|    #>
|    param([AllowNull()][string]$ManifestB64, [AllowNull()][string]$Signature, [AllowNull()][string]$KeyId, [AllowNull()][object[]]$TrustedKeys)
|    $no = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why; Manifest = $null } }
|    $trusted = @($TrustedKeys | Where-Object { $_ })
|    if (-not $trusted.Count) { return (& $no 'no trusted update-signing keys are embedded in this release -- every manifest is refused until Invardia''s public keys are added to engine/_shared/SI-InvardiaUpdateKeys.json') }
|    if (-not "$ManifestB64".Trim()) { return (& $no 'the answer carries no manifestB64') }
|    $sig = ConvertFrom-SIInvardiaBase64 $Signature
|    if (-not $sig) { return (& $no 'the answer carries no readable signature') }
|    $key = @($trusted | Where-Object { $_.KeyId -ceq "$KeyId".Trim() }) | Select-Object -First 1
|    if (-not $key) { return (& $no ("the manifest is signed with key '{0}', which is not a trusted update-signing key" -f "$KeyId".Trim())) }
|    $bytes = ConvertFrom-SIInvardiaBase64 $ManifestB64
|    if (-not $bytes) { return (& $no 'the answer''s manifestB64 is not base64') }
|    $ok = $false
|    $rsa = $null
|    try {
|        $rsa = [System.Security.Cryptography.RSA]::Create()
|        $rsa.ImportParameters($key.Parameters)
|        # #270: over the base64-DECODED manifest bytes (UPDATE-1.2, the framework verifier's rule, live-proven by PIM). Until
|        # 2026-10-04 this verified the base64 TEXT, which would have refused every real Invardia manifest.
|        $ok = $rsa.VerifyData([byte[]]$bytes, $sig,
|            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
|    } catch { $ok = $false } finally { if ($rsa) { $rsa.Dispose() } }
|    if (-not $ok) { return (& $no ("the manifest's signature does NOT verify against trusted key '{0}' -- it was changed or not signed by Invardia" -f $key.KeyId)) }
|    $m = $null
|    try { $m = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop } catch { $m = $null }
|    if ($null -eq $m) { return (& $no 'the signed manifest is not JSON') }
|    [pscustomobject]@{ Ok = $true; Reason = ''; Manifest = $m }
|}
|
|function Compare-SIInvardiaVersion {
|    <# PURE. -1 / 0 / 1, numeric per part (64-bit: a template pack version carries a yyyyMMddHHmm part). #>
|    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
|    $pa = @("$A".Trim().Split('.') | Where-Object { $_ -ne '' }); $pb = @("$B".Trim().Split('.') | Where-Object { $_ -ne '' })
|    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
|        $x = [long]0; $y = [long]0
|        if ($i -lt $pa.Count) { [void][long]::TryParse($pa[$i], [ref]$x) }
|        if ($i -lt $pb.Count) { [void][long]::TryParse($pb[$i], [ref]$y) }
|        if ($x -ne $y) { if ($x -lt $y) { return -1 } else { return 1 } }
|    }
|    0
|}
|
|function Test-SIInvardiaSameMajor {
|    <# PURE. #919 (3): do -Running and -Offered share their MAJOR (the first number)? The MAJOR only -- 3.0.1 and
|       3.0.0.202610272235 do, 2.2.460 and 3.0.1 do not. $null when either is not a version. #>
|    param([AllowNull()][AllowEmptyString()][string]$Running, [AllowNull()][AllowEmptyString()][string]$Offered)
|    $a = [regex]::Match("$Running".Trim(), '^v?(\d+)(\.|$)'); $b = [regex]::Match("$Offered".Trim(), '^v?(\d+)(\.|$)')
|    if (-not $a.Success -or -not $b.Success) { return $null }
|    ([long]$a.Groups[1].Value -eq [long]$b.Groups[1].Value)
|}
|
|function Get-SIInvardiaArchiveName {
|    <# PURE. The file a manifest names (archive), when it is a plain file name; else the contract's default name. #>
|    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Version, [AllowNull()][string]$Archive)
|    $a = "$Archive".Trim()
|    if ($a -and $a -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -and $a -notmatch '\.\.') { return $a }
|    if ($Kind -eq 'templates') { return ('{0}-templates-{1}.json' -f $script:SIInvardiaUpdateProduct, $Version) }
|    '{0}-src-{1}.zip' -f $script:SIInvardiaUpdateProduct, $Version
|}
|
|function Test-SIInvardiaManifestContent {
|    <#
|        PURE. A VERIFIED manifest against what was asked and what this install applied. Returns @{ Action; Reason; Sequence;
|        ManualStep }: update | current (this sequence is applied already) | hold (manualStep set, not accepted) | refused.
|          * product securityinsight and the kind asked for; ring, sequence, version, sha256 and size well formed;
|          * -Ring (0-3, UPDATE-1.7): the signed ring must be the one this environment asked for (the update pull always
|            passes this environment's ring; -1 is only for reading a manifest's content for display);
|          * a sequence LOWER than -AppliedSequence is refused (replay); -1 = nothing applied yet;
|          * manualStep set = hold, unless -AcceptManualStepSequence names exactly this sequence.
|          * CR3 (#657, framework 12.11e item 2) A PRE-RELEASE WAVE NEVER MOVES AN INSTALL BACK: when the code this install
|            applied came from a wave (-AppliedWave, version -AppliedVersion) and the ring's manifest (no wave) has a LOWER
|            sequence, it is not refused as a replay: an older or equal version = 'current' (the install keeps the wave's
|            version until its ring reaches it); a newer one = 'update'.
|    #>
|    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$Kind, [long]$AppliedSequence = -1, [long]$AcceptManualStepSequence = -1,
|          # minFromVersion newer than this (when known) = hold (UPDATE-1.2, #270)
|          [AllowEmptyString()][string]$RunningVersion = '', [int]$Ring = -1,
|          # CR3: the wave of the applied code ('' = none) and its version
|          [AllowEmptyString()][string]$AppliedWave = '', [AllowEmptyString()][string]$AppliedVersion = '')
|    $out = { param($a, $why, $seq = -1, $ms = '') [pscustomobject]@{ Action = $a; Reason = $why; Sequence = [long]$seq; ManualStep = $ms } }
|    $prop = { param($n) if ($Manifest.PSObject.Properties[$n]) { $Manifest.$n } else { $null } }
|    if ("$(& $prop 'product')" -ne $script:SIInvardiaUpdateProduct) { return (& $out 'refused' ("the manifest is for product '{0}', not {1}" -f (& $prop 'product'), $script:SIInvardiaUpdateProduct)) }
|    if ("$(& $prop 'kind')" -ne $Kind) { return (& $out 'refused' ("the manifest is for kind '{0}', not '{1}'" -f (& $prop 'kind'), $Kind)) }
|    $seq = [long]-1
|    if (-not [long]::TryParse("$(& $prop 'sequence')", [ref]$seq) -or $seq -lt 0) { return (& $out 'refused' 'the manifest has no usable sequence') }
|    # (PowerShell names are case-blind: the manifest's ring is $mRing, the ring asked for is -Ring)
|    $mRing = 0
|    if (-not [int]::TryParse("$(& $prop 'ring')", [ref]$mRing) -or $mRing -lt 0) { return (& $out 'refused' $(if ($Ring -ge 0) { "the manifest names no ring (this environment asked for ring $Ring)" } else { 'the manifest has no usable ring' })) }
|    if ($Ring -ge 0 -and $mRing -ne $Ring) { return (& $out 'refused' ("the manifest is for ring {0}, not ring {1} that this environment asked for" -f $mRing, $Ring)) }
|    $ver = "$(& $prop 'version')".Trim()
|    if ($ver -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { return (& $out 'refused' ("the manifest names '{0}', which is not a version" -f $ver)) }
|    if ("$(& $prop 'sha256')".Trim() -notmatch '^[0-9a-fA-F]{64}$') { return (& $out 'refused' 'the manifest has no usable SHA-256') }
|    $size = [long]0
|    if (-not [long]::TryParse("$(& $prop 'size')", [ref]$size) -or $size -le 0) { return (& $out 'refused' 'the manifest has no usable size') }
|    $waveOk = $false
|    if ($AppliedSequence -ge 0 -and $seq -lt $AppliedSequence) {
|        # CR3: after a pre-release wave the ring's own manifest may carry a lower sequence -- never a replay, never a step back
|        $mWave = "$(& $prop 'wave')".Trim()
|        if ("$AppliedWave".Trim() -and -not $mWave -and "$AppliedVersion".Trim()) {
|            if ((Compare-SIInvardiaVersion $ver $AppliedVersion) -le 0) {
|                $why = if ((Compare-SIInvardiaVersion $ver $AppliedVersion) -eq 0) { "ring {0} now has {1} {2}, the version this install took early in the pre-release wave '{3}' -- the wave has ended for this install" -f $mRing, $Kind, $ver, $AppliedWave }
|                       else { "this install keeps {0} {1} from the pre-release wave '{2}': ring {3} names {4} (sequence {5}), and an install is never moved back -- it follows its ring again once the ring reaches {1}" -f $Kind, $AppliedVersion, $AppliedWave, $mRing, $ver, $seq }
|                return (& $out 'current' $why $seq)
|            }
|            $waveOk = $true
|        }
|        if (-not $waveOk) { return (& $out 'refused' ("the manifest's sequence {0} is LOWER than the {1} this install applied -- an old manifest is never applied again" -f $seq, $AppliedSequence) $seq) }
|    }
|    $ms = "$(& $prop 'manualStep')".Trim()
|    if ($ms -and $AcceptManualStepSequence -ne $seq) {
|        return (& $out 'hold' ("HELD: {0} {1} (sequence {2}) needs a manual step first: {3}" -f $Kind, $ver, $seq, $ms) $seq $ms)
|    }
|    if ($AppliedSequence -ge 0 -and $seq -eq $AppliedSequence) { return (& $out 'current' ("{0} {1} (sequence {2}) is applied already" -f $Kind, $ver, $seq) $seq $ms) }
|    $mf = "$(& $prop 'minFromVersion')".Trim()
|    if ($mf -and "$RunningVersion".Trim() -and (Compare-SIInvardiaVersion "$RunningVersion" $mf) -lt 0) {
|        return (& $out 'hold' ("HELD: {0} {1} (sequence {2}) needs at least {3} -- this install runs {4}" -f $Kind, $ver, $seq, $mf, "$RunningVersion".Trim()) $seq $ms)
|    }
|    # #919 (3) / (4): a MAJOR version is never an update (v3 is installed side by side): code of another major than the one this
|    # install runs is refused (after the holds: a minFromVersion hold says it first) -- the MAJOR only is compared (3.0.1 after 3.0.0.<build> is an update; 2.2 -> 3.x never is)
|    if ($Kind -eq 'code' -and "$RunningVersion".Trim()) {
|        # an OLDER major (the vendor's roll-back) goes on to the forward-only rules below; a NEWER major is never an update
|        $mj = Test-SIInvardiaSameMajor -Running "$RunningVersion" -Offered $ver
|        if ($mj -eq $false -and [long]([regex]::Match($ver, '^\d+').Value) -gt [long]([regex]::Match("$RunningVersion".Trim(), '\d+').Value)) { return (& $out 'refused' ("{0} {1} is another major version than the {2} this install runs -- a major version is never an update (installed side by side)" -f $Kind, $ver, "$RunningVersion".Trim()) $seq) }
|    }
|    & $out 'update' ("ring {0} has {1} {2} (sequence {3})" -f $mRing, $Kind, $ver, $seq) $seq $ms
|}
|
|function Get-SIInvardiaFileSha256 {
|    param([Parameter(Mandatory)][string]$Path)
|    $sha = [System.Security.Cryptography.SHA256]::Create()
|    $fs = [System.IO.File]::OpenRead($Path)
|    try { $b = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
|    -join ($b | ForEach-Object { $_.ToString('x2') })
|}
|
|# =====================================================================================================================
|#  HTTP (the default seams)
|# =====================================================================================================================
|function Get-SIInvardiaRetryAfter {
|    <# Seconds from a Retry-After header (delta seconds or an HTTP date), 0 when absent. #>
|    param($Response)
|    $ra = 0
|    try {
|        if ($Response -is [System.Net.WebResponse]) {
|            $h = [string]$Response.Headers['Retry-After']
|            if (-not [int]::TryParse($h, [ref]$ra)) { $d = [datetime]::MinValue; if ([datetime]::TryParse($h, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { $ra = [int][Math]::Max(0, ($d - [datetime]::UtcNow).TotalSeconds) } }
|        } elseif ($Response.Headers.RetryAfter) {
|            if ($Response.Headers.RetryAfter.Delta) { $ra = [int]$Response.Headers.RetryAfter.Delta.Value.TotalSeconds }
|            elseif ($Response.Headers.RetryAfter.Date) { $ra = [int][Math]::Max(0, ($Response.Headers.RetryAfter.Date.Value.UtcDateTime - [datetime]::UtcNow).TotalSeconds) }
|        }
|    } catch { }
|    $ra
|}
|
|function Invoke-SIInvardiaUpdateHttp {
|    <#
|        One POST with a JSON body and, when given, the install key in its header (-KeyHeader; the key claim sends none).
|        Returns @{ Status (0 = no answer); Body; RetryAfter; Error }; never throws. Headers are not part of exception text,
|        and the error text is scrubbed anyway.
|    #>
|    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Body, [AllowEmptyString()][string]$InstallKey,
|          [string]$KeyHeader = $script:SIInvardiaUpdateKeyHeader, [int]$TimeoutSec = 60,
|          # Invardia S16: the install's lasting id -> X-Invardia-Install-Id, only when it is a GUID (the manifest pull passes
|          # it; the key claim never does); '' = no header
|          [AllowNull()][AllowEmptyString()][string]$InstallId = '')
|    $h = @{ Accept = 'application/json' }
|    if ($InstallKey) { $h[$KeyHeader] = $InstallKey }
|    $h = Add-SIInvardiaInstallIdHeader -Headers $h -InstallId $InstallId
|    try {
|        $r = Invoke-WebRequest -Method Post -Uri $Uri -Headers $h -Body $Body -ContentType 'application/json' -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
|        $content = $r.Content; if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
|        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$content; RetryAfter = 0; Error = '' }
|    } catch {
|        $resp = $null; try { $resp = $_.Exception.Response } catch { }
|        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = (Hide-SIInvardiaSecret "$($_.Exception.Message)" -Secret $InstallKey) } }
|        $code = 0; try { $code = [int]$resp.StatusCode } catch { }
|        $text = ''
|        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $text = [string]$_.ErrorDetails.Message }
|        elseif ($resp -is [System.Net.WebResponse]) { try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $text = $sr.ReadToEnd(); $sr.Close() } catch { } }
|        return [pscustomobject]@{ Status = $code; Body = (Hide-SIInvardiaSecret $text -Secret $InstallKey); RetryAfter = (Get-SIInvardiaRetryAfter $resp); Error = "HTTP $code" }
|    }
|}
|
|function Invoke-SIInvardiaUpdateDownload {
|    <# GET the download URL to a file. Returns @{ Status; Error }; never throws, and the URL's token is never in Error. #>
|    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$OutFile, [int]$TimeoutSec = 600)
|    try {
|        $r = Invoke-WebRequest -Method Get -Uri $Uri -OutFile $OutFile -PassThru -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
|        return [pscustomobject]@{ Status = [int]$r.StatusCode; Error = '' }
|    } catch {
|        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
|        return [pscustomobject]@{ Status = $code; Error = (Hide-SIInvardiaSecret "$($_.Exception.Message)" -Secret $Uri) }
|    }
|}
|
|# =====================================================================================================================
|#  The pull
|# =====================================================================================================================
|function Get-SIInvardiaManifestWave {
|    <# PURE. CR3 (#657): the signed manifest's "wave" (a name; an object's name) -- trimmed, at most 60 safe characters; '' = none. #>
|    param([AllowNull()]$Manifest)
|    if ($null -eq $Manifest -or -not $Manifest.PSObject.Properties['wave'] -or $null -eq $Manifest.wave) { return '' }
|    $w = $Manifest.wave
|    if (-not ($w -is [string]) -and $w.PSObject.Properties['name']) { $w = $w.name }
|    $v = ("$w" -replace '[\r\n\t]+', ' ').Trim()
|    if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}$') { return '' }
|    $v
|}
|
|function New-SIInvardiaManifestResult {
|    param([string]$Kind, [string]$Action, [string]$Reason, [int]$StatusCode = 0, [int]$RetryAfter = 0, $Manifest = $null, [string]$KeyId = '',
|          [string]$DownloadUrl = '', [long]$Sequence = -1, [string]$ManualStep = '', [string[]]$Fields = @(),
|          # the SIGNED manifest as it came (base64 + signature): kept with a staged template pack, so the install job checks it again
|          [string]$ManifestB64 = '', [string]$Signature = '')
|    [pscustomobject]@{
|        Kind = $Kind; Action = $Action; Ok = ($Action -in @('update', 'current')); Reason = $Reason; StatusCode = $StatusCode; RetryAfter = $RetryAfter
|        Manifest = $Manifest; KeyId = $KeyId; Sequence = $Sequence; ManualStep = $ManualStep; Fields = $Fields
|        ManifestB64 = $ManifestB64; Signature = $Signature
|        Version = $(if ($Manifest -and $Manifest.PSObject.Properties['version']) { "$($Manifest.version)" } else { '' })
|        Ring = $(if ($Manifest -and $Manifest.PSObject.Properties['ring']) { $Manifest.ring } else { $null })
|        # CR3 (#657): the pre-release wave Invardia served this manifest for ('' = the ring's own release)
|        Wave = (Get-SIInvardiaManifestWave $Manifest)
|        # the 15-minute download link: used by Save-SIInvardiaUpdateFile, never printed (Hide-SIInvardiaSecret drops its token)
|        DownloadUrl = $DownloadUrl
|    }
|}
|
|function Request-SIInvardiaManifest {
|    <#
|        Ask Invardia for this install's manifest of -Kind, verify it, and decide. NEVER throws.
|        The install key and the licence text come from -InstallKey / -Licence, else from the install's Key Vault through
|        -Seams.ReadSecret (SI-Invardia-InstallKey, SI-License).
|        -Seams (hashtable of scriptblocks, all optional except ReadSecret when the key / licence are not given):
|          Http        { param($Uri, $Body, $InstallKey, $KeyHeader, $InstallId) } -> @{ Status; Body; RetryAfter; Error }   (default Invoke-SIInvardiaUpdateHttp)
|          ReadSecret  { param($Name) } -> text or $null
|        -InstallId (Invardia S16): the install's LASTING id; not given = read (only) from SI-InstallId through ReadSecret.
|        A GUID goes as X-Invardia-Install-Id; none / not a GUID / unreadable = no header (the pull itself is unchanged).
|          TrustedKeys { } -> @(@{ KeyId; Parameters })     (default: the embedded SI-InvardiaUpdateKeys.json)
|        Returns New-SIInvardiaManifestResult. Action:
|          update | current | hold | none (204) | refused | unauthorized (401) | forbidden (403) | notfound (404) |
|          invalid (422) | waiting (429) | network (no answer / 5xx) | off (no install key, licence or ring) | error
|        -Ring: this environment's OWN update ring (0-3; UPDATE-1.7). Sent with the pull; the signed manifest must name it.
|        None (or not a ring) = no pull at all, Action 'off', and the reason says so.
|    #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind,
|        [System.Collections.IDictionary]$Seams = @{},
|        [string]$BaseUrl,
|        [long]$AppliedSequence = -1,
|        [long]$AcceptManualStepSequence = -1,
|        [string]$InstallKey,
|        [string]$Licence,
|        # The updates endpoint + header the key claim returned (Get-SIInvardiaUpdatesEndpoint); empty = the frozen defaults.
|        [string]$ManifestUri,
|        [string]$KeyHeader,
|        # The version this install runs (kind code): a manifest whose minFromVersion is newer HOLDS (UPDATE-1.2).
|        [AllowEmptyString()][string]$RunningVersion = '',
|        # UPDATE-1.7: this environment's own ring (SI_UPDATER_RING / cfg.InstallState 'Ring'); none = no pull
|        [AllowNull()]$Ring = $null,
|        [int]$TimeoutSec = 60,
|        # CR3 (#657): the wave of the code this install applied ('' = none) and its version -- never moved back after a wave
|        [AllowEmptyString()][string]$AppliedWave = '',
|        [AllowEmptyString()][string]$AppliedVersion = '',
|        # Invardia S16: the install's lasting id (SI-InstallId); not given = read through -Seams.ReadSecret
|        [AllowNull()][AllowEmptyString()][string]$InstallId
|    )
|    $key = $InstallKey
|    try {
|        $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|        if (-not "$KeyHeader".Trim()) { $KeyHeader = $script:SIInvardiaUpdateKeyHeader }
|        if ("$ManifestUri".Trim() -and "$ManifestUri".Trim() -notmatch '^https://[^/\s]+/') { $ManifestUri = '' }
|        if (-not "$ManifestUri".Trim()) { $ManifestUri = Get-SIInvardiaManifestUri -BaseUrl $base }
|        if (-not "$key".Trim() -and $Seams['ReadSecret']) { try { $key = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey) } catch { $key = '' } }
|        $key = "$key".Trim()
|        if (-not $key) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason ("no Invardia install key in the install's Key Vault ({0}) -- the updater claims one on its next run" -f $script:SIInvardiaUpdateSecretKey)) }
|        if (-not (Test-SIInvardiaInstallKeyFormat $key)) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason ("the Invardia install key in {0} is not an install key (it must start with inv-)" -f $script:SIInvardiaUpdateSecretKey)) }
|        $lic = $Licence
|        if (-not "$lic".Trim() -and $Seams['ReadSecret']) { try { $lic = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretLicence) } catch { $lic = '' } }
|        if (-not "$lic".Trim()) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason 'no SecurityInsight Pro licence is installed -- updates from Invardia need one') }
|        $ringN = ConvertTo-SIInvardiaPullRing $Ring
|        if ($ringN -lt 0) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason (Get-SIInvardiaNoRingReason -Ring $Ring)) }
|
|        # Trusted keys BEFORE the network: an empty list refuses everything, so there is nothing to ask for.
|        $trusted = if ($Seams['TrustedKeys']) { @(& $Seams.TrustedKeys) } else { $tk = Get-SIInvardiaTrustedKeys; @($tk.Keys) }
|        if (-not @($trusted | Where-Object { $_ }).Count) {
|            return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -Reason 'no trusted update-signing keys are embedded in this release -- every manifest is refused until Invardia''s public keys are added to engine/_shared/SI-InvardiaUpdateKeys.json')
|        }
|
|        # Invardia S16: the lasting id, READ ONLY (never created by the pull); '' = no header
|        $iid = if ($PSBoundParameters.ContainsKey('InstallId')) { ConvertTo-SIInvardiaInstallId $InstallId } elseif ($Seams['ReadSecret'] -or $Seams['ReadVersions']) { Get-SIInvardiaInstallId -ReadSecret $Seams['ReadSecret'] -ReadVersions $Seams['ReadVersions'] } else { '' }
|        $http = if ($Seams['Http']) { $Seams['Http'] } else { { param($u, $b, $k, $hn, $id) Invoke-SIInvardiaUpdateHttp -Uri $u -Body $b -InstallKey $k -KeyHeader $hn -InstallId $id -TimeoutSec $TimeoutSec } }
|        $r = & $http $ManifestUri (New-SIInvardiaManifestBody -Kind $Kind -Licence ([string]$lic) -Ring $ringN) $key $KeyHeader $iid
|        $code = [int]$r.Status
|        # Parsed RAW (downloadUrl carries its token); every text taken from it for a reason is scrubbed in $why.
|        $body = [string]$r.Body
|        $j = $null; if ($body.Trim()) { try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
|        $why = { $t = ''; if ($j) { foreach ($n in 'reason', 'error', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim()) { $t = "$($j.$n)".Trim(); break } } }; if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; Hide-SIInvardiaSecret $t -Secret $key }
|        switch ($code) {
|            200 { break }
|            204 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'none' -StatusCode 204 -Reason ("nothing is released for ring {0} ({1})" -f $ringN, $Kind)) }
|            401 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'unauthorized' -StatusCode 401 -Reason ("Invardia did not accept the install key{0} -- check {1} in the install's Key Vault, or ask Invardia support for a new one" -f $(if (& $why) { " ($(& $why))" } else { '' }), $script:SIInvardiaUpdateSecretKey)) }
|            403 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'forbidden' -StatusCode 403 -Reason ("Invardia refused the licence: {0}" -f $(if (& $why) { & $why } else { 'no reason given' }))) }
|            404 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'notfound' -StatusCode 404 -Reason 'Invardia does not know this product (404)') }
|            422 {
|                $fields = @(); try { $fields = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['field']) { "$($_.field)" } elseif ($_.PSObject.Properties['name']) { "$($_.name)" } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
|                # UPDATE-1.7: Invardia answers 422 (fields ['ring']) to a pull without a usable ring
|                $ringHint = if (-not $fields.Count -or @($fields | Where-Object { "$_" -match '(?i)\bring\b' }).Count) { " -- the pull must carry this environment's update ring (0-3); it sent ring $ringN" } else { '' }
|                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'invalid' -StatusCode 422 -Fields $fields -Reason ("Invardia refused the request as invalid; fields: {0}{1}" -f $(if ($fields.Count) { $fields -join ', ' } else { 'none named' }), $ringHint))
|            }
|            429 {
|                $ra = [int]$r.RetryAfter; if ($ra -le 0) { $ra = 3600 }
|                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'waiting' -StatusCode 429 -RetryAfter $ra -Reason ("Invardia asked to slow down -- not asked again for {0} s" -f $ra))
|            }
|            0   { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'network' -Reason ("Invardia could not be reached: {0}" -f (Hide-SIInvardiaSecret ([string]$r.Error) -Secret $key))) }
|            default {
|                if ($code -ge 500) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'network' -StatusCode $code -Reason ("Invardia answered {0} -- tried again on a later run" -f $code)) }
|                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'error' -StatusCode $code -Reason ("Invardia answered {0}{1}" -f $code, $(if (& $why) { ": $(& $why)" } else { '' })))
|            }
|        }
|        if (-not $j) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -Reason 'the answer is not JSON') }
|        $prop = { param($n) if ($j.PSObject.Properties[$n]) { [string]$j.$n } else { '' } }
|        $sig = Test-SIInvardiaManifestSignature -ManifestB64 (& $prop 'manifestB64') -Signature (& $prop 'signature') -KeyId (& $prop 'keyId') -TrustedKeys $trusted
|        if (-not $sig.Ok) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -KeyId (& $prop 'keyId') -Reason $sig.Reason) }
|        $chk = Test-SIInvardiaManifestContent -Manifest $sig.Manifest -Kind $Kind -AppliedSequence $AppliedSequence -AcceptManualStepSequence $AcceptManualStepSequence `
|                    -RunningVersion $(if ($Kind -eq 'code') { $RunningVersion } else { '' }) -Ring $ringN -AppliedWave $AppliedWave -AppliedVersion $AppliedVersion
|        $dl = & $prop 'downloadUrl'
|        if ($chk.Action -eq 'update' -and $dl -notmatch '^https://[^/\s]+/') {
|            return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -Manifest $sig.Manifest -KeyId (& $prop 'keyId') -Sequence $chk.Sequence -Reason 'the answer carries no https download link')
|        }
|        New-SIInvardiaManifestResult -Kind $Kind -Action $chk.Action -StatusCode 200 -Manifest $sig.Manifest -KeyId (& $prop 'keyId') -DownloadUrl $dl `
|            -Sequence $chk.Sequence -ManualStep $chk.ManualStep -Reason (Hide-SIInvardiaSecret $chk.Reason -Secret $key) `
|            -ManifestB64 (& $prop 'manifestB64') -Signature (& $prop 'signature')
|    } catch {
|        New-SIInvardiaManifestResult -Kind $Kind -Action 'error' -Reason (Hide-SIInvardiaSecret ("the update check did not complete: {0}" -f $_.Exception.Message) -Secret $key)
|    } finally { $key = $null }
|}
|
|function Save-SIInvardiaUpdateFile {
|    <#
|        Download what a VERIFIED manifest names into -OutDir and check it: size, then SHA-256, both from the signed manifest.
|        A file that does not match is deleted. Returns @{ Ok; Path; Reason; Sha256; Size }. NEVER throws.
|        -Seams.Download { param($Uri, $OutFile) } -> @{ Status; Error }  (default Invoke-SIInvardiaUpdateDownload)
|    #>
|    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$OutDir, [System.Collections.IDictionary]$Seams = @{})
|    $fail = { param($why) [pscustomobject]@{ Ok = $false; Path = ''; Reason = $why; Sha256 = ''; Size = 0 } }
|    $path = ''
|    try {
|        # 'current' too: the release this install runs can be fetched again (the template gate checks a pack with it).
|        if (-not $Result -or $Result.Action -notin @('update', 'current') -or -not $Result.Manifest) { return (& $fail 'there is no verified manifest to download') }
|        $m = $Result.Manifest
|        if ("$($Result.DownloadUrl)" -notmatch '^https://[^/\s]+/') { return (& $fail 'the manifest came without an https download link') }
|        $name = Get-SIInvardiaArchiveName -Kind $Result.Kind -Version "$($m.version)" -Archive $(if ($m.PSObject.Properties['archive']) { "$($m.archive)" } else { '' })
|        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
|        $path = [IO.Path]::Combine($OutDir, $name)
|        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
|        $dl = if ($Seams['Download']) { $Seams['Download'] } else { { param($u, $f) Invoke-SIInvardiaUpdateDownload -Uri $u -OutFile $f } }
|        $r = & $dl ([string]$Result.DownloadUrl) $path
|        $code = [int]$r.Status
|        if ($code -ne 200 -or -not (Test-Path -LiteralPath $path)) {
|            $why = if ($code -eq 401) { 'the download link expired (401) -- the next run asks for a new one' } elseif ($code -eq 0) { "the download did not complete: $(Hide-SIInvardiaSecret ([string]$r.Error) -Secret $Result.DownloadUrl)" } else { "the download answered $code" }
|            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
|            return (& $fail $why)
|        }
|        $size = (Get-Item -LiteralPath $path).Length
|        if ([long]$size -ne [long]$m.size) {
|            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
|            return (& $fail ("{0} is {1} bytes, the signed manifest says {2} -- refused" -f $name, $size, $m.size))
|        }
|        $sha = Get-SIInvardiaFileSha256 -Path $path
|        if ($sha -ne "$($m.sha256)".Trim().ToLowerInvariant()) {
|            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
|            return (& $fail ("{0} does NOT match the signed manifest's SHA-256 (file {1}, manifest {2}) -- refused" -f $name, $sha.Substring(0, 12), "$($m.sha256)".Substring(0, 12).ToLowerInvariant()))
|        }
|        [pscustomobject]@{ Ok = $true; Path = $path; Reason = ("{0} verified (SHA-256 {1}, {2} bytes)" -f $name, $sha, $size); Sha256 = $sha; Size = [long]$size }
|    } catch {
|        if ($path -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
|        & $fail (Hide-SIInvardiaSecret ("the download did not complete: {0}" -f $_.Exception.Message) -Secret $Result.DownloadUrl)
|    }
|}
|
|function Get-SIInvardiaUpdate {
|    <#
|        The whole pull for one kind: the manifest (Request-SIInvardiaManifest), and when it says 'update' the verified file
|        (Save-SIInvardiaUpdateFile). Returns the manifest result with File (the verified local path, '' when none) and,
|        when the download failed, Action 'refused' and its reason. NEVER throws.
|    #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind,
|        [Parameter(Mandatory)][string]$OutDir,
|        [System.Collections.IDictionary]$Seams = @{},
|        [string]$BaseUrl, [long]$AppliedSequence = -1, [long]$AcceptManualStepSequence = -1, [string]$InstallKey, [string]$Licence,
|        [string]$ManifestUri, [string]$KeyHeader,
|        # UPDATE-1.7: this environment's own ring (0-3); none = no pull (Action 'off')
|        [AllowNull()]$Ring = $null,
|        # Invardia S16: the install's lasting id; not given = Request-SIInvardiaManifest reads SI-InstallId through -Seams
|        [AllowNull()][AllowEmptyString()][string]$InstallId
|    )
|    $idArg = @{}; if ($PSBoundParameters.ContainsKey('InstallId')) { $idArg.InstallId = $InstallId }
|    $r = Request-SIInvardiaManifest -Kind $Kind -Seams $Seams -BaseUrl $BaseUrl -AppliedSequence $AppliedSequence -AcceptManualStepSequence $AcceptManualStepSequence `
|            -InstallKey $InstallKey -Licence $Licence -ManifestUri $ManifestUri -KeyHeader $KeyHeader -Ring $Ring @idArg
|    $r | Add-Member -NotePropertyName File -NotePropertyValue '' -Force
|    if ($r.Action -ne 'update') { return $r }
|    $f = Save-SIInvardiaUpdateFile -Result $r -OutDir $OutDir -Seams $Seams
|    if (-not $f.Ok) { $r.Action = 'refused'; $r.Reason = $f.Reason; $r | Add-Member -NotePropertyName Ok -NotePropertyValue $false -Force; return $r }
|    $r.File = $f.Path
|    $r
|}
|
|# =====================================================================================================================
|#  The install's update state (Key Vault SI-Update-State; mirrored into the Pro database for the web app)
|# =====================================================================================================================
|function New-SIInvardiaKindState {
|    # appliedWave / lastWave (CR3 #657): the pre-release wave of the applied / last manifest ('' = the ring's own release)
|    [ordered]@{ appliedSequence = -1; appliedVersion = ''; appliedRing = $null; appliedUtc = $null; appliedWave = ''
|                lastSequence = -1; lastVersion = ''; lastRing = $null; lastAction = ''; lastReason = ''; lastCheckUtc = $null; lastWave = ''
|                hold = ''; nextTryUtc = $null
|                # (templates) the fingerprint of a release's template change that waits for an Admin while its code rolled ('' = none)
|                pendingFingerprint = ''
|                # (code) #1406: the version an update stopped part-way is finished for, and how many runs tried it ('' = none)
|                resumeVersion = ''; resumeTries = '' }
|}
|
|function ConvertTo-SIInvardiaUtc {
|    param([AllowNull()]$Value)
|    if ($null -eq $Value -or -not "$Value".Trim()) { return $null }
|    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
|    $d = [datetime]::MinValue
|    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
|    $null
|}
|
|function ConvertFrom-SIInvardiaUpdateState {
|    <# PURE. The stored state (JSON) as an ordered hashtable with every field; an unreadable state starts empty. #>
|    param([AllowNull()][string]$Json)
|    # channel (PRO-COMMUNITY-SAME): the manifest address the applied code came from -- 'invardia' (the install route) or
|    # 'community' (the anonymous Community route); sequences are counted per address
|    $s = [ordered]@{ source = ''; channel = ''; lastCheckUtc = $null; lastError = ''; updatesEndpoint = ''; updatesHeader = ''
|                     claimResult = ''; claimReason = ''; claimUtc = $null
|                     claimAgainResult = ''; claimAgainBy = ''; claimAgainUtc = $null
|                     # 2026-10-23: the update waits for a pipeline run (the run gate) -- since when, why, run | store
|                     waitsSinceUtc = $null; waitsReason = ''; waitsKind = ''
|                     code = (New-SIInvardiaKindState); templates = (New-SIInvardiaKindState) }
|    if ([string]::IsNullOrWhiteSpace($Json)) { return $s }
|    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $s }
|    foreach ($k in 'source', 'channel', 'lastError', 'updatesEndpoint', 'updatesHeader', 'claimResult', 'claimReason', 'claimAgainResult', 'claimAgainBy', 'waitsReason', 'waitsKind') { if ($o.PSObject.Properties[$k] -and $null -ne $o.$k) { $s[$k] = "$($o.$k)" } }
|    foreach ($k in 'lastCheckUtc', 'claimUtc', 'claimAgainUtc', 'waitsSinceUtc') { if ($o.PSObject.Properties[$k]) { $s[$k] = ConvertTo-SIInvardiaUtc $o.$k } }
|    foreach ($kind in $script:SIInvardiaUpdateKinds) {
|        if (-not $o.PSObject.Properties[$kind] -or $null -eq $o.$kind) { continue }
|        $src = $o.$kind; $dst = $s[$kind]
|        foreach ($f in @($dst.Keys)) {
|            if (-not $src.PSObject.Properties[$f]) { continue }
|            $v = $src.$f
|            if ($f -like '*Utc') { $dst[$f] = ConvertTo-SIInvardiaUtc $v }
|            elseif ($f -like '*Sequence') { $n = [long]-1; if ([long]::TryParse("$v", [ref]$n)) { $dst[$f] = $n } }
|            elseif ($f -like '*Ring') { $n = 0; if ($null -ne $v -and [int]::TryParse("$v", [ref]$n)) { $dst[$f] = $n } }
|            else { $dst[$f] = $(if ($null -eq $v) { '' } else { "$v" }) }
|        }
|    }
|    $s
|}
|
|function ConvertTo-SIInvardiaUpdateStateJson {
|    <#
|        PURE. The state as JSON. -Compact = what the Pro database row holds (cfg.InstallState.Value is NVARCHAR(400)): per
|        kind the last manifest (version, sequence, ring), the result, the applied sequence and any HOLD, shortened to fit.
|    #>
|    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [switch]$Compact)
|    $iso = { param($d) if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
|    if (-not $Compact) {
|        $o = [ordered]@{ source = $State.source; channel = $(if ($State.Contains('channel')) { [string]$State.channel } else { '' }); lastCheckUtc = (& $iso $State.lastCheckUtc); lastError = $State.lastError
|                         updatesEndpoint = $State.updatesEndpoint; updatesHeader = $State.updatesHeader
|                         claimResult = $State.claimResult; claimReason = $State.claimReason; claimUtc = (& $iso $State.claimUtc)
|                         claimAgainResult = $State.claimAgainResult; claimAgainBy = $State.claimAgainBy; claimAgainUtc = (& $iso $State.claimAgainUtc) }
|        if ($State.Contains('waitsSinceUtc') -and $State.waitsSinceUtc) { $o['waitsSinceUtc'] = (& $iso $State.waitsSinceUtc); $o['waitsReason'] = $State.waitsReason; $o['waitsKind'] = $State.waitsKind }
|        foreach ($kind in $script:SIInvardiaUpdateKinds) {
|            $k = [ordered]@{}
|            foreach ($f in $State[$kind].Keys) { $v = $State[$kind][$f]; if ($f -like '*Utc') { $v = & $iso $v }; $k[$f] = $v }
|            $o[$kind] = $k
|        }
|        return ($o | ConvertTo-Json -Compress -Depth 4)
|    }
|    foreach ($max in 90, 50, 20, 0) {
|        $short = { param($t) $t = "$t"; if ($t.Length -gt $max) { if ($max -le 3) { '' } else { $t.Substring(0, $max - 3) + '...' } } else { $t } }
|        $c = [ordered]@{ source = $State.source; lastCheckUtc = (& $iso $State.lastCheckUtc) }
|        foreach ($kind in $script:SIInvardiaUpdateKinds) {
|            $k = $State[$kind]
|            if (-not $k.lastAction -and $k.appliedSequence -lt 0) { continue }
|            $c[$kind] = [ordered]@{ version = $k.lastVersion; sequence = $k.lastSequence; ring = $k.lastRing; action = $k.lastAction; applied = $k.appliedSequence; hold = (& $short $k.hold) }
|            # CR3 (#657): the pre-release wave of the code the jobs run -- the web app's header and the heartbeat read it here
|            if ("$($k.appliedWave)".Trim()) { $c[$kind]['wave'] = [ordered]@{ name = "$($k.appliedWave)"; version = $k.appliedVersion; ring = $k.appliedRing } }
|        }
|        if ($State.claimResult -and $State.claimResult -notin @('claimed', 'present', 'bundle')) { $c['claim'] = $State.claimResult }
|        # the last 'claim the install key again' (an Admin on the Settings page, or SI_UPDATER_CLAIM_AGAIN) and its outcome
|        if ($State.claimAgainResult) { $c['claimAgain'] = $State.claimAgainResult; $c['claimAgainUtc'] = (& $iso $State.claimAgainUtc) }
|        $c['error'] = (& $short $State.lastError)
|        # 2026-10-23: the update waits for a pipeline run -- the heartbeat warns when it has waited more than 24 hours
|        if ($State.Contains('waitsSinceUtc') -and $State.waitsSinceUtc) { $c['waits'] = [ordered]@{ since = (& $iso $State.waitsSinceUtc); kind = $State.waitsKind; why = (& $short $State.waitsReason) } }
|        # FLEET-STATUS-1 (Invardia 2026-11-27): an update is being installed NOW (Set-SIInvardiaUpdateInProgress) -- the
|        # heartbeat then never carries the previous run's result for it (the row only; never the Key Vault state). Kept SHORT --
|        # only its start time (the release being installed is code.version already): 31 characters, so the row stays within
|        # its 400 (an install whose column is not widened yet refuses a longer value)
|        if ($State.Contains('updatingSinceUtc') -and $State.updatingSinceUtc) { $c['updating'] = (& $iso $State.updatingSinceUtc) }
|        $json = $c | ConvertTo-Json -Compress -Depth 4
|        if ($json.Length -le 400) { return $json }
|    }
|    # FLEET-STATUS-1 (review): still over 400 with every text shortened away (both kinds held in pre-release waves, a claim
|    # again, a wait...): the parts the heartbeat's update result needs least give way, in this order, until it fits -- the
|    # templates' wave, the claim-again, the wait, the templates, the claim. The code's record WITH ITS WAVE, the error and
|    # the "installing" mark stay: the heartbeat (Get-SIReleaseWaveFromUpdateState) and the web app's header read the code's
|    # wave from this row with no other source, so it is never dropped -- as the very last step its NAME is shortened (to
|    # 40, then 20, then 8 characters), never removed. The Key Vault state keeps everything; this row is the shown copy (an
|    # install whose column is not widened yet refuses a longer value, and the whole save would fail).
|    $drop = @(
|        { if ($c.Contains('templates') -and $c['templates'].Contains('wave')) { $c['templates'].Remove('wave') } },
|        { $c.Remove('claimAgain'); $c.Remove('claimAgainUtc') },
|        { $c.Remove('waits') },
|        { $c.Remove('templates') },
|        { $c.Remove('claim') })
|    foreach ($d in $drop) {
|        . $d
|        $json = $c | ConvertTo-Json -Compress -Depth 4
|        if ($json.Length -le 400) { return $json }
|    }
|    if ($c.Contains('code') -and $c['code'].Contains('wave')) {
|        $full = [string]$c['code']['wave']['name']
|        foreach ($n in 40, 20, 8) {
|            if ($full.Length -le $n) { continue }
|            $c['code']['wave']['name'] = $full.Substring(0, $n).TrimEnd()
|            $json = $c | ConvertTo-Json -Compress -Depth 4
|            if ($json.Length -le 400) { return $json }
|        }
|    }
|    $json
|}
|
|function Set-SIInvardiaUpdateCheck {
|    <# Record one manifest check of -Kind in the state: the last manifest, the result, a HOLD and when to try again (429). #>
|    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)][datetime]$NowUtc, [string]$Hold)
|    $k = $State[$Result.Kind]
|    $k.lastCheckUtc = $NowUtc; $State.lastCheckUtc = $NowUtc
|    $k.lastAction = [string]$Result.Action; $k.lastReason = [string]$Result.Reason
|    if ($Result.Manifest) { $k.lastVersion = [string]$Result.Version; $k.lastSequence = [long]$Result.Sequence; $k.lastRing = $(if ($null -ne $Result.Ring) { [int]$Result.Ring } else { $null }); $k.lastWave = $(if ($Result.PSObject.Properties['Wave']) { [string]$Result.Wave } else { '' }) }
|    $k.hold = $(if ($Hold) { $Hold } elseif ($Result.Action -eq 'hold') { [string]$Result.Reason } else { '' })
|    $k.nextTryUtc = $(if ($Result.Action -eq 'waiting' -and $Result.RetryAfter -gt 0) { $NowUtc.AddSeconds([int]$Result.RetryAfter) } else { $null })
|    if ($Result.Action -in @('refused', 'unauthorized', 'forbidden', 'notfound', 'invalid', 'network', 'error', 'off')) { $State.lastError = ('{0}: {1}' -f $Result.Kind, $Result.Reason) }
|}
|
|function Set-SIInvardiaUpdateInProgress {
|    <#
|        FLEET-STATUS-1 (Invardia 2026-11-27: heartbeats on the NEW version carried the OLD "nothing-to-do" for up to 45 minutes
|        after the swap, because the update state row was written only at the end of the run). -Version: the release being
|        installed now -- marks the state (the compact row carries 'updating', Get-SIHeartbeatUpdate reads it as "no result
|        yet" and never the previous run's); -Clear: the install is over (succeeded or failed), the mark goes. The caller saves
|        the state right after either. Only in memory + the row: the Key Vault state never keeps it (a run that dies under
|        the mark leaves it in the row, and the heartbeat reads an old mark as failed).
|    #>
|    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [string]$Version = '', [datetime]$NowUtc = [datetime]::UtcNow, [switch]$Clear)
|    if ($Clear) { $State['updatingVersion'] = ''; $State['updatingSinceUtc'] = $null; return }
|    $State['updatingVersion'] = "$Version".Trim(); $State['updatingSinceUtc'] = $NowUtc.ToUniversalTime()
|}
|
|function Set-SIInvardiaUpdateApplied {
|    <#
|        Record that -Kind's manifest is APPLIED (the code rolled / the templates published, or already in force), with the
|        pre-release wave it was served for (CR3 #657: appliedWave; '' = the ring's own release). An older sequence is never
|        recorded -- EXCEPT the end of a wave: the ring's own manifest (no wave) naming the wave's version or a later one
|        under a lower sequence puts the install back on its ring's sequence (the wave is over for it).
|    #>
|    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)][datetime]$NowUtc)
|    $k = $State[$Result.Kind]
|    $wave = if ($Result.PSObject.Properties['Wave']) { "$($Result.Wave)".Trim() } else { '' }
|    if ([long]$Result.Sequence -lt [long]$k.appliedSequence) {
|        $waveEnd = ("$($k.appliedWave)".Trim() -and -not $wave -and "$($k.appliedVersion)".Trim() -and "$($Result.Version)".Trim() -and
|                    (Compare-SIInvardiaVersion ([string]$Result.Version) ([string]$k.appliedVersion)) -ge 0)
|        if (-not $waveEnd) { return }
|    }
|    $k.appliedSequence = [long]$Result.Sequence; $k.appliedVersion = [string]$Result.Version
|    $k.appliedRing = $(if ($null -ne $Result.Ring) { [int]$Result.Ring } else { $null }); $k.appliedUtc = $NowUtc; $k.hold = ''
|    $k.appliedWave = $wave
|}
|
|function Get-SIInvardiaUpdateStatus {
|    <#
|        PURE. The update state for the health check and the admin: @{ Source; LastCheckUtc; Code; Templates; Holds; Refused;
|        LastError; Summary }. -Json is the stored state (SI-Update-State).
|    #>
|    param([AllowNull()][string]$Json)
|    $s = ConvertFrom-SIInvardiaUpdateState -Json $Json
|    $when = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { 'never' } }
|    $line = {
|        param($kind)
|        $k = $s[$kind]
|        if (-not $k.lastAction) { return ('{0}: not checked yet' -f $kind) }
|        $m = if ($k.lastVersion) { '{0} (sequence {1}, ring {2})' -f $k.lastVersion, $k.lastSequence, $k.lastRing } else { 'no manifest' }
|        '{0}: {1} -- {2}{3}' -f $kind, $m, $k.lastAction, $(if ($k.appliedSequence -ge 0) { "; applied sequence $($k.appliedSequence) ($($k.appliedVersion))" } else { '' })
|    }
|    $holds = @($script:SIInvardiaUpdateKinds | Where-Object { $s[$_].hold } | ForEach-Object { '{0}: {1}' -f $_, $s[$_].hold })
|    $refused = @($script:SIInvardiaUpdateKinds | Where-Object { $s[$_].lastAction -eq 'refused' }).Count -gt 0
|    $src = if ($s.source) { $s.source } else { 'none recorded' }
|    $summary = if (-not $s.lastCheckUtc) { 'no update check recorded' } else { 'update source {0}; last check {1}; {2}; {3}' -f $src, (& $when $s.lastCheckUtc), (& $line 'code'), (& $line 'templates') }
|    if ($s.claimResult -in @('conflict', 'forbidden', 'invalid', 'error', 'network', 'refused')) { $summary += ('; install key claim: {0} -- {1}' -f $s.claimResult, $s.claimReason) }
|    [pscustomobject]@{ Source = $src; LastCheckUtc = $s.lastCheckUtc; Code = [pscustomobject]$s.code; Templates = [pscustomobject]$s.templates
|                       Holds = $holds; Refused = $refused; LastError = $s.lastError; Summary = $summary
|                       ClaimResult = $s.claimResult; ClaimReason = $s.claimReason }
|}
|
|# =====================================================================================================================
|#  The install key: claimed automatically (Invardia owner decision 2026-10-04 -- nobody hands one out)
|# =====================================================================================================================
|function Get-SIInvardiaUpdatesEndpoint {
|    <#
|        PURE. Where the manifest is asked for, and in which header the key goes: what the key claim returned
|        (updates.endpoint / updates.header, kept in the update state), else the frozen defaults
|        (<base>/api/updates/securityinsight/manifest, X-Invardia-Install-Key). An endpoint that is not https is ignored.
|        The returned endpoint may be the manifest URL itself, the product's updates root, the updates root or a bare origin.
|    #>
|    param([AllowNull()][System.Collections.IDictionary]$State, [string]$BaseUrl)
|    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|    $uri = Get-SIInvardiaManifestUri -BaseUrl $base
|    $hdr = $script:SIInvardiaUpdateKeyHeader
|    $ep = if ($State) { "$($State['updatesEndpoint'])".Trim().TrimEnd('/') } else { '' }
|    if ($ep -match '^https://[^/\s?#]+(/[^\s?#]*)?$') {
|        $path = $Matches[1]
|        if ($ep -match '/manifest$') { $uri = $ep }
|        elseif ($ep -match ('/' + $script:SIInvardiaUpdateProduct + '$')) { $uri = $ep + '/manifest' }
|        elseif (-not $path) { $uri = Get-SIInvardiaManifestUri -BaseUrl $ep }
|        else { $uri = '{0}/{1}/manifest' -f $ep, $script:SIInvardiaUpdateProduct }
|    }
|    $h = if ($State) { "$($State['updatesHeader'])".Trim() } else { '' }
|    if ($h -match '^[A-Za-z0-9-]{1,64}$') { $hdr = $h }
|    [pscustomobject]@{ ManifestUri = $uri; KeyHeader = $hdr }
|}
|
|function New-SIInvardiaClaimBody {
|    <# PURE. The claim's JSON body: { product, tenantId (from the identity's TOKEN), licence (the licence file text) } -- or,
|       -Community (framework PRO-COMMUNITY-SAME, a Community install that said yes to "Connect this install to Invardia"):
|       { product, tenantId, edition: 'community' } with NO licence. #>
|    param([Parameter(Mandatory)][string]$TenantId, [AllowEmptyString()][string]$Licence = '', [switch]$Community)
|    if ($Community) { return (([ordered]@{ product = $script:SIInvardiaUpdateProduct; tenantId = $TenantId.Trim().ToLowerInvariant(); edition = 'community' }) | ConvertTo-Json -Compress) }
|    if (-not "$Licence".Trim()) { throw 'New-SIInvardiaClaimBody: a licence claim needs -Licence' }
|    ([ordered]@{ product = $script:SIInvardiaUpdateProduct; tenantId = $TenantId.Trim().ToLowerInvariant(); licence = $Licence }) | ConvertTo-Json -Compress
|}
|
|function Request-SIInvardiaInstallKey {
|    <#
|        Make sure the install has its Invardia install key, in the install's Key Vault (SI-Invardia-InstallKey). NEVER throws.
|          1. -BundleKey (the guided install's bundle field installKey) -> stored, and NO claim;
|          2. a key is stored already                                  -> nothing to do;
|          3. an earlier claim answered 409                            -> NOT claimed again (no loop): someone must ask
|                                                                         Invardia for a reset; -Force claims once anyway;
|          4. otherwise CLAIM: POST <base>/api/install-keys/claim { product, tenantId, licence }. The tenant is the 'tid' of
|             the identity's own token (-Seams.TenantId), never config. 201 -> the key is stored and read back, and the
|             answer's updates.endpoint / updates.header are kept in the state for the manifest pulls.
|        -State is the update state (ConvertFrom-SIInvardiaUpdateState); the claim's outcome is recorded in it.
|        -Seams: ReadSecret, WriteSecret, TenantId (required); ClaimHttp { param($Uri, $Body) } (default: a POST with no key).
|        Returns @{ Action; Reason; StatusCode; HasKey; Environment; TelemetryEnabled }. Action: bundle | present | claimed |
|        conflict | held | forbidden | invalid | waiting | network | off | error. The key is never in it.
|    #>
|    [CmdletBinding()]
|    param(
|        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
|        [Parameter(Mandatory)][System.Collections.IDictionary]$Seams,
|        [string]$BaseUrl, [string]$Licence, [string]$BundleKey, [switch]$Force, [int]$TimeoutSec = 60,
|        # framework PRO-COMMUNITY-SAME: a Community install that said yes to "Connect this install to Invardia" claims WITHOUT a
|        # licence ({ product, tenantId, edition: 'community' }); the caller asks the opt-in first (Test-SIInvardiaConnect)
|        [switch]$Community,
|        [AllowNull()][object]$NowUtc
|    )
|    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
|    $newKey = $null
|    $out = {
|        param($act, $why, $code = 0, $has = $false, $envName = '', $tel = $null)
|        if ($act -notin @('present')) { $State.claimResult = $act; $State.claimReason = $why; $State.claimUtc = $now }
|        [pscustomobject]@{ Action = $act; Reason = $why; StatusCode = $code; HasKey = [bool]$has; Environment = $envName; TelemetryEnabled = $tel }
|    }
|    try {
|        foreach ($req in 'ReadSecret', 'WriteSecret') { if (-not $Seams[$req]) { throw "the install key claim needs the '$req' seam" } }
|        $store = {
|            param([string]$k)
|            & $Seams.WriteSecret $script:SIInvardiaUpdateSecretKey $k
|            $back = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim()
|            if ($back -ne $k) { throw 'the install key was written to the Key Vault but did not read back identical' }
|        }
|        if ("$BundleKey".Trim()) {
|            $newKey = "$BundleKey".Trim()
|            if (-not (Test-SIInvardiaInstallKeyFormat $newKey)) { return (& $out 'invalid' 'the install key from the installation bundle is not an install key (it must start with inv-) -- nothing was stored') }
|            & $store $newKey
|            return (& $out 'bundle' ("the install key from the installation bundle is stored in the Key Vault ({0}); no claim was made" -f $script:SIInvardiaUpdateSecretKey) 0 $true)
|        }
|        $have = ''
|        try { $have = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim() } catch { $have = '' }
|        if (Test-SIInvardiaInstallKeyFormat $have) { $have = $null; return (& $out 'present' 'the install key is in the Key Vault' 0 $true) }
|        $have = $null
|        if (-not $Force -and $State.claimResult -eq 'conflict') {
|            return [pscustomobject]@{ Action = 'held'; Reason = ("not claimed again: an earlier claim was refused ({0}) -- ask Invardia support for a reset of this install's key, then claim it again once (Settings > Updates in the web app, or SI_UPDATER_CLAIM_AGAIN=1 on one updater run)" -f $State.claimReason); StatusCode = 0; HasKey = $false; Environment = ''; TelemetryEnabled = $null }
|        }
|        if (-not $Seams['TenantId']) { throw "the install key claim needs the 'TenantId' seam" }
|        $tenant = $null
|        try { $tenant = [string](& $Seams.TenantId) } catch { $tenant = $null }
|        if ("$tenant" -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
|            return (& $out 'off' 'the tenant this install runs in could not be proven from its identity token -- no claim was sent')
|        }
|        $lic = $Licence
|        if (-not $Community) {
|            if (-not "$lic".Trim()) { try { $lic = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretLicence) } catch { $lic = '' } }
|            if (-not "$lic".Trim()) { return (& $out 'off' 'no SecurityInsight Pro licence is installed -- an install key is claimed with the licence') }
|        }
|
|        $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|        $http = if ($Seams['ClaimHttp']) { $Seams['ClaimHttp'] } else { { param($u, $b) Invoke-SIInvardiaUpdateHttp -Uri $u -Body $b -InstallKey '' -TimeoutSec $TimeoutSec } }
|        $r = & $http ('{0}/api/install-keys/claim' -f $base) $(if ($Community) { New-SIInvardiaClaimBody -TenantId $tenant -Community } else { New-SIInvardiaClaimBody -TenantId $tenant -Licence ([string]$lic) })
|        $code = [int]$r.Status
|        $j = $null; if ("$($r.Body)".Trim()) { try { $j = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
|        $p = { param($o, $n) if ($o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
|        $why = { $t = "$(& $p $j 'reason')".Trim(); if (-not $t) { $t = "$(& $p $j 'error')".Trim() }; if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; Hide-SIInvardiaSecret $t }
|        if ($code -in @(200, 201)) {
|            $newKey = "$(& $p $j 'key')".Trim()
|            if (-not (Test-SIInvardiaInstallKeyFormat $newKey)) { return (& $out 'error' 'Invardia answered the claim without a usable install key' $code) }
|            & $store $newKey
|            $upd = & $p $j 'updates'
|            $State.updatesEndpoint = "$(& $p $upd 'endpoint')".Trim()
|            $State.updatesHeader = "$(& $p $upd 'header')".Trim()
|            $envName = "$(& $p $j 'environment')"
|            $tel = & $p $j 'telemetryEnabled'
|            return (& $out 'claimed' ("the install key was claimed{0} and stored in the Key Vault ({1})" -f $(if ($envName) { " for environment $envName" } else { '' }), $script:SIInvardiaUpdateSecretKey) $code $true $envName $tel)
|        }
|        switch ($code) {
|            403 { return (& $out 'forbidden' ("Invardia refused the licence for the install key claim: {0}" -f $(if (& $why) { & $why } else { 'no reason given' })) 403) }
|            409 {
|                $err = "$(& $p $j 'error')".Trim()
|                # a Community claim (no licence): two answers are NOT failures -- said plainly, the install goes on
|                if ($Community -and $err -eq 'tenantKnown') {
|                    return [pscustomobject]@{ Action = 'tenant-known'; Reason = 'this tenant belongs to a company with a SecurityInsight licence at Invardia -- connect it with that licence (the Pro install from your installation page) instead; this install stays anonymous'; StatusCode = 409; HasKey = $false; Environment = ''; TelemetryEnabled = $null }
|                }
|                if ($Community -and $err -eq 'keyExists') {
|                    $back = ''; try { $back = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim() } catch { $back = '' }
|                    $has = [bool](Test-SIInvardiaInstallKeyFormat $back); $back = $null
|                    return [pscustomobject]@{ Action = 'exists'; Reason = $(if ($has) { 'this install is already connected to Invardia -- the key stored for it is kept' } else { 'this install is already connected to Invardia, but its key is not in this install''s Key Vault -- ask Invardia support to send it again; the install goes on' }); StatusCode = 409; HasKey = $has; Environment = ''; TelemetryEnabled = $null }
|                }
|                $msg = switch -Regex ($err) {
|                    '^keyExists$'                     { 'the key was reset or exists: ask Invardia support for a reset of this install''s key' }
|                    '^tenantBelongsToAnotherCompany$' { 'this tenant belongs to another company at Invardia -- contact Invardia support' }
|                    default                           { "Invardia refused the claim (409{0}) -- contact Invardia support" -f $(if ($err) { ": $err" } else { '' }) }
|                }
|                return (& $out 'conflict' $msg 409)
|            }
|            422 {
|                $fields = @(); try { $fields = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['field']) { "$($_.field)" } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
|                return (& $out 'invalid' ("Invardia refused the claim as invalid; fields: {0}" -f $(if ($fields.Count) { $fields -join ', ' } else { 'none named' })) 422)
|            }
|            429 { return (& $out 'waiting' 'Invardia asked to slow down -- the claim is tried again on a later run' 429) }
|            0   { return (& $out 'network' ("Invardia could not be reached for the install key claim: {0}" -f (Hide-SIInvardiaSecret ([string]$r.Error)))) }
|            default {
|                if ($code -ge 500) { return (& $out 'network' ("Invardia answered {0} to the install key claim -- tried again on a later run" -f $code) $code) }
|                return (& $out 'error' ("Invardia answered {0} to the install key claim{1}" -f $code, $(if (& $why) { ": $(& $why)" } else { '' })) $code)
|            }
|        }
|    } catch {
|        & $out 'error' (Hide-SIInvardiaSecret ("the install key claim did not complete: {0}" -f $_.Exception.Message) -Secret $newKey)
|    } finally { $newKey = $null }
|}
|
|# =====================================================================================================================
|#  The real seams, and the guided install's first package
|# =====================================================================================================================
|function New-SIInvardiaUpdateSeams {
|    <#
|        The seams for a real run against the install's Key Vault: ReadSecret / WriteSecret over REST through SecurityInsight's
|        own sign-in (#521, no az CLI: -Mode Rest for the updater job, -Mode Az as setup names the same client). The same Key
|        Vault access the licence request client uses (engine/_shared/SI-LicenceRequest.ps1), so both read the vault the same way.
|    #>
|    param([Parameter(Mandatory)][string]$VaultName, [ValidateSet('Az', 'Rest')][string]$Mode = 'Rest', [string]$SubscriptionId)
|    if (-not (Get-Command -Name New-SILicenceRequestSeams -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-LicenceRequest.ps1')) }
|    $lr = New-SILicenceRequestSeams -VaultName $VaultName -Mode $Mode -SubscriptionId $SubscriptionId
|    # TenantId = the 'tid' of the identity's own token (the install key claim sends it; never config).
|    $out = @{ ReadSecret = $lr.ReadSecret; WriteSecret = $lr.WriteSecret; TenantId = $lr.TenantId }
|    # Invardia S16: the versions of SI-InstallId -- the pull sends the FIRST id written (Get-SIInvardiaInstallId)
|    if ($lr['ReadVersions']) { $out.ReadVersions = $lr.ReadVersions }
|    $out
|}
|
|function Save-SIInvardiaPackage {
|    <#
|        THE GUIDED INSTALL'S FIRST DOWNLOAD through the same pull (#225 hand-over contract v2): ask for the code manifest of
|        -Ring (the ring the new install goes into, 0-3 -- UPDATE-1.7: SI decides it; the bootstrap passes the install's ring,
|        3 for a customer install named 'prod'; none = nothing is fetched, and the reason says so) with the customer's licence, verify it, download the archive, check its size + SHA-256, check it
|        holds SOLUTIONS/SecurityInsight with the VERSION the manifest names, and extract that folder into -OutDir/SecurityInsight.
|        Returns @{ Ok; Action; Path (the SecurityInsight folder to run setup/Install-SecurityInsight from); Version; Sequence;
|        Ring; ManualStep; Reason }. NEVER throws; the install key is never in anything it returns.
|    #>
|    [CmdletBinding()]
|    param([Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [Parameter(Mandatory)][string]$OutDir,
|          [string]$BaseUrl, [System.Collections.IDictionary]$Seams = @{}, [AllowNull()]$Ring = $null)
|    $res = { param($ok, $act, $why, $p = '', $r = $null) [pscustomobject]@{ Ok = $ok; Action = $act; Path = $p; Reason = $why
|        Version = $(if ($r) { $r.Version } else { '' }); Sequence = $(if ($r) { $r.Sequence } else { -1 }); Ring = $(if ($r) { $r.Ring } else { $null })
|        ManualStep = $(if ($r) { $r.ManualStep } else { '' }) } }
|    try {
|        $r = Get-SIInvardiaUpdate -Kind code -OutDir $OutDir -Seams $Seams -BaseUrl $BaseUrl -InstallKey $InstallKey -Licence $LicenceText -Ring $Ring
|        if ($r.Action -ne 'update' -or -not $r.File) { return (& $res $false $r.Action $r.Reason '' $r) }
|        Add-Type -AssemblyName System.IO.Compression.FileSystem
|        $dst = [IO.Path]::Combine($OutDir, 'SecurityInsight')
|        if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
|        $zip = [System.IO.Compression.ZipFile]::OpenRead($r.File)
|        $n = 0; $tops = @{}
|        try {
|            foreach ($e in $zip.Entries) {
|                $name = $e.FullName -replace '\\', '/'
|                $i = $name.IndexOf('/'); if ($i -lt 0) { continue }
|                $tops[$name.Substring(0, $i)] = $true
|                $rel = $name.Substring($i + 1)
|                if (-not $rel.StartsWith('SOLUTIONS/SecurityInsight/') -or $rel.EndsWith('/')) { continue }
|                $sub = $rel.Substring('SOLUTIONS/SecurityInsight/'.Length)
|                if ($sub.Contains('..')) { continue }
|                $f = [IO.Path]::Combine($dst, ($sub -replace '/', [IO.Path]::DirectorySeparatorChar))
|                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $f) | Out-Null
|                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $f, $true)
|                $n++
|            }
|        } finally { $zip.Dispose() }
|        if ($tops.Count -ne 1 -or $n -eq 0) { return (& $res $false 'refused' 'the archive is not a SecurityInsight release (one folder with SOLUTIONS/SecurityInsight)' '' $r) }
|        $vf = [IO.Path]::Combine($dst, 'VERSION')
|        $v = if (Test-Path -LiteralPath $vf) { ([IO.File]::ReadAllText($vf)).Trim() } else { '' }
|        if (-not (Test-SIInvardiaReleaseOfVersion -Released $r.Version -Archive $v)) { return (& $res $false 'refused' ("the archive holds SecurityInsight '{0}', not the {1} the manifest names" -f $v, $r.Version) '' $r) }
|        & $res $true 'update' ("SecurityInsight {0} downloaded and verified ({1} files)" -f $v, $n) $dst $r
|    } catch { & $res $false 'error' (Hide-SIInvardiaSecret ("the package could not be fetched: {0}" -f $_.Exception.Message) -Secret $InstallKey) }
|}
|
|# =====================================================================================================================
|#  The vendor's release upload (setup/Publish-SIRelease.ps1) -- pure request builder
|# =====================================================================================================================
|function New-SIInvardiaReleaseRequest {
|    <#
|        PURE. The publish request of contract section 10: POST <base>/api/releases/securityinsight?kind=<kind>&version=<v>
|        [&minFromVersion=][&image=], the raw file as the body (application/zip for code, application/json for templates),
|        optional X-Release-Notes / X-Release-Manual-Step (URL-encoded), Authorization: Bearer <publisher token>.
|        -Ring 0-3 (UPDATE-1.7, SI decides the ring): &ring=<n> -- published AND released to that ring in one call; -1 = only
|        registered (released later with New-SIInvardiaRingReleaseRequest).
|        -EngineChanged 'true' | 'false' (CR4 #654, Invardia 1.0.445): &engineChanged=<v> -- whether the release changes engine
|        code, which starts the strict-guard period at the installs; '' = not said (Invardia's default).
|        -ChangedScopes (CR3 #657, framework 12.11e item 3): &changedScopes=<id,id,...> | * -- the components the release
|        changed (Format-SIReleaseChangedScopes: '*' = every component, a core file); '' = not sent.
|        Returns @{ Method; Uri; ContentType; Headers; InFile }. The token is only ever in Headers.
|    #>
|    param([Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind, [Parameter(Mandatory)][string]$Version,
|          [Parameter(Mandatory)][string]$FilePath, [string]$BaseUrl, [string]$AccessToken, [string]$Notes, [string]$ManualStep,
|          [string]$MinFromVersion, [string]$Image, [ValidateRange(-1, 3)][int]$Ring = -1,
|          [ValidateSet('', 'true', 'false')][string]$EngineChanged = '',
|          [AllowEmptyString()][string]$ChangedScopes = '')
|    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
|    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|    $q = 'kind={0}&version={1}' -f $Kind, [uri]::EscapeDataString($Version.Trim())
|    if ("$MinFromVersion".Trim()) { $q += '&minFromVersion=' + [uri]::EscapeDataString($MinFromVersion.Trim()) }
|    if ("$Image".Trim()) { $q += '&image=' + [uri]::EscapeDataString($Image.Trim()) }
|    if ($Ring -ge 0) { $q += '&ring=' + $Ring }
|    if ($EngineChanged) { $q += '&engineChanged=' + $EngineChanged }
|    if ("$ChangedScopes".Trim()) { $q += '&changedScopes=' + [uri]::EscapeDataString("$ChangedScopes".Trim()) }
|    $h = [ordered]@{ Accept = 'application/json' }
|    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
|    if ("$Notes".Trim()) { $h['X-Release-Notes'] = [uri]::EscapeDataString($Notes.Trim()) }
|    if ("$ManualStep".Trim()) { $h['X-Release-Manual-Step'] = [uri]::EscapeDataString($ManualStep.Trim()) }
|    [pscustomobject]@{
|        Method = 'POST'; Uri = ('{0}/api/releases/{1}?{2}' -f $base, $script:SIInvardiaUpdateProduct, $q)
|        ContentType = $(if ($Kind -eq 'code') { 'application/zip' } else { 'application/json' }); Headers = $h; InFile = $FilePath
|    }
|}
|
|# =====================================================================================================================
|#  SI decides the version AND the ring; Invardia relays (framework UPDATE-1.7, operator 2026-10-06) -- pure builders for
|#  the release calls of SI's publisher identity (setup/Publish-SIRelease.ps1, setup/Publish-SICommunityRelease.ps1)
|# =====================================================================================================================
|function ConvertFrom-SIJsonText {
|    <# PURE. JSON text -> objects, with ISO date strings KEPT as text where the shell can (pwsh 7.5+: -DateKind String), so a
|       time is judged by what was written ("+02:00" stays "+02:00"), never by what ConvertFrom-Json made of it. THROWS on
|       text that is not JSON. #>
|    # -NoDateKind: the path a shell before pwsh 7.5 takes (tests)
|    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [switch]$NoDateKind)
|    if (-not $NoDateKind -and (Get-Command -Name ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { return ($Text | ConvertFrom-Json -DateKind String -ErrorAction Stop) }
|    # before pwsh 7.5 (review round 2): every ISO date string is marked first so ConvertFrom-Json leaves it as text, then the
|    # mark is taken off again -- "+00:00" stays "+00:00" (UTC), "+02:00" stays "+02:00" (refused by the caller)
|    $mark = '~si-iso~'
|    $o = ([regex]::Replace($Text, '"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}[^"]*)"', ('"' + $mark + '$1"'))) | ConvertFrom-Json -ErrorAction Stop
|    $un = $null
|    $un = { param($v)
|        if ($v -is [string]) { if ($v.StartsWith($mark)) { return $v.Substring($mark.Length) }; return $v }
|        if ($v -is [System.Array]) { return ,@($v | ForEach-Object { & $un $_ }) }
|        if ($v -is [System.Management.Automation.PSCustomObject]) { foreach ($pp in @($v.PSObject.Properties)) { $v.($pp.Name) = (& $un $pp.Value) }; return $v }
|        $v }
|    & $un $o
|}
|
|function ConvertTo-SIRingTestGate {
|    <#
|        PURE (framework RING-GATE-PROOF, Invardia 2026-11-11; SI #1186). A ring call's "testGate" -- from an object, a
|        hashtable or JSON text -- as Invardia takes it: [ordered]@{ commit (7-40 hex, lower case); run (1-200 characters);
|        result green | red; at (ISO UTC, yyyy-MM-ddTHH:mm:ssZ) }. THROWS on anything malformed (Invardia would answer 422
|        and write nothing). An "at" that came back from ConvertFrom-Json as a [datetime] is made ISO UTC again, never refused
|        for it (PIM 3.1.4's ring calls were refused locally by exactly that).
|    #>
|    param([Parameter(Mandatory)][AllowNull()]$TestGate)
|    $tg = $TestGate
|    if ($tg -is [string]) { try { $tg = ConvertFrom-SIJsonText -Text $tg } catch { throw 'testGate is not JSON' } }
|    if ($null -eq $tg) { throw 'no testGate' }
|    $g = { param($k) if ($tg -is [System.Collections.IDictionary]) { $tg[$k] } elseif ($tg.PSObject.Properties[$k]) { $tg.$k } else { $null } }
|    $commit = "$(& $g 'commit')".Trim().ToLowerInvariant()
|    $run = "$(& $g 'run')".Trim()
|    $result = "$(& $g 'result')".Trim().ToLowerInvariant()
|    $atRaw = & $g 'at'
|    $at = if ($atRaw -is [datetime]) { $atRaw.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
|          elseif ($atRaw -is [datetimeoffset]) { $atRaw.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
|          else { "$atRaw".Trim() }
|    $bad = New-Object System.Collections.Generic.List[string]
|    if ($commit -notmatch '^[0-9a-f]{7,40}$') { $bad.Add('commit (7-40 hex)') }
|    if (-not $run -or $run.Length -gt 200) { $bad.Add('run (1-200 characters)') }
|    if ($result -notin @('green', 'red')) { $bad.Add('result (green | red)') }
|    if ($at -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$') { $bad.Add('at (ISO UTC)') }
|    if ($bad.Count) { throw ('testGate malformed: {0}' -f ($bad -join ', ')) }
|    $out = [ordered]@{ commit = $commit; run = $run; result = $result; at = $at }
|    # TWO-AGENT-CHECK-1 (#1404): reviewer verdicts + findings the testGate already carries (a stored proof, a given one) stay
|    # in it -- checked again against its commit (ConvertTo-SIRingReviews; a malformed set THROWS, nothing is sent)
|    $rs = Get-SIRingReviewsShape
|    $rvIn = & $g $rs.Reviews
|    if ($null -ne $rvIn) {
|        $rv = ConvertTo-SIRingReviews -Reviews @($rvIn) -Findings (& $g $rs.Findings) -Commit $commit
|        $out[$rs.Reviews] = $rv[$rs.Reviews]; $out[$rs.Findings] = $rv[$rs.Findings]
|    }
|    $out
|}
|
|function Get-SIRingReviewsShape {
|    <#
|        PURE. THE ONE PLACE the ring call's reviewer verdicts are named (framework TWO-AGENT-CHECK-1, Invardia bfbccf0f; SI #1404).
|        Invardia's shape (2026-11-26): INSIDE the testGate object --
|          "testGate": { commit, run, result, at,
|                        "reviews":  [ { "agent": <text, at most 60>, "verdict": "PASS" | "FAIL", "at": <ISO-8601 UTC>,
|                                        "commit": <40 hex, = testGate.commit> }, ... ],
|                        "findings": { "raised": <int>, "agreedRight": <int>, "agreedWrong": <int> } }
|        Reviews / Findings: the keys inside testGate. Agent / Verdict / At / Commit: an entry's keys. Raised / AgreedRight /
|        AgreedWrong: the findings' keys. Pass: the verdict a ring call takes (Verdicts: every verdict Invardia knows). Min: the
|        fewest DISTINCT agents with Pass. AgentMax: an agent id's longest length. Change the shape HERE only.
|    #>
|    [ordered]@{ Reviews = 'reviews'; Findings = 'findings'; Agent = 'agent'; Verdict = 'verdict'; At = 'at'; Commit = 'commit'
|                Raised = 'raised'; AgreedRight = 'agreedRight'; AgreedWrong = 'agreedWrong'
|                Pass = 'PASS'; Verdicts = @('PASS', 'FAIL'); Min = 2; AgentMax = 60 }
|}
|
|function ConvertTo-SIRingReviews {
|    <#
|        PURE (framework TWO-AGENT-CHECK-1, Invardia bfbccf0f; SI #1404). The reviewer verdicts + the findings a ring call's
|        testGate carries (Get-SIRingReviewsShape) -- from JSON text or an object { reviews: [...], findings: {...} }, or an array
|        of entries with -Findings given beside it. Returns [ordered]@{ reviews = @([ordered]@{ agent; verdict; at; commit });
|        findings = [ordered]@{ raised; agreedRight; agreedWrong } }.
|        THROWS -- the LOCAL refusal, before any call -- unless:
|          * at least Min (2) entries, every agent id given (1-60 characters) and DISTINCT (case-insensitive);
|          * every verdict PASS (a FAIL on the release commit means the two-agent check did not pass: nothing is sent);
|          * every "at" ISO-8601 UTC as WRITTEN (Z or +00:00; JSON text is read with its dates kept as text, ConvertFrom-SIJsonText;
|            a [datetime] is taken only when its kind is Utc), not in the future (more than 5 minutes after -Now), and not
|            before -NotBefore (the reviewed commit's commit time, when the caller knows it: a review older than the commit
|            it names did not review it);
|          * every commit 40 hex and the commit the testGate names (-Commit, 7-40 hex: the same commit, one may be the short
|            form) -- a review of another tree never proves this one; all entries name the same commit;
|          * findings given, each an exact JSON whole number >= 0 (never text: "3" is refused), and raised = agreedRight + agreedWrong (owner: every finding was agreed
|            right -- fixed before the merge -- or wrong -- reason recorded -- by both agents and the author; no agreement = FAIL).
|    #>
|    param([AllowNull()]$Reviews, [AllowNull()]$Findings = $null, [AllowEmptyString()][string]$Commit = '',
|          [AllowNull()][Nullable[datetime]]$NotBefore = $null, [datetime]$Now = [datetime]::UtcNow, [int]$SkewMinutes = 5)
|    $s = Get-SIRingReviewsShape
|    $r = $Reviews
|    if ($r -is [string]) {
|        if (-not "$r".Trim()) { throw 'reviews: none given' }
|        try { $r = ConvertFrom-SIJsonText -Text $r } catch { throw 'reviews is not JSON' }
|    }
|    $g = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
|    $fd = $Findings
|    if ($fd -is [string]) { if ("$fd".Trim()) { try { $fd = ConvertFrom-SIJsonText -Text $fd } catch { throw 'findings is not JSON' } } else { $fd = $null } }
|    # an object that carries the list (and the findings) under their names: { "reviews": [ ... ], "findings": { ... } }
|    $wrapped = ($null -ne $r -and $r -isnot [System.Array] -and $r -isnot [System.Collections.IList] -and
|                $(if ($r -is [System.Collections.IDictionary]) { $r.Contains($s.Reviews) } else { [bool]$r.PSObject.Properties[$s.Reviews] }))
|    if ($wrapped) {
|        if ($null -eq $fd) { $fd = & $g $r $s.Findings }
|        $r = & $g $r $s.Reviews
|    }
|    $list = @(@($r) | Where-Object { $null -ne $_ })
|    $bad = New-Object System.Collections.Generic.List[string]
|    if ($list.Count -lt [int]$s.Min) { throw ('reviews refused: {0} given -- a ring call needs at least {1} independent reviewer verdicts on the release commit (TWO-AGENT-CHECK-1)' -f $list.Count, $s.Min) }
|    $tc = "$Commit".Trim().ToLowerInvariant()
|    if ($tc -notmatch '^[0-9a-f]{7,40}$') { $bad.Add('the testGate names no commit to match the reviews to') }
|    $seen = @{}; $commits = @{}
|    $out = New-Object System.Collections.Generic.List[object]
|    for ($i = 0; $i -lt $list.Count; $i++) {
|        $e = $list[$i]; $n = $i + 1
|        $agent = "$(& $g $e $s.Agent)".Trim()
|        $verdict = "$(& $g $e $s.Verdict)".Trim().ToUpperInvariant()
|        $atRaw = & $g $e $s.At
|        $at = ''; $atUtc = $null
|        # a [datetime] only when it IS UTC (ConvertFrom-Json before pwsh 7.5 turns "+02:00" into a Local one: refused)
|        if ($atRaw -is [datetime]) { if ($atRaw.Kind -eq [DateTimeKind]::Utc) { $atUtc = $atRaw } }
|        elseif ($atRaw -is [datetimeoffset]) { if ($atRaw.Offset -eq [TimeSpan]::Zero) { $atUtc = $atRaw.UtcDateTime } }
|        else {
|            $t = "$atRaw".Trim()
|            $o = [datetimeoffset]::MinValue
|            if ($t -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00)$' -and
|                [datetimeoffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$o)) {
|                $atUtc = $o.UtcDateTime
|            }
|        }
|        if ($null -ne $atUtc) { $at = $atUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
|        $ec = "$(& $g $e $s.Commit)".Trim().ToLowerInvariant()
|        if (-not $agent -or $agent.Length -gt [int]$s.AgentMax) { $bad.Add(('review {0}: agent (1-{1} characters)' -f $n, $s.AgentMax)) }
|        elseif ($seen.ContainsKey($agent.ToLowerInvariant())) { $bad.Add(('review {0}: agent {1} reviewed twice -- the reviewers must be distinct' -f $n, $agent)) }
|        else { $seen[$agent.ToLowerInvariant()] = $true }
|        if ($verdict -notin @($s.Verdicts)) { $bad.Add(('review {0}: verdict {1} ({2})' -f $n, $(if ($verdict) { $verdict } else { 'none' }), (@($s.Verdicts) -join ' | '))) }
|        elseif ($verdict -ne $s.Pass) { $bad.Add(('review {0}: verdict {1} -- only {2} from every reviewer reaches a ring' -f $n, $verdict, $s.Pass)) }
|        if (-not $at) { $bad.Add(('review {0}: at (ISO-8601 UTC, yyyy-MM-ddTHH:mm:ssZ)' -f $n)) }
|        elseif ($atUtc -gt $Now.ToUniversalTime().AddMinutes([Math]::Abs($SkewMinutes))) { $bad.Add(('review {0}: at {1} is in the future' -f $n, $at)) }
|        elseif ($null -ne $NotBefore -and $atUtc -lt ([datetime]$NotBefore).ToUniversalTime()) { $bad.Add(('review {0}: at {1} is before the reviewed commit was made ({2:yyyy-MM-ddTHH:mm:ssZ}) -- it did not review that commit' -f $n, $at, ([datetime]$NotBefore).ToUniversalTime())) }
|        if ($ec -notmatch '^[0-9a-f]{40}$') { $bad.Add(('review {0}: commit (40 hex, the release commit)' -f $n)) }
|        elseif ($tc -match '^[0-9a-f]{7,40}$' -and -not ($ec.StartsWith($tc) -or $tc.StartsWith($ec))) { $bad.Add(('review {0}: reviewed {1}, the testGate (the release commit) is {2} -- the reviewed tree is not the released tree' -f $n, $ec, $tc)) }
|        else { $commits[$ec] = $true }
|        $x = [ordered]@{}
|        $x[$s.Agent] = $agent; $x[$s.Verdict] = $verdict; $x[$s.At] = $at; $x[$s.Commit] = $ec
|        $out.Add($x)
|    }
|    if ($commits.Count -gt 1) { $bad.Add(('the reviews name {0} different commits' -f $commits.Count)) }
|    $fo = [ordered]@{}
|    if ($null -eq $fd) { $bad.Add(('findings ({0}, {1}, {2}) not given' -f $s.Raised, $s.AgreedRight, $s.AgreedWrong)) }
|    else {
|        $num = @{}
|        foreach ($k in @($s.Raised, $s.AgreedRight, $s.AgreedWrong)) {
|            $v = & $g $fd $k
|            # an exact JSON whole number only: text ("3"), a fraction or a negative is refused
|            if (($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte]) -and $v -ge 0 -and $v -le 999999999) { $num[$k] = [int]$v; $fo[$k] = $num[$k] }
|            else { $bad.Add(('findings: {0} (a whole number >= 0)' -f $k)) }
|        }
|        if ($num.Count -eq 3 -and $num[$s.Raised] -ne ($num[$s.AgreedRight] + $num[$s.AgreedWrong])) {
|            $bad.Add(('findings: {0} raised, but {1} agreed right + {2} agreed wrong -- every finding must be agreed right or wrong by both reviewers and the author (no agreement = FAIL)' -f $num[$s.Raised], $num[$s.AgreedRight], $num[$s.AgreedWrong]))
|        }
|    }
|    if ($bad.Count) { throw ('reviews refused: {0}' -f ($bad -join '; ')) }
|    $res = [ordered]@{}
|    $res[$s.Reviews] = @($out.ToArray()); $res[$s.Findings] = $fo
|    $res
|}
|
|function Add-SIRingTestGateReviews {
|    <#
|        PURE (TWO-AGENT-CHECK-1, SI #1404). The testGate (ConvertTo-SIRingTestGate shape) with the reviewer verdicts and the
|        findings put INSIDE it (Get-SIRingReviewsShape) -- -Reviews: JSON text / object { reviews, findings } / an array (with
|        -Findings). Checked against the testGate's commit (ConvertTo-SIRingReviews); THROWS on a refusal. When the testGate
|        names its commit in short form, it takes the full 40-hex commit the reviews name (Invardia compares them as equal).
|        -Reviews $null: the testGate as it is.
|    #>
|    param([Parameter(Mandatory)][AllowNull()]$TestGate, [AllowNull()]$Reviews, [AllowNull()]$Findings = $null, [AllowNull()][Nullable[datetime]]$NotBefore = $null)
|    $tg = ConvertTo-SIRingTestGate -TestGate $TestGate
|    if ($null -eq $Reviews -or ($Reviews -is [string] -and -not "$Reviews".Trim())) { return $tg }
|    $s = Get-SIRingReviewsShape
|    $rv = ConvertTo-SIRingReviews -Reviews $Reviews -Findings $Findings -Commit $tg.commit -NotBefore $NotBefore
|    $full = "$(@($rv[$s.Reviews])[0][$s.Commit])"
|    if ($full -match '^[0-9a-f]{40}$') { $tg.commit = $full }
|    $tg[$s.Reviews] = $rv[$s.Reviews]; $tg[$s.Findings] = $rv[$s.Findings]
|    $tg
|}
|
|function Test-SIRingTestGateHasReviews {
|    <# PURE. Does -TestGate (any form ConvertTo-SIRingTestGate takes) carry reviewer verdicts? Never throws. #>
|    param([AllowNull()]$TestGate)
|    try {
|        $s = Get-SIRingReviewsShape
|        $tg = ConvertTo-SIRingTestGate -TestGate $TestGate
|        [bool]($tg.Contains($s.Reviews) -and @($tg[$s.Reviews]).Count)
|    } catch { $false }
|}
|
|function New-SIInvardiaRingReleaseRequest {
|    <#
|        PURE. Release a version Invardia already holds to ONE ring:
|          POST <base>/api/releases/securityinsight/<kind>/rings/<ring>   { version[, tag][, testGate] }   (kind code | templates | community)
|        -TestGate (framework RING-GATE-PROOF, #1186): the green quick-gate run on exactly the release commit
|        (ConvertTo-SIRingTestGate shape; setup\_shared\SI-ReleaseGateProof.ps1 decides it). A request that will be SENT (it
|        carries -AccessToken) without one is refused here -- no ring call ever leaves without its proof; a plan (no token)
|        shows the body without it.
|        -Reviews (+ -Findings) (framework TWO-AGENT-CHECK-1, #1404): testGate.reviews [{ agent, verdict, at, commit }] and
|        testGate.findings { raised, agreedRight, agreedWrong } (Get-SIRingReviewsShape) -- the /check dry run carries the same
|        body (New-SIInvardiaRingCheckRequest builds it from the same arguments).
|        Community: rings 0-3, as Pro (framework PRO-COMMUNITY-SAME, SI #1207). Only SI's publisher identity may call it.
|        -EngineChanged 'true' | 'false' (CR4 #654): sets engineChanged on that version's record (a version published before
|        SI said it); '' = not sent.
|        -ChangedScopes (CR3 #657): the components the release changed, as a JSON list (changedScopes: [id, ...] or ['*']);
|        '' = not sent. The same text Format-SIReleaseChangedScopes gives the publish call (comma-separated).
|        -ImageOnly + -ImageDiff (framework IMAGE-PATCH-1 point 8, IMAGE-ONLY-AUTO-1; SI #1204): the version is an IMAGE-ONLY
|        release (base digests / version stamps / notes only) -- the body adds "imageOnly": true and "imageDiff": { fromVersion,
|        files: [ { path, removed: [...], added: [...] } ] }, every file changed since the version ring 2 runs. Invardia checks
|        the diff and approves rings 2 / 3 on the owner's standing yes once rings 0 / 1 proved it. Over Invardia's limits (300
|        files, 20,000 lines, 1,000 characters a line) or no fromVersion = refused here (Invardia would answer 422).
|        Returns @{ Method; Uri; ContentType; Headers; Body }. The token is only ever in Headers.
|    #>
|    param([Parameter(Mandatory)][ValidateSet('code', 'templates', 'community')][string]$Kind, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring,
|          # -Tag: '' only (2026-10-28, as PIM: the stable zip v<version>; a ring name never belongs in it)
|          [Parameter(Mandatory)][string]$Version, [ValidateSet('')][string]$Tag = '', [string]$BaseUrl, [string]$AccessToken,
|          [ValidateSet('', 'true', 'false')][string]$EngineChanged = '', [AllowEmptyString()][string]$ChangedScopes = '',
|          [AllowNull()]$TestGate = $null, [switch]$ImageOnly, [AllowNull()]$ImageDiff = $null,
|          # #1324 (framework DIGEST-PROOF-1): the rings 2/3 image patch of an older build is proven by the NEWER patch rings 0/1
|          # proved -- { version; imageDiff } of that patch (ConvertTo-SIRingProvenBy); with -ImageOnly only
|          [AllowNull()]$ProvenBy = $null,
|          # #1404 (framework TWO-AGENT-CHECK-1): the two independent reviewers' verdicts + the findings, put INSIDE testGate
|          # (Add-SIRingTestGateReviews; JSON / object { reviews, findings } / an array with -Findings). Refused here, before
|          # any call, unless every check of ConvertTo-SIRingReviews passes. $null = the testGate as it is (it may carry them).
|          [AllowNull()]$Reviews = $null, [AllowNull()]$Findings = $null,
|          # #1404 review round 3 (H4): a roll-back to the version a ring ran before (its own stored proof as it was) -- the ONE
|          # ring call that is sent (it carries -AccessToken) without reviewer verdicts, beside an image-only call
|          [switch]$RollBack)
|    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
|    if ($null -ne $ProvenBy -and -not $ImageOnly) { throw 'provenBy goes with an image-only ring call only' }
|    $hasReviews = -not ($null -eq $Reviews -or ($Reviews -is [string] -and -not "$Reviews".Trim()))
|    if ($hasReviews -and $null -eq $TestGate) { throw 'refused: reviews go INSIDE testGate (TWO-AGENT-CHECK-1) -- a ring call with reviews needs its testGate' }
|    # SI #1207 (framework PRO-COMMUNITY-SAME): a Community version goes to rings 0-3, the same rings as Pro
|    if ($AccessToken -and $null -eq $TestGate) { throw ("refused: the ring {0} call carries no testGate -- a ring call is sent only with the green quick-gate run on exactly the release commit (RING-GATE-PROOF)" -f $Ring) }
|    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|    $b = [ordered]@{ version = $Version.Trim() }
|    if ($Tag) { $b['tag'] = $Tag }
|    if ($EngineChanged) { $b['engineChanged'] = ($EngineChanged -eq 'true') }
|    if ("$ChangedScopes".Trim()) { $b['changedScopes'] = [string[]]@("$ChangedScopes".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
|    if ($null -ne $TestGate) { $b['testGate'] = $(if ($hasReviews) { Add-SIRingTestGateReviews -TestGate $TestGate -Reviews $Reviews -Findings $Findings } else { ConvertTo-SIRingTestGate -TestGate $TestGate }) }
|    # #1404 review round 3 (H4, fail closed): a ring call that will be SENT carries two PASS reviews inside testGate -- unless it
|    # is image-only (Invardia's exemption decides) or an explicit roll-back. Checked on the testGate as it will go (malformed
|    # ones were refused just above).
|    $rsh = Get-SIRingReviewsShape
|    if ($AccessToken -and -not $ImageOnly -and -not $RollBack -and -not ($b['testGate'].Contains($rsh.Reviews) -and @($b['testGate'][$rsh.Reviews]).Count)) {
|        throw ("refused: the ring {0} call carries no reviewer verdicts -- two fresh independent reviewers must PASS on exactly the release commit (TWO-AGENT-CHECK-1)" -f $Ring)
|    }
|    if ($ImageOnly) {
|        $b['imageOnly'] = $true
|        $b['imageDiff'] = ConvertTo-SIRingImageDiff -ImageDiff $ImageDiff
|        if ($null -ne $ProvenBy) { $b['provenBy'] = ConvertTo-SIRingProvenBy -ProvenBy $ProvenBy -Version $Version }
|    }
|    $h = [ordered]@{ Accept = 'application/json' }
|    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
|    [pscustomobject]@{ Method = 'POST'; Uri = ('{0}/api/releases/{1}/{2}/rings/{3}' -f $base, $script:SIInvardiaUpdateProduct, $Kind, $Ring)
|                       ContentType = 'application/json'; Headers = $h; Body = ($b | ConvertTo-Json -Compress -Depth 8) }
|}
|
|function ConvertTo-SIRingImageDiff {
|    <#
|        PURE (framework IMAGE-PATCH-1 point 8; SI #1204). An image-only ring call's "imageDiff" -- from an object, a hashtable
|        or JSON text -- as Invardia takes it: [ordered]@{ fromVersion; files = @([ordered]@{ path; removed = @(); added = @() }) }.
|        THROWS on what Invardia would refuse with 422: no fromVersion, no file, more than 300 files, more than 20,000 lines in
|        all, a line over 1,000 characters.
|    #>
|    param([AllowNull()]$ImageDiff)
|    $d = $ImageDiff
|    if ($d -is [string]) { try { $d = $d | ConvertFrom-Json -ErrorAction Stop } catch { throw 'imageDiff is not JSON' } }
|    if ($null -eq $d) { throw 'an image-only ring call needs its imageDiff' }
|    $g = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
|    $from = "$(& $g $d 'fromVersion')".Trim()
|    if ($from -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "imageDiff: fromVersion is not a release version: '$from'" }
|    $files = New-Object System.Collections.Generic.List[object]
|    $lines = 0
|    foreach ($f in @(& $g $d 'files')) {
|        if ($null -eq $f) { continue }
|        $p = "$(& $g $f 'path')".Trim()
|        if (-not $p) { throw 'imageDiff: a file without its path' }
|        $rem = [string[]]@(@(& $g $f 'removed') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
|        $add = [string[]]@(@(& $g $f 'added') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
|        foreach ($l in @($rem) + @($add)) { if ($l.Length -gt 1000) { throw ("imageDiff: a line of {0} is over 1,000 characters" -f $p) } }
|        $lines += $rem.Count + $add.Count
|        $files.Add([ordered]@{ path = $p; removed = @($rem); added = @($add) })
|    }
|    if (-not $files.Count) { throw 'imageDiff: no file changed' }
|    if ($files.Count -gt 300) { throw ("imageDiff: {0} files (Invardia takes at most 300)" -f $files.Count) }
|    if ($lines -gt 20000) { throw ("imageDiff: {0} lines (Invardia takes at most 20,000)" -f $lines) }
|    [ordered]@{ fromVersion = $from; files = @($files.ToArray()) }
|}
|
|function New-SIInvardiaRingCheckRequest {
|    <#
|        PURE (framework RELEASE-DRYRUN-1, #1327). The DRY RUN of a ring call: POST <base>/api/releases/securityinsight/<kind>/rings/
|        <ring>/check with the EXACT body New-SIInvardiaRingReleaseRequest builds for the same arguments (version, testGate,
|        imageOnly, imageDiff, provenBy, ...). Invardia answers { outcome, problems[], imageOnly, standing, proof } and changes
|        NOTHING (no ring release, no question, no mail). Takes every argument of New-SIInvardiaRingReleaseRequest.
|    #>
|    param([Parameter(Mandatory)][hashtable]$RingArgs)
|    $q = New-SIInvardiaRingReleaseRequest @RingArgs
|    [pscustomobject]@{ Method = 'POST'; Uri = ($q.Uri + '/check'); ContentType = $q.ContentType; Headers = $q.Headers; Body = $q.Body }
|}
|
|function Get-SIInvardiaRingCheckVerdict {
|    <#
|        PURE (framework RELEASE-DRYRUN-1 point 2). The dry run's answer (-Response @{ Status; Body }) -> may the ring call go?
|          releases / standing-approves / standing-waits-for-proof  = go (the last: Invardia approves once the proof is in)
|          owner-asked = go ONLY when the call does not mean a standing-yes release (-Standing: an image-only call does) --
|                        a standing-yes release that would ask the owner is a STOP
|          refused, an unknown outcome, no 200 answer = STOP
|        -Ring 0 / 1 (#1327: EVERY ring call is dry-run first): the one expected outcome is releases (rings 0 / 1 release at
|        once at Invardia) -- anything else is a STOP; -Ring 2 / 3 or not given: the rule above.
|        @{ Ok; Outcome; Problems; Line; Expected } -- Line names the outcome (and the problems), for the log.
|    #>
|    param($Response, [switch]$Standing, [ValidateRange(-1, 3)][int]$Ring = -1)
|    $st = 0; try { $st = [int]$Response.Status } catch { }
|    $j = $null; try { if ("$($Response.Body)".Trim()) { $j = "$($Response.Body)" | ConvertFrom-Json -ErrorAction Stop } } catch { }
|    $outcome = if ($j -and $j.PSObject.Properties['outcome']) { "$($j.outcome)".Trim() } else { '' }
|    $probs = @(if ($j -and $j.PSObject.Properties['problems']) { @($j.problems) | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['message']) { "$($_.message)" } else { ($_ | ConvertTo-Json -Compress -Depth 4) } } } )
|    $pt = if ($probs.Count) { ' -- problems: ' + ($probs -join '; ') } else { '' }
|    $expected = if ($Ring -ge 0 -and $Ring -le 1) { 'releases' } elseif ($Standing) { 'releases / standing-approves / standing-waits-for-proof' } else { 'releases / standing-approves / standing-waits-for-proof / owner-asked' }
|    if ($st -ne 200 -or -not $outcome) {
|        $why = if ($st -eq 0) { 'no answer' } else { "HTTP $st" }
|        return [pscustomobject]@{ Ok = $false; Outcome = $(if ($outcome) { $outcome } else { 'none' }); Problems = $probs; Expected = $expected; Line = ('the dry run (/check) did not answer an outcome ({0}{1}) -- nothing was sent' -f $why, $(if ("$($Response.Body)".Trim()) { ': ' + (Hide-SIInvardiaSecret ("$($Response.Body)".Substring(0, [Math]::Min(300, "$($Response.Body)".Length)))) } else { '' })) }
|    }
|    $go = $outcome -in 'releases', 'standing-approves', 'standing-waits-for-proof'
|    if ($outcome -eq 'owner-asked' -and -not $Standing) { $go = $true }
|    # #1327: a ring 0 / 1 call releases at once -- any other answer means the real call would not do what this tool expects
|    if ($Ring -ge 0 -and $Ring -le 1) { $go = ($outcome -eq 'releases') }
|    $line = if ($go) { 'the dry run (/check): {0}{1}' -f $outcome, $pt }
|            elseif ($Ring -ge 0 -and $Ring -le 1) { 'the dry run (/check): {0} -- a ring {1} call is expected to answer releases{2}; nothing was sent' -f $outcome, $Ring, $pt }
|            elseif ($outcome -eq 'owner-asked') { 'the dry run (/check): owner-asked -- an image-only call goes under the standing yes and never asks (SECURITY-NO-ASK-1){0}; nothing was sent' -f $pt }
|            else { 'the dry run (/check): {0}{1}; nothing was sent' -f $outcome, $pt }
|    [pscustomobject]@{ Ok = $go; Outcome = $outcome; Problems = $probs; Line = $line; Expected = $expected }
|}
|
|function ConvertTo-SIRingProvenBy {
|    <#
|        PURE (#1324, framework DIGEST-PROOF-1). The "provenBy" of an image-only ring call -- from an object, a hashtable or JSON
|        text -- as Invardia takes it: [ordered]@{ version = <the proving patch rings 0/1 run>; imageDiff = <its own diff,
|        ConvertTo-SIRingImageDiff: fromVersion = the release it was built on> }. THROWS when the version is not a release
|        version, equals the version being released (a patch cannot prove itself), or the diff is refused.
|    #>
|    param([AllowNull()]$ProvenBy, [string]$Version = '')
|    $p = $ProvenBy
|    if ($p -is [string]) { try { $p = $p | ConvertFrom-Json -ErrorAction Stop } catch { throw 'provenBy is not JSON' } }
|    if ($null -eq $p) { throw 'provenBy is empty' }
|    $g = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
|    $v = "$(& $g $p 'version')".Trim()
|    if ($v -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "provenBy: version is not a release version: '$v'" }
|    if ("$Version".Trim() -and $v -eq "$Version".Trim()) { throw "provenBy: $v cannot prove itself" }
|    [ordered]@{ version = $v; imageDiff = (ConvertTo-SIRingImageDiff -ImageDiff (& $g $p 'imageDiff')) }
|}
|
|function New-SIInvardiaCommunityRegisterRequest {
|    <#
|        PURE. Register a Community version with Invardia: POST <base>/api/releases/securityinsight/community { version, tag }.
|        Invardia fetches the PUBLIC GitHub release zip once (tag v<version>, or v<version>-ring2 with tag 'ring2') and stores
|        its URL, SHA-256 and size -- the file stays on GitHub; Invardia only signs the ring entries. Returns the request shape
|        of New-SIInvardiaRingReleaseRequest.
|    #>
|    # -EngineChanged (2026-10-28, the alignment with PIM's community-register): sent as engineChanged when given -- whether this
|    # version changed engine code (Invardia's release mode); not given = the body is exactly { version, tag } as before
|    # -Tag: '' only (2026-10-28, as PIM's community-register: the stable zip v<version>; a ring name never belongs in it)
|    # -Sha256 (2026-10-31): the SHA-256 of the zip the publisher downloaded and checked -- Invardia signs only that exact file
|    # and refuses a fetch whose hash differs (a release asset replaced between the check and Invardia's fetch is never signed)
|    param([Parameter(Mandatory)][string]$Version, [ValidateSet('')][string]$Tag = '', [string]$BaseUrl, [string]$AccessToken, [AllowNull()][object]$EngineChanged = $null,
|          [AllowEmptyString()][string]$Sha256 = '')
|    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
|    if ("$Sha256".Trim() -and "$Sha256".Trim() -notmatch '^[0-9a-fA-F]{64}$') { throw "not a SHA-256: '$Sha256'" }
|    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
|    $h = [ordered]@{ Accept = 'application/json' }
|    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
|    $b = [ordered]@{ version = $Version.Trim(); tag = $Tag }
|    if ($null -ne $EngineChanged) { $b['engineChanged'] = [bool]$EngineChanged }
|    if ("$Sha256".Trim()) { $b['sha256'] = "$Sha256".Trim().ToLowerInvariant() }
|    [pscustomobject]@{ Method = 'POST'; Uri = ('{0}/api/releases/{1}/community' -f $base, $script:SIInvardiaUpdateProduct)
|                       ContentType = 'application/json'; Headers = $h; Body = ($b | ConvertTo-Json -Compress) }
|}
|
|function Get-SIInvardiaNotApproved {
|    <#
|        PURE. CR3 (#657, framework 12.11e item 7): Invardia refuses a ring 2 / 3 release, or a wave, of a version the owner
|        has not APPROVED -- 409 "notApproved" with the reason. Returns @{ NotApproved; Reason } from an answer
|        (-Response: @{ Status; Body }); NotApproved $false for any other answer (a 409 "version exists" included).
|    #>
|    param([Parameter(Mandatory)]$Response)
|    $no = [pscustomobject]@{ NotApproved = $false; Reason = '' }
|    if ([int]$Response.Status -ne 409) { return $no }
|    $body = "$($Response.Body)"
|    $j = $null; try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { }
|    $hit = $false; $why = ''
|    if ($j -and -not ($j -is [string])) {
|        foreach ($n in 'error', 'code', 'status', 'title', 'kind') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -ieq 'notApproved') { $hit = $true } }
|        foreach ($n in 'reason', 'detail', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -and "$($j.$n)".Trim() -ine 'notApproved') { $why = "$($j.$n)".Trim(); break } }
|    } elseif ($j -is [string] -and "$j".Trim() -ieq 'notApproved') { $hit = $true }
|    if (-not $hit -and $body -match '(?i)\bnotApproved\b') { $hit = $true }
|    if (-not $hit) { return $no }
|    $why = Hide-SIInvardiaSecret $why
|    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
|    # framework SECURITY-NO-ASK-1 (2026-11-23): an image-only call's 409 carries "standing", "ownerAsked" and its own text, and
|    # a refused image-only claim names the task it became on SI's board (dedupe imageclaim:...)
|    $g = { param($n) if ($j -and -not ($j -is [string]) -and $j.PSObject.Properties[$n]) { $j.$n } else { $null } }
|    $standing = & $g 'standing'
|    $oa = & $g 'ownerAsked'
|    $text = ''; foreach ($n in 'hint', 'note', 'text', 'message') { $v = & $g $n; if ($v -and "$v".Trim() -and "$v".Trim() -ne $why) { $text = Hide-SIInvardiaSecret "$v".Trim(); break } }
|    $task = ''; foreach ($n in 'taskId', 'task', 'dedupe', 'dedupeKey') { $v = & $g $n; if ($v) { $task = if ($v -is [string]) { "$v".Trim() } elseif ($v.PSObject.Properties['taskId']) { "$($v.taskId)".Trim() } elseif ($v.PSObject.Properties['dedupe']) { "$($v.dedupe)".Trim() } else { ($v | ConvertTo-Json -Compress -Depth 3) }; break } }
|    [pscustomobject]@{ NotApproved = $true; Reason = $why
|        Standing = $(if ($null -eq $standing) { '' } elseif ($standing -is [string] -or $standing -is [bool]) { "$standing" } else { ($standing | ConvertTo-Json -Compress -Depth 3) })
|        OwnerAsked = $(if ($null -eq $oa) { $null } else { [bool]("$oa" -match '^(?i)true$') }); Text = $text; Task = (Hide-SIInvardiaSecret $task) }
|}
|
|function Format-SIInvardiaNotApproved {
|    <# PURE. The plain words for a 409 notApproved of a CODE release to rings 2 / 3: what happened, Invardia's reason, who
|       decides. An IMAGE-ONLY call never gets these words (framework SECURITY-NO-ASK-1): Format-SIInvardiaImageOnlyNotApproved. #>
|    param([Parameter(Mandatory)][string]$What, [AllowEmptyString()][string]$Reason)
|    ("{0}: NOT APPROVED -- Invardia refused it (409 notApproved). A release to ring 2 or 3, or a pre-release wave, needs the owner's APPROVED on this version first (Invardia's back office: Updates > the release). Invardia's reason: {1}. Nothing was released; rings 0 and 1 are not affected." -f $What, $(if ("$Reason".Trim()) { "$Reason".Trim() } else { 'none given' }))
|}
|
|function Format-SIInvardiaImageOnlyNotApproved {
|    <#
|        PURE. Framework SECURITY-NO-ASK-1 (owner 2026-11-23: security updates never ask; they go to rings 0-3 under the standing
|        yes). An image-only ring call's 409 notApproved in Invardia's OWN fields -- standing, ownerAsked, its text -- and never a
|        line that sends anyone for an approval:
|          * ownerAsked false (or not said): Invardia approves under the standing yes once the proof is in -- wait (expected)
|          * ownerAsked true: the image-only claim was refused; Invardia put it on SecurityInsight's task board (dedupe
|            imageclaim:<version>) -- the line points to that task
|        -NotApproved: Get-SIInvardiaNotApproved's answer.
|    #>
|    param([Parameter(Mandatory)][string]$What, [Parameter(Mandatory)]$NotApproved, [string]$Version = '')
|    $na = $NotApproved
|    $f = @()
|    if ("$($na.Standing)".Trim()) { $f += ('standing: {0}' -f "$($na.Standing)".Trim()) }
|    $f += ('ownerAsked: {0}' -f $(if ($null -eq $na.OwnerAsked) { 'not said' } else { "$([bool]$na.OwnerAsked)".ToLowerInvariant() }))
|    if ("$($na.Text)".Trim()) { $f += ('Invardia: "{0}"' -f "$($na.Text)".Trim()) }
|    if ("$($na.Reason)".Trim()) { $f += ('reason: {0}' -f "$($na.Reason)".Trim()) }
|    $fields = $f -join '; '
|    if ($na.OwnerAsked -eq $true) {
|        $task = if ("$($na.Task)".Trim()) { "$($na.Task)".Trim() } else { 'imageclaim:' + $(if ($Version) { $Version } else { '<version>' }) }
|        return ('{0}: the image-only claim was REFUSED (409 notApproved; {1}) -- it is a task on SecurityInsight''s board at Invardia ({2}): fix the claim there; nothing was released' -f $What, $fields, $task)
|    }
|    ('{0}: 409 notApproved under the standing yes (image-only; {1}) -- Invardia approves by itself once the proof is in' -f $What, $fields)
|}
|
|function Get-SIInvardiaHealthHold {
|    <#
|        PURE. CR2 (framework 12.11d): Invardia holds a ring 2 / 3 release of a code version while a lower-ring install that
|        took it turned Unhealthy or Unknown -- 409 { error "healthHold", ring, version, reason, holding, warnings }. Returns
|        @{ HealthHold; Reason; Holding } from an answer (-Response: @{ Status; Body }); HealthHold $false for any other answer.
|    #>
|    param([Parameter(Mandatory)]$Response)
|    $no = [pscustomobject]@{ HealthHold = $false; Reason = ''; Holding = '' }
|    if ([int]$Response.Status -ne 409) { return $no }
|    $body = "$($Response.Body)"
|    $j = $null; try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { }
|    $hit = $false; $why = ''; $who = ''
|    if ($j -and -not ($j -is [string])) {
|        foreach ($n in 'error', 'code', 'status', 'kind') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -ieq 'healthHold') { $hit = $true } }
|        if ($j.PSObject.Properties['reason'] -and "$($j.reason)".Trim()) { $why = "$($j.reason)".Trim() }
|        if ($j.PSObject.Properties['holding'] -and $null -ne $j.holding) { $who = (@($j.holding) | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ConvertTo-Json -Compress -Depth 4) } }) -join ', ' }
|    }
|    if (-not $hit -and $body -match '(?i)\bhealthHold\b') { $hit = $true }
|    if (-not $hit) { return $no }
|    $why = Hide-SIInvardiaSecret $why; $who = Hide-SIInvardiaSecret $who
|    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
|    if ($who.Length -gt 300) { $who = $who.Substring(0, 297) + '...' }
|    [pscustomobject]@{ HealthHold = $true; Reason = $why; Holding = $who }
|}
|
|function Format-SIInvardiaHealthHold {
|    <# PURE. The plain words for a 409 healthHold: what happened, why, which installs hold it, who decides. #>
|    param([Parameter(Mandatory)][string]$What, [AllowEmptyString()][string]$Reason, [AllowEmptyString()][string]$Holding)
|    ("{0}: HELD FOR DATA HEALTH -- Invardia refused it (409 healthHold): an install of a lower ring that took this version is Unhealthy or Unknown since. Invardia's reason: {1}. Holding: {2}. Fix that install's data health (or the owner overrides the hold with a reason in Invardia's back office). Nothing was released; rings 0 and 1 are not affected." -f $What, $(if ("$Reason".Trim()) { "$Reason".Trim() } else { 'none given' }), $(if ("$Holding".Trim()) { "$Holding".Trim() } else { 'not named' }))
|}
|function Get-SIInvardiaReleaseCallOutcome {
|    <# PURE. A register / ring-release answer in words. Returns @{ Ok; Status; Reason; NotApproved }. #>
|    # -ImageOnly (framework SECURITY-NO-ASK-1): the call was image-only -- a 409 notApproved is said in Invardia's own fields
|    # (Format-SIInvardiaImageOnlyNotApproved), never as a release that needs an approval; -Version names its task (imageclaim:<v>)
|    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)][string]$What, [switch]$ImageOnly, [string]$Version = '')
|    $code = [int]$Response.Status
|    $j = $null; try { $j = "$($Response.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
|    $why = ''; if ($j -and -not ($j -is [string])) { foreach ($n in 'reason', 'error', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim()) { $why = "$($j.$n)".Trim(); break } } }
|    $o = { param($ok, $r, $na = $false) [pscustomobject]@{ Ok = $ok; Status = $code; Reason = $r; NotApproved = [bool]$na } }
|    $tail = if ($why) { ": $why" } else { '' }
|    # CR3: a 409 "notApproved" is said plainly -- never as "Invardia holds it already"
|    $na = Get-SIInvardiaNotApproved -Response $Response
|    if ($na.NotApproved) {
|        if ($ImageOnly) { $r = & $o $false (Format-SIInvardiaImageOnlyNotApproved -What $What -NotApproved $na -Version $Version) $true; $r | Add-Member -NotePropertyName ClaimRefused -NotePropertyValue ($na.OwnerAsked -eq $true) -Force; return $r }
|        return (& $o $false (Format-SIInvardiaNotApproved -What $What -Reason $na.Reason) $true)
|    }
|    # CR2: a 409 "healthHold" is said plainly too -- never as "Invardia holds it already"
|    $hh = Get-SIInvardiaHealthHold -Response $Response
|    if ($hh.HealthHold) { return (& $o $false (Format-SIInvardiaHealthHold -What $What -Reason $hh.Reason -Holding $hh.Holding)) }
|    switch ($code) {
|        { $_ -in 200, 201, 202 } { return (& $o $true ("{0}: done (HTTP {1})" -f $What, $code)) }
|        401 { return (& $o $false ("{0}: Invardia did not accept the publisher token (401)" -f $What)) }
|        403 { return (& $o $false ("{0}: refused (403{1}) -- only SecurityInsight's publisher identity (Invardia.Publisher.securityinsight) may release SecurityInsight" -f $What, $tail)) }
|        404 { return (& $o $false ("{0}: Invardia does not hold that version (404{1}) -- publish / register it first" -f $What, $tail)) }
|        409 { return (& $o $false ("{0}: Invardia holds it already (409{1})" -f $What, $tail)) }
|        422 {
|            $f = @(); try { $f = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
|            return (& $o $false ("{0}: refused as invalid (422; fields: {1}){2}" -f $What, $(if ($f.Count) { $f -join ', ' } else { 'none named' }), $tail))
|        }
|        0 { return (& $o $false ("{0}: Invardia could not be reached: {1}" -f $What, (Hide-SIInvardiaSecret "$($Response.Body)"))) }
|        default { return (& $o $false ("{0}: Invardia answered {1}{2}" -f $What, $code, $tail)) }
|    }
|}
|
|function Test-SIInvardiaScopesRecorded {
|    <#
|        PURE. CR3 READ-BACK: did Invardia record the changedScopes a publish / ring call sent (-Sent: the comma text sent, ''
|        = none sent)? Invardia answers a call it took with the list it stored (`changedScopes` in the 201 body) and leaves the
|        key out when it stored nothing. Returns @{ Sent; Recorded; Line }: Recorded $true = the answer names the same ids,
|        $false = sent but not in the answer (said plainly -- never a silent null at Invardia), $null = nothing was sent.
|    #>
|    param([Parameter(Mandatory)]$Response, [AllowEmptyString()][string]$Sent = '')
|    $want = @("$Sent".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
|    if (-not $want.Count) { return [pscustomobject]@{ Sent = $false; Recorded = $null; Line = '' } }
|    $code = [int]$Response.Status
|    if ($code -notin 200, 201, 202) { return [pscustomobject]@{ Sent = $true; Recorded = $false; Line = '' } }
|    $j = $null; try { $j = "$($Response.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
|    $got = @(); if ($j -and -not ($j -is [string]) -and $j.PSObject.Properties['changedScopes']) { $got = @($j.changedScopes | ForEach-Object { "$_" }) }
|    if (-not $got.Count) {
|        return [pscustomobject]@{ Sent = $true; Recorded = $false
|            Line = ('WARNING: changedScopes was sent ({0}) but Invardia''s answer does not carry it -- Invardia did not record the changed components of this call' -f $(if ($want.Count -gt 5) { '{0} ids' -f $want.Count } else { $want -join ',' })) }
|    }
|    $same = (@($want | Sort-Object) -join ',') -eq (@($got | Sort-Object) -join ',')
|    [pscustomobject]@{ Sent = $true; Recorded = [bool]$same
|        Line = $(if ($same) { 'Invardia recorded the changed components: {0}' -f $(if ($got.Count -gt 5) { '{0} ids' -f $got.Count } else { $got -join ',' }) } else { 'WARNING: Invardia recorded other changed components than were sent (sent {0}, recorded {1})' -f ($want -join ','), ($got -join ',') }) }
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-InvardiaInstallId.ps1'] = @{ Sha256 = '9817b4a05b6021c91c6cd3bb75e61d25587364f0889a86801136e6f4270fe917'; Text = @'
|#Requires -Version 5.1
|<#
|    SecurityInsight -- THE INSTALL'S LASTING ID ON ITS CALLS TO INVARDIA (Invardia S16, agreed 2026-11-01; the same contract
|    PIM 3.0.14 runs).
|
|    THE ID. One per install: the Key Vault secret SI-InstallId -- the GUID the licence request (SI-LicenceRequest.ps1)
|    created ONCE, at the install's first knock, kept next to the licence and sent as the knock body's installId on every knock
|    since. It is what Invardia already knows the install by. An update, a restart or a new container never replaces it (it
|    lives in the install's Key Vault, not in the image or on a disk; a reinstall that keeps the vault keeps the id). It is
|    CREATED ONCE when missing -- by the licence knock and (Invardia 2026-11-01) by the uplink heartbeat job -- with the same
|    code (Resolve-SIInvardiaInstallId: a GUID, written, read back), and never rewritten. Every other caller only READS it.
|    No id stored / not readable / not a GUID = NO header and NO field -- never an empty, a placeholder or a made-up value
|    (a wrong id would lock the install key at Invardia).
|
|    NOT the anonymous telemetry id (Get-SITelemetryInstallId: <state>\install-id, or derived from the storage account in a
|    container). That one identifies nothing but "the same Community install as last time"; the two are never joined.
|
|    WHERE IT GOES:
|      header X-Invardia-Install-Id (lower-case GUID) on the manifest pull (SI-InvardiaUpdate.ps1 Request-SIInvardiaManifest)
|                                     and the licence knock (SI-LicenceRequest.ps1, POST /api/licence-requests);
|      field  InstallId on every IDENTIFIED uplink record -- heartbeat, run, guard (SI-TelemetrySend.ps1,
|                                     SI-Guard.ps1, SI-GuardHeal.ps1; the health record's own installId, SI-DataHealth.ps1);
|      never on the setup report (Kind setup), an anonymous record, the key claim, the licence pull, the install-run tracking
|      or the update-now signal.
|
|    PURE helpers, no network. PS 5.1 and 7.
|#>
|
|# The names are LITERALS inside each function (no $script: state): these functions are loaded by one script and called from
|# another's scope (an engine's own script, the updater), where a file-level variable would be empty.
|
|function ConvertTo-SIInvardiaInstallId {
|    <# PURE. A GUID (any case, trimmed) -> its lower-case 8-4-4-4-12 text; anything else ($null, '', '-', not a GUID) -> ''. #>
|    param([AllowNull()][object]$Value)
|    if ($null -eq $Value) { return '' }
|    $t = "$Value".Trim().ToLowerInvariant()
|    if ($t -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $t }
|    return ''
|}
|
|function Select-SIInvardiaFirstInstallId {
|    <#
|        PURE. FIRST WRITE WINS (Invardia 2026-11-01): from the versions of SI-InstallId (-Versions: objects with Value, Enabled,
|        Created, Version), the OLDEST ENABLED version that holds a GUID is the install's id -- whichever side wrote it. Order:
|        Created ascending, then the version id (ordinal) so two versions made in the same second are ordered the same way by
|        every reader. Returns @{ First (the id, lower-cased, '' = none); Newest (the newest enabled version's value as stored);
|        Count (enabled versions) }.
|    #>
|    param([AllowNull()][object[]]$Versions)
|    # a seam that hands back its list as ONE object (a List, an array in an array) is read as its items
|    $flat = foreach ($x in @($Versions)) { if ($x -is [System.Collections.IEnumerable] -and $x -isnot [string] -and $x -isnot [System.Collections.IDictionary]) { foreach ($y in $x) { $y } } else { $x } }
|    $en = @(@($flat) | Where-Object { $null -ne $_ -and -not ($_.PSObject.Properties['Enabled'] -and $_.Enabled -eq $false) })
|    $key = { param($x) $c = $x.Created; if ($c -is [datetime]) { $c.ToUniversalTime().Ticks } elseif ($null -ne $c -and "$c" -match '^\d+$') { [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc).AddSeconds([double]"$c").Ticks } else { [long]::MaxValue } }
|    $sorted = @($en | Sort-Object -Property @{ Expression = { & $key $_ } }, @{ Expression = { [string]$_.Version } })
|    $first = ''
|    foreach ($x in $sorted) { $g = ConvertTo-SIInvardiaInstallId $x.Value; if ($g) { $first = $g; break } }
|    [pscustomobject]@{ First = $first; Newest = $(if ($sorted.Count) { [string]$sorted[-1].Value } else { $null }); Count = $sorted.Count }
|}
|
|function Get-SIInvardiaKvInstallIdVersions {
|    <#
|        The versions of a Key Vault secret over REST (engine\_shared\SI-AzRest.ps1, the run's own sign-in): GET
|        /secrets/<name>/versions (every page), then each enabled version's value (at most 50, oldest first, plus the newest).
|        Returns @(@{ Value; Enabled; Created; Version }); none (404) = @(). THROWS when the vault cannot be read -- a caller
|        never takes an unreadable vault for an empty one.
|    #>
|    param([Parameter(Mandatory)][string]$VaultName, [string]$Name = 'SI-InstallId')
|    $uri = 'https://{0}.vault.azure.net/secrets/{1}/versions?api-version=7.4&maxresults=25' -f $VaultName, [uri]::EscapeDataString($Name)
|    $items = New-Object System.Collections.Generic.List[object]
|    $pages = 0
|    while ($uri -and $pages -lt 20) {
|        $pages++
|        $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -What ("the versions of Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
|        if (-not $r) { break }
|        $j = $r.Content | ConvertFrom-Json
|        foreach ($v in @($j.value)) { if ($v) { $items.Add($v) } }
|        $uri = if ($j.PSObject.Properties['nextLink'] -and "$($j.nextLink)" -match '^https://') { [string]$j.nextLink } else { $null }
|    }
|    $rows = @($items | ForEach-Object {
|        $ver = ([string]$_.id).TrimEnd('/').Split('/')[-1]
|        [pscustomobject]@{ Value = $null; Enabled = -not ($_.attributes -and $_.attributes.enabled -eq $false); Created = $(if ($_.attributes) { $_.attributes.created } else { $null }); Version = $ver }
|    } | Where-Object { $_.Enabled })
|    $order = @($rows | Sort-Object -Property @{ Expression = { if ("$($_.Created)" -match '^\d+$') { [double]"$($_.Created)" } else { [double]::MaxValue } } }, @{ Expression = { [string]$_.Version } })
|    $want = @($order | Select-Object -First 50) + @($order | Select-Object -Last 1)
|    $seen = @{}
|    foreach ($x in $want) {
|        if ($seen.ContainsKey([string]$x.Version)) { continue }; $seen[[string]$x.Version] = $true
|        # only the versions that can decide: the 50 oldest (the first GUID is among them) and the newest (the converge check)
|        $raw = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name -Version $x.Version
|        if ($raw) { $x.Value = [string]$raw.value }
|    }
|    # one object per version (an empty vault returns nothing): callers wrap the call in @()
|    return $order
|}
|
|function Get-SIInvardiaInstallId {
|    <#
|        This install's lasting id, READ ONLY. With -ReadVersions { param($Name) } (the versions of SI-InstallId): the OLDEST
|        enabled version holding a GUID (first write wins); when the versions cannot be read, the current value through
|        -ReadSecret { param($Name) }. A GUID comes back lower-cased; none / not a GUID / the read failed -> ''. Never creates
|        it, never throws.
|    #>
|    param([scriptblock]$ReadSecret, [scriptblock]$ReadVersions)
|    if ($ReadVersions) {
|        try { $p = Select-SIInvardiaFirstInstallId -Versions @(& $ReadVersions 'SI-InstallId'); if ($p.First -or $p.Count) { return $p.First } } catch { }
|    }
|    if (-not $ReadSecret) { return '' }
|    $v = $null
|    try { $v = & $ReadSecret 'SI-InstallId' } catch { return '' }
|    return (ConvertTo-SIInvardiaInstallId $v)
|}
|
|function Resolve-SIInvardiaInstallId {
|    <#
|        Invardia 2026-11-01 (S16, answer 2): the lasting id, CREATED ONCE when it is missing -- by the licence knock and by the
|        uplink (heartbeat) job, with the same code and format: [guid]::NewGuid().ToString(), written to SI-InstallId.
|          * FIRST WRITE WINS (-ReadVersions): the id is the OLDEST enabled version of SI-InstallId that holds a GUID
|            (Select-SIInvardiaFirstInstallId), whichever side wrote it. A side that just wrote reads back the same way, so
|            when the knock and the uplink create at once both send the first value. When a later version holds ANOTHER GUID
|            (the losing write of such a race), the first value is written once more as the current version, so a plain read
|            (the engines' status reports) gives the same id -- the id itself never changes. One version (every install
|            before a race) behaves exactly as a plain read.
|          * without -ReadVersions, or when the versions cannot be read: the current value (-ReadSecret), as before;
|          * a stored GUID is KEPT (returned lower-cased) -- never replaced by another id;
|          * a stored value that is not a GUID is left as it is and '' comes back, unless -ReplaceNotGuid (the knock's rule
|            since #239: its body needs a GUID);
|          * the vault cannot be read or written -> '' (no id this time), never a throw.
|        -ReadSecret { param($Name) } / -WriteSecret { param($Name, $Value) } / -ReadVersions { param($Name) } -> @(@{ Value;
|        Enabled; Created; Version }).
|    #>
|    param([scriptblock]$ReadSecret, [scriptblock]$WriteSecret, [scriptblock]$ReadVersions, [switch]$ReplaceNotGuid)
|    if ($ReadVersions) {
|        $pick = { Select-SIInvardiaFirstInstallId -Versions @(& $ReadVersions 'SI-InstallId') }
|        $p = $null
|        try { $p = & $pick } catch { $p = $null }
|        if ($null -ne $p) {
|            $converge = {
|                param($sel)
|                $nw = ConvertTo-SIInvardiaInstallId $sel.Newest
|                if ($WriteSecret -and $sel.First -and $nw -and $nw -ne $sel.First) { try { $null = & $WriteSecret 'SI-InstallId' $sel.First } catch { } }
|            }
|            if ($p.First) { & $converge $p; return $p.First }
|            if ($null -ne $p.Newest -and "$($p.Newest)".Trim() -and -not $ReplaceNotGuid) { return '' }
|            if (-not $WriteSecret) { return '' }
|            $new = [guid]::NewGuid().ToString()
|            try { $null = & $WriteSecret 'SI-InstallId' $new } catch { return '' }
|            try { $p = & $pick } catch { return '' }
|            if ($p.First) { & $converge $p }
|            return [string]$p.First
|        }
|        # the versions could not be read: the plain read below (as before)
|    }
|    if (-not $ReadSecret) { return '' }
|    $v = $null
|    try { $v = & $ReadSecret 'SI-InstallId' } catch { return '' }
|    $have = ConvertTo-SIInvardiaInstallId $v
|    if ($have) { return $have }
|    if ($null -ne $v -and "$v".Trim() -and -not $ReplaceNotGuid) { return '' }
|    if (-not $WriteSecret) { return '' }
|    $new = [guid]::NewGuid().ToString()
|    try { $null = & $WriteSecret 'SI-InstallId' $new } catch { return '' }
|    $back = $null
|    try { $back = & $ReadSecret 'SI-InstallId' } catch { return '' }
|    return (ConvertTo-SIInvardiaInstallId $back)
|}
|function Add-SIInvardiaInstallIdHeader {
|    <# PURE. -Headers with X-Invardia-Install-Id = -InstallId added when it is a GUID (lower-case); unchanged otherwise. #>
|    param([AllowNull()][System.Collections.IDictionary]$Headers, [AllowNull()][AllowEmptyString()][string]$InstallId = '')
|    $h = if ($null -ne $Headers) { $Headers } else { @{} }
|    $iid = ConvertTo-SIInvardiaInstallId $InstallId
|    if ($iid) { $h['X-Invardia-Install-Id'] = $iid }
|    return $h
|}
|
|function Add-SIUplinkInstallId {
|    <#
|        PURE (sets one field). An IDENTIFIED uplink record with -FieldName (default InstallId, the name PIM 3.0.14 sends) =
|        -InstallId, lower-cased. Unchanged when the id is not a GUID, when the record is a setup report (Kind / kind 'setup'),
|        or when it is $null. The caller decides identified vs anonymous: an anonymous record is never passed here.
|    #>
|    param([AllowNull()][object]$Record, [AllowNull()][AllowEmptyString()][string]$InstallId = '', [string]$FieldName = 'InstallId')
|    if ($null -eq $Record) { return $Record }
|    $iid = ConvertTo-SIInvardiaInstallId $InstallId
|    if (-not $iid) { return $Record }
|    if ($Record -is [System.Collections.IDictionary]) {
|        foreach ($k in 'Kind', 'kind') { if ($Record.Contains($k) -and "$($Record[$k])" -eq 'setup') { return $Record } }
|        $Record[$FieldName] = $iid
|        return $Record
|    }
|    $kp = $Record.PSObject.Properties['Kind']
|    if ($kp -and "$($kp.Value)" -eq 'setup') { return $Record }
|    $Record | Add-Member -NotePropertyName $FieldName -NotePropertyValue $iid -Force
|    return $Record
|}
'@ }
$__siLauncherFiles['engine/_shared/SI-InvardiaUpdateKeys.json'] = @{ Sha256 = 'df34af77594ad139e018fc08d6bcd909442f5c9bfccad4c71a26e4bee7c42a02'; Text = @'
|{
|  "_comment": "SecurityInsight Pro -- the TRUSTED update-signing public keys. A manifest from Invardia is used only when its RS256 signature verifies against one of these, chosen by the manifest answer's keyId (exact string). Only PUBLIC keys are here; rotation = Invardia sends a new key, it is added here (old and new side by side) and shipped, then the old one is removed. A key list fetched at run time (GET /api/updates/keys) is never trusted on its own: a key is trusted only when it is in this file, which ships with the release. An empty list refuses every manifest. Entry forms: { keyId, certificateB64 (+ thumbprint, checked) } | { keyId, jwk: { kty: 'RSA', n, e } } | { keyId, publicKeyPem } | { keyId, modulus, exponent }.",
|  "keys": [
|    {
|      "keyId": "https://kv-invardia-gml64wkoe7np.vault.azure.net/keys/invardia-updates",
|      "subject": "CN=Invardia-Updates",
|      "thumbprint": "DDFF1C84 930C290E CF234FB4 C3F3C1D5 B3F532F2",
|      "notAfter": "2036-10-04T06:44:22Z",
|      "keySize": 4096,
|      "certificateB64": "MIIFPDCCAySgAwIBAgIQD6Em4umvSvOjQSdU0fjtejANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExBJbnZhcmRpYS1VcGRhdGVzMB4XDTI2MTAwNDA2MzQyMloXDTM2MTAwNDA2NDQyMlowGzEZMBcGA1UEAxMQSW52YXJkaWEtVXBkYXRlczCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALSw65TKtXrdx97yKJnI6JIRV35JMmmFU9hfgQcixpPD2u5aze8XfudwGyd5Hqr9GWUkBv1dKyhcW7eW9Ju2EzSmwVF77ICyxUEG6Lg7vgJvvG5czQYyMgyqECmCmGmHwmy9043Ype0Q+aRTVekLd8FueI84TxJsgK69sUY1VDoNlmEHvQqQ/6XevsMPXRZRkMLU/1Sby7NMXF7CZIrX8XubSez1fAVCqA6VyUDZeo9jOoqiC8QLowcRQd/3xhxH6KAyRlrtY5Kqdpltsl6LbP92bSlJZwJsADUDQLFVgMS6vvGy8um91UyLzDFsPScmbmwYVPDq4ltzgSiujtpOQlf/juW9M3/02kEq+uDKtlT7SpM2NcHohUZcA8xH6vmoi86/h1sdbQeN0BCEjaAZK3YQvhvcIwkEYFkqCDVm5y/vthzp8HYr0/RkWid/DJ4PYKj3azxX67+rdmSJ+oOV/Rjs/7mtRYtFsn0SdSAs80IIorwdGwXZVLcX1fPW9E18CE/Scp1e1WEvbr+R+eiF6XLg2lsyLnqum1ZVqpOqfnBDL4gyjHWjBNyVv0PqjQQhdUPnAgBpduvSrRVkLdmi1Nn+dCZMFvIebJWNSNOT12yWl9up/mbvaXa6vrrN5WvA9b/1fXobEdrOl4+HCmUWQFEXebreNkfIexCHuyteynmRAgMBAAGjfDB6MA4GA1UdDwEB/wQEAwIHgDAJBgNVHRMEAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBRxu9RZeaRO8csDZ5RtYFCokSdNsTAdBgNVHQ4EFgQUcbvUWXmkTvHLA2eUbWBQqJEnTbEwDQYJKoZIhvcNAQELBQADggIBADL2qxoN9PoCk58d9lM9rZxgib6Qgy441k+xbKifFtlu6E3ty2YRMEMmalH390JUp/mTNkAEZ6NTnqHEnHVRdR95mQv2dkggnQnlFZXh94ngcEoiu+a8q9m7c9Yjp+pZt9HV9nGdymL2/OPla98zS6hYtAGamvwqt/6TW5dshjYA+SOCquEMd6WkIY0/cpkeUoExc1vm8iFv9Q+mJZOZH2t/v9SwICa7WsqzPZIiI3hWE1Ra1gUywC5CsJ9HYyjfxIIGw0LR46Xp7n09Qy25GM62yazkvQb6BvchFhhqgHP07ThuyhLPzIqqjX2l1xxN5n4GT1sjavT98aTj/DojqhYlcKumX0KUvnAzfnGkHmaAN0/C3AeuLmJ/iYG9SRENIvCYVDypFFXYtHB1XeLTt8DX7W2GhEjp5cPg+LYJtBU4qPQ5VZ8kZCAlkP4mkHezCYsvKpN2E9IBGtV28t1Fo0T+6l6HVkBWiYXvlzdqZWGf7mnUUi5oLUaHuezAJTMIkmrgiVjnAD/2NquusQKauajhOf4qCDdIzNcVqgUoDFhoBnoG6wvBdCxiPrhdrY6XsRHUBCFnduERlY5x0/tc/OuPGbJ58kL3YI6SkhBssSz5lh+ObzegVSgTDzb9jbQhk3qfObWWqP7a4hXOxWUlRO3BuYbv3puRPHzD73qsZV7Y"
|    }
|  ]
|}
'@ }
$ErrorActionPreference = 'Stop'

$siOwn = @('Version', 'KeepDownload', 'LauncherSeams')
$seam = @{}; if ($LauncherSeams) { foreach ($k in @($LauncherSeams.Keys)) { $seam[[string]$k] = $LauncherSeams[$k] } }

# ---- the version line: first, before anything else is printed ----
$selfVersion = "$__siLauncherVersion".Trim()
if (-not $selfVersion -and $PSScriptRoot) {
    $vf = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'VERSION')
    if ([IO.File]::Exists($vf)) { $selfVersion = ([IO.File]::ReadAllText($vf)).Trim() }
}
if (-not $selfVersion) { $selfVersion = 'unknown (not a released copy)' }
Write-Host ('Install-SecurityInsight launcher {0}' -f $selfVersion)
$isPro = ("$script:SIInstallChannel" -eq 'pro')
$editionName = if ($isPro) { 'SecurityInsight Pro' } else { 'SecurityInsight Community' }
Write-Host ('Installs {0}: the release Invardia has signed for your update ring. Documentation: https://invardia.com/docs/si/scripts/Install-SecurityInsight/' -f $editionName)

function Get-SILauncherNotePath {
    <# Where the note that remembers the download folder lives: Cloud Shell's clouddrive, else the user profile. #>
    param([string]$NoteDir)
    if ("$NoteDir".Trim()) { return [IO.Path]::Combine($NoteDir, 'securityinsight-launcher.json') }
    $h = $HOME; if (-not $h) { $h = [Environment]::GetFolderPath('UserProfile') }
    $cd = [IO.Path]::Combine($h, 'clouddrive')
    if ([IO.Directory]::Exists($cd)) { return [IO.Path]::Combine($cd, 'invardia', 'securityinsight-launcher.json') }
    [IO.Path]::Combine($h, '.invardia', 'securityinsight-launcher.json')
}

function Read-SILauncherNote {
    param([string]$Path)
    $o = @{}
    if (-not [IO.File]::Exists($Path)) { return $o }
    try {
        $j = [IO.File]::ReadAllText($Path) | ConvertFrom-Json
        foreach ($p in @($j.PSObject.Properties)) { $o[$p.Name] = $p.Value }
    } catch { }
    $o
}

function Write-SILauncherNote {
    <# The note: per install id, the download folder and its version only -- never a parameter, never a secret. #>
    param([string]$Path, [hashtable]$Note)
    $d = [IO.Path]::GetDirectoryName($Path)
    if (-not [IO.Directory]::Exists($d)) { [void][IO.Directory]::CreateDirectory($d) }
    [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $Note -Depth 4), (New-Object System.Text.UTF8Encoding($false)))
}

function Find-SILauncherTree {
    <#
        The release tree in an unpacked folder: setup/Install-SecurityInsight.ps1 at its top, or in its one sub-folder (the
        GitHub release), or in that sub-folder's SOLUTIONS/SecurityInsight (the Pro package Invardia serves: a git archive,
        top folder securityinsight-src-<version>/).
    #>
    param([string]$Dir)
    if (-not $Dir -or -not [IO.Directory]::Exists($Dir)) { return '' }
    if ([IO.File]::Exists([IO.Path]::Combine($Dir, 'setup', 'Install-SecurityInsight.ps1'))) { return $Dir }
    $tops = @([IO.Directory]::GetDirectories($Dir))
    if ($tops.Count -ne 1) { return '' }
    if ([IO.File]::Exists([IO.Path]::Combine($tops[0], 'setup', 'Install-SecurityInsight.ps1'))) { return $tops[0] }
    $nested = [IO.Path]::Combine($tops[0], 'SOLUTIONS', 'SecurityInsight')
    if ([IO.File]::Exists([IO.Path]::Combine($nested, 'setup', 'Install-SecurityInsight.ps1'))) { return $nested }
    ''
}

function Test-SILauncherZip {
    <#
        The checks of a downloaded release zip, before anything is unpacked. Returns '' when it is good, else the reason in
        plain words: empty, not the size or SHA-256 the release states, no SHA-256 stated at all, not a zip, no
        setup/Install-SecurityInsight.ps1, or a VERSION that is not the release's version. -AllowBuildNumber (both editions:
        one version format): a release named <VERSION>.<build number> carries the code of VERSION -- the rule SecurityInsight's
        updater applies. A download is used only when its SHA-256 matches the one the release states.
    #>
    param([string]$Path, [string]$Version, [long]$Size = 0, [string]$Sha256 = '', [switch]$AllowBuildNumber)
    if (-not [IO.File]::Exists($Path)) { return 'the download did not complete (no file)' }
    $len = (New-Object IO.FileInfo($Path)).Length
    if ($len -le 0) { return 'the download is empty (0 bytes)' }
    if ($Size -gt 0 -and $len -ne $Size) { return ('the download has {0} bytes, the release states {1}' -f $len, $Size) }
    $want = "$Sha256".Trim().ToLowerInvariant()
    if ($want -notmatch '^[0-9a-f]{64}$') { return 'the release states no SHA-256 for the download, so it cannot be checked' }
    $sha = [System.Security.Cryptography.SHA256]::Create(); $fs = [IO.File]::OpenRead($Path)
    try { $got = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $fs.Dispose(); $sha.Dispose() }
    if ($got -ne $want) { return ('the download''s SHA-256 is {0}, the release states {1}' -f $got, $want) }
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($Path) } catch { return 'the download is not a zip that opens' }
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
        $inst = @($names | Where-Object { $_ -match '^([^/]+/)?(SOLUTIONS/SecurityInsight/)?setup/Install-SecurityInsight\.ps1$' } | Sort-Object { $_.Length })
        if (-not $inst.Count) { return 'the zip holds no setup/Install-SecurityInsight.ps1' }
        $prefix = ($inst[0] -replace 'setup/Install-SecurityInsight\.ps1$', '')
        $ve = @($zip.Entries | Where-Object { $_.FullName.Replace('\', '/') -eq ($prefix + 'VERSION') })
        if (-not $ve.Count) { return 'the zip holds no VERSION file' }
        $r = New-Object IO.StreamReader($ve[0].Open())
        try { $zv = $r.ReadToEnd().Trim() } finally { $r.Dispose() }
        $want = "$Version".Trim().TrimStart('v', 'V')
        $same = ($zv -eq $want) -or ($AllowBuildNumber -and $zv -and $want -match ('^' + [regex]::Escape($zv) + '\.\d{1,14}$'))
        if (-not $same) { return ('the zip''s VERSION says {0}, the release is {1}' -f $zv, $want) }
    } finally { $zip.Dispose() }
    ''
}

function Expand-SILauncherZip {
    <# Unpacks the zip into -To, entry by entry: an entry that would land outside -To is refused. #>
    param([string]$Path, [string]$To)
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $root = [IO.Path]::GetFullPath($To).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    [void][IO.Directory]::CreateDirectory($root)
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        foreach ($e in $zip.Entries) {
            $rel = $e.FullName.Replace('\', '/')
            $dest = [IO.Path]::GetFullPath([IO.Path]::Combine($root, $rel.Replace('/', [string][IO.Path]::DirectorySeparatorChar)))
            if (-not $dest.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw ('the zip entry {0} points outside the folder' -f $e.FullName) }
            if ($rel.EndsWith('/')) { [void][IO.Directory]::CreateDirectory($dest); continue }
            $dd = [IO.Path]::GetDirectoryName($dest)
            if (-not [IO.Directory]::Exists($dd)) { [void][IO.Directory]::CreateDirectory($dd) }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dest, $true)
        }
    } finally { $zip.Dispose() }
}

function Set-SILauncherEditionStamp {
    <#
        The channel to the full installer: the unpacked setup/Install-SecurityInsight.ps1 carries ONE constant line,
        $siEditionStamp = 'community'. The Pro channel writes 'pro' into that line of the unpacked copy (the same one-line
        change the build makes for Invardia's copy). Returns '' when done, else the reason.
    #>
    param([string]$Path, [ValidateSet('pro', 'community')][string]$Edition)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $bom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $text = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes, $(if ($bom) { 3 } else { 0 }), $bytes.Length - $(if ($bom) { 3 } else { 0 }))
    $rx = '(?m)^\$siEditionStamp = ''[a-z]*''(?=\r?$)'
    $n = [regex]::Matches($text, $rx).Count
    if ($n -ne 1) { return ('the installer holds its edition line {0} times, not once' -f $n) }
    $text = [regex]::Replace($text, $rx, ('$siEditionStamp = ''{0}''' -f $Edition))
    [IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($bom)))
    ''
}

function Get-SILauncherResumeDecision {
    <#
        PURE. Framework INSTALL-1 / installer rule 12 (owner 2026-11-04: "-Resume never reuses a different package"): on
        -Resume the release downloaded before (-Note: the launcher's note { path; folder; version; channel }, -TreePath: its
        installer folder when it is still there) is used again ONLY when it is the SAME edition (-Edition: 'pro' |
        'community', the note's channel) AND the same version this launcher installs now (-Version). Anything else -- another
        edition, an older or a newer release, the folder gone -- is downloaded afresh, said in ONE line; the install itself
        continues from its OWN saved progress (its state folder). Returns @{ Reuse; Line }.
    #>
    param($Note, [string]$TreePath = '', [Parameter(Mandatory)][string]$Edition, [AllowEmptyString()][string]$Version = '')
    $label = { param($e) if ("$e" -eq 'pro') { 'Pro' } elseif ("$e" -eq 'community') { 'Community' } elseif ("$e") { "$e" } else { 'of an unknown edition' } }
    $nowV = "$Version".Trim().TrimStart('v', 'V')
    if (-not $Note -or -not "$($Note.path)".Trim() -or -not "$TreePath".Trim()) {
        return @{ Reuse = $false; Line = ('Resume: the release folder of the first run is not there any more, so the release ({0} {1}) is downloaded again. The install keeps its own progress, so it still continues where it stopped.' -f $nowV, (& $label $Edition)) }
    }
    $prevV = "$($Note.version)".Trim().TrimStart('v', 'V'); $prevE = "$($Note.channel)".Trim()
    if ($prevE -eq $Edition -and $prevV -and $prevV -eq $nowV) {
        return @{ Reuse = $true; Line = ('Resume: using the release {0} {1} downloaded before, in {2} -- it is the release this launcher installs, so nothing is downloaded.' -f $prevV, (& $label $prevE), $TreePath) }
    }
    @{ Reuse = $false; Line = ('Resume: the release downloaded before is {0} {1}; this launcher installs {2} {3} -- downloading it. The install continues from its own saved progress.' -f $(if ($prevV) { $prevV } else { '(unknown version)' }), (& $label $prevE), $nowV, (& $label $Edition)) }
}

function Get-SILauncherPassThrough {
    <# PURE. The parameters for the full installer: every one given, unchanged, except the launcher's own. #>
    param([System.Collections.IDictionary]$Bound, [string[]]$Own = @('Version', 'KeepDownload', 'LauncherSeams'))
    $a = @{}
    foreach ($k in @($Bound.Keys)) { if ([string]$k -notin $Own) { $a[[string]$k] = $Bound[$k] } }
    $a
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE RELEASE OF THE RING, from Invardia -- one path for Pro and Community (framework PRO-COMMUNITY-SAME)
# ---------------------------------------------------------------------------------------------------------------------
function Get-SILauncherPackageUrl {
    <#
        PURE. Where the launcher asks Invardia for the release of the ring -- the address is the ONE difference between the
        editions. Pro: the Pro package route (tenantId always, ring only when one is asked for: Invardia's default is ring 3).
        Community: the Community release of the ring (<base>/api/updates/securityinsight/community/<ring>; ring 3 when none
        is asked for).
    #>
    param([string]$BaseUrl = 'https://invardia.com', [string]$TenantId, [int]$Ring = -1, [ValidateSet('pro', 'community')][string]$Edition = 'pro')
    if ($Edition -eq 'community') { return ('{0}/api/updates/securityinsight/community/{1}' -f "$BaseUrl".Trim().TrimEnd('/'), $(if ($Ring -ge 0) { $Ring } else { 3 })) }
    if (-not "$TenantId".Trim()) { throw 'Get-SILauncherPackageUrl: the Pro package route needs -TenantId' }
    $u = '{0}/api/install/securityinsight/package?tenantId={1}' -f "$BaseUrl".Trim().TrimEnd('/'), [uri]::EscapeDataString("$TenantId".Trim())
    if ($Ring -ge 0) { $u += ('&ring={0}' -f $Ring) }
    $u
}

function Get-SILauncherRouteRefusal {
    <#
        PURE. Why Invardia did not hand out the release of the ring, in plain words: Invardia's own message ({ error, message }) with
        the status and its error code, else a sentence of our own for the status. Never the token.
    #>
    param([int]$Status, [AllowEmptyString()][AllowNull()][string]$Body, [AllowEmptyString()][AllowNull()][string]$ErrorText,
          [ValidateSet('pro', 'community')][string]$Edition = 'pro')
    if ($Status -eq 0) { return ('Invardia could not be reached ({0}) -- check the network (invardia.com) and run the same command again' -f $(if ("$ErrorText".Trim()) { "$ErrorText".Trim() } else { 'no answer' })) }
    $j = $null
    if ("$Body".Trim()) { try { $j = "$Body" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
    $err = ''; $msg = ''
    if ($j -and $j.PSObject.Properties['error']) { $err = "$($j.error)".Trim() }
    if ($j -and $j.PSObject.Properties['message']) { $msg = ("$($j.message)" -replace '\s+', ' ').Trim() }
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 297) + '...' }
    if (-not $msg) {
        $msg = switch ($Status) {
            204 { 'nothing is released to this ring yet' }
            401 { 'Invardia did not accept the sign-in' }
            403 { 'the sign-in is for another tenant than -TenantId' }
            404 { if ($Edition -eq 'community') { 'Invardia has no SecurityInsight Community release for that ring' } else { 'this tenant has no Invardia environment with SecurityInsight, or nothing is released on that ring' } }
            422 { 'Invardia found the request not valid' }
            503 { 'Invardia cannot hand out packages right now' }
            default { 'Invardia answered {0}' -f $Status }
        }
    }
    $hint = switch ($err) {
        'noEnvironment'   { ' Ask Invardia to add SecurityInsight to this tenant''s environment, then run the same command again.' }
        'nothingReleased' { ' Choose another -UpdateRing, or wait until SecurityInsight is released to this ring.' }
        'wrongTenant'     { ' Sign in with an admin of the tenant -TenantId names.' }
        'notSignedIn'     { ' Run the same command again and complete the sign-in.' }
        default           { '' }
    }
    '{0} (HTTP {1}{2}).{3}' -f $msg.TrimEnd('.'), $Status, $(if ($err) { ", $err" } else { '' }), $hint
}

function Invoke-SILauncherPackageGet {
    <# GET the release route: Pro with the admin's ARM token, Community anonymous (-Token ''). Returns @{ Status (0 = no answer); Body; Error }; never
       throws, and the token is never in what it returns. #>
    param([Parameter(Mandatory)][string]$Url, [AllowEmptyString()][string]$Token = '', [int]$TimeoutSec = 60)
    $h = @{ Accept = 'application/json'; 'User-Agent' = 'SecurityInsight-Installer' }
    if ("$Token".Trim()) { $h['Authorization'] = 'Bearer ' + $Token }
    try {
        $r = Invoke-WebRequest -Method Get -Uri $Url -Headers $h -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        $c = $r.Content; if ($c -is [byte[]]) { $c = [System.Text.Encoding]::UTF8.GetString($c) }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$c; Error = '' }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = ''; Error = $(if ("$Token".Trim()) { ("$($_.Exception.Message)").Replace($Token, '<withheld>') } else { "$($_.Exception.Message)" }) } }
        $code = 0; try { $code = [int]$resp.StatusCode } catch { }
        $text = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $text = [string]$_.ErrorDetails.Message }
        elseif ($resp -is [System.Net.WebResponse]) { try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $text = $sr.ReadToEnd(); $sr.Close() } catch { } }
        return [pscustomobject]@{ Status = $code; Body = $text; Error = ('HTTP {0}' -f $code) }
    }
}

function Export-SILauncherCode {
    <#
        Writes the code the build embedded into this copy ($__siLauncherFiles: relative path -> @{ Sha256; Text, every line
        prefixed with '|' }) into -To with the package's own layout, and checks each file's SHA-256 first. Returns
        @{ Ok; Reason; Root; Count }. The same text rules as every standalone SecurityInsight script.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Files, [Parameter(Mandatory)][string]$To)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $n = 0
    try {
        foreach ($k in @($Files.Keys)) {
            $rel = "$k".Replace('\', '/')
            if ($rel -match '(^|/)\.\.(/|$)' -or $rel.StartsWith('/')) { return [pscustomobject]@{ Ok = $false; Reason = ('the embedded file {0} has no safe name' -f $k); Root = ''; Count = $n } }
            $lines = ([string]$Files[$k].Text -replace "`r", '') -split "`n"
            $body = (@($lines | ForEach-Object { if ($_.StartsWith('|')) { $_.Substring(1) } else { $_ } }) -join "`r`n") + "`r`n"
            $hash = -join ($sha.ComputeHash((New-Object System.Text.UTF8Encoding($false)).GetBytes($body)) | ForEach-Object { $_.ToString('x2') })
            if ($hash -ne [string]$Files[$k].Sha256) { return [pscustomobject]@{ Ok = $false; Reason = ('the embedded file {0} is damaged (SHA-256 mismatch) -- download the launcher again' -f $k); Root = ''; Count = $n } }
            $p = [IO.Path]::Combine($To, ($rel -replace '/', [string][IO.Path]::DirectorySeparatorChar))
            $d = [IO.Path]::GetDirectoryName($p)
            if (-not [IO.Directory]::Exists($d)) { [void][IO.Directory]::CreateDirectory($d) }
            [IO.File]::WriteAllText($p, $body, (New-Object System.Text.UTF8Encoding($rel -match '\.ps[dm]?1$')))
            $n++
        }
    } finally { $sha.Dispose() }
    [pscustomobject]@{ Ok = $true; Reason = ''; Root = $To; Count = $n }
}

function Connect-SILauncherAzure {
    <#
        The admin's sign-in (both editions: one sign-in that the installer takes over), with SecurityInsight's OWN setup sign-in (setup/_shared/SI-SetupAzure.ps1,
        loaded beside this): Azure Cloud Shell's token endpoint with no prompt, else the browser (authorization code + PKCE on
        localhost; never device code), or the Invardia Support session's tokens with -ViaSupportApp. The sign-in stays in
        THIS PowerShell process (memory only): the installer, started from here in the same process, finds it and uses it
        (it reuses a sign-in of the same tenant) -- the admin signs in once. Returns @{ TenantId; Account; Token } (Token =
        an access token for Azure Resource Manager, the one Invardia's Pro package route accepts).
    #>
    param([string]$TenantId, [string]$SubscriptionId)
    $ca = @{ ErrorAction = 'Stop' }
    if ("$TenantId".Trim()) { $ca['TenantId'] = "$TenantId".Trim() }
    if ("$SubscriptionId".Trim()) { $ca['SubscriptionId'] = "$SubscriptionId".Trim() }
    $ctx = Connect-SISetupAzure @ca
    $tok = [string](Get-SIAzureToken -Audience Arm)
    $tid = ''; $acct = ''
    if ($ctx) {
        if ($ctx.PSObject.Properties['Tenant'] -and $ctx.Tenant) { $tid = [string]$ctx.Tenant.Id }
        if ($ctx.PSObject.Properties['Account'] -and $ctx.Account) { $acct = [string]$ctx.Account.Id }
    }
    [pscustomobject]@{ TenantId = $tid; Account = $acct; Token = $tok }
}

function Test-SILauncherPackage {
    <#
        Invardia's answer for the release of the ring (-Kind code: the Pro package route; -Kind community: the Community
        release of the ring), checked EXACTLY as SecurityInsight's updater checks an update (the
        functions of engine/_shared/SI-InvardiaUpdate.ps1, loaded beside this -- no second implementation): the signature
        over the manifest against the trusted update-signing keys (Test-SIInvardiaManifestSignature), then the signed
        manifest itself -- product securityinsight, the kind asked for, the ring asked for, a version, SHA-256 and size
        (Test-SIInvardiaManifestContent). The unsigned fields of the answer must say what the signed manifest says, and the
        download link must be https. Returns @{ Ok; Reason; Manifest; Version; DownloadUrl; Sequence; Kind }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Body, [Parameter(Mandatory)][int]$Ring, [AllowNull()][object[]]$TrustedKeys, [ValidateSet('code', 'community')][string]$Kind = 'code')
    $no = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why; Manifest = $null; Version = ''; DownloadUrl = ''; Sequence = -1; Kind = $Kind } }
    $j = $null
    if ("$Body".Trim()) { try { $j = "$Body" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
    if (-not $j) { return (& $no 'Invardia''s answer is not JSON') }
    $p = { param($n) if ($j.PSObject.Properties[$n] -and $null -ne $j.$n) { [string]$j.$n } else { '' } }
    $sig = Test-SIInvardiaManifestSignature -ManifestB64 (& $p 'manifestB64') -Signature (& $p 'signature') -KeyId (& $p 'keyId') -TrustedKeys $TrustedKeys
    if (-not $sig.Ok) { return (& $no $sig.Reason) }
    $m = $sig.Manifest
    $chk = Test-SIInvardiaManifestContent -Manifest $m -Kind $Kind -Ring $Ring
    # 'hold' is a manual step an UPDATE of an existing install needs: a new install has nothing to step from
    if ($chk.Action -notin @('update', 'hold')) { return (& $no $chk.Reason) }
    foreach ($n in 'version', 'sha256', 'size', 'sequence') {
        $said = (& $p $n).Trim()
        $signed = $(if ($m.PSObject.Properties[$n]) { "$($m.$n)".Trim() } else { '' })
        if ($said -and $said.ToLowerInvariant() -ne $signed.ToLowerInvariant()) { return (& $no ("Invardia's answer names {0} {1}, its signed manifest {2}" -f $n, $said, $signed)) }
    }
    $dl = & $p 'downloadUrl'
    if ($dl -notmatch '^https://[^/\s]+/') { return (& $no 'Invardia''s answer carries no https download link') }
    [pscustomobject]@{ Ok = $true; Reason = ''; Manifest = $m; Version = "$($m.version)".Trim(); DownloadUrl = $dl; Sequence = $chk.Sequence; Kind = $Kind }
}

$code = 0
$dir = ''
$codeDir = ''
do {
    # ---- -ViaSupportApp needs the support session for THIS tenant: refused before anything is downloaded ----
    if ($ViaSupportApp) {
        $supState = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
        if (-not $supState) { Write-Host 'With -ViaSupportApp, run the install inside a Connect-InvardiaSupport session for this tenant. Nothing was downloaded or installed.' -ForegroundColor Red; $code = 3; break }
        if ("$TenantId".Trim() -and "$($supState.TenantId)".Trim() -ne "$TenantId".Trim()) { Write-Host ('The support session is for tenant {0}, not for -TenantId {1}: connect the session to this tenant first. Nothing was downloaded or installed.' -f $supState.TenantId, $TenantId) -ForegroundColor Red; $code = 3; break }
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5.1: Invardia and the download need TLS 1.2
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    }
    $runInstaller = $seam['RunInstaller']
    if (-not $runInstaller) { $runInstaller = { param([string]$Path, [hashtable]$Arguments) $global:LASTEXITCODE = 0; & $Path @Arguments | Out-Host; [int]$LASTEXITCODE } }
    $tempRoot = if ("$($seam['TempRoot'])".Trim()) { "$($seam['TempRoot'])" } else { [IO.Path]::GetTempPath() }
    $notePath = Get-SILauncherNotePath -NoteDir "$($seam['NoteDir'])"
    $noteKey = if ("$InstallId".Trim()) { "$InstallId".Trim().ToLowerInvariant() } else { 'securityinsight' }
    $steps = 5   # the same steps for both editions

    # ---- 1. -Resume: the folder of the first run -- used again ONLY when it is the release this launcher installs now ----
    # framework INSTALL-1 / installer rule 12 ("-Resume never reuses a different package", owner 2026-11-04): the release
    # downloaded before is reused only when it is the SAME edition AND the same version this launcher would install now
    # (Get-SILauncherResumeDecision, decided once the version is known below); otherwise it is downloaded afresh, said in
    # ONE line, and the install continues from its OWN saved progress (its state folder).
    $tree = ''; $treeVersion = ''; $resumeNote = $null; $resumeTree = ''; $reused = $false
    if ($Resume) {
        $note = Read-SILauncherNote -Path $notePath
        $resumeNote = $note[$noteKey]
        if ($resumeNote -and "$($resumeNote.path)".Trim()) { $resumeTree = [string](Find-SILauncherTree -Dir "$($resumeNote.path)") }
    }
    $useEarlier = {
        # the version this launcher installs now is known: reuse the earlier folder, or say why it is downloaded afresh
        param([string]$NowVersion)
        if (-not $Resume) { return $false }
        $d = Get-SILauncherResumeDecision -Note $resumeNote -TreePath $resumeTree -Edition "$script:SIInstallChannel" -Version $NowVersion
        Write-Host $d.Line -ForegroundColor $(if ($d.Reuse) { 'Gray' } else { 'Yellow' })
        if ($d.Reuse) { $script:SILauncherReuse = @{ Tree = $resumeTree; Version = "$($resumeNote.version)"; Folder = "$($resumeNote.folder)" } }
        [bool]$d.Reuse
    }

    if (-not $tree) {
        $zipPath = ''; $assetName = ''; $relVersion = ''; $stated = ''; $statedSize = 0L
        # ======== ONE path for both editions (framework PRO-COMMUNITY-SAME): the signed release of the ring, from Invardia ========
        # Pro and Community take the same steps: sign in, ask Invardia for the release its ring serves, check the signed
        # manifest with the updater's own code, download, check size + SHA-256, run the installer. The address and the
        # credential are the only difference: Pro asks the Pro package route with the admin's sign-in; Community reads the
        # Community manifest of the ring (anonymous) and downloads the public release zip the signed manifest names.
        $edition = "$script:SIInstallChannel"
        if ("$Version".Trim()) { Write-Host ('-Version {0} is not used: {1} installs the release Invardia serves to its update ring.' -f "$Version".Trim(), $editionName) -ForegroundColor Yellow }
        # the code this launcher uses: embedded in this copy, else the package this file stands in
        $codeRoot = ''
        if ($__siLauncherFiles.Count) {
            $codeDir = [IO.Path]::Combine($tempRoot, ('securityinsight-launcher-code-' + [guid]::NewGuid().ToString('N').Substring(0, 8)))
            $ex = Export-SILauncherCode -Files $__siLauncherFiles -To $codeDir
            if (-not $ex.Ok) { Write-Host ('This launcher cannot be used: {0}. Nothing was downloaded or installed.' -f $ex.Reason) -ForegroundColor Red; $code = 3; break }
            $codeRoot = $ex.Root
        } elseif ("$($seam['CodeRoot'])".Trim()) {
            $codeRoot = "$($seam['CodeRoot'])".Trim()
        } elseif ($PSScriptRoot) {
            $pkg = Split-Path -Parent $PSScriptRoot
            if ([IO.File]::Exists([IO.Path]::Combine($pkg, 'engine', '_shared', 'SI-InvardiaUpdate.ps1'))) { $codeRoot = $pkg }
        }
        if (-not $codeRoot) { Write-Host ('This copy of the launcher carries no SecurityInsight sign-in and package check, so it cannot install {0}. Download it again ({1}). Nothing was downloaded or installed.' -f $editionName, $(if ($isPro) { 'https://invardia.com/support/si/Install-SecurityInsight.ps1' } else { 'https://github.com/KnudsenMorten/SecurityInsight/releases/latest/download/Install-SecurityInsight.ps1' })) -ForegroundColor Red; $code = 3; break }
        $loads = @('engine/_shared/SI-InvardiaUpdate.ps1')
        if (-not $seam['SignIn']) { $loads = @('setup/_shared/SI-SetupAzure.ps1') + $loads }
        $loadFailed = ''
        foreach ($__rel in $loads) {
            $__siLauncherLoad = [IO.Path]::Combine($codeRoot, ($__rel -replace '/', [string][IO.Path]::DirectorySeparatorChar))
            try { . $__siLauncherLoad } catch { $loadFailed = ('{0}: {1}' -f $__rel, $_.Exception.Message); break }
        }
        if ($loadFailed) { Write-Host ('This launcher cannot be used: its code did not load ({0}). Nothing was downloaded or installed.' -f $loadFailed) -ForegroundColor Red; $code = 3; break }
        # tests only: the REST layer's ONE HTTP call (Invoke-SIAzRestHttp) answered by the test -- the sign-in is still SecurityInsight's own
        if ($seam['RestHttp']) { Set-Item -Path 'function:script:Invoke-SIAzRestHttp' -Value $seam['RestHttp'] }

        # ---- 1. sign in (once: the installer takes this sign-in over) ----
        Write-Host ('Step 1 of {0}: signing in to Azure{1} -- the installer uses this sign-in, so you sign in once' -f $steps, $(if ("$TenantId".Trim()) { ' (tenant {0})' -f "$TenantId".Trim() } else { '' }))
        $signIn = $seam['SignIn']
        if (-not $signIn) { $signIn = { param([string]$T, [string]$S) Connect-SILauncherAzure -TenantId $T -SubscriptionId $S } }
        $who = $null; $signInWhy = ''
        try { $who = & $signIn "$TenantId".Trim() "$SubscriptionId".Trim() } catch { $signInWhy = "$($_.Exception.Message)" }
        if (-not $who -or -not "$($who.Token)".Trim()) {
            Write-Host ('The Azure sign-in did not complete{0}. Nothing was downloaded or installed. Run the same command again and complete the sign-in (in Azure Cloud Shell it is automatic; on a workstation a browser window opens).' -f $(if ($signInWhy) { ': ' + $signInWhy } else { '' })) -ForegroundColor Red
            $code = 3; break
        }
        $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { "$($who.TenantId)".Trim() }
        if ($tid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { Write-Host 'The tenant is not known: give -TenantId (the tenant id, a GUID). Nothing was downloaded or installed.' -ForegroundColor Red; $code = 3; break }
        if ("$($who.Account)".Trim()) { Write-Host ('  signed in as {0} (tenant {1})' -f "$($who.Account)".Trim(), $tid) }

        # ---- 2. ask Invardia for the release of the ring ----
        $ringAsked = if ($PSBoundParameters.ContainsKey('UpdateRing')) { [int]$UpdateRing } else { -1 }
        $ringSigned = if ($ringAsked -ge 0) { $ringAsked } else { 3 }   # the default ring: a new install never starts ahead of its ring
        $url = Get-SILauncherPackageUrl -TenantId $tid -Ring $ringAsked -Edition $edition
        Write-Host ('Step 2 of {0}: asking Invardia for the {1} release of ring {2}{3}' -f $steps, $editionName, $ringSigned, $(if ($ringAsked -lt 0) { ' (the default)' } else { '' }))
        $getPackage = $seam['GetPackage']
        if (-not $getPackage) { $getPackage = { param([string]$Url, [string]$Token) Invoke-SILauncherPackageGet -Url $Url -Token $Token } }
        # Pro: the admin's ARM token (Invardia hands the Pro package only to a signed-in admin of the tenant); Community: anonymous
        $bearer = if ($isPro) { "$($who.Token)" } else { '' }
        $ans = $null
        try { $ans = & $getPackage $url $bearer } catch { $ans = [pscustomobject]@{ Status = 0; Body = ''; Error = "$($_.Exception.Message)" } }
        $who = $null; $bearer = ''   # the token is not kept by the launcher (the sign-in itself stays in the process for the installer)
        if (-not $ans -or [int]$ans.Status -ne 200) {
            $why = Get-SILauncherRouteRefusal -Status $(if ($ans) { [int]$ans.Status } else { 0 }) -Body $(if ($ans) { [string]$ans.Body } else { '' }) -ErrorText $(if ($ans -and $ans.PSObject.Properties['Error']) { [string]$ans.Error } else { '' }) -Edition $edition
            Write-Host ('Invardia did not hand out the {0} release: {1}' -f $editionName, $why) -ForegroundColor Red
            Write-Host ('Nothing was downloaded or installed. {0} installs only from Invardia''s signed release of its ring.' -f $editionName) -ForegroundColor Red
            $code = 3; break
        }
        $trusted = if ($seam['TrustedKeys']) { @(& $seam['TrustedKeys']) } else { @((Get-SIInvardiaTrustedKeys).Keys) }
        $chk = Test-SILauncherPackage -Body ([string]$ans.Body) -Ring $ringSigned -TrustedKeys $trusted -Kind $(if ($isPro) { 'code' } else { 'community' })
        if (-not $chk.Ok) { Write-Host ('Invardia''s answer cannot be used: {0}. Nothing was downloaded or installed.' -f $chk.Reason) -ForegroundColor Red; $code = 3; break }
        $relVersion = $chk.Version
        Write-Host ('  SecurityInsight {0} (ring {1}, sequence {2}): the manifest''s signature verifies with Invardia''s update-signing key' -f $relVersion, $ringSigned, $chk.Sequence)
        $reused = & $useEarlier $relVersion
      if (-not $reused) {

        # ---- 3. download into a NEW, empty folder: size and SHA-256 of the signed manifest ----
        $dir = [IO.Path]::Combine($tempRoot, ('securityinsight-release-{0}-{1}' -f $relVersion, [guid]::NewGuid().ToString('N').Substring(0, 8)))
        [void][IO.Directory]::CreateDirectory($dir)
        $assetName = Get-SIInvardiaArchiveName -Kind $chk.Kind -Version $relVersion -Archive $(if ($chk.Manifest.PSObject.Properties['archive']) { "$($chk.Manifest.archive)" } else { '' })
        Write-Host ('Step 3 of {0}: downloading {1} ({2}) into {3}' -f $steps, $assetName, $(if ($isPro) { 'the Pro package, from Invardia' } else { 'the public release the signed manifest names' }), $dir)
        $saveSeams = @{}
        if ($seam['Download']) {
            $dlSeam = $seam['Download']
            $saveSeams['Download'] = { param($u, $f) try { & $dlSeam $u $f; [pscustomobject]@{ Status = 200; Error = '' } } catch { [pscustomobject]@{ Status = 0; Error = "$($_.Exception.Message)" } } }.GetNewClosure()
        }
        $saved = Save-SIInvardiaUpdateFile -Result ([pscustomobject]@{ Kind = $chk.Kind; Action = 'update'; Manifest = $chk.Manifest; DownloadUrl = $chk.DownloadUrl }) -OutDir $dir -Seams $saveSeams
        if (-not $saved.Ok) {
            Write-Host ('The download cannot be used: {0}. Nothing was installed; the folder is removed. Run the command again.' -f $saved.Reason) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        $zipPath = $saved.Path
        $stated = "$($chk.Manifest.sha256)".Trim().ToLowerInvariant(); try { $statedSize = [long]$chk.Manifest.size } catch { $statedSize = 0L }
        Write-Host ('  {0}: size and SHA-256 as the signed manifest states' -f $assetName)
      }

        if ($reused) {
            # the release downloaded before IS the one this launcher installs now (same edition, same version): used again
            $tree = [string]$script:SILauncherReuse.Tree; $treeVersion = [string]$script:SILauncherReuse.Version; $dir = [string]$script:SILauncherReuse.Folder
        } else {
        # ---- check it, unpack it ----
        Write-Host ('Step {0} of {1}: checking the download' -f ($steps - 1), $steps)
        $why = Test-SILauncherZip -Path $zipPath -Version $relVersion -Size $statedSize -Sha256 $stated -AllowBuildNumber
        if ($why) {
            Write-Host ('The download cannot be used: {0}. Nothing was installed; the folder is removed. Run the command again.' -f $why) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        Write-Host ('  {0}: not empty, opens, holds the installer, VERSION {1}, SHA-256 as the signed manifest states' -f $assetName, $relVersion)
        $unpack = [IO.Path]::Combine($dir, 'release')
        try { Expand-SILauncherZip -Path $zipPath -To $unpack } catch {
            Write-Host ('The release could not be unpacked: {0}. Nothing was installed; the folder is removed.' -f $_.Exception.Message) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        $tree = Find-SILauncherTree -Dir $unpack
        if (-not $tree) { Write-Host 'The unpacked release holds no setup/Install-SecurityInsight.ps1. Nothing was installed; the folder is removed.' -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $dir = ''; $code = 3; break }
        $treeVersion = $relVersion
        # the edition of this copy, into the unpacked installer's one edition line (the same step for both editions)
        $why = Set-SILauncherEditionStamp -Path ([IO.Path]::Combine($tree, 'setup', 'Install-SecurityInsight.ps1')) -Edition "$script:SIInstallChannel"
        if ($why) { Write-Host ('The release''s installer cannot be set to install {0}: {1}. Nothing was installed; the folder is removed.' -f $editionName, $why) -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $dir = ''; $code = 3; break }
        # the note, so -Resume finds this folder again (a -WhatIf run writes nothing outside the temp folder)
        if (-not $WhatIfPreference) {
            try {
                $note = Read-SILauncherNote -Path $notePath
                $note[$noteKey] = [ordered]@{ path = $tree; folder = $dir; version = $relVersion; channel = "$script:SIInstallChannel"; savedUtc = [datetime]::UtcNow.ToString('o') }
                Write-SILauncherNote -Path $notePath -Note $note
            } catch { Write-Host ('(the note for -Resume could not be written: {0})' -f $_.Exception.Message) -ForegroundColor DarkGray }
        }
        }
    }

    # ---- run the full installer from the release, with exactly the parameters given ----
    $installer = [IO.Path]::Combine($tree, 'setup', 'Install-SecurityInsight.ps1')
    $pass = Get-SILauncherPassThrough -Bound $PSBoundParameters -Own $siOwn
    Write-Host ('Step {0} of {0}: running the installer of SecurityInsight {1} ({2}) with {3} parameter(s) as given: {4}' -f $steps, $treeVersion, $editionName, $pass.Count, $installer)
    $code = [int](@(& $runInstaller $installer $pass) | Select-Object -Last 1)

    if ($code -eq 0 -and -not $KeepDownload -and "$dir".Trim()) {
        try { [IO.Directory]::Delete($dir, $true) } catch { }
        if (-not $WhatIfPreference) {
            try { $note = Read-SILauncherNote -Path $notePath; if ($note.ContainsKey($noteKey)) { [void]$note.Remove($noteKey); Write-SILauncherNote -Path $notePath -Note $note } } catch { }
        }
        Write-Host 'The downloaded release folder is removed (-KeepDownload keeps it).'
    } elseif ("$dir".Trim() -or $tree) {
        Write-Host ('Release files: {0}' -f $tree)
        if ($code -ne 0) { Write-Host '  The same command with -Resume continues from here.' -ForegroundColor Yellow }
    }
} while ($false)
# the code the Pro copy wrote out for itself is not left behind (the installer runs from its own package)
if ("$codeDir".Trim() -and [IO.Directory]::Exists($codeDir)) { try { [IO.Directory]::Delete($codeDir, $true) } catch { } }
$global:LASTEXITCODE = $code
exit $code
