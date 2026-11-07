<#
.SYNOPSIS
    Installs SecurityInsight with two lines: line 1 downloads this one small file, line 2 runs it with every setting as a
    parameter. It downloads the SecurityInsight package, checks it and runs its installer with your parameters.

.DESCRIPTION
    The ONE file a person downloads to install SecurityInsight (framework INSTALL-1). Runs in Azure Cloud Shell
    (PowerShell 7) and in PowerShell 7 or Windows PowerShell 5.1 on Windows. It needs no PowerShell module.

    The edition comes with this file, never with a parameter. The copy in the public SecurityInsight repository installs
    SecurityInsight Community from the public release on GitHub. The copy Invardia hands out at
    https://invardia.com/support/si/ installs SecurityInsight Pro from Invardia -- never from GitHub.

    SecurityInsight Pro (the copy from invardia.com):
      1. Signs you in to Azure for -TenantId: in Azure Cloud Shell with no prompt, on a workstation in your browser (the
         same sign-in the installer uses; no device code). The installer started in step 5 takes this sign-in over, so you
         sign in ONCE.
      2. Asks Invardia for the SecurityInsight Pro package of your update ring (-UpdateRing; without it Invardia's default,
         ring 3), with that sign-in. Invardia hands it out only to a signed-in admin of a tenant that has an Invardia
         environment with SecurityInsight. No licence is needed: the install deploys with every job parked until the
         licence is assigned. A refusal stops here with Invardia's reason (exit 3); there is no other source.
      3. Checks Invardia's answer exactly as SecurityInsight's updater checks an update: the manifest's signature against
         Invardia's update-signing keys that come with this file, then downloads the package into a NEW, empty folder in
         the temp folder (securityinsight-release-<version>-<random>) and checks its size and SHA-256 against the signed
         manifest. -Version is not used: Pro installs the release Invardia serves to the ring.
      4. Checks the zip (it opens, it holds setup/Install-SecurityInsight.ps1, its VERSION is the package's) and unpacks it.
      5. Runs the full installer, setup/Install-SecurityInsight.ps1, FROM that folder as SecurityInsight Pro with exactly the
         parameters you gave, and ends with its exit code.

    SecurityInsight Community (the copy from GitHub):
      1. Reads the public SecurityInsight release on GitHub (the latest, or the one -Version names). No sign-in.
      2. Downloads the release zip (SecurityInsight-v<version>.zip) into a NEW, empty folder in the temp folder.
      3. Checks the download before anything runs: it is not empty (and has the size and SHA-256 the release states, when
         the release states them), the zip opens, it holds setup/Install-SecurityInsight.ps1, and its VERSION file is the
         release's version. A failed check stops here: nothing is installed and the folder is removed.
      4. Unpacks it and runs the full installer FROM that folder with exactly the parameters you gave (the same parameters
         as the installer; this help lists them), and ends with its exit code.

    Both: after a successful install the downloaded folder is removed (-KeepDownload keeps it). After a stop it is kept, and
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
    SecurityInsight Pro installs the package Invardia serves to this ring.
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
    SecurityInsight Community: the release to install, e.g. 3.0.21 (default: the latest public release). Not used by
    SecurityInsight Pro, which installs the release Invardia serves to its update ring.
.PARAMETER KeepDownload
    Keep the downloaded release folder after a successful install (it is always kept after a stop, for -Resume).

.OUTPUTS
    Exit code: the installer's -- 0 installed (warnings included), 1 a step failed (fix it and run again with -Resume),
    2 a check failed, 3 the settings are not valid. 3 also when the release cannot be read, Invardia refuses the Pro
    package, or a check of the download fails (nothing was installed).

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
.EXAMPLE
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Version 3.0.21
    # install one named release instead of the latest

.NOTES
    Requirements:
      PowerShell 7 (Azure Cloud Shell) or Windows PowerShell 5.1. No PowerShell module.
      Role: Owner (or Contributor + User Access Administrator) -- on the subscription SecurityInsight is installed in
      Role: Privileged Role Administrator (or Global Administrator) -- optional -- on the tenant
      Hosts: SecurityInsight Pro: invardia.com (the package), login.microsoftonline.com and management.azure.com (the
        sign-in). SecurityInsight Community: github.com, api.github.com, objects.githubusercontent.com,
        release-assets.githubusercontent.com (the release). Then the installer's: login.microsoftonline.com,
        management.azure.com, graph.microsoft.com and the install's own Azure resources (the full list is on the
        documentation page)

    Reads: Pro -- the Pro package at invardia.com (with your sign-in) and the zip it names; Community -- the public release
    at api.github.com (anonymous) and the zip it names. Writes: a new folder in the temp folder (the zip and its unpacked
    files; the Pro copy also writes the sign-in and package-check code it carries there, removed when it ends) and the
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

    # the release to install (e.g. 3.0.21); default: the latest public release
    [string]$Version,
    # keep the downloaded release folder after a successful install
    [switch]$KeepDownload,
    # Tests only: GetRelease { param($Url) } -> the release object, Download { param($Url, $OutFile) },
    # RunInstaller { param($Path, $Arguments) } -> exit code, TempRoot, NoteDir; the Pro channel also:
    # SignIn { param($TenantId, $SubscriptionId) } -> @{ TenantId; Account; Token }, GetPackage { param($Url, $Token) } ->
    # @{ Status; Body; Error }, TrustedKeys { } -> the update-signing keys, CodeRoot (the package root its code is loaded from),
    # RestHttp (replaces the REST layer's one HTTP call, Invoke-SIAzRestHttp, under the real sign-in)
    [Parameter(DontShow)][System.Collections.IDictionary]$LauncherSeams
)
#Requires -Version 5.1
# THE CHANNEL (framework INSTALL-1): 'community' in the repository and the GitHub copy; the copy handed to Invardia for
# https://invardia.com/support/si/ says 'pro' (release\Build-SISupportScripts.ps1 Set-SIInstallLauncherStamp). One line.
$script:SIInstallChannel = 'community'
# the release version this copy was built with (stamped by the build; empty in the repository)
$__siLauncherVersion = ''
# THE CODE THE PRO CHANNEL USES (Invardia DESIGN ch 8, Pro installs from Invardia): SecurityInsight's own setup sign-in
# (setup/_shared/SI-SetupAzure.ps1 and what it loads) and its updater's package check (engine/_shared/SI-InvardiaUpdate.ps1
# with its update-signing keys). release\Build-SISupportScripts.ps1 EMBEDS them below this line in the copy handed to
# Invardia -- readable, each file SHA-256 checked when it is written out -- so the published launcher stays ONE file.
# Empty in the repository: there the launcher uses the files of the package it stands in.
$__siLauncherFiles = [ordered]@{}
$ErrorActionPreference = 'Stop'

$siRepo = 'KnudsenMorten/SecurityInsight'
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
Write-Host ('Installs {0} from {1}. Documentation: https://invardia.com/docs/si/scripts/Install-SecurityInsight/' -f $editionName, $(if ($isPro) { 'Invardia (the Pro package of your update ring)' } else { 'the public SecurityInsight release on GitHub' }))

function Get-SILauncherReleaseUrl {
    <# PURE. The GitHub API address of the release: the latest, or the tag v<version>. #>
    param([string]$Repo = 'KnudsenMorten/SecurityInsight', [string]$Version)
    $v = "$Version".Trim().TrimStart('v', 'V')
    if ($v) { 'https://api.github.com/repos/{0}/releases/tags/v{1}' -f $Repo, $v } else { 'https://api.github.com/repos/{0}/releases/latest' -f $Repo }
}

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
        setup/Install-SecurityInsight.ps1, or a VERSION that is not the release's version. -AllowBuildNumber (the Pro
        package): a release named <VERSION>.<build number> carries the code of VERSION -- the rule SecurityInsight's
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
#  THE PRO CHANNEL: the package from Invardia (Invardia DESIGN ch 8, framework section 0.1 -- never GitHub for Pro)
# ---------------------------------------------------------------------------------------------------------------------
function Get-SILauncherPackageUrl {
    <# PURE. Invardia's Pro package route: tenantId always, ring only when one is asked for (Invardia's default is ring 3). #>
    param([string]$BaseUrl = 'https://invardia.com', [Parameter(Mandatory)][string]$TenantId, [int]$Ring = -1)
    $u = '{0}/api/install/securityinsight/package?tenantId={1}' -f "$BaseUrl".Trim().TrimEnd('/'), [uri]::EscapeDataString("$TenantId".Trim())
    if ($Ring -ge 0) { $u += ('&ring={0}' -f $Ring) }
    $u
}

function Get-SILauncherRouteRefusal {
    <#
        PURE. Why Invardia did not hand out the Pro package, in plain words: Invardia's own message ({ error, message }) with
        the status and its error code, else a sentence of our own for the status. Never the token.
    #>
    param([int]$Status, [AllowEmptyString()][AllowNull()][string]$Body, [AllowEmptyString()][AllowNull()][string]$ErrorText)
    if ($Status -eq 0) { return ('Invardia could not be reached ({0}) -- check the network (invardia.com) and run the same command again' -f $(if ("$ErrorText".Trim()) { "$ErrorText".Trim() } else { 'no answer' })) }
    $j = $null
    if ("$Body".Trim()) { try { $j = "$Body" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
    $err = ''; $msg = ''
    if ($j -and $j.PSObject.Properties['error']) { $err = "$($j.error)".Trim() }
    if ($j -and $j.PSObject.Properties['message']) { $msg = ("$($j.message)" -replace '\s+', ' ').Trim() }
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 297) + '...' }
    if (-not $msg) {
        $msg = switch ($Status) {
            401 { 'Invardia did not accept the sign-in' }
            403 { 'the sign-in is for another tenant than -TenantId' }
            404 { 'this tenant has no Invardia environment with SecurityInsight, or nothing is released on that ring' }
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
    <# GET Invardia's Pro package route with the admin's ARM token. Returns @{ Status (0 = no answer); Body; Error }; never
       throws, and the token is never in what it returns. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$Token, [int]$TimeoutSec = 60)
    $h = @{ Authorization = ('Bearer ' + $Token); Accept = 'application/json'; 'User-Agent' = 'SecurityInsight-Installer' }
    try {
        $r = Invoke-WebRequest -Method Get -Uri $Url -Headers $h -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        $c = $r.Content; if ($c -is [byte[]]) { $c = [System.Text.Encoding]::UTF8.GetString($c) }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$c; Error = '' }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = ''; Error = ("$($_.Exception.Message)").Replace($Token, '<withheld>') } }
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
        The admin's sign-in for the Pro package, with SecurityInsight's OWN setup sign-in (setup/_shared/SI-SetupAzure.ps1,
        loaded beside this): Azure Cloud Shell's token endpoint with no prompt, else the browser (authorization code + PKCE on
        localhost; never device code), or the Invardia Support session's tokens with -ViaSupportApp. The sign-in stays in
        THIS PowerShell process (memory only): the installer, started from here in the same process, finds it and uses it
        (it reuses a sign-in of the same tenant) -- the admin signs in once. Returns @{ TenantId; Account; Token } (Token =
        an access token for Azure Resource Manager, the one Invardia's route accepts).
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

function Test-SILauncherProPackage {
    <#
        Invardia's answer to the Pro package route, checked EXACTLY as SecurityInsight's updater checks an update (the
        functions of engine/_shared/SI-InvardiaUpdate.ps1, loaded beside this -- no second implementation): the signature
        over the manifest against the trusted update-signing keys (Test-SIInvardiaManifestSignature), then the signed
        manifest itself -- product securityinsight, kind code, the ring asked for, a version, SHA-256 and size
        (Test-SIInvardiaManifestContent). The unsigned fields of the answer must say what the signed manifest says, and the
        download link must be https. Returns @{ Ok; Reason; Manifest; Version; DownloadUrl; Sequence }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Body, [Parameter(Mandatory)][int]$Ring, [AllowNull()][object[]]$TrustedKeys)
    $no = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why; Manifest = $null; Version = ''; DownloadUrl = ''; Sequence = -1 } }
    $j = $null
    if ("$Body".Trim()) { try { $j = "$Body" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
    if (-not $j) { return (& $no 'Invardia''s answer is not JSON') }
    $p = { param($n) if ($j.PSObject.Properties[$n] -and $null -ne $j.$n) { [string]$j.$n } else { '' } }
    $sig = Test-SIInvardiaManifestSignature -ManifestB64 (& $p 'manifestB64') -Signature (& $p 'signature') -KeyId (& $p 'keyId') -TrustedKeys $TrustedKeys
    if (-not $sig.Ok) { return (& $no $sig.Reason) }
    $m = $sig.Manifest
    $chk = Test-SIInvardiaManifestContent -Manifest $m -Kind 'code' -Ring $Ring
    # 'hold' is a manual step an UPDATE of an existing install needs: a new install has nothing to step from
    if ($chk.Action -notin @('update', 'hold')) { return (& $no $chk.Reason) }
    foreach ($n in 'version', 'sha256', 'size', 'sequence') {
        $said = (& $p $n).Trim()
        $signed = $(if ($m.PSObject.Properties[$n]) { "$($m.$n)".Trim() } else { '' })
        if ($said -and $said.ToLowerInvariant() -ne $signed.ToLowerInvariant()) { return (& $no ("Invardia's answer names {0} {1}, its signed manifest {2}" -f $n, $said, $signed)) }
    }
    $dl = & $p 'downloadUrl'
    if ($dl -notmatch '^https://[^/\s]+/') { return (& $no 'Invardia''s answer carries no https download link') }
    [pscustomobject]@{ Ok = $true; Reason = ''; Manifest = $m; Version = "$($m.version)".Trim(); DownloadUrl = $dl; Sequence = $chk.Sequence }
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
        # Windows PowerShell 5.1: GitHub and Invardia need TLS 1.2
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }
    }
    $getRelease = $seam['GetRelease']
    if (-not $getRelease) { $getRelease = { param([string]$Url) Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'SecurityInsight-Installer' } -TimeoutSec 60 } }
    $download = $seam['Download']
    if (-not $download) { $download = { param([string]$Url, [string]$OutFile) Invoke-WebRequest -Method Get -Uri $Url -OutFile $OutFile -UseBasicParsing -Headers @{ 'User-Agent' = 'SecurityInsight-Installer' } -TimeoutSec 900 | Out-Null } }
    $runInstaller = $seam['RunInstaller']
    if (-not $runInstaller) { $runInstaller = { param([string]$Path, [hashtable]$Arguments) $global:LASTEXITCODE = 0; & $Path @Arguments | Out-Host; [int]$LASTEXITCODE } }
    $tempRoot = if ("$($seam['TempRoot'])".Trim()) { "$($seam['TempRoot'])" } else { [IO.Path]::GetTempPath() }
    $notePath = Get-SILauncherNotePath -NoteDir "$($seam['NoteDir'])"
    $noteKey = if ("$InstallId".Trim()) { "$InstallId".Trim().ToLowerInvariant() } else { 'securityinsight' }
    $steps = if ($isPro) { 5 } else { 4 }

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
        if ($isPro) {
            # ======== SecurityInsight Pro: the package of the ring, from Invardia. No GitHub, no fallback. ========
            if ("$Version".Trim()) { Write-Host ('-Version {0} is not used: SecurityInsight Pro installs the release Invardia serves to its update ring.' -f "$Version".Trim()) -ForegroundColor Yellow }
            # the code this channel uses: embedded in this copy, else the package this file stands in
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
            if (-not $codeRoot) { Write-Host 'This copy of the launcher carries no SecurityInsight sign-in and package check, so it cannot install SecurityInsight Pro. Download it again from https://invardia.com/support/si/Install-SecurityInsight.ps1. Nothing was downloaded or installed.' -ForegroundColor Red; $code = 3; break }
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

            # ---- 2. sign in (once: the installer takes this sign-in over) ----
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

            # ---- 3. ask Invardia for the ring's Pro package ----
            $ringAsked = if ($PSBoundParameters.ContainsKey('UpdateRing')) { [int]$UpdateRing } else { -1 }
            $ringSigned = if ($ringAsked -ge 0) { $ringAsked } else { 3 }   # Invardia's default ring: a new install never starts ahead of its ring
            $url = Get-SILauncherPackageUrl -TenantId $tid -Ring $ringAsked
            Write-Host ('Step 2 of {0}: asking Invardia for the SecurityInsight Pro package of ring {1}{2}' -f $steps, $ringSigned, $(if ($ringAsked -lt 0) { ' (the default)' } else { '' }))
            $getPackage = $seam['GetPackage']
            if (-not $getPackage) { $getPackage = { param([string]$Url, [string]$Token) Invoke-SILauncherPackageGet -Url $Url -Token $Token } }
            $ans = $null
            try { $ans = & $getPackage $url "$($who.Token)" } catch { $ans = [pscustomobject]@{ Status = 0; Body = ''; Error = "$($_.Exception.Message)" } }
            $who = $null   # the token is not kept by the launcher (the sign-in itself stays in the process for the installer)
            if (-not $ans -or [int]$ans.Status -ne 200) {
                $why = Get-SILauncherRouteRefusal -Status $(if ($ans) { [int]$ans.Status } else { 0 }) -Body $(if ($ans) { [string]$ans.Body } else { '' }) -ErrorText $(if ($ans -and $ans.PSObject.Properties['Error']) { [string]$ans.Error } else { '' })
                Write-Host ('Invardia did not hand out the SecurityInsight Pro package: {0}' -f $why) -ForegroundColor Red
                Write-Host 'Nothing was downloaded or installed. SecurityInsight Pro installs only from Invardia.' -ForegroundColor Red
                $code = 3; break
            }
            $trusted = if ($seam['TrustedKeys']) { @(& $seam['TrustedKeys']) } else { @((Get-SIInvardiaTrustedKeys).Keys) }
            $chk = Test-SILauncherProPackage -Body ([string]$ans.Body) -Ring $ringSigned -TrustedKeys $trusted
            if (-not $chk.Ok) { Write-Host ('Invardia''s answer cannot be used: {0}. Nothing was downloaded or installed.' -f $chk.Reason) -ForegroundColor Red; $code = 3; break }
            $relVersion = $chk.Version
            Write-Host ('  SecurityInsight {0} (ring {1}, sequence {2}): the manifest''s signature verifies with Invardia''s update-signing key' -f $relVersion, $ringSigned, $chk.Sequence)
            $reused = & $useEarlier $relVersion
          if (-not $reused) {

            # ---- 4. download into a NEW, empty folder: size and SHA-256 of the signed manifest ----
            $dir = [IO.Path]::Combine($tempRoot, ('securityinsight-release-{0}-{1}' -f $relVersion, [guid]::NewGuid().ToString('N').Substring(0, 8)))
            [void][IO.Directory]::CreateDirectory($dir)
            $assetName = Get-SIInvardiaArchiveName -Kind 'code' -Version $relVersion -Archive $(if ($chk.Manifest.PSObject.Properties['archive']) { "$($chk.Manifest.archive)" } else { '' })
            Write-Host ('Step 3 of {0}: downloading {1} from Invardia into {2}' -f $steps, $assetName, $dir)
            $saveSeams = @{}
            if ($seam['Download']) {
                $dlSeam = $seam['Download']
                $saveSeams['Download'] = { param($u, $f) try { & $dlSeam $u $f; [pscustomobject]@{ Status = 200; Error = '' } } catch { [pscustomobject]@{ Status = 0; Error = "$($_.Exception.Message)" } } }.GetNewClosure()
            }
            $saved = Save-SIInvardiaUpdateFile -Result ([pscustomobject]@{ Kind = 'code'; Action = 'update'; Manifest = $chk.Manifest; DownloadUrl = $chk.DownloadUrl }) -OutDir $dir -Seams $saveSeams
            if (-not $saved.Ok) {
                Write-Host ('The download cannot be used: {0}. Nothing was installed; the folder is removed. Run the command again.' -f $saved.Reason) -ForegroundColor Red
                try { [IO.Directory]::Delete($dir, $true) } catch { }
                $dir = ''; $code = 3; break
            }
            $zipPath = $saved.Path
            $stated = "$($chk.Manifest.sha256)".Trim().ToLowerInvariant(); try { $statedSize = [long]$chk.Manifest.size } catch { $statedSize = 0L }
            Write-Host ('  {0}: size and SHA-256 as the signed manifest states' -f $assetName)
          }
        } else {
            # ======== SecurityInsight Community: the public release on GitHub ========
            $relUrl = Get-SILauncherReleaseUrl -Repo $siRepo -Version $Version
            Write-Host ('Step 1 of {0}: reading the release from GitHub ({1})' -f $steps, $relUrl)
            $rel = $null
            try { $rel = & $getRelease $relUrl } catch { Write-Verbose "$($_.Exception.Message)"; $rel = $null }
            if (-not $rel -or -not "$($rel.tag_name)".Trim()) { Write-Host ('The SecurityInsight release could not be read from GitHub ({0}). Check the network (github.com, api.github.com) and -Version, then run the command again. Nothing was installed.' -f $relUrl) -ForegroundColor Red; $code = 3; break }
            $relVersion = "$($rel.tag_name)".Trim().TrimStart('v', 'V')
            $reused = & $useEarlier $relVersion
          if (-not $reused) {
            $assetName = 'SecurityInsight-v{0}.zip' -f $relVersion
            $asset = @(@($rel.assets) | Where-Object { "$($_.name)" -eq $assetName }) | Select-Object -First 1
            if (-not $asset -or -not "$($asset.browser_download_url)".Trim()) { Write-Host ('The release {0} has no {1} to download. Nothing was installed.' -f $relVersion, $assetName) -ForegroundColor Red; $code = 3; break }
            $stated = if ("$($asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' }
            # a download is used only when GitHub states its SHA-256: without one it cannot be checked, so it is not fetched
            if (-not $stated) { Write-Host ('GitHub states no SHA-256 for {0} of release {1}, so the download cannot be checked. Nothing was downloaded or installed. Run the command again later, or give -Version for another release.' -f $assetName, $relVersion) -ForegroundColor Red; $code = 3; break }
            $statedSize = 0L; try { $statedSize = [long]$asset.size } catch { $statedSize = 0L }

            # ---- 3. download into a NEW, empty folder ----
            $dir = [IO.Path]::Combine($tempRoot, ('securityinsight-release-{0}-{1}' -f $relVersion, [guid]::NewGuid().ToString('N').Substring(0, 8)))
            [void][IO.Directory]::CreateDirectory($dir)
            $zipPath = [IO.Path]::Combine($dir, $assetName)
            Write-Host ('Step 2 of {0}: downloading {1} into {2}' -f $steps, $assetName, $dir)
            try { & $download "$($asset.browser_download_url)" $zipPath } catch { Write-Verbose "$($_.Exception.Message)" }
          }
        }

        if ($reused) {
            # the release downloaded before IS the one this launcher installs now (same edition, same version): used again
            $tree = [string]$script:SILauncherReuse.Tree; $treeVersion = [string]$script:SILauncherReuse.Version; $dir = [string]$script:SILauncherReuse.Folder
        } else {
        # ---- check it, unpack it ----
        Write-Host ('Step {0} of {1}: checking the download' -f ($steps - 1), $steps)
        $why = Test-SILauncherZip -Path $zipPath -Version $relVersion -Size $statedSize -Sha256 $stated -AllowBuildNumber:$isPro
        if ($why) {
            Write-Host ('The download cannot be used: {0}. Nothing was installed; the folder is removed. Run the command again.' -f $why) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        Write-Host ('  {0}: not empty, opens, holds the installer, VERSION {1}{2}' -f $assetName, $relVersion, $(if ($isPro) { ', SHA-256 as the signed manifest states' } else { ', SHA-256 as the release states' }))
        $unpack = [IO.Path]::Combine($dir, 'release')
        try { Expand-SILauncherZip -Path $zipPath -To $unpack } catch {
            Write-Host ('The release could not be unpacked: {0}. Nothing was installed; the folder is removed.' -f $_.Exception.Message) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        $tree = Find-SILauncherTree -Dir $unpack
        if (-not $tree) { Write-Host 'The unpacked release holds no setup/Install-SecurityInsight.ps1. Nothing was installed; the folder is removed.' -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $dir = ''; $code = 3; break }
        $treeVersion = $relVersion
        # the edition of this copy, into the unpacked installer's one edition line
        if ($isPro) {
            $why = Set-SILauncherEditionStamp -Path ([IO.Path]::Combine($tree, 'setup', 'Install-SecurityInsight.ps1')) -Edition 'pro'
            if ($why) { Write-Host ('The release''s installer cannot be set to install SecurityInsight Pro: {0}. Nothing was installed; the folder is removed.' -f $why) -ForegroundColor Red; try { [IO.Directory]::Delete($dir, $true) } catch { }; $dir = ''; $code = 3; break }
        }
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
