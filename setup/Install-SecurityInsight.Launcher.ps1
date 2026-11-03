<#
.SYNOPSIS
    Installs SecurityInsight with two lines: line 1 downloads this one small file, line 2 runs it with every setting as a
    parameter. It downloads the public SecurityInsight release, checks it and runs its installer with your parameters.

.DESCRIPTION
    The ONE file a person downloads to install SecurityInsight (framework INSTALL-1). Runs in Azure Cloud Shell
    (PowerShell 7) and in PowerShell 7 or Windows PowerShell 5.1 on Windows. It needs no PowerShell module.

      1. Reads the public SecurityInsight release on GitHub (the latest, or the one -Version names). No sign-in.
      2. Downloads the release zip (SecurityInsight-v<version>.zip) into a NEW, empty folder in the temp folder
         (securityinsight-release-<version>-<random>).
      3. Checks the download before anything runs: it is not empty (and has the size and SHA-256 the release states, when
         the release states them), the zip opens, it holds setup/Install-SecurityInsight.ps1, and its VERSION file is the
         release's version. A failed check stops here: nothing is installed and the folder is removed.
      4. Unpacks it and runs the full installer, setup/Install-SecurityInsight.ps1, FROM that folder with exactly the
         parameters you gave (the same parameters as the installer; this help lists them), and ends with its exit code.
      5. After a successful install the downloaded folder is removed (-KeepDownload keeps it). After a stop it is kept, and
         -Resume uses it again (a small note remembers where it is: ~/clouddrive/invardia/securityinsight-launcher.json in
         Azure Cloud Shell, else .invardia/securityinsight-launcher.json in your user profile). When the folder is gone (a
         new Cloud Shell session), -Resume downloads the release again -- the install keeps its own progress in its state
         folder, so it still continues where it stopped.

    The edition comes with this file, never with a parameter. The copy in the public SecurityInsight repository installs
    SecurityInsight Community. The copy Invardia hands out at https://invardia.com/support/si/ installs SecurityInsight
    Pro: the same public release, installed as Pro. Nothing licensed is downloaded before a licence exists: the install
    claims its own key, and its updater fetches the licensed Pro code through Invardia later.

    Nothing secret is a parameter, and this file writes no secret anywhere: the keys a feature needs are asked for by the
    installer and go straight to the install's Key Vault.

.PARAMETER TenantId
    The tenant SecurityInsight assesses (GUID). Required (with -SubscriptionId); every other setting has a default.
.PARAMETER SubscriptionId
    The subscription for SecurityInsight's own resources (GUID). Required.
.PARAMETER Location
    The Azure region (default westeurope).
.PARAMETER ResourceGroup
    The resource group, created when it does not exist (default rg-si-prod-community-ca).
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
    The new workspace's name (default log-si-prod-community-ca).
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
    The SecurityInsight release to install, e.g. 3.0.21 (default: the latest public release).
.PARAMETER KeepDownload
    Keep the downloaded release folder after a successful install (it is always kept after a stop, for -Resume).

.OUTPUTS
    Exit code: the installer's -- 0 installed (warnings included), 1 a step failed (fix it and run again with -Resume),
    2 a check failed, 3 the settings are not valid. 3 also when the release cannot be read, or a check of the download
    fails (nothing was installed).

.EXAMPLE
    Invoke-WebRequest https://invardia.com/support/si/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>'
    # the quickest install: every other setting has its default
.EXAMPLE
    Invoke-WebRequest https://invardia.com/support/si/Install-SecurityInsight.ps1 -OutFile Install-SecurityInsight.ps1
    ./Install-SecurityInsight.ps1 -TenantId '00000000-0000-0000-0000-000000000001' -SubscriptionId '00000000-0000-0000-0000-000000000002' -Location 'westeurope' -ResourceGroup 'rg-si-prod-pro-ca' -Owner 'secops@contoso.com' -UpdateRing 2 -MailMode sharedMailbox -MailFrom 'securityinsight@contoso.com' -MailTo 'secops@contoso.com' -SqlLocation 'swedencentral' -SqlAdminGroupId '00000000-0000-0000-0000-000000000003' -WebAppAccess internal -WebAppAdmins 'admin1@contoso.com','admin2@contoso.com' -PrivateNetwork -VnetId '/subscriptions/00000000-0000-0000-0000-000000000004/resourceGroups/rg-network-spoke/providers/Microsoft.Network/virtualNetworks/vnet-spoke-security' -AppsSubnetName 'snet-si-apps' -AppsSubnetPrefix '10.0.24.0/27' -EndpointsSubnetName 'snet-si-endpoints' -EndpointsSubnetPrefix '10.0.24.32/28' -SupportAppId '00000000-0000-0000-0000-000000000006' -SupportAccess troubleshoot
    # a private-network install as two lines: every setting written out on line 2
.EXAMPLE
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -PreflightOnly
    # the checks only: the release is downloaded to the temp folder, nothing is created, changed or written in Azure
.EXAMPLE
    ./Install-SecurityInsight.ps1 -Resume
    # continue an install that stopped, with the release and the answers of its first run
.EXAMPLE
    ./Install-SecurityInsight.ps1 -TenantId '<tenant id>' -SubscriptionId '<subscription id>' -Version 3.0.21
    # install one named release instead of the latest

.NOTES
    Requirements:
      PowerShell 7 (Azure Cloud Shell) or Windows PowerShell 5.1. No PowerShell module.
      Role: Owner (or Contributor + User Access Administrator) -- on the subscription SecurityInsight is installed in
      Role: Privileged Role Administrator (or Global Administrator) -- optional -- on the tenant
      Hosts: github.com, api.github.com, objects.githubusercontent.com, release-assets.githubusercontent.com (the release);
        then the installer's: login.microsoftonline.com, management.azure.com, graph.microsoft.com and the install's own
        Azure resources (the full list is on the documentation page)

    Reads: the public release at api.github.com (anonymous) and the zip it names. Writes: a new folder in the temp folder
    (the zip and its unpacked files) and the small note with that folder's path; everything else is the installer's.

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
    # RunInstaller { param($Path, $Arguments) } -> exit code, TempRoot, NoteDir
    [Parameter(DontShow)][System.Collections.IDictionary]$LauncherSeams
)
#Requires -Version 5.1
# THE CHANNEL (framework INSTALL-1): 'community' in the repository and the GitHub copy; the copy handed to Invardia for
# https://invardia.com/support/si/ says 'pro' (release\Build-SISupportScripts.ps1 Set-SIInstallLauncherStamp). One line.
$script:SIInstallChannel = 'community'
# the release version this copy was built with (stamped by the build; empty in the repository)
$__siLauncherVersion = ''
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
$editionName = if ("$script:SIInstallChannel" -eq 'pro') { 'SecurityInsight Pro' } else { 'SecurityInsight Community' }
Write-Host ('Installs {0} from the public SecurityInsight release on GitHub. Documentation: https://invardia.com/docs/si/scripts/Install-SecurityInsight/' -f $editionName)

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
    <# The release tree in an unpacked folder: setup/Install-SecurityInsight.ps1 at its top, or in its one sub-folder. #>
    param([string]$Dir)
    if (-not $Dir -or -not [IO.Directory]::Exists($Dir)) { return '' }
    if ([IO.File]::Exists([IO.Path]::Combine($Dir, 'setup', 'Install-SecurityInsight.ps1'))) { return $Dir }
    $tops = @([IO.Directory]::GetDirectories($Dir))
    if ($tops.Count -eq 1 -and [IO.File]::Exists([IO.Path]::Combine($tops[0], 'setup', 'Install-SecurityInsight.ps1'))) { return $tops[0] }
    ''
}

function Test-SILauncherZip {
    <#
        The checks of a downloaded release zip, before anything is unpacked. Returns '' when it is good, else the reason in
        plain words: empty, not the size or SHA-256 the release states, not a zip, no setup/Install-SecurityInsight.ps1, or
        a VERSION that is not the release's version.
    #>
    param([string]$Path, [string]$Version, [long]$Size = 0, [string]$Sha256 = '')
    if (-not [IO.File]::Exists($Path)) { return 'the download did not complete (no file)' }
    $len = (New-Object IO.FileInfo($Path)).Length
    if ($len -le 0) { return 'the download is empty (0 bytes)' }
    if ($Size -gt 0 -and $len -ne $Size) { return ('the download has {0} bytes, the release states {1}' -f $len, $Size) }
    if ("$Sha256".Trim()) {
        $sha = [System.Security.Cryptography.SHA256]::Create(); $fs = [IO.File]::OpenRead($Path)
        try { $got = -join ($sha.ComputeHash($fs) | ForEach-Object { $_.ToString('x2') }) } finally { $fs.Dispose(); $sha.Dispose() }
        if ($got -ne "$Sha256".Trim().ToLowerInvariant()) { return ('the download''s SHA-256 is {0}, the release states {1}' -f $got, "$Sha256".Trim().ToLowerInvariant()) }
    }
    if (-not ('System.IO.Compression.ZipFile' -as [type])) { Add-Type -AssemblyName System.IO.Compression.FileSystem }
    $zip = $null
    try { $zip = [System.IO.Compression.ZipFile]::OpenRead($Path) } catch { return 'the download is not a zip that opens' }
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
        $inst = @($names | Where-Object { $_ -match '^([^/]+/)?setup/Install-SecurityInsight\.ps1$' })
        if (-not $inst.Count) { return 'the zip holds no setup/Install-SecurityInsight.ps1' }
        $prefix = ($inst[0] -replace 'setup/Install-SecurityInsight\.ps1$', '')
        $ve = @($zip.Entries | Where-Object { $_.FullName.Replace('\', '/') -eq ($prefix + 'VERSION') })
        if (-not $ve.Count) { return 'the zip holds no VERSION file' }
        $r = New-Object IO.StreamReader($ve[0].Open())
        try { $zv = $r.ReadToEnd().Trim() } finally { $r.Dispose() }
        $want = "$Version".Trim().TrimStart('v', 'V')
        if ($zv -ne $want) { return ('the zip''s VERSION says {0}, the release is {1}' -f $zv, $want) }
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

function Get-SILauncherPassThrough {
    <# PURE. The parameters for the full installer: every one given, unchanged, except the launcher's own. #>
    param([System.Collections.IDictionary]$Bound, [string[]]$Own = @('Version', 'KeepDownload', 'LauncherSeams'))
    $a = @{}
    foreach ($k in @($Bound.Keys)) { if ([string]$k -notin $Own) { $a[[string]$k] = $Bound[$k] } }
    $a
}

$code = 0
$dir = ''
do {
    # ---- -ViaSupportApp needs the support session for THIS tenant: refused before anything is downloaded ----
    if ($ViaSupportApp) {
        $supState = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
        if (-not $supState) { Write-Host 'With -ViaSupportApp, run the install inside a Connect-InvardiaSupport session for this tenant. Nothing was downloaded or installed.' -ForegroundColor Red; $code = 3; break }
        if ("$TenantId".Trim() -and "$($supState.TenantId)".Trim() -ne "$TenantId".Trim()) { Write-Host ('The support session is for tenant {0}, not for -TenantId {1}: connect the session to this tenant first. Nothing was downloaded or installed.' -f $supState.TenantId, $TenantId) -ForegroundColor Red; $code = 3; break }
    }
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        # Windows PowerShell 5.1: GitHub needs TLS 1.2
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

    # ---- 1. -Resume: the folder of the first run, when it is still there ----
    $tree = ''; $treeVersion = ''
    if ($Resume) {
        $note = Read-SILauncherNote -Path $notePath
        $n = $note[$noteKey]
        if ($n -and "$($n.path)".Trim()) {
            $t = Find-SILauncherTree -Dir "$($n.path)"
            $want = "$Version".Trim().TrimStart('v', 'V')
            if ($t -and (-not $want -or $want -eq "$($n.version)") -and "$($n.channel)" -eq "$script:SIInstallChannel") {
                $tree = $t; $treeVersion = "$($n.version)"; $dir = "$($n.folder)"
                Write-Host ('Resume: using the release {0} downloaded before, in {1} -- nothing is downloaded.' -f $treeVersion, $tree)
            }
        }
        if (-not $tree) { Write-Host 'Resume: the release folder of the first run is not there any more, so the release is downloaded again. The install keeps its own progress, so it still continues where it stopped.' -ForegroundColor Yellow }
    }

    if (-not $tree) {
        # ---- 2. read the release ----
        $relUrl = Get-SILauncherReleaseUrl -Repo $siRepo -Version $Version
        Write-Host ('Step 1 of 4: reading the release from GitHub ({0})' -f $relUrl)
        $rel = $null
        try { $rel = & $getRelease $relUrl } catch { Write-Verbose "$($_.Exception.Message)"; $rel = $null }
        if (-not $rel -or -not "$($rel.tag_name)".Trim()) { Write-Host ('The SecurityInsight release could not be read from GitHub ({0}). Check the network (github.com, api.github.com) and -Version, then run the command again. Nothing was installed.' -f $relUrl) -ForegroundColor Red; $code = 3; break }
        $relVersion = "$($rel.tag_name)".Trim().TrimStart('v', 'V')
        $assetName = 'SecurityInsight-v{0}.zip' -f $relVersion
        $asset = @(@($rel.assets) | Where-Object { "$($_.name)" -eq $assetName }) | Select-Object -First 1
        if (-not $asset -or -not "$($asset.browser_download_url)".Trim()) { Write-Host ('The release {0} has no {1} to download. Nothing was installed.' -f $relVersion, $assetName) -ForegroundColor Red; $code = 3; break }
        $stated = if ("$($asset.digest)" -match '^(?i)sha256:([0-9a-f]{64})$') { $Matches[1].ToLowerInvariant() } else { '' }
        $statedSize = 0L; try { $statedSize = [long]$asset.size } catch { $statedSize = 0L }

        # ---- 3. download into a NEW, empty folder ----
        $dir = [IO.Path]::Combine($tempRoot, ('securityinsight-release-{0}-{1}' -f $relVersion, [guid]::NewGuid().ToString('N').Substring(0, 8)))
        [void][IO.Directory]::CreateDirectory($dir)
        $zipPath = [IO.Path]::Combine($dir, $assetName)
        Write-Host ('Step 2 of 4: downloading {0} into {1}' -f $assetName, $dir)
        try { & $download "$($asset.browser_download_url)" $zipPath } catch { Write-Verbose "$($_.Exception.Message)" }

        # ---- 4. check it, unpack it ----
        Write-Host 'Step 3 of 4: checking the download'
        $why = Test-SILauncherZip -Path $zipPath -Version $relVersion -Size $statedSize -Sha256 $stated
        if ($why) {
            Write-Host ('The download cannot be used: {0}. Nothing was installed; the folder is removed. Run the command again.' -f $why) -ForegroundColor Red
            try { [IO.Directory]::Delete($dir, $true) } catch { }
            $dir = ''; $code = 3; break
        }
        Write-Host ('  {0}: not empty, opens, holds the installer, VERSION {1}{2}' -f $assetName, $relVersion, $(if ($stated) { ', SHA-256 as the release states' } else { '' }))
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
        if ("$script:SIInstallChannel" -eq 'pro') {
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

    # ---- 5. run the full installer from the release, with exactly the parameters given ----
    $installer = [IO.Path]::Combine($tree, 'setup', 'Install-SecurityInsight.ps1')
    $pass = Get-SILauncherPassThrough -Bound $PSBoundParameters -Own $siOwn
    Write-Host ('Step 4 of 4: running the installer of SecurityInsight {0} ({1}) with {2} parameter(s) as given: {3}' -f $treeVersion, $editionName, $pass.Count, $installer)
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
$global:LASTEXITCODE = $code
exit $code
