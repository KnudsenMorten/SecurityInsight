#Requires -Version 5.1
<#
.SYNOPSIS
    caj-si-updater -- keeps a CONTAINER-hosted SecurityInsight on the version its update ring approves.

.DESCRIPTION
    Runs nightly as its own Container Apps Job (#160, operator ruling 2026-09-29: "Updater job"), at 18:30 in the time zone of
    the install's Azure region (owner 2026-10-21: "move the start time for all si jobs to 7pm on all sites"): the job's timer
    is that zone's 18:30 in UTC (two ticks with daylight saving, e.g. '30 16,17 * * *' for West Europe) and the start that is
    not 18:30 there ends at once (Test-SIUpdaterRunNow, setup/_shared/SI-NightlySchedule.ps1; a job still on the earlier 23:00
    ticks is checked against 23:00); the daily pipeline starts after it, at 19:00. ONE SOURCE: Invardia's
    platform (operator 2026-10-06: "we are not having separate platforms like a si storage account for si updates. one
    solution: invardia"; framework UPDATE-1.7: "Solution (si, pim) decides WHAT version and WHICH Ring to release in
    updates, Invardia relays only"). SecurityInsight releases a build to a ring (setup\Publish-SIRelease.ps1 -Ring <n>);
    this job pulls what its OWN ring got, verifies it and applies it (_shared/SI-UpdaterInvardia.ps1):
      1. sign in ONCE with SecurityInsight's own REST token client (#521: no az CLI in the image, no PowerShell module, no
         fallback) as the job's managed identity (SI_UPDATER_AUTH = ManagedIdentity) or the SPN by certificate
         (/si/setup/_shared/SI-UpdateRest.ps1); every Azure call after it is ARM / data-plane REST;
      2. the licence request step (#239) and the customer's two switches;
      3. the install key (claimed automatically when missing), then the signed manifests of kind templates and code for
         the environment's ring (SI_UPDATER_RING, else cfg.InstallState 'Ring'; no ring = no pull, said in plain words):
         signature against the embedded keys, product, kind, the SIGNED ring, sequence (no replay), size + SHA-256;
      4. a newer code release: wait while a manual deploy or an SI run is in progress, then the archive is extracted and
         its setup/Invoke-SIContainerUpdate.ps1 -Apply builds + rolls every SI job (the database step and the template gate
         first, restore on failure), then the Pro web app + MCP server, the record of what now runs (tags si-installed /
         si-installed-commit) and, LAST, the updater's own job (_shared/SI-UpdaterSelf.ps1; SI_UPDATER_SELF_UPDATE=0 = off).
         #416 the fast roll (_shared/SI-UpdaterFastRoll.ps1 + the release's setup/_shared/SI-FastRoll.ps1): every other
         image is queued in parallel with the engine roll (web / MCP only when their sources changed, the updater as a
         thin layer on its cached base), the jobs swap by one ARM PATCH each, all at once, verified;
      5. a newer template pack: verified, gated (a pack that changes templates in force is held for an Admin).

    THE COMMUNITY EDITION (SI #750 (b), owner 2026-10-18: "the IN-CLOUD UPDATER, as Pro, on the community channel"): an image
    WITHOUT the Invardia client takes the signed Community channel instead (_shared/SI-UpdaterCommunity.ps1): ring 2 or 3,
    the same signature / sequence / size + SHA-256 checks, then the SAME roll (run gate, database step, engine roll, web app,
    the updater last). No licence request, no install key, no report to Invardia (Get-SIUpdaterEditionPath decides).

    SI's OWN UPDATE FEED IS RETIRED (2026-10-06): no storage container, no channel.json, no feed link. An updater still
    configured for it (SI_UPDATER_SOURCE = feed, or SI_UPDATER_SOURCE_URL without SI_UPDATER_SOURCE = invardia) changes
    NOTHING -- no sign-in, no read -- and says how to move (setup\Install-SIUpdaterJob.ps1 -Source invardia).

    Runs on PowerShell 7 in the container; every decision is 5.1-compatible so the offline gate exercises it.

    Configuration (environment): SI_UPDATER_TENANT_ID, SI_UPDATER_CLIENT_ID, SI_UPDATER_SUBSCRIPTION_ID,
      SI_UPDATER_RESOURCE_GROUP, SI_UPDATER_ACR, SI_UPDATER_KEY_VAULT, [SI_UPDATER_RING = 0..3], [SI_UPDATER_AUTH],
      [SI_UPDATER_CERT_PFX_B64 + SI_UPDATER_CERT_PASSWORD (certificate sign-in)], [SI_UPDATER_BLOCK = e.g. 'engine-image'],
      [SI_UPDATER_PRO_SQL_SERVER, SI_UPDATER_PRO_SQL_DATABASE], [SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT],
      [SI_UPDATER_ACCEPT_MANUAL_STEP], [SI_UPDATER_WAIT_MINUTES], [SI_UPDATER_SELF_UPDATE], [SI_UPDATER_INVARDIA_BASE_URL].
    THE CUSTOMER'S SWITCHES (owner decision 2026-10-05; engine/_shared/SI-ProAutomation.ps1), both ON by default:
      SI_LicenseRequest_Auto    (job: SI_LICENSE_REQUEST_AUTO)    the licence request step; off = Invardia is not asked.
      SI_InvardiaUpdate_Enabled (job: SI_INVARDIA_UPDATE_ENABLED) the Invardia pull; off = no install key claim, no
                                manifest, nothing applied -- the run says so and ends.
      The Pro settings database (the Settings page) wins over the job's environment; a database that cannot be read
      skips both steps for that run.
#>
[CmdletBinding()]
param([switch]$DefineOnly)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterCore.ps1')
. (Join-Path $PSScriptRoot '_shared/SI-UpdateFeed.ps1')
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterLicence.ps1')
# #350: the deploy-lock check (a manual deploy marks the updater job) -- used by the Invardia path
. (Join-Path $PSScriptRoot '_shared/SI-UpdateChannel.ps1')
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterChannel.ps1')
# #350 (c): the updater's own image, rolled LAST from the same verified release (both editions)
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterSelf.ps1')
# #416: the fast roll on the update path -- every other image queued in parallel with the engine roll, waited for later
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterFastRoll.ps1')
# 2026-10-23: the run gate -- nothing changes the install while a pipeline run is going; the wait is handed to caj-si-flow
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterRunGate.ps1')
# #947 (owner 2026-10-29): a bound on the wait -- after 6 hours a run that started on an older version is cancelled and the update installed
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterWaitBound.ps1')
# #750 (b): the roll steps both editions share (pre-roll, post-roll, self-retry, the state row, the running release)
. (Join-Path $PSScriptRoot '_shared/SI-UpdaterRollSteps.ps1')
# Pro: the web app + MCP server roll (absent from the Community edition)
$siWebRoll = Join-Path $PSScriptRoot '_shared/SI-UpdaterWebApp.ps1'
if (Test-Path -LiteralPath $siWebRoll) { . $siWebRoll }
# Pro: the database step of an update -- the release's schema and grants BEFORE anything is rolled (#352, UPDATE-1.6 (j))
$siDbStep = Join-Path $PSScriptRoot '_shared/SI-UpdaterDatabase.ps1'
if (Test-Path -LiteralPath $siDbStep) { . $siDbStep }
# Pro: the secret hand-over -- the web app never writes a secret; this run stores what it handed over (SI-UpdaterSecretHandover.ps1)
$siHandover = Join-Path $PSScriptRoot '_shared/SI-UpdaterSecretHandover.ps1'
if (Test-Path -LiteralPath $siHandover) { . $siHandover }
# The two switches the customer has (automatic licence request, Pro updates from Invardia -- both ON by default) and the
# licence notice: engine/_shared/SI-ProAutomation.ps1, carried under /si (from a checkout: this solution's copy).
$siAutoRoot = Find-SIUpdaterLicenceRoot
# #521: Azure over REST only -- the one sign-in and seam (SI-UpdateRest.ps1, over engine/_shared/SI-AzRest.ps1 and
# auth/SI-ManagedIdentity.ps1) and the registry's own build (SI-AcrBuild.ps1), carried under /si (from a checkout: this
# solution's copy). The image has no Azure CLI. (The fast roll stays the RELEASE's: _shared/SI-UpdaterFastRoll.ps1.)
# SI-NightlySchedule.ps1 (owner 2026-10-21): the update runs at 18:30 in its Azure region's zone -- the job's UTC ticks, the other one ends here
# #911 (e): SI-UpdateWatch.ps1 -- a step with no log line for 20 minutes says "still working: <step>" (never mistaken for a hang)
foreach ($siUpdLib in 'SI-UpdateRest.ps1', 'SI-AcrBuild.ps1', 'SI-NightlySchedule.ps1', 'SI-UpdateWatch.ps1') {
    if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'setup', '_shared', $siUpdLib)))) { . ([IO.Path]::Combine($siAutoRoot, 'setup', '_shared', $siUpdLib)) }
}
if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-ProAutomation.ps1')))) {
    . ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-ProAutomation.ps1'))
}
# #427: every failure of this run reaches Invardia's uplink (_shared/SI-UpdaterTelemetry.ps1 records them; the release's
# engine/_shared/SI-TelemetrySend.ps1 sends them). A missing or broken file only means no report -- never a failed update.
try { . (Join-Path $PSScriptRoot '_shared/SI-UpdaterTelemetry.ps1') } catch { }
# #506: the run's stages to Invardia (framework §8.8 UPDATE-TRACK) -- a missing or broken file only means no tracking
try { . (Join-Path $PSScriptRoot '_shared/SI-UpdaterRunTrack.ps1') } catch { }
if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-TelemetrySend.ps1')))) {
    try { . ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-TelemetrySend.ps1')) } catch { }
}
# #308: the install's update ring, recorded in the Pro database whenever this run resolves one (engine/_shared/SI-InstallRing.ps1).
if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-InstallRing.ps1')))) {
    . ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-InstallRing.ps1'))
}
# CR5 step 1 (framework §12.11c item 6, #655): this install's own resource names from its record, never a literal
# (engine/_shared/SI-InstallNames.ps1; without it, the variables and today's names as before).
if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-InstallNames.ps1')))) {
    . ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-InstallNames.ps1'))
}
# 2026-10-23: the updater job's start body with SI_UPDATER_MODE (the second update) and "is an updater running" -- the same
# helpers the heartbeat's "update now" uses too (engine/_shared/SI-UpdaterStart.ps1, every edition)
if ($siAutoRoot -and (Test-Path -LiteralPath ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-UpdaterStart.ps1')))) {
    . ([IO.Path]::Combine($siAutoRoot, 'engine', '_shared', 'SI-UpdaterStart.ps1'))
}

function Get-SIUpdaterInstallName {
    <#
        The name of one part of this install the updater acts on (-Role web | mcp | updater): the install record this run
        resolved ($global:SI_InstallNames, Invoke-SIUpdaterInstallNames), then the job's variable, then today's name. An
        image without SI-InstallNames.ps1: the variable, then today's name -- exactly as before.
    #>
    param([Parameter(Mandatory)][ValidateSet('web', 'mcp', 'updater')][string]$Role, [hashtable]$Env = @{})
    if (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue) { return (Get-SIInstallName -Role $Role -Env $Env) }
    $var = @{ web = 'SI_UPDATER_WEB_APP'; mcp = 'SI_UPDATER_MCP_APP'; updater = 'SI_UPDATER_JOB_NAME' }[$Role]
    $v = if ($Env.ContainsKey($var)) { "$($Env[$var])".Trim() } else { "$([Environment]::GetEnvironmentVariable($var))".Trim() }
    if ($v) { return $v }
    @{ web = 'ca-si-management'; mcp = 'ca-si-mcp'; updater = 'caj-si-updater' }[$Role]
}

function Invoke-SIUpdaterInstallNames {
    <#
        CR5 step 1 (framework §12.11c item 6, #655): THE INSTALL RECORD. The names this install runs with -- the web app, the
        MCP server and this updater job -- from what the job was set up with (SI_UPDATER_WEB_APP / SI_UPDATER_MCP_APP /
        SI_UPDATER_JOB_NAME, else this execution's own job name CONTAINER_APP_JOB_NAME for the updater), else what is already
        recorded, else today's name; stored in cfg.InstallState 'InstallNames' only when it changes, and kept for this process
        in $global:SI_InstallNames (every later lookup of the run, and the release's own update scripts, read it). Existing
        installs record TODAY's names: nothing is renamed, every lookup answers what it answered before. Without a Pro
        database (Community) nothing is stored. Never throws, never fails the run. Returns the record (or $null).
    #>
    param([hashtable]$Env = @{}, $Store)
    try {
        if (-not (Get-Command -Name New-SIInstallNamesRecord -ErrorAction SilentlyContinue)) { return $null }
        $read = { param($k) if ($Env.ContainsKey($k)) { "$($Env[$k])".Trim() } else { "$([Environment]::GetEnvironmentVariable($k))".Trim() } }
        $cur = if ($Store) { Read-SIInstallNamesRecord -Store $Store } else { $null }
        $names = @{}
        foreach ($role in 'web', 'mcp', 'updater') {
            $given = & $read (Get-SIInstallNameVariable -Role $role)
            if ($role -eq 'updater' -and -not (Test-SIInstallNameValue $given)) { $given = & $read 'CONTAINER_APP_JOB_NAME' }
            $names[$role] = if (Test-SIInstallNameValue $given) { $given }
                            elseif ($null -ne $cur) { Get-SIInstallName -Role $role -Record $cur -Env $Env }
                            else { Get-SIInstallName -Role $role -NoRecord -Env $Env }
        }
        $rec = New-SIInstallNamesRecord -Names $names -Current $cur
        $global:SI_InstallNames = [pscustomobject]$rec.Record
        if ($Store -and $rec.Changed) {
            if (Save-SIInstallNamesRecord -Store $Store -Value $rec.Value) { Write-UpdLog ("install names recorded: web app {0}, MCP server {1}, updater {2}" -f $names.web, $names.mcp, $names.updater) }
            else { Write-UpdLog 'WARNING: the install names could not be recorded in the Pro database -- this run uses them, the next run tries again' }
        }
        $global:SI_InstallNames
    } catch { $null }
}

function Write-UpdLog([string]$m) {
    Write-Host ("[{0:u}] {1}" -f [datetime]::UtcNow, $m)
    # #506: a log line after the step moved = the stage moved (silent when no run is tracked)
    if (Get-Command -Name Step-SIUpdateTrack -ErrorAction SilentlyContinue) { Step-SIUpdateTrack }
    # #911 (e) / (d): the watch hears the line; the install's lock (when this update holds it) is beaten with the step
    if (Get-Command -Name Set-SIUpdateWatchLine -ErrorAction SilentlyContinue) { Set-SIUpdateWatchLine -Step ("$global:SI_UpdaterStep") }
    if (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterLockBeat -What ("$global:SI_UpdaterStep") }
}
# #427: records a failure of this run for Invardia's uplink (SI-UpdaterTelemetry.ps1); without that file, nothing
function Add-SIUpdaterFailureIf([string]$Step, [string]$Text, [string]$Code = '') {
    $c = Get-Command -Name Add-SIUpdaterFailure -ErrorAction SilentlyContinue
    if (-not $c) { return }
    # SUP-2026-00198: the failure's catalogue code (si-upd-0803 / 0804 / 0805) rides along where the recorder knows it
    if ("$Code".Trim() -and $c.Parameters.ContainsKey('Code')) { Add-SIUpdaterFailure -Step $Step -Text $Text -Code $Code } else { Add-SIUpdaterFailure -Step $Step -Text $Text }
}

# ---- external calls: one small function each, so the run is testable end to end ---------------------
# #521 NO az CLI: SecurityInsight's own REST token client (/si/setup/_shared/SI-UpdateRest.ps1). The image's own steps call
# ARM through Invoke-SIUpdaterArm; the release's build / roll libraries take the seam itself (Get-SIUpdaterRest).
$script:SIUpdaterArmApi = '2025-07-01'   # Microsoft.App jobs / containerApps: the fast roll's own api-version (one schema)

function Get-SIUpdaterRest {
    <# The REST seam of this run (setup/_shared/SI-UpdateRest.ps1) -- after Connect-SIUpdaterRest. Tests replace it. #>
    New-SIUpdateRestSeam
}

function Connect-SIUpdaterRest {
    <#
        THE ONE SIGN-IN of the run (framework 12.17: one connect path, no az login, no fallback): the job's managed identity
        (SI_UPDATER_AUTH = ManagedIdentity, SI_UPDATER_CLIENT_ID) or the SPN by certificate (SI_UPDATER_CERT_PFX_B64 /
        _PASSWORD / SI_UPDATER_TENANT_ID), recorded in SecurityInsight's REST client. Returns the identity in plain words.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)][string]$SubscriptionId)
    Connect-SIUpdateRest -SubscriptionId $SubscriptionId -Env $Env
}

function Invoke-SIUpdaterArm {
    <#
        THE image's ARM seam: one call through the REST client. -Path '/subscriptions/...' (or a full URL); -ApiVersion
        (default: the Container Apps one). -List: every item (nextLink). -AllowNotFound: a 404 is $null. Anything else that
        is not a success THROWS '<what> failed: HTTP <code>: <what Azure said>'.
    #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [string]$ApiVersion = $script:SIUpdaterArmApi, $Body, [switch]$AllowNotFound, [switch]$List)
    $rest = Get-SIUpdaterRest
    $uri = Get-SIArmUri -Path $Path -ApiVersion $ApiVersion
    if ($List) { return @(Get-SIRestList -Rest $rest -Uri $uri) }
    $b = if ($null -ne $Body -and -not ($Body -is [string])) { ConvertTo-Json -InputObject $Body -Depth 60 -Compress } else { $Body }
    Invoke-SIRestJson -Rest $rest -Method $Method -Uri $uri -Body $b -AllowNotFound:$AllowNotFound -Headers @{ 'Content-Type' = 'application/json' }
}

function Get-SIUpdaterRgPath {
    <# PURE. /subscriptions/<sub>/resourceGroups/<rg>/providers/<provider path>. #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$Provider)
    '/subscriptions/{0}/resourceGroups/{1}/providers/{2}' -f $SubscriptionId, $ResourceGroup, $Provider
}

function Get-SIUpdaterRegistry {
    <#
        The install's registry as ARM knows it: @{ id; name; resourceGroup; loginServer } (what `az acr show` gave): looked up
        in -ResourceGroup, else among every registry of the subscription. Throws when it is not found.
    #>
    param([Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId, [string]$ResourceGroup)
    $r = $null
    if ($ResourceGroup) { $r = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.ContainerRegistry/registries/' + $AcrName)) -ApiVersion '2023-07-01' -AllowNotFound }
    if (-not $r) { $r = @(Invoke-SIUpdaterArm -Path ('/subscriptions/{0}/providers/Microsoft.ContainerRegistry/registries' -f $SubscriptionId) -ApiVersion '2023-07-01' -List | Where-Object { $_ -and ([string]$_.name) -ieq $AcrName }) | Select-Object -First 1 }
    if (-not $r) { throw ("the container registry '{0}' was not found in subscription {1} (or this identity cannot read it)" -f $AcrName, $SubscriptionId) }
    $rg = if ([string]$r.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $ResourceGroup }
    [pscustomobject]@{ id = [string]$r.id; name = [string]$r.name; resourceGroup = $rg
        loginServer = $(if ($r.properties -and $r.properties.PSObject.Properties['loginServer']) { [string]$r.properties.loginServer } else { ('{0}.azurecr.io' -f $AcrName.ToLowerInvariant()) }) }
}

function Get-SIUpdaterJobs {
    <# Every Container Apps job of the resource group (ARM shape, the fast roll's api-version). #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs') -List | Where-Object { $_ })
}

function Get-SIUpdaterContainerApp {
    <# One container app (ARM shape), $null when there is none. #>
    param([AllowEmptyString()][string]$App, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    if (-not $App) { return $null }
    Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/containerApps/' + $App)) -AllowNotFound
}

function Set-SIUpdaterImage {
    <#
        Points a Container Apps job or app's FIRST container at -Image (what `az containerapp (job) update --image` did): ONE
        read-modify-write -- the resource read, its whole template sent back by ARM PATCH with only that image changed
        (New-SITemplateImagePatchBody); never the configuration. Throws with what Azure said (a 409 = an operation in flight).
    #>
    param([Parameter(Mandatory)][ValidateSet('jobs', 'containerApps')][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$Image, [double]$MinCpu = 0, [double]$MinMemoryGi = 0)
    $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/{0}/{1}' -f $Kind, $Name)
    # #911 (b): a 409 "an operation is in progress" is WAITED OUT -- the resource's provisioningState polled (bounded: at most
    # $script:SIUpdaterBusyWaitMinutes) and the PATCH sent again on a fresh read; never a failure at the first refusal
    Invoke-SIUpdaterPatchWhenFree -Name $Name -Read { Invoke-SIUpdaterArm -Path $path } `
        -Patch { param($now) $null = Invoke-SIUpdaterArm -Method PATCH -Path $path -Body (New-SITemplateImagePatchBody -Resource $now -Image $Image -MinCpu $MinCpu -MinMemoryGi $MinMemoryGi) }
}

$script:SIUpdaterBusyWaitMinutes = 10
$script:SIUpdaterBusyPollSeconds = 15

function Test-SIUpdaterOperationInProgress {
    <# PURE. #911: is an ARM refusal "another operation is in progress on this resource" (HTTP 409 ContainerAppOperationInProgress
       / OperationInProgress / AnotherOperationInProgress, or a 409 that says an operation is in progress)? #>
    param([AllowNull()][AllowEmptyString()][string]$Message)
    [bool]("$Message" -match '(?i)ContainerAppOperationInProgress|AnotherOperationInProgress|\bOperationInProgress\b|HTTP 409\b.*operation.*in progress|operation .*is in progress')
}

function Invoke-SIUpdaterPatchWhenFree {
    <#
        #911 (b): ONE read-modify-write PATCH (-Read { } -> the resource, -Patch { param($Resource) }) that waits out "an
        operation is in progress" (Test-SIUpdaterOperationInProgress): the resource's properties.provisioningState is polled
        every -PollSeconds while it is InProgress / Updating / Provisioning / Deleting (and at least once), then it is read
        again and the PATCH sent again -- bounded by -WaitMinutes in all. Past it: the 409 is thrown with how long it was
        waited. Any other error is thrown at once. -Sleep / -Now / -Log are seams.
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Read, [Parameter(Mandatory)][scriptblock]$Patch,
          [double]$WaitMinutes = $script:SIUpdaterBusyWaitMinutes, [int]$PollSeconds = $script:SIUpdaterBusyPollSeconds,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Log = { param($m) Write-UpdLog $m })
    $t0 = & $Now; $tries = 0
    while ($true) {
        $res = & $Read
        if (-not $res) { throw ("{0} was not found" -f $Name) }
        try { & $Patch $res; return }
        catch {
            $msg = [string]$_.Exception.Message
            if (-not (Test-SIUpdaterOperationInProgress $msg)) { throw }
            $tries++
            $waited = ((& $Now) - $t0).TotalMinutes
            if ($waited -ge $WaitMinutes) { throw ("{0}: Azure still answered 'an operation is in progress' after {1:N0} min and {2} attempt(s) -- {3}" -f $Name, $waited, $tries, $msg) }
            & $Log ("{0}: another operation is in progress on it (409) -- waiting for it to finish, then the change is sent again ({1})" -f $Name, $tries)
            do {
                & $Sleep $PollSeconds
                $ps = ''; try { $cur = & $Read; if ($cur -and $cur.properties) { $ps = [string]$cur.properties.provisioningState } } catch { $ps = '' }
                $waited = ((& $Now) - $t0).TotalMinutes
            } while ($ps -in @('InProgress', 'Updating', 'Provisioning', 'Deleting', 'Creating') -and $waited -lt $WaitMinutes)
        }
    }
}

function Update-SIUpdaterTags {
    <# Tags on a resource as a MERGE (no other tag changes, no new revision): ARM PATCH <id>/providers/Microsoft.Resources/tags/default. #>
    param([Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][hashtable]$Tags)
    $t = [ordered]@{}; foreach ($k in @($Tags.Keys | Sort-Object)) { $t[[string]$k] = [string]$Tags[$k] }
    $body = ConvertTo-Json -InputObject ([ordered]@{ operation = 'Merge'; properties = [ordered]@{ tags = $t } }) -Depth 5 -Compress
    $null = Invoke-SIUpdaterArm -Method PATCH -Path ($ResourceId.TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -ApiVersion '2021-04-01' -Body $body
}

function Test-SIUpdaterImageTag {
    <# Is <repo>:<tag> in the install's registry? The registry's own data plane (Test-SIAcrManifest). Never throws: $false = build it. #>
    param([Parameter(Mandatory)][string]$LoginServer, [Parameter(Mandatory)][string]$Repo, [Parameter(Mandatory)][string]$Tag)
    try { [bool](Test-SIAcrManifest -Rest (Get-SIUpdaterRest) -LoginServer $LoginServer -Repo $Repo -Tag $Tag) } catch { $false }
}

function Get-SIUpdaterSqlToken {
    <# An Entra token for Azure SQL as this run's identity (the REST client). #>
    [string](Get-SIAzureToken -Resource 'https://database.windows.net/')
}

function Get-SIUpdaterAuthMode {
    <# PURE. SI_UPDATER_AUTH: 'ManagedIdentity' or 'Certificate' (the default). Anything else is refused. #>
    param([AllowEmptyString()][string]$Auth)
    $a = "$Auth".Trim()
    if (-not $a -or $a -ieq 'Certificate') { return 'Certificate' }
    if ($a -ieq 'ManagedIdentity') { return 'ManagedIdentity' }
    throw "SI_UPDATER_AUTH must be 'ManagedIdentity' or 'Certificate', not '$Auth'."
}

function Expand-SIUpdaterSolution {
    <# Extract ONLY SOLUTIONS/SecurityInsight/ from a GitHub zipball into -Destination (clean). Returns the file count. #>
    param([Parameter(Mandatory)][string]$ZipPath, [Parameter(Mandatory)][string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (Test-Path -LiteralPath $Destination) { Remove-Item -LiteralPath $Destination -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    $n = 0
    try {
        foreach ($e in $zip.Entries) {
            # GitHub zipballs use '/'; .NET Framework's own zip writer uses '\' -- accept both.
            $name = $e.FullName -replace '\\', '/'
            $i = $name.IndexOf('/'); if ($i -lt 0) { continue }
            $rel = $name.Substring($i + 1)
            if (-not $rel.StartsWith('SOLUTIONS/SecurityInsight/') -or $rel.EndsWith('/')) { continue }
            $sub = $rel.Substring('SOLUTIONS/SecurityInsight/'.Length)
            if ($sub.Contains('..')) { continue }
            $dst = Join-Path $Destination $sub
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dst, $true)
            $n++
        }
    } finally { $zip.Dispose() }
    return $n
}

function New-SIUpdaterProStore {
    <#
        The Pro settings database as the updater's identity (an Entra token from the REST client), in the store shape the
        release's own pro-settings code takes: @{ Name; Invoke(sql, params, mode) }. A connection per call.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$SubscriptionId)
    $token = Get-SIUpdaterSqlToken
    if (-not $token) { throw 'no access token for the Pro database' }
    $cs = 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $Server, $Database
    $invoke = {
        param([string]$sql, $p, [string]$mode)
        $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
        $cn.AccessToken = $token
        try {
            $cn.Open()
            $cmd = $cn.CreateCommand(); $cmd.CommandText = $sql; $cmd.CommandTimeout = 0
            if ($p) { foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [System.DBNull]::Value } else { $p[$k] })) } }
            if ($mode -eq 'reader') {
                $rd = $cmd.ExecuteReader()
                $out = New-Object System.Collections.Generic.List[object]
                while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) }
                $rd.Close(); , $out.ToArray()
            } elseif ($mode -eq 'scalar') { $cmd.ExecuteScalar() } else { [void]$cmd.ExecuteNonQuery() }
        } finally { $cn.Dispose() }
    }.GetNewClosure()
    # Server / Database / GetToken: the database step's one-connection transaction per schema file (#352)
    [pscustomobject]@{ Name = ('{0}/{1}' -f $Server, $Database); Invoke = $invoke; Server = $Server; Database = $Database; GetToken = { $token }.GetNewClosure() }
}

function Invoke-SIUpdaterTemplateGate {
    <#
        THE TEMPLATE GATE ON THE UPDATE PATH (adopted from PIM4EntraPS -- BUG-55: an image roll silently changed 217 of
        325 policies; BUG-223: a path that bypassed the gate). For a Pro install (the Pro database is configured on the
        job) the approved release's OWN setup/Publish-SITemplates.ps1 plans its templates against the install's recorded
        template fingerprint. When the content in force would change, the update is HELD -- no image roll, no publish --
        until SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT names exactly the fingerprint printed here. The publish itself runs
        after the roll (Publish-SIUpdaterTemplates) and records the fingerprint only after it verified the write.
        Returns @{ Proceed; Accept; Fingerprint; Reason; Plan }. -Families: tests only.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)]$Store, [string]$AcceptFingerprint, [string[]]$Families)
    $publish = Join-Path $SIRoot 'setup/Publish-SITemplates.ps1'
    if (-not (Test-Path -LiteralPath $publish)) {
        return [pscustomobject]@{ Proceed = $true; Accept = $false; Fingerprint = ''; Reason = 'this release publishes no templates'; Plan = $null }
    }
    $a = @{ InstallPath = $SIRoot; Store = $Store; PassThru = $true }
    if ($Families) { $a.Families = $Families }
    # A release that can stage its templates puts them in cfg.TemplatePackStaged, so a held change can be reviewed and
    # accepted in the web app's Template releases page (an older release has no -Stage).
    if ((Get-Command -Name $publish).Parameters.ContainsKey('Stage')) { $a.Stage = $true; $a.StageOrigin = 'shipped' }
    $plan = & $publish @a | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
    if (-not $plan) { throw 'the release''s template plan returned nothing' }
    $short = if ($plan.Fingerprint) { $plan.Fingerprint.Substring(0, [Math]::Min(12, $plan.Fingerprint.Length)) } else { '' }
    if (-not $plan.Moved) {
        return [pscustomobject]@{ Proceed = $true; Accept = $false; Fingerprint = $plan.Fingerprint; Reason = $plan.Reason; Plan = $plan }
    }
    # #405: a release whose templates are classified (the split install) installs its fix and default templates WITH the
    # code -- never held; the release's own publish accepts them itself (a customer's edits are overrides, never changed)
    if ($plan.PSObject.Properties['Auto'] -and $plan.Auto -and $plan.Allowed) {
        return [pscustomobject]@{ Proceed = $true; Accept = $false; Fingerprint = $plan.Fingerprint
            Reason = ('the templates of this release are installed with the code ({0} template(s) change; your own changes are kept)' -f @($plan.Changes).Count); Plan = $plan }
    }
    if ($AcceptFingerprint -and $AcceptFingerprint.Length -ge 12 -and $plan.Fingerprint.StartsWith($AcceptFingerprint, [StringComparison]::OrdinalIgnoreCase)) {
        return [pscustomobject]@{ Proceed = $true; Accept = $true; Fingerprint = $plan.Fingerprint; Reason = ('template change accepted for fingerprint {0}' -f $short); Plan = $plan }
    }
    [pscustomobject]@{ Proceed = $false; Accept = $false; Fingerprint = $plan.Fingerprint
        Reason = ('HELD: this release changes {0} configuration template(s) in force (fingerprint {1}). Nothing was rolled or written. Review the change, then set SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT = {1} on the updater job.' -f @($plan.Changes).Count, $short)
        Plan = $plan }
}

function Publish-SIUpdaterTemplates {
    <# After a successful roll: the release's templates, through its own publish script (the gate runs again there). #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)]$Store, [string]$AcceptFingerprint, [switch]$Accept, [string[]]$Families)
    $a = @{ InstallPath = $SIRoot; Store = $Store; PassThru = $true; Apply = $true }
    if ($Accept) { $a.AcceptTemplateChange = $true; $a.AcceptFingerprint = $AcceptFingerprint }
    if ($Families) { $a.Families = $Families }
    & (Join-Path $SIRoot 'setup/Publish-SITemplates.ps1') @a | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
}

function Read-SIUpdaterInstalledPack {
    <# The template pack the install recorded (cfg.InstallState 'TemplatePack'), '' when none. #>
    param([Parameter(Mandatory)]$Store)
    $rows = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = 'TemplatePack'" @{} 'reader' | ForEach-Object { $_ })
    if ($rows.Count) { $v = $rows[0]; if ($v -is [System.Collections.IDictionary]) { return ([string]$v['Value']).Trim() } else { return ([string]$v.Value).Trim() } }
    ''
}

function Invoke-SIUpdaterTemplatePackGate {
    <#
        One VERIFIED template pack file through the INSTALLED release's own publish script (-SIRoot): staged in
        cfg.TemplatePackStaged and planned against the install -- the same fingerprint gate for every source (the feed's
        template channel, the `templates` manifest kind on Invardia's update platform). Content in force does not move -> published (verified, recorded);
        it moves -> HELD until the web app's Template releases page or SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT accepts it.
        Returns @{ Channel; Action = published | held; Version; Fingerprint; Reason }. Throws when the publish fails.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$PackFile, [Parameter(Mandatory)][string]$PackVersion,
          [AllowEmptyString()][string]$RingKey, [string]$Origin = 'feed', [string]$Deployed, [string]$AcceptFingerprint)
    $out = { param($act, $fp, $why) [pscustomobject]@{ Channel = $true; Action = $act; Version = $PackVersion; Fingerprint = $fp; Reason = $why } }
    $publish = Join-Path $SIRoot 'setup/Publish-SITemplates.ps1'
    if (-not (Test-Path -LiteralPath $publish) -or -not (Get-Command -Name $publish).Parameters.ContainsKey('PackPath')) {
        return (& $out 'held' '' ("HELD: template pack {0} is approved, but SecurityInsight {1} cannot take template packs -- update the code first" -f $PackVersion, $Deployed))
    }
    $plan = & $publish -InstallPath $SIRoot -Store $Store -PackPath $PackFile -Stage -StageOrigin $Origin -StageRing $RingKey -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
    if (-not $plan) { throw 'the template pack plan returned nothing' }
    $fp = [string]$plan.SelectionFingerprint
    $short = if ($fp) { $fp.Substring(0, [Math]::Min(12, $fp.Length)) } else { '' }
    $accepted = $AcceptFingerprint -and $AcceptFingerprint.Length -ge 12 -and $fp.StartsWith($AcceptFingerprint, [StringComparison]::OrdinalIgnoreCase)
    # owner decision 2026-10-11: a pack that is in force already (ring 1's direct deploy put its content in) -- nothing to do
    if ($plan.PSObject.Properties['Decision'] -and [string]$plan.Decision -eq 'installed' -and -not $accepted) {
        return (& $out 'published' $fp ('{0}' -f $plan.Reason))
    }
    # #405: a template pack held by the customer's switch, rolled back from, or waiting for newer code -- say exactly that
    if (-not $plan.Allowed -and -not ($accepted -and [string]$plan.Decision -ne 'wait-code') -and $plan.PSObject.Properties['Decision'] -and [string]$plan.Decision -in @('hold', 'wait-code')) {
        return (& $out 'held' $fp ('HELD: {0}. It is staged on the Template releases page.' -f $plan.Reason))
    }
    if (-not $plan.Allowed -and -not $accepted) {
        return (& $out 'held' $fp ("HELD: template pack {0} changes {1} template(s) in force{2} (selection fingerprint {3}). Nothing was written. It is staged: release it in the web app's Template releases page, or set SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT = {3} on the updater job." -f $PackVersion, @($plan.Changes).Count, $(if ($plan.Affected) { ", $($plan.Affected) of them overridden or switched off by you" } else { '' }), $short))
    }
    $a = @{ InstallPath = $SIRoot; Store = $Store; PackPath = $PackFile; Apply = $true; PassThru = $true }
    if ($accepted) { $a.AcceptFingerprint = $AcceptFingerprint }
    $pub = & $publish @a | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
    if (-not $pub -or $pub.Mode -ne 'applied') { throw ("template pack {0} NOT published: {1}" -f $PackVersion, $(if ($pub) { $pub.Reason } else { 'no result' })) }
    # #405 + owner decision 2026-10-11: a template pack installed automatically (every pack, not only Microsoft content) says so
    $auto = $plan.PSObject.Properties['Auto'] -and $plan.Auto -and -not $accepted
    & $out 'published' $fp ("template pack {0} {1} and verified ({2} change(s){3})" -f $PackVersion, $(if ($auto) { 'installed automatically' } else { 'published' }), $pub.Written, $(if ($accepted) { ', accepted by fingerprint' } else { '' }))
}

function Test-SIUpdaterTemplateSplit {
    <#
        #405: does a release (-SIRoot) run the SPLIT template install? Its own publish script says so in a plan (nothing
        written, nothing staged): Split = its shipped classification is present and marked reviewed. Then its code roll
        installs its fix and default templates even where the templates follow a template channel (that channel now
        carries only Microsoft content, and the release's publish keeps a newer pack in force). A release from before
        #405 has no Split -- $false.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)]$Store)
    $publish = Join-Path $SIRoot 'setup/Publish-SITemplates.ps1'
    if (-not (Test-Path -LiteralPath $publish)) { return $false }
    try { $plan = & $publish -InstallPath $SIRoot -Store $Store -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1 }
    catch { return $false }
    [bool]($plan -and $plan.PSObject.Properties['Split'] -and $plan.Split)
}

function Save-SIUpdaterSqlTierRow {
    <#
        #507: the release's SQL database size line (setup\Invoke-SIContainerUpdate.ps1 step 7, $global:SI_UpdateSqlTier) into
        cfg.InstallState 'SqlTier' (at most 400 characters), with the time. Never throws: $true written, $false not.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    $v = "$Line".Trim(); if (-not $v) { return $false }
    if ($v.Length -gt 400) { $v = $v.Substring(0, 397) + '...' }
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'SqlTier')
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'SqlTier';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'SqlTier', @Value, NULL, @By);
    COMMIT;
END
'@
    try { $null = & $Store.Invoke $sql ([ordered]@{ Value = $v; By = 'caj-si-updater' }) 'nonquery'; Write-UpdLog $v; $true }
    catch { Write-UpdLog ("WARNING: the SQL database size could not be recorded in the Pro database: {0}" -f $_.Exception.Message); $false }
}

function ConvertTo-SIUpdaterPipelineScheduleValue {
    <# PURE. The update's pipeline-schedule check (Invoke-SIJobOrchestrationRepair) as the cfg.InstallState 'PipelineSchedule'
       value: {"state":"ok|repaired|would-repair|failed","why":"...","checkedUtc":"..."} (why at most 300 characters). '' for none. #>
    param([AllowNull()]$Result, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $Result -or -not $Result.PSObject.Properties['State'] -or -not "$($Result.State)".Trim()) { return '' }
    $why = "$($Result.Why)".Trim(); if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    ([ordered]@{ state = "$($Result.State)"; why = $why; checkedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress)
}

function Save-SIUpdaterInstallStateValue {
    <# One cfg.InstallState row (-Name, -Value) written by the updater. Never throws: $true written, $false not. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][ValidateSet('PipelineSchedule', 'SecretHandover', 'EngineFingerprint', 'CommunityUpdateState', 'UpdateState')][string]$Name, [AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $false }
    $sql = @'
IF OBJECT_ID('cfg.InstallState') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name)
        UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@Name, @Value, NULL, @By);
    COMMIT;
END
'@
    try { $null = & $Store.Invoke $sql ([ordered]@{ Name = $Name; Value = "$Value"; By = 'caj-si-updater' }) 'nonquery'; $true }
    catch { Write-UpdLog ("WARNING: {0} could not be recorded in the Pro database: {1}" -f $Name, $_.Exception.Message); $false }
}

function Save-SIUpdaterPipelineScheduleRow {
    <# The pipeline-schedule check into cfg.InstallState 'PipelineSchedule' -- the heartbeat's setup report reads it (job-layout
       = wrong while the pipeline is not scheduled and no job has its own timer). Never throws: $true written, $false not. #>
    param([Parameter(Mandatory)]$Store, [AllowNull()]$Result)
    Save-SIUpdaterInstallStateValue -Store $Store -Name 'PipelineSchedule' -Value (ConvertTo-SIUpdaterPipelineScheduleValue -Result $Result)
}

function Save-SIUpdaterEngineFingerprint {
    <#
        CR4 (#654): the engine fingerprint of the code just installed (-SIRoot: the extracted, verified release) into
        cfg.InstallState 'EngineFingerprint' -- { hash, version, since, strictFrom, strictVersion } (engine\_shared\
        SI-GuardStrict.ps1, New-SIEngineFingerprintRecord). A fingerprint that differs from the recorded one starts the
        24-hour stricter period of the safety checks; the same one keeps the record; the FIRST one an install records starts
        nothing. Never throws, never fails the update: $true recorded, $false not.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [string]$Version = '', $NowUtc)
    try {
        if (-not (Get-Command -Name New-SIEngineFingerprintRecord -ErrorAction SilentlyContinue)) {
            foreach ($root in @($SIRoot, '/si')) {
                $f = [IO.Path]::Combine($root, 'engine', '_shared', 'SI-GuardStrict.ps1')
                if (Test-Path -LiteralPath $f) { . $f; break }
            }
        }
        if (-not (Get-Command -Name New-SIEngineFingerprintRecord -ErrorAction SilentlyContinue)) { Write-UpdLog 'engine fingerprint: this release does not carry it -- not recorded'; return $false }
        $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
        $hash = Get-SIEngineFingerprint -SIRoot $SIRoot
        if (-not $hash) { Write-UpdLog 'engine fingerprint: no engine folder in this release -- not recorded'; return $false }
        # the record before: a read that FAILS writes nothing -- recording the fingerprint as "the first one" would end an open
        # stricter period (the same engine code must never end or hide it); the next update records it
        $prev = $null
        try { $prev = @(& $Store.Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'EngineFingerprint'" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
        catch { Write-UpdLog ("WARNING: the engine fingerprint was not recorded -- the recorded one could not be read: {0}" -f $_.Exception.Message); return $false }
        $prevJson = if ($prev) { [string]$(if ($prev -is [System.Collections.IDictionary]) { $prev['Value'] } elseif ($prev -is [System.Data.DataRow]) { $prev['Value'] } else { $prev.Value }) } else { '' }
        $r = New-SIEngineFingerprintRecord -Previous $prevJson -Hash $hash -Version $Version -NowUtc $now
        if (-not $r) { return $false }
        $ok = Save-SIUpdaterInstallStateValue -Store $Store -Name 'EngineFingerprint' -Value ($r.Record | ConvertTo-Json -Compress)
        $short = $hash.Substring(0, 12)
        Write-UpdLog $(if ($r.First) { "engine fingerprint $short recorded (the first one: no stricter period)" }
                       elseif ($r.Changed) { "engine fingerprint $short -- the engine code changed: the safety checks are stricter for 24 hours (their limits halved)" }
                       else { "engine fingerprint $short -- the engine code is unchanged" + $(if ($r.Record['strictFrom']) { ' (a stricter period that is open stays open: it started {0} with release {1})' -f $r.Record['strictFrom'], $r.Record['strictVersion'] } else { '' }) })
        return [bool]$ok
    } catch { Write-UpdLog ("WARNING: the engine fingerprint could not be recorded: {0}" -f $_.Exception.Message); return $false }
}

function Save-SIUpdaterReleaseScopes {
    <#
        CR3 (#657): the fingerprint of each component (collections per source, correlation, Risk Analysis per report, data out
        per channel -- config\release-scopes.locked.json) of the code just installed (-SIRoot) into cfg.ReleaseScope: a
        component whose code changed is Testing until 3 good daily runs; the FIRST record marks nothing Testing. A release
        that does not carry the component map records nothing. Never throws, never fails the update: $true recorded.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$SIRoot, [string]$Version = '', $NowUtc)
    try {
        if (-not (Get-Command -Name Save-SIReleaseScopeRecords -ErrorAction SilentlyContinue)) {
            foreach ($root in @($SIRoot, '/si')) {
                $f = [IO.Path]::Combine($root, 'engine', '_shared', 'SI-ReleaseControl.ps1')
                if (Test-Path -LiteralPath $f) { . $f; break }
            }
        }
        if (-not (Get-Command -Name Save-SIReleaseScopeRecords -ErrorAction SilentlyContinue)) { Write-UpdLog 'components: this release does not carry the component map -- not recorded'; return $false }
        if (-not (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'config', 'release-scopes.locked.json')))) { Write-UpdLog 'components: this release does not carry the component map -- not recorded'; return $false }
        $r = Save-SIReleaseScopeRecords -Invoke $Store.Invoke -SIRoot $SIRoot -Version $Version -NowUtc $NowUtc
        Write-UpdLog ("components: {0}" -f $r.Reason)
        return [bool]$r.Ok
    } catch { Write-UpdLog ("WARNING: the components could not be recorded: {0}" -f $_.Exception.Message); return $false }
}

function Save-SIUpdaterStateRow {
    <# A control state (-State ok | missing; $null / '' = not known, nothing written) into cfg.InstallState -Name as
       {"state":"...","checkedUtc":"..."} -- the heartbeat's setup report reads it (secret-handover). Never throws. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][ValidateSet('SecretHandover')][string]$Name, [AllowNull()][AllowEmptyString()][string]$State)
    if (-not "$State".Trim()) { return $false }
    $v = [ordered]@{ state = "$State".Trim(); checkedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress
    Save-SIUpdaterInstallStateValue -Store $Store -Name $Name -Value $v
}

function Invoke-SIUpdaterRecordEndpoints {
    <#
        Framework §8.4: the install's own links for the identified heartbeat. Reads the Container App FQDN of the web app and
        the MCP server (-WebApp / -McpApp, the names this updater already rolls) over ARM, keeps the list for this process
        ($global:SI_InstallEndpoints) and records it in cfg.InstallState 'Endpoints' (Save-SIInstallEndpointsRow), where every
        engine run reads it at start. An app that is not there, or has no ingress, is left out. -GetApp { param($App) } -> the
        ARM shape (the test seam; default Get-SIUpdaterContainerApp). NEVER throws, never fails the run. Returns the list.
    #>
    param($Store, [string]$SubscriptionId, [string]$ResourceGroup, [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp', [scriptblock]$GetApp)
    try {
        if (-not (Get-Command -Name ConvertTo-SITelemetryEndpointList -ErrorAction SilentlyContinue)) { return @() }
        if (-not $GetApp) { $GetApp = { param($App) Get-SIUpdaterContainerApp -App $App -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId } }
        $items = New-Object System.Collections.Generic.List[object]
        # framework §8.9 kinds: webapp = the Pro web app, mcp = its MCP server
        foreach ($p in @(@('webapp', $WebApp), @('mcp', $McpApp))) {
            if (-not "$($p[1])".Trim()) { continue }
            $fqdn = ''
            try { $a = & $GetApp $p[1]; if ($a) { $fqdn = [string]$a.properties.configuration.ingress.fqdn } } catch { $fqdn = '' }
            if ($fqdn.Trim()) { $items.Add([pscustomobject]@{ kind = $p[0]; url = $fqdn.Trim() }) }
        }
        $list = @(ConvertTo-SITelemetryEndpointList -Items $items.ToArray())
        if (-not $list.Count) { return @() }
        $global:SI_InstallEndpoints = $list
        if ($Store -and (Get-Command -Name Save-SIInstallEndpointsRow -ErrorAction SilentlyContinue)) {
            if (Save-SIInstallEndpointsRow -Store $Store -Endpoints $list) { Write-UpdLog ("install links recorded: {0}" -f (($list | ForEach-Object { '{0} {1}' -f $_.kind, $_.url }) -join ', ')) }
        }
        $list
    } catch { @() }
}

function Invoke-SIUpdaterRoll {
    <#
        From an EXTRACTED, verified release (-SIRoot) to running jobs: the release's own template gate first (Pro, unless the
        templates follow a template channel), then setup/Invoke-SIContainerUpdate.ps1 -Apply (build, roll, verify, restore on
        failure), then the release's templates. Shared by the feed and Invardia. Returns @{ Code (exit code); Held; Reason }.
        Pro: the database step (Invoke-SIUpdaterDatabase: schema, grants, record) comes FIRST of all; its failure = Code 1 with
        the Reason, and nothing is rolled.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, $Store, [string]$AcceptFingerprint, [switch]$TemplatesFollowChannel,
          # #405: ring 1 -- the release's templates installed DIRECTLY after the roll (Publish-SITemplates -InstallCurrent)
          [switch]$InstallTemplatesDirect,
          # #416: the release's version + commit (the updater image tag) and this environment's app / updater names -- every
          # other image is queued in parallel with the engine roll
          [string]$Version = '', [string]$Commit = '', [string]$WebApp = 'ca-si-management', [string]$McpApp = 'ca-si-mcp',
          [string]$UpdaterJob = 'caj-si-updater', [switch]$SelfOff)
    # Pro: THE DATABASE FIRST (#352, framework UPDATE-1.6 (j)) -- the release's own schema (additive, gated, one transaction
    # per file) and the grants its code needs, BEFORE the template gate, the build or any roll. Never new code on an old
    # schema: a failure here stops the update with nothing rolled. No Pro database (Community / VM) = skipped.
    if ($Store -and (Get-Command -Name Invoke-SIUpdaterDatabase -ErrorAction SilentlyContinue)) {
        $global:SI_UpdaterStep = 'database'
        $db = Invoke-SIUpdaterDatabase -SIRoot $SIRoot -Store $Store -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
        Write-UpdLog ("database: {0}" -f $db.Reason)
        if (-not $db.Ok) {
            Add-SIUpdaterFailureIf 'database' ([string]$db.Reason)
            return [pscustomobject]@{ Code = 1; Held = $false; Reason = ("the database was not updated, so nothing was rolled: {0}" -f $db.Reason) }
        }
    }
    $global:SI_UpdaterStep = 'templates'
    # Pro: the template gate BEFORE anything changes (a Community install has no Pro database and no templates).
    # An install whose ring takes template packs from a template channel keeps the templates that channel released:
    # the code roll does not republish the release's own templates over them.
    $tplGate = $null
    $publishScript = Join-Path $SIRoot 'setup/Publish-SITemplates.ps1'
    $direct = $InstallTemplatesDirect -and $Store -and (Test-Path -LiteralPath $publishScript) -and (Get-Command -Name $publishScript).Parameters.ContainsKey('InstallCurrent')
    if ($direct) { Write-UpdLog 'configuration templates: ring 1 -- every template of this release is installed directly after the roll (no pack, no gate)'; $TemplatesFollowChannel = $true }
    # #405: a release with the split install brings its fix and default templates WITH the code, also when the templates
    # follow a template channel (which carries only Microsoft content now; a newer pack in force is kept by the release)
    if (-not $direct -and $TemplatesFollowChannel -and $Store -and (Test-SIUpdaterTemplateSplit -SIRoot $SIRoot -Store $Store)) {
        Write-UpdLog 'configuration templates: this release installs its fix and default templates with the code; the Microsoft content follows the template channel'
        $TemplatesFollowChannel = $false
    }
    if ($TemplatesFollowChannel) {
        Write-UpdLog 'configuration templates follow the template channel -- the release''s own templates are not published by this roll'
    } elseif ($Store) {
        $tplGate = Invoke-SIUpdaterTemplateGate -SIRoot $SIRoot -Store $Store -AcceptFingerprint $AcceptFingerprint
        Write-UpdLog ("configuration templates: {0}" -f $tplGate.Reason)
        if (-not $tplGate.Proceed) { return [pscustomobject]@{ Code = 0; Held = $true; Reason = $tplGate.Reason } }
    }

    # #416: every OTHER image of this release starts building NOW, in parallel with the engine build and roll
    if (Get-Command -Name Start-SIUpdaterPrebuilds -ErrorAction SilentlyContinue) {
        $updTag = if ($Version -and (Get-Command -Name New-SIUpdaterBuildTag -ErrorAction SilentlyContinue)) { New-SIUpdaterBuildTag -Version $Version -Commit $Commit } else { '' }
        $null = Start-SIUpdaterPrebuilds -SIRoot $SIRoot -ResourceGroup $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId -UpdaterTag $updTag `
                    -WebApp $WebApp -McpApp $McpApp -UpdaterJob $UpdaterJob -SelfOff:$SelfOff
    }
    Write-UpdLog 'building and rolling the engine jobs'
    $global:SI_UpdaterStep = 'build'
    # #427: the release's Invoke-SIContainerUpdate.ps1 names its stage and its first warning here (build / roll / restore)
    $global:SI_UpdateStage = ''; $global:SI_UpdateFirstWarn = ''; $global:SI_UpdateSqlTier = ''; $global:SI_UpdateOrchestration = $null; $global:SI_UpdateFailures = $null
    $global:LASTEXITCODE = 0
    & (Join-Path $SIRoot 'setup/Invoke-SIContainerUpdate.ps1') -Apply -ResourceGroupName $ResourceGroup -AcrName $AcrName -SubscriptionId $SubscriptionId
    $code = if ($LASTEXITCODE) { [int]$LASTEXITCODE } else { 0 }
    # #507: the release's SQL database size step (one line) -- recorded where the web app reads the install's state
    if ($Store -and "$global:SI_UpdateSqlTier".Trim()) { $null = Save-SIUpdaterSqlTierRow -Store $Store -Line ([string]$global:SI_UpdateSqlTier) }
    # the pipeline-schedule check ("neither mode" repaired, or not) -- the heartbeat's setup report says it (job-layout)
    if ($Store -and $global:SI_UpdateOrchestration) { $null = Save-SIUpdaterPipelineScheduleRow -Store $Store -Result $global:SI_UpdateOrchestration }
    # CR4 (#654): the engine fingerprint of the code the jobs now run -- a changed one starts the 24-hour stricter period
    if ($code -eq 0 -and $Store) { $null = Save-SIUpdaterEngineFingerprint -Store $Store -SIRoot $SIRoot -Version $Version }
    # CR3 (#657): the fingerprint of each component of that code -- a changed component is Testing until 3 good daily runs
    if ($code -eq 0 -and $Store) { $null = Save-SIUpdaterReleaseScopes -Store $Store -SIRoot $SIRoot -Version $Version }
    # SUP-2026-00198: a release that records its failures (step + catalogue code) is reported as it recorded them -- the
    # roll as 'roll', ONLY a job that could not be put back as 'restore'. An older release: the stage it stopped in, as before.
    $recorded = @(if ($code -ne 0 -and $global:SI_UpdateFailures) { @($global:SI_UpdateFailures) | Where-Object { $_ -and "$($_.Step)".Trim() } })
    $notRestored = @($recorded | Where-Object { "$($_.Step)" -eq 'restore' })
    Write-UpdLog $(if ($code -eq 0) { 'engine jobs are on the approved version' }
                   elseif ($notRestored.Count) { "the update FAILED (exit $code) -- $($notRestored.Count) job restore(s) failed: see the update log, restore them by hand" }
                   else { "the update FAILED (exit $code) -- every changed job was restored to its previous image" })
    if ($code -ne 0) {
        if ($recorded.Count) {
            foreach ($f in $recorded) { Add-SIUpdaterFailureIf ([string]$f.Step) ([string]$f.Text) ([string]$f.Code) }
        } else {
            $rollStep = if (Get-Command -Name ConvertTo-SIUpdaterRollStep -ErrorAction SilentlyContinue) { ConvertTo-SIUpdaterRollStep -Stage ([string]$global:SI_UpdateStage) } else { 'roll' }
            Add-SIUpdaterFailureIf $rollStep $(if ("$global:SI_UpdateFirstWarn".Trim()) { [string]$global:SI_UpdateFirstWarn } else { "the engine update ended with exit code $code; every changed job was restored" })
        }
    }
    $global:SI_UpdaterStep = 'post-roll'
    if ($code -eq 0 -and $direct) {
        try {
            $pub = & $publishScript -InstallPath $SIRoot -Store $Store -InstallCurrent -PassThru | Where-Object { $_ -and $_.PSObject.Properties['Mode'] } | Select-Object -Last 1
            if (-not $pub -or $pub.Mode -ne 'applied') { Write-UpdLog ("configuration templates NOT installed: {0}" -f $(if ($pub) { $pub.Reason } else { 'no result' })); Add-SIUpdaterFailureIf 'templates' ("configuration templates NOT installed: {0}" -f $(if ($pub) { $pub.Reason } else { 'no result' })); return [pscustomobject]@{ Code = 1; Held = $false; Reason = 'templates not installed' } }
            Write-UpdLog ("configuration templates installed directly ({0} change(s))" -f $pub.Written)
        } catch { Write-UpdLog ("configuration templates NOT installed: {0}" -f $_.Exception.Message); Add-SIUpdaterFailureIf 'templates' ("configuration templates NOT installed: {0}" -f $_.Exception.Message); return [pscustomobject]@{ Code = 1; Held = $false; Reason = 'templates not installed' } }
    }
    if ($code -ne 0 -or -not $tplGate) { return [pscustomobject]@{ Code = $code; Held = $false; Reason = '' } }

    try {
        $pub = Publish-SIUpdaterTemplates -SIRoot $SIRoot -Store $Store -AcceptFingerprint $AcceptFingerprint -Accept:$tplGate.Accept
        if (-not $pub -or $pub.Mode -ne 'applied') { Write-UpdLog ("configuration templates NOT published: {0}" -f $(if ($pub) { $pub.Reason } else { 'no result' })); Add-SIUpdaterFailureIf 'templates' ("configuration templates NOT published: {0}" -f $(if ($pub) { $pub.Reason } else { 'no result' })); return [pscustomobject]@{ Code = 1; Held = $false; Reason = 'templates not published' } }
        Write-UpdLog ("configuration templates published and verified ({0} change(s)); fingerprint {1} recorded" -f $pub.Written, $pub.Fingerprint.Substring(0, [Math]::Min(12, $pub.Fingerprint.Length)))
    } catch { Write-UpdLog ("configuration templates NOT published: {0}" -f $_.Exception.Message); Add-SIUpdaterFailureIf 'templates' ("configuration templates NOT published: {0}" -f $_.Exception.Message); return [pscustomobject]@{ Code = 1; Held = $false; Reason = 'templates not published' } }
    [pscustomobject]@{ Code = 0; Held = $false; Reason = '' }
}

function Invoke-SIUpdaterSizingPass {
    <#
        #756: a run that installs NO new code (the ring's release is applied already) still applies the sizes the customer's
        settings set -- live 2026-10-19: SI_Bootstrap_SqlServiceObjective = S2 was set, the code was current, and the database
        stayed S3 because only the roll ran the size steps. Runs -SIRoot's setup/Invoke-SIContainerUpdate.ps1 -Apply -SizingOnly
        (the SQL database, job and web app sizes; nothing built or rolled) and records its SQL line in cfg.InstallState
        'SqlTier', as the roll does. -SIRoot: the SecurityInsight code this updater image carries (/si). -Why: what the run
        found (one line in the log). A release whose update script has no -SizingOnly is said in one line and skipped. -Run
        { param($Script, $Arguments) } is the test seam. NEVER throws, never fails the run: $true = the sizes were checked.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName,
          [Parameter(Mandatory)][string]$SubscriptionId, $Store, [string]$Why = 'the code is current', [scriptblock]$Run)
    try {
        $upd = Join-Path $SIRoot 'setup/Invoke-SIContainerUpdate.ps1'
        if (-not (Test-Path -LiteralPath $upd) -or -not (Get-Command -Name $upd).Parameters.ContainsKey('SizingOnly')) {
            Write-UpdLog ("sizes: {0} -- this updater's code has no settings-only size check; the next release applies the sizes" -f $Why); return $false
        }
        Write-UpdLog ("sizes: {0} -- nothing is built or rolled; checking the SQL database, job and web app sizes against the settings" -f $Why)
        $global:SI_UpdaterStep = 'sizes'
        $global:SI_UpdateStage = ''; $global:SI_UpdateFirstWarn = ''; $global:SI_UpdateSqlTier = ''
        $a = @{ Apply = $true; SizingOnly = $true; ResourceGroupName = $ResourceGroup; AcrName = $AcrName; SubscriptionId = $SubscriptionId }
        $global:LASTEXITCODE = 0
        # its lines go to the log (Out-Host), never into this function's answer
        if ($Run) { & $Run $upd $a | Out-Host } else { & $upd @a | Out-Host }
        # the same record as after a roll (#507): the web app reads the install's database size from it
        if ($Store -and "$global:SI_UpdateSqlTier".Trim()) { $null = Save-SIUpdaterSqlTierRow -Store $Store -Line ([string]$global:SI_UpdateSqlTier) }
        $true
    } catch { Write-UpdLog ("WARNING: sizes: not checked ({0}) -- the run goes on; the next run tries again" -f $_.Exception.Message); $false }
}

function Get-SIUpdaterDeployed {
    <# The registry and the version the SI jobs run now -> the forward-only guard and the update record's from-version: the
       release recorded on the updater job when it was last applied (tag si-installed), the jobs' image tags as the fallback
       (they carry only the base version since the images are tagged by content). #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$AcrName, [Parameter(Mandatory)][string]$SubscriptionId,
          [hashtable]$Env = @{})
    $acr  = Get-SIUpdaterRegistry -AcrName $AcrName -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $updName = 'caj-si-updater'; try { $updName = [string](Get-SIUpdaterInstallName -Role updater -Env $Env) } catch { }
    $recorded = ''
    $all = @(Get-SIUpdaterJobs -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId)
    $jobs = $all | ForEach-Object {
        if ([string]$_.name -eq $updName) { try { if ($_.tags -and $_.tags.PSObject.Properties['si-installed']) { $recorded = ([string]$_.tags.'si-installed').Trim() } } catch { } }
        $img = $null; try { $img = [string]$_.properties.template.containers[0].image } catch { }
        [pscustomobject]@{ Name = [string]$_.name; Image = $img }
    }
    Get-SIDeployedVersionFromJobs -Jobs @($jobs) -LoginServer $acr.loginServer -Recorded $recorded
}

function Get-SIUpdaterSourceKind {
    <#
        PURE. What this updater is configured for: 'invardia' (the only source), or 'feed' -- SI's own update feed, RETIRED
        2026-10-06 (SI_UPDATER_SOURCE = feed, or a feed link SI_UPDATER_SOURCE_URL without SI_UPDATER_SOURCE): Invoke-SIUpdaterCore
        then changes nothing and says how to move. Anything else is refused.
    #>
    param([AllowEmptyString()][string]$Source, [AllowEmptyString()][string]$SourceUrl)
    $s = "$Source".Trim().ToLowerInvariant()
    if (-not $s) { if ("$SourceUrl".Trim()) { return 'feed' } else { return 'invardia' } }
    # 'community' (#750 (b)): what setup writes on a Community edition's updater -- the edition decides the path (below)
    if ($s -notin @('feed', 'invardia', 'community')) { throw "SI_UPDATER_SOURCE must be 'invardia' or 'feed' (or 'community' in the Community edition), not '$Source'." }
    $s
}

function Get-SIUpdaterEditionPath {
    <#
        PURE (Test-Path only). Which update path this image takes (SI #750 (b)):
          'invardia'  -- the image carries the Invardia update client (-HookFolder/SI-UpdaterInvardia.ps1): SecurityInsight Pro.
                         A Pro image ALWAYS takes it -- the public channel would replace Pro with the Community edition.
          'community' -- no Invardia client, but the Community hook (-HookFolder/SI-UpdaterCommunity.ps1) and the signed
                         Community client in the code the image carries (-SIRoot/engine/_shared/SI-CommunityUpdate.ps1).
          ''          -- neither (an image built before either): the run says so and ends.
    #>
    param([Parameter(Mandatory)][string]$HookFolder, [AllowEmptyString()][string]$SIRoot)
    if (Test-Path -LiteralPath (Join-Path $HookFolder 'SI-UpdaterInvardia.ps1')) { return 'invardia' }
    if ((Test-Path -LiteralPath (Join-Path $HookFolder 'SI-UpdaterCommunity.ps1')) -and "$SIRoot".Trim() -and
        (Test-Path -LiteralPath ([IO.Path]::Combine($SIRoot, 'engine', '_shared', 'SI-CommunityUpdate.ps1')))) { return 'community' }
    ''
}

function Get-SIUpdaterAutoSwitches {
    <#
        The customer's two switches for this run (SI-ProAutomation.ps1): the Pro settings database first (-Store; a store
        that could not be opened = -StoreFailed), then the job's environment, else ON. An unreadable database turns both
        Invardia steps off for this run -- a switch set to off there is never overruled. Without SI-ProAutomation.ps1 in the
        image (an image built before the switches): $null, and both steps run as before.
    #>
    param([hashtable]$Env = @{}, $Store, [switch]$StoreFailed, [string]$StoreError)
    if (-not (Get-Command -Name Get-SIProAutoSwitches -ErrorAction SilentlyContinue)) { return $null }
    $settings = if ($StoreFailed) { [pscustomobject]@{ Ok = $false; Values = @{}; Secrets = @{}; Error = $StoreError } }
                elseif ($Store) { Read-SIProSolutionSettings -Store $Store }
                else { $null }
    Get-SIProAutoSwitches -Settings $settings -Env $Env
}

function Save-SIUpdaterInstallRing {
    <#
        #308: records the ring this run resolved (cfg.InstallState 'Ring'), so the web app shows the install's ring. -Ring
        $null (nothing resolved, e.g. no ring assigned) falls back to SI_UpdateRing, then to the resource-group name. A
        no-op without the Pro database or without SI-InstallRing.ps1 in the image; never fails the run.
    #>
    param($Store, [AllowNull()]$Ring, [string]$Channel = '', [string]$ResourceGroup = '')
    if (-not $Store -or -not (Get-Command -Name Invoke-SIRecordInstallRing -ErrorAction SilentlyContinue)) { return $null }
    $r = Invoke-SIRecordInstallRing -Store $Store -Ring $Ring -RingSource updater -ResourceGroupName $ResourceGroup -Channel $Channel -SetBy 'caj-si-updater'
    if ($r.Written -or $null -eq $r.Ring -or $r.Reason -like 'the update ring could not be recorded*') { Write-UpdLog ("update ring: {0}" -f $r.Reason) }
    $r
}

function Get-SIUpdaterOwnTimer {
    <#
        The updater job's own timer: @{ Cron ('' when it has no timer or cannot be read -- the run then goes on); Zone (the
        zone the job records, tag si-nightly-schedule '18:30 <zone>'; none -> Europe/Copenhagen) }. Tests replace it.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$JobName)
    try {
        $j = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $JobName)) -AllowNotFound
        if ($j -and (Get-Command -Name Get-SINightlyJobZone -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ Cron = [string](Get-SINightlyJobCron $j); Zone = [string](Get-SINightlyJobZone $j) } }
    } catch { }
    [pscustomobject]@{ Cron = ''; Zone = '' }
}

function Test-SIUpdaterRunNow {
    <#
        THE NIGHTLY TICK (owner 2026-10-21: 18:30 / 19:00 local time for region). The job's timer is the UTC times that are
        18:30 in the zone of the install's Azure region (with daylight saving two ticks, e.g. '30 16,17 * * *' for
        Europe/Amsterdam; without it one; a job the update has not moved yet: its 23:00 ticks), and the job records that zone
        -- so on that timer the start that is NOT that time in the zone ends here,
        before anything is read or changed, with one plain line (exit 0, not a failure). A timer of the customer's own, a run
        started by hand, by a release or by the web app (SI_UPDATER_MODE), and an image without SI-NightlySchedule.ps1 always
        go on. Returns $true = go on.
    #>
    param([hashtable]$Env = @{}, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Get-Command -Name Test-SIUpdaterNightlyTick -ErrorAction SilentlyContinue)) { return $true }
    $mode = if ($Env.ContainsKey('SI_UPDATER_MODE')) { "$($Env['SI_UPDATER_MODE'])" } else { "$([Environment]::GetEnvironmentVariable('SI_UPDATER_MODE'))" }
    $u = $NowUtc.ToUniversalTime()
    # a purpose run goes on at once; any other start reads its own timer (one ARM read) -- the ticks depend on the zone
    if ($mode.Trim()) { return $true }
    $jn = if ($Env.ContainsKey('CONTAINER_APP_JOB_NAME')) { "$($Env['CONTAINER_APP_JOB_NAME'])".Trim() } else { "$([Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_NAME'))".Trim() }
    if (-not $jn) { $jn = Get-SIUpdaterInstallName -Role updater -Env $Env }
    $own = Get-SIUpdaterOwnTimer -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $jn
    if (-not "$($own.Cron)".Trim()) { return $true }
    $t = Test-SIUpdaterNightlyTick -NowUtc $u -Cron ([string]$own.Cron) -Mode $mode -Zone ([string]$own.Zone)
    if (-not $t.Go) { Write-UpdLog $t.Why }
    [bool]$t.Go
}

function Invoke-SIUpdater {
    <# The run. (#521: the sign-in leaves no key file behind -- the certificate's temporary PFX is removed as it is read.) #>
    param([hashtable]$Env = @{})
    Invoke-SIUpdaterCore -Env $Env
}

function Get-SIUpdaterFeedRetiredReason {
    <#
        PURE. SI's own update feed is RETIRED (operator 2026-10-06: "we are not having separate platforms like a si storage
        account for si updates. one solution: invardia"). An updater still configured for it (SI_UPDATER_SOURCE = feed, or a
        feed link SI_UPDATER_SOURCE_URL without SI_UPDATER_SOURCE = invardia) does NOTHING and says how to move. $null = not
        configured for the feed.
    #>
    param([AllowEmptyString()][string]$Source, [AllowEmptyString()][string]$SourceUrl)
    if ((Get-SIUpdaterSourceKind -Source $Source -SourceUrl $SourceUrl) -ne 'feed') { return $null }
    'SecurityInsight''s own update feed is RETIRED -- Pro updates come only from Invardia''s platform (signed manifests, the ring SI released to). Nothing was changed. Move this updater with: setup\Install-SIUpdaterJob.ps1 -Source invardia -UpdateRing <0-3> ... -Apply (it removes the feed link from the job).'
}

function Invoke-SIUpdaterCore {
    param([hashtable]$Env = @{})
    $get = { param($k, $d = '') $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { $d } else { "$v".Trim() } }
    # SI's own feed is retired: an updater still set up for it changes nothing (no sign-in, no read) and says how to move.
    $retired = Get-SIUpdaterFeedRetiredReason -Source (& $get 'SI_UPDATER_SOURCE') -SourceUrl (& $get 'SI_UPDATER_SOURCE_URL')
    if ($retired) { Write-UpdLog $retired; return 0 }
    $tenant = & $get 'SI_UPDATER_TENANT_ID'; $client = & $get 'SI_UPDATER_CLIENT_ID'; $sub = & $get 'SI_UPDATER_SUBSCRIPTION_ID'
    $rg = & $get 'SI_UPDATER_RESOURCE_GROUP'; $acrName = & $get 'SI_UPDATER_ACR'
    $pfx = & $get 'SI_UPDATER_CERT_PFX_B64'; $pfxPw = & $get 'SI_UPDATER_CERT_PASSWORD'
    $blocked = @((& $get 'SI_UPDATER_BLOCK') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    # #350 / #222: SI_UPDATER_AUTH = ManagedIdentity signs in as the job's user-assigned identity (SI_UPDATER_CLIENT_ID = its
    # client id) -- no certificate in the vault at all, as PIM's ca-pim-update. Default: the SPN by certificate.
    $auth = Get-SIUpdaterAuthMode -Auth (& $get 'SI_UPDATER_AUTH')
    $global:SI_UpdaterStep = 'settings'
    $need = @('SI_UPDATER_TENANT_ID', 'SI_UPDATER_CLIENT_ID', 'SI_UPDATER_SUBSCRIPTION_ID', 'SI_UPDATER_RESOURCE_GROUP', 'SI_UPDATER_ACR', 'SI_UPDATER_KEY_VAULT')
    if ($auth -eq 'Certificate') { $need += 'SI_UPDATER_CERT_PFX_B64' }
    foreach ($req in $need) { if (-not (& $get $req)) { throw "$req is not set on the updater job." } }
    # WHICH EDITION'S UPDATE PATH (SI #750 (b)): Pro updates come from Invardia (#240) -- the hook is Pro
    # (SI-UpdaterInvardia.ps1), and a Pro image ALWAYS takes it. An image without it (the Community edition) updates from the
    # signed Community channel (SI-UpdaterCommunity.ps1 + /si/engine/_shared/SI-CommunityUpdate.ps1), in the cloud, as Pro.
    $edition = Get-SIUpdaterEditionPath -HookFolder (Join-Path $PSScriptRoot '_shared') -SIRoot $siAutoRoot
    $global:SI_UpdaterEdition = $edition
    if ($edition -eq 'invardia') {
        . (Join-Path $PSScriptRoot '_shared/SI-UpdaterInvardia.ps1')
        Write-UpdLog 'update source: Invardia (signed manifests)'
    } elseif ($edition -eq 'community') {
        . (Join-Path $PSScriptRoot '_shared/SI-UpdaterCommunity.ps1')
        Write-UpdLog 'update source: the signed Community channel (SecurityInsight Community edition)'
    } else { throw 'this updater image carries no update client (neither the Invardia client of SecurityInsight Pro nor the signed Community client) -- re-run setup/Install-SIUpdaterJob.ps1 to rebuild it.' }

    $global:SI_UpdaterStep = 'signin'
    Write-UpdLog ('signing in over REST ({0})' -f $(if ($auth -eq 'ManagedIdentity') { 'managed identity' } else { 'service principal, certificate' }))
    $who = Connect-SIUpdaterRest -Env $Env -SubscriptionId $sub
    Write-UpdLog ("signed in as {0}" -f $who)
    # the nightly tick: on its zone's ticks only the start that is 18:30 (23:00 on a job not moved yet) in the region's zone goes on (SI-NightlySchedule.ps1)
    if (-not (Test-SIUpdaterRunNow -Env $Env -SubscriptionId $sub -ResourceGroup $rg)) { return 0 }
    # 2026-10-23: the second update (SI_UPDATER_MODE = second-pass, started by the update that installed the release) waits
    # for that update to end first -- two updates never change the install at once
    if ((& $get 'SI_UPDATER_MODE') -ieq 'second-pass') {
        $selfExec = & $get 'CONTAINER_APP_JOB_EXECUTION_NAME'
        $updJobName = Get-SIUpdaterInstallName -Role updater -Env $Env
        Write-UpdLog (Wait-SIUpdaterPreviousEnded -Self $selfExec -Executions { @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $sub -ResourceGroup $rg -Provider ('Microsoft.App/jobs/{0}/executions' -f $updJobName)) -List) })
    }
    elseif ((& $get 'SI_UPDATER_MODE') -ine 'apply-settings' -and (Get-Command -Name Select-SIUpdaterEarlierRunning -ErrorAction SilentlyContinue)) {
        # #911: an hourly (or update-now) execution steps aside at once while an EARLIER execution of this job still runs --
        # two updates never change the install at once (live 2026-10-27: overlapping rolls, a 409 and a customer ticket).
        # The job's executions cannot be read: said, and the update goes on (the install lock still keeps runs out).
        $global:SI_UpdaterStep = 'overlap'
        try {
            $updJobName = Get-SIUpdaterInstallName -Role updater -Env $Env
            $execs = @(Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $sub -ResourceGroup $rg -Provider ('Microsoft.App/jobs/{0}/executions' -f $updJobName)) -List)
            $earlier = Select-SIUpdaterEarlierRunning -Executions $execs -Self (& $get 'CONTAINER_APP_JOB_EXECUTION_NAME') -NowUtc ([datetime]::UtcNow)
            if ($earlier) { Write-UpdLog (Get-SIUpdaterStepAsideText -Earlier $earlier); return 0 }
        } catch { Write-UpdLog ("WARNING: whether an earlier update still runs could not be read ({0}) -- this update goes on" -f $_.Exception.Message) }
    }
    # The Pro settings database (Pro only), opened once: the customer's switches, the licence state mirror, the gates.
    $proSql = & $get 'SI_UPDATER_PRO_SQL_SERVER'; $proDb = & $get 'SI_UPDATER_PRO_SQL_DATABASE'
    $proStore = $null; $proStoreError = ''
    $global:SI_UpdaterStep = 'settings'
    if ($proSql -and $proDb) {
        try { $proStore = New-SIUpdaterProStore -Server $proSql -Database $proDb -SubscriptionId $sub }
        catch { $proStoreError = $_.Exception.Message; Write-UpdLog ("WARNING: the Pro settings database could not be opened: {0}" -f $proStoreError) }
    }
    $script:SIUpdaterProStore = $proStore   # #427: the telemetry switch on the Settings page, read when a failure is reported
    # CR5 step 1 (#655): the names this install runs with, recorded -- every lookup below reads them (Get-SIUpdaterInstallName)
    $null = Invoke-SIUpdaterInstallNames -Env $Env -Store $proStore
    # THE SECRET HAND-OVER (Pro): the hand-over key, every secret the web app handed over (it never writes one itself), and
    # the web app's old Key Vault right removed -- on every run. SI_UPDATER_MODE = apply-settings (the short run the web app
    # starts after a paste) does ONLY this, then ends: no licence step, no update.
    $updMode = (& $get 'SI_UPDATER_MODE').ToLowerInvariant()
    if (Get-Command -Name Invoke-SIUpdaterSecretHandover -ErrorAction SilentlyContinue) {
        $global:SI_UpdaterStep = 'secret-handover'
        $ho = Invoke-SIUpdaterSecretHandover -Rest (Get-SIUpdaterRest) -Store $proStore -KeyVault (& $get 'SI_UPDATER_KEY_VAULT') -SubscriptionId $sub -ResourceGroup $rg `
                  -WebApp (Get-SIUpdaterInstallName -Role web -Env $Env) -Log { param($m) Write-UpdLog $m }
        foreach ($t in @($ho.Report)) { Add-SIUpdaterFailureIf 'secret-handover' $t }
        # the updater lacks its Key Vault right (the updater setup not re-run with its role grants): the customer's action,
        # reported as such (kv-403, Outcome warning, the exact command) -- never an update failure
        foreach ($t in @($(if ($ho.PSObject.Properties['CustomerAction']) { $ho.CustomerAction }))) { if (Get-Command -Name Add-SIUpdaterCustomerAction -ErrorAction SilentlyContinue) { Add-SIUpdaterCustomerAction -Step 'secret-handover' -Text $t -Class 'kv-403' } }
        # the setup report's secret-handover control (cfg.InstallState 'SecretHandover', read by the heartbeat)
        if ($proStore -and (Get-Command -Name Get-SIHandoverControlState -ErrorAction SilentlyContinue)) { $null = Save-SIUpdaterStateRow -Store $proStore -Name 'SecretHandover' -State (Get-SIHandoverControlState -Result $ho) }
    }
    if ($updMode -eq 'apply-settings') {
        if ($proSql -and $proDb -and -not $proStore) { throw "the Pro settings database could not be opened: $proStoreError" }
        Write-UpdLog 'apply-settings run: the settings handed over in the web app were applied -- nothing else runs'
        return 0
    }
    if ($edition -eq 'community') {
        # THE COMMUNITY EDITION (#750 (b)): no licence request to Invardia (a Community install holds no licence and must
        # never ask for one), no install key, no Invardia switch -- the signed Community channel only.
        Write-UpdLog 'licence request: not in the Community edition -- Invardia is not asked'
        $global:SI_UpdaterStep = 'endpoints'
        $null = Invoke-SIUpdaterRecordEndpoints -Store $proStore -SubscriptionId $sub -ResourceGroup $rg `
                    -WebApp (Get-SIUpdaterInstallName -Role web -Env $Env) -McpApp (Get-SIUpdaterInstallName -Role mcp -Env $Env)
        $global:SI_UpdaterStep = 'updater'
        if ($proSql -and $proDb -and -not $proStore) { throw "the SecurityInsight database could not be opened: $proStoreError" }
        return (Invoke-SIUpdaterFromCommunity -Env $Env -SubscriptionId $sub -ResourceGroup $rg -AcrName $acrName -Blocked $blocked -Store $proStore `
                    -Deployed (Get-SIUpdaterDeployed -ResourceGroup $rg -AcrName $acrName -SubscriptionId $sub -Env $Env) -AcceptFingerprint (& $get 'SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT'))
    }
    $switches = Get-SIUpdaterAutoSwitches -Env $Env -Store $proStore -StoreFailed:([bool]$proStoreError) -StoreError $proStoreError
    # Licence requests (#239): ask Invardia for this install's licence, install the approved file. Never fails the run.
    # Off when the customer switched SI_LicenseRequest_Auto off (it is ON by default).
    $global:SI_UpdaterStep = 'licence'
    $lr = Invoke-SIUpdaterLicenceRequest -Env $Env -SubscriptionId $sub -Log { param($m) Write-UpdLog $m } -Store $proStore `
                -Switch $(if ($switches) { $switches['SI_LicenseRequest_Auto'] } else { $null })
    # #427: a refused licence request is a failure Invardia hears about (the run itself goes on, as before)
    if (Get-Command -Name Get-SIUpdaterLicenceFailure -ErrorAction SilentlyContinue) { $lf = Get-SIUpdaterLicenceFailure -Result $lr; if ($lf) { Add-SIUpdaterFailureIf 'licence' $lf } }
    # framework §8.4: the web app's and MCP server's addresses, for the identified heartbeat's links (never fails the run)
    $global:SI_UpdaterStep = 'endpoints'
    $null = Invoke-SIUpdaterRecordEndpoints -Store $proStore -SubscriptionId $sub -ResourceGroup $rg `
                -WebApp (Get-SIUpdaterInstallName -Role web -Env $Env) -McpApp (Get-SIUpdaterInstallName -Role mcp -Env $Env)
    $global:SI_UpdaterStep = 'updater'
    # #350: both of the customer's switches, stated on every run (PIM: 'licence.autoRequest' / 'updates.invardia')
    if ($switches) { foreach ($k in 'SI_LicenseRequest_Auto', 'SI_InvardiaUpdate_Enabled') { if ($switches[$k]) { Write-UpdLog ("switch {0} = {1}: {2}" -f $k, $(if ($switches[$k].On) { 'ON' } else { 'OFF' }), $switches[$k].Text) } } }
    # Pro updates from Invardia: off when the customer switched SI_InvardiaUpdate_Enabled off (it is ON by default).
    $updSwitch = if ($switches) { $switches['SI_InvardiaUpdate_Enabled'] } else { $null }
    if ($updSwitch) { Write-UpdLog ("Pro updates: {0}" -f $updSwitch.Text) }
    if ($updSwitch -and -not $updSwitch.On) { return 0 }
    if ($proSql -and $proDb -and -not $proStore) { throw "the Pro settings database could not be opened: $proStoreError" }
    return (Invoke-SIUpdaterFromInvardia -Env $Env -SubscriptionId $sub -ResourceGroup $rg -AcrName $acrName -Blocked $blocked -Store $proStore `
                -Deployed (Get-SIUpdaterDeployed -ResourceGroup $rg -AcrName $acrName -SubscriptionId $sub -Env $Env) -AcceptFingerprint (& $get 'SI_UPDATER_ACCEPT_TEMPLATE_FINGERPRINT'))
}

function Invoke-SIUpdaterFailureReport {
    <#
        #427: at the end of the run, every failure it recorded (and a non-zero exit with none recorded) goes to Invardia's
        uplink: the telemetry switch (the Settings page, then SI_TELEMETRY_ENABLED on the job), identified with the install
        key from the Key Vault when there is one, anonymous otherwise. Never throws, never changes the exit code.
        -ReadKey { } -> the install key ('' = none) -- the test seam; default: the Key Vault secret over REST (only when a
        failure is to be reported).
    #>
    param([int]$ExitCode, $StartedAt, [hashtable]$Env = @{}, [scriptblock]$ReadKey, [scriptblock]$Send)
    try {
        if (-not (Get-Command -Name Send-SIUpdaterFailureReports -ErrorAction SilentlyContinue)) { return @() }
        # the Community edition's updater (#750 (b)) reports nothing to Invardia: its failures are in the job's log and on the
        # Settings page (cfg.InstallState 'UpdateState')
        if ("$global:SI_UpdaterEdition" -eq 'community') { return @() }
        if (-not @(Get-SIUpdaterFailures).Count -and $ExitCode -eq 0) { return @() }
        $get = { param($k) $v = if ($Env.ContainsKey($k)) { $Env[$k] } else { [Environment]::GetEnvironmentVariable($k) }; if ([string]::IsNullOrWhiteSpace($v)) { '' } else { "$v".Trim() } }
        $settings = $null
        if ($script:SIUpdaterProStore -and (Get-Command -Name Read-SIProSolutionSettings -ErrorAction SilentlyContinue)) { try { $settings = Read-SIProSolutionSettings -Store $script:SIUpdaterProStore } catch { $settings = $null } }
        $tev = & $get 'SI_TELEMETRY_ENABLED'
        # #918: in a Pester session the process-wide value is the test gate's (SI_TEST_GATE=1), not the test's
        if (-not $Env.ContainsKey('SI_TELEMETRY_ENABLED') -and "$env:SI_TEST_GATE" -eq '1' -and (Get-Module -Name Pester)) { $tev = '' }
        $on = Test-SIUpdaterTelemetryOn -Settings $settings -EnvValue $tev
        $key = ''
        if ($on) {
            if ($ReadKey) { try { $key = [string](& $ReadKey) } catch { $key = '' } }
            elseif ((& $get 'SI_UPDATER_KEY_VAULT') -and -not (Get-Module -Name Pester)) {
                try { $key = ([string](Get-SIKeyVaultSecretValue -VaultName (& $get 'SI_UPDATER_KEY_VAULT') -Name 'SI-Invardia-InstallKey')).Trim() } catch { $key = '' }
            }
        }
        $a = @{ ExitCode = $ExitCode; On = $on; InstallKey = $key; TenantId = (& $get 'SI_UPDATER_TENANT_ID'); StartedAt = $StartedAt; Log = { param($m) Write-UpdLog $m } }
        if ($Send) { $a.Send = $Send }
        Send-SIUpdaterFailureReports @a
    } catch { @() }
}

if (-not $DefineOnly) {
    $rc = 1
    $updStarted = [datetime]::UtcNow
    $global:SI_UpdaterRunStartedUtc = $updStarted   # #506: the 'check' stage of a tracked run starts here
    # #911 (e): the watch for a long silent step, for the whole run
    if (Get-Command -Name Start-SIUpdateWatch -ErrorAction SilentlyContinue) { try { $null = Start-SIUpdateWatch -QuietMinutes 20 } catch { } }
    try { $rc = Invoke-SIUpdater } catch {
        Write-UpdLog ("FAILED: {0}" -f $_.Exception.Message)
        Add-SIUpdaterFailureIf $(if ("$global:SI_UpdaterStep".Trim()) { "$global:SI_UpdaterStep" } else { 'updater' }) $_.Exception.Message
    }
    # #506: the tracked run's last stage (done / failed / rolled back / waiting); never changes the exit code
    try { if (Get-Command -Name Stop-SIUpdateTrack -ErrorAction SilentlyContinue) { $null = Stop-SIUpdateTrack -ExitCode $rc } } catch { }
    if (Get-Command -Name Stop-SIUpdateWatch -ErrorAction SilentlyContinue) { Stop-SIUpdateWatch }
    $null = Invoke-SIUpdaterFailureReport -ExitCode $rc -StartedAt $updStarted
    exit $rc
}
