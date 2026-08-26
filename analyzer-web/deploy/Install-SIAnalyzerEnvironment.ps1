#Requires -Version 5.1
<#
.SYNOPSIS
    Idempotent, unattended CREATE-IF-ABSENT installer for the SI Analyzer (SIA)
    Azure environment. Audit #40.

.DESCRIPTION
    THE GAP THIS CLOSES (audit #40, operator 2026-08-07: "how do we do this using the
    sync-automateit routine as capability. or does it support only update. if yes, i need
    to install unattended so it can be updated").

    The AutomateIT sync CAN deploy a solution unattended -- sync/_SyncDeploy.ps1 runs the
    solution's declared Deploy.Script whenever synced content changes, treats a first-ever
    sync as changed, and does NOT advance its marker on failure (so it self-heals). But the
    script it runs, Deploy-SIAnalyzer.ps1, is an UPDATER: az acr build -> az containerapp
    update -> health-gated revision swap -> MI grants -> Easy Auth. It never CREATES the
    resource group, the registry, the Container Apps environment, the app, the storage
    account or the Entra app registration. solution.deploy.json says so itself: those five
    are listed under `requires` as PRECONDITIONS, not outputs, and
    Setup-SecurityInsight-Unattended.ps1 covers none of them either (its Phase 5 Container
    Apps JOB is the ENGINES, not SIA).

    So on a customer who has never had SIA, the sync had nothing to update and failed on the
    first az call, forever. This script is the missing half: it establishes every
    precondition, after which the EXISTING sync deploy keeps SIA current with no change to
    the sync engine at all.

    🔒 sync/ IS FRAMEWORK-OWNED AND IS DELIBERATELY NOT TOUCHED (SI CLAUDE.md rule 8). The
    install belongs to SI; the update path already works. Nothing here edits shared files.

    WHAT IT ESTABLISHES (each step is create-if-absent and safe to re-run):
      1. Resource group                     -- SIA's OWN, never another solution's (#3b).
      2. Azure Container Registry           -- admin user DISABLED; the app pulls via its MI.
      3. Storage account + two tables       -- SIA's durable state (#7 governance register,
                                               #9 scheduler send markers). Without it both
                                               fall back to in-memory.
      4. Container Apps environment         -- PRIVATE: workload-profiles env with
                                               publicNetworkAccess=Disabled (#3a part 3).
      5. Private endpoint + private DNS     -- optional but required for anyone to REACH a
                                               private env. Skipped (loudly) without a subnet.
      6. The container app itself           -- internal ingress, target-port 8080, plain HTTP
                                               refused, multiple-revision mode, system MI.
      7. AcrPull for the app's MI           -- so it can pull its own image.
      8. Entra app registration             -- for Easy Auth, with the callback reply URL.

    WHAT IT DELIBERATELY DOES NOT DO -- these belong to Deploy-SIAnalyzer.ps1, which runs on
    every sync and is where they stay idempotently correct:
      * Log Analytics Reader / Cognitive Services OpenAI User / Storage Table Data
        Contributor grants on the app's MI.
      * Enabling Easy Auth on the app (this script only CREATES the app registration).
      * Rolling the image after the first one.
    Splitting it this way means the installer runs once and the updater runs nightly, rather
    than two scripts fighting over the same settings.

.PARAMETER ResourceGroup
    SIA's OWN resource group. Guarded against landing inside another solution's RG the same
    way Deploy-SIAnalyzer.ps1 is -- see -WorkspaceResourceId.

.PARAMETER WorkspaceResourceId
    ARM id of the SI Log Analytics workspace. Used ONLY as the #3b allowlist source: the RG
    segment of this id is SecurityInsight's resource group, and -ResourceGroup must equal it.
    Pass -AllowResourceGroupMismatch when the workspace legitimately lives elsewhere (it does
    in the internal env: same RG NAME, different subscription).

.PARAMETER Location
    Azure region for every resource created here. Default westeurope.

.PARAMETER SubscriptionId
    Target subscription. Defaults to the az CLI's current one.

.PARAMETER AcrName
    Registry name (globally unique, lowercase alphanumeric). Default derived from the RG.

.PARAMETER EnvName
    Container Apps environment name. Default cae-sia.

.PARAMETER AppName
    Container app name. Default ca-sia.

.PARAMETER StorageAccountName
    Storage account for SIA's two state tables. Default derived from the RG. Pass
    -SkipStorage for a deliberately non-durable install.

.PARAMETER PrivateEndpointSubnetId
    ARM id of the subnet to place the environment's private endpoint in. REQUIRED to make a
    private environment reachable. Without it the environment is created private and the app
    is unreachable until an endpoint is added -- which the script says loudly rather than
    quietly leaving a dead install.

.PARAMETER PrivateDnsZoneVnetId
    ARM id of the VNET to link the private DNS zone to. Defaults to the VNET containing
    -PrivateEndpointSubnetId.

.PARAMETER AllowPublicIngress
    Create the environment with public network access ENABLED. Fail-closed escape hatch that
    matches Deploy-SIAnalyzer.ps1's: #3a.3 says SIA must not be reachable from the internet,
    so making it so is a deliberate, warned act, never a default.

.PARAMETER AuthAppDisplayName
    Display name of the Entra app registration created for Easy Auth. Default
    'SecurityInsight Analyzer'. Matched by display name, so re-runs reuse it.

.PARAMETER SkipEntraApp
    Do not create the Entra app registration (e.g. the identity team pre-creates it, or the
    running principal has no Graph application permissions).

.PARAMETER SkipStorage
    Do not create the storage account. SIA's governance register and scheduler markers then
    fall back to in-memory -- see Deploy-SIAnalyzer.ps1's -StorageAccountId notes.

.PARAMETER SkipPrivateEndpoint
    Do not create the private endpoint / DNS zone even when a subnet is supplied.

.PARAMETER SkipAzLogin
    The caller has already signed the az CLI in. Same meaning as in Deploy-SIAnalyzer.ps1
    (audit #33): not a way to opt out of authentication -- without a context every az call
    below fails.

.OUTPUTS
    pscustomobject describing every resolved resource, plus DeployCommand: the exact
    Deploy-SIAnalyzer.ps1 invocation for this environment, with the ids already filled in.

.EXAMPLE
    # Full private install, then the sync's own deploy takes over from here.
    .\Install-SIAnalyzerEnvironment.ps1 -ResourceGroup rg-securityinsight `
        -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/Microsoft.OperationalInsights/workspaces/<ws>" `
        -PrivateEndpointSubnetId "/subscriptions/<sub>/resourceGroups/<net-rg>/providers/Microsoft.Network/virtualNetworks/<vnet>/subnets/<subnet>"

.EXAMPLE
    # See what a fresh customer install would do, without touching anything.
    .\Install-SIAnalyzerEnvironment.ps1 -ResourceGroup rg-securityinsight -WorkspaceResourceId <id> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$WorkspaceResourceId,
    [string]$Location = 'westeurope',
    [string]$SubscriptionId,
    [string]$AcrName,
    [string]$EnvName = 'cae-sia',
    [string]$AppName = 'ca-sia',
    [string]$StorageAccountName,
    [string]$GovernanceTableName = 'sigovernance',
    [string]$ScheduleTableName = 'sischedule',
    [string]$PrivateEndpointSubnetId,
    [string]$PrivateDnsZoneVnetId,
    [switch]$AllowResourceGroupMismatch,
    [switch]$AllowPublicIngress,
    [string]$AuthAppDisplayName = 'SecurityInsight Analyzer',
    [switch]$SkipEntraApp,
    [switch]$SkipStorage,
    [switch]$SkipPrivateEndpoint,
    [switch]$SkipAzLogin
)

$ErrorActionPreference = 'Stop'

# deploy/ -> analyzer-web/ -> SecurityInsight/ (the docker build context root).
$siRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dockerfile = Join-Path $PSScriptRoot 'Dockerfile'

# The image binds Kestrel to a FIXED port (deploy/Dockerfile: ASPNETCORE_URLS). Container Apps
# does not inject a port, so the app MUST be CREATED with this target-port -- Deploy-SIAnalyzer's
# audit #12 gate throws on a mismatch, and that gate is exactly what this constant feeds.
# tests/pester/SIA-Container.Tests.ps1 asserts the Dockerfile against the same number.
$ContainerListenPort = 8080

function _Step([string]$m) { Write-Host "  [STEP] $m" -ForegroundColor Cyan }
function _Ok  ([string]$m) { Write-Host "  [OK]   $m" -ForegroundColor Green }
function _Info([string]$m) { Write-Host "  [INFO] $m" -ForegroundColor Gray }
function _Warn([string]$m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function _Made([string]$m) { Write-Host "  [NEW]  $m" -ForegroundColor Magenta }

# az CLI writes harmless warnings to stderr (the 32-bit-Python notice among them), which PS 5.1
# under EAP=Stop turns into terminating NativeCommandErrors. Run az with EAP=Continue and judge
# by exit code -- the same pattern as Deploy-SIAnalyzer.ps1 and CEH's deploy-app.ps1.
function Invoke-Az {
    # -Quiet suppresses the stderr echo. Use it for EXISTENCE PROBES, where a non-zero exit is
    # the expected answer "not there yet" -- printing ResourceNotFound in red on every clean
    # install trains the operator to ignore red, which is how a real failure gets missed.
    param([Parameter(Mandatory)][string[]]$AzArgs, [switch]$Quiet)
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # -WhatIf sets $WhatIfPreference for the whole scope, and STREAM REDIRECTION honours it:
    # `2>$errFile` becomes a "What if: Output to File" line and writes nothing. Every az call
    # this function makes is a READ (the writes are guarded by ShouldProcess at the call sites),
    # and a -WhatIf run that cannot read the live environment cannot report what it would do --
    # it would claim it was creating resources that already exist. So the preference is turned
    # off locally: it belongs to the callers, not to the plumbing they use to look things up.
    $WhatIfPreference = $false
    $errFile = Join-Path $env:TEMP ("az-err-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    try { $out = az @AzArgs 2>$errFile } finally { $ErrorActionPreference = $eap }
    $script:AzExit = $LASTEXITCODE
    if ($script:AzExit -ne 0 -and -not $Quiet -and (Test-Path $errFile)) {
        Get-Content $errFile | Where-Object {
            $_ -and $_ -notmatch '32-bit Python|UserWarning|cryptography|CategoryInfo|FullyQualifiedErrorId|NativeCommandError|^\s*\+ |^At .*\.ps1:\d+ char:\d+' -and $_.Trim() -ne ''
        } | Select-Object -First 10 | ForEach-Object { Write-Host "   az: $_" -ForegroundColor Red }
    }
    Remove-Item $errFile -Force -ErrorAction SilentlyContinue
    return $out
}

# Existence probe. Returns $true only on a clean exit AND non-empty output: `az ... show` on a
# missing resource exits non-zero, but a query that selects nothing exits ZERO with a blank
# line, and treating that as "exists" would skip the create and fail later somewhere else.
function Test-AzExists {
    param([Parameter(Mandatory)][string[]]$AzArgs)
    $v = Invoke-Az $AzArgs -Quiet
    if ($script:AzExit -ne 0) { return $false }
    return -not [string]::IsNullOrWhiteSpace(($v -join '').Trim())
}

Write-Host ''
Write-Host '=== Install-SIAnalyzerEnvironment ===' -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# GUARDRAIL (#3b): SIA is BORN in SecurityInsight's own resource group.
#
# Identical rule to Deploy-SIAnalyzer.ps1's, and deliberately so -- an installer that can
# create the app in the wrong place makes the updater's guard pointless, because by the time
# the updater runs the mistake is already provisioned. -WorkspaceResourceId carries
# /resourceGroups/<rg>/, and THAT is SecurityInsight's resource group.
#
# Note this compares resource group NAMES, not subscriptions, which is correct: in the internal
# env the workspace lives in a different subscription under the same RG name, and that is a
# supported topology (the MI grant simply crosses subscriptions).
# ---------------------------------------------------------------------------
if ($WorkspaceResourceId -match '/resourceGroups/(?<rg>[^/]+)/') {
    $siResourceGroup = $Matches['rg']
    if ($ResourceGroup -ine $siResourceGroup) {
        $msg = "ResourceGroup '$ResourceGroup' is NOT SecurityInsight's resource group ('$siResourceGroup', derived from -WorkspaceResourceId). " +
               "SIA must be installed into the SAME resource group as the rest of SecurityInsight, never inside another solution's. " +
               "If the SI workspace genuinely lives in a different resource group, re-run with -AllowResourceGroupMismatch."
        if ($AllowResourceGroupMismatch) { Write-Warning $msg } else { throw $msg }
    }
} elseif (-not [string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
    throw "WorkspaceResourceId '$WorkspaceResourceId' does not contain a /resourceGroups/<name>/ segment, so SIA's resource group cannot be verified. Fix the resource id."
} else {
    _Warn 'No -WorkspaceResourceId: the #3b same-resource-group guard cannot run. Pass it on a real install.'
}

# --- AZ CLI SIGN-IN (audit #33) --------------------------------------------
# An Az PowerShell context is NOT an az CLI context -- separate token caches -- so a session
# that can read Key Vault happily still fails every az command here. Connect-SIAzCli bridges
# exactly that, from the customer's own config globals, and is idempotent.
if (-not $SkipAzLogin) {
    . (Join-Path $siRoot 'auth\Connect-SIAzCli.ps1')
    Connect-SIAzCli
}

if ($SubscriptionId) {
    [void](Invoke-Az @('account','set','--subscription',$SubscriptionId))
    if ($script:AzExit -ne 0) { throw "Could not select subscription $SubscriptionId." }
} else {
    $SubscriptionId = (Invoke-Az @('account','show','--query','id','-o','tsv'))
    if ($script:AzExit -ne 0 -or [string]::IsNullOrWhiteSpace($SubscriptionId)) {
        throw 'No az CLI subscription context. Pass -SubscriptionId or sign in first.'
    }
    $SubscriptionId = "$SubscriptionId".Trim()
}
_Info "subscription   : $SubscriptionId"

# ---------- Derived names ----------
# ACR: lowercase alphanumeric, 5-50 chars, globally unique. Same derivation as
# Initialize-SIContainerInfra.ps1 so the two halves of SI agree on naming.
if (-not $AcrName) {
    $AcrName = ('acr' + ($ResourceGroup -replace '[^a-zA-Z0-9]','')).ToLowerInvariant()
    if ($AcrName.Length -gt 50) { $AcrName = $AcrName.Substring(0, 50) }
    if ($AcrName.Length -lt 5)  { $AcrName = $AcrName + 'si' }
    _Info "AcrName derived: $AcrName"
}
# Storage: lowercase alphanumeric, 3-24 chars, globally unique.
if (-not $StorageAccountName) {
    $StorageAccountName = ('st' + ($ResourceGroup -replace '[^a-zA-Z0-9]','') + 'sia').ToLowerInvariant()
    if ($StorageAccountName.Length -gt 24) { $StorageAccountName = $StorageAccountName.Substring(0, 24) }
    _Info "Storage derived: $StorageAccountName"
}

_Info "resource group : $ResourceGroup"
_Info "location       : $Location"
_Info "environment    : $EnvName"
_Info "app            : $AppName"

$created = New-Object System.Collections.Generic.List[string]

# ===========================================================================
# 1. RESOURCE GROUP
# ===========================================================================
_Step "resource group $ResourceGroup"
if (Test-AzExists @('group','show','-n',$ResourceGroup,'--query','name','-o','tsv')) {
    _Ok "already exists"
} elseif ($PSCmdlet.ShouldProcess($ResourceGroup, 'create resource group')) {
    [void](Invoke-Az @('group','create','-n',$ResourceGroup,'-l',$Location,'--output','none'))
    if ($script:AzExit -ne 0) { throw "Could not create resource group $ResourceGroup." }
    _Made "created"; $created.Add("resource group $ResourceGroup")
}

# ===========================================================================
# 2. CONTAINER REGISTRY
#
# Admin user stays DISABLED: it is a shared username/password pair that would have to be
# stored somewhere, and the app pulls with its managed identity instead (step 7). Basic SKU
# is sufficient -- one repository, one image.
# ===========================================================================
_Step "container registry $AcrName"
if (Test-AzExists @('acr','show','-n',$AcrName,'-g',$ResourceGroup,'--query','name','-o','tsv')) {
    _Ok "already exists"
} elseif ($PSCmdlet.ShouldProcess($AcrName, 'create container registry')) {
    [void](Invoke-Az @('acr','create','-n',$AcrName,'-g',$ResourceGroup,'-l',$Location,'--sku','Basic','--admin-enabled','false','--output','none'))
    if ($script:AzExit -ne 0) { throw "Could not create container registry $AcrName." }
    _Made "created (Basic, admin user disabled)"; $created.Add("registry $AcrName")
}

# ===========================================================================
# 3. STORAGE ACCOUNT + SIA'S TWO STATE TABLES (audit #7 + #9)
#
# SIA GETS ITS OWN ACCOUNT, and that is a least-privilege decision rather than a naming one.
# Deploy-SIAnalyzer.ps1 grants the app's identity 'Storage Table Data Contributor' at ACCOUNT
# scope -- the narrowest scope that role supports for table access. Pointing SIA at the SI
# ENGINES' storage account would therefore hand the web app write access to every engine table
# in it (the CMDB, the fingerprint store, the Shodan budget), none of which SIA has any reason
# to touch. A separate account keeps that grant confined to SIA's own two tables.
#
# Created with the data plane locked down: TLS 1.2 floor, no public blob containers, and
# shared-key auth DISABLED so the only way in is Entra -- which is how the app reaches it
# (Storage Table Data Contributor on its MI, granted by Deploy-SIAnalyzer.ps1).
#
# The tables are created here rather than left to the app: the app does call
# CreateIfNotExists() at startup, but that path needs the MI grant to have landed first, and
# creating them now means a missing grant surfaces as a permission error naming the table
# instead of as an empty governance register that silently looks like "no exemptions yet".
# ===========================================================================
if ($SkipStorage) {
    _Warn 'storage SKIPPED (-SkipStorage): the governance register (#7) and scheduler markers (#9) will be IN-MEMORY -- acceptances are lost on restart and the exec email can double-send.'
    $storageAccountId = $null
} else {
    _Step "storage account $StorageAccountName"
    $storageAccountId = Invoke-Az @('storage','account','show','-n',$StorageAccountName,'-g',$ResourceGroup,'--query','id','-o','tsv') -Quiet
    if ($script:AzExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($storageAccountId)) {
        $storageAccountId = "$storageAccountId".Trim()
        _Ok "already exists"
    } elseif ($PSCmdlet.ShouldProcess($StorageAccountName, 'create storage account')) {
        [void](Invoke-Az @('storage','account','create','-n',$StorageAccountName,'-g',$ResourceGroup,'-l',$Location,
                           '--sku','Standard_LRS','--kind','StorageV2',
                           '--min-tls-version','TLS1_2','--allow-blob-public-access','false',
                           '--allow-shared-key-access','false','--output','none'))
        if ($script:AzExit -ne 0) { throw "Could not create storage account $StorageAccountName." }
        $storageAccountId = "$(Invoke-Az @('storage','account','show','-n',$StorageAccountName,'-g',$ResourceGroup,'--query','id','-o','tsv'))".Trim()
        _Made "created (TLS1.2, no public blob, shared-key auth disabled)"; $created.Add("storage $StorageAccountName")
    }

    # Shared-key access is off, so the table calls below must use the caller's Entra identity.
    foreach ($t in @($GovernanceTableName, $ScheduleTableName)) {
        _Step "table $t"
        $exists = Invoke-Az @('storage','table','exists','--name',$t,'--account-name',$StorageAccountName,'--auth-mode','login','--query','exists','-o','tsv') -Quiet
        if ($script:AzExit -eq 0 -and "$exists".Trim() -ieq 'true') {
            _Ok "already exists"
        } elseif ($PSCmdlet.ShouldProcess($t, 'create table')) {
            [void](Invoke-Az @('storage','table','create','--name',$t,'--account-name',$StorageAccountName,'--auth-mode','login','--output','none'))
            if ($script:AzExit -ne 0) {
                # Not fatal: the app creates its own tables at startup once the MI grant lands.
                # Worth a warning rather than a throw, because the usual cause is that the
                # INSTALLER's identity lacks Table Data Contributor -- which does not affect
                # whether SIA works, only whether this step could pre-create the table.
                _Warn "could not create table '$t' (the app will create it at startup once its MI grant lands). Usually means the installing identity lacks 'Storage Table Data Contributor' on $StorageAccountName."
            } else {
                _Made "created"; $created.Add("table $t")
            }
        }
    }
}

# ===========================================================================
# 4. CONTAINER APPS ENVIRONMENT -- PRIVATE (audit #3a part 3)
#
# Topology: a WORKLOAD-PROFILES environment with publicNetworkAccess=Disabled, reached over a
# private endpoint (step 5). This is the operator-approved shape -- no VNET injection, no
# public exposure -- and it is what the internal environment already runs, so the installer
# reproduces the proven topology rather than inventing a second one.
#
# publicNetworkAccess is set at CREATE time. It is settable afterwards too, but a window
# between "environment exists" and "environment is private" is exactly the exposure #3a.3 is
# about, so it is never opened here.
# ===========================================================================
_Step "container apps environment $EnvName"
if (Test-AzExists @('containerapp','env','show','-n',$EnvName,'-g',$ResourceGroup,'--query','name','-o','tsv')) {
    _Ok "already exists"
    $livePna = "$(Invoke-Az @('containerapp','env','show','-n',$EnvName,'-g',$ResourceGroup,'--query','properties.publicNetworkAccess','-o','tsv'))".Trim()
    if ($livePna -ieq 'Enabled' -and -not $AllowPublicIngress) {
        # Report, do not silently "fix": flipping an existing environment's network access is a
        # connectivity change for anything already using it. #3a.3 wants it private, and the
        # operator wants to know, but the decision to cut over is theirs.
        _Warn "environment $EnvName has publicNetworkAccess=Enabled. #3a.3 requires SIA to be unreachable from the internet. Fix with: az containerapp env update -n $EnvName -g $ResourceGroup --public-network-access Disabled  (verify a private endpoint exists FIRST, or the app becomes unreachable)."
    } else {
        _Info "publicNetworkAccess=$livePna"
    }
} elseif ($PSCmdlet.ShouldProcess($EnvName, 'create container apps environment')) {
    $pna = 'Disabled'
    if ($AllowPublicIngress) {
        _Warn 'creating the environment with PUBLIC network access (-AllowPublicIngress). #3a.3 says SIA must not be reachable from the internet -- this is a deliberate exception.'
        $pna = 'Enabled'
    }
    [void](Invoke-Az @('containerapp','env','create','-n',$EnvName,'-g',$ResourceGroup,'-l',$Location,
                       '--enable-workload-profiles','true','--public-network-access',$pna,'--output','none'))
    if ($script:AzExit -ne 0) { throw "Could not create container apps environment $EnvName." }
    _Made "created (workload profiles, publicNetworkAccess=$pna)"; $created.Add("environment $EnvName")
}
$envResourceId = "$(Invoke-Az @('containerapp','env','show','-n',$EnvName,'-g',$ResourceGroup,'--query','id','-o','tsv'))".Trim()

# ===========================================================================
# 5. PRIVATE ENDPOINT + PRIVATE DNS
#
# A private environment with no endpoint is not "secure", it is UNREACHABLE. Saying so is the
# point of this block: the install still succeeds (the endpoint is often the network team's to
# place), but it never pretends the result is usable.
#
# The DNS zone name is the environment's own defaultDomain, and three records point at the
# endpoint's IP: '@', '*' and '*.internal' -- the last one because internal-ingress apps get
# <app>.internal.<domain> and a bare wildcard does not cover a second label.
# ===========================================================================
$peName = "pe-$EnvName"
if ($SkipPrivateEndpoint) {
    _Warn "private endpoint SKIPPED (-SkipPrivateEndpoint)."
} elseif (-not $PrivateEndpointSubnetId) {
    if ($AllowPublicIngress) {
        _Info 'no private endpoint requested, and the environment is public by explicit exception.'
    } else {
        # Ask the ENVIRONMENT whether it is already reachable before warning that it is not.
        # A re-run against an environment whose endpoint was placed by the network team (or by
        # an earlier run with the subnet supplied) would otherwise report a healthy install as
        # broken -- and a warning that fires when nothing is wrong is a warning that stops
        # being read.
        # Counted in PowerShell rather than with a JMESPath length() -- `az` on Windows is a
        # BATCH FILE, so cmd.exe parses the argument list first and the parentheses in
        # `length(...)` terminate it early. The call then fails with "-o was unexpected at this
        # time", exit 255, which this check read as "no endpoint" and warned about an
        # environment that had one. Projecting a list and measuring it has no such problem.
        $peNames = @(Invoke-Az @('containerapp','env','show','-n',$EnvName,'-g',$ResourceGroup,'--query','properties.privateEndpointConnections[].name','-o','tsv') -Quiet |
                     Where-Object { $_ -and $_.Trim() })
        if ($script:AzExit -eq 0 -and $peNames.Count -gt 0) {
            _Ok "environment already has $($peNames.Count) private endpoint connection(s) -- no -PrivateEndpointSubnetId needed."
        } else {
            _Warn "NO -PrivateEndpointSubnetId, and the environment has no private endpoint connection. The environment is PRIVATE, which means $AppName is UNREACHABLE from anywhere until an endpoint is placed in a VNET that its users can route to. This is an incomplete install, not a hardened one -- re-run with -PrivateEndpointSubnetId, or have the network team add the endpoint to $envResourceId (group id 'managedEnvironments')."
        }
    }
} else {
    _Step "private endpoint $peName"
    if (Test-AzExists @('network','private-endpoint','show','-n',$peName,'-g',$ResourceGroup,'--query','name','-o','tsv')) {
        _Ok "already exists"
    } elseif ($PSCmdlet.ShouldProcess($peName, 'create private endpoint')) {
        [void](Invoke-Az @('network','private-endpoint','create','-n',$peName,'-g',$ResourceGroup,'-l',$Location,
                           '--subnet',$PrivateEndpointSubnetId,
                           '--private-connection-resource-id',$envResourceId,
                           '--group-id','managedEnvironments',
                           '--connection-name',"$peName-conn",'--output','none'))
        if ($script:AzExit -ne 0) { throw "Could not create private endpoint $peName." }
        _Made "created"; $created.Add("private endpoint $peName")
    }

    $defaultDomain = "$(Invoke-Az @('containerapp','env','show','-n',$EnvName,'-g',$ResourceGroup,'--query','properties.defaultDomain','-o','tsv'))".Trim()
    if ([string]::IsNullOrWhiteSpace($defaultDomain)) {
        _Warn 'could not read the environment defaultDomain, so the private DNS zone was not created.'
    } else {
        _Step "private DNS zone $defaultDomain"
        if (Test-AzExists @('network','private-dns','zone','show','-n',$defaultDomain,'-g',$ResourceGroup,'--query','name','-o','tsv')) {
            _Ok "already exists"
        } elseif ($PSCmdlet.ShouldProcess($defaultDomain, 'create private dns zone')) {
            [void](Invoke-Az @('network','private-dns','zone','create','-n',$defaultDomain,'-g',$ResourceGroup,'--output','none'))
            if ($script:AzExit -ne 0) { throw "Could not create private DNS zone $defaultDomain." }
            _Made "created"; $created.Add("dns zone $defaultDomain")
        }

        # Link the zone to the VNET the endpoint sits in, unless told otherwise.
        $vnetId = $PrivateDnsZoneVnetId
        if (-not $vnetId -and $PrivateEndpointSubnetId -match '^(?<v>.+)/subnets/[^/]+$') { $vnetId = $Matches['v'] }
        if ($vnetId) {
            $linkName = "$EnvName-link"
            _Step "dns zone link $linkName"
            if (Test-AzExists @('network','private-dns','link','vnet','show','-n',$linkName,'-g',$ResourceGroup,'-z',$defaultDomain,'--query','name','-o','tsv')) {
                _Ok "already exists"
            } elseif ($PSCmdlet.ShouldProcess($linkName, 'create dns zone vnet link')) {
                [void](Invoke-Az @('network','private-dns','link','vnet','create','-n',$linkName,'-g',$ResourceGroup,'-z',$defaultDomain,'-v',$vnetId,'-e','false','--output','none'))
                if ($script:AzExit -ne 0) { throw "Could not link private DNS zone $defaultDomain to $vnetId." }
                _Made "created"; $created.Add("dns link $linkName")
            }
        } else {
            _Warn 'could not derive a VNET from the subnet id, so the private DNS zone was not linked. Names will not resolve until it is.'
        }

        # Point the zone at the endpoint's private IP.
        $peIp = "$(Invoke-Az @('network','private-endpoint','show','-n',$peName,'-g',$ResourceGroup,'--query','customDnsConfigs[0].ipAddresses[0]','-o','tsv'))".Trim()
        if ([string]::IsNullOrWhiteSpace($peIp)) {
            _Warn 'could not read the private endpoint IP, so no DNS records were written.'
        } else {
            _Info "endpoint IP    : $peIp"
            # '*.internal' is NOT redundant with '*': internal-ingress apps resolve as
            # <app>.internal.<domain>, and a single-label wildcard does not match two labels.
            foreach ($rec in @('@','*','*.internal')) {
                _Step "A record $rec -> $peIp"
                $have = Invoke-Az @('network','private-dns','record-set','a','show','-n',$rec,'-g',$ResourceGroup,'-z',$defaultDomain,'--query','aRecords[0].ipv4Address','-o','tsv') -Quiet
                if ($script:AzExit -eq 0 -and "$have".Trim() -eq $peIp) {
                    _Ok "already points at $peIp"
                } elseif ($PSCmdlet.ShouldProcess("$rec.$defaultDomain", 'set A record')) {
                    [void](Invoke-Az @('network','private-dns','record-set','a','create','-n',$rec,'-g',$ResourceGroup,'-z',$defaultDomain,'--output','none'))
                    [void](Invoke-Az @('network','private-dns','record-set','a','add-record','-n',$rec,'-g',$ResourceGroup,'-z',$defaultDomain,'-a',$peIp,'--output','none'))
                    if ($script:AzExit -ne 0) { throw "Could not write A record $rec in $defaultDomain." }
                    _Made "set"; $created.Add("dns record $rec")
                }
            }
        }
    }
}

# ===========================================================================
# 6. THE CONTAINER APP
#
# Created with an image, because an app created against a placeholder that does not listen on
# $ContainerListenPort provisions into a permanently unhealthy revision -- and the next thing
# to run is Deploy-SIAnalyzer's health gate, which would refuse a swap and report it as an app
# fault. So: if the registry has no SIA image yet, build one here from this very tree. One
# build, and the install ends with something that actually serves.
#
# Every setting the app is CREATED with is one Deploy-SIAnalyzer.ps1 asserts and cannot fix:
# target-port (#12), allow-insecure (#13), internal ingress (#3a.3). Getting them right at
# birth is the whole point of #40 -- the alternative is provisioning the mistake and migrating
# out of it later, which is exactly what #3b is.
# ===========================================================================
_Step "container app $AppName"
if (Test-AzExists @('containerapp','show','-n',$AppName,'-g',$ResourceGroup,'--query','name','-o','tsv')) {
    _Ok "already exists (Deploy-SIAnalyzer.ps1 owns its image and settings from here on)"
} elseif ($PSCmdlet.ShouldProcess($AppName, 'create container app')) {
    $image = "$AcrName.azurecr.io/securityinsight-analyzer:install"
    $tags = Invoke-Az @('acr','repository','show-tags','-n',$AcrName,'--repository','securityinsight-analyzer','-o','tsv') -Quiet
    if ($script:AzExit -ne 0 -or [string]::IsNullOrWhiteSpace(($tags -join ''))) {
        _Info 'registry holds no securityinsight-analyzer image yet -- building one so the app is born serving.'
        if (-not (Test-Path -LiteralPath $dockerfile)) { throw "Dockerfile not found at $dockerfile -- cannot build the first image." }
        [void](Invoke-Az @('acr','build','--registry',$AcrName,'--image','securityinsight-analyzer:install','--file',$dockerfile,$siRoot,'--output','none'))
        if ($script:AzExit -ne 0) { throw 'az acr build failed while producing the first SIA image.' }
        _Made 'first image built'; $created.Add('image securityinsight-analyzer:install')
    } else {
        # Reuse the newest existing tag rather than rebuilding -- the updater rolls it anyway.
        $newest = @($tags | Where-Object { $_ -and $_.Trim() } | Select-Object -Last 1)
        if ($newest.Count -gt 0) { $image = "$AcrName.azurecr.io/securityinsight-analyzer:$($newest[0].Trim())" }
        _Info "reusing existing image $image"
    }

    # --ingress internal: reachable only inside the environment / over the private endpoint.
    [void](Invoke-Az @('containerapp','create','-n',$AppName,'-g',$ResourceGroup,'--environment',$EnvName,
                       '--image',$image,'--target-port',"$ContainerListenPort",'--ingress','internal',
                       '--transport','auto','--system-assigned',
                       '--registry-server',"$AcrName.azurecr.io",'--registry-identity','system',
                       '--min-replicas','1','--max-replicas','3','--output','none'))
    if ($script:AzExit -ne 0) { throw "Could not create container app $AppName." }
    _Made "created (internal ingress, target-port $ContainerListenPort, system-assigned identity)"
    $created.Add("app $AppName")

    # Multiple-revision mode is what makes Deploy-SIAnalyzer's PROD blue/green possible: the
    # live revision keeps 100% of traffic while the new one warms. Set at install so the very
    # first update is already zero-downtime.
    [void](Invoke-Az @('containerapp','revision','set-mode','-n',$AppName,'-g',$ResourceGroup,'--mode','multiple','--output','none'))
    if ($script:AzExit -ne 0) { _Warn 'could not set multiple-revision mode; Deploy-SIAnalyzer.ps1 sets it too.' }

    # Plain HTTP off (#13). The app emits HSTS and must not be undermined at the ingress.
    [void](Invoke-Az @('containerapp','ingress','update','-n',$AppName,'-g',$ResourceGroup,'--allow-insecure','false','--output','none'))
    if ($script:AzExit -ne 0) { _Warn 'could not set ingress.allowInsecure=false; Deploy-SIAnalyzer.ps1 gates on it and will refuse to proceed.' }
}

$appPrincipalId = "$(Invoke-Az @('containerapp','show','-n',$AppName,'-g',$ResourceGroup,'--query','identity.principalId','-o','tsv'))".Trim()
$appFqdn        = "$(Invoke-Az @('containerapp','show','-n',$AppName,'-g',$ResourceGroup,'--query','properties.configuration.ingress.fqdn','-o','tsv'))".Trim()

# ===========================================================================
# 7. AcrPull FOR THE APP'S MANAGED IDENTITY
#
# The one grant that belongs to INSTALL rather than to the updater: without it the app cannot
# pull its own image, so it never starts, so there is nothing for the updater to update. The
# data-plane grants (Log Analytics Reader, OpenAI User, Storage Table Data Contributor) stay
# in Deploy-SIAnalyzer.ps1, which re-applies them on every sync.
# ===========================================================================
if ([string]::IsNullOrWhiteSpace($appPrincipalId)) {
    _Warn 'no system-assigned principal id on the app yet -- skipping the AcrPull grant.'
} else {
    _Step "AcrPull for the app identity on $AcrName"
    $acrId = "$(Invoke-Az @('acr','show','-n',$AcrName,'-g',$ResourceGroup,'--query','id','-o','tsv'))".Trim()
    $have = Invoke-Az @('role','assignment','list','--assignee',$appPrincipalId,'--scope',$acrId,'--role','AcrPull','--query','[0].id','-o','tsv') -Quiet
    if ($script:AzExit -eq 0 -and -not [string]::IsNullOrWhiteSpace(($have -join '').Trim())) {
        _Ok 'already granted'
    } elseif ($PSCmdlet.ShouldProcess("$AppName -> $AcrName", 'grant AcrPull')) {
        [void](Invoke-Az @('role','assignment','create','--assignee-object-id',$appPrincipalId,'--assignee-principal-type','ServicePrincipal','--role','AcrPull','--scope',$acrId,'--output','none'))
        if ($script:AzExit -ne 0) { _Warn 'could not grant AcrPull -- the installing identity needs Microsoft.Authorization/roleAssignments/write on the registry. The app cannot pull its image until this lands.' }
        else { _Made 'granted'; $created.Add('AcrPull grant') }
    }
}

# ===========================================================================
# 8. ENTRA APP REGISTRATION FOR EASY AUTH
#
# Created here, ENABLED by Deploy-SIAnalyzer.ps1 (-AuthClientId/-AuthTenantId). Split that way
# because creating a directory object needs Graph application permissions the deploy identity
# may not hold, while enabling Easy Auth is an ARM operation on the app it already owns.
#
# Matched by display name so a re-run reuses the existing registration instead of littering
# the tenant with duplicates -- there is no natural idempotency key for an app registration.
# ===========================================================================
$authClientId = $null
$authTenantId = "$(Invoke-Az @('account','show','--query','tenantId','-o','tsv'))".Trim()
if ($SkipEntraApp) {
    _Warn 'Entra app registration SKIPPED (-SkipEntraApp). Easy Auth cannot be enabled without one.'
} else {
    _Step "Entra app registration '$AuthAppDisplayName'"
    $found = Invoke-Az @('ad','app','list','--display-name',$AuthAppDisplayName,'--query','[0].appId','-o','tsv')
    if ($script:AzExit -ne 0) {
        _Warn "could not query Entra app registrations -- the installing identity likely lacks Graph Application.Read.All. Create '$AuthAppDisplayName' manually and pass its client id to Deploy-SIAnalyzer.ps1 -AuthClientId."
    } elseif (-not [string]::IsNullOrWhiteSpace(($found -join '').Trim())) {
        $authClientId = "$found".Trim()
        _Ok "already exists (appId $authClientId)"
    } elseif ($PSCmdlet.ShouldProcess($AuthAppDisplayName, 'create Entra app registration')) {
        $replyUrl = $null
        if (-not [string]::IsNullOrWhiteSpace($appFqdn)) { $replyUrl = "https://$appFqdn/.auth/login/aad/callback" }
        $adArgs = @('ad','app','create','--display-name',$AuthAppDisplayName,'--sign-in-audience','AzureADMyOrg','--query','appId','-o','tsv')
        if ($replyUrl) { $adArgs += @('--web-redirect-uris',$replyUrl) }
        $authClientId = Invoke-Az $adArgs
        if ($script:AzExit -ne 0 -or [string]::IsNullOrWhiteSpace(($authClientId -join '').Trim())) {
            $authClientId = $null
            _Warn "could not create the app registration -- the installing identity needs Graph Application.ReadWrite.All (or an admin creates it). Easy Auth stays off until one exists."
        } else {
            $authClientId = "$authClientId".Trim()
            _Made "created (appId $authClientId, reply URL $replyUrl)"; $created.Add("Entra app $AuthAppDisplayName")
        }
    }

    # An app registration alone does not authenticate anything -- Easy Auth resolves the caller
    # against a SERVICE PRINCIPAL in this tenant. Creating the registration without it is the
    # kind of half-configured state that surfaces much later as a login loop.
    if ($authClientId) {
        _Step "service principal for $authClientId"
        if (Test-AzExists @('ad','sp','show','--id',$authClientId,'--query','id','-o','tsv')) {
            _Ok 'already exists'
        } elseif ($PSCmdlet.ShouldProcess($authClientId, 'create service principal')) {
            [void](Invoke-Az @('ad','sp','create','--id',$authClientId,'--output','none'))
            if ($script:AzExit -ne 0) { _Warn 'could not create the service principal; Easy Auth sign-in will fail until it exists.' }
            else { _Made 'created'; $created.Add('service principal') }
        }
    }
}

# ===========================================================================
# SUMMARY + THE HANDOFF TO THE UPDATER
# ===========================================================================
Write-Host ''
Write-Host '=== install summary ===' -ForegroundColor Cyan
if ($created.Count -eq 0) { _Ok 'nothing to create -- every precondition was already in place (idempotent re-run).' }
else { foreach ($c in $created) { _Made $c } }

$deployArgs = @(
    ".\analyzer-web\deploy\Deploy-SIAnalyzer.ps1 -Env prod"
    "-ResourceGroup $ResourceGroup"
    "-AcrName $AcrName"
    "-AppName $AppName"
)
if ($WorkspaceResourceId) {
    $deployArgs += "-WorkspaceResourceId `"$WorkspaceResourceId`""
    if ($AllowResourceGroupMismatch) { $deployArgs += '-AllowResourceGroupMismatch' }
}
if ($storageAccountId) { $deployArgs += "-StorageAccountId `"$storageAccountId`"" }
if ($authClientId)     { $deployArgs += "-AuthClientId $authClientId -AuthTenantId $authTenantId" }

Write-Host ''
Write-Host 'Next: the EXISTING deploy path takes over -- it runs on every sync, and this is the' -ForegroundColor Cyan
Write-Host 'same command with the ids from this install filled in:' -ForegroundColor Cyan
Write-Host ("  " + ($deployArgs -join " `\`n      ")) -ForegroundColor White
if (-not [string]::IsNullOrWhiteSpace($appFqdn)) {
    Write-Host ''
    Write-Host "  app FQDN: https://$appFqdn  (private -- resolvable only from a linked VNET)" -ForegroundColor Gray
}

[pscustomobject]@{
    SubscriptionId      = $SubscriptionId
    ResourceGroup       = $ResourceGroup
    Location            = $Location
    AcrName             = $AcrName
    EnvName             = $EnvName
    EnvResourceId       = $envResourceId
    AppName             = $AppName
    AppFqdn             = $appFqdn
    AppPrincipalId      = $appPrincipalId
    StorageAccountId    = $storageAccountId
    GovernanceTableName = $GovernanceTableName
    ScheduleTableName   = $ScheduleTableName
    AuthClientId        = $authClientId
    AuthTenantId        = $authTenantId
    Created             = @($created)
    DeployCommand       = ($deployArgs -join ' ')
}
