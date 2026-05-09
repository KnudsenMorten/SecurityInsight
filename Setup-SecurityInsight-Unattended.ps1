#Requires -Version 5.1
<#
.SYNOPSIS
    Unattended Setup for SecurityInsight v2.2 -- no browser, no GUI, no operator interaction.

.DESCRIPTION
    Standalone alternative to setup\ConfigWizard\Start-SetupWizard.ps1 (the
    HTML wizard). Reads setup-unattended.json + CLI overrides, picks a
    flavour (Internal vs Community), then drives the same backend cmdlets
    the HTML wizard uses (New-SISpn / Initialize-SIInfra /
    Write-SICustomConfig / Set-SIEntraDiagnosticSetting /
    Initialize-SIContainerInfra) in sequence.

    Two flavours:

      Internal  -- existing v1 customer migrating to v2 SecurityInsight.
                   Re-uses the v1 cert-based SPN ($global:HighPriv_Modern_*)
                   from platform-defaults.ps1; tops up Graph perms only.
                   Renders the v1<->v2 BRIDGE custom.ps1 (no secrets in file).
                   Connects to all 3 surfaces (Az PS / Mg / az CLI) using the
                   v1 cert in LocalMachine\My.

      Community -- standalone install (no v1 platform layer). Creates a
                   new SI SPN with cert in LocalCertStore (or KV). Renders
                   the INLINE custom.ps1 (resolved values written directly).
                   Operator must Connect-AzAccount + Connect-MgGraph in
                   their shell first (same prereq as the HTML wizard).

    Idempotent. Re-run whenever you want; backend cmdlets short-circuit on
    "already in place" / "already granted".

.PARAMETER ConfigPath
    Path to setup-unattended.json. Default: <repo>\config\setup-unattended.json,
    falling back to <repo>\config\setup-unattended.sample.json if the customer
    file doesn't exist.

.PARAMETER Flavour
    Override the JSON's Flavour. 'Internal' | 'Community'.

.PARAMETER TenantId
    Override Sub.TenantId.

.PARAMETER SubscriptionId
    Override Sub.SubscriptionId.

.PARAMETER Location
    Override Sub.Location.

.PARAMETER NamingSuffix
    Override Resources.NamingSuffix.

.PARAMETER EntraDiag_Enabled
    Force EntraDiag.Enabled = $true (overrides JSON).

.PARAMETER Container_Enabled
    Force Container.Enabled = $true (overrides JSON).

.PARAMETER SkipPhase1
    Skip the SPN phase entirely (use when an admin pre-granted Graph perms
    out-of-band). Phase 2-5 still run.

.OUTPUTS
    Exit code: 0 = all enabled phases completed; non-zero on first failure.
    Per-phase status streams to Write-Host with [STEP]/[OK]/[WARN]/[ERR] markers.

.EXAMPLE
    # Internal flavour (FVF-style migration). Reads setup-unattended.json,
    # connects via v1 cert, deploys SI v2 onto the existing v1 platform.
    .\Setup-SecurityInsight-Unattended.ps1

.EXAMPLE
    # One-off override for a Sentinel customer who NOW wants Entra Diag too:
    .\Setup-SecurityInsight-Unattended.ps1 -EntraDiag_Enabled

.EXAMPLE
    # Community install with a custom config path:
    .\Setup-SecurityInsight-Unattended.ps1 -ConfigPath D:\customers\acme.json -Flavour Community

.NOTES
    Status: v2.2.151 -- new in this release.
    Developed by Morten Knudsen, Microsoft MVP | https://mortenknudsen.net
#>
[CmdletBinding()]
param(
    [Parameter()] [string]$ConfigPath,
    [Parameter()] [ValidateSet('Internal','Community')] [string]$Flavour,
    [Parameter()] [string]$TenantId,
    [Parameter()] [string]$SubscriptionId,
    [Parameter()] [string]$Location,
    [Parameter()] [string]$NamingSuffix,
    [Parameter()] [switch]$EntraDiag_Enabled,
    [Parameter()] [switch]$Container_Enabled,
    [Parameter()] [switch]$SkipPhase1,
    [Parameter()] [switch]$SkipPlatformDefaults
)

$ErrorActionPreference = 'Stop'

# ----------- Logging helpers (mirror the wizard's style) -----------
function _Banner([string]$msg) { Write-Host ""; Write-Host ("=== {0} ===" -f $msg) -ForegroundColor Cyan }
function _Step  ([string]$msg) { Write-Host ("  [STEP] {0}" -f $msg) -ForegroundColor Cyan }
function _Ok    ([string]$msg) { Write-Host ("  [OK]   {0}" -f $msg) -ForegroundColor Green }
function _Info  ([string]$msg) { Write-Host ("  [INFO] {0}" -f $msg) -ForegroundColor Gray }
function _Warn  ([string]$msg) { Write-Host ("  [WARN] {0}" -f $msg) -ForegroundColor Yellow }
function _Err   ([string]$msg) { Write-Host ("  [ERR]  {0}" -f $msg) -ForegroundColor Red }

# ----------- Resolve repo root + paths -----------
$repoRoot   = $PSScriptRoot
$backendDir = Join-Path $repoRoot 'setup\ConfigWizard\backend'

$cmdletNewSISpn      = Join-Path $backendDir 'New-SISpn.ps1'
$cmdletInitInfra     = Join-Path $backendDir 'Initialize-SIInfra.ps1'
$cmdletWriteConfig   = Join-Path $backendDir 'Write-SICustomConfig.ps1'
$cmdletEntraDiag     = Join-Path $backendDir 'Set-SIEntraDiagnosticSetting.ps1'
$cmdletContainer     = Join-Path $backendDir 'Initialize-SIContainerInfra.ps1'
foreach ($c in $cmdletNewSISpn, $cmdletInitInfra, $cmdletWriteConfig, $cmdletEntraDiag, $cmdletContainer) {
    if (-not (Test-Path -LiteralPath $c)) { throw "backend cmdlet missing: $c" }
}

# Load VERSION for the banner
$siVersion = 'unknown'
$verFile   = Join-Path $repoRoot 'VERSION'
if (Test-Path -LiteralPath $verFile) { $siVersion = (Get-Content -LiteralPath $verFile -Raw).Trim() }

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Setup -- UNATTENDED MODE" -ForegroundColor Cyan
Write-Host (" v{0}" -f $siVersion) -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " Built by Morten Knudsen, Microsoft MVP"  -ForegroundColor Gray
Write-Host " Web    : https://mortenknudsen.net"     -ForegroundColor Gray
Write-Host " GitHub : https://github.com/KnudsenMorten/SecurityInsight" -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# ----------- Load setup-unattended.json -----------
if (-not $ConfigPath) {
    $cfgCustom = Join-Path $repoRoot 'config\setup-unattended.json'
    $cfgSample = Join-Path $repoRoot 'config\setup-unattended.sample.json'
    if     (Test-Path -LiteralPath $cfgCustom) { $ConfigPath = $cfgCustom }
    elseif (Test-Path -LiteralPath $cfgSample) { $ConfigPath = $cfgSample; _Warn "no setup-unattended.json found -- using sample defaults from $cfgSample" }
    else { throw "No setup-unattended.json found. Copy config\setup-unattended.sample.json -> config\setup-unattended.json and edit." }
}
_Info ("config path  : {0}" -f $ConfigPath)

try {
    $cfgRaw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
    $cfg    = $cfgRaw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw ("Could not parse {0}: {1}" -f $ConfigPath, $_.Exception.Message)
}

# ----------- Apply CLI overrides on top of JSON -----------
if ($PSBoundParameters.ContainsKey('Flavour'))         { $cfg.Flavour                  = $Flavour }
if ($PSBoundParameters.ContainsKey('TenantId'))        { $cfg.Sub.TenantId             = $TenantId }
if ($PSBoundParameters.ContainsKey('SubscriptionId'))  { $cfg.Sub.SubscriptionId       = $SubscriptionId }
if ($PSBoundParameters.ContainsKey('Location'))        { $cfg.Sub.Location             = $Location }
if ($PSBoundParameters.ContainsKey('NamingSuffix'))    { $cfg.Resources.NamingSuffix   = $NamingSuffix }
if ($EntraDiag_Enabled)                                 { $cfg.EntraDiag.Enabled        = $true }
if ($Container_Enabled)                                 { $cfg.Container.Enabled        = $true }

if (-not $cfg.Flavour) { throw "Flavour not set (must be 'Internal' or 'Community')." }
_Info ("flavour      : {0}" -f $cfg.Flavour)

# ----------- Internal flavour: dot-source platform-defaults.ps1 -----------
$pdLoaded = $false
if ($cfg.Flavour -eq 'Internal') {
    if ($SkipPlatformDefaults) {
        # Operator pre-loaded platform-defaults via their own connect script
        # (e.g. v1 ConnectDetails + Default_Variables + Connect_Azure.ps1 chain).
        # Trust that $global:AzureTenantId / HighPriv_Modern_* are already set.
        _Step "skip platform-defaults dot-source (-SkipPlatformDefaults)"
        if (-not $global:HighPriv_Modern_CertificateThumbprint_Azure) {
            throw "-SkipPlatformDefaults was passed but `$global:HighPriv_Modern_CertificateThumbprint_Azure is not set. Run your connect script first, then re-run."
        }
        $global:AutomationFramework = $true
        $pdLoaded = $true
        _Ok "using pre-loaded globals"
    } else {
        $pdPath = $cfg.Auth_Internal.PlatformDefaultsPath
        if (-not $pdPath) {
            # Auto-resolve: SOLUTIONS\PlatformConfiguration\config\platform-defaults.ps1
            # is at <repo>\..\PlatformConfiguration\config\platform-defaults.ps1 since
            # the SI repo lives at SOLUTIONS\SecurityInsight\.
            $pdPath = Join-Path (Split-Path -Parent $repoRoot) 'PlatformConfiguration\config\platform-defaults.ps1'
        }
        if (-not (Test-Path -LiteralPath $pdPath)) {
            throw ("platform-defaults.ps1 not found at {0}. Internal flavour requires it (port from v1's Automation-DefaultVariables.psm1), OR pass -SkipPlatformDefaults if you've pre-loaded globals via your own connect script. See bootstrap\Onboarding.txt step 3." -f $pdPath)
        }
        # v1 Connect_Azure.ps1 + Default_Variables branch on this flag to take the
        # cert-based unattended auth path (vs interactive). Set BEFORE dot-source so
        # the cert thumbprint + tenant + KV context globals get populated.
        $global:AutomationFramework = $true

        _Step ("dot-source platform-defaults.ps1 ({0})" -f $pdPath)
        . $pdPath
        $pdLoaded = $true
        _Ok "platform-defaults.ps1 loaded"
    }

    # Resolve Internal-flavour params from globals when not explicitly set
    if (-not $cfg.Sub.TenantId)            { $cfg.Sub.TenantId       = $global:AzureTenantId }
    if (-not $cfg.Sub.SubscriptionId)      { $cfg.Sub.SubscriptionId = $global:MainLogAnalyticsWorkspaceSubId }
    if (-not $cfg.Auth_Internal.AppId)     { $cfg.Auth_Internal.AppId                 = $global:HighPriv_Modern_ApplicationID_Azure }
    if (-not $cfg.Auth_Internal.CertificateThumbprint) {
                                             $cfg.Auth_Internal.CertificateThumbprint = $global:HighPriv_Modern_CertificateThumbprint_Azure
    }
}

# Validate the resolved values
if (-not $cfg.Sub.TenantId)       { throw "Sub.TenantId not set (and `$global:AzureTenantId is empty). Pass -TenantId or fix platform-defaults.ps1." }
if (-not $cfg.Sub.SubscriptionId) { throw "Sub.SubscriptionId not set (and `$global:MainLogAnalyticsWorkspaceSubId is empty). Pass -SubscriptionId or fix platform-defaults.ps1." }
if (-not $cfg.Sub.Location)       { $cfg.Sub.Location = 'westeurope' }
if ($cfg.Flavour -eq 'Internal') {
    if (-not $cfg.Auth_Internal.AppId)                  { throw "Auth_Internal.AppId not set (and `$global:HighPriv_Modern_ApplicationID_Azure is empty)." }
    if (-not $cfg.Auth_Internal.CertificateThumbprint)  { throw "Auth_Internal.CertificateThumbprint not set (and `$global:HighPriv_Modern_CertificateThumbprint_Azure is empty)." }
}

# Apply NamingSuffix to resource names if set
if ($cfg.Resources.NamingSuffix) {
    $sfx = $cfg.Resources.NamingSuffix
    if ($cfg.Resources.ResourceGroupName  -notlike "*$sfx") { $cfg.Resources.ResourceGroupName  = "$($cfg.Resources.ResourceGroupName)$sfx" }
    if ($cfg.Resources.WorkspaceName      -notlike "*$sfx") { $cfg.Resources.WorkspaceName      = "$($cfg.Resources.WorkspaceName)$sfx" }
    if ($cfg.Resources.DceName            -notlike "*$sfx") { $cfg.Resources.DceName            = "$($cfg.Resources.DceName)$sfx" }
}
# Auto-derive StorageAccountName when null (lowercase alnum, max 24, no hyphens)
if (-not $cfg.Resources.StorageAccountName) {
    $sa = ('st' + (($cfg.Resources.ResourceGroupName -replace '[^a-z0-9]','') + 'si')).ToLowerInvariant()
    if ($sa.Length -gt 24) { $sa = $sa.Substring(0, 24) }
    $cfg.Resources.StorageAccountName = $sa
}

_Info ("tenant       : {0}" -f $cfg.Sub.TenantId)
_Info ("subscription : {0}" -f $cfg.Sub.SubscriptionId)
_Info ("location     : {0}" -f $cfg.Sub.Location)
_Info ("RG / WS / DCE / Storage : {0} / {1} / {2} / {3}" -f $cfg.Resources.ResourceGroupName, $cfg.Resources.WorkspaceName, $cfg.Resources.DceName, $cfg.Resources.StorageAccountName)
Write-Host ""

# ----------- Internal flavour: cert-based connect (Az PS + Mg + optional az CLI) -----------
if ($cfg.Flavour -eq 'Internal') {
    _Banner "Cert-based connect (v1 SPN)"
    $tenantId = $cfg.Sub.TenantId
    $appId    = $cfg.Auth_Internal.AppId
    $thumb    = $cfg.Auth_Internal.CertificateThumbprint

    # Verify cert exists
    $certPath = "Cert:\LocalMachine\My\$thumb"
    $cert = Get-Item -Path $certPath -ErrorAction SilentlyContinue
    if (-not $cert) {
        $certPath = "Cert:\CurrentUser\My\$thumb"
        $cert = Get-Item -Path $certPath -ErrorAction SilentlyContinue
    }
    if (-not $cert) {
        throw ("v1 cert with thumbprint {0} not found in LocalMachine\My or CurrentUser\My. Install the v1 bootstrap cert before retrying." -f $thumb)
    }
    _Ok ("cert found in {0} (subject={1}, expires={2:u})" -f $cert.PSPath, $cert.Subject, $cert.NotAfter)

    _Step ("Connect-AzAccount via cert (AppId={0})" -f $appId)
    Import-Module Az.Accounts -ErrorAction Stop
    $null = Connect-AzAccount -ServicePrincipal -Tenant $tenantId -ApplicationId $appId -CertificateThumbprint $thumb -Subscription $cfg.Sub.SubscriptionId -ErrorAction Stop
    _Ok "Az PS connected"

    _Step ("Connect-MgGraph via cert (AppId={0})" -f $appId)
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $null = Connect-MgGraph -TenantId $tenantId -ClientId $appId -CertificateThumbprint $thumb -NoWelcome -ErrorAction Stop
    _Ok "Microsoft Graph connected"

    # az CLI is only needed when Phase 5 (container) will run
    if ($cfg.Container.Enabled) {
        _Step "az CLI cert login (Container Apps Job phase needs it)"
        # Export the cert + key to a temp PEM for `az login --service-principal --certificate`
        # (az CLI doesn't accept thumbprint references; needs the PEM file).
        $tmpPem = Join-Path ([IO.Path]::GetTempPath()) ("si-unattended-{0}.pem" -f ([guid]::NewGuid().Guid))
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            if (-not $rsa) { throw "Cert has no exportable RSA private key. Re-import with the .pfx if needed." }
            # Build a PEM containing private key + certificate
            $keyPem  = "-----BEGIN PRIVATE KEY-----`n" + [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(), [Base64FormattingOptions]::InsertLineBreaks) + "`n-----END PRIVATE KEY-----`n"
            $certPem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.RawData, [Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----`n"
            Set-Content -LiteralPath $tmpPem -Value ($keyPem + $certPem) -NoNewline -Encoding ASCII
            $null = & az login --service-principal --tenant $tenantId --username $appId --certificate $tmpPem --output none 2>&1
            if ($LASTEXITCODE -ne 0) { throw "az login (cert) failed; check cert + AppId + tenant." }
            $null = & az account set --subscription $cfg.Sub.SubscriptionId 2>&1
            _Ok ("az CLI signed in (sub {0})" -f $cfg.Sub.SubscriptionId)
        } finally {
            if (Test-Path -LiteralPath $tmpPem) { Remove-Item -LiteralPath $tmpPem -Force -ErrorAction SilentlyContinue }
        }
    }
} else {
    # Community flavour: caller is expected to have done Connect-AzAccount + Connect-MgGraph
    # in the same shell (matches the HTML wizard's pre-flight contract).
    _Banner "Community flavour -- using operator's existing Az + Mg context"
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
    $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
    if (-not $azCtx) { throw "No Az context. Run Connect-AzAccount in this shell first." }
    if (-not $mgCtx) { throw "No Microsoft Graph context. Run Connect-MgGraph in this shell first." }
    _Ok ("Az PS  : {0} (sub {1})" -f $azCtx.Account.Id, $azCtx.Subscription.Id)
    _Ok ("MgGraph: {0} (tenant {1})" -f $mgCtx.Account, $mgCtx.TenantId)
}

# Result accumulators
$spnOut       = $null
$infraOut     = $null
$cfgOut       = $null
$diagOut      = $null
$containerOut = $null
$phaseStatus  = @{ spn='pending'; infra='pending'; config='pending'; entraDiag='pending'; container='pending' }

# ----------------------------------------------------------------------------
# Phase 1 -- SPN
# ----------------------------------------------------------------------------
if ($SkipPhase1) {
    $phaseStatus.spn = 'skipped'
    _Warn 'Phase 1 (SPN) skipped via -SkipPhase1'
} else {
    try {
        if ($cfg.Flavour -eq 'Internal') {
            $spnArgs = @{
                TenantId          = $cfg.Sub.TenantId
                SubscriptionId    = $cfg.Sub.SubscriptionId
                UseExistingAppId  = $true
                ExistingAppId     = $cfg.Auth_Internal.AppId
                ExistingThumbprint= $cfg.Auth_Internal.CertificateThumbprint
            }
            if (-not $cfg.Auth_Internal.TopUpGraphPerms) { $spnArgs.SkipAdminConsent = $true }
            $spnOut = & $cmdletNewSISpn @spnArgs
        } else {
            # Community flavour
            $spnArgs = @{
                DisplayName    = $cfg.Auth_Community.DisplayName
                TenantId       = $cfg.Sub.TenantId
                SubscriptionId = $cfg.Sub.SubscriptionId
                CredKind       = $cfg.Auth_Community.CredKind
                CredStorage    = $cfg.Auth_Community.CredStorage
            }
            if ($cfg.Auth_Community.KeyVaultName) { $spnArgs.KeyVaultName = $cfg.Auth_Community.KeyVaultName }
            $spnOut = & $cmdletNewSISpn @spnArgs
        }
        $phaseStatus.spn = 'ok'
    } catch {
        $phaseStatus.spn = 'failed'
        _Err "Phase 1 (SPN) failed: $($_.Exception.Message)"
        throw
    }
}

# ----------------------------------------------------------------------------
# Phase 2 -- Infrastructure (LA + DCE + Storage + RBAC)
# ----------------------------------------------------------------------------
try {
    $infraArgs = @{
        SpnObjectId        = $spnOut.ObjectId
        TenantId           = $cfg.Sub.TenantId
        SubscriptionId     = $cfg.Sub.SubscriptionId
        ResourceGroupName  = $cfg.Resources.ResourceGroupName
        Location           = $cfg.Sub.Location
        WorkspaceName      = $cfg.Resources.WorkspaceName
        DceName            = $cfg.Resources.DceName
        StorageAccountName = $cfg.Resources.StorageAccountName
    }
    $infraOut = & $cmdletInitInfra @infraArgs
    $phaseStatus.infra = 'ok'
} catch {
    $phaseStatus.infra = 'failed'
    _Err "Phase 2 (Infrastructure) failed: $($_.Exception.Message)"
    throw
}

# ----------------------------------------------------------------------------
# Phase 3 -- Config file (Bridged for Internal, Inline for Community)
# ----------------------------------------------------------------------------
try {
    $cfgArgs = @{
        Spn   = $spnOut
        Infra = $infraOut
        Mode  = if ($cfg.Flavour -eq 'Internal') { 'Bridged' } else { 'Inline' }
    }
    $cfgOut = & $cmdletWriteConfig @cfgArgs
    $phaseStatus.config = 'ok'
} catch {
    $phaseStatus.config = 'failed'
    _Err "Phase 3 (Config file) failed: $($_.Exception.Message)"
    throw
}

# ----------------------------------------------------------------------------
# Phase 4 -- Entra ID Diagnostic Setting (toggle-gated)
# ----------------------------------------------------------------------------
if ($cfg.EntraDiag.Enabled) {
    try {
        $diagOut = & $cmdletEntraDiag -WorkspaceResourceId $infraOut.WorkspaceResourceId
        $phaseStatus.entraDiag = 'ok'
    } catch {
        $phaseStatus.entraDiag = 'failed'
        _Err "Phase 4 (Entra Diag) failed: $($_.Exception.Message)"
        throw
    }
} else {
    $phaseStatus.entraDiag = 'skipped'
    _Info 'Phase 4 (Entra Diag) skipped (EntraDiag.Enabled=false)'
}

# ----------------------------------------------------------------------------
# Phase 5 -- Container Apps Job runtime (toggle-gated)
# ----------------------------------------------------------------------------
if ($cfg.Container.Enabled) {
    try {
        $containerArgs = @{
            ResourceGroupName = $cfg.Resources.ResourceGroupName
            Location          = $cfg.Sub.Location
            SubscriptionId    = $cfg.Sub.SubscriptionId
        }
        if ($cfg.Container.AcrName)         { $containerArgs.AcrName         = $cfg.Container.AcrName }
        if ($cfg.Container.EnvName)         { $containerArgs.EnvName         = $cfg.Container.EnvName }
        if ($null -ne $cfg.Container.UseKEDA) { $containerArgs.UseKEDA       = [bool]$cfg.Container.UseKEDA }
        if ($cfg.Container.KedaMaxReplicas) { $containerArgs.KedaMaxReplicas = [int]$cfg.Container.KedaMaxReplicas }
        $containerOut = & $cmdletContainer @containerArgs
        $phaseStatus.container = 'ok'
    } catch {
        $phaseStatus.container = 'failed'
        _Err "Phase 5 (Container) failed: $($_.Exception.Message)"
        throw
    }
} else {
    $phaseStatus.container = 'skipped'
    _Info 'Phase 5 (Container) skipped (Container.Enabled=false)'
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host (" UNATTENDED SETUP DONE  (flavour={0})" -f $cfg.Flavour) -ForegroundColor Magenta
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host (" SPN       : {0}" -f $phaseStatus.spn)       -ForegroundColor Gray
Write-Host (" Infra     : {0}" -f $phaseStatus.infra)     -ForegroundColor Gray
Write-Host (" Config    : {0}" -f $phaseStatus.config)    -ForegroundColor Gray
Write-Host (" EntraDiag : {0}" -f $phaseStatus.entraDiag) -ForegroundColor Gray
Write-Host (" Container : {0}" -f $phaseStatus.container) -ForegroundColor Gray
Write-Host ""

exit 0
