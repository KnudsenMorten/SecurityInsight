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

.EXAMPLE
    # Community install -- non-interactive variant. If Az PS + Microsoft Graph
    # are already connected in this shell (any SPN with sufficient privilege --
    # Modern SPN works), the Community block skips Connect-AzAccount/MgGraph
    # browser flow and reuses the existing context. Lets unattended Community
    # deploys run from a SYSTEM scheduled task or CI agent without prompts.
    Connect-Platform   # or any Connect-AzAccount + Connect-MgGraph pair
    .\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled

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
    # Default = REFUSE to overwrite an existing config/SecurityInsight.custom.ps1.
    # Pre-v2.2.310 silently backed up + overwrote, which in practice wiped a live
    # internal-VM config when an operator ran a sicont/container-flavour bootstrap
    # from the same repo checkout. Pass -ForceConfigOverwrite to opt into the old
    # rewrite-with-backup behaviour (re-onboarding, tenant migration, etc.).
    [Parameter()] [switch]$ForceConfigOverwrite
)

$ErrorActionPreference = 'Stop'

# ----------- Logging helpers (mirror the wizard's style) -----------
function _Banner([string]$msg) { Write-Host ""; Write-Host ("=== {0} ===" -f $msg) -ForegroundColor Cyan }
function _Step  ([string]$msg) { Write-Host ("  [STEP] {0}" -f $msg) -ForegroundColor Cyan }
function _Ok    ([string]$msg) { Write-Host ("  [OK]   {0}" -f $msg) -ForegroundColor Green }
function _Info  ([string]$msg) { Write-Host ("  [INFO] {0}" -f $msg) -ForegroundColor Gray }
function _Warn  ([string]$msg) { Write-Host ("  [WARN] {0}" -f $msg) -ForegroundColor Yellow }
function _Err   ([string]$msg) { Write-Host ("  [ERR]  {0}" -f $msg) -ForegroundColor Red }

# ----------- Defensive: New-Guid shim for constrained runspaces ------------
# Az.Monitor 7.0+ DCR autorest cmdlets call New-Guid for telemetry tracking.
# In constrained PS 5.1 runspaces (-NoProfile, SYSTEM scheduled tasks,
# certain hosts) Microsoft.PowerShell.Utility's New-Guid isn't visible
# from inside Az.Monitor's child runspace, even after Import-Module. Define
# a global shim against [System.Guid]::NewGuid() -- harmless if real one
# is already loaded (PowerShell picks the alphabetically-first match, and
# the real cmdlet wins by source-load order anyway).
Import-Module Microsoft.PowerShell.Utility -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
if (-not (Get-Command New-Guid -ErrorAction SilentlyContinue)) {
    function global:New-Guid { [System.Guid]::NewGuid() }
}

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

# ----------- Phase 0: Connect-Platform (Internal flavour) ----------------------
# v2.3: Internal flavour calls Connect-Platform from AutomateITPS. That reads
# bootstrap\platform-config.json (5 fields), cert/MI-connects the Bootstrap
# identity, pulls Modern-AppId + Modern-Secret from KV, secret-connects Az + Mg
# as the Modern SPN, and populates $global:HighPriv_Modern_* / $global:Context.
#
# v2.2 path (Legacy-Connect.ps1 + v1 ConnectDetails) is gone in v2.3. Operators
# migrate via SOLUTIONS\PlatformConfiguration\INTERNAL\Migrate\Convert-V1ToPlatform.ps1.
#
# Community flavour: unchanged -- interactive Connect-AzAccount + Connect-MgGraph
# happens in the dedicated Community block further down.
if ($cfg.Flavour -eq 'Internal') {
    _Step "Internal flavour -- calling Connect-Platform (v2.3)"

    # Locate AutomateITPS module (walk up to repo root)
    $r = $PSScriptRoot
    while ($r -and -not (Test-Path (Join-Path $r 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $parent = Split-Path -Parent $r
        if ($parent -eq $r) { break }
        $r = $parent
    }
    if (-not $r) { throw "Internal flavour: cannot locate FUNCTIONS\AutomateITPS\AutomateITPS.psd1 from $PSScriptRoot. Is the repo cloned correctly?" }

    Import-Module (Join-Path $r 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Force -ErrorAction Stop -WarningAction SilentlyContinue

    try {
        $null = Connect-Platform -ErrorAction Stop
    } catch {
        throw ("Internal flavour: Connect-Platform failed -- {0}. Run Initialize-PlatformVm or Convert-V1ToPlatform first." -f $_.Exception.Message)
    }

    _Ok ("Modern SPN active: {0}" -f $global:HighPriv_Modern_ApplicationID_Azure)
    _Ok ("KV: {0}" -f $global:KV_HighPriv_KeyVaultName)

    # Hydrate Sub.* + Auth_Internal from Connect-Platform results when not in JSON
    if (-not $cfg.Sub.TenantId)        { $cfg.Sub.TenantId       = $global:AzureTenantId }
    if (-not $cfg.Sub.SubscriptionId)  { $cfg.Sub.SubscriptionId = $global:KV_HighPriv_SubscriptionId }
    if (-not $cfg.Auth_Internal.AppId) { $cfg.Auth_Internal.AppId = $global:HighPriv_Modern_ApplicationID_Azure }
    # CertificateThumbprint is no longer required (v2.3 Modern is secret-only).
    # Auth_Internal.Secret is populated from $global:HighPriv_Modern_Secret_Azure for Phase 1 New-SISpn.
    if (-not $cfg.Auth_Internal.PSObject.Properties['Secret']) {
        $cfg.Auth_Internal | Add-Member -NotePropertyName Secret -NotePropertyValue $global:HighPriv_Modern_Secret_Azure -Force
    } elseif (-not $cfg.Auth_Internal.Secret) {
        $cfg.Auth_Internal.Secret = $global:HighPriv_Modern_Secret_Azure
    }
}

# Validate the resolved values
if (-not $cfg.Sub.TenantId)       { throw "Sub.TenantId not set. Pass -TenantId or set Sub.TenantId in setup-unattended.json." }
if (-not $cfg.Sub.SubscriptionId) { throw "Sub.SubscriptionId not set. Pass -SubscriptionId or set Sub.SubscriptionId in setup-unattended.json." }
if (-not $cfg.Sub.Location)       { $cfg.Sub.Location = 'westeurope' }
if ($cfg.Flavour -eq 'Internal') {
    if (-not $cfg.Auth_Internal.AppId) { throw "Auth_Internal.AppId not set after Connect-Platform (Modern-AppId KV secret missing?)." }
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

# ----------- Community flavour: auth (reuse existing context if present, else browser) -----------
if ($cfg.Flavour -eq 'Community') {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $azCtxExisting = Get-AzContext -ErrorAction SilentlyContinue
    $mgCtxExisting = Get-MgContext -ErrorAction SilentlyContinue

    if ($azCtxExisting -and $azCtxExisting.Subscription.Id -eq $cfg.Sub.SubscriptionId -and $mgCtxExisting -and $mgCtxExisting.TenantId -eq $cfg.Sub.TenantId) {
        _Banner "Reusing existing Az + Mg context (non-interactive Community deploy)"
        _Ok ("Az PS  : {0} (sub {1})" -f $azCtxExisting.Account.Id, $azCtxExisting.Subscription.Id)
        _Ok ("MgGraph: {0} (tenant {1})" -f $mgCtxExisting.Account, $mgCtxExisting.TenantId)
    } else {
        _Banner "Interactive auth (browser)"
        _Step ("Connect-AzAccount -Tenant {0} -Subscription {1}" -f $cfg.Sub.TenantId, $cfg.Sub.SubscriptionId)
        $null = Connect-AzAccount -Tenant $cfg.Sub.TenantId -Subscription $cfg.Sub.SubscriptionId -ErrorAction Stop
        _Ok "Az PS connected"

        _Step ("Connect-MgGraph -TenantId {0} (browser)" -f $cfg.Sub.TenantId)
        $null = Connect-MgGraph -TenantId $cfg.Sub.TenantId -NoWelcome -ErrorAction Stop
        _Ok "Microsoft Graph connected"
    }

    if ($cfg.Container.Enabled) {
        # az CLI: try existing context first; if missing, try SPN secret from cfg.Auth_Community.Secret (set via SI_SPN_Secret env)
        $azCliOk = $false
        try {
            $null = & az account show --output none 2>&1
            if ($LASTEXITCODE -eq 0) { $azCliOk = $true }
        } catch { }
        if (-not $azCliOk) {
            $cliSecret = $null
            if ($cfg.Auth_Community.PSObject.Properties['Secret']) { $cliSecret = $cfg.Auth_Community.Secret }
            if (-not $cliSecret -and $env:SI_SPN_Secret)            { $cliSecret = $env:SI_SPN_Secret }
            $cliAppId = $env:SI_SPN_AppId
            if ($cliSecret -and $cliAppId) {
                $null = & az login --service-principal --tenant $cfg.Sub.TenantId --username $cliAppId --password $cliSecret --output none 2>&1
                if ($LASTEXITCODE -ne 0) { throw "az login (SPN secret) failed -- check SI_SPN_AppId / SI_SPN_Secret env vars" }
            } else {
                $null = & az login --tenant $cfg.Sub.TenantId --output none 2>&1
                if ($LASTEXITCODE -ne 0) { throw "az login (interactive) failed and no SPN secret available" }
            }
            $null = & az account set --subscription $cfg.Sub.SubscriptionId 2>&1
        }
        _Ok ("az CLI signed in (sub {0})" -f $cfg.Sub.SubscriptionId)
    }
}

# ----------- Internal flavour: az CLI secret login (Container phase only) -----------
# v2.3: Az PS + Mg are already connected by Connect-Platform in Phase 0 above
# (Modern SPN secret-auth). The v2.2 cert-connect block here is gone -- it was
# already broken in v2.3 (Modern is secret-only, no thumbprint in cfg).
# az CLI still needs its own login when Container Apps Job phase will run.
if ($cfg.Flavour -eq 'Internal') {
    if ($cfg.Container.Enabled) {
        _Banner "az CLI secret login (Container Apps Job phase needs it)"
        $tenantId = $cfg.Sub.TenantId
        $appId    = $cfg.Auth_Internal.AppId
        $secret   = $cfg.Auth_Internal.Secret    # populated from $global:HighPriv_Modern_Secret_Azure in Phase 0
        if (-not $secret) {
            throw "az CLI login: Auth_Internal.Secret is empty -- Connect-Platform should have populated it from \$global:HighPriv_Modern_Secret_Azure. Did Connect-Platform fail?"
        }
        $null = & az login --service-principal --tenant $tenantId --username $appId --password $secret --output none 2>&1
        if ($LASTEXITCODE -ne 0) { throw "az login (secret) failed; check Modern AppId + secret + tenant." }
        $null = & az account set --subscription $cfg.Sub.SubscriptionId 2>&1
        _Ok ("az CLI signed in as Modern SPN (sub {0})" -f $cfg.Sub.SubscriptionId)
    } else {
        _Info "Internal flavour Az + Mg already connected by Connect-Platform (Phase 0). Container phase disabled -- skipping az CLI login."
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
# Phase 2.5 -- Seed v1 Key Vault with SI-required secrets (Internal only)
# ----------------------------------------------------------------------------
# Ensures SI-Shodan-ApiKey + OpenAI-ApiKey exist in the v1 platform KV so the
# generated SecurityInsight.custom.ps1 KV-pull section works at engine runtime.
# Idempotent (Set-AzKeyVaultSecret creates a new version each call but Azure
# auto-prunes; cheap operation). Skipped for Community flavour.
$phaseStatus.kvSeed = 'skipped'
if ($cfg.Flavour -eq 'Internal' -and $global:KV_HighPriv_KeyVaultName) {
    _Banner "Seed v1 KeyVault with SI secrets"
    $kv = $global:KV_HighPriv_KeyVaultName
    _Info ("KeyVault: {0}" -f $kv)

    # Shodan -- fixed key shared across all internal customers
    try {
        $shodanKey = 'tyScfnKkuf4hz87DaHwnhzXST3wKExfg'
        Set-AzKeyVaultSecret -VaultName $kv -Name 'SI-Shodan-ApiKey' `
            -SecretValue ([System.Net.NetworkCredential]::new('', $shodanKey).SecurePassword) -ErrorAction Stop | Out-Null
        _Ok "SI-Shodan-ApiKey seeded"
    } catch {
        _Warn ("SI-Shodan-ApiKey seed failed: {0}" -f $_.Exception.Message)
    }

    # OpenAI -- migrate from v1's $global:OpenAI_apiKey (set by v1 Default_Variables)
    if ($global:OpenAI_apiKey) {
        try {
            Set-AzKeyVaultSecret -VaultName $kv -Name 'OpenAI-ApiKey' `
                -SecretValue ([System.Net.NetworkCredential]::new('', $global:OpenAI_apiKey).SecurePassword) -ErrorAction Stop | Out-Null
            _Ok ("OpenAI-ApiKey seeded ({0} chars from `$global:OpenAI_apiKey)" -f $global:OpenAI_apiKey.Length)
            _Info "Safe to delete `$global:OpenAI_apiKey from v1 Automation-DefaultVariables.psm1 -- engines load from KV via custom.ps1 section 11"
        } catch {
            _Warn ("OpenAI-ApiKey seed failed: {0}" -f $_.Exception.Message)
        }
    } else {
        _Warn "`$global:OpenAI_apiKey not set in v1 globals -- skipping OpenAI seed (set it in v1 Default_Variables, or pre-create the KV secret manually)"
    }
    $phaseStatus.kvSeed = 'ok'
} elseif ($cfg.Flavour -eq 'Internal') {
    _Warn "Phase 2.5 (KV secret seed) skipped: `$global:KV_HighPriv_KeyVaultName not set (Legacy-Connect.ps1 didn't run, or v1 ConnectDetails uses a different global name)"
}

# ----------------------------------------------------------------------------
# Phase 3 -- Config file (Bridged for Internal, Inline for Community)
# ----------------------------------------------------------------------------
try {
    # v2.3: Write-SICustomConfig is single-template (no -Mode). Section 1 always
    # emits resolved values; Section 11 KV pulls gate at runtime on $global:Context.
    $cfgArgs = @{
        Spn   = $spnOut
        Infra = $infraOut
    }
    if ($ForceConfigOverwrite) { $cfgArgs.Force = $true }
    # v2.2.355 -- pass Smtp through to the custom.ps1 writer when the operator
    # populated it in setup-unattended.json. Community ONLY -- Internal flavour
    # gets SMTP from PlatformConfiguration/config/platform-defaults.ps1 via
    # Connect-Platform's automatic dot-source, so we skip even when Smtp is
    # defined to avoid duplicating + diverging from the platform-wide default.
    if ($cfg.Flavour -eq 'Community' -and $cfg.PSObject.Properties['Smtp'] -and $cfg.Smtp -and $cfg.Smtp.Server) {
        $smtpHash = @{
            Server     = [string]$cfg.Smtp.Server
            Port       = if ($cfg.Smtp.Port)   { [int]$cfg.Smtp.Port }   else { 587 }
            User       = [string]$cfg.Smtp.User
            Password   = [string]$cfg.Smtp.Password
            From       = [string]$cfg.Smtp.From
            UseSsl     = if ($null -ne $cfg.Smtp.UseSsl) { [bool]$cfg.Smtp.UseSsl } else { $true }
            MailTo     = @($cfg.Smtp.MailTo     | Where-Object { $_ })
            DetailedTo = @($cfg.Smtp.DetailedTo | Where-Object { $_ })
            SummaryTo  = @($cfg.Smtp.SummaryTo  | Where-Object { $_ })
        }
        $cfgArgs.Smtp = $smtpHash
        _Info ("Smtp section: server={0}:{1} from={2} mailTo={3} (Community flavour -- emitted into custom.ps1)" -f `
            $smtpHash.Server, $smtpHash.Port, $smtpHash.From, ((@($smtpHash.MailTo) + @($smtpHash.DetailedTo) + @($smtpHash.SummaryTo) | Sort-Object -Unique) -join ','))
    } elseif ($cfg.Flavour -eq 'Internal' -and $cfg.PSObject.Properties['Smtp'] -and $cfg.Smtp -and $cfg.Smtp.Server) {
        _Info "Smtp section ignored: Internal flavour reads SMTP from PlatformConfiguration/config/platform-defaults.ps1. Edit there if a change is needed."
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
