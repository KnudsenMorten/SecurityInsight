#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight\Setup-SecurityInsight-CustomSecurityAttributes.
.DESCRIPTION
    OPTIONAL one-time setup launcher. Runs on a Windows box in the customer's
    own tenant. Reads values from LauncherConfig.ps1 (.gitignore'd). By default
    uses INTERACTIVE Graph sign-in (engine prompts the admin user). Also
    supports the standard 4 auth methods (MI, SPN+KV, SPN+cert, SPN+plaintext)
    if the chosen identity has been granted the elevated Entra roles required
    to create CSA definitions.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)
$ErrorActionPreference = 'Stop'

# Get-PublishedVersion: shared helper in _lib/. Dot-sourced before the banner.
. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = '',
        [string]$Version = '(dev)'
    )
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $Engine, $Flavour, $Version) -ForegroundColor Cyan
    if ($Description) {
        foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) {
            Write-Host ('  {0}' -f $chunk) -ForegroundColor Gray
        }
    }
    Write-Host '' -ForegroundColor Cyan
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step   { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info   { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray }
function Write-Ok     { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2  { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2   { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

function Test-LauncherModule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Required,
        [switch]$AutoInstall
    )
    $mod = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mod) { return $true }  # silent-on-success; engine's Ensure-SecurityInsightModules logs the canonical [MODULE] X v... present line
    if ($AutoInstall) {
        Write-Warn2 "module '$Name' missing -- attempting Install-Module -Scope CurrentUser"
        try {
            Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Ok "installed '$Name'"
            return $true
        } catch {
            if ($Required) { throw "Required module '$Name' could not be installed: $($_.Exception.Message)" }
            Write-Warn2 "optional module '$Name' install failed: $($_.Exception.Message) (continuing)"
            return $false
        }
    }
    if ($Required) { throw "Required module '$Name' is not installed. Run: Install-Module $Name -Scope CurrentUser" }
    Write-Warn2 "optional module '$Name' not installed (some features may be unavailable)"
    return $false
}

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $communityMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (-not $communityMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'scripts') -and ($dirs -ccontains 'launchers')) { $communityMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($communityMatch) { return $communityMatch }
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a lowercase scripts/+launchers/ pair (community repo)." -f $Start)
}
# Resolve repo root + version BEFORE the banner so the banner can show the version.
try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'Setup-SecurityInsight-CustomSecurityAttributes' -Flavour 'community-vm' -Version $versionStamp

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step 'Resolving repo root'
Write-Ok "repo root: $InstallPath"

# Resolve engine path portably -- works in the monorepo and in a published repo.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'Setup-SecurityInsight-CustomSecurityAttributes.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'Setup-SecurityInsight-CustomSecurityAttributes.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts." }

try {
    # Layered config: defaults (ours) -> platform (internal only) ->
    # solution-wide custom -> per-engine custom -> CLI args.
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'Setup-SecurityInsight-CustomSecurityAttributes' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'community' `
        -CustomConfigPath $LauncherConfigPath
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

Write-Step 'Ensuring Microsoft.Graph.Authentication module'
[void](Test-LauncherModule -Name 'Microsoft.Graph.Authentication' -Required -AutoInstall)
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue

# Resolve which (if any) non-interactive auth path to use. For this engine
# interactive is the default -- if no SPN / MI globals are set, skip launcher
# auth and let the engine prompt the admin user itself.
$authMethodUsed = $null
$hasSpnKv   = $global:SpnKeyVaultName -and $global:SpnSecretName -and $global:SpnClientId -and $global:SpnTenantId
$hasSpnCrt  = $global:SpnCertificateThumbprint -and $global:SpnClientId -and $global:SpnTenantId
$hasSpnPt   = $global:SpnClientId -and $global:SpnClientSecret -and $global:SpnTenantId
$wantsMi    = [bool]$global:UseManagedIdentity

try {
    if ($wantsMi) {
        Write-Step 'Auth method: Managed Identity'
        Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'ManagedIdentity'
    }
    elseif ($hasSpnKv) {
        Write-Step ("Auth method: SPN + Key Vault (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
        [void](Test-LauncherModule -Name 'Az.Accounts'  -Required -AutoInstall)
        [void](Test-LauncherModule -Name 'Az.KeyVault' -Required -AutoInstall)
        Import-Module Az.Accounts  -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        $secretSecure = (Get-AzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
        if (-not $secretSecure) { throw "Key Vault returned no value for secret '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
        Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
        $credForGraph = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-KeyVault'
    }
    elseif ($hasSpnCrt) {
        Write-Step ("Auth method: SPN + certificate (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientId $global:SpnClientId `
            -CertificateThumbprint $global:SpnCertificateThumbprint -NoWelcome -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-Certificate'
    }
    elseif ($hasSpnPt) {
        Write-Step 'Auth method: SPN + plaintext secret  [TESTING ONLY]'
        Write-Warn2 'Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production.'
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credForGraph = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        Write-Step 'Auth method: INTERACTIVE (engine will prompt the admin user)'
        Write-Info 'No MI / SPN credentials configured in LauncherConfig.ps1 -- this is the default and recommended path for this one-time setup.'
        $authMethodUsed = 'Interactive (deferred to engine)'
    }
} catch {
    Write-Err2 "Authentication failed: $($_.Exception.Message)"
    throw
}

Write-Ok ('Authentication path: {0}' -f $authMethodUsed)

Write-Step 'Setting engine globals'
$global:AutomationFramework = $false
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

try {
    Write-Step 'Invoking engine'
    Write-Info "engine: $engine"
    & $engine `
        -PipelinePrincipalId $global:SI_CSA_PipelinePrincipalId `
        -TestObjectId        $global:SI_CSA_TestObjectId `
        -TenantId            $global:SI_CSA_TenantId
    Write-Ok 'Engine completed successfully'
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}
