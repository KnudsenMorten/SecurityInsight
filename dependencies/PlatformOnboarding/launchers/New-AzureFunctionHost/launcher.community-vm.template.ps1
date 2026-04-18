#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for PlatformOnboarding\New-AzureFunctionHost.
.DESCRIPTION
    Runs the New-AzureFunctionHost engine on a Windows box in the customer's own tenant.
    Reads credentials from LauncherConfig.ps1 (.gitignore'd). Supports 4 auth
    methods (MI, SPN+KV, SPN+cert, SPN+plaintext). See LauncherConfig.sample.ps1.
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

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = ''
    )
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]" -f $Solution, $Engine, $Flavour) -ForegroundColor Cyan
    if ($Description) {
        foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) {
            Write-Host ("  {0}" -f $chunk) -ForegroundColor Gray
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
    if ($mod) { Write-Ok "module '$Name' v$($mod.Version) present"; return $true }
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
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (Test-Path (Join-Path $cur 'scripts') -and (Test-Path (Join-Path $cur 'launchers'))) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected to find either FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a scripts/+launchers/ pair (published community repo)." -f $Start)
}

Write-Banner -Solution 'PlatformOnboarding' -Engine 'New-AzureFunctionHost' -Flavour 'community-vm' -Description 'New-AzureFunctionHost -- v2 ported engine under PlatformOnboarding.'

try {
    Write-Step "Resolving repo root"
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
    Write-Ok "repo root: $InstallPath"
} catch {
    Write-Err2 $_.Exception.Message
    throw
}

try {
    Write-Step "Loading LauncherConfig.ps1"
    if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
    if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
        throw "LauncherConfig.ps1 not found at $LauncherConfigPath. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in the values for whichever auth method you want to use."
    }
    . $LauncherConfigPath
    Write-Ok "LauncherConfig loaded"
} catch {
    Write-Err2 "Failed to load LauncherConfig: $($_.Exception.Message)"
    throw
}

Write-Step "Resolving authentication"
if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw "Launcher: `$global:SpnTenantId is required (set it in LauncherConfig.ps1)."
}

try {
    [void](Test-LauncherModule -Name 'Az.Accounts' -Required -AutoInstall)
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
} catch {
    Write-Err2 "Failed to load Az.Accounts: $($_.Exception.Message)"
    throw
}

$haveKv = Test-LauncherModule -Name 'Az.KeyVault' -AutoInstall
$haveMg = Test-LauncherModule -Name 'Microsoft.Graph.Authentication' -AutoInstall

$authMethodUsed = $null
try {
    if ([bool]$global:UseManagedIdentity) {
        Write-Step "Auth method: Managed Identity"
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'ManagedIdentity'
    }
    elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
        Write-Step ("Auth method: SPN + Key Vault  (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
        if (-not $haveKv)             { throw "Az.KeyVault is required for Key Vault auth." }
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + Key Vault auth." }
        Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        $secretSecure = (Get-AzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
        if (-not $secretSecure) { throw "Key Vault returned no value for secret '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
        Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
        try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force))
            Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'SPN-KeyVault'
    }
    elseif ($global:SpnCertificateThumbprint) {
        Write-Step ("Auth method: SPN + certificate (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + certificate auth." }
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId `
            -ApplicationId $global:SpnClientId -CertificateThumbprint $global:SpnCertificateThumbprint `
            -WarningAction SilentlyContinue | Out-Null
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-MgGraph -TenantId $global:SpnTenantId -ClientId $global:SpnClientId `
                -CertificateThumbprint $global:SpnCertificateThumbprint -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'SPN-Certificate'
    }
    elseif ($global:SpnClientId -and $global:SpnClientSecret) {
        Write-Step "Auth method: SPN + plaintext secret  [TESTING ONLY]"
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can (see LauncherConfig.sample.ps1)."
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured in LauncherConfig.ps1.
Populate ONE of (see LauncherConfig.sample.ps1 for copy-pasteable blocks):
  1. `$global:UseManagedIdentity = `$true  (Managed Identity)
  2. `$global:SpnKeyVaultName + `$global:SpnSecretName + SpnClientId  (SPN + KV secret)
  3. `$global:SpnCertificateThumbprint + SpnClientId                  (SPN + cert)
  4. `$global:SpnClientSecret + SpnClientId                           (SPN + plaintext, testing only)
"@
    }
} catch {
    Write-Err2 "Authentication failed: $($_.Exception.Message)"
    throw
}

Write-Ok ("Authentication established ({0})" -f $authMethodUsed)

Write-Step "Setting engine globals"
$global:AutomationFramework = $false
$settingsOwner = $engineOwner
$settingsResolved = $null
foreach ($case in 'DATA','data') {
    $candidate = Join-Path $settingsOwner $case
    if (Test-Path -LiteralPath $candidate) { $settingsResolved = $candidate; break }
}
$global:SettingsPath = if ($settingsResolved) { $settingsResolved } else { $PSScriptRoot }
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

try {
    Write-Step "Invoking engine"
    # Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'New-AzureFunctionHost.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'New-AzureFunctionHost.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts. Expected the launcher to live at <solroot>\LAUNCHERS\<engine>\ with a sibling SCRIPTS\ or scripts\ folder." }
    if (-not (Test-Path -LiteralPath $engine)) { throw "engine script not found at $engine" }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}