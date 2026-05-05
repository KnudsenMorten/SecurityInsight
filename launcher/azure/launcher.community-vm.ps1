#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight asset-profiling azure engine.
    Invokes Invoke-SIEngineRun -Engine azure.

.DESCRIPTION
    Runs the SecurityInsight asset-profiling azure engine on a Windows box in
    the customer's own tenant. Reads credentials from LauncherConfig.custom.ps1
    (.gitignore'd). Supports 4 auth methods (MI, SPN+KV, SPN+cert, SPN+plaintext).
    See LauncherConfig.custom.sample.ps1 in this same folder.

    Asset-profiling engines do NOT use $global:SettingsPath. Storage-account
    context (used for shard coordination) is resolved in this order:
      1. -StorageAccountName / -StorageAccountKey on the CLI
      2. -UseStorageOAuth switch (AAD-based storage auth)
      3. $global:SI_StorageAccount + $global:SI_StorageKey from custom.ps1

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.ps1
    Engine         : asset-profiling/azure (Invoke-SIEngineRun -Engine azure)
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    # Generic launcher knobs
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings,

    # Asset-profiling engine knobs (passthrough to Invoke-SIEngineRun)
    [switch]$Mock,
    [int]$AssetLimit = 0,
    [string[]]$Sinks,
    [switch]$ForceFullRun,
    [switch]$UseStorageOAuth,
    [string]$StorageAccountName,
    [string]$StorageAccountKey
)
$ErrorActionPreference = 'Stop'

# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths so
# Microsoft.PowerShell.Security loads cleanly (PS7's TypeData clashes
# with the v5.1 host -> ConvertTo-SecureString refuses to load).
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

# SecureString built via constructor instead of ConvertTo-SecureString.
function ConvertTo-SecureStringSafe {
    param([Parameter(Mandatory)][string]$Plain)
    $ss = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

# Get-PublishedVersion: shared helper in _lib/. Dot-sourced before the banner
# so the version shows on the very first line.
. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')
. (Join-Path $PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1')

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = '',
        [string]$Version = '(dev)'
    )
    $line = '=' * 88
    # Strip the redundant 'SecurityInsight_' prefix on the engine label so the
    # banner reads "SecurityInsight -- AssetProfiling_Identity" instead of the
    # noisy "SecurityInsight -- SecurityInsight_AssetProfiling_Identity". 2026-05-02.
    $engineLabel = $Engine -replace '^SecurityInsight[_-]', ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $engineLabel, $Flavour, $Version) -ForegroundColor Cyan
    if ($Description) {
        foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) {
            Write-Host ("  {0}" -f $chunk) -ForegroundColor White
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
function Write-Info   { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
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
    if ($mod) { return $true }
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
            # v2.2 dev tree: engine/ + launcher/ siblings (uncopied/unpublished). Lets customers run preview directly without going through the publish step (engine->scripts rename).
            elseif (($dirs -ccontains 'engine') -and ($dirs -ccontains 'launcher')) { $communityMatch = $cur }
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
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'AssetProfiling_Azure' -Flavour 'community-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'azure' -Flavour 'community-vm' -RepoRoot $InstallPath

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    # Layered config: Layer 1 LauncherConfig.defaults.ps1 (this folder) -> Layer 3
    # SecurityInsight.custom.ps1 (config) -> Layer 5 LauncherConfig.custom.ps1
    # (this folder, gitignored) -> CLI args.
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'AssetProfiling_Azure' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'community' `
        -CustomConfigPath $LauncherConfigPath
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

Write-Step "Resolving authentication"
if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw @"
Launcher: `$global:SpnTenantId is required but not set.

Put your SPN / Managed Identity credentials in ONE of these files:
  * config\SecurityInsight.custom.ps1         (solution-wide -- recommended; covers every SI engine)
  * LAUNCHERS\<engine>\LauncherConfig.custom.ps1  (per-engine override; closest wins)

Copy the matching .sample.ps1 next to the target file and fill in your values.
See README section 3.5 for the layered-config model.
"@
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
            $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret))
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
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can (see LauncherConfig.custom.sample.ps1)."
        $secretSecure = ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured in LauncherConfig.custom.ps1.
Populate ONE of (see LauncherConfig.custom.sample.ps1 for copy-pasteable blocks):
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

Write-Step "Resolving asset-profiling engine + run knobs"
$global:WhatIfMode       = [bool]$WhatIfMode
$global:SuppressErrors   = [bool]$SuppressErrors
$global:SuppressWarnings = [bool]$SuppressWarnings

# Snapshot CLI bound params -- helpers below need the launcher's own bound set.
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $PSBoundParameters[$k] }

# Resolve Sinks: CLI > $global:SI_Sinks_Azure > engine default.
if ($cliBound.ContainsKey('Sinks') -and $Sinks) {
    $effectiveSinks = $Sinks
} elseif ($global:SI_Sinks_Azure) {
    $effectiveSinks = @($global:SI_Sinks_Azure)
} else {
    $effectiveSinks = @('LA','JSON','Excel')
}

# Resolve AssetLimit: CLI > $global:SI_AssetLimit_Azure > 0.
if ($cliBound.ContainsKey('AssetLimit')) {
    $effectiveAssetLimit = [int]$AssetLimit
} elseif ($null -ne $global:SI_AssetLimit_Azure) {
    $effectiveAssetLimit = [int]$global:SI_AssetLimit_Azure
} else {
    $effectiveAssetLimit = 0
}

# Resolve ForceFullRun: CLI > $global:SI_ForceFullRun_Azure > $global:SI_ForceFullRun.
$effectiveForceFullRun = $false
if ($cliBound.ContainsKey('ForceFullRun')) {
    $effectiveForceFullRun = [bool]$ForceFullRun
} elseif ($global:SI_ForceFullRun_Azure) {
    $effectiveForceFullRun = [bool]$global:SI_ForceFullRun_Azure
} elseif ($global:SI_ForceFullRun) {
    $effectiveForceFullRun = [bool]$global:SI_ForceFullRun
}

Write-Info ("[LAUNCHER] Sinks={0} AssetLimit={1} ForceFullRun={2} Mock={3} UseStorageOAuth={4}" -f `
    ($effectiveSinks -join ','), $effectiveAssetLimit, $effectiveForceFullRun, [bool]$Mock, [bool]$UseStorageOAuth)

# Build the splat for Invoke-SIEngineRun.
$cliPassthrough = @{
    AssetLimit   = $effectiveAssetLimit
    ForceFullRun = $effectiveForceFullRun
}
if ($Mock)            { $cliPassthrough['Mock']               = $true }
if ($UseStorageOAuth) { $cliPassthrough['UseStorageOAuth']    = $true }
if ($StorageAccountName) { $cliPassthrough['StorageAccountName'] = $StorageAccountName }
if ($StorageAccountKey)  { $cliPassthrough['StorageAccountKey']  = $StorageAccountKey  }

try {
    Write-Step "Invoking engine"
    # Launcher lives at v2.2/launcher/azure/. Engine entry is at
    # v2.2/engine/asset-profiling/Invoke-SIEngineRun.ps1. 2-up from launcher = v2.2/.
    # Asset-profiling is v2.2-only -- no legacy fallback.
    $launcherDir = $PSScriptRoot
    $siRootForEngine = Split-Path -Parent (Split-Path -Parent $launcherDir)
    $engine = Join-Path $siRootForEngine 'engine\asset-profiling\Invoke-SIEngineRun.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        throw "Launcher: engine 'Invoke-SIEngineRun.ps1' not found at $engine. Asset-profiling is v2.2-only; check the v2.2/engine/asset-profiling/ tree."
    }
    Write-Info "engine: $engine -Engine azure"
    & $engine -Engine 'azure' -Sinks $effectiveSinks @cliPassthrough
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

# flush + close the transcript started right after Write-Banner.
Stop-SILauncherTranscript
