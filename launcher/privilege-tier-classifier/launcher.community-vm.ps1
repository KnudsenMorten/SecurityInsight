#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight privilege-tier-classifier engine.
    Invokes engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1.

.DESCRIPTION
    Builds the SecurityInsight tier-definitions JSON (AD groups, Entra roles, API
    permissions, Azure RBAC) using AI-batched tiering. Output written to
    v2.2/privilege-tier-catalog/privilege-tier-catalog.locked.json.

    Reads credentials from LauncherConfig.custom.ps1 (.gitignore'd).
    Supports 4 auth methods (MI, SPN+KV, SPN+cert, SPN+plaintext).
    See LauncherConfig.custom.sample.ps1 in this same folder.

    The Tiering engine reads $global:SpnTenantId / SpnClientId / SpnClientSecret
    directly when $global:AutomationFramework=$false, so this launcher resolves
    those before delegating to the engine script.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.ps1
    Engine         : privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
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

# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths so PS 5.1 host
# doesn't pick up PS 7 module variants that cause TypeData clashes.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

function ConvertTo-SecureStringSafe {
    param([Parameter(Mandatory)][string]$Plain)
    $ss = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

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
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

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

try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'PrivilegeTierClassifier' -Flavour 'community-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'privilege-tier-classifier' -Flavour 'community-vm' -RepoRoot $InstallPath

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'PrivilegeTierClassifier' `
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

$authMethodUsed = $null
try {
    if ([bool]$global:UseManagedIdentity) {
        Write-Step "Auth method: Managed Identity"
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
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
        # Tiering engine reads $global:SpnClientSecret as plain text -- reveal once for engine
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
        try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $authMethodUsed = 'SPN-KeyVault'
    }
    elseif ($global:SpnCertificateThumbprint) {
        # Tiering engine doesn't natively support certificate auth -- it expects a plain
        # SpnClientSecret. If you need cert auth, run via internal-vm flavour instead
        # (uses Initialize-PlatformAutomationFramework which handles cert).
        throw "SPN certificate auth is not supported by privilege-tier-classifier community-vm flavour. Use launcher.internal-vm.ps1 (Initialize-PlatformAutomationFramework) for cert-based auth, or switch to SPN + Key Vault / SPN + plaintext."
    }
    elseif ($global:SpnClientId -and $global:SpnClientSecret) {
        Write-Step "Auth method: SPN + plaintext secret  [TESTING ONLY]"
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or run via internal-vm (cert-based) when you can."
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured in LauncherConfig.custom.ps1.
Populate ONE of (see LauncherConfig.custom.sample.ps1 for copy-pasteable blocks):
  1. `$global:UseManagedIdentity = `$true  (Managed Identity)
  2. `$global:SpnKeyVaultName + `$global:SpnSecretName + SpnClientId  (SPN + KV secret)
  3. `$global:SpnClientSecret + SpnClientId                           (SPN + plaintext, testing only)
"@
    }
} catch {
    Write-Err2 "Authentication failed: $($_.Exception.Message)"
    throw
}

Write-Ok ("Authentication established ({0})" -f $authMethodUsed)

Write-Step "Setting engine globals"
$global:AutomationFramework = $false
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

$launcherDir       = $PSScriptRoot
$v22Root           = Split-Path -Parent (Split-Path -Parent $launcherDir)
$global:SettingsPath = Join-Path $v22Root 'privilege-tier-catalog'

Write-Info ("[LAUNCHER] AutomationFramework={0} SettingsPath={1} Auth={2}" -f $global:AutomationFramework, $global:SettingsPath, $authMethodUsed)

try {
    Write-Step "Invoking engine"
    $engine = Join-Path $v22Root 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        throw "Launcher: engine 'Invoke-PrivilegeTierClassifier.ps1' not found at $engine."
    }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

Stop-SILauncherTranscript
