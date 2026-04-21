#Requires -Version 7.4
<#
.SYNOPSIS
    Community Azure serverless launcher for SecurityInsight\Setup-SecurityInsight-CustomSecurityAttributes.
.DESCRIPTION
    OPTIONAL one-time setup, Azure Function / Automation Account variant. Only
    works if the Managed Identity (or SPN) running the Function App has been
    granted the elevated Entra roles required to create CSA definitions:
      - Attribute Definition Administrator
      - Privileged Role Administrator (if granting pipeline roles)

    A plain app-only SPN is typically NOT sufficient. For a one-time setup the
    recommended path is launcher.community-vm.template.ps1 run interactively
    by an admin user.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-azure.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    [string]$LauncherConfigPath
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

# Resolve repo root + version BEFORE the banner so the banner can show the version.
try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'Setup-SecurityInsight-CustomSecurityAttributes' -Flavour 'community-azure' -Version $versionStamp

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}

# Resolve engine path portably
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
if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
    Install-Module 'Microsoft.Graph.Authentication' -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
}
Import-Module 'Microsoft.Graph.Authentication' -ErrorAction Stop -WarningAction SilentlyContinue

try {
    if ([bool]$global:UseManagedIdentity -or -not ($global:SpnClientId -and ($global:SpnClientSecret -or $global:SpnCertificateThumbprint))) {
        Write-Step 'Auth method: Managed Identity'
        Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } elseif ($global:SpnCertificateThumbprint) {
        Write-Step 'Auth method: SPN + certificate'
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientId $global:SpnClientId `
            -CertificateThumbprint $global:SpnCertificateThumbprint -NoWelcome -WarningAction SilentlyContinue | Out-Null
    } else {
        Write-Step 'Auth method: SPN + secret  [use MI or cert in production]'
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credForGraph = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
    }
    Write-Ok 'Graph authenticated'
} catch {
    Write-Err2 "Graph authentication failed: $($_.Exception.Message)"
    throw
}

$global:AutomationFramework = $false

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
