#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot helper to bundle the v2.2 dev tree + FUNCTIONS for testing.

.DESCRIPTION
    Replaces the painful manual copy you've been doing. Pick a layout:

      -Layout Community  ->  FUNCTIONS inlined under the solution folder
                             (matches what the publish workflow will eventually push)
      -Layout Internal   ->  FUNCTIONS as sibling of the solution folder
                             (mirrors the AutomateIT monorepo where FUNCTIONS sits
                              one level above SOLUTIONS\SecurityInsight\)

    Use Community for testing on your laptop / community repo simulation.
    Use Internal for customer environments that already have FUNCTIONS at a parent path.

.PARAMETER TargetRoot
    Where to drop the bundle (will be created/wiped). For Internal layout the script
    creates two siblings under this root: FUNCTIONS\ and SecurityInsightPreview\.
    For Community layout, FUNCTIONS\ is inside SecurityInsightPreview\.

.PARAMETER Layout
    'Community' (default) | 'Internal' | 'Zip'
    'Zip' produces a single zip at <TargetRoot>\SI-Preview.zip ready to email/copy
    to a customer. The zip's internal layout matches Internal (FUNCTIONS sibling).

.PARAMETER SourceRoot
    Path to the AutomateIT monorepo root. Defaults to the script's grandparent
    (i.e. ..\..\..\.. from this file). Override only when running from elsewhere.

.EXAMPLE
    # Community layout on this laptop
    .\Push-PreviewBundle.ps1 -TargetRoot C:\Demo\SecurityInsightPreview -Layout Community

.EXAMPLE
    # Internal layout for a customer dev box (FUNCTIONS one level up)
    .\Push-PreviewBundle.ps1 -TargetRoot C:\Demo -Layout Internal

.EXAMPLE
    # Zip ready to ship to a customer
    .\Push-PreviewBundle.ps1 -TargetRoot C:\Temp -Layout Zip
    # -> C:\Temp\SI-Preview.zip
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetRoot,
    [ValidateSet('Community','Internal','Zip')][string]$Layout = 'Community',
    [string]$SourceRoot
)

$ErrorActionPreference = 'Stop'

# Resolve source. This script lives at SOLUTIONS\SecurityInsight\tools\Push-PreviewBundle.ps1:
# the solution is one level up, the AutomateIT root three levels above that. (The v2.2\ subfolder this
# used to read no longer exists -- the solution was flattened.)
if (-not $SourceRoot) {
    $SourceRoot = (Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
}
$v22Src       = Join-Path $SourceRoot 'SOLUTIONS\SecurityInsight'
$functionsSrc = Join-Path $SourceRoot 'FUNCTIONS'

if (-not (Test-Path -LiteralPath (Join-Path $v22Src 'engine'))) { throw "SecurityInsight source not found at $v22Src" }
if (-not (Test-Path -LiteralPath $functionsSrc)) { throw "FUNCTIONS source not found at $functionsSrc" }

$modules = @('AutomateITPS','AutomateITPS.AD','AutomateITPS.Compat')

# WHAT A BUNDLE MAY CONTAIN. A folder copy of a working tree carries the customer's config\*.custom.ps1
# (SPN secret), the classifier's tenant catalog, logs and output -- and this bundle is meant to be
# handed to a customer. So only files GIT TRACKS are copied (never an untracked customer file), and of
# those, never the internal-only documents the public publish also strips.
$script:NeverBundle = @(
    'CLAUDE.md', 'README.PLAN.md', 'docs/REQUIREMENTS.md', 'docs/TESTS.md',
    'docs/V3-*.md', 'docs/SERVICENOW-*.md', 'internal/*'
)
function Get-SIBundleFiles {
    param([string]$SolutionRoot, [switch]$Community)
    $files = @(& git -C $SolutionRoot ls-files 2>$null)
    if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) {
        throw "Could not list tracked files under $SolutionRoot (git ls-files). A bundle is built from tracked files only."
    }
    # The Community layout is the PUBLIC edition, so it also drops what the publish drops: every
    # SecurityInsight Pro path in solution.publish.json excludePaths (PUB-6). Internal/Zip go to paying
    # customers and keep them.
    $proPaths = @()
    if ($Community) {
        $pub = Get-Content -Raw -LiteralPath (Join-Path $SolutionRoot 'solution.publish.json') | ConvertFrom-Json
        $proPaths = @($pub.excludePaths | ForEach-Object { "$_".Replace('\', '/').Trim('/') })
    }
    @($files | Where-Object {
        $f = $_
        -not (@($script:NeverBundle | Where-Object { $f -like $_ }).Count) -and
        -not (@($proPaths | Where-Object { $f -eq $_ -or $f.StartsWith("$_/") }).Count)
    })
}

function Copy-V22Tree {
    param([string]$Dest, [switch]$Community)
    Write-Host "[STEP] Copying tracked SecurityInsight files -> $Dest" -ForegroundColor Cyan
    $n = 0
    foreach ($rel in (Get-SIBundleFiles -SolutionRoot $v22Src -Community:$Community)) {
        $src = Join-Path $v22Src $rel
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { continue }
        $dst = Join-Path $Dest $rel
        $dir = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dst -Force
        $n++
    }
    Write-Host ("[OK]   {0} tracked files copied (customer config, output and internal docs excluded)" -f $n) -ForegroundColor Green
}

function Copy-Functions {
    param([string]$Dest)
    Write-Host "[STEP] Copying FUNCTIONS -> $Dest" -ForegroundColor Cyan
    foreach ($mod in $modules) {
        $modSrc = Join-Path $functionsSrc $mod
        if (Test-Path -LiteralPath $modSrc) {
            & robocopy $modSrc (Join-Path $Dest $mod) /E /NFL /NDL /NP /NJH /NJS | Out-Null
        }
    }
}

switch ($Layout) {
    'Community' {
        $solRoot = $TargetRoot
        if (Test-Path -LiteralPath $solRoot) { Remove-Item -LiteralPath $solRoot -Recurse -Force }
        New-Item -Path $solRoot -ItemType Directory | Out-Null
        Copy-V22Tree -Dest $solRoot -Community
        Copy-Functions -Dest (Join-Path $solRoot 'FUNCTIONS')
        $check = Join-Path $solRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'
        Write-Host ''
        Write-Host "[OK]   Community bundle ready at: $solRoot" -ForegroundColor Green
        Write-Host ("[OK]   AutomateITPS.psd1 present: " + (Test-Path -LiteralPath $check)) -ForegroundColor Green
        Write-Host ''
        Write-Host "Run the launcher:" -ForegroundColor Yellow
        Write-Host "  $solRoot\launcher\risk-analysis\launcher.community-vm.ps1 -Summary" -ForegroundColor Gray
    }
    'Internal' {
        if (-not (Test-Path -LiteralPath $TargetRoot)) { New-Item -Path $TargetRoot -ItemType Directory | Out-Null }
        $solDir   = Join-Path $TargetRoot 'SecurityInsightPreview'
        $funcDir  = Join-Path $TargetRoot 'FUNCTIONS'
        if (Test-Path -LiteralPath $solDir)  { Remove-Item -LiteralPath $solDir  -Recurse -Force }
        if (Test-Path -LiteralPath $funcDir) { Remove-Item -LiteralPath $funcDir -Recurse -Force }
        New-Item -Path $solDir  -ItemType Directory | Out-Null
        New-Item -Path $funcDir -ItemType Directory | Out-Null
        Copy-V22Tree -Dest $solDir
        Copy-Functions -Dest $funcDir
        $check = Join-Path $funcDir 'AutomateITPS\AutomateITPS.psd1'
        Write-Host ''
        Write-Host "[OK]   Internal bundle ready under: $TargetRoot" -ForegroundColor Green
        Write-Host "[OK]     $solDir"  -ForegroundColor Green
        Write-Host "[OK]     $funcDir" -ForegroundColor Green
        Write-Host ("[OK]   AutomateITPS.psd1 present: " + (Test-Path -LiteralPath $check)) -ForegroundColor Green
        Write-Host ''
        Write-Host "Run the launcher:" -ForegroundColor Yellow
        Write-Host "  $solDir\launcher\risk-analysis\launcher.internal-vm.ps1 -Summary" -ForegroundColor Gray
    }
    'Zip' {
        if (-not (Test-Path -LiteralPath $TargetRoot)) { New-Item -Path $TargetRoot -ItemType Directory | Out-Null }
        $stage   = Join-Path $env:TEMP ('SI-Preview-Bundle-' + [guid]::NewGuid().ToString('N').Substring(0,8))
        $solDir  = Join-Path $stage 'SecurityInsightPreview'
        $funcDir = Join-Path $stage 'FUNCTIONS'
        New-Item -Path $solDir  -ItemType Directory -Force | Out-Null
        New-Item -Path $funcDir -ItemType Directory -Force | Out-Null
        Copy-V22Tree -Dest $solDir
        Copy-Functions -Dest $funcDir
        $zipOut = Join-Path $TargetRoot 'SI-Preview.zip'
        if (Test-Path -LiteralPath $zipOut) { Remove-Item -LiteralPath $zipOut -Force }
        Write-Host "[STEP] Compressing to $zipOut" -ForegroundColor Cyan
        Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zipOut -Force
        Remove-Item -LiteralPath $stage -Recurse -Force
        Write-Host ''
        Write-Host "[OK]   Zip ready: $zipOut" -ForegroundColor Green
        Write-Host ''
        Write-Host "Customer extract command:" -ForegroundColor Yellow
        Write-Host "  Expand-Archive -Path C:\Temp\SI-Preview.zip -DestinationPath C:\Demo\ -Force" -ForegroundColor Gray
        Write-Host "  C:\Demo\SecurityInsightPreview\launcher\risk-analysis\launcher.internal-vm.ps1 -Summary" -ForegroundColor Gray
    }
}
