#Requires -Version 5.1
<#
.SYNOPSIS
    Wire Start-/Stop-SILauncherTranscript into every SI v2.2 launcher.

.DESCRIPTION
    Idempotent. Adds 3 things to each launcher.*-vm.ps1:
      1. Dot-source `_lib/Start-LauncherTranscript.ps1` (right after the
         existing Get-PublishedVersion dot-source).
      2. Call Start-SILauncherTranscript right after Write-Banner so the
         banner is captured in the transcript.
      3. Drop a `Stop-SILauncherTranscript` call at the end of the file.

    Detects existing wiring via the `Start-LauncherTranscript.ps1` substring
    and skips files already wired. Run again after editing the helper -- it
    won't double-add.

.PARAMETER WhatIfMode
    Preview without writing.
#>
[CmdletBinding()]
param(
    [switch]$WhatIfMode
)

$launcherRoot = Join-Path $PSScriptRoot '..\launcher'
$launchers = Get-ChildItem -Path $launcherRoot -Recurse -Filter 'launcher.*-vm.ps1' |
             Where-Object { $_.FullName -notmatch '\\_lib\\' }

# Per-flavour: how many Split-Path's to walk from the launcher dir to reach
# the v22 root that owns logs/. Identity/Azure/etc. live at .../launcher/<engine>/launcher.X.ps1
# so 2 Split-Path's = launcher/, 3 = v2.2/.
function Get-EngineFromPath([string]$file) {
    # .../launcher/<engine>/launcher.X.ps1
    $engineDir = Split-Path -Parent $file
    return Split-Path -Leaf $engineDir   # 'risk-analysis' | 'identity' | ...
}

function Get-FlavourFromName([string]$name) {
    if ($name -match 'launcher\.(community-vm|internal-vm|container)\.ps1$') { return $matches[1] }
    return $null
}

$wired = 0; $skipped = 0
foreach ($f in $launchers) {
    $orig = Get-Content -LiteralPath $f.FullName -Raw
    if ($orig -match 'Start-LauncherTranscript\.ps1') {
        Write-Host ("SKIP    {0}  (already wired)" -f $f.FullName) -ForegroundColor White
        $skipped++
        continue
    }

    $engine  = Get-EngineFromPath $f.FullName
    $flavour = Get-FlavourFromName $f.Name
    if (-not $flavour) {
        Write-Host ("SKIP    {0}  (unknown flavour)" -f $f.FullName) -ForegroundColor White
        $skipped++
        continue
    }

    $new = $orig

    # 1. Dot-source the helper after Get-PublishedVersion dot-source.
    $dotSourceLine = ". (Join-Path `$PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1')"
    if ($new -match "(\. \(Join-Path \`$PSScriptRoot '\.\.\\_lib\\Get-PublishedVersion\.ps1'\))") {
        $new = $new -replace [regex]::Escape($matches[1]), ($matches[1] + "`r`n" + $dotSourceLine)
    } else {
        Write-Host ("WARN    {0}  (no Get-PublishedVersion anchor; manual fix)" -f $f.FullName) -ForegroundColor Yellow
        $skipped++
        continue
    }

    # 2. Call Start-SILauncherTranscript right after Write-Banner.
    $startCall = "`$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine '$engine' -Flavour '$flavour' -RepoRoot `$InstallPath"
    $bannerPattern = '(?m)^(Write-Banner -Solution[^\r\n]+\r?\n)'
    if ([regex]::IsMatch($new, $bannerPattern)) {
        $new = [regex]::Replace($new, $bannerPattern, ('${1}' + $startCall + "`r`n"), 1)
    } else {
        Write-Host ("WARN    {0}  (no Write-Banner anchor; manual fix)" -f $f.FullName) -ForegroundColor Yellow
        $skipped++
        continue
    }

    # 3. Append Stop-SILauncherTranscript at the very end.
    if ($new -notmatch 'Stop-SILauncherTranscript') {
        if ($new -notmatch "`r?`n`s*$") { $new += "`r`n" }
        $new += "`r`n# flush + close the transcript started right after Write-Banner.`r`nStop-SILauncherTranscript`r`n"
    }

    if ($new -ne $orig) {
        $wired++
        if (-not $WhatIfMode) {
            Set-Content -LiteralPath $f.FullName -Value $new -Encoding UTF8 -NoNewline
        }
        Write-Host ("WIRED   {0}  ({1} / {2})" -f $f.FullName, $engine, $flavour) -ForegroundColor Green
    }
}

Write-Host ''
Write-Host ("Total launchers: {0}  Wired: {1}  Skipped: {2}" -f $launchers.Count, $wired, $skipped) -ForegroundColor Cyan
if ($WhatIfMode) { Write-Host '(WhatIf mode -- no writes)' -ForegroundColor White }
