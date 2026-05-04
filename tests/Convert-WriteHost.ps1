#Requires -Version 5.1
<#
.SYNOPSIS
    Bulk-convert raw Write-Host calls to Write-SI* helpers across SI v2.2 engine stages.

.DESCRIPTION
    Polish helper for . Maps:
      - Write-Host '<msg>' -ForegroundColor Yellow|DarkYellow  -> Write-SIWarn
      - Write-Host '<msg>' -ForegroundColor Red                -> Write-SIErr
      - Write-Host '<msg>' -ForegroundColor Green              -> Write-SIOk
      - Write-Host '<msg>' -ForegroundColor Cyan               -> Write-SIStep
      - Write-Host '<msg>' -ForegroundColor White|DarkGray      -> kept as Write-Host (separator/aligned columns)
      - Write-Host '<msg>'                                     -> Write-SIInfo
      - Write-Host ''                                          -> kept (blank line)
      - Write-Host '<msg>' -NoNewline                          -> kept (in-place progress)
      - Write-Host with `r prefix                              -> kept (carriage-return overwrite)
    Strips a single leading space from the message (helpers prepend ' [TAG] ').
    Multi-space leading indent (3+ chars used for alignment) is kept.

.PARAMETER Path
    Folder to recurse. Default: v2.2/engine/asset-profiling.

.PARAMETER WhatIf
    Preview changes without writing.
#>
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot '..\engine\asset-profiling'),
    [switch]$WhatIfMode
)

$colorMap = @{
    'Yellow'     = 'Write-SIWarn'
    'DarkYellow' = 'Write-SIWarn'
    'Red'        = 'Write-SIErr'
    'Green'      = 'Write-SIOk'
    'Cyan'       = 'Write-SIStep'
}

# Files to skip: tools/, lint/ (internal/dev), and Write-SIStyle itself.
# storage/ INCLUDED -- CmdbCache.ps1 + DcrMergeDiagnostic.ps1 + StagingBlob.ps1 emit
# raw Write-Host that bleeds through stage output (e.g. `=== CMDB cache refresh ===`).
$skipPatterns = @(
    '\\_shared\\Write-SIStyle\.ps1$',
    '\\lint\\',
    '\\tools\\',
    '\\Convert-WriteHost\.ps1$'
)

function Should-Skip([string]$file) {
    foreach ($p in $skipPatterns) { if ($file -match $p) { return $true } }
    return $false
}

function Convert-Line {
    param([string]$line)

    # Skip lines without Write-Host (fast path)
    if ($line -notmatch '\bWrite-Host\b') { return $line }

    # Skip Write-Host '' (blank line emit)
    if ($line -match "^(\s*)Write-Host\s*''\s*$") { return $line }
    if ($line -match '^(\s*)Write-Host\s*""\s*$') { return $line }

    # Skip -NoNewline / `r prefix (in-place progress) -- needs Write-Host
    if ($line -match '-NoNewline\b') { return $line }
    if ($line -match '"`r' -or $line -match "'`r") { return $line }

    # Detect color
    $color = $null
    if ($line -match '-ForegroundColor\s+(\w+)') { $color = $matches[1] }

    # Skip Gray/DarkGray (used for aligned column outputs, separators, headers)
    if ($color -in @('Gray','DarkGray')) { return $line }

    # Pick replacement function
    $fn = if ($color -and $colorMap.ContainsKey($color)) { $colorMap[$color] } else { 'Write-SIInfo' }

    # Strip the -ForegroundColor argument
    $stripped = $line -replace '\s*-ForegroundColor\s+\w+\s*',''

    # Replace `Write-Host` -> chosen helper, AND strip a single leading space from the
    # message so Write-SI*'s ' [TAG] ' prefix doesn't double-up. Multi-space leading
    # indents (alignment >= 3 spaces) preserved.
    # Patterns we handle:
    #   Write-Host ' single quote msg'
    #   Write-Host " double quote msg"
    #   Write-Host (' formatted ...' -f ...)
    #   Write-Host (" formatted ...' -f ...)
    $newLine = $stripped -replace `
        "Write-Host\s+'(\s)([^']*)'", "$fn '`$2'"
    $newLine = $newLine -replace `
        'Write-Host\s+"(\s)([^"]*)"', "$fn ""`$2"""
    $newLine = $newLine -replace `
        "Write-Host\s+\(\s*'(\s)([^']*?)'\s*-f\s+", "$fn ('`$2' -f "
    $newLine = $newLine -replace `
        'Write-Host\s+\(\s*"(\s)([^"]*?)"\s*-f\s+', "$fn (""`$2"" -f "

    # If still says "Write-Host" (no leading-space msg), still convert keyword to helper
    # for non-leading-space messages -- but ONLY if we had no -fg-color or non-mapped color.
    if ($newLine -match '\bWrite-Host\b') {
        $newLine = $newLine -replace 'Write-Host\b', $fn
    }

    return $newLine
}

$total = 0
$changed = 0
$convertedFiles = @()

Get-ChildItem -Path $Path -Recurse -Filter '*.ps1' | Where-Object { -not (Should-Skip $_.FullName) } | ForEach-Object {
    $file = $_.FullName
    $orig = Get-Content -LiteralPath $file -Raw
    $lines = $orig -split "`r?`n"

    $newLines = foreach ($l in $lines) { Convert-Line -line $l }
    $new = $newLines -join "`r`n"

    if ($new -ne $orig) {
        $changed++
        $convertedFiles += $file
        if (-not $WhatIfMode) {
            Set-Content -LiteralPath $file -Value $new -Encoding UTF8 -NoNewline
        }
        Write-Host ("CHANGED  {0}" -f $file) -ForegroundColor Yellow
    }
    $total++
}

Write-Host ''
Write-Host ("Scanned: {0}  Changed: {1}" -f $total, $changed) -ForegroundColor Cyan
if ($WhatIfMode) { Write-Host '(WhatIf mode -- no files written)' -ForegroundColor White }
