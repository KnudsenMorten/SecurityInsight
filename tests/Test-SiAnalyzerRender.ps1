#Requires -Version 5.1
<#
.SYNOPSIS
    Headless render check for the SI Analyzer SPA. No browser is ever opened.
.DESCRIPTION
    1. Renders the SPA to a temp HTML file via Open-SiAnalyzer.ps1 -NoServer.
    2. Asserts the key panels / hooks are present in the markup (both surfaces).
    3. Extracts the inline <script> and runs `node --check` on it to prove the
       JS parses (catches syntax errors before they reach a browser).
    Exits non-zero on any failure. Skips the node step (with a warning) if node
    isn't installed -- a skip is NOT a pass for that sub-check.
.NOTES
    Operator rule: NEVER auto-open a browser / Start-Process on a render file.
#>
param()

$ErrorActionPreference = 'Stop'
$fail = 0
function Ok($m){ Write-Host "  OK: $m" -ForegroundColor Green }
function Bad($m){ Write-Host "  FAIL: $m" -ForegroundColor Red; $script:fail++ }

Write-Host "SI Analyzer headless render check" -ForegroundColor Cyan

$analyzer = Join-Path (Split-Path -Parent $PSScriptRoot) 'analyzer\Open-SiAnalyzer.ps1'
if (-not (Test-Path $analyzer)) { $analyzer = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight\analyzer\Open-SiAnalyzer.ps1' }

$out = Join-Path ([System.IO.Path]::GetTempPath()) ("si-analyzer-rendercheck-{0}.html" -f ([guid]::NewGuid().ToString('N')))
& $analyzer -NoServer -OutHtml $out | Out-Null
if (-not (Test-Path $out)) { Bad "render did not produce $out"; exit 1 }
$html = Get-Content -LiteralPath $out -Raw -Encoding UTF8
Ok "rendered SPA to a file (no browser)"

# Key panels / hooks for BOTH surfaces.
$mustHave = @(
    'SecurityInsight Analyzer',          # title
    'id="view-analyst"',                 # analyst surface
    'id="view-mgmt"',                    # management surface
    'id="worklist"',                     # top worklist table
    'id="prestaged"',                    # prestaged analyses
    'id="adhoc"',                        # ad-hoc prompt box
    'id="suggest"',                      # suggested-prompt chips
    'id="adhoc-kql"',                    # show/edit query toggle target
    'id="chart"',                        # mgmt risk-over-time chart
    'id="mgmt-stats"',                   # new/closed/open stats
    'id="mgmt-summary"',                 # AI exec summary panel
    '/api/worklist','/api/prestaged','/api/adhoc','/api/management','/api/verdict'
)
foreach ($h in $mustHave) {
    if ($html.Contains($h)) { Ok "panel/hook present: $h" } else { Bad "missing panel/hook: $h" }
}

# Extract the inline <script> block(s) and node --check them.
$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) {
    Write-Host "  WARN: node not found -- skipping JS parse check (this is a SKIP, not a pass)" -ForegroundColor Yellow
} else {
    $scriptBlocks = [regex]::Matches($html, '(?s)<script>(.*?)</script>')
    if ($scriptBlocks.Count -eq 0) { Bad "no inline <script> block found" }
    $i = 0
    foreach ($m in $scriptBlocks) {
        $js = $m.Groups[1].Value
        $jsFile = Join-Path ([System.IO.Path]::GetTempPath()) ("si-analyzer-js-{0}-{1}.js" -f ([guid]::NewGuid().ToString('N')), $i)
        Set-Content -LiteralPath $jsFile -Value $js -Encoding UTF8
        $null = & node --check $jsFile 2>&1
        if ($LASTEXITCODE -eq 0) { Ok "inline JS block #$i parses (node --check)" } else { Bad "inline JS block #$i failed node --check" }
        Remove-Item -LiteralPath $jsFile -ErrorAction SilentlyContinue
        $i++
    }
}

Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue

if ($fail -gt 0) { Write-Host "RENDER CHECK FAILED ($fail)" -ForegroundColor Red; exit 1 }
Write-Host "RENDER CHECK PASSED" -ForegroundColor Green
exit 0
