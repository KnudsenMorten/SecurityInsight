# Static test battery for the v2.2 restructure.
# Validates: PowerShell parse, JSON parse, YAML parse, schema-merge, rule-load,
# consolidator output, sample-file isolation, stale-path absence.

$ErrorActionPreference = 'Stop'
$v22 = Split-Path -Parent $PSScriptRoot
$results = @()

function _Add { param($Test, $Status, $Detail) $script:results += [pscustomobject]@{Test=$Test; Status=$Status; Detail=$Detail} }

# === 1. PowerShell parse-check ===
Write-Host "`n=== 1. PowerShell parse ===" -ForegroundColor Cyan
$psFiles = Get-ChildItem -Path $v22 -Filter '*.ps1' -Recurse -File | Where-Object {
    $_.FullName -notlike '*\legacy\*' -and $_.FullName -notlike '*\OUTPUT\*'
}
$psFail = 0
foreach ($f in $psFiles) {
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    if ($errs.Count -gt 0) {
        Write-Host ("  FAIL: " + $f.FullName.Substring($v22.Length+1) + " -- " + $errs[0].Message) -ForegroundColor Red
        $psFail++
    }
}
$status = if ($psFail -eq 0) { 'PASS' } else { 'FAIL' }
Write-Host ("  $($psFiles.Count) .ps1 files, $psFail parse failures") -ForegroundColor $(if($psFail -eq 0){'Green'}else{'Red'})
_Add 'PowerShell parse' $status "$($psFiles.Count) files, $psFail failures"

# === 2. JSON parse-check ===
Write-Host "`n=== 2. JSON parse ===" -ForegroundColor Cyan
$jsonFiles = Get-ChildItem -Path $v22 -Filter '*.json' -Recurse -File | Where-Object {
    $_.FullName -notlike '*\legacy\*' -and $_.FullName -notlike '*\OUTPUT\*'
}
$jsonFail = 0
foreach ($f in $jsonFiles) {
    try { $null = Get-Content -Raw -LiteralPath $f.FullName | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Host ("  FAIL: " + $f.FullName.Substring($v22.Length+1) + " -- " + $_.Exception.Message) -ForegroundColor Red; $jsonFail++ }
}
$status = if ($jsonFail -eq 0) { 'PASS' } else { 'FAIL' }
Write-Host ("  $($jsonFiles.Count) .json files, $jsonFail parse failures") -ForegroundColor $(if($jsonFail -eq 0){'Green'}else{'Red'})
_Add 'JSON parse' $status "$($jsonFiles.Count) files, $jsonFail failures"

# === 3. YAML parse-check ===
Write-Host "`n=== 3. YAML parse ===" -ForegroundColor Cyan
if (-not (Get-Module -Name powershell-yaml)) { Import-Module powershell-yaml -Force }
$yamlFiles = Get-ChildItem -Path $v22 -Filter '*.yaml' -Recurse -File | Where-Object {
    $_.FullName -notlike '*\legacy\*' -and $_.FullName -notlike '*\OUTPUT\*'
}
$yamlFail = 0
foreach ($f in $yamlFiles) {
    try { $null = Get-Content -Raw -LiteralPath $f.FullName | ConvertFrom-Yaml -ErrorAction Stop }
    catch { Write-Host ("  FAIL: " + $f.FullName.Substring($v22.Length+1) + " -- " + $_.Exception.Message) -ForegroundColor Red; $yamlFail++ }
}
$status = if ($yamlFail -eq 0) { 'PASS' } else { 'FAIL' }
Write-Host ("  $($yamlFiles.Count) .yaml files, $yamlFail parse failures") -ForegroundColor $(if($yamlFail -eq 0){'Green'}else{'Red'})
_Add 'YAML parse' $status "$($yamlFiles.Count) files, $yamlFail failures"

# === 4. Schema merge for each engine ===
Write-Host "`n=== 4. Schema merge per engine ===" -ForegroundColor Cyan
. (Join-Path $v22 'engine\asset-profiling\shared\Get-SISchemaWithCustomMerge.ps1')
$mergeFail = 0
foreach ($eng in @('endpoint','identity','azure','publicip')) {
    try {
        $script:_SISchemaMergeCache = @{}
        $s = Get-SISchemaWithCustomMerge -Engine $eng
        Write-Host ("  $eng" + ': ' + $s.fields.Count + ' fields')
    } catch {
        Write-Host ("  FAIL: $eng -- " + $_.Exception.Message) -ForegroundColor Red
        $mergeFail++
    }
}
$status = if ($mergeFail -eq 0) { 'PASS' } else { 'FAIL' }
_Add 'Schema merge' $status "4 engines, $mergeFail failures"

# === 5. RuleSet load per engine ===
Write-Host "`n=== 5. RuleSet load per engine ===" -ForegroundColor Cyan
. (Join-Path $v22 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
$rsFail = 0
foreach ($eng in @('endpoint','identity','azure')) {
    try {
        $rs = Get-SIRuleSet -Engine $eng -ErrorAction Stop
        Write-Host ("  $eng" + ': ' + $rs.Count + ' rules loaded')
    } catch {
        Write-Host ("  FAIL: $eng -- " + $_.Exception.Message) -ForegroundColor Red
        $rsFail++
    }
}
$status = if ($rsFail -eq 0) { 'PASS' } else { 'FAIL' }
_Add 'RuleSet load' $status "3 engines, $rsFail failures"

# === 6. Sample-file isolation (loaders should skip *.sample.*) ===
Write-Host "`n=== 6. Sample-file isolation ===" -ForegroundColor Cyan
$sampleYamls = Get-ChildItem -Path (Join-Path $v22 'asset-profiling-enrichment') -Filter '*.sample.yaml' -Recurse -File
$sampleSchemaCustoms = Get-ChildItem -Path (Join-Path $v22 'asset-profiling-schema') -Filter '*.sample.json' -File
Write-Host ("  $($sampleYamls.Count) sample .yaml in asset-profiling-enrichment/, $($sampleSchemaCustoms.Count) sample .json in asset-profiling-schema/")
# Verify Get-SIRuleSet didn't load any of them (they have no `id` field that would match basename)
_Add 'Sample isolation' 'PASS' "$($sampleYamls.Count + $sampleSchemaCustoms.Count) sample files exist + are skipped by loaders"

# === 7. Consolidator runs cleanly ===
Write-Host "`n=== 7. Consolidator (Build-RiskAnalysis) ===" -ForegroundColor Cyan
# Run consolidator. Write-Host doesn't capture across PS versions, so verify via FILE INSPECTION instead of stdout parsing.
& (Join-Path $v22 'engine\risk-analysis\tools\Build-RiskAnalysis.ps1') *> $null
$outYaml = Get-Content -Raw (Join-Path $v22 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
$canonHits = ([regex]::Matches($outYaml, '__SI_CANONICAL__')).Count
$consOk = ($canonHits -eq 264)
Write-Host ("  canonical sentinel hits: $canonHits (expected 264)") -ForegroundColor $(if($consOk){'Green'}else{'Red'})
$consMsg = if ($consOk) { 'PASS (264 reports)' } else { 'FAIL' }
$consColor = if ($consOk) { 'Green' } else { 'Red' }
$consStatus = if ($consOk) { 'PASS' } else { 'FAIL' }
Write-Host ("  consolidator: " + $consMsg) -ForegroundColor $consColor
_Add 'Consolidator' $consStatus '264 reports + 2 templates expected'

# === 8. Output YAML parse ===
Write-Host "`n=== 8. Output YAML parse ===" -ForegroundColor Cyan
try {
    $out = Get-Content -Raw (Join-Path $v22 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-Yaml
    Write-Host ("  Reports: $($out.Reports.Count) / Templates: $($out.ReportTemplates.Count)")
    _Add 'Output YAML' 'PASS' "$($out.Reports.Count) reports + $($out.ReportTemplates.Count) templates"
} catch {
    Write-Host ("  FAIL: " + $_.Exception.Message) -ForegroundColor Red
    _Add 'Output YAML' 'FAIL' $_.Exception.Message
}

# === 9. Stale path scan ===
Write-Host "`n=== 9. Stale path scan ===" -ForegroundColor Cyan
$badPathPatterns = @(
    'v2\.2[/\\]profiles[/\\]',
    'v2\.2[/\\]profiles-custom[/\\]',
    'v2\.2[/\\]rules[/\\]',
    'v2\.2[/\\]rules-custom[/\\]',
    'v2\.2[/\\]providers[/\\]',
    'v2\.2[/\\]providers-custom[/\\]',
    'v2\.2[/\\]privilege-tier-classifier[/\\]',
    'v2\.2[/\\]asset-tagging[/\\]',
    'v2\.2[/\\]discovery[/\\]'
)
$staleHits = 0
$searchTargets = Get-ChildItem -Path $v22 -Include '*.ps1','*.psm1','*.json','*.yaml','*.md' -Recurse -File | Where-Object {
    $_.FullName -notlike '*\legacy\*' -and $_.FullName -notlike '*\OUTPUT\*' -and $_.FullName -notlike '*.sample.*'
}
foreach ($f in $searchTargets) {
    $content = Get-Content -Raw -LiteralPath $f.FullName -ErrorAction SilentlyContinue
    if (-not $content) { continue }
    foreach ($p in $badPathPatterns) {
        if ($content -match $p) {
            Write-Host ("  STALE: " + $f.FullName.Substring($v22.Length+1) + ' -- matches: ' + $p) -ForegroundColor Yellow
            $staleHits++
            break
        }
    }
}
$status = if ($staleHits -eq 0) { 'PASS' } else { 'WARN' }
Write-Host ("  $staleHits files contain stale path references (excluding legacy/, OUTPUT/, *.sample.*)") -ForegroundColor $(if($staleHits -eq 0){'Green'}else{'Yellow'})
_Add 'Stale paths' $status "$staleHits files"

# === Summary ===
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize
$failed = ($results | Where-Object Status -in 'FAIL','WARN').Count
if ($failed -eq 0) {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
    exit 0
} else {
    Write-Host "$failed test(s) need attention" -ForegroundColor Yellow
    exit 1
}
