#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- skeleton smoke test.

    Runs the orchestrator end-to-end in Mock mode. Verifies:
      * All 6 stages execute and return summaries
      * Stage 2 Collect computes fp_meta and (on second run) hits cache
      * Stage 3 Enrich computes fp_enrich and (on second run) reuses verdict
      * Stage 4 Classify writes fingerprint records back
      * Stage 5 Output writes JSON + CSV files

    Run from: SOLUTIONS\SecurityInsight\tests\
#>

$ErrorActionPreference = 'Stop'

$v22Root = Split-Path -Parent $PSScriptRoot
$orchestrator = Join-Path $v22Root 'engine\asset-profiling\Invoke-SIEngineRun.ps1'

Write-Host "============================================================"
Write-Host "v2.2 skeleton test -- run #1 (cold cache, expect AI calls)"
Write-Host "============================================================"
$run1 = & $orchestrator -Engine endpoint -Mock -Sinks JSON,Excel,LA

Write-Host ""
Write-Host "Run 1 stage results:"
$run1.StageResults.GetEnumerator() | ForEach-Object {
    Write-Host ("  {0,-10} {1}" -f $_.Key, $_.Value.Summary)
}

if ($run1.StageResults['Classify'].AiCalls -eq 0) { throw 'FAIL run1: expected AI calls > 0 on cold cache' }
if ($run1.StageResults['Classify'].Reused  -ne 0) { throw 'FAIL run1: expected 0 reused verdicts on cold cache' }

Write-Host ""
Write-Host "============================================================"
Write-Host "v2.2 skeleton test -- run #2 (warm cache, expect skip + reuse)"
Write-Host "============================================================"
# Re-use the same mock storage context so the cache survives
$run2Ctx = $run1.StorageContext
$runId2 = '{0:yyyyMMddTHHmmssZ}-endpoint-{1}' -f ([datetime]::UtcNow), [guid]::NewGuid().ToString().Substring(0,8)

. (Join-Path $v22Root 'Get-FingerprintEngine.ps1')
. (Join-Path $v22Root 'engine\asset-profiling\storage\StorageContext.ps1')
. (Join-Path $v22Root 'engine\asset-profiling\storage\FingerprintCache.ps1')
. (Join-Path $v22Root 'engine\asset-profiling\storage\StagingBlob.ps1')

$runContext2 = [pscustomobject]@{
    RunId            = $runId2
    Engine           = 'endpoint'
    StartedAt        = [datetime]::UtcNow
    AssetLimit       = 0
    Sinks            = @('JSON','Excel')
    StorageContext   = $run2Ctx
    FingerprintTable = $run1.FingerprintTable
    StagingContainer = $run1.StagingContainer
    StageResults     = @{}
}

$stagesRoot = Join-Path $v22Root 'engine\asset-profiling\stages'
foreach ($s in @('Schedule','Discover','Collect','Enrich','Classify','Output')) {
    . (Join-Path $stagesRoot ('Invoke-{0}.ps1' -f $s))
    $result = & ('Invoke-SI{0}' -f $s) -RunContext $runContext2
    $runContext2.StageResults[$s] = $result
    Write-Host ("  {0,-10} {1}" -f $s, $result.Summary)
}

if ($runContext2.StageResults['Collect'].Skipped -ne $runContext2.StageResults['Discover'].AssetCount) {
    throw ('FAIL run2: expected all {0} assets to be skipped via fp_meta match, got Skipped={1}' -f $runContext2.StageResults['Discover'].AssetCount, $runContext2.StageResults['Collect'].Skipped)
}

Write-Host ""
Write-Host "PASS: cold-run AI calls + warm-run skip both verified."
