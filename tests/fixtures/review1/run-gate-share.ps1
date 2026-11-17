#Requires -Version 7.0
<#
    The Azure test runner's command for ONE SHARE of the quick gate (Invoke-FastGate.ps1 -Only): the runner's shell ends a
    command at ';', so the share is named with commas here and handed on with ';'. Everything else is the gate's own.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/review1/run-gate-share.ps1 -Base <sha> -Share SIv3-A,SIv3-B
#>
param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Share, [string]$ResultFile = './si-gate-result.json')
$gate = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Invoke-FastGate.ps1'
$only = (@($Share -split '[,\s]+' | Where-Object { $_ }) -join ';')
# the runner's bundle carries no origin/main: SIv3-Telemetry compares SI's uplink client with main's framework copy by its git
# blob -- main's blob as read on the development machine (git rev-parse origin/main:sync/_AitUplink.ps1, 2026-11-17), handed in so the comparison
# runs instead of being skipped (it still fails when SI's copy differs from it)
if (-not $env:SI_TEST_MAIN_AITUPLINK_BLOB) { $env:SI_TEST_MAIN_AITUPLINK_BLOB = '52690703d5a812595c6d5e703a75d7ef4bca3a1c' }
& pwsh -NoProfile -File $gate -ResultFile $ResultFile -Runtime pwsh -Base $Base -Workers 3 -NoDotnet -Hotfix -Only $only
exit $LASTEXITCODE
