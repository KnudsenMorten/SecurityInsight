#Requires -Version 7.0
param([string]$SIRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), [int]$N = 14000)
# Vendor bench (not a test; run it on the test VM): one synthetic Device_Missing_CVEs_Detailed slice through the engine's
# steps between the column union and the database write (the SQL seam stubbed), each step timed.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function global:Write-Info { param($m) }
function global:Write-Warn2 { param($m) Write-Host "WARN: $m" }
function global:Write-Ok { param($m) }
function global:Write-Diag { param($m) }
. (Join-Path $PSScriptRoot 'RaPerfFixture.ps1')
. (Join-Path $PSScriptRoot 'RaShapingFixture.ps1')
foreach ($f in (Import-RaPerfEngine -SIRoot $SIRoot)) { . $f }
$sw = [Diagnostics.Stopwatch]::StartNew()
$rows = New-RaShapingRows -Count $N
$cols = Get-RaShapingColumns -Rows $rows
Write-Host ("pwsh {0}  rows={1} columns={2} (row 1 has {3})  built in {4:N1}s  cores={5}" -f $PSVersionTable.PSVersion, $rows.Count, $cols.Count, @($rows[0].PSObject.Properties).Count, $sw.Elapsed.TotalSeconds, [Environment]::ProcessorCount)
$res = Invoke-RaShapingStages -Rows $rows -Columns $cols
$t = 0.0; foreach ($k in $res.Times.Keys) { $t += $res.Times[$k]; Write-Host ("{0,-58} {1,8:N2}s" -f $k, $res.Times[$k]) }
Write-Host ("{0,-58} {1,8:N2}s  ({2} rows written)" -f 'TOTAL', $t, $res.Written)
