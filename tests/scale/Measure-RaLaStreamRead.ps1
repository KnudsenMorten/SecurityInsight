#Requires -Version 7.0
<#
.SYNOPSIS
    MEASUREMENT (offline, test VM only): the memory a Risk Analysis lookup takes WHILE it is read from Log Analytics --
    the lean read (#639: the answer's bytes in one array, a JsonDocument over them, then the rows) against the read as it
    arrives (#730, engine\_shared\SI-LaStreamRead.ps1), through the real engine code, each in a process of its own.

.DESCRIPTION
    A generated answer of -Rows rows in the shape of the identity CI lookup (_ciLink: 17 columns, two of them dynamic
    lists) is written to a file once. Then, per mode, a NEW pwsh process reads it the way the engine reads an answer --
      lean    the bytes in one array (as Invoke-SIAzRestHttp reads a body of known length), ConvertFrom-SILaQueryRows
      stream  a FileStream handed to ConvertFrom-SILaQueryStream (as Invoke-SIAzRestHttp -ReadStream hands the response)
    -- with compact rows (SI_LaCompactRows, as Get-SIHybridLetRows asks). Each process reports its peak working set, the
    managed heap with the rows still held, the rows, the seconds and a SHA-256 over every row's values (the two must be
    equal). Output: one JSON line per mode, and -OutFile.
    Never on mgmt1. Not a gate: the gate runs SIv3-RaStreamRead.Tests.ps1, which is small.

.EXAMPLE
    pwsh -NoProfile -File tests\scale\Measure-RaLaStreamRead.ps1 -Rows 300000 -OutFile C:\work\si\rasize\stream.json
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 5000000)][int]$Rows = 300000,
    [string]$OutFile = '',
    [string]$WorkDir = '',
    # internal: one measurement in this process
    [ValidateSet('', 'lean', 'stream')][string]$Mode = '',
    [string]$AnswerFile = ''
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

if ($Mode) {
    . (Join-Path $siRoot 'engine\_shared\SI-AzRest.ps1')
    $global:SI_LaCompactRows = $true
    [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($Mode -eq 'lean') {
        [byte[]]$bytes = [IO.File]::ReadAllBytes($AnswerFile)
        $ans = ConvertFrom-SILaQueryRows -Bytes $bytes
        $bytes = $null
    } else {
        $fs = [IO.File]::OpenRead($AnswerFile)
        try { $ans = ConvertFrom-SILaQueryStream -Stream $fs -Compact } finally { $fs.Dispose() }
    }
    $sw.Stop()
    [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    $heldMB = [Math]::Round([GC]::GetTotalMemory($true) / 1MB, 1)
    $p = [Diagnostics.Process]::GetCurrentProcess(); $p.Refresh()
    $sha = [Security.Cryptography.SHA256]::Create()
    $names = @($ans.Columns | ForEach-Object { [string]$_.name })
    foreach ($r in $ans.Rows) {
        $line = [Text.Encoding]::UTF8.GetBytes((($names | ForEach-Object { $v = $r.$_; if ($null -eq $v) { "`0" } else { [string]$v } }) -join "`t") + "`n")
        [void]$sha.TransformBlock($line, 0, $line.Length, $null, 0)
    }
    [void]$sha.TransformFinalBlock([byte[]]@(), 0, 0)
    [pscustomobject]@{
        Mode = $Mode; Rows = @($ans.Rows).Count; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        PeakWorkingSetMB = [Math]::Round($p.PeakWorkingSet64 / 1MB, 0); HeldManagedMB = $heldMB
        RowType = $(if (@($ans.Rows).Count) { @($ans.Rows)[0].GetType().FullName } else { '' })
        Sha256 = ([BitConverter]::ToString($sha.Hash) -replace '-', '')
    } | ConvertTo-Json -Compress
    return
}

if (-not $WorkDir) { $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ('si-lastream-' + [guid]::NewGuid().ToString('N').Substring(0, 8)) }
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$file = Join-Path $WorkDir 'answer.json'
$cols = '_ciKey:string', 'si_ci_id:string', 'si_class:string', 'si_asset_name:string', 'si_tier:int', 'si_tier_set_by:string', 'si_cmdb_id:string',
        'si_cmdb_name:string', 'si_cmdb_criticality:string', 'si_cmdb_data_sensitivity:string', 'si_criticality_factor:real', 'si_rf_p:dynamic',
        'si_rf_c:dynamic', 'si_rf_names_:dynamic', 'si_stale_:bool', 'si_tags_:string', 'si_in_scope_:bool'
$w = New-Object IO.StreamWriter($file, $false, (New-Object Text.UTF8Encoding($false)))
try {
    $w.Write('{"tables":[{"name":"PrimaryResult","columns":[')
    $w.Write((($cols | ForEach-Object { $n, $t = $_ -split ':'; '{"name":"' + $n + '","type":"' + $t + '"}' }) -join ','))
    $w.Write('],"rows":[')
    for ($i = 0; $i -lt $Rows; $i++) {
        if ($i) { $w.Write(',') }
        $ci = [int]($i / 4)
        $w.Write(('["{0:x8}-{1:x4}-4a1b-9c2d-{2:x12}","ci-{3:x12}","identity","user{3}@contoso.example","{4}","rule","CMDB{5}","Service {5}","High","Confidential",1.5,"[\"no_mfa\",\"old_password\"]","[\"permanent_privileged_role\"]","[\"NoMFA\",\"OldPassword\"]",{6},"","{7}"]' -f
            $i, ($i % 65536), ([long]$i * 7919), $ci, ($i % 4), ($ci % 500), $(if ($i % 9) { 'false' } else { 'true' }), $(if ($i % 11) { 'true' } else { 'false' })))
    }
    $w.Write(']}]}')
} finally { $w.Dispose() }
$size = (Get-Item $file).Length
$out = [ordered]@{ Rows = $Rows; AnswerMB = [Math]::Round($size / 1MB, 1); Results = @() }
foreach ($m in 'lean', 'stream') {
    $j = & pwsh -NoProfile -File $PSCommandPath -Mode $m -AnswerFile $file
    $o = ($j | Select-Object -Last 1) | ConvertFrom-Json
    $out.Results += $o
    Write-Host ("{0,-6} rows {1:N0}  peak working set {2:N0} MB  rows held {3:N1} MB  {4:N1} s  {5}" -f $o.Mode, $o.Rows, $o.PeakWorkingSetMB, $o.HeldManagedMB, $o.Seconds, $o.RowType)
}
$out.SameRows = ($out.Results[0].Sha256 -eq $out.Results[1].Sha256 -and $out.Results[0].Rows -eq $out.Results[1].Rows)
Write-Host ("answer {0:N1} MB; the same rows: {1}" -f $out.AnswerMB, $out.SameRows)
$json = $out | ConvertTo-Json -Depth 5
if ($OutFile) { Set-Content -LiteralPath $OutFile -Value $json -Encoding utf8 }
Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
$json
