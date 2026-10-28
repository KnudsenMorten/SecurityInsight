#Requires -Version 5.1
<#
.SYNOPSIS
    ON DEMAND ONLY (no gate runs it): the memory a Risk Analysis workbook takes, at a chosen size -- the offline repro of the
    live out-of-memory of 2026-10-16 (a Detailed run of 1,167,338 rows x ~94 columns).
.DESCRIPTION
    Rows like a Detailed run's (-Columns columns of short text, a score, a date, a list every 7th row) are handed over a page
    at a time, as the database pager does, and written:
      -Mode Streamed   the export since the hotfix (RA-WorkbookExport.ps1 Write-RAXlsxStreamed): one page held at a time.
      -Mode Gathered   the export before it: every row gathered in a list, then the workbook written (Export-Worksheet).
    Prints one JSON line: rows, columns, mode, seconds, the process's peak working set, the managed heap after the last page,
    the file size and the sheets. Run each mode in its own process (a peak is per process). Test VM only, never mgmt1.
.EXAMPLE
    pwsh -NoProfile -File tests\Measure-RaWorkbookMemory.ps1 -Rows 1200000 -Columns 94 -Mode Streamed -Path C:\work\m\s.xlsx
#>
param([long]$Rows = 1200000, [int]$Columns = 94, [int]$PageRows = 2000, [ValidateSet('Streamed', 'Gathered')][string]$Mode = 'Streamed',
      [Parameter(Mandatory)][string]$Path)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$sh = Join-Path $root 'engine\risk-analysis\_shared'
$script:_sheetWritten = @{}
. (Join-Path $sh 'RA-RunProgress.ps1')
. (Join-Path $sh 'RA-ExcelReport.ps1')
. (Join-Path $sh 'RA-WorkbookExport.ps1')
$script:_sheetWritten = @{}

$cols = @('RowKey', 'RiskScoreTotal_Weighted', 'CollectionTime', 'Tags') + @(1..($Columns - 4) | ForEach-Object { 'C{0:D3}' -f $_ })
$t0 = [datetime]::new(2026, 10, 16, 8, 0, 0, [DateTimeKind]::Utc)
$state = @{ At = 0L }
$make = {
    if ($state.At -ge $Rows) { return $null }
    $n = [int][Math]::Min([long]$PageRows, $Rows - $state.At)
    $out = New-Object 'System.Collections.Generic.List[object]' $n
    for ($k = 0; $k -lt $n; $k++) {
        $i = $state.At + $k
        $o = [ordered]@{ RowKey = ('finding-{0:D8}' -f $i); RiskScoreTotal_Weighted = [int](1000000 - ($i % 999983)); CollectionTime = $t0 }
        if ($i % 7 -eq 0) { $o['Tags'] = @('internet-facing', ('tier{0}' -f ($i % 4))) }
        for ($c = 1; $c -le $Columns - 4; $c++) { $o[('C{0:D3}' -f $c)] = ('{0} value {1} of row {2}' -f $c, ($i % 9973), $i) }
        $out.Add([pscustomobject]$o)
    }
    $state.At += $n
    , $out.ToArray()
}.GetNewClosure()   # its own variables: the writer has a -Columns of its own
$heap = 0L
$sw = [Diagnostics.Stopwatch]::StartNew()
if ($Mode -eq 'Streamed') {
    $res = Write-RAXlsxStreamed -Path $Path -SheetName 'Details' -Columns $cols -NextPage $make -WrapColumns $script:RAExcelWrapColumns -WidthCaps $script:RAExcelWidthCaps
    $sheets = @($res.Sheets)
} else {
    $all = New-Object System.Collections.Generic.List[object]
    while ($true) { $p = & $make; if ($null -eq $p) { break }; foreach ($r in $p) { $all.Add($r) }; $p = $null }
    $global:SI_ExcelMaxDataRows = 1048575
    Export-Worksheet -Path $Path -SheetName 'Details' -Rows $all.ToArray() -DesiredColumns $cols -TableStyle 'Medium9'
    $sheets = @('Details')
}
$sw.Stop()
[GC]::Collect(); $heap = [GC]::GetTotalMemory($true)
$proc = [Diagnostics.Process]::GetCurrentProcess(); $proc.Refresh()
[pscustomobject]@{ Mode = $Mode; Rows = $Rows; Columns = $Columns; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    PeakWorkingSetMB = [Math]::Round($proc.PeakWorkingSet64 / 1MB); HeapAfterMB = [Math]::Round($heap / 1MB)
    FileMB = [Math]::Round((Get-Item -LiteralPath $Path).Length / 1MB, 1); Sheets = ($sheets -join ', '); PowerShell = $PSVersionTable.PSVersion.ToString() } | ConvertTo-Json -Compress
