#Requires -Version 7.0
<#
.SYNOPSIS
    Compares two digest files of Measure-SICiBuildScale.ps1 -DigestFile (one line per stored CI: its id, members, links and
    whole document without the per-build values; then one line per full row posted to SI_CI_CL). Vendor tool: never shipped.
    Prints the counts and the first differences; exit 0 = the same CIs, CI for CI; 1 = a difference.
#>
param([Parameter(Mandatory)][string]$Before, [Parameter(Mandatory)][string]$After, [int]$Show = 3)
foreach ($p in $Before, $After) { if (-not (Test-Path -LiteralPath $p)) { Write-Host ('NOT COMPARED: {0} is missing (the run did not finish)' -f $p); exit 2 } }
$a = [IO.File]::ReadAllLines($Before); $b = [IO.File]::ReadAllLines($After)
if ($a.Count -eq 0 -or $b.Count -eq 0) { Write-Host 'NOT COMPARED: a digest is empty'; exit 2 }
Write-Host ('lines: before {0:N0} (CIs {1:N0}, posted rows {2:N0}) / after {3:N0} (CIs {4:N0}, posted rows {5:N0})' -f $a.Count, @($a | Where-Object { -not $_.StartsWith('POST ') }).Count, @($a | Where-Object { $_.StartsWith('POST ') }).Count,
    $b.Count, @($b | Where-Object { -not $_.StartsWith('POST ') }).Count, @($b | Where-Object { $_.StartsWith('POST ') }).Count)
$n = 0
for ($i = 0; $i -lt [Math]::Max($a.Count, $b.Count); $i++) {
    $x = $(if ($i -lt $a.Count) { $a[$i] } else { '' }); $y = $(if ($i -lt $b.Count) { $b[$i] } else { '' })
    if ($x -ceq $y) { continue }
    $n++
    if ($n -le $Show) {
        $k = 0; while ($k -lt [Math]::Min($x.Length, $y.Length) -and $x[$k] -ceq $y[$k]) { $k++ }
        $s = [Math]::Max(0, $k - 120)
        Write-Host ("DIFFERENT line {0} at character {1}:" -f $i, $k)
        Write-Host ('  before: ' + $x.Substring($s, [Math]::Min(360, $x.Length - $s)))
        Write-Host ('  after : ' + $y.Substring($s, [Math]::Min(360, $y.Length - $s)))
    }
}
Write-Host ('different lines: {0}' -f $n)
if ($n -gt 0) { exit 1 }
exit 0
