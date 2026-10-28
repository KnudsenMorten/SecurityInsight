#Requires -Version 7.0
<#
    Vendor bench (not a test, not shipped): one synthetic Device_Missing_CVEs_Detailed slice through every Risk Analysis
    step (tests\fixtures\ra-perf\RaPerfFixture.ps1, Invoke-RaPerfSlice) on -Threads cores, in THIS process held to -Cores
    processor cores (the job's size), with the process's memory sampled every 50 ms during the scoring and the stored form.
    One JSON line out. Run it once per -Threads in its own process (the peak is the process's own):

      pwsh -NoProfile -File parallel-bench.ps1 -N 16000 -Threads 1 -Cores 4
      pwsh -NoProfile -File parallel-bench.ps1 -N 16000 -Threads 4 -Cores 4

    Test VM only (never mgmt1). Synthetic data only.
#>
param([string]$SIRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), [int]$N = 16000, [int]$Threads = 4, [int]$Cores = 4, [long]$Mask = 0,
      [string]$Culture = '', [int]$Repeat = 2)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($Mask -gt 0) { [System.Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity = [IntPtr]$Mask } elseif ($Cores -gt 0) { [System.Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity = [IntPtr]([long]([Math]::Pow(2, $Cores) - 1)) }
if ($Culture) { [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($Culture) }
Add-Type -TypeDefinition @'
using System; using System.Diagnostics; using System.Threading;
public static class RaBenchMem {
    static long _peak; static Timer _t;
    public static void Start() { _peak = Process.GetCurrentProcess().WorkingSet64; _t = new Timer(_ => { using (var p = Process.GetCurrentProcess()) { long w = p.WorkingSet64; if (w > Interlocked.Read(ref _peak)) Interlocked.Exchange(ref _peak, w); } }, null, 0, 50); }
    public static long Stop() { _t.Dispose(); return Interlocked.Read(ref _peak); }
    public static long Now() { using (var p = Process.GetCurrentProcess()) { return p.WorkingSet64; } }
}
'@
function global:Write-Info { param($m) if ($m -like 'risk scores of*' -or $m -like 'rows of this query slice prepared*') { $global:RaBenchSaid.Add([string]$m) } }
function global:Write-Warn2 { param($m) $global:RaBenchSaid.Add('WARN: ' + [string]$m) }
function global:Write-Ok { param($m) }
function global:Write-Diag { param($m) }
$global:RaBenchSaid = [System.Collections.Generic.List[string]]::new()
. (Join-Path $PSScriptRoot 'RaPerfFixture.ps1')
foreach ($f in (Import-RaPerfEngine -SIRoot $SIRoot)) { . $f }
$global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
$global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
$global:SI_RA_ScoringThreads = $Threads
$idx = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
$cis = New-RaPerfCis
# a small slice first: the worker runspaces are made once per process, as the engine makes them once per run
$null = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 2500 -Seed 11) -Cis $cis -RiskIndex $idx
$runs = [System.Collections.Generic.List[object]]::new()
for ($r = 1; $r -le $Repeat; $r++) {
    $raw = New-RaPerfRawRows -Count $N
    [GC]::Collect(); [GC]::WaitForPendingFinalizers(); [GC]::Collect()
    $before = [RaBenchMem]::Now()
    $global:RaBenchSaid.Clear()
    [RaBenchMem]::Start()
    $res = Invoke-RaPerfSlice -Raw $raw -Cis $cis -RiskIndex $idx
    $peak = [RaBenchMem]::Stop()
    $runs.Add([ordered]@{
        Run = $r; Rows = $res.Rows['scoring']
        ScoringSeconds = [Math]::Round($res.Times['scoring'], 2); SqlItemsSeconds = [Math]::Round($res.Times['sql write'], 2)
        ScoringRowsPerSecond = [Math]::Round($res.Rows['scoring'] / [Math]::Max(0.001, $res.Times['scoring']), 0)
        WorkingSetBeforeMB = [Math]::Round($before / 1MB, 0); PeakWorkingSetMB = [Math]::Round($peak / 1MB, 0)
        Said = $global:RaBenchSaid.ToArray() })
    $res = $null; $raw = $null
}
[ordered]@{ N = $N; Threads = $Threads; Cores = $Cores; ProcessorCount = [Environment]::ProcessorCount; Culture = [System.Globalization.CultureInfo]::CurrentCulture.Name
    Pwsh = [string]$PSVersionTable.PSVersion; ProcessPeakWorkingSetMB = [Math]::Round([System.Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64 / 1MB, 0); Runs = $runs.ToArray() } | ConvertTo-Json -Depth 5 -Compress
