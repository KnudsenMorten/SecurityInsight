#Requires -Version 7.0
<#
    Vendor diagnostic (not a test, not shipped): WHERE the time of the several-core scoring goes. One synthetic
    Device_Missing_CVEs_Detailed slice is prepared once (conversion + CI / Defender context), then Calculate-RiskScore is
    timed on 1 / 2 / 4 cores, and each worker part's own time is read (a part that takes as long as the whole one-core
    run means the parts wait on each other, not on the work). Test VM only.
#>
param([string]$SIRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), [int]$N = 16000, [int]$Cores = 0, [long]$Mask = 0, [string]$Threads = '1,2,4')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($Mask -gt 0) { [System.Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity = [IntPtr]$Mask } elseif ($Cores -gt 0) { [System.Diagnostics.Process]::GetCurrentProcess().ProcessorAffinity = [IntPtr]([long]([Math]::Pow(2, $Cores) - 1)) }
function global:Write-Info { param($m) if ($m -like 'risk scores of*') { Write-Host "  $m" } }
function global:Write-Warn2 { param($m) Write-Host "WARN: $m" }
function global:Write-Ok { param($m) }
function global:Write-Diag { param($m) }
. (Join-Path $PSScriptRoot 'RaPerfFixture.ps1')
foreach ($f in (Import-RaPerfEngine -SIRoot $SIRoot)) { . $f }
$global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
$global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
$idx = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
$cis = New-RaPerfCis
Write-Host ("pwsh {0}; cores seen {1}; server GC {2}; concurrent GC {3}; load {4}%" -f $PSVersionTable.PSVersion, [Environment]::ProcessorCount, [System.Runtime.GCSettings]::IsServerGC, ([System.AppContext]::GetData('System.GC.Concurrent')), ((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average))
$rows = ConvertTo-PSObjectDeep (New-RaPerfRawRows -Count $N) -StripOData -CastPrimitiveArrays
$rows = @(Add-RACiContext -Rows @($rows) -FactorSet @() -Index (New-RACiIndex -Cis $cis))
$score = { param($r) @(Calculate-RiskScore -Rows $r -RiskIndex $idx -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
        -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -OutputPropertyOrder (Get-RaPerfOutputOrder) `
        -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Detailed') }
# warm (workers made, catalogs read)
$global:SI_RA_ScoringThreads = 4; $null = & $score @($rows | Select-Object -First 3000 | ForEach-Object { $_.PSObject.Copy() })
foreach ($t in ($Threads -split ',')) {
    $global:SI_RA_ScoringThreads = [int]$t
    $copy = @(foreach ($r in $rows) { $r.PSObject.Copy() })
    $g0 = [GC]::CollectionCount(0); $g2 = [GC]::CollectionCount(2); $p0 = [GC]::GetTotalPauseDuration(); $lc0 = [System.Threading.Monitor]::LockContentionCount
    $al0 = [GC]::GetTotalAllocatedBytes($false)
    $cpu0 = [System.Diagnostics.Process]::GetCurrentProcess().TotalProcessorTime
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $null = & $score $copy
    $s = $sw.Elapsed.TotalSeconds
    $cpu = ([System.Diagnostics.Process]::GetCurrentProcess().TotalProcessorTime - $cpu0).TotalSeconds
    Write-Host ("threads {0}: {1:N1} s wall, {2:N1} s CPU ({3:N2} cores busy); GC gen0 {4}, gen2 {5}, GC pause {6:N1} s; lock contentions {7:N0}; allocated {8:N0} MB" -f $t, $s, $cpu, ($cpu / $s), ([GC]::CollectionCount(0) - $g0), ([GC]::CollectionCount(2) - $g2), ([GC]::GetTotalPauseDuration() - $p0).TotalSeconds, ([System.Threading.Monitor]::LockContentionCount - $lc0), (([GC]::GetTotalAllocatedBytes($false) - $al0) / 1MB))
}
if ($env:RA_DIAG_SKIPPARTS) { return }
# each part's own time inside its worker
$parts = Split-RAParallelParts -Count $rows.Count -Parts 4
$pa = [System.Collections.Generic.List[object]]::new()
foreach ($range in $parts) {
    $p = @{ RiskIndex = $idx; SecurityDomain = 'Endpoint'; CategoryInputName = 'Category'; SubCategoryInputName = 'Subcategory'; ConfigurationIdInputName = 'ConfigurationId'
            SecuritySeverityInputName = 'SecuritySeverity'; CriticalityTierLevelInputName = 'CriticalityTierLevel'; SecurityDomainInputName = 'SecurityDomain'; OutputPropertyOrder = (Get-RaPerfOutputOrder); ReportName = 'Device_Missing_CVEs_Detailed' }
    $pa.Add(@(@(foreach ($r in (Get-RAParallelPart -Rows $rows -Range $range)) { $r.PSObject.Copy() }), $p))
}
$timed = @'
param($Rows, $P)
$ProgressPreference = 'SilentlyContinue'
$global:RA_ParallelWorker = $true
$sw = [Diagnostics.Stopwatch]::StartNew()
$cpu0 = [System.Threading.Thread]::CurrentThread.ManagedThreadId
$res = @(Calculate-RiskScore -Rows $Rows @P)
[pscustomobject]@{ Seconds = $sw.Elapsed.TotalSeconds; Rows = $res.Count; Thread = $cpu0 }
'@
$sw = [Diagnostics.Stopwatch]::StartNew()
$r = Invoke-RAParallelParts -Script $timed -PartArgs $pa.ToArray()
Write-Host ("4 parts at once: {0:N1} s wall; each part: {1}" -f $sw.Elapsed.TotalSeconds, (($r | ForEach-Object { '{0:N1} s / {1} rows (thread {2})' -f $_.Seconds, $_.Rows, $_.Thread }) -join '; '))
# one part alone, for the reference
$sw = [Diagnostics.Stopwatch]::StartNew()
$r1 = Invoke-RAParallelParts -Script $timed -PartArgs @(, $pa[0])
Write-Host ("1 part alone: {0:N1} s ({1} rows)" -f $r1[0].Seconds, $r1[0].Rows)
