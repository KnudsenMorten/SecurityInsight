#Requires -Version 7.0
<#
    Vendor diagnostic (not a test, not shipped): how many BYTES each part of Calculate-RiskScore's row loop allocates per
    row (a profiled copy with lap marks, as bench.ps1 -Prof marks time). Test VM only.
#>
param([string]$SIRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), [int]$N = 3000)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function global:Write-Info { param($m) }
function global:Write-Warn2 { param($m) Write-Host "WARN: $m" }
function global:Write-Ok { param($m) }
function global:Write-Diag { param($m) }
. (Join-Path $PSScriptRoot 'RaPerfFixture.ps1')
foreach ($f in (Import-RaPerfEngine -SIRoot $SIRoot)) { . $f }
$global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
$global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
$global:SI_RA_ScoringThreads = 1
$idx = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
$cis = New-RaPerfCis
$rows = ConvertTo-PSObjectDeep (New-RaPerfRawRows -Count $N) -StripOData -CastPrimitiveArrays
$rows = @(Add-RACiContext -Rows @($rows) -FactorSet @() -Index (New-RACiIndex -Cis $cis))
$txt = ${function:Calculate-RiskScore}.ToString()
$marks = [ordered]@{
    '# RiskFactor_Consequence is derived dynamically' = 'A findvals'; '# Layer 3 -- business-criticality multiplier' = 'B bases+rf'
    '# Engine-level RiskFactor_*_Detailed token enrichment' = 'C copy+numeric'; '# M4 (V3-DATA-MODEL 2.21)' = 'D tokens/signals'
    '# ---- #559 RISK FACTOR MODEL V2: each factor ONCE' = 'E cimode'; '# ---- ONE safe-math call' = 'F findtok+measure'; '# Provenance: stamp ReportName' = 'G setscores'
    '# 2) Portal/security links removed' = 'H md harvest'; '# 3) MITRE links derived' = 'I cve links'; '# Dedupe (preserves order), cap at 25' = 'J mitre+portal'
    '# YAML''s OutputPropertyOrder is the SINGLE source' = 'K md cap + h'; '# Issues_Details collects per-row' = 'M grp'; '# Preserve YAML-computed aggregates' = 'N tmp2 copy'
    '# MITRE inference: priority order' = 'O summary/issue'; '# ComplianceTags inference: when YAML' = 'P mitre'; '# #590 HOW TO FIX' = 'Q compliance'
    '# #561 / #562 THE FINDING' = 'R fix'; '# NEW (v2.2.89): RiskScoreDomainKPI' = 'S dims'; '# STRICT mode -- when OutputPropertyOrder' = 'T kpi'; '# YAML OutputPropertyOrder is the LEADING' = 'U h2'
}
foreach ($k in $marks.Keys) { $i = $txt.IndexOf($k); if ($i -lt 0) { Write-Host "MARK NOT FOUND: $k"; continue }; $txt = $txt.Substring(0, $i) + ('[RaAlloc]::Mark(''' + $marks[$k] + '''); ') + $txt.Substring($i) }
$txt = $txt.Replace('        $done++' + "`n", '        $done++; [RaAlloc]::Mark(''Z loop tail'')' + "`n").Replace('        $done++' + "`r`n", '        $done++; [RaAlloc]::Mark(''Z loop tail'')' + "`r`n")
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic;
public static class RaAlloc {
    public static Dictionary<string,long> T = new Dictionary<string,long>(); static long _last = GC.GetAllocatedBytesForCurrentThread();
    public static void Reset() { T.Clear(); _last = GC.GetAllocatedBytesForCurrentThread(); }
    public static void Mark(string n) { long a = GC.GetAllocatedBytesForCurrentThread(); long d = a - _last; long v; T.TryGetValue(n, out v); T[n] = v + d; _last = GC.GetAllocatedBytesForCurrentThread(); }
}
'@
Set-Item -Path function:global:Calculate-RiskScoreProf -Value ([scriptblock]::Create($txt))
$pr = @($rows | ForEach-Object { $_.PSObject.Copy() })
[RaAlloc]::Reset()
$a0 = [GC]::GetAllocatedBytesForCurrentThread()
$null = Calculate-RiskScoreProf -Rows $pr -RiskIndex $idx -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Detailed'
$tot = [GC]::GetAllocatedBytesForCurrentThread() - $a0
Write-Host ("allocated {0:N0} KB per row in total over {1} rows" -f ($tot / 1KB / $pr.Count), $pr.Count)
foreach ($k in ([RaAlloc]::T.Keys | Sort-Object)) { Write-Host ("  lap {0,-22} {1,10:N1} KB/row" -f $k, ([RaAlloc]::T[$k] / 1KB / $pr.Count)) }
