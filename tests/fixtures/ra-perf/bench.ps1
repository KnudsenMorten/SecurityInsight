param([string]$SIRoot = (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), [int]$N = 5000, [switch]$Before, [switch]$Compare, [int]$Micro = 0, [switch]$Prof, [int]$Repeat = 1)
# Vendor bench (not a test): times one synthetic slice through the current code; -Before: through the code as it was;
# -Compare: both, and every output compared.
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
$idx = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
$cis = New-RaPerfCis
Write-Host ("pwsh {0}  N={1}" -f $PSVersionTable.PSVersion, $N)
function Show($label, $res) {
    foreach ($k in $res.Times.Keys) { Write-Host ("{0,-7} {1,-12} {2,9:N2}s {3,10:N0} rows/s  ({4} rows)" -f $label, $k, $res.Times[$k], ($res.Rows[$k] / [Math]::Max(0.0001, $res.Times[$k])), $res.Rows[$k]) }
}
$old = $null; $new = $null
if ($Before -or $Compare) {
    foreach ($sb in (Get-RaPerfBeforeScripts -SIRoot $SIRoot)) { . $sb }
    $old = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count $N) -Cis $cis -RiskIndex $idx
    Show 'BEFORE' $old
    foreach ($f in (Import-RaPerfEngine -SIRoot $SIRoot)) { . $f }
}
if (-not $Before -or $Compare) {
    for ($rep = 1; $rep -le $Repeat; $rep++) {
        $new = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count $N) -Cis $cis -RiskIndex $idx
        Show ('AFTER' + $(if ($Repeat -gt 1) { $rep } else { '' })) $new
    }
}
if ($Micro -and $new) {
    $m = @($new.Context | Select-Object -First $Micro)
    function MicroT([string]$Name, [scriptblock]$Sb) { $sw = [Diagnostics.Stopwatch]::StartNew(); foreach ($r in $m) { . $Sb }; $sw.Stop(); Write-Host ("  micro {0,-36} {1,8:N3} ms/row" -f $Name, ($sw.Elapsed.TotalMilliseconds / $m.Count)) }
    $plan = New-RAFindingFactorPlan -Factors $script:RAFindingFactorList
    $ciIdx1 = New-RACiIndex -Cis $cis
    MicroT 'Get-SIRiskIndexFindingValues' { $null = Get-SIRiskIndexFindingValues -Row $r -DomainValue 'Endpoint' }
    $iv = Get-SIRiskIndexFindingValues -Row $m[0] -DomainValue 'Endpoint'
    MicroT 'Get-SIRiskIndexSiScore x2' { $null = Get-SIRiskIndexSiScore -Index $idx -Kind Asset -Values $iv.Asset; $null = Get-SIRiskIndexSiScore -Index $idx -Kind Vulnerability -Values $iv.Vulnerability }
    MicroT 'Get-RAFindingFactorPlanKey' { $null = Get-RAFindingFactorPlanKey -Row $r -Plan $plan }
    MicroT 'Get-RAFindingFactorTokens -Plan' { $null = Get-RAFindingFactorTokens -Row $r -Plan $plan }
    MicroT 'Measure-RARowFactors' { $null = Measure-RARowFactors -AssetTokens @('InternetExposed', 'ExploitSignals') -VulnerabilityTokens @('RemoteCodeExecutionRisk') -UnnamedAssetCount 0 }
    MicroT 'copy row to ordered' { $h = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    MicroT 'Set-SIRaRowDimensions' { $h = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }; $null = Set-SIRaRowDimensions -Row $h }
    MicroT 'ConvertTo-SIFindingClassificationItem' { $null = ConvertTo-SIFindingClassificationItem -Row $r }
    MicroT 'pscustomobject from ordered' { $h = [ordered]@{}; foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value }; $null = [pscustomobject]$h }
    MicroT 'Calculate-RiskScore 1 row' { $null = Calculate-RiskScore -Rows @($r) -RiskIndex $idx -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Detailed' }
    MicroT 'Add-RACiContext 1 row' { $null = Add-RACiContext -Rows @($r.PSObject.Copy()) -FactorSet @() -Index (New-RACiIndex -Cis @($cis[0])) }
    MicroT 'Find-RACiForRow' { $null = Find-RACiForRow -Row $r -Index $ciIdx1 }
    $m = @($new.Shaped | Select-Object -First $Micro)
    $dc = New-Object 'System.Collections.Generic.HashSet[string]'
    MicroT 'ConvertTo-RAStreamJson' { $null = ConvertTo-RAStreamJson -Row $r -DateCols $dc }
    MicroT 'Get-RARowDedupKey' { $null = Get-RARowDedupKey -Row $r -ConfigurationIdInputName ConfigurationId }
    MicroT 'Get-RAStreamTraceInfo' { $null = Get-RAStreamTraceInfo -Row $r -IsDetailed $true }
    MicroT 'Get-SIFindingGroupKey' { $null = Get-SIFindingGroupKey -Row $r -Equivalence $null }
    $nar = [pscustomobject]@{ SI_AssetId = 'a'; AssetName = 'n'; ReportName = 'Device_Missing_CVEs_Detailed'; SecurityDomain = 'Endpoint'; ConfigurationId = 'CVE-2020-1'; Cve = 'CVE-2020-1'; Title = 't'; Severity = 'High'; Tier = '1'; SourceTier = ''; IsPath = $false; RiskScore = '12'; ExemptionId = ''; ExemptedUntil = ''; ExemptionRequestId = ''; DetailJson = '{"x":"y"}' }
    MicroT 'Get-SIDataRowTiers' { $null = Get-SIDataRowTiers -Row $nar }
    MicroT 'ConvertTo-SIDataFindingJson' { $null = ConvertTo-SIDataFindingJson -Row $nar -KeyOf @{} }
    MicroT 'Join-RAStreamJson' { $null = Join-RAStreamJson -Json '{"a":1}' -Extra ([ordered]@{ RaReport = 1; RaBucket = '9/24'; RaDedup = 'ab'; RaSort = 1.5; RaInView = $true; RaTraceHash = 'cd'; RaTraceKey = 'k'; RaTraceSuffixed = $false; RaSeq = 5; RaFindingKey = 'x'; RaAssetId = 'a'; RaAssetTier = 1 }) }
    MicroT 'Select-Object 1 row' { $null = $r | Select-Object -Property @($r.PSObject.Properties.Name) }
}
if ($Prof -and $new) {
    # a profiled copy of Calculate-RiskScore: lap marks inserted before known statements (vendor bench only)
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
    foreach ($k in $marks.Keys) { $i = $txt.IndexOf($k); if ($i -lt 0) { Write-Host "MARK NOT FOUND: $k"; continue }; $txt = $txt.Substring(0, $i) + ('$global:__L.Mark(''' + $marks[$k] + '''); ') + $txt.Substring($i) }
    $txt = $txt.Replace('        $done++' + "`n", '        $done++; $global:__L.Mark(''Z loop tail'')' + "`n").Replace('        $done++' + "`r`n", '        $done++; $global:__L.Mark(''Z loop tail'')' + "`r`n")
    Set-Item -Path function:global:Calculate-RiskScoreProf -Value ([scriptblock]::Create($txt))
    $global:__L = [pscustomobject]@{ sw = [Diagnostics.Stopwatch]::StartNew(); t = [ordered]@{} }
    $global:__L | Add-Member -MemberType ScriptMethod -Name Mark -Value { param($n) $e = $this.sw.Elapsed.TotalMilliseconds; $this.sw.Restart(); $this.t[$n] = [double]$this.t[$n] + $e }
    $pr = @($new.Context | ForEach-Object { $_.PSObject.Copy() })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $null = Calculate-RiskScoreProf -Rows $pr -RiskIndex $idx -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Detailed'
    Write-Host ("profiled scoring {0:N2}s over {1} rows" -f $sw.Elapsed.TotalSeconds, $pr.Count)
    foreach ($k in ($global:__L.t.Keys | Sort-Object)) { Write-Host ("  lap {0,-22} {1,8:N3} ms/row" -f $k, ($global:__L.t[$k] / $pr.Count)) }
}
if ($Compare) {
    $bad = 0
    if ($old.Scored.Count -ne $new.Scored.Count) { Write-Host "scored count differs: $($old.Scored.Count) vs $($new.Scored.Count)"; $bad++ }
    for ($i = 0; $i -lt [Math]::Min($old.Scored.Count, $new.Scored.Count); $i++) {
        $a = Get-RaPerfRowText $old.Scored[$i]; $b = Get-RaPerfRowText $new.Scored[$i]
        if ($a -cne $b) { if ($bad -lt 3) { Write-Host "scored row $i differs:`n OLD $a`n NEW $b" }; $bad++ }
    }
    for ($i = 0; $i -lt [Math]::Min($old.Shaped.Count, $new.Shaped.Count); $i++) {
        $a = Get-RaPerfRowText $old.Shaped[$i]; $b = Get-RaPerfRowText $new.Shaped[$i]
        if ($a -cne $b) { if ($bad -lt 6) { Write-Host "shaped row $i differs:`n OLD $a`n NEW $b" }; $bad++ }
    }
    $oi = $old.Items -join "`n"; $ni = $new.Items -join "`n"
    if ($oi -cne $ni) { Write-Host ("sql items differ (lengths {0} / {1})" -f $oi.Length, $ni.Length); $bad++ }
    Write-Host ("COMPARE: {0} difference(s); scored {1}, shaped {2}, sql statements {3}" -f $bad, $new.Scored.Count, $new.Shaped.Count, $new.Items.Count)
}
