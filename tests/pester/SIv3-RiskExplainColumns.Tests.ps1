#Requires -Version 7.0
<#
    THE EXPLAINED RISK SCORE -- the engine's four added columns (REQUIREMENTS #910, owner 2026-10-27: "build #910").

    Every scored row now also carries how its score was made:
      RiskConsequenceBase / RiskProbabilityBase       the asset side's and the vulnerability side's base (the risk index)
      RiskFactor_Consequence_Impacts / _Probability_  each counted factor with its impact, "Name=impact;Name=impact", in the
                                                      order of the _Detailed names; a factor a report gave as a number only
                                                      is "ReportFactor=<impact>" (after the named ones)
    This suite pins:
      1. Measure-RARowFactors returns each factor's impact beside its name (catalog, report-scoped, number-only factors).
      2. THE SCORE DOES NOT CHANGE. The engine edit is a set of text pairs (tests\fixtures\risk-explain\RiskExplainEdits.ps1);
         taken out of the current files they give the files as they were (a recorded hash). The same synthetic slice
         (tests\fixtures\ra-perf: conversion, filters, CI / Defender context, scoring, shaping, the SQL write) runs through
         both: every column that existed before is identical -- name, type, value, order -- in the scored rows, the
         shaped rows and every JSON item written to the database; only the four new columns are added. Also in the 'ci'
         data model and for Summary rows.
      3. THE INVARIANTS on every row: base + sum(impacts) = the side's score, the impacts name exactly the _Detailed
         factors in their order, asset side x vulnerability side = RiskScoreTotal.
      4. The owner's worked example: 4 + 3 + 4 + 3 + 3 = 17 on the asset side, 4 + 3 + 4 + 4 + 3 + 3 = 21 on the
         vulnerability side, 357; x 225 % = 803 weighted.
    Offline; PowerShell 7 (the v3 gate). Runs on the test VM only (never on mgmt1). Synthetic data only.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Fx = Join-Path $script:SIRoot 'tests\fixtures\ra-perf'
    function global:Write-Info { param($m) }
    function global:Write-Warn2 { param($m) }
    function global:Write-Ok { param($m) }
    function global:Write-Diag { param($m) }
    $ProgressPreference = 'SilentlyContinue'
    . (Join-Path $script:Fx 'RaPerfFixture.ps1')
    . (Join-Path $script:SIRoot 'tests\fixtures\risk-explain\RiskExplainEdits.ps1')
    foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Cis = New-RaPerfCis
    $script:Cols = Get-RiskExplainColumns
    $script:Ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    $script:Catalog = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\risk-factors.locked.json')) | ConvertFrom-Json
    $script:Map = New-RAFactorImpactMap -Catalog ([pscustomobject]@{ factors = @($script:Catalog.factors) })
    $script:Imp = @{}; foreach ($f in @($script:Catalog.factors)) { $script:Imp[[string]$f.shortName] = [int]$f.impact }

    # the files as they were before the edit: the current text with the pairs taken out (CRLF, UTF-8, no BOM)
    $script:BeforeHash = @{
        'RA-FactorKeys.ps1' = 'E967DEC2CB9F90F8F7D2C31DC943BC7C5610B66F6917692B481B7B9C271B44D2'
        'RA-RiskScore.ps1'  = 'A758DA44DA64D0A1B5721D02EC9FDD5B3E40C8B80811BE8F356C55618C651CA9'
    }
    $script:BeforeText = @{}
    foreach ($k in $script:BeforeHash.Keys) {
        $script:BeforeText[$k] = Invoke-RiskExplainEdit -Text ([IO.File]::ReadAllText((Join-Path $script:Ra $k))) -File $k -Reverse
    }

    function script:Get-ImpactSum([string]$Text) {
        $s = 0
        foreach ($e in ($Text -split ';')) { if ($e) { $s += [int]$e.Substring($e.LastIndexOf('=') + 1) } }
        $s
    }
    function script:Get-ImpactNames([string]$Text) { @(foreach ($e in ($Text -split ';')) { if ($e) { $e.Substring(0, $e.LastIndexOf('=')) } }) }
    function script:Remove-ExplainColumns($Row) {
        $o = [ordered]@{}
        foreach ($p in $Row.PSObject.Properties) { if ($p.Name -notin $script:Cols) { $o[$p.Name] = $p.Value } }
        [pscustomobject]$o
    }
    function script:Compare-Rows([object[]]$Old, [object[]]$New) {
        $d = New-Object System.Collections.Generic.List[string]
        if ($Old.Count -ne $New.Count) { $d.Add(('rows: {0} before, {1} now' -f $Old.Count, $New.Count)) }
        for ($i = 0; $i -lt [Math]::Min($Old.Count, $New.Count); $i++) {
            $a = Get-RaPerfRowText $Old[$i]; $b = Get-RaPerfRowText (Remove-ExplainColumns $New[$i])
            if ($a -cne $b) { $d.Add(("row {0}:`n  before {1}`n  now    {2}" -f $i, $a, $b)); if ($d.Count -ge 3) { break } }
        }
        , $d.ToArray()
    }
    # one JSON item written to the database, with the four columns taken out of its row document (DetailJson)
    function script:Remove-ExplainKeys($Node) {
        # walks the parsed document: the four columns leave every object; a row document held as text is opened, cleaned
        # and written back as text
        if ($Node -is [System.Collections.IDictionary]) {
            foreach ($c in $script:Cols) { if ($Node.Contains($c)) { $Node.Remove($c) } }
            foreach ($k in @($Node.Keys)) {
                $v = $Node[$k]
                if ($v -is [string] -and $v.StartsWith('{')) {
                    try { $d = $v | ConvertFrom-Json -AsHashtable -Depth 100 } catch { $d = $null }
                    if ($d -is [System.Collections.IDictionary]) { Remove-ExplainKeys $d; $Node[$k] = (Get-CanonText $d) }
                } elseif ($null -ne $v -and $v -isnot [string]) { Remove-ExplainKeys $v }
            }
        } elseif ($Node -is [System.Collections.IList]) { foreach ($e in $Node) { Remove-ExplainKeys $e } }
    }
    # canonical text of a parsed node: object keys in ordinal order (a parsed object's key order is not the document's)
    function script:Get-CanonText($Node) {
        if ($Node -is [System.Collections.IDictionary]) {
            $parts = foreach ($k in (@($Node.Keys) | Sort-Object { [string]$_ } -CaseSensitive)) { (ConvertTo-Json -InputObject ([string]$k) -Compress) + ':' + (Get-CanonText $Node[$k]) }
            return '{' + (@($parts) -join ',') + '}'
        }
        if ($Node -is [System.Collections.IList]) { return '[' + (@(foreach ($e in $Node) { Get-CanonText $e }) -join ',') + ']' }
        ConvertTo-Json -InputObject $Node -Compress
    }
    # every row item the SQL write sent, in order, with the four columns taken out of its row document -- one text per row
    # (the statements batch rows by size: a longer row may start a new batch, so batches are not compared, the rows are)
    function script:Get-ItemRows([string[]]$Items) {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($json in $Items) {
            $doc = $json | ConvertFrom-Json -AsHashtable -Depth 100 -NoEnumerate
            $rows = if ($doc -is [System.Collections.IList]) { $doc } else { , $doc }
            foreach ($r in $rows) { Remove-ExplainKeys $r; $out.Add((Get-CanonText $r)) }
        }
        , $out.ToArray()
    }
}

AfterAll { $global:SI_RA_ScoringThreads = $null; $global:SI_RA_ParallelMinRows = $null }

Describe '1. Measure-RARowFactors: each factor''s impact beside its name' {
    It 'catalog factors: "ShortName=impact" on their own side, in the order of the names; the sums are unchanged' {
        $r = Measure-RARowFactors -AssetTokens @('Internet-Exposed', 'ExploitSignals') -VulnerabilityTokens @('PortOpenInternet') -Map $script:Map
        $r.AssetTokens | Should -Be @('InternetExposed', 'PortOpenInternet')
        $r.AssetImpacts | Should -Be @("InternetExposed=$($script:Imp['InternetExposed'])", "PortOpenInternet=$($script:Imp['PortOpenInternet'])")
        $r.VulnerabilityImpacts | Should -Be @("ExploitAvailable=$($script:Imp['ExploitAvailable'])")
        (Get-ImpactSum ($r.AssetImpacts -join ';')) | Should -Be $r.AssetImpact
        (Get-ImpactSum ($r.VulnerabilityImpacts -join ';')) | Should -Be $r.VulnerabilityImpact
    }
    It 'one factor under several names: one entry' {
        $r = Measure-RARowFactors -AssetTokens @('RF_P_InternetExposed', 'InternetExposureSignal', 'internet_exposed', 'InternetExposed') -Map $script:Map
        $r.AssetImpacts | Should -Be @("InternetExposed=$($script:Imp['InternetExposed'])")
    }
    It 'a report''s own question shows as the report wrote it, with the report-scoped impact' {
        $r = Measure-RARowFactors -AssetTokens @('MultipleIPs') -VulnerabilityTokens @('DomainTakeoverPotential') -Map $script:Map
        $r.AssetImpacts | Should -Be @("MultipleIPs=$($script:Map.ReportScoped.Impact)")
        $r.VulnerabilityImpacts | Should -Be @("DomainTakeoverPotential=$($script:Map.ReportScoped.Impact)")
    }
    It 'a number-only report: one "ReportFactor=<impact>" per unnamed factor, after the named ones' {
        $r = Measure-RARowFactors -AssetTokens @('MultipleIPs') -UnnamedAssetCount 2 -Map $script:Map
        $i = [int]$script:Map.ReportScoped.Impact
        $r.AssetImpacts | Should -Be @("MultipleIPs=$i", "ReportFactor=$i", "ReportFactor=$i")
        (Get-ImpactSum ($r.AssetImpacts -join ';')) | Should -Be $r.AssetImpact
    }
    It 'nothing counted: empty lists' {
        $r = Measure-RARowFactors -Map $script:Map
        @($r.AssetImpacts).Count | Should -Be 0; @($r.VulnerabilityImpacts).Count | Should -Be 0
    }
}

Describe '2. the score does not change: every column that existed before is identical' {
    BeforeAll {
        # one core: a worker would load the CURRENT files from disk, and this compares the files before the edit too
        $global:SI_RA_ScoringThreads = 1; $global:SI_RA_ParallelMinRows = $null
        $scoreSum = { param($rows) @(Calculate-RiskScore -Rows $rows -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory `
                -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain `
                -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName 'Device_Missing_CVEs_Summary') }

        # BEFORE: the two files as they were (the pairs taken out), over the current engine
        foreach ($k in $script:BeforeText.Keys) {
            $root = $script:Ra.Replace("'", "''")
            . ([scriptblock]::Create($script:BeforeText[$k].Replace('$PSScriptRoot', "'$root'")))
        }
        $global:RA_FactorImpactMap = $null
        $script:Old = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 900) -Cis $script:Cis -RiskIndex $script:Index
        $script:OldCi = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 300 -Seed 7) -Cis $script:Cis -RiskIndex $script:Index -Mode ci
        $script:OldSum = & $scoreSum (New-RaPerfSummaryRows -Count 120)

        # NOW: the current files
        foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
        $global:RA_FactorImpactMap = $null
        $script:New = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 900) -Cis $script:Cis -RiskIndex $script:Index
        $script:NewCi = Invoke-RaPerfSlice -Raw (New-RaPerfRawRows -Count 300 -Seed 7) -Cis $script:Cis -RiskIndex $script:Index -Mode ci
        $script:NewSum = & $scoreSum (New-RaPerfSummaryRows -Count 120)
    }
    It 'taking the edit out gives the files exactly as they were before it (recorded hash)' {
        foreach ($k in $script:BeforeHash.Keys) {
            $h = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($script:BeforeText[$k])))
            $h | Should -Be $script:BeforeHash[$k] -Because "$k without the pairs must be the file before the explained score"
        }
    }
    It 'the slice is a real one (rows scored, CVEs) and the before-run has none of the four columns' {
        $script:Old.Scored.Count | Should -BeGreaterThan 800
        foreach ($c in $script:Cols) { $script:Old.Scored[0].PSObject.Properties[$c] | Should -BeNullOrEmpty }
        foreach ($c in $script:Cols) { $script:New.Scored[0].PSObject.Properties[$c] | Should -Not -BeNullOrEmpty }
    }
    It 'scored rows: identical apart from the four columns (every column, type, value, the order)' {
        Compare-Rows $script:Old.Scored $script:New.Scored | Should -BeNullOrEmpty
    }
    It 'shaped rows: identical apart from the four columns, which come last before the trace columns' {
        Compare-Rows $script:Old.Shaped $script:New.Shaped | Should -BeNullOrEmpty
    }
    It 'every JSON item written to the database: identical apart from the four columns in its row document' {
        $o = Get-ItemRows $script:Old.Items; $n = Get-ItemRows $script:New.Items
        $o.Count | Should -BeGreaterThan 800
        $n.Count | Should -Be $o.Count
        $bad = @(for ($i = 0; $i -lt $o.Count; $i++) { if ($n[$i] -cne $o[$i]) { "row $i`n  before $($o[$i])`n  now    $($n[$i])" } })
        ($bad | Select-Object -First 2) | Should -BeNullOrEmpty
        # and the four columns really reach the row document (sidata.Finding.DetailJson)
        $script:New.Items[0] | Should -Match 'RiskConsequenceBase'
        $script:New.Items[0] | Should -Match 'RiskFactor_Probability_Impacts'
    }
    It 'data model ci (the CI decides the asset factors): identical apart from the four columns' {
        Compare-Rows $script:OldCi.Scored $script:NewCi.Scored | Should -BeNullOrEmpty
    }
    It 'Summary rows: identical apart from the four columns' {
        $script:OldSum.Count | Should -BeGreaterThan 0
        Compare-Rows $script:OldSum $script:NewSum | Should -BeNullOrEmpty
    }
    It 'THE INVARIANTS on every row: base + impacts = side, the impacts name the _Detailed factors in order, side x side = score' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($script:New.Scored) + @($script:NewCi.Scored) + @($script:NewSum)) {
            $ci = [string]$r.RiskFactor_Consequence_Impacts; $pi = [string]$r.RiskFactor_Probability_Impacts
            if ([double]$r.RiskConsequenceBase + (Get-ImpactSum $ci) -ne [double]$r.RiskConsequenceScore) { $bad.Add("asset side: $($r.RiskConsequenceBase) + $ci <> $($r.RiskConsequenceScore)") }
            if ([double]$r.RiskProbabilityBase + (Get-ImpactSum $pi) -ne [double]$r.RiskProbabilityScore) { $bad.Add("vulnerability side: $($r.RiskProbabilityBase) + $pi <> $($r.RiskProbabilityScore)") }
            if ((Get-ImpactSum $ci) -ne [int]$r.RiskFactor_Consequence -or (Get-ImpactSum $pi) -ne [int]$r.RiskFactor_Probability) { $bad.Add("impact sums <> RiskFactor_* ($ci / $pi)") }
            $dn = @(([string]$r.RiskFactor_Consequence_Detailed -split ';') | Where-Object { $_ })
            $in = @(Get-ImpactNames $ci)
            if (($in[0..([Math]::Max(0, $dn.Count - 1))] -join ';') -cne ($dn -join ';') -and $dn.Count) { $bad.Add("asset names: $($dn -join ';') vs $ci") }
            if (@($in | Select-Object -Skip $dn.Count | Where-Object { $_ -ne 'ReportFactor' }).Count) { $bad.Add("asset extras: $ci") }
            $dp = @(([string]$r.RiskFactor_Probability_Detailed -split ';') | Where-Object { $_ })
            if ((@(Get-ImpactNames $pi) -join ';') -cne ($dp -join ';')) { $bad.Add("vulnerability names: $($dp -join ';') vs $pi") }
            if ([double]$r.RiskConsequenceScore * [double]$r.RiskProbabilityScore -ne [double]$r.RiskScoreTotal) { $bad.Add("product: $($r.RiskConsequenceScore) x $($r.RiskProbabilityScore) <> $($r.RiskScoreTotal)") }
            if ($bad.Count -ge 5) { break }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'the slice really exercises factors on both sides (not only empty lists)' {
        @($script:New.Scored | Where-Object { $_.RiskFactor_Consequence_Impacts }).Count | Should -BeGreaterThan 0
        @($script:New.Scored | Where-Object { $_.RiskFactor_Probability_Impacts }).Count | Should -BeGreaterThan 0
    }
}

Describe '3. the owner''s worked example' {
    It '(4 + HighMachineRisk 3 + InternetExposed 4 + ConfidentialData 3 + HighMsCriticality 3) x (4 + ExploitAvailable 3 + RCE 4 + KnownExploited 4 + NetworkNoUserAction 3 + OldVuln 3) = 17 x 21 = 357; x 225 % = 803' {
        $r = Measure-RARowFactors -AssetTokens @('HighMachineRisk', 'InternetExposed', 'ConfidentialData', 'HighMsCriticality') `
            -VulnerabilityTokens @('ExploitAvailable', 'RCE', 'KnownExploited', 'NetworkNoUserAction', 'OldVuln') -Map $script:Map
        ($r.AssetImpacts -join ';') | Should -Be 'HighMachineRisk=3;InternetExposed=4;ConfidentialData=3;HighMsCriticality=3'
        ($r.VulnerabilityImpacts -join ';') | Should -Be 'ExploitAvailable=3;RCE=4;KnownExploited=4;NetworkNoUserAction=3;OldVuln=3'
        $a = 4 + $r.AssetImpact; $v = 4 + $r.VulnerabilityImpact
        $a | Should -Be 17; $v | Should -Be 21; ($a * $v) | Should -Be 357
        [int][math]::Floor([double]($a * $v) * 225 / 100.0) | Should -Be 803
    }
}
