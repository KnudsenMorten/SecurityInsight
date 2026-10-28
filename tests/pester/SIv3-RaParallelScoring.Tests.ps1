#Requires -Version 7.0
<#
    RISK ANALYSIS SCORES A SLICE ON SEVERAL CORES BY DEFAULT -- AND THE RESULT IS THE ONE-CORE RESULT, ROW BY ROW.

    Measured in production 2026-10-16 (a customer, 4 CPU / 8 GiB Detailed job): per query slice of ~14-22k rows the risk
    scoring took 70-125 s on one core -- the largest step; a 64-slice report spent 1.5-2 h scoring. The several-core step
    (engine\risk-analysis\_shared\RA-ParallelScore.ps1) existed but was OFF since 2026-10-14 (a live run reported hung; the
    run log showed later the silence was the Defender catalogue read before scoring, REQUIREMENTS #666). This suite pins:

      1. EQUIVALENCE on a slice shaped like Device_Missing_CVEs_Detailed (16,000 rows, the messy shapes real answers carry,
         plus rows with Impact 12.5 and weight 137.5): the scored rows on ONE core and on FOUR are identical -- every row,
         in order, every column, its type and value (the score, every factor / score column) -- in en-US AND in da-DK
         (a comma-decimal culture must never turn 12.5 into 125: both cultures give the same rows as en-US on one core),
         and the rows' stored form (the JSON for sidata.Finding) is identical too.
      2. ON BY DEFAULT: unset = the cores the process has; the slice says how many cores scored it and how long it took;
         1 / off (setting or environment SI_RA_SCORINGTHREADS) = one core, and the line says why; Summary = one core.
      3. A worker gets no script block / delegate from the run's globals (bound to the MAIN runspace: called in a worker it
         runs against the main runspace's variables from another thread) and works in the main thread's culture.
    Offline; PowerShell 7. Test VM only (never mgmt1).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Fx = Join-Path $script:SIRoot 'tests\fixtures\ra-perf'
    $global:RaPsSaid = [System.Collections.Generic.List[string]]::new()
    function global:Write-Info { param($m) $global:RaPsSaid.Add([string]$m) }
    function global:Write-Warn2 { param($m) $global:RaPsSaid.Add('WARN: ' + [string]$m) }
    function global:Write-Ok { param($m) }
    function global:Write-Diag { param($m) }
    $ProgressPreference = 'SilentlyContinue'
    . (Join-Path $script:Fx 'RaPerfFixture.ps1')
    foreach ($f in (Import-RaPerfEngine -SIRoot $script:SIRoot)) { . $f }
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $global:SI_SPN_TenantId = '00000000-0000-0000-0000-000000000001'
    $global:SI_RA_ScoringThreads = $null; $global:SI_RA_ParallelMinRows = $null
    $script:EnvBefore = $env:SI_RA_SCORINGTHREADS; $env:SI_RA_SCORINGTHREADS = $null
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Cis = New-RaPerfCis
    $script:CultureBefore = [System.Globalization.CultureInfo]::CurrentCulture

    function script:Get-RaPsRowText {
        <# One row: every column in order -- name, type and invariant value (lists item by item). Inline, fast enough for 16k rows. #>
        param($Row)
        $sb = [System.Text.StringBuilder]::new()
        foreach ($p in $Row.PSObject.Properties) {
            $v = $p.Value
            [void]$sb.Append($p.Name).Append('=')
            if ($null -eq $v) { [void]$sb.Append('~') }
            elseif ($v -is [string]) { [void]$sb.Append('s:').Append($v) }
            elseif ($v -is [double]) { [void]$sb.Append('d:').Append($v.ToString('R', [cultureinfo]::InvariantCulture)) }
            elseif ($v -is [System.Collections.IEnumerable] -and $v -isnot [System.Collections.IDictionary]) { [void]$sb.Append((Get-RaPerfValueText $v)) }
            elseif ($v -is [System.IFormattable]) { [void]$sb.Append($v.GetType().Name).Append(':').Append($v.ToString($null, [cultureinfo]::InvariantCulture)) }
            else { [void]$sb.Append((Get-RaPerfValueText $v)) }
            [void]$sb.Append([char]31)
        }
        $sb.ToString()
    }
    function script:Compare-RaPsRows([object[]]$A, [object[]]$B) {
        $d = [System.Collections.Generic.List[string]]::new()
        if ($A.Count -ne $B.Count) { $d.Add(('rows: {0} on one core, {1} now' -f $A.Count, $B.Count)) }
        for ($i = 0; $i -lt [Math]::Min($A.Count, $B.Count); $i++) {
            $x = Get-RaPsRowText $A[$i]; $y = Get-RaPsRowText $B[$i]
            if ($x -cne $y) { $d.Add(("row {0}:`n  one core {1}`n  now      {2}" -f $i, $x, $y)); if ($d.Count -ge 3) { break } }
        }
        , $d.ToArray()
    }
    function script:Invoke-RaPsScore([object[]]$Rows, $Threads, [string]$Culture, [string]$ReportName = 'Device_Missing_CVEs_Detailed') {
        $global:SI_RA_ScoringThreads = $Threads
        [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($Culture)
        $global:RaPsSaid.Clear()
        try {
            $copy = @(foreach ($r in $Rows) { $r.PSObject.Copy() })
            $out = @(Calculate-RiskScore -Rows $copy -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory `
                    -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel `
                    -SecurityDomainInputName SecurityDomain -OutputPropertyOrder (Get-RaPerfOutputOrder) -SortBy @('RiskScoreTotal_Weighted') -Descending -ReportName $ReportName)
            [pscustomobject]@{ Rows = $out; Said = $global:RaPsSaid.ToArray() }
        } finally { [System.Globalization.CultureInfo]::CurrentCulture = $script:CultureBefore; $global:SI_RA_ScoringThreads = $null }
    }
    function script:Invoke-RaPsItems([object[]]$Rows, $Threads, [string]$Culture) {
        $global:SI_RA_ScoringThreads = $Threads
        [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($Culture)
        $global:RaPsSaid.Clear()
        try {
            $ctx = @{ Grain = 'Detailed'; Ordinal = 1; Bucket = '9/24'; IsDetailedShape = $true; ConfigurationIdInputName = 'ConfigurationId'; SortColumn = 'RiskScoreTotal_Weighted'
                      FallbackSortColumn = 'RiskScoreTotal'; Dedup = $true; Equivalence = $null }
            $inv = [bool[]]::new($Rows.Count); for ($i = 0; $i -lt $Rows.Count; $i += 3) { $inv[$i] = $true }
            $dc = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $b = Invoke-RAParallelStreamItems -Rows $Rows -FirstSeq 101 -InView $inv -Context $ctx -DateCols $dc
            $how = 'several'
            if ($null -eq $b) { $how = 'one'; $b = ConvertTo-RAStreamRowItems -Rows $Rows -FirstSeq 101 -InView $inv -Context $ctx -DateCols $dc }
            [pscustomobject]@{ Items = [string[]]$b.Items; Assets = [string[]]$b.AssetItems; Illegal = [long]$b.Illegal; DateCols = (@($dc) | Sort-Object) -join ','; How = $how; Said = $global:RaPsSaid.ToArray() }
        } finally { [System.Globalization.CultureInfo]::CurrentCulture = $script:CultureBefore; $global:SI_RA_ScoringThreads = $null }
    }
}

AfterAll {
    [System.Globalization.CultureInfo]::CurrentCulture = $script:CultureBefore
    $global:SI_RA_ScoringThreads = $null; $global:SI_RA_ParallelMinRows = $null; $env:SI_RA_SCORINGTHREADS = $script:EnvBefore
    Remove-Variable -Name RaPsPlanted, RaPsPlantedFn -Scope Global -ErrorAction SilentlyContinue
    function global:Write-Info { param($m) }
    function global:Write-Warn2 { param($m) }
}

Describe '1. 16,000 rows shaped like Device_Missing_CVEs_Detailed: one core and four cores give the same rows (en-US and da-DK)' {
    BeforeAll {
        # the slice: the report's columns, the messy shapes (null / empty cells, lists in cells, very long text, no tier,
        # 13,750 / 137.5 weights, no finding key), and a decimal a comma culture could misread (Impact 12.5)
        $raw = New-RaPerfRawRows -Count 16000 -Messy
        $script:Decimal = 0
        for ($i = 5; $i -lt $raw.Count; $i += 97) { $raw[$i]['Impact'] = [double]12.5; $raw[$i]['RiskScore_Weight_Factor'] = [double]137.5; $script:Decimal++ }
        $rows = ConvertTo-PSObjectDeep $raw -StripOData -CastPrimitiveArrays
        $rows = Add-RACiContext -Rows @($rows) -FactorSet @() -Index (New-RACiIndex -Cis $script:Cis)
        $cveIx = @{}; foreach ($r in $rows) { $k = ([string]$r.ConfigurationId).ToUpperInvariant(); if ($k -and -not $cveIx.ContainsKey($k) -and ($k.Length % 3 -eq 0)) { $cveIx[$k] = [ordered]@{ si_exploit_verified = $true; si_in_exploit_kit = $false; si_exploit_types = 'Remote'; si_exposed_devices = 3 } } }
        $rows = Add-RADefenderCveContext -Rows @($rows) -Index @{ Index = $cveIx; Complete = $true } -Log { param($m) }
        $script:Input = @($rows)

        $global:SI_RA_ParallelMinRows = $null
        # warm: the workers are made once per process (the engine makes them once per run)
        $null = Invoke-RaPsScore -Rows @($script:Input | Select-Object -First 2500) -Threads 4 -Culture 'en-US'
        $script:SerialEn = Invoke-RaPsScore -Rows $script:Input -Threads 1 -Culture 'en-US'
        $script:ParEn = Invoke-RaPsScore -Rows $script:Input -Threads 4 -Culture 'en-US'
        $script:ParDa = Invoke-RaPsScore -Rows $script:Input -Threads 4 -Culture 'da-DK'
        # the stored form: the first 6,000 scored rows (every decimal row is among them; the step is the same per row)
        $script:ItemRows = @($script:SerialEn.Rows | Select-Object -First 6000)
        $script:ItemsSerial = Invoke-RaPsItems -Rows $script:ItemRows -Threads 1 -Culture 'en-US'
        $script:ItemsPar = Invoke-RaPsItems -Rows $script:ItemRows -Threads 4 -Culture 'en-US'
        $script:ItemsParDa = Invoke-RaPsItems -Rows $script:ItemRows -Threads 4 -Culture 'da-DK'
    }
    It 'the slice is the report''s size and shape: 16,000 rows scored, CVE findings, the decimal rows present' {
        $script:SerialEn.Rows.Count | Should -BeGreaterThan 15000
        $script:Decimal | Should -BeGreaterThan 100
        @($script:SerialEn.Rows | Where-Object { [string]$_.ConfigurationId -like 'CVE-*' }).Count | Should -BeGreaterThan 14000
    }
    It 'four cores really scored it (the slice says so; no fall-back to one core was said)' {
        ($script:ParEn.Said -join "`n") | Should -Match 'risk scores of \d{2},\d{3} row\(s\) worked out on 4 processor cores in \d+\.\d s'
        ($script:ParEn.Said -join "`n") | Should -Not -Match 'WARN'
        ($script:ParDa.Said -join "`n") | Should -Match 'worked out on 4 processor cores'
        ($script:SerialEn.Said -join "`n") | Should -Match 'worked out on one processor core in \d+\.\d s \(SI_RA_ScoringThreads = 1\)'
    }
    It 'en-US: four cores = one core -- every row, in order, every column, type and value' {
        Compare-RaPsRows $script:SerialEn.Rows $script:ParEn.Rows | Should -BeNullOrEmpty
    }
    It 'da-DK: four cores in da-DK = one core in en-US (a comma-decimal culture changes nothing)' {
        Compare-RaPsRows $script:SerialEn.Rows $script:ParDa.Rows | Should -BeNullOrEmpty
    }
    It 'every score and factor column is a value (not one empty), and 12.5 stays 12.5 on four cores in da-DK' {
        foreach ($c in 'RiskConsequenceScore', 'RiskProbabilityScore', 'RiskScoreTotal', 'RiskScoreTotal_Weighted', 'RiskRating', 'RiskFactor_Consequence', 'RiskFactor_Probability') {
            @($script:ParDa.Rows | Where-Object { $null -eq $_.$c -or [string]$_.$c -eq '' }).Count | Should -Be 0 -Because "$c is filled on every row"
        }
        $dec = @($script:ParDa.Rows | Where-Object { $_.RiskScore_Weight_Factor -is [double] -and $_.RiskScore_Weight_Factor -eq 137.5 })
        $dec.Count | Should -BeGreaterThan 0
        @($script:ParDa.Rows | Where-Object { $_.Impact -is [double] -and $_.Impact -eq 12.5 }).Count | Should -BeGreaterThan 0
        @($script:ParDa.Rows | Where-Object { $_.Impact -is [double] -and $_.Impact -eq 125 }).Count | Should -Be 0
    }
    It 'the stored form (the JSON for sidata.Finding, write order, keys, date columns): four cores = one core, also in da-DK' {
        $script:ItemsSerial.How | Should -Be 'one'
        $script:ItemsPar.How | Should -Be 'several'
        $script:ItemsParDa.How | Should -Be 'several'
        $script:ItemsPar.Items.Count | Should -Be $script:ItemsSerial.Items.Count
        ($script:ItemsPar.Items -join "`n") | Should -BeExactly ($script:ItemsSerial.Items -join "`n")
        ($script:ItemsParDa.Items -join "`n") | Should -BeExactly ($script:ItemsSerial.Items -join "`n")
        $script:ItemsPar.DateCols | Should -Be $script:ItemsSerial.DateCols
        $script:ItemsPar.Illegal | Should -Be $script:ItemsSerial.Illegal
        ($script:ItemsPar.Said -join "`n") | Should -Match 'prepared for the database: \d,\d{3} row\(s\) on 4 processor cores'
        # the decimal as stored: 12.5, never 12,5 or 125 (the row's JSON may sit inside another JSON text: \" quotes)
        @($script:ItemsParDa.Items | Where-Object { $_ -match 'Impact\\*"\s*:\s*\\*"?12\.5(?![0-9])' }).Count | Should -BeGreaterThan 0
        @($script:ItemsParDa.Items | Where-Object { $_ -match 'Impact\\*"\s*:\s*\\*"?(125(?![0-9.])|12,5)' }).Count | Should -Be 0
    }
}

Describe '2. on by default, a setting / environment variable to switch it off, and the line every slice says' {
    It 'unset = the cores the process has; 1 / 0 / off = one core; a number never above the cores; the setting before the environment' {
        Get-RAScoringThreads -Setting $null -Cores 4 -EnvValue '' | Should -Be 4
        Get-RAScoringThreads -Setting '' -Cores 1 -EnvValue '' | Should -Be 1
        foreach ($off in '1', '0', 'off', 'OFF', 'false', 'no', 'disabled') { Get-RAScoringThreads -Setting $off -Cores 4 -EnvValue '' | Should -Be 1 -Because "'$off' switches it off" }
        Get-RAScoringThreads -Setting '8' -Cores 4 -EnvValue '' | Should -Be 4
        Get-RAScoringThreads -Setting $null -Cores 4 -EnvValue 'off' | Should -Be 1 -Because 'the environment variable switches a job off without a configuration change'
        Get-RAScoringThreads -Setting $null -Cores 4 -EnvValue '2' | Should -Be 2
        Get-RAScoringThreads -Setting '3' -Cores 4 -EnvValue 'off' | Should -Be 3 -Because 'the setting wins over the environment'
        Get-RAScoringThreads -Setting 'nonsense' -Cores 4 -EnvValue '' | Should -Be 4 -Because 'a value that is not a number or off leaves the default'
    }
    It 'WIRING: with nothing set, a Detailed slice of 2,100 rows is scored on more than one core (this host has several)' -Skip:([Environment]::ProcessorCount -lt 2) {
        $global:SI_RA_ScoringThreads = $null; $env:SI_RA_SCORINGTHREADS = $null; $global:RaPsSaid.Clear()
        $rows = @(foreach ($r in (ConvertTo-PSObjectDeep (New-RaPerfRawRows -Count 2100 -Seed 5) -StripOData -CastPrimitiveArrays)) { $r })
        $null = Calculate-RiskScore -Rows $rows -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -OutputPropertyOrder (Get-RaPerfOutputOrder) -ReportName 'Device_Missing_CVEs_Detailed'
        $line = @($global:RaPsSaid | Where-Object { $_ -like 'risk scores of*' })
        $line.Count | Should -Be 1
        $line[0] | Should -Match ('worked out on {0} processor cores' -f [Environment]::ProcessorCount)
    }
    It 'switched off by the environment variable: one core, and the line says why' {
        $env:SI_RA_SCORINGTHREADS = 'off'; $global:RaPsSaid.Clear()
        try {
            $rows = @(foreach ($r in (ConvertTo-PSObjectDeep (New-RaPerfRawRows -Count 2100 -Seed 6) -StripOData -CastPrimitiveArrays)) { $r })
            $null = Calculate-RiskScore -Rows $rows -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -OutputPropertyOrder (Get-RaPerfOutputOrder) -ReportName 'Device_Missing_CVEs_Detailed'
        } finally { $env:SI_RA_SCORINGTHREADS = $null }
        @($global:RaPsSaid | Where-Object { $_ -like 'risk scores of*' })[0] | Should -Match 'on one processor core in .* \((SI_RA_ScoringThreads = 1|this machine has one core)\)'
    }
    It 'a Summary report is scored on one core and says why; a small slice says the minimum' {
        $global:RaPsSaid.Clear()
        $null = Calculate-RiskScore -Rows (New-RaPerfSummaryRows -Count 60) -RiskIndex $script:Index -SecurityDomain 'Endpoint' -CategoryInputName Category -SubCategoryInputName Subcategory `
            -ConfigurationIdInputName ConfigurationId -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -OutputPropertyOrder (Get-RaPerfOutputOrder) -ReportName 'Device_Missing_CVEs_Summary'
        @($global:RaPsSaid | Where-Object { $_ -like 'risk scores of*' })[0] | Should -Match 'one processor core .*Summary report'
        Get-RAOneCoreReason -Count 100 -Summary $false | Should -Match 'fewer than 2,000 rows'
    }
    It 'the line is the same in every culture (16,000 not 16.000; 3.2 s not 3,2 s)' {
        [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
        try { Format-RAScoringLine -Rows 16000 -Cores 4 -Seconds 3.24 | Should -BeExactly 'risk scores of 16,000 row(s) worked out on 4 processor cores in 3.2 s' }
        finally { [System.Globalization.CultureInfo]::CurrentCulture = $script:CultureBefore }
        Format-RAScoringLine -Rows 10 -Cores 1 -Seconds 0.04 -Why 'x' | Should -BeExactly 'risk scores of 10 row(s) worked out on one processor core in 0.0 s (x)'
    }
}

Describe '3. what a worker is handed' {
    It 'never a script block or a delegate; anything else is' {
        Test-RAParallelHandOver { 'x' } | Should -BeFalse
        Test-RAParallelHandOver ([Func[int]] { 1 }) | Should -BeFalse
        Test-RAParallelHandOver ([psobject]{ 'x' }) | Should -BeFalse
        Test-RAParallelHandOver 'text' | Should -BeTrue
        Test-RAParallelHandOver @{ a = 1 } | Should -BeTrue
        Test-RAParallelHandOver $null | Should -BeTrue
    }
    It 'a planted global script block / delegate does not reach a worker; a plain global does; the worker works in the main thread''s culture' {
        $global:RaPsPlanted = { 'main' }; $global:RaPsPlantedFn = [Func[int]] { 1 }; $global:RaPsPlain = 'plain'
        [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
        try {
            $probe = @'
param($X)
if ($global:RA_ParallelCulture) { [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0]) }
[pscustomobject]@{ X = $X; Sb = [bool](Get-Variable -Name RaPsPlanted -Scope Global -ValueOnly -ErrorAction SilentlyContinue); Fn = [bool](Get-Variable -Name RaPsPlantedFn -Scope Global -ValueOnly -ErrorAction SilentlyContinue)
    Plain = [string]$global:RaPsPlain; Culture = [System.Globalization.CultureInfo]::CurrentCulture.Name; Worker = [bool]$global:RA_ParallelWorker }
'@
            # a worker kept from an earlier part may still hold one from before: clear it there first (as a fresh run has none)
            foreach ($w in (Get-RAParallelWorkers -Count 2)) { $w.SessionStateProxy.SetVariable('RaPsPlanted', $null); $w.SessionStateProxy.SetVariable('RaPsPlantedFn', $null) }
            [object[]]$pa = @(@(1), @(2))
            $r = Invoke-RAParallelParts -Script $probe -PartArgs $pa
        } finally { [System.Globalization.CultureInfo]::CurrentCulture = $script:CultureBefore; Remove-Variable -Name RaPsPlanted, RaPsPlantedFn, RaPsPlain -Scope Global -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 2
        foreach ($x in $r) {
            $x.Sb | Should -BeFalse; $x.Fn | Should -BeFalse
            $x.Plain | Should -Be 'plain'
            $x.Culture | Should -Be 'da-DK'
            $x.Worker | Should -BeTrue
        }
    }
}
