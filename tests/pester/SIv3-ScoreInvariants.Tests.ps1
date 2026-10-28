#Requires -Version 5.1
<#
    RISK SCORE INVARIANTS (owner 2026-10-10: "risk score validated by INVARIANT TESTS") -- re-baselined to the RISK FACTOR
    MODEL V2 (REQUIREMENTS #559, owner 2026-10-10: "(5+5) x (5+4) = 90", "Sum, no cap").

    Properties every score must keep, checked over the shipped risk index (keyed by the SI fields), the scoring function
    (Calculate-RiskScore, with the CI context of RA-CiContext.ps1 in front of it) and the locked report catalog -- not over
    a few hand-picked rows. The documented model (docs/DESIGN.md, "Risk-score model"):

        asset side         = AssetBase(finding x asset class x tier)        + SUM(enabled asset factors' impacts)    no cap
        vulnerability side = VulnerabilityBase(finding type/cat/sub/severity) + SUM(enabled finding factors' impacts)  no cap
        RiskScoreTotal = asset side x vulnerability side                     RiskScoreTotal_Weighted = floor(total x weight / 100)
        (RiskConsequenceScore = the asset side, RiskProbabilityScore = the vulnerability side)

      1. TIER     the same finding on a Tier 0 asset scores >= Tier 1 >= Tier 2 >= Tier 3 (every matcher set of the shipped
                  index -- server / client rows included -- and every report's own category / subcategory / configuration id,
                  every severity)
      2. SEVERITY the same finding with a higher severity has a vulnerability side >= a lower one (same tier)
      3. FACTORS  a risk factor never lowers a score: adding any factor -- a report token in either column, a catalog factor
                  through the CI, an engine signal column, a CMDB value -- leaves every score column >= before (every impact
                  is >= 1, a disabled factor adds 0)
      4. ONCE     one factor counts once: the same catalog factor arriving under two names (report + engine, report + CI, two
                  report tokens of one factor) adds its impact once, on its own side
      5. FORMULA  each side = its base + the sum of the impacts of the factors it lists (no cap, nothing else); total = their
                  product, never negative; weighted = floor(total x weight / 100) exactly; the owner's example scores 90
      6. CATALOG  every report carries the weight columns (RiskScore_Weight_*) to its output; every RiskFactor_*_Detailed a
                  report computes reaches the engine; a constant RiskFactor_* value is engine scaffolding, the weighted
                  block's documented no-op default, or a constant factor list listed below with its reason
    No exceptions: the v1 severity exception (scid-2001 / scid-2000) went with #527 (2) and none was added for v2.
    Offline; PS 7 (the v3 gate), PS 5.1 compatible.
#>

BeforeDiscovery {
    $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $y = [IO.File]::ReadAllText((Join-Path $root 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:ReportCases = @([regex]::Matches($y, '(?s)    - ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') |
        Where-Object { $_.Groups[2].Value -match 'ReportQuery:' } | ForEach-Object { @{ Name = $_.Groups[1].Value } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportBlock([string]$Name) {
        [regex]::Match($script:Yaml, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
    }
    function script:Get-Query([string]$Block) { [regex]::Match($Block, '(?s)ReportQuery:(.*)$').Groups[1].Value }
    function script:Get-MainPipeline([string]$Query) {
        $semi = [regex]::Matches($Query, ';[ \t]*(//[^\r\n]*)?\r?\n')
        if ($semi.Count -eq 0) { return $Query }
        $Query.Substring($semi[$semi.Count - 1].Index)
    }
    function script:Get-Projects([string]$Text) { @([regex]::Matches($Text, '(?s)\|\s*project\s+(.*?)(?=\r?\n\s*\||\z)') | ForEach-Object { $_.Groups[1].Value }) }
    function script:Get-Summarizes([string]$Text) {
        @([regex]::Matches($Text, '(?s)\|\s*summarize\b(.*?)(?=\r?\n\s*\||\z)') |
            Where-Object { ([regex]::Matches($_.Value, '\(').Count) -ge ([regex]::Matches($_.Value, '\)').Count) } | ForEach-Object { $_.Groups[1].Value })
    }

    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $script:IndexRows = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Index = New-RiskIndex -CsvRows $script:IndexRows
    $script:MaxAsset = (@($script:IndexRows | Where-Object { $_.AssetBase } | ForEach-Object { [double]::Parse($_.AssetBase, [Globalization.CultureInfo]::InvariantCulture) }) | Measure-Object -Maximum).Maximum
    $script:MaxVuln = (@($script:IndexRows | Where-Object { $_.VulnerabilityBase } | ForEach-Object { [double]::Parse($_.VulnerabilityBase, [Globalization.CultureInfo]::InvariantCulture) }) | Measure-Object -Maximum).Maximum
    $script:Tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $script:Sevs = @('Very High', 'High', 'Medium-High', 'Medium', 'Low')
    $script:Catalog = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\risk-factors.locked.json')) | ConvertFrom-Json
    $script:Impact = @{}; foreach ($f in @($script:Catalog.factors)) { $script:Impact[[string]$f.id] = [int]$f.impact }
    $script:Map = New-RAFactorImpactMap -Catalog $script:Catalog
    $script:DomainOf = @{ 'device' = 'Endpoint'; 'device_server' = 'Endpoint'; 'device_client' = 'Endpoint'; 'identity' = 'Identity'; 'cloud_resource' = 'Azure'; 'public_ip' = 'PublicIP'; '' = 'Identity' }

    function script:Score {
        param([Parameter(Mandatory)][System.Collections.IDictionary]$Row, [object[]]$Cis, $Index = $script:Index)
        $o = [pscustomobject]$Row
        if ($Cis) { $o = @(Add-RACiContext -Rows @($o) -Index (New-RACiIndex -Cis $Cis))[0] }
        $ProgressPreference = 'SilentlyContinue'
        @(Calculate-RiskScore -Rows @($o) -RiskIndex $Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'Inv_Detailed')[0]
    }
    function script:New-Finding {
        param([string]$Domain = 'Endpoint', [string]$Category = 'Vulnerabilities', [string]$Sub = 'CVEs', [string]$Cfg = 'CVE-1', [string]$Sev = 'High', [int]$Tier = 2, [string]$AssetClass = '')
        $h = [ordered]@{ SecurityDomain = $Domain; Category = $Category; Subcategory = $Sub; ConfigurationName = 'x'; ConfigurationId = $Cfg; SecuritySeverity = $Sev
            CriticalityTier = $Tier; CriticalityTierLevel = $script:Tiers[$Tier]; AssetName = 'a1'; MdeDeviceId = 'dev-1'
            RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' }
        if ($AssetClass) { $h['si_asset_class'] = $AssetClass }
        $h
    }
    function script:Assert-NotLower($Before, $After, [string]$Because) {
        foreach ($c in 'RiskConsequenceScore', 'RiskProbabilityScore', 'RiskScoreTotal', 'RiskScoreTotal_Weighted') {
            [double]$After.$c | Should -BeGreaterOrEqual ([double]$Before.$c) -Because "$Because ($c)"
        }
    }
    # the impact a listed factor name adds (a catalog factor's impact, else the report_scoped impact)
    function script:Get-ListedImpact([string]$List) {
        $s = 0
        foreach ($t in @(([string]$List) -split ';' | Where-Object { $_ })) {
            $k = ConvertTo-RALetterKey $t
            if ($script:Map.ByKey.ContainsKey($k)) { $s += [int]$script:Map.ByKey[$k].Impact } else { $s += [int]$script:Map.ReportScoped.Impact }
        }
        $s
    }
    # every token a factor can arrive as: catalog ids + short names + legacy tokens, per side, plus report-only tokens
    $script:AssetTokens = New-Object System.Collections.Generic.List[string]; $script:VulnTokens = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($script:Catalog.factors | Where-Object { $_.evaluatedBy -eq 'catalog' })) {
        $l = $script:AssetTokens; if ([string]$f.appliesTo -eq 'finding') { $l = $script:VulnTokens }
        $l.Add([string]$f.id); $l.Add([string]$f.shortName); foreach ($t in @($f.legacyTokens)) { if ($t) { $l.Add(([string]$t -replace '^RF_[PC]_', '')) } }
    }
    $script:AssetTokens.AddRange([string[]]@('Internet-Exposed', 'SomeReportOnlyFactor'))
    $script:VulnTokens.AddRange([string[]]@('ExploitSignals', 'RemoteCodeExecutionRisk', 'DomainTakeoverPotential'))
    $script:SignalColumns = @(
        @{ IsCompromisedRecently = $true }, @{ MachineRiskState = 'High' }, @{ DefenderAvStatus = 'Disabled' }, @{ DefenderAvStatus = 'OutOfDate' },
        @{ OnboardingStatus = 'InsufficientInfo' }, @{ DeviceManagementType = 'Unmanaged' }, @{ IsExcluded = $true }, @{ HasInternetExposureSignal = $true },
        @{ MsCriticalityLevel = 'VeryHigh' }, @{ IsProductionEnvironment = $true },
        @{ IsExchangeOnlineMailbox = $true }, @{ cmdbCriticality = 'Critical' }, @{ cmdbDataSensitivity = 'Restricted' }, @{ cmdbDataSensitivity = 'Confidential' })
}

Describe '1 + 2. tier and severity order the score' {
    It 'the shipped index: for every matcher set, Tier 0 >= Tier 1 >= Tier 2 >= Tier 3 at every severity' {
        $sets = @($script:IndexRows | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.asset_class, $_.si_category, $_.si_subcategory, $_.si_finding_key } | Sort-Object -Unique)
        $sets += 'identity|Sign-in Behaviour||'; $sets += 'cloud_resource|||'; $sets += 'public_ip|External Exposure|Vulnerability|'
        foreach ($s in $sets) {
            $p = $s -split '\|'
            $dom = $script:DomainOf[$p[0]]
            $ac = ''; if ($p[0] -in 'device_server', 'device_client') { $ac = $p[0] }
            foreach ($sev in $script:Sevs) {
                $prev = $null
                for ($t = 0; $t -le 3; $t++) {
                    $r = Score (New-Finding -Domain $dom -Category $p[1] -Sub $p[2] -Cfg $(if ($p[3]) { $p[3] } else { 'X-1' }) -Sev $sev -Tier $t -AssetClass $ac)
                    if ($null -ne $prev) { [double]$r.RiskScoreTotal | Should -BeLessOrEqual ([double]$prev.RiskScoreTotal) -Because "$s, $sev, tier $t vs tier $($t - 1)" }
                    $prev = $r
                }
            }
        }
    }
    It 'the shipped index: a higher severity never has a lower vulnerability side (same finding, same tier)' {
        $sets = @($script:IndexRows | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_.asset_class, $_.si_category, $_.si_subcategory, $_.si_finding_key } | Sort-Object -Unique)
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($s in $sets) {
            $p = $s -split '\|'; $dom = $script:DomainOf[$p[0]]
            $ac = ''; if ($p[0] -in 'device_server', 'device_client') { $ac = $p[0] }
            $prev = $null
            foreach ($sev in $script:Sevs) {
                $r = Score (New-Finding -Domain $dom -Category $p[1] -Sub $p[2] -Cfg $(if ($p[3]) { $p[3] } else { 'X-1' }) -Sev $sev -Tier 2 -AssetClass $ac)
                if ($null -ne $prev -and [double]$r.RiskProbabilityScore -gt [double]$prev.RiskProbabilityScore) { if (-not $bad.Contains($s)) { $bad.Add($s) } }
                $prev = $r
            }
        }
        @($bad) | Should -BeNullOrEmpty
    }
    It 'a CI''s tier decides the row''s tier, and a Tier 0 CI scores >= a Tier 3 CI for the same finding' {
        $ci0 = [pscustomobject]@{ si_ci_id = 'c0'; si_asset_name = 'a1'; si_tier = '0'; si_link_mde = 'dev-1'; si_risk_factors = '[]' }
        $ci3 = [pscustomobject]@{ si_ci_id = 'c3'; si_asset_name = 'a1'; si_tier = '3'; si_link_mde = 'dev-1'; si_risk_factors = '[]' }
        $a = Score (New-Finding -Tier 3) -Cis @($ci0)
        $b = Score (New-Finding -Tier 0) -Cis @($ci3)
        [int]$a.CriticalityTier | Should -Be 0
        [int]$b.CriticalityTier | Should -Be 3
        [double]$a.RiskScoreTotal | Should -BeGreaterOrEqual ([double]$b.RiskScoreTotal)
    }
    It 'the owner''s example behaviour: Defender not responding (scid-2002) is critical on a server and low on a client' {
        $srv = Score (New-Finding -Category 'Security controls' -Sub 'EDR' -Cfg 'scid-2002' -Sev 'Very High' -Tier 2 -AssetClass 'device_server')
        $cli = Score (New-Finding -Category 'Security controls' -Sub 'EDR' -Cfg 'scid-2002' -Sev 'Very High' -Tier 2 -AssetClass 'device_client')
        [double]$srv.RiskConsequenceScore | Should -Be 5
        [double]$cli.RiskConsequenceScore | Should -Be 1
        [double]$srv.RiskScoreTotal | Should -BeGreaterThan ([double]$cli.RiskScoreTotal)
    }
}

Describe '1. every report''s own finding: Tier 0 >= Tier 3' {
    It '<Name>' -ForEach $script:ReportCases {
        $b = Get-ReportBlock $Name
        $dom = [regex]::Match($b, '(?m)^\s+SecurityDomain:\s*(\S+)').Groups[1].Value
        $cat = [regex]::Match($b, 'extend Category\s*=\s*"([^"]+)"').Groups[1].Value
        $sub = [regex]::Match($b, 'extend Subcategory\s*=\s*"([^"]+)"').Groups[1].Value
        $cfg = [regex]::Match($b, 'extend ConfigurationId\s*=\s*"([^"]+)"').Groups[1].Value
        if (-not $dom) { $dom = 'Endpoint' }
        foreach ($ac in @('', 'device_server', 'device_client')) {
            if ($ac -and $dom -ne 'Endpoint') { continue }
            foreach ($sev in $script:Sevs) {
                $s = @(0..3 | ForEach-Object { [double](Score (New-Finding -Domain $dom -Category $cat -Sub $sub -Cfg $(if ($cfg) { $cfg } else { 'X-1' }) -Sev $sev -Tier $_ -AssetClass $ac)).RiskScoreTotal })
                for ($i = 1; $i -le 3; $i++) { $s[$i] | Should -BeLessOrEqual $s[$i - 1] -Because "$Name, $ac, $sev, tier $i" }
            }
        }
    }
}

Describe '3. a risk factor never lowers a score' {
    BeforeAll {
        # a report that gives its factors as a NUMBER only (nine Detailed reports do)
        $h = New-Finding -Tier 1 -Sev 'High'; $h.Remove('RiskFactor_Probability_Detailed'); $h['RiskFactor_Probability'] = 3
        # a report with its own tokens in both columns, on a Tier 0 business-critical asset
        $g = New-Finding -Tier 0 -Sev 'High'; $g['RiskFactor_Probability_Detailed'] = 'ExploitSignals;Internet-Exposed'; $g['RiskFactor_Consequence_Detailed'] = 'RemoteCodeExecutionRisk'; $g['cmdbCriticality'] = 'Critical'
        $script:Bases = @((New-Finding -Tier 0 -Sev 'Very High'), (New-Finding -Tier 2 -Sev 'Medium'), (New-Finding -Tier 3 -Sev 'Low'), $h, $g)
        $script:AllTokens = @($script:AssetTokens) + @($script:VulnTokens)
    }
    It 'adding any token to the report''s RiskFactor_Probability_Detailed' {
        foreach ($b in $script:Bases) {
            if (-not $b.Contains('RiskFactor_Probability_Detailed')) { continue }
            $before = Score $b
            foreach ($tok in $script:AllTokens) {
                $x = [ordered]@{}; foreach ($k in $b.Keys) { $x[$k] = $b[$k] }
                $cur = [string]$x['RiskFactor_Probability_Detailed']; $x['RiskFactor_Probability_Detailed'] = (@(@($cur -split ';' | Where-Object { $_ }) + $tok) -join ';')
                Assert-NotLower $before (Score $x) "token $tok (probability column)"
            }
        }
    }
    It 'adding any token to the report''s RiskFactor_Consequence_Detailed' {
        foreach ($b in $script:Bases) {
            $before = Score $b
            foreach ($tok in $script:AllTokens) {
                $x = [ordered]@{}; foreach ($k in $b.Keys) { $x[$k] = $b[$k] }
                $cur = [string]$x['RiskFactor_Consequence_Detailed']; $x['RiskFactor_Consequence_Detailed'] = (@(@($cur -split ';' | Where-Object { $_ }) + $tok) -join ';')
                Assert-NotLower $before (Score $x) "token $tok (consequence column)"
            }
        }
    }
    It 'adding any engine signal column or CMDB value' {
        foreach ($b in $script:Bases) {
            $before = Score $b
            foreach ($sig in $script:SignalColumns) {
                $x = [ordered]@{}; foreach ($k in $b.Keys) { $x[$k] = $b[$k] }
                foreach ($k in $sig.Keys) { $x[$k] = $sig[$k] }
                Assert-NotLower $before (Score $x) ("signal " + (($sig.Keys | ForEach-Object { "$_=$($sig[$_])" }) -join ','))
            }
        }
    }
    It 'adding any catalog asset factor through the CI context, incl. to a number-only report' {
        foreach ($b in $script:Bases) {
            $empty = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = ([string]$b['CriticalityTier']); si_link_mde = 'dev-1'; si_risk_factors = '[]' }
            $before = Score $b -Cis @($empty)
            foreach ($f in @($script:Catalog.factors | Where-Object { $_.evaluatedBy -eq 'catalog' -and $_.appliesTo -eq 'asset' })) {
                $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = ([string]$b['CriticalityTier']); si_link_mde = 'dev-1'
                    si_risk_factors = (ConvertTo-Json -Compress -InputObject @([ordered]@{ id = $f.id; shortName = $f.shortName; axis = $f.axis; side = 'asset'; impact = [int]$f.impact; state = 'enabled'; stage = 'production' })) }
                Assert-NotLower $before (Score $b -Cis @($ci)) "CI factor $($f.id)"
            }
        }
    }
    It 'adding a finding factor''s SI field (KnownExploited, ExploitKit, ...) never lowers, and an absent field adds nothing' {
        $b = New-Finding -Tier 1 -Sev 'High'
        $before = Score $b
        foreach ($pair in @(@{ si_exploit_verified = $true }, @{ si_in_exploit_kit = $true }, @{ si_has_exploit = $true }, @{ si_zero_day = $true }, @{ si_fix_available = $false },
                @{ si_cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }, @{ si_due_date = '2020-01-01T00:00:00Z' }, @{ si_published = '2019-01-01T00:00:00Z' })) {
            $x = [ordered]@{}; foreach ($k in $b.Keys) { $x[$k] = $b[$k] }
            foreach ($k in $pair.Keys) { $x[$k] = $pair[$k] }
            $after = Score $x
            Assert-NotLower $before $after ("finding field " + (@($pair.Keys) -join ','))
            [double]$after.RiskProbabilityScore | Should -BeGreaterThan ([double]$before.RiskProbabilityScore) -Because "$(@($pair.Keys) -join ',') holds: its finding factor adds its impact"
        }
        # a field that is not there is UNKNOWN -- never a finding (#546)
        [int]$before.RiskFactor_Probability | Should -Be 0
    }
    It 'random combinations: every superset of factors scores >= its subset (seeded, 300 pairs)' {
        $rnd = New-Object System.Random 4242
        $all = @($script:AssetTokens | ForEach-Object { @{ Col = 'p'; T = $_ } }) + @($script:VulnTokens | ForEach-Object { @{ Col = 'c'; T = $_ } })
        for ($i = 0; $i -lt 300; $i++) {
            $b = New-Finding -Tier ($rnd.Next(0, 4)) -Sev $script:Sevs[$rnd.Next(0, 5)]
            $pick = @(0..($rnd.Next(1, 6)) | ForEach-Object { $all[$rnd.Next(0, $all.Count)] })
            $sub = @($pick | Select-Object -First ([Math]::Max(1, [int]($pick.Count / 2))))
            $mk = { param($set) $x = [ordered]@{}; foreach ($k in $b.Keys) { $x[$k] = $b[$k] }
                $x['RiskFactor_Probability_Detailed'] = (@($set | Where-Object { $_.Col -eq 'p' } | ForEach-Object { $_.T }) -join ';')
                $x['RiskFactor_Consequence_Detailed'] = (@($set | Where-Object { $_.Col -eq 'c' } | ForEach-Object { $_.T }) -join ';'); $x }
            Assert-NotLower (Score (& $mk $sub)) (Score (& $mk $pick)) "combination $i"
        }
    }
}

Describe '4. one factor counts once' {
    It 'the report''s Internet-Exposed and the engine''s internet-exposure signal are one factor (impact once, asset side)' {
        $a = New-Finding; $a['RiskFactor_Probability_Detailed'] = 'Internet-Exposed'
        $b = New-Finding; $b['RiskFactor_Probability_Detailed'] = 'Internet-Exposed'; $b['HasInternetExposureSignal'] = $true
        [int](Score $b).RiskFactor_Consequence | Should -Be ([int](Score $a).RiskFactor_Consequence)
        [int](Score $a).RiskFactor_Consequence | Should -Be $script:Impact['internet_exposed']
        (Score $a).RiskFactor_Consequence_Detailed | Should -Be 'InternetExposed'
    }
    It 'the report''s LegacyEndOfSupport and the CI''s unsupported_os are one factor' {
        $f = New-Finding; $f['RiskFactor_Probability_Detailed'] = 'LegacyEndOfSupport'
        $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = '2'; si_link_mde = 'dev-1'; si_risk_factors = '[{"id":"unsupported_os","axis":"probability","impact":4,"state":"enabled","stage":"production"}]' }
        $r = Score $f -Cis @($ci)
        [int]$r.RiskFactor_Consequence | Should -Be $script:Impact['unsupported_os']
        $r.RiskFactor_Consequence_Detailed | Should -Be 'UnsupportedOS'
    }
    It 'the identity reports'' NoMfaIsRegistered and the CI''s no_mfa are one factor' {
        $f = New-Finding -Domain 'Identity' -Category 'Identity' -Sub 'MFA' -Cfg 'IDENTITY-MFA-001'; $f['RiskFactor_Probability_Detailed'] = 'NoMfaIsRegistered'
        $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = '2'; si_link_mde = 'dev-1'; si_risk_factors = '[{"id":"no_mfa","axis":"probability","impact":3,"state":"enabled","stage":"production"}]' }
        [int](Score $f -Cis @($ci)).RiskFactor_Consequence | Should -Be $script:Impact['no_mfa']
    }
    It 'the CI''s restricted_data and the engine''s RestrictedDataAccess are one factor' {
        $f = New-Finding -Tier 2; $f['cmdbDataSensitivity'] = 'Restricted'
        $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = '2'; si_link_mde = 'dev-1'; si_risk_factors = '[{"id":"restricted_data","axis":"consequence","impact":4,"state":"enabled","stage":"production"}]' }
        [int](Score $f -Cis @($ci)).RiskFactor_Consequence | Should -Be $script:Impact['restricted_data']
    }
    It 'a report''s own two tokens of one catalog factor count ONCE (#559: one factor, one impact)' {
        $f = New-Finding; $f['RiskFactor_Probability_Detailed'] = 'Stale;StaleLogin'
        $r = Score $f
        [int]$r.RiskFactor_Consequence | Should -Be $script:Impact['stale_sign_in']
        $r.RiskFactor_Consequence_Detailed | Should -Be 'EnabledNoSignInStale'
    }
    It 'a finding factor arriving in the asset column counts on the VULNERABILITY side' {
        $f = New-Finding; $f['RiskFactor_Probability_Detailed'] = 'ExploitSignals'
        $r = Score $f
        [int]$r.RiskFactor_Probability | Should -Be $script:Impact['exploit_available']
        [int]$r.RiskFactor_Consequence | Should -Be 0
        $r.RiskFactor_Probability_Detailed | Should -Be 'ExploitAvailable'
    }
    It 'tier is never a factor (#527 (5)): a Tier 0 row with no factor of its own has no factor on either side, and no catalog factor names tier' {
        [int](Score (New-Finding -Tier 0)).RiskFactor_Consequence | Should -Be 0
        [int](Score (New-Finding -Tier 0)).RiskFactor_Probability | Should -Be 0
        foreach ($id in 'tier0', 'tier0_or_1', 'tier0_blast_radius', 'adfs_server', 'exchange_server', 'business_critical_asset') { @($script:Catalog.factors | Where-Object { $_.id -eq $id }).Count | Should -Be 0 -Because "$id restated tier / the multiplier" }
        $map = New-RAFactorAliasMap -Catalog $script:Catalog
        foreach ($tok in 'RF_P_Tier0', 'Tier0Role', 'RF_P_Privileged', 'PrivilegedRole', 'Tier0BlastRadius', 'BusinessCriticalAsset') { $map.ContainsKey((ConvertTo-RALetterKey $tok)) | Should -BeFalse -Because "$tok maps to no factor" }
    }
    It 'break glass is no factor any more (#559): RF_P_BreakGlass adds nothing' {
        $a = New-Finding -Domain 'Identity'; $b = New-Finding -Domain 'Identity'; $b['RiskFactor_Probability_Detailed'] = 'RF_P_BreakGlass'
        [double](Score $b).RiskScoreTotal | Should -Be ([double](Score $a).RiskScoreTotal)
        @($script:Catalog.factors | Where-Object { $_.id -in 'break_glass', 'very_stale_sign_in' }).Count | Should -Be 0
    }
    It 'the marker the CI context sets never reaches the output row; the factor shows by its short name' {
        $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = '2'; si_link_mde = 'dev-1'; si_risk_factors = '[{"id":"no_mfa","axis":"probability","impact":3,"state":"enabled","stage":"production"}]' }
        $r = Score (New-Finding) -Cis @($ci)
        $r.PSObject.Properties['si_ci_factor_tokens'] | Should -BeNullOrEmpty
        $r.RiskFactor_Consequence_Detailed | Should -Match '(^|;)NoMFA(;|$)'
    }
    It 'every token a report emits for a catalog factor''s RF_* flag names that factor (else the CI adds the factor a second time)' {
        $map = New-RAFactorAliasMap -Catalog $script:Catalog
        $pairs = @([regex]::Matches($script:Yaml, 'iff\((RF_[PC]_\w+)\s*==\s*1,\s*dynamic\(\["([^"]+)"\]\)') | ForEach-Object { [pscustomobject]@{ Flag = $_.Groups[1].Value; Tok = $_.Groups[2].Value } } | Sort-Object Flag, Tok -Unique)
        $pairs.Count | Should -BeGreaterThan 20
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($p in $pairs) {
            $ff = $map[(ConvertTo-RALetterKey $p.Flag)]
            if (-not $ff) { continue }
            if ($p.Flag -eq 'RF_P_HighRisk') { continue }                # reports use it for the DEVICE's risk -> high_machine_risk, which the token names
            if ($p.Flag -eq 'RF_P_VeryOld' -and $p.Tok -eq 'PasswordOver730Days') { continue }   # one report's VeryOld is password age -> old_password
            $tf = $map[(ConvertTo-RALetterKey $p.Tok)]
            if ($tf -ne $ff) { $bad.Add("$($p.Flag) -> $($p.Tok) (token names '$tf', flag is '$ff')") }
        }
        @($bad) | Should -BeNullOrEmpty
    }
}

Describe '5. the formula, exactly' {
    It 'the owner''s example: (Tier 0 base 5 + PortOpenInternet 5) x (very high 5 + ExploitKit 4) = 90' {
        $rows = @(
            [pscustomobject][ordered]@{ si_finding_type = ''; si_category = ''; si_subcategory = ''; si_component = ''; si_finding_key = ''; asset_class = ''; si_severity = 'critical'; VulnerabilityBase = '5'; si_tier = ''; AssetBase = ''; Comments = ''; Precedence = '1' },
            [pscustomobject][ordered]@{ si_finding_type = ''; si_category = ''; si_subcategory = ''; si_component = ''; si_finding_key = ''; asset_class = ''; si_severity = ''; VulnerabilityBase = ''; si_tier = '0'; AssetBase = '5'; Comments = ''; Precedence = '2' })
        $idx = New-RiskIndex -CsvRows $rows
        $f = New-Finding -Tier 0 -Sev 'Very High'; $f['RiskFactor_Probability_Detailed'] = 'PortOpenInternet'; $f['RiskFactor_Consequence_Detailed'] = 'ExploitKit'
        $r = Score $f -Index $idx
        [double]$r.RiskConsequenceScore | Should -Be 10
        [double]$r.RiskProbabilityScore | Should -Be 9
        [double]$r.RiskScoreTotal | Should -Be 90
        $r.RiskRating | Should -Be 'Critical'
    }
    It 'every side is its base + the impacts of the factors it lists; total = product; weighted = floor (seeded, 400 rows)' {
        $rnd = New-Object System.Random 777
        for ($i = 0; $i -lt 400; $i++) {
            $f = New-Finding -Tier ($rnd.Next(0, 4)) -Sev $script:Sevs[$rnd.Next(0, 5)]
            $f['RiskFactor_Probability_Detailed'] = (@(0..($rnd.Next(0, 5)) | ForEach-Object { $script:AssetTokens[$rnd.Next(0, $script:AssetTokens.Count)] }) -join ';')
            $f['RiskFactor_Consequence_Detailed'] = (@(0..($rnd.Next(0, 3)) | ForEach-Object { $script:VulnTokens[$rnd.Next(0, $script:VulnTokens.Count)] }) -join ';')
            $sig = $script:SignalColumns[$rnd.Next(0, $script:SignalColumns.Count)]; foreach ($k in $sig.Keys) { $f[$k] = $sig[$k] }
            $w = @(100, 105, 125, 150, 262)[$rnd.Next(0, 5)]; $f['RiskFactor_Weight'] = $w
            $r = Score $f
            $vals = Get-SIRiskIndexFindingValues -Row ([pscustomobject]$f) -CategoryInputName Category -SubCategoryInputName Subcategory
            $ab = (Get-SIRiskIndexSiScore -Index $script:Index -Kind Asset -Values $vals.Asset).Score
            $vb = (Get-SIRiskIndexSiScore -Index $script:Index -Kind Vulnerability -Values $vals.Vulnerability).Score
            $ai = Get-ListedImpact $r.RiskFactor_Consequence_Detailed
            $vi = Get-ListedImpact $r.RiskFactor_Probability_Detailed
            [int]$r.RiskFactor_Consequence | Should -Be $ai -Because "row ${i}: the asset sum is the impacts of the asset factors it lists"
            [int]$r.RiskFactor_Probability | Should -Be $vi -Because "row ${i}: the vulnerability sum is the impacts of the factors it lists"
            [double]$r.RiskConsequenceScore | Should -Be ($ab + $ai) -Because "row ${i}: asset side = AssetBase + impacts, no cap"
            [double]$r.RiskProbabilityScore | Should -Be ($vb + $vi) -Because "row ${i}: vulnerability side = VulnerabilityBase + impacts, no cap"
            $ab | Should -BeLessOrEqual $script:MaxAsset
            $vb | Should -BeLessOrEqual $script:MaxVuln
            [double]$r.RiskScoreTotal | Should -Be ([double]$r.RiskConsequenceScore * [double]$r.RiskProbabilityScore)
            [double]$r.RiskScoreTotal | Should -BeGreaterOrEqual 0
            [int]$r.RiskScoreTotal_Weighted | Should -Be ([int][Math]::Floor([double]$r.RiskScoreTotal * $w / 100.0))
            $r.RiskRating | Should -Be (Get-SIRiskRating -Score ([double]$r.RiskScoreTotal))
        }
    }
    It 'a numeric RiskFactor_Consequence a report sets is scaffolding: the engine sums the listed factors instead' {
        $f = New-Finding -Tier 2; $f['RiskFactor_Consequence'] = 3
        [int](Score $f).RiskFactor_Consequence | Should -Be 0
    }
    It 'a number-only report''s factors count the report_scoped impact each, on the asset side' {
        $f = New-Finding -Tier 2; $f.Remove('RiskFactor_Probability_Detailed'); $f['RiskFactor_Probability'] = 3
        [int](Score $f).RiskFactor_Consequence | Should -Be (3 * [int]$script:Map.ReportScoped.Impact)
    }
    It 'the bands: Critical >= 50, High >= 30, Moderate >= 15, else Low' {
        Get-SIRiskRating -Score 90 | Should -Be 'Critical'; Get-SIRiskRating -Score 50 | Should -Be 'Critical'
        Get-SIRiskRating -Score 49 | Should -Be 'High'; Get-SIRiskRating -Score 30 | Should -Be 'High'
        Get-SIRiskRating -Score 29 | Should -Be 'Moderate'; Get-SIRiskRating -Score 15 | Should -Be 'Moderate'
        Get-SIRiskRating -Score 14 | Should -Be 'Low'; Get-SIRiskRating -Score 16 -Lower | Should -Be 'moderate'
    }
}

Describe '6. the report catalog' {
    BeforeAll {
        # constant factor lists that ARE the finding's definition: every row of the report has exactly these factors
        $script:ConstantTokenReports = @{
            'Identity_BreakGlass_SignIn_Detected_Summary'   = 'a break-glass sign-in always means last-resort access loss + tenant takeover potential'
            'Identity_SPN_RoleManagementWrite_Summary'      = 'RoleManagement.ReadWrite.Directory always means any Entra role is assignable, Global Admin included'
            'Identity_SPN_RoleManagementWrite_Detailed'     = 'as the Summary'
            'Identity_TooManyGlobalAdmins_Detailed'         = 'every row is a Global Admin by the report''s definition'
        }
        $script:KnownDroppedTokens = @{}
    }
    It '<Name>: carries the weight columns (RiskScore_Weight_*) to its output' -ForEach $script:ReportCases {
        $b = Get-ReportBlock $Name; $q = Get-Query $b
        $q | Should -Match '//__WEIGHTED_FACTORS_BEGIN__'
        $wb = [regex]::Match($q, '(?s)//__WEIGHTED_FACTORS_BEGIN__(.*?)//__WEIGHTED_FACTORS_END__').Groups[1].Value
        foreach ($c in 'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed') { $wb | Should -Match "extend $c\s*=" -Because "the weighted block's no-op default sets $c" }
        $main = Get-MainPipeline $q
        $e = $main.IndexOf('//__WEIGHTED_FACTORS_END__'); $after = $main; if ($e -ge 0) { $after = $main.Substring($e) }
        $pr = @(Get-Projects $after)
        foreach ($c in 'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed') {
            if ($pr.Count -gt 0) { $pr[$pr.Count - 1] | Should -Match "\b$c\b" -Because "$c reaches the final projection" }
            foreach ($s in (Get-Summarizes $after)) { $s | Should -Match "\b$c\b" -Because "$c survives every summarize after the weighted block" }
        }
        $b | Should -Match '(?m)^\s+- RiskScore_Weight_Detailed\s*$'
        $b | Should -Match '(?m)^\s+- RiskScore_Weight_Factor\s*$'
    }
    It '<Name>: every RiskFactor_*_Detailed it computes reaches the engine' -ForEach $script:ReportCases {
        $q = Get-Query (Get-ReportBlock $Name); $main = Get-MainPipeline $q
        foreach ($c in 'RiskFactor_Consequence_Detailed', 'RiskFactor_Probability_Detailed') {
            if (-not [regex]::IsMatch($q, "\b$c\s*=")) { continue }
            $sets = [regex]::Matches($main, "\b$c\s*=")
            $after = $main; if ($sets.Count -gt 0) { $after = $main.Substring($sets[$sets.Count - 1].Index) }
            $miss = @()
            $pr = @(Get-Projects $after); if ($pr.Count -gt 0 -and $pr[$pr.Count - 1] -notmatch "\b$c\b") { $miss += 'final project' }
            foreach ($s in (Get-Summarizes $after)) { if ($s -notmatch "\b$c\b") { $miss += 'summarize' } }
            $key = "$Name|$c"
            if ($script:KnownDroppedTokens.ContainsKey($key)) { $miss.Count | Should -BeGreaterThan 0 -Because "$key is listed as dropped (owner decision) -- it is carried now: remove it from the list"; continue }
            $miss | Should -BeNullOrEmpty -Because "$c is computed and must reach the engine"
        }
    }
    It '<Name>: a constant RiskFactor_* value is scaffolding, the documented weight default, or a listed constant factor list' -ForEach $script:ReportCases {
        $q = Get-Query (Get-ReportBlock $Name)
        $wb = [regex]::Match($q, '(?s)//__WEIGHTED_FACTORS_BEGIN__(.*?)//__WEIGHTED_FACTORS_END__').Groups[1].Value
        $rest = $q.Replace($wb, '')
        foreach ($m in [regex]::Matches($rest, '(?m)\b(RiskFactor_\w+)\s*=\s*("[^"]*"|-?\d+(\.\d+)?)\s*(,|$|//.*$|\))')) {
            $col = $m.Groups[1].Value
            switch -Regex ($col) {
                '^RiskFactor_Consequence$' { continue }       # the engine re-stamps it as the asset side's impact sum (Describe 5)
                '^RiskFactor_Probability$' { continue }       # a number the engine uses only without tokens, never lowered (Describe 3 / 5)
                '^RiskFactor_Weight$' { continue }            # basis-100 default 100 = no lift; the CI's criticality factor or the weighted block replaces it
                '_Detailed$' { $script:ConstantTokenReports.ContainsKey($Name) | Should -BeTrue -Because "$Name sets a constant $col ($($m.Groups[2].Value)) -- list it with its reason or compute it" }
                default { throw "$Name sets a constant $col = $($m.Groups[2].Value) the invariants do not know" }
            }
        }
    }
}
