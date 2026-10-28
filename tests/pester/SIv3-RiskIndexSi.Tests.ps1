#Requires -Version 5.1
<#
    THE RISK INDEX RE-KEYED TO THE SI GENERIC FIELDS (REQUIREMENTS #559, owner 2026-10-10: "risk index base values must be
    adjusted to the si names ... if mde has not responded in 7 days on a server, it is critical - but on a client for a user
    being on vacation it is not same criticality"; "a test proves every shipped risk-index row resolves under the new keys
    and that a v2.2 reference set scores the same before factor impacts").

      1. SHAPE        the shipped index has exactly the SI columns; every row resolves: known asset class, tier 0..3, an SI
                      severity, numeric bases, at least one base, and its own matcher values reach a rule
      2. TRANSLATION  the translation table is data (riskscore.index.translation.locked.json) and covers every v2.2 column;
                      the shipped index IS the translation of the 3.0 index (tests/fixtures/riskindex/
                      riskscore.index.v30-v22keys.csv) row for row, behind the owner's server / client rows
      3. REFERENCE    every combination of the 3.0 index's matcher values (each blank too) x severity x tier scores the SAME
                      asset and vulnerability base through the SI index (translated finding) as the 3.0 index did through
                      first match on its 2.2 keys -- and the 2.2 file itself (59 rows, fixtures) through the ladder
      4. OWNER        scid-2002 (Defender not responding): 5 on a server at any tier, 1 on a user client, 4 on a Tier 0 client;
                      a device that is neither keeps the 2.2 tier values
      5. FAMILY       asset_class 'device' fits device_server and device_client; device_server fits only servers
      6. FILES        a 2.2-keyed customer file (with or without Precedence) is translated on load and walked first
    Offline; PS 7 (the v3 gate), PS 5.1 compatible. Written 2026-10-10, not run yet (owner: "we build all then we test").
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    $script:Shipped = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:V30 = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'tests\fixtures\riskindex\riskscore.index.v30-v22keys.csv'))
    $script:V22 = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'tests\fixtures\riskindex\riskscore.index.v22.csv'))
    $script:Tr = Get-SIRiskIndexTranslation -Path (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.translation.locked.json')
    $script:Index = New-SIRiskIndexSi -Rows $script:Shipped
    $script:TierLabels = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $script:SevLabels = @('Very High', 'High', 'Medium-High', 'Medium', 'Low')
    # a v2.2 finding (its 2.2 values) -> the SI values the engine compares (Get-SIRiskIndexFindingValues on a report row)
    function script:Get-SiValues([hashtable]$F) {
        $row = [pscustomobject]@{ SecurityDomain = $F.SecurityDomain; Category = $F.Category; SubCategory = $F.SubCategory; ConfigurationId = $F.ConfigurationId
            SecuritySeverity = $F.SecuritySeverity; CriticalityTierLevel = $F.CriticalityTierLevel }
        Get-SIRiskIndexFindingValues -Row $row -CategoryInputName Category -SubCategoryInputName SubCategory -ConfigurationIdInputName ConfigurationId -Translation $script:Tr
    }
}

Describe '1. every shipped row resolves under the SI keys' {
    It 'the columns are the SI index columns, in order' {
        @($script:Shipped[0].PSObject.Properties.Name) | Should -Be @('si_finding_type', 'si_category', 'si_subcategory', 'si_component', 'si_finding_key', 'asset_class', 'si_severity', 'VulnerabilityBase', 'si_tier', 'AssetBase', 'Comments', 'Precedence')
    }
    It 'every row: a known asset class, tier 0..3, an SI severity, numeric bases, at least one base, and its own values reach a rule' {
        $classes = @('', 'device_server', 'device_client', 'device', 'identity', 'cloud_resource', 'public_ip')
        $sevs = @('', 'critical', 'high', 'medium_high', 'medium', 'low', 'info')
        $i = 0
        foreach ($r in $script:Shipped) {
            $i++
            $classes | Should -Contain ([string]$r.asset_class) -Because "row $i asset_class"
            @('', '0', '1', '2', '3') | Should -Contain ([string]$r.si_tier) -Because "row $i si_tier"
            $sevs | Should -Contain ([string]$r.si_severity) -Because "row $i si_severity"
            ($r.AssetBase -or $r.VulnerabilityBase) | Should -BeTrue -Because "row $i sets a base"
            foreach ($c in 'AssetBase', 'VulnerabilityBase') { if ($r.$c) { $d = 0.0; [double]::TryParse($r.$c, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) | Should -BeTrue -Because "row $i $c" } }
            [int]$r.Precedence | Should -Be $i
            # the row's own values (a blank matcher filled with a value no row names) reach SOME rule of each kind it sets
            $fill = { param($v, $x) if ([string]::IsNullOrWhiteSpace($v)) { $x } else { $v } }
            $base = @((& $fill $r.si_finding_type 'zz-type'), (& $fill $r.si_category 'zz-cat'), (& $fill $r.si_subcategory 'zz-sub'), (& $fill $r.si_component 'zz-comp'), (& $fill $r.si_finding_key 'zz-key'), (& $fill $r.asset_class 'identity'))
            if ($r.AssetBase) { $h = Get-SIRiskIndexSiScore -Index $script:Index -Kind Asset -Values ([string[]](@($base) + @((& $fill $r.si_tier '2')))); $h.Position | Should -BeGreaterThan 0 -Because "row $i (asset)"; $h.Position | Should -BeLessOrEqual $i }
            if ($r.VulnerabilityBase) { $h = Get-SIRiskIndexSiScore -Index $script:Index -Kind Vulnerability -Values ([string[]](@($base) + @((& $fill $r.si_severity 'high')))); $h.Position | Should -BeGreaterThan 0 -Because "row $i (vulnerability)"; $h.Position | Should -BeLessOrEqual $i }
        }
    }
}

Describe '2. the translation table and the shipped translation' {
    It 'covers every v2.2 column and is shipped as data' {
        foreach ($c in $script:SIRiskIndexV22Columns + @('Comments', 'Precedence')) { $script:Tr.columns.Contains($c) | Should -BeTrue -Because $c }
        $script:Tr.columns['RiskProbablityScore_CriticialityTierLevel'] | Should -Be 'AssetBase'
        $script:Tr.columns['RiskConsequenceScore_SecuritySeverity'] | Should -Be 'VulnerabilityBase'
        $script:Tr.values['si_tier']['critical - tier 0'] | Should -Be '0'
        $script:Tr.values['si_severity']['medium-high'] | Should -Be 'medium_high'
        $script:Tr.values['asset_class']['endpoint'] | Should -Be 'device'
    }
    It 'the shipped index = the owner''s scid-2002 rows, then the 3.0 index translated row for row (every v2.2 base value carried over)' {
        $tr = @(ConvertTo-SIRiskIndexSiRows -Rows $script:V30 -Translation $script:Tr)
        $tr.Count | Should -Be $script:V30.Count
        $owner = @($script:Shipped | Where-Object { [string]$_.asset_class -in 'device_server', 'device_client' })
        $owner.Count | Should -Be 3
        $rest = @($script:Shipped | Select-Object -Skip $owner.Count)
        $rest.Count | Should -Be $tr.Count
        for ($i = 0; $i -lt $tr.Count; $i++) {
            foreach ($c in 'si_category', 'si_subcategory', 'si_finding_key', 'asset_class', 'si_severity', 'VulnerabilityBase', 'si_tier', 'AssetBase') {
                [string]$rest[$i].$c | Should -Be ([string]$tr[$i][$c]) -Because "translated row $($i + 1), $c"
            }
        }
    }
}

Describe '3. a v2.2 reference set scores the same bases' {
    It 'every combination of the 3.0 index''s matcher values x severity x tier: the SI base == the 3.0 first-match base, per kind' {
        $v30Rules = New-SIRiskIndexRules -OrderedRows @(Get-SIRiskIndexOrderedRows -Rows $script:V30)
        $vals = @{}
        foreach ($c in 'SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId') { $vals[$c] = @(@('') + @($script:V30 | ForEach-Object { [string]$_.$c } | Where-Object { $_ } | Sort-Object -Unique)) }
        $bad = New-Object System.Collections.Generic.List[string]
        $n = 0
        foreach ($d in $vals.SecurityDomain) { foreach ($cat in $vals.Category) { foreach ($sub in $vals.SubCategory) { foreach ($cfg in $vals.ConfigurationId) {
            foreach ($sev in @('') + $script:SevLabels) { foreach ($tier in @('') + $script:TierLabels) {
                $f = @{ SecurityDomain = $d; Category = $cat; SubCategory = $sub; ConfigurationId = $cfg; SecuritySeverity = $sev; CriticalityTierLevel = $tier }
                $n++
                $si = Get-SiValues $f
                $wantA = Get-SIRiskIndexFirstMatchScore -Rules $v30Rules -Finding $f -Kind Probability
                $wantV = Get-SIRiskIndexFirstMatchScore -Rules $v30Rules -Finding $f -Kind Consequence
                $gotA = (Get-SIRiskIndexSiScore -Index $script:Index -Kind Asset -Values $si.Asset).Score
                $gotV = (Get-SIRiskIndexSiScore -Index $script:Index -Kind Vulnerability -Values $si.Vulnerability).Score
                if ($gotA -ne $wantA -or $gotV -ne $wantV) { $bad.Add(('{0} | asset {1} vs {2} | vulnerability {3} vs {4}' -f (($f.Values) -join '/'), $gotA, $wantA, $gotV, $wantV)) }
            } }
        } } } }
        $n | Should -BeGreaterThan 1000
        @($bad | Select-Object -First 20) | Should -BeNullOrEmpty
    }
    It 'the 2.2 file itself (59 rows, no Precedence): ladder score == the SI index built from it, every combination' {
        $idx = New-SIRiskIndexSi -Rows $script:V22
        $idx.SourceForm | Should -Be 'v2.2'
        $ladder = New-SIRiskIndexLadderIndex -Rows $script:V22
        $vals = @{}
        foreach ($c in 'SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId') { $vals[$c] = @(@('') + @($script:V22 | ForEach-Object { [string]$_.$c } | Where-Object { $_ } | Sort-Object -Unique)) }
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($d in $vals.SecurityDomain) { foreach ($cat in $vals.Category) { foreach ($sub in $vals.SubCategory) { foreach ($cfg in $vals.ConfigurationId) {
            foreach ($sev in @('') + $script:SevLabels) { foreach ($tier in @('') + $script:TierLabels) {
                $f = @{ SecurityDomain = $d; Category = $cat; SubCategory = $sub; ConfigurationId = $cfg; SecuritySeverity = $sev; CriticalityTierLevel = $tier }
                $si = Get-SiValues $f
                $wantA = Get-SIRiskIndexLadderScore -Rows $script:V22 -Finding $f -Kind Probability -Index $ladder
                $wantV = Get-SIRiskIndexLadderScore -Rows $script:V22 -Finding $f -Kind Consequence -Index $ladder
                $gotA = (Get-SIRiskIndexSiScore -Index $idx -Kind Asset -Values $si.Asset).Score
                $gotV = (Get-SIRiskIndexSiScore -Index $idx -Kind Vulnerability -Values $si.Vulnerability).Score
                if ($gotA -ne $wantA -or $gotV -ne $wantV) { $bad.Add(('{0} | asset {1} vs {2} | vulnerability {3} vs {4}' -f (($f.Values) -join '/'), $gotA, $wantA, $gotV, $wantV)) }
            } }
        } } } }
        @($bad | Select-Object -First 20) | Should -BeNullOrEmpty
    }
}

Describe '4. the owner''s example: Defender not responding is critical on a server, low on a client' {
    BeforeAll {
        function script:AssetBase([string]$Class, [int]$Tier) {
            $v = [string[]]@('', 'Security controls', 'EDR', '', 'scid-2002', $Class, [string]$Tier)
            (Get-SIRiskIndexSiScore -Index $script:Index -Kind Asset -Values $v).Score
        }
    }
    It 'server: 5 at every tier' { foreach ($t in 0..3) { AssetBase 'device_server' $t | Should -Be 5 } }
    It 'user client: 1 (tiers 1..3); a Tier 0 client (a privileged workstation): 4' {
        AssetBase 'device_client' 0 | Should -Be 4
        foreach ($t in 1..3) { AssetBase 'device_client' $t | Should -Be 1 }
    }
    It 'a device that is neither keeps the 2.2 tier values (4 / 3 / 2 / 1)' {
        @(0..3 | ForEach-Object { AssetBase 'device' $_ }) | Should -Be @(4, 3, 2, 1)
    }
    It 'the vulnerability base is unchanged (Very High = 4 for scid-2002)' {
        (Get-SIRiskIndexSiScore -Index $script:Index -Kind Vulnerability -Values ([string[]]@('', 'Security controls', 'EDR', '', 'scid-2002', 'device_server', 'critical'))).Score | Should -Be 4
    }
}

Describe '5. the asset class family' {
    It 'a device row fits a server and a client; a server row fits only a server' {
        $rows = @(
            [pscustomobject][ordered]@{ si_finding_type = ''; si_category = ''; si_subcategory = ''; si_component = ''; si_finding_key = 'k'; asset_class = 'device_server'; si_severity = ''; VulnerabilityBase = ''; si_tier = ''; AssetBase = '5'; Comments = ''; Precedence = '1' },
            [pscustomobject][ordered]@{ si_finding_type = ''; si_category = ''; si_subcategory = ''; si_component = ''; si_finding_key = 'k'; asset_class = 'device'; si_severity = ''; VulnerabilityBase = ''; si_tier = ''; AssetBase = '2'; Comments = ''; Precedence = '2' })
        $idx = New-SIRiskIndexSi -Rows $rows
        foreach ($p in @(@('device_server', 5), @('device_client', 2), @('device', 2), @('identity', 0))) {
            (Get-SIRiskIndexSiScore -Index $idx -Kind Asset -Values ([string[]]@('', '', '', '', 'k', $p[0], '1'))).Score | Should -Be $p[1] -Because $p[0]
        }
    }
    It 'the asset class of a device comes from its category / OS' {
        Get-SIRiskIndexAssetClass -Class device -OsPlatform 'WindowsServer2019' | Should -Be 'device_server'
        Get-SIRiskIndexAssetClass -Class device -DeviceCategory 'server' | Should -Be 'device_server'
        Get-SIRiskIndexAssetClass -Class device -OsPlatform 'Windows11' | Should -Be 'device_client'
        Get-SIRiskIndexAssetClass -Class device -DeviceCategory 'endpoint' | Should -Be 'device_client'
        Get-SIRiskIndexAssetClass -Class device -OsPlatform 'Linux' | Should -Be 'device'
        Get-SIRiskIndexAssetClass -Class identity | Should -Be 'identity'
    }
}

Describe '6. 2.2-keyed customer rows are translated on load and walked first' {
    It 'a 3.0-style custom file (2.2 columns + Precedence) overrides the shipped base' {
        $ov = @([pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Security controls'; SubCategory = 'EDR'; ConfigurationId = 'scid-2002'; SecuritySeverity = 'Very High'
                RiskConsequenceScore_SecuritySeverity = '5'; CriticalityTierLevel = ''; RiskProbablityScore_CriticialityTierLevel = ''; Comments = ''; Precedence = '1' })
        $idx = New-RiskIndex -CsvRows $script:Shipped -OverlayRows $ov
        $idx.OverlayForm | Should -Be 'v3-v2.2keys'
        $idx.OverlayRowCount | Should -Be 1
        (Get-SIRiskIndexSiScore -Index $idx -Kind Vulnerability -Values ([string[]]@('', 'Security controls', 'EDR', '', 'scid-2002', 'device', 'critical'))).Score | Should -Be 5
    }
    It 'the shipped sample custom file is SI-keyed and loads as an overlay' {
        $s = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.custom.sample.csv'))
        (New-RiskIndex -CsvRows $script:Shipped -OverlayRows $s).OverlayForm | Should -Be 'si'
    }
    It 'a 2.2-keyed SHIPPED file (an old install) still builds the same bases as the SI one' {
        $a = New-RiskIndex -CsvRows $script:V30
        $a.SourceForm | Should -Be 'v3-v2.2keys'
        foreach ($v in @([string[]]@('', 'Security controls', 'EDR', '', 'scid-2001', 'device', '0'), [string[]]@('', '', '', '', 'X-1', 'identity', '2'))) {
            (Get-SIRiskIndexSiScore -Index $a -Kind Asset -Values $v).Score | Should -Be (Get-SIRiskIndexSiScore -Index $script:Index -Kind Asset -Values $v).Score
        }
    }
}
