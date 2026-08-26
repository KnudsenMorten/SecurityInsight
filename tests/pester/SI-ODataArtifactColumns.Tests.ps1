#Requires -Version 5.1
<#
    TWO ROWS MUST NOT ADD SEVENTEEN COLUMNS TO EVERYBODY'S WORKBOOK.

    Graph advanced hunting annotates each value with a sibling "<name>@odata.type" key holding the
    OData type name (#Int64, #SByte, #Collection(String)). Three AH call sites already strip them
    via ConvertTo-PSObjectDeep -StripOData (Invoke-RiskAnalysis.ps1 :2792, :3016, :3150) -- but at
    least one path does not, so they reached the export pool.

    MEASURED on the internal estate 2026-08-26, and the disproportion is the whole point:

        rows carrying @odata props : 2      (of 6,339)
        producing report           : Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources
        columns added to the xlsx  : 17     (of 316)

    Export-Worksheet takes the UNION of column names across all rows, so TWO rows out of 6,339
    (0.03%) added SEVENTEEN junk columns (5.4%) to every customer workbook and to the JSON sibling.
    That asymmetry -- a vanishingly rare row shape polluting a shared output -- is the class of
    defect worth a regression test.

    LOG ANALYTICS WAS NEVER AFFECTED, and the tests below pin why, because it explains the fix.
    The ingest already filters its schema sample with the legal-identifier regex
    (Invoke-RiskAnalysis.ps1 ~:3923), and Build-DataArrayToAlignWithSchema drops undeclared columns
    from the posted rows -- so declared and posted agreed and only legal names ever landed.
    v2.2.453 applies that SAME regex to the export pool, so the workbook matches the table.

    WHY THE REGEX IS SAFE TO APPLY WHOLESALE -- verified against a real 316-column workbook before
    shipping, not assumed:
        columns failing the regex : 17
        of those, @odata.type     : 17
        legitimate columns lost   : 0
    TenantId and Type PASS the regex. They are renamed later, to TenantId_ / Type_, by
    AzLogDcrIngestPS because Log Analytics reserves those names -- that is the ingest module's job,
    it preserves the data, and it is unrelated to this filter. A test below pins that they survive,
    because dropping them here would silently delete two real columns.
#>

BeforeAll {
    # THREE levels: tests\pester\<file> -> tests\pester -> tests -> SecurityInsight.
    # Two levels lands on tests\, Get-Content then fails non-terminating and $Src is $null,
    # which makes every wiring assertion below fail against "$null" instead of the engine.
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Engine = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    if (-not (Test-Path -LiteralPath $script:Engine)) { throw "engine not found at $script:Engine" }
    $script:Src    = Get-Content -LiteralPath $script:Engine -Raw

    $script:LegalCol = [regex]'^[A-Za-z][A-Za-z0-9_]*$'

    # The 17 artefact names exactly as observed in the 2026-08-26 run.
    $script:RealArtifacts = @(
        'RiskFactor_Consequence@odata.type'
        'RiskFactor_Probability@odata.type'
        'RiskScore_Weight_Factor@odata.type'
        'RiskFactor_Weight@odata.type'
        'AttackPathPriorityScore@odata.type'
        'TierEscalation@odata.type'
        'IsLateralMovement@odata.type'
        'EscalationWeight@odata.type'
        'ExposureWeight@odata.type'
        'TotalIdentitiesInGroup@odata.type'
        'AllIdentities@odata.type'
        'IdentityTypes@odata.type'
        'TargetIsInternetExposed@odata.type'
        'TargetLegacyEndOfSupport@odata.type'
        'SourceIsInternetExposed@odata.type'
        'SourceLegacyEndOfSupport@odata.type'
        'SourceRiskProb@odata.type'
    )

    # Real column names from the same workbook that MUST survive.
    $script:RealKeepers = @(
        'SecurityDomain'
        'Category'
        'ConfigurationId'
        'CriticalityTier'
        'SecuritySeverity'
        'AssetName'
        'AadDeviceId'
        'RiskScoreTotal'
        'RiskScoreTotal_Weighted'
        'RiskFactor_Consequence'
        'RiskFactor_Probability_Detailed'
        'IsApplicableForDefenderForServersReason'
        'cmdbCriticality'
        'TenantId'
        'Type'
    )

    # Mirror of the engine row filter, so BEHAVIOUR is tested and not just source text.
    function script:Remove-ODataArtifacts {
        param([object[]]$Rows)
        $out = New-Object 'System.Collections.Generic.List[object]'
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            $hasIllegal = $false
            foreach ($p in $row.PSObject.Properties) {
                if (-not $script:LegalCol.IsMatch($p.Name)) { $hasIllegal = $true; break }
            }
            if (-not $hasIllegal) {
                [void]$out.Add($row)
                continue
            }
            $kept = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) {
                if ($script:LegalCol.IsMatch($p.Name)) { $kept[$p.Name] = $p.Value }
            }
            [void]$out.Add([pscustomobject]$kept)
        }
        return $out.ToArray()
    }

    function script:Names {
        param($Row)
        return @($Row.PSObject.Properties | ForEach-Object { $_.Name })
    }
}

Describe 'the legal-column contract' {

    It 'rejects every one of the 17 artefact names observed in production' {
        foreach ($n in $script:RealArtifacts) {
            $script:LegalCol.IsMatch($n) | Should -BeFalse -Because "$n is an OData artefact"
        }
    }

    It 'accepts every real column name, INCLUDING TenantId and Type' {
        # If this ever fails, the filter is deleting customer data, not artefacts.
        foreach ($n in $script:RealKeepers) {
            $script:LegalCol.IsMatch($n) | Should -BeTrue -Because "$n is a real column and must survive"
        }
    }

    It 'rejects the other shapes Log Analytics cannot accept either' {
        foreach ($n in @('_leading', 'has-hyphen', 'has.period', 'has:colon', 'has space', '1startsWithDigit', '')) {
            $script:LegalCol.IsMatch($n) | Should -BeFalse
        }
    }
}

Describe 'stripping artefacts from the export pool' {

    It 'THE ACTUAL DEFECT: 2 artefact rows no longer widen a large pool' {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt 200; $i++) {
            [void]$rows.Add([pscustomobject]@{ AssetName = "host-$i"; RiskScoreTotal = $i; SecurityDomain = 'Endpoint' })
        }
        for ($i = 0; $i -lt 2; $i++) {
            $h = [ordered]@{ AssetName = "path-$i"; RiskScoreTotal = 1; SecurityDomain = 'Azure' }
            foreach ($a in $script:RealArtifacts) { $h[$a] = '#Int64' }
            [void]$rows.Add([pscustomobject]$h)
        }

        $before = @($rows.ToArray() | ForEach-Object { script:Names $_ } | Sort-Object -Unique)
        $before.Count | Should -Be 20   # 3 real + 17 artefacts: the union is polluted

        $after = script:Remove-ODataArtifacts -Rows $rows.ToArray()
        $union = @($after | ForEach-Object { script:Names $_ } | Sort-Object -Unique)

        $union.Count | Should -Be 3
        $union | Should -Not -Contain 'AllIdentities@odata.type'
        @($after).Count | Should -Be 202   # no row is lost, only properties
    }

    It 'keeps every legal value on the rows it rebuilds' {
        $h = [ordered]@{ AssetName = 'srv1'; RiskScoreTotal = 42; TenantId = 't-1'; Type = 'vm' }
        $h['AllIdentities@odata.type'] = '#Collection(String)'
        $out = script:Remove-ODataArtifacts -Rows @([pscustomobject]$h)

        $out[0].AssetName      | Should -Be 'srv1'
        $out[0].RiskScoreTotal | Should -Be 42
        $out[0].TenantId       | Should -Be 't-1'
        $out[0].Type           | Should -Be 'vm'
        $names = script:Names $out[0]
        $names | Should -Not -Contain 'AllIdentities@odata.type'
    }

    It 'leaves a clean row as the SAME object (no needless rebuild)' {
        # The normal case is 100% clean rows; rebuilding 6,339 of them would cost seconds for nothing.
        $row = [pscustomobject]@{ AssetName = 'srv1'; RiskScoreTotal = 1 }
        $out = script:Remove-ODataArtifacts -Rows @($row)
        [object]::ReferenceEquals($out[0], $row) | Should -BeTrue
    }

    It 'preserves row order' {
        $rows = 1..50 | ForEach-Object { [pscustomobject]@{ AssetName = "h$_"; N = $_ } }
        $out  = script:Remove-ODataArtifacts -Rows @($rows)
        $out[0].N  | Should -Be 1
        $out[49].N | Should -Be 50
    }

    It 'is idempotent' {
        $h = [ordered]@{ AssetName = 'a' }
        $h['X@odata.type'] = '#Int64'
        $once   = script:Remove-ODataArtifacts -Rows @([pscustomobject]$h)
        $twice  = script:Remove-ODataArtifacts -Rows $once
        $nOnce  = @(script:Names $once[0])
        $nTwice = @(script:Names $twice[0])
        $nTwice.Count | Should -Be $nOnce.Count
        $nTwice[0]    | Should -Be $nOnce[0]
    }
}

Describe 'the engine actually applies it (wiring, not just capability)' {
    # A green helper proves nothing if production never calls it -- this solution has shipped
    # five "declared but never wired" defects. Assert the guard is in the shipping file.

    It 'the strip runs in Invoke-RiskAnalysis.ps1' {
        $script:Src | Should -Match '_RAIllegalColName'
    }

    It 'it uses the same regex the LA schema sample already trusts' {
        # Both the ingest schema filter and this one must agree, or the workbook and the table
        # would disagree about which columns exist -- which is the bug being fixed.
        $pattern     = '^[A-Za-z][A-Za-z0-9_]*$'
        $occurrences = ([regex]::Matches($script:Src, [regex]::Escape($pattern))).Count
        $occurrences | Should -BeGreaterOrEqual 2
    }

    It 'it filters FinalDesiredColumns too, not only the rows' {
        # Export-Worksheet selects columns from this list. A name left here survives as an EMPTY
        # column even after every row carrying it was cleaned.
        $script:Src | Should -Match 'FinalDesiredColumns.*Where-Object'
    }

    It 'it runs AFTER the final sort and BEFORE the excel export' {
        $iSort   = $script:Src.IndexOf('Tick "final sort"')
        $iStrip  = $script:Src.IndexOf('_RAIllegalColName')
        $iExport = $script:Src.IndexOf('exporting to excel (single write)')
        $iSort   | Should -BeGreaterThan 0
        $iStrip  | Should -BeGreaterThan $iSort
        $iExport | Should -BeGreaterThan $iStrip
    }
}
