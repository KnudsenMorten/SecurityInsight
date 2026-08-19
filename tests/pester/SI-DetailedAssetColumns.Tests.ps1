#Requires -Version 5.1
<#
    v2.2.443 -- EVERY DETAILED REPORT MUST EMIT THE ASSET COLUMNS IT DECLARES.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS.

    THE CONTRACT, and it is already unambiguous in the catalog:
      * all 60 Detailed reports DECLARE AssetName, AssetId and AssetType in OutputPropertyOrder;
      * all 60 Summary reports declare NONE of them, and declare ImpactedAssetsList instead --
        correct for an aggregate view, and the reason Summary cannot carry this defect.

    WHAT WENT WRONG. 15 of the 60 Detailed reports declared these columns and their query never
    produced them, so the rows arrived without the one field that says WHICH asset. That is not
    cosmetic for AssetName: the engine's per-row dedup keys on it, and the AI summary resolves assets
    from it. Identity_SPN_OwnsResourcePublicAccess_Detailed collapsed 296 rows to 12 for exactly this
    reason -- with no name, the rows were genuinely indistinguishable.

    WHY THIS GUARD READS THE FINAL PROJECT AND NOT THE WHOLE QUERY. A whole-query search was tried and
    was wrong in BOTH directions: it reported AssetId as "produced" in a report whose final project
    drops it, and cleared a report that computed AssetId in an earlier summarize which the final
    project then discarded. Only the last projection decides what is emitted, so only the last
    projection is inspected here. Ground truth for the fix itself came from running every query with
    `| getschema` against a live workspace -- 47 of 47 answerable reports now emit all three.
#>

BeforeAll {
    $script:SIRoot = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..') ''
    if (-not (Get-Module -Name 'powershell-yaml')) { Import-Module 'powershell-yaml' -Force -ErrorAction Stop }
    $script:Yaml = ConvertFrom-Yaml -Yaml (Get-Content -Raw -LiteralPath (Join-Path (Join-Path $script:SIRoot 'risk-analysis-detection') 'RiskAnalysis_Queries_Locked.yaml'))
    $script:Detailed = @($script:Yaml.Reports | Where-Object { $_.ReportName -like '*_Detailed*' })
    $script:Summary  = @($script:Yaml.Reports | Where-Object { $_.ReportName -like '*_Summary*' })

    # A column is EMITTED when either:
    #   * the report ends with a projection and that projection names it, or
    #   * the report has NO final projection, in which case every extended column flows through.
    # Both shapes are in the catalog: Endpoint_ExcludedAssets_Detailed and
    # Endpoint_ActiveCompromise_Detected_Detailed emit purely by `extend`, and a first version of this
    # guard reported them as defective because it assumed a projection always exists.
    function script:Test-EmitsColumn {
        param([string]$Query, [string]$Column)
        $i = $Query.LastIndexOf('| project')
        $scope = if ($i -lt 0) { $Query } else { $Query.Substring($i) }
        # Token match, not line-anchored: a projection lists columns comma-separated across
        # continuation lines ("AssetName, AssetId, AssetType,"), so anchoring to ^ finds only the
        # first of them. \b also keeps AssetId from matching AssetId_From_CL, and the trailing
        # [,=]/newline keeps it from matching column_ifexists("AssetId", "").
        $scope -match "\b$Column\b\s*(,|=|\r|\n|$)"
    }
}

Describe 'the contract itself -- Detailed declares the asset columns, Summary does not' {

    It 'every Detailed report declares AssetName, AssetId and AssetType' {
        $bad = @($script:Detailed | Where-Object {
            $o = @($_.OutputPropertyOrder)
            ($o -notcontains 'AssetName') -or ($o -notcontains 'AssetId') -or ($o -notcontains 'AssetType')
        })
        @($bad).Count | Should -Be 0 -Because ("these declare fewer than all three: " + (($bad | ForEach-Object { $_.ReportName }) -join ', '))
    }

    It 'no Summary report declares them -- it declares ImpactedAssetsList instead' {
        # Not a gap in the sweep: an aggregate view names the asset SET, not a single asset. This
        # pins that, so a future Summary report cannot quietly acquire a per-row asset column.
        @($script:Summary | Where-Object { @($_.OutputPropertyOrder) -contains 'AssetName' }).Count | Should -Be 0
        @($script:Summary | Where-Object { @($_.OutputPropertyOrder) -notcontains 'ImpactedAssetsList' }).Count | Should -Be 0
    }
}

Describe 'every Detailed report EMITS what it declares' {

    It 'the final projection of every Detailed report carries <Column>' -ForEach @(
        @{ Column = 'AssetName' }, @{ Column = 'AssetId' }, @{ Column = 'AssetType' }
    ) {
        $col = $Column
        $bad = @($script:Detailed | Where-Object {
            -not (script:Test-EmitsColumn -Query ((@($_.ReportQuery)) -join "`n") -Column $col)
        })
        @($bad).Count | Should -Be 0 -Because ("these declare $col but never emit it: " + (($bad | ForEach-Object { $_.ReportName }) -join ', '))
    }

    It 'SELF-CHECK: the detector says NO for a projection that omits the column' {
        # Without a failing case the assertions above could pass by never being able to fail.
        script:Test-EmitsColumn -Query "| project SecurityDomain, Category, ConfigurationName" -Column 'AssetName' | Should -BeFalse
    }

    It 'SELF-CHECK: it says YES for a column listed MID-LINE, not just at line start' {
        # The real catalog lists them comma-separated on a continuation line. A line-anchored pattern
        # missed AssetId/AssetType there and reported a healthy report as defective.
        script:Test-EmitsColumn -Query "| project A, B,`n   AssetName, AssetId, AssetType, C" -Column 'AssetType' | Should -BeTrue
    }

    It 'SELF-CHECK: it is not fooled by AssetId_From_CL or a quoted column_ifexists name' {
        script:Test-EmitsColumn -Query '| project AssetId_From_CL = tostring(x)' -Column 'AssetId' | Should -BeFalse
        script:Test-EmitsColumn -Query '| project Foo = tostring(column_ifexists("AssetId",""))' -Column 'AssetId' | Should -BeFalse
    }
}
