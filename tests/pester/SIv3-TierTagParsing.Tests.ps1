#Requires -Version 5.1
<#
    #690 (11) -- Endpoint_ConflictingTierTags_* READ THE TAGS AS TAGS (report certification #688, review-ABD A3).

    Before: the reports split tolower(tostring(si_tags)) -- the JSON text of the {source, name, value} array -- on commas,
    so the output carried JSON fragments (name":"pawdevices--tier0--si), a tag with a comma broke, and tier([0-9]) saw
    only "tier0" written together (not "Tier 0" / "tier-0" / "tier_0"), took tier 4-9 as tiers, and a CI without an
    engine tier was shown as tier 3 (coalesce(si_tier, 3)).
    Now: mv-expand over the si_tags dynamic array, each tag's name (=value) read as text, its source named; the tier
    pattern accepts tier0 / Tier 0 / tier-0 / tier_0 / Tier=0 in any case, only 0-3; a missing engine tier says why (not tiered, no tier rule matches).
    Offline: the pattern is taken from the shipped YAML and run with .NET's regex (the same semantics as KQL's RE2 for
    this pattern); the query shape is asserted on the YAML. Nothing runs a query.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml
    function script:QueryOf([string]$Name) { (@(@($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0].ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" }
    $script:Names = @('Endpoint_ConflictingTierTags_Detailed', 'Endpoint_ConflictingTierTags_Summary')
    function script:TierPattern([string]$Name) {
        $m = [regex]::Match((QueryOf $Name), '_tier\s*=\s*extract\(@"(?<p>[^"]+)",\s*1,\s*_tagText\)')
        $m.Success | Should -BeTrue -Because "$Name reads the tier from the tag text with one extract()"
        $m.Groups['p'].Value
    }
    function script:TierOf([string]$Pattern, [string]$Text) { $m = [regex]::Match($Text, $Pattern); if ($m.Success) { $m.Groups[1].Value } else { '' } }
}

Describe 'the tier a tag claims' {
    It 'accepts tier0 / Tier 0 / tier-0 / tier_0 / TIER0 / Tier=0 (any case) in <_>' -ForEach @('Endpoint_ConflictingTierTags_Detailed', 'Endpoint_ConflictingTierTags_Summary') {
        $p = TierPattern $_
        foreach ($case in @(
            @('pawdevices--tier0--si', '0'), @('Tier 0', '0'), @('tier-1', '1'), @('tier_2', '2'), @('TIER3', '3'), @('EmployeeWorkstations Tier 3', '3'),
            @('Tier=0', '0'), @('Criticality=Tier 1', '1'), @('tier: 2', '2'), @('ServersTier1', '1'))) {
            (TierOf $p $case[0]) | Should -Be $case[1] -Because ("'{0}' claims tier {1}" -f $case[0], $case[1])
        }
    }
    It 'rejects what is not a tier 0-3 claim in <_>' -ForEach @('Endpoint_ConflictingTierTags_Detailed', 'Endpoint_ConflictingTierTags_Summary') {
        $p = TierPattern $_
        foreach ($t in 'tier4', 'Tier 9', 'tier10', 'tier 12', 'production', 'teir0', 'tierX') {
            (TierOf $p $t) | Should -BeNullOrEmpty -Because "'$t' is not a tier 0-3 claim"
        }
    }
}

Describe 'the tags are read as the dynamic array they are' {
    It '<_> expands si_tags as an array and never splits its JSON text' -ForEach @('Endpoint_ConflictingTierTags_Detailed', 'Endpoint_ConflictingTierTags_Summary') {
        $q = QueryOf $_
        $q | Should -Match 'mv-expand _t = si_tags to typeof\(dynamic\)'
        $q | Should -Not -Match 'split\(si_tags_'
        $q | Should -Match 'tostring\(_t\.name\)'
        $q | Should -Match 'tostring\(_t\.value\)'
        $q | Should -Match 'tostring\(_t\.source\)' -Because 'the fix is made in the system that set the tag'
        $q | Should -Not -Match 'tier\(\[0-9\]\)'
    }
    It 'the Detailed report keeps every tag of the asset in AssetTags (as text, not JSON) and never shows an unknown engine tier as 3' {
        $q = QueryOf 'Endpoint_ConflictingTierTags_Detailed'
        $q | Should -Not -Match 'coalesce\(si_tier,\s*3\)'
        $q | Should -Not -Match 'strcat_array\(si_tags'
        $q | Should -Match 'AssetTags = strcat_array\(array_sort_asc\(_allTags\)'
        $q | Should -Match '_engineTier = iff\(isnull\(_tierCol\), "not tiered \(no tier rule matches\)", tostring\(_tierCol\)\)'
        $q | Should -Match ([regex]::Escape('The engine has no tier for this asset yet - no tier rule matches it.'))
        $q | Should -Not -Match '"Unknown"' -Because 'a missing tier is labelled by its cause, never Unknown'
    }
}
