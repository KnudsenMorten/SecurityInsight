#Requires -Version 5.1
<#
    THE DEFENDER HAND-OFF LOOKUP MUST STAY SMALL ENOUGH TO SEND.

    Measured in the live 2.2.460 -> 3.0 upgrade test (2026-10-05, #261 round 1): Risk Analysis -Summary never
    finished. Azure_Recommendations_Summary runs in Advanced Hunting with the Log Analytics lookups inlined as
    datatables, and the request body is capped at 1 MB. The hand-off lookup `_dfcPairs` (every
    (resource, recommendation) pair Defender for Cloud reports, by name AND by ARM id -- 3,317 keys from
    1,681 recommendations) was inlined as full text: 464 KB, copied into EVERY bucket because it has no
    bucket key. With the report's other name/path lookups that was over the cap at any bucket count, so the
    engine escalated 2 -> 4 -> ... -> 1024 buckets at ~100 s each (more than a day for one report).

    The pairs are now compared as a short hash of the same lower-cased text on both sides (KQL hash(),
    xxhash64 -- measured identical in Log Analytics and Advanced Hunting), prefixed with a letter so the
    inliner keeps the column a string (an all-digit column is inlined as `long`, and a string = long join
    is a type error). ~28 bytes a key instead of ~140.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    $script:Y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:Graph = foreach ($g in 'Summary', 'Detailed') {
        [regex]::Match($script:Y, "(?s)- ReportName: Azure_Recommendations_$g\r?\n.*?(?=\r?\n    - ReportName: |\z)").Value
    }
    $script:Hashed = 'strcat("h", tostring(hash(strcat('
}

Describe 'both graph recommendation reports compare the hand-off pairs as short hashes' {
    It 'the report blocks are found' {
        @($script:Graph | Where-Object { $_.Length -gt 1000 }).Count | Should -Be 2
    }

    It 'the lookup hashes the name pair and the ARM id pair' {
        foreach ($b in $script:Graph) {
            $let = [regex]::Match($b, '(?s)let _dfcPairs = .*?;').Value
            $let | Should -Match ([regex]::Escape('_keys = make_set(' + $script:Hashed + 'tolower(tostring(ResourceName))'))
            $let | Should -Match ([regex]::Escape('_ids = make_set_if(' + $script:Hashed + 'tolower(tostring(ResourceIdLower))'))
        }
    }

    It 'the report side builds its two keys the same way' {
        foreach ($b in $script:Graph) {
            $b | Should -Match ([regex]::Escape('| extend _dfcKey = ' + $script:Hashed + 'tolower(tostring(AssetName))'))
            # #505 -- the ARM id side is the graph node's AssetArmId (the CI link key), no longer peeled out of an
            # "az:"-prefixed profile AssetId. It must be lower-case, like ResourceIdLower on the Defender side.
            $b | Should -Match ([regex]::Escape('_dfcIdKey = iff(isnotempty(AssetArmId), ' + $script:Hashed + 'AssetArmId, "|", tolower(tostring(FindingName))'))
            $b | Should -Match ([regex]::Escape('| extend _armId = tolower(coalesce(extract('))
            $b | Should -Match ([regex]::Escape('| extend _egHierarchyId = tolower(tostring(NodeProperties.rawData.hierarchyIdentifier))'))
            $b | Should -Match ([regex]::Escape('strcat("/subscriptions/", _egHierarchyId, "/resourcegroups/", tolower(tostring(NodeName)))'))
            $b | Should -Match ([regex]::Escape('| extend AssetArmId = iff(isnotempty(_armId), _armId, _scopeArmId)'))
        }
    }

    It 'no plain-text pair is left on either side' {
        foreach ($b in $script:Graph) {
            $b | Should -Not -Match '_keys = make_set\(strcat\(tolower'
            $b | Should -Not -Match '_ids = make_set_if\(strcat\(tolower'
            $b | Should -Not -Match '_dfcKey = strcat\(tolower'
        }
    }
}

Describe 'the inlined lookup stays a small string column' {
    It 'prefixed hash keys are inlined as string (an all-digit column would become long)' {
        $rows = @([pscustomobject]@{ _dfcKey = 'h7045401300756806514' }, [pscustomobject]@{ _dfcKey = 'h-12345' })
        Convert-RowsToKqlDatatable -LetVarName '_dfcPairs' -Rows $rows | Should -Match 'datatable\(_dfcKey:string\)'
        $digits = @([pscustomobject]@{ _dfcKey = '7045401300756806514' })
        Convert-RowsToKqlDatatable -LetVarName '_dfcPairs' -Rows $digits | Should -Match 'datatable\(_dfcKey:long\)' -Because 'this is the trap the prefix avoids'
    }

    It '3,317 keys (the measured install) inline well under the 1 MB request cap' {
        $rnd = New-Object System.Random 7
        $rows = for ($i = 0; $i -lt 3317; $i++) { [pscustomobject]@{ _dfcKey = 'h' + ([int64]$rnd.Next() * [int64]$rnd.Next()).ToString() } }
        $dt = Convert-RowsToKqlDatatable -LetVarName '_dfcPairs' -Rows $rows
        $dt.Length | Should -BeLessThan 120000
    }
}
