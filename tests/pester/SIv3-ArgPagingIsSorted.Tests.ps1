#Requires -Version 5.1
<#
    EVERY PAGED RESOURCE GRAPH QUERY IN THE PROFILING ENGINES SORTS (#149).

    Resource Graph pages an UNSORTED result inconsistently. Measured on the internal tenant 2026-09-28
    reading all 9,618 Defender for Cloud assessments: unsorted, each read repeated 222-226 rows across pages
    AND skipped as many (8,593 distinct entities instead of 8,819) -- a silent loss behind a total that
    looked right. Sorted: 9,618 distinct, 0 repeats, identical on two reads.
    Every query text these files page with is lifted from the source and must contain `order by`.
#>

BeforeDiscovery {
    $script:Files = @(
        @{ Rel = 'engine\asset-profiling\discovery\AzureResourceTypeQueries.ps1'; Min = 23 }
        @{ Rel = 'engine\asset-profiling\discovery\Get-DiscoveryFromShodan.ps1';  Min = 1 }
        @{ Rel = 'engine\asset-profiling\discovery\Get-DiscoveryFromARG.ps1';     Min = 1 }
        @{ Rel = 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1'; Min = 1 }
        @{ Rel = 'engine\asset-profiling\shared\AzureParentScopeCache.ps1';       Min = 3 }
        @{ Rel = 'engine\asset-profiling\shared\RuleIndexes.ps1';                 Min = 3 }
    )
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    # Every here-string whose text starts with an ARG table (resources / resourcecontainers / securityresources).
    function script:Get-ArgQueries([string]$Path) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        @($ast.FindAll({ param($n)
            ($n -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $n -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and
            $n.StringConstantType -in 'SingleQuotedHereString','DoubleQuotedHereString' -and
            $n.Value -match '(?m)^\s*(resources|resourcecontainers|securityresources)\s*$'
        }, $true) | ForEach-Object { $_.Value })
    }
}

Describe '<Rel>' -ForEach $script:Files {
    It 'every Resource Graph query sorts' {
        $qs = Get-ArgQueries (Join-Path $script:SIRoot $Rel)
        $qs.Count | Should -BeGreaterOrEqual $Min
        $unsorted = @($qs | Where-Object { $_ -notmatch '(?m)^\|\s*(order|sort) by\b' })
        $unsorted.Count | Should -Be 0 -Because (($unsorted | ForEach-Object { ($_ -split "`n" | Select-Object -First 3) -join ' / ' }) -join ' || ')
    }
}

Describe 'the Defender recommendation collector' {
    It 'sorts by assessment id' {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderRecommendations.ps1')
        Get-SIDefenderRecommendationKql | Should -Match '(?m)^\| order by id asc'
    }
}
