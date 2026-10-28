#Requires -Version 5.1
<#
    EVERY COLLIDING NAME CAN BE SEPARATED, AND NO RESOLVED NAME CHANGES (#129).

    The fallback qualifier was the last 8 alphanumerics of SI_AssetId. For an ARM id that tail is the
    resource name -- exactly what the colliding rows share -- so once the discriminators ran out, the
    5th 'vnet-hub' in same-named resource groups across subscriptions was left Unqualifiable. Also
    '1.2.3.45' vs '12.3.4.5' share the tail '12345'. A short SHA-256 of the full id is now the last
    resort -- and ONLY the last resort, so a name that resolved before resolves identically now.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AssetNameUniqueness.ps1')
    function script:New-Row([string]$Name, [string]$Id, [string]$Rg) {
        [pscustomobject]@{ SI_AssetName = $Name; SI_AssetId = $Id; AzResourceGroup = $Rg }
    }
}

Describe 'the hash fallback separates what the tail cannot' {
    It 'five same-named vnets in same-named RGs across subscriptions all end up UNIQUE' {
        $rows = @(1..5 | ForEach-Object { New-Row 'vnet-hub' ("/subscriptions/sub-$_/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/vnet-hub") 'rg-net' })
        $s = Resolve-SIAssetNameCollisions -Rows $rows -Discriminators @('AzResourceGroup')
        $s.Unqualifiable | Should -Be 0 -Because 'the old tail fallback left members Unqualifiable here'
        @($rows | ForEach-Object { $_.SI_AssetName } | Sort-Object -Unique).Count | Should -Be 5
    }
    It 'two ids whose alphanumeric tails are identical are separated' {
        $rows = @((New-Row 'pip' '1.2.3.45' ''), (New-Row 'pip' '12.3.4.5' ''))
        $s = Resolve-SIAssetNameCollisions -Rows $rows
        $s.Unqualifiable | Should -Be 0
        @($rows | ForEach-Object { $_.SI_AssetName } | Sort-Object -Unique).Count | Should -Be 2
    }
    It 'the hash qualifier is deterministic -- the same id gets the same name every run' {
        $mk = { @(1..5 | ForEach-Object { New-Row 'vnet-hub' ("/subscriptions/sub-$_/resourcegroups/rg-net/providers/microsoft.network/virtualnetworks/vnet-hub") 'rg-net' }) }
        $a = & $mk; $b = & $mk
        $null = Resolve-SIAssetNameCollisions -Rows $a -Discriminators @('AzResourceGroup')
        $null = Resolve-SIAssetNameCollisions -Rows $b -Discriminators @('AzResourceGroup')
        (@($a | ForEach-Object { $_.SI_AssetName }) -join '|') | Should -BeExactly (@($b | ForEach-Object { $_.SI_AssetName }) -join '|')
    }
}

Describe 'names that already resolved are byte-identical' {
    It 'a collision the TAIL separates keeps its tail-qualified name (no churn into the CMDB)' {
        $rows = @((New-Row 'web-01' 'aaaa-1111-bbbb-2222' ''), (New-Row 'web-01' 'cccc-3333-dddd-4444' ''))
        $null = Resolve-SIAssetNameCollisions -Rows $rows
        $rows[1].SI_AssetName | Should -BeExactly ('web-01 ({0})' -f (Get-SIIdFragment -Id 'cccc-3333-dddd-4444'))
    }
    It 'a discriminator-resolved collision is unchanged' {
        $rows = @((New-Row 'kv' 'id-1' 'rg-a'), (New-Row 'kv' 'id-2' 'rg-b'))
        $null = Resolve-SIAssetNameCollisions -Rows $rows -Discriminators @('AzResourceGroup')
        $rows[1].SI_AssetName | Should -BeExactly 'kv (rg-b)'
    }
}
