#Requires -Version 5.1
<#
    ONE MACHINE = ONE ASSET, ONE NAME, ONE TIER -- in the reports and in classification.

    Measured 2026-10-02 (operator: "i dont like correlation is not working", "this is same device", "it must also work
    with classification so it gets same tier"):
      * the Top 50 listed one server twice -- MGMT1 (153 findings) and mgmt1.2linkit.local (35). The device reports
        carried the right asset id under ExposureGraph's name; the Azure reports carried the VM's ARM id, which the
        endpoint profile records on that same device since #204. Every later step grouped by NAME.
      * mgmt1, dc1 and dc3 were tier 0 as devices and tier 3 as VMs.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AssetIdentityMap.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\EndpointAzureCorrelationCache.ps1')
    function script:Set-TestIdentityMap {
        $dev = [pscustomobject]@{ Id = 'fa6a7a3b-246e-40e6-be2d-ac527133da0e'; Name = 'MGMT1'; Type = 'Server'; Table = 'SI_Endpoint_Profile_CL' }
        $shell = [pscustomobject]@{ Id = 'eg:az:9d4f6d2ec54b426ea8e4e95f8e3578a5'; Name = '9d4f6d2ec54b426ea8e4e95f8e3578a5'; Type = 'AzureResource'; Table = 'SI_Azure_Profile_CL' }
        $kv = [pscustomobject]@{ Id = 'az:/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1'; Name = 'kv1'; Type = 'KeyVault'; Table = 'SI_Azure_Profile_CL' }
        $script:_SIIdentityById = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $script:_SIIdentityById[$dev.Id] = $dev; $script:_SIIdentityById[$shell.Id] = $shell; $script:_SIIdentityById[$kv.Id] = $kv
        $script:_SIIdentityByArm = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $script:_SIIdentityByArm['/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/mgmt1'] = $dev
        $script:_SIIdentityByEg = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $script:_SIIdentityByEg['7d4f6d2ec54b426ea8e4e95f8e3578a5'] = $dev
    }
}

Describe 'the reports: a resolved identity names its asset' {
    BeforeEach { Set-TestIdentityMap }
    It 'a device id named by ExposureGraph takes the profile''s name' {
        $c = Resolve-SICanonicalAsset -Name 'mgmt1.2linkit.local' -Id 'fa6a7a3b-246e-40e6-be2d-ac527133da0e'
        $c.Name | Should -Be 'MGMT1'; $c.Changed | Should -BeTrue
    }
    It 'an Azure VM id (any case, with or without az:) becomes the device that IS that VM' {
        $c = Resolve-SICanonicalAsset -Name 'mgmt1' -Id 'az:/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/MGMT1'
        $c.Id | Should -Be 'fa6a7a3b-246e-40e6-be2d-ac527133da0e'; $c.Name | Should -Be 'MGMT1'
    }
    It 'an ExposureGraph shell for the VM becomes the device with the same graph node' {
        (Resolve-SICanonicalAsset -Name '7d4f6d2ec54b426ea8e4e95f8e3578a5' -Id 'eg:az:7D4F6D2EC54B426EA8E4E95F8E3578A5').Name | Should -Be 'MGMT1'
        # the attack-path reports carry the BARE node id (dc1 / dc3 showed twice in the Top 50 because of it)
        (Resolve-SICanonicalAsset -Name 'mgmt1.2linkit.local' -Id '7d4f6d2ec54b426ea8e4e95f8e3578a5').Id | Should -Be 'fa6a7a3b-246e-40e6-be2d-ac527133da0e'
        (Resolve-SICanonicalAsset -Name 'x' -Id 'fd73f1d478c5140aa1b9244bcc8286bce88d18e7').Changed | Should -BeFalse -Because 'a 40-hex MDE id is not a graph node'
    }
    It '🔴 a profile "name" that is only an id never replaces a real name' {
        $c = Resolve-SICanonicalAsset -Name 'storage-vm-disk' -Id 'eg:az:9d4f6d2ec54b426ea8e4e95f8e3578a5'
        $c.Name | Should -Be 'storage-vm-disk'
        Test-SIAssetNameIsId 'fd73f1d478c5140aa1b9244bcc8286bce88d18e7' | Should -BeTrue
        Test-SIAssetNameIsId 'MGMT1' | Should -BeFalse
    }
    It 'an id the map does not know, and an empty id, are left exactly as they were' {
        (Resolve-SICanonicalAsset -Name 'x' -Id 'unknown-id').Changed | Should -BeFalse
        (Resolve-SICanonicalAsset -Name 'x' -Id '').Changed | Should -BeFalse
    }
    It 'a row''s list: one machine named three ways is ONE entry; another asset stays; the ids stay aligned' {
        $r = ConvertTo-SICanonicalAssetPairs -Names @('mgmt1.2linkit.local', 'kv1', 'mgmt1', 'MGMT1') `
                -Ids @('fa6a7a3b-246e-40e6-be2d-ac527133da0e', 'az:/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1', 'az:/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/mgmt1', 'fa6a7a3b-246e-40e6-be2d-ac527133da0e')
        $r.Changed | Should -BeTrue
        @($r.Names) | Should -Be @('MGMT1', 'kv1')
        @($r.Ids)[0] | Should -Be 'fa6a7a3b-246e-40e6-be2d-ac527133da0e'
    }
    It '🔴 two machines that only share a NAME stay two (the key is the id)' {
        $r = ConvertTo-SICanonicalAssetPairs -Names @('dc1', 'dc1') -Ids @('id-a', 'id-b')
        @($r.Names).Count | Should -Be 2
    }
    It 'the identity map reads each device''s Azure id and graph node, and a VM claimed by two devices links to nothing' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AssetIdentityMap.ps1')
        $src | Should -Match 'AzureResourceId = tolower\(tostring\(column_ifexists\("AzureResourceId",""\)\)\)'
        $src | Should -Match 'EgNodeId = tolower\(tostring\(column_ifexists\("ExposureGraphNodeId",""\)\)\)'
        $src | Should -Match 'foreach \(\$ak in \$armCollisions\) \{ \[void\]\$byArm\.Remove\(\$ak\) \}'
        $src | Should -Match 'foreach \(\$ek in \$egCollisions\) \{ \[void\]\$byEg\.Remove\(\$ek\) \}'
        $src | Should -Match 'Seen = CollectionTime'
        @([regex]::Matches($src, 'Add-SIIdentityClaim -Map \$by(Arm|Eg) ')).Count | Should -Be 2
    }
    It '🔴 a merged device''s NEWER row wins the graph node its stale twin still claims; same-snapshot claimants still link to nothing (live 2026-10-02)' {
        $map = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $col = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $node = '0b92ed443c544007bfd3c555c1b87775'
        $twin = [pscustomobject]@{ Id = $node; Name = 'unnamed-endpoint-c1b87775'; Seen = (ConvertTo-SIIdentitySeen '2026-10-02T05:20:00Z') }
        $dev  = [pscustomobject]@{ Id = '336d75ff'; Name = 'pimhybridwrk.2linkit.local'; Seen = (ConvertTo-SIIdentitySeen '2026-10-02T06:07:00Z') }
        Add-SIIdentityClaim -Map $map -Collisions $col -Key $node -Entry $dev
        Add-SIIdentityClaim -Map $map -Collisions $col -Key $node -Entry $twin
        $map[$node].Name | Should -Be 'pimhybridwrk.2linkit.local'; $col.Count | Should -Be 0
        $map2 = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        $col2 = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        Add-SIIdentityClaim -Map $map2 -Collisions $col2 -Key $node -Entry $twin
        Add-SIIdentityClaim -Map $map2 -Collisions $col2 -Key $node -Entry ([pscustomobject]@{ Id = 'other'; Name = 'other'; Seen = $twin.Seen })
        $col2.Contains($node) | Should -BeTrue
        Add-SIIdentityClaim -Map $map2 -Collisions $col2 -Key $node -Entry $dev
        $col2.Contains($node) | Should -BeFalse -Because 'a newer snapshot settles an older conflict'
        (ConvertTo-SIIdentitySeen $null) | Should -Be ([datetime]::MinValue)
    }
}

Describe 'the Top 50: one entry per asset id' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowShaping.ps1')
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RARowAssetKeys' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    It 'a Summary row''s names key on their aligned ids' {
        $row = [pscustomobject]@{ ImpactedAssetsList = @('MGMT1', 'kv1'); ImpactedAssetIds = @('ID-1', 'id-2') }
        @(Get-RARowAssetKeys -Row $row -Names @('MGMT1', 'kv1')) | Should -Be @('id:id-1', 'id:id-2')
    }
    It 'a Detailed row keys on its AssetId; a list that does not line up falls back to names, never a guess' {
        @(Get-RARowAssetKeys -Row ([pscustomobject]@{ AssetId = 'ID-9' }) -Names @('dc3')) | Should -Be @('id:id-9')
        @(Get-RARowAssetKeys -Row ([pscustomobject]@{ ImpactedAssetIds = @('a') }) -Names @('x', 'y')) | Should -Be @('name:x', 'name:y')
    }
    It 'WIRING -- Add-AssetAgg aggregates on the key, the rollup and the Detailed collapse pass it, and the helper exists before its first use' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $src | Should -Match '\$aggKey = if \(\[string\]::IsNullOrWhiteSpace\(\$Key\)\)'
        $src | Should -Match '-MoreDetails \$rowMoreDetails -Key \$aKey'
        $src | Should -Match '\$key\s+= "\{0\}\|\{1\}" -f \$aKey, \$bucket'; $src | Should -Match 'if \(-not \$collapseSeen\.Add\(\$key\)\) \{ continue \}'
        $src.IndexOf('function Get-RARowAssetKeys') | Should -BeLessThan $src.IndexOf('Get-RARowAssetKeys -Row')
    }
    It 'WIRING -- Summary rows are canonicalised after their ids are resolved; Detailed rows after the trace stamp' {
        (Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')) | Should -Match 'ConvertTo-SICanonicalAssetPairs -Names'
        $ra = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        # the trace stamp is Set-RATraceIdentity (_shared/RA-RowShaping.ps1)
        $ra.IndexOf('Set-RATraceIdentity -Rows') | Should -BeGreaterThan 0
        $ra.IndexOf('Resolve-SICanonicalAsset -Name') | Should -BeGreaterThan $ra.IndexOf('Set-RATraceIdentity -Rows')
    }
}

Describe 'classification: an Azure VM takes the tier of the device it is' {
    It 'the same-machine match carries the device''s tier and says why' {
        $m = Get-SISameMachineTierMatch -Device ([pscustomobject]@{ MdeDeviceId = 'fd73'; Tier = 0; Name = 'MGMT1' })
        $m.RuleId | Should -Be 'SameMachineAsDevice'; $m.Tier | Should -Be 0; $m.Purpose | Should -Be 'Same machine as device MGMT1'
        Get-SISameMachineTierMatch -Device $null | Should -BeNullOrEmpty
        Get-SISameMachineTierMatch -Device ([pscustomobject]@{ MdeDeviceId = 'x'; Tier = $null; Name = 'n' }) | Should -BeNullOrEmpty
    }
    It 'the device lookup is case-insensitive on the VM id and empty for an unknown one' {
        $script:_SIEndpointAzureCorrelation = @{ Initialized = $true; Map = @{}; Devices = @{ '/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/mgmt1' = [pscustomobject]@{ MdeDeviceId = 'fd73'; Tier = 0; Name = 'MGMT1' } }; Source = 'la'; Count = 1 }
        (Get-SIEndpointDeviceForAzureResource -AzureResourceId '/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/MGMT1').Tier | Should -Be 0
        Get-SIEndpointDeviceForAzureResource -AzureResourceId '/subscriptions/s/x' | Should -BeNullOrEmpty
    }
    It '🔴 the bridge reads only recent snapshots and drops a VM id that two devices claim' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\shared\EndpointAzureCorrelationCache.ps1')
        $src | Should -Match 'where TimeGenerated > ago\(8d\)'
        $src | Should -Match '_devices = dcount\(_mdeid\)'
        $src | Should -Match '\| where _devices == 1'
    }
    It 'WIRING -- the Profile stage adds the match for an azure VM / Arc machine, before the tier MIN, and only one way' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Profile.ps1')
        $src | Should -Match "if \(\`$engine -eq 'azure' -and -not \`$global:SI_DisableEndpointAzureCorrelation\)"
        $src | Should -Match 'Get-SISameMachineTierMatch -Device \(Get-SIEndpointDeviceForAzureResource'
        $src.IndexOf('Get-SISameMachineTierMatch') | Should -BeLessThan $src.IndexOf("Name 'SI_RuleTier'")
        @([regex]::Matches($src, 'SI_Azure_Profile_CL')).Count | Should -Be 0 -Because 'the device never reads the VM back -- a merged tier must not hold itself in place'
    }
    It '🔴 the per-asset loop never uses -match -- its rule-match list is named $matches, which -match overwrites (broke the azure run, 2026-10-02)' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Profile.ps1')
        $loop = $src.Substring($src.IndexOf('foreach ($r in $records)'), $src.IndexOf("Name 'SI_RuleMatches'") - $src.IndexOf('foreach ($r in $records)'))
        $code = ($loop -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match '\s-c?i?match\s'
    }
}

Describe 'discovery: the Defender and ExposureGraph records of one device merge on the Defender id' {
    BeforeAll {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Merge-SIDiscoverRecordsByMdeId' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        function script:Rec($key, $source, $name, $fields) {
            $raw = @{ Source = $source; Name = $name } + $fields
            @{ AssetId = "${source}:$key"; Source = $source; Hint = 'endpoint'; Name = $name; NormalizedKey = $key; Sources = @($source); Raw = @($raw) } + $fields
        }
        $script:Pri = @{ 'MDEDevice' = 2; 'EndpointExposureGraph' = 3 }
        $script:Res = @('AssetId', 'Source', 'Hint', 'Name', 'NormalizedKey', 'Sources', 'Raw')
    }
    It 'the MDE record (short name) and the graph record (FQDN) of one device become ONE record with both sources' {
        $by = @{
            'pimhybridwrk'               = (Rec 'pimhybridwrk' 'MDEDevice' 'pimhybridwrk.2linkit.local' @{ MDE_DeviceId = '336D75FF' })
            'pimhybridwrk.2linkit.local' = (Rec 'pimhybridwrk.2linkit.local' 'EndpointExposureGraph' 'pimhybridwrk.2linkit.local' @{ EG_MdeDeviceId = '336d75ff'; EG_NodeId = '0b92ed44' })
        }
        $r = Merge-SIDiscoverRecordsByMdeId -ByKey $by -ReservedKeys $script:Res -SourcePriority $script:Pri
        $r.Merged | Should -Be 1
        $by.Count | Should -Be 1
        $one = @($by.Values)[0]
        @($one.Sources | Sort-Object) | Should -Be @('EndpointExposureGraph', 'MDEDevice')
        $one.EG_NodeId | Should -Be '0b92ed44'
        $one.MDE_DeviceId | Should -Be '336D75FF'
    }
    It '🔴 two machines are never fused: different ids stay apart, and a record carrying two Defender ids is refused' {
        $by = @{
            'a' = (Rec 'a' 'MDEDevice' 'a' @{ MDE_DeviceId = 'id-a' })
            'b' = (Rec 'b' 'EndpointExposureGraph' 'b' @{ EG_MdeDeviceId = 'id-b' })
            'c' = (Rec 'c' 'MDEDevice' 'c' @{ MDE_DeviceId = 'id-c'; EG_MdeDeviceId = 'id-x' })
        }
        $r = Merge-SIDiscoverRecordsByMdeId -ByKey $by -ReservedKeys $script:Res -SourcePriority $script:Pri
        $r.Merged | Should -Be 0; $r.Refused | Should -Be 1; $by.Count | Should -Be 3
    }
    It 'WIRING -- discovery runs the pass after the Entra-id pass, and the graph source reads the node''s EntityIds' {
        $d = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Discover.ps1')
        $d.IndexOf('Merge-SIDiscoverRecordsByMdeId -ByKey $byKey') | Should -BeGreaterThan $d.IndexOf('foreach ($k in $keysToDrop) { [void]$byKey.Remove($k) }')
        $g = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEndpointViaEG.ps1')
        $g | Should -Match '\| project NodeId, NodeName, NodeLabel, EntityIds,'
        $g | Should -Match "if \(\`$ty -eq 'SenseDeviceId'"
        $g | Should -Match 'EG_MdeDeviceId        = \$egMde'
        $g | Should -Match 'EG_AzureResourceId    = \$\(if \(\$egArm\.Count -eq 1\)'
    }
}

Describe 'tier enrichment reads the Entra device id Defender actually provides (#205)' {
    BeforeAll {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SIRecordAadDeviceId' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        $script:EnrichSrc = $src
    }
    It 'MDE_AadDeviceId -- the key MDE discovery emits -- is read when the graph has none' {
        Get-SIRecordAadDeviceId -Metadata @{ MDE_AadDeviceId = 'aad-1' } | Should -Be 'aad-1'
        Get-SIRecordAadDeviceId -Metadata ([pscustomobject]@{ MDE_AadDeviceId = 'aad-2' }) | Should -Be 'aad-2'
    }
    It 'an EG key that is present but empty does not stop the lookup; the graph''s own id still comes first' {
        Get-SIRecordAadDeviceId -Metadata @{ EG_AadDeviceId = ''; MDE_AadDeviceId = 'aad-1' } | Should -Be 'aad-1'
        Get-SIRecordAadDeviceId -Metadata @{ EG_AadDeviceId = 'aad-eg'; MDE_AadDeviceId = 'aad-1' } | Should -Be 'aad-eg'
    }
    It 'the zero GUID and an empty record are no id' {
        Get-SIRecordAadDeviceId -Metadata @{ MDE_AadDeviceId = '00000000-0000-0000-0000-000000000000' } | Should -BeNullOrEmpty
        Get-SIRecordAadDeviceId -Metadata $null | Should -BeNullOrEmpty
    }
    It 'WIRING -- both the map build and the per-record lookup use it; the dead key is read nowhere else' {
        @([regex]::Matches($script:EnrichSrc, 'Get-SIRecordAadDeviceId -Metadata \$r\.Metadata')).Count | Should -Be 2
        @([regex]::Matches($script:EnrichSrc, "'MDE_AzureADDeviceId'")).Count | Should -Be 1 -Because 'only as the last, legacy fallback inside the function'
    }
}