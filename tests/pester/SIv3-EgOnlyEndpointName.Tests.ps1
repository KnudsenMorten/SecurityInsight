#Requires -Version 5.1
<#
    SI v3 -- A DEVICE THAT EXPOSURE GRAPH NAMES KEEPS THAT NAME AFTER THE UPDATE.

    Measured in the live 2.2.460 -> 3.0 upgrade test (2026-10-05, #261 round 1), two shapes of one defect:
      * five devices only Exposure Graph knows (network-discovered, not onboarded to Defender -- Sonos speakers);
      * a device Defender knows only by its machine id (no computer name) that Exposure Graph names (`kristupaspc`).
    2.2 published the Exposure Graph name for all of them; 3.0 published `unnamed-endpoint-<8>` in SI_AssetName,
    although the row still carried the name in Hostname (first shape).

    Why: in its Exposure Graph branch the collect stage copied Exposure Graph's `deviceName` only into
    MDE_DeviceName (to fill the flat columns, and only when Defender had not filled it) and never set EG_Name --
    the key the endpoint name/id pair reads for the Exposure Graph source. MDE_DeviceName is paired with a
    Defender id, so it could not name the first shape (no Defender id) and held the machine id in the second.
    The collect stage now stores Exposure Graph's own name as EG_Name (Get-SIEgNodeName), unless it is one of
    the device's ids; the pair then takes the Exposure Graph name AND the Exposure Graph node id -- one source.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1')
    function script:Row([hashtable]$Meta, [string]$Primary) {
        $rec = [pscustomobject]@{ PrimaryEntityId = $Primary; Metadata = $Meta }
        $rc  = [pscustomobject]@{ Engine = 'endpoint'; RunId = 't'; CollectionTime = [datetime]::UtcNow.ToString('o') }
        Build-SIEndpointProfileRow -Record $rec -RunContext $rc
    }
    $script:EgId   = '39c558c1a469451b92833e523481f998'
    $script:EgName = '192.168.1.14 - Sonos Play:1 - RINCON_5CAAFDB0DB5801400'
    $script:Mde    = '0c8545c566aa838508be174878084b0c7a9cfd4e'
    $script:Eg2    = '61fe2bb3128e4c9690aa73c0423179b9'
}

Describe 'the collect stage keeps Exposure Graph''s own name for the node' {
    It 'Get-SIEgNodeName returns rawData.deviceName' {
        Get-SIEgNodeName -EgRaw ([pscustomobject]@{ deviceName = $script:EgName }) -Ids @($script:EgId) | Should -Be $script:EgName
        Get-SIEgNodeName -EgRaw @{ deviceName = 'kristupaspc' } -Ids @($script:Mde, $script:Eg2) | Should -Be 'kristupaspc'
    }

    It 'a deviceName that is one of the device''s ids, or empty, or no rawData at all, is not a name' {
        Get-SIEgNodeName -EgRaw ([pscustomobject]@{ deviceName = $script:Mde }) -Ids @($script:Mde, $script:Eg2) | Should -BeNullOrEmpty
        Get-SIEgNodeName -EgRaw ([pscustomobject]@{ deviceName = $script:EgId.ToUpperInvariant() }) -Ids @($script:EgId) | Should -BeNullOrEmpty
        Get-SIEgNodeName -EgRaw ([pscustomobject]@{ deviceName = '' }) -Ids @($script:Mde) | Should -BeNullOrEmpty
        Get-SIEgNodeName -EgRaw $null -Ids @($script:Mde) | Should -BeNullOrEmpty
    }

    It 'WIRING: the Exposure Graph branch of the collect stage stores it as EG_Name' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1')
        $src | Should -Match "_setIfEmpty \`$metadata 'EG_Name' \(Get-SIEgNodeName -EgRaw \`$egRaw"
    }
}

Describe 'the endpoint row then carries that name, paired with the Exposure Graph node id' {
    It 'a device only Exposure Graph knows (no Defender id)' {
        # The metadata the collect stage now builds for it: node id, the mirrored MDE_DeviceName, and EG_Name.
        $row = Row @{ MDE_AssetType = 'Endpoint'; EG_NodeId = $script:EgId; MDE_DeviceName = $script:EgName; EG_Name = $script:EgName } $script:EgId
        [string]$row.SI_AssetName | Should -Be $script:EgName
        [string]$row.SI_AssetId   | Should -Be $script:EgId
    }

    It 'a Defender device with no computer name that Exposure Graph names' {
        $row = Row @{ MDE_AssetType = 'Endpoint'; MDE_DeviceId = $script:Mde; MDE_DeviceName = $script:Mde; EG_NodeId = $script:Eg2; EG_Name = 'kristupaspc' } $script:Mde
        [string]$row.SI_AssetName | Should -Be 'kristupaspc'
        [string]$row.SI_AssetId   | Should -Be $script:Eg2
    }

    It 'with no name anywhere the row still gets the marked synthetic name' {
        $row = Row @{ MDE_AssetType = 'Endpoint'; EG_NodeId = $script:EgId } $script:EgId
        [string]$row.SI_AssetName | Should -Be 'unnamed-endpoint-3481f998'
    }

    It 'control: a Defender device with a name keeps its Defender name and id' {
        $row = Row @{ MDE_AssetType = 'Endpoint'; MDE_DeviceId = 'a' * 40; MDE_DeviceName = 'laptop-7.contoso.local'; EG_NodeId = $script:EgId; EG_Name = 'laptop-7' } ('a' * 40)
        [string]$row.SI_AssetName | Should -Be 'laptop-7.contoso.local'
        [string]$row.SI_AssetId   | Should -Be ('a' * 40)
    }
}
