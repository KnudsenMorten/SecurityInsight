#Requires -Version 5.1
<#
    AN EXPOSURE GRAPH RECORD CARRIES ITS STRONG IDS. Exposure Graph's EntityIds is an array of JSON TEXT, one string per id
    (["{\"type\":\"DeviceInventoryId\",\"id\":\"...\"}"], read live 2026-10-11). The mapping's select: normalisation did not read
    an element that is JSON text, so no Exposure Graph device / resource record carried its Defender device id or resource id:
    the CI build never joined it with its Defender / Azure record, the two groups collided on one CI id and the Defender one was
    dropped (ring 1: 211 of 218 device CIs without their Defender link; every CVE finding without its CI). A device Defender only
    discovered (not onboarded) names its Defender id as DeviceInventoryId -- the mapping takes it when SenseDeviceId is absent.
    Offline, pure functions. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldMapper.ps1')
    $script:Map = Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\mappings\eg.locked.json') -Raw | ConvertFrom-Json
    function script:ChainOf([string]$Field, [string]$RecordType) {
        @(@($script:Map.mappings) | Where-Object { $_.field -eq $Field -and @($_.recordTypes) -contains $RecordType } | Select-Object -First 1).normalize
    }
    function script:L([object[]]$v) { $l = New-Object 'System.Collections.Generic.List[object]'; foreach ($x in $v) { $l.Add($x) }; , $l }
    # the shape advanced hunting returns
    $script:EntityIds = [object[]]@('{"type":"DeviceInventoryId","id":"024A9DBF32807AF2A298577E90E2B696B06E4D12"}',
                                    '{"type":"AzureResourceId","id":"/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1"}',
                                    '{"type":"AadDeviceId","id":"07F8CE69-5B5D-4F31-97FA-9E5B4FE3684E"}')
}

Describe 'select: reads EntityIds elements that are JSON text' {
    It 'the whole array as one value' {
        @((Invoke-SINormalizeOp -Values (script:L @(, $script:EntityIds)) -Op select -Arg 'type=AadDeviceId:id').ToArray()) | Should -Be @('07F8CE69-5B5D-4F31-97FA-9E5B4FE3684E')
    }
    It 'the elements as values' {
        @((Invoke-SINormalizeOp -Values (script:L $script:EntityIds) -Op select -Arg 'type=AzureResourceId:id').ToArray()) | Should -Be @('/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/VM1')
    }
    It 'alternatives: the first alternative''s values come first' {
        $both = [object[]]@('{"type":"DeviceInventoryId","id":"inv"}', '{"type":"SenseDeviceId","id":"sense"}')
        @((Invoke-SINormalizeOp -Values (script:L @(, $both)) -Op select -Arg 'type=SenseDeviceId|DeviceInventoryId:id').ToArray()) | Should -Be @('sense', 'inv')
    }
    It 'objects and a single object (a condition on rawData) still work' {
        @((Invoke-SINormalizeOp -Values (script:L @([pscustomobject]@{ type = 'AadDeviceId'; id = 'g' })) -Op select -Arg 'type=AadDeviceId:id').ToArray()) | Should -Be @('g')
        @((Invoke-SINormalizeOp -Values (script:L @('not json')) -Op select -Arg 'type=AadDeviceId:id').ToArray()) | Should -BeNullOrEmpty
    }
}

Describe 'the eg mapping gives a device record its Defender, Entra and Azure ids' {
    It 'mde_device_id from SenseDeviceId, else DeviceInventoryId (one value, lower-cased)' {
        @((Invoke-SINormalize -Values (script:L @(, $script:EntityIds)) -Chain (script:ChainOf 'mde_device_id' 'device')).ToArray()) | Should -Be @('024a9dbf32807af2a298577e90e2b696b06e4d12')
        $sense = [object[]]@('{"type":"SenseDeviceId","id":"ABC"}', '{"type":"DeviceInventoryId","id":"ABC"}')
        @((Invoke-SINormalize -Values (script:L @(, $sense)) -Chain (script:ChainOf 'mde_device_id' 'device')).ToArray()) | Should -Be @('abc')
    }
    It 'entra_device_id and azure_resource_id' {
        @((Invoke-SINormalize -Values (script:L @(, $script:EntityIds)) -Chain (script:ChainOf 'entra_device_id' 'device')).ToArray()) | Should -Be @('07f8ce69-5b5d-4f31-97fa-9e5b4fe3684e')
        @((Invoke-SINormalize -Values (script:L @(, $script:EntityIds)) -Chain (script:ChainOf 'azure_resource_id' 'azure_resource')).ToArray()) | Should -Be @('/subscriptions/s/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm1')
    }
}
