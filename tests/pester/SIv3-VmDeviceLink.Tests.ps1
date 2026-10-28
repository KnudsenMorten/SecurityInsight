#Requires -Version 5.1
<#
    AN AZURE VM AND ITS DEFENDER DEVICE CARRY ONE SHARED IDENTIFIER (#204).

    Measured 2026-10-02 on the object map: 4 Azure VMs, 0 correlated with their device -- mgmt1 was two
    objects (the device + an Exposure Graph shell, and the ARM VM on its own). The Exposure Graph carries no
    ARM id, so the bridge is Defender's own record: /api/machines returns the VM's ARM id in
    vmMetadata.resourceId (9 of 206 machines here). The endpoint row builder always read MDE_AzureResourceId
    into the AzureResourceId column and the correlation identifiers; nothing ever produced it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Build-EndpointProfileRow.ps1')
    function script:Row([hashtable]$Meta) {
        $rec = [pscustomobject]@{ PrimaryEntityId = 'mde-1'; Metadata = $Meta }
        $rc  = [pscustomobject]@{ Engine = 'endpoint'; RunId = 't'; CollectionTime = [datetime]::UtcNow.ToString('o') }
        Build-SIEndpointProfileRow -Record $rec -RunContext $rc
    }
    function script:Ids($row, [string]$type) { @($row.EntityIds | Where-Object { $_.type -eq $type } | ForEach-Object { [string]$_.id }) }
    $script:Arm = '/subscriptions/S/resourceGroups/RG-MGMT/providers/Microsoft.Compute/virtualMachines/MGMT1'
}

Describe 'Defender discovery hands over the VM''s ARM id (#204)' {
    It 'MDE_AzureResourceId is read from vmMetadata.resourceId, and is null when Defender has none' {
        $src = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromMDE.ps1')
        $src | Should -Match 'MDE_AzureResourceId\s*=\s*\$\(if \(\$m\.vmMetadata -and \$m\.vmMetadata\.resourceId\) \{ \[string\]\$m\.vmMetadata\.resourceId \} else \{ \$null \}\)'
    }
}

Describe 'the endpoint row carries it as a correlation identifier (#204)' {
    It 'a VM device: the ARM id is in the AzureResourceId column and in EntityIds' {
        $row = Row @{ MDE_DeviceId = 'mde-1'; MDE_DeviceName = 'mgmt1.contoso.local'; MDE_AzureResourceId = $script:Arm }
        [string]$row.AzureResourceId | Should -Be $script:Arm
        Ids $row 'AzureResourceId' | Should -Be @($script:Arm)
    }

    It 'a device that is not a VM gets no ARM id -- nothing is invented' {
        $row = Row @{ MDE_DeviceId = 'mde-1'; MDE_DeviceName = 'laptop-7.contoso.local'; MDE_AzureResourceId = $null }
        [string]$row.AzureResourceId | Should -BeNullOrEmpty
        @(Ids $row 'AzureResourceId').Count | Should -Be 0
    }

    It 'the device''s Entra id from Defender (MDE_AadDeviceId, the key discovery emits) is an identifier too' {
        $row = Row @{ MDE_DeviceId = 'mde-1'; MDE_DeviceName = 'x'; MDE_AadDeviceId = 'aad-1' }
        Ids $row 'AadDeviceId' | Should -Be @('aad-1')
    }

    It 'every MDE_* key the builder reads for an identifier is one Defender discovery produces' {
        $disc = Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromMDE.ps1')
        foreach ($k in 'MDE_DeviceId', 'MDE_DeviceName', 'MDE_AadDeviceId', 'MDE_AzureResourceId') {
            $disc | Should -Match ('\b{0}\s*=' -f $k) -Because "$k is read for the correlation identifiers"
        }
    }
}
