#Requires -Version 5.1
<#
    THE v3 RECORD CAPTURE (engine/data-model/SI-RecordCapture.ps1) -- V3-DATA-MODEL part 2, P1.

      * ROUTING: every source system the profilers read lands on the right provider, record type, part and key;
        Exposure Graph nodes by their label; a VM extension (a child) is not a record.
      * PARTS MERGE: the MDE machines object and its DeviceInfo row are ONE record with fields from both.
      * COMPLETENESS: si_collection_complete follows the provider's pull (absence only from a complete run).
      * RAW: raw rows only for the providers SI_RawData names, in their own table shape; decimals go as text.
      * AT EVERY LEVEL: Add-SIFullSourceObject feeds the record capture also at the security level, where the full
        metadata keeps nothing.
      * WIRING: the engine run loads the capture before discovery; the Output stage publishes; the Azure and Exposure
        Graph capture points are no longer behind the full-level check; DeviceInfo, MFA registration and Shodan hosts
        are captured.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    function script:Src([string]$rel) { [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) }
}

Describe 'Routing source systems to records' {
    It 'routes <src>' -TestCases @(
        @{ src = 'mde'; obj = @{ id = 'M1' }; p = 'mde'; rt = 'device'; part = 'machine'; key = 'M1' }
        @{ src = 'entra-device'; obj = @{ deviceId = 'D1'; id = 'OBJ' }; p = 'entra'; rt = 'device'; part = 'device'; key = 'D1' }
        @{ src = 'entra-user'; obj = @{ id = 'U1' }; p = 'entra'; rt = 'user'; part = 'user'; key = 'U1' }
        @{ src = 'entra-serviceprincipal'; obj = @{ id = 'S1' }; p = 'entra'; rt = 'service_principal'; part = 'sp'; key = 'S1' }
        @{ src = 'arm'; obj = @{ id = '/x/st'; type = 'Microsoft.Storage/storageAccounts' }; p = 'azure'; rt = 'azure_resource'; part = 'resource'; key = '/x/st' }
        @{ src = 'arm'; obj = @{ id = '/x/pip'; type = 'microsoft.network/publicipaddresses' }; p = 'azure'; rt = 'public_ip'; part = 'resource'; key = '/x/pip' }
        @{ src = 'exposure-graph'; obj = @{ NodeId = 'N1'; NodeLabel = 'device' }; p = 'eg'; rt = 'device'; part = 'node'; key = 'N1' }
        @{ src = 'exposure-graph'; obj = @{ NodeId = 'N2'; NodeLabel = 'managedidentity' }; p = 'eg'; rt = 'service_principal'; part = 'node'; key = 'N2' }
        @{ src = 'exposure-graph'; obj = @{ NodeId = 'N3'; NodeLabel = 'microsoft.keyvault/vaults' }; p = 'eg'; rt = 'azure_resource'; part = 'node'; key = 'N3' }
        @{ src = 'intune-device'; obj = @{ id = 'I1' }; p = 'intune'; rt = 'device'; part = 'device'; key = 'I1' }
    ) {
        $r = Get-SIRecordSourceRoute -SourceSystem $src -Object ([pscustomobject]$obj)
        $r.Provider | Should -Be $p; $r.RecordType | Should -Be $rt; $r.Part | Should -Be $part; $r.Key | Should -Be $key
    }
    It 'records no VM extension and no unknown Exposure Graph label' {
        Get-SIRecordSourceRoute -SourceSystem 'arm-vm-extension' -Object ([pscustomobject]@{ id = 'x' }) | Should -BeNullOrEmpty
        Get-SIRecordSourceRoute -SourceSystem 'exposure-graph' -Object ([pscustomobject]@{ NodeId = 'x'; NodeLabel = 'cloud-application' }) | Should -BeNullOrEmpty
    }
}

Describe 'Records from captured parts' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine 'endpoint' -Clear }
    It 'merges the MDE machine and its DeviceInfo row into one record' {
        Add-SIRecordPart -Provider mde -RecordType device -Key 'ABC' -Part machine -Object ([pscustomobject]@{ id = 'ABC'; computerDnsName = 'pc1.contoso.com'; osPlatform = 'Windows11'; lastSeen = '2026-10-07T10:00:00Z' })
        Add-SIRecordPart -Provider mde -RecordType device -Key 'abc' -Part deviceInfo -Object ([pscustomobject]@{ DeviceId = 'abc'; IsInternetFacing = $true; DefenderAvStatus = 'Disabled' })
        Set-SIRecordPull -Provider mde -Complete $true
        $cap = @(Get-SICapturedRecords)
        $cap.Count | Should -Be 1
        $out = ConvertTo-SIRecordRows -Captured $cap -Model $script:Model -CollectionTime ([datetime]'2026-10-08T03:00:00Z') -RunId 'r1' -Pulls $global:SIRecordCaptureState.Pulls
        $row = $out.Rows[0]
        $row.si_record_key | Should -Be 'mde:abc'
        $row.si_hostname | Should -Be 'pc1'
        $row.si_os_platform | Should -Be 'windows'
        $row.si_internet_exposed | Should -BeTrue
        $row.si_av_status | Should -Be 'disabled'
        $row.si_collection_complete | Should -BeTrue
        $row.si_run_id | Should -Be 'r1'
        @($out.Raw).Count | Should -Be 0
    }
    It 'returns one item per record, so @() counts records (two records, not one array)' {
        Add-SIRecordPart -Provider mde -RecordType device -Key 'a' -Part machine -Object ([pscustomobject]@{ id = 'a' })
        Add-SIRecordPart -Provider entra -RecordType user -Key 'b' -Part user -Object ([pscustomobject]@{ id = 'b' })
        $cap = @(Get-SICapturedRecords)
        $cap.Count | Should -Be 2
        @($cap.Provider | Sort-Object) | Should -Be @('entra', 'mde')
        $out = ConvertTo-SIRecordRows -Captured $cap -Model $script:Model
        ($out.Errors -join "`n") | Should -BeNullOrEmpty
        @($out.Rows).Count | Should -Be 2
    }
    It 'marks every record of an incomplete provider pull' {
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/x/kv' -Part resource -Object ([pscustomobject]@{ id = '/x/kv'; name = 'kv'; type = 'microsoft.keyvault/vaults' }) -ResourceType 'microsoft.keyvault/vaults'
        Set-SIRecordPullFromSource -SourceSystem 'arm' -Complete $true
        Set-SIRecordPullFromSource -SourceSystem 'arm' -Complete $false -ErrorText 'page 9 throttled'
        $out = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model -Pulls $global:SIRecordCaptureState.Pulls
        $out.Rows[0].si_collection_complete | Should -BeFalse
    }
    It 'keeps raw objects only for the providers raw data names, and sends decimals as text' {
        # Shodan's real shape: vulns is an OBJECT keyed by CVE id
        $hostJson = '{"ip_str":"20.1.2.3","ports":[443,22],"data":[{"port":443,"vulns":{"CVE-2024-0001":{"cvss":9.8},"CVE-2023-0002":{"cvss":5.0}}},{"port":22}]}'
        Add-SIRecordPart -Provider shodan -RecordType public_ip -Key '20.1.2.3' -Part host -Object ($hostJson | ConvertFrom-Json)
        Add-SIRecordPart -Provider mde -RecordType device -Key 'm2' -Part machine -Object ([pscustomobject]@{ id = 'm2' })
        $raw = @(Get-SIRawDataProviders -Setting 'shodan' -AllProviders @('mde', 'shodan'))
        $out = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model -RawProviders $raw
        ($out.Errors -join "`n") | Should -BeNullOrEmpty
        @($out.Rows).Count | Should -Be 2
        @($out.Raw).Count | Should -Be 1
        $out.Raw[0].si_provider | Should -Be 'shodan'
        $out.Raw[0].properties_shodan_raw.host.ip_str | Should -Be '20.1.2.3'
        $ip = @($out.Rows | Where-Object si_provider -eq 'shodan')[0]
        $ip.si_max_cvss | Should -Be '9.8'
        $ip.si_max_cvss | Should -BeOfType [string]
        @($ip.si_open_ports) | Should -Be @(443, 22)
    }
    It 'reads SI_RawData as off, on, or a provider list' {
        @(Get-SIRawDataProviders -Setting $null -AllProviders @('a', 'b')).Count | Should -Be 0
        @(Get-SIRawDataProviders -Setting 'on' -AllProviders @('a', 'b')) | Should -Be @('a', 'b')
        @(Get-SIRawDataProviders -Setting ' MDE , azure ' -AllProviders @('a')) | Should -Be @('mde', 'azure')
    }
    It 'counts mapped fields a provider did not deliver' {
        Add-SIRecordPart -Provider mde -RecordType device -Key 'm3' -Part machine -Object ([pscustomobject]@{ id = 'm3' })
        $out = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        $out.Missing['mde|si_os_platform'] | Should -Be 1
    }
}

Describe 'Capture at every level' {
    It 'feeds the record capture from Add-SIFullSourceObject while the full metadata is off' {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
        $null = Reset-SIFullAssetProperties -Engine 'endpoint'
        $null = Reset-SIRecordCapture -Engine 'endpoint' -Clear
        Test-SIFullAssetPropertiesOn | Should -BeFalse
        Add-SIFullSourceObject -SourceSystem 'mde' -Object ([pscustomobject]@{ id = 'Z9'; computerDnsName = 'z9' }) -AnchorColumn 'MdeDeviceId' -AnchorValue 'Z9'
        Set-SIFullSourcePull -SourceSystem 'mde' -Complete $false
        @(Get-SICapturedRecords).Count | Should -Be 1
        @(Get-SIFullSourceObjects).Count | Should -Be 0
        $global:SIRecordCaptureState.Pulls['mde'].Complete | Should -BeFalse
    }
}

Describe 'Wiring' {
    It 'loads the capture in the engine run before discovery' {
        $t = Src 'engine\asset-profiling\Invoke-SIEngineRun.ps1'
        $load = $t.IndexOf("engine\data-model\SI-RecordCapture.ps1")
        $load | Should -BeGreaterThan 0
        $load | Should -BeLessThan $t.IndexOf('Initialize-SIFullAssetProperties -Engine')
        $t | Should -Match 'Reset-SIRecordCapture -Engine \$Engine'
    }
    It 'publishes the records in the Output stage' {
        Src 'engine\asset-profiling\stages\Invoke-Output.ps1' | Should -Match 'Publish-SIRecords -RunContext \$RunContext'
    }
    It 'captures Azure and Exposure Graph objects at every level, with EntityIds on Azure nodes' {
        foreach ($f in 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1', 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureViaEG.ps1', 'engine\asset-profiling\discovery\Get-DiscoveryFromEndpointViaEG.ps1') {
            Src $f | Should -Not -Match 'if \(Test-SIFullAssetPropertiesOn\) \{ Add-SIFullSourceObject'
        }
        Src 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureViaEG.ps1' | Should -Match '\| project NodeId, NodeName, NodeLabel, EntityIds,'
        Src 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1' | Should -Match "Add-SIRecordPartFromSource -SourceSystem 'exposure-graph'"
    }
    It 'captures DeviceInfo, MFA registration and Shodan hosts as parts' {
        ([regex]::Matches((Src 'engine\asset-profiling\stages\Invoke-Collect.ps1'), "-Part 'deviceInfo'")).Count | Should -Be 2
        Src 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1' | Should -Match "-Part 'registration'"
        Src 'engine\asset-profiling\discovery\Get-DiscoveryFromShodan.ps1' | Should -Match "-Provider 'shodan' -RecordType 'public_ip'"
    }
    It 'parses on Windows PowerShell 5.1 syntax rules (no ?. ?? or ternary in the new files)' {
        foreach ($f in 'engine\data-model\SI-RecordCapture.ps1', 'engine\data-model\SI-FieldMapper.ps1', 'engine\data-model\SI-Conditions.ps1', 'engine\data-model\SI-DataModelTemplates.ps1') {
            $tokens = $null; $errs = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $f), [ref]$tokens, [ref]$errs)
            @($errs).Count | Should -Be 0
            @($tokens | Where-Object { $_.Text -in '?.', '??', '??=' }).Count | Should -Be 0
        }
    }
}

Describe 'Memory at scale (#475): parts as text, published in batches' {
    It 'keeps a captured part as compact JSON text and gives it back whole, dates and nesting included' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        $when = [datetime]::SpecifyKind([datetime]'2026-10-08T05:50:00', [DateTimeKind]::Utc)
        Add-SIRecordPart -Provider entra -RecordType user -Key 'U1' -Part user -Object ([pscustomobject]@{ id = 'U1'; created = $when; tags = @('a', 'b'); meta = @{ level = 2 } })
        $stored = @($global:SIRecordCaptureState.Records.Values)[0].Parts['user']
        $stored.SIJson | Should -BeOfType [string]
        $o = @(Get-SICapturedRecords)[0].Object.user
        $o.id | Should -Be 'U1'
        ([datetime]$o.created).ToUniversalTime() | Should -Be $when
        @($o.tags) | Should -Be @('a', 'b')
        $o.meta.level | Should -Be 2
    }
    It 'Get-SICapturedRecords -Engine gives only that engine''s records' {
        $null = Reset-SIRecordCapture -Engine 'endpoint' -Clear
        Add-SIRecordPart -Provider mde -RecordType device -Key 'D1' -Part machine -Object @{ id = 'D1' }
        $null = Reset-SIRecordCapture -Engine 'identity'
        Add-SIRecordPart -Provider entra -RecordType user -Key 'U1' -Part user -Object @{ id = 'U1' }
        @(Get-SICapturedRecords -Engine 'identity').Count | Should -Be 1
        @(Get-SICapturedRecords).Count | Should -Be 2
    }
    It 'publishes in batches of SIRecordBatchSize, every record once, the counts added up' {
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        foreach ($i in 1..5) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; displayName = "User $i" } }
        Set-SIRecordPull -Provider entra -Complete $true
        $script:Sends = New-Object System.Collections.Generic.List[int]
        # the records go to the database (sql only); the batches are what the database is sent
        # (the publish also saves what the sources offered -- continuous discovery, another statement: answered here, not counted)
        $seam = { param($Sql, $Params, $Mode) if (-not $Params.ContainsKey('r')) { return [pscustomobject]@{ Properties = 0; Added = 0; NewContext = 0 } }; $n = @((ConvertFrom-Json -InputObject $Params.r) | ForEach-Object { $_ }).Count; $script:Sends.Add($n); [pscustomobject]@{ Seen = $n; Changed = $n } }
        function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) throw 'records are not posted to Log Analytics by default' }
        $saved = $script:SIRecordBatchSize
        try {
            $script:SIRecordBatchSize = 2
            $r = Publish-SIRecords -RunContext ([pscustomobject]@{ CollectionTime = [datetime]::UtcNow; RunId = 'r1' }) -Engine 'identity' -SqlInvoke $seam
        } finally { $script:SIRecordBatchSize = $saved; Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue }
        @($script:Sends) | Should -Be @(2, 2, 1)
        $r.Sql | Should -Be 5
    }
}
