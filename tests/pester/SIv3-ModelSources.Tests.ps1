#Requires -Version 5.1
<#
    THE DATA MODEL'S NEW SOURCES (REQUIREMENTS #497 on-prem AD from the cloud signals, #498 Intune devices, #499 Defender
    inventory on the CI, #500 non-Azure clouds) -- provider records -> data-model/mappings -> CIs, the same path every
    provider uses. OFFLINE: every REST call is a seam (the queries are text, the answers are fakes).

      * #497  the Entra reads ask the on-premises AD ids at every level; the Entra user / device, Defender for Identity and
              the Exposure Graph's AD computer-account nodes map them (ad_sid, ad_object_guid, si_ad_distinguished_name,
              si_ad_domain); a hybrid Entra device and its AD computer node are ONE CI (ad_sid); the computer-account read
              pages by count, a failed page is not complete, a graph without such nodes is "not present";
      * #498  Intune: the read-only permission is in the catalog, the grant plan and the update's permission note; the
              device record joins its Entra device by entra_device_id;
      * #499  the software inventory is its own paged query and part ('softwareInventory'), always read, mapped to
              si_installed_software / si_software_count / si_software_eos*; a device without rows gets no part;
      * #500  AWS / GCP resources from Defender for Cloud's multicloud connectors become mdc multicloud_resource records ->
              cloud_resource CIs keyed by Defender for Cloud's id (the id its recommendations carry), with the native id
              as a strong identifier; no connector = the source is not present; a recommendation on such a resource is
              never rolled up to its connector.
    PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIEgAdComputers.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderFindingSummary.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIMulticloudResources.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDefenderRecommendations.ps1')
    $script:Model = Get-SIDataModel
    $script:Read = { param($rel) [IO.File]::ReadAllText((Join-Path $script:SIRoot $rel)) }
    $script:Rows = { (ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model) }
    $script:Sid = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
    $script:Guid = '6f9619ff-8b86-d011-b42d-00c04fc964ff'
    $script:AwsId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-mc/providers/microsoft.security/securityconnectors/aws-prod/securityentitydata/aws-ec2-instance-i-0abc-eu-west-1'
}

Describe 'the data model stays valid with the new sources' {
    It 'Test-SIDataModel finds no problem; the two field catalogs stay identical' {
        (Test-SIDataModel -Model $script:Model) -join "`n" | Should -BeNullOrEmpty
        # the web app's copy is compared only where Test-Path finds it (the Community payload has no web app)
        if (Test-Path -LiteralPath (Join-Path $script:SIRoot 'pro-management')) {
            (& $script:Read 'data-model\field-catalog.locked.json') | Should -Be (& $script:Read 'pro-management\src\SI.Management.Core\ProData\DataModel\field-catalog.locked.json')
        }
    }
    It 'the new fields exist with the intended join strength' {
        $f = @{}; foreach ($x in $script:Model['field-catalog'].fields) { $f[[string]$x.name] = $x }
        foreach ($n in 'si_ad_distinguished_name', 'si_software_count', 'si_software_eos_count', 'si_software_eos', 'mdc_native_resource_id', 'si_cloud_resource_type', 'si_cloud_region', 'si_cloud_account_id', 'si_cloud_connector') {
            $f.ContainsKey($n) | Should -BeTrue -Because $n
        }
        $f['mdc_native_resource_id'].join | Should -Be 'strong'
        $f['si_ad_distinguished_name'].join | Should -Be 'none' -Because 'a name of a place in the directory never joins'
        @($f['si_cloud_provider'].classes) | Should -Contain 'cloud_resource'
        (Get-SICiLedgerTypeMap)['mdc_native_resource_id'] | Should -Be 'CloudNativeResourceId'
    }
}

Describe '#497 on-premises AD from the cloud signals' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine endpoint -Clear }
    It 'the Entra reads ask the on-premises ids at every level (same read, same permission)' {
        $u = & $script:Read 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'
        foreach ($p in 'onPremisesSecurityIdentifier', 'onPremisesImmutableId', 'onPremisesSamAccountName', 'onPremisesDistinguishedName', 'onPremisesDomainName') {
            $u | Should -Match ("users\?\`$select=[^']*\b$p\b") -Because "$p is on the security-level user read"
        }
        (& $script:Read 'engine\asset-profiling\discovery\Get-DiscoveryFromEntra.ps1') | Should -Match "devices\?\`$select=[^']*\bonPremisesSecurityIdentifier\b"
    }
    It 'the Entra user record maps the AD SID, object GUID, distinguished name and domain' {
        $uid = '11111111-2222-3333-4444-555555555555'
        Add-SIRecordPart -Provider entra -RecordType user -Key $uid -Part user -Object ([pscustomobject]@{ id = $uid; userPrincipalName = 'ada@contoso.test'
                onPremisesSecurityIdentifier = $script:Sid.ToLowerInvariant(); onPremisesImmutableId = ([Convert]::ToBase64String(([guid]$script:Guid).ToByteArray()))
                onPremisesDistinguishedName = 'CN=Ada,OU=Admins,DC=contoso,DC=local'; onPremisesDomainName = 'CONTOSO.local' })
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $r = @($res.Rows)[0]
        $r.ad_sid | Should -Be $script:Sid
        $r.ad_object_guid | Should -Be $script:Guid
        $r.si_ad_distinguished_name | Should -Be 'CN=Ada,OU=Admins,DC=contoso,DC=local'
        $r.si_ad_domain | Should -Be 'contoso.local'
    }
    It 'Defender for Identity maps the distinguished name it returns' {
        Add-SIRecordPart -Provider mdi -RecordType user -Key 'u1' -Part identity -Object ([pscustomobject]@{ AccountObjectId = 'u1'; AccountSID = $script:Sid; OnPremisesDistinguishedName = 'CN=Bo,OU=Users,DC=contoso,DC=local' })
        $r = @((& $script:Rows).Rows)[0]
        $r.si_ad_distinguished_name | Should -Be 'CN=Bo,OU=Users,DC=contoso,DC=local'
    }
    It 'an AD computer-account node of the Exposure Graph becomes an eg device record with its AD ids (EntityIds or rawData)' {
        $rows = @(
            [pscustomobject]@{ NodeId = 'N1'; NodeLabel = 'computer-account'; NodeName = 'SRV01'; EntityIds = @('{"type":"SecurityIdentifier","id":"' + $script:Sid + '"}'); NodeProperties = '{"rawData":{"objectGuid":"' + $script:Guid + '"}}' }
            [pscustomobject]@{ NodeId = 'N2'; NodeLabel = 'computer-account'; NodeName = 'SRV02'; EntityIds = @(); NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ objectSid = 'S-1-5-21-9-9-9-2001' } } }
        )
        $asked = New-Object System.Collections.Generic.List[string]
        $q = { param($k) $asked.Add($k); if ($k -match '\| count') { @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 2 }); Error = '' } } else { @{ Ok = $true; Rows = $rows; Error = '' } } }
        $out = Invoke-SIEgAdComputerCapture -Query $q
        ($out.Nodes, $out.Buckets, $out.Failed, $out.Present) | Should -Be @(2, 1, 0, $true)
        $asked[0] | Should -Match "NodeLabel == 'computer-account'\s+\| count"
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $n1 = @($res.Rows | Where-Object eg_node_id -eq 'n1')[0]
        $n1.si_record_type | Should -Be 'device'
        $n1.ad_sid | Should -Be $script:Sid
        $n1.ad_object_guid | Should -Be $script:Guid
        (@($res.Rows | Where-Object eg_node_id -eq 'n2')[0]).ad_sid | Should -Be 'S-1-5-21-9-9-9-2001'
        $global:SIRecordCaptureState.Pulls['eg'].Complete | Should -BeTrue
    }
    It 'pages by count (every node in one hash bucket); a failed page is not complete, never "gone"' {
        $asked = New-Object System.Collections.Generic.List[string]
        $q = { param($k) $asked.Add($k)
            if ($k -match '\| count') { return @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 12000 }); Error = '' } }
            if ($k -match 'hash\(NodeId, 3\) == 1') { return @{ Ok = $false; Rows = @(); Error = 'throttled' } }
            @{ Ok = $true; Rows = @(); Error = '' } }
        $out = Invoke-SIEgAdComputerCapture -Query $q -PageRows 5000
        $out.Buckets | Should -Be 3
        @($asked | Where-Object { $_ -match 'hash\(NodeId, 3\) == [012]' }).Count | Should -Be 3
        $out.Failed | Should -Be 1
        $out.Text | Should -Match 'UNKNOWN this run, not removed'
        $global:SIRecordCaptureState.Pulls['eg'].Complete | Should -BeFalse
    }
    It 'a graph without AD computer accounts: the source is not present, nothing read beyond the count' {
        $asked = New-Object System.Collections.Generic.List[string]
        $out = Invoke-SIEgAdComputerCapture -Query { param($k) $asked.Add($k); @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 0 }); Error = '' } }
        $out.Present | Should -BeFalse
        $out.Text | Should -Match 'source is not present'
        $asked.Count | Should -Be 1
    }
    It 'a hybrid-joined Entra device and its AD computer node are ONE CI (ad_sid)' {
        Add-SIRecordPart -Provider entra -RecordType device -Key 'aad-dev-1' -Part device -Object ([pscustomobject]@{ id = 'obj-1'; deviceId = 'aad-dev-1'; displayName = 'SRV01'; onPremisesSecurityIdentifier = $script:Sid; onPremisesSyncEnabled = $true })
        $null = Invoke-SIEgAdComputerCapture -Query { param($k) if ($k -match '\| count') { @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 1 }); Error = '' } } else { @{ Ok = $true; Rows = @([pscustomobject]@{ NodeId = 'N1'; NodeLabel = 'computer-account'; NodeName = 'SRV01'; EntityIds = @('{"type":"SecurityIdentifier","id":"' + $script:Sid + '"}'); NodeProperties = '{}' }); Error = '' } } }
        $res = & $script:Rows
        $g = Get-SICiGroups -Records @($res.Rows)
        @($g.Groups).Count | Should -Be 1
        @($g.Groups[0].Members).Count | Should -Be 2
    }
    It 'the endpoint discover runs the AD computer capture as a records-only source' {
        $d = & $script:Read 'engine\asset-profiling\stages\Invoke-Discover.ps1'
        $d | Should -Match "Get-SIEgAdComputers\.ps1"
        $d | Should -Match "Name = 'AdComputersEG'; RecordsOnly = \`$true; Fn = \{ \`$adc = Invoke-SIEgAdComputerCapture; Write-SIInfo \('   ' \+ \`$adc\.Text\); @\(\) \}"
        # records only: no profile rows BY DESIGN -- never the "returned NO rows" false alarm (live: on every endpoint run)
        $d | Should -Match "if \(\`$cnt -eq 0 -and -not \`$pair\.RecordsOnly\)"
    }
}

Describe '#498 Intune devices' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine endpoint -Clear }
    It 'the read-only permission is in the catalog, the grant plan and the update''s permission note; nothing writes' {
        $p = & $script:Read 'config\permissions.locked.json'
        $p | Should -Match '"DeviceManagementManagedDevices\.Read\.All"'
        $p | Should -Not -Match 'DeviceManagement\w*\.ReadWrite'
        (& $script:Read 'container\_shared\SI-ContainerConfig.ps1') | Should -Match "'DeviceManagementManagedDevices\.Read\.All'"
        (& $script:Read 'setup\_shared\SI-PermissionNote.ps1') | Should -Match "'permissions\.locked\.json'" -Because 'the update says what an existing install has not granted, from the same catalog'
    }
    It 'a refused Intune read is "not permitted" (source not present), never a failed collection' {
        (& $script:Read 'engine\asset-profiling\discovery\Get-SIIntuneContext.ps1') | Should -Match 'not permitted'
    }
    It 'the Intune device record joins its Entra device (entra_device_id) into one CI' {
        Add-SIRecordPart -Provider entra -RecordType device -Key 'aad-7' -Part device -Object ([pscustomobject]@{ id = 'o7'; deviceId = 'aad-7'; displayName = 'LT7' })
        Add-SIRecordPart -Provider intune -RecordType device -Key 'int-7' -Part device -Object ([pscustomobject]@{ id = 'int-7'; azureADDeviceId = 'AAD-7'; deviceName = 'LT7'; complianceState = 'noncompliant'; operatingSystem = 'Windows'; userPrincipalName = 'ada@contoso.test' })
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $i = @($res.Rows | Where-Object intune_device_id -eq 'int-7')[0]
        $i.si_is_compliant | Should -BeFalse
        $i.si_primary_user_upn | Should -Be 'ada@contoso.test'
        @((Get-SICiGroups -Records @($res.Rows)).Groups).Count | Should -Be 1
    }
}

Describe '#499 the Defender software inventory on the device' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine endpoint -Clear }
    It 'is its own query per page of devices, summarised per device (never a row per product)' {
        $ids = @(1..7 | ForEach-Object { '{0:x40}' -f $_ })
        $asked = New-Object System.Collections.Generic.List[string]
        $r = Add-SIDefenderSoftwareInventoryParts -DeviceIds $ids -PageDevices 3 -Query { param($k) $asked.Add($k); @() }
        ($r.Pages, $asked.Count) | Should -Be @(3, 3)
        $asked[0] | Should -Match 'union isfuzzy=true \(datatable\([^)]*\)\[\]\), \(DeviceTvmSoftwareInventory\)'
        $asked[0] | Should -Match 'summarize Installed = dcount\(_p\), Products = make_set\(_p\), EndOfSupport = dcountif\(_p, isnotempty\(_eos\)\)'
        $asked[0] | Should -Not -Match ('"{0}"' -f $ids[3]) -Because 'a page asks only its own devices'
        Get-SIDefenderSoftwareInventoryKql -DeviceIds @("x'; drop") | Should -BeNullOrEmpty -Because 'ids are checked hex, never free text'
    }
    It 'a row becomes part softwareInventory and the SI fields; a device without rows gets no part' {
        $d1 = 'a' * 40; $d2 = 'b' * 40
        foreach ($d in $d1, $d2) { Add-SIRecordPart -Provider mde -RecordType device -Key $d -Part machine -Object ([pscustomobject]@{ id = $d }) }
        $row = [pscustomobject]@{ DeviceId = $d1; Installed = 3; Products = @('microsoft/edge', 'google/chrome', 'oracle/java'); EndOfSupport = 1; EndOfSupportItems = '["oracle/java 8.0 (EOS Version, 2025-01-01)"]' }
        $r = Add-SIDefenderSoftwareInventoryParts -DeviceIds @($d1, $d2) -Query { param($k) @($row) }
        $r.Devices | Should -Be 1
        $res = & $script:Rows
        @($res.Errors) | Should -BeNullOrEmpty
        $m1 = @($res.Rows | Where-Object mde_device_id -eq $d1)[0]
        ($m1.si_software_count, $m1.si_software_eos_count) | Should -Be @(3, 1)
        @($m1.si_installed_software) | Should -Contain 'oracle/java'
        @($m1.si_software_eos)[0] | Should -Be 'oracle/java 8.0 (EOS Version, 2025-01-01)'
        (@($res.Rows | Where-Object mde_device_id -eq $d2)[0]).si_software_count | Should -BeNullOrEmpty -Because 'no rows is unknown, never "no software"'
    }
    It 'a failed page is said and costs only its devices' {
        $all = @(Add-SIDefenderSoftwareInventoryParts -DeviceIds @(('c' * 40), ('d' * 40)) -PageDevices 1 -Query { param($k) if ($k -match 'c{40}') { throw 'BadRequest (400)' }; @() } 3>&1)
        @($all | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count | Should -Be 1
        (@($all | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })[0]).Failed | Should -Be 1
    }
    It 'the collect stage reads it for the devices of its part, after the summaries' {
        (& $script:Read 'engine\asset-profiling\stages\Invoke-Collect.ps1') | Should -Match 'Add-SIDefenderSoftwareInventoryParts -DeviceIds \$defenderCtxIds\.ToArray\(\)'
    }
}

Describe '#500 resources in AWS / GCP' {
    BeforeEach { $null = Reset-SIRecordCapture -Engine azure -Clear }
    It 'no multicloud connector: the source is not present -- one line, the resources are not asked, the pull untouched' {
        $asked = New-Object System.Collections.Generic.List[string]
        $out = Invoke-SIMulticloudCapture -Query { param($k) $asked.Add($k); @() }
        ($out.Present, $out.Connectors, $out.Resources) | Should -Be @($false, 0, 0)
        $out.Text | Should -Match 'no AWS or GCP connector .* the source is not present'
        $asked.Count | Should -Be 1
        $asked[0] | Should -Match "microsoft\.security/securityconnectors"
        $global:SIRecordCaptureState.Pulls.ContainsKey('mdc') | Should -BeFalse
    }
    It 'a connector: each resource is an mdc multicloud_resource record -> a cloud_resource CI with its native id and assessments' {
        $mcConn = [pscustomobject]@{ id = '/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg-mc/providers/microsoft.security/securityconnectors/aws-prod'; name = 'aws-prod'; cloud = 'AWS' }
        $mcRes = [pscustomobject]@{ ResourceId = $script:AwsId.ToUpperInvariant(); Cloud = 'Aws'; NativeId = 'arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc'; ResName = 'web-1'; ResType = 'ec2.instance'; Region = 'eu-west-1'; Account = '123456789012'
            ConnectorId = $mcConn.id; Assessed = 4; Unhealthy = 2; High = 1; Medium = 1; Low = 0; OldestUnhealthy = '2026-09-01T00:00:00Z'; NewestChange = '2026-10-10T00:00:00Z'
            TopHigh = @([pscustomobject]@{ id = 'a1'; name = 'EC2 instances should not have a public IP'; severity = 'High' }); TopMedium = @(); TopLow = @() }
        $out = Invoke-SIMulticloudCapture -Query { param($k) if ($k -match 'environmentName') { @($mcConn) } else { @($mcRes) } }
        ($out.Present, $out.Connectors, $out.Resources, $out.Complete) | Should -Be @($true, 1, 1, $true)
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeTrue
        $rr = & $script:Rows
        @($rr.Errors) | Should -BeNullOrEmpty
        $r = @($rr.Rows)[0]
        ($r.si_class, $r.si_record_type) | Should -Be @('cloud_resource', 'multicloud_resource')
        $r.mdc_native_resource_id | Should -Be 'arn:aws:ec2:eu-west-1:123456789012:instance/i-0abc'
        ($r.si_cloud_provider, $r.si_cloud_resource_type, $r.si_cloud_region, $r.si_cloud_account_id, $r.si_cloud_connector, $r.si_asset_name) | Should -Be @('aws', 'ec2.instance', 'eu-west-1', '123456789012', 'aws-prod', 'web-1')
        ($r.si_mdc_unhealthy_count, $r.si_mdc_high_count) | Should -Be @(2, 1)
        $g = Get-SICiGroups -Records @($rr.Rows)
        @($g.Groups).Count | Should -Be 1 -Because 'the native id is a strong identifier: the resource is a CI'
        @($g.Unkeyable).Count | Should -Be 0
    }
    It 'the resource query reads only AWS / GCP assessments, summarised per resource' {
        $q = Get-SIMulticloudResourceKql
        $q | Should -Match "where Cloud in~ \('Aws', 'Gcp'\)"
        $q | Should -Match 'by ResourceId\s+\| order by ResourceId asc'
    }
    It 'a read that does not finish is not complete' {
        $out = Invoke-SIMulticloudCapture -Query { param($k) if ($k -match 'environmentName') { @([pscustomobject]@{ id = '/x/securityconnectors/g'; name = 'g'; cloud = 'GCP' }) } else { throw 'timeout' } }
        $out.Complete | Should -BeFalse
        $out.Text | Should -Match 'UNKNOWN this run, not removed'
        $global:SIRecordCaptureState.Pulls['mdc'].Complete | Should -BeFalse
    }
    It 'a recommendation on such a resource stays on the resource (its CI), never rolled up to the connector; an Azure container image still rolls up' {
        $p = Get-SIDefenderRecommendationParent -ResourceId $script:AwsId -ResourceType 'ec2.instance'
        ($p.ParentId, $p.IsEntity) | Should -Be @($script:AwsId, $false)
        $img = '/subscriptions/s/resourcegroups/rg/providers/microsoft.containerregistry/registries/acr1/securityentitydata/img-a'
        (Get-SIDefenderRecommendationParent -ResourceId $img -ResourceType '.containerimage').ParentId | Should -Be '/subscriptions/s/resourcegroups/rg/providers/microsoft.containerregistry/registries/acr1'
    }
    It 'the Azure discovery runs the multicloud capture after the assessment summary' {
        $a = & $script:Read 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1'
        $a.IndexOf('Invoke-SIMulticloudCapture -SubscriptionIds') | Should -BeGreaterThan $a.IndexOf('Invoke-SIMdcAssessmentSummaryCapture -SubscriptionIds')
    }
}
