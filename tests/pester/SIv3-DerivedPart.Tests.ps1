#Requires -Version 5.1
<#
    THE 'derived' RECORD PART FILLS EVERY derived.* PATH THE MAPPINGS NAME (engine/data-model/SI-RecordDerived.ps1).

    No collector wrote a 'derived' part, so derived.isPubliclyExposed, derived.credentialExpiryDays, derived.ownerCount and
    the rest were always empty: Azure exposure, credential expiry and orphan service principals never reached the CI.

    What these tests keep true:
      * EVERY derived.* path in data-model/mappings is covered here (a new one fails until it is computed and tested)
      * each one is filled from a fixture record (the parts the collectors capture) and reaches its si_* field through
        the shipped mappings (Get-SICapturedRecords -> ConvertTo-SIRecordRows)
      * unknown stays unknown: no owners read -> no owner count (never "orphaned"); no tenant id -> no third-party flag;
        no credentials -> no expiry
      * the two new reads: the owners read decorates only captured service principals and a failure records nothing; the
        management-group chain becomes a root-first path on every Azure record of the subscription
      * wired: the record assembly computes it; the service-principal and Azure discoveries run the reads
    Offline; PS 7 (v3 gate).
#>

BeforeAll {
    # the paths these tests fill (set here, not in BeforeDiscovery: a discovery variable is gone when the tests run)
    $script:Covered = @('derived.isPubliclyExposed', 'derived.inboundRdpFromInternet', 'derived.inboundSshFromInternet', 'derived.managementGroupPath',
        # rich context, Azure and public IP (filled and asserted in SIv3-RichAzure.Tests.ps1): names next to ids, the tag-key
        # map, what the child resources say about the machine, private endpoints, and the cached internet scan answer
        'derived.subscriptionName', 'derived.tenantId', 'derived.tenantName', 'derived.managementGroupId', 'derived.managementGroupName', 'derived.managementGroupIdPath',
        'derived.tagEnvironment', 'derived.tagCostCenter', 'derived.tagAppName', 'derived.tagOwner', 'derived.privateEndpointCount',
        'derived.mdeExtension', 'derived.amaExtension', 'derived.diskEncryption',
        'derived.exposedServices', 'derived.httpTitles', 'derived.httpServers', 'derived.tlsCertificates', 'derived.tlsCertExpired', 'derived.tlsSelfSigned',
        'derived.tlsEarliestExpiry', 'derived.tlsLegacyVersions', 'derived.shodanTags', 'derived.exposedOs', 'derived.domains', 'derived.cloudProvider',
        'derived.cloudRegion', 'derived.cloudService', 'derived.bannerFirstSeen', 'derived.bannerLastSeen',
        'derived.credentialExpiryDays', 'derived.ownerCount', 'derived.isThirdPartyMultiTenant',
        # Azure child resources rolling up into their parent (the children part; SIv3-AzureChildRollup covers every list)
        'derived.childResources', 'derived.si_vm_extensions', 'derived.si_disks', 'derived.si_network_interfaces', 'derived.si_public_ip_addresses',
        'derived.si_subnets', 'derived.si_sql_databases', 'derived.si_sql_firewall_rules', 'derived.si_ai_deployments',
        # identity context (owners of the principal and its application, the credential list and what to do about it, a
        # managed identity's resource, requested against granted permissions, MFA strength): SIv3-EntraContext fills each
        'derived.owners', 'derived.ownerNames', 'derived.ownerUpns[*]', 'derived.ownerIds[*]', 'derived.credentials', 'derived.credentialFix',
        'derived.attachedResourceName', 'derived.attachedResourceId', 'derived.managedIdentityKind', 'derived.permissionGap', 'derived.mfaStrength')
    $script:SIRoot =Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    $script:Model = Get-SIDataModel
    $script:Tenant = '11111111-2222-3333-4444-555555555555'
    function script:Rows {
        $res = ConvertTo-SIRecordRows -Captured @(Get-SICapturedRecords) -Model $script:Model
        @($res.Errors) | Should -BeNullOrEmpty
        @($res.Rows)
    }
    function script:Row([string]$Provider, [string]$Key) { @(Rows | Where-Object { $_.si_provider -eq $Provider -and $_.si_record_key -like "*$Key*" })[0] }
}

Describe 'every derived.* path of the mappings is covered' {
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine test -Clear
        $global:AzureTenantID = $script:Tenant
    }
    AfterEach { Remove-Variable -Scope Global -Name AzureTenantID -ErrorAction SilentlyContinue }
    It 'the mappings name exactly the paths these tests fill' {
        $paths = New-Object System.Collections.Generic.List[string]
        foreach ($p in $script:Model.Mappings.Keys) { foreach ($m in @($script:Model.Mappings[$p].mappings)) { foreach ($s in @($m.sources)) { if ([string]$s -like 'derived.*') { $paths.Add([string]$s) } } } }
        @($paths | Sort-Object -Unique) | Should -Be @($script:Covered | Sort-Object -Unique)
    }
}

Describe 'Azure records' {
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine test -Clear
        $global:AzureTenantID = $script:Tenant
    }
    AfterEach { Remove-Variable -Scope Global -Name AzureTenantID -ErrorAction SilentlyContinue }
    It 'derived.isPubliclyExposed -> si_internet_exposed (publicNetworkAccess Enabled; Disabled is not exposed)' {
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1'; name = 'kv1'; type = 'microsoft.keyvault/vaults'; properties = [pscustomobject]@{ publicNetworkAccess = 'Enabled' } })
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv2' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv2'; name = 'kv2'; type = 'microsoft.keyvault/vaults'; properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled'; networkAcls = [pscustomobject]@{ defaultAction = 'Allow' } } })
        (Row azure 'kv1').si_internet_exposed | Should -BeTrue
        (Row azure 'kv2').si_internet_exposed | Should -BeFalse
    }
    It 'a storage account allowing blob public access, and a network ACL that allows by default, are exposed' {
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st1' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st1'; name = 'st1'; type = 'microsoft.storage/storageaccounts'; properties = [pscustomobject]@{ allowBlobPublicAccess = $true } })
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st2' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/st2'; name = 'st2'; type = 'microsoft.storage/storageaccounts'; properties = [pscustomobject]@{ networkAcls = [pscustomobject]@{ defaultAction = 'Allow' } } })
        (Row azure 'st1').si_internet_exposed | Should -BeTrue
        (Row azure 'st2').si_internet_exposed | Should -BeTrue
    }
    It 'derived.inboundRdpFromInternet / inboundSshFromInternet -> si_nsg_open_rdp / si_nsg_open_ssh' {
        $rules = @(
            [pscustomobject]@{ name = 'rdp'; properties = [pscustomobject]@{ access = 'Allow'; direction = 'Inbound'; sourceAddressPrefix = 'Internet'; destinationPortRange = '3000-4000' } }
            [pscustomobject]@{ name = 'ssh-internal'; properties = [pscustomobject]@{ access = 'Allow'; direction = 'Inbound'; sourceAddressPrefix = '10.0.0.0/8'; destinationPortRange = '22' } }
            [pscustomobject]@{ name = 'deny'; properties = [pscustomobject]@{ access = 'Deny'; direction = 'Inbound'; sourceAddressPrefix = '*'; destinationPortRange = '22' } })
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.network/networksecuritygroups/nsg1' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.network/networksecuritygroups/nsg1'; name = 'nsg1'; type = 'microsoft.network/networksecuritygroups'; properties = [pscustomobject]@{ securityRules = $rules } })
        $r = Row azure 'nsg1'
        $r.si_nsg_open_rdp | Should -BeTrue
        $r.si_nsg_open_ssh | Should -BeFalse
    }
    It 'derived.managementGroupPath -> si_management_group_path, root first, from the subscription''s chain' {
        Add-SIRecordPart -Provider azure -RecordType azure_resource -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.web/sites/app1' -Part resource -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourcegroups/rg/providers/microsoft.web/sites/app1'; name = 'app1'; type = 'microsoft.web/sites'; properties = [pscustomobject]@{} })
        $n = Invoke-SIManagementGroupCapture -Query { param($q) @([pscustomobject]@{ SubscriptionId = 'S1'; Chain = @([pscustomobject]@{ name = 'prod'; displayName = 'Production' }, [pscustomobject]@{ name = 'corp'; displayName = '' }, [pscustomobject]@{ name = 'root'; displayName = 'Tenant Root Group' }) }) }
        $n | Should -Be 1
        (Row azure 'app1').si_management_group_path | Should -Be 'Tenant Root Group/corp/Production'
    }
    It 'derived.childResources and the per-type lists (si_vm_extensions, si_subnets, si_sql_databases, si_sql_firewall_rules, si_ai_deployments ...) from the children part' {
        $rg = '/subscriptions/s1/resourcegroups/rg/providers'
        $kids = @(
            @("$rg/microsoft.compute/virtualmachines/vm1", 'microsoft.compute/virtualmachines', "$rg/microsoft.compute/virtualmachines/vm1/extensions/ext1", 'microsoft.compute/virtualmachines/extensions', @{}),
            @("$rg/microsoft.compute/virtualmachines/vm1", 'microsoft.compute/virtualmachines', "$rg/microsoft.compute/disks/d1", 'microsoft.compute/disks', @{ managedBy = "$rg/microsoft.compute/virtualmachines/vm1" }),
            @("$rg/microsoft.compute/virtualmachines/vm1", 'microsoft.compute/virtualmachines', "$rg/microsoft.network/networkinterfaces/n1", 'microsoft.network/networkinterfaces', @{ properties = [pscustomobject]@{ virtualMachine = [pscustomobject]@{ id = "$rg/microsoft.compute/virtualmachines/vm1" } } }),
            @("$rg/microsoft.network/virtualnetworks/vn1", 'microsoft.network/virtualnetworks', "$rg/microsoft.network/virtualnetworks/vn1/subnets/s1", 'microsoft.network/virtualnetworks/subnets', @{}),
            @("$rg/microsoft.sql/servers/sql1", 'microsoft.sql/servers', "$rg/microsoft.sql/servers/sql1/databases/db1", 'microsoft.sql/servers/databases', @{}),
            @("$rg/microsoft.sql/servers/sql1", 'microsoft.sql/servers', "$rg/microsoft.sql/servers/sql1/firewallrules/fw1", 'microsoft.sql/servers/firewallrules', @{}),
            @("$rg/microsoft.cognitiveservices/accounts/ai1", 'microsoft.cognitiveservices/accounts', "$rg/microsoft.cognitiveservices/accounts/ai1/deployments/gpt", 'microsoft.cognitiveservices/accounts/deployments', @{}))
        foreach ($k in $kids) {
            Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $k[0] -Part resource -Object ([pscustomobject]@{ id = $k[0]; name = ($k[0] -split '/')[-1]; type = $k[1]; properties = [pscustomobject]@{} }) -ResourceType $k[1]
            $o = [ordered]@{ id = $k[2]; name = ($k[2] -split '/')[-1]; type = $k[3]; properties = [pscustomobject]@{} }; foreach ($x in $k[4].Keys) { $o[$x] = $k[4][$x] }
            Add-SIRecordPart -Provider azure -RecordType azure_resource -Key $k[2] -Part resource -Object ([pscustomobject]$o) -ResourceType $k[3]
        }
        Add-SIRecordPart -Provider azure -RecordType public_ip -Key "$rg/microsoft.network/publicipaddresses/p1" -Part resource -Object ([pscustomobject]@{ id = "$rg/microsoft.network/publicipaddresses/p1"; name = 'p1'; type = 'microsoft.network/publicipaddresses'; properties = [pscustomobject]@{ ipAddress = '20.1.1.1'; ipConfiguration = [pscustomobject]@{ id = "$rg/microsoft.network/networkinterfaces/n1/ipconfigurations/c" } } }) -ResourceType 'microsoft.network/publicipaddresses'
        $vm = Row azure 'virtualmachines/vm1'
        @($vm.si_vm_extensions)[0].name | Should -Be 'ext1'
        @($vm.si_disks)[0].name | Should -Be 'd1'
        @($vm.si_network_interfaces)[0].name | Should -Be 'n1'
        @($vm.si_public_ip_addresses)[0].ip_address | Should -Be '20.1.1.1'
        @($vm.si_child_resources).Count | Should -Be 4
        @((Row azure 'virtualnetworks/vn1').si_subnets)[0].name | Should -Be 's1'
        $sql = Row azure 'servers/sql1'
        @($sql.si_sql_databases)[0].name | Should -Be 'db1'
        @($sql.si_sql_firewall_rules)[0].name | Should -Be 'fw1'
        @((Row azure 'accounts/ai1').si_ai_deployments)[0].name | Should -Be 'gpt'
    }
    It 'the management-group read uses Resource Graph resourcecontainers (REST) and a failure records nothing' {
        Get-SIManagementGroupKql | Should -Match 'resourcecontainers'
        Get-SIManagementGroupKql | Should -Match 'managementGroupAncestorsChain'
        Invoke-SIManagementGroupCapture -Query { param($q) throw 'AuthorizationFailed' } -WarningAction SilentlyContinue | Should -Be 0
    }
}

Describe 'Entra service-principal records' {
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine test -Clear
        $global:AzureTenantID = $script:Tenant
    }
    AfterEach { Remove-Variable -Scope Global -Name AzureTenantID -ErrorAction SilentlyContinue }
    BeforeAll {
        # not 'Sp': that is PowerShell's alias of Set-ItemProperty, and an alias wins over a function
        function script:SpRecord([string]$Id, [hashtable]$Extra) {
            $o = [ordered]@{ id = $Id; displayName = "sp-$Id"; appId = "app-$Id"; servicePrincipalType = 'Application' }
            foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
            Add-SIRecordPart -Provider entra -RecordType service_principal -Key $Id -Part sp -Object ([pscustomobject]$o)
        }
    }
    It 'derived.credentialExpiryDays -> si_credential_expiry_days: the first credential to end, of the SP and its app; negative = expired' {
        $soon = [datetime]::UtcNow.AddDays(10.5).ToString('o'); $late = [datetime]::UtcNow.AddDays(400).ToString('o'); $past = [datetime]::UtcNow.AddDays(-3.5).ToString('o')
        SpRecord 'a1' @{ passwordCredentials = @([pscustomobject]@{ endDateTime = $late }); keyCredentials = @([pscustomobject]@{ endDateTime = $soon }) }
        SpRecord 'a2' @{ passwordCredentials = @() }
        Add-SIRecordPart -Provider entra -RecordType service_principal -Key 'a2' -Part app -Object ([pscustomobject]@{ passwordCredentials = @([pscustomobject]@{ endDateTime = $past }) })
        SpRecord 'a3' @{ passwordCredentials = @(); keyCredentials = @() }
        (Row entra 'a1').si_credential_expiry_days | Should -Be 10
        (Row entra 'a2').si_credential_expiry_days | Should -Be -4
        (Row entra 'a3').si_credential_expiry_days | Should -BeNullOrEmpty -Because 'no credentials = nothing expires, not 0'
    }
    It 'derived.ownerCount -> si_is_orphan_sp from the owners read; not read = unknown, never orphaned' {
        SpRecord 'o1' @{}; SpRecord 'o2' @{}; SpRecord 'o3' @{}
        $n = Invoke-SISpOwnerCapture -Fetch { param($u) @([pscustomobject]@{ id = 'O1'; owners = @() }, [pscustomobject]@{ id = 'o2'; owners = @([pscustomobject]@{ id = 'u1' }) }, [pscustomobject]@{ id = 'not-captured'; owners = @() }) }
        $n | Should -Be 2
        (Row entra 'o1').si_is_orphan_sp | Should -BeTrue
        (Row entra 'o2').si_is_orphan_sp | Should -BeFalse
        (Row entra 'o3').si_is_orphan_sp | Should -BeNullOrEmpty
        $global:SIRecordCaptureState.Records.ContainsKey('entra|service_principal|not-captured') | Should -BeFalse
    }
    It 'the owners read expands owners on the service-principal list and a failure records nothing' {
        $script:Url = $null
        $null = Invoke-SISpOwnerCapture -Fetch { param($u) $script:Url = $u; @() }
        $script:Url | Should -Match '\$expand=owners\(\$select=id,displayName,userPrincipalName\)'
        SpRecord 'f1' @{}
        Invoke-SISpOwnerCapture -Fetch { param($u) throw 'Forbidden' } -WarningAction SilentlyContinue | Should -Be 0
        (Row entra 'f1').si_is_orphan_sp | Should -BeNullOrEmpty
    }
    It 'derived.isThirdPartyMultiTenant -> si_is_third_party_multitenant: owned by another tenant; this tenant = false; no tenant id = unknown' {
        SpRecord 't1' @{ appOwnerOrganizationId = '99999999-0000-0000-0000-000000000000' }
        SpRecord 't2' @{ appOwnerOrganizationId = $script:Tenant.ToUpperInvariant() }
        (Row entra 't1').si_is_third_party_multitenant | Should -BeTrue
        (Row entra 't2').si_is_third_party_multitenant | Should -BeFalse
        Remove-Variable -Scope Global -Name AzureTenantID
        foreach ($n in 'SpnTenantId', 'SI_SPN_TenantId', 'SI_TenantId', 'HighPriv_Modern_TenantID', 'TenantId') { if (Get-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue) { Set-ItResult -Skipped -Because "the session has `$global:$n set"; return } }
        (Row entra 't1').si_is_third_party_multitenant | Should -BeNullOrEmpty
    }
}

Describe 'wiring' {
    BeforeEach {
        $null = Reset-SIRecordCapture -Engine test -Clear
        $global:AzureTenantID = $script:Tenant
    }
    AfterEach { Remove-Variable -Scope Global -Name AzureTenantID -ErrorAction SilentlyContinue }
    It 'the record assembly adds the derived part, the same in every path' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1'))
        $t | Should -Match "SI-RecordDerived\.ps1"
        $t | Should -Match '\$obj = Add-SIRecordDerivedPart -Provider \$r\.Provider -RecordType \$r\.RecordType -Object \(ConvertFrom-SIRecordParts \$r\.Parts\)'
    }
    It 'the service-principal discovery reads the owners (both paths); the Azure discovery reads the management groups' {
        $sp = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraServicePrincipals.ps1'))
        ([regex]::Matches($sp, 'Invoke-SISpOwnerCapture -Token \$token')).Count | Should -Be 2
        $az = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1'))
        $az | Should -Match 'Invoke-SIManagementGroupCapture -SubscriptionIds \$SubscriptionIds'
    }
}
