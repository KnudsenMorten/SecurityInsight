#Requires -Version 5.1
<#
    THE v3 DATA MODEL (data-model/*.json, engine/data-model/*) -- V3-DATA-MODEL part 2.

      * SHIPPED TEMPLATES: every template loads and validates against every other (catalog, mappings, value maps,
        risk factors, lists, outputs, trust, criticality mapping, coverage checks) -- zero problems.
      * NO FACTOR LOST: every RF_* flag the Risk Analysis catalogue computes today is claimed by exactly one risk factor.
      * CONDITIONS: the closed condition language, including the traps (case, numbers vs versions, CIDR v4/v6, dates
        against a fixed clock, tag entries, an unknown operation throws, a pathological pattern times out).
      * FIELD MAPPER: realistic MDE / Exposure Graph / Azure / Entra objects become the expected SI records; a missing
        source is reported, never an error; an unknown operation throws.
      * OVERRIDES: per item -- override, own item, remove, UpgradeAvailable on a changed shipped item, trust order delta,
        value-map key merge.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:DM = Join-Path $script:SIRoot 'data-model'
    $script:Model = Get-SIDataModel -Root $script:DM
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]'2026-10-08T00:00:00Z' }
    function script:Map([string]$Provider, $Object, [string]$RecordType, [string]$ResourceType) {
        ConvertTo-SIRecord -Object $Object -Mapping $script:Model.Mappings[$Provider] -RecordType $RecordType -Catalog $script:Model['field-catalog'] `
            -ValueMaps $script:Model['value-maps'].maps -ResourceType $ResourceType -CollectionTime ([datetime]'2026-10-08T03:00:00Z') -RunId 'run-1'
    }
}

Describe 'Shipped data-model templates' {
    It 'load and validate against each other with no problems' {
        $problems = Test-SIDataModel -Model $script:Model
        ($problems -join "`n") | Should -BeNullOrEmpty
    }
    It 'cover the eleven providers and the catalog''s classes' {
        @($script:Model.Mappings.Keys) | Should -Be @('ad', 'azure', 'cmdb', 'eg', 'entra', 'intune', 'mdc', 'mde', 'mdi', 'servicenow', 'shodan')
        @($script:Model['field-catalog'].classes) | Should -Be @('device', 'identity', 'cloud_resource', 'public_ip')
    }
    It 'claim every RF_* flag the Risk Analysis catalogue computes today (no factor is lost)' {
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $flags = @([regex]::Matches($yaml, 'RF_[PC]_[A-Za-z0-9_]+') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        $claimed = @{}
        foreach ($f in @($script:Model['risk-factors'].factors)) { foreach ($t in @($f.legacyTokens)) { $claimed[[string]$t] = $f.id } }
        # the tier flags map to NO factor on purpose: tier counts through the risk index and the tier multiplier, never as a factor
        $tierFlags = @('RF_P_Tier0', 'RF_P_ADTier0', 'RF_P_Tier01', 'RF_P_Privileged')
        # #541 (6): RF_P_CiFactors is the factor set the engine feeds a report (every catalog factor that fits it), not one flag;
        # RF_P_CiFactorNames is the same fed set as the catalog's factor names (what a report shows), not a flag either
        $fedSet = @('RF_P_CiFactors', 'RF_P_CiFactorNames')
        @($flags | Where-Object { -not $claimed.ContainsKey($_) -and $tierFlags -notcontains $_ -and $fedSet -notcontains $_ }) | Should -BeNullOrEmpty
        foreach ($tf in $tierFlags) { $claimed.ContainsKey($tf) | Should -BeFalse -Because "$tf restates tier" }
        $flags.Count | Should -BeGreaterThan 20
    }
    It 'name every SI field in lower snake_case with an owner prefix' {
        foreach ($f in @($script:Model['field-catalog'].fields)) { $f.name | Should -Match '^(si_|properties_|mde_|mdc_|entra_|intune_|azure_|eg_|ad_|servicenow_|cmdb_)[a-z0-9_]+$' -Because 'si_ is SecurityInsight''s own field; a provider-native id keeps its provider''s prefix (mdc = Defender for Cloud, data-model\mappings\mdc.locked.json)' }
    }
    It 'keep the ServiceNow import-set columns exactly as the hand-off contract has them (append only)' {
        $contract = @('u_si_correlation_id', 'u_id_source', 'u_class_hint', 'u_proposed_class', 'u_name', 'u_fqdn', 'u_dns_domain',
            'u_serial_number', 'u_mac_address', 'u_object_id', 'u_azure_resource_id', 'u_aad_device_id', 'u_mde_device_id',
            'u_entra_object_id', 'u_tier', 'u_tier_reason', 'u_criticality', 'u_exposed_internet', 'u_last_seen',
            'u_source_run', 'u_run_time', 'u_discovery_source', 'u_row_hash', 'u_changed_at', 'u_data_sensitivity', 'u_si_state',
            'u_si_asset_type', 'u_si_asset_subtype')
        @($script:Model.Outputs['servicenow-ci'].columns.target) | Should -Be $contract
    }
}

Describe 'Conditions (closed language)' {
    It 'compares case-insensitively and numerically' {
        Test-SICondition @{ field = 'si_os_platform'; op = 'eq'; value = 'Windows' } @{ si_os_platform = 'windows' } | Should -BeTrue
        Test-SICondition @{ field = 'si_tier'; op = 'lte'; value = 1 } @{ si_tier = '0' } | Should -BeTrue
        Test-SICondition @{ field = 'si_tier'; op = 'lte'; value = 1 } @{ si_tier = 2 } | Should -BeFalse
        Test-SICondition @{ field = 'si_os_version'; op = 'lt'; value = 13 } @{ si_os_version = '12.6.1' } | Should -BeTrue
    }
    It 'treats an unknown value as neither true nor false' {
        Test-SICondition @{ field = 'si_mfa_registered'; op = 'is_false' } @{ si_mfa_registered = $null } | Should -BeFalse
        Test-SICondition @{ field = 'si_mfa_registered'; op = 'is_false' } @{ si_mfa_registered = 'false' } | Should -BeTrue
        Test-SICondition @{ field = 'si_onboarding_status'; op = 'ne'; value = 'onboarded' } @{ } | Should -BeFalse
    }
    It 'evaluates the shipped unsupported-OS list' {
        Test-SICondition @{ field = 'si_os_name'; op = 'in_list'; value = 'unsupported_os' } @{ si_os_name = 'WindowsServer2012R2' } $script:Ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_os_name'; op = 'in_list'; value = 'unsupported_os' } @{ si_os_name = 'Ubuntu 18.04' } $script:Ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_os_name'; op = 'in_list'; value = 'unsupported_os' } @{ si_os_name = 'Ubuntu 18.10' } $script:Ctx | Should -BeFalse
        Test-SICondition @{ field = 'si_os_name'; op = 'in_list'; value = 'unsupported_os' } @{ si_os_platform = 'macos'; si_os_version = '12.7' } $script:Ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_os_name'; op = 'in_list'; value = 'unsupported_os' } @{ si_os_name = 'Windows11' } $script:Ctx | Should -BeFalse
    }
    It 'matches IPv4 and IPv6 addresses against CIDR ranges' {
        $ctx = @{ Lists = @{ dmz = [pscustomobject]@{ id = 'dmz'; type = 'ranges'; values = @('10.20.0.0/16', '2001:db8::/32') } } }
        Test-SICondition @{ field = 'si_ip_addresses'; op = 'in_ranges'; value = 'dmz' } @{ si_ip_addresses = @('192.168.1.4', '10.20.3.4') } $ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_ip_addresses'; op = 'in_ranges'; value = 'dmz' } @{ si_ip_addresses = @('2001:db8:1::7') } $ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_ip_addresses'; op = 'in_ranges'; value = 'dmz' } @{ si_ip_addresses = @('10.21.0.1') } $ctx | Should -BeFalse
    }
    It 'measures age against the context clock' {
        Test-SICondition @{ field = 'si_last_sign_in'; op = 'older_than_days'; value = 90 } @{ si_last_sign_in = '2026-06-01T00:00:00Z' } $script:Ctx | Should -BeTrue
        Test-SICondition @{ field = 'si_last_sign_in'; op = 'older_than_days'; value = 90 } @{ si_last_sign_in = '2026-09-01T00:00:00Z' } $script:Ctx | Should -BeFalse
        Test-SICondition @{ field = 'si_last_sign_in'; op = 'older_than_days'; value = 90 } @{ } $script:Ctx | Should -BeFalse
    }
    It 'finds tag entries by name, value or name=value, and list members by list id' {
        $ci = @{ si_tags = @([ordered]@{ source = 'mde'; name = 'Tier0'; value = '' }, [ordered]@{ source = 'azure'; name = 'env'; value = 'prod' }); si_open_ports = @(443, 3389) }
        Test-SICondition @{ field = 'si_tags'; op = 'contains'; value = 'tier0' } $ci | Should -BeTrue
        Test-SICondition @{ field = 'si_tags'; op = 'contains'; value = 'env=prod' } $ci | Should -BeTrue
        Test-SICondition @{ field = 'si_open_ports'; op = 'contains_any'; value = 'high_risk_ports' } $ci $script:Ctx | Should -BeTrue
    }
    It 'handles groups: empty all is true, empty any is false, nesting works' {
        Test-SICondition @{ all = @() } @{ } | Should -BeTrue
        Test-SICondition @{ any = @() } @{ } | Should -BeFalse
        Test-SICondition @{ all = @(@{ field = 'a'; op = 'eq'; value = 1 }, @{ any = @(@{ field = 'b'; op = 'is_true' }, @{ field = 'c'; op = 'not_empty' }) }) } @{ a = 1; c = 'x' } | Should -BeTrue
    }
    It 'refuses an unknown operation' {
        { Test-SICondition @{ field = 'si_tier'; op = 'eval'; value = '1+1' } @{ si_tier = 0 } } | Should -Throw '*unknown condition operation*'
    }
    It 'bounds a pathological pattern instead of hanging' {
        { Test-SICondition @{ field = 'x'; op = 'matches'; value = '^(a+)+$' } @{ x = ('a' * 40) + '!' } } | Should -Throw
    }
}

Describe 'Field mapper' {
    It 'maps an MDE device' {
        $o = [pscustomobject]@{
            machine    = [pscustomobject]@{ id = 'ABCDEF0123'; aadDeviceId = 'A1B2-C3'; computerDnsName = 'SRV01.Contoso.local'; osPlatform = 'WindowsServer2019'
                osVersion = '10.0.17763'; onboardingStatus = 'Onboarded'; healthStatus = 'Active'; lastSeen = '2026-10-07T21:00:00Z'; firstSeen = '2025-01-01T00:00:00Z'
                machineTags = @('Tier0', 'site=CPH'); ipAddresses = @([pscustomobject]@{ ipAddress = '10.1.2.3'; macAddress = '00-15-5D-01-02-03' }, [pscustomobject]@{ ipAddress = 'not-an-ip'; macAddress = '000000000000' })
                vmMetadata = [pscustomobject]@{ vmId = 'VM-1'; resourceId = '/SUBSCRIPTIONS/S1/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/SRV01'; subscriptionId = 'S1'; cloudProvider = 'Azure' }
                exposureLevel = 'Medium'; riskScore = 'High'; managedBy = 'Intune' }
            deviceInfo = [pscustomobject]@{ IsInternetFacing = 'true'; DefenderAvStatus = 'Updated'; DeviceType = 'Server'; LoggedOnUsers = '[{"UserName":"adm1","Sid":"S-1-5-21-1"}]' }
        }
        $r = (Map 'mde' $o 'device').Record
        $r.si_record_key | Should -Be 'mde:abcdef0123'
        $r.mde_device_id | Should -Be 'abcdef0123'
        $r.entra_device_id | Should -Be 'a1b2-c3'
        $r.si_hostname | Should -Be 'srv01'
        $r.si_fqdn | Should -Be 'srv01.contoso.local'
        $r.si_os_platform | Should -Be 'windows_server'
        $r.si_onboarding_status | Should -Be 'onboarded'
        $r.si_av_status | Should -Be 'up_to_date'
        $r.si_asset_type | Should -Be 'server'
        $r.si_internet_exposed | Should -BeTrue
        $r.si_machine_risk | Should -Be 'high'
        $r.si_cloud_provider | Should -Be 'azure'
        $r.azure_resource_id | Should -Be '/subscriptions/s1/resourcegroups/rg/providers/microsoft.compute/virtualmachines/srv01'
        @($r.si_ip_addresses) | Should -Be @('10.1.2.3')
        @($r.si_mac_addresses) | Should -Be @('00:15:5d:01:02:03')
        @($r.si_tags | ForEach-Object { "$($_.source)/$($_.name)/$($_.value)" }) | Should -Be @('mde/Tier0/', 'mde/site/CPH')
        @($r.si_logged_on_users)[0].Sid | Should -Be 'S-1-5-21-1'
        $r.si_source_last_seen | Should -Be ([datetime]'2026-10-07T21:00:00Z').ToUniversalTime()
        $r.si_class | Should -Be 'device'
    }
    It 'maps an Exposure Graph node whose EntityIds arrive as a JSON string' {
        $o = [pscustomobject]@{ node = [pscustomobject]@{ NodeId = 'EG-9'; NodeLabel = 'device'; NodeName = 'srv01'
                EntityIds = '[{"type":"AadDeviceId","id":"A1B2-C3"},{"type":"SenseDeviceId","id":"ABCDEF0123"}]'
                NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ exposedToInternet = [pscustomobject]@{ type = 'InternetExposure'; reasons = @('PublicIp') }; criticalityLevel = [pscustomobject]@{ criticalityLevel = 0 }; deviceRole = @('DomainController', 'DnsServer') } } } }
        $r = (Map 'eg' $o 'device').Record
        $r.eg_node_id | Should -Be 'eg-9'
        $r.entra_device_id | Should -Be 'a1b2-c3'
        $r.mde_device_id | Should -Be 'abcdef0123'
        $r.si_internet_exposed | Should -BeTrue
        $r.si_ms_criticality | Should -Be 'very_high'
        @($r.si_device_roles) | Should -Be @('domain_controller', 'dns_server')
    }
    It 'applies resource-type specific mappings only to that type' {
        $st = [pscustomobject]@{ resource = [pscustomobject]@{ id = '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1'; name = 'st1'; type = 'Microsoft.Storage/storageAccounts'
                properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled'; allowSharedKeyAccess = $true; minimumTlsVersion = 'TLS1_2'; allowBlobPublicAccess = $false } } }
        $r = (Map 'azure' $st 'azure_resource' 'microsoft.storage/storageaccounts').Record
        $r.si_public_network_access | Should -BeFalse
        $r.si_local_auth_enabled | Should -BeTrue
        $r.si_anonymous_access | Should -BeFalse
        $r.si_min_tls_version | Should -Be '1.2'
        $r.si_asset_type | Should -Be 'storageaccounts'
        $kv = [pscustomobject]@{ resource = [pscustomobject]@{ id = '/x/kv1'; name = 'kv1'; type = 'microsoft.keyvault/vaults'; properties = [pscustomobject]@{ allowSharedKeyAccess = $true; publicNetworkAccess = 'Enabled' } } }
        $k = (Map 'azure' $kv 'azure_resource' 'microsoft.keyvault/vaults').Record
        $k.Contains('si_local_auth_enabled') | Should -BeFalse
        $k.si_public_network_access | Should -BeTrue
    }
    It 'maps an Entra user: newest of three sign-ins, the on-premises GUID from the immutable id' {
        $guid = [guid]'5f8a1c2e-3b4d-4e6f-8a9b-0c1d2e3f4a5b'
        $o = [pscustomobject]@{ user = [pscustomobject]@{ id = 'U-1'; userPrincipalName = 'Ann@Contoso.com'; userType = 'Guest'; accountEnabled = $true
                onPremisesImmutableId = [Convert]::ToBase64String($guid.ToByteArray())
                signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-09-01T00:00:00Z'; lastNonInteractiveSignInDateTime = '2026-10-01T00:00:00Z'; lastSuccessfulSignInDateTime = '2026-08-01T00:00:00Z' } }
            registration = [pscustomobject]@{ isMfaRegistered = $false } }
        $r = (Map 'entra' $o 'user').Record
        $r.si_upn | Should -Be 'ann@contoso.com'
        $r.si_identity_type | Should -Be 'guest'
        $r.si_is_external | Should -BeTrue
        $r.si_mfa_registered | Should -BeFalse
        $r.si_last_sign_in | Should -Be ([datetime]'2026-10-01T00:00:00Z').ToUniversalTime()
        $r.ad_object_guid | Should -Be $guid.ToString()
        $r.si_source_last_seen | Should -Be ([datetime]'2026-10-08T03:00:00Z').ToUniversalTime()   # directory: the collection time
    }
    It 'reports a mapped source that is missing, without failing' {
        $res = Map 'mde' ([pscustomobject]@{ machine = [pscustomobject]@{ id = 'X1' } }) 'device'
        $res.Record.mde_device_id | Should -Be 'x1'
        $res.Missing | Should -Contain 'si_os_platform'
        $res.Missing | Should -Not -Contain 'mde_device_id'
    }
    It 'refuses an unknown normalise operation' {
        $m = [pscustomobject]@{ provider = 'mde'; objects = @([pscustomobject]@{ recordType = 'device'; class = 'device'; key = 'id'; timestamp = '$collection_time' })
            mappings = @([pscustomobject]@{ field = 'si_hostname'; recordTypes = @('device'); sources = @('n'); normalize = @('invoke_expression') }) }
        { ConvertTo-SIRecord -Object ([pscustomobject]@{ id = '1'; n = 'x' }) -Mapping $m -RecordType 'device' -Catalog $script:Model['field-catalog'] -ValueMaps $script:Model['value-maps'].maps } | Should -Throw '*unknown normalize operation*'
    }
}

Describe 'Customer overrides, per item' {
    BeforeAll {
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-dm-' + [guid]::NewGuid().ToString('N'))
        Copy-Item -Recurse $script:DM $script:Tmp
        $lockedFactor = @((Get-Content (Join-Path $script:Tmp 'risk-factors.locked.json') -Raw | ConvertFrom-Json).factors | Where-Object id -eq 'stale_sign_in')[0]
        $script:StaleHash = Get-SIDataModelItemHash $lockedFactor
        @{ kind = 'risk-factor'; factors = @(
                @{ id = 'stale_sign_in'; baseHash = $script:StaleHash; shortName = 'EnabledNoSignInStale'; name = 'No sign-in for 60 days'; appliesTo = 'asset'; group = 'Lifecycle'; class = 'optional'; axis = 'probability'; impact = 1; state = 'enabled'; evaluatedBy = 'catalog'; legacyTokens = @('RF_P_Stale', 'RF_P_StaleLogin'); when = @{ all = @(@{ field = 'si_last_sign_in'; op = 'older_than_days'; value = 60 }) } }
                @{ id = 'no_owner'; baseHash = 'stale-hash-from-an-older-template'; shortName = 'NoOwner'; name = 'No owner'; appliesTo = 'asset'; group = 'Apps'; class = 'optional'; axis = 'probability'; impact = 2; state = 'enabled'; evaluatedBy = 'catalog'; legacyTokens = @('RF_P_NoOwner'); when = @{ all = @(@{ field = 'si_is_orphan_sp'; op = 'is_true' }) } }
                @{ id = 'gdpr_data'; shortName = 'GdprData'; name = 'GDPR data'; appliesTo = 'asset'; group = 'Importance'; class = 'optional'; axis = 'consequence'; impact = 1; state = 'enabled'; evaluatedBy = 'catalog'; legacyTokens = @(); when = @{ all = @(@{ field = 'si_cmdb_data_sensitivity'; op = 'eq'; value = 'gdpr' }) } }
                @{ id = 'old_password'; remove = $true }
            ) } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Tmp 'risk-factors.custom.json') -Encoding utf8
        @{ kind = 'trust'; order = @(@{ id = 'mde.machine_tag'; trusted = $false; after = 'eg.graph_field' }, @{ id = 'customer.import'; trusted = $true }) } | ConvertTo-Json -Depth 5 |
            Set-Content (Join-Path $script:Tmp 'trust.custom.json') -Encoding utf8
        @{ kind = 'value-map'; maps = @{ onboarding = @{ 'Pending' = 'can_be_onboarded' }; my_map = @{ a = 'b' } } } | ConvertTo-Json -Depth 5 |
            Set-Content (Join-Path $script:Tmp 'value-maps.custom.json') -Encoding utf8
        $script:O = Get-SIDataModel -Root $script:Tmp
    }
    AfterAll { Remove-Item -Recurse -Force $script:Tmp -ErrorAction SilentlyContinue }

    It 'overrides, adds, removes and flags per item' {
        $f = $script:O['risk-factors'].factors
        @($f | Where-Object id -eq 'stale_sign_in')[0].when.all[0].value | Should -Be 60
        @($f | Where-Object id -eq 'gdpr_data').Count | Should -Be 1
        @($f | Where-Object id -eq 'old_password').Count | Should -Be 0
        $s = @{}; foreach ($x in $script:O.States['risk-factors']) { $s[$x.Key] = $x.State }
        $s['stale_sign_in'] | Should -Be 'Overridden'
        $s['no_owner'] | Should -Be 'UpgradeAvailable'
        $s['gdpr_data'] | Should -Be 'Own'
        $s['old_password'] | Should -Be 'Disabled'
        $s['internet_exposed'] | Should -Be 'UpToDate'
    }
    It 'keeps the trust order and applies the delta by id' {
        $ids = @($script:O['trust'].order.id)
        $ids[0] | Should -Be 'eg.graph_field'
        $ids[1] | Should -Be 'mde.machine_tag'
        @($script:O['trust'].order | Where-Object id -eq 'mde.machine_tag')[0].trusted | Should -BeFalse
        $ids[-1] | Should -Be 'customer.import'
        $ids.Count | Should -Be (@($script:Model['trust'].order).Count + 1)
    }
    It 'merges value maps key by key' {
        $script:O['value-maps'].maps.onboarding.Pending | Should -Be 'can_be_onboarded'
        $script:O['value-maps'].maps.onboarding.Onboarded | Should -Be 'onboarded'
        $script:O['value-maps'].maps.my_map.a | Should -Be 'b'
    }
    It 'still validates with the overrides in place' {
        (Test-SIDataModel -Model $script:O) -join "`n" | Should -BeNullOrEmpty
    }
}
