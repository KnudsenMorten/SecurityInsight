#Requires -Version 5.1
<#
    THE CI COLUMNS ARE RICH (owner 2026-10-12: "fix the empty columns, must be rich before release ... if field exist in
    discovery in source, it should include it"). A column that is empty for a resource that has no value is right; a column
    that is empty for EVERY CI although the source has the value is a defect. What these keep true:

      1. EVERY CI FIELD IS ACCOUNTED FOR   every field the field catalog puts on a CI (level ci / both) is posted to the CI
                         table (SI-CiBuildSql.ps1 $script:SICiPostFields), or is named in one of the two lists that say
                         why it is not ($script:SICiPostNever, $script:SICiPostDatabaseOnly). A field added to the catalog
                         without that decision fails here -- it cannot become a column no row ever fills.
      2. THE ROW CARRIES THEM   a CI that holds the device, identity, Azure and build facts gets them in its full row.
      3. A GROUP IS A GROUP   the Exposure Graph's group node becomes an identity of type group, asset type Group, subtype
                         Group -- never Other / General; a user or application only the graph knows says what it is too.
      4. AZURE CONTEXT REACHES EVERY RESOURCE   the Azure discovery makes every resource a record BEFORE it reads the
                         subscription names, management groups, backup, access, policy, changes and the Defender plan --
                         those reads add to the records in hand, and found none when the records came after.
    Offline; PS 7 (v3 gate). Nothing is read from or sent to a tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:CiFields = @($script:Model['field-catalog'].fields | Where-Object { [string]$_.level -in 'ci', 'both' } | ForEach-Object { [string]$_.name })
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]::UtcNow }
    $script:T = [datetime]::SpecifyKind([datetime]'2026-10-12T03:00:00', [DateTimeKind]::Utc)
    # one Exposure Graph node -> its SI record (the eg mapping, the shipped value maps)
    function script:EgRecord {
        param([string]$Label, [string]$Name, [string]$RecordType)
        $node = [pscustomobject]@{ NodeId = ('n-' + $Name); NodeLabel = $Label; NodeName = $Name; NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{} } }
        (ConvertTo-SIRecord -Object ([pscustomobject]@{ node = $node }) -Mapping $script:Model.Mappings['eg'] -RecordType $RecordType `
            -Catalog $script:Model['field-catalog'] -ValueMaps $script:Model['value-maps'].maps -CollectionTime $script:T).Record
    }
    # a CI as the build has it after field resolution: the record's fields (classification reads the CI)
    function script:CiOf {
        param($Record)
        $ci = [ordered]@{ si_ci_id = 'ci-1'; si_class = 'identity' }
        foreach ($k in $Record.Keys) { if (-not $ci.Contains($k)) { $ci[$k] = $Record[$k] } }
        $ci['si_class'] = 'identity'
        $ci
    }
}

Describe 'every CI field of the field catalog is posted to the CI table, or named as left out with the reason' {
    It 'GUARD: no CI field is unaccounted for (posted, never in a full row, or database only)' {
        $known = @($script:SICiPostFields) + @($script:SICiPostNever) + @($script:SICiPostDatabaseOnly)
        $lost = @($script:CiFields | Where-Object { $known -notcontains $_ })
        $lost | Should -BeNullOrEmpty -Because ('these CI fields of the field catalog are neither posted to the CI table nor named as left out: {0}. Add each to $script:SICiPostFields (engine\data-model\SI-CiBuildSql.ps1) -- or to $script:SICiPostDatabaseOnly when only the web app, the exports and the connectors need it.' -f ($lost -join ', '))
    }
    It 'a field is in ONE list only, and every listed field is a CI field of the catalog' {
        $all = @($script:SICiPostFields) + @($script:SICiPostNever | Where-Object { $_ -notin 'si_collection_time', 'si_last_seen' }) + @($script:SICiPostDatabaseOnly)
        @($all | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name) | Should -BeNullOrEmpty -Because 'a field that is posted is not also left out'
        $unknown = @(@($script:SICiPostDatabaseOnly) + @($script:SICiPostNever) | Where-Object { $script:CiFields -notcontains $_ })
        $unknown | Should -BeNullOrEmpty -Because 'a left-out list names catalog fields only (a renamed or removed field is taken out of it)'
    }
    It 'the fields that change every build stay out of the full row (it would be posted every build)' {
        foreach ($f in 'si_run_id', 'si_ci_action', 'si_days_inactive', 'si_field_sources') {
            $script:SICiPostNever | Should -Contain $f
            $script:SICiPostFields | Should -Not -Contain $f
        }
    }
    It 'the table stays inside the Log Analytics column limit (500), with room for the per-factor columns' {
        @($script:SICiPostFields).Count | Should -BeLessThan 400 -Because 'the posted fields + the risk factor columns + the row columns must fit one table; past this, move detail to the database-only list'
    }
    It 'the columns measured empty for every CI are posted now' {
        foreach ($f in 'si_os_name', 'si_os_build', 'si_os_architecture', 'si_ip_addresses', 'si_mac_addresses', 'si_fqdn', 'si_logged_on_users',
            'si_onboarding_status', 'si_sensor_health', 'si_join_type', 'si_device_category', 'si_tpm_enabled', 'si_machine_groups', 'si_rdp_enabled',
            'si_rdp_nla_required', 'si_smb1_enabled', 'si_managed_by', 'si_mail', 'si_job_title', 'si_admin_count', 'si_mfa_methods',
            'si_frequent_user_tier', 'si_public_network_access', 'si_https_only', 'si_min_tls_version', 'si_local_auth_enabled', 'si_anonymous_access',
            'si_network_default_action', 'si_ddos_protection', 'si_azure_parent_tags', 'si_bound_resource_id', 'si_cloud_provider', 'si_public_ip',
            'si_asn', 'si_geo_country', 'si_first_seen', 'si_lifecycle', 'si_category', 'si_purpose', 'si_coverage_gaps', 'si_link_count',
            'si_is_customer_facing', 'si_cmdb_match_rule', 'si_cmdb_match_confidence', 'si_cmdb_source', 'si_cmdb_service', 'si_cmdb_criticality_level') {
            $script:SICiPostFields | Should -Contain $f
        }
    }
}

Describe 'the full row of a CI carries the facts the CI holds' {
    It 'a device, an identity, an Azure resource and the build''s own decisions: every value is in the row' {
        $ci = [ordered]@{ si_ci_id = 'ci-9'; si_class = 'device'; si_collection_time = $script:T; si_last_seen = $script:T
            si_os_name = 'Windows11'; si_os_build = '26100'; si_os_architecture = '64-bit'; si_ip_addresses = @('10.0.0.4'); si_mac_addresses = @('00:11:22:33:44:55')
            si_fqdn = 'pc1.example.test'; si_onboarding_status = 'onboarded'; si_sensor_health = 'active'; si_join_type = 'hybrid'; si_tpm_enabled = $true
            si_rdp_enabled = $false; si_mail = 'a@example.test'; si_job_title = 'Engineer'; si_mfa_methods = @('fido2'); si_public_network_access = 'Disabled'
            si_https_only = $true; si_min_tls_version = '1.2'; si_first_seen = $script:T.AddDays(-30); si_lifecycle = 'active'; si_link_count = 3
            si_purpose = 'Domain controller'; si_category = 'Identity'; si_coverage_gaps = @('no-edr'); si_cmdb_match_rule = 'fqdn'; si_cmdb_source = 'cmdb'
            si_run_id = 'run-1'; si_ci_action = 'reuse'; si_days_inactive = 4; si_field_sources = [ordered]@{ si_os_name = [ordered]@{ provider = 'mde' } } }
        $row = ConvertTo-SICiPostRow -Ci $ci
        $names = @($row.PSObject.Properties.Name)
        foreach ($f in 'si_os_name', 'si_os_build', 'si_os_architecture', 'si_ip_addresses', 'si_mac_addresses', 'si_fqdn', 'si_onboarding_status', 'si_sensor_health',
            'si_join_type', 'si_tpm_enabled', 'si_rdp_enabled', 'si_mail', 'si_job_title', 'si_mfa_methods', 'si_public_network_access', 'si_https_only',
            'si_min_tls_version', 'si_first_seen', 'si_lifecycle', 'si_link_count', 'si_purpose', 'si_category', 'si_coverage_gaps', 'si_cmdb_match_rule', 'si_cmdb_source') {
            $names | Should -Contain $f
        }
        $row.si_os_build | Should -Be '26100'
        $row.si_lifecycle | Should -Be 'active'
        $row.si_rdp_enabled | Should -Be $false -Because 'a false is a value: it is posted, never dropped as empty'
        foreach ($f in 'si_run_id', 'si_ci_action', 'si_days_inactive', 'si_field_sources') { $names | Should -Not -Contain $f }
    }
    It 'a value the CI does not hold is not in the row (empty for this resource is right)' {
        $row = ConvertTo-SICiPostRow -Ci ([ordered]@{ si_ci_id = 'ci-8'; si_class = 'identity'; si_collection_time = $script:T; si_mail = 'b@example.test' })
        @($row.PSObject.Properties.Name) | Should -Not -Contain 'si_os_build'
        $row.si_mail | Should -Be 'b@example.test'
    }
    It 'the posted hash ignores nothing new: a changed device fact changes the posted content' {
        $a = ConvertTo-SICiPostRow -Ci ([ordered]@{ si_ci_id = 'c'; si_class = 'device'; si_collection_time = $script:T; si_os_build = '1' })
        $b = ConvertTo-SICiPostRow -Ci ([ordered]@{ si_ci_id = 'c'; si_class = 'device'; si_collection_time = $script:T; si_os_build = '2' })
        (Get-SIContentHash -Item $a -Exclude @('si_collection_time', 'si_last_seen')) | Should -Not -Be (Get-SIContentHash -Item $b -Exclude @('si_collection_time', 'si_last_seen'))
    }
}

Describe 'a directory group is typed Group -- never Other / General' {
    It 'the Exposure Graph group node: identity type group, the group''s name as display name' {
        $r = EgRecord -Label 'group' -Name 'SEC-Example-Admins' -RecordType 'user'
        $r['si_identity_type'] | Should -Be 'group'
        $r['si_asset_type'] | Should -Be 'group'
        $r['si_display_name'] | Should -Be 'SEC-Example-Admins'
    }
    It 'the classification rows: asset type Group, subtype Group, the source''s own kind kept' {
        $ci = CiOf (EgRecord -Label 'group' -Name 'SEC-Example-Admins' -RecordType 'user')
        $null = Invoke-SICiClassification -Cis @($ci) -Model $script:Model -Context $script:Ctx
        $ci['si_asset_type'] | Should -Be 'Group'
        $ci['si_asset_subtype'] | Should -Be 'Group'
        $ci['si_asset_type_source'] | Should -Be 'group'
    }
    It 'a user only the graph knows is a User / Member; a service principal and a managed identity say what they are' {
        $u = CiOf (EgRecord -Label 'user' -Name 'Example User' -RecordType 'user')
        $sp = CiOf (EgRecord -Label 'serviceprincipal' -Name 'example-app' -RecordType 'service_principal')
        $mi = CiOf (EgRecord -Label 'managedidentity' -Name 'example-mi' -RecordType 'service_principal')
        $u['si_identity_type'] | Should -Be 'user'
        $sp['si_identity_type'] | Should -Be 'service_principal'
        $mi['si_identity_type'] | Should -Be 'managed_identity'
        $null = Invoke-SICiClassification -Cis @($u, $sp, $mi) -Model $script:Model -Context $script:Ctx
        ($u['si_asset_type'], $u['si_asset_subtype']) | Should -Be @('User', 'Member')
        ($sp['si_asset_type'], $sp['si_asset_subtype']) | Should -Be @('Service principal', 'Application')
        ($mi['si_asset_type'], $mi['si_asset_subtype']) | Should -Be @('Managed identity', 'Managed identity')
    }
    It 'a node label the value map does not know gives no type (never a guess)' {
        $r = EgRecord -Label 'something-else' -Name 'x' -RecordType 'user'
        $r.Contains('si_identity_type') | Should -BeFalse
        $r.Contains('si_asset_type') | Should -BeFalse
    }
    It 'Group is a value of the asset type and asset subtype dimensions, and the data model is valid' {
        $dims = @{}; foreach ($d in @($script:Model['dimensions'].dimensions)) { $dims[[string]$d.id] = @($d.values) }
        $dims['asset_type'] | Should -Contain 'Group'
        $dims['asset_subtype'] | Should -Contain 'Group'
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
}

Describe 'every collection says what its sources offered -- new, nothing new, or not saved and why' {
    It 'the three lines of the run log are different, and each names the run' {
        $new = Get-SISourceDiscoverySummaryText -Result ([pscustomobject]@{ Properties = 12; NewContext = 2; Written = $true; Reason = '' }) -What 'the endpoint run'
        $same = Get-SISourceDiscoverySummaryText -Result ([pscustomobject]@{ Properties = 12; NewContext = 0; Written = $true; Reason = '' }) -What 'the identity run'
        $not = Get-SISourceDiscoverySummaryText -Result ([pscustomobject]@{ Properties = 12; NewContext = 0; Written = $false; Reason = 'no database is configured' }) -What 'the endpoint run'
        $new | Should -Match 'the endpoint run: 12; 2 are new'
        $same | Should -Match 'the identity run: 12; nothing new'
        $not | Should -Match 'not saved: no database is configured'
    }
    It 'GUARD: the publish writes the line to the run log for every outcome (once per process), not only when something is new' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1'))
        $src | Should -Match '\$script:SIDiscoverySaid\.ContainsKey\(\$dKey\)'
        $src | Should -Match "'not-saved'"
        $src | Should -Not -Match 'else \{ Write-Verbose \(Get-SISourceDiscoverySummaryText' -Because 'a run whose source properties were not saved, or that found nothing new, was silent'
    }
}

Describe 'the Azure context reaches every resource: the records exist before the context is read' {
    It 'the context reads add to the records in hand -- with no record there is nothing to add to' {
        $q = { param($k) @([pscustomobject]@{ SubscriptionId = 's1'; SubscriptionName = 'Example Production'; TenantId = 't1'; Chain = @([pscustomobject]@{ name = 'prod'; displayName = 'Production' }) }) }
        $null = Reset-SIRecordCapture -Engine 'azure' -Clear
        Invoke-SIManagementGroupCapture -Query $q -TenantNames @{} | Should -Be 0 -Because 'no Azure record is captured yet'
        Add-SIRecordPart -Provider 'azure' -RecordType 'azure_resource' -Key '/subscriptions/s1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1' -Part 'resource' `
            -Object ([pscustomobject]@{ id = '/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1'; name = 'kv1'; type = 'microsoft.keyvault/vaults' }) -ResourceType 'microsoft.keyvault/vaults'
        Invoke-SIManagementGroupCapture -Query $q -TenantNames @{} | Should -Be 1
        $rec = @($global:SIRecordCaptureState.Records.Values)[0]
        $rec.Parts.Contains('mg') | Should -BeTrue
        $global:SIRecordCaptureState = $null
    }
    It 'GUARD: the Azure discovery builds every resource''s record before it reads the subscription, management group and context' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureResources.ps1'))
        $build = $src.IndexOf('$built.Add((& $buildRes $r))')
        $mg = $src.IndexOf('Invoke-SIManagementGroupCapture -SubscriptionIds $SubscriptionIds')
        $cx = $src.IndexOf('Invoke-SIAzureContextCapture -SubscriptionIds $SubscriptionIds')
        $build | Should -BeGreaterThan 0
        $mg | Should -BeGreaterThan $build -Because 'the management-group and subscription-name read adds a part to the records already captured'
        $cx | Should -BeGreaterThan $build -Because 'backup, access, policy, changes, updates and the Defender plan are added to the records already captured'
        ([regex]::Matches($src, '&\s*\$buildRes\s+\$r')).Count | Should -Be 2 -Because 'one build per row: page by page when streamed, else once before the context reads -- never again after them'
    }
}
