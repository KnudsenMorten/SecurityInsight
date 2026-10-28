#Requires -Version 5.1
<#
    THE OUTPUT FIELD MAPPER (engine/data-model/SI-OutputMapper.ps1) -- V3-DATA-MODEL part 2, 2.12.

      * COLUMNS: an output map turns a CI document into the output's columns, in the map's order, with the closed output
        operations (render the linked objects, join the risk-factor ids, round, format a date, map a value, keep a value
        only for one class) and the system tokens ($run_id, $run_time, $const:).
      * DELTA: $row_hash covers every content column and not the run time: the same CI hashes the same on the next run,
        and a changed tier changes the hash -- what a connector's delta reads.
      * FILTER: a map's filter keeps only the classes it names (the ServiceNow CI map never sends a public IP).
      * CLOSED: an unknown operation throws; every shipped output map applies to a sample CI / finding without error.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-OutputMapper.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:VM = $script:Model['value-maps'].maps
    $script:Ci = [ordered]@{
        si_ci_id = '11111111-2222-3333-4444-555555555555'; si_class = 'device'; si_asset_name = 'srv01'; si_asset_type = 'Server'; si_asset_type_source = 'server'; si_tier = 0
        si_tier_set_by = 'rule'; si_tier_reason = 'Domain controller (ad/dc)'; si_fqdn = 'srv01.contoso.local'; si_mac_addresses = @('00:15:5d:00:00:01', '00:15:5d:00:00:02')
        si_link_mde = 'abc'; si_link_entra = 'aad-1'; si_link_azure = '/subscriptions/s/vm1'; si_internet_exposed = $true; si_lifecycle = 'active'
        si_last_seen = [datetime]'2026-10-08T03:00:00Z'; si_criticality_factor = 1.254; si_cmdb_criticality = 'High'
        si_risk_factors = @([ordered]@{ id = 'internet_exposed'; impact = 1 }, [ordered]@{ id = 'tier0'; impact = 1 })
        si_linked_objects = @([ordered]@{ provider = 'mde'; id = 'abc' }, [ordered]@{ provider = 'azure'; id = '/subscriptions/s/vm1' })
    }
}

Describe 'Mapping a CI to an output' {
    It 'builds the Excel CI row in the map''s order with its operations' {
        $r = @(Invoke-SIOutputMap -Map $script:Model.Outputs['excel-ci'] -Items @($script:Ci) -ValueMaps $script:VM)[0]
        @($r.PSObject.Properties.Name)[0..2] | Should -Be @('CI', 'Name', 'Class')
        $r.Tier | Should -Be 0
        $dump = $r | ConvertTo-Json -Compress -Depth 4
        $r.'Risk factors' | Should -Be 'internet_exposed;tier0' -Because $dump
        $r.'Linked objects' | Should -Be 'mde:abc; azure:/subscriptions/s/vm1' -Because $dump
        $r.'Criticality factor' | Should -Be 1.25
        $r.'Last seen' | Should -Be '2026-10-08 03:00' -Because $dump
    }
    It 'builds the ServiceNow hand-off row: class hint, device-only ids, the first MAC, the DNS domain, constants' {
        $r = @(Invoke-SIOutputMap -Map $script:Model.Outputs['servicenow-ci'] -Items @($script:Ci) -ValueMaps $script:VM -Context @{ RunId = 'run-9'; RunTime = [datetime]'2026-10-08T04:00:00Z' })[0]
        $r.u_si_correlation_id | Should -Be $script:Ci.si_ci_id
        $r.u_class_hint | Should -Be 'device'
        $r.u_proposed_class | Should -Be 'cmdb_ci_server'
        $r.u_aad_device_id | Should -Be 'aad-1'
        $r.u_entra_object_id | Should -BeNullOrEmpty
        $r.u_mac_address | Should -Be '00:15:5d:00:00:01'
        $r.u_dns_domain | Should -Be 'contoso.local'
        $r.u_discovery_source | Should -Be 'SecurityInsight'
        $r.u_source_run | Should -Be 'run-9'
        $r.u_row_hash | Should -Match '^[0-9a-f]{64}$'
    }
    It 'hashes the content, not the run: same CI next run = same hash; another tier = another hash' {
        $m = $script:Model.Outputs['servicenow-ci']
        $a = @(Invoke-SIOutputMap -Map $m -Items @($script:Ci) -ValueMaps $script:VM -Context @{ RunId = 'r1'; RunTime = [datetime]'2026-10-08' })[0].u_row_hash
        $b = @(Invoke-SIOutputMap -Map $m -Items @($script:Ci) -ValueMaps $script:VM -Context @{ RunId = 'r2'; RunTime = [datetime]'2026-10-09' })[0].u_row_hash
        $a | Should -Be $b
        $c2 = [ordered]@{}; foreach ($k in $script:Ci.Keys) { $c2[$k] = $script:Ci[$k] }; $c2.si_tier = 1
        @(Invoke-SIOutputMap -Map $m -Items @($c2) -ValueMaps $script:VM)[0].u_row_hash | Should -Not -Be $a
    }
    It 'sends only the classes the map''s filter names' {
        $pip = [ordered]@{ si_ci_id = 'p'; si_class = 'public_ip' }
        @(Invoke-SIOutputMap -Map $script:Model.Outputs['servicenow-ci'] -Items @($script:Ci, $pip) -ValueMaps $script:VM).Count | Should -Be 1
    }
}

Describe 'A closed operation set' {
    It 'refuses an unknown operation' {
        $m = [pscustomobject]@{ columns = @([pscustomobject]@{ target = 'x'; from = 'si_tier'; op = 'script:Get-Process' }) }
        { @(Invoke-SIOutputMap -Map $m -Items @($script:Ci)) } | Should -Throw '*unknown output operation*'
    }
    It 'applies every shipped output map to a sample CI and finding without error' {
        $finding = [ordered]@{ si_ci_id = 'x'; si_finding_key = 'CVE-2024-1'; si_title = 't'; si_severity = 'high'; si_finding_state = 'open'; si_detected_by = @('r1', 'r2'); si_finding_risk_factors = @('a') }
        foreach ($id in $script:Model.Outputs.Keys) {
            $rows = @(Invoke-SIOutputMap -Map $script:Model.Outputs[$id] -Items @($script:Ci, $finding) -ValueMaps $script:VM)
            $rows.Count | Should -BeGreaterThan 0 -Because "output map $id"
        }
    }
}
