#Requires -Version 5.1
<#
    ONE CMDB OWNER PER TENANT + THE CMDB FIELD CATALOG ON THE CI (#463, V3-DATA-MODEL 2.8.1, D11). Offline.
      * The catalog's `cmdb_owner` authority token is the tenant's owner (SIWeb_CmdbSource): a si_cmdb_* field takes its value
        from the owner's record only -- a non-owner CMDB never decides (before #463 the token matched no provider, so the
        newest record of ANY CMDB won).
      * The CMDB values come from the OWNER's records: SecurityInsight's own CMDB (the cache) when the owner is cmdb; the
        external system's cmdb_ci records (install database) when it is servicenow -- SI's own CMDB is then not read.
      * The whole catalog reaches the CI: name, class, criticality, data sensitivity, environment, owner, owner department,
        service, support group, source, match rule + confidence.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-10T06:00:00', 'Utc')
    $script:Field = [pscustomobject]@{ name = 'si_cmdb_criticality'; type = 'string'; level = 'both'; resolution = [pscustomobject]@{ policy = 'authority'; authority = @('cmdb_owner') } }
    function script:Cand([string]$prov, [string]$val, [int]$hoursAgo) {
        [pscustomobject]@{ Provider = $prov; Key = "$prov|cmdb_ci|1"; State = 'active'
            Record = [pscustomobject]@{ si_cmdb_criticality = $val; si_source_last_seen = $script:Now.AddHours(-$hoursAgo) } }
    }
}

Describe 'The cmdb_owner authority: only the owner decides a CMDB field' {
    It 'owner servicenow: its value wins even when SI''s own CMDB record is newer' {
        $r = Resolve-SICiField -Field $script:Field -Candidates @((Cand 'servicenow' 'Business Critical' 48), (Cand 'cmdb' 'Low' 1)) -Now $script:Now -CmdbOwner 'servicenow'
        $r.Value | Should -Be 'Business Critical'
        $r.Provider | Should -Be 'servicenow'
    }
    It 'owner cmdb: an external CMDB''s value never decides -- no owner value, no value' {
        (Resolve-SICiField -Field $script:Field -Candidates @((Cand 'servicenow' 'Business Critical' 1)) -Now $script:Now -CmdbOwner 'cmdb') | Should -BeNullOrEmpty
        (Resolve-SICiField -Field $script:Field -Candidates @((Cand 'servicenow' 'x' 1), (Cand 'cmdb' 'High' 5)) -Now $script:Now -CmdbOwner 'cmdb').Value | Should -Be 'High'
    }
    It 'a field with a provider authority list is unchanged' {
        $f = [pscustomobject]@{ name = 'si_os_version'; type = 'string'; level = 'both'; resolution = [pscustomobject]@{ policy = 'authority'; authority = @('mde', 'entra') } }
        $c = @([pscustomobject]@{ Provider = 'entra'; Key = 'e'; State = 'active'; Record = [pscustomobject]@{ si_os_version = '1'; si_source_last_seen = $script:Now } },
               [pscustomobject]@{ Provider = 'mde'; Key = 'm'; State = 'active'; Record = [pscustomobject]@{ si_os_version = '2'; si_source_last_seen = $script:Now.AddHours(-3) } })
        (Resolve-SICiField -Field $f -Candidates $c -Now $script:Now -CmdbOwner 'servicenow').Value | Should -Be '2'
    }
    It 'Get-SICmdbOwner reads SIWeb_CmdbSource (cmdb by default)' {
        $saved = $global:SIWeb_CmdbSource
        try {
            $global:SIWeb_CmdbSource = ''; Get-SICmdbOwner | Should -Be 'cmdb'
            $global:SIWeb_CmdbSource = 'External-Connector'; Get-SICmdbOwner | Should -Be 'servicenow'
        } finally { $global:SIWeb_CmdbSource = $saved }
    }
}

Describe 'The CMDB values come from the owner''s records' {
    BeforeAll {
        $script:SnRec = [pscustomobject]@{ si_cmdb_id = 'CI0012'; si_cmdb_name = 'Payroll VM'; si_cmdb_class = 'cmdb_ci_vm_instance'; si_cmdb_criticality = '1 - most critical'
            si_cmdb_data_sensitivity = 'Restricted'; si_cmdb_environment = 'Production'; si_cmdb_owner = 'bo@x'; si_cmdb_owner_department = 'Finance'; si_cmdb_service = 'Payroll'
            si_cmdb_support_group = 'Server Ops'; azure_resource_id = '/subscriptions/s/vm/payroll'; si_fqdn = 'payroll.corp' }
    }
    It 'an external owner''s cmdb_ci record gives the CI the whole catalog, by the Azure resource id (strong)' {
        $idx = New-SICiCmdbIndexFromRecords -Records @($script:SnRec)
        $ci = [ordered]@{ si_ci_id = 'c1'; si_class = 'device'; si_link_azure = '/subscriptions/s/vm/payroll' }
        $null = Set-SICiCmdb -Ci $ci -Index $idx -CmdbOwner 'servicenow'
        $ci['si_cmdb_id'] | Should -Be 'CI0012'
        foreach ($p in @(@('si_cmdb_name', 'Payroll VM'), @('si_cmdb_class', 'cmdb_ci_vm_instance'), @('si_cmdb_environment', 'Production'), @('si_cmdb_owner', 'bo@x'),
                         @('si_cmdb_owner_department', 'Finance'), @('si_cmdb_service', 'Payroll'), @('si_cmdb_support_group', 'Server Ops'), @('si_cmdb_data_sensitivity', 'restricted'))) {
            $ci[$p[0]] | Should -Be $p[1] -Because $p[0]
        }
        $ci['si_cmdb_source'] | Should -Be 'servicenow'
        $ci['si_cmdb_match_rule'] | Should -Be 'identifier'; $ci['si_cmdb_match_confidence'] | Should -Be 'strong'
    }
    It 'a rule''s CMDB id picks the record; a value a rule set still wins' {
        $idx = New-SICiCmdbIndexFromRecords -Records @($script:SnRec)
        $ci = [ordered]@{ si_ci_id = 'c2'; si_class = 'device'; si_cmdb_id = 'ci0012'; si_cmdb_criticality = 'Set by rule' }
        $null = Set-SICiCmdb -Ci $ci -Index $idx -CmdbOwner 'servicenow'
        $ci['si_cmdb_criticality'] | Should -Be 'Set by rule'
        $ci['si_cmdb_name'] | Should -Be 'Payroll VM'
        $ci['si_cmdb_match_rule'] | Should -Be 'rule'
    }
    It 'owner servicenow: its records are read from the database and SI''s own CMDB is not' {
        $script:Asked = $null
        Mock Get-SICiCmdbIndexFromCache { throw 'SI''s own CMDB must not be read when the owner is external' }
        $sql = { param($q, $p, $m) $script:Asked = $p; @([pscustomobject]@{ RecordKey = 'servicenow|cmdb_ci|CI0012'; DocJson = ($script:SnRec | ConvertTo-Json -Compress) }) }
        $idx = Get-SICiCmdbIndexForOwner -Owner 'servicenow' -Sql $sql -Log { param($l, $m) }
        $script:Asked.p | Should -Be 'servicenow'
        $idx.Services.ContainsKey('ci0012') | Should -BeTrue
        $idx.ByFqdn.ContainsKey('payroll.corp') | Should -BeTrue
    }
    It 'owner servicenow with no records: an empty index, said -- never a fall-back to SI''s own CMDB' {
        Mock Get-SICiCmdbIndexFromCache { throw 'no fall-back' }
        $w = New-Object System.Collections.Generic.List[string]
        $idx = Get-SICiCmdbIndexForOwner -Owner 'servicenow' -Sql { param($q, $p, $m) @() } -Log { param($l, $m) if ($l -eq 'WARN') { $w.Add($m) } }
        $idx.Count | Should -Be 0
        ($w -join ' ') | Should -Match 'no servicenow CMDB records'
    }
    It 'owner cmdb: SI''s own CMDB cache, with class and support group from a service' {
        Mock Get-SICiCmdbIndexFromCache { New-SICiCmdbIndex -Services @([pscustomobject]@{ id = 'svc-1'; name = 'Intranet'; Class = 'app'; SupportGroup = 'Web team' }) }
        # SecurityInsight's own CMDB is read only while SI_EnableCmdbProvider is on (off by default: SIv3-SettingsHonoured)
        $idx = Get-SICiCmdbIndexForOwner -Owner 'cmdb' -CmdbProviderOn $true
        $ci = [ordered]@{ si_ci_id = 'c3'; si_cmdb_id = 'svc-1' }
        $null = Set-SICiCmdb -Ci $ci -Index $idx -CmdbOwner 'cmdb'
        $ci['si_cmdb_class'] | Should -Be 'app'
        $ci['si_cmdb_support_group'] | Should -Be 'Web team'
        $ci['si_cmdb_source'] | Should -Be 'cmdb'
    }
}
