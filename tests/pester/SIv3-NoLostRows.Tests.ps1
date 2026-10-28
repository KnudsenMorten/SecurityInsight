#Requires -Version 5.1
<#
    #690 (35) -- NO SOURCE FINDING IS LOST ON THE WAY INTO SI (owner 2026-10-15: "any finding people can see in mde, mdc,
    entra, azure etc must exist in si. si might have more rows. but never less" / "we can NOT loose any data").

    Measured read-only on internal 2026-10-15 (the reports of si-v3 HEAD run against the workspace, Graph / hunting as the
    source):
      * ONE-ITEM LISTS were lost twice on the way from the identity profile to SI_CI_CL. The profile writes a one-item list as
        the bare item ("Global Administrator"); the field mapper's parse_json dropped every text that was not JSON, so
        si_entra_roles_permanent / _eligible, si_app_permissions, si_group_memberships ... were EMPTY for every identity with
        exactly one role, permission or group (14 identities with one standing role, 14 service principals with one
        application permission). And the SI_CI_CL post (ConvertTo-SILogValue) unrolled every one-item array into its item,
        so a report reading the field as a list (array_length, set_has_element, mv-expand) lost the identity again --
        Identity_TooManyGlobalAdmins saw 3 of 6 Global Administrators (0 rows), PrivilegedRole_PermanentNotEligible 4 of 22.
      * A SERVICE PRINCIPAL WITHOUT A PROFILE ROW had no creation date (si_created came from the profile only), so the
        old_account factor never fired for it (190 of 1,103 service principals had a date; Graph gives one for all).
      * THE STALE CUT (scope part `stale`, not(si_stale_)) removed a CI whose newest last-seen was older than the stale days.
        On an identity that last-seen is its sign-in activity and on a public IP Shodan's last scan -- the cut removed
        exactly the inactive accounts the stale-account reports ask about, and a scanned address Shodan still shows.
      * THE PUBLIC IP REPORTS read only CIs of class public_ip; every address Shodan scans on internal is an Azure public
        IP resource, a cloud_resource CI with a Shodan link -- the reports returned 0 rows (the source shows port 22 open).

    What this file pins (offline; nothing runs a query):
      A. a one-item list survives the field mapper and the SI_CI_CL post as a list; an empty list stays empty; a JSON text
         still parses; a malformed JSON text is still dropped
      B. a service principal gets si_created from its own Graph object when it has no profile row
      C. no identity or public IP report declares the stale cut, and no such report's shipped query carries it
      D. the public IP reports read every CI with a Shodan link (no class filter), and the excluded address ranges apply to
         such a CI whatever its class
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldMapper.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Map = {
        param($o, [string]$rt)
        (ConvertTo-SIRecord -Object $o -Mapping $script:Model.Mappings['entra'] -RecordType $rt -Catalog $script:Model['field-catalog'] `
            -ValueMaps $script:Model['value-maps'].maps -CollectionTime ([datetime]'2026-10-15T03:00:00Z') -RunId 'run-1').Record
    }
    $script:Scope = Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\report-scope.locked.json') -Raw | ConvertFrom-Json
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml
    function script:QueryOf([string]$Name) {
        $r = @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0]
        if ($null -eq $r) { throw "no report $Name" }
        (@($r.ReportQuery) -join "`n")
    }
}

Describe 'A. a one-item list stays a list from the profile to SI_CI_CL' {
    It 'parse_json keeps a bare one-item text as the value (it used to drop it)' {
        $v = [System.Collections.Generic.List[object]]::new(); $v.Add('Global Administrator')
        $out = Invoke-SINormalizeOp -Values $v -Op 'parse_json' -Arg '' -ValueMaps $null
        @($out) | Should -Be @('Global Administrator')
    }
    It 'parse_json still parses JSON text, and still drops a malformed JSON text' {
        $v = [System.Collections.Generic.List[object]]::new(); $v.Add('["Global Administrator","Security Reader"]')
        $out = Invoke-SINormalizeOp -Values $v -Op 'parse_json' -Arg '' -ValueMaps $null
        $fv = ConvertTo-SIFieldValue -Values $out -Type 'dynamic'
        ($fv -join '|') | Should -Be 'Global Administrator|Security Reader'
        $bad = [System.Collections.Generic.List[object]]::new(); $bad.Add('["broken'); $bad.Add('{nope')
        (Invoke-SINormalizeOp -Values $bad -Op 'parse_json' -Arg '' -ValueMaps $null).Count | Should -Be 0
    }
    It 'a service principal and a user with ONE standing role keep it (si_entra_roles_permanent is a one-item list)' {
        $sp = & $script:Map ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-1'; displayName = 'Backup' }
                profile = [pscustomobject]@{ EntraRoles_Permanent = 'Global Administrator'; EntraAppPermissions_Application = 'Mail.Send'; NestedGroups = 'Tier0-Admins' } }) 'service_principal'
        $r = $sp['si_entra_roles_permanent']
        ($r -is [array]) | Should -BeTrue
        @($r) | Should -Be @('Global Administrator')
        @($sp['si_app_permissions']) | Should -Be @('Mail.Send')
        $u = & $script:Map ([pscustomobject]@{ user = [pscustomobject]@{ id = 'u-1'; userPrincipalName = 'bga-1@contoso.com' }
                profile = [pscustomobject]@{ EntraRoles_Permanent = 'Global Administrator'; EntraRoles_Eligible = '["Security Reader","Global Reader"]' } }) 'user'
        @($u['si_entra_roles_permanent']) | Should -Be @('Global Administrator')
        ($u['si_entra_roles_eligible'] -join '|') | Should -Be 'Security Reader|Global Reader'
    }
    It 'ConvertTo-SILogValue keeps a one-item list a list; an empty list stays $null; scalars as before' {
        $one = ConvertTo-SILogValue @('Global Administrator')
        ($one -is [array]) | Should -BeTrue
        $one.Count | Should -Be 1
        (ConvertTo-Json -InputObject ([pscustomobject]@{ r = $one }) -Compress) | Should -Be '{"r":["Global Administrator"]}'
        (ConvertTo-SILogValue @()) | Should -BeNullOrEmpty
        $null -eq (ConvertTo-SILogValue @()) | Should -BeTrue
        ConvertTo-SILogValue 'x' | Should -BeExactly 'x'
        ConvertTo-SILogValue 3 | Should -Be 3
        (ConvertTo-SILogValue 1.5) | Should -BeExactly '1.5'
        $two = ConvertTo-SILogValue @('a', 'b')
        $two.Count | Should -Be 2
    }
    It 'the SI_CI_CL full row carries a one-item role, path and port list as a JSON list' {
        $ci = [ordered]@{ si_ci_id = 'ci-1'; si_class = 'identity'; si_entra_roles_permanent = @('Global Administrator'); si_role_paths = @('Global Administrator (direct)')
                          si_open_ports = @(22); si_collection_time = [datetime]'2026-10-15T03:00:00Z' }
        $row = ConvertTo-SICiPostRow -Ci $ci
        $j = ConvertTo-Json -InputObject $row -Compress -Depth 8
        $j | Should -Match ([regex]::Escape('"si_entra_roles_permanent":["Global Administrator"]'))
        $j | Should -Match ([regex]::Escape('"si_role_paths":["Global Administrator (direct)"]'))
        $j | Should -Match ([regex]::Escape('"si_open_ports":[22]'))
    }
}

Describe 'B. a service principal without a profile row still has its creation date' {
    It 'si_created from the service principal''s own Graph object when the profile part is missing' {
        $sp = & $script:Map ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-9'; displayName = 'Microsoft app'; createdDateTime = '2021-03-04T05:06:07Z' } }) 'service_principal'
        $sp['si_created'] | Should -Be ([datetime]::SpecifyKind([datetime]'2021-03-04T05:06:07', 'Utc'))
    }
    It 'the profile''s date still wins when both are there' {
        $sp = & $script:Map ([pscustomobject]@{ sp = [pscustomobject]@{ id = 'sp-8'; createdDateTime = '2021-03-04T05:06:07Z' }; profile = [pscustomobject]@{ CreatedDateTime = '2020-01-01T00:00:00Z' } }) 'service_principal'
        $sp['si_created'].Year | Should -Be 2020
    }
    It 'the factor catalog names the same source for old_account' {
        $f = @($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'old_account' })[0]
        @($f.providers.entra | Where-Object { @($_.recordTypes) -contains 'service_principal' } | ForEach-Object { $_.sources }) | Should -Contain 'sp.createdDateTime'
    }
}

Describe 'C. the stale cut never applies where the last-seen is activity or a scan date' {
    It 'no identity or public IP report declares the stale part' {
        $bad = @($script:Scope.reports | Where-Object { ([string]$_.id -like 'Identity_*' -or [string]$_.id -like 'PublicIP_*') -and $_.scope.stale -eq $true } | ForEach-Object { $_.id })
        $bad | Should -BeNullOrEmpty -Because 'an identity''s last-seen is its sign-in activity, a public IP''s is Shodan''s last scan'
    }
    It 'no report whose subjects are only identities or public IPs declares it (a customer report named otherwise too)' {
        $only = @('identity-user', 'service-principal', 'managed-identity', 'public-ip', 'vulnerability')
        $bad = @($script:Scope.reports | Where-Object { $_.scope.stale -eq $true -and @(@($_.subjects) | Where-Object { $only -notcontains [string]$_ }).Count -eq 0 } | ForEach-Object { $_.id })
        $bad | Should -BeNullOrEmpty
    }
    It 'the shipped query of every identity and public IP report carries no not(si_stale_)' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($script:Catalog.Reports)) {
            $n = [string]$r.ReportName
            if (-not ($n -like 'Identity_*' -or $n -like 'PublicIP_*')) { continue }
            if ((@($r.ReportQuery) -join "`n") -match 'not\(si_stale_\)') { $bad.Add($n) }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'the stale-account reports keep an account no source saw recently (the scope predicate has no stale test)' {
        foreach ($n in 'Identity_StaleUser_NoLogin180Days_Detailed', 'Identity_StaleGuest_NoLogin90Days_Detailed', 'Identity_PrivilegedSPN_NoLogin180Days_Detailed', 'Identity_AdminAccount_NeverUsed_Detailed') {
            $spec = Get-RAReportScope -ReportName $n -Template $script:Scope
            $spec.Scope.stale | Should -BeFalse -Because $n
            $a = Get-RAScopeActive -Spec $spec -Values (Get-RAScopeDefaults -Spec $spec)
            (Get-RAScopeCiPredicate -Active $a) | Should -Not -Match 'si_stale_' -Because $n
        }
    }
}

Describe 'D. the public IP reports read every CI Shodan scans' {
    It 'their CI block has no class filter and the report selects on the Shodan link' {
        foreach ($n in 'PublicIP_OpenPorts_Summary', 'PublicIP_OpenPorts_Detailed', 'PublicIP_Vulnerabilities_Summary', 'PublicIP_Vulnerabilities_Detailed') {
            $q = script:QueryOf $n
            $m = [regex]::Match($q, '(?s)//__SI_CI_ASSET_BEGIN__.*?//__SI_CI_ASSET_END__')
            $m.Success | Should -BeTrue -Because $n
            $m.Value | Should -Not -Match 'tostring\(si_class\) in' -Because "$n -- an Azure public IP resource is a cloud_resource CI"
            $q.Substring($m.Index + $m.Length) | Should -Match 'where isnotempty\(si_link_shodan\)' -Because $n
        }
    }
    It 'the excluded address ranges apply to a Shodan-linked CI whatever its class' {
        $spec = Get-RAReportScope -ReportName 'PublicIP_OpenPorts_Detailed' -Template $script:Scope
        $d = Get-RAScopeDefaults -Spec $spec; $d.ExcludedIpRanges = @('10.0.0.0/8')
        $p = Get-RAScopeCiPredicate -Active (Get-RAScopeActive -Spec $spec -Values $d)
        $p | Should -Match ([regex]::Escape('isnotempty(tostring(column_ifexists("si_link_shodan", "")))'))
        $p | Should -Match ([regex]::Escape('ipv4_is_in_any_range(tostring(column_ifexists("si_ip_address", "")), dynamic(["10.0.0.0/8"]))'))
    }
}
