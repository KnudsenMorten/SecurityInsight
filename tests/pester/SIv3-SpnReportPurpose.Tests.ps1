#Requires -Version 5.1
<#
    THE SERVICE PRINCIPAL REPORTS ANSWER THEIR PURPOSE (report certification, REQUIREMENTS #690 items 4-10). Each query was
    read against its ReportPurpose and fixed -- Detailed AND Summary:
      4  Identity_MultiTenant_HighPermission_SPN   the high-privilege filter; Microsoft first-party apps labelled apart, an
                                                  unreadable permission set kept and labelled (never dropped)
      5  Identity_SPN_OwnerMismatch               compares the owners of the two sides (si_owners.of), not names with a tenant id
      6  Identity_SPN_OverCredentialed            a secret AND a certificate (si_credentials), not the expiring filter
      7  Identity_SPN_PrivilegedAccessWrite       the current PIM schedule / policy permissions in pim_write_permissions
      8  Identity_SPN_RoleManagementWrite / AppRoleAssignmentWrite   each its own list (no overlap), tier from the CI, Very High
      9  Identity_SPN_MailboxAccess / MailboxImpersonation   the full mail list; the matched permissions in Impact
     10  Identity_PrivilegedSPN_NoLogin180Days    the privilege filter the name promises
    Plus the derive the owner-mismatch report reads: a person owning both sides is of = 'both'. Unknown tier = blank (never
    a default tier). Offline, PS 5.1 + 7 -- the query text is asserted; the queries are proved on internal by the certification.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordDerived.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    $script:Reports = @((ConvertFrom-SIYaml -Path (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')).Reports)
    $script:ByName = @{}; foreach ($r in $script:Reports) { $script:ByName[[string]$r.ReportName] = $r }
    $lists = (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'data-model\lists.locked.json') | ConvertFrom-Json).lists
    $script:List = @{}; foreach ($l in @($lists)) { $script:List[[string]$l.id] = @($l.values) }
    # the query body after the CI block (what the report itself says), comments removed
    function script:BodyOf([string]$Name) {
        $q = [string](@($script:ByName[$Name].ReportQuery) -join "`n")
        $i = $q.IndexOf('//__SI_CI_ASSET_END__'); if ($i -ge 0) { $q = $q.Substring($i) }
        (($q -split "`n") | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n"
    }
    function script:Both([string]$Base) { @("$($Base)_Detailed", "$($Base)_Summary") }
}

Describe '#690 (8) RoleManagementWrite and AppRoleAssignmentWrite: own list, CI tier, Very High' {
    It 'each reads only its own list and the two lists do not overlap (one finding, one report)' {
        foreach ($n in (script:Both 'Identity_SPN_RoleManagementWrite')) {
            $b = script:BodyOf $n
            $b | Should -Match 'SI_List_role_management_write_permissions' -Because $n
            $b | Should -Not -Match 'SI_List_role_assignment_write_permissions' -Because $n
            $b | Should -Not -Match 'SI_List_app_role_assignment_write_permissions' -Because $n
        }
        foreach ($n in (script:Both 'Identity_SPN_AppRoleAssignmentWrite')) {
            $b = script:BodyOf $n
            $b | Should -Match 'set_intersect\(_permsD, SI_List_app_role_assignment_write_permissions\)' -Because $n
            $b | Should -Not -Match 'SI_List_role_management_write_permissions|SI_List_role_assignment_write_permissions' -Because $n
        }
        @($script:List['role_management_write_permissions'] | Where-Object { $script:List['app_role_assignment_write_permissions'] -contains $_ }) | Should -BeNullOrEmpty
        @($script:List['pim_write_permissions'] | Where-Object { $script:List['role_management_write_permissions'] -contains $_ -or $script:List['app_role_assignment_write_permissions'] -contains $_ }) | Should -BeNullOrEmpty
    }
    It 'tier from the CI (unknown blank), never the constant 0; severity Very High as the purpose says (also PrivilegedAccessWrite)' {
        foreach ($n in @((script:Both 'Identity_SPN_RoleManagementWrite') + (script:Both 'Identity_SPN_AppRoleAssignmentWrite') + (script:Both 'Identity_SPN_PrivilegedAccessWrite'))) {
            $b = script:BodyOf $n
            $b | Should -Not -Match 'CriticalityTier\s*=\s*0\b' -Because $n
            $b | Should -Not -Match 'CriticalityTierLevel = "Critical - tier 0"' -Because $n
            $b | Should -Match 'CriticalityTier\s*=\s*si_tier' -Because $n
            $b | Should -Not -Match 'coalesce\(si_tier' -Because "$n -- a CI without a tier keeps CriticalityTier empty (the engine resolves it; SIv3-ReportScopeHonest pins the level label)"
            $b | Should -Match 'SecuritySeverity\s*=\s*"Very High"' -Because $n
        }
    }
}

Describe '#690 (7) PrivilegedAccessWrite: the current PIM permissions' {
    It 'pim_write_permissions holds the schedule, policy and legacy permissions' {
        foreach ($p in 'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleAssignmentSchedule.ReadWrite.Directory', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
                       'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup', 'RoleManagementPolicy.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.AzureADGroup',
                       'PrivilegedAccess.ReadWrite.AzureAD', 'PrivilegedAccess.ReadWrite.AzureADGroup', 'PrivilegedAccess.ReadWrite.AzureResources') {
            $script:List['pim_write_permissions'] | Should -Contain $p
        }
    }
    It 'both variants read it, and the YAML copy of the list is the data model''s' {
        foreach ($n in (script:Both 'Identity_SPN_PrivilegedAccessWrite')) {
            $q = [string](@($script:ByName[$n].ReportQuery) -join "`n")
            $q | Should -Match 'RoleEligibilitySchedule\.ReadWrite\.Directory' -Because "$n scope block"
            (script:BodyOf $n) | Should -Match 'set_intersect\(_permsD, SI_List_pim_write_permissions\)' -Because $n
        }
    }
}

Describe '#690 (9) MailboxAccess / MailboxImpersonation: the full mail list, the matched permissions named' {
    It 'mail_access_permissions holds MailboxItem.*, MailboxFolder.*, Mail-Advanced, Mailbox.Migration (and the old ones)' {
        foreach ($p in 'Mail.Read', 'Mail.ReadWrite', 'Mail.Send', 'Mail.ReadBasic', 'Mail.ReadBasic.All', 'Mail-Advanced.ReadWrite.All', 'MailboxSettings.ReadWrite',
                       'MailboxItem.Read.All', 'MailboxItem.ImportExport.All', 'MailboxFolder.Read.All', 'MailboxFolder.ReadWrite.All', 'Mailbox.Migration',
                       'full_access_as_app', 'EWS.AccessAsApp', 'EWS.AccessAsUser.All') {
            $script:List['mail_access_permissions'] | Should -Contain $p
        }
    }
    It 'every variant matches through the list (case-insensitive fallback) and the Detailed rows name the matched permissions in Impact' {
        foreach ($n in @((script:Both 'Identity_SPN_MailboxAccess') + (script:Both 'Identity_SPN_MailboxImpersonation'))) {
            $b = script:BodyOf $n
            $b | Should -Match 'set_intersect\(_permsD, SI_List_mail_access_permissions\)' -Because $n
            $b | Should -Match 'tolower\(tostring\(SI_List_mail_access_permissions\)\)' -Because $n
            $b | Should -Not -Match 'coalesce\(si_tier, (2|999)\)' -Because "$n -- no default tier"
        }
        (script:BodyOf 'Identity_SPN_MailboxAccess_Detailed') | Should -Match 'Impact = strcat\("Mail permissions held - ", strcat_array\(MatchedPermissions'
        (script:BodyOf 'Identity_SPN_MailboxAccess_Detailed') | Should -Match 'AssetType, Impact, SecuritySeverity'
        (script:BodyOf 'Identity_SPN_MailboxImpersonation_Detailed') | Should -Match 'strcat_array\(MailScopes, ", "\)'
    }
    It 'managed identities are not left out of the impersonation report' {
        foreach ($n in (script:Both 'Identity_SPN_MailboxImpersonation')) { (script:BodyOf $n) | Should -Match 'si_identity_type in \("service_principal", "managed_identity"\)' -Because $n }
    }
}

Describe '#690 (4) MultiTenant_HighPermission_SPN: the high-privilege filter; Microsoft apps labelled, unknown kept' {
    It 'filters on privilege, keeps an unreadable permission set, labels Microsoft first-party in Subcategory' {
        foreach ($n in (script:Both 'Identity_MultiTenant_HighPermission_SPN')) {
            $b = script:BodyOf $n
            $b | Should -Match 'set_intersect\(_permsD, SI_List_high_privilege_app_permissions\)' -Because $n
            $b | Should -Match ([regex]::Escape('si_high_risk_permission_grant == true or si_privilege_tier_permanent in (0, 1)')) -Because $n
            $b | Should -Match ([regex]::Escape('where _isPrivileged or not(_privKnown)')) -Because "$n -- unknown stays in"
            $b | Should -Match ([regex]::Escape('tolower(si_app_owner_org_id) in (SI_List_microsoft_first_party_tenants)')) -Because $n
            $b | Should -Match 'Multi-Tenant Exposure - Microsoft first-party application' -Because $n
            $b | Should -Not -Match 'where not\(.*microsoft_first_party' -Because "$n -- labelled, never dropped"
        }
        (script:BodyOf 'Identity_MultiTenant_HighPermission_SPN_Detailed') | Should -Match 'privilege is not readable'
    }
    It 'high_privilege_app_permissions carries the Tier 0 / 1 permissions (directory, roles, apps, PIM, mail, files)' {
        foreach ($p in 'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All', 'Directory.ReadWrite.All', 'Application.ReadWrite.All',
                       'RoleEligibilitySchedule.ReadWrite.Directory', 'Mail.ReadWrite', 'full_access_as_app', 'Sites.FullControl.All') {
            $script:List['high_privilege_app_permissions'] | Should -Contain $p
        }
    }
}

Describe '#690 (10) PrivilegedSPN_NoLogin180Days: the privilege filter' {
    It 'both variants keep only privileged workloads -- or ones whose privilege is unknown, labelled' {
        foreach ($n in (script:Both 'Identity_PrivilegedSPN_NoLogin180Days')) {
            $b = script:BodyOf $n
            $b | Should -Match 'SI_List_high_privilege_app_permissions' -Because $n
            $b | Should -Match ([regex]::Escape('si_privilege_tier_eligible in (0, 1) or si_tier in (0, 1)')) -Because $n
            $b | Should -Match ([regex]::Escape('where _isPrivileged or not(_privKnown)')) -Because $n
            $b | Should -Not -Match 'coalesce\(si_tier, 2\)' -Because $n
        }
        (script:BodyOf 'Identity_PrivilegedSPN_NoLogin180Days_Detailed') | Should -Match 'Impact = iff\(not\(_privKnown\), "Privilege not readable'
    }
}

Describe '#690 (6) OverCredentialed: a secret AND a certificate' {
    It 'counts the credential types from si_credentials; the expiring filter is gone' {
        foreach ($n in (script:Both 'Identity_SPN_OverCredentialed')) {
            $b = script:BodyOf $n
            $b | Should -Not -Match 'si_credential_expiry_days <= 30' -Because $n
            $b | Should -Match 'countif\(tostring\(_cr\.type\) == "secret"\)' -Because $n
            $b | Should -Match 'countif\(tostring\(_cr\.type\) == "certificate"\)' -Because $n
            $b | Should -Match 'where SecretCount > 0 and CertificateCount > 0' -Because $n
        }
    }
    It 'the derive types every credential secret or certificate (what the report counts)' {
        $o = [pscustomobject]@{ sp = [pscustomobject]@{ id = 's1'; keyCredentials = @([pscustomobject]@{ keyId = 'k1'; endDateTime = '2030-01-01T00:00:00Z' }) }
                                app = [pscustomobject]@{ passwordCredentials = @([pscustomobject]@{ keyId = 'p1'; endDateTime = '2030-01-01T00:00:00Z' }) } }
        $c = @((Get-SIEntraSpContextDerived -Object $o -Now ([datetime]'2026-10-15'))['credentials'])
        @($c | ForEach-Object { $_.type } | Sort-Object) | Should -Be @('certificate', 'secret')
    }
}

Describe '#690 (5) OwnerMismatch: the two owner lists compared' {
    It 'reads si_owners by side, never the owning tenant id; the CI block carries si_owners' {
        foreach ($n in (script:Both 'Identity_SPN_OwnerMismatch')) {
            $b = script:BodyOf $n
            $b | Should -Not -Match 'AppOwner = si_app_owner_org_id' -Because $n
            $b | Should -Match 'tostring\(_ow\["of"\]\) == "service principal"' -Because $n
            $b | Should -Match 'tostring\(_ow\["of"\]\) == "application"' -Because $n
            $b | Should -Match 'tostring\(_ow\["of"\]\) == "both"' -Because $n
            $b | Should -Match ([regex]::Escape('where array_length(SpOnlyOwners) > 0 or array_length(AppOnlyOwners) > 0')) -Because $n
            [string](@($script:ByName[$n].ReportQuery) -join "`n") | Should -Match 'si_owners = todynamic\(column_ifexists\("si_owners"' -Because $n
        }
        $script:RACiAssetFields.Contains('si_owners') | Should -BeTrue
    }
    It 'the derive marks a person owning both sides as both, one side as that side' {
        $o = [pscustomobject]@{
            sp     = [pscustomobject]@{ id = 's1' }
            owners = [pscustomobject]@{ count = 2; items = @([pscustomobject]@{ id = 'u-both'; upn = 'a@x' }, [pscustomobject]@{ id = 'u-sp'; upn = 'b@x' }) }
            app    = [pscustomobject]@{ owners = @([pscustomobject]@{ id = 'U-BOTH'; upn = 'a@x' }, [pscustomobject]@{ id = 'u-app'; upn = 'c@x' }) }
        }
        $own = @((Get-SIEntraSpContextDerived -Object $o)['owners'])
        $own.Count | Should -Be 3 -Because 'each person once'
        $of = @{}; foreach ($x in $own) { $of[[string]$x.id] = [string]$x.of }
        $of['u-both'] | Should -Be 'both'
        $of['u-sp'] | Should -Be 'service principal'
        $of['u-app'] | Should -Be 'application'
    }
}
