#Requires -Version 5.1
<#
    SI v3 -- THE IDENTITY PUBLISH SCOPE. What reaches SI_Identity_Profile_CL (and the provider records in SQL, written
    from the same set), and what does not. Drives the real decision: engine\asset-profiling\shared\SI-IdentityPublishScope.ps1.

    🔴 THE DROP THESE TESTS PIN (found 2026-10-10). MEASURED on a large customer tenant 2026-10-08/09: every identity
    run wrote ~8,994 rows -- 8,939 enabled members, 1 guest, 0 DISABLED, 44 service principals, 10 managed identities --
    while Graph counted 22,705 users. Discovery reads every user (enabled, disabled, guests, soft-deleted) and every
    service principal; Invoke-Output then dropped every identity whose ENTRA_Enabled was not $true
    (`if ($m.PSObject.Properties['ENTRA_Enabled'] -and $m.ENTRA_Enabled -ne $true) { $nDisabled++; continue }`).
    🔒 OWNER DECISION 2026-10-10 -- "Everything, findings decide": every user and every tenant-owned SP / MI is
    published; the reports decide what matters (each one that means "enabled" filters AccountEnabled itself -- pinned
    below). Microsoft first-party applications this tenant granted NOTHING stay out (the 2026-08-27 actionability rule).

    🔴 THE EARLIER DEFECT, still pinned: no sign-in RECORD is not evidence of inactivity (2026-08-27: 1,599 of 1,613
    identities carried no sign-in figure because the logs cover only what is ingested and retained).
#>

BeforeAll {
    $script:SIRootDir = (Resolve-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..')).Path
    $script:ScopePs1  = Join-Path $script:SIRootDir 'engine\asset-profiling\shared\SI-IdentityPublishScope.ps1'
    $script:OutputPs1 = Join-Path $script:SIRootDir 'engine\asset-profiling\stages\Invoke-Output.ps1'
    $script:Builder   = Join-Path $script:SIRootDir 'engine\asset-profiling\shared\Build-IdentityProfileRow.ps1'
    $script:RaYaml    = Join-Path $script:SIRootDir 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:MSTID     = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    . $script:ScopePs1

    function script:Rec {
        param(
            [string]$Name,
            [object]$Enabled = $true,
            [string]$OwnerTid,
            [object]$LastSignInDays,
            [object]$AppPerms, [object]$DirRoles, [object]$AzureRbac
        )
        $m = [pscustomobject]@{
            ENTRA_DisplayName                = $Name
            ENTRA_Enabled                    = $Enabled
            ENTRA_SPAppOwnerTenant           = $OwnerTid
            ENTRA_LastSignInDays             = $LastSignInDays
            ENTRA_AppPermissions_Application = $AppPerms
            ENTRA_AppPermissions_Delegated   = $null
            ENTRA_DirectoryRolesPermanent    = $DirRoles
            ENTRA_DirectoryRolesEligible     = $null
            ENTRA_AzureDelegations           = $AzureRbac
        }
        [pscustomobject]@{ Name = $Name; Metadata = $m }
    }
    function script:Scope {
        param([object[]]$Records, [switch]$IncludeInactive, [switch]$RequireSignIn, [int]$StaleDays = 30)
        ,@((Select-SIIdentityPublishScope -Records $Records -IncludeAll:$IncludeInactive -RequireRecentSignIn:$RequireSignIn -StaleDays $StaleDays).Records)
    }

    # ---- the reproduction: a FAKE DISCOVERY shaped exactly like the two identity connectors' records ------------------
    # (Get-DiscoveryFromEntraUsers $buildUser / Get-DiscoveryFromEntraServicePrincipals $buildSp -- the keys Collect and
    # the row builder read), turned into Collect's metadata, round-tripped through JSON (the staging blob), scoped.
    function script:FakeUser {
        param([string]$Id, [string]$Upn, [bool]$Enabled = $true, [string]$UserType = 'Member', [object[]]$Roles = @())
        @{ AssetId = "entra-user:$Id"; Source = 'EntraUser'; NormalizedKey = $Id; Name = $Upn
           ENTRA_UserId = $Id; ENTRA_UPN = $Upn; ENTRA_DisplayName = $Upn; ENTRA_Enabled = $Enabled; ENTRA_UserType = $UserType
           ENTRA_OnPrem = $false; ENTRA_LicenseCount = 1; ENTRA_DirectoryRolesPermanent = $Roles; ENTRA_DirectoryRolesEligible = @()
           ENTRA_AzureDelegations = @(); ENTRA_LastSignInDays = $null }
    }
    function script:FakeSp {
        param([string]$Id, [string]$Name, [string]$SpType = 'Application', [string]$Owner = 'aaaaaaaa-0000-0000-0000-000000000001',
              [bool]$Enabled = $true, [object[]]$AppPerms = @())
        @{ AssetId = "entra-sp:$Id"; Source = 'EntraServicePrincipal'; NormalizedKey = $Id; Name = $Name; Hint = 'app-registration'
           ENTRA_SPObjectId = $Id; ENTRA_SPAppId = "app-$Id"; ENTRA_SPType = $SpType; ENTRA_DisplayName = $Name; ENTRA_Enabled = $Enabled
           ENTRA_SPEnabled = $Enabled; ENTRA_SPAppOwnerTenant = $Owner; ENTRA_AppPermissions_Application = $AppPerms
           ENTRA_AppPermissions_Delegated = @(); ENTRA_DirectoryRolesPermanent = @(); ENTRA_DirectoryRolesEligible = @(); ENTRA_AzureDelegations = @() }
    }
    # Invoke-Collect's identity branches: ENTRA_AssetType + every ENTRA_* key, then the staging round-trip.
    function script:ToStagedRecord {
        param([hashtable]$Asset)
        $meta = @{ ENTRA_AssetType = $(if ($Asset.ENTRA_SPObjectId) { 'ServicePrincipal' } else { 'User' }) }
        foreach ($k in $Asset.Keys) { if ($k -like 'ENTRA_*') { $meta[$k] = $Asset[$k] } }
        $rec = [ordered]@{ AssetId = $Asset.AssetId; SI_RunId = 'r1'; TimeGenerated = '2026-10-10T00:00:00Z'; SI_Classify_Status = 'catalog'
                           Metadata = $meta; Verdict = @{ SI_Tier = 3; TierSources = '{}' } }
        ConvertTo-Json -InputObject $rec -Depth 8 -Compress | ConvertFrom-Json
    }
    $script:FakeDiscovery = @(
        script:FakeUser -Id '00000000-0000-0000-0000-000000000001' -Upn 'ada@contoso.test'
        script:FakeUser -Id '00000000-0000-0000-0000-000000000002' -Upn 'bob@contoso.test'
        script:FakeUser -Id '00000000-0000-0000-0000-000000000003' -Upn 'left.company@contoso.test' -Enabled $false
        script:FakeUser -Id '00000000-0000-0000-0000-000000000004' -Upn 'old.admin@contoso.test'    -Enabled $false -Roles @('Global Administrator')
        script:FakeUser -Id '00000000-0000-0000-0000-000000000005' -Upn 'partner_x.test#EXT#@contoso.test' -UserType 'Guest'
        script:FakeUser -Id '00000000-0000-0000-0000-000000000006' -Upn 'stale.guest#EXT#@contoso.test'    -UserType 'Guest' -Enabled $false
        script:FakeSp   -Id '10000000-0000-0000-0000-000000000001' -Name 'payroll-app'
        script:FakeSp   -Id '10000000-0000-0000-0000-000000000002' -Name 'retired-app' -Enabled $false
        script:FakeSp   -Id '10000000-0000-0000-0000-000000000003' -Name 'uami-backup' -SpType 'ManagedIdentity'
        script:FakeSp   -Id '10000000-0000-0000-0000-000000000004' -Name 'Office 365 Portal' -Owner $script:MSTID
        script:FakeSp   -Id '10000000-0000-0000-0000-000000000005' -Name 'Graph Explorer' -Owner $script:MSTID -AppPerms @('Directory.Read.All')
    )
}

Describe '🔴 the reproduction: every discovered identity of the kinds the owner named reaches the profile' {

    BeforeAll {
        $script:Staged = @($script:FakeDiscovery | ForEach-Object { script:ToStagedRecord $_ })
        $script:Res = Select-SIIdentityPublishScope -Records $script:Staged
    }

    It 'members, DISABLED users, guests (enabled and disabled), SPs (disabled too) and MIs are all published' {
        # 11 discovered: 1 Microsoft app granted nothing is the ONLY one left out. The old filter published 6 of these 11.
        $script:Res.Before    | Should -Be 11
        $script:Res.Published | Should -Be 10
        $names = @($script:Res.Records | ForEach-Object { $_.Metadata.ENTRA_DisplayName })
        foreach ($n in 'ada@contoso.test', 'bob@contoso.test', 'left.company@contoso.test', 'old.admin@contoso.test',
                       'partner_x.test#EXT#@contoso.test', 'stale.guest#EXT#@contoso.test', 'payroll-app', 'retired-app',
                       'uami-backup', 'Graph Explorer') {
            $names | Should -Contain $n
        }
        $names | Should -Not -Contain 'Office 365 Portal'
    }

    It 'the counts say what was published, by kind, and how many are disabled' {
        $script:Res.Users             | Should -Be 4
        $script:Res.Guests            | Should -Be 2
        $script:Res.ServicePrincipals | Should -Be 3
        $script:Res.ManagedIdentities | Should -Be 1
        $script:Res.Disabled          | Should -Be 4
        $script:Res.ExcludedVendor    | Should -Be 1
        $script:Res.GrantedFirstParty | Should -Be 1
        $line = Format-SIIdentityPublishScopeLine -Scope $script:Res
        $line | Should -Match '11 -> 10'
        $line | Should -Match '4 of them disabled'
        $line | Should -Match 'Left out 1 Microsoft-published'
    }

    It 'the built profile rows carry AccountEnabled / UserType / IdentityType, so the reports can filter (real row builder, child process)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-idscope-' + [guid]::NewGuid().ToString('N') + '.json')
        try {
            ConvertTo-Json -InputObject @($script:Res.Records) -Depth 10 | Set-Content -LiteralPath $tmp -Encoding UTF8
            # the builders share function names, so the row builder runs alone in its own process
            $cmd = @"
`$ErrorActionPreference='Stop'
. '$script:Builder'
`$rc = [pscustomobject]@{ CollectionTime = '2026-10-10T00:00:00Z'; Engine = 'identity'; RunId = 'r1' }
`$rows = foreach (`$r in @(Get-Content -LiteralPath '$tmp' -Raw | ConvertFrom-Json)) {
    `$row = Build-SIIdentityProfileRow -Record `$r -RunContext `$rc
    [ordered]@{ Name = [string]`$r.Metadata.ENTRA_DisplayName; AccountEnabled = [string]`$row.AccountEnabled; UserType = [string]`$row.UserType; IdentityType = [string]`$row.IdentityType }
}
'<ROWS>' + (ConvertTo-Json -InputObject @(`$rows) -Compress)
"@
            $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
            $out = & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -EncodedCommand $enc 2>&1
            $line = @($out) | Where-Object { "$_" -like '<ROWS>*' } | Select-Object -Last 1
            if (-not $line) { throw ('the row builder produced no rows; output was: {0}' -f (($out | Select-Object -Last 6) -join ' | ')) }
            $rows = @(ConvertFrom-Json -InputObject (([string]$line) -replace '^<ROWS>', ''))
        } finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }

        $rows.Count | Should -Be 10 -Because 'one profile row per published identity'
        $byName = @{}; foreach ($r in $rows) { $byName[$r.Name] = $r }
        $byName['left.company@contoso.test'].AccountEnabled        | Should -Be 'False'
        $byName['ada@contoso.test'].AccountEnabled                 | Should -Be 'True'
        $byName['partner_x.test#EXT#@contoso.test'].UserType       | Should -Be 'Guest'
        $byName['stale.guest#EXT#@contoso.test'].AccountEnabled    | Should -Be 'False'
        $byName['retired-app'].IdentityType                        | Should -Be 'ServicePrincipal'
        $byName['retired-app'].AccountEnabled                      | Should -Be 'False'
        $byName['uami-backup'].IdentityType                        | Should -Be 'ManagedIdentity'
        $byName['ada@contoso.test'].IdentityType                   | Should -Be 'User'
    }
}

Describe '🔴 no default exclusion on Enabled -- the drop cannot come back' {

    It 'a DISABLED account is published' {
        (script:Scope -Records @(script:Rec -Name 'ghost' -Enabled $false)).Count | Should -Be 1
    }

    It 'a disabled account holding permissions is published -- that is a finding (DisabledAccount_ActivePIMAssignment)' {
        (script:Scope -Records @(script:Rec -Name 'ghost-admin' -Enabled $false -DirRoles @('Global Administrator'))).Count | Should -Be 1
    }

    It 'Invoke-Output delegates to the scope function and no longer reads ENTRA_Enabled in its identity block' {
        $code = Get-Content $script:OutputPs1 -Raw
        $idBlock = [regex]::Match($code, '(?s)if \(\$RunContext\.Engine -ieq ''identity''\) \{.*?\n    \}').Value
        $idBlock | Should -Match 'Select-SIIdentityPublishScope'
        $idBlock | Should -Not -Match 'ENTRA_Enabled'
    }

    It 'the scope function leaves out only the vendor rule and the opt-in sign-in tightening' {
        $code = Get-Content $script:ScopePs1 -Raw
        $fn = [regex]::Match($code, '(?s)function Select-SIIdentityPublishScope \{.*?\n\}').Value
        $continues = [regex]::Matches($fn, '(?m)^.*\bcontinue\b.*$') | ForEach-Object { $_.Value.Trim() }
        @($continues).Count | Should -Be 3 -Because 'null record, vendor rule, sign-in tightening -- nothing else drops an identity'
        ($continues -join "`n") | Should -Not -Match 'ENTRA_Enabled'
    }
}

Describe '🔴 the sign-in figure: no RECORD is not evidence of inactivity' {

    It 'an identity with NO sign-in figure is PUBLISHED' {
        (script:Scope -Records @(script:Rec -Name 'svc-nightly' -LastSignInDays $null)).Count | Should -Be 1
    }

    It 'a DORMANT but enabled identity is published -- that is the finding, not the noise' {
        (script:Scope -Records @(script:Rec -Name 'svc-old' -LastSignInDays 400)).Count | Should -Be 1
    }
}

Describe '🔑 the one default exclusion: a Microsoft application this tenant granted nothing' {

    It 'is left out' {
        (script:Scope -Records @(script:Rec -Name 'Office 365 Portal' -OwnerTid $script:MSTID)).Count | Should -Be 0
    }

    It 'but is published when this tenant consented permissions to it' {
        (script:Scope -Records @(script:Rec -Name 'Some MS App' -OwnerTid $script:MSTID -AppPerms @('Directory.Read.All'))).Count | Should -Be 1
    }

    It 'and when it holds an Entra directory role' {
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -DirRoles @('Directory Readers'))).Count | Should -Be 1
    }

    It '🪤 and when it holds AZURE RBAC -- the signal a Graph-only check would miss' {
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -AzureRbac @('Reader @ /subscriptions/x'))).Count | Should -Be 1
    }

    It 'an EMPTY permission array is not a grant' {
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -AppPerms @() -DirRoles @() -AzureRbac @())).Count | Should -Be 0
    }

    It '🪤 an empty array that has been through JSON (the staging blob) is NOT a grant' {
        $roundTripped = @() | ConvertTo-Json -Compress | ConvertFrom-Json
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -AppPerms $roundTripped)).Count | Should -Be 0
    }

    It 'and a real grant that has been through JSON still IS one' {
        $roundTripped = @('User.ReadWrite.All', 'Directory.Read.All') | ConvertTo-Json -Compress | ConvertFrom-Json
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -AppPerms $roundTripped)).Count | Should -Be 1
    }

    It '🔴 a bare PSCustomObject with no properties reads as EMPTY' {
        (script:Scope -Records @(script:Rec -Name 'MS App' -OwnerTid $script:MSTID -AppPerms ([pscustomobject]@{}))).Count | Should -Be 0
    }

    It '🔒 USERS are never caught by the vendor rule -- they carry no owner tenant' {
        (script:Scope -Records @(script:Rec -Name 'morten' -OwnerTid $null)).Count | Should -Be 1
    }

    It 'a record with no metadata is kept rather than silently dropped' {
        (script:Scope -Records @([pscustomobject]@{ Name = 'odd'; Metadata = $null })).Count | Should -Be 1
    }
}

Describe 'the knobs' {

    It 'SI_IncludeInactive_Identity publishes everything, Microsoft applications too' {
        $recs = @(script:Rec -Name 'ghost' -Enabled $false; script:Rec -Name 'MS' -OwnerTid $script:MSTID)
        (script:Scope -Records $recs -IncludeInactive).Count | Should -Be 2
    }

    It 'SI_RequireRecentSignIn_Identity restores the old strict behaviour' {
        $recs = @(
            script:Rec -Name 'live'   -LastSignInDays 2
            script:Rec -Name 'old'    -LastSignInDays 400
            script:Rec -Name 'nodata' -LastSignInDays $null
        )
        $r = script:Scope -Records $recs -RequireSignIn
        @($r).Count   | Should -Be 1
        @($r)[0].Name | Should -Be 'live'
    }

    It 'Invoke-Output still reads both knobs and SI_ActiveStaleDays' {
        $code = Get-Content $script:OutputPs1 -Raw
        $code | Should -Match "SI_IncludeInactive_Identity'"
        $code | Should -Match "SI_RequireRecentSignIn_Identity'"
    }
}

Describe '🔒 the identity reports filter what they mean -- now that disabled accounts and guests are in the profile' {
    # #541: the enabled state is no longer a KQL line. data-model/report-scope declares each report's disabled part
    # (exclude = the question is about usable accounts; setting = SI_DisabledAssets_RiskAnalysis decides; include = the
    # disabled state is part of the finding) and the engine puts the predicate into the report's CI block.

    BeforeAll {
        $yaml = Get-Content -LiteralPath $script:RaYaml -Raw
        $script:Reports = @{}
        foreach ($chunk in ($yaml -split '(?m)^    - ReportName:\s*')) {
            $m = [regex]::Match($chunk, '^(\S+)')
            if ($m.Success -and $m.Groups[1].Value -like 'Identity_*') { $script:Reports[$m.Groups[1].Value] = $chunk }
        }
        $rs = Get-Content -LiteralPath (Join-Path $script:SIRootDir 'data-model\report-scope.locked.json') -Raw | ConvertFrom-Json
        $script:Mode = @{}; foreach ($r in @($rs.reports)) { $script:Mode[[string]$r.id] = [string]$r.scope.disabled }
        $script:Pred = 'coalesce(tobool(column_ifexists("si_account_enabled", bool(null))), true)'
        # the shipped CI asset block: the predicate is applied where the CI rows are read, before the report's own steps
        function script:Get-AssetBlock([string]$q) { [regex]::Match($q, '(?s)//__SI_CI_ASSET_BEGIN__.*?//__SI_CI_ASSET_END__').Value }
    }

    It 'the catalog was read' {
        $script:Reports.Count | Should -BeGreaterThan 50
    }

    # Every report whose question is about a USABLE account. With disabled accounts published, a report without the
    # enabled part would list every disabled account (thousands on a large tenant).
    It '<name> keeps only ENABLED accounts' -ForEach @(
        @{ name = 'Identity_NoMFA' }, @{ name = 'Identity_StaleUser_NoLogin180Days' }, @{ name = 'Identity_StaleGuest_NoLogin90Days' },
        @{ name = 'Identity_PrivilegedSPN_NoLogin180Days' }, @{ name = 'Identity_PermanentPrivilegedRole' }, @{ name = 'Identity_ShadowAdmin' },
        @{ name = 'Identity_PasswordNeverExpires_Privileged' }, @{ name = 'Identity_ExternalUser_PrivilegedRole' },
        @{ name = 'Identity_PrivilegedUser_StalePassword' }, @{ name = 'Identity_SPN_MailboxAccess' }, @{ name = 'Identity_HighValueTarget_MDIRisk' },
        @{ name = 'Identity_SPN_RoleManagementWrite' }, @{ name = 'Identity_SPN_AppRoleAssignmentWrite' }, @{ name = 'Identity_SPN_PrivilegedAccessWrite' },
        @{ name = 'Identity_SPN_UnverifiedPublisher_HighPermission' }, @{ name = 'Identity_NewAccount_ImmediateTier0Role' },
        @{ name = 'Identity_HighMDIInvestigationPriority' }, @{ name = 'Identity_AdminAccount_OnPremSynced' }, @{ name = 'Identity_AdminAccount_NeverUsed' },
        @{ name = 'Identity_TooManyGlobalAdmins' }, @{ name = 'Identity_PIM_EligibleNeverActivated' }
    ) {
        foreach ($kind in 'Summary', 'Detailed') {
            $key = '{0}_{1}' -f $name, $kind
            if (-not $script:Reports.ContainsKey($key)) { continue }
            $script:Mode[$key] | Should -Be 'exclude' -Because "$key asks about usable accounts, whatever the setting"
            (script:Get-AssetBlock $script:Reports[$key]) | Should -Match ([regex]::Escape($script:Pred)) -Because "$key keeps enabled accounts only"
        }
    }

    It 'the departed-but-still-enabled report asks for the enabled state ITSELF (its finding), so the scope leaves it alone' {
        foreach ($kind in 'Summary', 'Detailed') {
            $key = 'Identity_Departed_AccountStillEnabled_{0}' -f $kind
            $script:Mode[$key] | Should -Be 'include'
            $script:Reports[$key] | Should -Match 'si_account_enabled == true'
        }
    }

    # 🔒 OWNER DECISION 2026-10-10 -- "Enabled only, except 2". These seven had no enabled filter when disabled accounts
    # started reaching the profile; each one now keeps enabled accounts only by default, in Summary AND Detailed alike,
    # where the identity rows are read (the CI block, before any join or summarize) -- and SI_DisabledAssets_RiskAnalysis
    # may include them (SIv3-DisabledAssets.Tests.ps1).
    It '<name> keeps only ENABLED accounts in both Summary and Detailed' -ForEach @(
        @{ name = 'Identity_SPN_ExpiringCredentials' }, @{ name = 'Identity_SPN_Orphan_NoOwner' }, @{ name = 'Identity_SPN_OverCredentialed' },
        @{ name = 'Identity_MultiTenant_HighPermission_SPN' }, @{ name = 'Identity_SPN_MailboxImpersonation' }, @{ name = 'Identity_BreakGlass_Anomaly' },
        @{ name = 'Identity_HighRiskFactorComposite4Plus' }
    ) {
        foreach ($kind in 'Summary', 'Detailed') {
            $key = '{0}_{1}' -f $name, $kind
            $script:Reports.ContainsKey($key) | Should -BeTrue -Because "$key is in the catalog"
            $q = $script:Reports[$key]
            $script:Mode[$key] | Should -Be 'setting' -Because "$key follows SI_DisabledAssets_RiskAnalysis"
            $block = script:Get-AssetBlock $q
            $block | Should -Match ([regex]::Escape($script:Pred)) -Because "$key ships with the default (enabled only)"
            $q.IndexOf($block) | Should -BeLessThan ([regex]::Match($q, '(?m)^        _ciAsset\s*$').Index) -Because "$key filters where the identity rows are read"
        }
    }

    It '<name> deliberately KEEPS disabled accounts -- a privileged role or a public resource on a disabled account is still a hygiene finding' -ForEach @(
        @{ name = 'Identity_GuestWithPrivilegedRole' }, @{ name = 'Identity_SPN_OwnsResourcePublicAccess' }
    ) {
        foreach ($kind in 'Summary', 'Detailed') {
            $key = '{0}_{1}' -f $name, $kind
            $script:Reports.ContainsKey($key) | Should -BeTrue -Because "$key is in the catalog"
            $script:Mode[$key] | Should -Be 'include'
            $script:Reports[$key] | Should -Not -Match 'AccountEnabled\s*==|si_account_enabled\s*==' -Because "$key must not filter on the enabled state (owner decision 2026-10-10)"
            $script:Reports[$key] | Should -Not -Match ([regex]::Escape($script:Pred))
        }
    }

    It 'the NoMFA report lists only enabled, internal users' {
        $q = $script:Reports['Identity_NoMFA_Summary']
        $q | Should -Match 'where si_identity_type == "user"'
        $script:Mode['Identity_NoMFA_Summary'] | Should -Be 'exclude'
        (script:Get-AssetBlock $q) | Should -Match ([regex]::Escape($script:Pred))
        # internal users only; a user whose external flag could not be read is KEPT (owner: never fewer rows than the source) -- #690 (27)
        $q | Should -Match 'where (coalesce\(si_is_external, false\)|si_is_external) == false'
    }

    It '<name> exists BECAUSE the account is disabled -- it could never fire while the profile dropped them' -ForEach @(
        @{ name = 'Identity_DisabledAccount_ActivePIMAssignment_Summary' }, @{ name = 'Identity_DisabledUser_StillInCriticalGroup_Summary' }
    ) {
        $script:Reports[$name] | Should -Match 'si_account_enabled\s*==\s*false'
        $script:Mode[$name] | Should -Be 'include'
    }

    It 'every report whose stated purpose is about ENABLED accounts keeps them (its scope, or its own question)' {
        $miss = foreach ($k in $script:Reports.Keys) {
            $purpose = [regex]::Match($script:Reports[$k], '(?s)ReportPurpose:\s*>?\s*(.*?)\n      [A-Z]').Groups[1].Value
            if ($purpose -match '(?i)\benabled (user|account)s?\b' -and $script:Mode[$k] -ne 'exclude' -and $script:Mode[$k] -ne 'setting' -and $script:Reports[$k] -notmatch 'si_account_enabled\s*==\s*true') { $k }
        }
        @($miss) | Should -BeNullOrEmpty
    }
}
