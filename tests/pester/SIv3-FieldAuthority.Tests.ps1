#Requires -Version 5.1
<#
    #546 FIELD AUTHORITY BY IDENTITY ORIGIN -- AND UNKNOWN IS NEVER A FINDING.

    Customer feedback (2026-10-10): a "stale password" finding for accounts synchronised from Active Directory. Those
    accounts change their password in AD (pwdLastSet); Entra's lastPasswordChangeDateTime follows it only with password
    hash sync, so the Entra date stays old. And the report counted an UNKNOWN password age (-1) as stale.

    What these keep true:
      1. ORIGIN      synced = an AD user record is linked, or onPremisesSyncEnabled; cloud = Entra only; '' = cannot tell
      2. AUTHORITY   the field catalog's resolution.byOrigin decides who supplies a field per origin: a synced account's
                     password age = AD (then Defender for Identity / Exposure Graph), NEVER Entra; a cloud-only account's =
                     Entra. Password-never-expires likewise. The sign-in of a synced account is KNOWN only with its AD /
                     Defender for Identity record.
      3. UNKNOWN     a field that cannot be decided is in si_unknown_fields; a factor that reads it (or a date / number that
                     was never read) is in si_rf_unknown, its si_rf_<id> column is null, and it is never a finding -- it
                     is COUNTED (the CI build's run-log line, Risk Analysis' per-report line)
      4. THE REPORTS the stale-password reports read the old_password factor; every report reads an undecided sign-in or
                     password age as null; no report turns a missing value into a finding (guard over the locked YAML)
      5. EXCLUSIONS  a provider recommendation that is a known false positive in a stated situation is left out by a
                     default rule of the data model (customer-overridable), counted with its reason
    Offline; PS 7 (v3 gate). Nothing is sent anywhere.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecommendationExclusions.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-UnknownCount.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RecommendationExclusions.ps1')
    $script:Model = Get-SIDataModel
    $script:Cat = $script:Model['field-catalog']
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-10T03:00:00', [DateTimeKind]::Utc)
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:Migration = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\ra-ci-migration.locked.json')) | ConvertFrom-Json

    function script:Rec([string]$Provider, [string]$Type, [hashtable]$Fields, [int]$SeenHoursAgo = 2) {
        $o = [ordered]@{ si_class = 'identity'; si_provider = $Provider; si_record_type = $Type; si_record_key = ('{0}:{1}' -f $Provider, [guid]::NewGuid().ToString('N'))
            si_source_last_seen = $script:Now.AddHours(-$SeenHoursAgo); si_collection_time = $script:Now.AddHours(-1) }
        foreach ($k in $Fields.Keys) { $o[$k] = $Fields[$k] }
        [pscustomobject]$o
    }
    function script:Build([object[]]$Records) {
        $ci = New-SICiDocument -CiId 'ci-546' -Records $Records -Catalog $script:Cat -FeedLatest @{} -Now $script:Now
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context @{ Lists = (Get-SIDataModelListContext $script:Model); Now = $script:Now }
        $ci
    }
    function script:Has($Ci, [string]$Id) { @(@($Ci['si_risk_factors']) | Where-Object { $_.id -eq $Id }).Count -gt 0 }
    function script:Unknown($Ci, [string]$Id) { @($Ci['si_rf_unknown']) -contains $Id }
    function script:ReportText([string]$Name) {
        $m = [regex]::Match($script:Yaml, '(?ms)^    - ReportName: ' + [regex]::Escape($Name) + '\s*$.*?(?=^    - ReportName: |\z)')
        $m.Value
    }
    $script:Fresh = $script:Now.AddDays(-10)
    $script:Old = $script:Now.AddDays(-900)
}

Describe 'identity origin (#546)' {
    It 'an AD user record linked = synced; onPremisesSyncEnabled = synced; Entra only = cloud; neither = unknown' {
        Get-SICiIdentityOrigin -Candidates @([pscustomobject]@{ Provider = 'ad'; Record = (Rec 'ad' 'user' @{}); State = 'active' }) | Should -Be 'synced'
        Get-SICiIdentityOrigin -Candidates @([pscustomobject]@{ Provider = 'entra'; Record = (Rec 'entra' 'user' @{ si_onprem_synced = $true }); State = 'active' }) | Should -Be 'synced'
        Get-SICiIdentityOrigin -Candidates @([pscustomobject]@{ Provider = 'entra'; Record = (Rec 'entra' 'user' @{}); State = 'active' }) | Should -Be 'cloud'
        Get-SICiIdentityOrigin -Candidates @([pscustomobject]@{ Provider = 'eg'; Record = (Rec 'eg' 'user' @{}); State = 'active' }) | Should -Be ''
    }
    It 'the catalog carries the origin authority for the password age, the password expiry and the sign-in' {
        foreach ($n in 'si_password_last_changed', 'si_password_never_expires', 'si_last_sign_in') {
            $f = @($script:Cat.fields | Where-Object { $_.name -eq $n })[0]
            $f.resolution.byOrigin.synced | Should -Not -BeNullOrEmpty -Because $n
            $f.resolution.byOrigin.cloud | Should -Not -BeNullOrEmpty -Because $n
        }
        $pw = @($script:Cat.fields | Where-Object { $_.name -eq 'si_password_last_changed' })[0]
        @($pw.resolution.byOrigin.synced.authority) | Should -Not -Contain 'entra' -Because 'Entra never decides a synchronised account''s password age'
        @($pw.resolution.byOrigin.synced.authority)[0] | Should -Be 'ad'
        @($pw.resolution.byOrigin.cloud.authority) | Should -Be @('entra')
        $si = @($script:Cat.fields | Where-Object { $_.name -eq 'si_last_sign_in' })[0]
        @($si.resolution.byOrigin.synced.decidedBy) | Should -Be @('ad') -Because 'the Defender for Identity record SecurityInsight captures (IdentityInfo) carries no sign-in -- its presence decides nothing'
    }
    It 'the shipped data model is valid, and a byOrigin that names an unknown origin / provider is refused' {
        @(Test-SIDataModel -Model $script:Model | Where-Object { $_ -match 'byOrigin' }) | Should -BeNullOrEmpty
        $m = Get-SIDataModel
        $f = @($m['field-catalog'].fields | Where-Object { $_.name -eq 'si_password_last_changed' })[0]
        $f.resolution.byOrigin | Add-Member -NotePropertyName hybrid -NotePropertyValue ([pscustomobject]@{ authority = @('nobody') }) -Force
        $p = @(Test-SIDataModel -Model $m)
        @($p | Where-Object { $_ -match "unknown origin 'hybrid'" }).Count | Should -Be 1
    }
}

Describe 'password age by origin -- the customer case (#546)' {
    It 'a SYNCED account with a fresh AD pwdLastSet and an old Entra date: no finding' {
        $ci = Build @(
            (Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_last_changed = $script:Old })
            (Rec 'ad' 'user' @{ si_password_last_changed = $script:Fresh }))
        $ci['si_identity_origin'] | Should -Be 'synced'
        (ConvertTo-SIUtcOrNull $ci['si_password_last_changed']) | Should -Be $script:Fresh
        $ci['si_field_sources']['si_password_last_changed'].provider | Should -Be 'ad'
        Has $ci 'old_password' | Should -BeFalse
        Unknown $ci 'old_password' | Should -BeFalse
        $ci['si_rf_old_password'] | Should -BeFalse
    }
    It 'a SYNCED account with an old AD pwdLastSet and a fresh Entra date: the AD date decides -- a finding' {
        $ci = Build @(
            (Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_last_changed = $script:Fresh })
            (Rec 'ad' 'user' @{ si_password_last_changed = $script:Old }))
        Has $ci 'old_password' | Should -BeTrue
    }
    It 'a CLOUD-ONLY account with an old Entra date: a finding' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_password_last_changed = $script:Old }))
        $ci['si_identity_origin'] | Should -Be 'cloud'
        Has $ci 'old_password' | Should -BeTrue
        $ci['si_rf_old_password'] | Should -BeTrue
    }
    It 'a SYNCED account WITHOUT its AD record (only an old Entra date): unknown -- no finding, counted' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_last_changed = $script:Old }))
        @($ci['si_unknown_fields']) | Should -Contain 'si_password_last_changed'
        $ci.Contains('si_password_last_changed') | Should -BeFalse -Because 'Entra may not supply a synchronised account''s password age'
        Has $ci 'old_password' | Should -BeFalse
        Unknown $ci 'old_password' | Should -BeTrue
        $ci['si_rf_old_password'] | Should -BeNullOrEmpty -Because 'an undecided factor is null in its column -- never false, never true'
        $counts = Add-SICiUnknownFactorCounts -Counts @{} -Cis @($ci)
        $counts['old_password'] | Should -Be 1
        Format-SICiUnknownFactorLine -Counts $counts | Should -Match 'NOT findings.*old_password 1'
    }
    It 'a CLOUD-ONLY account whose password age was never read: unknown -- no finding, counted' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user' }))
        Has $ci 'old_password' | Should -BeFalse
        Unknown $ci 'old_password' | Should -BeTrue
    }
    It 'a service principal has no password age: old_password is neither raised nor counted' {
        $ci = Build @((Rec 'entra' 'service_principal' @{ si_identity_type = 'service_principal' }))
        Has $ci 'old_password' | Should -BeFalse
        Unknown $ci 'old_password' | Should -BeFalse
    }
}

Describe 'password never expires by origin (#546)' {
    It 'a SYNCED account: Entra''s DisablePasswordExpiration does not decide -- AD''s DONT_EXPIRE_PASSWORD does' {
        $ci = Build @(
            (Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_never_expires = $true })
            (Rec 'ad' 'user' @{ si_password_never_expires = $false }))
        $ci['si_password_never_expires'] | Should -BeFalse
        $ci['si_field_sources']['si_password_never_expires'].provider | Should -Be 'ad'
    }
    It 'a SYNCED account without its AD record: the flag is unknown (null), never Entra''s' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_never_expires = $true }))
        $ci.Contains('si_password_never_expires') | Should -BeFalse
        @($ci['si_unknown_fields']) | Should -Contain 'si_password_never_expires'
    }
    It 'a CLOUD-ONLY account: Entra decides' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_password_never_expires = $true }))
        $ci['si_password_never_expires'] | Should -BeTrue
    }
    It 'the AD mapping reads DONT_EXPIRE_PASSWORD from userAccountControl (uac_flag:65536)' {
        $m = @($script:Model.Mappings['ad'].mappings | Where-Object { $_.field -eq 'si_password_never_expires' })[0]
        @($m.normalize) | Should -Be @('uac_flag:65536')
        $v = New-Object System.Collections.Generic.List[object]; $v.Add(66048)
        # Invoke-SINormalize returns its List as ONE object (return , $list): read the list itself -- @(<call>) would nest it
        $r = Invoke-SINormalize -Values $v -Chain @('uac_flag:65536'); @($r) | Should -Be @($true)
        $v = New-Object System.Collections.Generic.List[object]; $v.Add(512)
        $r = Invoke-SINormalize -Values $v -Chain @('uac_flag:65536'); @($r) | Should -Be @($false)
        $v = New-Object System.Collections.Generic.List[object]
        $r = Invoke-SINormalize -Values $v -Chain @('uac_flag:65536'); $r.Count | Should -Be 0 -Because 'no value = nothing, never false'
    }
}

Describe 'sign-in by origin: never signed in / stale for accounts that sign in on-premises (#546)' {
    It 'a SYNCED account with no Entra sign-in but a fresh AD lastLogonTimestamp: not stale, not never signed in' {
        $ci = Build @(
            (Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true })
            (Rec 'ad' 'user' @{ si_last_sign_in = $script:Fresh }))
        Has $ci 'never_signed_in' | Should -BeFalse
        Has $ci 'stale_sign_in' | Should -BeFalse
        @($ci['si_unknown_fields']) | Should -Not -Contain 'si_last_sign_in'
    }
    It 'a SYNCED account WITHOUT its AD / Defender for Identity record and no Entra sign-in: unknown, never "never signed in"' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true }))
        Has $ci 'never_signed_in' | Should -BeFalse
        Unknown $ci 'never_signed_in' | Should -BeTrue
        $ci['si_rf_never_signed_in'] | Should -BeNullOrEmpty
    }
    It 'a SYNCED account WITHOUT its AD record and an old Entra sign-in: unknown, never stale' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_account_enabled = $true; si_last_sign_in = $script:Old }))
        Has $ci 'stale_sign_in' | Should -BeFalse
        Unknown $ci 'stale_sign_in' | Should -BeTrue
    }
    It 'a CLOUD-ONLY account with no sign-in in Entra: never signed in (a decided fact)' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user' }))
        Has $ci 'never_signed_in' | Should -BeTrue
        Has $ci 'stale_sign_in' | Should -BeFalse -Because 'no sign-in recorded is never_signed_in, not stale (the is_empty branch is gone)'
    }
    It 'a CLOUD-ONLY account with an old sign-in: stale' {
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_account_enabled = $true; si_last_sign_in = $script:Old }))
        Has $ci 'stale_sign_in' | Should -BeTrue
    }
    It 'stale_sign_in no longer reads an empty sign-in as stale' {
        $f = @($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'stale_sign_in' })[0]
        ($f.when | ConvertTo-Json -Depth 10 -Compress) | Should -Not -Match 'is_empty'
    }
}

Describe 'the three-state condition (#546)' {
    It 'an unknown field, an unread age or number = unknown; a population leaf on an empty value = false' {
        $c = @{ all = @(@{ field = 'si_identity_type'; op = 'in'; value = @('user') }, @{ field = 'si_password_last_changed'; op = 'older_than_days'; value = 365 }) }
        Test-SIConditionTri -Condition $c -Item @{ si_identity_type = 'user' } | Should -BeNullOrEmpty
        Test-SIConditionTri -Condition $c -Item @{ si_identity_type = 'device' } | Should -BeFalse
        Test-SIConditionTri -Condition $c -Item @{ si_identity_type = 'user'; si_password_last_changed = $script:Old } -Context @{ Now = $script:Now } | Should -BeTrue
        Test-SIConditionTri -Condition $c -Item @{ si_identity_type = 'user'; si_password_last_changed = $script:Old } -Context @{ Now = $script:Now } -UnknownFields @('si_password_last_changed') | Should -BeNullOrEmpty
        $any = @{ any = @(@{ field = 'a'; op = 'is_true' }, @{ field = 'b'; op = 'gt'; value = 1 }) }
        Test-SIConditionTri -Condition $any -Item @{ a = $true } | Should -BeTrue
        Test-SIConditionTri -Condition $any -Item @{ a = $false } | Should -BeNullOrEmpty
        Test-SIConditionTri -Condition $any -Item @{ a = $false; b = 0 } | Should -BeFalse
    }
}

Describe 'the reports: unknown is never a finding (guard over the locked catalog, #546)' {
    It 'no report counts a missing value as a finding (the -1 / default patterns)' {
        $bad = @(
            'column_ifexists\("[A-Za-z_]+",\s*-1\)\)\s*==\s*-1'                 # a default chosen so the test fails
            'PasswordLastChangedDays\s*==\s*-1'                                   # unknown password age = stale
            'column_ifexists\("PasswordLastChangedDays"'                          # a profile column no engine writes
            # empty OR failing = a finding. ONE named exception: Identity_SPN_OwnsResourcePublicAccess keeps an Azure role
            # assignment whose role NAME is unknown (isempty(RoleName) or ...) -- the finding is the assignment itself, a fact
            # the source shows (owner 2026-10-15: never fewer rows than the source), and the row says "an Azure role (name
            # unknown)"; the unknown value is a label there, not the reason for the finding
            'isempty\((?!RoleName\))[A-Za-z_]+\)\s+or\b'
            'iff\(isnull\(si_password_last_changed\),\s*-1'                       # the -1 sentinel for the password age
        )
        foreach ($rx in $bad) { [regex]::Matches($script:Yaml, $rx).Count | Should -Be 0 -Because "pattern $rx turns an unknown value into a finding" }
    }
    It 'every sign-in age is null when the CI could not decide it -- -1 means KNOWN never signed in' {
        $all = [regex]::Matches($script:Yaml, 'LastSignInDays\s*=\s*iff\([^\r\n]+')
        $all.Count | Should -BeGreaterThan 20
        foreach ($m in $all) { $m.Value | Should -Match 'set_has_element\(si_unknown_fields, "si_last_sign_in"\), long\(null\)' }
        [regex]::Matches($script:Yaml, 'LastSignInDays\s*=\s*iff\(isnull\(si_last_sign_in\), -1').Count | Should -Be 0
    }
    It 'every password age is null when unknown or never read' {
        foreach ($m in [regex]::Matches($script:Yaml, 'PasswordLastChangedDays\s*=\s*iff\([^\r\n]+')) {
            $m.Value | Should -Match 'isnull\(si_password_last_changed\) or set_has_element\(si_unknown_fields, "si_password_last_changed"\), long\(null\)'
        }
    }
    It 'the stale-password reports ARE the old_password factor (field authority by origin), with no "never changed" factor' -ForEach @(
        @{ R = 'Identity_PrivilegedUser_StalePassword_Summary' }, @{ R = 'Identity_PrivilegedUser_StalePassword_Detailed' }) {
        $t = ReportText $R
        $t | Should -Not -BeNullOrEmpty
        $t | Should -Match '\| where set_has_element\(si_rf_p, "old_password"\)'
        $t | Should -Not -Match 'RF_P_NeverChanged|PasswordNeverChanged'
        $t | Should -Match 'RiskFactor_Probability = _pwOver730 \+ array_length\(RF_P_CiFactors\)'
    }
    It 'the password-never-expires reports read the CI flag (resolved by origin)' -ForEach @(
        @{ R = 'Identity_PasswordNeverExpires_Privileged_Summary' }, @{ R = 'Identity_PasswordNeverExpires_Privileged_Detailed' }) {
        (ReportText $R) | Should -Match 'where coalesce\(si_password_never_expires, false\) == true'
    }
    It '"recently disabled" never counts a never-signed-in account (-1) as recent' -ForEach @(
        @{ R = 'Identity_DisabledAccount_ActivePIMAssignment_Summary' }, @{ R = 'Identity_DisabledAccount_ActivePIMAssignment_Detailed' }) {
        $t = ReportText $R
        $t | Should -Match 'RF_P_RecentlyDisabled = iff\(LastSignInDays between \(0 \.\. 30\), 1, 0\)'
        $t | Should -Not -Match 'iff\(LastSignInDays <= 30, 1, 0\)'
    }
    It 'the SPN-owns-public-resource inactivity is null when the sign-in is undecided' {
        foreach ($m in [regex]::Matches($script:Yaml, '\| extend DaysInactive = [^\r\n]+')) { $m.Value | Should -Match 'set_has_element\(si_unknown_fields, "si_last_sign_in"\), long\(null\)' }
    }
    It 'the asset block carries the origin and the undecided fields' {
        [regex]::Matches($script:Yaml, 'si_unknown_fields = todynamic\(column_ifexists\("si_unknown_fields", dynamic\(null\)\)\)').Count | Should -BeGreaterThan 20
        [regex]::Matches($script:Yaml, 'si_identity_origin = tostring\(column_ifexists\("si_identity_origin", ""\)\)').Count | Should -BeGreaterThan 20
    }
    It 'the column map has no -1 sentinel a threshold could match' {
        $script:Migration.columnMap.PasswordLastChangedDays.si | Should -Not -Match '-1'
        $script:Migration.columnMap.PasswordLastChangedDays.si | Should -Match 'long\(null\)'
        $script:Migration.columnMap.LastSignInDays.si | Should -Match 'set_has_element\(si_unknown_fields, "si_last_sign_in"\), long\(null\)'
    }
    It 'the guard can fail: each pattern matches its own bad example (control)' {
        'toint(column_ifexists("PasswordLastChangedDays", -1)) == -1' | Should -Match 'column_ifexists\("[A-Za-z_]+",\s*-1\)\)\s*==\s*-1'
        '| where isempty(MfaState) or MfaState == "none"' | Should -Match 'isempty\([A-Za-z_]+\)\s+or\b'
    }
}

Describe 'Risk Analysis says how much it could not judge, per report (#546)' {
    BeforeAll {
        $script:Cis = @(
            [pscustomobject]@{ si_ci_id = 'a'; si_tier = 0; si_rf_unknown = @('old_password'); si_unknown_fields = @('si_password_last_changed') }
            [pscustomobject]@{ si_ci_id = 'b'; si_tier = 1; si_rf_unknown = '["old_password","never_signed_in"]'; si_unknown_fields = '["si_last_sign_in"]' }
            [pscustomobject]@{ si_ci_id = 'c'; si_tier = 3; si_rf_unknown = @('old_password'); si_unknown_fields = $null }
            [pscustomobject]@{ si_ci_id = 'd'; si_tier = 0; si_rf_unknown = $null; si_unknown_fields = $null })
        $script:Idx = @{ ById = @{ a = $script:Cis[0]; b = $script:Cis[1]; c = $script:Cis[2]; d = $script:Cis[3]; 'alias-of-a' = $script:Cis[0] }; ByName = @{}; Count = 4 }
    }
    It 'reads what the query judges, ignoring comments' {
        $s = Get-RAUnknownSubjects -Query "| where set_has_element(si_rf_p, `"old_password`")`n// set_has_element(si_rf_p, `"no_mfa`")`n| extend X = iff(set_has_element(si_unknown_fields, `"si_last_sign_in`"), long(null), 1)"
        @($s.Factors) | Should -Be @('old_password')
        @($s.Fields) | Should -Be @('si_last_sign_in')
    }
    It 'counts distinct CIs within the report''s tier scope' {
        $c = Get-RAUnknownCounts -Index $script:Idx -Factors @('old_password') -Tiers @(0, 1)
        $c.Total | Should -Be 2
        $c.By['old_password'] | Should -Be 2
        (Get-RAUnknownCounts -Index $script:Idx -Factors @('old_password')).Total | Should -Be 3
        (Get-RAUnknownCounts -Index $script:Idx -Fields @('si_last_sign_in')).By['si_last_sign_in'] | Should -Be 1
    }
    It 'the tier scope comes from the scope block; the line names the report and says NOT findings' {
        @(Get-RAQueryScopeTiers -Query 'let SI_ScopeTiers = dynamic([0, 1]);') | Should -Be @(0, 1)
        $line = Get-RAUnknownLine -Query "let SI_ScopeTiers = dynamic([0, 1]);`n| where set_has_element(si_rf_p, `"old_password`")" -ReportName 'Identity_PrivilegedUser_StalePassword_Summary' -Index $script:Idx
        $line | Should -Match '^Identity_PrivilegedUser_StalePassword_Summary: 2 asset\(s\) in scope could not be judged \(value unknown, NOT counted as findings\) -- old_password 2$'
        Get-RAUnknownLine -Query '| take 1' -ReportName 'X' -Index $script:Idx | Should -BeExactly ''
    }
    It 'is wired into the engine after the scope, and the stale-password report judges old_password' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match "_shared/RA-UnknownCount.ps1"
        $t.IndexOf('Get-RAUnknownLine -Query $Query') | Should -BeGreaterThan $t.IndexOf('$raScope = Resolve-RAScopePreamble')
        @((Get-RAUnknownSubjects -Query (ReportText 'Identity_PrivilegedUser_StalePassword_Summary')).Factors) | Should -Contain 'old_password'
    }
}

Describe 'default exclusion rules for known false positives of a provider recommendation (#546 (5))' {
    BeforeAll {
        $script:Rule = [pscustomobject]@{ id = 'test-synced-password-expiry'; configurationIds = @('scid-9999'); reason = 'the password of a synchronised account is governed by Active Directory'
            when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_identity_origin'; op = 'eq'; value = 'synced' }) } }
    }
    It 'the template ships, is valid, and ships no rule that was not verified' {
        $t = (Get-SIDataModelTemplate -Name 'recommendation-exclusions').Document
        $t.kind | Should -Be 'recommendation-exclusion'
        @(Test-SIRecommendationExclusions -Document $t) | Should -BeNullOrEmpty
        @($t.rules).Count | Should -Be 0
    }
    It 'a rule needs ids, a reason, a condition over SI fields only and a known operation' {
        @(Test-SIRecommendationExclusionRule -Rule $script:Rule) | Should -BeNullOrEmpty
        @(Test-SIRecommendationExclusionRule -Rule ([pscustomobject]@{ id = 'x'; configurationIds = @(); reason = ''; when = $null })).Count | Should -Be 3
        @(Test-SIRecommendationExclusionRule -Rule ([pscustomobject]@{ id = 'x'; configurationIds = @('a'); reason = 'r'; when = [pscustomobject]@{ field = 'node.rawData.x'; op = 'eq'; value = 1 } })) -join ';' | Should -Match 'SI fields'
        @(Test-SIRecommendationExclusionRule -Rule ([pscustomobject]@{ id = 'x'; configurationIds = @('a'); reason = 'r'; when = [pscustomobject]@{ field = 'si_x'; op = 'exec'; value = 1 } })) -join ';' | Should -Match 'unknown condition operation'
    }
    It 'a customer custom file adds a rule (Community); a finding on a synced CI is left out, counted with the reason; others stay' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-546-' + [guid]::NewGuid().ToString('N'))
        Copy-Item -Recurse (Join-Path $script:SIRoot 'data-model') $tmp
        try {
            @{ kind = 'recommendation-exclusion'; rules = @($script:Rule) } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $tmp 'recommendation-exclusions.custom.json') -Encoding utf8
            $idx = Get-SIRecommendationExclusions -Root $tmp -OverlayRoot $tmp
            $idx.ContainsKey('scid-9999') | Should -BeTrue
            $ciIdx = @{ ById = @{ 'ci-s' = [pscustomobject]@{ si_ci_id = 'ci-s'; si_identity_origin = 'synced' }; 'ci-c' = [pscustomobject]@{ si_ci_id = 'ci-c'; si_identity_origin = 'cloud' } } }
            $rows = @(
                [pscustomobject]@{ ConfigurationId = 'scid-9999'; si_ci_id = 'ci-s' }
                [pscustomobject]@{ ConfigurationId = 'scid-9999'; si_ci_id = 'ci-c' }
                [pscustomobject]@{ ConfigurationId = 'scid-9999'; si_ci_id = '' }
                [pscustomobject]@{ ConfigurationId = 'scid-1'; si_ci_id = 'ci-s' })
            $r = Select-RARecommendationExclusions -Rows $rows -ReportName 'Device_Recommendations_Detailed' -Index $idx -CiIndex $ciIdx
            @($r.Rows).Count | Should -Be 3 -Because 'only the synced CI''s row is left out; a row without a known CI is never suppressed'
            $r.Suppressed['test-synced-password-expiry'].Count | Should -Be 1
            @(Format-RARecommendationExclusionLines -ReportName 'Device_Recommendations_Detailed' -Suppressed $r.Suppressed)[0] | Should -Match 'left out by the default exclusion rule test-synced-password-expiry -- the password of a synchronised account'
            # the customer switches it off
            @{ kind = 'recommendation-exclusion'; rules = @(@{ id = 'test-synced-password-expiry'; remove = $true }) } | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $tmp 'recommendation-exclusions.custom.json') -Encoding utf8
            (Get-SIRecommendationExclusions -Root $tmp -OverlayRoot $tmp).Count | Should -Be 0
        } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
    }
    It 'is a Pro data-model template (cfg.ItemOverride per rule) and wired after the CI context' {
        $rows = Join-Path $script:SIRoot 'engine\pro-settings\SI-DataModelTemplateRows.ps1'
        if (-not (Test-Path -LiteralPath $rows)) { Set-ItResult -Skipped -Because 'the data-model templates are SecurityInsight Pro (not in this copy)'; return }
        . $rows
        Get-SIDataModelProTemplateKind -Name 'recommendation-exclusions' | Should -Be 'recommendation-exclusion'
        Get-SIDataModelItemArrayName -Kind 'recommendation-exclusion' | Should -Be 'rules'
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t.IndexOf('Select-RARecommendationExclusions -Rows') | Should -BeGreaterThan $t.IndexOf('Add-RACiContext -Rows @($ResultFiltered)')
    }
}

Describe 'SI_CI_CL carries what the reports judge (#546)' {
    It 'the origin and the undecided fields are posted and in the asset block' {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')   # ConvertTo-SILogValue (SI-CiBuildRun.ps1 loads it in the engine)
        . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        $ci = Build @((Rec 'entra' 'user' @{ si_identity_type = 'user'; si_onprem_synced = $true; si_password_last_changed = $script:Old }))
        $ci['si_collection_time'] = $script:Now; $ci['si_last_seen'] = $script:Now
        $row = ConvertTo-SICiPostRow -Ci $ci
        $row.si_identity_origin | Should -Be 'synced'
        "$($row.si_unknown_fields)" | Should -Match 'si_password_last_changed'
        "$($row.si_rf_unknown)" | Should -Match 'old_password'
        $script:RACiAssetFields.Contains('si_identity_origin') | Should -BeTrue
        $script:RACiAssetFields.Contains('si_unknown_fields') | Should -BeTrue
    }
}
