#Requires -Version 5.1
<#
    #690 items 23, 25, 27, 28, 29 -- EACH REPORT ANSWERS ITS OWN ReportPurpose (found by the report certification #688,
    ops\report-certification\reviews\review-C1.md, review-E.md, verify.md; counts read-only on internal 2026-10-15).

      (23) Identity_PasswordNeverExpires_Privileged had no privilege filter; Identity_ExternalUser_PrivilegedRole listed all
           14 guests (none holds a role); Identity_BreakGlass_SignIn_Detected (Detailed) had no sign-in filter -- every
           break-glass account Very High every run -- and its Summary lost every sign-in with an empty location list
           (mv-expand of an empty array drops the row); Identity_TooManyGlobalAdmins counted only permanent user Global
           Administrators and its Detailed report had no "more than 5" threshold.
      (25) Identity_PrivilegedUser_NoConditionalAccess read interactive sign-ins only (SigninLogs).
      (27) NoMFA, StaleUser, StaleGuest, BreakGlass_Anomaly DROPPED an unknown value -- now listed and labelled Unknown.
      (28) Device_Missing_CVEs took the Exposure Graph's severity where Defender vulnerability management (what the MDE portal
           shows) holds the same pair with another severity (42 of 11,556 graph pairs on internal).
      (29) Identity_ShadowAdmin was a false zero (the profile flag is never set for an AD-only account; the graph's
           nestedCriticalAdGroups is a dictionary); Device_Certificates was a false zero (`has` matches whole terms --
           "sha1rsa" has "sha1" is false), DSA keys were never checked; now every weak certificate is listed, self-signed
           roots labelled (internal: 280 weak-signature + 14 weak-key certificates on 5 devices, all roots).

    No output column is added, renamed or removed (#692, SIv3-ReportOutputContract). Offline: reads the shipped catalog with
    SecurityInsight's own reader; the certificate algorithm tests are EVALUATED against the algorithm tokens Defender writes.
#>

BeforeDiscovery {
    function Twins([string]$Base) { @("$($Base)_Summary", "$($Base)_Detailed") }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($script:Path)) -SourceName $script:Path
    # the report's own KQL, comment lines left out (a comment may name the old behaviour to explain the fix) -- the generated
    # block markers (//__BUCKET_FILTER_BEGIN__ ...) are kept: the order checks are relative to them
    function script:CodeOf([string]$Name) {
        $r = @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })[0]
        $r | Should -Not -BeNullOrEmpty -Because "$Name is in the catalog"
        ((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^//' -or $_.Trim() -match '^//__\w+__$' }) -join "`n"
    }

}

Describe '(23) Identity_PasswordNeverExpires_Privileged -- privileged accounts only' {
    It '<_> keeps only a Tier 0/1 Entra role (permanent or eligible) or a critical AD group' -ForEach (Twins 'Identity_PasswordNeverExpires_Privileged') {
        $c = CodeOf $_
        $i = $c.IndexOf('| where coalesce(si_password_never_expires, false) == true')
        $i | Should -BeGreaterOrEqual 0
        $after = $c.Substring($i)
        if ($_ -like '*_Detailed') {
            $after | Should -Match '\| where IsPrivileged\b'
            $c | Should -Match ([regex]::Escape('| extend IsPrivileged = (coalesce(si_privilege_tier_permanent, 99) <= 1 or coalesce(si_privilege_tier_eligible, 99) <= 1 or coalesce(array_length(iff(gettype(si_ad_critical_groups) == "dictionary", si_ad_critical_groups.data, si_ad_critical_groups)), 0) > 0)'))
        } else {
            $after | Should -Match ([regex]::Escape('| where coalesce(si_privilege_tier_permanent, 99) <= 1 or coalesce(si_privilege_tier_eligible, 99) <= 1 or coalesce(array_length('))
        }
        $f = if ($_ -like '*_Detailed') { $after.IndexOf('| where IsPrivileged') } else { $after.IndexOf('| where coalesce(si_privilege_tier_permanent, 99) <= 1 or') }
        $f | Should -BeGreaterOrEqual 0
        $f | Should -BeLessThan $after.IndexOf('//__BUCKET_FILTER_BEGIN__') -Because 'the purpose filter runs before the slice'
    }
}

Describe '(23) Identity_ExternalUser_PrivilegedRole -- external users WITH a Tier 0/1 role' {
    It '<_> filters on the privilege tier after the external test' -ForEach (Twins 'Identity_ExternalUser_PrivilegedRole') {
        $c = CodeOf $_
        $i = $c.IndexOf('| where si_is_external == true or si_external_user_state in ("Accepted", "PendingAcceptance")')
        $i | Should -BeGreaterOrEqual 0
        $next = ($c.Substring($i) -split "`n")[1].Trim()
        if ($_ -like '*_Detailed') { $next | Should -Be '| where IsPrivileged' }
        else { $next | Should -Be '| where coalesce(si_privilege_tier_permanent, 99) <= 1 or coalesce(si_privilege_tier_eligible, 99) <= 1' }
    }
}

Describe '(23) Identity_BreakGlass_SignIn_Detected -- a break-glass account that SIGNED IN' {
    It '<_> reads interactive and non-interactive sign-ins, never drops one for an empty location list' -ForEach (Twins 'Identity_BreakGlass_SignIn_Detected') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('union isfuzzy=true (datatable(UserId:string, ResultType:string, TimeGenerated:datetime, IPAddress:string, Location:string, NetworkLocationDetails:string)[]), SigninLogs, AADNonInteractiveUserSignInLogs'))
        $c | Should -Match ([regex]::Escape('| extend IsTrusted = iff(tostring(NetworkLocationDetails) has "trustedNamedLocation", 1, 0)'))
        $c | Should -Not -Match 'mv-expand NetLoc' -Because 'mv-expand of an empty array drops the row (#690 (18))'
    }
    It '<_> keeps only the accounts with a sign-in in 30 days (sign-in logs, else the account''s own last sign-in)' -ForEach (Twins 'Identity_BreakGlass_SignIn_Detected') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| where si_is_break_glass == true'))
        $c | Should -Match ([regex]::Escape('| join kind=leftouter _bgSignIns on UserKey'))
        $c | Should -Match ([regex]::Escape('| where isnotnull(LastSignin) or (isnotnull(_lastSignInKnown) and _lastSignInKnown >= ago(30d))'))
        $c | Should -Match ([regex]::Escape('_lastSignInKnown = iff(coalesce(set_has_element(si_unknown_fields, "si_last_sign_in"), false), datetime(null), si_last_sign_in)')) -Because 'an undecided sign-in is never a sign-in'
    }
    It 'the Detailed row carries the sign-in evidence in its existing Impact column' {
        (CodeOf 'Identity_BreakGlass_SignIn_Detected_Detailed') | Should -Match ([regex]::Escape('AssetName, AssetId, AssetType, Impact = SignInEvidence,'))
    }
}

Describe '(23) Identity_TooManyGlobalAdmins -- more than 5, active + eligible + group-based' {
    It '<_> counts every identity holding Global Administrator, permanent or eligible' -ForEach (Twins 'Identity_TooManyGlobalAdmins') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| where tostring(si_entra_roles_permanent) has "Global Administrator" or tostring(si_entra_roles_eligible) has "Global Administrator"'))
        $c | Should -Not -Match 'si_identity_type in \("user", "guest"\)' -Because 'a service principal holding Global Administrator is counted too'
    }
    It 'the Summary keeps its one-row threshold' {
        (CodeOf 'Identity_TooManyGlobalAdmins_Summary') | Should -Match '\| where GACount > 5'
    }
    It 'the Detailed lists rows only over the threshold, counted over the whole tenant BEFORE the slice' {
        $c = CodeOf 'Identity_TooManyGlobalAdmins_Detailed'
        $c | Should -Match ([regex]::Escape('let _gaCount = toscalar(_gaAll | summarize _gaCount = dcount(si_ci_id));'))
        $w = $c.IndexOf('| where _gaCount > 5')
        $w | Should -BeGreaterThan 0
        $w | Should -BeLessThan $c.IndexOf('//__BUCKET_FILTER_BEGIN__')
        $c | Should -Match ([regex]::Escape('Impact = GaEvidence,'))
    }
}

Describe '(25) Identity_PrivilegedUser_NoConditionalAccess -- interactive AND non-interactive sign-ins' {
    # #690 (45): the sign-ins come from Entra's sign-in events in advanced hunting (interactive and non-interactive in one
    # table) -- SigninLogs / AADNonInteractiveUserSignInLogs exist only where Entra's diagnostic export reaches the
    # workspace, and internal's has neither, so the report was silently empty
    It '<_> reads Entra sign-in events (both kinds), successful sign-ins without a Conditional Access policy' -ForEach (Twins 'Identity_PrivilegedUser_NoConditionalAccess') {
        $c = CodeOf $_
        $c | Should -Match '(?m)^\s*EntraIdSignInEvents\s*$'
        $c | Should -Match ([regex]::Escape('| where ErrorCode == 0'))
        $c | Should -Match ([regex]::Escape('| where ConditionalAccessStatus == 2'))
        $c | Should -Match ([regex]::Escape('| join kind=leftouter _roleHolders on $left.UserKey == $right.RoleHolderKey'))
        $c | Should -Not -Match '(?m)^\s*SigninLogs\s*$' -Because 'the interactive table alone misses token sign-ins'
        $c | Should -Not -Match 'AADNonInteractiveUserSignInLogs' -Because 'a workspace without the Entra export returned nothing'
    }
}

Describe '(27) an unknown value is LISTED and labelled by its cause, never dropped' {
    It '<_> keeps an unread MFA registration and labels it' -ForEach (Twins 'Identity_NoMFA') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| extend _mfaUnknown = isnull(si_mfa_registered) or coalesce(set_has_element(si_unknown_fields, "si_mfa_registered"), false)'))
        $c | Should -Match ([regex]::Escape('| where si_mfa_registered == false or _mfaUnknown'))
        $c | Should -Match ([regex]::Escape('| extend ConfigurationName = iff(_mfaUnknown, "User MFA registration not readable from Entra", "User missing MFA registration")'))
        $c | Should -Not -Match '(?m)\| where si_mfa_registered == false\s*$'
        $c | Should -Match ([regex]::Escape('| where isnull(CreatedDays) or CreatedDays > 7'))
    }
    It '<_> keeps an undecided last sign-in (180 days) and labels it' -ForEach (Twins 'Identity_StaleUser_NoLogin180Days') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('or (isnull(LastSignInDays) and (isnull(CreatedDays) or CreatedDays > 180))'))
        $c | Should -Match ([regex]::Escape('iff(isnull(LastSignInDays), "User account inactive for 180+ days - no data source for the last sign-in", "User account inactive for 180+ days")'))
        $c | Should -Match ([regex]::Escape('| where coalesce(si_is_external, false) == false')) -Because 'an undecided external flag does not drop the account either'
    }
    It '<_> keeps an undecided last sign-in (90 days) and labels it' -ForEach (Twins 'Identity_StaleGuest_NoLogin90Days') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('or (isnull(LastSignInDays) and (isnull(CreatedDays) or CreatedDays > 90))'))
        $c | Should -Match ([regex]::Escape('iff(isnull(LastSignInDays), "Guest account inactive for 90+ days - no data source for the last sign-in", "Guest account inactive for 90+ days")'))
    }
    It '<_> lists a break-glass account with an undecided sign-in as anomaly NoSignInDataSource (the cause)' -ForEach (Twins 'Identity_BreakGlass_Anomaly') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| where LastSignInDays <= 30 or LastSignInDays > 180 or LastSignInDays == -1 or isnull(LastSignInDays)'))
        $c | Should -Match 'case\(isnull\(LastSignInDays\),\s+"NoSignInDataSource",'
        $c | Should -Match ([regex]::Escape('iff(AnomalyType == "NoSignInDataSource", "Break-glass account anomaly: no data source for the last sign-in", strcat("Break-glass account anomaly: ", AnomalyType))'))
    }
}

Describe '(28) Device_Missing_CVEs -- Defender vulnerability management''s severity where it holds the pair' {
    It '<_> overrides the graph severity with the TVM severity of the same device + CVE, inside the graph rows' -ForEach (Twins 'Device_Missing_CVEs') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| summarize TvmPairSeverity = take_any(tostring(VulnerabilitySeverityLevel)) by DeviceKey, _cveKey;'))
        $edges = [regex]::Match($c, '(?s)let _AssetFindingEdges =(.*?)\| project ').Groups[1].Value
        $edges | Should -Match ([regex]::Escape('| extend _cveKey = toupper(tostring(FindingName))'))
        $edges | Should -Match ([regex]::Escape('| join kind=leftouter (_TvmSeverityByPair) on DeviceKey, _cveKey')) -Because 'leftouter: a graph pair TVM lacks keeps its row and its graph severity'
        $edges | Should -Match ([regex]::Escape('| extend FindingSeverity = iff(isnotempty(TvmPairSeverity), TvmPairSeverity, FindingSeverity)'))
        $c.IndexOf('let _TvmSeverityByPair') | Should -BeGreaterThan $c.IndexOf('let _DeviceMap') -Because 'it reads only the devices of this slice'
    }
}

Describe '(29) Identity_ShadowAdmin -- critical AD groups and no Entra role, from the CI' {
    It '<_> reads the CI fields, dictionary-safe, a missing role list = no role' -ForEach (Twins 'Identity_ShadowAdmin') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| extend _critAdGroups = iff(gettype(si_ad_critical_groups) == "dictionary", si_ad_critical_groups.data, si_ad_critical_groups)'))
        $c | Should -Match ([regex]::Escape('| extend _hasCritAdGroup = coalesce(array_length(_critAdGroups), 0) > 0'))
        $c | Should -Match ([regex]::Escape('| extend _entraRoleCount = coalesce(array_length(si_entra_roles_permanent), 0) + coalesce(array_length(si_entra_roles_eligible), 0)'))
        $c | Should -Match ([regex]::Escape('| where coalesce(si_is_shadow_admin, false) == true or (_hasCritAdGroup and _entraRoleCount == 0)'))
    }
    It 'no report tests a role or group list with a bare array_length(...) == 0 (null is never 0)' {
        $all = (@($script:Catalog.Reports) | ForEach-Object { (@($_.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" }) -join "`n"
        [regex]::Matches($all, '(?<!coalesce\()array_length\((si_entra_roles_permanent|si_entra_roles_eligible|si_ad_critical_groups)\)\s*==\s*0').Count | Should -Be 0
    }
}

Describe '(29) the Exposure Graph critical AD groups are read through the dictionary' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\data-model\SI-FieldMapper.ps1')
        $map = Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\mappings\eg.locked.json') -Raw | ConvertFrom-Json
        $script:Item = @(@($map.mappings) | Where-Object { $_.field -eq 'si_ad_critical_groups' -and @($_.recordTypes) -contains 'user' })[0]
        function script:NodeWith($crit) { [pscustomobject]@{ node = [pscustomobject]@{ NodeProperties = [pscustomobject]@{ rawData = [pscustomobject]@{ nestedCriticalAdGroups = $crit } } } } }
    }
    It 'the shape advanced hunting returns (type + data of JSON text) gives the group names' {
        $dict = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.security.dynamicColumnValue'; type = 'NestedCriticalAdGroups'; 'data@odata.type' = '#Collection(String)'
                                   data = @('{"groupUniqueId":"S-1-5-32-544","groupName":"Administrators"}', '{"groupUniqueId":"S-1-5-21-1-512","groupName":"Domain Admins"}') }
        @((Get-SIMappingValues -MapItem $script:Item -Object (NodeWith $dict) -ValueMaps $null).ToArray()) | Sort-Object | Should -Be @('Administrators', 'Domain Admins')
    }
    It 'a plain list of groups still reads' {
        $list = @([pscustomobject]@{ groupUniqueId = 'S-1-5-21-1-519'; groupName = 'Enterprise Admins' })
        @((Get-SIMappingValues -MapItem $script:Item -Object (NodeWith $list) -ValueMaps $null).ToArray()) | Should -Be @('Enterprise Admins')
    }
    It 'NEGATIVE: an empty group list gives no group (the dictionary''s own type name is never a group)' {
        $empty = [pscustomobject]@{ type = 'NestedCriticalAdGroups'; data = @() }
        @((Get-SIMappingValues -MapItem $script:Item -Object (NodeWith $empty) -ValueMaps $null).ToArray()).Count | Should -Be 0
    }
}

Describe '(29) Device_Certificates -- every weak certificate, the algorithm read as Defender writes it' {
    BeforeAll {
        # the predicates as SHIPPED, evaluated -- KQL's startswith / endswith ignore case, as String.StartsWith(OrdinalIgnoreCase)
        function script:ToPs([string]$Expr) {
            $e = $Expr
            $e = [regex]::Replace($e, '_alg\s+startswith\s+"([^"]+)"', { param($m) "`$alg.StartsWith('$($m.Groups[1].Value)', [StringComparison]::OrdinalIgnoreCase)" })
            $e = [regex]::Replace($e, '_alg\s+endswith\s+"([^"]+)"', { param($m) "`$alg.EndsWith('$($m.Groups[1].Value)', [StringComparison]::OrdinalIgnoreCase)" })
            $e = $e -replace 'isnotnull\(_key\)', '($null -ne $key)' -replace '\b_key\b', '$key' -replace '\b_valid\b', '$true'
            $e = $e -replace '\bnot\(', '-not (' -replace '\band\b', '-and' -replace '\bor\b', '-or' -replace '\s<\s', ' -lt ' -replace '\s>\s', ' -gt '
            [scriptblock]::Create($e)
        }
        function script:Predicates([string]$Report) {
            $c = CodeOf $Report
            $c | Should -Not -Match '_alg has ' -Because '"has" matches whole terms -- "sha1rsa" has "sha1" is false'
            $wa = [regex]::Match($c, '_weakAlg = _valid and (\(.*?\)),\s*\r?\n').Groups[1].Value
            $wk = [regex]::Match($c, '_weakKey = _valid and (.*?),\s*\r?\n').Groups[1].Value
            $wa | Should -Not -BeNullOrEmpty; $wk | Should -Not -BeNullOrEmpty
            @{ Alg = (ToPs $wa); Key = (ToPs $wk) }
        }
    }
    It '<_> flags the weak hashes Defender writes (internal 2026-10-15) and not the strong ones' -ForEach (Twins 'Device_Certificates') {
        $p = Predicates $_
        foreach ($alg in 'sha1RSA', 'md5RSA', 'md2RSA', 'sha1DSA') { $key = 2048; (& $p.Alg) | Should -BeTrue -Because "$alg is a weak signature" }
        foreach ($alg in 'sha256RSA', 'sha384RSA', 'sha512RSA', 'sha384ECDSA') { $key = 2048; (& $p.Alg) | Should -BeFalse -Because "$alg is not weak" }
    }
    It '<_> flags RSA and DSA keys under 2048 bits, never an ECDSA key or a 2048-bit key' -ForEach (Twins 'Device_Certificates') {
        $p = Predicates $_
        $alg = 'md5RSA'; $key = 1024; (& $p.Key) | Should -BeTrue
        $alg = 'sha1DSA'; $key = 1024; (& $p.Key) | Should -BeTrue -Because 'DSA keys are checked now'
        $alg = 'sha256RSA'; $key = 2048; (& $p.Key) | Should -BeFalse
        $alg = 'sha384ECDSA'; $key = 384; (& $p.Key) | Should -BeFalse -Because 'an ECDSA key is not measured in RSA bits'
        $alg = 'sha256RSA'; $key = 0; (& $p.Key) | Should -BeFalse -Because 'an unknown key size is no finding'
    }
    It '<_> lists every kind a certificate has and labels self-signed roots (owner: "List all, label roots")' -ForEach (Twins 'Device_Certificates') {
        $c = CodeOf $_
        $c | Should -Match ([regex]::Escape('| mv-expand _kind = _kinds to typeof(string)'))
        $c | Should -Not -Match ([regex]::Escape('_kind = case(_expiring, "expiring"')) -Because 'one kind per certificate hid a weak certificate that also expires'
        $c | Should -Match ([regex]::Escape('| extend _root = isnotempty(tostring(_to)) and tostring(_to) == tostring(_by)'))
        $c | Should -Match ([regex]::Escape('iff(_root, " (self-signed root)", "")'))
        $c | Should -Match ([regex]::Escape('of them self-signed root(s)'))
        $c | Should -Not -Match 'where\s+not\(?\s*_root' -Because 'roots are labelled, never left out'
        # mv-expand of an empty list drops the row -- the list is never empty here (a certificate reaches it only with a problem)
        $c.IndexOf('| where _weakAlg or _weakKey or _expiring or _expired') | Should -BeLessThan $c.IndexOf('| mv-expand _kind = _kinds')
    }
}
