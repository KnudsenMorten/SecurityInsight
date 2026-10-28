#Requires -Version 5.1
<#
    #724 (1) -- A REPORT STATE THAT SAYS "Unknown" SAYS WHY INSTEAD (owner 2026-10-16: "Reword to the cause").

    Every customer-visible value of the Risk Analysis reports that read "Unknown" now names its real cause in plain words:
      not readable from Entra   -- the MFA registration / a workload's permissions could not be read
      no data source            -- the source that decides the last sign-in / password age / never-expires flag for this
                                   account's origin is not linked (si_unknown_fields; field catalog)
      not collected             -- an Azure role's name, a service principal's sign-in activity
      not tiered                -- no tier rule matches the asset (the tier is the MIN of the tier rules, never a default)
    The meaning (which rows are listed) is unchanged; where the query compares the value (the break-glass AnomalyType)
    both sides changed together. A blank stays blank (the *Scope columns) -- nothing new says Unknown.
    Offline: asserts on the shipped YAML. Nothing runs a query.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml
    function script:QueryOf([string]$Name) {
        $r = @($script:Catalog.Reports | Where-Object { [string]$_.ReportName -eq $Name })
        $r.Count | Should -Be 1 -Because "$Name is in the catalog"
        (@($r[0].ReportQuery) | ForEach-Object { [string]$_ }) -join "`n"
    }
    # the string literals a query writes (comments left out)
    function script:LiteralsOf([string]$Query) {
        $code = (($Query -split "`n") | Where-Object { $_ -notmatch '^\s*//' }) -join "`n"
        @([regex]::Matches($code, '"([^"\r\n]*)"|''([^''\r\n]*)''') | ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value })
    }
}

Describe 'no Risk Analysis report writes "Unknown" as a value' {
    It 'no string literal of any report holds the word unknown' {
        $hits = foreach ($r in @($script:Catalog.Reports)) {
            foreach ($l in (LiteralsOf ((@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n"))) {
                if ($l -match '(?i)\bunknown\b') { '{0}: "{1}"' -f $r.ReportName, $l }
            }
        }
        @($hits) | Should -BeNullOrEmpty -Because 'a state says its cause (not readable / no data source / not collected / not tiered)'
    }
}

Describe 'each reworded state names its cause' {
    It '<N> -- MFA registration not readable from Entra' -ForEach @(@{ N = 'Identity_NoMFA_Summary' }, @{ N = 'Identity_NoMFA_Detailed' }) {
        $q = QueryOf $N
        $q | Should -Match ([regex]::Escape('iff(_mfaUnknown, "User MFA registration not readable from Entra", "User missing MFA registration")'))
        $q | Should -Match ([regex]::Escape('| where si_mfa_registered == false or _mfaUnknown')) -Because 'the same rows are listed'
    }
    It '<N> -- no data source for the last sign-in' -ForEach @(
        @{ N = 'Identity_StaleUser_NoLogin180Days_Summary'; T = 'User account inactive for 180+ days' },
        @{ N = 'Identity_StaleUser_NoLogin180Days_Detailed'; T = 'User account inactive for 180+ days' },
        @{ N = 'Identity_StaleGuest_NoLogin90Days_Summary'; T = 'Guest account inactive for 90+ days' },
        @{ N = 'Identity_StaleGuest_NoLogin90Days_Detailed'; T = 'Guest account inactive for 90+ days' }) {
        (QueryOf $N) | Should -Match ([regex]::Escape(('iff(isnull(LastSignInDays), "{0} - no data source for the last sign-in", "{0}")' -f $T)))
    }
    It '<N> -- the break-glass anomaly NoSignInDataSource, set and compared the same way' -ForEach @(@{ N = 'Identity_BreakGlass_Anomaly_Summary' }, @{ N = 'Identity_BreakGlass_Anomaly_Detailed' }) {
        $q = QueryOf $N
        $q | Should -Match 'case\(isnull\(LastSignInDays\),\s+"NoSignInDataSource",'
        $q | Should -Match ([regex]::Escape('iff(AnomalyType == "NoSignInDataSource", "Break-glass account anomaly: no data source for the last sign-in"'))
    }
    It '<N> -- the risk factor PasswordNeverExpiresNoDataSource' -ForEach @(@{ N = 'Identity_PasswordNeverExpires_Privileged_Summary' }, @{ N = 'Identity_PasswordNeverExpires_Privileged_Detailed' }) {
        (QueryOf $N) | Should -Match ([regex]::Escape('iff(_pneUnknown, array_concat(coalesce(si_rf_names_, dynamic([])), dynamic(["PasswordNeverExpiresNoDataSource"])), si_rf_names_)'))
    }
    It '<N> -- the risk factor PasswordAgeNoDataSource' -ForEach @(@{ N = 'Identity_PrivilegedUser_StalePassword_Summary' }, @{ N = 'Identity_PrivilegedUser_StalePassword_Detailed' }) {
        (QueryOf $N) | Should -Match ([regex]::Escape('iff(_pwAgeUnknown, dynamic(["PasswordAgeNoDataSource"]), dynamic([]))'))
    }
    It 'Identity_PrivilegedSPN_NoLogin180Days_Detailed -- privilege not readable' {
        (QueryOf 'Identity_PrivilegedSPN_NoLogin180Days_Detailed') | Should -Match ([regex]::Escape('"Privilege not readable -- SI could not read this workload''s permissions, roles or tier"'))
    }
    It 'Identity_MultiTenant_HighPermission_SPN_Detailed -- privilege not readable' {
        (QueryOf 'Identity_MultiTenant_HighPermission_SPN_Detailed') | Should -Match ([regex]::Escape('SI could not read its permissions, so its privilege is not readable - check it in Entra"'))
    }
    It 'Identity_SPN_OwnsResourcePublicAccess_Detailed -- role name and sign-in activity not collected' {
        $q = QueryOf 'Identity_SPN_OwnsResourcePublicAccess_Detailed'
        $q | Should -Match ([regex]::Escape('iff(isempty(RoleName), "an Azure role (name not collected)", RoleName)'))
        $q | Should -Match ([regex]::Escape('isnull(DaysInactive), "sign-in activity not collected; no high-risk permission grant known"'))
    }
    It 'Endpoint_ConflictingTierTags_Detailed -- not tiered (no tier rule matches)' {
        $q = QueryOf 'Endpoint_ConflictingTierTags_Detailed'
        $q | Should -Match ([regex]::Escape('iff(isnull(_tierCol), "not tiered (no tier rule matches)", tostring(_tierCol))'))
        $q | Should -Match ([regex]::Escape('The engine has no tier for this asset yet - no tier rule matches it.'))
    }
}
