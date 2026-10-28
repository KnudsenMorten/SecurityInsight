#Requires -Version 5.1
<#
    ONE RISK-FACTOR CATALOG WITH PROVIDER LINKS (#458).

    data-model/risk-factors.locked.json defines every factor once over SI fields. Each catalog factor now also carries a
    description, its combination rule (any / all = the top level of its condition) and a providers block: per provider the
    provider fields that PROVE it, read from the field mappings (engine/data-model/SI-RiskFactorCatalog.ps1). Network ranges
    (DMZ, online landing zones) prove "internet exposed" too: the internet_exposed_ranges list plus the setting
    SI_InternetExposedRanges (Pro: a database setting; Community: the custom file or lists.custom.json).

    What these tests keep true:
      * the stored providers block of every catalog factor IS what the mappings say (never drifts); combine matches the
        condition; every factor has a description; Update-SIRiskFactorProviders is idempotent on the shipped files
      * the factors several providers prove are linked to each of them (internet exposed, no MFA, stale / never signed in,
        unsupported OS) and marked for a CI column; privileged = the computed tier; the single-provider ones say so
      * the network ranges: the setting is merged into the list (CIDR or address, IPv4 / IPv6; anything else left out), the
        CI enrichment uses the merged list, and a CI with an address in a range gets internet_exposed
      * the setting is in the settings catalog (Pro database setting) and the Community reference
    Offline; PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RiskFactorCatalog.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    $script:Model = Get-SIDataModel
    $script:Factors = @($script:Model['risk-factors'].factors)
    function script:F([string]$Id) { @($script:Factors | Where-Object { $_.id -eq $Id })[0] }
    function script:Provs([string]$Id) { @((F $Id).providers.PSObject.Properties | ForEach-Object { $_.Name }) }
}

Describe 'the catalog''s provider links' {
    It 'every catalog factor''s providers block is what the mappings say, its combine matches its condition, it has a description' {
        $p = Test-SIRiskFactorProviders -Model $script:Model
        @($p) | Should -BeNullOrEmpty
    }
    It 'the whole data model still validates' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
    It 'Update-SIRiskFactorProviders changes nothing on the shipped files (idempotent)' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-rf-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        Copy-Item -Recurse (Join-Path $script:SIRoot 'data-model') $tmp
        try {
            $before = [IO.File]::ReadAllText((Join-Path $tmp 'risk-factors.locked.json'))
            Update-SIRiskFactorProviders -Root $tmp
            [IO.File]::ReadAllText((Join-Path $tmp 'risk-factors.locked.json')) | Should -BeExactly $before
        } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
    }
    It 'a mapping change shows as drift until the block is regenerated' {
        $f = (F 'no_mfa') | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $f.providers.PSObject.Properties.Remove('eg')
        $m = [ordered]@{}; foreach ($k in $script:Model.Keys) { $m[$k] = $script:Model[$k] }
        $m['risk-factors'] = [pscustomobject]@{ factors = @($f) }
        @(Test-SIRiskFactorProviders -Model $m) | Should -Match 'no_mfa: the providers block is not what the mappings say'
    }
}

Describe 'the factors several providers prove (#458 start set)' {
    It 'internet exposed: Defender for Endpoint, Exposure Graph, Azure, Shodan and the network ranges; any of them' {
        $p = Provs 'internet_exposed'
        foreach ($x in 'mde', 'eg', 'azure', 'shodan', 'network') { $p | Should -Contain $x }
        (F 'internet_exposed').combine | Should -Be 'any'
        @((F 'internet_exposed').providers.mde | ForEach-Object { $_.sources } | ForEach-Object { $_ }) | Should -Contain 'deviceInfo.IsInternetFacing'
        (F 'internet_exposed').providers.network[0].list | Should -Be 'internet_exposed_ranges'
        (F 'internet_exposed').providers.network[0].setting | Should -Be 'SI_InternetExposedRanges'
    }
    It 'no MFA: Entra and Exposure Graph' {
        $p = Provs 'no_mfa'; $p | Should -Contain 'entra'; $p | Should -Contain 'eg'
    }
    It 'stale / never signed in: Entra, Active Directory and Defender for Identity' {
        foreach ($id in 'stale_sign_in', 'never_signed_in') { $p = Provs $id; foreach ($x in 'entra', 'ad', 'mdi') { $p | Should -Contain $x -Because $id } }
    }
    It 'unsupported OS: every device provider (through the OS name its list matches)' {
        $p = Provs 'unsupported_os'; foreach ($x in 'mde', 'eg', 'entra', 'intune', 'ad') { $p | Should -Contain $x }
    }
    It 'has_secret is its own factor (#527 (3)): a client secret in use, from the service principal''s password credentials' {
        Provs 'has_secret' | Should -Be @('entra')
        # a secret on the application registration counts too (the application's own credentials, read with the service
        # principal): the factor's source list is the mapping's, both paths in the mapping's order
        $mapped = @(@($script:Model.Mappings['entra'].mappings | Where-Object { $_.field -eq 'si_has_client_secret' })[0].sources)
        $mapped | Should -Be @('sp.passwordCredentials[*].keyId', 'app.passwordCredentials[*].keyId')
        (F 'has_secret').providers.entra[0].sources | Should -Be $mapped
        (F 'has_secret').legacyTokens | Should -Contain 'RF_P_HasSecret'
        (F 'expiring_credentials').legacyTokens | Should -Not -Contain 'RF_P_HasSecret'
    }
    It 'old_account and stale_sign_in are about identities only (#527 (3))' {
        foreach ($id in 'old_account', 'stale_sign_in') { ((F $id).when | ConvertTo-Json -Depth 10 -Compress) | Should -Match '"field":"si_identity_type"' -Because $id }
        $ci = [ordered]@{ si_ci_id = 'd'; si_class = 'device'; si_created = [datetime]'2020-01-01'; si_field_sources = [ordered]@{} }
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]::UtcNow }
        @($ci['si_risk_factors'] | ForEach-Object { $_.id }) | Should -Not -Contain 'old_account'
        @($ci['si_risk_factors'] | ForEach-Object { $_.id }) | Should -Not -Contain 'stale_sign_in'
    }
    It 'Defender for Cloud proves internet exposure through its own mapping onto si_internet_exposed (#527 (7))' {
        Provs 'internet_exposed' | Should -Contain 'mdc'
        (F 'internet_exposed').providers.mdc[0].siField | Should -Be 'si_internet_exposed'
        (F 'internet_exposed').providers.mdc[0].sources | Should -Be @('exposure.internetExposed')
    }
    It 'no owner, expiring credentials, has secret, high blast radius: the one provider that has the data today' {
        Provs 'no_owner' | Should -Be @('entra')
        Provs 'expiring_credentials' | Should -Be @('entra')
        Provs 'identity_high_blast_radius' | Should -Be @('mdi')
    }
    It 'the start set is marked for its own CI column; nothing else is' {
        $want = @('internet_exposed', 'no_mfa', 'stale_sign_in', 'never_signed_in', 'unsupported_os', 'no_owner', 'expiring_credentials', 'has_secret', 'identity_high_blast_radius', 'old_password')   # old_password: #546 the stale-password reports read it
        @(Get-SIRiskFactorCiColumns -Factors $script:Model['risk-factors'] | Sort-Object) | Should -Be @($want | Sort-Object)
    }
    It 'proof fields leave out the scoping fields and follow a conditions list' {
        $l = Get-SIDataModelListContext $script:Model
        $pf = Get-SIRiskFactorProofFields -Factor (F 'no_mfa') -Lists $l
        $pf | Should -Not -Contain 'si_identity_type'
        $pf | Should -Contain 'si_mfa_registered'
        (Get-SIRiskFactorProofFields -Factor (F 'unsupported_os') -Lists $l) | Should -Contain 'si_os_name'
    }
}

Describe 'network ranges (customer-overridable)' {
    It 'the setting is merged into internet_exposed_ranges; invalid values are left out; no setting = the lists unchanged' {
        $l = Get-SIDataModelListContext $script:Model
        (Merge-SIRiskFactorRanges -Lists $l -Setting $null) | Should -Be $l
        $m = Merge-SIRiskFactorRanges -Lists $l -Setting @('203.0.113.0/24', '10.50.0.0/16;2001:db8::/32', 'not-an-ip', '10.0.0.0/999', '198.51.100.7')
        @($m['internet_exposed_ranges'].values) | Should -Be @('203.0.113.0/24', '10.50.0.0/16', '2001:db8::/32', '198.51.100.7')
        @($l['internet_exposed_ranges'].values).Count | Should -Be 0 -Because 'the shipped list is not changed in place'
    }
    It 'keeps the ranges of lists.custom.json and adds the setting''s' {
        $l = @{ internet_exposed_ranges = [pscustomobject]@{ id = 'internet_exposed_ranges'; type = 'ranges'; values = @('192.0.2.0/24') } }
        @((Merge-SIRiskFactorRanges -Lists $l -Setting '203.0.113.0/24')['internet_exposed_ranges'].values) | Should -Be @('192.0.2.0/24', '203.0.113.0/24')
    }
    It 'a CI with an address in a range gets internet_exposed; one outside every range does not' {
        $ctx = @{ Lists = (Merge-SIRiskFactorRanges -Lists (Get-SIDataModelListContext $script:Model) -Setting '10.50.0.0/16'); Now = [datetime]::UtcNow }
        $ci = [ordered]@{ si_ci_id = 'c1'; si_class = 'device'; si_ip_addresses = @('10.50.3.4'); si_internet_exposed = $false; si_field_sources = [ordered]@{} }
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context $ctx
        @($ci['si_risk_factors'] | ForEach-Object { $_.id }) | Should -Contain 'internet_exposed'
        $ci2 = [ordered]@{ si_ci_id = 'c2'; si_class = 'device'; si_ip_addresses = @('10.60.3.4'); si_internet_exposed = $false; si_field_sources = [ordered]@{} }
        $null = Invoke-SICiRiskFactors -Ci $ci2 -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context $ctx
        @($ci2['si_risk_factors'] | ForEach-Object { $_.id }) | Should -Not -Contain 'internet_exposed'
    }
    It 'the CI enrichment uses the merged list' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $t | Should -Match '\$ctx = @\{ Lists = \(Merge-SIRiskFactorRanges -Lists \(Get-SIDataModelListContext \$Model\)\)'
        $t | Should -Match "SI-RiskFactorCatalog\.ps1"
    }
    It 'the setting is documented in the Community reference (the Pro settings catalog is built from it: SI-SettingsPage.Tests)' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'config\SecurityInsight.custom.reference.ps1')) | Should -Match '(?m)^# \$global:SI_InternetExposedRanges = @\('
    }
}

Describe 'the rules every factor keeps (#527 (5)-(7))' {
    BeforeAll {
        function script:With([object[]]$Factors) {
            $m = [ordered]@{}; foreach ($k in $script:Model.Keys) { $m[$k] = $script:Model[$k] }
            $m['risk-factors'] = [pscustomobject]@{ factors = $Factors }
            @(Test-SIRiskFactorRules -Model $m)
        }
        # #559: a factor carries the v2 fields (shortName, name, group, class, impact 1-5, state) -- held to them too
        function script:Fac([string]$Id, $Scope, $When) { [pscustomobject]@{ id = $Id; shortName = 'TestFactor'; name = 'A test factor'; appliesTo = $Scope; group = 'Exposure'; class = 'optional'; axis = 'probability'; impact = 1; state = 'enabled'; evaluatedBy = 'catalog'; when = $When } }
        $script:Ok = @{ all = @(@{ field = 'si_internet_exposed'; op = 'is_true' }) }
    }
    It 'the shipped catalog keeps them all, and the data-model validation enforces them' {
        @(Test-SIRiskFactorRules -Model $script:Model) | Should -BeNullOrEmpty
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')) | Should -Match 'foreach \(\$x in \(Test-SIRiskFactorRules -Model \$Model\)\) \{ \$p\.Add\(\$x\) \}'
    }
    It 'refuses a factor with no scope, both scopes or an unknown one' {
        (With @(Fac 'a' $null $script:Ok)) | Should -Match 'exactly one scope'
        (With @(Fac 'b' @('asset', 'finding') $script:Ok)) | Should -Match 'exactly one scope'
        (With @(Fac 'c' 'both' $script:Ok)) | Should -Match 'exactly one scope'
        @(With @(Fac 'd' 'asset' $script:Ok)) | Should -BeNullOrEmpty
        @(With @(Fac 'e' 'finding' $script:Ok)) | Should -BeNullOrEmpty
    }
    It 'refuses si_tier in a condition, also nested' {
        (With @(Fac 't' 'asset' @{ all = @(@{ field = 'si_tier'; op = 'eq'; value = 0 }) })) | Should -Match 'reads si_tier'
        (With @(Fac 't2' 'asset' @{ any = @(@{ field = 'si_internet_exposed'; op = 'is_true' }, @{ all = @(@{ field = 'si_tier'; op = 'lte'; value = 1 }) }) })) | Should -Match 'reads si_tier'
    }
    It 'refuses a raw source path as a field or a value' {
        (With @(Fac 'r1' 'asset' @{ all = @(@{ field = 'node.NodeProperties.rawData.exposedToInternet'; op = 'is_true' }) })) | Should -Match 'SI fields \(si_\*\) only'
        (With @(Fac 'r2' 'asset' @{ all = @(@{ field = 'identity.BlastRadius'; op = 'eq'; value = 'high' }) })) | Should -Match 'SI fields'
        (With @(Fac 'r3' 'asset' @{ all = @(@{ field = 'si_cmdb_data_sensitivity'; op = 'eq'; value = 'ci.u_data_sensitivity' }) })) | Should -Match 'raw source path'
        @(With @(Fac 'r4' 'asset' @{ all = @(@{ field = 'si_ip_addresses'; op = 'in_ranges'; value = '10.0.0.0/8' }) })) | Should -BeNullOrEmpty
    }
    It 'one factor alone is checked the same way (what a Pro override of risk-factors:<id> is held to on write)' {
        $bad = [pscustomobject]@{ id = 'x'; appliesTo = 'asset'; evaluatedBy = 'catalog'; when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_tier'; op = 'eq'; value = 0 }) } }
        @(Test-SIRiskFactorItem -Factor $bad) | Should -Match 'reads si_tier'
        $ok = [pscustomobject]@{ id = 'x'; shortName = 'CvssHigh'; name = 'CVSS high'; appliesTo = 'finding'; group = 'Severity'; class = 'optional'; impact = 2; state = 'enabled'; evaluatedBy = 'catalog'; when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_cvss'; op = 'gte'; value = 9 }) } }
        @(Test-SIRiskFactorItem -Factor $ok) | Should -BeNullOrEmpty
        # #559: impact outside 1..5 and a built-in factor switched off are refused (the web app refuses the same)
        $bi = $ok | Select-Object *; $bi.class = 'builtin'; $bi.state = 'disabled'
        @(Test-SIRiskFactorItem -Factor $bi) | Should -Match 'built-in factor cannot be disabled'
        $hi = $ok | Select-Object *; $hi.impact = 6
        @(Test-SIRiskFactorItem -Factor $hi) | Should -Match 'whole number 1\.\.5'
    }
    It 'high_cvss_public_ip is a finding factor now (a fact about the vulnerability)' {
        (F 'high_cvss_public_ip').appliesTo | Should -Be 'finding'
        ((F 'high_cvss_public_ip').when | ConvertTo-Json -Depth 10 -Compress) | Should -Match '"field":"si_cvss"'
    }
}