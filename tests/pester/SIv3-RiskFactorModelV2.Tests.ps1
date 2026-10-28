#Requires -Version 5.1
<#
    RISK FACTOR MODEL V2 (REQUIREMENTS #559 -- engine and catalog half; #558 short names / built-in / asset vs vulnerability).

      1. CATALOG    every factor carries shortName (PascalCase, no editable number), name (description), appliesTo, group (one
                    of ten), class (EXPLICIT: builtin | optional), impact 1..5, state; no stage; the owner's removals
                    (very_stale_sign_in, break_glass) and additions (KnownExploited, ExploitKit, NetworkNoUserAction, ZeroDay,
                    Overdue, OldVuln); the default impacts the owner set (PortOpenInternet 5, InternetExposed 4, ExploitKit 4,
                    LeakedCreds 5, NoMFA 3); real risk = built-in 3-5, the former hygiene = optional 1-2
      2. VALIDATION the engine-side twin of the web app's check, inside Test-SIDataModel: impact 1..5, a built-in factor is
                    never disabled, a factor without a class is built-in, shortName shape, group; break_glass_patterns is a
                    values list of glob patterns (letters, digits, space, . _ @ - and * ?), never wildcards only
      3. TWINS      Risk Analysis' Get-RAFactorMeta / Get-RARiskFactorLegendRows agree with the catalog's Get-SIRiskFactor* /
                    Get-SIRiskFactorLegend on every shipped factor
      4. ROW        Measure-RARowFactors: each factor once, on its own side, with its impact; unknown report tokens keep their
                    column's side; disabled factors add nothing; retired break-glass tokens add nothing
      5. FINDING    finding factors are evaluated on the row's SI fields; an absent field is unknown and adds nothing (#546)
      6. BUILT-IN   the run-start check re-enables a built-in factor an override tried to disable, and says so
      7. BREAK GLASS a classification (never a factor): provider, naming patterns, group, excluded from ALL CA policies;
                    unknown fields never classify; the CI build runs it before the tier rules
    Offline; PS 7 (the v3 gate), PS 5.1 compatible. Written 2026-10-10, not run yet (owner: "we build all then we test").
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-BreakGlass.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Factors = @($script:Model['risk-factors'].factors)
    $script:ById = @{}; foreach ($f in $script:Factors) { $script:ById[[string]$f.id] = $f }
    $script:Raw = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\risk-factors.locked.json')) | ConvertFrom-Json
    function script:Copy-Factor($f) { $f | ConvertTo-Json -Depth 30 | ConvertFrom-Json }
    function script:Copy-Model {
        $m = @{}; foreach ($k in $script:Model.Keys) { $m[$k] = $script:Model[$k] }
        $m['risk-factors'] = [pscustomobject]@{ kind = 'risk-factor'; factors = @($script:Factors | ForEach-Object { Copy-Factor $_ }) }
        $m['lists'] = ($script:Model['lists'] | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
        $m
    }
}

Describe '1. the catalog carries the v2 model' {
    It 'every factor has shortName, name, appliesTo, group, class (explicit), impact 1..5, state -- and no stage' {
        $groups = @('Exposure', 'Device health', 'Identity', 'Privilege', 'Apps', 'Importance', 'Exploitability', 'Impact', 'Severity', 'Lifecycle')
        foreach ($f in @($script:Raw.factors)) {
            $f.shortName | Should -Match '^[A-Z][A-Za-z0-9]{1,23}$' -Because "$($f.id) shortName"
            ([string]$f.name).Trim() | Should -Not -BeNullOrEmpty -Because "$($f.id) name (the GUI description)"
            @('asset', 'finding') | Should -Contain ([string]$f.appliesTo) -Because "$($f.id) appliesTo"
            $groups | Should -Contain ([string]$f.group) -Because "$($f.id) group"
            $f.PSObject.Properties['class'] | Should -Not -BeNullOrEmpty -Because "$($f.id): the GUI reads a class-less factor as built-in, so every shipped factor says it"
            @('builtin', 'optional') | Should -Contain ([string]$f.class)
            [int]$f.impact | Should -BeGreaterOrEqual 1; [int]$f.impact | Should -BeLessOrEqual 5
            [string]$f.state | Should -Be 'enabled' -Because "$($f.id): every shipped factor is enabled"
            $f.PSObject.Properties['stage'] | Should -BeNullOrEmpty -Because "$($f.id): state replaced stage (#559)"
        }
    }
    It 'short names are unique and carry no editable number (a factor with a threshold has no digit in its short name)' {
        $sn = @($script:Raw.factors | ForEach-Object { ([string]$_.shortName).ToLowerInvariant() })
        @($sn | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
        foreach ($f in @($script:Raw.factors | Where-Object { $_.PSObject.Properties['criteria'] -and [string]$_.criteria.kind -in 'threshold', 'range' })) { [string]$f.shortName | Should -Not -Match '\d' -Because $f.id }
    }
    It 'the owner''s short names exist' {
        $want = 'InternetExposed', 'PortOpenInternet', 'UnsupportedOS', 'NotOnboarded', 'AVDisabled', 'RecentIncident', 'HighMachineRisk', 'NoMFA', 'OldPassword',
            'LeakedCreds', 'IdentityAtRisk', 'Production', 'RestrictedData', 'HighBlastRadius', 'HighMsCriticality', 'ConfidentialData', 'ClientSecret', 'DefenderExcluded',
            'AVOutOfDate', 'EnabledNoSignInStale', 'NeverSignedIn', 'OldAccount', 'PermanentAdmin', 'NoOwner', 'CredsExpired', 'CredsExpiring', 'PublisherUnverified',
            'MultiTenantApp', 'Unmanaged', 'ExploitAvailable', 'RCE', 'CVSS9Plus', 'KnownExploited', 'ExploitKit', 'NetworkNoUserAction', 'ZeroDay', 'Overdue', 'OldVuln'
        $have = @($script:Raw.factors | ForEach-Object { [string]$_.shortName })
        foreach ($w in $want) { $have | Should -Contain $w }
    }
    It 'removed: very_stale_sign_in (one stale factor, days editable) and break_glass (a classification)' {
        $script:ById.ContainsKey('very_stale_sign_in') | Should -BeFalse
        $script:ById.ContainsKey('break_glass') | Should -BeFalse
        @($script:ById['stale_sign_in'].legacyTokens) | Should -Contain 'RF_P_VeryStale'
        [string]$script:ById['stale_sign_in'].criteria.kind | Should -Be 'threshold'
    }
    It 'the new finding factors read the #560 SI fields and are vulnerability factors' {
        $want = @{ known_exploited = 'si_exploit_verified'; exploit_kit = 'si_in_exploit_kit'; network_no_user_action = 'si_cvss_vector'; zero_day = 'si_fix_available'; overdue = 'si_due_date'; old_vuln = 'si_published' }
        foreach ($id in $want.Keys) {
            $f = $script:ById[$id]
            $f | Should -Not -BeNullOrEmpty -Because $id
            [string]$f.appliesTo | Should -Be 'finding'
            @(Get-SIConditionFields $f.when) | Should -Contain $want[$id]
            @($script:Model['field-catalog'].fields | Where-Object { [string]$_.name -eq $want[$id] }).Count | Should -Be 1 -Because "$($want[$id]) is in the field catalog"
        }
        [string]$script:ById['old_vuln'].criteria.field | Should -Be 'si_published'
    }
    It 'the owner''s default impacts, and real risk = built-in 3..5, the former hygiene = optional 1..2' {
        $want = @{ high_risk_port_open = 5; internet_exposed = 4; exploit_kit = 4; leaked_credentials = 5; no_mfa = 3 }
        foreach ($id in $want.Keys) { [int]$script:ById[$id].impact | Should -Be $want[$id] -Because $id }
        $hygiene = 'stale_sign_in', 'never_signed_in', 'old_account', 'permanent_privileged_role', 'no_owner', 'expired_credentials', 'expiring_credentials', 'publisher_not_verified', 'multitenant_app', 'unmanaged'
        foreach ($f in @($script:Raw.factors | Where-Object { $_.id -ne 'report_scoped' })) {
            if ($hygiene -contains $f.id) { [string]$f.class | Should -Be 'optional' -Because $f.id; [int]$f.impact | Should -BeLessOrEqual 2 -Because $f.id }
            else { [string]$f.class | Should -Be 'builtin' -Because $f.id; [int]$f.impact | Should -BeGreaterOrEqual 3 -Because $f.id }
        }
    }
    It 'the shipped data model validates (v2 fields, break_glass_patterns)' {
        @(Test-SIDataModel -Model $script:Model) | Should -BeNullOrEmpty
    }
}

Describe '2. the validation the web app agrees with' {
    It 'impact outside 1..5 is refused' {
        foreach ($bad in 0, 6, 2.5, 'x') {
            $f = Copy-Factor $script:ById['no_mfa']; $f.impact = $bad
            @(Test-SIRiskFactorModelV2 -Factor $f) -join ' ' | Should -Match 'impact' -Because "impact $bad"
        }
    }
    It 'a built-in factor cannot be disabled; an optional one can' {
        $b = Copy-Factor $script:ById['internet_exposed']; $b.state = 'disabled'
        @(Test-SIRiskFactorModelV2 -Factor $b) -join ' ' | Should -Match 'cannot be disabled'
        $o = Copy-Factor $script:ById['old_account']; $o.state = 'disabled'
        @(Test-SIRiskFactorModelV2 -Factor $o) | Should -BeNullOrEmpty
    }
    It 'a factor without a class is built-in (the GUI contract): it cannot be disabled' {
        $f = Copy-Factor $script:ById['old_account']; $f.PSObject.Properties.Remove('class'); $f.state = 'disabled'
        Get-SIRiskFactorClass $f | Should -Be 'builtin'
        @(Test-SIRiskFactorModelV2 -Factor $f) -join ' ' | Should -Match 'cannot be disabled'
        Get-SIRiskFactorState $f | Should -Be 'enabled'
    }
    It 'a short name with an editable number, or not PascalCase, is refused' {
        $f = Copy-Factor $script:ById['stale_sign_in']; $f.shortName = 'NoSignIn90d'
        @(Test-SIRiskFactorModelV2 -Factor $f) -join ' ' | Should -Match 'number'
        $f.shortName = 'no sign-in'
        @(Test-SIRiskFactorModelV2 -Factor $f) -join ' ' | Should -Match 'PascalCase'
    }
    It 'Test-SIDataModel carries the v2 checks (a customer override is held to them)' {
        $m = Copy-Model
        ($m['risk-factors'].factors | Where-Object { $_.id -eq 'no_mfa' }).impact = 9
        (@(Test-SIDataModel -Model $m) -join ' ') | Should -Match 'risk-factors/no_mfa: impact'
    }
    It 'break_glass_patterns: glob patterns only, never wildcards only' {
        Test-SIBreakGlassPattern -Pattern '*break*glass*' | Should -BeNullOrEmpty
        Test-SIBreakGlassPattern -Pattern 'bg-*@contoso.com' | Should -BeNullOrEmpty
        @(Test-SIBreakGlassPattern -Pattern '*') -join ' ' | Should -Match 'wildcards only'
        @(Test-SIBreakGlassPattern -Pattern '*?*') -join ' ' | Should -Match 'wildcards only'
        @(Test-SIBreakGlassPattern -Pattern '(?i)break') -join ' ' | Should -Match 'letters, digits'
        $m = Copy-Model
        ($m['lists'].lists | Where-Object { $_.id -eq 'break_glass_patterns' }).values = @('*', 'ok-*')
        (@(Test-SIDataModel -Model $m) -join ' ') | Should -Match 'break_glass_patterns'
        [string](@($script:Model['lists'].lists | Where-Object { $_.id -eq 'break_glass_patterns' })[0].type) | Should -Be 'values'
    }
}

Describe '3. the engine and the catalog agree' {
    It 'Get-RAFactorMeta == Get-SIRiskFactorShortName / -Side / -Impact / -State on every shipped factor (and on a disabled optional one)' {
        $set = @($script:Factors) + @((Copy-Factor $script:ById['old_account']) | ForEach-Object { $_.state = 'disabled'; $_ })
        foreach ($f in $set) {
            $m = Get-RAFactorMeta $f
            $m.ShortName | Should -Be (Get-SIRiskFactorShortName $f)
            $m.Side | Should -Be (Get-SIRiskFactorSide $f)
            $m.Impact | Should -Be (Get-SIRiskFactorImpact $f)
            $m.Enabled | Should -Be (Test-SIRiskFactorEnabled $f)
        }
    }
    It 'the legend rows are the same from both sides, asset factors first' {
        $a = @(Get-RARiskFactorLegendRows -Factors $script:Factors)
        $b = @(Get-SIRiskFactorLegend -Factors $script:Factors)
        ($a | ConvertTo-Json -Depth 4) | Should -Be ($b | ConvertTo-Json -Depth 4)
        $a.Count | Should -Be $script:Factors.Count
        $a[0].AppliesTo | Should -Be 'Asset'; $a[-1].AppliesTo | Should -Be 'Vulnerability'
        foreach ($c in 'ShortName', 'Description', 'AppliesTo', 'Impact') { $a[0].PSObject.Properties[$c] | Should -Not -BeNullOrEmpty }
    }
}

Describe '4. one row''s factors: once, on their side, with their impact' {
    BeforeAll { $script:Map = New-RAFactorImpactMap -Catalog ([pscustomobject]@{ factors = $script:Factors }) }
    It 'a catalog factor counts on its own side whatever column it came in; short names are shown' {
        $r = Measure-RARowFactors -AssetTokens @('Internet-Exposed', 'ExploitSignals') -VulnerabilityTokens @('PortOpenInternet') -Map $script:Map
        $r.AssetTokens | Should -Be @('InternetExposed', 'PortOpenInternet')
        $r.VulnerabilityTokens | Should -Be @('ExploitAvailable')
        $r.AssetImpact | Should -Be (4 + 5)
        $r.VulnerabilityImpact | Should -Be ([int]$script:ById['exploit_available'].impact)
    }
    It 'one factor under several names counts once' {
        $r = Measure-RARowFactors -AssetTokens @('RF_P_InternetExposed', 'InternetExposureSignal', 'internet_exposed', 'InternetExposed') -Map $script:Map
        $r.AssetImpact | Should -Be 4
        @($r.AssetTokens).Count | Should -Be 1
    }
    It 'an unknown report token keeps its column''s side and counts the report_scoped impact' {
        $r = Measure-RARowFactors -AssetTokens @('MultipleIPs') -VulnerabilityTokens @('DomainTakeoverPotential') -Map $script:Map
        $r.AssetImpact | Should -Be 1; $r.VulnerabilityImpact | Should -Be 1
        $r.AssetTokens | Should -Be @('MultipleIPs')
    }
    It 'a disabled optional factor adds nothing and is not shown; a retired break-glass token adds nothing' {
        $f2 = @($script:Factors | ForEach-Object { Copy-Factor $_ })
        ($f2 | Where-Object { $_.id -eq 'old_account' }).state = 'disabled'
        $m2 = New-RAFactorImpactMap -Catalog ([pscustomobject]@{ factors = $f2 })
        $r = Measure-RARowFactors -AssetTokens @('OldAccount', 'RF_P_BreakGlass') -Map $m2
        $r.AssetImpact | Should -Be 0
        @($r.AssetTokens).Count | Should -Be 0
    }
    It 'a number-only report: each unnamed factor counts the report_scoped impact on the asset side' {
        (Measure-RARowFactors -UnnamedAssetCount 3 -Map $script:Map).AssetImpact | Should -Be 3
    }
}

Describe '5. finding factors on the row''s SI fields' {
    It 'a field that holds raises its factor; an absent field is unknown and raises nothing' {
        $row = [pscustomobject]@{ si_exploit_verified = $true; si_cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; si_due_date = '2020-01-01T00:00:00Z' }
        $t = @(Get-RAFindingFactorTokens -Row $row -Factors $script:Factors)
        $t | Should -Contain 'KnownExploited'
        $t | Should -Contain 'NetworkNoUserAction'
        $t | Should -Contain 'Overdue'
        $t | Should -Not -Contain 'ExploitKit'      # si_in_exploit_kit absent -> unknown
        $t | Should -Not -Contain 'OldVuln'         # si_published absent -> unknown
        $t | Should -Not -Contain 'ZeroDay'
        @(Get-RAFindingFactorTokens -Row ([pscustomobject]@{ AssetName = 'x' }) -Factors $script:Factors).Count | Should -Be 0
    }
    It 'AV:N with user interaction is not NetworkNoUserAction; ZeroDay holds for no fix available' {
        $t = @(Get-RAFindingFactorTokens -Row ([pscustomobject]@{ si_cvss_vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H'; si_fix_available = $false }) -Factors $script:Factors)
        $t | Should -Not -Contain 'NetworkNoUserAction'
        $t | Should -Contain 'ZeroDay'
    }
}

Describe '6. a built-in factor is never switched off at run start' {
    It 'an override that disabled a built-in factor is re-enabled and said once' {
        $f = @($script:Factors | ForEach-Object { Copy-Factor $_ })
        ($f | Where-Object { $_.id -eq 'no_mfa' }).state = 'disabled'
        $r = Resolve-SIRiskFactorBuiltinState -Factors $f
        @($r.Lines).Count | Should -Be 1
        $r.Lines[0] | Should -Match 'NoMFA'
        [string](@($r.Factors | Where-Object { $_.id -eq 'no_mfa' })[0].state) | Should -Be 'enabled'
    }
}

Describe '8. the risk rating bands are data, not code' {
    It 'the shipped list risk_rating_bands is 50 / 30 / 15 (owner 2026-10-11) and validates; a bad list is refused' {
        $l = @($script:Model['lists'].lists | Where-Object { $_.id -eq 'risk_rating_bands' })[0]
        @($l.values | ForEach-Object { [int]$_ }) | Should -Be @(50, 30, 15)
        @(Test-SIRiskRatingBands -Model $script:Model) | Should -BeNullOrEmpty
        foreach ($bad in @(@(30, 60, 15), @(60, 30), @(60, 30, 0), @(60, 30, 'x'))) {
            $m = Copy-Model
            ($m['lists'].lists | Where-Object { $_.id -eq 'risk_rating_bands' }).values = $bad
            @(Test-SIRiskRatingBands -Model $m) -join ' ' | Should -Match 'risk_rating_bands' -Because ($bad -join ',')
        }
    }
    It 'the engine reads the bands from the list (a changed list moves the rating); an invalid list falls back to 50 / 30 / 15' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        ConvertTo-RARiskRatingBands ([pscustomobject]@{ values = @(80, 40, 20) }) | Should -Be @(80, 40, 20)
        ConvertTo-RARiskRatingBands ([pscustomobject]@{ values = @(20, 40, 80) }) | Should -BeNullOrEmpty
        Get-SIRiskRating -Score 70 -Bands @(80, 40, 20) | Should -Be 'High'
        Get-SIRiskRating -Score 70 -Bands @(60, 30, 15) | Should -Be 'Critical'
        $global:RA_RiskRatingBands = $null
        Get-RARiskRatingBands | Should -Be @(50, 30, 15)
        $global:RA_RiskRatingBands = $null
    }
}

Describe '7. break glass is a classification' {
    BeforeAll { $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model) } }
    It 'naming: a break-glass sign-in or display name classifies a user' {
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'breakglass01@contoso.com' } -Context $script:Ctx).IsBreakGlass | Should -BeTrue
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_display_name = 'Emergency Access Admin 2' } -Context $script:Ctx).IsBreakGlass | Should -BeTrue
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'john.doe@contoso.com'; si_display_name = 'John Doe' } -Context $script:Ctx).IsBreakGlass | Should -Not -BeTrue
    }
    It 'platform: an emergency-access group, or a permanent Tier 0 account excluded from ALL Conditional Access policies -- one excluding policy is not enough' {
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'a@contoso.com'; si_group_memberships = @('All staff', 'Emergency Access Accounts') } -Context $script:Ctx).Reasons | Should -Contain 'group'
        $r = Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'a@contoso.com'; si_ca_excluded_policies = @('Require MFA'); si_ca_excluded_from_all = $true; si_privilege_tier_permanent = 0 } -Context $script:Ctx
        $r.IsBreakGlass | Should -BeTrue; $r.Reasons | Should -Contain 'ca_excluded_from_all'
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'a@contoso.com'; si_ca_excluded_from_all = $true } -Context $script:Ctx).IsBreakGlass | Should -Not -BeTrue -Because 'excluded from all policies makes only a permanent Tier 0 account break-glass'
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'a@contoso.com'; si_ca_excluded_policies = @('Require MFA'); si_privilege_tier_permanent = 0 } -Context $script:Ctx).IsBreakGlass | Should -Not -BeTrue -Because 'excluded from one policy is context, not break-glass -- even with a permanent Tier 0 role'
    }
    It 'the provider''s value is kept; unknown fields never classify; a device is never classified' {
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_is_break_glass = $true } -Context $script:Ctx).Reasons | Should -Contain 'provider'
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'breakglass@contoso.com'; si_unknown_fields = @('si_upn') } -Context $script:Ctx).IsBreakGlass | Should -Not -BeTrue
        (Get-SIBreakGlassClassification -Ci @{ si_class = 'device'; si_asset_name = 'breakglass-pc' } -Context $script:Ctx).IsBreakGlass | Should -BeNullOrEmpty
    }
    It 'Set-SICiBreakGlass sets si_is_break_glass and its reasons, and never a risk factor' {
        $ci = [ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'bg-admin@contoso.com' }
        $null = Set-SICiBreakGlass -Ci $ci -Context $script:Ctx
        $ci['si_is_break_glass'] | Should -BeTrue
        @($ci['si_break_glass_reasons']) | Should -Contain 'naming:si_upn'
        $ci.Contains('si_risk_factors') | Should -BeFalse
    }
    It 'the CI build classifies before the tier rules (both the serial and the parallel path)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        @([regex]::Matches($src, 'Set-SICiBreakGlass -Ci \$ci[^\r\n]*\r?\n\s*\$null = Invoke-SICiRules')).Count | Should -Be 2
    }
}
