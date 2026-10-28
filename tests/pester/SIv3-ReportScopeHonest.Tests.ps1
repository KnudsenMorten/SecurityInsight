#Requires -Version 5.1
<#
    #643 -- EVERY REPORT FOLLOWS ITS DECLARED SCOPE, NOTHING NARROWS IT IN SECRET (owner 2026-10-13, "Follow scope 0-3":
    "we can NOT loose data ... they would simply go into defender and if they can find things there, which is not in SI
    then they dont trust it").

      * Device_Missing_CVEs_Detailed has NO tier filter of its own: the hidden Detailed-only default dynamic([0, 1, 2])
        (v2.2.218) dropped 174,289 of 184,313 CVE rows at a large install. The report's declared scope is tiers 0-3.
      * Endpoint_ActiveCompromise_Detected_* report a compromised device of EVERY tier (they kept tiers 0-1 only and
        dropped a device without a tier, although they declare 0-3).
      * A NULL TIER (a device not profiled yet) is never decided in the query: it passes, the engine gives it the tier the
        rules give it (Set-RAUnprofiledTiers) and only then applies the declared scope -- the same answer as once it has
        that tier. The CI scope predicate keeps a null tier for the same reason.
      * THE SWEEP: every remaining `where` on a tier, and every take / limit / sample / top in the shipped catalog, is on a
        reviewed list with the reason it is the report's own declared question -- a new one fails here until it is
        reviewed.
    Offline: reads the shipped YAML with SecurityInsight's own reader (as the engine loads it); nothing runs a query.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DisabledAssets.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')
    # the vulnerability loop is Pro: its reader is loaded only where Test-Path finds it (the Community copy skips that case)
    $script:VulnDesired = Join-Path $script:SIRoot 'engine\asset-cmdb\_shared\SI-VulnDesired.ps1'
    $script:HasVulnLoop = Test-Path -LiteralPath $script:VulnDesired
    if ($script:HasVulnLoop) { . $script:VulnDesired }
    $script:Path = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Text = [IO.File]::ReadAllText($script:Path)
    $script:Catalog = ConvertFrom-SIYaml -Yaml $script:Text -SourceName $script:Path
    $script:Reports = @($script:Catalog.Reports)
    function script:QueryOf($r) { (@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n" }
    function script:Report([string]$Name) { @($script:Reports | Where-Object { [string]$_.ReportName -eq $Name })[0] }
    # the report's own KQL with the engine-generated blocks left out (the scope block and the CI blocks are rewritten by
    # the engine from the declared scope -- RA-ScopePreamble.ps1 / RA-CiKql.ps1 -- and are tested there)
    function script:OwnLines($r) {
        $out = New-Object System.Collections.Generic.List[string]
        $skip = $false
        foreach ($l in ((QueryOf $r) -split "`r?`n")) {
            if ($l -match '//__(SI_SCOPE|SI_CI_LINK|SI_CI_ASSET)_BEGIN__') { $skip = $true; continue }
            if ($l -match '//__(SI_SCOPE|SI_CI_LINK|SI_CI_ASSET)_END__') { $skip = $false; continue }
            if (-not $skip) { $out.Add($l) }
        }
        $out.ToArray()
    }
}

Describe 'the Detailed CVE report follows its declared scope (tiers 0-3)' {
    It 'the shipped YAML, loaded as the engine loads it, has no hidden tier default on Device_Missing_CVEs_Detailed' {
        $r = Report 'Device_Missing_CVEs_Detailed'
        $r | Should -Not -BeNullOrEmpty
        $q = QueryOf $r
        $q | Should -Not -Match '_AssetTierFilter'
        $q | Should -Not -Match '__ASSET_TIER_FILTER'
        $q | Should -Not -Match 'dynamic\(\[\s*0\s*,\s*1\s*,\s*2\s*\]\)' -Because 'tiers 0-2 anywhere in the query is the hidden filter coming back'
        @($r.CriticalityTierLevelScope) | Should -Be @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
        $q | Should -Match 'let SI_ScopeTiers = dynamic\(\[0, 1, 2, 3\]\);'
    }
    It 'the whole catalog carries no _AssetTierFilter (the marker the vulnerability loop reads as a report''s tier restriction)' {
        $script:Text | Should -Not -Match '_AssetTierFilter'
    }
    It 'the vulnerability loop reads no tier restriction from the shipped catalog -- no Tier 3 finding closes as out of scope' {
        if (-not $script:HasVulnLoop) { Set-ItResult -Skipped -Because 'the vulnerability loop is Pro and not in this copy'; return }
        Get-SIVulnReportTierFilter -Text $script:Text -ReportName 'Device_Missing_CVEs_Detailed' | Should -BeNullOrEmpty
        Get-SIVulnReportTierFilter -Text $script:Text -ReportName 'Device_Missing_CVEs_Summary' | Should -BeNullOrEmpty
    }
    It 'every severity is in the Detailed scope and the stale "Low excluded" note is gone' {
        $r = Report 'Device_Missing_CVEs_Detailed'
        @($r.SecuritySeverityScope) | Should -Contain 'Low'
        $script:Text | Should -Not -Match 'Low severity intentionally excluded from Detailed scope'
    }
}

Describe 'a null tier is handled as the tier it later gets' {
    It 'no report decides on a null tier in its own KQL: a missing tier is labelled with a scope label, never filtered' {
        foreach ($r in $script:Reports) {
            $own = (OwnLines $r) -join "`n"
            # a missing tier turned into a number is never compared in a where (#690 (15): outside the attack paths a missing
            # tier is no longer turned into a number at all -- pinned in SIv3-SeverityModel.Tests.ps1)
            # (the Tier 0 admin reports' own question -- the ADMIN is Tier 0 -- is on the reviewed list of the sweep below)
            if ($own -match 'coalesce\(si_tier,\s*\d+\)') {
                foreach ($l in (OwnLines $r)) {
                    $t = $l.Trim()
                    if ($t -notmatch '^\|\s*where\s+CriticalityTier\s*(<|<=|>|>=|==|!=|in)') { continue }
                    if ($r.ReportName -like 'Identity_Admin_LogonTo_LowTierDevice_*' -and $t -eq '| where CriticalityTier == 0') { continue }
                    $t | Should -BeNullOrEmpty -Because ("{0}: a missing tier became a number and a tier filter decided on it" -f $r.ReportName)
                }
            }
            # every case() that names the tier level falls back to BLANK (#690 (15), owner 2026-10-15: unknown is labelled,
            # never a silent default): a row without a tier is kept by the engine's post-filter (a blank passes it), gets the
            # tier the rules give it, and stays Unclassified when none does -- never "Low - tier 3". A label outside the
            # declared scope would be dropped, so blank is the only honest default. The attack-path reports are #690 (1)/(2)
            # (their target tier, the Microsoft content pack) and may still carry the old label until that fix.
            foreach ($m in [regex]::Matches($own, 'CriticalityTierLevel\s*=\s*case\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\)')) {
                $default = [regex]::Match(($m.Value -replace '\s+', ' '), ',\s*("[^"]*")\s*\)$').Groups[1].Value
                if ([string]$r.ReportName -like 'Attack_Paths*') {
                    $default | Should -BeIn @('""', '"Low - tier 3"') -Because ("{0}: a row without a tier keeps a label the scope filter keeps" -f $r.ReportName)
                } else {
                    $default | Should -Be '""' -Because ("{0}: a row without a tier is labelled blank (Unknown), never Low - tier 3" -f $r.ReportName)
                }
            }
        }
    }
    It 'the active-compromise reports keep a device without a tier and map all four tiers' {
        foreach ($n in 'Endpoint_ActiveCompromise_Detected_Summary', 'Endpoint_ActiveCompromise_Detected_Detailed') {
            $own = (OwnLines (Report $n)) -join "`n"
            $own | Should -Not -Match '\|\s*where\s+CriticalityTier\s*<=\s*1' -Because "$n declares tiers 0-3; Defender shows a compromised Tier 3 device"
            $own | Should -Match 'extend CriticalityTier = toint\(si_tier\)'
            $own | Should -Match 'CriticalityTier == 2, "Medium - tier 2"'
        }
    }
    It 'the CI scope predicate keeps a null tier when a report narrows its tiers (the engine resolves it before the declared scope)' {
        $p = Get-RAScopeCiPredicate -Active @{ IncludeDisabled = $true; Tiers = @(0, 1); Apply = @{ tier = $true }; ExcludedAssets = @(); ExcludedAssetTags = @(); ExcludedIpRanges = @() }
        $p | Should -Match 'isnull\(toint\(column_ifexists\("si_tier", int\(null\)\)\)\) or toint\(column_ifexists\("si_tier", int\(null\)\)\) in \(0, 1\)'
        Get-RAScopeTiers @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3') | Should -Be @(0, 1, 2, 3)
    }
    It 'the engine gives a tier-less Detailed row its tier BEFORE the declared-scope filter (the order the decision rests on)' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $iTier = $ra.IndexOf('Set-RAUnprofiledTiers -Rows $ResultFiltered')
        $iScope = $ra.IndexOf('@{ Name="CriticalityTierLevel"; Column=$CriticalityTierLevelInputName; Scope=$CriticalityTierLevelScope }')
        $iTier | Should -BeGreaterThan 0
        $iScope | Should -BeGreaterThan $iTier
    }
}

Describe 'THE SWEEP -- no hidden filter narrows a report below its declared scope' {
    BeforeAll {
        # every `where` on a tier in a report's OWN KQL, with why it is the report's declared question (not a scope cut)
        $script:TierFilterAllowed = @{
            'Identity_Admin_LogonTo_LowTierDevice_Summary|| where CriticalityTier == 0'  = 'the question: a Tier 0 ADMIN signing in to a device that is not Tier 0 (the name and the purpose say so)'
            'Identity_Admin_LogonTo_LowTierDevice_Detailed|| where CriticalityTier == 0' = 'the same question, per row'
            'Identity_Admin_LogonTo_LowTierDevice_Summary|| where isnull(DeviceCritLvl) or DeviceCritLvl > 0'  = 'the question: the DEVICE is not Tier 0 (a device without a tier is not a known PAW)'
            'Identity_Admin_LogonTo_LowTierDevice_Detailed|| where isnull(DeviceCritLvl) or DeviceCritLvl > 0' = 'the same, per row'
            'Identity_NewAccount_ImmediateTier0Role_Summary|| where si_privilege_tier_permanent == 0 or si_privilege_tier_eligible == 0 or si_tier == 0'  = 'the question: a new account that already holds a TIER 0 role (the name says so) -- #690 the role tier, or an account SI rates Tier 0'
            'Identity_NewAccount_ImmediateTier0Role_Detailed|| where si_privilege_tier_permanent == 0 or si_privilege_tier_eligible == 0 or si_tier == 0' = 'the same, per row'
            # #690 (19): the privileged-account reports select on the ROLE tier; the asset tier and an unknown tier (resolved by the
            # engine before the declared scope) keep every row the former CI tier cut kept -- never fewer rows
            'Identity_PrivilegedUser_StalePassword_Summary|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'  = 'the question: a privileged ROLE (Tier 0 / 1) -- or the account''s own Tier 0 / 1, as before'
            'Identity_PrivilegedUser_StalePassword_Detailed|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)' = 'the same, per row'
            # #690 (45): the privileged sign-in reports select a PRIVILEGED user -- an Entra role holder (Defender for Identity),
            # the CI's permanent privileged role, or the account's own Tier 0 / 1 (the purpose of both reports)
            'Identity_PrivilegedUser_SignIn_NonTrustedLocation_Summary|| where coalesce(HasEntraRole, false) or HasPermanentPrivilegedRole or toint(si_tier) in (0, 1)'  = 'the question: a privileged user (role holder, standing privileged role, or Tier 0 / 1)'
            'Identity_PrivilegedUser_SignIn_NonTrustedLocation_Detailed|| where coalesce(HasEntraRole, false) or HasPermanentPrivilegedRole or toint(si_tier) in (0, 1)' = 'the same, per row'
            'Identity_PrivilegedUser_NoConditionalAccess_Summary|| where coalesce(HasEntraRole, false) or set_has_element(coalesce(si_rf_p, dynamic([])), "permanent_privileged_role") or toint(si_tier) in (0, 1)'  = 'the question: a privileged user (role holder, standing privileged role, or Tier 0 / 1)'
            'Identity_PrivilegedUser_NoConditionalAccess_Detailed|| where coalesce(HasEntraRole, false) or set_has_element(coalesce(si_rf_p, dynamic([])), "permanent_privileged_role") or toint(si_tier) in (0, 1)' = 'the same, per row'
            'Identity_AdminAccount_OnPremSynced_Summary|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'     = 'the question: a privileged ROLE (Tier 0 / 1) -- or the account''s own Tier 0 / 1, as before'
            'Identity_AdminAccount_OnPremSynced_Detailed|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'    = 'the same, per row'
            'Identity_AdminAccount_NeverUsed_Summary|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'        = 'the question: a privileged ROLE (Tier 0 / 1) -- or the account''s own Tier 0 / 1, as before'
            'Identity_AdminAccount_NeverUsed_Detailed|| where _roleTier <= 1 or isnull(si_tier) or si_tier in (0, 1)'       = 'the same, per row'
            # #691: the lower-tier owner of a PRIVILEGED application -- the application's own CI tier is the question (Tier 0 / 1),
            # and the owner sits on a less critical tier than it (an owner without a tier is kept: not a known admin)
            'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal|| where si_tier in (0, 1)'  = 'the question: a privileged (Tier 0 / 1) application -- the name says so'
            'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal|| where si_tier in (0, 1)' = 'the same, per row'
            'Attack_Paths_Summary_Owner_to_Privileged_Service_Principal|| where isnull(SourceCriticalityTier) or SourceCriticalityTier > si_tier'  = 'the question: the OWNER is on a less critical tier than the application (or not tiered)'
            'Attack_Paths_Detailed_Owner_to_Privileged_Service_Principal|| where isnull(SourceCriticalityTier) or SourceCriticalityTier > si_tier' = 'the same, per row'
            'Endpoint_ConflictingTierTags_Summary|| where isnotempty(_tier)'  = 'the question: tier TAGS that conflict -- a tag without a tier is not one'
            'Endpoint_ConflictingTierTags_Detailed|| where isnotempty(_tier)' = 'the same, per row'
        }
        # every take / limit / sample / top in the shipped catalog: none may cut a report's RESULT
        $script:CapAllowed = @{
            'Azure_Recommendations_Summary|| top 1 by CollectionTime desc'  = 'picks the newest profile SNAPSHOT inside a lookup (one row per snapshot), never the findings'
            'Azure_Recommendations_Detailed|| top 1 by CollectionTime desc' = 'the same lookup'
        }
    }
    It 'every where on a tier in a report''s own KQL is a reviewed, declared question' {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            foreach ($l in (OwnLines $r)) {
                $t = $l.Trim()
                if ($t -match '^\|\s*where\b' -and $t -match '(?i)\b(CriticalityTier|si_tier|_tier|DeviceCritLvl|_AssetTierFilter)\b') { $found.Add(('{0}|{1}' -f $r.ReportName, $t)) }
            }
        }
        $unreviewed = @($found | Where-Object { -not $script:TierFilterAllowed.ContainsKey($_) })
        $unreviewed | Should -BeNullOrEmpty -Because 'a tier filter the report does not declare narrows it in secret (#643) -- remove it, or declare it and review it here'
    }
    It 'no take / limit / sample / top cuts a report''s result' {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            foreach ($l in (QueryOf $r) -split "`r?`n") {
                $t = $l.Trim()
                if ($t -match '^\|\s*(take|limit|sample)\b' -or $t -match '^\|\s*top\s+\d') { $found.Add(('{0}|{1}' -f $r.ReportName, $t)) }
            }
        }
        @($found | Where-Object { -not $script:CapAllowed.ContainsKey($_) }) | Should -BeNullOrEmpty
    }
    It 'every report that declares a tier scope carries the same tiers in its scope block' {
        foreach ($r in $script:Reports) {
            if (@($r.CriticalityTierLevelScope).Count -eq 0) { continue }
            $m = [regex]::Match((QueryOf $r), 'let\s+SI_ScopeTiers\s*=\s*dynamic\(\[([0-9,\s]*)\]\)')
            if (-not $m.Success) { continue }
            $block = @([regex]::Matches($m.Groups[1].Value, '\d') | ForEach-Object { [int]$_.Value })
            ($block -join ',') | Should -Be ((Get-RAScopeTiers @($r.CriticalityTierLevelScope)) -join ',') -Because $r.ReportName
        }
    }
    It 'the source-side CVE and stale-device filters are no-ops in the shipped YAML (they apply only when the customer sets them)' {
        foreach ($mk in 'CVE_FILTER', 'CVE_FILTER_TVM', 'STALE_DEVICE_FILTER', 'BUCKET_FILTER') {
            foreach ($m in [regex]::Matches($script:Text, ('//__{0}_BEGIN__(?<b>.*?)//__{0}_END__' -f $mk), 'Singleline')) {
                $m.Groups['b'].Value.Trim() | Should -Be '| where 1 == 1' -Because "$mk ships empty"
            }
        }
    }
}

Describe 'the exclusion tag means what it says (#643)' {
    It 'only the intended exclusion suffix excludes: the shipped list holds --Excluded--SI and nothing that matches a plain onboarding word' {
        $l = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\lists.locked.json') | ConvertFrom-Json
        $x = @($l.lists | Where-Object { $_.id -eq 'excluded_asset_tags' })[0]
        @($x.values) | Should -Be @('--Excluded--SI')
    }
    It 'the asset-tagging CI rules write an exclusion tag only when the customer switched that exclusion on' {
        $p = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiRules.ps1'))
        $p | Should -Not -Match 'no config file = the shipped default: on'
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml'))
        $y | Should -Not -Match 'no file = on'
        # the sample the customer starts from: every switch off
        $s = Get-Content -Raw (Join-Path $script:SIRoot 'config\asset-tagging.config.sample.json') | ConvertFrom-Json
        foreach ($k in 'ExcludeCanBeOnboarded', 'ExcludeInsufficientInfo', 'ExcludeUnsupported', 'ExcludeByDeviceNamePattern') { $s.AutoExcludeRules.$k | Should -BeFalse -Because $k }
    }
}
