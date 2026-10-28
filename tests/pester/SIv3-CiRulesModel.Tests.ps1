#Requires -Version 5.1
<#
    THE GENERIC ENRICHMENT RULE MODEL ON THE CI (#462, V3-DATA-MODEL 2.8 / 2.19.2) -- engine/data-model/SI-CiRules.ps1 and
    the Invoke-SICiRules additions. Offline: scratch rule packs, a CI document in hand; nothing reads a provider.

      * NATIVE RULES: the design's own shape (when over SI fields, closed operations; set over SI fields) converts to the CI
        rule shape; a provider column or an unknown operation is refused; the override grain is one rule (custom replaces a
        shipped id, the overlay wins, not_used turns it off); an invalid rule is skipped and said.
      * ASSET TAGGING: the tagging engine's auto-exclusion tags as a native pack -- its AutoExcludeRules switches and the
        device-name patterns are honoured; the shipped pack tags a CI.
      * TWO TRUTH STAGES: a rule file's `stage: testing` reaches the CI rule (it was dropped before #462): recorded, never
        deciding, its effect a PROPOSAL beside the value.
      * PRIORITY: a single-value field takes the highest-priority deciding rule; equal priorities keep the order before.
      * TRACE: every claim carries its priority, pack, the evidence values with their provider, and what a non-deciding
        claim would have set.
      * OVERRIDES: a manual override wins over the rules (si_tier_set_by = override), is listed on the CI, expires.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-10T06:00:00', 'Utc')
    $script:Roots = New-Object System.Collections.Generic.List[string]
    function script:New-Root {
        $r = Join-Path ([IO.Path]::GetTempPath()) ('si462-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Force (Join-Path $r 'data-model\rules') | Out-Null
        $script:Roots.Add($r); $r
    }
    function script:Put([string]$Path, [string[]]$Lines) {
        $d = Split-Path -Parent $Path; if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null }
        [IO.File]::WriteAllText($Path, ($Lines -join "`r`n") + "`r`n")
    }
    function script:Ci([hashtable]$f) {
        $c = [ordered]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_asset_name = 'srv01'; si_field_sources = [ordered]@{} }
        foreach ($k in $f.Keys) { $c[$k] = $f[$k]; $c['si_field_sources'][$k] = [ordered]@{ provider = 'mde'; record = 'mde|device|1'; observed_at = $script:Now.AddHours(-1); stale = $false } }
        $c
    }
    function script:Enrich($ci, $rules, $ov) { $null = Invoke-SICiEnrichment -Cis @($ci) -Model $script:Model -Rules @($rules) -Now $script:Now -Overrides $ov; $ci }
    function script:RuleObj([string]$id, [string]$stage = 'production', [int]$prio = 100, [int]$tier = 2, [string]$purpose = '', [string]$pattern = '(?i)^srv') {
        $set = @{ Tier = $tier }; if ($purpose) { $set['Purpose'] = $purpose }
        [pscustomobject]@{ Id = $id; AppliesTo = 'endpoint'; Mode = 'locked'; osPlatformScope = @(); Purpose = $null; Category = $null; Description = $id
            Detections = @([pscustomobject]@{ Id = 'd1'; Detect = @{ any = @(@{ kind = 'nameMatches'; namePatterns = @($pattern) }) }; Set = $set; ExcludeAssets = @() })
            File = "endpoint\AssetProfileByDeviceType\$id.locked.yaml"; Folder = 'asset-profiling-enrichment'; Source = 'tree'; Fallback = $false; Stage = $stage; Priority = $prio }
    }
}

AfterAll { foreach ($r in $script:Roots) { Remove-Item -Recurse -Force $r -ErrorAction SilentlyContinue } }

Describe 'Native rules: the design shape over SI fields' {
    It 'converts groups, operations, a list (in) and a single value (eq)' {
        $w = [ordered]@{ any = @([ordered]@{ si_device_roles = [ordered]@{ contains = 'domain_controller' } }, [ordered]@{ si_os_platform = @('windows_server', 'linux') }, [ordered]@{ si_asset_name = 'dc01' }) }
        $c = ConvertTo-SICiNativeCondition -When $w -RuleId 'r'
        @($c.any).Count | Should -Be 3
        $c.any[0].op | Should -Be 'contains'; $c.any[1].op | Should -Be 'in'; $c.any[2].op | Should -Be 'eq'
        Test-SICondition $c @{ si_os_platform = 'linux' } | Should -BeTrue
        Test-SICondition $c @{ si_device_roles = @('domain_controller') } | Should -BeTrue
        Test-SICondition $c @{ si_asset_name = 'web01' } | Should -BeFalse
    }
    It 'refuses a provider column and an operation outside the closed set' {
        { ConvertTo-SICiNativeCondition -When ([ordered]@{ isInternetFacing = $true }) -RuleId 'r' } | Should -Throw '*not an SI field*'
        { ConvertTo-SICiNativeCondition -When ([ordered]@{ si_asset_name = [ordered]@{ script = 'x' } }) -RuleId 'r' } | Should -Throw '*not a condition operation*'
    }
    It 'a pack loads; a custom rule with a shipped id replaces it, the overlay wins, not_used turns one off, an invalid rule is skipped and said' {
        $r = New-Root
        Put (Join-Path $r 'data-model\rules\Roles.locked.yaml') @('rules:', '  - id: dc', '    applies_to: [device]', '    when:', '      any:', '        - si_device_roles:', '            contains: domain_controller', '    set:', '      si_tier: 0', '      si_purpose: Domain controller',
            '  - id: web', '    when:', '      any:', '        - si_asset_name:', '            like: "web*"', '    set:', '      si_tier: 2',
            '  - id: bad', '    when:', '      any:', '        - DeviceName:', '            eq: x', '    set:', '      si_tier: 1')
        Put (Join-Path $r 'data-model\rules\Roles.custom.yaml') @('rules:', '  - id: web', '    stage: not_used', '    when:', '      any:', '        - si_asset_name:', '            like: "web*"', '    set:', '      si_tier: 2',
            '  - id: dc', '    priority: 300', '    when:', '      any:', '        - si_device_roles:', '            contains: domain_controller', '    set:', '      si_tier: 1')
        $ov = Join-Path $r 'overlay'
        Put (Join-Path $ov 'rules\Roles.custom.yaml') @('rules:', '  - id: dc', '    priority: 500', '    when:', '      any:', '        - si_device_roles:', '            contains: domain_controller', '    set:', '      si_tier: 0')
        $n = Get-SICiNativeRules -Root $r -OverlayRoot $ov 3>$null
        @($n.Problems | Where-Object { $_ -match 'DeviceName' }).Count | Should -Be 1
        $dc = @($n.Rules | Where-Object { $_.id -eq 'dc' })[0]
        $dc.priority | Should -Be 500 -Because 'the overlay outranks the custom file beside the shipped one'
        $dc.set['si_tier'] | Should -Be 0
        $dc.pack | Should -Be 'Roles'
        @($n.Rules | Where-Object { $_.id -eq 'web' })[0].stage | Should -Be 'not_used'
        @($n.Rules | Where-Object { $_.id -eq 'bad' }).Count | Should -Be 0
    }
    It 'a native rule decides on a CI like a converted one' {
        $rule = ConvertTo-SICiNativeRule -Item ([ordered]@{ id = 'dc'; applies_to = @('device'); mechanism = 'eg.graph_field'; when = [ordered]@{ any = @([ordered]@{ si_device_roles = [ordered]@{ contains = 'domain_controller' } }) }; set = [ordered]@{ si_tier = 0; si_purpose = 'Domain controller'; si_tags = @('AD-Tier0') } }) -Pack 'Roles'
        $ci = Enrich (Ci @{ si_device_roles = @('domain_controller') }) @($rule) $null
        $ci['si_tier'] | Should -Be 0
        $ci['si_purpose'] | Should -Be 'Domain controller'
        @($ci['si_tags'] | Where-Object { $_.name -eq 'AD-Tier0' -and $_.source -eq 'rule' }).Count | Should -Be 1
    }
    It 'a rule with TWO values in applies_to / os_scope / exclude / si_tags keeps them as two values (a Pro override may carry several)' {
        $rule = ConvertTo-SICiNativeRule -Item ([ordered]@{ id = 'two'; applies_to = @('device', 'identity'); os_scope = @('Windows', 'Linux'); exclude = @('lab-*', 'test-*')
                when = [ordered]@{ any = @([ordered]@{ si_device_roles = [ordered]@{ contains = 'domain_controller' } }) }; set = [ordered]@{ si_tags = @('AD-Tier0', 'Crown-Jewel') } }) -Pack 'Roles'
        @($rule.classes) | Should -Be @('device', 'identity')
        @($rule.osScope) | Should -Be @('windows', 'linux')
        @($rule.exclude) | Should -Be @('lab-*', 'test-*')
        @($rule.set['si_tags']) | Should -Be @('AD-Tier0', 'Crown-Jewel')
        $ci = Enrich (Ci @{ si_device_roles = @('domain_controller') }) @($rule) $null
        @($ci['si_tags'] | Where-Object { $_.source -eq 'rule' } | ForEach-Object { $_.name }) | Sort-Object | Should -Be @('AD-Tier0', 'Crown-Jewel')
        # the SECOND exclude pattern excludes on its own
        $c2 = Ci @{ si_device_roles = @('domain_controller') }; $c2['si_asset_name'] = 'test-01'
        $c2 = Enrich $c2 @($rule) $null
        @($c2['si_tags'] | Where-Object { $_.source -eq 'rule' }).Count | Should -Be 0
    }
}

Describe 'AssetTagging expressed in the model' {
    It 'the shipped pack loads; with NO tagging config every exclusion rule is off and no CI is tagged excluded (#643)' {
        # a root without config\asset-tagging.config.json: the shipped default, as at an install that never set a switch
        $r = New-Root
        Copy-Item (Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml') (Join-Path $r 'data-model\rules\AssetTagging.locked.yaml')
        $saved = $global:SI_ProConfigRoot
        try {
            $global:SI_ProConfigRoot = $null
            $all = Get-SICiAllNativeRules -Root $r -OverlayRoot '' 3>$null
        } finally { $global:SI_ProConfigRoot = $saved }
        @($all.Problems).Count | Should -Be 0
        $at = @($all.Rules | Where-Object { $_.pack -eq 'AssetTagging' })
        $at.Count | Should -Be 4
        foreach ($x in $at) { $x.stage | Should -Be 'not_used' -Because ("{0} writes an EXCLUSION tag: nobody chose it, so it never runs (the engine and the GUI read a missing switch as off)" -f $x.id) }
        $ci = Enrich (Ci @{ si_onboarding_status = 'can_be_onboarded' }) $at $null
        @($ci['si_tags'] | Where-Object { $_.name -like '*--Excluded--SI' }).Count | Should -Be 0 -Because 'a device Defender can onboard is NOT excluded unless the customer chose that'
    }
    It 'a switch tags ONLY when it is true: missing, false or not a boolean = off; true (or "true") = on, and an onboarded CI is never tagged' {
        $raw = @{}; foreach ($it in (Get-SIValueList (Get-SIItemValue (ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml')))) 'rules'))) { $raw[[string]$it.id] = $it }
        $fresh = { @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' }) }
        $stage = { param($cfg) @(Get-SIAssetTaggingCiRules -Rules (& $fresh) -Config $cfg -RawItems $raw -Enabled $true | Where-Object { $_.id -eq 'asset-tagging/can-be-onboarded' })[0].stage }
        & $stage $null | Should -Be 'not_used' -Because 'no config file'
        & $stage ([pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeInsufficientInfo = $true } }) | Should -Be 'not_used' -Because 'the switch is missing'
        & $stage ([pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = $false } }) | Should -Be 'not_used'
        & $stage ([pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = 'maybe' } }) | Should -Be 'not_used' -Because 'not a boolean: fail closed, like the tagging engine'
        & $stage ([pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = 'true' } }) | Should -Be 'production'
        $on = @(Get-SIAssetTaggingCiRules -Rules (& $fresh) -Config ([pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = $true } }) -RawItems $raw -Enabled $true)
        @($on | Where-Object { $_.id -eq 'asset-tagging/can-be-onboarded' })[0].stage | Should -Be 'production'
        @($on | Where-Object { $_.id -eq 'asset-tagging/insufficient-info' })[0].stage | Should -Be 'not_used' -Because 'each switch stands alone'
        $ci = Enrich (Ci @{ si_onboarding_status = 'can_be_onboarded' }) $on $null
        @($ci['si_tags'] | Where-Object { $_.name -eq 'Auto-CanBeOnboarded--Excluded--SI' }).Count | Should -Be 1 -Because 'the customer chose to exclude the devices Defender can onboard'
        $ci2 = Enrich (Ci @{ si_onboarding_status = 'onboarded' }) $on $null
        @($ci2['si_tags'] | Where-Object { $_.name -like 'Auto-*' }).Count | Should -Be 0
    }
    It 'the tagging switches and device-name patterns apply' {
        $all = Get-SICiAllNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null
        $raw = @{}; foreach ($it in (Get-SIValueList (Get-SIItemValue (ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml')))) 'rules'))) { $raw[[string]$it.id] = $it }
        $cfg = [pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = $false; ExcludeByDeviceNamePattern = $true }
                                  DeviceNamePatterns = [pscustomobject]@{ StartsWith = @('desktop-'); Contains = @(); MatchesRegex = @('^kiosk\d+$') } }
        $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
        $r = @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $cfg -RawItems $raw -Enabled $true)
        @($r | Where-Object { $_.id -eq 'asset-tagging/can-be-onboarded' })[0].stage | Should -Be 'not_used'
        $np = @($r | Where-Object { $_.id -eq 'asset-tagging/name-pattern' })[0]
        $np.stage | Should -Be 'production'
        $ci = Enrich (Ci @{ si_onboarding_status = 'can_be_onboarded' }) $r $null
        $ci['si_asset_name'] = 'desktop-42'; $ci = Enrich $ci $r $null
        @($ci['si_tags'] | Where-Object { $_.name -eq 'Auto-NamePattern--Excluded--SI' }).Count | Should -Be 1
        @($ci['si_tags'] | Where-Object { $_.name -eq 'Auto-CanBeOnboarded--Excluded--SI' }).Count | Should -Be 0 -Because 'its switch is off'
    }
    It 'the setting "Asset tagging" (SI_AssetTagging_Enabled): only a real true turns it on (#643, off by default)' {
        foreach ($v in @($null, '', $false, 'false', '0', 'no', 'maybe')) { Test-SIAssetTaggingEnabled -Value $v | Should -BeFalse -Because "value '$v'" }
        foreach ($v in @($true, 'true', 'True', '$true', '1')) { Test-SIAssetTaggingEnabled -Value $v | Should -BeTrue -Because "value '$v'" }
    }
    It 'asset tagging OFF: every rule of the pack is not_used whatever its switch says, and its tags are marked to be taken off' {
        $raw = @{}; foreach ($it in (Get-SIValueList (Get-SIItemValue (ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml')))) 'rules'))) { $raw[[string]$it.id] = $it }
        $cfg = [pscustomobject]@{ AutoExcludeRules = [pscustomobject]@{ ExcludeCanBeOnboarded = $true; ExcludeInsufficientInfo = $true; ExcludeUnsupported = $true; ExcludeByDeviceNamePattern = $true }
                                  DeviceNamePatterns = [pscustomobject]@{ StartsWith = @('desktop-'); Contains = @(); MatchesRegex = @() } }
        foreach ($en in @($null, $false, 'false')) {
            $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
            $r = @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $cfg -RawItems $raw -Enabled $en)
            $r.Count | Should -Be 4
            foreach ($x in $r) { $x.stage | Should -Be 'not_used' -Because ("{0} with the setting '{1}'" -f $x.id, $en); [bool]$x.strip_tags | Should -BeTrue }
            $names = Get-SITaggingRuleTagNames -Rules $r
            foreach ($n in 'Auto-CanBeOnboarded--Excluded--SI', 'Auto-InsufficientInfo--Excluded--SI', 'Auto-Unsupported--Excluded--SI', 'Auto-NamePattern--Excluded--SI') { $names.Contains($n) | Should -BeTrue -Because $n }
        }
        # the default comes from the global setting: not set = off
        $saved = $global:SI_AssetTagging_Enabled
        try {
            Remove-Variable -Name SI_AssetTagging_Enabled -Scope Global -ErrorAction SilentlyContinue
            $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
            @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $cfg -RawItems $raw | Where-Object { $_.stage -ne 'not_used' }).Count | Should -Be 0
            $global:SI_AssetTagging_Enabled = $true
            $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
            @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $cfg -RawItems $raw | Where-Object { $_.id -eq 'asset-tagging/can-be-onboarded' })[0].stage | Should -Be 'production'
        } finally { if ($null -eq $saved) { Remove-Variable -Name SI_AssetTagging_Enabled -Scope Global -ErrorAction SilentlyContinue } else { $global:SI_AssetTagging_Enabled = $saved } }
    }
    It 'asset tagging OFF: a tagging-rule tag a provider brings back (an earlier run wrote it to Defender) is taken off the CI; the customer''s own exclusion tag stays' {
        $raw = @{}; foreach ($it in (Get-SIValueList (Get-SIItemValue (ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\rules\AssetTagging.locked.yaml')))) 'rules'))) { $raw[[string]$it.id] = $it }
        $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
        $off = @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $null -RawItems $raw -Enabled $false)
        $ci = Ci @{ si_onboarding_status = 'can_be_onboarded' }
        $ci['si_tags'] = @([ordered]@{ source = 'mde'; name = 'Auto-CanBeOnboarded--Excluded--SI'; value = '' }, [ordered]@{ source = 'mde'; name = 'Lab--Excluded--SI'; value = '' }, [ordered]@{ source = 'mde'; name = 'Prod'; value = '' })
        $ci = Enrich $ci $off $null
        @($ci['si_tags'] | ForEach-Object { $_.name }) | Sort-Object | Should -Be @('Lab--Excluded--SI', 'Prod')
        # ON: the same provider tag is kept (the customer chose tagging; the rule's own tag is the rule's decision)
        $fresh = @((Get-SICiNativeRules -Root $script:SIRoot -OverlayRoot '' 3>$null).Rules | Where-Object { $_.pack -eq 'AssetTagging' })
        $on = @(Get-SIAssetTaggingCiRules -Rules $fresh -Config $null -RawItems $raw -Enabled $true)
        $ci2 = Ci @{ si_onboarding_status = 'onboarded' }
        $ci2['si_tags'] = @([ordered]@{ source = 'mde'; name = 'Auto-CanBeOnboarded--Excluded--SI'; value = '' })
        $ci2 = Enrich $ci2 $on $null
        @($ci2['si_tags'] | Where-Object { $_.name -eq 'Auto-CanBeOnboarded--Excluded--SI' }).Count | Should -Be 1
    }
}

Describe 'Two truth stages, priority and the trace' {
    It 'a rule file''s stage: testing reaches the CI rule -- recorded, never deciding, its effect a proposal' {
        $root = New-Root
        Put (Join-Path $root 'asset-profiling-enrichment\endpoint\T1.locked.yaml') @('id: T1', 'appliesTo: endpoint', 'mode: locked', 'stage: testing', 'priority: 250', 'detections:', '  - id: d1', '    detect:', '      any:', '        - kind: nameMatches', '          namePatterns:', "            - '(?i)^srv'", '    set:', '      Tier: 0')
        function Write-SIInfo { param($m) }
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
        $all = Get-SIRuleSet -Engine endpoint -SolutionRootOverride $root 3>$null; $rs = @($all)   # one array object: assigned, then enumerated
        $rs[0].Stage | Should -Be 'testing'
        $rs[0].Priority | Should -Be 250
        $rules = @((ConvertTo-SICiRules -RuleSet @($rs + (RuleObj 'P1' -tier 2))).Rules)
        @($rules | Where-Object { $_.id -eq 'T1/d1' })[0].stage | Should -Be 'testing'
        $ci = Enrich (Ci @{}) $rules $null
        $ci['si_tier'] | Should -Be 2 -Because 'the testing rule never decides'
        $p = @($ci['si_rule_proposals'] | Where-Object { $_.field -eq 'si_tier' })
        $p.Count | Should -Be 1
        $p[0].rule | Should -Be 'T1/d1'; $p[0].proposed | Should -Be 0; $p[0].current | Should -Be 2; $p[0].reason | Should -Be 'stage: testing'
        $tc = @($ci['si_tier_claims'] | Where-Object { $_.rule -eq 'T1/d1' })[0]
        $tc.would_set['si_tier'] | Should -Be 0
        $tc.priority | Should -Be 250
    }
    It 'a single-value field takes the highest-priority deciding rule; equal priorities keep the order before' {
        $hi = RuleObj 'Late' -prio 300 -tier 2 -purpose 'from the priority rule'
        $lo = RuleObj 'Early' -prio 100 -tier 1 -purpose 'from the tier winner'
        $ci = Enrich (Ci @{}) @((ConvertTo-SICiRules -RuleSet @($lo, $hi)).Rules) $null
        $ci['si_tier'] | Should -Be 1 -Because 'tier is MIN over the deciding claims, never priority'
        $ci['si_purpose'] | Should -Be 'from the priority rule'
        $eq = RuleObj 'Late2' -prio 100 -tier 2 -purpose 'not the winner'
        $ci2 = Enrich (Ci @{}) @((ConvertTo-SICiRules -RuleSet @($lo, $eq)).Rules) $null
        $ci2['si_purpose'] | Should -Be 'from the tier winner' -Because 'equal priority: the winning tier claim first, as before #462'
    }
    It 'the trace carries the pack and the evidence values with their provider' {
        $ci = Enrich (Ci @{ si_device_roles = @('domain_controller') }) @((ConvertTo-SICiRules -RuleSet @(RuleObj 'Dt')).Rules) $null
        $c = @($ci['si_tier_claims'])[0]
        $c.pack | Should -Be 'AssetProfileByDeviceType'
        $ev = @($c.evidence_detail | Where-Object { $_.field -eq 'si_asset_name' })
        $ev[0].value | Should -Be 'srv01'
    }
}

Describe 'Manual CI overrides (precedence 1)' {
    It 'a tier override wins over the rules, says who and why, and is listed; the rules'' claim stays in the trace' {
        $idx = ConvertTo-SICiOverrideIndex -Rows @([pscustomobject]@{ CiId = 'CI-1'; Field = 'si_tier'; Value = '0'; Reason = 'crown jewel'; SetBy = 'admin@x'; SetAt = $script:Now; ExpiresAt = $null }) -Now $script:Now
        $ci = Enrich (Ci @{}) @((ConvertTo-SICiRules -RuleSet @(RuleObj 'Dt' -tier 2)).Rules) $idx
        $ci['si_tier'] | Should -Be 0
        $ci['si_tier_set_by'] | Should -Be 'override'
        $ci['si_tier_reason'] | Should -Match 'admin@x.*crown jewel'
        @($ci['si_overrides'])[0].rules_value | Should -Be 2
        @($ci['si_tier_claims'] | Where-Object { $_.winner }).Count | Should -Be 0
        @($ci['si_tier_claims']).Count | Should -Be 1
    }
    It 'an expired override, a field that may not be overridden and an invalid tier are ignored' {
        $rows = @([pscustomobject]@{ CiId = 'ci-1'; Field = 'si_tier'; Value = '0'; Reason = 'old'; SetBy = 'a'; ExpiresAt = $script:Now.AddDays(-1) }
                  [pscustomobject]@{ CiId = 'ci-1'; Field = 'si_lifecycle'; Value = 'retired'; Reason = 'no'; SetBy = 'a'; ExpiresAt = $null }
                  [pscustomobject]@{ CiId = 'ci-1'; Field = 'si_cmdb_owner'; Value = 'Team A'; Reason = 'known'; SetBy = 'a'; ExpiresAt = $null })
        $idx = ConvertTo-SICiOverrideIndex -Rows $rows -Now $script:Now
        @($idx['ci-1']).Count | Should -Be 1
        $ci = Enrich (Ci @{}) @((ConvertTo-SICiRules -RuleSet @(RuleObj 'Dt' -tier 2)).Rules) $idx
        $ci['si_tier'] | Should -Be 2
        $ci['si_cmdb_owner'] | Should -Be 'Team A'
        $bad = ConvertTo-SICiOverrideIndex -Rows @([pscustomobject]@{ CiId = 'ci-1'; Field = 'si_tier'; Value = '9'; Reason = 'x'; SetBy = 'a' }) -Now $script:Now
        (Enrich (Ci @{}) @((ConvertTo-SICiRules -RuleSet @(RuleObj 'Dt' -tier 2)).Rules) $bad)['si_tier'] | Should -Be 2
    }
    It 'the override read answers no rows on a database without the table (it is guarded, never an error)' {
        Get-SICiOverrideReadSql | Should -Match "IF OBJECT_ID\('sidata.CiOverride'\) IS NULL"
        Get-SICiOverrideReadSql | Should -Match 'ExpiresAt IS NULL OR ExpiresAt > SYSUTCDATETIME\(\)'
    }
}
