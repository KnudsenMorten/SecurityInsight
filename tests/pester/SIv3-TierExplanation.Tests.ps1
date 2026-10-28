#Requires -Version 5.1
<#
    EVERY CI EXPLAINS ITS TIER (owner 2026-10-11: "i would love a column with this") -- and the wrong reasons seen on
    internal ring 1 the same day, fixed at the root:

      1. THE DEFECT. paw-pxj70zk58z (a PAW) was Tier 0 "Domain Controller"; mgmt1, dc1 and dc3 were Tier 0 "AD CS Server".
         183 shipped rule detections carried a bare machine-tag pattern '(?i)tier.?N' -- it matches EVERY operator tier tag
         (PAWDevices--tier0--SI, AutomationServer--tier0--SI, DomainControllerDNS--tier0--SI), so each tier-0 tag made the
         device a Domain Controller AND an AD CS server, as OBSERVED rules (the tag's own low priority was bypassed). And a
         claim was ranked by its rule's FIRST detection kind (installed software) instead of the evidence that matched (a
         tag), so the wrong rule also beat the real PAW rule at the same tier. Both fixed: the patterns are gone from the rule
         files and ignored by the converter; a claim's mechanism is the best-placed detection that matched.
      2. si_tier_explanation: one plain sentence -- the tier, who decided (SI rule + evidence / your tag / manual override
         with who, reason, expiry / the default), then "Also claimed: ..." with why each other claim lost.
      3. si_tier_claims reached Log Analytics only before the SI_CI_CL column contract (2026-10-09): it was never in
         $script:SICiPostFields. It is now, slim (the claims on the tier, what matched).
    Offline, PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Trust = Get-SICiTrustIndex $script:Model['trust']
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = [datetime]'2026-10-11T06:00:00Z' }
    $script:TagRules = @(ConvertTo-SICiTagTierRules -TagPattern '(?i)tier[_-]?(?<tier>[0-3])(--SI)?')
    $script:Mk = { param($id, $detect, $set, [bool]$fb, [string]$purpose)
        [pscustomobject]@{ Id = $id; AppliesTo = @('endpoint'); Mode = 'merge'; osPlatformScope = @(); Purpose = $purpose; Category = $null; Description = $id
            Detections = @([pscustomobject]@{ Id = $id; Detect = $detect; Set = $set; ExcludeAssets = @() }); File = "$id.yaml"; Folder = 'test'; Source = 'tree'; Fallback = $fb } }
    $kind = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'assetKind'; kinds = @('endpoint') }) }
    $script:Default = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'DefaultTier-endpoint' $kind @{ Tier = 3 } $true 'Default tier for devices'))).Rules)
    $script:Tag = { param($n, $src = 'mde') [ordered]@{ source = $src; name = $n; value = '' } }

    # the SHIPPED endpoint rules, converted exactly as the CI build does (Get-SICiRuleSetAll: the rules + the fallback)
    if (-not (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1') }
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Get-SIRuleSet.ps1')
    # the loader returns its rules as ONE array object (,$results): assigned first, then enumerated
    $all = Get-SIRuleSet -Engine endpoint 3>$null
    $fb = Get-SIRuleSet -Engine endpoint -Fallback 3>$null
    $set = @(@($all) + @($fb) | Where-Object { $_ })
    if ($set.Count -lt 100) { throw "the shipped endpoint rules did not load ($($set.Count))" }
    $script:Shipped = @(@((ConvertTo-SICiRules -RuleSet @($set)).Rules) + $script:TagRules)
    $script:ByClass = Get-SICiRulesByClass -Rules $script:Shipped
    $script:Run = { param($ci) $null = Invoke-SICiRules -Ci $ci -Rules $script:Shipped -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now -RulesByClass $script:ByClass -FieldCache @{}; $ci }
}

Describe '1. THE DEFECT (internal 2026-10-11): an operator tier tag no longer makes a device a Domain Controller or an AD CS server' {
    It 'the PAW (paw-pxj70zk58z, tags PAWDevices--tier0--SI + EmployeeWorkstations--tier3--SI) is Tier 0 by the PAW rule, not "Domain Controller"' {
        foreach ($os in 'windows', '') {   # also without an OS: the tag alone must not drag the server rules in
            $ci = & $script:Run ([ordered]@{ si_class = 'device'; si_os_platform = $os; si_asset_name = 'paw-pxj70zk58z'; si_hostname = 'paw-pxj70zk58z'
                    si_tags = @((& $script:Tag 'EmployeeWorkstations--tier3--SI'), (& $script:Tag 'PAWDevices--tier0--SI'), [ordered]@{ source = 'entra'; name = 'extensionAttribute6'; value = 'W365_PAW_Windows_Client_EntraJoined_Tier0_English' }) })
            $ci.si_tier | Should -Be 0
            $ci.si_tier_reason | Should -Match 'Privileged Access Workstation'
            $ci.si_tier_reason | Should -Not -Match 'Domain Controller|AD CS'
            @($ci.si_tier_claims | Where-Object { $_.rule -match '^ADDomainController|^ADCertificateServices' }).Count | Should -Be 0 -Because "os '$os': no evidence of a DC or a CA"
            $ci.si_tier_explanation | Should -Match '^Tier 0 -- SI rule Privileged Access Workstation \('
            $ci.si_tier_explanation | Should -Match ' Also claimed: '
            # the evidence in words, one item per matched value (a rule over several fields once printed the field NAMES joined)
            $ci.si_tier_explanation | Should -Match '^Tier 0 -- SI rule Privileged Access Workstation \(name paw-pxj70zk58z; Defender tag PAWDevices--tier0--SI\)\.'
            $ci.si_tier_explanation | Should -Not -MatchExactly '\bsi\b|asset name'   # case-sensitive: "SI rule" is the product's word
            $t3 = @($ci.si_tier_claims | Where-Object { $_.rule -eq 'operator-tier-tag/tier3' })
            $t3.Count | Should -Be 1; $t3[0].winner | Should -BeFalse; @($t3[0].matched) | Should -Be @('EmployeeWorkstations--tier3--SI')
        }
    }
    It 'dc3 (tag DomainControllerDNS--tier0--SI, no CA evidence) is a Domain Controller and no AD CS server' {
        $ci = & $script:Run ([ordered]@{ si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'dc3.2linkit.local'; si_hostname = 'dc3'
                si_tags = @((& $script:Tag 'DomainControllerDNS--tier0--SI'), (& $script:Tag 'MDE-Management'), (& $script:Tag 'ServerBusinessServices--tier2--SI'), [ordered]@{ source = 'azure'; name = 'AssetTier--SI'; value = 'AzHubPlatformManagementResources--tier0--SI' }) })
        $ci.si_tier | Should -Be 0
        $ci.si_tier_reason | Should -Match '^Domain Controller'
        @($ci.si_tier_claims | Where-Object { $_.rule -match '^ADCertificateServices' }).Count | Should -Be 0
    }
    It 'mgmt1 (tag AutomationServer--tier0--SI, an Azure AssetTier tag) is no AD CS server' {
        $ci = & $script:Run ([ordered]@{ si_class = 'device'; si_os_platform = 'windows_server'; si_asset_name = 'mgmt1.2linkit.local'; si_hostname = 'mgmt1'
                si_tags = @((& $script:Tag 'AutomationServer--tier0--SI'), (& $script:Tag 'MDE-Management'), (& $script:Tag 'ServerBusinessServices--tier2--SI'), [ordered]@{ source = 'azure'; name = 'AssetTier--SI'; value = 'AzHubPlatformManagementResources--tier0--SI' }) })
        $ci.si_tier_reason | Should -Not -Match 'AD CS|Domain Controller'
        # no SI rule claims a tier here: the tags decide, written as they are (an Azure tag with its value)
        $ci.si_tier_set_by | Should -Be 'tag'
        $ci.si_tier_explanation | Should -BeExactly ('Tier 0 -- your tag AutomationServer--tier0--SI, AssetTier--SI=AzHubPlatformManagementResources--tier0--SI. Also claimed: your tag ' +
            'ServerBusinessServices--tier2--SI (a higher tier number; the lowest wins); default Tier 3 (the default applies only when nothing claims).')
        @($ci.si_tier_claims | Where-Object { $_.rule -match '^ADCertificateServices|^ADDomainController' }).Count | Should -Be 0
    }
    It 'no shipped rule file carries a bare tier tag pattern (it matches every operator tier tag)' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($f in Get-ChildItem -Path (Join-Path $script:SIRoot 'asset-profiling-enrichment') -Recurse -Filter *.yaml) {
            $inTags = $false
            foreach ($l in [IO.File]::ReadAllLines($f.FullName)) {
                if ($l -match '^\s*machineTagPatterns:\s*$') { $inTags = $true; continue }
                if ($inTags -and $l -match "^\s*-\s*'(.*)'\s*$") { if (Test-SIBareTierTagPattern $Matches[1]) { $bad.Add("$($f.Name): $($Matches[1])") }; continue }
                $inTags = $false
            }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'the converter ignores a bare tier pattern (a custom rule copied from an old sample); none left = never matches' {
        foreach ($p in '(?i)tier.?0', 'tier1', '^tier-2$', '(?i)tier_3') { Test-SIBareTierTagPattern $p | Should -BeTrue -Because $p }
        foreach ($p in '(?i)tier.?0.workstation', '(?i)backup.tier.?0', '(?i)^paw', '(?i)domain.controller') { Test-SIBareTierTagPattern $p | Should -BeFalse -Because $p }
        $c = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)domain.controller', '(?i)tier.?0') })
        @($c.any[0].value) | Should -Be @('(?i)domain.controller')
        $only = ConvertTo-SICiKindCondition -Spec ([pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)tier.?0') })
        Test-SICondition -Condition $only -Item @{ si_tags = @((& $script:Tag 'X--tier0--SI')) } | Should -BeFalse
    }
    It 'a claim''s mechanism is the evidence that MATCHED, not the rule''s first detection kind' {
        $det = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('contoso/dc') }, [pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)^dcgroup') }) }
        $rules = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'DcLike' $det @{ Tier = 0 } $false 'Domain Controller'))).Rules)
        $byTag = [ordered]@{ si_class = 'device'; si_tags = @((& $script:Tag 'DCGroup-A')) }
        $null = Invoke-SICiRules -Ci $byTag -Rules $rules -Trust $script:Trust -Context $script:Ctx
        @($byTag.si_tier_claims)[0].mechanism | Should -Be 'mde.machine_tag'
        $bySw = [ordered]@{ si_class = 'device'; si_installed_software = @('contoso/dc'); si_tags = @((& $script:Tag 'DCGroup-A')) }
        $null = Invoke-SICiRules -Ci $bySw -Rules $rules -Trust $script:Trust -Context $script:Ctx
        @($bySw.si_tier_claims)[0].mechanism | Should -Be 'mde.installed_software' -Because 'both matched: the better-placed in the trust list'
    }
    It 'at the same tier the rule with the stronger matched evidence wins (a tag-matched rule no longer outranks a name-matched one by its first kind)' {
        $sw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('contoso/dc') }, [pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)^shared') }) }
        # the PAW-like rule matches by directory group (entra.directory, 5th in the trust list), the DC-like rule only by a
        # tag (mde.machine_tag, 11th) -- ranked by its first kind (installed software, 3rd) the DC-like rule used to win
        $eg = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'groupMembership'; groups = @('PAW-Devices') }) }
        $rules = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'DcLike' $sw @{ Tier = 0 } $false 'Domain Controller'), (& $script:Mk 'PawLike' $eg @{ Tier = 0 } $false 'Privileged Access Workstation'))).Rules)
        $ci = [ordered]@{ si_class = 'device'; si_group_memberships = @('PAW-Devices'); si_tags = @((& $script:Tag 'Shared-1')) }
        $null = Invoke-SICiRules -Ci $ci -Rules $rules -Trust $script:Trust -Context $script:Ctx
        $ci.si_tier_reason | Should -Match '^Privileged Access Workstation'
    }
}

Describe '2. si_tier_explanation -- one plain sentence' {
    BeforeAll {
        $paw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)^paw') }) }
        $script:Paw = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'PrivilegedAccessWorkstation' $paw @{ Tier = 0 } $false 'Privileged Access Workstation'))).Rules)
        $sw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('microsoft/office') }) }
        $script:Office = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'Workstation' $sw @{ Tier = 2 } $false 'Workstation'))).Rules)
        $script:Expl = { param($ci, $rules) $null = Invoke-SICiRules -Ci $ci -Rules $rules -Trust $script:Trust -Context $script:Ctx -Now $script:Ctx.Now; $ci }
    }
    It 'an SI rule decides: its name and the evidence it matched; the tags and the default lost, each with why' {
        $ci = & $script:Expl ([ordered]@{ si_class = 'device'; si_tags = @((& $script:Tag 'PAWDevices--tier0--SI'), (& $script:Tag 'EmployeeWorkstations--tier3--SI')) }) @($script:Paw + $script:TagRules + $script:Default)
        $ci.si_tier_set_by | Should -Be 'rule'
        $ci.si_tier_explanation | Should -BeExactly ('Tier 0 -- SI rule Privileged Access Workstation (Defender tag PAWDevices--tier0--SI). Also claimed: your tag PAWDevices--tier0--SI ' +
            '(a tag counts only when no SI rule decides); your tag EmployeeWorkstations--tier3--SI (a tag counts only when no SI rule decides); default Tier 3 (the default applies only when nothing claims).')
    }
    It 'the tag decides when no SI rule claims a tier -- si_tier_set_by = tag' {
        $ci = & $script:Expl ([ordered]@{ si_class = 'device'; si_tags = @((& $script:Tag 'EmployeeWorkstations--tier2--SI')) }) @($script:TagRules + $script:Default)
        $ci.si_tier | Should -Be 2
        $ci.si_tier_set_by | Should -Be 'tag'
        $ci.si_tier_explanation | Should -BeExactly 'Tier 2 -- your tag EmployeeWorkstations--tier2--SI. Also claimed: default Tier 3 (the default applies only when nothing claims).'
    }
    It 'nothing claims: the default' {
        $ci = & $script:Expl ([ordered]@{ si_class = 'device' }) @($script:TagRules + $script:Default)
        $ci.si_tier_set_by | Should -Be 'default'
        $ci.si_tier_explanation | Should -BeExactly 'Tier 3 -- the default tier (no SI rule or tag claims one).'
    }
    It 'a higher tier number loses (the lowest wins), with the evidence of each rule' {
        $ci = & $script:Expl ([ordered]@{ si_class = 'device'; si_installed_software = @('microsoft/office'); si_tags = @((& $script:Tag 'PAW-1')) }) @($script:Paw + $script:Office + $script:Default)
        $ci.si_tier_explanation | Should -Match '^Tier 0 -- SI rule Privileged Access Workstation \(Defender tag PAW-1\)\. Also claimed: SI rule Workstation Tier 2 \(installed software microsoft/office\) \(a higher tier number; the lowest wins\); default Tier 3'
    }
    It 'a rule in testing is listed with why it decides nothing' {
        $t = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'Workstation' ([pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasSoftwareInstalled'; tvmSoftwareNames = @('microsoft/office') }) }) @{ Tier = 1 } $false 'Admin workstation'))).Rules)
        foreach ($r in $t) { $r.stage = 'testing' }
        $ci = & $script:Expl ([ordered]@{ si_class = 'device'; si_installed_software = @('microsoft/office') }) @($t + $script:Default)
        $ci.si_tier_explanation | Should -BeExactly 'Tier 3 -- the default tier (no SI rule or tag claims one). Also claimed: SI rule Admin workstation Tier 1 (installed software microsoft/office) (the rule is in testing, it decides nothing yet).'
    }
    It 'a manual override wins over everything: who, why, until when -- and the rule it replaced' {
        $ci = & $script:Expl ([ordered]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_tags = @((& $script:Tag 'PAW-1')) }) @($script:Paw + $script:Default)
        $idx = ConvertTo-SICiOverrideIndex -Rows @([pscustomobject]@{ CiId = 'ci-1'; Field = 'si_tier'; Value = '1'; Reason = 'Lab machine.'; SetBy = 'alice@contoso.com'; SetAt = '2026-10-01'; ExpiresAt = '2026-12-31T00:00:00Z' }) -Now $script:Ctx.Now
        $null = Set-SICiOverrides -Ci $ci -Index $idx
        $ci.si_tier_set_by | Should -Be 'override'
        $ci.si_tier_explanation | Should -BeExactly ('Tier 1 -- manual override by alice@contoso.com: Lab machine (until 2026-12-31). Also claimed: SI rule Privileged Access Workstation Tier 0 (Defender tag PAW-1) ' +
            '(the manual override decides); default Tier 3 (the manual override decides).')
    }
    It 'says no internal ids: no rule ids, no file names' {
        $ci = & $script:Run ([ordered]@{ si_class = 'device'; si_os_platform = 'windows'; si_asset_name = 'paw-x1'; si_tags = @((& $script:Tag 'EmployeeWorkstations--tier3--SI')) })
        $ci.si_tier_explanation | Should -Not -Match 'operator-tier-tag|AssetProfileBy|\.yaml'
        $ci.si_tier_explanation | Should -Match '^Tier \d -- '
    }
}

Describe '3. si_tier_claims and si_tier_explanation reach SI_CI_CL' {
    It 'both are in the post contract (si_ naming)' {
        $script:SICiPostFields | Should -Contain 'si_tier_explanation'
        $script:SICiPostFields | Should -Contain 'si_tier_claims'
    }
    It 'the posted claims are slim: only the claims on the tier, what matched, no evidence detail' {
        $paw = [pscustomobject]@{ any = @([pscustomobject]@{ kind = 'hasMdeMachineGroupTag'; machineTagPatterns = @('(?i)^paw') }) }
        $rules = @((ConvertTo-SICiRules -RuleSet @((& $script:Mk 'PrivilegedAccessWorkstation' $paw @{ Tier = 0 } $false 'Privileged Access Workstation'))).Rules) + $script:Default
        $ci = [ordered]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_tags = @((& $script:Tag 'PAW-1')) }
        $null = Invoke-SICiRules -Ci $ci -Rules $rules -Trust $script:Trust -Context $script:Ctx
        $row = ConvertTo-SICiPostRow -Ci $ci
        $row.si_tier_explanation | Should -Match '^Tier 0 -- SI rule Privileged Access Workstation'
        $claims = @($row.si_tier_claims)
        $claims.Count | Should -Be 2
        $w = @($claims | Where-Object { $_['winner'] })[0]
        $w['label'] | Should -Be 'Privileged Access Workstation'
        $w['kind'] | Should -Be 'rule'
        @($w['matched']) | Should -Be @('Defender tag PAW-1')
        $w.Contains('evidence_detail') | Should -BeFalse
        (ConvertTo-Json -InputObject $row -Depth 6 -Compress) | Should -Match '"si_tier_claims":\['
    }
    It 'the build version is 5 or later (every CI is rebuilt once with its explanation)' {
        $script:SICiBuildVersion | Should -BeGreaterOrEqual 5
    }
    It 'the field catalog (and the web app''s copy) lists si_tier_explanation; si_tier_set_by names the tag' {
        $cat = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\field-catalog.locked.json')) | ConvertFrom-Json
        $f = @($cat.fields | Where-Object { $_.name -eq 'si_tier_explanation' })
        $f.Count | Should -Be 1
        $f[0].type | Should -Be 'string'
        $f[0].level | Should -Be 'ci'
        @($cat.fields | Where-Object { $_.name -eq 'si_tier_set_by' })[0].description | Should -Match 'tag'
    }
}
