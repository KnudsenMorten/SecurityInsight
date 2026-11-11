#Requires -Version 5.1
<#
    A BREAK-GLASS ACCOUNT IS TIER 0 (owner 2026-11-11: "Yes, always Tier 0"; framework PIM-DELEGATION-1 item 5).

    SI classifies break-glass accounts (si_is_break_glass: the provider, the naming patterns, the emergency-access group,
    the extension attribute the customer defines, a permanent Tier 0 account excluded from all Conditional Access policies --
    SI-BreakGlass.ps1, before the rules run), but no shipped rule tiered them: only a SAMPLE extension-attribute rule did.
    Now one CI tier rule (Get-SICiBreakGlassTierRules, mechanism break_glass in the trust list) claims Tier 0 for every
    break-glass identity, whatever roles it holds today, beside the privilege rules -- the CI's tier stays the MIN of every
    claim. Also here: the CI build's privilege rules use the downloaded daily catalog when the tenant catalog was built from
    it (the same rule as the identity engine).

    OFFLINE: the CI rule engine on in-memory CIs, fixtures in TestDrive. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiRules.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Trust = Get-SICiTrustIndex $script:Model['trust']
    $script:Now = [datetime]'2026-11-11T06:00:00Z'
    $script:Ctx = @{ Lists = (Get-SIDataModelListContext $script:Model); Now = $script:Now }
    $script:BgRules = @(Get-SICiBreakGlassTierRules)
    # an operator's own rule: Tier 2 for the accounts named svc-*
    $script:OperatorRule = [pscustomobject][ordered]@{
        id = 'operator/service-accounts'; family = 'ci'; file = 'custom'; name = 'Service accounts'; stage = 'production'; priority = 50
        pack = 'Custom'; order = 1; classes = @('identity'); osScope = @(); fallback = $false; mechanism = 'name.pattern'
        when = [ordered]@{ any = @([ordered]@{ field = 'si_upn'; op = 'like'; value = 'svc-*' }) }
        set = [ordered]@{ si_tier = 2 }; exclude = @(); native = $true; asserted = $false
    }
    function script:TierOf($Ci, $Rules = $script:BgRules, $Context = $script:Ctx) {
        $null = Set-SICiBreakGlass -Ci $Ci -Context $Context
        $null = Invoke-SICiRules -Ci $Ci -Rules $Rules -Trust $script:Trust -Context $Context -Now $script:Now
        $Ci
    }
}

Describe 'the rule' {
    It 'one Tier 0 rule over si_is_break_glass: identities only, observed (never a default, never asserted), its own trusted mechanism' {
        $script:BgRules.Count | Should -Be 1
        $r = $script:BgRules[0]
        $r.id | Should -Be 'identity-break-glass/tier0'
        $r.name | Should -Be 'Break-glass account -> Tier 0'
        @($r.classes) | Should -Be @('identity')
        $r.set['si_tier'] | Should -Be 0
        $r.fallback | Should -BeFalse; $r.asserted | Should -BeFalse; $r.stage | Should -Be 'production'
        $r.mechanism | Should -Be 'break_glass'
        @($script:Model['trust'].order | Where-Object { $_.id -eq 'break_glass' })[0].trusted | Should -BeTrue
    }
    It 'the CI build runs it with the other tier rules' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')) | Should -Match '\+ @\(Get-SICiPrivilegeTierRules\) \+ @\(Get-SICiBreakGlassTierRules\)'
    }
}

Describe 'a break-glass account is Tier 0 whatever it holds today' {
    It 'a break-glass account the provider marks, with NO role, is Tier 0 -- and the explanation says why' {
        $ci = TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'emergency1@contoso.com'; si_is_break_glass = $true })
        $ci.si_tier | Should -Be 0
        $ci.si_tier_set_by | Should -Be 'rule'
        $ci.si_tier_reason | Should -Match 'identity-break-glass/tier0'
        (Get-SICiTierExplanation -Ci $ci) | Should -Match 'Break-glass account -> Tier 0'
        (Get-SICiTierExplanation -Ci $ci) | Should -Match 'break-glass account'
    }
    It 'detected by a naming pattern (no provider flag, no role): classified first, then Tier 0' {
        $ctx = @{ Lists = @{ break_glass_patterns = @{ id = 'break_glass_patterns'; type = 'values'; values = @('bg-*') } }; Now = $script:Now }
        $ci = TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'bg-admin@contoso.com'; si_display_name = 'BG admin' }) -Context $ctx
        $ci.si_is_break_glass | Should -BeTrue
        $ci.si_break_glass_reason | Should -Match 'sign-in name matches a break-glass naming pattern'
        $ci.si_tier | Should -Be 0
    }
    It 'an account that is not break-glass gets no claim from it (unchanged)' {
        $ci = TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'user@contoso.com'; si_is_break_glass = $false })
        $ci.Contains('si_tier') | Should -BeFalse
        $ci2 = TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'user2@contoso.com' })
        $ci2.Contains('si_tier') | Should -BeFalse -Because 'unknown is never break-glass'
    }
    It 'not an identity: never claimed' {
        $ci = TierOf ([ordered]@{ si_class = 'device'; si_asset_name = 'pc1'; si_is_break_glass = $true }) -Rules $script:BgRules
        $ci.Contains('si_tier') | Should -BeFalse
    }
    It 'an operator''s own rule still applies as MIN: Tier 2 for a normal account, Tier 0 for a break-glass one' {
        $rules = @($script:BgRules) + @($script:OperatorRule)
        (TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'svc-backup@contoso.com' }) -Rules $rules).si_tier | Should -Be 2
        $bg = TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'svc-emergency@contoso.com'; si_is_break_glass = $true }) -Rules $rules
        $bg.si_tier | Should -Be 0
        @($bg.si_tier_claims | Where-Object { [string](Get-SIItemValue $_ 'rule') -eq 'operator/service-accounts' }).Count | Should -Be 1 -Because 'the operator''s claim is recorded beside it'
    }
    It 'the privilege rules and the break-glass rule together: a break-glass account holding a Tier 2 role is Tier 0' {
        $rules = @(Get-SICiPrivilegeTierRules -Root $script:SIRoot) + @($script:BgRules)
        (TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'e2@contoso.com'; si_privilege_tier_permanent = 2; si_is_break_glass = $true }) -Rules $rules).si_tier | Should -Be 0
        (TierOf ([ordered]@{ si_class = 'identity'; si_identity_type = 'user'; si_upn = 'u2@contoso.com'; si_privilege_tier_permanent = 2 }) -Rules $rules).si_tier | Should -Be 2
    }
}

Describe 'the PROFILE row''s tier (what Risk Analysis reads as CriticalityTier): break glass is a tier source of its own' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityCatalogTierComputer.ps1')
        $script:PLists = @{
            break_glass_patterns  = [pscustomobject]@{ id = 'break_glass_patterns'; type = 'values'; values = @('bg-*', '*emergency access*') }
            break_glass_attribute = [pscustomobject]@{ id = 'break_glass_attribute'; type = 'values'; values = @('extensionAttribute6=Break_Glass') }
        }
        function script:Meta([hashtable]$Extra) {
            $m = @{ ENTRA_AssetType = 'User'; ENTRA_UserType = 'Member'; ENTRA_UPN = 'jane@contoso.com'; ENTRA_DisplayName = 'Jane'; ENTRA_DirectoryRolesPermanent = @() }
            foreach ($k in $Extra.Keys) { $m[$k] = $Extra[$k] }
            [pscustomobject]$m
        }
        $script:ClassifySrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Classify.ps1'))
        $script:EntraSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'))
    }
    It 'a break-glass account by NAMING PATTERN with no role: the source says Tier 0, the profile tier is 0, the proof gives the reason' {
        $bg = Get-SIProfileBreakGlass -Metadata (Meta @{ ENTRA_UPN = 'bg-admin@contoso.com' }) -Lists $script:PLists
        $bg.IsBreakGlass | Should -BeTrue
        $t = Get-SITierFromBreakGlass -IsBreakGlass $bg.IsBreakGlass
        $t | Should -Be 0
        Get-SIMinTier -Tiers @($null, $null, $null, $null, $t) | Should -Be 0
        (Get-SIBreakGlassProof -BreakGlass $bg).Reason | Should -Be 'Break-glass account -> Tier 0. Break-glass because its sign-in name matches a break-glass naming pattern.'
    }
    It 'by the EXTENSION ATTRIBUTE you define, no role: Tier 0, the reason names the attribute (the CI build''s own words)' {
        $bg = Get-SIProfileBreakGlass -Metadata (Meta @{ ENTRA_BreakGlassAttribute = 'extensionAttribute6=Break_Glass' }) -Lists $script:PLists
        Get-SITierFromBreakGlass -IsBreakGlass $bg.IsBreakGlass | Should -Be 0
        $bg.Reason | Should -Match 'carries the extension attribute and value you defined \(extensionAttribute6=Break_Glass\)'
    }
    It 'by a GROUP name and by the collection''s own signal' {
        (Get-SIProfileBreakGlass -Metadata (Meta @{ ENTRA_GroupNames = @('Emergency Access Accounts') }) -Lists $script:PLists).IsBreakGlass | Should -BeTrue
        $p = Get-SIProfileBreakGlass -Metadata (Meta @{}) -Lists @{} -ProviderSignal $true
        $p.IsBreakGlass | Should -BeTrue
        $p.Reason | Should -Match 'marks it as an emergency-access account'
    }
    It 'NOT break-glass: no claim, the tier the roles give is unchanged (MIN of the other sources)' {
        $bg = Get-SIProfileBreakGlass -Metadata (Meta @{ ENTRA_BreakGlassAttribute = 'extensionAttribute6=Other' }) -Lists $script:PLists
        $bg.IsBreakGlass | Should -BeFalse
        $t = Get-SITierFromBreakGlass -IsBreakGlass $bg.IsBreakGlass
        $t | Should -BeNullOrEmpty
        Get-SIMinTier -Tiers @(2, $null, $null, 3, $t) | Should -Be 2
    }
    It 'a service principal is never break-glass' {
        (Get-SIProfileBreakGlass -Metadata ([pscustomobject]@{ ENTRA_AssetType = 'ServicePrincipal'; ENTRA_DisplayName = 'bg-app' }) -Lists $script:PLists -ProviderSignal $true).IsBreakGlass | Should -BeFalse
    }
    It 'WIRING -- Invoke-Classify takes it as one more tier source (MIN), its proof first, IsBreakGlass from it; the collection records the attribute match and the group names' {
        $script:ClassifySrc | Should -Match ([regex]::Escape('$effective = Get-SIMinTier -Tiers @($entraRoleTier, $apiPermTier, $azureTier, $adTier, $breakGlassTier)'))
        $script:ClassifySrc | Should -Match ([regex]::Escape('$breakGlass = Get-SIProfileBreakGlass -Metadata $r.Metadata -Lists $bgLists -ProviderSignal $bgProvider'))
        $script:ClassifySrc | Should -Match ([regex]::Escape('if ($null -ne $breakGlassTier) { [void]$proofs.Add((Get-SIBreakGlassProof -BreakGlass $breakGlass)) }'))
        $script:ClassifySrc | Should -Match ([regex]::Escape('$isBreakGlass   = [bool]$breakGlass.IsBreakGlass'))
        $script:EntraSrc | Should -Match 'ENTRA_BreakGlassAttribute\s+= \$bgMatch'
        $script:EntraSrc | Should -Match 'ENTRA_GroupNames\s+= \$reachNames'
    }
}

Describe 'the CI build reads the same tenant catalog as the identity engine: refreshed from the storage account first' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-CatalogBlob.ps1')
        $root = Join-Path $TestDrive 'ciroot'
        $script:CiDir = Join-Path $root 'privilege-tier-catalog'
        New-Item -ItemType Directory -Force -Path $script:CiDir | Out-Null
        $c = [ordered]@{ Metadata = [ordered]@{ GeneratedAt = 'x' } }
        foreach ($t in 0..3) { $c["EntraID_BuiltInRoles_Tier$t"] = @([ordered]@{ DisplayName = "Role-T$t"; Tier = $t }) }
        [IO.File]::WriteAllText((Join-Path $script:CiDir 'privilege-tier-catalog.locked.json'), ($c | ConvertTo-Json -Depth 6))
        $script:CiRoot = $root
        $script:CiLocal = Join-Path $script:CiDir 'privilege-tier-catalog.custom.json'
        # the storage copy: the classifier moved Role-T0 to Tier 2 (the local copy does not know it yet)
        $script:BlobJson = (@{ Metadata = @{ CatalogSource = 'ai' }; EntraID_BuiltInRoles_Tier2 = @(@{ DisplayName = 'Role-T0'; Tier = 2 }) } | ConvertTo-Json -Depth 5)
        function script:Tier2Roles($Rules) { @(@(@($Rules | Where-Object { $_.id -eq 'identity-privilege/entra-role-tier2' })[0].when.any | Where-Object { $_.field -eq 'si_entra_roles_permanent' })[0].value) }
    }
    BeforeEach {
        [IO.File]::WriteAllText($script:CiLocal, (@{ Metadata = @{ CatalogSource = 'ai' } } | ConvertTo-Json -Depth 4))
        (Get-Item -LiteralPath $script:CiLocal).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-2)
        Mock New-SIAzStorageContext { 'ctx' }
    }
    It 'a NEWER storage copy of the tenant catalog replaces the local one, and the CI rules are built from it' {
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { if ($Blob -eq 'privilege-tier-catalog.custom.json') { [pscustomobject]@{ LastModified = [datetimeoffset]::UtcNow.AddMinutes(-5) } } else { $null } }
        Mock Get-SIAzStorageBlobContent -RemoveParameterType Context { [IO.File]::WriteAllText($Destination, $script:BlobJson) }
        $rules = @(Get-SICiPrivilegeTierRules -Root $script:CiRoot -StorageAccount 'acct' 6>$null)
        Tier2Roles $rules | Should -Contain 'Role-T0'
        Should -Invoke Get-SIAzStorageBlob -Times 1 -ParameterFilter { $Blob -eq 'privilege-tier-catalog.custom.json' }
        Should -Invoke Get-SIAzStorageBlob -Times 1 -ParameterFilter { $Blob -eq 'privilege-tier-catalog.downloaded.custom.json' } -Because 'the downloaded daily catalog is refreshed the same way'
    }
    It 'a FAILED refresh keeps the local copy, warns, and never fails the build' {
        Mock Get-SIAzStorageBlob -RemoveParameterType Context { throw 'AuthorizationPermissionMismatch' }
        $out = @(Get-SICiPrivilegeTierRules -Root $script:CiRoot -StorageAccount 'acct' 3>&1 6>$null)
        $warn = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
        ($warn -join ' ') | Should -Match "Could not refresh the privilege-tier catalog from storage account 'acct'"
        $rules = @($out | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] })
        $rules.Count | Should -BeGreaterThan 0
        Tier2Roles $rules | Should -Not -Contain 'Role-T0'
    }
    It 'no storage account (a VM: the classifier writes beside it) -- storage is never touched' {
        $null = @(Get-SICiPrivilegeTierRules -Root $script:CiRoot -StorageAccount '' 6>$null)
        Should -Invoke New-SIAzStorageContext -Times 0
    }
}

Describe 'the classifier job exists at every install, also without Azure OpenAI (it then downloads the catalog)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'setup deploys it without Azure OpenAI and says so in one line (an existing install: SIv3-MissingJobs)' {
        $r = Select-SIBootstrapEngines -Engines @('identity', 'privilege-tier-classifier') -HaveOpenAi $false
        @($r.Engines) | Should -Contain 'privilege-tier-classifier'
        $r.Note | Should -Match 'downloads the daily classified tier catalog'
        Get-SIBootstrapJobName -Engine 'privilege-tier-classifier' | Should -Be 'caj-si-ptc'
    }
}

Describe 'the CI build''s privilege rules use the downloaded daily catalog when the tenant catalog was built from it' {
    BeforeAll {
        $root = Join-Path $TestDrive 'si'
        $dir = Join-Path $root 'privilege-tier-catalog'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $mk = {
            param([string]$Version, [string]$Extra)
            $c = [ordered]@{ Metadata = [ordered]@{ GeneratedAt = 'x'; version = $Version } }
            foreach ($t in 0..3) {
                $c["AD_BuiltInPermissionGroups_Tier$t"] = @([ordered]@{ Name = "ADG-T$t"; Tier = $t })
                $c["EntraID_BuiltInRoles_Tier$t"] = @([ordered]@{ DisplayName = "Role-T$t"; Tier = $t })
                $c["EntraID_APIPermissions_Tier$t"] = @([ordered]@{ Value = "Perm.T$t"; PermissionType = 'Application'; Tier = $t })
                $c["Azure_BuiltInRoles_Tier$t"] = @([ordered]@{ Name = "AzRole-T$t"; Tier = $t })
            }
            if ($Extra) { $c['EntraID_BuiltInRoles_Tier0'] = @($c['EntraID_BuiltInRoles_Tier0'] + [ordered]@{ DisplayName = $Extra; Tier = 0 }) }
            $c
        }
        [IO.File]::WriteAllText((Join-Path $dir 'privilege-tier-catalog.locked.json'), ((& $mk '' '') | ConvertTo-Json -Depth 6))
        [IO.File]::WriteAllText((Join-Path $dir 'privilege-tier-catalog.downloaded.custom.json'), ((& $mk '2026.11.10' 'Fresh Role') | ConvertTo-Json -Depth 6))
        $script:Root = $root; $script:CustomPath = Join-Path $dir 'privilege-tier-catalog.custom.json'
        function script:Entra0 {
            $r = @(Get-SICiPrivilegeTierRules -Root $script:Root 3>$null)
            @(@(@($r | Where-Object { $_.id -eq 'identity-privilege/entra-role-tier0' })[0].when.any | Where-Object { $_.field -eq 'si_entra_roles_permanent' })[0].value)
        }
    }
    It 'source invardia: a role only the download lists is a Tier 0 rule' {
        [IO.File]::WriteAllText($script:CustomPath, (@{ Metadata = @{ CatalogSource = 'invardia'; CatalogVersion = '2026.11.10' } } | ConvertTo-Json -Depth 4))
        Entra0 | Should -Contain 'Fresh Role'
    }
    It 'source ai: the download is not used' {
        [IO.File]::WriteAllText($script:CustomPath, (@{ Metadata = @{ CatalogSource = 'ai' } } | ConvertTo-Json -Depth 4))
        Entra0 | Should -Not -Contain 'Fresh Role'
        Entra0 | Should -Contain 'Role-T0'
    }
}
