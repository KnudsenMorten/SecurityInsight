#Requires -Version 5.1
<#
    #1192 -- THE PIM DELEGATION CHAIN (framework contract PIM-DELEGATION-1). A person reaches privileges through groups:
      person -> persona group (holds NOTHING itself) -> bundle group(s), nested to any depth -> what the bundle holds.
    Before #1192 SI read the PIM for Groups schedules of the role-holding groups only, so "user -> persona -> role group"
    was lost (proven on a ring-1 directory: admins who can elevate to Privileged Role Administrator came out "Tier 3 is
    the default"), and a group holding only Azure roles never reached anyone.

    ONE TEST PER HOP TYPE and ONE PER ATTACH POINT, so the contract check is a test-by-test comparison:
      hops    PIM eligible, PIM active, PIM owner, plain transitive member, nested group-in-group, direct to the bundle
              (one hop), Roles-Direct (a role on the user itself); plus the cycle guard and depth 3+
      attach  Entra role at "/", Entra role on an administrative unit, Azure RBAC eligible + assigned at every scope level
              (tenant root, management group, subscription, resource group), workload identity (SP) through the same
              chain, Graph application permission on a workload identity (the privilege tier catalog -- a SEPARATE path,
              never on a group)
      unknown a failed read is "not complete", never "no privilege"
    Names are NEVER a tier source: the "-T0-" bundle below is a fixture hint only (the tier comes from the role it holds).
    Offline: no network, no token.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    foreach ($n in 'Write-SIInfo', 'Write-SIWarn', 'Write-SIProgress', 'Reset-SIProgress') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:global:{0}" -f $n) -Value { param() } }
    }
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityCatalogTierComputer.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIDerivedSources.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-SIEntraContext.ps1')
    Initialize-SIIdentityCatalog -Path (Join-Path $script:SIRoot 'privilege-tier-catalog\privilege-tier-catalog.locked.json') | Out-Null
    function script:Src([string]$Rel) { [IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }
    # the Azure seams this suite drives (stubs, script scope -- never leak into other suites)
    foreach ($n in 'Invoke-SIArm', 'Get-SIAzRestRoleDefinitionNames', 'Get-SIAzSubscription', 'Set-SIAzContext', 'Get-SIAzRoleAssignment') {
        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { Set-Item -Path ("function:script:{0}" -f $n) -Value { param($Path, $ApiVersion, [switch]$List, $Scope, $SubscriptionId) } }
    }

    $script:G = '#microsoft.graph.group'; $script:U = '#microsoft.graph.user'; $script:SP = '#microsoft.graph.servicePrincipal'
    function script:Row([string]$Principal, [string]$Group, [string]$Access = 'member') { [pscustomobject]@{ principalId = $Principal; groupId = $Group; accessId = $Access } }
    function script:Mem([string]$Id, [string]$Type = '#microsoft.graph.user') { [pscustomobject]@{ id = $Id; '@odata.type' = $Type } }

    # THE DIRECTORY A TEST DESCRIBES: who is eligible / active in each group (the group's schedules), each group's
    # transitive members, the kind of each object, and which reads fail
    function script:New-Dir {
        $script:Elig = @{}; $script:Act = @{}; $script:Members = @{}; $script:Kinds = @{}; $script:FailUrl = @(); $script:KindFail = $false
    }
    # one chain run, as the discoveries do it: members of the privilege-holding groups, then the PIM for Groups scan
    function script:Invoke-Chain([hashtable]$GroupRoles, [hashtable]$AzureLookup = @{}) {
        $script:_SICache = @{}; $global:SI_EntraRoleReadState = $null
        $script:_SICache['GroupRoles'] = $GroupRoles
        $priv = Get-SIPrivilegeHoldingGroupMap -RoleAssignedGroupMap $GroupRoles -AzureLookup $AzureLookup
        $m2g = Get-SIGroupTransitiveMembers -Token 't' -RoleAssignedGroupMap $priv 3>$null
        $pim = Get-SIPimForGroupsByPrincipal -Token 't' -RoleAssignedGroupMap $priv 3>$null
        $lk = Get-SIRoleGroupLookups
        @{ Priv = $priv; M2G = $m2g; Pim = $pim; Pgm = $lk.PimGroupMembers; Act = $lk.ActivatedMembers; Roles = $GroupRoles; Azure = $AzureLookup }
    }
    function script:Get-Reach($Run, [string]$Id) {
        @(Get-SIPrivilegeGroupReach -PrincipalId $Id -MemberToGroups $Run.M2G -PimGroups $Run.Pim -PimGroupMembers $Run.Pgm -ActivatedGroupMemberships $Run.Act)
    }
    function script:Get-Roles($Run, [string]$Id) { Get-SIEntraRolesFromGroupReach -Reach (Get-Reach $Run $Id) -GroupRoles $Run.Roles }

    $script:PRA = 'Privileged Role Administrator'
}

Describe 'PIM delegation chain' {
    BeforeAll {
        Mock Invoke-SIGraphPaged {
            foreach ($f in @($script:FailUrl)) { if ($RelativeUrl -like $f) { throw 'The remote server returned an error: (500) Internal Server Error.' } }
            if ($RelativeUrl -match "/group/eligibilitySchedules\?.*groupId eq '([^']+)'") { return @($script:Elig[$Matches[1]]) }
            if ($RelativeUrl -match "/group/assignmentSchedules\?.*groupId eq '([^']+)'") { return @($script:Act[$Matches[1]]) }
            if ($RelativeUrl -match 'assignmentScheduleInstances') { return @() }
            if ($RelativeUrl -match '^/groups/([^/]+)/transitiveMembers') { return @($script:Members[$Matches[1]]) }
            @()
        }
        Mock Get-SIDirectoryObjectTypes {
            $t = @{}; foreach ($i in @($Ids)) { if ($script:Kinds.ContainsKey($i)) { $t[$i] = $script:Kinds[$i] } }
            @{ Types = $t; Failed = [bool]$script:KindFail; Error = $(if ($script:KindFail) { 'kind read failed (500)' } else { '' }) }
        }
    }
    BeforeEach { New-Dir }
    AfterAll { $script:_SICache = @{}; $global:SI_EntraRoleReadState = $null }

    Context 'hop types' {
        It 'HOP pim-eligible: user eligible in persona P (holds nothing), P eligible in role group R -> the role is ELIGIBLE (the proven bug)' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Elig['P'] = @(Row 'u1' 'P')
            $script:Kinds['P'] = $G; $script:Kinds['u1'] = $U
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @($run.Pim['u1']) | Should -Be @('P') -Because 'the persona group is scanned although it holds no role'
            $r = Get-Roles $run 'u1'
            @($r.Eligible) | Should -Contain $PRA
            @($r.Permanent).Count | Should -Be 0 -Because 'everything reached through a PIM hop is eligible'
            (Test-SIEntraRoleReadComplete -Parts @('PimForGroups')) | Should -BeTrue
            @(Get-Reach $run 'u1' | Where-Object GroupId -eq 'R')[0].Via | Should -Be @('P')
        }
        It 'HOP pim-active: an ACTIVE (assignment schedule) membership of the persona counts the same -- eligible' {
            $script:Act['R'] = @(Row 'P' 'R'); $script:Act['P'] = @(Row 'u1' 'P')
            $script:Kinds['P'] = $G; $script:Kinds['u1'] = $U
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u1').Eligible) | Should -Contain $PRA
        }
        It 'HOP owner: an eligible OWNER of a group is a path too (accessId owner is read, never filtered out)' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Elig['P'] = @(Row 'u1' 'P' 'owner')
            $script:Kinds['P'] = $G
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u1').Eligible) | Should -Contain $PRA
            $f = [regex]::Match((Src 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'), '(?s)function Get-SIPimForGroupsByPrincipal \{.*?\r?\n\}\r?\n').Value
            $f | Should -Not -Match "accessId eq" -Because 'member AND owner schedules are read'
            $f | Should -Not -Match "principalId eq" -Because 'a principal filter is known to drop schedules: every read is per group'
        }
        It 'HOP plain member: a plain (transitive) member of the persona reaches what the persona can activate into' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Members['P'] = @(Mem 'u2')
            $script:Kinds['P'] = $G
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @($run.Pgm['u2']) | Should -Be @('P')
            @((Get-Roles $run 'u2').Eligible) | Should -Contain $PRA
        }
        It 'HOP nested group-in-group: a group nested in a role group -- its plain members hold the role, who can activate into it holds it eligible' {
            $script:Members['R'] = @((Mem 'N' $G), (Mem 'u3'))
            $script:Elig['N'] = @(Row 'u4' 'N')
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u3').Permanent) | Should -Be @($PRA) -Because 'a plain (nested) member holds it as the group does'
            @((Get-Roles $run 'u4').Eligible) | Should -Contain $PRA -Because 'the nested group''s schedules are read: eligible in N = eligible through R'
            Should -Invoke Invoke-SIGraphPaged -ParameterFilter { $RelativeUrl -match "eligibilitySchedules.*'N'" } -Times 1 -Exactly
            Should -Invoke Invoke-SIGraphPaged -ParameterFilter { $RelativeUrl -match "^/groups/N/transitiveMembers" } -Times 0 -Exactly -Because 'its members are R''s transitive members already'
        }
        It 'HOP direct to the bundle: an admin eligible directly in the role group (one hop) -- as before #1192' {
            $script:Elig['R'] = @(Row 'u5' 'R'); $script:Kinds['u5'] = $U
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u5').Eligible) | Should -Be @($PRA)
        }
        It 'HOP Roles-Direct: a role on the user itself still counts first (the discovery merges it before the group roles)' {
            $u = Src 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraUsers.ps1'
            $u | Should -Match ([regex]::Escape('$permRoles = @(if ($permRolesMap.ContainsKey([string]$u.id))'))
            $u | Should -Match ([regex]::Escape('$permRoles = @($permRoles + $inh.Permanent'))
            # and a plain member of a role group keeps the PERMANENT split (existing case unchanged)
            $script:Members['R'] = @(Mem 'u6')
            $run = Invoke-Chain @{ R = @{ Permanent = @('Global Administrator'); Eligible = @('Exchange Administrator') } }
            $r = Get-Roles $run 'u6'
            @($r.Permanent) | Should -Be @('Global Administrator')
            @($r.Eligible) | Should -Be @('Exchange Administrator')
        }
        It 'DEPTH 3+: user -> A -> B -> C -> role group, no depth cap' {
            $script:Elig['R'] = @(Row 'C' 'R'); $script:Elig['C'] = @(Row 'B' 'C'); $script:Elig['B'] = @(Row 'A' 'B'); $script:Elig['A'] = @(Row 'u7' 'A')
            foreach ($grp in 'A', 'B', 'C') { $script:Kinds[$grp] = $script:G }   # ($g would BE $G: PowerShell names are case-insensitive)
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u7').Eligible) | Should -Contain $PRA
            @(Get-Reach $run 'u7' | Where-Object GroupId -eq 'R')[0].Via | Should -Be @('A', 'B', 'C')
        }
        It 'CYCLE: P -> Q -> P ends, and the way out of the cycle is still found' {
            $script:Elig['R'] = @(Row 'Q' 'R'); $script:Elig['Q'] = @(Row 'P' 'Q'); $script:Elig['P'] = @((Row 'Q' 'P'), (Row 'u8' 'P'))
            $script:Kinds['P'] = $G; $script:Kinds['Q'] = $G
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            @((Get-Roles $run 'u8').Eligible) | Should -Contain $PRA
            Should -Invoke Invoke-SIGraphPaged -ParameterFilter { $RelativeUrl -match "eligibilitySchedules.*'P'" } -Times 1 -Exactly -Because 'each group is read once'
        }
        It 'CONTRACT HINT: a person who reaches a bundle named ...-T0-... holding a Tier 0 role is never "Tier 3 default" (names are no tier source)' {
            $bundle = 'PIM-Entra-ID-Groups-Update-L1-T0-CP-ID'
            $script:Elig[$bundle] = @(Row 'PIM-ROLE-DataAdmins-IT' $bundle); $script:Elig['PIM-ROLE-DataAdmins-IT'] = @(Row 'admin1' 'PIM-ROLE-DataAdmins-IT')
            $script:Kinds['PIM-ROLE-DataAdmins-IT'] = $G
            $run = Invoke-Chain @{ $bundle = @{ Permanent = @('Global Administrator'); Eligible = @() } }
            $r = Get-Roles $run 'admin1'
            (Get-SITierFromEntraRoles -Roles @($r.Eligible)) | Should -Be 0 -Because 'the tier comes from the role the bundle holds'
            (Src 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1') | Should -Not -Match "-T0-|'PIM-" -Because 'no name marker is product logic'
        }
    }

    Context 'attach points' {
        It 'ATTACH Entra role at "/": the role path names the way -- "Group R (can activate via P) -> role"' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Elig['P'] = @(Row 'u1' 'P'); $script:Kinds['P'] = $G
            $run = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            $script:_SICache['RolePrincipalNames'] = @{ R = 'PIM-Entra-ID-PRA'; P = 'PIM-ROLE-X' }
            $paths = @(Get-SIRolePaths -PrincipalId 'u1' -Items @() -Lookups (Get-SIRoleGroupLookups) -Names (Get-SIRolePrincipalNames))
            $paths | Should -Contain ('Group PIM-Entra-ID-PRA (can activate via PIM-ROLE-X) -> {0}' -f $PRA)
        }
        It 'ATTACH Entra role on an ADMINISTRATIVE UNIT: still the role (tier of the role), held through the chain' {
            $script:Elig['RAU'] = @(Row 'P' 'RAU'); $script:Elig['P'] = @(Row 'u1' 'P'); $script:Kinds['P'] = $G
            $run = Invoke-Chain @{ RAU = @{ Permanent = @('User Administrator'); Eligible = @() } }
            $script:_SICache['RoleScopes'] = @{ RAU = @([pscustomobject]@{ roleId = 'r-ua'; role = 'User Administrator'; scopeId = '/administrativeUnits/au1'; assignment = 'active' }) }
            @((Get-Roles $run 'u1').Eligible) | Should -Be @('User Administrator')
            (Get-SITierFromEntraRoles -Roles @('User Administrator')) | Should -Be (Get-SITierFromEntraRoles -Roles @((Get-Roles $run 'u1').Eligible))
            @(Get-SIPimGroupChainReach -PrincipalId 'u1' -GroupRoles $run.Roles -MemberToGroups $run.M2G -PimGroups $run.Pim -PimGroupMembers $run.Pgm).GroupId | Should -Be @('RAU') -Because 'the identity context lists the group''s scoped items from here'
        }
        It 'ATTACH Azure RBAC on a group at <Label> (<Kind>): reached through a persona, eligible, tier = Max(role, scope) = <Want>' -ForEach @(
            @{ Label = 'the tenant root'; Scope = '/providers/Microsoft.Management/managementGroups/tenant-root-id'; Kind = 'eligible'; Want = 0 }
            @{ Label = 'the tenant root'; Scope = '/providers/Microsoft.Management/managementGroups/tenant-root-id'; Kind = 'assigned'; Want = 0 }
            @{ Label = 'a management group'; Scope = '/providers/Microsoft.Management/managementGroups/mg-platform'; Kind = 'eligible'; Want = 0 }
            @{ Label = 'a subscription'; Scope = '/subscriptions/s1'; Kind = 'assigned'; Want = 1 }
            @{ Label = 'a subscription'; Scope = '/subscriptions/s1'; Kind = 'eligible'; Want = 1 }
            @{ Label = 'a resource group'; Scope = '/subscriptions/s1/resourceGroups/rg1'; Kind = 'eligible'; Want = 2 }
        ) {
            (Get-SITierFromAzureRoles -Roles @('Owner')) | Should -Be 0
            $entry = [ordered]@{ RoleName = 'Owner'; Scope = $Scope; ScopeLabel = (Get-SIAzureScopeLabel -Scope $Scope); PrincipalType = 'Group'; RoleTier = 0
                ScopeLevel = (Get-SIAzureScopeLevel -Scope $Scope); EffectiveTier = (Get-SIAzureEffectiveTier -RoleName 'Owner' -Scope $Scope) }
            if ($Kind -eq 'eligible') { $entry['Assignment'] = 'eligible' }
            $azure = @{ AZ = @($entry) }
            $script:Elig['AZ'] = @(Row 'P' 'AZ'); $script:Elig['P'] = @(Row 'u1' 'P'); $script:Kinds['P'] = $G
            $run = Invoke-Chain @{} $azure
            $run.Priv.ContainsKey('AZ') | Should -BeTrue -Because 'a group holding only an Azure role is a privilege-holding group'
            $script:_SICache['RolePrincipalNames'] = @{ AZ = 'PIM-AzRes-TenantRoot-Owner'; P = 'PIM-ROLE-X' }
            $d = @(Get-SIAzureDelegationsFromGroupReach -Reach (Get-Reach $run 'u1') -AzureLookup $azure -Names (Get-SIRolePrincipalNames))
            $d.Count | Should -Be 1
            $d[0]['EffectiveTier'] | Should -Be $Want
            $d[0]['Assignment'] | Should -Be 'eligible'
            $d[0]['Via'] | Should -Be 'PIM-ROLE-X -> PIM-AzRes-TenantRoot-Owner'
            $azure['AZ'][0].Contains('Via') | Should -BeFalse -Because 'the group''s own entry is never changed'
        }
        It 'ATTACH Azure RBAC on a group, PLAIN membership: the members hold it as the group does (before #1192 only Entra role groups were expanded)' {
            $azure = @{ AZ = @([ordered]@{ RoleName = 'Owner'; Scope = '/subscriptions/s1'; PrincipalType = 'Group'; EffectiveTier = 1 }) }
            $script:Members['AZ'] = @(Mem 'u9')
            $run = Invoke-Chain @{} $azure
            $d = @(Get-SIAzureDelegationsFromGroupReach -Reach (Get-Reach $run 'u9') -AzureLookup $azure)
            $d.Count | Should -Be 1
            $d[0].Contains('Assignment') | Should -BeFalse
        }
        It 'ATTACH Azure RBAC ELIGIBILITY is read per subscription (no principal filter) and tiered like an assignment' {
            $script:ArmCalls = 0
            Mock Invoke-SIArm {
                $script:ArmCalls++
                @([pscustomobject]@{ properties = [pscustomobject]@{ principalId = 'AZ'; principalType = 'Group'; scope = '/providers/Microsoft.Management/managementGroups/tenant-root-id'
                        roleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635' } })
            }
            Mock Get-SIAzRestRoleDefinitionNames { @{ BuiltIn = @{ '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner' }; Custom = @{} } }
            $r = Get-SIAzureEligibleRoleEntries -SubscriptionId 's1' -SubscriptionName 'Sub 1'
            $r.Failed | Should -BeFalse
            @($r.Entries).Count | Should -Be 1
            $r.Entries[0].ObjectId | Should -Be 'AZ'
            $r.Entries[0].Entry['EffectiveTier'] | Should -Be 0
            $r.Entries[0].Entry['Assignment'] | Should -Be 'eligible'
            Should -Invoke Invoke-SIArm -Times 1 -Exactly -ParameterFilter { $Path -eq '/subscriptions/s1/providers/Microsoft.Authorization/roleEligibilityScheduleInstances' }
        }
        It 'ATTACH workload identity: a service principal member of / eligible for a group gets the same chain (Entra AND Azure)' {
            $script:Members['R'] = @(Mem 'sp1' $SP)
            $script:Elig['AZ'] = @(Row 'P' 'AZ'); $script:Elig['P'] = @(Row 'sp2' 'P'); $script:Kinds['P'] = $G
            $azure = @{ AZ = @([ordered]@{ RoleName = 'Owner'; Scope = '/providers/Microsoft.Management/managementGroups/root'; PrincipalType = 'Group'; EffectiveTier = 0 }) }
            $run = Invoke-Chain @{ R = @{ Permanent = @('Application Administrator'); Eligible = @() } } $azure
            @((Get-Roles $run 'sp1').Permanent) | Should -Be @('Application Administrator')
            (Get-SITierFromEntraRoles -Roles @('Application Administrator')) | Should -Not -BeNullOrEmpty
            @(Get-SIAzureDelegationsFromGroupReach -Reach (Get-Reach $run 'sp2') -AzureLookup $azure)[0]['EffectiveTier'] | Should -Be 0
            $sp = Src 'engine\asset-profiling\discovery\Get-DiscoveryFromEntraServicePrincipals.ps1'
            $sp | Should -Match 'Get-SIPrivilegeGroupReach -PrincipalId \(\[string\]\$sp\.id\)'
            $sp | Should -Match 'Get-SIAzureDelegationsFromGroupReach'
        }
        It 'ATTACH Graph application permission on a workload identity: tiered by the privilege tier catalog (a separate path, never on a group)' {
            (Get-SITierFromEntraAPIPerms -Perms @('AppRoleAssignment.ReadWrite.All')) | Should -Be 0
            @(Get-SIEntraPermMatches -Perms @('AppRoleAssignment.ReadWrite.All'))[0].CatalogTier | Should -Be 0
            # (RoleManagement.ReadWrite.Directory: the shipped catalog's tier lists carry only its DELEGATED form, at Tier 1,
            # and the match is by name -- the application form therefore comes out Tier 1. A catalog finding, recorded
            # with #1192 in REQUIREMENTS; not asserted here until the catalog is corrected.)
            $c = Src 'engine\asset-profiling\stages\Invoke-Classify.ps1'
            $c | Should -Match ([regex]::Escape('$apiPermTier   = Get-SITierFromEntraAPIPerms -Perms $appPerms')) -Because 'the verdict comes from the catalog, not a fixed list'
        }
    }

    Context 'a failed read is unknown, never "no privilege"' {
        It 'the schedules of a persona group cannot be read -> the PIM for Groups read is NOT complete' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Kinds['P'] = $G
            $script:FailUrl = @("*eligibilitySchedules*'P'*")
            $null = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            (Test-SIEntraRoleReadComplete -Parts @('PimForGroups')) | Should -BeFalse
        }
        It 'the kind of a principal cannot be read -> NOT complete' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:KindFail = $true
            $null = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            (Test-SIEntraRoleReadComplete -Parts @('PimForGroups')) | Should -BeFalse
        }
        It 'the members of a persona group cannot be read -> NOT complete' {
            $script:Elig['R'] = @(Row 'P' 'R'); $script:Kinds['P'] = $G
            $script:FailUrl = @('/groups/P/transitiveMembers*')
            $null = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            (Test-SIEntraRoleReadComplete -Parts @('PimForGroups')) | Should -BeFalse
        }
        It 'the Azure eligibility read fails -> Failed (the caller says the eligible Azure roles there are UNKNOWN)' {
            Mock Invoke-SIArm { throw 'The remote server returned an error: (403) Forbidden.' }
            $r = Get-SIAzureEligibleRoleEntries -SubscriptionId 's1'
            $r.Failed | Should -BeTrue
            $r.Error | Should -Match '403'
            $f = [regex]::Match((Src 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'), '(?s)function Get-SIAzureDelegationsByPrincipal \{.*?\r?\n\}\r?\n').Value
            $f | Should -Match 'eligible Azure roles held there are UNKNOWN this run, not absent'
        }
    }

    Context 'cost and rights' {
        It 'only groups that lead into a privilege-holding group are read; a user principal is never scanned as a group' {
            $script:Elig['R'] = @((Row 'u1' 'R'), (Row 'P' 'R')); $script:Kinds['u1'] = $U; $script:Kinds['P'] = $G
            $null = Invoke-Chain @{ R = @{ Permanent = @($PRA); Eligible = @() } }
            Should -Invoke Invoke-SIGraphPaged -ParameterFilter { $RelativeUrl -match "eligibilitySchedules.*'u1'" } -Times 0 -Exactly
            Should -Invoke Invoke-SIGraphPaged -ParameterFilter { $RelativeUrl -match "eligibilitySchedules.*'P'" } -Times 1 -Exactly
        }
        It 'no new right: the reads are those the engine already holds' {
            $rights = Src 'setup\_shared\si-identity-rights.json'
            foreach ($r in 'engine.graph.PrivilegedAccess.Read.AzureADGroup', 'engine.graph.Group.Read.All', 'engine.graph.Directory.Read.All', 'engine.azure.Reader') { $rights | Should -Match ([regex]::Escape('"id": "' + $r + '"')) }
        }
    }
}
