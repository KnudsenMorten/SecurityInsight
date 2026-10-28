#Requires -Version 5.1
<#
    AN ENGINE CHECKS ITS OWN PERMISSIONS AT RUN START (engine/_shared/SI-PermissionCheck.ps1, catalog
    config/permissions.locked.json), and its run-health END record carries the gaps (PermissionGaps) to Get Started.

    Why: asset tagging's own identity had no user in the Pro database on every Pro install -- the daily run failed for days
    before anyone saw why (operator 2026-10-08: "make sure to add permissions into the get started so we can verify we have
    the needed permissions"). These tests hold the pure check: token roles against the catalog, the Azure permissions read,
    the Pro database roles, not-checked vs missing, that it never throws, and that Community (no Pro database) has no
    database area. The Pro settings layer's half (it records the database access) is in SIv3-PermissionCheckPro.Tests.ps1.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-PermissionCheck.ps1')
    $script:Cat = Get-SIPermissionCatalog -Path (Join-Path $script:SIRoot 'config\permissions.locked.json')

    function script:B64Url([string]$s) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    function script:New-Jwt([string[]]$Roles, [string]$AppId = 'aaaaaaaa-0000-0000-0000-000000000001', [switch]$NoRoles) {
        $p = [ordered]@{ aud = 'x'; appid = $AppId }
        if (-not $NoRoles) { $p['roles'] = @($Roles) }
        '{0}.{1}.sig' -f (B64Url '{"alg":"none"}'), (B64Url (ConvertTo-Json -InputObject $p -Compress))
    }
    $script:AllCollectionRoles = @{}
    foreach ($a in $script:Cat.identities.collection.api) { $script:AllCollectionRoles[[string]$a.audience] = @($a.roles) }
    $script:FullToken = { param($Resource) New-Jwt -Roles $script:AllCollectionRoles[[string]$Resource] }
    $script:Reader = { param($Scope) , @([pscustomobject]@{ actions = @('*/read'); notActions = @() }) }
    $script:Globals = @{ SI_UseManagedIdentity = $true; SI_UAMI_ClientId = 'cccccccc-0000-0000-0000-000000000001'; SI_AzSubscriptionId = 'sub-1' }
}

AfterAll { Remove-Variable -Scope Global -Name SI_PermissionCheck, SI_ProDatabaseAccess -ErrorAction SilentlyContinue }

Describe 'the catalog is the one list' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'every engine names a known identity and only known areas; there is a default' {
        $script:Cat.engines.default | Should -Not -BeNullOrEmpty
        foreach ($p in $script:Cat.engines.PSObject.Properties) {
            @($script:Cat.identities.PSObject.Properties.Name) | Should -Contain ([string]$p.Value.identity)
            foreach ($c in @($p.Value.checks)) { @('api', 'azure', 'database') | Should -Contain $c }
        }
        foreach ($i in $script:Cat.identities.PSObject.Properties) {
            foreach ($a in 'api', 'azure', 'database') { [string]$i.Value.fix.$a | Should -Not -BeNullOrEmpty -Because "$($i.Name) needs a fix text for $a" }
        }
    }
    It 'its application permissions are exactly the grant plans setup uses (collection and asset tagging) -- they cannot drift apart' {
        foreach ($pair in @(@{ Key = 'collection'; Plan = $script:SIContainerIdentityAppRoles }, @{ Key = 'tagging'; Plan = $script:SIAssetTaggingIdentityAppRoles })) {
            $cat = @{}
            foreach ($a in $script:Cat.identities.($pair.Key).api) {
                $roles = @(@($a.roles) + @($a.conditionalRoles | ForEach-Object { $_.role }) | Where-Object { $_ })
                $cat[[string]$a.resourceAppId] = @($roles | Sort-Object)
            }
            $plan = @{}
            foreach ($r in $pair.Plan) { $plan[[string]$r.ResourceAppId] = @($r.Roles | Sort-Object) }
            @($cat.Keys | Sort-Object) | Should -Be @($plan.Keys | Sort-Object) -Because $pair.Key
            foreach ($k in $plan.Keys) { $cat[$k] | Should -Be $plan[$k] -Because ('{0} {1}' -f $pair.Key, $k) }
        }
    }
    It 'the collection identity stays read only; asset tagging''s writes are conditional on SI_Pro_AssetTagging_Apply' {
        foreach ($a in $script:Cat.identities.collection.api) { @($a.roles) | Where-Object { $_ -match 'Write' } | Should -BeNullOrEmpty }
        foreach ($a in $script:Cat.identities.tagging.api) {
            @($a.roles) | Where-Object { $_ -match 'Write' } | Should -BeNullOrEmpty
            foreach ($c in @($a.conditionalRoles)) { [string]$c.when | Should -Be 'SI_Pro_AssetTagging_Apply' }
        }
        @($script:Cat.identities.tagging.database) | Should -Be @('db_datareader')
    }
    It 'no internal numbers in what a customer reads (fix texts, labels)' {
        $text = ($script:Cat.identities.PSObject.Properties | ForEach-Object { $_.Value.label; $_.Value.fix.api; $_.Value.fix.azure; $_.Value.fix.database }) -join ' '
        $text | Should -Not -Match '#\d|audit \d|fix request'
    }
}

Describe 'API permissions: the roles of the engine''s own token' {
    It 'a token with every role: all ok; a token without some: exactly those missing' {
        $api = $script:Cat.identities.collection.api[0]
        $all = @(Test-SIPermissionApiRoles -Api $api -TokenRoles @($api.roles) -Fix 'f')
        @($all | Where-Object State -ne 'ok').Count | Should -Be 0
        $some = @(Test-SIPermissionApiRoles -Api $api -TokenRoles @('User.Read.All', 'group.read.all') -Fix 'f')
        @($some | Where-Object State -eq 'ok' | ForEach-Object Item) | Should -Be @('User.Read.All', 'Group.Read.All')
        @($some | Where-Object State -eq 'missing').Count | Should -Be (@($api.roles).Count - 2)
        ($some | Where-Object State -eq 'missing' | Select-Object -First 1).Area | Should -Be 'Microsoft Graph'
    }
    It 'a token with NO roles claim: every role missing (an empty list is not "no token")' {
        $roles = Get-SIPermissionTokenRoles -Token (New-Jwt -NoRoles)
        $null -eq $roles | Should -BeFalse
        @($roles).Count | Should -Be 0
        # every role of the area, however many the area has (Defender has several)
        $api = $script:Cat.identities.collection.api[2]
        $r = @(Test-SIPermissionApiRoles -Api $api -TokenRoles $roles -Fix 'f')
        $r.Count | Should -Be @($api.roles).Count
        @($r | Where-Object State -ne 'missing').Count | Should -Be 0
        @($r | ForEach-Object Item) | Should -Be @($api.roles)
    }
    It 'no token at all: not checked, with the reason -- never missing' {
        Get-SIPermissionTokenRoles -Token '' | Should -BeNullOrEmpty
        Get-SIPermissionTokenRoles -Token 'not-a-jwt' | Should -BeNullOrEmpty
        $r = @(Test-SIPermissionApiRoles -Api $script:Cat.identities.collection.api[1] -TokenRoles $null -Fix 'f' -Reason 'no token')
        @($r.State | Select-Object -Unique) | Should -Be @('not-checked')
        @($r.Fix | Select-Object -Unique) | Should -Be @('no token')
    }
}

Describe 'Azure: one read of the caller''s own permissions' {
    BeforeAll { $script:Items = @($script:Cat.identities.tagging.azure) }
    It 'Reader (*/read) and Owner (*) grant Reader; a narrower action does not' {
        (Test-SIPermissionAzureActions -Items $script:Items[0] -Permissions @([pscustomobject]@{ actions = @('*/read'); notActions = @() }) -Scope '/subscriptions/s').State | Should -Be 'ok'
        (Test-SIPermissionAzureActions -Items $script:Items[0] -Permissions @([pscustomobject]@{ actions = @('*'); notActions = @('Microsoft.Authorization/*/Delete') })).State | Should -Be 'ok'
        (Test-SIPermissionAzureActions -Items $script:Items[0] -Permissions @([pscustomobject]@{ actions = @('Microsoft.Compute/*/read'); notActions = @() })).State | Should -Be 'missing'
    }
    It 'Tag Contributor is found by its action; a notAction removes it' {
        (Test-SIPermissionAzureActions -Items $script:Items[1] -Permissions @([pscustomobject]@{ actions = @('Microsoft.Resources/tags/*'); notActions = @() })).State | Should -Be 'ok'
        (Test-SIPermissionAzureActions -Items $script:Items[1] -Permissions @([pscustomobject]@{ actions = @('*'); notActions = @('Microsoft.Resources/tags/write') })).State | Should -Be 'missing'
        (Test-SIPermissionAzureActions -Items $script:Items[1] -Permissions @([pscustomobject]@{ actions = @('*/read'); notActions = @() })).When | Should -Be 'SI_Pro_AssetTagging_Apply'
    }
    It 'permissions that could not be read: not checked -- never missing' {
        $r = @(Test-SIPermissionAzureActions -Items $script:Items -Permissions $null -Reason 'unreadable')
        @($r.State | Select-Object -Unique) | Should -Be @('not-checked')
    }
    It 'the scope: an explicit one, else what setup granted Reader at, else the install''s subscription; else none' {
        Resolve-SIPermissionAzureScope -Globals @{ SI_PermissionCheck_AzureScope = '/providers/Microsoft.Management/managementGroups/t1/'; SI_AzSubscriptionId = 's' } | Should -Be '/providers/Microsoft.Management/managementGroups/t1'
        Resolve-SIPermissionAzureScope -Globals @{ SI_Bootstrap_IdentityReaderScopes = @('/providers/Microsoft.Management/managementGroups/root'); SI_AzSubscriptionId = 's' } | Should -Be '/providers/Microsoft.Management/managementGroups/root'
        Resolve-SIPermissionAzureScope -Globals @{ SI_AzSubscriptionId = 's1' } | Should -Be '/subscriptions/s1'
        Resolve-SIPermissionAzureScope -Globals @{ SI_WorkspaceResourceId = '/subscriptions/s2/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w' } | Should -Be '/subscriptions/s2'
        Resolve-SIPermissionAzureScope -Globals @{} | Should -Be ''
    }
}

Describe 'the Pro database: what the settings layer saw' {
    It 'IS_ROLEMEMBER per role; db_owner covers all; unknown is not checked' {
        $r = @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader', 'db_datawriter') -Access @{ SignIn = 'ok'; Roles = @{ db_owner = '0'; db_datareader = '1'; db_datawriter = '0' } } -Fix 'f')
        @($r | ForEach-Object { '{0}={1}' -f $_.Item, $_.State }) | Should -Be @('db_datareader=ok', 'db_datawriter=missing')
        @(Test-SIPermissionDatabaseRoles -Roles @('db_datawriter') -Access @{ SignIn = 'ok'; Roles = @{ db_owner = '1'; db_datawriter = '0' } } -Fix 'f').State | Should -Be @('ok')
        @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access @{ SignIn = 'ok'; Roles = @{} } -Fix 'f').State | Should -Be @('not-checked')
    }
    It 'a refused sign-in (no database user) is ONE missing item with the fix; not reached = not checked' {
        $r = @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader') -Access @{ SignIn = 'failed'; Error = 'Login failed' } -Fix 'the one-time grant')
        $r.Count | Should -Be 1
        $r[0].State | Should -Be 'missing'
        $r[0].Fix | Should -Be 'the one-time grant'
        @(Test-SIPermissionDatabaseRoles -Roles @('db_datareader', 'db_datawriter') -Access $null -Fix 'f').State | Should -Be @('not-checked', 'not-checked')
    }
}

Describe 'the self-check at run start' {
    AfterEach { Remove-Variable -Scope Global -Name SI_PermissionCheck, SI_ProDatabaseAccess -ErrorAction SilentlyContinue }
    It 'a profiling engine with every permission: nothing missing, the identity named, the result kept for the run record' {
        $r = Invoke-SIPermissionSelfCheck -Engine 'identity' -Catalog $script:Cat -GetToken $script:FullToken -GetArmPermissions $script:Reader -Globals $script:Globals -Quiet
        @($r.Checked | Where-Object State -ne 'ok').Count | Should -Be 0
        $r.Identity | Should -Be 'cccccccc-0000-0000-0000-000000000001'
        $r.IdentityKey | Should -Be 'collection'
        $global:SI_PermissionCheck | Should -Be $r
        @($r.Checked | Where-Object Area -eq 'Azure').Count | Should -Be 1
    }
    It 'missing roles and no Azure read: the roles are missing, Azure is not checked' {
        $tok = { param($Resource) if ($Resource -like '*graph*') { New-Jwt -Roles @('User.Read.All') } else { $null } }
        $r = Invoke-SIPermissionSelfCheck -Engine 'endpoint' -Catalog $script:Cat -GetToken $tok -GetArmPermissions { param($s) throw 'AuthorizationFailed' } -Globals $script:Globals -Quiet
        @($r.Checked | Where-Object { $_.Area -eq 'Microsoft Graph' -and $_.State -eq 'missing' }).Count | Should -Be (@(($script:Cat.identities.collection.api | Where-Object resource -eq 'Microsoft Graph').roles).Count - 1)   # every Graph role but the one the token has: 21 Graph roles (AccessReview.Read.All for the last access review, UserAuthenticationMethod.Read.All for passwordless-only accounts, DeviceManagementManagedDevices.Read.All for Intune serials / MACs, DeviceManagementConfiguration.Read.All for Intune compliance policies / update rings) less User.Read.All
        $mde = @($r.Checked | Where-Object { $_.Area -eq 'WindowsDefenderATP' }); $mde.Count | Should -Be @(($script:Cat.identities.collection.api | Where-Object resource -eq 'WindowsDefenderATP').roles).Count; @($mde | Where-Object State -ne 'not-checked').Count | Should -Be 0   # every Defender role: Machine.Read.All + Vulnerability.Read.All (the exploit details of a CVE) + SecurityRecommendation.Read.All (the exposure impact and active alert of a recommendation)
        $az = @($r.Checked | Where-Object Area -eq 'Azure')
        $az.State | Should -Be @('not-checked')
        $az.Fix | Should -Match 'could not be read'
    }
    It 'an engine that only checks the database makes no token or Azure call' {
        $script:calls = 0
        $r = Invoke-SIPermissionSelfCheck -Engine 'asset-trend' -Catalog $script:Cat -GetToken { param($x) $script:calls++ } -GetArmPermissions { param($x) $script:calls++ } -Globals $script:Globals -Quiet
        $script:calls | Should -Be 0
        @($r.Checked).Count | Should -Be 0
        $r.Checks | Should -Be @('database')
    }
    It 'NEVER THROWS: a broken catalog is a recorded error, not a stopped run' {
        { Invoke-SIPermissionSelfCheck -Engine 'identity' -Catalog ([pscustomobject]@{ engines = $null }) -Globals @{} -Quiet } | Should -Not -Throw
        $global:SI_PermissionCheck.Error | Should -Match 'could not run'
        $j = ConvertTo-SIPermissionGapsJson -Check (Complete-SIPermissionCheck -Check $global:SI_PermissionCheck)
        ($j | ConvertFrom-Json).error | Should -Match 'could not run'
    }
    It 'the identity falls back to the token''s app id when the run has none' {
        $r = Invoke-SIPermissionSelfCheck -Engine 'identity' -Catalog $script:Cat -GetToken $script:FullToken -GetArmPermissions $script:Reader -Globals @{ SI_AzSubscriptionId = 's' } -Quiet
        $r.Identity | Should -Be 'aaaaaaaa-0000-0000-0000-000000000001'
    }
}

Describe 'what the run-health END record carries' {
    AfterEach { Remove-Variable -Scope Global -Name SI_PermissionCheck, SI_ProDatabaseAccess, SI_ProSqlServer, SI_ProSqlDatabase, SI_Pro_AssetTagging_Apply -ErrorAction SilentlyContinue }
    It 'Community (no Pro database): no database area at all' {
        $c = Invoke-SIPermissionSelfCheck -Engine 'identity' -Catalog $script:Cat -GetToken $script:FullToken -GetArmPermissions $script:Reader -Globals $script:Globals -Quiet
        $done = Complete-SIPermissionCheck -Check $c -Globals @{} -DatabaseAccess $null
        @($done.Checked | Where-Object Area -eq 'Pro database').Count | Should -Be 0
        $o = (ConvertTo-SIPermissionGapsJson -Check $done) | ConvertFrom-Json
        $o.missing | Should -Be 0
        @($o.items).Count | Should -Be 0
        $o.engine | Should -Be 'identity'
        $o.identity | Should -Be 'cccccccc-0000-0000-0000-000000000001'
    }
    It 'Pro: the database area comes from the settings layer''s record -- a refused sign-in is the gap, with the script that fixes it' {
        $c = Invoke-SIPermissionSelfCheck -Engine 'asset-tagging' -Catalog $script:Cat -GetToken { param($r) New-Jwt -Roles @('ThreatHunting.Read.All', 'User.Read.All', 'Application.Read.All') } -GetArmPermissions $script:Reader -Globals $script:Globals -Quiet
        $g = @{ SI_ProSqlServer = 'sql.example.test'; SI_ProSqlDatabase = 'sqldb-si-pro' }
        $done = Complete-SIPermissionCheck -Check $c -Globals $g -DatabaseAccess @{ SignIn = 'failed'; Error = 'Login failed for user' }
        $gap = @($done.Checked | Where-Object { $_.State -eq 'missing' })
        $gap.Count | Should -Be 1
        $gap[0].Area | Should -Be 'Pro database'
        $gap[0].Fix | Should -Match 'Grant-SITaggingDatabase\.ps1'
        # report-only asset tagging: its write permissions are not asked for (they are missing, and that is fine)
        @($done.Checked | Where-Object { $_.Item -match 'ReadWrite|Tag Contributor' }).Count | Should -Be 0
        # ... until SI_Pro_AssetTagging_Apply is on
        $g['SI_Pro_AssetTagging_Apply'] = $true
        $on = Complete-SIPermissionCheck -Check $c -Globals $g -DatabaseAccess @{ SignIn = 'ok'; Roles = @{ db_owner = '0'; db_datareader = '1' } }
        @($on.Checked | Where-Object State -eq 'missing' | ForEach-Object Item) | Should -Be @('CustomSecAttributeAssignment.ReadWrite.All', 'Machine.ReadWrite.All', 'Tag Contributor (/subscriptions/sub-1)')
    }
    It 'only the gaps and the not-checked items, missing first, kept short' {
        $chk = [pscustomobject]@{ Engine = 'identity'; Identity = 'i'; Label = 'l'; Error = ''
            Checked = @((New-SIPermissionItem -Area 'A' -Item 'ok1' -State 'ok'), (New-SIPermissionItem -Area 'A' -Item 'nc' -State 'not-checked' -Fix 'x'),
                        (New-SIPermissionItem -Area 'A' -Item 'm1' -State 'missing' -Fix 'f'), (New-SIPermissionItem -Area 'A' -Item 'm2' -State 'missing' -Fix 'f')) }
        $o = (ConvertTo-SIPermissionGapsJson -Check $chk -MaxItems 2) | ConvertFrom-Json
        @($o.items | ForEach-Object item) | Should -Be @('m1', 'm2')
        $o.more | Should -Be 1
        $o.missing | Should -Be 2
        $o.notChecked | Should -Be 1
        # one item stays a list (PS 5.1)
        $one = ConvertTo-SIPermissionGapsJson -Check ([pscustomobject]@{ Engine = 'e'; Identity = ''; Label = ''; Error = ''; Checked = @((New-SIPermissionItem -Area 'A' -Item 'm' -State 'missing')) })
        $one | Should -Match '"items":\['
    }
    It 'the record of the engine''s own END only: not on a Start, not on the job flow''s step record, not without a check' {
        Remove-Variable -Scope Global -Name SI_PermissionCheck -ErrorAction SilentlyContinue
        Get-SIRunHealthPermissionGaps -RunContext ([pscustomobject]@{ Engine = 'identity' }) -Phase End | Should -Be ''
        $null = Invoke-SIPermissionSelfCheck -Engine 'identity' -Catalog $script:Cat -GetToken $script:FullToken -GetArmPermissions $script:Reader -Globals $script:Globals -Quiet
        Get-SIRunHealthPermissionGaps -RunContext ([pscustomobject]@{ Engine = 'identity' }) -Phase Start | Should -Be ''
        Get-SIRunHealthPermissionGaps -RunContext ([pscustomobject]@{ Engine = 'flow:identity' }) -Phase End | Should -Be ''
        (Get-SIRunHealthPermissionGaps -RunContext ([pscustomobject]@{ Engine = 'identity' }) -Phase End | ConvertFrom-Json).engine | Should -Be 'identity'
    }
}

Describe 'the wiring' {
    It 'the run-health record writes PermissionGaps (additive, like Execution and Build) from the self-check' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'))
        $src | Should -Match 'PermissionGaps\s+= \[string\]\$\(if \(Get-Command -Name Get-SIRunHealthPermissionGaps'
    }
    It 'both container entry points run the check before the Pro settings layer, and never stop on it' {
        foreach ($f in 'container\Start-SIInContainer.ps1', 'container\Start-RiskAnalysisInContainer.ps1') {
            $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f))
            $i = $src.IndexOf('Invoke-SIPermissionSelfCheck')
            $i | Should -BeGreaterThan 0 -Because $f
            $i | Should -BeLessThan $src.IndexOf('Invoke-SIProSettingsLayer') -Because $f
            $src | Should -Match "try \{ \. \(Join-Path \`$PSScriptRoot '\.\./engine/_shared/SI-PermissionCheck\.ps1'\); \`$null = Invoke-SIPermissionSelfCheck"
        }
    }
    It 'the check is PS 5.1 code and loads no PowerShell module' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-PermissionCheck.ps1'))
        $src | Should -Not -Match '\?\?|\?\.|Import-Module|#Requires -Modules'
        $tokens = $null; $errs = $null
        $null = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errs)
        @($errs).Count | Should -Be 0
    }
}
