#Requires -Version 5.1
<#
    A COLLECTION RUN ASSIGNS NO ROLE AND CREATES NO RESOURCE -- IT ONLY CHECKS (owner 2026-10-12).

    Verbatim: "Nothing: check only" / "something must be wrong if it can send data to la, but try to add more permissions".
    Every identity / endpoint / azure / publicip collection used to call a step that created a missing workspace,
    resource group, data collection endpoint or storage account and granted the run's own identity Contributor. On an
    install with the narrow roles setup gives it warned on every run; on an install whose identity may assign roles it
    gave itself Contributor. What these tests keep true:
      * the check is read-only: its only door to Azure has no method argument, and a run with the narrow roles makes no
        call but a handful of reads -- and says nothing;
      * a missing role is ONE line naming the role, where, and the setup command (Grant-SIIdentity ... -AllowSchemaCreate
        -Apply); it is said once per process;
      * what cannot be read is never guessed: a role list that is refused, a role definition that cannot be read, a
        resource lookup that is refused -- no line;
      * a role held above the scope, through a group, or by another role whose definition allows the action is held;
      * the create roles are asked for only by a run that had something to create;
      * a resource that does not exist is one line naming it and the setup script -- nothing is created;
      * GUARD: no collection source writes a role assignment or creates a resource group, workspace, endpoint or storage
        account. The files that still can are listed here by name, with the reason.
      * setup still creates what a new install needs, and grants the narrow roles instead of plain Contributor.
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-RunAccessCheck.ps1')

    $script:Sub = '00000000-0000-0000-0000-0000000000aa'
    $script:Oid = '11111111-2222-3333-4444-555555555555'
    $script:RgId = "/subscriptions/$($script:Sub)/resourceGroups/rg-si"
    $script:WsId = "$($script:RgId)/providers/Microsoft.OperationalInsights/workspaces/log-si"
    $script:DceId = "$($script:RgId)/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si"
    $script:StId = "$($script:RgId)/providers/Microsoft.Storage/storageAccounts/stsitest01"
    $script:Role = @{
        Mmp = '3913510d-42f4-4e42-8a64-420c390055eb'; MonContrib = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'; LaContrib = '92aaf0da-9dab-42b6-94a3-d43ce8d16293'
        Contributor = 'b24988ac-6180-42a0-ab88-20f7382dd24c'; Reader = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; LaReader = '73c42c96-874c-492b-b04d-ab87d138a893'
        Blob = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'; Custom = 'cccccccc-0000-0000-0000-00000000c001'
    }
    function script:Get-Values {
        @{ SI_AzSubscriptionId = $script:Sub; SI_WorkspaceResourceId = $script:WsId; SI_DcrResourceGroup = 'rg-si'; SI_DceResourceGroup = 'rg-si'
           SI_DceName = 'dce-si'; SI_StorageAccount = 'stsitest01'; SI_StorageResourceGroup = 'rg-si' }
    }
    function script:Get-Target { Resolve-SIRunAccessTarget -Values (Get-Values) }
    function script:New-Assignment([string]$RoleId, [string]$Scope) {
        [pscustomobject]@{ properties = [pscustomobject]@{ scope = $Scope; principalId = $script:Oid
            roleDefinitionId = "/subscriptions/$($script:Sub)/providers/Microsoft.Authorization/roleDefinitions/$RoleId" } }
    }
    # the roles setup gives a container install's identity WITHOUT -AllowSchemaCreate: it may send and read, not create
    function script:Get-NarrowRoles {
        @((New-Assignment $script:Role.Mmp $script:RgId), (New-Assignment $script:Role.LaReader $script:WsId), (New-Assignment $script:Role.Blob $script:StId),
          (New-Assignment $script:Role.Reader "/subscriptions/$($script:Sub)"))
    }
    function script:New-State { @{ Assignments = @{}; Definitions = @{}; Said = @{}; Resources = @{} } }
    # A recording Azure: every read is kept (-Calls), nothing can be written -- the check's door has no method.
    #   -Roles         the identity's own assignments           -GroupRoles  assignments it holds through a group
    #   -Definitions   role id -> permission blocks (a role id not listed cannot be read)
    #   -Absent        resource ids that do not exist            -Refused     resource ids whose lookup is refused
    #   -RoleListRefused  the identity may not read role assignments
    #   -EndpointsInSubscription  what a subscription-wide endpoint list returns
    function script:New-World {
        param([object[]]$Roles = @(), [object[]]$GroupRoles = @(), [hashtable]$Definitions = @{}, [string[]]$Absent = @(), [string[]]$Refused = @(),
              [switch]$RoleListRefused, [object[]]$EndpointsInSubscription = @())
        $w = @{ Calls = (New-Object System.Collections.Generic.List[object]); Roles = $Roles; GroupRoles = $GroupRoles; Definitions = $Definitions
                Absent = $Absent; Refused = $Refused; RoleListRefused = [bool]$RoleListRefused; Endpoints = $EndpointsInSubscription }
        $w.Arm = {
            param([string]$Path, [string]$ApiVersion, [bool]$List)
            $w.Calls.Add([pscustomobject]@{ Path = $Path; List = $List })
            $plain = [uri]::UnescapeDataString($Path)
            if ($plain -match '/roleAssignments\?') {
                if ($w.RoleListRefused) { throw 'AuthorizationFailed: the client does not have authorization to perform action Microsoft.Authorization/roleAssignments/read' }
                if ($plain -match 'assignedTo\(') { return @($w.Roles) + @($w.GroupRoles) }
                return @($w.Roles)
            }
            if ($plain -match '/roleDefinitions/([^/?]+)$') {
                $id = $Matches[1]
                if (-not $w.Definitions.ContainsKey($id)) { throw 'AuthorizationFailed' }
                return [pscustomobject]@{ id = $Path; properties = [pscustomobject]@{ permissions = @($w.Definitions[$id]) } }
            }
            if ($List) { return @($w.Endpoints) }
            if (@($w.Refused) -contains $Path) { throw 'AuthorizationFailed' }
            if (@($w.Absent) -contains $Path) { return $null }
            [pscustomobject]@{ id = $Path }
        }.GetNewClosure()
        $w
    }
    function script:Invoke-Check {
        param($World, [string]$Need = 'Send', [switch]$Resources, [hashtable]$State = (New-State), $Target = (Get-Target))
        Invoke-SIRunAccessCheck -Target $Target -PrincipalId $script:Oid -Need $Need -Resources:$Resources -Arm $World.Arm -State $State
    }
    function script:Get-Code([string]$Rel) { Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel) -Raw }
}

Describe 'what a run sends to, from its settings (pure)' {
    It 'the subscription, resource group and name of the workspace are read from its resource id' {
        $t = Resolve-SIRunAccessTarget -Values @{ SI_WorkspaceResourceId = $script:WsId; SI_DcrResourceGroup = 'rg-dcr' }
        $t.SubscriptionId | Should -Be $script:Sub
        $t.WorkspaceResourceGroup | Should -Be 'rg-si'
        $t.WorkspaceName | Should -Be 'log-si'
        $t.DcrResourceGroupId | Should -Be "/subscriptions/$($script:Sub)/resourceGroups/rg-dcr"
    }
    It 'with nothing set there is no subscription -- and then nothing is checked' {
        $t = Resolve-SIRunAccessTarget -Values @{}
        $t.SubscriptionId | Should -Be ''
        $w = New-World -Roles (Get-NarrowRoles)
        $r = Invoke-Check -World $w -Target $t -Resources
        $r.Checked | Should -BeFalse
        $r.Line | Should -Be ''
        $w.Calls.Count | Should -Be 0
    }
    It 'the storage account is checked only when its resource group is configured (it is reached by name)' {
        (Resolve-SIRunAccessTarget -Values @{ SI_AzSubscriptionId = $script:Sub; SI_StorageAccount = 'stsitest01' }).StorageAccountId | Should -Be ''
        (Get-Target).StorageAccountId | Should -Be $script:StId
    }
}

Describe 'which role allows what (pure)' {
    It 'a pattern covers an action with * and in any case; a "not" pattern takes it away again' {
        Test-SIRunAccessPattern -Pattern 'Microsoft.Insights/*' -Action 'microsoft.insights/dataCollectionRules/write' | Should -BeTrue
        Test-SIRunAccessPattern -Pattern '*/read' -Action 'Microsoft.Insights/dataCollectionRules/write' | Should -BeFalse
        Test-SIRunAccessAllowed -Definition @{ Actions = @('*'); NotActions = @('Microsoft.Insights/dataCollectionRules/*') } -Action 'Microsoft.Insights/dataCollectionRules/write' -DataAction $false | Should -BeFalse
        Test-SIRunAccessAllowed -Definition @{ Actions = @('*') } -Action 'Microsoft.Insights/Telemetry/Write' -DataAction $true | Should -BeFalse -Because 'a management wildcard is not a data action'
    }
    It 'a scope covers itself and everything below it, not its sibling' {
        Test-SIRunAccessScopeCovers -AssignmentScope "/subscriptions/$($script:Sub)" -NeededScope $script:RgId | Should -BeTrue
        Test-SIRunAccessScopeCovers -AssignmentScope $script:RgId.ToUpperInvariant() -NeededScope $script:RgId | Should -BeTrue
        Test-SIRunAccessScopeCovers -AssignmentScope "$($script:RgId)-other" -NeededScope $script:RgId | Should -BeFalse
        Test-SIRunAccessScopeCovers -AssignmentScope $script:WsId -NeededScope $script:RgId | Should -BeFalse
    }
    It 'the roles setup grants are the ones the check asks for' {
        $send = @(Get-SIRunAccessNeeds -Target (Get-Target) -Need Send)
        $send.Count | Should -Be 1
        $send[0].Role | Should -Be 'Monitoring Metrics Publisher'; $send[0].Scope | Should -Be $script:RgId
        $create = @(Get-SIRunAccessNeeds -Target (Get-Target) -Need Create)
        @($create | ForEach-Object { '{0}@{1}' -f $_.Role, $_.Scope }) | Should -Be @("Monitoring Contributor@$($script:RgId)", "Log Analytics Contributor@$($script:WsId)")
        $grant = Get-Code 'setup\Grant-SIIdentity.ps1'
        $grant | Should -Match "Role = 'Monitoring Contributor'; Scope = \`$dcrRgId"
        $grant | Should -Match "Role = 'Log Analytics Contributor'; Scope = \`$ws"
    }
    It 'Contributor may create but not send; Monitoring Metrics Publisher may send but not create' {
        $t = Get-Target
        $all = @(Get-SIRunAccessNeeds -Target $t -Need Send) + @(Get-SIRunAccessNeeds -Target $t -Need Create)
        $a = @([pscustomobject]@{ Scope = "/subscriptions/$($script:Sub)"; RoleDefinitionId = "/x/roleDefinitions/$($script:Role.Contributor)" })
        $v = @(Get-SIRunAccessVerdict -Needs $all -Assignments $a)
        @($v | ForEach-Object { '{0}={1}' -f $_.Need.Key, $_.State }) | Should -Be @('send=Missing', 'rule=Held', 'table=Held')
        $a = @([pscustomobject]@{ Scope = $script:RgId; RoleDefinitionId = "/x/roleDefinitions/$($script:Role.Mmp)" })
        $v = @(Get-SIRunAccessVerdict -Needs $all -Assignments $a)
        @($v | ForEach-Object { '{0}={1}' -f $_.Need.Key, $_.State }) | Should -Be @('send=Held', 'rule=Missing', 'table=Missing')
    }
    It 'a role whose definition was not read is Unknown, never Missing' {
        $a = @([pscustomobject]@{ Scope = $script:RgId; RoleDefinitionId = "/x/roleDefinitions/$($script:Role.Custom)" })
        $v = @(Get-SIRunAccessVerdict -Needs @(Get-SIRunAccessNeeds -Target (Get-Target) -Need Send) -Assignments $a -Definitions @{})
        $v[0].State | Should -Be 'Unknown'
        (Get-SIRunAccessLine -Verdicts $v -Target (Get-Target) -PrincipalId $script:Oid) | Should -Be ''
    }
}

Describe 'a run with the narrow roles setup gives: nothing is written, nothing is said' {
    BeforeAll {
        $script:W = New-World -Roles (Get-NarrowRoles)
        $script:R = Invoke-Check -World $script:W -Resources
    }
    It 'it says nothing' {
        $script:R.Checked | Should -BeTrue
        $script:R.Line | Should -Be ''
        @($script:R.Missing).Count | Should -Be 0
    }
    It 'it only reads: four lookups and ONE read of the role assignments -- no role definition, no second look' {
        $paths = @($script:W.Calls | ForEach-Object { $_.Path })
        $paths.Count | Should -Be 5
        @($paths | Where-Object { $_ -match 'roleAssignments' }).Count | Should -Be 1
        @($paths | Where-Object { $_ -match 'roleDefinitions' }).Count | Should -Be 0
        $paths | Should -Contain $script:WsId
        $paths | Should -Contain $script:RgId
        $paths | Should -Contain $script:DceId
        $paths | Should -Contain $script:StId
    }
    It 'the door to Azure has no method argument, and its real form is a GET' {
        $door = Get-SIRunAccessDefaultArm
        @($door.Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Be @('Path', 'ApiVersion', 'List')
        $door.ToString() | Should -Not -Match '-Method|-Body'
        $src = Get-Code 'engine\asset-profiling\shared\SI-RunAccessCheck.ps1'
        $src | Should -Not -Match '(?im)^[^#\r\n]*-Method\s+[''"]?(PUT|POST|PATCH|DELETE)'
        $src | Should -Not -Match '(?im)^[^#\r\n]*\b(New-SIAz\w+|New-SIRoleAssignment|New-Az\w+|Set-SIAz\w+|Update-SIAz\w+)\b'
    }
    It 'a second engine in the same process reads nothing again' {
        $st = New-State
        $w = New-World -Roles (Get-NarrowRoles)
        $null = Invoke-Check -World $w -Resources -State $st
        $n = $w.Calls.Count
        $null = Invoke-Check -World $w -Resources -State $st
        $w.Calls.Count | Should -Be $n
    }
    It 'the same roles held one level up (on the subscription) are held' {
        $w = New-World -Roles @((New-Assignment $script:Role.Mmp "/subscriptions/$($script:Sub)"))
        (Invoke-Check -World $w).Line | Should -Be ''
    }
}

Describe 'a missing role is ONE line with the setup command' {
    BeforeAll {
        # may read, may not send
        $script:W = New-World -Roles @((New-Assignment $script:Role.Reader "/subscriptions/$($script:Sub)"), (New-Assignment $script:Role.LaReader $script:WsId))
        $script:St = New-State
        $script:R = Invoke-Check -World $script:W -Resources -State $script:St
    }
    It 'names the role, where, and what it is for' {
        $script:R.Line | Should -Match '^access check: '
        $script:R.Line | Should -Match "does not hold Monitoring Metrics Publisher on resource group 'rg-si' \(to send rows to Log Analytics\)"
        $script:R.Line | Should -Match 'a run assigns no role, so nothing was changed'
        @($script:R.Missing | ForEach-Object { $_.Role }) | Should -Be @('Monitoring Metrics Publisher')
    }
    It 'carries the command with this install''s names, and -AllowSchemaCreate -Apply' {
        $cmd = "setup\Grant-SIIdentity.ps1 -PrincipalId $($script:Oid) -SubscriptionId $($script:Sub) -WorkspaceResourceId $($script:WsId) -StorageAccountName stsitest01 -StorageResourceGroup rg-si -DcrResourceGroup rg-si -AllowSchemaCreate -Apply"
        $script:R.Line.EndsWith($cmd) | Should -BeTrue
        $script:R.Line | Should -Not -Match '[\r\n]' -Because 'it is one line'
        $script:R.Line | Should -Not -Match '<[a-z ]+>' -Because 'no placeholder'
    }
    It 'every switch of that command exists in the script' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'setup\Grant-SIIdentity.ps1'), [ref]$null, [ref]$null)
        $have = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        foreach ($p in 'PrincipalId', 'SubscriptionId', 'WorkspaceResourceId', 'StorageAccountName', 'StorageResourceGroup', 'DcrResourceGroup', 'AllowSchemaCreate', 'Apply') { $have | Should -Contain $p }
    }
    It 'looked once more with group memberships before saying it -- still nothing was written' {
        @($script:W.Calls | Where-Object { [uri]::UnescapeDataString($_.Path) -match 'assignedTo\(' }).Count | Should -Be 1
    }
    It 'is said once per process' {
        (Invoke-Check -World $script:W -Resources -State $script:St).Line | Should -Be ''
    }
    It 'storage is left out of the command when where it is is not configured' {
        $t = Resolve-SIRunAccessTarget -Values @{ SI_AzSubscriptionId = $script:Sub; SI_WorkspaceResourceId = $script:WsId; SI_DcrResourceGroup = 'rg-si'; SI_StorageAccount = 'stsitest01' }
        $c = Get-SIRunAccessFixCommand -Target $t -PrincipalId $script:Oid
        $c | Should -Not -Match 'StorageAccountName'
        $c | Should -Match ' -DcrResourceGroup rg-si -AllowSchemaCreate -Apply$'
    }
}

Describe 'what cannot be read is never guessed: no line' {
    It 'the identity may not read its role assignments' {
        $w = New-World -RoleListRefused
        $r = Invoke-Check -World $w
        $r.Line | Should -Be ''
        $r.Checked | Should -BeFalse
        @($r.Missing).Count | Should -Be 0
    }
    It 'a role there whose definition cannot be read may be the one -- nothing is said' {
        $w = New-World -Roles @((New-Assignment $script:Role.Custom $script:RgId))
        (Invoke-Check -World $w).Line | Should -Be ''
    }
    It 'CONTROL: the same custom role, readable and not allowing the send, IS said' {
        $w = New-World -Roles @((New-Assignment $script:Role.Custom $script:RgId)) -Definitions @{ ($script:Role.Custom) = @([pscustomobject]@{ actions = @('*/read'); notActions = @(); dataActions = @(); notDataActions = @() }) }
        (Invoke-Check -World $w).Line | Should -Match 'does not hold Monitoring Metrics Publisher'
    }
    It 'a custom role whose definition allows the send is held' {
        $w = New-World -Roles @((New-Assignment $script:Role.Custom $script:RgId)) -Definitions @{ ($script:Role.Custom) = @([pscustomobject]@{ actions = @(); notActions = @(); dataActions = @('Microsoft.Insights/*/Write'); notDataActions = @() }) }
        $r = Invoke-Check -World $w
        $r.Line | Should -Be ''
        $r.Checked | Should -BeTrue
    }
    It 'a role held through a group is held' {
        $w = New-World -Roles @((New-Assignment $script:Role.Reader "/subscriptions/$($script:Sub)")) -GroupRoles @((New-Assignment $script:Role.Mmp $script:RgId))
        (Invoke-Check -World $w).Line | Should -Be ''
    }
    It 'a resource lookup that is refused says nothing about that resource' {
        $w = New-World -Roles (Get-NarrowRoles) -Refused @($script:WsId, $script:DceId, $script:StId, $script:RgId)
        (Invoke-Check -World $w -Resources).Line | Should -Be ''
    }
}

Describe 'the create roles are asked for only by a run that had something to create' {
    It 'the narrow roles without the create roles: one line naming both, with the same command' {
        $w = New-World -Roles (Get-NarrowRoles)
        $r = Invoke-Check -World $w -Need Create
        $r.Line | Should -Match "Monitoring Contributor on resource group 'rg-si' \(to create or extend a data collection rule\) and Log Analytics Contributor on workspace 'log-si' \(to create a table or add a column\)"
        $r.Line | Should -Match ' -AllowSchemaCreate -Apply$'
    }
    It 'with the two roles -AllowSchemaCreate grants: nothing is said' {
        $w = New-World -Roles (@(Get-NarrowRoles) + @((New-Assignment $script:Role.MonContrib $script:RgId), (New-Assignment $script:Role.LaContrib $script:WsId)))
        (Invoke-Check -World $w -Need Create).Line | Should -Be ''
    }
    It 'after the send check in the same process, the create check reads the role assignments from memory' {
        $st = New-State
        $w = New-World -Roles (@(Get-NarrowRoles) + @((New-Assignment $script:Role.MonContrib $script:RgId), (New-Assignment $script:Role.LaContrib $script:WsId)))
        $null = Invoke-Check -World $w -State $st
        $n = $w.Calls.Count
        $null = Invoke-Check -World $w -Need Create -State $st
        $w.Calls.Count | Should -Be $n
    }
    It 'the output stage knows from the create step''s own words whether it had something to create' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'), [ref]$null, [ref]$null)
        $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SIOutputSchemaChangeNeeded' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($f.Extent.Text))
        Test-SIOutputSchemaChangeNeeded -CreateOutput 'table SI_Endpoint_Profile_CL and rule dcr-si-endpoint-profile: every column is declared' | Should -BeFalse
        Test-SIOutputSchemaChangeNeeded -CreateOutput 'Existing table+DCR already match schema -- no create/update needed.' | Should -BeFalse
        Test-SIOutputSchemaChangeNeeded -CreateOutput 'data collection rule dcr-si-endpoint-profile: created on endpoint x with 40 column(s)' | Should -BeTrue
        Test-SIOutputSchemaChangeNeeded -CreateOutput 'Step 3 threw a terminating exception: AuthorizationFailed' | Should -BeTrue
        Test-SIOutputSchemaChangeNeeded -CreateOutput $null | Should -BeTrue
        # the two sentences are the ones the create step really says
        (Get-Code 'engine\_shared\SI-LogIngest.ps1') | Should -Match 'every column is declared'
        (Get-Code 'engine\asset-profiling\stages\Invoke-Output.ps1') | Should -Match 'Existing table\+DCR already match schema'
    }
    It 'WIRING: the output stage asks only then, and after the create step' {
        $o = Get-Code 'engine\asset-profiling\stages\Invoke-Output.ps1'
        $o | Should -Match '(?s)if \(Test-SIOutputSchemaChangeNeeded -CreateOutput \$_createOutput\) \{.{0,400}Write-SIRunAccessNote -Need Create'
        $o.IndexOf('Write-SIRunAccessNote -Need Create') | Should -BeGreaterThan $o.IndexOf('Update-SILogTableSchema `')
        @([regex]::Matches($o, 'Write-SIRunAccessNote')).Count | Should -Be 2 -Because 'one load check and one call'
    }
}

Describe 'something that does not exist is one line naming it and the setup script -- nothing is created' {
    It 'a workspace that is not there' {
        $w = New-World -Roles (Get-NarrowRoles) -Absent @($script:WsId)
        $r = Invoke-Check -World $w -Resources
        $r.Line | Should -Match "^access check: the Log Analytics workspace 'log-si' \(resource group 'rg-si'\) does not exist in subscription "
        $r.Line | Should -Match 'a run creates no Azure resource, so nothing was created'
        $r.Line | Should -Match 'setup\\ConfigWizard\\backend\\Initialize-SIInfra\.ps1'
        @($r.MissingResources).Count | Should -Be 1
        @($w.Calls | Where-Object { $_.Path -match 'roleAssignments' }).Count | Should -Be 0 -Because 'a role on something that is not there says nothing'
    }
    It 'several things missing are still ONE line' {
        $w = New-World -Roles (Get-NarrowRoles) -Absent @($script:WsId, $script:RgId, $script:StId)
        $r = Invoke-Check -World $w -Resources
        @($r.MissingResources).Count | Should -Be 3
        $r.Line | Should -Match ' do not exist in subscription '
        $r.Line | Should -Not -Match '[\r\n]'
    }
    It 'an endpoint that is not in its resource group but IS in the subscription is not missing (the send finds it there)' {
        $w = New-World -Roles (Get-NarrowRoles) -Absent @($script:DceId) -EndpointsInSubscription @([pscustomobject]@{ name = 'dce-si'; id = '/subscriptions/x/resourceGroups/other/providers/Microsoft.Insights/dataCollectionEndpoints/dce-si' })
        (Invoke-Check -World $w -Resources).Line | Should -Be ''
    }
    It 'an endpoint that is nowhere in the subscription is missing' {
        $w = New-World -Roles (Get-NarrowRoles) -Absent @($script:DceId) -EndpointsInSubscription @([pscustomobject]@{ name = 'dce-other'; id = 'x' })
        (Invoke-Check -World $w -Resources).Line | Should -Match "the data collection endpoint 'dce-si' does not exist"
    }
    It 'without -Resources (the create check) no resource is looked up' {
        $w = New-World -Roles (Get-NarrowRoles) -Absent @($script:WsId)
        $null = Invoke-Check -World $w -Need Create
        @($w.Calls | Where-Object { $_.Path -eq $script:WsId }).Count | Should -Be 0
    }
}

Describe 'WIRING: the run' {
    BeforeAll { $script:Run = Get-Code 'engine\asset-profiling\Invoke-SIEngineRun.ps1' }
    It 'has no create or grant step left, and the old file is gone' {
        $script:Run | Should -Not -Match 'Invoke-SIPrestageInfra|SI_PrestageInfra'
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Invoke-SIPrestageInfra.ps1') | Should -BeFalse
    }
    It 'checks once, where it starts -- not in a worker of a run collected in parts' {
        $script:Run | Should -Match "if \(\`$Phase -ne 'parts'\) \{ Write-SIRunAccessNote -Target \`$_acc -Need Send -Resources \}"
    }
    It 'still resolves the names the later stages read (before the storage context is built)' {
        foreach ($g in 'SI_WorkspaceResourceId', 'SI_DceName', 'SI_DcrResourceGroup', 'SI_DceResourceGroup', 'SI_AzSubscriptionId') {
            $script:Run | Should -Match ("if \(-not \`$global:{0}\)\s+\{{ \`$global:{0}\s+= \`$_acc\." -f $g)
        }
        $script:Run.IndexOf('Resolve-SIRunAccessTarget') | Should -BeLessThan $script:Run.IndexOf('$ctx = New-SIStorageContext -AccountName')
    }
    It 'a failing check never stops the run' {
        $script:Run | Should -Match "(?s)Write-SIRunAccessNote -Target.{0,200}\} catch \{\s+Write-Verbose \('access check skipped"
        (Get-Code 'engine\asset-profiling\shared\SI-RunAccessCheck.ps1') | Should -Match "(?s)function Write-SIRunAccessNote \{.{0,900}try \{.{0,700}\} catch \{ Write-Verbose"
    }
    It 'setup no longer writes the setting that switched the old step into a new configuration' {
        foreach ($rel in 'setup\ConfigWizard\backend\Write-SICustomConfig.ps1', 'setup\ConfigWizard\app.js') { (Get-Code $rel) | Should -Not -Match 'SI_PrestageInfra' }
    }
}

Describe 'GUARD: no collection source assigns a role or creates a resource group, workspace, endpoint or storage account' {
    BeforeAll {
        # Everything a job runs: the engines, the container entry points, the launchers and the sign-in. Setup, the
        # bootstrap scripts and the updater are where roles are assigned and resources are created -- not scanned.
        $script:Scanned = @(foreach ($d in 'engine', 'container', 'launcher', 'auth') {
            $dir = Join-Path $script:SIRoot $d
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            Get-ChildItem -LiteralPath $dir -Recurse -File |
                Where-Object { $_.Extension -in '.ps1', '.psm1' -and $_.FullName.Substring($script:SIRoot.Length + 1).Replace('/', '\') -notlike 'container\updater\*' }
        })
        $script:WriteCommands = @('New-SIAzRoleAssignment', 'New-SIRoleAssignment', 'New-AzRoleAssignment', 'New-SIAzResourceGroup', 'New-AzResourceGroup',
                                  'New-SIAzOperationalInsightsWorkspace', 'New-AzOperationalInsightsWorkspace', 'New-SIAzDataCollectionEndpoint',
                                  'New-AzDataCollectionEndpoint', 'New-SIAzStorageAccount', 'New-AzStorageAccount')
        # The files that still CAN, each with the reason. A new one fails this test until it is taken out or listed here.
        $script:Allowed = [ordered]@{
            'engine\_shared\SI-AzRest.ps1'    = 'the one place the calls are DEFINED -- setup calls them, no collection source does'
            'engine\_shared\SI-LogIngest.ps1' = 'the per-rule grant option of the ingestion client: off for every caller (asserted below)'
            'engine\risk-analysis\_shared\Ensure-SecurityInsightInfra.ps1'     = 'Risk Analysis, not a collection run: its own older self-repair of the endpoint and its roles'
            'engine\risk-analysis\_shared\Send-SecurityInsightExportFile.ps1' = 'Risk Analysis, not a collection run: the report upload grants its container role'
        }
        function script:Get-WriteHits([System.IO.FileInfo]$File) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$null, [ref]$null)
            $hits = New-Object System.Collections.Generic.List[string]
            foreach ($c in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) {
                $name = [string]$c.GetCommandName()
                if ($script:WriteCommands -contains $name) { $hits.Add(('{0} (line {1})' -f $name, $c.Extent.StartLineNumber)); continue }
                $text = $c.Extent.Text
                if ($text -match '(?i)roleAssignments' -and $text -match '(?i)-Method\s+[''"]?(PUT|POST|PATCH|DELETE)\b') { $hits.Add(('a role assignment write (line {0})' -f $c.Extent.StartLineNumber)) }
            }
            $hits.ToArray()
        }
        $script:Hits = @{}
        foreach ($f in $script:Scanned) {
            $rel = $f.FullName.Substring($script:SIRoot.Length + 1).Replace('/', '\')
            $h = @(Get-WriteHits $f)
            if ($h.Count) { $script:Hits[$rel] = $h }
        }
    }
    It 'the scan sees the collection engine, the container entry points and the check itself' {
        $rels = @($script:Scanned | ForEach-Object { $_.FullName.Substring($script:SIRoot.Length + 1).Replace('/', '\') })
        foreach ($must in 'engine\asset-profiling\Invoke-SIEngineRun.ps1', 'engine\asset-profiling\stages\Invoke-Output.ps1', 'engine\asset-profiling\shared\SI-RunAccessCheck.ps1',
                          'engine\data-model\SI-RecordHandover.ps1', 'container\Start-SIInContainer.ps1', 'container\Invoke-ShardProducer.ps1') { $rels | Should -Contain $must }
        @($rels | Where-Object { $_ -like 'container\updater\*' }).Count | Should -Be 0
    }
    It 'CONTROL: the scan recognises a role assignment write and a create call where they are defined' {
        $script:Hits.ContainsKey('engine\_shared\SI-AzRest.ps1') | Should -BeTrue
        @($script:Hits['engine\_shared\SI-AzRest.ps1'] | Where-Object { $_ -like 'a role assignment write*' }).Count | Should -BeGreaterThan 0
        $script:Hits.ContainsKey('engine\_shared\SI-LogIngest.ps1') | Should -BeTrue
    }
    It 'no file outside the list writes a role assignment or creates one of those resources' {
        $bad = @($script:Hits.Keys | Where-Object { -not $script:Allowed.Contains($_) } | Sort-Object | ForEach-Object { '{0}: {1}' -f $_, (@($script:Hits[$_]) -join ', ') })
        $bad | Should -BeNullOrEmpty -Because 'a run assigns no role and creates no resource -- setup does (setup\, the bootstrap scripts, the updater)'
    }
    It 'every file on the list still does it (a cleaned-up file leaves the list)' {
        foreach ($k in $script:Allowed.Keys) { $script:Hits.ContainsKey($k) | Should -BeTrue -Because "$k is listed: $($script:Allowed[$k])" }
    }
    It 'nothing under the collection engine or the container entry points is on the list' {
        @($script:Allowed.Keys | Where-Object { $_ -like 'engine\asset-profiling\*' -or $_ -like 'engine\data-model\*' -or $_ -like 'container\*' }).Count | Should -Be 0
    }
    It 'the ingestion client''s per-rule grant is OFF for every caller, and off by default' {
        $on = New-Object System.Collections.Generic.List[string]
        foreach ($f in $script:Scanned) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) {
                $el = @($c.CommandElements)
                for ($i = 0; $i -lt $el.Count; $i++) {
                    if ($el[$i] -isnot [System.Management.Automation.Language.CommandParameterAst] -or $el[$i].ParameterName -ne 'AzDcrSetLogIngestApiAppPermissionsDcrLevel') { continue }
                    $val = if ($el[$i].Argument) { $el[$i].Argument.Extent.Text } elseif ($i + 1 -lt $el.Count) { $el[$i + 1].Extent.Text } else { '' }
                    # the client hands its own argument on (a pass-through of what its caller gave); every other caller gives $false
                    if ($val -ne '$false' -and $val -ne '$AzDcrSetLogIngestApiAppPermissionsDcrLevel') { $on.Add(('{0}:{1} {2}' -f $f.Name, $c.Extent.StartLineNumber, $val)) }
                }
            }
        }
        $on.ToArray() | Should -BeNullOrEmpty
        (Get-Code 'engine\_shared\SI-LogIngest.ps1') | Should -Match '\[boolean\]\$AzDcrSetLogIngestApiAppPermissionsDcrLevel = \$false'
    }
}

Describe 'setup creates what a new install needs, and grants the narrow roles -- not plain Contributor' {
    It 'Initialize-SIInfra (the guided install and the unattended setup run it) creates the resource groups, the workspace, the endpoint and the storage account' {
        $c = Get-Code 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1'
        foreach ($call in 'New-SIAzResourceGroup', 'New-SIAzOperationalInsightsWorkspace', 'New-SIAzStorageAccount') { $c | Should -Match ([regex]::Escape($call)) }
        $c | Should -Match 'Invoke-SIArm -Method PUT -Path \$dcePath'
        (Get-Code 'setup\_shared\SI-GuidedInstall.ps1') | Should -Match "RelativePath 'setup/ConfigWizard/backend/Initialize-SIInfra.ps1'"
        (Get-Code 'Setup-SecurityInsight-Unattended.ps1') | Should -Match '\$infraOut = & \$cmdletInitInfra @infraArgs'
    }
    It '<_> grants no plain Contributor any more, and grants the roles a run needs to create its tables and rules' -ForEach @(
        'setup\ConfigWizard\backend\Initialize-SIInfra.ps1', 'setup\Validate-SILogAnalytics.ps1'
    ) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $_), [ref]$null, [ref]$null)
        # every role name written as a string in the file (comments are not strings)
        $roles = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
        $roles | Should -Not -Contain 'Contributor'
        $roles | Should -Contain 'Monitoring Metrics Publisher'
        $roles | Should -Contain 'Monitoring Contributor'
        $roles | Should -Contain 'Log Analytics Contributor'
    }
}
