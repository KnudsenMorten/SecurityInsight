#Requires -Version 5.1
<#
    SI #1268 (the owner's approved rights list, 2026-11-15) -- GRANTED IN SETUP, READ BACK:
      * the updater identity: Microsoft Graph Application.ReadWrite.OwnedBy + OWNER of the web app's sign-in app registration
        (setup/_shared/SI-UpdaterSigninRights.ps1 Grant-SIUpdaterSigninRights; setup/Install-SIUpdaterJob.ps1;
        pro-management/deploy/New-SIManagementAppRegistration.ps1 step 4b), each only when missing, each read back; a refusal
        is one customer step, never a stop;
      * the engine identity: Container Apps Jobs Contributor on the install resource group in setup/Grant-SIIdentity.ps1's
        engine plan (container/_shared/SI-ContainerConfig.ps1 Get-SIEngineJobsGrant) -- only where SI's jobs are, read back.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup/_shared/SI-UpdaterSigninRights.ps1')
    . (Join-Path $script:SIRoot 'container/_shared/SI-ContainerConfig.ps1')
    # a fake Graph: the Graph service principal with its roles, the updater's app-role assignments, the sign-in app's owners
    function script:New-Graph([switch]$HasRole, [switch]$IsOwner, [switch]$RefuseRole, [switch]$RefuseOwner, [switch]$NoReadBack) {
        $s = [pscustomobject]@{ Roles = (New-Object System.Collections.Generic.List[object]); Owners = (New-Object System.Collections.Generic.List[string]); Calls = (New-Object System.Collections.Generic.List[string]); Bodies = (New-Object System.Collections.Generic.List[object]) }
        if ($HasRole) { $s.Roles.Add([pscustomobject]@{ resourceId = 'graph-sp'; appRoleId = 'r-owned' }) }
        if ($IsOwner) { $s.Owners.Add('p-upd') }
        $f = [pscustomobject]@{ RefuseRole = [bool]$RefuseRole; RefuseOwner = [bool]$RefuseOwner; NoReadBack = [bool]$NoReadBack }
        $g = {
            param([string]$Method, [string]$Uri, $Body)
            $s.Calls.Add("$Method $Uri"); if ($null -ne $Body) { $s.Bodies.Add($Body) }
            if ($Uri -match "appId eq '00000003-0000-0000-c000-000000000000'") {
                return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'graph-sp'; appRoles = @(
                    [pscustomobject]@{ id = 'r-other'; value = 'Application.ReadWrite.All'; allowedMemberTypes = @('Application') }
                    [pscustomobject]@{ id = 'R-OWNED'; value = 'Application.ReadWrite.OwnedBy'; allowedMemberTypes = @('Application') }) }) }
            }
            if ($Uri -match '/servicePrincipals/p-upd/appRoleAssignments$') {
                if ($Method -eq 'POST') { if ($f.RefuseRole) { throw 'HTTP 403 Authorization_RequestDenied: Insufficient privileges' }; if (-not $f.NoReadBack) { $s.Roles.Add([pscustomobject]@{ resourceId = $Body.resourceId; appRoleId = $Body.appRoleId }) }; return $null }
                return [pscustomobject]@{ value = $s.Roles.ToArray() }
            }
            if ($Uri -match "/applications\(appId='c-signin'\)") { return [pscustomobject]@{ id = 'app-obj'; appId = 'c-signin' } }
            if ($Uri -match '/applications/app-obj/owners/\$ref$') { if ($f.RefuseOwner) { throw 'HTTP 403 Authorization_RequestDenied' }; if (-not $f.NoReadBack) { $s.Owners.Add('p-upd') }; return $null }
            if ($Uri -match '/applications/app-obj/owners') { return [pscustomobject]@{ value = @($s.Owners | ForEach-Object { [pscustomobject]@{ id = $_ } }) } }
            throw "unexpected $Method $Uri"
        }.GetNewClosure()
        [pscustomobject]@{ State = $s; Graph = $g }
    }
}

Describe 'the updater identity''s rights on the sign-in app (Grant-SIUpdaterSigninRights)' {
    It 'both missing: the role by value (its id from Graph''s own appRoles) and the owner are added -- each READ BACK' {
        $w = New-Graph
        $r = Grant-SIUpdaterSigninRights -Graph $w.Graph -PrincipalId 'p-upd' -SigninClientId 'c-signin' -Apply -Sleep { param($s) }
        $r.Ok | Should -BeTrue; $r.RoleOk | Should -BeTrue; $r.OwnerOk | Should -BeTrue
        $post = @($w.State.Bodies | Where-Object { $_.Contains('appRoleId') })[0]
        $post.appRoleId | Should -Be 'r-owned'; $post.principalId | Should -Be 'p-upd'; $post.resourceId | Should -Be 'graph-sp'
        @($w.State.Bodies | Where-Object { $_.Contains('@odata.id') })[0].'@odata.id' | Should -Be 'https://graph.microsoft.com/v1.0/directoryObjects/p-upd'
        ($r.Lines -join "`n") | Should -Match 'given the Microsoft Graph application permission Application\.ReadWrite\.OwnedBy \(read back\)'
        ($r.Lines -join "`n") | Should -Match 'made an owner of the sign-in app registration \(read back\)'
        # the owner is never added before it is read
        $c = [string[]]@($w.State.Calls)
        [array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'GET */owners*' }) | Should -BeLessThan ([array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'POST */owners/$ref' }))
    }
    It 'both present: nothing is written' {
        $w = New-Graph -HasRole -IsOwner
        $r = Grant-SIUpdaterSigninRights -Graph $w.Graph -PrincipalId 'p-upd' -SigninClientId 'c-signin' -Apply
        $r.Ok | Should -BeTrue
        @($w.State.Calls | Where-Object { $_ -notlike 'GET *' }) | Should -BeNullOrEmpty
    }
    It 'without -Apply: read only, the plan is said' {
        $w = New-Graph
        $r = Grant-SIUpdaterSigninRights -Graph $w.Graph -PrincipalId 'p-upd' -SigninClientId 'c-signin'
        $r.Ok | Should -BeFalse
        @($w.State.Calls | Where-Object { $_ -notlike 'GET *' }) | Should -BeNullOrEmpty
        ($r.Lines -join "`n") | Should -Match '^plan: the updater identity is given'
    }
    It 'a refusal is ONE customer step each -- it never throws; a grant that does not read back is said, never "done"' {
        $w = New-Graph -RefuseRole -RefuseOwner
        $r = Grant-SIUpdaterSigninRights -Graph $w.Graph -PrincipalId 'p-upd' -SigninClientId 'c-signin' -Apply -Sleep { param($s) }
        $r.Ok | Should -BeFalse
        @($r.Lines | Where-Object { $_ -like 'customer step:*' }).Count | Should -Be 2
        $w2 = New-Graph -NoReadBack
        $r2 = Grant-SIUpdaterSigninRights -Graph $w2.Graph -PrincipalId 'p-upd' -SigninClientId 'c-signin' -Apply -Sleep { param($s) } -ReadBackTries 2
        $r2.RoleOk | Should -BeFalse; $r2.OwnerOk | Should -BeFalse
        ($r2.Lines -join "`n") | Should -Match 'does not read back yet'
    }
    It 'no sign-in app known yet (a new install makes the web app later): the role is still given, the owner is said for the next run' {
        $w = New-Graph
        $r = Grant-SIUpdaterSigninRights -Graph $w.Graph -PrincipalId 'p-upd' -Apply -Sleep { param($s) }
        $r.RoleOk | Should -BeTrue; $r.OwnerOk | Should -BeFalse
        ($r.Lines -join "`n") | Should -Match 'not known to this run'
    }
    It 'WIRING: Install-SIUpdaterJob gives both with -GrantSpnRoles -UseManagedIdentity (the guided install), New-SIManagementAppRegistration with -UpdaterPrincipalId' {
        $iu = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup/Install-SIUpdaterJob.ps1'))
        $iu | Should -Match 'foreach \(\$l in @\(Invoke-SIUpdaterSigninAppRights -PrincipalId \(\[string\]\$uami\.PrincipalId\)\)\)'
        $iu | Should -Match "AzureAd__ClientId"
        $ar = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'pro-management/deploy/New-SIManagementAppRegistration.ps1'))
        $ar | Should -Match '\[string\]\$UpdaterPrincipalId'
        $ar | Should -Match 'Grant-SIUpdaterSigninRights -Graph \$updGraph -PrincipalId \$UpdaterPrincipalId'
        (Get-Content -Raw (Join-Path $script:SIRoot 'setup/_shared/SI-GuidedInstallData.ps1')) | Should -Match "RelativePath 'setup/Install-SIUpdaterJob.ps1'"
    }
}

Describe 'the engine identity''s Container Apps Jobs Contributor in Grant-SIIdentity (Get-SIEngineJobsGrant)' {
    It 'a container install (SI jobs in the resource group): the one role on the resource group, read back; a VM / Arc identity (no SI job): nothing' {
        $g = @(Get-SIEngineJobsGrant -ResourceGroupId '/subscriptions/s/resourceGroups/rg-si/' -Jobs @([pscustomobject]@{ name = 'caj-si-flow' }, [pscustomobject]@{ name = 'other' }))
        $g.Count | Should -Be 1
        $g[0].Kind | Should -Be 'AzureRole'; $g[0].Role | Should -Be 'Container Apps Jobs Contributor'
        $g[0].Scope | Should -Be '/subscriptions/s/resourceGroups/rg-si'; $g[0].ReadBack | Should -BeTrue
        @(Get-SIEngineJobsGrant -ResourceGroupId '/subscriptions/s/resourceGroups/rg-si' -Jobs @([pscustomobject]@{ name = 'other' })).Count | Should -Be 0
        @(Get-SIEngineJobsGrant -ResourceGroupId '' -Jobs @([pscustomobject]@{ name = 'caj-si-flow' })).Count | Should -Be 0
    }
    It 'WIRING: Grant-SIIdentity adds it to the engine plan from -JobsResourceGroup / -IdentityResourceGroup and reads a ReadBack grant back' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup/Grant-SIIdentity.ps1'))
        $t | Should -Match '\[string\]\$JobsResourceGroup'
        $t | Should -Match "@\(Get-SIEngineJobsGrant -ResourceGroupId \('/subscriptions/\{0\}/resourceGroups/\{1\}' -f \`$sub, \`$jobsRg\) -Jobs \`$jobsList\)"
        $t | Should -Match "if \(\`$g\.PSObject\.Properties\['ReadBack'\] -and \`$g\.ReadBack\)"
        $t | Should -Match "'NO-READ'"
        # the role-name lookup Grant-SIIdentity uses knows the role
        (Get-Content -Raw (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')) | Should -Match "Role = 'Container Apps Jobs Contributor'"
    }
}
