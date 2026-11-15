<#
    SECURE-WEB-1 (framework 12.11f, Invardia 2026-11-14): the internet-facing identities (the web app with its sign-in front,
    the MCP app) hold NO job, Owner / Contributor, role-assignment, registry-push or vault-admin right.
      - the rights list marks web + mcp internetFacing and lists none of the forbidden roles for them (the gate lint), and
        every Key Vault role on them is held only without the built-in sign-in (one named open item: magic links)
      - the updater's converge removes such an assignment at the resource group or below, READS IT BACK, says one above the
        group as a support step, and a read that fails is "not checked" -- never "clean"
      - the identity move never copies a forbidden role to web / mcp (it still copies it to the engine)
      - the updater runs the converge on every run, before the apply-settings return (wiring, asserted separately)
    Offline: ARM is a fake in script scope.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-WebJobRights.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-IdentityMove.ps1')
    $script:Sub = '00000000-0000-0000-0000-000000000001'
    $script:Rg = "/subscriptions/$($script:Sub)/resourceGroups/rg-si"
    $script:JobsContrib = '4e3d2b60-56ae-4dc6-a233-09c8e5a82e68'
    $script:JobsOperator = 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b'
    $script:KvCryptoUser = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
    function New-Assign([string]$Id, [string]$Principal, [string]$RoleGuid, [string]$Scope) {
        [pscustomobject]@{ id = $Id; properties = [pscustomobject]@{ principalId = $Principal; roleDefinitionId = "/subscriptions/$($script:Sub)/providers/Microsoft.Authorization/roleDefinitions/$RoleGuid"; scope = $Scope } }
    }
    function New-App([string]$Name, [string]$Principal) {
        [pscustomobject]@{ name = $Name; identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ "/subscriptions/x/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-$Name" = [pscustomobject]@{ principalId = $Principal; clientId = 'c' } } } }
    }
    function New-FakeArm {
        $script:Fake = @{ Apps = @(); Jobs = @(); Assign = New-Object System.Collections.Generic.List[object]; Deletes = New-Object System.Collections.Generic.List[string]; Sticky = @{}; FailRead = $false }
        { param([string]$Method, [string]$Path, [string]$ApiVersion)
            $f = $script:Fake
            if ($Method -eq 'GET' -and $Path -like '*/providers/Microsoft.App/containerApps') { if ($f.FailRead) { throw 'HTTP 403: AuthorizationFailed' }; return [pscustomobject]@{ value = @($f.Apps) } }
            if ($Method -eq 'GET' -and $Path -like '*/providers/Microsoft.App/jobs') { return [pscustomobject]@{ value = @($f.Jobs) } }
            if ($Method -eq 'GET' -and $Path -like '*/roleAssignments?$filter=*') {
                $p = [uri]::UnescapeDataString($Path) -replace "^.*principalId eq '([^']+)'.*$", '$1'
                return [pscustomobject]@{ value = @($f.Assign | Where-Object { $_.properties.principalId -eq $p }) }
            }
            if ($Method -eq 'GET') { return @($f.Assign | Where-Object { $_.id -eq $Path })[0] }
            if ($Method -eq 'DELETE') { $f.Deletes.Add($Path); if (-not $f.Sticky.ContainsKey($Path)) { foreach ($a in @($f.Assign | Where-Object { $_.id -eq $Path })) { $null = $f.Assign.Remove($a) } }; return $null }
            throw "unexpected $Method $Path"
        }
    }
}

Describe 'SECURE-WEB-1: the rights list (gate lint)' {
    BeforeAll { $script:Rights = Get-Content (Join-Path $script:SIRoot 'setup\_shared\si-identity-rights.json') -Raw | ConvertFrom-Json }
    It 'marks the web and MCP identities internet-facing' {
        @($script:Rights.identities | Where-Object { $_.internetFacing } | ForEach-Object { $_.role } | Sort-Object) | Should -Be @('mcp', 'web')
    }
    It 'gives no internet-facing identity a forbidden role (by role definition id or by name)' {
        $names = @($script:SIWebForbiddenRoleGuids.Values)
        foreach ($i in @($script:Rights.identities | Where-Object { $_.internetFacing })) {
            foreach ($r in @($i.rights)) {
                if ($r.PSObject.Properties['roleDefinitionId'] -and [string]$r.roleDefinitionId) { Get-SIWebForbiddenRoleName -RoleDefinitionId ([string]$r.roleDefinitionId) | Should -BeNullOrEmpty -Because "$($r.id) is on an internet-facing identity" }
                if ([string]$r.kind -eq 'azure-rbac') { $names | Should -Not -Contain ([string]$r.value) -Because "$($r.id) is on an internet-facing identity" }
            }
        }
    }
    It 'gives no internet-facing identity a standing Key Vault role: each one is held only without the built-in sign-in' {
        # the ONE named exception: the magic-link secret read (conditional, off by default) -- an open item, never a pattern
        $openItem = @('web.keyvault.SecretsUserMagicLinks')
        $kv = @(foreach ($i in @($script:Rights.identities | Where-Object { $_.internetFacing })) {
                @($i.rights | Where-Object { [string]$_.kind -eq 'keyvault' -or [string]$_.value -match '^(?i)Key Vault\b' }) })
        $kv.Count | Should -BeGreaterThan 0 -Because 'the web identity''s key roles are listed (and explained)'
        foreach ($r in $kv) {
            if ($openItem -contains [string]$r.id) { [string]$r.status | Should -Be 'conditional' -Because $r.id; continue }
            [string]$r.status | Should -Be 'only-without-built-in-signin' -Because "$($r.id) is a Key Vault role on an internet-facing identity"
            [string]$r.note | Should -Match 'Invoke-SIBuiltInAuthKeyRingMove' -Because "$($r.id) names what takes it away"
        }
        @($script:Rights.statusValues.PSObject.Properties.Name) | Should -Contain 'only-without-built-in-signin'
    }
    It 'gives no internet-facing identity a right to send mail or a Graph / Exchange WRITE right' {
        foreach ($i in @($script:Rights.identities | Where-Object { $_.internetFacing })) {
            foreach ($r in @($i.rights | Where-Object { [string]$_.kind -match '^(graph|exchange)' -or [string]$_.id -match '\.(graph|exchange)\.' })) {
                [string]$r.value | Should -Not -Match '(?i)Mail\.Send|ReadWrite|\.Write\b|FullAccess|SendAs' -Because "$($r.id) is on an internet-facing identity"
            }
        }
    }
    It 'the mail setup never gives the web app''s or the MCP app''s identity Mail.Send (default exclusion)' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Set-SIMail.ps1'))
        $m = [regex]::Match($s, "\[string\]\`$ExcludeIdentityPattern = '([^']+)'")
        $m.Success | Should -BeTrue
        foreach ($n in 'ca-si-management', 'id-si-web', 'uami-si-management', 'ca-si-mcp', 'id-si-mcp') { $n | Should -Match $m.Groups[1].Value }
        foreach ($n in 'id-si-engine', 'id-si-updater', 'uami-securityinsight', 'caj-si-close-loop-mail') { $n | Should -Not -Match $m.Groups[1].Value -Because 'the mail senders keep their right' }
    }
    It 'the identity move and the converge forbid the same roles' {
        @($script:SIInternetFacingForbiddenRoleGuids.Keys | Sort-Object) | Should -Be @($script:SIWebForbiddenRoleGuids.Keys | Sort-Object)
    }
}

Describe 'SECURE-WEB-1: the plan' {
    It 'removes a forbidden role at the group or below, says one above it, keeps allowed roles and other principals' {
        $princ = @([pscustomobject]@{ PrincipalId = 'pid-web'; App = 'ca-si-management'; Identity = 'id-si-web' })
        $a = @(
            (New-Assign 'a1' 'pid-web' $script:JobsContrib $script:Rg),
            (New-Assign 'a2' 'pid-web' $script:JobsOperator "$($script:Rg)/providers/Microsoft.App/jobs/caj-si-flow"),
            (New-Assign 'a3' 'pid-web' $script:JobsContrib "/subscriptions/$($script:Sub)"),
            (New-Assign 'a4' 'pid-web' $script:KvCryptoUser "$($script:Rg)/providers/Microsoft.KeyVault/vaults/kv/keys/k"),
            (New-Assign 'a5' 'pid-engine' $script:JobsContrib $script:Rg))
        $p = Get-SIWebJobRightsPlan -Assignments $a -Principals $princ -ResourceGroupId $script:Rg
        @($p.Remove | ForEach-Object Id | Sort-Object) | Should -Be @('a1', 'a2')
        @($p.Above | ForEach-Object Id) | Should -Be @('a3')
    }
    It 'a resource group whose name only starts like the install''s is not inside it' {
        Test-SIScopeInResourceGroup -Scope "$($script:Rg)-other" -ResourceGroupId $script:Rg | Should -BeFalse
        Test-SIScopeInResourceGroup -Scope "$($script:Rg)/providers/x" -ResourceGroupId $script:Rg | Should -BeTrue
    }
}

Describe 'SECURE-WEB-1: the converge' {
    BeforeEach { $script:Arm = New-FakeArm; $script:NoSleep = { param($s) } }
    It 'removes the web and MCP job rights and reads each removal back' {
        $script:Fake.Apps = @((New-App 'ca-si-management' 'pid-web'), (New-App 'ca-si-mcp' 'pid-mcp'))
        $script:Fake.Assign.Add((New-Assign "$($script:Rg)/providers/Microsoft.Authorization/roleAssignments/r1" 'pid-web' $script:JobsContrib $script:Rg))
        $script:Fake.Assign.Add((New-Assign "$($script:Rg)/providers/Microsoft.Authorization/roleAssignments/r2" 'pid-mcp' $script:JobsOperator $script:Rg))
        $script:Fake.Assign.Add((New-Assign "$($script:Rg)/providers/Microsoft.Authorization/roleAssignments/r3" 'pid-web' $script:KvCryptoUser $script:Rg))
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep
        $r.State | Should -Be 'removed'; $r.Ok | Should -BeTrue
        @($script:Fake.Assign | ForEach-Object { ($_.id -split '/')[-1] }) | Should -Be @('r3') -Because 'the key wrap role is the web''s own data right'
        @($r.Lines | Where-Object { $_ -match 'REMOVED \(read back\)' }).Count | Should -Be 2
    }
    It 'a removal that does not read back is a failure, never "removed"' {
        $script:Fake.Apps = @((New-App 'ca-si-management' 'pid-web'))
        $id = "$($script:Rg)/providers/Microsoft.Authorization/roleAssignments/r1"
        $script:Fake.Assign.Add((New-Assign $id 'pid-web' $script:JobsContrib $script:Rg)); $script:Fake.Sticky[$id] = $true
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep -ReadBackTries 2
        $r.Ok | Should -BeFalse; $r.State | Should -Be 'partial'; @($r.Failed).Count | Should -Be 1
        @($r.Lines | Where-Object { $_ -match 'NOT removed' }).Count | Should -Be 1
    }
    It 'an identity shared by the internet-facing app and a JOB is never stripped: a SECURITY support step instead' {
        $script:Fake.Apps = @((New-App 'ca-si-management' 'pid-shared'))
        $script:Fake.Jobs = @((New-App 'caj-si-flow' 'pid-shared'))
        $script:Fake.Assign.Add((New-Assign "$($script:Rg)/providers/Microsoft.Authorization/roleAssignments/r1" 'pid-shared' $script:JobsContrib $script:Rg))
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep
        $script:Fake.Deletes.Count | Should -Be 0 -Because 'the job may need the right mid-run'
        $r.Ok | Should -BeFalse; $r.State | Should -Be 'partial'; @($r.Shared).Count | Should -Be 1
        @($r.Lines | Where-Object { $_ -match '^SECURITY support step: identity .* is shared by the internet-facing app ca-si-management and the job\(s\) caj-si-flow' }).Count | Should -Be 1
    }
    It 'one above the resource group is a support step, never removed by the updater' {
        $script:Fake.Apps = @((New-App 'ca-si-management' 'pid-web'))
        $script:Fake.Assign.Add((New-Assign "/subscriptions/$($script:Sub)/providers/Microsoft.Authorization/roleAssignments/s1" 'pid-web' $script:JobsContrib "/subscriptions/$($script:Sub)"))
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep
        $script:Fake.Deletes.Count | Should -Be 0
        $r.Ok | Should -BeFalse; @($r.Lines | Where-Object { $_ -match '^support step:' }).Count | Should -Be 1
    }
    It 'nothing forbidden held = clean, nothing written' {
        $script:Fake.Apps = @((New-App 'ca-si-management' 'pid-web'))
        $script:Fake.Assign.Add((New-Assign 'k1' 'pid-web' $script:KvCryptoUser $script:Rg))
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep
        $r.State | Should -Be 'clean'; $r.Ok | Should -BeTrue; $script:Fake.Deletes.Count | Should -Be 0
    }
    It 'a read that fails is "not checked" -- never "clean" -- and never throws' {
        $script:Fake.FailRead = $true
        $r = Invoke-SIWebJobRightsConverge -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Sleep $script:NoSleep
        $r.State | Should -Be 'not-checked'; $r.Ok | Should -BeFalse
        @($r.Lines | Where-Object { $_ -match 'NOT CHECKED' }).Count | Should -Be 1
    }
}

Describe 'SECURE-WEB-1: the identity move never copies a forbidden role to web / mcp' {
    It 'web and mcp: the job right of the old identity is left out; the engine still gets it' {
        $old = @(
            [pscustomobject]@{ PrincipalId = 'old'; RoleGuid = $script:JobsContrib; Scope = $script:Rg },
            [pscustomobject]@{ PrincipalId = 'old'; RoleGuid = $script:KvCryptoUser; Scope = $script:Rg })
        foreach ($role in 'web', 'mcp', 'WEB') {
            @(Get-SIIdentityMoveAzureCopyPlan -Old $old -New @() -OldPrincipalId 'old' -NewPrincipalId 'new' -Role $role | ForEach-Object RoleGuid) | Should -Be @($script:KvCryptoUser)
        }
        @(Get-SIIdentityMoveAzureCopyPlan -Old $old -New @() -OldPrincipalId 'old' -NewPrincipalId 'new' -Role 'engine' | ForEach-Object RoleGuid | Sort-Object) | Should -Be @(@($script:JobsContrib, $script:KvCryptoUser) | Sort-Object)
    }
    It 'the copy plan is built with the selection''s role (wiring)' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-IdentityMove.ps1'))
        $s | Should -Match 'Get-SIIdentityMoveAzureCopyPlan -Old \$o\.Azure -New \$nAz -OldPrincipalId \$sel\.Old\.PrincipalId -NewPrincipalId \$newPid -Role \(\[string\]\$sel\.Role\)'
    }
}

Describe 'SECURE-WEB-1: the updater wiring' {
    BeforeAll { $script:Upd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) }
    It 'runs the converge on every run, BEFORE the apply-settings early return' {
        $call = $script:Upd.IndexOf('$null = Invoke-SIUpdaterWebJobRightsStep -SubscriptionId $sub -ResourceGroup $rg')
        $ret = $script:Upd.IndexOf("if (`$updMode -eq 'apply-settings') {")
        $call | Should -BeGreaterThan 0; $ret | Should -BeGreaterThan 0
        $call | Should -BeLessThan $ret
    }
    It 'loads the library from the release tree and reports a removal that did not read back' {
        $script:Upd | Should -Match "'setup', '_shared', 'SI-WebJobRights\.ps1'"
        $script:Upd | Should -Match "Add-SIUpdaterFailureIf 'web-rights'"
    }
    It 'the step never throws when the library is missing (a WARNING line, $null)' {
        $null = New-Item -ItemType Directory -Force (Join-Path $TestDrive 'upd')
        # the step function alone, out of the updater script (it needs Write-UpdLog and Add-SIUpdaterFailureIf)
        $m = [regex]::Match($script:Upd, '(?ms)^function Invoke-SIUpdaterWebJobRightsStep \{.*?^\}')
        $m.Success | Should -BeTrue
        $script:Log = New-Object System.Collections.Generic.List[string]
        function Write-UpdLog([string]$t) { $script:Log.Add($t) }
        function Add-SIUpdaterFailureIf([string]$Step, [string]$Text) { }
        . ([scriptblock]::Create($m.Value))
        $siAutoRoot = ''
        Invoke-SIUpdaterWebJobRightsStep -SubscriptionId 's' -ResourceGroup 'r' -Lib (Join-Path $TestDrive 'missing.ps1') | Should -BeNullOrEmpty
        @($script:Log | Where-Object { $_ -match '^WARNING: internet-facing identities: not checked' }).Count | Should -Be 1
    }
}
