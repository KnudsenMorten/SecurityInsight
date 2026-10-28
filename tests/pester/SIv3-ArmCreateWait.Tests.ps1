#Requires -Version 7.0
<#
    AFTER A CREATE: WAIT UNTIL IT EXISTS AND IS READY -- AND NEVER CREATE OVER WHAT EXISTS.

    Why: 2026-10-12, a new customer install. The wait after a create returned at once on "not found", so a database
    server was "created" while Azure was still making it and everything sent to it seconds later was lost. And a create
    carries a size: sent over a database that exists (because its read failed, or because it answered "not found" for a
    moment while being resized) it would lower a database the customer raised.

    The rules these tests hold (setup\_shared\SI-SetupArm.ps1):
      * Wait-SIArmResourceReady polls THROUGH a 404, knows the readiness property per type, THROWS at its deadline and
        on a failed resource (with Azure's own words);
      * Test-SIArmResourceAbsent says "not there" only on two "not found" answers; any other failure throws;
      * New-SISqlServerEntraOnly / New-SISqlDatabaseArm never PUT over something that exists;
      * Invoke-SIRetryNotThereYet retries ONLY the "not there yet" answer -- a refusal stops at once;
      * the server's administrator is set WITH its kind and both are read back.
    Offline: Invoke-SIArm is a stub that answers from a list.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    # the stubs first (script scope), then the file: it only defines functions
    function script:Get-SISetupSubscriptionId { param([string]$SubscriptionId) if ($SubscriptionId) { $SubscriptionId } else { '00000000-0000-0000-0000-000000000001' } }
    function script:Get-SIAzRestTenantId { '00000000-0000-0000-0000-0000000000aa' }
    function script:Invoke-SIArm {
        param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$AllowNotFound, [switch]$List)
        $script:ArmCalls.Add([pscustomobject]@{ Method = $Method.ToUpperInvariant(); Path = $Path; ApiVersion = $ApiVersion; Body = $Body })
        if ($Method -ne 'GET') {
            if ($script:ArmWriteError) { $e = $script:ArmWriteError; if ($script:ArmWriteErrorOnce) { $script:ArmWriteError = $null }; throw $e }
            return $null
        }
        if ($script:ArmReads.Count -eq 0) { return $script:ArmLastRead }
        $next = $script:ArmReads[0]; $script:ArmReads.RemoveAt(0)
        if ($next -is [string] -and $next -like 'THROW:*') { throw $next.Substring(6) }
        $script:ArmLastRead = $next
        return $next
    }
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
    $script:NoSleep = { param($Seconds) $script:Slept.Add([int]$Seconds) }
    function script:Reset-ArmStub([object[]]$Reads = @()) {
        $script:ArmCalls = New-Object System.Collections.Generic.List[object]
        $script:ArmReads = New-Object System.Collections.Generic.List[object]
        foreach ($x in $Reads) { $script:ArmReads.Add($x) }
        $script:ArmLastRead = $null; $script:ArmWriteError = $null; $script:ArmWriteErrorOnce = $false
        $script:Slept = New-Object System.Collections.Generic.List[int]
    }
    function script:New-ArmThing([string]$State, [string]$Property = 'provisioningState', [hashtable]$More = @{}) {
        $p = [ordered]@{}; $p[$Property] = $State; foreach ($k in $More.Keys) { $p[$k] = $More[$k] }
        [pscustomobject]@{ id = '/x'; location = 'westeurope'; properties = [pscustomobject]$p }
    }
    $script:SrvPath = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.Sql/servers/sql-x'
    $script:DbPath = $script:SrvPath + '/databases/sqldb-si-pro'
    $script:JobPath = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.App/jobs/caj-si-x'
    $script:Tier = [pscustomobject]@{ Name = 'S3'; Tier = 'Standard'; Capacity = 100; MaxSizeBytes = 268435456000 }
}

Describe 'Get-SIArmReadiness -- the property that says "ready" differs per type' {
    It 'a database is ready when its status is Online' {
        (Get-SIArmReadiness -Path $script:DbPath -Resource (New-ArmThing 'Online' 'status')).Ready | Should -BeTrue
        (Get-SIArmReadiness -Path $script:DbPath -Resource (New-ArmThing 'Creating' 'status')).Ready | Should -BeFalse
    }
    It 'a database server is ready when its state is Ready -- it carries no provisioning state at all' {
        (Get-SIArmReadiness -Path $script:SrvPath -Resource (New-ArmThing 'Ready' 'state')).Ready | Should -BeTrue
        (Get-SIArmReadiness -Path $script:SrvPath -Resource ([pscustomobject]@{ properties = [pscustomobject]@{} })).Ready | Should -BeFalse
    }
    It 'everything else: Succeeded is ready, no state at all is ready, InProgress is not' {
        (Get-SIArmReadiness -Path $script:JobPath -Resource (New-ArmThing 'Succeeded')).Ready | Should -BeTrue
        (Get-SIArmReadiness -Path $script:JobPath -Resource ([pscustomobject]@{ properties = [pscustomobject]@{} })).Ready | Should -BeTrue
        (Get-SIArmReadiness -Path $script:JobPath -Resource (New-ArmThing 'InProgress')).Ready | Should -BeFalse
    }
    It 'a failed resource carries what Azure itself said' {
        $r = Get-SIArmReadiness -Path $script:JobPath -Resource (New-ArmThing 'Failed' 'provisioningState' @{ provisioningError = 'the image could not be pulled' })
        $r.Failed | Should -BeTrue
        $r.Why | Should -Match 'the image could not be pulled'
    }
}

Describe 'Wait-SIArmResourceReady' {
    It 'a 404 right after the create is "not there yet": it is polled through' {
        Reset-ArmStub -Reads @($null, $null, (New-ArmThing 'Creating' 'state'), (New-ArmThing 'Ready' 'state'))
        $r = Wait-SIArmResourceReady -Path $script:SrvPath -ApiVersion '2021-11-01' -Sleep $script:NoSleep
        $r.properties.state | Should -Be 'Ready'
        $script:ArmCalls.Count | Should -Be 4
    }
    It 'THROWS at its deadline with the state Azure showed -- never returns something that is not ready' {
        Reset-ArmStub -Reads @((New-ArmThing 'InProgress'))
        { Wait-SIArmResourceReady -Path $script:JobPath -ApiVersion '2025-07-01' -TimeoutSec 30 -PollSec 10 -Sleep $script:NoSleep } |
            Should -Throw -ExpectedMessage '*caj-si-x is not ready 30 seconds*InProgress*'
    }
    It 'THROWS when the resource never appears' {
        Reset-ArmStub
        { Wait-SIArmResourceReady -Path $script:JobPath -ApiVersion '2025-07-01' -TimeoutSec 20 -PollSec 10 -Sleep $script:NoSleep } |
            Should -Throw -ExpectedMessage '*not there yet*'
    }
    It 'a failed resource throws with Azure''s own error text' {
        Reset-ArmStub -Reads @((New-ArmThing 'Failed' 'provisioningState' @{ provisioningError = 'quota exceeded in the region' }))
        { Wait-SIArmResourceReady -Path $script:JobPath -ApiVersion '2025-07-01' -Sleep $script:NoSleep } | Should -Throw -ExpectedMessage '*Failed*quota exceeded in the region*'
    }
    It 'a failed resource without a reason says where the reason is' {
        Reset-ArmStub -Reads @((New-ArmThing 'Failed'))
        { Wait-SIArmResourceReady -Path $script:JobPath -ApiVersion '2025-07-01' -Sleep $script:NoSleep } | Should -Throw -ExpectedMessage '*activity log*'
    }
}

Describe 'Test-SIArmResourceAbsent -- "could not read" is never "not there"' {
    It 'not there only when Azure says not found TWICE, with a pause between' {
        Reset-ArmStub -Reads @($null, $null)
        Test-SIArmResourceAbsent -Path $script:DbPath -ApiVersion '2021-11-01' -Sleep $script:NoSleep | Should -BeTrue
        $script:ArmCalls.Count | Should -Be 2
        $script:Slept.Count | Should -Be 1
    }
    It 'a database that answers not found once (while it is resized) and is there on the second read IS there' {
        Reset-ArmStub -Reads @($null, (New-ArmThing 'Online' 'status'))
        Test-SIArmResourceAbsent -Path $script:DbPath -ApiVersion '2021-11-01' -Sleep $script:NoSleep | Should -BeFalse
    }
    It 'any other failure of the read throws' {
        Reset-ArmStub -Reads @('THROW:Azure Resource Manager GET failed. HTTP Status: 503 (ServiceUnavailable)')
        { Test-SIArmResourceAbsent -Path $script:DbPath -ApiVersion '2021-11-01' -Sleep $script:NoSleep } | Should -Throw -ExpectedMessage '*503*'
    }
}

Describe 'a database or a server is never created over one that exists' {
    It 'New-SISqlDatabaseArm: a database that is there gets NO create -- it is waited for and returned as it is' {
        Reset-ArmStub -Reads @((New-ArmThing 'Online' 'status'))
        $db = New-SISqlDatabaseArm -ResourceGroupName 'rg-x' -ServerName 'sql-x' -Name 'sqldb-si-pro' -Target $script:Tier -Location 'westeurope' -Sleep $script:NoSleep
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 0 -Because 'a create carries a size and would change the database'
        $db.SIExisted | Should -BeTrue
    }
    It 'New-SISqlDatabaseArm: a read that fails throws -- no create is sent on a guess' {
        Reset-ArmStub -Reads @('THROW:HTTP Status: 429 (TooManyRequests)')
        { New-SISqlDatabaseArm -ResourceGroupName 'rg-x' -ServerName 'sql-x' -Name 'sqldb-si-pro' -Target $script:Tier -Location 'westeurope' -Sleep $script:NoSleep } | Should -Throw
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 0
    }
    It 'New-SISqlDatabaseArm: not found twice -> ONE create, then waited for until it is Online' {
        Reset-ArmStub -Reads @($null, $null, $null, (New-ArmThing 'Creating' 'status'), (New-ArmThing 'Online' 'status'))
        $db = New-SISqlDatabaseArm -ResourceGroupName 'rg-x' -ServerName 'sql-x' -Name 'sqldb-si-pro' -Target $script:Tier -Location 'westeurope' -Sleep $script:NoSleep
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 1
        $db.SIExisted | Should -BeFalse
        $db.properties.status | Should -Be 'Online'
    }
    It 'New-SISqlDatabaseArm: a create Azure dropped is sent again, three times at most, then it throws' {
        Reset-ArmStub
        { New-SISqlDatabaseArm -ResourceGroupName 'rg-x' -ServerName 'sql-x' -Name 'sqldb-si-pro' -Target $script:Tier -Location 'westeurope' -Sleep $script:NoSleep } |
            Should -Throw -ExpectedMessage '*three times*'
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 3
    }
    It 'New-SISqlServerEntraOnly: a server that is there gets NO create (it would make the installer its administrator again)' {
        Reset-ArmStub -Reads @((New-ArmThing 'Ready' 'state'))
        $srv = New-SISqlServerEntraOnly -ResourceGroupName 'rg-x' -Name 'sql-x' -Location 'westeurope' -AdminName 'a' -AdminSid 'b' -Sleep $script:NoSleep
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 0
        $srv.SIExisted | Should -BeTrue
    }
    It 'New-SISqlServerEntraOnly: a new server is waited for until it is Ready; one that never gets Ready THROWS' {
        Reset-ArmStub -Reads @($null, $null, $null, (New-ArmThing 'Ready' 'state'))
        (New-SISqlServerEntraOnly -ResourceGroupName 'rg-x' -Name 'sql-x' -Location 'westeurope' -AdminName 'a' -AdminSid 'b' -Sleep $script:NoSleep).SIExisted | Should -BeFalse
        @($script:ArmCalls | Where-Object Method -eq 'PUT').Count | Should -Be 1
        Reset-ArmStub -Reads @($null, $null, (New-ArmThing 'Creating' 'state'))
        { New-SISqlServerEntraOnly -ResourceGroupName 'rg-x' -Name 'sql-x' -Location 'westeurope' -AdminName 'a' -AdminSid 'b' -Sleep $script:NoSleep } | Should -Throw -ExpectedMessage '*is not ready*Creating*'
    }
}

Describe 'the database server''s administrator' {
    It 'is set through a PATCH of the SERVER, with its kind' {
        $after = [pscustomobject]@{ properties = [pscustomobject]@{ administrators = [pscustomobject]@{ sid = 'app-1'; login = 'the app'; principalType = 'Application' } } }
        Reset-ArmStub -Reads @($after)
        $r = Set-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' -AdminName 'the app' -AdminSid 'app-1' -AdminType Application -Sleep $script:NoSleep
        $w = @($script:ArmCalls | Where-Object Method -ne 'GET')
        $w.Count | Should -Be 1
        $w[0].Method | Should -Be 'PATCH'
        $w[0].Path | Should -Be $script:SrvPath
        $w[0].Body.properties.administrators.principalType | Should -Be 'Application'
        $w[0].Body.properties.administrators.sid | Should -Be 'app-1'
        $r.PrincipalType | Should -Be 'Application'
    }
    It 'the right sid under the WRONG kind is not "done": it throws and says what Azure shows' {
        $stale = [pscustomobject]@{ properties = [pscustomobject]@{ administrators = [pscustomobject]@{ sid = 'app-1'; login = 'the app'; principalType = 'Group' } } }
        Reset-ArmStub -Reads @($stale)
        { Set-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' -AdminName 'the app' -AdminSid 'app-1' -AdminType Application -Sleep $script:NoSleep } |
            Should -Throw -ExpectedMessage '*did not change*as Application*Group*'
    }
    It 'the server''s own "Entra-only sign-in" setting goes back in the PATCH exactly as it is -- <Case>' -ForEach @(
        @{ Case = 'on stays on'; Before = $true }
        @{ Case = 'off stays off'; Before = $false }
    ) {
        # ($Before is the case's value: the two server records get names of their own -- PowerShell names ignore case)
        $srvFirst = [pscustomobject]@{ properties = [pscustomobject]@{ administrators = [pscustomobject]@{ sid = 'grp-1'; login = 'the group'; principalType = 'Group'; azureADOnlyAuthentication = $Before } } }
        $srvThen = [pscustomobject]@{ properties = [pscustomobject]@{ administrators = [pscustomobject]@{ sid = 'app-1'; login = 'the app'; principalType = 'Application'; azureADOnlyAuthentication = $Before } } }
        Reset-ArmStub -Reads @($srvFirst, $srvThen)
        $null = Set-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' -AdminName 'the app' -AdminSid 'app-1' -AdminType Application -Sleep $script:NoSleep
        $script:ArmCalls[0].Method | Should -Be 'GET' -Because 'the server is read before it is changed'
        $w = @($script:ArmCalls | Where-Object Method -eq 'PATCH')
        $w.Count | Should -Be 1
        $w[0].Body.properties.administrators.Contains('azureADOnlyAuthentication') | Should -BeTrue
        $w[0].Body.properties.administrators.azureADOnlyAuthentication | Should -Be $Before
    }
    It 'a server that does not say whether sign-in is Entra-only gets a PATCH without that setting (never guessed)' {
        $after = [pscustomobject]@{ properties = [pscustomobject]@{ administrators = [pscustomobject]@{ sid = 'app-1'; login = 'the app'; principalType = 'Application' } } }
        Reset-ArmStub -Reads @($after)
        $null = Set-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' -AdminName 'the app' -AdminSid 'app-1' -AdminType Application -Sleep $script:NoSleep
        $w = @($script:ArmCalls | Where-Object Method -eq 'PATCH')
        $w[0].Body.properties.administrators.Contains('azureADOnlyAuthentication') | Should -BeFalse
    }
    It 'a server that cannot be read is NOT changed' {
        Reset-ArmStub -Reads @('THROW:HTTP Status: 403 (Forbidden)')
        { Set-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' -AdminName 'the app' -AdminSid 'app-1' -AdminType Application -Sleep $script:NoSleep } | Should -Throw -ExpectedMessage '*403*'
        @($script:ArmCalls | Where-Object Method -ne 'GET').Count | Should -Be 0
    }
    It 'Get-SISqlServerEntraAdmin: none set is $null; a server that cannot be read THROWS' {
        Reset-ArmStub -Reads @([pscustomobject]@{ properties = [pscustomobject]@{} })
        Get-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' | Should -BeNullOrEmpty
        Reset-ArmStub -Reads @('THROW:HTTP Status: 403 (Forbidden)')
        { Get-SISqlServerEntraAdmin -ResourceGroupName 'rg-x' -Name 'sql-x' } | Should -Throw -ExpectedMessage '*403*'
    }
}

Describe 'Invoke-SIRetryNotThereYet -- only the "not there yet" answer is waited for' {
    It 'a 404 on something just created is tried again and then succeeds' {
        $script:Slept = New-Object System.Collections.Generic.List[int]
        $script:Tries = 0
        $out = Invoke-SIRetryNotThereYet -Sleep $script:NoSleep -Action { $script:Tries++; if ($script:Tries -lt 3) { throw 'Microsoft Graph GET /v1.0/applications/x failed: HTTP 404 Request_ResourceNotFound' }; 'ok' }
        $out | Should -Be 'ok'
        $script:Tries | Should -Be 3
    }
    It 'a REFUSAL stops at once -- it is never waited for' {
        $script:Slept = New-Object System.Collections.Generic.List[int]
        $script:Tries = 0
        { Invoke-SIRetryNotThereYet -Sleep $script:NoSleep -Action { $script:Tries++; throw 'HTTP 403 Authorization_RequestDenied -- Insufficient privileges to complete the operation' } } | Should -Throw -ExpectedMessage '*Insufficient privileges*'
        $script:Tries | Should -Be 1
        $script:Slept.Count | Should -Be 0
    }
    It 'gives up after its waits and throws the last answer' {
        $script:Slept = New-Object System.Collections.Generic.List[int]
        $script:Tries = 0
        { Invoke-SIRetryNotThereYet -Waits @(1, 1) -Sleep $script:NoSleep -Action { $script:Tries++; throw 'HTTP Status: 404 (NotFound)' } } | Should -Throw -ExpectedMessage '*404*'
        $script:Tries | Should -Be 3
    }
    It 'Test-SINotThereYetAnswer: what counts and what does not' -ForEach @(
        @{ Text = 'HTTP 400 NoBackingApplicationObject -- the appId does not reference a valid application object'; Yet = $true }
        @{ Text = 'HTTP Status: 400 (BadRequest) PrincipalNotFound: Principal x does not exist in the directory'; Yet = $true }
        @{ Text = 'Response status code does not indicate success: 404 (Not Found). Request_ResourceNotFound'; Yet = $true }
        @{ Text = 'HTTP Status: 403 (Forbidden) AuthorizationFailed'; Yet = $false }
        @{ Text = 'HTTP 400 Request_BadRequest -- Not a valid reference update'; Yet = $false }
        @{ Text = 'HTTP Status: 409 (Conflict)'; Yet = $false }
    ) {
        Test-SINotThereYetAnswer -Text $Text | Should -Be $Yet
    }
    It 'these helpers read no script value of their file (a script that finds them defined does not load the file)' {
        $arm = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
        foreach ($fn in 'Get-SIArmReadiness', 'Wait-SIArmResourceReady', 'Test-SIArmResourceAbsent', 'Test-SINotThereYetAnswer', 'Invoke-SIRetryNotThereYet', 'New-SISqlServerEntraOnly', 'Set-SISqlServerEntraAdmin', 'Get-SISqlServerEntraAdmin') {
            $m = [regex]::Match($arm, '(?s)\nfunction ' + [regex]::Escape($fn) + ' \{.*?\n\}\r?\n')
            $m.Success | Should -BeTrue -Because $fn
            $m.Value | Should -Not -Match '\$script:' -Because ($fn + ' must work from a script that did not load the file')
        }
    }
}
