#Requires -Version 7.0
<#
    A CONTAINER APPS ENVIRONMENT THAT EXISTS IS NOT FINE BECAUSE IT EXISTS.

    Why: 2026-10-13, a customer-run install. Azure created the environment and then reported it Failed ("creation of the
    managed cluster failed, please retry later"). The install stopped and said "run the command again" -- and on that run
    the step found the Failed environment, did not create it again, never looked at its state, and stopped a step later.
    Azure does not repair a Failed managed environment: it has to be removed and created again.

    The rules these tests hold (Initialize-SIManagedEnvironment and its helpers, setup\_shared\SI-SetupArm.ps1):
      * ready                    -> returned as it is: nothing removed, nothing created;
      * still being made         -> waited for, never created a second time;
      * Failed / Canceled, EMPTY -> removed, waited for UNTIL IT IS GONE, created again, ready -- once per run;
      * Failed, NOT empty        -> NOT removed: it stops and names what runs in it;
      * "could not read what runs in it" is never "empty";
      * a create Azure fails says what the person does next -- and the second time, that the first removal was done.
    Offline: Invoke-SIArm is a fake Azure that answers per path (the environment from a list of states, in order).
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    function script:Get-SISetupSubscriptionId { param([string]$SubscriptionId) if ($SubscriptionId) { $SubscriptionId } else { '00000000-0000-0000-0000-000000000001' } }
    $script:EnvPath = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.App/managedEnvironments/cae-x'
    $script:AzureText = 'ErrorCode: ManagedEnvironmentProvisioningError, Message: Fail to create managed environment because creation of the managed cluster failed, please retry later.'
    function script:New-Env([string]$State, [string]$Why) {
        $p = [ordered]@{ provisioningState = $State; appLogsConfiguration = [pscustomobject]@{ destination = 'azure-monitor' } }
        if ($Why) { $p['deploymentErrors'] = $Why }
        [pscustomobject]@{ id = $script:EnvPath; name = 'cae-x'; location = 'westeurope'; properties = [pscustomobject]$p }
    }
    function script:Invoke-SIArm {
        param([string]$Method = 'GET', [string]$Path, [string]$ApiVersion, $Body, [switch]$AllowNotFound, [switch]$List)
        $m = $Method.ToUpperInvariant()
        $script:ArmCalls.Add([pscustomobject]@{ Method = $m; Path = $Path; ApiVersion = $ApiVersion; Body = $Body; List = [bool]$List })
        if ($List) {
            if ($Path -like '*/Microsoft.App/jobs') { if ($script:JobsError) { throw $script:JobsError }; return $script:Jobs }
            if ($Path -like '*/Microsoft.App/containerApps') { return $script:Apps }
            throw ('the fake Azure has no list for ' + $Path)
        }
        if ($Path -ne $script:EnvPath) { throw ('the fake Azure has nothing at ' + $Path) }
        if ($m -eq 'DELETE') { if ($script:DeleteError) { throw $script:DeleteError }; return $null }
        if ($m -ne 'GET') { return $null }
        # the environment: the next state of the list; the last one stays
        if ($script:EnvReads.Count -gt 1) { $next = $script:EnvReads[0]; $script:EnvReads.RemoveAt(0); return $next }
        if ($script:EnvReads.Count -eq 1) { return $script:EnvReads[0] }
        return $null
    }
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
    $script:NoSleep = { param($Seconds) $script:Slept.Add([int]$Seconds) }
    # -EnvReads: what Azure answers for the environment, read after read ($null = not found); the last answer stays.
    function script:Reset-FakeAzure([object[]]$EnvReads = @($null), [object[]]$Jobs = @(), [object[]]$Apps = @()) {
        $script:ArmCalls = New-Object System.Collections.Generic.List[object]
        $script:EnvReads = New-Object System.Collections.Generic.List[object]
        foreach ($x in $EnvReads) { $script:EnvReads.Add($x) }
        $script:Jobs = $Jobs; $script:Apps = $Apps; $script:JobsError = $null; $script:DeleteError = $null
        $script:Slept = New-Object System.Collections.Generic.List[int]
    }
    function script:Get-Writes([string]$Method) { @($script:ArmCalls | Where-Object { $_.Method -eq $Method -and $_.Path -eq $script:EnvPath }) }
    function script:Invoke-Step { Initialize-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Location 'westeurope' -Sleep $script:NoSleep 6>$null }
}

Describe 'the Container Apps environment step looks at the state of an environment that exists' {
    It 'exists and is ready: returned as it is -- nothing is removed, nothing is created, nothing else is read' {
        Reset-FakeAzure -EnvReads @((New-Env 'Succeeded'))
        $cae = Invoke-Step
        $cae.id | Should -Be $script:EnvPath
        (Get-Writes 'DELETE').Count | Should -Be 0
        (Get-Writes 'PUT').Count | Should -Be 0
        $script:ArmCalls.Count | Should -Be 1 -Because 'a ready environment costs one read'
    }
    It 'not there: created once and waited for until it is ready' {
        Reset-FakeAzure -EnvReads @($null, $null, (New-Env 'InfrastructureSetupInProgress'), (New-Env 'Succeeded'))
        $cae = Invoke-Step
        $cae.properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'PUT').Count | Should -Be 1
        (Get-Writes 'DELETE').Count | Should -Be 0
    }
    It 'still being made: it is waited for -- a second one is never created' {
        Reset-FakeAzure -EnvReads @((New-Env 'InfrastructureSetupInProgress'), (New-Env 'Waiting'), (New-Env 'Succeeded'))
        $cae = Invoke-Step
        $cae.properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'PUT').Count | Should -Be 0
        (Get-Writes 'DELETE').Count | Should -Be 0
        $script:Slept.Count | Should -BeGreaterThan 0
    }
    It 'Failed and EMPTY: removed, waited for until it is gone (still answering on the first polls), created again, ready' {
        $failed = New-Env 'Failed' $script:AzureText
        # read 1 = the step; reads 2-3 = still there after the DELETE; read 4 = gone; read 5 = not there yet after the
        # create; then being made; then ready
        Reset-FakeAzure -EnvReads @($failed, $failed, (New-Env 'ScheduledForDelete'), $null, $null, (New-Env 'Waiting'), (New-Env 'Succeeded')) `
            -Jobs @([pscustomobject]@{ name = 'caj-other'; properties = [pscustomobject]@{ environmentId = '/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-x/providers/Microsoft.App/managedEnvironments/cae-other' } })
        $cae = Invoke-Step
        $cae.properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'DELETE').Count | Should -Be 1
        (Get-Writes 'PUT').Count | Should -Be 1
        $order = @($script:ArmCalls | ForEach-Object { if ($_.List) { 'LIST' } else { $_.Method } }) -join ' '
        $order | Should -Be 'GET LIST LIST DELETE GET GET GET PUT GET GET GET' -Because 'both lists are read before the removal, and the create is sent only after Azure answered "not found"'
        (Get-Writes 'PUT')[0].Body.properties.appLogsConfiguration.destination | Should -Be 'azure-monitor' -Because 'it is created as for a new install'
    }
    It 'Canceled and empty is removed and created again too' {
        Reset-FakeAzure -EnvReads @((New-Env 'Canceled'), $null, $null, (New-Env 'Succeeded'))
        (Invoke-Step).properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'DELETE').Count | Should -Be 1
        (Get-Writes 'PUT').Count | Should -Be 1
    }
    It 'says in plain words what it does, with Azure''s own text' {
        Reset-FakeAzure -EnvReads @((New-Env 'Failed' $script:AzureText), $null, $null, (New-Env 'Succeeded'))
        $said = (Initialize-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Location 'westeurope' -Sleep $script:NoSleep 6>&1 | Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { [string]$_ }) -join "`n"
        $said | Should -Match 'the Container Apps environment cae-x was left Failed by Azure \(.*ManagedEnvironmentProvisioningError.*\) -- it holds nothing, so it is removed and created again'
        $said | Should -Match 'waiting until it is gone'
    }
    It 'Failed and a JOB refers to it: NOT removed -- it stops and names the environment, Azure''s text and the job' {
        Reset-FakeAzure -EnvReads @((New-Env 'Failed' $script:AzureText)) `
            -Jobs @([pscustomobject]@{ name = 'caj-si-flow'; properties = [pscustomobject]@{ environmentId = $script:EnvPath.ToUpperInvariant() + '/' } })
        { Invoke-Step } | Should -Throw -ExpectedMessage '*cae-x was left Failed by Azure*ManagedEnvironmentProvisioningError*NOT empty*the job caj-si-flow*Nothing was removed*support*'
        (Get-Writes 'DELETE').Count | Should -Be 0
        (Get-Writes 'PUT').Count | Should -Be 0
    }
    It 'Failed and a CONTAINER APP refers to it: NOT removed' {
        Reset-FakeAzure -EnvReads @((New-Env 'Failed')) -Apps @([pscustomobject]@{ name = 'ca-si-web'; properties = [pscustomobject]@{ managedEnvironmentId = $script:EnvPath } })
        { Invoke-Step } | Should -Throw -ExpectedMessage '*NOT empty*the container app ca-si-web*'
        (Get-Writes 'DELETE').Count | Should -Be 0
    }
    It 'what runs in it cannot be read: that is never "empty" -- nothing is removed' {
        Reset-FakeAzure -EnvReads @((New-Env 'Failed'))
        $script:JobsError = 'Azure Resource Manager GET failed. HTTP Status: 403 (Forbidden)'
        { Invoke-Step } | Should -Throw -ExpectedMessage '*403*'
        (Get-Writes 'DELETE').Count | Should -Be 0
        (Get-Writes 'PUT').Count | Should -Be 0
    }
    It 'a removal Azure refuses stops with a plain sentence -- nothing is created over it' {
        Reset-FakeAzure -EnvReads @((New-Env 'Failed'))
        $script:DeleteError = 'HTTP Status: 409 (Conflict) ManagedEnvironmentNotEmpty'
        { Invoke-Step } | Should -Throw -ExpectedMessage '*could not be removed*ManagedEnvironmentNotEmpty*'
        (Get-Writes 'PUT').Count | Should -Be 0
    }
    It 'an environment that never goes away stops at the limit -- nothing is created over it' {
        $failed = New-Env 'Failed'
        Reset-FakeAzure -EnvReads @($failed)
        { Invoke-Step } | Should -Throw -ExpectedMessage '*could not be removed*is still there*'
        (Get-Writes 'DELETE').Count | Should -Be 1
        (Get-Writes 'PUT').Count | Should -Be 0
    }
    It 'an environment Azure is already removing is waited for until it is gone, then created' {
        Reset-FakeAzure -EnvReads @((New-Env 'ScheduledForDelete'), (New-Env 'ScheduledForDelete'), $null, $null, (New-Env 'Succeeded'))
        (Invoke-Step).properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'DELETE').Count | Should -Be 0
        (Get-Writes 'PUT').Count | Should -Be 1
    }
    It 'being made, then Failed while it is waited for: removed and created again in the same run' {
        $failed = New-Env 'Failed' $script:AzureText
        # reads: the step (being made), the wait (Failed), the step's re-read (Failed), after the DELETE (gone), after the create
        Reset-FakeAzure -EnvReads @((New-Env 'Waiting'), $failed, $failed, $null, $null, (New-Env 'Succeeded'))
        (Invoke-Step).properties.provisioningState | Should -Be 'Succeeded'
        (Get-Writes 'DELETE').Count | Should -Be 1
        (Get-Writes 'PUT').Count | Should -Be 1
    }
}

Describe 'a create Azure fails says what the person does next' {
    It 'the FIRST failure: Azure''s text, that it is Azure''s capacity, and that the next run removes and creates it again' {
        Reset-FakeAzure -EnvReads @($null, $null, (New-Env 'Failed' $script:AzureText))
        $err = $null; try { Invoke-Step } catch { $err = [string]$_.Exception.Message }
        $err | Should -Match 'Azure could not make the Container Apps environment cae-x: .*please retry later'
        $err | Should -Match 'capacity in the region westeurope'
        $err | Should -Match 'run the same command again: it removes the failed environment'
        (Get-Writes 'PUT').Count | Should -Be 1
        (Get-Writes 'DELETE').Count | Should -Be 0
    }
    It 'the SECOND failure (removed, created again, Failed again): a useful sentence, and ONE remove-and-create in the run' {
        $failed = New-Env 'Failed' $script:AzureText
        # reads: the step (Failed), after the DELETE (gone), after the create (not there yet, then Failed again; it stays Failed)
        Reset-FakeAzure -EnvReads @($failed, $null, $null, $failed)
        $err = $null; try { Invoke-Step } catch { $err = [string]$_.Exception.Message }
        $err | Should -Match 'this time either'
        $err | Should -Match 'please retry later'
        $err | Should -Match 'capacity in the region westeurope at the moment -- nothing in this install is wrong'
        $err | Should -Match 'is removed by the next run'
        $err | Should -Match 'run the same command again'
        (Get-Writes 'DELETE').Count | Should -Be 1 -Because 'one remove-and-create per run: it does not loop'
        (Get-Writes 'PUT').Count | Should -Be 1
    }
    It 'a failure that is not about capacity does not claim it is' {
        Reset-FakeAzure -EnvReads @($null, $null, (New-Env 'Failed' 'the subnet is too small for the environment'))
        $err = $null; try { Invoke-Step } catch { $err = [string]$_.Exception.Message }
        $err | Should -Match 'the subnet is too small'
        $err | Should -Not -Match 'capacity'
    }
    It 'a create that only ran out of time keeps its own error (the environment is not Failed)' {
        Reset-FakeAzure -EnvReads @($null, $null, (New-Env 'Waiting'))
        { Invoke-Step } | Should -Throw -ExpectedMessage '*is not ready*Waiting*'
    }
}

Describe 'the helpers' {
    It 'Get-SIManagedEnvironmentUse: only what refers to THIS environment, whatever the case of the id' {
        Reset-FakeAzure `
            -Jobs @([pscustomobject]@{ name = 'caj-a'; properties = [pscustomobject]@{ environmentId = $script:EnvPath.ToLowerInvariant() } },
                    [pscustomobject]@{ name = 'caj-b'; properties = [pscustomobject]@{ environmentId = $script:EnvPath + '-other' } }) `
            -Apps @([pscustomobject]@{ name = 'ca-a'; properties = [pscustomobject]@{ managedEnvironmentId = $script:EnvPath; environmentId = $script:EnvPath } })
        $u = @(Get-SIManagedEnvironmentUse -ResourceGroupName 'rg-x' -EnvironmentId $script:EnvPath)
        $u | Should -Be @('the job caj-a', 'the container app ca-a')
    }
    It 'Remove-SIManagedEnvironment: DELETE, then polls until Azure answers "not found"' {
        Reset-FakeAzure -EnvReads @((New-Env 'ScheduledForDelete'), (New-Env 'ScheduledForDelete'), $null)
        Remove-SIManagedEnvironment -ResourceGroupName 'rg-x' -Name 'cae-x' -Sleep $script:NoSleep
        (Get-Writes 'DELETE').Count | Should -Be 1
        (Get-Writes 'GET').Count | Should -Be 3
        $script:Slept.Count | Should -Be 2
    }
    It 'Wait-SIArmResourceGone THROWS at its limit with the state Azure showed' {
        Reset-FakeAzure -EnvReads @((New-Env 'ScheduledForDelete'))
        { Wait-SIArmResourceGone -Path $script:EnvPath -ApiVersion '2025-07-01' -TimeoutSec 30 -PollSec 10 -Sleep $script:NoSleep } |
            Should -Throw -ExpectedMessage '*cae-x is still there 30 seconds*ScheduledForDelete*'
    }
    It 'WIRING -- the container setup takes its environment from this step, and no longer creates only when none exists' {
        $boot = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'Bootstrap-ContainerAppJob.ps1'))
        $boot | Should -Match '\$cae = Initialize-SIManagedEnvironment -ResourceGroupName \$ResourceGroupName -Name \$EnvName -Location \$Location -SubscriptionId \$subId'
        $boot | Should -Not -Match '\$cae = Get-SIManagedEnvironment'
        $boot | Should -Not -Match '\$cae = New-SIManagedEnvironment'
    }
}
