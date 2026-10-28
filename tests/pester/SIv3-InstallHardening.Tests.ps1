#Requires -Version 5.1
<#
    INSTALL HARDENING -- what the first production installs through the Invardia Support app found (2026-10-08, customer A /
    customer H / customer G; owner: "make sure to update install script with findings from today so it will not happen again.
    make sure that customers requesting a trial version will not have these issues"). A trial runs the same installer.

      * A NEW identity's registry pull right reaches the registry seconds to minutes after it is granted: a Container Apps
        job write refused with "unable to pull image using Managed identity" is WAITED for and retried (bounded), never a
        failed install step; any other failure fails at once. (#521: the write is an ARM PUT -- setup\_shared\SI-SetupArm.ps1
        Set-SIContainerAppJob / Test-SIContainerAppIdentityNotReady; it was an az command in Bootstrap.)
      * A failed job write is reported with the job and what Azure said -- never the environment or secret VALUES (the
        settings dump made the report unreadable).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SqlAdminReady.ps1')
    $script:Boot = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
    $script:Arm = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1'))
}

Describe 'a new identity''s registry pull right: waited for, not a failed install' {
    It 'tells the propagation refusal from every other failure' {
        Test-SIContainerAppIdentityNotReady "ERROR: (InvalidParameterValueInContainerTemplate) ... 'Invalid value: ""acr.azurecr.io/si:v3"": unable to pull image using Managed identity /subscriptions/s/.../uami-securityinsight-tagging for registry acr.azurecr.io'" | Should -BeTrue
        Test-SIContainerAppIdentityNotReady 'ERROR: (ResourceGroupNotFound) Resource group ''rg-x'' could not be found.' | Should -BeFalse
        Test-SIContainerAppIdentityNotReady 'ERROR: (InvalidParameterValueInContainerTemplate) cpu must be 0.25 to 4' | Should -BeFalse
        Test-SIContainerAppIdentityNotReady '' | Should -BeFalse
    }
    It 'the job write (ARM PUT) retries on it, bounded, and fails at once otherwise' {
        # waiting for the identity is bounded; any other refusal fails at once -- except a run limit above 24 hours, sent once more as 24 hours
        $script:Arm | Should -Match ([regex]::Escape('if (Test-SIContainerAppIdentityNotReady -Text $text) {'))
        $script:Arm | Should -Match ([regex]::Escape('if ((Get-Date) -ge $until) { throw }'))
        $script:Arm | Should -Match ([regex]::Escape('if ($lowered -or -not (Test-SIRunLimitRefusal -ReplicaTimeout $limit -Text $text)) { throw }'))
        $script:Arm | Should -Match '\[int\]\$IdentityWaitSeconds = 600'
        $script:Boot | Should -Match 'New-SIContainerAppJobFromArgs -CreateArgs \$createArgs'
        $script:Boot | Should -Match 'Update-SIContainerAppJob @upd'
    }
}

Describe 'a new registry whose name Azure cannot resolve yet: waited for, not a failed install' {
    # the customer-run install at customer C, 2026-10-15 07:12Z: registry made 07:08Z, Azure's resolver did not know it yet
    It 'tells the not-yet-resolvable registry from every other failure' {
        Test-SIContainerAppRegistryNotResolvable "Azure Resource Manager PUT ... {""error"":{""code"":""InvalidParameterValueInContainerTemplate"",""message"":""The following field(s) are either invalid or missing. Field 'template.containers.caj-si-identity-producer.image' is invalid with details: 'Invalid value: \""acrsiprodprocac63d1c.azurecr.io/si-orchestrator:v3.0.0-c5bef0020ff1\"": failed to resolve registry 'acrsiprodprocac63d1c.azurecr.io': lookup acrsiprodprocac63d1c.azurecr.io on 100.100.240.125:53: no such host';.""}}" | Should -BeTrue
        Test-SIContainerAppRegistryNotResolvable "Field 'template.containers.x.image' is invalid with details: 'Invalid value: ""acr.azurecr.io/si:v3"": manifest unknown'" | Should -BeFalse
        Test-SIContainerAppRegistryNotResolvable 'ERROR: (InvalidParameterValueInContainerTemplate) cpu must be 0.25 to 4' | Should -BeFalse
        Test-SIContainerAppRegistryNotResolvable '' | Should -BeFalse
    }
    It 'the job write waits on it (30 s at a time, within the same bounded window) and then succeeds' {
        $script:Arm | Should -Match ([regex]::Escape('if (Test-SIContainerAppRegistryNotResolvable -Text $text) {'))
        $calls = 0; $slept = 0
        Mock -CommandName Invoke-SIArm -MockWith {
            param($Method)
            if ($Method -eq 'PUT') { $script:__puts++; if ($script:__puts -lt 3) { throw "Field 'template.containers.j.image' is invalid with details: 'Invalid value: ""acrx.azurecr.io/si:v3"": failed to resolve registry 'acrx.azurecr.io': lookup acrx.azurecr.io on 100.100.240.125:53: no such host';." } }
            [pscustomobject]@{ properties = [pscustomobject]@{ provisioningState = 'Succeeded' } }
        }
        $script:__puts = 0
        $body = @{ properties = @{ configuration = @{ replicaTimeout = 3600 } } }
        $null = Set-SIContainerAppJob -JobId '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/j' -Body $body -Sleep { param($s) $script:__slept += $s } -NoWait
        $script:__puts | Should -Be 3 -Because 'two refusals are waited out, the third write goes through'
    }
}

Describe 'a new database administrator: waited for until Azure has finished it, and the first sign-in waits it out (#695)' {
    # the customer-run install at customer B, 2026-10-15: the admin write was Accepted 07:50:06Z, the sign-in refused
    # 07:50:14-19Z, the write Succeeded 07:50:22Z
    BeforeAll {
        $script:EkLogin = 'Initialize-SIVulnTargetSql: Exception calling "Open" with "0" argument(s): "Login failed for user ''<token-identified principal>''."'
        $script:AdminPath = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-x/administrators/ActiveDirectory?api-version=2021-11-01'
        $script:OpUrl = 'https://management.azure.com/subscriptions/s/providers/Microsoft.Sql/locations/swedencentral/administratorAzureAsyncOperation/op-1?api-version=2021-11-01'
        function script:New-AdminFake([string[]]$OpStates, [string]$Sid = 'grp-1', [string]$Login = 'grp-si-sql-admins') {
            $f = @{ OpStates = [System.Collections.Generic.Queue[string]]::new([string[]]$OpStates); OpReads = 0; AdminReads = 0; Sid = $Sid; Login = $Login
                    Slept = (New-Object System.Collections.Generic.List[int]); Said = (New-Object System.Collections.Generic.List[string]) }
            $opUrl = $script:OpUrl   # a closure does not see the test's script scope
            $f.Rest = {
                param([string]$Method, [string]$Path)
                if ($Path -eq $opUrl) {
                    $f.OpReads++
                    $s = $(if ($f.OpStates.Count -gt 1) { $f.OpStates.Dequeue() } else { $f.OpStates.Peek() })
                    $body = @{ name = 'op-1'; status = $s }
                    if ($s -eq 'Failed') { $body.error = @{ code = 'InternalServerError'; message = 'the server could not take the administrator' } }
                    return [pscustomobject]@{ StatusCode = 200; Content = ($body | ConvertTo-Json -Depth 4) }
                }
                $f.AdminReads++
                [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ administratorType = 'ActiveDirectory'; login = $f.Login; sid = $f.Sid } } | ConvertTo-Json -Depth 4) }
            }.GetNewClosure()
            $f.Sleep = { param([int]$s) $f.Slept.Add($s) }.GetNewClosure()
            $f.Print = { param([string]$t) $f.Said.Add($t) }.GetNewClosure()
            $f
        }
        $script:Accepted = [pscustomobject]@{ StatusCode = 202; Content = ''; Headers = @{ 'Azure-AsyncOperation' = $script:OpUrl; 'Location' = 'https://management.azure.com/x/operationResults/op-1' } }
    }
    It 'tells the token sign-in that the server does not let in yet from every other SQL error' {
        Test-SISqlLoginNotReady $script:EkLogin | Should -BeTrue
        Test-SISqlLoginNotReady "Login failed for user '<token-identified principal>'." | Should -BeTrue
        Test-SISqlLoginNotReady "Login failed for user 'sa'." | Should -BeFalse -Because 'a wrong password is never waited for'
        Test-SISqlLoginNotReady "Cannot open server 'sql-x' requested by the login. Client with IP address '1.2.3.4' is not allowed to access the server." | Should -BeFalse
        Test-SISqlLoginNotReady "Cannot open database ""sqldb-si-pro"" requested by the login. The login failed." | Should -BeFalse
        Test-SISqlLoginNotReady "Invalid object name 'vuln.VulnerabilityItem'." | Should -BeFalse
        Test-SISqlLoginNotReady '' | Should -BeFalse
    }
    It 'an admin write Azure answered Accepted is waited for (in progress twice, then Succeeded), then read back' {
        $f = New-AdminFake -OpStates 'InProgress', 'InProgress', 'Succeeded'
        $a = Wait-SISqlAdminWrite -Response $script:Accepted -Rest $f.Rest -AdminPath $script:AdminPath -Sid 'grp-1' -Login 'grp-si-sql-admins' -Sleep $f.Sleep -Print $f.Print
        $f.OpReads | Should -Be 3 -Because 'Azure''s own operation is followed until it is finished'
        @($f.Slept) | Should -Be @(10, 10)
        $f.AdminReads | Should -Be 1 -Because 'the admin is read back once the write is finished'
        [string]$a.properties.sid | Should -Be 'grp-1'
        @($f.Said).Count | Should -Be 1 -Because 'one plain line while it waits'
        ($f.Said -join ' ') | Should -Not -Match '#\d'
    }
    It 'a write that finished at once (200, no operation) is only read back' {
        $f = New-AdminFake -OpStates 'Succeeded'
        $null = Wait-SISqlAdminWrite -Response ([pscustomobject]@{ StatusCode = 200; Content = '{}'; Headers = @{} }) -Rest $f.Rest -AdminPath $script:AdminPath -Sid 'grp-1' -Login 'grp-si-sql-admins' -Sleep $f.Sleep
        $f.OpReads | Should -Be 0
        $f.AdminReads | Should -Be 1
    }
    It 'a write Azure reports Failed stops with Azure''s words' {
        $f = New-AdminFake -OpStates 'InProgress', 'Failed'
        { Wait-SISqlAdminWrite -Response $script:Accepted -Rest $f.Rest -AdminPath $script:AdminPath -Sid 'grp-1' -Sleep $f.Sleep -What 'the new Entra admin of sql-x' } |
            Should -Throw '*the new Entra admin of sql-x: Azure reports it Failed -- the server could not take the administrator*'
    }
    It 'bounded: an operation that never finishes, or an admin that never reads back, stops at the deadline' {
        $f = New-AdminFake -OpStates 'InProgress'
        { Wait-SISqlAdminWrite -Response $script:Accepted -Rest $f.Rest -AdminPath $script:AdminPath -Sid 'grp-1' -TimeoutSec 600 -PollSec 10 -Sleep $f.Sleep } | Should -Throw '*not finished 600 seconds after Azure accepted it*'
        $f.OpReads | Should -Be 61
        $g = New-AdminFake -OpStates 'Succeeded' -Sid 'someone-else'
        { Wait-SISqlAdminWrite -Response $script:Accepted -Rest $g.Rest -AdminPath $script:AdminPath -Sid 'grp-1' -Sleep $g.Sleep } | Should -Throw '*did not take effect*'
    }
    It 'the first sign-in: a token sign-in refused twice right after the admin was set is waited out, the third goes in' {
        $now = [datetime]'2026-10-15T07:50:14Z'
        $calls = @{ n = 0 }; $slept = New-Object System.Collections.Generic.List[int]; $said = New-Object System.Collections.Generic.List[string]
        $ek = $script:EkLogin
        $r = Invoke-SISqlLoginRetry -Action { $calls.n++; [pscustomobject]@{ ExitCode = $(if ($calls.n -lt 3) { 1 } else { 0 }); Error = $(if ($calls.n -lt 3) { $ek } else { $null }) } }.GetNewClosure() `
            -AdminSetAt '2026-10-15T07:50:06.0000000Z' -Now { $now }.GetNewClosure() -Sleep { param($s) $slept.Add($s) }.GetNewClosure() -Print { param($t) $said.Add($t) }.GetNewClosure()
        $calls.n | Should -Be 3
        $r.Error | Should -BeNullOrEmpty
        @($slept) | Should -Be @(30, 30)
        $said.Count | Should -Be 1
    }
    It 'controls: a wrong password, another SQL error, or an admin set long ago is NEVER retried -- the real message at once' {
        $now = [datetime]'2026-10-15T07:50:14Z'
        foreach ($case in @(
            @{ Error = "Login failed for user 'sa'."; SetAt = '2026-10-15T07:50:06Z' },
            @{ Error = "Invalid object name 'vuln.VulnerabilityItem'."; SetAt = '2026-10-15T07:50:06Z' },
            @{ Error = $script:EkLogin; SetAt = '2026-10-15T06:00:00Z' },
            @{ Error = $script:EkLogin; SetAt = '' })) {
            $calls = @{ n = 0 }; $slept = New-Object System.Collections.Generic.List[int]; $err = $case.Error
            $r = Invoke-SISqlLoginRetry -Action { $calls.n++; [pscustomobject]@{ ExitCode = 1; Error = $err } }.GetNewClosure() -AdminSetAt $case.SetAt -Now { $now }.GetNewClosure() -Sleep { param($s) $slept.Add($s) }.GetNewClosure()
            $calls.n | Should -Be 1 -Because ('not waited for: {0} (admin set {1})' -f $case.Error, $case.SetAt)
            $slept.Count | Should -Be 0
            $r.Error | Should -Be $case.Error
        }
        # run here, not inside a Should -Throw block: a closure made inside that block does not see this test's variables
        $thrownCalls = @{ n = 0 }
        $netAction = { $thrownCalls.n++; throw 'A network-related or instance-specific error occurred' }.GetNewClosure()
        $nowFn = { $now }.GetNewClosure()
        $caught = ''
        try { $null = Invoke-SISqlLoginRetry -Action $netAction -AdminSetAt '2026-10-15T07:50:06Z' -Now $nowFn -Sleep { } } catch { $caught = [string]$_.Exception.Message }
        $caught | Should -BeLike '*network-related*'
        $thrownCalls.n | Should -Be 1
    }
    It 'bounded: a refusal that does not go away is retried for 5 minutes (30 s steps), then the real message' {
        $clock = @{ t = [datetime]'2026-10-15T07:50:14Z' }
        $calls = @{ n = 0 }; $ek = $script:EkLogin
        $r = Invoke-SISqlLoginRetry -Action { $calls.n++; [pscustomobject]@{ ExitCode = 1; Error = $ek } }.GetNewClosure() -AdminSetAt '2026-10-15T07:50:06Z' `
            -Now { $clock.t }.GetNewClosure() -Sleep { param($s) $clock.t = $clock.t.AddSeconds($s) }.GetNewClosure()
        $calls.n | Should -Be 11 -Because 'the first try and 10 more, 30 s apart'
        $r.Error | Should -Be $script:EkLogin
        # thrown the same way: waited out, then thrown again
        $tc = @{ n = 0 }
        $thrownAction = { $tc.n++; if ($tc.n -lt 2) { throw $ek }; 'ok' }.GetNewClosure()
        $out = Invoke-SISqlLoginRetry -Action $thrownAction -AdminSetAt '2026-10-15T07:50:06Z' -Now { [datetime]'2026-10-15T07:50:14Z' } -Sleep { }
        $out | Should -Be 'ok'
        $tc.n | Should -Be 2
    }
    It 'WIRING: setup\Set-SISqlAdminGroup.ps1 waits for both of its admin writes (the admin, and its kind) before it returns' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Set-SISqlAdminGroup.ps1'))
        $src | Should -Match ([regex]::Escape(". ([IO.Path]::Combine(`$PSScriptRoot, '_shared', 'SI-SqlAdminReady.ps1'))"))
        $src | Should -Match '(?s)-Method PUT -Path \$adminPath.*?Wait-SISqlAdminWrite -Response \$r -Rest \$siAdminRest -AdminPath \$adminPath -Sid \(\[string\]\$grp\.id\) -Login \$GroupName'
        $src | Should -Match '(?s)-Method PATCH -Path \$serverUri.*?Wait-SIArmAsyncOperation -Response \$r -Rest \$siAdminRest'
    }
}

Describe 'a failed job write is reported readably' {
    It 'names the job and what Azure said -- the environment values are not in the message' {
        $script:Boot | Should -Match ([regex]::Escape("throw ('{0} of Container Apps job {1} failed: {2}' -f"))
        $script:Boot | Should -Not -Match 'Format-SIAzArgsForMessage'
    }
}
Describe 'the collection jobs are sized for the tenant (customer H: 22,705 users + 5,097 groups ran out of memory at 2 GiB)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'identity counts users + groups + service principals; endpoint counts devices; only Container Apps'' CPU/memory pairs' {
        Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 122; Groups = 579; ServicePrincipals = 1136 } | Should -BeNullOrEmpty
        $m = Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 6000; Groups = 2000; ServicePrincipals = 400 }
        # 4 CPU / 8 GiB from 5,000 objects up since 2026-10-12 (it was 2 CPU / 4 GiB up to 15,000; owner: "we can always lower it later")
        ($m.Cpu, $m.Memory, $m.ReplicaTimeout) | Should -Be @('4.0', '8.0Gi', 604800)
        $l = Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 22705; Groups = 5097; ServicePrincipals = 433 }
        ($l.Cpu, $l.Memory) | Should -Be @('4.0', '8.0Gi')
        (Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 16000 }).Memory | Should -Be '8.0Gi'
        Get-SITenantSizedJobResources -Engine identity -Counts @{ Devices = 99999 } | Should -BeNullOrEmpty -Because 'identity does not count devices'
        Get-SITenantSizedJobResources -Engine publicip -Counts @{ Users = 99999 } | Should -BeNullOrEmpty -Because 'an engine outside the rule is never sized'
    }
    It 'the threshold is 5,000 objects (owner 2026-10-12: "we can always lower it later"): 4,999 keeps the default, 5,000 gets 4 CPU / 8 GiB' {
        Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 3000; Groups = 1500; ServicePrincipals = 499 } | Should -BeNullOrEmpty
        $at = Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 3000; Groups = 1500; ServicePrincipals = 500 }
        ($at.Cpu, $at.Memory, $at.ReplicaTimeout, $at.Objects) | Should -Be @('4.0', '8.0Gi', 604800, 5000)
        Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 4999 } | Should -BeNullOrEmpty
        (Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 5000 }).Memory | Should -Be '8.0Gi'
        # at install: the job is written with that size (Get-SIContainerJobResources is what Bootstrap asks)
        $r = Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts @{ Users = 3000; Groups = 1500; ServicePrincipals = 500 }
        ($r.Cpu, $r.Memory) | Should -Be @('4.0', '8.0Gi')
    }
    It 'the Azure collection is sized too since 2026-10-12 (a new install ran its Azure worker out of memory at 4 GiB): it counts every object of the tenant' {
        Get-SITenantSizedJobResources -Engine azure -Counts @{ Users = 2000; Groups = 1000; ServicePrincipals = 999; Devices = 1000 } | Should -BeNullOrEmpty -Because '4,999 objects'
        $a = Get-SITenantSizedJobResources -Engine azure -Counts @{ Users = 2000; Groups = 1000; ServicePrincipals = 1000; Devices = 1000 }
        ($a.Cpu, $a.Memory, $a.Objects) | Should -Be @('4.0', '8.0Gi', 5000)
        (Get-SITenantSizedJobResources -Engine azure -Counts @{ Users = 99999 }).ReplicaTimeout | Should -Be 604800
    }
    It 'a large tenant raises the default; a size the customer set wins; without counts nothing changes' {
        $big = @{ Users = 22705; Groups = 5097; ServicePrincipals = 433 }
        $r = Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $big
        ($r.Cpu, $r.Memory) | Should -Be @('4.0', '8.0Gi')
        @($r.Notes) -join ' ' | Should -Match 'sized for this tenant'
        $own = Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $big -Globals @{ SI_Bootstrap_Memory_Identity = '2.0Gi'; SI_Bootstrap_Cpu_Identity = '1.0' }
        ($own.Cpu, $own.Memory) | Should -Be @('1.0', '2.0Gi') -Because 'a size the customer set wins over the tenant sizing'
        (Get-SIContainerJobResources -Engine identity -Kind Schedule).Memory | Should -Be '4.0Gi'   # the floor (2026-10-10)
    }
    It 'every job of a new install gets the longest run limit Azure takes, 7 days, at ANY tenant size (owner 2026-10-13: SecurityInsight chooses no run limit; customer H 2026-10-09 was stopped at the 1-hour default while publishing its records); a timeout the customer set wins' {
        $big = @{ Users = 22705; Groups = 5097; ServicePrincipals = 433 }
        (Get-SIContainerJobResources -Engine identity -Kind Schedule).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $big).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts @{ Users = 6000; Groups = 2000; ServicePrincipals = 400 }).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts @{ Users = 100 }).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine endpoint -Kind Keda -TenantCounts @{ Devices = 20000 }).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine risk-analysis -Kind RiskAnalysis -TenantCounts @{ Users = 80000; Devices = 25000 }).ReplicaTimeout | Should -Be 604800
        (Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $big -Globals @{ SI_Bootstrap_ReplicaTimeout_Identity = '3600' }).ReplicaTimeout | Should -Be 3600 -Because 'a shorter run limit the customer set on purpose wins'
        @((Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $big).Notes) -join ' ' | Should -Not -Match 'runs for up to' -Because 'no run-time band by tenant size any more'
    }
    It 'Bootstrap reads the tenant''s counts once and passes them to every job''s size' {
        $script:Boot | Should -Match ([regex]::Escape('Get-SIContainerJobResources -Engine $engine -Kind $jobKind -Globals $bootGlobals -TenantCounts $script:SITenantCounts'))
        # #521: Microsoft Graph $count over setup's own REST sign-in (setup\_shared\SI-SetupArm.ps1)
        $script:Boot | Should -Match ([regex]::Escape('$script:SITenantCounts = Get-SITenantDirectoryCounts'))
        $script:Arm | Should -Match ([regex]::Escape("'https://graph.microsoft.com/v1.0/{0}/`$count'"))
        $script:Arm | Should -Match ([regex]::Escape("@{ ConsistencyLevel = 'eventual' }"))
    }
}
