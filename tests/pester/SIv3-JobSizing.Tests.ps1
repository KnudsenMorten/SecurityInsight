#Requires -Version 5.1
<#
    #509 THE JOB SIZE ON EVERY UPDATE (operator 2026-10-09: "both si and pim are allowed to go to 4 cpu/8 gb if needed",
    "it is very little money"). setup/_shared/SI-JobSizing.ps1: the install-time rule (Get-SITenantSizedJobResources) applied
    by every update -- raise only, never above 4 CPU / 8 GiB, a size the customer set wins, the counts fallback
    (Graph -> sidata.CiRecord -> run health), and one band up after an out-of-memory or timed-out run. THE RUN LIMIT (owner
    2026-10-13: "we are not to judge that and it breaks the whole solution"): SecurityInsight chooses none -- every engine
    job gets the longest run limit Azure takes (Get-SIJobRunLimit, 7 days), at install and from the update's floor step
    (Invoke-SIJobFloor); the measured rule, the 4 h floor, the doubling and the tenant-size run-time bands are gone. Offline, against a
    fake ARM / Graph / Log Analytics behind the REST seam (#521: no az CLI; the change is ONE read-modify-write ARM PATCH).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    function script:New-Job([string]$Name, [string]$Cpu = '1.0', [string]$Memory = '2.0Gi', [int]$Timeout = 3600) {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{
            configuration = [pscustomobject]@{ triggerType = 'Schedule'; replicaTimeout = $Timeout; replicaRetryLimit = 0
                scheduleTriggerConfig = [pscustomobject]@{ cronExpression = '0 2 * * *'; parallelism = 1; replicaCompletionCount = 1 }
                secrets = @([pscustomobject]@{ name = 'si-license'; keyVaultUrl = 'https://kv/secrets/SI-License'; identity = '/x/uami' }) }
            template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; image = 'acr.io/si-orchestrator:v1'; imageType = 'ContainerImage'
                env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'identity' }, [pscustomobject]@{ name = 'SI_SECRET'; secretRef = 'si-license' })
                resources = [pscustomobject]@{ cpu = [double]$Cpu; memory = $Memory; ephemeralStorage = '4Gi' } }) } } }
    }
    function script:New-Exec([string]$Name, [string]$Status, [datetime]$Start, [int]$Seconds) {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ status = $Status; startTime = $Start.ToString('o'); endTime = $Start.AddSeconds($Seconds).ToString('o') } }
    }
    $script:T0 = [datetime]::new(2026, 10, 8, 3, 0, 0, [DateTimeKind]::Utc)
    $script:Big = @{ Users = 22705; Groups = 5097; ServicePrincipals = 433; Devices = 900 }
    # a fake Azure behind the REST seam: Graph counts (or refused), the jobs, executions per job, Log Analytics answers per
    # query kind; every call recorded as '<METHOD> <url>', every PATCH body kept
    function script:New-World([hashtable]$Counts, [hashtable]$Execs = @{}, [hashtable]$La = @{}, [string]$UpdateError = '', [object[]]$Jobs = @()) {
        $byName = @{}; foreach ($j in $Jobs) { $byName[[string]$j.name] = $j }
        [pscustomobject]@{ Counts = $Counts; Execs = $Execs; La = $La; UpdateError = $UpdateError; Jobs = $byName; Bodies = @{}; Calls = (New-Object System.Collections.Generic.List[string]) }
    }
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        $ok = { param($o) [pscustomobject]@{ Status = 200; Body = $(if ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 12 -Compress }) } }
        if ($Uri -like 'https://graph.microsoft.com/*') {
            if (-not $w.Counts) { return [pscustomobject]@{ Status = 403; Body = 'Forbidden' } }
            $k = ([regex]::Match($Uri, '/v1\.0/(\w+)/')).Groups[1].Value
            return (& $ok ([string]$w.Counts[$k]))
        }
        if ($Method -eq 'GET' -and $Uri -like '*Microsoft.App/jobs/*/executions*') {
            $j = ([regex]::Match($Uri, '/jobs/([^/]+)/executions')).Groups[1].Value
            return (& $ok ([pscustomobject]@{ value = @($w.Execs[$j]) }))
        }
        if ($Method -eq 'POST' -and $Uri -like '*api/query*') {
            $q = ([string]$Body | ConvertFrom-Json).query
            $kind = if ($q -like '*summarize Assets*') { 'RunHealthCounts' } elseif ($q -like '*ContainerAppSystemLogs*') { 'SystemLogs' } else { 'RunHealthRows' }
            $rows = @($w.La[$kind])
            if (-not $rows.Count) { return (& $ok ([pscustomobject]@{ tables = @([pscustomobject]@{ columns = @(); rows = @() }) })) }
            $cols = @($rows[0].PSObject.Properties | ForEach-Object { [pscustomobject]@{ name = $_.Name } })
            $vals = @($rows | ForEach-Object { , @($_.PSObject.Properties | ForEach-Object { $_.Value }) })
            return (& $ok ([pscustomobject]@{ tables = @([pscustomobject]@{ columns = $cols; rows = $vals }) }))
        }
        if ($Uri -match '/Microsoft\.App/jobs/([^/?]+)\?api-version=') {
            $n = $Matches[1]
            if ($Method -eq 'GET') { if ($w.Jobs.ContainsKey($n)) { return (& $ok $w.Jobs[$n]) }; return [pscustomobject]@{ Status = 404; Body = 'not found' } }
            if ($Method -eq 'PATCH') {
                if ($w.UpdateError) { return [pscustomobject]@{ Status = 403; Body = ('{"error":{"code":"' + $w.UpdateError + '","message":"no"}}') } }
                # an Azure that refuses a run limit above RefuseAbove seconds (when the world has one); every PATCH's run limit is kept in Asked
                if ($w.PSObject.Properties['RefuseAbove']) {
                    $cfg = ([string]$Body | ConvertFrom-Json).properties.PSObject.Properties['configuration']
                    $to = if ($cfg) { [int]$cfg.Value.replicaTimeout } else { 0 }
                    $w.Asked.Add(('{0}={1}' -f $n, $to))
                    if ($to -gt [int]$w.RefuseAbove) { return [pscustomobject]@{ Status = 400; Body = '{"error":{"code":"InvalidRequestParameterWithDetails","message":"ReplicaTimeout must be between 1 and 86400"}}' } }
                }
                $w.Bodies[$n] = [string]$Body
                return [pscustomobject]@{ Status = 202; Body = '' }
            }
        }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
}

Describe 'which jobs are sized, and as what' {
    It 'identity / endpoint / the Azure collection (scheduled or KEDA), the CI build and every Risk Analysis job; nothing else' {
        (Get-SIJobSizingEngine 'caj-si-identity').Engine | Should -Be 'identity'
        $w = Get-SIJobSizingEngine 'caj-si-endpoint-worker'; $w.Engine | Should -Be 'endpoint'; $w.Role | Should -Be 'worker'
        (Get-SIJobSizingEngine 'caj-si-asset-correlation').Engine | Should -Be 'asset-correlation'
        (Get-SIJobSizingEngine 'caj-si-risk-analysis-detailed').Engine | Should -Be 'risk-analysis-detailed'
        (Get-SIJobSizingEngine 'caj-si-ra-board').Engine | Should -Be 'ra-board'
        foreach ($n in 'caj-si-ptc', 'caj-si-publicip', 'caj-si-updater', 'caj-si-flow', 'caj-si-asset-correlation-worker', 'caj-si-azure-other', 'other-job') { Get-SIJobSizingEngine $n | Should -BeNullOrEmpty }
    }
    It 'the Azure collection job is sized since 2026-10-12 (a new install ran its Azure worker out of memory at 4 GiB): the scheduled job, its producer and its worker, on every object of the tenant' {
        $a = Get-SIJobSizingEngine 'caj-si-azure'; $a.Engine | Should -Be 'azure'; $a.Role | Should -Be 'job'
        (Get-SIJobSizingEngine 'caj-si-azure-producer').Role | Should -Be 'producer'
        $aw = Get-SIJobSizingEngine 'caj-si-azure-worker'; $aw.Engine | Should -Be 'azure'; $aw.Role | Should -Be 'worker'
        # no count of Azure resources is known, so it counts as the tenant does: users + groups + service principals + devices
        Get-SITenantSizedJobResources -Engine azure -Counts @{ Users = 2000; Groups = 1000; ServicePrincipals = 999; Devices = 1000 } | Should -BeNullOrEmpty -Because '4,999 objects'
        $s = Get-SITenantSizedJobResources -Engine azure -Counts @{ Users = 2000; Groups = 1000; ServicePrincipals = 1000; Devices = 1000 }
        ($s.Cpu, $s.Memory, $s.Objects) | Should -Be @('4.0', '8.0Gi', 5000)
        # on update: an Azure job at 2 CPU / 4 GiB on that tenant is raised
        $c = Get-SIJobSizeChange -JobName 'caj-si-azure-worker' -Engine azure -Current (Get-SIJobCurrentSize (New-Job 'caj-si-azure-worker' '2.0' '4.0Gi' 7200)) -Counts $script:Big -CountsFrom 'the directory'
        $c.Action | Should -Be 'raise'; $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'
        $c.Line | Should -Match '29,135 objects \(from the directory\)$'
    }
    It 'a tenant of 5,000 objects or more gets 4 CPU / 8 GiB jobs (owner 2026-10-12: "we can always lower it later"; it was 2 CPU / 4 GiB up to 15,000): just below, at it; the run limit is the same at every size' {
        Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 4999 } | Should -BeNullOrEmpty -Because 'below 5,000 the job kind''s default stands'
        Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 4999; Users = 90000 } | Should -BeNullOrEmpty -Because 'endpoint counts devices only'
        $at = Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = 3000; Groups = 1500; ServicePrincipals = 500 }
        ($at.Cpu, $at.Memory, $at.ReplicaTimeout, $at.Objects) | Should -Be @('4.0', '8.0Gi', 604800, 5000)
        $mid = Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 14999 }
        ($mid.Cpu, $mid.Memory, $mid.ReplicaTimeout) | Should -Be @('4.0', '8.0Gi', 604800)
        $top = Get-SITenantSizedJobResources -Engine endpoint -Counts @{ Devices = 15000 }
        ($top.Cpu, $top.Memory, $top.ReplicaTimeout) | Should -Be @('4.0', '8.0Gi', 604800) -Because 'no run-time band by tenant size any more'
        # on update: the same threshold. A job at 2 CPU / 4 GiB keeps its size at 4,999 objects and is raised at 5,000
        $cur = Get-SIJobCurrentSize (New-Job 'caj-si-endpoint' '2.0' '4.0Gi' 7200)
        (Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current $cur -Counts @{ Devices = 4999 }).Action | Should -Be 'keep'
        $up = Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current $cur -Counts @{ Devices = 5000 } -CountsFrom 'the directory'
        $up.Action | Should -Be 'raise'
        $up.Line | Should -Be 'job size: caj-si-endpoint raised 2.0 CPU / 4.0Gi, 2 h -> 4.0 CPU / 8.0Gi, 2 h -- 5,000 objects (from the directory)'
    }
    It 'the jobs that load the whole Risk Analysis result are sized like Risk Analysis (customer H 2026-10-10: data sync out of memory at 2 GiB)' {
        foreach ($n in 'asset-datasync', 'asset-vulnerabilities') {
            (Get-SIJobSizingEngine "caj-si-$n").Engine | Should -Be $n
            (Get-SITenantSizedJobResources -Engine $n -Counts $script:Big).Memory | Should -Be '8.0Gi'
        }
        $f = [pscustomobject]@{ Kind = 'oom'; Reason = 'its last run was stopped out of memory' }
        $c = Get-SIJobSizeChange -JobName 'caj-si-asset-datasync' -Engine 'asset-datasync' -Current (Get-SIJobCurrentSize (New-Job 'caj-si-asset-datasync')) -Counts @{ Users = 10; Devices = 10 } -Failure $f
        $c.Action | Should -Be 'raise'; $c.Memory | Should -Be '4.0Gi' -Because 'an out-of-memory run goes up one band'
    }
    It 'Risk Analysis counts every object (the same rule at install)' {
        Get-SITenantSizedJobResources -Engine 'risk-analysis' -Counts @{ Users = 1000; Devices = 500 } | Should -BeNullOrEmpty
        (Get-SITenantSizedJobResources -Engine 'risk-analysis-detailed' -Counts $script:Big).Memory | Should -Be '8.0Gi'
        (Get-SITenantSizedJobResources -Engine 'ra-board' -Counts @{ Users = 3000; Devices = 3000 }).Memory | Should -Be '8.0Gi' -Because '6,000 objects: 4 CPU / 8 GiB from 5,000 up since 2026-10-12 (it was 2 CPU / 4 GiB)'
        Get-SITenantSizedJobResources -Engine 'ra-board' -Counts @{ Users = 3000; Devices = 1999 } | Should -BeNullOrEmpty -Because 'users and devices are counted together: 4,999'
        (Get-SIContainerJobResources -Engine 'risk-analysis' -Kind RiskAnalysis -TenantCounts $script:Big).Cpu | Should -Be '4.0'
    }
}

Describe 'the rule on update: raise only, the cap, the customer wins' {
    It 'an install made before the rule is raised to the size the counts give' {
        $c = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity')) -Counts $script:Big -CountsFrom 'the directory'
        $c.Action | Should -Be 'raise'; $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'
        $c.ReplicaTimeout | Should -Be 3600 -Because 'the sizing changes CPU and memory only: the run limit is the floor step''s'
        $c.Line | Should -Be 'job size: caj-si-identity raised 1.0 CPU / 2.0Gi, 1 h -> 4.0 CPU / 8.0Gi, 1 h -- 28,235 objects (from the directory)'
    }
    It 'never lowers: a large job on a small tenant stays as it is' {
        $c = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity' '4.0' '8.0Gi' 14400)) -Counts @{ Users = 10 }
        $c.Action | Should -Be 'keep'
        # 6,000 devices give 4 CPU / 8 GiB and 2 h (since 2026-10-12): a job already at that size with a longer run time keeps both
        $mid = Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current (Get-SIJobCurrentSize (New-Job 'caj-si-endpoint' '4.0' '8.0Gi' 21600)) -Counts @{ Devices = 6000 }
        $mid.Action | Should -Be 'keep' -Because 'the run time is already longer than the rule gives'
        $mid.ReplicaTimeout | Should -Be 21600; $mid.Memory | Should -Be '8.0Gi'
        # a 2 CPU / 4 GiB job on a tenant just under the threshold (4,999 devices) is not touched either
        $under = Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current (Get-SIJobCurrentSize (New-Job 'caj-si-endpoint' '2.0' '4.0Gi' 21600)) -Counts @{ Devices = 4999 }
        $under.Action | Should -Be 'keep'; $under.Cpu | Should -Be '2.0'; $under.Memory | Should -Be '4.0Gi'; $under.ReplicaTimeout | Should -Be 21600
    }
    It 'A COUNT NOT KNOWN sizes for a large tenant (owner 2026-10-16: "we can always lower it later"; customer I 153k users ran on 2 CPU / 4 GiB): no counts at all -> every sized job 4 CPU / 8 GiB, one plain reason' {
        foreach ($e in 'identity', 'endpoint', 'azure', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'ra-board', 'asset-datasync', 'asset-vulnerabilities') {
            $c = Get-SIJobSizeChange -JobName "caj-si-$e" -Engine $e -Current (Get-SIJobCurrentSize (New-Job "caj-si-$e" '2.0' '4.0Gi')) -Counts $null
            $c.Action | Should -Be 'raise' -Because "$e has no known count"
            $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'
            $c.Line | Should -Match ' -- the tenant''s size could not be read -- sized for a large tenant$'
        }
        (Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity')) -Counts @{}).Memory | Should -Be '8.0Gi' -Because 'an empty answer is no answer'
        (Get-SIJobSizeChange -JobName 'caj-si-close-loop-mail' -Engine close-loop-mail -Current (Get-SIJobCurrentSize (New-Job 'caj-si-close-loop-mail')) -Counts $null -NoResize).Action | Should -Be 'keep' -Because 'a job this sizing does not cover is never resized'
    }
    It 'only ONE half known: the job that counts the missing half (or every object) is sized for a large tenant; the job whose half is known keeps the rule; a 0 is not known' {
        $cur = Get-SIJobCurrentSize (New-Job 'x' '2.0' '4.0Gi')
        $dev = @{ Users = 0; Groups = 0; ServicePrincipals = 0; Devices = 300 }
        (Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $dev).Memory | Should -Be '8.0Gi'
        (Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current $cur -Counts $dev).Action | Should -Be 'keep'
        (Get-SIJobSizeChange -JobName 'caj-si-risk-analysis' -Engine risk-analysis -Current $cur -Counts $dev).Memory | Should -Be '8.0Gi' -Because 'it reads every object; the identity half is missing'
        $id = @{ Users = 900; Groups = 50; ServicePrincipals = 40; Devices = 0 }
        (Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $id).Action | Should -Be 'keep'
        (Get-SIJobSizeChange -JobName 'caj-si-endpoint-worker' -Engine endpoint -Current $cur -Counts $id).Memory | Should -Be '8.0Gi'
        (Get-SIJobSizeChange -JobName 'caj-si-azure' -Engine azure -Current $cur -Counts $id).Memory | Should -Be '8.0Gi'
        Test-SIJobSizingCountKnown -Engine identity -Counts @{ Users = 0; Groups = 9000 } | Should -BeFalse -Because 'no users = the identity half was not read'
        Test-SIJobSizingCountKnown -Engine asset-correlation -Counts @{ Users = 1; Devices = 1 } | Should -BeTrue
    }
    It 'NEGATIVE: a KNOWN count below 5,000 keeps today''s size; a failure still goes one band up with both reasons said' {
        $small = @{ Users = 1200; Groups = 300; ServicePrincipals = 200; Devices = 900 }
        foreach ($e in 'identity', 'endpoint', 'azure', 'asset-correlation', 'risk-analysis') {
            $c = Get-SIJobSizeChange -JobName "caj-si-$e" -Engine $e -Current (Get-SIJobCurrentSize (New-Job "caj-si-$e")) -Counts $small
            $c.Action | Should -Be 'keep'; $c.Memory | Should -Be '2.0Gi'
        }
        $f = [pscustomobject]@{ Kind = 'oom'; Reason = 'its last run (x) was stopped out of memory' }
        $u = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity' '2.0' '4.0Gi')) -Counts $null -Failure $f
        $u.Memory | Should -Be '8.0Gi'; @($u.Reasons) | Should -Be @('the tenant''s size could not be read -- sized for a large tenant', 'its last run (x) was stopped out of memory')
    }
    It 'never above 4 CPU / 8 GiB; NEGATIVE: a run stopped at its limit no longer changes the run time here (no doubling, no 4 h floor)' {
        $f = [pscustomobject]@{ Kind = 'timeout'; Reason = 'its last run was stopped at its replica timeout' }
        foreach ($to in 7200, 14400, 21600, 86400, 604800) {
            $c = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity' '4.0' '8.0Gi' $to)) -Failure $f
            $c.Action | Should -Be 'keep'; $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'; $c.ReplicaTimeout | Should -Be $to
        }
        $m = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity' '4.0' '8.0Gi' 14400)) -Failure ([pscustomobject]@{ Kind = 'oom'; Reason = 'out of memory' })
        $m.Action | Should -Be 'keep'; @($m.Notes)[0] | Should -Match 'largest CPU and memory Container Apps gives a job'
    }
    It 'NO run-time band by tenant size: a tenant of a million objects and one of 5,000 get the same run limit, and the sizing rule never writes one' {
        $r = Get-SITenantSizedJobResources -Engine asset-correlation -Counts @{ Users = 600000; Groups = 200000; ServicePrincipals = 50000; Devices = 150000 }
        $r.ReplicaTimeout | Should -Be (Get-SIJobRunLimit); $r.Cpu | Should -Be '4.0'
        foreach ($n in 5000, 14999, 99000, 100000) { (Get-SITenantSizedJobResources -Engine identity -Counts @{ Users = $n }).ReplicaTimeout | Should -Be 604800 }
        $u = Get-SIJobSizeChange -JobName 'caj-si-asset-correlation' -Engine asset-correlation -Current (Get-SIJobCurrentSize (New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 14400)) -Counts @{ Users = 80000; Devices = 25000 } -CountsFrom 'the directory'
        $u.Action | Should -Be 'keep' -Because 'CPU and memory are at the top; the run limit is the floor step''s, not the sizing''s'
        $u.ReplicaTimeout | Should -Be 14400
    }
    It 'a size the customer set wins (CPU / memory); the run time is not the sizing''s to change' {
        $cur = Get-SIJobCurrentSize (New-Job 'caj-si-identity')
        $c = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $script:Big -Globals @{ SI_Bootstrap_Memory_Identity = '2.0Gi' }
        $c.Action | Should -Be 'keep'; $c.Memory | Should -Be '2.0Gi'; $c.Cpu | Should -Be '1.0'; $c.ReplicaTimeout | Should -Be 3600
        @($c.Notes) -join ' ' | Should -Match 'SI_Bootstrap_Memory_Identity is set'
        $t = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $script:Big -Globals @{ SI_Bootstrap_ReplicaTimeout_Identity = '3600' }
        $t.ReplicaTimeout | Should -Be 3600; $t.Memory | Should -Be '8.0Gi'
        $both = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $script:Big -Globals @{ SI_Bootstrap_Cpu_Identity = '1.0'; SI_Bootstrap_ReplicaTimeout_Identity = '3600' }
        $both.Action | Should -Be 'keep'
    }
}

Describe 'learn from failures: one band up' {
    It 'an out-of-memory run goes up one band (2/4, then 4/8) even when the counts do not ask for it' {
        $f = [pscustomobject]@{ Kind = 'oom'; Reason = 'its last run (x) was stopped out of memory' }
        $c = Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current (Get-SIJobCurrentSize (New-Job 'caj-si-endpoint')) -Counts @{ Devices = 50 } -Failure $f
        $c.Cpu | Should -Be '2.0'; $c.Memory | Should -Be '4.0Gi'; $c.ReplicaTimeout | Should -Be 3600
        $c.Line | Should -Match 'stopped out of memory$'
        (Get-SIJobSizeChange -JobName 'caj-si-endpoint' -Engine endpoint -Current (Get-SIJobCurrentSize (New-Job 'caj-si-endpoint' '2.0' '4.0Gi')) -Failure $f).Memory | Should -Be '8.0Gi'
    }
    It 'a run stopped at its limit goes up the next CPU / memory band, as before; its run time is left to the floor step' {
        $f = [pscustomobject]@{ Kind = 'timeout'; Reason = 'timeout' }
        $c = Get-SIJobSizeChange -JobName 'caj-si-asset-correlation' -Engine asset-correlation -Current (Get-SIJobCurrentSize (New-Job 'caj-si-asset-correlation' '2.0' '4.0Gi' 7200)) -Failure $f
        $c.Action | Should -Be 'raise'; $c.Memory | Should -Be '8.0Gi'; $c.ReplicaTimeout | Should -Be 7200
        # a step of the pipeline that is no sized job: nothing here changes it
        $n = Get-SIJobSizeChange -JobName 'caj-si-close-loop-mail' -Engine close-loop-mail -Current (Get-SIJobCurrentSize (New-Job 'caj-si-close-loop-mail' '2.0' '4.0Gi' 7200)) -Failure $f -Counts $script:Big -NoResize
        $n.Action | Should -Be 'keep'; $n.Cpu | Should -Be '2.0'; $n.ReplicaTimeout | Should -Be 7200
    }
    It 'the signal: OOMKilled in the system log, an OutOfMemory end, the replica timeout, a start with no end' {
        $e = @(New-Exec 'caj-si-identity-a1' 'Failed' $script:T0 900; New-Exec 'caj-si-identity-a0' 'Succeeded' $script:T0.AddDays(-1) 900)
        (Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions $e -SystemLogRows @([pscustomobject]@{ Exec = 'caj-si-identity-a1'; Job = 'caj-si-identity'; Reason = 'OOMKilled'; Msg = ''; TimeGenerated = $script:T0.AddMinutes(14).ToString('o') })).Kind | Should -Be 'oom'
        $rhOom = @([pscustomobject]@{ Engine = 'identity'; Phase = 'End'; ExitReason = 'error'; ErrorMessage = 'System.OutOfMemoryException'; TimeGenerated = $script:T0.AddMinutes(14).ToString('o') })
        (Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions $e -RunHealthRows $rhOom).Reason | Should -Match 'run health'
        $to = @(New-Exec 'caj-si-identity-b1' 'Failed' $script:T0 3600)
        $s = Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions $to
        $s.Kind | Should -Be 'timeout'; $s.Reason | Should -Match 'replica timeout after 1 h'
        $rhStart = @([pscustomobject]@{ Engine = 'identity'; Phase = 'Start'; ExitReason = ''; ErrorMessage = ''; TimeGenerated = $script:T0.AddMinutes(1).ToString('o') })
        (Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions $e -RunHealthRows $rhStart).Kind | Should -Be 'oom'
    }
    It 'a worker that ran out of memory although its run ended "Succeeded" is raised (a new install 2026-10-12: the Azure worker caught the error and ended cleanly); NEGATIVE: another error, another engine or another time is no signal' {
        $e = @(New-Exec 'caj-si-azure-worker-k1' 'Succeeded' $script:T0 120; New-Exec 'caj-si-azure-worker-k0' 'Failed' $script:T0.AddDays(-1) 120)
        $row = { param([string]$Engine, [string]$Msg, [datetime]$At) [pscustomobject]@{ Engine = $Engine; Phase = 'End'; ExitReason = 'error'; ErrorMessage = $Msg; TimeGenerated = $At.ToString('o') } }
        $s = Get-SIJobFailureSignal -JobName 'caj-si-azure-worker' -Engine azure -ReplicaTimeout 7200 -Executions $e -RunHealthRows @(& $row 'azure' 'System.OutOfMemoryException in Enrich' ($script:T0.AddMinutes(1)))
        $s.Kind | Should -Be 'oom'; $s.Execution | Should -Be 'caj-si-azure-worker-k1'
        $s.Reason | Should -Match 'ran out of memory \(its run health says so\), although the run itself ended without an error$'
        Get-SIJobFailureSignal -JobName 'caj-si-azure-worker' -Engine azure -ReplicaTimeout 7200 -Executions $e -RunHealthRows @(& $row 'azure' 'Forbidden' ($script:T0.AddMinutes(1))) | Should -BeNullOrEmpty -Because 'another error is not a size problem'
        Get-SIJobFailureSignal -JobName 'caj-si-azure-worker' -Engine azure -ReplicaTimeout 7200 -Executions $e -RunHealthRows @(& $row 'identity' 'System.OutOfMemoryException' ($script:T0.AddMinutes(1))) | Should -BeNullOrEmpty -Because 'another engine''s record'
        Get-SIJobFailureSignal -JobName 'caj-si-azure-worker' -Engine azure -ReplicaTimeout 7200 -Executions $e -RunHealthRows @(& $row 'azure' 'System.OutOfMemoryException' ($script:T0.AddHours(3))) | Should -BeNullOrEmpty -Because 'a record from long after the run'
        # and the signal raises the job one band, whatever the counts say
        $c = Get-SIJobSizeChange -JobName 'caj-si-azure-worker' -Engine azure -Current (Get-SIJobCurrentSize (New-Job 'caj-si-azure-worker' '2.0' '4.0Gi' 7200)) -Counts @{ Users = 10 } -Failure $s
        $c.Action | Should -Be 'raise'; $c.Cpu | Should -Be '4.0'; $c.Memory | Should -Be '8.0Gi'; $c.ReplicaTimeout | Should -Be 7200
    }
    It 'no signal: the last run succeeded, or failed for another reason (it ended, with its own error)' {
        $ok = @(New-Exec 'caj-si-identity-c1' 'Succeeded' $script:T0 900; New-Exec 'caj-si-identity-c0' 'Failed' $script:T0.AddDays(-1) 3600)
        Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions $ok | Should -BeNullOrEmpty -Because 'only the LAST run counts'
        $rh = @([pscustomobject]@{ Engine = 'identity'; Phase = 'Start'; TimeGenerated = $script:T0.AddMinutes(1).ToString('o') }, [pscustomobject]@{ Engine = 'identity'; Phase = 'End'; ExitReason = 'error'; ErrorMessage = 'Forbidden'; TimeGenerated = $script:T0.AddMinutes(10).ToString('o') })
        Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions @(New-Exec 'caj-si-identity-d1' 'Failed' $script:T0 700) -RunHealthRows $rh | Should -BeNullOrEmpty
    }
}

Describe 'THE RUN LIMIT: SecurityInsight chooses none -- every engine job gets the longest one Azure takes, at install and on every update (owner 2026-10-13: "we are not to judge that and it breaks the whole solution")' {
    BeforeAll {
        $script:StepKeys = @([pscustomobject]@{ Key = 'ptc'; Engine = 'privilege-tier-classifier' }, [pscustomobject]@{ Key = 'azure'; Engine = 'azure' }, [pscustomobject]@{ Key = 'close-loop-mail'; Engine = 'close-loop-mail' })
        $script:Why = 'a step gets the longest run limit Azure takes (7 days); SecurityInsight sets no shorter one'
        function script:Invoke-Floor([object[]]$Jobs, [hashtable]$Globals = @{}, [string]$UpdaterName = '', [switch]$WhatIf) {
            Invoke-SIJobFloor -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $Jobs -Globals $Globals -UpdaterName $UpdaterName -Steps $script:StepKeys -WhatIf:$WhatIf
        }
    }
    BeforeEach { Set-SIRunLimitRefused -Value $false }
    AfterAll { Set-SIRunLimitRefused -Value $false }
    It 'ONE named value, 7 days (604,800 s), used by every default: a new install''s engine jobs carry it at any tenant size; the measured rule, the 4 h floor and the doubling are gone' {
        Get-SIJobRunLimit | Should -Be 604800
        foreach ($kind in 'Keda', 'RiskAnalysis', 'Manual', 'Schedule') {
            (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind $kind).ReplicaTimeout | Should -Be 604800
            (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind $kind -TenantCounts @{ Users = 10 }).ReplicaTimeout | Should -Be 604800
            (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind $kind -TenantCounts @{ Users = 900000; Devices = 400000 }).ReplicaTimeout | Should -Be 604800
        }
        @((Get-SIContainerJobResources -Engine identity -Kind Schedule -TenantCounts $script:Big).Notes) -join ' ' | Should -Not -Match 'runs for up to' -Because 'the run time is not sized for the tenant any more'
        $p = @(Get-SIKedaProducerCreateArgs -Name 'caj-si-identity-producer' -ResourceGroup 'rg' -Environment 'cae' -Cron '0 4 * * *' -Image 'img' -LoginServer 'acr.io')
        $p[($p.IndexOf('--replica-timeout') + 1)] | Should -Be '604800'
        @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 604800) | Should -Be @('SI_QUEUE_LEASE_SECONDS=604800') -Because 'a storage queue gives no longer lease than 7 days'
        Format-SIJobTimeout -Seconds 604800 | Should -Be '7 days'; Format-SIJobTimeout -Seconds 7200 | Should -Be '2 h'; Format-SIJobTimeout -Seconds 86400 | Should -Be '24 h'
        foreach ($gone in 'Get-SIJobLongestRun', 'Get-SIJobMeasuredRunLimit') { Get-Command -Name $gone -ErrorAction Ignore | Should -BeNullOrEmpty }
        $lib = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1'))
        $lib | Should -Not -Match 'SIJobSizeTimeoutFloor|SIJobSizeTimeoutCap|SIJobRunLimitFactor|SIJobRunLimitDays|LongestRunSeconds'
    }
    It 'an existing job at 2 h is raised to 7 days by the update and the line says so -- with NO finished run and no count (a CI build stopped at 2 hours three runs in a row was left there by four updates)' {
        $jobs = @((New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 7200))
        $script:World = New-World -Counts $null -Jobs $jobs
        $r = Invoke-Floor $jobs
        @($r.Results)[0].Action | Should -Be 'raised'
        @($r.Lines) | Should -Be @("job size: caj-si-asset-correlation raised 4.0 CPU / 8.0Gi, 2 h -> 4.0 CPU / 8.0Gi, 7 days -- $($script:Why)")
        @($script:World.Calls | Where-Object { $_ -like '*executions*' -or $_ -like '*graph.microsoft.com*' -or $_ -like 'POST *' }) | Should -BeNullOrEmpty -Because 'the floor asks for no run history and no count'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -Be @('PATCH https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-asset-correlation?api-version=2025-07-01')
        $b = $script:World.Bodies['caj-si-asset-correlation'] | ConvertFrom-Json
        $b.properties.configuration.replicaTimeout | Should -Be 604800
        $b.properties.configuration.triggerType | Should -Be 'Schedule'
        $b.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '0 2 * * *'
        $b.properties.configuration.PSObject.Properties['secrets'] | Should -BeNullOrEmpty -Because 'ARM returns secrets without values; sending them would drop them'
        [double]$b.properties.template.containers[0].resources.cpu | Should -Be 4.0; $b.properties.template.containers[0].resources.memory | Should -Be '8.0Gi'
        # the update after that: one plain line, nothing sent
        $jobs = @((New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 604800))
        $script:World = New-World -Counts $null -Jobs $jobs
        $again = Invoke-Floor $jobs
        @($again.Lines) | Should -Be @('job size: caj-si-asset-correlation runs 4.0 CPU / 8.0Gi, 7 days -- nothing to raise')
        @($script:World.Calls) | Should -BeNullOrEmpty
    }
    It 'a job at 24 h or at 72 h is raised too, and EVERY engine job is covered -- a worker, a producer, a job that is no step of the pipeline; NEGATIVE: the updater (by either name), the pipeline job and a job that is not SecurityInsight''s are not touched' {
        $jobs = @((New-Job 'caj-si-identity-worker' '4.0' '8.0Gi' 86400), (New-Job 'caj-si-identity-producer' '4.0' '8.0Gi' 259200), (New-Job 'caj-si-config-backup' '2.0' '4.0Gi' 7200),
                  (New-Job 'caj-si-templates' '2.0' '4.0Gi' 1800), (New-Job 'caj-si-updater' '4.0' '8.0Gi' 3600), (New-Job 'caj-si-myupdater' '4.0' '8.0Gi' 3600),
                  (New-Job 'caj-si-flow' '2.0' '4.0Gi' 86400), (New-Job 'other-job' '0.5' '1.0Gi' 1800))
        $script:World = New-World -Counts $null -Jobs $jobs
        $r = Invoke-Floor $jobs -UpdaterName 'caj-si-myupdater'
        @($r.Results | Where-Object { $_.Action -eq 'raised' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-identity-worker', 'caj-si-identity-producer', 'caj-si-config-backup', 'caj-si-templates')
        @($r.Results | ForEach-Object { $_.Job }) | Should -Be @('caj-si-identity-worker', 'caj-si-identity-producer', 'caj-si-config-backup', 'caj-si-templates', 'caj-si-flow')
        @($r.Results | Where-Object { $_.Job -eq 'caj-si-flow' })[0].Line | Should -Be 'job size: caj-si-flow runs 2.0 CPU / 4.0Gi, 24 h -- nothing to raise'
        @($script:World.Bodies.Keys | Sort-Object) | Should -Be @('caj-si-config-backup', 'caj-si-identity-producer', 'caj-si-identity-worker', 'caj-si-templates')
        foreach ($n in $script:World.Bodies.Keys) { ($script:World.Bodies[$n] | ConvertFrom-Json).properties.configuration.replicaTimeout | Should -Be 604800 }
        @($r.Lines | Where-Object { $_ -match 'caj-si-identity-worker raised' })[0] | Should -Be "job size: caj-si-identity-worker raised 4.0 CPU / 8.0Gi, 24 h -> 4.0 CPU / 8.0Gi, 7 days -- $($script:Why)"
        @($r.Lines | Where-Object { $_ -match 'caj-si-identity-producer raised' })[0] | Should -Match '72 h -> 4\.0 CPU / 8\.0Gi, 7 days -- '
        # a queue worker's lease on its part goes with its run limit (the longest a storage queue gives); a producer has none
        $wEnv = ($script:World.Bodies['caj-si-identity-worker'] | ConvertFrom-Json).properties.template.containers[0].env
        @($wEnv | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }).value | Should -Be '604800'
        @($wEnv | Where-Object { $_.name -eq 'SI_SECRET' }).secretRef | Should -Be 'si-license' -Because 'the other settings stay as they are'
        @(($script:World.Bodies['caj-si-identity-producer'] | ConvertFrom-Json).properties.template.containers[0].env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }) | Should -BeNullOrEmpty
    }
    It 'CPU and memory as before: a small job gets 2 CPU / 4 GiB and its run limit in ONE PATCH; a producer at least its engine''s single job' {
        $jobs = @((New-Job 'caj-si-publicip' '0.5' '1.0Gi' 1800), (New-Job 'caj-si-identity' '4.0' '8.0Gi' 604800), (New-Job 'caj-si-identity-producer' '0.25' '0.5Gi' 600))
        $script:World = New-World -Counts $null -Jobs $jobs
        $r = Invoke-Floor $jobs
        @($r.Lines)[0] | Should -Be "job size: caj-si-publicip raised 0.5 CPU / 1.0Gi, 30 min -> 2.0 CPU / 4Gi, 7 days -- every job runs with at least 2 CPU / 4 GiB; $($script:Why)"
        @($r.Lines)[1] | Should -Be 'job size: caj-si-identity runs 4.0 CPU / 8.0Gi, 7 days -- nothing to raise'
        @($r.Lines)[2] | Should -Match '^job size: caj-si-identity-producer raised 0\.25 CPU / 0\.5Gi, 10 min -> 4\.0 CPU / 8Gi, 7 days -- '
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 2
        $b = $script:World.Bodies['caj-si-publicip'] | ConvertFrom-Json
        [double]$b.properties.template.containers[0].resources.cpu | Should -Be 2.0; $b.properties.template.containers[0].resources.memory | Should -Be '4Gi'
        $b.properties.configuration.replicaTimeout | Should -Be 604800
        $pb = $script:World.Bodies['caj-si-identity-producer'] | ConvertFrom-Json
        [double]$pb.properties.template.containers[0].resources.cpu | Should -Be 4.0; $pb.properties.template.containers[0].resources.memory | Should -Be '8Gi'
    }
    It 'the customer''s own run limit: a SHORTER one set on purpose is kept (the update leaves that job''s run limit alone, as it did), also under the engine''s long name; a longer one than 7 days cannot be set; CPU and memory are still raised' {
        $jobs = @((New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 21600), (New-Job 'caj-si-ptc' '1.0' '2.0Gi' 3600), (New-Job 'caj-si-endpoint' '4.0' '8.0Gi' 604800))
        $own = @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '21600'; SI_Bootstrap_ReplicaTimeout_PrivilegeTierClassifier = '3600'; SI_Bootstrap_ReplicaTimeout_Endpoint = '604800' }
        $script:World = New-World -Counts $null -Jobs $jobs
        $r = Invoke-Floor $jobs -Globals $own
        @($r.Lines)[0] | Should -Be 'job size: caj-si-asset-correlation runs 4.0 CPU / 8.0Gi, 6 h (its run limit is the customer''s own, SI_Bootstrap_ReplicaTimeout_AssetCorrelation -- kept) -- nothing to raise'
        @($r.Lines)[1] | Should -Be 'job size: caj-si-ptc raised 1.0 CPU / 2.0Gi, 1 h -> 2.0 CPU / 4Gi, 1 h -- every job runs with at least 2 CPU / 4 GiB'
        @($r.Lines)[2] | Should -Be 'job size: caj-si-endpoint runs 4.0 CPU / 8.0Gi, 7 days -- nothing to raise'
        @($script:World.Bodies.Keys) | Should -Be @('caj-si-ptc')
        ($script:World.Bodies['caj-si-ptc'] | ConvertFrom-Json).properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty -Because 'its run limit is not sent: the customer''s own stays'
        # at install the same setting is honoured as it always was: shorter on purpose, never longer than 7 days
        (Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '21600' }).ReplicaTimeout | Should -Be 21600
        $long = Get-SIContainerJobResources -Engine 'asset-correlation' -Kind Schedule -Globals @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '604801' }
        $long.ReplicaTimeout | Should -Be 604800; @($long.Notes) -join ' ' | Should -Match 'not a number of seconds between 300 and 604800'
        Get-SIJobRunLimitSetting -Engines @('ptc', 'privilege-tier-classifier') -Globals $own | Should -Be 'SI_Bootstrap_ReplicaTimeout_PrivilegeTierClassifier'
        Get-SIJobRunLimitSetting -Engines @('identity') -Globals $own | Should -Be ''
    }
    It '-WhatIf plans and sends nothing; a refused change and a job that cannot be read are each one line and nothing throws' {
        $jobs = @((New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 7200))
        $script:World = New-World -Counts $null -Jobs $jobs
        $w = Invoke-Floor $jobs -WhatIf
        @($w.Results)[0].Action | Should -Be 'would-raise'
        @($w.Lines)[0] | Should -Be "job size: caj-si-asset-correlation would be raised 4.0 CPU / 8.0Gi, 2 h -> 4.0 CPU / 8.0Gi, 7 days -- $($script:Why) (re-run with -Apply)"
        @($script:World.Calls) | Should -BeNullOrEmpty
        $script:World = New-World -Counts $null -UpdateError 'AuthorizationFailed' -Jobs $jobs
        $f = Invoke-Floor $jobs
        @($f.Results)[0].Action | Should -Be 'failed'; @($f.Lines)[0] | Should -Match 'caj-si-asset-correlation was NOT raised .*HTTP 403: AuthorizationFailed.* -- the next update tries again$'
        $script:World = New-World -Counts $null
        $g = Invoke-Floor $jobs
        @($g.Results)[0].Action | Should -Be 'failed'; @($g.Lines)[0] | Should -Match 'NOT raised'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
    }
    It 'the sizing step after the floor never writes a shorter run limit: a job list read BEFORE the floor raised the job still says 2 h, and the CPU / memory PATCH keeps the 7 days the job has now' {
        $stale = @((New-Job 'caj-si-identity' '2.0' '4.0Gi' 7200))
        $script:World = New-World -Counts @{ users = 22705; groups = 5097; servicePrincipals = 433; devices = 900 } -Jobs @((New-Job 'caj-si-identity' '2.0' '4.0Gi' 604800))
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $stale
        @($r.Results)[0].Action | Should -Be 'raised'
        $b = $script:World.Bodies['caj-si-identity'] | ConvertFrom-Json
        [double]$b.properties.template.containers[0].resources.cpu | Should -Be 4.0
        $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty -Because 'no run limit is sent, so the 7 days stay'
        # and asked outright for a shorter one, the one write keeps what the job has
        $p = Invoke-SIJobSizePatch -Rest $script:Rest -JobUri 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity?api-version=2025-07-01' -JobName 'caj-si-identity' -ReplicaTimeout 7200 -CurrentReplicaTimeout 7200
        $p.Ok | Should -BeTrue; $p.ReplicaTimeout | Should -Be 604800
        ($script:World.Bodies['caj-si-identity'] | ConvertFrom-Json).properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty
    }
    It 'which jobs are steps of the pipeline (the names a customer''s run limit setting may carry); the updater and the pipeline job are no steps' {
        $a = Get-SIJobRunLimitJob -JobName 'caj-si-azure' -Steps $script:StepKeys
        $a.Engine | Should -Be 'azure'; $a.Sized | Should -BeTrue
        $m = Get-SIJobRunLimitJob -JobName 'caj-si-close-loop-mail' -Steps $script:StepKeys
        $m.Engine | Should -Be 'close-loop-mail'; $m.Sized | Should -BeFalse
        $p = Get-SIJobRunLimitJob -JobName 'caj-si-ptc' -Steps $script:StepKeys
        $p.Sized | Should -BeFalse
        @($p.Names) | Should -Be @('ptc', 'privilege-tier-classifier')
        $aw = Get-SIJobRunLimitJob -JobName 'caj-si-azure-worker' -Steps $script:StepKeys
        $aw.Role | Should -Be 'worker'; $aw.Sized | Should -BeTrue
        (Get-SIJobRunLimitJob -JobName 'caj-si-identity' -Steps $script:StepKeys).Sized | Should -BeTrue
        foreach ($n in 'caj-si-updater', 'caj-si-flow', 'caj-si-templates', 'other-job') { Get-SIJobRunLimitJob -JobName $n -Steps $script:StepKeys | Should -BeNullOrEmpty }
        # the shipped map: the steps of the pipeline, never the updater / the pipeline job / a retired job
        $keys = @(Get-SIJobSizingStepKeys | ForEach-Object { $_.Key })
        foreach ($k in 'ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'asset-cmdb-sql', 'asset-datasync', 'close-loop-mail', 'verification') { $keys | Should -Contain $k }
        foreach ($k in 'updater', 'flow', 'asset-properties', 'templates', 'schema', 'config-backup') { $keys | Should -Not -Contain $k }
    }
    It 'the pipeline job itself (caj-si-flow) keeps its own rule: raised to 7 days; a longer one and the customer''s own setting are left alone' {
        $jobs = @((New-Job 'caj-si-flow' '2.0' '4.0Gi' 86400))
        $script:World = New-World -Counts $null -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($r.Results | Where-Object { $_.Job -eq 'caj-si-flow' })[0].Action | Should -Be 'raised'
        @($r.Lines) -join "`n" | Should -Match 'caj-si-flow \(the pipeline\) may run for up to 7 days, was 24 h'
        ($script:World.Bodies['caj-si-flow'] | ConvertFrom-Json).properties.configuration.replicaTimeout | Should -Be 604800
        $script:World = New-World -Counts $null -Jobs $jobs
        @(Invoke-SIFlowJobRunLimit -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -Globals @{ SI_Bootstrap_ReplicaTimeout_Flow = '86400' }) | Should -BeNullOrEmpty
        @(Invoke-SIFlowJobRunLimit -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs @((New-Job 'caj-si-flow' '2.0' '4.0Gi' 604800))) | Should -BeNullOrEmpty
        @(Invoke-SIFlowJobRunLimit -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -WhatIf)[0].Action | Should -Be 'would-raise'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
    }
    It 'the update''s floor step is this function, before the sizing step, and it reads the jobs again after raising one' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $h | Should -Match 'Invoke-SIJobFloor -Rest \$rest'
        $h | Should -Match ([regex]::Escape("Step ('8c. JOB FLOOR (2 CPU / 4 GiB; run limit {0}, the longest Azure takes)'"))
        $h | Should -Match '(?s)function Invoke-SIUpdateJobFloor \{.*?\$script:SISqlTierJobs = \$v.*?\n\}'
        $h | Should -Not -Match '\$fTo\b|JOB FLOOR \(2 CPU / 4 GiB, 2 h\)'
    }
}

Describe 'A RUN LIMIT ABOVE 24 HOURS THAT AZURE REFUSES is written as 24 hours: no update fails for it and no size raise is lost' {
    BeforeAll {
        function script:New-RefusingWorld([hashtable]$Counts, [object[]]$Jobs, [int]$RefuseAbove = 86400) {
            $w = New-World -Counts $Counts -Jobs $Jobs
            $w | Add-Member -NotePropertyName RefuseAbove -NotePropertyValue $RefuseAbove
            $w | Add-Member -NotePropertyName Asked -NotePropertyValue (New-Object System.Collections.Generic.List[string])
            $w
        }
        $script:Huge = @{ users = 80000; groups = 0; servicePrincipals = 0; devices = 25000 }
    }
    BeforeEach { Set-SIRunLimitRefused -Value $false }
    AfterAll { Set-SIRunLimitRefused -Value $false }
    It 'the rule: only a request for more than 24 hours, refused with a 400 or an error that names the replica timeout' {
        Test-SIRunLimitRefusal -ReplicaTimeout 259200 -Status 400 -Text 'anything' | Should -BeTrue
        Test-SIRunLimitRefusal -ReplicaTimeout 259200 -Status 422 -Text 'replicaTimeout is out of range' | Should -BeTrue
        Test-SIRunLimitRefusal -ReplicaTimeout 259200 -Text 'ARM PUT returned 400 (BadRequest)' | Should -BeTrue
        Test-SIRunLimitRefusal -ReplicaTimeout 86400 -Status 400 -Text 'replicaTimeout' | Should -BeFalse -Because '24 hours is what Azure is known to take'
        Test-SIRunLimitRefusal -ReplicaTimeout 259200 -Status 403 -Text 'AuthorizationFailed' | Should -BeFalse
        Test-SIRunLimitRefusal -ReplicaTimeout 259200 -Status 503 -Text 'replica timeout' | Should -BeFalse
        Get-SIRunLimitRefusedLine -Job 'caj-si-asset-correlation' -ReplicaTimeout 259200 | Should -Be 'Azure did not accept a run limit of 72 hours for caj-si-asset-correlation; it keeps 24 hours.'
        Get-SIRunLimitToSend -ReplicaTimeout 259200 | Should -Be 259200
        Set-SIRunLimitRefused; Get-SIRunLimitToSend -ReplicaTimeout 259200 | Should -Be 86400; Get-SIRunLimitToSend -ReplicaTimeout 7200 | Should -Be 7200
    }
    It 'the floor refused at 7 days: the same request once more with 24 h and the SAME CPU and memory, one line, and the next job of the run is sent 24 h at once' {
        $jobs = @((New-Job 'caj-si-asset-correlation'), (New-Job 'caj-si-risk-analysis'))
        $script:World = New-RefusingWorld -Counts $null -Jobs $jobs
        $r = Invoke-SIJobFloor -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -Steps @()
        @($script:World.Asked) | Should -Be @('caj-si-asset-correlation=604800', 'caj-si-asset-correlation=86400', 'caj-si-risk-analysis=86400')
        foreach ($n in 'caj-si-asset-correlation', 'caj-si-risk-analysis') {
            $b = $script:World.Bodies[$n] | ConvertFrom-Json
            $b.properties.configuration.replicaTimeout | Should -Be 86400
            [double]$b.properties.template.containers[0].resources.cpu | Should -Be 2.0 -Because 'the size raise is never lost'
            $b.properties.template.containers[0].resources.memory | Should -Be '4Gi'
        }
        @($r.Results | Where-Object { $_.Action -eq 'raised' }).Count | Should -Be 2
        @($r.Lines | Where-Object { $_ -match 'did not accept' }) | Should -Be @('job size: Azure did not accept a run limit of 168 hours for caj-si-asset-correlation; it keeps 24 hours.')
        @($r.Lines | Where-Object { $_ -match 'caj-si-asset-correlation raised' })[0] | Should -Match '1 h -> 2\.0 CPU / 4Gi, 24 h -- every job runs with at least 2 CPU / 4 GiB; a step gets the longest run limit Azure takes'
        @($r.Lines) -join "`n" | Should -Not -Match 'NOT raised'
        # a job that has 24 h already on such an Azure: asked once, kept, said -- and no update fails for it
        Set-SIRunLimitRefused -Value $false
        $day = @((New-Job 'caj-si-asset-correlation' '4.0' '8.0Gi' 86400))
        $script:World = New-RefusingWorld -Counts $null -Jobs $day
        $k = Invoke-SIJobFloor -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $day -Steps @()
        @($k.Results)[0].Action | Should -Be 'keep'
        @($k.Lines) | Should -Be @('job size: Azure did not accept a run limit of 168 hours for caj-si-asset-correlation; it keeps 24 hours.', 'job size: caj-si-asset-correlation runs 4.0 CPU / 8.0Gi, 24 h -- nothing to raise')
    }
    It 'accepted: one request only, with the long run limit, and nothing is remembered' {
        $jobs = @((New-Job 'caj-si-asset-correlation'))
        $script:World = New-RefusingWorld -Counts $null -Jobs $jobs -RefuseAbove 700000
        $null = Invoke-SIJobFloor -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -Steps @()
        @($script:World.Asked) | Should -Be @('caj-si-asset-correlation=604800')
        Test-SIRunLimitRefused | Should -BeFalse
    }
    It 'NEGATIVE: refused for another reason (24 h is refused too) -> the job is reported as not raised, and nothing is remembered' {
        $jobs = @((New-Job 'caj-si-asset-correlation'))
        $script:World = New-RefusingWorld -Counts $null -Jobs $jobs -RefuseAbove 0
        $r = Invoke-SIJobFloor -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -Steps @()
        @($script:World.Asked).Count | Should -Be 2
        @($r.Results)[0].Action | Should -Be 'failed'; @($r.Results)[0].Line | Should -Match 'NOT raised.*HTTP 400'
        Test-SIRunLimitRefused | Should -BeFalse
        @($r.Lines) -join "`n" | Should -Not -Match 'did not accept'
    }
    It 'a KEDA worker keeps its queue lease in step with the limit that was written; the pipeline job keeps 24 hours with the line' {
        $jobs = @((New-Job 'caj-si-identity-worker' '4.0' '8.0Gi' 14400), (New-Job 'caj-si-flow' '2.0' '4.0Gi' 86400))
        $script:World = New-RefusingWorld -Counts $null -Jobs $jobs
        $p = Invoke-SIJobSizePatch -Rest $script:Rest -JobUri 'https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity-worker?api-version=2025-07-01' `
                -JobName 'caj-si-identity-worker' -ReplicaTimeout 259200 -CurrentReplicaTimeout 14400 -Worker
        $p.Ok | Should -BeTrue; $p.ReplicaTimeout | Should -Be 86400
        $c = ($script:World.Bodies['caj-si-identity-worker'] | ConvertFrom-Json).properties.template.containers[0]
        @($c.env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }).value | Should -Be '86700'
        [double]$c.resources.cpu | Should -Be 4.0 -Because 'CPU and memory as the job has them when none is given'
        Set-SIRunLimitRefused -Value $false; $script:World.Asked.Clear()
        $f = @(Invoke-SIFlowJobRunLimit -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs)
        @($script:World.Asked) | Should -Be @('caj-si-flow=604800', 'caj-si-flow=0') -Because 'the second request leaves the run limit as it is (24 hours)'
        @($f | ForEach-Object { $_.Line }) | Should -Be @('job size: Azure did not accept a run limit of 168 hours for caj-si-flow; it keeps 24 hours.')
        # and once remembered, the pipeline job at 24 hours is not asked again
        @(Invoke-SIFlowJobRunLimit -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs) | Should -BeNullOrEmpty
    }
}

Describe 'the counts fallback' {
    It 'sidata.CiRecord: Entra users / groups / service principals, the largest device count of any provider' {
        $c = Get-SIJobSizingCountsFromCiRecords -Rows @(
            [pscustomobject]@{ Provider = 'entra'; RecordType = 'user'; Records = 22705 }, [pscustomobject]@{ Provider = 'entra'; RecordType = 'group'; Records = 5097 },
            [pscustomobject]@{ Provider = 'entra'; RecordType = 'service_principal'; Records = 433 }, [pscustomobject]@{ Provider = 'entra'; RecordType = 'device'; Records = 800 },
            [pscustomobject]@{ Provider = 'mde'; RecordType = 'device'; Records = 950 })
        $c.Users | Should -Be 22705; $c.Groups | Should -Be 5097; $c.Devices | Should -Be 950
        Get-SIJobSizingCountsFromCiRecords -Rows @() | Should -BeNullOrEmpty
    }
    It 'run health: the identity and endpoint engines'' largest runs' {
        $c = Get-SIJobSizingCountsFromRunHealth -Rows @([pscustomobject]@{ Engine = 'identity'; Assets = 27800 }, [pscustomobject]@{ Engine = 'endpoint'; Assets = 1200 })
        $c.Users | Should -Be 27800; $c.Devices | Should -Be 1200
        Get-SIJobSizingCountsFromRunHealth -Rows @([pscustomobject]@{ Engine = 'azure'; Assets = 9 }) | Should -BeNullOrEmpty
    }
    It 'Graph first, then the records, then the run health -- and the log says which' {
        (Resolve-SIJobSizingCounts -Graph @{ Users = 1 } -CiRecords @{ Users = 2 }).From | Should -Match 'Microsoft Graph'
        (Resolve-SIJobSizingCounts -CiRecords @{ Users = 2 } -RunHealth @{ Users = 3 }).From | Should -Match 'sidata.CiRecord'
        (Resolve-SIJobSizingCounts -RunHealth @{ Users = 3 }).From | Should -Match 'run health'
        (Resolve-SIJobSizingCounts).Counts | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-SIJobSizing against a fake Azure (REST seam)' {
    It 'Graph readable: raises the identity job, keeps the small endpoint job, one line per job changed, every ARM call in subscription s1' {
        # caj-si-ptc: a step of the pipeline that is no sized job (the Azure collection stood here until it became one, 2026-10-12)
        $jobs = @((New-Job 'caj-si-identity'), (New-Job 'caj-si-endpoint'), (New-Job 'caj-si-ptc'))
        $script:World = New-World -Counts @{ users = 22705; groups = 5097; servicePrincipals = 433; devices = 900 } -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($r.Results | Where-Object { $_.Action -eq 'raised' }).Job | Should -Be 'caj-si-identity'
        @($r.Results | Where-Object { $_.Action -eq 'keep' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-endpoint') -Because 'a step that is no sized job is not looked at here: its run limit is the floor step''s'
        @($r.Lines | Where-Object { $_ -match ' raised ' }).Count | Should -Be 1
        $r.Lines[0] | Should -Match 'tenant size from the directory \(Microsoft Graph\): 22,705 users'
        $u = @($script:World.Calls | Where-Object { $_ -like 'PATCH *' })
        $u.Count | Should -Be 1
        $u[0] | Should -Be 'PATCH https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity?api-version=2025-07-01'
        # READ-MODIFY-WRITE at ONE api-version: the job read right before its PATCH, at the PATCH's own version
        $iGet = $script:World.Calls.IndexOf('GET https://management.azure.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity?api-version=2025-07-01')
        $iGet | Should -BeGreaterThan -1
        $iGet | Should -BeLessThan $script:World.Calls.IndexOf($u[0])
        @($script:World.Calls | Where-Object { $_ -notlike '*graph.microsoft.com*' -and $_ -notmatch '^(GET|PATCH|POST) https://management\.azure\.com/subscriptions/s1/' }) | Should -BeNullOrEmpty
    }
    It 'the Azure collection is raised with the tenant (sized since 2026-10-12): 10,400 objects -> its scheduled job and its KEDA worker get 4 CPU / 8 GiB, their run limit untouched; the small endpoint job is kept' {
        $jobs = @((New-Job 'caj-si-azure'), (New-Job 'caj-si-azure-worker'), (New-Job 'caj-si-endpoint'))
        $script:World = New-World -Counts @{ users = 7000; groups = 2500; servicePrincipals = 600; devices = 300 } -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($r.Results | Where-Object { $_.Action -eq 'raised' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-azure', 'caj-si-azure-worker')
        @($r.Results | Where-Object { $_.Action -eq 'keep' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-endpoint')
        @($r.Lines | Where-Object { $_ -match 'caj-si-azure raised' })[0] | Should -Be 'job size: caj-si-azure raised 1.0 CPU / 2.0Gi, 1 h -> 4.0 CPU / 8.0Gi, 1 h -- 10,400 objects (from the directory (Microsoft Graph))'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 2
        foreach ($n in 'caj-si-azure', 'caj-si-azure-worker') {
            $b = $script:World.Bodies[$n] | ConvertFrom-Json
            [double]$b.properties.template.containers[0].resources.cpu | Should -Be 4.0
            $b.properties.template.containers[0].resources.memory | Should -Be '8.0Gi'
            $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty -Because 'the sizing sends no run limit'
        }
        $wEnv = ($script:World.Bodies['caj-si-azure-worker'] | ConvertFrom-Json).properties.template.containers[0].env
        @($wEnv | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }) | Should -BeNullOrEmpty -Because 'the run limit did not change, so the lease is left as it is'
        @(($script:World.Bodies['caj-si-azure'] | ConvertFrom-Json).properties.template.containers[0].env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }) | Should -BeNullOrEmpty
    }
    It 'the PATCH carries the WHOLE template (the container list as read) with the new size -- never the secrets, and no run limit' {
        $jobs = @(New-Job 'caj-si-identity')
        $script:World = New-World -Counts @{ users = 22705; groups = 5097; servicePrincipals = 433; devices = 900 } -Jobs $jobs
        $null = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        $b = $script:World.Bodies['caj-si-identity'] | ConvertFrom-Json
        @($b.properties.template.containers).Count | Should -Be 1
        $c = $b.properties.template.containers[0]
        $c.image | Should -Be 'acr.io/si-orchestrator:v1'; $c.name | Should -Be 'si'
        [double]$c.resources.cpu | Should -Be 4.0; $c.resources.memory | Should -Be '8.0Gi'
        @($c.env | ForEach-Object { $_.name }) | Should -Be @('SI_ENGINE', 'SI_SECRET') -Because 'the env list goes back whole'
        $c.PSObject.Properties['imageType'] | Should -BeNullOrEmpty; $c.resources.PSObject.Properties['ephemeralStorage'] | Should -BeNullOrEmpty
        $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty -Because 'the run limit is the floor step''s (its PATCH is tested with it)'
        $script:World.Bodies['caj-si-identity'] | Should -Not -Match 'keyVaultUrl|registries'
    }
    It 'a size change alone sends no configuration; the body builder never changes its input' {
        $j = New-Job 'caj-si-x' '1.0' '2.0Gi' 14400
        $body = New-SIJobSizePatchBody -Job $j -Cpu '2.0' -Memory '4.0Gi' -ReplicaTimeout 14400 | ConvertFrom-Json
        @($body.properties.PSObject.Properties.Name) | Should -Be @('template')
        $j.properties.template.containers[0].resources.memory | Should -Be '2.0Gi'
        $j.properties.template.containers[0].resources.ephemeralStorage | Should -Be '4Gi'
    }
    It 'no directory read: the Pro database''s records size the jobs, and the log says so' {
        $jobs = @(New-Job 'caj-si-identity')
        $script:World = New-World -Counts $null -Jobs $jobs
        $sql = { param($Sql) @([pscustomobject]@{ Provider = 'entra'; RecordType = 'user'; Records = 16000 }) }
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -SqlRows $sql
        $r.CountsFrom | Should -Match 'sidata.CiRecord'
        @($r.Results)[0].Action | Should -Be 'raised'
    }
    It 'LIVE 2026-10-16 (a 153,000-user tenant on 2 CPU / 4 GiB): no directory read for the updater -- the counts the collections recorded (cfg.InstallState TenantSize) size every job, and the log names that source' {
        $jobs = @((New-Job 'caj-si-identity' '2.0' '4.0Gi'), (New-Job 'caj-si-endpoint' '2.0' '4.0Gi'), (New-Job 'caj-si-risk-analysis' '2.0' '4.0Gi'))
        $script:World = New-World -Counts $null -Jobs $jobs
        $script:SqlAsked = New-Object System.Collections.Generic.List[string]
        $sql = { param($Sql) $script:SqlAsked.Add($Sql)
            if ($Sql -match "cfg\.InstallState WHERE Name = N'TenantSize'") { return @([pscustomobject]@{ Value = '{"users":153000,"groups":21000,"servicePrincipals":4100,"devices":38000,"identityAt":"2026-10-16T02:10:00Z","devicesAt":"2026-10-16T02:12:00Z"}' }) }
            @() }
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -SqlRows $sql
        $r.CountsFrom | Should -Match 'the directory counts the collections recorded \(cfg\.InstallState TenantSize\)'
        $r.Lines[0] | Should -Be 'job size: tenant size from the directory counts the collections recorded (cfg.InstallState TenantSize): 153,000 users, 21,000 groups, 4,100 service principals, 38,000 devices'
        @($r.Results | Where-Object { $_.Action -eq 'raised' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-identity', 'caj-si-endpoint', 'caj-si-risk-analysis')
        @($r.Lines | Where-Object { $_ -match 'caj-si-identity raised' })[0] | Should -Match '178,100 objects \(from the directory counts the collections recorded'
        @($r.Lines) -join "`n" | Should -Not -Match 'could not be read' -Because 'the size is KNOWN now -- not "unknown, so large"'
        @($script:World.Calls | Where-Object { $_ -like 'GET https://graph.microsoft.com/*' }).Count | Should -BeGreaterThan 0 -Because 'the directory is still asked first (it answers where the updater has the right)'
    }
    It 'the recorded counts come first; a half they do not have is taken from the next source (the records), never read as 0' {
        $c = Resolve-SIJobSizingCounts -Collected @{ Users = 153000; Groups = 0; ServicePrincipals = 4100; Devices = 0 } -CiRecords @{ Users = 99; Groups = 1; ServicePrincipals = 1; Devices = 38000 }
        $c.Counts.Users | Should -Be 153000; $c.Counts.Devices | Should -Be 38000
        $c.From | Should -Match '^users / groups / service principals from the directory counts the collections recorded.*devices from the records the last collection wrote'
        (Resolve-SIJobSizingCounts -Graph @{ Users = 1 } -Collected @{ Users = 2 }).From | Should -Match 'Microsoft Graph'
        Get-SIJobSizingCountsFromTenantMark -Rows @([pscustomobject]@{ Value = [System.DBNull]::Value }) | Should -BeNullOrEmpty
        Get-SIJobSizingCountsFromTenantMark -Rows @(@{ Value = '{"devices":12}' }) | ForEach-Object { $_.Devices } | Should -Be 12
        Get-SIJobSizingCountsFromTenantMark -Rows @(@{ Value = 'not json' }) | Should -BeNullOrEmpty
        # a Pro database whose read fails is said, and the update goes on with its other sources
        $jobs = @(New-Job 'caj-si-endpoint')
        $script:World = New-World -Counts $null -Jobs $jobs
        $f = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -SqlRows { param($Sql) throw 'Login failed for user' }
        @($f.Lines) -join "`n" | Should -Match 'the tenant size the collections recorded could not be read from the Pro database \(Login failed'
    }
    It 'no directory, no Pro database: the run health sizes them; nothing at all: every sized job is sized for a large tenant (owner 2026-10-16)' {
        $jobs = @(New-Job 'caj-si-endpoint')
        $script:World = New-World -Counts $null -La @{ RunHealthCounts = @([pscustomobject]@{ Engine = 'endpoint'; Assets = 6000 }) } -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -WorkspaceResourceId '/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.OperationalInsights/workspaces/law'
        $r.CountsFrom | Should -Match 'run health'
        @($r.Results)[0].Action | Should -Be 'raised'
        @($script:World.Calls | Where-Object { $_ -like 'POST *' }) | ForEach-Object { $_ | Should -Match 'workspaces/law/api/query\?api-version=2017-10-01$' }
        $script:World = New-World -Counts $null -Jobs $jobs
        $n = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($n.Lines) -join "`n" | Should -Match 'could not be read.*every sized job is sized for a large tenant \(4 CPU / 8 GiB\)'
        @($n.Results)[0].Action | Should -Be 'raised'
        @($n.Results)[0].Line | Should -Be 'job size: caj-si-endpoint raised 1.0 CPU / 2.0Gi, 1 h -> 4.0 CPU / 8.0Gi, 1 h -- the tenant''s size could not be read -- sized for a large tenant'
        ($script:World.Bodies['caj-si-endpoint'] | ConvertFrom-Json).properties.template.containers[0].resources.memory | Should -Be '8.0Gi'
    }
    It 'LIVE 2026-10-16 (customer B / AT): only the devices known -- the identity job is sized for a large tenant, the endpoint job by its known count; the log names the half that is missing' {
        $jobs = @((New-Job 'caj-si-identity' '2.0' '4.0Gi'), (New-Job 'caj-si-endpoint' '2.0' '4.0Gi'), (New-Job 'caj-si-asset-correlation' '2.0' '4.0Gi'))
        $script:World = New-World -Counts $null -Jobs $jobs
        $sql = { param($Sql) @([pscustomobject]@{ Provider = 'mde'; RecordType = 'device'; Records = 300 }) }
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -SqlRows $sql
        @($r.Results | Where-Object { $_.Action -eq 'raised' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-identity', 'caj-si-asset-correlation') -Because 'the identity half is not known; the CI build counts it too'
        @($r.Results | Where-Object { $_.Action -eq 'keep' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-endpoint') -Because '300 devices is a known small count'
        @($r.Lines) -join "`n" | Should -Match 'the tenant''s users could not be read -- the jobs that count them are sized for a large tenant'
        @($r.Lines | Where-Object { $_ -match 'caj-si-identity raised' })[0] | Should -Match 'sized for a large tenant$'
    }
    It 'NEGATIVE: known small counts keep today''s size; a size the customer set still wins over an unknown count; never lowers' {
        $jobs = @((New-Job 'caj-si-identity' '2.0' '4.0Gi'), (New-Job 'caj-si-endpoint' '2.0' '4.0Gi'))
        $script:World = New-World -Counts @{ users = 40; groups = 5; servicePrincipals = 20; devices = 12 } -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($r.Results | Where-Object { $_.Action -ne 'keep' }) | Should -BeNullOrEmpty
        @($r.Lines) -join "`n" | Should -Not -Match 'large tenant'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
        $cur = Get-SIJobCurrentSize (New-Job 'caj-si-identity')
        $c = Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current $cur -Counts $null -Globals @{ SI_Bootstrap_Memory_Identity = '2.0Gi' }
        $c.Action | Should -Be 'keep'; $c.Memory | Should -Be '2.0Gi'; @($c.Notes) -join ' ' | Should -Match 'customer''s size is kept'
        (Get-SIJobSizeChange -JobName 'caj-si-identity' -Engine identity -Current (Get-SIJobCurrentSize (New-Job 'caj-si-identity' '4.0' '8.0Gi')) -Counts $null).Action | Should -Be 'keep'
    }
    It 'a KEDA worker stopped at its run limit: one CPU / memory band up, as before; its run limit and its queue lease are the floor step''s' {
        $jobs = @(New-Job 'caj-si-identity-worker')
        $script:World = New-World -Counts @{ users = 10; groups = 0; servicePrincipals = 0; devices = 10 } -Execs @{ 'caj-si-identity-worker' = @(New-Exec 'caj-si-identity-worker-x1' 'Failed' $script:T0 3600) } -Jobs $jobs
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($r.Results)[0].Line | Should -Match 'replica timeout after 1 h'
        $b = $script:World.Bodies['caj-si-identity-worker'] | ConvertFrom-Json
        $c = $b.properties.template.containers[0]
        [double]$c.resources.cpu | Should -Be 2.0; $c.resources.memory | Should -Be '4.0Gi'
        $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty
        @($c.env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' }) | Should -BeNullOrEmpty
        @($c.env | Where-Object { $_.name -eq 'SI_SECRET' }).secretRef | Should -Be 'si-license' -Because 'the other settings stay as they are'
    }
    It '-WhatIf plans and sends nothing; a refused update is a line and never throws' {
        $jobs = @(New-Job 'caj-si-identity')
        $script:World = New-World -Counts @{ users = 22705; groups = 0; servicePrincipals = 0; devices = 0 } -Jobs $jobs
        $w = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -WhatIf
        @($w.Results)[0].Action | Should -Be 'would-raise'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
        $script:World = New-World -Counts @{ users = 22705; groups = 0; servicePrincipals = 0; devices = 0 } -UpdateError 'AuthorizationFailed' -Jobs $jobs
        $f = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($f.Results)[0].Action | Should -Be 'failed'; @($f.Results)[0].Line | Should -Match 'NOT raised.*HTTP 403: AuthorizationFailed'
        # a job that cannot be read is a line too (never a PATCH of a guessed template)
        $script:World = New-World -Counts @{ users = 22705; groups = 0; servicePrincipals = 0; devices = 0 }
        $g = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs
        @($g.Results)[0].Action | Should -Be 'failed'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }) | Should -BeNullOrEmpty
    }
    It 'Invoke-SIContainerUpdate runs the job size step on every exit that sizes the database, reading the customer''s sizes' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $h | Should -Match 'function Complete-SIUpdate \{ \$null = Invoke-SIUpdateSqlTier; \$null = Invoke-SIUpdateJobFloor; \$null = Invoke-SIUpdateJobSizing;'
        $h | Should -Match ([regex]::Escape("'^SI_Bootstrap_(Cpu|Memory|ReplicaTimeout)_'"))
        $h | Should -Match 'Invoke-SIJobSizing -Rest \$rest'
        $h | Should -Match "Get-SIAzureToken -Resource 'https://database\.windows\.net/'"
    }
}

# 2 CPU / 4 GiB since 2026-10-18 (owner: "reduce web app to 2cpus 4 gb ram" -- 7 days of telemetry: at most 0.1 CPU / 0.5 GiB
# used of 4 CPU / 8 GiB). Earlier: 1 CPU / 2 GiB (2026-10-11), 4 CPU / 8 GiB (2026-10-12).
Describe 'THE WEB APP''S SIZE: every update SETS 2 CPU / 4 GiB (owner 2026-10-18: "reduce web app to 2cpus 4 gb ram"); a size the customer set wins' {
    BeforeAll {
        function script:New-App([string]$Cpu = '0.5', [string]$Memory = '1Gi', [string]$State = 'Succeeded', [switch]$WithFront) {
            $cs = @([pscustomobject]@{ name = 'web'; image = 'acr.io/si-management:src-1'; imageType = 'ContainerImage'
                        env = @([pscustomobject]@{ name = 'A'; value = '1' }); resources = [pscustomobject]@{ cpu = [double]$Cpu; memory = $Memory; ephemeralStorage = '2Gi' } })
            if ($WithFront) { $cs += [pscustomobject]@{ name = 'signin-front'; image = 'acr.io/signin-front:1.0.0'; resources = [pscustomobject]@{ cpu = 0.25; memory = '0.5Gi' } } }
            [pscustomobject]@{ name = 'ca-si-management'; properties = [pscustomobject]@{ provisioningState = $State
                configuration = [pscustomobject]@{ secrets = @([pscustomobject]@{ name = 's'; keyVaultUrl = 'https://kv/secrets/x' }); ingress = [pscustomobject]@{ external = $true } }
                template = [pscustomobject]@{ revisionSuffix = 'v42'; scale = [pscustomobject]@{ minReplicas = 1; maxReplicas = 2 }; containers = $cs } } }
        }
        # a fake ARM: a PATCH replaces the app's template (so the read-back sees what was sent)
        $script:AppRest = {
            param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $w = $script:AppWorld; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
            if ($Uri -notmatch '/Microsoft\.App/containerApps/([^/?]+)\?api-version=') { return [pscustomobject]@{ Status = 400; Body = 'unexpected' } }
            $n = $Matches[1]
            if ($Method -eq 'GET') {
                if (-not $w.Apps.ContainsKey($n)) { return [pscustomobject]@{ Status = 404; Body = 'not found' } }
                return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $w.Apps[$n] -Depth 12 -Compress) }
            }
            if ($Method -eq 'PATCH') {
                if ($w.PatchStatus) { return [pscustomobject]@{ Status = $w.PatchStatus; Body = '{"error":{"code":"AuthorizationFailed","message":"no"}}' } }
                $w.Bodies[$n] = [string]$Body
                if (-not $w.NoApply) { $w.Apps[$n].properties.template = ($Body | ConvertFrom-Json).properties.template }
                return [pscustomobject]@{ Status = 202; Body = '' }
            }
            [pscustomobject]@{ Status = 400; Body = 'unexpected' }
        }
        function script:New-AppWorld([hashtable]$Apps, [int]$PatchStatus = 0, [switch]$NoApply) { [pscustomobject]@{ Apps = $Apps; PatchStatus = $PatchStatus; NoApply = [bool]$NoApply; Bodies = @{}; Calls = (New-Object System.Collections.Generic.List[string]) } }
        function script:Get-Sent([string]$Name = 'ca-si-management') { $r = ($script:AppWorld.Bodies[$Name] | ConvertFrom-Json).properties.template.containers[0].resources; ('{0}/{1}' -f $r.cpu, $r.memory) }
    }
    It 'raises a web app on 0.5 CPU / 1 GiB to 2 CPU / 4 GiB by ONE PATCH of its whole template -- secrets, suffix and the read-only size left out' {
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App); 'ca-si-mcp' = (New-App) }
        $r = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Name 'ca-si-management' -PollSeconds 0
        $r.Action | Should -Be 'raise'
        @($script:AppWorld.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 1
        $script:AppWorld.Bodies.Keys | Should -Be @('ca-si-management') -Because 'the MCP server keeps its size'
        $b = $script:AppWorld.Bodies['ca-si-management'] | ConvertFrom-Json
        $c = $b.properties.template.containers[0]
        ([string]$c.resources.cpu, [string]$c.resources.memory) | Should -Be @('2', '4Gi')
        $c.image | Should -Be 'acr.io/si-management:src-1'
        $c.env[0].name | Should -Be 'A'
        $b.properties.template.scale.maxReplicas | Should -Be 2
        $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty -Because 'never the configuration: ARM returns secrets without values'
        $b.properties.template.PSObject.Properties['revisionSuffix'] | Should -BeNullOrEmpty -Because 'a reused suffix is refused'
        $c.resources.PSObject.Properties['ephemeralStorage'] | Should -BeNullOrEmpty
        $c.PSObject.Properties['imageType'] | Should -BeNullOrEmpty
        $script:AppWorld.Calls[0] | Should -Match '^GET https://management\.azure\.com/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft\.App/containerApps/ca-si-management\?api-version='
        @($r.Lines).Count | Should -Be 1 -Because 'one plain line'
        @($r.Lines)[0] | Should -Match '^web app size: ca-si-management raised from 0.5 CPU / 1Gi to 2 CPU / 4Gi, the product''s size$'
    }
    It 'LOWERS the product''s earlier 4 CPU / 8 GiB to 2 CPU / 4 GiB; the size of 2026-10-11 (1 CPU / 2 GiB) is raised; 2 / 4 is left alone' {
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '4' -Memory '8Gi') }
        $r = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0
        $r.Action | Should -Be 'lower'; Get-Sent | Should -Be '2/4Gi'
        @($r.Lines)[0] | Should -Match 'lowered from 4 CPU / 8Gi to 2 CPU / 4Gi, the product''s size$'
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '1' -Memory '2Gi') }
        (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0).Action | Should -Be 'raise'
        Get-Sent | Should -Be '2/4Gi'
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '2' -Memory '4Gi') }
        $k = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0
        $k.Action | Should -Be 'keep'; @($k.Lines)[0] | Should -Match 'runs 2 CPU / 4Gi -- kept'
        @($script:AppWorld.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'NEGATIVE: any other larger size is the customer''s and is kept (3 / 6, 8 / 16); a pair is kept valid (memory = 2 x CPU)' {
        foreach ($s in @(@('3', '6Gi'), @('8', '16Gi'), @('4', '12Gi'))) {
            $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu $s[0] -Memory $s[1]) }
            (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0).Action | Should -Be 'keep' -Because "$($s[0]) CPU / $($s[1]) is not a size the product gave"
            @($script:AppWorld.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        }
        New-SIWebAppSizePatchBody -App (New-App -Cpu '2' -Memory '4Gi') | Should -BeNullOrEmpty
        # 1.5 CPU with 6 GiB (not a pair Azure takes, under the size): CPU raised to 3 to match the memory
        $p = (New-SIWebAppSizePatchBody -App (New-App -Cpu '1.5' -Memory '6Gi') | ConvertFrom-Json).properties.template.containers[0].resources
        ([string]$p.cpu, [string]$p.memory) | Should -Be @('3', '6Gi')
        # the rule at a size given by hand: 2 CPU with 1 GiB -> memory raised to 4 GiB, CPU kept
        $q = (New-SIWebAppSizePatchBody -App (New-App -Cpu '2' -Memory '1Gi') -Cpu 1 -MemoryGi 2 | ConvertFrom-Json).properties.template.containers[0].resources
        ([string]$q.cpu, [string]$q.memory) | Should -Be @('2', '4Gi')
    }
    It 'A SIZE THE CUSTOMER SET WINS, both ways (SI_Bootstrap_WebAppCpu / SI_Bootstrap_WebAppMemory)' {
        # 1 CPU set: a web app on 2 / 4 is LOWERED to 1 / 2 (memory 2 x CPU)
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '2' -Memory '4Gi') }
        $r = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Cpu '1.0'
        $r.Action | Should -Be 'lower'; Get-Sent | Should -Be '1/2Gi'
        @($r.Lines)[0] | Should -Match 'lowered from 2 CPU / 4Gi to 1 CPU / 2Gi, the size this install set$'
        # 3 CPU set: a web app on 4 / 8 (the product's earlier default) goes to 3 / 6, not to the product's 2 / 4
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '4' -Memory '8Gi') }
        (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Cpu '3').Action | Should -Be 'lower'
        Get-Sent | Should -Be '3/6Gi'
        # memory alone (6Gi): the CPU is half of it; and a web app already at the size set is kept
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '1' -Memory '2Gi') }
        (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Memory '6Gi').Action | Should -Be 'raise'
        Get-Sent | Should -Be '3/6Gi'
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '3' -Memory '6Gi') }
        $k = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Cpu '3' -Memory '6Gi'
        $k.Action | Should -Be 'keep'; @($k.Lines)[0] | Should -Match 'kept \(the size this install set\)'
        # a size Container Apps does not take is ignored with ONE line, and the product's size applies
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '4' -Memory '8Gi') }
        $bad = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Cpu '1.3'
        @($bad.Lines)[0] | Should -Match 'is not one Container Apps takes .* the product''s size applies'
        $bad.Action | Should -Be 'lower'; Get-Sent | Should -Be '2/4Gi'
        (Get-SIWebAppSizeSetting -Cpu 'lots').Note | Should -Match 'not a number'
        (Get-SIWebAppSizeSetting -Cpu '' -Memory '').Set | Should -BeFalse
        (Get-SIWebAppSizeSetting -Cpu '"2.5"').Cpu | Should -Be 2.5
        (Get-SIWebAppSizeSetting -Cpu '5').Set | Should -BeFalse -Because 'above one revision''s 4 CPU'
    }
    It 'behind the sign-in front: only the web container is sized (2 / 4, the app 2.25 / 4.5 -- a total Container Apps takes); the front keeps 0.25 / 0.5' {
        foreach ($was in @(@('1', '2Gi', 'raise'), @('3.75', '7.5Gi', 'lower'), @('4', '8Gi', 'lower'))) {
            $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu $was[0] -Memory $was[1] -WithFront) }
            (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0).Action | Should -Be $was[2]
            $cs = ($script:AppWorld.Bodies['ca-si-management'] | ConvertFrom-Json).properties.template.containers
            ('{0}/{1}' -f $cs[0].resources.cpu, $cs[0].resources.memory) | Should -Be '2/4Gi'
            $cs[1].name | Should -Be 'signin-front'; ('{0}/{1}' -f $cs[1].resources.cpu, $cs[1].resources.memory) | Should -Be '0.25/0.5Gi'
            $cs[1].image | Should -Be 'acr.io/signin-front:1.0.0'
            ([double]$cs[0].resources.cpu + [double]$cs[1].resources.cpu) | Should -Be 2.25
        }
        # a customer's 4 CPU behind the front: the web container takes what is left of one revision (3.75 / 7.5)
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '2' -Memory '4Gi' -WithFront) }
        (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -Cpu '4').Action | Should -Be 'raise'
        Get-Sent | Should -Be '3.75/7.5Gi'
    }
    It 'no web app (Community, or not deployed): nothing to do; -WhatIf plans; a refused PATCH is said, never thrown' {
        $script:AppWorld = New-AppWorld -Apps @{}
        (Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0).Action | Should -Be 'none'
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App) }
        $w = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -WhatIf
        $w.Action | Should -Be 'plan'; @($w.Lines)[0] | Should -Match 'would be raised from 0.5 CPU / 1Gi to 2 CPU / 4Gi'
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '4' -Memory '8Gi') }
        @((Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -WhatIf).Lines)[0] | Should -Match 'would be lowered from 4 CPU / 8Gi to 2 CPU / 4Gi'
        @($script:AppWorld.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -Cpu '4' -Memory '8Gi') } -PatchStatus 403
        $f = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0
        $f.Action | Should -Be 'failed'; @($f.Lines)[0] | Should -Match 'was NOT lowered'
    }
    It 'waits for the new revision before the web app roll patches the app again, and reads the size back' {
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App -State 'InProgress') }
        $r = Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0 -WaitSeconds 0
        $r.Action | Should -Be 'raise'
        @($script:AppWorld.Calls | Where-Object { $_ -like 'GET *' }).Count | Should -BeGreaterThan 1
        @($r.Lines)[0] | Should -Match 'still InProgress'
        # a read-back that does not show the size: said in the same line, the next update checks again
        $script:AppWorld = New-AppWorld -Apps @{ 'ca-si-management' = (New-App) } -NoApply
        @((Invoke-SIWebAppSize -Rest $script:AppRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -PollSeconds 0).Lines)[0] | Should -Match 'read back 0.5 CPU / 1Gi, the next update checks again'
    }
    It 'every update runs it, after the job steps, on the web app the install record names (else SI_UPDATER_WEB_APP, else ca-si-management)' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        # The ORDER is the point: after the last job step, before the templates. Other steps may stand between.
        $body = [regex]::Match($u, '(?m)^function Complete-SIUpdate \{(.*)\}\s*$').Groups[1].Value
        $steps = @([regex]::Matches($body, '(?:Invoke|Install)-SIUpdate\w+') | ForEach-Object { $_.Value })
        $steps | Should -Contain 'Invoke-SIUpdateWebAppSize'
        @($steps | Where-Object { $_ -eq 'Invoke-SIUpdateWebAppSize' }).Count | Should -Be 1
        $web = [array]::IndexOf($steps, 'Invoke-SIUpdateWebAppSize')
        foreach ($job in 'Invoke-SIUpdateSqlTier', 'Invoke-SIUpdateJobFloor', 'Invoke-SIUpdateJobSizing', 'Invoke-SIUpdateUpdaterSize', 'Invoke-SIUpdateKedaConvert', 'Invoke-SIUpdateOrchestration') {
            [array]::IndexOf($steps, $job) | Should -BeGreaterThan -1 -Because "$job is a step of every update"
            [array]::IndexOf($steps, $job) | Should -BeLessThan $web -Because "the web app's size comes after $job"
        }
        [array]::IndexOf($steps, 'Install-SIUpdateDefaultTemplates') | Should -BeGreaterThan $web -Because 'the templates come after the web app''s size'
        # CR5 step 1 (#655): the install record's name first (Get-SIInstallName -Role web); a release without the resolver: the variable, then today's name
        $u | Should -Match '\$name = Get-SIInstallName -Role web'
        $u | Should -Match "GetEnvironmentVariable\('SI_UPDATER_WEB_APP'\)\)""\.Trim\(\); if \(-not \`$name\) \{ \`$name = 'ca-si-management' \}"
        $u | Should -Match 'Invoke-SIWebAppSize -Rest \$rest -SubscriptionId \$sub -ResourceGroup \$target\.ResourceGroupName -Name \$name -Cpu \$webCpu -Memory \$webMem -WhatIf:\(-not \$Apply -or \$DetectOnly\)'
        # the size the customer set: the Pro database's setting first, then the config (Get-SIUpdateSetting), read for this step
        $u | Should -Match "\`$webCpu = Get-SIUpdateSetting -Name 'SI_Bootstrap_WebAppCpu'; \`$webMem = Get-SIUpdateSetting -Name 'SI_Bootstrap_WebAppMemory'"
        $u | Should -Match "'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory',"
    }
    It 'the size settings are in the settings catalog (Pro; empty = the product''s size), so support can set them per install' {
        $catPath = Join-Path $script:SIRoot 'config\settings.catalog.locked.json'   # a Pro file: not in the Community copy
        if (-not (Test-Path $catPath)) { Set-ItResult -Skipped -Because 'the settings catalog is Pro (not in the Community copy)'; return }
        $cat = Get-Content -Raw $catPath | ConvertFrom-Json
        foreach ($n in 'SI_Bootstrap_WebAppCpu', 'SI_Bootstrap_WebAppMemory') {
            $s = @($cat.settings | Where-Object { $_.name -eq $n })[0]
            $s | Should -Not -BeNullOrEmpty -Because "$n is a setting"
            $s.edition | Should -Be 'pro'; $s.default | Should -BeNullOrEmpty
        }
        $cpu = @($cat.settings | Where-Object { $_.name -eq 'SI_Bootstrap_WebAppCpu' })[0]
        foreach ($ok in '0.5', '1', '1.25', '2.0', '3.75', '4') { $ok | Should -Match $cpu.pattern }
        foreach ($no in '0.25', '1.3', '5', 'two') { $no | Should -Not -Match $cpu.pattern }
    }
    It 'Install-SIUpdaterJob keeps the UPDATER job at 4 CPU / 8 GiB -- a job, not the web app' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Install-SIUpdaterJob.ps1')) | Should -Match "'--cpu', '4\.0', '--memory', '8Gi'"
    }
}