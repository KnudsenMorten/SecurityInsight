#Requires -Version 5.1
<#
    #720 TWO COLLECTION-TRUST FIXES FOUND LIVE AT THE LARGE INSTALLS (2026-10-16, read-only through the Support app).

    (a) THE RAISE AFTER OUT OF MEMORY NEVER FIRED. ARM returns a FAILED Container Apps job execution WITHOUT an endTime
        (the identity producer's out-of-memory run: status Failed, a startTime, no endTime). Get-SIJobFailureSignal skipped
        every execution without one, so #702's "one band up after an out-of-memory run" never triggered -- the tests seeded
        an endTime. And with no directory read for the updater and 0 users in the records (the identity collection had
        written none), the size rule read 0 users. What these tests keep true, on REAL ARM shapes (no endTime on Failed):
          * a Failed / Stopped execution without endTime is a finished run: its END record, the system log's OOMKilled, an
            out-of-memory class (si-col-0501, si-ra-0303, out-of-memory) or a START without an END all raise it one band;
            a run still going is skipped and its START never counts for the run before it;
          * the counts: each half (identity objects, devices) from the first source that has it -- the records, the Graph
            counts setup read at install (kept on the jobs as si-tenant-* tags), the run health; a 0 is not known.
    (b) A FAILED HAND-OVER WAS REPORTED AS SUCCESS. The endpoint producer logged "[producer] the parts could not be queued:
        OutOfMemoryException" while its run-health END said "success" (the engine writes its END before the container
        hands the parts over). A failed hand-over now ends the run NOT COMPLETE: a second END (error, si-col-0501 when it
        was memory -- which (a) reads), the parts no worker will get marked failed, the records of a run with a failed part
        published WITHOUT closing the collection (the failed part's objects are unknown, never read as removed).
    Offline: the REST seam, an in-memory state store, the real record publish with a faked database. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    $script:T0 = [datetime]::new(2026, 10, 16, 1, 0, 0, [DateTimeKind]::Utc)
    # an execution EXACTLY as the ARM list returns a failed one: no endTime property at all
    function script:Arm-Exec([string]$Name, [string]$Status, [datetime]$Start, [int]$EndSeconds = -1) {
        $p = [ordered]@{ status = $Status; startTime = $Start.ToString("yyyy-MM-ddTHH:mm:ss'+00:00'") }
        if ($EndSeconds -ge 0) { $p.endTime = $Start.AddSeconds($EndSeconds).ToString("yyyy-MM-ddTHH:mm:ss'+00:00'") }
        $p.template = [ordered]@{ containers = @([ordered]@{ name = 'si'; image = 'acr.io/si-orchestrator:v1'; resources = [ordered]@{ cpu = 2.0; memory = '4Gi' } }) }
        ConvertFrom-Json (ConvertTo-Json -InputObject ([ordered]@{ id = "/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.App/jobs/x/executions/$Name"; name = $Name; type = 'Microsoft.App/jobs/executions'; properties = $p }) -Depth 8)
    }
    function script:Rh([string]$Exec, [string]$Phase, [datetime]$At, [string]$Exit = '', [string]$Msg = '', [string]$Engine = 'endpoint') {
        [pscustomobject]@{ TimeGenerated = $At.ToString('o'); Engine = $Engine; Phase = $Phase; ExitReason = $Exit; ErrorMessage = $Msg; Execution = $Exec }
    }
    function script:New-Job([string]$Name, [string]$Cpu = '2.0', [string]$Memory = '4.0Gi', [hashtable]$Tags) {
        $j = [ordered]@{ name = $Name; properties = [ordered]@{
            configuration = [ordered]@{ triggerType = 'Manual'; replicaTimeout = 604800; replicaRetryLimit = 0; manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
            template = [ordered]@{ containers = @([ordered]@{ name = 'si'; image = 'acr.io/si-orchestrator:v1'; env = @([ordered]@{ name = 'SI_ENGINE'; value = 'endpoint' }); resources = [ordered]@{ cpu = [double]$Cpu; memory = $Memory } }) } } }
        if ($Tags) { $j.tags = $Tags }
        ConvertFrom-Json (ConvertTo-Json -InputObject $j -Depth 12)
    }
    function script:New-World([hashtable]$Execs = @{}, [hashtable]$La = @{}, [object[]]$Jobs = @()) {
        $byName = @{}; foreach ($j in $Jobs) { $byName[[string]$j.name] = $j }
        [pscustomobject]@{ Execs = $Execs; La = $La; Jobs = $byName; Bodies = @{}; Calls = (New-Object System.Collections.Generic.List[string]) }
    }
    # the updater's identity: no directory read (Graph 403), ARM and Log Analytics as the world says
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
        $ok = { param($o) [pscustomobject]@{ Status = 200; Body = $(if ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 12 -Compress }) } }
        if ($Uri -like 'https://graph.microsoft.com/*') { return [pscustomobject]@{ Status = 403; Body = 'Authorization_RequestDenied' } }
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
            if ($Method -eq 'PATCH') { $w.Bodies[$n] = [string]$Body; return [pscustomobject]@{ Status = 202; Body = '' } }
        }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
    $script:Law = '/subscriptions/s1/resourceGroups/rg-si/providers/Microsoft.OperationalInsights/workspaces/law'
    function script:New-MemStore {
        $docs = @{}
        [pscustomobject]@{
            Docs  = $docs
            Read  = { param($p) if ($docs.ContainsKey($p)) { $docs[$p] } else { $null } }.GetNewClosure()
            Write = { param($p, $t) $docs[$p] = $t }.GetNewClosure()
            List  = { param($pre) @($docs.Keys | Where-Object { $_.StartsWith($pre) } | Sort-Object) }.GetNewClosure()
            Claim = { param($p, $t) if ($docs.ContainsKey($p)) { $false } else { $docs[$p] = $t; $true } }.GetNewClosure()
        }
    }
}

Describe '(a) a FAILED execution without endTime (the real ARM shape) is a finished run' {
    It 'the ARM shape really has no endTime -- the test does not seed one' {
        $e = Arm-Exec 'caj-si-identity-producer-s9npjjh' 'Failed' $script:T0
        $e.properties.PSObject.Properties['endTime'] | Should -BeNullOrEmpty
    }
    It 'its END record says out of memory -> one band up (the run health names the execution)' {
        $e = @(Arm-Exec 'caj-si-identity-producer-s9npjjh' 'Failed' $script:T0; Arm-Exec 'caj-si-identity-producer-old' 'Succeeded' $script:T0.AddDays(-1) 3000)
        $rh = @((Rh 'caj-si-identity-producer-s9npjjh' 'Start' $script:T0.AddMinutes(1) -Engine identity),
                (Rh 'caj-si-identity-producer-s9npjjh' 'End' $script:T0.AddMinutes(90) 'error' 'Discovery source ''EntraUsers'' threw -- OutOfMemoryException' -Engine identity))
        $s = Get-SIJobFailureSignal -JobName 'caj-si-identity-producer' -Engine identity -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh
        $s.Kind | Should -Be 'oom'; $s.Execution | Should -Be 'caj-si-identity-producer-s9npjjh'
        $s.Reason | Should -Match 'ended out of memory \(its run health says so\)'
    }
    It 'the out-of-memory CLASS counts on its own: si-col-0501 (a collection), si-ra-0303 (a Risk Analysis lookup), out-of-memory' {
        $e = @(Arm-Exec 'caj-si-endpoint-producer-x1' 'Failed' $script:T0)
        foreach ($m in 'si-col-0501', 'class out-of-memory') {
            $rh = @(Rh 'caj-si-endpoint-producer-x1' 'End' $script:T0.AddMinutes(30) 'error' $m)
            (Get-SIJobFailureSignal -JobName 'caj-si-endpoint-producer' -Engine endpoint -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh).Kind | Should -Be 'oom' -Because $m
        }
        # a Risk Analysis job that ended "Succeeded" with a report not complete for memory
        $ra = @(Arm-Exec 'caj-si-risk-analysis-detailed-r1' 'Succeeded' $script:T0 7200)
        $rr = @(Rh 'caj-si-risk-analysis-detailed-r1' 'End' $script:T0.AddMinutes(119) 'success-partial' 'report X not run: si-ra-0303' -Engine 'risk-analysis')
        (Get-SIJobFailureSignal -JobName 'caj-si-risk-analysis-detailed' -Engine 'risk-analysis-detailed' -ReplicaTimeout 604800 -Executions $ra -RunHealthRows $rr).Kind | Should -Be 'oom'
    }
    It 'the system log''s OOMKilled for that execution, without any end time' {
        $e = @(Arm-Exec 'caj-si-identity-k2' 'Failed' $script:T0)
        $sys = @([pscustomobject]@{ Exec = 'caj-si-identity-k2'; Job = 'caj-si-identity'; Reason = 'OOMKilled'; Msg = 'Container si was terminated with exit code 137'; TimeGenerated = $script:T0.AddMinutes(40).ToString('o') })
        (Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 604800 -Executions $e -SystemLogRows $sys).Kind | Should -Be 'oom'
    }
    It 'a START and no END (killed before it could write one), and no end time from Azure either -> out of memory, said plainly' {
        $e = @(Arm-Exec 'caj-si-identity-k3' 'Failed' $script:T0)
        $s = Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 604800 -Executions $e -RunHealthRows @(Rh 'caj-si-identity-k3' 'Start' $script:T0.AddMinutes(1) -Engine identity)
        $s.Kind | Should -Be 'oom'
        $s.Reason | Should -Match 'Azure gives the run no end time either'
    }
    It 'a Stopped execution without endTime is finished too' {
        $e = @(Arm-Exec 'caj-si-identity-k4' 'Stopped' $script:T0)
        (Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 604800 -Executions $e -RunHealthRows @(Rh 'caj-si-identity-k4' 'End' $script:T0.AddMinutes(5) 'error' 'OutOfMemoryException' -Engine identity)).Kind | Should -Be 'oom'
    }
    It 'NEGATIVE: a run still going is skipped -- and its own START never makes the failed run before it look killed' {
        $e = @((Arm-Exec 'caj-si-identity-k5' 'Failed' $script:T0), (Arm-Exec 'caj-si-identity-k6' 'Running' $script:T0.AddHours(2)))
        $rh = @((Rh 'caj-si-identity-k5' 'Start' $script:T0.AddMinutes(1) -Engine identity),
                (Rh 'caj-si-identity-k5' 'End' $script:T0.AddMinutes(10) 'error' 'Forbidden' -Engine identity),
                ([pscustomobject]@{ TimeGenerated = $script:T0.AddHours(2).AddMinutes(1).ToString('o'); Engine = 'identity'; Phase = 'Start'; ExitReason = ''; ErrorMessage = ''; Execution = '' }))
        Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh | Should -BeNullOrEmpty -Because 'it failed for another reason, and ended with its own error'
        Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 604800 -Executions @(Arm-Exec 'caj-si-identity-k7' 'Running' $script:T0) | Should -BeNullOrEmpty
    }
    It 'NEGATIVE: a failed run with no end time and nothing recorded about it is no signal (nothing is guessed), and no timeout is read from a length that is not known' {
        Get-SIJobFailureSignal -JobName 'caj-si-identity' -Engine identity -ReplicaTimeout 3600 -Executions @(Arm-Exec 'caj-si-identity-k8' 'Failed' $script:T0.AddDays(-2)) | Should -BeNullOrEmpty
    }
    It 'END TO END against a fake Azure: the producer whose last run Failed with no endTime goes from 2 CPU / 4 GiB to 4 CPU / 8 GiB' {
        $jobs = @(New-Job 'caj-si-identity-producer')
        $script:World = New-World -Jobs $jobs -Execs @{ 'caj-si-identity-producer' = @(Arm-Exec 'caj-si-identity-producer-s9npjjh' 'Failed' ([datetime]::UtcNow.AddHours(-5))) } `
            -La @{ RunHealthRows = @(Rh 'caj-si-identity-producer-s9npjjh' 'End' ([datetime]::UtcNow.AddHours(-4)) 'error' 'this identity collection is NOT COMPLETE (si-col-0501: out of memory)' -Engine identity) }
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -WorkspaceResourceId $script:Law
        @($r.Results | Where-Object { $_.Job -eq 'caj-si-identity-producer' }).Action | Should -Be 'raised'
        $b = $script:World.Bodies['caj-si-identity-producer'] | ConvertFrom-Json
        [double]$b.properties.template.containers[0].resources.cpu | Should -Be 4.0
        $b.properties.template.containers[0].resources.memory | Should -Be '8.0Gi'
        @($r.Lines) -join "`n" | Should -Match 'caj-si-identity-producer raised .* ended out of memory'
    }
}

Describe '(a) the tenant''s size when the updater cannot read the directory: never 0 users because one collection wrote none' {
    It 'setup keeps the Graph counts on every job as plain tags, and reads them back (the largest of any job)' {
        $t = @(Get-SITenantSizeTags -Counts @{ Users = 26640; Groups = 19862; ServicePrincipals = 1499; Devices = 195524 })
        $t | Should -Be @('si-tenant-users=26640', 'si-tenant-groups=19862', 'si-tenant-serviceprincipals=1499', 'si-tenant-devices=195524')
        @(Get-SITenantSizeTags -Counts $null).Count | Should -Be 0
        @(Get-SITenantSizeTags -Counts @{ Users = 0; Devices = 0 }).Count | Should -Be 0 -Because 'nothing read is no tag'
        $j1 = New-Job 'caj-si-identity' -Tags @{ 'si-build' = 'x'; 'si-tenant-users' = '26640'; 'si-tenant-devices' = '195524' }
        $j2 = New-Job 'caj-si-endpoint' -Tags @{ 'si-tenant-users' = '20000'; 'si-tenant-groups' = '19862' }
        $c = ConvertFrom-SITenantSizeTags -Jobs @($j1, $j2, (New-Job 'caj-si-flow'))
        ($c.Users, $c.Groups, $c.Devices) | Should -Be @(26640, 19862, 195524)
        ConvertFrom-SITenantSizeTags -Jobs @((New-Job 'caj-si-flow'), (New-Job 'x' -Tags @{ 'si-tenant-users' = 'many' })) | Should -BeNullOrEmpty
    }
    It 'each half from the first source that HAS it: 0 users in the records -> the users setup read; the devices from the records' {
        $r = Resolve-SIJobSizingCounts -CiRecords @{ Users = 0L; Groups = 0L; ServicePrincipals = 0L; Devices = 195524L } -Install @{ Users = 26640L; Groups = 19862L; ServicePrincipals = 1499L; Devices = 150000L }
        ($r.Counts.Users, $r.Counts.Groups, $r.Counts.ServicePrincipals, $r.Counts.Devices) | Should -Be @(26640, 19862, 1499, 195524)
        $r.From | Should -Match '^users / groups / service principals from the directory counts setup read at install .*; devices from the records the last collection wrote'
        # no setup counts either: the run health's identity runs
        (Resolve-SIJobSizingCounts -CiRecords @{ Users = 0L; Devices = 900L } -RunHealth @{ Users = 27800L; Devices = 0L }).Counts.Users | Should -Be 27800
        # Graph read now is the whole answer
        (Resolve-SIJobSizingCounts -Graph @{ Users = 5 } -Install @{ Users = 26640 }).Counts.Users | Should -Be 5
    }
    It 'END TO END: no directory read, the records hold devices but 0 users, the jobs carry setup''s counts -> the identity job is raised for 46,001 objects' {
        $tags = @{ 'si-build' = '3.0.0'; 'si-tenant-users' = '26640'; 'si-tenant-groups' = '17862'; 'si-tenant-serviceprincipals' = '1499'; 'si-tenant-devices' = '195524' }
        $jobs = @((New-Job 'caj-si-identity' '1.0' '2.0Gi' -Tags $tags), (New-Job 'caj-si-endpoint' '4.0' '8.0Gi' -Tags $tags))
        $script:World = New-World -Jobs $jobs
        $sql = { param($Sql) @([pscustomobject]@{ Provider = 'mde'; RecordType = 'device'; Records = 195524 }) }
        $r = Invoke-SIJobSizing -Rest $script:Rest -SubscriptionId 's1' -ResourceGroup 'rg-si' -Jobs $jobs -SqlRows $sql
        $r.Lines[0] | Should -Match '^job size: tenant size from users / groups / service principals from the directory counts setup read at install'
        $r.Lines[0] | Should -Match '26,640 users, 17,862 groups, 1,499 service principals, 195,524 devices'
        @($r.Results | Where-Object { $_.Action -eq 'raised' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-identity')
        @($r.Lines | Where-Object { $_ -match 'caj-si-identity raised' })[0] | Should -Match '46,001 objects'
    }
    It 'WIRING: setup tags every job it creates or updates (worker and producer) with the counts it read' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $b | Should -Match ([regex]::Escape('$siSizeTags = @(Get-SITenantSizeTags -Counts $script:SITenantCounts)'))
        ([regex]::Matches($b, ([regex]::Escape("@('--tags', `$siBuildTag) + `$siSizeTags")))).Count | Should -Be 3 -Because 'worker create, the Risk Analysis worker create, producer create'
        ([regex]::Matches($b, ([regex]::Escape('Tags = @($siBuildTag) + $siSizeTags')))).Count | Should -Be 3 -Because 'worker update, the Risk Analysis worker update, producer update'
        $b.IndexOf('$siSizeTags = @(') | Should -BeLessThan $b.IndexOf("@('--tags', `$siBuildTag) + `$siSizeTags")
    }
}

Describe '(b) a failed hand-over ends the run NOT COMPLETE -- never "success"' {
    It 'the producer''s out of memory: class si-col-0501, NOT COMPLETE, nothing read as removed; the parts not queued are named' {
        $f = Get-SICollectHandoverFailure -Engine Endpoint -ErrorText 'Exception of type ''System.OutOfMemoryException'' was thrown.' -Where producer -Parts 16 -Queued 10 -ManifestWritten
        $f.OutOfMemory | Should -BeTrue; $f.Code | Should -Be 'si-col-0501'; $f.ExitReason | Should -Be 'error'
        $f.Text | Should -Match '^The parts of this endpoint collection could not be handed to its workers \(si-col-0501: out of memory\) -- this endpoint collection is NOT COMPLETE and stays on its last good collection; nothing in it is read as removed: '
        @($f.FailParts) | Should -Be @(10, 11, 12, 13, 14, 15)
        @((Get-SICollectHandoverFailure -Engine endpoint -ErrorText 'x' -Where producer -Parts 16 -Queued 0).FailParts).Count | Should -Be 0 -Because 'no manifest: the pipeline follows nothing, and no worker runs'
        $o = Get-SICollectHandoverFailure -Engine identity -ErrorText 'The remote server returned an error: (403) Forbidden.' -Where discover
        $o.OutOfMemory | Should -BeFalse; $o.Code | Should -Be ''; $o.Text | Should -Match 'the hand-over failed\) -- this identity collection is NOT COMPLETE'
        (Get-SICollectHandoverFailure -Engine identity -ErrorText 'OutOfMemoryException' -Where part -Part 3).Text | Should -Match '^Part 4 of this identity collection could not hand its records over \(si-col-0501'
    }
    It 'its END text is what the update''s size rule reads as out of memory -- (b) feeds (a)' {
        $f = Get-SICollectHandoverFailure -Engine endpoint -ErrorText 'OutOfMemoryException' -Where producer -Parts 16 -Queued 3 -ManifestWritten
        $e = @(Arm-Exec 'caj-si-endpoint-producer-p1' 'Failed' $script:T0)
        $rh = @((Rh 'caj-si-endpoint-producer-p1' 'End' $script:T0.AddMinutes(50) 'success' ''), (Rh 'caj-si-endpoint-producer-p1' 'End' $script:T0.AddMinutes(51) $f.ExitReason $f.Text))
        (Get-SIJobFailureSignal -JobName 'caj-si-endpoint-producer' -Engine endpoint -ReplicaTimeout 604800 -Executions $e -RunHealthRows $rh).Kind | Should -Be 'oom'
    }
    It 'manifest written, 10 of 16 queued: the 6 others are marked FAILED -- the step can no longer read as succeeded; the queued workers still finish' {
        $s = New-MemStore
        Write-SICollectManifest -Store $s -Manifest (New-SICollectManifest -Engine endpoint -RunId 'prod1' -CollectionTime $script:T0 -Parts 16 -Now $script:T0 -EngineRunId 'eng1' -RecordsHandover)
        $f = Get-SICollectHandoverFailure -Engine endpoint -ErrorText 'OutOfMemoryException' -Where producer -Parts 16 -Queued 10 -ManifestWritten
        $w = Write-SICollectHandoverFailure -Store $s -Engine endpoint -RunId 'prod1' -Failure $f -Worker 'caj-si-endpoint-producer-p1'
        $w.Written | Should -Be 6; $w.Records | Should -Be 'not-last' -Because 'the 10 queued parts are still to come'
        $m = @(Read-SICollectPartMarkers -Store $s -Engine endpoint -RunId 'prod1')
        @($m | Where-Object { $_.State -eq 'failed' }).Count | Should -Be 6
        ($m | Select-Object -First 1).Reason | Should -Match 'si-col-0501'
        # the last of the queued workers publishes -- and is told that 6 parts failed
        foreach ($p in 0..9) { Write-SICollectPartMarker -Store $s -Engine endpoint -RunId 'prod1' -Marker (New-SICollectPartMarker -Part $p -State done) }
        $script:Told = -1
        Invoke-SICollectRecordsIfLast -Store $s -Engine endpoint -RunId 'prod1' -Publish { param($PartsFailed) $script:Told = $PartsFailed; [pscustomobject]@{ Records = 10; Buckets = 4; Failed = 0 } } | Should -Be 'published'
        $script:Told | Should -Be 6
        $pg = Get-SICollectProgress -Manifest (Read-SICollectManifest -Store $s -Engine endpoint -RunId 'prod1') -Markers @(Read-SICollectPartMarkers -Store $s -Engine endpoint -RunId 'prod1') -Records (Read-SICollectRecordsMarker -Store $s -Engine endpoint -RunId 'prod1') -TimeoutMinutes 0
        $pg.State | Should -Be 'failed'; $pg.Text | Should -Match '10 of 16 part\(s\) done, 6 failed'
    }
    It 'manifest written, NOTHING queued: no worker is left -- the producer ends the run''s records FAILED itself, so the step ends instead of waiting for ever' {
        $s = New-MemStore
        Write-SICollectManifest -Store $s -Manifest (New-SICollectManifest -Engine endpoint -RunId 'prod2' -CollectionTime $script:T0 -Parts 16 -Now $script:T0 -EngineRunId 'eng2' -RecordsHandover)
        $f = Get-SICollectHandoverFailure -Engine endpoint -ErrorText 'OutOfMemoryException' -Where producer -Parts 16 -Queued 0 -ManifestWritten
        $w = Write-SICollectHandoverFailure -Store $s -Engine endpoint -RunId 'prod2' -Failure $f
        ($w.Written, $w.Records) | Should -Be @(16, 'failed')
        $rm = Read-SICollectRecordsMarker -Store $s -Engine endpoint -RunId 'prod2'
        $rm.State | Should -Be 'failed'; $rm.Reason | Should -Match 'NOT COMPLETE'
        $pg = Get-SICollectProgress -Manifest (Read-SICollectManifest -Store $s -Engine endpoint -RunId 'prod2') -Markers @(Read-SICollectPartMarkers -Store $s -Engine endpoint -RunId 'prod2') -Records $rm -TimeoutMinutes 0
        $pg.State | Should -Be 'failed'
    }
    It 'a marker that cannot be written is said, never thrown' {
        $bad = New-MemStore; $bad | Add-Member -NotePropertyName Write -NotePropertyValue { param($p, $t) throw 'OutOfMemoryException' } -Force
        $f = Get-SICollectHandoverFailure -Engine endpoint -ErrorText 'x' -Where producer -Parts 2 -Queued 0 -ManifestWritten
        { $script:W = Write-SICollectHandoverFailure -Store $bad -Engine endpoint -RunId 'p' -Failure $f } | Should -Not -Throw
        $script:W.Written | Should -Be 0; $script:W.Why | Should -Match 'OutOfMemory'
    }
    It 'WIRING: the producer, a discovery child and a part each record a failed hand-over as a second END (error) of their run; the producer marks the parts it did not queue' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match '(?s)\$endRunNotComplete = \{.{0,1600}Send-SIRunHealthRow -RunContext \$ctx -Phase End -AssetCount -1 -ExitReason \(\[string\]\$Failure\.ExitReason\) -ErrorMessage \(\[string\]\$Failure\.Text\)'
        $c | Should -Match '(?s)\$pManifest = \$true.{0,900}\$pQueued = \$i \+ 1'
        $c | Should -Match '(?s)the parts could not be queued: \{0\}.{0,300}\$orchExit = 1.{0,500}Get-SICollectHandoverFailure -Engine \$engine -ErrorText \$pErr -Where producer -Parts \$pParts -Queued \$pQueued -ManifestWritten:\$pManifest.{0,300}Write-SICollectHandoverFailure.{0,600}& \$endRunNotComplete \$pFail'
        $c | Should -Match '(?s)the discovered run could not be handed over.{0,600}-Where discover.{0,100}& \$endRunNotComplete \$dFail'
        $c | Should -Match '(?s)its records were not handed over.{0,600}-Where part -Part \$shardIndex.{0,100}& \$endRunNotComplete \$hf'
        # the done marker of a finished part: tried twice, then the execution fails so it is seen
        $c | Should -Match '(?s)foreach \(\$attempt in 1, 2\).{0,1500}if \(-not \$doneWritten\) \{.{0,300}\$orchExit = 1'
    }
    It 'WIRING: the records of a run with a failed part are published without closing the collection -- KEDA (the last worker) and in-job parts alike' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        # (#874: the claimed last worker decides first how many processes publish -- one, or several at once)
        $c | Should -Match '(?s)-Publish \{.{0,200}param\(\[int\]\$PartsFailed\).{0,2500}Publish-SIRecordHandover -Store \$recStore .{0,200}-PartsFailed \$PartsFailed'
        $c | Should -Match '(?s)param\(\[int\]\$PartsFailed\).{0,4000}SI_COLLECT_PARTS_FAILED = \$PartsFailed \}'
        $c | Should -Match 'SI_COLLECT_PARTS_FAILED = \$failedParts\.Count'
        $c | Should -Match ([regex]::Escape("-PartsFailed ([int](Get-OptionalEnv 'SI_COLLECT_PARTS_FAILED' 0))"))
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1'))
        $h | Should -Match '(?s)if \(\$PartsFailed -gt 0\) \{\s+if \(\$runClose\) \{ \$runClose\.Failed = \[int\]\$runClose\.Failed \+ \$PartsFailed \}'
    }
}
