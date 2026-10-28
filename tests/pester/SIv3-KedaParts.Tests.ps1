#Requires -Version 5.1
<#
    PARTS IN PARALLEL THROUGH KEDA, WITH THE RECORDS HANDED OVER (#475; DESIGN.md 13 -- producer + queue-scaled worker).
    The producer discovers once into parts and hands discovery's records over; each worker runs its part and hands its
    records over; the LAST worker (a create-only claim -- exactly one wins) publishes every record once and writes the
    run's records marker; the pipeline's Collect step ends only when that marker says done. What these tests keep true:
      * the manifest says the records are handed over; the step then waits for the records marker -- running while it is
        absent, INCOMPLETE after the timeout, failed with the reason when the publish failed, succeeded when done (a
        failed part still fails the step); a manifest from before the hand-over behaves as before;
      * only the last worker publishes, once: parts still open -> nothing; every part marked -> one publish; a second
        claimant -> nothing; a publish that throws or loses a bucket -> the records marker says failed, with the reason;
      * the blob claim is create-only (If-None-Match: *) and "already there" is a lost claim, not an error;
      * the pipeline reads the records marker; the container hands over (producer + worker), finishes after a done or a
        failed marker, never marks a part done whose records were not kept; Bootstrap's producer discovers.
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
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
    $script:T0 = [datetime]'2026-10-08T20:00:00Z'
    function script:Handover-Manifest([int]$Parts = 2) { [pscustomobject](New-SICollectManifest -Engine identity -RunId 'exec1' -CollectionTime $script:T0 -Parts $Parts -Now $script:T0 -EngineRunId 'eng1' -RecordsHandover) }
    function script:Marks([string[]]$States) { $i = 0; foreach ($s in $States) { [pscustomobject](New-SICollectPartMarker -Part $i -State $s -Reason $(if ($s -eq 'failed') { 'out of memory' } else { '' })); $i++ } }
}

Describe 'the step waits for the records when the manifest says they are handed over' {
    It 'the manifest carries the engine run id and the hand-over; the records marker and the claim have fixed paths' {
        $m = Handover-Manifest
        ($m.EngineRunId, [bool]$m.RecordsHandover) | Should -Be @('eng1', $true)
        Get-SICollectPath -Engine Identity -RunId 'exec1' -Kind records | Should -Be 'collect/identity/exec1/records.json'
        Get-SICollectPath -Engine identity -RunId 'exec1' -Kind claim | Should -Be 'collect/identity/exec1/records.claim'
    }
    It 'running while the records are not published; INCOMPLETE after the timeout' {
        $p = Get-SICollectProgress -Manifest (Handover-Manifest) -Markers @(Marks 'done', 'done') -Now $script:T0.AddMinutes(30)
        ($p.State, $p.Text) | Should -Be @('running', '2 of 2 part(s) done -- publishing the records')
        $q = Get-SICollectProgress -Manifest (Handover-Manifest) -Markers @(Marks 'done', 'done') -Now $script:T0.AddMinutes(181) -TimeoutMinutes 180
        $q.State | Should -Be 'incomplete'
        $q.Text | Should -Match 'the records were not published after 180 minutes -- the collection is INCOMPLETE'
    }
    It 'failed with the reason when the publish failed; succeeded when done; a failed part still fails the step' {
        $bad = [pscustomobject](New-SICollectRecordsMarker -State failed -Reason 'the records could not be published: ingest refused')
        $f = Get-SICollectProgress -Manifest (Handover-Manifest) -Markers @(Marks 'done', 'done') -Records $bad
        $f.State | Should -Be 'failed'; $f.Text | Should -Match 'ingest refused'
        $ok = [pscustomobject](New-SICollectRecordsMarker -State done -Records 9000 -Buckets 2)
        (Get-SICollectProgress -Manifest (Handover-Manifest) -Markers @(Marks 'done', 'done') -Records $ok).State | Should -Be 'succeeded'
        $pf = Get-SICollectProgress -Manifest (Handover-Manifest) -Markers @(Marks 'done', 'failed') -Records $ok
        $pf.State | Should -Be 'failed'; $pf.Text | Should -Match 'part 2: out of memory'
    }
    It 'a manifest from before the hand-over behaves as before (no records marker needed)' {
        $old = [pscustomobject](New-SICollectManifest -Engine identity -RunId 'r' -CollectionTime $script:T0 -Parts 2 -Now $script:T0)
        (Get-SICollectProgress -Manifest $old -Markers @(Marks 'done', 'done')).State | Should -Be 'succeeded'
    }
}

Describe 'only the last worker publishes the records, once' {
    BeforeEach {
        $script:S = New-MemStore
        Write-SICollectManifest -Store $script:S -Manifest (Handover-Manifest -Parts 2)
        $script:Published = 0
        $script:Pub = { $script:Published++; [pscustomobject]@{ Records = 120; Buckets = 2; Failed = 0 } }
    }
    It 'parts still open -> nothing; every part marked -> one publish and a done marker; a second claimant -> nothing' {
        Write-SICollectPartMarker -Store $script:S -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 0 -State done)
        Invoke-SICollectRecordsIfLast -Store $script:S -Engine identity -RunId 'exec1' -Publish $script:Pub -Worker 'w1' | Should -Be 'not-last'
        $script:Published | Should -Be 0
        Write-SICollectPartMarker -Store $script:S -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 1 -State done)
        Invoke-SICollectRecordsIfLast -Store $script:S -Engine identity -RunId 'exec1' -Publish $script:Pub -Worker 'w2' | Should -Be 'published'
        Invoke-SICollectRecordsIfLast -Store $script:S -Engine identity -RunId 'exec1' -Publish $script:Pub -Worker 'w1' | Should -Be 'claimed-elsewhere'
        $script:Published | Should -Be 1
        $rm = Read-SICollectRecordsMarker -Store $script:S -Engine identity -RunId 'exec1'
        ($rm.State, [long]$rm.Records, $rm.Worker) | Should -Be @('done', 120, 'w2')
    }
    It 'a failed part counts as marked: the other parts'' records are still published' {
        Write-SICollectPartMarker -Store $script:S -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 0 -State failed -Reason 'parked')
        Write-SICollectPartMarker -Store $script:S -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 1 -State done)
        Invoke-SICollectRecordsIfLast -Store $script:S -Engine identity -RunId 'exec1' -Publish $script:Pub | Should -Be 'published'
    }
    It 'a publish that throws, or loses a bucket, writes a failed records marker with the reason' {
        foreach ($p in 0, 1) { Write-SICollectPartMarker -Store $script:S -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part $p -State done) }
        Invoke-SICollectRecordsIfLast -Store $script:S -Engine identity -RunId 'exec1' -Publish { throw 'ingest refused' } | Should -Be 'failed'
        (Read-SICollectRecordsMarker -Store $script:S -Engine identity -RunId 'exec1').Reason | Should -Match 'the records could not be published: ingest refused'
        $s2 = New-MemStore
        Write-SICollectManifest -Store $s2 -Manifest (Handover-Manifest -Parts 1)
        Write-SICollectPartMarker -Store $s2 -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 0 -State done)
        Invoke-SICollectRecordsIfLast -Store $s2 -Engine identity -RunId 'exec1' -Publish { [pscustomobject]@{ Records = 50; Buckets = 3; Failed = 1 } } | Should -Be 'failed'
        (Read-SICollectRecordsMarker -Store $s2 -Engine identity -RunId 'exec1').Reason | Should -Match '1 of 3 record bucket\(s\) could not be published'
    }
    It 'a manifest from before the hand-over: nothing is published by the worker' {
        $s3 = New-MemStore
        Write-SICollectManifest -Store $s3 -Manifest (New-SICollectManifest -Engine identity -RunId 'exec1' -CollectionTime $script:T0 -Parts 1 -Now $script:T0)
        Invoke-SICollectRecordsIfLast -Store $s3 -Engine identity -RunId 'exec1' -Publish $script:Pub | Should -Be 'no-handover'
        $script:Published | Should -Be 0
    }
}

Describe 'the blob claim is create-only' {
    It 'Set-SIBlobContent -IfNoneMatch sends If-None-Match: *; the store reads "already there" as a lost claim' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
        $script:H = $null
        Mock Invoke-SIStorageRequest { $script:H = $Headers; [pscustomobject]@{ Headers = @{ ETag = '"e1"' } } }
        $null = Set-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'b' -Bytes ([byte[]]@(1)) -IfNoneMatch
        $script:H['If-None-Match'] | Should -Be '*'
        $null = Set-SIBlobContent -Account 'st' -Container 'sistate' -Blob 'b' -Bytes ([byte[]]@(1))
        $script:H.ContainsKey('If-None-Match') | Should -BeFalse
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1'))
        $src | Should -Match ([regex]::Escape("-ContentType 'application/json' -IfNoneMatch; `$true } catch { if (`"`$(`$_.Exception.Message)`" -match '409|412|BlobAlreadyExists|ConditionNotMet') { `$false } else { throw } }"))
    }
}

Describe 'the pipeline, the container and the installer are wired' {
    It 'the pipeline''s Collect step waits for the records marker of a run that hands them over' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
        $log = New-Object System.Collections.Generic.List[string]
        $in = New-SIJobFlowSeams -Fields @{ Log = $log } -Methods @{
            Start = { param($Job) "$Job-exec1" }
            Poll  = { param($Job, $Execution) 'Succeeded' }
            Stop  = { param($Job, $Execution) }
            List  = { @('caj-si-identity-producer') }
        }
        $s = New-MemStore
        $w = Add-SIJobFlowCollectParts -Seams $in -Store $s -ProducerJobs @('caj-si-identity-producer') -Now { $script:T0.AddMinutes(10) }
        Write-SICollectManifest -Store $s -Manifest (Handover-Manifest -Parts 1)
        Write-SICollectPartMarker -Store $s -Engine identity -RunId 'exec1' -Marker (New-SICollectPartMarker -Part 0 -State done)
        $w.Poll('identity', 'exec1') | Should -Be 'Running'
        & $s.Write (Get-SICollectPath -Engine identity -RunId 'exec1' -Kind records) (ConvertTo-Json -InputObject (New-SICollectRecordsMarker -State failed -Reason 'bucket 3 lost') -Compress)
        $r = $w.Poll('identity', 'exec1')
        $r.Status | Should -Be 'Failed'; $r.Error | Should -Match 'bucket 3 lost'
        & $s.Write (Get-SICollectPath -Engine identity -RunId 'exec1' -Kind records) (ConvertTo-Json -InputObject (New-SICollectRecordsMarker -State done -Records 5) -Compress)
        $w.Poll('identity', 'exec1') | Should -Be 'Succeeded'
    }
    It 'the producer hands discovery''s records over BEFORE the manifest that says so' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $i = $c.IndexOf("-RunId ([string]`$ri.RunId) -Who 'discover' -Buckets `$recordBuckets")
        $j = $c.IndexOf("-ProducerExecution `$collectKey -EngineRunId ([string]`$ri.RunId) -RecordsHandover -RecordBuckets `$recordBuckets)")
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
    }
    It 'the run''s record bucket count: the producer decides it from discovery''s records, the manifest and every message carry it, a worker hands over into it' {
        $m = [pscustomobject](New-SICollectManifest -Engine identity -RunId 'exec1' -CollectionTime $script:T0 -Parts 3 -Now $script:T0 -EngineRunId 'eng1' -RecordsHandover -RecordBuckets 20)
        $m.RecordBuckets | Should -Be 20
        ([pscustomobject](New-SICollectManifest -Engine identity -RunId 'r' -CollectionTime $script:T0 -Parts 2 -Now $script:T0)).RecordBuckets | Should -Be 0   # before it: one per part
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match ([regex]::Escape('$recordBuckets = Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount) -Parts $parts'))
        $i = $c.IndexOf('$recordBuckets = Get-SIRecordBucketCount -Records (Get-SIRecordCaptureCount) -Parts $parts')
        $j = $c.IndexOf("-Who 'discover' -Buckets `$recordBuckets", $i)
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue -Because 'counted before the save clears the capture'
        $c | Should -Match ([regex]::Escape("Phase = 'parts'; RecordBuckets = `$recordBuckets;"))
        $c | Should -Match ([regex]::Escape("[Environment]::SetEnvironmentVariable('SI_COLLECT_RECORD_BUCKETS', [string][int]`$msg.Payload.RecordBuckets)"))
        # the part's hand-over reads it (and falls back to one bucket per part for a message from before it)
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')) | Should -Match ([regex]::Escape("[Environment]::GetEnvironmentVariable('SI_COLLECT_RECORD_BUCKETS')"))
    }
    It 'a worker on a part hands its records over (the same signal as a part of the in-job run), then the last one publishes' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match ([regex]::Escape("if (`$collectPhase -eq 'parts' -and `$collectEngineRun) {`r`n        [Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'parts')").Replace('\r\n', '\r?\n'))
        $c | Should -Match ([regex]::Escape("[Environment]::SetEnvironmentVariable('SI_COLLECT_ENGINE_RUN', `$collectEngineRun)"))
        # after the done marker, and after a parked part's failed marker
        $c | Should -Match ([regex]::Escape('& $finishKedaRecords $collectRunId $collectEngineRun ([string]$collectionFromMsg)'))
        $c | Should -Match ([regex]::Escape('& $finishKedaRecords ([string]$msg.Payload.RunId) ([string]$msg.Payload.EngineRunId) ([string]$msg.Payload.CollectionTime)'))
        # the finish publishes (it is not a part while it does) and the records go under the ENGINE run id
        $c | Should -Match ([regex]::Escape("[Environment]::SetEnvironmentVariable('SI_COLLECT_PHASE', 'records')"))
        $c | Should -Match ([regex]::Escape('Publish-SIRecordHandover -Store $recStore -Engine $recEngineName -RunId $RecEngineRun'))
    }
    It 'a part whose records were not kept is never marked done (the check comes before the KEDA success block)' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $i = $c.IndexOf("if (`$collectChild -eq 'parts' -and `$global:SI_RecordHandoverFailed) {")
        $j = $c.IndexOf('if ($useQueue -and $queueMessageId -and ($orchExit -eq 0 -or $null -eq $orchExit)) {')
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
        ([regex]::Matches($c, [regex]::Escape("`$global:SI_RecordHandoverFailed) {"))).Count | Should -Be 1
    }
    It 'Bootstrap''s producer discovers into parts, with the worker''s environment, as role producer' {
        # #519: the producer's environment is defined once (SI-ContainerConfig.ps1), Bootstrap and the update both use it
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $b | Should -Match ([regex]::Escape('$producerEnvArgs = @(Get-SIKedaProducerEnvArgs -EnvArgs $envArgs -Parallelism $parallelism)'))
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $p = @(Get-SIKedaProducerEnvArgs -EnvArgs @('SI_ENGINE=identity', 'SI_ROLE=worker', 'SI_TRIGGER_FROM_QUEUE=1', 'SI_QUEUE_LEASE_SECONDS=9000', 'SI_SHARD_COUNT=4', 'SI_UAMI_CLIENTID=c') -Parallelism 2)
        $p | Should -Be @('SI_ENGINE=identity', 'SI_UAMI_CLIENTID=c', 'SI_ROLE=producer', 'SI_PRODUCER_DISCOVERS=1', 'SI_SHARD_COUNT=2')
    }
}

Describe 'KEDA by design in the installer, on the managed identity (operator 2026-10-08)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $script:Boot = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        # functions defined inside Bootstrap, taken out by the parser so they run here against stubbed REST calls
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($script:Boot, [ref]$null, [ref]$null)
        foreach ($fn in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in 'Remove-SIBootstrapReplacedJob', 'Invoke-SIIdentityGrantPlan' }, $true))) {
            . ([scriptblock]::Create($fn.Extent.Text.Replace('function ' + $fn.Name, 'function script:' + $fn.Name)))
        }
    }
    It 'decides: <why>' -TestCases @(
        @{ why = 'a managed-identity install, nothing set -> producer + worker on the identity'; a = @{ AuthMode = 'ManagedIdentity'; AuthDefault = $true }; keda = $true; move = $false; refuse = $false }
        @{ why = 'a certificate install (it has the identity) -> producer + worker'; a = @{ AuthMode = 'Certificate' }; keda = $true; move = $false; refuse = $false }
        @{ why = 'an install that merely carries a client secret -> producer + worker, the jobs MOVE to the managed identity'; a = @{ AuthMode = 'Secret'; AuthDefault = $true }; keda = $true; move = $true; refuse = $false }
        @{ why = 'a carried secret with an explicit -UseKEDA -> moved too, not refused'; a = @{ AuthMode = 'Secret'; AuthDefault = $true; CliBound = $true; CliValue = $true }; keda = $true; move = $true; refuse = $false }
        @{ why = 'a secret chosen on purpose -> its jobs stay, no queue scaling'; a = @{ AuthMode = 'Secret'; AuthDefault = $false }; keda = $false; move = $false; refuse = $false }
        @{ why = 'a chosen secret with an explicit -UseKEDA -> refused, as before'; a = @{ AuthMode = 'Secret'; AuthDefault = $false; CliBound = $true; CliValue = $true }; keda = $false; move = $false; refuse = $true }
        @{ why = 'SI_Bootstrap_UseKEDA = $false opts out'; a = @{ AuthMode = 'ManagedIdentity'; Configured = $false }; keda = $false; move = $false; refuse = $false }
        @{ why = 'SI_Bootstrap_UseKEDA = false as text opts out'; a = @{ AuthMode = 'ManagedIdentity'; Configured = 'false' }; keda = $false; move = $false; refuse = $false }
        @{ why = '-UseKEDA:$false wins over a configured $true'; a = @{ AuthMode = 'ManagedIdentity'; Configured = $true; CliBound = $true; CliValue = $false }; keda = $false; move = $false; refuse = $false }
    ) {
        $c = Resolve-SIBootstrapKedaChoice @a
        ($c.Keda, $c.MoveToManagedIdentity, $c.Refuse) | Should -Be @($keda, $move, $refuse)
        $c.Message | Should -Not -BeNullOrEmpty
        $c.Message | Should -Not -Match '#\d'
    }
    It 'only the engines that discover into parts get producer + worker; the layout replaces only that engine''s other jobs' {
        foreach ($e in 'identity', 'endpoint', 'Azure') { Test-SIKedaPartsEngine $e | Should -BeTrue }
        foreach ($e in 'publicip', 'privilege-tier-classifier', 'risk-analysis', 'flow') { Test-SIKedaPartsEngine $e | Should -BeFalse }
        @(Get-SIBootstrapReplacedJobs -Engine identity -Keda $true) | Should -Be @('caj-si-identity')
        @(Get-SIBootstrapReplacedJobs -Engine identity -Keda $false) | Should -Be @('caj-si-identity-producer', 'caj-si-identity-worker')
        @(Get-SIBootstrapReplacedJobs -Engine publicip -Keda $true) | Should -BeNullOrEmpty
    }
    It 'removes a replaced job only when it exists and SI''s setup made it (si-build tag); a failed removal says the command' {
        $script:ResourceGroupName = 'rg-si-test'
        $script:Jobs = @{
            'caj-si-identity' = [pscustomobject]@{ name = 'caj-si-identity'; tags = [pscustomobject]@{ 'si-build' = '3.0.0' } }
            'caj-si-endpoint' = [pscustomobject]@{ name = 'caj-si-endpoint'; tags = [pscustomobject]@{ owner = 'someone-else' } }
        }
        $script:Deleted = New-Object System.Collections.Generic.List[string]
        # #521: over ARM (setup\_shared\SI-SetupArm.ps1), never az
        function script:Get-SIContainerAppJob { param($ResourceGroupName, $Name, $SubscriptionId) if ($script:Jobs.ContainsKey($Name)) { $script:Jobs[$Name] } else { $null } }
        function script:Remove-SIContainerAppJob { param($ResourceGroupName, $Name, $SubscriptionId) $script:Deleted.Add($Name); if ($script:DeleteExit) { throw 'AuthorizationFailed' } }
        $script:DeleteExit = 0
        Remove-SIBootstrapReplacedJob -Name 'caj-si-identity' 6>$null
        Remove-SIBootstrapReplacedJob -Name 'caj-si-endpoint' 3>$null
        Remove-SIBootstrapReplacedJob -Name 'caj-si-azure'
        @($script:Deleted) | Should -Be @('caj-si-identity')
        $script:DeleteExit = 1; $w = $null
        Remove-SIBootstrapReplacedJob -Name 'caj-si-identity' -WarningVariable w 3>$null
        "$w" | Should -Match 'caj-si-identity\] could not be removed \(AuthorizationFailed\)'
        "$w" | Should -Match ([regex]::Escape('resource group rg-si-test > caj-si-identity > Delete'))
        Test-SIBootstrapJobIsSI -Job ([pscustomobject]@{ tags = @{ 'si-build' = 'x' } }) | Should -BeTrue
        Test-SIBootstrapJobIsSI -Job $null | Should -BeFalse
    }
    It 'missing rights: the grant that could not be made is listed with the exact command, and counted' {
        $script:SIBootstrapSubscriptionId = 'sub-1'; $script:ResourceGroupName = 'rg-si-test'
        function script:Test-SIRoleAssignmentPresent { param($ObjectId, $Scope, $RoleDefinitionName) $false }
        function script:New-SIRoleAssignment { param($ObjectId, $Scope, $RoleDefinitionName, $PrincipalType) throw 'AuthorizationFailed: no roleAssignments/write' }
        $plan = @([pscustomobject]@{ Kind = 'AzureRole'; Role = 'Storage Queue Data Reader'; Scope = '/subscriptions/sub-1/resourceGroups/rg-si-test/providers/Microsoft.Storage/storageAccounts/st1'; Why = 'the queue scaler reads the parts queue' })
        $n = Invoke-SIIdentityGrantPlan -Plan $plan -PrincipalId 'pid-1' -Apply 3>$null 6>$null
        $n | Should -Be 1
        # #564: the exact grant as an Azure portal path (a customer has no az CLI) -- was an az role assignment command
        (@($script:SICustomerTasks) -join "`n") | Should -Match ([regex]::Escape('# Azure role "Storage Queue Data Reader" on "/subscriptions/sub-1/resourceGroups/rg-si-test/providers/Microsoft.Storage/storageAccounts/st1" for the managed identity pid-1 -- Azure portal: open the scope > Access control (IAM) > Add > Add role assignment > Storage Queue Data Reader > Managed identity'))
        (@($script:SICustomerTasks) -join "`n") | Should -Not -Match 'az role assignment'
    }
    It 'WIRING: the choice replaces the old switch; the move comes after the secret settings are checked and before the jobs'' sign-in; a move without every grant changes nothing' {
        $b = $script:Boot
        $b | Should -Not -Match "_Apply-CustomSwitch -ParamName 'UseKEDA'"
        $b | Should -Match ([regex]::Escape('$kedaChoice = Resolve-SIBootstrapKedaChoice -CliBound ($cliBound.ContainsKey(''UseKEDA'')) -CliValue ([bool]$UseKEDA)'))
        $b | Should -Match ([regex]::Escape('if ($kedaChoice.Refuse) { throw $kedaChoice.Message }'))
        $chk = $b.IndexOf('$spnObjectId = if ($global:SI_SPN_ObjectId)')
        $mv = $b.IndexOf("if (`$kedaMovesToIdentity) {")
        $gp = $b.IndexOf('$grantMissing = Invoke-SIIdentityGrantPlan -Plan $grantPlan')
        $rv = $b.IndexOf("if (`$kedaMovesToIdentity -and [int]`$grantMissing -gt 0) {")
        $ja = $b.IndexOf('$jobAuth = Get-SIContainerJobAuthArgs -Mode $authMode')
        ($chk -gt 0 -and $mv -gt $chk -and $gp -gt $mv -and $rv -gt $gp -and $ja -gt $rv) | Should -BeTrue -Because 'checked, moved, granted, reverted if a grant is missing, THEN the jobs get their sign-in'
        $revert = $b.Substring($rv, 700)
        $revert | Should -Match ([regex]::Escape("`$authMode = 'Secret'"))
        $revert | Should -Match ([regex]::Escape('$UseKEDA = [switch]$false'))
        $b | Should -Match ([regex]::Escape('$GrantIdentityRoles = [switch]$true'))
        $b | Should -Match ([regex]::Escape('-KedaQueueScaler:([bool]$UseKEDA)'))
    }
    It 'WIRING: queue scaling per engine only for the parts engines, the replaced layout removed after the new one, the wizard passes its choice both ways' {
        $b = $script:Boot
        $b | Should -Match ([regex]::Escape('$engineKeda   = ([bool]$UseKEDA -and (Test-SIKedaPartsEngine $engine))'))
        $b | Should -Not -Match ([regex]::Escape('($UseKEDA -and -not $isRiskAnalysis'))
        $b | Should -Match ([regex]::Escape('$effectiveUseKEDA = ($engineKeda -and -not $isRiskAnalysis'))
        $p = $b.IndexOf("Write-Host ('       {0}d producer.' -f `$producerVerb)")
        $r = $b.IndexOf('foreach ($replaced in @(Get-SIBootstrapReplacedJobs -Engine $engine -Keda ([bool]$effectiveUseKEDA))) {')
        ($p -gt 0 -and $r -gt $p) | Should -BeTrue
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1')) | Should -Match ([regex]::Escape('$bootstrapArgs.UseKEDA = [bool]$UseKEDA'))
    }
}

Describe 'the guided install works with producer + worker' {
    BeforeAll { . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1') }
    It 'an engine is present with its scheduled job or with producer AND worker; a run starts at the producer' {
        $pw = Get-SIInstallEngineJobs -Engine identity -Have @('caj-si-identity-producer', 'caj-si-identity-worker', 'caj-si-flow')
        ($pw.Present, $pw.Start) | Should -Be @($true, 'caj-si-identity-producer')
        @($pw.Jobs) | Should -Be @('caj-si-identity-producer', 'caj-si-identity-worker')
        $sj = Get-SIInstallEngineJobs -Engine endpoint -Have @('caj-si-endpoint')
        ($sj.Present, $sj.Start) | Should -Be @($true, 'caj-si-endpoint')
        (Get-SIInstallEngineJobs -Engine azure -Have @('caj-si-azure-producer')).Present | Should -BeFalse
        (Get-SIInstallEngineJobs -Engine privilege-tier-classifier -Have @('caj-si-ptc')).Present | Should -BeTrue
    }
    It 'WIRING: the container-jobs step and the first run use it' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
        $g | Should -Match ([regex]::Escape('$s = Get-SIInstallEngineJobs -Engine $e -Have $have'))
        $g | Should -Match ([regex]::Escape('$job = (Get-SIInstallEngineJobs -Engine $firstEngine -Have @($jobsNow)).Start'))
    }
}
