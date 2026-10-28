#Requires -Version 5.1
<#
    #742 -- RISK ANALYSIS ON QUEUE WORKERS: THE WIRING, THE CONTAINER SCOPE AND THE JOBS.
      * CONTAINER SCOPE (the 2105 lesson: a container ran a step whose function was loaded in another scope): the new entry
        points load every function they call in THEIR OWN scope -- RA-ScaleOut.ps1 alone in a fresh runspace, the update's
        SI-RaWorkerJobs.ps1 alone in a fresh runspace, and the engine's queue-worker glue against what the engine loads;
      * the engine (comment-stripped source): a worker sends no run-health record of its own, takes its first report before
        it prepares anything, joins its producer's collection (never begins one, never builds the CIs, never imports or
        resets the bucket counts, never loads the Defender list), numbers its reports as planned, leaves #674 to the
        producer, NEVER posts to Log Analytics, and STOPS after its loop (before the run's end); the producer hands its
        reports out and then posts the whole run ONCE from SQL -- the released post, every row, no per-report filter;
      * the container entry point: the role, the run safety and the guard history are the producer's, the transcript says
        "worker", the heartbeat signs in with the identity;
      * ON BY DEFAULT WHERE THEY CAN RUN (owner 2026-10-18: "pls dont turn off things that improve time, why do that"): not
        set = on; only an explicit SI_Bootstrap_RaScaleOut = $false (or SI_UPDATER_RA_SCALE_OUT = off; the config wins)
        turns them off -- the update's step 9b, run for real, then makes NO Azure call on a job that is no producer, and a
        Risk Analysis job still told it is one is told it is not (read back);
      * SETUP (Bootstrap): the Detailed Risk Analysis job is the producer of caj-si-raworker-detailed on the work queue when
        queue scaling is on -- one definition (container\_shared\SI-ContainerConfig.ps1); where it cannot run nothing is
        removed (one line why); only $false removes the worker; the worker learns how many workers share the Defender budget;
      * UPDATE (setup\_shared\SI-RaWorkerJobs.ps1, against a fake REST seam): by default an existing install gets the same
        worker, read back, and only then its Risk Analysis job is told; a second run changes nothing; a client secret /
        queue scaling off keeps it as it is; a worker that does not read back is removed again; the plan only under -WhatIf
        (no call at all).
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:EnginePath = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    function script:Strip([string]$Path) {
        # the source without comments (a comment never proves wiring)
        $tok = $null; $err = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tok, [ref]$err)
        $src = [IO.File]::ReadAllText($Path)
        $sb = New-Object System.Text.StringBuilder; $pos = 0
        foreach ($t in @($tok | Where-Object { $_.Kind -eq 'Comment' } | Sort-Object { $_.Extent.StartOffset })) { [void]$sb.Append($src.Substring($pos, $t.Extent.StartOffset - $pos)); $pos = $t.Extent.EndOffset }
        [void]$sb.Append($src.Substring($pos)); $sb.ToString()
    }
    $script:Eng = Strip $script:EnginePath
    $script:Entry = Strip (Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1')
    $script:Boot = Strip (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
    # in a FRESH runspace: load -Load (files, then function texts), then every command the functions of -Check call must resolve
    function script:Get-Unresolved([string[]]$Load = @(), [string[]]$Defs = @(), [string[]]$Functions = @(), [string]$From) {
        $ps = [powershell]::Create()
        try {
            [void]$ps.AddScript({
                param($Load, $Defs, $Functions, $From)
                foreach ($f in $Load) { . $f }
                foreach ($d in $Defs) { . ([scriptblock]::Create($d)) }
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($From, [ref]$null, [ref]$null)
                $fns = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | Where-Object { -not $Functions.Count -or $Functions -contains $_.Name })
                $missing = New-Object System.Collections.Generic.List[string]
                foreach ($fn in $fns) {
                    foreach ($c in @($fn.Body.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] }, $true))) {
                        $n = $c.GetCommandName()
                        if (-not $n -or $n -match '^[\.&]$' -or $n -match '[\\/]') { continue }
                        if ($n -in 'pwsh', 'git') { continue }
                        if (-not (Get-Command -Name $n -ErrorAction SilentlyContinue)) { $missing.Add(('{0} -> {1}' -f $fn.Name, $n)) }
                    }
                }
                $missing.ToArray() | Select-Object -Unique
            }).AddArgument($Load).AddArgument($Defs).AddArgument($Functions).AddArgument($From)
            @($ps.Invoke())
        } finally { $ps.Dispose() }
    }
}

Describe 'container scope -- every new entry point loads what it calls in ITS scope (2105)' {
    It 'RA-ScaleOut.ps1 alone, in a fresh runspace (the queue, the store, the markers, the hand-over, the lock)' {
        $f = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScaleOut.ps1'
        @(Get-Unresolved -Load @($f) -From $f) | Should -BeNullOrEmpty
    }
    It 'the store''s Remove (the lock release) calls Remove-SIBlob captured as a VALUE -- it works after the name is gone' {
        # The closure called Remove-SIBlob by NAME: it worked only when the job happened to have SI-AzRest.ps1 loaded where the
        # closure ran. In a fresh runspace: a stub, the store made, the name removed, Remove still reaches the stub.
        $f = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScaleOut.ps1'
        $ps = [powershell]::Create()
        try {
            [void]$ps.AddScript({
                param($F)
                . $F
                function Remove-SIBlob { param($Account, $Container, $Blob) "removed $Account/$Container/$Blob" }
                $s = New-RAScaleOutBlobStore -Account 'acct' -Container 'sistate'
                Remove-Item -Path 'function:Remove-SIBlob' -Force
                $after = [bool](Get-Command -Name Remove-SIBlob -CommandType Function -ErrorAction SilentlyContinue)
                [pscustomobject]@{ NameVisible = $after; Out = (& $s.Remove 'locks/ra.lock') }
            }).AddArgument($f)
            $r = @($ps.Invoke())[0]
            $r.NameVisible | Should -BeFalse
            $r.Out | Should -Be 'removed acct/sistate/locks/ra.lock'
        } finally { $ps.Dispose() }
    }
    It 'the store''s Remove with Remove-SIBlob not loadable is a plain error naming it' {
        $src = Strip (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScaleOut.ps1')
        $fn = [regex]::Match($src, '(?s)function New-RAScaleOutBlobStore \{.*?\n\}').Value
        $fn | Should -Match '\$\{function:Remove-SIBlob\}'
        $fn | Should -Match 'Remove-SIBlob is not loaded'
        $fn | Should -Not -Match '\{\s*param\(\$Path\)\s*Remove-SIBlob'
    }
    It 'the update''s SI-RaWorkerJobs.ps1 alone, in a fresh runspace' {
        $f = Join-Path $script:SIRoot 'setup\_shared\SI-RaWorkerJobs.ps1'
        @(Get-Unresolved -Load @($f) -From $f) | Should -BeNullOrEmpty
    }
    It 'the engine''s queue-worker glue calls only what the engine defines or loads' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
        $defs = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Extent.Text })
        $sh = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
        $load = @('RA-ScaleOut.ps1', 'RA-SqlStream.ps1', 'RA-DefenderFilter.ps1', 'RA-IngestKeyColumns.ps1', 'RA-ExcelColumnTypes.ps1', 'RA-AutoBucketing.ps1') | ForEach-Object { Join-Path $sh $_ }
        $glue = @('Get-RAScaleOutEngineState', 'Get-RAScaleOutEngineCounters', 'Clear-RAScaleOutReportRows', 'Receive-RAScaleOutWorkerItem',
                  'Invoke-RAScaleOutLocalWorker', 'Invoke-RAScaleOutProducerPass', 'Step-RALoopPass', 'Complete-RALoopPass',
                  'Get-RAScaleOutSplitOfItem', 'Complete-RAScaleOutSplitPart')
        @(Get-Unresolved -Load $load -Defs $defs -Functions $glue -From $script:EnginePath | Where-Object { $_ -notmatch '-> (Write-Section|Write-Err2|Write-Warn2|Write-Info|Write-Ok|Write-Diag)$' }) | Should -BeNullOrEmpty
        foreach ($g in $glue) { $script:Eng | Should -Match ('function {0} ' -f [regex]::Escape($g)) }
    }
}

Describe 'the engine: a worker and a producer' {
    It 'a worker sends no run-health record of its own' {
        $script:Eng | Should -Match ([regex]::Escape("if (`$script:RAScaleRole -ne 'worker') { try { Send-SIRunHealthRow -RunContext `$script:_RunHealthCtx -Phase 'Start' } catch {} }"))
    }
    It 'a worker takes its first report before it prepares anything' {
        $take = $script:Eng.IndexOf('$script:RAScaleFirst = Receive-RAScaleOutItem')
        $yaml = $script:Eng.IndexOf('Write-Step "loading report settings from YAML"')
        $loop = $script:Eng.IndexOf('while (Step-RALoopPass) {')
        ($take, $loop) | ForEach-Object { $_ | Should -BeGreaterThan 0 }
        $take | Should -BeLessThan $yaml
    }
    It 'a worker joins its producer''s collection: no new collection, no CI build, no import or reset of the counts' {
        $script:Eng | Should -Match ([regex]::Escape('-AttachCollectionId $__raAttach'))
        $script:Eng | Should -Match ([regex]::Escape("if (`$script:RAScaleRole -ne 'worker' -and (Test-RACiBuildHere)) {"))
        $script:Eng | Should -Match ([regex]::Escape("-ImportCache `$(if (`$script:RAScaleRole -ne 'worker' -and `$global:SI_RaBucketImportCache -is [hashtable])"))
        $script:Eng | Should -Match ([regex]::Escape("-ResetAll:([bool]`$global:ResetCache -and `$script:RAScaleRole -ne 'worker')"))
        $script:Eng | Should -Match ([regex]::Escape("if (`$script:RAScaleRole -eq 'worker' -and `$null -ne `$script:RAScaleRunTime) { `$global:RA_CollectionTime = `$script:RAScaleRunTime }"))
    }
    It 'a worker never loads the Defender list (the producer did, once)' {
        $script:Eng | Should -Match ([regex]::Escape("if (`$script:RAScaleRole -eq 'worker') {`r`n    `$script:RADfcWorker = `$true").Replace('\r\n', '\r?\n'))
        $df = Strip (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-DefenderFilter.ps1')
        $df | Should -Match ([regex]::Escape('if ($script:RADfcWorker) { throw (New-RALookupUnavailableError'))
        $script:Eng | Should -Match ([regex]::Escape('$set = Sync-RADefenderKeySet -Stream $script:RAStream -WorkspaceResourceId $ws'))
    }
    It 'the loop: one pass per item for a worker, the report numbered as planned, the item finished after its report; the worker STOPS before the run''s end' {
        $script:Eng | Should -Match ([regex]::Escape("while (Step-RALoopPass) {`nforeach (`$includeItem in `$script:RALoopList) {").Replace('\n', '\r?\n'))
        $script:Eng | Should -Match ([regex]::Escape('-Query $Query @__soStart'))
        $script:Eng | Should -Match ([regex]::Escape('$__soStart = @{ Ordinal = $__soOrd; SeqBase = (Get-RAScaleOutSeqBase -Ordinal $__soOrd) }'))
        $dm = [regex]::Match($script:Eng, '\nComplete-RALoopPass\r?\n\}'); $dm.Success | Should -BeTrue; $done = $dm.Index
        $stop = $script:Eng.IndexOf("if (`$script:RAScaleRole -eq 'worker') {", $done)
        $end = $script:Eng.IndexOf('try { $null = Complete-RADefenderFilterRun }')
        ($done, $stop, $end) | ForEach-Object { $_ | Should -BeGreaterThan 0 }
        $done | Should -BeLessThan $stop; $stop | Should -BeLessThan $end
        $script:Eng.Substring($stop, 200) | Should -Match 'return'
    }
    It 'the cross-report steps stay with the producer: #674 is decided over the whole run there, never by a worker' {
        $script:Eng | Should -Match ([regex]::Escape("if (`$script:RAScaleRole -ne 'worker' -and `$script:_RAHandoffEmptyGivers -and `$script:_RAHandoffEmptyGivers.Count -gt 0) {"))
        $script:Eng | Should -Match ([regex]::Escape('Get-RAScaleOutHandoffContradictions -EmptyGivers $state[''EmptyGivers''] -Retrieved $retrieved -Ordinals $ords'))
    }
    It 'Log Analytics: a worker NEVER posts; the producer posts the whole run ONCE from SQL, through the released post' {
        # the worker's item end (Complete-RALoopPass) has no post, no table update, no Log Analytics switch
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
        $done = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Complete-RALoopPass' }, $true)
        $done | Should -Not -BeNullOrEmpty
        $doneText =$done.Body.Extent.Text -replace '(?s)<#.*?#>', ''
        foreach ($n in 'Invoke-RALaPagedPost', 'Invoke-RALaChunkedPost', 'Update-SILogTableSchema', 'SendToLogAnalytics', 'Post-AzLogAnalytics', 'Invoke-RALaPublishStep') { $doneText | Should -Not -Match ([regex]::Escape($n)) }
        # no per-report Log Analytics step exists any more, and no worker definition of it
        $script:Eng | Should -Not -Match 'Invoke-RALaPublishStep|Get-RAScaleOutFunctionText|Confirm-RAScaleOutLaDelivery'
        # the worker STOPS before the one post of the run (every row: no -Reports filter on the pager)
        $dm = [regex]::Match($script:Eng, '\nComplete-RALoopPass\r?\n\}'); $dm.Success | Should -BeTrue
        $stop = $script:Eng.IndexOf("if (`$script:RAScaleRole -eq 'worker') {", $dm.Index)
        $post = $script:Eng.IndexOf('$__laDelivery = Invoke-RALaPagedPost -Pager $__pgL')
        ($stop, $post) | ForEach-Object { $_ | Should -BeGreaterThan 0 }
        $stop | Should -BeLessThan $post
        @([regex]::Matches($script:Eng, [regex]::Escape('$__laDelivery = Invoke-RALaPagedPost'))).Count | Should -Be 1 -Because 'one post in the engine'
        $script:Eng | Should -Match ([regex]::Escape('$__pgL = if ($script:RAStreamOn) { New-RARowPager -Stream $script:RAStream -Source All -ReadAhead } else'))
        $script:Eng | Should -Match ([regex]::Escape('if ([long]$__laDelivery.RowsPosted -ne $script:RAAllCount) { throw'))
        $script:Eng | Should -Match ([regex]::Escape('$script:RAAllCount = Get-RAStreamCount -Stream $script:RAStream -Source All'))
        # the pager has no per-report filter at all (the released pager)
        $ss = Strip (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
        $ss | Should -Not -Match 'OPENJSON\(@Reports\)'
        $pg = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'), [ref]$null, [ref]$null).Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RARowPager' }, $true)
        @($pg.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }) | Should -Not -Contain 'Reports'
    }
    It 'an item that did not deliver: its report NOT COMPLETE with the cause and its rows removed' {
        $script:Eng | Should -Match ([regex]::Escape('foreach ($f in @(Get-RAScaleOutItemFailures -Manifest $m -Markers @($w.Markers) -Handovers $handovers)) {'))
        $script:Eng | Should -Match ([regex]::Escape('Add-RAReportFailure -ReportName ([string]$f.Report) -Reason ("not complete: {0}" -f $f.Why)'))
        $script:Eng | Should -Match ([regex]::Escape('Clear-RAScaleOutReportRows -Ordinal ([int]$o[0].Ordinal)'))
    }
}

Describe 'the container entry point' {
    It 'the role from SI_RA_SCALEOUT_ROLE; the producer''s switches from the job; the heartbeat signs in with the identity' {
        $script:Entry | Should -Match ([regex]::Escape("`$raWorker = ((Get-OptionalEnv 'SI_RA_SCALEOUT_ROLE' '').Trim().ToLowerInvariant() -eq 'worker')"))
        $script:Entry | Should -Match ([regex]::Escape("`$global:SI_RA_WorkerJob = Get-OptionalEnv 'SI_RA_WORKER_JOB' ''"))
        $script:Entry | Should -Match ([regex]::Escape("`$global:SI_RA_BeatSignIn = @('/app/auth/SI-ManagedIdentity.ps1')"))
    }
    It 'a worker: its own transcript name, no run safety, no guard history; its bucket counts only for its reports' {
        $script:Entry | Should -Match ([regex]::Escape("-Template `$(if (`$raWorker) { '{0}-worker' -f `$global:ReportTemplate } else { `$global:ReportTemplate })"))
        $script:Entry | Should -Match ([regex]::Escape('if (-not $raWorker) { try { . /app/engine/_shared/SI-FirstRun.ps1'))
        $script:Entry | Should -Match ([regex]::Escape('if (-not $raWorker) { $null = Save-SIRaGuardHistory'))
        $script:Entry | Should -Match ([regex]::Escape('Merge-RAScaleOutBucketCache -Stored $bcStored -Local $bcLocal -Reports @($global:SI_RA_ScaleOutReportsRun)'))
        $script:Entry | Should -Match ([regex]::Escape('elseif (-not $global:SI_RA_ScaleOutRan) { $null = Save-SIRaAutoBucketCache'))
    }
}

Describe 'setup gives a new install the worker job (Bootstrap; one definition)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'ON BY DEFAULT where it can run: not set = on; only an explicit $false / off turns it off (the customer''s choice)' {
        $d = Resolve-SIRaScaleOutChoice -Engine 'risk-analysis-detailed' -Keda $true -IdentityResourceId '/id' -StorageAccount 'st'
        $d.On | Should -BeTrue; $d.Configured | Should -BeFalse; $d.SwitchedOff | Should -BeFalse
        foreach ($v in @($null, '', '  ')) {
            $x = Resolve-SIRaScaleOutChoice -Engine 'risk-analysis-detailed' -Keda $true -IdentityResourceId '/id' -StorageAccount 'st' -Globals @{ SI_Bootstrap_RaScaleOut = $v }
            $x.Configured | Should -BeFalse; $x.On | Should -BeTrue
        }
        $off = Resolve-SIRaScaleOutChoice -Engine 'risk-analysis-detailed' -Keda $true -IdentityResourceId '/id' -StorageAccount 'st' -Globals @{ SI_Bootstrap_RaScaleOut = $false }
        $off.On | Should -BeFalse; $off.Configured | Should -BeTrue; $off.SwitchedOff | Should -BeTrue; $off.Reason | Should -Match 'switched off'
        foreach ($v in @($false, 'false', '$false', 'off', 'OFF', '0', 'no', 'disabled')) { (Get-SIRaScaleOutOptIn -Globals @{ SI_Bootstrap_RaScaleOut = $v }).On | Should -BeFalse -Because "$v switches them off" }
        foreach ($v in @($true, 'true', 'on', '1', 'yes')) { (Get-SIRaScaleOutOptIn -Globals @{ SI_Bootstrap_RaScaleOut = $v }).On | Should -BeTrue }
        (Get-SIRaScaleOutOptIn -Globals @{}).On | Should -BeTrue
        (Get-SIRaScaleOutOptIn -Globals @{} -UpdaterValue 'off').On | Should -BeFalse
        (Get-SIRaScaleOutOptIn -Globals @{} -UpdaterValue 'on').On | Should -BeTrue
        (Get-SIRaScaleOutOptIn -Globals @{ SI_Bootstrap_RaScaleOut = $false } -UpdaterValue 'on').On | Should -BeFalse -Because 'the config wins over the updater job'
        (Get-SIRaScaleOutOptIn -Globals @{ SI_Bootstrap_RaScaleOut = $true } -UpdaterValue 'off').On | Should -BeTrue -Because 'the config wins over the updater job'
    }
    It 'where it cannot run: off, with one plain reason -- and not "switched off" (nothing is removed for it)' {
        (Resolve-SIRaScaleOutChoice -Engine 'risk-analysis-detailed' -Keda $true -IdentityResourceId '/id' -StorageAccount 'st').On | Should -BeTrue
        (Resolve-SIRaScaleOutChoice -Engine 'risk-analysis' -Keda $true -IdentityResourceId '/id' -StorageAccount 'st').On | Should -BeFalse
        foreach ($c in @(@{ Keda = $false; Id = '/id'; St = 'st'; Why = 'queue scaling is off' }, @{ Keda = $true; Id = ''; St = 'st'; Why = 'no managed identity' }, @{ Keda = $true; Id = '/id'; St = ''; Why = 'no storage account' })) {
            $x = Resolve-SIRaScaleOutChoice -Engine 'risk-analysis-detailed' -Keda $c.Keda -IdentityResourceId $c.Id -StorageAccount $c.St
            $x.On | Should -BeFalse; $x.SwitchedOff | Should -BeFalse; $x.Reason | Should -Match $c.Why
        }
    }
    It 'the worker: event-triggered on the WORK queue, the producer''s settings as role ra + worker, no producer switches; up to 4 at once' {
        $a = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-raworker-detailed' -ResourceGroup 'rg' -Environment 'cae' -Image 'img' -LoginServer 'acr.io' -ReplicaTimeout 604800 -Cpu '4.0' -Memory '8Gi' `
                -MaxExecutions (Get-SIRaWorkerMaxExecutions) -Engine 'risk-analysis-detailed' -StorageAccount 'stsi' -IdentityResourceId '/id' -QueueName (Get-SIRaScaleOutQueueName -Grain Detailed))
        ($a -join ' ') | Should -Match 'queueName=si-ra-detailed-items'
        ($a -join ' ') | Should -Match '--max-executions 4 '
        ($a -join ' ') | Should -Match '--trigger-type Event'
        $e = @(Get-SIRaWorkerEnvArgs -EnvArgs @('SI_ENGINE=risk-analysis-detailed', 'SI_ROLE=ra', 'SI_RA_SCALE_OUT=on', 'SI_RA_WORKER_JOB=caj-si-raworker-detailed', 'SI_CFG_X=1') -ReplicaTimeout 604800)
        $e | Should -Contain 'SI_RA_SCALEOUT_ROLE=worker'; $e | Should -Contain 'SI_ROLE=ra'; $e | Should -Contain 'SI_CFG_X=1'
        @($e | Where-Object { $_ -match '^SI_RA_SCALE_OUT=|^SI_RA_WORKER_JOB=' }).Count | Should -Be 0
        @($e | Where-Object { $_ -match '^SI_RA_WORKERS=' }).Count | Should -Be 0 -Because 'no count given, none written (an older worker: the default 4 applies)'
        $e4 = @(Get-SIRaWorkerEnvArgs -EnvArgs @('SI_ENGINE=risk-analysis-detailed', 'SI_RA_WORKERS=9') -ReplicaTimeout 604800 -Workers 4)
        @($e4 | Where-Object { $_ -match '^SI_RA_WORKERS=' }) | Should -Be @('SI_RA_WORKERS=4') -Because 'the worker learns how many workers share the Defender budget, once'
        Get-SIRaProducerScaleOutEnvArgs -Grain Detailed | Should -Be @('SI_RA_SCALE_OUT=on', 'SI_RA_WORKER_JOB=caj-si-raworker-detailed')
        Get-SIRaProducerScaleOutEnvArgs -Grain Detailed -Workers 6 | Should -Be @('SI_RA_SCALE_OUT=on', 'SI_RA_WORKER_JOB=caj-si-raworker-detailed', 'SI_RA_WORKERS=6') -Because '#831: the producer plans for the real worker count'
        Get-SIRaWorkerMaxExecutions -Globals @{ SI_Bootstrap_RaMaxWorkers = 8 } | Should -Be 8
        # the collection workers' queue is unchanged
        (@(Get-SIKedaQueueScaleArgs -Engine 'identity' -StorageAccount 'st' -IdentityResourceId '/id') -join ' ') | Should -Match 'queueName=si-identity-shards'
    }
    It 'Bootstrap: the producer''s switches on the Risk Analysis job, the worker in step 4c, removed only when switched off' {
        $script:Boot | Should -Match ([regex]::Escape('if ($raScale.On) { $envArgs += @(Get-SIRaProducerScaleOutEnvArgs -Grain $raScale.Grain -Workers (Get-SIRaWorkerMaxExecutions -Globals $bootGlobals)) }')) -Because '#831: the producer gets the same SI_RA_WORKERS as its workers'
        $script:Boot | Should -Match ([regex]::Escape('$raWorkerEnv = @(Get-SIRaWorkerEnvArgs -EnvArgs $envArgs -ReplicaTimeout ([int]$jobRes.ReplicaTimeout) -Workers $raWorkerMax)'))
        $script:Boot | Should -Match ([regex]::Escape('-Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId) -QueueName $raWorkerQueue)'))
        # on by default: step 4c runs for every Detailed job; where it cannot run it says why and removes nothing --
        # only the customer's $false removes a worker
        $script:Boot | Should -Match ([regex]::Escape('if ($isRiskAnalysis -and $raScale -and $raScale.Grain) {'))
        $script:Boot | Should -Match ([regex]::Escape('if ($raScale.SwitchedOff) { Remove-SIBootstrapReplacedJob -Name $raWorkerName }'))
        $script:Boot | Should -Not -Match ([regex]::Escape('$raScale.On -or $raScale.Configured'))
    }
}

Describe 'the update gives an existing install the worker job (REST seam)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-RaWorkerJobs.ps1')
        $script:Sub = 'sub-1'; $script:Rg = 'rg-si'
        $script:Uami = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-securityinsight'
        $script:Img = 'acrsi.azurecr.io/si-orchestrator:v3.1.0-abc'
        $script:Stg = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.Storage/storageAccounts/stsi'
        function script:New-RaJob([ValidateSet('MI', 'Secret')][string]$Auth = 'MI', [switch]$Flagged, [switch]$NoSiTag) {
            $env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'risk-analysis-detailed' }, [pscustomobject]@{ name = 'SI_ROLE'; value = 'ra' }, [pscustomobject]@{ name = 'SI_STORAGE_ACCOUNT'; value = 'stsi' },
                     [pscustomobject]@{ name = 'SI_RA_MODE'; value = 'Detailed' }, [pscustomobject]@{ name = 'SMTP_PASSWORD'; secretRef = 'smtp-password' })
            if ($Auth -eq 'MI') { $env += @([pscustomobject]@{ name = 'SI_UAMI_CLIENTID'; value = 'client-1' }, [pscustomobject]@{ name = 'SI_SPN_TENANTID'; value = 'ten' }) }
            else { $env += @([pscustomobject]@{ name = 'SI_SPN_APPID'; value = 'app' }, [pscustomobject]@{ name = 'SI_SPN_SECRET'; secretRef = 'si-spn-secret' }) }
            if ($Flagged) { $env += @([pscustomobject]@{ name = 'SI_RA_SCALE_OUT'; value = 'on' }, [pscustomobject]@{ name = 'SI_RA_WORKER_JOB'; value = 'caj-si-raworker-detailed' }, [pscustomobject]@{ name = 'SI_RA_WORKERS'; value = '4' }) }
            $tags = [ordered]@{}; if (-not $NoSiTag) { $tags['si-build'] = '3.1.0+abc' }
            $ident = if ($Auth -eq 'Secret') { $null } else { [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ $script:Uami = [pscustomobject]@{ clientId = 'client-1'; principalId = 'principal-1' } } } }
            [pscustomobject]@{ name = 'caj-si-risk-analysis-detailed'; location = 'westeurope'; tags = [pscustomobject]$tags; identity = $ident
                properties = [pscustomobject]@{ environmentId = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.App/managedEnvironments/cae-si'; provisioningState = 'Succeeded'
                    configuration = [pscustomobject]@{ triggerType = 'Manual'; replicaTimeout = 604800; registries = @([pscustomobject]@{ server = 'acrsi.azurecr.io'; identity = $script:Uami })
                                                       secrets = @([pscustomobject]@{ name = 'smtp-password' }); manualTriggerConfig = [pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1 } }
                    template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; image = $script:Img; env = $env; resources = [pscustomobject]@{ cpu = 4.0; memory = '8Gi' } }) } } }
        }
        function script:New-World([object[]]$Jobs, [hashtable]$Fail = @{}) {
            $w = [pscustomobject]@{ Jobs = @{}; Fail = $Fail; Calls = (New-Object System.Collections.Generic.List[string]); Req = (New-Object System.Collections.Generic.List[object]) }
            foreach ($j in $Jobs) { $w.Jobs[$j.name] = ($j | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
            $w
        }
        $script:Rest = {
            param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $w = $script:World; $line = '{0} {1}' -f $Method, $Uri; $w.Calls.Add($line)
            $w.Req.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            $ok = { param($s, $o) [pscustomobject]@{ Status = $s; Body = $(if ($null -eq $o) { '' } elseif ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 30 -Compress }) } }
            if ($Method -eq 'GET' -and $Uri -like '*/storageAccounts/stsi[?]*') { return (& $ok 200 @{ name = 'stsi'; id = $script:Stg }) }
            if ($Method -eq 'GET' -and $Uri -like '*/roleAssignments[?]*') { return (& $ok 200 @{ value = @(@{ properties = @{ roleDefinitionId = '/x/roleDefinitions/974c5e8b-45b9-4653-ba55-5f855dd0fb88' } }) }) }
            if ($Method -eq 'POST' -and $Uri -like '*/listSecrets[?]*') { return (& $ok 200 @{ value = @(@{ name = 'smtp-password'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/smtp'; identity = $script:Uami }) }) }
            if ($Uri -like 'https://*.queue.core.windows.net/*') { return (& $ok 201 '') }
            $m = [regex]::Match($Uri, '/providers/Microsoft\.App/jobs/([^/?]+)\?')
            if ($m.Success) {
                $n = $m.Groups[1].Value
                switch ($Method) {
                    'PUT' {
                        $j = $Body | ConvertFrom-Json; $j | Add-Member -Force -NotePropertyName name -NotePropertyValue $n
                        $j.properties | Add-Member -Force -NotePropertyName provisioningState -NotePropertyValue $(if ($w.Fail.provisioning) { 'Failed' } else { 'Succeeded' })
                        $w.Jobs[$n] = $j; return (& $ok 201 $j)
                    }
                    'GET' { if ($w.Jobs.ContainsKey($n)) { return (& $ok 200 $w.Jobs[$n]) }; return (& $ok 404 'ResourceNotFound') }
                    'DELETE' { $null = $w.Jobs.Remove($n); return (& $ok 200 '') }
                    'PATCH' {
                        if ($w.Fail.patch) { return (& $ok 409 'refused') }
                        $b = $Body | ConvertFrom-Json
                        $w.Jobs[$n].properties.template = $b.properties.template
                        return (& $ok 200 '')
                    }
                }
            }
            & $ok 400 "unexpected call: $line"
        }
        # (asked for, unless -Default: the install's own setting -- the default -- is off)
        function script:Invoke-Rw([object[]]$Jobs, [hashtable]$Globals = @{}, [switch]$WhatIf, [string]$UpdaterUseKeda, [string]$UpdaterRaScaleOut, [switch]$Default) {
            $g = @{}; if (-not $Default) { $g['SI_Bootstrap_RaScaleOut'] = $true }; foreach ($k in $Globals.Keys) { $g[$k] = $Globals[$k] }
            Invoke-SIRaWorkerJobs -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Jobs $Jobs -Globals $g -WhatIf:$WhatIf -UpdaterUseKeda $UpdaterUseKeda -UpdaterRaScaleOut $UpdaterRaScaleOut -PollSeconds 0 -PollMax 2
        }
        function script:Get-JobEnv([string]$Name) { @(ConvertTo-SIKedaConvertEnvArgs -Env @($script:World.Jobs[$Name].properties.template.containers[0].env)) }
    }
    It 'creates the worker from the Risk Analysis job, reads it back, THEN tells the Risk Analysis job' {
        $j = New-RaJob; $script:World = New-World @($j)
        $r = Invoke-Rw -Jobs @($j)
        $r.Results[0].Action | Should -Be 'created' -Because (@($r.Lines) -join ' | ')
        $r.Lines[0] | Should -Match 'now hands its reports to up to 4 queue-scaled workers \(caj-si-raworker-detailed\)'
        $w = $script:World.Jobs['caj-si-raworker-detailed']
        $w.properties.configuration.triggerType | Should -Be 'Event'
        $w.properties.configuration.eventTriggerConfig.scale.rules[0].metadata.queueName | Should -Be 'si-ra-detailed-items'
        $w.properties.configuration.eventTriggerConfig.scale.rules[0].identity | Should -Be $script:Uami
        $w.properties.configuration.eventTriggerConfig.scale.maxExecutions | Should -Be 4
        $w.properties.template.containers[0].image | Should -Be $script:Img
        $we = Get-JobEnv 'caj-si-raworker-detailed'
        $we | Should -Contain 'SI_RA_SCALEOUT_ROLE=worker'; $we | Should -Contain 'SMTP_PASSWORD=secretref:smtp-password'; $we | Should -Contain 'SI_UAMI_CLIENTID=client-1'
        $we | Should -Contain 'SI_RA_WORKERS=4' -Because 'each worker asks Defender for its share of one job''s parts at a time'
        @($w.properties.configuration.secrets | ForEach-Object { $_.name }) | Should -Contain 'smtp-password'
        $pe = Get-JobEnv 'caj-si-risk-analysis-detailed'
        $pe | Should -Contain 'SI_RA_SCALE_OUT=on'; $pe | Should -Contain 'SI_RA_WORKER_JOB=caj-si-raworker-detailed'; $pe | Should -Contain 'SI_RA_MODE=Detailed'
        $pe | Should -Contain 'SI_RA_WORKERS=4' -Because '#831: the producer gets the SAME worker count as its workers (read back)'
        $iPut = [array]::IndexOf(@($script:World.Calls), @($script:World.Calls | Where-Object { $_ -like 'PUT*/jobs/caj-si-raworker-detailed?*' })[0])
        $iPatch = [array]::IndexOf(@($script:World.Calls), @($script:World.Calls | Where-Object { $_ -like 'PATCH*/jobs/caj-si-risk-analysis-detailed?*' })[0])
        $iPut | Should -BeLessThan $iPatch
    }
    It 'a worker that does not read back is removed again; the Risk Analysis job is NOT told' {
        $j = New-RaJob; $script:World = New-World @($j) -Fail @{ provisioning = $true }
        $r = Invoke-Rw -Jobs @($j)
        $r.Results[0].Action | Should -Be 'failed'
        $r.Lines[0] | Should -Match 'was NOT given its workers.*runs its reports itself'
        $script:World.Jobs.ContainsKey('caj-si-raworker-detailed') | Should -BeFalse
        @($script:World.Calls | Where-Object { $_ -like 'PATCH*' }).Count | Should -Be 0
    }
    It 'the worker exists, the Risk Analysis job is not told yet: only the flag (one PATCH, read back)' {
        $j = New-RaJob; $wk = [pscustomobject]@{ name = 'caj-si-raworker-detailed' }
        $script:World = New-World @($j)
        $r = Invoke-Rw -Jobs @($j, $wk)
        $r.Results[0].Action | Should -Be 'flagged'
        @($script:World.Calls | Where-Object { $_ -like 'PUT*' }).Count | Should -Be 0
        Get-JobEnv 'caj-si-risk-analysis-detailed' | Should -Contain 'SI_RA_SCALE_OUT=on'
    }
    It '#831: a producer made before it knew the worker count (or with another) is told the count again -- one PATCH, read back; then nothing to do' {
        $old = New-RaJob -Flagged
        $old.properties.template.containers[0].env = @($old.properties.template.containers[0].env | Where-Object { $_.name -ne 'SI_RA_WORKERS' })
        $wk = [pscustomobject]@{ name = 'caj-si-raworker-detailed' }
        $script:World = New-World @($old, $wk)
        $r = Invoke-Rw -Jobs @($old, $wk) -Globals @{ SI_Bootstrap_RaMaxWorkers = 6 }
        $r.Results[0].Action | Should -Be 'flagged' -Because (@($r.Lines) -join ' | ')
        Get-JobEnv 'caj-si-risk-analysis-detailed' | Should -Contain 'SI_RA_WORKERS=6'
        @(Get-JobEnv 'caj-si-risk-analysis-detailed' | Where-Object { $_ -match '^SI_RA_WORKERS=' }).Count | Should -Be 1
        $script:World.Calls.Clear()
        (Invoke-Rw -Jobs @($script:World.Jobs['caj-si-risk-analysis-detailed'], $wk) -Globals @{ SI_Bootstrap_RaMaxWorkers = 6 }).Results[0].Action | Should -Be 'present'
        # switched off: the count is removed with the other switches
        Get-SIRaProducerUnflagPatch -Producer $script:World.Jobs['caj-si-risk-analysis-detailed'] | ForEach-Object { @($_.Body.properties.template.containers[0].env | Where-Object { $_.name -eq 'SI_RA_WORKERS' }).Count } | Should -Be 0 -Because 'switched off: the count goes with the other switches'
    }
    It 'already a producer with its worker: nothing to do; a client secret, an opt-out, a job SI did not make: left as it is, said' {
        $script:World = New-World @()
        (Invoke-Rw -Jobs @((New-RaJob -Flagged), [pscustomobject]@{ name = 'caj-si-raworker-detailed' })).Results[0].Action | Should -Be 'present'
        $s = Invoke-Rw -Jobs @(New-RaJob -Auth Secret); $s.Results[0].Action | Should -Be 'keep'; $s.Lines[0] | Should -Match 'client secret'
        (Invoke-Rw -Jobs @(New-RaJob) -Globals @{ SI_Bootstrap_UseKEDA = $false }).Lines[0] | Should -Match 'queue scaling is switched off'
        (Invoke-Rw -Jobs @(New-RaJob) -Globals @{ SI_Bootstrap_RaScaleOut = $false }).Results[0].Action | Should -Be 'off'
        (Invoke-Rw -Jobs @(New-RaJob) -UpdaterUseKeda 'false').Results[0].Action | Should -Be 'keep'
        (Invoke-Rw -Jobs @(New-RaJob -NoSiTag)).Lines[0] | Should -Match 'did not create'
        (Invoke-Rw -Jobs @()).Results[0].Action | Should -Be 'none'
        $script:World.Calls.Count | Should -Be 0
    }
    It 'ON BY DEFAULT: setting not given -- an existing install gets the worker (created, read back, then told); a second run changes nothing' {
        $j = New-RaJob; $script:World = New-World @($j)
        $r = Invoke-Rw -Jobs @($j) -Default
        $r.Results[0].Action | Should -Be 'created' -Because (@($r.Lines) -join ' | ')
        Get-JobEnv 'caj-si-risk-analysis-detailed' | Should -Contain 'SI_RA_SCALE_OUT=on'
        $script:World.Jobs.ContainsKey('caj-si-raworker-detailed') | Should -BeTrue
        # idempotent: the next update reads the jobs as they are now and finds nothing to do -- not one write
        $script:World.Calls.Clear()
        $now = @($script:World.Jobs['caj-si-risk-analysis-detailed'], $script:World.Jobs['caj-si-raworker-detailed'])
        $r2 = Invoke-Rw -Jobs $now -Default
        $r2.Results[0].Action | Should -Be 'present'
        @($script:World.Calls | Where-Object { $_ -notlike 'GET*' }).Count | Should -Be 0
        # SI_UPDATER_RA_SCALE_OUT = on (a Pro install without a config file): the same
        $script:World = New-World @($j)
        (Invoke-Rw -Jobs @($j) -Default -UpdaterRaScaleOut 'on').Results[0].Action | Should -Be 'created'
    }
    It 'EXPLICIT OFF is honoured: no worker, no role, no call on a job that is no producer; one line says so' {
        $j = New-RaJob; $script:World = New-World @($j)
        $before = ConvertTo-Json -InputObject $script:World.Jobs['caj-si-risk-analysis-detailed'] -Depth 30 -Compress
        foreach ($c in @(@{ G = @{ SI_Bootstrap_RaScaleOut = $false }; U = '' }, @{ G = @{}; U = 'off' }, @{ G = @{ SI_Bootstrap_RaScaleOut = $false }; U = 'on' })) {
            $r = Invoke-Rw -Jobs @($j) -Default -Globals $c.G -UpdaterRaScaleOut $c.U
            $r.Results[0].Action | Should -Be 'off'
            $r.Results[0].Line | Should -Match 'switched off'
        }
        $script:World.Calls.Count | Should -Be 0 -Because 'not one Azure call: no job created, no role granted, no job read or changed'
        $script:World.Jobs.ContainsKey('caj-si-raworker-detailed') | Should -BeFalse
        (ConvertTo-Json -InputObject $script:World.Jobs['caj-si-risk-analysis-detailed'] -Depth 30 -Compress) | Should -Be $before
    }
    It 'EXPLICIT OFF on an install that has the workers: the Risk Analysis job is told it is no producer (one PATCH, read back); the worker is left idle' {
        $j = New-RaJob -Flagged; $wk = [pscustomobject]@{ name = 'caj-si-raworker-detailed' }
        $script:World = New-World @($j, $wk)
        $r = Invoke-Rw -Jobs @($j, $wk) -Default -Globals @{ SI_Bootstrap_RaScaleOut = $false } -WhatIf
        $r.Results[0].Action | Should -Be 'would-unflag'; $script:World.Calls.Count | Should -Be 0
        $r = Invoke-Rw -Jobs @($j, $wk) -Default -Globals @{ SI_Bootstrap_RaScaleOut = $false }
        $r.Results[0].Action | Should -Be 'unflagged' -Because (@($r.Lines) -join ' | ')
        $r.Lines[0] | Should -Match 'runs its reports itself again \(read back\)'
        $pe = Get-JobEnv 'caj-si-risk-analysis-detailed'
        @($pe | Where-Object { $_ -match '^SI_RA_SCALE_OUT=|^SI_RA_WORKER_JOB=' }).Count | Should -Be 0
        $pe | Should -Contain 'SI_RA_MODE=Detailed' -Because 'nothing else of the job changes'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH*' }).Count | Should -Be 1
        @($script:World.Calls | Where-Object { $_ -like 'PUT*' -or $_ -like 'DELETE*' }).Count | Should -Be 0
        $script:World.Jobs.ContainsKey('caj-si-raworker-detailed') | Should -BeTrue
        # the next update: nothing to undo, no call
        $script:World.Calls.Clear()
        (Invoke-Rw -Jobs @($script:World.Jobs['caj-si-risk-analysis-detailed'], $wk) -Default -Globals @{ SI_Bootstrap_RaScaleOut = $false }).Results[0].Action | Should -Be 'off'
        $script:World.Calls.Count | Should -Be 0
        # a refused change: said, never thrown; a job SI's setup did not make: left as it is
        $script:World = New-World @($j, $wk) -Fail @{ patch = $true }
        $f = Invoke-Rw -Jobs @($j, $wk) -Default -Globals @{ SI_Bootstrap_RaScaleOut = $false }
        $f.Results[0].Action | Should -Be 'failed'; $f.Lines[0] | Should -Match 'was NOT told to run its reports itself'
        $script:World = New-World @()
        $n = Invoke-Rw -Jobs @((New-RaJob -Flagged -NoSiTag), $wk) -Default -Globals @{ SI_Bootstrap_RaScaleOut = $false }
        $n.Results[0].Action | Should -Be 'off'; $n.Lines[0] | Should -Match 'did not create'; $script:World.Calls.Count | Should -Be 0
    }
    It 'the update''s step 9b itself, run for real: on by default (it runs); explicit off makes no Azure call' {
        $u = Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'
        $fn = [System.Management.Automation.Language.Parser]::ParseFile($u, [ref]$null, [ref]$null).Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Invoke-SIUpdateRaWorkers' }, $true)
        $fn | Should -Not -BeNullOrEmpty
        $run = {
            param($Setting)
            $ps = [powershell]::Create()
            try {
                [void]$ps.AddScript({
                    param($FnText, $SetupDir, $Setting)
                    $log = New-Object System.Collections.Generic.List[string]; $calls = New-Object System.Collections.Generic.List[string]
                    function Step([string]$m) { $log.Add("STEP $m") }; function Info([string]$m) { $log.Add("INFO $m") }; function Warn([string]$m) { $log.Add("WARN $m") }
                    function Get-SIArmJobList { $calls.Add('list'); @() }
                    $script:SISqlTierJobs = @([pscustomobject]@{ name = 'caj-si-risk-analysis-detailed' })
                    $globals = @{}; if ($null -ne $Setting) { $globals['SI_Bootstrap_RaScaleOut'] = $Setting }
                    $Apply = $true; $DetectOnly = $false; $sub = 'sub-1'; $target = [pscustomobject]@{ ResourceGroupName = 'rg-si' }
                    $rest = { param($Method, $Uri, $Body, $Resource, $Headers) $calls.Add("$Method $Uri"); [pscustomobject]@{ Status = 404; Body = '' } }
                    [Environment]::SetEnvironmentVariable('SI_UPDATER_RA_SCALE_OUT', $null)
                    . ([scriptblock]::Create(($FnText -replace [regex]::Escape('$PSScriptRoot'), ("'{0}'" -f $SetupDir))))
                    $null = Invoke-SIUpdateRaWorkers
                    [pscustomobject]@{ Log = $log.ToArray(); Calls = $calls.ToArray() }
                }).AddArgument($fn.Extent.Text).AddArgument((Split-Path -Parent $u)).AddArgument($Setting)
                $o = @($ps.Invoke())[-1]
                @($ps.Streams.Error).Count | Should -Be 0 -Because (@($ps.Streams.Error) -join ' | ')
                $o
            } finally { $ps.Dispose() }
        }
        # not set: the step runs (said, the job list read)
        $d = & $run $null
        @($d.Log | Where-Object { $_ -like 'STEP 9b*' }).Count | Should -Be 1
        @($d.Calls) | Should -Contain 'list'
        # switched off: one line says so; no REST call at all (only the job list is read)
        $o = & $run $false
        @($o.Log | Where-Object { $_ -match 'switched off' }).Count | Should -Be 1 -Because (@($o.Log) -join ' | ')
        @($o.Calls | Where-Object { $_ -ne 'list' }).Count | Should -Be 0 -Because ('no Azure call: ' + (@($o.Calls) -join ' | '))
        # the step reads the customer's setting: it is one of the names the update keeps from the config
        (Strip $u) | Should -Match "'SI_Bootstrap_RaScaleOut', 'SI_Bootstrap_RaMaxWorkers'"
        (Strip $u) | Should -Not -Match ([regex]::Escape('if (-not $rwOptIn.On) { return }')) -Because 'the step is no longer skipped by default'
    }
    It '-WhatIf: the plan only -- no call at all' {
        $script:World = New-World @()
        $r = Invoke-Rw -Jobs @(New-RaJob) -WhatIf
        $r.Results[0].Action | Should -Be 'would-create'
        $script:World.Calls.Count | Should -Be 0
    }
    It 'every update runs it, after the collection''s queue scaling' {
        $u = Strip (Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1')
        $u | Should -Match ([regex]::Escape('$null = Invoke-SIUpdateKedaConvert; $null = Invoke-SIUpdateRaWorkers;'))
        $u | Should -Match ([regex]::Escape('$rw = Invoke-SIRaWorkerJobs -Rest $rwRest'))
    }
}
