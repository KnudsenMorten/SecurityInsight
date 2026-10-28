#Requires -Version 5.1
<#
    CONTAINER HOST: THE RA RUN MODE IS ONE DECISION, AND A SHARD IS PROCESSED ONCE -- OR PARKED (#138).

      * Start-RiskAnalysisInContainer set SI_RA_MODE and SI_RA_REPORT_TEMPLATE independently: a Detailed
        template with no mode ingested Detailed rows into the Summary table (#39 again, container path),
        and an unrecognised mode silently became Summary;
      * the Detailed RA job was provisioned with 'RiskAnalysis_Detailed_Bucket', a template no shipped
        YAML defines -- as were the engine's own fallback defaults -- so every such run threw;
      * the KEDA worker leased a shard for 1800s against a 3600s replica timeout (a second worker took
        a still-running shard), and a shard that crashed its worker was retried for ever.
    Functions are lifted by AST; the queue runs in its offline Mock mode. No network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function script:Lift([string]$Path, [string]$Name) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
        if ($fn) { $fn.Extent.Text } else { $null }
    }
    $script:RaContainer = Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1'
    $script:Engine      = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $src1 = Lift $script:RaContainer 'Resolve-SIContainerRaMode'
    $src2 = Lift $script:Engine 'Resolve-RALegacyTemplateName'
    if ($src1) { . ([scriptblock]::Create($src1)) }
    if ($src2) { . ([scriptblock]::Create($src2)) }
    $script:HaveResolvers = [bool]$src1 -and [bool]$src2

    . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')

    # Template names the shipped catalog actually defines.
    $yaml = Get-Content -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
    $inTpl = $false; $script:Shipped = @()
    foreach ($l in $yaml) {
        if ($l -match '^ReportTemplates:') { $inTpl = $true; continue }
        if ($inTpl -and $l -match '^\S') { $inTpl = $false }
        if ($inTpl -and $l -match 'ReportName:\s*(\S+)') { $script:Shipped += $Matches[1] }
    }
}

Describe 'the resolvers exist' {
    It 'both were lifted' { $script:HaveResolvers | Should -BeTrue }
}

Describe 'container RA: the template decides the mode' {
    It 'a Detailed template with NO mode runs Detailed (it ran Summary and wrote the Summary table)' {
        $r = Resolve-SIContainerRaMode -Template 'RiskAnalysis_Detailed' -Mode $null
        $r.Mode | Should -Be 'Detailed'; $r.Detailed | Should -BeTrue; $r.Summary | Should -BeFalse
    }
    It 'a mode with no template gets that mode''s shipped template' {
        (Resolve-SIContainerRaMode -Template $null -Mode 'Detailed').Template | Should -Be 'RiskAnalysis_Detailed'
        (Resolve-SIContainerRaMode -Template $null -Mode $null).Template     | Should -Be 'RiskAnalysis_Summary'
    }
    It 'a contradiction is refused, not resolved by guessing a table' {
        { Resolve-SIContainerRaMode -Template 'RiskAnalysis_Detailed' -Mode 'Summary' } | Should -Throw '*Contradictory*'
    }
    It 'an unrecognised mode is refused (it silently became Summary)' {
        { Resolve-SIContainerRaMode -Template $null -Mode 'Detail' } | Should -Throw '*not a run mode*'
    }
    It 'a custom template with no grain in its name keeps the stated mode' {
        $r = Resolve-SIContainerRaMode -Template 'Weekly_Board' -Mode 'detailed'
        $r.Mode | Should -Be 'Detailed'; $r.Template | Should -Be 'Weekly_Board'
    }
    It 'WIRING -- the container uses the resolver for both globals' {
        $src = Get-Content -LiteralPath $script:RaContainer -Raw
        $src | Should -Match '\$global:ReportTemplate\s*=\s*\$__ra\.Template'
        $src | Should -Match '\$global:Detailed\s*=\s*\$__ra\.Detailed'
    }
}

Describe 'no shipped path names a template that does not exist' {
    It 'the shipped catalog defines the two defaults' {
        $script:Shipped | Should -Contain 'RiskAnalysis_Summary'
        $script:Shipped | Should -Contain 'RiskAnalysis_Detailed'
    }
    It 'a legacy _Bucket name runs the shipped template when it is not defined' {
        Resolve-RALegacyTemplateName -Requested 'RiskAnalysis_Detailed_Bucket' -Available $script:Shipped | Should -Be 'RiskAnalysis_Detailed'
        Resolve-RALegacyTemplateName -Requested 'RiskAnalysis_Summary_Bucket'  -Available $script:Shipped | Should -Be 'RiskAnalysis_Summary'
    }
    It 'a customer who DEFINES a _Bucket template keeps it' {
        Resolve-RALegacyTemplateName -Requested 'RiskAnalysis_Detailed_Bucket' -Available @('RiskAnalysis_Detailed','RiskAnalysis_Detailed_Bucket') | Should -Be 'RiskAnalysis_Detailed_Bucket'
    }
    It 'any other unknown name is left for the engine to reject' {
        Resolve-RALegacyTemplateName -Requested 'Nope' -Available $script:Shipped | Should -Be 'Nope'
    }
    It 'the engine defaults and the Detailed container job name shipped templates' {
        $eng = Get-Content -LiteralPath $script:Engine -Raw
        $eng | Should -Not -Match "else \{ 'RiskAnalysis_(Summary|Detailed)_Bucket' \}"
        $eng | Should -Match '(?s)Resolve-RALegacyTemplateName -Requested.{0,1200}not found in YAML under ReportTemplates'
        # The Detailed job's template now comes from the job plan (the customer's RiskAnalysis_ReportTemplate_Default_Detailed,
        # else the shipped default) -- both defaults must be templates the shipped catalog defines.
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $plan = Get-SIRiskAnalysisJobPlan -Engines @('risk-analysis', 'risk-analysis-detailed')
        foreach ($j in $plan.Jobs) { $script:Shipped | Should -Contain $j.Template }
        $boot = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1') -Raw
        $boot -match "raTemplateForJob\s*=\s*if \(\`$raJob\) \{ \`$raJob\.Template \} elseif \(\`$isRiskAnalysisDetailed\) \{ '([^']+)' \}" | Should -BeTrue
        $script:Shipped | Should -Contain $Matches[1]
    }
}

Describe 'KEDA shards: one worker at a time, and a poison shard is parked, not lost' {
    BeforeEach {
        $script:ctx = New-SIStorageContext -Mock
        Initialize-SIQueue -Context $script:ctx -QueueName 'si-endpoint-shards' | Out-Null
        Add-SIWorkItem -Context $script:ctx -QueueName 'si-endpoint-shards' -Payload @{ ShardIndex = 2; ShardCount = 8; CollectionTime = '2026-09-28T04:00:00Z' }
    }
    It 'a dequeued item carries its dequeue count and original text' {
        $m = Get-SINextWorkItem -Context $script:ctx -QueueName 'si-endpoint-shards'
        $m.DequeueCount | Should -Be 1
        ($m.RawText | ConvertFrom-Json).ShardIndex | Should -Be 2
    }
    It 'a poison item is written to the queue''s -poison twin with its original text, then removed' {
        $m = Get-SINextWorkItem -Context $script:ctx -QueueName 'si-endpoint-shards'
        $p = Move-SIWorkItemToPoison -Context $script:ctx -QueueName 'si-endpoint-shards' -WorkItem $m -Reason 'test'
        $p | Should -Be 'si-endpoint-shards-poison'
        $parked = Get-SINextWorkItem -Context $script:ctx -QueueName $p
        ($parked.Payload.OriginalText | ConvertFrom-Json).ShardIndex | Should -Be 2
        $parked.Payload.OriginalQueue | Should -Be 'si-endpoint-shards'
    }
    It 'if parking fails, the original is NOT deleted' {
        $m = Get-SINextWorkItem -Context $script:ctx -QueueName 'si-endpoint-shards'
        Mock Add-SIWorkItem { throw 'storage unavailable' }
        Mock Complete-SIWorkItem { }
        { Move-SIWorkItemToPoison -Context $script:ctx -QueueName 'si-endpoint-shards' -WorkItem $m } | Should -Throw
        Should -Invoke Complete-SIWorkItem -Times 0 -Exactly
    }
    It 'the lease on a part is SHORT and renewed by the worker (2026-10-13; it used to outlive the worker''s run limit); the long lease from setup is only the fallback without a heartbeat' {
        $def = [int](((Lift (Join-Path $script:SIRoot 'engine\asset-profiling\storage\WorkerQueue.ps1') 'Get-SINextWorkItem') -split "`n" |
                       Where-Object { $_ -match '\$VisibilityTimeoutSeconds\s*=\s*(\d+)' } | Select-Object -First 1) -replace '.*=\s*(\d+).*','$1')
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $def | Should -Be 600 -Because 'a worker that dies gives its part back within 10 minutes (the heartbeat tests: SIv3-PartLease)'
        $def | Should -BeLessThan ([int](Get-SIContainerJobResources -Engine 'endpoint' -Kind Keda).ReplicaTimeout)
        $boot = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1') -Raw
        $keda = [regex]::Match($boot, "(?s)effectiveUseKEDA\) \{.*?\} elseif \(\`$isRiskAnalysis\)").Value
        # #519: the worker and its lease are defined once (SI-ContainerConfig.ps1); Bootstrap passes the job's replica timeout
        $keda | Should -Match ([regex]::Escape('-ReplicaTimeout $jobRes.ReplicaTimeout'))
        $boot | Should -Match ([regex]::Escape('if ($effectiveUseKEDA) { $envArgs += @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout $jobRes.ReplicaTimeout) }'))
        @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 3600).Count | Should -Be 0
        @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 14400) | Should -Be @('SI_QUEUE_LEASE_SECONDS=14700')
        $w = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-endpoint-worker' -ResourceGroup 'rg' -Environment 'cae' -Image 'img' -LoginServer 'acr.io' -ReplicaTimeout 14400 -Cpu '2.0' -Memory '4Gi' -Engine 'endpoint' -StorageAccount 'st' -IdentityResourceId '/uami')
        $w[($w.IndexOf('--replica-timeout') + 1)] | Should -Be '14400'
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1') -Raw
        $src | Should -Match "SI_QUEUE_LEASE_SECONDS' 3900"
        $src | Should -Not -Match 'VisibilityTimeoutSeconds 1800'
    }
    It 'WIRING -- the worker parks an over-retried shard BEFORE running the orchestrator' {
        $src  = Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1') -Raw
        $park = $src.IndexOf('Move-SIWorkItemToPoison')
        $run  = $src.IndexOf('& $orchestrator @orchArgs')
        $park | Should -BeGreaterThan 0
        $park | Should -BeLessThan $run
        $src  | Should -Match '\$msg\.DequeueCount -gt \$maxDequeue'
    }
}
