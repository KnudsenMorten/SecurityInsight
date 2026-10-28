#Requires -Version 5.1
<#
    SecurityInsight -- EXISTING INSTALLS GET THE RISK ANALYSIS WORKER JOB (#742; rule: existing installs reach new-install
    state). A new install's Detailed Risk Analysis job is the PRODUCER of a queue-scaled worker job, caj-si-raworker-detailed
    (Bootstrap-ContainerAppJob.ps1, step 4c): the producer plans one work item per report, the workers run them in parallel
    (engine/risk-analysis/_shared/RA-ScaleOut.ps1). Every update (setup\Invoke-SIContainerUpdate.ps1, the updater job and the
    VM sync hook both run it) gives an install made before it the same jobs, built by the same definitions Bootstrap uses
    (Get-SIKedaWorkerCreateArgs with the work queue, Get-SIRaWorkerEnvArgs, Get-SIRaProducerScaleOutEnvArgs in
    container\_shared\SI-ContainerConfig.ps1):

      * ON BY DEFAULT WHERE THEY CAN RUN (owner 2026-10-18: "pls dont turn off things that improve time, why do that"; they
        were off by default for one day as a review-gap closure). Not set = on (Get-SIRaScaleOutOptIn). The customer's
        SI_Bootstrap_RaScaleOut = $false (or SI_UPDATER_RA_SCALE_OUT = off on the updater job; the config wins) switches
        them off: no job is created, no role granted; a Risk Analysis job that was told it is a producer is told it is not
        any more (its two switches removed, read back -- 'unflag'), so it runs its reports itself; the idle worker job is
        left in place (setup with $false removes it). Where they cannot run, nothing changes and one line says why.
      * WHEN (Get-SIRaWorkerJobPlan, PURE): not switched off, the Detailed Risk Analysis job exists, SI's setup made it (si-build
        tag), it signs in with the managed identity (or the certificate, which also carries the identity) -- the queue
        scaler signs in with it -- and the install has not switched queue scaling off (SI_Bootstrap_UseKEDA /
        SI_UPDATER_USE_KEDA). Queue scaling off = an existing worker job is left in place and its producer runs its reports
        itself (one line says so).
      * HOW (Invoke-SIRaWorkerJobs): from the Risk Analysis job itself -- its image, environment, secrets, identity,
        registry and size: (1) the queue scaler's storage queue role for the identity (present, or granted; missing =
        nothing changes); (2) the work queue (the producer also makes it); (3) the worker (event-triggered, the queue rule,
        up to SI_Bootstrap_RaMaxWorkers at once, default 4), READ BACK; (4) only then the Risk Analysis job is told it is a
        producer (SI_RA_SCALE_OUT=on, SI_RA_WORKER_JOB) -- one read-modify-write PATCH of its container's environment, read
        back. A worker job with no producer flag is the state a failed step 4 leaves: the next update sets the flag.
      * Any failure: a worker this run created is removed again, the Risk Analysis job runs on as before, one line says
        why, and the next update tries again. Never throws; -WhatIf: the plan only, no Azure call at all.

    NO az CLI, no PowerShell module: ONE seam, -Rest { param([string]$Method, [string]$Uri, $Body, [string]$Resource,
    [hashtable]$Headers) } -> @{ Status; Body } (the same as setup\_shared\SI-KedaConvert.ps1).
#>

$script:SIRaWorkerJobsLibRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command ConvertFrom-SIJobCreateArgs -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRaWorkerJobsLibRoot, 'setup', '_shared', 'SI-KedaConvert.ps1')) }
if (-not (Get-Command Get-SIRaWorkerEnvArgs -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIRaWorkerJobsLibRoot, 'container', '_shared', 'SI-ContainerConfig.ps1')) }

$script:SIRaWorkerJobsArmApi = '2025-07-01'

function Get-SIRaWorkerJobPlan {
    <#
        PURE. Per grain with workers (Detailed): create | flag (the worker exists, its producer is not told yet) | present |
        keep (Reason says why) | none (no Risk Analysis job of that grain) | off (the customer switched the workers off, and
        no Risk Analysis job is told it is a producer) | unflag (switched off, and the Risk Analysis job SI's setup made is
        still told it is a producer). -Jobs: the job list (ARM shape). -UpdaterRaScaleOut: SI_UPDATER_RA_SCALE_OUT of the
        updater job. Returns @(@{ Grain; Engine; Producer; Worker; Action; Reason; AuthMode; Identity; StorageAccount }).
    #>
    param([object[]]$Jobs = @(), [hashtable]$Globals = @{}, [string]$UpdaterUseKeda, [string]$UpdaterRaScaleOut)
    $optIn = Get-SIRaScaleOutOptIn -Globals $Globals -UpdaterValue $UpdaterRaScaleOut
    $byName = @{}
    foreach ($j in @($Jobs)) { if ($j) { $n = [string](Get-SIKedaConvertProp $j @('name')); if ($n) { $byName[$n.ToLowerInvariant()] = $j } } }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($engine in @('risk-analysis-detailed')) {
        $grain = Get-SIRaScaleOutGrain -Engine $engine
        $pName = Get-SIBootstrapJobName -Engine $engine
        $wName = Get-SIRaWorkerJobName -Grain $grain
        $row = [ordered]@{ Grain = $grain; Engine = $engine; Producer = $pName; Worker = $wName; Action = 'keep'; Reason = ''; AuthMode = ''; Identity = $null; StorageAccount = '' }
        $p = $byName[$pName]
        $env = @()
        if ($p) { $env = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $p @('properties', 'template', 'containers') | Select-Object -First 1 | ForEach-Object { Get-SIKedaConvertProp $_ @('env') })) }
        $flagged = ((Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_SCALE_OUT') -match '^(?i)(1|true|on|yes)$') -and ((Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_WORKER_JOB') -eq $wName)
        # #831: a producer made before it knew the worker count (or with another) is told it again
        $flagged = $flagged -and ([string](Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_WORKERS') -eq [string](Get-SIRaWorkerMaxExecutions -Globals $Globals))
        if (-not $optIn.On) {
            # the customer's choice: the workers are off. A producer SI's setup made is told it is not one any more.
            $row.Action = 'off'
            $row.Reason = 'the Risk Analysis workers are switched off for this install (SI_Bootstrap_RaScaleOut = $false) -- the Risk Analysis reports run in their job'
            if ($p -and ((Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_SCALE_OUT') -or (Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_WORKER_JOB'))) {
                if (Test-SIBootstrapJobIsSI -Job $p) { $row.Action = 'unflag'; $row.Reason = 'the Risk Analysis workers are switched off for this install (SI_Bootstrap_RaScaleOut = $false), and the Risk Analysis job still hands its reports to them' }
                else { $row.Reason = 'the Risk Analysis workers are switched off for this install, but SecurityInsight''s setup did not create the Risk Analysis job (no si-build tag), so the update does not change it' }
            }
            $rows.Add([pscustomobject]$row); continue
        }
        if (-not $p) { $row.Action = 'none'; $row.Reason = 'no Detailed Risk Analysis job'; $rows.Add([pscustomobject]$row); continue }
        $ident = Get-SIKedaConvertJobIdentity -Job $p -ClientId (Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_UAMI_CLIENTID')
        $authEnv = @{}; foreach ($a in $env) { $kv = ([string]$a) -split '=', 2; if ($kv.Count -eq 2) { $authEnv[$kv[0]] = $kv[1] } }
        if ($ident) { $authEnv['IDENTITY_ENDPOINT'] = 'assigned' }
        $auth = Resolve-SIContainerAuthMode -Environment $authEnv
        $row.AuthMode = $auth.Mode; $row.Identity = $ident
        $row.StorageAccount = Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_STORAGE_ACCOUNT'
        if (-not $row.StorageAccount -and $Globals.ContainsKey('SI_StorageAccount')) { $row.StorageAccount = "$($Globals['SI_StorageAccount'])".Trim() }
        $hasWorker = $byName.ContainsKey($wName)
        $kedaCfg = Resolve-SIKedaConvertOptOut -Globals $Globals -UpdaterValue $UpdaterUseKeda
        $kedaOff = ($null -ne $kedaCfg -and -not ("$kedaCfg".Trim() -match '^(?i)(1|true|on|yes)$'))
        if ($kedaOff) { $row.Reason = 'queue scaling is switched off for this install (SI_Bootstrap_UseKEDA = $false) -- the Risk Analysis reports run in their job' }
        elseif ($auth.Mode -eq 'Secret' -or $auth.Mode -eq 'None') { $row.Reason = 'its job signs in with a client secret, and the queue scaler needs the jobs'' managed identity -- the update never changes how the jobs sign in' }
        elseif (-not $ident) { $row.Reason = 'the job''s managed identity could not be told apart (none, or more than one, assigned)' }
        elseif (-not (Test-SIBootstrapJobIsSI -Job $p)) { $row.Reason = 'SecurityInsight''s setup did not create the Risk Analysis job (no si-build tag), so the update does not change it' }
        elseif (-not $row.StorageAccount) { $row.Reason = 'the storage account that holds the work queue is not known (SI_STORAGE_ACCOUNT on the job)' }
        elseif (-not [string](Get-SIKedaConvertProp $p @('properties', 'environmentId'))) { $row.Reason = 'the job''s Container Apps environment could not be read' }
        elseif ($hasWorker -and $flagged) { $row.Action = 'present'; $row.Reason = 'already runs its reports on queue workers' }
        elseif ($hasWorker) { $row.Action = 'flag'; $row.Reason = 'the worker job exists; the Risk Analysis job is not told yet' }
        else { $row.Action = 'create'; $row.Reason = 'runs its reports one after another in one job' }
        $rows.Add([pscustomobject]$row)
    }
    $rows.ToArray()
}

function Get-SIRaWorkerJobSpec {
    <#
        PURE. The worker job from its producer (the Risk Analysis job): Bootstrap's definition (Get-SIKedaWorkerCreateArgs on the
        grain's work queue) with the producer's image, registry, identity, size, environment (Get-SIRaWorkerEnvArgs) and
        secrets, translated to the ARM resource. -SecretArgs: name=value / name=keyvaultref:... of every secret the producer
        carries (the registry password excluded -- -RegistryPassword). Returns @{ Name; Args; Body; Image; QueueName }.
    #>
    param([Parameter(Mandatory)]$Producer, [Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$SecretArgs = @(), [string]$RegistryPassword, [int]$MaxExecutions = 4)
    $c = @(Get-SIKedaConvertProp $Producer @('properties', 'template', 'containers'))[0]
    $image = [string](Get-SIKedaConvertProp $c @('image'))
    $env = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $c @('env')))
    $cfg = Get-SIKedaConvertProp $Producer @('properties', 'configuration')
    $timeout = [int](Get-SIKedaConvertProp $cfg @('replicaTimeout')); if ($timeout -le 0) { $timeout = [int](Get-SIJobRunLimit) }
    $cpuRaw = Get-SIKedaConvertProp $c @('resources', 'cpu')
    $cpu = if ($null -ne $cpuRaw -and "$cpuRaw".Trim()) { ([double]$cpuRaw).ToString([Globalization.CultureInfo]::InvariantCulture) } else { '4.0' }
    $mem = [string](Get-SIKedaConvertProp $c @('resources', 'memory')); if (-not $mem) { $mem = '8Gi' }
    $reg = @(Get-SIKedaConvertProp $cfg @('registries') | Where-Object { $_ })[0]
    $login = [string](Get-SIKedaConvertProp $reg @('server')); if (-not $login) { $login = ($image -split '/')[0] }
    $regArgs = @()
    $regIdentity = [string](Get-SIKedaConvertProp $reg @('identity')); $regUser = [string](Get-SIKedaConvertProp $reg @('username'))
    if ($regIdentity) { $regArgs = @(Get-SIRegistryPullArgs -Mode 'ManagedIdentity' -IdentityResourceId $regIdentity) }
    elseif ($regUser -and $RegistryPassword) { $regArgs = @('--registry-username', $regUser, '--registry-password', $RegistryPassword) }
    $build = [string](Get-SIKedaConvertProp $Producer @('tags', 'si-build'))
    $envId = [string](Get-SIKedaConvertProp $Producer @('properties', 'environmentId'))
    $location = [string](Get-SIKedaConvertProp $Producer @('location'))
    $queue = Get-SIRaScaleOutQueueName -Grain $Plan.Grain
    $a = @(Get-SIKedaWorkerCreateArgs -Name $Plan.Worker -ResourceGroup $ResourceGroup -Environment $envId -Image $image -LoginServer $login -ReplicaTimeout $timeout `
            -Cpu $cpu -Memory $mem -MaxExecutions $MaxExecutions -Engine $Plan.Engine -StorageAccount $Plan.StorageAccount -IdentityResourceId ([string]$Plan.Identity.ResourceId) -QueueName $queue)
    if ($build) { $a += @('--tags', "si-build=$build") }
    $a += $regArgs
    $a += @('--mi-user-assigned', [string]$Plan.Identity.ResourceId)
    if (@($SecretArgs).Count) { $a += @('--secrets') + @($SecretArgs) }
    $a += @('--env-vars') + @(Get-SIRaWorkerEnvArgs -EnvArgs $env -ReplicaTimeout $timeout -Workers $MaxExecutions)
    [pscustomobject]@{ Name = $Plan.Worker; Args = $a; Body = (ConvertFrom-SIJobCreateArgs -CreateArgs $a -Location $location).Body; Image = $image; QueueName = $queue }
}

function Get-SIRaProducerFlagPatch {
    <#
        PURE. The PATCH that tells the Risk Analysis job it is the producer: its template as it is, with SI_RA_SCALE_OUT=on and
        SI_RA_WORKER_JOB=<worker> set in its first container's environment (replaced when there, added when not); nothing
        else changes. Returns @{ Body; Changed }.
    #>
    # -Workers (#831): SI_RA_WORKERS, the same count the workers get (Get-SIRaWorkerMaxExecutions)
    param([Parameter(Mandatory)]$Producer, [Parameter(Mandatory)][string]$Grain, [int]$Workers = 0)
    $t = Get-SIKedaConvertProp $Producer @('properties', 'template')
    $tpl = ConvertTo-Json -InputObject $t -Depth 30 | ConvertFrom-Json
    $c0 = @($tpl.containers)[0]
    $want = [ordered]@{}; foreach ($e in @(Get-SIRaProducerScaleOutEnvArgs -Grain $Grain -Workers $Workers)) { $kv = ([string]$e) -split '=', 2; $want[$kv[0]] = $kv[1] }
    $list = New-Object System.Collections.Generic.List[object]
    $changed = $false
    foreach ($e in @($c0.env)) {
        if ($null -eq $e) { continue }
        $n = [string]$e.name
        if ($want.Contains($n)) { if ([string]$e.value -ne [string]$want[$n] -or $e.PSObject.Properties['secretRef']) { $changed = $true }; $list.Add([ordered]@{ name = $n; value = [string]$want[$n] }); $want.Remove($n); continue }
        $list.Add($e)
    }
    foreach ($k in @($want.Keys)) { $list.Add([ordered]@{ name = $k; value = [string]$want[$k] }); $changed = $true }
    $c0 | Add-Member -NotePropertyName env -NotePropertyValue $list.ToArray() -Force
    [pscustomobject]@{ Body = [ordered]@{ properties = [ordered]@{ template = $tpl } }; Changed = $changed }
}

function Get-SIRaProducerUnflagPatch {
    <#
        PURE. The PATCH that tells the Risk Analysis job it is NOT a producer any more (the customer switched the workers
        off): its template as it is, without SI_RA_SCALE_OUT and SI_RA_WORKER_JOB in its first container's environment;
        nothing else changes. Returns @{ Body; Changed }.
    #>
    param([Parameter(Mandatory)]$Producer)
    $t = Get-SIKedaConvertProp $Producer @('properties', 'template')
    $tpl = ConvertTo-Json -InputObject $t -Depth 30 | ConvertFrom-Json
    $c0 = @($tpl.containers)[0]
    $list = New-Object System.Collections.Generic.List[object]
    $changed = $false
    foreach ($e in @($c0.env)) {
        if ($null -eq $e) { continue }
        if ([string]$e.name -in @('SI_RA_SCALE_OUT', 'SI_RA_WORKER_JOB', 'SI_RA_WORKERS')) { $changed = $true; continue }
        $list.Add($e)
    }
    $c0 | Add-Member -NotePropertyName env -NotePropertyValue $list.ToArray() -Force
    [pscustomobject]@{ Body = [ordered]@{ properties = [ordered]@{ template = $tpl } }; Changed = $changed }
}

function Test-SIRaWorkerReadBack {
    <# PURE. The worker as Azure returned it: created, event-triggered with the queue rule on the work queue, on the image,
       role worker. Returns '' (good) or what is wrong. #>
    param($Worker, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$QueueName)
    if (-not $Worker) { return 'the worker could not be read back' }
    $ps = [string](Get-SIKedaConvertProp $Worker @('properties', 'provisioningState'))
    if ($ps -and $ps -ne 'Succeeded') { return ('the worker was not created (provisioning {0})' -f $ps) }
    if ([string](Get-SIKedaConvertProp $Worker @('properties', 'configuration', 'triggerType')) -ne 'Event') { return 'the worker is not event-triggered' }
    $rule = @(Get-SIKedaConvertProp $Worker @('properties', 'configuration', 'eventTriggerConfig', 'scale', 'rules') | Where-Object { $_ })[0]
    if (-not $rule) { return 'the worker has no queue scale rule' }
    $q = [string](Get-SIKedaConvertProp $rule @('metadata', 'queueName'))
    if ($q -ne $QueueName) { return ('the worker''s scale rule reads {0}, not {1}' -f $q, $QueueName) }
    $c = @(Get-SIKedaConvertProp $Worker @('properties', 'template', 'containers'))[0]
    if ([string](Get-SIKedaConvertProp $c @('image')) -ne $Image) { return ('the worker runs {0}, not {1}' -f [string](Get-SIKedaConvertProp $c @('image')), $Image) }
    $env = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $c @('env')))
    if ((Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_RA_SCALEOUT_ROLE') -ne 'worker') { return 'the worker does not run as a Risk Analysis worker (SI_RA_SCALEOUT_ROLE)' }
    ''
}

function Invoke-SIRaWorkerJobs {
    <#
        EXISTING INSTALLS: give the Detailed Risk Analysis job its queue-scaled worker job (the plan: Get-SIRaWorkerJobPlan).
        -Rest: the REST seam (ARM https://management.azure.com/, the queue data plane https://storage.azure.com/). -WhatIf:
        the plan only. Returns @{ Results = @(@{ Grain; Action = off | unflagged | would-unflag | created | flagged |
        would-create | would-flag | present | keep | none | failed; Line }); Lines }. NEVER throws. Off (switched off by the
        customer, no producer to undo) = not one call of -Rest.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [string]$UpdaterUseKeda, [string]$UpdaterRaScaleOut, [switch]$WhatIf, [int]$PollSeconds = 5, [int]$PollMax = 36)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $add = { param($r, $a, $l) $results.Add([pscustomobject]@{ Grain = $r.Grain; Worker = $r.Worker; Action = $a; Line = $l }); if ($l) { $lines.Add($l) } }
    try {
        $plan = @(Get-SIRaWorkerJobPlan -Jobs $Jobs -Globals $Globals -UpdaterUseKeda $UpdaterUseKeda -UpdaterRaScaleOut $UpdaterRaScaleOut)
        $arm = 'https://management.azure.com/'; $stor = 'https://storage.azure.com/'
        $api = $script:SIRaWorkerJobsArmApi
        $call = {
            param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $r = $null
            try { $r = & $Rest $Method $Uri $Body $Resource $Headers } catch { $r = [pscustomobject]@{ Status = 0; Body = $_.Exception.Message } }
            if (-not $r) { $r = [pscustomobject]@{ Status = 0; Body = 'no answer' } }
            $r
        }
        $isOk = { param($r) $r -and [int]$r.Status -ge 200 -and [int]$r.Status -lt 300 }
        $parse = { param($r) if (-not $r -or -not "$($r.Body)".Trim()) { return $null }; $o = $null; try { $o = ("$($r.Body)" | ConvertFrom-Json) } catch { $o = $null }; return $o }
        $why = { param($r) $t = ("$(if ($r) { $r.Body })" -replace '\s+', ' ').Trim(); if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; ('HTTP {0}{1}' -f $(if ($r) { [int]$r.Status } else { 0 }), $(if ($t) { ": $t" } else { '' })) }
        $jobUri = { param($n, [string]$Action) 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}{3}?api-version={4}' -f $SubscriptionId, $ResourceGroup, $n, $Action, $api }
        $toJson = { param($o) ConvertTo-Json -InputObject $o -Depth 30 -Compress }
        $readBack = {
            param([string]$n)
            $j = $null
            for ($k = 1; $k -le [Math]::Max(1, $PollMax); $k++) {
                $r = & $call 'GET' (& $jobUri $n) $null $arm $null
                if (-not (& $isOk $r)) { return $null }
                $j = & $parse $r
                $ps = [string](Get-SIKedaConvertProp $j @('properties', 'provisioningState'))
                if (-not $ps -or $ps -in @('Succeeded', 'Failed', 'Canceled')) { return $j }
                if ($k -lt $PollMax -and $PollSeconds -gt 0) { Start-Sleep -Seconds $PollSeconds }
            }
            $j
        }
        $byName = @{}; foreach ($j in @($Jobs)) { if ($j) { $byName[([string](Get-SIKedaConvertProp $j @('name'))).ToLowerInvariant()] = $j } }
        $max = Get-SIRaWorkerMaxExecutions -Globals $Globals
        # the producer is told it is one: its environment, read-modify-write, read back
        $flag = {
            param($row, $prod)
            $fp = Get-SIRaProducerFlagPatch -Producer $prod -Grain $row.Grain -Workers $max
            if ($fp.Changed) {
                $r = & $call 'PATCH' (& $jobUri $row.Producer) (& $toJson $fp.Body) $arm @{ 'Content-Type' = 'application/json' }
                if (-not (& $isOk $r)) { return ('the Risk Analysis job could not be told it is the producer ({0})' -f (& $why $r)) }
            }
            $pb = & $readBack $row.Producer
            $penv = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $pb @('properties', 'template', 'containers') | Select-Object -First 1 | ForEach-Object { Get-SIKedaConvertProp $_ @('env') }))
            if ((Get-SIKedaConvertEnvValue -EnvArgs $penv -Name 'SI_RA_SCALE_OUT') -ne 'on' -or (Get-SIKedaConvertEnvValue -EnvArgs $penv -Name 'SI_RA_WORKER_JOB') -ne $row.Worker) { return 'the Risk Analysis job did not read back as the producer' }
            # #831: the producer plans the parts of a big report for the real worker count
            if ([string](Get-SIKedaConvertEnvValue -EnvArgs $penv -Name 'SI_RA_WORKERS') -ne [string]$max) { return ('the Risk Analysis job did not read back with the worker count (SI_RA_WORKERS={0})' -f $max) }
            ''
        }
        foreach ($row in $plan) {
            if ($row.Action -eq 'off') { & $add $row 'off' ('risk analysis workers: {0}' -f $row.Reason); continue }
            if ($row.Action -eq 'unflag') {
                # the customer's off: the Risk Analysis job runs its reports itself again -- read-modify-write, read back
                if ($WhatIf) { & $add $row 'would-unflag' ('risk analysis workers: {0} would run its reports itself again -- the workers are switched off (re-run with -Apply)' -f $row.Producer); continue }
                $prod = $byName[$row.Producer.ToLowerInvariant()]
                $up = Get-SIRaProducerUnflagPatch -Producer $prod
                $bad = ''
                $r = & $call 'PATCH' (& $jobUri $row.Producer) (& $toJson $up.Body) $arm @{ 'Content-Type' = 'application/json' }
                if (-not (& $isOk $r)) { $bad = ('it could not be changed ({0})' -f (& $why $r)) }
                else {
                    $pb = & $readBack $row.Producer
                    $penv = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $pb @('properties', 'template', 'containers') | Select-Object -First 1 | ForEach-Object { Get-SIKedaConvertProp $_ @('env') }))
                    if (-not $pb) { $bad = 'it could not be read back' }
                    elseif ((Get-SIKedaConvertEnvValue -EnvArgs $penv -Name 'SI_RA_SCALE_OUT') -or (Get-SIKedaConvertEnvValue -EnvArgs $penv -Name 'SI_RA_WORKER_JOB')) { $bad = 'it still read back as the producer' }
                }
                if ($bad) { & $add $row 'failed' ('risk analysis workers: switched off, but {0} was NOT told to run its reports itself ({2}) -- it still hands them to {1}; the next update tries again' -f $row.Producer, $row.Worker, $bad) }
                else { & $add $row 'unflagged' ('risk analysis workers: switched off -- {0} runs its reports itself again (read back); {1} stays idle' -f $row.Producer, $row.Worker) }
                continue
            }
            if ($row.Action -eq 'none') { & $add $row 'none' ''; continue }
            if ($row.Action -eq 'present') { & $add $row 'present' ''; continue }
            if ($row.Action -eq 'keep') { & $add $row 'keep' ('risk analysis workers: {0} runs its reports in its own job -- {1}' -f $row.Producer, $row.Reason); continue }
            $prod = $byName[$row.Producer.ToLowerInvariant()]
            if ($WhatIf) {
                if ($row.Action -eq 'flag') { & $add $row 'would-flag' ('risk analysis workers: {0} would be told to hand its reports to {1} (re-run with -Apply)' -f $row.Producer, $row.Worker) }
                else { & $add $row 'would-create' ('risk analysis workers: {0} would get queue-scaled workers ({1}, up to {2} at once) and hand its reports to them (re-run with -Apply)' -f $row.Producer, $row.Worker, $max) }
                continue
            }
            if ($row.Action -eq 'flag') {
                $bad = & $flag $row $prod
                if ($bad) { & $add $row 'failed' ('risk analysis workers: {0} was NOT told to hand its reports to {1} ({2}) -- it runs them itself; the next update tries again' -f $row.Producer, $row.Worker, $bad) }
                else { & $add $row 'flagged' ('risk analysis workers: {0} now hands its reports to {1}' -f $row.Producer, $row.Worker) }
                continue
            }
            $created = $false
            $fail = {
                param([string]$Reason)
                if ($created) { $null = & $call 'DELETE' (& $jobUri $row.Worker) $null $arm $null }
                & $add $row 'failed' ('risk analysis workers: {0} was NOT given its workers ({1}) -- it runs its reports itself, as before; the next update tries again' -f $row.Producer, $Reason)
            }
            try {
                # (1) the storage account, and the queue scaler's role on it for the jobs' identity
                $acct = $row.StorageAccount.ToLowerInvariant(); $stgId = ''; $last = ''
                foreach ($rgName in @($ResourceGroup, $(if ($Globals.ContainsKey('SI_StorageResourceGroup')) { "$($Globals['SI_StorageResourceGroup'])".Trim() }) | Where-Object { $_ } | Select-Object -Unique)) {
                    if ($stgId) { break }
                    $r = & $call 'GET' ('https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}?api-version=2023-05-01' -f $SubscriptionId, $rgName, $acct) $null $arm $null
                    if (& $isOk $r) { $stgId = [string](Get-SIKedaConvertProp (& $parse $r) @('id')) } else { $last = (& $why $r) }
                }
                if (-not $stgId) { & $fail ('the storage account {0} could not be read{1}' -f $row.StorageAccount, $(if ($last) { ' -- Azure answered ' + $last } else { '' })); continue }
                $principal = [string]$row.Identity.PrincipalId
                if (-not $principal) { & $fail 'the managed identity''s object id could not be read'; continue }
                $roleOk = $false; $grantWhy = ''
                $flt = [uri]::EscapeDataString(("principalId eq '{0}'" -f $principal))
                $r = & $call 'GET' ('https://management.azure.com{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}&api-version=2022-04-01' -f $stgId, $flt) $null $arm $null
                if (& $isOk $r) {
                    $ids = @(@(Get-SIKedaConvertProp (& $parse $r) @('value')) | Where-Object { $_ } | ForEach-Object { ([string](Get-SIKedaConvertProp $_ @('properties', 'roleDefinitionId'))).ToLowerInvariant() })
                    $roleOk = [bool](@($ids | Where-Object { $_.EndsWith('/974c5e8b-45b9-4653-ba55-5f855dd0fb88') -or $_.EndsWith('/19e7f393-937e-4f77-808e-94535e297925') }).Count)
                    if (-not $roleOk) {
                        $body = [ordered]@{ properties = [ordered]@{ roleDefinitionId = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/974c5e8b-45b9-4653-ba55-5f855dd0fb88' -f $SubscriptionId); principalId = $principal; principalType = 'ServicePrincipal' } }
                        $g = & $call 'PUT' ('https://management.azure.com{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version=2022-04-01' -f $stgId, [guid]::NewGuid().ToString()) (& $toJson $body) $arm $null
                        if (& $isOk $g) { $roleOk = $true } else { $grantWhy = ('the jobs'' identity lacks Storage Queue Data Contributor on the storage account and it could not be granted here ({0}) -- grant it once to object id {1} on {2}' -f (& $why $g), $principal, $stgId) }
                    }
                } else { $grantWhy = ('the role assignments on the storage account could not be read ({0})' -f (& $why $r)) }
                if (-not $roleOk) { & $fail $grantWhy; continue }
                # (2) the producer's secrets, with their values (Key Vault references as references)
                $secretArgs = @(); $regPassword = ''
                $reg = @(Get-SIKedaConvertProp $prod @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
                $regPwRef = [string](Get-SIKedaConvertProp $reg @('passwordSecretRef'))
                if (@(Get-SIKedaConvertProp $prod @('properties', 'configuration', 'secrets') | Where-Object { $_ }).Count) {
                    $r = & $call 'POST' (& $jobUri $row.Producer '/listSecrets') $null $arm $null
                    if (-not (& $isOk $r)) { & $fail ('the Risk Analysis job''s secrets could not be read ({0})' -f (& $why $r)); continue }
                    foreach ($s in @(Get-SIKedaConvertProp (& $parse $r) @('value'))) {
                        $sn = [string](Get-SIKedaConvertProp $s @('name')); if (-not $sn) { continue }
                        $kvu = [string](Get-SIKedaConvertProp $s @('keyVaultUrl')); $val = [string](Get-SIKedaConvertProp $s @('value'))
                        if ($sn -eq $regPwRef) { $regPassword = $val; continue }
                        if ($kvu) { $id = [string](Get-SIKedaConvertProp $s @('identity')); $secretArgs += $(if ($id) { '{0}=keyvaultref:{1},identityref:{2}' -f $sn, $kvu, $id } else { '{0}=keyvaultref:{1}' -f $sn, $kvu }) }
                        else { $secretArgs += ('{0}={1}' -f $sn, $val) }
                    }
                }
                if ($regPwRef -and -not $regPassword -and -not [string](Get-SIKedaConvertProp $reg @('identity'))) { & $fail 'the registry password of the Risk Analysis job could not be read'; continue }
                $spec = Get-SIRaWorkerJobSpec -Producer $prod -Plan $row -ResourceGroup $ResourceGroup -SecretArgs $secretArgs -RegistryPassword $regPassword -MaxExecutions $max
                # (3) the work queue (the producer creates it on its first run as well)
                $r = & $call 'PUT' ('https://{0}.queue.core.windows.net/{1}' -f $acct, $spec.QueueName) $null $stor @{ 'x-ms-version' = '2021-08-06' }
                if (-not ((& $isOk $r) -or [int]$r.Status -eq 409)) { $lines.Add(('risk analysis workers: the queue {0} could not be created from here ({1}) -- the producer creates it on its first run' -f $spec.QueueName, (& $why $r))) }
                # (4) the worker -- idle until the producer queues reports, so creating it starts nothing
                $r = & $call 'GET' (& $jobUri $spec.Name) $null $arm $null
                if (& $isOk $r) { & $add $row 'present' ('risk analysis workers: {0} exists now (made meanwhile) -- the next update tells the Risk Analysis job' -f $spec.Name); continue }
                $r = & $call 'PUT' (& $jobUri $spec.Name) (& $toJson $spec.Body) $arm @{ 'Content-Type' = 'application/json' }
                if (-not (& $isOk $r)) { & $fail ('Azure refused the worker: {0}' -f (& $why $r)); continue }
                $created = $true
                $bad = Test-SIRaWorkerReadBack -Worker (& $readBack $spec.Name) -Image $spec.Image -QueueName $spec.QueueName
                if ($bad) { & $fail ('read back: {0}' -f $bad); continue }
                # (5) only now the producer is told -- a worker without its producer's flag is idle, never two layouts at once
                $bad = & $flag $row $prod
                if ($bad) { & $add $row 'failed' ('risk analysis workers: {0} was created, but {1} was NOT told to hand its reports to it ({2}) -- it runs them itself; the next update tells it' -f $spec.Name, $row.Producer, $bad); continue }
                & $add $row 'created' ('risk analysis workers: {0} now hands its reports to up to {1} queue-scaled workers ({2}) -- created, read back' -f $row.Producer, $max, $spec.Name)
            } catch { & $fail $_.Exception.Message }
        }
        if (-not @($results | Where-Object { $_.Line }).Count) { $lines.Add('risk analysis workers: nothing to do') }
    } catch {
        $lines.Add(('risk analysis workers: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}
