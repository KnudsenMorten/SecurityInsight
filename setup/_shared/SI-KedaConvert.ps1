#Requires -Version 5.1
<#
    SecurityInsight -- EXISTING INSTALLS MOVE TO QUEUE SCALING ON UPDATE (#519, measured 2026-10-09: an install made before
    queue scaling (f7faf3a8f, 2026-10-08) kept one scheduled caj-si-identity job, and its ~28,000-object identity collection
    ran ~2 h in one container. New installs get a producer + queue-scaled workers; the updater never moved the old ones).

    Every update (setup\Invoke-SIContainerUpdate.ps1, the updater job and the VM sync hook both run it) checks the engines
    that discover into parts (identity, endpoint, azure -- Test-SIKedaPartsEngine) and moves one that still runs as ONE
    scheduled job to what setup gives a new install -- the SAME jobs, built by the same definitions Bootstrap uses
    (Get-SIKedaWorkerCreateArgs / Get-SIKedaProducerCreateArgs / Get-SIKedaProducerEnvArgs / Get-SIKedaQueueScaleArgs in
    container\_shared\SI-ContainerConfig.ps1):

      * WHEN (Get-SIKedaConvertPlan, PURE): caj-si-<engine> exists, no caj-si-<engine>-producer / -worker exists, SI's
        setup created it (its si-build tag -- Test-SIBootstrapJobIsSI), it signs in with the managed identity (or the
        certificate, which also carries the identity) -- the rule of Resolve-SIBootstrapKedaChoice: a client secret stays
        as it is, the updater never changes a sign-in -- and the install has not switched queue scaling off
        (SI_Bootstrap_UseKEDA = $false in the config, or SI_UPDATER_USE_KEDA = false on the updater job).
      * HOW (Invoke-SIKedaConvert): from the old job itself -- its image, environment, secrets, identity, registry, size
        and schedule: (1) the queue scaler's storage queue role for the jobs' identity (present, or granted; missing =
        nothing changes); (2) the shard queue (the producer also makes it, so a refusal here is only noted); (3) the
        worker (event-triggered, the queue scale rule, up to SI_Bootstrap_KedaMaxReplicas at once, the old job's size);
        (4) the producer, created WITHOUT a timer (its cron remembered); (5) both read back; (6) only then the old job is
        switched off (its timer removed and remembered, the job kept) and the producer gets the old cron. A job of the
        daily job flow (no timer of its own) stays that way: the producer joins the flow in its place.
      * NEVER TWO SCHEDULES: the old job loses its timer before the producer gets one. Any failure: the jobs this run
        created are removed again, the old job runs on as before, one line says why, and the next update tries again.
      * Never throws; -WhatIf: the plan only, no Azure call at all.

    NO az CLI, no PowerShell module: every call is ARM or storage data-plane REST through ONE seam,
    -Rest { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body }
    ($Resource = the token audience: https://management.azure.com/ or https://storage.azure.com/). The jobs are built by
    translating Bootstrap's own job definitions (the az arguments) into the ARM resource (ConvertFrom-SIJobCreateArgs, PURE).
#>

$script:SIKedaConvertLibRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command Get-SIKedaWorkerCreateArgs -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIKedaConvertLibRoot, 'container', '_shared', 'SI-ContainerConfig.ps1')) }
if (-not (Get-Command Get-SIRegistryPullArgs -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIKedaConvertLibRoot, 'setup', '_shared', 'SI-ContainerUpdate.ps1')) }
if (-not (Get-Command ConvertTo-SIArmJobTrigger -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIKedaConvertLibRoot, 'engine', '_shared', 'SI-JobFlow.ps1')) }

# the PATCH of a job's trigger reads and writes in the schema the jobs were listed in (SI-FastRoll.ps1, live 2026-10-06)
$script:SIKedaConvertArmApi = '2025-07-01'
$script:SIKedaConvertDefaultMaxReplicas = 30   # Bootstrap's -KedaMaxReplicas default

function Get-SIKedaConvertProp {
    <# PURE. A property of a parsed ARM object, $null when absent (never throws on a missing level). #>
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($p)) { $o = $o[$p] } else { return $null }; continue }
        $pp = $o.PSObject.Properties[$p]; if (-not $pp) { return $null }; $o = $pp.Value
    }
    $o
}

function ConvertTo-SIKedaConvertEnvArgs {
    <# PURE. A job container's env list (ARM: name + value | secretRef) as az's NAME=value / NAME=secretref:<secret>. #>
    param([object[]]$Env = @())
    @(@($Env) | Where-Object { $_ -and "$(Get-SIKedaConvertProp $_ @('name'))".Trim() } | ForEach-Object {
        $n = [string](Get-SIKedaConvertProp $_ @('name')); $sr = [string](Get-SIKedaConvertProp $_ @('secretRef'))
        if ($sr) { '{0}=secretref:{1}' -f $n, $sr } else { '{0}={1}' -f $n, [string](Get-SIKedaConvertProp $_ @('value')) }
    })
}

function Get-SIKedaConvertEnvValue {
    <# PURE. The value of NAME in a NAME=value list ('' when absent). #>
    param([object[]]$EnvArgs = @(), [string]$Name)
    foreach ($e in @($EnvArgs)) { $s = [string]$e; if ($s.StartsWith($Name + '=')) { return $s.Substring($Name.Length + 1) } }
    ''
}

function Get-SIKedaWorkerEnvFromJob {
    <# PURE. The worker's environment from the scheduled job's: the same settings, and the worker's own queue settings
       (SI_TRIGGER_FROM_QUEUE=1, role worker, a shard lease longer than its replica) -- what Bootstrap gives a new worker. #>
    param([object[]]$EnvArgs = @(), [int]$ReplicaTimeout)
    @(@($EnvArgs | Where-Object { [string]$_ -notmatch '^(SI_TRIGGER_FROM_QUEUE|SI_ROLE|SI_QUEUE_LEASE_SECONDS)=' }) +
      @('SI_TRIGGER_FROM_QUEUE=1', 'SI_ROLE=worker') + @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout $ReplicaTimeout))
}

function Get-SIKedaConvertJobIdentity {
    <#
        PURE. The user-assigned identity the job signs in with: the one whose client id is SI_UAMI_CLIENTID, else the only
        one assigned. Returns @{ ResourceId; PrincipalId; ClientId } or $null.
    #>
    param($Job, [string]$ClientId)
    $ua = Get-SIKedaConvertProp $Job @('identity', 'userAssignedIdentities')
    if ($null -eq $ua) { return $null }
    $rows = @()
    if ($ua -is [System.Collections.IDictionary]) { foreach ($k in $ua.Keys) { $rows += [pscustomobject]@{ ResourceId = [string]$k; V = $ua[$k] } } }
    else { foreach ($p in $ua.PSObject.Properties) { $rows += [pscustomobject]@{ ResourceId = $p.Name; V = $p.Value } } }
    $rows = @($rows | ForEach-Object { [pscustomobject]@{ ResourceId = $_.ResourceId; PrincipalId = [string](Get-SIKedaConvertProp $_.V @('principalId')); ClientId = [string](Get-SIKedaConvertProp $_.V @('clientId')) } })
    if ($ClientId) { $m = @($rows | Where-Object { $_.ClientId -eq $ClientId }); if ($m.Count -eq 1) { return $m[0] } }
    if ($rows.Count -eq 1) { return $rows[0] }
    $null
}

function Resolve-SIKedaConvertOptOut {
    <# PURE. Queue scaling switched off for this install: the config's SI_Bootstrap_UseKEDA, else SI_UPDATER_USE_KEDA on
       the updater job. Returns the configured value as Resolve-SIBootstrapKedaChoice reads it ($null = not set). #>
    param([hashtable]$Globals = @{}, [string]$UpdaterValue)
    if ($Globals.ContainsKey('SI_Bootstrap_UseKEDA') -and $null -ne $Globals['SI_Bootstrap_UseKEDA'] -and "$($Globals['SI_Bootstrap_UseKEDA'])".Trim() -ne '') { return $Globals['SI_Bootstrap_UseKEDA'] }
    if ("$UpdaterValue".Trim()) { return "$UpdaterValue".Trim() }
    $null
}

function Get-SIKedaConvertPlan {
    <#
        PURE. What the update does per parts engine, from the job list (ARM shape) and the customer's settings:
          convert -- caj-si-<engine> runs as one job; it moves to producer + workers
          keep    -- it stays as it is (Reason says why, in plain words)
        An engine with no job of its own, or already on producer + worker, gives a 'keda' row (nothing to do).
        Returns @(@{ Engine; Action = convert | keep | keda; Job; Reason; AuthMode; Identity; StorageAccount; Cron; Trigger }).
    #>
    param([object[]]$Jobs = @(), [hashtable]$Globals = @{}, [string]$UpdaterUseKeda)
    $byName = @{}
    foreach ($j in @($Jobs)) { if ($j) { $n = [string](Get-SIKedaConvertProp $j @('name')); if ($n) { $byName[$n.ToLowerInvariant()] = $j } } }
    $configured = Resolve-SIKedaConvertOptOut -Globals $Globals -UpdaterValue $UpdaterUseKeda
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($script:SIKedaPartsEngines)) {
        $plainName = "caj-si-$e"; $plain = $byName[$plainName]
        $hasP = $byName.ContainsKey("caj-si-$e-producer"); $hasW = $byName.ContainsKey("caj-si-$e-worker")
        $row = [ordered]@{ Engine = $e; Action = 'keep'; Job = $plainName; Reason = ''; AuthMode = ''; Identity = $null; StorageAccount = ''; Cron = ''; Trigger = '' }
        if (-not $plain) {
            $row.Action = 'keda'
            $row.Reason = $(if ($hasP -and $hasW) { 'already runs as a producer and queue-scaled workers' } elseif ($hasP -or $hasW) { 'has only half of the producer and worker -- run the container setup again to complete it' } else { 'not installed' })
            $rows.Add([pscustomobject]$row); continue
        }
        if ($hasP -or $hasW) { $row.Reason = 'runs as a scheduled job and has a producer or worker beside it -- left as it is; run the container setup again to settle it'; $rows.Add([pscustomobject]$row); continue }
        $env = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $plain @('properties', 'template', 'containers') | Select-Object -First 1 | ForEach-Object { Get-SIKedaConvertProp $_ @('env') }))
        $ident = Get-SIKedaConvertJobIdentity -Job $plain -ClientId (Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_UAMI_CLIENTID')
        $authEnv = @{}; foreach ($a in $env) { $kv = ([string]$a) -split '=', 2; if ($kv.Count -eq 2) { $authEnv[$kv[0]] = $kv[1] } }
        if ($ident) { $authEnv['IDENTITY_ENDPOINT'] = 'assigned' }   # Container Apps injects it into a job that has an identity
        $auth = Resolve-SIContainerAuthMode -Environment $authEnv
        $row.AuthMode = $auth.Mode; $row.Identity = $ident
        $choice = Resolve-SIBootstrapKedaChoice -Configured $configured -AuthMode $(if ($auth.Mode -eq 'None') { 'Secret' } else { $auth.Mode }) -AuthDefault $false
        $trigger = [string](Get-SIKedaConvertProp $plain @('properties', 'configuration', 'triggerType'))
        $cron = [string](Get-SIKedaConvertProp $plain @('properties', 'configuration', 'scheduleTriggerConfig', 'cronExpression'))
        if (-not $cron) { $cron = [string](Get-SIKedaConvertProp $plain @('tags', 'si-disabled-cron')) }
        $row.Trigger = $trigger; $row.Cron = $cron
        $row.StorageAccount = Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_STORAGE_ACCOUNT'
        if (-not $row.StorageAccount -and $Globals.ContainsKey('SI_StorageAccount')) { $row.StorageAccount = "$($Globals['SI_StorageAccount'])".Trim() }
        if (-not $choice.Keda -and $choice.Explicit -and -not $choice.Refuse) { $row.Reason = 'queue scaling is switched off for this install (SI_Bootstrap_UseKEDA = $false)' }
        elseif ($auth.Mode -eq 'Secret' -or $auth.Mode -eq 'None') { $row.Reason = 'its job signs in with a client secret, and queue scaling needs the jobs'' managed identity -- the update never changes how the jobs sign in' }
        elseif (-not $ident) { $row.Reason = 'the job''s managed identity could not be told apart (none, or more than one, assigned)' }
        elseif (-not $choice.Keda) { $row.Reason = 'queue scaling is switched off for this install' }
        elseif (-not (Test-SIBootstrapJobIsSI -Job $plain)) { $row.Reason = 'SecurityInsight''s setup did not create this job (no si-build tag), so the update does not change it' }
        elseif ($trigger -notin @('Schedule', 'Manual')) { $row.Reason = ('its trigger is {0}, not a schedule' -f $(if ($trigger) { $trigger } else { 'unknown' })) }
        elseif ($trigger -eq 'Schedule' -and -not $cron) { $row.Reason = 'its schedule could not be read' }
        elseif (-not $row.StorageAccount) { $row.Reason = 'the storage account that holds the queues is not known (SI_STORAGE_ACCOUNT on the job)' }
        elseif (-not [string](Get-SIKedaConvertProp $plain @('properties', 'environmentId'))) { $row.Reason = 'the job''s Container Apps environment could not be read' }
        else { $row.Action = 'convert'; $row.Reason = 'runs as one scheduled job' }
        $rows.Add([pscustomobject]$row)
    }
    $rows.ToArray()
}

# The storage queue roles the queue scaler can read the queue length with, by role definition id (the same in every cloud)
$script:SIKedaConvertQueueRoleIds = @{
    'Storage Queue Data Contributor' = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
    'Storage Queue Data Reader'      = '19e7f393-937e-4f77-808e-94535e297925'
}
$script:SIKedaConvertRoleApi = '2022-04-01'
$script:SIKedaConvertStorageApi = '2023-05-01'
$script:SIKedaConvertQueueVersion = '2021-08-06'   # the data-plane x-ms-version engine/_shared/SI-AzRest.ps1 uses

function ConvertFrom-SIJobCreateArgs {
    <#
        PURE. Bootstrap's job definition -- the `az containerapp job create` arguments of Get-SIKedaWorkerCreateArgs /
        Get-SIKedaProducerCreateArgs plus tags, registry, identity, secrets and env -- as the ARM resource of
        Microsoft.App/jobs, so the update creates EXACTLY the job setup would, with no az CLI. Every flag is translated;
        a flag this does not know is refused (throws), never dropped.
          --environment            properties.environmentId (a resource id)
          --trigger-type           configuration.triggerType; --cron-expression scheduleTriggerConfig.cronExpression
          --replica-timeout / --replica-retry-limit                      configuration.replicaTimeout / replicaRetryLimit
          --parallelism / --replica-completion-count                     <trigger>TriggerConfig.parallelism / replicaCompletionCount
          --min-executions / --max-executions / --polling-interval      eventTriggerConfig.scale.*
          --scale-rule-name / -type / -metadata k=v / -identity         eventTriggerConfig.scale.rules[0] (identity auth)
          --image / --cpu / --memory / --env-vars N=V | N=secretref:S    template.containers[0] (named after the job, as az does)
          --registry-server + --registry-identity | --registry-username/--registry-password   configuration.registries[0]
          --secrets n=v | n=keyvaultref:<url>,identityref:<id>           configuration.secrets
          --mi-user-assigned       identity (UserAssigned);  --tags k=v  tags;  --name / --resource-group  the resource's path
        Returns @{ Name; ResourceGroup; Body }.
    #>
    param([Parameter(Mandatory)][object[]]$CreateArgs, [string]$Location)
    $a = @($CreateArgs | ForEach-Object { [string]$_ })
    if ($a.Count -lt 3 -or $a[0] -ne 'containerapp' -or $a[1] -ne 'job' -or $a[2] -ne 'create') { throw 'not an az containerapp job create argument list' }
    $known = @('--name', '--resource-group', '--environment', '--trigger-type', '--replica-timeout', '--replica-retry-limit', '--replica-completion-count',
               '--parallelism', '--cron-expression', '--min-executions', '--max-executions', '--polling-interval', '--scale-rule-name', '--scale-rule-type',
               '--scale-rule-metadata', '--scale-rule-identity', '--image', '--registry-server', '--registry-identity', '--registry-username',
               '--registry-password', '--cpu', '--memory', '--output', '--tags', '--mi-user-assigned', '--secrets', '--env-vars')
    $v = [ordered]@{}
    $i = 3
    while ($i -lt $a.Count) {
        $f = $a[$i]
        if (-not $f.StartsWith('--')) { throw ("unexpected value '{0}' in the job definition" -f $f) }
        if ($known -notcontains $f) { throw ("the ARM translation does not know {0} -- add it to ConvertFrom-SIJobCreateArgs" -f $f) }
        $i++
        if (-not $v.Contains($f)) { $v[$f] = New-Object System.Collections.Generic.List[string] }
        while ($i -lt $a.Count -and -not $a[$i].StartsWith('--')) { $v[$f].Add($a[$i]); $i++ }
    }
    $one = { param($f, $def) if ($v.Contains($f) -and $v[$f].Count) { $v[$f][0] } else { $def } }
    $all = { param($f) if ($v.Contains($f)) { @($v[$f]) } else { @() } }
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $name = & $one '--name' ''
    if (-not $name) { throw 'the job definition has no --name' }
    $trigger = & $one '--trigger-type' 'Manual'
    $cfg = [ordered]@{ triggerType = $trigger; replicaTimeout = [int](& $one '--replica-timeout' '1800'); replicaRetryLimit = [int](& $one '--replica-retry-limit' '0') }
    $tc = [ordered]@{ parallelism = [int](& $one '--parallelism' '1'); replicaCompletionCount = [int](& $one '--replica-completion-count' '1') }
    switch ($trigger) {
        'Schedule' { $cron = & $one '--cron-expression' ''; if (-not $cron) { throw 'a Schedule job needs --cron-expression' }; $cfg.scheduleTriggerConfig = [ordered]@{ cronExpression = $cron; parallelism = $tc.parallelism; replicaCompletionCount = $tc.replicaCompletionCount } }
        'Manual'   { $cfg.manualTriggerConfig = $tc }
        'Event'    {
            $scale = [ordered]@{ minExecutions = [int](& $one '--min-executions' '0'); maxExecutions = [int](& $one '--max-executions' '10'); pollingInterval = [int](& $one '--polling-interval' '30'); rules = @() }
            $rn = & $one '--scale-rule-name' ''
            if ($rn) {
                $md = [ordered]@{}; foreach ($kv in (& $all '--scale-rule-metadata')) { $p = $kv -split '=', 2; $md[$p[0]] = $(if ($p.Count -gt 1) { $p[1] } else { '' }) }
                $rule = [ordered]@{ name = $rn; type = (& $one '--scale-rule-type' ''); metadata = $md }
                $rid = & $one '--scale-rule-identity' ''; if ($rid) { $rule.identity = $rid }
                $scale.rules = @($rule)
            }
            $cfg.eventTriggerConfig = [ordered]@{ parallelism = $tc.parallelism; replicaCompletionCount = $tc.replicaCompletionCount; scale = $scale }
        }
        default { throw ("unknown trigger type '{0}'" -f $trigger) }
    }
    $secrets = New-Object System.Collections.Generic.List[object]
    foreach ($s in (& $all '--secrets')) {
        $p = $s -split '=', 2; $sv = $(if ($p.Count -gt 1) { $p[1] } else { '' })
        if ($sv.StartsWith('keyvaultref:')) {
            $ref = $sv.Substring(12); $k = $ref.IndexOf(',identityref:')
            if ($k -ge 0) { $secrets.Add([ordered]@{ name = $p[0]; keyVaultUrl = $ref.Substring(0, $k); identity = $ref.Substring($k + 13) }) } else { $secrets.Add([ordered]@{ name = $p[0]; keyVaultUrl = $ref }) }
        } else { $secrets.Add([ordered]@{ name = $p[0]; value = $sv }) }
    }
    $server = & $one '--registry-server' ''
    if ($server) {
        $reg = [ordered]@{ server = $server }
        $rid = & $one '--registry-identity' ''; $ru = & $one '--registry-username' ''
        if ($rid) { $reg.identity = $rid }
        elseif ($ru) { $reg.username = $ru; $reg.passwordSecretRef = 'registry-password'; $secrets.Add([ordered]@{ name = 'registry-password'; value = (& $one '--registry-password' '') }) }
        $cfg.registries = @($reg)
    }
    if ($secrets.Count) { $cfg.secrets = $secrets.ToArray() }
    $env = @(& $all '--env-vars' | ForEach-Object {
        $p = $_ -split '=', 2; $ev = $(if ($p.Count -gt 1) { $p[1] } else { '' })
        if ($ev.StartsWith('secretref:')) { [ordered]@{ name = $p[0]; secretRef = $ev.Substring(10) } } else { [ordered]@{ name = $p[0]; value = $ev } }
    })
    $container = [ordered]@{ name = $name; image = (& $one '--image' ''); resources = [ordered]@{ cpu = [double]::Parse((& $one '--cpu' '0.5'), $inv); memory = (& $one '--memory' '1Gi') }; env = $env }
    $tags = [ordered]@{}; foreach ($t in (& $all '--tags')) { $p = $t -split '=', 2; $tags[$p[0]] = $(if ($p.Count -gt 1) { $p[1] } else { '' }) }
    $body = [ordered]@{}
    if ($Location) { $body.location = $Location }
    if ($tags.Count) { $body.tags = $tags }
    $mi = @(& $all '--mi-user-assigned')
    if ($mi.Count) { $ua = [ordered]@{}; foreach ($m in $mi) { $ua[$m] = @{} }; $body.identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua } }
    $body.properties = [ordered]@{ environmentId = (& $one '--environment' ''); configuration = $cfg; template = [ordered]@{ containers = @($container) } }
    [pscustomobject]@{ Name = $name; ResourceGroup = (& $one '--resource-group' ''); Body = $body }
}

function Get-SIKedaConvertJobSpec {
    <#
        PURE. The producer and worker for one engine, from its scheduled job: Bootstrap's job definitions (the az create
        arguments) with the old job's image, registry, identity, size, environment and secrets, translated to the ARM
        resource (ConvertFrom-SIJobCreateArgs). The producer is created with NO timer (Manual; the cron remembered in
        si-disabled-cron) -- the update gives it the cron only after the old job has lost its own. -SecretArgs: name=value /
        name=keyvaultref:... for every secret the old job carries (the registry password excluded -- -RegistryPassword).
        Returns @{ Worker; Producer; WorkerArgs; ProducerArgs; WorkerBody; ProducerBody; QueueName; Image; Cron; ShardCount; MaxExecutions }.
    #>
    param([Parameter(Mandatory)]$Job, [Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$SecretArgs = @(), [string]$RegistryPassword, [int]$MaxExecutions = 30)
    $e = $Plan.Engine
    $c = @(Get-SIKedaConvertProp $Job @('properties', 'template', 'containers'))[0]
    $image = [string](Get-SIKedaConvertProp $c @('image'))
    $env = @(ConvertTo-SIKedaConvertEnvArgs -Env @(Get-SIKedaConvertProp $c @('env')))
    $cfg = Get-SIKedaConvertProp $Job @('properties', 'configuration')
    $timeout = [int](Get-SIKedaConvertProp $cfg @('replicaTimeout')); if ($timeout -le 0) { $timeout = [int](Get-SIJobRunLimit) }   # a job that names none: what every engine job gets
    $cpuRaw = Get-SIKedaConvertProp $c @('resources', 'cpu')
    $cpu = if ($null -ne $cpuRaw -and "$cpuRaw".Trim()) { ([double]$cpuRaw).ToString([Globalization.CultureInfo]::InvariantCulture) } else { '1.0' }
    $mem = [string](Get-SIKedaConvertProp $c @('resources', 'memory')); if (-not $mem) { $mem = '2Gi' }
    $reg = @(Get-SIKedaConvertProp $cfg @('registries') | Where-Object { $_ })[0]
    $login = [string](Get-SIKedaConvertProp $reg @('server')); if (-not $login) { $login = ($image -split '/')[0] }
    $regArgs = @()
    $regIdentity = [string](Get-SIKedaConvertProp $reg @('identity'))
    $regUser = [string](Get-SIKedaConvertProp $reg @('username'))
    if ($regIdentity) { $regArgs = @(Get-SIRegistryPullArgs -Mode 'ManagedIdentity' -IdentityResourceId $regIdentity) }
    elseif ($regUser -and $RegistryPassword) { $regArgs = @('--registry-username', $regUser, '--registry-password', $RegistryPassword) }
    $shards = 0; [void][int]::TryParse((Get-SIKedaConvertEnvValue -EnvArgs $env -Name 'SI_SHARD_COUNT'), [ref]$shards); if ($shards -le 0) { $shards = 1 }
    $build = [string](Get-SIKedaConvertProp $Job @('tags', 'si-build'))
    $envId = [string](Get-SIKedaConvertProp $Job @('properties', 'environmentId'))
    $location = [string](Get-SIKedaConvertProp $Job @('location'))
    $ident = $Plan.Identity
    $workerName = "caj-si-$e-worker"; $producerName = "caj-si-$e-producer"
    $workerEnv = @(Get-SIKedaWorkerEnvFromJob -EnvArgs $env -ReplicaTimeout $timeout)
    $producerEnv = @(Get-SIKedaProducerEnvArgs -EnvArgs $env -Parallelism $shards)
    $tail = {
        param([object[]]$EnvArgs, [string[]]$Tags)
        $t = @('--tags') + @($Tags | Where-Object { $_ })
        $t + $regArgs + @('--mi-user-assigned', $ident.ResourceId) + $(if (@($SecretArgs).Count) { @('--secrets') + @($SecretArgs) } else { @() }) + @('--env-vars') + @($EnvArgs)
    }
    $w = @(Get-SIKedaWorkerCreateArgs -Name $workerName -ResourceGroup $ResourceGroup -Environment $envId -Image $image -LoginServer $login `
            -ReplicaTimeout $timeout -Cpu $cpu -Memory $mem -MaxExecutions $MaxExecutions -Engine $e -StorageAccount $Plan.StorageAccount -IdentityResourceId $ident.ResourceId)
    $w += @(& $tail $workerEnv @($(if ($build) { "si-build=$build" })))
    $p = @(Get-SIKedaProducerCreateArgs -Name $producerName -ResourceGroup $ResourceGroup -Environment $envId -Cron $(if ($Plan.Cron) { $Plan.Cron } else { '0 0 * * *' }) -Image $image -LoginServer $login `
            -Cpu ([string]$cpu) -Memory ([string]$mem) -ReplicaTimeout ([int]$timeout))
    # assigned as it comes (it returns its array with a leading comma: @( ) around it would nest it)
    $p = ConvertTo-SIManualCreateArgs -CreateArgs $p -RememberCron ''   # no timer yet; the tag is set below, with si-build, in ONE --tags
    $p += @(& $tail $producerEnv @($(if ($build) { "si-build=$build" }), $(if ($Plan.Cron) { "si-disabled-cron=$($Plan.Cron)" })))
    [pscustomobject]@{ Worker = $workerName; Producer = $producerName; WorkerArgs = $w; ProducerArgs = $p
                       WorkerBody = (ConvertFrom-SIJobCreateArgs -CreateArgs $w -Location $location).Body
                       ProducerBody = (ConvertFrom-SIJobCreateArgs -CreateArgs $p -Location $location).Body
                       QueueName = (Get-SIKedaQueueName -Engine $e); Image = $image; Cron = $Plan.Cron; ShardCount = $shards; MaxExecutions = $MaxExecutions }
}

function Test-SIKedaConvertReadBack {
    <# PURE. The worker and producer as Azure returned them: created (provisioning not failed), the worker event-triggered
       with the queue rule on the image, the producer without a timer on the image. Returns '' (good) or what is wrong. #>
    param($Worker, $Producer, [Parameter(Mandatory)][string]$Image, [Parameter(Mandatory)][string]$QueueName)
    if (-not $Worker) { return 'the worker could not be read back' }
    if (-not $Producer) { return 'the producer could not be read back' }
    foreach ($x in @(@{ N = 'worker'; J = $Worker }, @{ N = 'producer'; J = $Producer })) {
        $ps = [string](Get-SIKedaConvertProp $x.J @('properties', 'provisioningState'))
        if ($ps -and $ps -ne 'Succeeded') { return ('the {0} was not created (provisioning {1})' -f $x.N, $ps) }
    }
    if ([string](Get-SIKedaConvertProp $Worker @('properties', 'configuration', 'triggerType')) -ne 'Event') { return 'the worker is not event-triggered' }
    $rule = @(Get-SIKedaConvertProp $Worker @('properties', 'configuration', 'eventTriggerConfig', 'scale', 'rules') | Where-Object { $_ -and [string](Get-SIKedaConvertProp $_ @('name')) -eq 'si-shards-queue' })[0]
    if (-not $rule) { return 'the worker has no queue scale rule' }
    $q = [string](Get-SIKedaConvertProp $rule @('metadata', 'queueName'))
    if ($q -and $q -ne $QueueName) { return ('the worker''s scale rule reads {0}, not {1}' -f $q, $QueueName) }
    if ([string](Get-SIKedaConvertProp $Producer @('properties', 'configuration', 'triggerType')) -ne 'Manual') { return 'the producer has a timer before the old job lost its own' }
    foreach ($x in @(@{ N = 'worker'; J = $Worker }, @{ N = 'producer'; J = $Producer })) {
        $img = [string](@(Get-SIKedaConvertProp $x.J @('properties', 'template', 'containers'))[0] | ForEach-Object { Get-SIKedaConvertProp $_ @('image') })
        if ($img -ne $Image) { return ('the {0} runs {1}, not {2}' -f $x.N, $img, $Image) }
    }
    ''
}

function Invoke-SIKedaConvert {
    <#
        EXISTING INSTALLS: move every parts engine that still runs as one scheduled job to a producer + queue-scaled workers
        (the plan: Get-SIKedaConvertPlan). -Jobs: the job list (ARM shape). -Rest { param([string]$Method, [string]$Uri,
        $Body, [string]$Resource, [hashtable]$Headers) } -> @{ Status; Body } -- ARM (https://management.azure.com/, every
        path under /subscriptions/<-SubscriptionId>) and the queue data plane (https://storage.azure.com/). No az CLI.
        -WhatIf: the plan only, no call. Returns @{ Results = @(@{ Engine; Action = converted | would-convert | keep | keda |
        failed; Line }); Lines }. NEVER throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [object[]]$Jobs = @(), [hashtable]$Globals = @{}, [string]$UpdaterUseKeda, [switch]$WhatIf, [int]$PollSeconds = 5, [int]$PollMax = 36)
    $results = New-Object System.Collections.Generic.List[object]
    $lines = New-Object System.Collections.Generic.List[string]
    $add = { param($e, $a, $l) $results.Add([pscustomobject]@{ Engine = $e; Action = $a; Line = $l }); if ($l) { $lines.Add($l) } }
    try {
        $plan = @(Get-SIKedaConvertPlan -Jobs $Jobs -Globals $Globals -UpdaterUseKeda $UpdaterUseKeda)
        $arm = 'https://management.azure.com/'; $stor = 'https://storage.azure.com/'
        $api = $script:SIKedaConvertArmApi
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
        $jobPath = { param($n) '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs/{2}' -f $SubscriptionId, $ResourceGroup, $n }
        $jobUri = { param($n, [string]$Action) 'https://management.azure.com{0}{1}?api-version={2}' -f (& $jobPath $n), $Action, $api }
        $max = $script:SIKedaConvertDefaultMaxReplicas
        if ($Globals.ContainsKey('SI_Bootstrap_KedaMaxReplicas')) { $m = 0; if ([int]::TryParse("$($Globals['SI_Bootstrap_KedaMaxReplicas'])", [ref]$m) -and $m -gt 0) { $max = $m } }
        $byName = @{}; foreach ($j in @($Jobs)) { if ($j) { $byName[([string](Get-SIKedaConvertProp $j @('name'))).ToLowerInvariant()] = $j } }
        $toJson = { param($o) ConvertTo-Json -InputObject $o -Depth 30 -Compress }
        # a created job is read back once its creation has finished (ARM creates a job asynchronously)
        $readBack = {
            param([string]$n)
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
        $stgIds = @{}

        foreach ($row in $plan) {
            $e = $row.Engine
            if ($row.Action -eq 'keda') { if ($row.Reason -ne 'not installed') { & $add $e 'keda' ('queue scaling: {0} {1}' -f $e, $row.Reason) } else { & $add $e 'keda' '' }; continue }
            if ($row.Action -eq 'keep') { & $add $e 'keep' ('queue scaling: {0} stays one scheduled job ({1}) -- {2}' -f $e, $row.Job, $row.Reason); continue }
            $old = $byName[$row.Job]
            $when = if ($row.Trigger -eq 'Schedule') { "on its schedule '$($row.Cron)'" } else { 'in the daily job flow, as the old job was' }
            if ($WhatIf) {
                & $add $e 'would-convert' ('queue scaling: {0} would move from one scheduled job ({1}) to a producer ({2}) and queue-scaled workers ({3}) (re-run with -Apply)' -f $e, $row.Job, "caj-si-$e-producer", "caj-si-$e-worker")
                continue
            }
            $created = New-Object System.Collections.Generic.List[string]
            $fail = {
                param([string]$Reason)
                foreach ($n in @($created)) { $null = & $call 'DELETE' (& $jobUri $n) $null $arm $null }
                & $add $e 'failed' ('queue scaling: {0} was NOT moved ({1}) -- it keeps running as the scheduled job {2}; the next update tries again' -f $e, $Reason, $row.Job)
            }
            try {
                # (1) the storage account's resource id (ARM list of the subscription's accounts, read once)
                $acct = $row.StorageAccount.ToLowerInvariant()
                if (-not $stgIds.ContainsKey($acct)) {
                    $found = ''
                    # FIRST the account read directly in its resource group (the install's own group, then the configured storage
                    # group): the updater's identity holds rights on the resource group, not on the subscription -- a
                    # subscription-wide list answers 403 there (internal ring 1, 2026-10-10: "could not be read").
                    $rgs = New-Object System.Collections.Generic.List[string]
                    foreach ($cand in @($ResourceGroup, $(if ($Globals -and $Globals.ContainsKey('SI_StorageResourceGroup')) { $Globals['SI_StorageResourceGroup'] }))) {
                        if ("$cand".Trim() -and -not $rgs.Contains("$cand".Trim())) { $rgs.Add("$cand".Trim()) }
                    }
                    $lastAnswer = ''
                    foreach ($rgName in $rgs) {
                        if ($found) { break }
                        $u = 'https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}?api-version={3}' -f $SubscriptionId, $rgName, $acct, $script:SIKedaConvertStorageApi
                        $r = & $call 'GET' $u $null $arm $null
                        if (& $isOk $r) { $found = [string](Get-SIKedaConvertProp (& $parse $r) @('id')) } else { $lastAnswer = ('in {0}: {1}' -f $rgName, (& $why $r)) }
                    }
                    $next = if ($found) { '' } else { 'https://management.azure.com/subscriptions/{0}/providers/Microsoft.Storage/storageAccounts?api-version={1}' -f $SubscriptionId, $script:SIKedaConvertStorageApi }
                    $pages = 0
                    while ($next -and -not $found -and $pages -lt 50) {
                        $pages++; $r = & $call 'GET' $next $null $arm $null
                        if (-not (& $isOk $r)) { $lastAnswer = ('{0}; the subscription list: {1}' -f $lastAnswer, (& $why $r)).TrimStart('; '); break }
                        $pg = & $parse $r
                        foreach ($sa in @(Get-SIKedaConvertProp $pg @('value'))) { if ($sa -and ([string](Get-SIKedaConvertProp $sa @('name'))).ToLowerInvariant() -eq $acct) { $found = [string](Get-SIKedaConvertProp $sa @('id')) } }
                        $next = [string](Get-SIKedaConvertProp $pg @('nextLink'))
                    }
                    $stgIds[$acct] = $found
                }
                $stgId = $stgIds[$acct]
                if (-not $stgId) { & $fail ('the storage account {0} could not be read{1}' -f $row.StorageAccount, $(if ("$lastAnswer".Trim()) { ' -- Azure answered ' + $lastAnswer } else { '' })); continue }
                # the scaler reads the queue length as the jobs' identity: its storage queue role (Bootstrap's grant plan)
                $grants = @(Get-SIContainerIdentityGrantPlan -Mode $row.AuthMode -StorageAccountId $stgId -KedaQueueScaler |
                            Where-Object { $_.Kind -eq 'AzureRole' -and $_.Scope -eq $stgId -and $_.Role -like 'Storage Queue*' })
                $principal = [string]$row.Identity.PrincipalId
                if (-not $principal) { & $fail 'the managed identity''s object id could not be read'; continue }
                $grantFailed = ''
                foreach ($g in $grants) {
                    $rid = $script:SIKedaConvertQueueRoleIds[$g.Role]
                    if (-not $rid) { $grantFailed = ('the role {0} is not known here' -f $g.Role); break }
                    $flt = [uri]::EscapeDataString(("principalId eq '{0}'" -f $principal))
                    $r = & $call 'GET' ('https://management.azure.com{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}&api-version={2}' -f $stgId, $flt, $script:SIKedaConvertRoleApi) $null $arm $null
                    if (-not (& $isOk $r)) { $grantFailed = ('the role assignments on the storage account could not be read ({0})' -f (& $why $r)); break }
                    $have = @(Get-SIKedaConvertProp (& $parse $r) @('value') | Where-Object { $_ -and ([string](Get-SIKedaConvertProp $_ @('properties', 'roleDefinitionId'))).ToLowerInvariant().EndsWith('/' + $rid) })
                    if ($have.Count) { continue }
                    $body = [ordered]@{ properties = [ordered]@{ roleDefinitionId = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $rid); principalId = $principal; principalType = 'ServicePrincipal' } }
                    $r = & $call 'PUT' ('https://management.azure.com{0}/providers/Microsoft.Authorization/roleAssignments/{1}?api-version={2}' -f $stgId, [guid]::NewGuid().ToString(), $script:SIKedaConvertRoleApi) (& $toJson $body) $arm $null
                    if (-not (& $isOk $r)) { $grantFailed = ('the jobs'' identity lacks {0} on the storage account and it could not be granted here ({1}) -- grant it once to object id {2} on {3}' -f $g.Role, (& $why $r), $principal, $stgId); break }
                }
                if ($grantFailed) { & $fail $grantFailed; continue }
                # (2) the old job's secrets, with their values (Key Vault references as references): ARM listSecrets
                $secretArgs = @(); $regPassword = ''
                $reg = @(Get-SIKedaConvertProp $old @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
                $regPwRef = [string](Get-SIKedaConvertProp $reg @('passwordSecretRef'))
                if (@(Get-SIKedaConvertProp $old @('properties', 'configuration', 'secrets') | Where-Object { $_ }).Count) {
                    $r = & $call 'POST' (& $jobUri $row.Job '/listSecrets') $null $arm $null
                    if (-not (& $isOk $r)) { & $fail ('the old job''s secrets could not be read ({0})' -f (& $why $r)); continue }
                    foreach ($s in @(Get-SIKedaConvertProp (& $parse $r) @('value'))) {
                        $sn = [string](Get-SIKedaConvertProp $s @('name')); if (-not $sn) { continue }
                        $kvu = [string](Get-SIKedaConvertProp $s @('keyVaultUrl'))
                        $val = [string](Get-SIKedaConvertProp $s @('value'))
                        if ($sn -eq $regPwRef) { $regPassword = $val; continue }
                        if ($kvu) { $secretArgs += ('{0}=keyvaultref:{1},identityref:{2}' -f $sn, $kvu, [string](Get-SIKedaConvertProp $s @('identity'))) }
                        else { $secretArgs += ('{0}={1}' -f $sn, $val) }
                    }
                }
                if ($regPwRef -and -not $regPassword -and -not [string](Get-SIKedaConvertProp $reg @('identity'))) { & $fail 'the registry password of the old job could not be read'; continue }
                $spec = Get-SIKedaConvertJobSpec -Job $old -Plan $row -ResourceGroup $ResourceGroup -SecretArgs $secretArgs -RegistryPassword $regPassword -MaxExecutions $max
                # (3) the shard queue (data plane) -- the producer creates it on its first run as well, so a refusal here changes nothing
                $r = & $call 'PUT' ('https://{0}.queue.core.windows.net/{1}' -f $acct, $spec.QueueName) $null $stor @{ 'x-ms-version' = $script:SIKedaConvertQueueVersion }
                if (-not ((& $isOk $r) -or [int]$r.Status -eq 409)) { $lines.Add(('queue scaling: {0}: the queue {1} could not be created from here ({2}) -- the producer creates it on its first run' -f $e, $spec.QueueName, (& $why $r))) }
                # (4) the worker -- idle until the producer queues work, so creating it starts nothing
                $r = & $call 'PUT' (& $jobUri $spec.Worker) (& $toJson $spec.WorkerBody) $arm $null
                if (-not (& $isOk $r)) { & $fail ('the worker could not be created ({0})' -f (& $why $r)); continue }
                $created.Add($spec.Worker)
                # (5) the producer -- without a timer until the old job has lost its own
                $r = & $call 'PUT' (& $jobUri $spec.Producer) (& $toJson $spec.ProducerBody) $arm $null
                if (-not (& $isOk $r)) { & $fail ('the producer could not be created ({0})' -f (& $why $r)); continue }
                $created.Add($spec.Producer)
                # (6) both read back
                $wb = & $readBack $spec.Worker; $pb = & $readBack $spec.Producer
                $bad = Test-SIKedaConvertReadBack -Worker $wb -Producer $pb -Image $spec.Image -QueueName $spec.QueueName
                if ($bad) { & $fail $bad; continue }
                # (7) the swap: the old job loses its timer FIRST, then the producer gets it -- never two schedules
                if ($row.Trigger -eq 'Schedule') {
                    $r = & $call 'PATCH' (& $jobUri $row.Job) (& $toJson (ConvertTo-SIArmJobTrigger -Job $old -Action 'to-manual')) $arm $null
                    if (-not (& $isOk $r)) { & $fail ('the old job''s schedule could not be switched off ({0})' -f (& $why $r)); continue }
                    $r = & $call 'PATCH' (& $jobUri $spec.Producer) (& $toJson (ConvertTo-SIArmJobTrigger -Job $pb -Action 'to-schedule' -Cron $row.Cron)) $arm $null
                    if (-not (& $isOk $r)) {
                        $pwhy = & $why $r
                        $back = & $call 'PATCH' (& $jobUri $row.Job) (& $toJson (ConvertTo-SIArmJobTrigger -Job $old -Action 'to-schedule' -Cron $row.Cron)) $arm $null
                        if (& $isOk $back) { & $fail ('the producer could not be given the schedule ({0})' -f $pwhy) }
                        else {
                            foreach ($n in @($created)) { $null = & $call 'DELETE' (& $jobUri $n) $null $arm $null }
                            & $add $e 'failed' ('queue scaling: {0} was NOT moved, and its scheduled job {1} could not be given its schedule back -- {0} does NOT run on a timer now. Switch it back on: Enable on the web app''s Jobs page (its schedule ''{2}'' is remembered on the job)' -f $e, $row.Job, $row.Cron)
                        }
                        continue
                    }
                }
                & $add $e 'converted' ('queue scaling: {0} now runs as a producer ({1}, {2}) and up to {3} workers that start as work arrives ({4}); the old scheduled job {5} is switched off and kept' -f $e, $spec.Producer, $when, $max, $spec.Worker, $row.Job)
            } catch { & $fail $_.Exception.Message }
        }
        if (-not @($results | Where-Object { $_.Line }).Count) { $lines.Add('queue scaling: no identity, endpoint or Azure job in this install -- nothing to move') }
    } catch {
        $lines.Add(('queue scaling: not checked ({0}) -- the update goes on; the next update tries again' -f $_.Exception.Message))
    }
    [pscustomobject]@{ Results = $results.ToArray(); Lines = $lines.ToArray() }
}
