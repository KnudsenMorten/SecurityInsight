#Requires -Version 5.1
<#
    #519 EXISTING INSTALLS MOVE TO QUEUE SCALING ON UPDATE (measured 2026-10-09: an install made before queue scaling kept one
    scheduled caj-si-identity job; its ~28,000-object identity collection ran ~2 h in one container). setup/_shared/SI-KedaConvert.ps1:
    a plain scheduled job of identity / endpoint / azure, made by SI's setup and signed in with the managed identity, moves to
    the producer + queue-scaled workers Bootstrap gives a new install -- Bootstrap's job definitions translated to the ARM
    resource, from the old job, over ARM / storage REST only (no az CLI, no module: operator "pure rest or arm only"). The old
    job loses its timer only after both new jobs read back, before the producer gets it; it is kept. A secret-by-choice
    install, an opted-out install and an install already on producer + worker are left alone. Offline, against a fake REST seam.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-KedaConvert.ps1')
    $script:Sub = 'sub-1'
    $script:Rg = 'rg-si'
    $script:Uami = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-securityinsight'
    $script:Img = 'acrsi.azurecr.io/si-orchestrator:v3.1.0-abc'
    $script:Stg = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.Storage/storageAccounts/stsi'
    $script:Env = '/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.App/managedEnvironments/cae-si'

    # a scheduled caj-si-<engine> job as ARM returns it
    function script:New-PlainJob([string]$Engine = 'identity', [ValidateSet('MI', 'Secret', 'Cert')][string]$Auth = 'MI',
                                 [string]$Trigger = 'Schedule', [string]$Cron = '30 4 * * *', [switch]$NoSiTag, [object[]]$Secrets = @()) {
        $env = @(
            [pscustomobject]@{ name = 'SI_ENGINE'; value = $Engine }, [pscustomobject]@{ name = 'SI_SHARD_COUNT'; value = '1' },
            [pscustomobject]@{ name = 'SI_STORAGE_ACCOUNT'; value = 'stsi' }, [pscustomobject]@{ name = 'SI_ROLE'; value = 'worker' },
            [pscustomobject]@{ name = 'SI_CFG_SI_Mode'; value = 'Pro' })
        switch ($Auth) {
            'MI'     { $env += @([pscustomobject]@{ name = 'SI_UAMI_CLIENTID'; value = 'client-1' }, [pscustomobject]@{ name = 'SI_SPN_TENANTID'; value = 'ten' }) }
            'Secret' { $env += @([pscustomobject]@{ name = 'SI_SPN_APPID'; value = 'app' }, [pscustomobject]@{ name = 'SI_SPN_SECRET'; secretRef = 'si-spn-secret' }) }
            'Cert'   { $env += @([pscustomobject]@{ name = 'SI_SPN_APPID'; value = 'app' }, [pscustomobject]@{ name = 'SI_SPN_TENANTID'; value = 'ten' }, [pscustomobject]@{ name = 'SI_SPN_CERT_PFX_B64'; secretRef = 'si-spn-cert' }) }
        }
        $tags = [ordered]@{}; if (-not $NoSiTag) { $tags['si-build'] = '3.1.0+abc' }
        if ($Trigger -eq 'Manual' -and $Cron) { $tags['si-disabled-cron'] = $Cron }
        $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 14400; registries = @([pscustomobject]@{ server = 'acrsi.azurecr.io'; identity = $script:Uami })
                           secrets = @($Secrets | ForEach-Object { [pscustomobject]@{ name = $_.name } }) }
        if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [pscustomobject]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
        else { $cfg.manualTriggerConfig = [pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1 } }
        $ident = if ($Auth -eq 'Secret') { $null } else { [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ $script:Uami = [pscustomobject]@{ clientId = 'client-1'; principalId = 'principal-1' } } } }
        [pscustomobject]@{ name = "caj-si-$Engine"; location = 'westeurope'; tags = [pscustomobject]$tags; identity = $ident
            properties = [pscustomobject]@{ environmentId = $script:Env; provisioningState = 'Succeeded'
                configuration = [pscustomobject]$cfg
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; image = $script:Img; env = $env; resources = [pscustomobject]@{ cpu = 4.0; memory = '8Gi' } }) } } }
    }
    function script:New-World([object[]]$Jobs, [hashtable]$Fail = @{}, [bool]$HasRole = $true, [object[]]$Secrets = @()) {
        $w = [pscustomobject]@{ Jobs = @{}; Fail = $Fail; HasRole = $HasRole; Secrets = $Secrets; Calls = (New-Object System.Collections.Generic.List[string])
                                Req = (New-Object System.Collections.Generic.List[object]) }
        foreach ($j in $Jobs) { $w.Jobs[$j.name] = ($j | ConvertTo-Json -Depth 20 | ConvertFrom-Json) }
        $w
    }
    # the values after a flag, up to the next --flag
    function script:Get-After([string[]]$A, [string]$Flag) {
        $i = [array]::IndexOf($A, $Flag); if ($i -lt 0) { return @() }
        $o = @(); for ($k = $i + 1; $k -lt $A.Count -and -not ([string]$A[$k]).StartsWith('--'); $k++) { $o += $A[$k] }; $o
    }
    # a fake Azure: ARM (jobs, storage accounts, role assignments) and the queue data plane
    $script:Rest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        $w = $script:World; $line = '{0} {1}' -f $Method, $Uri; $w.Calls.Add($line)
        $w.Req.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body; Resource = $Resource; Headers = $Headers })
        $ok = { param($s, $o) [pscustomobject]@{ Status = $s; Body = $(if ($null -eq $o) { '' } elseif ($o -is [string]) { $o } else { ConvertTo-Json -InputObject $o -Depth 30 -Compress }) } }
        $guidC = '974c5e8b-45b9-4653-ba55-5f855dd0fb88'; $guidR = '19e7f393-937e-4f77-808e-94535e297925'
        # the account read in its resource group (World.RgStorage = $false: not there / not allowed); the subscription-wide list
        # (World.SubList403: refused, as for an identity with rights on the resource group only -- internal ring 1 2026-10-10)
        if ($Method -eq 'GET' -and $Uri -like '*/resourceGroups/*/providers/Microsoft.Storage/storageAccounts/stsi?*') { if ($w.PSObject.Properties['RgStorage'] -and $w.RgStorage -eq $false) { return (& $ok 404 'ResourceNotFound') }; return (& $ok 200 @{ name = 'stsi'; id = $script:Stg }) }
        if ($Method -eq 'GET' -and $Uri -like '*/providers/Microsoft.Storage/storageAccounts?*') { if ($w.PSObject.Properties['SubList403'] -and $w.SubList403) { return (& $ok 403 'AuthorizationFailed') }; return (& $ok 200 @{ value = @(@{ name = 'other'; id = '/x' }, @{ name = 'stsi'; id = $script:Stg }) }) }
        if ($Method -eq 'GET' -and $Uri -like '*/roleAssignments?*') {
            $v = if ($w.HasRole) { @(@{ properties = @{ roleDefinitionId = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/$guidC" } }, @{ properties = @{ roleDefinitionId = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/$guidR" } }) } else { @() }
            return (& $ok 200 @{ value = $v })
        }
        if ($Method -eq 'PUT' -and $Uri -like '*/roleAssignments/*') { if ($w.Fail.grant) { return (& $ok 403 '{"error":{"code":"AuthorizationFailed"}}') }; $w.HasRole = $true; return (& $ok 201 '{}') }
        if ($Method -eq 'POST' -and $Uri -like '*/listSecrets?*') { return (& $ok 200 @{ value = @($w.Secrets) }) }
        if ($Uri -like 'https://*.queue.core.windows.net/*') { if ($w.Fail.queue) { return (& $ok 403 'AuthorizationPermissionMismatch') }; return (& $ok 201 '') }
        $m = [regex]::Match($Uri, '/providers/Microsoft\.App/jobs/([^/?]+)\?')
        if ($m.Success) {
            $n = $m.Groups[1].Value
            switch ($Method) {
                'PUT' {
                    $role = if ($n -like '*-worker') { 'worker' } else { 'producer' }
                    if ($w.Fail[$role]) { return (& $ok 400 ("{0} refused" -f $role)) }
                    $j = $Body | ConvertFrom-Json
                    $j | Add-Member -Force -NotePropertyName name -NotePropertyValue $n
                    $j.properties | Add-Member -Force -NotePropertyName provisioningState -NotePropertyValue $(if ($w.Fail.provisioning) { 'Failed' } else { 'Succeeded' })
                    if ($w.Fail.readback -and $role -eq 'worker') { $j.properties.template.containers[0].image = 'acrsi.azurecr.io/si-orchestrator:other' }
                    $w.Jobs[$n] = $j; return (& $ok 201 $j)
                }
                'GET' { if ($w.Jobs.ContainsKey($n)) { return (& $ok 200 $w.Jobs[$n]) }; return (& $ok 404 'ResourceNotFound') }
                'DELETE' { $null = $w.Jobs.Remove($n); return (& $ok 200 '') }
                'PATCH' {
                    $b = $Body | ConvertFrom-Json; $tt = [string]$b.properties.configuration.triggerType
                    if ($w.Fail["patch-$n-$tt"]) { return (& $ok 409 "patch $n refused") }
                    $j = $w.Jobs[$n]; $j.properties.configuration.triggerType = $tt
                    $j | Add-Member -Force -NotePropertyName tags -NotePropertyValue $b.tags
                    $j.properties.configuration | Add-Member -Force -NotePropertyName scheduleTriggerConfig -NotePropertyValue $(if ($tt -eq 'Schedule') { $b.properties.configuration.scheduleTriggerConfig } else { $null })
                    return (& $ok 200 '')
                }
            }
        }
        & $ok 400 "unexpected call: $line"
    }
    function script:Invoke-Convert([object[]]$Jobs, [hashtable]$Globals = @{}, [switch]$WhatIf, [string]$UpdaterUseKeda) {
        Invoke-SIKedaConvert -Rest $script:Rest -SubscriptionId $script:Sub -ResourceGroup $script:Rg -Jobs $Jobs -Globals $Globals -WhatIf:$WhatIf -UpdaterUseKeda $UpdaterUseKeda -PollSeconds 0 -PollMax 2
    }
    function script:Get-Trigger([string]$Name) { [string]$script:World.Jobs[$Name].properties.configuration.triggerType }
    function script:Get-PutBody([string]$Name) { (@($script:World.Req | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like "*/jobs/$Name`?*" })[0]).Body | ConvertFrom-Json }
}

Describe 'the decision (pure)' {
    It 'convert: a plain scheduled job SI made, on the managed identity (or the certificate); keep everything else, with the reason' {
        $p = @(Get-SIKedaConvertPlan -Jobs @((New-PlainJob 'identity'), (New-PlainJob 'endpoint' -Auth Cert), (New-PlainJob 'azure' -Auth Secret)))
        ($p | Where-Object Engine -eq 'identity').Action | Should -Be 'convert'
        ($p | Where-Object Engine -eq 'endpoint').Action | Should -Be 'convert'
        ($p | Where-Object Engine -eq 'azure').Action | Should -Be 'keep'
        ($p | Where-Object Engine -eq 'azure').Reason | Should -BeLike '*client secret*'
        ($p | Where-Object Engine -eq 'identity').Identity.ResourceId | Should -Be $script:Uami
        ($p | Where-Object Engine -eq 'identity').Cron | Should -Be '30 4 * * *'
    }
    It 'keep: switched off (config or the updater job), not made by SI''s setup, or a producer / worker already beside it' {
        (@(Get-SIKedaConvertPlan -Jobs @(New-PlainJob) -Globals @{ SI_Bootstrap_UseKEDA = $false }) | Where-Object Engine -eq 'identity').Reason | Should -BeLike '*switched off*'
        (@(Get-SIKedaConvertPlan -Jobs @(New-PlainJob) -UpdaterUseKeda 'false') | Where-Object Engine -eq 'identity').Action | Should -Be 'keep'
        (@(Get-SIKedaConvertPlan -Jobs @(New-PlainJob -NoSiTag)) | Where-Object Engine -eq 'identity').Reason | Should -BeLike '*did not create*'
        $half = @(Get-SIKedaConvertPlan -Jobs @((New-PlainJob), [pscustomobject]@{ name = 'caj-si-identity-worker' }))
        ($half | Where-Object Engine -eq 'identity').Action | Should -Be 'keep'
        # SI_Bootstrap_UseKEDA = $true with a secret: still no conversion (the update never changes the sign-in)
        (@(Get-SIKedaConvertPlan -Jobs @(New-PlainJob -Auth Secret) -Globals @{ SI_Bootstrap_UseKEDA = $true }) | Where-Object Engine -eq 'identity').Action | Should -Be 'keep'
    }
    It 'the producer and worker are Bootstrap''s own definitions, from the old job' {
        $plan = @(Get-SIKedaConvertPlan -Jobs @(New-PlainJob)) | Where-Object Engine -eq 'identity'
        $s = Get-SIKedaConvertJobSpec -Job (New-PlainJob) -Plan $plan -ResourceGroup $script:Rg -MaxExecutions 30
        $env = @(ConvertTo-SIKedaConvertEnvArgs -Env (New-PlainJob).properties.template.containers[0].env)
        $wExpect = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-identity-worker' -ResourceGroup $script:Rg -Environment $script:Env -Image $script:Img `
                    -LoginServer 'acrsi.azurecr.io' -ReplicaTimeout 14400 -Cpu '4' -Memory '8Gi' -MaxExecutions 30 -Engine 'identity' -StorageAccount 'stsi' -IdentityResourceId $script:Uami)
        @($s.WorkerArgs)[0..($wExpect.Count - 1)] | Should -Be $wExpect
        $we = @(Get-After $s.WorkerArgs '--env-vars')
        $we | Should -Contain 'SI_TRIGGER_FROM_QUEUE=1'; $we | Should -Contain 'SI_ROLE=worker'; $we | Should -Contain 'SI_QUEUE_LEASE_SECONDS=14700'
        $we | Should -Contain 'SI_CFG_SI_Mode=Pro'; $we | Should -Contain 'SI_UAMI_CLIENTID=client-1'
        @(Get-After $s.ProducerArgs '--env-vars') | Should -Be @(Get-SIKedaProducerEnvArgs -EnvArgs $env -Parallelism 1)
        @(Get-After $s.ProducerArgs '--trigger-type') | Should -Be 'Manual'
        $s.ProducerArgs | Should -Not -Contain '--cron-expression'
        @(Get-After $s.ProducerArgs '--tags') | Should -Be @('si-build=3.1.0+abc', 'si-disabled-cron=30 4 * * *')
    }
}

Describe 'Bootstrap''s job definition as the ARM resource (ConvertFrom-SIJobCreateArgs, pure)' {
    It 'the worker: event trigger, the azure-queue scale rule with identity auth, size, image, registry, identity, env, tags' {
        $a = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-identity-worker' -ResourceGroup $script:Rg -Environment $script:Env -Image $script:Img -LoginServer 'acrsi.azurecr.io' `
                -ReplicaTimeout 14400 -Cpu '4' -Memory '8Gi' -MaxExecutions 30 -Engine 'identity' -StorageAccount 'stsi' -IdentityResourceId $script:Uami) +
             @('--tags', 'si-build=3.1.0+abc', '--registry-identity', $script:Uami, '--mi-user-assigned', $script:Uami, '--env-vars', 'SI_ENGINE=identity', 'OPENAI_APIKEY=secretref:openai-apikey')
        $t = ConvertFrom-SIJobCreateArgs -CreateArgs $a -Location 'westeurope'
        $t.Name | Should -Be 'caj-si-identity-worker'; $t.ResourceGroup | Should -Be $script:Rg
        $b = (ConvertTo-Json -InputObject $t.Body -Depth 30) | ConvertFrom-Json
        $b.location | Should -Be 'westeurope'
        $b.properties.environmentId | Should -Be $script:Env
        $c = $b.properties.configuration
        $c.triggerType | Should -Be 'Event'; $c.replicaTimeout | Should -Be 14400; $c.replicaRetryLimit | Should -Be 0 -Because 'an engine job: the pipeline decides what runs again'
        $c.eventTriggerConfig.parallelism | Should -Be 1; $c.eventTriggerConfig.replicaCompletionCount | Should -Be 1
        $c.eventTriggerConfig.scale.minExecutions | Should -Be 0; $c.eventTriggerConfig.scale.maxExecutions | Should -Be 30; $c.eventTriggerConfig.scale.pollingInterval | Should -Be 30
        $r = @($c.eventTriggerConfig.scale.rules)[0]
        $r.name | Should -Be 'si-shards-queue'; $r.type | Should -Be 'azure-queue'; $r.identity | Should -Be $script:Uami
        $r.metadata.queueName | Should -Be 'si-identity-shards'; $r.metadata.accountName | Should -Be 'stsi'; $r.metadata.queueLength | Should -Be '1'
        @($c.registries)[0].server | Should -Be 'acrsi.azurecr.io'; @($c.registries)[0].identity | Should -Be $script:Uami
        $k = @($b.properties.template.containers)[0]
        $k.name | Should -Be 'caj-si-identity-worker'; $k.image | Should -Be $script:Img; $k.resources.cpu | Should -Be 4; $k.resources.memory | Should -Be '8Gi'
        (@($k.env) | Where-Object name -eq 'SI_ENGINE').value | Should -Be 'identity'
        (@($k.env) | Where-Object name -eq 'OPENAI_APIKEY').secretRef | Should -Be 'openai-apikey'
        $b.identity.type | Should -Be 'UserAssigned'; @($b.identity.userAssignedIdentities.PSObject.Properties.Name) | Should -Be @($script:Uami)
        $b.tags.'si-build' | Should -Be '3.1.0+abc'
    }
    It 'a schedule, a manual trigger, secrets (values and Key Vault references) and a registry password' {
        $p = @(Get-SIKedaProducerCreateArgs -Name 'caj-si-identity-producer' -ResourceGroup $script:Rg -Environment $script:Env -Cron '30 4 * * *' -Image $script:Img -LoginServer 'acrsi.azurecr.io') +
             @('--registry-username', 'acrsi', '--registry-password', 'pw', '--secrets', 'si-license=LIC', "openai-apikey=keyvaultref:https://kv.vault.azure.net/secrets/OpenAI-ApiKey,identityref:$($script:Uami)")
        $b = (ConvertTo-Json -InputObject (ConvertFrom-SIJobCreateArgs -CreateArgs $p).Body -Depth 30) | ConvertFrom-Json
        $b.properties.configuration.triggerType | Should -Be 'Schedule'
        $b.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 4 * * *'
        @($b.properties.template.containers)[0].resources.cpu | Should -BeGreaterOrEqual 1.0   # at least the single job's size: the identity producer runs the permission scan (exit 137 on 0.25 / 0.5 GiB, 2026-10-10)
        $sec = @($b.properties.configuration.secrets)
        ($sec | Where-Object name -eq 'si-license').value | Should -Be 'LIC'
        ($sec | Where-Object name -eq 'openai-apikey').keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/OpenAI-ApiKey'
        ($sec | Where-Object name -eq 'openai-apikey').identity | Should -Be $script:Uami
        ($sec | Where-Object name -eq 'registry-password').value | Should -Be 'pw'
        @($b.properties.configuration.registries)[0].passwordSecretRef | Should -Be 'registry-password'
        $m = (ConvertTo-Json -InputObject (ConvertFrom-SIJobCreateArgs -CreateArgs (ConvertTo-SIManualCreateArgs -CreateArgs $p -RememberCron '')).Body -Depth 30) | ConvertFrom-Json
        $m.properties.configuration.triggerType | Should -Be 'Manual'
        $m.properties.configuration.PSObject.Properties.Name | Should -Not -Contain 'scheduleTriggerConfig'
    }
    It 'NEGATIVE: a flag it does not know is refused, never dropped' {
        { ConvertFrom-SIJobCreateArgs -CreateArgs @('containerapp', 'job', 'create', '--name', 'x', '--scale-rule-auth', 'connection=c') } | Should -Throw '*does not know --scale-rule-auth*'
        { ConvertFrom-SIJobCreateArgs -CreateArgs @('containerapp', 'job', 'update', '--name', 'x') } | Should -Throw
    }
}

Describe 'Invoke-SIKedaConvert against a fake Azure (REST)' {
    It 'converts a plain managed-identity install: queue, worker, producer on the old cron; the old job is switched off LAST and kept; every call in this subscription' {
        $script:World = New-World -Jobs @(New-PlainJob 'identity')
        $r = Invoke-Convert -Jobs @(New-PlainJob 'identity')
        ($r.Results | Where-Object Engine -eq 'identity').Action | Should -Be 'converted'
        $w = $script:World.Jobs
        $w.ContainsKey('caj-si-identity') | Should -BeTrue                       # kept, not deleted
        Get-Trigger 'caj-si-identity' | Should -Be 'Manual'
        $w['caj-si-identity'].tags.'si-disabled-cron' | Should -Be '30 4 * * *'
        Get-Trigger 'caj-si-identity-worker' | Should -Be 'Event'
        Get-Trigger 'caj-si-identity-producer' | Should -Be 'Schedule'
        $w['caj-si-identity-producer'].properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 4 * * *'
        # the producer was CREATED without a timer
        (Get-PutBody 'caj-si-identity-producer').properties.configuration.triggerType | Should -Be 'Manual'
        (Get-PutBody 'caj-si-identity-worker').location | Should -Be 'westeurope'
        $q = @($script:World.Req | Where-Object { $_.Uri -eq 'https://stsi.queue.core.windows.net/si-identity-shards' })
        $q.Count | Should -Be 1; $q[0].Method | Should -Be 'PUT'; $q[0].Resource | Should -Be 'https://storage.azure.com/'; $q[0].Headers['x-ms-version'] | Should -Not -BeNullOrEmpty
        # the order: worker, producer, both read back, THEN the old job off, THEN the producer on
        $c = [string[]]@($script:World.Calls)
        $iw = [array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'PUT */jobs/caj-si-identity-worker?*' })
        $ip = [array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'PUT */jobs/caj-si-identity-producer?*' })
        $is = [array]::FindLastIndex($c, [Predicate[string]] { param($x) $x -like 'GET */jobs/caj-si-identity-*' })
        $io = [array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'PATCH */jobs/caj-si-identity?*' })
        $ipo = [array]::FindIndex($c, [Predicate[string]] { param($x) $x -like 'PATCH */jobs/caj-si-identity-producer?*' })
        ($iw -ge 0 -and $ip -gt $iw -and $is -gt $ip -and $io -gt $is -and $ipo -gt $io) | Should -BeTrue
        @($c | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
        foreach ($q in $script:World.Req) {
            if ($q.Uri -like 'https://management.azure.com/*') { $q.Uri | Should -BeLike 'https://management.azure.com/subscriptions/sub-1/*'; $q.Resource | Should -Be 'https://management.azure.com/' }
            else { $q.Resource | Should -Be 'https://storage.azure.com/' }
        }
        ($r.Lines -join "`n") | Should -Match "identity now runs as a producer \(caj-si-identity-producer, on its schedule '30 4 \* \* \*'\) and up to 30 workers"
        ($r.Lines -join "`n") | Should -Match 'the old scheduled job caj-si-identity is switched off and kept'
    }
    It 'the storage account is read in its RESOURCE GROUP: an updater identity with rights on the resource group only converts (internal ring 1 2026-10-10)' {
        $script:World = New-World -Jobs @(New-PlainJob 'identity')
        $script:World | Add-Member -NotePropertyName SubList403 -NotePropertyValue $true
        $r = Invoke-Convert -Jobs @(New-PlainJob 'identity')
        ($r.Results | Where-Object Engine -eq 'identity').Action | Should -Be 'converted'
        @($script:World.Calls | Where-Object { $_ -like 'GET */resourceGroups/*/providers/Microsoft.Storage/storageAccounts/stsi?*' }).Count | Should -BeGreaterThan 0
        @($script:World.Calls | Where-Object { $_ -match '^GET https://management\.azure\.com/subscriptions/[^/]+/providers/Microsoft\.Storage/storageAccounts\?' }).Count | Should -Be 0 -Because 'found in the resource group, the subscription list is never asked'
        # not in the resource group AND the list refused: not moved, said plainly, the old job keeps running
        $script:World = New-World -Jobs @(New-PlainJob 'identity')
        $script:World | Add-Member -NotePropertyName SubList403 -NotePropertyValue $true
        $script:World | Add-Member -NotePropertyName RgStorage -NotePropertyValue $false
        $r2 = Invoke-Convert -Jobs @(New-PlainJob 'identity')
        ($r2.Lines -join "`n") | Should -Match 'identity was NOT moved \(the storage account stsi could not be read -- Azure answered in rg-si: HTTP 404.*the subscription list: HTTP 403'
        Get-Trigger 'caj-si-identity' | Should -Not -Be 'Manual' -Because 'the old job keeps its schedule'
    }
    It 'a job of the daily job flow (no timer of its own): the producer joins the flow in its place, no schedule is touched' {
        $script:World = New-World -Jobs @(New-PlainJob 'endpoint' -Trigger Manual -Cron '0 4 * * *')
        $r = Invoke-Convert -Jobs @(New-PlainJob 'endpoint' -Trigger Manual -Cron '0 4 * * *')
        ($r.Results | Where-Object Engine -eq 'endpoint').Action | Should -Be 'converted'
        Get-Trigger 'caj-si-endpoint-producer' | Should -Be 'Manual'
        $script:World.Jobs['caj-si-endpoint-producer'].tags.'si-disabled-cron' | Should -Be '0 4 * * *'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'leaves a secret-by-choice install, an opted-out install and an install already on producer + worker alone -- no Azure call' {
        foreach ($case in @(
            @{ Jobs = @(New-PlainJob -Auth Secret); G = @{}; U = '' },
            @{ Jobs = @(New-PlainJob); G = @{ SI_Bootstrap_UseKEDA = $false }; U = '' },
            @{ Jobs = @(New-PlainJob); G = @{}; U = 'false' },
            @{ Jobs = @([pscustomobject]@{ name = 'caj-si-identity-producer' }, [pscustomobject]@{ name = 'caj-si-identity-worker' }); G = @{}; U = '' })) {
            $script:World = New-World -Jobs $case.Jobs
            $r = Invoke-Convert -Jobs $case.Jobs -Globals $case.G -UpdaterUseKeda $case.U
            @($script:World.Calls).Count | Should -Be 0
            @($r.Results | Where-Object { $_.Action -in 'converted', 'failed' }).Count | Should -Be 0
        }
        $script:World = New-World -Jobs @(New-PlainJob -Auth Secret)
        ((Invoke-Convert -Jobs @(New-PlainJob -Auth Secret)).Lines -join ' ') | Should -Match 'identity stays one scheduled job \(caj-si-identity\) -- its job signs in with a client secret'
    }
    It 'a failed worker create leaves the old job running on its schedule and says so; a failed producer create removes the worker again' {
        $script:World = New-World -Jobs @(New-PlainJob) -Fail @{ worker = $true }
        $r = Invoke-Convert -Jobs @(New-PlainJob)
        ($r.Results | Where-Object Engine -eq 'identity').Action | Should -Be 'failed'
        ($r.Lines -join ' ') | Should -Match 'identity was NOT moved \(the worker could not be created \(HTTP 400: worker refused\)\) -- it keeps running as the scheduled job caj-si-identity; the next update tries again'
        Get-Trigger 'caj-si-identity' | Should -Be 'Schedule'
        @($script:World.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0

        $script:World = New-World -Jobs @(New-PlainJob) -Fail @{ producer = $true }
        $null = Invoke-Convert -Jobs @(New-PlainJob)
        $script:World.Jobs.ContainsKey('caj-si-identity-worker') | Should -BeFalse
        Get-Trigger 'caj-si-identity' | Should -Be 'Schedule'
    }
    It 'a worker that reads back wrong or failed to provision, or a scaler role that cannot be granted: nothing changes on the old job' {
        $script:World = New-World -Jobs @(New-PlainJob) -Fail @{ readback = $true }
        $r = Invoke-Convert -Jobs @(New-PlainJob)
        ($r.Lines -join ' ') | Should -Match 'the worker runs .*si-orchestrator:other'
        $script:World.Jobs.Keys | Should -Not -Contain 'caj-si-identity-worker'
        Get-Trigger 'caj-si-identity' | Should -Be 'Schedule'

        $script:World = New-World -Jobs @(New-PlainJob) -Fail @{ provisioning = $true }
        ((Invoke-Convert -Jobs @(New-PlainJob)).Lines -join ' ') | Should -Match 'the worker was not created \(provisioning Failed\)'
        Get-Trigger 'caj-si-identity' | Should -Be 'Schedule'

        $script:World = New-World -Jobs @(New-PlainJob -Auth Cert) -HasRole $false -Fail @{ grant = $true }
        $r = Invoke-Convert -Jobs @(New-PlainJob -Auth Cert)
        ($r.Lines -join ' ') | Should -Match 'lacks Storage Queue Data Reader on the storage account'
        @($script:World.Calls | Where-Object { $_ -like 'PUT */jobs/*' }).Count | Should -Be 0
        # a missing role that CAN be granted is granted (built-in role id, the identity's object id), then the move goes on
        $script:World = New-World -Jobs @(New-PlainJob -Auth Cert) -HasRole $false
        ((Invoke-Convert -Jobs @(New-PlainJob -Auth Cert)).Results | Where-Object Engine -eq 'identity').Action | Should -Be 'converted'
        $g = @($script:World.Req | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like "https://management.azure.com$($script:Stg)/providers/Microsoft.Authorization/roleAssignments/*" })[0].Body | ConvertFrom-Json
        $g.properties.roleDefinitionId | Should -BeLike '*/roleDefinitions/19e7f393-937e-4f77-808e-94535e297925'
        $g.properties.principalId | Should -Be 'principal-1'
    }
    It 'the producer cannot take the schedule: the old job gets its schedule back, the new jobs are removed -- never two schedules, never none' {
        $script:World = New-World -Jobs @(New-PlainJob) -Fail @{ 'patch-caj-si-identity-producer-Schedule' = $true }
        $r = Invoke-Convert -Jobs @(New-PlainJob)
        ($r.Results | Where-Object Engine -eq 'identity').Action | Should -Be 'failed'
        Get-Trigger 'caj-si-identity' | Should -Be 'Schedule'
        $script:World.Jobs['caj-si-identity'].properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 4 * * *'
        $script:World.Jobs.Keys | Should -Not -Contain 'caj-si-identity-producer'
        $script:World.Jobs.Keys | Should -Not -Contain 'caj-si-identity-worker'
    }
    It 'the old job''s secrets travel with it (ARM listSecrets): values as values, Key Vault references as references' {
        $sec = @([pscustomobject]@{ name = 'si-license'; value = 'LIC' }, [pscustomobject]@{ name = 'openai-apikey'; keyVaultUrl = 'https://kv.vault.azure.net/secrets/OpenAI-ApiKey'; identity = $script:Uami })
        $script:World = New-World -Jobs @(New-PlainJob -Secrets $sec) -Secrets $sec
        $null = Invoke-Convert -Jobs @(New-PlainJob -Secrets $sec)
        @($script:World.Calls | Where-Object { $_ -like 'POST */jobs/caj-si-identity/listSecrets?*' }).Count | Should -Be 1
        foreach ($n in 'caj-si-identity-worker', 'caj-si-identity-producer') {
            $s = @((Get-PutBody $n).properties.configuration.secrets)
            ($s | Where-Object name -eq 'si-license').value | Should -Be 'LIC'
            ($s | Where-Object name -eq 'openai-apikey').keyVaultUrl | Should -Be 'https://kv.vault.azure.net/secrets/OpenAI-ApiKey'
            ($s | Where-Object name -eq 'openai-apikey').identity | Should -Be $script:Uami
        }
    }
    It '-WhatIf plans and sends nothing; nothing installed is one line; it never throws' {
        $script:World = New-World -Jobs @(New-PlainJob)
        $r = Invoke-Convert -Jobs @(New-PlainJob) -WhatIf
        @($script:World.Calls).Count | Should -Be 0
        ($r.Lines -join ' ') | Should -Match 'identity would move from one scheduled job \(caj-si-identity\) to a producer \(caj-si-identity-producer\) and queue-scaled workers \(caj-si-identity-worker\) \(re-run with -Apply\)'
        $script:World = New-World -Jobs @()
        (Invoke-Convert -Jobs @()).Lines | Should -Be @('queue scaling: no identity, endpoint or Azure job in this install -- nothing to move')
        { Invoke-SIKedaConvert -Rest { throw 'boom' } -SubscriptionId 's' -ResourceGroup 'r' -Jobs @(New-PlainJob) } | Should -Not -Throw
    }
}

Describe 'WIRING' {
    It 'NO az CLI and no PowerShell module in the converter: it never runs az, Invoke-RestMethod / Invoke-WebRequest or an Az cmdlet' {
        $path = Join-Path $script:SIRoot 'setup\_shared\SI-KedaConvert.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { [string]$_.GetCommandName() })
        @($cmds | Where-Object { $_ -match '^(?i)(az|az\.cmd|az\.exe)$' }).Count | Should -Be 0
        @($cmds | Where-Object { $_ -match '^(?i)(Invoke-RestMethod|Invoke-WebRequest|Import-Module|Connect-AzAccount)$' -or $_ -match '^(?i)[A-Za-z]+-Az[A-Z]' }).Count | Should -Be 0
        $src = [IO.File]::ReadAllText($path)
        $src | Should -Not -Match "&\s*az\s"
        $src | Should -Not -Match "\[string\[\]\]\`$AzArgs"
        # the step in the update script uses SecurityInsight's REST layer, not az
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $fn = [regex]::Match($h, '(?s)function Invoke-SIUpdateKedaConvert \{.*?\r?\n\}').Value
        # #521: the update's ONE REST seam (setup/_shared/SI-UpdateRest.ps1 over SI-AzRest.ps1), signed in once for the whole update
        $fn | Should -Match '\$kcRest = \$rest'
        $fn | Should -Match 'Get-SIArmJobList -Rest \$kcRest'
        $fn | Should -Not -Match '& az|Invoke-SIAz '
        $h | Should -Match 'Connect-SIUpdateRest -SubscriptionId \$sub'
        $h | Should -Match '\$rest = New-SIUpdateRestSeam'
    }
    It 'every update runs the step after the job size, on -DetectOnly as the plan, reading the customer''s opt-out' {
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $h | Should -Match 'function Complete-SIUpdate \{ \$null = Invoke-SIUpdateSqlTier; \$null = Invoke-SIUpdateJobFloor; \$null = Invoke-SIUpdateJobSizing; \$null = Invoke-SIUpdateUpdaterSize; \$null = Invoke-SIUpdateKedaConvert;'
        $h | Should -Match ([regex]::Escape("'SI_Bootstrap_UseKEDA', 'SI_Bootstrap_KedaMaxReplicas', 'SI_StorageAccount'"))
        # on for every install (owner 2026-10-10); SI_UPDATER_KEDA_CONVERT = off keeps an install on the plan only
        $h | Should -Match ([regex]::Escape("-match '^(?i)(0|false|off|no)$')"))
        $h | Should -Match ([regex]::Escape('$kcWhatIf = (-not $Apply -or $DetectOnly -or -not $kcOn)'))
        $h | Should -Match ([regex]::Escape("GetEnvironmentVariable('SI_UPDATER_KEDA_CONVERT')"))
        $h | Should -Match ([regex]::Escape("GetEnvironmentVariable('SI_UPDATER_USE_KEDA')"))
        $fn = [regex]::Match($h, '(?s)function Invoke-SIUpdateKedaConvert \{.*?\r?\n\}').Value
        $fn | Should -Match 'catch \{ Warn'
    }
    It 'Bootstrap and the update create the jobs through the same definitions' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $b | Should -Match 'Get-SIKedaWorkerCreateArgs -Name \$jobName'
        $b | Should -Match 'Get-SIKedaProducerCreateArgs -Name \$producerName'
        $k = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-KedaConvert.ps1'))
        $k | Should -Match 'Get-SIKedaWorkerCreateArgs -Name \$workerName'
        $k | Should -Match 'Get-SIKedaProducerCreateArgs -Name \$producerName'
        $k | Should -Match 'ConvertFrom-SIJobCreateArgs -CreateArgs \$w'
        $k | Should -Not -Match "'--trigger-type','Event'"
    }
}
