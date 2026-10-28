#Requires -Version 5.1
<#
    SETUP OFF THE AZ CLI (#521 phase 2) -- setup\_shared\SI-SetupArm.ps1 (the resources setup creates and changes) and
    setup\_shared\SI-AcrBuild.ps1 (phase 1's image build, wrapped by Invoke-SIAcrRestBuild), against a fake Azure behind the one HTTP seam (Invoke-SIAzRestHttp):
      * Container Apps jobs are READ-MODIFY-WRITE: the job read whole, its secret values read back (listSecrets), ONE PUT
        that keeps what was not asked to change (command, args, probes, other identities, a Manual job's trigger)
      * a job is created from Bootstrap's own create arguments (ConvertFrom-SIJobCreateArgs) with the environment's id
      * the image build: the .dockerignore honoured (customer config never uploaded), a tar.gz that reads back, the upload
        to the SAS URL WITHOUT a bearer token and WITH x-ms-blob-type, image names relative to the registry, Queued /
        Running = still going
      * SI-SqlTier's -Az contract answered over REST (New-SISqlTierRestAz), the overlay share over the blob REST API
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:GlobalNames = 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_SetupSignInState', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret'
    $script:keepAll = @{}
    foreach ($n in $script:GlobalNames) { $script:keepAll[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    $script:hadGlobalToken = [bool](Get-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-AcrBuild.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1')
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerRunState.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:JobId = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity"
    function script:Resp([int]$Code, $Obj, [hashtable]$Headers = @{}) {
        $c = if ($null -eq $Obj) { '' } elseif ($Obj -is [string]) { $Obj } else { $Obj | ConvertTo-Json -Depth 30 -Compress }
        [pscustomobject]@{ StatusCode = $Code; Content = $c; Bytes = $null; Headers = $Headers; RetryAfter = '' }
    }
    function script:New-ExistingJob {
        [pscustomobject]@{
            id = $script:JobId; name = 'caj-si-identity'; location = 'westeurope'; type = 'Microsoft.App/jobs'
            systemData = [pscustomobject]@{ createdBy = 'x' }
            tags = [pscustomobject]@{ 'si-build' = 'v3.0.1'; 'si-disabled-cron' = '30 4 * * *' }
            identity = [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ '/id/old' = [pscustomobject]@{ principalId = 'p'; clientId = 'c' } } }
            properties = [pscustomobject]@{
                provisioningState = 'Succeeded'; environmentId = '/env/cae'
                configuration = [pscustomobject]@{
                    triggerType = 'Schedule'; replicaTimeout = 1800; replicaRetryLimit = 1
                    scheduleTriggerConfig = [pscustomobject]@{ cronExpression = '30 4 * * *'; parallelism = 1; replicaCompletionCount = 1 }
                    secrets = @([pscustomobject]@{ name = 'si-spn-secret' }, [pscustomobject]@{ name = 'shodan-key'; keyVaultUrl = 'https://kv/secrets/s'; identity = '/id/old' }, [pscustomobject]@{ name = 'si-license' })
                    registries = @([pscustomobject]@{ server = 'acr.azurecr.io'; username = 'acr'; passwordSecretRef = 'acr-pw' })
                }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{
                    name = 'caj-si-identity'; image = 'acr.azurecr.io/si-orchestrator:old'; command = @('pwsh'); args = @('-File', '/app/x.ps1')
                    probes = @([pscustomobject]@{ type = 'Liveness' })
                    resources = [pscustomobject]@{ cpu = 0.5; memory = '1Gi'; ephemeralStorage = '2Gi' }
                    env = @([pscustomobject]@{ name = 'OLD'; value = '1' }, [pscustomobject]@{ name = 'SI_SPN_SECRET'; secretRef = 'si-spn-secret' }) }) }
            }
        }
    }
}

AfterAll {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keepAll[$n] }
    if (-not $script:hadGlobalToken) { Remove-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue }
}

Describe 'SIv3-SetupArmRest' {
BeforeEach {
    foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
    $global:SI_AzureAccess_Engine = 'Rest'
    $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'tid-1'; $global:SI_SPN_Secret = 's'
    (Get-SIAzRestState).SubscriptionId = $script:Sub
    (Get-SIAzRestState).TenantId = 'tid-1'
    $script:Calls = [System.Collections.Generic.List[object]]::new()
    $script:Handler = $null
    Mock Get-SILogIngestToken { 'tok|' + $Resource }
    Mock Invoke-SIAzRestHttp {
        $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Body = $Body })
        if ($script:Handler) { $r = & $script:Handler $Method $Uri $Body $Headers; if ($r) { return $r } }
        return (Resp 404 '{"error":{"code":"NotFound","message":"not in the fake"}}')
    }
    Mock Start-Sleep { }
}

Context 'Container Apps jobs: READ-MODIFY-WRITE' {
    It 'Merge keeps what was not asked to change and changes exactly what was' {
        $vals = @{ 'si-spn-secret' = [pscustomobject]@{ name = 'si-spn-secret'; value = 'S3CRET' }; 'si-license' = [pscustomobject]@{ name = 'si-license'; value = 'LIC' } }
        $b = Merge-SIContainerAppJobUpdate -Job (New-ExistingJob) -SecretValues $vals -Image 'acr.azurecr.io/si-orchestrator:new' -Cpu '1.5' -Memory '3Gi' `
            -Env @('A=1', 'SI_LICENSE=secretref:si-license') -Cron '0 5 * * *' -ReplicaTimeout 7200 -Tags @('si-build=v3.0.2') `
            -SetSecrets @('openai-apikey=keyvaultref:https://kv/secrets/oa,identityref:/id/new') -RemoveSecrets @('si-spn-secret') `
            -AddIdentity '/id/new' -RegistryServer 'acr.azurecr.io' -RegistryIdentity '/id/new'
        $b.Contains('systemData') | Should -BeFalse
        $b.properties.Contains('provisioningState') | Should -BeFalse
        $c = $b.properties.template.containers[0]
        $c.image | Should -Be 'acr.azurecr.io/si-orchestrator:new'
        @($c.command) | Should -Be @('pwsh')
        @($c.args) | Should -Be @('-File', '/app/x.ps1')
        @($c.probes).Count | Should -Be 1
        $c.resources.cpu | Should -Be 1.5
        $c.resources.memory | Should -Be '3Gi'
        @($c.env | ForEach-Object { $_.name }) | Should -Be @('A', 'SI_LICENSE')
        @($c.env)[1].secretRef | Should -Be 'si-license'
        $cfg = $b.properties.configuration
        $cfg.scheduleTriggerConfig.cronExpression | Should -Be '0 5 * * *'
        $cfg.replicaTimeout | Should -Be 7200
        $names = @($cfg.secrets | ForEach-Object { $_.name })
        $names | Should -Not -Contain 'si-spn-secret'
        $names | Should -Contain 'shodan-key'
        @($cfg.secrets | Where-Object { $_.name -eq 'si-license' })[0].value | Should -Be 'LIC'
        @($cfg.secrets | Where-Object { $_.name -eq 'shodan-key' })[0].keyVaultUrl | Should -Be 'https://kv/secrets/s'
        @($cfg.secrets | Where-Object { $_.name -eq 'openai-apikey' })[0].identity | Should -Be '/id/new'
        @($cfg.registries).Count | Should -Be 1
        @($cfg.registries)[0].identity | Should -Be '/id/new'
        @($b.identity.userAssignedIdentities.Keys) | Should -Be @('/id/old', '/id/new')
        $b.tags['si-build'] | Should -Be 'v3.0.2'
        $b.tags['si-disabled-cron'] | Should -Be '30 4 * * *'
    }
    It 'a Manual job keeps its trigger: no timer is written into it' {
        $j = New-ExistingJob
        $j.properties.configuration.triggerType = 'Manual'
        $j.properties.configuration.PSObject.Properties.Remove('scheduleTriggerConfig')
        $b = Merge-SIContainerAppJobUpdate -Job $j -Cron '0 5 * * *'
        $b.properties.configuration.triggerType | Should -Be 'Manual'
        $b.properties.configuration.Contains('scheduleTriggerConfig') | Should -BeFalse
    }
    It 'the queue scale rule of that name is replaced, other rules stay' {
        $j = New-ExistingJob
        $j.properties.configuration.triggerType = 'Event'
        $j.properties.configuration | Add-Member -NotePropertyName eventTriggerConfig -NotePropertyValue ([pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1
            scale = [pscustomobject]@{ minExecutions = 0; maxExecutions = 30; pollingInterval = 30; rules = @([pscustomobject]@{ name = 'si-shards-queue'; type = 'azure-queue'; metadata = [pscustomobject]@{ queueName = 'old' } }, [pscustomobject]@{ name = 'other'; type = 'cron' }) } })
        $rule = ConvertFrom-SIScaleRuleArgs -ScaleArgs @(Get-SIKedaQueueScaleArgs -Engine 'identity' -StorageAccount 'stsi' -IdentityResourceId '/id/new')
        $b = Merge-SIContainerAppJobUpdate -Job $j -ScaleRule $rule
        $rules = @($b.properties.configuration.eventTriggerConfig.scale.rules)
        @($rules | ForEach-Object { $_.name }) | Should -Be @('other', 'si-shards-queue')
        $q = @($rules | Where-Object { $_.name -eq 'si-shards-queue' })[0]
        $q.metadata.queueName | Should -Be 'si-identity-shards'
        $q.metadata.accountName | Should -Be 'stsi'
        $q.identity | Should -Be '/id/new'
    }
    It 'Update-SIContainerAppJob: GET, listSecrets, ONE PUT of the whole job with the secret values -- no az' {
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'GET' -and $u -like "https://management.azure.com$($script:JobId)?api-version=2025-07-01") { return (Resp 200 (New-ExistingJob)) }
            if ($m -eq 'POST' -and $u -like "*caj-si-identity/listSecrets?*") { return (Resp 200 @{ value = @(@{ name = 'si-spn-secret'; value = 'S3CRET' }, @{ name = 'si-license'; value = 'LIC' }, @{ name = 'shodan-key'; keyVaultUrl = 'https://kv/secrets/s'; identity = '/id/old' }) }) }
            if ($m -eq 'PUT') { return (Resp 200 @{ id = $script:JobId; properties = @{ provisioningState = 'Succeeded' } }) }
        }
        $null = Update-SIContainerAppJob -ResourceGroupName 'rg-si' -Name 'caj-si-identity' -Image 'acr.azurecr.io/si-orchestrator:new' -Env @('A=1')
        $puts = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
        $puts.Count | Should -Be 1
        $body = $puts[0].Body | ConvertFrom-Json
        @($body.properties.configuration.secrets | Where-Object { $_.name -eq 'si-spn-secret' })[0].value | Should -Be 'S3CRET'
        $body.properties.template.containers[0].image | Should -Be 'acr.azurecr.io/si-orchestrator:new'
        @($body.properties.template.containers[0].command) | Should -Be @('pwsh')
    }
    It 'a refusal because a new identity''s pull right has not arrived is waited out, then written' {
        $script:n = 0
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'PUT') { $script:n++; if ($script:n -eq 1) { return (Resp 400 '{"error":{"code":"InvalidParameterValueInContainerTemplate","message":"unable to pull image using Managed identity /id/new"}}') }; return (Resp 200 @{ id = $script:JobId }) }
            if ($m -eq 'GET') { return (Resp 200 @{ id = $script:JobId; properties = @{ provisioningState = 'Succeeded' } }) }
        }
        $null = Set-SIContainerAppJob -JobId $script:JobId -Body @{ properties = @{} } -Sleep { }
        $script:n | Should -Be 2
        Test-SIContainerAppIdentityNotReady 'cpu must be 0.25 to 4' | Should -BeFalse
    }
    It 'a job is created from Bootstrap''s create arguments with the environment''s id' {
        $script:Handler = { param($m, $u, $b) if ($m -eq 'PUT' -or $m -eq 'GET') { return (Resp 200 @{ id = 'x'; properties = @{ provisioningState = 'Succeeded' } }) } }
        $args1 = @(Get-SIKedaProducerCreateArgs -Name 'caj-si-identity-producer' -ResourceGroup 'rg-si' -Environment 'cae-si' -Cron '0 4 * * *' -Image 'acr.azurecr.io/si:v3' -LoginServer 'acr.azurecr.io') +
            @('--tags', 'si-build=v3', '--registry-identity', '/id/new', '--mi-user-assigned', '/id/new', '--env-vars', 'A=1')
        $null = New-SIContainerAppJobFromArgs -CreateArgs $args1 -Location 'westeurope' -EnvironmentId '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.App/managedEnvironments/cae-si'
        $put = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put.Uri | Should -BeLike "https://management.azure.com/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.App/jobs/caj-si-identity-producer?api-version=2025-07-01"
        $body = $put.Body | ConvertFrom-Json
        $body.properties.environmentId | Should -BeLike '*/managedEnvironments/cae-si'
        $body.location | Should -Be 'westeurope'
        $body.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '0 4 * * *'
        $body.properties.configuration.registries[0].identity | Should -Be '/id/new'
    }
    It 'a run limit above 24 hours that Azure refuses at CREATE is sent once more as 24 hours (the size and the rest unchanged, the worker''s queue lease with it); the next job of the run asks for 24 hours at once; the install does not fail' {
        Set-SIRunLimitRefused -Value $false
        try {
            $script:Handler = { param($m, $u, $b)
                if ($m -eq 'PUT') {
                    if ([int](($b | ConvertFrom-Json).properties.configuration.replicaTimeout) -gt 86400) { return (Resp 400 '{"error":{"code":"InvalidRequestParameterWithDetails","message":"ReplicaTimeout must be between 1 and 86400"}}') }
                    return (Resp 200 @{ id = 'x'; properties = @{ provisioningState = 'Succeeded' } })
                }
                if ($m -eq 'GET') { return (Resp 200 @{ id = 'x'; properties = @{ provisioningState = 'Succeeded' } }) }
            }
            $envId = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.App/managedEnvironments/cae-si'
            $worker = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-identity-worker' -ResourceGroup 'rg-si' -Environment 'cae-si' -Image 'acr.azurecr.io/si:v3' -LoginServer 'acr.azurecr.io' -ReplicaTimeout 259200 -Cpu '4.0' -Memory '8.0Gi' -Engine 'identity' -StorageAccount 'stsi' -IdentityResourceId '/id/new') +
                @('--registry-identity', '/id/new', '--mi-user-assigned', '/id/new', '--env-vars', 'A=1') + @(Get-SIKedaQueueLeaseEnvArgs -ReplicaTimeout 259200)
            $out = New-SIContainerAppJobFromArgs -CreateArgs $worker -Location 'westeurope' -EnvironmentId $envId 6>&1
            $puts = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
            $puts.Count | Should -Be 2
            ($puts[0].Body | ConvertFrom-Json).properties.configuration.replicaTimeout | Should -Be 259200
            $b2 = $puts[1].Body | ConvertFrom-Json
            $b2.properties.configuration.replicaTimeout | Should -Be 86400
            $c = $b2.properties.template.containers[0]
            [double]$c.resources.cpu | Should -Be 4.0; $c.resources.memory | Should -Be '8.0Gi'
            @($c.env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' })[0].value | Should -Be '86700'
            @($c.env | Where-Object { $_.name -eq 'A' })[0].value | Should -Be '1'
            (@($out) -join "`n") | Should -Match 'Azure did not accept a run limit of 72 hours for caj-si-identity-worker; it keeps 24 hours\.'
            Test-SIRunLimitRefused | Should -BeTrue
            # the next job of the same run: ONE request, 24 hours
            $script:Calls.Clear()
            $prod = @(Get-SIKedaProducerCreateArgs -Name 'caj-si-identity-producer' -ResourceGroup 'rg-si' -Environment 'cae-si' -Cron '0 4 * * *' -Image 'acr.azurecr.io/si:v3' -LoginServer 'acr.azurecr.io' -ReplicaTimeout 259200) +
                @('--registry-identity', '/id/new', '--mi-user-assigned', '/id/new', '--env-vars', 'A=1')
            $null = New-SIContainerAppJobFromArgs -CreateArgs $prod -Location 'westeurope' -EnvironmentId $envId 6>&1
            $puts = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
            $puts.Count | Should -Be 1
            ($puts[0].Body | ConvertFrom-Json).properties.configuration.replicaTimeout | Should -Be 86400
        } finally { Set-SIRunLimitRefused -Value $false }
    }
    It 'an accepted long run limit is ONE request; NEGATIVE: a create refused for another reason still fails, with its own error, and nothing is remembered' {
        Set-SIRunLimitRefused -Value $false
        $ok = { param($m, $u, $b) if ($m -eq 'PUT' -or $m -eq 'GET') { return (Resp 200 @{ id = 'x'; properties = @{ provisioningState = 'Succeeded' } }) } }
        $script:Handler = $ok
        $args1 = @(Get-SIKedaProducerCreateArgs -Name 'caj-si-identity-producer' -ResourceGroup 'rg-si' -Environment 'cae-si' -Cron '0 4 * * *' -Image 'acr.azurecr.io/si:v3' -LoginServer 'acr.azurecr.io' -ReplicaTimeout 259200) +
            @('--registry-identity', '/id/new', '--mi-user-assigned', '/id/new', '--env-vars', 'A=1')
        $null = New-SIContainerAppJobFromArgs -CreateArgs $args1 -Location 'westeurope' -EnvironmentId '/env/cae'
        $puts = @($script:Calls | Where-Object { $_.Method -eq 'PUT' })
        $puts.Count | Should -Be 1
        ($puts[0].Body | ConvertFrom-Json).properties.configuration.replicaTimeout | Should -Be 259200
        $script:Calls.Clear()
        $script:Handler = { param($m, $u, $b) if ($m -eq 'PUT') { return (Resp 400 '{"error":{"code":"InvalidParameterValueInContainerTemplate","message":"cpu must be 0.25 to 4"}}') } }
        { New-SIContainerAppJobFromArgs -CreateArgs $args1 -Location 'westeurope' -EnvironmentId '/env/cae' } | Should -Throw '*cpu must be 0.25 to 4*'
        @($script:Calls | Where-Object { $_.Method -eq 'PUT' }).Count | Should -Be 2 -Because 'tried once more with 24 hours, refused again: the run limit was not the cause'
        Test-SIRunLimitRefused | Should -BeFalse
    }
    It 'a job is started (with an execution template) and removed over ARM' {
        $script:Handler = { param($m, $u, $b) if ($m -in 'POST', 'DELETE') { return (Resp 200 @{ id = 'e'; name = 'caj-si-flow-abc' }) } }
        $e = Start-SIContainerAppJob -ResourceGroupName 'rg-si' -Name 'caj-si-flow' -Template @{ containers = @(@{ name = 'caj-si-flow'; env = @(@{ name = 'SI_FLOW_FORCE'; value = '1' }) }) }
        $e.name | Should -Be 'caj-si-flow-abc'
        $c = @($script:Calls | Where-Object { $_.Method -eq 'POST' })[0]
        $c.Uri | Should -BeLike '*/Microsoft.App/jobs/caj-si-flow/start?api-version=2025-07-01'
        $c.Body | Should -Match 'SI_FLOW_FORCE'
        Remove-SIContainerAppJob -ResourceGroupName 'rg-si' -Name 'caj-si-old'
        @($script:Calls | Where-Object { $_.Method -eq 'DELETE' })[0].Uri | Should -BeLike '*/jobs/caj-si-old?*'
    }
    It 'the web app''s environment variable is set READ-MODIFY-WRITE (the whole template, other containers kept)' {
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'GET') { return (Resp 200 @{ id = '/x/containerApps/ca-si-management'; properties = @{ provisioningState = 'Succeeded'; template = @{ containers = @(@{ name = 'web'; image = 'i'; env = @(@{ name = 'X'; value = '1' }) }, @{ name = 'side'; image = 's' }) } } }) }
            if ($m -eq 'PATCH') { return (Resp 200 @{}) }
        }
        Set-SIContainerAppEnvVar -ResourceGroupName 'rg-si' -Name 'ca-si-management' -SetEnv @('Access__GraphLookup=true') | Should -BeTrue
        $p = @($script:Calls | Where-Object { $_.Method -eq 'PATCH' })[0].Body | ConvertFrom-Json
        @($p.properties.template.containers).Count | Should -Be 2
        @($p.properties.template.containers[0].env | ForEach-Object { $_.name }) | Should -Be @('X', 'Access__GraphLookup')
    }
}

Context 'registry, environment, Key Vault, role assignments, SQL' {
    It 'creates the registry and environment over ARM with the bodies az sent' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*registries/acrsi?*') { return (Resp 200 @{ id = '/r/acrsi'; properties = @{ loginServer = 'acrsi.azurecr.io'; provisioningState = 'Succeeded' } }) }
            if ($u -like '*managedEnvironments/cae-si?*') { return (Resp 200 @{ id = '/e/cae-si'; properties = @{ provisioningState = 'Succeeded' } }) }
        }
        (New-SIContainerRegistry -ResourceGroupName 'rg-si' -Name 'acrsi' -Location 'westeurope').loginServer | Should -Be 'acrsi.azurecr.io'
        $null = New-SIManagedEnvironment -ResourceGroupName 'rg-si' -Name 'cae-si' -Location 'westeurope' -Sleep { }
        $acrPut = @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*registries*' })[0].Body | ConvertFrom-Json
        $acrPut.sku.name | Should -Be 'Basic'
        $acrPut.properties.adminUserEnabled | Should -BeTrue
        $envPut = @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and $_.Uri -like '*managedEnvironments*' })[0].Body | ConvertFrom-Json
        $envPut.properties.appLogsConfiguration.destination | Should -Be 'azure-monitor'
    }
    It 'lists a vault''s secret NAMES over every page; unreadable = $null, empty = an empty list' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like 'https://kv-si.vault.azure.net/secrets?api-version=7.4&maxresults=25') { return (Resp 200 @{ value = @(@{ id = 'https://kv-si.vault.azure.net/secrets/SI-License' }); nextLink = 'https://kv-si.vault.azure.net/secrets?page=2' }) }
            if ($u -like 'https://kv-si.vault.azure.net/secrets?page=2') { return (Resp 200 @{ value = @(@{ id = 'https://kv-si.vault.azure.net/secrets/SI-Shodan-ApiKey' }) }) }
            if ($u -like 'https://kv-empty*') { return (Resp 200 @{ value = @() }) }
            if ($u -like 'https://kv-locked*') { return (Resp 403 '{"error":{"code":"Forbidden"}}') }
        }
        $names = Get-SIKeyVaultSecretNames -VaultName 'kv-si'
        ($names -join ',') | Should -Be 'SI-License,SI-Shodan-ApiKey'
        $empty = Get-SIKeyVaultSecretNames -VaultName 'kv-empty'
        $null -eq $empty | Should -BeFalse
        @($empty).Count | Should -Be 0
        Get-SIKeyVaultSecretNames -VaultName 'kv-locked' | Should -BeNullOrEmpty
    }
    It 'a role is present when the principal holds it at the scope or above' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/roleDefinitions?*') { return (Resp 200 @{ value = @(@{ name = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'; properties = @{ roleName = 'Reader' } }) }) }
            if ($u -like '*/roleAssignments?*') { return (Resp 200 @{ value = @(@{ properties = @{ roleDefinitionId = '/x/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'; scope = "/subscriptions/$($script:Sub)" } }) }) }
        }
        Test-SIRoleAssignmentPresent -ObjectId 'p1' -Scope "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -RoleDefinitionName 'Reader' | Should -BeTrue
        Test-SIRoleAssignmentPresent -ObjectId 'p1' -Scope "/subscriptions/$($script:Sub)/resourceGroups/rg-si" -RoleDefinitionName 'Owner' | Should -BeFalse
    }
    It 'a SQL server is Entra-only from the first second, the database at the target size with local backups' {
        $b = Get-SISqlServerEntraOnlyBody -Location 'westeurope' -AdminName 'admin@contoso' -AdminSid 'oid-1' -AdminType 'Application'
        $b.properties.administrators.azureADOnlyAuthentication | Should -BeTrue
        $b.properties.administrators.principalType | Should -Be 'Application'
        $d = Get-SISqlDatabaseCreateBody -Location 'westeurope' -Target ([pscustomobject]@{ Name = 'S2'; Tier = 'Standard'; Capacity = 50; MaxSizeBytes = 268435456000 })
        $d.sku.name | Should -Be 'S2'
        $d.properties.maxSizeBytes | Should -Be 268435456000
        $d.properties.requestedBackupStorageRedundancy | Should -Be 'Local'
    }
}

Context 'the image build (az acr build over REST): ONE implementation -- phase 1''s SI-AcrBuild.ps1, wrapped for setup' {
    It 'packs, uploads WITHOUT a bearer token, schedules a registry-relative image and waits through Queued / Running' {
        $src = Join-Path $TestDrive 'b'; New-Item -ItemType Directory -Force -Path (Join-Path $src 'container') | Out-Null
        Set-Content -LiteralPath (Join-Path $src 'container\Dockerfile') -Value 'FROM x'
        Set-Content -LiteralPath (Join-Path $src 'a.custom.ps1') -Value 'secret'
        Set-Content -LiteralPath (Join-Path $src '.dockerignore') -Value '**/*.custom.ps1'
        $script:status = @('Queued', 'Running', 'Succeeded'); $script:poll = 0
        $script:RestCalls = [System.Collections.Generic.List[object]]::new()
        $rest = { param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
            $script:RestCalls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Resource = $Resource; Headers = $Headers; Body = $Body })
            $ok = { param($o) [pscustomobject]@{ Status = 200; Body = $(if ($o -is [string]) { $o } else { $o | ConvertTo-Json -Depth 10 -Compress }); Headers = @{} } }
            if ($Uri -like '*/registries/acrsi[?]*') { return (& $ok @{ id = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.ContainerRegistry/registries/acrsi'; name = 'acrsi'; properties = @{ loginServer = 'acrsi.azurecr.io'; publicNetworkAccess = 'Enabled' } }) }
            if ($Uri -like '*/listBuildSourceUploadUrl[?]*') { return (& $ok @{ uploadUrl = 'https://acrtask.blob.core.windows.net/src/ctx.tar.gz?sig=SAS'; relativePath = 'source/ctx.tar.gz' }) }
            if ($Uri -like 'https://acrtask.blob.core.windows.net/*') { return [pscustomobject]@{ Status = 201; Body = ''; Headers = @{} } }
            if ($Uri -like '*/scheduleRun[?]*') { return (& $ok @{ properties = @{ runId = 'ca1' } }) }
            if ($Uri -like '*/runs/ca1[?]*') { $s = $script:status[[Math]::Min($script:poll, 2)]; $script:poll++; return (& $ok @{ properties = @{ status = $s } }) }
            [pscustomobject]@{ Status = 404; Body = '{}'; Headers = @{} }
        }
        $r = Invoke-SIAcrRestBuild -SubscriptionId 's' -ResourceGroup 'rg-si' -RegistryName 'acrsi' -SourcePath $src -ImageNames @('si-orchestrator:v3') -DockerFilePath 'container/Dockerfile' -Rest $rest -Sleep { }
        $r.Ok | Should -BeTrue
        $r.Status | Should -Be 'Succeeded'
        $script:poll | Should -Be 3
        $up = @($script:RestCalls | Where-Object { $_.Uri -like 'https://acrtask.blob.core.windows.net/*' })[0]
        $up.Method | Should -Be 'PUT'
        $up.Resource | Should -BeNullOrEmpty -Because 'the SAS is the credential: no bearer token'
        $up.Headers['x-ms-blob-type'] | Should -Be 'BlockBlob'
        $run = @($script:RestCalls | Where-Object { $_.Uri -like '*/scheduleRun?*' })[0].Body | ConvertFrom-Json
        @($run.imageNames) | Should -Be @('si-orchestrator:v3')
        $run.dockerFilePath | Should -Be 'container/Dockerfile'
    }
    It 'Bootstrap and the updater-job installer build through it; there is ONE SI-AcrBuild.ps1 (phase 1''s)' {
        $arm = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-SetupArm.ps1'))
        $arm | Should -Match 'Invoke-SIAcrQueueBuild -Rest \$Rest'
        $arm | Should -Match 'Get-SIAcrRunStatus -Rest \$Rest'
        (Get-Command Invoke-SIAcrQueueBuild).ScriptBlock.File | Should -BeLike '*setup*_shared*SI-AcrBuild.ps1'
    }
}
Context 'the customisation share (overlay) over the blob REST API' {
    It 'Bootstrap shares the files through phase 1''s -Rest path (the update''s REST seam) -- never the az seam' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $b | Should -Match ([regex]::Escape('Publish-SIContainerOverlay -Root $PSScriptRoot -AccountName ([string]$global:SI_StorageAccount) -Rest (New-SIUpdateRestSeam)'))
        $b | Should -Not -Match 'Publish-SIContainerOverlay[^\r\n]*-Az '
    }
}
}