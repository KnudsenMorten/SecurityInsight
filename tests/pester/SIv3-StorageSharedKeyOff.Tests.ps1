#Requires -Version 5.1
<#
    SHARED-KEY ACCESS OFF ON SECURITYINSIGHT'S STORAGE -- managed identity / Entra ID only.

    Operator 2026-10-05: "shared storage off new, use mi". What must hold:
      * every install path that CREATES the storage account creates it with allowSharedKeyAccess = false,
        defaultToOAuthAuthentication = true, TLS 1.2 and no public blob access (Bootstrap-Storage end to end on a fake
        Azure Resource Manager; Initialize-SIInfra through the same create gate --
        a collection run creates no storage account at all);
      * an EXISTING account is not changed automatically: setup\Set-SIStorageSharedKey.ps1 reports, and -Disable switches
        it off only when nothing still uses a key (key / SAS traffic, a queue scaler without an identity, an older
        release's key secret or setting, an identity without the data roles) -- otherwise it refuses and changes nothing;
      * a KEDA worker's queue scaler signs in with the jobs' managed identity (--scale-rule-identity) on create AND on
        update; the Secret sign-in (no identity) is refused for queue scaling; in Certificate mode the identity is
        granted queue read for the scaler.

    OFFLINE. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-StorageSharedKey.ps1')

    $script:Acct = 'stsitest01'
    $script:Uami = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-securityinsight'
    $script:Principal = '11111111-2222-3333-4444-555555555555'
    function script:New-TestJob {
        param([string]$Name = 'caj-si-endpoint-worker', [object[]]$Rules = @(), [string[]]$Secrets = @(), [hashtable]$Env = @{})
        $e = @{ SI_StorageAccount = $script:Acct; SI_SPN_OBJECTID = $script:Principal }
        foreach ($k in $Env.Keys) { $e[$k] = $Env[$k] }
        [pscustomobject]@{
            name = $Name
            properties = [pscustomobject]@{
                configuration = [pscustomobject]@{
                    secrets = @($Secrets | ForEach-Object { [pscustomobject]@{ name = $_ } })
                    eventTriggerConfig = [pscustomobject]@{ scale = [pscustomobject]@{ rules = @($Rules) } }
                }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = $Name; env = @($e.Keys | ForEach-Object { [pscustomobject]@{ name = $_; value = $e[$_] } }) }) }
            }
        }
    }
    function script:New-TestRule([string]$Identity = $script:Uami, [object[]]$Auth = @()) {
        [pscustomobject]@{ name = 'si-shards-queue'; type = 'azure-queue'; identity = $Identity; auth = @($Auth)
            metadata = [pscustomobject]@{ queueName = 'si-endpoint-shards'; accountName = $script:Acct; queueLength = '1' } }
    }
    function script:New-TestRoles([string]$Principal = $script:Principal, [string[]]$RoleIds = @('ba92f5b4-2d11-453d-a403-e96b0029c9fe', '974c5e8b-45b9-4653-ba55-5f855dd0fb88', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')) {
        foreach ($r in $RoleIds) {
            [pscustomobject]@{ properties = [pscustomobject]@{ principalId = $Principal; roleDefinitionId = "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/$r" } }
        }
    }
    function script:New-TestMetrics([hashtable]$Totals) {
        [pscustomobject]@{ value = @([pscustomobject]@{ timeseries = @($Totals.Keys | ForEach-Object {
            [pscustomobject]@{ metadatavalues = @([pscustomobject]@{ name = [pscustomobject]@{ value = 'authentication' }; value = $_ })
                               data = @([pscustomobject]@{ total = $Totals[$_] / 2 }, [pscustomobject]@{ total = $Totals[$_] / 2 }, [pscustomobject]@{ timeStamp = 'x' }) } }) }) }
    }
}

Describe 'every install path that creates the storage account creates it with shared-key access off' {
    It 'the create properties are the locked-down set' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
        $p = Get-SIStorageAccountCreateProperties
        $p.allowSharedKeyAccess | Should -BeFalse
        $p.defaultToOAuthAuthentication | Should -BeTrue
        $p.minimumTlsVersion | Should -Be 'TLS1_2'
        $p.allowBlobPublicAccess | Should -BeFalse
        $p.supportsHttpsTrafficOnly | Should -BeTrue
    }

    It 'WIRING -- <_> creates the account through the one create gate (New-SIAzStorageAccount)' -ForEach @(
        'Bootstrap-Storage.ps1', 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1'
    ) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $_), [ref]$null, [ref]$null)
        $calls = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-SIAzStorageAccount' }, $true))
        $calls.Count | Should -Be 1
    }

    It 'WIRING -- the guided install (free and Pro) creates storage only through Initialize-SIInfra' {
        foreach ($rel in 'setup\_shared\SI-GuidedInstall.ps1', 'setup\_shared\SI-GuidedInstallData.ps1', 'setup\_shared\SI-GuidedInstallPro.ps1') {
            # the Pro guided install is not in a Community copy: checked where it exists (Test-Path), never loaded
            if (-not (Test-Path -LiteralPath (Join-Path $script:SIRoot $rel))) { continue }
            $c = Get-Content -LiteralPath (Join-Path $script:SIRoot $rel) -Raw
            $c | Should -Not -Match 'New-SIAzStorageAccount|''storage''\s*,\s*''account''\s*,\s*''create'''
        }
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1') -Raw) | Should -Match "RelativePath 'setup/ConfigWizard/backend/Initialize-SIInfra.ps1'"
    }

    Context 'Bootstrap-Storage end to end on a fake Azure Resource Manager -- a NEW account' {
        BeforeAll {
            . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
            $script:keepEngine = $global:SI_AzureAccess_Engine; $script:keepIngest = $global:SI_LogIngest_Engine
        }
        AfterAll {
            $global:SI_AzureAccess_Engine = $script:keepEngine; $global:SI_LogIngest_Engine = $script:keepIngest
            Remove-Variable -Scope Global -Name SI_AzRestState, SISkoFake -ErrorAction SilentlyContinue
        }
        It 'PUTs the account with allowSharedKeyAccess = false, defaultToOAuthAuthentication = true, TLS 1.2, no public blob' {
            $global:SISkoFake = [System.Collections.Generic.List[object]]::new()
            Mock Connect-SISetupAzure { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'sub one' }; Tenant = [pscustomobject]@{ Id = 't1' } } }
            Mock Get-SISetupSubscriptionId { 'sub-1' }
            Mock Get-SIAzRestSubscriptionId { 'sub-1' }
            Mock Get-SIAzStorageAccount { $null }
            Mock New-SIAzStorageContextRest { [pscustomobject]@{ StorageAccountName = 'stsitest01' } }
            Mock Start-Sleep { }
            Mock Invoke-SIArm {
                $m = if ($Method) { $Method } else { 'GET' }
                $global:SISkoFake.Add([pscustomobject]@{ Method = $m; Path = $Path; Body = $Body })
                if ($Path -like '*/managementPolicies/default') { if ($m -eq 'GET') { return $null }; return [pscustomobject]@{ id = $Path; properties = $Body.properties } }
                if ($Path -match '/storageAccounts/[^/]+$' -and $m -eq 'GET') {
                    return [pscustomobject]@{ name = 'stsitest01'; id = $Path; location = 'westeurope'; properties = [pscustomobject]@{ provisioningState = 'Succeeded'; primaryEndpoints = [pscustomobject]@{ blob = 'https://stsitest01.blob.core.windows.net/' } } }
                }
                if ($m -eq 'GET') { return $null }
                return [pscustomobject]@{ name = ($Path -split '/')[-1]; id = $Path }
            }
            $null = & (Join-Path $script:SIRoot 'Bootstrap-Storage.ps1') -ResourceGroupName 'rg-si' -StorageAccountName 'stsitest01' -Engines 'endpoint' 6>$null
            $put = @($global:SISkoFake | Where-Object { $_.Method -eq 'PUT' -and $_.Path -match '/storageAccounts/stsitest01$' })
            $put.Count | Should -Be 1
            $p = $put[0].Body.properties
            $p.allowSharedKeyAccess | Should -BeFalse
            $p.defaultToOAuthAuthentication | Should -BeTrue
            $p.minimumTlsVersion | Should -Be 'TLS1_2'
            $p.allowBlobPublicAccess | Should -BeFalse
            @($global:SISkoFake | Where-Object { $_.Path -match '(?i)listKeys|listAccountSas' }).Count | Should -Be 0
        }
    }
}

Describe 'the queue scaler of a KEDA worker signs in with the jobs'' managed identity' {
    It 'the scale rule names the identity, the shard queue and the account' {
        $a = @(Get-SIKedaQueueScaleArgs -Engine 'endpoint' -StorageAccount $script:Acct -IdentityResourceId $script:Uami)
        $a | Should -Be @('--scale-rule-name', 'si-shards-queue', '--scale-rule-type', 'azure-queue',
                          '--scale-rule-metadata', 'queueName=si-endpoint-shards', "accountName=$($script:Acct)", 'queueLength=1',
                          '--scale-rule-identity', $script:Uami)
        @($a | Where-Object { $_ -match '(?i)connection|secretref|--scale-rule-auth' }).Count | Should -Be 0
    }
    It 'NEGATIVE -- no identity (the Secret sign-in) or no account is refused, never a scaler without a sign-in' {
        { Get-SIKedaQueueScaleArgs -Engine 'endpoint' -StorageAccount $script:Acct -IdentityResourceId '' } | Should -Throw '*managed identity*'
        { Get-SIKedaQueueScaleArgs -Engine 'endpoint' -StorageAccount '' -IdentityResourceId $script:Uami } | Should -Throw '*SI_StorageAccount*'
    }
    It 'Certificate mode: the identity is granted queue read for the scaler only with queue scaling; ManagedIdentity already has the queue role' {
        $st = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/$($script:Acct)"
        $with = @(Get-SIContainerIdentityGrantPlan -Mode Certificate -KeyVaultId '/kv' -StorageAccountId $st -KedaQueueScaler)
        @($with | Where-Object { $_.Role -eq 'Storage Queue Data Reader' -and $_.Scope -eq $st }).Count | Should -Be 1
        $without = @(Get-SIContainerIdentityGrantPlan -Mode Certificate -KeyVaultId '/kv' -StorageAccountId $st)
        @($without | Where-Object { $_.Role -like 'Storage*' }).Count | Should -Be 0
        $mi = @(Get-SIContainerIdentityGrantPlan -Mode ManagedIdentity -StorageAccountId $st -KedaQueueScaler)
        @($mi | Where-Object { $_.Role -eq 'Storage Queue Data Contributor' }).Count | Should -Be 1
    }
    Context 'WIRING in Bootstrap-ContainerAppJob.ps1' {
        BeforeAll { $script:Boot = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1') -Raw }
        It 'the worker is CREATED with the identity-based scale rule (and no hand-built rule without one)' {
            $keda = [regex]::Match($script:Boot, "(?s)\`$createArgs = if \(\`$effectiveUseKEDA\) \{.*?\} elseif \(\`$isRiskAnalysis\)").Value
            # #519: the worker is defined once (Get-SIKedaWorkerCreateArgs), its scale rule from Get-SIKedaQueueScaleArgs
            $keda | Should -Match ([regex]::Escape('-Engine $engine -StorageAccount ([string]$global:SI_StorageAccount) -IdentityResourceId ([string]$engAuth.IdentityResourceId))'))
            $keda | Should -Match 'Get-SIKedaWorkerCreateArgs '
            $w = @(Get-SIKedaWorkerCreateArgs -Name 'caj-si-endpoint-worker' -ResourceGroup 'rg' -Environment 'cae' -Image 'img' -LoginServer 'acr.io' -ReplicaTimeout 3600 -Cpu '1.0' -Memory '2Gi' -Engine 'endpoint' -StorageAccount $script:Acct -IdentityResourceId $script:Uami)
            ($w -join ' ') | Should -BeLike ('* ' + ((@(Get-SIKedaQueueScaleArgs -Engine 'endpoint' -StorageAccount $script:Acct -IdentityResourceId $script:Uami)) -join ' '))
            (Get-Command Get-SIKedaWorkerCreateArgs).Definition | Should -Match "'--trigger-type','Event'"
            $script:Boot | Should -Not -Match "'--scale-rule-type','azure-queue'"
        }
        It 'an existing worker is UPDATED with the same rule (it gets the identity on the next run of setup)' {
            $script:Boot | Should -Match "(?s)if \(\`$effectiveUseKEDA\) \{\s*\`$upd\['ScaleRule'\] = ConvertFrom-SIScaleRuleArgs -ScaleArgs @\(Get-SIKedaQueueScaleArgs -Engine \`$engine -StorageAccount \(\[string\]\`$global:SI_StorageAccount\) -IdentityResourceId \(\[string\]\`$engAuth\.IdentityResourceId\)\)"
            # the identity is on the job in the same write as the rule that names it (READ-MODIFY-WRITE, #521)
            $assign = $script:Boot.IndexOf("if (`$engAuth.IdentityResourceId) { `$upd['AddIdentity'] = [string]`$engAuth.IdentityResourceId }")
            $update = $script:Boot.IndexOf('$null = Update-SIContainerAppJob @upd')
            $assign | Should -BeGreaterThan 0
            $update | Should -BeGreaterThan $assign
        }
        It 'the Secret sign-in with -UseKEDA is refused before anything is created' {
            $refuse = $script:Boot.IndexOf("if (`$kedaChoice.Refuse) { throw `$kedaChoice.Message }")
            $refuse | Should -BeGreaterThan 0
            $envStep = $script:Boot.IndexOf('Initialize-SIManagedEnvironment -ResourceGroupName $ResourceGroupName')
            $envStep | Should -BeGreaterThan 0
            $refuse | Should -BeLessThan $envStep
        }
        It 'the grant plan asks for the scaler''s queue read when queue scaling is on' {
            $script:Boot | Should -Match '-KedaQueueScaler:\(\[bool\]\$UseKEDA\)'
            $script:Boot | Should -Match "\`$stgId  = if \(\`$authMode -eq 'ManagedIdentity' -or \`$UseKEDA\)"
        }
    }
}

Describe 'an EXISTING account: shared-key access goes off only when nothing still uses a key' {
    It 'a clean install has no blockers' {
        $b = @(Get-SIStorageSharedKeyBlockers -AccountName $script:Acct -KeyTraffic @{ OAuth = 120.0; DelegationSas = 4.0 } `
                -Jobs @(New-TestJob -Rules @(New-TestRule)) -RoleAssignments @(New-TestRoles))
        $b.Count | Should -Be 0
    }
    It 'the metrics answer is summed per sign-in kind' {
        $t = ConvertFrom-SIStorageTransactionMetrics -Response (New-TestMetrics @{ AccountKey = 10.0; OAuth = 90.0 })
        $t['AccountKey'] | Should -Be 10
        $t['OAuth'] | Should -Be 90
        ConvertFrom-SIStorageTransactionMetrics -Response $null | Should -BeNullOrEmpty
    }
    It 'NEGATIVE -- <Case> blocks the switch' -ForEach @(
        @{ Case = 'account-key traffic';             Traffic = @{ AccountKey = 3.0; OAuth = 1.0 }; Job = 'clean'; Expect = '*account key*' }
        @{ Case = 'key-signed SAS traffic';          Traffic = @{ SAS = 1.0 };                     Job = 'clean'; Expect = '*key-signed SAS*' }
        @{ Case = 'metrics that cannot be read';     Traffic = $null;                              Job = 'clean'; Expect = '*could not be read*' }
        @{ Case = 'a queue scaler with no identity'; Traffic = @{};                                Job = 'noid';  Expect = '*no managed identity*' }
        @{ Case = 'a queue scaler with a secret';    Traffic = @{};                                Job = 'auth';  Expect = '*connection secret*' }
        @{ Case = 'an older release''s key secret';  Traffic = @{};                                Job = 'secret'; Expect = '*storage-key secret*' }
        @{ Case = 'an older release''s key setting'; Traffic = @{};                                Job = 'env';   Expect = '*older release*' }
        @{ Case = 'an identity without a data role'; Traffic = @{};                                Job = 'norole'; Expect = '*Storage Table Data Contributor*' }
    ) {
        $roles = @(New-TestRoles)
        $job = switch ($Job) {
            'clean'  { New-TestJob -Rules @(New-TestRule) }
            'noid'   { New-TestJob -Rules @(New-TestRule -Identity '') }
            'auth'   { New-TestJob -Rules @(New-TestRule -Auth @([pscustomobject]@{ secretRef = 'conn'; triggerParameter = 'connection' })) }
            'secret' { New-TestJob -Secrets @($script:SIRetiredJobSecrets[0]) }
            'env'    { New-TestJob -Env @{ (((Get-SIRetiredSettingNames)[0] -creplace '([a-z])([A-Z])', '$1_$2').ToUpperInvariant()) = 'x' } }
            'norole' { $roles = @(New-TestRoles -RoleIds @('ba92f5b4-2d11-453d-a403-e96b0029c9fe', '974c5e8b-45b9-4653-ba55-5f855dd0fb88')); New-TestJob }
        }
        $b = @(Get-SIStorageSharedKeyBlockers -AccountName $script:Acct -KeyTraffic $Traffic -Jobs @($job) -RoleAssignments $roles)
        $b.Count | Should -BeGreaterThan 0
        @($b | Where-Object { $_.Why -like $Expect }).Count | Should -BeGreaterThan 0
        @($b | Where-Object { [string]::IsNullOrWhiteSpace($_.Fix) }).Count | Should -Be 0
    }
    It 'a job that uses ANOTHER account is not looked at; a role held by another principal does not count' {
        $other = New-TestJob -Name 'caj-other' -Rules @() -Env @{ SI_StorageAccount = 'stsomethingelse' }
        @(Get-SIStorageSharedKeyBlockers -AccountName $script:Acct -KeyTraffic @{} -Jobs @($other)).Count | Should -Be 0
        $b = @(Get-SIStorageSharedKeyBlockers -AccountName $script:Acct -KeyTraffic @{} -Jobs @(New-TestJob) -RoleAssignments @(New-TestRoles -Principal 'someone-else'))
        $b.Count | Should -Be 3
    }
    It 'the state reads Off only when the account says allowSharedKeyAccess = false (never set = on)' {
        Get-SIStorageSharedKeyState -Account ([pscustomobject]@{ properties = [pscustomobject]@{ allowSharedKeyAccess = $false } }) | Should -Be 'Off'
        Get-SIStorageSharedKeyState -Account ([pscustomobject]@{ properties = [pscustomobject]@{ allowSharedKeyAccess = $true } }) | Should -Be 'On'
        Get-SIStorageSharedKeyState -Account ([pscustomobject]@{ properties = [pscustomobject]@{ minimumTlsVersion = 'TLS1_2' } }) | Should -Be 'On'
    }

    Context 'setup\Set-SIStorageSharedKey.ps1 end to end on a fake Azure Resource Manager' {
        BeforeAll {
            . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
            $script:keepEngine = $global:SI_AzureAccess_Engine; $script:keepIngest = $global:SI_LogIngest_Engine
            $script:Script = Join-Path $script:SIRoot 'setup\Set-SIStorageSharedKey.ps1'
        }
        AfterAll {
            $global:SI_AzureAccess_Engine = $script:keepEngine; $global:SI_LogIngest_Engine = $script:keepIngest
            Remove-Variable -Scope Global -Name SI_AzRestState, SISskFake -ErrorAction SilentlyContinue
        }
        BeforeEach {
            $global:SISskFake = @{
                Calls = [System.Collections.Generic.List[object]]::new()
                Account = [pscustomobject]@{ name = $script:Acct; properties = [pscustomobject]@{ allowSharedKeyAccess = $true; minimumTlsVersion = 'TLS1_2'; allowBlobPublicAccess = $false } }
                Metrics = (New-TestMetrics @{ OAuth = 500.0 })
                Jobs = @(New-TestJob -Rules @(New-TestRule))
                Roles = @(New-TestRoles)
            }
            Mock Get-SISetupAzureContext { [pscustomobject]@{ Subscription = 'sub-1' } }
            Mock Connect-SISetupAzure { throw 'not expected' }
            Mock Write-Host { }
            Mock Invoke-SIArm {
                $m = if ($Method) { $Method } else { 'GET' }
                $global:SISskFake.Calls.Add([pscustomobject]@{ Method = $m; Path = $Path; Body = $Body })
                if ($m -ne 'GET') { return $null }
                if ($Path -like '*/providers/Microsoft.Insights/metrics*') { return $global:SISskFake.Metrics }
                if ($Path -like '*/providers/Microsoft.App/jobs') { return $global:SISskFake.Jobs }
                if ($Path -like '*/roleAssignments*') { return $global:SISskFake.Roles }
                if ($Path -match '/storageAccounts/[^/]+$') { return $global:SISskFake.Account }
                return $null
            }
            $script:SwArgs = @{ StorageAccountName = $script:Acct; ResourceGroupName = 'rg-si'; SubscriptionId = 'sub-1' }
        }
        It 'without -Disable it only reports -- no write' {
            $r = & $script:Script @script:SwArgs
            $r.SharedKeyAccess | Should -Be 'On'
            $r.Changed | Should -BeFalse
            @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
            $m = @($global:SISskFake.Calls | Where-Object { $_.Path -like '*/metrics*' })[0].Path
            $m | Should -Match 'metricnames=Transactions'
            $m | Should -Match 'Authentication'
        }
        It '-Disable on a clean install switches shared-key access off and makes Entra ID the default (one PATCH)' {
            $r = & $script:Script @script:SwArgs -Disable
            $r.Changed | Should -BeTrue
            $r.SharedKeyAccess | Should -Be 'Off'
            $w = @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' })
            $w.Count | Should -Be 1
            $w[0].Method | Should -Be 'PATCH'
            $w[0].Path | Should -Match "/storageAccounts/$($script:Acct)$"
            $w[0].Body.properties.allowSharedKeyAccess | Should -BeFalse
            $w[0].Body.properties.defaultToOAuthAuthentication | Should -BeTrue
        }
        It '🔴 -Disable REFUSES and writes nothing when a key user is detected (account-key traffic)' {
            $global:SISskFake.Metrics = New-TestMetrics @{ AccountKey = 7.0; OAuth = 500.0 }
            { & $script:Script @script:SwArgs -Disable } | Should -Throw '*NOT switched off*'
            @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        }
        It '🔴 -Disable REFUSES when a KEDA worker''s scaler has no identity' {
            $global:SISskFake.Jobs = @(New-TestJob -Rules @(New-TestRule -Identity ''))
            { & $script:Script @script:SwArgs -Disable } | Should -Throw '*NOT switched off*'
            @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        }
        It '🔴 -Disable REFUSES when the metrics cannot be read (unknown is not "unused")' {
            Mock Invoke-SIArm {
                $m = if ($Method) { $Method } else { 'GET' }
                $global:SISskFake.Calls.Add([pscustomobject]@{ Method = $m; Path = $Path; Body = $Body })
                if ($m -ne 'GET') { return $null }
                if ($Path -like '*/providers/Microsoft.Insights/metrics*') { throw '403 AuthorizationFailed' }
                if ($Path -like '*/providers/Microsoft.App/jobs') { return $global:SISskFake.Jobs }
                if ($Path -like '*/roleAssignments*') { return $global:SISskFake.Roles }
                return $global:SISskFake.Account
            }
            { & $script:Script @script:SwArgs -Disable } | Should -Throw '*NOT switched off*'
            @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        }
        It '-Enable switches it back on (the way back)' {
            $global:SISskFake.Account = [pscustomobject]@{ name = $script:Acct; properties = [pscustomobject]@{ allowSharedKeyAccess = $false; defaultToOAuthAuthentication = $true } }
            $r = & $script:Script @script:SwArgs -Enable
            $r.Changed | Should -BeTrue
            $w = @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' })
            $w.Count | Should -Be 1
            $w[0].Body.properties.allowSharedKeyAccess | Should -BeTrue
        }
        It 'an account already off is left alone' {
            $global:SISskFake.Account = [pscustomobject]@{ name = $script:Acct; properties = [pscustomobject]@{ allowSharedKeyAccess = $false; defaultToOAuthAuthentication = $true } }
            $r = & $script:Script @script:SwArgs -Disable
            $r.Changed | Should -BeFalse
            @($global:SISskFake.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        }
    }
}
