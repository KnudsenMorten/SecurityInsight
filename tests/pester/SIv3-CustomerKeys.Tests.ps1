#Requires -Version 5.1
<#
    CUSTOMER-MANAGED KEYS AS AN OPTION (#683): setup\_shared\SI-CustomerKeys.ps1, its guided-install step, and the cut-over
    of an existing install (setup\Set-SICustomerManagedKeys.ps1) -- against a fake ARM store (tests\fixtures\SIArmStoreFake.ps1).
      * the vault (purge protection, one-way), the key (created with a rotation policy, never removed), the identity, its
        access on the KEY only; storage (versionless key), the database server (TDE protector, auto-rotation), Log Analytics
        (an existing or a new dedicated cluster); every change read back; the identity's new right waited for;
      * the cut-over: PLAN by default, the steps, the record, the rollback back to Microsoft-managed keys;
      * the guided install: the option's step only when it is chosen.
    OFFLINE. PS 5.1 + pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'tests\fixtures\SIArmStoreFake.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-CustomerKeys.ps1')
    $script:Cut = Join-Path $script:SIRoot 'setup\Set-SICustomerManagedKeys.ps1'
    $script:Sub = '11111111-1111-1111-1111-111111111111'
    $script:Rg = '/subscriptions/{0}/resourceGroups/rg-si-x' -f $script:Sub
    $script:Kv = "$script:Rg/providers/Microsoft.KeyVault/vaults/kv-si-x"
    $script:St = "$script:Rg/providers/Microsoft.Storage/storageAccounts/stsix"
    $script:Sql = "$script:Rg/providers/Microsoft.Sql/servers/sql-si-x"
    $script:Ws = "$script:Rg/providers/Microsoft.OperationalInsights/workspaces/log-si-x"
    $script:Slept = New-Object System.Collections.Generic.List[int]
    $script:NoSleep = { param($s) $script:Slept.Add([int]$s) }
    $script:Arm = { param($m, $p, $b) & $global:SIArmStoreFake $m $p $b }

    function script:New-World {
        param([bool]$Purge = $false)
        New-SIArmStore
        Set-SIArmStoreItem @{ id = $script:Kv; location = 'westeurope'; properties = @{ enableSoftDelete = $true; enablePurgeProtection = $Purge; softDeleteRetentionInDays = 90; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = $script:St; location = 'westeurope'; identity = @{ type = 'None' }; properties = @{ encryption = @{ keySource = 'Microsoft.Storage' }; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = $script:Sql; location = 'swedencentral'; identity = @{ type = 'SystemAssigned' }; properties = @{ fullyQualifiedDomainName = 'sql-si-x.example.test'; provisioningState = 'Succeeded' } }
        Set-SIArmStoreItem @{ id = "$script:Sql/encryptionProtector/current"; properties = @{ serverKeyType = 'ServiceManaged'; serverKeyName = 'ServiceManaged' } }
        Set-SIArmStoreItem @{ id = $script:Ws; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded' } }
        $mi = "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-engine"
        Set-SIArmStoreItem @{ id = $mi; properties = @{ clientId = 'cid-engine'; principalId = 'pid-engine' } }
        $ua = @{}; $ua[$mi] = @{ principalId = 'pid-engine'; clientId = 'cid-engine' }
        Set-SIArmStoreItem @{ id = "$script:Rg/providers/Microsoft.App/jobs/caj-si-flow"; location = 'westeurope'; identity = @{ type = 'UserAssigned'; userAssignedIdentities = $ua }
            properties = @{ provisioningState = 'Succeeded'; configuration = @{}; template = @{ containers = @(@{ name = 'si'; image = 'acrsix.azurecr.io/si-orchestrator:3'
                env = @(@{ name = 'SI_UAMI_ClientId'; value = 'cid-engine' }, @{ name = 'SI_ProSqlServer'; value = 'sql-si-x.example.test' }, @{ name = 'SI_ProSqlDatabase'; value = 'sqldb-si-pro' },
                        @{ name = 'SI_KeyVaultName'; value = 'kv-si-x' }, @{ name = 'SI_StorageAccount'; value = 'stsix' }, @{ name = 'SI_WorkspaceResourceId'; value = $script:Ws }) }) } } }
        $global:SIArmStore.Writes.Clear(); $script:Slept.Clear()
    }
    function script:Writes { @($global:SIArmStore.Writes) }
    function script:Setup { param([hashtable]$More = @{}) $a = @{ ResourceGroupId = $script:Rg; Location = 'westeurope'; KeyVaultId = $script:Kv; StorageAccountId = $script:St; SqlServerId = $script:Sql; WorkspaceId = $script:Ws; Arm = $script:Arm; Sleep = $script:NoSleep }; foreach ($k in $More.Keys) { $a[$k] = $More[$k] }; Invoke-SICustomerKeySetup @a }
    function script:Run { param([hashtable]$More = @{}) $a = @{ ResourceGroup = 'rg-si-x'; SubscriptionId = $script:Sub; Arm = $script:Arm; Sql = { param($a, $b, $c, $d, $e) , @() }; Graph = { param($m, $u, $b) $null }; Sleep = $script:NoSleep; RecordDirectory = (Join-Path $TestDrive 'rec'); Environment = 'pester'; ObserveMinutes = 0 }; foreach ($k in $More.Keys) { $a[$k] = $More[$k] }; & $script:Cut @a 6> $null }
}

AfterAll { Remove-SIArmStore }

Describe 'names, the key, the server key name' {
    It 'carries no ring, environment or edition in a name' {
        foreach ($v in @((Get-SICustomerKeyNames).Values)) { $v | Should -Not -Match '(?i)prod|community|\bpro\b|r0|r1|r2|ring' }
    }
    It 'a new key is RSA 3072 for wrap / unwrap, rotated every year, expires after two years, notice 30 days before' {
        $b = Get-SICustomerKeyBody
        $b.properties.kty | Should -Be 'RSA'; $b.properties.keySize | Should -Be 3072
        $b.properties.keyOps | Should -Be @('wrapKey', 'unwrapKey')
        $b.properties.rotationPolicy.attributes.expiryTime | Should -Be 'P2Y'
        @($b.properties.rotationPolicy.lifetimeActions | Where-Object { $_.action.type -eq 'rotate' })[0].trigger.timeAfterCreate | Should -Be 'P1Y'
        @($b.properties.rotationPolicy.lifetimeActions | Where-Object { $_.action.type -eq 'notify' })[0].trigger.timeBeforeExpiry | Should -Be 'P30D'
    }
    It 'the database server''s key name is <vault>_<key>_<version>' {
        Get-SISqlServerKeyName -KeyUriWithVersion 'https://kv-si-x.vault.azure.net/keys/si-data/0123456789abcdef0123456789abcdef' | Should -Be 'kv-si-x_si-data_0123456789abcdef0123456789abcdef'
        { Get-SISqlServerKeyName -KeyUriWithVersion 'https://kv-si-x.vault.azure.net/keys/si-data' } | Should -Throw
    }
}

Describe 'the whole option (setup''s call)' {
    It 'vault protected, key made, identity with access on the KEY only, storage and database server on the key, read back' {
        New-World
        $r = Setup
        $r.Ok | Should -BeTrue
        (Get-SIArmStoreItem $script:Kv).properties.enablePurgeProtection | Should -BeTrue
        $key = Get-SIArmStoreItem "$script:Kv/keys/si-data"
        $key | Should -Not -BeNullOrEmpty
        $key.properties.rotationPolicy | Should -Not -BeNullOrEmpty
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-keys" | Should -Not -BeNullOrEmpty
        $ra = @($global:SIArmStore.Items.Keys | Where-Object { $_ -like ("$script:Kv/keys/si-data/providers/Microsoft.Authorization/roleAssignments/*").ToLowerInvariant() })
        $ra.Count | Should -Be 1
        $global:SIArmStore.Items[$ra[0]].properties.roleDefinitionId | Should -Match 'e147488a-f6f5-4113-8e2d-b22465e65bf6$'
        @($global:SIArmStore.Items.Keys | Where-Object { $_ -like ("$script:Kv/providers/Microsoft.Authorization/roleAssignments/*").ToLowerInvariant() }).Count | Should -Be 0 -Because 'the right is on the key, never the vault'
        $st = Get-SIArmStoreItem $script:St
        $st.properties.encryption.keySource | Should -Be 'Microsoft.Keyvault'
        $st.properties.encryption.keyvaultproperties.keyname | Should -Be 'si-data'
        $st.properties.encryption.keyvaultproperties.Contains('keyversion') | Should -BeFalse -Because 'versionless: a new version is used automatically'
        $p = Get-SIArmStoreItem "$script:Sql/encryptionProtector/current"
        $p.properties.serverKeyType | Should -Be 'AzureKeyVault'
        $p.properties.serverKeyName | Should -Be 'kv-si-x_si-data_0123456789abcdef0123456789abcdef'
        $p.properties.autoRotationEnabled | Should -BeTrue
        (Get-SIArmStoreItem $script:Sql).identity.type | Should -Be 'SystemAssigned,UserAssigned' -Because 'the server''s own identity stays'
        @(Writes | Where-Object { $_ -match 'clusters|linkedServices' }) | Should -BeNullOrEmpty -Because 'Log Analytics is off unless chosen'
    }
    It 'is idempotent: a second run writes nothing' {
        New-World
        $null = Setup
        $global:SIArmStore.Writes.Clear()
        (Setup).Ok | Should -BeTrue
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'an existing key is used as it is, never changed' {
        New-World -Purge $true
        Set-SIArmStoreItem @{ id = "$script:Kv/keys/si-data"; properties = @{ kty = 'RSA'; keyUri = 'https://kv-si-x.vault.azure.net/keys/si-data'; keyUriWithVersion = 'https://kv-si-x.vault.azure.net/keys/si-data/ffffffffffffffffffffffffffffffff' } }
        $null = Setup
        @(Writes) | Should -Not -Contain "PUT $script:Kv/keys/si-data"
        (Get-SIArmStoreItem "$script:Sql/encryptionProtector/current").properties.serverKeyName | Should -Be 'kv-si-x_si-data_ffffffffffffffffffffffffffffffff'
    }
    It 'waits for the identity''s new right on the key (Azure honours it after minutes), then goes on' {
        New-World
        $global:SIArmStore.RefuseKeyAccess = 2
        (Setup).Ok | Should -BeTrue
        $script:Slept | Should -Contain 30
        (Get-SIArmStoreItem $script:St).properties.encryption.keySource | Should -Be 'Microsoft.Keyvault'
    }
    It 'a vault that is not there changes nothing' {
        New-World
        $r = Setup @{ KeyVaultId = "$script:Rg/providers/Microsoft.KeyVault/vaults/kv-nope" }
        $r.Ok | Should -BeFalse
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'Log Analytics: a new cluster still being made is PENDING, not linked; a ready one is linked, read back' {
        New-World
        $global:SIArmStore.ClusterState = 'ProvisioningAccount'
        $r = Setup @{ LogAnalytics = 'cluster-new' }
        $r.Ok | Should -BeTrue; $r.Pending | Should -BeTrue
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.OperationalInsights/clusters/log-si-cluster" | Should -Not -BeNullOrEmpty
        Get-SIArmStoreItem "$script:Ws/linkedServices/cluster" | Should -BeNullOrEmpty
        (Get-SIArmStoreItem "$script:Rg/providers/Microsoft.OperationalInsights/clusters/log-si-cluster").sku.capacity | Should -Be 100
        $global:SIArmStore.Items[("$script:Rg/providers/Microsoft.OperationalInsights/clusters/log-si-cluster").ToLowerInvariant()].properties.provisioningState = 'Succeeded'
        $r2 = Setup @{ LogAnalytics = 'cluster-new' }
        $r2.Pending | Should -BeFalse
        (Get-SIArmStoreItem "$script:Ws/linkedServices/cluster").properties.writeAccessResourceId | Should -Be "$script:Rg/providers/Microsoft.OperationalInsights/clusters/log-si-cluster"
    }
    It 'Log Analytics: an existing cluster without a customer-managed key is not linked' {
        New-World
        $cl = '/subscriptions/{0}/resourceGroups/rg-la/providers/Microsoft.OperationalInsights/clusters/la-hub' -f $script:Sub
        Set-SIArmStoreItem @{ id = $cl; properties = @{ provisioningState = 'Succeeded' } }
        $r = Setup @{ LogAnalytics = 'cluster-existing'; ClusterId = $cl }
        $r.Ok | Should -BeFalse
        Get-SIArmStoreItem "$script:Ws/linkedServices/cluster" | Should -BeNullOrEmpty
    }
}

Describe 'setup\Set-SICustomerManagedKeys.ps1 -- the cut-over of an existing install' {
    It 'PLAN by default: every step, nothing written' {
        New-World
        $r = Run
        $r.Mode | Should -Be 'plan'
        @(Writes) | Should -BeNullOrEmpty
        $r.Plan['vault-protection'].Action | Should -Be 'change'
        $r.Plan['key'].Action | Should -Be 'change'
        $r.Plan['log-analytics'].Action | Should -Be 'skip'
    }
    It '-Apply without -Steps is refused; cluster-existing without -ClusterId is refused' {
        New-World
        { Run @{ Apply = $true } } | Should -Throw '*-Apply needs -Steps*'
        { Run @{ LogAnalytics = 'cluster-existing' } } | Should -Throw '*-ClusterId*'
        @(Writes) | Should -BeNullOrEmpty
    }
    It 'a step that needs an earlier one says so and changes nothing' {
        New-World
        $r = Run @{ Apply = $true; Steps = @('storage') }
        @($r.Results)[0].Ok | Should -BeFalse
        (@($r.Results)[0].Lines -join ' ') | Should -Match 'run the key step first'
        (Get-SIArmStoreItem $script:St).properties.encryption.keySource | Should -Be 'Microsoft.Storage'
    }
    It 'all steps, one record; the rollback goes back to Microsoft-managed keys and KEEPS the key' {
        New-World
        $r = Run @{ Apply = $true; Steps = @('vault-protection', 'key', 'identity', 'key-access', 'storage', 'sql') }
        @($r.Results | Where-Object { -not $_.Ok } | ForEach-Object { $_.Step + ': ' + ($_.Lines -join '; ') }) | Should -BeNullOrEmpty
        (Get-SIArmStoreItem $script:St).properties.encryption.keySource | Should -Be 'Microsoft.Keyvault'
        (Get-SIArmStoreItem "$script:Sql/encryptionProtector/current").properties.serverKeyType | Should -Be 'AzureKeyVault'
        $rec = [IO.File]::ReadAllText($r.RecordPath) | ConvertFrom-Json
        @($rec.applied) | Should -Be @('vault-protection', 'key', 'identity', 'key-access', 'storage', 'sql')
        $global:SIArmStore.Writes.Clear()
        $null = Run @{ Rollback = $r.RecordPath; Apply = $true }
        (Get-SIArmStoreItem $script:St).properties.encryption.keySource | Should -Be 'Microsoft.Storage'
        (Get-SIArmStoreItem "$script:Sql/encryptionProtector/current").properties.serverKeyType | Should -Be 'ServiceManaged'
        Get-SIArmStoreItem "$script:Kv/keys/si-data" | Should -Not -BeNullOrEmpty -Because 'a key is never removed'
        @(Writes) | Should -Not -Contain "DELETE $script:Kv/keys/si-data"
        Get-SIArmStoreItem "$script:Rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-si-keys" | Should -BeNullOrEmpty -Because 'this run made it'
        (Get-SIArmStoreItem $script:Kv).properties.enablePurgeProtection | Should -BeTrue -Because 'one-way'
    }
}

Describe 'the guided install: an option, off by default' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
        $proLib = Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallPro.ps1'; if (Test-Path $proLib) { . $proLib }
        $script:Spec = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\install-parameters.json')) | ConvertFrom-Json
    }
    It 'the default plan has no key step; chosen, it comes after the updater and before support access' {
        @(Get-SIInstallStepPlan -Edition 'pro' | ForEach-Object Id) | Should -Not -Contain 'customer-managed-keys'
        $ids = @(Get-SIInstallStepPlan -Edition 'pro' -Options (Get-SIInstallChosenOptions -Values ([ordered]@{ customerManagedKeys = $true })) | ForEach-Object Id)
        [array]::IndexOf($ids, 'customer-managed-keys') | Should -Be ([array]::IndexOf($ids, 'updater-job') + 1)
        $c = @(Get-SIInstallStepPlan -Edition 'community' -Options @('customerManagedKeys') | ForEach-Object Id)
        $c | Should -Contain 'customer-managed-keys'
        [array]::IndexOf($c, 'customer-managed-keys') | Should -BeLessThan ([array]::IndexOf($c, 'support-app-access'))
    }
    It 'the answers: off by default (Microsoft-managed keys); an existing cluster needs its id' {
        $base = @{ installId = 'i1'; tenantId = '22222222-2222-2222-2222-222222222222'; subscriptionId = $script:Sub; mailMode = 'none' }
        $c = Test-SIInstallConfig -Config ([pscustomobject]$base) -Spec $script:Spec -Edition 'pro'
        [bool]$c.Values['customerManagedKeys'] | Should -BeFalse
        $c.Values.Contains('cmkLogAnalytics') | Should -BeFalse
        $on = $base.Clone(); $on.customerManagedKeys = $true; $on.cmkLogAnalytics = 'cluster-existing'
        (Test-SIInstallConfig -Config ([pscustomobject]$on) -Spec $script:Spec -Edition 'pro').Errors -join ' ' | Should -Match 'logAnalyticsClusterId: required'
        $on.cmkLogAnalytics = 'off'
        $ok = Test-SIInstallConfig -Config ([pscustomobject]$on) -Spec $script:Spec -Edition 'pro'
        $ok.Ok | Should -BeTrue
        $ok.Values['cmkKeyName'] | Should -Be 'si-data'
    }
    It 'the step: a failure is a WARNING, the data stays on Microsoft-managed keys, with the cut-over command' {
        $ctx = @{ Values = [ordered]@{ subscriptionId = $script:Sub; location = 'westeurope'; customerManagedKeys = $true; cmkLogAnalytics = 'off'; cmkKeyName = 'si-data' }; Names = @{ ResourceGroup = 'rg-si-x' }; Facts = [ordered]@{ keyVaultId = $script:Kv }
                  Cache = [ordered]@{ infra = [ordered]@{ StorageAccountResourceId = $script:St; WorkspaceResourceId = $script:Ws } }; ResumeCommand = 'resume'; Pro = $false
                  Seams = @{ Az = { param($Command, $Arguments) throw 'Forbidden' } } }
        $r = & (Get-SIInstallStepTable)['customer-managed-keys'] $ctx
        $r.State | Should -Be 'warning'
        $r.Message | Should -Match 'Microsoft-managed keys'
        $r.Action.command | Should -Match 'Set-SICustomerManagedKeys\.ps1 -ResourceGroup rg-si-x'
    }
}

Describe 'no module, no az, no native exe in the option''s code' {
    It '<_>' -ForEach @('setup\_shared\SI-CustomerKeys.ps1', 'setup\Set-SICustomerManagedKeys.ps1') {
        $c = Get-Content -Raw (Join-Path $script:SIRoot $_)
        $c | Should -Not -Match '(?im)^\s*Import-Module|\bInstall-Module\b|Connect-AzAccount|^\s*az\s|\baz (sql|storage|keyvault|monitor)\b|\.exe\b'
    }
}
