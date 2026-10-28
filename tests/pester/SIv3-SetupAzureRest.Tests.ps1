#Requires -Version 5.1
<#
    THE AZURE CALLS SETUP NEEDS, WITHOUT POWERSHELL MODULES (#305) -- setup/_shared/SI-SetupAzure.ps1.

    What the engines' REST layer never needed and setup does: Key Vault vaults (get by name across the subscription,
    soft-deleted, create, name check) and certificates (get, import); resource providers (get, register, newest
    api-version); deleting a role assignment and reading what a principal holds through its groups; typed ARM reads
    (any resource, VM, user-assigned identity, SQL server + database, Azure OpenAI, tenants, Log Analytics tables);
    storage management through ARM (tables / containers / queues, the lifecycle policy, account keys, name check);
    the Microsoft Graph user lookup. Each against a fake Azure: method, URL, api-version, body, and the object shape.
    Not-found reads behave like the cmdlets did: -ErrorAction SilentlyContinue gives $null, -ErrorAction Stop throws.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:GlobalNames = 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_SetupSignInState', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret'
    $script:keepAll = @{}
    foreach ($n in $script:GlobalNames) { $script:keepAll[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    $script:hadGlobalToken = [bool](Get-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GraphRest.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    function script:Resp([int]$Code, $Obj) {
        $c = if ($null -eq $Obj) { '' } elseif ($Obj -is [string]) { $Obj } else { $Obj | ConvertTo-Json -Depth 30 -Compress }
        [pscustomobject]@{ StatusCode = $Code; Content = $c; Bytes = $null; Headers = @{}; RetryAfter = '' }
    }
    function script:BodyOf($Call) { if ($Call.Body) { [string]$Call.Body | ConvertFrom-Json } }
}

AfterAll {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keepAll[$n] }
    if (-not $script:hadGlobalToken) { Remove-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue }
}

Describe 'setup Azure REST capabilities' {
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
        if ($script:Handler) { $r = & $script:Handler $Method $Uri $Body; if ($r) { return $r } }
        return (Resp 404 '{"error":{"code":"NotFound","message":"not in the fake"}}')
    }
    Mock Start-Sleep { }
}

Context 'Key Vault' {
    It 'finds a vault by name anywhere in the subscription; absent = $null quietly or an error with -ErrorAction Stop' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like "https://management.azure.com/subscriptions/$($script:Sub)/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01") {
                return (Resp 200 @{ value = @(@{ name = 'kv-other' }, @{ name = 'kv-si'; id = "/subscriptions/$($script:Sub)/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-si"; location = 'westeurope'
                    properties = @{ vaultUri = 'https://kv-si.vault.azure.net/'; enableRbacAuthorization = $true; enableSoftDelete = $true; tenantId = 'tid-1'; sku = @{ name = 'standard' } } }) })
            } }
        $v = Get-SIKeyVault -VaultName 'kv-si'
        $v.VaultName | Should -Be 'kv-si'
        $v.ResourceGroupName | Should -Be 'rg-si'
        $v.VaultUri | Should -Be 'https://kv-si.vault.azure.net/'
        $v.EnableRbacAuthorization | Should -BeTrue
        Get-SIKeyVault -VaultName 'kv-none' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        { Get-SIKeyVault -VaultName 'kv-none' -ErrorAction Stop } | Should -Throw '*kv-none*was not found*'
    }
    It '#866 a PRIVATE install CREATES the vault with public access disabled (its firewall Deny, trusted services) -- never public first' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-priv?*') {
                return (Resp 200 @{ name = 'kv-priv'; id = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-priv'; properties = @{ provisioningState = 'Succeeded'; vaultUri = 'https://kv-priv.vault.azure.net/' } })
            } }
        $null = New-SIKeyVault -VaultName 'kv-priv' -ResourceGroupName 'rg-si' -Location 'westeurope' -PublicNetworkAccess Disabled
        $put = BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put.properties.publicNetworkAccess | Should -Be 'Disabled'
        $put.properties.networkAcls.defaultAction | Should -Be 'Deny'
        $put.properties.networkAcls.bypass | Should -Be 'AzureServices'
        $script:Calls.Clear()
        $null = New-SIKeyVault -VaultName 'kv-priv' -ResourceGroupName 'rg-si' -Location 'westeurope'
        $put2 = BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put2.properties.PSObject.Properties['publicNetworkAccess'] | Should -BeNullOrEmpty -Because 'the default install is unchanged'
    }
    It '#866 a PRIVATE install CREATES the storage account with public access disabled; the default is unchanged' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/storageAccounts/stpriv?*') { return (Resp 200 @{ name = 'stpriv'; id = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.Storage/storageAccounts/stpriv'; location = 'westeurope'; properties = @{ provisioningState = 'Succeeded'; primaryEndpoints = @{ blob = 'https://stpriv.blob.core.windows.net/' } } }) } }
        $null = New-SIAzStorageAccount -ResourceGroupName 'rg-si' -Name 'stpriv' -Location 'westeurope' -SkuName 'Standard_LRS' -Kind 'StorageV2' -PublicNetworkAccess 'Disabled'
        $put = BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put.properties.publicNetworkAccess | Should -Be 'Disabled'
        $put.properties.allowSharedKeyAccess | Should -BeFalse
        $script:Calls.Clear()
        $null = New-SIAzStorageAccount -ResourceGroupName 'rg-si' -Name 'stpriv' -Location 'westeurope' -SkuName 'Standard_LRS' -Kind 'StorageV2'
        (BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]).properties.PSObject.Properties['publicNetworkAccess'] | Should -BeNullOrEmpty
    }
    It 'reads a soft-deleted vault in a region' {
        $script:Handler = { param($m, $u, $b) if ($u -like '*/locations/westeurope/deletedVaults/kv-si?*') { return (Resp 200 @{ name = 'kv-si'; id = 'x'; properties = @{ location = 'westeurope'; deletionDate = '2026-10-01T00:00:00Z'; scheduledPurgeDate = '2027-01-01T00:00:00Z'; purgeProtectionEnabled = $false } }) } }
        $d = Get-SIKeyVault -VaultName 'kv-si' -InRemovedState -Location 'westeurope'
        $d.VaultName | Should -Be 'kv-si'
        $d.ScheduledPurgeDate | Should -Not -BeNullOrEmpty
    }
    It 'creates a vault with Azure RBAC and soft delete in the signed-in tenant, and waits until it is ready' {
        $script:n = 0
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-new?*') {
                if ($m -eq 'PUT') { return (Resp 200 @{ name = 'kv-new'; id = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-new'; properties = @{ provisioningState = 'RegisteringDns' } }) }
                $script:n++
                return (Resp 200 @{ name = 'kv-new'; id = '/subscriptions/s/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-new'; properties = @{ provisioningState = 'Succeeded'; vaultUri = 'https://kv-new.vault.azure.net/' } })
            } }
        $v = New-SIKeyVault -VaultName 'kv-new' -ResourceGroupName 'rg-si' -Location 'westeurope' -Tag @{ owner = 'si' }
        $v.ProvisioningState | Should -Be 'Succeeded'
        $put = BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]
        $put.location | Should -Be 'westeurope'
        $put.properties.tenantId | Should -Be 'tid-1'
        $put.properties.enableRbacAuthorization | Should -BeTrue
        $put.properties.enableSoftDelete | Should -BeTrue
        $put.properties.sku.name | Should -Be 'standard'
        $put.tags.owner | Should -Be 'si'
        $script:n | Should -Be 1
    }
    It 'checks a vault name' {
        $script:Handler = { param($m, $u, $b) if ($u -like '*/providers/Microsoft.KeyVault/checkNameAvailability?api-version=2022-07-01') { return (Resp 200 @{ nameAvailable = $false; reason = 'AlreadyExists'; message = 'taken' }) } }
        $r = Test-SIKeyVaultNameAvailability -Name 'kv-x'
        $r.NameAvailable | Should -BeFalse; $r.Reason | Should -Be 'AlreadyExists'
        (BodyOf $script:Calls[0]).type | Should -Be 'Microsoft.KeyVault/vaults'
    }
    It 'reads a certificate (thumbprint from x5t) and imports a PFX on the vault data plane with a Key Vault token' {
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'GET' -and $u -eq 'https://kv-si.vault.azure.net/certificates/si-cert?api-version=7.4') { return (Resp 200 @{ id = 'https://kv-si.vault.azure.net/certificates/si-cert/v1'; x5t = 'q83vEjRWeJA'; attributes = @{ enabled = $true; exp = 1893456000 } }) }
            if ($m -eq 'POST' -and $u -eq 'https://kv-si.vault.azure.net/certificates/si-cert/import?api-version=7.4') { return (Resp 200 @{ id = 'https://kv-si.vault.azure.net/certificates/si-cert/v2'; x5t = 'q83vEjRWeJA' }) }
        }
        $c = Get-SIKeyVaultCertificate -VaultName 'kv-si' -Name 'si-cert'
        $c.Thumbprint | Should -Be 'ABCDEF1234567890'
        $c.Expires.Year | Should -Be 2030
        $c.Enabled | Should -BeTrue
        Get-SIKeyVaultCertificate -VaultName 'kv-si' -Name 'absent' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $i = Import-SIKeyVaultCertificate -VaultName 'kv-si' -Name 'si-cert' -CertificateBytes ([byte[]](1, 2, 3)) -Password (ConvertTo-SecureString 'pw' -AsPlainText -Force)
        $i.Id | Should -Match '/v2$'
        $imp = @($script:Calls | Where-Object { $_.Method -eq 'POST' })[0]
        $imp.Headers['Authorization'] | Should -Be 'Bearer tok|https://vault.azure.net/'
        $ib = BodyOf $imp
        $ib.value | Should -Be ([Convert]::ToBase64String([byte[]](1, 2, 3)))
        $ib.pwd | Should -Be 'pw'
        $ib.policy.secret_props.contentType | Should -Be 'application/x-pkcs12'
    }
}

Context 'resource providers' {
    It 'reads a provider''s registration, registers it, and picks the newest non-preview api-version' {
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'GET' -and $u -like "*/subscriptions/$($script:Sub)/providers/Microsoft.Sql?api-version=2021-04-01") {
                return (Resp 200 @{ namespace = 'Microsoft.Sql'; registrationState = 'NotRegistered'; resourceTypes = @(@{ resourceType = 'servers'; apiVersions = @('2023-08-01-preview', '2021-11-01', '2022-05-01-preview', '2023-05-01') }) }) }
            if ($m -eq 'POST' -and $u -like "*/providers/Microsoft.Sql/register?api-version=2021-04-01") { return (Resp 200 @{ registrationState = 'Registering' }) }
        }
        (Get-SIResourceProvider -ProviderNamespace 'Microsoft.Sql').RegistrationState | Should -Be 'NotRegistered'
        (Register-SIResourceProvider -ProviderNamespace 'Microsoft.Sql').RegistrationState | Should -Be 'Registering'
        Get-SIArmApiVersion -ResourceType 'Microsoft.Sql/servers' | Should -Be '2023-05-01'
        Get-SIResourceProvider -ProviderNamespace 'Microsoft.Nope' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
}

Context 'role assignments' {
    BeforeEach {
        $script:Defs = @{ value = @(@{ id = '/x/roleDefinitions/r-reader'; name = 'r-reader'; properties = @{ roleName = 'Reader' } }, @{ id = '/x/roleDefinitions/r-kvso'; name = 'r-kvso'; properties = @{ roleName = 'Key Vault Secrets Officer' } }) }
    }
    It 'deletes by id, or exactly the assignments of a role to a principal AT the scope (not inherited ones)' {
        $scope = "/subscriptions/$($script:Sub)/resourceGroups/rg-si"
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/providers/Microsoft.Authorization/roleDefinitions?*') { return (Resp 200 $script:Defs) }
            if ($m -eq 'GET' -and $u -like '*/resourceGroups/rg-si/providers/Microsoft.Authorization/roleAssignments?*') {
                return (Resp 200 @{ value = @(
                    @{ id = "$scope/providers/Microsoft.Authorization/roleAssignments/a1"; name = 'a1'; properties = @{ roleDefinitionId = '/x/r-reader'; principalId = 'p1'; scope = $scope } },
                    @{ id = "/subscriptions/$($script:Sub)/providers/Microsoft.Authorization/roleAssignments/a2"; name = 'a2'; properties = @{ roleDefinitionId = '/x/r-reader'; principalId = 'p1'; scope = "/subscriptions/$($script:Sub)" } }) }) }
            if ($m -eq 'DELETE') { return (Resp 200 @{}) }
            if ($u -like '*getByIds*') { return (Resp 200 @{ value = @() }) }
        }
        $gone = @(Remove-SIRoleAssignment -ObjectId 'p1' -RoleDefinitionName 'Reader' -Scope $scope)
        $gone.Count | Should -Be 1
        $gone[0].RoleAssignmentId | Should -BeLike '*/roleAssignments/a1'
        $del = @($script:Calls | Where-Object { $_.Method -eq 'DELETE' })
        $del.Count | Should -Be 1
        $del[0].Uri | Should -BeLike "https://management.azure.com$scope/providers/Microsoft.Authorization/roleAssignments/a1?api-version=2022-04-01"
        $script:Calls.Clear()
        $null = Remove-SIRoleAssignment -RoleAssignmentId '/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/zz'
        @($script:Calls | Where-Object { $_.Method -eq 'DELETE' }).Count | Should -Be 1
        { Remove-SIRoleAssignment -ObjectId 'p1' } | Should -Throw '*needs -RoleAssignmentId*'
    }
    It 'reads what a principal holds through its groups too (assignedTo)' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/providers/Microsoft.Authorization/roleDefinitions?*') { return (Resp 200 $script:Defs) }
            if ($u -like '*/roleAssignments?*') { return (Resp 200 @{ value = @(@{ id = 'a9'; name = 'a9'; properties = @{ roleDefinitionId = '/x/r-kvso'; principalId = 'group-1'; principalType = 'Group'; scope = '/s' } }) }) }
        }
        $r = @(Get-SIRoleAssignmentAssignedTo -ObjectId 'user-1' -RoleDefinitionName 'Key Vault Secrets Officer')
        $r.Count | Should -Be 1
        $r[0].ObjectType | Should -Be 'Group'
        [uri]::UnescapeDataString(@($script:Calls | Where-Object { $_.Uri -like '*roleAssignments*' })[0].Uri) | Should -Match "\`$filter=assignedTo\('user-1'\)"
    }
}

Context 'typed ARM reads' {
    It 'any resource by type and name (what Get-AzResource did), and by id with its newest api-version' {
        $script:Handler = { param($m, $u, $b)
            if ($u -like "*/subscriptions/$($script:Sub)/resources?*") { return (Resp 200 @{ value = @(@{ id = "/subscriptions/$($script:Sub)/resourceGroups/rg-sql/providers/Microsoft.Sql/servers/sql-si"; name = 'sql-si'; type = 'Microsoft.Sql/servers'; location = 'westeurope' }) }) }
            if ($u -like '*/providers/Microsoft.HybridCompute?api-version=2021-04-01') { return (Resp 200 @{ namespace = 'Microsoft.HybridCompute'; resourceTypes = @(@{ resourceType = 'machines'; apiVersions = @('2024-07-10', '2023-10-03-preview') }) }) }
            if ($u -like '*/providers/Microsoft.HybridCompute/machines/arc-1?api-version=2024-07-10') { return (Resp 200 @{ id = '/subscriptions/s/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/arc-1'; name = 'arc-1'; type = 'Microsoft.HybridCompute/machines'; identity = @{ principalId = 'mi-1' }; properties = @{ status = 'Connected' } }) }
        }
        $r = @(Get-SIArmResource -ResourceType 'Microsoft.Sql/servers' -Name 'sql-si')
        $r.Count | Should -Be 1
        $r[0].ResourceGroupName | Should -Be 'rg-sql'
        [uri]::UnescapeDataString($script:Calls[0].Uri) | Should -Match "resourceType eq 'Microsoft.Sql/servers' and name eq 'sql-si'"
        $a = Get-SIArmResource -ResourceId '/subscriptions/s/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/arc-1'
        $a.Identity.principalId | Should -Be 'mi-1'
        $a.Properties.status | Should -Be 'Connected'
    }
    It 'a VM, a user-assigned identity, SQL servers and databases, Azure OpenAI accounts, tenants, Log Analytics tables' {
        $script:Handler = { param($m, $u, $b)
            switch -Wildcard ($u) {
                '*/virtualMachines/vm-1?api-version=2023-09-01' { return (Resp 200 @{ name = 'vm-1'; id = 'vmid'; properties = @{ vmId = 'g-1' }; identity = @{ type = 'SystemAssigned'; principalId = 'vm-mi' } }) }
                '*/userAssignedIdentities/uami-si?api-version=2023-01-31' { return (Resp 200 @{ name = 'uami-si'; id = 'uid'; properties = @{ clientId = 'cid-1'; principalId = 'pid-1'; tenantId = 'tid-1' } }) }
                '*/providers/Microsoft.Sql/servers?api-version=2021-11-01' { return (Resp 200 @{ value = @(@{ name = 'sql-a'; id = '/subscriptions/s/resourceGroups/rg-a/providers/Microsoft.Sql/servers/sql-a'; properties = @{ fullyQualifiedDomainName = 'server.database.windows.net' } }) }) }
                '*/servers/sql-a/databases?api-version=2021-11-01' { return (Resp 200 @{ value = @(@{ name = 'master' }, @{ name = 'sipro'; properties = @{ status = 'Online' }; sku = @{ name = 'GP_S_Gen5' } }) }) }
                '*/providers/Microsoft.CognitiveServices/accounts?api-version=2023-05-01' { return (Resp 200 @{ value = @(@{ name = 'oai-1'; kind = 'OpenAI'; id = '/subscriptions/s/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-1'; properties = @{ endpoint = 'https://oai-1.openai.azure.com/' } }) }) }
                'https://management.azure.com/tenants?api-version=2022-12-01' { return (Resp 200 @{ value = @(@{ tenantId = 'tid-1'; displayName = 'Contoso'; defaultDomain = 'contoso.example' }) }) }
                '*/workspaces/ws-si/tables/SI_X_CL?api-version=2022-10-01' { return (Resp 200 @{ name = 'SI_X_CL'; properties = @{ plan = 'Analytics'; retentionInDays = 90; schema = @{ columns = @(@{ name = 'A'; type = 'string' }) } } }) }
            } }
        (Get-SIVirtualMachine -ResourceGroupName 'rg' -Name 'vm-1').Identity.principalId | Should -Be 'vm-mi'
        $u = Get-SIUserAssignedIdentity -ResourceGroupName 'rg' -Name 'uami-si'
        $u.ClientId | Should -Be 'cid-1'; $u.PrincipalId | Should -Be 'pid-1'
        Get-SIUserAssignedIdentity -ResourceGroupName 'rg' -Name 'absent' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $s = @(Get-SISqlServer)
        $s[0].ServerName | Should -Be 'sql-a'; $s[0].ResourceGroupName | Should -Be 'rg-a'; $s[0].FullyQualifiedDomainName | Should -Be 'server.database.windows.net'
        @(Get-SISqlDatabase -ResourceGroupName 'rg-a' -ServerName 'sql-a' | ForEach-Object { $_.DatabaseName }) | Should -Be @('master', 'sipro')
        (Get-SICognitiveServicesAccount)[0].Endpoint | Should -Be 'https://oai-1.openai.azure.com/'
        (Get-SITenant -TenantId 'tid-1').DefaultDomain | Should -Be 'contoso.example'
        Get-SITenant -TenantId 'tid-x' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        (Get-SILogAnalyticsTable -ResourceGroupName 'rg' -WorkspaceName 'ws-si' -TableName 'SI_X_CL').RetentionInDays | Should -Be 90
    }
}

Context 'storage management through ARM' {
    It 'creates a table, a PRIVATE container and a queue on the management plane (no data role, no key)' {
        $script:Handler = { param($m, $u, $b) if ($m -eq 'PUT') { return (Resp 200 @{ name = ($u -split '/')[-1].Split('?')[0]; id = 'x' }) } }
        $null = New-SIStorageArmChild -ResourceGroupName 'rg' -AccountName 'stsi' -Kind Table -Name 'sifingerprint'
        $null = New-SIStorageArmChild -ResourceGroupName 'rg' -AccountName 'stsi' -Kind Container -Name 'sistaging'
        $null = New-SIStorageArmChild -ResourceGroupName 'rg' -AccountName 'stsi' -Kind Queue -Name 'si-endpoint-collect'
        $script:Calls[0].Uri | Should -BeLike "*/storageAccounts/stsi/tableServices/default/tables/sifingerprint?api-version=2023-01-01"
        $script:Calls[1].Uri | Should -BeLike "*/storageAccounts/stsi/blobServices/default/containers/sistaging?api-version=2023-01-01"
        (BodyOf $script:Calls[1]).properties.publicAccess | Should -Be 'None'
        $script:Calls[2].Uri | Should -BeLike "*/storageAccounts/stsi/queueServices/default/queues/si-endpoint-collect?api-version=2023-01-01"
        $script:Calls[0].Headers['Authorization'] | Should -Be 'Bearer tok|https://management.azure.com/'
        Get-SIStorageArmChild -ResourceGroupName 'rg' -AccountName 'stsi' -Kind Table -Name 'nope' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }
    It 'reads and replaces the lifecycle policy; the delete rule is built as ARM expects' {
        $rule = New-SIStorageLifecycleDeleteRule -Name 'si-staging-7day-delete' -PrefixMatch 'sistaging/staging/' -DaysAfterModification 7
        Get-SIStorageLifecycleRuleDeleteDays -Rule ([pscustomobject]@{ definition = @{ actions = @{ baseBlob = @{ delete = @{ daysAfterModificationGreaterThan = 7 } } } } }) | Should -Be 7
        $script:Handler = { param($m, $u, $b)
            if ($u -like '*/managementPolicies/default?*') {
                if ($m -eq 'GET') { return (Resp 200 @{ id = 'p'; properties = @{ policy = @{ rules = @(@{ name = 'customer-own'; enabled = $true; type = 'Lifecycle'; definition = @{} }) } } }) }
                return (Resp 200 @{ id = 'p'; properties = @{ policy = ($b | ConvertFrom-Json).properties.policy } })
            } }
        $p = Get-SIStorageLifecyclePolicy -ResourceGroupName 'rg' -AccountName 'stsi'
        @($p.Rules).Count | Should -Be 1
        $set = Set-SIStorageLifecyclePolicy -ResourceGroupName 'rg' -AccountName 'stsi' -Rules (@($p.Rules) + @($rule))
        @($set.Rules | ForEach-Object { $_.name }) | Should -Be @('customer-own', 'si-staging-7day-delete')
        $sent = (BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]).properties.policy.rules[1]
        $sent.definition.actions.baseBlob.delete.daysAfterModificationGreaterThan | Should -Be 7
        @($sent.definition.filters.prefixMatch) | Should -Be @('sistaging/staging/')
        @($sent.definition.filters.blobTypes) | Should -Be @('blockBlob')
        $script:Handler = $null
        Get-SIStorageLifecyclePolicy -ResourceGroupName 'rg' -AccountName 'stsi' | Should -BeNullOrEmpty
    }
    It 'checks a storage account name, and has no way to read an account key (#307)' {
        $script:Handler = { param($m, $u, $b)
            if ($m -eq 'POST' -and $u -like '*/providers/Microsoft.Storage/checkNameAvailability?*') { return (Resp 200 @{ nameAvailable = $true }) }
        }
        Get-Command -Name Get-SIStorageAccountKey -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        (Test-SIStorageAccountNameAvailability -Name 'stsi2').NameAvailable | Should -BeTrue
        (BodyOf $script:Calls[-1]).type | Should -Be 'Microsoft.Storage/storageAccounts'
    }
}

Context 'Microsoft Graph user lookup' {
    It 'the signed-in person (/me) and a user by UPN; an unknown user is $null' {
        $script:GraphReq = [System.Collections.Generic.List[string]]::new()
        $SIGraphRestTokenSource = { 'graph-tok' }
        $SIGraphRestSend = { param($Method, $Url, $Headers, $BodyBytes)
            $script:GraphReq.Add("$Method $Url")
            if ($Url -like '*/v1.0/me?*') { return @{ StatusCode = 200; Body = (@{ id = 'oid-1'; userPrincipalName = 'admin@contoso.example'; displayName = 'Admin'; userType = 'Member' } | ConvertTo-Json) } }
            if ($Url -like '*/v1.0/users/a%40contoso.example?*') { return @{ StatusCode = 200; Body = (@{ id = 'oid-2'; userPrincipalName = 'a@contoso.example' } | ConvertTo-Json) } }
            return @{ StatusCode = 404; Body = '{"error":{"code":"Request_ResourceNotFound","message":"no"}}' }
        }
        (Get-SIGraphUser -SignedIn).Id | Should -Be 'oid-1'
        (Get-SIGraphUser -Id 'a@contoso.example').Id | Should -Be 'oid-2'
        Get-SIGraphUser -Id 'ghost@contoso.example' | Should -BeNullOrEmpty
        $script:GraphReq[0] | Should -BeLike 'GET https://graph.microsoft.com/v1.0/me?$select=*'
    }
}
}
