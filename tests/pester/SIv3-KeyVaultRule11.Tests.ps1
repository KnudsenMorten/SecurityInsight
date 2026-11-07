#Requires -Version 5.1
<#
    FRAMEWORK INSTALLER RULE 11 -- the install's Key Vault network shape, set and READ BACK every run, whether the vault is
    MADE, RECOVERED or FOUND (setup/_shared/SI-SetupAzure.ps1 Initialize-SIKeyVault / Set-SIKeyVaultRule11, called by
    setup/ConfigWizard/backend/Initialize-SIInfra.ps1; a resume past the Key Vault step: SI-GuidedInstall.ps1
    Invoke-SIInstallVaultShape). Found by another product's live private install: a re-install RECOVERS the soft-deleted
    vault (purge protection), a recover IGNORES networkAcls (bypass None), and ARM key calls then fail ForbiddenByConnection.
    Against a fake Azure (the one HTTP seam, Invoke-SIAzRestHttp, mocked; a vault store in script scope). OFFLINE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:GlobalNames = 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_SetupSignInState', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret'
    $script:keepAll = @{}
    foreach ($n in $script:GlobalNames) { $script:keepAll[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    $script:hadGlobalToken = [bool](Get-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-PrivateNetwork.ps1')

    $script:Sub = '11111111-1111-1111-1111-111111111111'
    function script:Resp([int]$Code, $Obj) {
        $c = if ($null -eq $Obj) { '' } elseif ($Obj -is [string]) { $Obj } else { $Obj | ConvertTo-Json -Depth 30 -Compress }
        [pscustomobject]@{ StatusCode = $Code; Content = $c; Bytes = $null; Headers = @{}; RetryAfter = '' }
    }
    function script:VaultId([string]$Rg, [string]$Name) { "/subscriptions/$($script:Sub)/resourceGroups/$Rg/providers/Microsoft.KeyVault/vaults/$Name" }
    function script:NewVault([string]$Rg, [string]$Name, $NetworkAcls, [string]$Pna) {
        $p = [ordered]@{ provisioningState = 'Succeeded'; vaultUri = "https://$Name.vault.azure.net/"; tenantId = 'tid-1'; enableRbacAuthorization = $true; enablePurgeProtection = $true; sku = @{ family = 'A'; name = 'standard' } }
        if ($Pna) { $p['publicNetworkAccess'] = $Pna }
        if ($null -ne $NetworkAcls) { $p['networkAcls'] = $NetworkAcls }
        [ordered]@{ name = $Name; id = (VaultId $Rg $Name); location = 'westeurope'; properties = $p }
    }
    function script:Patches { @($script:Calls | Where-Object { $_.Method -eq 'PATCH' }) }
    function script:BodyOf($Call) { if ($Call.Body) { [string]$Call.Body | ConvertFrom-Json } }
    # The fake Azure: vaults by name (any resource group), soft-deleted vaults by name. A recover brings the vault back with
    # its settings -- and networkAcls bypass None (what Azure does). -IgnorePatch: Azure answers a PATCH but changes nothing.
    $script:FakeAzure = { param($m, $u, $b)
        if ($u -match '/locations/([^/]+)/deletedVaults/([^/?]+)\?') {
            $d = $script:Deleted[$Matches[2]]
            if ($d) { return (Resp 200 @{ name = $Matches[2]; id = 'x'; properties = @{ location = $Matches[1]; vaultId = $d.id; deletionDate = '2026-11-01T00:00:00Z'; scheduledPurgeDate = '2027-01-30T00:00:00Z'; purgeProtectionEnabled = $true } }) }
            return $null
        }
        if ($u -match '/subscriptions/[^/]+/providers/Microsoft\.KeyVault/vaults\?') { return (Resp 200 @{ value = @($script:Vaults.Values) }) }
        if ($u -match '/resourceGroups/([^/]+)/providers/Microsoft\.KeyVault/vaults/([^/?]+)\?') {
            $rg = $Matches[1]; $name = $Matches[2]
            switch ($m) {
                'GET' { if ($script:Vaults[$name]) { return (Resp 200 $script:Vaults[$name]) }; return $null }
                'PUT' {
                    $body = [string]$b | ConvertFrom-Json
                    if ([string]$body.properties.createMode -eq 'recover') {
                        $d = $script:Deleted[$name]
                        if (-not $d) { return (Resp 404 '{"error":{"code":"DeletedVaultNotFound","message":"no deleted vault"}}') }
                        $script:Deleted.Remove($name)
                        $d.properties['networkAcls'] = [ordered]@{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(); virtualNetworkRules = @() }
                        $script:Vaults[$name] = $d
                        return (Resp 200 $d)
                    }
                    if ($script:Deleted[$name]) { return (Resp 409 '{"error":{"code":"ConflictError","message":"A vault with the same name already exists in deleted state."}}') }
                    $acl = if ($body.properties.networkAcls) { [ordered]@{ defaultAction = [string]$body.properties.networkAcls.defaultAction; bypass = [string]$body.properties.networkAcls.bypass; ipRules = @(); virtualNetworkRules = @() } } else { $null }
                    $script:Vaults[$name] = NewVault $rg $name $acl ([string]$body.properties.publicNetworkAccess)
                    return (Resp 200 $script:Vaults[$name])
                }
                'PATCH' {
                    if ($script:IgnorePatch) { return (Resp 200 $script:Vaults[$name]) }
                    $body = [string]$b | ConvertFrom-Json
                    foreach ($p in $body.properties.PSObject.Properties) { $script:Vaults[$name].properties[$p.Name] = $p.Value }
                    return (Resp 200 $script:Vaults[$name])
                }
            }
        }
        $null
    }
}

AfterAll {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keepAll[$n] }
    if (-not $script:hadGlobalToken) { Remove-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue }
}

Describe 'framework installer rule 11: the Key Vault network shape' {
    BeforeEach {
        foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $global:SI_AzureAccess_Engine = 'Rest'
        $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'tid-1'; $global:SI_SPN_Secret = 's'
        (Get-SIAzRestState).SubscriptionId = $script:Sub
        (Get-SIAzRestState).TenantId = 'tid-1'
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $script:Vaults = @{}; $script:Deleted = @{}; $script:IgnorePatch = $false
        Mock Get-SILogIngestToken { 'tok|' + $Resource }
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
            $r = & $script:FakeAzure $Method $Uri $Body
            if ($r) { return $r }
            return (Resp 404 '{"error":{"code":"NotFound","message":"not in the fake"}}')
        }
        Mock Start-Sleep { }
    }

    Context 'the body builder (PURE)' {
        It 'private: a vault already in the shape needs NO patch' {
            $v = NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Deny'; bypass = 'AzureServices'; ipRules = @(); virtualNetworkRules = @() }) 'Disabled'
            Get-SIKeyVaultRule11Patch -Vault $v -Private | Should -BeNullOrEmpty
            Test-SIKeyVaultRule11Shape -Vault $v -Private | Should -BeTrue
        }
        It 'private: a RECOVERED vault (bypass None) gets ONLY networkAcls -- its public access is already Disabled' {
            $v = NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(); virtualNetworkRules = @() }) 'Disabled'
            $p = Get-SIKeyVaultRule11Patch -Vault $v -Private
            @($p.properties.Keys) | Should -Be @('networkAcls')
            $p.properties.networkAcls.bypass | Should -Be 'AzureServices'
            $p.properties.networkAcls.defaultAction | Should -Be 'Deny'
            @($p.properties.networkAcls.ipRules).Count | Should -Be 0
        }
        It 'private: an open vault with an IP rule gets public access Disabled AND the rule removed' {
            $v = NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Allow'; bypass = 'AzureServices'; ipRules = @(@{ value = '1.2.3.4' }); virtualNetworkRules = @() }) 'Enabled'
            $p = Get-SIKeyVaultRule11Patch -Vault $v -Private
            $p.properties.publicNetworkAccess | Should -Be 'Disabled'
            $p.properties.networkAcls.defaultAction | Should -Be 'Deny'
            @($p.properties.networkAcls.ipRules).Count | Should -Be 0
        }
        It 'private: a vault with no networkAcls at all is not taken as having the bypass' {
            (Get-SIKeyVaultRule11Patch -Vault (NewVault 'rg-si' 'kv' $null 'Disabled') -Private).properties.networkAcls.bypass | Should -Be 'AzureServices'
        }
        It 'public: only the bypass -- public access and the firewall stay as the customer has them' {
            $v = NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(@{ value = '1.2.3.4' }); virtualNetworkRules = @() }) 'Enabled'
            $p = Get-SIKeyVaultRule11Patch -Vault $v
            @($p.properties.Keys) | Should -Be @('networkAcls')
            $p.properties.networkAcls.bypass | Should -Be 'AzureServices'
            $p.properties.networkAcls.defaultAction | Should -Be 'Deny'
            @($p.properties.networkAcls.ipRules).Count | Should -Be 1
            Get-SIKeyVaultRule11Patch -Vault (NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Allow'; bypass = 'AzureServices' }) 'Enabled') | Should -BeNullOrEmpty
        }
        It 'public: a vault open to all networks needs NO patch -- Azure keeps no bypass on a vault without a firewall, so it could never read back' {
            $fresh = NewVault 'rg-si' 'kv' $null 'Enabled'
            Get-SIKeyVaultRule11Patch -Vault $fresh | Should -BeNullOrEmpty
            Test-SIKeyVaultRule11Shape -Vault $fresh | Should -BeTrue
            Get-SIKeyVaultRule11Patch -Vault (NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Allow' }) 'Enabled') | Should -BeNullOrEmpty
            Get-SIKeyVaultRule11Patch -Vault (NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Allow'; bypass = 'None' }) 'Enabled') | Should -BeNullOrEmpty
            # a PRIVATE install still demands the full shape on a vault without a firewall
            Test-SIKeyVaultRule11Shape -Vault $fresh -Private | Should -BeFalse
        }
        It 'the stop text names only the missing setting -- never "set the networking" (framework rule 17)' {
            $src = Get-Content (Join-Path $PSScriptRoot '..\..\setup\_shared\SI-SetupAzure.ps1') -Raw
            $src | Should -Not -Match 'set it in the Azure portal \(Key vaults > \{0\} > Networking\)'
            $src | Should -Match "Networking > Exceptions\) tick only 'Allow trusted Microsoft services"
            $src | Should -Match 'change nothing else there'
        }
        It 'public: NEGATIVE -- a public install never opens a closed vault' {
            $v = NewVault 'rg-si' 'kv' ([ordered]@{ defaultAction = 'Deny'; bypass = 'None' }) 'Disabled'
            $p = Get-SIKeyVaultRule11Patch -Vault $v
            $p.properties.Contains('publicNetworkAccess') | Should -BeFalse
            $p.properties.networkAcls.defaultAction | Should -Be 'Deny'
        }
        It 'the recover body: createMode recover, with the tenant and sku the schema requires' {
            $b = Get-SIKeyVaultRecoverBody -Location 'westeurope' -TenantId 'tid-1'
            $b.location | Should -Be 'westeurope'
            $b.properties.createMode | Should -Be 'recover'
            $b.properties.tenantId | Should -Be 'tid-1'
            $b.properties.sku.name | Should -Be 'standard'
        }
    }

    Context 'the recover decision (PURE)' {
        It 'found > recover (the install''s own resource group, or not known) > create; another resource group''s deleted vault is never taken' {
            Get-SIKeyVaultEnsureAction -Found ([pscustomobject]@{ VaultName = 'kv' }) -Deleted $null -ResourceGroupName 'rg-si' | Should -Be 'found'
            Get-SIKeyVaultEnsureAction -Found $null -Deleted ([pscustomobject]@{ ResourceId = (VaultId 'rg-si' 'kv') }) -ResourceGroupName 'rg-si' | Should -Be 'recover'
            Get-SIKeyVaultEnsureAction -Found $null -Deleted ([pscustomobject]@{ ResourceId = '' }) -ResourceGroupName 'rg-si' | Should -Be 'recover'
            Get-SIKeyVaultEnsureAction -Found $null -Deleted ([pscustomobject]@{ ResourceId = (VaultId 'rg-other' 'kv') }) -ResourceGroupName 'rg-si' | Should -Be 'create'
            Get-SIKeyVaultEnsureAction -Found $null -Deleted $null -ResourceGroupName 'rg-si' | Should -Be 'create'
        }
    }

    Context 'Initialize-SIKeyVault (what Initialize-SIInfra runs): made, recovered or found -- set and read back' {
        It 'RECOVERED (a re-install, private): recovered with createMode recover, then PATCHed to bypass AzureServices and read back' {
            $script:Deleted['kv-si'] = NewVault 'rg-si' 'kv-si' $null 'Disabled'
            $r = Initialize-SIKeyVault -VaultName 'kv-si' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -PublicNetworkAccess Disabled
            $r.Action | Should -Be 'recovered'
            $r.Changed | Should -BeTrue
            $r.Shape | Should -Match 'bypass AzureServices'
            $r.Vault.VaultUri | Should -Be 'https://kv-si.vault.azure.net/'
            (BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]).properties.createMode | Should -Be 'recover'
            @(Patches).Count | Should -Be 1
            $script:Vaults['kv-si'].properties.networkAcls.bypass | Should -Be 'AzureServices'
            # the order: the PATCH comes after the recover, and a read-back GET after the PATCH
            $i = [array]::IndexOf(@($script:Calls | ForEach-Object Method), 'PATCH')
            @($script:Calls | Select-Object -Skip ($i + 1) | Where-Object { $_.Method -eq 'GET' -and $_.Uri -like '*/vaults/kv-si?*' }).Count | Should -BeGreaterThan 0
        }
        It 'FOUND with bypass None: converged and read back; FOUND in the shape: no PATCH at all' {
            $script:Vaults['kv-si'] = NewVault 'rg-si' 'kv-si' ([ordered]@{ defaultAction = 'Deny'; bypass = 'None'; ipRules = @(); virtualNetworkRules = @() }) 'Disabled'
            $r = Initialize-SIKeyVault -VaultName 'kv-si' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -PublicNetworkAccess Disabled
            $r.Action | Should -Be 'found'
            $r.Changed | Should -BeTrue
            @(Patches).Count | Should -Be 1
            $script:Calls.Clear()
            $r2 = Initialize-SIKeyVault -VaultName 'kv-si' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -PublicNetworkAccess Disabled
            $r2.Changed | Should -BeFalse
            @(Patches).Count | Should -Be 0
        }
        It 'MADE (private): created private from birth, and read back -- no PATCH needed' {
            $r = Initialize-SIKeyVault -VaultName 'kv-new' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -EnablePurgeProtection -PublicNetworkAccess Disabled
            $r.Action | Should -Be 'created'
            $r.Changed | Should -BeFalse
            $r.Shape | Should -Match 'publicNetworkAccess Disabled, defaultAction Deny, bypass AzureServices, ipRules 0, virtualNetworkRules 0'
            @(Patches).Count | Should -Be 0
            @($script:Calls | Where-Object { $_.Method -eq 'GET' -and $_.Uri -like '*/resourceGroups/rg-si/providers/Microsoft.KeyVault/vaults/kv-new?*' }).Count | Should -BeGreaterThan 0 -Because 'the shape is READ BACK, not assumed from the create'
        }
        It 'MADE (public): created as before, open to all networks -- nothing to PATCH, and it passes the read-back' {
            # Live 2026-11-04: a new public vault reads back with no networkAcls at all (Azure keeps no bypass on a vault
            # without a firewall), so PATCHing a bypass could never read back and stopped every new public install.
            $r = Initialize-SIKeyVault -VaultName 'kv-pub' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1'
            $r.Action | Should -Be 'created'
            (BodyOf @($script:Calls | Where-Object { $_.Method -eq 'PUT' })[0]).properties.PSObject.Properties['publicNetworkAccess'] | Should -BeNullOrEmpty
            @(Patches).Count | Should -Be 0
            $r.Changed | Should -BeFalse
        }
        It 'NEGATIVE: another resource group''s deleted vault is not recovered -- the create fails with Azure''s own conflict, as before' {
            $script:Deleted['kv-si'] = NewVault 'rg-other' 'kv-si' $null 'Disabled'
            { Initialize-SIKeyVault -VaultName 'kv-si' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -PublicNetworkAccess Disabled } | Should -Throw '*deleted state*'
            @($script:Calls | Where-Object { $_.Method -eq 'PUT' -and [string]$_.Body -match 'recover' }) | Should -BeNullOrEmpty
        }
        It 'NEGATIVE: a vault that does not read back in the shape FAILS plainly (no key or secret step after it)' {
            $script:Vaults['kv-si'] = NewVault 'rg-si' 'kv-si' ([ordered]@{ defaultAction = 'Deny'; bypass = 'None' }) 'Disabled'
            $script:IgnorePatch = $true
            { Initialize-SIKeyVault -VaultName 'kv-si' -ResourceGroupName 'rg-si' -Location 'westeurope' -SubscriptionId $script:Sub -TenantId 'tid-1' -PublicNetworkAccess Disabled } | Should -Throw '*does not read back*bypass None*'
        }
    }

    Context 'the public-endpoint close test (SI-PrivateNetwork.ps1)' {
        It 'a vault with public access Disabled but bypass None is NOT closed -- Set-SIPublicAccess then fixes it' {
            $none = [pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled'; networkAcls = [pscustomobject]@{ defaultAction = 'Deny'; bypass = 'None' } } }
            Test-SIPublicAccessClosed -Kind vault -Resource $none | Should -BeFalse
            Test-SIPublicAccessClosed -Kind vault -Resource ([pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled'; networkAcls = [pscustomobject]@{ defaultAction = 'Deny'; bypass = 'AzureServices' } } }) | Should -BeTrue
            Test-SIPublicAccessClosed -Kind storage -Resource ([pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled' } }) | Should -BeTrue -Because 'only a vault needs the bypass'
            # Set-SIPublicAccess: the vault is PATCHed to the close body (which carries the bypass) and reads back closed
            $store = @{ v = $none }
            $arm = { param($Method, $Path, $Body) if ($Method -eq 'PATCH') { $store.v = [pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = $Body.properties.publicNetworkAccess; networkAcls = [pscustomobject]$Body.properties.networkAcls } } }; $store.v }.GetNewClosure()
            $x = Set-SIPublicAccess -Arm $arm -ResourceId (VaultId 'rg-si' 'kv-si') -Sleep { param($s) }
            $x.Action | Should -Be 'close'
            $x.Ok | Should -BeTrue
        }
    }

    Context 'WIRING' {
        It 'Initialize-SIInfra runs the vault through Initialize-SIKeyVault (made, recovered or found) and says a recover in one line' {
            $i = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1'))
            $i | Should -Match '\$kvr = Initialize-SIKeyVault -VaultName \$KeyVaultName -ResourceGroupName \$ResourceGroupName'
            $i | Should -Match "'recovered' \{ _Warn \(`"KV RECOVERED"
            $i | Should -Not -Match '\$kv = New-SIKeyVault' -Because 'no create path past the converge'
            $i.IndexOf('$kvr = Initialize-SIKeyVault') | Should -BeLessThan $i.IndexOf("_GrantRbac -RoleName 'Key Vault Secrets User'")
        }
        It 'a resume past the Key Vault step converges the vault BEFORE the step loop; an earlier resume reaches the infrastructure step first' {
            $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
            $a = $g.IndexOf("if (@(`$ctx.State['completed']) -contains 'key-vault') {")
            $a | Should -BeGreaterThan 0
            $g.IndexOf('$vs = Invoke-SIInstallVaultShape -Ctx $ctx', $a) | Should -BeGreaterThan $a
            $a | Should -BeLessThan $g.IndexOf("foreach (`$s in @(`$plan | Where-Object { -not `$_.Preflight -and `$_.Id -ne 'completed' }))")
            foreach ($step in 'storage', 'private-network-data', 'key-vault') {
                $s = $g.IndexOf("`$t['$step'] = {"); $s | Should -BeGreaterThan 0
                $g.IndexOf('Get-SIInstallInfra -Ctx $ctx', $s) | Should -BeLessThan $g.IndexOf('$t[', $s + 10) -Because "$step runs the infrastructure step (and its converge) before anything else"
            }
        }
        It 'the preflight no longer stops on the install''s OWN soft-deleted vault (it is recovered); another resource group''s still stops' {
            $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1'))
            $g | Should -Match "if \(\`$deleted -and \`$delRg -and \`$delRg -eq \`$n\.ResourceGroup\) \{ \`$keptNames \+="
            $g | Should -Match "elseif \(\`$deleted\) \{ \`$problems \+= \('a deleted Key Vault still holds the name"
        }
    }
}
