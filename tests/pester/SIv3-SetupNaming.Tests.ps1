#Requires -Version 5.1
<#
    SETUP NAMES WHAT IT CREATES BY PURPOSE; WHAT FINDS AN EXISTING INSTALL STAYS AS IT IS (framework 5.5, 2026-10-03).

    Setup defaults follow <type>-si-<ring>-<edition>-<hosting> (rg-si-prod-community-ca): no tenant shorthand, no
    'ait' / 'automateit', the edition spelled out, the instance 01 on registry / storage / Key Vault. Every resource
    group setup creates carries product, ring, edition, hosting, tenant, owner, purpose. The SQL admin group is ONE
    product group, grp-si-sql-admins, and it is role-assignable.

    THE PART THAT MUST NOT MOVE. ~30 customers and ~6,000 Community installs run with configs that may rely on the
    names earlier releases created (rg-securityinsight, dce-securityinsight, cae-securityinsight, ...). The engines,
    the launchers and the container bootstrap fall back to those names when a config does not name a resource. They
    are pinned here, value for value, so a later "tidy-up" cannot strand an existing install silently.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupNaming.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-ContainerUpdate.ps1')
    function script:Read-SI([string]$Rel) { [IO.File]::ReadAllText((Join-Path $script:SIRoot $Rel)) }
    function script:Get-ParamDefault([string]$Rel, [string]$Name) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $Rel), [ref]$null, [ref]$null)
        $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $Name })
        if ($p.Count -ne 1) { throw "no parameter $Name in $Rel" }
        if ($p[0].DefaultValue) { $p[0].DefaultValue.SafeGetValue() } else { $null }
    }
    # A setup default that names a resource: what it must never contain.
    $script:BadInDefault = '(?i)(^|[^a-z])(ait|automateit)([^a-z]|$)|-com(-|$)|securityinsight-|-securityinsight'
}

Describe 'the pattern: <type>-si-<ring>-<edition>-<hosting>' {
    It 'names every environment-level resource from ring, edition and hosting' {
        $n = Get-SISetupResourceNames -Ring prod -Edition community -Hosting ca
        $n.ResourceGroup   | Should -BeExactly 'rg-si-prod-community-ca'
        $n.Workspace       | Should -BeExactly 'log-si-prod-community-ca'
        $n.Dce             | Should -BeExactly 'dce-si-prod-community-ca'
        $n.ContainerEnv    | Should -BeExactly 'cae-si-prod-community-ca'
        $n.ManagedIdentity | Should -BeExactly 'id-si-prod-community-ca'
        $n.SqlServer       | Should -BeExactly 'sql-si-prod-community-ca'
        $n.SpnDisplayName  | Should -BeExactly 'SecurityInsight'
        (Get-SISetupResourceNames -Ring r1 -Edition pro -Hosting ca).WebAppDisplayName | Should -BeExactly 'SecurityInsight Management'
        # no release ring / environment in a directory object's name (operator 2026-10-04)
        foreach ($r in 'r0', 'r1', 'r2', 'prod') { foreach ($e in 'community', 'pro') { $n = Get-SISetupResourceNames -Ring $r -Edition $e -Hosting ca; $n.WebAppDisplayName | Should -BeExactly 'SecurityInsight Management'; $n.SpnDisplayName | Should -BeExactly 'SecurityInsight' } }
    }
    It 'globally unique names carry the instance 01 and drop the dashes where Azure allows none' {
        $n = Get-SISetupResourceNames -Ring r1 -Edition pro -Hosting ca
        $n.StorageAccount | Should -BeExactly 'stsir1proca01'
        $n.Acr            | Should -BeExactly 'acrsir1proca01'
        $n.KeyVault       | Should -BeExactly 'kv-si-r1-pro-ca01'
    }
    It 'every combination fits Azure''s limits (storage 3-24 lowercase alphanumeric, registry 5-50, Key Vault 3-24)' {
        foreach ($r in 'r0', 'r1', 'r2', 'prod') { foreach ($e in 'community', 'pro') { foreach ($h in 'ca', 'vm') {
            $n = Get-SISetupResourceNames -Ring $r -Edition $e -Hosting $h
            $n.StorageAccount | Should -Match '^[a-z0-9]{3,24}$'
            $n.Acr            | Should -Match '^[a-z0-9]{5,50}$'
            $n.KeyVault       | Should -Match '^[a-z][a-z0-9-]{1,22}[a-z0-9]$'
            # CR5 step 1 (#655): the component names are TODAY's names, kept value for value (asset tagging's identity is
            # uami-securityinsight-tagging on every install); the CR5 names for new installs are a later step
            $components = @((Get-SISetupComponentNames).Keys)
            foreach ($k in @($n.Keys)) { if ($components -notcontains $k) { $n[$k] | Should -Not -Match $script:BadInDefault } }
        } } }
    }
    It 'the edition is spelled out: com is refused, community and pro are the only editions' {
        { Resolve-SISetupEdition -Edition 'com' } | Should -Throw '*community*'
        { Get-SISetupResourceNames -Ring prod -Edition com -Hosting ca } | Should -Throw
        Resolve-SISetupEdition -Edition 'Pro' | Should -BeExactly 'pro'
    }
    It 'the edition comes from the licence: a licence path, a licence value or a licence file = pro; nothing = community' {
        Resolve-SISetupEdition | Should -BeExactly 'community'
        Resolve-SISetupEdition -LicencePath 'C:\x\customer.silicense' | Should -BeExactly 'pro'
        Resolve-SISetupEdition -LicenceValue 'eyJ...' | Should -BeExactly 'pro'
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si-naming-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path (Join-Path $root 'config') | Out-Null
        try {
            Resolve-SISetupEdition -SIRoot $root | Should -BeExactly 'community'
            Set-Content -LiteralPath (Join-Path $root 'config\acme.silicense') -Value '{}'
            Resolve-SISetupEdition -SIRoot $root | Should -BeExactly 'pro'
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'a pattern resource group names what goes inside it (a suffix carries over); any other resource group returns nothing' {
        (Get-SISetupNamesFromResourceGroup -ResourceGroupName 'rg-si-r1-community-ca').ContainerEnv | Should -BeExactly 'cae-si-r1-community-ca'
        $s = Get-SISetupNamesFromResourceGroup -ResourceGroupName 'rg-si-prod-pro-ca-test'
        $s.ContainerEnv | Should -BeExactly 'cae-si-prod-pro-ca-test'
        $s.Acr          | Should -BeExactly 'acrsiprodprocatest01'
        foreach ($rg in 'rg-securityinsight', 'rg-customer-own', 'rg-si-prod-com-ca', 'RG-SI-PROD-PRO-CA', '', $null) {
            Get-SISetupNamesFromResourceGroup -ResourceGroupName $rg | Should -BeNullOrEmpty -Because "'$rg' is not a setup-pattern resource group"
        }
    }
}

Describe 'globally unique names carry a stable per-subscription suffix (live 2026-10-07: sql-si-prod-pro-ca taken by another tenant)' {
    BeforeAll {
        $script:SubA = '22222222-2222-2222-2222-222222222222'
        $script:SubB = 'f8de5145-1111-2222-3333-444444444444'
    }
    It 'the suffix is the first 6 hex of SHA-256(subscription id, lower case): stable, case-insensitive, empty without a subscription' {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $want = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($script:SubA))[0..2] | ForEach-Object { $_.ToString('x2') })); $sha.Dispose()
        Get-SISetupSubscriptionSuffix -SubscriptionId $script:SubA | Should -BeExactly $want
        Get-SISetupSubscriptionSuffix -SubscriptionId (' ' + $script:SubA.ToUpperInvariant() + ' ') | Should -BeExactly $want
        Get-SISetupSubscriptionSuffix -SubscriptionId $script:SubA | Should -Match '^[0-9a-f]{6}$'
        Get-SISetupSubscriptionSuffix -SubscriptionId '' | Should -BeExactly ''
        Get-SISetupSubscriptionSuffix -SubscriptionId $script:SubB | Should -Not -Be $want
    }
    It 'two installs in different subscriptions get different storage, Key Vault, registry and SQL server names -- and the same other names' {
        $a = Get-SISetupResourceNames -Ring prod -Edition pro -Hosting ca -SubscriptionId $script:SubA
        $b = Get-SISetupResourceNames -Ring prod -Edition pro -Hosting ca -SubscriptionId $script:SubB
        $sfx = Get-SISetupSubscriptionSuffix -SubscriptionId $script:SubA
        $a.SqlServer      | Should -BeExactly ('sql-si-prod-pro-ca-' + $sfx)
        $a.KeyVault       | Should -BeExactly ('kv-si-prod-pro-ca-' + $sfx)
        $a.StorageAccount | Should -BeExactly ('stsiprodproca' + $sfx)
        $a.Acr            | Should -BeExactly ('acrsiprodproca' + $sfx)
        foreach ($k in 'StorageAccount', 'KeyVault', 'Acr', 'SqlServer') { $a[$k] | Should -Not -Be $b[$k] -Because $k }
        foreach ($k in 'ResourceGroup', 'Workspace', 'Dce', 'ContainerEnv', 'ManagedIdentity', 'SpnDisplayName') { $a[$k] | Should -BeExactly $b[$k] -Because "$k is not a global name" }
    }
    It 'without a subscription the names are what older releases created (existing installs and callers unchanged)' {
        $n = Get-SISetupResourceNames -Ring prod -Edition pro -Hosting ca
        $n.SqlServer | Should -BeExactly 'sql-si-prod-pro-ca'; $n.StorageAccount | Should -BeExactly 'stsiprodproca01'; $n.KeyVault | Should -BeExactly 'kv-si-prod-pro-ca01'
    }
    It 'every combination, with or without a resource-group suffix, keeps each resource''s length and character rules -- and the suffix' {
        $labels = @()
        foreach ($r in 'r0', 'r1', 'r2', 'prod') { foreach ($e in 'community', 'pro') { foreach ($h in 'ca', 'vm') { $labels += ('rg-si-{0}-{1}-{2}' -f $r, $e, $h); $labels += ('rg-si-{0}-{1}-{2}-a-very-long-naming-suffix-for-a-test-environment' -f $r, $e, $h) } } }
        foreach ($sub in $script:SubA, $script:SubB) {
            $sfx = Get-SISetupSubscriptionSuffix -SubscriptionId $sub
            foreach ($rg in $labels) {
                $n = Get-SISetupNamesFromResourceGroup -ResourceGroupName $rg -SubscriptionId $sub
                $n.StorageAccount | Should -Match '^[a-z0-9]{3,24}$' -Because $rg
                $n.Acr            | Should -Match '^[a-zA-Z0-9]{5,50}$' -Because $rg
                $n.KeyVault       | Should -Match '^[a-z][a-z0-9-]{1,22}[a-z0-9]$' -Because $rg
                $n.KeyVault       | Should -Not -Match '--'
                $n.SqlServer      | Should -Match '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$' -Because $rg
                $n.SqlServer      | Should -Not -Match '--'
                foreach ($k in 'StorageAccount', 'KeyVault', 'Acr', 'SqlServer') { $n[$k] | Should -Match ([regex]::Escape($sfx) + '$') -Because "$k keeps the suffix ($rg)" }
            }
        }
    }
}

Describe 'the resource group tags' {
    It 'are exactly the seven keys, purpose SecurityInsight, owner empty unless given' {
        $t = Get-SIResourceGroupTags -Ring prod -Edition community -Hosting vm -Tenant 'contoso.onmicrosoft.com'
        @($t.Keys) | Should -Be @('product', 'ring', 'edition', 'hosting', 'tenant', 'owner', 'purpose')
        $t.product | Should -BeExactly 'si'; $t.purpose | Should -BeExactly 'SecurityInsight'
        $t.owner | Should -BeExactly ''; $t.tenant | Should -BeExactly 'contoso.onmicrosoft.com'
        (Get-SIResourceGroupTags -Ring r1 -Edition pro -Hosting ca -Owner 'secops').owner | Should -BeExactly 'secops'
        (ConvertTo-SIAzCliTagArgs -Tags $t)[0] | Should -BeExactly '--tags'
        (ConvertTo-SIAzCliTagArgs -Tags $t) | Should -Contain 'owner='
        (ConvertTo-SIAzTagHashtable -Tags $t)['hosting'] | Should -BeExactly 'vm'
    }
    It 'no personal address is baked into shipped code as an owner' {
        foreach ($f in 'setup\_shared\SI-SetupNaming.ps1', 'config\setup-unattended.sample.json', 'setup\install-parameters.json') {
            Read-SI $f | Should -Not -Match '(?i)owner[^\r\n]{0,40}[a-z0-9._-]+@[a-z0-9.-]+\.[a-z]{2,}' -Because "$f must not default the owner to a person"
        }
    }
    It 'every place SETUP creates a resource group sets them' {
        $ps = @{
            'setup\ConfigWizard\backend\Initialize-SIInfra.ps1' = 'New-AzResourceGroup'
            'setup\Validate-SILogAnalytics.ps1'                 = 'New-AzResourceGroup'
            'setup\Validate-SIOpenAI.ps1'                       = 'New-AzResourceGroup'
        }
        foreach ($f in $ps.Keys) {
            # the module cmdlet or its REST twin (#305: setup runs with no PowerShell modules)
            $lines = @((Read-SI $f) -split "`n" | Where-Object { $_ -match 'New-(SI)?AzResourceGroup\s+-Name' })
            $lines.Count | Should -BeGreaterThan 0 -Because "$f creates a resource group"
            foreach ($l in $lines) { $l | Should -Match '-Tag \(' -Because "$f`: $($l.Trim())" }
        }
        Read-SI 'setup\ConfigWizard\backend\Initialize-SIInfra.ps1' | Should -Match 'Get-SIResourceGroupTags -Ring \$Ring -Edition \$rgTagEdition -Hosting \$Hosting'
        Read-SI 'Setup-SecurityInsight-Unattended.ps1' | Should -Match 'Hosting\s+= \$nHosting'
        Read-SI 'setup\ConfigWizard\Start-SetupWizard.ps1' | Should -Match "Hosting\s+= \`$\(if \(\`$st\.hostType -eq 'azureContainerMI'\) \{ 'ca' \} else \{ 'vm' \}\)"
    }
}

Describe 'the tenant tag (REST sign-in, no module, never signs anyone in)' {
    It 'is the default domain when someone is signed in, the tenant id otherwise, and never fails' {
        function Get-SISetupAzureContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tid-1' } } }
        function Get-SITenant { param($TenantId) $script:TenantAsked = $TenantId; [pscustomobject]@{ DefaultDomain = 'contoso.onmicrosoft.com' } }
        Resolve-SITenantTag -TenantId '' | Should -BeExactly 'contoso.onmicrosoft.com'
        $script:TenantAsked | Should -Be 'tid-1'
        function Get-SITenant { throw 'no rights' }
        Resolve-SITenantTag -TenantId 'tid-2' | Should -BeExactly 'tid-2'
        function Get-SISetupAzureContext { $null }
        $script:TenantCalled = $false
        function Get-SITenant { $script:TenantCalled = $true }
        Resolve-SITenantTag -TenantId 'tid-3' | Should -BeExactly 'tid-3'
        Resolve-SITenantTag -TenantId '' | Should -BeExactly ''
        $script:TenantCalled | Should -BeFalse -Because 'a tag never makes anyone sign in'
    }
}

Describe 'the setup defaults follow the pattern' {
    It 'the unattended sample leaves every resource name to the pattern, with the naming knobs' {
        $j = Read-SI 'config\setup-unattended.sample.json' | ConvertFrom-Json
        foreach ($k in 'ResourceGroupName', 'WorkspaceName', 'DceName', 'StorageAccountName') { $j.Resources.$k | Should -BeNullOrEmpty -Because "Resources.$k defaults to the pattern" }
        $j.Auth_Community.DisplayName | Should -BeNullOrEmpty
        $j.Container.EnvName | Should -BeNullOrEmpty
        $j.Naming.Ring | Should -BeExactly 'prod'
        $j.Naming.Owner | Should -BeExactly ''
        foreach ($sec in 'Naming', 'Resources', 'Auth_Community', 'Container') {
            foreach ($p in $j.$sec.PSObject.Properties) { if ($p.Value -is [string]) { $p.Value | Should -Not -Match $script:BadInDefault -Because "$sec.$($p.Name)" } }
        }
    }
    It 'the unattended setup fills ONLY empty names, and keeps a customer resource group''s storage derivation as before' {
        $c = Read-SI 'Setup-SecurityInsight-Unattended.ps1'
        $c | Should -Match '\$defaultNames = Get-SISetupResourceNames -Ring \$nRing -Edition \$nEdition -Hosting \$nHosting'
        $c | Should -Match "\`$nHosting = if \(\[bool\]\(_CfgValue \`$cfg\.Container 'Enabled'\)\) \{ 'ca' \} else \{ 'vm' \}"
        $c | Should -Match "Resolve-SISetupEdition -Edition \`$nEditionIn -LicencePath"
        $c | Should -Match "if \(\`$rgDefaulted\)\s+\{ _CfgSet \`$cfg\.Resources 'ResourceGroupName'"
        $c | Should -Match "\('st' \+ \(\(\`$cfg\.Resources\.ResourceGroupName -replace '\[\^a-z0-9\]',''\) \+ 'si'\)\)"
    }
    It 'the guided install defaults to the Community container name, and names the Pro one' {
        $j = Read-SI 'setup\install-parameters.json' | ConvertFrom-Json
        $rg = @($j.parameters | Where-Object key -eq 'resourceGroup')[0]
        $rg.default | Should -BeExactly 'rg-si-prod-community-ca'
        $rg.defaultByEdition.pro | Should -BeExactly 'rg-si-prod-pro-ca'
        $ws = @($j.parameters | Where-Object key -eq 'workspaceName')[0]
        $ws.default | Should -BeExactly 'log-si-prod-community-ca'
        @($j.parameters | Where-Object key -eq 'owner')[0].default | Should -BeExactly ''
        $j.naming.sqlAdminGroup | Should -BeExactly 'grp-si-sql-admins'
        foreach ($p in $j.parameters) { if ($p.PSObject.Properties['default'] -and $p.default -is [string]) { $p.default | Should -Not -Match $script:BadInDefault -Because $p.key } }
    }
    It 'the wizard page''s name defaults follow the pattern (the storage container and the secret NAME are not resource names)' {
        $html = Read-SI 'setup\ConfigWizard\Setup-SecurityInsight.html'
        $defs = @([regex]::Matches($html, 'data-default="([^"]*)"') | ForEach-Object { $_.Groups[1].Value })
        $defs | Should -Contain 'rg-si-prod-community-vm'
        $defs | Should -Contain 'log-si-prod-community-vm'
        $defs | Should -Contain 'dce-si-prod-community-vm'
        $defs | Should -Contain 'SecurityInsight (prod-community-vm)'
        foreach ($d in $defs | Where-Object { $_ -notin 'SecurityInsight-Secret', 'securityinsight' }) { $d | Should -Not -Match $script:BadInDefault -Because "data-default '$d'" }
        $html | Should -Not -Match '(?i)myorg'
    }
    It 'the wizard script swaps vm for ca when the engines run as container jobs, and never sends a hard-coded environment name' {
        $js = Read-SI 'setup\ConfigWizard\app.js'
        $js | Should -Match "const SI_DEFAULT_LABEL_CA = 'prod-community-ca'"
        $js | Should -Match "if \(key === 'hostType'\) syncHostingDefaults\(\)"
        $js | Should -Not -Match "\|\| '(rg|log|dce|cae|sp)-[a-z-]*securityinsight[a-z-]*'"
        $js | Should -Not -Match "EnvName:\s+'cae-securityinsight'"
        $js | Should -Match '\[A-Za-z0-9 \\-_\.\(\)\]' -Because 'the display name default has the environment in brackets'
    }
    It 'the SQL admin group default is grp-si-sql-admins' {
        Get-ParamDefault 'setup\Set-SISqlAdminGroup.ps1' 'GroupName' | Should -BeExactly 'grp-si-sql-admins'
    }
    It 'the container setup takes a saved name first, then the pattern, then the name earlier releases used' {
        foreach ($p in 'EnvName', 'ManagedIdentityName') { Get-ParamDefault 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1' $p | Should -BeExactly '' }
        $c = Read-SI 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1'
        $c | Should -Match "_PickName \`$EnvName 'SI_Bootstrap_EnvName' 'ContainerEnv' 'cae-securityinsight'"
        $c | Should -Match "_PickName \`$ManagedIdentityName 'SI_Bootstrap_ManagedIdentityName' 'ManagedIdentity' 'uami-securityinsight'"
        $c | Should -Match '-ManagedIdentityName \$ManagedIdentityName'
    }
    It 'the engine jobs'' identity name is saved with the hosting, and kept when a later run does not pass it' {
        $f = Join-Path ([IO.Path]::GetTempPath()) ('si-naming-' + [guid]::NewGuid().ToString('N') + '.ps1')
        try {
            $null = Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'rg-si-prod-community-ca' -AcrName 'acrsiprodcommunityca01' -ManagedIdentityName 'id-si-prod-community-ca'
            Get-SIContainerHostingValue -Text ([IO.File]::ReadAllText($f)) -Name 'SI_Bootstrap_ManagedIdentityName' | Should -BeExactly 'id-si-prod-community-ca'
            # Bootstrap-ContainerAppJob.ps1 saves without the identity: the saved one stays
            $null = Save-SIContainerHostingConfig -ConfigPath $f -SubscriptionId 's' -ResourceGroupName 'rg-si-prod-community-ca' -AcrName 'acrsiprodcommunityca01' -EnvName 'cae-si-prod-community-ca'
            Get-SIContainerHostingValue -Text ([IO.File]::ReadAllText($f)) -Name 'SI_Bootstrap_ManagedIdentityName' | Should -BeExactly 'id-si-prod-community-ca'
        } finally { Get-Item -Path ($f + '*') -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'server / unattended / container setup: a defaulted storage or registry name carries the subscription suffix; an existing install keeps its own (#442)' {
    BeforeAll { $script:Sfx = Get-SISetupSubscriptionSuffix -SubscriptionId '11111111-2222-3333-4444-555555555555' }
    It 'a new install (nothing in the group) gets the new suffixed name' {
        $want = Get-SISetupGlobalName -Kind StorageAccount -Label 'prod-community-vm' -Suffix $script:Sfx
        # stsiprodcommunityvm + 6 hex = 25 > 24: the label is shortened, never the suffix
        $want | Should -BeExactly ('stsiprodcommunityv' + $script:Sfx)
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted $want -Legacy @('stsiprodcommunityvm01') -Existing @() | Should -BeExactly $want
    }
    It 'an existing install keeps the name an earlier release gave it -- pattern group and the customer''s own group' {
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted ('stsiprodcommunityvm' + $script:Sfx) -Legacy @('stsiprodcommunityvm01') -Existing @('stsiprodcommunityvm01') | Should -BeExactly 'stsiprodcommunityvm01'
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted ('stsirgsecurityinsight' + $script:Sfx) -Legacy @('strgsecurityinsightsi') -Existing @('strgsecurityinsightsi', 'customerdata') | Should -BeExactly 'strgsecurityinsightsi'
        Resolve-SISetupDefaultGlobalName -Kind Acr -Wanted ('acrsirgsecurityinsight' + $script:Sfx) -Legacy @('acrrgsecurityinsight') -Existing @('acrrgsecurityinsight') | Should -BeExactly 'acrrgsecurityinsight'
    }
    It 'the only SecurityInsight-named resource of the kind is kept; a customer''s own resource is never taken over; two candidates: the new name' {
        Resolve-SISetupDefaultGlobalName -Kind Acr -Wanted 'acrsinew' -Legacy @('acrsiold01') -Existing @('acrsicustomname') | Should -BeExactly 'acrsicustomname'
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted 'stsinew' -Legacy @('stsiold01') -Existing @('customerdata') | Should -BeExactly 'stsinew'
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted 'stsinew' -Legacy @('stsiold01') -Existing @('stsia', 'stsib') | Should -BeExactly 'stsinew'
    }
    It 'a group setup could not read keeps the name earlier releases used -- never a second storage account next to an unseen install' {
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted 'stsinew' -Legacy @('stsiprodcommunityvm01') -ReadFailed | Should -BeExactly 'stsiprodcommunityvm01'
        Resolve-SISetupDefaultGlobalName -Kind StorageAccount -Wanted 'stsinew' -Legacy @() -ReadFailed | Should -BeExactly 'stsinew'
    }
    It 'the guided install''s selection is the same rule (Select-SIInstallExistingName delegates)' {
        Select-SISetupExistingName -Existing @('stsiprodproca01') -Wanted 'stsiprodproca1a2b3c' -Legacy @('stsiprodproca01') -Prefix '^stsi' | Should -BeExactly 'stsiprodproca01'
        Read-SI 'setup\_shared\SI-GuidedInstall.ps1' | Should -Match 'Select-SISetupExistingName -Existing \$Existing -Wanted \$Wanted -Legacy @\(\$Legacy\)'
    }
    It 'a customer''s own group gets a suffixed storage / registry name within each kind''s limits' {
        $rg = 'rg-a-very-long-customer-resource-group-name-for-security'
        $st = Get-SISetupGlobalName -Kind StorageAccount -Label $rg -Suffix $script:Sfx
        $st.Length | Should -BeLessOrEqual 24; $st | Should -Match ('^stsi[a-z0-9]+' + $script:Sfx + '$')
        $acr = Get-SISetupGlobalName -Kind Acr -Label $rg -Suffix $script:Sfx
        $acr.Length | Should -BeLessOrEqual 50; $acr | Should -Match ('^acrsi[a-z0-9]+' + $script:Sfx + '$')
    }
    It 'the unattended setup defaults both names with the suffix and resolves them against the group after sign-in, before Phase 2' {
        $u = Read-SI 'Setup-SecurityInsight-Unattended.ps1'
        $u | Should -Match 'Get-SISetupSubscriptionSuffix -SubscriptionId \(\[string\]\$cfg\.Sub\.SubscriptionId\)'
        $u | Should -Match "_NewGlobalName 'StorageAccount' \`$siPatternLabel \`$saOld"
        $u | Should -Match "_NewGlobalName 'StorageAccount' \(\[string\]\`$cfg\.Resources\.ResourceGroupName\) \`$saOld"
        $u | Should -Match "_NewGlobalName 'Acr' \`$siPatternLabel \`$acrOld"
        $u | Should -Match 'Resolve-SISetupDefaultGlobalName -Kind \$k -Wanted \$siGlobalDefaults\[\$k\]\.Wanted -Legacy \$siGlobalDefaults\[\$k\]\.Legacy -Existing \$have -ReadFailed:\$siReadFailed'
        $call = $u.IndexOf('$pick = Resolve-SISetupDefaultGlobalName')
        $call | Should -BeLessThan $u.IndexOf('# Phase 2 -- Infrastructure')
        $call | Should -BeGreaterThan $u.IndexOf('Community flavour -- using this session''s sign-in')
        $u | Should -Match "\('st' \+ \(\(\`$cfg\.Resources\.ResourceGroupName -replace '\[\^a-z0-9\]',''\) \+ 'si'\)\)\.ToLowerInvariant\(\)" -Because 'the name earlier releases derived from the customer''s own group stays the legacy candidate'
    }
    It 'the container setup: an explicit or saved registry name wins; otherwise the group''s existing registry; otherwise the suffixed name' {
        $c = Read-SI 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1'
        $c | Should -Match "_PickName \`$AcrName 'SI_Bootstrap_AcrName' '' ''"
        $c | Should -Match "Get-SIArmResource -ResourceGroupName \`$ResourceGroupName -ResourceType 'Microsoft\.ContainerRegistry/registries'"   # #521: ARM, not az resource list
        $c | Should -Match 'Resolve-SISetupDefaultGlobalName -Kind Acr -Wanted \$acrNew -Legacy @\(\$acrOld\) -Existing \$acrHave -ReadFailed:\$acrReadFailed'
        $c | Should -Match "\('acr' \+ \(\`$ResourceGroupName -replace '\[\^a-z0-9\]',''\)\)\.ToLowerInvariant\(\)" -Because 'the name earlier releases derived stays the legacy candidate'
    }
}

Describe 'LOCKED: the runtime fallbacks an existing install may rely on are UNCHANGED' {
    It 'the container bootstrap''s own defaults (a re-run without SI_Bootstrap_* in the config)' {
        Get-ParamDefault 'Bootstrap-ContainerAppJob.ps1' 'ResourceGroupName'   | Should -BeExactly 'rg-securityinsight'
        Get-ParamDefault 'Bootstrap-ContainerAppJob.ps1' 'AcrName'             | Should -BeExactly 'acrsecurityinsight'
        Get-ParamDefault 'Bootstrap-ContainerAppJob.ps1' 'EnvName'             | Should -BeExactly 'cae-securityinsight'
        Get-ParamDefault 'Bootstrap-ContainerAppJob.ps1' 'ManagedIdentityName' | Should -BeExactly 'uami-securityinsight'
    }
    It 'the launchers'' layer-0 infrastructure names' {
        $c = Read-SI 'launcher\_lib\SecurityInsight.shared-defaults.ps1'
        $c | Should -Match "(?m)^\`$global:WorkspaceName\s+= 'log-platform-management-securityinsight'"
        $c | Should -Match "(?m)^\`$global:WorkspaceResourceGroup = 'rg-securityinsight'"
        $c | Should -Match "(?m)^\`$global:DceName\s+= 'dce-securityinsight'"
        $c | Should -Match "(?m)^\`$global:DceResourceGroup\s+= 'rg-dce-securityinsight'"
        $c | Should -Match "(?m)^\`$global:DcrResourceGroup\s+= 'rg-dcr-securityinsight'"
    }
    It 'the engines'' fallbacks when the config names nothing' {
        $ra = Read-SI 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $ra | Should -Match "\`$laDceName = 'dce-securityinsight'"
        $ra | Should -Match "\`$laDcrRg   = 'rg-dcr-securityinsight'"
        $ra | Should -Match "\`$laWsName = 'log-platform-management-securityinsight'"
        $ra | Should -Match "else \{ 'rg-securityinsight' \}"
        $ra | Should -Match "'rg-dce-securityinsight'"
        # the collection run's fallbacks live in its access check (the run reads its targets there; same names as before)
        $run = Read-SI 'engine\asset-profiling\shared\SI-RunAccessCheck.ps1'
        $run | Should -Match "if \(-not \`$wsRg\) \{ \`$wsRg = 'rg-securityinsight' \}"
        $run | Should -Match "if \(-not \`$wsName\) \{ \`$wsName = 'log-platform-management-securityinsight' \}"
        $run | Should -Match "if \(-not \`$dceRg\) \{ \`$dceRg = 'rg-securityinsight' \}"
        $run | Should -Match "if \(-not \`$dcrRg\) \{ \`$dcrRg = 'rg-securityinsight' \}"
        Read-SI 'engine\risk-analysis\_shared\Ensure-SecurityInsightInfra.ps1' | Should -Match "\[string\] \`$WorkspaceResourceGroup = 'rg-securityinsight'"
    }
    It 'the setup tools that FIND an existing install (the validators) keep their lookup names' {
        $la = Read-SI 'setup\Validate-SILogAnalytics.ps1'
        foreach ($v in "else { `"rg-securityinsight`" }", "else { `"rg-dce-securityinsight`" }", "else { `"rg-dcr-securityinsight`" }",
                       "else { `"log-platform-management-securityinsight`" }", "else { `"dce-securityinsight`" }") {
            $la | Should -Match ([regex]::Escape($v))
        }
    }
    It 'the container update finds the engine jobs by the same prefix' {
        Read-SI 'setup\ConfigWizard\backend\Initialize-SIContainerInfra.ps1' | Should -Match "-like 'caj-si-\*'"
    }
}

Describe 'the SQL admin group is role-assignable (a Graph fake)' {
    BeforeAll {
        $script:Tool = Join-Path $script:SIRoot 'setup\Set-SISqlAdminGroup.ps1'
        function script:Get-SISetupAzureContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' }; Tenant = [pscustomobject]@{ Id = 'tid-1' } } }
        function script:Get-SIAzureToken { 'tok' }
        function script:Start-Sleep { }
        function script:Write-Host { param([Parameter(ValueFromRemainingArguments)]$a) $global:SINamingSaid.Add((@($a | Where-Object { $_ -isnot [System.ConsoleColor] -and "$_" -notmatch '^-' }) -join ' ')) }
        function script:Invoke-SIAzRestMethod {
            param([string]$Method, [string]$Path, [string]$Payload)
            if ($Method -eq 'PUT') { $global:SINamingFake.Puts.Add($Payload); $p = ($Payload | ConvertFrom-Json).properties; $global:SINamingFake.AdminSid = $p.sid; $global:SINamingFake.AdminLogin = $p.login; return [pscustomobject]@{ StatusCode = 200; Content = '{}' } }
            [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ sid = $global:SINamingFake.AdminSid; login = $global:SINamingFake.AdminLogin } } | ConvertTo-Json) }
        }
        function script:Invoke-RestMethod {
            param([string]$Method, [string]$Uri, $Headers, [string]$ContentType, [string]$Body)
            $global:SINamingFake.Calls.Add(('{0} {1}' -f $Method, $Uri))
            if ($Method -eq 'Get' -and $Uri -match '/v1\.0/groups\?\$filter=') { return [pscustomobject]@{ value = @($global:SINamingFake.Groups) } }
            if ($Method -eq 'Post' -and $Uri -match '/v1\.0/groups$') { $global:SINamingFake.Created = $Body | ConvertFrom-Json; return [pscustomobject]@{ id = 'grp-new' } }
            if ($Method -eq 'Get' -and $Uri -match '/v1\.0/groups/[^/?]+\?') { return [pscustomobject]@{ id = 'x' } }
            if ($Method -eq 'Get' -and $Uri -match '/v1\.0/directoryObjects/([^/?]+)$') {
                $id = $Matches[1]; if ($global:SINamingFake.Objects.ContainsKey($id)) { return $global:SINamingFake.Objects[$id] }; throw '404'
            }
            if ($Method -eq 'Get' -and $Uri -match '/v1\.0/servicePrincipals\?') { return [pscustomobject]@{ value = @() } }
            if ($Method -eq 'Post' -and $Uri -match '/checkMemberGroups$') { return [pscustomobject]@{ value = @() } }
            if ($Method -eq 'Post' -and $Uri -match '/members/\$ref$') { $global:SINamingFake.Added.Add((($Body | ConvertFrom-Json).'@odata.id' -split '/')[-1]); return $null }
            throw "unexpected Graph call: $Method $Uri"
        }
        # The script calls Invoke-SIRestMethod, which another suite of the same batch may have published GLOBALLY: that
        # copy calls the real Invoke-RestMethod from its own file and never sees the fake above (four of these tests then
        # went to the network and got 401). This suite's own copy is found first and stays on the fake.
        function script:Invoke-SIRestMethod {
            param([string]$Method = 'GET', [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 120)
            $b = $Body
            if ($null -ne $b -and -not ($b -is [string])) { $b = ConvertTo-Json -InputObject $b -Depth 30 -Compress }
            Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType $ContentType -Body ([string]$b)
        }
        function script:New-Fake([object[]]$Groups = @(), [string]$AdminSid = '', [string]$AdminLogin = '', [hashtable]$Objects = @{}) {
            $global:SINamingSaid = New-Object System.Collections.Generic.List[string]
            $global:SINamingFake = @{ Groups = $Groups; AdminSid = $AdminSid; AdminLogin = $AdminLogin; Objects = $Objects; Created = $null
                              Calls = New-Object System.Collections.Generic.List[string]; Added = New-Object System.Collections.Generic.List[string]; Puts = New-Object System.Collections.Generic.List[string] }
        }
    }
    It 'creates the group with isAssignableToRole = true, adds the current admin, then makes the group the admin' {
        New-Fake -AdminSid 'user-1' -AdminLogin 'admin@x' -Objects @{ 'user-1' = [pscustomobject]@{ id = 'user-1'; '@odata.type' = '#microsoft.graph.user' } }
        & $script:Tool -SqlServerName 'sql-si-prod-pro-ca' -ResourceGroupName 'rg-si-prod-pro-ca'
        $global:SINamingFake.Created.displayName | Should -BeExactly 'grp-si-sql-admins'
        $global:SINamingFake.Created.isAssignableToRole | Should -BeTrue
        $global:SINamingFake.Created.securityEnabled | Should -BeTrue
        $global:SINamingFake.Created.mailEnabled | Should -BeFalse
        @($global:SINamingFake.Added) | Should -Be @('user-1')
        $global:SINamingFake.AdminSid | Should -BeExactly 'grp-new'
        $global:SINamingFake.AdminLogin | Should -BeExactly 'grp-si-sql-admins'
    }
    It 'REFUSES an existing group that is not role-assignable: no member added, the server untouched, the steps printed' {
        New-Fake -Groups @([pscustomobject]@{ id = 'grp-old'; displayName = 'grp-si-sql-admins'; securityEnabled = $true; isAssignableToRole = $false }) -AdminSid 'grp-old' -AdminLogin 'grp-si-sql-admins'
        { & $script:Tool -SqlServerName 'sql-si-prod-pro-ca' -ResourceGroupName 'rg-si-prod-pro-ca' -MemberObjectIds 'spn-1' } | Should -Throw '*not role-assignable*'
        $global:SINamingFake.Added.Count | Should -Be 0
        $global:SINamingFake.Puts.Count | Should -Be 0
        $global:SINamingFake.Created | Should -BeNullOrEmpty
        $all = $global:SINamingSaid -join "`n"
        $all | Should -Match "-GroupName 'grp-si-sql-admins-new' -MemberObjectIds"
        $all | Should -Match '-ReplaceCurrentAdminGroup'
        # #564: the delete step is a Microsoft Entra admin center path (a customer has no az CLI) -- was 'az ad group delete'
        $all | Should -Match 'Microsoft Entra admin center: Groups > All groups > grp-old > Delete'
        $all | Should -Not -Match '\baz (ad|rest) '
        # the rename step: the admin center's Properties page (was an 'az rest' PATCH of displayName)
        $all | Should -Match 'Properties > Group name = '
    }
    It 'an existing role-assignable group is used as it is' {
        New-Fake -Groups @([pscustomobject]@{ id = 'grp-ok'; displayName = 'grp-si-sql-admins'; securityEnabled = $true; isAssignableToRole = $true }) -AdminSid 'grp-ok' -AdminLogin 'grp-si-sql-admins'
        & $script:Tool -SqlServerName 's' -ResourceGroupName 'r'
        $global:SINamingFake.Created | Should -BeNullOrEmpty
        $global:SINamingFake.Puts.Count | Should -Be 0
    }
    It 'when the server''s admin is ANOTHER group it is never nested: refused without -ReplaceCurrentAdminGroup, replaced by the named members with it' {
        $objs = @{ 'grp-legacy' = [pscustomobject]@{ id = 'grp-legacy'; '@odata.type' = '#microsoft.graph.group' } }
        New-Fake -AdminSid 'grp-legacy' -AdminLogin 'grp-securityinsight-sql-admins' -Objects $objs
        { & $script:Tool -SqlServerName 's' -ResourceGroupName 'r' } | Should -Throw '*ReplaceCurrentAdminGroup*'
        $global:SINamingFake.Puts.Count | Should -Be 0
        New-Fake -AdminSid 'grp-legacy' -AdminLogin 'grp-securityinsight-sql-admins' -Objects $objs
        & $script:Tool -SqlServerName 's' -ResourceGroupName 'r' -MemberObjectIds 'spn-1', 'user-2' -ReplaceCurrentAdminGroup
        @($global:SINamingFake.Added) | Should -Be @('spn-1', 'user-2')
        @($global:SINamingFake.Added) | Should -Not -Contain 'grp-legacy'
        $global:SINamingFake.AdminSid | Should -BeExactly 'grp-new'
    }
    AfterAll { Remove-Variable -Name SINamingFake, SINamingSaid -Scope Global -ErrorAction SilentlyContinue }
    It 'the help says which rights a role-assignable group needs' {
        $c = Read-SI 'setup\Set-SISqlAdminGroup.ps1'
        $c | Should -Match 'Privileged Role Administrator'
        $c | Should -Match 'RoleManagement\.ReadWrite\.Directory'
    }
}

Describe 'setup\Set-SISqlAdminGroup.ps1: the server records its administrator AS A GROUP' {
    BeforeAll {
        $script:AdminTool = Join-Path $script:SIRoot 'setup\Set-SISqlAdminGroup.ps1'
        function script:Get-SISetupAzureContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1' }; Tenant = [pscustomobject]@{ Id = 'tid-1' } } }
        function script:Get-SIAzureToken { 'tok' }
        function script:Start-Sleep { }
        function script:Write-Host { param([Parameter(ValueFromRemainingArguments)]$a) if ($null -ne $global:SIGroupKindSaid) { $global:SIGroupKindSaid.Add((@($a | Where-Object { $_ -isnot [System.ConsoleColor] -and "$_" -notmatch '^-' }) -join ' ')) } }
        # the server: its administrators resource (no kind) and the server itself (the kind)
        function script:Invoke-SIAzRestMethod {
            param([string]$Method, [string]$Path, [string]$Payload)
            $f = $global:SIGroupKindFake
            if ($Method -eq 'PATCH') {
                $f.Patches.Add($Payload)
                if (-not $f.PatchNoEffect) { $a = ($Payload | ConvertFrom-Json).properties.administrators; $f.Kind = [string]$a.principalType; $f.Sid = [string]$a.sid; $f.Login = [string]$a.login }
                return [pscustomobject]@{ StatusCode = 200; Content = '{}' }
            }
            if ($Method -eq 'PUT') { $f.Puts.Add($Payload); $p = ($Payload | ConvertFrom-Json).properties; $f.Sid = [string]$p.sid; $f.Login = [string]$p.login; return [pscustomobject]@{ StatusCode = 200; Content = '{}' } }
            if ($Path -match '/administrators/ActiveDirectory') { return [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ administratorType = 'ActiveDirectory'; sid = $f.Sid; login = $f.Login } } | ConvertTo-Json) } }
            [pscustomobject]@{ StatusCode = 200; Content = (@{ properties = @{ administrators = @{ administratorType = 'ActiveDirectory'; principalType = $f.Kind; sid = $f.Sid; login = $f.Login; azureADOnlyAuthentication = $true } } } | ConvertTo-Json -Depth 5) }
        }
        function script:Invoke-SIRestMethod {
            param([string]$Method = 'GET', [string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 120)
            if ($Uri -match '/v1\.0/groups\?\$filter=') { return [pscustomobject]@{ value = @([pscustomobject]@{ id = 'grp-ok'; displayName = 'grp-si-sql-admins'; securityEnabled = $true; isAssignableToRole = $true }) } }
            throw "unexpected Graph call: $Method $Uri"
        }
        function script:New-KindFake([string]$Kind, [switch]$PatchNoEffect) {
            $global:SIGroupKindSaid = New-Object System.Collections.Generic.List[string]
            $global:SIGroupKindFake = @{ Sid = 'grp-ok'; Login = 'grp-si-sql-admins'; Kind = $Kind; PatchNoEffect = [bool]$PatchNoEffect
                                         Patches = (New-Object System.Collections.Generic.List[string]); Puts = (New-Object System.Collections.Generic.List[string]) }
        }
    }
    It 'a server that names the group as "User" (it was made with a person as its admin) is set to Group on the server itself, and read back' {
        New-KindFake -Kind 'User'
        & $script:AdminTool -SqlServerName 'sql-x' -ResourceGroupName 'rg-x'
        $global:SIGroupKindFake.Puts.Count | Should -Be 0 -Because 'the group already is the admin'
        $global:SIGroupKindFake.Patches.Count | Should -Be 1
        $a = ($global:SIGroupKindFake.Patches[0] | ConvertFrom-Json).properties.administrators
        $a.principalType | Should -BeExactly 'Group'
        $a.sid | Should -BeExactly 'grp-ok'
        $a.login | Should -BeExactly 'grp-si-sql-admins'
        $a.azureADOnlyAuthentication | Should -BeTrue -Because 'the server''s Entra-only sign-in setting goes back as it was'
        ($global:SIGroupKindSaid -join "`n") | Should -Match 'now records its Entra admin as a group \(was "User"\)'
    }
    It 'a server that already records the group as a group is not written to' {
        New-KindFake -Kind 'Group'
        & $script:AdminTool -SqlServerName 'sql-x' -ResourceGroupName 'rg-x'
        $global:SIGroupKindFake.Patches.Count | Should -Be 0
        $global:SIGroupKindFake.Puts.Count | Should -Be 0
        ($global:SIGroupKindSaid -join "`n") | Should -Match 'records its Entra admin as a group'
    }
    It '-WhatIf says it and writes nothing' {
        New-KindFake -Kind 'Application'
        & $script:AdminTool -SqlServerName 'sql-x' -ResourceGroupName 'rg-x' -WhatIf
        $global:SIGroupKindFake.Patches.Count | Should -Be 0
        $global:SIGroupKindFake.Kind | Should -Be 'Application'
        ($global:SIGroupKindSaid -join "`n") | Should -Match 'plan.*record the Entra admin of sql-x as a group \(it is "Application"\)'
    }
    It 'a change that does not read back stops with the reason -- it is never reported as done' {
        New-KindFake -Kind 'Application' -PatchNoEffect
        { & $script:AdminTool -SqlServerName 'sql-x' -ResourceGroupName 'rg-x' } | Should -Throw '*still records its Entra admin as "Application", not as a group*'
    }
    AfterAll { Remove-Variable -Name SIGroupKindFake, SIGroupKindSaid -Scope Global -ErrorAction SilentlyContinue }
}
