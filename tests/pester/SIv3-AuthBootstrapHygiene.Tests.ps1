#Requires -Version 5.1
<#
    AUTH AND BOOTSTRAP HYGIENE -- A SETUP STEP MUST NOT CHANGE WHO, OR WHICH TENANT, THE NEXT STEP IS (#139).

      * Bootstrap-Auth's certificate probe signed in AS THE SPN and left that as the current sign-in (now it
        only asks Entra for a token as the SPN and signs nobody in),
        so the grants that follow ran as the SPN, not the operator;
      * (Connect-SIAzCli, which reused any az login, was deleted with the retired SI Analyzer: SI runs no az CLI);
      * Bootstrap-Storage replaced the account's whole lifecycle policy (deleting the customer's own
        rules) and printed the account key for pasting into config (storage is OAuth by default);
      * `'a {0}' + 'b' -f $x` formats only 'b', so several error messages printed literal {0}/{1};
      * the last-resort token path cached for a flat 50 minutes regardless of the token's expiry.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    function script:Lift([string]$Path, [string]$Name) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
        if ($fn) { $fn.Extent.Text } else { $null }
    }
    . ([scriptblock]::Create((Lift (Join-Path $script:SIRoot 'Bootstrap-Auth.ps1') 'Test-SISpnConnection')))
    . (Join-Path $script:SIRoot 'auth\Get-SIGraphToken.ps1')
    # the REST layer whose Get-SIAzAccessToken a test below mocks, loaded HERE: Get-SIGraphToken.ps1 loads it only when no
    # Invoke-SIArm is visible, and in a shared gate worker an earlier suite's Invoke-SIArm stub can be (the mock then has no
    # command to replace)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')

    # the certificate probe's REST helpers (auth\Find-SICertificate.ps1) and the sign-in it must NOT touch
    function script:Get-SICertificateFromStore { param($Thumbprint, $StoreLocations) }
    function script:Get-SICertificateClientToken { param($TenantId, $ClientId, $Thumbprint, $Resource) }
    function script:Connect-SISetupAzure { param($TenantId, $ApplicationId, $CertificateThumbprint) }
    function script:Connect-SIAzAccountRest { param([switch]$ServicePrincipal, $Tenant, $ApplicationId, $CertificateThumbprint) }
    function script:Get-AzAccessToken { param($ResourceUrl) }

}

Describe 'the certificate probe never changes who is signed in (the operator stays the operator)' {
    BeforeEach {
        Mock Get-SICertificateFromStore { [pscustomobject]@{ Certificate = 'cert'; StoreLocation = 'LocalMachine' } }
        Mock Connect-SISetupAzure { }
        Mock Connect-SIAzAccountRest { }
    }
    It 'a successful probe asks for a token AS THE SPN and signs nobody in' {
        Mock Get-SICertificateClientToken { 'spn-token' }
        (Test-SISpnConnection -TenantId 't' -AppId 'a' -CertThumbprint 'AB').Ok | Should -BeTrue
        Should -Invoke Get-SICertificateClientToken -Times 1 -Exactly -ParameterFilter { $TenantId -eq 't' -and $ClientId -eq 'a' -and $Thumbprint -eq 'AB' -and $Resource -eq 'https://graph.microsoft.com/.default' }
        Should -Invoke Connect-SISetupAzure -Times 0 -Exactly
        Should -Invoke Connect-SIAzAccountRest -Times 0 -Exactly
    }
    It 'a failed probe reports the failure and signs nobody in' {
        Mock Get-SICertificateClientToken { throw 'AADSTS700027' }
        $p = Test-SISpnConnection -TenantId 't' -AppId 'a' -CertThumbprint 'AB'
        $p.Ok | Should -BeFalse
        $p.Error | Should -Match 'AADSTS700027'
        Should -Invoke Connect-SISetupAzure -Times 0 -Exactly
        Should -Invoke Connect-SIAzAccountRest -Times 0 -Exactly
    }
    It 'a certificate in neither store is a clear refusal, without asking Entra' {
        Mock Get-SICertificateFromStore { $null }
        Mock Get-SICertificateClientToken { 'x' }
        $p = Test-SISpnConnection -TenantId 't' -AppId 'a' -CertThumbprint 'AB' -CertStoreLocation CurrentUser
        $p.Ok | Should -BeFalse
        $p.Error | Should -Match 'not found in Cert:\\LocalMachine\\My or Cert:\\CurrentUser\\My'
        Should -Invoke Get-SICertificateFromStore -Times 1 -Exactly -ParameterFilter { ($StoreLocations -join ',') -eq 'CurrentUser,LocalMachine' }
        Should -Invoke Get-SICertificateClientToken -Times 0 -Exactly
    }
}

Describe 'the last-resort token is cached no longer than it lives' {
    It 'a token with 10 minutes left is cached for at most ~5 (it was 50)' {
        $saved = @{}
        # SI_AzureAccess_Engine too: a setup suite that ran earlier in this process switched it to 'Rest'
        foreach ($n in 'SI_SPN_AppId','SI_Graph_AppId','SI_SPN_TenantId','SI_Graph_TenantId','SI_PreferUami','SI_SPN_CertThumbprint','HighPriv_Modern_CertificateThumbprint_Azure','SI_AzureAccess_Engine') {
            $saved[$n] = (Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue)
            Set-Variable -Scope Global -Name $n -Value $null
        }
        try {
            # the last resort is the run's own sign-in over REST (#305), no Az module
            Mock Get-SIAzAccessToken { [pscustomobject]@{ Token = 'tok'; ExpiresOn = [DateTimeOffset]::UtcNow.AddMinutes(10) } }
            Get-SIGraphToken -Resource MDE -ForceRefresh | Should -Be 'tok'
            $exp = $script:SIGraphTokenCache['https://api.security.microsoft.com'].ExpiresAt
            ($exp - [datetime]::UtcNow).TotalMinutes | Should -BeLessThan 6
        } finally {
            foreach ($n in $saved.Keys) { Set-Variable -Scope Global -Name $n -Value $saved[$n] }
        }
    }
}

Describe 'Bootstrap-Storage keeps other lifecycle rules and prints no key' {
    BeforeAll { $script:Bs = Get-Content -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-Storage.ps1') -Raw }
    It 'the policy write carries the existing rules, not only ours' {
        $script:Bs | Should -Match '-Rules \(@\(\$otherRules\) \+ @\(\$rule\)\)'
        $script:Bs | Should -Not -Match '(?m)^\s*-Rules? \$rule \| Out-Null'
    }
    It 'the account key is never fetched or printed -- storage is reached with the identity (#307)' {
        $script:Bs | Should -Not -Match 'Get-AzStorageAccountKey|EmitKey|SI_StorageKey'
    }
}

Describe 'Bootstrap-Storage end to end on a fake Azure Resource Manager (no modules)' {
    BeforeAll {
        $script:BsPath = Join-Path $script:SIRoot 'Bootstrap-Storage.ps1'
        . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
        $script:keepEngine = $global:SI_AzureAccess_Engine; $script:keepIngest = $global:SI_LogIngest_Engine
    }
    AfterAll {
        $global:SI_AzureAccess_Engine = $script:keepEngine; $global:SI_LogIngest_Engine = $script:keepIngest
        Remove-Variable -Scope Global -Name SI_AzRestState, SIBsFake -ErrorAction SilentlyContinue
    }
    BeforeEach {
        # ONE global hashtable: the mocks run from inside Bootstrap-Storage.ps1, where `$script:` is that script
        $global:SIBsFake = @{}
        $global:SIBsFake.Arm = [System.Collections.Generic.List[object]]::new()
        $global:SIBsFake.Existing = @{}      # path (lower) -> object the fake returns on GET
        $global:SIBsFake.Policy = $null
        Mock Connect-SISetupAzure { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'sub one' }; Tenant = [pscustomobject]@{ Id = 't1' } } }
        Mock Get-SISetupSubscriptionId { 'sub-1' }
        Mock Get-SIAzStorageAccount { [pscustomobject]@{ StorageAccountName = 'sitest'; PrimaryEndpoints = [pscustomobject]@{ Blob = 'https://sitest.blob.core.windows.net/'; Table = 't'; Queue = 'q' } } }
        Mock New-SIAzStorageAccount { throw 'not expected' }
        Mock Invoke-SIArm {
            $global:SIBsFake.Arm.Add([pscustomobject]@{ Method = $(if ($Method) { $Method } else { 'GET' }); Path = $Path; Body = $Body })
            $m = if ($Method) { $Method } else { 'GET' }
            if ($Path -like '*/managementPolicies/default') {
                if ($m -eq 'GET') { return $global:SIBsFake.Policy }
                return [pscustomobject]@{ id = $Path; properties = $Body.properties }
            }
            if ($m -eq 'GET') { return $global:SIBsFake.Existing[$Path.ToLowerInvariant()] }
            return [pscustomobject]@{ name = ($Path -split '/')[-1]; id = $Path }
        }
    }
    It 'creates the table, the private container and the queues through ARM, and merges the lifecycle rule with the customer''s own' {
        $global:SIBsFake.Policy = [pscustomobject]@{ id = 'p'; properties = [pscustomobject]@{ policy = [pscustomobject]@{ rules = @([pscustomobject]@{ name = 'customer-rule'; enabled = $true; type = 'Lifecycle' }) } } }
        $out = & $script:BsPath -ResourceGroupName 'rg-si' -StorageAccountName 'sitest' -Engines 'endpoint' 6>$null
        $puts = @($global:SIBsFake.Arm | Where-Object { $_.Method -eq 'PUT' })
        @($puts | Where-Object { $_.Path -like '*/tableServices/default/tables/sifingerprint' }).Count | Should -Be 1
        $c = @($puts | Where-Object { $_.Path -like '*/blobServices/default/containers/sistaging' })
        $c.Count | Should -Be 1
        $c[0].Body.properties.publicAccess | Should -Be 'None'
        @($puts | Where-Object { $_.Path -like '*/queueServices/default/queues/si-endpoint-*' }).Count | Should -Be 4
        $pol = @($puts | Where-Object { $_.Path -like '*/managementPolicies/default' })
        $pol.Count | Should -Be 1
        @($pol[0].Body.properties.policy.rules | ForEach-Object { $_.name }) | Should -Be @('customer-rule', 'si-staging-7day-delete')
        @(@($out)[-1].PSObject.Properties.Name) | Should -Not -Contain 'Key'
        @($global:SIBsFake.Arm | Where-Object { $_.Path -like '*/listKeys' }).Count | Should -Be 0
    }
    It 'is idempotent: everything present and the rule at the right retention -> no write at all' {
        foreach ($p in @('tableServices/default/tables/sifingerprint', 'blobServices/default/containers/sistaging') + @('discover', 'collect', 'enrich', 'classify' | ForEach-Object { "queueServices/default/queues/si-endpoint-$_" })) {
            $global:SIBsFake.Existing[('/subscriptions/sub-1/resourceGroups/rg-si/providers/Microsoft.Storage/storageAccounts/sitest/' + $p).ToLowerInvariant()] = [pscustomobject]@{ name = 'x'; id = 'x' }
        }
        $rule = [pscustomobject]@{ name = 'si-staging-7day-delete'; definition = [pscustomobject]@{ actions = [pscustomobject]@{ baseBlob = [pscustomobject]@{ delete = [pscustomobject]@{ daysAfterModificationGreaterThan = 7 } } } } }
        $global:SIBsFake.Policy = [pscustomobject]@{ id = 'p'; properties = [pscustomobject]@{ policy = [pscustomobject]@{ rules = @($rule) } } }
        $null = & $script:BsPath -ResourceGroupName 'rg-si' -StorageAccountName 'sitest' -Engines 'endpoint' 6>$null
        @($global:SIBsFake.Arm | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }
}

Describe 'no message formats only the last piece of a concatenation' {
    It 'no a + b -f x where a carries a placeholder, anywhere in the shipped code' {
        $bad = foreach ($f in Get-ChildItem $script:SIRoot -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '\\tests\\' }) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Operator -eq 'Plus' -and
                $n.Right -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Right.Operator -eq 'Format' -and
                @($n.Left.FindAll({ param($m) ($m -is [System.Management.Automation.Language.StringConstantExpressionAst] -or $m -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and $m.Value -match '\{\d+(,[-\d]+)?(:[^}]*)?\}' }, $true)).Count -gt 0
            }, $true) | ForEach-Object { '{0}:{1}' -f $f.Name, $_.Extent.StartLineNumber }
        }
        @($bad).Count | Should -Be 0 -Because ($bad -join ', ')
    }
}

Describe 'Bootstrap signs in itself when nobody is signed in (#521: never through the az CLI)' {
    # found 2026-10-06 on ring 1: a run with no REST sign-in stopped with "ManagedIdentity sign-in: the tenant id is empty".
    # #521 removed the az CLI fallback that fixed it then: Bootstrap now signs in through setup's own client.
    It 'signs in with Connect-SISetupAzure (support tokens, Cloud Shell or the browser) when no REST sign-in exists -- no az' {
        $src = [IO.File]::ReadAllText((Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'Bootstrap-ContainerAppJob.ps1'))
        $src | Should -Match 'if \(-not \$azCtx -or -not \$azCtx\.Account\) \{'
        $src | Should -Match '\$azCtx = Connect-SISetupAzure @signIn'
        $src | Should -Not -Match 'az account show'
        # the sign-in sits BEFORE the ManagedIdentity tenant is taken from the context
        $src.IndexOf('Connect-SISetupAzure @signIn') | Should -BeLessThan $src.IndexOf("if (`$authMode -eq 'ManagedIdentity' -and [string]::IsNullOrWhiteSpace([string]`$spnTenantId))")
    }
}
