#Requires -Version 7.0
<#
    #1102 (framework rule 11; rule 11f: only logs / the data collection endpoint may stay public) -- the OPTIONAL Azure
    OpenAI account of a PRIVATE install. setup\Validate-SIOpenAI.ps1:
      * private install, no account   -> REFUSED with one plain line; no create / patch call, not even the resource group;
                                         AI features stay off;
      * private install, an existing account that reads public Enabled -> REPORTED, never changed (no PUT / PATCH of it);
      * public install                -> as before (the account is created with the public access it always had).
    Private = the install's answer (-PrivateNetwork), else its SecurityInsight database server reads public network access
    off (Test-SISqlServerPrivate). Offline: Azure is a fake behind Pester mocks (script scope); the script runs end to end.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Script = [IO.Path]::Combine($script:SIRoot, 'setup', 'Validate-SIOpenAI.ps1')
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-ScriptRun.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupAzure.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-SetupArm.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-OpenAIPrivate.ps1'))
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    # the script reads its launcher globals under strict mode: defined (empty) here, as a launcher does, removed after
    $script:Globals = @('SubscriptionId', 'ResourceGroupName', 'Location', 'AccountName', 'DeploymentName', 'ModelName', 'ModelVersion', 'Capacity', 'PublicNetworkAccess', 'WaitForAccountReady', 'DeploymentSkuOrder', 'WriteModelDumps')
    foreach ($g in $script:Globals) { if (-not (Get-Variable -Name $g -Scope Global -ErrorAction SilentlyContinue)) { Set-Variable -Name $g -Scope Global -Value $null } }

    # the fake Azure (a GLOBAL: $script: inside the fakes is the running script's scope while Validate-SIOpenAI runs):
    # the install's SQL server (Pna; $null = no server), the OpenAI account (Account; $null = not there),
    # every write recorded in Writes
    $global:SIv3OpenAIWorld = $null
    function script:New-World([AllowNull()][string]$Pna, $Account) {
        $global:SIv3OpenAIWorld = @{ Pna = $Pna; Account = $Account; Deployment = $null; Writes = (New-Object System.Collections.Generic.List[string]); Reads = (New-Object System.Collections.Generic.List[string]) }
    }
    function script:Invoke-FakeArm([string]$Method, [string]$Path) {
        if (-not $Method) { $Method = 'GET' }
        $global:SIv3OpenAIWorld.Reads.Add(('{0} {1}' -f $Method, $Path))
        if ($Method -ne 'GET') { $global:SIv3OpenAIWorld.Writes.Add(('{0} {1}' -f $Method, $Path)); return $null }
        if ($Path -match '/providers/Microsoft\.Sql/servers$') {
            if ($null -eq $global:SIv3OpenAIWorld.Pna) { return [pscustomobject]@{ value = @() } }
            return [pscustomobject]@{ value = @([pscustomobject]@{ name = 'sql-si-x' }) }
        }
        if ($Path -match '/providers/Microsoft\.Sql/servers/sql-si-x$') { return [pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = $global:SIv3OpenAIWorld.Pna; privateEndpointConnections = @() } } }
        throw "unexpected ARM call $Method $Path"
    }
    function script:Invoke-FakeRest([string]$Method, [string]$Path, [string]$Payload) {
        $r = { param($c, $o) [pscustomobject]@{ StatusCode = $c; Content = $(if ($null -ne $o) { $o | ConvertTo-Json -Depth 20 } else { '' }) } }
        $p = ($Path -split '\?')[0]
        if ($Method -ne 'GET') { $global:SIv3OpenAIWorld.Writes.Add(('{0} {1} {2}' -f $Method, $p, $Payload)) }
        switch -Regex ($p) {
            '/listKeys$' { return (& $r 200 @{ key1 = 'k1'; key2 = 'k2' }) }
            '/models$' { return (& $r 200 @{ value = @(@{ name = 'gpt-4.1-mini'; version = '2025-04-14'; format = 'OpenAI' }) }) }
            '/deployments/[^/]+$' {
                if ($Method -eq 'PUT') { $global:SIv3OpenAIWorld.Deployment = @{ properties = @{ model = @{ name = 'gpt-4.1-mini'; version = '2025-04-14' } } }; return (& $r 201 $global:SIv3OpenAIWorld.Deployment) }
                if ($global:SIv3OpenAIWorld.Deployment) { return (& $r 200 $global:SIv3OpenAIWorld.Deployment) }; return (& $r 404 $null)
            }
            '/accounts/[^/]+$' {
                if ($Method -eq 'PUT') { $b = $Payload | ConvertFrom-Json; $global:SIv3OpenAIWorld.Account = @{ properties = @{ provisioningState = 'Succeeded'; endpoint = 'https://x.openai.azure.com/'; publicNetworkAccess = [string]$b.properties.publicNetworkAccess } }; return (& $r 201 $global:SIv3OpenAIWorld.Account) }
                if ($global:SIv3OpenAIWorld.Account) { return (& $r 200 $global:SIv3OpenAIWorld.Account) }; return (& $r 404 $null)
            }
        }
        throw "unexpected REST call $Method $p"
    }
    Mock Start-SIScriptRun { $null }
    Mock Stop-SIScriptRun { }
    Mock Get-SISetupAzureContext { [pscustomobject]@{ SubscriptionId = $script:Sub } }
    Mock Set-SIAzContext { }
    Mock Get-SIAzResourceGroup { [pscustomobject]@{ ResourceGroupName = 'rg-si'; Location = 'westeurope' } }
    Mock New-SIAzResourceGroup { $global:SIv3OpenAIWorld.Writes.Add('PUT resource group') }
    Mock Invoke-SIArm { Invoke-FakeArm -Method $Method -Path $Path }
    Mock Invoke-SIAzRestMethod { Invoke-FakeRest -Method $Method -Path $Path -Payload $Payload }
    $script:BaseArgs = @{ SubscriptionId = $script:Sub; ResourceGroupName = 'rg-si'; Location = 'westeurope'; AccountName = 'oai-si-x'; DeploymentName = 'chat'
                      WriteModelDumps = $false; WaitForAccountReady = $false }
    function script:Invoke-OpenAIScript([hashtable]$Extra = @{}) {
        $a = @{}; foreach ($k in $script:BaseArgs.Keys) { $a[$k] = $script:BaseArgs[$k] }; foreach ($k in $Extra.Keys) { $a[$k] = $Extra[$k] }
        $global:BuildSummaryByAI = $null
        @(& $script:Script @a 6>&1 | ForEach-Object { [string]$_ })
    }
    $script:Refusal = 'this install is private: an Azure OpenAI account would need a private endpoint (framework rule 11) -- not created; AI features stay off'
}

AfterAll { foreach ($g in @($script:Globals) + @('BuildSummaryByAI', 'OpenAI_apiKey', 'OpenAI_endpoint', 'OpenAI_deployment', 'OpenAI_apiVersion', 'OpenAI_MaxTokensPerRequest', 'SIv3OpenAIWorld')) { Remove-Variable -Name $g -Scope Global -ErrorAction SilentlyContinue } }

Describe '#1102 a PRIVATE install gets no Azure OpenAI account with public access' {
    It 'its database server reads public access Disabled, no account: REFUSED in one line, no create / patch call, AI stays off' {
        New-World -Pna 'Disabled' -Account $null
        $out = Invoke-OpenAIScript
        ($out -join "`n") | Should -Match ([regex]::Escape($script:Refusal))
        @($global:SIv3OpenAIWorld.Writes) | Should -BeNullOrEmpty -Because 'nothing is created or changed -- not the account, not the resource group'
        $global:BuildSummaryByAI | Should -BeFalse
    }
    It 'the install''s private-network answer refuses too, without reading the server' {
        New-World -Pna $null -Account $null
        $out = Invoke-OpenAIScript @{ PrivateNetwork = $true }
        ($out -join "`n") | Should -Match ([regex]::Escape($script:Refusal))
        @($global:SIv3OpenAIWorld.Writes) | Should -BeNullOrEmpty
        @($global:SIv3OpenAIWorld.Reads | Where-Object { $_ -match 'Microsoft\.Sql' }) | Should -BeNullOrEmpty
    }
    It 'an EXISTING account that reads public Enabled is REPORTED, never changed' {
        New-World -Pna 'Disabled' -Account @{ properties = @{ provisioningState = 'Succeeded'; endpoint = 'https://x.openai.azure.com/'; publicNetworkAccess = 'Enabled' } }
        $out = Invoke-OpenAIScript
        ($out -join "`n") | Should -Match 'this install is private: the existing Azure OpenAI account oai-si-x reads public network access Enabled -- reported, not changed'
        @($global:SIv3OpenAIWorld.Writes | Where-Object { $_ -match '/accounts/oai-si-x ' -or $_ -match '^PATCH' }) | Should -BeNullOrEmpty -Because 'the account is only read'
        $global:SIv3OpenAIWorld.Account.properties.publicNetworkAccess | Should -Be 'Enabled'
    }
    It 'a server that cannot be read creates nothing' {
        New-World -Pna 'Disabled' -Account $null
        Mock Invoke-SIArm { throw 'HTTP Status: 403 (Forbidden) AuthorizationFailed' }
        { Invoke-OpenAIScript } | Should -Throw '*Forbidden*'
        @($global:SIv3OpenAIWorld.Writes) | Should -BeNullOrEmpty
    }
}

Describe '#1102 a PUBLIC install: as before' {
    It 'no SQL server / one with public access Enabled: the account is created with public access Enabled, the deployment made, AI on' {
        foreach ($pna in @($null, 'Enabled')) {
            New-World -Pna $pna -Account $null
            $out = Invoke-OpenAIScript
            ($out -join "`n") | Should -Not -Match 'this install is private'
            $put = @($global:SIv3OpenAIWorld.Writes | Where-Object { $_ -match '^PUT /subscriptions/.*/accounts/oai-si-x ' })
            $put.Count | Should -Be 1
            (($put[0] -split ' ', 3)[2] | ConvertFrom-Json).properties.publicNetworkAccess | Should -Be 'Enabled'
            @($global:SIv3OpenAIWorld.Writes | Where-Object { $_ -match '/deployments/chat ' }).Count | Should -Be 1
            $global:BuildSummaryByAI | Should -BeTrue
        }
    }
}

Describe '#1102 the plan (pure) and the wiring' {
    It 'Get-SIOpenAIPrivatePlan: proceed / refuse / report / reuse' {
        (Get-SIOpenAIPrivatePlan -Private $false -Account $null -AccountName 'a').Action | Should -Be 'proceed'
        (Get-SIOpenAIPrivatePlan -Private $true -Account $null -AccountName 'a').Line | Should -Be $script:Refusal
        (Get-SIOpenAIPrivatePlan -Private $true -Account ([pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Enabled' } }) -AccountName 'a').Action | Should -Be 'report'
        (Get-SIOpenAIPrivatePlan -Private $true -Account ([pscustomobject]@{ properties = [pscustomobject]@{} }) -AccountName 'a').Action | Should -Be 'report' -Because 'not set = Azure''s default, Enabled'
        (Get-SIOpenAIPrivatePlan -Private $true -Account ([pscustomobject]@{ properties = [pscustomobject]@{ publicNetworkAccess = 'Disabled' } }) -AccountName 'a').Action | Should -Be 'reuse'
    }
    It 'the decision comes before the resource group and the account create; the create branch refuses a private install too' {
        $t = [IO.File]::ReadAllText($script:Script)
        $t | Should -Match '(?s)Test-SIOpenAIInstallPrivate .*?if \(\$__plan\.Action -eq ''refuse''\) \{.*?return\s*\}.*?Write-Section "4\) Resource Group"\s*\r?\nEnsure-ResourceGroup'
        $t | Should -Match '(?s)\} elseif \(\$__priv\.Private\) \{.*?return\s*\} else \{\s*Write-Log INFO "Account does not exist -> creating\.\.\."'
        $t | Should -Match "\. \(Join-Path \`$ScriptRoot '_shared\\SI-OpenAIPrivate\.ps1'\)"
    }
}
