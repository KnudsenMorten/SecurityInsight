#Requires -Version 5.1
<#
    #1257 AI WITHOUT A KEY: every Azure OpenAI call of the engines signs in as the ENGINE'S OWN IDENTITY first (an Entra
    token for https://cognitiveservices.azure.com, "Authorization: Bearer"), the key only as the fallback
    (engine/_shared/SI-OpenAIAuth.ps1):
      - the identity's token works: the request carries the bearer token and NO api-key header;
      - the identity is refused (403) and a key is set: the same request again with the key, ONE plain warning, and the rest
        of the run on the key (no second refused call);
      - no token and a key is set: the key, the same warning;
      - no key and the identity fails (no token, or 401 / 403): the AI part fails ALONE with the plain message, said once;
        every later AI call of the run is skipped at once (no request);
      - the gates no longer need a key (endpoint + deployment are what is required);
      - WIRING: no engine file builds an api-key header itself any more -- every caller goes through the helper.
    Offline: Get-SIAzureToken and Invoke-RestMethod are Pester mocks.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-OpenAIAuth.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Test-SIAIEnabled.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TierCatalogDownload.ps1')
    $script:Uri = 'https://x.openai.azure.com/openai/deployments/gpt/chat/completions?api-version=2024-08-01-preview'
    $script:Ok = [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = '{"ok":true}' } }) }
    function script:New-HttpError([int]$Status) {
        $ex = New-Object System.Exception ("Response status code does not indicate success: $Status")
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $Status }) -Force
        [System.Management.Automation.ErrorRecord]::new($ex, 'http', 'InvalidOperation', $null)
    }
    $global:SIv3OaiCalls = New-Object System.Collections.Generic.List[hashtable]
}
AfterAll {
    foreach ($g in 'SIv3OaiCalls', 'OpenAI_apiKey', 'OpenAI_endpoint', 'OpenAI_deployment', 'SI_EnableAI', 'SI_OpenAIUseKey', 'SI_OpenAIKeyWarned', 'SI_OpenAINoAccess', 'SI_OpenAINoAccessSaid', 'SI_OpenAIAuthMode', 'SI_OpenAIModeSaid') {
        Remove-Variable -Scope Global -Name $g -ErrorAction SilentlyContinue
    }
}

Describe '#1257 the engine''s identity first' {
    BeforeEach {
        Reset-SIOpenAIAuthState
        $global:SIv3OaiCalls.Clear()
        $global:OpenAI_apiKey = $null
        Mock Write-Warning { }
        Mock Get-SIAzureToken { 'tok-engine' }
        Mock Invoke-RestMethod { $global:SIv3OaiCalls.Add(@{} + $Headers); $script:Ok }
    }
    It 'the token works: a bearer token for Azure OpenAI, no api-key header' {
        $r = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $r.choices[0].message.content | Should -Be '{"ok":true}'
        $global:SIv3OaiCalls.Count | Should -Be 1
        $global:SIv3OaiCalls[0]['Authorization'] | Should -Be 'Bearer tok-engine'
        $global:SIv3OaiCalls[0].ContainsKey('api-key') | Should -BeFalse
        Should -Invoke Get-SIAzureToken -Times 1 -ParameterFilter { $Resource -eq 'https://cognitiveservices.azure.com/' }
        Should -Invoke Write-Warning -Times 0
        $global:SI_OpenAIAuthMode | Should -Be 'ManagedIdentity'
    }
    It 'a configured key is NOT used while the identity works' {
        $global:OpenAI_apiKey = 'key-1'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $global:SIv3OaiCalls[0].ContainsKey('api-key') | Should -BeFalse
        $global:SIv3OaiCalls[0]['Authorization'] | Should -Be 'Bearer tok-engine'
    }
    It 'the header helper says the same' {
        $a = Get-SIOpenAIAuthHeader
        $a.Mode | Should -Be 'ManagedIdentity'
        $a.Headers['Authorization'] | Should -Be 'Bearer tok-engine'
    }
    It 'the run log says ONCE how AI signs in -- and, with a legacy key still set, that the key is only the fallback' {
        Mock Write-Host { }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -eq "[AI] AI signs in to Azure OpenAI as the engine's own identity (no key)." }
        Reset-SIOpenAIAuthState
        $global:OpenAI_apiKey = 'key-1'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -match 'the key that is still set is used only if that sign-in is refused' }
        Should -Invoke Write-Warning -Times 0
    }
}

Describe '#1257 the identity is refused (403) and a key is set: the key, one warning' {
    BeforeEach {
        Reset-SIOpenAIAuthState
        $global:SIv3OaiCalls.Clear()
        $global:OpenAI_apiKey = 'key-1'
        Mock Write-Warning { }
        Mock Get-SIAzureToken { 'tok-engine' }
        Mock Invoke-RestMethod {
            $global:SIv3OaiCalls.Add(@{} + $Headers)
            if ($Headers.ContainsKey('Authorization')) { throw (New-HttpError 403) }
            $script:Ok
        }
    }
    It 'the same request again with the key; the warning in plain words, once' {
        $r = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $r | Should -Not -BeNullOrEmpty
        $global:SIv3OaiCalls.Count | Should -Be 2
        $global:SIv3OaiCalls[0]['Authorization'] | Should -Be 'Bearer tok-engine'
        $global:SIv3OaiCalls[1]['api-key'] | Should -Be 'key-1'
        $global:SIv3OaiCalls[1].ContainsKey('Authorization') | Should -BeFalse
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq 'AI is still using a key; ask your support partner to give the engine access to the Azure OpenAI resource.' }
    }
    It 'the rest of the run stays on the key: no second refused call, no second warning' {
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $global:SIv3OaiCalls.Count | Should -Be 4 -Because 'one refused call, then the key for every request'
        @($global:SIv3OaiCalls | Where-Object { $_.ContainsKey('Authorization') }).Count | Should -Be 1
        Should -Invoke Write-Warning -Times 1 -Exactly
        $global:SI_OpenAIAuthMode | Should -Be 'Key'
    }
    It 'a 401 is the same as a 403' {
        Mock Invoke-RestMethod { $global:SIv3OaiCalls.Add(@{} + $Headers); if ($Headers.ContainsKey('Authorization')) { throw (New-HttpError 401) }; $script:Ok }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $global:SIv3OaiCalls[1]['api-key'] | Should -Be 'key-1'
    }
    It 'another failure (429, 500) is NOT a reason to switch: it is thrown to the caller''s own handling' {
        Mock Invoke-RestMethod { $global:SIv3OaiCalls.Add(@{} + $Headers); throw (New-HttpError 429) }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } | Should -Throw '*429*'
        $global:SIv3OaiCalls.Count | Should -Be 1
        $global:SI_OpenAIUseKey | Should -BeFalse
    }
    It 'no token at all and a key is set: the key, the same warning' {
        Mock Get-SIAzureToken { throw 'no managed identity endpoint' }
        Mock Invoke-RestMethod { $global:SIv3OaiCalls.Add(@{} + $Headers); $script:Ok }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}'
        $global:SIv3OaiCalls.Count | Should -Be 1
        $global:SIv3OaiCalls[0]['api-key'] | Should -Be 'key-1'
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like 'AI is still using a key*' }
    }
}

Describe '#1257 no key and the identity fails: the AI part fails alone, the run goes on' {
    BeforeEach {
        Reset-SIOpenAIAuthState
        $global:SIv3OaiCalls.Clear()
        $global:OpenAI_apiKey = $null
        Mock Write-Warning { }
        Mock Invoke-RestMethod { $global:SIv3OaiCalls.Add(@{} + $Headers); if ($Headers.ContainsKey('Authorization')) { throw (New-HttpError 403) }; $script:Ok }
    }
    It 'no token: a clear message (no internal words), said once; no request is sent' {
        Mock Get-SIAzureToken { throw 'no managed identity endpoint' }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } | Should -Throw (Get-SIOpenAINoAccessText)
        $global:SIv3OaiCalls.Count | Should -Be 0
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -eq (Get-SIOpenAINoAccessText) }
        (Get-SIOpenAINoAccessText) | Should -Match 'support partner'
        (Get-SIOpenAINoAccessText) | Should -Not -Match '#\d|managed identity|RBAC|token|SI_'
    }
    It 'the identity is refused (403): the same message; later calls are skipped at once' {
        Mock Get-SIAzureToken { 'tok-engine' }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } | Should -Throw (Get-SIOpenAINoAccessText)
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } | Should -Throw (Get-SIOpenAINoAccessText)
        $global:SIv3OaiCalls.Count | Should -Be 1 -Because 'the second call sends nothing'
        Should -Invoke Get-SIAzureToken -Times 1 -Exactly
        Should -Invoke Write-Warning -Times 1 -Exactly
        (Get-SIOpenAIAuthHeader).Mode | Should -Be 'None'
    }
    It 'a callers'' try/catch keeps the run going (the profiling helpers return $null on a failed call)' {
        Mock Get-SIAzureToken { throw 'no managed identity endpoint' }
        $r = try { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } catch { 'ai-skipped' }
        $r | Should -Be 'ai-skipped'
    }
}

Describe '#1257 the gates no longer need a key' {
    BeforeEach { $global:SI_EnableAI = $true; $global:OpenAI_endpoint = 'https://x.openai.azure.com'; $global:OpenAI_deployment = 'gpt'; $global:OpenAI_apiKey = $null }
    It 'AI integration: endpoint + deployment, no key' {
        Test-SIAIEnabled -Engine 'endpoint' | Should -BeTrue
        $global:OpenAI_deployment = $null
        Test-SIAIEnabled -Engine 'endpoint' | Should -BeFalse
    }
    It 'the tier classifier''s AI: endpoint + deployment, no key' {
        Test-SITierCatalogAIAvailable -AIIntegration $true -RunAI $true -Endpoint 'https://x.openai.azure.com' -Deployment 'gpt' -ApiKey '' | Should -BeTrue
    }
    It 'the container entry: configured without a key' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        (Resolve-SIContainerAi -OpenAi @{ endpoint = 'e'; deployment = 'd'; apiVersion = 'v' } -Requested $true).Enabled | Should -BeTrue
        # endpoint + deployment alone (no key, no API version: the engines' default applies)
        (Resolve-SIContainerAi -OpenAi @{ endpoint = 'e'; deployment = 'd' } -Requested $true).Enabled | Should -BeTrue
        (Resolve-SIContainerAi -OpenAi @{ endpoint = 'e' } -Requested $true).Reason | Should -Match 'missing: deployment'
    }
}

Describe '#1257 wiring: every engine AI call goes through the helper' {
    It 'no engine file builds an api-key header itself (only SI-OpenAIAuth.ps1, the fallback)' {
        $hits = @(Get-ChildItem -Path (Join-Path $script:SIRoot 'engine') -Recurse -Filter '*.ps1' | Where-Object { $_.Name -ne 'SI-OpenAIAuth.ps1' } |
            Where-Object { [IO.File]::ReadAllText($_.FullName) -match "'api-key'\s*=|""api-key""\s*=|Headers\.Add\(\s*[""']api-key" } | ForEach-Object { $_.Name })
        $hits | Should -BeNullOrEmpty -Because ($hits -join ', ')
    }
    It 'the profiling stages and the tier classifier call Invoke-SIOpenAIChat' {
        foreach ($f in 'engine\asset-profiling\stages\Invoke-Classify.ps1', 'engine\asset-profiling\stages\Invoke-Enrich.ps1', 'engine\asset-profiling\stages\Invoke-SchemaPropose.ps1', 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1') {
            [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)) | Should -Match 'Invoke-SIOpenAIChat -Uri' -Because $f
        }
        @([regex]::Matches([IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Enrich.ps1')), 'Invoke-SIOpenAIChat -Uri')).Count | Should -Be 3
    }
    It 'the Risk Analysis AI summary signs in through the helper and switches to the key on a refusal' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match '\$__aiAuth = Get-SIOpenAIAuthHeader'
        $t | Should -Match '(?s)Test-SIOpenAIAuthRefused -StatusCode \$__aiCode.{0,400}Switch-SIOpenAIToKey'
        $t | Should -Not -Match 'OpenAI_apiKey is missing' -Because 'the key is not required any more'
    }
    It 'the token helper reuses the ONE token function (no new sign-in mechanism)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-OpenAIAuth.ps1'))
        $t | Should -Match 'Get-SIAzureToken -Resource \(Get-SIOpenAIResource\)'
        $t | Should -Not -Match 'IDENTITY_ENDPOINT\s*\)|Import-Module|Get-AzAccessToken'
        $t | Should -Match 'REMOVE-ME \(#1257\)'
    }
}
