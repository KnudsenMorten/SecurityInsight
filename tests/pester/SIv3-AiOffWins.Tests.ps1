#Requires -Version 5.1
<#
    SI #1304 (SUP-2026-00667, Invardia 2026-11-21) -- AI SWITCHED OFF WINS, AND A MISSING AI CONNECTION NEVER FAILS A RUN.
    An installation had AI switched off (SI_EnableAI = false, the engines' Azure OpenAI values removed) while the AI summary
    setting (BuildSummaryByAI) and two per-engine switches (SI_EnableAI_azure / _endpoint) were still on in its settings
    database. Its complete Risk Analysis run then ENDED FAILED at the export step ("BuildSummaryByAI is enabled, but
    Global:OpenAI_endpoint is missing"), and a per-engine switch counted as an opt-in despite the global off.
    What must hold (mocked only -- no AI call is made and nothing is switched on):
      - SI_EnableAI = false wins over EVERY per-engine switch (Test-SIAIEnabled), with a valid endpoint configured;
      - the AI summary is not built while SI_EnableAI is false, nor without an endpoint / deployment / API version -- one
        line, the top lists alone, never a throw (Get-RAAISummaryGate), and Risk Analysis takes that gate before its AI block;
      - the tier classifier's AI is not usable while SI_EnableAI is false, whatever its own switch says.
    The update's off-only control-plane values are in SIv3-UpdaterControlPlane.Tests.ps1.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine/asset-profiling/shared/Test-SIAIEnabled.ps1')
    . (Join-Path $script:SIRoot 'engine/risk-analysis/_shared/RA-AISummaryMode.ps1')
    . (Join-Path $script:SIRoot 'engine/_shared/SI-TierCatalogDownload.ps1')
    $script:RaText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/risk-analysis/Invoke-RiskAnalysis.ps1'))
    $script:AiNames = @('SI_EnableAI', 'SI_EnableAI_endpoint', 'SI_EnableAI_azure', 'SI_EnableAI_identity', 'SI_DisableAI', 'OpenAI_endpoint', 'OpenAI_deployment', 'SI_AIEndpointWarned')
    function script:Reset-AiGlobals { foreach ($n in $script:AiNames) { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue } }
}
AfterAll { Reset-AiGlobals }

Describe 'Test-SIAIMasterSwitchOff: what counts as AI switched off for the whole install' {
    It 'false (bool or text) is off; not set is NOT off; true is not off' {
        Test-SIAIMasterSwitchOff -Value $false | Should -BeTrue
        Test-SIAIMasterSwitchOff -Value 'false' | Should -BeTrue
        Test-SIAIMasterSwitchOff -Value '"False"' | Should -BeTrue
        Test-SIAIMasterSwitchOff -Value '0' | Should -BeTrue
        Test-SIAIMasterSwitchOff -Value $null | Should -BeFalse
        Test-SIAIMasterSwitchOff -Value '' | Should -BeFalse
        Test-SIAIMasterSwitchOff -Value $true | Should -BeFalse
        Test-SIAIMasterSwitchOff -Value 'true' | Should -BeFalse
    }
}

Describe 'SI_EnableAI = false wins over every per-engine switch (Test-SIAIEnabled)' {
    BeforeEach {
        Reset-AiGlobals
        # a valid Azure OpenAI connection, so only the switches decide (mocked: nothing is called)
        $global:OpenAI_endpoint = 'https://example.openai.azure.com/'; $global:OpenAI_deployment = 'chat'
    }
    It 'control: with SI_EnableAI NOT set, a per-engine opt-in still opts that engine in (the switch is what decides)' {
        $global:SI_EnableAI_endpoint = $true
        Test-SIAIEnabled -Engine 'endpoint' | Should -BeTrue
    }
    It 'every per-engine true plus a global false -> no AI path for ANY engine (<_>)' -ForEach @('endpoint', 'azure', 'identity', 'publicip') {
        $global:SI_EnableAI = $false
        foreach ($e in 'endpoint', 'azure', 'identity', 'publicip') { Set-Variable -Name "SI_EnableAI_$e" -Value $true -Scope Global }
        Test-SIAIEnabled -Engine $_ | Should -BeFalse
    }
    It 'the global false as text from the settings database ("false") wins too' {
        $global:SI_EnableAI = 'false'; $global:SI_EnableAI_azure = $true
        Test-SIAIEnabled -Engine 'azure' | Should -BeFalse
    }
}

Describe 'the AI summary gate (Get-RAAISummaryGate): never a throw, the top lists alone' {
    It 'the summary switched off -> not built, silently' {
        $g = Get-RAAISummaryGate -BuildSummaryByAI $false -MasterOff $false -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -ApiVersion '2025-01-01-preview'
        $g.Build | Should -BeFalse; $g.Level | Should -Be ''
    }
    It 'the internal case: summary ON, AI switched OFF -> not built, one INFO line naming SI_EnableAI (also with a full connection)' {
        $g = Get-RAAISummaryGate -BuildSummaryByAI $true -MasterOff $true -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -ApiVersion '2025-01-01-preview'
        $g.Build | Should -BeFalse; $g.Level | Should -Be 'info'; $g.Why | Should -Match 'SI_EnableAI'
    }
    It 'summary ON, AI on, no <Missing> -> not built, one WARNING naming it' -ForEach @(
        @{ Missing = 'OpenAI_endpoint';   E = '';                            D = 'chat'; V = '2025-01-01-preview' }
        @{ Missing = 'OpenAI_deployment'; E = 'https://e.openai.azure.com/'; D = '';     V = '2025-01-01-preview' }
        @{ Missing = 'OpenAI_apiVersion'; E = 'https://e.openai.azure.com/'; D = 'chat'; V = '' }
    ) {
        $g = Get-RAAISummaryGate -BuildSummaryByAI $true -MasterOff $false -Endpoint $E -Deployment $D -ApiVersion $V
        $g.Build | Should -BeFalse; $g.Level | Should -Be 'warn'
        $g.Why | Should -Match ([regex]::Escape($Missing))
        $g.Why | Should -Match 'the run goes on'
    }
    It 'summary ON, AI on, a full connection -> built (the gate does not stop a configured install)' {
        (Get-RAAISummaryGate -BuildSummaryByAI $true -MasterOff $false -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -ApiVersion '2025-01-01-preview').Build | Should -BeTrue
    }
    It 'summary ON, AI switched OFF, an explicit AI_Uri -> still NOT built (AI off wins over everything)' {
        (Get-RAAISummaryGate -BuildSummaryByAI $true -MasterOff $true -AiUri 'https://e.openai.azure.com/openai/deployments/chat/chat/completions?api-version=x').Build | Should -BeFalse
    }
}

Describe 'WIRING: Risk Analysis takes the gate before its AI block, and the mail follows it' {
    It 'the gate call comes after the summary switch is read and before the AI configuration block that held the throws' {
        $gate = $script:RaText.IndexOf('$__aiGate = Get-RAAISummaryGate', [StringComparison]::Ordinal)
        $read = $script:RaText.IndexOf('$script:_RATopListsOnly = -not [bool]$global:BuildSummaryByAI', [StringComparison]::Ordinal)
        $throw = $script:RaText.IndexOf('BuildSummaryByAI is enabled, but Global:OpenAI_endpoint is missing', [StringComparison]::Ordinal)
        $read | Should -BeGreaterThan 0
        $gate | Should -BeGreaterThan $read
        $throw | Should -BeGreaterThan $gate
        $script:RaText | Should -Match ([regex]::Escape('-MasterOff (Test-SIAIMasterSwitchOff)'))
        # a "no" from the gate sets the top-lists-only path, which skips the AI block
        $script:RaText.Substring($gate, 900) | Should -Match ([regex]::Escape('$script:_RATopListsOnly = $true'))
    }
    It 'the mail says "AI summary" only when it was built this run' {
        $script:RaText | Should -Match ([regex]::Escape('-AISummaryEnabled ([bool]$global:BuildSummaryByAI -and -not $script:_RATopListsOnly)'))
        $script:RaText | Should -Match ([regex]::Escape('$aiEnabled = [bool]$global:BuildSummaryByAI -and -not $script:_RATopListsOnly'))
    }
}

Describe 'the tier classifier: AI is not usable while SI_EnableAI is false, whatever its own switch says' {
    It 'RunAI true + a full connection + SI_EnableAI false -> not usable; SI_EnableAI true -> usable' {
        Test-SITierCatalogAIAvailable -RunAI $true -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -AIIntegration $false | Should -BeFalse
        Test-SITierCatalogAIAvailable -RunAI $true -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -AIIntegration 'false' | Should -BeFalse
        Test-SITierCatalogAIAvailable -RunAI $true -Endpoint 'https://e.openai.azure.com/' -Deployment 'chat' -AIIntegration $true | Should -BeTrue
    }
    It 'the request builder itself refuses with SI_EnableAI false (the single place a request is built)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1'))
        $t | Should -Match ([regex]::Escape('if ($global:SI_PrivilegeTierClassifier_RunAI -eq $false -or $ptcAiOffAll) {'))
    }
}
