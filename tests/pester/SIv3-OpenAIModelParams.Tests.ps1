#Requires -Version 5.1
<#
    #1269 AI WORKS WITH THE NEWEST AZURE OPENAI MODELS (engine/_shared/SI-OpenAIAuth.ps1):
      - every AI request carries the output cap as max_completion_tokens (never max_tokens, which the newest models refuse
        with HTTP 400 "Unsupported parameter: 'max_tokens' ... Use 'max_completion_tokens' instead.");
      - a 400 refusing a request parameter (max_completion_tokens <-> max_tokens; temperature / top_p / penalties dropped)
        sends the request ONCE more adapted, says ONE log line, and the rest of the run is sent adapted from the start;
      - never a loop: a second 400 is thrown to the caller (the AI summary is skipped with the reason, as before);
      - any other 400 / failure is thrown as before, unchanged;
      - WIRING: the Risk Analysis AI summary (its own streamed request) uses the same adaptation.
    Offline: Get-SIAzureToken and Invoke-RestMethod are Pester mocks.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-OpenAIAuth.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Test-SIAIEnabled.ps1')
    $script:Uri = 'https://x.openai.azure.com/openai/deployments/chat/chat/completions?api-version=2025-01-01-preview'
    $script:Ok = [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = '{"ok":true}' } }) }
    # the live answer of 2026-11-15 (a gpt-5.5 deployment)
    $script:RefuseMaxTokens = '{"error":{"message":"Unsupported parameter: ''max_tokens'' is not supported with this model. Use ''max_completion_tokens'' instead.","type":"invalid_request_error","param":"max_tokens","code":"unsupported_parameter"}}'
    $script:RefuseTemperature = '{"error":{"message":"Unsupported value: ''temperature'' does not support 0.1 with this model. Only the default (1) value is supported.","type":"invalid_request_error","param":"temperature","code":"unsupported_value"}}'
    $script:RefuseNewName = '{"error":{"code":"BadRequest","message":"Unrecognized request argument supplied: max_completion_tokens"}}'
    $script:ContentFilter = '{"error":{"message":"The response was filtered due to the prompt triggering the content management policy.","type":null,"param":"prompt","code":"content_filter","status":400}}'
    function script:New-Http400([string]$Json) {
        $ex = New-Object System.Exception 'Response status code does not indicate success: 400 (Bad Request).'
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = 400 }) -Force
        $er = [System.Management.Automation.ErrorRecord]::new($ex, 'http', 'InvalidOperation', $null)
        $er.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($Json)
        $er
    }
    $script:Word = 'bl' + [char]0xE5 + 'b' + [char]0xE6 + 'r'   # non-ASCII text survives the adaptation
    function script:Get-SentText($b) { if ($b -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString([byte[]]$b) } else { [string]$b } }
    $global:SIv3ParamBodies = New-Object System.Collections.Generic.List[string]
    $script:Body = (@{ messages = @(@{ role = 'user'; content = 'hi' }); max_completion_tokens = 100; temperature = 0.1 } | ConvertTo-Json -Depth 5 -Compress)
    $script:OldBody = (@{ messages = @(@{ role = 'user'; content = 'hi' }); max_tokens = 100; temperature = 0; top_p = 1.0 } | ConvertTo-Json -Depth 5 -Compress)
}
AfterAll {
    foreach ($g in 'SIv3ParamBodies', 'OpenAI_apiKey', 'SI_OpenAIUseKey', 'SI_OpenAIKeyWarned', 'SI_OpenAINoAccess', 'SI_OpenAINoAccessSaid', 'SI_OpenAIAuthMode', 'SI_OpenAIModeSaid', 'SI_OpenAITokenParam', 'SI_OpenAIDropSampling') {
        Remove-Variable -Scope Global -Name $g -ErrorAction SilentlyContinue
    }
}

Describe '#1269 which parameter a 400 refuses' {
    It 'the live answer names max_tokens' { Get-SIOpenAIUnsupportedParameter -ErrorText $script:RefuseMaxTokens | Should -Be 'max_tokens' }
    It 'a refused temperature value' { Get-SIOpenAIUnsupportedParameter -ErrorText $script:RefuseTemperature | Should -Be 'temperature' }
    It 'an API version that does not know max_completion_tokens' { Get-SIOpenAIUnsupportedParameter -ErrorText $script:RefuseNewName | Should -Be 'max_completion_tokens' }
    It 'the message alone (no JSON) is enough' {
        Get-SIOpenAIUnsupportedParameter -ErrorText "Unsupported parameter: 'top_p' is not supported with this model." | Should -Be 'top_p'
        Get-SIOpenAIUnsupportedParameter -ErrorText "Unsupported value: 'presence_penalty' does not support 0.5 with this model." | Should -Be 'presence_penalty'
    }
    It 'another 400 (content filter, an unknown parameter, nothing) is not a parameter refusal' {
        Get-SIOpenAIUnsupportedParameter -ErrorText $script:ContentFilter | Should -Be ''
        Get-SIOpenAIUnsupportedParameter -ErrorText "Unsupported parameter: 'logprobs' is not supported with this model." | Should -Be ''
        Get-SIOpenAIUnsupportedParameter -ErrorText '' | Should -Be ''
    }
}

Describe '#1269 the request body is adapted once and remembered' {
    BeforeEach {
        Reset-SIOpenAIAuthState
        $global:SIv3ParamBodies.Clear()
        $global:OpenAI_apiKey = $null
        Mock Write-Warning { }
        Mock Write-Host { }
        Mock Get-SIAzureToken { 'tok-engine' }
    }
    It 'no adaptation in the run: the body is sent exactly as the caller built it' {
        Mock Invoke-RestMethod { $global:SIv3ParamBodies.Add((Get-SentText $Body)); $script:Ok }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:Body
        $global:SIv3ParamBodies.Count | Should -Be 1
        $global:SIv3ParamBodies[0] | Should -BeExactly $script:Body
    }
    It 'max_tokens refused (the live bug): sent once more with max_completion_tokens, one log line, remembered' {
        Mock Invoke-RestMethod {
            $t = Get-SentText $Body; $global:SIv3ParamBodies.Add($t)
            if ($t -match '"max_tokens"') { throw (New-Http400 $script:RefuseMaxTokens) }
            $script:Ok
        }
        $r = Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:OldBody
        $r.choices[0].message.content | Should -Be '{"ok":true}'
        $global:SIv3ParamBodies.Count | Should -Be 2
        $sent = $global:SIv3ParamBodies[1] | ConvertFrom-Json
        $sent.max_completion_tokens | Should -Be 100
        $sent.PSObject.Properties['max_tokens'] | Should -BeNullOrEmpty
        $sent.temperature | Should -Be 0 -Because 'only the refused parameter changes'
        $sent.messages[0].content | Should -Be 'hi'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -like "*does not accept 'max_tokens'*max_completion_tokens*rest of this run*" }
        # the next request of the run goes adapted at once: one request, no refused call, no second line
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:OldBody
        $global:SIv3ParamBodies.Count | Should -Be 3
        $global:SIv3ParamBodies[2] | Should -Match '"max_completion_tokens":100'
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -like '*does not accept*' }
    }
    It 'max_completion_tokens unknown to an older API version: sent once more with max_tokens' {
        Mock Invoke-RestMethod {
            $t = Get-SentText $Body; $global:SIv3ParamBodies.Add($t)
            if ($t -match '"max_completion_tokens"') { throw (New-Http400 $script:RefuseNewName) }
            $script:Ok
        }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:Body
        $global:SIv3ParamBodies.Count | Should -Be 2
        ($global:SIv3ParamBodies[1] | ConvertFrom-Json).max_tokens | Should -Be 100
        $global:SI_OpenAITokenParam | Should -Be 'max_tokens'
    }
    It 'temperature refused: temperature / top_p / penalties are dropped together, remembered' {
        Mock Invoke-RestMethod {
            $t = Get-SentText $Body; $global:SIv3ParamBodies.Add($t)
            if ($t -match '"temperature"|"top_p"') { throw (New-Http400 $script:RefuseTemperature) }
            $script:Ok
        }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body ((@{ messages = @(@{ role = 'user'; content = 'hi' }); max_completion_tokens = 5; temperature = 0.1; top_p = 0.9; presence_penalty = 0; frequency_penalty = 0 } | ConvertTo-Json -Depth 5 -Compress))
        $global:SIv3ParamBodies.Count | Should -Be 2
        $sent = $global:SIv3ParamBodies[1] | ConvertFrom-Json
        foreach ($p in 'temperature', 'top_p', 'presence_penalty', 'frequency_penalty') { $sent.PSObject.Properties[$p] | Should -BeNullOrEmpty -Because $p }
        $sent.max_completion_tokens | Should -Be 5
        Should -Invoke Write-Host -Times 1 -Exactly -ParameterFilter { "$Object" -like "*does not accept 'temperature'*defaults*" }
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:Body
        $global:SIv3ParamBodies.Count | Should -Be 3
        $global:SIv3ParamBodies[2] | Should -Not -Match '"temperature"'
    }
    It 'a UTF-8 byte body (the tier classifier) stays bytes and is adapted' {
        Mock Invoke-RestMethod {
            $global:SIv3ParamBodies.Add($(if ($Body -is [byte[]]) { 'bytes:' } else { 'text:' }) + (Get-SentText $Body))
            if ((Get-SentText $Body) -match '"temperature"') { throw (New-Http400 $script:RefuseTemperature) }
            $script:Ok
        }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes((@{ messages = @(@{ role = 'user'; content = $script:Word }); max_completion_tokens = 7; temperature = 0.1 } | ConvertTo-Json -Depth 5 -Compress))
        $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body $bytes -ContentType 'application/json; charset=utf-8'
        $global:SIv3ParamBodies.Count | Should -Be 2
        $global:SIv3ParamBodies[1] | Should -BeLike 'bytes:*'
        ($global:SIv3ParamBodies[1].Substring(6) | ConvertFrom-Json).messages[0].content | Should -Be $script:Word
    }
}

Describe '#1269 never a loop; other failures unchanged' {
    BeforeEach {
        Reset-SIOpenAIAuthState
        $global:SIv3ParamBodies.Clear()
        $global:OpenAI_apiKey = $null
        Mock Write-Warning { }
        Mock Write-Host { }
        Mock Get-SIAzureToken { 'tok-engine' }
    }
    It 'a second 400 after the adaptation is thrown: two requests, not more' {
        Mock Invoke-RestMethod { $global:SIv3ParamBodies.Add((Get-SentText $Body)); throw (New-Http400 $script:RefuseMaxTokens) }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:OldBody } | Should -Throw
        $global:SIv3ParamBodies.Count | Should -Be 2
    }
    It 'the token name never flips back: a refusal of the adapted name is thrown at once' {
        Mock Invoke-RestMethod {
            $t = Get-SentText $Body; $global:SIv3ParamBodies.Add($t)
            if ($t -match '"max_tokens"') { throw (New-Http400 $script:RefuseMaxTokens) }
            throw (New-Http400 $script:RefuseNewName)
        }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:OldBody } | Should -Throw
        $global:SIv3ParamBodies.Count | Should -Be 2
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:OldBody } | Should -Throw
        $global:SIv3ParamBodies.Count | Should -Be 3 -Because 'the run already adapted the token name: one request, thrown'
        $global:SI_OpenAITokenParam | Should -Be 'max_completion_tokens'
    }
    It 'a refused parameter that is not in the body is not re-sent' {
        Mock Invoke-RestMethod { $global:SIv3ParamBodies.Add((Get-SentText $Body)); throw (New-Http400 $script:RefuseTemperature) }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{"messages":[],"max_completion_tokens":5}' } | Should -Throw
        $global:SIv3ParamBodies.Count | Should -Be 1
    }
    It 'another 400 (content filter) is thrown at once, nothing adapted' {
        Mock Invoke-RestMethod { $global:SIv3ParamBodies.Add((Get-SentText $Body)); throw (New-Http400 $script:ContentFilter) }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body $script:Body } | Should -Throw
        $global:SIv3ParamBodies.Count | Should -Be 1
        $global:SI_OpenAITokenParam | Should -Be ''
        $global:SI_OpenAIDropSampling | Should -BeFalse
    }
    It 'a new run starts as the caller built it (Reset-SIOpenAIAuthState)' {
        $null = Add-SIOpenAIParamAdaptation -Parameter 'max_tokens'
        $null = Add-SIOpenAIParamAdaptation -Parameter 'temperature'
        Reset-SIOpenAIAuthState
        ConvertTo-SIOpenAIAdaptedBody -Body $script:OldBody | Should -BeExactly $script:OldBody
    }
}

Describe '#1269 wiring: every AI caller sends max_completion_tokens' {
    It 'no engine or setup script sends max_tokens' {
        $hits = @(foreach ($d in 'engine', 'setup', 'container') {
            Get-ChildItem -Path (Join-Path $script:SIRoot $d) -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue |
                Where-Object { [IO.File]::ReadAllText($_.FullName) -match '(?m)^\s*max_tokens\s*=|[;{]\s*max_tokens\s*=' } | ForEach-Object { $_.Name }
        })
        $hits | Should -BeNullOrEmpty -Because ($hits -join ', ')
    }
    It 'the Risk Analysis AI summary, the tier classifier and the setup check send max_completion_tokens' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match 'max_completion_tokens = \[int\]\$global:AI_MaxTokensPerRequest'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1')) | Should -Match 'max_completion_tokens = \$maxTokens'
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Validate-SIOpenAI.ps1')) | Should -Match 'max_completion_tokens = 16'
    }
    It 'the Risk Analysis AI summary adapts a refused parameter once, then a second 400 skips the summary as before' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match '\$body = ConvertTo-SIOpenAIAdaptedBody -Body \$__aiBodyBuilt'
        $t | Should -Match '(?s)\$__aiCode -eq 400 -and -not \$__aiAdapted.{0,200}Get-SIOpenAIUnsupportedParameter -ErrorText \$__aiErrBody.{0,200}Add-SIOpenAIParamAdaptation.{0,200}\$__aiAdapted = \$true'
        $t | Should -Match 'if \(-not \$__aiTransient -or \$__aiAtt -ge \$__aiMax\) \{ throw "Azure OpenAI returned \$__aiErr" \}'
    }
    It 'the profiling stages and the tier classifier go through Invoke-SIOpenAIChat (where the adaptation lives)' {
        foreach ($f in 'engine\asset-profiling\stages\Invoke-Classify.ps1', 'engine\asset-profiling\stages\Invoke-Enrich.ps1', 'engine\asset-profiling\stages\Invoke-SchemaPropose.ps1', 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1') {
            [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)) | Should -Match 'Invoke-SIOpenAIChat -Uri' -Because $f
        }
    }
}
