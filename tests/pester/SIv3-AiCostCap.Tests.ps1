#Requires -Version 5.1
<#
    OPENAI-CAP (owner 2026-11-21, Invardia relay; a 3.1.41 release blocker): AI CAN NO LONGER RUN UNBOUNDED.
    The internal install's engines made ~2,200 Azure OpenAI requests a day (5-6M prompt tokens): Classify asked about every
    asset on every run, one request per asset, with the whole raw Metadata. What must hold:
      (a) an answer is cached under a hash of the deciding fields; an unchanged asset is never asked again; a changed one is;
      (b) the new / changed assets are asked 25 per request;
      (c) a request carries only the deciding fields -- never raw Metadata, never a nested blob;
      (d) the instruction text describes exactly the fields that are sent;
      (e) a FINITE daily token budget per install (default with no setting; 0 / invalid = default): at the budget nothing is
          sent, ONE warning, ONE alert (the uplink record waits until Invardia's catalog has the id); the budget is a
          Settings entry next to the AI switch, with its cost in plain words;
      (f) AI is OFF by default everywhere: the tier classifier's RunAI, BuildSummaryByAI in both samples, and the AI
          switches never travel as a copied SI_CFG_ value;
      (g) at most 2 attempts of one request, and never again after a 400.
    Offline, mocked HTTP only: Invoke-RestMethod / Get-SIAzureToken / Invoke-SIOpenAIChat are Pester mocks -- ZERO real calls.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-OpenAIAuth.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AiBudget.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\Test-SIAIEnabled.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-ClassifyAi.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Classify.ps1')
    $script:Uri = 'https://x.openai.azure.com/openai/deployments/chat/chat/completions?api-version=2025-01-01-preview'
    function script:Write-SIInfo { param($m) }
    function script:Write-SIStageShard { param($Context, $ContainerName, $RunId, $Stage, $ShardIndex, $ReplicaIndex, $Records) $script:Written = $Records }
    function script:Read-SIStageShards { param($Context, $ContainerName, $RunId, $Stage, $ReplicaIndex) $script:Input }
    function script:New-Rec([string]$Id, [string]$Os = 'Windows11', [int]$Big = 0) {
        @{
            AssetId = $Id; Sources = @('mde'); Hint = 'device'
            PostureHits = @(@{ Label = 'Posture=AvOff'; Mode = 'Shadow' })
            Enrichment = @{ XENG_AppGroup = 'Fleet'; XENG_CriticalityScore = 12 }
            Metadata = @{ MDE_DeviceName = $Id; MDE_OSPlatform = $Os; MDE_RawJson = ('{"x":"' + ('y' * [Math]::Max(1, $Big)) + '"}'); EG_Criticality = 'Low'
                          MDE_Properties = @{ nested = 'blob' }; MDE_LongText = ('z' * 400) }
        }
    }
    function script:Invoke-Run($Records) {
        $script:Input = $Records
        Invoke-SIClassify -RunContext ([pscustomobject]@{ Engine = 'endpoint'; RunId = 'r1'; ShardIndex = 0; StagingContainer = 'sistaging'; WhatIf = $false
                                                          StorageContext = [pscustomobject]@{ Mode = 'OAuth'; AccountName = '' } })
    }
    # the mocked model: answers every item it was sent
    $script:Answer = {
        param($Uri, $Body)
        $script:Bodies.Add([string]$Body)
        $u = (([string]$Body | ConvertFrom-Json).messages | Where-Object role -eq 'user').content | ConvertFrom-Json
        $res = @($u.Items | ForEach-Object { @{ AssetId = $_.AssetId; SI_Tier = 1; SI_ServiceType = 'Server'; SI_ServiceName = $_.AssetId; SI_Group = 'g'; SI_Tier_Proofs = @() } })
        [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = (@{ Results = $res } | ConvertTo-Json -Depth 6 -Compress) } }); usage = [pscustomobject]@{ total_tokens = 1000 } }
    }
    function script:New-Http([int]$Code) {
        $ex = New-Object System.Exception ("Response status code does not indicate success: {0}." -f $Code)
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = $Code }) -Force
        [System.Management.Automation.ErrorRecord]::new($ex, 'http', 'InvalidOperation', $null)
    }
}
AfterAll {
    foreach ($g in 'SI_EnableAI', 'OpenAI_endpoint', 'OpenAI_deployment', 'SI_ClassifyAnswerStore', 'SI_AiBudgetLedger', 'SI_AiBudgetAlert', 'SI_AI_DailyTokenBudget', 'MaxAiSpendPerRun', 'SI_AiBudgetProcessUse') {
        Remove-Variable -Scope Global -Name $g -ErrorAction SilentlyContinue
    }
}

Describe 'OPENAI-CAP (a)-(d): Classify asks only about new or changed assets, in batches, with the deciding fields only' {
    BeforeEach {
        Reset-SIAiBudgetState; $global:SI_AiBudgetLedger = $null
        $global:SI_EnableAI = $true; $global:OpenAI_endpoint = 'https://x.openai.azure.com'; $global:OpenAI_deployment = 'chat'
        $global:MaxAiSpendPerRun = 0
        $global:SI_ClassifyAnswerStore = New-SIClassifyAnswerStore -Account ''   # in-process cache, shared by the runs of one test
        $script:Bodies = New-Object System.Collections.Generic.List[string]
        Mock Invoke-SIOpenAIChat $script:Answer
    }
    It '(b) 60 new assets = 3 requests of at most 25, and every asset gets its AI verdict' {
        $r = Invoke-Run @(1..60 | ForEach-Object { New-Rec "dev$_" })
        Should -Invoke Invoke-SIOpenAIChat -Times 3 -Exactly
        $r.AiCalls | Should -Be 3
        @($script:Written | Where-Object { $_.SI_Classify_Status -eq 'ai' }).Count | Should -Be 60
        foreach ($b in $script:Bodies) { (((($b | ConvertFrom-Json).messages | Where-Object role -eq 'user').content | ConvertFrom-Json).Items).Count | Should -BeLessOrEqual 25 }
        Get-SIClassifyBatchSize | Should -BeIn @(20..25)
    }
    It '(a) the next run with the same assets sends NOTHING (all from the cache); one changed asset is the only one asked' {
        $recs = @(1..30 | ForEach-Object { New-Rec "dev$_" })
        $null = Invoke-Run $recs
        Should -Invoke Invoke-SIOpenAIChat -Times 2 -Exactly
        $again = Invoke-Run $recs
        Should -Invoke Invoke-SIOpenAIChat -Times 2 -Exactly   # still 2: no new request
        $again.Reused | Should -Be 30
        @($script:Written | Where-Object { $_.SI_Classify_Status -eq 'ai-cached' }).Count | Should -Be 30
        $recs[4].Metadata.MDE_OSPlatform = 'WindowsServer2022'
        $null = Invoke-Run $recs
        Should -Invoke Invoke-SIOpenAIChat -Times 3 -Exactly
        $last = ((($script:Bodies[-1] | ConvertFrom-Json).messages | Where-Object role -eq 'user').content | ConvertFrom-Json).Items
        @($last).Count | Should -Be 1
        $last[0].AssetId | Should -Be 'dev5'
    }
    It '(a) the hash ignores what the answer does not depend on (a huge raw blob) and follows what it does' {
        $h1 = Get-SIClassifyItemHash -Item (Get-SIClassifyAiItem -Record (New-Rec 'a' -Big 10)) -Instruction 'i'
        $h2 = Get-SIClassifyItemHash -Item (Get-SIClassifyAiItem -Record (New-Rec 'a' -Big 90000)) -Instruction 'i'
        $h3 = Get-SIClassifyItemHash -Item (Get-SIClassifyAiItem -Record (New-Rec 'a' -Os 'Linux')) -Instruction 'i'
        $h4 = Get-SIClassifyItemHash -Item (Get-SIClassifyAiItem -Record (New-Rec 'a' -Big 10)) -Instruction 'a changed instruction'
        $h1 | Should -Be $h2
        $h1 | Should -Not -Be $h3
        $h1 | Should -Not -Be $h4
    }
    It '(c) a request carries no raw Metadata: no raw JSON, no nested blob, no long text -- and stays small' {
        $null = Invoke-Run @(New-Rec 'dev1' -Big 90000)
        $user = (($script:Bodies[0] | ConvertFrom-Json).messages | Where-Object role -eq 'user').content
        $user | Should -Not -Match 'MDE_RawJson|MDE_Properties|MDE_LongText|nested|yyyyyyyy'
        $user | Should -Not -Match '"Metadata"'
        $item = ($user | ConvertFrom-Json).Items[0]
        $item.Facts.MDE_OSPlatform | Should -Be 'Windows11'
        $item.Signals.XENG_AppGroup | Should -Be 'Fleet'
        $item.Signals.EG_Criticality | Should -Be 'Low'
        $user.Length | Should -BeLessThan 2000
    }
    It '(d) the instruction names the fields that are sent, and no longer claims raw Properties / rawData' {
        $sys =(Get-SISystemPromptForEngine -Engine 'endpoint') + (Get-SIClassifyBatchInstruction)
        foreach ($f in 'AssetId', 'Hint', 'Sources', 'PostureHits', 'Signals', 'Facts') { $sys | Should -Match $f }
        $sys | Should -Not -Match 'rawData|Properties carries|verbatim EG NodeProperties'
        ((Get-SISystemPromptForEngine -Engine 'azure') + (Get-SIClassifyBatchInstruction)) | Should -Not -Match 'rawData|verbatim EG NodeProperties|AZ_FpMeta'
        (Get-Content -Raw (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Classify.ps1')) | Should -Not -Match 'function Invoke-SIOpenAIClassify \{'
    }
    It '(g) a 400 is never sent again: the batch falls back to rules, one request only' {
        Mock Invoke-SIOpenAIChat { throw (New-Http 400) }
        $r = Invoke-Run @(1..3 | ForEach-Object { New-Rec "dev$_" })
        Should -Invoke Invoke-SIOpenAIChat -Times 1 -Exactly
        $r.Errored | Should -Be 3
    }
    It '(g) a platform failure (503) is tried at most twice' {
        Mock Invoke-SIOpenAIChat { throw (New-Http 503) }
        $null = Invoke-Run @(New-Rec 'dev1')
        Should -Invoke Invoke-SIOpenAIChat -Times 2 -Exactly
        Get-SIOpenAIMaxAttempts | Should -Be 2
    }
}

Describe 'OPENAI-CAP (e): the daily token budget is a finite circuit breaker' {
    BeforeEach {
        Reset-SIAiBudgetState; Reset-SIOpenAIAuthState
        Remove-Variable -Scope Global -Name SI_AI_DailyTokenBudget -ErrorAction SilentlyContinue
        $script:Ledger = @{}
        $global:SI_AiBudgetLedger = @{ Read = { param($Day) if ($script:Ledger.ContainsKey($Day)) { $script:Ledger[$Day] } else { 0L } }; Add = { param($Day, $Tokens) $script:Ledger[$Day] = [long]$script:Ledger[$Day] + $Tokens } }
        $script:Alerts = New-Object System.Collections.Generic.List[object]
        $global:SI_AiBudgetAlert = { param($e) $script:Alerts.Add($e) }
        Mock Get-SIAzureToken { 'tok' }
        $script:Sent = 0
        Mock Invoke-RestMethod { $script:Sent++; [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = '{}' } }); usage = [pscustomobject]@{ prompt_tokens = 60000; completion_tokens = 0 } } }
    }
    It 'the default is finite with no setting, and 0 / negative / text mean the default -- never unlimited' {
        Get-SIAiDailyTokenBudget | Should -Be 200000
        foreach ($v in 0, -5, 'abc', '') { $global:SI_AI_DailyTokenBudget = $v; Get-SIAiDailyTokenBudget | Should -Be 200000 }
        $global:SI_AI_DailyTokenBudget = '500,000'; Get-SIAiDailyTokenBudget | Should -Be 500000
    }
    It 'at the budget nothing more is sent: one warning line, one alert, every later request refused without a send' {
        $global:SI_AI_DailyTokenBudget = 150000
        $warn = @()
        1..6 | ForEach-Object { try { $null = Invoke-SIOpenAIChat -Uri $script:Uri -Body '{"messages":[]}' 3>&1 | ForEach-Object { if ($_ -is [System.Management.Automation.WarningRecord]) { $warn += $_ } } } catch { $script:LastErr = $_.Exception.Message } }
        $script:Sent | Should -Be 3                 # 3 x 60,000 = 180,000 >= 150,000: the 4th..6th are never sent
        $script:LastErr | Should -Match '^AI daily limit reached'
        @($warn | Where-Object { "$_" -match 'AI daily limit reached' }).Count | Should -Be 1
        $script:Alerts.Count | Should -Be 1
        $script:Alerts[0].Id | Should -Be 'si.ai.daily-budget-reached'
        $script:Ledger.Values | Should -Be @(180000)
    }
    It 'a breaker opened by another engine of the install (the shared ledger) stops this one before it sends' {
        $script:Ledger[(Get-SIAiBudgetDay)] = 250000
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' } | Should -Throw '*AI daily limit reached*'
        $script:Sent | Should -Be 0
    }
    It 'a ledger that cannot be read sends nothing (unknown spend is never a reason to spend more)' {
        $global:SI_AiBudgetLedger = @{ Read = { throw 'storage 403' }; Add = { } }
        { Invoke-SIOpenAIChat -Uri $script:Uri -Body '{}' 3>$null } | Should -Throw '*AI daily limit reached*'
        $script:Sent | Should -Be 0
    }
    It 'the alert record: Area ai, Measured { tokens, budgetTokens }, Job = the execution kind; sent now that the catalog has it' {
        $ev = Get-SIAiBudgetAlert -Used 210000 -Budget 200000 -Day '2026-11-21'
        $rec = ConvertTo-SIAiBudgetAlertRecord -Event $ev -Context ([pscustomobject]@{ Mode = 'identified'; Version = '3.1.41' }) -Kind 'flow'
        $rec.AlertId | Should -Be 'si.ai.daily-budget-reached'
        $rec.Severity | Should -Be 'warning'
        $rec.Area | Should -Be 'ai'
        $rec.Job | Should -Be 'flow'
        @($rec.Measured.PSObject.Properties.Name) | Should -Be @('tokens', 'budgetTokens')
        Test-SIAiBudgetAlertLive | Should -BeTrue   # Invardia 1.0.1190 accepts the id (2026-11-21)
        $sent = New-Object System.Collections.Generic.List[object]
        Send-SIAiBudgetAlert -Event $ev -Context ([pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://x'; AccessCode = 'c' }) -Transport { param($Record) $sent.Add($Record); [pscustomobject]@{ Status = 'ok' } } | Should -Be 'sent'
        $sent[0].AlertId | Should -Be 'si.ai.daily-budget-reached'
    }
    It 'the Risk Analysis summary (its own streamed request) asks the same budget and counts its use' {
        $ra = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $ra | Should -Match 'if \(-not \(Test-SIAiBudgetOpen\)\) \{ throw \(Get-SIAiBudgetRefusedText\) \}'
        $ra | Should -Match 'Add-SIAiBudgetUsage -Tokens'
    }
    It 'the budget is a Settings entry next to the AI switch, with its cost in plain words' {
        $c = Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($c.settings | Where-Object name -eq 'SI_AI_DailyTokenBudget')[0]
        $s | Should -Not -BeNullOrEmpty
        [long]$s.default | Should -Be 200000
        $s.group | Should -Be 'AI'
        $s.defaultText | Should -Match 'tokens a day.*USD.*DKK'
        $card = @($c.cards | Where-Object name -eq 'Where AI is used')[0]
        $i = [array]::IndexOf(@($card.settings), 'SI_EnableAI')
        @($card.settings)[$i + 1] | Should -Be 'SI_AI_DailyTokenBudget'
        (Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.descriptions.locked.json') | ConvertFrom-Json).help.PSObject.Properties.Name | Should -Contain 'SI_AI_DailyTokenBudget'
    }
}

Describe 'OPENAI-CAP (f): AI is off by default everywhere' {
    It 'the tier classifier''s RunAI is off unless set' {
        Remove-Variable -Scope Global -Name SI_PrivilegeTierClassifier_RunAI -ErrorAction SilentlyContinue
        . (Join-Path $script:SIRoot 'launcher\privilege-tier-classifier\LauncherConfig.defaults.ps1')
        $global:SI_PrivilegeTierClassifier_RunAI | Should -BeFalse
        $c = Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') | ConvertFrom-Json
        @($c.settings | Where-Object name -eq 'SI_PrivilegeTierClassifier_RunAI')[0].default | Should -BeFalse
        foreach ($n in 'SI_EnableAI', 'BuildSummaryByAI', 'SI_EnableAI_endpoint', 'SI_EnableAI_azure') { @($c.settings | Where-Object name -eq $n)[0].default | Should -Not -BeTrue }
        Remove-Variable -Scope Global -Name SI_PrivilegeTierClassifier_RunAI -ErrorAction SilentlyContinue
    }
    It 'both shipped samples have the AI summary off' {
        foreach ($f in 'config\SecurityInsight.custom.sample.ps1', 'config\SecurityInsight.community.custom.sample.ps1') {
            $t = Get-Content -Raw (Join-Path $script:SIRoot $f)
            $t | Should -Match '(?m)^\$global:BuildSummaryByAI\s*=\s*\$false'
            $t | Should -Not -Match '(?m)^\$global:(BuildSummaryByAI|SI_EnableAI\w*|SI_PrivilegeTierClassifier_RunAI)\s*=\s*\$true'
        }
    }
    It 'the AI switches never travel as a copied SI_CFG_ value (only a person''s Settings switch them on)' {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        $r = Get-SIConfigEnvArgs -Names @('SI_EnableAI', 'BuildSummaryByAI', 'SI_PrivilegeTierClassifier_RunAI', 'SI_AI_DailyTokenBudget') -Globals @{ SI_EnableAI = $true; BuildSummaryByAI = $true; SI_PrivilegeTierClassifier_RunAI = $true; SI_AI_DailyTokenBudget = 100000 }
        @($r.Refused) | Should -Be @('SI_EnableAI', 'BuildSummaryByAI', 'SI_PrivilegeTierClassifier_RunAI')
        @($r.EnvArgs) | Should -Be @('SI_CFG_SI_AI_DailyTokenBudget=100000')
        $imp = Import-SIConfigFromEnv -Environment @{ SI_CFG_SI_EnableAI = 'true'; SI_CFG_BuildSummaryByAI = 'true' }
        @($imp.Refused) | Should -Contain 'SI_EnableAI'
        @($imp.Refused) | Should -Contain 'BuildSummaryByAI'
    }
}

Describe 'OPENAI-CAP (g): no caller sends one AI request more than twice, and never after a 400' {
    It 'the retry rule: only 408 / 429 / 5xx / no answer, never 400, 401, 403 or the daily limit' {
        Test-SIOpenAIRetryable (New-Http 400) | Should -BeFalse
        Test-SIOpenAIRetryable (New-Http 401) | Should -BeFalse
        Test-SIOpenAIRetryable (New-Http 403) | Should -BeFalse
        foreach ($c in 408, 429, 500, 503) { Test-SIOpenAIRetryable (New-Http $c) | Should -BeTrue }
        $lim = [System.Management.Automation.ErrorRecord]::new([Exception]::new((Get-SIAiBudgetRefusedText)), 'x', 'InvalidOperation', $null)
        Test-SIOpenAIRetryable $lim | Should -BeFalse
    }
    It 'the tier classifier: at most 2 attempts, and a non-retryable failure ends them' {
        $p = Get-Content -Raw (Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1')
        $p | Should -Match '\[int\]\$global:AI_MaxRetries -gt 2\) \{ \$global:AI_MaxRetries = 2 \}'
        $p | Should -Match 'if \(\(Get-Command -Name Test-SIOpenAIRetryable -ErrorAction SilentlyContinue\) -and -not \(Test-SIOpenAIRetryable \$_\)\) \{ break \}'
    }
    It 'Risk Analysis: at most 2 attempts whatever AI_MaxAttempts says' {
        (Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) | Should -Match '\[Math\]::Min\(2, \[int\]\$global:AI_MaxAttempts\) \} else \{ 2 \}'
    }
}
