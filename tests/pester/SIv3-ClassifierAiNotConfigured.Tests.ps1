#Requires -Version 5.1
<#
    AZURE OPENAI NOT CONFIGURED IS A CHOICE, NOT AN ERROR -- THE TIER CLASSIFIER SAYS SO ONCE.

    Found by the live 2.2 -> 3.0 upgrade test: without Azure OpenAI (the Community default) the privilege tier
    classifier printed 52 "[ERROR] AI tiering skipped -- missing OpenAI config" lines per run, one per chunk, and the
    text called the solution config "Layer 3" (it is Layer 4). A 2.2 README told users to schedule this engine daily;
    on 3.0 it now runs -- and flooded every log with errors for a setting nobody had to make.
    Now: one INFO line per run when nothing is configured; one WARN line when only part of it is.

    SI_TEST_ROOT (optional) points the tests at another tree, e.g. an export of the code before the fix.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    $path = Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-AISingleChunk' }, $true)
    # the engine's own function, not a copy
    . ([scriptblock]::Create($fn.Extent.Text))
    $script:Log = New-Object System.Collections.ArrayList
    function script:Write-Log { param([string]$Message, [string]$Level = 'INFO') [void]$script:Log.Add([pscustomobject]@{ Level = $Level; Message = $Message }) }
    $script:Chunk = @([pscustomobject]@{ Name = 'Global Administrator' }, [pscustomobject]@{ Name = 'Reports Reader' })
    function script:Invoke-Chunks([int]$N) {
        $out = @()
        for ($i = 1; $i -le $N; $i++) { $out += @(Invoke-AISingleChunk -CategoryName 'Entra roles' -Chunk $script:Chunk -ChunkIndex $i -TotalChunks $N) }
        $out
    }
}

Describe 'no Azure OpenAI configured (the Community default)' {
    BeforeEach {
        $script:Log.Clear()
        $script:PtcAINotConfiguredSaid = $null
        $global:SI_PrivilegeTierClassifier_RunAI = $null
        $global:OpenAI_ApiKey = $null; $global:OpenAI_Endpoint = $null; $global:OpenAI_Deployment = $null
    }

    It '52 chunks: ONE line, at INFO, not 52 errors' {
        $null = Invoke-Chunks 52
        @($script:Log).Count | Should -Be 1
        $script:Log[0].Level | Should -Be 'INFO'
        @($script:Log | Where-Object Level -eq 'ERROR').Count | Should -Be 0
    }

    It 'the line names where to set it, without the wrong layer number' {
        $null = Invoke-Chunks 3
        $script:Log[0].Message | Should -Match 'SecurityInsight\.custom\.ps1'
        $script:Log[0].Message | Should -Not -Match 'Layer 3'
        $script:Log[0].Message | Should -Match 'not configured'
    }

    It 'nothing is lost: every item comes back unresolved for the previous catalog to keep' {
        $r = @(Invoke-Chunks 2)
        $r.Count | Should -Be 4
        @($r | Where-Object { $_.Unresolved -and $_.Tier -eq 99 }).Count | Should -Be 4
    }
}

Describe 'Azure OpenAI only partly configured (a real mistake)' {
    BeforeEach {
        $script:Log.Clear()
        $script:PtcAINotConfiguredSaid = $null
        $global:SI_PrivilegeTierClassifier_RunAI = $null
        $global:OpenAI_ApiKey = $null; $global:OpenAI_Endpoint = 'https://x.openai.azure.com'; $global:OpenAI_Deployment = 'gpt'
    }
    AfterAll { $global:OpenAI_Endpoint = $null; $global:OpenAI_Deployment = $null }

    It 'one WARN line naming what is missing' {
        $null = Invoke-Chunks 5
        @($script:Log).Count | Should -Be 1
        $script:Log[0].Level | Should -Be 'WARN'
        $script:Log[0].Message | Should -Match 'OpenAI_ApiKey'
    }
}
