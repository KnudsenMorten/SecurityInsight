#Requires -Version 5.1
<#
    THE CLASSIFIER'S LOG NEVER SAYS "AI" WHEN NO AI IS USED.

    Found live 2026-11-11 (the catalog download on internal): with the downloaded catalog the privilege tier classifier
    correctly sent no AI request, yet its log -- which the customer reads -- still printed "name-based AI tiering",
    "Classification method: Azure OpenAI ...", "=== AI TIERING: ... ===" and "AI batch: ..." for every section. A customer
    reading it thinks AI was used and paid for. Now: with the download, each section says what really happens (its tiers
    come from the daily catalog, the rest keep the tier they had); the AI wording only when it is built here with AI.

    The engine's own functions are lifted by AST; Write-Log, the AI call and the sleeps are script-scope stubs. No network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $path = [IO.Path]::Combine($script:SIRoot, 'engine', 'privilege-tier-classifier', 'Invoke-PrivilegeTierClassifier.ps1')
    $script:EngineSrc = [IO.File]::ReadAllText($path)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
    $script:Lifted = @()
    foreach ($name in 'Get-PTCDailyCatalogLabel', 'Write-PTCSectionAHeader', 'Sanitize-ForJson', 'Invoke-AISingleChunk', 'Invoke-AIBatchTiering', 'Invoke-AllAITiering') {
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
        if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)); $script:Lifted += $name }
    }
    $script:Log = New-Object System.Collections.ArrayList
    function script:Write-Log { param([string]$Message, [string]$Level = 'INFO') [void]$script:Log.Add([pscustomobject]@{ Level = $Level; Message = $Message }) }
    function script:Start-Sleep { param($Seconds, $Milliseconds) }
    function script:Test-SIOpenAIEndpoint { param([string]$Endpoint) '' }
    $script:AICalls = 0
    function script:Invoke-RestMethod {
        param($Uri, $Method, $Headers, $Body, $ErrorAction)
        $script:AICalls++
        $items = ([Text.Encoding]::UTF8.GetString($Body) | ConvertFrom-Json).messages[1].content
        $json = ($items -split "Items:\r?\n", 2)[1] | ConvertFrom-Json
        $out = @($json | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Tier = 1; Reason = 'r' } })
        [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = (ConvertTo-Json -InputObject $out -Compress -Depth 4) } }) }
    }

    $script:BuiltInADGroups = @('Domain Admins', 'Enterprise Admins', 'Print Operators')
    $script:Entra = @([pscustomobject]@{ Id = 'r1'; DisplayName = 'Global Administrator'; IsBuiltIn = $true; Permissions = @('a') },
                      [pscustomobject]@{ Id = 'c1'; DisplayName = 'Org Custom Role'; IsBuiltIn = $false; Permissions = @('b') })
    $script:Api = @([pscustomobject]@{ ServicePrincipal = 'Microsoft Graph'; AppId = 'g'; PermissionType = 'Application'; Value = 'Directory.ReadWrite.All'; DisplayName = 'x'; Description = 'y' })
    $script:Azure = @([pscustomobject]@{ Id = 'a1'; Name = 'Owner'; Description = 'o'; IsCustom = $false; Actions = @('*'); NotActions = @(); DataActions = @() })

    function script:New-Map([string[]]$Keys) {
        $m = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $Keys) { $m[$k] = [pscustomobject]@{ Tier = 0; Reason = 'listed' } }
        $m
    }
    # the downloaded catalog lists 2 of the 3 groups, the built-in Entra role, the permission and the Azure role
    $script:Maps = @{ ADGroups = (New-Map 'Domain Admins', 'Enterprise Admins'); EntraRoles = (New-Map 'Global Administrator')
                      APIPerms = (New-Map 'Directory.ReadWrite.All'); AzureRoles = (New-Map 'Owner') }

    function script:Invoke-Run([bool]$NoAI) {
        $script:Log.Clear(); $script:AICalls = 0; $script:PtcNoAISaid = $null; $script:PtcAINotConfiguredSaid = $null
        $script:PtcNoAI = $NoAI
        $script:PtcCatalog = $(if ($NoAI) { [pscustomobject]@{ Source = 'invardia'; Version = '2026.11.10'; Maps = $script:Maps } } else { [pscustomobject]@{ Source = 'ai'; Version = ''; Maps = $null } })
        Write-PTCSectionAHeader -NoAI $NoAI -Version ([string]$script:PtcCatalog.Version) -GroupCount $script:BuiltInADGroups.Count
        $null = Invoke-AllAITiering -EntraRoles $script:Entra -APIPermissions $script:Api -AzureRoles $script:Azure -Known $script:PtcCatalog.Maps
        @($script:Log | ForEach-Object Message)
    }
    $global:AI_ChunkSize = 50; $global:AI_MaxRetries = 1; $global:AI_MaxTokens = 1000
    $global:OpenAI_Endpoint = 'https://x.openai.azure.com'; $global:OpenAI_Deployment = 'gpt'; $global:OpenAI_ApiKey = 'k'; $global:OpenAI_ApiVersion = 'v'
    $global:SI_PrivilegeTierClassifier_RunAI = $null
}

AfterAll {
    $global:OpenAI_Endpoint = $null; $global:OpenAI_Deployment = $null; $global:OpenAI_ApiKey = $null; $global:OpenAI_ApiVersion = $null
}

Describe 'the functions exist' {
    It 'all were lifted from the engine' { $script:Lifted.Count | Should -Be 6 -Because ($script:Lifted -join ',') }
}

Describe 'the downloaded catalog (the default): no line says AI' {
    BeforeAll { $script:Lines = Invoke-Run -NoAI $true }

    It 'no AI request is sent' { $script:AICalls | Should -Be 0 }

    It 'no section line uses the AI wording' {
        foreach ($l in $script:Lines) {
            $l | Should -Not -Match '\bAI TIERING\b|AI batch|Classification method|Azure OpenAI|name-based AI|AI tiering' -Because $l
        }
        ($script:Lines | Where-Object { $_ -match '^===' }) | ForEach-Object { $_ | Should -Not -Match '\bAI\b' -Because $_ }
    }

    It 'the AD built-in groups section says where its tiers come from' {
        $script:Lines | Should -Contain '=== AD built-in groups: tiers from the daily catalog version 2026.11.10 ==='
        $script:Lines | Should -Contain '=== Roles, groups and permissions: tiers from the daily catalog version 2026.11.10 ==='
    }

    It 'one line per section: how many take the downloaded tier, how many keep the tier they had' {
        $script:Lines | Should -Contain 'Active Directory Built-in Groups: 2 item(s) take their tier from the daily catalog version 2026.11.10; 1 not listed keep the tier they had.'
        $script:Lines | Should -Contain 'Entra ID Role Definitions: 1 item(s) take their tier from the daily catalog version 2026.11.10; 1 not listed keep the tier they had.'
        $script:Lines | Should -Contain 'Entra API Permissions: 1 item(s) take their tier from the daily catalog version 2026.11.10; 0 not listed keep the tier they had.'
        $script:Lines | Should -Contain 'Azure RBAC Role Definitions: 1 item(s) take their tier from the daily catalog version 2026.11.10; 0 not listed keep the tier they had.'
        @($script:Lines | Where-Object { $_ -match 'take their tier from the daily catalog' }).Count | Should -Be 4
    }

    It 'a catalog not downloaded yet is said so' {
        Get-PTCDailyCatalogLabel -Version '' | Should -Be 'the daily catalog (not downloaded yet)'
    }
}

Describe 'built here with AI (the opt-in): the AI wording is kept' {
    BeforeAll { $script:Lines = Invoke-Run -NoAI $false }

    It 'the AI requests are sent' { $script:AICalls | Should -Be 4 }

    It 'the AI section lines are there' {
        $script:Lines | Should -Contain '=== SECTION A: AD Built-in Groups (name-based AI tiering) ==='
        $script:Lines | Should -Contain 'Classification method: Azure OpenAI tiers each group name into Tier 0/1/2/3.'
        $script:Lines | Should -Contain '=== AI TIERING: Preparing batch inputs ==='
        $script:Lines | Should -Contain '=== AI TIERING: Sending 4 batch requests ==='
        @($script:Lines | Where-Object { $_ -like 'AI batch: *' }).Count | Should -Be 4
        @($script:Lines | Where-Object { $_ -like 'AI batch complete: *' }).Count | Should -Be 4
        @($script:Lines | Where-Object { $_ -match 'daily catalog' }).Count | Should -Be 0
    }
}

Describe 'wiring in the engine' {
    It 'Main opens the AD built-in groups section through the helper, with the run''s source and catalog version' {
        $main = $script:EngineSrc.Substring($script:EngineSrc.IndexOf('function Main {'))
        $main | Should -Match 'Write-PTCSectionAHeader -NoAI \(\[bool\]\$script:PtcNoAI\) -Version \(\[string\]\$script:PtcCatalog\.Version\)'
        $main | Should -Not -Match 'Classification method: Azure OpenAI'
    }
}
