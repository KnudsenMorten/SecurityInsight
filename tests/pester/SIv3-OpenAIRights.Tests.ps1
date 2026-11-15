#Requires -Version 5.1
<#
    #1257 AI WITHOUT A KEY -- the right "Cognitive Services OpenAI User" (5e0bd9bd-...) on the customer's Azure OpenAI
    resource, for the ENGINE's identity (AI) and the WEB identity (web chat inference: the named SECURE-WEB-1 exception,
    scoped to the chat resource), only when OpenAI_endpoint is set (setup/_shared/SI-OpenAIRights.ps1):
      - the resource is found from the endpoint (endpoint host, endpoints map, custom subdomain); none found = a support step;
      - the engine identity is found by its name on the jobs, the web identity on the web app;
      - the endpoint comes from the Pro setting, else a job's OPENAI_ENDPOINT, else the web app's Chat__Endpoint;
      - CHECKED, NEVER GRANTED (owner 2026-11-15: the customer or Invardia gives it on the control plane): a missing right
        is a SUPPORT STEP; one already there (on the resource or above) is said; ONLY GET is ever sent (a PUT / DELETE
        from the check fails the test); a failed read is "not checked" -- never a throw;
      - not configured: nothing is read;
      - Validate-SIOpenAI's check says which way of signing in works, in plain words;
      - WIRING: the guided install (web step, AI on) and the updater (every update) CHECK both identities on the resource
        the endpoint names, through a GET-only seam;
      - the rights list carries the engine entry and the web entry as the named exception, with no open gap, and no
        SecurityInsight code granting either.
    Offline: ARM is a fake scriptblock.
#>
BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Lib = Join-Path $script:SIRoot 'setup\_shared\SI-OpenAIRights.ps1'
    . $script:Lib
    $script:Sub = '00000000-0000-0000-0000-000000000001'
    $script:Role = '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'
    $script:AcctId = "/subscriptions/$($script:Sub)/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-cust"
    $script:Acct = [pscustomobject]@{ id = $script:AcctId; name = 'oai-cust'; properties = [pscustomobject]@{ endpoint = 'https://oai-cust.openai.azure.com/'; customSubDomainName = 'oai-cust' } }
    $script:Engine = [pscustomobject]@{ PrincipalId = 'e0000000-0000-0000-0000-00000000000e'; Name = 'engine'; Identity = 'id-si-engine' }
    $script:Web = [pscustomobject]@{ PrincipalId = 'w0000000-0000-0000-0000-00000000000w'; Name = 'web'; Identity = 'id-si-web' }
    function script:New-Assign([string]$Principal, [string]$RoleGuid, [string]$Scope) {
        [pscustomobject]@{ id = "$Scope/providers/Microsoft.Authorization/roleAssignments/$([guid]::NewGuid())"; properties = [pscustomobject]@{ principalId = $Principal; roleDefinitionId = "/subscriptions/$($script:Sub)/providers/Microsoft.Authorization/roleDefinitions/$RoleGuid"; scope = $Scope } }
    }
    function script:New-Uami([string]$Name, [string]$Principal) {
        [pscustomobject]@{ type = 'UserAssigned'; userAssignedIdentities = [pscustomobject]@{ "/subscriptions/x/resourceGroups/rg-si/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$Name" = [pscustomobject]@{ principalId = $Principal; clientId = 'c' } } }
    }
    function script:New-FakeArm {
        # READ ONLY: every call that is not a GET is recorded in Writes and refused -- the tests assert Writes stays empty
        $script:Fake = @{ Accounts = @($script:Acct); Assign = New-Object System.Collections.Generic.List[object]; Writes = New-Object System.Collections.Generic.List[object]
                          FailRead = $false; Jobs = @(); Apps = @() }
        { param([string]$Method, [string]$Path, [string]$ApiVersion, $Body)
            $f = $script:Fake
            if ($Method -ne 'GET') { $f.Writes.Add([pscustomobject]@{ Method = $Method; Path = $Path }); throw "a write was sent: $Method $Path" }
            if ($Path -like '*/providers/Microsoft.CognitiveServices/accounts') { if ($f.FailRead) { throw 'HTTP 403: AuthorizationFailed' }; return [pscustomobject]@{ value = @($f.Accounts) } }
            if ($Path -like '*/providers/Microsoft.App/jobs') { return [pscustomobject]@{ value = @($f.Jobs) } }
            if ($Path -like '*/providers/Microsoft.App/containerApps') { return [pscustomobject]@{ value = @($f.Apps) } }
            if ($Path -like '*/roleAssignments?$filter=*') {
                $p = [uri]::UnescapeDataString($Path) -replace "^.*principalId eq '([^']+)'.*$", '$1'
                return [pscustomobject]@{ value = @($f.Assign | Where-Object { $_.properties.principalId -eq $p }) }
            }
            throw "unexpected $Method $Path"
        }
    }
}

Describe '#1257 the Azure OpenAI resource from the endpoint (pure)' {
    It 'by the endpoint host, by a full request URI, by the custom subdomain, by the endpoints map' {
        (Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint 'https://oai-cust.openai.azure.com/').id | Should -Be $script:AcctId
        (Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint 'https://OAI-CUST.openai.azure.com/openai/deployments/gpt/chat/completions?api-version=x').id | Should -Be $script:AcctId
        (Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint 'https://oai-cust.cognitiveservices.azure.com/').id | Should -Be $script:AcctId -Because 'the custom subdomain names it'
        $multi = [pscustomobject]@{ id = 'x'; properties = [pscustomobject]@{ endpoint = 'https://other.cognitiveservices.azure.com/'; endpoints = [pscustomobject]@{ 'OpenAI Language Model Instance API' = 'https://chat-x.openai.azure.com/' } } }
        (Find-SIOpenAIAccountForEndpoint -Accounts @($multi) -Endpoint 'https://chat-x.openai.azure.com').id | Should -Be 'x'
    }
    It 'none matches, or not an https address: nothing' {
        Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint 'https://someone-else.openai.azure.com/' | Should -BeNullOrEmpty
        Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint 'http://oai-cust.openai.azure.com/' | Should -BeNullOrEmpty
        Find-SIOpenAIAccountForEndpoint -Accounts @($script:Acct) -Endpoint '' | Should -BeNullOrEmpty
    }
    It 'an assignment on the resource or ABOVE it counts; one on another resource does not; another role does not' {
        $p = Get-SIOpenAIRightsPlan -ResourceId $script:AcctId -Principals @($script:Engine, $script:Web) -Assignments @(
            (New-Assign $script:Engine.PrincipalId $script:Role "/subscriptions/$($script:Sub)/resourceGroups/rg-ai"),
            (New-Assign $script:Web.PrincipalId $script:Role "/subscriptions/$($script:Sub)/resourceGroups/rg-ai/providers/Microsoft.CognitiveServices/accounts/oai-other"),
            (New-Assign $script:Web.PrincipalId 'acdd72a7-3385-48ef-bd42-f606fba81ae7' $script:AcctId))
        @($p.Present | ForEach-Object Name) | Should -Be @('engine')
        @($p.Missing | ForEach-Object Name) | Should -Be @('web')
    }
}

Describe '#1257 who needs the right, and the endpoint (pure)' {
    It 'the engine by its identity name on a job (standard and older names), the web identity on the web app; nothing else' {
        $jobs = @(
            [pscustomobject]@{ name = 'caj-si-endpoint'; identity = (New-Uami 'id-si-engine' 'p-eng') },
            [pscustomobject]@{ name = 'caj-si-ra'; identity = (New-Uami 'id-si-engine' 'p-eng') },
            [pscustomobject]@{ name = 'caj-si-old'; identity = (New-Uami 'uami-securityinsight' 'p-old') },
            [pscustomobject]@{ name = 'caj-si-updater'; identity = (New-Uami 'id-si-updater' 'p-upd') },
            [pscustomobject]@{ name = 'caj-si-tagging'; identity = (New-Uami 'id-si-tagging' 'p-tag') })
        $apps = @([pscustomobject]@{ name = 'ca-si-management'; identity = (New-Uami 'id-si-web' 'p-web') }, [pscustomobject]@{ name = 'ca-si-mcp'; identity = (New-Uami 'id-si-mcp' 'p-mcp') })
        $ps = @(Get-SIOpenAIRightsPrincipals -Jobs $jobs -Apps $apps -WebAppName 'ca-si-management')
        @($ps | ForEach-Object { '{0}:{1}' -f $_.Name, $_.PrincipalId }) | Should -Be @('engine:p-eng', 'engine:p-old', 'web:p-web')
    }
    It 'the endpoint: the Pro setting first, then a job''s OPENAI_ENDPOINT, then the web app''s Chat__Endpoint; none = not configured' {
        $job = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ env = @([pscustomobject]@{ name = 'OPENAI_ENDPOINT'; value = 'https://job.openai.azure.com' }) }) } } }
        $app = [pscustomobject]@{ properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ env = @([pscustomobject]@{ name = 'Chat__Endpoint'; value = 'https://chat.openai.azure.com' }) }) } } }
        Resolve-SIOpenAIEndpointSetting -SettingRows @([pscustomobject]@{ Name = 'OpenAI_endpoint'; ValueJson = '"https://pro.openai.azure.com"' }) -Jobs @($job) -Apps @($app) | Should -Be 'https://pro.openai.azure.com'
        Resolve-SIOpenAIEndpointSetting -SettingRows @() -Jobs @($job) -Apps @($app) | Should -Be 'https://job.openai.azure.com'
        Resolve-SIOpenAIEndpointSetting -SettingRows @() -Jobs @() -Apps @($app) | Should -Be 'https://chat.openai.azure.com'
        Resolve-SIOpenAIEndpointSetting -SettingRows @([pscustomobject]@{ Name = 'OpenAI_endpoint'; ValueJson = '""' }) -Jobs @() -Apps @() | Should -Be ''
    }
}

Describe '#1257 the check: read only, a support step when missing' {
    BeforeEach { $script:Arm = New-FakeArm }
    AfterEach { $script:Fake.Writes.Count | Should -Be 0 -Because 'SecurityInsight never writes a role assignment for Azure OpenAI' }
    It 'not configured: nothing is read' {
        $r = Get-SIOpenAIRightsState -Arm { throw 'must not be called' } -SubscriptionId $script:Sub -Endpoint '' -Principals @($script:Engine)
        $r.State | Should -Be 'not-configured'
        $r.Ok | Should -BeTrue
    }
    It 'missing for both: two support steps on THE RESOURCE, nothing granted' {
        $r = Get-SIOpenAIRightsState -Arm $script:Arm -SubscriptionId $script:Sub -Endpoint 'https://oai-cust.openai.azure.com/' -Principals @($script:Engine, $script:Web)
        $r.State | Should -Be 'missing'
        $r.Ok | Should -BeFalse
        $r.ResourceId | Should -Be $script:AcctId
        @($r.Support).Count | Should -Be 2
        $r.Support[0] | Should -Match '^support step: give the engine''s identity \(AI\) id-si-engine the role "Cognitive Services OpenAI User" on the Azure OpenAI resource '
        $r.Support[0] | Should -Match 'never gives this role itself'
        $r.Support[1] | Should -Match 'web chat'
        ($r.Lines -join ' ') | Should -Not -Match 'GIVEN|granted'
    }
    It 'already there (on the resource or above): present, said' {
        $script:Fake.Assign.Add((New-Assign $script:Engine.PrincipalId $script:Role $script:AcctId))
        $r = Get-SIOpenAIRightsState -Arm $script:Arm -SubscriptionId $script:Sub -Endpoint 'https://oai-cust.openai.azure.com/' -Principals @($script:Engine)
        $r.State | Should -Be 'present'
        $r.Ok | Should -BeTrue
        $r.Lines[0] | Should -Match 'id-si-engine \(engine\) holds "Cognitive Services OpenAI User"'
    }
    It 'the resource is not found from the endpoint: NOT CHECKED, with the support steps naming the endpoint' {
        $r = Get-SIOpenAIRightsState -Arm $script:Arm -SubscriptionId $script:Sub -Endpoint 'https://elsewhere.openai.azure.com/' -Principals @($script:Engine, $script:Web)
        $r.State | Should -Be 'not-checked'
        @($r.Support).Count | Should -Be 2
        $r.Support[1] | Should -Match 'named by https://elsewhere'
    }
    It 'a read that fails is NOT CHECKED -- never "present", never a throw' {
        $script:Fake.FailRead = $true
        $r = Get-SIOpenAIRightsState -Arm $script:Arm -SubscriptionId $script:Sub -Endpoint 'https://oai-cust.openai.azure.com/' -Principals @($script:Engine)
        $r.State | Should -Be 'not-checked'
        $r.Ok | Should -BeFalse
        $r.Lines[0] | Should -Match 'NOT CHECKED'
    }
    It 'STATIC: the file sends nothing but GET (no PUT / PATCH / DELETE, no role-assignment body, no grant function)' {
        $t = [IO.File]::ReadAllText($script:Lib)
        $t | Should -Not -Match "& \`$Arm '(PUT|PATCH|DELETE|POST)'"
        $t | Should -Not -Match 'principalType\s*='
        $t | Should -Not -Match 'Invoke-SIOpenAIRightsConverge'
    }
}

Describe '#1257 Validate-SIOpenAI says which way of signing in works' {
    It 'the engine holds the right: no key needed' {
        $r = Test-SIOpenAIAccessPaths -Send { param($Headers) 200 } -GetToken { 't' } -Key 'k' -EngineHasRight $true
        $r.Key | Should -Be 'works'; $r.Token | Should -Be 'works'; $r.Engine | Should -Be 'has access'
        $r.Verdict | Should -Match 'own identity\. No key is needed'
    }
    It 'no right but a working key: the key for now, the plain warning' {
        $r = Test-SIOpenAIAccessPaths -Send { param($Headers) if ($Headers.ContainsKey('api-key')) { 200 } else { 403 } } -GetToken { 't' } -Key 'k' -EngineHasRight $false
        $r.Token | Should -Be 'refused (HTTP 403)'
        $r.Verdict | Should -Match 'AI is still using a key; ask your support partner to give the engine access to the Azure OpenAI resource'
    }
    It 'no right and no key: AI will not work yet, said plainly' {
        $r = Test-SIOpenAIAccessPaths -Send { param($Headers) 403 } -GetToken { throw 'no sign-in' } -Key '' -EngineHasRight $false
        $r.Key | Should -Be 'not set'; $r.Token | Should -Be 'no token'
        $r.Verdict | Should -Match '^AI will not work yet'
        ($r.Lines -join ' ') | Should -Not -Match '#\d|RBAC|5e0bd9bd'
    }
    It 'the script runs the check (skippable) and names the engine identity' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Validate-SIOpenAI.ps1'))
        $t | Should -Match "\. \(Join-Path \`$ScriptRoot '_shared\\SI-OpenAIRights\.ps1'\)"
        $t | Should -Match 'Test-SIOpenAIAccessPaths -Send \$send -GetToken \$getToken'
        $t | Should -Match '\[switch\]\$SkipAccessCheck'
        $t | Should -Match "\[string\]\`$EngineIdentityName = 'id-si-engine'"
    }
}


Describe '#1257 wiring: the guided install and the updater CHECK it (never grant)' {
    It 'the guided install (web step, AI on) checks the web AND the engine identity on the resource the chat endpoint names, through a GET-only seam' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallData.ps1'))
        $t | Should -Match "\. \(\[IO\.Path\]::Combine\(\`$PSScriptRoot, 'SI-OpenAIRights\.ps1'\)\)"
        $t | Should -Match "(?s)if \(\[bool\]\`$v\['aiClassification'\] -and \[string\]\`$v\['openAiEndpoint'\]\) \{.{0,1800}Name = 'web'.{0,600}Name = 'engine'.{0,1400}Get-SIOpenAIRightsState -Arm \`$oaiArm -SubscriptionId .{0,80}-Endpoint \(\[string\]\`$v\['openAiEndpoint'\]\)"
        $t | Should -Match "if \(\`$Method -ne 'GET'\) \{ throw \('the Azure OpenAI rights check only reads"
        $t | Should -Match '(?s)if \(@\(\$oaiSupport\)\.Count\) \{.{0,400}New-SIInstallResult -State ''warning'''
        $t | Should -Not -Match 'Invoke-SIOpenAIRightsConverge'
    }
    It 'the updater runs the check on every run, before the apply-settings return' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $step = $t.IndexOf('$null = Invoke-SIUpdaterOpenAIRightsStep -SubscriptionId $sub -ResourceGroup $rg -Store $proStore -Env $Env')
        $ret = $t.IndexOf("if (`$updMode -eq 'apply-settings') {`n        if (`$proSql")
        if ($ret -lt 0) { $ret = $t.IndexOf("if (`$updMode -eq 'apply-settings') {`r`n        if (`$proSql") }
        $step | Should -BeGreaterThan 0
        $ret | Should -BeGreaterThan $step
        $t | Should -Not -Match 'Invoke-SIOpenAIRightsConverge'
    }
    It 'the updater step: reads the endpoint, finds the identities, checks; a missing right is a WARNING support line; nothing is written' {
        $path = Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        foreach ($n in 'Invoke-SIUpdaterOpenAIRightsStep', 'Read-SIUpdaterAiSettingRows') {
            $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
            $fn | Should -Not -BeNullOrEmpty
            . ([scriptblock]::Create($fn.Extent.Text))
        }
        # its own default seam refuses anything but GET
        $fn.Extent.Text | Should -Not -BeNullOrEmpty
        $t = [IO.File]::ReadAllText($path)
        $t | Should -Match "if \(\`$Method -ne 'GET'\) \{ throw \('the Azure OpenAI rights check only reads \(refused: \{0\}\)' -f \`$Method\) \}; Invoke-SIUpdaterArm -Method GET"
        $global:SIv3OaiUpdLog = New-Object System.Collections.Generic.List[string]
        function Write-UpdLog { param([string]$Message) $global:SIv3OaiUpdLog.Add($Message) }
        function Get-SIUpdaterInstallName { param($Role, $Env) 'ca-si-management' }
        $arm = New-FakeArm
        $script:Fake.Jobs = @([pscustomobject]@{ name = 'caj-si-endpoint'; identity = (New-Uami 'id-si-engine' $script:Engine.PrincipalId) })
        $script:Fake.Apps = @([pscustomobject]@{ name = 'ca-si-management'; identity = (New-Uami 'id-si-web' $script:Web.PrincipalId) })
        $r = Invoke-SIUpdaterOpenAIRightsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Arm $arm -Lib $script:Lib `
            -SettingRows @([pscustomobject]@{ Name = 'OpenAI_endpoint'; ValueJson = '"https://oai-cust.openai.azure.com/"' })
        $r.State | Should -Be 'missing'
        @($global:SIv3OaiUpdLog | Where-Object { $_ -match '^WARNING: support step' }).Count | Should -Be 2
        $script:Fake.Writes.Count | Should -Be 0
        # present: said, no warning
        $script:Fake.Assign.Add((New-Assign $script:Engine.PrincipalId $script:Role $script:AcctId))
        $script:Fake.Assign.Add((New-Assign $script:Web.PrincipalId $script:Role $script:AcctId))
        $global:SIv3OaiUpdLog.Clear()
        $r2 = Invoke-SIUpdaterOpenAIRightsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Arm $arm -Lib $script:Lib `
            -SettingRows @([pscustomobject]@{ Name = 'OpenAI_endpoint'; ValueJson = '"https://oai-cust.openai.azure.com/"' })
        $r2.State | Should -Be 'present'
        @($global:SIv3OaiUpdLog | Where-Object { $_ -match '^WARNING' }).Count | Should -Be 0
        # not configured: nothing is read beyond the lists
        $arm3 = New-FakeArm
        $r3 = Invoke-SIUpdaterOpenAIRightsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Arm $arm3 -Lib $script:Lib -SettingRows @()
        $r3 | Should -BeNullOrEmpty
        $script:Fake.Writes.Count | Should -Be 0
        Remove-Variable -Scope Global -Name SIv3OaiUpdLog -ErrorAction SilentlyContinue
    }
}

Describe '#1257 the rights list' {
    BeforeAll {
        $j = Get-Content (Join-Path $script:SIRoot 'setup\_shared\si-identity-rights.json') -Raw | ConvertFrom-Json
        $script:EngineRight = @(@($j.identities | Where-Object role -eq 'engine')[0].rights | Where-Object id -eq 'engine.azure.CognitiveServicesOpenAIUser')
        $script:WebRight = @(@($j.identities | Where-Object role -eq 'web')[0].rights | Where-Object id -eq 'web.azure.CognitiveServicesOpenAIUser')
    }
    It 'the engine holds "Cognitive Services OpenAI User" on the customer''s Azure OpenAI resource, only when AI is configured -- given by the customer / Invardia, SecurityInsight only checks it' {
        $script:EngineRight.Count | Should -Be 1
        $script:EngineRight[0].roleDefinitionId | Should -Be $script:Role
        $script:EngineRight[0].status | Should -Be 'conditional'
        $script:EngineRight[0].scope | Should -Match 'OpenAI_endpoint'
        @($script:EngineRight[0].grantedBy).Count | Should -Be 0
        ($script:EngineRight[0].checkedBy -join ' ') | Should -Match 'SI-OpenAIRights\.ps1 Get-SIOpenAIRightsState \(read only\)'
        $script:EngineRight[0].note | Should -Match 'never grants it'
    }
    It 'the web identity keeps it as the NAMED EXCEPTION (web chat inference, scoped to the chat resource) with no open gap; the guided install only checks it' {
        $script:WebRight.Count | Should -Be 1
        $script:WebRight[0].roleDefinitionId | Should -Be $script:Role
        $script:WebRight[0].approval | Should -Match 'named exception.*web chat inference, scoped to the chat resource'
        $script:WebRight[0].PSObject.Properties['gap'] | Should -BeNullOrEmpty
        ($script:WebRight[0].grantedBy -join ' ') | Should -Not -Match 'SI-GuidedInstallData|SI-OpenAIRights|Start-SIUpdater'
        ($script:WebRight[0].checkedBy -join ' ') | Should -Match 'SI-GuidedInstallData\.ps1'
    }
}
