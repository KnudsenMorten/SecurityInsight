#Requires -Version 5.1
<#
    #1257 AI WITHOUT A KEY -- THE DATABASE'S AI SETTINGS REACH THE WEB CHAT AND THE ENGINE JOBS (setup\_shared\SI-AiSettings.ps1,
    container\updater\Start-SIUpdater.ps1 Invoke-SIUpdaterAiSettingsStep).

    What is kept true:
      * AI on (SI_EnableAI true + an Azure OpenAI https endpoint + a deployment): the web app's FIRST container gets
        Chat__Endpoint / Chat__Deployment, every engine job (SI_ENGINE) OPENAI_ENDPOINT / OPENAI_DEPLOYMENT / OPENAI_APIVERSION;
        every other variable (secret references included), every other container and the configuration stay as read; READ BACK;
      * IDEMPOTENT: values already there = no PATCH at all (a new web revision only when a value changes);
      * AI off: the web app's two are removed; the jobs are left alone;
      * on but incomplete / an endpoint that is not Azure OpenAI / the settings not read: nothing is changed;
      * never a key: no OPENAI_APIKEY, no Chat__ApiKey, nothing secret is written;
      * -WhatIf (SI_UPDATER_AI_SETTINGS = plan): no PATCH; a refusal or a value that does not read back is a line, never a throw;
      * WIRING: the updater runs the step on every run, before the apply-settings return, and before the rights check.
    Offline: ARM is a fake scriptblock.
    NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Lib = [IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-AiSettings.ps1')
    . $script:Lib
    $script:Sub = '00000000-0000-0000-0000-000000000001'
    $script:On = @{ SI_EnableAI = 'true'; OpenAI_endpoint = 'https://oai-cust.openai.azure.com/'; OpenAI_deployment = 'gpt-4o' }
    function script:E([string]$n, [string]$v) { [pscustomobject]@{ name = $n; value = $v } }
    function script:New-Web([object[]]$Env) {
        [pscustomobject]@{ name = 'ca-si-management'; properties = [pscustomobject]@{ provisioningState = 'Succeeded'; configuration = [pscustomobject]@{ secrets = @([pscustomobject]@{ name = 's1' }) }
            template = [pscustomobject]@{ revisionSuffix = 'r1'; containers = @(
                [pscustomobject]@{ name = 'web'; image = 'acr/web:1'; imageType = 'ContainerImage'; env = $Env; resources = [pscustomobject]@{ cpu = 2; memory = '4Gi'; ephemeralStorage = '8Gi' } },
                [pscustomobject]@{ name = 'front'; image = 'acr/front:1'; env = @((E 'FRONT' '1')) }) } } }
    }
    function script:New-Job([string]$Name, [object[]]$Env) {
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'c'; image = 'img:1'; env = $Env }) } } }
    }
    function script:New-FakeArm {
        $script:Fake = @{ Items = @{}; Patches = New-Object System.Collections.Generic.List[object]; PatchError = ''; NoApply = $false }
        { param([string]$Method, [string]$Path, [string]$ApiVersion, $Body)
            $f = $script:Fake
            if ($Method -eq 'GET' -and $Path -like '*/providers/Microsoft.App/jobs') { return [pscustomobject]@{ value = @($f.Items.Values | Where-Object { [string]$_.name -like 'caj-*' }) } }
            $name = ($Path -split '/')[-1]
            if ($Method -eq 'GET') { if ($f.Items.ContainsKey($name)) { return ($f.Items[$name] | ConvertTo-Json -Depth 30 | ConvertFrom-Json) }; return $null }
            if ($Method -eq 'PATCH') {
                $f.Patches.Add([pscustomobject]@{ Name = $name; Body = ($Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json) })
                if ($f.PatchError) { throw $f.PatchError }
                if (-not $f.NoApply) {
                    $cur = $f.Items[$name] | ConvertTo-Json -Depth 30 | ConvertFrom-Json
                    $cur.properties.template = ($Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json).properties.template
                    $f.Items[$name] = $cur
                }
                return $null
            }
            throw "unexpected $Method $Path"
        }
    }
    $script:NoSleep = { param([int]$Seconds) }
    function script:EnvOf($Res) { $h = [ordered]@{}; foreach ($e in @(@($Res.properties.template.containers)[0].env)) { $h[[string]$e.name] = $(if ($e.PSObject.Properties['secretRef']) { 'secretref:' + $e.secretRef } else { [string]$e.value }) }; $h }
}

Describe '#1257 AI settings: what the settings ask for (pure)' {
    It 'on = the switch + an Azure OpenAI https endpoint + a deployment; the endpoint without its trailing slash' {
        $w = Get-SIAiSettingsWant -Settings $script:On
        $w.State | Should -Be 'on'
        $w.Endpoint | Should -Be 'https://oai-cust.openai.azure.com'
        $w.Deployment | Should -Be 'gpt-4o'
    }
    It 'off: the switch not true (or not set)' {
        (Get-SIAiSettingsWant -Settings @{ SI_EnableAI = 'false'; OpenAI_endpoint = 'https://x.openai.azure.com'; OpenAI_deployment = 'd' }).State | Should -Be 'off'
        (Get-SIAiSettingsWant -Settings @{}).State | Should -Be 'off'
    }
    It 'incomplete: no deployment, no endpoint, or a host that is not Azure OpenAI; unknown: not read' {
        (Get-SIAiSettingsWant -Settings @{ SI_EnableAI = 'true'; OpenAI_endpoint = 'https://x.openai.azure.com' }).Why | Should -Match 'OpenAI_deployment not set'
        (Get-SIAiSettingsWant -Settings @{ SI_EnableAI = 'true'; OpenAI_deployment = 'd' }).State | Should -Be 'incomplete'
        $bad = Get-SIAiSettingsWant -Settings @{ SI_EnableAI = 'true'; OpenAI_endpoint = 'https://evil.example.com'; OpenAI_deployment = 'd' }
        $bad.State | Should -Be 'incomplete'
        $bad.Why | Should -Match 'not an Azure OpenAI host'
        (Get-SIAiSettingsWant -Settings $script:On -Known $false).State | Should -Be 'unknown'
    }
    It 'the setting rows: the JSON values, only the AI names' {
        $s = ConvertFrom-SIAiSettingRows -Rows @(@{ Name = 'SI_EnableAI'; ValueJson = 'true' }, [pscustomobject]@{ Name = 'OpenAI_endpoint'; ValueJson = '"https://x.openai.azure.com"' }, @{ Name = 'SMTPServer'; ValueJson = '"m"' })
        $s['SI_EnableAI'] | Should -Be 'True'
        $s['OpenAI_endpoint'] | Should -Be 'https://x.openai.azure.com'
        $s.ContainsKey('SMTPServer') | Should -BeFalse
    }
    It 'the env plan keeps every other variable and secret reference in place, adds what is missing, removes on $null' {
        $env = @((E 'A' '1'), [pscustomobject]@{ name = 'S'; secretRef = 'sec' }, (E 'Chat__Endpoint' 'https://old.openai.azure.com'))
        $p = Get-SIAiEnvPlan -Env $env -Want ([ordered]@{ Chat__Endpoint = 'https://new.openai.azure.com'; Chat__Deployment = 'd' })
        $p.Changed | Should -BeTrue
        @($p.Env | ForEach-Object name) | Should -Be @('A', 'S', 'Chat__Endpoint', 'Chat__Deployment')
        $p.Env[1].secretRef | Should -Be 'sec'
        $r = Get-SIAiEnvPlan -Env $p.Env -Want ([ordered]@{ Chat__Endpoint = $null; Chat__Deployment = $null })
        @($r.Env | ForEach-Object name) | Should -Be @('A', 'S')
        (Get-SIAiEnvPlan -Env $p.Env -Want ([ordered]@{ Chat__Endpoint = 'https://new.openai.azure.com'; Chat__Deployment = 'd' })).Changed | Should -BeFalse
    }
    It 'an engine job is a job whose first container carries SI_ENGINE' {
        Test-SIAiEngineJob -Job (New-Job 'caj-si-endpoint' @((E 'SI_ENGINE' 'endpoint'))) | Should -BeTrue
        Test-SIAiEngineJob -Job (New-Job 'caj-si-updater' @((E 'SI_UPDATER_ACR' 'x'))) | Should -BeFalse
    }
}

Describe '#1257 AI settings: the converge' {
    BeforeEach {
        $script:Arm = New-FakeArm
        $script:Fake.Items['ca-si-management'] = New-Web @((E 'Identity__ClientId' 'c'), [pscustomobject]@{ name = 'X'; secretRef = 's1' })
        $script:Fake.Items['caj-si-endpoint'] = New-Job 'caj-si-endpoint' @((E 'SI_ENGINE' 'endpoint'), [pscustomobject]@{ name = 'OPENAI_APIKEY'; secretRef = 'openai-apikey' })
        $script:Fake.Items['caj-si-updater'] = New-Job 'caj-si-updater' @((E 'SI_UPDATER_ACR' 'x'))
        $script:Jobs = @($script:Fake.Items['caj-si-endpoint'], $script:Fake.Items['caj-si-updater'])
    }
    It 'AI on: the web chat and the engine job get the settings, read back; the updater job and the key are untouched' {
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $script:On -Sleep $script:NoSleep
        $r.State | Should -Be 'on'
        @($r.Results | Where-Object Action -eq 'set').Count | Should -Be 2
        $web = EnvOf $script:Fake.Items['ca-si-management']
        $web['Chat__Endpoint'] | Should -Be 'https://oai-cust.openai.azure.com'
        $web['Chat__Deployment'] | Should -Be 'gpt-4o'
        $web['X'] | Should -Be 'secretref:s1'
        $web.Contains('Chat__ApiKey') | Should -BeFalse
        $job = EnvOf $script:Fake.Items['caj-si-endpoint']
        $job['OPENAI_ENDPOINT'] | Should -Be 'https://oai-cust.openai.azure.com'
        $job['OPENAI_DEPLOYMENT'] | Should -Be 'gpt-4o'
        $job['OPENAI_APIVERSION'] | Should -Be '2024-08-01-preview'
        $job['OPENAI_APIKEY'] | Should -Be 'secretref:openai-apikey' -Because 'a legacy key reference is left exactly as it was'
        @($script:Fake.Patches | ForEach-Object Name) | Should -Not -Contain 'caj-si-updater'
    }
    It 'the web PATCH: the whole template, the sign-in front as read, no revision suffix, never the configuration' {
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @() -Settings $script:On -Sleep $script:NoSleep
        $b = @($script:Fake.Patches | Where-Object Name -eq 'ca-si-management')[0].Body
        $b.properties.PSObject.Properties['configuration'] | Should -BeNullOrEmpty
        $b.properties.template.PSObject.Properties['revisionSuffix'] | Should -BeNullOrEmpty
        @($b.properties.template.containers).Count | Should -Be 2
        @($b.properties.template.containers)[1].env[0].name | Should -Be 'FRONT'
        @($b.properties.template.containers)[0].resources.PSObject.Properties['ephemeralStorage'] | Should -BeNullOrEmpty
    }
    It 'IDEMPOTENT: a second run changes nothing (no PATCH -- no new web revision)' {
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $script:On -Sleep $script:NoSleep
        $script:Fake.Patches.Clear()
        $jobs2 = @($script:Fake.Items['caj-si-endpoint'], $script:Fake.Items['caj-si-updater'])
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $jobs2 -Settings $script:On -Sleep $script:NoSleep
        $script:Fake.Patches.Count | Should -Be 0
        @($r.Results | ForEach-Object Action | Sort-Object -Unique) | Should -Be @('in-place')
    }
    It 'a changed deployment: one PATCH per resource, the new value' {
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $script:On -Sleep $script:NoSleep
        $script:Fake.Patches.Clear()
        $s = @{} + $script:On; $s['OpenAI_deployment'] = 'gpt-4.1'
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @($script:Fake.Items['caj-si-endpoint']) -Settings $s -Sleep $script:NoSleep
        $script:Fake.Patches.Count | Should -Be 2
        (EnvOf $script:Fake.Items['ca-si-management'])['Chat__Deployment'] | Should -Be 'gpt-4.1'
    }
    It 'the job keeps its own API version when the setting has none; the setting wins when set' {
        $script:Fake.Items['caj-si-endpoint'] = New-Job 'caj-si-endpoint' @((E 'SI_ENGINE' 'endpoint'), (E 'OPENAI_APIVERSION' '2025-01-01-preview'))
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @($script:Fake.Items['caj-si-endpoint']) -Settings $script:On -Sleep $script:NoSleep
        (EnvOf $script:Fake.Items['caj-si-endpoint'])['OPENAI_APIVERSION'] | Should -Be '2025-01-01-preview'
        $s = @{} + $script:On; $s['OpenAI_apiVersion'] = '2024-10-21'
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @($script:Fake.Items['caj-si-endpoint']) -Settings $s -Sleep $script:NoSleep
        (EnvOf $script:Fake.Items['caj-si-endpoint'])['OPENAI_APIVERSION'] | Should -Be '2024-10-21'
    }
    It 'AI off: the web app''s chat settings are removed; the jobs are left alone' {
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $script:On -Sleep $script:NoSleep
        $script:Fake.Patches.Clear()
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @($script:Fake.Items['caj-si-endpoint']) -Settings @{ SI_EnableAI = 'false' } -Sleep $script:NoSleep
        $r.State | Should -Be 'off'
        @($script:Fake.Patches | ForEach-Object Name) | Should -Be @('ca-si-management')
        $web = EnvOf $script:Fake.Items['ca-si-management']
        $web.Contains('Chat__Endpoint') | Should -BeFalse
        $web.Contains('Chat__Deployment') | Should -BeFalse
        $web['Identity__ClientId'] | Should -Be 'c'
        (EnvOf $script:Fake.Items['caj-si-endpoint'])['OPENAI_ENDPOINT'] | Should -Be 'https://oai-cust.openai.azure.com'
        # off again: nothing to remove = no PATCH
        $script:Fake.Patches.Clear()
        $null = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Settings @{ SI_EnableAI = 'false' } -Sleep $script:NoSleep
        $script:Fake.Patches.Count | Should -Be 0
    }
    It 'not read / incomplete / not an Azure OpenAI host: nothing is changed, one line says why' {
        foreach ($c in @(@{ S = $script:On; K = $false; M = 'not checked' }, @{ S = @{ SI_EnableAI = 'true'; OpenAI_endpoint = 'https://x.openai.azure.com' }; K = $true; M = 'AI is on, but' },
                         @{ S = @{ SI_EnableAI = 'true'; OpenAI_endpoint = 'https://evil.example.com'; OpenAI_deployment = 'd' }; K = $true; M = 'not an Azure OpenAI host' })) {
            $r = Invoke-SIAiSettings -Arm { throw 'must not be called' } -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $c.S -Known $c.K
            @($r.Lines).Count | Should -Be 1
            $r.Lines[0] | Should -Match $c.M
        }
    }
    It '-WhatIf: the plan only, no PATCH' {
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs $script:Jobs -Settings $script:On -WhatIf
        $script:Fake.Patches.Count | Should -Be 0
        @($r.Results | ForEach-Object Action | Sort-Object -Unique) | Should -Be @('would-set')
    }
    It 'refused, or not read back: a line, never a throw, never "set"' {
        $script:Fake.PatchError = 'HTTP 403: AuthorizationFailed'
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @() -Settings $script:On -Sleep $script:NoSleep
        $r.Results[0].Action | Should -Be 'failed'
        $r.Lines[0] | Should -Match 'could not be set .*403'
        $script:Fake.PatchError = ''; $script:Fake.NoApply = $true
        $r2 = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @() -Settings $script:On -Sleep $script:NoSleep -ReadBackTries 1
        $r2.Results[0].Action | Should -Be 'failed'
        $r2.Lines[0] | Should -Match 'does not read back'
    }
    It 'no web app in the install: said, nothing sent' {
        $script:Fake.Items.Remove('ca-si-management')
        $r = Invoke-SIAiSettings -Arm $script:Arm -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Jobs @() -Settings $script:On
        $r.Results[0].Action | Should -Be 'none'
        $script:Fake.Patches.Count | Should -Be 0
    }
    It 'the lib never writes a key or a secret' {
        $t = [IO.File]::ReadAllText($script:Lib)
        $t | Should -Not -Match "'OPENAI_APIKEY'\s*="
        $t | Should -Not -Match 'Chat__ApiKey'
        $t | Should -Not -Match 'secretRef\s*='
    }
}

Describe '#1257 AI settings: the updater step' {
    BeforeAll {
        $path = [IO.Path]::Combine($script:SIRoot, 'container', 'updater', 'Start-SIUpdater.ps1')
        $script:UpdText = [IO.File]::ReadAllText($path)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
        foreach ($n in 'Invoke-SIUpdaterAiSettingsStep', 'Read-SIUpdaterAiSettingRows') {
            $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)
            $fn | Should -Not -BeNullOrEmpty
            . ([scriptblock]::Create(($fn.Extent.Text -replace ('^function ' + [regex]::Escape($n)), ('function script:' + $n))))
        }
        $global:SIv3AiUpdLog = New-Object System.Collections.Generic.List[string]
        function script:Write-UpdLog { param([string]$Message) $global:SIv3AiUpdLog.Add($Message) }
        function script:Get-SIUpdaterInstallName { param($Role, $Env) 'ca-si-management' }
    }
    AfterAll { Remove-Variable -Scope Global -Name SIv3AiUpdLog -ErrorAction SilentlyContinue }
    It 'reads the settings from the database rows, lists the jobs, sets the web chat and the engine jobs' {
        $arm = New-FakeArm
        $script:Fake.Items['ca-si-management'] = New-Web @()
        $script:Fake.Items['caj-si-endpoint'] = New-Job 'caj-si-endpoint' @((E 'SI_ENGINE' 'endpoint'))
        $store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) @(@{ Name = 'SI_EnableAI'; ValueJson = 'true' }, @{ Name = 'OpenAI_endpoint'; ValueJson = '"https://oai-cust.openai.azure.com"' }, @{ Name = 'OpenAI_deployment'; ValueJson = '"gpt-4o"' }) } }
        $r = Invoke-SIUpdaterAiSettingsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Store $store -Arm $arm -Lib $script:Lib -Sleep $script:NoSleep
        $r.State | Should -Be 'on'
        (EnvOf $script:Fake.Items['ca-si-management'])['Chat__Deployment'] | Should -Be 'gpt-4o'
        (EnvOf $script:Fake.Items['caj-si-endpoint'])['OPENAI_DEPLOYMENT'] | Should -Be 'gpt-4o'
    }
    It 'the database could not be read: nothing changed (never "AI off" on a guess)' {
        $arm = New-FakeArm
        $script:Fake.Items['ca-si-management'] = New-Web @((E 'Chat__Endpoint' 'https://oai-cust.openai.azure.com'), (E 'Chat__Deployment' 'gpt-4o'))
        $store = [pscustomobject]@{ Invoke = { param($sql, $p, $mode) throw 'login failed' } }
        $global:SIv3AiUpdLog.Clear()
        $r = Invoke-SIUpdaterAiSettingsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Store $store -Arm $arm -Lib $script:Lib -Sleep $script:NoSleep
        $r.State | Should -Be 'unknown'
        $script:Fake.Patches.Count | Should -Be 0
        @($global:SIv3AiUpdLog | Where-Object { $_ -match '^WARNING: AI settings: not checked' }).Count | Should -Be 1
        # no database at all: the same
        (Invoke-SIUpdaterAiSettingsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Store $null -Arm $arm -Lib $script:Lib).State | Should -Be 'unknown'
    }
    It 'SI_UPDATER_AI_SETTINGS = plan: the plan only' {
        $arm = New-FakeArm
        $script:Fake.Items['ca-si-management'] = New-Web @()
        $r = Invoke-SIUpdaterAiSettingsStep -SubscriptionId $script:Sub -ResourceGroup 'rg-si' -Env @{ SI_UPDATER_AI_SETTINGS = 'plan' } -Arm $arm -Lib $script:Lib `
            -SettingRows @(@{ Name = 'SI_EnableAI'; ValueJson = 'true' }, @{ Name = 'OpenAI_endpoint'; ValueJson = '"https://oai-cust.openai.azure.com"' }, @{ Name = 'OpenAI_deployment'; ValueJson = '"gpt-4o"' })
        $script:Fake.Patches.Count | Should -Be 0
        $r.Results[0].Action | Should -Be 'would-set'
    }
    It 'WIRING: on every run, before the apply-settings return, before the rights check; reported under a step name the uplink knows' {
        $t = $script:UpdText
        $ai = $t.IndexOf('$null = Invoke-SIUpdaterAiSettingsStep -SubscriptionId $sub -ResourceGroup $rg -Store $proStore -Env $Env')
        $rights = $t.IndexOf('$null = Invoke-SIUpdaterOpenAIRightsStep -SubscriptionId $sub -ResourceGroup $rg -Store $proStore -Env $Env')
        $ret = $t.IndexOf("Write-UpdLog 'apply-settings run: the settings handed over in the web app were applied")
        $ai | Should -BeGreaterThan 0
        $rights | Should -BeGreaterThan $ai
        $ret | Should -BeGreaterThan $rights
        $t | Should -Not -Match "SI_UpdaterStep = 'openai-rights'"
    }
}
