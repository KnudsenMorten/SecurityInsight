#Requires -Version 5.1
<#
    THE PRIVILEGE-TIER CLASSIFIER RUNS WHERE IT IS DEPLOYED, SENDS NOTHING WHEN AI IS OFF, AND NEVER
    ERASES A KNOWN TIER (#137).

      * the container entrypoint dispatched the classifier BEFORE hydrating any env var or connecting
        -- "Missing SPN globals" on every container run;
      * SI_PrivilegeTierClassifier_RunAI was documented and read by nothing -- role and permission
        text still went to Azure OpenAI with AI turned off;
      * a failed AI chunk (3 attempts, 3s apart -- inside one throttle window) turned its items into
        Tier 99 and the catalog was REWRITTEN; the consumer reads only Tier 0-3 and a tenant's custom
        roles live only in that file, so one bad AI night dropped every custom Tier-0 role;
      * the community launcher threw "not supported" on a certificate, and the engine's own Azure
        connect could only use a secret.
    Engine functions are lifted by AST and run against mocks. No network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:EnginePath = Join-Path $script:SIRoot 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
    $script:EngineSrc  = Get-Content -LiteralPath $script:EnginePath -Raw
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$null, [ref]$null)
    $script:Lifted = @()
    foreach ($name in 'Get-PTCRetryDelaySeconds','Restore-PTCPriorTiers','Invoke-AISingleChunk','Connect-AzWithSPN') {
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true) | Select-Object -First 1
        if ($fn) { . ([scriptblock]::Create($fn.Extent.Text)); $script:Lifted += $name }
    }
    # the engine calls Azure through the SI wrappers (plain REST, no module); the tests mock those
    . (Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1')
    function script:Write-Log { param($Message, $Level) }

    function script:New-Err($Response) {
        $ex = New-Object System.Exception 'throttled'
        if ($Response) { $ex | Add-Member -NotePropertyName Response -NotePropertyValue $Response -Force }
        [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'NotSpecified', $null)
    }
    $script:Chunk = @([pscustomobject]@{ Name = 'Org Tier0 Admin' }, [pscustomobject]@{ Name = 'Reader' })
}

Describe 'the fixed functions exist' {
    It 'all four were lifted from the engine' {
        $script:Lifted.Count | Should -Be 4 -Because ($script:Lifted -join ',')
    }
}

Describe 'AI turned off sends nothing' {
    BeforeEach {
        $global:OpenAI_ApiKey = 'k'; $global:OpenAI_Endpoint = 'https://x'; $global:OpenAI_Deployment = 'd'; $global:OpenAI_ApiVersion = 'v'
        $global:AI_MaxRetries = 2; $global:AI_MaxTokens = 100
        $script:PtcAICallsUsed = 0
    }
    AfterEach { Remove-Variable -Scope Global -Name SI_PrivilegeTierClassifier_RunAI -ErrorAction SilentlyContinue }

    It 'RunAI = $false: no request, every item comes back UNRESOLVED' {
        $global:SI_PrivilegeTierClassifier_RunAI = $false
        Mock Invoke-RestMethod { throw 'must not be called' }
        $r = @(Invoke-AISingleChunk -CategoryName 'Entra' -Chunk $script:Chunk -ChunkIndex 1 -TotalChunks 1)
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        $r.Count | Should -Be 2
        @($r | Where-Object { $_.Unresolved -and $_.Tier -eq 99 }).Count | Should -Be 2
    }
    It 'RunAI unset: the request is sent and counted (control)' {
        Mock Invoke-RestMethod { [pscustomobject]@{ choices = @([pscustomobject]@{ message = [pscustomobject]@{ content = '[{"Name":"Reader","Tier":3,"Reason":"r"}]' } }) } }
        $r = @(Invoke-AISingleChunk -CategoryName 'Entra' -Chunk $script:Chunk -ChunkIndex 1 -TotalChunks 1)
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        $r[0].Tier | Should -Be 3
        $script:PtcAICallsUsed | Should -Be 1
    }
    It 'retries back off (not a fixed 3s), and exhaustion marks items UNRESOLVED' {
        Mock Invoke-RestMethod { throw 'HTTP 429' }
        Mock Start-Sleep { }
        $r = @(Invoke-AISingleChunk -CategoryName 'Entra' -Chunk $script:Chunk -ChunkIndex 1 -TotalChunks 1)
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 5 }
        @($r | Where-Object { $_.Unresolved }).Count | Should -Be 2
    }
}

Describe 'Retry-After is honoured on both editions' {
    It 'header indexer (PS 5.1 shape)' {
        Get-PTCRetryDelaySeconds -ErrorRecord (New-Err ([pscustomobject]@{ Headers = @{ 'Retry-After' = '30' } })) -Attempt 1 | Should -Be 31
    }
    It 'typed RetryAfter.Delta (pwsh 7 shape)' {
        $h = [pscustomobject]@{ RetryAfter = [pscustomobject]@{ Delta = [timespan]::FromSeconds(12); Date = $null } }
        Get-PTCRetryDelaySeconds -ErrorRecord (New-Err ([pscustomobject]@{ Headers = $h })) -Attempt 1 | Should -Be 13
    }
    It 'no header: exponential, capped' {
        Get-PTCRetryDelaySeconds -ErrorRecord (New-Err $null) -Attempt 1 | Should -Be 5
        Get-PTCRetryDelaySeconds -ErrorRecord (New-Err $null) -Attempt 3 | Should -Be 20
        Get-PTCRetryDelaySeconds -ErrorRecord (New-Err $null) -Attempt 9 | Should -Be 60
    }
}

Describe 'a known tier is never erased by an unresolved run' {
    BeforeAll {
        $script:Prior = Join-Path $TestDrive 'prior.json'
        @{
            EntraID_CustomRoles_Tier0    = @(@{ DisplayName = 'Org Tier0 Admin'; Reason = 'can reset admin passwords' })
            EntraID_BuiltInRoles_Tier3   = @(@{ DisplayName = 'Reader'; Reason = 'read only' })
            EntraID_APIPermissions_Tier1 = @(@{ Value = 'Mail.Send'; Reason = 'send as anyone' })
            Azure_CustomRoles_Tier0      = @(@{ Name = 'Org Owner'; Reason = 'owner-equivalent' })
            AD_BuiltInPermissionGroups_Tier0 = @(@{ Name = 'Domain Admins'; Reason = 'dc admin' })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:Prior -Encoding UTF8
    }
    It 'unresolved items take their previous tier; fresh AI tiers and never-seen items are left alone' {
        $t = @{
            ADGroups   = @([pscustomobject]@{ Name = 'Domain Admins'; Tier = 99; Reason = 'x' })
            EntraRoles = @([pscustomobject]@{ DisplayName = 'org tier0 admin'; Tier = 99; Reason = 'x' },
                           [pscustomobject]@{ DisplayName = 'Reader'; Tier = 2; Reason = 'fresh' },
                           [pscustomobject]@{ DisplayName = 'Brand New Role'; Tier = 99; Reason = 'x' })
            APIPerms   = @([pscustomobject]@{ Value = 'Mail.Send'; Tier = 99; Reason = 'x' })
            AzureRoles = @([pscustomobject]@{ Name = 'Org Owner'; Tier = 99; Reason = 'x' })
        }
        Restore-PTCPriorTiers -Tiered $t -PriorPath $script:Prior | Should -Be 4
        $t.EntraRoles[0].Tier   | Should -Be 0
        $t.EntraRoles[0].Reason | Should -Match 'kept from the previous catalog'
        $t.EntraRoles[1].Tier   | Should -Be 2
        $t.EntraRoles[2].Tier   | Should -Be 99
        $t.APIPerms[0].Tier     | Should -Be 1
        $t.AzureRoles[0].Tier   | Should -Be 0
        $t.ADGroups[0].Tier     | Should -Be 0
    }
    It 'no previous catalog: nothing restored, nothing thrown' {
        Restore-PTCPriorTiers -Tiered @{ EntraRoles = @() } -PriorPath (Join-Path $TestDrive 'none.json') | Should -Be 0
    }
    It 'an unreadable previous catalog: nothing restored, nothing thrown' {
        $bad = Join-Path $TestDrive 'bad.json'; Set-Content -LiteralPath $bad -Value '{ not json'
        Restore-PTCPriorTiers -Tiered @{ EntraRoles = @() } -PriorPath $bad | Should -Be 0
    }
    It 'WIRING -- Main restores between tiering and export, and reports real AI call counts' {
        $script:EngineSrc | Should -Match '(?s)Invoke-AllAITiering.{0,400}Restore-PTCPriorTiers -Tiered \$tiered -PriorPath \$OutputFile.{0,800}Export-TieredJSON'
        $script:EngineSrc | Should -Not -Match 'AICallsUsed\s*=\s*4'
    }
}

Describe 'certificate auth works on the community path' {
    It 'the engine connects Azure with the certificate when there is no secret' {
        $global:SpnClientId = 'app'; $global:SpnTenantId = 'tid'; $global:SpnClientSecret = $null; $global:SpnCertificateThumbprint = 'ABC'
        Mock Get-SIAzContext { $null }
        Mock Connect-SIAzAccount { }
        Mock Get-SIAzSubscription { }
        Connect-AzWithSPN
        Should -Invoke Connect-SIAzAccount -Times 1 -Exactly -ParameterFilter { $CertificateThumbprint -eq 'ABC' -and $ApplicationId -eq 'app' }
    }
    It 'the Graph token bridge carries the thumbprint' {
        $script:EngineSrc | Should -Match 'SI_SPN_CertThumbprint\s*=\s*\$global:SpnCertificateThumbprint'
    }
    It 'the community launcher no longer refuses a certificate' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'launcher\privilege-tier-classifier\launcher.community-vm.ps1') -Raw
        $src | Should -Not -Match 'certificate auth is not supported'
        $src | Should -Match "authMethodUsed = 'SPN-Certificate'"
    }
}

Describe 'WIRING -- the container dispatches the classifier after it is configured' {
    It 'the classifier call comes after env hydration and Connect-AzAccount, not inside the role switch' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1') -Raw
        $call    = $src.IndexOf('& $classifierScript')
        $hydrate = $src.IndexOf("Get-RequiredEnv 'SI_SPN_APPID'")
        $connect = $src.IndexOf('Connect-SIAzAccount -ServicePrincipal')   # the SI wrapper (plain REST)
        $call    | Should -BeGreaterThan 0
        $hydrate | Should -BeGreaterThan 0
        $call    | Should -BeGreaterThan $hydrate
        $call    | Should -BeGreaterThan $connect
    }
}
