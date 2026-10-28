#Requires -Version 5.1
<#
    ONE connect path (owner 2026-10-09: "modern single connect only"; "we dont do ps modules"): SecurityInsight's
    own REST token client -- managed identity, certificate, client secret (and in setup a person's own sign-in). The old
    sign-in mode "AzContext" (#413: borrow the current Azure session of the process) and its file
    engine/_shared/SI-AzSession.ps1 are GONE.
    #524 -- one TOKEN SOURCE of that path (owner 2026-10-09 via Invardia: "support installs use TOKENS, never the secret"):
    an Invardia support session's Get-InvardiaSupportToken -Resource <r>. A raw token (for what no HTTP request can carry)
    comes from it; each token's tenant is checked against the tenant SI works in.
    Owner 2026-10-12 -- the session itself is USED: who SI works as is read from the session (no token asked for), and
    the session is detected in ONE place (Get-SISupportSession: its state names a tenant AND its recording command is
    in the shell). Routing and Grant-SIIdentity inside a session: SIv3-SetupInSupportSession.Tests.ps1.

    OFFLINE. An Az PowerShell session (Get-AzContext / Get-AzAccessToken) is a FAKE that counts every call: always 0.
    The support session is a fake: the state Connect-InvardiaSupport leaves, its recording command (counts each call) and
    Get-InvardiaSupportToken (records each resource asked, returns a JWT with tid / appid / oid). No module, no network.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')

    $script:Tid = '11111111-1111-1111-1111-111111111111'
    $script:Other = '99999999-9999-9999-9999-999999999999'
    $script:Sub = '22222222-2222-2222-2222-222222222222'
    $script:GlobalNames = 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_AzSessionTokens', 'SI_AuthMethod', 'SI_UseManagedIdentity', 'UseManagedIdentity',
                          'SI_UAMI_ClientId', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret', 'SI_SPN_CertThumbprint', 'SpnClientId', 'SpnTenantId',
                          'SpnClientSecret', 'SpnCertificateThumbprint', 'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_CertificateThumbprint_Azure',
                          'HighPriv_Modern_TenantID', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_ApplicationSecret_Azure', 'AzureTenantId', 'TenantId',
                          'SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SubscriptionId', 'SI_TokenProvider', 'InvardiaSupportState',
                          'FakeAzCalls', 'FakeSupportCalls', 'FakeSupportTid', 'FakeSupportRequests'
    $script:EnvNames = 'INVARDIA_SUPPORT_ENVIRONMENT', 'INVARDIA_SUPPORT_TENANT', 'INVARDIA_SUPPORT_SUBSCRIPTIONS'
    $script:FakeFns = 'Get-AzContext', 'Get-AzAccessToken', 'Get-InvardiaSupportToken', 'Invoke-InvardiaSupportRequest'
    # these are GLOBAL names by Invardia's contract: whatever was there before this file ran is put back in AfterAll
    $script:HadState = [bool](Get-Variable -Scope Global -Name InvardiaSupportState -ErrorAction Ignore)
    $script:StateBefore = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
    $script:FnsBefore = @{}
    foreach ($n in 'Get-InvardiaSupportToken', 'Invoke-InvardiaSupportRequest') { $fn = Get-Item -LiteralPath ('Function:\' + $n) -ErrorAction Ignore; if ($fn) { $script:FnsBefore[$n] = $fn.ScriptBlock } }

    function script:Install-FakeAzSession {
        # an Az PowerShell sign-in in the same shell: SecurityInsight must never touch it
        $global:FakeAzCalls = New-Object System.Collections.Generic.List[string]
        Set-Item -Path 'function:global:Get-AzContext' -Value {
            $global:FakeAzCalls.Add('Get-AzContext')
            [pscustomobject]@{ Account = [pscustomobject]@{ Id = 'person@contoso.example'; Type = 'User' }; Tenant = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' } }
        }
        Set-Item -Path 'function:global:Get-AzAccessToken' -Value { param([string]$ResourceUrl) $global:FakeAzCalls.Add('Get-AzAccessToken'); [pscustomobject]@{ Token = 'az-session-token' } }
    }
    function script:Install-FakeSupport([string]$Tid = '11111111-1111-1111-1111-111111111111', [string]$StateTid = '11111111-1111-1111-1111-111111111111') {
        # what Connect-InvardiaSupport leaves: its state, its recording command, and
        # Get-InvardiaSupportToken -Resource <r> [-ForceRefresh] -> a bearer JWT (-Tid: the tenant the TOKEN is for)
        $global:FakeSupportCalls = New-Object System.Collections.Generic.List[object]
        $global:FakeSupportRequests = New-Object System.Collections.Generic.List[object]
        $global:FakeSupportTid = $Tid
        Set-Item -Path 'function:global:Invoke-InvardiaSupportRequest' -Value {
            param([string]$Method = 'GET', [string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers, [string]$Reason, [switch]$AsBytes, [switch]$ReadOnly, [int]$TimeoutSec = 0, [string]$TokenResource)
            $global:FakeSupportRequests.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; ReadOnly = [bool]$ReadOnly })
            [pscustomobject]@{ StatusCode = 200; Content = '{"displayName":"Sub One","value":[]}'; Headers = @{}; Method = $Method }
        }
        Set-Item -Path 'function:global:Get-InvardiaSupportToken' -Value {
            param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
            $global:FakeSupportCalls.Add([pscustomobject]@{ Resource = $Resource; ForceRefresh = [bool]$ForceRefresh })
            $b = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
            $claims = @{ tid = $global:FakeSupportTid; appid = 'support-app-id'; oid = '55555555-5555-5555-5555-555555555555'; aud = $Resource; n = $global:FakeSupportCalls.Count } | ConvertTo-Json -Compress
            '{0}.{1}.sig' -f (& $b '{"alg":"RS256"}'), (& $b $claims)
        }
        # the session's own state: who SI works as is read from it (Get-SISupportSession)
        $global:InvardiaSupportState = @{ Environment = 'test-env'; TenantId = $StateTid; AppId = 'support-app-id'
            Subscriptions = @('22222222-2222-2222-2222-222222222222', '33333333-3333-3333-3333-333333333333'); SubscriptionId = '22222222-2222-2222-2222-222222222222'
            SubscriptionName = 'Sub One'; EnvironmentId = '44444444-4444-4444-4444-444444444444'; SessionId = '66666666-6666-6666-6666-666666666666'; Tokens = @{}; Reads = @{} }
    }
    function script:Remove-Fakes {
        foreach ($n in $script:FakeFns) {
            $i = 0
            while ((Test-Path -LiteralPath ('Function:\' + $n)) -and $i -lt 5) { Remove-Item -LiteralPath ('Function:\' + $n) -Force -ErrorAction SilentlyContinue; $i++ }
        }
        Remove-Variable -Scope Global -Name InvardiaSupportState -ErrorAction SilentlyContinue
    }
}

AfterAll {
    Remove-Fakes
    if ($script:HadState) { $global:InvardiaSupportState = $script:StateBefore }
    foreach ($n in $script:FnsBefore.Keys) { Set-Item -Path ('function:global:' + $n) -Value $script:FnsBefore[$n] }
}

Describe 'one connect path: SI''s own REST client, with the Invardia support session as a token source (#524)' {
    BeforeEach {
        $script:keep = @{}
        foreach ($n in $script:GlobalNames) { $script:keep[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue; Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $script:envKeep = @{}
        foreach ($e in $script:EnvNames) { $script:envKeep[$e] = [Environment]::GetEnvironmentVariable($e); [Environment]::SetEnvironmentVariable($e, $null) }
        Remove-Fakes
        $st = Get-SIAzRestState; $st.Connection = $null; $st.TenantId = $null; $st.SubscriptionId = $null; $st.Cache = @{}
        if ($global:SI_LogIngestRunCache -is [hashtable]) { $global:SI_LogIngestRunCache.Tokens = @{} }
    }
    AfterEach {
        Remove-Fakes
        $st = Get-SIAzRestState; $st.Connection = $null; $st.Cache = @{}
        foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue; if ($null -ne $script:keep[$n]) { Set-Variable -Scope Global -Name $n -Value $script:keep[$n] } }
        foreach ($e in $script:EnvNames) { [Environment]::SetEnvironmentVariable($e, $script:envKeep[$e]) }
    }

    Context 'no support session: SI''s own clients only, never an Azure session' {
        It 'an Az PowerShell session alone is no sign-in: the plain "No sign-in is configured" error; Az never called' {
            Install-FakeAzSession
            $msg = $null; try { $null = Resolve-SIAzRestAuth } catch { $msg = $_.Exception.Message }
            $msg | Should -BeLike '*No sign-in is configured*'
            $msg | Should -BeLike '*managed identity*certificate*client secret*Get-InvardiaSupportToken*'
            { Get-SIAzureToken -Audience Arm } | Should -Throw '*No sign-in is configured*'
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'SI_AuthMethod = AzContext (the retired mode) is refused by name; Az never called' {
            Install-FakeAzSession
            $global:SI_AuthMethod = 'AzContext'
            $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'ten-1'; $global:SI_SPN_Secret = 's'
            { Resolve-SIAzRestAuth } | Should -Throw '*SI_AuthMethod = AzContext*no longer supported*'
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'a managed identity / an SPN certificate / an SPN secret resolves as before (<Kind>)' -ForEach @(
            @{ Kind = 'ManagedIdentity'; Set = { $global:SI_UseManagedIdentity = $true } }
            @{ Kind = 'Certificate'; Set = { $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'ten-1'; $global:SI_SPN_CertThumbprint = 'AB CD' } }
            @{ Kind = 'Secret'; Set = { $global:SI_SPN_AppId = 'app-1'; $global:SI_SPN_TenantId = 'ten-1'; $global:SI_SPN_Secret = 's' } }
        ) {
            Install-FakeAzSession
            [Environment]::SetEnvironmentVariable('INVARDIA_SUPPORT_ENVIRONMENT', 'contoso-test')   # an env var alone selects nothing
            & $Set
            (Resolve-SIAzRestAuth).Mode | Should -Be $Kind
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'the log-ingest default is the run''s own sign-in (Mode Run)' {
            (Resolve-SILogIngestAuth -Bound @{}).Mode | Should -Be 'Run'
        }
    }

    Context 'an Invardia support session in the shell: read from the session; a raw token only from Get-InvardiaSupportToken (#524)' {
        It 'the run works as the support app: Mode Support, app / tenant / first subscription read from the SESSION -- no token asked for' {
            Install-FakeSupport; Install-FakeAzSession
            $a = Resolve-SIAzRestAuth
            $a.Mode | Should -Be 'Support'
            $a.AppId | Should -Be 'support-app-id'
            $a.TenantId | Should -Be $script:Tid
            $a.SubscriptionId | Should -Be $script:Sub
            $global:FakeSupportCalls.Count | Should -Be 0 -Because 'who SI works as is read from the session, not from a token'
            $global:FakeSupportRequests.Count | Should -Be 0
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'the session is detected in ONE way: its state names a tenant AND its recording command is in the shell' {
            Get-SISupportSession | Should -BeNullOrEmpty
            Install-FakeSupport
            (Get-SISupportSession).TenantId | Should -Be $script:Tid
            @((Get-SISupportSession).Subscriptions) | Should -Be @($script:Sub, '33333333-3333-3333-3333-333333333333')
            Test-SISupportTokenSource | Should -BeTrue
            # the token command alone (no state) is no session -- as after Disconnect-InvardiaSupport, which empties the state
            $global:InvardiaSupportState = $null
            Get-SISupportSession | Should -BeNullOrEmpty
            Test-SISupportTokenSource | Should -BeFalse
            { Resolve-SIAzRestAuth } | Should -Throw '*No sign-in is configured*'
            # a state WITHOUT the recording command is said and stops -- never guessed
            Install-FakeSupport
            Remove-Item -LiteralPath 'Function:\Invoke-InvardiaSupportRequest' -Force
            { Get-SISupportSession } | Should -Throw '*recording command Invoke-InvardiaSupportRequest is not here*Nothing was done*'
            { Resolve-SIAzRestAuth } | Should -Throw '*recording command*'
        }
        It 'a Support sign-in whose session was closed is dropped, not used on' {
            Install-FakeSupport
            (Get-SIAzRestState).Connection = Resolve-SIAzRestAuth
            Remove-Fakes
            { Resolve-SIAzRestAuth } | Should -Throw '*No sign-in is configured*'
            (Get-SIAzRestState).Connection | Should -BeNullOrEmpty
        }
        It 'each audience SI uses is asked of the support session with its resource; -ForceRefresh is passed on' {
            Install-FakeSupport
            $want = [ordered]@{ Arm = 'https://management.azure.com'; Graph = 'https://graph.microsoft.com'; LaQuery = 'https://api.loganalytics.io'
                                KeyVault = 'https://vault.azure.net'; Storage = 'https://storage.azure.com'; Monitor = 'https://monitor.azure.com' }
            foreach ($aud in $want.Keys) {
                $global:FakeSupportCalls.Clear()
                $t = Get-SIAzureToken -Audience $aud
                (ConvertFrom-SIJwtPayload $t).aud | Should -Be $want[$aud] -Because $aud
                @($global:FakeSupportCalls | ForEach-Object Resource) | Should -Contain $want[$aud]
            }
            $global:FakeSupportCalls.Clear()
            (ConvertFrom-SIJwtPayload (Get-SIAzureToken -Resource 'https://database.windows.net/')).aud | Should -Be 'https://database.windows.net'
            $global:FakeSupportCalls.Clear()
            $null = Get-SIAzureToken -Audience Arm -ForceRefresh
            @($global:FakeSupportCalls | Where-Object { $_.Resource -eq 'https://management.azure.com' -and $_.ForceRefresh }).Count | Should -Be 1
        }
        It 'a token for another tenant than the one SI works in is REFUSED (never trusted blindly)' {
            Install-FakeSupport -Tid $script:Other -StateTid $script:Other
            $global:SI_SPN_TenantId = $script:Tid   # the tenant this install works in
            { Resolve-SIAzRestAuth } | Should -Throw "*is for tenant $($script:Other), not $($script:Tid)*refused*"
            Remove-Variable -Scope Global -Name SI_SPN_TenantId -ErrorAction SilentlyContinue
            # and per token: an established support sign-in whose later token comes back for another tenant
            Install-FakeSupport
            $null = Resolve-SIAzRestAuth
            (Get-SIAzRestState).Connection = Resolve-SIAzRestAuth
            $global:FakeSupportTid = $script:Other
            { Get-SIAzureToken -Audience Graph } | Should -Throw '*refused*'
        }
        It 'a token for another tenant than the session''s own is refused (the session says one tenant, its token another)' {
            Install-FakeSupport -Tid $script:Other
            $null = Resolve-SIAzRestAuth
            { Get-SIAzureToken -Audience Graph } | Should -Throw '*refused*'
        }
        It 'the subscription is the first the session names (its state, not an environment variable)' {
            Install-FakeSupport
            [Environment]::SetEnvironmentVariable('INVARDIA_SUPPORT_SUBSCRIPTIONS', '33333333-3333-3333-3333-333333333333')
            Get-SIAzRestSubscriptionId -NoLookup | Should -Be $script:Sub
        }
    }

    Context 'setup sign-in (Connect-SISetupAzure)' {
        BeforeEach { Mock Invoke-SIAzRestHttp { throw 'offline: no HTTP in this test' } }
        It 'a support session: the context is the session''s -- no browser, no secret, no token request, no Az call' {
            Install-FakeSupport; Install-FakeAzSession
            Mock Connect-SISetupUser { throw 'a browser must not be opened' }
            $c = Connect-SISetupAzure -TenantId $script:Tid -SubscriptionId $script:Sub
            Should -Invoke Connect-SISetupUser -Times 0
            $c.SignInMethod | Should -Be 'Support'
            $c.Account.Id | Should -Be 'support-app-id'
            $c.Account.Type | Should -Be 'ServicePrincipal'
            $c.Tenant.Id | Should -Be $script:Tid
            $c.Subscription.Id | Should -Be $script:Sub
            $c.Subscription.Name | Should -Be 'Sub One'
            $global:FakeSupportCalls.Count | Should -Be 0 -Because 'no token is asked for to say who is signed in'
            # the object id is found only when asked: from the session's own token
            Get-SISetupSignedInObjectId | Should -Be '55555555-5555-5555-5555-555555555555'
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'a support session for another tenant than -TenantId: refused, no browser' {
            Install-FakeSupport
            Mock Connect-SISetupUser { throw 'a browser must not be opened' }
            { Connect-SISetupAzure -TenantId $script:Other } | Should -Throw '*refused*'
            Should -Invoke Connect-SISetupUser -Times 0
            (Get-SIAzRestState).Connection | Should -BeNullOrEmpty
        }
        It 'no support session: the person signs in through SI''s own client; an Az PowerShell session is not borrowed' {
            Install-FakeAzSession
            Mock Connect-SISetupUser { [pscustomobject]@{ Account = 'me@contoso.example'; TenantId = $script:Tid; ObjectId = 'o'; Method = 'Browser' } }
            $c = Connect-SISetupAzure -TenantId $script:Tid
            Should -Invoke Connect-SISetupUser -Times 1
            $c.SignInMethod | Should -Be 'Browser'
            $global:FakeAzCalls.Count | Should -Be 0
        }
        It 'an explicit app or managed identity sign-in beside an open support session is REFUSED (it would not be recorded there)' {
            Install-FakeSupport
            Initialize-SIAzRestHelpers
            Mock Get-SILogIngestToken { 'tok-' + $Auth.Mode + '-' + $Auth.AppId }
            { Connect-SISetupAzure -TenantId $script:Tid -ApplicationId 'app-1' -ClientSecret 's3cret' } | Should -Throw '*Support session for test-env is open*would not be recorded*refused*Disconnect-InvardiaSupport*'
            { Connect-SISetupAzure -Identity } | Should -Throw '*a managed identity*refused*'
            Should -Invoke Get-SILogIngestToken -Times 0 -Exactly
        }
        It 'without a support session an explicit app (client secret) signs in as before' {
            Initialize-SIAzRestHelpers
            Mock Get-SILogIngestToken { 'tok-' + $Auth.Mode + '-' + $Auth.AppId }
            $c = Connect-SISetupAzure -TenantId $script:Tid -ApplicationId 'app-1' -ClientSecret 's3cret'
            $c.SignInMethod | Should -Be 'Secret'
            Should -Invoke Get-SILogIngestToken -Times 1 -ParameterFilter { $Auth.Mode -eq 'Secret' -and $Auth.AppId -eq 'app-1' }
        }
        It 'SI_AuthMethod = AzContext: refused with the supported sign-ins -- no browser' {
            $global:SI_AuthMethod = 'AzContext'
            Mock Connect-SISetupUser { throw 'a browser must not be opened' }
            { Connect-SISetupAzure -TenantId $script:Tid } | Should -Throw '*no longer supported*'
            Should -Invoke Connect-SISetupUser -Times 0
        }
    }

    Context 'nothing shipped borrows a session' {
        It 'engine/_shared/SI-AzSession.ps1 is gone' {
            Test-Path -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-AzSession.ps1') | Should -BeFalse
        }
        It 'no shipped script calls a session command; the support session''s state is read in ONE file (SI-AzRest.ps1, Get-SISupportSession)' {
            $files = @(foreach ($d in 'engine', 'launcher', 'container', 'auth', 'setup') { Get-ChildItem -LiteralPath (Join-Path $script:SIRoot $d) -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' } })
            $files += @(Get-ChildItem -LiteralPath $script:SIRoot -File | Where-Object { $_.Extension -in '.ps1', '.psm1' })
            $hits = @(foreach ($fi in $files) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($fi.FullName, [ref]$null, [ref]$null)
                $calls = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -in 'Get-AzAccessToken', 'Get-AzContext', 'Connect-AzAccount', 'Connect-MgGraph', 'Get-MgContext', 'Connect-InvardiaSupport', 'Get-SIAzSessionAuth', 'Get-SIAzSessionToken' }, $true))
                $vars = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.VariableExpressionAst] -and $args[0].VariablePath.UserPath -match '^(global:)?InvardiaSupportState$' }, $true))
                if ($calls.Count -or ($vars.Count -and $fi.Name -ne 'SI-AzRest.ps1')) { $fi.FullName.Substring($script:SIRoot.Length + 1) }
            })
            $hits | Should -BeNullOrEmpty
            # and in that file by NAME only, inside Get-SISupportSession (Get-Variable -Name InvardiaSupportState): one read
            $azRest = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-AzRest.ps1'))
            @([regex]::Matches($azRest, '-Name InvardiaSupportState\b')).Count | Should -Be 1
            # the token source is used in exactly one place: SI-AzRest.ps1's Get-SISupportToken
            $users = @(foreach ($fi in $files) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($fi.FullName, [ref]$null, [ref]$null)
                if (@($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -eq 'Get-InvardiaSupportToken' }, $true)).Count) { $fi.Name }
            })
            $users | Should -Be @('SI-AzRest.ps1')
        }
    }
}

Describe 'setup shows no noise from expected lookups (live 2026-10-06, guided install through Invardia Support)' {
    # The guided install shows EVERY new $Error entry (Invoke-SIInstallAz). Two kinds of expected lookup filled the
    # transcript: "Cannot find a variable with the name 'SI_TokenProvider' / 'SI_AuthMethod'", and "(404) Not Found"
    # from each "does it exist?" probe. Neither is an error of the process; neither may reach $Error any more.
    It 'an unset SI_AuthMethod / SI_TokenProvider adds nothing to $Error' {
        Remove-Variable -Scope Global -Name SI_AuthMethod, SI_TokenProvider -ErrorAction Ignore
        $global:Error.Clear()   # $Error holds at most 256: the count is taken from empty
        $before = $global:Error.Count
        $null = Get-SIAzRestValue 'SI_NoSuchSettingXyz'
        try { $null = Get-SIAzureToken -Resource 'https://vault.azure.net' } catch { $global:Error.RemoveAt(0) }   # no sign-in here: that throw is expected
        $global:Error.Count | Should -Be $before
    }
    It 'no Get-Variable / Get-Command lookup in the REST, session or ingest layer records a missing name' {
        foreach ($n in 'engine\_shared\SI-AzRest.ps1', 'engine\_shared\SI-LogIngest.ps1', 'setup\_shared\SI-SetupAzure.ps1', 'setup\_shared\SI-SetupSignIn.ps1') {
            $bad = @(Get-Content -LiteralPath (Join-Path $script:SIRoot $n) | Where-Object { $_ -match 'Get-(Variable|Command)\b' -and $_ -match '-ErrorAction SilentlyContinue' })
            $bad | Should -BeNullOrEmpty -Because "$n records the missing name in `$Error with SilentlyContinue (use Ignore)"
        }
    }
    It 'a real HTTP 404 is returned as a status and leaves $Error as it was (both editions)' {
        $port = Get-Random -Minimum 20000 -Maximum 40000
        $prefix = "http://127.0.0.1:$port/"
        $ps = [powershell]::Create()
        [void]$ps.AddScript({
            param($prefix)
            $l = New-Object System.Net.HttpListener; $l.Prefixes.Add($prefix); $l.Start()
            try { $ctx = $l.GetContext(); $ctx.Response.StatusCode = 404; $b = [Text.Encoding]::UTF8.GetBytes('{"error":{"code":"SecretNotFound"}}')
                  $ctx.Response.OutputStream.Write($b, 0, $b.Length); $ctx.Response.Close(); Start-Sleep -Seconds 3 } finally { $l.Stop() }
        }).AddArgument($prefix)
        $null = $ps.BeginInvoke()
        try {
            Start-Sleep -Milliseconds 500
            $global:Error.Clear()
            $before = $global:Error.Count
            $r = Invoke-SIAzRestHttp -Method GET -Uri ($prefix + 'secrets/x') -TimeoutSec 10
            $r.StatusCode | Should -Be 404
            $r.Content | Should -Match 'SecretNotFound'
            $global:Error.Count | Should -Be $before
        } finally { try { $ps.Stop() } catch { }; $ps.Dispose() }
    }
    It 'a handled record is taken out of $Error; anything else is left alone' {
        $global:Error.Clear()
        try { [int]::Parse('x') } catch { $rec = $_ }
        $before = $global:Error.Count
        Remove-SIAzRestCaughtError -Record ([System.Management.Automation.ErrorRecord]::new([Exception]::new('other'), 'x', 'NotSpecified', $null))
        $global:Error.Count | Should -Be $before
        Remove-SIAzRestCaughtError -Record $rec
        $global:Error.Count | Should -Be ($before - 1)
    }
}

Describe 'an expected not-found in a create-if-missing probe is one info line, not an error block (finding H)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstall.ps1')
    }
    It 'Get-SISqlServer / Get-SISqlDatabase "not found yet": no error record printed, one [INFO] line each' {
        Mock Get-SISetupSubscriptionId { '22222222-2222-2222-2222-222222222222' }
        Mock Invoke-SIArm { $null }
        $global:Error.Clear()   # $Error holds at most 256: the count is taken from empty
        $lines = New-Object System.Collections.Generic.List[string]
        $seams = Get-SIInstallDefaultSeams
        $seams['Print'] = { param($t, $c) $lines.Add([string]$t) }.GetNewClosure()
        $ctx = @{ Seams = $seams; StateDirectory = $null }
        $srv = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlServer' -Arguments ([ordered]@{ ResourceGroupName = 'rg'; ServerName = 'sql-x'; ErrorAction = 'SilentlyContinue' })
        $db = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISqlDatabase' -Arguments ([ordered]@{ ResourceGroupName = 'rg'; ServerName = 'sql-x'; DatabaseName = 'db-x'; ErrorAction = 'SilentlyContinue' })
        $srv | Should -BeNullOrEmpty
        $db | Should -BeNullOrEmpty
        $lines.Count | Should -Be 2
        $lines[0] | Should -Match '^\s*\[INFO\] The SQL server ''sql-x'' was not found'
        $lines[1] | Should -Match '^\s*\[INFO\] The database ''db-x'' was not found'
        ($lines -join "`n") | Should -Not -Match 'stack|error    :|context  :'
    }
    It 'any other swallowed error is still shown in full' {
        $global:Error.Clear()   # $Error holds at most 256: the count is taken from empty
        $lines = New-Object System.Collections.Generic.List[string]
        $seams = Get-SIInstallDefaultSeams
        $seams['Print'] = { param($t, $c) $lines.Add([string]$t) }.GetNewClosure()
        $seams['Az'] = { param($Command, $Arguments) Write-Error -Message 'something real broke' -ErrorAction SilentlyContinue }
        $ctx = @{ Seams = $seams; StateDirectory = $null }
        $null = Invoke-SIInstallAz -Ctx $ctx -Command 'Get-SISomething' -Arguments @{}
        ($lines -join "`n") | Should -Match 'error    : .*something real broke'
    }
}
