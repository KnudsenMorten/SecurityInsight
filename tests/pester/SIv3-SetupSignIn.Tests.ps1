#Requires -Version 5.1
<#
    SETUP SIGN-IN WITHOUT POWERSHELL MODULES (#305) -- setup/_shared/SI-SetupSignIn.ps1 + SI-SetupAzure.ps1.

      * PKCE (RFC 7636 S256): verifier shape, the challenge of a known verifier (cross-checked with openssl), fresh
        values every time; the authorize URL; the browser's redirect (code, state check, Entra errors)
      * the loopback listener: a REAL HttpListener round trip on localhost (a favicon probe is ignored, the redirect
        is answered with a page), and the timeout
      * the browser sign-in end to end against a fake Entra: the code exchange carries the verifier that matches the
        challenge in the URL and the same redirect URI; other resources come from the refresh token (rotated);
        tokens are cached in memory; Invoke-SIArm and Graph run as the signed-in person
      * Azure Cloud Shell: the token endpoint (POST, Metadata: true, resource=...), per resource; a Cloud Shell in
        another tenant is refused in customer language
      * an app (client secret) through Connect-SISetupAzure: proven at once, a wrong secret fails there; a sign-in
        is reused, not repeated
      * no device code, nothing written to disk
    Offline: every HTTP call goes through Invoke-SIAzRestHttp (mocked), the browser through Open-SISignInBrowser.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:GlobalNames = 'SI_AzureAccess_Engine', 'SI_LogIngest_Engine', 'SI_AzRestState', 'SI_LogIngestRunCache', 'SI_SetupSignInState',
                          'SI_SetupSignInClientId', 'SI_SPN_AppId', 'SI_SPN_TenantId', 'SI_SPN_Secret', 'SI_SPN_CertThumbprint', 'SI_UseManagedIdentity',
                          'UseManagedIdentity', 'SI_AzSubscriptionId', 'SI_WorkspaceResourceId', 'SubscriptionId', 'SpnClientId', 'SpnTenantId',
                          'SpnClientSecret', 'HighPriv_Modern_ApplicationID_Azure', 'HighPriv_Modern_TenantID', 'HighPriv_Modern_Secret_Azure',
                          'HighPriv_Modern_ApplicationSecret_Azure', 'HighPriv_Modern_CertificateThumbprint_Azure', 'AzureTenantId', 'TenantId'
    $script:keepAll = @{}
    foreach ($n in $script:GlobalNames) { $script:keepAll[$n] = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
    $script:hadGlobalToken = [bool](Get-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')

    function script:New-FakeJwt([hashtable]$Claims) {
        $enc = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        '{0}.{1}.sig' -f (& $enc '{"alg":"none"}'), (& $enc ($Claims | ConvertTo-Json -Compress))
    }
    function script:Resp([int]$Code, $Obj) {
        $c = if ($Obj -is [string]) { $Obj } else { $Obj | ConvertTo-Json -Depth 20 -Compress }
        [pscustomobject]@{ StatusCode = $Code; Content = $c; Bytes = $null; Headers = @{}; RetryAfter = '' }
    }
    function script:Form([string]$Body) { ConvertFrom-SIQueryString -Query $Body }
}

AfterAll {
    foreach ($n in $script:GlobalNames) { Set-Variable -Scope Global -Name $n -Value $script:keepAll[$n] }
    if (-not $script:hadGlobalToken) { Remove-Item -Path 'function:global:Get-SIAzureToken' -ErrorAction SilentlyContinue }
}

Describe 'PKCE, state, the authorize URL and the redirect' {
    It 'a verifier is 43 unreserved characters and fresh every time; the challenge is S256 of it' {
        $a = New-SIPkcePair; $b = New-SIPkcePair
        $a.Verifier | Should -Match '^[A-Za-z0-9\-_]{43}$'
        $a.Verifier | Should -Not -Be $b.Verifier
        $a.Method | Should -Be 'S256'
        $a.Challenge | Should -Be (Get-SIPkceChallenge -Verifier $a.Verifier)
        $a.Challenge | Should -Match '^[A-Za-z0-9\-_]{43}$'   # base64url, no padding
    }
    It 'the challenge of a known verifier is the SHA-256 openssl computes (base64url, no padding)' {
        # printf '%s' dBjftJeZ4CVP-mJ92K27uhbUJU1p1r-wW1gFWFOEjXk | openssl dgst -sha256 -binary | openssl base64
        Get-SIPkceChallenge -Verifier 'dBjftJeZ4CVP-mJ92K27uhbUJU1p1r-wW1gFWFOEjXk' | Should -BeExactly '6Y3vkOgSwz2skbRkaUT_UFe6JaIeTED0E2ZNnarAPDM'
    }
    It 'the authorize URL asks for a code with PKCE S256 on the loopback redirect; no tenant = organizations' {
        $u = Get-SIAuthorizeUrl -ClientId 'cid' -RedirectUri 'http://localhost:5555/' -Scope 'https://management.azure.com/.default offline_access' -CodeChallenge 'CH' -State 'ST' -LoginHint 'a@b.example'
        $u | Should -BeLike 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?*'
        $q = ConvertFrom-SIQueryString -Query ([uri]$u).Query
        $q['response_type'] | Should -Be 'code'
        $q['code_challenge'] | Should -Be 'CH'
        $q['code_challenge_method'] | Should -Be 'S256'
        $q['redirect_uri'] | Should -Be 'http://localhost:5555/'
        $q['state'] | Should -Be 'ST'
        $q['scope'] | Should -Be 'https://management.azure.com/.default offline_access'
        $q['login_hint'] | Should -Be 'a@b.example'
        (Get-SIAuthorizeUrl -TenantId 'tid-1' -ClientId 'c' -RedirectUri 'http://localhost:1/' -Scope 's' -CodeChallenge 'x' -State 'y') | Should -BeLike 'https://login.microsoftonline.com/tid-1/*'
    }
    It 'the redirect gives the code; a foreign state, an Entra error and a missing code are refused' {
        Resolve-SIAuthRedirect -Query '?code=abc%2B1&state=S1' -ExpectedState 'S1' | Should -BeExactly 'abc+1'
        { Resolve-SIAuthRedirect -Query '?code=abc&state=OTHER' -ExpectedState 'S1' } | Should -Throw '*did not belong to this sign-in*'
        { Resolve-SIAuthRedirect -Query '?error=access_denied&error_description=AADSTS65004%3A+User+declined&state=S1' -ExpectedState 'S1' } | Should -Throw '*access_denied*AADSTS65004*'
        { Resolve-SIAuthRedirect -Query '?state=S1' -ExpectedState 'S1' } | Should -Throw '*no authorization code*'
    }
    It 'the scope of a resource is <resource>/.default' {
        Get-SISignInScope -Resource 'https://graph.microsoft.com/' | Should -Be 'https://graph.microsoft.com/.default'
        Get-SISignInScope -Resource 'https://vault.azure.net' | Should -Be 'https://vault.azure.net/.default'
    }
}

Describe 'the loopback listener (a real HttpListener on localhost)' {
    It 'ignores a favicon probe, answers the redirect with a page and returns its query' {
        $port = Get-SIFreeLoopbackPort
        $l = New-Object System.Net.HttpListener
        $l.Prefixes.Add("http://localhost:$port/"); $l.Start()
        try {
            $probe = [System.Net.HttpWebRequest]::Create("http://localhost:$port/favicon.ico"); $probe.Timeout = 10000
            $pa = $probe.BeginGetResponse($null, $null)
            $req = [System.Net.HttpWebRequest]::Create("http://localhost:$port/?code=c-1&state=s-1"); $req.Timeout = 10000
            $ra = $req.BeginGetResponse($null, $null)
            $q = Wait-SILoopbackAuthCode -Port $port -Listener $l -TimeoutSec 20
            $q | Should -Be '?code=c-1&state=s-1'
            $resp = $req.EndGetResponse($ra)
            $sr = New-Object IO.StreamReader($resp.GetResponseStream()); $html = $sr.ReadToEnd(); $resp.Close()
            $html | Should -Match 'sign-in is complete'
            try { $probe.EndGetResponse($pa).Close() } catch { }
        } finally { $l.Stop(); $l.Close() }
    }
    It 'gives up after the timeout, in customer language' {
        $port = Get-SIFreeLoopbackPort
        { Wait-SILoopbackAuthCode -Port $port -TimeoutSec 1 } | Should -Throw '*No answer from the browser sign-in within 1 seconds*'
    }
}

Describe 'signing a person in' {
    BeforeEach {
        foreach ($n in $script:GlobalNames) { Remove-Variable -Scope Global -Name $n -ErrorAction SilentlyContinue }
        $global:SI_AzureAccess_Engine = 'Rest'
        $script:Env = @{}
        foreach ($e in 'AZUREPS_HOST_ENVIRONMENT', 'ACC_CLOUD', 'ACC_TERM_ID', 'MSI_ENDPOINT', 'IDENTITY_ENDPOINT') { $script:Env[$e] = [Environment]::GetEnvironmentVariable($e); [Environment]::SetEnvironmentVariable($e, $null) }
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        $script:Opened = $null
        $script:Handler = $null
        Mock Invoke-SIAzRestHttp {
            $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Body = [string]$Body; ContentType = $ContentType })
            if ($script:Handler) { $r = & $script:Handler $Method $Uri $Headers ([string]$Body); if ($r) { return $r } }
            return (Resp 404 '{"error":{"code":"NotFound"}}')
        }
        # the app sign-in (client secret) posts through the ingestion layer's own HTTP seam: the same fake answers it
        Mock Invoke-SILogIngestHttp {
            $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Body = [string]$Body; ContentType = $ContentType })
            if ($script:Handler) { $r = & $script:Handler $Method $Uri $Headers ([string]$Body); if ($r) { return $r } }
            return (Resp 404 '{"error":{"code":"NotFound"}}')
        }
        # the browser path needs an interactive session; the gate on the test VM runs over SSH (never interactive)
        Mock Test-SISignInInteractive { $true }
        Mock Open-SISignInBrowser { $script:Opened = $Url; $true }
        Mock Wait-SILoopbackAuthCode {
            $q = ConvertFrom-SIQueryString -Query ([uri]$script:Opened).Query
            '?code=the-code&state=' + [uri]::EscapeDataString($q['state'])
        }
        Mock Write-Host { }
        Mock Start-Sleep { }
        $script:ArmTok   = New-FakeJwt @{ tid = 'tid-1'; upn = 'admin@contoso.example'; oid = 'oid-1'; aud = 'https://management.azure.com/'; scp = 'user_impersonation' }
        $script:GraphTok = New-FakeJwt @{ tid = 'tid-1'; upn = 'admin@contoso.example'; oid = 'oid-1'; aud = 'https://graph.microsoft.com'; scp = 'Directory.AccessAsUser.All' }
    }
    AfterEach {
        foreach ($e in $script:Env.Keys) { [Environment]::SetEnvironmentVariable($e, $script:Env[$e]) }
        Disconnect-SISetupAzure
    }

    It 'a session that cannot open a browser (a service, SSH) is told how to sign in instead -- no browser, no token call' {
        Mock Test-SISignInInteractive { $false }
        { Connect-SISetupUser -TenantId 'tid-1' -Method Browser } | Should -Throw '*cannot open a browser*Cloud Shell*'
        Should -Invoke Open-SISignInBrowser -Times 0 -Exactly
        $script:Calls.Count | Should -Be 0
    }
    It 'browser: the code exchange carries the verifier of the URL''s challenge and the same redirect; Graph comes from the refresh token' {
        $script:Handler = {
            param($m, $u, $h, $b)
            $f = Form $b
            if ($u -like 'https://login.microsoftonline.com/tid-1/oauth2/v2.0/token' -and $f['grant_type'] -eq 'authorization_code') { return (Resp 200 @{ access_token = $script:ArmTok; refresh_token = 'rt-1'; expires_in = 3600 }) }
            if ($u -like 'https://login.microsoftonline.com/tid-1/oauth2/v2.0/token' -and $f['grant_type'] -eq 'refresh_token') { return (Resp 200 @{ access_token = $script:GraphTok; refresh_token = 'rt-2'; expires_in = 3600 }) }
            if ($u -like 'https://management.azure.com/subscriptions/sub-1?*') { return (Resp 200 @{ subscriptionId = 'sub-1'; displayName = 'Production' }) }
        }
        $ctx = Connect-SISetupAzure -TenantId 'tid-1' -SubscriptionId 'sub-1' -UserSignIn Browser
        $ctx.Account.Id | Should -Be 'admin@contoso.example'
        $ctx.Account.Type | Should -Be 'User'
        $ctx.Account.ObjectId | Should -Be 'oid-1'
        $ctx.Tenant.Id | Should -Be 'tid-1'
        $ctx.Subscription.Id | Should -Be 'sub-1'
        $ctx.Subscription.Name | Should -Be 'Production'
        $ctx.SignInMethod | Should -Be 'Browser'

        $url = ConvertFrom-SIQueryString -Query ([uri]$script:Opened).Query
        $url['client_id'] | Should -Be '1950a258-227b-4e31-a9cf-717495945fc2'
        $url['redirect_uri'] | Should -Match '^http://localhost:\d+/$'
        $url['scope'] | Should -Match 'offline_access'
        $x = Form (@($script:Calls | Where-Object { $_.Body -match 'grant_type=authorization_code' })[0].Body)
        $x['code'] | Should -Be 'the-code'
        $x['redirect_uri'] | Should -Be $url['redirect_uri']
        Get-SIPkceChallenge -Verifier $x['code_verifier'] | Should -Be $url['code_challenge']

        Get-SIAzureToken -Audience Graph | Should -Be $script:GraphTok
        $rf = Form (@($script:Calls | Where-Object { $_.Body -match 'grant_type=refresh_token' })[0].Body)
        $rf['refresh_token'] | Should -Be 'rt-1'
        $rf['scope'] | Should -Be 'https://graph.microsoft.com/.default offline_access'
        (Get-SISignInState).Session.RefreshToken | Should -Be 'rt-2'   # rotated
        $n = $script:Calls.Count
        Get-SIAzureToken -Audience Graph | Should -Be $script:GraphTok   # memory cache
        $script:Calls.Count | Should -Be $n
        $null = Get-SIAzureToken -Audience Graph -ForceRefresh
        (Form $script:Calls[-1].Body)['refresh_token'] | Should -Be 'rt-2'
    }

    It 'browser: Invoke-SIArm runs as the signed-in person (the ARM token of the code exchange)' {
        $script:Handler = {
            param($m, $u, $h, $b)
            if ($u -like 'https://login.microsoftonline.com/*') { return (Resp 200 @{ access_token = $script:ArmTok; refresh_token = 'rt-1'; expires_in = 3600 }) }
            if ($u -like 'https://management.azure.com/subscriptions/sub-1/resourcegroups/rg-x?*') { return (Resp 200 @{ name = 'rg-x'; location = 'westeurope'; id = '/subscriptions/sub-1/resourceGroups/rg-x' }) }
            if ($u -like 'https://management.azure.com/subscriptions/sub-1?*') { return (Resp 200 @{ displayName = 'S' }) }
        }
        $null = Connect-SISetupAzure -TenantId 'tid-1' -SubscriptionId 'sub-1' -UserSignIn Browser
        (Get-SIAzResourceGroup -Name 'rg-x').ResourceGroupName | Should -Be 'rg-x'
        $armCall = @($script:Calls | Where-Object { $_.Uri -like '*resourcegroups/rg-x*' })[0]
        $armCall.Headers['Authorization'] | Should -Be ('Bearer ' + $script:ArmTok)
    }

    It 'a second Connect-SISetupAzure reuses the sign-in (no second browser); -Force signs in again' {
        $script:Handler = { param($m, $u, $h, $b) if ($u -like 'https://login.microsoftonline.com/*') { return (Resp 200 @{ access_token = $script:ArmTok; refresh_token = 'rt-1'; expires_in = 3600 }) } }
        $null = Connect-SISetupAzure -TenantId 'tid-1' -UserSignIn Browser
        $null = Connect-SISetupAzure -TenantId 'tid-1' -UserSignIn Browser
        Should -Invoke Open-SISignInBrowser -Times 1 -Exactly
        $null = Connect-SISetupAzure -TenantId 'tid-1' -UserSignIn Browser -Force
        Should -Invoke Open-SISignInBrowser -Times 2 -Exactly
    }

    It 'an Entra error at the code exchange is shown in a sentence' {
        $script:Handler = { param($m, $u, $h, $b) if ($u -like 'https://login.microsoftonline.com/*') { return (Resp 400 @{ error = 'invalid_grant'; error_description = "AADSTS50126: Error validating credentials.`r`nTrace ID: x" }) } }
        { Connect-SISetupAzure -TenantId 'tid-1' -UserSignIn Browser } | Should -Throw '*The Azure sign-in failed (HTTP 400): AADSTS50126: Error validating credentials.'
    }

    It 'Azure Cloud Shell: tokens per resource from the Cloud Shell endpoint, no browser' {
        [Environment]::SetEnvironmentVariable('AZUREPS_HOST_ENVIRONMENT', 'cloud-shell/1.0')
        [Environment]::SetEnvironmentVariable('MSI_ENDPOINT', 'http://localhost:50342/oauth2/token')
        $exp = [DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()
        $script:Handler = {
            param($m, $u, $h, $b)
            if ($u -eq 'http://localhost:50342/oauth2/token') {
                $res = (Form $b)['resource']
                $t = if ($res -eq 'https://graph.microsoft.com/') { $script:GraphTok } else { $script:ArmTok }
                return (Resp 200 @{ access_token = $t; expires_on = [string]$exp; resource = $res; token_type = 'Bearer' })
            }
        }
        Test-SICloudShell | Should -BeTrue
        $ctx = Connect-SISetupAzure -TenantId 'tid-1'
        $ctx.SignInMethod | Should -Be 'CloudShell'
        $ctx.Account.Id | Should -Be 'admin@contoso.example'
        Should -Invoke Open-SISignInBrowser -Times 0 -Exactly
        $c = $script:Calls[0]
        $c.Method | Should -Be 'POST'
        $c.Headers['Metadata'] | Should -Be 'true'
        (Form $c.Body)['resource'] | Should -Be 'https://management.azure.com/'
        Get-SIAzureToken -Audience Graph | Should -Be $script:GraphTok
        (Form $script:Calls[-1].Body)['resource'] | Should -Be 'https://graph.microsoft.com/'
    }

    It 'Azure Cloud Shell in another tenant is refused with what to do' {
        [Environment]::SetEnvironmentVariable('ACC_CLOUD', 'PROD')
        [Environment]::SetEnvironmentVariable('MSI_ENDPOINT', 'http://localhost:50342/oauth2/token')
        $script:Handler = { param($m, $u, $h, $b) return (Resp 200 @{ access_token = (New-FakeJwt @{ tid = 'other'; upn = 'x@y.example' }); expires_on = '0' }) }
        { Connect-SISetupAzure -TenantId 'tid-1' } | Should -Throw '*Cloud Shell is signed in to tenant other, but this needs tenant tid-1*Switch directory*'
    }

    It 'an app with a client secret is proven at once; a wrong secret fails there and leaves nobody signed in' {
        $script:Handler = {
            param($m, $u, $h, $b)
            if ($u -eq 'https://login.microsoftonline.com/tid-1/oauth2/v2.0/token') {
                if ((Form $b)['client_secret'] -eq 'good') { return (Resp 200 @{ access_token = (New-FakeJwt @{ tid = 'tid-1'; appid = 'app-1'; oid = 'sp-1' }); expires_in = 3600 }) }
                return (Resp 401 @{ error = 'invalid_client'; error_description = 'AADSTS7000215: Invalid client secret provided.' })
            }
        }
        { Connect-SISetupAzure -TenantId 'tid-1' -ApplicationId 'app-1' -ClientSecret 'bad' } | Should -Throw '*Signing in to Azure as app app-1 failed*'
        Get-SISetupAzureContext | Should -BeNullOrEmpty
        $ctx = Connect-SISetupAzure -TenantId 'tid-1' -ApplicationId 'app-1' -ClientSecret 'good' -SubscriptionId 'sub-9'
        $ctx.Account.Type | Should -Be 'ServicePrincipal'
        $ctx.Account.Id | Should -Be 'app-1'
        $ctx.Subscription.Id | Should -Be 'sub-9'
        Get-SISetupSignedInObjectId | Should -Be 'sp-1'
        (Form @($script:Calls | Where-Object { $_.Uri -like 'https://login.microsoftonline.com/*' })[-1].Body)['grant_type'] | Should -Be 'client_credentials'
    }
}

Describe 'what the sign-in never does' {
    BeforeAll {
        function script:CodeOf([string]$Rel) {
            $t = $null; $e = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot $Rel), [ref]$t, [ref]$e)
            (@($t | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
        }
    }
    It 'no device code flow anywhere in the setup sign-in' {
        foreach ($rel in 'setup\_shared\SI-SetupSignIn.ps1', 'setup\_shared\SI-SetupAzure.ps1') {
            CodeOf $rel | Should -Not -Match '(?i)devicecode|device_code|device-code'
        }
    }
    It 'tokens are kept in memory: the sign-in writes no file' {
        foreach ($rel in 'setup\_shared\SI-SetupSignIn.ps1', 'setup\_shared\SI-SetupAzure.ps1') {
            CodeOf $rel | Should -Not -Match '(?i)Set-Content|Out-File|Add-Content|WriteAll(Text|Bytes)|Export-Clixml'
        }
    }
    It 'the loopback listener is bound to localhost only' {
        CodeOf 'setup\_shared\SI-SetupSignIn.ps1' | Should -Match "http://localhost:\{0\}/"
        CodeOf 'setup\_shared\SI-SetupSignIn.ps1' | Should -Not -Match "http://(\+|\*|0\.0\.0\.0)"
    }
}
