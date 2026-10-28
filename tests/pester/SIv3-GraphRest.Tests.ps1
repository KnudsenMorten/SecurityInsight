#Requires -Version 5.1
<#
    MICROSOFT GRAPH OVER PLAIN REST -- setup (setup/_shared/SI-GraphRest.ps1) and asset tagging
    (engine/asset-tagging/_shared/AT-GraphRest.ps1), no Microsoft.Graph SDK.

    Everything runs against a FAKE HTTP seam ($SIGraphRestSend) and a fake token -- no network:
      * paging follows @odata.nextLink; 429 / 5xx / a dropped connection are retried (Retry-After honoured);
        a 401 refreshes the token once; anything else fails at once with Graph's own code and message;
      * the token comes from setup's own sign-in (Get-SIAzureToken); who is signed in is read from its claims;
      * the request of every call setup now makes: method, URL, headers, JSON body;
      * New-SISpn end to end on the fake Graph: the same objects created and the same permissions granted
        as with the SDK;
      * WIRING (AST): no -Mg* cmdlet, Connect-MgGraph or Invoke-MgGraphRequest left in engine/, setup/,
        launcher/, container/ (one documented exception), and the Graph SDK in no module list.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'setup\_shared\SI-GraphRest.ps1')

    function script:New-FakeJwt([hashtable]$Claims) {
        $enc = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
        '{0}.{1}.sig' -f (& $enc '{"alg":"none"}'), (& $enc ($Claims | ConvertTo-Json -Compress))
    }
    function script:Resp([int]$Status, $Object, $RetryAfter) {
        $body = if ($null -eq $Object) { '' } elseif ($Object -is [string]) { $Object } else { $Object | ConvertTo-Json -Depth 10 -Compress }
        @{ StatusCode = $Status; Body = $body; RetryAfter = $RetryAfter }
    }
    function script:BodyOf($Request) { if ($Request.Bytes) { [Text.Encoding]::UTF8.GetString($Request.Bytes) | ConvertFrom-Json } }

    # The seams the helper looks up -- by plain name, so they are found from inside a script (New-SISpn) too.
    # ALL state sits in ONE hashtable: `$script:` inside a scriptblock means the script that is RUNNING it
    # (New-SISpn, in the end-to-end test), not this file, so a `$script:` list would be a different one.
    $Fake = @{
        Requests = New-Object System.Collections.Generic.List[object]
        Replies  = New-Object System.Collections.Generic.Queue[object]
        Router   = $null
        Sleeps   = New-Object System.Collections.Generic.List[int]
        TokenCalls = 0
        RbacGranted = $false
    }
    $SIGraphRestSend = {
        param($Method, $Url, $Headers, $BodyBytes)
        $req = [pscustomobject]@{ Method = $Method; Url = $Url; Headers = $Headers; Bytes = $BodyBytes }
        $Fake.Requests.Add($req)
        if ($Fake.Router) { return (& $Fake.Router $req) }
        $r = $Fake.Replies.Dequeue()
        if ($r -is [scriptblock]) { return (& $r) }
        return $r
    }
    $SIGraphRestTokenSource = { $Fake.TokenCalls++; 'tok-' + $Fake.TokenCalls }
    $SIGraphRestSleep = { param($s) $Fake.Sleeps.Add([int]$s) }
    function script:Reset-Fake { $Fake.Requests.Clear(); $Fake.Replies.Clear(); $Fake.Sleeps.Clear(); $Fake.Router = $null; $Fake.TokenCalls = 0; $Fake.RbacGranted = $false }
}


Describe 'the transport: paging, retries, errors' {
    BeforeEach { Reset-Fake }
    It 'paging follows @odata.nextLink verbatim and returns every item of every page' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ id = 1 }, @{ id = 2 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/things?$skiptoken=A' }))
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ id = 3 }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/things?$skiptoken=B' }))
        $Fake.Replies.Enqueue((Resp 200 @{ value = @() }))
        $items = Invoke-SIGraphRequest -Uri '/v1.0/things' -All
        @($items | ForEach-Object { $_.id }) | Should -Be @(1, 2, 3)
        $Fake.Requests.Count | Should -Be 3
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/things'
        $Fake.Requests[1].Url | Should -Be 'https://graph.microsoft.com/v1.0/things?$skiptoken=A'
        $Fake.Requests[2].Url | Should -Be 'https://graph.microsoft.com/v1.0/things?$skiptoken=B'
    }
    It 'an empty page set is an empty array, not one empty item' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @() }))
        @(Invoke-SIGraphRequest -Uri '/v1.0/things' -All).Count | Should -Be 0
    }
    It '429 is retried after Retry-After seconds, then succeeds' {
        $Fake.Replies.Enqueue((Resp 429 @{ error = @{ code = 'TooManyRequests'; message = 'slow down' } } 7))
        $Fake.Replies.Enqueue((Resp 200 @{ ok = $true }))
        (Invoke-SIGraphRequest -Uri '/v1.0/x').ok | Should -BeTrue
        $Fake.Sleeps | Should -Be @(7)
    }
    It '5xx and a dropped connection are retried with backoff' {
        $Fake.Replies.Enqueue((Resp 503 ''))
        $Fake.Replies.Enqueue({ throw 'connection reset' })
        $Fake.Replies.Enqueue((Resp 502 ''))
        $Fake.Replies.Enqueue((Resp 200 @{ ok = 1 }))
        (Invoke-SIGraphRequest -Uri '/v1.0/x').ok | Should -Be 1
        $Fake.Requests.Count | Should -Be 4
        $Fake.Sleeps | Should -Be @(2, 4, 8)
    }
    It 'gives up after -MaxAttempts on a transient error and says so' {
        1..3 | ForEach-Object { $Fake.Replies.Enqueue((Resp 500 @{ error = @{ code = 'InternalServerError'; message = 'boom' } })) }
        { Invoke-SIGraphRequest -Uri '/v1.0/x' -MaxAttempts 3 } | Should -Throw '*HTTP 500 InternalServerError -- boom (after 3 attempts)*'
        $Fake.Requests.Count | Should -Be 3
    }
    It 'a 403 fails at once with Graph''s code and message (so setup''s permission hint still matches)' {
        $Fake.Replies.Enqueue((Resp 403 @{ error = @{ code = 'Authorization_RequestDenied'; message = 'Insufficient privileges to complete the operation.'; innerError = @{ 'request-id' = 'r-1' } } }))
        $err = $null
        try { Invoke-SIGraphRequest -Method POST -Uri '/v1.0/applications' -Body @{ displayName = 'x' } } catch { $err = $_.Exception.Message }
        $err | Should -BeLike 'Microsoft Graph POST /v1.0/applications failed: HTTP 403 Authorization_RequestDenied -- Insufficient privileges to complete the operation. (request-id r-1)'
        $err | Should -Match '(?i)403|Forbidden|Authorization_RequestDenied|Insufficient privileges'
        $Fake.Requests.Count | Should -Be 1
        $Fake.Sleeps.Count | Should -Be 0
    }
    It 'a 400 is not retried' {
        $Fake.Replies.Enqueue((Resp 400 @{ error = @{ code = 'Request_BadRequest'; message = 'Invalid filter clause' } }))
        { Invoke-SIGraphRequest -Uri '/v1.0/x' } | Should -Throw '*HTTP 400 Request_BadRequest -- Invalid filter clause'
        $Fake.Requests.Count | Should -Be 1
    }
    It 'a 401 refreshes the token once and retries' {
        $Fake.Replies.Enqueue((Resp 401 @{ error = @{ code = 'InvalidAuthenticationToken'; message = 'expired' } }))
        $Fake.Replies.Enqueue((Resp 200 @{ ok = 1 }))
        (Invoke-SIGraphRequest -Uri '/v1.0/x').ok | Should -Be 1
        $Fake.Requests[0].Headers.Authorization | Should -Be 'Bearer tok-1'
        $Fake.Requests[1].Headers.Authorization | Should -Be 'Bearer tok-2'
    }
    It 'bodies go as UTF-8 JSON bytes (non-ASCII intact); relative paths default to /v1.0; -Eventual adds ConsistencyLevel' {
        $Fake.Replies.Enqueue((Resp 201 @{ id = 'n' }))
        $name = 'SI ' + [char]0xE6 + [char]0xF8 + [char]0xE5
        $null = Invoke-SIGraphRequest -Method POST -Uri '/applications' -Body @{ displayName = $name } -Eventual
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/applications'
        $Fake.Requests[0].Headers.ConsistencyLevel | Should -Be 'eventual'
        (BodyOf $Fake.Requests[0]).displayName | Should -BeExactly $name
    }
}

Describe 'the token and the signed-in identity' {
    BeforeEach { Reset-Fake }
    It 'takes the Graph token from setup''s own sign-in (Get-SIAzureToken -Audience Graph), no Az module' {
        $SIGraphRestTokenSource = $null
        function Get-SISetupAzureContext { $null }
        function Get-SIAzureToken { param($Audience, $Resource, [switch]$ForceRefresh)
            $script:TokAsked = $Audience; $script:TokForced = [bool]$ForceRefresh
            (ConvertTo-SecureString 'plain-token' -AsPlainText -Force) }
        Get-SIGraphAccessToken -ForceRefresh | Should -BeExactly 'plain-token'
        $script:TokAsked | Should -Be 'Graph'
        $script:TokForced | Should -BeTrue
        ConvertFrom-SIGraphSecureToken -Token 'already-plain' | Should -BeExactly 'already-plain'
    }
    It 'reads a delegated sign-in (UPN, tenant, scopes) and an app-only sign-in (app id, roles) from the token' {
        $SIGraphRestTokenSource = { New-FakeJwt @{ tid = 't1'; upn = 'admin@contoso.example'; scp = 'Directory.AccessAsUser.All User.Read'; app_displayname = 'Azure PowerShell' } }
        $c = Get-SIGraphContext
        $c.Account | Should -Be 'admin@contoso.example'; $c.TenantId | Should -Be 't1'; $c.AuthType | Should -Be 'Delegated'
        $c.Scopes | Should -Contain 'Directory.AccessAsUser.All'
        $SIGraphRestTokenSource = { New-FakeJwt @{ tid = 't2'; appid = 'app-1'; roles = @('Application.ReadWrite.OwnedBy', 'AppRoleAssignment.ReadWrite.All') } }
        $a = Get-SIGraphContext
        $a.Account | Should -Be 'app-1'; $a.AuthType | Should -Be 'AppOnly'; $a.Scopes | Should -Contain 'Application.ReadWrite.OwnedBy'
    }
    It 'nobody signed in -> no context (callers then sign in)' {
        $SIGraphRestTokenSource = { throw 'no account' }
        $null -eq (Get-SIGraphContext) | Should -BeTrue
    }
    It 'missing permissions: the least-privilege equivalents count, a delegated Directory.AccessAsUser.All covers all' {
        $eq = @{ 'Application.ReadWrite.All' = @('Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy') }
        $req = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All')
        @(Get-SIGraphMissingScopes -Context ([pscustomobject]@{ AuthType = 'AppOnly'; Scopes = @('Application.ReadWrite.OwnedBy', 'AppRoleAssignment.ReadWrite.All') }) -Required $req -Equivalents $eq).Count | Should -Be 0
        @(Get-SIGraphMissingScopes -Context ([pscustomobject]@{ AuthType = 'AppOnly'; Scopes = @('Application.ReadWrite.OwnedBy') }) -Required $req -Equivalents $eq) | Should -Be @('AppRoleAssignment.ReadWrite.All')
        @(Get-SIGraphMissingScopes -Context ([pscustomobject]@{ AuthType = 'Delegated'; Scopes = @('Directory.AccessAsUser.All') }) -Required $req -Equivalents $eq).Count | Should -Be 0
        @(Get-SIGraphMissingScopes -Context ([pscustomobject]@{ AuthType = 'AppOnly'; Scopes = @('Directory.AccessAsUser.All') }) -Required $req -Equivalents $eq).Count | Should -Be 2
    }
}

Describe 'the request of every call setup makes' {
    BeforeEach { Reset-Fake }
    It 'Find-SIGraphServicePrincipal: GET /servicePrincipals filtered by appId (or display name, quotes escaped)' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ id = 'sp1'; appId = 'a1'; displayName = 'n' }) }))
        (Find-SIGraphServicePrincipal -AppId 'a1').id | Should -Be 'sp1'
        $Fake.Requests[0].Method | Should -Be 'GET'
        [uri]::UnescapeDataString($Fake.Requests[0].Url) | Should -Be "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq 'a1'"
        $Fake.Replies.Enqueue((Resp 200 @{ value = @() }))
        $null -eq (Find-SIGraphServicePrincipal -DisplayName "O'Brien SI") | Should -BeTrue
        [uri]::UnescapeDataString($Fake.Requests[1].Url) | Should -Be "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'O''Brien SI'"
    }
    It 'New-SIGraphServicePrincipal: POST /servicePrincipals { appId }' {
        $Fake.Replies.Enqueue((Resp 201 @{ id = 'sp2'; appId = 'a2' }))
        (New-SIGraphServicePrincipal -AppId 'a2').id | Should -Be 'sp2'
        $Fake.Requests[0].Method | Should -Be 'POST'; $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/servicePrincipals'
        (BodyOf $Fake.Requests[0]).appId | Should -Be 'a2'
    }
    It 'Find-SIGraphApplication: GET /applications filtered, with $count and ConsistencyLevel: eventual (as Get-MgApplication -ConsistencyLevel eventual)' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ id = 'o1'; appId = 'a1' }) }))
        (Find-SIGraphApplication -DisplayName 'SI (prod)').id | Should -Be 'o1'
        [uri]::UnescapeDataString($Fake.Requests[0].Url) | Should -Be "https://graph.microsoft.com/v1.0/applications?`$filter=displayName eq 'SI (prod)'&`$count=true"
        $Fake.Requests[0].Headers.ConsistencyLevel | Should -Be 'eventual'
    }
    It 'New-SIGraphApplication: POST /applications { displayName, signInAudience = AzureADMyOrg }' {
        $Fake.Replies.Enqueue((Resp 201 @{ id = 'o2'; appId = 'a3' }))
        $null = New-SIGraphApplication -DisplayName 'SI (prod)'
        $b = BodyOf $Fake.Requests[0]
        $b.displayName | Should -Be 'SI (prod)'; $b.signInAudience | Should -Be 'AzureADMyOrg'
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/applications'
    }
    It 'Add-SIGraphApplicationPassword: POST /applications/{id}/addPassword; the expiry comes back as a [datetime]' {
        $Fake.Replies.Enqueue((Resp 200 @{ secretText = 's3cr3t'; endDateTime = '2028-10-03T10:00:00Z'; keyId = 'k' }))
        $end = [datetime]::new(2028, 10, 3, 10, 0, 0, [DateTimeKind]::Utc)
        $p = Add-SIGraphApplicationPassword -ApplicationObjectId 'o1' -DisplayName 'SI-Wizard-1' -EndDateTime $end
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/applications/o1/addPassword'
        $b = BodyOf $Fake.Requests[0]
        $b.passwordCredential.displayName | Should -Be 'SI-Wizard-1'
        ([datetime]$b.passwordCredential.endDateTime).ToUniversalTime() | Should -Be $end
        $p.SecretText | Should -BeExactly 's3cr3t'
        $p.EndDateTime | Should -BeOfType [datetime]
        $p.EndDateTime.ToUniversalTime() | Should -Be $end
    }
    It 'Set-SIGraphApplicationCertificate: PATCH /applications/{id} with one keyCredential (base64 key, ISO dates)' {
        $Fake.Replies.Enqueue((Resp 204 $null))
        $bytes = [byte[]](1, 2, 3, 250)
        Set-SIGraphApplicationCertificate -ApplicationObjectId 'o1' -CertificateBytes $bytes -DisplayName 'SI-Wizard-2' `
            -StartDateTime ([datetime]'2026-10-03T00:00:00Z') -EndDateTime ([datetime]'2028-10-03T00:00:00Z')
        $Fake.Requests[0].Method | Should -Be 'PATCH'
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/applications/o1'
        $raw = [Text.Encoding]::UTF8.GetString($Fake.Requests[0].Bytes)
        $raw | Should -Match '"keyCredentials":\['
        $kc = @((BodyOf $Fake.Requests[0]).keyCredentials)
        $kc.Count | Should -Be 1
        $kc[0].type | Should -Be 'AsymmetricX509Cert'; $kc[0].usage | Should -Be 'Verify'
        $kc[0].key | Should -Be ([Convert]::ToBase64String($bytes))
        $raw | Should -Match '"startDateTime":"2026-10-03T00:00:00\.0000000Z"'
    }
    It 'Get-SIGraphKeyCredentialThumbprint reads customKeyIdentifier as base64 (REST) or bytes (SDK)' {
        $b = [byte[]](0xAB, 0x01, 0xFF)
        Get-SIGraphKeyCredentialThumbprint -KeyCredential ([pscustomobject]@{ customKeyIdentifier = [Convert]::ToBase64String($b) }) | Should -Be 'AB01FF'
        Get-SIGraphKeyCredentialThumbprint -KeyCredential ([pscustomobject]@{ customKeyIdentifier = $b }) | Should -Be 'AB01FF'
        $null -eq (Get-SIGraphKeyCredentialThumbprint -KeyCredential ([pscustomobject]@{ customKeyIdentifier = $null })) | Should -BeTrue
    }
    It 'Get-SIGraphAppRoleAssignments: every page of /servicePrincipals/{id}/appRoleAssignments' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ appRoleId = 'r1'; resourceId = 'g' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp1/appRoleAssignments?$skiptoken=X' }))
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ appRoleId = 'r2'; resourceId = 'g' }) }))
        @(Get-SIGraphAppRoleAssignments -ServicePrincipalId 'sp1' | ForEach-Object { $_.appRoleId }) | Should -Be @('r1', 'r2')
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/servicePrincipals/sp1/appRoleAssignments'
    }
    It 'New-SIGraphAppRoleAssignment: POST /servicePrincipals/{id}/appRoleAssignments { principalId, resourceId, appRoleId }' {
        $Fake.Replies.Enqueue((Resp 201 @{ id = 'as1' }))
        $null = New-SIGraphAppRoleAssignment -ServicePrincipalId 'sp1' -ResourceId 'graphSp' -AppRoleId 'role-1'
        $Fake.Requests[0].Url | Should -Be 'https://graph.microsoft.com/v1.0/servicePrincipals/sp1/appRoleAssignments'
        $b = BodyOf $Fake.Requests[0]
        $b.principalId | Should -Be 'sp1'; $b.resourceId | Should -Be 'graphSp'; $b.appRoleId | Should -Be 'role-1'
    }
    It 'Get-SIGraphUserDirectoryRoleNames: the user by UPN, then its memberOf (all pages), directory roles only' {
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ id = 'u1' }) }))
        $Fake.Replies.Enqueue((Resp 200 @{ value = @(@{ '@odata.type' = '#microsoft.graph.directoryRole'; displayName = 'Global Administrator' }, @{ '@odata.type' = '#microsoft.graph.group'; displayName = 'g' }) }))
        @(Get-SIGraphUserDirectoryRoleNames -UserPrincipalName 'admin@contoso.example') | Should -Be @('Global Administrator')
        [uri]::UnescapeDataString($Fake.Requests[0].Url) | Should -Be "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq 'admin@contoso.example'"
        $Fake.Requests[1].Url | Should -Be 'https://graph.microsoft.com/v1.0/users/u1/memberOf'
    }
}

Describe 'New-SISpn end to end on a fake Graph: the same objects, the same permissions' {
    BeforeEach { Reset-Fake }
    BeforeAll {
        $Fake.GraphRoles = @(
            'ThreatHunting.Read.All', 'Device.Read.All', 'User.Read.All', 'Application.Read.All', 'Group.Read.All', 'Policy.Read.All',
            'AuditLog.Read.All', 'IdentityRiskEvent.Read.All', 'IdentityRiskyUser.Read.All', 'IdentityRiskyServicePrincipal.Read.All',
            'Directory.Read.All', 'RoleManagement.Read.All', 'RoleManagementPolicy.Read.Directory', 'RoleEligibilitySchedule.Read.Directory',
            'RoleAssignmentSchedule.Read.Directory', 'PrivilegedAccess.Read.AzureADGroup', 'RoleManagement.Read.Directory',
            'UserAuthenticationMethod.Read.All'
        ) | ForEach-Object { @{ id = ('g-' + $_); value = $_; allowedMemberTypes = @('Application') } }
        $script:Spn = Join-Path $script:SIRoot 'setup\ConfigWizard\backend\New-SISpn.ps1'
    }
    It 'creates the app, its service principal and a secret, and grants every Graph, MTP and MDE permission' {
        $SIGraphRestTokenSource = { New-FakeJwt @{ tid = 'tenant-1'; upn = 'admin@contoso.example'; scp = 'Directory.AccessAsUser.All'; app_displayname = 'Azure PowerShell' } }
        $Fake.Router = {
            param($r)
            $u = [uri]::UnescapeDataString($r.Url)
            switch -Regex ("$($r.Method) $u") {
                "^GET .*/applications\?\`$filter=displayName eq 'SecurityInsight \(test\)'" { return (Resp 200 @{ value = @() }) }
                '^POST .*/v1\.0/applications$'                       { return (Resp 201 @{ id = 'app-obj'; appId = 'app-id'; displayName = 'SecurityInsight (test)' }) }
                "^GET .*/servicePrincipals\?\`$filter=appId eq 'app-id'" { return (Resp 200 @{ value = @() }) }
                '^POST .*/v1\.0/servicePrincipals$'                  { return (Resp 201 @{ id = 'sp-obj'; appId = 'app-id' }) }
                '^POST .*/applications/app-obj/addPassword$'         { return (Resp 200 @{ secretText = 'new-secret'; endDateTime = '2028-10-03T10:00:00Z' }) }
                "^GET .*appId eq '00000003-0000-0000-c000-000000000000'" { return (Resp 200 @{ value = @(@{ id = 'graph-sp'; appRoles = $Fake.GraphRoles }) }) }
                "^GET .*appId eq '8ee8fdad-f234-4243-8f3b-15c294843740'" { return (Resp 200 @{ value = @(@{ id = 'mtp-sp'; appRoles = @(@{ id = 'mtp-r'; value = 'AdvancedHunting.Read.All'; allowedMemberTypes = @('Application') }) }) }) }
                "^GET .*appId eq 'fc780465-2017-40d4-a0c5-307022471b92'" { return (Resp 200 @{ value = @(@{ id = 'mde-sp'; appRoles = @(@{ id = 'mde-r'; value = 'Machine.Read.All'; allowedMemberTypes = @('Application') }, @{ id = 'mde-v'; value = 'Vulnerability.Read.All'; allowedMemberTypes = @('Application') }, @{ id = 'mde-s'; value = 'SecurityRecommendation.Read.All'; allowedMemberTypes = @('Application') }) }) }) }
                '^GET .*/servicePrincipals/sp-obj/appRoleAssignments$' { return (Resp 200 @{ value = @(@{ appRoleId = 'g-User.Read.All'; resourceId = 'graph-sp' }) }) }
                '^POST .*/servicePrincipals/sp-obj/appRoleAssignments$' { return (Resp 201 @{ id = 'as' }) }
                default { throw "unexpected request: $($r.Method) $u" }
            }
        }
        # Azure REST stubs (the setup sign-in and role assignments): the RBAC half is not what this test is about.
        # Defined here, so New-SISpn finds them and does not load the REST layer itself.
        function Get-SISetupAzureContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = 'sub-1'; Name = 'sub' }; Account = [pscustomobject]@{ Id = 'admin@contoso.example'; Type = 'User' } } }
        function Get-SIAzRoleAssignment { $null }
        function New-SIRoleAssignment { $Fake.RbacGranted = $true }
        function Set-SIAzContext { }

        $out = & $script:Spn -DisplayName 'SecurityInsight (test)' -TenantId 'tenant-1' -SubscriptionId 'sub-1' -CredKind Secret -CredStorage Inline -SkipTenantRbac 6>$null
        $out = @($out)[-1]

        $out.AppId | Should -Be 'app-id'
        $out.ObjectId | Should -Be 'sp-obj'
        $out.CredValue | Should -BeExactly 'new-secret'
        $out.ExpiresUtc | Should -Be ([datetime]::new(2028, 10, 3, 10, 0, 0, [DateTimeKind]::Utc))
        $out.ConsentStatus | Should -Be 'granted'

        $grants = @($Fake.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Url -like '*/servicePrincipals/sp-obj/appRoleAssignments' } | ForEach-Object { BodyOf $_ })
        # every Graph role except the one already held, plus MTP + MDE -- each to the SI service principal
        @($grants | ForEach-Object { $_.appRoleId } | Sort-Object) | Should -Be @(@($Fake.GraphRoles | ForEach-Object { $_.id } | Where-Object { $_ -ne 'g-User.Read.All' }) + 'mde-r' + 'mde-s' + 'mde-v' + 'mtp-r' | Sort-Object)
        @($grants | Where-Object { $_.principalId -ne 'sp-obj' }).Count | Should -Be 0
        @($grants | Where-Object { $_.appRoleId -like 'g-*' -and $_.resourceId -ne 'graph-sp' }).Count | Should -Be 0
        ($grants | Where-Object { $_.appRoleId -eq 'mtp-r' }).resourceId | Should -Be 'mtp-sp'
        ($grants | Where-Object { $_.appRoleId -eq 'mde-r' }).resourceId | Should -Be 'mde-sp'

        $app = BodyOf ($Fake.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Url -like '*/v1.0/applications' })
        $app.displayName | Should -Be 'SecurityInsight (test)'; $app.signInAudience | Should -Be 'AzureADMyOrg'
        (BodyOf ($Fake.Requests | Where-Object { $_.Method -eq 'POST' -and $_.Url -like '*/v1.0/servicePrincipals' })).appId | Should -Be 'app-id'
        (BodyOf ($Fake.Requests | Where-Object { $_.Url -like '*/addPassword' })).passwordCredential.displayName | Should -BeLike 'SI-Wizard-*'
        $Fake.RbacGranted | Should -BeTrue
    }
    It 'refuses a Graph sign-in to another tenant, and a service principal without the permissions, before writing anything' {
        $Fake.Router = { param($r) throw "no request expected: $($r.Method) $($r.Url)" }
        $SIGraphRestTokenSource = { New-FakeJwt @{ tid = 'other-tenant'; upn = 'admin@contoso.example'; scp = 'Directory.AccessAsUser.All' } }
        { & $script:Spn -DisplayName 'x' -TenantId 'tenant-1' -SubscriptionId 'sub-1' -CredKind Secret -CredStorage Inline 6>$null } | Should -Throw '*tenant mismatch*Start-SetupWizard.ps1 -TenantId tenant-1*'
        $SIGraphRestTokenSource = { New-FakeJwt @{ tid = 'tenant-1'; appid = 'invardia'; roles = @('Application.ReadWrite.OwnedBy') } }
        { & $script:Spn -DisplayName 'x' -TenantId 'tenant-1' -SubscriptionId 'sub-1' -CredKind Secret -CredStorage Inline 6>$null } | Should -Throw '*missing required permissions: AppRoleAssignment.ReadWrite.All,Directory.Read.All*'
        $Fake.Requests.Count | Should -Be 0
    }
}

Describe 'asset tagging reaches Graph and Defender over REST' {
    BeforeEach { Reset-Fake }
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-GraphRest.ps1')
        . (Join-Path $script:SIRoot 'engine\asset-tagging\_shared\AT-GraphRest.ps1')
    }
    It 'signs in as the same identity: secret -> client_credentials for graph.microsoft.com/.default' {
        $captured = $null
        $tok = Get-ATSpnAccessToken -Resource 'https://graph.microsoft.com' -TenantId 't1' -ClientId 'c1' -CertificateThumbprint '' -ClientSecret 's1' -Invoke { param($u, $b) $script:AtUri = $u; $script:AtBody = $b; @{ access_token = 'at' } }
        $tok | Should -Be 'at'
        $script:AtUri | Should -Be 'https://login.microsoftonline.com/t1/oauth2/v2.0/token'
        $script:AtBody.client_id | Should -Be 'c1'; $script:AtBody.client_secret | Should -Be 's1'
        $script:AtBody.scope | Should -Be 'https://graph.microsoft.com/.default'; $script:AtBody.grant_type | Should -Be 'client_credentials'
    }
    It 'refuses to fall through to a prompt when neither a certificate nor a secret is set' {
        { Get-ATSpnAccessToken -Resource 'https://graph.microsoft.com' -TenantId 't1' -ClientId 'c1' -CertificateThumbprint '' -ClientSecret '' } | Should -Throw '*Refusing to fall through to an interactive prompt*'
    }
    It 'writes the custom security attribute with PATCH and the same body the SDK sent; reads with GET ?$select' {
        $script:ATGraphToken = 'graph-token'
        Mock Invoke-RestMethod { $script:AtCalls += , @{ Method = $Method; Uri = $Uri; Body = $Body; Headers = $Headers }; [pscustomobject]@{ ok = 1 } }
        $script:AtCalls = @()
        $body = @{ customSecurityAttributes = @{ SI = @{ '@odata.type' = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'; 'AssetTags@odata.type' = '#Collection(String)'; AssetTags = @('T0--tier0--SI') } } }
        $null = Invoke-ATGraphRequest -Method Patch -Uri 'https://graph.microsoft.com/v1.0/users/u1' -Body $body
        $null = Invoke-ATGraphRequest -Method Get -Uri 'https://graph.microsoft.com/v1.0/users/u1?$select=customSecurityAttributes'
        $script:AtCalls[0].Method | Should -Be 'Patch'
        $script:AtCalls[0].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/u1'
        $script:AtCalls[0].Headers.Authorization | Should -Be 'Bearer graph-token'
        $sent = [Text.Encoding]::UTF8.GetString($script:AtCalls[0].Body) | ConvertFrom-Json
        @($sent.customSecurityAttributes.SI.AssetTags) | Should -Be @('T0--tier0--SI')
        $sent.customSecurityAttributes.SI.'AssetTags@odata.type' | Should -Be '#Collection(String)'
        $script:AtCalls[1].Method | Should -Be 'Get'
        $script:AtCalls[1].Uri | Should -Be 'https://graph.microsoft.com/v1.0/users/u1?$select=customSecurityAttributes'
    }
    It 'Defender headers keep the module''s shape (Content-Type, Accept, Authorization)' {
        $global:SpnTenantId = 't1'; $global:SpnClientId = 'c1'; $global:SpnClientSecret = 's1'
        try {
            $h = Get-ATDefenderHeaders -SecretOnly -Invoke { param($u, $b) $script:DefScope = $b.scope; @{ access_token = 'def' } }
            $h.Authorization | Should -Be 'Bearer def'; $h.Accept | Should -Be 'application/json'; $h.'Content-Type' | Should -Be 'application/json'
            $script:DefScope | Should -Be 'https://api.securitycenter.microsoft.com/.default'
        } finally { Remove-Variable -Name SpnTenantId, SpnClientId, SpnClientSecret -Scope Global -ErrorAction SilentlyContinue }
    }
}

Describe 'wiring: no Microsoft.Graph SDK left' {
    BeforeEach { Reset-Fake }
    BeforeAll {
        $script:CodeFiles = @(
            foreach ($d in 'engine', 'setup', 'launcher', 'container') {
                Get-ChildItem -LiteralPath (Join-Path $script:SIRoot $d) -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.ps1', '.psm1' }
            }
            Get-ChildItem -LiteralPath $script:SIRoot -File -Filter '*.ps1'
        )
    }
    It 'no -Mg* cmdlet, Connect-MgGraph, Invoke-MgGraphRequest or Import-Module Microsoft.Graph* (AST)' {
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($f in $script:CodeFiles) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = [string]$c.GetCommandName()
                # The ONE exception, deliberate: the privilege-tier classifier tears down the PLATFORM framework's own
                # Graph session on its MSAL-cache retry (VM only, catch-guarded, a no-op without the SDK). It is not
                # a dependency of SecurityInsight -- see the comment at that line.
                if ($name -eq 'Disconnect-MgGraph' -and $f.Name -eq 'Invoke-PrivilegeTierClassifier.ps1') { continue }
                if ($name -match '^[A-Za-z]+-Mg[A-Z]' -or $name -in 'Connect-MicrosoftGraphPS', 'Connect-MicrosoftRestApiEndpointPS') { $hits.Add(('{0}:{1} {2}' -f $f.Name, $c.Extent.StartLineNumber, $name)) }
                if ($name -in 'Import-Module', 'Install-Module' -and $c.Extent.Text -match 'Microsoft\.Graph|MicrosoftGraphPS') { $hits.Add(('{0}:{1} {2}' -f $f.Name, $c.Extent.StartLineNumber, $c.Extent.Text)) }
            }
        }
        $hits -join "`n" | Should -BeNullOrEmpty
    }
    It 'the Graph SDK is in no module list: setup''s list and the engines'' (empty) opt-in list' {
        # neither the engines nor setup carry a module installer any more (#305); a copy that is gone carries no Graph
        # SDK either, and SIv3-NoPsModulesSetup asserts setup's is gone
        foreach ($rel in 'setup\_shared\Ensure-Module.ps1', 'engine\risk-analysis\_shared\Ensure-Module.ps1',
                         'engine\privilege-tier-classifier\_shared\Ensure-Module.ps1', 'engine\asset-tagging\_shared\Ensure-Module.ps1') {
            if (-not (Test-Path -LiteralPath (Join-Path $script:SIRoot $rel))) { continue }
            $code = ((Get-Content -LiteralPath (Join-Path $script:SIRoot $rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match "'Microsoft\.Graph[A-Za-z.]*'" -Because $rel
            $code | Should -Not -Match "(?m)^\s*'MicrosoftGraphPS'\s*$" -Because $rel
        }
        # the image's own build guard (owner 2026-10-10, SIv3-ImageNoAzNoModules) names the Graph SDK to REFUSE it --
        # that line fails the build when the SDK is present; every other line must not mention it
        (@(Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Dockerfile')) | Where-Object { $_ -notmatch 'Get-Module -ListAvailable -Name .*exit 1' }) -join "`n" | Should -Not -Match 'Microsoft\.Graph'
    }
    It 'every rerouted setup script goes through SI-GraphRest' {
        $want = @{
            'setup\ConfigWizard\backend\New-SISpn.ps1'       = @('Find-SIGraphApplication', 'New-SIGraphApplication', 'Find-SIGraphServicePrincipal', 'New-SIGraphServicePrincipal', 'Add-SIGraphApplicationPassword', 'Set-SIGraphApplicationCertificate', 'Get-SIGraphKeyCredentialThumbprint', 'Get-SIGraphAppRoleAssignments', 'New-SIGraphAppRoleAssignment', 'Get-SIGraphContext', 'Get-SIGraphMissingScopes')
            'setup\ConfigWizard\Start-SetupWizard.ps1'       = @('Get-SIGraphContext', 'Get-SIGraphMissingScopes', 'Get-SIGraphUserDirectoryRoleNames')
            'Setup-SecurityInsight-Unattended.ps1'           = @('Get-SIGraphContext', 'Get-SIGraphAccessToken')
            'engine\asset-tagging\AssetTagging.ps1'          = @('Get-ATSpnAccessToken', 'Invoke-ATGraphRequest', 'Get-ATDefenderHeaders')
        }
        foreach ($rel in $want.Keys) {
            $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $rel)
            $t | Should -Match 'SI-GraphRest\.ps1' -Because "$rel must load the REST helper"
            foreach ($fn in $want[$rel]) { $t | Should -Match ([regex]::Escape($fn)) -Because "$rel calls $fn" }
        }
    }
}
