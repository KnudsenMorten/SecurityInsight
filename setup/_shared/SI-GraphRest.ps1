#Requires -Version 5.1
<#
    Microsoft Graph over plain REST for SecurityInsight SETUP -- replaces the Microsoft.Graph SDK.

    WHY. SecurityInsight v3 carries no PowerShell module dependencies. Setup used the Graph SDK
    (Connect-MgGraph, Get-MgContext, Get-Mg* / New-Mg* / Update-Mg*, Invoke-MgGraphRequest) for a dozen
    calls: find or create the SecurityInsight app and its service principal, give it a secret or a
    certificate, and grant it application permissions. Those are the same HTTP calls made here.

    WHO IS SIGNED IN. The token comes from setup's own sign-in (setup\_shared\SI-SetupAzure.ps1:
    Connect-SISetupAzure -- a person through Azure Cloud Shell or the browser, or an app with a certificate
    or a secret), through Get-SIAzureToken -Audience Graph. So setup needs ONE sign-in, not two, and the
    identity that creates the app is the identity that grants it Azure roles. No PowerShell module, no
    device code, no second browser prompt.
    INSIDE AN INVARDIA SUPPORT SESSION no token is asked for at all: every call goes through the session's
    recording command (Test-SIGraphViaSupport), which signs as the environment's Support app and records it.

    WHAT EVERY CALL GETS.
      - paging: -All follows @odata.nextLink and returns every item of every page;
      - retries: 429 and 5xx (and a dropped connection) are retried, honouring Retry-After, up to
        -MaxAttempts; a 401 refreshes the token once; anything else fails at once;
      - errors: the exception names the method, the path, the HTTP status, Graph's error code and Graph's
        own message (e.g. "HTTP 403 Authorization_RequestDenied -- Insufficient privileges ..."), so the
        existing 403 / Authorization_RequestDenied hints in setup keep matching.

    TEST SEAMS (looked up dynamically, so a test defines them in its own scope; production never does):
      $SIGraphRestSend        { param($Method, $Url, $Headers, $BodyBytes) } -> @{ StatusCode; Body; RetryAfter }
      $SIGraphRestTokenSource { } -> token string
      $SIGraphRestSleep       { param($Seconds) }

    PS 5.1 safe: no ?. / ??; request bodies are UTF-8 BYTES (a string body is transcoded to a single-byte
    encoding by Windows PowerShell and loses every non-ASCII character).
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

function ConvertFrom-SIGraphSecureToken {
    <# A token as a plain string -- a SecureString is unwrapped. #>
    param($Token)
    if ($Token -is [System.Security.SecureString]) { return [System.Net.NetworkCredential]::new('', $Token).Password }
    return [string]$Token
}

function Get-SIGraphAccessToken {
    <# A Microsoft Graph access token from setup's sign-in (Get-SIAzureToken; the sign-in caches it until five minutes before it expires). #>
    param([switch]$ForceRefresh)
    $src = $SIGraphRestTokenSource
    if ($src) { return [string](& $src) }
    if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) {
        . ([IO.Path]::Combine($PSScriptRoot, 'SI-SetupAzure.ps1'))
    }
    $tok = ConvertFrom-SIGraphSecureToken -Token (Get-SIAzureToken -Audience Graph -ForceRefresh:$ForceRefresh)
    if ([string]::IsNullOrWhiteSpace($tok)) { throw 'The Azure sign-in returned an empty Microsoft Graph token. Run the same command again to sign in.' }
    return $tok
}

function Get-SIGraphTokenClaims {
    <# The claims of a JWT access token (no signature check -- it is only read to report who is signed in). #>
    param([Parameter(Mandatory)][string]$Token)
    $parts = $Token.Split('.')
    if ($parts.Count -lt 2) { throw 'Not a JWT access token.' }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
    return ($json | ConvertFrom-Json)
}

function Get-SIGraphContext {
    <#
        Who Graph calls run as. $null when nobody is signed in.
        Account (UPN, or the app id for an app-only sign-in), TenantId, Scopes (delegated scp, or the
        app roles of an app-only token), AuthType 'Delegated' | 'AppOnly', AppName.
    #>
    param()
    $tok = $null
    try { $tok = Get-SIGraphAccessToken } catch { return $null }
    if ([string]::IsNullOrWhiteSpace($tok)) { return $null }
    $c = Get-SIGraphTokenClaims -Token $tok
    $isApp = -not $c.scp    # delegated tokens carry scp; app-only tokens carry roles
    $account = if ($isApp) { [string]$c.appid } else {
        $u = [string]$c.upn; if (-not $u) { $u = [string]$c.unique_name }; if (-not $u) { $u = [string]$c.preferred_username }; $u
    }
    $scopes = if ($isApp) { @($c.roles | Where-Object { $_ }) } else { @(([string]$c.scp).Split(' ') | Where-Object { $_ }) }
    return [pscustomobject]@{
        Account  = $account
        TenantId = [string]$c.tid
        Scopes   = [string[]]$scopes
        AuthType = $(if ($isApp) { 'AppOnly' } else { 'Delegated' })
        AppName  = [string]$c.app_displayname
        ObjectId = [string]$c.oid
    }
}

function Get-SIGraphMissingScopes {
    <#
        The required permissions the signed-in Graph context does not hold. -Equivalents maps a requirement to
        the permissions that satisfy it. A person's sign-in (the Azure PowerShell public client) carries
        Directory.AccessAsUser.All (act with the signed-in user's own directory rights), which satisfies every
        requirement here: what the user may do is then decided by their directory role, as in the portal.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string[]]$Required,
        [hashtable]$Equivalents = @{}
    )
    $have = @($Context.Scopes)
    if ($Context.AuthType -eq 'Delegated' -and $have -contains 'Directory.AccessAsUser.All') { return @() }
    return @($Required | Where-Object {
        $need = $_
        $ok = if ($Equivalents.ContainsKey($need)) { @($Equivalents[$need]) } else { @($need) }
        -not @($ok | Where-Object { $have -contains $_ }).Count
    })
}

function Test-SIGraphViaSupport {
    <# Does a Microsoft Graph call of this file go through the Invardia Support session's recording command? Yes inside a
       Support session (engine/_shared/SI-AzRest.ps1 decides); never when a test seam answers instead. The caller then
       asks for NO token: the recording command signs as the environment's Support app. #>
    if ($SIGraphRestSend -or $SIGraphRestTokenSource) { return $false }
    return [bool]((Get-Command -Name Test-SISupportRequestRoute -ErrorAction SilentlyContinue) -and (Test-SISupportRequestRoute -Audience 'Graph'))
}

function Invoke-SIGraphHttpSend {
    <# The transport: one HTTP exchange, never throws on an HTTP status (HttpClient), throws on a dropped connection. #>
    param([string]$Method, [string]$Url, [hashtable]$Headers, [byte[]]$BodyBytes, [int]$TimeoutSec = 300)
    $send = $SIGraphRestSend
    if ($send) { return (& $send $Method $Url $Headers $BodyBytes) }
    # #548: inside an Invardia support session the exchange goes through Invardia's RECORDING wrapper (the customer's
    # audit log), never a raw token + HTTP; the wrapper signs as the support app (a bearer header here is dropped)
    if (Test-SIGraphViaSupport) {
        $r = Invoke-SISupportHttp -Method $Method -Uri $Url -Headers $Headers -Body $BodyBytes -Audience 'Graph' -TimeoutSec $TimeoutSec -ContentType $(if ($null -ne $BodyBytes) { 'application/json; charset=utf-8' } else { '' })
        if ([int]$r.StatusCode -eq 0) { throw ('No answer from Microsoft Graph: {0}' -f $r.Content) }
        $ra = $null; $n = 0; if ([int]::TryParse([string]$r.RetryAfter, [ref]$n)) { $ra = $n }
        return @{ StatusCode = [int]$r.StatusCode; Body = [string]$r.Content; RetryAfter = $ra }
    }
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    $client = New-Object System.Net.Http.HttpClient
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $req = New-Object System.Net.Http.HttpRequestMessage((New-Object System.Net.Http.HttpMethod($Method.ToUpperInvariant())), $Url)
        foreach ($k in $Headers.Keys) { [void]$req.Headers.TryAddWithoutValidation([string]$k, [string]$Headers[$k]) }
        if ($null -ne $BodyBytes) {
            $content = New-Object System.Net.Http.ByteArrayContent(, $BodyBytes)
            [void]$content.Headers.Remove('Content-Type')
            [void]$content.Headers.TryAddWithoutValidation('Content-Type', 'application/json; charset=utf-8')
            $req.Content = $content
        }
        # GetAwaiter().GetResult(), never .Result: PowerShell swallows exceptions raised in a property getter.
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $body = ''
        if ($resp.Content) { $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
        $retryAfter = $null
        try { if ($resp.Headers.RetryAfter -and $resp.Headers.RetryAfter.Delta) { $retryAfter = [int]$resp.Headers.RetryAfter.Delta.TotalSeconds } } catch { }
        return @{ StatusCode = [int]$resp.StatusCode; Body = $body; RetryAfter = $retryAfter }
    } finally {
        if ($client) { $client.Dispose() }
    }
}

function Get-SIGraphErrorText {
    <# "HTTP <status> <Graph error code> -- <Graph message>" from a Graph error body. #>
    param([int]$StatusCode, [string]$Body)
    $code = $null; $msg = $null; $rid = $null
    if ($Body) {
        try {
            $e = ($Body | ConvertFrom-Json).error
            if ($e) {
                $code = [string]$e.code; $msg = [string]$e.message
                if ($e.innerError) { $rid = [string]$e.innerError.'request-id' }
            }
        } catch { $msg = $Body.Substring(0, [Math]::Min(500, $Body.Length)) }
    }
    $t = 'HTTP {0}' -f $StatusCode
    if ($code) { $t += ' ' + $code }
    if ($msg)  { $t += ' -- ' + $msg }
    if ($rid)  { $t += (' (request-id {0})' -f $rid) }
    return $t
}

function Invoke-SIGraphRequest {
    <#
        One Microsoft Graph call.
          -Method  GET | POST | PATCH | DELETE
          -Uri     absolute, or a path starting with /v1.0/ or /beta/ (a bare '/x' means /v1.0/x)
          -Body    hashtable / object, sent as JSON (UTF-8 bytes)
          -All     GET with paging: follows @odata.nextLink, returns every item of .value as an array
          -Eventual sends ConsistencyLevel: eventual (for $count / advanced filters)
        Returns the parsed response (or, with -All, the items). Throws "Microsoft Graph <METHOD> <path>
        failed: HTTP <status> <code> -- <message>" after retrying 429 / 5xx.
    #>
    param(
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')][string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        $Body,
        [switch]$All,
        [switch]$Eventual,
        [int]$MaxAttempts = 5,
        [int]$TimeoutSec = 300
    )
    $url = if ($Uri -match '^https?://') { $Uri }
           elseif ($Uri -match '^/(v1\.0|beta)/') { 'https://graph.microsoft.com' + $Uri }
           else { 'https://graph.microsoft.com' + '/v1.0' + $(if ($Uri.StartsWith('/')) { $Uri } else { '/' + $Uri }) }
    $bytes = $null
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { ConvertTo-Json -InputObject $Body -Depth 20 -Compress }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    }
    $items = New-Object System.Collections.Generic.List[object]
    $refreshed = $false; $forceNow = $false
    # inside an Invardia Support session: no token of ours -- the recording command signs the call
    $viaSupport = Test-SIGraphViaSupport
    while ($url) {
        $attempt = 0
        while ($true) {
            $attempt++
            $headers = @{}
            if (-not $viaSupport) { $headers['Authorization'] = ('Bearer ' + (Get-SIGraphAccessToken -ForceRefresh:$forceNow)) }
            $forceNow = $false
            if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
            $r = $null; $transportError = $null
            try { $r = Invoke-SIGraphHttpSend -Method $Method -Url $url -Headers $headers -BodyBytes $bytes -TimeoutSec $TimeoutSec }
            catch { $transportError = $_.Exception.Message }
            $status = if ($r) { [int]$r.StatusCode } else { 0 }
            if ($status -ge 200 -and $status -lt 300) { break }
            if ($status -eq 401 -and -not $refreshed -and -not $transportError) { $refreshed = $true; $forceNow = $true; $attempt--; continue }
            $transient = ($status -eq 0) -or ($status -eq 429) -or ($status -ge 500 -and $status -le 599)
            $what = if ($transportError) { 'no response (' + $transportError + ')' } else { Get-SIGraphErrorText -StatusCode $status -Body ([string]$r.Body) }
            $path = ([uri]$url).PathAndQuery
            # A POST that CREATES and got NO ANSWER is never sent again: Graph may have made the object and lost only the
            # answer, and a second POST would make a second one (two app registrations of one name stop every later run).
            # The caller reads first and then decides. A POST that only reads (checkMemberGroups, getByIds, ...) is repeated.
            if ($status -eq 0 -and $Method -eq 'POST' -and $path -notmatch '(?i)/(getByIds|getMemberObjects|getMemberGroups|checkMemberObjects|checkMemberGroups)(\?|$)') {
                throw ('Microsoft Graph POST {0} got no answer ({1}). It is NOT sent again: it is not known whether Graph made the object -- run the same command again, it reads what is there first.' -f $path, $(if ($transportError) { $transportError } else { 'no response' }))
            }
            if (-not $transient -or $attempt -ge $MaxAttempts) {
                $tail = if ($transient) { (' (after {0} attempts)' -f $attempt) } else { '' }
                throw ('Microsoft Graph {0} {1} failed: {2}{3}' -f $Method, $path, $what, $tail)
            }
            $delay = if ($r -and $r.RetryAfter) { [int]$r.RetryAfter } else { [int][Math]::Min(30, [Math]::Pow(2, $attempt)) }
            Write-Verbose ('Microsoft Graph {0} {1}: {2} -- retry {3}/{4} in {5}s' -f $Method, $path, $what, $attempt, ($MaxAttempts - 1), $delay)
            $sleep = $SIGraphRestSleep
            if ($sleep) { & $sleep $delay } else { Start-Sleep -Seconds $delay }
        }
        $obj = $null
        if ($r.Body) { $obj = $r.Body | ConvertFrom-Json }
        if (-not $All) { return $obj }
        if ($null -ne $obj -and $obj.PSObject.Properties['value']) { foreach ($v in @($obj.value)) { if ($null -ne $v) { $items.Add($v) } } }
        $url = if ($null -ne $obj -and $obj.PSObject.Properties['@odata.nextLink']) { [string]$obj.'@odata.nextLink' } else { $null }
    }
    # Unrolled on purpose: a caller's @( ) then holds exactly the items (an empty result stays empty).
    return $items.ToArray()
}

# ---------------------------------------------------------------------------------------------------------
#  The calls setup makes. One function each, so every request's shape is tested in one place.
# ---------------------------------------------------------------------------------------------------------

function ConvertTo-SIODataString {
    <# A value inside an OData filter's single quotes ('' escapes a quote). #>
    param([AllowEmptyString()][string]$Value)
    return $Value.Replace("'", "''")
}

function Get-SIGraphEngineNameCandidates {
    <#
        PURE. The display names a lookup of SecurityInsight's ENGINE application by -DisplayName tries, in order (framework
        12.11c item 5, #655): an existing install's engine application "SecurityInsight" may have been renamed to
        "SecurityInsight Engine" -- and the web app's sign-in application may now carry "SecurityInsight". So a lookup of
        either engine name tries both, and SKIPS any object that is the web app's sign-in application (it carries its role
        ids). Any other name: just that name, as before.
    #>
    param([AllowEmptyString()][string]$DisplayName)
    if ($DisplayName -ceq 'SecurityInsight' -or $DisplayName -ceq 'SecurityInsight Engine') { return @($DisplayName, $(if ($DisplayName -ceq 'SecurityInsight') { 'SecurityInsight Engine' } else { 'SecurityInsight' })) }
    @($DisplayName)
}

function Select-SIGraphEngineObject {
    <# PURE. The first object of -Objects that is NOT the web app's sign-in application (its stable app role ids). #>
    param([AllowEmptyCollection()][object[]]$Objects = @())
    $web = @('5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a05', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a01', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a02', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a04', '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a06')
    @(@($Objects) | Where-Object { $_ -and -not ($_.PSObject.Properties['appRoles'] -and @(@($_.appRoles) | Where-Object { $_ -and $_.PSObject.Properties['id'] -and $web -contains [string]$_.id }).Count) }) | Select-Object -First 1
}

function Find-SIGraphServicePrincipal {
    <# The first service principal with this appId (or display name), or $null. By display name "SecurityInsight" /
       "SecurityInsight Engine": both names, never the web app's sign-in application (Get-SIGraphEngineNameCandidates). #>
    param([string]$AppId, [string]$DisplayName)
    if ($AppId) {
        $r = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/servicePrincipals?$filter=' + [uri]::EscapeDataString(("appId eq '{0}'" -f (ConvertTo-SIODataString $AppId))))
        if ($null -eq $r) { return $null }
        return (@($r.value) | Select-Object -First 1)
    }
    foreach ($n in @(Get-SIGraphEngineNameCandidates -DisplayName $DisplayName)) {
        $r = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/servicePrincipals?$filter=' + [uri]::EscapeDataString(("displayName eq '{0}'" -f (ConvertTo-SIODataString $n))))
        if ($null -eq $r) { continue }
        $hit = Select-SIGraphEngineObject -Objects @($r.value)
        if ($hit) { return $hit }
    }
    return $null
}

function New-SIGraphServicePrincipal {
    <# POST /servicePrincipals for an app id. #>
    param([Parameter(Mandatory)][string]$AppId)
    return (Invoke-SIGraphRequest -Method POST -Uri '/v1.0/servicePrincipals' -Body @{ appId = $AppId })
}

function Find-SIGraphApplication {
    <# The first app registration with this appId (or display name), or $null. By display name "SecurityInsight" /
       "SecurityInsight Engine": both names, never the web app's sign-in application (Get-SIGraphEngineNameCandidates). #>
    param([string]$AppId, [string]$DisplayName)
    if ($AppId) {
        $r = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/applications?$filter=' + [uri]::EscapeDataString(("appId eq '{0}'" -f (ConvertTo-SIODataString $AppId))) + '&$count=true') -Eventual
        if ($null -eq $r) { return $null }
        return (@($r.value) | Select-Object -First 1)
    }
    foreach ($n in @(Get-SIGraphEngineNameCandidates -DisplayName $DisplayName)) {
        $r = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/applications?$filter=' + [uri]::EscapeDataString(("displayName eq '{0}'" -f (ConvertTo-SIODataString $n))) + '&$count=true') -Eventual
        if ($null -eq $r) { continue }
        $hit = Select-SIGraphEngineObject -Objects @($r.value)
        if ($hit) { return $hit }
    }
    return $null
}

function New-SIGraphApplication {
    <# POST /applications: a single-tenant app registration. #>
    param([Parameter(Mandatory)][string]$DisplayName, [string]$SignInAudience = 'AzureADMyOrg')
    return (Invoke-SIGraphRequest -Method POST -Uri '/v1.0/applications' -Body @{ displayName = $DisplayName; signInAudience = $SignInAudience })
}

function Add-SIGraphApplicationPassword {
    <#
        POST /applications/{id}/addPassword. Returns SecretText + EndDateTime ([datetime], UTC) -- the two
        fields setup reads (the SDK returned EndDateTime as a DateTime as well).
    #>
    param([Parameter(Mandatory)][string]$ApplicationObjectId, [Parameter(Mandatory)][string]$DisplayName, [Parameter(Mandatory)][datetime]$EndDateTime)
    $body = @{ passwordCredential = @{ displayName = $DisplayName; endDateTime = $EndDateTime.ToUniversalTime().ToString('o') } }
    $r = Invoke-SIGraphRequest -Method POST -Uri ('/v1.0/applications/{0}/addPassword' -f $ApplicationObjectId) -Body $body
    $end = $r.endDateTime
    if ($end -isnot [datetime]) { $end = [datetime]::Parse([string]$end, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
    return [pscustomobject]@{ SecretText = [string]$r.secretText; EndDateTime = $end; KeyId = [string]$r.keyId }
}

function Set-SIGraphApplicationCertificate {
    <#
        PATCH /applications/{id} keyCredentials = this one certificate's public key. Like the SDK's
        Update-MgApplication -KeyCredentials, this REPLACES the app's certificate list (setup guards that).
    #>
    param(
        [Parameter(Mandatory)][string]$ApplicationObjectId,
        [Parameter(Mandatory)][byte[]]$CertificateBytes,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][datetime]$StartDateTime,
        [Parameter(Mandatory)][datetime]$EndDateTime
    )
    $kc = @{
        type          = 'AsymmetricX509Cert'
        usage         = 'Verify'
        key           = [Convert]::ToBase64String($CertificateBytes)
        displayName   = $DisplayName
        startDateTime = $StartDateTime.ToUniversalTime().ToString('o')
        endDateTime   = $EndDateTime.ToUniversalTime().ToString('o')
    }
    $null = Invoke-SIGraphRequest -Method PATCH -Uri ('/v1.0/applications/{0}' -f $ApplicationObjectId) -Body @{ keyCredentials = @($kc) }
}

function Get-SIGraphKeyCredentialThumbprint {
    <# A key credential's certificate thumbprint (hex) from customKeyIdentifier -- base64 over REST, bytes from the SDK. #>
    param($KeyCredential)
    $k = $KeyCredential.customKeyIdentifier
    if (-not $k) { return $null }
    # statements, never `= if (...) { $k }`: an if-expression enumerates a byte array into object[]
    [byte[]]$bytes = $null
    if ($k -is [byte[]]) { $bytes = $k } else { try { $bytes = [Convert]::FromBase64String([string]$k) } catch { $bytes = $null } }
    if (-not $bytes) { return $null }
    return ([BitConverter]::ToString($bytes)).Replace('-', '')
}

function Get-SIGraphAppRoleAssignments {
    <# Every app-role assignment a service principal holds (all pages). #>
    param([Parameter(Mandatory)][string]$ServicePrincipalId)
    return (Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $ServicePrincipalId) -All)
}

function New-SIGraphAppRoleAssignment {
    <# Grant one application permission: POST /servicePrincipals/{id}/appRoleAssignments. #>
    param([Parameter(Mandatory)][string]$ServicePrincipalId, [Parameter(Mandatory)][string]$ResourceId, [Parameter(Mandatory)][string]$AppRoleId)
    $body = @{ principalId = $ServicePrincipalId; resourceId = $ResourceId; appRoleId = $AppRoleId }
    return (Invoke-SIGraphRequest -Method POST -Uri ('/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $ServicePrincipalId) -Body $body)
}

function Get-SIGraphUserDirectoryRoleNames {
    <# The directory roles (display names) a user holds, by UPN; $null when the user is not found. #>
    param([Parameter(Mandatory)][string]$UserPrincipalName)
    $f = "userPrincipalName eq '{0}'" -f (ConvertTo-SIODataString $UserPrincipalName)
    $u = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/users?$filter=' + [uri]::EscapeDataString($f))
    $me = if ($u) { @($u.value) | Select-Object -First 1 } else { $null }
    if (-not $me) { return $null }
    $m = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/users/{0}/memberOf' -f $me.id) -All
    return @($m | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | ForEach-Object { [string]$_.displayName })
}

function Get-SIGraphUser {
    <#
        One user by object id or user principal name (-Id), or the signed-in person (-SignedIn, /me). Returns Id,
        UserPrincipalName, DisplayName, Mail, UserType; $null when there is no such user.
    #>
    param([string]$Id, [switch]$SignedIn)
    $sel = '?$select=id,userPrincipalName,displayName,mail,userType'
    $u = $null
    if ($SignedIn) { $u = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/me' + $sel) }
    elseif ($Id) {
        try { $u = Invoke-SIGraphRequest -Method GET -Uri ('/v1.0/users/{0}{1}' -f [uri]::EscapeDataString($Id), $sel) }
        catch { if ("$($_.Exception.Message)" -match 'HTTP 404') { return $null } else { throw } }
    } else { throw 'Get-SIGraphUser needs -Id or -SignedIn.' }
    if (-not $u) { return $null }
    return [pscustomobject]@{ Id = [string]$u.id; UserPrincipalName = [string]$u.userPrincipalName; DisplayName = [string]$u.displayName; Mail = [string]$u.mail; UserType = [string]$u.userType }
}
