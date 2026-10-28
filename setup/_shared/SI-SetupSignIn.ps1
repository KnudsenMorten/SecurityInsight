#Requires -Version 5.1
<#
    SecurityInsight SETUP -- signing in to Azure with NO PowerShell modules (native REST and .NET only).

    WHO SIGNS IN, AND HOW
      A person (the guided install, the wizard, Setup-SecurityInsight, Bootstrap-*, Grant-*, Validate-* ...):
        * Azure Cloud Shell  -- the Cloud Shell token endpoint ($env:MSI_ENDPOINT, else $env:IDENTITY_ENDPOINT). It hands
                                out tokens for the person who opened Cloud Shell, per resource, with no prompt.
        * a workstation      -- OAuth 2.0 authorization code + PKCE in the person's own browser, answered on a loopback
                                listener (System.Net.HttpListener on http://localhost:<free port>/). The client is the
                                public Azure PowerShell client, so the same consent and the same Microsoft Graph rights
                                (Directory.AccessAsUser.All) setup always had. NO device code: it is blocked by
                                Conditional Access in many tenants and is deliberately not offered.
        Tokens for the other resources (Graph, Key Vault, Storage, Log Analytics, SQL ...) come from the refresh token
        (browser) or the Cloud Shell endpoint, on first use. EXCEPT Exchange Online (https://outlook.office365.com): its
        admin API accepts only a token of the Exchange Online PowerShell client (Get-SISignInExchangeClientId), so the first
        Exchange token is one more browser sign-in with that client (same flow, the account pre-filled), then its own
        refresh token. Everything is kept IN MEMORY in this PowerShell process --
        nothing is written to disk.
      An app (unattended setup, CI): a certificate or a client secret -- recorded by Connect-SIAzAccount (REST), tokens
        minted by engine/_shared (client assertion / client credentials). A managed identity likewise.

    HOW THE REST LAYER USES IT
      engine/_shared/SI-AzRest.ps1 asks Get-SIAzureToken for every token. setup/_shared/SI-SetupAzure.ps1 loads that file
      and then defines Get-SIAzureToken once more, here: a USER sign-in is answered from this file, anything else exactly
      as the engine does. So Invoke-SIArm, the *-SIAz* REST twins, Key Vault, Graph and storage all run as the signed-in
      person without knowing it.

    TEST SEAMS: every HTTP call goes through Invoke-SIAzRestHttp (engine); the browser through Open-SISignInBrowser; the
    loopback wait through Wait-SILoopbackAuthCode. Pure helpers (PKCE pair, authorize URL, redirect parsing) are public.

    PS 5.1 safe (no ?. / ??), pwsh 7 on Windows, Linux (Cloud Shell) and macOS.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.


function Get-SISignInClientId {
    <# The public client the browser sign-in uses: $global:SI_SetupSignInClientId (an organisation's own public app
       registration with an http://localhost redirect) when set, else the Azure PowerShell client. #>
    $c = "$(Get-Variable -Scope Global -Name SI_SetupSignInClientId -ValueOnly -ErrorAction Ignore)"
    if ($c.Trim()) { return $c.Trim() }
    return '1950a258-227b-4e31-a9cf-717495945fc2'
}

function Get-SISignInExchangeClientId {
    <# The public client the Exchange Online admin API (https://outlook.office365.com/adminapi/...) is signed in with:
       "Microsoft Exchange REST API Based Powershell", the client the Exchange Online PowerShell V3 module itself uses
       (PIM4EntraPS does the same). A delegated token for Exchange must carry Exchange.Manage; the Azure PowerShell client
       is not consented for it, so Exchange answered its token with 401 Unauthorized (customer ticket 2026-10-15).
       $global:SI_SetupExchangeClientId overrides it (an organisation's own public app with Exchange.Manage). #>
    $c = "$(Get-Variable -Scope Global -Name SI_SetupExchangeClientId -ValueOnly -ErrorAction Ignore)"
    if ($c.Trim()) { return $c.Trim() }
    return 'fb78d390-0c51-40cd-8e17-fdbfab77341b'
}

function Test-SISignInExchangeResource {
    <# PURE. True for the Exchange Online resource (its admin API takes only a token of the Exchange client). #>
    param([string]$Resource)
    $r = ("$Resource" -replace '/\.default$', '').TrimEnd('/').ToLowerInvariant()
    return ($r -eq 'https://outlook.office365.com' -or $r -eq 'https://outlook.office.com')
}

function Get-SISignInState {
    <# The in-memory sign-in of this process: the user session (method, tenant, account, refresh token) and its tokens. #>
    if (-not ((Get-Variable -Scope Global -Name SI_SetupSignInState -ValueOnly -ErrorAction Ignore) -is [hashtable])) {
        $global:SI_SetupSignInState = @{ Session = $null; Tokens = @{} }
    }
    return $global:SI_SetupSignInState
}

function Test-SICloudShell {
    <# True in Azure Cloud Shell: the Cloud Shell markers AND a token endpoint. #>
    $marker = ([string]$env:AZUREPS_HOST_ENVIRONMENT) -like 'cloud-shell*' -or [bool]$env:ACC_CLOUD -or [bool]$env:ACC_TERM_ID
    return ($marker -and [bool](Get-SICloudShellEndpoint))
}

function Get-SICloudShellEndpoint {
    $e = [string]$env:MSI_ENDPOINT
    if (-not $e.Trim()) { $e = [string]$env:IDENTITY_ENDPOINT }
    return $e.Trim()
}

# ---------------------------------------------------------------------------------------------------------------
# PURE helpers: PKCE, state, the authorize URL, the redirect, token claims
# ---------------------------------------------------------------------------------------------------------------
function ConvertTo-SIBase64Url {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    return ([Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'))
}

function New-SIRandomBase64Url {
    param([int]$ByteCount = 32)
    $b = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($b) } finally { $rng.Dispose() }
    return (ConvertTo-SIBase64Url -Bytes $b)
}

function Get-SIPkceChallenge {
    <# RFC 7636 S256: BASE64URL(SHA256(ASCII(verifier))). #>
    param([Parameter(Mandatory)][string]$Verifier)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Verifier)) } finally { $sha.Dispose() }
    return (ConvertTo-SIBase64Url -Bytes $h)
}

function New-SIPkcePair {
    <# A fresh verifier (43 chars from 32 random bytes, inside RFC 7636's 43..128 unreserved set) and its S256 challenge. #>
    $v = New-SIRandomBase64Url -ByteCount 32
    return [pscustomobject]@{ Verifier = $v; Challenge = (Get-SIPkceChallenge -Verifier $v); Method = 'S256' }
}

function Get-SISignInScope {
    <# The v2 scope of a resource: 'https://graph.microsoft.com/' -> 'https://graph.microsoft.com/.default'. #>
    param([Parameter(Mandatory)][string]$Resource)
    $r = ($Resource -replace '/\.default$', '').TrimEnd('/')
    return ($r + '/.default')
}

function Get-SIAuthorizeUrl {
    <# The Microsoft Entra authorize URL for the code + PKCE flow. #>
    param(
        [string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$RedirectUri,
        [Parameter(Mandatory)][string]$Scope,
        [Parameter(Mandatory)][string]$CodeChallenge,
        [Parameter(Mandatory)][string]$State,
        [string]$LoginHint,
        [string]$Prompt = 'select_account'
    )
    $t = if ([string]::IsNullOrWhiteSpace($TenantId)) { 'organizations' } else { $TenantId.Trim() }
    $q = [ordered]@{
        client_id             = $ClientId
        response_type         = 'code'
        redirect_uri          = $RedirectUri
        response_mode         = 'query'
        scope                 = $Scope
        state                 = $State
        code_challenge        = $CodeChallenge
        code_challenge_method = 'S256'
    }
    if ($Prompt) { $q['prompt'] = $Prompt }
    if ($LoginHint) { $q['login_hint'] = $LoginHint }
    $pairs = foreach ($k in $q.Keys) { '{0}={1}' -f $k, [uri]::EscapeDataString([string]$q[$k]) }
    return ('https://login.microsoftonline.com/{0}/oauth2/v2.0/authorize?{1}' -f [uri]::EscapeDataString($t), ($pairs -join '&'))
}

function ConvertFrom-SIQueryString {
    <# '?a=1&b=x%20y' -> @{ a = '1'; b = 'x y' } (case-insensitive keys). #>
    param([string]$Query)
    $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    $q = ([string]$Query).TrimStart('?')
    foreach ($p in ($q -split '&')) {
        if (-not $p) { continue }
        $i = $p.IndexOf('=')
        $k = if ($i -ge 0) { $p.Substring(0, $i) } else { $p }
        $v = if ($i -ge 0) { $p.Substring($i + 1) } else { '' }
        $h[[uri]::UnescapeDataString($k.Replace('+', ' '))] = [uri]::UnescapeDataString($v.Replace('+', ' '))
    }
    return $h
}

function Resolve-SIAuthRedirect {
    <#
        The browser's redirect back to the loopback listener -> the authorization code. Throws in customer language when
        Entra returned an error, when the state does not match (a response this sign-in did not ask for), or when no
        code came back.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [Parameter(Mandatory)][string]$ExpectedState)
    $q = ConvertFrom-SIQueryString -Query $Query
    if ($q['error']) {
        $d = [string]$q['error_description']
        throw ("The Microsoft sign-in did not complete: {0}{1}" -f $q['error'], $(if ($d) { ' -- ' + $d } else { '' }))
    }
    if ([string]$q['state'] -ne $ExpectedState) {
        throw 'The sign-in answer did not belong to this sign-in (the state value does not match). Nothing was signed in; run the same command again.'
    }
    if (-not $q['code']) { throw 'The sign-in answer carried no authorization code. Run the same command again.' }
    return [string]$q['code']
}

function ConvertFrom-SISignInJwt {
    <# The claims of a JWT (no signature check -- only read to learn the tenant, the account and the expiry). #>
    param([string]$Token)
    $parts = ([string]$Token) -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    try { return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
}

function Get-SISignInAccountName {
    param($Claims)
    if (-not $Claims) { return $null }
    foreach ($n in 'upn', 'preferred_username', 'unique_name', 'email', 'oid') {
        if ($Claims.PSObject.Properties[$n] -and [string]$Claims.$n) { return [string]$Claims.$n }
    }
    return $null
}

function Get-SITokenExpiry {
    <# When a token response expires (5 minutes early): expires_in (seconds) or expires_on (unix seconds / a date). #>
    param($Response)
    $now = [datetime]::UtcNow
    $s = 0
    if ($Response.PSObject.Properties['expires_in'] -and [int]::TryParse([string]$Response.expires_in, [ref]$s) -and $s -gt 0) {
        return $now.AddSeconds([Math]::Max(60, $s - 300))
    }
    if ($Response.PSObject.Properties['expires_on']) {
        $l = 0L
        if ([long]::TryParse([string]$Response.expires_on, [ref]$l) -and $l -gt 0) {
            return ([DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime.AddMinutes(-5))
        }
        $d = [datetime]::MinValue
        if ([datetime]::TryParse([string]$Response.expires_on, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) {
            return $d.AddMinutes(-5)
        }
    }
    return $now.AddMinutes(30)
}

# ---------------------------------------------------------------------------------------------------------------
# HANDED-OVER TOKENS (#876, owner 2026-10-21 "test trial with support app today"): Invardia's bootstrap may hand the
# install the access tokens it already holds, in $env:SI_HANDOFF_TOKENS -- the same shape as PIM_HANDOFF_TOKENS:
#   { "https://management.azure.com/": { "access_token": "...", "expires_on": <unix seconds> },
#     "https://graph.microsoft.com/": {...}, "https://database.windows.net/": {...} }
# With them the install signs in to NOTHING itself: no browser, no Cloud Shell endpoint, no app sign-in. The tokens may be
# a person's (delegated) or an application's (the Invardia Support app: idtyp app, no scp) -- the claims say which, and an
# application's object id (oid) IS its service principal's. Every token must be for the SAME tenant (and for the install's
# tenant when one is named): one for another tenant refuses the whole hand-over. Read ONCE, kept in memory only
# ($global:SI_SetupHandoff), and the variable is removed from the environment so no later process inherits it. No refresh
# token crosses over, so a token cannot be renewed: when one is about to run out the install STOPS with one plain line
# and resumes from that step with a fresh hand-over. An Invardia Support session open in the same shell wins over the
# hand-over (its calls are recorded in the customer's audit log and its tokens are renewed by the session).
# ---------------------------------------------------------------------------------------------------------------
$script:SIHandoffMinMinutes = 2

function Get-SIHandoffResourceKey {
    <# PURE. The comparison key of a token audience: 'https://graph.microsoft.com' and '.../' and '.../.default' are one. #>
    param([string]$Resource)
    return ((("$Resource".Trim()) -replace '/\.default$', '').TrimEnd('/') + '/').ToLowerInvariant()
}

function Get-SIHandoffExpiredText {
    <# PURE. The one line said when a handed-over token runs out (the install resumes from the step it stopped at). #>
    param([string]$Resource)
    $what = if ("$Resource".Trim()) { ' (for {0})' -f (Get-SIHandoffResourceKey $Resource).TrimEnd('/') } else { '' }
    'The hand-over sign-in{0} has expired -- restart the install with a fresh code from the installation page (the install resumes where it stopped).' -f $what
}

function Import-SIHandoffTokens {
    <#
        PURE given -Json and -NowUtc. Reads the bootstrap's hand-over JSON. Returns
          @{ Present; Ok; Reason; TenantId; IsApp; ObjectId; AppId; Account; Tokens = @{ <resource key> = @{ Token; ExpiresAt } } }
        Present = something was handed over. Ok = it can be used (at least an Azure Resource Manager token, every token for
        one tenant -- -TenantId when given -- and every token of one kind: all a person's or all one application's).
        Reason (when not Ok) never contains token text. ExpiresAt = the earlier of expires_on and the token's own exp.
    #>
    param([AllowEmptyString()][string]$Json, [string]$TenantId, [datetime]$NowUtc = [datetime]::UtcNow)
    $out = @{ Present = $false; Ok = $false; Reason = ''; TenantId = ''; IsApp = $false; ObjectId = ''; AppId = ''; Account = ''; Tokens = @{} }
    if (-not "$Json".Trim()) { return $out }
    $out.Present = $true
    $o = $null
    try { $o = "$Json" | ConvertFrom-Json } catch { $out.Reason = 'the hand-over could not be read (it is not JSON)'; return $out }
    $tids = @(); $kinds = @(); $oids = @()
    foreach ($p in @($o.PSObject.Properties)) {
        $v = $p.Value; $tok = ''; $exp = $null
        if ($v -is [string]) { $tok = $v }
        elseif ($null -ne $v -and $v.PSObject.Properties['access_token']) { $tok = [string]$v.access_token; if ($v.PSObject.Properties['expires_on']) { $exp = $v.expires_on } }
        if (-not $tok.Trim()) { continue }
        $c = ConvertFrom-SISignInJwt $tok
        if (-not $c -or -not $c.PSObject.Properties['tid'] -or -not [string]$c.tid) { $out.Reason = ('the token handed over for {0} cannot be read (no tenant in it)' -f $p.Name); return $out }
        $tid = ([string]$c.tid).Trim().ToLowerInvariant()
        if ("$TenantId".Trim() -and $tid -ne "$TenantId".Trim().ToLowerInvariant()) {
            $out.Reason = ('the token handed over for {0} is for tenant {1}, not this installation''s tenant {2}' -f $p.Name, $tid, "$TenantId".Trim()); return $out
        }
        $isApp = ([string]$(if ($c.PSObject.Properties['idtyp']) { $c.idtyp } else { '' }) -eq 'app') -or -not ($c.PSObject.Properties['scp'] -and [string]$c.scp)
        # the expiry: the earlier of what the bootstrap says and the token's own exp claim
        $ends = @()
        $l = 0L
        if ($null -ne $exp -and [long]::TryParse([string]$exp, [ref]$l) -and $l -gt 0) { $ends += [DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime }
        if ($c.PSObject.Properties['exp'] -and [long]::TryParse([string]$c.exp, [ref]$l) -and $l -gt 0) { $ends += [DateTimeOffset]::FromUnixTimeSeconds($l).UtcDateTime }
        if (-not $ends.Count) { $out.Reason = ('the token handed over for {0} carries no expiry' -f $p.Name); return $out }
        $out.Tokens[(Get-SIHandoffResourceKey $p.Name)] = @{ Token = $tok; ExpiresAt = (@($ends | Sort-Object) | Select-Object -First 1) }
        $tids += $tid; $kinds += $isApp; $oids += ([string]$(if ($c.PSObject.Properties['oid']) { $c.oid } else { '' })).ToLowerInvariant()
        if (-not $out.AppId -and $c.PSObject.Properties['appid']) { $out.AppId = [string]$c.appid }
        if (-not $out.AppId -and $c.PSObject.Properties['azp']) { $out.AppId = [string]$c.azp }
        if (-not $out.Account -and -not $isApp) { $out.Account = [string](Get-SISignInAccountName $c) }
    }
    if (-not $out.Tokens.Count) { $out.Reason = 'the hand-over holds no token'; return $out }
    if (@($tids | Select-Object -Unique).Count -gt 1) { $out.Reason = ('the tokens handed over are for different tenants ({0})' -f ((@($tids | Select-Object -Unique)) -join ', ')); $out.Tokens = @{}; return $out }
    if (@($kinds | Select-Object -Unique).Count -gt 1 -or @($oids | Where-Object { $_ } | Select-Object -Unique).Count -gt 1) {
        $out.Reason = 'the tokens handed over are not all for the same identity'; $out.Tokens = @{}; return $out
    }
    if (-not $out.Tokens.ContainsKey('https://management.azure.com/')) { $out.Reason = 'the hand-over holds no Azure Resource Manager token'; $out.Tokens = @{}; return $out }
    $out.TenantId = [string]$tids[0]; $out.IsApp = [bool]$kinds[0]
    $out.ObjectId = [string](@($oids | Where-Object { $_ }) | Select-Object -First 1)
    if ($out.IsApp) { $out.Account = $out.AppId }
    $out.Ok = $true
    return $out
}

function Get-SISetupHandoff {
    <#
        The hand-over of this process ($global:SI_SetupHandoff), read from $env:SI_HANDOFF_TOKENS the first time it is asked
        for (then removed from the environment). $null when nothing was handed over. -TenantId: the install's tenant (a
        hand-over for another tenant THROWS -- never used, never silently replaced by another sign-in).
    #>
    param([string]$TenantId)
    $h = Get-Variable -Scope Global -Name SI_SetupHandoff -ValueOnly -ErrorAction Ignore
    if (-not ($h -is [hashtable])) {
        $json = [string][Environment]::GetEnvironmentVariable('SI_HANDOFF_TOKENS')
        if (-not $json.Trim()) { return $null }
        $h = Import-SIHandoffTokens -Json $json -TenantId $TenantId
        [Environment]::SetEnvironmentVariable('SI_HANDOFF_TOKENS', $null)
        Remove-Item -Path 'env:SI_HANDOFF_TOKENS' -ErrorAction SilentlyContinue
        $global:SI_SetupHandoff = $h
    }
    if (-not $h.Present) { return $null }
    if (-not $h.Ok) { throw ('The sign-in handed over by the installation page cannot be used: {0}. Nothing was changed. Restart the install with a fresh code from the installation page.' -f $h.Reason) }
    if ("$TenantId".Trim() -and $h.TenantId -and $h.TenantId -ne "$TenantId".Trim().ToLowerInvariant()) {
        throw ('The sign-in handed over by the installation page is for tenant {0}, not this installation''s tenant {1}. Nothing was changed. Restart the install from the installation page of tenant {1}.' -f $h.TenantId, "$TenantId".Trim())
    }
    return $h
}

function Test-SISetupHandoffPresent {
    <# Was a sign-in handed over to this process (and not refused)? Never throws. #>
    try { return [bool](Get-SISetupHandoff) } catch { return $false }
}

function Get-SISetupHandoffStatus {
    <#
        PURE given -NowUtc. Which handed-over tokens are usable for at least -MinMinutes more: @{ Expired = @(<resource>);
        Missing = @(<resource>) } over -Resources. Used before each install step, so a step never starts on a token that
        runs out under it.
    #>
    param([Parameter(Mandatory)][hashtable]$Handoff, [string[]]$Resources = @('https://management.azure.com/'), [datetime]$NowUtc = [datetime]::UtcNow, [int]$MinMinutes = $script:SIHandoffMinMinutes)
    $exp = @(); $miss = @()
    foreach ($r in $Resources) {
        $k = Get-SIHandoffResourceKey $r
        if (-not $Handoff.Tokens.ContainsKey($k)) { $miss += $k; continue }
        if ($Handoff.Tokens[$k].ExpiresAt -le $NowUtc.AddMinutes($MinMinutes)) { $exp += $k }
    }
    @{ Expired = $exp; Missing = $miss }
}

# ---------------------------------------------------------------------------------------------------------------
# The loopback listener and the browser
# ---------------------------------------------------------------------------------------------------------------
function Get-SIFreeLoopbackPort {
    <# A free TCP port on the loopback interface (the OS picks it). #>
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    try { $l.Start(); return ([System.Net.IPEndPoint]$l.LocalEndpoint).Port } finally { $l.Stop() }
}

function Get-SISignInEdgePath {
    <# The Microsoft Edge executable on Windows ($null when absent): the sign-in opens InPrivate in it. #>
    foreach ($b in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not "$b".Trim()) { continue }
        $p = [IO.Path]::Combine($b, 'Microsoft', 'Edge', 'Application', 'msedge.exe')
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $null
}

function Open-SISignInBrowser {
    <#
        Opens the sign-in page. Never throws: the URL is always printed as well.
        #564 (PIM's install at customer I, 2026-10-10): a normal browser window opens the DEFAULT profile, whose saved account signs in
        silently -- the person never sees a credential prompt and lands in the wrong tenant. On Windows the page opens in an
        Edge InPrivate window (no saved account, the sign-in form always appears); without Edge, the default browser.
        SI_SIGNIN_BROWSER=none: nothing is opened -- the person pastes the printed address into the right browser profile.
    #>
    param([Parameter(Mandatory)][string]$Url)
    if ("$env:SI_SIGNIN_BROWSER".Trim().ToLowerInvariant() -eq 'none') { return $false }
    try {
        if ($PSVersionTable.PSEdition -ne 'Core' -or $IsWindows) {
            $edge = Get-SISignInEdgePath
            if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--inprivate', '--new-window', $Url) | Out-Null; return $true }
            Start-Process -FilePath $Url | Out-Null; return $true
        }
        if ($IsMacOS) { & open $Url 2>$null | Out-Null; return $true }
        & xdg-open $Url 2>$null | Out-Null
        return $true
    } catch { return $false }
}

function Wait-SILoopbackAuthCode {
    <#
        Listens on http://localhost:<Port>/ (the loopback interface only) for the browser's redirect, answers it with a
        short page, and returns the request's query string. -Listener is a test seam (an HttpListener the test drives).
    #>
    param([Parameter(Mandatory)][int]$Port, [int]$TimeoutSec = 300, $Listener)
    $own = $false
    if (-not $Listener) {
        $Listener = New-Object System.Net.HttpListener
        $Listener.Prefixes.Add(('http://localhost:{0}/' -f $Port))
        $Listener.Start()
        $own = $true
    }
    try {
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSec)
        while ($true) {
            $task = $Listener.GetContextAsync()
            $left = [int][Math]::Max(1, ($deadline - [datetime]::UtcNow).TotalMilliseconds)
            if (-not $task.Wait($left)) {
                throw ('No answer from the browser sign-in within {0} seconds. Run the same command again and complete the sign-in in the browser window that opens.' -f $TimeoutSec)
            }
            $ctx = $task.Result
            $query = [string]$ctx.Request.Url.Query
            $isAnswer = ($query -match '(^|[?&])(code|error)=')
            $html = if ($isAnswer) {
                '<!doctype html><html><head><meta charset="utf-8"><title>SecurityInsight sign-in</title></head><body style="font-family:Segoe UI,Arial,sans-serif;margin:40px"><h2>SecurityInsight</h2><p>The sign-in is complete. You can close this window and return to PowerShell.</p></body></html>'
            } else { '<!doctype html><html><body></body></html>' }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
            try {
                $ctx.Response.StatusCode = 200
                $ctx.Response.ContentType = 'text/html; charset=utf-8'
                $ctx.Response.ContentLength64 = $bytes.Length
                $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
            } finally { $ctx.Response.OutputStream.Close(); $ctx.Response.Close() }
            if ($isAnswer) { return $query }
            # a favicon or a probe: keep listening for the real redirect
        }
    } finally {
        if ($own) { try { $Listener.Stop(); $Listener.Close() } catch { } }
    }
}

# ---------------------------------------------------------------------------------------------------------------
# Token endpoints
# ---------------------------------------------------------------------------------------------------------------
function Invoke-SISignInTokenRequest {
    <# POST to the Entra v2 token endpoint of -TenantId with -Form. Returns the parsed response; throws Entra's own
       error text (AADSTS...) in a customer sentence. #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][System.Collections.IDictionary]$Form, [string]$What = 'Sign-in')
    $pairs = foreach ($k in $Form.Keys) { '{0}={1}' -f $k, [uri]::EscapeDataString([string]$Form[$k]) }
    $uri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f [uri]::EscapeDataString($TenantId)
    $r = Invoke-SIAzRestHttp -Method POST -Uri $uri -Body ($pairs -join '&') -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60
    $code = [int]$r.StatusCode
    $j = $null; try { $j = ([string]$r.Content) | ConvertFrom-Json } catch { }
    if ($code -lt 200 -or $code -ge 300 -or -not $j -or -not $j.access_token) {
        $msg = if ($j -and $j.error_description) { ([string]$j.error_description -split "`r?`n")[0] } elseif ($code -eq 0) { [string]$r.Content } else { [string]$r.Content }
        throw ('{0} failed (HTTP {1}): {2}' -f $What, $code, $msg)
    }
    return $j
}

function Get-SICloudShellToken {
    <# A token for -Resource from the Azure Cloud Shell token endpoint: the person who opened Cloud Shell. #>
    param([Parameter(Mandatory)][string]$Resource)
    $ep = Get-SICloudShellEndpoint
    if (-not $ep) { throw 'This is not Azure Cloud Shell: no Cloud Shell token endpoint (MSI_ENDPOINT) is set.' }
    $res = ($Resource -replace '/\.default$', '').TrimEnd('/') + '/'
    $r = Invoke-SIAzRestHttp -Method POST -Uri $ep -Headers @{ Metadata = 'true' } -Body ('resource=' + [uri]::EscapeDataString($res)) `
             -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60
    $j = $null; try { $j = ([string]$r.Content) | ConvertFrom-Json } catch { }
    if ([int]$r.StatusCode -lt 200 -or [int]$r.StatusCode -ge 300 -or -not $j -or -not $j.access_token) {
        throw ('Azure Cloud Shell did not hand out a token for {0} (HTTP {1}): {2}. Close and reopen Cloud Shell, then run the same command again.' -f $res, $r.StatusCode, $r.Content)
    }
    return [pscustomobject]@{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
}

# ---------------------------------------------------------------------------------------------------------------
# The user session
# ---------------------------------------------------------------------------------------------------------------
function Send-SISignInNotice {
    <#
        #564: says "waiting: sign-in required for <resource> in tenant <t>" BEFORE a browser window opens -- on the console
        and to the host's progress feed: $global:SI_SignInNotify = { param($Resource, $TenantId) ... } (the guided install
        registers it and posts the line as an event, so the status page shows WHY the install waits). Never throws.
    #>
    param([Parameter(Mandatory)][string]$Resource, [string]$TenantId)
    $t = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { 'your organisation' }
    Write-Host ('waiting: sign-in required for {0} in tenant {1}' -f $Resource, $t) -ForegroundColor Yellow
    $n = Get-Variable -Scope Global -Name SI_SignInNotify -ValueOnly -ErrorAction Ignore
    if ($n -is [scriptblock]) { try { & $n $Resource $TenantId } catch { } }
}

function Assert-SISignInTenant {
    <# PURE apart from throwing. #564: a token whose tid is not the target tenant (a wrong browser profile or account) is
       refused before any call is made with it. No target tenant (or not a tenant id) = nothing to compare. #>
    param([AllowEmptyString()][string]$Token, [string]$TenantId, [string]$Where = 'the browser')
    if (-not "$TenantId".Trim() -or "$TenantId" -notmatch '^[0-9a-fA-F-]{36}$') { return }
    $c = ConvertFrom-SISignInJwt $Token
    $tid = if ($c -and $c.PSObject.Properties['tid']) { [string]$c.tid } else { '' }
    if ($tid -and $tid -ne $TenantId) {
        throw ('You signed in to tenant {0} in {1}, but this installation is for tenant {2}. Sign in with an account of tenant {2} (open the address in the browser profile of an admin of that tenant), then run the same command again.' -f $tid, $Where, $TenantId)
    }
}

function Test-SISignInInteractive {
    <# Can this session open a browser for a person? (A seam: tests fake it -- a gate run over SSH is never interactive.) #>
    $interactive = $true
    try { $interactive = [Environment]::UserInteractive } catch { }
    [bool]$interactive
}

function Invoke-SIBrowserCodeSignIn {
    <#
        ONE browser sign-in (authorization code + PKCE on a loopback listener) for -Resource with the public client
        -ClientId. Returns Entra's token response (access_token, refresh_token, expires_in). The account must belong to
        -TenantId (#564). -Prompt '' with a -LoginHint lets the browser reuse the person's sign-in (no account picker).
    #>
    param(
        [string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Resource,
        [string]$LoginHint,
        [string]$Prompt = 'select_account',
        [string]$What = 'Azure Resource Manager',
        [string]$Title = 'Sign in to Azure in your browser.',
        [string]$FailText = 'The Azure sign-in',
        [int]$TimeoutSec = 300
    )
    $pkce = New-SIPkcePair
    $state = New-SIRandomBase64Url -ByteCount 16
    $port = Get-SIFreeLoopbackPort
    $redirect = 'http://localhost:{0}/' -f $port
    $scope = (Get-SISignInScope -Resource $Resource) + ' offline_access openid profile'
    $url = Get-SIAuthorizeUrl -TenantId $TenantId -ClientId $ClientId -RedirectUri $redirect -Scope $scope -CodeChallenge $pkce.Challenge -State $state -LoginHint $LoginHint -Prompt $Prompt
    # #564: the reason for the wait is said BEFORE any window opens; the address is always printed
    Send-SISignInNotice -Resource $What -TenantId $TenantId
    $who = if ($TenantId) { 'an admin of tenant ' + $TenantId } else { 'the admin who installs' }
    Write-Host ''
    Write-Host ('{0} If no window opens, or it opens in the wrong profile or account, open this address in the browser profile of {1}:' -f $Title, $who) -ForegroundColor Cyan
    Write-Host ('  {0}' -f $url)
    $null = Open-SISignInBrowser -Url $url
    $query = Wait-SILoopbackAuthCode -Port $port -TimeoutSec $TimeoutSec
    $code = Resolve-SIAuthRedirect -Query $query -ExpectedState $state
    $authTenant = if ($TenantId) { $TenantId } else { 'organizations' }
    $j = Invoke-SISignInTokenRequest -TenantId $authTenant -What $FailText -Form ([ordered]@{
        client_id     = $ClientId
        grant_type    = 'authorization_code'
        code          = $code
        redirect_uri  = $redirect
        code_verifier = $pkce.Verifier
        scope         = $scope
    })
    # #564: the account must belong to the TARGET tenant -- refused here, before any call uses the token
    Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId $TenantId -Where 'the browser'
    return $j
}

function Connect-SISetupUser {
    <#
        Signs a PERSON in for setup and records the session in this process (memory only).
          -Method Auto       Cloud Shell when this is Cloud Shell, else the browser (code + PKCE on a loopback listener)
          -Method CloudShell the Cloud Shell token endpoint
          -Method Browser    the browser
        -TenantId: the tenant to sign in to (the browser signs in there; Cloud Shell must already be in it).
        Returns the session: Method, TenantId, Account, ObjectId.
    #>
    param(
        [string]$TenantId,
        [ValidateSet('Auto', 'CloudShell', 'Browser', 'Handoff')][string]$Method = 'Auto',
        [string]$LoginHint,
        [int]$TimeoutSec = 300,
        [string]$ClientId
    )
    # #876: a sign-in handed over by the installation page answers first -- nothing is signed in here
    $ho = $null
    if ($Method -in 'Auto', 'Handoff') { $ho = Get-SISetupHandoff -TenantId $TenantId }
    if ($Method -eq 'Handoff' -and -not $ho) { throw 'No sign-in was handed over to this PowerShell session (SI_HANDOFF_TOKENS is not set).' }
    if ($ho) { $Method = 'Handoff' }
    if ($Method -eq 'Auto') { $Method = if (Test-SICloudShell) { 'CloudShell' } else { 'Browser' } }
    $st = Get-SISignInState
    $st.Tokens = @{}
    $st['Exchange'] = $null
    $arm = 'https://management.azure.com/'
    if ($Method -eq 'Handoff') {
        $armTok = $ho.Tokens[$arm]
        if ($armTok.ExpiresAt -le [datetime]::UtcNow.AddMinutes($script:SIHandoffMinMinutes)) { throw (Get-SIHandoffExpiredText -Resource $arm) }
        $st.Session = @{ Method = 'Handoff'; TenantId = $ho.TenantId; Account = $ho.Account; ObjectId = $ho.ObjectId; IsApp = [bool]$ho.IsApp; AppId = $ho.AppId; RefreshToken = $null; ClientId = $null }
        foreach ($k in @($ho.Tokens.Keys)) { $st.Tokens[$k] = @{ Token = $ho.Tokens[$k].Token; ExpiresAt = $ho.Tokens[$k].ExpiresAt } }
        Write-Host ('Using the sign-in handed over by the installation page: {0} {1} (tenant {2}) -- no sign-in here.' -f $(if ($ho.IsApp) { 'the application' } else { 'the account' }), $ho.Account, $ho.TenantId) -ForegroundColor Green
        return [pscustomobject]@{ Method = 'Handoff'; TenantId = $ho.TenantId; Account = $ho.Account; ObjectId = $ho.ObjectId; IsApp = [bool]$ho.IsApp }
    }
    if ($Method -eq 'CloudShell') {
        $t = Get-SICloudShellToken -Resource $arm
        $c = ConvertFrom-SISignInJwt $t.Token
        $tid = if ($c) { [string]$c.tid } else { '' }
        if ($TenantId -and $tid -and $tid -ne $TenantId) {
            throw ("Azure Cloud Shell is signed in to tenant {0}, but this needs tenant {1}. Switch directory in the Azure portal (Settings > Directories), reopen Cloud Shell, then run the same command again." -f $tid, $TenantId)
        }
        $st.Session = @{ Method = 'CloudShell'; TenantId = $tid; Account = (Get-SISignInAccountName $c); ObjectId = $(if ($c) { [string]$c.oid } else { '' }); RefreshToken = $null; ClientId = $null }
        $st.Tokens[$arm] = @{ Token = $t.Token; ExpiresAt = $t.ExpiresAt }
    } else {
        if (Test-SICloudShell) {
            # #564: Cloud Shell has its own token endpoint (-Method CloudShell / Auto); a localhost answer cannot reach it
            throw 'Azure Cloud Shell cannot take the browser sign-in''s answer (it goes to localhost on your own machine). In Cloud Shell setup signs in through Cloud Shell itself: run the same command without asking for the browser sign-in.'
        }
        if (-not (Test-SISignInInteractive)) {
            throw 'A person has to sign in for this step, and this PowerShell session cannot open a browser. Run it in an interactive session or in Azure Cloud Shell, or sign in with an app (certificate or client secret).'
        }
        if (-not $ClientId) { $ClientId = Get-SISignInClientId }
        $j = Invoke-SIBrowserCodeSignIn -TenantId $TenantId -ClientId $ClientId -Resource $arm -LoginHint $LoginHint -TimeoutSec $TimeoutSec
        $c = ConvertFrom-SISignInJwt ([string]$j.access_token)
        $tid = if ($c -and $c.tid) { [string]$c.tid } else { $TenantId }
        $st.Session = @{ Method = 'Browser'; TenantId = $tid; Account = (Get-SISignInAccountName $c); ObjectId = $(if ($c) { [string]$c.oid } else { '' }); RefreshToken = [string]$j.refresh_token; ClientId = $ClientId }
        $st.Tokens[$arm] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
    }
    Write-Host ('Signed in to Azure as {0} (tenant {1}, {2}).' -f $st.Session.Account, $st.Session.TenantId, $(if ($st.Session.Method -eq 'CloudShell') { 'Azure Cloud Shell' } else { 'browser sign-in' })) -ForegroundColor Green
    return [pscustomobject]@{ Method = $st.Session.Method; TenantId = $st.Session.TenantId; Account = $st.Session.Account; ObjectId = $st.Session.ObjectId }
}

function Test-SISetupUserSignedIn {
    $st = Get-SISignInState
    return ($st.Session -is [hashtable])
}

function Get-SISetupUserToken {
    <# A token for -Resource as the signed-in person: memory cache, else the Cloud Shell endpoint or the refresh token. #>
    param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
    $st = Get-SISignInState
    $s = $st.Session
    if (-not ($s -is [hashtable])) { throw 'No one is signed in to Azure in this PowerShell session. Run the same command again to sign in.' }
    $res = ($Resource -replace '/\.default$', '').TrimEnd('/') + '/'
    if ($s.Method -eq 'Handoff') {
        # #876: a handed-over token cannot be renewed here (no refresh token crosses over): one that is about to run out
        # stops the step with one plain line, and the install resumes from that step with a fresh hand-over
        $k = Get-SIHandoffResourceKey $res
        $hit = $null
        foreach ($tk in @($st.Tokens.Keys)) { if ((Get-SIHandoffResourceKey $tk) -eq $k) { $hit = $st.Tokens[$tk]; break } }
        if (-not $hit) {
            throw ('The sign-in handed over by the installation page holds no token for {0}, which this step needs. Nothing more was changed. Restart the install with a hand-over that includes {0} (the install resumes where it stopped).' -f $k.TrimEnd('/'))
        }
        if ($hit.ExpiresAt -le [datetime]::UtcNow.AddMinutes($script:SIHandoffMinMinutes)) { $global:SI_SetupHandoffExpired = $k; throw (Get-SIHandoffExpiredText -Resource $k) }
        return [string]$hit.Token
    }
    if (-not $ForceRefresh -and $st.Tokens.ContainsKey($res) -and $st.Tokens[$res].ExpiresAt -gt [datetime]::UtcNow) { return [string]$st.Tokens[$res].Token }
    if ($s.Method -eq 'CloudShell') {
        $t = Get-SICloudShellToken -Resource $res
        $st.Tokens[$res] = @{ Token = $t.Token; ExpiresAt = $t.ExpiresAt }
        return $t.Token
    }
    if (Test-SISignInExchangeResource -Resource $res) {
        # Exchange Online takes only a token of its own client (Exchange.Manage): its own refresh token, and the first time
        # one more browser sign-in -- the same account pre-filled, so the browser normally signs straight in.
        $xc = Get-SISignInExchangeClientId
        $x = $st['Exchange']
        $j = $null
        if ($x -is [hashtable] -and $x.RefreshToken -and $x.ClientId -eq $xc) {
            try {
                $j = Invoke-SISignInTokenRequest -TenantId $s.TenantId -What 'Getting a token for Exchange Online' -Form ([ordered]@{
                    client_id = $xc; grant_type = 'refresh_token'; refresh_token = $x.RefreshToken; scope = (Get-SISignInScope -Resource $res) + ' offline_access' })
            } catch { $j = $null }
        }
        if (-not $j) {
            if (-not (Test-SISignInInteractive)) { throw 'Exchange Online needs its own sign-in in the browser, and this PowerShell session cannot open a browser. Run it in an interactive PowerShell window.' }
            $j = Invoke-SIBrowserCodeSignIn -TenantId $s.TenantId -ClientId $xc -Resource $res -LoginHint ([string]$s.Account) -Prompt '' `
                     -What 'Exchange Online' -Title 'Sign in once more, for Exchange Online (it accepts only its own sign-in; your account is filled in).' -FailText 'The Exchange Online sign-in'
        }
        $st['Exchange'] = @{ ClientId = $xc; RefreshToken = $(if ($j.refresh_token) { [string]$j.refresh_token } elseif ($x -is [hashtable]) { $x.RefreshToken } else { $null }) }
        Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId ([string]$s.TenantId) -Where 'the token for Exchange Online'
        $st.Tokens[$res] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
        return [string]$j.access_token
    }
    if (-not $s.RefreshToken) { throw 'The Azure sign-in has expired. Run the same command again to sign in.' }
    $j = Invoke-SISignInTokenRequest -TenantId $s.TenantId -What ('Getting a token for {0}' -f $res) -Form ([ordered]@{
        client_id     = $s.ClientId
        grant_type    = 'refresh_token'
        refresh_token = $s.RefreshToken
        scope         = (Get-SISignInScope -Resource $res) + ' offline_access'
    })
    if ($j.refresh_token) { $s.RefreshToken = [string]$j.refresh_token }   # Entra rotates it
    Assert-SISignInTenant -Token ([string]$j.access_token) -TenantId ([string]$s.TenantId) -Where ('the token for ' + $res)
    $st.Tokens[$res] = @{ Token = [string]$j.access_token; ExpiresAt = (Get-SITokenExpiry -Response $j) }
    return [string]$j.access_token
}

function Disconnect-SISetupUser {
    $st = Get-SISignInState
    $st.Session = $null
    $st.Tokens = @{}
    $st['Exchange'] = $null
}
