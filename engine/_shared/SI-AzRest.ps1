#Requires -Version 5.1
<#
    SecurityInsight -- Azure over plain REST, without the Az.* PowerShell modules (REQUIREMENTS 9.3, decision 2:
    "no PS module dependencies ... go pure REST").

    SecurityInsight runs with NO PowerShell modules: every Azure call is plain REST with tokens from SecurityInsight's
    own sign-in (managed identity, certificate client assertion, client secret -- the run's decision). There is no
    switch and no module path: no Az module is loaded, installed or needed anywhere in the runtime.

    The call sites keep the familiar names with 'SIAz' in place of 'Az' (Invoke-SIAzOperationalInsightsQuery,
    Search-SIAzGraph, ...). Each wrapper takes the arguments the call sites pass and does the job over REST (its *Rest
    twin), returning objects with the properties the call sites read. Connect-SIAzAccount only RECORDS which identity to
    sign in as; each REST call mints its token when it needs one.
    The REST building blocks are public and usable directly:
        Get-SIAzureToken -Audience Arm|LaQuery|Storage|KeyVault|Graph      one token function per audience
        Invoke-SILaQuery                                                   Log Analytics data plane (api.loganalytics.io)
        Invoke-SIArm                                                       ARM GET/PUT/PATCH/DELETE, list with nextLink
        Search-SIResourceGraph                                             Resource Graph, every page ($skipToken)
        Get-SIKeyVaultSecretValue                                          one secret, as plain text
        Get-SIBlobContent / Set-SIBlobContent / Get-SIBlobList / ...       blob data plane (OAuth, x-ms-version)
        Send-SIQueueMessage / Receive-SIQueueMessage / Remove-SIQueueMessage
        Get-SITableEntity / Set-SITableEntity                              table data plane (upsert)

    HTTP: every call of this file goes through Invoke-SIAzRestHttp. Token requests (client secret) go through
    SI-LogIngest.ps1's Invoke-SILogIngestHttp -- the same HttpWebRequest shape; tests mock both seams.
    Token hook: $global:SI_TokenProvider = { param($Resource) ... } (a scriptblock returning a bearer token) is consulted
    first by Get-SIAzureToken and Get-SILogIngestToken when set -- for a host with its own sign-in, e.g. setup.

    Retry rule (CLAUDE.md working rule 4): 429 / 408 / 5xx / no response -> wait (Retry-After when sent) and retry
    in-run; 401 once -> refresh the token and repeat once; any other 4xx -> FAIL FAST with the service's own body.

    PS 5.1 safe (no ?. / ??, no RSA.ImportFromPem); works on pwsh 7 and in a Linux container (no Cert: drive needed).
    Ships in both editions and never references a Pro path.
#>

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

# #730: the streaming Log Analytics reader (Invoke-SILaQuery reads Risk Analysis' answers with it; compiled on first use)
if (-not (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore)) {
    $__siLaStream = [System.IO.Path]::Combine($PSScriptRoot, 'SI-LaStreamRead.ps1')
    if ([System.IO.File]::Exists($__siLaStream)) { . $__siLaStream }
}

# ONE connect path (#524, owner 2026-10-09 "modern single connect only"): SecurityInsight's own REST token client --
# managed identity, certificate, client secret (and, in setup, a person's own sign-in). The old sign-in mode "AzContext"
# (#413: borrow the current Azure / Invardia Support session of the process) and its file SI-AzSession.ps1 are gone.
#
# ONE TOKEN SOURCE more for that same path (#524, owner 2026-10-09 via Invardia: "support installs use TOKENS, never the
# secret"): in a shell where Invardia's Connect-InvardiaSupport is open, its function Get-InvardiaSupportToken -Resource <r>
# returns a bearer token as the customer's Invardia support app (cached by Invardia, tid + appid verified there). SI takes
# EVERY token from it -- Mode 'Support' -- and still checks each token's tenant against the tenant it works in. No session
# state is read (only the token), no Az / Graph cmdlet is called. Outside a support session nothing changes.
#
# THE SESSION ITSELF IS USED (owner 2026-10-12: a change in an environment is made inside its Invardia Support session, so
# it is recorded in that environment's audit log). Get-SISupportSession is the ONE place that says whether a session is
# open: Invardia's $global:InvardiaSupportState names a tenant AND its recording command Invoke-InvardiaSupportRequest is
# in the shell. With a session, who SecurityInsight works as (tenant, app, subscriptions) is read from it -- no sign-in of
# SecurityInsight's own and no token request -- and every HTTP call goes through the recording command (Invoke-SISupportHttp).

function Get-SISupportedSignInText {
    <# PURE. The sign-ins SecurityInsight supports, for an error message. #>
    'a managed identity (SI_AuthMethod = ManagedIdentity), an app with a certificate (SI_SPN_AppId + SI_SPN_TenantId + SI_SPN_CertThumbprint), an app with a client secret (SI_SPN_AppId + SI_SPN_TenantId + SI_SPN_Secret), or the tokens of an Invardia support session (Get-InvardiaSupportToken). An Azure session of this PowerShell process (Connect-AzAccount, az login) is never used'
}

function Get-SISupportSession {
    <#
        THE ONE PLACE that says whether an Invardia Support session is open in this PowerShell session, and what it names.
        Open = Invardia's $global:InvardiaSupportState is a hashtable that names a tenant AND its recording command
        Invoke-InvardiaSupportRequest is here (Test-Path Function: -- never Get-Command, which can load a module).
        $null when there is none (Disconnect-InvardiaSupport empties the state). Never guessed: a state WITHOUT the
        recording command is said and stops the caller -- nothing could be recorded.
        Returns TenantId, AppId, Environment (the handle), EnvironmentId, SessionId, Subscriptions (lower case; the ones the
        environment names), SubscriptionId (the first of them, '' when it names none), SubscriptionName.
    #>
    $s = Get-Variable -Scope Global -Name InvardiaSupportState -ValueOnly -ErrorAction Ignore
    if (-not ($s -is [hashtable])) { return $null }
    $tid = [string]$s['TenantId']
    if ([string]::IsNullOrWhiteSpace($tid)) { return $null }
    if (-not (Test-Path -LiteralPath 'Function:\Invoke-InvardiaSupportRequest')) {
        throw ('An Invardia Support session is noted in this PowerShell session (tenant {0}), but its recording command Invoke-InvardiaSupportRequest is not here, so nothing SecurityInsight does could be recorded. Nothing was done. Open the session again (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>''), or end it (Disconnect-InvardiaSupport) and work with your own sign-in.' -f $tid)
    }
    $subs = @(@($s['Subscriptions']) | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
    $first = ''
    if ($subs.Count) { $first = [string]$subs[0] }
    return [pscustomobject]@{
        TenantId = $tid.Trim(); AppId = [string]$s['AppId']; Environment = [string]$s['Environment']; EnvironmentId = [string]$s['EnvironmentId']
        SessionId = [string]$s['SessionId']; Subscriptions = [string[]]$subs; SubscriptionId = $first; SubscriptionName = [string]$s['SubscriptionName']
    }
}

function Get-SISupportSessionName {
    <# PURE. How a Support session is named in a message: its environment handle, else its tenant. #>
    param($Session)
    if ($Session -and [string]$Session.Environment) { return [string]$Session.Environment }
    if ($Session) { return ('tenant {0}' -f $Session.TenantId) }
    return ''
}

function Assert-SISupportSubscription {
    <# In a Support session only a subscription the environment names is worked in: any other is REFUSED (throws). A session
       whose environment names no subscription refuses none (Invardia's own rule). No session = nothing to check. #>
    param([string]$SubscriptionId, $Session)
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { return }
    if (-not $Session) { $Session = Get-SISupportSession }
    if (-not $Session) { return }
    $named = @($Session.Subscriptions)
    if ($named.Count -and $named -notcontains $SubscriptionId.Trim().ToLowerInvariant()) {
        throw ('Subscription {0} is not one the Invardia Support session for {1} names ({2}) -- refused, nothing was done there. Use a subscription of this environment, or open the Support session of the environment that owns {0}.' -f $SubscriptionId, (Get-SISupportSessionName $Session), ($named -join ', '))
    }
}

function Test-SISupportTokenSource {
    <# Is an Invardia Support session open in this shell? (Get-SISupportSession decides -- the one place.) #>
    return [bool](Get-SISupportSession)
}

function Get-SISupportExpectedTenantId {
    <# The tenant SI works in, which the Support session must be for: -TenantId, else the configured one. Empty = the
       session's own. #>
    param([string]$TenantId)
    if ($TenantId) { return $TenantId }
    return [string](Get-SIAzRestValue 'SI_SPN_TenantId', 'SpnTenantId', 'AzureTenantId', 'TenantId')
}

function Get-SISupportToken {
    <#
        A bearer token for -Resource from the Invardia Support session; its 'tid' must be -TenantId (refused otherwise).
        ONLY for what has no HTTP request the recording command can send -- the SQL sign-in of a database step, the
        container registry's own token exchange, reading who the Support app is from its token. Invardia records that the
        token was issued; what is done with it is not recorded. Every HTTP call goes through Invoke-SISupportHttp instead
        and asks for no token here.
    #>
    param([Parameter(Mandatory)][string]$Resource, [string]$TenantId, [switch]$ForceRefresh)
    if (-not (Get-SISupportSession)) { throw 'No Invardia Support session is open in this PowerShell session (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>'').' }
    if (-not (Test-Path -LiteralPath 'Function:\Get-InvardiaSupportToken')) { throw ('The Invardia Support session in this PowerShell session has no token command (Get-InvardiaSupportToken), so no token for {0} can be taken from it. Open the session again (Connect-InvardiaSupport).' -f $Resource) }
    $p = @{ Resource = $Resource.TrimEnd('/') }
    if ($ForceRefresh) { $p['ForceRefresh'] = $true }
    $tok = [string](Get-InvardiaSupportToken @p)
    if ([string]::IsNullOrWhiteSpace($tok)) { throw ('The Invardia support session returned no token for {0}.' -f $Resource) }
    $c = ConvertFrom-SIJwtPayload $tok
    if (-not $c -or -not [string]$c.tid) { throw ('The Invardia support token for {0} could not be read (no tenant in it) -- refused.' -f $Resource) }
    if ($TenantId -and [string]$c.tid -ne $TenantId) {
        throw ('The Invardia support token for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f $Resource, $c.tid, $TenantId)
    }
    return $tok
}

function Get-SISupportAuth {
    <# The Auth hashtable of the Invardia Support session: Mode 'Support', app + tenant + first subscription read from the
       SESSION (Get-SISupportSession) -- no token is asked for. Refused when the session is for another tenant than
       -TenantId / the configured one. ObjectId is not known here (Get-SISetupSignedInObjectId finds it when asked). #>
    param([string]$TenantId)
    $sess = Get-SISupportSession
    if (-not $sess) { throw 'No Invardia Support session is open in this PowerShell session (Connect-InvardiaSupport -Environment <handle> -Reason ''<why>'').' }
    $want = Get-SISupportExpectedTenantId -TenantId $TenantId
    if ($want -and $want -ne $sess.TenantId) {
        throw ('The Invardia Support session for {0} is for tenant {1}, not {2} -- refused. Connect the support session of tenant {2}.' -f (Get-SISupportSessionName $sess), $sess.TenantId, $want)
    }
    return @{ Mode = 'Support'; AppId = [string]$sess.AppId; TenantId = [string]$sess.TenantId; ObjectId = $null; SubscriptionId = [string]$sess.SubscriptionId
              Environment = [string]$sess.Environment; EnvironmentId = [string]$sess.EnvironmentId; SessionId = [string]$sess.SessionId }
}

function Sync-SISupportConnection {
    <#
        Keeps the recorded sign-in of this process in step with the Invardia Support session, and returns the session
        ($null = none):
          * no session, but the recorded sign-in is a Support one  -> the session was closed: the sign-in is dropped
          * a session and no recorded sign-in (or one of ANOTHER session) -> the session becomes the sign-in
          * a session and a recorded sign-in of SecurityInsight's own -> kept, unless -TakeOver (setup: a Support session
            in the shell always wins there -- setup never works beside it with a sign-in of its own)
        Says ONE plain line the first time a session is used. Throws what Get-SISupportSession / Get-SISupportAuth refuse.
    #>
    param([switch]$TakeOver)
    $sess = Get-SISupportSession
    $st = Get-SIAzRestState
    $c = $st.Connection
    $isSupport = ($c -is [hashtable]) -and ([string]$c.Mode -eq 'Support')
    if (-not $sess) {
        if ($isSupport) { $st.Connection = $null; $st.TenantId = $null; $st.SubscriptionId = $null; $st.Cache = @{} }
        return $null
    }
    $same = $isSupport -and ([string]$c.TenantId -eq $sess.TenantId) -and ([string]$c.SessionId -eq $sess.SessionId) -and ([string]$c.EnvironmentId -eq $sess.EnvironmentId)
    if ($same) { return $sess }
    if (($c -is [hashtable]) -and -not $isSupport -and -not $TakeOver) { return $sess }
    $st.Connection = Get-SISupportAuth
    $st.TenantId = [string]$sess.TenantId
    $st.Cache = @{}
    if ($st.SubscriptionId -and @($sess.Subscriptions).Count -and @($sess.Subscriptions) -notcontains ([string]$st.SubscriptionId).Trim().ToLowerInvariant()) { $st.SubscriptionId = $null }
    $key = '{0}|{1}|{2}' -f $sess.TenantId, $sess.EnvironmentId, $sess.SessionId
    if ([string]$st['SupportSaid'] -ne $key) {
        $st['SupportSaid'] = $key
        Write-Host ('using the Invardia Support session for {0} -- every change is recorded there' -f (Get-SISupportSessionName $sess))
    }
    return $sess
}

function Test-SISupportRecorderPresent {
    <# #548: is an Invardia Support session, with its RECORDING wrapper, open in this shell? (Get-SISupportSession decides.) #>
    return [bool](Get-SISupportSession)
}

function Test-SISupportRequestRoute {
    <#
        #548 (Invardia, 2026-10-10: every Support app action is recorded in the customer's audit log): does a request for
        -Audience, as -Auth (none = the run's own sign-in), go through Invardia's recording wrapper? Yes when a Support
        session is open (Get-SISupportSession) AND the call is made as the support session (Mode 'Support' -- the recorded
        sign-in, or no recorded sign-in at all) AND no host token provider ($global:SI_TokenProvider) answers instead.
        Every audience SecurityInsight signs in to: Arm, Graph, Log Analytics, Storage, Exchange Online's admin API, Key
        Vault and Azure Monitor -- on any host (a host the wrapper does not know by itself gets its token audience named,
        Get-SISupportTokenResource). A URL that is none of these (-Audience Other: another service with its own key) is
        not a call as the support app and never goes through it. -Uri is accepted for callers that pass it.
    #>
    param([string]$Audience = 'Arm', [hashtable]$Auth, [string]$Uri)
    if ($Audience -notin 'Arm', 'Graph', 'LaQuery', 'Storage', 'Exchange', 'KeyVault', 'Monitor') { return $false }
    if ($Auth) {
        if ([string]$Auth.Mode -ne 'Support') { return $false }
        return [bool](Get-SISupportSession)
    }
    $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
    if ($tp -is [scriptblock]) { return $false }
    # a caller that loaded only part of this file (a script's own fakes, a lifted function) has no state helpers -- and no
    # support session either
    if (-not (Test-Path -LiteralPath 'Function:\Get-SIAzRestState')) { return $false }
    if (-not (Test-Path -LiteralPath 'Function:\Sync-SISupportConnection')) { return $false }
    if (-not (Sync-SISupportConnection)) { return $false }
    $c = (Get-SIAzRestState).Connection
    return (($c -is [hashtable]) -and ([string]$c.Mode -eq 'Support'))
}

function Get-SISupportTokenResource {
    <# PURE. The token audience to NAME to the recording wrapper for a request it cannot name from the URL's host by
       itself: a Key Vault or Azure Monitor URL on another host than <vault>.vault.azure.net /
       <endpoint>.ingest.monitor.azure.com. '' = the wrapper names it (Arm, Graph, Log Analytics, Storage, Exchange). #>
    param([string]$Audience, [string]$Uri)
    $h = ''
    try { $h = ([uri]$Uri).Host } catch { $h = '' }
    if ($Audience -eq 'KeyVault' -and $h -notmatch '(?i)\.vault\.azure\.net$') { return 'https://vault.azure.net' }
    if ($Audience -eq 'Monitor' -and $h -notmatch '(?i)\.ingest\.monitor\.azure\.com$') { return 'https://monitor.azure.com' }
    return ''
}

function Test-SISupportReadOnlyPost {
    <#
        PURE. Is this POST a READ (recorded as a read, not as a change)? Only the POSTs known to change nothing:
          ARM    Resource Graph (/providers/Microsoft.ResourceGraph/resources), a provider's checkNameAvailability, a
                 workspace query (.../workspaces/<name>/query, /api/query)
          Log Analytics   /v1/workspaces/<id>/query
          Graph  getByIds, getMemberObjects, getMemberGroups, checkMemberObjects, checkMemberGroups, security/runHuntingQuery
                 (a KQL hunting query), and a $batch whose
                 requests are ALL GET
        Anything else -- and anything not understood -- is a CHANGE. A GET / HEAD is a read by its method (not asked here).
    #>
    param([string]$Method, [string]$Uri, $Body)
    if (([string]$Method).ToUpperInvariant() -ne 'POST') { return $false }
    $u = $null
    try { $u = [uri]$Uri } catch { return $false }
    if (-not $u -or -not $u.IsAbsoluteUri) { return $false }
    $h = $u.Host.ToLowerInvariant(); $p = $u.AbsolutePath
    if ($h -match '^management\.(azure\.com|core\.windows\.net)$') {
        if ($p -match '(?i)^/providers/Microsoft\.ResourceGraph/resources/?$') { return $true }
        if ($p -match '(?i)/providers/[^/]+/checkNameAvailability/?$') { return $true }
        if ($p -match '(?i)/providers/Microsoft\.OperationalInsights/workspaces/[^/]+/(api/)?query/?$') { return $true }
        return $false
    }
    if ($h -eq 'api.loganalytics.io' -or $h -eq 'api.loganalytics.azure.com') { return [bool]($p -match '(?i)^/v1/workspaces/[^/]+/query/?$') }
    if ($h -eq 'graph.microsoft.com') {
        if ($p -match '(?i)/(getByIds|getMemberObjects|getMemberGroups|checkMemberObjects|checkMemberGroups)/?$') { return $true }
        # Defender advanced hunting: a KQL query, which can only read
        if ($p -match '(?i)^/(v1\.0|beta)/security/runHuntingQuery/?$') { return $true }
        if ($p -match '(?i)^/(v1\.0|beta)/\$batch/?$') {
            try {
                $text = ''
                if ($Body -is [byte[]]) { $text = [System.Text.Encoding]::UTF8.GetString($Body) } else { $text = [string]$Body }
                $reqs = @(($text | ConvertFrom-Json).requests | Where-Object { $null -ne $_ })
                if (-not $reqs.Count) { return $false }
                return (-not @($reqs | Where-Object { ([string]$_.method).ToUpperInvariant() -ne 'GET' }).Count)
            } catch { return $false }
        }
        return $false
    }
    return $false
}

function Test-SISupportBodyIsText {
    <# PURE. Can -Body go through Invardia's recording wrapper? Yes for every body: the wrapper sends a [byte[]] body
       unchanged (Invardia, 2026-10-10). Kept as the one place to say otherwise. #>
    param($Body, [string]$ContentType)
    return $true
}

function Invoke-SISupportHttp {
    <#
        #548: ONE HTTP exchange through Invardia's recording wrapper, in the shape of Invoke-SIAzRestHttp (StatusCode,
        Content, Bytes, Headers, RetryAfter) so Invoke-SIAzRestRequest's retry and error rules stay exactly as they are
        (an HTTP status >= 400 becomes SecurityInsight's own error there). The wrapper adds the support app's token: an
        Authorization header of the caller is dropped. No answer = StatusCode 0 (retried like any network failure); a
        refusal to record the action in the customer's audit log is RETHROWN (fail-closed: the action was not made).
        A GET / HEAD is a read by its method; a POST that only reads (Test-SISupportReadOnlyPost) is sent -ReadOnly;
        everything else is recorded as a change. An Azure Resource Manager URL of a subscription the session's environment
        does not name is REFUSED before anything is sent (Assert-SISupportSubscription). -Audience names the token audience
        for a host the wrapper does not know (Get-SISupportTokenResource); -TimeoutSec is passed on.
    #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [switch]$AsBytes,
          [string]$Audience, [int]$TimeoutSec = 0)
    $sess = Get-SISupportSession
    if (-not $sess) { throw 'No Invardia support session is open in this PowerShell session, so this request cannot be sent through it.' }
    $target = $null
    try { $target = [uri]$Uri } catch { $target = $null }
    if ($target -and $target.IsAbsoluteUri -and $target.Host -match '(?i)^management\.(azure\.com|core\.windows\.net)$' -and
        $target.AbsolutePath -match '(?i)^/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)') {
        Assert-SISupportSubscription -SubscriptionId $Matches[1] -Session $sess
    }
    $h = @{}
    if ($Headers) { foreach ($k in @($Headers.Keys)) { if ([string]$k -ine 'Authorization' -and [string]$k -ine 'Content-Type') { $h[[string]$k] = $Headers[$k] } elseif ([string]$k -ieq 'Content-Type' -and -not $ContentType) { $ContentType = [string]$Headers[$k] } } }
    $p = @{ Method = $Method.ToUpperInvariant(); Uri = $Uri }
    if ($h.Count) { $p.Headers = $h }
    if ($null -ne $Body) {
        # bytes go unchanged (a source package upload). NOT $(if ...): a subexpression ENUMERATES the byte array into an
        # object[] -- the wrapper then sent it as JSON numbers instead of the file
        if ($Body -is [byte[]]) { $p.Body = $Body } else { $p.Body = [string]$Body }
        if ($ContentType) { $p.ContentType = $ContentType }
    }
    $o = $null
    if ($AsBytes) { $p.AsBytes = $true }   # the raw answer as ContentBytes (a download)
    if (Test-SISupportReadOnlyPost -Method $Method -Uri $Uri -Body $Body) { $p.ReadOnly = $true }   # a POST that only reads
    if ($TimeoutSec -gt 0) { $p.TimeoutSec = $TimeoutSec }
    $tokenResource = Get-SISupportTokenResource -Audience $Audience -Uri $Uri
    if ($tokenResource) { $p.TokenResource = $tokenResource }
    try { $o = Invoke-InvardiaSupportRequest @p }
    catch {
        $m = [string]$_.Exception.Message
        if ($m -match '(?i)audit log|fail-closed|could not be recorded|No Invardia support session') { throw }
        return [pscustomobject]@{ StatusCode = 0; Content = $m; Bytes = $null; Headers = @{}; RetryAfter = $null }
    }
    $hh = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
    if ($o -and $o.Headers) {
        try {
            if ($o.Headers -is [System.Collections.IDictionary]) { foreach ($k in @($o.Headers.Keys)) { $hh[[string]$k] = (@($o.Headers[$k]) | ForEach-Object { [string]$_ }) -join ',' } }
            else { foreach ($k in @($o.Headers.AllKeys)) { $hh[[string]$k] = [string]$o.Headers[$k] } }
        } catch { }
    }
    $text = if ($o) { [string]$o.Content } else { '' }
    # the raw answer as [byte[]] -- assigned in statements, never through $( ... ), which would enumerate it into object[]
    [byte[]]$raw = $null
    if ($AsBytes) {
        if ($o -and $o.PSObject.Properties['ContentBytes'] -and $o.ContentBytes) { $raw = [byte[]]$o.ContentBytes } else { $raw = [System.Text.Encoding]::UTF8.GetBytes($text) }
    }
    $out = [pscustomobject]@{
        StatusCode = $(if ($o) { [int]$o.StatusCode } else { 0 }); Content = $(if ($AsBytes) { '' } else { $text })
        Bytes = $null; Headers = $hh; RetryAfter = [string]$hh['Retry-After']
    }
    $out.Bytes = $raw
    $out
}

function Invoke-SIRestMethod {
    <#
        #548: the drop-in for Invoke-RestMethod that setup's own Graph / ARM calls use (-Method, -Uri, -Headers with the
        caller's bearer token, -Body, -ContentType): inside an Invardia support session the call goes through the recording
        wrapper (the caller's Authorization header is dropped -- the wrapper signs as the support app); otherwise exactly
        Invoke-RestMethod. Throws on HTTP >= 400 like Invoke-RestMethod, with the service's answer in the message; returns
        the parsed JSON (or the text when it is not JSON).
    #>
    [CmdletBinding()]   # -ErrorAction and the other common parameters, as Invoke-RestMethod callers pass them
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, [hashtable]$Headers, $Body, [string]$ContentType, [int]$TimeoutSec = 120)
    $host_ = ([uri]$Uri).Host
    $aud = if ($host_ -eq 'graph.microsoft.com') { 'Graph' } elseif ($host_ -match '^management\.(azure\.com|core\.windows\.net)$') { 'Arm' } elseif ($host_ -eq 'api.loganalytics.io') { 'LaQuery' } elseif ($host_ -eq 'outlook.office365.com') { 'Exchange' } else { 'Other' }
    # this function is published GLOBALLY: a caller that never loaded this file (a script run on its own, a test with its
    # own fakes) has no routing helpers -- and then no support session either: plain Invoke-RestMethod
    if ((Test-Path -LiteralPath 'Function:\Test-SISupportRequestRoute') -and (Test-SISupportRequestRoute -Audience $aud)) {
        $b = $Body
        if ($null -ne $b -and -not ($b -is [string]) -and -not ($b -is [byte[]])) { $b = ConvertTo-Json -InputObject $b -Depth 30 -Compress }
        $ct = if ($ContentType) { $ContentType } elseif ($null -ne $b) { 'application/json' } else { '' }
        $r = Invoke-SISupportHttp -Method $Method -Uri $Uri -Headers $Headers -Body $b -ContentType $ct -Audience $aud -TimeoutSec $TimeoutSec
        $code = [int]$r.StatusCode
        if ($code -lt 200 -or $code -ge 300) {
            throw (New-SIAzRestError -Message ('{0} {1} failed. HTTP Status: {2} ({3}) Response: {4}' -f $Method.ToUpperInvariant(), ($Uri -replace '\?.*$', ''), $code, (Get-SIAzRestStatusName $code), $r.Content) -Response $r)
        }
        $t = [string]$r.Content
        if (-not $t.Trim()) { return $null }
        try { return ($t | ConvertFrom-Json) } catch { return $t }
    }
    $a = @{ Method = $Method; Uri = $Uri; ErrorAction = 'Stop'; TimeoutSec = $TimeoutSec }
    if ($Headers) { $a.Headers = $Headers }
    if ($null -ne $Body) { $a.Body = $Body }
    if ($ContentType) { $a.ContentType = $ContentType }
    Invoke-RestMethod @a
}
# published globally: a product script the install runs (in this process) finds it even when it loaded only part of the layer
Set-Item -Path 'function:global:Invoke-SIRestMethod' -Value ${function:Invoke-SIRestMethod}

# =====================================================================================================================
#  The wrapper map, shared state
# =====================================================================================================================

function Get-SIAzRestWrapperMap {
    <# wrapper -> the Az cmdlet it replaces -> its REST twin, as data. The wiring tests read it. #>
    $m = [ordered]@{}
    foreach ($az in @(
        'Connect-AzAccount', 'Disconnect-AzAccount', 'Disable-AzContextAutosave', 'Get-AzContext', 'Set-AzContext',
        'Get-AzAccessToken', 'Get-AzSubscription', 'Invoke-AzRestMethod',
        'Invoke-AzOperationalInsightsQuery', 'Get-AzOperationalInsightsWorkspace', 'New-AzOperationalInsightsWorkspace',
        'Search-AzGraph', 'Get-AzKeyVaultSecret', 'Set-AzKeyVaultSecret',
        'Get-AzResourceGroup', 'New-AzResourceGroup', 'Get-AzRoleAssignment', 'New-AzRoleAssignment', 'Get-AzRoleDefinition',
        'Get-AzTag', 'Update-AzTag', 'Get-AzADServicePrincipal',
        'Get-AzDataCollectionEndpoint', 'New-AzDataCollectionEndpoint', 'Get-AzDataCollectionRule',
        'New-AzStorageContext', 'Get-AzStorageAccount', 'New-AzStorageAccount',
        'Get-AzStorageContainer', 'New-AzStorageContainer', 'Get-AzStorageBlob', 'Get-AzStorageBlobContent',
        'Set-AzStorageBlobContent', 'Remove-AzStorageBlob', 'Start-AzStorageBlobCopy',
        'Get-AzStorageQueue', 'New-AzStorageQueue')) {
        $w = $az -replace '-Az', '-SIAz'
        $m[$w] = @{ Replaces = $az; Rest = ($w + 'Rest') }
    }
    return $m
}

function Get-SIAzRestState {
    <# Per-process state: the recorded sign-in, the current subscription, token / lookup caches. Global because this
       file is dot-sourced at different depths by different engines. #>
    # StrictMode-safe: an unset global is read through Get-Variable, never directly (a caller may run Set-StrictMode).
    if (-not ((Get-Variable -Scope Global -Name SI_AzRestState -ValueOnly -ErrorAction Ignore) -is [hashtable])) {
        $global:SI_AzRestState = @{ Connection = $null; SubscriptionId = $null; TenantId = $null; Cache = @{} }
    }
    return $global:SI_AzRestState
}

function Initialize-SIAzRestHelpers {
    <# The token functions (SI-LogIngest.ps1), the KQL error reader (SI-KqlError.ps1) and the certificate helpers
       (auth/Find-SICertificate.ps1). Loaded on first need; only what is MISSING is loaded and published globally, so a
       caller's own copy or a test's mock is never replaced. #>
    $want = @(
        @{ Path = (Join-Path $PSScriptRoot 'SI-LogIngest.ps1'); Fns = @('Get-SILogIngestToken', 'Invoke-SILogIngestHttp', 'Get-SILogIngestRunCache', 'Get-SILogIngestRetryDelay', 'Initialize-SILogIngestAuthHelpers') }
        @{ Path = (Join-Path $PSScriptRoot 'SI-KqlError.ps1');   Fns = @('Get-SIKqlErrorText', 'Get-SIKqlErrorSummary', 'Test-SIKqlTableMissing') }
        @{ Path = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Find-SICertificate.ps1'); Fns = @('Get-SICertificateClientToken', 'Get-SICertificateFromStore', 'Test-SICertDriveAvailable') }
    )
    foreach ($w in $want) {
        $missing = @($w.Fns | Where-Object { -not (Get-Command -Name $_ -ErrorAction Ignore) })
        if ($missing.Count -eq 0) { continue }
        if (-not (Test-Path -LiteralPath $w.Path)) { continue }
        . $w.Path
        foreach ($n in $missing) {
            $f = Get-Command -Name $n -CommandType Function -ErrorAction Ignore
            if ($f) { Set-Item -Path ("function:global:{0}" -f $n) -Value $f.ScriptBlock }
        }
    }
}

# =====================================================================================================================
#  HTTP seam, sign-in, tokens
# =====================================================================================================================

function Remove-SIAzRestCaughtError {
    <# Takes a HANDLED error record back out of $global:Error (newest entries only). PS 5.1 safe. #>
    param($Record)
    if ($null -eq $Record) { return }
    $errs = $global:Error
    for ($i = 0; $i -lt [Math]::Min(3, $errs.Count); $i++) {
        $e = $errs[$i]
        if ([object]::ReferenceEquals($e, $Record) -or ($e -is [System.Management.Automation.ErrorRecord] -and $Record -is [System.Management.Automation.ErrorRecord] -and [object]::ReferenceEquals($e.Exception, $Record.Exception))) {
            $errs.RemoveAt($i); return
        }
    }
}

function Invoke-SIAzRestHttp {
    <#
        THE ONE HTTP SEAM of this file (tests Mock it). Never throws on an HTTP status: returns
        @{ StatusCode; Content; Bytes; Headers; RetryAfter }. A network failure (no response) is StatusCode 0.
        HttpWebRequest, not Invoke-WebRequest: the 4xx body and headers read the same way on PS 5.1 and pwsh 7.
        -AsBytes keeps the body as bytes (blob downloads); Content is then ''.
    #>
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        $Body,
        [string]$ContentType,
        [int]$TimeoutSec = 300,
        [switch]$AsBytes,
        # A 2xx body read AS IT ARRIVES (SI-LaStreamRead.ps1): { param([IO.Stream]$Stream) <the parsed answer> } -- the body
        # is never held whole; the answer is returned as .Parsed (Content '', Bytes $null). Any other status: as without it.
        [scriptblock]$ReadStream
    )
    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = $Method.ToUpperInvariant()
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.Accept = 'application/json'
    if ($Headers) {
        foreach ($k in $Headers.Keys) {
            if ($k -eq 'Content-Type') { $req.ContentType = [string]$Headers[$k] }
            elseif ($k -eq 'Accept')   { $req.Accept = [string]$Headers[$k] }
            else { $req.Headers[$k] = [string]$Headers[$k] }
        }
    }
    if ($ContentType) { $req.ContentType = $ContentType }
    if ($null -ne $Body) {
        # statements, never `= if (...) { $Body }`: an if-expression ENUMERATES a byte array into object[] (one boxed object
        # per byte) -- a build context of tens of MB became gigabytes and the updater ran out of memory
        [byte[]]$bytes = $null
        if ($Body -is [byte[]]) { $bytes = $Body } else { $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Body) }
        $req.ContentLength = $bytes.Length
        # A connection that fails while the BODY is sent (connect, DNS, reset) is "no answer" (StatusCode 0), which the caller
        # retries -- for a request that is safe to send again (PUT / PATCH / DELETE / MERGE: idempotent, as an ARM or table PUT
        # is). A POST that failed here is thrown as before: it is not repeated blindly. (The sweep of 2026-10-22: this threw
        # past every retry loop on blob, table and ARM writes.)
        try {
            $s = $req.GetRequestStream()
            try { $s.Write($bytes, 0, $bytes.Length) } finally { $s.Close() }
        } catch {
            if ($req.Method -eq 'POST') { throw }
            return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; Bytes = $null; Headers = @{}; RetryAfter = $null }
        }
    } elseif ($req.Method -in 'POST', 'PUT', 'PATCH', 'MERGE') {
        $req.ContentLength = 0
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch {
        $we = $_.Exception
        while ($we -and -not ($we -is [System.Net.WebException])) { $we = $we.InnerException }
        if ($we -and $we.Response) {
            $resp = $we.Response
            # An HTTP status is an ANSWER, returned to the caller (who decides whether a 404 is "not there" or a failure)
            # -- not an error of this process. PowerShell still records the caught exception in $Error, and setup shows
            # every new $Error entry: each "does it exist?" probe printed "(404) Not Found" (live 2026-10-06). Drop it.
            Remove-SIAzRestCaughtError -Record $_
        }
        else { return [pscustomobject]@{ StatusCode = 0; Content = [string]$_.Exception.Message; Bytes = $null; Headers = @{}; RetryAfter = $null } }
    }
    try {
        $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($k in $resp.Headers.AllKeys) { $h[$k] = [string]$resp.Headers[$k] }
        $text = ''; $raw = $null
        $rs = $resp.GetResponseStream()
        $sc = [int]$resp.StatusCode
        if ($rs -and $ReadStream -and $sc -ge 200 -and $sc -lt 300) {
            $parsed = $null
            try { $parsed = & $ReadStream $rs } finally { $rs.Close() }
            return [pscustomobject]@{ StatusCode = $sc; Content = ''; Bytes = $null; Headers = $h; RetryAfter = [string]$h['Retry-After']; Parsed = $parsed }
        }
        if ($rs) {
            # #639: the body is read ONCE into an array of its own length when the service says how long it is -- not into a
            # growing buffer that is then copied again (a large answer was held two or three times before it was parsed)
            try {
                $len = [long]$resp.ContentLength
                if ($len -gt 0 -and $len -lt [int]::MaxValue) {
                    $raw = [byte[]]::new([int]$len); $off = 0
                    while ($off -lt $len) { $n = $rs.Read($raw, $off, [int]($len - $off)); if ($n -le 0) { break }; $off += $n }
                    if ($off -lt $len) { $part = [byte[]]::new($off); [Array]::Copy($raw, $part, $off); $raw = $part; $part = $null }
                } else {
                    $ms = New-Object System.IO.MemoryStream
                    $rs.CopyTo($ms); $raw = $ms.ToArray(); $ms.Dispose(); $ms = $null
                }
            } finally { $rs.Close() }
            if (-not $AsBytes) { $text = [System.Text.Encoding]::UTF8.GetString($raw); $raw = $null }
        }
        return [pscustomobject]@{ StatusCode = [int]$resp.StatusCode; Content = $text; Bytes = $raw; Headers = $h; RetryAfter = [string]$h['Retry-After'] }
    } finally { $resp.Close() }
}

function Get-SIAzRestValue {
    <# The first non-empty global of -Names. #>
    param([string[]]$Names)
    foreach ($n in $Names) {
        $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction Ignore
        if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { return [string]$v }
    }
    return $null
}

function Resolve-SIAzRestAuth {
    <#
        WHO this run signs in as, for the REST path:
          1. what Connect-SIAzAccount recorded in this process (the launcher / container entry point decided)
          1b. an Invardia Support session open in this shell (Mode 'Support', read from the session)
          2. the run's managed-identity switch (SI_UseManagedIdentity / UseManagedIdentity, #222)
          3. an SPN certificate   (SI_SPN_AppId | SpnClientId | HighPriv_* + SI_SPN_CertThumbprint | SpnCertificateThumbprint)
          4. an SPN client secret (SI_SPN_Secret | SpnClientSecret | HighPriv_*)
        Certificate before secret, as everywhere in SecurityInsight. Returns the Auth hashtable Get-SILogIngestToken
        takes. Throws when nothing is configured -- the REST path never falls back to an Az session.
    #>
    # An Invardia Support session in this shell: it IS the sign-in when nothing else was recorded (and a Support sign-in
    # whose session was closed is dropped) -- Sync-SISupportConnection, read from the session, no token asked for.
    $null = Sync-SISupportConnection
    $st = Get-SIAzRestState
    if ($st.Connection -is [hashtable]) { return $st.Connection }
    # #524: the retired sign-in mode "AzContext" (borrow this process's Azure session) is refused by name
    if ([string](Get-Variable -Scope Global -Name SI_AuthMethod -ValueOnly -ErrorAction Ignore) -eq 'AzContext') {
        throw ('SI_AuthMethod = AzContext (use the current Azure session of this PowerShell process) is no longer supported: SecurityInsight signs in itself. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
    }
    if ([bool](Get-Variable -Scope Global -Name SI_UseManagedIdentity -ValueOnly -ErrorAction Ignore) -or [bool](Get-Variable -Scope Global -Name UseManagedIdentity -ValueOnly -ErrorAction Ignore)) {
        return @{ Mode = 'ManagedIdentity'; ClientId = [string](Get-SIAzRestValue 'SI_UAMI_ClientId', 'SI_ManagedIdentityClientId') }
    }
    $tid   = Get-SIAzRestValue 'SI_SPN_TenantId', 'SpnTenantId', 'HighPriv_Modern_TenantID', 'AzureTenantId', 'TenantId'
    $app   = Get-SIAzRestValue 'SI_SPN_AppId', 'SpnClientId', 'HighPriv_Modern_ApplicationID_Azure'
    $thumb = Get-SIAzRestValue 'SI_SPN_CertThumbprint', 'SpnCertificateThumbprint', 'HighPriv_Modern_CertificateThumbprint_Azure'
    $sec   = Get-SIAzRestValue 'SI_SPN_Secret', 'SpnClientSecret', 'HighPriv_Modern_Secret_Azure', 'HighPriv_Modern_ApplicationSecret_Azure'
    if ($app -and $thumb -and $tid) { return @{ Mode = 'Certificate'; AppId = $app; TenantId = $tid; Thumbprint = ($thumb -replace '\s', '') } }
    if ($app -and $sec -and $tid)   { return @{ Mode = 'Secret'; AppId = $app; TenantId = $tid; Secret = $sec } }
    throw ('No sign-in is configured for Azure access over REST. Supported sign-ins: {0}.' -f (Get-SISupportedSignInText))
}

function Get-SIAzureAudience {
    <# The token resource of each audience the REST path talks to. #>
    param([Parameter(Mandatory)][ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience)
    switch ($Audience) {
        'Arm'      { 'https://management.azure.com/' }
        'LaQuery'  { 'https://api.loganalytics.io/' }
        'Storage'  { 'https://storage.azure.com/' }
        'KeyVault' { 'https://vault.azure.net/' }
        'Graph'    { 'https://graph.microsoft.com/' }
        'Monitor'  { 'https://monitor.azure.com/' }
    }
}

function Get-SIAzureToken {
    <#
        ONE token function for every audience: a bearer token as the identity Resolve-SIAzRestAuth names, minted by
        Get-SILogIngestToken (managed identity endpoint / certificate client assertion / client secret), cached per
        identity + audience until 5 minutes before expiry. -Audience or a raw -Resource; -Auth overrides the identity.
    #>
    param(
        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
        [string]$Resource,
        [hashtable]$Auth,
        [switch]$ForceRefresh
    )
    if (-not $Resource) { $Resource = Get-SIAzureAudience -Audience $Audience }
    # A host that signs in its own way (setup, a test) can supply tokens: $global:SI_TokenProvider = { param($Resource) <token> }.
    # Consulted first, only when no explicit -Auth was passed; an empty answer falls through to SecurityInsight's own sign-in.
    if (-not $Auth) {
        $tp = Get-Variable -Scope Global -Name SI_TokenProvider -ValueOnly -ErrorAction Ignore
        if ($tp -is [scriptblock]) { $pt = [string](& $tp $Resource); if (-not [string]::IsNullOrWhiteSpace($pt)) { return $pt } }
    }
    Initialize-SIAzRestHelpers
    if (-not $Auth) { $Auth = Resolve-SIAzRestAuth }
    return (Get-SILogIngestToken -Resource $Resource -Auth $Auth -ForceRefresh:$ForceRefresh)
}

function ConvertFrom-SIJwtPayload {
    <# PURE. The claims of a JWT (no signature check -- only used to read tid / exp / appid of our own token). #>
    param([string]$Token)
    $parts = ([string]$Token) -split '\.'
    if ($parts.Count -lt 2) { return $null }
    $p = $parts[1].Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } }
    try { return ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json) } catch { return $null }
}

function New-SIAzRestError {
    <# An exception carrying the service's response (Response.StatusCode / Content / Headers), so the existing readers
       (Get-SIKqlErrorText, the ledger's 412 match, ...) find what the service said. #>
    param([string]$Message, $Response)
    $ex = New-Object System.Exception($Message)
    if ($Response) {
        $r = [pscustomobject]@{ StatusCode = [int]$Response.StatusCode; Content = [string]$Response.Content; Headers = $Response.Headers }
        Add-Member -InputObject $ex -NotePropertyName Response -NotePropertyValue $r -Force
    }
    return $ex
}

function Get-SIAzRestStatusName {
    param([int]$Code)
    if ($Code -le 0) { return 'NoResponse' }
    try { return [string][System.Net.HttpStatusCode]$Code } catch { return [string]$Code }
}

function Invoke-SIAzRestRequest {
    <#
        One authenticated REST call with the retry rule:
          429 / 408 / 5xx / no response -> PLATFORM: wait (Retry-After when sent) and retry in-run
          401 once                      -> refresh the token, repeat once
          404 with -AllowNotFound       -> $null
          any other 4xx                 -> FAIL FAST with the body
        Returns the response (StatusCode / Content / Bytes / Headers).
    #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('Arm', 'LaQuery', 'Storage', 'KeyVault', 'Graph', 'Monitor')][string]$Audience = 'Arm',
        $Body,
        [string]$ContentType = 'application/json',
        [hashtable]$Headers,
        [switch]$AllowNotFound,
        [int[]]$AllowStatus = @(),
        [switch]$AsBytes,
        [int]$TimeoutSec = 300,
        [int]$MaxAttempts = 6,
        [string]$What = 'Azure request',
        [hashtable]$Auth,  # another identity than the run's (the platform sign-in reads its Key Vault as the bootstrap identity)
        # a 2xx body read as it arrives (Invoke-SIAzRestHttp -ReadStream); not through an Invardia support session, whose
        # recording wrapper hands the answer back whole
        [scriptblock]$ReadStream
    )
    $refreshed = $false; $force = $false
    # #548: inside an Invardia support session every call SecurityInsight makes as the support app goes through Invardia's
    # RECORDING wrapper (Invoke-InvardiaSupportRequest: the customer's audit log, fail-closed) -- never a raw token + HTTP.
    # Every body and every answer goes through the wrapper: a binary body is sent unchanged, a binary answer (a download)
    # comes back as its ContentBytes (Invardia, 2026-10-10).
    $viaSupport = (Test-SISupportBodyIsText -Body $Body -ContentType $ContentType) -and (Test-SISupportRequestRoute -Audience $Audience -Auth $Auth -Uri $Uri)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        if ($viaSupport) {
            $h = @{}
            if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
            $r = Invoke-SISupportHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -AsBytes:$AsBytes -Audience $Audience -TimeoutSec $TimeoutSec
        } else {
            $token = Get-SIAzureToken -Audience $Audience -Auth $Auth -ForceRefresh:$force
            $force = $false
            $h = @{ 'Authorization' = ('Bearer ' + $token) }
            if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
            if ($ReadStream) { $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec -AsBytes:$AsBytes -ReadStream $ReadStream }
            else { $r = Invoke-SIAzRestHttp -Method $Method -Uri $Uri -Headers $h -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec -AsBytes:$AsBytes }
        }
        $code = [int]$r.StatusCode
        if ($code -ge 200 -and $code -lt 300) { return $r }
        if ($AllowStatus -contains $code) { return $r }
        if ($code -eq 404 -and $AllowNotFound) { return $null }
        if ($code -eq 401 -and -not $refreshed) { $refreshed = $true; $force = $true; continue }
        $transient = ($code -eq 0 -or $code -eq 408 -or $code -eq 429 -or $code -ge 500)
        if ($transient -and $attempt -lt $MaxAttempts) {
            Initialize-SIAzRestHelpers
            $wait = Get-SILogIngestRetryDelay -RetryAfter ([string]$r.RetryAfter) -Attempt $attempt
            Write-Verbose ("{0}: HTTP {1}, retrying in {2}s (attempt {3}/{4})" -f $What, $code, $wait, $attempt, $MaxAttempts)
            Start-Sleep -Seconds $wait
            continue
        }
        $body = [string]$r.Content
        if ($AsBytes -and $r.Bytes) { try { $body = [System.Text.Encoding]::UTF8.GetString($r.Bytes) } catch { } }
        $errCode = ''
        if ($r.Headers -and $r.Headers['x-ms-error-code']) { $errCode = ' ' + [string]$r.Headers['x-ms-error-code'] }
        $resp = [pscustomobject]@{ StatusCode = $code; Content = $body; Headers = $r.Headers }
        throw (New-SIAzRestError -Message ("{0} failed. HTTP Status: {1} ({2}){3} Response: {4}" -f $What, $code, (Get-SIAzRestStatusName $code), $errCode, $body) -Response $resp)
    }
    throw ("{0} failed after {1} attempts." -f $What, $MaxAttempts)
}

# =====================================================================================================================
#  ARM, Resource Graph, Key Vault, Log Analytics
# =====================================================================================================================

function Test-SIArmBusyError {
    <# PURE. #564: an ARM refusal that means "another operation on this resource is still running" (HTTP 409
       OperationInProgress and its per-service names) -- a wait, not a failure. A plain 409 Conflict ("already exists") is NOT. #>
    param([AllowEmptyString()][string]$Message)
    [bool]("$Message" -match '(?i)\w*OperationInProgress|operation is (still )?in progress|another operation is (in progress|ongoing|running)|active provisioning operation|is currently being (updated|provisioned)')
}

function Invoke-SIArmWriteBusyRetry {
    <#
        #564 (PIM's install at customer I, 2026-10-10): ONE ARM write (PUT / PATCH / POST / DELETE) with a BOUNDED wait for a busy
        resource: a write seconds after another change to the same resource is refused "409 OperationInProgress". Waits
        $global:SI_ArmBusyWaits (default 6 x 20 s) between attempts, RE-READS the resource before each retry (PUT / PATCH /
        DELETE: what Azure has now), and after a write that had to wait READS IT BACK until it is provisioned (about 60 s).
        Any other failure is rethrown at once WITH ITS OWN ERROR; the last busy failure is rethrown after the last wait.
        NOT a closure (a GetNewClosure() block cannot see the functions this file defines). $global:SI_ArmBusySleep
        { param($Seconds) } is the test seam for the waits. Returns the response (Invoke-SIAzRestRequest's shape).
    #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Uri, $Json, [switch]$AllowNotFound, [string]$What = 'Azure Resource Manager write')
    $waits = @(20, 20, 20, 20, 20, 20)
    $gw = Get-Variable -Scope Global -Name SI_ArmBusyWaits -ValueOnly -ErrorAction Ignore
    if ($null -ne $gw) { $waits = @($gw | ForEach-Object { [int]$_ }) }
    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
    $verb = $Method.ToUpperInvariant()
    $resourceUri = if ($verb -in 'PUT', 'PATCH', 'DELETE') { $Uri } else { $null }
    $try = 0; $waited = $false
    while ($true) {
        try { $r = Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Body $Json -AllowNotFound:$AllowNotFound -What $What; break }
        catch {
            if (-not (Test-SIArmBusyError -Message ([string]$_.Exception.Message)) -or $try -ge $waits.Count) { throw }
            $w = [int]$waits[$try]; $try++; $waited = $true
            Write-Host ('       Azure is still busy with another change to {0} -- waiting {1} s, then trying again ({2}/{3}) ...' -f (($Uri -replace '\?.*$', '') -split '/')[-1], $w, $try, $waits.Count) -ForegroundColor DarkYellow
            if ($w -gt 0) { if ($sleep -is [scriptblock]) { & $sleep $w } else { Start-Sleep -Seconds $w } }
            # re-read before the retry: what Azure has now (never fails the write -- the retry decides)
            if ($resourceUri) { try { $null = Invoke-SIAzRestRequest -Method GET -Uri $resourceUri -AllowNotFound -What ('Reading ' + $What) } catch { } }
        }
    }
    if ($waited -and $verb -in 'PUT', 'PATCH') {
        # read back: the write that waited is followed until Azure has provisioned it (bounded, about 60 s)
        for ($i = 0; $i -lt 6; $i++) {
            $back = $null
            try { $back = Invoke-SIAzRestRequest -Method GET -Uri $resourceUri -AllowNotFound -What ('Reading back ' + $What) } catch { break }
            $ps = ''
            try { $ps = [string](($back.Content | ConvertFrom-Json).properties.provisioningState) } catch { $ps = '' }
            if (-not $ps -or $ps -in 'Succeeded', 'Failed', 'Canceled', 'Cancelled') { break }
            if ($sleep -is [scriptblock]) { & $sleep 10 } else { Start-Sleep -Seconds 10 }
        }
    }
    $r
}

function Invoke-SIArm {
    <#
        Azure Resource Manager. -Path is '/subscriptions/...' (or a full https:// URL, e.g. a nextLink); -ApiVersion is
        appended when the path has none. Returns the parsed body ($null for a 404 with -AllowNotFound).
        -List returns every item of a list, following nextLink.
    #>
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Path,
        [string]$ApiVersion,
        $Body,
        [switch]$AllowNotFound,
        [switch]$List
    )
    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
    if ($ApiVersion -and $uri -notmatch '[?&]api-version=') { $uri += $(if ($uri -match '\?') { '&' } else { '?' }) + 'api-version=' + $ApiVersion }
    $json = if ($null -ne $Body -and -not ($Body -is [string])) { $Body | ConvertTo-Json -Depth 50 -Compress } else { $Body }
    # #564 (PIM's install at customer I, 2026-10-10): an ARM POST ACTION with no body (listSecrets, listCredentials, listKeys,
    # sharedKeys, a revision restart, a provider register) sends '{}' -- an empty body with a JSON content type was
    # refused with HTTP 415.
    if ($Method.ToUpperInvariant() -eq 'POST' -and ($null -eq $json -or ([string]$json) -eq '')) { $json = '{}' }
    $what = 'Azure Resource Manager {0} {1}' -f $Method, ($uri -replace '\?.*$', '')
    if (-not $List) {
        if ($Method.ToUpperInvariant() -eq 'GET') { $r = Invoke-SIAzRestRequest -Method $Method -Uri $uri -Body $json -AllowNotFound:$AllowNotFound -What $what }
        else { $r = Invoke-SIArmWriteBusyRetry -Method $Method -Uri $uri -Json $json -AllowNotFound:$AllowNotFound -What $what }
        if (-not $r -or [string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
        return ($r.Content | ConvertFrom-Json)
    }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $uri
    while ($next) {
        $r = Invoke-SIAzRestRequest -Method 'GET' -Uri $next -AllowNotFound:$AllowNotFound -What $what
        if (-not $r) { break }
        $page = $r.Content | ConvertFrom-Json
        foreach ($v in @($page.value)) { if ($null -ne $v) { [void]$items.Add($v) } }
        $next = [string]$page.nextLink
    }
    return $items.ToArray()
}

function Search-SIResourceGraph {
    <# Resource Graph: EVERY row of -Query, following $skipToken. -Subscription / -ManagementGroup scope it; neither =
       every subscription the identity can read (as Search-AzGraph without them). #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [string[]]$Subscription,
        [string[]]$ManagementGroup,
        [int]$PageSize = 1000
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = $null
    do {
        $page = Invoke-SIResourceGraphPage -Query $Query -Subscription $Subscription -ManagementGroup $ManagementGroup -First $PageSize -SkipToken $skip
        foreach ($d in @($page.Data)) { if ($null -ne $d) { [void]$rows.Add($d) } }
        $skip = [string]$page.SkipToken
    } while ($skip)
    return $rows.ToArray()
}

function Invoke-SIResourceGraphPage {
    <# ONE Resource Graph page: @{ Data; SkipToken; TotalRecords }. #>
    param([string]$Query, [string[]]$Subscription, [string[]]$ManagementGroup, [int]$First = 1000, [int]$Skip = 0, [string]$SkipToken)
    $opt = [ordered]@{ resultFormat = 'objectArray'; '$top' = $First }
    if ($Skip -gt 0) { $opt['$skip'] = $Skip }
    if ($SkipToken) { $opt['$skipToken'] = $SkipToken }
    $body = [ordered]@{ query = $Query; options = $opt }
    $subs = @(@($Subscription) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $mgs  = @(@($ManagementGroup) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($subs.Count) { $body['subscriptions'] = [string[]]$subs }
    if ($mgs.Count) { $body['managementGroups'] = [string[]]$mgs }
    $r = Invoke-SIAzRestRequest -Method POST -Uri 'https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01' `
             -Body ($body | ConvertTo-Json -Depth 10 -Compress) -What 'Resource Graph query'
    $j = $r.Content | ConvertFrom-Json
    $tok = $null
    if ($j.PSObject.Properties['$skipToken']) { $tok = [string]$j.'$skipToken' }
    return [pscustomobject]@{ Data = @($j.data); SkipToken = $tok; TotalRecords = $j.totalRecords }
}

function Get-SIKeyVaultSecretValue {
    <# One Key Vault secret as plain text; $null when the secret does not exist. #>
    param([Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$Name, [string]$Version, [hashtable]$Auth)
    $j = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name -Version $Version -Auth $Auth
    if (-not $j) { return $null }
    return [string]$j.value
}

function Get-SIKeyVaultSecretRaw {
    param([string]$VaultName, [string]$Name, [string]$Version, [hashtable]$Auth)
    $v = if ($Version) { '/' + $Version } else { '' }
    $uri = 'https://{0}.vault.azure.net/secrets/{1}{2}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name), $v
    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience KeyVault -AllowNotFound -Auth $Auth -What ("Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
    if (-not $r) { return $null }
    return ($r.Content | ConvertFrom-Json)
}

function ConvertTo-SIAzLaCellString {
    <# One Log Analytics cell, as Az.OperationalInsights hands it to callers: TEXT. Strings and dates stay as the
       service sent them, numbers keep their JSON spelling, booleans are 'true' / 'false', null stays null, nested
       values are JSON text. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.FFFFFFFZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
    return (ConvertTo-Json -InputObject $Value -Depth 20 -Compress)
}

function ConvertFrom-SILaQueryJson {
    <#
        The Log Analytics query response -> @{ Tables = @( @{ Name; Columns = @(@{name;type}); Rows = @(@(cells as text)) } ); Error }.
        pwsh 7: System.Text.Json, so a date stays the exact text the service sent (ConvertFrom-Json would turn it into a
        local DateTime). Windows PowerShell 5.1: ConvertFrom-Json, which leaves dates as text.
    #>
    param([Parameter(Mandatory)][string]$Json)
    $tables = [System.Collections.Generic.List[object]]::new()
    $err = $null
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $doc = [System.Text.Json.JsonDocument]::Parse($Json)
        try {
            $root = $doc.RootElement
            $tEl = [System.Text.Json.JsonElement]::new()
            if ($root.TryGetProperty('tables', [ref]$tEl)) {
                foreach ($t in $tEl.EnumerateArray()) {
                    $cols = [System.Collections.Generic.List[object]]::new()
                    foreach ($c in $t.GetProperty('columns').EnumerateArray()) {
                        $ty = [System.Text.Json.JsonElement]::new(); $tyS = ''
                        if ($c.TryGetProperty('type', [ref]$ty)) { $tyS = $ty.GetString() }
                        [void]$cols.Add([pscustomobject]@{ name = $c.GetProperty('name').GetString(); type = $tyS })
                    }
                    $rows = [System.Collections.Generic.List[object]]::new()
                    foreach ($row in $t.GetProperty('rows').EnumerateArray()) {
                        $cells = [System.Collections.Generic.List[object]]::new()
                        foreach ($cell in $row.EnumerateArray()) {
                            switch ($cell.ValueKind.ToString()) {
                                'String' { [void]$cells.Add($cell.GetString()) }
                                'Null'   { [void]$cells.Add($null) }
                                'True'   { [void]$cells.Add('true') }
                                'False'  { [void]$cells.Add('false') }
                                default  { [void]$cells.Add($cell.GetRawText()) }
                            }
                        }
                        [void]$rows.Add($cells.ToArray())
                    }
                    $nm = [System.Text.Json.JsonElement]::new(); $nmS = ''
                    if ($t.TryGetProperty('name', [ref]$nm)) { $nmS = $nm.GetString() }
                    [void]$tables.Add([pscustomobject]@{ Name = $nmS; Columns = $cols.ToArray(); Rows = $rows.ToArray() })
                }
            }
            $eEl = [System.Text.Json.JsonElement]::new()
            if ($root.TryGetProperty('error', [ref]$eEl) -and $eEl.ValueKind.ToString() -ne 'Null') { $err = ($eEl.GetRawText() | ConvertFrom-Json) }
        } finally { $doc.Dispose() }
    } else {
        $j = $Json | ConvertFrom-Json
        foreach ($t in @($j.tables)) {
            if ($null -eq $t) { continue }
            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($row in @($t.rows)) {
                $cells = [System.Collections.Generic.List[object]]::new()
                foreach ($cell in @($row)) { [void]$cells.Add((ConvertTo-SIAzLaCellString $cell)) }
                [void]$rows.Add($cells.ToArray())
            }
            [void]$tables.Add([pscustomobject]@{ Name = [string]$t.name; Columns = @($t.columns); Rows = $rows.ToArray() })
        }
        if ($j.PSObject.Properties['error'] -and $j.error) { $err = $j.error }
    }
    return [pscustomobject]@{ Tables = $tables.ToArray(); Error = $err }
}

function Get-SILaCompactRowType {
    <#
        #711. A .NET class for one column list: one public text property per column, in the column order, built from the
        row's values in one call (new(string[])). Built once per column list and process (Add-Type, pwsh 7 / .NET 8) and
        reused. $null when it cannot be built -- a column name that is not a plain identifier, two names that differ only in
        case (PowerShell reads properties without case), Windows PowerShell -- and the caller keeps PSCustomObject rows.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Names)
    if ($PSVersionTable.PSEdition -ne 'Core' -or $Names.Count -eq 0) { return $null }
    if ($null -eq $script:SILaCompactRowTypes) { $script:SILaCompactRowTypes = @{} }
    $key = ($Names -join "`n")
    if ($script:SILaCompactRowTypes.ContainsKey($key)) { return $script:SILaCompactRowTypes[$key] }
    $type = $null
    try {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($n in $Names) { if ($n -notmatch '^[A-Za-z_][A-Za-z0-9_]*$' -or -not $seen.Add($n)) { throw ('not a plain column name: {0}' -f $n) } }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key))) -replace '-', '').Substring(0, 20) } finally { $sha.Dispose() }
        $cls = 'R' + $h
        $full = 'SecurityInsight.LaRows.' + $cls
        $type = $full -as [type]
        if ($null -eq $type) {
            $sb = New-Object System.Text.StringBuilder
            [void]$sb.Append('namespace SecurityInsight.LaRows { public sealed class ').Append($cls).Append(' { ')
            foreach ($n in $Names) { [void]$sb.Append('public string @').Append($n).Append(' { get; set; } ') }
            [void]$sb.Append('public ').Append($cls).Append('(string[] v) { ')
            for ($i = 0; $i -lt $Names.Count; $i++) { [void]$sb.Append('this.@').Append($Names[$i]).Append(' = v[').Append($i).Append(']; ') }
            [void]$sb.Append('} } }')
            Add-Type -TypeDefinition $sb.ToString() -Language CSharp -ErrorAction Stop
            $type = $full -as [type]
        }
    } catch { $type = $null }
    $script:SILaCompactRowTypes[$key] = $type
    return $type
}

function ConvertFrom-SILaQueryRows {
    <#
        The Log Analytics query response AS THE BYTES THE SERVICE SENT -> @{ Rows; Error }: the primary table's rows, one
        object per row, one TEXT property per column -- the same rows Invoke-SILaQuery hands out as .Results.
        For large answers (Invoke-SILaQuery -RowsOnly): the bytes are parsed where they are. The answer is never also held
        as one text (twice its size), as a second copy of every table, or as a list of cells per row -- on a large install
        those copies together ran a job out of memory. pwsh 7 only (System.Text.Json).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    $rows = [System.Collections.Generic.List[object]]::new()
    $cols = [System.Collections.Generic.List[object]]::new()
    $err = $null
    $doc = [System.Text.Json.JsonDocument]::Parse([System.ReadOnlyMemory[byte]]::new($Bytes))
    try {
        $root = $doc.RootElement
        $tEl = [System.Text.Json.JsonElement]::new()
        if ($root.TryGetProperty('tables', [ref]$tEl)) {
            # the table named PrimaryResult, else the first one -- as .Results has always been chosen
            $have = $false
            $pick = [System.Text.Json.JsonElement]::new()
            foreach ($t in $tEl.EnumerateArray()) {
                $nm = [System.Text.Json.JsonElement]::new(); $nmS = ''
                if ($t.TryGetProperty('name', [ref]$nm)) { $nmS = [string]$nm.GetString() }
                if (-not $have) { $pick = $t; $have = $true }
                if ($nmS -eq 'PrimaryResult') { $pick = $t; break }
            }
            if ($have) {
                $names = [System.Collections.Generic.List[string]]::new()
                foreach ($c in $pick.GetProperty('columns').EnumerateArray()) {
                    $names.Add([string]$c.GetProperty('name').GetString())
                    $ty = [System.Text.Json.JsonElement]::new(); $tyS = $null
                    if ($c.TryGetProperty('type', [ref]$ty)) { $tyS = $ty.GetString() }
                    $cols.Add([pscustomobject]@{ name = $names[$names.Count - 1]; type = $tyS })
                }
                $nCols = $names.Count
                # #711: a caller that keeps the rows for long (Risk Analysis' lookups) asks for COMPACT rows -- one small
                # .NET object per row with one text property per column (Get-SILaCompactRowType), not a PSCustomObject
                # (measured on the test VM: ~6 KB per row of 11 columns as a PSCustomObject). Read the same way by
                # every reader ($row.Col, $row.PSObject.Properties['Col'].Value). Not available -> the rows as always.
                $compactType = $null
                if ([bool]$global:SI_LaCompactRows) { $compactType = Get-SILaCompactRowType -Names $names.ToArray() }
                if ($null -ne $compactType) {
                    # a short value that repeats (a tier, a flag, an empty text, a short factor list) is held once per read
                    $pool = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
                    foreach ($row in $pick.GetProperty('rows').EnumerateArray()) {
                        # a null cell is left as the array's own null (assigning $null to a [string] element would make it '')
                        $vals = [string[]]::new($nCols)
                        $i = 0
                        foreach ($cell in $row.EnumerateArray()) {
                            if ($i -ge $nCols) { break }
                            $kind = $cell.ValueKind.ToString()
                            if ($kind -ne 'Null') {
                                $s = if ($kind -eq 'String') { $cell.GetString() } elseif ($kind -eq 'True') { 'true' } elseif ($kind -eq 'False') { 'false' } else { $cell.GetRawText() }
                                if ($s.Length -le 32) { $p0 = $null; if ($pool.TryGetValue($s, [ref]$p0)) { $s = $p0 } else { $pool[$s] = $s } }
                                $vals[$i] = $s
                            }
                            $i++
                        }
                        [void]$rows.Add($compactType::new($vals))
                    }
                    $nCols = -1
                }
                if ($nCols -ge 0) {
                foreach ($row in $pick.GetProperty('rows').EnumerateArray()) {
                    $o = [ordered]@{}
                    $i = 0
                    foreach ($cell in $row.EnumerateArray()) {
                        if ($i -ge $nCols) { break }
                        $name = $names[$i]
                        $kind = $cell.ValueKind.ToString()
                        if ($kind -eq 'String') { $o[$name] = $cell.GetString() }
                        elseif ($kind -eq 'Null') { $o[$name] = $null }
                        elseif ($kind -eq 'True') { $o[$name] = 'true' }
                        elseif ($kind -eq 'False') { $o[$name] = 'false' }
                        else { $o[$name] = $cell.GetRawText() }
                        $i++
                    }
                    # a row shorter than its columns: the missing ones are empty, as before
                    for (; $i -lt $nCols; $i++) { $o[$names[$i]] = $null }
                    [void]$rows.Add([pscustomobject]$o)
                }
                }
            }
        }
        $eEl = [System.Text.Json.JsonElement]::new()
        if ($root.TryGetProperty('error', [ref]$eEl) -and $eEl.ValueKind.ToString() -ne 'Null') { $err = ($eEl.GetRawText() | ConvertFrom-Json) }
    } finally { $doc.Dispose() }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Columns = $cols.ToArray(); Error = $err }
}

function Get-SILaServiceRowLimit {
    <# The most rows ONE Log Analytics query answer carries (the service's own limit). An answer holding exactly that many
       rows cannot be told from an answer the service cut there. $global:SI_LaServiceRowLimit overrides it (tests). #>
    $v = 0L
    try { $v = [long]$global:SI_LaServiceRowLimit } catch { $v = 0L }
    if ($v -gt 0) { return $v }
    return 500000L
}

function Get-SILaPartialVerdict {
    <#
        PURE. What a Log Analytics partial answer (the "error" object beside the rows of an HTTP 200 answer) says, read from
        its LEAVES (the innermost error objects -- the outer ones are generic). Returns @{ Kind; Code; Detail; Tables }:
          Unresolved  every leaf is "Failed to resolve table or column expression named 'SI_..._CL'": a `union isfuzzy=true`
                      leg over a SecurityInsight table this workspace does not have yet. The answer IS the whole result (the
                      missing table has no rows) -- the one partial answer that is not a cut one.
          Limit       a leaf names a limit (rows / size / time / memory): the answer is CUT; a smaller read fixes it.
          Other       anything else: the answer is short, and a smaller read does not fix it.
        The same reading as Risk Analysis' own (RA-LaPartedRead.ps1 Get-RALaPartialVerdict); kept here so every reader of
        Log Analytics refuses a cut answer, not only Risk Analysis.
        -MayBeMissing (2026-10-23): other tables the CALLER names that this workspace may not have (the capability probe's
        SecurityIncident / SecurityAlert in a workspace without Sentinel): a leaf that cannot resolve one of them is
        Unresolved too -- the answer is whole, the table has no rows. Only the tables named; never any other.
    #>
    param([AllowNull()][object]$ErrorObject, [string[]]$MayBeMissing = @())
    $leaves = New-Object System.Collections.Generic.List[string]
    $all = New-Object System.Collections.Generic.List[string]
    $codes = New-Object System.Collections.Generic.List[string]
    $get = {
        param($o, $n)
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }
        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value }; return $null
    }
    $stack = New-Object System.Collections.Stack
    if ($null -ne $ErrorObject -and $ErrorObject -isnot [string]) { $stack.Push($ErrorObject) }
    $visited = 0
    while ($stack.Count -gt 0 -and $visited -lt 256) {
        $o = $stack.Pop(); $visited++
        if ($null -eq $o -or $o -is [string]) { continue }
        $m = [string](& $get $o 'message'); $c = [string](& $get $o 'code')
        if ($c -and $codes.Count -lt 3 -and -not $codes.Contains($c)) { $codes.Add($c) }
        if ($m) { $all.Add($m) }
        $children = New-Object System.Collections.Generic.List[object]
        $ie = & $get $o 'innererror'; if ($null -ne $ie -and $ie -isnot [string]) { $children.Add($ie) }
        $ds = & $get $o 'details'
        if ($null -ne $ds) { foreach ($d in @($ds)) { if ($null -ne $d -and $d -isnot [string]) { $children.Add($d) } } }
        if ($children.Count -eq 0) { if ($m) { $leaves.Add($m) } }
        else { for ($i = $children.Count - 1; $i -ge 0; $i--) { $stack.Push($children[$i]) } }
    }
    if ($null -ne $ErrorObject -and $ErrorObject -is [string]) { $leaves.Add([string]$ErrorObject); $all.Add([string]$ErrorObject) }
    $generic = '^(There were some errors when processing your query\.?|Something went wrong processing your query on the server\.?)$'
    $specific = @($all | Where-Object { $_ -notmatch $generic } | Select-Object -Unique)
    $detail = (@($specific) -join '; ')
    if (-not $detail) { $detail = (@($all | Select-Object -Unique) -join '; ') }
    if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + '...' }
    $code = (@($codes) -join '/')
    # a 'union' leaf says "table expression", a 'where' leaf "table or column expression" (both: the table is not there)
    $rx = "Failed to resolve table (?:or column )?expression named '(?<t>[A-Za-z0-9_]+)'"
    $okMissing = { param($t) ($t -match '^SI_[A-Za-z0-9_]+_CL$') -or (@($MayBeMissing | Where-Object { $_ -and [string]$_ -ieq $t }).Count -gt 0) }
    $tables = New-Object System.Collections.Generic.List[string]
    $leafSpecific = @($leaves | Where-Object { $_ -notmatch $generic })
    $allResolve = ($leafSpecific.Count -gt 0)
    foreach ($l in $leafSpecific) {
        $mm = [regex]::Match($l, $rx)
        if (-not $mm.Success -or -not (& $okMissing $mm.Groups['t'].Value)) { $allResolve = $false; break }
        if (-not $tables.Contains($mm.Groups['t'].Value)) { $tables.Add($mm.Groups['t'].Value) }
    }
    if ($allResolve) { return @{ Kind = 'Unresolved'; Code = $code; Detail = $detail; Tables = $tables.ToArray() } }
    $limitRx = '(?i)limit|exceeded|too large|E_QUERY_RESULT_SET_TOO_LARGE|timed out|timeout|E_RUNAWAY|out of memory|memory|truncat|cancell?ed|preempted'
    if (@($all | Where-Object { $_ -match $limitRx }).Count -gt 0) { return @{ Kind = 'Limit'; Code = $code; Detail = $detail; Tables = @() } }
    return @{ Kind = 'Other'; Code = $code; Detail = $detail; Tables = @() }
}

function Test-SILaAnswerWhole {
    <#
        PURE. Is a Log Analytics answer the WHOLE result? -ErrorObject: the partial-error object beside the rows; -Rows: how
        many rows the answer held. Returns @{ Whole; Kind; Code; Detail; Tables; Rows }:
          no error and fewer rows than the service's own row limit   -> whole
          an Unresolved partial error (a missing SI table in a fuzzy union)  -> whole (the missing table has no rows)
          a Limit / Other partial error                              -> NOT whole
          no error, but exactly as many rows as the service's limit  -> NOT whole (Limit): it cannot be told from a cut answer
    #>
    # -MayBeMissing: as Get-SILaPartialVerdict (the tables the caller names that the workspace may not have)
    param([AllowNull()][object]$ErrorObject, [long]$Rows = 0, [string[]]$MayBeMissing = @())
    if ($null -ne $ErrorObject) {
        $v = Get-SILaPartialVerdict -ErrorObject $ErrorObject -MayBeMissing $MayBeMissing
        return @{ Whole = ($v.Kind -eq 'Unresolved'); Kind = $v.Kind; Code = $v.Code; Detail = $v.Detail; Tables = $v.Tables; Rows = $Rows }
    }
    $cap = Get-SILaServiceRowLimit
    if ($Rows -ge $cap) {
        $d = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, 'the answer holds {0:N0} rows, the most one answer carries (the service''s limit of {1:N0} rows) -- it cannot be told from a cut answer', $Rows, $cap)
        return @{ Whole = $false; Kind = 'Limit'; Code = 'RowLimit'; Detail = $d; Tables = @(); Rows = $Rows }
    }
    return @{ Whole = $true; Kind = ''; Code = ''; Detail = ''; Tables = @(); Rows = $Rows }
}

function New-SILaCutAnswerError {
    <#
        The error a refused cut answer becomes (Invoke-SILaQuery without -AllowPartial). An ErrorRecord whose exception
        carries the service's own words three ways, so every classifier that reads a failed query finds them:
          * the message: "Log Analytics returned a PARTIAL answer (<code>: <detail>) -- ..."; a Limit also says "Query
            execution has exceeded the allowed limits" (the text Risk Analysis' bucket logic makes a slice smaller on);
          * Exception.Response.Content and ErrorDetails: the error object as JSON (Get-SIKqlErrorText -> the data sync's
            "too large" check, Test-SIDataResponseTooLarge, cuts that page in two);
          * Exception.Data: SILaPartial / SIRALaPartial = the kind, SIRALaPartialRows = the rows the short answer held (Risk
            Analysis' parted reader measures with them).
    #>
    param([Parameter(Mandatory)][hashtable]$Verdict, [AllowNull()][object]$ErrorObject, [string]$WorkspaceId = '')
    $msg = if ($Verdict.Kind -eq 'Limit') {
        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- Query execution has exceeded the allowed limits; the rows it returned are not the whole result and were not used" -f $Verdict.Code, $Verdict.Detail
    } else {
        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- the rows it returned are not the whole result and were not used" -f $Verdict.Code, $Verdict.Detail
    }
    $json = ''
    if ($null -ne $ErrorObject) { try { $json = ConvertTo-Json -InputObject ([pscustomobject]@{ error = $ErrorObject }) -Depth 12 -Compress } catch { $json = [string]$ErrorObject } }
    else { $json = ConvertTo-Json -InputObject ([pscustomobject]@{ error = [pscustomobject]@{ code = [string]$Verdict.Code; message = [string]$Verdict.Detail } }) -Depth 4 -Compress }
    $ex = New-SIAzRestError -Message $msg -Response ([pscustomobject]@{ StatusCode = 200; Content = $json; Headers = @{} })
    $ex.Data['SILaPartial'] = [string]$Verdict.Kind
    $ex.Data['SIRALaPartial'] = [string]$Verdict.Kind
    $ex.Data['SIRALaPartialRows'] = [long]$Verdict.Rows
    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'SILaQueryPartial', [System.Management.Automation.ErrorCategory]::LimitsExceeded, $WorkspaceId)
    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($json)
    return $er
}

function Test-SILaCutAnswerError {
    <# PURE. Was this failure a cut answer Invoke-SILaQuery refused (New-SILaCutAnswerError)? -Kind: only that kind. #>
    param([AllowNull()][object]$Err, [string]$Kind = '')
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('SILaPartial')) { return ((-not $Kind) -or ([string]$ex.Data['SILaPartial'] -eq $Kind)) }
        $ex = $ex.InnerException
    }
    return $false
}

function Invoke-SILaQuery {
    <#
        A KQL query on the Log Analytics DATA PLANE: POST https://api.loganalytics.io/v1/workspaces/{id}/query. Not the
        ARM /api/query route, which hides the semantic error behind a generic one.
        Returns the shape Invoke-AzOperationalInsightsQuery returns and every caller reads:
            .Results   the primary table's rows, one object per row, one TEXT property per column (as Az hands them)
            .Columns   the primary table's columns (name / type) -- what the workbooks type their columns from
            .Tables    ONE entry: the primary table's Name and Columns, NO rows (RowsOmitted). The rows are in .Results only;
                       the answer is never held a second time as tables beside them (#639). No caller reads table rows.
            .Error     the partial-error object (or $null) -- only ever set beside rows that ARE the whole result (a missing SI
                       table in a fuzzy union), or with -AllowPartial
            .RowCount  the rows the answer held (with -OnPage: the rows handed to it)
        A CUT ANSWER IS REFUSED (#639, working rule 4). Log Analytics answers HTTP 200 with the rows it got to AND an error
        object when it stopped early (a result over its row / size limit, a part that timed out); an answer with exactly as
        many rows as the service's own row limit cannot be told from one cut there. Such an answer THROWS
        (New-SILaCutAnswerError: the service's words, the kind, the rows it held) -- a cut answer is never handed out as
        whole. -AllowPartial: the caller reads .Error itself and decides (the rows and the error come back as before, and
        .Partial says the kind). A read that pages (its query keys the rows) catches the "too large" refusal and reads that
        page again in smaller pages -- the refusal carries the same words the cut answer did.
        -OnPage { param($Rows) }: the rows are handed on a PAGE at a time as they arrive (about -PageBytes of answer each,
        the size measured from the answer's own bytes) and never collected -- memory is one page, whatever the size of the
        answer. .Results is then empty. The pages are PROVISIONAL until this call returns: a cut answer (said at the END of
        the answer) or a read that fails half-way throws AFTER pages were handed on, so a caller stages the pages and keeps
        them only when the call returned. Without the streaming reader (Windows PowerShell, or it cannot be built) the
        answer is read the older way and then handed on in pages of the same size.
        THE LEAN READ IS THE DEFAULT (#639): on pwsh 7 the answer arrives as bytes and its rows are read from those bytes
        (ConvertFrom-SILaQueryRows) -- never also held as one text (twice its size) or as a list of cells per row. The same
        rows and the same text values as before. Windows PowerShell (no System.Text.Json) reads the text, as always.
        -WorkspaceId is the workspace's customer id (GUID). -Wait = server timeout in seconds (Prefer: wait=N).
        -RowsOnly is kept for the callers that name it; it is what every read does now.
        A refused query throws with the service's own code and message, e.g.
            "Operation returned an invalid status code 'BadRequest' -- BadArgumentError/SemanticError/SEM0100: ..."
        and carries the body in Exception.Response.Content and ErrorDetails -- what SI-KqlError.ps1 reads.
    #>
    param(
        [Parameter(Mandatory)][string]$WorkspaceId,
        [Parameter(Mandatory)][string]$Query,
        [int]$Wait = 0,
        [timespan]$Timespan = [timespan]::Zero,
        [int]$MaxAttempts = 4,
        [switch]$RowsOnly,
        # the caller reads .Error itself and decides what a cut answer means (never the default)
        [switch]$AllowPartial,
        # the rows a page at a time, never collected (see above)
        [scriptblock]$OnPage,
        [long]$PageBytes = 4MB
    )
    Initialize-SIAzRestHelpers
    if ($OnPage) {
        return (Invoke-SILaQueryPaged -WorkspaceId $WorkspaceId -Query $Query -Wait $Wait -Timespan $Timespan -MaxAttempts $MaxAttempts -AllowPartial:$AllowPartial -OnPage $OnPage -PageBytes $PageBytes)
    }
    $uri = 'https://api.loganalytics.io/v1/workspaces/{0}/query' -f $WorkspaceId.Trim()
    $body = [ordered]@{ query = $Query }
    if ($Timespan -gt [timespan]::Zero) { $body['timespan'] = [System.Xml.XmlConvert]::ToString($Timespan) }
    $headers = @{}
    $timeout = 300
    # #882 (A4): Log Analytics stops a query at 3 minutes unless asked to wait -- every query asks for its maximum (10 minutes)
    if ($Wait -le 0) { $Wait = 600 }
    if ($Wait -gt 0) { $headers['Prefer'] = ('wait={0}' -f $Wait); $timeout = $Wait + 60 }
    # the answer as bytes wherever it can be read from them (pwsh 7) -- the lean read is the default (#639)
    $asBytes = ([bool]$RowsOnly -or $PSVersionTable.PSEdition -eq 'Core')
    # #730: Risk Analysis' reads (its lookups -- SI_LaCompactRows -- and its Log Analytics answers -- SI_LaStreamRows) are
    # read AS THEY ARRIVE (SI-LaStreamRead.ps1): the same rows, the answer never held whole. Everything else reads as before.
    $readStream = $null
    if ($PSVersionTable.PSEdition -eq 'Core' -and ([bool]$global:SI_LaCompactRows -or [bool]$global:SI_LaStreamRows) -and
        (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore)) {
        if (Get-SILaStreamReaderType) {
            $__lsCompact = [bool]$global:SI_LaCompactRows
            # (no closure: it runs inside this call, so $__lsCompact is seen; a closure would not see this file's functions)
            # #836: a failed stream read answers a marker -- read again below the older way, never an error of the query
            $readStream = { param($s) Read-SILaQueryStreamSafe -Stream $s -Compact:$__lsCompact }
        } else {
            # #836: never silent -- one line on the run log says the older read is used and why
            Write-SILaStreamFallback -Once -Reason ([string]$global:SI_LaStreamReaderOff)
        }
    }
    $rq = @{ Method = 'POST'; Uri = $uri; Audience = 'LaQuery'; Body = ($body | ConvertTo-Json -Compress -Depth 5); Headers = $headers
             TimeoutSec = $timeout; MaxAttempts = $MaxAttempts; AllowStatus = @(400, 403, 404, 409, 413, 422); What = 'Log Analytics query'; AsBytes = $asBytes }
    if ($readStream) { $rq['ReadStream'] = $readStream }
    $r = Invoke-SIAzRestRequest @rq
    if ($readStream -and $r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and $r.Parsed.PSObject.Properties['SILaStreamFailed']) {
        # #836: the stream read of this answer failed -- the same query again, read the older way (data first), and said
        Write-SILaStreamFallback -Reason ('reading this answer as it arrived failed (' + [string]$r.Parsed.SILaStreamFailed + '), so it was read again')
        $r = $null
        [void]$rq.Remove('ReadStream')
        $r = Invoke-SIAzRestRequest @rq
    }
    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and [int]$r.StatusCode -lt 400) {
        $streamed = $r.Parsed
        $r = $null
        return (Complete-SILaQueryAnswer -Results $streamed.Rows -Columns $streamed.Columns -QueryError $streamed.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
    }
    $code = [int]$r.StatusCode
    # A refusal (always small) is read as text, as is every answer on Windows PowerShell (no System.Text.Json there); an
    # answer on pwsh 7 is parsed from its bytes below.
    $content = [string]$r.Content
    $hasBytes = ($asBytes -and $null -ne $r.Bytes -and $r.Bytes.Length -gt 0)
    $lean = ($hasBytes -and $code -lt 400 -and $PSVersionTable.PSEdition -eq 'Core')
    if ($hasBytes -and -not $lean) { $content = [System.Text.Encoding]::UTF8.GetString($r.Bytes) }
    if ($code -ge 400) { throw (New-SILaQueryRefusedError -Code $code -Content $content -Headers $r.Headers -WorkspaceId $WorkspaceId) }
    if ($lean) {
        # a plain statement, never through $( ... ): a subexpression would enumerate the byte array into object[]
        [byte[]]$answer = $r.Bytes
        $r = $null
        $leanAnswer = ConvertFrom-SILaQueryRows -Bytes $answer
        $answer = $null
        return (Complete-SILaQueryAnswer -Results $leanAnswer.Rows -Columns $leanAnswer.Columns -QueryError $leanAnswer.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
    }
    $parsed = ConvertFrom-SILaQueryJson -Json $content
    $content = $null
    $results = [System.Collections.Generic.List[object]]::new()
    $first = @($parsed.Tables | Where-Object { $_.Name -eq 'PrimaryResult' }) + @($parsed.Tables) | Select-Object -First 1
    $cols = @()
    if ($first) {
        $names = @($first.Columns | ForEach-Object { [string]$_.name })
        $cols = @($first.Columns | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; type = $(if ($_.PSObject.Properties['type']) { [string]$_.type } else { $null }) } })
        foreach ($row in $first.Rows) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $row[$i] }
            [void]$results.Add([pscustomobject]$o)
        }
    }
    $err = $parsed.Error
    $parsed = $null; $first = $null
    return (Complete-SILaQueryAnswer -Results $results.ToArray() -Columns $cols -QueryError $err -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId)
}

function New-SILaQueryRefusedError {
    <# The error a refused query (HTTP 4xx) becomes: the service's own code and message, the body for SI-KqlError. #>
    param([int]$Code, [AllowNull()][AllowEmptyString()][string]$Content, $Headers, [string]$WorkspaceId = '')
    $base = "Operation returned an invalid status code '{0}'" -f (Get-SIAzRestStatusName $Code)
    $resp = [pscustomobject]@{ StatusCode = $Code; Content = $Content; Headers = $Headers }
    $probe = New-SIAzRestError -Message $base -Response $resp
    $msg = Get-SIKqlErrorSummary -ErrorRecord $probe
    if ($msg -eq $base) {
        # no innererror chain: the top-level error code + message
        try { $e = ($Content | ConvertFrom-Json).error; if ($e) { $msg = ('{0} -- {1}: {2}' -f $base, [string]$e.code, [string]$e.message) } } catch { }
    }
    $ex = New-SIAzRestError -Message $msg -Response $resp
    $er = New-Object System.Management.Automation.ErrorRecord($ex, 'SILaQueryFailed', [System.Management.Automation.ErrorCategory]::InvalidOperation, $WorkspaceId)
    $er.ErrorDetails = New-Object System.Management.Automation.ErrorDetails($Content)
    $er
}

function Complete-SILaQueryAnswer {
    <#
        The end of every Invoke-SILaQuery read: a cut answer (Test-SILaAnswerWhole) THROWS (New-SILaCutAnswerError) unless
        -AllowPartial; otherwise the answer (New-SILaQueryAnswer), with .Partial = the kind of a partial answer handed out
        under -AllowPartial ('' when whole).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Results = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Columns = @(), $QueryError,
          [switch]$AllowPartial, [string]$WorkspaceId = '', [long]$RowCount = -1)
    $n = $RowCount
    if ($n -lt 0) { $n = 0L; if ($null -ne $Results) { $n = [long]$Results.Count } }
    $v = Test-SILaAnswerWhole -ErrorObject $QueryError -Rows $n
    if (-not $v.Whole -and -not $AllowPartial) { throw (New-SILaCutAnswerError -Verdict $v -ErrorObject $QueryError -WorkspaceId $WorkspaceId) }
    $a = New-SILaQueryAnswer -Results $Results -Columns $Columns -QueryError $QueryError
    $kind = ''; if (-not $v.Whole) { $kind = [string]$v.Kind }
    $a | Add-Member -NotePropertyName Partial -NotePropertyValue $kind -Force
    $a | Add-Member -NotePropertyName RowCount -NotePropertyValue $n -Force
    $a
}

function Invoke-SILaQueryPaged {
    <#
        Invoke-SILaQuery -OnPage: the rows handed on a page at a time, never collected (see Invoke-SILaQuery). The streaming
        reader (SI-LaStreamRead.ps1) delivers each page as soon as about -PageBytes of the answer's own bytes are in; the
        compact rows of $global:SI_LaCompactRows apply. A cut answer is refused at the end, after the pages (they are
        provisional until this returns). A stream read that fails BEFORE any page was handed on is read again the older way;
        one that fails AFTER a page was handed on throws (handing the pages on again would hand some rows twice).
        Without the streaming reader: the older read, then the rows in pages of the same measured size.
        Returns the answer shape with no rows in .Results; .RowCount = the rows handed on, .Pages = the pages.
    #>
    param([Parameter(Mandatory)][string]$WorkspaceId, [Parameter(Mandatory)][string]$Query, [int]$Wait = 0,
          [timespan]$Timespan = [timespan]::Zero, [int]$MaxAttempts = 4, [switch]$AllowPartial,
          [Parameter(Mandatory)][scriptblock]$OnPage, [long]$PageBytes = 4MB)
    if ($PageBytes -lt 1KB) { $PageBytes = 1KB }
    $uri = 'https://api.loganalytics.io/v1/workspaces/{0}/query' -f $WorkspaceId.Trim()
    $body = [ordered]@{ query = $Query }
    if ($Timespan -gt [timespan]::Zero) { $body['timespan'] = [System.Xml.XmlConvert]::ToString($Timespan) }
    $headers = @{}
    $timeout = 300
    # #882 (A4): Log Analytics stops a query at 3 minutes unless asked to wait -- every query asks for its maximum (10 minutes)
    if ($Wait -le 0) { $Wait = 600 }
    if ($Wait -gt 0) { $headers['Prefer'] = ('wait={0}' -f $Wait); $timeout = $Wait + 60 }
    $rq = @{ Method = 'POST'; Uri = $uri; Audience = 'LaQuery'; Body = ($body | ConvertTo-Json -Compress -Depth 5); Headers = $headers
             TimeoutSec = $timeout; MaxAttempts = $MaxAttempts; AllowStatus = @(400, 403, 404, 409, 413, 422); What = 'Log Analytics query'
             AsBytes = ($PSVersionTable.PSEdition -eq 'Core') }
    $streamable = ($PSVersionTable.PSEdition -eq 'Core' -and (Get-Command -Name Get-SILaStreamReaderType -ErrorAction Ignore) -and (Get-SILaStreamReaderType))
    $state = @{ Pages = 0; Rows = 0L }
    if ($streamable) {
        $__lpCompact = [bool]$global:SI_LaCompactRows
        $__lpOn = $OnPage; $__lpBytes = $PageBytes; $__lpState = $state
        $rq['ReadStream'] = { param($s) Read-SILaQueryStreamSafe -Stream $s -Compact:$__lpCompact -OnPage $__lpOn -PageBytes $__lpBytes -PageState $__lpState }
    } elseif ($PSVersionTable.PSEdition -eq 'Core') {
        Write-SILaStreamFallback -Once -Reason ([string]$global:SI_LaStreamReaderOff)
    }
    $r = Invoke-SIAzRestRequest @rq
    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and $r.Parsed.PSObject.Properties['SILaStreamFailed']) {
        if ([int]$state.Pages -gt 0) {
            throw ('Log Analytics: the answer could not be read to its end ({0}) after {1} page(s) had been handed on -- the read is not whole and its pages must not be used' -f [string]$r.Parsed.SILaStreamFailed, $state.Pages)
        }
        Write-SILaStreamFallback -Reason ('reading this answer as it arrived failed (' + [string]$r.Parsed.SILaStreamFailed + '), so it was read again')
        $r = $null
        [void]$rq.Remove('ReadStream')
        $r = Invoke-SIAzRestRequest @rq
    }
    if ($r -and $r.PSObject.Properties['Parsed'] -and $null -ne $r.Parsed -and [int]$r.StatusCode -lt 400) {
        $p = $r.Parsed; $r = $null
        $a = Complete-SILaQueryAnswer -Results @() -Columns $p.Columns -QueryError $p.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId -RowCount ([long]$p.RowCount)
        $a | Add-Member -NotePropertyName Pages -NotePropertyValue ([int]$p.Pages) -Force
        return $a
    }
    # the older read (no streaming reader, or read again): the same refusal of a 4xx and of a cut answer, then the pages
    [void]$rq.Remove('ReadStream')
    if ($null -eq $r) { $r = Invoke-SIAzRestRequest @rq }
    $code = [int]$r.StatusCode
    $content = [string]$r.Content
    if ($null -ne $r.Bytes -and $r.Bytes.Length -gt 0 -and ($code -ge 400 -or $PSVersionTable.PSEdition -ne 'Core')) { $content = [System.Text.Encoding]::UTF8.GetString($r.Bytes) }
    if ($code -ge 400) { throw (New-SILaQueryRefusedError -Code $code -Content $content -Headers $r.Headers -WorkspaceId $WorkspaceId) }
    $lean = $null
    if ($null -ne $r.Bytes -and $r.Bytes.Length -gt 0 -and $PSVersionTable.PSEdition -eq 'Core') {
        [byte[]]$bytes = $r.Bytes
        $total = [long]$bytes.Length
        $r = $null
        $lean = ConvertFrom-SILaQueryRows -Bytes $bytes
        $bytes = $null
    } else {
        $total = [long][System.Text.Encoding]::UTF8.GetByteCount($content)
        $parsed = ConvertFrom-SILaQueryJson -Json $content
        $content = $null
        $first = @($parsed.Tables | Where-Object { $_.Name -eq 'PrimaryResult' }) + @($parsed.Tables) | Select-Object -First 1
        $rowsL = [System.Collections.Generic.List[object]]::new(); $colsL = @()
        if ($first) {
            $names = @($first.Columns | ForEach-Object { [string]$_.name })
            $colsL = @($first.Columns | ForEach-Object { [pscustomobject]@{ name = [string]$_.name; type = $(if ($_.PSObject.Properties['type']) { [string]$_.type } else { $null }) } })
            foreach ($row in $first.Rows) { $o = [ordered]@{}; for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $row[$i] }; [void]$rowsL.Add([pscustomobject]$o) }
        }
        $lean = [pscustomobject]@{ Rows = $rowsL.ToArray(); Columns = $colsL; Error = $parsed.Error }
        $parsed = $null; $first = $null
    }
    $all = @($lean.Rows); $n = $all.Count
    # a cut answer is refused BEFORE a page is handed on (the whole answer is in hand on this path)
    $v = Test-SILaAnswerWhole -ErrorObject $lean.Error -Rows $n
    if (-not $v.Whole -and -not $AllowPartial) { throw (New-SILaCutAnswerError -Verdict $v -ErrorObject $lean.Error -WorkspaceId $WorkspaceId) }
    # pages of about -PageBytes of the answer: the measured bytes per row of this answer decide the rows per page
    $per = $n
    if ($n -gt 0 -and $total -gt $PageBytes) { $per = [int][Math]::Max(1, [Math]::Floor($n * ([double]$PageBytes / [double]$total))) }
    $pages = 0
    for ($i = 0; $i -lt $n; $i += [Math]::Max(1, $per)) {
        $len = [Math]::Min([Math]::Max(1, $per), $n - $i)
        $pg = [object[]]::new($len); [Array]::Copy($all, $i, $pg, 0, $len)
        $null = & $OnPage $pg
        $pages++
        for ($k = $i; $k -lt $i + $len; $k++) { $all[$k] = $null }
    }
    $a = Complete-SILaQueryAnswer -Results @() -Columns $lean.Columns -QueryError $lean.Error -AllowPartial:$AllowPartial -WorkspaceId $WorkspaceId -RowCount ([long]$n)
    $a | Add-Member -NotePropertyName Pages -NotePropertyValue $pages -Force
    $a
}

function New-SILaQueryAnswer {
    <#
        PURE. The one shape Invoke-SILaQuery answers (#639): .Results (the rows), .Columns (name / type), .Tables = the
        primary table's SCHEMA only (Name, Columns, no rows -- RowsOmitted), .Error. The rows are never held twice.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Results = @(), [AllowNull()][AllowEmptyCollection()][object[]]$Columns = @(), $QueryError)
    $c = @($Columns | Where-Object { $null -ne $_ })
    $schema = [pscustomobject]@{ Name = 'PrimaryResult'; Columns = $c; Rows = @(); RowsOmitted = $true }
    # plain statements: an if used as a value would unroll the rows (one row would come back as that row, not a list)
    $rows = $Results
    if ($null -eq $rows) { $rows = [object[]]@() }
    [pscustomobject]@{ Results = $rows; Columns = $c; Tables = @($schema); Error = $QueryError; Statistics = $null; Render = $null }
}

# =====================================================================================================================
#  Storage data plane: blob, queue, table (OAuth bearer, x-ms-version)
# =====================================================================================================================

function Get-SIStorageApiVersion { '2021-08-06' }

function Get-SIStorageUri {
    param([Parameter(Mandatory)][string]$Account, [ValidateSet('blob', 'queue', 'table')][string]$Service = 'blob', [string]$Path = '', [string]$Query = '')
    $p = (($Path -split '/') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/'
    $u = 'https://{0}.{1}.core.windows.net/{2}' -f $Account, $Service, $p
    if ($Query) { $u += '?' + $Query }
    return $u
}

function Invoke-SIStorageRequest {
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [string]$ContentType, [hashtable]$Headers, [switch]$AllowNotFound, [int[]]$AllowStatus = @(), [switch]$AsBytes, [string]$What = 'Azure Storage request')
    $h = @{ 'x-ms-version' = (Get-SIStorageApiVersion); 'x-ms-date' = [datetime]::UtcNow.ToString('R') }
    if ($Headers) { foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] } }
    if (-not $ContentType) { $ContentType = 'application/octet-stream' }
    return (Invoke-SIAzRestRequest -Method $Method -Uri $Uri -Audience Storage -Body $Body -ContentType $ContentType -Headers $h -AllowNotFound:$AllowNotFound -AllowStatus $AllowStatus -AsBytes:$AsBytes -What $What)
}

function ConvertTo-SIStorageDate {
    param([string]$Text)
    $d = [DateTimeOffset]::MinValue
    if ($Text -and [DateTimeOffset]::TryParse($Text, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    return $null
}

function Get-SIBlobProperties {
    <# HEAD of one blob: @{ Name; Length; LastModified; ETag; ContentType } or $null when it does not exist. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob)
    $r = Invoke-SIStorageRequest -Method HEAD -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AllowNotFound -What ("Blob '{0}/{1}'" -f $Container, $Blob)
    if (-not $r) { return $null }
    $len = 0L; [void][long]::TryParse([string]$r.Headers['Content-Length'], [ref]$len)
    return [pscustomobject]@{ Name = $Blob; Container = $Container; Length = $len; LastModified = (ConvertTo-SIStorageDate $r.Headers['Last-Modified']); ETag = [string]$r.Headers['ETag']; ContentType = [string]$r.Headers['Content-Type'] }
}

function Get-SIBlobList {
    <# Every blob in -Container under -Prefix (List Blobs, following the marker). #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [string]$Prefix)
    $out = [System.Collections.Generic.List[object]]::new()
    $marker = $null
    do {
        $q = 'restype=container&comp=list&maxresults=5000'
        if ($Prefix) { $q += '&prefix=' + [uri]::EscapeDataString($Prefix) }
        if ($marker) { $q += '&marker=' + [uri]::EscapeDataString($marker) }
        $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query $q) -Headers @{ Accept = 'application/xml' } -What ("List blobs in '{0}'" -f $Container)
        # The listing is XML (EnumerationResults). A cast `[xml]$text` that fails puts the WHOLE listing (up to 5,000 blobs)
        # into its error text -- customer B 2026-10-15: "Cannot convert value "<?xml ... EnumerationResults ..." to type
        # System.Xml.XmlDocument. Error: OutOfMemoryException" as the run's end text. Parsed here; a failure says what failed
        # and why, in one short line, never the payload.
        $x = New-Object System.Xml.XmlDocument
        try { $x.LoadXml((([string]$r.Content) -replace '^\uFEFF', '')) }
        catch {
            $why = $_.Exception.Message; if ($_.Exception.InnerException) { $why = $_.Exception.InnerException.Message }
            if ($why.Length -gt 300) { $why = $why.Substring(0, 300) }
            throw ("The blob list of '{0}' (prefix '{1}') could not be read: {2}" -f $Container, $Prefix, $why)
        }
        foreach ($b in @($x.EnumerationResults.Blobs.Blob)) {
            if ($null -eq $b) { continue }
            $len = 0L; [void][long]::TryParse([string]$b.Properties.'Content-Length', [ref]$len)
            [void]$out.Add([pscustomobject]@{ Name = [string]$b.Name; Container = $Container; Length = $len; LastModified = (ConvertTo-SIStorageDate ([string]$b.Properties.'Last-Modified')); ETag = [string]$b.Properties.Etag; ContentType = [string]$b.Properties.'Content-Type' })
        }
        $marker = [string]$x.EnumerationResults.NextMarker
    } while ($marker)
    return $out.ToArray()
}

function Get-SIBlobContent {
    <# Download one blob: the bytes, or -Destination writes them to a file (returns the path). -AllowMissing: a blob that
       does not exist (404) returns $null -- no error is raised or logged (2026-10-23: the pipeline's poll of a run's
       records marker logged a TerminatingError 404 every 30 s, hiding the real errors). #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob, [string]$Destination, [switch]$AllowMissing)
    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AsBytes -AllowNotFound:$AllowMissing -What ("Download blob '{0}/{1}'" -f $Container, $Blob)
    if ($AllowMissing -and $null -eq $r) { return $null }
    # PLAIN statements, never `$bytes = if (...) { [byte[]]... }`: an `if` used as a value sends the array through the
    # pipeline ONE BYTE AT A TIME into an object[] -- about 30 times the blob's size in memory. A new customer install
    # 2026-10-12: the Azure collection's 13,562 assets made one large part, and reading it back ended in
    # "System.OutOfMemoryException" on a job with 4 GiB and again with 8 GiB.
    $bytes = $r.Bytes
    if ($null -eq $bytes) { $bytes = [byte[]]::new(0) }
    if (-not $Destination) { return ,$bytes }
    [System.IO.File]::WriteAllBytes($Destination, $bytes)
    return $Destination
}

function Set-SIBlobContent {
    <# Upload one block blob (create or overwrite) from -File or -Bytes. -IfMatchETag makes it conditional (412 when
       another writer got there first); -IfNoneMatch creates it only when it does not exist yet (409 / 412 when it does --
       a claim exactly one writer wins). Returns the new ETag. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob,
          [string]$File, [byte[]]$Bytes, [string]$IfMatchETag, [string]$ContentType = 'application/octet-stream', [switch]$IfNoneMatch)
    if ($File) { $Bytes = [System.IO.File]::ReadAllBytes($File) }
    if ($null -eq $Bytes) { $Bytes = [byte[]]@() }
    $h = @{ 'x-ms-blob-type' = 'BlockBlob' }
    if ($IfMatchETag) { $h['If-Match'] = $IfMatchETag }
    if ($IfNoneMatch) { $h['If-None-Match'] = '*' }
    $r = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -Body $Bytes -ContentType $ContentType -Headers $h -What ("Upload blob '{0}/{1}'" -f $Container, $Blob)
    return [string]$r.Headers['ETag']
}

function Remove-SIBlob {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob)
    $null = Invoke-SIStorageRequest -Method DELETE -Uri (Get-SIStorageUri -Account $Account -Path ("$Container/$Blob")) -AllowNotFound -What ("Delete blob '{0}/{1}'" -f $Container, $Blob)
}

function Test-SIBlobContainer {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container)
    $r = Invoke-SIStorageRequest -Method HEAD -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query 'restype=container') -AllowNotFound -What ("Container '{0}'" -f $Container)
    if (-not $r) { return $null }
    return [pscustomobject]@{ Name = $Container; LastModified = (ConvertTo-SIStorageDate $r.Headers['Last-Modified']); ETag = [string]$r.Headers['ETag'] }
}

function New-SIBlobContainer {
    <# Create a private container; an existing one is not an error. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Container)
    $null = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Path $Container -Query 'restype=container') -AllowStatus @(409) -What ("Create container '{0}'" -f $Container)
    return [pscustomobject]@{ Name = $Container }
}

function Test-SIQueue {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue)
    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Service queue -Path $Queue -Query 'comp=metadata') -AllowNotFound -What ("Queue '{0}'" -f $Queue)
    return [bool]$r
}

function New-SIQueue {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue)
    $null = Invoke-SIStorageRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Service queue -Path $Queue) -AllowStatus @(409) -What ("Create queue '{0}'" -f $Queue)
}

function Send-SIQueueMessage {
    <# Put one message. The text is sent as-is (XML-escaped), the encoding the Az.Storage 9 queue client uses. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $body = '<QueueMessage><MessageText>{0}</MessageText></QueueMessage>' -f [System.Security.SecurityElement]::Escape($Text)
    $r = Invoke-SIStorageRequest -Method POST -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages")) -Body $body -ContentType 'application/xml' -What ("Send to queue '{0}'" -f $Queue)
    $x = [xml]($r.Content -replace '^\uFEFF', '')
    return [pscustomobject]@{ MessageId = [string]$x.QueueMessagesList.QueueMessage.MessageId; PopReceipt = [string]$x.QueueMessagesList.QueueMessage.PopReceipt }
}

function Receive-SIQueueMessage {
    <# Lease one message for -VisibilityTimeoutSeconds: @{ MessageId; PopReceipt; MessageText; DequeueCount } or $null
       when the queue is empty. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [int]$VisibilityTimeoutSeconds = 30)
    $q = 'numofmessages=1&visibilitytimeout={0}' -f $VisibilityTimeoutSeconds
    $r = Invoke-SIStorageRequest -Method GET -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages") -Query $q) -Headers @{ Accept = 'application/xml' } -What ("Receive from queue '{0}'" -f $Queue)
    $x = [xml]($r.Content -replace '^\uFEFF', '')
    $m = @($x.QueueMessagesList.QueueMessage) | Where-Object { $_ } | Select-Object -First 1
    if (-not $m) { return $null }
    return [pscustomobject]@{ MessageId = [string]$m.MessageId; PopReceipt = [string]$m.PopReceipt; MessageText = [string]$m.MessageText; DequeueCount = [int]$m.DequeueCount }
}

function Update-SIQueueMessage {
    <#
        RENEW the hold on one leased message: its visibility timeout is set to -VisibilityTimeoutSeconds from now (Update
        Message). The message text goes back unchanged (-Text: as it was received). NEVER THROWS -- the answer says which:
          @{ Ok = $true;  PopReceipt = <the NEW receipt: the old one is no longer valid> }
          @{ Ok = $false; Lost = $true;  Why }   the message is gone (404) or another worker holds it (400 PopReceiptMismatch)
          @{ Ok = $false; Lost = $false; Why }   anything else (network, sign-in, a 5xx): not known -- try again
        Short timeouts and two attempts: this is called from a heartbeat, which must not hang on one request.
        -Auth: the identity to sign in as (a second thread has no sign-in of its own; Resolve-SIAzRestAuth's answer).
    #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][string]$MessageId, [Parameter(Mandatory)][string]$PopReceipt,
          [Parameter(Mandatory)][int]$VisibilityTimeoutSeconds, [AllowEmptyString()][string]$Text = '', [hashtable]$Auth, [int]$TimeoutSec = 30)
    try {
        $q = 'popreceipt={0}&visibilitytimeout={1}' -f [uri]::EscapeDataString($PopReceipt), $VisibilityTimeoutSeconds
        $body = '<QueueMessage><MessageText>{0}</MessageText></QueueMessage>' -f [System.Security.SecurityElement]::Escape($Text)
        $h = @{ 'x-ms-version' = (Get-SIStorageApiVersion); 'x-ms-date' = [datetime]::UtcNow.ToString('R') }
        $r = Invoke-SIAzRestRequest -Method PUT -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages/$MessageId") -Query $q) -Audience Storage -Body $body `
                -ContentType 'application/xml' -Headers $h -AllowStatus @(400, 404) -TimeoutSec $TimeoutSec -MaxAttempts 2 -Auth $Auth -What ("Renew the hold on a message of queue '{0}'" -f $Queue)
        $code = 0; try { $code = [int]$r.StatusCode } catch { }
        if ($code -ge 200 -and $code -lt 300) {
            $new = [string]$r.Headers['x-ms-popreceipt']
            if (-not $new) { return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = 'the queue answered without a new receipt' } }
            return [pscustomobject]@{ Ok = $true; Lost = $false; PopReceipt = $new; Why = '' }
        }
        if ($code -eq 404) { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'the message is no longer in the queue' } }
        $said = [string]$r.Content; try { if ($r.Headers -and $r.Headers['x-ms-error-code']) { $said += ' ' + [string]$r.Headers['x-ms-error-code'] } } catch { }
        if ($code -eq 400 -and $said -match '(?i)PopReceiptMismatch|MessageNotFound') { return [pscustomobject]@{ Ok = $false; Lost = $true; PopReceipt = $PopReceipt; Why = 'another worker holds the message now' } }
        return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = ('HTTP {0}: {1}' -f $code, (([string]$r.Content -replace '\s+', ' ').Trim() -replace '^(.{200}).*$', '$1...')) }
    } catch {
        return [pscustomobject]@{ Ok = $false; Lost = $false; PopReceipt = $PopReceipt; Why = [string]$_.Exception.Message }
    }
}

function Remove-SIQueueMessage {
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Queue, [Parameter(Mandatory)][string]$MessageId, [Parameter(Mandatory)][string]$PopReceipt)
    $q = 'popreceipt=' + [uri]::EscapeDataString($PopReceipt)
    $null = Invoke-SIStorageRequest -Method DELETE -Uri (Get-SIStorageUri -Account $Account -Service queue -Path ("$Queue/messages/$MessageId") -Query $q) -AllowNotFound -What ("Delete from queue '{0}'" -f $Queue)
}

function Get-SITableEntity {
    <# One table entity (PartitionKey + RowKey) or $null; without -RowKey, every entity of the partition (following the
       continuation headers). #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey, [string]$RowKey)
    $h = @{ Accept = 'application/json;odata=nometadata' }
    $esc = { param($s) ([string]$s).Replace("'", "''") }
    if ($RowKey) {
        $path = "{0}(PartitionKey='{1}',RowKey='{2}')" -f $Table, [uri]::EscapeDataString((& $esc $PartitionKey)), [uri]::EscapeDataString((& $esc $RowKey))
        $r = Invoke-SIStorageRequest -Method GET -Uri ('https://{0}.table.core.windows.net/{1}' -f $Account, $path) -Headers $h -ContentType 'application/json' -AllowNotFound -What ("Table '{0}' entity" -f $Table)
        if (-not $r) { return $null }
        return ($r.Content | ConvertFrom-Json)
    }
    $out = [System.Collections.Generic.List[object]]::new()
    $filter = [uri]::EscapeDataString(("PartitionKey eq '{0}'" -f (& $esc $PartitionKey)))
    $np = $null; $nr = $null
    do {
        $q = '$filter=' + $filter
        if ($np) { $q += '&NextPartitionKey=' + [uri]::EscapeDataString($np) }
        if ($nr) { $q += '&NextRowKey=' + [uri]::EscapeDataString($nr) }
        $r = Invoke-SIStorageRequest -Method GET -Uri ('https://{0}.table.core.windows.net/{1}()?{2}' -f $Account, $Table, $q) -Headers $h -ContentType 'application/json' -What ("Table '{0}' query" -f $Table)
        foreach ($e in @(($r.Content | ConvertFrom-Json).value)) { if ($e) { [void]$out.Add($e) } }
        $np = [string]$r.Headers['x-ms-continuation-NextPartitionKey']; $nr = [string]$r.Headers['x-ms-continuation-NextRowKey']
    } while ($np)
    return $out.ToArray()
}

function Set-SITableEntity {
    <# UPSERT one entity (Insert Or Replace; -Merge = Insert Or Merge). -Entity is a hashtable of properties. #>
    param([Parameter(Mandatory)][string]$Account, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$PartitionKey,
          [Parameter(Mandatory)][string]$RowKey, [hashtable]$Entity = @{}, [switch]$Merge)
    $e = [ordered]@{ PartitionKey = $PartitionKey; RowKey = $RowKey }
    foreach ($k in $Entity.Keys) { if ($k -notin 'PartitionKey', 'RowKey') { $e[$k] = $Entity[$k] } }
    $esc = { param($s) ([string]$s).Replace("'", "''") }
    $path = "{0}(PartitionKey='{1}',RowKey='{2}')" -f $Table, [uri]::EscapeDataString((& $esc $PartitionKey)), [uri]::EscapeDataString((& $esc $RowKey))
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($e | ConvertTo-Json -Depth 5 -Compress))
    $null = Invoke-SIStorageRequest -Method $(if ($Merge) { 'MERGE' } else { 'PUT' }) -Uri ('https://{0}.table.core.windows.net/{1}' -f $Account, $path) -Body $bytes `
                -ContentType 'application/json' -Headers @{ Accept = 'application/json;odata=nometadata' } -What ("Table '{0}' upsert" -f $Table)
}

# =====================================================================================================================
#  The wrappers -- each forwards to its REST twin below
# =====================================================================================================================
# Each declares the parameters SecurityInsight's call sites use, UNTYPED except switches, and forwards @PSBoundParameters
# -- never @args (measured: @args splits -Name:$value into a switch plus a positional value).
function Connect-SIAzAccount {
    [CmdletBinding()]
    param([switch]$Identity, $AccountId, [switch]$ServicePrincipal, $ApplicationId, $CertificateThumbprint,
          $CertificatePath, $CertificatePassword, $Credential,
          [Alias('TenantId')]$Tenant, [Alias('SubscriptionId')]$Subscription, $Scope)
    return (Connect-SIAzAccountRest @PSBoundParameters)
}
function Disconnect-SIAzAccount {
    [CmdletBinding()] param($Scope)
    return (Disconnect-SIAzAccountRest @PSBoundParameters)
}
function Disable-SIAzContextAutosave {
    [CmdletBinding()] param($Scope)
    return (Disable-SIAzContextAutosaveRest @PSBoundParameters)
}
function Get-SIAzContext {
    [CmdletBinding()] param()
    return (Get-SIAzContextRest @PSBoundParameters)
}
function Set-SIAzContext {
    [CmdletBinding()]
    param([Alias('SubscriptionId', 'SubscriptionName')]$Subscription, [Alias('TenantId', 'Domain')]$Tenant, $Context, $Scope)
    return (Set-SIAzContextRest @PSBoundParameters)
}
function Get-SIAzAccessToken {
    [CmdletBinding()] param($ResourceUrl, $TenantId)
    return (Get-SIAzAccessTokenRest @PSBoundParameters)
}
function Get-SIAzSubscription {
    [CmdletBinding()] param($TenantId, $SubscriptionId)
    return (Get-SIAzSubscriptionRest @PSBoundParameters)
}
function Invoke-SIAzRestMethod {
    [CmdletBinding()] param($Path, $Method, $Payload)
    return (Invoke-SIAzRestMethodRest @PSBoundParameters)
}
function Invoke-SIAzOperationalInsightsQuery {
    # -AllowPartial: the caller reads .Error itself (Invoke-SILaQuery refuses a cut answer otherwise); -OnPage / -PageBytes:
    # the rows a page at a time (Invoke-SILaQuery)
    [CmdletBinding()] param($WorkspaceId, $Query, $Wait, $Timespan, [switch]$AllowPartial, [scriptblock]$OnPage, [long]$PageBytes)
    return (Invoke-SIAzOperationalInsightsQueryRest @PSBoundParameters)
}
function Get-SIAzOperationalInsightsWorkspace {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    return (Get-SIAzOperationalInsightsWorkspaceRest @PSBoundParameters)
}
function New-SIAzOperationalInsightsWorkspace {
    [CmdletBinding()] param($ResourceGroupName, $Name, $Location, $Sku, $RetentionInDays)
    return (New-SIAzOperationalInsightsWorkspaceRest @PSBoundParameters)
}
function Search-SIAzGraph {
    [CmdletBinding()] param($Query, $First, $Skip, $Subscription, $ManagementGroup, $SkipToken)
    return ,(Search-SIAzGraphRest @PSBoundParameters)   # one page object, not its rows
}
function Get-SIAzKeyVaultSecret {
    [CmdletBinding()] param($VaultName, $Name, [switch]$AsPlainText)
    return (Get-SIAzKeyVaultSecretRest @PSBoundParameters)
}
function Set-SIAzKeyVaultSecret {
    [CmdletBinding()] param($VaultName, $Name, $SecretValue, $ContentType)
    return (Set-SIAzKeyVaultSecretRest @PSBoundParameters)
}
function Get-SIAzResourceGroup {
    [CmdletBinding()] param($Name)
    return (Get-SIAzResourceGroupRest @PSBoundParameters)
}
function New-SIAzResourceGroup {
    [CmdletBinding()] param($Name, $Location, $Tag)
    return (New-SIAzResourceGroupRest @PSBoundParameters)
}
function Get-SIAzRoleAssignment {
    [CmdletBinding()] param($ObjectId, $Scope, $RoleDefinitionName)
    return (Get-SIAzRoleAssignmentRest @PSBoundParameters)
}
function New-SIAzRoleAssignment {
    [CmdletBinding()] param($ObjectId, $Scope, $RoleDefinitionName)
    return (New-SIAzRoleAssignmentRest @PSBoundParameters)
}
function Get-SIAzRoleDefinition {
    [CmdletBinding()] param([switch]$Custom, $Name, $Scope)
    return (Get-SIAzRoleDefinitionRest @PSBoundParameters)
}
function Get-SIAzTag {
    [CmdletBinding()] param($ResourceId)
    return (Get-SIAzTagRest @PSBoundParameters)
}
function Update-SIAzTag {
    [CmdletBinding()] param($ResourceId, $Tag, $Operation)
    return (Update-SIAzTagRest @PSBoundParameters)
}
function Get-SIAzADServicePrincipal {
    [CmdletBinding()] param($ApplicationId, $ObjectId)
    return (Get-SIAzADServicePrincipalRest @PSBoundParameters)
}
function Get-SIAzDataCollectionEndpoint {
    [CmdletBinding()] param($Name, $ResourceGroupName)
    return (Get-SIAzDataCollectionEndpointRest @PSBoundParameters)
}
function New-SIAzDataCollectionEndpoint {
    [CmdletBinding()] param($Name, $ResourceGroupName, $Location, $NetworkAclsPublicNetworkAccess)
    return (New-SIAzDataCollectionEndpointRest @PSBoundParameters)
}
function Get-SIAzDataCollectionRule {
    [CmdletBinding()] param($Name, $ResourceGroupName)
    return (Get-SIAzDataCollectionRuleRest @PSBoundParameters)
}
function New-SIAzStorageContext {
    [CmdletBinding()] param($StorageAccountName, [switch]$UseConnectedAccount)
    return (New-SIAzStorageContextRest @PSBoundParameters)
}
function Get-SIAzStorageAccount {
    [CmdletBinding()] param($ResourceGroupName, $Name)
    return (Get-SIAzStorageAccountRest @PSBoundParameters)
}
function New-SIAzStorageAccount {
    [CmdletBinding()]
    param($ResourceGroupName, $Name, $Location, $SkuName, $Kind, $EnableHttpsTrafficOnly,
          $MinimumTlsVersion, $AllowBlobPublicAccess, $PublicNetworkAccess)
    return (New-SIAzStorageAccountRest @PSBoundParameters)
}
function Get-SIAzStorageContainer {
    [CmdletBinding()] param($Name, $Context)
    return (Get-SIAzStorageContainerRest @PSBoundParameters)
}
function New-SIAzStorageContainer {
    [CmdletBinding()] param($Name, $Context, $Permission)
    return (New-SIAzStorageContainerRest @PSBoundParameters)
}
function Get-SIAzStorageBlob {
    [CmdletBinding()] param($Container, $Blob, $Prefix, $Context)
    return (Get-SIAzStorageBlobRest @PSBoundParameters)
}
function Get-SIAzStorageBlobContent {
    [CmdletBinding()] param($Container, $Blob, $CloudBlob, $Destination, $Context, [switch]$Force)
    return (Get-SIAzStorageBlobContentRest @PSBoundParameters)
}
function Set-SIAzStorageBlobContent {
    [CmdletBinding()] param($File, $Container, $Blob, $Context, [switch]$Force)
    return (Set-SIAzStorageBlobContentRest @PSBoundParameters)
}
function Remove-SIAzStorageBlob {
    [CmdletBinding()] param($Container, $Blob, $Context, [switch]$Force)
    return (Remove-SIAzStorageBlobRest @PSBoundParameters)
}
function Start-SIAzStorageBlobCopy {
    [CmdletBinding()] param($SrcContainer, $SrcBlob, $DestContainer, $DestBlob, $Context, [switch]$Force)
    return (Start-SIAzStorageBlobCopyRest @PSBoundParameters)
}
function Get-SIAzStorageQueue {
    [CmdletBinding()] param($Name, $Context)
    return (Get-SIAzStorageQueueRest @PSBoundParameters)
}
function New-SIAzStorageQueue {
    [CmdletBinding()] param($Name, $Context)
    return (New-SIAzStorageQueueRest @PSBoundParameters)
}

function Set-SIAzStorageBlobContentIfMatch {
    <# The ledger's CONDITIONAL write (only when the blob still has -IfMatchETag): PUT with If-Match. A lost race fails
       with '412 ConditionNotMet'. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string]$Container, [Parameter(Mandatory)][string]$Blob,
          [Parameter(Mandatory)][object]$Context, [Parameter(Mandatory)][string]$IfMatchETag)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    $null = Set-SIBlobContent -Account $acct -Container $Container -Blob $Blob -File $File -IfMatchETag $IfMatchETag
}
# =====================================================================================================================
#  The REST twins -- what each wrapper does with no Az module
# =====================================================================================================================

function Write-SIAzRestNotFound {
    <# A lookup that found nothing, the way the Az cmdlet reports it: a NON-terminating error, so -ErrorAction
       SilentlyContinue yields $null and -ErrorAction Stop throws. #>
    param([Parameter(Mandatory)]$Cmdlet, [Parameter(Mandatory)][string]$Message, [string]$Target)
    $er = New-Object System.Management.Automation.ErrorRecord((New-Object System.Exception($Message)), 'SIAzRestNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $Target)
    $Cmdlet.WriteError($er)
}

function Get-SIAzRestSubscriptionId {
    <# The current subscription: Set-SIAzContext / Connect -Subscription, else the install's workspace subscription,
       else the first enabled subscription the identity sees (what Connect-AzAccount selects). #>
    param([switch]$NoLookup)
    $st = Get-SIAzRestState
    if ($st.SubscriptionId) { return [string]$st.SubscriptionId }
    $s = [string](Get-SIAzRestValue 'SI_AzSubscriptionId')
    if (-not $s -and [string](Get-SIAzRestValue 'SI_WorkspaceResourceId') -match '/subscriptions/([^/]+)/') { $s = $Matches[1] }
    if (-not $s) { $s = [string](Get-SIAzRestValue 'SubscriptionId') }
    # in an Invardia Support session, the first subscription the environment names
    if (-not $s) { $sess = Get-SISupportSession; if ($sess -and $sess.SubscriptionId) { $s = [string]$sess.SubscriptionId } }
    if (-not $s -and -not $NoLookup) {
        try {
            $first = @(Invoke-SIArm -Path '/subscriptions' -ApiVersion '2022-12-01' -List | Where-Object { [string]$_.state -eq 'Enabled' }) | Select-Object -First 1
            if ($first) { $s = [string]$first.subscriptionId }
        } catch { }
    }
    if ($s) { $st.SubscriptionId = $s }
    return $s
}

function Get-SIAzRestTenantId {
    $st = Get-SIAzRestState
    if ($st.TenantId) { return [string]$st.TenantId }
    $a = Resolve-SIAzRestAuth
    $t = [string]$a.TenantId
    if (-not $t) {
        # a managed identity knows its tenant: read it from its own ARM token
        try { $c = ConvertFrom-SIJwtPayload (Get-SIAzureToken -Audience Arm); if ($c) { $t = [string]$c.tid } } catch { }
    }
    if ($t) { $st.TenantId = $t }
    return $t
}

function Connect-SIAzAccountRest {
    <# RECORDS the identity; no sign-in happens here (each REST call mints its token when it needs one). #>
    [CmdletBinding()]
    param([switch]$Identity, [string]$AccountId, [switch]$ServicePrincipal, [string]$ApplicationId, [string]$CertificateThumbprint,
          [string]$CertificatePath, [securestring]$CertificatePassword, [pscredential]$Credential,
          [Alias('TenantId')][string]$Tenant, [Alias('SubscriptionId')][string]$Subscription, [string]$Scope)
    $st = Get-SIAzRestState
    $conn = $null
    if ($Identity) {
        $cid = if ($AccountId) { $AccountId } else { [string](Get-SIAzRestValue 'SI_UAMI_ClientId', 'SI_ManagedIdentityClientId') }
        $conn = @{ Mode = 'ManagedIdentity'; ClientId = $cid }
    } elseif ($Credential) {
        $conn = @{ Mode = 'Secret'; AppId = [string]$Credential.UserName; TenantId = $Tenant; Secret = $Credential.GetNetworkCredential().Password }
    } elseif ($CertificateThumbprint -or $CertificatePath) {
        $thumb = $CertificateThumbprint
        if ($CertificatePath) {
            # the PFX the container wrote: the token signer looks a certificate up by thumbprint in the X509 store, so
            # it goes into CurrentUser\My (the only store a Linux container has) unless it is already there
            $pw = if ($CertificatePassword) { [System.Net.NetworkCredential]::new('', $CertificatePassword).Password } else { '' }
            $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.IO.File]::ReadAllBytes($CertificatePath), $pw, $flags)
            $thumb = [string]$cert.Thumbprint
            Initialize-SIAzRestHelpers
            if (-not (Get-SICertificateFromStore -Thumbprint $thumb)) {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
                try { $store.Open('ReadWrite'); $store.Add($cert) } finally { $store.Close() }
            }
        }
        $conn = @{ Mode = 'Certificate'; AppId = $ApplicationId; TenantId = $Tenant; Thumbprint = ($thumb -replace '\s', '') }
    } else {
        throw 'Connect-SIAzAccount (REST): name the identity -- -Identity, -Credential, or -ApplicationId with -CertificateThumbprint / -CertificatePath.'
    }
    $st.Connection = $conn
    $st.TenantId = if ($Tenant) { $Tenant } else { $null }
    $st.SubscriptionId = if ($Subscription) { $Subscription } else { $null }
    $st.Cache = @{}
    return (Get-SIAzContextRest)
}

function Disconnect-SIAzAccountRest {
    [CmdletBinding()] param([string]$Scope)
    $st = Get-SIAzRestState
    $st.Connection = $null; $st.SubscriptionId = $null; $st.TenantId = $null; $st.Cache = @{}
    $rc = Get-Variable -Scope Global -Name SI_LogIngestRunCache -ValueOnly -ErrorAction Ignore
    if ($rc -is [hashtable]) { $rc.Tokens = @{} }
}

function Disable-SIAzContextAutosaveRest { [CmdletBinding()] param([string]$Scope) }

function Get-SIAzContextRest {
    <# The context object the call sites read (Subscription.Id / .Name, Tenant.Id, Account.Id / .Type), or $null when
       no identity is configured. #>
    [CmdletBinding()] param()
    try { $a = Resolve-SIAzRestAuth } catch { return $null }
    $sub = Get-SIAzRestSubscriptionId
    $tid = Get-SIAzRestTenantId
    $acct = switch ($a.Mode) { 'ManagedIdentity' { [pscustomobject]@{ Id = $(if ($a.ClientId) { $a.ClientId } else { 'MSI' }); Type = 'ManagedService' } } default { [pscustomobject]@{ Id = $a.AppId; Type = 'ServicePrincipal' } } }
    return [pscustomobject]@{
        PSTypeName   = 'SI.AzRest.Context'
        Name         = ('{0} ({1})' -f $sub, $acct.Id)
        Account      = $acct
        Subscription = $(if ($sub) { [pscustomobject]@{ Id = $sub; SubscriptionId = $sub; Name = $sub; TenantId = $tid; ExtendedProperties = @{} } } else { $null })
        Tenant       = [pscustomobject]@{ Id = $tid; TenantId = $tid }
        Environment  = [pscustomobject]@{ Name = 'AzureCloud' }
    }
}

function Set-SIAzContextRest {
    [CmdletBinding()]
    param([Alias('SubscriptionId', 'SubscriptionName')][string]$Subscription, [Alias('TenantId', 'Domain')][string]$Tenant, [object]$Context, [string]$Scope)
    $st = Get-SIAzRestState
    if ($Context -and $Context.Subscription) { $Subscription = [string]$Context.Subscription.Id }
    if ($Subscription) { $st.SubscriptionId = $Subscription }
    if ($Tenant) { $st.TenantId = $Tenant }
    return (Get-SIAzContextRest)
}

function Get-SIAzAccessTokenRest {
    [CmdletBinding()] param([string]$ResourceUrl, [string]$TenantId)
    $res = if ($ResourceUrl) { $ResourceUrl } else { 'https://management.azure.com/' }
    $tok = Get-SIAzureToken -Resource $res
    $c = ConvertFrom-SIJwtPayload $tok
    $exp = [DateTimeOffset]::UtcNow.AddMinutes(45)
    if ($c -and $c.exp) { try { $exp = [DateTimeOffset]::FromUnixTimeSeconds([long]$c.exp) } catch { } }
    return [pscustomobject]@{ Token = $tok; ExpiresOn = $exp; Type = 'Bearer'; TenantId = $(if ($c) { [string]$c.tid } else { $null }); UserId = $(if ($c) { [string]$c.appid } else { $null }) }
}

function Get-SIAzSubscriptionRest {
    [CmdletBinding()] param([string]$TenantId, [string]$SubscriptionId)
    foreach ($s in @(Invoke-SIArm -Path '/subscriptions' -ApiVersion '2022-12-01' -List)) {
        if ($TenantId -and [string]$s.tenantId -and [string]$s.tenantId -ne $TenantId) { continue }
        if ($SubscriptionId -and [string]$s.subscriptionId -ne $SubscriptionId) { continue }
        [pscustomobject]@{ Id = [string]$s.subscriptionId; SubscriptionId = [string]$s.subscriptionId; Name = [string]$s.displayName; State = [string]$s.state; TenantId = [string]$s.tenantId; HomeTenantId = [string]$s.tenantId }
    }
}

function Invoke-SIAzRestMethodRest {
    <# As Invoke-AzRestMethod: never throws on an HTTP status; returns StatusCode / Content / Headers / Method. #>
    [CmdletBinding()] param([string]$Path, [string]$Method = 'GET', [string]$Payload)
    if (-not $Method) { $Method = 'GET' }
    $uri = if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $Path }
    $body = if ($Payload) { $Payload } else { $null }
    # #564: a POST action with no body sends '{}' (an empty JSON body was refused with HTTP 415)
    if ($Method.ToUpperInvariant() -eq 'POST' -and $null -eq $body) { $body = '{}' }
    # #548: inside an Invardia support session through the recording wrapper, never a raw token
    if (Test-SISupportRequestRoute -Audience Arm) { $r = Invoke-SISupportHttp -Method $Method -Uri $uri -Body $body -ContentType 'application/json' -Audience Arm }
    else {
        $tok = Get-SIAzureToken -Audience Arm
        $r = Invoke-SIAzRestHttp -Method $Method -Uri $uri -Headers @{ Authorization = ('Bearer ' + $tok) } -Body $body -ContentType 'application/json'
    }
    return [pscustomobject]@{ StatusCode = [int]$r.StatusCode; Content = [string]$r.Content; Headers = $r.Headers; Method = $Method.ToUpperInvariant() }
}

function Invoke-SIAzOperationalInsightsQueryRest {
    [CmdletBinding()] param([string]$WorkspaceId, [string]$Query, [int]$Wait, [timespan]$Timespan, [switch]$AllowPartial, [scriptblock]$OnPage, [long]$PageBytes)
    $p = @{ WorkspaceId = $WorkspaceId; Query = $Query }
    if ($PSBoundParameters.ContainsKey('Wait')) { $p['Wait'] = $Wait }
    if ($PSBoundParameters.ContainsKey('Timespan')) { $p['Timespan'] = $Timespan }
    if ($AllowPartial) { $p['AllowPartial'] = $true }
    if ($OnPage) { $p['OnPage'] = $OnPage }
    if ($PSBoundParameters.ContainsKey('PageBytes') -and $PageBytes -gt 0) { $p['PageBytes'] = $PageBytes }
    return (Invoke-SILaQuery @p)
}

function ConvertTo-SIAzWorkspaceObject {
    param($Ws)
    $cid = [guid]::Empty
    [void][guid]::TryParse([string]$Ws.properties.customerId, [ref]$cid)
    $rg = if ([string]$Ws.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
    [pscustomobject]@{
        Name = [string]$Ws.name; ResourceId = [string]$Ws.id; ResourceGroupName = $rg; Location = [string]$Ws.location
        CustomerId = $cid; Sku = [string]$Ws.properties.sku.name; RetentionInDays = $Ws.properties.retentionInDays
        ProvisioningState = [string]$Ws.properties.provisioningState; Tags = $Ws.tags
    }
}

function Get-SIAzOperationalInsightsWorkspaceRest {
    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name)
    $sub = Get-SIAzRestSubscriptionId
    if ($ResourceGroupName -and $Name) {
        $ws = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$Name") -ApiVersion '2022-10-01' -AllowNotFound
        if (-not $ws) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The Log Analytics workspace '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
        return (ConvertTo-SIAzWorkspaceObject $ws)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces" } else { "/subscriptions/$sub/providers/Microsoft.OperationalInsights/workspaces" }
    foreach ($w in @(Invoke-SIArm -Path $path -ApiVersion '2022-10-01' -List)) {
        if ($Name -and [string]$w.name -ne $Name) { continue }
        ConvertTo-SIAzWorkspaceObject $w
    }
}

function New-SIAzOperationalInsightsWorkspaceRest {
    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name, [string]$Location, [string]$Sku = 'PerGB2018', [int]$RetentionInDays = 30)
    if (-not $Sku) { $Sku = 'PerGB2018' }
    $sub = Get-SIAzRestSubscriptionId
    $body = @{ location = $Location; properties = @{ sku = @{ name = $Sku } } }
    if ($PSBoundParameters.ContainsKey('RetentionInDays')) { $body.properties['retentionInDays'] = $RetentionInDays }
    $wsPath = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$Name"
    $ws = Invoke-SIArm -Method PUT -Path $wsPath -ApiVersion '2022-10-01' -Body $body
    # the create is asynchronous (its answer can be empty, or a workspace still being made): wait until the workspace is
    # THERE and provisioned -- its id and customer id are used right after this returns. Not ready in time = a clear stop.
    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
    $state = ''
    for ($i = 0; $i -lt 60; $i++) {
        $state = if ($ws -and $ws.properties) { [string]$ws.properties.provisioningState } else { '' }
        if ($ws -and [string]$ws.id -and ($state -eq 'Succeeded' -or -not $state)) { return (ConvertTo-SIAzWorkspaceObject $ws) }
        if ($state -in 'Failed', 'Canceled') { throw ("The Log Analytics workspace '{0}' was not created: Azure reports it {1} -- see the activity log of resource group '{2}' for its reason." -f $Name, $state, $ResourceGroupName) }
        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
        $ws = Invoke-SIArm -Path $wsPath -ApiVersion '2022-10-01' -AllowNotFound
    }
    throw ("The Log Analytics workspace '{0}' is not ready 5 minutes after it was created (Azure shows: {1})." -f $Name, $(if ($state) { $state } else { 'not there yet' }))
}

function New-SIAzGraphPage {
    <# A page shaped like Search-AzGraph's response: enumerates as the rows, with .Data and .SkipToken. #>
    param([object[]]$Rows, [string]$SkipToken)
    $list = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Rows)) { if ($null -ne $r) { [void]$list.Add($r) } }
    Add-Member -InputObject $list -NotePropertyName Data -NotePropertyValue $list.ToArray() -Force
    Add-Member -InputObject $list -NotePropertyName SkipToken -NotePropertyValue $(if ($SkipToken) { $SkipToken } else { $null }) -Force
    return ,$list
}

function Search-SIAzGraphRest {
    [CmdletBinding()] param([string]$Query, [int]$First = 100, [int]$Skip, [string[]]$Subscription, [string[]]$ManagementGroup, [string]$SkipToken)
    if (-not $PSBoundParameters.ContainsKey('First') -or $First -le 0) { $First = 100 }
    $page = Invoke-SIResourceGraphPage -Query $Query -Subscription $Subscription -ManagementGroup $ManagementGroup -First $First -Skip $Skip -SkipToken $SkipToken
    $p = New-SIAzGraphPage -Rows $page.Data -SkipToken $page.SkipToken
    return ,$p
}

function Get-SIAzKeyVaultSecretRest {
    [CmdletBinding()] param([string]$VaultName, [string]$Name, [switch]$AsPlainText)
    $j = Get-SIKeyVaultSecretRaw -VaultName $VaultName -Name $Name
    if (-not $j) { return }
    if ($AsPlainText) { return [string]$j.value }
    $sec = New-Object System.Security.SecureString
    foreach ($ch in ([string]$j.value).ToCharArray()) { $sec.AppendChar($ch) }
    $sec.MakeReadOnly()
    return [pscustomobject]@{ VaultName = $VaultName; Name = $Name; Id = [string]$j.id; SecretValue = $sec; ContentType = [string]$j.contentType; Enabled = $j.attributes.enabled; Tags = $j.tags }
}

function Set-SIAzKeyVaultSecretRest {
    <# PUT secrets/{name}: a new version of the secret. -SecretValue is a SecureString (as for the cmdlet) or plain text. #>
    [CmdletBinding()] param([string]$VaultName, [string]$Name, $SecretValue, [string]$ContentType)
    $plain = if ($SecretValue -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $SecretValue).Password } else { [string]$SecretValue }
    $body = @{ value = $plain }
    if ($ContentType) { $body.contentType = $ContentType }
    $uri = 'https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $VaultName, [uri]::EscapeDataString($Name)
    $r = Invoke-SIAzRestRequest -Method PUT -Uri $uri -Audience KeyVault -Body ($body | ConvertTo-Json -Compress) -What ("Key Vault secret '{0}' in '{1}'" -f $Name, $VaultName)
    $j = $r.Content | ConvertFrom-Json
    return [pscustomobject]@{ VaultName = $VaultName; Name = $Name; Id = [string]$j.id; ContentType = [string]$j.contentType; Enabled = $j.attributes.enabled }
}

function ConvertTo-SIAzResourceGroupObject {
    param($Rg)
    [pscustomobject]@{ ResourceGroupName = [string]$Rg.name; Location = [string]$Rg.location; ResourceId = [string]$Rg.id; ProvisioningState = [string]$Rg.properties.provisioningState; Tags = $Rg.tags }
}

function Get-SIAzResourceGroupRest {
    [CmdletBinding()] param([string]$Name)
    $sub = Get-SIAzRestSubscriptionId
    if ($Name) {
        $rg = Invoke-SIArm -Path ("/subscriptions/$sub/resourcegroups/$Name") -ApiVersion '2021-04-01' -AllowNotFound
        if (-not $rg) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Provided resource group '{0}' does not exist." -f $Name) -Target $Name; return }
        return (ConvertTo-SIAzResourceGroupObject $rg)
    }
    foreach ($rg in @(Invoke-SIArm -Path ("/subscriptions/$sub/resourcegroups") -ApiVersion '2021-04-01' -List)) { ConvertTo-SIAzResourceGroupObject $rg }
}

function New-SIAzResourceGroupRest {
    [CmdletBinding()] param([string]$Name, [string]$Location, [hashtable]$Tag)
    $sub = Get-SIAzRestSubscriptionId
    $body = @{ location = $Location }
    if ($Tag) { $body['tags'] = $Tag }
    $rg = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourcegroups/$Name") -ApiVersion '2021-04-01' -Body $body
    return (ConvertTo-SIAzResourceGroupObject $rg)
}

function Get-SIAzRestRoleDefinitions {
    <# Role definitions visible at -Scope (built-in + custom), cached per scope for the run. #>
    param([string]$Scope, [switch]$CustomOnly)
    $st = Get-SIAzRestState
    $key = 'roledefs|' + $Scope.ToLowerInvariant() + '|' + [string][bool]$CustomOnly
    if ($st.Cache.ContainsKey($key)) { return $st.Cache[$key] }
    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleDefinitions'
    if ($CustomOnly) { $path += '?$filter=' + [uri]::EscapeDataString("type eq 'CustomRole'") }
    $defs = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
    $st.Cache[$key] = $defs
    return $defs
}

function Get-SIAzRestRoleDefinitionNames {
    <#
        The role NAME of every role definition visible at -Scope, by its id (lowercase): @{ <id> = <roleName> }. For the
        role-assignment read, which needs only the name. Built-in roles are the same at every scope: they are read ONCE per
        run and kept as names only; a scope's custom roles are read per scope, names only. The full definitions (every
        permission of ~800 built-in roles) are never kept. customer B 2026-10-15: the identity producer read the role
        assignments of 1,195 subscriptions and kept the WHOLE definition list of every one of them (Get-SIAzRestRoleDefinitions
        caches per scope) -- the process ran out of memory in its sixth minute and every read after that failed.
        -Fetch (tests): { param($Path) } -> the ARM rows of that list.
    #>
    param([Parameter(Mandatory)][string]$Scope, [scriptblock]$Fetch)
    $st = Get-SIAzRestState
    $read = { param($p) if ($Fetch) { @(& $Fetch $p) } else { @(Invoke-SIArm -Path $p -ApiVersion '2022-04-01' -List) } }
    $base = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleDefinitions?$filter='
    $bk = 'roledefnames|builtin'
    if (-not $st.Cache.ContainsKey($bk)) {
        $m = @{}
        foreach ($d in (& $read ($base + [uri]::EscapeDataString("type eq 'BuiltInRole'")))) { if ($d -and $d.name) { $m[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName } }
        $st.Cache[$bk] = $m
    }
    $ck = 'roledefnames|custom|' + $Scope.ToLowerInvariant()
    if (-not $st.Cache.ContainsKey($ck)) {
        $m = @{}
        foreach ($d in (& $read ($base + [uri]::EscapeDataString("type eq 'CustomRole'")))) { if ($d -and $d.name) { $m[([string]$d.name).ToLowerInvariant()] = [string]$d.properties.roleName } }
        $st.Cache[$ck] = $m
    }
    [pscustomobject]@{ BuiltIn = $st.Cache[$bk]; Custom = $st.Cache[$ck] }
}

function ConvertTo-SIAzRoleDefinitionObject {
    param($D)
    $perm = @($D.properties.permissions) | Select-Object -First 1
    [pscustomobject]@{
        Name = [string]$D.properties.roleName; Id = [string]$D.name; IsCustom = ([string]$D.properties.type -eq 'CustomRole')
        Description = [string]$D.properties.description
        Actions = @($perm.actions); NotActions = @($perm.notActions); DataActions = @($perm.dataActions); NotDataActions = @($perm.notDataActions)
        AssignableScopes = @($D.properties.assignableScopes)
    }
}

function Get-SIAzRoleDefinitionRest {
    [CmdletBinding()] param([switch]$Custom, [string]$Name, [string]$Scope)
    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SIAzRestSubscriptionId) }
    $out = @(Get-SIAzRestRoleDefinitions -Scope $Scope -CustomOnly:$Custom | ForEach-Object { ConvertTo-SIAzRoleDefinitionObject $_ })
    if ($Name) { $out = @($out | Where-Object { $_.Name -eq $Name }) }
    return $out
}

function Resolve-SIAzRestPrincipalNames {
    <# DisplayName per object id, best effort (Microsoft Graph directoryObjects/getByIds). Empty on any failure: a name
       is informational, never a reason to fail the read. #>
    param([string[]]$Ids)
    $map = @{}
    $ids = @($Ids | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $ids.Count; $i += 1000) {
        $chunk = @($ids[$i..([Math]::Min($i + 999, $ids.Count - 1))])
        try {
            $r = Invoke-SIAzRestRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' -Audience Graph `
                     -Body (@{ ids = $chunk } | ConvertTo-Json -Compress) -What 'Microsoft Graph getByIds' -MaxAttempts 3
            foreach ($o in @(($r.Content | ConvertFrom-Json).value)) { if ($o.id) { $map[[string]$o.id] = [string]$o.displayName } }
        } catch { Write-Verbose ('principal names not resolved: {0}' -f $_.Exception.Message) }
    }
    return $map
}

function Get-SIAzRoleAssignmentRest {
    [CmdletBinding()] param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName)
    $explicitScope = [bool]$Scope
    if (-not $Scope) { $Scope = '/subscriptions/' + (Get-SIAzRestSubscriptionId) }
    $path = $Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments'
    if ($ObjectId) { $path += '?$filter=' + [uri]::EscapeDataString(("principalId eq '{0}'" -f $ObjectId)) }
    elseif ($explicitScope) { $path += '?$filter=' + [uri]::EscapeDataString('atScope()') }
    $items = @(Invoke-SIArm -Path $path -ApiVersion '2022-04-01' -List)
    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
    # names only, built-ins read once per run (Get-SIAzRestRoleDefinitionNames) -- never the whole definition list per scope
    $defs = Get-SIAzRestRoleDefinitionNames -Scope $subScope
    $names = Resolve-SIAzRestPrincipalNames -Ids @($items | ForEach-Object { [string]$_.properties.principalId })
    foreach ($a in $items) {
        $rdId = ([string]$a.properties.roleDefinitionId -split '/')[-1]
        $rdKey = $rdId.ToLowerInvariant()
        $rdName = if ($defs.BuiltIn.ContainsKey($rdKey)) { $defs.BuiltIn[$rdKey] } else { $defs.Custom[$rdKey] }
        if ($RoleDefinitionName -and $rdName -ne $RoleDefinitionName) { continue }
        $oid = [string]$a.properties.principalId
        [pscustomobject]@{
            RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = [string]$a.properties.scope
            DisplayName = $(if ($names.ContainsKey($oid)) { $names[$oid] } else { $null }); SignInName = $null
            RoleDefinitionName = $rdName; RoleDefinitionId = $rdId; ObjectId = $oid; ObjectType = [string]$a.properties.principalType
            CanDelegate = $false; Condition = $a.properties.condition
        }
    }
}

function New-SIAzRoleAssignmentRest {
    [CmdletBinding()] param([string]$ObjectId, [string]$Scope, [string]$RoleDefinitionName)
    $subScope = if ($Scope -match '^(/subscriptions/[^/]+)') { $Matches[1] } else { $Scope }
    $def = @(Get-SIAzRestRoleDefinitions -Scope $subScope | Where-Object { [string]$_.properties.roleName -eq $RoleDefinitionName }) | Select-Object -First 1
    if (-not $def) { throw ("The role definition '{0}' was not found at scope '{1}'." -f $RoleDefinitionName, $subScope) }
    $name = [guid]::NewGuid().ToString()
    $body = @{ properties = @{ roleDefinitionId = [string]$def.id; principalId = $ObjectId } }
    $a = Invoke-SIArm -Method PUT -Path ($Scope.TrimEnd('/') + '/providers/Microsoft.Authorization/roleAssignments/' + $name) -ApiVersion '2022-04-01' -Body $body
    return [pscustomobject]@{ RoleAssignmentId = [string]$a.id; RoleAssignmentName = [string]$a.name; Scope = $Scope; RoleDefinitionName = $RoleDefinitionName; RoleDefinitionId = [string]$def.name; ObjectId = $ObjectId; ObjectType = [string]$a.properties.principalType }
}

function Get-SIAzTagRest {
    [CmdletBinding()] param([string]$ResourceId)
    $t = Invoke-SIArm -Path ($ResourceId.TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -ApiVersion '2021-04-01'
    $h = @{}
    if ($t -and $t.properties -and $t.properties.tags) { foreach ($p in $t.properties.tags.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
    return [pscustomobject]@{ Id = [string]$t.id; Name = 'default'; Properties = [pscustomobject]@{ TagsProperty = $h } }
}

function Update-SIAzTagRest {
    [CmdletBinding()] param([string]$ResourceId, [hashtable]$Tag, [string]$Operation = 'Merge')
    if (-not $Operation) { $Operation = 'Merge' }
    $t = Invoke-SIArm -Method PATCH -Path ($ResourceId.TrimEnd('/') + '/providers/Microsoft.Resources/tags/default') -ApiVersion '2021-04-01' -Body @{ operation = $Operation; properties = @{ tags = $Tag } }
    $h = @{}
    if ($t -and $t.properties -and $t.properties.tags) { foreach ($p in $t.properties.tags.PSObject.Properties) { $h[$p.Name] = [string]$p.Value } }
    return [pscustomobject]@{ Id = [string]$t.id; Name = 'default'; Properties = [pscustomobject]@{ TagsProperty = $h } }
}

function Get-SIAzADServicePrincipalRest {
    [CmdletBinding()] param([string]$ApplicationId, [string]$ObjectId)
    $uri = if ($ObjectId) { 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=id,appId,displayName,servicePrincipalNames' -f $ObjectId }
           else { 'https://graph.microsoft.com/v1.0/servicePrincipals?$filter={0}&$select=id,appId,displayName,servicePrincipalNames' -f [uri]::EscapeDataString(("appId eq '{0}'" -f $ApplicationId)) }
    $r = Invoke-SIAzRestRequest -Method GET -Uri $uri -Audience Graph -AllowNotFound -What 'Microsoft Graph service principal'
    if (-not $r) { return }
    $j = $r.Content | ConvertFrom-Json
    $items = if ($j.PSObject.Properties['value']) { @($j.value) } else { @($j) }
    foreach ($s in $items) { if ($s) { [pscustomobject]@{ Id = [string]$s.id; AppId = [string]$s.appId; DisplayName = [string]$s.displayName; ServicePrincipalName = @($s.servicePrincipalNames) } } }
}

function ConvertTo-SIAzDceObject {
    param($D)
    [pscustomobject]@{
        Name = [string]$D.name; Id = [string]$D.id; Location = [string]$D.location
        LogIngestionEndpoint = [string]$D.properties.logsIngestion.endpoint; ConfigurationAccessEndpoint = [string]$D.properties.configurationAccess.endpoint
        NetworkAclsPublicNetworkAccess = [string]$D.properties.networkAcls.publicNetworkAccess; ProvisioningState = [string]$D.properties.provisioningState
    }
}

function Get-SIAzDataCollectionEndpointRest {
    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName)
    $sub = Get-SIAzRestSubscriptionId
    if ($Name -and $ResourceGroupName) {
        $d = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$Name") -ApiVersion '2022-06-01' -AllowNotFound
        if (-not $d) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The data collection endpoint '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
        return (ConvertTo-SIAzDceObject $d)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints" } else { "/subscriptions/$sub/providers/Microsoft.Insights/dataCollectionEndpoints" }
    foreach ($d in @(Invoke-SIArm -Path $path -ApiVersion '2022-06-01' -List)) { if (-not $Name -or [string]$d.name -eq $Name) { ConvertTo-SIAzDceObject $d } }
}

function New-SIAzDataCollectionEndpointRest {
    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName, [string]$Location, [string]$NetworkAclsPublicNetworkAccess = 'Enabled')
    if (-not $NetworkAclsPublicNetworkAccess) { $NetworkAclsPublicNetworkAccess = 'Enabled' }
    $sub = Get-SIAzRestSubscriptionId
    $d = Invoke-SIArm -Method PUT -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$Name") -ApiVersion '2022-06-01' `
             -Body @{ location = $Location; properties = @{ networkAcls = @{ publicNetworkAccess = $NetworkAclsPublicNetworkAccess } } }
    return (ConvertTo-SIAzDceObject $d)
}

function Get-SIAzDataCollectionRuleRest {
    [CmdletBinding()] param([string]$Name, [string]$ResourceGroupName)
    $sub = Get-SIAzRestSubscriptionId
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Insights/dataCollectionRules" } else { "/subscriptions/$sub/providers/Microsoft.Insights/dataCollectionRules" }
    foreach ($d in @(Invoke-SIArm -Path $path -ApiVersion '2022-06-01' -List)) {
        if ($Name -and [string]$d.name -ne $Name) { continue }
        [pscustomobject]@{ Name = [string]$d.name; Id = [string]$d.id; Location = [string]$d.location; ImmutableId = [string]$d.properties.immutableId; DataCollectionEndpointId = [string]$d.properties.dataCollectionEndpointId }
    }
}

function New-SIAzStorageContextRest {
    <# The storage "context" the REST path needs: the account name (and its endpoints). Every call
       signs in with the run's identity (OAuth); there is no account-key form. #>
    [CmdletBinding()] param([string]$StorageAccountName, [switch]$UseConnectedAccount)
    return [pscustomobject]@{
        PSTypeName = 'SI.AzRest.StorageContext'; SIRest = $true; StorageAccountName = $StorageAccountName
        BlobEndPoint = ('https://{0}.blob.core.windows.net/' -f $StorageAccountName)
        QueueEndPoint = ('https://{0}.queue.core.windows.net/' -f $StorageAccountName)
        TableEndPoint = ('https://{0}.table.core.windows.net/' -f $StorageAccountName)
    }
}

function Get-SIAzRestStorageAccountName {
    param($Context)
    if ($null -eq $Context) { throw 'No storage context was given.' }
    $n = [string]$Context.StorageAccountName
    if (-not $n) { throw 'The storage context does not name a storage account.' }
    return $n
}

function ConvertTo-SIAzStorageAccountObject {
    param($S)
    $rg = if ([string]$S.id -match '/resourceGroups/([^/]+)/') { $Matches[1] } else { $null }
    [pscustomobject]@{
        StorageAccountName = [string]$S.name; ResourceGroupName = $rg; Id = [string]$S.id; Location = [string]$S.location
        Kind = [string]$S.kind; Sku = $S.sku; PrimaryEndpoints = $S.properties.primaryEndpoints; ProvisioningState = [string]$S.properties.provisioningState
        Context = (New-SIAzStorageContextRest -StorageAccountName ([string]$S.name) -UseConnectedAccount)
    }
}

function Get-SIAzStorageAccountRest {
    [CmdletBinding()] param([string]$ResourceGroupName, [string]$Name)
    $sub = Get-SIAzRestSubscriptionId
    if ($ResourceGroupName -and $Name) {
        $s = Invoke-SIArm -Path ("/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Name") -ApiVersion '2023-01-01' -AllowNotFound
        if (-not $s) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("The storage account '{0}' was not found in resource group '{1}'." -f $Name, $ResourceGroupName) -Target $Name; return }
        return (ConvertTo-SIAzStorageAccountObject $s)
    }
    $path = if ($ResourceGroupName) { "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts" } else { "/subscriptions/$sub/providers/Microsoft.Storage/storageAccounts" }
    foreach ($s in @(Invoke-SIArm -Path $path -ApiVersion '2023-01-01' -List)) { if (-not $Name -or [string]$s.name -eq $Name) { ConvertTo-SIAzStorageAccountObject $s } }
}

function Get-SIStorageAccountCreateProperties {
    <#
        PURE. The properties EVERY storage account SecurityInsight creates gets: shared-key access OFF (no account key
        and no key-signed SAS works -- a user-delegation SAS still does), Entra ID the default in the portal, HTTPS only,
        TLS 1.2 at least, no public blob access. Every SecurityInsight host reaches its storage with its own identity
        (Storage Blob / Queue / Table Data roles), so nothing needs a key. An EXISTING account is never changed here;
        setup\Set-SIStorageSharedKey.ps1 -Disable switches one off after checking nothing still uses a key.
    #>
    return @{
        supportsHttpsTrafficOnly     = $true
        allowBlobPublicAccess        = $false
        allowSharedKeyAccess         = $false
        defaultToOAuthAuthentication = $true
        minimumTlsVersion            = 'TLS1_2'
    }
}

function New-SIAzStorageAccountRest {
    [CmdletBinding()]
    param([string]$ResourceGroupName, [string]$Name, [string]$Location, [string]$SkuName, [string]$Kind, [bool]$EnableHttpsTrafficOnly = $true,
          [string]$MinimumTlsVersion, [bool]$AllowBlobPublicAccess = $false,
          # #866 (a private install): 'Disabled' CREATES the account with no public access -- only its private endpoints
          [ValidateSet('', 'Disabled')][string]$PublicNetworkAccess = '')
    $sub = Get-SIAzRestSubscriptionId
    # -EnableHttpsTrafficOnly / -MinimumTlsVersion / -AllowBlobPublicAccess keep the Az cmdlet's shape, but a NEW
    # account is always created locked down (Get-SIStorageAccountCreateProperties): no caller can weaken it.
    $props = Get-SIStorageAccountCreateProperties
    if ($PublicNetworkAccess -eq 'Disabled') { $props['publicNetworkAccess'] = 'Disabled' }
    $path = "/subscriptions/$sub/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$Name"
    $null = Invoke-SIArm -Method PUT -Path $path -ApiVersion '2023-01-01' -Body @{ location = $Location; sku = @{ name = $SkuName }; kind = $Kind; properties = $props }
    # the create is asynchronous: wait until the account is THERE AND PROVISIONED (10 minutes at most) -- what follows
    # (its roles, its containers) is refused "operation in progress" on an account Azure is still making. A "not found"
    # in between is "not yet"; an account that is not ready in time is a clear stop, never handed on as if it were.
    $s = $null; $state = ''
    $sleep = Get-Variable -Scope Global -Name SI_ArmBusySleep -ValueOnly -ErrorAction Ignore
    for ($i = 0; $i -lt 120; $i++) {
        $s = Invoke-SIArm -Path $path -ApiVersion '2023-01-01' -AllowNotFound
        $state = if ($s -and $s.properties) { [string]$s.properties.provisioningState } else { '' }
        if ($s -and ($state -eq 'Succeeded' -or -not $state)) { return (ConvertTo-SIAzStorageAccountObject $s) }
        if ($state -in 'Failed', 'Canceled') { throw ("The storage account '{0}' was not created: Azure reports it {1} -- see the activity log of resource group '{2}' for its reason." -f $Name, $state, $ResourceGroupName) }
        if ($sleep -is [scriptblock]) { & $sleep 5 } else { Start-Sleep -Seconds 5 }
    }
    if (-not $s) { throw ("The storage account '{0}' was requested but did not appear." -f $Name) }
    throw ("The storage account '{0}' is not ready 10 minutes after it was created (Azure shows: {1})." -f $Name, $(if ($state) { $state } else { 'no state' }))
}

function Get-SIAzStorageContainerRest {
    [CmdletBinding()] param([string]$Name, [object]$Context)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    $c = Test-SIBlobContainer -Account $acct -Container $Name
    if (-not $c) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find the container '{0}' (ContainerNotFound)." -f $Name) -Target $Name; return }
    return $c
}

function New-SIAzStorageContainerRest {
    [CmdletBinding()] param([string]$Name, [object]$Context, [string]$Permission)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    return (New-SIBlobContainer -Account $acct -Container $Name)
}

function ConvertTo-SIAzBlobObject {
    <# A blob shaped like Get-AzStorageBlob's: Name / Length / LastModified / ETag, and the ICloudBlob members the call
       sites read (Name, Container.Name, Properties.ETag / LastModified / Length). #>
    param($B, [string]$Account)
    $cloud = [pscustomobject]@{
        Name = $B.Name; SIAccount = $Account
        Container = [pscustomobject]@{ Name = $B.Container }
        Properties = [pscustomobject]@{ ETag = $B.ETag; LastModified = $B.LastModified; Length = $B.Length; ContentType = $B.ContentType }
    }
    [pscustomobject]@{ Name = $B.Name; Length = $B.Length; LastModified = $B.LastModified; ETag = $B.ETag; ContentType = $B.ContentType; BlobType = 'BlockBlob'; ICloudBlob = $cloud }
}

function Get-SIAzStorageBlobRest {
    [CmdletBinding()] param([string]$Container, [string]$Blob, [string]$Prefix, [object]$Context)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    if ($Blob) {
        $b = Get-SIBlobProperties -Account $acct -Container $Container -Blob $Blob
        if (-not $b) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find blob '{0}' in container '{1}' (BlobNotFound)." -f $Blob, $Container) -Target $Blob; return }
        return (ConvertTo-SIAzBlobObject $b $acct)
    }
    foreach ($b in @(Get-SIBlobList -Account $acct -Container $Container -Prefix $Prefix)) { ConvertTo-SIAzBlobObject $b $acct }
}

function Get-SIAzStorageBlobContentRest {
    [CmdletBinding()] param([string]$Container, [string]$Blob, [object]$CloudBlob, [string]$Destination, [object]$Context, [switch]$Force)
    if ($CloudBlob) { $Blob = [string]$CloudBlob.Name; $Container = [string]$CloudBlob.Container.Name }
    $acct = if ($Context) { Get-SIAzRestStorageAccountName -Context $Context } else { [string]$CloudBlob.SIAccount }
    $target = $Destination
    if (-not $target) { $target = (Get-Location).Path }
    if (Test-Path -LiteralPath $target -PathType Container) { $target = [System.IO.Path]::Combine($target, ($Blob -replace '/', [System.IO.Path]::DirectorySeparatorChar)) }
    $dir = Split-Path -Parent $target
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $null = Get-SIBlobContent -Account $acct -Container $Container -Blob $Blob -Destination $target
    $b = Get-SIBlobProperties -Account $acct -Container $Container -Blob $Blob
    if ($b) { return (ConvertTo-SIAzBlobObject $b $acct) }
}

function Set-SIAzStorageBlobContentRest {
    [CmdletBinding()] param([string]$File, [string]$Container, [string]$Blob, [object]$Context, [switch]$Force)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    if (-not $Blob) { $Blob = Split-Path -Leaf $File }
    $etag = Set-SIBlobContent -Account $acct -Container $Container -Blob $Blob -File $File
    $len = (Get-Item -LiteralPath $File).Length
    return (ConvertTo-SIAzBlobObject ([pscustomobject]@{ Name = $Blob; Container = $Container; Length = $len; LastModified = [DateTimeOffset]::UtcNow; ETag = $etag; ContentType = 'application/octet-stream' }) $acct)
}

function Remove-SIAzStorageBlobRest {
    [CmdletBinding()] param([string]$Container, [string]$Blob, [object]$Context, [switch]$Force)
    Remove-SIBlob -Account (Get-SIAzRestStorageAccountName -Context $Context) -Container $Container -Blob $Blob
}

function Start-SIAzStorageBlobCopyRest {
    <# A copy within the account: download and upload (the files SI copies are small exports), so no SAS and no
       copy-source authorization is needed. #>
    [CmdletBinding()] param([string]$SrcContainer, [string]$SrcBlob, [string]$DestContainer, [string]$DestBlob, [object]$Context, [switch]$Force)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    $bytes = Get-SIBlobContent -Account $acct -Container $SrcContainer -Blob $SrcBlob
    $null = Set-SIBlobContent -Account $acct -Container $DestContainer -Blob $DestBlob -Bytes $bytes
    return [pscustomobject]@{ Name = $DestBlob; Container = $DestContainer }
}

function New-SIAzQueueObject {
    <# A queue shaped like Get-AzStorageQueue's: .QueueClient with SendMessage / ReceiveMessage / DeleteMessage, as the
       worker queue calls them. #>
    param([string]$Account, [string]$Name)
    $client = [pscustomobject]@{ Name = $Name; SIAccount = $Account }
    $client | Add-Member -MemberType ScriptMethod -Name SendMessage -Value { param($Text) Send-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -Text ([string]$Text) }
    $client | Add-Member -MemberType ScriptMethod -Name ReceiveMessage -Value {
        param($VisibilityTimeout)
        $secs = if ($VisibilityTimeout -is [timespan]) { [int]$VisibilityTimeout.TotalSeconds } elseif ($VisibilityTimeout) { [int]$VisibilityTimeout } else { 30 }
        [pscustomobject]@{ Value = (Receive-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -VisibilityTimeoutSeconds $secs) }
    }
    $client | Add-Member -MemberType ScriptMethod -Name DeleteMessage -Value { param($Id, $PopReceipt) Remove-SIQueueMessage -Account $this.SIAccount -Queue $this.Name -MessageId ([string]$Id) -PopReceipt ([string]$PopReceipt) }
    return [pscustomobject]@{ Name = $Name; QueueClient = $client }
}

function Get-SIAzStorageQueueRest {
    [CmdletBinding()] param([string]$Name, [object]$Context)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    if (-not (Test-SIQueue -Account $acct -Queue $Name)) { Write-SIAzRestNotFound -Cmdlet $PSCmdlet -Message ("Can not find queue '{0}' (QueueNotFound)." -f $Name) -Target $Name; return }
    return (New-SIAzQueueObject -Account $acct -Name $Name)
}

function New-SIAzStorageQueueRest {
    [CmdletBinding()] param([string]$Name, [object]$Context)
    $acct = Get-SIAzRestStorageAccountName -Context $Context
    New-SIQueue -Account $acct -Queue $Name
    return (New-SIAzQueueObject -Account $acct -Name $Name)
}

# #639 lane 4: a read in parts when one answer cannot carry it (Read-SILaParts) -- for every reader of a large result.
# Loaded LAST: it reads through this file's Invoke-SIAzOperationalInsightsQuery (and loads this file itself when it is
# dot-sourced alone, guarded on Invoke-SIArm -- defined by now, so never twice).
if (-not (Get-Command -Name Read-SILaParts -ErrorAction Ignore)) {
    $__siLaParts = [System.IO.Path]::Combine($PSScriptRoot, 'SI-LaParts.ps1')
    if ([System.IO.File]::Exists($__siLaParts)) { . $__siLaParts }
}
