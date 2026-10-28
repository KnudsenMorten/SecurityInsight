#Requires -Version 5.1
<#
    THE GRAPH REST CLIENT FOR ENGINES MIGRATING OFF THE Microsoft.Graph SDK (#113).

    🔑 WHY THIS EXISTS. Operator, 2026-09-08: *"do we need graph in image. can we use pure rest api"*.
    Measured answer: no, and REST was already the house style -- the four asset-profiling engines use
    ZERO `-Mg*` cmdlets, and every Graph call the remaining engines make already had a working REST
    implementation somewhere in this solution. The SDK was carrying no capability, only a dependency:
    enormous modules baked into every image for a handful of calls, a second auth path, and the
    mixed-module-version hazard where a bundled `Azure.Core` poisons `Connect-MgGraph` and cmdlets
    return SILENT NULLS.

    🔒 AUTH IS NOT DUPLICATED HERE. Tokens come from `auth/Get-SIGraphToken.ps1`, the solution's one
    token path (SPN secret or certificate, with its own cache). This file is transport only. Copying
    auth logic is how two paths drift into disagreeing about which identity is in use.

    📌 THERE IS AN OLDER PRIVATE COPY OF THIS PAGER, and it is deliberately left alone for now:
    `engine/asset-profiling/shared/IdentityRoleFetcher.ps1` defines its own `Invoke-SIGraphPaged` +
    `Get-SIGraphHttpStatus`. That engine is working, shipped and heavily tested; refactoring it in the
    same change that migrates two OTHER engines would put unrelated blast radius into one commit.
    ◻ Convergence is recorded as follow-up in `#113`. The behaviour here is modelled on that copy on
    purpose, so converging later is a deletion rather than a reconciliation.

    🔴 RETRY POLICY, and the distinction that matters most in this solution: TRANSIENT failures are
    retried; PERMANENT ones propagate immediately. A platform failure retried is a few seconds lost; a
    query defect retried burns a whole run and fails identically. That rule is `CLAUDE.md` working rule
    4, and findings `#99` and `#106` are both cases of it being got wrong in the other direction --
    a cancellation and a service-side resolution failure each reported as *"fix your query"*.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope (measured 2026-08-12), and the shipped
# engines deliberately run without it.

function New-SIGraphJsonBody {
    <#
        Serialise a request body to UTF-8 BYTES. Every POST in this file goes through here.

        🔴 THIS EXISTS BECAUSE A STRING BODY IS SILENTLY CORRUPTED ON PS 5.1, WHICH IS THE SHELL
        CUSTOMERS RUN. `Invoke-RestMethod -Body <string>` transcodes to a single-byte encoding, so
        every non-ASCII character is destroyed before it reaches the wire. MEASURED against a local
        HttpListener, capturing the actual received bytes:

            payload, correct UTF-8 : 47 bytes
            -Body <string>         : 35 bytes received, content mangled
            -Body <utf8 bytes>     : 47 bytes received, byte-exact

        🪤 IT FAILS AS A JSON ERROR, WHICH POINTS AT THE WRONG HALF. The service answers
        `400 BadRequest -- "Unable to read JSON request payload. Please ensure Content-Type header is
        set and payload is of valid JSON format."` The Content-Type *is* set and the JSON *was* valid
        when built; the bytes were broken in transit. Risk Analysis then classified it as a QUERY
        DEFECT and reported "re-running will fail identically" -- correct advice about the wrong cause.

        🔑 WHY IT SURVIVED THE OFFLINE SUITE AND ONLY APPEARED ON A LIVE RUN. It needs a non-ASCII
        character in the request. Plain KQL is ASCII; RA is the first caller to inline hundreds of real
        device and user names into the query body, and this estate is Danish -- æ, ø and å in a
        customer's own asset names are what broke it. No amount of offline testing would have produced
        that byte.

        📌 The charset must ALSO be declared on the Content-Type, or the service is entitled to guess.
    #>
    param(
        [Parameter(Mandatory)]$Object,
        [int]$Depth = 10
    )
    $json = ConvertTo-Json $Object -Depth $Depth -Compress
    # 🪤 THE LEADING COMMA IS LOAD-BEARING. PowerShell UNROLLS an array on return, so without it the
    # caller receives an Object[] of boxed bytes rather than a byte[] -- and Invoke-RestMethod then
    # does not treat the body as raw bytes at all, which reintroduces the very corruption this
    # function exists to prevent. Caught by `serialises to a byte array, not a string` before it
    # shipped; the failure is otherwise invisible until a live call with a non-ASCII character.
    # 📌 Note this is the OPPOSITE of the `,$x.ToArray()` trap warned about below: there the comma
    # wraps an empty result into a phantom single element, here it stops a real array being scattered.
    return ,[System.Text.Encoding]::UTF8.GetBytes($json)
}

function Invoke-SIGraphHttp {
    <#
        The transport. Returns status + body and NEVER throws on an HTTP status code.

        🔴 THIS EXISTS BECAUSE `Invoke-RestMethod` THROWS ON EVERY NON-2xx, AND A THROWN ERROR IS
        WRITTEN TO THE TRANSCRIPT EVEN WHEN IT IS CAUGHT. The first live run after the REST migration
        took `PS>TerminatingError` lines from **2 to 16** -- the exact noise
        `tests/pester/SI-TranscriptNoise.Tests.ps1` exists to prevent, and the operator's own
        complaint: *"it looks very amateur"*. The SDK path avoided it with
        `-ErrorAction SilentlyContinue`; there is no such switch for a REST client that throws by
        design, so the transport has to stop throwing instead.

        🪤 AND THE PROBE IS THE COMMON CASE, NOT THE RARE ONE. `Test-AdvancedHuntingHasTable` asks
        whether a custom LA table is mirrored into XDR, and the ANSWER IS NORMALLY NO -- arriving as a
        400. Every SI_*_Profile_CL table produces one, every run. That is a routing decision working
        correctly, and it was being written to the transcript as a terminating error.

        📌 `HttpClient` returns a response object for 4xx/5xx rather than raising, and it exists on
        PS 5.1 (.NET 4.5+). It still throws on a genuine transport failure or timeout, which is
        correct -- that is the TaskCanceled signal RA's bucket escalation depends on.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [ValidateSet('Get','Post')][string]$Method = 'Get',
        [byte[]]$BodyBytes,
        [string]$ContentType = 'application/json; charset=utf-8',
        [int]$TimeoutSec = 300,
        [hashtable]$ExtraHeaders
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $client = New-SIGraphHttpClient
    try {
        $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
        $req = New-Object System.Net.Http.HttpRequestMessage(
                    [System.Net.Http.HttpMethod]::$Method, $Uri)
        [void]$req.Headers.TryAddWithoutValidation('Authorization', ('Bearer ' + $Token))
        if ($ExtraHeaders) {
            foreach ($k in $ExtraHeaders.Keys) { [void]$req.Headers.TryAddWithoutValidation([string]$k, [string]$ExtraHeaders[$k]) }
        }
        if ($BodyBytes) {
            $content = New-Object System.Net.Http.ByteArrayContent(,$BodyBytes)
            # Set on the CONTENT, not the request: charset lives with the payload it describes.
            $content.Headers.Remove('Content-Type') | Out-Null
            [void]$content.Headers.TryAddWithoutValidation('Content-Type', $ContentType)
            $req.Content = $content
        }

        # PS 5.1 has no await, and this call is synchronous by design -- so the task is waited on here.
        # 🔴 GetAwaiter().GetResult(), NEVER .Result. `.Result` is a PROPERTY GETTER, and PowerShell
        # swallows an exception raised inside a getter: a timed-out request returned $null instead of
        # throwing, reached the caller as "0 HTTP error", and RA's AutoBucket escalation -- which keys
        # on the TaskCanceledException text -- never fired on the 900s ceiling. Measured on PS 5.1 and
        # pwsh 7 (#117). A method call throws: MethodInvocationException wrapping TaskCanceledException,
        # which the catch in Invoke-SIHuntingQueryRest already inspects (exception AND inner).
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $body = ''
        if ($resp.Content) { $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }

        return [pscustomobject]@{
            StatusCode    = [int]$resp.StatusCode
            Body          = $body
            Ok            = $resp.IsSuccessStatusCode
            RetryAfterSec = (Get-SIHttpRetryAfterSeconds -Response $resp)
        }
    } finally {
        if ($client) { $client.Dispose() }
    }
}

function New-SIGraphHttpClient {
    <# One HttpClient for one request. $script:SIGraphHttpHandler is a seam for tests only (an HttpMessageHandler that
       answers in-process); unset -- always, in a run -- it is the plain client. #>
    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue
    if ($null -ne $script:SIGraphHttpHandler) { return (New-Object System.Net.Http.HttpClient -ArgumentList $script:SIGraphHttpHandler, $false) }
    New-Object System.Net.Http.HttpClient
}

function Get-SIHttpRetryAfterSeconds {
    <# The seconds a 429 / 503 answer's Retry-After header asks for (a delay or a date); 0 when it says nothing. #>
    param($Response)
    try {
        if ($null -eq $Response -or $null -eq $Response.Headers -or $null -eq $Response.Headers.RetryAfter) { return 0 }
        $ra = $Response.Headers.RetryAfter
        if ($null -ne $ra.Delta) { return [int][Math]::Ceiling($ra.Delta.TotalSeconds) }
        if ($null -ne $ra.Date) { return [int][Math]::Max(0, [Math]::Ceiling(($ra.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds)) }
    } catch { }
    0
}

# ---- PARTS ASKED AHEAD (Risk Analysis: several query parts at a time) -----------------------------------------------
# Risk Analysis asks its parts one by one and processes each (scoring, the database) before it asks the next. With
# $script:SIHuntingPrefetch set (engine/risk-analysis/_shared/RA-PartsInParallel.ps1), the hunting request of a part
# further ahead is SENT now and its answer waits here, keyed by the exact request body: when the part's turn comes, its
# own call (Invoke-SIHuntingQueryRest, from the unchanged Invoke-GraphHuntingQuery) finds the answer instead of sending
# the same request again. Everything else -- the retries, the error classification, the order the parts are processed
# in -- is the one-at-a-time path, on the main thread. Only HttpClient runs in the background: no PowerShell code ever
# runs on another thread, so no engine state is shared between threads. Unset (every other engine, and RA with
# SI_RA_PartsInParallel_Max = 1): nothing here is used.
# (functions, not file-level variables: the same text wherever a file is loaded from)
function Get-SIHuntingAheadStartedText { 'the hunting request of this part was sent ahead -- its answer is read when the part runs' }
function Get-SIHuntingNotAheadText { 'this part is not asked ahead -- it is not answered by advanced hunting' }

function New-SIHuntingPrefetchStore {
    [pscustomobject]@{
        Capture = $false                                                                      # on while a part is being asked ahead
        Entries = (New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal))
        Answers = (New-Object System.Collections.Generic.List[object])                       # what each answer read here was like
        Part    = -1                                                                          # the part being asked ahead
    }
}

function Get-SIHuntingBodyKey {
    <# PURE. The key of one request: the SHA-256 of its exact body bytes. #>
    param([Parameter(Mandatory)][byte[]]$BodyBytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { [System.BitConverter]::ToString($sha.ComputeHash($BodyBytes)) -replace '-', '' } finally { $sha.Dispose() }
}

function Start-SIHuntingPrefetch {
    <# Sends one hunting request now and keeps its pending answer in the store. Returns the request's key. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][byte[]]$BodyBytes, [int]$TimeoutSec = 900)
    $key = Get-SIHuntingBodyKey -BodyBytes $BodyBytes
    if ($Store.Entries.ContainsKey($key)) { return $key }     # the same request is already on its way
    $client = New-SIGraphHttpClient
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::Post, $Uri)
    [void]$req.Headers.TryAddWithoutValidation('Authorization', ('Bearer ' + $Token))
    $content = New-Object System.Net.Http.ByteArrayContent(, $BodyBytes)
    $content.Headers.Remove('Content-Type') | Out-Null
    [void]$content.Headers.TryAddWithoutValidation('Content-Type', 'application/json; charset=utf-8')
    $req.Content = $content
    # the default completion (ResponseContentRead): the task completes with the answer's body already read
    $task = $client.SendAsync($req)
    $Store.Entries[$key] = [pscustomobject]@{ Key = $key; Part = [int]$Store.Part; Task = $task; Client = $client; Request = $req; Watch = [System.Diagnostics.Stopwatch]::StartNew(); Peeked = $false }
    $key
}

function Receive-SIHuntingPrefetch {
    <# The answer of a request sent ahead, in the shape Invoke-SIGraphHttp returns -- waiting for it if it is still on its
       way. A transport failure (the 900 s ceiling included) is thrown exactly as Invoke-SIGraphHttp throws it. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)]$Entry)
    $wait = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 0; $ra = 0
    try {
        # GetAwaiter().GetResult(), never .Result (see Invoke-SIGraphHttp: a getter swallows the timeout)
        $resp = $Entry.Task.GetAwaiter().GetResult()
        $body = ''
        if ($resp.Content) { $body = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult() }
        $status = [int]$resp.StatusCode
        $ra = Get-SIHttpRetryAfterSeconds -Response $resp
        return [pscustomobject]@{ StatusCode = $status; Body = $body; Ok = $resp.IsSuccessStatusCode; RetryAfterSec = $ra }
    } finally {
        $wait.Stop()
        $Store.Answers.Add([pscustomobject]@{ Part = [int]$Entry.Part; Status = $status; RetryAfterSec = $ra; WaitedSec = [double]$wait.Elapsed.TotalSeconds; Seconds = [double]$Entry.Watch.Elapsed.TotalSeconds; Peeked = [bool]$Entry.Peeked })
        try { $Entry.Client.Dispose() } catch { }
    }
}

function Remove-SIHuntingPrefetch {
    <# Drops answers sent ahead that no part will read (the report ended, ran again with more parts, or a part's request
       came out different): an answer still on its way is cancelled. Returns how many were dropped. #>
    param($Store, [string]$Key)
    if ($null -eq $Store) { return 0 }
    $keys = if ($Key) { @($Key) } else { @($Store.Entries.Keys) }
    $n = 0
    foreach ($k in $keys) {
        if (-not $Store.Entries.ContainsKey($k)) { continue }
        $e = $Store.Entries[$k]; [void]$Store.Entries.Remove($k); $n++
        try { $e.Client.CancelPendingRequests() } catch { }
        try { $e.Client.Dispose() } catch { }
    }
    $n
}

function Get-SIHuntingPrefetchThrottle {
    <# Looks at the answers sent ahead that have already come back, WITHOUT reading them for their part: the highest
       Retry-After of a 429 / 503 / 504 among them (-1: none was throttled). Each answer is looked at once. #>
    param($Store)
    $worst = -1
    if ($null -eq $Store) { return $worst }
    foreach ($e in @($Store.Entries.Values)) {
        if ($e.Peeked -or -not $e.Task.IsCompleted) { continue }
        $e.Peeked = $true
        if ($e.Task.Status -ne [System.Threading.Tasks.TaskStatus]::RanToCompletion) { continue }
        $r = $e.Task.GetAwaiter().GetResult()
        if ([int]$r.StatusCode -in 429, 503, 504) { $worst = [Math]::Max($worst, [int](Get-SIHttpRetryAfterSeconds -Response $r)) }
    }
    $worst
}

function Get-SIGraphRestStatus {
    <#
        Pull the HTTP status code out of an ErrorRecord across BOTH PowerShell editions.

        🪤 PS 5.1 and PS 7 do not agree here, and getting it wrong silently disables the retry policy:
        5.1 raises WebException with .Response.StatusCode, 7 raises HttpResponseException with
        .Response.StatusCode as an enum. A miss returns 0, which this treats as transient (a network
        reset produces no status at all), so a wrong read fails toward retrying rather than toward
        declaring a permanent defect.
    #>
    param([Parameter(Mandatory)]$ErrorRecord)

    $r = $ErrorRecord.Exception.Response
    if ($null -eq $r) { return 0 }
    try {
        $code = $r.StatusCode
        if ($null -eq $code) { return 0 }
        return [int]$code
    } catch { return 0 }
}

function Test-SIGraphRestTransient {
    <#
        429 throttle, 502/503/504 gateway, and 0 (no response at all -- a reset or timeout).

        🔒 408 and 409 are NOT here. A request timeout and a conflict both mean "this specific call
        will not succeed by repeating it unchanged", and quietly retrying them is how a run burns its
        budget looking busy.
    #>
    param([int]$Status)
    return ($Status -in 429, 502, 503, 504) -or ($Status -eq 0)
}

function Get-SIGraphRestRetryAfter {
    <# #882 (A2): the wait Graph asks for (Retry-After: seconds or an HTTP date), read on both editions; $null when absent. #>
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    try {
        $resp = $ErrorRecord.Exception.Response
        if (-not $resp) { return $null }
        if ($resp.Headers -and $resp.Headers.PSObject.Properties['RetryAfter'] -and $null -ne $resp.Headers.RetryAfter) {
            $t = $resp.Headers.RetryAfter
            if ($null -ne $t.Delta) { return [int][Math]::Max(0, [Math]::Ceiling($t.Delta.TotalSeconds)) }
            if ($null -ne $t.Date) { $d = [int][Math]::Ceiling(($t.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds); if ($d -gt 0) { return $d } }
            return $null
        }
        $raw = $null; try { $raw = $resp.Headers['Retry-After'] } catch { $raw = $null }
        $s = 0; if ($raw -and [int]::TryParse([string]$raw, [ref]$s)) { return [Math]::Max(0, $s) }
    } catch { }
    $null
}

function Invoke-SIGraphRest {
    <#
        One Graph call, with the transient-retry policy applied. GET, POST or PATCH.

          -Uri        absolute, or a /v1.0-relative path ('/servicePrincipals?...')
          -Token      from Get-SIGraphToken
          -Method     Get (default) | Post | Patch (asset tagging writes custom security attributes)
          -Body       hashtable, sent as JSON, POST / PATCH only
          -TimeoutSec per-attempt ceiling

        Returns the deserialised response object. Throws on permanent failure, after retries on
        transient failure -- so a caller that gets a return value knows the call actually worked.
    #>
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [ValidateSet('Get','Post','Patch')][string]$Method = 'Get',
        [hashtable]$Body,
        [int]$TimeoutSec = 300,
        # #882 (A2): 6 attempts (was 3 in ~3 s -- data sync, asset tagging and the close-loop mail failed under ordinary
        # Graph throttling), the wait Graph asks for (Retry-After) honoured, a 500 temporary for a read or a PATCH (never for
        # a POST, which may not be safe to repeat), and an expired token renewed once
        [int]$MaxAttempts = 6,
        [string]$ApiVersion = 'v1.0',
        # test seam: { param($Seconds) }
        [scriptblock]$Sleep
    )

    $url = if ($Uri -match '^https?://') { $Uri } else { ('https://graph.microsoft.com/{0}{1}' -f $ApiVersion, $Uri) }
    $headers = @{ Authorization = ('Bearer ' + $Token); 'ConsistencyLevel' = 'eventual' }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $renewed = $false

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $irmArgs = @{
                Method      = $Method
                Uri         = $url
                Headers     = $headers
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }
            if ($Method -eq 'Post' -or $Method -eq 'Patch') {
                # -Depth 10: the default of 2 silently truncates nested request bodies into the string
                # "System.Collections.Hashtable", which the service rejects with a message about the
                # payload rather than about the serialisation -- an error naming the wrong half.
                # 🔴 UTF-8 BYTES, NOT A STRING -- see New-SIGraphJsonBody. A string body is silently
                # transcoded to a single-byte encoding by PS 5.1 and every non-ASCII character is
                # destroyed.
                $irmArgs['Body']        = (New-SIGraphJsonBody -Object $Body -Depth 10)
                $irmArgs['ContentType'] = 'application/json; charset=utf-8'
            }
            return Invoke-RestMethod @irmArgs
        } catch {
            $status = Get-SIGraphRestStatus -ErrorRecord $_
            if ($status -eq 401 -and -not $renewed -and $url -match '^https://graph\.microsoft\.com/' -and (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) {
                $renewed = $true; $attempt--
                $tk = $null; try { $tk = [string](Get-SIGraphToken -Resource Graph -ForceRefresh) } catch { $tk = $null }
                if ($tk) { $headers['Authorization'] = 'Bearer ' + $tk; continue }
            }
            $temp = (Test-SIGraphRestTransient -Status $status) -or ($status -eq 500 -and $Method -ne 'Post')
            if (-not $temp -or $attempt -ge $MaxAttempts) { throw }
            $delay = Get-SIGraphRestRetryAfter -ErrorRecord $_
            if ($null -eq $delay) { $delay = [int][Math]::Min(60, [Math]::Pow(2, $attempt)) }   # 2, 4, 8, 16, 32 s
            Write-Verbose ('Graph transient error (HTTP {0}) on {1} -- retry {2}/{3} in {4}s' -f $status, $url, $attempt, $MaxAttempts, $delay)
            & $Sleep $delay
        }
    }
}

function Invoke-SIGraphRestPaged {
    <#
        GET with `@odata.nextLink` paging. Returns the combined `.value` array.

        🪤 RETURNS A REAL ARRAY, ALWAYS. `,$list.ToArray()` is the shape that has defeated guards in
        this codebase repeatedly -- with zero results a `@(...)` wrapper yields an array CONTAINING an
        empty array, so `.Count` reads 1 and "nothing found" becomes "found one thing". Emitting the
        ArrayList's ToArray() directly keeps an empty result empty.
    #>
    param(
        [Parameter(Mandatory)][string]$RelativeUrl,
        [Parameter(Mandatory)][string]$Token,
        [int]$TimeoutSec = 300,
        [string]$ApiVersion = 'v1.0'
    )

    $all = New-Object System.Collections.ArrayList
    $url = $RelativeUrl
    while ($url) {
        $resp = Invoke-SIGraphRest -Uri $url -Token $Token -Method Get -TimeoutSec $TimeoutSec -ApiVersion $ApiVersion
        if ($null -ne $resp -and $resp.PSObject.Properties['value'] -and $null -ne $resp.value) {
            foreach ($item in @($resp.value)) { [void]$all.Add($item) }
        }
        # The nextLink is absolute and already carries the query + skiptoken.
        $url = if ($resp -and $resp.PSObject.Properties['@odata.nextLink']) { [string]$resp.'@odata.nextLink' } else { $null }
    }
    return $all.ToArray()
}

function Invoke-SIHuntingQueryRest {
    <#
        Advanced Hunting over REST -- the replacement for `Start-MgBetaSecurityHuntingQuery` (#113b).

        🔑 IT IS THE SAME ENDPOINT THE SDK CALLED. `POST /security/runHuntingQuery`, which
        `engine/asset-profiling/shared/HuntingQuery.ps1:136` has been calling directly all along, and
        which Risk Analysis' own comments name while debugging the nginx in front of it
        (`RA-GraphHunting.ps1:593,659`). The SDK was a wrapper over this URL, not a capability.

        🔒 THIS RETURNS THE SDK'S RESPONSE SHAPE ON PURPOSE, and that is the whole design of the port.
        `Invoke-RiskAnalysis.ps1` reads `$resp.Results.AdditionalProperties` in FOUR places, and
        `RA-ExcelReport.ps1` documents that bag as the row source. Returning raw Graph JSON would have
        meant changing every one of those and the tests around them. Emitting
        `Results[].AdditionalProperties` confines the change to the transport, so nothing downstream
        moves.

        🔴 NO RETRY HERE, DELIBERATELY, AND IT IS NOT AN OVERSIGHT. `Invoke-SIGraphRest` retries
        429/502/503/504 -- correct for ordinary reads, WRONG for hunting. Risk Analysis records why:
        a 502 from the nginx in front of the AH backend is the deterministic "response too large to
        proxy" signal, and "retrying the identical query just burns 4 more attempts (each up to 900s)
        on the same fail". The bucket-escalation loop OWNS retry for this call; a second retry policy
        underneath it would silently multiply a 15-minute failure by four.

        🪤 THE TWO ERROR SIGNALS MUST SURVIVE THE TRANSPORT CHANGE, or AutoBucket escalation stops and
        nothing says so. Downstream classification matches on TEXT:
          * the 900s ceiling must still read as `TaskCanceledException` -- under the SDK it arrived as
            that type; over REST a client timeout is a WebException on 5.1 and a TaskCanceled/
            HttpRequestException on 7, so it is NORMALISED to text containing 'TaskCanceledException'.
          * a 502 must still read as `502 Bad Gateway`. Invoke-RestMethod's own message is
            "(502) Bad Gateway" -- parenthesised -- which does NOT match the existing
            `-match '502 Bad Gateway'`. The status line is therefore composed explicitly.
        Getting either wrong does not throw; it silently stops the ramp on exactly the reports that
        need it, which is the failure this comment exists to prevent.
    #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [Parameter(Mandatory)][string]$Token,
        [int]$TimeoutSec  = 900,          # matches the old Set-MgRequestContext -ClientTimeout 900
        [string]$ApiVersion = 'beta',     # the SDK cmdlet was the BETA one; endpoint kept identical

        # 🔒 Return a result object instead of throwing. Used by the advanced-hunting PROBE, whose
        # expected answer is a 400 -- once per SI_*_Profile_CL table, every run. See the comment at
        # the throw site: this is what keeps a working routing decision out of the transcript.
        [switch]$AsResult
    )

    $url  = ('https://graph.microsoft.com/{0}/security/runHuntingQuery' -f $ApiVersion)
    # 🔴 UTF-8 BYTES. RA inlines real device and user names into the query, so this body carries
    # customer data, not just KQL -- and on PS 5.1 a STRING body loses every non-ASCII character.
    # That is not theoretical: it is what a live run produced on 2026-09-08, as 400 BadRequest
    # "Unable to read JSON request payload" on 18 buckets. See New-SIGraphJsonBody.
    $body = New-SIGraphJsonBody -Object @{ Query = $Query } -Depth 5

    $errText = $null
    $http    = $null
    # PARTS ASKED AHEAD (see Start-SIHuntingPrefetch): while a part is asked ahead its request is sent now and left on its
    # way; when the part runs, its own request finds that answer. The probe (-AsResult) is never asked ahead.
    $__pf = $null
    if (-not $AsResult -and $null -ne $script:SIHuntingPrefetch) {
        if ($script:SIHuntingPrefetch.Capture) {
            $null = Start-SIHuntingPrefetch -Store $script:SIHuntingPrefetch -Uri $url -Token $Token -BodyBytes $body -TimeoutSec $TimeoutSec
            throw (Get-SIHuntingAheadStartedText)
        }
        if ($script:SIHuntingPrefetch.Entries.Count -gt 0) {
            $__pfKey = Get-SIHuntingBodyKey -BodyBytes $body
            if ($script:SIHuntingPrefetch.Entries.ContainsKey($__pfKey)) { $__pf = $script:SIHuntingPrefetch.Entries[$__pfKey]; [void]$script:SIHuntingPrefetch.Entries.Remove($__pfKey) }
        }
    }
    # a request sent here and now while parts are asked ahead is measured too (the engine waited for all of it): how quickly
    # Defender answers -- and whether it throttles -- is learned from every answer, not only from the parts asked ahead
    $__direct = if ($null -eq $__pf -and -not $AsResult -and $null -ne $script:SIHuntingPrefetch) { [System.Diagnostics.Stopwatch]::StartNew() } else { $null }
    try {
        $http = if ($null -ne $__pf) { Receive-SIHuntingPrefetch -Store $script:SIHuntingPrefetch -Entry $__pf }
                else { Invoke-SIGraphHttp -Uri $url -Token $Token -Method Post -BodyBytes $body -TimeoutSec $TimeoutSec }
        if ($null -ne $__direct) {
            $__direct.Stop()
            $script:SIHuntingPrefetch.Answers.Add([pscustomobject]@{ Part = -1; Status = [int]$http.StatusCode; RetryAfterSec = [int]$http.RetryAfterSec; WaitedSec = [double]$__direct.Elapsed.TotalSeconds; Seconds = [double]$__direct.Elapsed.TotalSeconds; Peeked = $false })
        }
    } catch {
        # Only a genuine TRANSPORT failure reaches here now -- HTTP status codes come back as data.
        # A timeout arrives as TaskCanceledException wrapped in the MethodInvocationException that
        # GetResult() raises through PowerShell, so both the exception and its inner are inspected.
        $ex = $_.Exception
        $inner = $ex.InnerException
        $isTimeout = ($ex -is [System.Threading.Tasks.TaskCanceledException]) -or
                     ($inner -is [System.Threading.Tasks.TaskCanceledException]) -or
                     ($ex -is [System.Net.WebException] -and $ex.Status -eq [System.Net.WebExceptionStatus]::Timeout) -or
                     ($ex.Message -match 'timed out' -or $ex.Message -match 'canceled' -or $ex.Message -match 'cancelled')
        if ($isTimeout) {
            $errText = ("TaskCanceledException: the request was canceled due to the configured timeout of {0} seconds elapsing." -f $TimeoutSec)
        } else {
            $errText = [string]$ex.Message
        }
    }

    if (-not $errText -and $http -and -not $http.Ok) {
        # ---- compose the status line the classifiers already match on -------------------------------
        # 🪤 The BODY is appended because the AH backend puts the real reason there -- including the
        # "Query cancelled on creation" text that #99/#106 turn on, and the "Failed to resolve table"
        # text the advanced-hunting probe reads. The status line alone does not carry it.
        $reason = switch ($http.StatusCode) {
            502 { 'Bad Gateway' }
            503 { 'Service Unavailable' }
            504 { 'Gateway Timeout' }
            413 { 'Request Entity Too Large' }
            429 { 'Too Many Requests' }
            400 { 'Bad Request' }
            default { 'HTTP error' }
        }
        # the service's Retry-After, when it sent one, in the words Get-RABucketRetryDelaySeconds reads
        $__ra = if ($http.PSObject.Properties['RetryAfterSec'] -and [int]$http.RetryAfterSec -gt 0) { (' (retry-after {0}s)' -f [int]$http.RetryAfterSec) } else { '' }
        $errText = ("{0} {1} -- {2}" -f $http.StatusCode, ($reason + $__ra), $http.Body)
    }

    if ($errText) {
        # 🔒 -AsResult IS WHAT KEEPS THE TRANSCRIPT CLEAN, and it is not a convenience. The
        # advanced-hunting PROBE asks whether a custom LA table is mirrored into XDR and the answer is
        # normally NO, arriving as a 400 -- once per SI_*_Profile_CL table, every run. Throwing there
        # writes a terminating error to the transcript for a routing decision that worked perfectly.
        # The QUERY path still throws, because RA's bucket-escalation loop is built around catching it.
        if ($AsResult) { return [pscustomobject]@{ Ok = $false; Error = $errText; Results = @(); Schema = $null } }
        throw $errText
    }

    $resp = $null
    if ($http -and $http.Body) {
        try { $resp = $http.Body | ConvertFrom-Json } catch {
            $msg = ('advanced hunting returned a body that is not JSON: {0}' -f $_.Exception.Message)
            if ($AsResult) { return [pscustomobject]@{ Ok = $false; Error = $msg; Results = @(); Schema = $null } }
            throw $msg
        }
    }

    # ---- adapt to the SDK's shape ------------------------------------------------------------------
    # Each row becomes an object carrying an AdditionalProperties dictionary, because that is exactly
    # what `Results[].AdditionalProperties` broadcasts over downstream.
    $rows = New-Object System.Collections.ArrayList
    if ($null -ne $resp -and $resp.PSObject.Properties['results'] -and $null -ne $resp.results) {
        foreach ($r in @($resp.results)) {
            $bag = [ordered]@{}
            foreach ($p in $r.PSObject.Properties) { $bag[$p.Name] = $p.Value }
            [void]$rows.Add([pscustomobject]@{ AdditionalProperties = $bag })
        }
    }
    $schema = if ($resp -and $resp.PSObject.Properties['schema']) { $resp.schema } else { $null }
    # 📌 Ok/Error are present on the SUCCESS shape too, so an -AsResult caller can test one property
    # either way rather than distinguishing two different object shapes.
    return [pscustomobject]@{ Schema = $schema; Results = $rows.ToArray(); Ok = $true; Error = $null }
}
