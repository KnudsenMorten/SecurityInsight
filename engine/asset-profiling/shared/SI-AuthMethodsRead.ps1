#Requires -Version 5.1
<#
    PASSWORDLESS-ONLY ACCOUNTS ARE READ, NOT GUESSED (REQUIREMENTS #549, owner 2026-10-10: "Yes, add the permission").

    The identity discovery reads each kept user's authentication methods -- GET /users/{id}/authentication/methods --
    through Microsoft Graph $batch (20 users per request) and decides si_passwordless_only from what it gets back.
    Application permission: UserAuthenticationMethod.Read.All (config/permissions.locked.json, collection identity).

    🔒 THE RULE (docs/DESIGN.md "Passwordless-only accounts" carries the same text)
      false   the user's method list was read completely and holds a #microsoft.graph.passwordAuthenticationMethod.
              A password that exists is a password that can be used: Graph cannot say that a password is blocked by
              Conditional Access or an authentication strength, so a password that is present always counts (the
              strictest correct reading).
      true    the list was read completely, it holds NO password method, the account is a cloud-only MEMBER account
              (not synchronised from Active Directory, not a guest / external account) and it holds at least one method
              Microsoft documents as a way to sign in without a password: FIDO2 security key / passkey, Windows Hello
              for Business, Microsoft Authenticator, platform credential (macOS), certificate-based authentication,
              Temporary Access Pass, SMS sign-in (phone), QR code.
      unknown everything else: the read was refused (no permission / consent yet), throttled out, stopped part-way, the
              list was paged (not read whole), the user was not read (guest, soft-deleted, disabled while disabled
              accounts are not collected), a synchronised or guest account without a cloud password method (its password
              lives in Active Directory or in its home tenant, which this read cannot see), or a list with no password
              and no sign-in method.
      UNKNOWN IS NEVER FALSE: a report reads unknown as "may use a password".

    COMPLETENESS
      Per user: ReadComplete (this user's list was read whole). Per run: Get-SIEntraAuthMethodsState -- Requested /
      Read / Unread / Refused / Throttled / Complete / Error. The discovery stamps ENTRA_AuthMethodsReadComplete and
      ENTRA_PasswordlessOnly on every user it builds; the record part 'authenticationMethods' of the user's Entra record
      is written only for a user whose list was read whole.

    THROTTLING IS NORMAL (#532): a 429 / 503 / 504 is retried (the batch's own Retry-After, and each throttled item's
    Retry-After), the users still throttled after the last round stay unknown, and the run says so in ONE plain
    information line -- never a warning, never a failed run. A refused read (401 / 403) stops the read at once (the
    permission is tenant-wide; reading on would only collect more refusals) and says so in ONE plain line.

    Offline-testable: every Graph call goes through -Post (test seam) and every wait through -Sleep.
#>

$script:SIAuthMethodPasswordType = '#microsoft.graph.passwordauthenticationmethod'
# Microsoft's documented authentication method types that sign a user in WITHOUT a password (lower case, as compared)
$script:SIAuthMethodPasswordlessSignInTypes = @(
    '#microsoft.graph.fido2authenticationmethod',
    '#microsoft.graph.windowshelloforbusinessauthenticationmethod',
    '#microsoft.graph.microsoftauthenticatorauthenticationmethod',
    '#microsoft.graph.platformcredentialauthenticationmethod',
    '#microsoft.graph.x509certificateauthenticationmethod',
    '#microsoft.graph.temporaryaccesspassauthenticationmethod',
    '#microsoft.graph.phoneauthenticationmethod',
    '#microsoft.graph.qrcodepinauthenticationmethod'
)
$script:SIAuthMethodBatchSize = 20

if (-not (Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue)) { $script:_SICache = @{} }

function Get-SIAuthMethodTypes {
    <# PURE. The lower-cased @odata.type of each method object (strings are taken as types). #>
    param([AllowNull()]$Methods)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in @($Methods)) {
        if ($null -eq $m) { continue }
        $t = $null
        if ($m -is [string]) { $t = $m }
        elseif ($m -is [System.Collections.IDictionary]) { $t = [string]$m['@odata.type'] }
        else { $p = $m.PSObject.Properties['@odata.type']; if ($p) { $t = [string]$p.Value } }
        if ($t) { $out.Add($t.Trim().ToLowerInvariant()) }
    }
    # one by one: every caller collects with @(...), and a `, $array` return read through @() nests (one element: the array)
    foreach ($t in $out) { $t }
}

function Test-SIAuthMethodUserIsCloudMember {
    <# PURE. $true for a cloud-only member account: not synchronised from AD, userType Member, no #EXT# in the UPN. #>
    param([AllowNull()]$User)
    if ($null -eq $User) { return $false }
    if ($User.PSObject.Properties['onPremisesSyncEnabled'] -and [bool]$User.onPremisesSyncEnabled) { return $false }
    $type = ''; if ($User.PSObject.Properties['userType']) { $type = [string]$User.userType }
    if ($type -and $type -ne 'Member') { return $false }
    $upn = ''; if ($User.PSObject.Properties['userPrincipalName']) { $upn = [string]$User.userPrincipalName }
    if ($upn -match '#EXT#') { return $false }
    return $true
}

function Get-SIPasswordlessOnlyVerdict {
    <#
        PURE. si_passwordless_only for ONE user: $true / $false / $null (unknown). The rule is in the header above.
          -Methods       the method objects (or their @odata.type strings) the read returned
          -ReadComplete  the user's list was read whole -- anything else is unknown, never false
          -User          the Graph user (onPremisesSyncEnabled, userType, userPrincipalName)
    #>
    param([AllowNull()]$Methods, [bool]$ReadComplete, [AllowNull()]$User)
    if (-not $ReadComplete) { return $null }
    $types = @(Get-SIAuthMethodTypes -Methods $Methods)
    if ($types -contains $script:SIAuthMethodPasswordType) { return $false }
    if (-not (Test-SIAuthMethodUserIsCloudMember -User $User)) { return $null }
    foreach ($t in $types) { if ($script:SIAuthMethodPasswordlessSignInTypes -contains $t) { return $true } }
    return $null
}

function Select-SIAuthMethodReadUsers {
    <#
        PURE. The users whose methods are read: the users the identity profile keeps and for whom the answer can be
        true or false -- not soft-deleted, not a guest / external account (their sign-in methods live in their home
        tenant), and a disabled account only while disabled accounts are collected (SI_DisabledAssets_Collect,
        -IncludeDisabled).
    #>
    param([AllowNull()]$Users, [bool]$IncludeDisabled = $true)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($u in @($Users)) {
        if ($null -eq $u -or -not $u.PSObject.Properties['id'] -or -not [string]$u.id) { continue }
        if ($u.PSObject.Properties['ENTRA_IsDeleted'] -and [bool]$u.ENTRA_IsDeleted) { continue }
        if ($u.PSObject.Properties['deletedDateTime'] -and $u.deletedDateTime) { continue }
        $type = ''; if ($u.PSObject.Properties['userType']) { $type = [string]$u.userType }
        if ($type -and $type -ne 'Member') { continue }
        if ($u.PSObject.Properties['userPrincipalName'] -and [string]$u.userPrincipalName -match '#EXT#') { continue }
        if (-not $IncludeDisabled -and $u.PSObject.Properties['accountEnabled'] -and $u.accountEnabled -eq $false) { continue }
        $out.Add($u)
    }
    # one by one (the caller collects with @(...); a `, $array` return read through @() nests)
    foreach ($u in $out) { $u }
}

function Get-SIAuthMethodItemRetryAfter {
    <# PURE. A $batch item's Retry-After in seconds ($null when absent). #>
    param([AllowNull()]$Item)
    if ($null -eq $Item -or -not $Item.PSObject.Properties['headers'] -or $null -eq $Item.headers) { return $null }
    foreach ($p in $Item.headers.PSObject.Properties) {
        if ($p.Name -ieq 'Retry-After') { $s = 0; if ([int]::TryParse([string]$p.Value, [ref]$s)) { return [Math]::Max(0, $s) } }
    }
    if ($Item.headers -is [System.Collections.IDictionary]) {
        foreach ($k in $Item.headers.Keys) { if ([string]$k -ieq 'Retry-After') { $s = 0; if ([int]::TryParse([string]$Item.headers[$k], [ref]$s)) { return [Math]::Max(0, $s) } } }
    }
    $null
}

function Get-SIAuthMethodsMissingLine {
    <# PURE. The one plain line a run prints when the sign-in methods could not be read for every user. Customer text. #>
    param([Parameter(Mandatory)]$State)
    if ([bool]$State.Refused) {
        return 'Passwordless sign-in could not be checked this run: Microsoft refused to list the users'' sign-in methods. SecurityInsight''s identity needs the Microsoft Graph application permission UserAuthenticationMethod.Read.All with admin consent -- run the permission setup again (setup\Grant-SIIdentity.ps1 -Apply, or setup\Grant-SIIdentity.ps1 -AppId <client id> -Apply for an app registration). Until then "passwordless only" shows as unknown, never as no.'
    }
    $why = if ([bool]$State.Throttled) { 'Microsoft asked SecurityInsight to slow down' } elseif ([string]$State.Error) { [string]$State.Error } else { 'no reason given' }
    ('Passwordless sign-in was checked for {0:N0} of {1:N0} users this run; the rest were not read ({2}). For those users "passwordless only" shows as unknown, never as no.' -f [int]$State.Read, [int]$State.Requested, $why)
}

function Update-SIAuthMethodConcurrency {
    <#
        PURE (changes -State). #874: how many $batch requests the next wave sends -- one more after a wave Microsoft answered
        without a 429, half (never below one) after a throttled wave. Returns the new number.
    #>
    param([Parameter(Mandatory)]$State, [bool]$Throttled)
    $c = [Math]::Max(1, [int]$State.Concurrency)
    if ($Throttled) {
        $c = [Math]::Max(1, [int][Math]::Floor($c / 2))
        if ($State.PSObject.Properties['ThrottledWaves']) { $State.ThrottledWaves = [int]$State.ThrottledWaves + 1 }
    } else { $c = $c + 1 }
    $State.Concurrency = $c
    $c
}

function Invoke-SIAuthMethodBatchRequests {
    <#
        #874: the $batch bodies sent to Microsoft Graph AT ONCE (one HTTP request each, all in flight together) -- one outcome
        per body, in order: @{ Response (the parsed answer); Status (0 = no answer); RetryAfter (seconds or $null); Error }.
        Never throws. REST / .NET only.
    #>
    param([Parameter(Mandatory)][string]$Token, [string[]]$Bodies = @(), [int]$TimeoutSeconds = 100)
    $out = New-Object System.Collections.Generic.List[object]
    if (@($Bodies).Count -eq 0) { return , $out.ToArray() }
    try { Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue } catch { }
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    try {
        $tasks = New-Object System.Collections.Generic.List[object]
        foreach ($b in @($Bodies)) {
            try {
                $req = New-Object System.Net.Http.HttpRequestMessage ([System.Net.Http.HttpMethod]::Post), 'https://graph.microsoft.com/v1.0/$batch'
                $req.Headers.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue 'Bearer', $Token
                $req.Content = New-Object System.Net.Http.StringContent ([string]$b), ([System.Text.Encoding]::UTF8), 'application/json'
                $tasks.Add($client.SendAsync($req))
            } catch { $tasks.Add($_.Exception) }
        }
        foreach ($t in $tasks) {
            if ($t -is [System.Exception]) { $out.Add([pscustomobject]@{ Response = $null; Status = 0; RetryAfter = $null; Error = $t.Message }); continue }
            try {
                $resp = $t.GetAwaiter().GetResult()
                $status = [int]$resp.StatusCode
                $ra = $null
                # (PowerShell hands a Nullable<T> over as T or $null: .Delta is a TimeSpan here, .Date a DateTimeOffset)
                try { $rah = $resp.Headers.RetryAfter; if ($rah) { if ($null -ne $rah.Delta) { $ra = [int][Math]::Ceiling(([TimeSpan]$rah.Delta).TotalSeconds) } elseif ($null -ne $rah.Date) { $ra = [int][Math]::Max(0, [Math]::Ceiling((([DateTimeOffset]$rah.Date).UtcDateTime - [datetime]::UtcNow).TotalSeconds)) } } } catch { }
                $text = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                $parsed = $null
                if ($status -eq 200 -and $text) { try { $parsed = $text | ConvertFrom-Json } catch { $parsed = $null } }
                $err = ''; if ($status -ne 200) { $err = ('{0} {1}' -f $status, [string]$resp.ReasonPhrase) }
                $out.Add([pscustomobject]@{ Response = $parsed; Status = $status; RetryAfter = $ra; Error = $err })
                $resp.Dispose()
            } catch {
                $m = $_.Exception.Message; if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
                $out.Add([pscustomobject]@{ Response = $null; Status = 0; RetryAfter = $null; Error = $m })
            }
        }
    } finally { $client.Dispose() }
    , $out.ToArray()
}

function Get-SIAuthMethodsPaceLine {
    <# PURE. #874: how the read went -- the requests, the most sent at once, how often Microsoft asked to slow down. Plain text. #>
    param([Parameter(Mandatory)]$State)
    if (-not $State.PSObject.Properties['Requests'] -or [int]$State.Requests -eq 0) { return $null }
    ('[perms] sign-in methods: {0:N0} request(s) of 20 users, up to {1} at once; Microsoft asked to slow down {2:N0} time(s)' -f [int]$State.Requests, [int]$State.MaxConcurrency, [int]$State.ThrottledWaves)
}

function Get-SIEntraAuthMethodsState {
    <# The outcome of this process's authentication-methods read ($null when it has not run). #>
    if ($script:_SICache.ContainsKey('AuthMethodsState')) { return $script:_SICache['AuthMethodsState'] }
    $null
}

function Reset-SIEntraAuthMethodsState { $script:_SICache.Remove('AuthMethodsState') }

function Get-SIEntraPasswordlessByUser {
    <#
    .SYNOPSIS
        Reads GET /users/{id}/authentication/methods for the given users through Graph $batch (20 per request) and
        returns @{ <userId> = [pscustomobject]@{ ReadComplete; PasswordlessOnly; MethodTypes } } for every user whose
        list came back whole. A user not in the map was not read: unknown.
    .NOTES
        Never throws. Accumulates into the run state (Get-SIEntraAuthMethodsState) so a discovery that streams page by
        page calls it once per page; after a refusal it reads nothing more this run.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [AllowNull()]$Users,
        # test seam: { param($Body) } -> the parsed $batch response ({ responses = [...] }); throws like Invoke-RestMethod.
        # A wave's requests go through it one after another.
        [scriptblock]$Post,
        # test seam (#874): { param([string[]]$Bodies) } -> one outcome per body, in order: @{ Response (the parsed $batch
        # response); Status (200, the HTTP status, 0 = no answer, -1 = not sent); RetryAfter (seconds or $null); Error }.
        # Default: the bodies sent AT ONCE (Invoke-SIAuthMethodBatchRequests).
        [scriptblock]$PostMany,
        # test seam: { param($Seconds) }
        [scriptblock]$Sleep,
        [int]$MaxRounds = 5,
        # (no longer used: a request that did not come back is asked again in the next round, with the others -- kept so a
        # caller that passes it still runs)
        [int]$MaxAttempts = 4,
        [int]$MaxDelaySeconds = 60
    )
    $result = @{}
    if (-not $script:_SICache.ContainsKey('AuthMethodsState') -or $null -eq $script:_SICache['AuthMethodsState']) {
        $script:_SICache['AuthMethodsState'] = [pscustomobject]@{ Requested = 0; Read = 0; Unread = 0; PasswordlessOnly = 0; Refused = $false; Throttled = $false; Complete = $true; Error = '' }
    }
    $state = $script:_SICache['AuthMethodsState']
    $list = @($Users | Where-Object { $null -ne $_ -and [string]$_.id })
    if ($list.Count -eq 0) { return $result }
    $state.Requested += $list.Count
    if ($state.Refused) { $state.Unread += $list.Count; $state.Complete = $false; return $result }

    if (-not $Sleep) { $Sleep = { param($Seconds) Start-Sleep -Seconds $Seconds } }
    # in the order the users came (a plain hashtable's key order is arbitrary): the requests follow the user list
    $byId = @{}
    $pending = New-Object System.Collections.Generic.List[string]
    foreach ($u in $list) {
        $k = ([string]$u.id).ToLowerInvariant()
        if (-not $byId.ContainsKey($k)) { $pending.Add($k) }
        $byId[$k] = $u
    }
    $refused = $false; $lastError = ''
    # #874: SEVERAL $batch REQUESTS AT ONCE, AS MANY AS MICROSOFT TAKES. Measured (ring 2, 2026-10-20/21, 143,000 users):
    # one request at a time took 5 hours of the identity collection (~2.5 s a request) and still left 15-20 % of the users
    # unread. Each wave sends -Concurrency requests together (-PostMany); a wave Microsoft answered without a 429 lets the
    # next one send one more, a throttled wave halves it (never below one) -- measured and adapted on every wave, the same
    # for every tenant size, no fixed number. A throttled wave's Retry-After is waited ONCE for the whole wave (never one
    # sleep per request) before the next wave; the throttled users are asked again in the next round, as before.
    if (-not $state.PSObject.Properties['Concurrency']) {
        $state | Add-Member -NotePropertyName Concurrency -NotePropertyValue 1
        $state | Add-Member -NotePropertyName MaxConcurrency -NotePropertyValue 1
        $state | Add-Member -NotePropertyName ThrottledWaves -NotePropertyValue 0
        $state | Add-Member -NotePropertyName Requests -NotePropertyValue 0
    }
    if (-not $PostMany) {
        if ($Post) {
            # the single-request seam (tests): the wave's requests one after another, a refusal stops the wave
            $one = $Post
            $PostMany = {
                param([string[]]$Bodies)
                $out = New-Object System.Collections.Generic.List[object]
                $stop = $false
                foreach ($b in $Bodies) {
                    if ($stop) { $out.Add([pscustomobject]@{ Response = $null; Status = -1; RetryAfter = $null; Error = 'not sent: the read was refused' }); continue }
                    try { $out.Add([pscustomobject]@{ Response = (& $one $b); Status = 200; RetryAfter = $null; Error = '' }) } catch {
                        $st = 0
                        try { $rr = $_.Exception.Response; if ($rr -and $rr.StatusCode) { $st = [int]$rr.StatusCode } } catch { }
                        if ($st -eq 0 -and $_.Exception.Message -match '\((\d{3})\)') { $st = [int]$Matches[1] }
                        $ra = $null
                        if (Get-Command -Name Get-SIRetryAfterSeconds -ErrorAction SilentlyContinue) { try { $ra = Get-SIRetryAfterSeconds -ErrorRecord $_ } catch { } }
                        $out.Add([pscustomobject]@{ Response = $null; Status = $st; RetryAfter = $ra; Error = [string]$_.Exception.Message })
                        if ($st -in 401, 403) { $stop = $true }
                    }
                }
                , $out.ToArray()
            }
        } else {
            # (no closure: called from here, it finds $Token and the function of this file where they are)
            # the function hands its outcomes back as ONE array already: never wrapped again (live 2026-10-22: `, @(...)` nested
            # it, so a wave of 2+ requests threw on its first outcome and only the first 20 users were ever read)
            $PostMany = { param([string[]]$Bodies) Invoke-SIAuthMethodBatchRequests -Token $Token -Bodies $Bodies }
        }
    }

    for ($round = 1; $round -le $MaxRounds -and $pending.Count -gt 0 -and -not $refused; $round++) {
        $retry = New-Object System.Collections.Generic.List[string]
        $wait = 0
        # the round's requests, 20 users each
        $chunks = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $pending.Count; $i += $script:SIAuthMethodBatchSize) {
            $chunks.Add(@($pending.GetRange($i, [Math]::Min($script:SIAuthMethodBatchSize, $pending.Count - $i))))
        }
        $next = 0; $paid = $false; $lastWaveThrottled = $false
        while ($next -lt $chunks.Count -and -not $refused) {
            $width = [Math]::Max(1, [Math]::Min([int]$state.Concurrency, $chunks.Count - $next))
            $wave = $chunks.GetRange($next, $width).ToArray(); $next += $width   # (never @(<list>): that is ONE item, the list)
            $bodies = foreach ($chunk in $wave) {
                $reqs = for ($j = 0; $j -lt $chunk.Count; $j++) { @{ id = [string]($j + 1); method = 'GET'; url = ('/users/{0}/authentication/methods' -f $chunk[$j]) } }
                ConvertTo-Json -InputObject @{ requests = @($reqs) } -Depth 5 -Compress
            }
            if ($width -gt [int]$state.MaxConcurrency) { $state.MaxConcurrency = $width }
            # the seam hands its outcomes back as ONE array (`, $list`): taken as it is, never wrapped in another array
            $outcomes = & $PostMany @($bodies)
            $outcomes = @($outcomes)
            $state.Requests = [int]$state.Requests + $wave.Count
            $waveThrottled = $false; $waveWait = 0
            for ($w = 0; $w -lt $wave.Count; $w++) {
            $chunk = @($wave[$w])
            $o = $null; if ($w -lt $outcomes.Count) { $o = $outcomes[$w] }
            if ($null -eq $o -or [int]$o.Status -eq -1) { foreach ($k in $chunk) { $retry.Add($k) }; continue }   # not sent
            $resp = $o.Response
            if ([int]$o.Status -ne 200 -or $null -eq $resp) {
                $status = [int]$o.Status
                if ($status -ne 200) { $lastError = ('HTTP {0} {1}' -f $status, [string]$o.Error) }
                if ($status -in 401, 403) { $refused = $true; break }
                if ($status -eq 429) { $state.Throttled = $true; $waveThrottled = $true }
                if ($status -in 429, 502, 503, 504 -or $status -eq 0) {
                    $ra = $o.RetryAfter
                    if ($null -ne $ra -and [int]$ra -gt $waveWait) { $waveWait = [int]$ra }
                }
                # the whole request did not come back: its users are asked again next round
                foreach ($k in $chunk) { $retry.Add($k) }
                continue
            }
            $answered = @{}
            foreach ($item in @($resp.responses)) {
                if ($null -eq $item) { continue }
                $n = 0; if (-not [int]::TryParse([string]$item.id, [ref]$n) -or $n -lt 1 -or $n -gt $chunk.Count) { continue }
                $key = $chunk[$n - 1]; $answered[$key] = $true
                $status = [int]$item.status
                if ($status -eq 200) {
                    $b = $item.body
                    # a paged list was not read whole -- unknown for this user (never decided from part of the list)
                    if ($b -and $b.PSObject.Properties['@odata.nextLink'] -and $b.'@odata.nextLink') { $state.Complete = $false; continue }
                    $methods = @(); if ($b -and $b.PSObject.Properties['value']) { $methods = @($b.value) }
                    $u = $byId[$key]
                    $types = @(Get-SIAuthMethodTypes -Methods $methods)
                    $verdict = Get-SIPasswordlessOnlyVerdict -Methods $types -ReadComplete $true -User $u
                    $result[[string]$u.id] = [pscustomobject]@{ ReadComplete = $true; PasswordlessOnly = $verdict; MethodTypes = $types }
                    $state.Read++
                    if ($verdict -eq $true) { $state.PasswordlessOnly++ }
                    if (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue) {
                        $part = [ordered]@{ readComplete = $true; methodTypes = $types }
                        if ($null -ne $verdict) { $part['passwordlessOnly'] = [bool]$verdict }
                        try { Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key ([string]$u.id) -Part 'authenticationMethods' -Object ([pscustomobject]$part) } catch { }
                    }
                } elseif ($status -in 401, 403) {
                    $refused = $true; $lastError = ('HTTP {0}' -f $status)
                } elseif ($status -in 429, 502, 503, 504) {
                    if ($status -eq 429) { $state.Throttled = $true; $waveThrottled = $true }
                    $ra = Get-SIAuthMethodItemRetryAfter -Item $item
                    if ($null -ne $ra -and $ra -gt $waveWait) { $waveWait = $ra }
                    $retry.Add($key)
                } else {
                    # 404 (gone since the user list was read) or anything else: not read, unknown
                    $state.Complete = $false; $lastError = ('HTTP {0}' -f $status)
                }
            }
            # an item the response did not answer is read again next round
            foreach ($k in $chunk) { if (-not $answered.ContainsKey($k)) { $retry.Add($k) } }
            }
            if ($waveWait -gt $wait) { $wait = $waveWait }
            if ($refused) { break }
            # measure -> adapt: a wave Microsoft throttled halves the next one and its Retry-After is waited ONCE before the
            # next wave of this round (the round's own end waits for the last one); a clean wave lets the next send one more
            $null = Update-SIAuthMethodConcurrency -State $state -Throttled $waveThrottled
            $lastWaveThrottled = $waveThrottled
            if ($waveThrottled -and $next -lt $chunks.Count) {
                $d = if ($waveWait -gt 0) { $waveWait } else { 1 }
                if ($d -gt $MaxDelaySeconds) { $d = $MaxDelaySeconds }
                & $Sleep $d
                $paid = $true
            }
        }
        $pending = $retry
        # the Retry-After was already waited during this round (and the waves after it took their time): the round's end does
        # not wait it again -- only when the LAST wave was throttled, or nothing was throttled (the usual short backoff)
        if ($paid -and -not $lastWaveThrottled) { continue }
        if ($pending.Count -gt 0 -and -not $refused -and $round -lt $MaxRounds) {
            $d = if ($wait -gt 0) { $wait } else { [int][Math]::Pow(2, $round - 1) }
            if ($d -gt $MaxDelaySeconds) { $d = $MaxDelaySeconds }
            & $Sleep $d
        }
    }

    $unread = $list.Count - $result.Count
    $state.Unread += $unread
    if ($unread -gt 0) { $state.Complete = $false }
    if ($refused) { $state.Refused = $true; $state.Complete = $false }
    if ($lastError -and -not $state.Error) { $state.Error = $lastError }
    return $result
}

function Write-SIEntraAuthMethodsOutcome {
    <# The run's ONE line about the read: information when complete or throttled (normal), a warning when refused. #>
    param($State = (Get-SIEntraAuthMethodsState))
    if ($null -eq $State -or [int]$State.Requested -eq 0) { return }
    $info = { param($m) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $m } else { Write-Host $m } }
    # #874: the pace first (measured: the next run's sizing evidence), then the one outcome line
    $pace = Get-SIAuthMethodsPaceLine -State $State
    if ($pace) { & $info $pace }
    if ([bool]$State.Complete) {
        & $info ('[perms] sign-in methods read for {0:N0} users; {1:N0} sign in passwordless only' -f [int]$State.Read, [int]$State.PasswordlessOnly)
        return
    }
    $line = Get-SIAuthMethodsMissingLine -State $State
    # one plain information line, refused or not: the missing permission is shown in Get Started and the permission check;
    # a warning on every run until admin consent would be noise (owner: throttling and known gaps never alarm)
    & $info $line
}
