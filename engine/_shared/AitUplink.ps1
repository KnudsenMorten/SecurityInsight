#Requires -Version 5.1
<#
.SYNOPSIS
    §8 -- the uplink client. Turns a sync outcome into a record, and decides when to retry.

.DESCRIPTION
    **This is the gate.** RING-1: "the uplink must exist before the FIRST real customer is
    assigned." Until it does, "nothing happened" and "nothing needed to happen" are
    indistinguishable, which is why no real customer is on a ring today.

    🔒 THE API IS THE ONLY TRANSPORT (operator, 2026-09-08: "drop email"). Each customer sends
    its state up; nothing is ever sent down. §8 had named email a secondary channel and that is
    now dropped rather than left half-built -- a transport nobody maintains is a transport
    nobody trusts, and two half-wired paths would make "did it report?" ambiguous.

    🔒 AND EMAIL COULD NEVER HAVE BEEN THE MECHANISM ANYWAY. A customer whose sync never ran
    sends no mail, so absence of failure mail is indistinguishable from health -- the same
    defect as `[sync] done` printed after doing nothing, `built=True deployed=False`, and
    RING-8's green board. Only a stored record carrying a LAST-SEEN timestamp makes silence
    visible, and that lives in the API's store (uplink.vSilentTargets).

    🔒 WHY NOT A STORAGE ACCOUNT (operator decision, 2026-08-08). Granting ~30 customer SPNs
    write access to a storage account is an inbound data-plane grant from every customer into
    the operator tenant; one compromised customer would own the whole fleet store. The chosen
    transport is an Entra-authenticated, append-only API that fronts SQL and exposes no reads.

    🔒 IDENTITY COMES FROM THE TOKEN, NEVER THE BODY. New-AitUplinkRecord stamps TenantId for
    the LOCAL record and the email path only. The server must establish the writer from the
    access token and ignore the field entirely -- otherwise any authenticated customer could
    write another customer's row by editing one JSON value. The field is named
    ClaimedTenantId to make that impossible to forget at the API end.

    🔒 INERT BY CONSTRUCTION. With no endpoint configured, Send-AitUplink returns 'disabled'
    and performs no network call. sync/ auto-deploys from main to ~30 customers with no review
    step, so this ships doing nothing until an operator configures a target.
#>

Set-StrictMode -Off

<#
.SYNOPSIS
    PURE. Build the §8 uplink record from a sync plan. No disk, no network, no clock of its own.

.DESCRIPTION
    §8 fixes the payload: Action, Ring, Version, Run/Held/Blocked/Refused, a last-seen
    timestamp, and the FULL error message (open item 4 -- "yes, the full error message"),
    which is what makes the uplink actionable rather than merely a status board.

    🔑 IT MUST REPORT CAPABILITIES, NOT JUST VERSIONS. Otherwise "held by policy" and "failed
    to apply" are identical, which is precisely the ambiguity ring gating introduces. That is
    also why Held / Blocked / Refused travel separately rather than collapsed into one list:
    a stalled rollout and a healthy customer opt-out must never look the same.

.PARAMETER Plan
    A Get-AitSyncPlan result. Its shape is the contract: Solution, Action, Ring, Version,
    Capabilities{Run,Held,Blocked,Refused}, Reason.

.PARAMETER ErrorText
    The FULL error, verbatim. Truncating it here would recreate the problem the uplink exists
    to solve -- a status without a cause.
#>
function New-AitUplinkRecord {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$Plan,
        [Parameter()][AllowNull()][string]$TenantId,
        [Parameter()][AllowNull()][string]$Solution,
        [Parameter()][AllowNull()][string]$DeployedVersion,
        [Parameter()][AllowNull()][string]$ErrorText,
        [Parameter()][AllowNull()][object]$Now,
        # 🪤 NOT $Host. That is a read-only automatic variable: a parameter named $Host PARSES
        # CLEAN on 5.1 and 7, then fails at BIND time with "Cannot overwrite variable Host",
        # and every field of the record comes back empty. Found by running it, 2026-09-08 --
        # a parse check would have shipped it.
        [Parameter()][AllowNull()][string]$HostName
    )

    $ts = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { (Get-Date).ToUniversalTime() }
    $caps = if ($Plan) { $Plan.Capabilities } else { $null }

    # 🪤 PLAIN ASSIGNMENTS, NOT AN INLINE `(if ...)` IN ARGUMENT POSITION. `& $f (if ($x) {…})`
    # PARSES CLEAN and then fails at runtime with "The term 'if' is not recognized as a name of
    # a cmdlet" -- because in argument position `if` is read as a COMMAND, not an expression.
    # Every field silently came back empty. This is RING-7's landmine 2 in a new costume, and
    # its own lesson is exactly this: prefer plain assignments before the call.
    # (`Key = if (...) {...}` inside the hashtable below IS valid -- that is assignment
    # position, not argument position. The distinction is the whole trap.)
    $runCaps = @(); $heldCaps = @(); $blockedCaps = @(); $refusedCaps = @()
    if ($caps) {
        if ($caps.Run)     { $runCaps     = @($caps.Run     | Where-Object { $_ }) }
        if ($caps.Held)    { $heldCaps    = @($caps.Held    | Where-Object { $_ }) }
        if ($caps.Blocked) { $blockedCaps = @($caps.Blocked | Where-Object { $_ }) }
        if ($caps.Refused) { $refusedCaps = @($caps.Refused | Where-Object { $_ }) }
    }

    return [pscustomobject]@{
        Schema          = 1
        # Named ClaimedTenantId on purpose: the API MUST take identity from the token and
        # ignore this. See the header. Kept because the local record and the email path have
        # no token to read.
        ClaimedTenantId = "$TenantId"
        Solution        = if ($Solution) { "$Solution" } elseif ($Plan) { "$($Plan.Solution)" } else { '' }
        Action          = if ($Plan) { "$($Plan.Action)" } else { 'unknown' }
        Ring            = if ($Plan -and $null -ne $Plan.Ring) { [int]$Plan.Ring } else { $null }
        Version         = if ($Plan) { "$($Plan.Version)" } else { '' }
        DeployedVersion = "$DeployedVersion"
        Run             = $runCaps
        Held            = $heldCaps
        Blocked         = $blockedCaps
        Refused         = $refusedCaps
        Reason          = if ($Plan) { "$($Plan.Reason)" } else { '' }
        ErrorText       = "$ErrorText"
        Ok              = (-not "$ErrorText".Trim())
        Host            = if ("$HostName".Trim()) { "$HostName" } else { "$env:COMPUTERNAME" }
        LastSeenUtc     = $ts.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
}

<#
.SYNOPSIS
    PURE. Should this target retry, and should somebody be told?

.DESCRIPTION
    §8: "Retry policy is part of observability." _SyncDeploy.ps1 already does not advance its
    marker on a failed deploy, so the next cycle retries -- a good pattern. What is MISSING is
    a ceiling and backoff: without them a permanently broken deploy retries nightly forever
    and nobody is told, which is the same silence failure wearing different clothes.

    🔑 EXHAUSTING THE CEILING IS AN ALERTABLE EVENT, not a quiet stop. A retry loop that gives
    up silently is strictly worse than one that never stops, because it also stops producing
    the failures somebody might have noticed.

.OUTPUTS
    Retry   -- try again on the next cycle
    Backoff -- skip this cycle; DelayCycles says how many to wait
    Alert   -- ceiling exhausted. Stop retrying AND tell a human.
#>
function Get-AitUplinkRetryDecision {
    [CmdletBinding()]
    param(
        [Parameter()][int]$ConsecutiveFailures = 0,
        [Parameter()][int]$Ceiling = 5
    )

    if ($ConsecutiveFailures -le 0) {
        return [pscustomobject]@{ Action = 'Retry'; DelayCycles = 0; Alert = $false; Reason = 'no failures recorded' }
    }
    if ($ConsecutiveFailures -ge $Ceiling) {
        return [pscustomobject]@{
            Action = 'Alert'; DelayCycles = 0; Alert = $true
            Reason = "retry ceiling reached ($ConsecutiveFailures of $Ceiling consecutive failures) -- stopping automatic retries and raising this, because a loop that gives up QUIETLY also stops producing the failures somebody might notice"
        }
    }
    # Exponential: 1,2,4,8... cycles. CAPPED, because [Math]::Pow(2, 98) overflows the [int]
    # cast and throws -- turning a retry-policy helper into the thing that breaks the sync.
    # Unreachable while the ceiling check above stands; capped anyway, because a guard that
    # only holds while a DIFFERENT guard holds is not a guard.
    $exp = [Math]::Min([double]($ConsecutiveFailures - 1), 16.0)
    $delay = [Math]::Pow(2, $exp)
    return [pscustomobject]@{
        Action = 'Backoff'; DelayCycles = [int]$delay; Alert = $false
        Reason = "failure $ConsecutiveFailures of $Ceiling -- backing off $([int]$delay) cycle(s) before the next attempt"
    }
}

<#
.SYNOPSIS
    Send a record to the uplink API. INERT unless an endpoint is configured.

.DESCRIPTION
    🔒 NO ENDPOINT => NO NETWORK CALL, and the result says 'disabled' rather than 'ok'. This
    file ships to ~30 customers from main with no review step, so the resting state must be
    provably nothing, and a disabled uplink must never be mistaken for a healthy one.

    🔒 A FAILED UPLINK MUST NEVER FAIL THE SYNC. Observability that can break the thing it
    observes is worse than none: a customer would stop updating because telemetry was down.
    Every transport failure returns a result and is reported by the caller; nothing throws.

.PARAMETER Endpoint
    HTTPS URL of the append-only API. Absent => disabled.

.PARAMETER AccessToken
    Entra token for the SPN the customer already holds. The server derives identity from the
    token and ignores the body's ClaimedTenantId.

.PARAMETER AccessCode
    Shared access code (operator decision, 2026-09-08). Chosen over per-tenant Entra consent
    because this is telemetry: append-only, no read surface, nothing to steal or escalate, and
    ~30 admin consents is real cost against a threat that does not exist here.

    🔑 THE CONSEQUENCE, AND IT IS UNAVOIDABLE RATHER THAN AN OVERSIGHT: a shared code proves
    that SOME customer is calling, never WHICH. So with a code the tenant necessarily comes
    from the BODY, and the server records `WriterSource = 'shared-code'` on the row to say so.
    Rows are then honest about their own provenance instead of implying a proof that was not
    performed -- and if per-customer credentials arrive later, the old rows still say what they
    were.

    🪤 The realistic failure this leaves open is NOT forgery, it is a CLONED CONFIG: a VM imaged
    from another customer's reports as that customer, and with one shared code every caller
    looks identical. `HostName` is on every record precisely so two hosts under one identity are
    still visible.

    Exactly one of -AccessToken / -AccessCode is used; the token wins if both are supplied,
    because a proven identity should never be silently downgraded to an asserted one.
#>
function Send-AitUplink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Record,
        [Parameter()][AllowNull()][string]$Endpoint,
        [Parameter()][AllowNull()][string]$AccessToken,
        [Parameter()][AllowNull()][string]$AccessCode,
        [Parameter()][int]$TimeoutSec = 20
    )

    if (-not "$Endpoint".Trim()) {
        return [pscustomobject]@{ Status = 'disabled'; Reason = 'no uplink endpoint configured -- nothing was sent (this is the shipped resting state)'; Sent = $false }
    }
    if ("$Endpoint" -notmatch '^https://') {
        # Still refused with a shared code -- arguably MORE so. A bearer code in a plaintext
        # request is readable by anything on the path, and unlike a token it does not expire.
        return [pscustomobject]@{ Status = 'refused'; Reason = "uplink endpoint must be https -- refusing to post run data over '$Endpoint'"; Sent = $false }
    }
    if (-not "$AccessToken".Trim() -and -not "$AccessCode".Trim()) {
        return [pscustomobject]@{ Status = 'refused'; Reason = 'no access token and no access code -- there is deliberately no anonymous path'; Sent = $false }
    }

    try {
        $body = $Record | ConvertTo-Json -Depth 6 -Compress
        # Token WINS when both are present: a proven identity must never be silently downgraded
        # to an asserted one just because a code happens to be configured alongside it.
        $headers = if ("$AccessToken".Trim()) { @{ Authorization = "Bearer $AccessToken"; 'Content-Type' = 'application/json' } }
                   else                       { @{ 'X-Ait-Uplink-Code' = $AccessCode;     'Content-Type' = 'application/json' } }
        $null = Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $headers -Body $body -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
        return [pscustomobject]@{ Status = 'ok'; Reason = 'uplink accepted'; Sent = $true }
    } catch {
        # Never rethrow: see the header. The sync must survive a broken uplink.
        return [pscustomobject]@{ Status = 'failed'; Reason = "uplink POST failed: $($_.Exception.Message)"; Sent = $false }
    }
}

# =====================================================================================================
# SCHEMA 2 -- product heartbeat + run reports (Invardia-hosted uplink, owner decisions 2026-10-03;
# Invardia docs/design/TELEMETRY-UPLINK.md section 7, framework DOCS/REQUIREMENTS.md section 8.4).
#
# ADDITIVE ONLY. The sync engine does not call anything below; a PRODUCT (PIM, SI) calls it from its own
# jobs behind its own switch. Nothing here reads config, touches disk or the network except
# Send-AitUplink, which is unchanged and still refuses without an https endpoint + a credential.
#
# Two senders, one endpoint (POST https://invardia.com/api/uplink/v1/report, header X-Ait-Uplink-Code):
#   anonymous   -- the PUBLIC community code; the record carries NO ClaimedTenantId, NO Host, NO ErrorText,
#                  only an ErrorClass and BUCKETED counts, plus a random InstallId the product keeps.
#                  Data that is never sent cannot leak: the server drops these fields too, but we do not
#                  rely on that.
#   identified  -- a per-install key Invardia issued (Pro / trial). The KEY proves the environment; the
#                  body's ClaimedTenantId is only compared for mismatch. ErrorText is shortened + redacted
#                  here as well as on the server.
# The server refuses unknown fields and checks closed value lists, so the lists below mirror Invardia's
# packages/core/src/uplink.ts exactly; a value outside them is dropped here rather than failing the POST.
# =====================================================================================================

$script:AitUplinkCommunityCode   = 'invardia-community-telemetry-v1'   # public by design: "a Community install", nothing more
$script:AitUplinkInvardiaEndpoint = 'https://invardia.com/api/uplink/v1/report'
$script:AitUplinkKinds     = @('heartbeat', 'run', 'install')
$script:AitUplinkOutcomes  = @('ok', 'warning', 'failed')
$script:AitUplinkEditions  = @('community', 'pro', 'trial')
$script:AitUplinkHosting   = @('container', 'vm', 'arc')
$script:AitUplinkRuntime   = @('mi-container', 'mi-vm', 'mi-arc', 'spn-certificate', 'spn-secret')
$script:AitUplinkLicence   = @('valid', 'grace', 'expired', 'none')

function ConvertTo-AitUplinkRedacted {
    <# PURE. Removes secrets from free text before it can leave the install (same rules as Invardia's redact()). #>
    [CmdletBinding()]
    param([AllowNull()][string]$Text)
    $t = "$Text"
    if (-not $t) { return '' }
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*', '[jwt]')
    $t = [regex]::Replace($t, '(?i)\b(Bearer)\s+[A-Za-z0-9._~+/=-]{10,}', '$1 [redacted]')
    $t = [regex]::Replace($t, '(?i)\b(client_secret|password|pwd|secret|apikey|api_key|accountkey|sharedaccesskey)\s*[=:]\s*("[^"]*"|''[^'']*''|[^\s;&,]+)', '$1=[redacted]')
    $t = [regex]::Replace($t, '(?i)([?&](sig|se|sv|sp|skoid|sktid)=)[^&\s]+', '$1[redacted]')
    $t = [regex]::Replace($t, '-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----', '[pem]')
    # An X-Ait-Uplink-Code / install key that ends up in an error message (e.g. a proxy echoing headers).
    $t = [regex]::Replace($t, 'inv-[A-Za-z0-9_-]{20,}', '[install-key]')
    return $t
}

function Get-AitUplinkCountBucket {
    <# PURE. Anonymous mode never sends an exact count: 0, 1-100, 100-1k, 1k-10k, 10k-100k, 100k+. #>
    param([double]$Count)
    if ($Count -le 0) { return '0' }
    if ($Count -le 100) { return '1-100' }
    if ($Count -le 1000) { return '100-1k' }
    if ($Count -le 10000) { return '1k-10k' }
    if ($Count -le 100000) { return '10k-100k' }
    return '100k+'
}

function New-AitUplinkReport {
    <#
    .SYNOPSIS
        PURE. Build a Schema 2 record (Kind heartbeat | run | install) for -Mode anonymous | identified.
    .DESCRIPTION
        Only fields with a value are emitted (the server refuses unknown fields and checks enums; an empty
        string where an enum is expected would be refused). An enum value outside the closed list is
        DROPPED, never sent. Job / FailedStep are normalised to the server's id shape (lower-case,
        [a-z0-9.-], 60 chars). ErrorClass is lower-cased (PIM's failure codes are upper-case).
        Anonymous: ClaimedTenantId, Host and ErrorText are never put in the record, counts are bucketed,
        and an InstallId (GUID) is REQUIRED -- without one the result is $null and nothing should be sent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('heartbeat', 'run', 'install')][string]$Kind,
        [Parameter(Mandatory)][ValidateSet('anonymous', 'identified')][string]$Mode,
        [Parameter(Mandatory)][string]$Product,
        [AllowNull()][string]$Version,
        [AllowNull()][object]$Ring,
        [AllowNull()][string]$Edition,
        [AllowNull()][string]$Hosting,
        [AllowNull()][string]$RuntimeIdentity,
        [AllowNull()][string]$LicenceState,
        [AllowNull()][string]$Job,
        [AllowNull()][string]$Outcome,
        [AllowNull()][object]$DurationMs,
        [AllowNull()][string]$FailedStep,
        [AllowNull()][string]$ErrorClass,
        [AllowNull()][string]$ErrorText,
        [AllowNull()][hashtable]$Counts,
        [AllowNull()][string]$InstallId,
        [AllowNull()][string]$TenantId,
        [AllowNull()][string]$HostName,
        [AllowNull()][object]$Now
    )
    $anon = ($Mode -eq 'anonymous')
    $iid = "$InstallId".Trim().ToLowerInvariant()
    if ($anon -and $iid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { return $null }
    $ts = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { (Get-Date).ToUniversalTime() }
    $idOf = { param($v) $s = ("$v".Trim().ToLowerInvariant() -replace '[^a-z0-9.-]', '-') -replace '^[^a-z0-9]+', ''; if ($s.Length -gt 60) { $s = $s.Substring(0, 60) }; $s }
    $o = [ordered]@{ Schema = 2; Kind = $Kind; Product = "$Product".Trim().ToLowerInvariant() }
    $ver = "$Version".Trim(); if ($ver -match '^[0-9A-Za-z.+-]{1,50}$') { $o['Version'] = $ver }
    $rp = 0; if ($null -ne $Ring -and "$Ring" -ne '' -and [int]::TryParse("$Ring", [ref]$rp) -and $rp -ge 0 -and $rp -le 10) { $o['Ring'] = $rp }
    foreach ($pair in @(@('Edition', $Edition, $script:AitUplinkEditions), @('Hosting', $Hosting, $script:AitUplinkHosting),
                        @('RuntimeIdentity', $RuntimeIdentity, $script:AitUplinkRuntime), @('LicenceState', $LicenceState, $script:AitUplinkLicence),
                        @('Outcome', $Outcome, $script:AitUplinkOutcomes))) {
        $v = "$($pair[1])".Trim().ToLowerInvariant()
        if ($v -and ($pair[2] -contains $v)) { $o[$pair[0]] = $v }
    }
    $j = & $idOf $Job; if ($j) { $o['Job'] = $j }
    $fs = & $idOf $FailedStep; if ($fs) { $o['FailedStep'] = $fs }
    $ec = ("$ErrorClass".Trim().ToLowerInvariant() -replace '[^a-z0-9-]', '-'); if ($ec.Length -gt 40) { $ec = $ec.Substring(0, 40) }; if ($ec) { $o['ErrorClass'] = $ec }
    $d = [int64]0; if ($null -ne $DurationMs -and [int64]::TryParse("$DurationMs", [ref]$d) -and $d -ge 0) { $o['DurationMs'] = [int][Math]::Min($d, [int64]2147483646) }
    if ($Counts -and $Counts.Count) {
        $c = [ordered]@{}
        foreach ($k in @($Counts.Keys | Sort-Object | Select-Object -First 40)) {   # 40 keys: agreed by SI + PIM + Invardia, owner yes 2026-10-13 (Invardia accepts 40 since 1.0.413)
            if ("$k" -notmatch '^[a-z][A-Za-z0-9]{0,30}$') { continue }
            $n = 0.0; if (-not [double]::TryParse("$($Counts[$k])", [ref]$n) -or $n -lt 0) { continue }
            $c["$k"] = if ($anon) { Get-AitUplinkCountBucket -Count $n } else { [int64][Math]::Floor($n) }
        }
        if ($c.Count) { $o['Counts'] = [pscustomobject]$c }
    }
    if ($anon) {
        $o['InstallId'] = $iid
    } else {
        if ("$TenantId".Trim()) { $o['ClaimedTenantId'] = "$TenantId".Trim() }
        $h = if ("$HostName".Trim()) { "$HostName".Trim() } else { "$env:COMPUTERNAME" }
        if ($h) { $o['Host'] = $(if ($h.Length -gt 100) { $h.Substring(0, 100) } else { $h }) }
        $et = ConvertTo-AitUplinkRedacted -Text "$ErrorText".Trim()
        if ($et) { $o['ErrorText'] = $(if ($et.Length -gt 8000) { $et.Substring(0, 8000) } else { $et }) }
    }
    $o['LastSeenUtc'] = $ts.ToString('yyyy-MM-ddTHH:mm:ssZ')
    return [pscustomobject]$o
}

function Resolve-AitUplinkSender {
    <#
    .SYNOPSIS
        PURE. Which credential + mode this install sends with, or 'disabled'.
    .DESCRIPTION
        -Enabled $false (the product's opt-out)  -> disabled; nothing is sent.
        an install key (Pro / trial, issued by Invardia) -> identified, the key in X-Ait-Uplink-Code.
        no key                                    -> anonymous with the public community code -- also for a Pro
                                                     install that has no key yet: it then reports like a
                                                     Community install (no tenant, no host, no text) rather
                                                     than inventing an identity it cannot prove.
        -Endpoint overrides Invardia's (a private estate); it must still be https (Send-AitUplink refuses
        anything else).
    #>
    param([bool]$Enabled, [AllowNull()][string]$InstallKey, [AllowNull()][string]$Endpoint)
    if (-not $Enabled) { return [pscustomobject]@{ Mode = 'disabled'; Endpoint = ''; AccessCode = ''; Reason = 'telemetry is switched off' } }
    $ep = if ("$Endpoint".Trim()) { "$Endpoint".Trim() } else { $script:AitUplinkInvardiaEndpoint }
    $key = "$InstallKey".Trim()
    if ($key) { return [pscustomobject]@{ Mode = 'identified'; Endpoint = $ep; AccessCode = $key; Reason = 'install key' } }
    return [pscustomobject]@{ Mode = 'anonymous'; Endpoint = $ep; AccessCode = $script:AitUplinkCommunityCode; Reason = 'no install key -- anonymous (community code)' }
}
