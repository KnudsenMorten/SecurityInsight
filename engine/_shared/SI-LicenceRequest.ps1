#Requires -Version 5.1
<#
    SecurityInsight -- THE INSTALL REQUESTS AND RENEWS ITS OWN LICENCE (#239).

    The contract is Invardia's (licence requests, owner GO 2026-10-03). Three steps, run by the updater job on each
    update run (container/updater/_shared/SI-UpdaterLicence.ps1) and by setup/Request-SILicense.ps1 by hand:

      1. KNOCK  -- when there is no valid licence for THIS tenant, or the one installed ends within 30 days:
                   POST <base>/api/licence-requests  {product, version, tenantId, installId, edition?, contactEmail?,
                   currentLicenceId?, currentValidTo?}  ->  202 {requestId, pullToken, status, pollAfterSeconds}.
                   The pull token is kept in the install's Key Vault (SI-LicenceRequest-PullToken), never printed.
                   A repeat knock returns the same request with a NEW token, which overwrites the stored one.
      2. PULL   -- each run, never faster than pollAfterSeconds: POST <base>/api/licence-requests/pull with the header
                   X-Invardia-Pull-Token and the JSON body {} -> {status: Pending | Rejected | Approved, licence?}.
                   401 = the token is unknown or expired -> knock again. A token older than 30 days is not used.
      3. VERIFY offline, then INSTALL -- the SHA-256 of the file, the signature against the trusted signers (the
                   framework verifier, engine/_shared/AitLicense.ps1), the REAL tenant among its tenantIds, valid dates,
                   product securityinsight and features SecurityInsight has. Only then setup/Set-SILicense.ps1 writes
                   SI-License (it verifies again and reads it back), and the cycle reads it back once more.

    🔒 THE TENANT IS THE TOKEN'S, NEVER THE CONFIG'S. The tenant sent and checked is the 'tid' of the identity's own
    access token (a managed identity: $global:SI_IdentityTokenTenantId, recorded by the managed identity token helper in auth/; an SPN:
    the tid of its token). A tenant that cannot be proven is not guessed: nothing is sent.

    Answers that are not a licence: Rejected is stored with its reason and shown to the admin; it is NOT asked again
    automatically for 7 days (Request-SILicense.ps1 -Force asks at once). 422 = Invardia refused the request body: the
    fields are reported and the request is not repeated for a day. 429 = wait at least Retry-After. A network failure is
    a warning; it never fails the run that called this.

    The state (no token) is kept as the Key Vault secret SI-LicenceRequest-State and, on a Pro install, mirrored into the
    Pro database (cfg.InstallState 'LicenceRequest') for the web app. The install id is SI-InstallId, created once.

    Every call that leaves the process goes through -Seams, so the contract test runs offline. PS 5.1 safe.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-AzRest.ps1') }
# #517: the re-issued licence marker the engine records (Read-SILicenceSupersededMark -- the updater's SupersededBy seam)
if (-not (Get-Command -Name Read-SILicenceSupersededMark -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-LicenceSuperseded.ps1') }

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

$script:SILicenceRequestProduct      = 'securityinsight'
$script:SILicenceRequestDefaultBase  = 'https://invardia.com'
$script:SILicenceRequestSecretState  = 'SI-LicenceRequest-State'
$script:SILicenceRequestSecretToken  = 'SI-LicenceRequest-PullToken'
$script:SILicenceRequestSecretId     = 'SI-InstallId'
$script:SILicenceRequestSecretLic    = 'SI-License'
$script:SILicenceRequestTokenHeader  = 'X-Invardia-Pull-Token'
$script:SILicenceRequestRenewDays    = 30      # knock when the licence ends within this many days
$script:SILicenceRequestRejectDays   = 7       # after a rejection, ask again only after this many days (or -Force)
$script:SILicenceRequestTokenDays    = 30      # a pull token lives this long
$script:SILicenceRequestPollSeconds  = 1800    # when Invardia sends no pollAfterSeconds (it sends 1800)
$script:SILicenceRequestInvalidHours = 24      # after a 422, the request is not repeated for this long
$script:SILicenceRequestStates       = @('none', 'requested', 'pending', 'approved', 'rejected')

# The licence verifier and the feature catalog (Get-SILicense, Test-SILicenseForInstall, Resolve-AitLicenseStatus).
if (-not (Get-Command -Name Test-SILicenseForInstall -ErrorAction SilentlyContinue)) {
    $siLrCatalog = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'SI-FeatureCatalog.ps1')
    if (Test-Path -LiteralPath $siLrCatalog) { . $siLrCatalog }
}

# =====================================================================================================================
#  Pure helpers
# =====================================================================================================================
function Get-SILicenceRequestBaseUrl {
    <#
        Where Invardia is: -BaseUrl, else $global:SI_LicenseRequest_BaseUrl, else $env:SI_LICENSE_REQUEST_BASE_URL, else
        https://invardia.com. HTTPS only (the pull token travels in a header). No trailing slash.
    #>
    param([string]$BaseUrl)
    $u = @($BaseUrl, [string]$global:SI_LicenseRequest_BaseUrl, [string]$env:SI_LICENSE_REQUEST_BASE_URL) | Where-Object { "$_".Trim() } | Select-Object -First 1
    if (-not $u) { $u = $script:SILicenceRequestDefaultBase }
    $u = "$u".Trim().TrimEnd('/')
    if ($u -notmatch '^https://[^/\s]+') { throw ("the licence request address must be an https:// URL, not '{0}'" -f $u) }
    $u
}

function Get-SILicenceRequestTenantFromToken {
    <# The 'tid' claim of an access token (JWT), lower-case; $null when it has none or is not a token. Never prints it. #>
    param([AllowNull()][string]$AccessToken)
    if ([string]::IsNullOrWhiteSpace($AccessToken)) { return $null }
    try {
        $seg = $AccessToken.Split('.')
        if ($seg.Count -lt 2) { return $null }
        $p = $seg[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
        $tid = [string](([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))) | ConvertFrom-Json).tid
        if ($tid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $tid.ToLowerInvariant() }
    } catch { }
    return $null
}

function Test-SILicenceRequestTenantProven {
    param([AllowNull()][string]$TenantId)
    return ("$TenantId" -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
}

function Test-SILicenceRequestNeeded {
    <#
        PURE. Should the install ask for a licence? Yes when it has no valid licence FOR THIS TENANT, or the licence ends
        within 30 days: (validTo as a UTC date) - (today, UTC) <= 30. Returns @{ Needed; Reason; ValidTo; LicenceId; DaysLeft }.
    #>
    param([AllowNull()][object]$License, [AllowNull()][string]$TenantId, [Parameter(Mandatory)][datetime]$NowUtc,
          # #517 (framework §12.6b): the newest licence Invardia named when it answered that the installed one was re-issued --
          # a GUID other than the installed licence's id makes the install ask now (Superseded = $true)
          [AllowNull()][AllowEmptyString()][string]$SupersededBy)
    $sup = "$SupersededBy".Trim().ToLowerInvariant()
    if ($sup -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { $sup = '' }
    $out = { param($n, $why, $to, $id, $d, $s) [pscustomobject]@{ Needed = [bool]$n; Reason = $why; ValidTo = $to; LicenceId = $id; DaysLeft = $d; Superseded = [bool]$s } }
    if ($null -eq $License) { return (& $out $true 'there is no licence' $null '' $null) }
    $st = "$($License.Status)"
    $id = "$($License.LicenseId)"
    $to = $null
    if ($License.ValidTo) { try { $to = ([datetime]$License.ValidTo).Date } catch { $to = $null } }
    if ($st -in @('Missing', 'Invalid', 'Expired')) { return (& $out $true ("there is no valid licence ({0})" -f $st) $to $id $null) }
    $ids = @($License.TenantIds | Where-Object { $_ } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if (-not $ids.Count -or $ids -notcontains "$TenantId".Trim().ToLowerInvariant()) {
        return (& $out $true 'the licence installed is not for this tenant' $to $id $null)
    }
    if ($null -eq $to) { return (& $out $true 'the licence has no end date' $null $id $null) }
    $days = [int]($to - $NowUtc.ToUniversalTime().Date).TotalDays
    if ($sup -and $sup -ne "$id".Trim().ToLowerInvariant()) {
        return (& $out $true ("Invardia has issued a newer licence for this install ({0})" -f $sup) $to $id $days $true)
    }
    if ($st -eq 'Grace') { return (& $out $true ("the licence ended {0} and is in its grace period" -f $to.ToString('yyyy-MM-dd')) $to $id $days) }
    if ($days -le $script:SILicenceRequestRenewDays) {
        return (& $out $true $(if ($days -lt 0) { "the licence ended {0}" -f $to.ToString('yyyy-MM-dd') } else { "the licence ends in {0} day(s)" -f $days }) $to $id $days)
    }
    & $out $false ("the licence is valid until {0}" -f $to.ToString('yyyy-MM-dd')) $to $id $days
}

function New-SILicenceRequestBody {
    <#
        PURE. The knock's JSON body. Field names are the contract's, in its order; an optional field is sent only when it
        has a value (contactEmail only when configured, the current licence only when there is one).
    #>
    param(
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$InstallId,
        [string]$Edition,
        [string]$ContactEmail,
        [string]$CurrentLicenceId,
        [AllowNull()][object]$CurrentValidTo,
        # the SHA-256 of the licence the install holds (Invardia delivers a renewal only to a knock that proves it holds the
        # tenant's licence: its id, this hash, or a valid install key in the header). 64 hex characters, else not sent.
        [string]$CurrentLicenceSha256
    )
    $b = [ordered]@{ product = $script:SILicenceRequestProduct; version = $Version; tenantId = $TenantId.ToLowerInvariant(); installId = $InstallId }
    if ("$Edition".Trim())          { $b.edition = "$Edition".Trim() }
    if ("$ContactEmail".Trim())     { $b.contactEmail = "$ContactEmail".Trim() }
    if ("$CurrentLicenceId".Trim()) { $b.currentLicenceId = "$CurrentLicenceId".Trim() }
    if ("$CurrentLicenceSha256".Trim() -match '^[0-9a-fA-F]{64}$') { $b.currentLicenceSha256 = "$CurrentLicenceSha256".Trim().ToLowerInvariant() }
    if ($null -ne $CurrentValidTo -and "$CurrentValidTo".Trim()) {
        $b.currentValidTo = ([datetime]$CurrentValidTo).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    $b | ConvertTo-Json -Compress
}

function Get-SILicenceRequestSha256 {
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { return (($h.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $h.Dispose() }
}

function Test-SILicenceRequestFile {
    <#
        OFFLINE verification of the licence Invardia handed back, BEFORE anything is installed:
          * the SHA-256 of the decoded bytes equals 'sha256';
          * the signature verifies against the trusted signers (the framework verifier);
          * the dates make it valid today;
          * the REAL tenant is one of its tenantIds;
          * the product is securityinsight;
          * every feature it grants is one SecurityInsight has.
        Returns @{ Ok; Problems; License; Text }. Never throws.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Licence,
        [AllowNull()][string]$TenantId,
        [AllowNull()][string[]]$TrustedCertsB64,
        [AllowNull()][object]$Now
    )
    $problems = New-Object System.Collections.Generic.List[string]
    $res = { param($lic, $text) [pscustomobject]@{ Ok = ($problems.Count -eq 0); Problems = $problems.ToArray(); License = $lic; Text = $text } }
    if (-not (Test-SILicenceRequestTenantProven $TenantId)) { $problems.Add('the tenant this install runs in is not proven') ; return (& $res $null $null) }
    if ($null -eq $Licence -or -not "$($Licence.contentBase64)".Trim()) { $problems.Add('the answer carries no licence file'); return (& $res $null $null) }
    $bytes = $null
    try { $bytes = [Convert]::FromBase64String("$($Licence.contentBase64)".Trim()) } catch { $problems.Add('the licence file is not base64'); return (& $res $null $null) }
    $sha = Get-SILicenceRequestSha256 -Bytes $bytes
    if ($sha -ne "$($Licence.sha256)".Trim().ToLowerInvariant()) {
        $problems.Add(("the licence file does not match its SHA-256 (file {0}, stated {1})" -f $sha.Substring(0, 12), $(if ("$($Licence.sha256)".Length -ge 12) { "$($Licence.sha256)".Substring(0, 12) } else { "'$($Licence.sha256)'" })))
        return (& $res $null $null)
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF).Trim()
    $doc = $null
    try { $doc = $text | ConvertFrom-Json -ErrorAction Stop } catch { $doc = $null }
    if ($null -eq $doc) { $problems.Add('the licence file is not licence JSON'); return (& $res $null $text) }
    if (-not (Get-Command -Name Resolve-AitLicenseStatus -ErrorAction SilentlyContinue)) { $problems.Add('the licence verifier is not installed'); return (& $res $null $text) }
    $lic = Resolve-AitLicenseStatus -Document $doc -TrustedCertsB64 $TrustedCertsB64 -Now $Now
    if ("$($lic.Status)" -eq 'Invalid') { $problems.Add(("the licence does not verify: {0}" -f $lic.Reason)); return (& $res $lic $text) }
    if ("$($lic.Status)" -ne 'Valid')   { $problems.Add(("the licence dates are not valid today: {0} ({1})" -f $lic.Status, $lic.Reason)) }
    $ids = @($lic.TenantIds | Where-Object { $_ } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    if ($ids -notcontains $TenantId.ToLowerInvariant()) {
        $problems.Add(("the licence is for tenant(s) {0}, not for this tenant {1}" -f $(if ($ids.Count) { $ids -join ', ' } else { 'none' }), $TenantId))
    }
    # The product: the signed payload's when it says one, else the file's own field. Never absent.
    $prod = ''
    try { $p = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($doc.payloadB64)")) | ConvertFrom-Json; if ($p.PSObject.Properties['product']) { $prod = "$($p.product)" } } catch { }
    if (-not $prod -and $doc.PSObject.Properties['product']) { $prod = "$($doc.product)" }
    if (($prod -replace '[^A-Za-z]', '').ToLowerInvariant() -ne $script:SILicenceRequestProduct) {
        $problems.Add(("the licence is for product '{0}', not SecurityInsight" -f $prod))
    }
    if (Get-Command -Name Test-SILicenseForInstall -ErrorAction SilentlyContinue) {
        $known = @(); if (Get-Command -Name Get-SIFeatureCatalog -ErrorAction SilentlyContinue) { $known = @(Get-SIFeatureCatalog | ForEach-Object { $_.Name }) }
        $chk = Test-SILicenseForInstall -License $lic -KnownFeatures $known -TenantId $TenantId
        foreach ($x in @($chk.Problems)) { if ($x -notmatch '^(the licence does not verify|it is bound to tenant)') { $problems.Add($x) } }
    }
    & $res $lic $text
}

# =====================================================================================================================
#  State (Key Vault, no token) and its mirror
# =====================================================================================================================
function ConvertTo-SILicenceRequestUtc {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or -not "$Value".Trim()) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function ConvertFrom-SILicenceRequestState {
    <# The stored state (JSON) as an ordered hashtable with every field; an unreadable state starts empty. #>
    param([AllowNull()][string]$Json)
    $s = [ordered]@{ status = 'none'; requestId = ''; requestedUtc = $null; nextPollUtc = $null; nextKnockUtc = $null; pollAfterSeconds = 0
                     lastCheckUtc = $null; validTo = ''; licenceId = ''; reason = ''; rejectedUtc = $null; lastError = ''; lastResult = ''
                     # #517: the re-issued licence id already asked for (each one is asked for once)
                     supersededHandled = '' }
    if ([string]::IsNullOrWhiteSpace($Json)) { return $s }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $s }
    foreach ($k in @($s.Keys)) {
        if (-not $o.PSObject.Properties[$k]) { continue }
        $v = $o.$k
        if ($k -like '*Utc') { $s[$k] = ConvertTo-SILicenceRequestUtc $v }
        elseif ($k -eq 'pollAfterSeconds') { $n = 0; if ([int]::TryParse("$v", [ref]$n)) { $s[$k] = $n } }
        else { $s[$k] = $(if ($null -eq $v) { '' } else { "$v" }) }
    }
    if ($script:SILicenceRequestStates -notcontains $s.status) { $s.status = 'none' }
    $s
}

function ConvertTo-SILicenceRequestStateJson {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [switch]$Compact)
    $o = [ordered]@{}
    foreach ($k in $State.Keys) {
        $v = $State[$k]
        if ($v -is [datetime]) { $v = $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
        $o[$k] = $v
    }
    if ($Compact) {
        # cfg.InstallState.Value is NVARCHAR(400): the fields the web app shows, with the free text shortened.
        $short = { param($t) $t = "$t"; if ($t.Length -gt 90) { $t.Substring(0, 87) + '...' } else { $t } }
        $c = [ordered]@{ status = $o.status; requestedUtc = $o.requestedUtc; nextPollUtc = $o.nextPollUtc; lastCheckUtc = $o.lastCheckUtc
                         validTo = $o.validTo; reason = (& $short $o.reason); lastError = (& $short $o.lastError) }
        return ($c | ConvertTo-Json -Compress)
    }
    $o | ConvertTo-Json -Compress
}

function Get-SILicenceRequestStatus {
    <#
        The licence request state for the health check and the admin: @{ Status; RequestId; RequestedUtc; NextPollUtc;
        LastCheckUtc; ValidTo; Reason; LastError; Summary }. -Json is the stored state (SI-LicenceRequest-State).
    #>
    param([AllowNull()][string]$Json)
    $s = ConvertFrom-SILicenceRequestState -Json $Json
    $when = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { '-' } }
    $summary = switch ($s.status) {
        'requested' { "licence requested on {0}, waiting for Invardia" -f (& $when $s.requestedUtc) }
        'pending'   { "licence requested on {0}, waiting for Invardia (next check {1})" -f (& $when $s.requestedUtc), (& $when $s.nextPollUtc) }
        'approved'  { "licence installed{0}" -f $(if ($s.validTo) { ", valid until $($s.validTo)" } else { '' }) }
        'rejected'  { "the licence request was REJECTED on {0}{1}" -f (& $when $s.rejectedUtc), $(if ($s.reason) { ": $($s.reason)" } else { '' }) }
        default     { if ($s.validTo) { "no request needed -- the licence is valid until $($s.validTo)" } else { 'no licence has been requested' } }
    }
    if ($s.lastError) { $summary += " (last problem: $($s.lastError))" }
    [pscustomobject]@{ Status = $s.status; RequestId = $s.requestId; RequestedUtc = $s.requestedUtc; NextPollUtc = $s.nextPollUtc
                       LastCheckUtc = $s.lastCheckUtc; ValidTo = $s.validTo; Reason = $s.reason; LastError = $s.lastError; Summary = $summary }
}

function ConvertTo-SILicenceSummaryJson {
    <#
        The INSTALLED licence for the Pro web app's Licence card, as compact JSON for cfg.InstallState 'Licence'
        (NVARCHAR(400)): what Get-SILicense verified offline (signature, dates) plus whether it names this tenant. Never
        the licence text or its signature -- the web app shows these facts and reads no secret.
          status      Valid | Grace | Expired | NotYetValid | Invalid | Missing (the verifier's word)
          tenantOk    true = bound to this tenant or to none; false = bound to others; null = this tenant is not proven
          limits      only for Pro Business: the signed limits ({ "devices": 250 }); absent = Pro Enterprise
    #>
    param([AllowNull()]$License, [AllowNull()][string]$TenantId, [Parameter(Mandatory)][datetime]$NowUtc)
    $day = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { '' } }
    $short = { param($t, [int]$n) $t = "$t"; if ($t.Length -gt $n) { $t.Substring(0, $n - 3) + '...' } else { $t } }
    $st = if ($License) { "$($License.Status)" } else { 'Missing' }
    if ($st -notin @('Valid', 'Grace', 'Expired', 'NotYetValid', 'Invalid', 'Missing')) { $st = 'Invalid' }
    $ids = @(if ($License) { @($License.TenantIds) | Where-Object { $_ } | ForEach-Object { "$_".Trim().ToLowerInvariant() } })
    $tenantOk = $null
    if ($ids.Count -eq 0) { $tenantOk = $true }
    elseif ((Test-SILicenceRequestTenantProven $TenantId)) { $tenantOk = ($ids -contains "$TenantId".Trim().ToLowerInvariant()) }
    $o = [ordered]@{
        status      = $st
        licenceId   = (& $short $(if ($License) { $License.LicenseId }) 40)
        customer    = (& $short $(if ($License) { $License.Customer }) 60)
        sku         = (& $short $(if ($License -and $st -ne 'Missing') { $License.Sku }) 20)
        features    = (& $short $(if ($License) { (@($License.Features) | Where-Object { $_ }) -join ', ' }) 60)
        tenantOk    = $tenantOk
        validFrom   = (& $day $(if ($License) { $License.ValidFrom }))
        validTo     = (& $day $(if ($License) { $License.ValidTo }))
        graceUntil  = (& $day $(if ($License) { $License.GraceUntil }))
        reason      = (& $short $(if ($License) { $License.Reason }) 70)
        verifiedUtc = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    }
    # LICENCE-DIMENSION: the signed limits of a Pro Business licence (absent = Pro Enterprise), at most four, as Get-SILicense
    # read them; the feature list gives up room so the summary still fits its 400 characters.
    if ($License -and $License.PSObject.Properties['Limits'] -and $License.Limits -is [System.Collections.IDictionary] -and $st -ne 'Missing') {
        $lim = [ordered]@{}
        foreach ($k in @($License.Limits.Keys) | Select-Object -First 4) { $lim[(& $short $k 16)] = [int]$License.Limits[$k] }
        $o['features'] = (& $short $o['features'] 30)
        $o['limits'] = $lim
    }
    $o | ConvertTo-Json -Compress
}

# =====================================================================================================================
#  HTTP (the default seam)
# =====================================================================================================================
function Invoke-SILicenceRequestHttp {
    <#
        One POST to Invardia with a JSON body. Returns @{ Status (0 = no answer); Body; RetryAfter; Error }; never throws.
        The pull token goes in the header only, and no error text here can carry it (headers are not in exception text).
    #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Body, [AllowNull()][string]$Token, [int]$TimeoutSec = 30,
          # the install key proves the knock comes from this tenant's install (a header only; never in a message)
          [AllowNull()][string]$InstallKey)
    $h = @{ Accept = 'application/json' }
    if ($Token) { $h[$script:SILicenceRequestTokenHeader] = $Token }
    if ($InstallKey) { $h['X-Invardia-Install-Key'] = $InstallKey }
    try {
        $r = Invoke-WebRequest -Method Post -Uri $Uri -Headers $h -Body $Body -ContentType 'application/json' -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        $content = $r.Content; if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$content; RetryAfter = 0; Error = '' }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = "$($_.Exception.Message)" } }
        $code = 0; try { $code = [int]$resp.StatusCode } catch { }
        $body = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = [string]$_.ErrorDetails.Message }
        elseif ($resp -is [System.Net.WebResponse]) {
            try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $body = $sr.ReadToEnd(); $sr.Close() } catch { }
        }
        $ra = 0
        try {
            if ($resp -is [System.Net.WebResponse]) { [void][int]::TryParse([string]$resp.Headers['Retry-After'], [ref]$ra) }
            elseif ($resp.Headers.RetryAfter) { if ($resp.Headers.RetryAfter.Delta) { $ra = [int]$resp.Headers.RetryAfter.Delta.Value.TotalSeconds } }
        } catch { }
        return [pscustomobject]@{ Status = $code; Body = $body; RetryAfter = $ra; Error = "HTTP $code" }
    }
}

# =====================================================================================================================
#  The cycle
# =====================================================================================================================
function Invoke-SILicenceRequest {
    <#
        One licence request cycle: decide, knock or pull, verify, install, record. NEVER throws -- a failure is a warning
        and a result with Action 'error' / 'network', so an update run that calls this is never failed by it.

        -Seams (hashtable of scriptblocks):
          Http          { param($Uri, $Body, $Token) }  -> @{ Status; Body; RetryAfter; Error }   (default Invoke-SILicenceRequestHttp)
          ReadSecret    { param($Name) }  -> text or $null                                         (required)
          WriteSecret   { param($Name, $Value) }                                                   (required)
          TenantId      { }  -> the tenant id from the identity's TOKEN                            (required)
          Install       { param($Text, $TenantId) } -> @{ Ok; Message }  (setup/Set-SILicense.ps1) (required)
          CurrentLicence{ } -> the installed licence's status (default: Get-SILicense of SI-License)
          Verify        { param($Licence, $TenantId) } -> Test-SILicenceRequestFile result         (default)
          SaveState     { param($CompactJson) }  the Pro database mirror                          (optional)
          Now           { } -> [datetime] UTC                                                      (default)
          Log           { param($Level, $Text) }  Level = info | warn                              (default Write-Host / Write-Warning)
        Returns @{ Status; Action; Message; Problems; State }.
          Action: none | waiting | knocked | pending | installed | refused | rejected | invalid | network | error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Seams,
        [Parameter(Mandatory)][string]$Version,
        [string]$BaseUrl,
        [string]$Edition,
        [string]$ContactEmail,
        [int]$TimeoutSec = 30,
        [AllowNull()][string[]]$TrustedCertsB64,
        [switch]$Force
    )
    $log = if ($Seams['Log']) { $Seams['Log'] } else { { param($l, $t) if ($l -eq 'warn') { Write-Warning $t } else { Write-Host ("  [licence] {0}" -f $t) } } }
    $nowF = if ($Seams['Now']) { $Seams['Now'] } else { { [datetime]::UtcNow } }
    $problems = New-Object System.Collections.Generic.List[string]
    $state = ConvertFrom-SILicenceRequestState -Json $null
    $result = { param($action, $msg) [pscustomobject]@{ Status = $state.status; Action = $action; Message = $msg; Problems = $problems.ToArray(); State = (Get-SILicenceRequestStatus -Json (ConvertTo-SILicenceRequestStateJson -State $state)) } }
    $save = {
        try { & $Seams.WriteSecret $script:SILicenceRequestSecretState (ConvertTo-SILicenceRequestStateJson -State $state) }
        catch { & $log 'warn' ("the licence request state could not be saved: {0}" -f $_.Exception.Message) }
        if ($Seams['SaveState']) {
            try { & $Seams.SaveState (ConvertTo-SILicenceRequestStateJson -State $state -Compact) }
            catch { & $log 'warn' ("the licence request state could not be shown in the Pro database: {0}" -f $_.Exception.Message) }
        }
    }
    try {
        foreach ($req in 'ReadSecret', 'WriteSecret', 'TenantId', 'Install') { if (-not $Seams[$req]) { throw "the licence request client needs the '$req' seam" } }
        # (no GetNewClosure anywhere a file function is called: a closure cannot see functions dot-sourced into a caller's scope)
        $http = if ($Seams['Http']) { $Seams['Http'] } else { { param($u, $b, $t, $k) Invoke-SILicenceRequestHttp -Uri $u -Body $b -Token $t -TimeoutSec $TimeoutSec -InstallKey $k } }
        $base = Get-SILicenceRequestBaseUrl -BaseUrl $BaseUrl
        $now = ([datetime](& $nowF)).ToUniversalTime()
        $state = ConvertFrom-SILicenceRequestState -Json (& $Seams.ReadSecret $script:SILicenceRequestSecretState)
        $state.lastCheckUtc = $now

        # ---- the REAL tenant, from the identity's token. Unproven = nothing is sent. ----
        $tenant = $null
        try { $tenant = [string](& $Seams.TenantId) } catch { $tenant = $null }
        if (-not (Test-SILicenceRequestTenantProven $tenant)) {
            $state.lastError = 'the tenant this install runs in could not be proven from its identity token -- nothing was sent'
            & $log 'warn' $state.lastError
            & $save
            return (& $result 'refused' $state.lastError)
        }
        $tenant = $tenant.ToLowerInvariant()

        # ---- what is installed now ----
        $readCurrent = {
            if ($Seams['CurrentLicence']) { return (& $Seams.CurrentLicence) }
            $t = & $Seams.ReadSecret $script:SILicenceRequestSecretLic
            if (-not (Get-Command -Name Get-SILicense -ErrorAction SilentlyContinue)) { return $null }
            if ($TrustedCertsB64) { Get-SILicense -SecretText "$t" -TrustedCertsB64 $TrustedCertsB64 -Now $now } else { Get-SILicense -SecretText "$t" -Now $now }
        }
        $current = & $readCurrent
        # #517: Invardia answered a status report that the installed licence was re-issued (the engine recorded the newest id;
        # seam SupersededBy) -- ask now, once per id
        $sup = ''
        if ($Seams['SupersededBy']) { try { $sup = "$(& $Seams.SupersededBy)".Trim().ToLowerInvariant() } catch { $sup = '' } }
        if ($sup -and $sup -eq "$($state.supersededHandled)".Trim().ToLowerInvariant()) { $sup = '' }
        $need = Test-SILicenceRequestNeeded -License $current -TenantId $tenant -NowUtc $now -SupersededBy $sup
        if ($need.ValidTo) { $state.validTo = $need.ValidTo.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } else { $state.validTo = '' }
        $state.licenceId = "$($need.LicenceId)"
        $poll = if ($state.pollAfterSeconds -gt 0) { [int]$state.pollAfterSeconds } else { $script:SILicenceRequestPollSeconds }
        $open = ($state.status -in @('requested', 'pending')) -and $state.requestId

        if (-not $need.Needed -and -not $open) {
            if ($state.status -ne 'approved') { $state.status = 'none' }
            $state.lastError = ''; $state.lastResult = $need.Reason
            & $save
            return (& $result 'none' ("no licence request needed: {0}" -f $need.Reason))
        }
        if (-not $need.Needed -and $open) {
            # A valid licence arrived another way (installed by hand): the open request is no longer this install's business.
            $state.status = 'none'; $state.requestId = ''; $state.nextPollUtc = $null; $state.lastError = ''; $state.lastResult = $need.Reason
            & $save
            return (& $result 'none' ("no licence request needed: {0}" -f $need.Reason))
        }

        # ---- KNOCK (a local block, so a 401 on pull can knock in the same run) ----
        $knock = {
            param([string]$Why)
            $iid = "$(& $Seams.ReadSecret $script:SILicenceRequestSecretId)".Trim()
            if ($iid -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                $iid = [guid]::NewGuid().ToString()
                & $Seams.WriteSecret $script:SILicenceRequestSecretId $iid      # kept for good: every later knock reuses it
            }
            $cv = $null; $cid = ''
            if ($current -and "$($current.Status)" -notin @('Missing', 'Invalid')) { $cid = "$($current.LicenseId)"; $cv = $need.ValidTo }
            # the proof that this install holds the tenant's licence: the SHA-256 of the licence file as it is kept here
            # (UTF-8, no byte order mark, trimmed -- how Test-SILicenceRequestFile stores it), and the install key in the header
            $csha = ''
            try { $lt = "$(& $Seams.ReadSecret $script:SILicenceRequestSecretLic)".TrimStart([char]0xFEFF).Trim(); if ($lt -and $lt -ne '-') { $csha = Get-SILicenceRequestSha256 -Bytes ([System.Text.Encoding]::UTF8.GetBytes($lt)) } } catch { $csha = '' }
            $ikey = ''
            try { $ikey = "$(& $Seams.ReadSecret 'SI-Invardia-InstallKey')".Trim(); if ($ikey -notmatch '^inv-[^\s]{8,}$') { $ikey = '' } } catch { $ikey = '' }
            $body = New-SILicenceRequestBody -Version $Version -TenantId $tenant -InstallId $iid -Edition $Edition -ContactEmail $ContactEmail -CurrentLicenceId $cid -CurrentValidTo $cv -CurrentLicenceSha256 $csha
            & $log 'info' ("asking Invardia for a licence ({0}) for tenant {1}" -f $Why, $tenant)
            $r = & $http ($base + '/api/licence-requests') $body $null $ikey
            $code = [int]$r.Status
            if ($code -in @(200, 201, 202)) {
                $j = $null; try { $j = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
                if (-not $j -or -not "$($j.pullToken)".Trim() -or -not "$($j.requestId)".Trim()) {
                    $state.lastError = 'Invardia accepted the request but sent no request id or pull token'
                    $state.nextKnockUtc = $now.AddSeconds($script:SILicenceRequestPollSeconds)
                    & $log 'warn' $state.lastError
                    return 'error'
                }
                & $Seams.WriteSecret $script:SILicenceRequestSecretToken ([string]$j.pullToken)   # a repeat knock's NEW token replaces the old
                $pa = 0; [void][int]::TryParse("$($j.pollAfterSeconds)", [ref]$pa)
                $state.pollAfterSeconds = $(if ($pa -gt 0) { $pa } else { $script:SILicenceRequestPollSeconds })
                $state.requestId = [string]$j.requestId
                $state.requestedUtc = $now
                $state.status = 'requested'
                $state.reason = ''; $state.rejectedUtc = $null; $state.lastError = ''; $state.nextKnockUtc = $null
                $state.nextPollUtc = $(if ("$($j.status)" -eq 'Approved') { $now } else { $now.AddSeconds($state.pollAfterSeconds) })
                $state.lastResult = "requested ($($j.status))"
                & $log 'info' ("licence requested (request {0}, {1}); next check after {2:yyyy-MM-dd HH:mm}Z" -f $state.requestId, $j.status, $state.nextPollUtc)
                return $(if ("$($j.status)" -eq 'Approved') { 'approved-now' } else { 'knocked' })
            }
            return (& $failed $r 'knock')
        }
        # ---- an answer that is not success (knock or pull): record it, decide when to try again ----
        $failed = {
            param($r, [string]$What)
            $code = [int]$r.Status
            $next = $now.AddSeconds($poll)
            $kind = 'network'
            if ($code -eq 0) {
                $state.lastError = ("Invardia could not be reached ({0}): {1}" -f $What, $r.Error)
            } elseif ($code -eq 429) {
                $ra = [int]$r.RetryAfter; if ($ra -le 0) { $ra = 60 }
                $next = $now.AddSeconds([Math]::Max($ra, $(if ($What -eq 'pull') { $poll } else { 0 })))
                $state.lastError = ("Invardia asked to slow down ({0}); next try after {1} s" -f $What, [int]($next - $now).TotalSeconds)
                $kind = 'waiting'
            } elseif ($code -eq 422) {
                $fields = @(); try { $fields = @(("$($r.Body)" | ConvertFrom-Json -ErrorAction Stop).fields | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['field']) { "$($_.field)" } elseif ($_.PSObject.Properties['name']) { "$($_.name)" } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
                $next = $now.AddHours($script:SILicenceRequestInvalidHours)
                $state.lastError = ("Invardia refused the {0} as invalid; fields: {1}. It is not repeated before {2:yyyy-MM-dd HH:mm}Z" -f $What, $(if ($fields.Count) { $fields -join ', ' } else { 'none named' }), $next)
                foreach ($f in $fields) { $problems.Add("invalid field: $f") }
                $kind = 'invalid'
            } elseif ($code -ge 400 -and $code -lt 500) {
                $state.lastError = ("Invardia answered {0} to the {1}" -f $code, $What)
                $kind = 'error'
            } else {
                $state.lastError = ("Invardia answered {0} to the {1} -- tried again on a later run" -f $code, $What)
            }
            if ($What -eq 'knock') { $state.nextKnockUtc = $next } else { $state.nextPollUtc = $next }
            & $log 'warn' $state.lastError
            return $kind
        }

        # ---- PULL ----
        $pull = {
            $tok = "$(& $Seams.ReadSecret $script:SILicenceRequestSecretToken)".Trim()
            if (-not $tok -or $tok -eq '-') { return 'reknock' }
            $r = & $http ($base + '/api/licence-requests/pull') '{}' $tok
            $tok = $null
            $code = [int]$r.Status
            if ($code -eq 401) { & $log 'info' 'the pull token is no longer accepted -- asking again'; return 'reknock' }
            if ($code -ne 200) { return (& $failed $r 'pull') }
            $j = $null; try { $j = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
            $st = if ($j) { "$($j.status)" } else { '' }
            switch ($st) {
                'Rejected' {
                    $state.status = 'rejected'; $state.reason = $(if ($j.PSObject.Properties['reason']) { "$($j.reason)" } else { '' })
                    $state.rejectedUtc = $now; $state.nextPollUtc = $null; $state.lastError = ''
                    $state.lastResult = 'rejected'
                    & $Seams.WriteSecret $script:SILicenceRequestSecretToken '-'
                    & $log 'warn' ("the licence request was REJECTED by Invardia{0}. It is not asked again automatically before {1:yyyy-MM-dd}; run setup/Request-SILicense.ps1 -Force to ask now." -f $(if ($state.reason) { ": $($state.reason)" } else { '' }), $now.AddDays($script:SILicenceRequestRejectDays))
                    return 'rejected'
                }
                'Approved' {
                    if (-not $j.PSObject.Properties['licence'] -or $null -eq $j.licence) { break }
                    $verify = if ($Seams['Verify']) { $Seams['Verify'] } else { { param($l, $t) Test-SILicenceRequestFile -Licence $l -TenantId $t -TrustedCertsB64 $TrustedCertsB64 -Now $now } }
                    $v = & $verify $j.licence $tenant
                    if (-not $v.Ok) {
                        foreach ($p in @($v.Problems)) { $problems.Add($p) }
                        $state.status = 'pending'; $state.nextPollUtc = $now.AddSeconds($poll)
                        $state.lastError = ("the licence Invardia sent was NOT installed: {0}" -f (@($v.Problems) -join '; '))
                        & $log 'warn' $state.lastError
                        return 'refused'
                    }
                    $ins = $null
                    try { $ins = & $Seams.Install $v.Text $tenant } catch { $ins = [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message } }
                    if (-not $ins -or -not $ins.Ok) {
                        $state.status = 'pending'; $state.nextPollUtc = $now.AddSeconds($poll)
                        $state.lastError = ("the licence verified but could not be installed: {0}" -f $(if ($ins) { $ins.Message } else { 'no result' }))
                        & $log 'warn' $state.lastError
                        return 'error'
                    }
                    # Read it back: what the engines will read must be the licence just verified.
                    $back = & $readCurrent
                    if (-not $back -or "$($back.Status)" -ne 'Valid' -or "$($back.LicenseId)" -ne "$($v.License.LicenseId)") {
                        $state.status = 'pending'; $state.nextPollUtc = $now.AddSeconds($poll)
                        $state.lastError = 'the licence was written but did not read back as the one verified'
                        & $log 'warn' $state.lastError
                        return 'error'
                    }
                    $state.status = 'approved'; $state.requestId = ''; $state.nextPollUtc = $null; $state.lastError = ''; $state.reason = ''
                    $state.validTo = ([datetime]$v.License.ValidTo).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
                    $state.licenceId = "$($v.License.LicenseId)"
                    $state.lastResult = 'installed'
                    & $Seams.WriteSecret $script:SILicenceRequestSecretToken '-'
                    & $log 'info' ("licence installed and read back: valid until {0}" -f $state.validTo)
                    return 'installed'
                }
            }
            # Pending, or Approved but not signed yet
            $state.status = 'pending'; $state.nextPollUtc = $now.AddSeconds($poll); $state.lastError = ''; $state.lastResult = 'pending'
            & $log 'info' ("waiting for Invardia (request {0}); next check after {1:yyyy-MM-dd HH:mm}Z" -f $state.requestId, $state.nextPollUtc)
            return 'pending'
        }

        $action = $null
        if ($open) {
            $tokenAge = if ($state.requestedUtc) { ($now - [datetime]$state.requestedUtc).TotalDays } else { 999 }
            if ($tokenAge -ge $script:SILicenceRequestTokenDays) {
                $action = 'reknock'
            } elseif (-not $Force -and $state.nextPollUtc -and $now -lt [datetime]$state.nextPollUtc) {
                $state.lastResult = 'waiting'
                & $save
                return (& $result 'waiting' ("waiting for Invardia (request {0}); next check after {1:yyyy-MM-dd HH:mm}Z" -f $state.requestId, $state.nextPollUtc))
            } else {
                $action = & $pull
            }
            if ($action -ne 'reknock') { & $save; return (& $result $action $(if ($state.lastError) { $state.lastError } else { Get-SILicenceRequestStatus -Json (ConvertTo-SILicenceRequestStateJson -State $state) | ForEach-Object { $_.Summary } })) }
        }

        # ---- no open request (or its token is gone): knock, unless a rejection or a refusal says wait ----
        if (-not $Force -and $state.status -eq 'rejected' -and $state.rejectedUtc -and $now -lt ([datetime]$state.rejectedUtc).AddDays($script:SILicenceRequestRejectDays)) {
            & $save
            return (& $result 'rejected' ("the licence request was rejected{0}; not asked again before {1:yyyy-MM-dd} (setup/Request-SILicense.ps1 -Force asks now)" -f $(if ($state.reason) { ": $($state.reason)" } else { '' }), ([datetime]$state.rejectedUtc).AddDays($script:SILicenceRequestRejectDays)))
        }
        if (-not $Force -and $action -ne 'reknock' -and $state.nextKnockUtc -and $now -lt [datetime]$state.nextKnockUtc) {
            & $save
            return (& $result 'waiting' ("not asking again before {0:yyyy-MM-dd HH:mm}Z{1}" -f $state.nextKnockUtc, $(if ($state.lastError) { " ($($state.lastError))" } else { '' })))
        }
        $why = if ($action -eq 'reknock') { 'the pull token expired or was not accepted' } else { $need.Reason }
        $k = & $knock $why
        if ($need.Superseded -and $k -in @('knocked', 'approved-now')) { $state.supersededHandled = $sup }
        if ($k -eq 'approved-now') { $k = & $pull; if ($k -eq 'reknock') { $k = 'error'; $state.lastError = 'the new pull token was not accepted' } }
        & $save
        return (& $result $k $(if ($state.lastError) { $state.lastError } else { (Get-SILicenceRequestStatus -Json (ConvertTo-SILicenceRequestStateJson -State $state)).Summary }))
    } catch {
        $msg = "the licence request did not complete: $($_.Exception.Message)"
        try { $state.lastError = $msg; & $save } catch { }
        & $log 'warn' $msg
        return (& $result 'error' $msg)
    }
}

# =====================================================================================================================
#  The real seams
# =====================================================================================================================
function New-SILicenceRequestSeams {
    <#
        The seams for a real run, against the install's Key Vault -- over REST through SecurityInsight's own sign-in
        (engine/_shared/SI-AzRest.ps1: Get-SIAzKeyVaultSecret / Set-SIAzKeyVaultSecret; #521, no az CLI):
          -Mode Rest   the updater job (signed in once by Connect-SIUpdateRest: its managed identity or certificate).
          -Mode Az     the same REST client, as setup/Request-SILicense.ps1 names it on an admin machine or VM.
        The tenant is the tid of the managed identity's token when the install signs in as one, else of the run's own token.
        Install = setup/Set-SILicense.ps1 of -SIRoot (it verifies again and reads the secret back).
    #>
    param([Parameter(Mandatory)][string]$VaultName, [ValidateSet('Az', 'Rest')][string]$Mode = 'Az', [string]$SubscriptionId, [string]$SIRoot)
    if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $setter = [IO.Path]::Combine($SIRoot, 'setup', 'Set-SILicense.ps1')
    $vault = $VaultName
    $s = @{}
    # The closures need $vault, but a closure cannot see functions dot-sourced into a caller's SCRIPT scope: run as
    # `.\Request-SILicense.ps1` from a prompt (or from another script) it failed with "Get-SIAzKeyVaultSecret is not
    # recognized" (found live on ring 1, 2026-10-05). So the functions are captured here and called by reference.
    $kvGet = ${function:Get-SIAzKeyVaultSecret}; $kvSet = ${function:Set-SIAzKeyVaultSecret}
    $atGet = ${function:Get-SIAzAccessToken}; $tidOf = ${function:Get-SILicenceRequestTenantFromToken}
    $miTok = ${function:Get-SIManagedIdentityToken}
    # A function the closures need and this job did not load is named in a plain error at the call -- never an opaque
    # "& $null" and never a different sign-in path taken silently.
    $need = { param([string]$Fn, $Value) if (-not $Value) { throw ("the licence request cannot run: {0} is not loaded in this job (engine\_shared\SI-AzRest.ps1)" -f $Fn) } }
    $s.ReadSecret = {
        param([string]$Name)
        & $need 'Get-SIAzKeyVaultSecret' $kvGet
        $sec = & $kvGet -VaultName $vault -Name $Name -ErrorAction Stop
        if (-not $sec) { return $null }
        [System.Net.NetworkCredential]::new('', $sec.SecretValue).Password
    }.GetNewClosure()
    $s.WriteSecret = {
        param([string]$Name, [string]$Value)
        & $need 'Set-SIAzKeyVaultSecret' $kvSet
        $null = & $kvSet -VaultName $vault -Name $Name -SecretValue (ConvertTo-SecureString -String $Value -AsPlainText -Force) -ErrorAction Stop
    }.GetNewClosure()
    $s.TenantId = {
        if ([bool]$global:SI_UseManagedIdentity) {
            # the install signs in as its managed identity: the tenant is that token's (auth\SI-ManagedIdentity.ps1)
            # (a guided install sets its token hook as the global function after the seams may have been made -- it is taken
            # then; every copy of the function asks $global:SI_InstallTokenProvider first, so the captured one is right too)
            $mi = $miTok; if (-not $mi) { $c = Get-Command -Name Get-SIManagedIdentityToken -CommandType Function -ErrorAction SilentlyContinue; if ($c) { $mi = $c.ScriptBlock } }
            if (-not $mi) { throw 'the licence request cannot read the tenant: the install signs in as its managed identity and Get-SIManagedIdentityToken is not loaded in this job (auth\SI-ManagedIdentity.ps1)' }
            $null = & $mi -Resource 'https://management.azure.com/'
            return [string]$global:SI_IdentityTokenTenantId
        }
        & $need 'Get-SIAzAccessToken' $atGet; & $need 'Get-SILicenceRequestTenantFromToken' $tidOf
        $t = & $atGet -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
        $tok = if ($t.Token -is [System.Security.SecureString]) { [System.Net.NetworkCredential]::new('', $t.Token).Password } else { [string]$t.Token }
        & $tidOf -AccessToken $tok
    }.GetNewClosure()
    $s.Install = {
        param([string]$Text, [string]$TenantId)
        if (-not (Test-Path -LiteralPath $setter)) { return [pscustomobject]@{ Ok = $false; Message = "setup/Set-SILicense.ps1 is not in this copy ($setter)" } }
        $f = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'si-lr-' + [guid]::NewGuid().ToString('N') + '.silicense')
        [IO.File]::WriteAllText($f, $Text, (New-Object System.Text.UTF8Encoding($false)))
        try {
            $a = @{ Path = $f; VaultName = $vault; TenantId = $TenantId; Confirm = $false }
            $null = & $setter @a 6>$null
            [pscustomobject]@{ Ok = $true; Message = 'installed' }
        } catch { [pscustomobject]@{ Ok = $false; Message = $_.Exception.Message } }
        finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
    }.GetNewClosure()
    $s
}
