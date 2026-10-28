#Requires -Version 5.1
<#
    SecurityInsight -- SIGNED REQUESTS, OBSERVE ONLY (CR8 step 2, framework DOCS/REQUIREMENTS.md 12.11f item 2; SI #659).

    The web app records every change a person makes with the person's signed Entra token as it received it
    (cfg.SignedRequest; SI.Management.Web Audit/SignedRequests.cs). The pipeline runner verifies each waiting row at every
    wake-up, AS THE ENGINE, independently of the web app:
      * the signature (RS256) against Entra's PUBLISHED keys for the install's tenant (the key id kept);
      * the issuer = the install's tenant (v1 or v2 issuer);
      * the audience = the web app's sign-in app (the row's Audience; an engine-side value wins when the install sets
        SI_Web_SignInClientId -- said in the detail which one was used);
      * issued <= captured <= expires (5 minutes' clock skew);
      * the person: the token's preferred_username / upn / oid = the row's Actor.
    The verdict -- verified | would-refuse (with the reason) -- is recorded and the TOKEN IS CLEARED (only the key id, the
    issuer and the person stay in the detail). NOTHING IS REFUSED: one summary line per wake-up says what the engine would
    refuse once this is enforced (ring by ring, a later step). NEVER THROWS. PS 5.1 safe; no module (.NET RSA).
#>

$script:SISignedSkewSeconds = 300

function ConvertFrom-SIBase64Url {
    <# PURE. Base64url text -> bytes. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $s = $Text.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    [Convert]::FromBase64String($s)
}

function ConvertFrom-SIJwtPart {
    <# PURE. One JWT part (header / payload) -> object; $null when it is not JSON. #>
    param([string]$Part)
    try { [Text.Encoding]::UTF8.GetString((ConvertFrom-SIBase64Url -Text $Part)) | ConvertFrom-Json } catch { $null }
}

function Test-SIJwtSignature {
    <# PURE. Does -Token carry a valid RS256 signature by one of -Keys (JWKS keys: kid, kty RSA, n, e)? @{ Ok; Kid; Why }. #>
    param([Parameter(Mandatory)][string]$Token, [object[]]$Keys = @())
    $p = $Token.Split('.')
    if ($p.Count -ne 3) { return @{ Ok = $false; Kid = ''; Why = 'not a signed token (three parts)' } }
    $h = ConvertFrom-SIJwtPart -Part $p[0]
    if (-not $h) { return @{ Ok = $false; Kid = ''; Why = 'the token header is not readable' } }
    $kid = [string]$h.kid
    if ([string]$h.alg -ne 'RS256') { return @{ Ok = $false; Kid = $kid; Why = ('algorithm {0} -- only RS256 is accepted' -f $h.alg) } }
    $k = @($Keys | Where-Object { $null -ne $_ -and [string]$_.kid -eq $kid -and [string]$_.kty -eq 'RSA' }) | Select-Object -First 1
    if (-not $k) { return @{ Ok = $false; Kid = $kid; Why = ('key {0} is not among the published keys (an older request than the keys -- fails closed)' -f $kid) } }
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
        $prm = New-Object System.Security.Cryptography.RSAParameters
        $prm.Modulus = ConvertFrom-SIBase64Url -Text ([string]$k.n); $prm.Exponent = ConvertFrom-SIBase64Url -Text ([string]$k.e)
        $rsa.ImportParameters($prm)
        $ok = $rsa.VerifyData([Text.Encoding]::ASCII.GetBytes($p[0] + '.' + $p[1]), (ConvertFrom-SIBase64Url -Text $p[2]),
                              [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { $ok = $false } finally { $rsa.Dispose() }
    @{ Ok = [bool]$ok; Kid = $kid; Why = $(if ($ok) { '' } else { 'the signature does not verify' }) }
}

function Get-SISignedRequestVerdict {
    <#
        PURE. One row (Actor, TokenSource, Token, Audience, CapturedUtc as [datetime] UTC) against -Keys, -TenantId and
        -Audience (the engine's own value; '' = the row's). @{ Verdict = verified | would-refuse; Detail }.
    #>
    param([Parameter(Mandatory)]$Row, [object[]]$Keys = @(), [string]$TenantId = '', [string]$Audience = '')
    $no = { param($why) @{ Verdict = 'would-refuse'; Detail = $why } }
    $tok = [string]$Row.Token
    if (-not $tok) { return (& $no ('no signed token came with the change (source {0})' -f $Row.TokenSource)) }
    $sig = Test-SIJwtSignature -Token $tok -Keys $Keys
    if (-not $sig.Ok) { return (& $no $sig.Why) }
    $c = ConvertFrom-SIJwtPart -Part ($tok.Split('.')[1])
    if (-not $c) { return (& $no 'the token claims are not readable') }
    $tid = ([string]$TenantId).Trim().ToLowerInvariant()
    $iss = [string]$c.iss
    if (-not $tid -or ($iss -ne ('https://login.microsoftonline.com/{0}/v2.0' -f $tid) -and $iss -ne ('https://sts.windows.net/{0}/' -f $tid))) { return (& $no ('issuer {0} is not the install''s tenant' -f $iss)) }
    $audWant = if ($Audience) { $Audience } else { [string]$Row.Audience }
    $audSrc = if ($Audience) { 'the engine' } else { 'the web app' }
    # #852 / front 1.4.0: the ID token (aud = the client id) or the access token for the web app's own API (aud = the client
    # id, or api://<client id>) -- two forms of the SAME app; anything else is another app
    $audNorm = { param($a) ("$a").Trim().ToLowerInvariant() -replace '^api://', '' -replace '/+$', '' }
    if (-not $audWant -or (& $audNorm $c.aud) -ne (& $audNorm $audWant)) { return (& $no ('audience {0} is not the web app''s sign-in app ({1}, from {2})' -f $c.aud, $audWant, $audSrc)) }
    $kind = if ($c.PSObject.Properties['scp'] -and "$($c.scp)".Trim()) { 'access token' } else { 'ID token' }
    $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $cap = ([datetime]$Row.CapturedUtc).ToUniversalTime()
    $iat = $epoch.AddSeconds([double]$c.iat); $exp = $epoch.AddSeconds([double]$c.exp)
    if ($cap -lt $iat.AddSeconds(-$script:SISignedSkewSeconds) -or $cap -gt $exp.AddSeconds($script:SISignedSkewSeconds)) { return (& $no ('captured {0:u} outside the token''s life {1:u} - {2:u}' -f $cap, $iat, $exp)) }
    $who = @([string]$c.preferred_username, [string]$c.upn, [string]$c.oid) | Where-Object { $_ }
    if (@($who | Where-Object { $_.ToLowerInvariant() -eq ([string]$Row.Actor).ToLowerInvariant() }).Count -eq 0) { return (& $no ('the token is {0}, the change is recorded for {1}' -f ($who -join ' / '), $Row.Actor)) }
    @{ Verdict = 'verified'; Detail = ('{4}; key {0}; issuer {1}; audience from {2}; {3}' -f $sig.Kid, $iss, $audSrc, $Row.Actor, $kind) }
}

function Invoke-SISignedRequestCheck {
    <#
        Verifies the waiting rows (oldest first, at most 200 a wake-up), records each verdict, CLEARS the token, and says one
        summary line. -Invoke: the Pro database seam; -GetKeys { param($TenantId) } -> the JWKS keys (default: Entra's
        published keys, no sign-in); -Log { param($Level, $Message) }. NEVER THROWS, NEVER REFUSES. Returns the verdicts.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$TenantId = '', [string]$Audience = '', [scriptblock]$GetKeys, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) } }
    if (-not $GetKeys) { $GetKeys = { param($t) @((Invoke-RestMethod -Uri ('https://login.microsoftonline.com/{0}/discovery/v2.0/keys' -f $t) -TimeoutSec 30).keys) } }
    $rows = @()
    try { $rows = @(& $Invoke 'SELECT TOP (200) Id, Action, Actor, TokenSource, Token, Audience, CapturedUtc FROM cfg.SignedRequest WHERE VerifiedUtc IS NULL ORDER BY Id' @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch { & $Log 'INFO' ('signed requests (observe only): not read ({0})' -f (([string]$_.Exception.Message) -split "`n")[0]); return @() }
    if (-not $rows.Count) { return @() }
    $keys = @(); $keyWhy = ''
    if ($TenantId) { try { $keys = @(& $GetKeys $TenantId) } catch { $keyWhy = ('the published keys could not be read ({0})' -f (([string]$_.Exception.Message) -split "`n")[0]) } }
    else { $keyWhy = 'the install''s tenant is not known to the engine' }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) {
        $get = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
        $row = [pscustomobject]@{ Id = & $get 'Id'; Action = [string](& $get 'Action'); Actor = [string](& $get 'Actor'); TokenSource = [string](& $get 'TokenSource')
                                  Token = [string](& $get 'Token'); Audience = [string](& $get 'Audience'); CapturedUtc = & $get 'CapturedUtc' }
        $v = if ($keyWhy -and $row.Token) { @{ Verdict = 'would-refuse'; Detail = $keyWhy } } else { Get-SISignedRequestVerdict -Row $row -Keys $keys -TenantId $TenantId -Audience $Audience }
        $d = [string]$v.Detail; if ($d.Length -gt 1000) { $d = $d.Substring(0, 1000) }
        try { $null = & $Invoke 'UPDATE cfg.SignedRequest SET VerifiedUtc = SYSUTCDATETIME(), Verdict = @Verdict, Detail = @Detail, Token = NULL WHERE Id = @Id AND VerifiedUtc IS NULL' @{ Verdict = $v.Verdict; Detail = $d; Id = $row.Id } 'nonquery' }
        catch { & $Log 'WARN' ('signed request {0}: the verdict could not be recorded ({1})' -f $row.Id, $_.Exception.Message) }
        $out.Add([pscustomobject]@{ Id = $row.Id; Action = $row.Action; Verdict = $v.Verdict; Detail = $d })
    }
    $bad = @($out | Where-Object { $_.Verdict -ne 'verified' })
    $why = @($bad | Group-Object { ($_.Detail -split ' \(|:')[0] } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { '{0} x {1}' -f $_.Count, $_.Name }) -join '; '
    & $Log 'INFO' ('signed requests (observe only -- nothing is refused): {0} checked, {1} verified, {2} would be refused{3}' -f $out.Count, ($out.Count - $bad.Count), $bad.Count, $(if ($why) { ' (' + $why + ')' } else { '' }))
    $out.ToArray()
}
