#Requires -Version 5.1
<#
    SecurityInsight -- SIGNED REQUESTS: OBSERVE, ONE SUPERADMIN-SIGNED ADOPTION, THEN ENFORCED (CR8 step 2, framework 12.11f
    item 2; owner 2026-11-04, framework REQUIREMENTS.md:64-65; SI #659; Invardia OPEN-04).

    The pipeline runner's first wake-up on this version RECORDS the existing configuration (per kind the row count + a
    SHA-256 over the rows; cfg.SignedRequestEnforcement + one audit row). Until a SuperAdmin of the install signs the
    adoption of EXACTLY that recorded set (Configuration > Signed requests; verified by the runner like any signed request)
    the install is OBSERVE ONLY: it reports what it would refuse (signedrequest.change.would-refuse, counts per kind, one
    run-log line) and holds / refuses nothing. Once adopted (Invoke-SISignedRequestEnforcement, below):
      * a WEB-WRITTEN configuration change the engine acts on (cfg.ConfigJournal, WebWriter = the database's own word on who
        wrote it, entities in $script:SISignedEnforcedEntities) whose commit has no VERIFIED signed request is REFUSED: new
        pipeline runs are HELD (a running run is never stopped) until the change is undone or saved again signed in -- a
        later journal row on the same record from a verified commit or from a non-web writer resolves it;
      * a resend / undo into a connector (cfg.CollectionSend, data out) without a verified signed request is set 'refused';
      * every refusal is said in plain words, recorded (cfg.SignedRequest Verdict 'refused', the resend's OutcomeText) and
        written once per refused commit to the audit trail (signedrequest.change.refuse, outcome refused: who changed what,
        why it was refused, what to do -- Operations > Audit trail). No guard switch: a security refusal cannot be turned off.
    Never touched: the Invardia Support app, the updater, the engine, setup -- none of them is the web app's identity.

    THE VERIFICATION (as in observe):

    The web app records every change a person makes with the person's signed Entra token as it received it
    (cfg.SignedRequest; SI.Management.Web Audit/SignedRequests.cs). The pipeline runner verifies each waiting row at every
    wake-up, AS THE ENGINE, independently of the web app:
      * the signature (RS256) against Entra's PUBLISHED keys for the install's tenant (the key id kept);
      * the issuer = the install's tenant (v1 or v2 issuer);
      * the audience = the web app's sign-in app (the row's Audience; an engine-side value wins when the install sets
        SI_Web_SignInClientId -- said in the detail which one was used);
      * issued <= captured <= expires (5 minutes' clock skew);
      * the person: the token's preferred_username / upn / oid = the row's Actor.
    The verdict -- verified | refused (would-refuse for a row captured before the cut-over) with the reason -- is recorded
    and the TOKEN IS CLEARED (only the key id, the issuer and the person stay in the detail). One summary line per wake-up.
    NEVER THROWS. PS 5.1 safe; no module (.NET RSA).
#>

$script:SISignedSkewSeconds = 300

# The journaled records (config\config-entities.locked.json) the ENGINE acts on -- a web-written change to one of them needs
# a verified signed request (framework 12.11f item 2, SI's list: connector settings, exemptions, tagging, data-out decisions).
$script:SISignedEnforcedEntities = @('setting', 'document', 'exemption', 'connector', 'override', 'jobflow', 'remediationflow',
    'template', 'cmdbservice', 'cmdblink', 'responsibilityrule', 'responsibilityoverride')
# ... and the ones it does not act on, each with its reason (a test fails on an entity in neither list).
$script:SISignedNotEnforcedEntities = [ordered]@{
    access       = 'who may do what in the web app -- read only by the web app itself (the engine reads it only to mail the SuperAdmins)'
    domainrole   = 'web app authorization (security domain roles)'
    categoryrole = 'web app authorization (category roles)'
    pivotview    = 'a saved view of the web app'
    guardack     = 'a person''s acknowledgement of a guard event on the Guards page'
    mgmtreport   = 'management reports are sent by the web app''s own scheduler, not by the engine'
    department   = 'the department roster is also kept from department sign-in-link sessions (no Entra token; a named exception, off by default)'
    member       = 'the department roster (see department)'
    advisor      = 'the department roster (see department)'
}
# a resend whose signed request has not arrived yet is waited for this long before it is refused (the web app writes the
# signed request right after the request itself)
$script:SISignedSendGraceMinutes = 10
# the audit trail's record of each refused change (config\audit-actions.locked.json)
$script:SISignedAuditAction = 'signedrequest.change.refuse'
$script:SISignedWouldAuditAction = 'signedrequest.change.would-refuse'
# SecurityInsight's root (the entity catalog of the recorded set)
$script:SISignedRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

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
    # OPEN-04: the person's object id and app roles ride on the verified detail (the adoption's SuperAdmin check reads them)
    $roles = @(@($c.roles) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ','
    @{ Verdict = 'verified'; Detail = ('{4}; key {0}; issuer {1}; audience from {2}; {3}; oid {5}; roles {6}' -f $sig.Kid, $iss, $audSrc, $Row.Actor, $kind, [string]$c.oid, $roles) }
}

function Invoke-SISignedRequestCheck {
    <#
        Verifies the waiting rows (oldest first, at most 1000 a wake-up), records each verdict, CLEARS the token, and says one
        summary line. -Invoke: the Pro database seam; -GetKeys { param($TenantId) } -> the JWKS keys (default: Entra's
        published keys, no sign-in); -Log { param($Level, $Message) }. -FromRequestId: the install's cut-over (rows with a
        higher id are ENFORCED: 'refused'; the others 'would-refuse'); -1 = observe only. NEVER THROWS. Returns the verdicts.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$TenantId = '', [string]$Audience = '', [scriptblock]$GetKeys, [scriptblock]$Log, [long]$FromRequestId = -1)
    if (-not $Log) { $Log = { param($l, $m) } }
    if (-not $GetKeys) { $GetKeys = { param($t) @((Invoke-RestMethod -Uri ('https://login.microsoftonline.com/{0}/discovery/v2.0/keys' -f $t) -TimeoutSec 30).keys) } }
    $mode = if ($FromRequestId -ge 0) { 'enforced' } else { 'observe only -- nothing is refused' }
    $rows = @()
    try { $rows = @(& $Invoke 'SELECT TOP (1000) Id, Action, Actor, TokenSource, Token, Audience, CapturedUtc FROM cfg.SignedRequest WHERE VerifiedUtc IS NULL ORDER BY Id' @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch { & $Log 'INFO' ('signed requests ({0}): not read ({1})' -f $mode, (([string]$_.Exception.Message) -split "`n")[0]); return @() }
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
        # enforced after the install's cut-over: what observe called would-refuse is refused
        if ($v.Verdict -ne 'verified' -and $FromRequestId -ge 0 -and [long]$row.Id -gt $FromRequestId) { $v = @{ Verdict = 'refused'; Detail = $v.Detail } }
        $d = [string]$v.Detail; if ($d.Length -gt 1000) { $d = $d.Substring(0, 1000) }
        try { $null = & $Invoke 'UPDATE cfg.SignedRequest SET VerifiedUtc = SYSUTCDATETIME(), Verdict = @Verdict, Detail = @Detail, Token = NULL WHERE Id = @Id AND VerifiedUtc IS NULL' @{ Verdict = $v.Verdict; Detail = $d; Id = $row.Id } 'nonquery' }
        catch { & $Log 'WARN' ('signed request {0}: the verdict could not be recorded ({1})' -f $row.Id, $_.Exception.Message) }
        $out.Add([pscustomobject]@{ Id = $row.Id; Action = $row.Action; Verdict = $v.Verdict; Detail = $d })
    }
    $bad = @($out | Where-Object { $_.Verdict -ne 'verified' })
    $why = @($bad | Group-Object { ($_.Detail -split ' \(|:')[0] } | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { '{0} x {1}' -f $_.Count, $_.Name }) -join '; '
    & $Log $(if (@($bad | Where-Object { $_.Verdict -eq 'refused' }).Count) { 'WARN' } else { 'INFO' }) ('signed requests ({0}): {1} checked, {2} verified, {3} {4}{5}' -f $mode, $out.Count, ($out.Count - $bad.Count), $bad.Count, $(if ($FromRequestId -ge 0) { 'refused' } else { 'would be refused' }), $(if ($why) { ' (' + $why + ')' } else { '' }))
    $out.ToArray()
}

function ConvertTo-SISignedUtc {
    <# PURE. A time from the database (DATETIME2 = UTC, Kind Unspecified) or a [datetime] as UTC. #>
    param($Value)
    $d = [datetime]$Value
    if ($d.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($d, [DateTimeKind]::Utc) }
    $d.ToUniversalTime()
}

function Get-SISignedRequestRefusedChangeSql {
    <# PURE. The query of the web-written changes after the cut-over that carry no verified signed request and are not
       resolved (a later row on the same record from a verified commit or a non-web writer). @From = the cut-over's journal id. #>
    $ents = (@($script:SISignedEnforcedEntities) | ForEach-Object { "N'$_'" }) -join ', '
    @"
WITH w AS (
    SELECT j.JournalId, j.CommitId, j.Entity, j.EntityKey, j.Op, j.InitiatedBy, j.CommittedUtc
    FROM cfg.ConfigJournal AS j
    WHERE j.JournalId > @From AND j.Entity IN ($ents)
      AND (ISNULL(j.WebWriter, 0) = 1 OR j.ActorSource IN (N'web', N'portal'))
      AND NOT EXISTS (SELECT 1 FROM cfg.SignedRequest AS s WHERE s.CorrelationId = j.CommitId AND s.Verdict = N'verified')
)
SELECT TOP (50) w.JournalId, w.CommitId, w.Entity, w.EntityKey, w.Op, w.InitiatedBy, w.CommittedUtc,
       (SELECT TOP (1) ISNULL(s.Verdict, N'not verified yet') + N': ' + ISNULL(s.Detail, N'') FROM cfg.SignedRequest AS s WHERE s.CorrelationId = w.CommitId ORDER BY s.Id DESC) AS Signed
FROM w
WHERE NOT EXISTS (
    SELECT 1 FROM cfg.ConfigJournal AS l
    WHERE l.Entity = w.Entity AND l.EntityKey = w.EntityKey AND l.JournalId > w.JournalId
      AND ((ISNULL(l.WebWriter, 0) = 0 AND ISNULL(l.ActorSource, N'') NOT IN (N'web', N'portal'))
           OR EXISTS (SELECT 1 FROM cfg.SignedRequest AS s2 WHERE s2.CorrelationId = l.CommitId AND s2.Verdict = N'verified')))
ORDER BY w.JournalId;
"@
}

function Get-SISignedRequestSendSql {
    <# PURE. The resend / undo requests into a connector after the cut-over that wait and carry no verified signed request. #>
    @"
SELECT TOP (50) c.SendId, c.Kind, c.Connector, c.RequestedBy, c.RequestedUtc, c.CorrelationId,
       (SELECT TOP (1) ISNULL(s.Verdict, N'not verified yet') + N': ' + ISNULL(s.Detail, N'') FROM cfg.SignedRequest AS s WHERE s.CorrelationId = c.CorrelationId ORDER BY s.Id DESC) AS Signed
FROM cfg.CollectionSend AS c
WHERE c.State = N'requested' AND c.SendId > @From
  AND NOT EXISTS (SELECT 1 FROM cfg.SignedRequest AS s WHERE s.CorrelationId = c.CorrelationId AND s.Verdict = N'verified')
ORDER BY c.SendId;
"@
}

function Get-SISignedRequestWhy {
    <# PURE. The plain reason of one refused change from its newest signed-request text (Verdict: Detail), or none. #>
    param([string]$Signed)
    if (-not "$Signed".Trim()) { return 'no signed request was recorded with this change' }
    $p = "$Signed" -split ': ', 2
    $d = if ($p.Count -gt 1) { $p[1].Trim() } else { '' }
    switch ($p[0]) {
        'not verified yet' { return 'its signed request is not verified yet (the next wake-up verifies it)' }
        default { if ($d) { return ('its signed request did not verify: {0}' -f $d) } else { return 'its signed request did not verify' } }
    }
}

function Test-SISignedRequestPending {
    <# PURE. Is this change only WAITING for its verification (not refused yet)? #>
    param([string]$Signed)
    "$Signed" -like 'not verified yet*'
}

function Get-SISignedRequestHoldText {
    <#
        PURE. The one plain sentence a held wake-up says, from the refused changes (CommitId, Entity, EntityKey, InitiatedBy,
        CommittedUtc, Signed) and the waiting resends. '' = nothing holds.
    #>
    param([object[]]$Changes = @(), [object[]]$Sends = @())
    $c = @($Changes | Where-Object { $_ }); $s = @($Sends | Where-Object { $_ })
    if (-not $c.Count -and -not $s.Count) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($c | Select-Object -First 3)) {
        $parts.Add(('{0} {1} by {2} at {3:yyyy-MM-dd HH:mm}Z ({4})' -f $x.Entity, $x.EntityKey, $(if ("$($x.InitiatedBy)".Trim()) { $x.InitiatedBy } else { 'an unknown writer' }), (ConvertTo-SISignedUtc $x.CommittedUtc), (Get-SISignedRequestWhy -Signed ([string]$x.Signed))))
    }
    foreach ($x in @($s | Select-Object -First 2)) { $parts.Add(('a {0} into {1} asked by {2} (its signed request is not verified yet)' -f $x.Kind, $x.Connector, $x.RequestedBy)) }
    $more = ($c.Count + $s.Count) - $parts.Count
    ('signed requests: no new pipeline run starts -- {0} change(s) made in the web app carry no verified signed request: {1}{2}. A running run is not stopped. Undo the change on Operations > Commits (undo), or make it again signed in; the next wake-up then starts the run.' -f ($c.Count + $s.Count), ($parts -join '; '), $(if ($more -gt 0) { (' and {0} more' -f $more) } else { '' }))
}

function Get-SISignedRequestKindCounts {
    <# PURE. The records of some changes counted per kind (entity), in kind order: @{ connector = 2; setting = 1 }. #>
    param([object[]]$Changes = @())
    $o = [ordered]@{}
    foreach ($g in @($Changes | Where-Object { $_ } | Group-Object { [string]$_.Entity } | Sort-Object Name)) { $o[[string]$g.Name] = [int]$g.Count }
    $o
}

function Get-SISignedRequestAuditRecords {
    <# PURE. One audit record per commit without a verified signed request (Write-SIAuditEvent arguments; CorrelationId = the
       commit id, so it is written once), with its records counted per kind. -Observe: signedrequest.change.would-refuse
       (outcome warning, nothing held); else signedrequest.change.refuse (outcome refused). Waiting changes get none. #>
    param([object[]]$Changes = @(), [switch]$Observe)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in @($Changes | Where-Object { $_ -and -not (Test-SISignedRequestPending -Signed ([string]$_.Signed)) } | Group-Object { [string]$_.CommitId })) {
        $f = $g.Group[0]
        $what = (@($g.Group | ForEach-Object { '{0} {1}' -f $_.Entity, $_.EntityKey }) | Select-Object -First 5) -join ', '
        $who = if ("$($f.InitiatedBy)".Trim()) { [string]$f.InitiatedBy } else { 'an unknown writer' }
        $why = Get-SISignedRequestWhy -Signed ([string]$f.Signed)
        $text = if ($Observe) { '{0} changed {1} at {2:yyyy-MM-dd HH:mm}Z in the web app; the change carries no verified signed request ({3}). It would be refused once this install is adopted -- nothing is held now.' -f $who, $what, (ConvertTo-SISignedUtc $f.CommittedUtc), $why }
                else { '{0} changed {1} at {2:yyyy-MM-dd HH:mm}Z in the web app; the change carries no verified signed request ({3}), so no new pipeline run starts until it is undone on Operations > Commits (undo) or made again signed in.' -f $who, $what, (ConvertTo-SISignedUtc $f.CommittedUtc), $why }
        $out.Add(@{ Action = $(if ($Observe) { $script:SISignedWouldAuditAction } else { $script:SISignedAuditAction }); ActorSource = 'engine'; Outcome = $(if ($Observe) { 'warning' } else { 'refused' }); CorrelationId = [string]$g.Name
                    Target = ('{0}' -f $what); Reason = $why; OutcomeText = $text
                    After = [ordered]@{ commitId = [string]$g.Name; changedBy = $who; counts = (Get-SISignedRequestKindCounts -Changes $g.Group); records = @($g.Group | ForEach-Object { '{0} {1} ({2})' -f $_.Entity, $_.EntityKey, $_.Op }) } })
    }
    $out.ToArray()
}

function Get-SISignedRequestObserveText {
    <# PURE. The one run-log line of an install in observe: what WOULD be refused, counted per kind. '' = nothing. #>
    param([object[]]$Changes = @(), [object[]]$Sends = @())
    $c = @($Changes | Where-Object { $_ -and -not (Test-SISignedRequestPending -Signed ([string]$_.Signed)) }); $s = @($Sends | Where-Object { $_ })
    if (-not $c.Count -and -not $s.Count) { return '' }
    $counts = Get-SISignedRequestKindCounts -Changes $c
    $parts = @($counts.Keys | ForEach-Object { '{0} {1}' -f $_, $counts[$_] })
    if ($s.Count) { $parts += ('resend {0}' -f $s.Count) }
    ('signed requests (observe only, waiting for adoption by a SuperAdmin): {0} change(s) made in the web app would be refused once adopted ({1}) -- nothing is held or refused now; see the audit trail (signedrequest.change.would-refuse)' -f ($c.Count + $s.Count), ($parts -join ', '))
}
function Get-SISignedRequestEntityCatalog {
    <# The enforced entities with their table, primary key and recorded columns (config\config-entities.locked.json). #>
    param([string]$SIRoot = $script:SISignedRoot)
    $j = [IO.File]::ReadAllText([IO.Path]::Combine($SIRoot, 'config', 'config-entities.locked.json')).TrimStart([char]0xFEFF) | ConvertFrom-Json
    @($j.entities | Where-Object { [string]$_.entity -in $script:SISignedEnforcedEntities } | Sort-Object { [string]$_.entity } | ForEach-Object {
        [pscustomobject]@{ Kind = [string]$_.entity; Table = [string]$_.table; Pk = @($_.pk | ForEach-Object { [string]$_ }); Columns = @($_.columns | ForEach-Object { [string]$_ }) } })
}

function Get-SISignedRequestManifestSql {
    <# PURE. One kind's row count + SHA-256 (hex) over its rows: the recorded columns in the catalog's order, the rows in
       primary-key order, as JSON (nulls included) -- a stable order and stable columns. #>
    param([Parameter(Mandatory)]$Entity)
    if ($Entity.Table -notmatch '^cfg\.[A-Za-z]+$') { throw ('not a cfg table: {0}' -f $Entity.Table) }
    $q = { param($n) if ($n -notmatch '^[A-Za-z][A-Za-z0-9]*$') { throw ('not a column name: {0}' -f $n) }; '[' + $n + ']' }
    $cols = (@($Entity.Columns) | ForEach-Object { & $q $_ }) -join ', '
    $ord = (@($Entity.Pk) | ForEach-Object { & $q $_ }) -join ', '
    "SELECT COUNT_BIG(*) AS N, CONVERT(NVARCHAR(64), HASHBYTES('SHA2_256', ISNULL((SELECT $cols FROM $($Entity.Table) ORDER BY $ord FOR JSON PATH, INCLUDE_NULL_VALUES), N'[]')), 2) AS H FROM $($Entity.Table);"
}

function Get-SISignedRequestRecordedHash {
    <# PURE. The recorded set's hash: SHA-256 (lower-case hex) over "kind|rows|sha256" per kind, in kind order, one per line. #>
    param([object[]]$Kinds = @())
    $text = (@($Kinds | Sort-Object { [string]$_.kind } | ForEach-Object { '{0}|{1}|{2}' -f $_.kind, $_.rows, ([string]$_.sha256).ToLowerInvariant() })) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') }) -join '') } finally { $sha.Dispose() }
}

function Test-SISignedRequestSuperAdmin {
    <# Is the verified token's person a SuperAdmin? Their app role SuperAdmin in the token, or their own (person) assignment
       on Configuration > Access (roles + scopes). A SuperAdmin only through a group cannot be checked by the engine (said). @{ Ok; Why } #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Detail)
    $oid = if ("$Detail" -match '; oid ([0-9a-fA-F-]{36})') { $Matches[1].ToLowerInvariant() } else { '' }
    $roles = if ("$Detail" -match '; roles ([^;]*)$') { @($Matches[1] -split ',' | Where-Object { $_ }) } else { @() }
    if ($roles -contains 'SuperAdmin') { return @{ Ok = $true; Why = 'SuperAdmin by the app role in the signed token' } }
    if (-not $oid) { return @{ Ok = $false; Why = 'the signed token names no person (object id)' } }
    $n = @(& $Invoke "SELECT COUNT(*) AS N FROM cfg.AccessAssignment WHERE PrincipalType = N'User' AND Role = N'SuperAdmin' AND LOWER(PrincipalId) = @Oid" @{ Oid = $oid } 'reader' | ForEach-Object { $_ }) | Select-Object -First 1
    $cnt = if ($n -is [System.Collections.IDictionary]) { [long]$n['N'] } elseif ($n) { [long]$n.N } else { 0 }
    if ($cnt -gt 0) { return @{ Ok = $true; Why = 'SuperAdmin on Configuration > Access (roles + scopes)' } }
    @{ Ok = $false; Why = 'the person who signed is not a SuperAdmin of this install (a SuperAdmin only through a group: ask one assigned as a person, or with the app role)' }
}

function Get-SISignedRequestState {
    <# The install's state for the page and the heartbeat: @{ Mode observe|enforce; RecordedUtc; RecordedHash; AdoptedUtc;
       AdoptedBy; Wire }; $null when nothing is recorded yet. Never throws.
       Wire = the SHARED any-product heartbeat field SignedRequests (PIM sends the same; Invardia 2026-11-20):
         { mode 'observe'|'enforce'; checked; wouldRefuse; refused (ints: the signed requests verified since sinceUtc, those
           that WOULD be refused while observing, those refused while enforcing); sinceUtc (the record, or the adoption;
           yyyy-MM-ddTHH:mm:ssZ); adoptedUtc (null while observing); waitingSince (the record while observing, else null) } #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $r = @(& $Invoke "IF OBJECT_ID(N'cfg.SignedRequestEnforcement') IS NOT NULL SELECT StartedUtc, RecordedHash, AdoptedUtc, AdoptedBy FROM cfg.SignedRequestEnforcement WHERE Id = 1" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if (-not $r) { return $null }
        $g = { param($o, $n) if ($o -is [System.Collections.IDictionary]) { $o[$n] } else { $o.$n } }
        $has = { param($v) -not ($null -eq $v -or $v -is [DBNull] -or "$v" -eq '') }
        $iso = { param($v) if (& $has $v) { (ConvertTo-SISignedUtc $v).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
        $ad = & $g $r 'AdoptedUtc'
        $mode = if (& $has $ad) { 'enforce' } else { 'observe' }
        $since = if ($mode -eq 'enforce') { $ad } else { & $g $r 'StartedUtc' }
        $cnt = @{ Checked = 0; Would = 0; Refused = 0 }
        try {
            $k = @(& $Invoke "SELECT COUNT(*) AS Checked, SUM(CASE WHEN Verdict = N'would-refuse' THEN 1 ELSE 0 END) AS Would, SUM(CASE WHEN Verdict = N'refused' THEN 1 ELSE 0 END) AS Refused FROM cfg.SignedRequest WHERE VerifiedUtc IS NOT NULL AND CapturedUtc >= @Since" @{ Since = (ConvertTo-SISignedUtc $since) } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
            if ($k) { foreach ($n in 'Checked', 'Would', 'Refused') { $v = & $g $k $n; if (& $has $v) { $cnt[$n] = [int]$v } } }
        } catch { }
        [pscustomobject]@{ Mode = $mode; RecordedUtc = & $g $r 'StartedUtc'; RecordedHash = [string](& $g $r 'RecordedHash'); AdoptedUtc = $ad; AdoptedBy = [string](& $g $r 'AdoptedBy')
                           Wire = [ordered]@{ mode = $mode; checked = [int]$cnt.Checked; wouldRefuse = [int]$cnt.Would; refused = [int]$cnt.Refused; sinceUtc = [string](& $iso $since)
                                              adoptedUtc = (& $iso $ad); waitingSince = $(if ($mode -eq 'observe') { & $iso (& $g $r 'StartedUtc') } else { $null }) } }
    } catch { $null }
}
function Invoke-SISignedRequestEnforcement {
    <#
        THE pipeline runner's call at every wake-up, BEFORE anything acts (framework 12.11f item 2; owner 2026-11-04,
        framework REQUIREMENTS.md:64-65: "observe (log only) ... then ENFORCE ring by ring ..., each install with one
        SuperAdmin-signed adoption step").
          1. RECORD (once): the existing state per enforced kind -- the row count + SHA-256 (Get-SISignedRequestManifestSql),
             the recorded hash over them, the newest journal / signed-request / resend ids -- into cfg.SignedRequestEnforcement,
             and ONE audit row (signedrequest.adoption.record) listing it. The install is then OBSERVE ONLY.
          2. the waiting signed requests verified (Invoke-SISignedRequestCheck; 'refused' only once adopted).
          3. ADOPTION: a SuperAdmin's request (cfg.SignedRequestAdoption) is decided -- adopted only when its signed request
             verified, the person is a SuperAdmin and the hash is EXACTLY the recorded one; else refused with the reason. A
             verified adoption sets AdoptedUtc: ENFORCED from then on.
          4. the web-written changes after the record without a verified signed request:
             observe  reported (audit signedrequest.change.would-refuse once per commit, counts per kind; one run-log line
                      "would be refused"); no hold, no refused resend;
             enforce  the HOLD (no new pipeline run) + audit signedrequest.change.refuse; a resend without one is refused.
        NEVER THROWS. A read that fails holds nothing (said as a WARN). -Audit { param($Record) } is the test seam (else
        Write-SIAuditEvent). Returns @{ Enforced; Mode; Hold; Changes; Sends; Refused; Adoption }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$TenantId = '', [string]$Audience = '', [string]$Version = '',
          [scriptblock]$GetKeys, [scriptblock]$Log, [scriptblock]$Audit, [datetime]$NowUtc = ([datetime]::UtcNow), [object[]]$Catalog)
    if (-not $Log) { $Log = { param($l, $m) } }
    $res = [ordered]@{ Enforced = $false; Mode = 'observe'; Hold = ''; Changes = @(); Sends = @(); Refused = @(); Adoption = '' }
    $first = { param($e) (([string]$e.Exception.Message) -split "`n")[0] }
    $get = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
    $writeAudit = {
        param($rec, [switch]$Once)
        try {
            if ($Once -and $rec.CorrelationId) {
                $seen = @(& $Invoke 'SELECT TOP (1) 1 AS Seen FROM cfg.AuditEvent WHERE Action = @Action AND CorrelationId = @Cid' @{ Action = $rec.Action; Cid = $rec.CorrelationId } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }).Count
                if ($seen) { return }
            }
            if ($Audit) { $null = & $Audit $rec }
            elseif (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue) { $null = Write-SIAuditEvent -Invoke $Invoke -NoAttribution -Actor 'SecurityInsight engine (signed requests)' -Log $Log @rec }
        } catch { & $Log 'WARN' ('signed requests: {0} could not be written to the audit trail ({1})' -f $rec.Action, (& $first $_)) }
    }
    $readCut = { @(& $Invoke 'SELECT Id, FromJournalId, FromRequestId, FromCollectionSendId, StartedUtc, Version, RecordedHash, AdoptedUtc, AdoptedBy FROM cfg.SignedRequestEnforcement WHERE Id = 1' @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1 }
    # 1. the record
    $cut = $null
    try {
        $cut = & $readCut
        if (-not $cut) {
            $cat = if ($PSBoundParameters.ContainsKey('Catalog')) { @($Catalog) } else { @(Get-SISignedRequestEntityCatalog) }
            $kinds = New-Object System.Collections.Generic.List[object]
            foreach ($e in $cat) {
                $m = @(& $Invoke (Get-SISignedRequestManifestSql -Entity $e) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
                $kinds.Add([ordered]@{ kind = $e.Kind; table = $e.Table; rows = [long](& $get $m 'N'); sha256 = ([string](& $get $m 'H')).ToLowerInvariant() })
            }
            $hash = Get-SISignedRequestRecordedHash -Kinds $kinds.ToArray()
            $manifest = ([ordered]@{ recordedHash = $hash; kinds = $kinds.ToArray() } | ConvertTo-Json -Depth 5 -Compress)
            $basis = ('recorded with release {0}; observe only until a SuperAdmin adopts it' -f $(if ($Version) { $Version } else { '(unknown)' }))
            $null = & $Invoke @"
IF NOT EXISTS (SELECT 1 FROM cfg.SignedRequestEnforcement WHERE Id = 1)
INSERT cfg.SignedRequestEnforcement (Id, FromJournalId, FromRequestId, FromCollectionSendId, Version, Basis, RecordedHash, Manifest)
SELECT 1, ISNULL((SELECT MAX(JournalId) FROM cfg.ConfigJournal), 0), ISNULL((SELECT MAX(Id) FROM cfg.SignedRequest), 0),
       ISNULL((SELECT MAX(SendId) FROM cfg.CollectionSend), 0), @Version, LEFT(@Basis, 1000), @Hash, @Manifest;
"@ @{ Version = $Version; Basis = $basis; Hash = $hash; Manifest = $manifest } 'nonquery'
            $cut = & $readCut
            if ($cut) {
                & $writeAudit @{ Action = 'signedrequest.adoption.record'; ActorSource = 'engine'; Outcome = 'ok'; CorrelationId = ('record-' + $hash.Substring(0, 16)); Target = 'the recorded configuration'
                            Reason = ('{0} kind(s); recorded hash {1}' -f $kinds.Count, $hash); After = [ordered]@{ recordedHash = $hash; kinds = $kinds.ToArray() } } -Once
                & $Log 'INFO' ('signed requests: the existing configuration is RECORDED for adoption ({0} kind(s), {1} row(s), hash {2}) -- OBSERVE ONLY until a SuperAdmin adopts it on Configuration > Signed requests' -f $kinds.Count, (@($kinds | ForEach-Object { [long]$_.rows }) | Measure-Object -Sum).Sum, $hash.Substring(0, 12))
            }
        }
    } catch { & $Log 'WARN' ('signed requests: the install''s recorded set could not be read or recorded ({0}) -- observe only in this wake-up' -f (& $first $_)); $cut = $null }
    $adopted = $cut -and "$(& $get $cut 'AdoptedUtc')" -ne ''
    # 2. the verification (refused only once adopted)
    $chk = @{ Invoke = $Invoke; TenantId = $TenantId; Audience = $Audience; Log = $Log; FromRequestId = $(if ($adopted) { [long](& $get $cut 'FromRequestId') } else { -1 }) }
    if ($GetKeys) { $chk.GetKeys = $GetKeys }
    $null = Invoke-SISignedRequestCheck @chk
    if (-not $cut) { return [pscustomobject]$res }
    # 3. the adoption
    if (-not $adopted) {
        try {
            foreach ($a in @(& $Invoke "SELECT TOP (5) a.AdoptionId, a.RecordedHash, a.RequestedBy, a.RequestedUtc, a.CorrelationId, s.Verdict, s.Detail FROM cfg.SignedRequestAdoption AS a OUTER APPLY (SELECT TOP (1) Verdict, Detail FROM cfg.SignedRequest WHERE CorrelationId = a.CorrelationId ORDER BY Id DESC) AS s WHERE a.DecidedUtc IS NULL ORDER BY a.AdoptionId" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })) {
                $aid = [long](& $get $a 'AdoptionId'); $by = [string](& $get $a 'RequestedBy'); $verdict = [string](& $get $a 'Verdict'); $detail = [string](& $get $a 'Detail')
                $why = ''
                if (-not $verdict) {
                    $age = $NowUtc.ToUniversalTime() - (ConvertTo-SISignedUtc (& $get $a 'RequestedUtc'))
                    if ($age.TotalHours -lt 24) { & $Log 'INFO' ('signed requests: the adoption asked by {0} waits for its signed request to be verified' -f $by); continue }
                    $why = 'no signed request was verified for it within a day'
                }
                elseif ($verdict -ne 'verified') { $why = ('its signed request did not verify: {0}' -f $detail) }
                elseif (([string](& $get $a 'RecordedHash')).Trim().ToLowerInvariant() -ne ([string](& $get $cut 'RecordedHash')).Trim().ToLowerInvariant()) { $why = 'the hash it adopts is not the recorded one (the page was older than the record) -- open the page again and adopt what it shows' }
                else { $sa = Test-SISignedRequestSuperAdmin -Invoke $Invoke -Detail $detail; if (-not $sa.Ok) { $why = $sa.Why } }
                if ($why) {
                    $null = & $Invoke "UPDATE cfg.SignedRequestAdoption SET DecidedUtc = SYSUTCDATETIME(), Decision = N'refused', Reason = LEFT(@Why, 1000) WHERE AdoptionId = @Id AND DecidedUtc IS NULL" @{ Why = $why; Id = $aid } 'nonquery'
                    & $writeAudit @{ Action = 'signedrequest.adoption.refuse'; ActorSource = 'engine'; Outcome = 'refused'; CorrelationId = [string](& $get $a 'CorrelationId'); Target = 'the recorded configuration'; Reason = $why; After = [ordered]@{ requestedBy = $by; adoptionId = $aid } } -Once
                    & $Log 'WARN' ('signed requests: the adoption asked by {0} is refused -- {1}. The install stays observe only.' -f $by, $why)
                    continue
                }
                $null = & $Invoke "UPDATE cfg.SignedRequestEnforcement SET AdoptedUtc = SYSUTCDATETIME(), AdoptedBy = LEFT(@By, 256), AdoptionId = @Id WHERE Id = 1 AND AdoptedUtc IS NULL; UPDATE cfg.SignedRequestAdoption SET DecidedUtc = SYSUTCDATETIME(), Decision = N'adopted' WHERE AdoptionId = @Id AND DecidedUtc IS NULL" @{ By = $by; Id = $aid } 'nonquery'
                & $writeAudit @{ Action = 'signedrequest.adoption.adopt'; ActorSource = 'engine'; Outcome = 'ok'; CorrelationId = [string](& $get $a 'CorrelationId'); Target = 'the recorded configuration'; Reason = ('adopted by {0}' -f $by); After = [ordered]@{ adoptedBy = $by; adoptionId = $aid; recordedHash = [string](& $get $cut 'RecordedHash') } } -Once
                & $Log 'INFO' ('signed requests: {0} adopted the recorded configuration (verified) -- ENFORCED at this install from now on' -f $by)
                $res.Adoption = 'adopted'; $adopted = $true
                break
            }
        } catch { & $Log 'WARN' ('signed requests: the adoption requests could not be decided in this wake-up ({0})' -f (& $first $_)) }
    }
    $res.Enforced = [bool]$adopted; $res.Mode = $(if ($adopted) { 'enforce' } else { 'observe' })
    # 4. the changes after the record
    try { $res.Changes = @(& $Invoke (Get-SISignedRequestRefusedChangeSql) @{ From = [long](& $get $cut 'FromJournalId') } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object {
            [pscustomobject]@{ JournalId = & $get $_ 'JournalId'; CommitId = [string](& $get $_ 'CommitId'); Entity = [string](& $get $_ 'Entity'); EntityKey = [string](& $get $_ 'EntityKey')
                               Op = [string](& $get $_ 'Op'); InitiatedBy = [string](& $get $_ 'InitiatedBy'); CommittedUtc = & $get $_ 'CommittedUtc'; Signed = [string](& $get $_ 'Signed') } }) }
    catch { & $Log 'WARN' ('signed requests: the changes made in the web app could not be checked in this wake-up ({0}) -- nothing is held for it' -f (& $first $_)); $res.Changes = @() }
    # the web app writes the signed request right AFTER the change: a change of the last minutes with none yet is waited for
    foreach ($x in @($res.Changes)) {
        if (-not "$($x.Signed)".Trim() -and $x.CommittedUtc -and (ConvertTo-SISignedUtc $x.CommittedUtc).AddMinutes($script:SISignedSendGraceMinutes) -gt $NowUtc.ToUniversalTime()) { $x.Signed = 'not verified yet: its signed request has not arrived yet' }
    }
    # the resends into a connector after the record
    $wait = New-Object System.Collections.Generic.List[object]; $refused = New-Object System.Collections.Generic.List[object]; $would = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($r in @(& $Invoke (Get-SISignedRequestSendSql) @{ From = [long](& $get $cut 'FromCollectionSendId') } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })) {
            $x = [pscustomobject]@{ SendId = & $get $r 'SendId'; Kind = [string](& $get $r 'Kind'); Connector = [string](& $get $r 'Connector'); RequestedBy = [string](& $get $r 'RequestedBy')
                                    RequestedUtc = & $get $r 'RequestedUtc'; CorrelationId = [string](& $get $r 'CorrelationId'); Signed = [string](& $get $r 'Signed') }
            $young = $x.RequestedUtc -and ((ConvertTo-SISignedUtc $x.RequestedUtc).AddMinutes($script:SISignedSendGraceMinutes) -gt $NowUtc.ToUniversalTime())
            if ((-not "$($x.Signed)".Trim() -and $young) -or (Test-SISignedRequestPending -Signed $x.Signed)) { if ($adopted) { $wait.Add($x) }; continue }
            if (-not $adopted) { $would.Add($x); continue }
            $why = ('Refused: the request carries no verified signed request - {0}. Ask for it again signed in.' -f (Get-SISignedRequestWhy -Signed $x.Signed))
            try { $null = & $Invoke "UPDATE cfg.CollectionSend SET State = N'refused', OutcomeText = LEFT(@Text, 2000), DoneUtc = SYSUTCDATETIME() WHERE SendId = @Id AND State = N'requested'" @{ Text = $why; Id = $x.SendId } 'nonquery'; $refused.Add($x) }
            catch { & $Log 'WARN' ('signed requests: the {0} into {1} could not be marked refused ({2}) -- it waits' -f $x.Kind, $x.Connector, (& $first $_)); $wait.Add($x) }
            & $Log 'WARN' ('signed requests: the {0} into {1} asked by {2} is refused -- {3}' -f $x.Kind, $x.Connector, $x.RequestedBy, (Get-SISignedRequestWhy -Signed $x.Signed))
        }
    } catch { & $Log 'WARN' ('signed requests: the resends into a connector could not be checked in this wake-up ({0})' -f (& $first $_)) }
    $res.Sends = $wait.ToArray(); $res.Refused = $refused.ToArray()
    $recs = @(Get-SISignedRequestAuditRecords -Changes $res.Changes -Observe:(-not $adopted))
    if (-not $adopted) {
        # OBSERVE: reported, nothing held, nothing refused
        foreach ($x in $would) { $recs += @{ Action = $script:SISignedWouldAuditAction; ActorSource = 'engine'; Outcome = 'warning'; CorrelationId = $x.CorrelationId; Target = ('{0} into {1}' -f $x.Kind, $x.Connector)
                                                Reason = (Get-SISignedRequestWhy -Signed $x.Signed); OutcomeText = ('{0} asked for a {1} into {2}; it carries no verified signed request and would be refused once this install is adopted (nothing is refused now).' -f $x.RequestedBy, $x.Kind, $x.Connector)
                                                After = [ordered]@{ counts = [ordered]@{ resend = 1 } } } }
        $line = Get-SISignedRequestObserveText -Changes $res.Changes -Sends $would.ToArray()
        if ($line) { & $Log 'WARN' $line }
        foreach ($rec in $recs) { & $writeAudit $rec -Once }
        return [pscustomobject]$res
    }
    $res.Hold = Get-SISignedRequestHoldText -Changes $res.Changes -Sends $res.Sends
    if ($res.Hold) { & $Log 'WARN' $res.Hold; foreach ($rec in $recs) { & $writeAudit $rec -Once } }
    [pscustomobject]$res
}
