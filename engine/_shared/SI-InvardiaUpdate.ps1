#Requires -Version 5.1
<#
    SecurityInsight -- UPDATES FROM INVARDIA (#240). The client side of Invardia's frozen update contract v1 (owner
    2026-10-04: "licence + install key"). ONE client for both editions (framework PRO-COMMUNITY-SAME, 2026-11-11): an install
    with a licence asks the install route below; a Community install without one asks Invardia's anonymous Community route
    (container/updater/_shared/SI-UpdaterCommunity.ps1) -- the same signed-manifest checks, the same trusted keys.

    THE INSTALL KEY IS CLAIMED AUTOMATICALLY (Invardia owner decision 2026-10-04 -- nobody hands one out):
      POST <base>/api/install-keys/claim  { product, tenantId (the 'tid' of the identity's own token), licence }
        201 { key, environment, telemetryEnabled, uplink{...}, updates{ endpoint, header } } -> stored in the Key Vault
        403 licence (reason) | 409 keyExists / tenantBelongsToAnotherCompany (reported, NEVER claimed again in a loop) | 422
      at install (unless the guided install's bundle carries installKey -- then that is stored and nothing is claimed) and
      when the updater starts with no key stored. The manifest is then asked for at the returned updates.endpoint, with
      the key in updates.header; the frozen URLs below are the defaults.

    PULL (each update run, for kind 'code' and kind 'templates'):
      POST <base>/api/updates/securityinsight/manifest   body { kind, licence: <the licence file text>, ring: 0-3 }
           header X-Invardia-Install-Key: inv-...      (the install key -- read from the install's Key Vault)
           header X-Invardia-Install-Id: <guid>        (Invardia S16: the install's LASTING id, SI-InstallId -- only when the
                                                        install has one; never the anonymous telemetry id, never made up here)
        200 { manifest, manifestB64, signature, keyId, downloadUrl }
        204 nothing released for this install's ring + kind     401 the install key     403 the licence (reason)
        404 product   422 invalid request (fields; 'ring' when the pull carries none)   429 slow down (Retry-After)
    THE RING IS SECURITYINSIGHT'S (framework UPDATE-1.7, operator 2026-10-06: "Solution (si, pim) decides WHAT version and
      WHICH Ring to release in updates, Invardia relays only"): the pull carries this environment's OWN ring -- the updater's
      SI_UPDATER_RING, else the ring recorded for the install (cfg.InstallState 'Ring', #308). With no ring known, NO pull is
      made and the result says why (Action 'off'). Invardia answers with what SI released to that ring.
    VERIFY before anything is used:
      * the signature: RS256 (RSASSA-PKCS1-v1_5, SHA-256) over the base64-DECODED manifest bytes (UPDATE-1.2), against the TRUSTED
        public keys EMBEDDED in this release (engine/_shared/SI-InvardiaUpdateKeys.json), chosen by keyId. A key list
        fetched at run time is never trusted on its own. An EMPTY list refuses every manifest, and says so;
      * the manifest is the one asked for (product securityinsight, the kind) and well formed;
      * its sequence is not LOWER than the one this install applied for that kind (no replay of an old, validly signed
        manifest);
      * the SIGNED ring is the ring this environment asked for (UPDATE-1.7) -- a manifest for another ring, or none, is refused;
      * manualStep set = HOLD: shown, never applied automatically, until the admin accepts that exact sequence.
    DOWNLOAD: GET downloadUrl (a 15-minute token for that one file) -> the file; its size AND SHA-256 must equal the
      signed manifest's, else it is deleted and refused.

    🔒 THE INSTALL KEY IS A SECRET. It travels only in the X-Invardia-Install-Key header; it is never printed, never
    logged, never put in a result, and every text this file returns is scrubbed of it. The download URL's token is
    withheld from everything printed as well. Updates work even when telemetry is switched off.

    🔒 NEVER THROWS. A network failure, a 4xx / 5xx or a refused manifest becomes a RESULT with an Action and a Reason,
    so an update run that calls this is never failed by it. Every call that leaves the process goes through -Seams, so
    the contract test runs offline. PS 5.1 safe.
#>

# NO Set-StrictMode HERE -- a dot-sourced file that sets it leaks into the caller's scope.

# Invardia S16: the install's lasting id (SI-InstallId) as X-Invardia-Install-Id on the manifest pull
if (-not (Get-Command -Name ConvertTo-SIInvardiaInstallId -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaInstallId.ps1')) }

$script:SIInvardiaUpdateProduct      = 'securityinsight'
$script:SIInvardiaUpdateDefaultBase   = 'https://invardia.com'
$script:SIInvardiaUpdateKeyHeader     = 'X-Invardia-Install-Key'
$script:SIInvardiaUpdateSecretKey     = 'SI-Invardia-InstallKey'
$script:SIInvardiaUpdateSecretState   = 'SI-Update-State'
$script:SIInvardiaUpdateSecretLicence = 'SI-License'
$script:SIInvardiaUpdateKinds         = @('code', 'templates')
$script:SIInvardiaUpdateKeysFile      = [IO.Path]::Combine($PSScriptRoot, 'SI-InvardiaUpdateKeys.json')

# =====================================================================================================================
#  Pure helpers
# =====================================================================================================================
function Get-SIInvardiaUpdateBaseUrl {
    <# Where Invardia is: -BaseUrl, else $global:SI_InvardiaUpdate_BaseUrl, else $env:SI_UPDATER_INVARDIA_BASE_URL, else
       https://invardia.com. HTTPS only (the install key travels in a header). No trailing slash. Throws on http://. #>
    param([string]$BaseUrl)
    $u = @($BaseUrl, [string]$global:SI_InvardiaUpdate_BaseUrl, [string]$env:SI_UPDATER_INVARDIA_BASE_URL) | Where-Object { "$_".Trim() } | Select-Object -First 1
    if (-not $u) { $u = $script:SIInvardiaUpdateDefaultBase }
    $u = "$u".Trim().TrimEnd('/')
    if ($u -notmatch '^https://[^/\s]+') { throw ("the update address must be an https:// URL, not '{0}'" -f $u) }
    $u
}

function Get-SIInvardiaManifestUri {
    param([Parameter(Mandatory)][string]$BaseUrl)
    '{0}/api/updates/{1}/manifest' -f $BaseUrl.TrimEnd('/'), $script:SIInvardiaUpdateProduct
}

function Test-SIInvardiaInstallKeyFormat {
    <# PURE. An Invardia install key: 'inv-' and at least 8 more visible characters. Never echoes the value. #>
    param([AllowNull()][AllowEmptyString()][string]$InstallKey)
    ("$InstallKey".Trim() -match '^inv-[^\s]{8,}$')
}

function Hide-SIInvardiaSecret {
    <#
        PURE. Text with the secrets withheld: every URL query (the download token, a SAS) dropped, anything shaped like an
        install key (inv-...) masked, and each literal -Secret replaced. Everything this file returns passes through here.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [string[]]$Secret)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    foreach ($s in @($Secret | Where-Object { "$_".Length -ge 4 })) { $t = $t.Replace([string]$s, '<withheld>') }
    $t = $t -replace '(https?://[^\s?"'']+)\?[^\s"'']*', '$1?<token withheld>'
    $t = $t -replace '\binv-[^\s"'',;]+', 'inv-<withheld>'
    $t
}

function New-SIInvardiaManifestBody {
    <# PURE. The pull's JSON body: { kind, licence, ring } -- the licence is the licence FILE TEXT, as installed; the ring is
       this environment's own (UPDATE-1.7: SI decides the ring; Invardia answers 422 without it). #>
    param([Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind, [Parameter(Mandatory)][string]$Licence,
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
    ([ordered]@{ kind = $Kind; licence = $Licence; ring = $Ring }) | ConvertTo-Json -Compress
}

function ConvertTo-SIInvardiaPullRing {
    <# PURE. This environment's update ring as the pull sends it: 0..3 (number, '1', 'r1', 'ring 1'), else -1 (none / not a ring). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [bool]) { return -1 }
    $t = ("$Value").Trim().ToLowerInvariant() -replace '^(ring\s*|r)', ''
    $n = 0
    if (-not [int]::TryParse($t, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { return -1 }
    if ($n -lt 0 -or $n -gt 3) { return -1 }
    $n
}

function Test-SIInvardiaReleaseOfVersion {
    <#
        PURE. Does a release named -Released carry the code whose VERSION file says -Archive? Equal, or a BUILD of it:
        '<VERSION>.<build number>' (e.g. 3.0.0.202610061530). Ring 1 takes every build of the same VERSION, and Invardia
        keeps a version immutable, so each build is released under its own number (Publish-SIRelease.ps1 -Build).
    #>
    param([AllowEmptyString()][string]$Released, [AllowEmptyString()][string]$Archive)
    $r = "$Released".Trim(); $a = "$Archive".Trim()
    if (-not $r -or -not $a) { return $false }
    ($r -eq $a) -or ($r -match ('^' + [regex]::Escape($a) + '\.\d{1,14}$'))
}

function Get-SIInvardiaNoRingReason {
    <# PURE. Why no Pro pull is made when this environment has no update ring (UPDATE-1.7), in plain words. #>
    param([AllowNull()]$Ring)
    $what = if ($null -ne $Ring -and "$Ring".Trim()) { "'$Ring' is not 0, 1, 2 or 3" } else { 'none is set' }
    "this environment has no update ring ($what) -- SecurityInsight decides which ring an environment is in, so no update is asked for until one is set: SI_UPDATER_RING on the updater job (setup\Install-SIUpdaterJob.ps1 -UpdateRing <0-3>), or setup\Set-SIInstallRing.ps1 -Ring <0-3> / 'Update ring' on the Settings page"
}

function ConvertFrom-SIInvardiaBase64 {
    <# PURE. Bytes from base64 OR base64url (padding optional). $null when it is neither. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $s = "$Text".Trim()
    if (-not $s) { return $null }
    $s = $s.Replace('-', '+').Replace('_', '/')
    while ($s.Length % 4) { $s += '=' }
    try { return , [Convert]::FromBase64String($s) } catch { return $null }
}

function Read-SIInvardiaDer {
    <# PURE. One DER TLV at -Offset: @{ Tag; Start (of the value); Length; Next }. Throws on a malformed length. #>
    param([Parameter(Mandatory)][byte[]]$Bytes, [int]$Offset = 0)
    $tag = $Bytes[$Offset]; $i = $Offset + 1
    $len = [int]$Bytes[$i]; $i++
    if ($len -band 0x80) {
        $n = $len -band 0x7F
        if ($n -lt 1 -or $n -gt 4) { throw 'unsupported DER length' }
        $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + [int]$Bytes[$i]; $i++ }
    }
    if ($i + $len -gt $Bytes.Length) { throw 'truncated DER' }
    [pscustomobject]@{ Tag = $tag; Start = $i; Length = $len; Next = ($i + $len) }
}

function Get-SIInvardiaDerInteger {
    param([byte[]]$Bytes, $Tlv)
    if ($Tlv.Tag -ne 0x02) { throw 'expected a DER INTEGER' }
    $start = $Tlv.Start; $len = $Tlv.Length
    while ($len -gt 1 -and $Bytes[$start] -eq 0) { $start++; $len-- }   # the sign byte is not part of the number
    $out = New-Object byte[] $len
    [Array]::Copy($Bytes, $start, $out, 0, $len)
    , $out
}

function ConvertFrom-SIInvardiaPublicKeyPem {
    <#
        PURE. RSAParameters (Modulus, Exponent) from a PEM public key: 'BEGIN PUBLIC KEY' (SubjectPublicKeyInfo) or
        'BEGIN RSA PUBLIC KEY' (PKCS#1). Parsed by hand: Windows PowerShell 5.1 has no ImportFromPem. Throws when unreadable.
    #>
    param([Parameter(Mandatory)][string]$Pem)
    $body = ($Pem -replace '-----[A-Z ]+-----', '' -replace '\s', '')
    $der = [Convert]::FromBase64String($body)
    $top = Read-SIInvardiaDer -Bytes $der -Offset 0
    if ($top.Tag -ne 0x30) { throw 'not a DER SEQUENCE' }
    $first = Read-SIInvardiaDer -Bytes $der -Offset $top.Start
    if ($first.Tag -eq 0x30) {
        # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, RSAPublicKey } }
        $bits = Read-SIInvardiaDer -Bytes $der -Offset $first.Next
        if ($bits.Tag -ne 0x03) { throw 'expected a BIT STRING' }
        $rsaSeq = Read-SIInvardiaDer -Bytes $der -Offset ($bits.Start + 1)
    } else {
        $rsaSeq = $top
    }
    if ($rsaSeq.Tag -ne 0x30) { throw 'expected an RSAPublicKey SEQUENCE' }
    $n = Read-SIInvardiaDer -Bytes $der -Offset $rsaSeq.Start
    $e = Read-SIInvardiaDer -Bytes $der -Offset $n.Next
    $p = New-Object System.Security.Cryptography.RSAParameters
    $p.Modulus = Get-SIInvardiaDerInteger -Bytes $der -Tlv $n
    $p.Exponent = Get-SIInvardiaDerInteger -Bytes $der -Tlv $e
    $p
}

function ConvertFrom-SIInvardiaKeyEntry {
    <#
        PURE. One trusted-key entry -> @{ KeyId; Parameters (RSAParameters); Thumbprint; KeySize; Subject; NotAfter }. Accepts
        { keyId, certificateB64 [, thumbprint -- must match] } (Invardia's public certificate, base64 DER), { keyId, jwk: { kty RSA,
        n, e } } (the shape GET /api/updates/keys returns), { keyId, publicKeyPem } or { keyId, modulus, exponent }.
        Throws with the reason when the entry is unusable.
    #>
    param([Parameter(Mandatory)]$Entry)
    $id = "$($Entry.keyId)".Trim()
    if (-not $id) { throw 'an entry has no keyId' }
    $p = New-Object System.Security.Cryptography.RSAParameters
    $has = { param($o, $n) $o -and $o.PSObject.Properties[$n] -and "$($o.$n)".Trim() }
    $thumb = ''
    if (& $has $Entry 'certificateB64') {
        # Invardia's public CERTIFICATE (base64 DER): its RSA public key, and its thumbprint must be the one recorded with it.
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String(("$($Entry.certificateB64)" -replace '\s', '')))
        $thumb = $cert.Thumbprint.ToUpperInvariant()
        if ((& $has $Entry 'thumbprint') -and ("$($Entry.thumbprint)" -replace '\s', '').ToUpperInvariant() -ne $thumb) { throw ("key '{0}': the certificate's thumbprint {1} is not the one recorded with it" -f $id, $thumb) }
        $rk = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if (-not $rk) { throw ("key '{0}': the certificate carries no RSA public key" -f $id) }
        $p = $rk.ExportParameters($false)
    } elseif (& $has $Entry 'jwk') {
        $j = $Entry.jwk
        if ((& $has $j 'kty') -and "$($j.kty)" -ne 'RSA') { throw ("key '{0}' is not an RSA key" -f $id) }
        $p.Modulus = ConvertFrom-SIInvardiaBase64 "$($j.n)"; $p.Exponent = ConvertFrom-SIInvardiaBase64 "$($j.e)"
    } elseif (& $has $Entry 'publicKeyPem') {
        $p = ConvertFrom-SIInvardiaPublicKeyPem -Pem "$($Entry.publicKeyPem)"
    } elseif ((& $has $Entry 'modulus') -and (& $has $Entry 'exponent')) {
        $p.Modulus = ConvertFrom-SIInvardiaBase64 "$($Entry.modulus)"; $p.Exponent = ConvertFrom-SIInvardiaBase64 "$($Entry.exponent)"
    } else { throw ("key '{0}' has no jwk, publicKeyPem or modulus/exponent" -f $id) }
    if (-not $p.Modulus -or -not $p.Exponent -or $p.Modulus.Length -lt 256) { throw ("key '{0}' is not a usable RSA public key of at least 2048 bits" -f $id) }
    [pscustomobject]@{ KeyId = $id; Parameters = $p; Thumbprint = $thumb; KeySize = ($p.Modulus.Length * 8)
                       Subject = $(if (& $has $Entry 'subject') { "$($Entry.subject)" } else { '' }); NotAfter = $(if (& $has $Entry 'notAfter') { $na = $Entry.notAfter; if ($na -is [datetime]) { $na.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { "$na" } } else { '' }) }
}

function Get-SIInvardiaTrustedKeys {
    <#
        The trusted update-signing keys EMBEDDED in this release (-Path, default SI-InvardiaUpdateKeys.json next to this file).
        Returns @{ Keys; Problems }. An unreadable file or entry is a problem, never a trusted key. Never throws.
    #>
    param([string]$Path = $script:SIInvardiaUpdateKeysFile)
    $keys = New-Object System.Collections.Generic.List[object]
    $problems = New-Object System.Collections.Generic.List[string]
    try {
        if (-not (Test-Path -LiteralPath $Path)) { $problems.Add('the trusted update-signing key list is not in this release') }
        else {
            $doc = [IO.File]::ReadAllText($Path) | ConvertFrom-Json -ErrorAction Stop
            foreach ($e in @($doc.keys | Where-Object { $_ })) {
                try { $keys.Add((ConvertFrom-SIInvardiaKeyEntry -Entry $e)) } catch { $problems.Add($_.Exception.Message) }
            }
        }
    } catch { $problems.Add(('the trusted update-signing key list cannot be read: {0}' -f $_.Exception.Message)) }
    [pscustomobject]@{ Keys = $keys.ToArray(); Problems = $problems.ToArray() }
}

function Test-SIInvardiaManifestSignature {
    <#
        PURE. The signature over the base64-DECODED manifest bytes (RS256, UPDATE-1.2), against the trusted key named by keyId. Then the
        manifest is decoded FROM manifestB64 -- the unsigned 'manifest' object in the answer is never used.
        Returns @{ Ok; Reason; Manifest }. Never throws.
    #>
    param([AllowNull()][string]$ManifestB64, [AllowNull()][string]$Signature, [AllowNull()][string]$KeyId, [AllowNull()][object[]]$TrustedKeys)
    $no = { param($why) [pscustomobject]@{ Ok = $false; Reason = $why; Manifest = $null } }
    $trusted = @($TrustedKeys | Where-Object { $_ })
    if (-not $trusted.Count) { return (& $no 'no trusted update-signing keys are embedded in this release -- every manifest is refused until Invardia''s public keys are added to engine/_shared/SI-InvardiaUpdateKeys.json') }
    if (-not "$ManifestB64".Trim()) { return (& $no 'the answer carries no manifestB64') }
    $sig = ConvertFrom-SIInvardiaBase64 $Signature
    if (-not $sig) { return (& $no 'the answer carries no readable signature') }
    $key = @($trusted | Where-Object { $_.KeyId -ceq "$KeyId".Trim() }) | Select-Object -First 1
    if (-not $key) { return (& $no ("the manifest is signed with key '{0}', which is not a trusted update-signing key" -f "$KeyId".Trim())) }
    $bytes = ConvertFrom-SIInvardiaBase64 $ManifestB64
    if (-not $bytes) { return (& $no 'the answer''s manifestB64 is not base64') }
    $ok = $false
    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $rsa.ImportParameters($key.Parameters)
        # #270: over the base64-DECODED manifest bytes (UPDATE-1.2, the framework verifier's rule, live-proven by PIM). Until
        # 2026-10-04 this verified the base64 TEXT, which would have refused every real Invardia manifest.
        $ok = $rsa.VerifyData([byte[]]$bytes, $sig,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { $ok = $false } finally { if ($rsa) { $rsa.Dispose() } }
    if (-not $ok) { return (& $no ("the manifest's signature does NOT verify against trusted key '{0}' -- it was changed or not signed by Invardia" -f $key.KeyId)) }
    $m = $null
    try { $m = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop } catch { $m = $null }
    if ($null -eq $m) { return (& $no 'the signed manifest is not JSON') }
    [pscustomobject]@{ Ok = $true; Reason = ''; Manifest = $m }
}

function Compare-SIInvardiaVersion {
    <# PURE. -1 / 0 / 1, numeric per part (64-bit: a template pack version carries a yyyyMMddHHmm part). #>
    param([AllowEmptyString()][string]$A, [AllowEmptyString()][string]$B)
    $pa = @("$A".Trim().Split('.') | Where-Object { $_ -ne '' }); $pb = @("$B".Trim().Split('.') | Where-Object { $_ -ne '' })
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = [long]0; $y = [long]0
        if ($i -lt $pa.Count) { [void][long]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][long]::TryParse($pb[$i], [ref]$y) }
        if ($x -ne $y) { if ($x -lt $y) { return -1 } else { return 1 } }
    }
    0
}

function Test-SIInvardiaSameMajor {
    <# PURE. #919 (3): do -Running and -Offered share their MAJOR (the first number)? The MAJOR only -- 3.0.1 and
       3.0.0.202610272235 do, 2.2.460 and 3.0.1 do not. $null when either is not a version. #>
    param([AllowNull()][AllowEmptyString()][string]$Running, [AllowNull()][AllowEmptyString()][string]$Offered)
    $a = [regex]::Match("$Running".Trim(), '^v?(\d+)(\.|$)'); $b = [regex]::Match("$Offered".Trim(), '^v?(\d+)(\.|$)')
    if (-not $a.Success -or -not $b.Success) { return $null }
    ([long]$a.Groups[1].Value -eq [long]$b.Groups[1].Value)
}

function Get-SIInvardiaArchiveName {
    <# PURE. The file a manifest names (archive), when it is a plain file name; else the contract's default name. #>
    param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Version, [AllowNull()][string]$Archive)
    $a = "$Archive".Trim()
    if ($a -and $a -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' -and $a -notmatch '\.\.') { return $a }
    if ($Kind -eq 'templates') { return ('{0}-templates-{1}.json' -f $script:SIInvardiaUpdateProduct, $Version) }
    '{0}-src-{1}.zip' -f $script:SIInvardiaUpdateProduct, $Version
}

function Test-SIInvardiaManifestContent {
    <#
        PURE. A VERIFIED manifest against what was asked and what this install applied. Returns @{ Action; Reason; Sequence;
        ManualStep }: update | current (this sequence is applied already) | hold (manualStep set, not accepted) | refused.
          * product securityinsight and the kind asked for; ring, sequence, version, sha256 and size well formed;
          * -Ring (0-3, UPDATE-1.7): the signed ring must be the one this environment asked for (the update pull always
            passes this environment's ring; -1 is only for reading a manifest's content for display);
          * a sequence LOWER than -AppliedSequence is refused (replay); -1 = nothing applied yet;
          * manualStep set = hold, unless -AcceptManualStepSequence names exactly this sequence.
          * CR3 (#657, framework 12.11e item 2) A PRE-RELEASE WAVE NEVER MOVES AN INSTALL BACK: when the code this install
            applied came from a wave (-AppliedWave, version -AppliedVersion) and the ring's manifest (no wave) has a LOWER
            sequence, it is not refused as a replay: an older or equal version = 'current' (the install keeps the wave's
            version until its ring reaches it); a newer one = 'update'.
    #>
    param([Parameter(Mandatory)]$Manifest, [Parameter(Mandatory)][string]$Kind, [long]$AppliedSequence = -1, [long]$AcceptManualStepSequence = -1,
          # minFromVersion newer than this (when known) = hold (UPDATE-1.2, #270)
          [AllowEmptyString()][string]$RunningVersion = '', [int]$Ring = -1,
          # CR3: the wave of the applied code ('' = none) and its version
          [AllowEmptyString()][string]$AppliedWave = '', [AllowEmptyString()][string]$AppliedVersion = '')
    $out = { param($a, $why, $seq = -1, $ms = '') [pscustomobject]@{ Action = $a; Reason = $why; Sequence = [long]$seq; ManualStep = $ms } }
    $prop = { param($n) if ($Manifest.PSObject.Properties[$n]) { $Manifest.$n } else { $null } }
    if ("$(& $prop 'product')" -ne $script:SIInvardiaUpdateProduct) { return (& $out 'refused' ("the manifest is for product '{0}', not {1}" -f (& $prop 'product'), $script:SIInvardiaUpdateProduct)) }
    if ("$(& $prop 'kind')" -ne $Kind) { return (& $out 'refused' ("the manifest is for kind '{0}', not '{1}'" -f (& $prop 'kind'), $Kind)) }
    $seq = [long]-1
    if (-not [long]::TryParse("$(& $prop 'sequence')", [ref]$seq) -or $seq -lt 0) { return (& $out 'refused' 'the manifest has no usable sequence') }
    # (PowerShell names are case-blind: the manifest's ring is $mRing, the ring asked for is -Ring)
    $mRing = 0
    if (-not [int]::TryParse("$(& $prop 'ring')", [ref]$mRing) -or $mRing -lt 0) { return (& $out 'refused' $(if ($Ring -ge 0) { "the manifest names no ring (this environment asked for ring $Ring)" } else { 'the manifest has no usable ring' })) }
    if ($Ring -ge 0 -and $mRing -ne $Ring) { return (& $out 'refused' ("the manifest is for ring {0}, not ring {1} that this environment asked for" -f $mRing, $Ring)) }
    $ver = "$(& $prop 'version')".Trim()
    if ($ver -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { return (& $out 'refused' ("the manifest names '{0}', which is not a version" -f $ver)) }
    if ("$(& $prop 'sha256')".Trim() -notmatch '^[0-9a-fA-F]{64}$') { return (& $out 'refused' 'the manifest has no usable SHA-256') }
    $size = [long]0
    if (-not [long]::TryParse("$(& $prop 'size')", [ref]$size) -or $size -le 0) { return (& $out 'refused' 'the manifest has no usable size') }
    $waveOk = $false
    if ($AppliedSequence -ge 0 -and $seq -lt $AppliedSequence) {
        # CR3: after a pre-release wave the ring's own manifest may carry a lower sequence -- never a replay, never a step back
        $mWave = "$(& $prop 'wave')".Trim()
        if ("$AppliedWave".Trim() -and -not $mWave -and "$AppliedVersion".Trim()) {
            if ((Compare-SIInvardiaVersion $ver $AppliedVersion) -le 0) {
                $why = if ((Compare-SIInvardiaVersion $ver $AppliedVersion) -eq 0) { "ring {0} now has {1} {2}, the version this install took early in the pre-release wave '{3}' -- the wave has ended for this install" -f $mRing, $Kind, $ver, $AppliedWave }
                       else { "this install keeps {0} {1} from the pre-release wave '{2}': ring {3} names {4} (sequence {5}), and an install is never moved back -- it follows its ring again once the ring reaches {1}" -f $Kind, $AppliedVersion, $AppliedWave, $mRing, $ver, $seq }
                return (& $out 'current' $why $seq)
            }
            $waveOk = $true
        }
        if (-not $waveOk) { return (& $out 'refused' ("the manifest's sequence {0} is LOWER than the {1} this install applied -- an old manifest is never applied again" -f $seq, $AppliedSequence) $seq) }
    }
    $ms = "$(& $prop 'manualStep')".Trim()
    if ($ms -and $AcceptManualStepSequence -ne $seq) {
        return (& $out 'hold' ("HELD: {0} {1} (sequence {2}) needs a manual step first: {3}" -f $Kind, $ver, $seq, $ms) $seq $ms)
    }
    if ($AppliedSequence -ge 0 -and $seq -eq $AppliedSequence) { return (& $out 'current' ("{0} {1} (sequence {2}) is applied already" -f $Kind, $ver, $seq) $seq $ms) }
    $mf = "$(& $prop 'minFromVersion')".Trim()
    if ($mf -and "$RunningVersion".Trim() -and (Compare-SIInvardiaVersion "$RunningVersion" $mf) -lt 0) {
        return (& $out 'hold' ("HELD: {0} {1} (sequence {2}) needs at least {3} -- this install runs {4}" -f $Kind, $ver, $seq, $mf, "$RunningVersion".Trim()) $seq $ms)
    }
    # #919 (3) / (4): a MAJOR version is never an update (v3 is installed side by side): code of another major than the one this
    # install runs is refused (after the holds: a minFromVersion hold says it first) -- the MAJOR only is compared (3.0.1 after 3.0.0.<build> is an update; 2.2 -> 3.x never is)
    if ($Kind -eq 'code' -and "$RunningVersion".Trim()) {
        # an OLDER major (the vendor's roll-back) goes on to the forward-only rules below; a NEWER major is never an update
        $mj = Test-SIInvardiaSameMajor -Running "$RunningVersion" -Offered $ver
        if ($mj -eq $false -and [long]([regex]::Match($ver, '^\d+').Value) -gt [long]([regex]::Match("$RunningVersion".Trim(), '\d+').Value)) { return (& $out 'refused' ("{0} {1} is another major version than the {2} this install runs -- a major version is never an update (installed side by side)" -f $Kind, $ver, "$RunningVersion".Trim()) $seq) }
    }
    & $out 'update' ("ring {0} has {1} {2} (sequence {3})" -f $mRing, $Kind, $ver, $seq) $seq $ms
}

function Get-SIInvardiaFileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::OpenRead($Path)
    try { $b = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
    -join ($b | ForEach-Object { $_.ToString('x2') })
}

# =====================================================================================================================
#  HTTP (the default seams)
# =====================================================================================================================
function Get-SIInvardiaRetryAfter {
    <# Seconds from a Retry-After header (delta seconds or an HTTP date), 0 when absent. #>
    param($Response)
    $ra = 0
    try {
        if ($Response -is [System.Net.WebResponse]) {
            $h = [string]$Response.Headers['Retry-After']
            if (-not [int]::TryParse($h, [ref]$ra)) { $d = [datetime]::MinValue; if ([datetime]::TryParse($h, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { $ra = [int][Math]::Max(0, ($d - [datetime]::UtcNow).TotalSeconds) } }
        } elseif ($Response.Headers.RetryAfter) {
            if ($Response.Headers.RetryAfter.Delta) { $ra = [int]$Response.Headers.RetryAfter.Delta.Value.TotalSeconds }
            elseif ($Response.Headers.RetryAfter.Date) { $ra = [int][Math]::Max(0, ($Response.Headers.RetryAfter.Date.Value.UtcDateTime - [datetime]::UtcNow).TotalSeconds) }
        }
    } catch { }
    $ra
}

function Invoke-SIInvardiaUpdateHttp {
    <#
        One POST with a JSON body and, when given, the install key in its header (-KeyHeader; the key claim sends none).
        Returns @{ Status (0 = no answer); Body; RetryAfter; Error }; never throws. Headers are not part of exception text,
        and the error text is scrubbed anyway.
    #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$Body, [AllowEmptyString()][string]$InstallKey,
          [string]$KeyHeader = $script:SIInvardiaUpdateKeyHeader, [int]$TimeoutSec = 60,
          # Invardia S16: the install's lasting id -> X-Invardia-Install-Id, only when it is a GUID (the manifest pull passes
          # it; the key claim never does); '' = no header
          [AllowNull()][AllowEmptyString()][string]$InstallId = '')
    $h = @{ Accept = 'application/json' }
    if ($InstallKey) { $h[$KeyHeader] = $InstallKey }
    $h = Add-SIInvardiaInstallIdHeader -Headers $h -InstallId $InstallId
    try {
        $r = Invoke-WebRequest -Method Post -Uri $Uri -Headers $h -Body $Body -ContentType 'application/json' -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        $content = $r.Content; if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Body = [string]$content; RetryAfter = 0; Error = '' }
    } catch {
        $resp = $null; try { $resp = $_.Exception.Response } catch { }
        if (-not $resp) { return [pscustomobject]@{ Status = 0; Body = ''; RetryAfter = 0; Error = (Hide-SIInvardiaSecret "$($_.Exception.Message)" -Secret $InstallKey) } }
        $code = 0; try { $code = [int]$resp.StatusCode } catch { }
        $text = ''
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $text = [string]$_.ErrorDetails.Message }
        elseif ($resp -is [System.Net.WebResponse]) { try { $sr = New-Object System.IO.StreamReader($resp.GetResponseStream()); $text = $sr.ReadToEnd(); $sr.Close() } catch { } }
        return [pscustomobject]@{ Status = $code; Body = (Hide-SIInvardiaSecret $text -Secret $InstallKey); RetryAfter = (Get-SIInvardiaRetryAfter $resp); Error = "HTTP $code" }
    }
}

function Invoke-SIInvardiaUpdateDownload {
    <# GET the download URL to a file. Returns @{ Status; Error }; never throws, and the URL's token is never in Error. #>
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$OutFile, [int]$TimeoutSec = 600)
    try {
        $r = Invoke-WebRequest -Method Get -Uri $Uri -OutFile $OutFile -PassThru -UseBasicParsing -TimeoutSec $TimeoutSec -ErrorAction Stop
        return [pscustomobject]@{ Status = [int]$r.StatusCode; Error = '' }
    } catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        return [pscustomobject]@{ Status = $code; Error = (Hide-SIInvardiaSecret "$($_.Exception.Message)" -Secret $Uri) }
    }
}

# =====================================================================================================================
#  The pull
# =====================================================================================================================
function Get-SIInvardiaManifestWave {
    <# PURE. CR3 (#657): the signed manifest's "wave" (a name; an object's name) -- trimmed, at most 60 safe characters; '' = none. #>
    param([AllowNull()]$Manifest)
    if ($null -eq $Manifest -or -not $Manifest.PSObject.Properties['wave'] -or $null -eq $Manifest.wave) { return '' }
    $w = $Manifest.wave
    if (-not ($w -is [string]) -and $w.PSObject.Properties['name']) { $w = $w.name }
    $v = ("$w" -replace '[\r\n\t]+', ' ').Trim()
    if ($v -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}$') { return '' }
    $v
}

function New-SIInvardiaManifestResult {
    param([string]$Kind, [string]$Action, [string]$Reason, [int]$StatusCode = 0, [int]$RetryAfter = 0, $Manifest = $null, [string]$KeyId = '',
          [string]$DownloadUrl = '', [long]$Sequence = -1, [string]$ManualStep = '', [string[]]$Fields = @(),
          # the SIGNED manifest as it came (base64 + signature): kept with a staged template pack, so the install job checks it again
          [string]$ManifestB64 = '', [string]$Signature = '')
    [pscustomobject]@{
        Kind = $Kind; Action = $Action; Ok = ($Action -in @('update', 'current')); Reason = $Reason; StatusCode = $StatusCode; RetryAfter = $RetryAfter
        Manifest = $Manifest; KeyId = $KeyId; Sequence = $Sequence; ManualStep = $ManualStep; Fields = $Fields
        ManifestB64 = $ManifestB64; Signature = $Signature
        Version = $(if ($Manifest -and $Manifest.PSObject.Properties['version']) { "$($Manifest.version)" } else { '' })
        Ring = $(if ($Manifest -and $Manifest.PSObject.Properties['ring']) { $Manifest.ring } else { $null })
        # CR3 (#657): the pre-release wave Invardia served this manifest for ('' = the ring's own release)
        Wave = (Get-SIInvardiaManifestWave $Manifest)
        # the 15-minute download link: used by Save-SIInvardiaUpdateFile, never printed (Hide-SIInvardiaSecret drops its token)
        DownloadUrl = $DownloadUrl
    }
}

function Request-SIInvardiaManifest {
    <#
        Ask Invardia for this install's manifest of -Kind, verify it, and decide. NEVER throws.
        The install key and the licence text come from -InstallKey / -Licence, else from the install's Key Vault through
        -Seams.ReadSecret (SI-Invardia-InstallKey, SI-License).
        -Seams (hashtable of scriptblocks, all optional except ReadSecret when the key / licence are not given):
          Http        { param($Uri, $Body, $InstallKey, $KeyHeader, $InstallId) } -> @{ Status; Body; RetryAfter; Error }   (default Invoke-SIInvardiaUpdateHttp)
          ReadSecret  { param($Name) } -> text or $null
        -InstallId (Invardia S16): the install's LASTING id; not given = read (only) from SI-InstallId through ReadSecret.
        A GUID goes as X-Invardia-Install-Id; none / not a GUID / unreadable = no header (the pull itself is unchanged).
          TrustedKeys { } -> @(@{ KeyId; Parameters })     (default: the embedded SI-InvardiaUpdateKeys.json)
        Returns New-SIInvardiaManifestResult. Action:
          update | current | hold | none (204) | refused | unauthorized (401) | forbidden (403) | notfound (404) |
          invalid (422) | waiting (429) | network (no answer / 5xx) | off (no install key, licence or ring) | error
        -Ring: this environment's OWN update ring (0-3; UPDATE-1.7). Sent with the pull; the signed manifest must name it.
        None (or not a ring) = no pull at all, Action 'off', and the reason says so.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind,
        [System.Collections.IDictionary]$Seams = @{},
        [string]$BaseUrl,
        [long]$AppliedSequence = -1,
        [long]$AcceptManualStepSequence = -1,
        [string]$InstallKey,
        [string]$Licence,
        # The updates endpoint + header the key claim returned (Get-SIInvardiaUpdatesEndpoint); empty = the frozen defaults.
        [string]$ManifestUri,
        [string]$KeyHeader,
        # The version this install runs (kind code): a manifest whose minFromVersion is newer HOLDS (UPDATE-1.2).
        [AllowEmptyString()][string]$RunningVersion = '',
        # UPDATE-1.7: this environment's own ring (SI_UPDATER_RING / cfg.InstallState 'Ring'); none = no pull
        [AllowNull()]$Ring = $null,
        [int]$TimeoutSec = 60,
        # CR3 (#657): the wave of the code this install applied ('' = none) and its version -- never moved back after a wave
        [AllowEmptyString()][string]$AppliedWave = '',
        [AllowEmptyString()][string]$AppliedVersion = '',
        # Invardia S16: the install's lasting id (SI-InstallId); not given = read through -Seams.ReadSecret
        [AllowNull()][AllowEmptyString()][string]$InstallId
    )
    $key = $InstallKey
    try {
        $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
        if (-not "$KeyHeader".Trim()) { $KeyHeader = $script:SIInvardiaUpdateKeyHeader }
        if ("$ManifestUri".Trim() -and "$ManifestUri".Trim() -notmatch '^https://[^/\s]+/') { $ManifestUri = '' }
        if (-not "$ManifestUri".Trim()) { $ManifestUri = Get-SIInvardiaManifestUri -BaseUrl $base }
        if (-not "$key".Trim() -and $Seams['ReadSecret']) { try { $key = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey) } catch { $key = '' } }
        $key = "$key".Trim()
        if (-not $key) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason ("no Invardia install key in the install's Key Vault ({0}) -- the updater claims one on its next run" -f $script:SIInvardiaUpdateSecretKey)) }
        if (-not (Test-SIInvardiaInstallKeyFormat $key)) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason ("the Invardia install key in {0} is not an install key (it must start with inv-)" -f $script:SIInvardiaUpdateSecretKey)) }
        $lic = $Licence
        if (-not "$lic".Trim() -and $Seams['ReadSecret']) { try { $lic = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretLicence) } catch { $lic = '' } }
        if (-not "$lic".Trim()) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason 'no SecurityInsight Pro licence is installed -- updates from Invardia need one') }
        $ringN = ConvertTo-SIInvardiaPullRing $Ring
        if ($ringN -lt 0) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'off' -Reason (Get-SIInvardiaNoRingReason -Ring $Ring)) }

        # Trusted keys BEFORE the network: an empty list refuses everything, so there is nothing to ask for.
        $trusted = if ($Seams['TrustedKeys']) { @(& $Seams.TrustedKeys) } else { $tk = Get-SIInvardiaTrustedKeys; @($tk.Keys) }
        if (-not @($trusted | Where-Object { $_ }).Count) {
            return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -Reason 'no trusted update-signing keys are embedded in this release -- every manifest is refused until Invardia''s public keys are added to engine/_shared/SI-InvardiaUpdateKeys.json')
        }

        # Invardia S16: the lasting id, READ ONLY (never created by the pull); '' = no header
        $iid = if ($PSBoundParameters.ContainsKey('InstallId')) { ConvertTo-SIInvardiaInstallId $InstallId } elseif ($Seams['ReadSecret'] -or $Seams['ReadVersions']) { Get-SIInvardiaInstallId -ReadSecret $Seams['ReadSecret'] -ReadVersions $Seams['ReadVersions'] } else { '' }
        $http = if ($Seams['Http']) { $Seams['Http'] } else { { param($u, $b, $k, $hn, $id) Invoke-SIInvardiaUpdateHttp -Uri $u -Body $b -InstallKey $k -KeyHeader $hn -InstallId $id -TimeoutSec $TimeoutSec } }
        $r = & $http $ManifestUri (New-SIInvardiaManifestBody -Kind $Kind -Licence ([string]$lic) -Ring $ringN) $key $KeyHeader $iid
        $code = [int]$r.Status
        # Parsed RAW (downloadUrl carries its token); every text taken from it for a reason is scrubbed in $why.
        $body = [string]$r.Body
        $j = $null; if ($body.Trim()) { try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
        $why = { $t = ''; if ($j) { foreach ($n in 'reason', 'error', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim()) { $t = "$($j.$n)".Trim(); break } } }; if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; Hide-SIInvardiaSecret $t -Secret $key }
        switch ($code) {
            200 { break }
            204 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'none' -StatusCode 204 -Reason ("nothing is released for ring {0} ({1})" -f $ringN, $Kind)) }
            401 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'unauthorized' -StatusCode 401 -Reason ("Invardia did not accept the install key{0} -- check {1} in the install's Key Vault, or ask Invardia support for a new one" -f $(if (& $why) { " ($(& $why))" } else { '' }), $script:SIInvardiaUpdateSecretKey)) }
            403 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'forbidden' -StatusCode 403 -Reason ("Invardia refused the licence: {0}" -f $(if (& $why) { & $why } else { 'no reason given' }))) }
            404 { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'notfound' -StatusCode 404 -Reason 'Invardia does not know this product (404)') }
            422 {
                $fields = @(); try { $fields = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['field']) { "$($_.field)" } elseif ($_.PSObject.Properties['name']) { "$($_.name)" } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
                # UPDATE-1.7: Invardia answers 422 (fields ['ring']) to a pull without a usable ring
                $ringHint = if (-not $fields.Count -or @($fields | Where-Object { "$_" -match '(?i)\bring\b' }).Count) { " -- the pull must carry this environment's update ring (0-3); it sent ring $ringN" } else { '' }
                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'invalid' -StatusCode 422 -Fields $fields -Reason ("Invardia refused the request as invalid; fields: {0}{1}" -f $(if ($fields.Count) { $fields -join ', ' } else { 'none named' }), $ringHint))
            }
            429 {
                $ra = [int]$r.RetryAfter; if ($ra -le 0) { $ra = 3600 }
                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'waiting' -StatusCode 429 -RetryAfter $ra -Reason ("Invardia asked to slow down -- not asked again for {0} s" -f $ra))
            }
            0   { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'network' -Reason ("Invardia could not be reached: {0}" -f (Hide-SIInvardiaSecret ([string]$r.Error) -Secret $key))) }
            default {
                if ($code -ge 500) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'network' -StatusCode $code -Reason ("Invardia answered {0} -- tried again on a later run" -f $code)) }
                return (New-SIInvardiaManifestResult -Kind $Kind -Action 'error' -StatusCode $code -Reason ("Invardia answered {0}{1}" -f $code, $(if (& $why) { ": $(& $why)" } else { '' })))
            }
        }
        if (-not $j) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -Reason 'the answer is not JSON') }
        $prop = { param($n) if ($j.PSObject.Properties[$n]) { [string]$j.$n } else { '' } }
        $sig = Test-SIInvardiaManifestSignature -ManifestB64 (& $prop 'manifestB64') -Signature (& $prop 'signature') -KeyId (& $prop 'keyId') -TrustedKeys $trusted
        if (-not $sig.Ok) { return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -KeyId (& $prop 'keyId') -Reason $sig.Reason) }
        $chk = Test-SIInvardiaManifestContent -Manifest $sig.Manifest -Kind $Kind -AppliedSequence $AppliedSequence -AcceptManualStepSequence $AcceptManualStepSequence `
                    -RunningVersion $(if ($Kind -eq 'code') { $RunningVersion } else { '' }) -Ring $ringN -AppliedWave $AppliedWave -AppliedVersion $AppliedVersion
        $dl = & $prop 'downloadUrl'
        if ($chk.Action -eq 'update' -and $dl -notmatch '^https://[^/\s]+/') {
            return (New-SIInvardiaManifestResult -Kind $Kind -Action 'refused' -StatusCode 200 -Manifest $sig.Manifest -KeyId (& $prop 'keyId') -Sequence $chk.Sequence -Reason 'the answer carries no https download link')
        }
        New-SIInvardiaManifestResult -Kind $Kind -Action $chk.Action -StatusCode 200 -Manifest $sig.Manifest -KeyId (& $prop 'keyId') -DownloadUrl $dl `
            -Sequence $chk.Sequence -ManualStep $chk.ManualStep -Reason (Hide-SIInvardiaSecret $chk.Reason -Secret $key) `
            -ManifestB64 (& $prop 'manifestB64') -Signature (& $prop 'signature')
    } catch {
        New-SIInvardiaManifestResult -Kind $Kind -Action 'error' -Reason (Hide-SIInvardiaSecret ("the update check did not complete: {0}" -f $_.Exception.Message) -Secret $key)
    } finally { $key = $null }
}

function Save-SIInvardiaUpdateFile {
    <#
        Download what a VERIFIED manifest names into -OutDir and check it: size, then SHA-256, both from the signed manifest.
        A file that does not match is deleted. Returns @{ Ok; Path; Reason; Sha256; Size }. NEVER throws.
        -Seams.Download { param($Uri, $OutFile) } -> @{ Status; Error }  (default Invoke-SIInvardiaUpdateDownload)
    #>
    param([Parameter(Mandatory)]$Result, [Parameter(Mandatory)][string]$OutDir, [System.Collections.IDictionary]$Seams = @{})
    $fail = { param($why) [pscustomobject]@{ Ok = $false; Path = ''; Reason = $why; Sha256 = ''; Size = 0 } }
    $path = ''
    try {
        # 'current' too: the release this install runs can be fetched again (the template gate checks a pack with it).
        if (-not $Result -or $Result.Action -notin @('update', 'current') -or -not $Result.Manifest) { return (& $fail 'there is no verified manifest to download') }
        $m = $Result.Manifest
        if ("$($Result.DownloadUrl)" -notmatch '^https://[^/\s]+/') { return (& $fail 'the manifest came without an https download link') }
        $name = Get-SIInvardiaArchiveName -Kind $Result.Kind -Version "$($m.version)" -Archive $(if ($m.PSObject.Properties['archive']) { "$($m.archive)" } else { '' })
        if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
        $path = [IO.Path]::Combine($OutDir, $name)
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
        $dl = if ($Seams['Download']) { $Seams['Download'] } else { { param($u, $f) Invoke-SIInvardiaUpdateDownload -Uri $u -OutFile $f } }
        $r = & $dl ([string]$Result.DownloadUrl) $path
        $code = [int]$r.Status
        if ($code -ne 200 -or -not (Test-Path -LiteralPath $path)) {
            $why = if ($code -eq 401) { 'the download link expired (401) -- the next run asks for a new one' } elseif ($code -eq 0) { "the download did not complete: $(Hide-SIInvardiaSecret ([string]$r.Error) -Secret $Result.DownloadUrl)" } else { "the download answered $code" }
            if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
            return (& $fail $why)
        }
        $size = (Get-Item -LiteralPath $path).Length
        if ([long]$size -ne [long]$m.size) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            return (& $fail ("{0} is {1} bytes, the signed manifest says {2} -- refused" -f $name, $size, $m.size))
        }
        $sha = Get-SIInvardiaFileSha256 -Path $path
        if ($sha -ne "$($m.sha256)".Trim().ToLowerInvariant()) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
            return (& $fail ("{0} does NOT match the signed manifest's SHA-256 (file {1}, manifest {2}) -- refused" -f $name, $sha.Substring(0, 12), "$($m.sha256)".Substring(0, 12).ToLowerInvariant()))
        }
        [pscustomobject]@{ Ok = $true; Path = $path; Reason = ("{0} verified (SHA-256 {1}, {2} bytes)" -f $name, $sha, $size); Sha256 = $sha; Size = [long]$size }
    } catch {
        if ($path -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue }
        & $fail (Hide-SIInvardiaSecret ("the download did not complete: {0}" -f $_.Exception.Message) -Secret $Result.DownloadUrl)
    }
}

function Get-SIInvardiaUpdate {
    <#
        The whole pull for one kind: the manifest (Request-SIInvardiaManifest), and when it says 'update' the verified file
        (Save-SIInvardiaUpdateFile). Returns the manifest result with File (the verified local path, '' when none) and,
        when the download failed, Action 'refused' and its reason. NEVER throws.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind,
        [Parameter(Mandatory)][string]$OutDir,
        [System.Collections.IDictionary]$Seams = @{},
        [string]$BaseUrl, [long]$AppliedSequence = -1, [long]$AcceptManualStepSequence = -1, [string]$InstallKey, [string]$Licence,
        [string]$ManifestUri, [string]$KeyHeader,
        # UPDATE-1.7: this environment's own ring (0-3); none = no pull (Action 'off')
        [AllowNull()]$Ring = $null,
        # Invardia S16: the install's lasting id; not given = Request-SIInvardiaManifest reads SI-InstallId through -Seams
        [AllowNull()][AllowEmptyString()][string]$InstallId
    )
    $idArg = @{}; if ($PSBoundParameters.ContainsKey('InstallId')) { $idArg.InstallId = $InstallId }
    $r = Request-SIInvardiaManifest -Kind $Kind -Seams $Seams -BaseUrl $BaseUrl -AppliedSequence $AppliedSequence -AcceptManualStepSequence $AcceptManualStepSequence `
            -InstallKey $InstallKey -Licence $Licence -ManifestUri $ManifestUri -KeyHeader $KeyHeader -Ring $Ring @idArg
    $r | Add-Member -NotePropertyName File -NotePropertyValue '' -Force
    if ($r.Action -ne 'update') { return $r }
    $f = Save-SIInvardiaUpdateFile -Result $r -OutDir $OutDir -Seams $Seams
    if (-not $f.Ok) { $r.Action = 'refused'; $r.Reason = $f.Reason; $r | Add-Member -NotePropertyName Ok -NotePropertyValue $false -Force; return $r }
    $r.File = $f.Path
    $r
}

# =====================================================================================================================
#  The install's update state (Key Vault SI-Update-State; mirrored into the Pro database for the web app)
# =====================================================================================================================
function New-SIInvardiaKindState {
    # appliedWave / lastWave (CR3 #657): the pre-release wave of the applied / last manifest ('' = the ring's own release)
    [ordered]@{ appliedSequence = -1; appliedVersion = ''; appliedRing = $null; appliedUtc = $null; appliedWave = ''
                lastSequence = -1; lastVersion = ''; lastRing = $null; lastAction = ''; lastReason = ''; lastCheckUtc = $null; lastWave = ''
                hold = ''; nextTryUtc = $null
                # (templates) the fingerprint of a release's template change that waits for an Admin while its code rolled ('' = none)
                pendingFingerprint = '' }
}

function ConvertTo-SIInvardiaUtc {
    param([AllowNull()]$Value)
    if ($null -eq $Value -or -not "$Value".Trim()) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function ConvertFrom-SIInvardiaUpdateState {
    <# PURE. The stored state (JSON) as an ordered hashtable with every field; an unreadable state starts empty. #>
    param([AllowNull()][string]$Json)
    # channel (PRO-COMMUNITY-SAME): the manifest address the applied code came from -- 'invardia' (the install route) or
    # 'community' (the anonymous Community route); sequences are counted per address
    $s = [ordered]@{ source = ''; channel = ''; lastCheckUtc = $null; lastError = ''; updatesEndpoint = ''; updatesHeader = ''
                     claimResult = ''; claimReason = ''; claimUtc = $null
                     claimAgainResult = ''; claimAgainBy = ''; claimAgainUtc = $null
                     # 2026-10-23: the update waits for a pipeline run (the run gate) -- since when, why, run | store
                     waitsSinceUtc = $null; waitsReason = ''; waitsKind = ''
                     code = (New-SIInvardiaKindState); templates = (New-SIInvardiaKindState) }
    if ([string]::IsNullOrWhiteSpace($Json)) { return $s }
    try { $o = $Json | ConvertFrom-Json -ErrorAction Stop } catch { return $s }
    foreach ($k in 'source', 'channel', 'lastError', 'updatesEndpoint', 'updatesHeader', 'claimResult', 'claimReason', 'claimAgainResult', 'claimAgainBy', 'waitsReason', 'waitsKind') { if ($o.PSObject.Properties[$k] -and $null -ne $o.$k) { $s[$k] = "$($o.$k)" } }
    foreach ($k in 'lastCheckUtc', 'claimUtc', 'claimAgainUtc', 'waitsSinceUtc') { if ($o.PSObject.Properties[$k]) { $s[$k] = ConvertTo-SIInvardiaUtc $o.$k } }
    foreach ($kind in $script:SIInvardiaUpdateKinds) {
        if (-not $o.PSObject.Properties[$kind] -or $null -eq $o.$kind) { continue }
        $src = $o.$kind; $dst = $s[$kind]
        foreach ($f in @($dst.Keys)) {
            if (-not $src.PSObject.Properties[$f]) { continue }
            $v = $src.$f
            if ($f -like '*Utc') { $dst[$f] = ConvertTo-SIInvardiaUtc $v }
            elseif ($f -like '*Sequence') { $n = [long]-1; if ([long]::TryParse("$v", [ref]$n)) { $dst[$f] = $n } }
            elseif ($f -like '*Ring') { $n = 0; if ($null -ne $v -and [int]::TryParse("$v", [ref]$n)) { $dst[$f] = $n } }
            else { $dst[$f] = $(if ($null -eq $v) { '' } else { "$v" }) }
        }
    }
    $s
}

function ConvertTo-SIInvardiaUpdateStateJson {
    <#
        PURE. The state as JSON. -Compact = what the Pro database row holds (cfg.InstallState.Value is NVARCHAR(400)): per
        kind the last manifest (version, sequence, ring), the result, the applied sequence and any HOLD, shortened to fit.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [switch]$Compact)
    $iso = { param($d) if ($d) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
    if (-not $Compact) {
        $o = [ordered]@{ source = $State.source; channel = $(if ($State.Contains('channel')) { [string]$State.channel } else { '' }); lastCheckUtc = (& $iso $State.lastCheckUtc); lastError = $State.lastError
                         updatesEndpoint = $State.updatesEndpoint; updatesHeader = $State.updatesHeader
                         claimResult = $State.claimResult; claimReason = $State.claimReason; claimUtc = (& $iso $State.claimUtc)
                         claimAgainResult = $State.claimAgainResult; claimAgainBy = $State.claimAgainBy; claimAgainUtc = (& $iso $State.claimAgainUtc) }
        if ($State.Contains('waitsSinceUtc') -and $State.waitsSinceUtc) { $o['waitsSinceUtc'] = (& $iso $State.waitsSinceUtc); $o['waitsReason'] = $State.waitsReason; $o['waitsKind'] = $State.waitsKind }
        foreach ($kind in $script:SIInvardiaUpdateKinds) {
            $k = [ordered]@{}
            foreach ($f in $State[$kind].Keys) { $v = $State[$kind][$f]; if ($f -like '*Utc') { $v = & $iso $v }; $k[$f] = $v }
            $o[$kind] = $k
        }
        return ($o | ConvertTo-Json -Compress -Depth 4)
    }
    foreach ($max in 90, 50, 20, 0) {
        $short = { param($t) $t = "$t"; if ($t.Length -gt $max) { if ($max -le 3) { '' } else { $t.Substring(0, $max - 3) + '...' } } else { $t } }
        $c = [ordered]@{ source = $State.source; lastCheckUtc = (& $iso $State.lastCheckUtc) }
        foreach ($kind in $script:SIInvardiaUpdateKinds) {
            $k = $State[$kind]
            if (-not $k.lastAction -and $k.appliedSequence -lt 0) { continue }
            $c[$kind] = [ordered]@{ version = $k.lastVersion; sequence = $k.lastSequence; ring = $k.lastRing; action = $k.lastAction; applied = $k.appliedSequence; hold = (& $short $k.hold) }
            # CR3 (#657): the pre-release wave of the code the jobs run -- the web app's header and the heartbeat read it here
            if ("$($k.appliedWave)".Trim()) { $c[$kind]['wave'] = [ordered]@{ name = "$($k.appliedWave)"; version = $k.appliedVersion; ring = $k.appliedRing } }
        }
        if ($State.claimResult -and $State.claimResult -notin @('claimed', 'present', 'bundle')) { $c['claim'] = $State.claimResult }
        # the last 'claim the install key again' (an Admin on the Settings page, or SI_UPDATER_CLAIM_AGAIN) and its outcome
        if ($State.claimAgainResult) { $c['claimAgain'] = $State.claimAgainResult; $c['claimAgainUtc'] = (& $iso $State.claimAgainUtc) }
        $c['error'] = (& $short $State.lastError)
        # 2026-10-23: the update waits for a pipeline run -- the heartbeat warns when it has waited more than 24 hours
        if ($State.Contains('waitsSinceUtc') -and $State.waitsSinceUtc) { $c['waits'] = [ordered]@{ since = (& $iso $State.waitsSinceUtc); kind = $State.waitsKind; why = (& $short $State.waitsReason) } }
        $json = $c | ConvertTo-Json -Compress -Depth 4
        if ($json.Length -le 400) { return $json }
    }
    $json
}

function Set-SIInvardiaUpdateCheck {
    <# Record one manifest check of -Kind in the state: the last manifest, the result, a HOLD and when to try again (429). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)][datetime]$NowUtc, [string]$Hold)
    $k = $State[$Result.Kind]
    $k.lastCheckUtc = $NowUtc; $State.lastCheckUtc = $NowUtc
    $k.lastAction = [string]$Result.Action; $k.lastReason = [string]$Result.Reason
    if ($Result.Manifest) { $k.lastVersion = [string]$Result.Version; $k.lastSequence = [long]$Result.Sequence; $k.lastRing = $(if ($null -ne $Result.Ring) { [int]$Result.Ring } else { $null }); $k.lastWave = $(if ($Result.PSObject.Properties['Wave']) { [string]$Result.Wave } else { '' }) }
    $k.hold = $(if ($Hold) { $Hold } elseif ($Result.Action -eq 'hold') { [string]$Result.Reason } else { '' })
    $k.nextTryUtc = $(if ($Result.Action -eq 'waiting' -and $Result.RetryAfter -gt 0) { $NowUtc.AddSeconds([int]$Result.RetryAfter) } else { $null })
    if ($Result.Action -in @('refused', 'unauthorized', 'forbidden', 'notfound', 'invalid', 'network', 'error', 'off')) { $State.lastError = ('{0}: {1}' -f $Result.Kind, $Result.Reason) }
}

function Set-SIInvardiaUpdateApplied {
    <#
        Record that -Kind's manifest is APPLIED (the code rolled / the templates published, or already in force), with the
        pre-release wave it was served for (CR3 #657: appliedWave; '' = the ring's own release). An older sequence is never
        recorded -- EXCEPT the end of a wave: the ring's own manifest (no wave) naming the wave's version or a later one
        under a lower sequence puts the install back on its ring's sequence (the wave is over for it).
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State, [Parameter(Mandatory)]$Result, [Parameter(Mandatory)][datetime]$NowUtc)
    $k = $State[$Result.Kind]
    $wave = if ($Result.PSObject.Properties['Wave']) { "$($Result.Wave)".Trim() } else { '' }
    if ([long]$Result.Sequence -lt [long]$k.appliedSequence) {
        $waveEnd = ("$($k.appliedWave)".Trim() -and -not $wave -and "$($k.appliedVersion)".Trim() -and "$($Result.Version)".Trim() -and
                    (Compare-SIInvardiaVersion ([string]$Result.Version) ([string]$k.appliedVersion)) -ge 0)
        if (-not $waveEnd) { return }
    }
    $k.appliedSequence = [long]$Result.Sequence; $k.appliedVersion = [string]$Result.Version
    $k.appliedRing = $(if ($null -ne $Result.Ring) { [int]$Result.Ring } else { $null }); $k.appliedUtc = $NowUtc; $k.hold = ''
    $k.appliedWave = $wave
}

function Get-SIInvardiaUpdateStatus {
    <#
        PURE. The update state for the health check and the admin: @{ Source; LastCheckUtc; Code; Templates; Holds; Refused;
        LastError; Summary }. -Json is the stored state (SI-Update-State).
    #>
    param([AllowNull()][string]$Json)
    $s = ConvertFrom-SIInvardiaUpdateState -Json $Json
    $when = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { 'never' } }
    $line = {
        param($kind)
        $k = $s[$kind]
        if (-not $k.lastAction) { return ('{0}: not checked yet' -f $kind) }
        $m = if ($k.lastVersion) { '{0} (sequence {1}, ring {2})' -f $k.lastVersion, $k.lastSequence, $k.lastRing } else { 'no manifest' }
        '{0}: {1} -- {2}{3}' -f $kind, $m, $k.lastAction, $(if ($k.appliedSequence -ge 0) { "; applied sequence $($k.appliedSequence) ($($k.appliedVersion))" } else { '' })
    }
    $holds = @($script:SIInvardiaUpdateKinds | Where-Object { $s[$_].hold } | ForEach-Object { '{0}: {1}' -f $_, $s[$_].hold })
    $refused = @($script:SIInvardiaUpdateKinds | Where-Object { $s[$_].lastAction -eq 'refused' }).Count -gt 0
    $src = if ($s.source) { $s.source } else { 'none recorded' }
    $summary = if (-not $s.lastCheckUtc) { 'no update check recorded' } else { 'update source {0}; last check {1}; {2}; {3}' -f $src, (& $when $s.lastCheckUtc), (& $line 'code'), (& $line 'templates') }
    if ($s.claimResult -in @('conflict', 'forbidden', 'invalid', 'error', 'network', 'refused')) { $summary += ('; install key claim: {0} -- {1}' -f $s.claimResult, $s.claimReason) }
    [pscustomobject]@{ Source = $src; LastCheckUtc = $s.lastCheckUtc; Code = [pscustomobject]$s.code; Templates = [pscustomobject]$s.templates
                       Holds = $holds; Refused = $refused; LastError = $s.lastError; Summary = $summary
                       ClaimResult = $s.claimResult; ClaimReason = $s.claimReason }
}

# =====================================================================================================================
#  The install key: claimed automatically (Invardia owner decision 2026-10-04 -- nobody hands one out)
# =====================================================================================================================
function Get-SIInvardiaUpdatesEndpoint {
    <#
        PURE. Where the manifest is asked for, and in which header the key goes: what the key claim returned
        (updates.endpoint / updates.header, kept in the update state), else the frozen defaults
        (<base>/api/updates/securityinsight/manifest, X-Invardia-Install-Key). An endpoint that is not https is ignored.
        The returned endpoint may be the manifest URL itself, the product's updates root, the updates root or a bare origin.
    #>
    param([AllowNull()][System.Collections.IDictionary]$State, [string]$BaseUrl)
    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
    $uri = Get-SIInvardiaManifestUri -BaseUrl $base
    $hdr = $script:SIInvardiaUpdateKeyHeader
    $ep = if ($State) { "$($State['updatesEndpoint'])".Trim().TrimEnd('/') } else { '' }
    if ($ep -match '^https://[^/\s?#]+(/[^\s?#]*)?$') {
        $path = $Matches[1]
        if ($ep -match '/manifest$') { $uri = $ep }
        elseif ($ep -match ('/' + $script:SIInvardiaUpdateProduct + '$')) { $uri = $ep + '/manifest' }
        elseif (-not $path) { $uri = Get-SIInvardiaManifestUri -BaseUrl $ep }
        else { $uri = '{0}/{1}/manifest' -f $ep, $script:SIInvardiaUpdateProduct }
    }
    $h = if ($State) { "$($State['updatesHeader'])".Trim() } else { '' }
    if ($h -match '^[A-Za-z0-9-]{1,64}$') { $hdr = $h }
    [pscustomobject]@{ ManifestUri = $uri; KeyHeader = $hdr }
}

function New-SIInvardiaClaimBody {
    <# PURE. The claim's JSON body: { product, tenantId (from the identity's TOKEN), licence (the licence file text) } -- or,
       -Community (framework PRO-COMMUNITY-SAME, a Community install that said yes to "Connect this install to Invardia"):
       { product, tenantId, edition: 'community' } with NO licence. #>
    param([Parameter(Mandatory)][string]$TenantId, [AllowEmptyString()][string]$Licence = '', [switch]$Community)
    if ($Community) { return (([ordered]@{ product = $script:SIInvardiaUpdateProduct; tenantId = $TenantId.Trim().ToLowerInvariant(); edition = 'community' }) | ConvertTo-Json -Compress) }
    if (-not "$Licence".Trim()) { throw 'New-SIInvardiaClaimBody: a licence claim needs -Licence' }
    ([ordered]@{ product = $script:SIInvardiaUpdateProduct; tenantId = $TenantId.Trim().ToLowerInvariant(); licence = $Licence }) | ConvertTo-Json -Compress
}

function Request-SIInvardiaInstallKey {
    <#
        Make sure the install has its Invardia install key, in the install's Key Vault (SI-Invardia-InstallKey). NEVER throws.
          1. -BundleKey (the guided install's bundle field installKey) -> stored, and NO claim;
          2. a key is stored already                                  -> nothing to do;
          3. an earlier claim answered 409                            -> NOT claimed again (no loop): someone must ask
                                                                         Invardia for a reset; -Force claims once anyway;
          4. otherwise CLAIM: POST <base>/api/install-keys/claim { product, tenantId, licence }. The tenant is the 'tid' of
             the identity's own token (-Seams.TenantId), never config. 201 -> the key is stored and read back, and the
             answer's updates.endpoint / updates.header are kept in the state for the manifest pulls.
        -State is the update state (ConvertFrom-SIInvardiaUpdateState); the claim's outcome is recorded in it.
        -Seams: ReadSecret, WriteSecret, TenantId (required); ClaimHttp { param($Uri, $Body) } (default: a POST with no key).
        Returns @{ Action; Reason; StatusCode; HasKey; Environment; TelemetryEnabled }. Action: bundle | present | claimed |
        conflict | held | forbidden | invalid | waiting | network | off | error. The key is never in it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$State,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Seams,
        [string]$BaseUrl, [string]$Licence, [string]$BundleKey, [switch]$Force, [int]$TimeoutSec = 60,
        # framework PRO-COMMUNITY-SAME: a Community install that said yes to "Connect this install to Invardia" claims WITHOUT a
        # licence ({ product, tenantId, edition: 'community' }); the caller asks the opt-in first (Test-SIInvardiaConnect)
        [switch]$Community,
        [AllowNull()][object]$NowUtc
    )
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    $newKey = $null
    $out = {
        param($act, $why, $code = 0, $has = $false, $envName = '', $tel = $null)
        if ($act -notin @('present')) { $State.claimResult = $act; $State.claimReason = $why; $State.claimUtc = $now }
        [pscustomobject]@{ Action = $act; Reason = $why; StatusCode = $code; HasKey = [bool]$has; Environment = $envName; TelemetryEnabled = $tel }
    }
    try {
        foreach ($req in 'ReadSecret', 'WriteSecret') { if (-not $Seams[$req]) { throw "the install key claim needs the '$req' seam" } }
        $store = {
            param([string]$k)
            & $Seams.WriteSecret $script:SIInvardiaUpdateSecretKey $k
            $back = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim()
            if ($back -ne $k) { throw 'the install key was written to the Key Vault but did not read back identical' }
        }
        if ("$BundleKey".Trim()) {
            $newKey = "$BundleKey".Trim()
            if (-not (Test-SIInvardiaInstallKeyFormat $newKey)) { return (& $out 'invalid' 'the install key from the installation bundle is not an install key (it must start with inv-) -- nothing was stored') }
            & $store $newKey
            return (& $out 'bundle' ("the install key from the installation bundle is stored in the Key Vault ({0}); no claim was made" -f $script:SIInvardiaUpdateSecretKey) 0 $true)
        }
        $have = ''
        try { $have = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim() } catch { $have = '' }
        if (Test-SIInvardiaInstallKeyFormat $have) { $have = $null; return (& $out 'present' 'the install key is in the Key Vault' 0 $true) }
        $have = $null
        if (-not $Force -and $State.claimResult -eq 'conflict') {
            return [pscustomobject]@{ Action = 'held'; Reason = ("not claimed again: an earlier claim was refused ({0}) -- ask Invardia support for a reset of this install's key, then claim it again once (Settings > Updates in the web app, or SI_UPDATER_CLAIM_AGAIN=1 on one updater run)" -f $State.claimReason); StatusCode = 0; HasKey = $false; Environment = ''; TelemetryEnabled = $null }
        }
        if (-not $Seams['TenantId']) { throw "the install key claim needs the 'TenantId' seam" }
        $tenant = $null
        try { $tenant = [string](& $Seams.TenantId) } catch { $tenant = $null }
        if ("$tenant" -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            return (& $out 'off' 'the tenant this install runs in could not be proven from its identity token -- no claim was sent')
        }
        $lic = $Licence
        if (-not $Community) {
            if (-not "$lic".Trim()) { try { $lic = [string](& $Seams.ReadSecret $script:SIInvardiaUpdateSecretLicence) } catch { $lic = '' } }
            if (-not "$lic".Trim()) { return (& $out 'off' 'no SecurityInsight Pro licence is installed -- an install key is claimed with the licence') }
        }

        $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
        $http = if ($Seams['ClaimHttp']) { $Seams['ClaimHttp'] } else { { param($u, $b) Invoke-SIInvardiaUpdateHttp -Uri $u -Body $b -InstallKey '' -TimeoutSec $TimeoutSec } }
        $r = & $http ('{0}/api/install-keys/claim' -f $base) $(if ($Community) { New-SIInvardiaClaimBody -TenantId $tenant -Community } else { New-SIInvardiaClaimBody -TenantId $tenant -Licence ([string]$lic) })
        $code = [int]$r.Status
        $j = $null; if ("$($r.Body)".Trim()) { try { $j = "$($r.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { $j = $null } }
        $p = { param($o, $n) if ($o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }
        $why = { $t = "$(& $p $j 'reason')".Trim(); if (-not $t) { $t = "$(& $p $j 'error')".Trim() }; if ($t.Length -gt 300) { $t = $t.Substring(0, 297) + '...' }; Hide-SIInvardiaSecret $t }
        if ($code -in @(200, 201)) {
            $newKey = "$(& $p $j 'key')".Trim()
            if (-not (Test-SIInvardiaInstallKeyFormat $newKey)) { return (& $out 'error' 'Invardia answered the claim without a usable install key' $code) }
            & $store $newKey
            $upd = & $p $j 'updates'
            $State.updatesEndpoint = "$(& $p $upd 'endpoint')".Trim()
            $State.updatesHeader = "$(& $p $upd 'header')".Trim()
            $envName = "$(& $p $j 'environment')"
            $tel = & $p $j 'telemetryEnabled'
            return (& $out 'claimed' ("the install key was claimed{0} and stored in the Key Vault ({1})" -f $(if ($envName) { " for environment $envName" } else { '' }), $script:SIInvardiaUpdateSecretKey) $code $true $envName $tel)
        }
        switch ($code) {
            403 { return (& $out 'forbidden' ("Invardia refused the licence for the install key claim: {0}" -f $(if (& $why) { & $why } else { 'no reason given' })) 403) }
            409 {
                $err = "$(& $p $j 'error')".Trim()
                # a Community claim (no licence): two answers are NOT failures -- said plainly, the install goes on
                if ($Community -and $err -eq 'tenantKnown') {
                    return [pscustomobject]@{ Action = 'tenant-known'; Reason = 'this tenant belongs to a company with a SecurityInsight licence at Invardia -- connect it with that licence (the Pro install from your installation page) instead; this install stays anonymous'; StatusCode = 409; HasKey = $false; Environment = ''; TelemetryEnabled = $null }
                }
                if ($Community -and $err -eq 'keyExists') {
                    $back = ''; try { $back = "$(& $Seams.ReadSecret $script:SIInvardiaUpdateSecretKey)".Trim() } catch { $back = '' }
                    $has = [bool](Test-SIInvardiaInstallKeyFormat $back); $back = $null
                    return [pscustomobject]@{ Action = 'exists'; Reason = $(if ($has) { 'this install is already connected to Invardia -- the key stored for it is kept' } else { 'this install is already connected to Invardia, but its key is not in this install''s Key Vault -- ask Invardia support to send it again; the install goes on' }); StatusCode = 409; HasKey = $has; Environment = ''; TelemetryEnabled = $null }
                }
                $msg = switch -Regex ($err) {
                    '^keyExists$'                     { 'the key was reset or exists: ask Invardia support for a reset of this install''s key' }
                    '^tenantBelongsToAnotherCompany$' { 'this tenant belongs to another company at Invardia -- contact Invardia support' }
                    default                           { "Invardia refused the claim (409{0}) -- contact Invardia support" -f $(if ($err) { ": $err" } else { '' }) }
                }
                return (& $out 'conflict' $msg 409)
            }
            422 {
                $fields = @(); try { $fields = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } elseif ($_.PSObject.Properties['field']) { "$($_.field)" } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
                return (& $out 'invalid' ("Invardia refused the claim as invalid; fields: {0}" -f $(if ($fields.Count) { $fields -join ', ' } else { 'none named' })) 422)
            }
            429 { return (& $out 'waiting' 'Invardia asked to slow down -- the claim is tried again on a later run' 429) }
            0   { return (& $out 'network' ("Invardia could not be reached for the install key claim: {0}" -f (Hide-SIInvardiaSecret ([string]$r.Error)))) }
            default {
                if ($code -ge 500) { return (& $out 'network' ("Invardia answered {0} to the install key claim -- tried again on a later run" -f $code) $code) }
                return (& $out 'error' ("Invardia answered {0} to the install key claim{1}" -f $code, $(if (& $why) { ": $(& $why)" } else { '' })) $code)
            }
        }
    } catch {
        & $out 'error' (Hide-SIInvardiaSecret ("the install key claim did not complete: {0}" -f $_.Exception.Message) -Secret $newKey)
    } finally { $newKey = $null }
}

# =====================================================================================================================
#  The real seams, and the guided install's first package
# =====================================================================================================================
function New-SIInvardiaUpdateSeams {
    <#
        The seams for a real run against the install's Key Vault: ReadSecret / WriteSecret over REST through SecurityInsight's
        own sign-in (#521, no az CLI: -Mode Rest for the updater job, -Mode Az as setup names the same client). The same Key
        Vault access the licence request client uses (engine/_shared/SI-LicenceRequest.ps1), so both read the vault the same way.
    #>
    param([Parameter(Mandatory)][string]$VaultName, [ValidateSet('Az', 'Rest')][string]$Mode = 'Rest', [string]$SubscriptionId)
    if (-not (Get-Command -Name New-SILicenceRequestSeams -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-LicenceRequest.ps1')) }
    $lr = New-SILicenceRequestSeams -VaultName $VaultName -Mode $Mode -SubscriptionId $SubscriptionId
    # TenantId = the 'tid' of the identity's own token (the install key claim sends it; never config).
    $out = @{ ReadSecret = $lr.ReadSecret; WriteSecret = $lr.WriteSecret; TenantId = $lr.TenantId }
    # Invardia S16: the versions of SI-InstallId -- the pull sends the FIRST id written (Get-SIInvardiaInstallId)
    if ($lr['ReadVersions']) { $out.ReadVersions = $lr.ReadVersions }
    $out
}

function Save-SIInvardiaPackage {
    <#
        THE GUIDED INSTALL'S FIRST DOWNLOAD through the same pull (#225 hand-over contract v2): ask for the code manifest of
        -Ring (the ring the new install goes into, 0-3 -- UPDATE-1.7: SI decides it; the bootstrap passes the install's ring,
        3 for a customer install named 'prod'; none = nothing is fetched, and the reason says so) with the customer's licence, verify it, download the archive, check its size + SHA-256, check it
        holds SOLUTIONS/SecurityInsight with the VERSION the manifest names, and extract that folder into -OutDir/SecurityInsight.
        Returns @{ Ok; Action; Path (the SecurityInsight folder to run setup/Install-SecurityInsight from); Version; Sequence;
        Ring; ManualStep; Reason }. NEVER throws; the install key is never in anything it returns.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [Parameter(Mandatory)][string]$OutDir,
          [string]$BaseUrl, [System.Collections.IDictionary]$Seams = @{}, [AllowNull()]$Ring = $null)
    $res = { param($ok, $act, $why, $p = '', $r = $null) [pscustomobject]@{ Ok = $ok; Action = $act; Path = $p; Reason = $why
        Version = $(if ($r) { $r.Version } else { '' }); Sequence = $(if ($r) { $r.Sequence } else { -1 }); Ring = $(if ($r) { $r.Ring } else { $null })
        ManualStep = $(if ($r) { $r.ManualStep } else { '' }) } }
    try {
        $r = Get-SIInvardiaUpdate -Kind code -OutDir $OutDir -Seams $Seams -BaseUrl $BaseUrl -InstallKey $InstallKey -Licence $LicenceText -Ring $Ring
        if ($r.Action -ne 'update' -or -not $r.File) { return (& $res $false $r.Action $r.Reason '' $r) }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $dst = [IO.Path]::Combine($OutDir, 'SecurityInsight')
        if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
        $zip = [System.IO.Compression.ZipFile]::OpenRead($r.File)
        $n = 0; $tops = @{}
        try {
            foreach ($e in $zip.Entries) {
                $name = $e.FullName -replace '\\', '/'
                $i = $name.IndexOf('/'); if ($i -lt 0) { continue }
                $tops[$name.Substring(0, $i)] = $true
                $rel = $name.Substring($i + 1)
                if (-not $rel.StartsWith('SOLUTIONS/SecurityInsight/') -or $rel.EndsWith('/')) { continue }
                $sub = $rel.Substring('SOLUTIONS/SecurityInsight/'.Length)
                if ($sub.Contains('..')) { continue }
                $f = [IO.Path]::Combine($dst, ($sub -replace '/', [IO.Path]::DirectorySeparatorChar))
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $f) | Out-Null
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $f, $true)
                $n++
            }
        } finally { $zip.Dispose() }
        if ($tops.Count -ne 1 -or $n -eq 0) { return (& $res $false 'refused' 'the archive is not a SecurityInsight release (one folder with SOLUTIONS/SecurityInsight)' '' $r) }
        $vf = [IO.Path]::Combine($dst, 'VERSION')
        $v = if (Test-Path -LiteralPath $vf) { ([IO.File]::ReadAllText($vf)).Trim() } else { '' }
        if (-not (Test-SIInvardiaReleaseOfVersion -Released $r.Version -Archive $v)) { return (& $res $false 'refused' ("the archive holds SecurityInsight '{0}', not the {1} the manifest names" -f $v, $r.Version) '' $r) }
        & $res $true 'update' ("SecurityInsight {0} downloaded and verified ({1} files)" -f $v, $n) $dst $r
    } catch { & $res $false 'error' (Hide-SIInvardiaSecret ("the package could not be fetched: {0}" -f $_.Exception.Message) -Secret $InstallKey) }
}

# =====================================================================================================================
#  The vendor's release upload (setup/Publish-SIRelease.ps1) -- pure request builder
# =====================================================================================================================
function New-SIInvardiaReleaseRequest {
    <#
        PURE. The publish request of contract section 10: POST <base>/api/releases/securityinsight?kind=<kind>&version=<v>
        [&minFromVersion=][&image=], the raw file as the body (application/zip for code, application/json for templates),
        optional X-Release-Notes / X-Release-Manual-Step (URL-encoded), Authorization: Bearer <publisher token>.
        -Ring 0-3 (UPDATE-1.7, SI decides the ring): &ring=<n> -- published AND released to that ring in one call; -1 = only
        registered (released later with New-SIInvardiaRingReleaseRequest).
        -EngineChanged 'true' | 'false' (CR4 #654, Invardia 1.0.445): &engineChanged=<v> -- whether the release changes engine
        code, which starts the strict-guard period at the installs; '' = not said (Invardia's default).
        -ChangedScopes (CR3 #657, framework 12.11e item 3): &changedScopes=<id,id,...> | * -- the components the release
        changed (Format-SIReleaseChangedScopes: '*' = every component, a core file); '' = not sent.
        Returns @{ Method; Uri; ContentType; Headers; InFile }. The token is only ever in Headers.
    #>
    param([Parameter(Mandatory)][ValidateSet('code', 'templates')][string]$Kind, [Parameter(Mandatory)][string]$Version,
          [Parameter(Mandatory)][string]$FilePath, [string]$BaseUrl, [string]$AccessToken, [string]$Notes, [string]$ManualStep,
          [string]$MinFromVersion, [string]$Image, [ValidateRange(-1, 3)][int]$Ring = -1,
          [ValidateSet('', 'true', 'false')][string]$EngineChanged = '',
          [AllowEmptyString()][string]$ChangedScopes = '')
    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
    $q = 'kind={0}&version={1}' -f $Kind, [uri]::EscapeDataString($Version.Trim())
    if ("$MinFromVersion".Trim()) { $q += '&minFromVersion=' + [uri]::EscapeDataString($MinFromVersion.Trim()) }
    if ("$Image".Trim()) { $q += '&image=' + [uri]::EscapeDataString($Image.Trim()) }
    if ($Ring -ge 0) { $q += '&ring=' + $Ring }
    if ($EngineChanged) { $q += '&engineChanged=' + $EngineChanged }
    if ("$ChangedScopes".Trim()) { $q += '&changedScopes=' + [uri]::EscapeDataString("$ChangedScopes".Trim()) }
    $h = [ordered]@{ Accept = 'application/json' }
    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
    if ("$Notes".Trim()) { $h['X-Release-Notes'] = [uri]::EscapeDataString($Notes.Trim()) }
    if ("$ManualStep".Trim()) { $h['X-Release-Manual-Step'] = [uri]::EscapeDataString($ManualStep.Trim()) }
    [pscustomobject]@{
        Method = 'POST'; Uri = ('{0}/api/releases/{1}?{2}' -f $base, $script:SIInvardiaUpdateProduct, $q)
        ContentType = $(if ($Kind -eq 'code') { 'application/zip' } else { 'application/json' }); Headers = $h; InFile = $FilePath
    }
}

# =====================================================================================================================
#  SI decides the version AND the ring; Invardia relays (framework UPDATE-1.7, operator 2026-10-06) -- pure builders for
#  the release calls of SI's publisher identity (setup/Publish-SIRelease.ps1, setup/Publish-SICommunityRelease.ps1)
# =====================================================================================================================
function ConvertTo-SIRingTestGate {
    <#
        PURE (framework RING-GATE-PROOF, Invardia 2026-11-11; SI #1186). A ring call's "testGate" -- from an object, a
        hashtable or JSON text -- as Invardia takes it: [ordered]@{ commit (7-40 hex, lower case); run (1-200 characters);
        result green | red; at (ISO UTC, yyyy-MM-ddTHH:mm:ssZ) }. THROWS on anything malformed (Invardia would answer 422
        and write nothing). An "at" that came back from ConvertFrom-Json as a [datetime] is made ISO UTC again, never refused
        for it (PIM 3.1.4's ring calls were refused locally by exactly that).
    #>
    param([Parameter(Mandatory)][AllowNull()]$TestGate)
    $tg = $TestGate
    if ($tg -is [string]) { try { $tg = $tg | ConvertFrom-Json -ErrorAction Stop } catch { throw 'testGate is not JSON' } }
    if ($null -eq $tg) { throw 'no testGate' }
    $g = { param($k) if ($tg -is [System.Collections.IDictionary]) { $tg[$k] } elseif ($tg.PSObject.Properties[$k]) { $tg.$k } else { $null } }
    $commit = "$(& $g 'commit')".Trim().ToLowerInvariant()
    $run = "$(& $g 'run')".Trim()
    $result = "$(& $g 'result')".Trim().ToLowerInvariant()
    $atRaw = & $g 'at'
    $at = if ($atRaw -is [datetime]) { $atRaw.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
          elseif ($atRaw -is [datetimeoffset]) { $atRaw.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
          else { "$atRaw".Trim() }
    $bad = New-Object System.Collections.Generic.List[string]
    if ($commit -notmatch '^[0-9a-f]{7,40}$') { $bad.Add('commit (7-40 hex)') }
    if (-not $run -or $run.Length -gt 200) { $bad.Add('run (1-200 characters)') }
    if ($result -notin @('green', 'red')) { $bad.Add('result (green | red)') }
    if ($at -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$') { $bad.Add('at (ISO UTC)') }
    if ($bad.Count) { throw ('testGate malformed: {0}' -f ($bad -join ', ')) }
    [ordered]@{ commit = $commit; run = $run; result = $result; at = $at }
}

function New-SIInvardiaRingReleaseRequest {
    <#
        PURE. Release a version Invardia already holds to ONE ring:
          POST <base>/api/releases/securityinsight/<kind>/rings/<ring>   { version[, tag][, testGate] }   (kind code | templates | community)
        -TestGate (framework RING-GATE-PROOF, #1186): the green quick-gate run on exactly the release commit
        (ConvertTo-SIRingTestGate shape; setup\_shared\SI-ReleaseGateProof.ps1 decides it). A request that will be SENT (it
        carries -AccessToken) without one is refused here -- no ring call ever leaves without its proof; a plan (no token)
        shows the body without it.
        Community: rings 0-3, as Pro (framework PRO-COMMUNITY-SAME, SI #1207). Only SI's publisher identity may call it.
        -EngineChanged 'true' | 'false' (CR4 #654): sets engineChanged on that version's record (a version published before
        SI said it); '' = not sent.
        -ChangedScopes (CR3 #657): the components the release changed, as a JSON list (changedScopes: [id, ...] or ['*']);
        '' = not sent. The same text Format-SIReleaseChangedScopes gives the publish call (comma-separated).
        -ImageOnly + -ImageDiff (framework IMAGE-PATCH-1 point 8, IMAGE-ONLY-AUTO-1; SI #1204): the version is an IMAGE-ONLY
        release (base digests / version stamps / notes only) -- the body adds "imageOnly": true and "imageDiff": { fromVersion,
        files: [ { path, removed: [...], added: [...] } ] }, every file changed since the version ring 2 runs. Invardia checks
        the diff and approves rings 2 / 3 on the owner's standing yes once rings 0 / 1 proved it. Over Invardia's limits (300
        files, 20,000 lines, 1,000 characters a line) or no fromVersion = refused here (Invardia would answer 422).
        Returns @{ Method; Uri; ContentType; Headers; Body }. The token is only ever in Headers.
    #>
    param([Parameter(Mandatory)][ValidateSet('code', 'templates', 'community')][string]$Kind, [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring,
          # -Tag: '' only (2026-10-28, as PIM: the stable zip v<version>; a ring name never belongs in it)
          [Parameter(Mandatory)][string]$Version, [ValidateSet('')][string]$Tag = '', [string]$BaseUrl, [string]$AccessToken,
          [ValidateSet('', 'true', 'false')][string]$EngineChanged = '', [AllowEmptyString()][string]$ChangedScopes = '',
          [AllowNull()]$TestGate = $null, [switch]$ImageOnly, [AllowNull()]$ImageDiff = $null)
    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
    # SI #1207 (framework PRO-COMMUNITY-SAME): a Community version goes to rings 0-3, the same rings as Pro
    if ($AccessToken -and $null -eq $TestGate) { throw ("refused: the ring {0} call carries no testGate -- a ring call is sent only with the green quick-gate run on exactly the release commit (RING-GATE-PROOF)" -f $Ring) }
    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
    $b = [ordered]@{ version = $Version.Trim() }
    if ($Tag) { $b['tag'] = $Tag }
    if ($EngineChanged) { $b['engineChanged'] = ($EngineChanged -eq 'true') }
    if ("$ChangedScopes".Trim()) { $b['changedScopes'] = [string[]]@("$ChangedScopes".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    if ($null -ne $TestGate) { $b['testGate'] = ConvertTo-SIRingTestGate -TestGate $TestGate }
    if ($ImageOnly) {
        $b['imageOnly'] = $true
        $b['imageDiff'] = ConvertTo-SIRingImageDiff -ImageDiff $ImageDiff
    }
    $h = [ordered]@{ Accept = 'application/json' }
    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
    [pscustomobject]@{ Method = 'POST'; Uri = ('{0}/api/releases/{1}/{2}/rings/{3}' -f $base, $script:SIInvardiaUpdateProduct, $Kind, $Ring)
                       ContentType = 'application/json'; Headers = $h; Body = ($b | ConvertTo-Json -Compress -Depth 8) }
}

function ConvertTo-SIRingImageDiff {
    <#
        PURE (framework IMAGE-PATCH-1 point 8; SI #1204). An image-only ring call's "imageDiff" -- from an object, a hashtable
        or JSON text -- as Invardia takes it: [ordered]@{ fromVersion; files = @([ordered]@{ path; removed = @(); added = @() }) }.
        THROWS on what Invardia would refuse with 422: no fromVersion, no file, more than 300 files, more than 20,000 lines in
        all, a line over 1,000 characters.
    #>
    param([AllowNull()]$ImageDiff)
    $d = $ImageDiff
    if ($d -is [string]) { try { $d = $d | ConvertFrom-Json -ErrorAction Stop } catch { throw 'imageDiff is not JSON' } }
    if ($null -eq $d) { throw 'an image-only ring call needs its imageDiff' }
    $g = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
    $from = "$(& $g $d 'fromVersion')".Trim()
    if ($from -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "imageDiff: fromVersion is not a release version: '$from'" }
    $files = New-Object System.Collections.Generic.List[object]
    $lines = 0
    foreach ($f in @(& $g $d 'files')) {
        if ($null -eq $f) { continue }
        $p = "$(& $g $f 'path')".Trim()
        if (-not $p) { throw 'imageDiff: a file without its path' }
        $rem = [string[]]@(@(& $g $f 'removed') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        $add = [string[]]@(@(& $g $f 'added') | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
        foreach ($l in @($rem) + @($add)) { if ($l.Length -gt 1000) { throw ("imageDiff: a line of {0} is over 1,000 characters" -f $p) } }
        $lines += $rem.Count + $add.Count
        $files.Add([ordered]@{ path = $p; removed = @($rem); added = @($add) })
    }
    if (-not $files.Count) { throw 'imageDiff: no file changed' }
    if ($files.Count -gt 300) { throw ("imageDiff: {0} files (Invardia takes at most 300)" -f $files.Count) }
    if ($lines -gt 20000) { throw ("imageDiff: {0} lines (Invardia takes at most 20,000)" -f $lines) }
    [ordered]@{ fromVersion = $from; files = @($files.ToArray()) }
}

function New-SIInvardiaCommunityRegisterRequest {
    <#
        PURE. Register a Community version with Invardia: POST <base>/api/releases/securityinsight/community { version, tag }.
        Invardia fetches the PUBLIC GitHub release zip once (tag v<version>, or v<version>-ring2 with tag 'ring2') and stores
        its URL, SHA-256 and size -- the file stays on GitHub; Invardia only signs the ring entries. Returns the request shape
        of New-SIInvardiaRingReleaseRequest.
    #>
    # -EngineChanged (2026-10-28, the alignment with PIM's community-register): sent as engineChanged when given -- whether this
    # version changed engine code (Invardia's release mode); not given = the body is exactly { version, tag } as before
    # -Tag: '' only (2026-10-28, as PIM's community-register: the stable zip v<version>; a ring name never belongs in it)
    # -Sha256 (2026-10-31): the SHA-256 of the zip the publisher downloaded and checked -- Invardia signs only that exact file
    # and refuses a fetch whose hash differs (a release asset replaced between the check and Invardia's fetch is never signed)
    param([Parameter(Mandatory)][string]$Version, [ValidateSet('')][string]$Tag = '', [string]$BaseUrl, [string]$AccessToken, [AllowNull()][object]$EngineChanged = $null,
          [AllowEmptyString()][string]$Sha256 = '')
    if ("$Version".Trim() -notmatch '^\d{1,12}(\.\d{1,12}){1,5}$') { throw "not a release version: '$Version'" }
    if ("$Sha256".Trim() -and "$Sha256".Trim() -notmatch '^[0-9a-fA-F]{64}$') { throw "not a SHA-256: '$Sha256'" }
    $base = Get-SIInvardiaUpdateBaseUrl -BaseUrl $BaseUrl
    $h = [ordered]@{ Accept = 'application/json' }
    if ($AccessToken) { $h['Authorization'] = 'Bearer ' + $AccessToken }
    $b = [ordered]@{ version = $Version.Trim(); tag = $Tag }
    if ($null -ne $EngineChanged) { $b['engineChanged'] = [bool]$EngineChanged }
    if ("$Sha256".Trim()) { $b['sha256'] = "$Sha256".Trim().ToLowerInvariant() }
    [pscustomobject]@{ Method = 'POST'; Uri = ('{0}/api/releases/{1}/community' -f $base, $script:SIInvardiaUpdateProduct)
                       ContentType = 'application/json'; Headers = $h; Body = ($b | ConvertTo-Json -Compress) }
}

function Get-SIInvardiaNotApproved {
    <#
        PURE. CR3 (#657, framework 12.11e item 7): Invardia refuses a ring 2 / 3 release, or a wave, of a version the owner
        has not APPROVED -- 409 "notApproved" with the reason. Returns @{ NotApproved; Reason } from an answer
        (-Response: @{ Status; Body }); NotApproved $false for any other answer (a 409 "version exists" included).
    #>
    param([Parameter(Mandatory)]$Response)
    $no = [pscustomobject]@{ NotApproved = $false; Reason = '' }
    if ([int]$Response.Status -ne 409) { return $no }
    $body = "$($Response.Body)"
    $j = $null; try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { }
    $hit = $false; $why = ''
    if ($j -and -not ($j -is [string])) {
        foreach ($n in 'error', 'code', 'status', 'title', 'kind') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -ieq 'notApproved') { $hit = $true } }
        foreach ($n in 'reason', 'detail', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -and "$($j.$n)".Trim() -ine 'notApproved') { $why = "$($j.$n)".Trim(); break } }
    } elseif ($j -is [string] -and "$j".Trim() -ieq 'notApproved') { $hit = $true }
    if (-not $hit -and $body -match '(?i)\bnotApproved\b') { $hit = $true }
    if (-not $hit) { return $no }
    $why = Hide-SIInvardiaSecret $why
    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    [pscustomobject]@{ NotApproved = $true; Reason = $why }
}

function Format-SIInvardiaNotApproved {
    <# PURE. The plain words for a 409 notApproved: what happened, Invardia's reason, who decides. #>
    param([Parameter(Mandatory)][string]$What, [AllowEmptyString()][string]$Reason)
    ("{0}: NOT APPROVED -- Invardia refused it (409 notApproved). A release to ring 2 or 3, or a pre-release wave, needs the owner's APPROVED on this version first (Invardia's back office: Updates > the release). Invardia's reason: {1}. Nothing was released; rings 0 and 1 are not affected." -f $What, $(if ("$Reason".Trim()) { "$Reason".Trim() } else { 'none given' }))
}

function Get-SIInvardiaHealthHold {
    <#
        PURE. CR2 (framework 12.11d): Invardia holds a ring 2 / 3 release of a code version while a lower-ring install that
        took it turned Unhealthy or Unknown -- 409 { error "healthHold", ring, version, reason, holding, warnings }. Returns
        @{ HealthHold; Reason; Holding } from an answer (-Response: @{ Status; Body }); HealthHold $false for any other answer.
    #>
    param([Parameter(Mandatory)]$Response)
    $no = [pscustomobject]@{ HealthHold = $false; Reason = ''; Holding = '' }
    if ([int]$Response.Status -ne 409) { return $no }
    $body = "$($Response.Body)"
    $j = $null; try { $j = $body | ConvertFrom-Json -ErrorAction Stop } catch { }
    $hit = $false; $why = ''; $who = ''
    if ($j -and -not ($j -is [string])) {
        foreach ($n in 'error', 'code', 'status', 'kind') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim() -ieq 'healthHold') { $hit = $true } }
        if ($j.PSObject.Properties['reason'] -and "$($j.reason)".Trim()) { $why = "$($j.reason)".Trim() }
        if ($j.PSObject.Properties['holding'] -and $null -ne $j.holding) { $who = (@($j.holding) | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ConvertTo-Json -Compress -Depth 4) } }) -join ', ' }
    }
    if (-not $hit -and $body -match '(?i)\bhealthHold\b') { $hit = $true }
    if (-not $hit) { return $no }
    $why = Hide-SIInvardiaSecret $why; $who = Hide-SIInvardiaSecret $who
    if ($why.Length -gt 300) { $why = $why.Substring(0, 297) + '...' }
    if ($who.Length -gt 300) { $who = $who.Substring(0, 297) + '...' }
    [pscustomobject]@{ HealthHold = $true; Reason = $why; Holding = $who }
}

function Format-SIInvardiaHealthHold {
    <# PURE. The plain words for a 409 healthHold: what happened, why, which installs hold it, who decides. #>
    param([Parameter(Mandatory)][string]$What, [AllowEmptyString()][string]$Reason, [AllowEmptyString()][string]$Holding)
    ("{0}: HELD FOR DATA HEALTH -- Invardia refused it (409 healthHold): an install of a lower ring that took this version is Unhealthy or Unknown since. Invardia's reason: {1}. Holding: {2}. Fix that install's data health (or the owner overrides the hold with a reason in Invardia's back office). Nothing was released; rings 0 and 1 are not affected." -f $What, $(if ("$Reason".Trim()) { "$Reason".Trim() } else { 'none given' }), $(if ("$Holding".Trim()) { "$Holding".Trim() } else { 'not named' }))
}
function Get-SIInvardiaReleaseCallOutcome {
    <# PURE. A register / ring-release answer in words. Returns @{ Ok; Status; Reason; NotApproved }. #>
    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)][string]$What)
    $code = [int]$Response.Status
    $j = $null; try { $j = "$($Response.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
    $why = ''; if ($j -and -not ($j -is [string])) { foreach ($n in 'reason', 'error', 'message') { if ($j.PSObject.Properties[$n] -and "$($j.$n)".Trim()) { $why = "$($j.$n)".Trim(); break } } }
    $o = { param($ok, $r, $na = $false) [pscustomobject]@{ Ok = $ok; Status = $code; Reason = $r; NotApproved = [bool]$na } }
    $tail = if ($why) { ": $why" } else { '' }
    # CR3: a 409 "notApproved" is said plainly -- never as "Invardia holds it already"
    $na = Get-SIInvardiaNotApproved -Response $Response
    if ($na.NotApproved) { return (& $o $false (Format-SIInvardiaNotApproved -What $What -Reason $na.Reason) $true) }
    # CR2: a 409 "healthHold" is said plainly too -- never as "Invardia holds it already"
    $hh = Get-SIInvardiaHealthHold -Response $Response
    if ($hh.HealthHold) { return (& $o $false (Format-SIInvardiaHealthHold -What $What -Reason $hh.Reason -Holding $hh.Holding)) }
    switch ($code) {
        { $_ -in 200, 201, 202 } { return (& $o $true ("{0}: done (HTTP {1})" -f $What, $code)) }
        401 { return (& $o $false ("{0}: Invardia did not accept the publisher token (401)" -f $What)) }
        403 { return (& $o $false ("{0}: refused (403{1}) -- only SecurityInsight's publisher identity (Invardia.Publisher.securityinsight) may release SecurityInsight" -f $What, $tail)) }
        404 { return (& $o $false ("{0}: Invardia does not hold that version (404{1}) -- publish / register it first" -f $What, $tail)) }
        409 { return (& $o $false ("{0}: Invardia holds it already (409{1})" -f $What, $tail)) }
        422 {
            $f = @(); try { $f = @($j.fields | ForEach-Object { if ($_ -is [string]) { $_ } else { ($_ | ConvertTo-Json -Compress) } }) } catch { }
            return (& $o $false ("{0}: refused as invalid (422; fields: {1}){2}" -f $What, $(if ($f.Count) { $f -join ', ' } else { 'none named' }), $tail))
        }
        0 { return (& $o $false ("{0}: Invardia could not be reached: {1}" -f $What, (Hide-SIInvardiaSecret "$($Response.Body)"))) }
        default { return (& $o $false ("{0}: Invardia answered {1}{2}" -f $What, $code, $tail)) }
    }
}

function Test-SIInvardiaScopesRecorded {
    <#
        PURE. CR3 READ-BACK: did Invardia record the changedScopes a publish / ring call sent (-Sent: the comma text sent, ''
        = none sent)? Invardia answers a call it took with the list it stored (`changedScopes` in the 201 body) and leaves the
        key out when it stored nothing. Returns @{ Sent; Recorded; Line }: Recorded $true = the answer names the same ids,
        $false = sent but not in the answer (said plainly -- never a silent null at Invardia), $null = nothing was sent.
    #>
    param([Parameter(Mandatory)]$Response, [AllowEmptyString()][string]$Sent = '')
    $want = @("$Sent".Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if (-not $want.Count) { return [pscustomobject]@{ Sent = $false; Recorded = $null; Line = '' } }
    $code = [int]$Response.Status
    if ($code -notin 200, 201, 202) { return [pscustomobject]@{ Sent = $true; Recorded = $false; Line = '' } }
    $j = $null; try { $j = "$($Response.Body)" | ConvertFrom-Json -ErrorAction Stop } catch { }
    $got = @(); if ($j -and -not ($j -is [string]) -and $j.PSObject.Properties['changedScopes']) { $got = @($j.changedScopes | ForEach-Object { "$_" }) }
    if (-not $got.Count) {
        return [pscustomobject]@{ Sent = $true; Recorded = $false
            Line = ('WARNING: changedScopes was sent ({0}) but Invardia''s answer does not carry it -- Invardia did not record the changed components of this call' -f $(if ($want.Count -gt 5) { '{0} ids' -f $want.Count } else { $want -join ',' })) }
    }
    $same = (@($want | Sort-Object) -join ',') -eq (@($got | Sort-Object) -join ',')
    [pscustomobject]@{ Sent = $true; Recorded = [bool]$same
        Line = $(if ($same) { 'Invardia recorded the changed components: {0}' -f $(if ($got.Count -gt 5) { '{0} ids' -f $got.Count } else { $got -join ',' }) } else { 'WARNING: Invardia recorded other changed components than were sent (sent {0}, recorded {1})' -f ($want -join ','), ($got -join ',') }) }
}
