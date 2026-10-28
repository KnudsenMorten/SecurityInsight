#Requires -Version 5.1
<#
.SYNOPSIS
  The product-NEUTRAL half of an Invardia update client: verify a signed update manifest and the archive it names.
  Framework contract UPDATE-1 (one signer for every product); Invardia docs/DESIGN.md §10 (the manifest + the pull).

.DESCRIPTION
  Copied BYTE-IDENTICAL into every product that takes updates from Invardia (PIM: engine/_shared/; SecurityInsight:
  engine/_shared/) and pinned there by a whole-file drift test. So: NO product names, settings, environment variables or
  layouts in this file -- the product is always PASSED IN (-Product). A change is made here first and copied.

  * the trusted update-signing public keys, EMBEDDED (a key fetched at run time is never trusted);
  * Test-InvardiaManifestSignature  RS256 (PKCS#1 v1.5, SHA-256) over the base64-DECODED manifest bytes;
  * Test-InvardiaManifest           signature + product + kind + version + SHA-256 + sequence (no replay) + https link;
                                    manualStep / minFromVersion HOLD;
  * Invoke-InvardiaManifestPull     POST <base>/api/updates/<product>/manifest {kind, licence, ring} + X-Invardia-Install-Key;
  * Save-InvardiaArchive / Test-InvardiaArchiveFile   the download is a zip of the SIGNED size + SHA-256.
  PS 5.1 + 7. No modules. Nothing here writes anything.
#>

$script:InvardiaUpdateDefaultBase = 'https://invardia.com'
# The trusted update-signing public keys (RSA, JWK n/e base64url), Invardia's list at GET /api/updates/keys, EMBEDDED.
# Add a key here -- never remove the old one in the same release.
# CN=Invardia-Updates (RSA 4096, valid to 2036-10-04, cert SHA-1 DDFF1C84930C290ECF234FB4C3F3C1D5B3F532F2), delivered by
# the Invardia session 2026-10-04 and checked here against Invardia's committed public certificate (modulus identical).
# Then verified against the LIVE GET https://invardia.com/api/updates/keys (same keyId, n and e).
$script:InvardiaUpdateTrustedKeys = @(
    @{ keyId = 'https://kv-invardia-gml64wkoe7np.vault.azure.net/keys/invardia-updates'; e = 'AQAB'
       n = 'tLDrlMq1et3H3vIomcjokhFXfkkyaYVT2F-BByLGk8Pa7lrN7xd-53AbJ3keqv0ZZSQG_V0rKFxbt5b0m7YTNKbBUXvsgLLFQQbouDu-Am-8blzNBjIyDKoQKYKYaYfCbL3Tjdil7RD5pFNV6Qt3wW54jzhPEmyArr2xRjVUOg2WYQe9CpD_pd6-ww9dFlGQwtT_VJvLs0xcXsJkitfxe5tJ7PV8BUKoDpXJQNl6j2M6iqILxAujBxFB3_fGHEfooDJGWu1jkqp2mW2yXots_3ZtKUlnAmwANQNAsVWAxLq-8bLy6b3VTIvMMWw9JyZubBhU8OriW3OBKK6O2k5CV_-O5b0zf_TaQSr64Mq2VPtKkzY1weiFRlwDzEfq-aiLzr-HWx1tB43QEISNoBkrdhC-G9wjCQRgWSoINWbnL--2HOnwdivT9GRaJ38Mng9gqPdrPFfrv6t2ZIn6g5X9GOz_ua1Fi0WyfRJ1ICzzQgiivB0bBdlUtxfV89b0TXwIT9JynV7VYS9uv5H56IXpcuDaWzIueq6bVlWqk6p-cEMviDKMdaME3JW_Q-qNBCF1Q-cCAGl269KtFWQt2aLU2f50JkwW8h5slY1I05PXbJaX26n-Zu9pdrq-us3la8D1v_V9ehsR2s6Xj4cKZRZAURd5ut42R8h7EIe7K17KeZE' }
)

function ConvertFrom-InvardiaBase64Url {
    <# PURE. base64url (or plain base64) text -> bytes. #>
    param([AllowEmptyString()][string]$Text)
    $t = "$Text".Trim().Replace('-', '+').Replace('_', '/')
    switch ($t.Length % 4) { 2 { $t += '==' } 3 { $t += '=' } }
    return [Convert]::FromBase64String($t)
}

function Compare-InvardiaReleaseVersion {
    <# PURE. -1 / 0 / 1 for two dotted numeric versions ('2.4.491'); a non-numeric part compares as 0. #>
    param([string]$A, [string]$B)
    $pa = @("$A".Trim() -split '\.'); $pb = @("$B".Trim() -split '\.')
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = 0; $y = 0
        if ($i -lt $pa.Count) { [void][int]::TryParse($pa[$i], [ref]$x) }
        if ($i -lt $pb.Count) { [void][int]::TryParse($pb[$i], [ref]$y) }
        if ($x -lt $y) { return -1 }; if ($x -gt $y) { return 1 }
    }
    return 0
}

function Test-InvardiaManifestSignature {
    <#
      PURE (crypto only). RS256 over the bytes behind -ManifestB64, signature base64, by the key -KeyId of -TrustedKeys
      (@( @{ keyId; n; e } )). Returns @{ ok; reason }. PS 5.1-safe: RSAParameters + ImportParameters, no ImportFromPem.
    #>
    param([string]$ManifestB64, [string]$Signature, [string]$KeyId, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys)
    $keys = @($TrustedKeys | Where-Object { $_ })
    if (-not $keys.Count) { return @{ ok = $false; reason = 'no trusted update-signing key is embedded in this version yet -- every manifest is refused until one is' } }
    $k = @($keys | Where-Object { "$($_.keyId)" -ceq "$KeyId" })[0]
    if (-not $k) { return @{ ok = $false; reason = "the manifest is signed by key '$KeyId', which this version does not trust" } }
    try {
        $data = [Convert]::FromBase64String("$ManifestB64".Trim())
        $sig = [Convert]::FromBase64String("$Signature".Trim())
        $p = New-Object System.Security.Cryptography.RSAParameters
        $p.Modulus = ConvertFrom-InvardiaBase64Url "$($k.n)"
        $p.Exponent = ConvertFrom-InvardiaBase64Url "$($k.e)"
        $rsa = [System.Security.Cryptography.RSA]::Create()
        try {
            $rsa.ImportParameters($p)
            $ok = $rsa.VerifyData($data, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        } finally { $rsa.Dispose() }
        if ($ok) { return @{ ok = $true; reason = '' } }
        return @{ ok = $false; reason = 'the manifest signature does not verify' }
    } catch { return @{ ok = $false; reason = "the manifest signature could not be checked: $($_.Exception.Message)" } }
}

function Test-InvardiaManifest {
    <#
      PURE (given the trusted keys). Everything about a 200 answer, before anything is downloaded. Returns
      @{ ok; hold; reason; version; sequence; sha256; size; downloadUrl; manifest }.
        ok=$false            refused (signature, shape, product, kind, replay) -- nothing moves
        ok=$true, hold=$true  verified, but the release asks for a manual step or a newer starting version -- nothing moves
    #>
    # -Ring (framework UPDATE-1.7, 2026-10-06: the solution decides the ring, Invardia relays): the ring this environment
    # asked for. A manifest for another ring, or one that names no ring, is refused. -1 = not checked (legacy callers only).
    param([Parameter(Mandatory)][object]$Response, [object[]]$TrustedKeys = $script:InvardiaUpdateTrustedKeys,
          [string]$Kind = 'code', [int]$AppliedSequence = 0, [string]$RunningVersion = '', [Parameter(Mandatory)][string]$Product, [int]$Ring = -1)
    $no = { param($why) @{ ok = $false; hold = $false; reason = $why; version = ''; sequence = 0; sha256 = ''; size = 0; downloadUrl = ''; manifest = $null } }
    $g = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $pp = $o.PSObject.Properties[$n]; if ($pp) { $pp.Value } }
    $b64 = "$(& $g $Response 'manifestB64')".Trim()
    if (-not $b64) { return (& $no 'the answer carries no manifest') }
    $sv = Test-InvardiaManifestSignature -ManifestB64 $b64 -Signature "$(& $g $Response 'signature')" -KeyId "$(& $g $Response 'keyId')" -TrustedKeys $TrustedKeys
    if (-not $sv.ok) { return (& $no $sv.reason) }
    # Only the SIGNED bytes are read; the answer's own 'manifest' object is ignored.
    $m = $null; try { $m = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json } catch { return (& $no 'the signed manifest is not JSON') }
    if ("$($m.product)" -cne $Product) { return (& $no "the manifest is for '$($m.product)', not $Product") }
    if ("$($m.kind)" -cne $Kind) { return (& $no "the manifest is kind '$($m.kind)', not $Kind") }
    if ($Ring -ge 0) {
        $mr = -1; if (-not [int]::TryParse("$($m.ring)", [ref]$mr)) { return (& $no "the manifest names no ring (this environment asked for ring $Ring)") }
        if ($mr -ne $Ring) { return (& $no "the manifest is for ring $mr, not ring $Ring that this environment asked for") }
    }
    $ver = "$($m.version)".Trim(); if ($ver -notmatch '^\d+\.\d+\.\d+$') { return (& $no "the manifest names no release version ('$ver')") }
    $sha = "$($m.sha256)".Trim().ToLowerInvariant(); if ($sha -notmatch '^[0-9a-f]{64}$') { return (& $no 'the manifest carries no SHA-256') }
    $seq = 0; if (-not [int]::TryParse("$($m.sequence)", [ref]$seq) -or $seq -lt 1) { return (& $no 'the manifest carries no sequence') }
    if ($seq -lt $AppliedSequence) { return (& $no "REPLAY refused: sequence $seq is lower than the $AppliedSequence already applied here") }
    # F4 (framework UPDATE-1.5, 2026-10-05): the SIGNED size is required -- a manifest without it (or with 0) is refused,
    # so the archive check below always compares the length, never only the hash.
    $size = [int64]0; if (-not [int64]::TryParse("$($m.size)", [ref]$size) -or $size -lt 1) { return (& $no 'the manifest carries no archive size') }
    $url = "$(& $g $Response 'downloadUrl')".Trim()
    if ($url -notmatch '^https://') { return (& $no 'the download link is not https') }
    $r = @{ ok = $true; hold = $false; reason = "signed manifest: $ver (ring $($m.ring), sequence $seq)"; version = $ver; sequence = $seq; sha256 = $sha; size = $size; downloadUrl = $url; manifest = $m }
    if ("$($m.manualStep)".Trim()) { $r.hold = $true; $r.reason = "HELD -- $ver asks for a manual step first: $("$($m.manualStep)".Trim())" ; return $r }
    $mf = "$($m.minFromVersion)".Trim()
    if ($mf -and "$RunningVersion".Trim() -and (Compare-InvardiaReleaseVersion "$RunningVersion" $mf) -lt 0) {
        $r.hold = $true; $r.reason = "HELD -- $ver can only be installed from $mf or later; this environment runs $RunningVersion"; return $r
    }
    return $r
}

function Get-InvardiaPullReason {
    <# PURE. The admin's sentence for a non-200 pull answer. #>
    param([int]$Status, [AllowNull()][object]$Body, [string]$ErrorText = '')
    $why = if ($Body -and $Body.PSObject.Properties['reason']) { " ($($Body.reason))" } else { '' }
    switch ($Status) {
        204 { return 'nothing is released to this environment''s ring yet' }
        401 { return 'Invardia refused the install key (revoked, reset or wrong) -- claim a new one, or set the install key again' }
        403 { return "Invardia refused the licence$why -- updates need a valid Invardia-issued Pro licence for this tenant" }
        404 { return 'Invardia does not know the product' }
        422 { return "Invardia refused the request$why -- the pull must carry this environment's ring (0-3)" }
        429 { return 'Invardia asked to wait (rate limit) -- the next run asks again' }
        0   { return "Invardia could not be reached: $ErrorText" }
        default { return "Invardia answered HTTP $Status$why" }
    }
}

function Invoke-InvardiaManifestPull {
    <# The pull. -Http { param($Method, $Url, $Body, $Headers) } -> @{ status; body; error } (the product's own HTTP helper). #>
    # -Ring (UPDATE-1.7): the environment's OWN ring (0-3), set in the product; Invardia answers with what the product
    # published for that ring (204 when nothing). Required -- Invardia answers 422 without it.
    param([Parameter(Mandatory)][string]$Product, [Parameter(Mandatory)][scriptblock]$Http, [string]$BaseUrl = '', [Parameter(Mandatory)][string]$InstallKey, [Parameter(Mandatory)][string]$LicenceText, [string]$Kind = 'code',
          [Parameter(Mandatory)][ValidateRange(0, 3)][int]$Ring)
    $base = if ("$BaseUrl".Trim()) { "$BaseUrl".Trim().TrimEnd('/') } else { $script:InvardiaUpdateDefaultBase }
    $r = & $Http 'POST' "$base/api/updates/$Product/manifest" @{ kind = $Kind; licence = $LicenceText; ring = $Ring } @{ 'X-Invardia-Install-Key' = $InstallKey }
    $pullStatus = [int]$r.status
    return @{ status = $pullStatus; body = $r.body; reason = $(if ($pullStatus -eq 200) { '' } else { Get-InvardiaPullReason -Status $pullStatus -Body $r.body -ErrorText "$($r.error)" }) }
}

function Save-InvardiaArchive {
    <# Download the release zip and prove it is the one the manifest names (zip magic, size, SHA-256). @{ ok; bytes; reason }. #>
    param([Parameter(Mandatory)][string]$Url, [Parameter(Mandatory)][string]$OutFile, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0, [int]$TimeoutSeconds = 300)
    try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.ServicePointManager]::SecurityProtocol } catch { }
    try { Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop }
    catch { return @{ ok = $false; bytes = 0; reason = "download failed: $($_.Exception.Message -replace '\?t=[^\s''"]+', '?t=***')" } }
    return (Test-InvardiaArchiveFile -Path $OutFile -ExpectedSha256 $ExpectedSha256 -ExpectedSize $ExpectedSize)
}

function Test-InvardiaArchiveFile {
    <# PURE (file read). The downloaded file is a zip of the size and SHA-256 the SIGNED manifest names. #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedSha256, [int64]$ExpectedSize = 0)
    # F4: the signed size is REQUIRED -- no expected size = refused (a caller that has none must not skip the length check)
    if ($ExpectedSize -lt 1) { return @{ ok = $false; bytes = 0; reason = 'no signed archive size to check the download against -- refused' } }
    if (-not (Test-Path -LiteralPath $Path)) { return @{ ok = $false; bytes = 0; reason = 'the download produced no file' } }
    $len = (Get-Item -LiteralPath $Path).Length
    $magic = New-Object byte[] 2
    $fs = [System.IO.File]::OpenRead($Path); try { [void]$fs.Read($magic, 0, 2) } finally { $fs.Dispose() }
    if ($magic[0] -ne 0x50 -or $magic[1] -ne 0x4B) { return @{ ok = $false; bytes = $len; reason = 'the downloaded file is not a zip' } }
    if ($len -ne $ExpectedSize) { return @{ ok = $false; bytes = $len; reason = "the archive is $len bytes, the signed manifest says $ExpectedSize" } }
    $sha = [System.Security.Cryptography.SHA256]::Create(); $fh = [System.IO.File]::OpenRead($Path)
    try { $h = ([BitConverter]::ToString($sha.ComputeHash($fh))).Replace('-', '').ToLowerInvariant() } finally { $fh.Dispose(); $sha.Dispose() }
    if ($h -ne "$ExpectedSha256".Trim().ToLowerInvariant()) { return @{ ok = $false; bytes = $len; reason = "the archive's SHA-256 ($h) is not the one the signed manifest names -- refused" } }
    return @{ ok = $true; bytes = $len; reason = '' }
}
