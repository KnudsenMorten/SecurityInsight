#Requires -Version 5.1
<#
.SYNOPSIS
    LIC-1 -- the FRAMEWORK licence verifier. One implementation, every solution.

.DESCRIPTION
    The licence FORMAT is framework-wide by design: a customer holding one file for two
    products must get identical semantics from both. LIC-1 therefore rules out the obvious
    shortcut -- "Not chosen: copying PIM's verifier into SI ... two verifiers would drift
    into two meanings of the same file" -- and LIC-3 places the verifier here, "beside
    sync/_AitRings.ps1 as shared code that PIM and SI both call, with each solution keeping
    only its own feature list."

    So this file owns VERIFICATION. It deliberately owns nothing else:

      here (framework)     : signature, validity window, grace, tenant binding, feature match
      per solution         : the feature CATALOG, and what a gated feature does when refused

    File format, as emitted by TOOLS/New-AitLicense.ps1:
      { "product": "...", "payloadB64": "<b64 payload JSON>", "signature": "<b64 RSA sig>" }
      payload: { licenseId, customer, sku, features[], tenantIds[], validFrom, validTo, graceDays }

    Signature is RSA-SHA256 / PKCS#1 over the RAW PAYLOAD BYTES -- verified against the exact
    payloadB64 bytes, never a re-serialised object, so JSON canonicalisation can never change
    the answer.

    🔒 OFFLINE. No activation, no call-home, no endpoint. Customers on locked-down automation
    servers need nothing but the file. Only the PUBLIC certificate is embedded; the private key
    never leaves mgmt1.

    🪤 SIGNED != FOUND (LIC-1 first issuance, 2026-09-05). The crypto half of a migration can
    land while the DISCOVERY half does not, and the symptom -- Status=Missing -- is EXACTLY the
    quiet resting state of an unlicensed install. The failure mode of a licensing system is
    indistinguishable from its correct idle state, so discovery is treated as a first-class
    concern here and tested on its own.

.NOTES
    PS 5.1: the certificate is loaded from raw bytes (X509Certificate2) and RSA comes via
    RSACertificateExtensions. NOT RSA.ImportFromPem -- that is .NET Core 3.0+ / PS 7 only and
    would break every customer engine, which run on 5.1.
#>

Set-StrictMode -Off

# Public certificate of the framework licensing signer, CN=AutomateIT-Licensing-Service.
# PUBLIC half only. Byte-identical to the copy PIM embeds, so a licence issued by
# TOOLS/New-AitLicense.ps1 verifies the same under either until PIM migrates onto this file.
$script:AitLicenseSignerCertB64 = 'MIIFFzCCAv+gAwIBAgIQNY8l3/KZOoxF7K1nXIXwazANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxBdXRvbWF0ZUlULUxpY2Vuc2luZy1TZXJ2aWNlMB4XDTI2MDgxMTEzMDY0NloXDTQ2MDgxMTEzMTE0NlowJzElMCMGA1UEAwwcQXV0b21hdGVJVC1MaWNlbnNpbmctU2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALuth8WywLfudbaoZ6eR570apvs5LXzOeGfl5Z14z6Nl6DQgvwMLXG/8lZEHOCKsHWVtEnjZOZigsh4c16owJVhuW67OgY0Iy6OjmfeXzu+kcTICSdZ+Qj3ecsGp1Cz6Xo1AjYbgIORdqUBncy4BAuA1bxH0E+V+1zT+ltEk840xpLdWde+m7W8q7BrG9klh+xQl8xJTjeliyV0JN2mvBjI0JwB9t9vL2/luMWWtHp752/ZG4Icd9u6HyqSR/xEmlZIjkZwI7LEPLTICXV1iA3c3nFUEHkLhLlpDW6EQn3cip0Sijr7SVWEBH1fCA8vCo+PxIEgJc3RXaeRhqD4UOwPJIziHtrpy8+9L15zrhXnhIGZv2mUAHKiamUIOmKl9vj31vFp/vJx1chE0XA358T09HGu0jKgSbbC4afKQPKf3v+BHPU42T/xIOPMxDJWuFqKvr4anL7P5PEkTjycBRCkXnIPC5PlrXR/ZZz4oit4WKhbdzONYwb8CKnsF2Z9IVL9yviVJxAIr7kiGqRme9+H0t5A+hzAydxdFMQnop+R8Q02a0sei9WrdtCbwLempVVrXIS6N4hh5kvLqMouDi62b0h645UNk2cWahDIZWTKd/MYdlcdrtRt5muy2LOasHByVxUrZKwH7IetCmv+Kkm1BfMF6Fvi1Jh2Qgz4bo5XJAgMBAAGjPzA9MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT+IiWP1iqSIwaRLiV1somJAQ+ELjANBgkqhkiG9w0BAQsFAAOCAgEAFiDfl7nhDNIywkCZgu9iw0RtJUyJqiq8y+fXomucqowAQZKPhkpuHftZZjtDe09WM35TqjRgL7hqmJiEgqPlRrAv78FjE41RwMcANN2PVCrdcMcuDVdRbS40rObpp0B6+uVUiWY4+8MW6G8Wv+7CIBUEP8ypo3BhxQJZLpyJDKLNiPqnTVKOmYXe7BivfVz63F2Pg2dNXic1poQ7S6JTi/8FM4AV2Ge/zVQF+LaiIuBDJX3JjHnKXxNf1Zhk8PF6DeWaVSNyXtjESlaUfsz0U2Ue87UUZ8ELIuqjHTpG66HPInblBZme6VvR13n5QxmnvjPXdtmXAJzDzCf+76labSGQu9fMFxUoKwjAwT9vHrdFw8JEStappW7urXj+Oafp1wVafJOXzjd9utr8WT3AhaPeqMx3FYH20e2b7QNCI3owtm0ogHRg36neahe78PikiMe15AUpD3+BD6pKeLV7tsExeXZjxDxhFUSpScD0TrCOUEJdKL2Cfx8rM3ceISSiTTYmuJmU7fznQ122A6GNW58mpSk8miPYb3MzbLW0JFPRrEDiyT8dW1M9s98DL+7VR0z2QxgxhNMKyrVgBM7YgQtbtPLz26NBqAQsqG50rOdn7XmprzvnTmnb+r2PUQuqb6rCTAQFTJ3MjH7BviP3GkwJyvzMZ+S6OnUAGB2Fn3Y='

# LIC-4 (operator 2026-10-03): the Invardia licence signer, CN=Invardia-Licensing (thumbprint BA65E6AA62128EBE89A743722E404980F6D2878D,
# RSA 4096, valid to 2036-10-03). PUBLIC half only. Trusted ALONGSIDE the AutomateIT signer above -- never instead of it -- so
# every licence already issued keeps verifying, and Invardia switches its signer only after this release is rolled out.
# Byte-identical to the copy PIM embeds (engine/_shared/PIM-License.ps1) and to SI's copy of this file.
$script:AitLicenseInvardiaCertB64 = 'MIIFQDCCAyigAwIBAgIQXXs1IY0ZQE2MwtugYutXwDANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwHhcNMjYxMDAzMTY1NDMxWhcNMzYxMDAzMTcwNDMxWjAdMRswGQYDVQQDExJJbnZhcmRpYS1MaWNlbnNpbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCn9X21WYLer9r3ojq9lCP3eGV5YK8UMHoyyGT/q8carwQK+ztBRweKAgHyg8rr67utZ1zZBDRei64T/63nXGZpC666efzNZjIU+Og7vtO0bTNjQm/yVD/Q4KFZachYbE5orU+99HQcgRrcwnmmltyazyun2MV2CTk2nUDeMX5IIFD/1yIT8SLNFa6b6Gy4Ms/TIlc4u3lEH3zjbTSF+phSrbv7J6ytz5Eq1ahRkKHWcdBoF9GJo2ynWP0vTGHWvvjNdeVpXP1rkGnLt9MAQj2Us/2XiTgZzf26QLNiXX9YeJeUA9IVdPWczJav+YYkcICyG4ynwhPCudI6S2iDeu8jyL54gfVT871/+RFebzKHq9teY2vB0aGsbaW9VOmV5dDQ2mVfQLFTkNd1ByeZKv9tR0vPfaiZCza+DedApF2LfoAa7Y34pb9WHGRJFAPVmG2WMSsTY90Y0VBYrktF4g4q712W2ZdQc+QIxtvP5nsz6bk1QBvJ1Hcsr/euiysxmkFxcl3NH7WM1EKzdzUaYDJpysoE9e0jkjdJpb9bNNmSE7V9IMTk7r/XOiYJ+8qOALTgwUIEyOLi/hfOihJDRn31aJ6aPvzCEYikueJV5oALrDxquiXbPi8z10aMuXLL4hfi6B7U0qo2kOTPQ9Qh/cJFVkV9pEXjtY+NwwI9EtxgaQIDAQABo3wwejAOBgNVHQ8BAf8EBAMCB4AwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHwYDVR0jBBgwFoAUuZzWkYh3hkE0oJH42LneYVKXIzowHQYDVR0OBBYEFLmc1pGId4ZBNKCR+Ni53mFSlyM6MA0GCSqGSIb3DQEBCwUAA4ICAQCluVZnotzEyS5ux+4hMuz9mOfpSJCNg5nkS8XxIHySiE2AEjVT4ZFEyykZUFoROv5clLBkO5icvDDRBitkeKHvioZruRPtVGy0fs0VxJ4VMcOU/i5cVdJXBQeyUFE8o//4+7FXZp10ToVNv/drjdO7adcNHRVjsddm2mXPNyHmE07ErV6eInPj+r0/1dogPBW1knF+T53RTwT2O0Ppe5qK0QEdBfo5sf4nvjg7ONNXYlW38SzXGLsXy6TZphRWqxLq7u31HAwujQGy9syO+TPIzusH1WHkCsvjDDRXNI8iYhKcS2wq/P/O6O4Ebt/PFN0hxyzyuYx4kreXKKhqrfsEMDxzMUQNnUEjFgU4/4atLVJpBvoDmb/MuQDIzlhxz8obAJi5BuxyjyemR9jg6XMIE2IAhe1v+MN0ZY58tbZR3t5rF30tp541NRaJfn4DBpqNmAIFyDQMdM2FogkFoOV+Mo0IBmGzV/jyv/2z+sre1P5MncLP2qZhfFmu595gWnNoOsMdUZmEWMkbISMGvGzfpPRF3IBan+fymCZSsKNB00E3W50Sh/t2sopEYc3eSwpu6bhvPUgB2ZKU6KN49Al4Pf41uldHVY0aVVp+kpLmRntDFzkTNXUG4OWOwF5gHuGY8jIrwDR7pCPSNzDWrUf857O6DyWEsHXERWg5OPLNUg=='

# Every trusted signer, in the order they are tried (a licence is valid if ANY of them verifies it).
$script:AitLicenseTrustedCertsB64 = @($script:AitLicenseSignerCertB64, $script:AitLicenseInvardiaCertB64)

# Extensions a licence may use, MOST SPECIFIC FIRST. A solution-specific file wins a tie so an
# existing per-solution licence keeps precedence over a framework-wide one in the same folder.
$script:AitLicenseExtensions = @('.pimlicense', '.silicense', '.aitlicense')

<#
.SYNOPSIS
    PURE. Verify an RSA-SHA256/PKCS#1 signature over raw payload bytes.

.DESCRIPTION
    Returns $true only on a genuine match. Every failure path -- malformed certificate,
    unusable key, bad signature -- returns $false rather than throwing, because a verifier
    that throws on a tampered file turns "refuse this licence" into "crash the engine".
#>
function Test-AitLicenseSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [Parameter(Mandatory)][string]$PublicCertB64
    )
    try {
        $certBytes = [Convert]::FromBase64String($PublicCertB64)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $certBytes)
        $rsa  = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
        if (-not $rsa) { return $false }
        return $rsa.VerifyData(
            $PayloadBytes,
            $SignatureBytes,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { return $false }
}

<#
.SYNOPSIS
    PURE. Turn a licence document + a clock into a status. No disk, no network.

.DESCRIPTION
    Split out from any file handling deliberately: this is where every rule that matters
    lives, so it must be testable without writing a file. `Get-AitLicense` is the thin
    impure wrapper that finds a file and calls this.

.PARAMETER Document
    The parsed licence object ({ payloadB64, signature }).

.PARAMETER TrustedCertsB64
    Accepted signers, in order. A caller mid-migration passes its legacy key as a second
    entry so anything already issued keeps verifying -- there is no cutover and no reissue.

.PARAMETER Now
    Injected clock. A licence verifier whose tests cannot control time can only be tested
    on the day the fixtures happen to be valid.

.OUTPUTS
    Status: Missing | Invalid | NotYetValid | Valid | Grace | Expired
    Core is NEVER affected by any of them -- see Test-AitLicenseFeature.
#>
function Resolve-AitLicenseStatus {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$Document,
        [Parameter()][AllowNull()][string[]]$TrustedCertsB64,
        [Parameter()][AllowNull()][object]$Now
    )

    $result = [pscustomobject]@{
        Status     = 'Missing'; Reason = 'no licence document supplied'
        Customer   = ''; Sku = 'Core'; LicenseId = ''
        Features   = @(); TenantIds = @()
        ValidFrom  = $null; ValidTo = $null; GraceUntil = $null
    }
    if ($null -eq $Document) { return $result }

    $today = if ($Now) { ([datetime]$Now).Date } else { (Get-Date).Date }
    $certs = @($TrustedCertsB64 | Where-Object { $_ })
    if (-not $certs.Count) { $certs = @($script:AitLicenseTrustedCertsB64) }

    try {
        if (-not $Document.payloadB64 -or -not $Document.signature) {
            throw "not an AutomateIT licence (payloadB64/signature missing)"
        }
        $payloadBytes = [Convert]::FromBase64String("$($Document.payloadB64)")
        $sigBytes     = [Convert]::FromBase64String("$($Document.signature)")

        # Try every trusted signer. Order matters only for speed -- a licence is valid if ANY
        # trusted key verifies it, which is what makes a signer migration a non-event.
        $ok = $false
        foreach ($c in $certs) {
            if (Test-AitLicenseSignature -PayloadBytes $payloadBytes -SignatureBytes $sigBytes -PublicCertB64 $c) { $ok = $true; break }
        }
        if (-not $ok) {
            $result.Status = 'Invalid'
            $result.Reason = 'signature verification FAILED (file tampered, or not issued by a trusted AutomateIT licensing key)'
            return $result
        }

        $p = [System.Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
        $result.Customer  = "$($p.customer)"
        $result.Sku       = "$($p.sku)"
        $result.LicenseId = "$($p.licenseId)"
        $result.Features  = @($p.features  | Where-Object { $_ })
        $result.TenantIds = @($p.tenantIds | Where-Object { $_ })
        # InvariantCulture, always. On da-DK "08/27/2026" parses as day 8 of month 27 and throws;
        # the same locale bug already ate a promotedUtc stamp once (RING-7).
        $result.ValidFrom = [datetime]::Parse("$($p.validFrom)", [System.Globalization.CultureInfo]::InvariantCulture).Date
        $result.ValidTo   = [datetime]::Parse("$($p.validTo)",   [System.Globalization.CultureInfo]::InvariantCulture).Date

        $graceDays = 30
        if ($p.PSObject.Properties.Name -contains 'graceDays' -and "$($p.graceDays)" -match '^\d+$') { $graceDays = [int]$p.graceDays }
        $result.GraceUntil = $result.ValidTo.AddDays($graceDays)

        if     ($today -lt $result.ValidFrom)  { $result.Status = 'NotYetValid'; $result.Reason = "licence starts $($result.ValidFrom.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $result.ValidTo)    { $result.Status = 'Valid';       $result.Reason = "valid until $($result.ValidTo.ToString('yyyy-MM-dd'))" }
        elseif ($today -le $result.GraceUntil) { $result.Status = 'Grace';       $result.Reason = "EXPIRED $($result.ValidTo.ToString('yyyy-MM-dd')) -- grace until $($result.GraceUntil.ToString('yyyy-MM-dd')), renew now" }
        else                                   { $result.Status = 'Expired';     $result.Reason = "expired $($result.ValidTo.ToString('yyyy-MM-dd')) (grace ended $($result.GraceUntil.ToString('yyyy-MM-dd')))" }
    } catch {
        $result.Status = 'Invalid'
        $result.Reason = "licence could not be read: $($_.Exception.Message)"
    }
    return $result
}

<#
.SYNOPSIS
    PURE. Is this licence bound to the tenant we are actually running against?

.DESCRIPTION
    An EMPTY or absent tenantIds list means "any tenant" -- that is the deliberate shape for
    a site licence. A non-empty list binds, and the binding is the Entra tenant GUID.

    🔒 A licence that names other tenants is NOT a licence for this one. That is the whole
    point of binding, and it is why LIC-2 refuses to let a per-tenant licence be baked into a
    build context shared by three tenants' images.
#>
function Test-AitLicenseTenant {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$License,
        [Parameter()][AllowNull()][string]$TenantId
    )
    if ($null -eq $License) { return $false }
    $ids = @($License.TenantIds | Where-Object { $_ })
    # LIC anti-copy (operator 2026-10-03): a licence that names NO tenant is valid in NO tenant -- it used to be valid in
    # every tenant, which made a copied file work anywhere. Every licence ever issued names its tenant(s).
    if (-not $ids.Count) { return $false }
    if (-not "$TenantId".Trim()) { return $false }      # bound, but we do not know who we are
    foreach ($i in $ids) { if ("$i".Trim() -ieq "$TenantId".Trim()) { return $true } }
    return $false
}

<#
.SYNOPSIS
    PURE. May this feature run?

.DESCRIPTION
    🔒 THE INVARIANT (LIC-1): a REQUIRED capability must never be Pro, and Core is never
    affected by licence state. So this answers only for features a catalog has declared Pro;
    everything else is free and must never be routed through here.

    Grace counts as entitled -- that is what a grace window is for. Expired and Invalid do not.
    '*' in the feature list means every Pro feature, which is how a site licence is expressed.

.PARAMETER Enforce
    🔒 ENFORCEMENT SHIPS OFF (LIC-1). With -Enforce absent, this returns $true with a reason
    saying so: every feature behaves as though licensed, with no nag. That is what makes it
    safe to issue licences to all ~30 customers and populate the registry BEFORE anything is
    gated -- the rollout and the enforcement are separate events, and only the second one can
    break somebody.
#>
function Test-AitLicenseFeature {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$License,
        [Parameter(Mandatory)][string]$Feature,
        [Parameter()][AllowNull()][string]$TenantId,
        [switch]$Enforce
    )

    if (-not $Enforce) {
        return [pscustomobject]@{ Allowed = $true; Reason = 'enforcement is OFF -- every feature runs (LIC-1 default posture)' }
    }
    if ($null -eq $License -or $License.Status -notin @('Valid', 'Grace')) {
        $st = if ($License) { "$($License.Status)" } else { 'Missing' }
        return [pscustomobject]@{ Allowed = $false; Reason = "no entitlement: licence status is $st" }
    }
    if (-not (Test-AitLicenseTenant -License $License -TenantId $TenantId)) {
        return [pscustomobject]@{ Allowed = $false; Reason = "licence '$($License.Customer)' is not valid for tenant $TenantId" }
    }
    $feats = @($License.Features | Where-Object { $_ })
    if ($feats -contains '*')       { return [pscustomobject]@{ Allowed = $true; Reason = "site licence ('*') covers '$Feature'" } }
    foreach ($f in $feats) { if ("$f".Trim() -ieq "$Feature".Trim()) { return [pscustomobject]@{ Allowed = $true; Reason = "licensed for '$Feature'" } } }
    return [pscustomobject]@{ Allowed = $false; Reason = "licence does not include feature '$Feature'" }
}

<#
.SYNOPSIS
    Find a licence file in a directory. IMPURE (disk), and separated for exactly that reason.

.DESCRIPTION
    🪤 THIS FUNCTION IS WHY LIC-1's FIRST ISSUANCE FAILED. The issuer wrote
    `<customer>.aitlicense` while discovery globbed `*.pimlicense` only, so a correctly signed
    licence reported Status=Missing -- indistinguishable from having no licence at all.
    Accept EVERY known extension, most specific first.
#>
function Find-AitLicenseFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Directory)

    if (-not (Test-Path -LiteralPath $Directory)) { return $null }
    $rank = @{}
    for ($i = 0; $i -lt $script:AitLicenseExtensions.Count; $i++) { $rank[$script:AitLicenseExtensions[$i]] = $i }

    $f = Get-ChildItem -LiteralPath $Directory -File -ErrorAction SilentlyContinue |
             Where-Object { $script:AitLicenseExtensions -contains $_.Extension.ToLowerInvariant() } |
             Sort-Object @{ Expression = { $rank[$_.Extension.ToLowerInvariant()] } }, Name |
             Select-Object -First 1
    if ($f) { return $f.FullName }
    return $null
}

<#
.SYNOPSIS
    Load + verify a licence. The thin impure wrapper over Resolve-AitLicenseStatus.

.PARAMETER Path
    A specific licence file. Wins over -Directory, and is what tests use.

.PARAMETER Directory
    Where to look when no -Path is given.
#>
function Get-AitLicense {
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][string]$Path,
        [Parameter()][AllowNull()][string]$Directory,
        [Parameter()][AllowNull()][string[]]$TrustedCertsB64,
        [Parameter()][AllowNull()][object]$Now
    )

    $file = if ("$Path".Trim()) { $Path } elseif ("$Directory".Trim()) { Find-AitLicenseFile -Directory $Directory } else { $null }

    if (-not $file -or -not (Test-Path -LiteralPath $file)) {
        $r = Resolve-AitLicenseStatus -Document $null -TrustedCertsB64 $TrustedCertsB64 -Now $Now
        $r.Reason = 'no .pimlicense / .silicense / .aitlicense file found'
        Add-Member -InputObject $r -NotePropertyName Path -NotePropertyValue '' -Force
        return $r
    }

    $doc = $null
    try { $doc = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $doc = $null }
    $res = Resolve-AitLicenseStatus -Document $doc -TrustedCertsB64 $TrustedCertsB64 -Now $Now
    if ($null -eq $doc) { $res.Status = 'Invalid'; $res.Reason = 'licence file is not readable JSON' }
    Add-Member -InputObject $res -NotePropertyName Path -NotePropertyValue $file -Force
    return $res
}
