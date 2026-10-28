#Requires -Version 5.1
<#
    SecurityInsight -- find the engine SPN's certificate on ANY host, and bring one into a container (#209).

    KEY POINT: THE `Cert:` DRIVE IS A WINDOWS CONVENIENCE; [X509Store] IS THE AUTHORITY. The drive does not exist
    in a Linux container at all (pwsh on Linux has no certificate provider), and on Windows it can vanish
    from a PS 5.1 child that inherited a pwsh 7 PSModulePath (framework finding AUTH-1). Five ingest sites
    looked a thumbprint up through the drive ONLY, so in a container the lookup always "missed", the store
    location fell back to LocalMachine, and certificate sign-in could not work there at all.

    Every function here uses the drive when it exists -- exactly what the engines did before -- and the
    X509Store only when it does not, so a Windows VM with its certificate in LocalMachine\My resolves the
    same certificate, from the same store, as it always has.

    Functions:
      Get-SICertificateFromStore    -- one thumbprint -> @{ Certificate; StoreLocation } or $null
      Get-SICertStoreLocation       -- 'LocalMachine' / 'CurrentUser' for the log-ingestion sign-in (default LocalMachine)
      Get-SICertificateClientToken  -- client_credentials with a certificate-signed assertion (no Cert: drive)
      Import-SIContainerCertificate -- a base64 PFX (Key Vault reference) -> CurrentUser\My + a PFX file

    PS 5.1 safe: no ?. / ??, no ImportFromPem.
#>

function Test-SICertDriveAvailable {
    <# The Windows certificate provider is loaded in this process. A seam for the tests. #>
    return [bool](Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)
}

function Get-SICertificateFromStore {
    <#
        Find a certificate WITH a private key by thumbprint, LocalMachine first, then CurrentUser -- the order
        every SI engine already used. Returns @{ Certificate; StoreLocation } or $null.

        -HasCertDrive and -OpenStore are test seams: -OpenStore takes a store location and returns the
        certificates in its My store.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint,
        [string[]]$StoreLocations = @('LocalMachine', 'CurrentUser'),
        [scriptblock]$HasCertDrive,
        [scriptblock]$OpenStore
    )
    $clean = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($clean)) { return $null }
    if (-not $HasCertDrive) { $HasCertDrive = { Test-SICertDriveAvailable } }
    if (-not $OpenStore) {
        $OpenStore = {
            param([string]$Location)
            $x = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $Location)
            try {
                $x.Open('ReadOnly')
                return @($x.Certificates)
            } finally { $x.Close() }
        }
    }
    $drive = [bool](& $HasCertDrive)
    foreach ($loc in $StoreLocations) {
        $found = $null
        if ($drive) {
            $found = Get-ChildItem "Cert:\$loc\My" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
                     Select-Object -First 1
        } else {
            try {
                $found = @(& $OpenStore $loc | Where-Object { $_ -and $_.Thumbprint -eq $clean -and $_.HasPrivateKey })[0]
            } catch {
                Write-Verbose ("certificate store {0}\My unreadable: {1}" -f $loc, $_.Exception.Message)
            }
        }
        if ($found) { return [pscustomobject]@{ Certificate = $found; StoreLocation = $loc } }
    }
    return $null
}

function Get-SICertStoreLocation {
    <#
        The store the log-ingestion sign-in should be told to look in. Same answer the five ingest sites computed
        through the Cert: drive (LocalMachine when nothing is found), now also right where the drive is
        missing.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Thumbprint,
        [scriptblock]$HasCertDrive,
        [scriptblock]$OpenStore
    )
    $hit = Get-SICertificateFromStore -Thumbprint $Thumbprint -HasCertDrive $HasCertDrive -OpenStore $OpenStore
    if ($hit) { return [string]$hit.StoreLocation }
    return 'LocalMachine'
}

function Get-SICertificateClientToken {
    <#
        An access token for -Resource via client_credentials with a certificate-signed JWT assertion -- the
        grant Get-SIGraphToken and the log ingestion already use, without the Cert: drive. Returns the
        token string. -Invoke is a test seam: { param($Uri, $Body) } returning the token response.
    #>
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$Thumbprint,
        [Parameter(Mandatory)][string]$Resource,
        [scriptblock]$Invoke
    )
    $hit = Get-SICertificateFromStore -Thumbprint $Thumbprint
    if (-not $hit) { throw ("certificate '{0}' was not found with a private key in LocalMachine\My or CurrentUser\My." -f (($Thumbprint -replace '\s', '').ToUpperInvariant())) }
    $cert = $hit.Certificate

    $scope = if ($Resource -match '/\.default$') { $Resource } else { ($Resource.TrimEnd('/') + '/.default') }
    $tokenUri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
    $b64url = { param([byte[]]$Bytes) [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = (& $b64url $cert.GetCertHash()) } | ConvertTo-Json -Compress
    $claims = @{ aud = $tokenUri; iss = $ClientId; sub = $ClientId; jti = [guid]::NewGuid().ToString(); nbf = $now; exp = ($now + 600) } | ConvertTo-Json -Compress
    $enc = [System.Text.Encoding]::UTF8
    $unsigned = '{0}.{1}' -f (& $b64url $enc.GetBytes($header)), (& $b64url $enc.GetBytes($claims))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if (-not $rsa) { throw ("certificate '{0}' has no usable RSA private key." -f $cert.Thumbprint) }
    $sig = $rsa.SignData($enc.GetBytes($unsigned), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $body = @{
        client_id             = $ClientId
        scope                 = $scope
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = ('{0}.{1}' -f $unsigned, (& $b64url $sig))
        grant_type            = 'client_credentials'
    }
    $resp = if ($Invoke) { & $Invoke $tokenUri $body }
            # a time limit: without one this call waits for as long as the other side stays silent (PowerShell 7 has no default)
            else { Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded' -TimeoutSec 60 }
    if (-not $resp.access_token) { throw 'the token endpoint returned no access_token.' }
    return [string]$resp.access_token
}

function Import-SIContainerCertificate {
    <#
        CONTAINER ONLY. The SPN's PFX arrives as a Key Vault-referenced secret (base64), exactly as the SI
        updater receives its own. This puts it where every engine looks:
          * CurrentUser\My, through [X509Store] (the only certificate store a Linux container has), so
            Get-SIGraphToken, the ledger and the log ingestion find it by thumbprint;
          * a PFX file (owner-only), so Connect-SIAzAccount -CertificatePath can sign in with it -- az and
            the sign-in remember the PATH, not the key, so the file is kept for the life of the run.
        Returns @{ Thumbprint; PfxPath }. Never prints the certificate or its password.
    #>
    param(
        [Parameter(Mandatory)][string]$PfxBase64,
        [string]$Password,
        [string]$Directory = [IO.Path]::GetTempPath(),
        [switch]$SkipStore
    )
    $bytes = [Convert]::FromBase64String(($PfxBase64 -replace '\s', ''))
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
             [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    # A Key Vault certificate's secret is a password-less PFX; '' opens those on both .NET hosts.
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes, [string]$Password, $flags)
    if (-not $cert.HasPrivateKey) { throw 'the SPN certificate (SI_SPN_CERT_PFX_B64) carries no private key.' }

    if (-not $SkipStore) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
        try {
            $store.Open('ReadWrite')
            $store.Add($cert)
        } finally { $store.Close() }
    }

    $pfxPath = Join-Path $Directory ('si-spn-' + [guid]::NewGuid().ToString('N') + '.pfx')
    [IO.File]::WriteAllBytes($pfxPath, $bytes)
    if ($PSVersionTable.PSVersion.Major -ge 6 -and -not $IsWindows) { try { & chmod 600 $pfxPath } catch { } }
    return [pscustomobject]@{ Thumbprint = [string]$cert.Thumbprint; PfxPath = $pfxPath }
}
