#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- Microsoft Graph / MDE / Defender token helper.

    Three paths, tried in order:
      1. User Assigned Managed Identity (production / Container App Job)
         -- when $env:IDENTITY_ENDPOINT and $env:IDENTITY_HEADER are set
         (Container Apps injects these), we hit the local IMDS endpoint
         to mint a token. No secrets, no rotation overhead.
      2. SPN with secret (production / dev VM)
         -- pulls from $global:SI_Graph_AppId + $global:SI_Graph_TenantId
         + $global:SI_Graph_Secret. Uses the v2 token endpoint directly.
      3. The run's own sign-in (last resort)
         -- Get-SIAzAccessToken, over REST (no PowerShell module).

    Bootstrap-Auth.ps1 populates the SI_Graph_* globals from the customer's
    Key Vault (Modern-ApplicationId-O365 / Modern-Secret-O365).
    Bootstrap-ContainerAppJob.ps1 -UseManagedIdentity assigns ONE user-assigned
    identity to every engine job (#209); the container entry point then sets
    $global:SI_UseManagedIdentity + SI_UAMI_ClientId and this helper takes the
    identity endpoint (auth/SI-ManagedIdentity.ps1) before anything else.

    Tokens are cached for 50 minutes (Graph token TTL is 60-90 minutes;
    50-minute cache leaves a safety margin).
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }

if (-not (Get-Variable -Name SIGraphTokenCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SIGraphTokenCache = @{}    # resourceUrl -> @{ Token; ExpiresAt }
}

function Get-SIGraphToken {
    [CmdletBinding()]
    param(
        [ValidateSet('Graph','MDE','Defender','SentinelDataLake')]
        [string]$Resource = 'Graph',

        [switch]$ForceRefresh
    )

    $resourceUrl = switch ($Resource) {
        'Graph'            { 'https://graph.microsoft.com' }
        'MDE'              { 'https://api.security.microsoft.com' }
        'Defender'         { 'https://api.securitycenter.microsoft.com' }
        'SentinelDataLake' { 'https://api.securityplatform.microsoft.com' }
    }

    # The cache is created HERE, not only when this file loads: `$script:` is the scope of the SCRIPT that is running, and
    # a script started from another one (the data health check, started by the verification engine) has its own -- this
    # function is visible there, the file-level cache is not. Measured live 2026-10-15 (the first data health run): "You
    # cannot call a method on a null-valued expression" on every Graph and Defender read. (auth\SI-ManagedIdentity.ps1
    # has the same guard for the same reason.)
    if ($null -eq $script:SIGraphTokenCache) { $script:SIGraphTokenCache = @{} }
    if (-not $ForceRefresh -and $script:SIGraphTokenCache.ContainsKey($resourceUrl)) {
        $cached = $script:SIGraphTokenCache[$resourceUrl]
        if ($cached.ExpiresAt -gt [datetime]::UtcNow) {
            return $cached.Token
        }
    }

    # #209/#222 -- the MANAGED IDENTITY, first, and ONLY when the run's one switch is on ($global:SI_UseManagedIdentity,
    # set by the container entry point, or on a VM by the sign-in decision in the config loader). The client id is
    # optional; auth/SI-ManagedIdentity.ps1 picks the host's endpoint (container, Azure VM, Azure Arc server). When the
    # helper is not loaded, Test-SIUseManagedIdentity does not exist and nothing below this block changes.
    if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
        # The data lake's resource is its app id (see the SPN branch below for why).
        $miResource = if ($Resource -eq 'SentinelDataLake') { '4500ebfb-89b6-4b14-a480-7f749797bfcd' } else { $resourceUrl }
        $tokenStr = Get-SIManagedIdentityToken -Resource $miResource -ForceRefresh:$ForceRefresh
        $script:SIGraphTokenCache[$resourceUrl] = @{ Token = $tokenStr; ExpiresAt = [datetime]::UtcNow.AddMinutes(30) }
        return $tokenStr
    }

    # SPN-secret is the primary path. Read SI_SPN_* (new names)
    # with backwards-compat fallback to SI_Graph_*.
    # UAMI/IMDS is now opt-in (only when $global:SI_PreferUami = $true) --
    # SPN replication across tenants is more flexible than UAMI.
    $spnAppId    = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_Graph_AppId }
    $spnSecret   = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_Graph_Secret }
    $spnTenantId = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_Graph_TenantId }

    # Certificate, resolved the same way every other SI engine resolves it. Also accept the
    # AutomationFramework's HighPriv_* name, because on an internal install that is the ONLY place the
    # thumbprint exists -- which is exactly how a cert customer ended up with no first-class token path.
    $spnCertThumb = if ($global:SI_SPN_CertThumbprint) { [string]$global:SI_SPN_CertThumbprint }
                    else { [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

    # SPN with secret (PRIMARY path ).
    if ($spnAppId -and $spnSecret -and $spnTenantId) {
        # SentinelDataLake's resource principal isn't registered under a URI in
        # most tenants -- AADSTS500011 if you ask for the URL. Microsoft docs the
        # data-lake service principal as the GUID below; use it as the v2 scope
        # identifier. Other resources still resolve fine via their URL.
        $scope = if ($Resource -eq 'SentinelDataLake') {
                     '4500ebfb-89b6-4b14-a480-7f749797bfcd/.default'
                 } else {
                     ($resourceUrl + '/.default')
                 }
        $body = @{
            client_id     = $spnAppId
            scope         = $scope
            client_secret = $spnSecret
            grant_type    = 'client_credentials'
        }
        $resp = Invoke-RestMethod -Method Post `
            -Uri ('https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $spnTenantId) `
            -Body $body -ContentType 'application/x-www-form-urlencoded'
        $tokenStr = $resp.access_token
        $expiresAt = [datetime]::UtcNow.AddSeconds(($resp.expires_in - 600))
    }
    elseif ($spnAppId -and $spnCertThumb -and $spnTenantId) {
        # SPN with CERTIFICATE -- first-class, same client_credentials grant as the secret path above,
        # signed with a JWT client assertion instead of a shared secret.
        #
        # WHY THIS EXISTS. Before this, a certificate-authenticated customer had no SPN path at all: the
        # secret branch was skipped (no secret) and the run fell through to the interactive-Az fallback,
        # which failed with the opaque "ClientCertificateCredential authentication failed:" -- no AADSTS
        # code, no scope, nothing to act on. Observed live on a customer whose Sentinel data lake route
        # died on that line, which then forced every RA query onto advanced hunting, the one path that
        # HAS a 900s ceiling.
        #
        # NOTE ON SCOPE, so this is not misread: making the certificate path first-class does not by
        # itself grant the SPN anything. If the app registration is not consented for the resource, this
        # branch now returns a real AADSTS error naming the missing grant, instead of the opaque
        # credential failure above. Diagnosable rather than silent -- that is the improvement.
        $scope = if ($Resource -eq 'SentinelDataLake') {
                     '4500ebfb-89b6-4b14-a480-7f749797bfcd/.default'
                 } else {
                     ($resourceUrl + '/.default')
                 }

        $clean = ($spnCertThumb -replace '\s','').ToUpperInvariant()
        $cert  = $null

        # 🔴 THE `Cert:` PROVIDER IS THE CONVENIENCE; `X509Store` IS THE AUTHORITY. This is framework
        # finding AUTH-1, and until 2026-08-31 this function only used the provider.
        #
        # 🪤 THE PROVIDER IS NOT ALWAYS THERE. A Windows PowerShell 5.1 child that inherits a pwsh 7
        # parent's PSModulePath resolves Microsoft.PowerShell.Security to the PS7 build, fails to load
        # it, and LOSES THE `Cert:` DRIVE WITH IT -- so `Get-ChildItem Cert:\LocalMachine\My` returns
        # nothing for a certificate that is installed, readable and has a private key. The failure then
        # reads as "the certificate is missing", which sends someone to re-issue a certificate that was
        # never gone.
        #
        # 📌 MEASURED HERE 2026-08-31: the identity profiler failed with
        # `certificate '78E4…' was not found with a private key`, while the SAME thumbprint resolved
        # via BOTH paths from a directly-invoked shell in the same session. The difference was only how
        # the process was launched. `SI-ObjectLedgerStore.ps1` already carried this workaround; the auth
        # path every engine depends on did not.
        foreach ($store in 'LocalMachine','CurrentUser') {
            if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
                $cert = Get-ChildItem "Cert:\$store\My" -ErrorAction SilentlyContinue |
                        Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
                        Select-Object -First 1
            }
            if (-not $cert) {
                try {
                    $x = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $store)
                    $x.Open('ReadOnly')
                    $cert = @($x.Certificates | Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey })[0]
                    $x.Close()
                } catch { }
            }
            if ($cert) { break }
        }
        if (-not $cert) {
            # 🪤 THE MESSAGE USED TO PRINT THE LITERAL `{0}`, AND THAT COST A DIAGNOSIS.
            # `"A" + "B" -f $x` parses as `"A" + ("B" -f $x)`, so the placeholder in the FIRST literal
            # was never substituted and the error named no thumbprint at all -- on the one failure
            # whose entire question is "which thumbprint?". Parenthesise the concatenation before -f.
            # 🔑 And distinguish the case that actually bit: an EMPTY thumbprint is not a missing
            # certificate, it is a missing CONFIGURATION, and sending someone to the certificate store
            # to look for '' wastes the trip.
            if ([string]::IsNullOrWhiteSpace($clean)) {
                throw ("Get-SIGraphToken: no certificate thumbprint is configured, so there is nothing to look for. " +
                       "On the internal-vm flavour this comes from Connect-Platform / Initialize-PlatformAutomationFramework " +
                       "(HighPriv_Modern_CertificateThumbprint_Azure); on community installs from " +
                       "config\SecurityInsight.custom.ps1 (SI_SPN_CertThumbprint). Running an engine standalone, " +
                       "without the platform connect, reaches here.")
            }
            throw (("Get-SIGraphToken: certificate '{0}' was not found with a private key in LocalMachine\My or CurrentUser\My. " +
                    "Note that a sandboxed or restricted-profile shell can report BOTH stores as empty.") -f $clean)
        }

        $tokenUri = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $spnTenantId
        $now      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        # base64url, per RFC 7515: standard base64 with +/ swapped for -_ and the padding stripped.
        $b64url = {
            param([byte[]]$Bytes)
            [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
        }

        # x5t is the cert's SHA-1 thumbprint as base64url BYTES -- not the hex string. Passing the hex
        # yields AADSTS700027 with no hint that the encoding is what is wrong.
        $x5t = & $b64url $cert.GetCertHash()

        $header = @{ alg = 'RS256'; typ = 'JWT'; x5t = $x5t } | ConvertTo-Json -Compress
        # aud/iss/sub/jti/nbf/exp per the client-assertion spec. 10-minute life: the assertion is used
        # once, immediately, so a short window costs nothing and limits replay.
        $claims = @{
            aud = $tokenUri
            iss = $spnAppId
            sub = $spnAppId
            jti = [guid]::NewGuid().ToString()
            nbf = $now
            exp = $now + 600
        } | ConvertTo-Json -Compress

        $enc         = [System.Text.Encoding]::UTF8
        $signingInput = ('{0}.{1}' -f (& $b64url $enc.GetBytes($header)), (& $b64url $enc.GetBytes($claims)))

        # GetRSAPrivateKey (not the legacy .PrivateKey property): CNG-stored keys return $null from
        # .PrivateKey on PS 5.1, and most modern certs are CNG. Do NOT reach for ImportFromPem here --
        # it is .NET Core 3.0+ / PS 7 only and these engines run on Windows PowerShell 5.1.
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if (-not $rsa) {
            throw (("Get-SIGraphToken: certificate '{0}' has no usable RSA private key (GetRSAPrivateKey returned null). " +
                    "If the key is CNG-stored, confirm this account has read access to it.") -f $clean)
        }
        $sig = $rsa.SignData($enc.GetBytes($signingInput),
                             [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                             [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $assertion = '{0}.{1}' -f $signingInput, (& $b64url $sig)

        $body = @{
            client_id             = $spnAppId
            scope                 = $scope
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $assertion
            grant_type            = 'client_credentials'
        }
        $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $tokenStr  = $resp.access_token
        $expiresAt = [datetime]::UtcNow.AddSeconds(($resp.expires_in - 600))
    }
    else {
        # Last resort -- the run's own sign-in, over REST.
        $azTok = Get-SIAzAccessToken -ResourceUrl $resourceUrl
        if ($azTok.Token -is [System.Security.SecureString]) {
            $tokenStr = [System.Net.NetworkCredential]::new('', $azTok.Token).Password
        } else {
            $tokenStr = $azTok.Token
        }
        # Cache until the token's OWN expiry less a margin. A flat 50 minutes outlived tokens a
        # token cache handed back part-used (e.g. 10 minutes left), and every call for the next ~40
        # minutes then sent an expired token.
        $expiresAt = [datetime]::UtcNow.AddMinutes(50)
        try {
            if ($azTok.ExpiresOn) {
                $tokExp = ([DateTimeOffset]$azTok.ExpiresOn).UtcDateTime.AddMinutes(-5)
                if ($tokExp -lt $expiresAt) { $expiresAt = $tokExp }
            }
        } catch {}
    }

    $script:SIGraphTokenCache[$resourceUrl] = @{
        Token     = $tokenStr
        ExpiresAt = $expiresAt
    }
    return $tokenStr
}
