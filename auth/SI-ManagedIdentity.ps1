#Requires -Version 5.1
<#
    SecurityInsight -- sign in with a MANAGED IDENTITY: a container job's (#209), an Azure VM's or an Azure Arc
    server's (#222).

    WHY. An engine container could only sign in with an SPN client SECRET. Internal installs are certificate
    only, and Pro is container only, so a certificate-only customer could not run Pro at all. PIM4EntraPS's
    containers sign in as the job's managed identity; this copies that (PIM: Get-PimManagedIdentityToken).
    #222 (operator 2026-10-03): the managed identity is the DEFAULT everywhere; an SPN stays supported.

    THE ONE SWITCH. A run uses the managed identity when $global:SI_UseManagedIdentity = $true.
        $global:SI_UAMI_ClientId = '<client id>'   optional: a USER-assigned identity; empty = the host's
                                                    system-assigned identity
    Who sets it: the container entry points (when the job has an identity endpoint), and on a VM the sign-in
    decision in the config loader (auth/SI-AuthMethod.ps1). When it is off, every function below either is
    never called or returns "not mine" -- the secret and certificate paths are exactly what they were.
    The host decides the endpoint (Get-SIManagedIdentityHost): container IDENTITY_ENDPOINT + IDENTITY_HEADER;
    Azure Arc IDENTITY_ENDPOINT + IMDS_ENDPOINT (401 challenge file); otherwise the Azure VM endpoint.

    Log ingestion keeps its existing switch ($global:SI_PreferUami + SI_UAMI_ClientId -> -UseManagedIdentity on
    SI's REST ingestion, which mints the token here); the container sets that from the same decision. No second
    identity switch.

    PS 5.1 safe: no ?. / ??.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }

$__siFindCert = Join-Path $PSScriptRoot 'Find-SICertificate.ps1'
if ((Test-Path -LiteralPath $__siFindCert) -and -not (Get-Command Get-SICertificateFromStore -ErrorAction SilentlyContinue)) { . $__siFindCert }

if (-not (Get-Variable -Name SIManagedIdentityTokenCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SIManagedIdentityTokenCache = @{}   # '<clientId>|<resource>' -> @{ Token; ExpiresAt }
}

function Test-SIUseManagedIdentity {
    <# THE switch: this run signs in as a managed identity (a container job's, an Azure VM's or an Azure Arc
       server's -- #222). The client id is optional: empty = the host's SYSTEM-assigned identity. #>
    return [bool]$global:SI_UseManagedIdentity
}

function Get-SIManagedIdentityHost {
    <#
        PURE (reads env only). Which managed-identity endpoint this host has (#222):
          Container -- Azure Container Apps / App Service: IDENTITY_ENDPOINT + IDENTITY_HEADER
          Arc       -- an Azure Arc-enabled server: IDENTITY_ENDPOINT + IMDS_ENDPOINT, no IDENTITY_HEADER (the Arc
                       agent sets both machine-wide); the token needs a challenge-file handshake
          AzureVm   -- an Azure VM (and anything else): the instance metadata endpoint 169.254.169.254
    #>
    param([scriptblock]$GetEnv)
    if (-not $GetEnv) { $GetEnv = { param($n) [Environment]::GetEnvironmentVariable($n) } }
    $ep = [string](& $GetEnv 'IDENTITY_ENDPOINT'); $hd = [string](& $GetEnv 'IDENTITY_HEADER'); $imds = [string](& $GetEnv 'IMDS_ENDPOINT')
    if ($ep -and $hd) { return 'Container' }
    if ($ep -and $imds) { return 'Arc' }
    return 'AzureVm'
}

function Get-SIManagedIdentityToken {
    <#
        A token for -Resource as this host's managed identity (#209 container, #222 Azure VM + Azure Arc):
          Container -- IDENTITY_ENDPOINT + X-IDENTITY-HEADER, api-version 2019-08-01, client_id when known
          AzureVm   -- http://169.254.169.254/metadata/identity/oauth2/token, Metadata: true, client_id when known
          Arc       -- IDENTITY_ENDPOINT (api-version 2020-06-01, Metadata: true): the first call answers 401 with
                       'WWW-Authenticate: Basic realm=<file>'; the file's content is the secret for the second call.
                       Reading it needs local Administrators or the 'Hybrid agent extension applications' group. Arc
                       has the SYSTEM-assigned identity only, so no client_id.

        TRAP: THE client_id IS NOT OPTIONAL IN PRACTICE for a user-assigned identity. PIM measured it (BUG-76): with a
        user-assigned identity only, the endpoint has nothing to default to and the failure surfaces far away as
        "Login failed" / 401. So it is always sent when known.

        Cached per identity + resource until 5 minutes before the token's own expiry. -Invoke is a test seam:
        { param($Uri, $Headers) } returning the endpoint's response (Arc: the @{Status;Body;WwwAuthenticate} shape).
        -ReadFile is a test seam for the Arc challenge file.
    #>
    param(
        [Parameter(Mandatory)][string]$Resource,
        [string]$ClientId,
        [switch]$ForceRefresh,
        [scriptblock]$Invoke,
        [scriptblock]$ReadFile
    )
    # A guided install's own sign-in wins (live 2026-10-06, an AzContext install on an Azure VM got the VM's IMDS token for
    # SQL): while $global:SI_InstallTokenProvider is set, the token comes from it and NO identity endpoint is called.
    $installProvider = Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore
    # Re-entry = the install's sign-in itself IS this host's managed identity (sign-in mode ManagedIdentity): then, and only
    # then, the identity endpoint below answers.
    if (($installProvider -is [scriptblock]) -and -not $global:SI_InstallTokenProviderBusy) {
        $global:SI_InstallTokenProviderBusy = $true
        try { $pt = [string](& $installProvider $Resource) } finally { $global:SI_InstallTokenProviderBusy = $false }
        if ([string]::IsNullOrWhiteSpace($pt)) { throw ("the install's sign-in returned no token for '{0}'." -f $Resource) }
        return $pt
    }
    # SELF-CONTAINED on purpose: it is published to the global scope and may run where this file's other functions are
    # not visible. The host rule is Get-SIManagedIdentityHost's, repeated here.
    $endpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')
    $header   = [Environment]::GetEnvironmentVariable('IDENTITY_HEADER')
    $imdsEp   = [Environment]::GetEnvironmentVariable('IMDS_ENDPOINT')
    $hostKind = if ($endpoint -and $header) { 'Container' } elseif ($endpoint -and $imdsEp) { 'Arc' } else { 'AzureVm' }
    $arcGet = {
        param([string]$U, [hashtable]$H)
        $req = [System.Net.HttpWebRequest]::Create($U)
        $req.Method = 'GET'; $req.Timeout = 60000
        foreach ($k in $H.Keys) { if ($k -eq 'Authorization') { $req.Headers['Authorization'] = [string]$H[$k] } else { $req.Headers.Add($k, [string]$H[$k]) } }
        try { $r = $req.GetResponse() }
        catch [System.Net.WebException] { $r = $_.Exception.Response; if (-not $r) { throw } }
        try {
            $sr = New-Object System.IO.StreamReader($r.GetResponseStream()); $b = $sr.ReadToEnd(); $sr.Close()
            [pscustomobject]@{ Status = [int]$r.StatusCode; Body = $b; WwwAuthenticate = [string]$r.Headers['WWW-Authenticate'] }
        } finally { $r.Close() }
    }
    if ([string]::IsNullOrWhiteSpace($ClientId)) { $ClientId = [string]$global:SI_UAMI_ClientId }
    # The cache is created HERE, not only when this file loads: when this function runs from another scope, `$script:` is
    # that scope and the file-level cache does not exist.
    # Measured live 2026-10-02 (first container run on the identity): "You cannot call a method on a null-valued
    # expression" on every token, and every Log Analytics post failed.
    if ($null -eq $script:SIManagedIdentityTokenCache) { $script:SIManagedIdentityTokenCache = @{} }
    $res = ($Resource -replace '/\.default$', '')
    $key = '{0}|{1}' -f $ClientId, $res
    if (-not $ForceRefresh -and $script:SIManagedIdentityTokenCache.ContainsKey($key)) {
        $c = $script:SIManagedIdentityTokenCache[$key]
        if ($c.ExpiresAt -gt [datetime]::UtcNow) { return $c.Token }
    }

    $resp = $null
    switch ($hostKind) {
        'Container' {
            $uri = '{0}?resource={1}&api-version=2019-08-01' -f $endpoint, [uri]::EscapeDataString($res)
            if (-not [string]::IsNullOrWhiteSpace($ClientId)) { $uri += '&client_id=' + [uri]::EscapeDataString($ClientId) }
            $headers = @{ 'X-IDENTITY-HEADER' = $header }
            $resp = if ($Invoke) { & $Invoke $uri $headers }
                    else { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 60 }
        }
        'AzureVm' {
            $uri = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={0}' -f [uri]::EscapeDataString($res)
            if (-not [string]::IsNullOrWhiteSpace($ClientId)) { $uri += '&client_id=' + [uri]::EscapeDataString($ClientId) }
            $headers = @{ 'Metadata' = 'true' }
            $resp = if ($Invoke) { & $Invoke $uri $headers }
                    else { Invoke-RestMethod -Method Get -Uri $uri -Headers $headers -TimeoutSec 60 }
        }
        'Arc' {
            $uri = '{0}?api-version=2020-06-01&resource={1}' -f $endpoint, [uri]::EscapeDataString($res)
            $first = if ($Invoke) { & $Invoke $uri @{ 'Metadata' = 'true' } } else { & $arcGet $uri @{ 'Metadata' = 'true' } }
            if ([int]$first.Status -ne 401 -or [string]$first.WwwAuthenticate -notmatch '(?i)realm=(.+)$') {
                throw ("managed identity (Azure Arc): expected a 401 challenge from {0}, got {1}. Is the Arc agent running?" -f $endpoint, $first.Status)
            }
            $keyFile = $Matches[1].Trim().Trim('"')
            $secret = $null
            try { $secret = if ($ReadFile) { & $ReadFile $keyFile } else { [System.IO.File]::ReadAllText($keyFile) } }
            catch { throw ("managed identity (Azure Arc): cannot read the challenge file {0} -- the run must be a local Administrator or in the 'Hybrid agent extension applications' group. {1}" -f $keyFile, $_.Exception.Message) }
            $second = if ($Invoke) { & $Invoke $uri @{ 'Metadata' = 'true'; 'Authorization' = ('Basic ' + $secret) } }
                      else { & $arcGet $uri @{ 'Metadata' = 'true'; 'Authorization' = ('Basic ' + $secret) } }
            if ([int]$second.Status -ne 200) { throw ("managed identity (Azure Arc): the identity endpoint refused the token request ({0})." -f $second.Status) }
            $resp = $second.Body | ConvertFrom-Json
        }
    }
    $token = [string]$resp.access_token
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw ("managed identity ({2}): the identity endpoint returned no token for '{0}' (client id {1}). Is that identity assigned to this host / job?" -f $res, $ClientId, $hostKind)
    }

    $expiresAt = [datetime]::UtcNow.AddMinutes(50)
    $epoch = 0L
    if ([long]::TryParse([string]$resp.expires_on, [ref]$epoch) -and $epoch -gt 0) {
        $expiresAt = [DateTimeOffset]::FromUnixTimeSeconds($epoch).UtcDateTime.AddMinutes(-5)
    } else {
        $secs = 0
        if ([int]::TryParse([string]$resp.expires_in, [ref]$secs) -and $secs -gt 600) { $expiresAt = [datetime]::UtcNow.AddSeconds($secs - 300) }
    }
    $script:SIManagedIdentityTokenCache[$key] = @{ Token = $token; ExpiresAt = $expiresAt }
    # #232 -- the licence is checked against the tenant the identity REALLY lives in. A managed identity's token always
    # comes from its home tenant, whatever the configuration claims, so its 'tid' claim is the proof; a configured tenant
    # id is not (a copied licence plus an edited config would otherwise pass). Recorded from every real token.
    try {
        $seg = $token.Split('.')
        if ($seg.Count -ge 2) {
            $p = $seg[1].Replace('-', '+').Replace('_', '/'); while ($p.Length % 4) { $p += '=' }
            $tid = [string](([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))) | ConvertFrom-Json).tid
            if ($tid -match '^[0-9a-fA-F-]{36}$') { $global:SI_IdentityTokenTenantId = $tid.ToLowerInvariant() }
        }
    } catch { }
    try { [System.Console]::Out.WriteLine(("  [mi] token for {0} via the {2} identity endpoint (len {1})" -f $res, $token.Length, $hostKind)) } catch { }
    return $token
}

function Get-SIAccessToken {
    <#
        "A token for resource X as the identity this run uses." The managed identity when the switch is on;
        otherwise the run's own sign-in (Get-SIAzAccessToken, over REST).
    #>
    param([Parameter(Mandatory)][string]$Resource, [switch]$ForceRefresh)
    if (Test-SIUseManagedIdentity) { return (Get-SIManagedIdentityToken -Resource $Resource -ForceRefresh:$ForceRefresh) }
    $t = Get-SIAzAccessToken -ResourceUrl $Resource -ErrorAction Stop
    if ($t.Token -is [System.Security.SecureString]) { return [System.Net.NetworkCredential]::new('', $t.Token).Password }
    return [string]$t.Token
}
