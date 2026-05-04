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
      3. Interactive Az context (developer first-run fallback)
         -- uses current Az.Accounts session via Get-AzAccessToken.

    Bootstrap-Auth.ps1 populates the SI_Graph_* globals from the customer's
    Key Vault (Modern-ApplicationId-O365 / Modern-Secret-O365).
    Bootstrap-ContainerAppJob.ps1 -UseManagedIdentity creates a UAMI per
    engine and assigns it to the Container App Job; the IDENTITY_ENDPOINT
    env vars then steer this helper to the IMDS path.

    Tokens are cached for 50 minutes (Graph token TTL is 60-90 minutes;
    50-minute cache leaves a safety margin).
#>

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

    if (-not $ForceRefresh -and $script:SIGraphTokenCache.ContainsKey($resourceUrl)) {
        $cached = $script:SIGraphTokenCache[$resourceUrl]
        if ($cached.ExpiresAt -gt [datetime]::UtcNow) {
            return $cached.Token
        }
    }

    # SPN-secret is the primary path. Read SI_SPN_* (new names)
    # with backwards-compat fallback to SI_Graph_*.
    # UAMI/IMDS is now opt-in (only when $global:SI_PreferUami = $true) --
    # SPN replication across tenants is more flexible than UAMI.
    $spnAppId    = if ($global:SI_SPN_AppId)    { $global:SI_SPN_AppId }    else { $global:SI_Graph_AppId }
    $spnSecret   = if ($global:SI_SPN_Secret)   { $global:SI_SPN_Secret }   else { $global:SI_Graph_Secret }
    $spnTenantId = if ($global:SI_SPN_TenantId) { $global:SI_SPN_TenantId } else { $global:SI_Graph_TenantId }

    # Optional UAMI path -- legacy / single-tenant deployments.
    if ($global:SI_PreferUami) {
        $imdsEndpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT')
        $imdsHeader   = [Environment]::GetEnvironmentVariable('IDENTITY_HEADER')
        if ($imdsEndpoint -and $imdsHeader) {
            $imdsUrl = ('{0}?resource={1}&api-version=2019-08-01' -f $imdsEndpoint, $resourceUrl)
            if ($global:SI_UAMI_ClientId) {
                $imdsUrl += ('&client_id={0}' -f $global:SI_UAMI_ClientId)
            }
            $resp = Invoke-RestMethod -Method Get -Uri $imdsUrl -Headers @{ 'X-IDENTITY-HEADER' = $imdsHeader }
            $tokenStr  = $resp.access_token
            $expiresAt = [datetime]::UtcNow.AddSeconds(($resp.expires_in - 600))
            $script:SIGraphTokenCache[$resourceUrl] = @{ Token = $tokenStr; ExpiresAt = $expiresAt }
            return $tokenStr
        }
    }

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
    else {
        # Last-resort dev fallback -- interactive Az context.
        $azTok = Get-AzAccessToken -ResourceUrl $resourceUrl
        if ($azTok.Token -is [System.Security.SecureString]) {
            $tokenStr = [System.Net.NetworkCredential]::new('', $azTok.Token).Password
        } else {
            $tokenStr = $azTok.Token
        }
        $expiresAt = [datetime]::UtcNow.AddMinutes(50)
    }

    $script:SIGraphTokenCache[$resourceUrl] = @{
        Token     = $tokenStr
        ExpiresAt = $expiresAt
    }
    return $tokenStr
}
