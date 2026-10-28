#Requires -Version 5.1
<#
    Asset tagging's Microsoft Graph and Defender access over plain REST.

    WHY. SecurityInsight v3 carries no PowerShell module dependencies. Asset tagging was the last engine on
    the Microsoft.Graph SDK (Connect-MicrosoftGraphPS -> Connect-MgGraph, Invoke-MgGraphRequest,
    Set-MgRequestContext) and on MicrosoftGraphPS for its Defender token. Everything it did is a handful of
    HTTP calls, so it now makes them itself.

    SAME IDENTITY AS BEFORE. The token is minted for exactly the identity the SDK connect used --
    $global:SpnClientId in $global:SpnTenantId, CERTIFICATE FIRST, then the client secret, and a loud
    refusal when neither is set (an interactive prompt on an unattended host reads as a hang). The
    certificate grant is auth/Find-SICertificate.ps1's Get-SICertificateClientToken, the one every other
    SI engine uses without the Cert: drive.

    SAME RETRY POLICY AS BEFORE, as close as REST allows. The SDK was told
    `Set-MgRequestContext -ClientTimeout 900 -MaxRetry 6`; every Graph call here goes through
    engine/_shared/SI-GraphRest.ps1's Invoke-SIGraphRest with -TimeoutSec 900 -MaxAttempts 6 (429 / 502 /
    503 / 504 / no-response retried, anything else thrown at once).

    -Invoke on Get-ATSpnAccessToken is a test seam: { param($Uri, $Body) } returning the token response.

    MANAGED IDENTITY (#236). When the run signs in as a managed identity ($global:SI_UseManagedIdentity, set by the
    container entry point or by the sign-in decision in auth\SI-AuthMethod.ps1), every token -- Graph, Defender for
    Endpoint and Azure Resource Manager -- comes from the identity endpoint (Get-SIManagedIdentityToken, loaded by the
    host: the container entry point or the launcher's config loader). The SPN paths below (certificate, then secret) are unchanged and still used whenever
    the switch is off.
#>

function Get-ATAuthMode {
    <#
        PURE. How this asset-tagging run signs in, from -Globals (name -> value; the live globals by default):
          ManagedIdentity     -- SI_UseManagedIdentity is on (a container job's identity, an Azure VM's or an Arc server's)
          AutomationFramework -- an internal install: the platform identity (certificate or secret from its Key Vault)
          Certificate         -- SpnClientId + SpnTenantId + SpnCertificateThumbprint
          Secret              -- SpnClientId + SpnTenantId + SpnClientSecret
          None                -- nothing usable (the engine refuses with Reason)
        The managed identity wins when its switch is on: the sign-in decision already chose it.
        Returns @{ Mode; ClientId; Reason }.
    #>
    param([hashtable]$Globals)
    if (-not $Globals) { $Globals = @{}; foreach ($v in (Get-Variable -Scope Global)) { $Globals[$v.Name] = $v.Value } }
    $g = { param($n) if ($Globals.ContainsKey($n)) { $Globals[$n] } else { $null } }
    if ([bool](& $g 'SI_UseManagedIdentity')) {
        $cid = [string](& $g 'SI_UAMI_ClientId')
        if (-not $cid) { $cid = [string](& $g 'SI_ManagedIdentityClientId') }
        $who = if ($cid) { "the user-assigned managed identity $cid" } else { "the host's system-assigned managed identity" }
        return [pscustomobject]@{ Mode = 'ManagedIdentity'; ClientId = $cid; Reason = $who }
    }
    if ([bool](& $g 'AutomationFramework')) {
        return [pscustomobject]@{ Mode = 'AutomationFramework'; ClientId = ''; Reason = 'the platform identity of an internal install' }
    }
    $tid = [string](& $g 'SpnTenantId'); $app = [string](& $g 'SpnClientId')
    $thumb = [string](& $g 'SpnCertificateThumbprint'); $sec = [string](& $g 'SpnClientSecret')
    if ($tid -and $app -and $thumb) { return [pscustomobject]@{ Mode = 'Certificate'; ClientId = $app; Reason = "the SPN $app by certificate" } }
    if ($tid -and $app -and $sec)   { return [pscustomobject]@{ Mode = 'Secret'; ClientId = $app; Reason = "the SPN $app by client secret" } }
    [pscustomobject]@{ Mode = 'None'; ClientId = ''; Reason = 'no sign-in: set SI_AuthMethod = ManagedIdentity, or SpnTenantId + SpnClientId with SpnCertificateThumbprint or SpnClientSecret' }
}

function Get-ATAccessToken {
    <#
        A token for -Resource as the identity this run uses: the managed identity when its switch is on, otherwise the
        SPN (Get-ATSpnAccessToken: certificate first, then the secret). -MiToken is a test seam for the identity endpoint.
    #>
    param([Parameter(Mandatory)][string]$Resource, [scriptblock]$MiToken, [scriptblock]$Invoke)
    if ([bool]$global:SI_UseManagedIdentity) {
        $res = $Resource.TrimEnd('/')
        if ($MiToken) { return [string](& $MiToken $res) }
        # The host loads the identity helper (container entry point / launcher config loader); the engine never does.
        if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) {
            throw 'managed identity sign-in is on, but the identity helper is not loaded -- start asset tagging through its launcher or the container job.'
        }
        return [string](Get-SIManagedIdentityToken -Resource $res -ClientId ([string]$global:SI_UAMI_ClientId))
    }
    return (Get-ATSpnAccessToken -Resource $Resource -Invoke $Invoke)
}

function Get-ATSpnAccessToken {
    <# An app-only token for -Resource ('https://graph.microsoft.com', 'https://api.securitycenter.microsoft.com'). #>
    param(
        [Parameter(Mandatory)][string]$Resource,
        [string]$TenantId              = [string]$global:SpnTenantId,
        [string]$ClientId              = [string]$global:SpnClientId,
        [AllowEmptyString()][string]$CertificateThumbprint = [string]$global:SpnCertificateThumbprint,
        [AllowEmptyString()][string]$ClientSecret          = [string]$global:SpnClientSecret,
        [scriptblock]$Invoke
    )
    $scope = $Resource.TrimEnd('/') + '/.default'
    if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        if (-not (Get-Command -Name Get-SICertificateClientToken -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))), 'auth', 'Find-SICertificate.ps1'))
        }
        return (Get-SICertificateClientToken -TenantId $TenantId -ClientId $ClientId -Thumbprint $CertificateThumbprint -Resource $scope -Invoke $Invoke)
    }
    if (-not [string]::IsNullOrWhiteSpace($ClientSecret)) {
        $uri  = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
        $body = @{ client_id = $ClientId; client_secret = $ClientSecret; scope = $scope; grant_type = 'client_credentials' }
        $resp = if ($Invoke) { & $Invoke $uri $body }
                else { Invoke-RestMethod -Method Post -Uri $uri -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop }
        if (-not $resp.access_token) { throw ("the token endpoint returned no access_token for {0}." -f $Resource) }
        return [string]$resp.access_token
    }
    throw (("Cannot sign in to {0}: neither `$global:SpnCertificateThumbprint nor `$global:SpnClientSecret is set for AppId '{1}' / tenant '{2}'. " +
            "Refusing to fall through to an interactive prompt on an unattended host.") -f $Resource, $ClientId, $TenantId)
}

function Invoke-ATGraphRequest {
    <# One Graph call with asset tagging's token: -Method Get | Post | Patch, -Uri absolute or /v1.0-relative, -Body hashtable. #>
    param(
        [Parameter(Mandatory)][ValidateSet('Get', 'Post', 'Patch')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Body
    )
    if ([string]::IsNullOrWhiteSpace([string]$script:ATGraphToken)) { throw 'Microsoft Graph is not signed in (Connect-GraphHighPriv has not run).' }
    $a = @{ Uri = $Uri; Token = [string]$script:ATGraphToken; Method = $Method; TimeoutSec = 900; MaxAttempts = 6 }
    if ($null -ne $Body) { $a['Body'] = $Body }
    return (Invoke-SIGraphRest @a)
}

function Invoke-ATHuntingQuery {
    <#
        Advanced hunting (POST /security/runHuntingQuery) with asset tagging's token. Returns the result
        rows as they came back, or an empty array.
    #>
    param([Parameter(Mandatory)][string]$Query)
    $resp = Invoke-ATGraphRequest -Method Post -Uri '/security/runHuntingQuery' -Body @{ Query = $Query }
    if ($null -eq $resp) { return @() }
    if ($resp.PSObject.Properties['results'] -and $null -ne $resp.results) { return @($resp.results) }
    return @()
}

function Get-ATDefenderHeaders {
    <#
        Headers for the Defender for Endpoint API (api.securitycenter.microsoft.com), the shape MicrosoftGraphPS'
        Connect-MicrosoftRestApiEndpointPS returned: Content-Type, Accept, Authorization. -SecretOnly keeps the
        caller's "secret first" order (see Get-DefenderAccessHeaders in AssetTagging.ps1).
    #>
    param([switch]$SecretOnly, [scriptblock]$Invoke, [scriptblock]$MiToken)
    if ([bool]$global:SI_UseManagedIdentity) {
        # #236: the managed identity's own token -- no secret and no certificate exist on this path.
        $tok = Get-ATAccessToken -Resource 'https://api.securitycenter.microsoft.com' -MiToken $MiToken
    } else {
        $thumb = if ($SecretOnly) { '' } else { [string]$global:SpnCertificateThumbprint }
        $tok = Get-ATSpnAccessToken -Resource 'https://api.securitycenter.microsoft.com' -CertificateThumbprint $thumb -Invoke $Invoke
    }
    return @{
        'Content-Type' = 'application/json'
        Accept         = 'application/json'
        Authorization  = "Bearer $tok"
    }
}
