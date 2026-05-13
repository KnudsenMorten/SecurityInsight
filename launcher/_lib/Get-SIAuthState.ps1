#Requires -Version 5.1
<#
.SYNOPSIS
    Single source-of-truth helper for SecurityInsight engine auth state.

.DESCRIPTION
    Returns a $state object describing which authentication mode is configured
    and the parameters to pass into AzLogDcrIngestPS calls. Engines call this
    helper instead of inlining their own SpnClientSecret-vs-CertThumbprint
    checks -- which historically drifted (v2.2.229 - v2.2.237 fixed five
    separate per-engine gates that each demanded Secret only).

    Single source-of-truth means: a new credential type (cert, MI variant,
    federated identity) lands in ONE file and every engine picks it up.

.OUTPUTS
    pscustomobject @{
        IsConfigured   = [bool]    # true when ANY valid auth method is set
        AuthMode       = [string]  # 'MI' | 'SPN-Cert' | 'SPN-Secret' | 'AF' | 'None'
        AuthParams     = [hashtable]
                                   # splat-ready for Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output,
                                   # CheckCreateUpdate-TableDcr-Structure, Get-AzDcrListAll,
                                   # Get-AzDceListAll, Update-AzDataCollectionRule*, Delete-*
                                   # (every public function in AzLogDcrIngestPS)
        MissingReason  = [string]  # populated when IsConfigured=$false
        TenantId       = [string]  # populated when an SPN/MI/AF auth is configured
        ClientId       = [string]  # populated for SPN paths; null otherwise
        ObjectId       = [string]  # SPN object id for RBAC grants (when known)
    }

.NOTES
    Priority order (highest first):
        1. AutomationFramework  (sets $global:AutomationFramework=$true; v1 chain)
        2. Managed Identity     ($global:SI_PreferUami + $global:SI_UAMI_ClientId)
        3. SPN + Certificate    ($global:SI_SPN_CertThumbprint set; thumbprint trumps secret)
        4. SPN + Secret         ($global:SI_SPN_Secret set, no cert)
        5. SI_LogIngest_*       (legacy fallback when SI_SPN_* unset)

    The bridge in Initialize-LauncherConfig.ps1 mirrors SI_SPN_* onto the
    legacy $global:Spn* names, so an engine can ALSO read $global:Spn* and
    get the same result. This helper reads SI_SPN_* directly (the canonical
    v2.3 names) and falls back to SI_LogIngest_* / Spn* only when needed.
#>

function Resolve-SICertStoreLocation {
    <#
    .SYNOPSIS
    Auto-detect which cert store (LocalMachine\My or CurrentUser\My) holds the
    given thumbprint with a usable private key.

    .DESCRIPTION
    `Connect-AzAccount -CertificateThumbprint` probes both stores automatically,
    but AzLogDcrIngestPS only looks in the store passed via
    -AzAppCertificateStoreLocation (default LocalMachine). When the cert is in
    CurrentUser\My, the engine auth succeeds but LA ingest fails with
    "Certificate with thumbprint '...' was not found in Cert:\LocalMachine\My".

    This helper probes both stores in priority order (LocalMachine first since
    that's the conventional production install) and returns the store that
    holds the cert WITH a private key. Returns 'LocalMachine' as a fallback
    when neither store contains it so the downstream error message stays
    accurate. The customer's $global:SI_SPN_CertStoreLocation always wins.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Thumbprint
    )
    if ([string]::IsNullOrWhiteSpace($Thumbprint)) { return 'LocalMachine' }
    $clean = $Thumbprint -replace '\s', ''
    $lmHit = Get-ChildItem 'Cert:\LocalMachine\My' -ErrorAction SilentlyContinue |
             Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
             Select-Object -First 1
    if ($lmHit) { return 'LocalMachine' }
    $cuHit = Get-ChildItem 'Cert:\CurrentUser\My' -ErrorAction SilentlyContinue |
             Where-Object { $_.Thumbprint -eq $clean -and $_.HasPrivateKey } |
             Select-Object -First 1
    if ($cuHit) {
        # v2.2.243 -- emit ONCE per process so repeated calls don't spam.
        if (-not $script:_SICertStoreWarnedCurrentUser) {
            Write-Warning ("[auth] SPN cert '{0}' was found only in Cert:\CurrentUser\My (HasPrivateKey=True). For production -- and for scheduled-task / SYSTEM service-account use -- install the cert in Cert:\LocalMachine\My so it's available to every account on this host. CurrentUser scope is fine for dev/interactive but will fail when the engine runs as a different account." -f $clean)
            $script:_SICertStoreWarnedCurrentUser = $true
        }
        return 'CurrentUser'
    }
    return 'LocalMachine'
}

function Get-SIAuthState {
    [CmdletBinding()]
    param()

    # ---- AutomationFramework branch (v1 chain has its own session) ----
    if ([bool]$global:AutomationFramework) {
        $afTenant  = if ($global:SpnTenantId)              { [string]$global:SpnTenantId }     else { [string]$global:AzureTenantId }
        $afClient  = if ($global:SpnClientId)              { [string]$global:SpnClientId }     else { [string]$global:HighPriv_Modern_ApplicationID_Azure }
        $afSecret  = if ($global:SpnClientSecret)          { [string]$global:SpnClientSecret } else { [string]$global:HighPriv_Modern_Secret_Azure }
        $afCert    = if ($global:SpnCertificateThumbprint) { [string]$global:SpnCertificateThumbprint } else { [string]$global:HighPriv_Modern_Thumbprint_Azure }

        $params = @{ AzAppId = $afClient; TenantId = $afTenant }
        if ($afCert)        { $params['AzAppCertificateThumbprint'] = $afCert; $params['AzAppCertificateStoreLocation'] = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation } else { 'LocalMachine' } }
        elseif ($afSecret)  { $params['AzAppSecret'] = $afSecret }

        return [pscustomobject]@{
            IsConfigured  = $true
            AuthMode      = 'AF'
            AuthParams    = $params
            MissingReason = $null
            TenantId      = $afTenant
            ClientId      = $afClient
            ObjectId      = if ($global:SpnObjectId) { [string]$global:SpnObjectId } else { [string]$global:HighPriv_Modern_ObjectId_Azure }
        }
    }

    # ---- Managed Identity branch ----
    if ($global:SI_PreferUami -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_UAMI_ClientId)) {
        return [pscustomobject]@{
            IsConfigured  = $true
            AuthMode      = 'MI'
            AuthParams    = @{
                                UseManagedIdentity      = $true
                                ManagedIdentityClientId = [string]$global:SI_UAMI_ClientId
                             }
            MissingReason = $null
            TenantId      = [string]$global:SI_SPN_TenantId
            ClientId      = $null
            ObjectId      = [string]$global:SI_SPN_ObjectId
        }
    }

    # ---- SPN branch: prefer SI_SPN_* (v2.3), fall back to SI_LogIngest_* (legacy) ----
    $appId    = if ($global:SI_SPN_AppId)    { [string]$global:SI_SPN_AppId }    else { [string]$global:SI_LogIngest_AppId }
    $tenantId = if ($global:SI_SPN_TenantId) { [string]$global:SI_SPN_TenantId } else { [string]$global:SI_LogIngest_TenantId }
    $secret   = if ($global:SI_SPN_Secret)   { [string]$global:SI_SPN_Secret }   else { [string]$global:SI_LogIngest_Secret }
    $objectId = if ($global:SI_SPN_ObjectId) { [string]$global:SI_SPN_ObjectId } else { [string]$global:SI_LogIngest_ObjectId }
    $thumb    = [string]$global:SI_SPN_CertThumbprint
    $store    = if ($global:SI_SPN_CertStoreLocation) { [string]$global:SI_SPN_CertStoreLocation }
                else { Resolve-SICertStoreLocation -Thumbprint $thumb }

    if (-not $appId -or -not $tenantId) {
        return [pscustomobject]@{
            IsConfigured  = $false
            AuthMode      = 'None'
            AuthParams    = @{}
            MissingReason = 'No auth configured. Set $global:SI_SPN_AppId + $global:SI_SPN_TenantId + (one of $global:SI_SPN_Secret OR $global:SI_SPN_CertThumbprint) + $global:SI_SPN_ObjectId in config\SecurityInsight.custom.ps1, OR set $global:SI_PreferUami + $global:SI_UAMI_ClientId for managed identity, OR enable -AutomationFramework. Run Bootstrap-Auth.ps1 to populate from Key Vault.'
            TenantId      = $null
            ClientId      = $null
            ObjectId      = $null
        }
    }

    # Cert wins over secret -- if both globals are set, prefer cert (no plaintext
    # secret leaves the host).
    if ($thumb) {
        return [pscustomobject]@{
            IsConfigured  = $true
            AuthMode      = 'SPN-Cert'
            AuthParams    = @{
                                AzAppId                       = $appId
                                AzAppCertificateThumbprint    = $thumb
                                AzAppCertificateStoreLocation = $store
                                TenantId                      = $tenantId
                             }
            MissingReason = $null
            TenantId      = $tenantId
            ClientId      = $appId
            ObjectId      = $objectId
        }
    }
    if ($secret) {
        return [pscustomobject]@{
            IsConfigured  = $true
            AuthMode      = 'SPN-Secret'
            AuthParams    = @{
                                AzAppId     = $appId
                                AzAppSecret = $secret
                                TenantId    = $tenantId
                             }
            MissingReason = $null
            TenantId      = $tenantId
            ClientId      = $appId
            ObjectId      = $objectId
        }
    }

    return [pscustomobject]@{
        IsConfigured  = $false
        AuthMode      = 'None'
        AuthParams    = @{}
        MissingReason = "SI_SPN_AppId + SI_SPN_TenantId are set, but neither SI_SPN_Secret nor SI_SPN_CertThumbprint is populated. Set one of them in config\SecurityInsight.custom.ps1 (cert preferred), or run Bootstrap-Auth.ps1 to pull from Key Vault."
        TenantId      = $tenantId
        ClientId      = $appId
        ObjectId      = $objectId
    }
}
