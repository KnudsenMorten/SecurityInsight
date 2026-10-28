#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Microsoft Graph connection for the high-privilege SPN, and the reconnect guard.
#
#  The two functions that own the Graph session: the initial cert/secret connect, and the
#  max-age check every hunting call runs through before it submits.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Connect-GraphHighPriv {
    [CmdletBinding()]
    param()

    # 🔑 PURE REST -- no Microsoft.Graph SDK, no MicrosoftGraphPS (#113b). There is no session to
    # establish any more, so this ACQUIRES A TOKEN. `Get-SIGraphToken` is the solution's one token
    # path and already handles BOTH shapes this function used to branch on: SPN+certificate and
    # SPN+secret. The branch is therefore gone rather than reimplemented -- two auth paths that
    # each decide which credential to use is how they drift into disagreeing.
    #
    # 🪤 THE GLOBAL NAMES DIFFER. This engine carries $global:Spn* ; the token helper reads
    # $global:SI_SPN_* (with SI_Graph_* fallback). Without the bridge the helper silently authenticates
    # as a DIFFERENT identity or none, and it surfaces later as a 403 on a hunting call -- an
    # authorization error that is really a configuration error. Only fill what is empty: in a container
    # the entrypoint has already set SI_SPN_* from the Container App Job's env vars, and overwriting
    # them there would swap the job's identity for this engine's.
    if (-not $global:SI_SPN_AppId    -and $global:SpnClientId)     { $global:SI_SPN_AppId    = $global:SpnClientId }
    if (-not $global:SI_SPN_Secret   -and $global:SpnClientSecret) { $global:SI_SPN_Secret   = $global:SpnClientSecret }
    if (-not $global:SI_SPN_TenantId -and $global:SpnTenantId)     { $global:SI_SPN_TenantId = $global:SpnTenantId }
    # 🪤 THE NAME IS `SI_SPN_CertThumbprint`, NOT `...CertificateThumbprint`. The first draft of this
    # bridge used the longer form -- which is what THIS engine calls it -- and `Get-SIGraphToken` would
    # have found nothing, fallen through to its `HighPriv_Modern_CertificateThumbprint_Azure` fallback,
    # and on a cert-only install produced a 403 rather than a "no credential" error. Verified against
    # auth/Get-SIGraphToken.ps1:64.
    if (-not $global:SI_SPN_CertThumbprint -and $global:SpnCertificateThumbprint) {
        $global:SI_SPN_CertThumbprint = $global:SpnCertificateThumbprint
    }

    $hasCert = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    Write-Info ("Acquiring Microsoft Graph token ({0}, REST)..." -f $(if ($hasCert) { 'app+certificate' } else { 'app+secret' }))

    # -ForceRefresh: this function is only called when Ensure-GraphAuth has decided the session is too
    # old, so honouring the token helper's own cache here would defeat the max-age check entirely and
    # hand back the same near-expiry token the caller just rejected.
    $script:GraphAccessToken = Get-SIGraphToken -Resource Graph -ForceRefresh
    if (-not $script:GraphAccessToken) { throw 'Get-SIGraphToken returned no token for Graph.' }

    # 🔒 THE 900s CEILING DID NOT DISAPPEAR, IT MOVED. It used to be
    # `Set-MgRequestContext -ClientTimeout 900`; it is now the -TimeoutSec on each hunting POST
    # (Invoke-SIHuntingQueryRest, default 900). That number is load-bearing: the AutoBucket ramp keys
    # off the timeout arriving as a TaskCanceled signal, so shortening it here would change WHEN
    # escalation triggers, not merely how long a call waits.
    # 📌 The SDK's MaxRetry/RetryDelay/RetriesTimeLimit are deliberately NOT reproduced. RA's bucket
    # loop owns retry for hunting, and a second retry policy underneath it multiplies every failure --
    # the same reason Invoke-SIHuntingQueryRest does not retry either.
    $script:GraphLastConnectUtc = [datetime]::UtcNow
    Write-Ok ("Graph token acquired at {0:u}" -f $script:GraphLastConnectUtc)
    Write-Info "Graph transport: REST, per-call ClientTimeout=900s, retry owned by the bucket loop"
}

function Ensure-GraphAuth {
    [CmdletBinding()]
    param(
        [int]$MaxAgeMinutes = 45
    )

    $need = $false

    if ($script:GraphLastConnectUtc -eq [datetime]::MinValue) { $need = $true }
    else {
        $ageMin = ([datetime]::UtcNow - $script:GraphLastConnectUtc).TotalMinutes
        if ($ageMin -ge $MaxAgeMinutes) { $need = $true }
    }

    if ($need) {
        Connect-GraphHighPriv
    }
}
