#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE WEB APP'S SIGN-IN CREDENTIAL FOR THE "SET UP MAIL" CLICK FLOW (#443 a, MAIL-1). PURE.

    The guided mail setup (Settings > E-mail > Set up mail) calls Exchange Online with the signed-in admin's delegated
    token. Microsoft.Identity.Web can acquire it only when the app registration has a client credential. SecurityInsight
    uses NO secret and NO certificate for it: the app registration trusts the web app's user-assigned managed identity
    through a FEDERATED credential, and the web app presents a token of that identity as its client assertion
    (AzureAd:ClientCredentials:0:SourceType = SignedAssertionFromManagedIdentity).

    CAUTION: turning the credential settings on switches EVERY user's sign-in to the authorization-code flow (the code is
    redeemed with that assertion). Without the federated credential that redemption fails and NOBODY can sign in. So the
    settings are written only after the federated credential was READ BACK from the app registration
    (Set-SIManagementSignInCredential.ps1), and removed again when it is not there.

    Dot-sourced by New-SIManagementAppRegistration.ps1 (creates the credential), Set-SIManagementSignInCredential.ps1
    (the guard) and the tests. Strict-mode safe; PS 5.1.

    Also here (below): the organisation-wide consent to the sign-in permissions (Invoke-SISignInConsent), the ONE
    implementation New-SIManagementAppRegistration.ps1 step 2b, the sign-in front's switch (SI-ManagementSigninFront.ps1)
    and the updater (container\updater\_shared\SI-UpdaterWebApp.ps1) use. Pure except its -Graph seam.
#>

$script:SIManagementFicAudience = 'api://AzureADTokenExchange'
$script:SIManagementCredentialSettingNames = @('AzureAd__ClientCredentials__0__SourceType', 'AzureAd__ClientCredentials__0__ManagedIdentityClientId')

function Get-SIManagementFederatedCredentialSpec {
    <# PURE. The federated credential that lets the web app's managed identity (by its principal / object id) act as the
       app registration. Named after the identity: several installs sharing the one app each keep their own. #>
    param([Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    $pid_ = $PrincipalId.Trim().ToLowerInvariant()
    [ordered]@{
        name        = 'si-web-' + $pid_
        issuer      = 'https://login.microsoftonline.com/{0}/v2.0' -f $TenantId.Trim().ToLowerInvariant()
        subject     = $pid_
        audiences   = @($script:SIManagementFicAudience)
        description = 'SecurityInsight web app (its managed identity): the Set up mail sign-in. No secret, no certificate.'
    }
}

function Test-SIManagementFederatedCredential {
    <# PURE. True when one of -Credentials (Graph's federatedIdentityCredentials) trusts exactly this identity: the
       tenant's v2.0 issuer, the principal id as subject, and the token-exchange audience. #>
    param([AllowEmptyCollection()][object[]]$Credentials = @(), [Parameter(Mandatory)][string]$TenantId, [Parameter(Mandatory)][string]$PrincipalId)
    $want = Get-SIManagementFederatedCredentialSpec -TenantId $TenantId -PrincipalId $PrincipalId
    foreach ($c in @($Credentials | Where-Object { $_ })) {
        $iss = if ($c.PSObject.Properties['issuer']) { ([string]$c.issuer).Trim().TrimEnd('/').ToLowerInvariant() } else { '' }
        $sub = if ($c.PSObject.Properties['subject']) { ([string]$c.subject).Trim().ToLowerInvariant() } else { '' }
        $aud = if ($c.PSObject.Properties['audiences']) { @($c.audiences | ForEach-Object { ([string]$_).Trim() }) } else { @() }
        if ($iss -eq $want.issuer.TrimEnd('/') -and $sub -eq $want.subject -and $aud -contains $script:SIManagementFicAudience) { return $true }
    }
    $false
}

function Get-SIManagementCredentialSettings {
    <# PURE. The two web app settings that turn the credential on: the managed identity's token as client assertion. #>
    param([Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ManagedIdentityClientId)
    @(
        ('{0}=SignedAssertionFromManagedIdentity' -f $script:SIManagementCredentialSettingNames[0]),
        ('{0}={1}' -f $script:SIManagementCredentialSettingNames[1], $ManagedIdentityClientId.Trim().ToLowerInvariant())
    )
}

# ===================================================================================================================
# THE SIGN-IN PERMISSIONS, CONSENTED FOR THE WHOLE ORGANISATION (#616; CR7 consent, 2026-10-18).
# The web app -- and the shared sign-in front (FRAMEWORK/signin-front) in front of it -- asks Entra for openid, profile,
# offline_access (the front's refresh token; MSAL adds it) and User.Read (the front's RefreshScope). A tenant that does not let
# users consent stops the first sign-in at "Approval required" unless ONE organisation-wide grant (consentType AllPrincipals)
# on Microsoft Graph carries all four. New-SIManagementAppRegistration.ps1 step 2b gives it; installs registered before that
# step only had "openid profile" -- the owner's first sign-in through the front hit exactly that. setup\Set-SISigninFront.ps1
# (Invoke-SISigninFrontCutover) makes sure of it before the front is switched on, and the updater says so when a web app
# behind the front lacks it. One implementation for all three: Invoke-SISignInConsent.
# ===================================================================================================================
$script:SISignInConsentScopes = @('openid', 'profile', 'offline_access', 'User.Read')
$script:SIGraphResourceAppId = '00000003-0000-0000-c000-000000000000'

function Get-SISignInConsentScopes { @($script:SISignInConsentScopes) }

function Get-SISignInConsentPlan {
    <#
        PURE. What the organisation-wide grant needs, from -Grants (oauth2PermissionGrants of the app's service principal on
        Microsoft Graph, any consent type). Returns @{ Action = none | extend | create; GrantId (the AllPrincipals grant
        to extend); Have (its scopes); Missing; Scope (the scope string to write: what it has + what is missing) }.
        Only the AllPrincipals grant counts: a person's own consent does not let anyone else sign in.
    #>
    param([AllowEmptyCollection()][AllowNull()][object[]]$Grants = @(), [string[]]$Scopes = $script:SISignInConsentScopes)
    $all = @(@($Grants) | Where-Object { $_ -and $_.PSObject.Properties['consentType'] -and [string]$_.consentType -eq 'AllPrincipals' }) | Select-Object -First 1
    $have = @(); if ($all -and $all.PSObject.Properties['scope']) { $have = @(([string]$all.scope) -split '\s+' | Where-Object { $_ }) }
    # Entra compares scope names without case
    $missing = @($Scopes | Where-Object { $s = $_; -not @($have | Where-Object { $_ -ieq $s }).Count })
    $action = if (-not $all) { 'create' } elseif ($missing.Count) { 'extend' } else { 'none' }
    [pscustomobject]@{
        Action = $action; GrantId = $(if ($all -and $all.PSObject.Properties['id']) { [string]$all.id } else { '' })
        Have = $have; Missing = $missing; Scope = ((@($have) + @($missing)) -join ' ')
    }
}

function Get-SISignInConsentAdminText {
    <# PURE. What an administrator does when this sign-in may not give the consent, in one sentence. #>
    param([AllowEmptyString()][string]$AppName = '', [AllowEmptyString()][string]$ClientId = '')
    $what = if ("$AppName".Trim()) { '"{0}"' -f "$AppName".Trim() } elseif ("$ClientId".Trim()) { 'the application {0}' -f "$ClientId".Trim() } else { 'the web app''s sign-in application' }
    ('An administrator (Cloud Application Administrator, Application Administrator or Global Administrator) grants admin consent once: Entra admin center > Enterprise applications > {0} > Permissions > Grant admin consent -- or runs setup\Set-SISigninFront.ps1 -Apply signed in with that role (an app needs Microsoft Graph DelegatedPermissionGrant.ReadWrite.All). Until then a tenant that does not let users consent shows "Approval required" at sign-in.' -f $what)
}

function Invoke-SISignInConsent {
    <#
        Makes sure of the organisation-wide grant of the sign-in permissions (openid profile offline_access User.Read) for
        the app's service principal -- found by -ServicePrincipalId, else by -ClientId. -Graph: { param([string]$Method,
        [string]$Uri, $Body) } -> the parsed answer (Body a hashtable, $null for a read); throws on failure. Without -Apply
        it only READS and says what it would do. With -Apply: one POST (no grant) or one PATCH (the scopes added to the
        grant there is -- nothing it carries is removed), then READ BACK (a few tries: the directory replicates).
        NEVER THROWS. Returns @{ State; Action; Missing; Line; Error; ServicePrincipalId; AppName }:
          in-place   the grant carries every scope -- nothing to do
          planned    (no -Apply) what it would add
          given      written and read back
          no-rights  the sign-in may not read or write consents: Line names what an administrator does
          failed     written but it does not read back, or another error (Error)
          unchecked  the application's service principal could not be found
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [AllowEmptyString()][string]$ServicePrincipalId = '', [AllowEmptyString()][string]$ClientId = '',
          [switch]$Apply, [scriptblock]$Sleep, [int[]]$Waits = @(0, 5, 10, 20), [string]$GraphBase = 'https://graph.microsoft.com/v1.0')
    $r = [pscustomobject]@{ State = ''; Action = ''; Missing = @(); Line = ''; Error = ''; ServicePrincipalId = "$ServicePrincipalId".Trim(); AppName = '' }
    $scopesText = ($script:SISignInConsentScopes -join ' ')
    $rights = { param([string]$m) "$m" -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden' }
    $firstValue = { param($o) if ($o -and $o.PSObject.Properties['value']) { @($o.value | Where-Object { $_ })[0] } else { $null } }
    try {
        if (-not $r.ServicePrincipalId) {
            if ("$ClientId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { $r.State = 'unchecked'; $r.Line = 'the sign-in permissions: no client id to look the application up by -- not checked'; return $r }
            $sp = & $firstValue (& $Graph 'GET' ("$GraphBase/servicePrincipals?`$filter={0}&`$select=id,appId,displayName" -f [uri]::EscapeDataString(("appId eq '{0}'" -f "$ClientId".Trim()))) $null)
            if (-not $sp) { $r.State = 'unchecked'; $r.Line = ('the sign-in permissions: the application {0} has no enterprise application (service principal) -- not checked' -f "$ClientId".Trim()); return $r }
            $r.ServicePrincipalId = [string]$sp.id; $r.AppName = [string]$sp.displayName
        }
        $gsp = & $firstValue (& $Graph 'GET' ("$GraphBase/servicePrincipals?`$filter={0}&`$select=id" -f [uri]::EscapeDataString(("appId eq '{0}'" -f $script:SIGraphResourceAppId))) $null)
        if (-not $gsp) { throw 'Microsoft Graph''s service principal was not found in this tenant' }
        $graphSpId = [string]$gsp.id
        $grantsUri = "$GraphBase/oauth2PermissionGrants?`$filter={0}" -f [uri]::EscapeDataString(("clientId eq '{0}' and resourceId eq '{1}'" -f $r.ServicePrincipalId, $graphSpId))
        $read = { $g = & $Graph 'GET' $grantsUri $null; @($(if ($g -and $g.PSObject.Properties['value']) { $g.value })) }
        $plan = Get-SISignInConsentPlan -Grants (& $read)
        $r.Action = $plan.Action; $r.Missing = @($plan.Missing)
        if ($plan.Action -eq 'none') { $r.State = 'in-place'; $r.Line = ('the sign-in permissions are consented for the organisation ({0})' -f $scopesText); return $r }
        $what = if ($plan.Action -eq 'create') { 'POST /oauth2PermissionGrants (for the organisation: {0})' -f $scopesText } else { 'PATCH /oauth2PermissionGrants/{0} (for the organisation: + {1})' -f $plan.GrantId, ($plan.Missing -join ' ') }
        if (-not $Apply) { $r.State = 'planned'; $r.Line = ('the sign-in permissions are NOT all consented for the organisation (missing: {0}) -- would {1}' -f ($plan.Missing -join ' '), $what); return $r }
        if ($plan.Action -eq 'create') { $null = & $Graph 'POST' "$GraphBase/oauth2PermissionGrants" ([ordered]@{ clientId = $r.ServicePrincipalId; consentType = 'AllPrincipals'; resourceId = $graphSpId; scope = $plan.Scope }) }
        else { $null = & $Graph 'PATCH' ("$GraphBase/oauth2PermissionGrants/{0}" -f $plan.GrantId) ([ordered]@{ scope = $plan.Scope }) }
        foreach ($w in $Waits) {
            if ($w) { if ($Sleep) { & $Sleep $w } else { Start-Sleep -Seconds $w } }
            $again = $null; try { $again = Get-SISignInConsentPlan -Grants (& $read) } catch { $again = $null }
            if ($again -and $again.Action -eq 'none') { $r.State = 'given'; $r.Line = ('the sign-in permissions consented for the organisation ({0}), read back' -f $scopesText); return $r }
        }
        $r.State = 'failed'; $r.Error = 'the consent was written but does not read back'
        $r.Line = ('the sign-in permissions: the consent was written but does not read back (missing: {0}) -- run the same command again in a minute. {1}' -f ($plan.Missing -join ' '), (Get-SISignInConsentAdminText -AppName $r.AppName -ClientId $ClientId))
        return $r
    } catch {
        $r.Error = [string]$_.Exception.Message
        if (& $rights $r.Error) {
            $r.State = 'no-rights'
            $r.Line = ('the sign-in permissions ({0}) could not be checked or consented for the organisation: this sign-in may not ({1}). {2}' -f $scopesText, $r.Error, (Get-SISignInConsentAdminText -AppName $r.AppName -ClientId $ClientId))
        } else {
            $r.State = 'failed'
            $r.Line = ('the sign-in permissions ({0}) could not be checked or consented for the organisation ({1}). {2}' -f $scopesText, $r.Error, (Get-SISignInConsentAdminText -AppName $r.AppName -ClientId $ClientId))
        }
        return $r
    }
}

function Get-SIManagementCredentialDecision {
    <#
        PURE. What the guard does: 'enable' (the federated credential was read back), 'disable' (it is not there, and the
        app carries the settings -- remove them so sign-in keeps working), or 'none' (not there, and not set: nothing to
        do). A credential list that could not be read is never 'enable'; it removes nothing either ('unknown').
    #>
    param([AllowNull()][object[]]$Credentials, [switch]$ReadFailed, [Parameter(Mandatory)][string]$TenantId,
          [Parameter(Mandatory)][string]$PrincipalId, [string[]]$CurrentSettingNames = @())
    if ($ReadFailed) { return 'unknown' }
    if (Test-SIManagementFederatedCredential -Credentials @($Credentials) -TenantId $TenantId -PrincipalId $PrincipalId) { return 'enable' }
    $set = @($CurrentSettingNames | Where-Object { $script:SIManagementCredentialSettingNames -contains $_ })
    if ($set.Count) { return 'disable' }
    'none'
}
