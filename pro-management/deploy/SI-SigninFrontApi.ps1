#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE WEB APP'S OWN API FOR THE SHARED SIGN-IN FRONT 1.4.0 (#852, framework DOCS/REQUIREMENTS.md
    12.11g item 9). The front 1.4.0 can send the web app an ACCESS token for the app's own API instead of the ID token: it asks
    for openid profile offline_access + SIGNIN_UPSTREAM_SCOPE = api://<client id>/user_impersonation (only that form for
    THIS client id). For that the web app's app registration needs:
      uri    the identifier URI api://<client id> (added; any other URI kept);
      scope  a delegated scope "user_impersonation" (admin consent; added beside the scopes it has -- Estate.Read stays);
      grant  an organisation-wide (AllPrincipals) oauth2PermissionGrant from the app's service principal to ITSELF for that
             scope, so nobody is asked to consent.
    requestedAccessTokenVersion is NEVER set here (it stays as it is; PIM's MCP clients share the pattern). Each piece only
    when missing, read back; idempotent. The front's SIGNIN_UPSTREAM_SCOPE is handed out ONLY when every piece reads back,
    and only to a front from 1.4.0 on (unset = the ID token, as in 1.3.0).

    One library for the setup scripts (New-SIManagementAppRegistration.ps1, Set-SISigninFront.ps1) and the update's step
    9h. -Graph { param([string]$Method, [string]$Uri, $Body) } -> the parsed answer; throws on failure. No module. PS 5.1 + pwsh 7.
#>

$script:SISigninApiScope = 'user_impersonation'
# the scope's id in a NEW registration (fixed, as Estate.Read's): an app that has the scope keeps its own id
$script:SISigninApiScopeId = '8d1c4f0e-3b7a-4e52-9c61-5a2f7e0d9b14'

function Get-SISigninApiProp {
    param($Object, [string[]]$Path)
    $o = $Object
    foreach ($p in $Path) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($p)) { $o[$p] } else { $null }); continue }
        $pp = $o.PSObject.Properties[$p]
        $o = $(if ($pp) { $pp.Value } else { $null })
    }
    $o
}

function Test-SISigninFrontWantsScope {
    <# PURE. Does the pinned front (-Pin, or a version text) take SIGNIN_UPSTREAM_SCOPE? 1.4.2 on: 1.4.0 and 1.4.1 asked for the access token without naming the sign-in scheme and looped every sign-in back (2026-10-21, PIM and SI internal) -- never access mode before 1.4.2. #>
    param([Parameter(Mandatory)]$Pin)
    $v = $(if ($Pin -is [string]) { $Pin } else { [string](Get-SISigninApiProp $Pin @('version')) })
    $pv = $null
    if (-not [version]::TryParse("$v".Trim(), [ref]$pv)) { return $false }
    $pv -ge [version]'1.4.2'
}

function Get-SISigninApiScopeValue {
    <# PURE. The front's SIGNIN_UPSTREAM_SCOPE for -ClientId: api://<client id>/user_impersonation. #>
    param([Parameter(Mandatory)][string]$ClientId)
    'api://{0}/{1}' -f $ClientId.Trim().ToLowerInvariant(), $script:SISigninApiScope
}

function New-SISigninApiScope {
    <# PURE. The delegated scope (admin consent) the front asks for. #>
    param([string]$Id = $script:SISigninApiScopeId)
    [ordered]@{ id = $Id; value = $script:SISigninApiScope; type = 'Admin'; isEnabled = $true
                adminConsentDisplayName = 'Sign in to SecurityInsight'
                adminConsentDescription = 'Lets the SecurityInsight sign-in front call the SecurityInsight web app as the signed-in user. The user still needs a SecurityInsight role.'
                userConsentDisplayName = 'Sign in to SecurityInsight'
                userConsentDescription = 'Lets the sign-in front call SecurityInsight as you.' }
}

function Get-SISigninApiAppPlan {
    <#
        PURE. What the app registration (-App as read: identifierUris, api) lacks, and the ONE PATCH that adds it:
        @{ NeedUri; NeedScope; Body ($null = nothing to send) }. The PATCH carries the WHOLE api object as read (a PATCH
        replaces a complex property) with the scope added -- every other scope and requestedAccessTokenVersion as they are.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$ClientId)
    $uri = 'api://{0}' -f $ClientId.Trim().ToLowerInvariant()
    $uris = @(@(Get-SISigninApiProp $App @('identifierUris')) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $needUri = -not @($uris | Where-Object { $_.TrimEnd('/') -ieq $uri }).Count
    $scopes = @(@(Get-SISigninApiProp $App @('api', 'oauth2PermissionScopes')) | Where-Object { $_ })
    $needScope = -not @($scopes | Where-Object { [string](Get-SISigninApiProp $_ @('value')) -ceq $script:SISigninApiScope }).Count
    if (-not $needUri -and -not $needScope) { return [pscustomobject]@{ NeedUri = $false; NeedScope = $false; Body = $null } }
    $body = [ordered]@{}
    if ($needUri) { $body.identifierUris = @(@($uris) + @($uri)) }
    if ($needScope) {
        $api = [ordered]@{}
        $have = Get-SISigninApiProp $App @('api')
        if ($have) {
            $props = if ($have -is [System.Collections.IDictionary]) { @($have.Keys) } else { @($have.PSObject.Properties | ForEach-Object { $_.Name }) }
            # sent back as read; an unset value (null) is not sent, so nothing is set that was not set
            foreach ($k in $props) { $v = Get-SISigninApiProp $have @([string]$k); if ($null -ne $v) { $api[[string]$k] = $v } }
        }
        $ids = @($scopes | ForEach-Object { [string](Get-SISigninApiProp $_ @('id')) })
        $id = $(if ($ids -contains $script:SISigninApiScopeId) { [guid]::NewGuid().ToString() } else { $script:SISigninApiScopeId })
        $api.oauth2PermissionScopes = @(@($scopes) + @(New-SISigninApiScope -Id $id))
        $body.api = $api
    }
    [pscustomobject]@{ NeedUri = $needUri; NeedScope = $needScope; Body = $body }
}

function Get-SISigninApiGrantPlan {
    <# PURE. The app's own organisation-wide grant to itself (-Grants: clientId = resourceId = the app's service principal):
       @{ Action = none | create | patch; GrantId; Scope (the scope text to write) }. Scopes are only ever added. #>
    param([AllowNull()][object[]]$Grants)
    $g = @(@($Grants) | Where-Object { $_ -and [string](Get-SISigninApiProp $_ @('consentType')) -eq 'AllPrincipals' }) | Select-Object -First 1
    if (-not $g) { return [pscustomobject]@{ Action = 'create'; GrantId = ''; Scope = $script:SISigninApiScope } }
    $have = @(("$(Get-SISigninApiProp $g @('scope'))" -split '\s+') | Where-Object { $_ })
    if ($have -ccontains $script:SISigninApiScope) { return [pscustomobject]@{ Action = 'none'; GrantId = [string](Get-SISigninApiProp $g @('id')); Scope = ($have -join ' ') } }
    [pscustomobject]@{ Action = 'patch'; GrantId = [string](Get-SISigninApiProp $g @('id')); Scope = ((@($have) + @($script:SISigninApiScope)) -join ' ') }
}

function Invoke-SISigninFrontApi {
    <#
        Makes sure of the identifier URI, the scope and the self grant for the app -ClientId (see the file header). Without
        -Apply: reads only and says what it would do. NEVER THROWS. Returns @{ State = in-place | given | planned |
        no-read | no-rights | failed; Ok (every piece reads back); Scope (SIGNIN_UPSTREAM_SCOPE's value when Ok, else '');
        Lines; Why }.
        #905: the ways it ends without the scope are kept apart, because only ONE of them is anybody's action:
          no-read    a READ was refused (403 / insufficient privileges on the app registration, its service principal or
                     its grants): nothing is known about what is there -- it may well all be in place;
          planned    read OK, a piece is missing, no -Apply;
          no-rights  read OK, a piece is missing, and the WRITE was refused.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId, [switch]$Apply,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int[]]$Waits = @(0, 5, 10, 20), [string]$GraphBase = 'https://graph.microsoft.com/v1.0')
    $lines = New-Object System.Collections.Generic.List[string]
    $rights = { param([string]$m) "$m" -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden' }
    $res = { param([string]$state, [string]$why) [pscustomobject]@{ State = $state; Ok = ($state -in 'in-place', 'given'); Scope = $(if ($state -in 'in-place', 'given') { Get-SISigninApiScopeValue -ClientId $ClientId } else { '' }); Lines = $lines.ToArray(); Why = $why } }
    $cid = "$ClientId".Trim().ToLowerInvariant()
    if ($cid -notmatch '^[0-9a-f-]{36}$') { return (& $res 'failed' 'no client id') }
    $step = 'read'
    try {
        $readApp = { & $Graph 'GET' ("$GraphBase/applications(appId='{0}')?`$select=id,identifierUris,api" -f $cid) $null }
        $app = & $readApp
        if (-not $app -or -not [string](Get-SISigninApiProp $app @('id'))) { return (& $res 'failed' ('the app registration {0} was not found' -f $cid)) }
        $plan = Get-SISigninApiAppPlan -App $app -ClientId $cid
        $sps = & $Graph 'GET' ("$GraphBase/servicePrincipals?`$filter={0}&`$select=id" -f [uri]::EscapeDataString(("appId eq '{0}'" -f $cid))) $null
        $spId = [string](Get-SISigninApiProp (@(@(Get-SISigninApiProp $sps @('value')) | Where-Object { $_ }) | Select-Object -First 1) @('id'))
        if (-not $spId) { return (& $res 'failed' ('the app {0} has no enterprise application (service principal)' -f $cid)) }
        $grantsUri = "$GraphBase/oauth2PermissionGrants?`$filter={0}" -f [uri]::EscapeDataString(("clientId eq '{0}' and resourceId eq '{0}'" -f $spId))
        $readGrants = { $g = & $Graph 'GET' $grantsUri $null; @($(if ($g) { Get-SISigninApiProp $g @('value') })) }
        $gplan = Get-SISigninApiGrantPlan -Grants (& $readGrants)
        if (-not $plan.Body -and $gplan.Action -eq 'none') { $lines.Add(('the web app''s own API: api://{0}, the scope {1} and its organisation-wide consent are in place' -f $cid, $script:SISigninApiScope)); return (& $res 'in-place' '') }
        $what = @()
        if ($plan.NeedUri) { $what += ('the identifier URI api://{0}' -f $cid) }
        if ($plan.NeedScope) { $what += ('the delegated scope {0} (admin consent)' -f $script:SISigninApiScope) }
        if ($gplan.Action -ne 'none') { $what += ('the organisation-wide consent of the app to its own scope {0}' -f $script:SISigninApiScope) }
        if (-not $Apply) { $lines.Add(('the web app''s own API (plan): would add ' + ($what -join '; '))); return (& $res 'planned' '') }
        if ($plan.Body) { $step = 'app'; $null = & $Graph 'PATCH' ("$GraphBase/applications/{0}" -f (Get-SISigninApiProp $app @('id'))) $plan.Body }
        if ($gplan.Action -eq 'create') { $step = 'grant'; $null = & $Graph 'POST' "$GraphBase/oauth2PermissionGrants" ([ordered]@{ clientId = $spId; consentType = 'AllPrincipals'; resourceId = $spId; scope = $gplan.Scope }) }
        elseif ($gplan.Action -eq 'patch') { $step = 'grant'; $null = & $Graph 'PATCH' ("$GraphBase/oauth2PermissionGrants/{0}" -f $gplan.GrantId) ([ordered]@{ scope = $gplan.Scope }) }
        # read back (the directory replicates: a few tries)
        $step = 'read back'
        foreach ($w in $Waits) {
            if ($w -gt 0) { & $Sleep $w }
            $p2 = Get-SISigninApiAppPlan -App (& $readApp) -ClientId $cid
            $g2 = Get-SISigninApiGrantPlan -Grants (& $readGrants)
            if (-not $p2.Body -and $g2.Action -eq 'none') { $lines.Add(('the web app''s own API: added ' + ($what -join '; ') + ' (read back)')); return (& $res 'given' '') }
        }
        $lines.Add(('the web app''s own API: ' + ($what -join '; ') + ' written but does not read back yet -- the next run checks again'))
        & $res 'failed' 'written but not read back'
    } catch {
        $m = [string]$_.Exception.Message
        if ((& $rights $m) -and $step -in 'read', 'read back') {
            # #905: a refused READ says nothing about what is there (2026-10-27: all of it was in place on every install
            # whose update could not read it) -- never "may not change", never a customer action
            $lines.Add(('the web app''s own API: this sign-in may not read the app registration or its consent ({0}: {1}) -- whether api://{2}, the scope {3} and its organisation-wide consent are in place is not known' -f $step, $m, $cid, $script:SISigninApiScope))
            return (& $res 'no-read' $m)
        }
        if (& $rights $m) {
            $lines.Add(('the web app''s own API: this sign-in may not change the app registration or its consent ({0}: {1})' -f $step, $m))
            return (& $res 'no-rights' $m)
        }
        $lines.Add(('the web app''s own API: {0} failed ({1})' -f $step, $m))
        & $res 'failed' $m
    }
}

function Get-SISigninFrontApiUpdateOutcome {
    <#
        PURE. #905 -- what the update's step 9h SAYS about one Invoke-SISigninFrontApi result (-Result) for the web app
        -WebApp, and whether it is a customer action. Returns @{ Info (lines); Warn (lines); Env ('SIGNIN_UPSTREAM_SCOPE=...'
        when every piece reads back, else ''); Action (the customer action's text, '' = none) }.
          in-place / given  Info; the update hands the front SIGNIN_UPSTREAM_SCOPE itself.
          planned           Info (-WhatIf / detect only).
          no-read           Info ONLY: the update's identity could not READ the app registration or its consent, so it
                            knows nothing about what is there (on 2026-10-27 all of it was in place on every install that
                            said "config-missing"). The front stays on the ID token -- it signs in as before. NEVER a
                            customer action.
          no-rights         read OK, a piece missing, the WRITE refused: Warn + ONE customer action naming
                            setup\Set-SISigninFront.ps1 -Apply AND what else that script does (it is more than a scope).
          failed            Warn; no customer action (the next update tries again).
    #>
    param([Parameter(Mandatory)]$Result, [string]$WebApp = 'ca-si-management', [switch]$WhatIf)
    $state = [string](Get-SISigninApiProp $Result @('State'))
    $lines = @(@(Get-SISigninApiProp $Result @('Lines')) | Where-Object { "$_".Trim() } | ForEach-Object { [string]$_ })
    $o = [ordered]@{ Info = @(); Warn = @(); Env = ''; Action = '' }
    switch ($state) {
        { $_ -in 'in-place', 'given' } {
            $o.Info = $lines
            $sc = [string](Get-SISigninApiProp $Result @('Scope'))
            if ($sc) { $o.Env = ('SIGNIN_UPSTREAM_SCOPE={0}' -f $sc) }
        }
        'no-read' {
            $o.Info = @($lines) + @(('{0}: the sign-in front stays on the ID token (it signs users in as before) -- this update''s identity may not read the app registration or its consent, so it cannot tell whether the scope {1} and its organisation-wide consent are in place. Nothing to do: once the update can read them (its identity holds Directory.Read.All, which Install-SIUpdaterJob gives when it may) and they are in place, the update hands the front the access token for the web app''s own API itself.' -f $WebApp, $script:SISigninApiScope))
        }
        'no-rights' {
            $o.Warn = $lines
            if (-not $WhatIf) {
                $o.Action = ('{0}: the sign-in front signs users in with the ID token, not an access token for the web app''s own API -- the update read that the scope {1} or its organisation-wide consent is missing, and it may not add them. Run setup\Set-SISigninFront.ps1 -Apply through the Support app (as an administrator); it adds them and reads them back. That script does more than the scope -- run it first WITHOUT -Apply to see its plan: it also makes sure of the sign-in consent, the federated credential and the front''s store, rolls a new revision of the web app with the pinned front, turns Easy Auth off, and DELETES the app registration''s client secrets unless -KeepClientSecrets is given.' -f $WebApp, $script:SISigninApiScope)
            }
        }
        'planned' { $o.Info = $lines }
        default { $o.Warn = $lines }
    }
    [pscustomobject]$o
}
