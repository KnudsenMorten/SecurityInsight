#Requires -Version 5.1
<#
    THE MCP SERVER'S OWN DELEGATED SCOPE mcp.access (framework SECURE-WEB-1 (3): "a DEDICATED delegated scope
    api://<app>/mcp.access is the TARGET standard"). The MCP server (pro-management/src/SI.Management.Mcp) answers a person's
    delegated token whose scp carries mcp.access, and names the scope in its RFC 9728 metadata; an MCP client asks Entra for
    api://<client id>/mcp.access.

    The sign-in app registration (the one the web app and the MCP share, AzureAd__ClientId) exposes it:
      scope  a delegated scope "mcp.access", admin consent, the stable id $script:SIMcpScopeId (an app that already has a
             scope by that value keeps its own id; the stable id is taken only when no other scope of the app holds it);
             ADDED BESIDE the scopes the app has -- a PATCH of `api` replaces the whole oauth2PermissionScopes list, so the
             PATCH carries the whole `api` object as read (every existing scope, requestedAccessTokenVersion and every other
             member as they are) with mcp.access added;
      uri    the identifier URI api://<client id> (added when missing; every other URI kept) -- the scope is named by it.
    Read back after the write: mcp.access there and enabled, every scope that was there still there (same id, same value),
    requestedAccessTokenVersion unchanged. The web app's own sign-in is not touched (no web / spa / redirect / login setting).

    Used by: new installs (pro-management/deploy/New-SIManagementAppRegistration.ps1, in its one api PATCH: New-SIMcpApiScope)
    and EXISTING installs (the updater's built-in sign-in step, setup/_shared/SI-BuiltInAuthStandard.ps1
    Invoke-SIBuiltInAuthStandardStep -> Invoke-SIMcpScopeConverge, with the updater's Graph sign-in: Application.ReadWrite.
    OwnedBy as the registration's owner -- the same right the built-in sign-in's redirect-URI write uses; a refusal is a
    support step, never a failure of the update).

    -Graph { param([string]$Method, [string]$Uri, $Body) } -> the parsed answer; THROWS on failure. No module. PS 5.1 + pwsh 7.
#>

$script:SIMcpScope   = 'mcp.access'
# generated once (2026-11-15) and kept: a NEW registration and an app without the scope get this id
$script:SIMcpScopeId = '3a3db793-b323-4fd6-a435-49fd163fcdbf'

function Get-SIMcpScopeProp {
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

function New-SIMcpApiScope {
    <# PURE. The delegated scope mcp.access (admin consent), plain-English texts. #>
    param([string]$Id = $script:SIMcpScopeId)
    [ordered]@{ id = $Id; value = $script:SIMcpScope; type = 'Admin'; isEnabled = $true
                adminConsentDisplayName = 'Use the SecurityInsight MCP server'
                adminConsentDescription = 'Lets an MCP client (an AI assistant) read SecurityInsight data through the SecurityInsight MCP server as the signed-in person. The person still needs a role in SecurityInsight, and sees only what that role allows.'
                userConsentDisplayName = 'Use the SecurityInsight MCP server'
                userConsentDescription = 'Lets your AI assistant read SecurityInsight data as you, through the SecurityInsight MCP server. You see only what your SecurityInsight role allows.' }
}

function Get-SIMcpScopeValue {
    <# PURE. What an MCP client asks for: api://<client id>/mcp.access. #>
    param([Parameter(Mandatory)][string]$ClientId)
    'api://{0}/{1}' -f $ClientId.Trim().ToLowerInvariant(), $script:SIMcpScope
}

function Get-SIMcpScopePlan {
    <#
        PURE. What the app registration (-App as read: identifierUris, api) lacks for mcp.access, and the ONE PATCH that adds
        it: @{ NeedUri; NeedScope; Body ($null = nothing to send) }. The body carries the WHOLE api object as read (a PATCH
        replaces a complex property) with the scope added -- every other scope and requestedAccessTokenVersion as they are.
    #>
    param([Parameter(Mandatory)]$App, [Parameter(Mandatory)][string]$ClientId)
    $uri = 'api://{0}' -f $ClientId.Trim().ToLowerInvariant()
    $uris = @(@(Get-SIMcpScopeProp $App @('identifierUris')) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $needUri = -not @($uris | Where-Object { $_.TrimEnd('/') -ieq $uri }).Count
    $scopes = @(@(Get-SIMcpScopeProp $App @('api', 'oauth2PermissionScopes')) | Where-Object { $_ })
    $needScope = -not @($scopes | Where-Object { [string](Get-SIMcpScopeProp $_ @('value')) -ceq $script:SIMcpScope }).Count
    if (-not $needUri -and -not $needScope) { return [pscustomobject]@{ NeedUri = $false; NeedScope = $false; Body = $null } }
    $body = [ordered]@{}
    if ($needUri) { $body.identifierUris = @(@($uris) + @($uri)) }
    if ($needScope) {
        $api = [ordered]@{}
        $have = Get-SIMcpScopeProp $App @('api')
        if ($have) {
            # sent back as read -- the value itself, never through a function (PowerShell would unroll a one-item list into
            # its item and an empty list into nothing, and Graph refuses an object where it wants a list); an unset value
            # (null) is not sent, so nothing is set that was not set
            $pairs = if ($have -is [System.Collections.IDictionary]) { @($have.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $have[$_] } }) } else { @($have.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
            foreach ($pr in $pairs) { if ($null -ne $pr.Value) { $api[$pr.Name] = $pr.Value } }
        }
        $ids = @($scopes | ForEach-Object { [string](Get-SIMcpScopeProp $_ @('id')) })
        $id = $(if ($ids -contains $script:SIMcpScopeId) { [guid]::NewGuid().ToString() } else { $script:SIMcpScopeId })
        $api.oauth2PermissionScopes = @(@($scopes) + @(New-SIMcpApiScope -Id $id))
        $body.api = $api
    }
    [pscustomobject]@{ NeedUri = $needUri; NeedScope = $needScope; Body = $body }
}

function Test-SIMcpScopeReadBack {
    <#
        PURE. -After (the app as read after the PATCH) against -Before (as read before): mcp.access there and enabled, the
        identifier URI there, every scope of -Before still there (same id AND value), requestedAccessTokenVersion the same.
        @{ Ok; Why }.
    #>
    param($Before, $After, [Parameter(Mandatory)][string]$ClientId)
    $why = New-Object System.Collections.Generic.List[string]
    $p = Get-SIMcpScopePlan -App $After -ClientId $ClientId
    if ($p.NeedUri) { $why.Add(('the identifier URI api://{0} is missing' -f $ClientId.Trim().ToLowerInvariant())) }
    if ($p.NeedScope) { $why.Add('the scope mcp.access is missing') }
    $now = @(@(Get-SIMcpScopeProp $After @('api', 'oauth2PermissionScopes')) | Where-Object { $_ })
    $mine = @($now | Where-Object { [string](Get-SIMcpScopeProp $_ @('value')) -ceq $script:SIMcpScope }) | Select-Object -First 1
    if ($mine -and "$(Get-SIMcpScopeProp $mine @('isEnabled'))" -notmatch '^(?i)true$') { $why.Add('the scope mcp.access is not enabled') }
    foreach ($s in @(@(Get-SIMcpScopeProp $Before @('api', 'oauth2PermissionScopes')) | Where-Object { $_ })) {
        $sid = [string](Get-SIMcpScopeProp $s @('id')); $sv = [string](Get-SIMcpScopeProp $s @('value'))
        if (-not @($now | Where-Object { [string](Get-SIMcpScopeProp $_ @('id')) -eq $sid -and [string](Get-SIMcpScopeProp $_ @('value')) -ceq $sv }).Count) { $why.Add(('the scope {0} that was there is gone' -f $sv)) }
    }
    $v1 = "$(Get-SIMcpScopeProp $Before @('api', 'requestedAccessTokenVersion'))"; $v2 = "$(Get-SIMcpScopeProp $After @('api', 'requestedAccessTokenVersion'))"
    if ($v1 -ne $v2) { $why.Add(('requestedAccessTokenVersion changed ({0} -> {1})' -f $v1, $v2)) }
    [pscustomobject]@{ Ok = ($why.Count -eq 0); Why = ($why -join '; ') }
}

function Invoke-SIMcpScopeConverge {
    <#
        Makes sure the sign-in app registration -ClientId exposes mcp.access (see the file header). -Mode plan reads only and
        says what it would do; apply writes the ONE PATCH and reads it back. NEVER THROWS.
        @{ State = in-place | planned | given | no-read | no-rights | failed; Ok (in place or given, read back); Scope
        (api://<client id>/mcp.access when Ok); Lines; Support (the support step's text when the write was refused, else '') }.
          no-read    a READ was refused: nothing is known about what is there -- information only;
          no-rights  read OK, the scope missing, the WRITE refused: the support step (an administrator, or the Invardia
                     Support app, adds it: setup or New-SIManagementAppRegistration.ps1 -Apply).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$ClientId, [ValidateSet('plan', 'apply')][string]$Mode = 'plan',
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int[]]$Waits = @(0, 5, 10, 20), [string]$GraphBase = 'https://graph.microsoft.com/v1.0')
    $lines = New-Object System.Collections.Generic.List[string]
    $cid = "$ClientId".Trim().ToLowerInvariant()
    $res = { param([string]$state, [string]$support) [pscustomobject]@{ State = $state; Ok = ($state -in 'in-place', 'given'); Scope = $(if ($state -in 'in-place', 'given') { Get-SIMcpScopeValue -ClientId $cid } else { '' }); Lines = $lines.ToArray(); Support = $support } }
    $rights = { param([string]$m) "$m" -match '(?i)\b(401|403)\b|Authorization_RequestDenied|Insufficient privileges|Forbidden' }
    if ($cid -notmatch '^[0-9a-f-]{36}$') { $lines.Add('the MCP scope: no sign-in app registration (AzureAd__ClientId) -- not checked'); return (& $res 'failed' '') }
    $step = 'read'
    try {
        $readApp = { & $Graph 'GET' ("$GraphBase/applications(appId='{0}')?`$select=id,identifierUris,api" -f $cid) $null }
        $app = & $readApp
        if (-not $app -or -not [string](Get-SIMcpScopeProp $app @('id'))) { $lines.Add(('the MCP scope: the sign-in app registration {0} was not found' -f $cid)); return (& $res 'failed' '') }
        $plan = Get-SIMcpScopePlan -App $app -ClientId $cid
        if (-not $plan.Body) { $lines.Add(('the MCP scope: api://{0}/{1} is in place' -f $cid, $script:SIMcpScope)); return (& $res 'in-place' '') }
        $what = @()
        if ($plan.NeedUri) { $what += ('the identifier URI api://{0}' -f $cid) }
        if ($plan.NeedScope) { $what += ('the delegated scope {0} (admin consent), beside the scopes the app has' -f $script:SIMcpScope) }
        if ($Mode -eq 'plan') { $lines.Add(('the MCP scope -- would add on the sign-in app registration {0}: {1} (nothing was changed)' -f $cid, ($what -join '; '))); return (& $res 'planned' '') }
        $step = 'write'
        $null = & $Graph 'PATCH' ("$GraphBase/applications/{0}" -f (Get-SIMcpScopeProp $app @('id'))) $plan.Body
        $step = 'read back'
        $last = ''
        foreach ($w in $Waits) {
            if ($w -gt 0) { & $Sleep $w }
            $t = Test-SIMcpScopeReadBack -Before $app -After (& $readApp) -ClientId $cid
            if ($t.Ok) { $lines.Add(('the MCP scope: added {0} on the sign-in app registration {1} (read back; every other scope kept)' -f ($what -join '; '), $cid)); return (& $res 'given' '') }
            $last = $t.Why
        }
        $lines.Add(('the MCP scope: {0} written but does not read back yet ({1}) -- the next update checks again' -f ($what -join '; '), $last))
        & $res 'failed' ''
    } catch {
        $m = [string]$_.Exception.Message
        if ((& $rights $m) -and $step -in 'read', 'read back') {
            $lines.Add(('the MCP scope: this sign-in may not read the sign-in app registration {0} ({1}: {2}) -- whether api://{0}/{3} is in place is not known' -f $cid, $step, $m, $script:SIMcpScope))
            return (& $res 'no-read' '')
        }
        if (& $rights $m) {
            $sup = ('on the sign-in app registration {0}: add the delegated scope {1} (admin consent) beside its other scopes -- the updater may not write the registration here (New-SIManagementAppRegistration.ps1 -Apply adds it)' -f $cid, $script:SIMcpScope)
            $lines.Add(('the MCP scope: this sign-in may not change the sign-in app registration ({0})' -f $m))
            return (& $res 'no-rights' $sup)
        }
        $lines.Add(('the MCP scope: {0} failed ({1})' -f $step, $m))
        & $res 'failed' ''
    }
}
