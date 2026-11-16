#Requires -Version 5.1
<#
    SECURITYINSIGHT -- THE UPDATER'S TWO RIGHTS ON THE WEB APP'S SIGN-IN APP REGISTRATION, GIVEN BY SETUP (SI #1268, the
    owner's approved rights list 2026-11-15; setup/_shared/si-identity-rights.json updater.graph.Application.ReadWrite.OwnedBy
    and updater.appOwner.SigninApp).

    The updater keeps the sign-in app current on every update (its redirect addresses, the sign-in API scope, the MCP scope,
    the web identity's federated credential -- container/updater/_shared/SI-UpdaterWebApp.ps1, setup/_shared/SI-McpScope.ps1).
    It may change ONLY applications it owns, so it needs both:
      role   the Microsoft Graph application permission Application.ReadWrite.OwnedBy (id read BY VALUE from Graph's own
             service principal, the roles an application may hold) -- granted only when missing, READ BACK;
      owner  the updater identity as an OWNER of the sign-in app registration (applications/{id}/owners/$ref) -- added only
             when missing, READ BACK from the app's owners.
    Run with the sign-in of the person (or the Invardia Support app) running setup: the updater can never give itself either.
    A refusal is one plain customer step, never a stop of setup.

    -Graph { param([string]$Method, [string]$Uri, $Body) } -> the parsed answer; THROWS on an error (HTTP status in the text).
    PS 5.1 + pwsh 7, no module.
#>

function Get-SIUpdaterSigninRightsProp {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] }; return $null }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; $null
}

function Grant-SIUpdaterSigninRights {
    <#
        The updater identity (-PrincipalId, its service principal's object id) given Application.ReadWrite.OwnedBy and made an
        owner of the sign-in app (-SigninClientId, its application / client id), each only when missing and each READ BACK.
        -Apply:$false = read only (what is missing is said). Returns @{ Ok; RoleOk; OwnerOk; Lines }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$PrincipalId, [string]$SigninClientId = '',
          [switch]$Apply, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ReadBackTries = 4, [int]$ReadBackSeconds = 5)
    $lines = New-Object System.Collections.Generic.List[string]
    $refused = { param($m) "$m" -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges|Forbidden' }
    $short = { param($m) $t = ([string]$m -replace '\s+', ' ').Trim(); if ($t.Length -gt 240) { $t = $t.Substring(0, 237) + '...' }; $t }
    $role = 'Application.ReadWrite.OwnedBy'
    $roleOk = $false; $ownerOk = $false
    # ---- role: Application.ReadWrite.OwnedBy, by value, read back ----
    try {
        $gsp = @(Get-SIUpdaterSigninRightsProp (& $Graph 'GET' "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles" $null) 'value' | Where-Object { $_ })[0]
        $gspId = [string](Get-SIUpdaterSigninRightsProp $gsp 'id')
        $ar = @(@(Get-SIUpdaterSigninRightsProp $gsp 'appRoles') | Where-Object { $_ -and [string](Get-SIUpdaterSigninRightsProp $_ 'value') -ceq $role -and @(Get-SIUpdaterSigninRightsProp $_ 'allowedMemberTypes') -contains 'Application' })[0]
        $rid = ([string](Get-SIUpdaterSigninRightsProp $ar 'id')).ToLowerInvariant()
        if (-not $gspId -or -not $rid) { throw ('Microsoft Graph''s application permission {0} was not found in this tenant' -f $role) }
        $held = {
            $out = New-Object System.Collections.Generic.List[string]
            $next = 'https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $PrincipalId
            for ($i = 0; $next -and $i -lt 20; $i++) {
                $pg = & $Graph 'GET' $next $null
                foreach ($a in @(Get-SIUpdaterSigninRightsProp $pg 'value' | Where-Object { $_ })) { if ([string](Get-SIUpdaterSigninRightsProp $a 'resourceId') -eq $gspId) { $out.Add(([string](Get-SIUpdaterSigninRightsProp $a 'appRoleId')).ToLowerInvariant()) } }
                $next = [string](Get-SIUpdaterSigninRightsProp $pg '@odata.nextLink')
            }
            , $out.ToArray()
        }
        if ((& $held) -contains $rid) { $roleOk = $true; $lines.Add(('the updater identity holds the Microsoft Graph application permission {0} (read back)' -f $role)) }
        elseif (-not $Apply) { $lines.Add(('plan: the updater identity is given the Microsoft Graph application permission {0} (it changes only the apps it owns: the sign-in app)' -f $role)) }
        else {
            try { $null = & $Graph 'POST' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $PrincipalId) ([ordered]@{ principalId = $PrincipalId; resourceId = $gspId; appRoleId = $rid }) }
            catch { if ("$($_.Exception.Message)" -notmatch '(?i)already exist') { throw } }
            for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) { if ((& $held) -contains $rid) { $roleOk = $true; break }; if ($i -lt $ReadBackTries -and $Sleep) { & $Sleep $ReadBackSeconds } }
            if ($roleOk) { $lines.Add(('the updater identity is given the Microsoft Graph application permission {0} (read back)' -f $role)) }
            else { $lines.Add(('the updater identity''s Microsoft Graph application permission {0} was granted, but does not read back yet -- run setup again' -f $role)) }
        }
    } catch {
        $m = [string]$_.Exception.Message
        $lines.Add($(if (& $refused $m) { 'customer step: an Entra administrator (Privileged Role Administrator, or the right to grant application permissions) gives the updater identity {0} the Microsoft Graph application permission {1}, then runs setup again -- this sign-in may not ({2})' -f $PrincipalId, $role, (& $short $m) }
                     else { 'the updater identity''s Microsoft Graph application permission {0} could not be checked ({1}) -- run setup again' -f $role, (& $short $m) }))
    }
    # ---- owner of the sign-in app registration, read back ----
    if (-not "$SigninClientId".Trim()) {
        $lines.Add('the sign-in app registration is not known to this run (the web app is not there yet) -- the updater identity is made its owner when setup runs again')
    } else {
        try {
            $app = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications(appId='{0}')?`$select=id,appId" -f "$SigninClientId".Trim()) $null
            $appObj = [string](Get-SIUpdaterSigninRightsProp $app 'id')
            if (-not $appObj) { throw ('the sign-in app registration {0} was not found' -f $SigninClientId) }
            $owners = { @(@(Get-SIUpdaterSigninRightsProp (& $Graph 'GET' ("https://graph.microsoft.com/v1.0/applications/{0}/owners?`$select=id" -f $appObj) $null) 'value') | Where-Object { $_ } | ForEach-Object { ([string](Get-SIUpdaterSigninRightsProp $_ 'id')).ToLowerInvariant() }) }
            $pidL = $PrincipalId.ToLowerInvariant()
            if ((& $owners) -contains $pidL) { $ownerOk = $true; $lines.Add('the updater identity is an owner of the sign-in app registration (read back)') }
            elseif (-not $Apply) { $lines.Add('plan: the updater identity is made an owner of the sign-in app registration (it keeps the app current on every update)') }
            else {
                try { $null = & $Graph 'POST' ('https://graph.microsoft.com/v1.0/applications/{0}/owners/$ref' -f $appObj) ([ordered]@{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/{0}' -f $PrincipalId) }) }
                catch { if ("$($_.Exception.Message)" -notmatch '(?i)already exist') { throw } }
                for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) { if ((& $owners) -contains $pidL) { $ownerOk = $true; break }; if ($i -lt $ReadBackTries -and $Sleep) { & $Sleep $ReadBackSeconds } }
                if ($ownerOk) { $lines.Add('the updater identity is made an owner of the sign-in app registration (read back)') }
                else { $lines.Add('the updater identity was added as an owner of the sign-in app registration, but it does not read back yet -- run setup again') }
            }
        } catch {
            $m = [string]$_.Exception.Message
            $lines.Add($(if (& $refused $m) { 'customer step: an owner of the sign-in app registration {0} (or an Application Administrator) adds the updater identity {1} as an owner (Entra admin center: App registrations > the app > Owners), then runs setup again -- this sign-in may not ({2})' -f $SigninClientId, $PrincipalId, (& $short $m) }
                         else { 'the owners of the sign-in app registration could not be checked ({0}) -- run setup again' -f (& $short $m) }))
        }
    }
    [pscustomobject]@{ Ok = ($roleOk -and $ownerOk); RoleOk = $roleOk; OwnerOk = $ownerOk; Lines = $lines.ToArray() }
}
