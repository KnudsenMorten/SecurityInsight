#Requires -Version 5.1
<#
    SecurityInsight -- #1390 THE ONE PERMISSION AN UPDATE GRANTS (owner 2026-11-25: "Yes, add the right"; Invardia: the
    update's reconcile grants ONLY that one new permission, nothing else widened, and reads it back).

    setup/_shared/SI-PermissionNote.ps1 stays READ ONLY (it says what is missing). This file is the only place an update
    grants an application permission: the ones in $script:SIPermissionUpdateGrantable -- today ONLY Microsoft Graph
    DeviceManagementApps.Read.All (Intune's audit events: the Intune deletion proof) -- to SecurityInsight's collection
    identity, only when the plan (config/permissions.locked.json) holds it and the identity does not, by value, POSTed once
    and READ BACK. The updater identity may not grant application permissions (it never holds AppRoleAssignment.ReadWrite.All
    -- not widened): there it is one line naming Invardia's Support step; a Support-app-run update grants it itself.
    Uses the note's readers (Get-SIPermissionNoteCatalog / -Identity / -GraphList / Test-SIPermissionNoteSafe), loaded here
    when missing. -Rest is the update's REST seam (setup/_shared/SI-UpdateRest.ps1). PS 5.1 + pwsh 7, no module, no az.
#>
if (-not (Get-Command -Name Get-SIPermissionNoteCatalog -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-PermissionNote.ps1')) }

# =====================================================================================================================
# Every other permission stays as above: said, never granted by the update. This list is the whole of what an update may
# grant, and only to SecurityInsight's own collection identity, only when the plan (config/permissions.locked.json) holds it.
$script:SIPermissionUpdateGrantable = @('DeviceManagementApps.Read.All')

function Get-SIPermissionGrantCommand {
    <#
        PURE. The two lines that grant exactly -Roles to the collection identity (Grant-SIIdentity.ps1 -Only <roles> -Apply:
        the application permissions named, nothing else read or granted) -- what Invardia's Support app runs when the
        update's own sign-in may not grant. '' when a name it needs is not known here.
    #>
    param($Identity, [string]$SubscriptionId, [string[]]$Roles = @())
    if (-not $Identity -or -not @($Roles).Count) { return '' }
    $ok = { param($v) $t = "$v".Trim(); [bool]($t -and (Test-SIPermissionNoteSafe -Value $t)) }
    foreach ($r in $Roles) { if (-not (& $ok $r)) { return '' } }
    if (-not (& $ok $SubscriptionId)) { return '' }
    $cmd = './Grant-SIIdentity.ps1'
    if (-not $Identity.Managed) { if (-not (& $ok $Identity.ClientId)) { return '' }; $cmd += ' -AppId ' + "$($Identity.ClientId)".Trim() }
    elseif ((& $ok $Identity.IdentityName) -and (& $ok $Identity.IdentityResourceGroup)) { $cmd += ' -IdentityName {0} -IdentityResourceGroup {1}' -f "$($Identity.IdentityName)".Trim(), "$($Identity.IdentityResourceGroup)".Trim() }
    elseif (& $ok $Identity.ObjectId) { $cmd += ' -PrincipalId ' + "$($Identity.ObjectId)".Trim() }
    else { return '' }
    ('Invoke-WebRequest {0}Grant-SIIdentity.ps1 -OutFile Grant-SIIdentity.ps1' -f $script:SIPermissionNoteUrlBase) + "`n" + $cmd + (' -SubscriptionId {0} -Only {1} -Apply' -f "$SubscriptionId".Trim(), (@($Roles) -join ','))
}

function Invoke-SIPermissionUpdateGrant {
    <#
        The update's grant of the permissions in $script:SIPermissionUpdateGrantable (today ONLY DeviceManagementApps.Read.All,
        the Intune deletion proof) to SecurityInsight's collection identity -- each only when the plan holds it AND the
        identity does not, by value (the app role id read from the API's own service principal), POSTed once and READ BACK.
        Idempotent: a permission the identity holds is left alone and nothing is said. A sign-in that may not grant
        application permissions (401 / 403 -- the updater identity never holds that right; it is granted by setup or by
        Invardia's Support app running the update / Grant-SIIdentity -Only) is ONE information line naming the exact step,
        never a warning or a failed update. -Apply:$false = the plan only. NEVER throws.
          @{ Granted = string[]; Present = string[]; Refused = string[]; Lines = string[] }
    #>
    param([Parameter(Mandatory)][scriptblock]$Rest, [object[]]$Jobs = @(), [string]$SubscriptionId, [string]$CatalogPath, [switch]$Apply,
          [string[]]$Grantable = $script:SIPermissionUpdateGrantable,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$ReadBackTries = 4, [int]$ReadBackSeconds = 10)
    $out = [ordered]@{ Granted = New-Object System.Collections.Generic.List[string]; Present = New-Object System.Collections.Generic.List[string]; Refused = New-Object System.Collections.Generic.List[string]; Lines = New-Object System.Collections.Generic.List[string] }
    $done = { [pscustomobject]@{ Granted = $out.Granted.ToArray(); Present = $out.Present.ToArray(); Refused = $out.Refused.ToArray(); Lines = $out.Lines.ToArray() } }
    $code = { param($r) $c = 0; try { $c = [int]$r.Status } catch { $c = 0 }; $c }
    try {
        $cat = Get-SIPermissionNoteCatalog -Path $CatalogPath
        $id = Get-SIPermissionNoteIdentity -Jobs $Jobs -Engines $cat.Engines
        if (-not $id) { return (& $done) }
        # only a permission THE PLAN holds (never one this list names alone)
        $want = @(foreach ($g in @($Grantable)) { foreach ($a in @($cat.Apis)) { if ((@($a.Roles) + @($a.SupportRoles)) -contains $g) { [pscustomobject]@{ Api = $a; Role = [string]$g } } } })
        if (-not $want.Count) { return (& $done) }
        $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        # the identity's service principal object id (the job names it, else by its client id)
        $oid = "$($id.ObjectId)".Trim()
        if ($oid -notmatch $guid) {
            if ("$($id.ClientId)".Trim() -notmatch $guid) { return (& $done) }
            $r = & $Rest 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals(appId='{0}')?`$select=id" -f "$($id.ClientId)".Trim()) $null $script:SIPermissionNoteGraph @{}
            if ((& $code $r) -ne 200) { $out.Lines.Add(('permissions: {0} not checked for the update to grant -- the identity could not be read (HTTP {1}); the next update tries again.' -f (($want | ForEach-Object { $_.Role }) -join ', '), (& $code $r))); return (& $done) }
            $oid = "$(([string]$r.Body | ConvertFrom-Json).id)".Trim()
            if ($oid -notmatch $guid) { return (& $done) }
        }
        $held = {
            $l = Get-SIPermissionNoteGraphList -Rest $Rest -Uri ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $oid)
            if ($l.Status -ne 200) { return $null }
            , @($l.Items | ForEach-Object { ('{0}|{1}' -f "$($_.resourceId)".Trim(), "$($_.appRoleId)".Trim()).ToLowerInvariant() })
        }
        $have = & $held
        if ($null -eq $have) { $out.Lines.Add(('permissions: {0} not checked for the update to grant -- this sign-in may not read the identity''s permissions; the next update tries again.' -f (($want | ForEach-Object { $_.Role }) -join ', '))); return (& $done) }
        foreach ($w in $want) {
            $rr = & $Rest 'GET' ("https://graph.microsoft.com/v1.0/servicePrincipals(appId='{0}')?`$select=id,appRoles" -f $w.Api.ResourceAppId) $null $script:SIPermissionNoteGraph @{}
            if ((& $code $rr) -ne 200) { continue }   # the API is not in this directory (or not readable): nothing to grant on it
            $res = [string]$rr.Body | ConvertFrom-Json
            $rid = "$($res.id)".Trim().ToLowerInvariant()
            $role = @(@($res.appRoles) | Where-Object { $_ -and [string]$_.value -ceq $w.Role -and @($_.allowedMemberTypes) -contains 'Application' })[0]
            if (-not $rid -or -not $role) { continue }
            $key = ('{0}|{1}' -f $rid, "$($role.id)".Trim()).ToLowerInvariant()
            if (@($have) -contains $key) { $out.Present.Add($w.Role); continue }
            if (-not $Apply) { $out.Lines.Add(('permissions: plan -- the update grants {0} {1} (read only) to {2}.' -f $w.Api.Resource, $w.Role, $cat.Label)); continue }
            $p = & $Rest 'POST' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments' -f $oid) ([ordered]@{ principalId = $oid; resourceId = $rid; appRoleId = "$($role.id)".Trim() }) $script:SIPermissionNoteGraph @{}
            $pc = & $code $p
            if ($pc -eq 401 -or $pc -eq 403) {
                $out.Refused.Add($w.Role)
                $cmd = Get-SIPermissionGrantCommand -Identity $id -SubscriptionId $SubscriptionId -Roles @($w.Role)
                $out.Lines.Add(('permissions: {0} {1} (read only) is not granted yet -- this update''s sign-in may not grant application permissions (the updater identity never holds that right). Invardia''s Support app grants exactly this one{2}' -f $w.Api.Resource, $w.Role, $(if ($cmd) { ':' } else { ' (Get Started > Permissions shows the lines).' })))
                if ($cmd) { foreach ($c in ($cmd -split "`n")) { if ($c.Trim()) { $out.Lines.Add($c.Trim()) } } }
                continue
            }
            if (($pc -lt 200 -or $pc -ge 300) -and "$($p.Body)" -notmatch '(?i)already exist') {
                $out.Lines.Add(('permissions: {0} {1} could not be granted (HTTP {2}); the next update tries again.' -f $w.Api.Resource, $w.Role, $pc)); continue
            }
            # READ BACK (the directory is eventually consistent)
            $ok = $false
            for ($i = 1; $i -le [Math]::Max(1, $ReadBackTries); $i++) {
                $now = & $held
                if ($null -ne $now -and @($now) -contains $key) { $ok = $true; break }
                if ($i -lt $ReadBackTries -and $Sleep) { & $Sleep $ReadBackSeconds }
            }
            if ($ok) { $out.Granted.Add($w.Role); $out.Lines.Add(('permissions: {0} {1} (read only) granted to {2} and read back.' -f $w.Api.Resource, $w.Role, $cat.Label)) }
            else { $out.Lines.Add(('permissions: {0} {1} was granted to {2} but does not read back yet; the next update checks again.' -f $w.Api.Resource, $w.Role, $cat.Label)) }
        }
    } catch { $out.Lines.Add(('permissions: the update''s grant was not checked ({0}); the next update tries again.' -f $_.Exception.Message)) }
    & $done
}

