<#
    SECURE-WEB-1 (framework 12.11f, Invardia 2026-11-14): THE INTERNET-FACING IDENTITIES HOLD NO RIGHT THAT RUNS CODE AS ANOTHER
    IDENTITY OR CHANGES RIGHTS.

    SecurityInsight's container APPS (the web app with its sign-in front, the MCP app) are reachable from the internet. Every
    container in an app can take the app's managed identity tokens, so whatever that identity may do, a compromised container
    may do. A job right is the worst of it: a job START alone accepts a container override, so "start a job" = "run my own
    command as the job's identity" (the engine's or the updater's, which hold far more). The rule: such an identity holds only
    its own data rights -- never a job right, Owner / Contributor, a role-assignment right, AcrPush, or a vault-wide secret role.

    Invoke-SIWebJobRightsConverge -- run by the updater on every update (it holds Role Based Access Control Administrator on
    the install's resource group): every identity of every container app in the install's resource group is read; any
    assignment of a FORBIDDEN role (by built-in role definition GUID) at the resource group or below is DELETED and READ BACK.
    One above the resource group (subscription / management group) cannot be removed by the updater: it is said as a support
    step, never a customer action. NEVER throws; a read that fails is said ("not checked"), never "clean".

    Seam: -Arm { param([string]$Method, [string]$Path, [string]$ApiVersion) } -> the parsed answer (GET of a list: the object
    with .value; a 404 on GET: $null); anything else that is not a success THROWS. -Sleep { param([int]$Seconds) } for tests.
#>

$script:SIWebJobRightsApi = @{ Apps = '2024-03-01'; Roles = '2022-04-01' }

# The built-in role definitions (GUIDs are the same in every tenant; read back against Azure's names 2026-11-14).
$script:SIWebForbiddenRoleGuids = [ordered]@{
    '4e3d2b60-56ae-4dc6-a233-09c8e5a82e68' = 'Container Apps Jobs Contributor'
    'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' = 'Container Apps Jobs Operator'
    '358470bc-b998-42bd-ab17-a7e34c199c0f' = 'Container Apps Contributor'
    '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
    'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
    '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
    'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
    '8311e382-0749-4cb8-b61a-304f252e45ec' = 'AcrPush'
    'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
    '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
    # roles that let an identity give itself or others more (Invardia review 2026-11-14)
    'f1a07417-d97a-45cb-824c-7a7467783830' = 'Managed Identity Operator'
    'e40ec5ca-96e0-45a2-b4ff-59039f2c2b59' = 'Managed Identity Contributor'
    '8b54135c-b56d-4d72-a534-26097cfdc8d8' = 'Key Vault Data Access Administrator'
    '57cc5028-e6a7-4284-868d-0611c5923f8d' = 'Container Apps ManagedEnvironments Contributor'
}

function Get-SIWebForbiddenRoleName {
    <# PURE. The forbidden role's name for a role definition id or GUID, '' when the role is allowed. #>
    param([string]$RoleDefinitionId)
    $g = ("$RoleDefinitionId" -split '/')[-1].Trim().ToLowerInvariant()
    if ($script:SIWebForbiddenRoleGuids.Contains($g)) { return [string]$script:SIWebForbiddenRoleGuids[$g] }
    ''
}

function Get-SIWebAppPrincipals {
    <# PURE. Every managed identity principal of the container apps in -Apps: @{ PrincipalId; App; Identity }. #>
    param([object[]]$Apps = @())
    $out = New-Object System.Collections.Generic.List[object]; $seen = @{}
    foreach ($a in @($Apps | Where-Object { $_ })) {
        $app = [string]$a.name
        $id = $a.identity
        if (-not $id) { continue }
        if ($id.PSObject.Properties['principalId'] -and [string]$id.principalId) {
            $p = ([string]$id.principalId).ToLowerInvariant()
            if (-not $seen.ContainsKey($p)) { $seen[$p] = $true; $out.Add([pscustomobject]@{ PrincipalId = $p; App = $app; Identity = 'system-assigned' }) }
        }
        if ($id.PSObject.Properties['userAssignedIdentities'] -and $id.userAssignedIdentities) {
            foreach ($u in @($id.userAssignedIdentities.PSObject.Properties)) {
                $p = ([string]$u.Value.principalId).ToLowerInvariant()
                if (-not $p -or $seen.ContainsKey($p)) { continue }
                $seen[$p] = $true; $out.Add([pscustomobject]@{ PrincipalId = $p; App = $app; Identity = (([string]$u.Name) -split '/')[-1] })
            }
        }
    }
    $out.ToArray()
}

function Test-SIScopeInResourceGroup {
    <# PURE. $true when -Scope is the resource group -ResourceGroupId or a resource below it. #>
    param([string]$Scope, [string]$ResourceGroupId)
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant(); $rg = "$ResourceGroupId".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $s -or -not $rg) { return $false }
    ($s -eq $rg) -or $s.StartsWith($rg + '/')
}

function Get-SIWebJobRightsPlan {
    <# PURE. Of -Assignments (ARM roleAssignment objects) the forbidden ones held by -Principals:
       @{ Remove (in the resource group: the updater removes them); Above (above it: a support step);
          Shared (the identity is ALSO on a job -- -JobPrincipals: @{ principalId = 'job, job' } -- never removed here: the job
          may need the right mid-run; a SECURITY support step: the identity is detached from the app instead) }. #>
    param([object[]]$Assignments = @(), [object[]]$Principals = @(), [Parameter(Mandatory)][string]$ResourceGroupId, [hashtable]$JobPrincipals = @{})
    $byPid = @{}; foreach ($p in @($Principals)) { $byPid[[string]$p.PrincipalId] = $p }
    $remove = New-Object System.Collections.Generic.List[object]; $above = New-Object System.Collections.Generic.List[object]; $shared = New-Object System.Collections.Generic.List[object]; $seen = @{}
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $pid_ = ([string]$a.properties.principalId).ToLowerInvariant()
        if (-not $byPid.ContainsKey($pid_)) { continue }
        $name = Get-SIWebForbiddenRoleName -RoleDefinitionId ([string]$a.properties.roleDefinitionId)
        if (-not $name) { continue }
        $aid = ([string]$a.id); if ($seen.ContainsKey($aid.ToLowerInvariant())) { continue }; $seen[$aid.ToLowerInvariant()] = $true
        $jobs = if ($JobPrincipals.ContainsKey($pid_)) { [string]$JobPrincipals[$pid_] } else { '' }
        $row = [pscustomobject]@{ Id = $aid; Role = $name; Scope = [string]$a.properties.scope; App = $byPid[$pid_].App; Identity = $byPid[$pid_].Identity; PrincipalId = $pid_; Jobs = $jobs }
        if ($jobs) { $shared.Add($row) }
        elseif (Test-SIScopeInResourceGroup -Scope $row.Scope -ResourceGroupId $ResourceGroupId) { $remove.Add($row) } else { $above.Add($row) }
    }
    [pscustomobject]@{ Remove = $remove.ToArray(); Above = $above.ToArray(); Shared = $shared.ToArray() }
}

function Invoke-SIWebJobRightsConverge {
    <# Reads, removes, reads back. @{ Ok; State (clean | removed | partial | not-checked); Lines; Removed; Failed; Above }. NEVER throws. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [scriptblock]$Sleep, [int]$ReadBackTries = 6)
    $lines = New-Object System.Collections.Generic.List[string]
    $res = [pscustomobject]@{ Ok = $false; State = 'not-checked'; Lines = $lines; Removed = @(); Failed = @(); Above = @() }
    $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    try {
        $apps = @((& $Arm 'GET' ($rgId + '/providers/Microsoft.App/containerApps') $script:SIWebJobRightsApi.Apps).value)
        $principals = @(Get-SIWebAppPrincipals -Apps $apps)
        if (-not $principals.Count) { $res.Ok = $true; $res.State = 'clean'; $lines.Add('internet-facing identities: no container app identity in the resource group -- nothing to check'); return $res }
        # an identity that is ALSO on a job is never stripped here (the job may need the right mid-run)
        $jobPids = @{}
        foreach ($jp in @(Get-SIWebAppPrincipals -Apps @((& $Arm 'GET' ($rgId + '/providers/Microsoft.App/jobs') $script:SIWebJobRightsApi.Apps).value))) {
            $jobPids[$jp.PrincipalId] = (@(@($jobPids[$jp.PrincipalId]) + $jp.App | Where-Object { $_ }) -join ', ')
        }
        $assign = New-Object System.Collections.Generic.List[object]
        foreach ($p in $principals) {
            $f = [uri]::EscapeDataString("principalId eq '$($p.PrincipalId)'")
            foreach ($a in @((& $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}' -f $rgId, $f) $script:SIWebJobRightsApi.Roles).value)) { $assign.Add($a) }
        }
        $plan = Get-SIWebJobRightsPlan -Assignments $assign.ToArray() -Principals $principals -ResourceGroupId $rgId -JobPrincipals $jobPids
    } catch {
        $lines.Add(('internet-facing identities: NOT CHECKED ({0}) -- the next update tries again' -f ($_.Exception.Message -replace '\s+', ' ')))
        return $res
    }
    $who = ($principals | ForEach-Object { '{0} ({1})' -f $_.Identity, $_.App }) -join ', '
    $removed = New-Object System.Collections.Generic.List[object]; $failed = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($plan.Remove)) {
        $gone = $false; $why = ''
        try {
            $null = & $Arm 'DELETE' $r.Id $script:SIWebJobRightsApi.Roles
            for ($i = 0; $i -lt [Math]::Max(1, $ReadBackTries); $i++) {
                if ($null -eq (& $Arm 'GET' $r.Id $script:SIWebJobRightsApi.Roles)) { $gone = $true; break }
                if ($Sleep) { & $Sleep 5 } else { Start-Sleep -Seconds 5 }
            }
            if (-not $gone) { $why = 'still there after the removal' }
        } catch { $why = ($_.Exception.Message -replace '\s+', ' ') }
        if ($gone) { $removed.Add($r); $lines.Add(('internet-facing identity {0} ({1}): "{2}" on {3} REMOVED (read back)' -f $r.Identity, $r.App, $r.Role, $r.Scope)) }
        else { $failed.Add($r); $lines.Add(('internet-facing identity {0} ({1}): "{2}" on {3} NOT removed: {4} -- the next update tries again' -f $r.Identity, $r.App, $r.Role, $r.Scope, $why)) }
    }
    foreach ($r in @($plan.Above)) {
        $lines.Add(('support step: internet-facing identity {0} ({1}) holds "{2}" on {3}, above the install''s resource group -- the updater may not remove it there; the Support app removes it' -f $r.Identity, $r.App, $r.Role, $r.Scope))
    }
    foreach ($r in @($plan.Shared)) {
        $lines.Add(('SECURITY support step: identity {0} is shared by the internet-facing app {1} and the job(s) {2}; it holds "{3}" on {4} -- NOT removed here (the job may need it); detach the identity from the app' -f $r.Identity, $r.App, $r.Jobs, $r.Role, $r.Scope))
    }
    $res.Removed = $removed.ToArray(); $res.Failed = $failed.ToArray(); $res.Above = @($plan.Above)
    $res | Add-Member -NotePropertyName Shared -NotePropertyValue @($plan.Shared) -Force
    if (-not @($plan.Remove).Count -and -not @($plan.Above).Count -and -not @($plan.Shared).Count) { $res.State = 'clean'; $lines.Add(('internet-facing identities: none holds a job, owner, contributor, role-assignment, registry-push or vault-admin right ({0})' -f $who)) }
    elseif ($failed.Count -or @($plan.Above).Count -or @($plan.Shared).Count) { $res.State = 'partial' }
    else { $res.State = 'removed' }
    $res.Ok = ($failed.Count -eq 0 -and -not @($plan.Above).Count -and -not @($plan.Shared).Count)
    $res
}
