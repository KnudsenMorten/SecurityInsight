#Requires -Version 5.1
<#
    Discovery source: Entra ID users (for the identity engine).

    Endpoint: GET https://graph.microsoft.com/v1.0/users
    Auth:     Microsoft Graph with User.Read.All

    Returns Entra user objects -- members + guests + service accounts that
    appear as users. Service principals (apps) are pulled separately by
    Get-DiscoveryFromEntraServicePrincipals.

    OS-hint inference doesn't apply to users; the Hint field reflects the
    user "shape" (member / guest / disabled / on-prem-sync) instead.
#>

function Get-DiscoveryFromEntraUsers {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'Entra-users discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    . (Join-Path (Split-Path -Parent $PSScriptRoot) "shared/IdentityRoleFetcher.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('EntraUsers: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # bulk fetch tenant-wide role assignments (permanent + PIM
    # eligible) once, bucket by principalId for O(1) per-user lookup.
    Write-SIInfo '[perms] fetching tenant-wide Entra role definitions...'
    $roleDefMap   = Get-SIEntraRoleDefinitionMap -Token $token
    Write-SIInfo '[perms] role assignments (permanent)...'
    $permRolesMap = Get-SIEntraRoleAssignmentsByPrincipal -Token $token -RoleDefinitionMap $roleDefMap
    Write-SIInfo '[perms] role assignments (PIM eligible)...'
    $eligRolesMap = Get-SIEntraPIMEligibleByPrincipal -Token $token -RoleDefinitionMap $roleDefMap

    # MFA registration bulk fetch -- ONE paged call returns the per-user
    # IsMfaRegistered/IsPasswordlessCapable/methodsRegistered map. Replaces v1's
    # per-user /authentication/methods loop. Permission: UserAuthenticationMethod.Read.All
    # OR AuditLog.Read.All (already required by Step1 onboarding).
    $mfaRegMap = Get-SIEntraMfaRegistrationByPrincipal -Token $token

    # transitive group -> role expansion. Discover which GROUPS hold
    # roles, then walk each role-assigned group's transitiveMembers + invert.
    Write-SIInfo '[perms] discovering role-assigned groups...'
    $groupRoles = Get-SIRoleAssignedGroups -Token $token -PermanentRolesByPrincipal $permRolesMap -EligibleRolesByPrincipal $eligRolesMap
    Write-SIInfo ('[perms] {0} groups hold Entra roles -- expanding transitive memberships...' -f $groupRoles.Count)
    $memberToGroups = if ($groupRoles.Count -gt 0) {
        Get-SIGroupTransitiveMembers -Token $token -RoleAssignedGroupMap $groupRoles
    } else { @{} }
    # PIM-for-Groups: principals who can ELEVATE into a role-bearing group
    # (not currently a member). Without this, EntraRoles_Eligible misses
    # the entire PIM-for-Groups path (User -> PIM Group A -> Role).
    $pimGroupsMap = if ($groupRoles.Count -gt 0) {
        Get-SIPimForGroupsByPrincipal -Token $token -RoleAssignedGroupMap $groupRoles
    } else { @{} }
    Write-SIInfo ('[perms] {0} principals inherit at least one role via group membership' -f $memberToGroups.Count)

    # Azure RBAC delegations (scope-aware Max). Caller must have
    # called Connect-AzAccount; SI bootstrap already does this for the SPN.
    $azureLookup = Get-SIAzureDelegationsByPrincipal -ExcludeSubscriptionPatterns @($global:SI_AzureSubscriptionExcludePatterns)

    # Defender XDR IdentityInfo (synced AD groups + MFA + risk signals).
    # prefer $global:SI_DefenderWorkspaceResourceId (separate Defender/
    # Sentinel workspace) over the SI output workspace -- legacy IAC has the same
    # split. Falls back to $global:SI_WorkspaceResourceId when not set.
    $defenderWs   = if ($global:SI_DefenderWorkspaceResourceId) { $global:SI_DefenderWorkspaceResourceId } else { $global:SI_WorkspaceResourceId }
    $defenderNote = if ($global:SI_DefenderWorkspaceResourceId) { 'separate Defender workspace' } else { 'same as output workspace' }
    Write-SIInfo ('[perms] fetching IdentityInfo from Log Analytics ({0})...' -f $defenderNote)
    $identityInfoMap = Get-SIIdentityInfoByObjectId -WorkspaceResourceId $defenderWs

    # Exposure Graph identity enrichment -- one bulk hunting query,
    # results indexed by AAD ObjectId. Populates the EG-sourced fields declared in
    # identity.schema.json (AdminCount, UserAccountControl, SidHistory, criticalityLevel,
    # nestedAdGroupNames, hasLeakedCredentials, etc.). Schema-driven row builder
    # walks sourcePath against the cached RawData blob -- no per-field hard-coding.
    $egIdentitiesMap = Get-SIExposureGraphIdentities

    $rows = New-Object System.Collections.ArrayList
    # include signInActivity + customSecurityAttributes
    $url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,jobTitle,department,onPremisesSyncEnabled,mail,userType,assignedLicenses,signInActivity,customSecurityAttributes&$top=999'

    try {
        do {
            $resp = Invoke-RestMethod -Method Get -Uri $url `
                -Headers @{ Authorization = ('Bearer ' + $token) }
            foreach ($u in $resp.value) {
                # Stamp IsDeleted=$false on every active-user row so the column
                # exists for the deleted-user merge below (avoids null-vs-missing
                # ambiguity downstream).
                $u | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $false -Force
                [void]$rows.Add($u)
            }
            $url = $resp.'@odata.nextLink'
        } while ($url)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('EntraUsers: /users call failed -- {0}' -f $msg)
        return @()
    }

    # Deleted users -- /directory/deletedItems/microsoft.graph.user lists users
    # that have been soft-deleted in the last 30 days (Entra retention window).
    # EG retains identity nodes longer than Entra's active list, so without this
    # query we silently miss recently-deleted accounts that EG still tracks.
    # Permission required: User.Read.All AND Directory.AccessAsUser.All (or
    # Directory.ReadWrite.All for the tenant). Failure here is non-fatal --
    # active-user discovery already succeeded.
    $deletedUrl = 'https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,deletedDateTime,jobTitle,department,onPremisesSyncEnabled,mail,userType&$top=999'
    $deletedCount = 0
    try {
        do {
            $resp = Invoke-RestMethod -Method Get -Uri $deletedUrl `
                -Headers @{ Authorization = ('Bearer ' + $token) }
            foreach ($u in $resp.value) {
                $u | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $true -Force
                [void]$rows.Add($u)
                $deletedCount++
            }
            $deletedUrl = $resp.'@odata.nextLink'
        } while ($deletedUrl)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('EntraUsers: deletedItems call skipped -- {0} (likely permission gap; active users already loaded).' -f $msg)
    }
    if ($deletedCount -gt 0) {
        Write-SIInfo ('[perms] EntraUsers: included {0} soft-deleted user(s) from /directory/deletedItems' -f $deletedCount)
    }

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EntraUsers' -ErrorAction SilentlyContinue
    foreach ($u in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EntraUsers' -Index $_i -Total $_total } catch { }
        $name = $u.userPrincipalName
        if (-not $name) { $name = $u.displayName }
        if (-not $name) { $name = $u.id }

        $hint = if (-not $u.accountEnabled) { 'disabled' }
                elseif ($u.userType -eq 'Guest') { 'guest' }
                elseif ($u.onPremisesSyncEnabled) { 'on-prem-synced' }
                else { 'cloud-only' }

        $permRoles = if ($permRolesMap.ContainsKey([string]$u.id)) { @($permRolesMap[[string]$u.id]) } else { @() }
        $eligRoles = if ($eligRolesMap.ContainsKey([string]$u.id)) { @($eligRolesMap[[string]$u.id]) } else { @() }
        # append roles inherited via group membership
        $inh = Get-SIInheritedRolesForPrincipal -ObjectId ([string]$u.id) -MemberToGroupsMap $memberToGroups -RoleAssignedGroupMap $groupRoles -PimGroupsByPrincipal $pimGroupsMap
        $permRoles = @($permRoles + $inh.Permanent | Select-Object -Unique)
        $eligRoles = @($eligRoles + $inh.Eligible  | Select-Object -Unique)
        # Azure delegations -- include direct + via inherited groups
        $userGroupIds = if ($memberToGroups.ContainsKey([string]$u.id)) { @($memberToGroups[[string]$u.id]) } else { @() }
        $azDelegations = New-Object System.Collections.ArrayList
        if ($azureLookup.ContainsKey([string]$u.id)) { foreach ($e in $azureLookup[[string]$u.id]) { [void]$azDelegations.Add($e) } }
        foreach ($gid in $userGroupIds) { if ($azureLookup.ContainsKey($gid)) { foreach ($e in $azureLookup[$gid]) { [void]$azDelegations.Add($e) } } }

        # IdentityInfo enrichment (AD groups + MFA + risk + investigation priority)
        $ii = $identityInfoMap[[string]$u.id]
        $adGroups = if ($ii) { ConvertTo-SIADGroupNames $ii.GroupMembership } else { @() }

        # EG enrichment lookup (cached from Get-SIExposureGraphIdentities call above).
        # The full RawData blob lands on the record; the schema-driven row builder walks
        # arbitrary paths declared in identity.schema.json against it. New EG-sourced fields
        # become a JSON edit, no engine code change.
        $egEntry = $egIdentitiesMap[([string]$u.id).ToLowerInvariant()]
        $egRawData = if ($egEntry) { $egEntry.RawData } else { $null }

        # sign-in activity + CSA tags
        $lastInteractive    = if ($u.signInActivity) { $u.signInActivity.lastSignInDateTime } else { $null }
        $lastNonInteractive = if ($u.signInActivity) { $u.signInActivity.lastNonInteractiveSignInDateTime } else { $null }
        $lastSignIn = if ($lastInteractive -and $lastNonInteractive) {
            ([datetime]$lastInteractive, [datetime]$lastNonInteractive | Measure-Object -Maximum).Maximum
        } elseif ($lastInteractive) { [datetime]$lastInteractive }
        elseif ($lastNonInteractive) { [datetime]$lastNonInteractive }
        else { $null }
        $lastSignInDays = Get-SIDaysSince $lastSignIn
        $csa = ConvertTo-SICustomSecurityAttributes $u.customSecurityAttributes

        @{
            AssetId         = 'entra-user:' + $u.id
            Source          = 'EntraUser'
            Hint            = $hint
            Name            = $name
            # dedup by ObjectId, NOT displayName. Two distinct users
            # can share a displayName -- name-based dedup collapsed them to one.
            NormalizedKey   = ([string]$u.id).ToLowerInvariant()
            ENTRA_UserId    = $u.id
            ENTRA_UPN       = $u.userPrincipalName
            ENTRA_DisplayName = $u.displayName
            ENTRA_Enabled   = $u.accountEnabled
            ENTRA_JobTitle  = $u.jobTitle
            ENTRA_Department = $u.department
            ENTRA_Created   = $u.createdDateTime
            ENTRA_OnPrem    = if ($null -ne $u.onPremisesSyncEnabled) { [bool]$u.onPremisesSyncEnabled } else { $false }
            ENTRA_Mail      = $u.mail
            ENTRA_UserType  = $u.userType
            ENTRA_LicenseCount = ($u.assignedLicenses | Measure-Object).Count
            # catalog inputs for deterministic tier classification.
            ENTRA_DirectoryRolesPermanent = $permRoles   # Entra directory roles (permanent + inherited via groups)
            ENTRA_DirectoryRolesEligible = $eligRoles    # Entra directory roles (PIM eligible + inherited via groups)
            # Azure RBAC delegations (scope-aware tier precomputed).
            ENTRA_AzureDelegations       = $azDelegations.ToArray()
            # MFA registration from Graph /reports/authenticationMethods/userRegistrationDetails
            # (bulk fetched in $mfaRegMap above). Authoritative for current MFA state;
            # IdentityInfo's IsMFARegistered below is stale by hours-to-days.
            ENTRA_MfaIsRegistered          = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsMfaRegistered } else { $false })
            ENTRA_MfaIsCapable             = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsMfaCapable } else { $false })
            ENTRA_IsPasswordlessCapable    = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsPasswordlessCapable } else { $false })
            ENTRA_IsSsprRegistered         = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsSsprRegistered } else { $false })
            ENTRA_IsSsprCapable            = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsSsprCapable } else { $false })
            ENTRA_IsSsprEnabled            = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { $mfaRegMap[[string]$u.id].IsSsprEnabled } else { $false })
            ENTRA_MfaMethods               = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { @($mfaRegMap[[string]$u.id].MfaMethods) } else { @() })
            ENTRA_MfaMethodCount           = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { [int]$mfaRegMap[[string]$u.id].MfaMethodCount } else { 0 })
            ENTRA_MfaDefaultMethod         = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { [string]$mfaRegMap[[string]$u.id].DefaultMfaMethod } else { '' })
            ENTRA_MfaSystemPreferredMethods= $(if ($mfaRegMap.ContainsKey([string]$u.id)) { @($mfaRegMap[[string]$u.id].SystemPreferredAuthMethods) } else { @() })
            ENTRA_MfaPreferredSecondary    = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { [string]$mfaRegMap[[string]$u.id].PreferredSecondaryAuthMethod } else { '' })
            ENTRA_MfaLastUpdatedDateTime   = $(if ($mfaRegMap.ContainsKey([string]$u.id)) { [string]$mfaRegMap[[string]$u.id].MfaLastUpdatedDateTime } else { '' })
            # IdentityInfo (AD groups + Defender activity / risk signals)
            ENTRA_Groups                 = $adGroups
            ENTRA_IsMFARegistered        = if ($ii) { [bool]$ii.IsMFARegistered } else { $null }
            ENTRA_IsServiceAccount       = if ($ii) { [bool]$ii.IsServiceAccount } else { $null }
            ENTRA_RiskLevel              = if ($ii) { [string]$ii.RiskLevel } else { $null }
            ENTRA_RiskState              = if ($ii) { [string]$ii.RiskState } else { $null }
            ENTRA_EntityRiskScore        = if ($ii) { $ii.EntityRiskScore } else { $null }
            ENTRA_BlastRadius            = if ($ii) { [string]$ii.BlastRadius } else { $null }
            ENTRA_InvestigationPriority  = if ($ii) { $ii.InvestigationPriority } else { $null }
            ENTRA_OnPremDN               = if ($ii) { [string]$ii.OnPremisesDistinguishedName } else { $null }
            ENTRA_LastSeenDate           = if ($ii) { $ii.LastSeenDate } else { $null }
            # sign-in activity + CSA tags
            ENTRA_LastSignInDateTime     = if ($lastSignIn) { $lastSignIn.ToString('o') } else { '' }
            ENTRA_LastSignInDays         = $lastSignInDays
            ENTRA_LastInteractiveSignIn  = if ($lastInteractive) { [string]$lastInteractive } else { '' }
            ENTRA_CustomSecurityAttributes = ($csa | ConvertTo-Json -Depth 6 -Compress)
            # Exposure Graph raw data blob (whole NodeProperties.rawData).
            # The schema-driven row builder walks paths declared in identity.schema.json
            # against this blob (source=exposureGraph + sourcePath=eg.node.NodeProperties.rawData.<path>).
            ENTRA_EgRawData              = $egRawData
        }
    }
}
