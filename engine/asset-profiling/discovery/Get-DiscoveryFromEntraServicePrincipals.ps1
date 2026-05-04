#Requires -Version 5.1
<#
    Discovery source: Entra ID service principals (for the identity engine).

    Endpoint: GET https://graph.microsoft.com/v1.0/servicePrincipals
    Auth:     Microsoft Graph with Application.Read.All

    Returns Entra service principal objects -- app registrations, managed
    identities, and legacy SPs. SPs are a major identity-side risk surface:
    orphan SPs (no owner), multi-tenant SPs with high permissions,
    SPs with expiring/expired credentials, etc.

    Hint inference:
      managed-identity -- servicePrincipalType == 'ManagedIdentity'
      first-party      -- Microsoft-published (well-known tenant ID)
      multi-tenant     -- signInAudience indicates multi-tenant
      app-registration -- our-tenant SP backed by an app registration
      legacy           -- servicePrincipalType == 'Legacy'

    NOTE: 1st-party Microsoft SPs are INCLUDED by default (there are
    hundreds, but they appear in EG / Defender views and customers
    generally want parity with what's visible in those tools).
    Opt out: $global:SI_IncludeFirstPartySpns = $false  -- skips
    SPs whose appOwnerOrganizationId == Microsoft 1st-party tenant.
#>

function Get-DiscoveryFromEntraServicePrincipals {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'Entra-SP discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    . (Join-Path (Split-Path -Parent $PSScriptRoot) "shared/IdentityRoleFetcher.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('EntraServicePrincipals: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # bulk-fetch tenant-wide role + perm data ONCE, then bucket by
    # principalId for O(1) per-SP lookup. Mirrors legacy IAC's batch model.
    Write-SIInfo '[perms] fetching tenant-wide Entra role definitions...'
    $roleDefMap = Get-SIEntraRoleDefinitionMap -Token $token
    Write-SIInfo ('[perms] role assignments (permanent)...')
    $permRolesMap = Get-SIEntraRoleAssignmentsByPrincipal -Token $token -RoleDefinitionMap $roleDefMap
    Write-SIInfo ('[perms] role assignments (PIM eligible)...')
    $eligRolesMap = Get-SIEntraPIMEligibleByPrincipal -Token $token -RoleDefinitionMap $roleDefMap
    Write-SIInfo ('[perms] building appRole resolver (resourceSP appRoles[])...')
    $appRoleResolver = Get-SIAppRolePermissionResolver -Token $token
    Write-SIInfo ('[perms] {0} role defs, {1} principals with permanent roles, {2} with PIM eligible' -f $roleDefMap.Count, $permRolesMap.Count, $eligRolesMap.Count)

    # transitive group -> role expansion (mostly affects User assets,
    # but SPs can also be group members so we wire the same lookup here).
    Write-SIInfo '[perms] discovering role-assigned groups...'
    $groupRoles = Get-SIRoleAssignedGroups -Token $token -PermanentRolesByPrincipal $permRolesMap -EligibleRolesByPrincipal $eligRolesMap
    Write-SIInfo ('[perms] {0} groups hold Entra roles -- expanding transitive memberships...' -f $groupRoles.Count)
    $memberToGroups = if ($groupRoles.Count -gt 0) {
        Get-SIGroupTransitiveMembers -Token $token -RoleAssignedGroupMap $groupRoles
    } else { @{} }
    # PIM-for-Groups (cache hit -- already fetched by EntraUsers discovery in same run).
    $pimGroupsMap = if ($groupRoles.Count -gt 0) {
        Get-SIPimForGroupsByPrincipal -Token $token -RoleAssignedGroupMap $groupRoles
    } else { @{} }
    Write-SIInfo ('[perms] {0} principals inherit at least one role via group membership' -f $memberToGroups.Count)

    # Azure RBAC delegations (scope-aware Max).
    $azureLookup = Get-SIAzureDelegationsByPrincipal -ExcludeSubscriptionPatterns @($global:SI_AzureSubscriptionExcludePatterns)

    # SP sign-in activity from LA. same Defender-workspace
    # split as IdentityInfo -- AAD*SignInLogs typically live in the Sentinel/
    # Defender workspace, not the SI output workspace.
    $defenderWs   = if ($global:SI_DefenderWorkspaceResourceId) { $global:SI_DefenderWorkspaceResourceId } else { $global:SI_WorkspaceResourceId }
    $defenderNote = if ($global:SI_DefenderWorkspaceResourceId) { 'separate Defender workspace' } else { 'same as output workspace' }
    Write-SIInfo ('[perms] fetching SP sign-in activity from Log Analytics ({0})...' -f $defenderNote)
    $spnSignInMap = Get-SISpnSignInLastActivity -WorkspaceResourceId $defenderWs

    # EG identity enrichment (cached -- already pulled by Users discovery if it ran first;
    # otherwise this fires the bulk hunting query). Indexed by AAD ObjectId.
    $egIdentitiesMap = Get-SIExposureGraphIdentities

    $microsoftFirstPartyTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    # Default = include 1st-party SPs (parity with EG / Defender views).
    # Customer opts out by setting $global:SI_IncludeFirstPartySpns = $false.
    $includeFirstParty = if ($null -ne $global:SI_IncludeFirstPartySpns) { [bool]$global:SI_IncludeFirstPartySpns } else { $true }

    $rows = New-Object System.Collections.ArrayList
    # include customSecurityAttributes
    $url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,signInAudience,accountEnabled,publisherName,verifiedPublisher,appOwnerOrganizationId,passwordCredentials,keyCredentials,tags,homepage,customSecurityAttributes,createdDateTime&$top=999'

    try {
        do {
            $resp = Invoke-RestMethod -Method Get -Uri $url `
                -Headers @{ Authorization = ('Bearer ' + $token) }
            foreach ($sp in $resp.value) { [void]$rows.Add($sp) }
            $url = $resp.'@odata.nextLink'
        } while ($url)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('EntraServicePrincipals: /servicePrincipals call failed -- {0}' -f $msg)
        return @()
    }

    $now = [datetime]::UtcNow
    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EntraSPs' -ErrorAction SilentlyContinue
    foreach ($sp in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EntraSPs' -Index $_i -Total $_total } catch { }
        # Skip 1st-party Microsoft SPs unless customer opts in
        if (-not $includeFirstParty -and $sp.appOwnerOrganizationId -eq $microsoftFirstPartyTenantId) {
            continue
        }

        $name = $sp.displayName
        if (-not $name) { $name = $sp.id }

        $hint = if ($sp.servicePrincipalType -eq 'ManagedIdentity') { 'managed-identity' }
                elseif ($sp.appOwnerOrganizationId -eq $microsoftFirstPartyTenantId) { 'first-party' }
                elseif ($sp.signInAudience -in 'AzureADMultipleOrgs','AzureADandPersonalMicrosoftAccount') { 'multi-tenant' }
                elseif ($sp.servicePrincipalType -eq 'Legacy') { 'legacy' }
                else { 'app-registration' }

        $credCount = 0
        $credExpiringSoon = 0
        $credExpired = 0
        foreach ($collection in @($sp.passwordCredentials, $sp.keyCredentials)) {
            foreach ($c in $collection) {
                if (-not $c) { continue }
                $credCount++
                if ($c.endDateTime) {
                    try {
                        $end = [datetime]$c.endDateTime
                        if ($end -lt $now) { $credExpired++ }
                        elseif ($end -lt $now.AddDays(30)) { $credExpiringSoon++ }
                    } catch { }
                }
            }
        }

        # per-SP perm enumeration (admin-consented application
        # perms + delegated oauth2 perms). Both are needed by the catalog
        # tier computer to classify the SP deterministically.
        $appPerms      = Get-SISPAppRoleAssignments -Token $token -ObjectId $sp.id -AppRoleResolver $appRoleResolver
        $delegPerms    = Get-SISPOauth2Grants     -Token $token -ObjectId $sp.id
        $permRoles     = if ($permRolesMap.ContainsKey([string]$sp.id))  { @($permRolesMap[[string]$sp.id])  } else { @() }
        $eligRoles     = if ($eligRolesMap.ContainsKey([string]$sp.id))  { @($eligRolesMap[[string]$sp.id])  } else { @() }
        # append roles inherited via group membership
        $inh = Get-SIInheritedRolesForPrincipal -ObjectId ([string]$sp.id) -MemberToGroupsMap $memberToGroups -RoleAssignedGroupMap $groupRoles -PimGroupsByPrincipal $pimGroupsMap
        $permRoles     = @($permRoles + $inh.Permanent | Select-Object -Unique)
        $eligRoles     = @($eligRoles + $inh.Eligible  | Select-Object -Unique)
        # Azure delegations for the SP + via inherited groups
        $spGroupIds = if ($memberToGroups.ContainsKey([string]$sp.id)) { @($memberToGroups[[string]$sp.id]) } else { @() }
        $azDelegations = New-Object System.Collections.ArrayList
        if ($azureLookup.ContainsKey([string]$sp.id)) { foreach ($e in $azureLookup[[string]$sp.id]) { [void]$azDelegations.Add($e) } }
        foreach ($gid in $spGroupIds) { if ($azureLookup.ContainsKey($gid)) { foreach ($e in $azureLookup[$gid]) { [void]$azDelegations.Add($e) } } }

        # SP sign-in + CSA tags
        $spLastSignIn = if ($spnSignInMap.ContainsKey([string]$sp.id)) { $spnSignInMap[[string]$sp.id] } else { $null }
        $spLastSignInDays = Get-SIDaysSince $spLastSignIn
        $spCsa = ConvertTo-SICustomSecurityAttributes $sp.customSecurityAttributes

        @{
            AssetId                       = 'entra-sp:' + $sp.id
            Source                        = 'EntraServicePrincipal'
            Hint                          = $hint
            Name                          = $name
            # dedup by ObjectId, NOT displayName. First-party SPs
            # ('Microsoft Graph Change Tracking', etc.) reuse the same display
            # name across many app registrations -- name-based dedup collapsed
            # ~828 raw identities to ~401, hiding hundreds of distinct SPs.
            NormalizedKey                 = ([string]$sp.id).ToLowerInvariant()
            ENTRA_SPObjectId              = $sp.id
            ENTRA_SPAppId                 = $sp.appId
            ENTRA_SPType                  = $sp.servicePrincipalType
            ENTRA_SPSignInAudience        = $sp.signInAudience
            ENTRA_SPEnabled               = $sp.accountEnabled
            # Canonical-name aliases so the row builder's identity-type-agnostic
            # key map (DisplayName -> ENTRA_DisplayName, AccountEnabled -> ENTRA_Enabled)
            # resolves for SPNs the same way it does for users. Without these,
            # SPN rows landed with empty DisplayName / AccountEnabled in LA.
            ENTRA_DisplayName             = $sp.displayName
            ENTRA_Enabled                 = $sp.accountEnabled
            ENTRA_Created                 = $sp.createdDateTime
            # SPNs almost never sync from on-prem (only synced gMSA / hybrid scenarios).
            # Coerce null to false so the bool column is populated rather than empty.
            ENTRA_OnPrem                  = $false
            ENTRA_SPPublisher             = $sp.publisherName
            ENTRA_SPVerifiedPublisher     = if ($sp.verifiedPublisher) { $sp.verifiedPublisher.displayName } else { $null }
            ENTRA_SPAppOwnerTenant        = $sp.appOwnerOrganizationId
            ENTRA_SPCredCount             = $credCount
            ENTRA_SPCredExpired           = $credExpired
            ENTRA_SPCredExpiringSoon      = $credExpiringSoon
            ENTRA_SPHomepage              = $sp.homepage
            ENTRA_SPTags                  = $sp.tags
            # catalog inputs for deterministic tier classification.
            ENTRA_AppPermissions_Application = $appPerms     # admin-consented application perms ('Directory.ReadWrite.All', ...)
            ENTRA_AppPermissions_Delegated   = $delegPerms   # oauth2 delegated perms
            ENTRA_DirectoryRolesPermanent = $permRoles       # Entra directory roles (permanent + inherited via groups)
            ENTRA_DirectoryRolesEligible  = $eligRoles       # Entra directory roles (PIM eligible + inherited via groups)
            ENTRA_AzureDelegations        = $azDelegations.ToArray()   # Azure RBAC, scope-aware tier
            # sign-in activity + CSA tags
            ENTRA_LastSignInDateTime      = if ($spLastSignIn) { $spLastSignIn.ToString('o') } else { '' }
            ENTRA_LastSignInDays          = $spLastSignInDays
            ENTRA_CustomSecurityAttributes = ($spCsa | ConvertTo-Json -Depth 6 -Compress)
            # Exposure Graph raw data blob (whole NodeProperties.rawData).
            # Schema-driven row builder walks identity.schema.json sourcePath against this
            # (e.g., eg.node.NodeProperties.rawData.appOwnerOrganizationId / criticalityLevel.*).
            ENTRA_EgRawData               = $(
                $egEntry = $egIdentitiesMap[([string]$sp.id).ToLowerInvariant()]
                if ($egEntry) { $egEntry.RawData } else { $null }
            )
        }
    }
}
