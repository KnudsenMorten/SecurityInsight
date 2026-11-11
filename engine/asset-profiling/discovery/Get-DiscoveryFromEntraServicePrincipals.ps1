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

# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }
# the owners read (ENTRA_OwnerCount on each record, the 'owners' record part)
if (-not (Get-Command -Name Get-SISpOwnerCount -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }
# the application registrations (their owners count with the principal's own) and the rest of the Entra context
if (-not (Get-Command -Name Get-SIEntraApplications -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIEntraContext.ps1') }

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
    # #1049 F0: each phase's time (a log line + a cfg.StepPhaseTime row); measurement only
    Reset-SIIdentityPhaseTotals
    $ph = Start-SIIdentityPhase -Phase 'service principals: Entra roles + application role names'
    Write-SIInfo '[perms] fetching tenant-wide Entra role definitions...'
    $roleDefMap = Get-SIEntraRoleDefinitionMap -Token $token
    Write-SIInfo ('[perms] role assignments (permanent)...')
    $permRolesMap = Get-SIEntraRoleAssignmentsByPrincipal -Token $token -RoleDefinitionMap $roleDefMap
    Write-SIInfo ('[perms] role assignments (PIM eligible)...')
    $eligRolesMap = Get-SIEntraPIMEligibleByPrincipal -Token $token -RoleDefinitionMap $roleDefMap
    Write-SIInfo ('[perms] building appRole resolver (resourceSP appRoles[])...')
    $appRoleResolver = Get-SIAppRolePermissionResolver -Token $token
    Write-SIInfo ('[perms] {0} role defs, {1} principals with permanent roles, {2} with PIM eligible' -f $roleDefMap.Count, $permRolesMap.Count, $eligRolesMap.Count)
    $null = Stop-SIIdentityPhase $ph -Rows ([long](@($permRolesMap.Keys).Count + @($eligRolesMap.Keys).Count)) -Detail 'principals with a permanent or eligible role'
    # #899: why the role facts are partial this run ('' = they are not) -- stamped on every service principal, so a worker of a
    # run collected in parts knows it too (Properties.collect.entra.RoleReadPartial)
    $rolePartial = ''; if (Get-Command -Name Get-SIEntraRoleReadPartialText -ErrorAction SilentlyContinue) { $rolePartial = [string](Get-SIEntraRoleReadPartialText) }
    $spDupWatch = New-SIIdDuplicateWatch -Label 'EntraServicePrincipals /servicePrincipals'

    # transitive group -> role expansion (mostly affects User assets,
    # but SPs can also be group members so we wire the same lookup here).
    # Azure RBAC delegations (scope-aware Max). Read BEFORE the group expansion (#1192): a group that holds only Azure roles
    # is a privilege-holding group too.
    $ph = Start-SIIdentityPhase -Phase 'service principals: Azure RBAC'
    $azureLookup = Get-SIAzureDelegationsByPrincipal -ExcludeSubscriptionPatterns @($global:SI_AzureSubscriptionExcludePatterns)
    if ($null -eq $azureLookup) { $azureLookup = @{} }
    $null = Stop-SIIdentityPhase $ph -Rows ([long]$azureLookup.Count) -Detail 'principals with an Azure role'

    $ph = Start-SIIdentityPhase -Phase 'service principals: role-holding groups (members, PIM for Groups)'
    Write-SIInfo '[perms] discovering role-assigned groups...'
    $groupRoles = Get-SIRoleAssignedGroups -Token $token -PermanentRolesByPrincipal $permRolesMap -EligibleRolesByPrincipal $eligRolesMap
    $privGroups = Get-SIPrivilegeHoldingGroupMap -RoleAssignedGroupMap $groupRoles -AzureLookup $azureLookup
    Write-SIInfo ('[perms] {0} groups hold Entra roles, {1} hold Entra or Azure roles -- expanding transitive memberships...' -f $groupRoles.Count, $privGroups.Count)
    $memberToGroups = if ($privGroups.Count -gt 0) {
        Get-SIGroupTransitiveMembers -Token $token -RoleAssignedGroupMap $privGroups
    } else { @{} }
    # PIM-for-Groups (cache hit -- already fetched by EntraUsers discovery in same run).
    $pimGroupsMap = if ($privGroups.Count -gt 0) {
        Get-SIPimForGroupsByPrincipal -Token $token -RoleAssignedGroupMap $privGroups
    } else { @{} }
    $grpLookups = Get-SIRoleGroupLookups
    $pimGroupMembers = $grpLookups.PimGroupMembers
    $activatedGroupMemberships = $grpLookups.ActivatedMembers
    $groupNames = Get-SIRolePrincipalNames
    Write-SIInfo ('[perms] {0} principals inherit at least one role via group membership' -f $memberToGroups.Count)
    $null = Stop-SIIdentityPhase $ph -Rows ([long]$privGroups.Count) -Detail 'privilege-holding groups'

    # SP sign-in activity from LA. same Defender-workspace
    # split as IdentityInfo -- AAD*SignInLogs typically live in the Sentinel/
    # Defender workspace, not the SI output workspace.
    $defenderWs   = if ($global:SI_DefenderWorkspaceResourceId) { $global:SI_DefenderWorkspaceResourceId } else { $global:SI_WorkspaceResourceId }
    $defenderNote = if ($global:SI_DefenderWorkspaceResourceId) { 'separate Defender workspace' } else { 'same as output workspace' }
    Write-SIInfo ('[perms] fetching SP sign-in activity from Log Analytics ({0})...' -f $defenderNote)
    $ph = Start-SIIdentityPhase -Phase 'service principals: sign-in activity (Log Analytics)'
    $spnSignInMap = Get-SISpnSignInLastActivity -WorkspaceResourceId $defenderWs
    $null = Stop-SIIdentityPhase $ph -Rows ([long]$(if ($null -ne $spnSignInMap) { $spnSignInMap.Count } else { 0 }))
    # no source answered a sign-in for the tenant: UNKNOWN -- each service principal's sign-in days stay empty, never -1
    # ("never signed in"); the lookup said so once
    $spnSignInKnown = Test-SISpnSignInKnown

    # EG identity enrichment (cached -- already pulled by Users discovery if it ran first;
    # otherwise this fires the bulk hunting query). Indexed by AAD ObjectId.
    $ph = Start-SIIdentityPhase -Phase 'service principals: Exposure Graph identities'
    $egIdentitiesMap = Get-SIExposureGraphIdentities
    $null = Stop-SIIdentityPhase $ph -Rows ([long]$(if ($null -ne $egIdentitiesMap) { $egIdentitiesMap.Count } else { 0 }))

    $microsoftFirstPartyTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
    # Default = include 1st-party SPs (parity with EG / Defender views).
    # Customer opts out by setting $global:SI_IncludeFirstPartySpns = $false.
    $includeFirstParty = if ($null -ne $global:SI_IncludeFirstPartySpns) { [bool]$global:SI_IncludeFirstPartySpns } else { $true }

    $rows = New-Object System.Collections.ArrayList
    # include customSecurityAttributes
    # LIST KEPT: customSecurityAttributes is returned only when named, and the service principals of Microsoft carry very large role and permission lists. What Graph offers beyond the list shows as "offered, not read" in the weekly discovery.
    $url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,displayName,appId,servicePrincipalType,signInAudience,accountEnabled,publisherName,verifiedPublisher,appOwnerOrganizationId,passwordCredentials,keyCredentials,tags,homepage,customSecurityAttributes,createdDateTime&$top=999'

    # Audit #4: retry transient failures and KEEP the pages already collected.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1')

    # The record of ONE service principal -- shared by the whole-set loop below and the streaming pages (#475). Reads the
    # tenant-wide lookups built above; $now is set where each path starts.
    $buildSp = {
        param($sp)
        # Skip 1st-party Microsoft SPs unless customer opts in
        if (-not $includeFirstParty -and $sp.appOwnerOrganizationId -eq $microsoftFirstPartyTenantId) {
            return
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
        $apW = [System.Diagnostics.Stopwatch]::StartNew()
        $appPerms      = Get-SISPAppRoleAssignments -Token $token -ObjectId $sp.id -AppRoleResolver $appRoleResolver
        Add-SIIdentityPhaseTotal -Phase 'service principals: application permissions (one read per principal)' -Seconds $apW.Elapsed.TotalSeconds -Rows 1 -Calls 1
        # delegated permissions: from the ONE read of the tenant's grants; when that read did not complete, per principal
        # as before (a failed read never becomes "no delegated permission")
        $delegPerms    = if ($oauthGrants -and $oauthGrants.Complete) { @(Get-SIOauth2ClientScopes -State $oauthGrants -ClientId ([string]$sp.id)) }
                         else { Get-SISPOauth2Grants -Token $token -ObjectId $sp.id }
        # a function's ONE-item list comes back as the bare item: kept a list, so the profile publishes ["X"] like every
        # other list (an SP with exactly one permission was published as the text "X"). None stays none ($null).
        if ($appPerms -is [string])   { $appPerms   = @($appPerms) }
        if ($delegPerms -is [string]) { $delegPerms = @($delegPerms) }
        # @( ) around the WHOLE if: assigning an if-statement unrolls a one-role list to a bare string, and the string +
        # the inherited list below then concatenated into ONE text
        $permRoles     = @(if ($permRolesMap.ContainsKey([string]$sp.id))  { $permRolesMap[[string]$sp.id] })
        $eligRoles     = @(if ($eligRolesMap.ContainsKey([string]$sp.id))  { $eligRolesMap[[string]$sp.id] })
        # append roles inherited via group membership
        # #1192: the same hop rules and attach points as a user (a workload identity can be a member of, or PIM-eligible
        # for, a group that holds Entra or Azure roles)
        $reach = @(Get-SIPrivilegeGroupReach -PrincipalId ([string]$sp.id) -MemberToGroups $memberToGroups -PimGroups $pimGroupsMap -PimGroupMembers $pimGroupMembers -ActivatedGroupMemberships $activatedGroupMemberships)
        $inh = Get-SIEntraRolesFromGroupReach -Reach $reach -GroupRoles $groupRoles
        $permRoles     = @($permRoles + $inh.Permanent | Select-Object -Unique)
        $eligRoles     = @($eligRoles + $inh.Eligible  | Select-Object -Unique)
        # Azure delegations for the SP + via every group reached (eligible through a PIM hop)
        $azDelegations = New-Object System.Collections.ArrayList
        if ($azureLookup.ContainsKey([string]$sp.id)) { foreach ($e in $azureLookup[[string]$sp.id]) { [void]$azDelegations.Add($e) } }
        foreach ($e in @(Get-SIAzureDelegationsFromGroupReach -Reach $reach -AzureLookup $azureLookup -Names $groupNames)) { [void]$azDelegations.Add($e) }

        # SP sign-in + CSA tags
        $spLastSignIn = if ($spnSignInMap.ContainsKey([string]$sp.id)) { $spnSignInMap[[string]$sp.id] } else { $null }
        $spLastSignInDays = if ($spnSignInKnown) { Get-SIDaysSince $spLastSignIn } else { $null }
        $spCsa = ConvertTo-SICustomSecurityAttributes $sp.customSecurityAttributes

        $spRec = @{
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
            # owners of the principal from the run's owners read; $null = not read (the profile then leaves IsOrphanSPN unknown)
            # the principal's own owners AND the owners of its application registration, each person once
            ENTRA_OwnerCount              = (Get-SISpOwnerCount -Id ([string]$sp.id) -AppOwners (Get-SIEntraAppOwners -Apps $appRegs -AppId ([string]$sp.appId)) -AppOwnersKnown (Test-SIEntraAppOwnersKnown -Apps $appRegs -ServicePrincipal $sp -TenantId $thisTenant))
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
        # #899: the role lists above were kept from the stored record this run (only then is it said)
        if ($rolePartial) { $spRec['ENTRA_RoleReadPartial'] = $rolePartial }
        $spRec
    }

    # the owners of every service principal, read ONCE before the principals (both paths): each record carries ENTRA_OwnerCount
    # for the identity profile, and the record capture adds the 'owners' part from the same read. Never fails the run.
    if (-not (Get-Command -Name Get-SISpOwnerCounts -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }
    $ph = Start-SIIdentityPhase -Phase 'service principals: owners, application registrations, delegated grants'
    try { $null = Get-SISpOwnerCounts -Token $token -Refresh } catch { Write-Warning ('Service principal owners: ' + $_.Exception.Message) }
    # the application registrations, read ONCE before the principals: an application's owners count as the principal's.
    # Not read = $null: the principal's own owners decide, as before. Never fails the run.
    $appRegs = $null
    try { $appRegs = Get-SIEntraApplications -Token $token -Refresh } catch { Write-Warning ('Application registrations: ' + $_.Exception.Message) }
    $thisTenant = ''
    if (Get-Command -Name Get-SIRecordTenantId -ErrorAction SilentlyContinue) { try { $thisTenant = [string](Get-SIRecordTenantId) } catch { $thisTenant = '' } }
    # the delegated permission grants of the tenant in ONE read (instead of one request per service principal)
    $oauthGrants = $null
    try { $oauthGrants = Get-SIOauth2GrantsByClient -Token $token } catch { $oauthGrants = $null }
    $null = Stop-SIIdentityPhase $ph

    # #475 STREAMING (the discover phase of a run collected in parts): each page's service principals become records and go
    # straight into their parts. Invoke-SIDiscover decided the parts before this source ran.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        $now = [datetime]::UtcNow
        Reset-SIPermissionFetchFailures
        $onSps = {
            param($PageRows)
            Add-SIIdDuplicateWatch -Watch $spDupWatch -Rows @($PageRows)
            $batch = New-Object System.Collections.Generic.List[object]
            foreach ($ssp in $PageRows) {
                Add-SIFullSourceObject -SourceSystem 'entra-serviceprincipal' -Object $ssp -AnchorColumn 'EntraAccountObjectId' -AnchorValue ([string]$ssp.id)
                $rec = & $buildSp $ssp
                if ($rec) { $batch.Add($rec) }
            }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray()
        }
        $phPages = Start-SIIdentityPhase -Phase 'service principals: pages (read + permissions + records)'
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'EntraServicePrincipals /servicePrincipals' -OnPage $onSps
        $null = Stop-SIIdentityPhase $phPages -Rows ([long]$page.Count) -Detail ('{0} page(s)' -f [int]$page.Pages)
        Write-SIIdentityPhaseTotals -Prefix 'service principals:'
        $null = Write-SIGraphRetrySummary
        $null = Write-SIIdDuplicateWarning $spDupWatch
        if (-not $page.Complete) {
            Write-Warning ('EntraServicePrincipals: {0} -- continuing with {1} SP(s) from {2} page(s); the run is NOT blocked.' -f $page.Error, $page.Count, $page.Pages)
        }
        Write-SIPermissionFetchSummary -Label 'service principal'
        # the owners of every service principal -> its record's 'owners' part (derived.ownerCount -> si_is_orphan_sp); never fails the run
        if (-not (Get-Command -Name Invoke-SISpOwnerCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }
        try { $null = Invoke-SISpOwnerCapture -Token $token } catch { Write-Warning ('Service principal owners: ' + $_.Exception.Message) }
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['EntraServicePrincipals'] = [int]$page.Count }
        Write-SIInfo ('[perms] EntraServicePrincipals: {0} service principal(s) streamed into {1} part(s), page by page' -f $page.Count, $stream.Parts)
        return
    }
    if (Test-SIFullAssetPropertiesOn) {
        # #412 full asset metadata: ONE wide pull -- the $select above UNION the service principal's other properties. The
        # record below reads the same fields from it, so the security record is unchanged.
        $page = Invoke-SIFullAwareGraphPull -SourceSystem 'entra-serviceprincipal' -SecurityUrl $url -Label 'EntraServicePrincipals /servicePrincipals' -Fetch { param($u, $l) Invoke-SIPagedRest -Url $u -Token $token -SourceLabel $l }
    } else {
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'EntraServicePrincipals /servicePrincipals'
    }
    Add-SIIdDuplicateWatch -Watch $spDupWatch -Rows @($page.Rows); $null = Write-SIIdDuplicateWarning $spDupWatch
    foreach ($sp in $page.Rows) {
        Add-SIFullSourceObject -SourceSystem 'entra-serviceprincipal' -Object $sp -AnchorColumn 'EntraAccountObjectId' -AnchorValue ([string]$sp.id)
        [void]$rows.Add($sp)
    }
    if (-not $page.Complete) {
        Write-Warning ('EntraServicePrincipals: {0} -- continuing with {1} SP(s) from {2} page(s); the run is NOT blocked.' -f `
            $page.Error, $rows.Count, $page.Pages)
    }

    # the owners of every service principal -> its record's 'owners' part (derived.ownerCount -> si_is_orphan_sp); never fails the run
    if (-not (Get-Command -Name Invoke-SISpOwnerCapture -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDerivedSources.ps1') }
    try { $null = Invoke-SISpOwnerCapture -Token $token } catch { Write-Warning ('Service principal owners: ' + $_.Exception.Message) }

    $now = [datetime]::UtcNow
    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EntraSPs' -ErrorAction SilentlyContinue
    # Per-principal permission lookups that fail after every retry are counted and reported once, after
    # the loop -- a failure used to publish the SP with NO permissions and say nothing (#125).
    Reset-SIPermissionFetchFailures
    foreach ($sp in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EntraSPs' -Index $_i -Total $_total } catch { }
        & $buildSp $sp
    }
    Write-SIPermissionFetchSummary -Label 'service principal'
    Write-SIIdentityPhaseTotals -Prefix 'service principals:'
    $null = Write-SIGraphRetrySummary
}
