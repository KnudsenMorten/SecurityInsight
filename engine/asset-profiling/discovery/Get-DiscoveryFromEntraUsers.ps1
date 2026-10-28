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

# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

function Get-DiscoveryFromEntraUsers {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'Entra-users discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    . (Join-Path (Split-Path -Parent $PSScriptRoot) "shared/IdentityRoleFetcher.ps1")
    . (Join-Path (Split-Path -Parent $PSScriptRoot) "shared/SI-AuthMethodsRead.ps1")

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

    # #549 passwordless-only accounts: each kept user's authentication methods (GET /users/{id}/authentication/methods,
    # Graph $batch, UserAuthenticationMethod.Read.All), read per page of users below. A refused, throttled or partial read
    # leaves si_passwordless_only UNKNOWN for the users not read -- never false (shared\SI-AuthMethodsRead.ps1).
    Reset-SIEntraAuthMethodsState
    $authReadDisabled = $true
    if (-not (Get-Command -Name Test-SIDisabledIncluded -ErrorAction SilentlyContinue)) {
        $disFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-DisabledAssets.ps1'
        if (Test-Path -LiteralPath $disFile) { . $disFile }
    }
    if (Get-Command -Name Test-SIDisabledIncluded -ErrorAction SilentlyContinue) { try { $authReadDisabled = [bool](Test-SIDisabledIncluded -Stage Collect) } catch { } }
    $authMap = @{}
    $readAuthMethods = {
        param($PageUsers)
        $sel = @(Select-SIAuthMethodReadUsers -Users $PageUsers -IncludeDisabled $authReadDisabled)
        if ($sel.Count -eq 0) { return }
        # a read that fails part-way is NEVER complete: the users not read stay unknown, the run says so (no silent loss)
        try { $got = Get-SIEntraPasswordlessByUser -Token $token -Users $sel }
        catch {
            $st = Get-SIEntraAuthMethodsState
            if ($st) { $st.Complete = $false; $st.Error = [string]$_.Exception.Message }
            Write-SIWarn ('[perms] the sign-in-method read stopped part-way ({0}) -- the users not read are unknown this run' -f $_.Exception.Message)
            return
        }
        foreach ($k in @($got.Keys)) { $authMap[$k] = $got[$k] }
    }

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
    # shadow-admin guard: no group holds a role = nothing to expand -- the group reads are complete by definition
    if ($groupRoles.Count -eq 0 -and (Get-Command -Name Set-SIEntraRoleReadPart -ErrorAction SilentlyContinue)) {
        Set-SIEntraRoleReadPart -Part 'GroupMembers' -Complete $true
        Set-SIEntraRoleReadPart -Part 'PimForGroups' -Complete $true
    }
    # did EVERY role read complete? Stamped on each user (ENTRA_RoleReadComplete -> the profile row's
    # Properties.collect.entra.RoleReadComplete): "this user holds no Entra role" is a FACT only then -- otherwise unknown
    $roleReadComplete = $false
    if (Get-Command -Name Test-SIEntraRoleReadComplete -ErrorAction SilentlyContinue) { $roleReadComplete = [bool](Test-SIEntraRoleReadComplete) }
    if (-not $roleReadComplete) { Write-SIInfo '[perms] the Entra role read did not complete -- "no role" is unknown this run (shadow admin stays unknown)' }
    # #899: why the role facts are partial this run ('' = they are not) -- stamped on every user, so a worker of a run
    # collected in parts knows it too (Properties.collect.entra.RoleReadPartial)
    $rolePartial = ''; if (Get-Command -Name Get-SIEntraRoleReadPartialText -ErrorAction SilentlyContinue) { $rolePartial = [string](Get-SIEntraRoleReadPartialText) }
    $userDupWatch = New-SIIdDuplicateWatch -Label 'EntraUsers /users'

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
    # v3 data model: how the Defender for Identity pull went -- a failed read leaves the mdi records FROZEN (absence proves
    # nothing), never "not seen"
    if ($null -ne $global:SIRecordCaptureState -and (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue)) {
        $iiState = $null; if ($script:_SICache) { $iiState = $script:_SICache['IdentityInfoState'] }
        $iiOk = $true; $iiErr = ''; $iiCode = ''
        if ($iiState) {
            $iiOk = [bool]$iiState.Complete; $iiErr = [string]$iiState.Error
            if ($iiState.PSObject.Properties['Code']) { $iiCode = [string]$iiState.Code }
        }
        elseif ($null -eq $identityInfoMap -or $identityInfoMap.Count -eq 0) { $iiOk = $false; $iiErr = 'IdentityInfo returned no rows' }
        # source-not-present: no table, so nothing to read -- not a failed read (its records stay as they were, never "not seen")
        try { Set-SIRecordPull -Provider 'mdi' -Complete $iiOk -ErrorText $iiErr -Code $iiCode } catch { }
    }

    # Exposure Graph identity enrichment -- one bulk hunting query,
    # results indexed by AAD ObjectId. Populates the EG-sourced fields declared in
    # identity.schema.json (AdminCount, UserAccountControl, SidHistory, criticalityLevel,
    # nestedAdGroupNames, hasLeakedCredentials, etc.). Schema-driven row builder
    # walks sourcePath against the cached RawData blob -- no per-field hard-coding.
    $egIdentitiesMap = Get-SIExposureGraphIdentities

    $rows = New-Object System.Collections.ArrayList
    # include signInActivity + customSecurityAttributes
    # #497 the on-premises AD ids (SID, immutable id = the AD objectGUID, sAMAccountName, distinguished name, domain) at EVERY level:
    # they join the Entra user to its AD account in the model (ad_sid / ad_object_guid) -- same read, same permission (User.Read.All).
    # LIST KEPT: Microsoft Graph returns only a default set of a user without a property list (there is no "everything"), and signInActivity / customSecurityAttributes only when named. What Graph offers beyond the list shows as "offered, not read" in the weekly discovery.
    $url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,jobTitle,department,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesImmutableId,onPremisesSamAccountName,onPremisesDistinguishedName,onPremisesDomainName,mail,userType,assignedLicenses,signInActivity,customSecurityAttributes&$top=999'
    # BREAK-GLASS BY THE EXTENSION ATTRIBUTE THE CUSTOMER DEFINES (the data-model list break_glass_attribute, entries
    # "attribute=value"; nothing shipped). Only while the list names an attribute is it added to the property list above --
    # with no entry the read is exactly as before. The match is decided here, on the user as Graph returned it, and kept as
    # the 'breakGlass' part of the user's record (-> si_break_glass_attribute); the CI build classifies from it.
    $bgRules = @()
    try {
        $dmDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $dmDir 'SI-DataModelTemplates.ps1') }
        if (-not (Get-Command -Name Get-SIBreakGlassAttributeRules -ErrorAction SilentlyContinue)) { . (Join-Path $dmDir 'SI-BreakGlass.ps1') }
        $bgLists = @{}
        foreach ($bgL in @((Get-SIDataModelTemplate -Name 'lists' -OverlayRoot $global:SI_DataModelOverlayRoot).Document.lists)) { if ($bgL -and $bgL.id) { $bgLists[[string]$bgL.id] = $bgL } }
        $bgRules = @(Get-SIBreakGlassAttributeRules -Lists $bgLists)
        $bgSelect = @(Get-SIBreakGlassAttributeSelect -Rules $bgRules)
        # a directory extension the directory does not know would make Microsoft Graph refuse the WHOLE user read: each
        # such name is asked for once on a single user first (one request per name, never per identity); a name Graph
        # refuses is left out, said in plain words, and its rule classifies nobody this run
        $bgKeep = New-Object System.Collections.Generic.List[string]
        foreach ($bgName in $bgSelect) {
            if ($bgName -eq 'onPremisesExtensionAttributes') { $bgKeep.Add($bgName); continue }
            try {
                # LIST KEPT: a probe -- one user, its id and the one property, only to learn whether Graph knows the name; nothing is kept
                $null = Invoke-RestMethod -Method Get -Uri ('https://graph.microsoft.com/v1.0/users?$select=id,{0}&$top=1' -f $bgName) -Headers @{ Authorization = ('Bearer ' + $token) } -ErrorAction Stop
                $bgKeep.Add($bgName)
            } catch {
                Write-Warning ('EntraUsers: the break-glass attribute {0} is not a property Microsoft Graph returns for users ({1}) -- no account is classified by it this run. Check the name in the break-glass attribute setting.' -f $bgName, $_.Exception.Message)
                $bgRules = @($bgRules | Where-Object { [string]$_.Attribute -ne $bgName })
            }
        }
        $bgSelect = $bgKeep.ToArray()
        if ($bgSelect.Count -gt 0) {
            $url = $url.Replace('customSecurityAttributes&$top=999', ('customSecurityAttributes,' + ($bgSelect -join ',') + '&$top=999'))
            Write-SIInfo ('[perms] break-glass attribute: {0} rule(s) defined -- reading {1} with each user' -f $bgRules.Count, ($bgSelect -join ', '))
        }
    } catch {
        $bgRules = @()
        Write-Warning ('EntraUsers: the break-glass extension attribute setting could not be read ({0}) -- no account is classified by it this run; the other break-glass rules are unaffected.' -f $_.Exception.Message)
    }

    # Audit #4: retry transient failures and KEEP the pages already collected.
    # Identity has only TWO sources, so discarding a throttled page-40-of-50 cost
    # far more here than on the five-source endpoint engine.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1')

    # The record of ONE user -- shared by the whole-set loop below and the streaming pages (#475). Reads the tenant-wide
    # lookups built above (roles, PIM, MFA, Azure, IdentityInfo, Exposure Graph).
    $buildUser = {
        param($u)
        $name = $u.userPrincipalName
        if (-not $name) { $name = $u.displayName }
        if (-not $name) { $name = $u.id }

        $hint = if (-not $u.accountEnabled) { 'disabled' }
                elseif ($u.userType -eq 'Guest') { 'guest' }
                elseif ($u.onPremisesSyncEnabled) { 'on-prem-synced' }
                else { 'cloud-only' }

        # @( ) around the WHOLE if: assigning an if-statement unrolls a one-role list to a bare string, and the string +
        # the inherited list below then concatenated into ONE text ("Attribute Definition AdministratorGroups Administrator ...")
        $permRoles = @(if ($permRolesMap.ContainsKey([string]$u.id)) { $permRolesMap[[string]$u.id] })
        $eligRoles = @(if ($eligRolesMap.ContainsKey([string]$u.id)) { $eligRolesMap[[string]$u.id] })
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
        # v3 data model (unwritten-fields): the IdentityInfo row this read already holds IS the user's Defender for Identity
        # record (data-model/mappings/mdi.locked.json, part 'identity') -- service account, investigation priority
        # percentile, blast radius, risk, the on-premises object id. Captured only for a user the Entra collection holds,
        # so no CI is minted for an IdentityInfo row alone. No new read, no new permission.
        if ($ii -and (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) {
            try { Add-SIRecordPart -Provider 'mdi' -RecordType 'user' -Key ([string]$u.id) -Part 'identity' -Object $ii } catch { }
        }

        # break-glass by the customer's extension attribute: which entry this user carries, if any (part 'breakGlass')
        if ($bgRules.Count -gt 0 -and (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) {
            try {
                $bgHit = Get-SIBreakGlassAttributeMatch -User $u -Rules $bgRules
                if ($bgHit) { Add-SIRecordPart -Provider 'entra' -RecordType 'user' -Key ([string]$u.id) -Part 'breakGlass' -Object ([pscustomobject]$bgHit) }
            } catch { }
        }

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
        # #522 no registration row (the read failed, stopped part-way, or the user is not listed) = MFA UNKNOWN ($null),
        # never "no MFA"
        $mf = ConvertTo-SIUserMfaFields -Entry $mfaRegMap[[string]$u.id]
        # #549 no complete read of this user's sign-in methods = passwordless-only UNKNOWN ($null), never false
        $pw = $authMap[[string]$u.id]

        $userRec = @{
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
            # shadow-admin guard: the two lists above are COMPLETE only when every role read completed this run
            ENTRA_RoleReadComplete       = [bool]$roleReadComplete
            # Azure RBAC delegations (scope-aware tier precomputed).
            ENTRA_AzureDelegations       = $azDelegations.ToArray()
            # MFA registration from Graph /reports/authenticationMethods/userRegistrationDetails
            # (bulk fetched in $mfaRegMap above). Authoritative for current MFA state;
            # IdentityInfo's IsMFARegistered below is stale by hours-to-days.
            ENTRA_MfaIsRegistered          = $mf.ENTRA_MfaIsRegistered
            ENTRA_MfaIsCapable             = $mf.ENTRA_MfaIsCapable
            ENTRA_IsPasswordlessCapable    = $mf.ENTRA_IsPasswordlessCapable
            ENTRA_IsSsprRegistered         = $mf.ENTRA_IsSsprRegistered
            ENTRA_IsSsprCapable            = $mf.ENTRA_IsSsprCapable
            ENTRA_IsSsprEnabled            = $mf.ENTRA_IsSsprEnabled
            ENTRA_MfaMethods               = $mf.ENTRA_MfaMethods
            ENTRA_MfaMethodCount           = $mf.ENTRA_MfaMethodCount
            ENTRA_MfaDefaultMethod         = $mf.ENTRA_MfaDefaultMethod
            ENTRA_MfaSystemPreferredMethods= $mf.ENTRA_MfaSystemPreferredMethods
            ENTRA_MfaPreferredSecondary    = $mf.ENTRA_MfaPreferredSecondary
            ENTRA_MfaLastUpdatedDateTime   = $mf.ENTRA_MfaLastUpdatedDateTime
            # #549 the user's authentication methods (GET /users/{id}/authentication/methods): was THIS user's list read
            # whole, and the verdict -- $null (unknown) unless it was
            ENTRA_AuthMethodsReadComplete  = if ($pw) { [bool]$pw.ReadComplete } else { $false }
            ENTRA_PasswordlessOnly         = if ($pw -and [bool]$pw.ReadComplete) { $pw.PasswordlessOnly } else { $null }
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
        # #899: the role lists above were kept from the stored record this run (only then is it said)
        if ($rolePartial) { $userRec['ENTRA_RoleReadPartial'] = $rolePartial }
        $userRec
    }

    # #475 STREAMING (the discover phase of a run collected in parts): each page's users become records and go straight into
    # their parts -- the tenant's users are never all held. Invoke-SIDiscover decided the parts before this source ran.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        $onUsers = {
            param($PageRows)
            if (-not $streamState.Deleted) { Add-SIIdDuplicateWatch -Watch $userDupWatch -Rows @($PageRows) }
            $batch = New-Object System.Collections.Generic.List[object]
            foreach ($su in $PageRows) {
                Add-SIFullSourceObject -SourceSystem 'entra-user' -Object $su -AnchorColumn 'EntraAccountObjectId' -AnchorValue ([string]$su.id)
                $su | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue ([bool]$streamState.Deleted) -Force
            }
            # #549 this page's kept users' sign-in methods, before their records are built
            try { & $readAuthMethods @($PageRows) } catch { }
            foreach ($su in $PageRows) { $batch.Add((& $buildUser $su)) }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray()
        }
        $streamState = @{ Deleted = $false }
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'EntraUsers /users' -OnPage $onUsers
        $null = Write-SIIdDuplicateWarning $userDupWatch
        if (-not $page.Complete) {
            Write-Warning ('EntraUsers: {0} -- continuing with {1} user(s) from {2} page(s); the run is NOT blocked.' -f $page.Error, $page.Count, $page.Pages)
        }
        $streamState.Deleted = $true
        # LIST KEPT: the same properties as the active users (above), plus when the user was deleted
        $streamDeletedUrl = 'https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,deletedDateTime,jobTitle,department,onPremisesSyncEnabled,mail,userType&$top=999'
        $delPage = Invoke-SIPagedRest -Url $streamDeletedUrl -Token $token -SourceLabel 'EntraUsers /directory/deletedItems' -OnPage $onUsers
        if (-not $delPage.Complete) {
            Write-Warning ('EntraUsers: deletedItems incomplete -- {0} (likely permission gap; {1} soft-deleted user(s) loaded, active users unaffected).' -f $delPage.Error, $delPage.Count)
        }
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['EntraUsers'] = [int]$page.Count + [int]$delPage.Count }
        Write-SIEntraAuthMethodsOutcome
        Write-SIInfo ('[perms] EntraUsers: {0} user(s) + {1} soft-deleted streamed into {2} part(s), page by page' -f $page.Count, $delPage.Count, $stream.Parts)
        return
    }
    if (Test-SIFullAssetPropertiesOn) {
        # #412 full asset metadata: ONE wide pull -- the $select above UNION the user's other properties. The record below
        # reads the same fields from it, so the security record is unchanged.
        $page = Invoke-SIFullAwareGraphPull -SourceSystem 'entra-user' -SecurityUrl $url -Label 'EntraUsers /users' -Fetch { param($u, $l) Invoke-SIPagedRest -Url $u -Token $token -SourceLabel $l }
    } else {
        $page = Invoke-SIPagedRest -Url $url -Token $token -SourceLabel 'EntraUsers /users'
    }
    Add-SIIdDuplicateWatch -Watch $userDupWatch -Rows @($page.Rows); $null = Write-SIIdDuplicateWarning $userDupWatch
    foreach ($u in $page.Rows) {
        # the source's object, BEFORE SecurityInsight stamps its own ENTRA_IsDeleted on it (a no-op at the security level)
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object $u -AnchorColumn 'EntraAccountObjectId' -AnchorValue ([string]$u.id)
        # Stamp IsDeleted=$false on every active-user row so the column exists for
        # the deleted-user merge below (avoids null-vs-missing ambiguity downstream).
        $u | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $false -Force
        [void]$rows.Add($u)
    }
    if (-not $page.Complete) {
        Write-Warning ('EntraUsers: {0} -- continuing with {1} user(s) from {2} page(s); the run is NOT blocked.' -f `
            $page.Error, $rows.Count, $page.Pages)
    }

    # Deleted users -- /directory/deletedItems/microsoft.graph.user lists users
    # that have been soft-deleted in the last 30 days (Entra retention window).
    # EG retains identity nodes longer than Entra's active list, so without this
    # query we silently miss recently-deleted accounts that EG still tracks.
    # Permission required: User.Read.All AND Directory.AccessAsUser.All (or
    # Directory.ReadWrite.All for the tenant). Failure here is non-fatal --
    # active-user discovery already succeeded.
    # LIST KEPT: the same properties as the active users (above), plus when the user was deleted
    $deletedUrl = 'https://graph.microsoft.com/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,deletedDateTime,jobTitle,department,onPremisesSyncEnabled,mail,userType&$top=999'
    $deletedCount = 0
    # Audit #4: same retry treatment. This block was already non-blocking (it warns
    # and keeps the active users), but a transient 429 still lost every soft-deleted
    # user; now it retries first and keeps whatever pages it did get.
    $delPage = Invoke-SIPagedRest -Url $deletedUrl -Token $token -SourceLabel 'EntraUsers /directory/deletedItems'
    foreach ($u in $delPage.Rows) {
        # a soft-deleted user is kept as the deletedItems call returned it (that call is unchanged at both levels)
        Add-SIFullSourceObject -SourceSystem 'entra-user' -Object $u -AnchorColumn 'EntraAccountObjectId' -AnchorValue ([string]$u.id)
        $u | Add-Member -NotePropertyName ENTRA_IsDeleted -NotePropertyValue $true -Force
        [void]$rows.Add($u)
        $deletedCount++
    }
    if (-not $delPage.Complete) {
        Write-Warning ('EntraUsers: deletedItems incomplete -- {0} (likely permission gap; {1} soft-deleted user(s) loaded, active users unaffected).' -f `
            $delPage.Error, $deletedCount)
    }
    if ($deletedCount -gt 0) {
        Write-SIInfo ('[perms] EntraUsers: included {0} soft-deleted user(s) from /directory/deletedItems' -f $deletedCount)
    }

    # #549 the kept users' sign-in methods, before their records are built (soft-deleted users are left out by the selection)
    try { & $readAuthMethods $rows.ToArray() } catch { }
    Write-SIEntraAuthMethodsOutcome

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EntraUsers' -ErrorAction SilentlyContinue
    foreach ($u in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EntraUsers' -Index $_i -Total $_total } catch { }
        & $buildUser $u
    }
}
