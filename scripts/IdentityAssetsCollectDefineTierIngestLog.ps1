<#
.SYNOPSIS
    SecurityInsight - Identity Assets: Collect, Define Tier, Ingest, Log

    Collects all identity metadata from Entra ID (Users, Service Principals, Managed Identities),
    classifies each identity across four risk dimensions, and ingests into SI_IdentityAssets_CL
    via DCR / Log Ingestion API using the AzLogDcrIngestPS module.

.DESCRIPTION
    -----------------------------------------------------------------------
    ARCHITECTURE
    -----------------------------------------------------------------------
    Dot-sourced by a launcher script. All configuration via launcher globals.
    No parameters except TierDefinitionsPath (optional path override).

    Launcher modes:
      Automation_Framework    - cert-based auth via Automation-DefaultVariables / Connect_Azure
      Community / Test        - SPN + secret, TroubleshootingMode limits to 10 records

    Workspace layout:
      WorkspaceResourceId               - target LA workspace for SI_IdentityAssets_CL ingestion
      DefenderWorkspaceResourceId       - (optional) separate LA workspace where IdentityInfo
                                          and AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs
                                          reside (Defender / Sentinel workspace).
                                          If not set, both tables are read from WorkspaceResourceId.

    -----------------------------------------------------------------------
    TIERING MODEL
    -----------------------------------------------------------------------
    Every identity receives an EffectiveTier (0=critical, 1=privileged, 2=standard, 3=low).
    The tier is computed across four independent providers. Each provider calculates its own
    tier from the SecurityInsight_IdentityTiering.json catalog. EffectiveTier = Min across providers.

    TierSources column (JSON) stores per-provider tier + CatalogMatches (proof):

    1. ENTRA ID ROLES  (EntraID_Roles provider)
       Source  : Graph roleManagement/directory/roleAssignmentSchedules +
                 roleEligibilitySchedules + PIM for Groups
       Catalog : EntraID_BuiltInRoles_Tier0-3 + EntraID_CustomRoles_Tier0-3 (DisplayName exact match)
       Covers  : Users, SPNs, MIs

    2. ENTRA ID API PERMISSIONS  (EntraID_APIPermissions provider)
       Source  : servicePrincipals appRoleAssignedTo (bulk, per resource SP) +
                 oauth2PermissionGrants (tenant-wide AllPrincipals consent)
       Catalog : EntraID_APIPermissions_Tier0-3 (Value field exact match, case-insensitive)
       Covers  : SPNs, MIs (not applicable for users)

    3. LEGACY AD  (AD provider)
       Source  : IdentityInfo GroupMembership column from Log Analytics (contains synced AD groups)
       Catalog : AD_BuiltInPermissionGroups_Tier0-3 (Name field, exact case-insensitive match)
       Covers  : AD-synced users only (AccountDomain + AccountSID present in IdentityInfo)
       Note    : Cloud-only users get AD Tier = null (no signal)

    4. AZURE RBAC  (Azure provider)
       Source  : Get-AzRoleAssignment per subscription
       Catalog : Azure_BuiltInRoles_Tier0-3 + Azure_CustomRoles_Tier0-3 (Name field exact match)
       Covers  : Users, SPNs, MIs (direct + inherited via group membership / PIM for Groups)

       AZURE SCOPE MODULATION:
       Role tier from catalog defines ceiling risk. Scope narrows the effective impact:

         EffectiveTier per assignment = Max(RoleTier, ScopeLevel)

         ScopeLevel:
           0 - Tenant root (/) or root Management Group
           1 - Management Group (non-root) or Subscription
           2 - Resource Group
           3 - Individual resource

         Examples:
           Owner (T0) at tenant root    -> Max(0, 0) = Tier 0
           Owner (T0) at subscription   -> Max(0, 1) = Tier 1
           Owner (T0) at resource group -> Max(0, 2) = Tier 2
           Contributor (T1) at sub      -> Max(1, 1) = Tier 1
           Reader (T3) at tenant root   -> Max(3, 0) = Tier 3

         Azure_Delegations column stores RoleTier, ScopeLevel, and Tier (effective) per assignment.

    -----------------------------------------------------------------------
    OUTPUT COLUMNS
    -----------------------------------------------------------------------
    SI_IdentityAssets_CL (all fields stored as typed int/bool/string):

      Core identity
        ObjectId, ObjectType, DisplayName, UPN, AppId, SPType, AccountEnabled

      Classification
        EffectiveTier          int    Min across all providers (0=critical, 3=low)
        TierSources            string JSON: {EntraID_Roles, EntraID_APIPermissions, AD, Azure}
                                            each with {Tier, CatalogMatches[]}

      Entra ID roles + perms
        EntraID_Roles          string JSON: {Permanent[], Eligible[], Tier}
        EntraID_AppPermissions string JSON: {AppRoles[], Delegated[], HighestRisk, Tier, ...}
        EntraID_Groups         string JSON array of all group memberships from IdentityInfo

      AD (synced users only)
        AD_Roles               string JSON: {Tier, TierSourceGroup, MatchedGroups[]}
        AD_Info                string JSON: {Domain, SAMAccountName, DistinguishedName, ...}

      Azure RBAC
        Azure_Delegations      string JSON array: [{RoleName, Scope, SubscriptionId,
                                                    SubscriptionName, PrincipalType,
                                                    RoleTier, ScopeLevel, Tier,
                                                    InheritedFromGroup, InheritedGroupId}]

      Workload identity
        Workload_Credentials   string JSON: {HasSecret, HasCert, ExpiryDays, HasExpired,
                                             HasNoOwner, OwnersCount, Owners[]}

      MDI enrichment (users only)
        MDI_BlastRadius, MDI_Tags, MDI_InvestigationPriority, MDI_RiskLevel,
        MDI_RiskState, MDI_EntityRiskScore, MDI_AssignedRoles, MDI_IsMFARegistered

      Risk flags (bool)
        IsPrivileged, IsPrivilegedEligible, HasPermanentPrivilegedRole,
        IsSensitive (Tier 0), IsHighValueTarget (Tier 0-1), IsBreakGlass,
        IsShadowAdmin, IsOrphan, IsExternal, IsB2BCollaborator,
        IsManagedIdentity, IsManagedIdentityUserAssigned, IsMultiTenant,
        IsExternal_SPN, IsStale, IsPasswordNeverExpires, IsPasswordlessOnly

      Sign-in lifecycle (int days, string datetime)
        CreatedDays, LastSignInDays, LastInteractiveSignInDays,
        LastNonInteractiveSignInDays, PasswordLastChangedDays

      MFA
        MFARegistered (bool), MFAMethodCount (int), MFAMethods (semicolon-separated)

      Infrastructure
        CSA, ExtensionAttributes (JSON)
        CollectionTime, Computer, ComputerFqdn, UserLoggedOn

    -----------------------------------------------------------------------
    PERFORMANCE NOTES
    -----------------------------------------------------------------------
    - SPN app permissions: pre-loaded in bulk (O(resource SPs) calls, not O(client SPs))
    - User group memberships: inverted transitiveMemberOf (O(role-bearing groups) not O(users))
    - Azure RBAC: per-subscription Get-AzRoleAssignment (reliable, no ARG dependency)
    - Streaming: records written to OUTPUT\IdentityAssets_Collection.jsonl during collection
      (not buffered in RAM). Schema sample (100 of each type) passed to CheckCreateUpdate.
    - Ingest: read from file in chunks of 10,000, native AzLogDcrIngestPS pipeline per chunk.

    -----------------------------------------------------------------------
    REQUIRED PERMISSIONS
    -----------------------------------------------------------------------
    Microsoft Graph (Application):
      User.Read.All                         - enumerate users
      AuditLog.Read.All                     - sign-in timestamps
      Directory.Read.All                    - groups, roles, organization
      Application.Read.All                  - service principals
      RoleManagement.Read.Directory         - role assignments + schedules
      CustomSecAttributeAssignment.Read.All - CSA attributes
      UserAuthenticationMethod.Read.All     - MFA methods
      PrivilegedAccess.Read.AzureAD         - PIM eligible role schedules
      PrivilegedAccess.Read.AzureADGroup    - PIM for Groups eligibility
      ThreatHunting.Read.All                - Exposure Graph (AD group memberships via Advanced Hunting)

    Azure RBAC (on SecurityInsight SPN):
      Reader on all subscriptions           - Get-AzRoleAssignment
      Log Analytics Reader on WorkspaceResourceId
      Log Analytics Reader on DefenderWorkspaceResourceId (if set, for IdentityInfo + sign-in logs)

    -----------------------------------------------------------------------
    TROUBLESHOOTING
    -----------------------------------------------------------------------
    TroubleshootingMode=true limits collection to 10 users / 10 SPNs / 10 subscriptions.
    Temp file survives the run at: OUTPUT\IdentityAssets_Collection.jsonl
    All Clear()/GC() calls tagged [TROUBLESHOOTING] and commented out.
    $ingestChunk kept in memory for post-run inspection.

    Manual replay (re-ingest without re-collecting):
      $tempFile = Join-Path $PSScriptRoot "OUTPUT\IdentityAssets_Collection.jsonl"
      # Then run the ingest loop manually - see end of script for quick one-liners.

    Check field types after collection:
      $ingestChunk[0].PSObject.Properties | Select-Object Name,
        @{N='Type';E={<#
.SYNOPSIS
    SecurityInsight - Identity Assets: Collect, Define Tier, Ingest, Log

    Collects all identity metadata from Entra ID (Users, Service Principals, Managed Identities),
    classifies each identity across four risk dimensions, and ingests into SI_IdentityAssets_CL
    via DCR / Log Ingestion API using the AzLogDcrIngestPS module.

.DESCRIPTION
    -----------------------------------------------------------------------
    ARCHITECTURE
    -----------------------------------------------------------------------
    Dot-sourced by a launcher script. All configuration via launcher globals.
    No parameters except TierDefinitionsPath (optional path override).

    Launcher modes:
      Automation_Framework    - cert-based auth via Automation-DefaultVariables / Connect_Azure
      Community / Test        - SPN + secret, TroubleshootingMode limits to 10 records

    Workspace layout:
      WorkspaceResourceId               - target LA workspace for SI_IdentityAssets_CL ingestion
      DefenderWorkspaceResourceId       - (optional) separate LA workspace where IdentityInfo
                                          and AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs
                                          reside (Defender / Sentinel workspace).
                                          If not set, both tables are read from WorkspaceResourceId.

    -----------------------------------------------------------------------
    TIERING MODEL
    -----------------------------------------------------------------------
    Every identity receives an EffectiveTier (0=critical, 1=privileged, 2=standard, 3=low).
    The tier is computed across four independent providers. Each provider calculates its own
    tier from the SecurityInsight_IdentityTiering.json catalog. EffectiveTier = Min across providers.

    TierSources column (JSON) stores per-provider tier + CatalogMatches (proof):

    1. ENTRA ID ROLES  (EntraID_Roles provider)
       Source  : Graph roleManagement/directory/roleAssignmentSchedules +
                 roleEligibilitySchedules + PIM for Groups
       Catalog : EntraID_BuiltInRoles_Tier0-3 + EntraID_CustomRoles_Tier0-3 (DisplayName exact match)
       Covers  : Users, SPNs, MIs

    2. ENTRA ID API PERMISSIONS  (EntraID_APIPermissions provider)
       Source  : servicePrincipals appRoleAssignedTo (bulk, per resource SP) +
                 oauth2PermissionGrants (tenant-wide AllPrincipals consent)
       Catalog : EntraID_APIPermissions_Tier0-3 (Value field exact match, case-insensitive)
       Covers  : SPNs, MIs (not applicable for users)

    3. LEGACY AD  (AD provider)
       Source  : IdentityInfo GroupMembership column from Log Analytics (contains synced AD groups)
       Catalog : AD_BuiltInPermissionGroups_Tier0-3 (Name field, exact case-insensitive match)
       Covers  : AD-synced users only (AccountDomain + AccountSID present in IdentityInfo)
       Note    : Cloud-only users get AD Tier = null (no signal)

    4. AZURE RBAC  (Azure provider)
       Source  : Get-AzRoleAssignment per subscription
       Catalog : Azure_BuiltInRoles_Tier0-3 + Azure_CustomRoles_Tier0-3 (Name field exact match)
       Covers  : Users, SPNs, MIs (direct + inherited via group membership / PIM for Groups)

       AZURE SCOPE MODULATION:
       Role tier from catalog defines ceiling risk. Scope narrows the effective impact:

         EffectiveTier per assignment = Max(RoleTier, ScopeLevel)

         ScopeLevel:
           0 - Tenant root (/) or root Management Group
           1 - Management Group (non-root) or Subscription
           2 - Resource Group
           3 - Individual resource

         Examples:
           Owner (T0) at tenant root    -> Max(0, 0) = Tier 0
           Owner (T0) at subscription   -> Max(0, 1) = Tier 1
           Owner (T0) at resource group -> Max(0, 2) = Tier 2
           Contributor (T1) at sub      -> Max(1, 1) = Tier 1
           Reader (T3) at tenant root   -> Max(3, 0) = Tier 3

         Azure_Delegations column stores RoleTier, ScopeLevel, and Tier (effective) per assignment.

    -----------------------------------------------------------------------
    OUTPUT COLUMNS
    -----------------------------------------------------------------------
    SI_IdentityAssets_CL (all fields stored as typed int/bool/string):

      Core identity
        ObjectId, ObjectType, DisplayName, UPN, AppId, SPType, AccountEnabled

      Classification
        EffectiveTier          int    Min across all providers (0=critical, 3=low)
        TierSources            string JSON: {EntraID_Roles, EntraID_APIPermissions, AD, Azure}
                                            each with {Tier, CatalogMatches[]}

      Entra ID roles + perms
        EntraID_Roles          string JSON: {Permanent[], Eligible[], Tier}
        EntraID_AppPermissions string JSON: {AppRoles[], Delegated[], HighestRisk, Tier, ...}
        EntraID_Groups         string JSON array of all group memberships from IdentityInfo

      AD (synced users only)
        AD_Roles               string JSON: {Tier, TierSourceGroup, MatchedGroups[]}
        AD_Info                string JSON: {Domain, SAMAccountName, DistinguishedName, ...}

      Azure RBAC
        Azure_Delegations      string JSON array: [{RoleName, Scope, SubscriptionId,
                                                    SubscriptionName, PrincipalType,
                                                    RoleTier, ScopeLevel, Tier,
                                                    InheritedFromGroup, InheritedGroupId}]

      Workload identity
        Workload_Credentials   string JSON: {HasSecret, HasCert, ExpiryDays, HasExpired,
                                             HasNoOwner, OwnersCount, Owners[]}

      MDI enrichment (users only)
        MDI_BlastRadius, MDI_Tags, MDI_InvestigationPriority, MDI_RiskLevel,
        MDI_RiskState, MDI_EntityRiskScore, MDI_AssignedRoles, MDI_IsMFARegistered

      Risk flags (bool)
        IsPrivileged, IsPrivilegedEligible, HasPermanentPrivilegedRole,
        IsSensitive (Tier 0), IsHighValueTarget (Tier 0-1), IsBreakGlass,
        IsShadowAdmin, IsOrphan, IsExternal, IsB2BCollaborator,
        IsManagedIdentity, IsManagedIdentityUserAssigned, IsMultiTenant,
        IsExternal_SPN, IsStale, IsPasswordNeverExpires, IsPasswordlessOnly

      Sign-in lifecycle (int days, string datetime)
        CreatedDays, LastSignInDays, LastInteractiveSignInDays,
        LastNonInteractiveSignInDays, PasswordLastChangedDays

      MFA
        MFARegistered (bool), MFAMethodCount (int), MFAMethods (semicolon-separated)

      Infrastructure
        CSA, ExtensionAttributes (JSON)
        CollectionTime, Computer, ComputerFqdn, UserLoggedOn

    -----------------------------------------------------------------------
    PERFORMANCE NOTES
    -----------------------------------------------------------------------
    - SPN app permissions: pre-loaded in bulk (O(resource SPs) calls, not O(client SPs))
    - User group memberships: inverted transitiveMemberOf (O(role-bearing groups) not O(users))
    - Azure RBAC: per-subscription Get-AzRoleAssignment (reliable, no ARG dependency)
    - Streaming: records written to OUTPUT\IdentityAssets_Collection.jsonl during collection
      (not buffered in RAM). Schema sample (100 of each type) passed to CheckCreateUpdate.
    - Ingest: read from file in chunks of 10,000, native AzLogDcrIngestPS pipeline per chunk.

    -----------------------------------------------------------------------
    REQUIRED PERMISSIONS
    -----------------------------------------------------------------------
    Microsoft Graph (Application):
      User.Read.All                         - enumerate users
      AuditLog.Read.All                     - sign-in timestamps
      Directory.Read.All                    - groups, roles, organization
      Application.Read.All                  - service principals
      RoleManagement.Read.Directory         - role assignments + schedules
      CustomSecAttributeAssignment.Read.All - CSA attributes
      UserAuthenticationMethod.Read.All     - MFA methods
      PrivilegedAccess.Read.AzureAD         - PIM eligible role schedules
      PrivilegedAccess.Read.AzureADGroup    - PIM for Groups eligibility
      ThreatHunting.Read.All                - Exposure Graph (AD group memberships via Advanced Hunting)

    Azure RBAC (on SecurityInsight SPN):
      Reader on all subscriptions           - Get-AzRoleAssignment
      Log Analytics Reader on WorkspaceResourceId
      Log Analytics Reader on DefenderWorkspaceResourceId (if set, for IdentityInfo + sign-in logs)

    -----------------------------------------------------------------------
    TROUBLESHOOTING
    -----------------------------------------------------------------------
    TroubleshootingMode=true limits collection to 10 users / 10 SPNs / 10 subscriptions.
    Temp file survives the run at: OUTPUT\IdentityAssets_Collection.jsonl
    All Clear()/GC() calls tagged [TROUBLESHOOTING] and commented out.
    $ingestChunk kept in memory for post-run inspection.

    Manual replay (re-ingest without re-collecting):
      $tempFile = Join-Path $PSScriptRoot "OUTPUT\IdentityAssets_Collection.jsonl"
      # Then run the ingest loop manually - see end of script for quick one-liners.

    Check field types after collection:
      $ingestChunk[0].PSObject.Properties | Select-Object Name,
        @{N='Type';E={<#
.SYNOPSIS
    SecurityInsight - Identity Assets: Collect, Define Tier, Ingest, Log

    Collects all identity metadata from Entra ID (Users, Service Principals, Managed Identities),
    classifies each identity across four risk dimensions, and ingests into SI_IdentityAssets_CL
    via DCR / Log Ingestion API using the AzLogDcrIngestPS module.

.DESCRIPTION
    -----------------------------------------------------------------------
    ARCHITECTURE
    -----------------------------------------------------------------------
    Dot-sourced by a launcher script. All configuration via launcher globals.
    No parameters except TierDefinitionsPath (optional path override).

    Launcher modes:
      Automation_Framework    - cert-based auth via Automation-DefaultVariables / Connect_Azure
      Community / Test        - SPN + secret, TroubleshootingMode limits to 10 records

    Workspace layout:
      WorkspaceResourceId               - target LA workspace for SI_IdentityAssets_CL ingestion
      DefenderWorkspaceResourceId       - (optional) separate LA workspace where IdentityInfo
                                          and AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs
                                          reside (Defender / Sentinel workspace).
                                          If not set, both tables are read from WorkspaceResourceId.

    -----------------------------------------------------------------------
    TIERING MODEL
    -----------------------------------------------------------------------
    Every identity receives an EffectiveTier (0=critical, 1=privileged, 2=standard, 3=low).
    The tier is computed across four independent providers. Each provider calculates its own
    tier from the SecurityInsight_IdentityTiering.json catalog. EffectiveTier = Min across providers.

    TierSources column (JSON) stores per-provider tier + CatalogMatches (proof):

    1. ENTRA ID ROLES  (EntraID_Roles provider)
       Source  : Graph roleManagement/directory/roleAssignmentSchedules +
                 roleEligibilitySchedules + PIM for Groups
       Catalog : EntraID_BuiltInRoles_Tier0-3 + EntraID_CustomRoles_Tier0-3 (DisplayName exact match)
       Covers  : Users, SPNs, MIs

    2. ENTRA ID API PERMISSIONS  (EntraID_APIPermissions provider)
       Source  : servicePrincipals appRoleAssignedTo (bulk, per resource SP) +
                 oauth2PermissionGrants (tenant-wide AllPrincipals consent)
       Catalog : EntraID_APIPermissions_Tier0-3 (Value field exact match, case-insensitive)
       Covers  : SPNs, MIs (not applicable for users)

    3. LEGACY AD  (AD provider)
       Source  : IdentityInfo GroupMembership column from Log Analytics (contains synced AD groups)
       Catalog : AD_BuiltInPermissionGroups_Tier0-3 (Name field, exact case-insensitive match)
       Covers  : AD-synced users only (AccountDomain + AccountSID present in IdentityInfo)
       Note    : Cloud-only users get AD Tier = null (no signal)

    4. AZURE RBAC  (Azure provider)
       Source  : Get-AzRoleAssignment per subscription
       Catalog : Azure_BuiltInRoles_Tier0-3 + Azure_CustomRoles_Tier0-3 (Name field exact match)
       Covers  : Users, SPNs, MIs (direct + inherited via group membership / PIM for Groups)

       AZURE SCOPE MODULATION:
       Role tier from catalog defines ceiling risk. Scope narrows the effective impact:

         EffectiveTier per assignment = Max(RoleTier, ScopeLevel)

         ScopeLevel:
           0 - Tenant root (/) or root Management Group
           1 - Management Group (non-root) or Subscription
           2 - Resource Group
           3 - Individual resource

         Examples:
           Owner (T0) at tenant root    -> Max(0, 0) = Tier 0
           Owner (T0) at subscription   -> Max(0, 1) = Tier 1
           Owner (T0) at resource group -> Max(0, 2) = Tier 2
           Contributor (T1) at sub      -> Max(1, 1) = Tier 1
           Reader (T3) at tenant root   -> Max(3, 0) = Tier 3

         Azure_Delegations column stores RoleTier, ScopeLevel, and Tier (effective) per assignment.

    -----------------------------------------------------------------------
    OUTPUT COLUMNS
    -----------------------------------------------------------------------
    SI_IdentityAssets_CL (all fields stored as typed int/bool/string):

      Core identity
        ObjectId, ObjectType, DisplayName, UPN, AppId, SPType, AccountEnabled

      Classification
        EffectiveTier          int    Min across all providers (0=critical, 3=low)
        TierSources            string JSON: {EntraID_Roles, EntraID_APIPermissions, AD, Azure}
                                            each with {Tier, CatalogMatches[]}

      Entra ID roles + perms
        EntraID_Roles          string JSON: {Permanent[], Eligible[], Tier}
        EntraID_AppPermissions string JSON: {AppRoles[], Delegated[], HighestRisk, Tier, ...}
        EntraID_Groups         string JSON array of all group memberships from IdentityInfo

      AD (synced users only)
        AD_Roles               string JSON: {Tier, TierSourceGroup, MatchedGroups[]}
        AD_Info                string JSON: {Domain, SAMAccountName, DistinguishedName, ...}

      Azure RBAC
        Azure_Delegations      string JSON array: [{RoleName, Scope, SubscriptionId,
                                                    SubscriptionName, PrincipalType,
                                                    RoleTier, ScopeLevel, Tier,
                                                    InheritedFromGroup, InheritedGroupId}]

      Workload identity
        Workload_Credentials   string JSON: {HasSecret, HasCert, ExpiryDays, HasExpired,
                                             HasNoOwner, OwnersCount, Owners[]}

      MDI enrichment (users only)
        MDI_BlastRadius, MDI_Tags, MDI_InvestigationPriority, MDI_RiskLevel,
        MDI_RiskState, MDI_EntityRiskScore, MDI_AssignedRoles, MDI_IsMFARegistered

      Risk flags (bool)
        IsPrivileged, IsPrivilegedEligible, HasPermanentPrivilegedRole,
        IsSensitive (Tier 0), IsHighValueTarget (Tier 0-1), IsBreakGlass,
        IsShadowAdmin, IsOrphan, IsExternal, IsB2BCollaborator,
        IsManagedIdentity, IsManagedIdentityUserAssigned, IsMultiTenant,
        IsExternal_SPN, IsStale, IsPasswordNeverExpires, IsPasswordlessOnly

      Sign-in lifecycle (int days, string datetime)
        CreatedDays, LastSignInDays, LastInteractiveSignInDays,
        LastNonInteractiveSignInDays, PasswordLastChangedDays

      MFA
        MFARegistered (bool), MFAMethodCount (int), MFAMethods (semicolon-separated)

      Infrastructure
        CSA, ExtensionAttributes (JSON)
        CollectionTime, Computer, ComputerFqdn, UserLoggedOn

    -----------------------------------------------------------------------
    PERFORMANCE NOTES
    -----------------------------------------------------------------------
    - SPN app permissions: pre-loaded in bulk (O(resource SPs) calls, not O(client SPs))
    - User group memberships: inverted transitiveMemberOf (O(role-bearing groups) not O(users))
    - Azure RBAC: per-subscription Get-AzRoleAssignment (reliable, no ARG dependency)
    - Streaming: records written to OUTPUT\IdentityAssets_Collection.jsonl during collection
      (not buffered in RAM). Schema sample (100 of each type) passed to CheckCreateUpdate.
    - Ingest: read from file in chunks of 10,000, native AzLogDcrIngestPS pipeline per chunk.

    -----------------------------------------------------------------------
    REQUIRED PERMISSIONS
    -----------------------------------------------------------------------
    Microsoft Graph (Application):
      User.Read.All                         - enumerate users
      AuditLog.Read.All                     - sign-in timestamps
      Directory.Read.All                    - groups, roles, organization
      Application.Read.All                  - service principals
      RoleManagement.Read.Directory         - role assignments + schedules
      CustomSecAttributeAssignment.Read.All - CSA attributes
      UserAuthenticationMethod.Read.All     - MFA methods
      PrivilegedAccess.Read.AzureAD         - PIM eligible role schedules
      PrivilegedAccess.Read.AzureADGroup    - PIM for Groups eligibility
      ThreatHunting.Read.All                - Exposure Graph (AD group memberships via Advanced Hunting)

    Azure RBAC (on SecurityInsight SPN):
      Reader on all subscriptions           - Get-AzRoleAssignment
      Log Analytics Reader on WorkspaceResourceId
      Log Analytics Reader on DefenderWorkspaceResourceId (if set, for IdentityInfo + sign-in logs)

    -----------------------------------------------------------------------
    TROUBLESHOOTING
    -----------------------------------------------------------------------
    TroubleshootingMode=true limits collection to 10 users / 10 SPNs / 10 subscriptions.
    Temp file survives the run at: OUTPUT\IdentityAssets_Collection.jsonl
    All Clear()/GC() calls tagged [TROUBLESHOOTING] and commented out.
    $ingestChunk kept in memory for post-run inspection.

    Manual replay (re-ingest without re-collecting):
      $tempFile = Join-Path $PSScriptRoot "OUTPUT\IdentityAssets_Collection.jsonl"
      # Then run the ingest loop manually - see end of script for quick one-liners.

    Check field types after collection:
      $ingestChunk[0].PSObject.Properties | Select-Object Name,
        @{N='Type';E={<#
.SYNOPSIS
    SecurityInsight - Identity Assets: Collect, Define Tier, Ingest, Log

    Collects all identity metadata from Entra ID (Users, Service Principals, Managed Identities),
    classifies each identity across four risk dimensions, and ingests into SI_IdentityAssets_CL
    via DCR / Log Ingestion API using the AzLogDcrIngestPS module.

.DESCRIPTION
    -----------------------------------------------------------------------
    ARCHITECTURE
    -----------------------------------------------------------------------
    Dot-sourced by a launcher script. All configuration via launcher globals.
    No parameters except TierDefinitionsPath (optional path override).

    Launcher modes:
      Automation_Framework    - cert-based auth via Automation-DefaultVariables / Connect_Azure
      Community / Test        - SPN + secret, TroubleshootingMode limits to 10 records

    Workspace layout:
      WorkspaceResourceId               - target LA workspace for SI_IdentityAssets_CL ingestion
      DefenderWorkspaceResourceId       - (optional) separate LA workspace where IdentityInfo
                                          and AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs
                                          reside (Defender / Sentinel workspace).
                                          If not set, both tables are read from WorkspaceResourceId.

    -----------------------------------------------------------------------
    TIERING MODEL
    -----------------------------------------------------------------------
    Every identity receives an EffectiveTier (0=critical, 1=privileged, 2=standard, 3=low).
    The tier is computed across four independent providers. Each provider calculates its own
    tier from the SecurityInsight_IdentityTiering.json catalog. EffectiveTier = Min across providers.

    TierSources column (JSON) stores per-provider tier + CatalogMatches (proof):

    1. ENTRA ID ROLES  (EntraID_Roles provider)
       Source  : Graph roleManagement/directory/roleAssignmentSchedules +
                 roleEligibilitySchedules + PIM for Groups
       Catalog : EntraID_BuiltInRoles_Tier0-3 + EntraID_CustomRoles_Tier0-3 (DisplayName exact match)
       Covers  : Users, SPNs, MIs

    2. ENTRA ID API PERMISSIONS  (EntraID_APIPermissions provider)
       Source  : servicePrincipals appRoleAssignedTo (bulk, per resource SP) +
                 oauth2PermissionGrants (tenant-wide AllPrincipals consent)
       Catalog : EntraID_APIPermissions_Tier0-3 (Value field exact match, case-insensitive)
       Covers  : SPNs, MIs (not applicable for users)

    3. LEGACY AD  (AD provider)
       Source  : IdentityInfo GroupMembership column from Log Analytics (contains synced AD groups)
       Catalog : AD_BuiltInPermissionGroups_Tier0-3 (Name field, exact case-insensitive match)
       Covers  : AD-synced users only (AccountDomain + AccountSID present in IdentityInfo)
       Note    : Cloud-only users get AD Tier = null (no signal)

    4. AZURE RBAC  (Azure provider)
       Source  : Get-AzRoleAssignment per subscription
       Catalog : Azure_BuiltInRoles_Tier0-3 + Azure_CustomRoles_Tier0-3 (Name field exact match)
       Covers  : Users, SPNs, MIs (direct + inherited via group membership / PIM for Groups)

       AZURE SCOPE MODULATION:
       Role tier from catalog defines ceiling risk. Scope narrows the effective impact:

         EffectiveTier per assignment = Max(RoleTier, ScopeLevel)

         ScopeLevel:
           0 - Tenant root (/) or root Management Group
           1 - Management Group (non-root) or Subscription
           2 - Resource Group
           3 - Individual resource

         Examples:
           Owner (T0) at tenant root    -> Max(0, 0) = Tier 0
           Owner (T0) at subscription   -> Max(0, 1) = Tier 1
           Owner (T0) at resource group -> Max(0, 2) = Tier 2
           Contributor (T1) at sub      -> Max(1, 1) = Tier 1
           Reader (T3) at tenant root   -> Max(3, 0) = Tier 3

         Azure_Delegations column stores RoleTier, ScopeLevel, and Tier (effective) per assignment.

    -----------------------------------------------------------------------
    OUTPUT COLUMNS
    -----------------------------------------------------------------------
    SI_IdentityAssets_CL (all fields stored as typed int/bool/string):

      Core identity
        ObjectId, ObjectType, DisplayName, UPN, AppId, SPType, AccountEnabled

      Classification
        EffectiveTier          int    Min across all providers (0=critical, 3=low)
        TierSources            string JSON: {EntraID_Roles, EntraID_APIPermissions, AD, Azure}
                                            each with {Tier, CatalogMatches[]}

      Entra ID roles + perms
        EntraID_Roles          string JSON: {Permanent[], Eligible[], Tier}
        EntraID_AppPermissions string JSON: {AppRoles[], Delegated[], HighestRisk, Tier, ...}
        EntraID_Groups         string JSON array of all group memberships from IdentityInfo

      AD (synced users only)
        AD_Roles               string JSON: {Tier, TierSourceGroup, MatchedGroups[]}
        AD_Info                string JSON: {Domain, SAMAccountName, DistinguishedName, ...}

      Azure RBAC
        Azure_Delegations      string JSON array: [{RoleName, Scope, SubscriptionId,
                                                    SubscriptionName, PrincipalType,
                                                    RoleTier, ScopeLevel, Tier,
                                                    InheritedFromGroup, InheritedGroupId}]

      Workload identity
        Workload_Credentials   string JSON: {HasSecret, HasCert, ExpiryDays, HasExpired,
                                             HasNoOwner, OwnersCount, Owners[]}

      MDI enrichment (users only)
        MDI_BlastRadius, MDI_Tags, MDI_InvestigationPriority, MDI_RiskLevel,
        MDI_RiskState, MDI_EntityRiskScore, MDI_AssignedRoles, MDI_IsMFARegistered

      Risk flags (bool)
        IsPrivileged, IsPrivilegedEligible, HasPermanentPrivilegedRole,
        IsSensitive (Tier 0), IsHighValueTarget (Tier 0-1), IsBreakGlass,
        IsShadowAdmin, IsOrphan, IsExternal, IsB2BCollaborator,
        IsManagedIdentity, IsManagedIdentityUserAssigned, IsMultiTenant,
        IsExternal_SPN, IsStale, IsPasswordNeverExpires, IsPasswordlessOnly

      Sign-in lifecycle (int days, string datetime)
        CreatedDays, LastSignInDays, LastInteractiveSignInDays,
        LastNonInteractiveSignInDays, PasswordLastChangedDays

      MFA
        MFARegistered (bool), MFAMethodCount (int), MFAMethods (semicolon-separated)

      Infrastructure
        CSA, ExtensionAttributes (JSON)
        CollectionTime, Computer, ComputerFqdn, UserLoggedOn

    -----------------------------------------------------------------------
    PERFORMANCE NOTES
    -----------------------------------------------------------------------
    - SPN app permissions: pre-loaded in bulk (O(resource SPs) calls, not O(client SPs))
    - User group memberships: inverted transitiveMemberOf (O(role-bearing groups) not O(users))
    - Azure RBAC: per-subscription Get-AzRoleAssignment (reliable, no ARG dependency)
    - Streaming: records written to OUTPUT\IdentityAssets_Collection.jsonl during collection
      (not buffered in RAM). Schema sample (100 of each type) passed to CheckCreateUpdate.
    - Ingest: read from file in chunks of 10,000, native AzLogDcrIngestPS pipeline per chunk.

    -----------------------------------------------------------------------
    REQUIRED PERMISSIONS
    -----------------------------------------------------------------------
    Microsoft Graph (Application):
      User.Read.All                         - enumerate users
      AuditLog.Read.All                     - sign-in timestamps
      Directory.Read.All                    - groups, roles, organization
      Application.Read.All                  - service principals
      RoleManagement.Read.Directory         - role assignments + schedules
      CustomSecAttributeAssignment.Read.All - CSA attributes
      UserAuthenticationMethod.Read.All     - MFA methods
      PrivilegedAccess.Read.AzureAD         - PIM eligible role schedules
      PrivilegedAccess.Read.AzureADGroup    - PIM for Groups eligibility
      ThreatHunting.Read.All                - Exposure Graph (AD group memberships via Advanced Hunting)

    Azure RBAC (on SecurityInsight SPN):
      Reader on all subscriptions           - Get-AzRoleAssignment
      Log Analytics Reader on WorkspaceResourceId
      Log Analytics Reader on DefenderWorkspaceResourceId (if set, for IdentityInfo + sign-in logs)

    -----------------------------------------------------------------------
    TROUBLESHOOTING
    -----------------------------------------------------------------------
    TroubleshootingMode=true limits collection to 10 users / 10 SPNs / 10 subscriptions.
    Temp file survives the run at: OUTPUT\IdentityAssets_Collection.jsonl
    All Clear()/GC() calls tagged [TROUBLESHOOTING] and commented out.
    $ingestChunk kept in memory for post-run inspection.

    Manual replay (re-ingest without re-collecting):
      $tempFile = Join-Path $PSScriptRoot "OUTPUT\IdentityAssets_Collection.jsonl"
      # Then run the ingest loop manually - see end of script for quick one-liners.

    Check field types after collection:
      $ingestChunk[0].PSObject.Properties | Select-Object Name,
        @{N='Type';E={$_.Value.GetType().Name}} | Sort-Object Name

.PARAMETER TierDefinitionsPath
    Path to SecurityInsight_IdentityTiering.json. Defaults to
    ..\DATA\SecurityInsight_IdentityTiering.json relative to this script
    (the same path Build_Tier_Definitions_JSON_File.ps1 writes to).

.EXAMPLE
    # Run via launcher (recommended):
    .\RunIdentityAssetsCollectDefineTierIngestLog_Community_TestVariables.ps1

.EXAMPLE
    # Override tier definitions path:
    $TierDefinitionsPath = "D:\SecurityInsight\DATA\SecurityInsight_IdentityTiering.json"
    . .\IdentityAssetsCollectDefineTierIngestLog.ps1
#>

param(
    [string]$TierDefinitionsPath    # Only param kept - all other config comes from launcher globals
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules
#########################################################################################################
# HELPERS
#########################################################################################################

function Write-Step  ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan  }
function Write-Info  ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray  }
function Write-Ok    ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn  ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err2  ($m) { Write-Host "[ERR]  $m" -ForegroundColor Red   }
function Write-Sep         { Write-Host ("-" * 80) -ForegroundColor DarkGray }

# Returns $true if a subscription name matches ANY exclude pattern.
# Patterns are PowerShell wildcards (e.g. '*Azure for Students*').
# Empty/null pattern list => never excludes.
function Test-SubscriptionExcluded {
    param([string]$Name, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        if ($Name -like $pat) { return $true }
    }
    return $false
}

function Invoke-Graph {
    param([string]$Uri, [string]$Method = "GET")
    # Use Invoke-RestMethod with the Bearer token read from script scope at call time.
    # $script:graphToken ensures we always get the current token even when dot-sourced.
    # Avoids Invoke-MgGraphRequest URL rewriting (strips beta base, adds v1.0).
    try {
        return Invoke-RestMethod -Method $Method -Uri $Uri `
               -Headers @{ "Authorization" = "Bearer $script:graphToken"; "Content-Type" = "application/json" } `
               -ErrorAction Stop
    } catch {
        $detail = $null
        try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue) } catch {}
        if ($detail -and $detail.error -and $detail.error.message) { $errMsg = $detail.error.message } else { $errMsg = $_.Exception.Message }
        throw "[$Method $Uri] $errMsg"
    }
}

function Get-AllPages ([string]$Uri) {
    $items   = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    do {
        $r = Invoke-Graph -Uri $nextUri

        # Add values - handle both array and single object responses
        if ($r.value) { foreach ($v in $r.value) { $items.Add($v) } }

        # Get nextLink - Invoke-MgGraphRequest returns a Hashtable so check both ways
        $nextUri = $null
        if ($r -is [System.Collections.IDictionary]) {
            # Hashtable - use key access
            if ($r.ContainsKey('@odata.nextLink') -and $r['@odata.nextLink']) {
                $nextUri = $r['@odata.nextLink']
            }
        } elseif ($r.PSObject.Properties['@odata.nextLink']) {
            # PSCustomObject
            $nextUri = $r.PSObject.Properties['@odata.nextLink'].Value
        }
    } while ($nextUri)
    return $items
}

function Get-DaysSince ([object]$DateValue) {
    if (-not $DateValue) { return -1 }
    try { return [int]([datetime]::UtcNow - [datetime]::Parse($DateValue.ToString())).TotalDays }
    catch { return -1 }
}

function Get-TierFromEntraAPIPerms ([string[]]$Perms) {
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier0.Contains($p)) { return 0 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier1.Contains($p)) { return 1 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier2.Contains($p)) { return 2 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier3.Contains($p)) { return 3 } }
    if ($Perms.Count -gt 0) { return 2 }  # has perms but none in catalog - treat as Tier 2
    return $null   # no perms = no signal, caller defaults
}

function Get-HighestRiskEntraAPIPermission ([string[]]$Perms) {
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier0.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier1.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier2.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier3.Contains($p)) { return $p } }
    $first = $Perms | Select-Object -First 1
    if ($null -ne $first) { return $first } else { return "" }
}

function Get-TierFromEntraRoles ([string[]]$Roles) {
    # Checks all four tiers in priority order - first match wins (lowest number = highest risk)
    # null : no roles at all -> caller defaults to tier 2
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier3 -contains $r) { return 3 } }
    if ($Roles.Count -gt 0) { return 2 }  # has roles but none in catalog - treat as Tier 2
    return $null
}

function Get-TierFromADGroups ([string[]]$Groups) {
    # O(1) lookup via catalog hashtable - returns lowest tier found across all matched groups
    $minTier = $null
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($entry) {
            $t = [int]$entry.Tier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier   # null = no catalog match
}

function Get-TierSourceFromADGroups ([string[]]$Groups) {
    # Returns the Name of the highest-risk catalog entry matched
    $best = $null
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($entry) {
            if ($null -eq $best -or [int]$entry.Tier -lt [int]$best.Tier) { $best = $entry }
        }
    }
    return if ($best) { [string]$best.Name } else { "" }
}

function Get-TierFromAzureRoles ([string[]]$Roles) {
    # Checks all four tiers in priority order - first match wins (lowest number = highest risk)
    # null : no Azure roles at all -> no signal, caller defaults
    foreach ($r in $Roles) { if ($Azure_Roles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier3 -contains $r) { return 3 } }
    if ($Roles.Count -gt 0) { return 2 }  # has Azure roles but none in catalog - treat as Tier 2
    return $null
}

function Get-EntraRoleMatches ([string[]]$Roles) {
    # Returns all roles that matched a catalog entry, annotated with which tier they matched.
    # Proof: identity -> catalog entry -> tier
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Roles) {
        $t = if     ($EntraID_Roles_Tier0 -contains $r) { 0 }
             elseif ($EntraID_Roles_Tier1 -contains $r) { 1 }
             elseif ($EntraID_Roles_Tier2 -contains $r) { 2 }
             elseif ($EntraID_Roles_Tier3 -contains $r) { 3 }
             else                                        { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-EntraPermMatches ([string[]]$Perms) {
    # Returns all permissions that matched a catalog entry, annotated with tier.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Perms) {
        $t = if     ($EntraID_APIPerms_Tier0.Contains($p)) { 0 }
             elseif ($EntraID_APIPerms_Tier1.Contains($p)) { 1 }
             elseif ($EntraID_APIPerms_Tier2.Contains($p)) { 2 }
             elseif ($EntraID_APIPerms_Tier3.Contains($p)) { 3 }
             else                                          { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Permission = $p; CatalogTier = $t }) }
    }
    return $matched
}

function Get-AzureRoleMatches ([string[]]$Roles) {
    # Returns all Azure roles that matched a catalog entry, annotated with tier.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Roles) {
        $t = if     ($Azure_Roles_Tier0 -contains $r) { 0 }
             elseif ($Azure_Roles_Tier1 -contains $r) { 1 }
             elseif ($Azure_Roles_Tier2 -contains $r) { 2 }
             elseif ($Azure_Roles_Tier3 -contains $r) { 3 }
             else                                      { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-ADGroupMatches ([string[]]$Groups) {
    # Match IdentityInfo GroupMembership names against AD_BuiltInPermissionGroups_Tier0-3 catalog.
    # Exact case-insensitive match on Name field. Tier and Reason are read from the catalog entry.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $catalogEntry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($catalogEntry) {
            $matched.Add([ordered]@{
                Name   = [string]$catalogEntry.Name
                Tier   = [int]$catalogEntry.Tier
                Reason = [string]$catalogEntry.Reason
            })
        }
    }
    return $matched
}

function Get-AzureScopeLabel ([string]$Scope) {
    # Returns a human-readable label for the scope, including the resource name where possible.
    if ([string]::IsNullOrWhiteSpace($Scope)) { return "Unknown" }
    $s = $Scope.Trim().TrimEnd('/')
    if ($s -eq '' -or $s -eq '/')                                                              { return "Tenant Root" }
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$')               { return "Management Group: $($Matches[1])" }
    if ($s -match '^/subscriptions/([^/]+)$')                                                  { return "Subscription: $($Matches[1])" }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)$')                            { return "Resource Group: $($Matches[1])" }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/[^/]+/([^/]+)/([^/]+)')  { return "Resource: $($Matches[3]) ($($Matches[2]))" }
    if ($s -match '^/subscriptions/[^/]+/providers/(.+)$')                                    { return "Subscription Resource: $($Matches[1])" }
    return $Scope
}

function Get-AzurePrincipalRoleNames ([string]$ObjectId, [string[]]$MemberIds = @()) {
    # Returns all distinct Azure role names assigned to this principal (direct + inherited via groups).
    $names = [System.Collections.Generic.List[string]]::new()
    $allIds = @($ObjectId) + $MemberIds | Where-Object { $_ } | Select-Object -Unique
    foreach ($id in $allIds) {
        if ($azureDelegationLookup.ContainsKey($id)) {
            foreach ($e in $azureDelegationLookup[$id]) {
                $n = if ($e -is [System.Collections.IDictionary]) { [string]$e['RoleName'] } else { [string]$e.RoleName }
                if ($n -and -not $names.Contains($n)) { $names.Add($n) }
            }
        }
    }
    return $names.ToArray()
}

function Get-AzurePrincipalAssignments ([string]$ObjectId, [string[]]$MemberIds = @()) {
    # Returns full assignment detail for TierSources: role, scope label, scope level, tier.
    # Includes direct assignments and inherited via group membership / PIM for Groups.
    $assignments = [System.Collections.Generic.List[object]]::new()
    $allIds = @($ObjectId) + $MemberIds | Where-Object { $_ } | Select-Object -Unique
    foreach ($id in $allIds) {
        if (-not $azureDelegationLookup.ContainsKey($id)) { continue }
        foreach ($e in $azureDelegationLookup[$id]) {
            $roleName  = if ($e -is [System.Collections.IDictionary]) { [string]$e['RoleName']  } else { [string]$e.RoleName  }
            $scope     = if ($e -is [System.Collections.IDictionary]) { [string]$e['Scope']     } else { [string]$e.Scope     }
            $subName   = if ($e -is [System.Collections.IDictionary]) { [string]$e['SubscriptionName'] } else { [string]$e.SubscriptionName }
            $roleTier  = if ($e -is [System.Collections.IDictionary]) { $e['RoleTier']  } else { $e.RoleTier  }
            $scopeLvl  = if ($e -is [System.Collections.IDictionary]) { $e['ScopeLevel'] } else { $e.ScopeLevel }
            $effTier   = if ($e -is [System.Collections.IDictionary]) { $e['Tier']      } else { $e.Tier      }
            $isInher   = $id -ne $ObjectId

            $assignments.Add([ordered]@{
                Role             = $roleName
                Scope            = $scope
                ScopeLabel       = Get-AzureScopeLabel -Scope $scope
                SubscriptionName = $subName
                ScopeLevel       = $scopeLvl
                RoleTier         = $roleTier
                EffectiveTier    = $effTier
                InheritedViaGroup = $isInher
            })
        }
    }
    return $assignments
}

function Get-AzureScopeLevel ([string]$Scope) {
    # Resolves an Azure RBAC scope string to a risk level (0=highest, 3=lowest).
    # Risk decreases as scope narrows - same role is less impactful at a lower scope.
    #
    # Level 0 - Tenant root or root Management Group
    #           Scope: "/"  or  "/providers/Microsoft.Management/managementGroups/<tenantId>"
    # Level 1 - Management Group (non-root) or Subscription
    #           Scope: "/providers/Microsoft.Management/managementGroups/<name>"
    #                  "/subscriptions/<subId>"
    # Level 2 - Resource Group
    #           Scope: "/subscriptions/<subId>/resourceGroups/<rg>"
    # Level 3 - Individual resource (anything deeper)
    #           Scope: "/subscriptions/<subId>/resourceGroups/<rg>/providers/..."

    if ([string]::IsNullOrWhiteSpace($Scope)) { return 1 }   # unknown = treat as subscription level

    $s = $Scope.Trim().TrimEnd('/')

    # Tenant root
    if ($s -eq '' -or $s -eq '/') { return 0 }

    # Root management group (scope contains only one MG segment with no parent MG)
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') {
        # Determine if this is the root MG (same ID as tenant) - treat all top-level MGs as L0
        return 0
    }

    # Subscription only
    if ($s -match '^/subscriptions/[^/]+$') { return 1 }

    # Resource Group
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 2 }

    # Individual resource (anything deeper)
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/') { return 3 }

    # Subscription-level resource provider scope (no RG)
    if ($s -match '^/subscriptions/[^/]+/providers/') { return 1 }

    # Fallback
    return 1
}

function Get-AzureEffectiveTier ([string]$RoleName, [string]$Scope) {
    # Effective tier = Max(RoleTier, ScopeLevel)
    # The role defines the ceiling risk; scope can only reduce impact (raise tier number), never increase it.
    # Example: Owner (T0) at ResourceGroup scope -> Max(0, 2) = 2
    #          Owner (T0) at TenantRoot scope    -> Max(0, 0) = 0
    #          Reader (T3) at TenantRoot scope   -> Max(3, 0) = 3 (Reader is always low risk)
    $roleTier  = Get-TierFromAzureRoles -Roles @($RoleName)
    if ($null -eq $roleTier) { $roleTier = 2 }   # unknown role = standard
    $scopeLevel = Get-AzureScopeLevel -Scope $Scope
    return [Math]::Max($roleTier, $scopeLevel)
}

function Get-MinTier ([object[]]$Tiers) {
    # Returns the lowest (most privileged) tier from the supplied values.
    # Nulls and -1 are excluded (= no signal / not applicable).
    # Default is 3 - a user with no signals has no privileged access.
    $valid = @($Tiers | Where-Object { $_ -ne $null -and [int]$_ -ge 0 } | ForEach-Object { [int]$_ })
    if ($valid.Count -eq 0) { return 3 }
    return ($valid | Measure-Object -Minimum).Minimum
}

function To-JsonStr ([object]$obj) {
    # PS 5.1 ConvertTo-Json collapses single-element arrays to plain strings.
    # Recursively wrap any array values in a typed string array before serializing.
    function Protect-Arrays ([object]$o) {
        if ($o -is [System.Collections.IDictionary]) {
            $out = [ordered]@{}
            foreach ($k in $o.Keys) {
                $v = $o[$k]
                if ($v -is [System.Array] -or $v -is [System.Collections.IList]) {
                    # Force typed string array - ConvertTo-Json always emits [] for these
                    $out[$k] = [string[]]@($v | ForEach-Object { "$_" })
                } else {
                    $out[$k] = Protect-Arrays $v
                }
            }
            return $out
        }
        return $o
    }
    try {
        $safe = Protect-Arrays $obj
        return ($safe | ConvertTo-Json -Depth 5 -Compress)
    } catch { return '{}' }
}

function Join-Array ([object]$Value) {
    if (-not $Value) { return "" }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return ($Value | ForEach-Object { [string]$_ }) -join ";"
    }
    return [string]$Value
}


########################################################################################################
# # GLOBAL-ONLY CONFIG - PHASE 1: execution-control globals (available before AF module load)
#########################################################################################################

if ($null -eq $global:AutomationFramework)  { $global:AutomationFramework  = $false }
if ($null -eq $global:SuppressErrors)       { $global:SuppressErrors       = $false }
if ($null -eq $global:SuppressWarnings)     { $global:SuppressWarnings     = $false }
if ($null -eq $global:WhatIfMode)           { $global:WhatIfMode           = $false }

$AutomationFramework = [bool]$global:AutomationFramework
$SuppressErrors      = [bool]$global:SuppressErrors
$SuppressWarnings    = [bool]$global:SuppressWarnings
$WhatIfMode          = [bool]$global:WhatIfMode
$script:SuppressErrors   = $SuppressErrors
$script:SuppressWarnings = $SuppressWarnings
$script:WhatIfMode       = $WhatIfMode

#########################################################################################################
# AUTHENTICATION + AZURE / GRAPH CONNECT
# Matches the pattern used in CriticalAssetTagging.ps1 and SecurityInsight_RiskAnalysis.ps1
#
# AF mode:        modules -> ConnectDetails -> Default_Variables -> Connect_Azure.ps1
#                 Default_Variables populates $global:SecurityInsight_LOG_* and
#                 $global:SecurityInsight_Identity_* - resolved into locals AFTER this block.
# Community mode: SpnTenantId/SpnClientId/SpnClientSecret set directly by launcher.
#########################################################################################################

if ($AutomationFramework) {
    #----------------------
    # AUTOMATION FRAMEWORK
    #----------------------
    # v2 AutomationFramework bootstrap (replaces v1 Connect_Azure.ps1 chain).
    # Walks up to the AutomateITPS module, then one call to
    # Initialize-PlatformAutomationFramework does cert-based Connect-AzAccount,
    # fetches Modern secrets from KV, and populates the v1-contract
    # $global:HighPriv_* / $global:AzureTenantId names. Zero v1 module imports.
    $repoRoot = $PSScriptRoot
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$PSScriptRoot'."
    }
    $global:PathScripts = $repoRoot
    Write-Output ""
    Write-Output "Repo root          -> $($global:PathScripts)"

    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue
    $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientSecret)) {
        throw "Missing SPN globals after Automation Framework load (SpnTenantId/SpnClientId/SpnClientSecret)."
    }

} else {
    #----------------------
    # COMMUNITY / CUSTOM AUTH
    #----------------------
    if ([string]::IsNullOrWhiteSpace($global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientId) -or
        [string]::IsNullOrWhiteSpace($global:SpnClientSecret)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret). Launcher must set them or enable AutomationFramework."
    }

    Write-Host "Connect using ServicePrincipal with AppId & Secret"
    Write-Step "connecting to Azure"
    try {
        $global:SecureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $global:Credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $global:SecureSecret)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $global:Credential -WarningAction SilentlyContinue | Out-Null
        Write-Ok "azure connection step done"
    } catch { Write-Err2 "azure connection failed: $($_.Exception.Message)"; throw }
}

# Resolve auth locals - used throughout the rest of the script
$TenantId                 = [string]$global:SpnTenantId
$IngestionSpnClientId     = [string]$global:SpnClientId
$IngestionSpnClientSecret = [string]$global:SpnClientSecret

#########################################################################################################
# GLOBAL-ONLY CONFIG - PHASE 2: infrastructure locals
# AF mode:        read from $global:SecurityInsight_LOG_* / $global:SecurityInsight_Identity_*
#                 populated by Default_Variables above.
# Community mode: read from $global:DceIngestionUri etc. set directly by the launcher.
#########################################################################################################

# LOG_* names (platform-defaults-set) are still AF-only; the four behaviour
# globals (TroubleshootingMode / CsaAttributeSet / Defender workspace /
# SubscriptionNameExcludePatterns) are now read from the PLAIN names in BOTH
# modes, with fallback to the legacy SecurityInsight_Identity_* / _Defender_*
# names so existing platform-defaults.ps1 installs keep working.
if ($AutomationFramework) {
    $BatchSize            = if ($null -ne $global:SecurityInsight_LOG_BatchSize -and $global:SecurityInsight_LOG_BatchSize -gt 0) { [int]$global:SecurityInsight_LOG_BatchSize               } else { 300 }
    $TableName            = if (-not [string]::IsNullOrWhiteSpace([string]$global:SecurityInsight_LOG_TableName))              { [string]$global:SecurityInsight_LOG_TableName                 } else { 'SI_IdentityAssets' }
    $WorkspaceResourceId  = [string]$global:SecurityInsight_LOG_WorkspaceResourceId
    $WorkspaceName        = [string]$global:SecurityInsight_LOG_WorkspaceName
    $WorkspaceResourceGroup = [string]$global:SecurityInsight_LOG_WorkspaceResourceGroup
    $DcrResourceGroup     = [string]$global:SecurityInsight_LOG_DcrResourceGroup
    $DcrName              = [string]$global:SecurityInsight_LOG_DcrName
    $DceName              = [string]$global:SecurityInsight_LOG_DceName
    $DceResourceGroup     = [string]$global:SecurityInsight_LOG_DceResourceGroup
    $DceIngestionUri      = [string]$global:SecurityInsight_LOG_DceIngestionUri
    $TenantDomain         = [string]$global:TenantDomain
} else {
    $BatchSize            = if ($null -ne $global:BatchSize -and $global:BatchSize -gt 0)                                     { [int]$global:BatchSize                                       } else { 300 }
    $TableName            = if (-not [string]::IsNullOrWhiteSpace([string]$global:TableName))                                  { [string]$global:TableName                                    } else { 'SI_IdentityAssets' }
    $WorkspaceResourceId  = [string]$global:WorkspaceResourceId
    $WorkspaceName        = [string]$global:WorkspaceName
    $WorkspaceResourceGroup = [string]$global:WorkspaceResourceGroup
    $DcrResourceGroup     = [string]$global:DcrResourceGroup
    $DcrName              = [string]$global:DcrName
    $DceName              = [string]$global:DceName
    $DceResourceGroup     = [string]$global:DceResourceGroup
    $DceIngestionUri      = [string]$global:DceIngestionUri
    $TenantDomain         = [string]$global:TenantDomain
}

# Behaviour globals -- plain names preferred in BOTH modes, fall back to legacy.
$TroubleshootingMode = if ($null -ne $global:TroubleshootingMode)                                      { [bool]$global:TroubleshootingMode }
                       elseif ($null -ne $global:SecurityInsight_Identity_TroubleshootingMode)         { [bool]$global:SecurityInsight_Identity_TroubleshootingMode }
                       else                                                                            { $false }
$CsaAttributeSet     = if (-not [string]::IsNullOrWhiteSpace([string]$global:CsaAttributeSet))         { [string]$global:CsaAttributeSet }
                       elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SecurityInsight_Identity_CsaAttributeSet)) { [string]$global:SecurityInsight_Identity_CsaAttributeSet }
                       else                                                                            { 'SecurityInsight' }
# Sentinel/Defender workspace -- set when IdentityInfo lives in a different LA
# workspace than the identity table workspace. Accepts three names:
#   $global:Defender_WorkspaceNameResourceId  (new canonical)
#   $global:DefenderWorkspaceResourceId       (legacy community)
#   $global:SecurityInsight_Defender_WorkspaceResourceId (legacy AF)
$DefenderWorkspaceResourceId = if (-not [string]::IsNullOrWhiteSpace([string]$global:Defender_WorkspaceNameResourceId))       { [string]$global:Defender_WorkspaceNameResourceId }
                               elseif (-not [string]::IsNullOrWhiteSpace([string]$global:DefenderWorkspaceResourceId))        { [string]$global:DefenderWorkspaceResourceId }
                               elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SecurityInsight_Defender_WorkspaceResourceId)) { [string]$global:SecurityInsight_Defender_WorkspaceResourceId }
                               else                                                                                           { '' }
# Subscription name exclude patterns (wildcard, e.g. '*Azure for Students*')
$SubscriptionNameExcludePatterns = if ($global:SubscriptionNameExcludePatterns)                                { @($global:SubscriptionNameExcludePatterns | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) }
                                   elseif ($global:SecurityInsight_Identity_SubscriptionNameExcludePatterns)   { @($global:SecurityInsight_Identity_SubscriptionNameExcludePatterns | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }) }
                                   else                                                                        { @() }

#########################################################################################################
# DEFAULTS + VALIDATE - infrastructure locals must be set regardless of auth mode
#
# Everything auto-resolves from sensible defaults unless the customer overrides.
# Workspace: provide ResourceId OR Name (resource ID wins; name is looked up / auto-created).
# DceIngestionUri: auto-resolved from DceName via $global:AzDceDetails.
# DCE and DCR are auto-created if missing (see BUILD DCE/DCR CACHE section below).
#########################################################################################################

if ([string]::IsNullOrWhiteSpace($DceName))                { $DceName                = 'dce-securityinsight' }
if ([string]::IsNullOrWhiteSpace($DcrResourceGroup))       { $DcrResourceGroup       = 'rg-dcr-securityinsight' }
if ([string]::IsNullOrWhiteSpace($DceResourceGroup))       { $DceResourceGroup       = 'rg-dce-securityinsight' }
if ([string]::IsNullOrWhiteSpace($DcrName))                { $DcrName                = 'dcr-si-identity-assets' }
if ([string]::IsNullOrWhiteSpace($TableName))              { $TableName              = 'SI_IdentityAssets' }
if ([string]::IsNullOrWhiteSpace($WorkspaceResourceGroup)) { $WorkspaceResourceGroup = 'rg-securityinsight' }
if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId) -and [string]::IsNullOrWhiteSpace($WorkspaceName)) {
    $WorkspaceName = 'log-platform-management-securityinsight'
}

$missing = @()
if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId) -and [string]::IsNullOrWhiteSpace($WorkspaceName)) {
    $missing += "WorkspaceResourceId or WorkspaceName"
}
if ([string]::IsNullOrWhiteSpace($DcrResourceGroup))     { $missing += "DcrResourceGroup" }
if ([string]::IsNullOrWhiteSpace($DceName))              { $missing += "DceName" }

if ($missing.Count -gt 0) {
    $src = if ($AutomationFramework) { "global:SecurityInsight_LOG_* / SecurityInsight_Identity_*" } else { "launcher globals" }
    $hint = if ($AutomationFramework) {
        ""
    } else {
        "`n`nThese values come from the SecurityInsight Log Analytics infrastructure (Workspace + DCE + DCR + SI_IdentityAssets_CL table). If you have not provisioned it yet, run the onboarding launcher first:`n  LAUNCHERS\Step2_OnboardValidate-SecurityInsight-LogAnalytics\launcher.community-vm.template.ps1`nIts output prints the exact values to copy into LauncherConfig.custom.ps1."
    }
    throw ("The following required values are not set ($src):`n  " + ($missing -join "`n  ") + $hint)
}

#########################################################################################################
# SCRIPT BEHAVIOUR CONSTANTS
#########################################################################################################

$TroubleshootingLimit = 10

# Lookback window (days) for IdentityInfo (Log Analytics / Entra ID)
# IdentityInfo is a snapshot table updated daily - 90 days ensures full historical coverage
$IdentityInfoLookbackDays = 90

# Lookback window (days) for SPN/MI sign-in logs
# AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs
# 7 days is sufficient for active workload identities
$SpnSignInLookbackDays = 7

# Collection timestamp - consistent across all records in this run
[datetime]$CollectionTime = ( Get-Date ([datetime]::Now.ToUniversalTime()) -Format "yyyy-MM-ddTHH:mm:ssK" )

# SolutionVersion - which release of SecurityInsight produced these rows.
# Stamped alongside CollectionTime on every ingested row so KQL can answer
# "which version wrote this?" with `SI_IdentityAssets_CL | distinct SolutionVersion`.
# Walks up from $PSScriptRoot until a VERSION.txt is found (covers monorepo
# runs AND community installs where the engine lives at scripts/).
$SolutionVersion = '(dev)'
try {
    $_cur = $PSScriptRoot
    while ($_cur) {
        $_ver = Join-Path $_cur 'VERSION.txt'
        if (Test-Path -LiteralPath $_ver) {
            $SolutionVersion = (Get-Content -LiteralPath $_ver -Raw).Trim()
            break
        }
        $_parent = Split-Path -Parent $_cur
        if (-not $_parent -or $_parent -eq $_cur) { break }
        $_cur = $_parent
    }
} catch { }

#########################################################################################################
# CONSTANTS
#########################################################################################################

$GRAPH_BASE    = "https://graph.microsoft.com/beta"
$GRAPH_BETA    = "https://graph.microsoft.com/beta"   # kept for reference, same as GRAPH_BASE
$GRAPH_V1      = "https://graph.microsoft.com/v1.0"   # used for endpoints where beta returns 400
$GRAPH_APP_ID  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph SP

#########################################################################################################
# LOAD TIER DEFINITIONS FROM JSON
# Generated daily by Build_Tier_Definitions_JSON_File.ps1
# Path can be overridden via $TierDefinitionsPath parameter or the variable below.
#########################################################################################################

if ([string]::IsNullOrWhiteSpace($TierDefinitionsPath)) {
    # Single canonical location: the solution's DATA\ folder. Both
    # Build_Tier_Definitions_JSON_File.ps1 (writer) and this engine (reader)
    # use the same path. v1's SCRIPTS\Output\ subfolder is no longer used.
    $TierDefinitionsPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'DATA\SecurityInsight_IdentityTiering.json'
}

if (-not (Test-Path $TierDefinitionsPath)) {
    throw "Tier definitions JSON not found at:`n  $TierDefinitionsPath`nRun Build_Tier_Definitions_JSON_File.ps1 to generate it (writes to the same DATA\ path). You can also set `$TierDefinitionsPath explicitly to point at a different file."
}

Write-Host "[INFO] Loading tier definitions from: $TierDefinitionsPath" -ForegroundColor Cyan
$tierDefs = Get-Content -Path $TierDefinitionsPath -Raw -Encoding UTF8 | ConvertFrom-Json

# Expand-TierSection: normalises a JSON section to a guaranteed PowerShell array.
#
# PowerShell ConvertTo-Json has two known serialisation quirks that break direct iteration:
#   1. An empty array @() is written as {} (empty object) instead of []
#   2. A single-element array is collapsed to a bare object instead of a one-item array
# This helper handles all three shapes - proper array, bare object, empty object - and
# always returns a typed array safe for ForEach-Object and .Count.
function Expand-TierSection ([object]$Section) {
    if ($null -eq $Section)                          { return @() }          # missing key
    if ($Section -is [System.Array])                 { return $Section }     # normal array
    if ($Section -is [System.Collections.IEnumerable] -and
        -not ($Section -is [string]))                { return @($Section) }  # other enumerable
    # PSCustomObject: check if it has any properties (single item) or none (empty {})
    $props = @($Section.PSObject.Properties)
    if ($props.Count -eq 0)                          { return @() }          # was empty array {}
    return @($Section)                                                        # was single-item array
}

# --- Entra ID role lists (built-in + custom merged per tier) ---
# Property name in JSON is DisplayName (not Name)
$EntraID_Roles_Tier0 = @(
    @(Expand-TierSection $tierDefs.EntraID_BuiltInRoles_Tier0) + @(Expand-TierSection $tierDefs.EntraID_CustomRoles_Tier0) |
    ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique
)
$EntraID_Roles_Tier1 = @(
    @(Expand-TierSection $tierDefs.EntraID_BuiltInRoles_Tier1) + @(Expand-TierSection $tierDefs.EntraID_CustomRoles_Tier1) |
    ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique
)
$EntraID_Roles_Tier2 = @(
    @(Expand-TierSection $tierDefs.EntraID_BuiltInRoles_Tier2) + @(Expand-TierSection $tierDefs.EntraID_CustomRoles_Tier2) |
    ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique
)
$EntraID_Roles_Tier3 = @(
    @(Expand-TierSection $tierDefs.EntraID_BuiltInRoles_Tier3) + @(Expand-TierSection $tierDefs.EntraID_CustomRoles_Tier3) |
    ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique
)

# --- API permission HashSets per tier ---
# Property name in JSON is Value (not Name)
$EntraID_APIPerms_Tier0 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Expand-TierSection $tierDefs.EntraID_APIPermissions_Tier0 | ForEach-Object { [string]$_.Value } | Where-Object { $_ })) {
    $EntraID_APIPerms_Tier0.Add($p) | Out-Null
}

$EntraID_APIPerms_Tier1 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Expand-TierSection $tierDefs.EntraID_APIPermissions_Tier1 | ForEach-Object { [string]$_.Value } | Where-Object { $_ })) {
    $EntraID_APIPerms_Tier1.Add($p) | Out-Null
}

$EntraID_APIPerms_Tier2 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Expand-TierSection $tierDefs.EntraID_APIPermissions_Tier2 | ForEach-Object { [string]$_.Value } | Where-Object { $_ })) {
    $EntraID_APIPerms_Tier2.Add($p) | Out-Null
}

$EntraID_APIPerms_Tier3 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($p in (Expand-TierSection $tierDefs.EntraID_APIPermissions_Tier3 | ForEach-Object { [string]$_.Value } | Where-Object { $_ })) {
    $EntraID_APIPerms_Tier3.Add($p) | Out-Null
}

# --- AD group catalog: full objects (Name, Tier, Reason) for exact matching ---
# Also keep flat name arrays for the tier functions that need them
$AD_Groups_Catalog = @(
    @(Expand-TierSection $tierDefs.AD_BuiltInPermissionGroups_Tier0) +
    @(Expand-TierSection $tierDefs.AD_BuiltInPermissionGroups_Tier1) +
    @(Expand-TierSection $tierDefs.AD_BuiltInPermissionGroups_Tier2) +
    @(Expand-TierSection $tierDefs.AD_BuiltInPermissionGroups_Tier3)
)
# Build a hashtable for O(1) lookup: Name (lowercase) -> catalog entry object
$AD_Groups_CatalogLookup = @{}
foreach ($entry in $AD_Groups_Catalog) {
    $n = [string]$entry.Name
    if ($n) { $AD_Groups_CatalogLookup[$n.ToLower()] = $entry }
}
# Flat name arrays still needed by Get-TierFromADGroups / Get-TierSourceFromADGroups
$AD_Groups_Tier0 = @($AD_Groups_Catalog | Where-Object { $_.Tier -eq 0 } | ForEach-Object { [string]$_.Name } | Where-Object { $_ })
$AD_Groups_Tier1 = @($AD_Groups_Catalog | Where-Object { $_.Tier -eq 1 } | ForEach-Object { [string]$_.Name } | Where-Object { $_ })
$AD_Groups_Tier2 = @($AD_Groups_Catalog | Where-Object { $_.Tier -eq 2 } | ForEach-Object { [string]$_.Name } | Where-Object { $_ })
$AD_Groups_Tier3 = @($AD_Groups_Catalog | Where-Object { $_.Tier -eq 3 } | ForEach-Object { [string]$_.Name } | Where-Object { $_ })

# --- Azure role lists per tier (built-in + custom merged, property name is Name) ---
$Azure_Roles_Tier0 = @(
    @(Expand-TierSection $tierDefs.Azure_BuiltInRoles_Tier0) + @(Expand-TierSection $tierDefs.Azure_CustomRoles_Tier0) |
    ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique
)
$Azure_Roles_Tier1 = @(
    @(Expand-TierSection $tierDefs.Azure_BuiltInRoles_Tier1) + @(Expand-TierSection $tierDefs.Azure_CustomRoles_Tier1) |
    ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique
)
$Azure_Roles_Tier2 = @(
    @(Expand-TierSection $tierDefs.Azure_BuiltInRoles_Tier2) + @(Expand-TierSection $tierDefs.Azure_CustomRoles_Tier2) |
    ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique
)
$Azure_Roles_Tier3 = @(
    @(Expand-TierSection $tierDefs.Azure_BuiltInRoles_Tier3) + @(Expand-TierSection $tierDefs.Azure_CustomRoles_Tier3) |
    ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique
)

Write-Host "[OK]   Tier definitions loaded:" -ForegroundColor Green
Write-Host "         EntraID roles  T0/T1/T2/T3 : $($EntraID_Roles_Tier0.Count) / $($EntraID_Roles_Tier1.Count) / $($EntraID_Roles_Tier2.Count) / $($EntraID_Roles_Tier3.Count)" -ForegroundColor Green
Write-Host "         EntraID perms  T0/T1/T2/T3 : $($EntraID_APIPerms_Tier0.Count) / $($EntraID_APIPerms_Tier1.Count) / $($EntraID_APIPerms_Tier2.Count) / $($EntraID_APIPerms_Tier3.Count)" -ForegroundColor Green
Write-Host "         AD groups      T0/T1/T2/T3 : $($AD_Groups_Tier0.Count) / $($AD_Groups_Tier1.Count) / $($AD_Groups_Tier2.Count) / $($AD_Groups_Tier3.Count)" -ForegroundColor Green
Write-Host "         Azure roles    T0/T1/T2/T3 : $($Azure_Roles_Tier0.Count) / $($Azure_Roles_Tier1.Count) / $($Azure_Roles_Tier2.Count) / $($Azure_Roles_Tier3.Count)" -ForegroundColor Green
Write-Host "         Definitions date           : $($tierDefs.Metadata.GeneratedAt)" -ForegroundColor Green

# AD group memberships are sourced exclusively from the Exposure Graph (Advanced Hunting).
# AD_GroupMembership JSON snapshot is no longer used.

#########################################################################################################
# CONNECT TO MICROSOFT GRAPH
# Must run BEFORE the Exposure Graph / Advanced Hunting query below, which uses
# Invoke-MgGraphRequest. Kept here (not in the earlier auth block) so we have the
# $TenantId / $IngestionSpnClientId / $IngestionSpnClientSecret locals available.
#########################################################################################################

Write-Sep
Write-Step "Connecting to Microsoft Graph (token via REST)"
try {
    $tokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $IngestionSpnClientId
        client_secret = $IngestionSpnClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $tokenResponse = Invoke-RestMethod `
        -Method POST `
        -Uri    "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body   $tokenBody `
        -ContentType "application/x-www-form-urlencoded" `
        -ErrorAction Stop

    $script:graphToken = $tokenResponse.access_token
    Connect-MgGraph -AccessToken ($script:graphToken | ConvertTo-SecureString -AsPlainText -Force) -ErrorAction Stop | Out-Null
    Write-Ok "Graph connected"
} catch { Write-Err2 "Graph connect failed: $($_.Exception.Message)"; throw }

#########################################################################################################
# PRE-LOAD AD GROUP MEMBERSHIPS VIA EXPOSURE GRAPH (ADVANCED HUNTING)
# Queries ExposureGraphEdges for "member of" edges between AD users and AD groups.
# UserObjectId is the Entra Object ID (NodeId) so it matches $user.id during user processing.
# Requires: ThreatHunting.Read.All permission on the SecurityInsight SPN.
# AD group memberships are sourced exclusively from here - no JSON snapshot fallback.
#########################################################################################################

Write-Sep
Write-Step "Loading AD group memberships via Exposure Graph (Advanced Hunting)"

$exposureAdMemberships = [System.Collections.Generic.List[object]]::new()   # flat list of {ObjectId, UPN, GroupName, Provider}

try {
    # Return all user->AD-group "member of" edges, filter client-side against catalog.
    # UserObjectId = NodeId (Entra Object ID) so it matches $user.id during user processing.
    $huntingQuery = @"
ExposureGraphEdges
| where EdgeLabel =~ "member of"
| where SourceNodeLabel =~ "user"
| where TargetNodeLabel =~ "group"
| project SourceNodeId, TargetNodeId
| join kind=inner (
    ExposureGraphNodes
    | where NodeLabel =~ "group"
    | extend GroupProvider = tostring(NodeProperties.rawData.primaryProvider)
    | where GroupProvider =~ "ActiveDirectory"
    | project TargetNodeId = NodeId, GroupName = NodeName, GroupProvider
) on TargetNodeId
| join kind=inner (
    ExposureGraphNodes
    | where NodeLabel =~ "user"
    | extend UserUPN = tostring(NodeProperties.rawData.accountUpn)
    | project SourceNodeId = NodeId, UserUPN, UserDisplayName = NodeName, UserObjectId = NodeId
) on SourceNodeId
| project UserObjectId, UserUPN, UserDisplayName, GroupName, GroupProvider
| order by UserUPN asc
"@

    $huntingBody   = @{ Query = $huntingQuery } | ConvertTo-Json -Compress
    $huntingResp   = Invoke-MgGraphRequest `
                         -Method POST `
                         -Uri    "https://graph.microsoft.com/v1.0/security/runHuntingQuery" `
                         -Body   $huntingBody `
                         -ContentType "application/json" `
                         -ErrorAction Stop

    $huntingResults = $huntingResp['results']
    if (-not $huntingResults) { $huntingResults = $huntingResp.results }

    $totalRows = @($huntingResults).Count
    Write-Info "Exposure Graph raw results: $totalRows rows"

    if ($totalRows -gt 0) {
        # Show first row for diagnostics
        $firstRow = @($huntingResults)[0]
        $sampleOid   = if ($firstRow -is [System.Collections.IDictionary]) { [string]$firstRow['UserObjectId'] } else { [string]$firstRow.UserObjectId }
        $sampleUpn   = if ($firstRow -is [System.Collections.IDictionary]) { [string]$firstRow['UserUPN']       } else { [string]$firstRow.UserUPN       }
        $sampleGroup = if ($firstRow -is [System.Collections.IDictionary]) { [string]$firstRow['GroupName']     } else { [string]$firstRow.GroupName     }
        $sampleProv  = if ($firstRow -is [System.Collections.IDictionary]) { [string]$firstRow['GroupProvider'] } else { [string]$firstRow.GroupProvider }
        $sampleKeys  = if ($firstRow -is [System.Collections.IDictionary]) { ($firstRow.Keys -join ', ') } else { ($firstRow.PSObject.Properties | ForEach-Object { $_.Name }) -join ', ' }
        Write-Info "  Sample row keys: $sampleKeys"
        Write-Info "  Sample: UserObjectId=$sampleOid UPN=$sampleUpn Group=$sampleGroup Provider=$sampleProv"

        foreach ($row in $huntingResults) {
            $userObjectId  = if ($row -is [System.Collections.IDictionary]) { [string]$row['UserObjectId']  } else { [string]$row.UserObjectId  }
            $userUpn       = if ($row -is [System.Collections.IDictionary]) { [string]$row['UserUPN']       } else { [string]$row.UserUPN       }
            $groupName     = if ($row -is [System.Collections.IDictionary]) { [string]$row['GroupName']     } else { [string]$row.GroupName     }
            $groupProvider = if ($row -is [System.Collections.IDictionary]) { [string]$row['GroupProvider'] } else { [string]$row.GroupProvider }
            if (-not $groupName) { continue }
            # Only store rows where the group exists in the tier catalog
            if (-not $AD_Groups_CatalogLookup.ContainsKey($groupName.ToLower())) { continue }
            $exposureAdMemberships.Add([ordered]@{
                ObjectId  = $userObjectId.ToLower()
                UPN       = $userUpn.ToLower()
                GroupName = $groupName
                Provider  = $groupProvider
            })
        }
        Write-Ok "Exposure Graph AD group memberships loaded: $($exposureAdMemberships.Count) catalog-relevant (of $totalRows total AD group edges)"
        if ($exposureAdMemberships.Count -eq 0) {
            Write-Warn "  No rows matched the tier catalog - sample group names from query:"
            @($huntingResults)[0..([Math]::Min(4, $totalRows-1))] | ForEach-Object {
                $gn = if ($_ -is [System.Collections.IDictionary]) { $_['GroupName'] } else { $_.GroupName }
                Write-Info "    GroupName='$gn' | InCatalog=$($AD_Groups_CatalogLookup.ContainsKey([string]$gn.ToLower()))"
            }
            Write-Info "  Catalog sample (first 5): $(($AD_Groups_CatalogLookup.Keys | Select-Object -First 5) -join ', ')"
        }
    } else {
        Write-Warn "Exposure Graph returned no results - AD tier will be null for all users"
    }
} catch {
    Write-Warn "Exposure Graph query failed - AD tier will be null for all users: $($_.Exception.Message)"
    Write-Warn "Ensure ThreatHunting.Read.All permission is granted to the SecurityInsight SPN"
}




#########################################################################################################
# CONTEXT + MODULE
#########################################################################################################

if ($TroubleshootingMode) {
    Write-Host ""
    Write-Host (" TROUBLESHOOTING MODE ON - collections limited to $TroubleshootingLimit users, $TroubleshootingLimit SPNs/MIs, $TroubleshootingLimit subscriptions ") -ForegroundColor Black -BackgroundColor Yellow
    Write-Host ""
}

Write-Sep
Write-Step "Setting Azure subscription context"

# Subscription priority:
#   1. Explicit $global:SubscriptionId (community customer sets it; AF derives from
#      $global:MainLogAnalyticsWorkspaceSubId via Initialize-LauncherConfig)
#   2. Parsed from $WorkspaceResourceId if it's a full ARM ID
#   3. Current Az context (fallback)
if (-not [string]::IsNullOrWhiteSpace([string]$global:SubscriptionId)) {
    $WorkspaceSubscriptionId = [string]$global:SubscriptionId
} elseif (-not [string]::IsNullOrWhiteSpace($WorkspaceResourceId) -and $WorkspaceResourceId -match '/subscriptions/([^/]+)/') {
    $WorkspaceSubscriptionId = $Matches[1]
} else {
    try { $WorkspaceSubscriptionId = (Get-AzContext -ErrorAction Stop).Subscription.Id } catch { $WorkspaceSubscriptionId = $null }
    if (-not $WorkspaceSubscriptionId) { throw "Cannot determine subscription -- set `$global:SubscriptionId, provide WorkspaceResourceId, or ensure an Az context." }
}
try {
    Set-AzContext -SubscriptionId $WorkspaceSubscriptionId -TenantId $TenantId -ErrorAction Stop | Out-Null
    Write-Ok "Context set - subscription: $WorkspaceSubscriptionId"
} catch { Write-Err2 "Set-AzContext failed: $($_.Exception.Message)"; throw }

# Build global DCE/DCR cache + self-heal: create Workspace + DCE + DCR RG if missing, assign RBAC.
# Logic lives in the shared helper (same pattern as Step2_OnboardValidate-SecurityInsight-LogAnalytics.ps1).
. (Join-Path $PSScriptRoot '_shared\Ensure-SecurityInsightInfra.ps1')
Write-Step "Ensuring SecurityInsight Workspace/DCE/DCR infra (auto-provisions if missing)"
try {
    # Resolve SecurityInsight SPN ObjectId -- needed for RBAC assignments on auto-created resources
    $spnObj = Get-AzADServicePrincipal -ApplicationId $IngestionSpnClientId -ErrorAction SilentlyContinue
    $spnObjectId = if ($spnObj) { [string]$spnObj.Id } else { $null }
    if (-not $spnObjectId) {
        Write-Warn "Could not resolve SecurityInsight SPN ObjectId -- RBAC assignments will be skipped on auto-create"
    }

    # Derive location: explicit global > workspace RG location > default
    $Location = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Location)) { [string]$global:SI_Location }
                elseif (-not [string]::IsNullOrWhiteSpace([string]$global:Location)) { [string]$global:Location }
                else {
                    $__wsLoc = $null
                    try { $__wsLoc = (Get-AzResourceGroup -Name $WorkspaceResourceGroup -ErrorAction Stop).Location } catch { }
                    if ($__wsLoc) { $__wsLoc } else { 'westeurope' }
                }

    # Resolve workspace: prefer ResourceId; else look up by name; else auto-create
    $WorkspaceResourceId = Ensure-SecurityInsightWorkspace `
                              -WorkspaceResourceId     $WorkspaceResourceId `
                              -WorkspaceName           $WorkspaceName `
                              -WorkspaceResourceGroup  $WorkspaceResourceGroup `
                              -Location                $Location `
                              -SubscriptionId          $WorkspaceSubscriptionId `
                              -IngestionSpnObjectId    $spnObjectId

    # Re-extract subscription from the resolved workspace (may differ if name-lookup
    # picked up a workspace in a different sub than the initial context).
    if ($WorkspaceResourceId -match '/subscriptions/([^/]+)/') {
        $WorkspaceSubscriptionId = $Matches[1]
        Set-AzContext -SubscriptionId $WorkspaceSubscriptionId -TenantId $TenantId -ErrorAction Stop | Out-Null
    }

    # Ensure DCE exists (creates RG + DCE + assigns RBAC if missing)
    $null = Ensure-SecurityInsightDce `
                    -DceName              $DceName `
                    -DceResourceGroup     $DceResourceGroup `
                    -Location             $Location `
                    -SubscriptionId       $WorkspaceSubscriptionId `
                    -TenantId             $TenantId `
                    -AzAppId              $IngestionSpnClientId `
                    -AzAppSecret          $IngestionSpnClientSecret `
                    -IngestionSpnObjectId $spnObjectId

    # Ensure DCR RG exists + SPN has RBAC there (DCR itself is created by CheckCreateUpdate-TableDcr-Structure)
    $null = Ensure-SecurityInsightRg `
                    -ResourceGroup        $DcrResourceGroup `
                    -Location             $Location `
                    -SubscriptionId       $WorkspaceSubscriptionId `
                    -IngestionSpnObjectId $spnObjectId

    Write-Ok "WorkspaceResourceId: $WorkspaceResourceId"
    Write-Ok "DCE entries: $(($global:AzDceDetails | Measure-Object).Count) | DCR entries: $(($global:AzDcrDetails | Measure-Object).Count)"
} catch { Write-Err2 "Workspace/DCE/DCR infra build failed: $($_.Exception.Message)"; throw }

#########################################################################################################
# LOAD IDENTITYINFO FROM SENTINEL (MDI enrichment - AD groups, risk, SIDs, location)
# Queried once, stored as hashtable keyed by AccountObjectId for O(1) per-user lookup
#########################################################################################################

Write-Sep
Write-Step "Loading tenant verified domains"

# All verified domains in the tenant (includes all AD UPN suffixes, custom domains, onmicrosoft.com)
# Used to distinguish internal users from cross-tenant guests/B2B users
$tenantVerifiedDomains = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
try {
    $orgInfo = Invoke-Graph -Uri "$GRAPH_BASE/organization?`$select=verifiedDomains"
    $orgObj  = if ($orgInfo -is [System.Collections.IDictionary]) { $orgInfo['value'] } else { $orgInfo.value }
    if ($orgObj) {
        $org = if ($orgObj -is [System.Array]) { $orgObj[0] } else { $orgObj }
        $vd  = if ($org -is [System.Collections.IDictionary]) { $org['verifiedDomains'] } else { $org.verifiedDomains }
        if ($vd) {
            foreach ($d in $vd) {
                $dn = if ($d -is [System.Collections.IDictionary]) { [string]$d['name'] } else { [string]$d.name }
                if ($dn) { $tenantVerifiedDomains.Add($dn) | Out-Null }
            }
        }
    }
    Write-Ok "Tenant verified domains ($($tenantVerifiedDomains.Count)): $($tenantVerifiedDomains -join ', ')"
} catch {
    Write-Warn "Could not load verified domains: $($_.Exception.Message) - falling back to TenantDomain variable"
    $tenantVerifiedDomains.Add($TenantDomain) | Out-Null
}

Write-Sep
Write-Step "Loading IdentityInfo from Log Analytics workspace"

# Workspace routing:
#   SI_IdentityAssets_CL is always ingested into WorkspaceResourceId.
#   IdentityInfo and sign-in logs live in a SEPARATE workspace (Defender/Sentinel).
#   If DefenderWorkspaceResourceId is set -> query that workspace for IdentityInfo + sign-in logs.
#   If not set -> IdentityInfo and sign-in logs are in the same workspace as SI_IdentityAssets_CL.

$identityInfoLookup  = @{}
$isCrossWorkspace    = -not [string]::IsNullOrWhiteSpace($DefenderWorkspaceResourceId)

# Helper: resolve workspace GUID from resource ID.
# Uses ARM REST directly so we work even when the workspace lives in a
# different Az subscription than the SPN's current context (typical when the
# SI ingestion sub differs from the Defender/Sentinel sub). The resource ID
# already contains the subscription, so we never need to Set-AzContext.
function Get-WorkspaceGuid ([string]$ResourceId) {
    if ($ResourceId -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/[^/]+/workspaces/[^/]+$') {
        throw "Cannot parse workspace resource ID: $ResourceId"
    }
    $resp = Invoke-AzRestMethod -Method GET -Uri "https://management.azure.com$ResourceId`?api-version=2022-10-01" -ErrorAction Stop
    if ($resp.StatusCode -ne 200) {
        throw ("ARM lookup of workspace failed (HTTP {0}): {1}" -f $resp.StatusCode, $resp.Content)
    }
    $obj = $resp.Content | ConvertFrom-Json
    if (-not $obj.properties.customerId) {
        throw "Workspace ARM response missing properties.customerId for: $ResourceId"
    }
    return [string]$obj.properties.customerId
}

# Resolve the workspace GUID where IdentityInfo lives
$identityInfoSourceWorkspace = if ($isCrossWorkspace) { $DefenderWorkspaceResourceId } else { $WorkspaceResourceId }
Write-Info "$(if ($isCrossWorkspace) { 'Defender/Sentinel workspace (separate)' } else { 'Same workspace as SI_IdentityAssets_CL' }): $identityInfoSourceWorkspace"

try {
    $queryEndpointGuid = Get-WorkspaceGuid -ResourceId $identityInfoSourceWorkspace

    $kqlQuery = @"
IdentityInfo
| where TimeGenerated > ago($($IdentityInfoLookbackDays)d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| project
    AccountObjectId, AccountUPN, AccountDisplayName, AccountName, SAMAccountName, AccountDomain,
    AccountSID, AccountCloudSID, AccountTenantId,
    OnPremisesAccountObjectId, OnPremisesDistinguishedName,
    GivenName, Surname, MailAddress, Phone, City, State, Country, StreetAddress, CompanyName,
    Department, JobTitle, EmployeeId, Manager,
    IsAccountEnabled, IsMFARegistered, IsServiceAccount,
    UserType, UserState, UserAccountControl, UACFlags,
    AccountCreationTime, DeletedDateTime, LastSeenDate,
    SourceSystem, UserStateChangedOn,
    GroupMembership, AssignedRoles,
    BlastRadius, Tags,
    InvestigationPriority, InvestigationPriorityPercentile,
    RiskLevel, RiskLevelDetails, RiskState, EntityRiskScore,
    OnPremisesExtensionAttributes
"@

    $kqlBody = @{ query = $kqlQuery } | ConvertTo-Json -Compress
    $lawResp = Invoke-AzRestMethod `
        -Method  POST `
        -Uri     "https://api.loganalytics.io/v1/workspaces/$queryEndpointGuid/query" `
        -Payload $kqlBody `
        -ErrorAction Stop

    if ($lawResp.StatusCode -ne 200) {
        throw "Query returned HTTP $($lawResp.StatusCode): $($lawResp.Content)"
    }

    $lawResult = $lawResp.Content | ConvertFrom-Json

    # Parse column names + rows into hashtable
    $cols     = @($lawResult.tables[0].columns | ForEach-Object { $_.name })
    $colCount = $cols.Count
    foreach ($row in $lawResult.tables[0].rows) {
        $rowArr = @($row)
        $entry  = [ordered]@{}
        for ($c = 0; $c -lt $colCount; $c++) {
            $entry[$cols[$c]] = if ($c -lt $rowArr.Count) { $rowArr[$c] } else { $null }
        }
        $oid = [string]$entry['AccountObjectId']
        if ($oid) { $identityInfoLookup[$oid] = $entry }
    }
    $modeLabel = if ($isCrossWorkspace) { "Defender workspace" } else { "same workspace" }
    Write-Ok "IdentityInfo loaded ($modeLabel): $($identityInfoLookup.Count) identities | columns: $colCount"

    # Diagnostic: dump columns and first entry to verify parsing
    Write-Info "IdentityInfo columns: $($cols -join ', ')"
    if ($identityInfoLookup.Count -gt 0) {
        $sampleKey   = @($identityInfoLookup.Keys)[0]
        $sampleEntry = $identityInfoLookup[$sampleKey]
        Write-Info "Sample entry ($sampleKey):"
        Write-Info "  AccountDomain     : $($sampleEntry['AccountDomain'])"
        Write-Info "  SAMAccountName    : $($sampleEntry['SAMAccountName'])"
        Write-Info "  OnPremDN          : $($sampleEntry['OnPremisesDistinguishedName'])"
        Write-Info "  OnPremObjectId    : $($sampleEntry['OnPremisesAccountObjectId'])"
        $gmSample = $sampleEntry['GroupMembership']
        Write-Info "  GroupMembership type: $($gmSample.GetType().FullName)"
        Write-Info "  GroupMembership raw : $($gmSample | ConvertTo-Json -Compress -Depth 3)"
    }
} catch {
    Write-Warn "IdentityInfo query failed - AD enrichment will be empty: $($_.Exception.Message)"
    $hint = if ($isCrossWorkspace) { "Log Analytics Reader on the Defender/Sentinel workspace ($DefenderWorkspaceResourceId)" } else { "Log Analytics Reader on $WorkspaceResourceId" }
    Write-Warn "Ensure the SecurityInsight SPN has $hint"
}

#########################################################################################################
# LOAD SPN / MI LAST SIGN-IN FROM SENTINEL SIGN-IN LOG TABLES
# AADServicePrincipalSignInLogs  - SPNs using client secret/cert
# AADManagedIdentitySignInLogs   - Managed Identities
# Keyed by ServicePrincipalId for O(1) lookup per SP
#########################################################################################################

Write-Sep
Write-Step "Loading SPN/MI last sign-in data from Log Analytics (Entra ID)"

# Sign-in logs (AADServicePrincipalSignInLogs / AADManagedIdentitySignInLogs) live in the
# Sentinel/Defender workspace - same cross-workspace logic as IdentityInfo.
# Cross-workspace mode: query DefenderWorkspaceResourceId  (where sign-in logs are)
# Same-workspace mode : query WorkspaceResourceId          (sign-in logs co-located)

$spnSignInLookup = @{}

try {
    # Sign-in logs live in the same workspace as IdentityInfo
    Write-Info "SPN sign-in: querying $identityInfoSourceWorkspace"
    $signInWorkspaceGuid = Get-WorkspaceGuid -ResourceId $identityInfoSourceWorkspace

    $spnSignInQuery = @"
// AADServicePrincipalSignInLogs - SPNs authenticating with client secret or certificate
let SPNSignIn = AADServicePrincipalSignInLogs
    | where TimeGenerated > ago($($SpnSignInLookbackDays)d)
    | where ResultType == 0
    | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId;
// AADManagedIdentitySignInLogs - Managed Identity token acquisitions
// Note: ResultType is always 0 for MI logs, no filter needed
let MISignIn = AADManagedIdentitySignInLogs
    | where TimeGenerated > ago($($SpnSignInLookbackDays)d)
    | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId;
// Combine and take most recent per principal
SPNSignIn
| union MISignIn
| summarize LastSignIn = max(LastSignIn) by ServicePrincipalId
"@

    $spnSignInBody = @{ query = $spnSignInQuery } | ConvertTo-Json -Compress
    $spnSignInResp = Invoke-AzRestMethod `
        -Method  POST `
        -Uri     "https://api.loganalytics.io/v1/workspaces/$signInWorkspaceGuid/query" `
        -Payload $spnSignInBody `
        -ErrorAction Stop

    if ($spnSignInResp.StatusCode -eq 200) {
        $spnSignInResult = $spnSignInResp.Content | ConvertFrom-Json
        $spnCols     = @($spnSignInResult.tables[0].columns | ForEach-Object { $_.name })
        $spnColCount = $spnCols.Count
        foreach ($row in $spnSignInResult.tables[0].rows) {
            $rowArr = @($row)
            $entry  = [ordered]@{}
            for ($c = 0; $c -lt $spnColCount; $c++) {
                $entry[$spnCols[$c]] = if ($c -lt $rowArr.Count) { $rowArr[$c] } else { $null }
            }
            $spId = [string]$entry['ServicePrincipalId']
            if ($spId) { $spnSignInLookup[$spId] = $entry }
        }
        Write-Ok "SPN/MI sign-in data loaded: $($spnSignInLookup.Count) identities with sign-in records"
    } else {
        Write-Warn "SPN/MI sign-in query returned HTTP $($spnSignInResp.StatusCode)"
    }
} catch {
    Write-Warn "SPN/MI sign-in query failed: $($_.Exception.Message)"
    Write-Warn "Ensure the SecurityInsight SPN has Log Analytics Reader on $identityInfoSourceWorkspace"
}
#########################################################################################################

Write-Sep
Write-Step "Building Graph permission lookup table"

$roleLookup = @{}
try {
    # The Microsoft Graph SP object id varies per tenant - discover it via search first
    $graphSpSearch = Invoke-RestMethod `
        -Method  GET `
        -Uri     "$GRAPH_BASE/servicePrincipals?`$search=`"displayName:Microsoft Graph`"&`$select=id,displayName&`$top=20" `
        -Headers @{ "Authorization" = "Bearer $script:graphToken"; "Content-Type" = "application/json"; "ConsistencyLevel" = "eventual" } `
        -ErrorAction Stop

    $graphSpId = $null

    # value may come back as array or as hashtable entries - handle both
    $spValues = @()
    if ($graphSpSearch -and $graphSpSearch['value']) {
        $spValues = @($graphSpSearch['value'])
    } elseif ($graphSpSearch -and $graphSpSearch.value) {
        $spValues = @($graphSpSearch.value)
    }

    Write-Info "Graph SP search returned $($spValues.Count) results"
    foreach ($sp in $spValues) {
        $spName = if ($sp -is [hashtable]) { $sp['displayName'] } else { $sp.displayName }
        $spId   = if ($sp -is [hashtable]) { $sp['id'] }          else { $sp.id }
        Write-Info "  SP: '$spName' ($spId)"
        if ($spName -eq "Microsoft Graph") {
            $graphSpId = $spId
            break
        }
    }

    if ($graphSpId) {
        Write-Info "Fetching appRoles for Graph SP id: $graphSpId"
        $graphSpFull  = Invoke-RestMethod `
            -Method  GET `
            -Uri     "$GRAPH_BASE/servicePrincipals/$graphSpId`?`$select=id,appRoles" `
            -Headers @{ "Authorization" = "Bearer $script:graphToken"; "Content-Type" = "application/json" } `
            -ErrorAction Stop

        $appRolesRaw = if ($graphSpFull -is [hashtable]) { $graphSpFull['appRoles'] } else { $graphSpFull.appRoles }
        if ($appRolesRaw) {
            foreach ($role in $appRolesRaw) {
                $rid = if ($role -is [hashtable]) { $role['id'] }    else { $role.id }
                $rv  = if ($role -is [hashtable]) { $role['value'] } else { $role.value }
                if ($rid -and $rv) { $roleLookup[$rid] = $rv }
            }
        }
    } else {
        Write-Warn "Microsoft Graph SP not found in search results"
    }
} catch {
    Write-Warn "Could not load Graph permission definitions: $($_.Exception.Message)"
}

if ($roleLookup.Count -eq 0) {
    Write-Warn "Graph permission definitions unavailable - app permissions will be stored as GUIDs"
} else {
    Write-Ok "Loaded $($roleLookup.Count) Graph permission definitions"
}

#########################################################################################################
# PRE-LOAD SPN PERMISSIONS IN BULK
# Replaces 2 Graph calls per SP with a single bulk fetch + O(1) hashtable lookup.
# spAppRoleLookup  : spId -> [appRole names]
# spDelegatedLookup: spId -> [delegated scope strings]
#########################################################################################################

Write-Sep
Write-Step "Pre-loading SPN appRoleAssignments in bulk (via appRoleAssignedTo per resource SP)"

$spAppRoleLookup   = @{}
$spDelegatedLookup = @{}

# The correct bulk approach: query appRoleAssignedTo on each RESOURCE service principal.
# There are typically only a handful of resource SPs that grant app roles (Graph, SharePoint,
# Exchange, Intune etc.) - far fewer than the number of client SPs. This gives us all
# client->role mappings in O(resource SPs) calls instead of O(client SPs) calls.
try {
    # Fetch all SPs with id + appRoles, filter client-side to those with appRoles defined.
    # Avoids $filter=appRoles/$count which requires ConsistencyLevel:eventual and is
    # often rejected with BadRequest depending on tenant/Graph version.
    $allSPsForRoles = Get-AllPages -Uri "$GRAPH_BASE/servicePrincipals?`$select=id,displayName,appRoles&`$top=999"
    $resourceSPs    = @($allSPsForRoles | Where-Object {
        $ar = if ($_ -is [System.Collections.IDictionary]) { $_['appRoles'] } else { $_.appRoles }
        $ar -and @($ar).Count -gt 0
    })
    Write-Info "Resource SPs with appRoles: $($resourceSPs.Count) (of $($allSPsForRoles.Count) total)"

    $totalAssignments = 0
    foreach ($rsp in $resourceSPs) {
        $rspId = if ($rsp -is [System.Collections.IDictionary]) { [string]$rsp['id'] } else { [string]$rsp.id }
        if (-not $rspId) { continue }

        # Build roleId->name lookup for this resource SP's appRoles
        $localRoleLookup = @{}
        $appRolesRaw = if ($rsp -is [System.Collections.IDictionary]) { $rsp['appRoles'] } else { $rsp.appRoles }
        if ($appRolesRaw) {
            foreach ($role in $appRolesRaw) {
                $rid = if ($role -is [System.Collections.IDictionary]) { [string]$role['id'] }    else { [string]$role.id }
                $rv  = if ($role -is [System.Collections.IDictionary]) { [string]$role['value'] } else { [string]$role.value }
                if ($rid -and $rv) { $localRoleLookup[$rid] = $rv }
            }
        }
        if ($localRoleLookup.Count -eq 0) { continue }

        try {
            $assignments = Get-AllPages -Uri "$GRAPH_BASE/servicePrincipals/$rspId/appRoleAssignedTo"
            foreach ($a in $assignments) {
                $clientId   = if ($a -is [System.Collections.IDictionary]) { [string]$a['principalId'] } else { [string]$a.principalId }
                $roleId     = if ($a -is [System.Collections.IDictionary]) { [string]$a['appRoleId']   } else { [string]$a.appRoleId   }
                $clientType = if ($a -is [System.Collections.IDictionary]) { [string]$a['principalType'] } else { [string]$a.principalType }
                # Only index ServicePrincipal assignments (not User/Group)
                if (-not $clientId -or $clientType -ne 'ServicePrincipal') { continue }
                $roleName = if ($localRoleLookup.ContainsKey($roleId)) { $localRoleLookup[$roleId] }
                            elseif ($roleLookup.ContainsKey($roleId))  { $roleLookup[$roleId] }
                            else                                        { $roleId }
                if (-not $spAppRoleLookup.ContainsKey($clientId)) { $spAppRoleLookup[$clientId] = [System.Collections.Generic.List[string]]::new() }
                if (-not $spAppRoleLookup[$clientId].Contains($roleName)) { $spAppRoleLookup[$clientId].Add($roleName); $totalAssignments++ }
            }
        } catch {
            Write-Warn "  appRoleAssignedTo failed for SP $rspId : $($_.Exception.Message)"
        }
    }
    Write-Ok "SPN appRoleAssignments pre-loaded: $totalAssignments entries across $($spAppRoleLookup.Count) client principals"
} catch {
    Write-Warn "Bulk appRoleAssignments pre-load failed: $($_.Exception.Message)"
    Write-Warn "App permissions will be empty for this run - check Application.Read.All permission"
}

Write-Step "Pre-loading SPN oauth2PermissionGrants in bulk"

try {
    $allGrants = Get-AllPages -Uri "$GRAPH_BASE/oauth2PermissionGrants?`$filter=consentType eq 'AllPrincipals'"
    foreach ($g in $allGrants) {
        $spId  = if ($g -is [System.Collections.IDictionary]) { [string]$g['clientId'] } else { [string]$g.clientId }
        $scope = if ($g -is [System.Collections.IDictionary]) { [string]$g['scope']    } else { [string]$g.scope    }
        if (-not $spId -or -not $scope) { continue }
        foreach ($s in ($scope -split '\s+' | Where-Object { $_ })) {
            if (-not $spDelegatedLookup.ContainsKey($spId)) { $spDelegatedLookup[$spId] = [System.Collections.Generic.List[string]]::new() }
            if (-not $spDelegatedLookup[$spId].Contains($s)) { $spDelegatedLookup[$spId].Add($s) }
        }
    }
    Write-Ok "SPN oauth2PermissionGrants pre-loaded: $($allGrants.Count) grants across $($spDelegatedLookup.Count) principals"
} catch {
    Write-Warn "Bulk oauth2PermissionGrants pre-load failed: $($_.Exception.Message)"
}

#########################################################################################################
# LOAD ENTRA ROLE DEFINITIONS
#########################################################################################################

Write-Step "Loading Entra directory role definitions"

$roleDefLookup = @{}

# Use the Graph PS module cmdlet - uses the existing Connect-MgGraph session,
# bypasses Invoke-RestMethod token/URL issues entirely, handles paging via -All.
try {
    $roleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All -Property Id,DisplayName -ErrorAction Stop
    foreach ($r in $roleDefs) {
        if ($r.Id -and $r.DisplayName) { $roleDefLookup[[string]$r.Id] = [string]$r.DisplayName }
    }
} catch {
    Write-Warn "Could not load role definitions: $($_.Exception.Message)"
}
Write-Ok "Loaded $($roleDefLookup.Count) role definitions"

#########################################################################################################
# BUILD GROUP ROLE CACHE
# Pre-load all role assignments and eligibility schedules where the principal is a group.
# This avoids per-user Graph calls for group role resolution - O(1) lookup per group instead.
#
# $groupPermanentRoles  = @{ groupId = @("Role A", "Role B") }
# $groupEligibleRoles   = @{ groupId = @("Role C") }
#########################################################################################################

Write-Sep
Write-Step "Building group role cache (permanent + PIM eligible)"

$groupPermanentRoles = @{}
$groupEligibleRoles  = @{}

# Pre-load all group IDs to identify which role principals are groups
$allGroupIds = [System.Collections.Generic.HashSet[string]]::new()
try {
    $allGroups = Get-AllPages -Uri "$GRAPH_BASE/groups?`$select=id&`$top=999"
    foreach ($g in $allGroups) {
        $gId = if ($g -is [System.Collections.IDictionary]) { [string]$g['id'] } else { [string]$g.id }
        if ($gId) { $allGroupIds.Add($gId) | Out-Null }
    }
    Write-Ok "Loaded $($allGroupIds.Count) group IDs"
} catch {
    Write-Warn "Could not load group IDs: $($_.Exception.Message)"
}

# All permanent role assignments - using Get-Mg cmdlets (no filter needed, returns all)
$roleAssignmentGroupIds = [System.Collections.Generic.HashSet[string]]::new()
try {
    # RoleAssignmentSchedule covers active/permanent assignments (assigned state)
    $allActive = Get-AllPages -Uri "$GRAPH_BASE/roleManagement/directory/roleAssignmentSchedules?`$select=principalId,roleDefinitionId&`$top=999"
    foreach ($a in $allActive) {
        $principalId = if ($a -is [System.Collections.IDictionary]) { [string]$a['principalId'] } else { [string]$a.principalId }
        $rdId        = if ($a -is [System.Collections.IDictionary]) { [string]$a['roleDefinitionId'] } else { [string]$a.roleDefinitionId }
        if (-not $principalId -or -not $rdId) { continue }
        $roleName = if ($roleDefLookup.ContainsKey($rdId)) { $roleDefLookup[$rdId] } else { $rdId }
        if (-not $groupPermanentRoles.ContainsKey($principalId)) { $groupPermanentRoles[$principalId] = [System.Collections.Generic.List[string]]::new() }
        if (-not $groupPermanentRoles[$principalId].Contains($roleName)) { $groupPermanentRoles[$principalId].Add($roleName) }
        if ($allGroupIds.Contains($principalId)) { $roleAssignmentGroupIds.Add($principalId) | Out-Null }
    }
    Write-Ok "Role assignment schedules loaded: $($allActive.Count) entries | $($roleAssignmentGroupIds.Count) role-bearing groups"
} catch {
    Write-Warn "Could not load role assignment schedules: $($_.Exception.Message)"
}

# All PIM eligible role assignments
try {
    $allEligible = Get-AllPages -Uri "$GRAPH_BASE/roleManagement/directory/roleEligibilitySchedules?`$select=principalId,roleDefinitionId&`$top=999"
    foreach ($a in $allEligible) {
        $principalId = if ($a -is [System.Collections.IDictionary]) { [string]$a['principalId'] } else { [string]$a.principalId }
        $rdId        = if ($a -is [System.Collections.IDictionary]) { [string]$a['roleDefinitionId'] } else { [string]$a.roleDefinitionId }
        if (-not $principalId -or -not $rdId) { continue }
        $roleName = if ($roleDefLookup.ContainsKey($rdId)) { $roleDefLookup[$rdId] } else { $rdId }
        if (-not $groupEligibleRoles.ContainsKey($principalId)) { $groupEligibleRoles[$principalId] = [System.Collections.Generic.List[string]]::new() }
        if (-not $groupEligibleRoles[$principalId].Contains($roleName)) { $groupEligibleRoles[$principalId].Add($roleName) }
        if ($allGroupIds.Contains($principalId)) { $roleAssignmentGroupIds.Add($principalId) | Out-Null }
    }
    Write-Ok "PIM eligible schedules loaded: $($allEligible.Count) entries"
} catch {
    Write-Warn "Could not load PIM eligible schedules: $($_.Exception.Message)"
}

# PIM for Groups - iterate per role-bearing group using $filter=groupId (as per reference script)
$userPimGroupEligibility = @{}
Write-Info "Checking PIM for Groups on $($roleAssignmentGroupIds.Count) role-bearing groups ..."
$pimGroupCount   = 0
$pimGroupTotal   = $roleAssignmentGroupIds.Count
$pimGroupCounter = 0

foreach ($groupId in $roleAssignmentGroupIds) {
    $pimGroupCounter++
    $pimGroupPct = [int](($pimGroupCounter / $pimGroupTotal) * 100)
    Write-Progress -Id 4 -Activity "PIM for Groups - checking role-bearing groups" `
        -Status "$pimGroupCounter / $pimGroupTotal" `
        -PercentComplete $pimGroupPct
    # Eligible (not yet activated)
    try {
        $geList = Get-AllPages -Uri "$GRAPH_BASE/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq '$groupId'&`$select=principalId,groupId&`$top=999"
        foreach ($ge in $geList) {
            $principalId = if ($ge -is [System.Collections.IDictionary]) { [string]$ge['principalId'] } else { [string]$ge.principalId }
            $gid         = if ($ge -is [System.Collections.IDictionary]) { [string]$ge['groupId'] }     else { [string]$ge.groupId }
            if (-not $principalId -or -not $gid) { continue }
            if (-not $userPimGroupEligibility.ContainsKey($principalId)) { $userPimGroupEligibility[$principalId] = [System.Collections.Generic.List[string]]::new() }
            if (-not $userPimGroupEligibility[$principalId].Contains($gid)) { $userPimGroupEligibility[$principalId].Add($gid); $pimGroupCount++ }
        }
    } catch {}

    # Active (already activated)
    try {
        $gaList = Get-AllPages -Uri "$GRAPH_BASE/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=groupId eq '$groupId'&`$select=principalId,groupId&`$top=999"
        foreach ($ga in $gaList) {
            $principalId = if ($ga -is [System.Collections.IDictionary]) { [string]$ga['principalId'] } else { [string]$ga.principalId }
            $gid         = if ($ga -is [System.Collections.IDictionary]) { [string]$ga['groupId'] }     else { [string]$ga.groupId }
            if (-not $principalId -or -not $gid) { continue }
            if (-not $userPimGroupEligibility.ContainsKey($principalId)) { $userPimGroupEligibility[$principalId] = [System.Collections.Generic.List[string]]::new() }
            if (-not $userPimGroupEligibility[$principalId].Contains($gid)) { $userPimGroupEligibility[$principalId].Add($gid); $pimGroupCount++ }
        }
    } catch {}
}
Write-Progress -Id 4 -Activity "PIM for Groups - checking role-bearing groups" -Completed
Write-Ok "PIM for Groups loaded: $pimGroupCount entries across $($userPimGroupEligibility.Count) principals"

Write-Ok "Group role cache ready:"
Write-Ok "  Direct permanent role assignments : $($groupPermanentRoles.Count) principals"
Write-Ok "  Direct PIM eligible schedules     : $($groupEligibleRoles.Count) principals"
Write-Ok "  PIM for Groups (eligible+active)  : $($userPimGroupEligibility.Count) principals | $pimGroupCount group memberships"
Write-Ok "  Role-bearing groups identified    : $($roleAssignmentGroupIds.Count)"

#########################################################################################################
# PRE-LOAD USER GROUP MEMBERSHIPS (INVERTED transitiveMemberOf)
# Instead of calling /users/{id}/transitiveMemberOf per user (O(users) calls),
# call /groups/{id}/transitiveMembers per role-bearing group (O(groups) calls).
# On most tenants: hundreds of users vs dozens of role-bearing groups = 10-50x fewer API calls.
# userActiveGroupMembership: userId -> HashSet of groupIds the user actively belongs to
#########################################################################################################

Write-Sep
Write-Step "Pre-loading user group memberships via inverted transitiveMemberOf"

$userActiveGroupMembership = @{}
$ugmGroupCounter = 0
$ugmGroupTotal   = $roleAssignmentGroupIds.Count

foreach ($groupId in $roleAssignmentGroupIds) {
    $ugmGroupCounter++
    Write-Progress -Id 5 -Activity "Pre-loading user group memberships" `
        -Status "$ugmGroupCounter / $ugmGroupTotal groups" `
        -PercentComplete ([int](($ugmGroupCounter / [Math]::Max(1,$ugmGroupTotal)) * 100))

    try {
        $members = Get-AllPages -Uri "$GRAPH_BASE/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=id"
        foreach ($m in $members) {
            $uid = if ($m -is [System.Collections.IDictionary]) { [string]$m['id'] } else { [string]$m.id }
            if (-not $uid) { continue }
            if (-not $userActiveGroupMembership.ContainsKey($uid)) {
                $userActiveGroupMembership[$uid] = [System.Collections.Generic.HashSet[string]]::new()
            }
            $userActiveGroupMembership[$uid].Add($groupId) | Out-Null
        }
    } catch {
        Write-Warn "  Could not load members for group $groupId : $($_.Exception.Message)"
    }
}
Write-Progress -Id 5 -Activity "Pre-loading user group memberships" -Completed
Write-Ok "User group membership cache built: $($userActiveGroupMembership.Count) users with role-bearing group memberships"

#########################################################################################################
# HELPER: RESOLVE GROUP ROLES RECURSIVELY
# Traverses nested PIM for Groups chains to any depth, preventing infinite loops via $Visited
# User -> PIM Group A (eligible) -> PIM Group B (eligible) -> Role
#########################################################################################################

function Get-AllGroupRoles {
    param(
        [string[]]$GroupIds,
        [System.Collections.Generic.List[string]]$Permanent,
        [System.Collections.Generic.List[string]]$Eligible,
        [System.Collections.Generic.HashSet[string]]$Visited,
        [bool]$AsEligible,   # nested eligible groups always produce Eligible roles for the user
        # ReachableGroups accumulates every group ID traversed (PIM eligible chain).
        # Used by the caller to scope Azure RBAC delegation lookups to inherited groups.
        [System.Collections.Generic.HashSet[string]]$ReachableGroups = $null
    )

    $addIfNew = {
        param($list, $val)
        if ($val -and -not $list.Contains($val)) { $list.Add($val) }
    }

    foreach ($groupId in $GroupIds) {
        if ($Visited.Contains($groupId)) { continue }
        $Visited.Add($groupId) | Out-Null
        if ($null -ne $ReachableGroups) { $ReachableGroups.Add($groupId) | Out-Null }

        # Roles directly assigned to this group
        if ($AsEligible) {
            if ($groupPermanentRoles.ContainsKey($groupId)) {
                foreach ($r in $groupPermanentRoles[$groupId]) { & $addIfNew $Eligible $r }
            }
        } else {
            if ($groupPermanentRoles.ContainsKey($groupId)) {
                foreach ($r in $groupPermanentRoles[$groupId]) { & $addIfNew $Permanent $r }
            }
        }
        if ($groupEligibleRoles.ContainsKey($groupId)) {
            foreach ($r in $groupEligibleRoles[$groupId]) { & $addIfNew $Eligible $r }
        }

        # Recurse into nested PIM for Groups memberships of this group
        if ($userPimGroupEligibility.ContainsKey($groupId)) {
            $nested = @($userPimGroupEligibility[$groupId] | Where-Object { -not $Visited.Contains($_) })
            if ($nested.Count -gt 0) {
                Get-AllGroupRoles -GroupIds $nested -Permanent $Permanent -Eligible $Eligible `
                    -Visited $Visited -AsEligible $true -ReachableGroups $ReachableGroups
            }
        }
    }
}

#########################################################################################################
# HELPER: GET PRINCIPAL ROLES (uses pre-built global cache + recursive group nesting)
#
# Resolution chain:
#   1. Direct permanent + eligible roles from cache (direct assignments on the principal)
#   2. transitiveMemberOf -> all active group memberships (Graph resolves active nesting)
#      -> cache lookup per group -> Permanent
#   3. PIM for Groups eligible memberships -> recursive expansion via Get-AllGroupRoles
#      User -> PIM Group A -> PIM Group B -> ... -> Role  (any depth, loop-safe)
#########################################################################################################

function Get-PrincipalRoles ([string]$ObjectId) {
    $permanent       = [System.Collections.Generic.List[string]]::new()
    $eligible        = [System.Collections.Generic.List[string]]::new()
    $visited         = [System.Collections.Generic.HashSet[string]]::new()
    # Collects every group the principal can reach via active membership OR PIM eligible chain.
    # Includes both active transitive groups and all groups traversed by Get-AllGroupRoles.
    # Used to scope Azure RBAC delegation lookups to inherited groups.
    $reachableGroups = [System.Collections.Generic.HashSet[string]]::new()

    $addIfNew = {
        param($list, $val)
        if ($val -and -not $list.Contains($val)) { $list.Add($val) }
    }

    # 1. Direct permanent + eligible roles
    if ($groupPermanentRoles.ContainsKey($ObjectId)) {
        foreach ($r in $groupPermanentRoles[$ObjectId]) { & $addIfNew $permanent $r }
    }
    if ($groupEligibleRoles.ContainsKey($ObjectId)) {
        foreach ($r in $groupEligibleRoles[$ObjectId]) { & $addIfNew $eligible $r }
    }

    # 2. Active group memberships via pre-loaded inverted membership cache (no per-user API call)
    $activeGroupIds = [System.Collections.Generic.List[string]]::new()
    if ($userActiveGroupMembership.ContainsKey($ObjectId)) {
        foreach ($gid in $userActiveGroupMembership[$ObjectId]) {
            $activeGroupIds.Add($gid)
            $visited.Add($gid)         | Out-Null
            $reachableGroups.Add($gid) | Out-Null
        }
    }

    foreach ($groupId in $activeGroupIds) {
        if ($groupPermanentRoles.ContainsKey($groupId)) {
            foreach ($r in $groupPermanentRoles[$groupId]) { & $addIfNew $permanent $r }
        }
        if ($groupEligibleRoles.ContainsKey($groupId)) {
            foreach ($r in $groupEligibleRoles[$groupId]) { & $addIfNew $eligible $r }
        }
    }

    # 3. PIM for Groups eligible memberships - recursive nested group expansion.
    # ReachableGroups is populated as the traversal proceeds so Azure RBAC
    # assignments on any group in the eligible chain are included.
    if ($userPimGroupEligibility.ContainsKey($ObjectId)) {
        $eligibleGroupIds = @($userPimGroupEligibility[$ObjectId] | Where-Object { -not $visited.Contains($_) })
        if ($eligibleGroupIds.Count -gt 0) {
            Get-AllGroupRoles -GroupIds $eligibleGroupIds -Permanent $permanent -Eligible $eligible `
                -Visited $visited -AsEligible $true -ReachableGroups $reachableGroups
        }
    }

    $permArr = @($permanent | Select-Object -Unique)
    $eligArr = @($eligible  | Select-Object -Unique)
    return @{
        Permanent       = $permArr
        Eligible        = $eligArr
        All             = @($permArr + $eligArr | Select-Object -Unique)
        ReachableGroups = @($reachableGroups)   # all active + PIM-eligible group IDs
    }
}

#########################################################################################################
# HELPER: GET SPN PERMISSIONS
#########################################################################################################

function Get-SPNPermissions ([string]$SpId) {
    # O(1) lookup into pre-built bulk caches (populated in pre-load phase below)
    $appPerms  = if ($spAppRoleLookup.ContainsKey($SpId))   { @($spAppRoleLookup[$SpId])   } else { @() }
    $delegated = if ($spDelegatedLookup.ContainsKey($SpId)) { @($spDelegatedLookup[$SpId]) } else { @() }
    return @{
        App       = $appPerms
        Delegated = $delegated
        All       = @($appPerms + $delegated | Select-Object -Unique)
    }
}

#########################################################################################################
# HELPER: GET CSA TAGS
#########################################################################################################

function Get-CSATags {
    param(
        [string]$Endpoint,
        [string]$ObjectId,
        [object]$FromObject
    )

    $emptyResult = "{}"

    try {
        $obj = if ($FromObject) { $FromObject } else {
            Invoke-Graph -Uri "$GRAPH_BASE/$Endpoint/$ObjectId`?`$select=customSecurityAttributes"
        }
        if (-not $obj) { return $emptyResult }

        # Extract customSecurityAttributes block - handle hashtable or PSCustomObject
        $csaRaw = $null
        if ($obj -is [System.Collections.IDictionary]) {
            if ($obj.ContainsKey('customSecurityAttributes')) { $csaRaw = $obj['customSecurityAttributes'] }
        } else {
            $p = $obj.PSObject.Properties['customSecurityAttributes']
            if ($p) { $csaRaw = $p.Value }
        }
        if (-not $csaRaw) { return $emptyResult }

        # Helper: safely get value from hashtable or PSCustomObject
        $getVal = {
            param($o, $k)
            if ($o -is [System.Collections.IDictionary]) {
                if ($o.ContainsKey($k)) { return $o[$k] } else { return $null }
            } else {
                $p2 = $o.PSObject.Properties[$k]
                return if ($p2) { $p2.Value } else { $null }
            }
        }

        # Build result object with ALL attribute sets found
        $result = [ordered]@{}

        # Get all attribute set keys
        $keys = @()
        if ($csaRaw -is [System.Collections.IDictionary]) { $keys = @($csaRaw.Keys) }
        else { $keys = @($csaRaw.PSObject.Properties | ForEach-Object { $_.Name }) }

        foreach ($setName in $keys) {
            $setBlock = & $getVal $csaRaw $setName
            if (-not $setBlock) { continue }

            $setResult = [ordered]@{}
            $setKeys = @()
            if ($setBlock -is [System.Collections.IDictionary]) { $setKeys = @($setBlock.Keys) }
            else { $setKeys = @($setBlock.PSObject.Properties | ForEach-Object { $_.Name }) }

            foreach ($propName in $setKeys) {
                # Skip ALL OData annotation keys (e.g. AssetTagName@odata.type)
                if ($propName -like '*@odata*' -or $propName -like '@odata*') { continue }
                $val = & $getVal $setBlock $propName
                if ($val -is [System.Collections.IEnumerable] -and -not ($val -is [string])) {
                    $setResult[$propName] = @($val | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
                } else {
                    $setResult[$propName] = [string]$val
                }
            }
            if ($setResult.Count -gt 0) { $result[$setName] = $setResult }
        }

        if ($result.Count -eq 0) { return $emptyResult }
        return To-JsonStr $result

    } catch { return $emptyResult }
}

#########################################################################################################
# LOAD AZURE ROLE DELEGATIONS
# Enumerates Get-AzRoleAssignment per subscription - same pattern as PIM eligible schedules.
# Keyed by ObjectId for O(1) lookup per identity during user/SPN processing.
#########################################################################################################

Write-Sep
Write-Step "Loading Azure RBAC role delegations across all subscriptions"

$azureDelegationLookup = @{}
$azureDelegationCount  = 0

try {
    # Connect Az module
    $secureAzSecret = ConvertTo-SecureString $IngestionSpnClientSecret -AsPlainText -Force
    $azCred         = New-Object System.Management.Automation.PSCredential($IngestionSpnClientId, $secureAzSecret)
    Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $azCred -ErrorAction Stop | Out-Null
    Write-Ok "Az module connected"

    $subsAll = @(Get-AzSubscription -TenantId $TenantId -ErrorAction Stop | Where-Object { $_.State -eq "Enabled" })
    if ($SubscriptionNameExcludePatterns -and $SubscriptionNameExcludePatterns.Count -gt 0) {
        $excluded = @($subsAll | Where-Object { Test-SubscriptionExcluded -Name $_.Name -Patterns $SubscriptionNameExcludePatterns })
        $subscriptions = @($subsAll | Where-Object { -not (Test-SubscriptionExcluded -Name $_.Name -Patterns $SubscriptionNameExcludePatterns) })
        Write-Ok ("Subscriptions found: $($subscriptions.Count) (excluded $($excluded.Count) by SubscriptionNameExcludePatterns: " + (($excluded | ForEach-Object { $_.Name }) -join ', ') + ")")
    } else {
        $subscriptions = $subsAll
        Write-Ok "Subscriptions found: $($subscriptions.Count)"
    }

    if ($TroubleshootingMode) {
        $subscriptions = @($subscriptions | Select-Object -First $TroubleshootingLimit)
        Write-Warn "TROUBLESHOOTING MODE - limited to $TroubleshootingLimit subscriptions"
    }

    foreach ($sub in $subscriptions) {
        Set-AzContext -SubscriptionId $sub.Id -TenantId $TenantId -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        try {
            $assignments = @(Get-AzRoleAssignment -ErrorAction Stop -WarningAction SilentlyContinue)
            Write-Info "  Subscription '$($sub.Name)' ($($sub.Id)): $($assignments.Count) role assignments"

            foreach ($a in $assignments) {
                $principalId = [string]$a.ObjectId
                if ([string]::IsNullOrWhiteSpace($principalId)) { continue }

                $entry = [ordered]@{
                    RoleName         = [string]$a.RoleDefinitionName
                    Scope            = [string]$a.Scope
                    SubscriptionId   = [string]$sub.Id
                    SubscriptionName = [string]$sub.Name
                    PrincipalType    = [string]$a.ObjectType
                    PrincipalName    = [string]$a.DisplayName
                    Tier             = $null
                }

                # EffectiveTier = Max(RoleTier, ScopeLevel) - role risk modulated by scope breadth
                # Owner at tenant root = Tier 0; Owner at resource group = Tier 2
                $entry.RoleTier  = Get-TierFromAzureRoles -Roles @($entry.RoleName)
                if ($null -eq $entry.RoleTier) { $entry.RoleTier = 2 }
                $entry.ScopeLevel = Get-AzureScopeLevel -Scope $entry.Scope
                $entry.Tier       = Get-AzureEffectiveTier -RoleName $entry.RoleName -Scope $entry.Scope

                if (-not $azureDelegationLookup.ContainsKey($principalId)) {
                    $azureDelegationLookup[$principalId] = [System.Collections.Generic.List[object]]::new()
                }
                $azureDelegationLookup[$principalId].Add($entry)
                $azureDelegationCount++
            }
        } catch {
            Write-Warn "  Could not read role assignments for '$($sub.Name)': $($_.Exception.Message)"
        }
    }

    Write-Ok "Azure RBAC delegations loaded: $azureDelegationCount assignments across $($azureDelegationLookup.Count) unique principals"
} catch {
    Write-Warn "Azure delegation collection failed - Azure_Delegations will be empty: $($_.Exception.Message)"
    Write-Warn "Ensure the SecurityInsight SPN has Reader on subscriptions"
}

# Helper: build Azure_Delegations JSON for a given ObjectId.
# MemberIds: group IDs reachable via active membership or PIM eligible chains.
# Assignments on those groups are included and annotated with InheritedFromGroup=true.
function Get-AzureDelegationsJson ([string]$ObjectId, [string[]]$MemberIds = @()) {
    $entries = [System.Collections.Generic.List[object]]::new()

    # Direct assignments on the principal itself
    if ($azureDelegationLookup.ContainsKey($ObjectId)) {
        foreach ($e in $azureDelegationLookup[$ObjectId]) {
            $copy = [ordered]@{}
            foreach ($k in $e.Keys) { $copy[$k] = $e[$k] }
            $copy['InheritedFromGroup'] = $false
            $copy['InheritedGroupId']   = ""
            $entries.Add($copy)
        }
    }

    # Assignments inherited via active group memberships and PIM eligible chains
    foreach ($groupId in ($MemberIds | Where-Object { $_ -and $_ -ne $ObjectId })) {
        if (-not $azureDelegationLookup.ContainsKey($groupId)) { continue }
        foreach ($e in $azureDelegationLookup[$groupId]) {
            $copy = [ordered]@{}
            foreach ($k in $e.Keys) { $copy[$k] = $e[$k] }
            $copy['InheritedFromGroup'] = $true
            $copy['InheritedGroupId']   = $groupId
            $entries.Add($copy)
        }
    }

    if ($entries.Count -eq 0) { return '[]' }
    try { return ($entries.ToArray() | ConvertTo-Json -Depth 5 -Compress) }
    catch { return '[]' }
}

# Helper: get the minimum (highest-risk) Azure delegation tier for a given ObjectId
# For Groups: also aggregates delegations of all member ObjectIds passed in $MemberIds
function Get-AzureDelegationTier ([string]$ObjectId, [string[]]$MemberIds = @()) {
    $allIds = @($ObjectId) + $MemberIds | Select-Object -Unique
    $minTier = $null
    foreach ($id in $allIds) {
        if (-not $azureDelegationLookup.ContainsKey($id)) { continue }
        foreach ($entry in $azureDelegationLookup[$id]) {
            $t = [int]$entry.Tier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier   # null = no Azure delegations
}

#########################################################################################################
# COLLECT USERS
#########################################################################################################

Write-Sep
Write-Step "Getting information about Users from Entra"

$userSelect = "id,displayName,userPrincipalName,userType,accountEnabled," +
              "createdDateTime,lastPasswordChangeDateTime,passwordPolicies," +
              "onPremisesSyncEnabled,onPremisesSamAccountName,onPremisesDistinguishedName," +
              "department,jobTitle,manager,externalUserState," +
              "onPremisesExtensionAttributes,signInActivity,customSecurityAttributes"

$allUsers = Get-AllPages -Uri "$GRAPH_BASE/users?`$select=$userSelect"
Write-Ok "Found $($allUsers.Count) users"

# ---------------------------------------------------------------------------------
# Bulk MFA registration fetch -- ONE paged call against
#   /reports/authenticationMethods/userRegistrationDetails
# (the same endpoint that powers the Entra portal's "Authentication methods
# activity" page). Cached by user ObjectId. Per-user enrichment below looks this
# up first and only falls back to the per-user /authentication/methods call when
# bulk lookup misses (e.g. brand-new users not yet in the report -- can take ~24h).
#
# Why this matters: the previous per-user-only path silently produced
# MFAMethodCount=0 / MFARegistered=false whenever the per-user call threw (the
# catch was empty), making the entire MFA report unreliable when a single
# transient Graph error occurred. The bulk endpoint is also orders of magnitude
# faster on big tenants and far less throttle-prone.
#
# Permission: UserAuthenticationMethod.Read.All (already required by Step1; same
# scope covers both the bulk and per-user endpoints).
# ---------------------------------------------------------------------------------
$script:_MfaRegByObjectId = @{}
try {
    $regs = Get-AllPages -Uri "$GRAPH_BASE/reports/authenticationMethods/userRegistrationDetails?`$top=999"
    foreach ($reg in $regs) {
        if ($reg -and $reg.id) { $script:_MfaRegByObjectId[[string]$reg.id] = $reg }
    }
    Write-Ok ("Fetched MFA registration details for {0} users from /reports/authenticationMethods/userRegistrationDetails" -f $script:_MfaRegByObjectId.Count)
} catch {
    Write-Warn ("Bulk MFA registration fetch failed: {0}. Falling back to per-user calls (slower; see per-user warnings below if this user count is large)." -f $_.Exception.Message)
    $script:_MfaRegByObjectId = $null
}

if ($TroubleshootingMode) {
    $allUsers = @($allUsers | Select-Object -First $TroubleshootingLimit)
    Write-Warn "TROUBLESHOOTING MODE - limited to $TroubleshootingLimit users"
}

# Stream directly to temp file during collection - no in-memory array needed
# Fixed predictable temp file path in .\OUTPUT\ relative to the script directory.
# Overwritten on each new collection run. Survives the run for manual ingest replay.
$outputFolder = Join-Path $PSScriptRoot "OUTPUT"
If (-not (Test-Path $outputFolder)) { New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null }
$tempFile = Join-Path $outputFolder "IdentityAssets_Collection.jsonl"
Write-Info "Temp file: $tempFile"

# Delete any leftover file from a previous run - this releases any stale OS handle
# and gives us a clean slate. The file is recreated by StreamWriter below.
if (Test-Path $tempFile) {
    try {
        Remove-Item -Path $tempFile -Force -ErrorAction Stop
        Write-Info "Previous temp file removed"
    } catch {
        Write-Warn "Could not remove previous temp file (may be locked): $($_.Exception.Message)"
        Write-Warn "Close any process holding '$tempFile' and re-run"
        throw
    }
}

$script:streamWriter = [System.IO.StreamWriter]::new($tempFile, $false, [System.Text.Encoding]::UTF8)

# Ensure writer is always flushed+disposed even if collection crashes mid-way,
# so the file handle is released and the next run can open it cleanly.
trap {
    if ($script:streamWriter) {
        try { $script:streamWriter.Flush(); $script:streamWriter.Dispose() } catch {}
        $script:streamWriter = $null
    }
    if ($script:streamReader) {
        try { $script:streamReader.Dispose() } catch {}
        $script:streamReader = $null
    }
    break   # re-throw to caller
}
$userCount      = 0
$spCount        = 0
$schemaUsers    = [System.Collections.Generic.List[object]]::new()   # up to 100 for schema sample
$schemaSPNs     = [System.Collections.Generic.List[object]]::new()   # up to 100 SPNs
$schemaMIs      = [System.Collections.Generic.List[object]]::new()   # up to 100 MIs
$counter        = 0
$totalUsers     = $allUsers.Count

foreach ($user in $allUsers) {
    $counter++
    $pct    = [int](($counter / $totalUsers) * 100)
    $upn    = [string]$user.userPrincipalName

    Write-Progress -Id 1 -Activity "Getting information about Users" `
        -Status "$counter / $totalUsers  |  $upn" `
        -PercentComplete $pct

    $isExternal = $user.userType -eq "Guest" -or ([string]$user.userPrincipalName) -like "*#EXT#*"
    $extDomain  = if ($isExternal -and [string]$user.userPrincipalName -match "([^_]+)_([^#]+)#EXT#") {
        ($Matches[2])
    } else { "" }

    $lastInteractive     = $user.signInActivity.lastSignInDateTime
    $lastNonInteractive  = $user.signInActivity.lastNonInteractiveSignInDateTime
    $lastInteractiveDays = Get-DaysSince $lastInteractive
    $lastNonIntDays      = Get-DaysSince $lastNonInteractive

    # Most recent sign-in across both interactive and non-interactive
    $lastSignIn     = $lastInteractive
    $lastSignInDays = $lastInteractiveDays
    if ($lastNonIntDays -ge 0 -and ($lastSignInDays -lt 0 -or $lastNonIntDays -lt $lastSignInDays)) {
        $lastSignIn     = $lastNonInteractive
        $lastSignInDays = $lastNonIntDays
    }

    $createdDays   = Get-DaysSince $user.createdDateTime
    $pwdDays       = Get-DaysSince $user.lastPasswordChangeDateTime
    $isStale       = $user.accountEnabled -eq $true -and $lastSignInDays -gt $IdentityInfoLookbackDays

    # Entra roles
    $roles    = Get-PrincipalRoles -ObjectId $user.id
    $roleTier      = Get-TierFromEntraRoles -Roles $roles.All
    $entraRoleTier = if ($null -ne $roleTier) { $roleTier } else { 3 }   # default 3 = no roles assigned
    $entraRoleTierForSource = $roleTier   # null = no Entra role signal (shown in TierSources)

    $requiresPIM  = ($roles.Permanent | Where-Object { ($EntraID_Roles_Tier0 + $EntraID_Roles_Tier1) -contains $_ }).Count -gt 0
    $isPrivileged = $roles.All.Count -gt 0
    $isBreakGlass = ($roles.Permanent -contains "Global Administrator") -and
                    ($lastSignInDays -gt 30 -or $lastSignIn -eq $null) -and
                    ([string]$user.displayName -match "break|emergency|glass|bg-")

    # EntraID_Roles JSON
    $entraRolesJson = To-JsonStr ([ordered]@{
        Permanent             = @($roles.Permanent)
        Eligible              = @($roles.Eligible)
        Tier                  = $entraRoleTier
    })

    # EntraID_AppPermissions + Workload_Credentials not applicable for users - only for SPNs/MIs
    $entraPermsJson = '{}'
    $credJson       = '{}'

    # MFA methods - only query for enabled internal non-guest accounts
    # Guests, disabled users, and external accounts cannot register MFA in this tenant
    $mfaMethods  = @()
    $mfaCount    = 0
    $mfaReg      = $false
    $passwordless= $false
    $needsMFACheck = ($user.accountEnabled -eq $true) -and ($user.userType -ne 'Guest') -and (-not $isExternal)
    if ($needsMFACheck) {

        # Primary path: bulk userRegistrationDetails cache (fetched once at startup).
        $reg = $null
        if ($script:_MfaRegByObjectId) { $reg = $script:_MfaRegByObjectId[[string]$user.id] }

        if ($reg) {
            $mfaReg     = [bool]$reg.isMfaRegistered
            $methodsRaw = @()
            if ($reg.PSObject.Properties['methodsRegistered'] -and $reg.methodsRegistered) {
                $methodsRaw = @($reg.methodsRegistered)
            }
            # Drop 'password' if present -- holding a password isn't MFA on its own.
            $mfaMethods   = @($methodsRaw | Where-Object { $_ -and $_ -ne 'password' })
            $mfaCount     = $mfaMethods.Count
            $passwordless = $false
            if ($reg.PSObject.Properties['isPasswordlessCapable']) { $passwordless = [bool]$reg.isPasswordlessCapable }
        }
        else {
            # Fallback path: per-user /authentication/methods. Used when the bulk fetch failed,
            # or when a brand-new user isn't in userRegistrationDetails yet (~24h propagation).
            # NOTE: previously this had an empty `catch {}` which silently produced MFA=false
            # for every user the per-user call threw on. Now logged so the failure is visible.
            try {
                $authMethods = Get-AllPages -Uri "$GRAPH_BASE/users/$($user.id)/authentication/methods"
                $mfaMethods  = @($authMethods | ForEach-Object {
                                    $odataType = $null
                                    if ($_ -is [System.Collections.IDictionary]) {
                                        if ($_.ContainsKey('@odata.type')) { $odataType = [string]$_['@odata.type'] }
                                    } else {
                                        $p = $_.PSObject.Properties['@odata.type']
                                        if ($p -and $p.Value) { $odataType = [string]$p.Value }
                                    }
                                    if ($odataType -and $odataType -ne '') { $odataType -replace '#microsoft.graph.','' }
                                } | Where-Object { $_ -and $_.Trim() -ne '' -and $_ -ne 'passwordAuthenticationMethod' })
                $mfaCount    = $mfaMethods.Count
                $mfaReg      = $mfaCount -gt 0
                $passwordless= ($mfaMethods | Where-Object { $_ -in @('fido2AuthenticationMethod','windowsHelloForBusinessAuthenticationMethod') }).Count -gt 0 -and
                               ($mfaMethods | Where-Object { $_ -eq 'passwordAuthenticationMethod' }).Count -eq 0
            } catch {
                Write-Warn ("MFA fetch failed for {0} ({1}): {2}" -f $upn, $user.id, $_.Exception.Message)
            }
        }
    }

    # ExtensionAttributes JSON - non-empty only
    $ext     = $user.onPremisesExtensionAttributes
    $extHash = [ordered]@{}
    if ($ext) {
        for ($i = 1; $i -le 15; $i++) {
            $key = "extensionAttribute$i"
            $val = $null
            if ($ext -is [System.Collections.IDictionary]) {
                if ($ext.ContainsKey($key)) { $val = $ext[$key] }
            } else {
                $p = $ext.PSObject.Properties[$key]
                if ($p) { $val = $p.Value }
            }
            if ($val -and [string]$val -ne '') { $extHash["$i"] = [string]$val }
        }
    }
    $extJson = if ($extHash.Count -gt 0) { To-JsonStr $extHash } else { '{}' }

    # CSA JSON - all attribute sets
    $csaJson = Get-CSATags -FromObject $user

    # IdentityInfo enrichment from Log Analytics (Entra ID / MDI)
    $ii = $identityInfoLookup[[string]$user.id]

    # Diagnostic: warn if on-prem synced user has no IdentityInfo match
    if (-not $ii -and $user.onPremisesSyncEnabled -eq $true) {
        $upnDomain = ([string]$user.userPrincipalName -split '@')[-1]
        if ($isExternal -or -not $tenantVerifiedDomains.Contains($upnDomain)) {
            # Expected - cross-tenant B2B user synced from a partner domain not in our tenant
            Write-Info "  IdentityInfo skip (cross-tenant domain '$upnDomain'): $($user.userPrincipalName)"
        } else {
            # Unexpected - internal on-prem user with no MDI record
            # Possible causes: user never authenticated, MDI sensor gap, or account created after last MDI sync
            Write-Warn "  No IdentityInfo match for internal on-prem user: $($user.userPrincipalName) (id: $($user.id))"
        }
    }

    # Initialise all AD variables
    $allEntraGroups = @()
    $adTier         = -1
    $adTierSrc      = ''
    $adScopedGroups = @()   # AD catalog-matched groups only - empty for cloud-only users
    $adDomain       = ''
    $adSam          = ''
    $adDn           = ''
    $adOnPremOid    = ''
    $adUac          = @()
    $isAdUser       = $false

    if ($ii) {
        $adDomain = [string]$ii['AccountDomain']
        $adSid    = [string]$ii['AccountSID']

        # AD user = has both AccountDomain and AccountSID populated in IdentityInfo
        $isAdUser = ($adDomain -ne '' -and $adSid -ne '')

        # Extract GroupMembership - Dynamic column, may be wrapped as {"value":[...]} or plain array
        $gmRaw = $ii['GroupMembership']
        if ($gmRaw) {
            if ($gmRaw -is [System.Collections.IDictionary] -and $gmRaw.ContainsKey('value')) {
                $allEntraGroups = @($gmRaw['value'] | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
            } elseif ($gmRaw -is [System.Collections.IEnumerable] -and -not ($gmRaw -is [string])) {
                $allEntraGroups = @($gmRaw | ForEach-Object {
                    if ($_ -is [System.Collections.IDictionary] -and $_.ContainsKey('value')) {
                        $_.value | ForEach-Object { [string]$_ }
                    } else { [string]$_ }
                } | Where-Object { $_ -ne '' })
            } elseif ($gmRaw -is [string] -and $gmRaw -ne '') {
                # Try JSON parse first (LA returns GroupMembership as JSON array string)
                try {
                    $parsed = $gmRaw | ConvertFrom-Json
                    # ConvertFrom-Json on ["a b c"] gives single element "a b c" - detect and split
                    if ($parsed -is [string]) {
                        # Single string - may be space-separated group names
                        $allEntraGroups = @($parsed -split '\s+' | Where-Object { $_ -ne '' })
                    } elseif ($parsed -is [System.Array]) {
                        $allEntraGroups = @($parsed | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
                    } else {
                        $allEntraGroups = @([string]$parsed)
                    }
                } catch {
                    # Not JSON - treat as space-separated list
                    $allEntraGroups = @($gmRaw -split '\s+' | Where-Object { $_ -ne '' })
                }
            }
        }

        # Tier from group memberships - ONLY for AD-synced users.
        # Cloud-only users have cloud group names (e.g. Intune_Users_All_Dynamic) in
        # GroupMembership which must NOT be matched against the AD built-in group catalog.
        # For AD users: filter to only groups that exist in the AD catalog before tiering.
        if ($isAdUser) {
            # Resolve AD group memberships from Exposure Graph (pre-loaded, catalog-filtered).
            # Keyed by Entra Object ID (UserObjectId = NodeId) with UPN as fallback.
            $adGroupsWithSource = @()   # [{Name, Provider}] for AD_Roles proof
            $userOidKey         = $user.id.ToLower()
            $userUpnKey         = ([string]$user.userPrincipalName).ToLower()

            if ($exposureAdMemberships.Count -gt 0) {
                $userRows = @($exposureAdMemberships | Where-Object {
                    $_.ObjectId -eq $userOidKey -or $_.UPN -eq $userUpnKey
                })
                $adGroupsWithSource = @($userRows | ForEach-Object { [ordered]@{ Name = $_.GroupName; Provider = $_.Provider } })
                if ($adGroupsWithSource.Count -gt 0) {
                    Write-Info "  AD groups via ExposureGraph for $($user.userPrincipalName): $(($adGroupsWithSource | ForEach-Object { $_.Name }) -join ', ')"
                }
            }

            $adGroupsForUser = @($adGroupsWithSource | ForEach-Object { $_.Name })

            $adMatches  = Get-ADGroupMatches -Groups $adGroupsForUser
            $adTier     = if ($adMatches.Count -gt 0) {
                            ($adMatches | ForEach-Object { [int]$_.Tier } | Measure-Object -Minimum).Minimum
                          } else {
                            # No catalog group matches - primary group (Domain Users) is invisible
                            # to Exposure Graph edges (stored via primaryGroupID, not member attribute).
                            # Every AD-synced user is implicitly at minimum Tier 3.
                            3
                          }
            $adTierSrc  = if ($adMatches.Count -gt 0) {
                            ($adMatches | Sort-Object { [int]$_.Tier } | Select-Object -First 1).Name
                          } else { 'Domain Users (implicit)' }
            $adScopedGroups = @($adMatches | ForEach-Object { $_.Name })
        }
        # Cloud-only users: $adTier and $adTierSrc remain -1 / '' (initialised above)

        # AD_Info fields - only meaningful for AD users
        if ($isAdUser) {
            $adSam       = [string]$ii['SAMAccountName']
            $adDn        = [string]$ii['OnPremisesDistinguishedName']
            $adOnPremOid = [string]$ii['OnPremisesAccountObjectId']
            $uacRaw      = $ii['UserAccountControl']
            if ($uacRaw -is [System.Collections.IEnumerable] -and -not ($uacRaw -is [string])) {
                $adUac = @($uacRaw | ForEach-Object { [string]$_ })
            } elseif ($uacRaw) {
                $adUac = @([string]$uacRaw)
            }
        }
    }

    # MDI AssignedRoles - can cross-validate with EntraID_Roles
    $mdiRolesRaw = if ($ii) { $ii['AssignedRoles'] } else { $null }
    $mdiRoles    = @()
    if ($mdiRolesRaw -is [System.Collections.IEnumerable] -and -not ($mdiRolesRaw -is [string])) {
        $mdiRoles = @($mdiRolesRaw | ForEach-Object { [string]$_ } | Where-Object { $_ -ne '' })
    }

    # MDI EntityRiskScore - UEBA dynamic score
    $mdiEntityRisk    = if ($ii) { $ii['EntityRiskScore'] } else { $null }
    $mdiEntityRiskStr = if ($mdiEntityRisk) { ($mdiEntityRisk | ConvertTo-Json -Compress) } else { '{}' }

    # EntraID_Groups JSON - all group memberships from IdentityInfo (cloud + on-prem)
    # $allEntraGroups is already correctly parsed into individual group name strings above.
    # Use unary comma to force PS 5.1 to emit [] even for single-element arrays.
    $entraGroupsJson = if ($allEntraGroups.Count -gt 0) {
        (,[string[]]$allEntraGroups | ConvertTo-Json -Compress)
    } else { '[]' }

    # AD_Roles JSON - only populated for AD-synced users.
    # Cloud-only accounts get '{}' - they have no AD group memberships to tier.
    # MatchedGroups  = catalog-matched groups that drove the tier assignment.
    # ExposureGraphGroups = all groups returned by the Exposure Graph for this user
    #                       (includes non-catalog groups like custom/cloud groups).
    $adRolesJson = if ($isAdUser) {
        ([ordered]@{
            Tier                = $adTier
            TierSourceGroup     = $adTierSrc
            MatchedGroups       = @($adMatches | ForEach-Object {
                $matchName = $_.Name
                $src = $adGroupsWithSource | Where-Object { $_.Name -ieq $matchName } | Select-Object -First 1
                [ordered]@{
                    Name     = $_.Name
                    Tier     = $_.Tier
                    Reason   = $_.Reason
                    Provider = if ($src) { $src.Provider } else { "AD" }
                }
            })
            ExposureGraphGroups = @($adGroupsWithSource | ForEach-Object { $_.Name })
        } | ConvertTo-Json -Depth 4 -Compress)
    } else { '{}' }

    # AD_Info JSON - only populated for AD users (AccountDomain + AccountSID present in IdentityInfo)
    $adInfoJson = if ($isAdUser) {
        To-JsonStr ([ordered]@{
            Domain             = $adDomain
            SAMAccountName     = $adSam
            DistinguishedName  = $adDn
            OnPremObjectId     = $adOnPremOid
            UserAccountControl = ($adUac -join ';')
        })
    } else { '{}' }

    # Azure delegations for this user - includes direct assignments AND assignments
    # inherited via active group memberships and PIM for Groups eligible chains
    $azureDelegationsJson = Get-AzureDelegationsJson -ObjectId $user.id `
                                                     -MemberIds $roles.ReachableGroups
    $azureTierRaw         = Get-AzureDelegationTier  -ObjectId $user.id `
                                                     -MemberIds $roles.ReachableGroups
    $azureTier            = if ($null -ne $azureTierRaw) { $azureTierRaw } else { 3 }   # default 3 = no Azure delegations
    $azureTierForSource   = $azureTierRaw   # null = no Azure delegations (shown in TierSources)

    # TierSources: per-provider tier + catalog-matched proof from the JSON tier definition file.
    # Each provider shows the tier it resolved to and exactly which catalog entries matched.
    $userEntraMatches      = Get-EntraRoleMatches         -Roles $roles.All
    $userADMatches         = if ($isAdUser) { @($adMatches) } else { @() }
    $userAzureAssignments  = Get-AzurePrincipalAssignments -ObjectId $user.id -MemberIds $roles.ReachableGroups

    $tierSourcesJson = ([ordered]@{
        EntraID_Roles = [ordered]@{
            Tier           = $entraRoleTierForSource   # null = no roles assigned
            CatalogMatches = @($userEntraMatches)
        }
        EntraID_APIPermissions = [ordered]@{
            Tier           = $null
            CatalogMatches = @()
        }
        AD = [ordered]@{
            Tier           = if ($isAdUser) { $adTier } else { $null }   # null = cloud-only user
            CatalogMatches = @($userADMatches)
        }
        Azure = [ordered]@{
            Tier        = $azureTierForSource   # null = no Azure delegations
            Assignments = @($userAzureAssignments)
        }
    } | ConvertTo-Json -Depth 6 -Compress)

    $effectiveTier = [int](Get-MinTier -Tiers @($entraRoleTier, $adTier, $azureTier))

    # Derived flags
    $isSensitive  = $effectiveTier -eq 0
    $isHighValue  = $effectiveTier -le 1

    # IsShadowAdmin: AD-synced user with T0/T1 AD group membership but no visible Entra roles.
    # Privileged access via AD path only - not reflected in Entra ID role assignments.
    # Must guard with $isAdUser: $adTier=-1 for cloud-only and -1 -le 1 is $true in PowerShell.
    $isShadowAdmin = $isAdUser -and
                     ($adTier -ge 0 -and $adTier -le 1) -and
                     ($roles.All.Count -eq 0 -or ([bool]($user.onPremisesSyncEnabled -eq $true) -and -not $isPrivileged))

    $rec = [PSCustomObject]@{
        # -- Core identity --
        ObjectId                      = [string]$user.id
        ObjectType                    = [string]"User"
        DisplayName                   = [string]$user.displayName
        UPN                           = [string]$user.userPrincipalName
        AppId                         = [string]""
        SPType                        = [string]""
        AccountEnabled                = [bool]($user.accountEnabled -eq $true)

        # -- External / guest --
        IsExternal                    = [bool]$isExternal
        ExternalDomain                = [string]$extDomain
        IsB2BCollaborator             = [bool]($isExternal -and $user.externalUserState -eq "Accepted")

        # -- On-prem sync --
        OnPremSynced                  = [bool]($user.onPremisesSyncEnabled -eq $true)
        OnPremSamAccountName          = [string]$user.onPremisesSamAccountName
        OnPremDistinguishedName       = [string]$user.onPremisesDistinguishedName

        # -- Profile --
        Department                    = [string]$user.department
        JobTitle                      = [string]$user.jobTitle
        Manager                       = [string]$user.manager.displayName

        # -- Lifecycle --
        CreatedDateTime               = [string]$user.createdDateTime
        CreatedDays                   = [int]$createdDays
        LastSignInDateTime               = [string]$lastSignIn
        LastSignInDays                   = [int]$lastSignInDays
        LastInteractiveSignInDateTime    = [string]$lastInteractive
        LastInteractiveSignInDays        = [int]$lastInteractiveDays
        LastNonInteractiveSignInDateTime = [string]$lastNonInteractive
        LastNonInteractiveSignInDays     = [int]$lastNonIntDays
        IsStale                       = [bool]$isStale
        PasswordLastChangedDays       = [int]$pwdDays
        IsPasswordNeverExpires        = [bool]([string]$user.passwordPolicies -like "*DisablePasswordExpiration*")

        # -- MFA --
        MFARegistered                 = [bool]$mfaReg
        MFAMethodCount                = [int]$mfaCount
        MFAMethods                    = [string](($mfaMethods | Where-Object { $_ -and $_.Trim() -ne '' }) -join ";")
        IsPasswordlessOnly            = [bool]$passwordless

        # -- Risk flags (flat for analytics rules) --
        IsPrivileged                  = [bool]$isPrivileged
        IsPrivilegedEligible          = [bool]($roles.Eligible.Count -gt 0)
        HasPermanentPrivilegedRole    = [bool]$requiresPIM
        RequiresPIMReview             = [bool]$requiresPIM
        IsSensitive                   = [bool]$isSensitive
        IsHighValueTarget             = [bool]$isHighValue
        IsBreakGlass                  = [bool]$isBreakGlass
        IsShadowAdmin                 = [bool]$isShadowAdmin
        IsOrphan                      = [bool]$false
        IsManagedIdentity             = [bool]$false
        IsManagedIdentityUserAssigned = [bool]$false
        ManagedIdentityResourceId     = [string]""
        IsMultiTenant                 = [bool]$false
        PublisherVerified             = [bool]$false
        IsExternal_SPN                = [bool]$false

        # -- MDI enrichment (flat) --
        OnPremSid                     = [string]$(if ($ii) { [string]$ii['AccountSID'] } else { "" })
        CloudSid                      = [string]$(if ($ii) { [string]$ii['AccountCloudSID'] } else { "" })
        AccountUPN                    = [string]$(if ($ii) { [string]$ii['AccountUPN'] } else { "" })
        GivenName                     = [string]$(if ($ii) { [string]$ii['GivenName'] } else { "" })
        Surname                       = [string]$(if ($ii) { [string]$ii['Surname'] } else { "" })
        MailAddress                   = [string]$(if ($ii) { [string]$ii['MailAddress'] } else { "" })
        Phone                         = [string]$(if ($ii) { [string]$ii['Phone'] } else { "" })
        City                          = [string]$(if ($ii) { [string]$ii['City'] } else { "" })
        State                         = [string]$(if ($ii) { [string]$ii['State'] } else { "" })
        Country                       = [string]$(if ($ii) { [string]$ii['Country'] } else { "" })
        StreetAddress                 = [string]$(if ($ii) { [string]$ii['StreetAddress'] } else { "" })
        CompanyName                   = [string]$(if ($ii) { [string]$ii['CompanyName'] } else { "" })
        EmployeeId                    = [string]$(if ($ii) { [string]$ii['EmployeeId'] } else { "" })
        UserType                      = [string]$(if ($ii) { [string]$ii['UserType'] } else { "" })
        UserState                     = [string]$(if ($ii) { [string]$ii['UserState'] } else { "" })
        UACFlags                      = [string]$(if ($ii) { [string]$ii['UACFlags'] } else { "" })
        SourceSystem                  = [string]$(if ($ii) { [string]$ii['SourceSystem'] } else { "" })
        LastSeenDate                  = [string]$(if ($ii) { [string]$ii['LastSeenDate'] } else { "" })
        MDI_IsMFARegistered           = [bool]$(if ($ii) { [bool]$ii['IsMFARegistered'] } else { $false })
        MDI_IsServiceAccount          = [bool]$(if ($ii) { [bool]$ii['IsServiceAccount'] } else { $false })
        MDI_BlastRadius               = [string]$(if ($ii) { [string]$ii['BlastRadius'] } else { "" })
        MDI_Tags                      = [string]$(if ($ii) { [string]$ii['Tags'] } else { "" })
        MDI_InvestigationPriority     = [int]$(if ($ii) { [int]$ii['InvestigationPriority'] } else { -1 })
        MDI_InvestigationPriorityPct  = [int]$(if ($ii) { [int]$ii['InvestigationPriorityPercentile'] } else { -1 })
        MDI_RiskLevel                 = [string]$(if ($ii) { [string]$ii['RiskLevel'] } else { "" })
        MDI_RiskLevelDetails          = [string]$(if ($ii) { [string]$ii['RiskLevelDetails'] } else { "" })
        MDI_RiskState                 = [string]$(if ($ii) { [string]$ii['RiskState'] } else { "" })
        MDI_EntityRiskScore           = [string]$mdiEntityRiskStr
        MDI_AssignedRoles             = [string]($mdiRoles -join ";")

        # -- AD columns --
        AD_Roles                      = $adRolesJson
        AD_Info                       = $adInfoJson

        # -- JSON columns --
        EntraID_Roles                 = $entraRolesJson
        EntraID_AppPermissions        = $entraPermsJson
        EntraID_Groups                = $entraGroupsJson
        Workload_Credentials          = $credJson
        ExtensionAttributes           = $extJson
        CSA                           = $csaJson

        # -- Azure RBAC delegations --
        Azure_Delegations             = $azureDelegationsJson

        # -- Tier sources + effective tier --
        TierSources                   = $tierSourcesJson
        EffectiveTier                 = [int]$effectiveTier
        CollectionTime                = $CollectionTime
        SolutionVersion               = $SolutionVersion
    }

    # Stream record immediately - frees memory as soon as the loop iteration completes
    $script:streamWriter.WriteLine((ConvertTo-Json -InputObject $rec -Depth 10 -Compress))
    $userCount++
    # Accumulate schema sample (first 100 users)
    if ($schemaUsers.Count -lt 100) { $schemaUsers.Add($rec) }
}

Write-Progress -Id 1 -Activity "Getting information about Users" -Completed
Write-Ok "Users streamed: $userCount"

#########################################################################################################
# COLLECT SERVICE PRINCIPALS + MANAGED IDENTITIES
#########################################################################################################

Write-Sep
Write-Step "Getting information about Service Principals and Managed Identities from Entra"

$spSelect = "id,displayName,appId,servicePrincipalType,accountEnabled," +
            "createdDateTime,passwordCredentials,keyCredentials," +
            "verifiedPublisher,signInAudience,alternativeNames,appOwnerOrganizationId,customSecurityAttributes"

$allSPs = Get-AllPages -Uri "$GRAPH_BASE/servicePrincipals?`$select=$spSelect&`$top=999"
Write-Ok "Found $($allSPs.Count) service principals"

if ($TroubleshootingMode) {
    $allSPs = @($allSPs | Select-Object -First $TroubleshootingLimit)
    Write-Warn "TROUBLESHOOTING MODE - limited to $TroubleshootingLimit service principals"
}

$counter  = 0
$totalSPs = $allSPs.Count

# Get current tenant ID for external SPN detection (reuse org info already fetched)
$tenantInfo      = Invoke-Graph -Uri "$GRAPH_BASE/organization?`$select=id"
$currentTenantId = if ($tenantInfo -is [System.Collections.IDictionary]) { [string]$tenantInfo['value'][0]['id'] } else { [string]$tenantInfo.value[0].id }

foreach ($sp in $allSPs) {
    $counter++
    $pct = [int](($counter / $totalSPs) * 100)

    Write-Progress -Id 2 -Activity "Getting information about Service Principals & Managed Identities" `
        -Status "$counter / $totalSPs  |  $([string]$sp.displayName)" `
        -PercentComplete $pct

    $isMI       = $sp.servicePrincipalType -eq "ManagedIdentity"
    $objectType = if ($isMI) { "ManagedIdentity" } else { "ServicePrincipal" }

    $perms      = Get-SPNPermissions -SpId $sp.id
    $permTierRaw = Get-TierFromEntraAPIPerms -Perms $perms.All
    $permTier        = if ($null -ne $permTierRaw) { $permTierRaw } else { 3 }   # default 3 = no API permissions
    $permTierForSource = $permTierRaw   # null = no API permissions (shown in TierSources)
    $highestPerm= Get-HighestRiskEntraAPIPermission -Perms $perms.All

    $roles      = Get-PrincipalRoles -ObjectId $sp.id
    $roleTier   = Get-TierFromEntraRoles -Roles $roles.All

    # $permTier and $roleTier may be $null (no perms/roles found) - Get-MinTier handles nulls

    # Credentials
    $now        = [datetime]::UtcNow
    $allCreds   = @($sp.passwordCredentials) + @($sp.keyCredentials) | Where-Object { $_ }
    $expiryDays = if ($allCreds.Count -gt 0) {
        $allCreds | Where-Object { $_.endDateTime } |
        ForEach-Object { [int]([datetime]::Parse($_.endDateTime.ToString()) - $now).TotalDays } |
        Sort-Object | Select-Object -First 1
    } else { -1 }
    $hasExpired = $expiryDays -lt 0 -and $allCreds.Count -gt 0

    # Managed Identity
    $isMIUser     = $isMI -and ($sp.alternativeNames | Where-Object { $_ -like "*/userAssignedIdentities/*" }).Count -gt 0
    $miResourceId = if ($isMIUser) {
        $sp.alternativeNames | Where-Object { $_ -like "/subscriptions/*" } | Select-Object -First 1
    } else { "" }

    # Owners
    $owners     = @()
    $ownerNames = ""
    $ownerList  = @()
    try {
        $ownersResp = Get-AllPages -Uri "$GRAPH_BASE/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
        $ownerList  = @($ownersResp | ForEach-Object { if ($_.userPrincipalName) { [string]$_.userPrincipalName } else { [string]$_.displayName } })
        $ownerNames = $ownerList -join ";"
        $owners     = $ownersResp
    } catch {}

    $isOrphan = ($owners.Count -eq 0) -and ($sp.accountEnabled -eq $true) -and (-not $isMI)
    $isExtSPN = [string]$sp.appOwnerOrganizationId -ne $currentTenantId -and -not [string]::IsNullOrEmpty($sp.appOwnerOrganizationId)

    # CSA JSON - all attribute sets from pre-fetched SP object
    $csaJson  = Get-CSATags -FromObject $sp

    # EntraID_Roles JSON
    $spRoleTier          = if ($null -ne $roleTier) { $roleTier } else { 3 }   # default 3 = no roles assigned
    $spRoleTierForSource = $roleTier   # null = no Entra role signal (shown in TierSources)
    $spRequiresPIM = $roles.Permanent.Count -gt 0
    $entraRolesJson = To-JsonStr ([ordered]@{
        Permanent            = @($roles.Permanent)
        Eligible             = @($roles.Eligible)
        Tier                 = $spRoleTier
    })

    # EntraID_AppPermissions JSON
    $allPerms = $perms.All
    $entraPermsJson = To-JsonStr ([ordered]@{
        AppRoles             = @($perms.App)
        Delegated            = @($perms.Delegated)
        HighestRisk          = $highestPerm
        Tier                 = $permTier
        TargetAPICount       = ($perms.App | Select-Object -Unique).Count
        HasWrite             = ($allPerms | Where-Object { $_ -like "*Write*" }).Count -gt 0
        HasDirectoryWrite    = $allPerms -contains "Directory.ReadWrite.All"
        HasRoleWrite         = $allPerms -contains "RoleManagement.ReadWrite.Directory"
        HasMailboxAccess     = ($allPerms | Where-Object { $_ -like "Mail.*" }).Count -gt 0
    })

    # Workload_Credentials JSON
    $credJson = To-JsonStr ([ordered]@{
        HasSecret    = $sp.passwordCredentials.Count -gt 0
        HasCert      = $sp.keyCredentials.Count -gt 0
        ExpiryDays   = $expiryDays
        HasExpired   = $hasExpired
        HasNoOwner   = $isOrphan
        OwnersCount  = $owners.Count
        Owners       = $ownerList
    })

    # AD flat columns - empty for SPNs/MIs (not in IdentityInfo)

    # ExtensionAttributes - empty for SPNs
    $extJson = '{}'

    # Azure delegations for this SPN / MI - includes direct assignments AND assignments
    # inherited via active group memberships and PIM for Groups eligible chains
    $azureDelegationsJson = Get-AzureDelegationsJson -ObjectId $sp.id `
                                                     -MemberIds $roles.ReachableGroups
    $azureTierRaw         = Get-AzureDelegationTier  -ObjectId $sp.id `
                                                     -MemberIds $roles.ReachableGroups
    $azureTier            = if ($null -ne $azureTierRaw) { $azureTierRaw } else { 3 }   # default 3 = no Azure delegations
    $azureTierForSource   = $azureTierRaw   # null = no Azure delegations (shown in TierSources)

    # TierSources: per-provider tier + catalog-matched proof from the JSON tier definition file.
    $spnEntraMatches      = Get-EntraRoleMatches         -Roles $roles.All
    $spnPermMatches       = Get-EntraPermMatches         -Perms $perms.All
    $spnAzureAssignments  = Get-AzurePrincipalAssignments -ObjectId $sp.id -MemberIds $roles.ReachableGroups

    $tierSourcesJson = ([ordered]@{
        EntraID_Roles = [ordered]@{
            Tier           = $spRoleTierForSource   # null = no roles assigned
            CatalogMatches = @($spnEntraMatches)
        }
        EntraID_APIPermissions = [ordered]@{
            Tier           = $permTierForSource   # null = no API permissions
            CatalogMatches = @($spnPermMatches)
        }
        AD = [ordered]@{
            Tier           = $null
            CatalogMatches = @()
        }
        Azure = [ordered]@{
            Tier        = $azureTierForSource   # null = no Azure delegations
            Assignments = @($spnAzureAssignments)
        }
    } | ConvertTo-Json -Depth 6 -Compress)

    $effectiveTier = [int](Get-MinTier -Tiers @($spRoleTier, $permTier, $azureTier))

    # IsShadowAdmin: has dangerous permissions but no visible Entra role
    $isShadow = ($permTier -le 1) -and ($roles.All.Count -eq 0)

    $rec = [PSCustomObject]@{
        # -- Core identity --
        ObjectId                      = [string]$sp.id
        ObjectType                    = [string]$objectType
        DisplayName                   = [string]$sp.displayName
        UPN                           = [string]""
        AppId                         = [string]$sp.appId
        SPType                        = [string]$sp.servicePrincipalType
        AccountEnabled                = [bool]($sp.accountEnabled -eq $true)

        # -- External --
        IsExternal                    = [bool]$isExtSPN
        ExternalDomain                = [string]""
        IsB2BCollaborator             = [bool]$false

        # -- On-prem --
        OnPremSynced                  = [bool]$false
        OnPremSamAccountName          = [string]""
        OnPremDistinguishedName       = [string]""

        # -- Profile --
        Department                    = [string]""
        JobTitle                      = [string]""
        Manager                       = [string]""

        # -- Lifecycle --
        CreatedDateTime               = [string]$sp.createdDateTime
        CreatedDays                   = [int](Get-DaysSince $sp.createdDateTime)
        LastSignInDateTime               = [string]$(if ($spnSignInLookup.ContainsKey($sp.id)) { [string]$spnSignInLookup[$sp.id]['LastSignIn'] } else { "" })
        LastSignInDays                   = [int]$(if ($spnSignInLookup.ContainsKey($sp.id)) { Get-DaysSince $spnSignInLookup[$sp.id]['LastSignIn'] } else { -1 })
        LastInteractiveSignInDateTime    = [string]$(if ($spnSignInLookup.ContainsKey($sp.id)) { [string]$spnSignInLookup[$sp.id]['LastSignIn'] } else { "" })
        LastInteractiveSignInDays        = [int]$(if ($spnSignInLookup.ContainsKey($sp.id)) { Get-DaysSince $spnSignInLookup[$sp.id]['LastSignIn'] } else { -1 })
        LastNonInteractiveSignInDateTime = [string]""
        LastNonInteractiveSignInDays     = [int]-1
        IsStale                          = [bool]$(if ($spnSignInLookup.ContainsKey($sp.id)) { $sp.accountEnabled -eq $true -and (Get-DaysSince $spnSignInLookup[$sp.id]['LastSignIn']) -gt $SpnSignInLookbackDays } else { $false })
        PasswordLastChangedDays          = [int]-1
        IsPasswordNeverExpires        = [bool]$false

        # -- MFA --
        MFARegistered                 = [bool]$false
        MFAMethodCount                = [int]0
        MFAMethods                    = [string]""
        IsPasswordlessOnly            = [bool]$false

        # -- Risk flags --
        IsPrivileged                  = [bool]($roles.All.Count -gt 0)
        IsPrivilegedEligible          = [bool]($roles.Eligible.Count -gt 0)
        HasPermanentPrivilegedRole    = [bool]$spRequiresPIM
        RequiresPIMReview             = [bool]$spRequiresPIM
        IsSensitive                   = [bool]($effectiveTier -eq 0)
        IsHighValueTarget             = [bool]($effectiveTier -le 1)
        IsBreakGlass                  = [bool]$false
        IsShadowAdmin                 = [bool]$isShadow
        IsOrphan                      = [bool]$isOrphan
        IsManagedIdentity             = [bool]$isMI
        IsManagedIdentityUserAssigned = [bool]$isMIUser
        ManagedIdentityResourceId     = [string]$miResourceId
        IsMultiTenant                 = [bool]([string]$sp.signInAudience -ne "AzureADMyOrg")
        PublisherVerified             = [bool]($null -ne $sp.verifiedPublisher.verifiedPublisherId)
        IsExternal_SPN                = [bool]$isExtSPN

        # -- MDI enrichment - empty for SPNs --
        OnPremSid                     = ""
        CloudSid                      = ""
        AccountUPN                    = ""
        GivenName                     = ""
        Surname                       = ""
        MailAddress                   = ""
        Phone                         = ""
        City                          = ""
        State                         = ""
        Country                       = ""
        StreetAddress                 = ""
        CompanyName                   = ""
        EmployeeId                    = ""
        UserType                      = ""
        UserState                     = ""
        UACFlags                      = ""
        SourceSystem                  = ""
        LastSeenDate                  = ""
        MDI_IsMFARegistered           = $false
        MDI_IsServiceAccount          = $false
        MDI_BlastRadius               = ""
        MDI_Tags                      = ""
        MDI_InvestigationPriority     = -1
        MDI_InvestigationPriorityPct  = -1
        MDI_RiskLevel                 = ""
        MDI_RiskLevelDetails          = ""
        MDI_RiskState                 = ""
        MDI_EntityRiskScore           = "{}"
        MDI_AssignedRoles             = ""

        # -- AD columns - empty for SPNs/MIs --
        AD_Roles                      = To-JsonStr ([ordered]@{ Tier = -1; TierSourceGroup = "" })
        AD_Info                       = '{}'

        # -- JSON columns --
        EntraID_Roles                 = $entraRolesJson
        EntraID_AppPermissions        = $entraPermsJson
        EntraID_Groups                = '[]'
        Workload_Credentials          = $credJson
        ExtensionAttributes           = $extJson
        CSA                           = $csaJson

        # -- Azure RBAC delegations --
        Azure_Delegations             = $azureDelegationsJson

        # -- Tier sources + effective tier --
        TierSources                   = $tierSourcesJson
        EffectiveTier                 = [int]$effectiveTier
        CollectionTime                = $CollectionTime
        SolutionVersion               = $SolutionVersion
    }

    # Stream record immediately
    $script:streamWriter.WriteLine((ConvertTo-Json -InputObject $rec -Depth 10 -Compress))
    $spCount++
    # Accumulate schema samples per type (first 100 of each)
    if ($isMI) {
        if ($schemaMIs.Count -lt 100) { $schemaMIs.Add($rec) }
    } else {
        if ($schemaSPNs.Count -lt 100) { $schemaSPNs.Add($rec) }
    }
}

Write-Progress -Id 2 -Activity "Getting information about Service Principals & Managed Identities" -Completed
$script:streamWriter.Flush()
$script:streamWriter.Dispose()
$script:streamWriter = $null
[System.GC]::Collect()
Write-Ok "SPNs/MIs streamed: $spCount"

#########################################################################################################
# COLLECTION COMPLETE - stats
# Data was streamed record-by-record during collection loops above.
# Peak memory = one record at a time + schema samples (max 300 objects total).
#########################################################################################################

Write-Sep
$totalCount = $userCount + $spCount
$fileSizeMB = [Math]::Round((Get-Item $tempFile).Length / 1MB, 1)
Write-Ok "Collection complete: $totalCount records in temp file ($fileSizeMB MB)"
Write-Ok "  Users: $userCount (schema sample: $($schemaUsers.Count))"
Write-Ok "  SPNs : $(($schemaSPNs.Count)) schema samples  |  MIs: $($schemaMIs.Count) schema samples"
# [TROUBLESHOOTING] [System.GC]::Collect()

#########################################################################################################
# BUILD SCHEMA SAMPLE FOR CheckCreateUpdate-TableDcr-Structure
# Requires min 100 records of each type (User, ServicePrincipal, ManagedIdentity) so the
# DCR schema is built from a representative column set. Normalise + align same as ingest path.
#########################################################################################################

Write-Sep
Write-Step "Building schema sample for DCR table structure"

# Schema sample = raw records exactly as built by the record constructors.
# No transformation - types (bool, int, string) must be identical to what gets ingested
# so CheckCreateUpdate-TableDcr-Structure sees the correct column types and updates
# the DCR and LA table schema to match.
$schemaSampleArr = [array](@($schemaUsers) + @($schemaSPNs) + @($schemaMIs))
$schemaColCount  = if ($schemaSampleArr.Count -gt 0) { [int]($schemaSampleArr[0].PSObject.Properties | Measure-Object).Count } else { 0 }
Write-Ok "Schema sample ready: $($schemaSampleArr.Count) records, $schemaColCount columns"

#########################################################################################################
# REFRESH AUTH TOKENS
# Collection phase can take 30+ minutes on large tenants. Tokens may have expired.
#########################################################################################################

Write-Sep
Write-Step "Refreshing auth tokens before ingestion"

try {
    # Refresh Azure context
    $global:SecureSecret = ConvertTo-SecureString $IngestionSpnClientSecret -AsPlainText -Force
    $global:Credential   = New-Object System.Management.Automation.PSCredential ($IngestionSpnClientId, $global:SecureSecret)
    Connect-AzAccount -ServicePrincipal -Tenant $TenantId -Credential $global:Credential -WarningAction SilentlyContinue | Out-Null
    Set-AzContext -SubscriptionId $WorkspaceSubscriptionId -TenantId $TenantId -ErrorAction Stop | Out-Null

    # Refresh DCE/DCR cache (uses ARM tokens). Filter to the target subscription
    # AND the target DCE/DCR resource groups so duplicate-named DCEs/DCRs
    # elsewhere in the same tenant / same sub don't poison the module's
    # internal name lookup inside Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output.
    Ensure-SecurityInsightAzDceDcrCache `
        -AzAppId           $IngestionSpnClientId `
        -AzAppSecret       $IngestionSpnClientSecret `
        -TenantId          $TenantId `
        -SubscriptionId    $WorkspaceSubscriptionId `
        -DceResourceGroup  $DceResourceGroup `
        -DcrResourceGroup  $DcrResourceGroup `
        -Force

    Write-Ok "Auth tokens and DCE/DCR cache refreshed (filtered to sub: $WorkspaceSubscriptionId, DceRG: $DceResourceGroup, DcrRG: $DcrResourceGroup)"
} catch {
    Write-Warn "Token refresh failed: $($_.Exception.Message) - continuing with existing tokens"
}

#########################################################################################################
# CREATE / UPDATE TABLE + DCR SCHEMA
#########################################################################################################

Write-Sep
Write-Step "Creating/updating Log Analytics table + DCR schema"

# Use schema sample (up to 300 representative records) - NOT the full dataset
# This avoids holding all records in RAM just for schema inference
$ResultMgmt = CheckCreateUpdate-TableDcr-Structure `
                  -AzLogWorkspaceResourceId                   $WorkspaceResourceId `
                  -AzAppId                                    $IngestionSpnClientId `
                  -AzAppSecret                                $IngestionSpnClientSecret `
                  -TenantId                                   $TenantId `
                  -Verbose:$false `
                  -DceName                                    $DceName `
                  -DcrName                                    $DcrName `
                  -DcrResourceGroup                           $DcrResourceGroup `
                  -TableName                                  $TableName `
                  -Data                                       $schemaSampleArr `
                  -AzDcrSetLogIngestApiAppPermissionsDcrLevel $false `
                  -AzLogDcrTableCreateFromAnyMachine          $true `
                  -AzLogDcrTableCreateFromReferenceMachine    @()

# Refresh the filtered DCE/DCR cache -- CheckCreateUpdate-TableDcr-Structure may
# have just created a new DCR, and Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output
# reads $global:AzDcrDetails to resolve the DCR name -> immutableId. If the new
# DCR isn't in the cache, the module falls back to a bogus value (e.g. DCE's
# location 'westeurope' gets sent as an immutableId and the API returns 404).
# A brief sleep lets ARM's eventual consistency catch up before re-listing.
Start-Sleep -Seconds 15
Ensure-SecurityInsightAzDceDcrCache `
    -AzAppId           $IngestionSpnClientId `
    -AzAppSecret       $IngestionSpnClientSecret `
    -TenantId          $TenantId `
    -SubscriptionId    $WorkspaceSubscriptionId `
    -DceResourceGroup  $DceResourceGroup `
    -DcrResourceGroup  $DcrResourceGroup `
    -Force
Write-Ok "DCE/DCR cache re-sync after DCR provisioning (DCE: $(@($global:AzDceDetails).Count) | DCR: $(@($global:AzDcrDetails).Count))"

# Free schema sample - no longer needed
# [TROUBLESHOOTING] $schemaSampleArr = $null
# [TROUBLESHOOTING] [System.GC]::Collect()

#########################################################################################################
# INGEST VIA DCR / LOG INGESTION API
# AzLogDcrIngestPS now handles batch sizing automatically (1 MB limit) with compression.
# No need for manual BatchSize splitting.
#########################################################################################################

Write-Sep
Write-Step "Ingesting into $TableName`_CL via Log Ingestion API"

$total = $totalCount

# Enable compression globally for this run
$global:EnableCompressionDefault = $true

#########################################################################################################
# STREAMING INGEST
# Read temp file in chunks of $IngestChunkSize, run through the native
# AzLogDcrIngestPS pipeline (ValidateFix -> Build-DataArray -> Post) per chunk.
#########################################################################################################

$IngestChunkSize = 10000   # records read per chunk - Post-* handles internal API batching

Write-Sep
Write-Step "Streaming ingest from temp file (chunk size: $IngestChunkSize)"

$ingestChunk      = [System.Collections.Generic.List[object]]::new()
$statsAccumulator = [System.Collections.Generic.List[object]]::new()
$ingestCounter    = 0
$chunkNum         = 0
$script:streamReader = [System.IO.StreamReader]::new($tempFile, [System.Text.Encoding]::UTF8)

$DnsName = [System.Net.Dns]::GetHostEntry('').HostName

try {
    while (-not $script:streamReader.EndOfStream) {
        $line = $script:streamReader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $row = $line | ConvertFrom-Json
        $clean = [ordered]@{}
        foreach ($prop in $row.PSObject.Properties) {
            $v = $prop.Value
            if ($null -eq $v)                                                              { $clean[$prop.Name] = "" }
            elseif ($v -is [bool])                                                         { $clean[$prop.Name] = [bool]$v }
            elseif ($v -is [int] -or $v -is [int32] -or $v -is [int64] -or $v -is [long]) { $clean[$prop.Name] = [int]$v }
            elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string]))  { $clean[$prop.Name] = [string](($v | ForEach-Object { [string]$_ }) -join ";") }
            else                                                                           { $clean[$prop.Name] = [string]$v }
        }
        $ingestChunk.Add([PSCustomObject]$clean)

        # Lightweight stats record - only the fields the summary needs
        $statsAccumulator.Add([PSCustomObject]@{
            ObjectType                    = $clean['ObjectType']
            EffectiveTier                 = $clean['EffectiveTier']
            IsPrivileged                  = $clean['IsPrivileged']
            IsPrivilegedEligible          = $clean['IsPrivilegedEligible']
            Azure_Delegations             = $clean['Azure_Delegations']
            IsStale                       = $clean['IsStale']
            MFARegistered                 = $clean['MFARegistered']
            AccountEnabled                = $clean['AccountEnabled']
            IsExternal                    = $clean['IsExternal']
            IsShadowAdmin                 = $clean['IsShadowAdmin']
            IsBreakGlass                  = $clean['IsBreakGlass']
            IsOrphan                      = $clean['IsOrphan']
            IsExternal_SPN                = $clean['IsExternal_SPN']
            IsManagedIdentityUserAssigned = $clean['IsManagedIdentityUserAssigned']
            EntraID_Roles                 = $clean['EntraID_Roles']
            EntraID_AppPermissions        = $clean['EntraID_AppPermissions']
            Workload_Credentials          = $clean['Workload_Credentials']
        })

        $ingestCounter++

        if ($ingestChunk.Count -ge $IngestChunkSize) {
            $chunkNum++
            Write-Progress -Id 3 -Activity "Ingesting" `
                -Status "Chunk $chunkNum | $ingestCounter / $total records" `
                -PercentComplete ([Math]::Round(($ingestCounter / [Math]::Max(1,$total)) * 100))

            $DataVariable = $ingestChunk.ToArray()

            # add CollectionTime to existing array
            $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable -Verbose:$false

            # add Computer, ComputerFqdn & UserLoggedOn info to existing array
            $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                                -Column1Name Computer     -Column1Data $Env:ComputerName `
                                -Column2Name ComputerFqdn -Column2Data $DnsName `
                                -Column3Name UserLoggedOn -Column3Data $Env:USERNAME `
                                -Verbose:$false

            # Validating/fixing schema data structure of source data
            $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$false

            # Aligning data structure with schema (requirement for DCR)
            $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable -Verbose:$false

            # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
            $ResultPost = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                              -DceName     $DceName `
                              -DcrName     $DcrName `
                              -Data        $DataVariable `
                              -TableName   $TableName `
                              -AzAppId     $IngestionSpnClientId `
                              -AzAppSecret $IngestionSpnClientSecret `
                              -TenantId    $TenantId `
                              -Verbose:$false

            $ingestChunk.Clear()
            [System.GC]::Collect()
        }
    }

    # Ingest final partial chunk
    if ($ingestChunk.Count -gt 0) {
        $chunkNum++
        $DataVariable = $ingestChunk.ToArray()

        # add CollectionTime to existing array
        $DataVariable = Add-CollectionTimeToAllEntriesInArray -Data $DataVariable -Verbose:$false

        # add Computer, ComputerFqdn & UserLoggedOn info to existing array
        $DataVariable = Add-ColumnDataToAllEntriesInArray -Data $DataVariable `
                            -Column1Name Computer     -Column1Data $Env:ComputerName `
                            -Column2Name ComputerFqdn -Column2Data $DnsName `
                            -Column3Name UserLoggedOn -Column3Data $Env:USERNAME `
                            -Verbose:$false

        # Validating/fixing schema data structure of source data
        $DataVariable = ValidateFix-AzLogAnalyticsTableSchemaColumnNames -Data $DataVariable -Verbose:$false

        # Aligning data structure with schema (requirement for DCR)
        $DataVariable = Build-DataArrayToAlignWithSchema -Data $DataVariable -Verbose:$false

        # Upload data to LogAnalytics using DCR / DCE / Log Ingestion API
        $ResultPost = Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output `
                          -DceName     $DceName `
                          -DcrName     $DcrName `
                          -Data        $DataVariable `
                          -TableName   $TableName `
                          -AzAppId     $IngestionSpnClientId `
                          -AzAppSecret $IngestionSpnClientSecret `
                          -TenantId    $TenantId `
                          -Verbose:$false

        $ingestChunk.Clear()
        [System.GC]::Collect()
    }
} finally {
    if ($script:streamReader) { $script:streamReader.Dispose(); $script:streamReader = $null }
}

Write-Progress -Id 3 -Activity "Ingesting" -Completed
Write-Ok "Ingest complete: $ingestCounter records in $chunkNum chunks"

#########################################################################################################
# JSON SIBLING + UPLOAD EXPORT
#
# The engine already streams every collected record to
#   OUTPUT\IdentityAssets_Collection.jsonl
# during collection. When $global:WriteJsonOutput is $true (default ON), the
# engine converts that JSONL into a standard JSON array at
#   OUTPUT\IdentityAssets_Collection.json
# (sibling of the .jsonl).
#
# When $global:ExportDestination is set, both files (the .jsonl and the .json)
# are uploaded to the destination. Destination type is auto-detected:
#   \\server\share\path\                                -> UNC share
#   https://<acct>.blob.core.windows.net/<container>/   -> Azure Storage blob
#########################################################################################################

if ($null -eq $global:WriteJsonOutput) { $global:WriteJsonOutput = $true }

$__jsonPath = $null
if ([bool]$global:WriteJsonOutput) {
    $__jsonPath = [System.IO.Path]::ChangeExtension($tempFile, 'json')
    Write-Sep
    Write-Step "Writing JSON sibling of the collection file"
    Write-Info ("path: {0}" -f $__jsonPath)
    try {
        # Read JSONL line-by-line and emit a single JSON array -- avoids loading
        # the whole dataset into memory twice.
        $__reader = [System.IO.StreamReader]::new($tempFile, [System.Text.Encoding]::UTF8)
        $__writer = [System.IO.StreamWriter]::new($__jsonPath, $false, [System.Text.Encoding]::UTF8)
        try {
            $__writer.Write('[')
            $__first = $true
            while (-not $__reader.EndOfStream) {
                $__line = $__reader.ReadLine()
                if ([string]::IsNullOrWhiteSpace($__line)) { continue }
                if (-not $__first) { $__writer.Write(',') }
                $__writer.Write($__line)
                $__first = $false
            }
            $__writer.Write(']')
        } finally {
            $__writer.Flush(); $__writer.Dispose()
            $__reader.Dispose()
        }
        Write-Ok ("json file ready: {0}" -f $__jsonPath)
    } catch {
        Write-Warn ("JSON export failed: {0} (continuing -- jsonl is still on disk)" -f $_.Exception.Message)
        $__jsonPath = $null
    }
}

if (-not [string]::IsNullOrWhiteSpace([string]$global:ExportDestination)) {
    . (Join-Path $PSScriptRoot '_shared\Send-SecurityInsightExportFile.ps1')
    Write-Sep
    Write-Step ("Uploading export files to: {0}" -f $global:ExportDestination)
    foreach ($localPath in @($tempFile, $__jsonPath)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$localPath)) {
            Send-ExportFile -LocalPath $localPath `
                -Destination          $global:ExportDestination `
                -IngestionSpnAppId    $IngestionSpnClientId `
                -IngestionSpnObjectId $spnObjectId
        }
    }
}

#########################################################################################################
# SUMMARY
# Derived from $statsAccumulator - a lightweight per-record snapshot built during ingest.
# $ingestChunk is cleared after each chunk so cannot be used here.
#########################################################################################################

Write-Sep
Write-Step "Ingestion complete"

# Partition by identity type
$recUsers = @($statsAccumulator | Where-Object { $_.ObjectType -eq 'User' })
$recSPNs  = @($statsAccumulator | Where-Object { $_.ObjectType -eq 'ServicePrincipal' })
$recMIs   = @($statsAccumulator | Where-Object { $_.ObjectType -eq 'ManagedIdentity' })

# Users
$usersPrivileged   = @($recUsers | Where-Object { $_.IsPrivileged         -eq $true })
$usersPrivEligible = @($recUsers | Where-Object { $_.IsPrivilegedEligible -eq $true })
$usersWithAzure    = @($recUsers | Where-Object { $_.Azure_Delegations    -ne '[]' -and $_.Azure_Delegations -ne '' })
$usersStale        = @($recUsers | Where-Object { $_.IsStale              -eq $true })
$usersNoMFA        = @($recUsers | Where-Object { $_.MFARegistered        -eq $false -and $_.AccountEnabled -eq $true -and $_.IsExternal -eq $false })
$usersShadowAdmin  = @($recUsers | Where-Object { $_.IsShadowAdmin        -eq $true })
$usersBreakGlass   = @($recUsers | Where-Object { $_.IsBreakGlass         -eq $true })
$usersExternal     = @($recUsers | Where-Object { $_.IsExternal           -eq $true })
$usersT0           = @($recUsers | Where-Object { $_.EffectiveTier        -eq 0 })
$usersT1           = @($recUsers | Where-Object { $_.EffectiveTier        -eq 1 })
$usersT2           = @($recUsers | Where-Object { $_.EffectiveTier        -eq 2 })
$usersT3           = @($recUsers | Where-Object { $_.EffectiveTier        -eq 3 })

# SPNs
$spnsWithRoles = @($recSPNs | Where-Object {
    try { ($_.EntraID_Roles | ConvertFrom-Json).Permanent.Count -gt 0 -or ($_.EntraID_Roles | ConvertFrom-Json).Eligible.Count -gt 0 } catch { $false }
})
$spnsWithPerms = @($recSPNs | Where-Object {
    try { ($_.EntraID_AppPermissions | ConvertFrom-Json).AppRoles.Count -gt 0 -or ($_.EntraID_AppPermissions | ConvertFrom-Json).Delegated.Count -gt 0 } catch { $false }
})
$spnsWithAzure    = @($recSPNs | Where-Object { $_.Azure_Delegations -ne '[]' -and $_.Azure_Delegations -ne '' })
$spnsOrphan       = @($recSPNs | Where-Object { $_.IsOrphan          -eq $true })
$spnsExternal     = @($recSPNs | Where-Object { $_.IsExternal_SPN    -eq $true })
$spnsShadow       = @($recSPNs | Where-Object { $_.IsShadowAdmin     -eq $true })
$spnsExpiredCreds = @($recSPNs | Where-Object {
    try { ($_.Workload_Credentials | ConvertFrom-Json).HasExpired -eq $true } catch { $false }
})
$spnsT0 = @($recSPNs | Where-Object { $_.EffectiveTier -eq 0 })
$spnsT1 = @($recSPNs | Where-Object { $_.EffectiveTier -eq 1 })
$spnsT2 = @($recSPNs | Where-Object { $_.EffectiveTier -eq 2 })
$spnsT3 = @($recSPNs | Where-Object { $_.EffectiveTier -eq 3 })

# MIs
$misWithRoles = @($recMIs | Where-Object {
    try { ($_.EntraID_Roles | ConvertFrom-Json).Permanent.Count -gt 0 -or ($_.EntraID_Roles | ConvertFrom-Json).Eligible.Count -gt 0 } catch { $false }
})
$misWithPerms = @($recMIs | Where-Object {
    try { ($_.EntraID_AppPermissions | ConvertFrom-Json).AppRoles.Count -gt 0 } catch { $false }
})
$misWithAzure    = @($recMIs | Where-Object { $_.Azure_Delegations             -ne '[]' -and $_.Azure_Delegations -ne '' })
$misUserAssigned = @($recMIs | Where-Object { $_.IsManagedIdentityUserAssigned -eq $true })
$misT0 = @($recMIs | Where-Object { $_.EffectiveTier -eq 0 })
$misT1 = @($recMIs | Where-Object { $_.EffectiveTier -eq 1 })
$misT2 = @($recMIs | Where-Object { $_.EffectiveTier -eq 2 })
$misT3 = @($recMIs | Where-Object { $_.EffectiveTier -eq 3 })

Write-Ok "Table          : $TableName`_CL"
Write-Ok "Total records  : $total  ($chunkNum chunks)"
Write-Host ""
Write-Host "  USERS ($userCount total)" -ForegroundColor Cyan
Write-Ok "    Tier 0 (critical)          : $($usersT0.Count)"
Write-Ok "    Tier 1 (privileged)        : $($usersT1.Count)"
Write-Ok "    Tier 2 (standard)          : $($usersT2.Count)"
Write-Ok "    Tier 3 (low / service)     : $($usersT3.Count)"
Write-Ok "    Privileged (active roles)  : $($usersPrivileged.Count)"
Write-Ok "    Privileged (PIM eligible)  : $($usersPrivEligible.Count)"
Write-Ok "    With Azure RBAC            : $($usersWithAzure.Count)"
Write-Ok "    Shadow admins              : $($usersShadowAdmin.Count)"
Write-Ok "    Break glass                : $($usersBreakGlass.Count)"
Write-Ok "    Stale (no sign-in)         : $($usersStale.Count)"
Write-Ok "    No MFA (enabled+internal)  : $($usersNoMFA.Count)"
Write-Ok "    External / B2B             : $($usersExternal.Count)"
Write-Host ""
Write-Host "  SERVICE PRINCIPALS ($($recSPNs.Count) total)" -ForegroundColor Cyan
Write-Ok "    Tier 0 (critical)          : $($spnsT0.Count)"
Write-Ok "    Tier 1 (privileged)        : $($spnsT1.Count)"
Write-Ok "    Tier 2 (standard)          : $($spnsT2.Count)"
Write-Ok "    Tier 3 (low / internal)    : $($spnsT3.Count)"
Write-Ok "    With Entra roles           : $($spnsWithRoles.Count)"
Write-Ok "    With API permissions       : $($spnsWithPerms.Count)"
Write-Ok "    With Azure RBAC            : $($spnsWithAzure.Count)"
Write-Ok "    Shadow admins              : $($spnsShadow.Count)"
Write-Ok "    Orphaned (no owner)        : $($spnsOrphan.Count)"
Write-Ok "    External (foreign tenant)  : $($spnsExternal.Count)"
Write-Ok "    Expired credentials        : $($spnsExpiredCreds.Count)"
Write-Host ""
Write-Host "  MANAGED IDENTITIES ($($recMIs.Count) total)" -ForegroundColor Cyan
Write-Ok "    Tier 0 (critical)          : $($misT0.Count)"
Write-Ok "    Tier 1 (privileged)        : $($misT1.Count)"
Write-Ok "    Tier 2 (standard)          : $($misT2.Count)"
Write-Ok "    Tier 3 (low / internal)    : $($misT3.Count)"
Write-Ok "    With Entra roles           : $($misWithRoles.Count)"
Write-Ok "    With API permissions       : $($misWithPerms.Count)"
Write-Ok "    With Azure RBAC            : $($misWithAzure.Count)"
Write-Ok "    User-assigned              : $($misUserAssigned.Count)"
Write-Host ""
Write-Host "  AZURE RBAC" -ForegroundColor Cyan
Write-Ok "    Total assignments          : $azureDelegationCount"
Write-Ok "    Unique principals          : $($azureDelegationLookup.Count)"
Write-Host ""
Write-Host "  Verify in Log Analytics:" -ForegroundColor Cyan
Write-Host "  $TableName`_CL" -ForegroundColor White
Write-Host "  | summarize Count=count() by ObjectType, EffectiveTier" -ForegroundColor White
Write-Host "  | order by EffectiveTier asc" -ForegroundColor White
Write-Host ""


#########################################################################################################
# HELPERS
#########################################################################################################

function Write-Step  ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan  }
function Write-Info  ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray  }
function Write-Ok    ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn  ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err2  ($m) { Write-Host "[ERR]  $m" -ForegroundColor Red   }
function Write-Sep         { Write-Host ("-" * 80) -ForegroundColor DarkGray }

# Returns $true if a subscription name matches ANY exclude pattern.
# Patterns are PowerShell wildcards (e.g. '*Azure for Students*').
# Empty/null pattern list => never excludes.
function Test-SubscriptionExcluded {
    param([string]$Name, [string[]]$Patterns)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        if ($Name -like $pat) { return $true }
    }
    return $false
}

function Invoke-Graph {
    param([string]$Uri, [string]$Method = "GET")
    # Use Invoke-RestMethod with the Bearer token read from script scope at call time.
    # $script:graphToken ensures we always get the current token even when dot-sourced.
    # Avoids Invoke-MgGraphRequest URL rewriting (strips beta base, adds v1.0).
    try {
        return Invoke-RestMethod -Method $Method -Uri $Uri `
               -Headers @{ "Authorization" = "Bearer $script:graphToken"; "Content-Type" = "application/json" } `
               -ErrorAction Stop
    } catch {
        $detail = $null
        try { $detail = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue) } catch {}
        if ($detail -and $detail.error -and $detail.error.message) { $errMsg = $detail.error.message } else { $errMsg = $_.Exception.Message }
        throw "[$Method $Uri] $errMsg"
    }
}

function Get-AllPages ([string]$Uri) {
    $items   = New-Object System.Collections.Generic.List[object]
    $nextUri = $Uri
    do {
        $r = Invoke-Graph -Uri $nextUri

        # Add values - handle both array and single object responses
        if ($r.value) { foreach ($v in $r.value) { $items.Add($v) } }

        # Get nextLink - Invoke-MgGraphRequest returns a Hashtable so check both ways
        $nextUri = $null
        if ($r -is [System.Collections.IDictionary]) {
            # Hashtable - use key access
            if ($r.ContainsKey('@odata.nextLink') -and $r['@odata.nextLink']) {
                $nextUri = $r['@odata.nextLink']
            }
        } elseif ($r.PSObject.Properties['@odata.nextLink']) {
            # PSCustomObject
            $nextUri = $r.PSObject.Properties['@odata.nextLink'].Value
        }
    } while ($nextUri)
    return $items
}

function Get-DaysSince ([object]$DateValue) {
    if (-not $DateValue) { return -1 }
    try { return [int]([datetime]::UtcNow - [datetime]::Parse($DateValue.ToString())).TotalDays }
    catch { return -1 }
}

function Get-TierFromEntraAPIPerms ([string[]]$Perms) {
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier0.Contains($p)) { return 0 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier1.Contains($p)) { return 1 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier2.Contains($p)) { return 2 } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier3.Contains($p)) { return 3 } }
    if ($Perms.Count -gt 0) { return 2 }  # has perms but none in catalog - treat as Tier 2
    return $null   # no perms = no signal, caller defaults
}

function Get-HighestRiskEntraAPIPermission ([string[]]$Perms) {
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier0.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier1.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier2.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($EntraID_APIPerms_Tier3.Contains($p)) { return $p } }
    $first = $Perms | Select-Object -First 1
    if ($null -ne $first) { return $first } else { return "" }
}

function Get-TierFromEntraRoles ([string[]]$Roles) {
    # Checks all four tiers in priority order - first match wins (lowest number = highest risk)
    # null : no roles at all -> caller defaults to tier 2
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($EntraID_Roles_Tier3 -contains $r) { return 3 } }
    if ($Roles.Count -gt 0) { return 2 }  # has roles but none in catalog - treat as Tier 2
    return $null
}

function Get-TierFromADGroups ([string[]]$Groups) {
    # O(1) lookup via catalog hashtable - returns lowest tier found across all matched groups
    $minTier = $null
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($entry) {
            $t = [int]$entry.Tier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier   # null = no catalog match
}

function Get-TierSourceFromADGroups ([string[]]$Groups) {
    # Returns the Name of the highest-risk catalog entry matched
    $best = $null
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($entry) {
            if ($null -eq $best -or [int]$entry.Tier -lt [int]$best.Tier) { $best = $entry }
        }
    }
    return if ($best) { [string]$best.Name } else { "" }
}

function Get-TierFromAzureRoles ([string[]]$Roles) {
    # Checks all four tiers in priority order - first match wins (lowest number = highest risk)
    # null : no Azure roles at all -> no signal, caller defaults
    foreach ($r in $Roles) { if ($Azure_Roles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($Azure_Roles_Tier3 -contains $r) { return 3 } }
    if ($Roles.Count -gt 0) { return 2 }  # has Azure roles but none in catalog - treat as Tier 2
    return $null
}

function Get-EntraRoleMatches ([string[]]$Roles) {
    # Returns all roles that matched a catalog entry, annotated with which tier they matched.
    # Proof: identity -> catalog entry -> tier
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Roles) {
        $t = if     ($EntraID_Roles_Tier0 -contains $r) { 0 }
             elseif ($EntraID_Roles_Tier1 -contains $r) { 1 }
             elseif ($EntraID_Roles_Tier2 -contains $r) { 2 }
             elseif ($EntraID_Roles_Tier3 -contains $r) { 3 }
             else                                        { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-EntraPermMatches ([string[]]$Perms) {
    # Returns all permissions that matched a catalog entry, annotated with tier.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $Perms) {
        $t = if     ($EntraID_APIPerms_Tier0.Contains($p)) { 0 }
             elseif ($EntraID_APIPerms_Tier1.Contains($p)) { 1 }
             elseif ($EntraID_APIPerms_Tier2.Contains($p)) { 2 }
             elseif ($EntraID_APIPerms_Tier3.Contains($p)) { 3 }
             else                                          { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Permission = $p; CatalogTier = $t }) }
    }
    return $matched
}

function Get-AzureRoleMatches ([string[]]$Roles) {
    # Returns all Azure roles that matched a catalog entry, annotated with tier.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Roles) {
        $t = if     ($Azure_Roles_Tier0 -contains $r) { 0 }
             elseif ($Azure_Roles_Tier1 -contains $r) { 1 }
             elseif ($Azure_Roles_Tier2 -contains $r) { 2 }
             elseif ($Azure_Roles_Tier3 -contains $r) { 3 }
             else                                      { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-ADGroupMatches ([string[]]$Groups) {
    # Match IdentityInfo GroupMembership names against AD_BuiltInPermissionGroups_Tier0-3 catalog.
    # Exact case-insensitive match on Name field. Tier and Reason are read from the catalog entry.
    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $catalogEntry = $AD_Groups_CatalogLookup[$g.ToLower()]
        if ($catalogEntry) {
            $matched.Add([ordered]@{
                Name   = [string]$catalogEntry.Name
                Tier   = [int]$catalogEntry.Tier
                Reason = [string]$catalogEntry.Reason
            })
        }
    }
    return $matched
}

function Get-AzureScopeLabel ([string]$Scope) {
    # Returns a human-readable label for the scope, including the resource name where possible.
    if ([string]::IsNullOrWhiteSpace($Scope)) { return "Unknown" }
    $s = $Scope.Trim().TrimEnd('/')
    if ($s -eq '' -or $s -eq '/')                                                              { return "Tenant Root" }
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$')               { return "Management Group: $($Matches[1])" }
    if ($s -match '^/subscriptions/([^/]+)$')                                                  { return "Subscription: $($Matches[1])" }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)$')                            { return "Resource Group: $($Matches[1])" }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/[^/]+/([^/]+)/([^/]+)')  { return "Resource: $($Matches[3]) ($($Matches[2]))" }
    if ($s -match '^/subscriptions/[^/]+/providers/(.+)$')                                    { return "Subscription Resource: $($Matches[1])" }
    return $Scope
}

function Get-AzurePrincipalRoleNames ([string]$ObjectId, [string[]]$MemberIds = @()) {
    # Returns all distinct Azure role names assigned to this principal (direct + inherited via groups).
    $names = [System.Collections.Generic.List[string]]::new()
    $allIds = @($ObjectId) + $MemberIds | Where-Object { $_ } | Select-Object -Unique
    foreach ($id in $allIds) {
        if ($azureDelegationLookup.ContainsKey($id)) {
            foreach ($e in $azureDelegationLookup[$id]) {
                $n = if ($e -is [System.Collections.IDictionary]) { [string]$e['RoleName'] } else { [string]$e.RoleName }
                if ($n -and -not $names.Contains($n)) { $names.Add($n) }
            }
        }
    }
    return $names.ToArray()
}

function Get-AzurePrincipalAssignments ([string]$ObjectId, [string[]]$MemberIds = @()) {
    # Returns full assignment detail for TierSources: role, scope label, scope level, tier.
    # Includes direct assignments and inherited via group membership / PIM for Groups.
    $assignments = [System.Collections.Generic.List[object]]::new()
    $allIds = @($ObjectId) + $MemberIds | Where-Object { $_ } | Select-Object -Unique
    foreach ($id in $allIds) {
        if (-not $azureDelegationLookup.ContainsKey($id)) { continue }
        foreach ($e in $azureDelegationLookup[$id]) {
            $roleName  = if ($e -is [System.Collections.IDictionary]) { [string]$e['RoleName']  } else { [string]$e.RoleName  }
            $scope     = if ($e -is [System.Collections.IDictionary]) { [string]$e['Scope']     } else { [string]$e.Scope     }
            $subName   = if ($e -is [System.Collections.IDictionary]) { [string]$e['SubscriptionName'] } else { [string]$e.SubscriptionName }
            $roleTier  = if ($e -is [System.Collections.IDictionary]) { $e['RoleTier']  } else { $e.RoleTier  }
            $scopeLvl  = if ($e -is [System.Collections.IDictionary]) { $e['ScopeLevel'] } else { $e.ScopeLevel }
            $effTier   = if ($e -is [System.Collections.IDictionary]) { $e['Tier']      } else { $e.Tier      }
            $isInher   = $id -ne $ObjectId

            $assignments.Add([ordered]@{
                Role             = $roleName
                Scope            = $scope
                ScopeLabel       = Get-AzureScopeLabel -Scope $scope
                SubscriptionName = $subName
                ScopeLevel       = $scopeLvl
                RoleTier         = $roleTier
                EffectiveTier    = $effTier
                InheritedViaGroup = $isInher
            })
        }
    }
    return $assignments
}

function Get-AzureScopeLevel ([string]$Scope) {
    # Resolves an Azure RBAC scope string to a risk level (0=highest, 3=lowest).
    # Risk decreases as scope narrows - same role is less impactful at a lower scope.
    #
    # Level 0 - Tenant root or root Management Group
    #           Scope: "/"  or  "/providers/Microsoft.Management/managementGroups/<tenantId>"
    # Level 1 - Management Group (non-root) or Subscription
    #           Scope: "/providers/Microsoft.Management/managementGroups/<name>"
    #                  "/subscriptions/<subId>"
    # Level 2 - Resource Group
    #           Scope: "/subscriptions/<subId>/resourceGroups/<rg>"
    # Level 3 - Individual resource (anything deeper)
    #           Scope: "/subscriptions/<subId>/resourceGroups/<rg>/providers/..."

    if ([string]::IsNullOrWhiteSpace($Scope)) { return 1 }   # unknown = treat as subscription level

    $s = $Scope.Trim().TrimEnd('/')

    # Tenant root
    if ($s -eq '' -or $s -eq '/') { return 0 }

    # Root management group (scope contains only one MG segment with no parent MG)
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') {
        # Determine if this is the root MG (same ID as tenant) - treat all top-level MGs as L0
        return 0
    }

    # Subscription only
    if ($s -match '^/subscriptions/[^/]+$') { return 1 }

    # Resource Group
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 2 }

    # Individual resource (anything deeper)
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/') { return 3 }

    # Subscription-level resource provider scope (no RG)
    if ($s -match '^/subscriptions/[^/]+/providers/') { return 1 }

    # Fallback
    return 1
}

function Get-AzureEffectiveTier ([string]$RoleName, [string]$Scope) {
    # Effective tier = Max(RoleTier, ScopeLevel)
    # The role defines the ceiling risk; scope can only reduce impact (raise tier number), never increase it.
    # Example: Owner (T0) at ResourceGroup scope -> Max(0, 2) = 2
    #          Owner (T0) at TenantRoot scope    -> Max(0, 0) = 0
    #          Reader (T3) at TenantRoot scope   -> Max(3, 0) = 3 (Reader is always low risk)
    $roleTier  = Get-TierFromAzureRoles -Roles @($RoleName)
    if ($null -eq $roleTier) { $roleTier = 2 }   # unknown role = standard
    $scopeLevel = Get-AzureScopeLevel -Scope $Scope
    return [Math]::Max($roleTier, $scopeLevel)
}

function Get-MinTier ([object[]]$Tiers) {
    # Returns the lowest (most privileged) tier from the supplied values.
    # Nulls and -1 are excluded (= no signal / not applicable).
    # Default is 3 - a user with no signals has no privileged access.
    $valid = @($Tiers | Where-Object { $_ -ne $null -and [int]$_ -ge 0 } | ForEach-Object { [int]$_ })
    if ($valid.Count -eq 0) { return 3 }
    return ($valid | Measure-Object -Minimum).Minimum
}

function To-JsonStr ([object]$obj) {
    # PS 5.1 ConvertTo-Json collapses single-element arrays to plain strings.
    # Recursively wrap any array values in a typed string array before serializing.
    function Protect-Arrays ([object]$o) {
        if ($o -is [System.Collections.IDictionary]) {
            $out = [ordered]@{}
            foreach ($k in $o.Keys) {
                $v = $o[$k]
                if ($v -is [System.Array] -or $v -is [System.Collections.IList]) {
                    # Force typed string array - ConvertTo-Json always emits [] for these
                    $out[$k] = [string[]]@($v | ForEach-Object { "$_" })
                } else {
                    $out[$k] = Protect-Arrays $v
                }
            }
            return $out
        }
        return $o
    }
    try {
        $safe = Protect-Arrays $obj
        return ($safe | ConvertTo-Json -Depth 5 -Compress)
    } catch { return '{}' }
}

function Join-Array ([object]$Value) {
    if (-not $Value) { return "" }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return ($Value | ForEach-Object { [string]$_ }) -join ";"
    }
    return [string]$Value
}

#########################################################################################################
# END OF PIPELINE -- explicit return so any future copy-paste accidents below this line stay unreachable.
# History (v2.1.29 -> v2.1.30): the file used to contain 4 sequential copies of the entire collection +
# ingest pipeline (~12k lines; each invocation ran the work 4x). Phase 1 was the canonical implementation;
# phases 2 and 3 were byte-identical paste duplicates and phase 4 was a truncated leftover. v2.1.30 deleted
# phases 2-4 (~8100 lines removed) leaving only this canonical phase. The 'return' below is a belt-and-
# braces guard against that recurring.
#########################################################################################################
return

