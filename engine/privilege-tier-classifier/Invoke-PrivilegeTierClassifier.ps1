#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Identity Tiering -- collects AD groups, Entra roles, API permissions,
    Azure roles; sends one AI request per category (4 total);
    exports a fully tiered JSON output file.

.DESCRIPTION
    Data collection:
      A) AD built-in group members (recursive, group-in-group)
      B) Entra ID role definitions -- built-in + custom (no assignments)
      C) API permission catalog from well-known Microsoft service principals (no grants)
      D) Azure built-in + custom role definitions (no assignments)

    AI tiering (4 batched calls -- one per category):
      1) AD built-in groups
      2) Entra ID roles (built-in + custom)
      3) Entra API permissions
      4) Azure RBAC roles
    Output:
      Single structured JSON file with all tier sections

.NOTES
    Solution       : SecurityInsight
    File           : Build_Tier_Definitions_JSON_File.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.


#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }


# #113a: Graph is reached over PURE REST now -- no Microsoft.Graph SDK. Forward slashes on purpose:
# this engine runs in a Linux container as well as on a Windows VM, and Join-Path emits the separator
# it is given, so a backslash literal survives into the path and fails only on Linux.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/Get-SIGraphToken.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared/SI-GraphRest.ps1')

# v2.2.233 -- SPN name bridge (defensive copy of Initialize-LauncherConfig).
# Mirrors $global:SI_SPN_* (v2.3 Setup Wizard output) onto the legacy
# $global:Spn* names this engine still reads, so the engine works when invoked
# outside the standard launcher path.
if ($global:SI_SPN_TenantId        -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
if ($global:SI_SPN_AppId           -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
if ($global:SI_SPN_Secret          -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
if ($global:SI_SPN_ObjectId        -and -not $global:SpnObjectId)              { $global:SpnObjectId              = [string]$global:SI_SPN_ObjectId }
if ($global:SI_SPN_CertThumbprint  -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }
# v2.2.278 -- bridge from internal-AutomateIT framework's HighPriv_Modern_*_Azure
# globals (set by Connect-Platform). SI_SPN_* > HighPriv_* precedence.
if ($global:HighPriv_Modern_TenantID                       -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:HighPriv_Modern_TenantID }
if ($global:HighPriv_Modern_ApplicationID_Azure            -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if ($global:HighPriv_Modern_ApplicationSecret_Azure        -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:HighPriv_Modern_ApplicationSecret_Azure }
if ($global:HighPriv_Modern_CertificateThumbprint_Azure    -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

# ============================================================
# CONFIGURATION (v2: launcher is source of truth)
# ============================================================

if (-not $global:SettingsPath -or [string]::IsNullOrWhiteSpace([string]$global:SettingsPath)) {
    $global:SettingsPath = $PSScriptRoot
}
if ($null -eq $global:AutomationFramework) { $global:AutomationFramework = $false }

# ----------------------------------------------------------------------
#  -WhatIfMode = a DRY RUN (#257). It used to REFUSE (#22: the switch had been inert -- a "dry run"
#  overwrote the tiered catalog every other engine reads). Now the roles and permissions are read and
#  tiered (the AI requests ARE sent -- that is the work being previewed) and the result is written to
#  a SEPARATE file beside the catalog (Get-PTCDryRunPath: <catalog>.dryrun.json). NOT written: the
#  catalog itself, its copy in the storage account, and the run-health row. A catalog missing locally
#  is not fetched from storage either.
# ----------------------------------------------------------------------
$script:PtcWhatIf = [bool]$global:WhatIfMode
function Get-PTCDryRunPath {
    <# PURE. Where a dry run writes its result: beside the catalog, never over it. #>
    param([Parameter(Mandatory)][string]$CatalogPath)
    $dir = [System.IO.Path]::GetDirectoryName($CatalogPath)
    $name = [System.IO.Path]::GetFileNameWithoutExtension($CatalogPath) + '.dryrun.json'
    if ([string]::IsNullOrEmpty($dir)) { return $name }
    return [System.IO.Path]::Combine($dir, $name)
}

if (-not [bool]$global:AutomationFramework) {
    # v2.2.233 -- accept either ClientSecret OR CertificateThumbprint. The old
    # check required Secret, breaking SPN+cert customers entirely.
    $hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    # #209: a container job signing in as its managed identity needs neither (the entry point set the switch).
    $hasMi     = [bool]((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity))
    if (-not $hasMi -and (
        [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
        (-not $hasSecret -and -not $hasCert))) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Launcher must set them or enable AutomationFramework."
    }
}

if ([bool]$global:AutomationFramework) {
    # --- Automation Framework branch (internal installs) ---
    # The platform identity, signed in by SecurityInsight itself over plain REST (no PowerShell module):
    # bootstrap\platform-config.json -> the platform Key Vault -> the platform identity, and the framework's
    # $global:HighPriv_* / $global:AzureTenantId names populated. The launcher normally did this already (its
    # configuration layer 1); then nothing is signed in twice.
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'auth/SI-PlatformConnect.ps1')
    $__platformCfg = Find-SIPlatformConfigPath -Start $PSScriptRoot
    if ($__platformCfg) {
        $global:PathScripts = Split-Path -Parent (Split-Path -Parent $__platformCfg)
        Write-Output ""
        Write-Output "Repo root          -> $($global:PathScripts)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$global:HighPriv_Modern_ApplicationID_Azure)) {
        $null = Connect-SIPlatform -Start $PSScriptRoot
    }
    Write-Output ("[INFO] Auth method (bootstrap)  : platform identity, {0}" -f $(if ($global:HighPriv_Modern_CertificateThumbprint_Azure) { 'certificate' } else { 'client secret' }))

    # Map AF-mode variables to the SPN globals the rest of this script expects.
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure
    if ($global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }
} else {
    # --- Community / standalone branch (SPN globals set by launcher) ---
    if (-not (Get-SIAzContext -ErrorAction SilentlyContinue)) {
        if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
            Connect-SIAzAccount -Identity -AccountId ([string]$global:SI_UAMI_ClientId) -WarningAction SilentlyContinue | Out-Null   # #209
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
            $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
            $credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $secretSecure)
            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
        } else {
            # Certificate-only SPN: the top-of-script check already guaranteed a thumbprint.
            Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -ApplicationId $global:SpnClientId `
                -CertificateThumbprint $global:SpnCertificateThumbprint -WarningAction SilentlyContinue | Out-Null
        }
    }
}

# Force TLS 1.2 for .NET Framework HTTP stack (PS 5.1 default can be TLS 1.0/1.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# 2026-05-02: silent defaults for AI batching globals so the per-chunk loop
# stops emitting [WARN] AI_ChunkSize / AI_MaxRetries / AI_MaxTokens lines on
# every batch when the launcher's locked config doesn't override them.
if (-not $global:AI_ChunkSize  -or [int]$global:AI_ChunkSize  -lt 1) { $global:AI_ChunkSize  = 50 }
if (-not $global:AI_MaxRetries -or [int]$global:AI_MaxRetries -lt 1) { $global:AI_MaxRetries = 5 }
if (-not $global:AI_MaxTokens  -or [int]$global:AI_MaxTokens  -lt 1) { $global:AI_MaxTokens  = 16384 }

# Output goes to v2.2/privilege-tier-catalog/ (the dedicated cross-engine catalog
# folder). The engine script lives at v2.2/engine/privilege-tier-classifier/ --
# two levels up reaches v2.2/, then 'privilege-tier-catalog/'. The catalog is
# CONSUMED by the asset-profiling engines (Identity/Endpoint/Azure) and the RA
# engine, so it lives in its own peer folder rather than under data/ or under
# this engine's own tree.
$_v22Root     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$OutputFolder = Join-Path $_v22Root 'privilege-tier-catalog'
if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# Write to .custom.json -- the customer overlay -- NOT .locked.json.
# .locked.json is the shipped baseline (Microsoft + AD core), updated via
# `git pull` (or whichever updater the operator runs). PTC output goes to
# .custom.json so:
#   1. Customer's tenant-specific tier choices survive `git pull`
#   2. Baseline updates (new Microsoft roles, new AD group conventions) still
#      flow through whenever the customer pulls the next release
#   3. Engine merges both at read time (custom wins on overlap, locked-only
#      keys still apply) -- see IdentityCatalogTierComputer.ps1 :: Initialize-SIIdentityCatalog
$OutputFile   = Join-Path $OutputFolder 'privilege-tier-catalog.custom.json'

# ============================================================
# AI SYSTEM PROMPT  tiering definitions and output contract
# ============================================================

$SystemPrompt = @"
You are a Microsoft security expert performing attacker-centric tiering of identities, groups, roles, and permissions.
Assign each item a criticality tier (0, 1, 2, or 3) based on:
"If I compromise this role/group/permission, how directly can I take over the entire tenant or domain?"

=== CRITICAL TIERING RULES  apply these before evaluating any item ===

The ONLY path to Tier 0 or Tier 1 is direct or near-direct control over:
  - Identity plane: ability to assign roles, reset credentials, modify MFA,
    impersonate admins, forge authentication tokens, or control authentication infrastructure
  - Directory plane: ability to replicate credentials, modify trust relationships,
    write to tier 0 AD objects, or manipulate authentication backends
  - Role plane: ability to grant yourself or others elevated permissions in the tenant or subscription

The following capabilities do NOT qualify for Tier 0 or Tier 1 on their own, regardless of scope:
  - Read or write access to mailboxes, calendars, contacts, or files  these are Tier 2 at most (data exfiltration, not tenant takeover)
  - Read or write access to Teams messages, SharePoint content, OneDrive, or documents
  - Ability to create or modify content, datasets, or documents
  - Ability to read or modify user profiles, photos, display names, or preferences
  - Ability to read audit logs, sign-in logs, risk events, or security reports
  - Ability to modify contacts, on-premises sync behavior of non-critical objects
  - Ability to flag, dismiss, or modify identity risk detections
  - Ability to read or write industry data, acronyms, or tenant-specific non-security data
  - IMAP, POP, or SMTP access to mailboxes  this enables data exfiltration but not credential theft or role assignment
  - Delegated permissions scoped to the signed-in user only  always Tier 3

Apply this test for every item before assigning a tier:
  "Can an attacker use THIS PERMISSION ALONE, or with ONE obvious and reliable pivot,
   to assign a Global Administrator role or dump all domain credential hashes?"
  If NO  it cannot be Tier 0 or Tier 1. Period.

=== TIER 0 - Immediate full environment compromise ===
Qualifying path: single permission or role directly yields full identity plane control with no additional steps.
Entra ID Roles: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Partner / GDAP Delegated Admin, Directory Synchronization Accounts, Hybrid Identity Administrator (when Entra Connect is in password hash sync mode)
Application Permissions (Graph / API): RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Policy.ReadWrite.AuthenticationMethod, PrivilegedAccess.ReadWrite.AzureAD, RoleManagement.ReadWrite.CloudPC, Organization.ReadWrite.All, Domain.ReadWrite.All, CrossTenantUserProfileSharing.ReadWrite.All, OnPremDirectorySynchronization.ReadWrite.All
Azure Built-in Roles: Owner (root management group), User Access Administrator (root management group), Owner (tenant root subscription)
Azure Permissions: Contributor + blueprint assign (root MG), Managed Identity Contributor (root scope), Entra ID joined device with Global Admin token cache, Subscription Owner with Az AD write federation
AD Built-in Groups: Domain Admins, Enterprise Admins, Schema Admins, Administrators (builtin), Group Policy Creator Owners, Cert Publishers, Domain Controllers group
AD Permissions: Replication rights (DCSync), DnsAdmins (with DC write), SYSTEM on any DC
Accounts: krbtgt account, SYSTEM on DC, Entra Connect sync account (MSOL_), ADConnect service account, Break-glass emergency access accounts, Service accounts with DCSync rights, Accounts with AdminSDHolder propagated ACLs

=== TIER 1 - High impact, one or two reliable pivots to full compromise ===
Qualifying path: permission enables a well-documented, reliable attack chain to full identity plane control (e.g. reset admin MFA, modify auth policy, write to privileged AD objects, manipulate app registrations that hold T0 permissions).
Entra ID Roles: Authentication Administrator, Hybrid Identity Administrator, Exchange Administrator, Cloud App Administrator, Application Administrator, Security Administrator, Intune Administrator, Identity Governance Administrator, External Identity Provider Administrator, B2C IEF Policy Administrator, Domain Name Administrator, Password Administrator (when targeting admins), Helpdesk Administrator (when targeting admins), Billing Administrator, Azure DevOps Administrator, Windows 365 Administrator
Application Permissions (Graph / API): Application.ReadWrite.All, Mail.ReadWrite (app  all users), User.ReadWrite.All, Group.ReadWrite.All, Sites.FullControl.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementApps.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, ServicePrincipalEndpoint.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.PermissionGrant, EntitlementManagement.ReadWrite.All, PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, AuthenticationContext.ReadWrite.All, TrustFrameworkKeySet.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, IdentityProvider.ReadWrite.All, Organization.ReadWrite.All, Domain.ReadWrite.All, AccessReview.ReadWrite.All, Agreement.ReadWrite.All, RoleEligibilitySchedule.ReadWrite.Directory, RoleAssignmentSchedule.ReadWrite.Directory
AD Built-in Groups: Account Operators, Backup Operators, Server Operators, Print Operators
AD Permissions: GPO edit rights on tier 0 OUs, AdminSDHolder write access, msDS-KeyCredentialLink write, WriteOwner on domain root, WriteDACL on domain root, GenericAll on tier 0 groups, GenericWrite on Domain Controllers OU, AllExtendedRights on domain root, ForceChangePassword on admin accounts, Manage CA (AD CS), Certificate enrollment agents, ESC1-ESC8 vulnerable certificate templates, SeBackupPrivilege holders, SeRestorePrivilege holders, SeTakeOwnershipPrivilege holders, SeDebugPrivilege on DC, SeImpersonatePrivilege on DC, Unconstrained delegation, Shadow Credentials write on admin accounts, SID History injection rights, GPO link rights on tier 0 OUs, OU owner on Domain Controllers OU
Accounts: Entra Connect service account, High-privilege service principals with T0 Graph permissions, Admin-consented OAuth apps with T1 permissions, AD CS enrollment agent accounts, Service accounts with unconstrained delegation, Accounts with GenericAll on tier 0 objects, Federated identity credentials on high-privilege app registrations, Managed identities with Owner or UAA at subscription scope, Workload identities bound to high-privilege Azure RBAC roles, Azure Automation Run As accounts, Service principals with client secrets in Key Vault accessible to lower-trust identities

=== TIER 2 - Significant data or workload impact, no direct identity plane path ===
Qualifying path: permission enables mass data exfiltration across the tenant, manipulation of security-relevant settings short of identity plane control, or escalation only when additional unrelated misconfigurations are present.
Entra ID Roles: User Administrator, Groups Administrator, Conditional Access Administrator, SharePoint Administrator, Teams Administrator, Lifecycle Workflows Administrator
Application Permissions (Graph / API): Mail.Read (app  all users), Mail.ReadWrite (app  all users only when no better option exists), Calendars.ReadWrite (app  all users), Files.ReadWrite.All, AuditLog.Read.All, IdentityRiskyUser.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, IMAP.AccessAsApp, POP.AccessAsApp, SMTP.Send (app  all users)
Azure Built-in Roles: Network Contributor, Log Analytics Contributor, Automation Operator, Azure DevOps stakeholder, Azure Kubernetes Service Cluster User
Azure Permissions: Contributor (single non-sensitive resource group), Storage Blob Data Reader (scoped), Log Analytics Reader, Monitoring Reader, Security Reader (Defender for Cloud)
AD Built-in Groups: DNS Admins
AD Permissions: OU-scoped write ACLs, LAPS read rights, Constrained delegation (msDS-AllowedToDelegateTo), RBCD write rights, Kerberoastable high-priv SAs
Accounts: High-privilege service principals scoped to workload, Admin-consented OAuth apps with scoped permissions, Automation accounts with limited RBAC, Azure DevOps service connections scoped to single subscription

=== TIER 3 - Low blast radius, no realistic escalation path ===
Qualifying path: read-only access, self-scoped delegated access, or write access to non-security non-identity data with no documented escalation path even with misconfigurations chained.
Entra ID Roles: Global Reader, Security Reader, Reports Reader, Message Center Reader, Usage Summary Reports Reader, Directory Readers, Guest User (default)
Application Permissions (Graph / API): User.Read (delegated), Mail.Read (delegated  self only), Calendars.Read (delegated  self only), Directory.Read.All, AuditLog.Read.All (delegated), IdentityRiskEvent.Read.All, Contacts.Read, Contacts.ReadWrite, Contacts.Read.Shared, Contacts.ReadWrite.Shared, Content.Create, Content.DelegatedWriter, Content.DelegatedReader, Content.Process.User, IdentityUserFlow.Read.All, IdentityUserFlow.ReadWrite.All, IndustryData.ReadBasic.All, IndustryData-DataConnector.Read.All, activitydata.tenant.read, Acronym.Read.All, Notes.Read, Notes.ReadWrite, Calendars.Read, Calendars.ReadWrite (delegated  self only), Files.Read, Files.ReadWrite (delegated  self only), Tasks.Read, Tasks.ReadWrite, People.Read, People.ReadWrite
Azure Built-in Roles: Reader (subscription or resource group), Billing Reader, Cost Management Reader, Tag Contributor
Azure Permissions: Storage Blob Data Reader (scoped, non-sensitive), Managed Identity with Reader only, Service principal with Reader on isolated resource group
AD Built-in Groups: Domain Users (default), Read-only DC (RODC)
AD Permissions: Scoped helpdesk OU read, GenericRead on non-priv objects
Accounts: Standard user accounts, Guest accounts, Read-only service accounts, Managed identities with no RBAC, Expired or disabled service principals

=== SPECIAL IDENTITY GROUPS (implicit - no direct AD membership) ===
Everyone, Authenticated Users, Creator Owner, Network, Interactive, Service, Dialup, Anonymous Logon, Batch, SELF, SYSTEM, Local Service, Network Service
Tier these based on access implications  typically Tier 2-3 unless misconfigured.

=== FINAL CALIBRATION CHECK  apply before returning each result ===
Before assigning Tier 0 or Tier 1, confirm:
  1. Does this permission touch the identity plane (role assignment, credential reset, MFA, auth policy, AD object write)?
  2. Is the escalation path direct and reliable  not theoretical or dependent on rare misconfigurations?
If both answers are not YES  downgrade to Tier 2 or Tier 3.
Mailbox access, file access, contact write, content creation, risk event modification, and protocol access (IMAP/POP/SMTP)
are NEVER Tier 0 or Tier 1 on their own. They are data plane, not identity plane.

=== OUTPUT CONTRACT ===
You will receive a JSON array of items to evaluate. Each item has a Name and optional context fields.
You MUST return a valid JSON array  one object per input item  with NO additional text, NO markdown fences.
Each object must have exactly:
  "Name"   : the exact name from the input
  "Tier"   : integer 0, 1, 2, or 3
  "Reason" : 1-2 sentence attacker-centric justification focused on the identity/tenant takeover path

Example output:
[
  {"Name": "Domain Admins", "Tier": 0, "Reason": "Direct full AD compromise via unrestricted domain admin rights."},
  {"Name": "DNS Admins", "Tier": 2, "Reason": "Can load arbitrary DLL into DNS service running on DC, enabling code execution as SYSTEM  requires DC access to be useful."},
  {"Name": "Contacts.ReadWrite", "Tier": 3, "Reason": "Write access to contacts only; no path to identity plane control or credential access."},
  {"Name": "IMAP.AccessAsApp", "Tier": 2, "Reason": "Enables full mailbox read across all users via IMAP  mass data exfiltration risk but no identity plane access or credential theft path."}
]
"@

# ============================================================
# BUILT-IN AD GROUPS TO SCAN
# ============================================================

$BuiltInADGroups = @(
    "Administrators", "Users", "Guests", "Print Operators", "Backup Operators",
    "Replicator", "Remote Desktop Users", "Network Configuration Operators",
    "Performance Monitor Users", "Performance Log Users", "Distributed COM Users",
    "IIS_IUSRS", "Cryptographic Operators", "Event Log Readers",
    "Certificate Service DCOM Access", "RDS Remote Access Servers",
    "RDS Endpoint Servers", "RDS Management Servers", "Hyper-V Administrators",
    "Access Control Assistance Operators", "Remote Management Users",
    "Storage Replica Administrators", "Server Operators", "Account Operators",
    "Pre-Windows 2000 Compatible Access", "Incoming Forest Trust Builders",
    "Windows Authorization Access Group", "Terminal Server License Servers",
    "Domain Admins", "Domain Users", "Domain Guests", "Domain Computers",
    "Domain Controllers", "Schema Admins", "Enterprise Admins",
    "Group Policy Creator Owners", "Read-only Domain Controllers",
    "Enterprise Read-only Domain Controllers", "Cloneable Domain Controllers",
    "Protected Users", "Key Admins", "Enterprise Key Admins",
    "DnsAdmins", "DnsUpdateProxy", "Cert Publishers", "RAS and IAS Servers",
    "Allowed RODC Password Replication Group", "Denied RODC Password Replication Group",
    "Enterprise Domain Controllers",
    "Everyone", "Authenticated Users", "Creator Owner", "Network", "Interactive",
    "Service", "Dialup", "Anonymous Logon", "Batch", "Proxy", "SELF",
    "Creator Group", "Local Service", "Network Service", "Remote Interactive Logon",
    "This Organization", "Other Organization", "IUSR", "SYSTEM", "Terminal Server User"
)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        default   { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Sanitize-ForJson {
    param([string]$s)
    if ([string]::IsNullOrEmpty($s)) { return "" }
    $clean = [System.Text.StringBuilder]::new($s.Length)
    foreach ($c in $s.ToCharArray()) {
        $code = [int]$c
        if ($code -eq 9) {
            [void]$clean.Append(' ')
        } elseif ($code -eq 10 -or $code -eq 13) {
            [void]$clean.Append(' ')
        } elseif ($code -ge 32) {
            [void]$clean.Append($c)
        }
    }
    return $clean.ToString().Trim()
}

function Connect-GraphWithSPN {
    <#
        Acquire a Graph token for this run. PURE REST -- no Microsoft.Graph SDK (#113).

        🔑 There is no "connection" to make any more, so this acquires and caches a token instead.
        `Get-SIGraphToken` is the solution's ONE token path and holds its own expiry-aware cache, so
        calling this repeatedly is still idempotent -- which is what the old Get-MgContext check was
        for.

        🪤 THE GLOBAL NAMES DIFFER, AND THAT BRIDGE IS THE WHOLE RISK IN THIS FUNCTION. This engine
        carries the SPN in $global:SpnClientId / SpnClientSecret / SpnTenantId; `Get-SIGraphToken`
        reads $global:SI_SPN_AppId / SI_SPN_Secret / SI_SPN_TenantId. Without the bridge the token
        helper falls through to a DIFFERENT identity (or none) and the failure surfaces later as a
        403 on a role query -- an authorization error that is really a configuration error, which is
        the most expensive kind to read. Only set what is missing: in a container the entrypoint has
        already populated the SI_SPN_* names from env vars, and overwriting them there would replace
        the Container App Job's identity with this engine's.
    #>
    if (-not $global:SI_SPN_AppId    -and $global:SpnClientId)     { $global:SI_SPN_AppId    = $global:SpnClientId }
    if (-not $global:SI_SPN_Secret   -and $global:SpnClientSecret) { $global:SI_SPN_Secret   = $global:SpnClientSecret }
    if (-not $global:SI_SPN_TenantId -and $global:SpnTenantId)     { $global:SI_SPN_TenantId = $global:SpnTenantId }
    if (-not $global:SI_SPN_CertThumbprint -and $global:SpnCertificateThumbprint) { $global:SI_SPN_CertThumbprint = $global:SpnCertificateThumbprint }

    $script:PtcGraphToken = Get-SIGraphToken -Resource Graph
    if (-not $script:PtcGraphToken) { throw 'Get-SIGraphToken returned no token for Graph.' }
    Write-Log "Acquired Microsoft Graph token (REST, no SDK)" "SUCCESS"
    $ptcGraphHow = if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
        'managed identity' + $(if ($global:SI_UAMI_ClientId) { ' (user-assigned ' + $global:SI_UAMI_ClientId + ')' } else { ' (system-assigned)' })
    } else { 'service principal ' + $global:SI_SPN_AppId }
    Write-Log ("Auth method (Graph)        : {0}, token via REST  (tenant={1})" -f $ptcGraphHow, $global:SI_SPN_TenantId) "INFO"
}

function Connect-AzWithSPN {
    # Idempotent: if an Az context already exists for our SPN, no-op.
    try {
        $ctx = Get-SIAzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account.Id -eq $global:SpnClientId -and $ctx.Subscription) {
            Write-Log "Azure already connected as SPN $($global:SpnClientId) (subscription=$($ctx.Subscription.Name))" "INFO"
            Write-Log "Auth method (Azure)        : already connected (re-using existing session)" "INFO"
            return
        }
    } catch {}
    # -WarningAction SilentlyContinue suppresses the "TenantId contains more than
    # one active subscription. First one will be selected" + "To override... use
    # Update-AzConfig" noise on every run; we explicitly select a subscription
    # below so the auto-pick doesn't matter.
    if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
        # #209: the container job's managed identity. The entry point normally connected already.
        if (-not (Get-SIAzContext -ErrorAction SilentlyContinue)) {
            Connect-SIAzAccount -Identity -AccountId ([string]$global:SI_UAMI_ClientId) -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        }
        $azAuthLabel = 'managed identity'
    } elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)) {
        $secureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credential   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secureSecret)
        Connect-SIAzAccount -ServicePrincipal -TenantId $global:SpnTenantId -Credential $credential -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        $azAuthLabel = 'SPN + Secret'
    } else {
        Connect-SIAzAccount -ServicePrincipal -TenantId $global:SpnTenantId -ApplicationId $global:SpnClientId `
            -CertificateThumbprint $global:SpnCertificateThumbprint -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
        $azAuthLabel = 'SPN + Certificate'
    }
    Write-Log "Connected to Azure" "SUCCESS"
    Write-Log ("Auth method (Azure)        : {2}  (clientId={0}, tenant={1})" -f $global:SpnClientId, $global:SpnTenantId, $azAuthLabel) "INFO"

    # Pick a default subscription so Get-AzRoleDefinition has a scope to read against.
    # Without a subscription selected, Get-AzRoleDefinition (no -Scope) returns an
    # empty result silently even when the SPN has Reader at tenant-root MG -- which
    # was why Azure_BuiltInRoles_Tier0..3 + Azure_Roles_Catalog were empty
    # (reproducible repro in v2.1.174 and earlier; fixed in v2.1.175).
    try {
        $ctx = Get-SIAzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or -not $ctx.Subscription) {
            $firstSub = Get-SIAzSubscription -TenantId $global:SpnTenantId -ErrorAction Stop | Select-Object -First 1
            if ($firstSub) {
                Set-SIAzContext -SubscriptionId $firstSub.Id -TenantId $global:SpnTenantId -ErrorAction Stop | Out-Null
                Write-Log ("Default subscription set: {0} ({1})" -f $firstSub.Name, $firstSub.Id) "INFO"
            } else {
                Write-Log "SPN has no accessible subscriptions -- Get-AzRoleDefinition may return empty. Grant the SPN 'Reader' at tenant-root MG (or any subscription) and re-run." "WARN"
            }
        }
    } catch {
        Write-Log "Could not auto-select a subscription for the SPN: $_" "WARN"
    }
}

# ============================================================
# AI SINGLE CHUNK CALL  sends one chunk, returns parsed array
# ============================================================

function Get-PTCRetryDelaySeconds {
    # Seconds to wait before the next AI attempt. A 429/503 carrying Retry-After is honoured
    # (both editions: PS 5.1 exposes a header indexer, pwsh 7 a typed RetryAfter); otherwise
    # exponential 5, 10, 20, 40 -- capped at 60s.
    param($ErrorRecord, [int]$Attempt)
    $fallback = [int][Math]::Min(60, 5 * [Math]::Pow(2, [Math]::Max(0, $Attempt - 1)))
    try {
        $resp = $ErrorRecord.Exception.Response
        if ($null -eq $resp) { return $fallback }
        $secs = $null
        $typed = $null
        try { $typed = $resp.Headers.RetryAfter } catch {}
        if ($typed) {
            if ($typed.Delta) { $secs = $typed.Delta.TotalSeconds }
            elseif ($typed.Date) { $secs = ($typed.Date.UtcDateTime - [datetime]::UtcNow).TotalSeconds }
        }
        if ($null -eq $secs) {
            $raw = $null
            try { $raw = [string]$resp.Headers['Retry-After'] } catch {}
            $n = 0
            if ($raw -and [int]::TryParse($raw.Trim(), [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) { $secs = $n }
        }
        if ($null -ne $secs -and $secs -ge 0) { return [int][Math]::Min(120, [Math]::Ceiling($secs) + 1) }
    } catch {}
    return $fallback
}

function Restore-PTCPriorTiers {
    <#
        KEEP WHAT WAS KNOWN. An AI chunk that fails (throttle, outage, missing config) or is turned
        off returns its items as Tier 99, and the catalog is then REWRITTEN. The consumer
        (Initialize-SIIdentityCatalog) reads only the Tier 0-3 sections, and a tenant's CUSTOM roles
        exist nowhere but this file -- so one bad AI night silently removed every custom Tier-0 role
        from classification, and the identities holding them lost their tier.

        For every item still at Tier 99 this looks up the tier it had in the previous catalog (same
        key the consumer uses) and keeps it, saying so in the Reason. An item that had no tier
        before stays 99 -- that is a genuinely new, unreviewed role. Returns the number restored.
    #>
    param([Parameter(Mandatory)][hashtable]$Tiered, [string]$PriorPath)
    if ([string]::IsNullOrWhiteSpace($PriorPath) -or -not (Test-Path -LiteralPath $PriorPath)) { return 0 }
    try {
        $prior = Get-Content -LiteralPath $PriorPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Write-Log ("Previous catalog could not be read ({0}) -- unresolved items stay unreviewed this run." -f $_.Exception.Message) "WARN"
        return 0
    }
    if ($null -eq $prior) { return 0 }

    $spec = @(
        @{ Cat = 'ADGroups';   Key = 'Name';        Sections = @('AD_BuiltInPermissionGroups') },
        @{ Cat = 'EntraRoles'; Key = 'DisplayName'; Sections = @('EntraID_BuiltInRoles','EntraID_CustomRoles') },
        @{ Cat = 'APIPerms';   Key = 'Value';       Sections = @('EntraID_APIPermissions') },
        @{ Cat = 'AzureRoles'; Key = 'Name';        Sections = @('Azure_BuiltInRoles','Azure_CustomRoles') }
    )
    $restored = 0
    foreach ($s in $spec) {
        $map = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sec in $s.Sections) {
            foreach ($t in 0..3) {
                $p = $prior.PSObject.Properties["$($sec)_Tier$t"]
                if (-not $p) { continue }
                foreach ($row in @($p.Value)) {
                    if ($null -eq $row) { continue }
                    $k = [string]$row.($s.Key)
                    if (-not [string]::IsNullOrWhiteSpace($k) -and -not $map.ContainsKey($k.Trim())) {
                        $map[$k.Trim()] = [pscustomobject]@{ Tier = $t; Reason = [string]$row.Reason }
                    }
                }
            }
        }
        foreach ($item in @($Tiered[$s.Cat])) {
            if ($null -eq $item -or [int]$item.Tier -ne 99) { continue }
            $k = [string]$item.($s.Key)
            if ([string]::IsNullOrWhiteSpace($k)) { continue }
            $hit = $null
            if ($map.TryGetValue($k.Trim(), [ref]$hit)) {
                $item.Tier   = [int]$hit.Tier
                $item.Reason = ('{0} (kept from the previous catalog -- not re-evaluated this run)' -f $hit.Reason).Trim()
                $restored++
            }
        }
    }
    return $restored
}

function Get-PTCInputFingerprint {
    <#
        PURE. A fingerprint of EVERYTHING the tiered catalog is made from: the Entra role definitions, the API permission
        catalog and the Azure role definitions as collected this run (each sorted, so the order Graph / ARM return them in
        does not matter), the built-in AD group names, the engine's own code (its prompts and hardcoded lists change with a
        release), whether AI runs, and the AI deployment. Same fingerprint = the AI pass would be sent the same input.
        Collecting the inputs costs seconds (2 Graph lists, 14 service-principal lookups, 2 ARM lists); the AI pass is the
        minutes. Returns 'sha256:<hex>'.
    #>
    param([array]$EntraRoles = @(), [array]$APIPermissions = @(), [array]$AzureRoles = @(), [string[]]$ADGroups = @(),
          [string]$EngineHash = '', [string]$RunAI = '', [string]$AIDeployment = '')
    $s = { param($v) if ($null -eq $v) { '' } else { [string]$v } }
    $list = { param($v) (@(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ } | Sort-Object -Culture '' -CaseSensitive)) -join ',' }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($EntraRoles | Where-Object { $_ })) { $lines.Add(('E|{0}|{1}|{2}|{3}|{4}' -f (& $s $r.Id), (& $s $r.DisplayName), (& $s $r.Description), [bool]$r.IsBuiltIn, (& $list $r.Permissions))) }
    foreach ($p in @($APIPermissions | Where-Object { $_ })) { $lines.Add(('P|{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f (& $s $p.AppId), (& $s $p.ServicePrincipal), (& $s $p.PermissionType), (& $s $p.Id), (& $s $p.Value), (& $s $p.DisplayName), (& $s $p.Description))) }
    foreach ($r in @($AzureRoles | Where-Object { $_ })) { $lines.Add(('A|{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f (& $s $r.Id), (& $s $r.Name), (& $s $r.Description), [bool]$r.IsCustom, (& $list $r.Actions), (& $list $r.NotActions), (& $list $r.DataActions))) }
    foreach ($g in @($ADGroups | Where-Object { $_ } | Select-Object -Unique)) { $lines.Add(('G|{0}' -f $g)) }
    $sorted = @($lines | Sort-Object -Culture '' -CaseSensitive)
    $text = (@('engine=' + $EngineHash, 'runAI=' + $RunAI, 'deployment=' + $AIDeployment) + $sorted) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    'sha256:' + (($h | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-PTCCatalogState {
    <# What the previous catalog says about itself: @{ Fingerprint; GeneratedUtc; Complete } ($null when there is no
       readable catalog). A catalog written before fingerprints has none -- the next run rebuilds once and records it. #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }
    try { $j = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json } catch { return $null }
    if ($null -eq $j -or -not $j.PSObject.Properties['Metadata'] -or $null -eq $j.Metadata) { return $null }
    $m = $j.Metadata
    $gen = $null
    if ($m.PSObject.Properties['GeneratedAtUtc'] -and "$($m.GeneratedAtUtc)") {
        try { $gen = ([datetime]::Parse([string]$m.GeneratedAtUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } catch { $gen = $null }
    }
    if ($null -eq $gen) { $gen = (Get-Item -LiteralPath $Path).LastWriteTimeUtc }
    [pscustomobject]@{ Fingerprint = $(if ($m.PSObject.Properties['InputFingerprint']) { [string]$m.InputFingerprint } else { '' })
                       GeneratedUtc = $gen
                       Complete = [bool]($m.PSObject.Properties['Complete'] -and [bool]$m.Complete) }
}

function Get-PTCUnchangedDecision {
    <#
        PURE. May this run skip the AI pass and keep the catalog it has? @{ Skip; Reason }. Only when ALL hold:
          * the setting allows it (-MaxAgeDays > 0; SI_PrivilegeTierClassifier_RefreshDays, default 7) and no forced rebuild;
          * this run's inputs were collected in full (-CollectionOk: no section came back empty);
          * the previous catalog has a fingerprint and it equals this run's (-Fingerprint);
          * the previous catalog was complete -- every item tiered, nothing kept from an older catalog (rule 4: a catalog an
            AI failure left open is never frozen as if it were whole);
          * it is younger than -MaxAgeDays -- so it is still rebuilt at least once a week whatever the fingerprint says.
        Reason is the one line the run logs (a skip: 'skipped: unchanged since <date>').
    #>
    param($Prior, [string]$Fingerprint, [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxAgeDays = 7, [bool]$Force = $false, [bool]$CollectionOk = $true)
    $no = { param($why) [pscustomobject]@{ Skip = $false; Reason = $why } }
    if ($Force) { return (& $no 'a rebuild is forced (ForcePrivilegedTierProfilerRebuild)') }
    if ($MaxAgeDays -le 0) { return (& $no 'the unchanged-input skip is off (SI_PrivilegeTierClassifier_RefreshDays = 0): rebuilt every run') }
    if (-not $CollectionOk) { return (& $no 'not every input could be collected this run -- rebuilt, and this run is not recorded as unchanged') }
    if ($null -eq $Prior) { return (& $no 'there is no previous catalog to compare with') }
    if (-not "$($Prior.Fingerprint)") { return (& $no 'the previous catalog has no input fingerprint (written before they were recorded) -- rebuilt once') }
    if ([string]$Prior.Fingerprint -ne $Fingerprint) { return (& $no 'the roles, permissions or the engine changed since the previous catalog') }
    if (-not [bool]$Prior.Complete) { return (& $no 'the previous catalog left items untiered or kept from an older catalog -- they are tiered again') }
    $age = ($NowUtc - ([datetime]$Prior.GeneratedUtc).ToUniversalTime()).TotalDays
    if ($age -ge $MaxAgeDays) { return (& $no ('the catalog is {0:n1} days old -- rebuilt at least every {1} days' -f $age, $MaxAgeDays)) }
    [pscustomobject]@{ Skip = $true; Reason = ('skipped: unchanged since {0:yyyy-MM-dd HH:mm} UTC (the roles, permissions and engine are the same; rebuilt at the latest after {1} days)' -f ([datetime]$Prior.GeneratedUtc).ToUniversalTime(), $MaxAgeDays) }
}

function Get-PTCOpenItemCount {
    <# PURE. How many items of the tiered result are still untiered (Tier 99 -- an AI chunk failed or AI is off, and no
       earlier catalog knew them). A catalog with any is not complete. #>
    param([hashtable]$Tiered)
    if ($null -eq $Tiered) { return 0 }
    $n = 0
    foreach ($k in @('ADGroups', 'EntraRoles', 'APIPerms', 'AzureRoles')) { foreach ($i in @($Tiered[$k])) { if ($null -ne $i -and [int]$i.Tier -eq 99) { $n++ } } }
    $n
}

function Get-PTCRefreshDays {
    <# The setting SI_PrivilegeTierClassifier_RefreshDays: a whole number 0-365 (0 = rebuild every run); anything else = 7. #>
    param($Value = $global:SI_PrivilegeTierClassifier_RefreshDays)
    $n = 0
    if ($null -ne $Value -and "$Value".Trim() -and [int]::TryParse("$Value".Trim(), [ref]$n) -and $n -ge 0 -and $n -le 365) { return $n }
    7
}

function Invoke-AISingleChunk {
    param(
        [string]$CategoryName,
        [array]$Chunk,
        [int]$ChunkIndex,
        [int]$TotalChunks
    )

    $label     = if ($TotalChunks -gt 1) { "$CategoryName (chunk $ChunkIndex/$TotalChunks)" } else { $CategoryName }

    # AI TURNED OFF MEANS NOTHING IS SENT. SI_PrivilegeTierClassifier_RunAI is documented in the
    # shipped config and was read by nothing, so role and permission text still went to Azure
    # OpenAI for a customer who had switched AI off. This is the single place a request is built,
    # so the check lives here. Items come back unresolved; Main then keeps the tier each one had
    # in the previous catalog (Restore-PTCPriorTiers), so turning AI off never erases a known tier.
    if ($global:SI_PrivilegeTierClassifier_RunAI -eq $false) {
        Write-Log "[$label] AI is turned off (SI_PrivilegeTierClassifier_RunAI = `$false) -- nothing sent; known tiers are kept from the previous catalog." "INFO"
        return $Chunk | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Name; Tier = 99; Reason = 'AI turned off for this engine. Manual review required.'; Unresolved = $true }
        }
    }

    $itemsJson = $Chunk | ConvertTo-Json -Depth 5 -Compress

    # Defensive: guard against missing/invalid globals so a typo in the
    # defaults module cannot silently produce max_tokens=null or an
    # infinite/never-running retry loop.
    # Silent defaults are seeded at script top (line ~135). These globals are now
    # always populated; the per-chunk re-validation has been removed.
    $maxRetries = [int]$global:AI_MaxRetries
    $maxTokens  = [int]$global:AI_MaxTokens

    $userPrompt = @"
Category: $label
Evaluate every item in the following JSON array and return a tiered result array.
Return ONLY a valid JSON array with one object per input item. No markdown, no explanation.

Items:
$itemsJson
"@

    $body = @{
        model    = $global:OpenAI_Deployment
        messages = @(
            @{ role = "system"; content = $SystemPrompt },
            @{ role = "user";   content = $userPrompt }
        )
        max_tokens  = $maxTokens
        temperature = 0.1
    } | ConvertTo-Json -Depth 6 -Compress

    $headers = @{
        "Content-Type" = "application/json; charset=utf-8"
        "api-key"      = $global:OpenAI_ApiKey
    }

    $uri = "$($global:OpenAI_Endpoint)/openai/deployments/$($global:OpenAI_Deployment)/chat/completions?api-version=$($global:OpenAI_ApiVersion)"

    # Required OpenAI settings. A missing/empty value only matters when AI is actually
    # used -- so it must NOT halt the whole engine. Instead surface a clear ERROR and
    # return the SAME per-chunk fallback as a retry-exhaustion (Tier 99 / manual review):
    # the classifier still completes, the AI summary just isn't delivered for these
    # items. (Empty config previously THREW here and crashed the entire run; that also
    # masked the real cause when an upstream optional-secret pull left the key unset.)
    $missingAI = @(
        @(
            @{ Name = 'OpenAI_ApiKey';     Value = $global:OpenAI_ApiKey },
            @{ Name = 'OpenAI_Endpoint';   Value = $global:OpenAI_Endpoint },
            @{ Name = 'OpenAI_Deployment'; Value = $global:OpenAI_Deployment }
        ) | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Value) } | ForEach-Object { $_.Name }
    )
    if ($missingAI.Count -gt 0) {
        # SAID ONCE PER RUN, and only as an error-free INFO when nothing is configured: Azure OpenAI is optional
        # (the Community default has none), so "not configured" is a choice, not a fault. Measured on an upgraded
        # Community install: one [ERROR] line per chunk -- 52 per run -- for a setting the customer never had to make.
        # A PARTIAL configuration (some of the three set) is a real mistake and is a warning, still once.
        if (-not $script:PtcAINotConfiguredSaid) {
            $script:PtcAINotConfiguredSaid = $true
            if ($missingAI.Count -ge 3) {
                Write-Log ("AI tiering is not configured (no Azure OpenAI settings), so it is not used: roles and permissions keep the tier they had in the previous catalog, and new ones are left for manual review (Tier 99). To use it, set OpenAI_Endpoint, OpenAI_Deployment and OpenAI_ApiKey in config\SecurityInsight.custom.ps1 or in this engine's LauncherConfig.custom.ps1.") "INFO"
            } else {
                Write-Log ("AI tiering is only partly configured -- missing: $($missingAI -join ', '). Set the missing value(s) in config\SecurityInsight.custom.ps1 or in this engine's LauncherConfig.custom.ps1. Until then AI tiering is not used: known tiers are kept from the previous catalog and new items are left for manual review (Tier 99).") "WARN"
            }
        }
        return $Chunk | ForEach-Object {
            [PSCustomObject]@{
                Name   = $_.Name
                Tier   = 99
                Reason = "AI not configured (missing: $($missingAI -join ', ')). Manual review required."
                Unresolved = $true
            }
        }
    }

    # Encode body as UTF-8 bytes  prevents PowerShell's default encoding from
    # producing malformed JSON when descriptions contain non-ASCII or special characters
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($body)

    $attempt = 0
    while ($attempt -lt $maxRetries) {
        $attempt++
        try {
            Write-Log "  [$label] attempt $attempt/$maxRetries..." "INFO"
            $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $bodyBytes -ErrorAction Stop

            # Defensive null-checks on the response shape. Azure OpenAI can return a
            # 200-OK body that's an error envelope (content-filter trigger, token
            # budget exceeded, invalid model deployment) rather than the expected
            # {choices:[{message:{content:...}}]} shape. Before v2.1.176 the code
            # dereferenced blindly and NRE'd 'Object reference not set to an instance
            # of an object.' on every retry -- which looked like an AI flake but was
            # really an always-fails configuration problem.
            if ($null -eq $response) {
                throw "response is `$null (Invoke-RestMethod returned nothing -- network blackhole or proxy)"
            }
            if ($null -eq $response.choices -or @($response.choices).Count -eq 0) {
                $errBody = if ($response.error) { $response.error | ConvertTo-Json -Compress -Depth 5 } else { $response | ConvertTo-Json -Compress -Depth 5 }
                throw "response has no 'choices' array -- API error envelope instead. Body: $errBody"
            }
            $msg = $response.choices[0].message
            if ($null -eq $msg -or $null -eq $msg.content) {
                throw "response.choices[0].message.content is `$null (content filter? finish_reason=$($response.choices[0].finish_reason))"
            }
            $content = ([string]$msg.content).Trim()

            # Strip markdown fences if model wrapped the response
            $content = $content -replace '(?s)```json\s*', '' -replace '(?s)```\s*', ''
            $content = $content.Trim()

            $parsed = $content | ConvertFrom-Json
            if ($parsed -isnot [array] -and $parsed -isnot [System.Collections.Generic.List[object]]) {
                $parsed = @($parsed)
            }

            Write-Log "  [$label] returned $($parsed.Count) results" "SUCCESS"
            $script:PtcAICallsUsed++
            return $parsed
        }
        catch {
            Write-Log "  [$label] attempt $attempt failed: $($_.Exception.Message)" "WARN"
            if ($attempt -lt $maxRetries) {
                # A throttled service says how long to wait; honour it. Otherwise back off
                # exponentially -- a fixed 3s let three attempts land inside one throttle window.
                Start-Sleep -Seconds (Get-PTCRetryDelaySeconds -ErrorRecord $_ -Attempt $attempt)
            }
        }
    }

    # All retries exhausted -- these items are UNRESOLVED, not re-tiered. Main keeps each
    # one's tier from the previous catalog (Restore-PTCPriorTiers).
    Write-Log "  [$label] all retries exhausted -- tiers from the previous catalog are kept for these items" "ERROR"
    return $Chunk | ForEach-Object {
        [PSCustomObject]@{
            Name   = $_.Name
            Tier   = 99
            Reason = "AI evaluation failed after $maxRetries attempts. Manual review required."
            Unresolved = $true
        }
    }
}

# ============================================================
# AI BATCH TIERING  splits large categories into chunks,
# sends each chunk separately, merges results
# ============================================================

function Invoke-AIBatchTiering {
    param(
        [string]$CategoryName,
        [array]$Items
    )

    $total      = $Items.Count
    # Silent default is seeded at script top.
    $chunkSize  = [int]$global:AI_ChunkSize
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Split into chunks
    $chunks = [System.Collections.Generic.List[object[]]]::new()
    for ($i = 0; $i -lt $total; $i += $chunkSize) {
        $end = [Math]::Min($i + $chunkSize - 1, $total - 1)
        $chunks.Add($Items[$i..$end])
    }

    $totalChunks = $chunks.Count
    Write-Log "AI batch: $CategoryName  $total items across $totalChunks chunk(s) of max $chunkSize" "INFO"

    $chunkIndex = 0
    foreach ($chunk in $chunks) {
        $chunkIndex++
        $chunkResults = Invoke-AISingleChunk `
            -CategoryName $CategoryName `
            -Chunk        $chunk `
            -ChunkIndex   $chunkIndex `
            -TotalChunks  $totalChunks

        foreach ($r in $chunkResults) { $allResults.Add($r) }

        # Brief pause between chunks to avoid rate limiting
        if ($chunkIndex -lt $totalChunks) { Start-Sleep -Milliseconds 500 }
    }

    Write-Log "AI batch complete: $CategoryName  $($allResults.Count) total results" "SUCCESS"
    return $allResults.ToArray()
}

# ============================================================
# SECTION A  AD BUILT-IN GROUPS -- tier classification only
# ============================================================
# AD group *membership* is resolved at runtime via the Exposure Graph
# inside IdentityAssetsCollectDefineTierIngestLog (the identity engine
# checks whether a user has access to Domain Admins etc. directly from
# EG -- no need to mirror the on-prem directory into local JSON).
#
# What this engine still produces: the AI-tiered classification of the
# hardcoded $BuiltInADGroups list into AD_BuiltInPermissionGroups_Tier0..3,
# which IdentityAssetsCollect reads via $tierDefs.AD_BuiltInPermissionGroups_TierN.
#
# No RSAT / ActiveDirectory module dependency. No members enumerated.
# Classification runs on group NAMES alone.

# ============================================================
# SECTION B  ENTRA ID ROLE DEFINITIONS (no assignments)
# ============================================================

function Get-EntraRoleDefinitions {
    Write-Log "=== SECTION B: Entra ID Role Definitions ===" "INFO"

    # Safety net: ensure a clean Mg context. The platform bootstrap may have
    # connected with cert auth (which can have stale-cache issues); this
    # connects with SPN+secret which is more robust for unattended runs.
    try { Connect-GraphWithSPN } catch { Write-Log "Connect-GraphWithSPN failed: $_" "ERROR" }

    $roles = [System.Collections.Generic.List[PSCustomObject]]::new()

    # 🔑 PURE REST (#113). The SDK cmdlet was `Get-MgRoleManagementDirectoryRoleDefinition -Filter ...
    # -All`; this is the same endpoint the SDK called, and the same one
    # `engine/asset-profiling/shared/IdentityRoleFetcher.ps1:119` already queries.
    # 🪤 THE PROPERTY NAMES CHANGE CASE, AND SILENTLY. The SDK returns PascalCase
    # (.DisplayName, .RolePermissions[].AllowedResourceActions); raw Graph JSON is camelCase
    # (.displayName, .rolePermissions[].allowedResourceActions). PowerShell property access is
    # case-INSENSITIVE, so `.DisplayName` still binds against the camelCase JSON -- which is why this
    # conversion is safe, and also why a mistake here would NOT throw: it would return $null and
    # publish empty columns. The emitted object below therefore keeps the SAME PascalCase shape the
    # rest of this engine consumes, so nothing downstream changes.
    try {
        $builtIn = @(Invoke-SIGraphRestPaged -Token $script:PtcGraphToken `
                        -RelativeUrl '/roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq true')
        foreach ($r in $builtIn) {
            $perms = @()
            if ($r.rolePermissions) {
                $perms = @($r.rolePermissions | ForEach-Object { $_.allowedResourceActions } | Where-Object { $_ })
            }
            $roles.Add([PSCustomObject]@{ Id = $r.id; DisplayName = $r.displayName; Description = $r.description; IsBuiltIn = $true; Permissions = $perms })
        }
        Write-Log "Built-in roles: $($builtIn.Count)" "SUCCESS"

        # 🔒 The custom-role query was -ErrorAction SilentlyContinue under the SDK: a tenant with no
        # custom roles is normal, and must not fail the section. Its own try/catch preserves that,
        # rather than letting a REST throw abort the built-in roles already collected above.
        $custom = @()
        try {
            $custom = @(Invoke-SIGraphRestPaged -Token $script:PtcGraphToken `
                            -RelativeUrl '/roleManagement/directory/roleDefinitions?$filter=isBuiltIn eq false')
        } catch { Write-Log "Custom role definitions unavailable (continuing): $_" "INFO" }
        foreach ($r in $custom) {
            $perms = @()
            if ($r.rolePermissions) {
                $perms = @($r.rolePermissions | ForEach-Object { $_.allowedResourceActions } | Where-Object { $_ })
            }
            $roles.Add([PSCustomObject]@{ Id = $r.id; DisplayName = $r.displayName; Description = $r.description; IsBuiltIn = $false; Permissions = $perms })
        }
        Write-Log "Custom roles: $($custom.Count)" "SUCCESS"
    }
    catch { Write-Log "Error collecting Entra role definitions: $_" "ERROR" }

    Write-Log "Total Entra roles: $($roles.Count)" "SUCCESS"
    return $roles
}

# ============================================================
# SECTION C  API PERMISSION CATALOG (no grants)
# ============================================================

function Get-EntraAPIPermissionCatalog {
    Write-Log "=== SECTION C: Entra API Permission Catalog ===" "INFO"

    # Safety net: ensure Mg context (idempotent if already connected).
    try { Connect-GraphWithSPN } catch { Write-Log "Connect-GraphWithSPN failed: $_" "ERROR" }

    $permissions = [System.Collections.Generic.List[PSCustomObject]]::new()

    $wellKnownApps = [ordered]@{
        "00000003-0000-0000-c000-000000000000" = "Microsoft Graph"
        "00000002-0000-0ff1-ce00-000000000000" = "Exchange Online"
        "00000003-0000-0ff1-ce00-000000000000" = "SharePoint Online"
        "00000004-0000-0ff1-ce00-000000000000" = "Skype for Business"
        "00000007-0000-0000-c000-000000000000" = "Dynamics CRM"
        "797f4846-ba00-4fd7-ba43-dac1f8f63013" = "Azure Service Management"
        "fc68d9e5-1f76-45ef-99aa-214805418498" = "Windows Azure Active Directory"
        "0000000a-0000-0000-c000-000000000000" = "Microsoft Intune"
        "00000009-0000-0000-c000-000000000000" = "Power BI Service"
        "c5393580-f805-4401-95e8-94b7a6ef2fc2" = "Office 365 Management APIs"
        "00000012-0000-0000-c000-000000000000" = "Microsoft Rights Management Services"
        "8bdebf23-c0fe-4187-a378-717ad86f6a53" = "Microsoft Defender for Endpoint"
        "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "Microsoft Teams"
        "2f3f02c9-5679-4a5c-a605-0de55b07d135" = "Microsoft Threat Protection"
    }

    foreach ($appId in $wellKnownApps.Keys) {
        try {
            # 🔑 PURE REST (#113) -- the same /servicePrincipals endpoint
            # `Get-DiscoveryFromEntraServicePrincipals.ps1:94` already queries.
            # 🪤 A FILTERED GRAPH GET RETURNS A COLLECTION, NOT AN OBJECT. The SDK cmdlet handed back
            # a single item (or $null); the REST endpoint always returns `value: []`. Taking [0] is
            # what preserves the `$null` that the not-in-tenant check below depends on -- without it
            # $sp would be an empty ARRAY, which is not $null, and every absent app would fall through
            # to the AppRoles loop and silently catalogue nothing. That reads as success.
            $spResp = @(Invoke-SIGraphRestPaged -Token $script:PtcGraphToken `
                            -RelativeUrl ("/servicePrincipals?`$filter=appId eq '{0}'" -f $appId))
            $sp = if ($spResp.Count -gt 0) { $spResp[0] } else { $null }
            # Demoted from WARN to INFO: a missing well-known app SP (e.g. Microsoft
            # Teams in tenants without Teams licensing) is normal, not a problem.
            if ($null -eq $sp) { Write-Log "Not in tenant: $($wellKnownApps[$appId]) (skipping)" "INFO"; continue }

            Write-Log "Cataloging: $($sp.DisplayName)" "INFO"

            foreach ($r in $sp.AppRoles) {
                if (-not $r.IsEnabled) { continue }
                $permissions.Add([PSCustomObject]@{
                    ServicePrincipal = $sp.DisplayName; AppId = $appId
                    PermissionType   = "Application"; Id = $r.Id
                    Value = $r.Value; DisplayName = $r.DisplayName; Description = $r.Description
                })
            }
            foreach ($s in $sp.Oauth2PermissionScopes) {
                if (-not $s.IsEnabled) { continue }
                $permissions.Add([PSCustomObject]@{
                    ServicePrincipal = $sp.DisplayName; AppId = $appId
                    PermissionType   = "Delegated"; Id = $s.Id
                    Value = $s.Value; DisplayName = $s.AdminConsentDisplayName; Description = $s.AdminConsentDescription
                })
            }
        }
        catch { Write-Log "Error cataloging '$($wellKnownApps[$appId])': $_" "WARN" }
    }

    Write-Log "API permission catalog: $($permissions.Count) entries" "SUCCESS"
    return $permissions
}

# ============================================================
# SECTION D  AZURE ROLE DEFINITIONS (no assignments)
# ============================================================

function Get-AzureRoleDefinitions {
    Write-Log "=== SECTION D: Azure Role Definitions ===" "INFO"

    $azureRoles = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        Connect-AzWithSPN

        # -WarningAction SilentlyContinue silences the Az 'Upcoming breaking changes
        # in Get-AzRoleDefinition' notice that prints on every batch run. We're
        # already reading the legacy flat properties (Actions / NotActions / etc.)
        # which works in Az < 16; when we move to Az 16 this engine needs to
        # switch to Permissions[n].Actions anyway.
        $builtIn = Get-SIAzRoleDefinition -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_.IsCustom -eq $false }
        foreach ($r in $builtIn) {
            $azureRoles.Add([PSCustomObject]@{
                Id = $r.Id; Name = $r.Name; Description = $r.Description; IsCustom = $false
                Actions = @($r.Actions); NotActions = @($r.NotActions); DataActions = @($r.DataActions)
            })
        }
        Write-Log "Azure built-in roles: $($builtIn.Count)" "SUCCESS"

        # Same suppression + when no custom roles exist Az emits 3 WARNs ("No role
        # definitions were found", "If the role was created recently...", "Please
        # try again later"); zero-custom is normal in lab tenants.
        $custom = Get-SIAzRoleDefinition -Custom -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        foreach ($r in $custom) {
            $azureRoles.Add([PSCustomObject]@{
                Id = $r.Id; Name = $r.Name; Description = $r.Description; IsCustom = $true
                Actions = @($r.Actions); NotActions = @($r.NotActions); DataActions = @($r.DataActions)
            })
        }
        Write-Log "Azure custom roles: $($custom.Count)" "SUCCESS"
    }
    catch { Write-Log "Error collecting Azure role definitions: $_" "ERROR" }

    Write-Log "Total Azure roles: $($azureRoles.Count)" "SUCCESS"
    return $azureRoles
}

# ============================================================
# AI TIERING  5 batch calls, one per category
# ============================================================

function Invoke-AllAITiering {
    param(
        [array]$EntraRoles,
        [array]$APIPermissions,
        [array]$AzureRoles
    )

    Write-Log "=== AI TIERING: Preparing batch inputs ===" "INFO"

    # ---- 1. AD Groups ----
    # Input is just the group name -- the AI has enough signal in Windows
    # built-in group names (Domain Admins, Enterprise Admins, DnsAdmins,
    # Account Operators, etc.) to classify tier without a member snapshot.
    # Membership analysis happens at query time via the Exposure Graph.
    $adGroupSummary = $BuiltInADGroups | Select-Object -Unique | ForEach-Object {
        [PSCustomObject]@{ Name = $_ }
    }

    # ---- 2. Entra Roles ----
    $entraRoleInput = $EntraRoles | ForEach-Object {
        $sample = if ($_.Permissions.Count -gt 0) { ($_.Permissions | Select-Object -First 8) -join "; " } else { "no explicit permissions" }
        [PSCustomObject]@{
            Name        = $_.DisplayName
            Type        = if ($_.IsBuiltIn) { "built-in" } else { "custom" }
            Permissions = $sample
        }
    }

    # ---- 3. API Permissions ----
    # Deduplicate by Value  same permission name from different SPs is one evaluation
    $apiPermInput = $APIPermissions | Sort-Object Value -Unique | ForEach-Object {
        [PSCustomObject]@{
            Name        = $_.Value
            Type        = $_.PermissionType
            Publisher   = $_.ServicePrincipal
            Description = $_.Description
        }
    }

    # ---- 4. Azure Roles ----
    # Sanitize description and actions  Azure role descriptions frequently contain
    # special characters (backslashes, quotes, control chars) that break JSON body parsing
    $azureRoleInput = $AzureRoles | ForEach-Object {
        $actionSample = ($_.Actions | Select-Object -First 8) -join "; "
        [PSCustomObject]@{
            Name        = Sanitize-ForJson $_.Name
            Type        = if ($_.IsCustom) { "custom" } else { "built-in" }
            Actions     = Sanitize-ForJson $actionSample
            Description = Sanitize-ForJson $_.Description
        }
    }

    # ---- 5. Account Types ----

    # ---- Send batch calls ----
    Write-Log "=== AI TIERING: Sending 4 batch requests ===" "INFO"

    $tieredADGroups   = Invoke-AIBatchTiering -CategoryName "Active Directory Built-in Groups"    -Items $adGroupSummary
    $tieredEntraRoles = Invoke-AIBatchTiering -CategoryName "Entra ID Role Definitions"           -Items $entraRoleInput
    $tieredAPIPerms   = Invoke-AIBatchTiering -CategoryName "Entra API Permissions"               -Items $apiPermInput
    $tieredAzureRoles = Invoke-AIBatchTiering -CategoryName "Azure RBAC Role Definitions"         -Items $azureRoleInput

    # ---- Merge AI tier results back with full source data ----
    # All maps use case-insensitive string comparer and name trimming so AI name
    # variations (casing, whitespace) still match the source correctly.

    function Normalize-Key { param([string]$s) $s.Trim() }

    # AD Groups
    $adGroupTierMap = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $tieredADGroups) {
        $k = Normalize-Key $r.Name
        if (-not $adGroupTierMap.ContainsKey($k)) { $adGroupTierMap[$k] = $r }
    }
    $mergedADGroups = $BuiltInADGroups | Select-Object -Unique | ForEach-Object {
        $match = $null; $adGroupTierMap.TryGetValue((Normalize-Key $_), [ref]$match) | Out-Null
        [PSCustomObject]@{
            Name   = $_
            Tier   = if ($match) { [int]$match.Tier } else { 99 }
            Reason = if ($match) { $match.Reason }    else { "AI result not matched - manual review required" }
        }
    }

    # Entra Roles
    $entraRoleTierMap = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $tieredEntraRoles) {
        $k = Normalize-Key $r.Name
        if (-not $entraRoleTierMap.ContainsKey($k)) { $entraRoleTierMap[$k] = $r }
    }
    $mergedEntraRoles = $EntraRoles | ForEach-Object {
        $match = $null; $entraRoleTierMap.TryGetValue((Normalize-Key $_.DisplayName), [ref]$match) | Out-Null
        [PSCustomObject]@{
            Id          = $_.Id
            DisplayName = $_.DisplayName
            IsBuiltIn   = $_.IsBuiltIn
            Tier        = if ($match) { [int]$match.Tier } else { 99 }
            Reason      = if ($match) { $match.Reason }    else { "AI result not matched - manual review required" }
            Permissions = $_.Permissions
        }
    }

    # API Permissions (deduplicated by Value for tiered output)
    $apiPermTierMap = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $tieredAPIPerms) {
        $k = Normalize-Key $r.Name
        if (-not $apiPermTierMap.ContainsKey($k)) { $apiPermTierMap[$k] = $r }
    }
    $mergedAPIPerms = $APIPermissions | Sort-Object Value -Unique | ForEach-Object {
        $match = $null; $apiPermTierMap.TryGetValue((Normalize-Key $_.Value), [ref]$match) | Out-Null
        [PSCustomObject]@{
            ServicePrincipal = $_.ServicePrincipal
            AppId            = $_.AppId
            PermissionType   = $_.PermissionType
            Value            = $_.Value
            DisplayName      = $_.DisplayName
            Description      = $_.Description
            Tier             = if ($match) { [int]$match.Tier } else { 99 }
            Reason           = if ($match) { $match.Reason }    else { "AI result not matched - manual review required" }
        }
    }

    # Azure Roles
    $azureRoleTierMap = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $tieredAzureRoles) {
        $k = Normalize-Key $r.Name
        if (-not $azureRoleTierMap.ContainsKey($k)) { $azureRoleTierMap[$k] = $r }
    }
    $mergedAzureRoles = $AzureRoles | ForEach-Object {
        $match = $null; $azureRoleTierMap.TryGetValue((Normalize-Key $_.Name), [ref]$match) | Out-Null
        [PSCustomObject]@{
            Id          = $_.Id
            Name        = $_.Name
            IsCustom    = $_.IsCustom
            Tier        = if ($match) { [int]$match.Tier } else { 99 }
            Reason      = if ($match) { $match.Reason }    else { "AI result not matched - manual review required" }
            Actions     = $_.Actions
            NotActions  = $_.NotActions
            DataActions = $_.DataActions
        }
    }


    return @{
        ADGroups   = $mergedADGroups
        EntraRoles = $mergedEntraRoles
        APIPerms   = $mergedAPIPerms
        AzureRoles = $mergedAzureRoles
    }
}

# ============================================================
# BUILD AND EXPORT JSON
# ============================================================

function Export-TieredJSON {
    param(
        [array]$TieredADGroups,
        [array]$TieredEntraRoles,
        [array]$TieredAPIPerms,
        [array]$TieredAzureRoles,
        [array]$RawAPIPermissions,
        [array]$RawAzureRoles,
        # the run's input fingerprint (Get-PTCInputFingerprint) and whether every item was tiered this run -- the next run
        # skips the AI pass only when both say nothing changed and nothing was left open (Get-PTCUnchangedDecision)
        [string]$InputFingerprint = '',
        [bool]$Complete = $false
    )

    Write-Log "=== Building and Exporting JSON ===" "INFO"

    # Get-ByTier: returns List[object] so PS 5.1 ConvertTo-Json always emits a JSON array.
    # PS 5.1 re-reflects hashtable values at serialisation time and silently unwraps
    # [object[]] casts, emitting {} for empty and a bare object for single-item arrays.
    # System.Collections.Generic.List[object] implements IList<T> which PS 5.1's
    # Newtonsoft.Json serialiser always renders as a JSON array regardless of Count.
    function Get-ByTier {
        param($Data, $Tier)
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($item in @($Data | Where-Object { $_.Tier -eq $Tier })) { $list.Add($item) }
        return ,$list   # comma operator prevents PowerShell unwrapping the list on return
    }

    # Intermediate split variables use List[object] for the same PS 5.1 reason:
    # if only 1 item matches the Where-Object filter, @(...) stores a bare object
    # in the variable, and Get-ByTier then receives a non-enumerable as $Data.
    $builtInEntra  = [System.Collections.Generic.List[object]]::new(); foreach ($r in @($TieredEntraRoles | Where-Object { $_.IsBuiltIn -eq $true  })) { $builtInEntra.Add($r) }
    $customEntra   = [System.Collections.Generic.List[object]]::new(); foreach ($r in @($TieredEntraRoles | Where-Object { $_.IsBuiltIn -eq $false })) { $customEntra.Add($r) }
    $builtInAzure  = [System.Collections.Generic.List[object]]::new(); foreach ($r in @($TieredAzureRoles | Where-Object { $_.IsCustom  -eq $false })) { $builtInAzure.Add($r) }
    $customAzure   = [System.Collections.Generic.List[object]]::new(); foreach ($r in @($TieredAzureRoles | Where-Object { $_.IsCustom  -eq $true  })) { $customAzure.Add($r) }

    $output = [ordered]@{

        Metadata = [ordered]@{
            GeneratedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            GeneratedBy     = "SecurityInsight-PrivilegeTierClassifier.ps1 v2.0"
            TenantId        = $global:SpnTenantId
            TieringModel    = "Attacker-centric (0=immediate compromise, 3=low blast radius)"
            AICallsUsed     = [int]$script:PtcAICallsUsed
            GeneratedAtUtc  = ([datetime]::UtcNow).ToString('o', [Globalization.CultureInfo]::InvariantCulture)
            InputFingerprint = $InputFingerprint
            Complete        = [bool]$Complete
        }

        # ---- AD Built-in Permission Groups ----
        AD_BuiltInPermissionGroups_Tier0 = Get-ByTier $TieredADGroups 0
        AD_BuiltInPermissionGroups_Tier1 = Get-ByTier $TieredADGroups 1
        AD_BuiltInPermissionGroups_Tier2 = Get-ByTier $TieredADGroups 2
        AD_BuiltInPermissionGroups_Tier3 = Get-ByTier $TieredADGroups 3

        # ---- Entra ID Built-in Roles ----
        EntraID_BuiltInRoles_Tier0 = Get-ByTier $builtInEntra 0
        EntraID_BuiltInRoles_Tier1 = Get-ByTier $builtInEntra 1
        EntraID_BuiltInRoles_Tier2 = Get-ByTier $builtInEntra 2
        EntraID_BuiltInRoles_Tier3 = Get-ByTier $builtInEntra 3

        # ---- Entra ID Custom Roles ----
        EntraID_CustomRoles_Tier0 = Get-ByTier $customEntra 0
        EntraID_CustomRoles_Tier1 = Get-ByTier $customEntra 1
        EntraID_CustomRoles_Tier2 = Get-ByTier $customEntra 2
        EntraID_CustomRoles_Tier3 = Get-ByTier $customEntra 3

        # ---- Entra API Permissions ----
        EntraID_APIPermissions_Tier0 = Get-ByTier $TieredAPIPerms 0
        EntraID_APIPermissions_Tier1 = Get-ByTier $TieredAPIPerms 1
        EntraID_APIPermissions_Tier2 = Get-ByTier $TieredAPIPerms 2
        EntraID_APIPermissions_Tier3 = Get-ByTier $TieredAPIPerms 3

        # Raw full API permission catalog (all enabled permissions per service principal)
        EntraID_APIPermissions_Catalog = @($RawAPIPermissions)


        # ---- Azure Built-in Roles ----
        Azure_BuiltInRoles_Tier0 = Get-ByTier $builtInAzure 0
        Azure_BuiltInRoles_Tier1 = Get-ByTier $builtInAzure 1
        Azure_BuiltInRoles_Tier2 = Get-ByTier $builtInAzure 2
        Azure_BuiltInRoles_Tier3 = Get-ByTier $builtInAzure 3

        # ---- Azure Custom Roles ----
        Azure_CustomRoles_Tier0 = Get-ByTier $customAzure 0
        Azure_CustomRoles_Tier1 = Get-ByTier $customAzure 1
        Azure_CustomRoles_Tier2 = Get-ByTier $customAzure 2
        Azure_CustomRoles_Tier3 = Get-ByTier $customAzure 3

        # Raw Azure role catalog (full action lists)
        Azure_Roles_Catalog = @($RawAzureRoles)

        # ---- Summary ----
        Summary = [ordered]@{
            AD_Groups = [ordered]@{
                Tier0 = (Get-ByTier $TieredADGroups 0).Count
                Tier1 = (Get-ByTier $TieredADGroups 1).Count
                Tier2 = (Get-ByTier $TieredADGroups 2).Count
                Tier3 = (Get-ByTier $TieredADGroups 3).Count
                Untiered = (Get-ByTier $TieredADGroups 99).Count
                TotalGroups = $TieredADGroups.Count
            }
            EntraRoles = [ordered]@{
                Tier0 = (Get-ByTier $TieredEntraRoles 0).Count
                Tier1 = (Get-ByTier $TieredEntraRoles 1).Count
                Tier2 = (Get-ByTier $TieredEntraRoles 2).Count
                Tier3 = (Get-ByTier $TieredEntraRoles 3).Count
                Untiered = (Get-ByTier $TieredEntraRoles 99).Count
                TotalRoles = $TieredEntraRoles.Count
            }
            APIPermissions = [ordered]@{
                Tier0 = (Get-ByTier $TieredAPIPerms 0).Count
                Tier1 = (Get-ByTier $TieredAPIPerms 1).Count
                Tier2 = (Get-ByTier $TieredAPIPerms 2).Count
                Tier3 = (Get-ByTier $TieredAPIPerms 3).Count
                Untiered = (Get-ByTier $TieredAPIPerms 99).Count
                TotalPermissions = $TieredAPIPerms.Count
            }
            AzureRoles = [ordered]@{
                Tier0 = (Get-ByTier $TieredAzureRoles 0).Count
                Tier1 = (Get-ByTier $TieredAzureRoles 1).Count
                Tier2 = (Get-ByTier $TieredAzureRoles 2).Count
                Tier3 = (Get-ByTier $TieredAzureRoles 3).Count
                Untiered = (Get-ByTier $TieredAzureRoles 99).Count
                TotalRoles = $TieredAzureRoles.Count
            }
        }
    }

    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
    }

    # ConvertTo-Json note: array integrity is guaranteed by [object[]] casts in Get-ByTier.
    # -Depth 20 covers nested Permissions arrays inside role objects.
    # A dry run (#257) writes beside the catalog and never shares it -- the catalog itself is untouched.
    if ($script:PtcWhatIf) {
        $dryPath = Get-PTCDryRunPath -CatalogPath $OutputFile
        $output | ConvertTo-Json -Depth 20 | Out-File -FilePath $dryPath -Encoding UTF8 -Force
        Write-Log ("[dry run] result written to {0}; the catalog {1} and its shared copy are unchanged." -f $dryPath, $OutputFile) "SUCCESS"
        return $dryPath
    }
    $output | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
    Write-Log "JSON exported to: $OutputFile" "SUCCESS"
    # Share it through the storage account too: in a container this job's disk disappears with it, and the
    # profiler jobs read the catalog from storage (they refresh their local copy when this one is newer).
    . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-CatalogBlob.ps1')
    if (Publish-SICatalogToBlob -LocalPath $OutputFile) {
        Write-Log ("Catalog shared to storage account {0} for the other engines." -f $global:SI_StorageAccount) "SUCCESS"
    }
    return $OutputFile
}

# ============================================================
# MAIN
# ============================================================

function Main {
    # RunHealth heartbeat -> SI_RunHealth_CL.
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/shared/Send-SIRunHealthRow.ps1')
    $script:_RunHealthCtx = [pscustomobject]@{
        RunId          = [guid]::NewGuid().ToString()
        Engine         = 'privilege-tier-classifier'
        ShardIndex     = 0
        ShardCount     = 1
        StartedAt      = [datetime]::UtcNow
        CollectionTime = ([datetime]::UtcNow).ToString('yyyy-MM-dd HH:mm:ss')
    }
    try { Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'Start' } catch {}
    $_phRH_Exit = 'success'; $_phRH_Err = ''; $_phRH_Count = -1
    try {

    $script:PtcAICallsUsed = 0
    Write-Log "SecurityInsight Identity Tiering - Starting" "INFO"
    Write-Log "Output: $OutputFile" "INFO"

    # v2.2.383 -- 24h rebuild skip. If the catalog was rebuilt in the last 24h
    # the AI pass + 4 batch calls + JSON export would just reproduce the same
    # output (the catalog moves on the order of days, not hours). Skip and
    # let the heartbeat record a clean run. Override via custom.ps1:
    #     $global:ForcePrivilegedTierProfilerRebuild = $true
    $_forceRebuild = [bool]$global:ForcePrivilegedTierProfilerRebuild
    # A container job starts with no catalog on its disk -- the one it built last time lives only in the storage account
    # -- so the skip below never fired there and every run rebuilt (AI calls included). With no local copy, take the
    # shared one first: its age (the time it was shared) then decides, exactly as the local file's does on a VM. A VM
    # that has its file is unchanged; without a storage account this is a no-op.
    if (-not $script:PtcWhatIf -and -not (Test-Path -LiteralPath $OutputFile) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_StorageAccount)) {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-CatalogBlob.ps1')
        if ((Update-SICatalogFromBlob -LocalPath $OutputFile) -eq 'storage') {
            Write-Log ("No local catalog -- using the copy shared in storage account {0} (its age decides whether to rebuild)." -f $global:SI_StorageAccount) "INFO"
        }
    }
    if (-not $_forceRebuild -and (Test-Path -LiteralPath $OutputFile)) {
        $_lastWrite = (Get-Item -LiteralPath $OutputFile).LastWriteTimeUtc
        $_ageHours = ([datetime]::UtcNow - $_lastWrite).TotalHours
        if ($_ageHours -lt 24) {
            Write-Log ("Skipping rebuild -- existing catalog is {0:n1}h old (<24h). Override with `$global:ForcePrivilegedTierProfilerRebuild = `$true in SecurityInsight.custom.ps1." -f $_ageHours) "SUCCESS"
            return
        }
        Write-Log ("Existing catalog is {0:n1}h old (>=24h) -- rebuilding." -f $_ageHours) "INFO"
    } elseif ($_forceRebuild -and (Test-Path -LiteralPath $OutputFile)) {
        Write-Log "ForcePrivilegedTierProfilerRebuild=`$true -- rebuilding regardless of catalog age." "INFO"
    }

    Write-Log "=== SECTION A: AD Built-in Groups (name-based AI tiering) ===" "INFO"
    Write-Log "Catalog size: $($BuiltInADGroups.Count) built-in group names (hardcoded list)." "INFO"
    Write-Log "Classification method: Azure OpenAI tiers each group name into Tier 0/1/2/3." "INFO"
    Write-Log "Membership analysis happens at query time in IdentityAssetsCollect via the Exposure Graph -- no on-prem AD enumeration, no RSAT required." "INFO"

    # ---- Collect all data first ----
    $entraRoles     = Get-EntraRoleDefinitions
    $apiPermissions = Get-EntraAPIPermissionCatalog
    $azureRoles     = Get-AzureRoleDefinitions

    # ---- Skip the AI pass when nothing it would read changed (#528) ----
    # The inputs cost seconds; the AI pass is the minutes (measured 15 min of the 2026-10-09 internal pipeline). Same
    # fingerprint as the last complete catalog, and that catalog younger than SI_PrivilegeTierClassifier_RefreshDays
    # (default 7) -> the catalog is kept as it is and the run ends successfully. Never on a dry run (it shows the rebuild).
    $_engineHash = ''
    try { if ($PSCommandPath) { $_engineHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash } } catch { $_engineHash = '' }
    $_fingerprint = Get-PTCInputFingerprint -EntraRoles @($entraRoles) -APIPermissions @($apiPermissions) -AzureRoles @($azureRoles) -ADGroups @($BuiltInADGroups) `
                        -EngineHash $_engineHash -RunAI ([string]$global:SI_PrivilegeTierClassifier_RunAI) -AIDeployment ([string]$global:OpenAI_Deployment)
    $_collectionOk = (@($entraRoles).Count -gt 0) -and (@($apiPermissions).Count -gt 0) -and (@($azureRoles).Count -gt 0)
    if (-not $script:PtcWhatIf) {
        $_unchanged = Get-PTCUnchangedDecision -Prior (Get-PTCCatalogState -Path $OutputFile) -Fingerprint $_fingerprint -NowUtc ([datetime]::UtcNow) `
                          -MaxAgeDays (Get-PTCRefreshDays) -Force $_forceRebuild -CollectionOk $_collectionOk
        if ($_unchanged.Skip) {
            Write-Log $_unchanged.Reason "SUCCESS"
            $_phRH_Err = $_unchanged.Reason
            return
        }
        Write-Log ("Rebuilding the catalog: {0}." -f $_unchanged.Reason) "INFO"
    }

    # ---- Single AI pass  4 batch calls (AD group names tiered from hardcoded list) ----
    $tiered = Invoke-AllAITiering `
        -EntraRoles        $entraRoles `
        -APIPermissions    $apiPermissions `
        -AzureRoles        $azureRoles `

    # ---- Keep known tiers for anything the AI did not resolve this run ----
    $keptFromPrior = Restore-PTCPriorTiers -Tiered $tiered -PriorPath $OutputFile
    if ($keptFromPrior -gt 0) {
        Write-Log ("{0} item(s) were not re-evaluated this run; their tier from the previous catalog is kept." -f $keptFromPrior) "WARN"
    }

    # ---- Build and export JSON ----
    # Pass the RAW catalogs through as well so the JSON's *_Catalog fields actually
    # populate. Without these two arguments the Export-TieredJSON function's
    # $RawAPIPermissions / $RawAzureRoles params defaulted to empty, and the JSON
    # output carried [null] for EntraID_APIPermissions_Catalog + Azure_Roles_Catalog
    # (fixed in v2.1.175).
    $outputPath = Export-TieredJSON `
        -TieredADGroups    $tiered.ADGroups `
        -TieredEntraRoles  $tiered.EntraRoles `
        -TieredAPIPerms    $tiered.APIPerms `
        -TieredAzureRoles  $tiered.AzureRoles `
        -RawAPIPermissions $apiPermissions `
        -RawAzureRoles     $azureRoles `
        -InputFingerprint  $_fingerprint `
        -Complete          ($_collectionOk -and $keptFromPrior -eq 0 -and (Get-PTCOpenItemCount -Tiered $tiered) -eq 0)

    Write-Log "" "INFO"
    Write-Log "============================================" "SUCCESS"
    Write-Log "SecurityInsight Identity Tiering - COMPLETE" "SUCCESS"
    Write-Log "Output: $outputPath" "SUCCESS"
    Write-Log "============================================" "SUCCESS"
    } catch {
        $_phRH_Exit = 'failure'; $_phRH_Err = $_.Exception.Message
        throw
    } finally {
        try {
            Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase 'End' `
                                -AssetCount $_phRH_Count -ExitReason $_phRH_Exit -ErrorMessage $_phRH_Err
        } catch {}
    }
}

Main
