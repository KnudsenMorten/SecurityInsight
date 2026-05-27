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

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules

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

if (-not [bool]$global:AutomationFramework) {
    # v2.2.233 -- accept either ClientSecret OR CertificateThumbprint. The old
    # check required Secret, breaking SPN+cert customers entirely.
    $hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
        (-not $hasSecret -and -not $hasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Launcher must set them or enable AutomationFramework."
    }
}

if ([bool]$global:AutomationFramework) {
    # --- Automation Framework branch (internal 2LINKIT infra) ---
    $ScriptDirectory = $PSScriptRoot

    # v2 bootstrap: walk up to find the AutomateITPS module (= repo root),
    # then one call to Initialize-PlatformAutomationFramework takes care of
    # cert-based Connect-AzAccount, fetching Modern secrets from KV, and
    # populating the v1-contract $global:HighPriv_* / $global:AzureTenantId
    # names. Zero v1 module imports.
    $repoRoot = $ScriptDirectory
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$ScriptDirectory'."
    }
    $global:PathScripts = $repoRoot
    Write-Output ""
    Write-Output "Repo root          -> $($global:PathScripts)"

    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue

    # Initialize-PlatformAutomationFramework does cert-based Connect-MgGraph
    # internally. MSAL caches the resulting token under %LOCALAPPDATA%; if that
    # cache is corrupted (e.g. partial write, version mismatch, half-encrypted
    # remnant) the bootstrap fails with:
    #   "ClientCertificateCredential authentication failed:
    #    MSAL deserialization failed to parse the cache contents."
    # Wipe the cache and retry once. This is harmless -- the next sign-in just
    # recreates the cache from scratch.
    $bootstrapAttempt = 0
    while ($true) {
        $bootstrapAttempt++
        try {
            $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
            Write-Output "[INFO] Auth method (bootstrap)  : SPN + Certificate (Initialize-PlatformAutomationFramework)"
            break
        } catch {
            $msg = "$($_.Exception.Message) $($_.Exception.InnerException.Message)"
            $isCacheCorruption = $msg -match 'MSAL deserialization' -or $msg -match 'cache contents' -or $msg -match 'token cache encryption'
            if ($isCacheCorruption -and $bootstrapAttempt -lt 2) {
                Write-Warning "Initialize-PlatformAutomationFramework failed with MSAL cache corruption -- clearing cache and retrying once."
                foreach ($p in @(
                    (Join-Path $env:LOCALAPPDATA '.IdentityService'),
                    (Join-Path $env:LOCALAPPDATA 'Microsoft\IdentityCache'),
                    (Join-Path $env:LOCALAPPDATA '.mgraph')
                )) {
                    if (Test-Path -LiteralPath $p) {
                        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Output "[INFO] Cleared cache: $p"
                    }
                }
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
                Start-Sleep -Seconds 2
                continue
            }
            throw
        }
    }

    # Map AF-mode variables to the SPN globals the rest of this script expects.
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

} else {
    # --- Community / standalone branch (SPN globals set by launcher) ---
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
    }
}

# Force TLS 1.2 for .NET Framework HTTP stack (PS 5.1 default can be TLS 1.0/1.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# 2026-05-02: silent defaults for AI batching globals so the per-chunk loop
# stops emitting [WARN] AI_ChunkSize / AI_MaxRetries / AI_MaxTokens lines on
# every batch when the launcher's locked config doesn't override them.
if (-not $global:AI_ChunkSize  -or [int]$global:AI_ChunkSize  -lt 1) { $global:AI_ChunkSize  = 50 }
if (-not $global:AI_MaxRetries -or [int]$global:AI_MaxRetries -lt 1) { $global:AI_MaxRetries = 3 }
if (-not $global:AI_MaxTokens  -or [int]$global:AI_MaxTokens  -lt 1) { $global:AI_MaxTokens  = 16384 }

# Output goes to v2.2/privilege-tier-catalog/ (the dedicated cross-engine catalog
# folder). The engine script lives at v2.2/engine/privilege-tier-classifier/ --
# two levels up reaches v2.2/, then 'privilege-tier-catalog/'. The catalog is
# CONSUMED by the asset-profiling engines (Identity/Endpoint/Azure) and the RA
# engine, so it lives in its own peer folder rather than under data/ or under
# this engine's own tree.
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

# ----------------------------------------------------------------------
#  Module dependencies -- centralized helper under _shared/
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
Ensure-SecurityInsightModules

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

if (-not [bool]$global:AutomationFramework) {
    # v2.2.233 -- accept either ClientSecret OR CertificateThumbprint. The old
    # check required Secret, breaking SPN+cert customers entirely.
    $hasSecret = -not [string]::IsNullOrWhiteSpace([string]$global:SpnClientSecret)
    $hasCert   = -not [string]::IsNullOrWhiteSpace([string]$global:SpnCertificateThumbprint)
    if ([string]::IsNullOrWhiteSpace([string]$global:SpnTenantId) -or
        [string]::IsNullOrWhiteSpace([string]$global:SpnClientId) -or
        (-not $hasSecret -and -not $hasCert)) {
        throw "Missing SPN globals (SpnTenantId/SpnClientId + one of SpnClientSecret OR SpnCertificateThumbprint). Launcher must set them or enable AutomationFramework."
    }
}

if ([bool]$global:AutomationFramework) {
    # --- Automation Framework branch (internal 2LINKIT infra) ---
    $ScriptDirectory = $PSScriptRoot

    # v2 bootstrap: walk up to find the AutomateITPS module (= repo root),
    # then one call to Initialize-PlatformAutomationFramework takes care of
    # cert-based Connect-AzAccount, fetching Modern secrets from KV, and
    # populating the v1-contract $global:HighPriv_* / $global:AzureTenantId
    # names. Zero v1 module imports.
    $repoRoot = $ScriptDirectory
    while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1'))) {
        $repoRoot = Split-Path -Parent $repoRoot
    }
    if (-not $repoRoot) {
        throw "AutomationFramework bootstrap: cannot find FUNCTIONS\AutomateITPS\AutomateITPS.psd1 walking up from '$ScriptDirectory'."
    }
    $global:PathScripts = $repoRoot
    Write-Output ""
    Write-Output "Repo root          -> $($global:PathScripts)"

    Import-Module (Join-Path $repoRoot 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1') -Global -Force -WarningAction SilentlyContinue

    # Initialize-PlatformAutomationFramework does cert-based Connect-MgGraph
    # internally. MSAL caches the resulting token under %LOCALAPPDATA%; if that
    # cache is corrupted (e.g. partial write, version mismatch, half-encrypted
    # remnant) the bootstrap fails with:
    #   "ClientCertificateCredential authentication failed:
    #    MSAL deserialization failed to parse the cache contents."
    # Wipe the cache and retry once. This is harmless -- the next sign-in just
    # recreates the cache from scratch.
    $bootstrapAttempt = 0
    while ($true) {
        $bootstrapAttempt++
        try {
            $null = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
            Write-Output "[INFO] Auth method (bootstrap)  : SPN + Certificate (Initialize-PlatformAutomationFramework)"
            break
        } catch {
            $msg = "$($_.Exception.Message) $($_.Exception.InnerException.Message)"
            $isCacheCorruption = $msg -match 'MSAL deserialization' -or $msg -match 'cache contents' -or $msg -match 'token cache encryption'
            if ($isCacheCorruption -and $bootstrapAttempt -lt 2) {
                Write-Warning "Initialize-PlatformAutomationFramework failed with MSAL cache corruption -- clearing cache and retrying once."
                foreach ($p in @(
                    (Join-Path $env:LOCALAPPDATA '.IdentityService'),
                    (Join-Path $env:LOCALAPPDATA 'Microsoft\IdentityCache'),
                    (Join-Path $env:LOCALAPPDATA '.mgraph')
                )) {
                    if (Test-Path -LiteralPath $p) {
                        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Output "[INFO] Cleared cache: $p"
                    }
                }
                try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}
                Start-Sleep -Seconds 2
                continue
            }
            throw
        }
    }

    # Map AF-mode variables to the SPN globals the rest of this script expects.
    $global:SpnTenantId     = $global:AzureTenantId
    $global:SpnClientId     = $global:HighPriv_Modern_ApplicationID_Azure
    $global:SpnClientSecret = $global:HighPriv_Modern_Secret_Azure

} else {
    # --- Community / standalone branch (SPN globals set by launcher) ---
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $credential   = New-Object System.Management.Automation.PSCredential ($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $credential -WarningAction SilentlyContinue | Out-Null
    }
}

# Force TLS 1.2 for .NET Framework HTTP stack (PS 5.1 default can be TLS 1.0/1.1)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# 2026-05-02: silent defaults for AI batching globals so the per-chunk loop
# stops emitting [WARN] AI_ChunkSize / AI_MaxRetries / AI_MaxTokens lines on
# every batch when the launcher's locked config doesn't override them.
if (-not $global:AI_ChunkSize  -or [int]$global:AI_ChunkSize  -lt 1) { $global:AI_ChunkSize  = 50 }
if (-not $global:AI_MaxRetries -or [int]$global:AI_MaxRetries -lt 1) { $global:AI_MaxRetries = 3 }
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
    # Idempotent: if a Graph context already exists for our SPN, no-op.
    try {
        $ctx = Get-MgContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.ClientId -eq $global:SpnClientId) {
            Write-Log "Microsoft Graph already connected as SPN $($global:SpnClientId)" "INFO"
            Write-Log "Auth method (Graph)        : already connected (re-using existing session)" "INFO"
            return
        }
    } catch {}
    $secureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $credential   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secureSecret)
    Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
    Write-Log "Connected to Microsoft Graph" "SUCCESS"
    Write-Log ("Auth method (Graph)        : SPN + Secret  (clientId={0}, tenant={1})" -f $global:SpnClientId, $global:SpnTenantId) "INFO"
}

function Connect-AzWithSPN {
    # Idempotent: if an Az context already exists for our SPN, no-op.
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if ($ctx -and $ctx.Account.Id -eq $global:SpnClientId -and $ctx.Subscription) {
            Write-Log "Azure already connected as SPN $($global:SpnClientId) (subscription=$($ctx.Subscription.Name))" "INFO"
            Write-Log "Auth method (Azure)        : already connected (re-using existing session)" "INFO"
            return
        }
    } catch {}
    $secureSecret = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
    $credential   = New-Object System.Management.Automation.PSCredential($global:SpnClientId, $secureSecret)
    # -WarningAction SilentlyContinue suppresses the "TenantId contains more than
    # one active subscription. First one will be selected" + "To override... use
    # Update-AzConfig" noise on every run; we explicitly select a subscription
    # below so the auto-pick doesn't matter.
    Connect-AzAccount -ServicePrincipal -TenantId $global:SpnTenantId -Credential $credential -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    Write-Log "Connected to Azure" "SUCCESS"
    Write-Log ("Auth method (Azure)        : SPN + Secret  (clientId={0}, tenant={1})" -f $global:SpnClientId, $global:SpnTenantId) "INFO"

    # Pick a default subscription so Get-AzRoleDefinition has a scope to read against.
    # Without a subscription selected, Get-AzRoleDefinition (no -Scope) returns an
    # empty result silently even when the SPN has Reader at tenant-root MG -- which
    # was why Azure_BuiltInRoles_Tier0..3 + Azure_Roles_Catalog were empty
    # (reproducible repro in v2.1.174 and earlier; fixed in v2.1.175).
    try {
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx -or -not $ctx.Subscription) {
            $firstSub = Get-AzSubscription -TenantId $global:SpnTenantId -ErrorAction Stop | Select-Object -First 1
            if ($firstSub) {
                Set-AzContext -SubscriptionId $firstSub.Id -TenantId $global:SpnTenantId -ErrorAction Stop | Out-Null
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

function Invoke-AISingleChunk {
    param(
        [string]$CategoryName,
        [array]$Chunk,
        [int]$ChunkIndex,
        [int]$TotalChunks
    )

    $label     = if ($TotalChunks -gt 1) { "$CategoryName (chunk $ChunkIndex/$TotalChunks)" } else { $CategoryName }
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

    # Fail fast if any of the three required OpenAI settings is missing. Previously
    # a typo/empty in one of these silently produced a request that Azure OpenAI
    # answered with an error body, which the response-parsing code then NRE'd on
    # every retry with the cryptic 'Object reference not set to an instance of an
    # object.' (v2.1.176 fix).
    foreach ($pair in @(
        @{ Name = 'OpenAI_ApiKey';     Value = $global:OpenAI_ApiKey },
        @{ Name = 'OpenAI_Endpoint';   Value = $global:OpenAI_Endpoint },
        @{ Name = 'OpenAI_Deployment'; Value = $global:OpenAI_Deployment })) {
        if ([string]::IsNullOrWhiteSpace([string]$pair.Value)) {
            throw ("[$label] `$global:$($pair.Name) is empty. Set it in SecurityInsight.custom.ps1 (Layer 3) or the engine's LauncherConfig.custom.ps1 (Layer 5). See README section 3.8 -- Step 4.")
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
            return $parsed
        }
        catch {
            Write-Log "  [$label] attempt $attempt failed: $($_.Exception.Message)" "WARN"
            if ($attempt -lt $maxRetries) {
                Start-Sleep -Seconds 3
            }
        }
    }

    # All retries exhausted  return fallback for this chunk
    Write-Log "  [$label] all retries exhausted  fallback applied" "ERROR"
    return $Chunk | ForEach-Object {
        [PSCustomObject]@{
            Name   = $_.Name
            Tier   = 99
            Reason = "AI evaluation failed after $maxRetries attempts. Manual review required."
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

    try {
        $builtIn = Get-MgRoleManagementDirectoryRoleDefinition -Filter "isBuiltIn eq true" -All -ErrorAction Stop
        foreach ($r in $builtIn) {
            $perms = @()
            if ($r.RolePermissions) {
                $perms = @($r.RolePermissions | ForEach-Object { $_.AllowedResourceActions } | Where-Object { $_ })
            }
            $roles.Add([PSCustomObject]@{ Id = $r.Id; DisplayName = $r.DisplayName; Description = $r.Description; IsBuiltIn = $true; Permissions = $perms })
        }
        Write-Log "Built-in roles: $($builtIn.Count)" "SUCCESS"

        $custom = Get-MgRoleManagementDirectoryRoleDefinition -Filter "isBuiltIn eq false" -All -ErrorAction SilentlyContinue
        foreach ($r in $custom) {
            $perms = @()
            if ($r.RolePermissions) {
                $perms = @($r.RolePermissions | ForEach-Object { $_.AllowedResourceActions } | Where-Object { $_ })
            }
            $roles.Add([PSCustomObject]@{ Id = $r.Id; DisplayName = $r.DisplayName; Description = $r.Description; IsBuiltIn = $false; Permissions = $perms })
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
            $sp = Get-MgServicePrincipal -Filter "appId eq '$appId'" -ErrorAction SilentlyContinue
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
        $builtIn = Get-AzRoleDefinition -ErrorAction Stop -WarningAction SilentlyContinue | Where-Object { $_.IsCustom -eq $false }
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
        $custom = Get-AzRoleDefinition -Custom -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
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
        [array]$RawAzureRoles
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
            AICallsUsed     = 4
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
    $output | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
    Write-Log "JSON exported to: $OutputFile" "SUCCESS"
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

    Write-Log "SecurityInsight Identity Tiering - Starting" "INFO"
    Write-Log "Output: $OutputFile" "INFO"

    # v2.2.383 -- 24h rebuild skip. If the catalog was rebuilt in the last 24h
    # the AI pass + 4 batch calls + JSON export would just reproduce the same
    # output (the catalog moves on the order of days, not hours). Skip and
    # let the heartbeat record a clean run. Override via custom.ps1:
    #     $global:ForcePrivilegedTierProfilerRebuild = $true
    $_forceRebuild = [bool]$global:ForcePrivilegedTierProfilerRebuild
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

    # ---- Single AI pass  4 batch calls (AD group names tiered from hardcoded list) ----
    $tiered = Invoke-AllAITiering `
        -EntraRoles        $entraRoles `
        -APIPermissions    $apiPermissions `
        -AzureRoles        $azureRoles `

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
        -RawAzureRoles     $azureRoles

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
