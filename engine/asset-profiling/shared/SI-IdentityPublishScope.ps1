#Requires -Version 5.1
<#
    The IDENTITY engine's publish scope: which discovered identities reach SI_Identity_Profile_CL (and the provider
    records in SQL, which are written from the same set). Called once by Invoke-SIOutput, before every sink.

    🔒 OWNER DECISION 2026-10-10 -- "Everything, findings decide". The profile covers EVERY user (enabled, disabled,
       guests, soft-deleted) and EVERY service principal and managed identity the tenant owns. Reports and risk scoring
       decide what matters: a report that means "enabled users" says so itself (`where AccountEnabled == true`), and
       several reports exist precisely BECAUSE an account is disabled (Identity_DisabledAccount_ActivePIMAssignment,
       Identity_DisabledPrivilegedUser, Identity_DisabledUser_StillInCriticalGroup) -- they could never fire while the
       profile dropped every disabled account.

    🔴 WHAT THIS REPLACED. Until 2026-10-10 the block in Invoke-Output dropped every identity whose ENTRA_Enabled was not
       $true. MEASURED on a large customer tenant 2026-10-08/09: every identity run wrote ~8,994 rows (8,939 enabled
       members, 1 guest, 0 disabled, 44 SPNs, 10 MIs) while Graph counted 22,705 users -- discovery read them all, and
       this stage threw the disabled ones away. "0 disabled" in a 22k-user tenant was the tell.

    WHAT IS STILL LEFT OUT BY DEFAULT -- one rule, unchanged: a Microsoft first-party application (appOwnerOrganizationId
    = Microsoft's tenant) that this tenant granted NOTHING -- no consented Graph permission, no Entra directory role
    (permanent or PIM-eligible), no Azure RBAC. The customer has no action available on it. Users carry no owner
    tenant, so the rule can never catch a user.

    KNOBS (names unchanged, so existing configs keep working):
      $global:SI_IncludeInactive_Identity     = $true   publish everything, Microsoft-published applications too
      $global:SI_RequireRecentSignIn_Identity = $true   TIGHTEN: only identities with a sign-in within SI_ActiveStaleDays
#>

$script:SIMicrosoftFirstPartyTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

function Test-SIIdentityValueHasAny {
    <#
        Does a grant field hold anything at all?
        🪤 MEASURED 2026-08-27, and it published 839 Microsoft applications the tenant had granted NOTHING before it was
        caught: these fields reach Output THROUGH THE STAGING BLOB, so an EMPTY array arrives as a PSCustomObject with
        ZERO properties -- and `@($v).Count` on that is 1, not 0. A real grant arrives as System.Object[]. So the
        PSObject branch counts PROPERTIES, and it comes after the collection tests.
    #>
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return -not [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IDictionary]) { return ($Value.Count -gt 0) }
    if ($Value -is [System.Collections.IEnumerable]) { return (@($Value).Count -gt 0) }
    if ($Value.PSObject -and $null -ne $Value.PSObject.Properties) { return (@($Value.PSObject.Properties).Count -gt 0) }
    return $true
}

function Get-SIIdentityRecordKind {
    <# User | Guest | ServicePrincipal | ManagedIdentity | Other -- for the counts only; never a filter. #>
    param($Metadata)
    if (-not $Metadata) { return 'Other' }
    $t = [string]$Metadata.ENTRA_AssetType
    $sp = [string]$Metadata.ENTRA_SPType
    if ($sp -eq 'ManagedIdentity') { return 'ManagedIdentity' }
    if ($t -eq 'ServicePrincipal' -or $Metadata.ENTRA_SPObjectId) { return 'ServicePrincipal' }
    if ([string]$Metadata.ENTRA_UserType -eq 'Guest') { return 'Guest' }
    if ($t -eq 'User' -or $Metadata.ENTRA_UserId -or $Metadata.ENTRA_UPN) { return 'User' }
    return 'Other'
}

function Select-SIIdentityPublishScope {
    <#
    .SYNOPSIS
        PURE. The identity records to publish, and the counts that explain the number.
    .OUTPUTS
        [pscustomobject] Records (object[]), Before, Published, Users, Guests, Disabled, ServicePrincipals,
        ManagedIdentities, ExcludedVendor, GrantedFirstParty, ExcludedNoRecentSignIn, IncludeAll, RequireRecentSignIn
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$Records = @(),
        [switch]$IncludeAll,
        [switch]$RequireRecentSignIn,
        [int]$StaleDays = 30
    )
    if ($StaleDays -le 0) { $StaleDays = 30 }
    $kept = New-Object System.Collections.Generic.List[object]
    $c = [ordered]@{ Users = 0; Guests = 0; Disabled = 0; ServicePrincipals = 0; ManagedIdentities = 0
                    ExcludedVendor = 0; GrantedFirstParty = 0; ExcludedNoRecentSignIn = 0 }

    foreach ($rec in @($Records)) {
        if ($null -eq $rec) { continue }
        $m = $rec.Metadata
        if (-not $IncludeAll -and $m) {
            $granted = (Test-SIIdentityValueHasAny $m.ENTRA_AppPermissions_Application) -or
                       (Test-SIIdentityValueHasAny $m.ENTRA_AppPermissions_Delegated)   -or
                       (Test-SIIdentityValueHasAny $m.ENTRA_DirectoryRolesPermanent)    -or
                       (Test-SIIdentityValueHasAny $m.ENTRA_DirectoryRolesEligible)     -or
                       (Test-SIIdentityValueHasAny $m.ENTRA_AzureDelegations)
            $ownerTid = [string]$m.ENTRA_SPAppOwnerTenant
            # Microsoft's own application, nothing granted here -> no customer action. 🔒 Users carry no owner tenant.
            if ($ownerTid -eq $script:SIMicrosoftFirstPartyTenantId -and -not $granted) { $c.ExcludedVendor++; continue }
            if ($RequireRecentSignIn) {
                $days = $null
                if ($null -ne $m.ENTRA_LastSignInDays) { try { $days = [int]$m.ENTRA_LastSignInDays } catch { $days = $null } }
                if ($null -eq $days -or $days -lt 0 -or $days -gt $StaleDays) { $c.ExcludedNoRecentSignIn++; continue }
            }
            if ($granted -and $ownerTid -eq $script:SIMicrosoftFirstPartyTenantId) { $c.GrantedFirstParty++ }
        }
        $kept.Add($rec)
        switch (Get-SIIdentityRecordKind $m) {
            'User'             { $c.Users++ }
            'Guest'            { $c.Guests++ }
            'ServicePrincipal' { $c.ServicePrincipals++ }
            'ManagedIdentity'  { $c.ManagedIdentities++ }
        }
        # disabled = the source SAID so (accountEnabled false); a record that carries no Enabled value is not counted
        if ($m -and $null -ne $m.ENTRA_Enabled -and $m.ENTRA_Enabled -ne $true -and [string]$m.ENTRA_Enabled -ne 'True') { $c.Disabled++ }
    }

    $out = [ordered]@{ Records = $kept.ToArray(); Before = @($Records | Where-Object { $null -ne $_ }).Count; Published = $kept.Count }
    foreach ($k in $c.Keys) { $out[$k] = $c[$k] }
    $out.IncludeAll = [bool]$IncludeAll
    $out.RequireRecentSignIn = [bool]$RequireRecentSignIn
    [pscustomobject]$out
}

function Format-SIIdentityPublishScopeLine {
    <# PURE. The one line the run log carries -- says what was published, by kind, and what was left out and why. #>
    param([Parameter(Mandatory)]$Scope, [int]$StaleDays = 30)
    if ($Scope.IncludeAll) {
        return ('identity scope: {0} -> {1}, nothing left out ($global:SI_IncludeInactive_Identity = $true) -- {2} user(s), {3} guest(s), {4} service principal(s), {5} managed identit(ies); {6} of them disabled.' -f `
            $Scope.Before, $Scope.Published, $Scope.Users, $Scope.Guests, $Scope.ServicePrincipals, $Scope.ManagedIdentities, $Scope.Disabled)
    }
    $line = ('identity scope: {0} -> {1}. Published {2} user(s), {3} guest(s), {4} service principal(s), {5} managed identit(ies) -- {6} of them disabled (published: reports decide what matters). Left out {7} Microsoft-published application(s) this tenant granted nothing; {8} Microsoft-published application(s) holding permissions granted here are published.' -f `
        $Scope.Before, $Scope.Published, $Scope.Users, $Scope.Guests, $Scope.ServicePrincipals, $Scope.ManagedIdentities, $Scope.Disabled, $Scope.ExcludedVendor, $Scope.GrantedFirstParty)
    if ($Scope.RequireRecentSignIn) {
        $line += (' A sign-in within {0} day(s) was REQUIRED ($global:SI_RequireRecentSignIn_Identity), so {1} more were left out -- including any whose sign-in history is simply unavailable.' -f $StaleDays, $Scope.ExcludedNoRecentSignIn)
    }
    $line
}
