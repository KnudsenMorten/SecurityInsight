#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- identity-catalog tier computer.

    Pure-function port of the tier-compute logic from the legacy
    SCRIPTS\IdentityAssetsCollectDefineTierIngestLog.ps1.

    The catalog itself (privilege-tier-catalog/privilege-tier-catalog.locked.json) is the
    AI-curated authority -- it lists every Entra role, Graph application
    permission, on-prem AD privileged group, and Azure built-in role with
    its tier (0-3). Per-asset tier computation is then 100% deterministic
    catalog-match: enumerate the principal's roles+perms, look each up,
    take Min across the four providers, attach proofs.

    No Graph calls, no Azure REST, no AI calls. All inputs are PowerShell
    arrays (string[]). Stage Discover enumerates the perms
    and assignments; this module ranks them.

    Usage:
        . v2.2\identity-catalog\IdentityCatalogTierComputer.ps1
        Initialize-SIIdentityCatalog -Path 'privilege-tier-catalog/privilege-tier-catalog.locked.json'
        $tier = Get-SITierFromEntraAPIPerms -Perms @('Directory.ReadWrite.All','Mail.Send')
        $matches = Get-SIEntraRoleMatches -Roles @('Global Administrator')
        $effective = Get-SIMinTier -Tiers @($entraTier, $apiTier, $azureTier, $adTier)
#>

# Catalog state -- script-scoped so callers don't see internal vars.
# Initialize-SIIdentityCatalog populates these from the JSON file.
$script:SICatalog_EntraRoles_Tier0    = @()
$script:SICatalog_EntraRoles_Tier1    = @()
$script:SICatalog_EntraRoles_Tier2    = @()
$script:SICatalog_EntraRoles_Tier3    = @()
$script:SICatalog_APIPerms_Tier0      = $null   # HashSet[string] case-insensitive
$script:SICatalog_APIPerms_Tier1      = $null
$script:SICatalog_APIPerms_Tier2      = $null
$script:SICatalog_APIPerms_Tier3      = $null
$script:SICatalog_ADGroups_Lookup     = @{}     # lower-case Name -> entry object
$script:SICatalog_ADGroups_LockedCount  = 0
$script:SICatalog_ADGroups_CustomCount  = 0
$script:SICatalog_AzureRoles_Tier0    = @()
$script:SICatalog_AzureRoles_Tier1    = @()
$script:SICatalog_AzureRoles_Tier2    = @()
$script:SICatalog_AzureRoles_Tier3    = @()
$script:SICatalog_LoadedFrom          = $null
$script:SICatalog_CustomFrom          = $null
$script:SICatalog_GeneratedAt         = $null

function Expand-SITierSection {
    # PS 5.1 ConvertFrom-Json quirks: empty array becomes empty PSCustomObject,
    # single-element array becomes a bare object. Always returns a typed array.
    param([object]$Section)
    if ($null -eq $Section)                          { return @() }
    if ($Section -is [System.Array])                 { return $Section }
    if ($Section -is [System.Collections.IEnumerable] -and -not ($Section -is [string])) { return @($Section) }
    $props = @($Section.PSObject.Properties)
    if ($props.Count -eq 0)                          { return @() }
    return @($Section)
}

function Merge-SIIdentityTierSection {
    # Per-section merge: locked entries first, then any custom entry with the
    # same key REPLACES, and any custom entry with a new key is APPENDED.
    # Returns an array of the merged entries (preserves locked order, then
    # appends new custom rows).
    param(
        [object[]]$LockedRows,
        [object[]]$CustomRows,
        [string]$KeyField   # 'Name' for AD groups + Azure roles; 'DisplayName' for Entra roles; 'Value' for API perms
    )
    $merged = [ordered]@{}
    foreach ($r in @($LockedRows)) {
        if ($null -eq $r) { continue }
        $k = [string]$r.$KeyField
        if (-not [string]::IsNullOrWhiteSpace($k)) { $merged[$k.ToLowerInvariant()] = $r }
    }
    foreach ($r in @($CustomRows)) {
        if ($null -eq $r) { continue }
        $k = [string]$r.$KeyField
        if (-not [string]::IsNullOrWhiteSpace($k)) { $merged[$k.ToLowerInvariant()] = $r }   # replace OR add
    }
    return @($merged.Values)
}

function Initialize-SIIdentityCatalog {
    [CmdletBinding()]
    param(
        [Parameter()] [string]$Path,
        [Parameter()] [string]$CustomPath,
        [Parameter()] [switch]$Force
    )

    # Cache hit: if the catalog has already been loaded (any of the four AD-tier
    # tables / role tables non-empty), skip work and the banner re-print.
    if (-not $Force -and `
        $script:SICatalog_LoadedFrom -and `
        $script:SICatalog_ADGroups_Lookup -and `
        $script:SICatalog_ADGroups_Lookup.Count -gt 0) {
        return [pscustomobject]@{
            LoadedFrom      = $script:SICatalog_LoadedFrom
            CustomFrom      = $script:SICatalog_CustomFrom
            GeneratedAt     = $script:SICatalog_GeneratedAt
            EntraRoleCounts = @{ T0=$script:SICatalog_EntraRoles_Tier0.Count; T1=$script:SICatalog_EntraRoles_Tier1.Count; T2=$script:SICatalog_EntraRoles_Tier2.Count; T3=$script:SICatalog_EntraRoles_Tier3.Count }
            APIPermCounts   = @{ T0=$script:SICatalog_APIPerms_Tier0.Count;   T1=$script:SICatalog_APIPerms_Tier1.Count;   T2=$script:SICatalog_APIPerms_Tier2.Count;   T3=$script:SICatalog_APIPerms_Tier3.Count }
            ADGroupCount    = $script:SICatalog_ADGroups_Lookup.Count
            ADGroupCustom   = $script:SICatalog_ADGroups_CustomCount
            AzureRoleCounts = @{ T0=$script:SICatalog_AzureRoles_Tier0.Count; T1=$script:SICatalog_AzureRoles_Tier1.Count; T2=$script:SICatalog_AzureRoles_Tier2.Count; T3=$script:SICatalog_AzureRoles_Tier3.Count }
            CacheHit        = $true
        }
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        # file moved from identity-catalog/ to engine/shared/.
        # $PSScriptRoot now = v2.2/engine/asset-profiling/shared/; three parents -> SecurityInsight/
        $solnRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $Path = Join-Path $solnRoot 'privilege-tier-catalog/privilege-tier-catalog.locked.json'
    }

    if ([string]::IsNullOrWhiteSpace($CustomPath)) {
        # Customer override path -- deleted identity-catalog-custom/.
        # New convention: rules-custom/identity/AssetProfileByExtensionAttributes.yaml
        # carries the equivalent customisation. This loader's CustomPath remains
        # for legacy config-style overrides; absent path = silent no-op.
        $v22Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $CustomPath = Join-Path $v22Root 'asset-profiling-enrichment\identity\PrivilegeTierClassifier.json'
    }

    if (-not (Test-Path $Path)) {
        throw "SI identity catalog not found at: $Path. Run launcher\privilege-tier-classifier\launcher.community-vm.ps1 (community) or launcher.internal-vm.ps1 (internal) once to generate it; the identity engine cannot classify users without this catalog."
    }

    $tierDefs = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    # Optional custom override -- file may not exist.
    $customDefs   = $null
    $customLoaded = $false
    if (Test-Path $CustomPath) {
        try {
            $customRaw = Get-Content -Path $CustomPath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($customRaw)) {
                $customDefs   = $customRaw | ConvertFrom-Json
                $customLoaded = $true
            }
        } catch {
            Write-Warning ("SI identity catalog -- failed to parse custom override at {0}: {1}" -f $CustomPath, $_.Exception.Message)
            $customDefs = $null
        }
    }

    # Helper: pull a section out of the custom file with shape tolerance.
    function _SafeCustomSection { param($Defs, [string]$Section)
        if ($null -eq $Defs) { return @() }
        if ($Defs -is [System.Collections.IDictionary]) {
            if ($Defs.Contains($Section)) { return @(Expand-SITierSection $Defs[$Section]) } else { return @() }
        }
        if ($Defs.PSObject.Properties[$Section]) { return @(Expand-SITierSection $Defs.$Section) }
        return @()
    }

    # ---- Entra roles (DisplayName key) -- BuiltIn + Custom (locked) + Custom (override) merged per tier
    $entraTier0Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_BuiltInRoles_Tier0) + @(Expand-SITierSection $tierDefs.EntraID_CustomRoles_Tier0)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_CustomRoles_Tier0') `
        -KeyField 'DisplayName'
    $entraTier1Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_BuiltInRoles_Tier1) + @(Expand-SITierSection $tierDefs.EntraID_CustomRoles_Tier1)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_CustomRoles_Tier1') `
        -KeyField 'DisplayName'
    $entraTier2Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_BuiltInRoles_Tier2) + @(Expand-SITierSection $tierDefs.EntraID_CustomRoles_Tier2)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_CustomRoles_Tier2') `
        -KeyField 'DisplayName'
    $entraTier3Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_BuiltInRoles_Tier3) + @(Expand-SITierSection $tierDefs.EntraID_CustomRoles_Tier3)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_CustomRoles_Tier3') `
        -KeyField 'DisplayName'

    $script:SICatalog_EntraRoles_Tier0 = @($entraTier0Merged | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_EntraRoles_Tier1 = @($entraTier1Merged | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_EntraRoles_Tier2 = @($entraTier2Merged | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_EntraRoles_Tier3 = @($entraTier3Merged | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ } | Select-Object -Unique)

    # ---- API permissions -- Value field, HashSet for O(1) case-insensitive lookup.
    # The locked catalog publishes EntraID_APIPermissions_Tier* directly; we also
    # accept matching custom override sections (rare but kept for symmetry).
    $apiTier0Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_APIPermissions_Tier0)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_APIPermissions_Tier0') `
        -KeyField 'Value'
    $apiTier1Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_APIPermissions_Tier1)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_APIPermissions_Tier1') `
        -KeyField 'Value'
    $apiTier2Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_APIPermissions_Tier2)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_APIPermissions_Tier2') `
        -KeyField 'Value'
    $apiTier3Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.EntraID_APIPermissions_Tier3)) `
        -CustomRows (_SafeCustomSection $customDefs 'EntraID_APIPermissions_Tier3') `
        -KeyField 'Value'

    $script:SICatalog_APIPerms_Tier0 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $apiTier0Merged) { $v = [string]$r.Value; if ($v) { [void]$script:SICatalog_APIPerms_Tier0.Add($v) } }
    $script:SICatalog_APIPerms_Tier1 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $apiTier1Merged) { $v = [string]$r.Value; if ($v) { [void]$script:SICatalog_APIPerms_Tier1.Add($v) } }
    $script:SICatalog_APIPerms_Tier2 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $apiTier2Merged) { $v = [string]$r.Value; if ($v) { [void]$script:SICatalog_APIPerms_Tier2.Add($v) } }
    $script:SICatalog_APIPerms_Tier3 = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $apiTier3Merged) { $v = [string]$r.Value; if ($v) { [void]$script:SICatalog_APIPerms_Tier3.Add($v) } }

    # ---- AD groups -- BuiltIn (locked) + new AD_CustomGroups (locked OR override).
    # Both BuiltIn (Microsoft-defined) and CustomGroups (tenant-specific) feed the
    # same lookup. On-disk the locked file may already publish AD_CustomGroups_*
    # (currently empty placeholders); the customer override file contributes the
    # tenant-specific names like ORG-FINANCE / IT-Admins.
    $adLockedRows = @(
        @(Expand-SITierSection $tierDefs.AD_BuiltInPermissionGroups_Tier0) +
        @(Expand-SITierSection $tierDefs.AD_BuiltInPermissionGroups_Tier1) +
        @(Expand-SITierSection $tierDefs.AD_BuiltInPermissionGroups_Tier2) +
        @(Expand-SITierSection $tierDefs.AD_BuiltInPermissionGroups_Tier3) +
        @(Expand-SITierSection $tierDefs.AD_CustomGroups_Tier0) +
        @(Expand-SITierSection $tierDefs.AD_CustomGroups_Tier1) +
        @(Expand-SITierSection $tierDefs.AD_CustomGroups_Tier2) +
        @(Expand-SITierSection $tierDefs.AD_CustomGroups_Tier3)
    )
    $adCustomRows = @()
    if ($customLoaded) {
        $adCustomRows = @(
            @(_SafeCustomSection $customDefs 'AD_CustomGroups_Tier0') +
            @(_SafeCustomSection $customDefs 'AD_CustomGroups_Tier1') +
            @(_SafeCustomSection $customDefs 'AD_CustomGroups_Tier2') +
            @(_SafeCustomSection $customDefs 'AD_CustomGroups_Tier3') +
            @(_SafeCustomSection $customDefs 'AD_BuiltInPermissionGroups_Tier0') +
            @(_SafeCustomSection $customDefs 'AD_BuiltInPermissionGroups_Tier1') +
            @(_SafeCustomSection $customDefs 'AD_BuiltInPermissionGroups_Tier2') +
            @(_SafeCustomSection $customDefs 'AD_BuiltInPermissionGroups_Tier3')
        )
    }
    # Ensure each custom row carries a Tier (1-tag override files keep Tier on
    # the entry; if the user dropped one, the section name would be the only
    # source of truth -- and the merged sections above already kept entries
    # that had a Tier on them, so we can rely on entry.Tier being present).

    $script:SICatalog_ADGroups_Lookup = @{}
    $script:SICatalog_ADGroups_LockedCount = 0
    foreach ($entry in $adLockedRows) {
        if ($null -eq $entry) { continue }
        $n = [string]$entry.Name
        if ($n) {
            $script:SICatalog_ADGroups_Lookup[$n.ToLower()] = $entry
            $script:SICatalog_ADGroups_LockedCount++
        }
    }
    $script:SICatalog_ADGroups_CustomCount = 0
    foreach ($entry in $adCustomRows) {
        if ($null -eq $entry) { continue }
        $n = [string]$entry.Name
        if ($n) {
            $script:SICatalog_ADGroups_Lookup[$n.ToLower()] = $entry   # replace OR add
            $script:SICatalog_ADGroups_CustomCount++
        }
    }

    # ---- Azure roles (Name key) -- BuiltIn + Custom (locked) + Custom (override) merged per tier
    $azTier0Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.Azure_BuiltInRoles_Tier0) + @(Expand-SITierSection $tierDefs.Azure_CustomRoles_Tier0)) `
        -CustomRows (_SafeCustomSection $customDefs 'Azure_CustomRoles_Tier0') `
        -KeyField 'Name'
    $azTier1Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.Azure_BuiltInRoles_Tier1) + @(Expand-SITierSection $tierDefs.Azure_CustomRoles_Tier1)) `
        -CustomRows (_SafeCustomSection $customDefs 'Azure_CustomRoles_Tier1') `
        -KeyField 'Name'
    $azTier2Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.Azure_BuiltInRoles_Tier2) + @(Expand-SITierSection $tierDefs.Azure_CustomRoles_Tier2)) `
        -CustomRows (_SafeCustomSection $customDefs 'Azure_CustomRoles_Tier2') `
        -KeyField 'Name'
    $azTier3Merged = Merge-SIIdentityTierSection `
        -LockedRows (@(Expand-SITierSection $tierDefs.Azure_BuiltInRoles_Tier3) + @(Expand-SITierSection $tierDefs.Azure_CustomRoles_Tier3)) `
        -CustomRows (_SafeCustomSection $customDefs 'Azure_CustomRoles_Tier3') `
        -KeyField 'Name'

    $script:SICatalog_AzureRoles_Tier0 = @($azTier0Merged | ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_AzureRoles_Tier1 = @($azTier1Merged | ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_AzureRoles_Tier2 = @($azTier2Merged | ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique)
    $script:SICatalog_AzureRoles_Tier3 = @($azTier3Merged | ForEach-Object { [string]$_.Name } | Where-Object { $_ } | Select-Object -Unique)

    $script:SICatalog_LoadedFrom  = $Path
    $script:SICatalog_CustomFrom  = if ($customLoaded) { $CustomPath } else { $null }
    $script:SICatalog_GeneratedAt = if ($tierDefs.Metadata) { [string]$tierDefs.Metadata.GeneratedAt } else { '' }

    # ---- Banner ----
    Write-SIInfo ("identity catalog loaded -- dated {0}" -f $script:SICatalog_GeneratedAt)
    Write-SIInfo (" Entra roles    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}" -f `
        $script:SICatalog_EntraRoles_Tier0.Count, `
        $script:SICatalog_EntraRoles_Tier1.Count, `
        $script:SICatalog_EntraRoles_Tier2.Count, `
        $script:SICatalog_EntraRoles_Tier3.Count)
    Write-SIInfo (" Graph perms    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}" -f `
        $script:SICatalog_APIPerms_Tier0.Count, `
        $script:SICatalog_APIPerms_Tier1.Count, `
        $script:SICatalog_APIPerms_Tier2.Count, `
        $script:SICatalog_APIPerms_Tier3.Count)
    Write-SIInfo (" AD groups      total       : {0,3} (+{1} custom)" -f `
        $script:SICatalog_ADGroups_Lookup.Count, `
        $script:SICatalog_ADGroups_CustomCount)
    Write-SIInfo (" Azure roles    T0/T1/T2/T3 : {0,3} / {1,3} / {2,4} / {3,4}" -f `
        $script:SICatalog_AzureRoles_Tier0.Count, `
        $script:SICatalog_AzureRoles_Tier1.Count, `
        $script:SICatalog_AzureRoles_Tier2.Count, `
        $script:SICatalog_AzureRoles_Tier3.Count)

    [pscustomobject]@{
        LoadedFrom      = $Path
        CustomFrom      = $script:SICatalog_CustomFrom
        GeneratedAt     = $script:SICatalog_GeneratedAt
        EntraRoleCounts = @{ T0=$script:SICatalog_EntraRoles_Tier0.Count; T1=$script:SICatalog_EntraRoles_Tier1.Count; T2=$script:SICatalog_EntraRoles_Tier2.Count; T3=$script:SICatalog_EntraRoles_Tier3.Count }
        APIPermCounts   = @{ T0=$script:SICatalog_APIPerms_Tier0.Count;   T1=$script:SICatalog_APIPerms_Tier1.Count;   T2=$script:SICatalog_APIPerms_Tier2.Count;   T3=$script:SICatalog_APIPerms_Tier3.Count }
        ADGroupCount    = $script:SICatalog_ADGroups_Lookup.Count
        ADGroupCustom   = $script:SICatalog_ADGroups_CustomCount
        AzureRoleCounts = @{ T0=$script:SICatalog_AzureRoles_Tier0.Count; T1=$script:SICatalog_AzureRoles_Tier1.Count; T2=$script:SICatalog_AzureRoles_Tier2.Count; T3=$script:SICatalog_AzureRoles_Tier3.Count }
        CacheHit        = $false
    }
}

# ---- Tier-from-X functions ---------------------------------------------------
# Each returns the lowest tier matched (0=critical, 3=lowest), or $null when no
# input. If input is non-empty but nothing matches the catalog, default to 2.

function Get-SITierFromEntraRoles {
    param([string[]]$Roles)
    foreach ($r in $Roles) { if ($script:SICatalog_EntraRoles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($script:SICatalog_EntraRoles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($script:SICatalog_EntraRoles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($script:SICatalog_EntraRoles_Tier3 -contains $r) { return 3 } }
    if ($Roles -and $Roles.Count -gt 0) { return 2 }
    return $null
}

function Get-SITierFromEntraAPIPerms {
    param([string[]]$Perms)
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier0.Contains($p)) { return 0 } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier1.Contains($p)) { return 1 } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier2.Contains($p)) { return 2 } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier3.Contains($p)) { return 3 } }
    if ($Perms -and $Perms.Count -gt 0) { return 2 }
    return $null
}

function Get-SITierFromADGroups {
    param([string[]]$Groups)
    $minTier = $null
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $script:SICatalog_ADGroups_Lookup[$g.ToLower()]
        if ($entry) {
            $t = [int]$entry.Tier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier
}

function Get-SITierFromAzureRoles {
    param([string[]]$Roles)
    foreach ($r in $Roles) { if ($script:SICatalog_AzureRoles_Tier0 -contains $r) { return 0 } }
    foreach ($r in $Roles) { if ($script:SICatalog_AzureRoles_Tier1 -contains $r) { return 1 } }
    foreach ($r in $Roles) { if ($script:SICatalog_AzureRoles_Tier2 -contains $r) { return 2 } }
    foreach ($r in $Roles) { if ($script:SICatalog_AzureRoles_Tier3 -contains $r) { return 3 } }
    if ($Roles -and $Roles.Count -gt 0) { return 2 }
    return $null
}

# ---- Match functions (return per-input proof rows) ---------------------------

function Get-SIEntraRoleMatches {
    param([string[]]$Roles)
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Roles) {
        $t = if     ($script:SICatalog_EntraRoles_Tier0 -contains $r) { 0 }
             elseif ($script:SICatalog_EntraRoles_Tier1 -contains $r) { 1 }
             elseif ($script:SICatalog_EntraRoles_Tier2 -contains $r) { 2 }
             elseif ($script:SICatalog_EntraRoles_Tier3 -contains $r) { 3 }
             else                                                      { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-SIEntraPermMatches {
    param([string[]]$Perms)
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Perms) {
        $t = if     ($script:SICatalog_APIPerms_Tier0.Contains($p)) { 0 }
             elseif ($script:SICatalog_APIPerms_Tier1.Contains($p)) { 1 }
             elseif ($script:SICatalog_APIPerms_Tier2.Contains($p)) { 2 }
             elseif ($script:SICatalog_APIPerms_Tier3.Contains($p)) { 3 }
             else                                                    { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Permission = $p; CatalogTier = $t }) }
    }
    return $matched
}

function Get-SIAzureRoleMatches {
    param([string[]]$Roles)
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Roles) {
        $t = if     ($script:SICatalog_AzureRoles_Tier0 -contains $r) { 0 }
             elseif ($script:SICatalog_AzureRoles_Tier1 -contains $r) { 1 }
             elseif ($script:SICatalog_AzureRoles_Tier2 -contains $r) { 2 }
             elseif ($script:SICatalog_AzureRoles_Tier3 -contains $r) { 3 }
             else                                                      { $null }
        if ($null -ne $t) { $matched.Add([ordered]@{ Role = $r; CatalogTier = $t }) }
    }
    return $matched
}

function Get-SIADGroupMatches {
    param([string[]]$Groups)
    $matched = New-Object System.Collections.Generic.List[object]
    foreach ($g in $Groups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        $entry = $script:SICatalog_ADGroups_Lookup[$g.ToLower()]
        if ($entry) {
            $matched.Add([ordered]@{
                Name   = [string]$entry.Name
                Tier   = [int]$entry.Tier
                Reason = [string]$entry.Reason
            })
        }
    }
    return $matched
}

function Get-SIHighestRiskEntraAPIPermission {
    param([string[]]$Perms)
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier0.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier1.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier2.Contains($p)) { return $p } }
    foreach ($p in $Perms) { if ($script:SICatalog_APIPerms_Tier3.Contains($p)) { return $p } }
    $first = $Perms | Select-Object -First 1
    if ($null -ne $first) { return [string]$first } else { return '' }
}

# ---- Azure scope-aware tier --------------------------------------------------
# Risk decreases as scope narrows -- same role is less impactful at a lower scope.

function Get-SIAzureScopeLevel {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return 1 }   # unknown defaults to subscription
    $s = $Scope.Trim().TrimEnd('/')
    if ($s -eq '' -or $s -eq '/')                                                 { return 0 }   # tenant root
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$')    { return 0 }   # any MG
    if ($s -match '^/subscriptions/[^/]+$')                                       { return 1 }   # subscription
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$')                  { return 2 }   # resource group
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/')                        { return 3 }   # individual resource
    if ($s -match '^/subscriptions/[^/]+/providers/')                             { return 1 }   # subscription resource provider
    return 1
}

function Get-SIAzureScopeLabel {
    param([string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return 'Unknown' }
    $s = $Scope.Trim().TrimEnd('/')
    if ($s -eq '' -or $s -eq '/')                                                 { return 'Tenant Root' }
    if ($s -match '^/providers/Microsoft\.Management/managementGroups/([^/]+)$')  { return ('Management Group: {0}' -f $matches[1]) }
    if ($s -match '^/subscriptions/([^/]+)$')                                     { return ('Subscription: {0}' -f $matches[1]) }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)$')                { return ('Resource Group: {0}' -f $matches[1]) }
    if ($s -match '^/subscriptions/[^/]+/resourceGroups/([^/]+)/providers/[^/]+/([^/]+)/([^/]+)') { return ('Resource: {0} ({1})' -f $matches[3], $matches[2]) }
    if ($s -match '^/subscriptions/[^/]+/providers/(.+)$')                        { return ('Subscription Resource: {0}' -f $matches[1]) }
    return $Scope
}

function Get-SIAzureEffectiveTier {
    # Effective tier per assignment = Max(RoleTier, ScopeLevel).
    # Role defines ceiling risk; scope can only reduce impact (raise tier number).
    #   Owner (T0) at TenantRoot   -> Max(0,0) = 0
    #   Owner (T0) at Subscription -> Max(0,1) = 1
    #   Owner (T0) at ResourceGroup-> Max(0,2) = 2
    #   Reader (T3) at TenantRoot  -> Max(3,0) = 3 (Reader is always low risk)
    param([string]$RoleName, [string]$Scope)
    $roleTier = Get-SITierFromAzureRoles -Roles @($RoleName)
    if ($null -eq $roleTier) { $roleTier = 2 }   # unknown role = standard
    $scopeLevel = Get-SIAzureScopeLevel -Scope $Scope
    return [Math]::Max($roleTier, $scopeLevel)
}

# ---- Min across providers ----------------------------------------------------

function Get-SIMinTier {
    # Returns the lowest (most privileged) tier from supplied values.
    # Nulls and -1 are excluded (no signal). Default 3 when nothing applies.
    param([object[]]$Tiers)
    $valid = @($Tiers | Where-Object { $_ -ne $null -and [int]$_ -ge 0 } | ForEach-Object { [int]$_ })
    if ($valid.Count -eq 0) { return 3 }
    return ($valid | Measure-Object -Minimum).Minimum
}
