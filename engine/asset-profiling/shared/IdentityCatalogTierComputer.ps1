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
# #1194: which catalog the built-in sections came from, in words ("the daily classified catalog version 2026.11.10, built
# 2026-11-10" / "built here with AI on ..." / "the shipped catalog dated ..."). Every identity row records it.
$script:SICatalog_Label               = $null

function Get-SIIdentityCatalogLabel {
    <# The loaded catalog's source, version and date in words ('' before Initialize-SIIdentityCatalog ran). #>
    [string]$script:SICatalog_Label
}

function Get-SIIdentityCatalogSourceLabel {
    <# PURE. The words for the catalog in effect. #>
    param([string]$Source, [string]$Version, [string]$BuiltUtc, [string]$CustomGeneratedAt, [string]$ShippedGeneratedAt)
    $day = { param($s) if (-not $s) { return '' } try { ([datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch { [string]$s } }
    if ($Source -eq 'invardia' -and $Version) {
        $d = & $day $BuiltUtc
        return ('the daily classified catalog version {0}{1}' -f $Version, $(if ($d) { ', built ' + $d } else { '' }))
    }
    if ($Source -eq 'ai') {
        $d = & $day $CustomGeneratedAt
        return ('built here with AI{0} (an entry it does not list: the shipped catalog dated {1})' -f $(if ($d) { ' on ' + $d } else { '' }), $ShippedGeneratedAt)
    }
    if ($Source -eq 'invardia') { return ('the shipped catalog dated {0} (the daily classified catalog is not downloaded yet)' -f $ShippedGeneratedAt) }
    $d = & $day $CustomGeneratedAt
    if ($d) { return ('the shipped catalog dated {0}, with this tenant''s catalog of {1}' -f $ShippedGeneratedAt, $d) }
    ('the shipped catalog dated {0}' -f $ShippedGeneratedAt)
}

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

function Merge-SIClassifiedBuiltIns {
    <#
        PURE. "Tier classification wins" (owner 2026-11-11). The tenant's CLASSIFIED catalog (the classifier's
        privilege-tier-catalog.custom.json: built with AI, or from the daily download) decides the tier of every BUILT-IN
        entry it lists -- AD built-in groups, Entra built-in roles, API permissions, Azure built-in roles -- PER ENTRY: the
        entry is taken out of the base's tier sections and put in the tier the classified catalog gives it. An entry the
        classified catalog does not list keeps its base (shipped) tier. Custom-role sections are not touched here (the
        tenant's custom roles are merged by the reader as before).
        Before this, only the API permissions and AD groups of the classified catalog were laid over the base, and per TIER
        (an entry in both kept the more privileged tier), while the Entra and Azure built-in roles were read from the shipped
        file only. Returns @{ Catalog (a new object; the inputs are not changed); Entries (how many classified entries) }.
    #>
    param([Parameter(Mandatory)]$Base, $Classified)
    if ($null -eq $Classified) { return [pscustomobject]@{ Catalog = $Base; Entries = 0 } }
    $sectionOf = {
        param($Doc, [string]$Name)
        if ($null -eq $Doc) { return @() }
        if ($Doc -is [System.Collections.IDictionary]) { if ($Doc.Contains($Name)) { return @(Expand-SITierSection $Doc[$Name]) } else { return @() } }
        $p = $Doc.PSObject.Properties[$Name]
        if ($p) { return @(Expand-SITierSection $p.Value) }
        @()
    }
    $out = [ordered]@{}
    foreach ($p in $Base.PSObject.Properties) { $out[$p.Name] = $p.Value }
    $n = 0
    foreach ($s in @(@{ F = 'AD_BuiltInPermissionGroups'; K = 'Name' }, @{ F = 'EntraID_BuiltInRoles'; K = 'DisplayName' },
                     @{ F = 'EntraID_APIPermissions'; K = 'Value' }, @{ F = 'Azure_BuiltInRoles'; K = 'Name' })) {
        $tierOf = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::OrdinalIgnoreCase)
        $rowOf = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($t in 0..3) {
            foreach ($row in (& $sectionOf $Classified ('{0}_Tier{1}' -f $s.F, $t))) {
                if ($null -eq $row) { continue }
                $k = ([string]$row.($s.K)).Trim()
                if ($k -and -not $tierOf.ContainsKey($k)) { $tierOf[$k] = $t; $rowOf[$k] = $row }
            }
        }
        if ($tierOf.Count -eq 0) { continue }
        $lists = @{}
        foreach ($t in 0..3) {
            $l = New-Object System.Collections.Generic.List[object]
            foreach ($row in (& $sectionOf $Base ('{0}_Tier{1}' -f $s.F, $t))) {
                if ($null -eq $row) { continue }
                $k = ([string]$row.($s.K)).Trim()
                if ($k -and $tierOf.ContainsKey($k)) { continue }   # the classified catalog places it
                $l.Add($row)
            }
            $lists[$t] = $l
        }
        foreach ($k in @($rowOf.Keys)) { $lists[$tierOf[$k]].Add($rowOf[$k]); $n++ }
        foreach ($t in 0..3) { $out[('{0}_Tier{1}' -f $s.F, $t)] = $lists[$t].ToArray() }
    }
    [pscustomobject]@{ Catalog = [pscustomobject]$out; Entries = $n }
}

function Initialize-SIIdentityCatalog {
    [CmdletBinding()]
    param(
        [Parameter()] [string]$Path,
        [Parameter()] [string]$CustomPath,
        # #1194: the downloaded daily classified catalog (privilege-tier-catalog.downloaded.custom.json beside the custom
        # catalog by default). Its BUILT-IN sections replace the shipped ones when the classifier built this tenant's
        # catalog from it (the custom catalog's Metadata.CatalogSource = 'invardia'); the custom catalog still wins on top.
        [Parameter()] [string]$DownloadedPath,
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
            Label           = $script:SICatalog_Label
            CacheHit        = $true
        }
    }
    $sharedDir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared'
    $fromStorage = $false

    if ([string]::IsNullOrWhiteSpace($Path)) {
        # file moved from identity-catalog/ to engine/shared/.
        # $PSScriptRoot now = v2.2/engine/asset-profiling/shared/; three parents -> SecurityInsight/
        $solnRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $Path = Join-Path $solnRoot 'privilege-tier-catalog/privilege-tier-catalog.locked.json'
    }

    if ([string]::IsNullOrWhiteSpace($CustomPath)) {
        # Customer overlay = sibling .custom.json next to the shipped .locked.json.
        # PrivilegeTierClassifier writes here on customer machines; gitignored
        # so it survives `git pull` (or whichever updater). Engine merges
        # this on top of .locked.json -- custom wins on key collisions, but
        # NEW keys added in shipped .locked.json (via baseline updates) still
        # apply because they're not shadowed in custom.
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $CustomPath = Join-Path $siRoot 'privilege-tier-catalog\privilege-tier-catalog.custom.json'

        # The classifier also shares this file through the storage account. In a container this engine's
        # disk carries only the image's copy, so take the shared one when it is newer. No storage account
        # configured = no-op; any storage failure = keep the local copy (it warns).
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-CatalogBlob.ps1')
        $catalogFrom = Update-SICatalogFromBlob -LocalPath $CustomPath
        if ($catalogFrom -eq 'storage') { Write-Host ' [INFO] Tenant privilege-tier catalog: refreshed from the storage account (newer than the local copy).' }
        $fromStorage = $true
    }
    if ([string]::IsNullOrWhiteSpace($DownloadedPath)) {
        $DownloadedPath = Join-Path (Split-Path -Parent $CustomPath) 'privilege-tier-catalog.downloaded.custom.json'
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

    # ---- #1194: the downloaded daily classified catalog replaces the shipped BUILT-IN sections ----
    # Only when the classifier built this tenant's catalog from it (its Metadata.CatalogSource = 'invardia'), so an install
    # building with AI is unchanged. The shipped *_CustomRoles_* / AD_CustomGroups_* sections stay, a *_CustomRoles_*
    # section of the download is never taken, and the custom catalog is merged on top below exactly as before -- it wins.
    # A missing or unreadable download keeps the shipped sections and says so; it never stops the run.
    $customMeta = $null
    if ($customDefs -and $customDefs.PSObject.Properties['Metadata']) { $customMeta = $customDefs.Metadata }
    $catSource = $(if ($customMeta -and $customMeta.PSObject.Properties['CatalogSource']) { [string]$customMeta.CatalogSource } else { '' })
    $catVersion = ''; $catBuilt = ''
    if ($catSource -eq 'invardia') {
        try {
            . (Join-Path $sharedDir 'SI-TierCatalogDownload.ps1')
            if ($fromStorage) {
                if (-not (Get-Command -Name Update-SICatalogFromBlob -ErrorAction SilentlyContinue)) { . (Join-Path $sharedDir 'SI-CatalogBlob.ps1') }
                $null = Update-SICatalogFromBlob -LocalPath $DownloadedPath -BlobName $script:SITierCatalogFileName
            }
            $dl = Get-SITierCatalogDownloadState -Path $DownloadedPath
            if ($null -eq $dl) {
                Write-Warning 'SI identity catalog -- the daily classified catalog is selected but no downloaded copy is available; the shipped built-in sections are used until the privilege tier classifier downloads it.'
            } else {
                $bad = @(Test-SITierCatalogSections $dl.Catalog)
                if ($bad.Count -gt 0) {
                    Write-Warning ("SI identity catalog -- the downloaded catalog is not used ({0}); the shipped built-in sections are used." -f ($bad -join '; '))
                } else {
                    $tierDefs = Merge-SITierCatalogBuiltIns -Shipped $tierDefs -Downloaded $dl.Catalog
                    $catVersion = [string]$dl.Version
                    if ($dl.BuiltUtc) { $catBuilt = ([datetime]$dl.BuiltUtc).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
                }
            }
        } catch {
            Write-Warning ("SI identity catalog -- the downloaded catalog could not be read ({0}); the shipped built-in sections are used." -f $_.Exception.Message)
        }
    }

    # ---- tier classification wins: the tenant's classified catalog places every built-in entry it lists ----
    # (built with AI, or from the daily download), per entry; an entry it does not list keeps the shipped tier. The custom
    # roles and the custom catalog's own sections are merged below exactly as before.
    if ($customDefs) { $tierDefs = (Merge-SIClassifiedBuiltIns -Base $tierDefs -Classified $customDefs).Catalog }

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
    $customGen = ''
    if ($customMeta) {
        foreach ($n in 'GeneratedAtUtc', 'GeneratedAt') {
            if ($customMeta.PSObject.Properties[$n] -and "$($customMeta.$n)") {
                $v = $customMeta.$n
                $customGen = $(if ($v -is [datetime]) { ([datetime]$v).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture) } else { [string]$v })
                break
            }
        }
    }
    $script:SICatalog_Label = Get-SIIdentityCatalogSourceLabel -Source $catSource -Version $catVersion -BuiltUtc $catBuilt `
                                  -CustomGeneratedAt $customGen -ShippedGeneratedAt $script:SICatalog_GeneratedAt

    # ---- Banner ----
    Write-SIInfo ("identity catalog loaded -- {0}" -f $script:SICatalog_Label)
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
        Label           = $script:SICatalog_Label
        CatalogSource   = $(if ($catVersion) { 'invardia' } elseif ($catSource -eq 'ai') { 'ai' } else { 'shipped' })
        CatalogVersion  = $catVersion
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

# ---- Break glass: a tier source of its own (owner 2026-11-11: "Yes, always Tier 0") --------------------------
# The profile row's tier is the MIN over its tier sources (Entra roles, API permissions, Azure roles, AD groups); a
# break-glass account is one more source that says Tier 0, whatever the account holds today. The classification is the
# CI build's own (engine/data-model/SI-BreakGlass.ps1: naming patterns of the list break_glass_patterns on the sign-in
# name, display name and group names; the extension attribute you define; the collection's own signal) on what the
# profile has, so the profile and the CI say the same thing in the same words.

function Get-SIProfileBreakGlass {
    <#
        PURE (with SI-BreakGlass.ps1 loaded). One identity record's metadata -> @{ IsBreakGlass; Reasons; Reason }.
          -Lists           the data-model lists (break_glass_patterns, break_glass_attribute), id -> list
          -ProviderSignal  the collection's own signal (a permanent Global Administrator named like an emergency account)
        Users and guests only; a service principal is never break-glass. Without SI-BreakGlass.ps1 only the provider
        signal counts.
    #>
    param($Metadata, [hashtable]$Lists = @{}, [bool]$ProviderSignal = $false)
    $none = [pscustomobject]@{ IsBreakGlass = $false; Reasons = @(); Reason = '' }
    if ($null -eq $Metadata) { return $none }
    $get = {
        param($n)
        if ($Metadata -is [System.Collections.IDictionary]) {
            if ($Metadata.Contains($n)) { return $Metadata[$n] }
            return $null
        }
        $p = $Metadata.PSObject.Properties[$n]
        if ($p) { return $p.Value }
        return $null
    }
    if ([string](& $get 'ENTRA_AssetType') -and [string](& $get 'ENTRA_AssetType') -ne 'User') { return $none }
    $groups = New-Object System.Collections.Generic.List[string]
    foreach ($g in @(& $get 'ENTRA_GroupNames') + @(& $get 'ENTRA_Groups')) { if ($g -and -not $groups.Contains([string]$g)) { $groups.Add([string]$g) } }
    $egRaw = & $get 'ENTRA_EgRawData'
    if ($egRaw -and $egRaw.PSObject.Properties['nestedAdGroupNames']) { foreach ($g in @($egRaw.nestedAdGroupNames)) { if ($g -and -not $groups.Contains([string]$g)) { $groups.Add([string]$g) } } }
    $ci = [ordered]@{
        si_class = 'identity'
        si_identity_type = $(if ([string](& $get 'ENTRA_UserType') -eq 'Guest') { 'guest' } else { 'user' })
        si_upn = [string](& $get 'ENTRA_UPN'); si_display_name = [string](& $get 'ENTRA_DisplayName')
        si_group_memberships = $groups.ToArray()
        si_break_glass_attribute = [string](& $get 'ENTRA_BreakGlassAttribute')
    }
    if ($ProviderSignal) { $ci['si_is_break_glass'] = $true }
    if (-not (Get-Command -Name Get-SIBreakGlassClassification -ErrorAction SilentlyContinue)) {
        if ($ProviderSignal) { return [pscustomobject]@{ IsBreakGlass = $true; Reasons = @('provider'); Reason = 'Break-glass because the identity collection marks it as an emergency-access account.' } }
        return $none
    }
    $c = Get-SIBreakGlassClassification -Ci $ci -Context @{ Lists = $Lists }
    if ($c.IsBreakGlass -ne $true) { return $none }
    [pscustomobject]@{ IsBreakGlass = $true; Reasons = @($c.Reasons); Reason = (Get-SIBreakGlassReasonText -Reasons @($c.Reasons) -Ci $ci) }
}

function Get-SITierFromBreakGlass {
    <# PURE. The break-glass tier source: 0 for a break-glass account, $null (no claim) otherwise. #>
    param([bool]$IsBreakGlass)
    if ($IsBreakGlass) { return 0 }
    return $null
}

function Get-SIBreakGlassProof {
    <# PURE. The proof row of the break-glass tier source -- the same reason text as the CI build. #>
    param([Parameter(Mandatory)]$BreakGlass)
    @{ Source = 'BreakGlass'; ProofLabel = 'BreakGlass'; ProofWeight = 100
       Reason = ('Break-glass account -> Tier 0. {0}' -f [string]$BreakGlass.Reason).Trim() }
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
