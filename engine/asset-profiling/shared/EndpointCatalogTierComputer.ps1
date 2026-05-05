#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- endpoint-catalog tier computer.

    Per-device tier computation is 100% deterministic catalog-match: load the
    endpoint-tiering.json catalog once (locked + optional customer override),
    then for each device evaluate every catalog entry's 4-channel detection
    (TVM software names, EG signals, name patterns, machine-tag patterns).

    Mirrors the structure of identity-catalog\IdentityCatalogTierComputer.ps1
    but the matching model is different: instead of looking up known role
    names in tier-bucketed lists, every catalog entry has its own Detection
    block and we walk all entries per device.

    Authority files:
        endpoint-catalog\endpoint-tiering.json          (locked, AI-curated)
        endpoint-catalog-custom\endpoint-tiering.json   (optional, customer)

    Custom merge semantics:
        - same Name as locked  -> custom REPLACES locked entry whole
        - new Name             -> custom ADDED to merged set
        - file missing/empty   -> use locked only

    Usage:
        . v2.2\endpoint-catalog\EndpointCatalogTierComputer.ps1
        Initialize-SIEndpointCatalog
        $r = Get-SITierFromEndpointDevice -Metadata $deviceMeta
        $proofs = Get-SIEndpointAssetClassMatches -Metadata $deviceMeta

    No Graph calls, no MDE REST, no AI calls. All inputs are PowerShell
    objects from Stage Collect / Stage Enrich.
#>

# Catalog state -- script-scoped so callers don't see internal vars.
# Initialize-SIEndpointCatalog populates these from the JSON file(s).
$script:SICatalog_Endpoint_AllClasses = @()       # merged locked + custom -> array of entry objects
$script:SICatalog_Endpoint_TierCounts = @{ T0 = 0; T1 = 0; T2 = 0; T3 = 0 }
$script:SICatalog_Endpoint_LoadedFrom = $null
$script:SICatalog_Endpoint_CustomFrom = $null
$script:SICatalog_Endpoint_GeneratedAt = $null

function Expand-SIEndpointTierSection {
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

function Get-SIEndpointDetectionList {
    # Pulls a string-list field out of an entry's Detection block in a
    # shape-tolerant way (hashtable OR pscustomobject). Returns empty array
    # when missing or non-enumerable.
    param([object]$Entry, [string]$Field)
    if ($null -eq $Entry) { return @() }
    $det = $null
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains('Detection')) { $det = $Entry['Detection'] }
    } else {
        if ($Entry.PSObject.Properties['Detection']) { $det = $Entry.Detection }
    }
    if ($null -eq $det) { return @() }
    $val = $null
    if ($det -is [System.Collections.IDictionary]) {
        if ($det.Contains($Field)) { $val = $det[$Field] }
    } else {
        if ($det.PSObject.Properties[$Field]) { $val = $det.$Field }
    }
    if ($null -eq $val) { return @() }
    if ($val -is [string]) { return @($val) }
    if ($val -is [System.Collections.IEnumerable]) { return @($val) }
    return @($val)
}

function Get-SIEndpointMetaValue {
    # Walks a dotted path against $Metadata. Returns $null if any segment
    # unresolved. Shape-tolerant for hashtable OR pscustomobject at every
    # level (Stage Collect/Enrich may emit either).
    param([object]$Metadata, [string]$Path)
    if ($null -eq $Metadata) { return $null }
    $cur = $Metadata
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
        } else {
            if ($cur.PSObject.Properties[$seg]) { $cur = $cur.$seg } else { return $null }
        }
    }
    return $cur
}

function Initialize-SIEndpointCatalog {
    [CmdletBinding()]
    param(
        [Parameter()] [string]$Path,
        [Parameter()] [string]$CustomPath,
        [Parameter()] [switch]$Force
    )

    # Cache hit: if already loaded, return early (no banner re-print).
    if (-not $Force -and $script:SICatalog_Endpoint_AllClasses -and $script:SICatalog_Endpoint_AllClasses.Count -gt 0) {
        return [pscustomobject]@{
            LoadedFrom  = $script:SICatalog_Endpoint_LoadedFrom
            CustomFrom  = $script:SICatalog_Endpoint_CustomFrom
            GeneratedAt = $script:SICatalog_Endpoint_GeneratedAt
            TierCounts  = $script:SICatalog_Endpoint_TierCounts
            Total       = $script:SICatalog_Endpoint_AllClasses.Count
            CacheHit    = $true
        }
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        # Default: <solution-root>\v2.2\endpoint-catalog\endpoint-tiering.json
        # This script lives in v2.2\endpoint-catalog so $PSScriptRoot already points there.
        $Path = Join-Path $PSScriptRoot 'endpoint-tiering.json'
    }

    if ([string]::IsNullOrWhiteSpace($CustomPath)) {
        # endpoint-catalog-custom/ deleted in . Customer
        # overrides now live in rules-custom/endpoint/. This loader's CustomPath
        # remains as a legacy override path; absent file = silent no-op.
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $CustomPath = Join-Path $siRoot 'asset-profiling-enrichment\endpoint\endpoint-tiering.json'
    }

    if (-not (Test-Path $Path)) {
        throw "SI endpoint catalog not found at: $Path"
    }

    $catalog = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    $lockedEntries = New-Object System.Collections.Generic.List[object]
    foreach ($section in @('Endpoint_AssetClasses_Tier0','Endpoint_AssetClasses_Tier1','Endpoint_AssetClasses_Tier2','Endpoint_AssetClasses_Tier3')) {
        $rows = Expand-SIEndpointTierSection $catalog.$section
        foreach ($r in $rows) { if ($null -ne $r) { [void]$lockedEntries.Add($r) } }
    }

    # Merge: build a Name -> entry hashtable starting from locked, then let
    # custom REPLACE on Name match and ADD on new Name.
    $merged = [ordered]@{}
    foreach ($e in $lockedEntries) {
        $n = [string]$e.Name
        if (-not [string]::IsNullOrWhiteSpace($n)) { $merged[$n] = $e }
    }

    $customLoaded = $false
    if (Test-Path $CustomPath) {
        try {
            $customRaw = Get-Content -Path $CustomPath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($customRaw)) {
                $customCatalog = $customRaw | ConvertFrom-Json
                foreach ($section in @('Endpoint_AssetClasses_Tier0','Endpoint_AssetClasses_Tier1','Endpoint_AssetClasses_Tier2','Endpoint_AssetClasses_Tier3')) {
                    $rows = Expand-SIEndpointTierSection $customCatalog.$section
                    foreach ($r in $rows) {
                        if ($null -eq $r) { continue }
                        $n = [string]$r.Name
                        if (-not [string]::IsNullOrWhiteSpace($n)) {
                            $merged[$n] = $r   # replace OR add (same op)
                            $customLoaded = $true
                        }
                    }
                }
            }
        } catch {
            Write-Warning ("SI endpoint catalog -- failed to parse custom override at {0}: {1}" -f $CustomPath, $_.Exception.Message)
        }
    }

    $allClasses = @($merged.Values)

    # Tier counts on the merged set.
    $tierCounts = @{ T0 = 0; T1 = 0; T2 = 0; T3 = 0 }
    foreach ($e in $allClasses) {
        $t = [int]$e.Tier
        switch ($t) {
            0 { $tierCounts.T0++ }
            1 { $tierCounts.T1++ }
            2 { $tierCounts.T2++ }
            3 { $tierCounts.T3++ }
        }
    }

    $script:SICatalog_Endpoint_AllClasses = $allClasses
    $script:SICatalog_Endpoint_TierCounts = $tierCounts
    $script:SICatalog_Endpoint_LoadedFrom = $Path
    $script:SICatalog_Endpoint_CustomFrom = if ($customLoaded) { $CustomPath } else { $null }
    $script:SICatalog_Endpoint_GeneratedAt = if ($catalog.Metadata) { [string]$catalog.Metadata.GeneratedAt } else { '' }

    $tag = if ($customLoaded) { '(locked + custom)' } else { '(locked only)' }
    Write-SIInfo ("endpoint catalog loaded -- dated {0}" -f $script:SICatalog_Endpoint_GeneratedAt)
    Write-SIInfo (" T0 / T1 / T2 / T3 :  {0} / {1} / {2} / {3}  {4}" -f `
        $tierCounts.T0, $tierCounts.T1, $tierCounts.T2, $tierCounts.T3, $tag)

    [pscustomobject]@{
        LoadedFrom  = $script:SICatalog_Endpoint_LoadedFrom
        CustomFrom  = $script:SICatalog_Endpoint_CustomFrom
        GeneratedAt = $script:SICatalog_Endpoint_GeneratedAt
        TierCounts  = $script:SICatalog_Endpoint_TierCounts
        Total       = $allClasses.Count
        CacheHit    = $false
    }
}

# ---------------------------------------------------------------------------
# Per-channel test helpers (return $true on first hit)
# ---------------------------------------------------------------------------

function Test-SIEndpointTvmSoftware {
    param([string[]]$Patterns, [object[]]$SoftwareList)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    if (-not $SoftwareList -or $SoftwareList.Count -eq 0) { return $false }
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        foreach ($sw in $SoftwareList) {
            $s = [string]$sw
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            if ($s -like $pat) { return $true }
        }
    }
    return $false
}

function Test-SIEndpointEgSignal {
    param([string[]]$SignalNames, [object]$EgRawData)
    if (-not $SignalNames -or $SignalNames.Count -eq 0) { return $false }
    if ($null -eq $EgRawData) { return $false }
    foreach ($name in $SignalNames) {
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $val = Get-SIEndpointMetaValue -Metadata $EgRawData -Path $name
        if ($null -eq $val) { continue }
        if ($val -is [bool]) {
            if ($val) { return $true }
        } else {
            # Tolerate string 'true' / 1 in addition to booleans
            $sv = [string]$val
            if ($sv -eq 'True' -or $sv -eq '1') { return $true }
        }
    }
    return $false
}

function Test-SIEndpointNamePattern {
    param([string[]]$Patterns, [string[]]$Names)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    if (-not $Names -or $Names.Count -eq 0) { return $false }
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        foreach ($n in $Names) {
            if ([string]::IsNullOrWhiteSpace($n)) { continue }
            try {
                if ($n -match $pat) { return $true }
            } catch {
                # Bad regex in catalog -- skip but don't crash the run.
            }
        }
    }
    return $false
}

function Test-SIEndpointTagPattern {
    param([string[]]$Patterns, [object[]]$Tags)
    if (-not $Patterns -or $Patterns.Count -eq 0) { return $false }
    if (-not $Tags -or $Tags.Count -eq 0) { return $false }
    foreach ($pat in $Patterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        foreach ($t in $Tags) {
            $ts = [string]$t
            if ([string]::IsNullOrWhiteSpace($ts)) { continue }
            try {
                if ($ts -match $pat) { return $true }
            } catch {
                # Bad regex in catalog -- skip.
            }
        }
    }
    return $false
}

# ---------------------------------------------------------------------------
# Metadata projection: collapse all device-name and tag inputs to flat lists
# ---------------------------------------------------------------------------

function ConvertTo-SIEndpointMatchInput {
    # Normalises the device's Metadata into the four lists the test helpers
    # expect. Handles MDE_MachineTags being string (semicolon-separated) or
    # array, and folds in EG manual + dynamic tag arrays.
    param([object]$Metadata)
    if ($null -eq $Metadata) {
        return [pscustomobject]@{
            Software = @(); EgRawData = $null; Names = @(); Tags = @()
        }
    }

    $software = @(Get-SIEndpointMetaValue -Metadata $Metadata -Path 'TvmSoftwareList')
    if ($software.Count -eq 1 -and $null -eq $software[0]) { $software = @() }

    $egRaw = Get-SIEndpointMetaValue -Metadata $Metadata -Path 'EgRawData'

    $names = New-Object System.Collections.Generic.List[string]
    foreach ($field in @('MDE_DeviceName','EG_DeviceName','ComputerDnsName','EG_DeviceDnsName')) {
        $v = Get-SIEndpointMetaValue -Metadata $Metadata -Path $field
        if ($null -ne $v) {
            $sv = [string]$v
            if (-not [string]::IsNullOrWhiteSpace($sv)) { [void]$names.Add($sv) }
        }
    }

    $tags = New-Object System.Collections.Generic.List[string]
    foreach ($field in @('MDE_MachineTags','EG_DeviceManualTags','EG_DeviceDynamicTags','MachineTags')) {
        $v = Get-SIEndpointMetaValue -Metadata $Metadata -Path $field
        if ($null -eq $v) { continue }
        if ($v -is [string]) {
            # MDE may emit semicolon-separated string.
            foreach ($piece in ($v -split '[;,]')) {
                $p = $piece.Trim()
                if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$tags.Add($p) }
            }
        } elseif ($v -is [System.Collections.IEnumerable]) {
            foreach ($item in $v) {
                $ts = [string]$item
                if (-not [string]::IsNullOrWhiteSpace($ts)) { [void]$tags.Add($ts) }
            }
        } else {
            $ts = [string]$v
            if (-not [string]::IsNullOrWhiteSpace($ts)) { [void]$tags.Add($ts) }
        }
    }

    [pscustomobject]@{
        Software  = @($software)
        EgRawData = $egRaw
        Names     = @($names)
        Tags      = @($tags)
    }
}

# ---------------------------------------------------------------------------
# Per-device match (returns ALL matches in Proofs, lowest tier in Tier)
# ---------------------------------------------------------------------------

function Get-SITierFromEndpointDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Metadata
    )

    if (-not $script:SICatalog_Endpoint_AllClasses -or $script:SICatalog_Endpoint_AllClasses.Count -eq 0) {
        # Lazy-load if caller forgot.
        $null = Initialize-SIEndpointCatalog
    }

    # NOTE: $input is a PowerShell automatic variable (pipeline iterator);
    # never use it as a local variable name -- subtle binding/type errors.
    $matchInput = ConvertTo-SIEndpointMatchInput -Metadata $Metadata
    $proofs = New-Object System.Collections.Generic.List[object]
    $minTier = $null
    $matchedClass = $null

    foreach ($entry in $script:SICatalog_Endpoint_AllClasses) {
        if ($null -eq $entry) { continue }

        $tvmPats  = @(Get-SIEndpointDetectionList -Entry $entry -Field 'TvmSoftwareNames')
        $egSigs   = @(Get-SIEndpointDetectionList -Entry $entry -Field 'EgSignals')
        $namePats = @(Get-SIEndpointDetectionList -Entry $entry -Field 'NamePatterns')
        $tagPats  = @(Get-SIEndpointDetectionList -Entry $entry -Field 'MachineTagPatterns')

        $detectedVia = $null
        if (Test-SIEndpointTvmSoftware -Patterns $tvmPats -SoftwareList $matchInput.Software) {
            $detectedVia = 'TvmSoftware'
        } elseif (Test-SIEndpointEgSignal -SignalNames $egSigs -EgRawData $matchInput.EgRawData) {
            $detectedVia = 'EgSignal'
        } elseif (Test-SIEndpointNamePattern -Patterns $namePats -Names $matchInput.Names) {
            $detectedVia = 'NamePattern'
        } elseif (Test-SIEndpointTagPattern -Patterns $tagPats -Tags $matchInput.Tags) {
            $detectedVia = 'MachineTag'
        }

        if ($null -ne $detectedVia) {
            $entryTier = [int]$entry.Tier
            $entryName = [string]$entry.Name
            $entryReason = [string]$entry.Reason

            [void]$proofs.Add([pscustomobject]@{
                Name        = $entryName
                Tier        = $entryTier
                Reason      = $entryReason
                DetectedVia = $detectedVia
            })

            if ($null -eq $minTier -or $entryTier -lt $minTier) {
                $minTier = $entryTier
                $matchedClass = $entryName
            }
        }
    }

    $result = @{}
    $result['Tier']         = $minTier
    $result['MatchedClass'] = $matchedClass
    $result['MatchCount']   = $proofs.Count
    $result['Proofs']       = $proofs.ToArray()
    return $result
}

function Get-SIEndpointAssetClassMatches {
    # Convenience wrapper: returns just the Proofs array (one entry per
    # matching catalog class). Used by the row builder for per-source verdict
    # display.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Metadata
    )
    $r = Get-SITierFromEndpointDevice -Metadata $Metadata
    return $r.Proofs
}

# ---------------------------------------------------------------------------
# Server-application catalog (server-applications.json)
#
# Separate cache from the per-class endpoint-tiering catalog above. The
# server-applications catalog is keyed by (software_vendor, software_name)
# pairs that match what Microsoft Defender XDR's DeviceTvmSoftwareInventory
# emits per device. Stage Enrich does ONE bulk hunting query per run to fan
# out (DeviceId -> [{Vendor, Name, Version}]) and per-asset calls
# Get-SITierFromInstalledApplications to produce the lowest-tier server-app
# match plus per-app proofs.
# ---------------------------------------------------------------------------

$script:SICatalog_ServerApps_All                = @()        # merged locked + custom -> array of entry objects
$script:SICatalog_ServerApps_LookupByVendorName = @{}        # "vendor|name" lower-case -> entry
$script:SICatalog_ServerApps_TierCounts         = @{ T0 = 0; T1 = 0; T2 = 0; T3 = 0 }
$script:SICatalog_ServerApps_LoadedFrom         = $null
$script:SICatalog_ServerApps_CustomFrom         = $null
$script:SICatalog_ServerApps_Generated          = $null

function Initialize-SIServerAppCatalog {
    [CmdletBinding()]
    param(
        [Parameter()] [string]$Path,
        [Parameter()] [string]$CustomPath,
        [Parameter()] [switch]$Force
    )

    # Cache hit: skip work AND skip banner re-print.
    if (-not $Force -and $script:SICatalog_ServerApps_All -and $script:SICatalog_ServerApps_All.Count -gt 0) {
        return [pscustomobject]@{
            LoadedFrom  = $script:SICatalog_ServerApps_LoadedFrom
            CustomFrom  = $script:SICatalog_ServerApps_CustomFrom
            Generated   = $script:SICatalog_ServerApps_Generated
            TierCounts  = $script:SICatalog_ServerApps_TierCounts
            Total       = $script:SICatalog_ServerApps_All.Count
            CacheHit    = $true
        }
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        # Default: <solution-root>\v2.2\endpoint-catalog\server-applications.json
        $Path = Join-Path $PSScriptRoot 'server-applications.json'
    }
    if ([string]::IsNullOrWhiteSpace($CustomPath)) {
        # endpoint-catalog-custom/ deleted in . Silent no-op when absent.
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        $CustomPath = Join-Path $siRoot 'asset-profiling-enrichment\endpoint\server-applications.json'
    }

    if (-not (Test-Path $Path)) {
        throw "SI server-app catalog not found at: $Path"
    }

    $catalog = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json

    # Normalise the locked apps array (PS 5.1 ConvertFrom-Json may collapse
    # single-element arrays to a bare object).
    $lockedApps = @()
    if ($null -ne $catalog.applications) {
        if ($catalog.applications -is [System.Array]) {
            $lockedApps = $catalog.applications
        } else {
            $lockedApps = @($catalog.applications)
        }
    }

    # Build merged ordered hashtable keyed by "vendor|name" (lower-case).
    $merged = [ordered]@{}
    foreach ($app in $lockedApps) {
        if ($null -eq $app) { continue }
        $vendor = [string]$app.software_vendor
        $name   = [string]$app.software_name
        if ([string]::IsNullOrWhiteSpace($vendor) -or [string]::IsNullOrWhiteSpace($name)) { continue }
        $key = $vendor.ToLowerInvariant() + '|' + $name.ToLowerInvariant()
        $merged[$key] = $app
    }

    $customLoaded = $false
    if (Test-Path $CustomPath) {
        try {
            $customRaw = Get-Content -Path $CustomPath -Raw -Encoding UTF8
            if (-not [string]::IsNullOrWhiteSpace($customRaw)) {
                $customCatalog = $customRaw | ConvertFrom-Json
                $customApps = @()
                if ($null -ne $customCatalog.applications) {
                    if ($customCatalog.applications -is [System.Array]) {
                        $customApps = $customCatalog.applications
                    } else {
                        $customApps = @($customCatalog.applications)
                    }
                }
                foreach ($app in $customApps) {
                    if ($null -eq $app) { continue }
                    $vendor = [string]$app.software_vendor
                    $name   = [string]$app.software_name
                    if ([string]::IsNullOrWhiteSpace($vendor) -or [string]::IsNullOrWhiteSpace($name)) { continue }
                    $key = $vendor.ToLowerInvariant() + '|' + $name.ToLowerInvariant()
                    $merged[$key] = $app   # replace OR add (same op)
                    $customLoaded = $true
                }
            }
        } catch {
            Write-Warning ("SI server-app catalog -- failed to parse custom override at {0}: {1}" -f $CustomPath, $_.Exception.Message)
        }
    }

    $allApps = @($merged.Values)
    $lookup  = @{}
    foreach ($key in $merged.Keys) {
        $lookup[$key] = $merged[$key]
    }

    $tierCounts = @{ T0 = 0; T1 = 0; T2 = 0; T3 = 0 }
    foreach ($app in $allApps) {
        $t = [int]$app.tier
        switch ($t) {
            0 { $tierCounts.T0++ }
            1 { $tierCounts.T1++ }
            2 { $tierCounts.T2++ }
            3 { $tierCounts.T3++ }
        }
    }

    $script:SICatalog_ServerApps_All                = $allApps
    $script:SICatalog_ServerApps_LookupByVendorName = $lookup
    $script:SICatalog_ServerApps_TierCounts         = $tierCounts
    $script:SICatalog_ServerApps_LoadedFrom         = $Path
    $script:SICatalog_ServerApps_CustomFrom         = if ($customLoaded) { $CustomPath } else { $null }
    $script:SICatalog_ServerApps_Generated          = if ($catalog.generated) { [string]$catalog.generated } else { '' }

    $tag = if ($customLoaded) { '(locked + custom)' } else { '(locked only)' }
    Write-SIInfo ("server-application catalog loaded -- {0} apps (T0={1} T1={2} T2={3} T3={4}) {5}" -f `
        $allApps.Count, $tierCounts.T0, $tierCounts.T1, $tierCounts.T2, $tierCounts.T3, $tag)

    [pscustomobject]@{
        LoadedFrom  = $script:SICatalog_ServerApps_LoadedFrom
        CustomFrom  = $script:SICatalog_ServerApps_CustomFrom
        Generated   = $script:SICatalog_ServerApps_Generated
        TierCounts  = $script:SICatalog_ServerApps_TierCounts
        Total       = $allApps.Count
        CacheHit    = $false
    }
}

function Get-SIServerAppDisplayName {
    # Pick the first non-empty display name (catalog entry has a display_names
    # array). Falls back to "<vendor>/<name>" when the array is missing.
    param([object]$Entry)
    if ($null -eq $Entry) { return $null }
    $names = $null
    if ($Entry -is [System.Collections.IDictionary]) {
        if ($Entry.Contains('display_names')) { $names = $Entry['display_names'] }
    } else {
        if ($Entry.PSObject.Properties['display_names']) { $names = $Entry.display_names }
    }
    if ($null -ne $names) {
        if ($names -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($names)) { return [string]$names }
        } elseif ($names -is [System.Collections.IEnumerable]) {
            foreach ($n in $names) {
                $sn = [string]$n
                if (-not [string]::IsNullOrWhiteSpace($sn)) { return $sn }
            }
        }
    }
    return ('{0}/{1}' -f [string]$Entry.software_vendor, [string]$Entry.software_name)
}

function Get-SITierFromInstalledApplications {
    <#
        Per-device matcher. Walks the installed-apps list (from the bulk TVM
        fetch in Stage Enrich) and looks up each (vendor, name) pair in the
        catalog lookup hashtable. Returns the LOWEST tier hit (Tier 0 wins
        over Tier 1) plus a Proofs array describing every match for the row
        builder.

        $InstalledApps shape: array of @{ Vendor; Name; Version } entries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$InstalledApps
    )

    if (-not $script:SICatalog_ServerApps_All -or $script:SICatalog_ServerApps_All.Count -eq 0) {
        # Lazy-load if caller forgot.
        $null = Initialize-SIServerAppCatalog
    }

    $proofs = New-Object System.Collections.Generic.List[object]
    $minTier = $null
    $matchedAppDisplay = $null

    if ($null -ne $InstalledApps) {
        foreach ($app in $InstalledApps) {
            if ($null -eq $app) { continue }

            # Shape-tolerant: hashtable OR pscustomobject after JSON round-trip.
            $vendor = $null; $name = $null; $version = $null
            if ($app -is [System.Collections.IDictionary]) {
                if ($app.Contains('Vendor'))  { $vendor  = [string]$app['Vendor'] }
                if ($app.Contains('Name'))    { $name    = [string]$app['Name'] }
                if ($app.Contains('Version')) { $version = [string]$app['Version'] }
            } else {
                if ($app.PSObject.Properties['Vendor'])  { $vendor  = [string]$app.Vendor }
                if ($app.PSObject.Properties['Name'])    { $name    = [string]$app.Name }
                if ($app.PSObject.Properties['Version']) { $version = [string]$app.Version }
            }
            if ([string]::IsNullOrWhiteSpace($vendor) -or [string]::IsNullOrWhiteSpace($name)) { continue }

            $key = $vendor.ToLowerInvariant() + '|' + $name.ToLowerInvariant()
            if (-not $script:SICatalog_ServerApps_LookupByVendorName.ContainsKey($key)) { continue }

            $entry      = $script:SICatalog_ServerApps_LookupByVendorName[$key]
            $entryTier  = [int]$entry.tier
            $entryName  = Get-SIServerAppDisplayName -Entry $entry
            $category   = [string]$entry.category
            $serverRole = [string]$entry.server_role
            $reason     = ('TVM software {0} / {1} -> Tier {2} ({3}; {4})' -f $vendor, $name, $entryTier, $category, $serverRole)

            [void]$proofs.Add([ordered]@{
                Name         = $entryName
                Tier         = $entryTier
                Vendor       = $vendor
                SoftwareName = $name
                Version      = $version
                ServerRole   = $serverRole
                Reason       = $reason
            })

            if ($null -eq $minTier -or $entryTier -lt $minTier) {
                $minTier = $entryTier
                $matchedAppDisplay = $entryName
            }
        }
    }

    $result = @{}
    $result['Tier']        = $minTier
    $result['MatchedApp']  = $matchedAppDisplay
    $result['MatchCount']  = $proofs.Count
    $result['Proofs']      = $proofs.ToArray()
    return $result
}

function Get-SIServerAppCatalogMatches {
    # Convenience wrapper: returns just the Proofs array. Mirrors
    # Get-SIEndpointAssetClassMatches above but for the server-app catalog.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$InstalledApps
    )
    $r = Get-SITierFromInstalledApplications -InstalledApps $InstalledApps
    return $r.Proofs
}
