#Requires -Version 5.1
<#
    SecurityInsight -- the SERVER-APPLICATION catalog tier contributor.

    Loads the server-application catalog once and computes a tier contribution for a device from the
    applications installed on it. That is the whole of this file.

    ---------------------------------------------------------------------------------------------
    🔴 THE ENDPOINT-CLASS CATALOG HALF WAS DELETED 2026-08-31 (finding #87). Do not restore it.

    This file used to hold NINETEEN functions. Sixteen of them were a second, parallel tier
    computer -- an endpoint-CLASS catalog with its own loader, its own custom-overlay merge, its own
    four-channel detection and its own reducer -- and NONE of it had a production caller.

    🪤 IT LOOKED ALIVE, AND A CALLER COUNT SAID SO. `Get-SITierFromEndpointDevice` appeared to have
    two callers: one was inside this file's own header comment (a usage example), and the other was
    `Get-SIEndpointAssetClassMatches`, which was itself only called by a test. Dead code whose
    callers are also dead reads as live to grep. Transitive reachability from the two functions
    production actually calls gave 3 live, 16 dead -- and the live three shared NOT ONE helper with
    the dead sixteen, which is what made the removal safe rather than merely tempting.

    ✅ WHAT SUPERSEDED IT: `Build-EndpointProfileRow` calls `Resolve-SITierClaims` directly (armed
    2026-08-25), which is the reducer that actually runs. Keeping a second implementation of a
    mechanism this codebase had already decided twice was how the two drifted apart unnoticed.

    📌 The endpoint TIERING CATALOG DATA (`endpoint-tiering.json`) is untouched and still shipped --
    it feeds the live rule path. What went was this file's private loader and matcher for it.
    ---------------------------------------------------------------------------------------------

    No Graph calls, no MDE REST, no AI calls. All inputs are PowerShell objects from Stage Collect /
    Stage Enrich.
#>

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
        # SecurityInsight Pro: the override imported into the settings database (item serverapps/catalog) is materialised
        # into the run's config folder (SI_ProConfigRoot) -- it comes first; a Pro container has no installation file.
        if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProConfigRoot)) {
            $proCustom = Join-Path ([string]$global:SI_ProConfigRoot) 'server-applications.json'
            if (Test-Path -LiteralPath $proCustom) { $CustomPath = $proCustom }
        }
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
