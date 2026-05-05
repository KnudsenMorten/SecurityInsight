#Requires -Version 5.1
<#
    Get-SISchemaWithCustomMerge.ps1

    Loads profiles/<engine>.schema.json (locked) and merges it with the
    optional profiles-custom/<engine>.schema.custom.json (customer
    overlay). Used by every row builder + tier computer so the engine reads
    the SAME merged schema regardless of source.

    Merge semantics (mirrors the locked+custom pattern already used for
    posture rules + privilege-tier-classifier catalog + endpoint-tiering catalog):

      fields[*]                        -- same `name`     => REPLACES locked
                                         -- new `name`      => APPENDS
      aggregator.contributors[*]       -- same `id`       => REPLACES locked
                                         -- new `id`        => APPENDS
      rawPayload.sources.<src>.includePaths[*]
                                       -- UNION (de-duped, locked first)
      rawPayload.sources.<new-src>     -- new source bucket entirely => ADD
      hashes / entityIds / aiEligibility / engine-meta
                                       -- UNCHANGED (cannot be overridden;
                                          these are engine invariants)

    Cached per engine on first call. To force a reload (rare -- e.g., during
    development), call: $script:_SISchemaMergeCache.Remove('<engine>')

    Customer drops their override at:
        v2.2/asset-profiling-schema/<engine>.schema.custom.json

    See profiles-custom/<engine>.schema.custom.sample.json for a working
    template per engine.
#>

if (-not (Get-Variable -Name _SISchemaMergeCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaMergeCache = @{}
}

function Get-SISchemaWithCustomMerge {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('identity','endpoint','azure','publicip')]
        [string]$Engine,

        [switch]$NoCache    # force re-read + re-merge (development helper)
    )

    if (-not $NoCache -and $script:_SISchemaMergeCache.ContainsKey($Engine)) {
        return $script:_SISchemaMergeCache[$Engine]
    }

    # Resolve solution paths from this script's location.
    # $PSScriptRoot = v2.2/engine/asset-profiling/shared -> three parents = v2.2 root.
    $siRoot    = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    # publicip schema file is named 'public-ip.schema.json' (hyphen) for
    # readability; engine token stays 'publicip' everywhere else.
    $fileBase   = if ($Engine -eq 'publicip') { 'public-ip' } else { $Engine }
    $lockedPath = Join-Path $siRoot ('asset-profiling-schema\{0}.schema.locked.json' -f $fileBase)
    $customPath = Join-Path $siRoot ('asset-profiling-schema\{0}.schema.custom.json' -f $fileBase)

    if (-not (Test-Path $lockedPath)) {
        throw ('Locked schema not found at {0}' -f $lockedPath)
    }

    $locked = Get-Content $lockedPath -Raw -Encoding UTF8 | ConvertFrom-Json

    # Locked-only path -- no custom overlay present
    if (-not (Test-Path $customPath)) {
        $script:_SISchemaMergeCache[$Engine] = $locked
        return $locked
    }

    $custom = $null
    try {
        $custom = Get-Content $customPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Write-Warning ("Custom schema overlay parse failed for engine '{0}'; using locked-only. Path: {1}. Error: {2}" -f $Engine, $customPath, $_.Exception.Message)
        $script:_SISchemaMergeCache[$Engine] = $locked
        return $locked
    }
    if (-not $custom) {
        $script:_SISchemaMergeCache[$Engine] = $locked
        return $locked
    }

    # ---- 1. Merge fields[] -----------------------------------------------
    $fieldsAdded    = 0
    $fieldsReplaced = 0
    if ($custom.PSObject.Properties['fields'] -and $custom.fields) {
        $merged = New-Object System.Collections.ArrayList
        foreach ($f in $locked.fields) { [void]$merged.Add($f) }
        $existingByName = @{}
        for ($i = 0; $i -lt $merged.Count; $i++) {
            if ($merged[$i].PSObject.Properties['name']) { $existingByName[[string]$merged[$i].name] = $i }
        }
        foreach ($cf in $custom.fields) {
            if (-not $cf.PSObject.Properties['name']) { continue }
            $cn = [string]$cf.name
            if ($existingByName.ContainsKey($cn)) {
                $merged[$existingByName[$cn]] = $cf
                $fieldsReplaced++
            } else {
                [void]$merged.Add($cf)
                $existingByName[$cn] = $merged.Count - 1
                $fieldsAdded++
            }
        }
        $locked.fields = $merged.ToArray()
    }

    # ---- 2. Merge aggregator.contributors[] ------------------------------
    $contribAdded    = 0
    $contribReplaced = 0
    if ($custom.PSObject.Properties['aggregator'] -and $custom.aggregator -and
        $custom.aggregator.PSObject.Properties['contributors'] -and $custom.aggregator.contributors) {
        if (-not $locked.aggregator) {
            # No locked aggregator at all; lift the custom one verbatim
            $locked | Add-Member -NotePropertyName aggregator -NotePropertyValue $custom.aggregator -Force
        } else {
            $merged = New-Object System.Collections.ArrayList
            foreach ($c in $locked.aggregator.contributors) { [void]$merged.Add($c) }
            $existingById = @{}
            for ($i = 0; $i -lt $merged.Count; $i++) {
                if ($merged[$i].PSObject.Properties['id']) { $existingById[[string]$merged[$i].id] = $i }
            }
            foreach ($cc in $custom.aggregator.contributors) {
                if (-not $cc.PSObject.Properties['id']) { continue }
                $cid = [string]$cc.id
                if ($existingById.ContainsKey($cid)) {
                    $merged[$existingById[$cid]] = $cc
                    $contribReplaced++
                } else {
                    [void]$merged.Add($cc)
                    $existingById[$cid] = $merged.Count - 1
                    $contribAdded++
                }
            }
            $locked.aggregator.contributors = $merged.ToArray()
        }
    }

    # ---- 3. Merge rawPayload.sources.<src>.includePaths[] (UNION) --------
    $pathsAdded   = 0
    $sourcesAdded = 0
    if ($custom.PSObject.Properties['rawPayload'] -and $custom.rawPayload -and
        $custom.rawPayload.PSObject.Properties['sources'] -and $custom.rawPayload.sources) {
        foreach ($srcProp in $custom.rawPayload.sources.PSObject.Properties) {
            $srcName = $srcProp.Name
            $cs      = $srcProp.Value
            $ls      = $null
            if ($locked.rawPayload -and $locked.rawPayload.sources -and
                $locked.rawPayload.sources.PSObject.Properties[$srcName]) {
                $ls = $locked.rawPayload.sources.$srcName
            }
            if (-not $ls) {
                # Entirely new source bucket
                $locked.rawPayload.sources | Add-Member -NotePropertyName $srcName -NotePropertyValue $cs -Force
                $sourcesAdded++
                continue
            }
            if ($cs.PSObject.Properties['includePaths'] -and $cs.includePaths) {
                $existing  = if ($ls.PSObject.Properties['includePaths'] -and $ls.includePaths) { @($ls.includePaths) } else { @() }
                $additions = @($cs.includePaths) | Where-Object { $_ -notin $existing }
                if ($additions.Count -gt 0) {
                    $ls.includePaths = @($existing + $additions)
                    $pathsAdded += $additions.Count
                }
            }
        }
    }

    # ---- Diagnostic summary (only when something actually changed) -------
    if ($fieldsAdded + $fieldsReplaced + $contribAdded + $contribReplaced + $pathsAdded + $sourcesAdded -gt 0) {
        Write-SIInfo ('   [schema] {0} custom overlay merged: fields +{1}/replaced {2}, contributors +{3}/replaced {4}, includePaths +{5}, new source buckets +{6}' -f `
            $Engine, $fieldsAdded, $fieldsReplaced, $contribAdded, $contribReplaced, $pathsAdded, $sourcesAdded)
    }

    $script:_SISchemaMergeCache[$Engine] = $locked
    return $locked
}
