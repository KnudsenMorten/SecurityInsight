#Requires -Version 5.1
<#
    Get-SIRuleSet.ps1

    New rule loader for the AssetProfileBy* rules introduced in (ARCHITECTURE.md § 7). Reads YAMLs from:

      v2.2/asset-profiling-enrichment/<engine>/AssetProfileBy*/*.yaml          (locked, ships in repo)
      v2.2/asset-profiling-enrichment/<engine>/AssetProfileBy*.yaml            (locked, single-file flavour)
      v2.2/asset-profiling-enrichment/shared/AssetProfileBy*.yaml
      v2.2/asset-profiling-enrichment/<engine>/AssetProfileBy*/*.yaml   (customer overrides)
      v2.2/asset-profiling-enrichment/<engine>/AssetProfileBy*.yaml     (customer overrides)
      v2.2/asset-profiling-enrichment/shared/AssetProfileBy*.yaml

    appliesTo accepts:
      'endpoint' | 'identity' | 'azure' | 'publicip' (single)
      'any'                                          (loads in every engine)
      ['endpoint','identity']                        (YAML list)
      'endpoint,identity'                            (comma-separated)

    Returns array of [pscustomobject] in the schema:

        Id          : <filename-basename, must equal $y.id>     -- string
        AppliesTo   : 'endpoint' | 'identity' | 'azure'         -- string
        Mode        : 'locked' | 'append' | 'merge' | 'overwrite' | 'disable'
        Purpose     : free text                                 -- string
        Category    : group label (e.g. 'Server Roles')         -- string
        Description : multi-line                                -- string
        Detections  : array of [pscustomobject] per detection block:
            Id      : <inner detection id, mirrors file id when single-detection>
            Detect  : @{ any=[detect-kinds] } OR @{ all=[detect-kinds] }
            Set     : @{ Tier=N; Purpose='...'; Category='...'; cmdbId='...'; ... }
        File        : repo-relative path, for diagnostics
        Folder      : 'rules' | 'rules-custom'
        SchemaShape : 'AssetProfileBy'                          -- discriminator
                      so callers can tell new-loader rules apart
                      from legacy Get-SIPostureRules output.

    Backward compat note:

      This loader does NOT replace Get-SIPostureRules. Both run side-by-side.
      Callers opt in to the new loader explicitly. Old engine code that
      reads from posture-rules-locked/ continues to work unchanged.

      Future introduces RuleEval.ps1 (the kind: registry +
      bulk-source builder). Until then, Get-SIRuleSet output is for
      inspection / lint / new-stage prototyping only.

    Locked + custom merge:

      returns BOTH locked + custom rules tagged via the Folder
      property. Per-rule merge semantics (mode: append/merge/overwrite/disable
      from ARCHITECTURE.md § 7) get implemented in alongside
      the kind: registry, since merge ordering matters for detection
      evaluation.
#>

function Get-SIRuleSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('endpoint','identity','azure','publicip')]
        [string]$Engine,

        # Pass to restrict to a single AssetProfileBy* method (folder or file
        # basename, e.g. 'AssetProfileByApplicationServiceDetection',
        # 'AssetProfileByExtensionAttributes'). Empty = all methods.
        [Parameter()]
        [string]$Method,

        # Pass $false to skip rules-custom/. Default loads both locked + custom.
        [Parameter()]
        [bool]$IncludeCustom = $true
    )

    if (-not (Get-Module -Name 'powershell-yaml')) {
        Import-Module 'powershell-yaml' -Force -ErrorAction Stop
    }

    # Resolve v2.2 root from this script's location.
    # $PSScriptRoot = v2.2/engine/asset-profiling/shared -> three parents up = v2.2 root.
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))

    # rules now live under asset-profiling-enrichment/<engine>/
    # (locked + custom coexist in the same dir, distinguished by file suffix
    # *.locked.yaml vs *.custom.yaml -- handled by the .custom/.locked-strip
    # logic in the file-loop below). Old layout with separate rules/ +
    # rules-custom/ folders is deprecated -- the doc comment at the top of
    # this file already says asset-profiling-enrichment/, the code just never
    # got updated. -IncludeCustom remains honored at the file-suffix level.
    $folders = @('asset-profiling-enrichment')

    $results = New-Object System.Collections.ArrayList
    $loaded  = 0
    $skipped = 0

    # also walk rules/shared/ + rules-custom/shared/ for cross-engine rules.
    # Each rules root contributes two scan folders: <Engine>/ and shared/.
    $scanRoots = @()
    foreach ($folder in $folders) {
        foreach ($sub in @($Engine, 'shared')) {
            $p = Join-Path $siRoot (Join-Path $folder $sub)
            if (Test-Path $p) { $scanRoots += [pscustomobject]@{ Folder = $folder; Path = $p; Sub = $sub } }
        }
    }

    foreach ($root in $scanRoots) {
        $folder      = $root.Folder
        $engineRoot  = $root.Path
        $isShared    = ($root.Sub -eq 'shared')

        # Both shapes are legal:
        #   1) <engineRoot>/<MethodName>.yaml                     (single file)
        #   2) <engineRoot>/<MethodName>/<roleName>.yaml          (folder per method)
        # Walk both with one Get-ChildItem -Recurse.
        $yamls = @(Get-ChildItem -Path $engineRoot -Filter '*.yaml' -Recurse -File -ErrorAction SilentlyContinue)

        foreach ($f in $yamls) {
            # Skip .gitkeep, _samples, *.sample.yaml/json (sample/template files
            # for customer reference -- they are NOT loaded by the engine).
            if ($f.Name -like '_*' -or $f.Name -like '.*' -or $f.Name -like '*.sample.*') { continue }
            # honor -IncludeCustom at the file-suffix level since
            # locked + custom now share one folder.
            if (-not $IncludeCustom -and $f.Name -like '*.custom.yaml') { continue }

            # Optional method filter
            if ($Method) {
                # Match either: file basename = $Method, or parent folder name = $Method
                $parentName = (Split-Path -Parent $f.FullName | Split-Path -Leaf)
                if ($f.BaseName -ne $Method -and $parentName -ne $Method) { continue }
            }

            try {
                $obj = ConvertFrom-Yaml -Yaml (Get-Content -Raw $f.FullName)
            } catch {
                Write-Warning ('Get-SIRuleSet: skipping {0} (parse error: {1})' -f $f.Name, $_.Exception.Message)
                $skipped++
                continue
            }

            # Required: id (must match filename basename per ARCHITECTURE.md § 7).
            # customer files in rules-custom/ may use the .custom.yaml
            # naming convention (AssetProfileByTags.custom.yaml). Strip the .custom
            # infix from basename before id-comparison so the override file pairs
            # cleanly with the locked file's id.
            $id = [string]$obj.id
            if ([string]::IsNullOrWhiteSpace($id)) {
                Write-Warning ('Get-SIRuleSet: skipping {0} (no id field)' -f $f.Name)
                $skipped++; continue
            }
            $effectiveBaseName = $f.BaseName
            if ($effectiveBaseName -like '*.custom') { $effectiveBaseName = $effectiveBaseName.Substring(0, $effectiveBaseName.Length - 7) }
            elseif ($effectiveBaseName -like '*.locked') { $effectiveBaseName = $effectiveBaseName.Substring(0, $effectiveBaseName.Length - 7) }
            if ($id -ne $effectiveBaseName) {
                Write-Warning ("Get-SIRuleSet: id/filename mismatch in {0} (id='{1}', basename='{2}'). Per ARCHITECTURE.md § 7 the id MUST equal the file basename (or '<id>.custom'/'<id>.locked' in asset-profiling-enrichment/). Loading anyway." -f $f.Name, $id, $f.BaseName)
            }

            # appliesTo can be a string ('endpoint'), 'any', a comma-
            # separated string ('endpoint,identity'), or a YAML list ([endpoint,
            # identity]). Normalise to a [string[]] of lowercased engine names.
            $appliesToList = @()
            if ($null -eq $obj.appliesTo) {
                # Per-engine folders default to that engine; shared/ defaults to 'any'.
                $appliesToList = if ($isShared) { @('any') } else { @($Engine) }
            } elseif ($obj.appliesTo -is [System.Collections.IEnumerable] -and -not ($obj.appliesTo -is [string])) {
                $appliesToList = @($obj.appliesTo | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() })
            } else {
                $appliesToList = @(([string]$obj.appliesTo) -split '[,;]\s*' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
            }
            $appliesTo = ($appliesToList -join ',')   # preserved for diagnostic output

            # Engine-match: rule loads if appliesTo contains 'any' or the current Engine
            $matchesEngine = ($appliesToList -contains 'any') -or ($appliesToList -contains $Engine.ToLowerInvariant())
            if (-not $matchesEngine) {
                if (-not $isShared) {
                    # Engine-folder rule that explicitly targets a different engine -- legacy warning.
                    Write-Warning ("Get-SIRuleSet: appliesTo='{0}' in {1} doesn't match folder engine='{2}', skipping" -f $appliesTo, $f.Name, $Engine)
                }
                # Shared-folder rules silently skip when the current engine isn't in their appliesTo list.
                $skipped++; continue
            }

            $mode = if ($obj.mode) { [string]$obj.mode } else { 'locked' }

            # Disable mode: customer wants this rule's locked counterpart suppressed.
            # Surface in result so the merge step in can act on it.
            if ($mode -eq 'disable') {
                [void]$results.Add([pscustomobject]@{
                    Id          = $id
                    AppliesTo   = $appliesTo
                    Mode        = 'disable'
                    Purpose     = $null
                    Category    = $null
                    Description = $null
                    Detections  = @()
                    File        = $f.FullName.Substring($siRoot.Length).TrimStart('\','/')
                    Folder      = $folder
                    SchemaShape = 'AssetProfileBy'
                })
                $loaded++
                continue
            }

            # Detections array — required for non-disable modes
            $detections = New-Object System.Collections.ArrayList
            if ($obj.detections) {
                foreach ($d in $obj.detections) {
                    $detId = if ($d.id) { [string]$d.id } else { $id }
                    [void]$detections.Add([pscustomobject]@{
                        Id     = $detId
                        Detect = $d.detect      # leave nested @{ any|all = [...]} as-is for RuleEval to consume
                        Set    = $d.set
                    })
                }
            }

            [void]$results.Add([pscustomobject]@{
                Id          = $id
                AppliesTo   = $appliesTo
                Mode        = $mode
                Purpose     = if ($obj.purpose)     { [string]$obj.purpose }     else { $null }
                Category    = if ($obj.category)    { [string]$obj.category }    else { $null }
                Description = if ($obj.description) { [string]$obj.description } else { $null }
                Detections  = $detections.ToArray()
                File        = $f.FullName.Substring($siRoot.Length).TrimStart('\','/')
                Folder      = $folder
                SchemaShape = 'AssetProfileBy'
            })
            $loaded++
        }
    }

    # dedup by id -- locked + custom both load (same folder, just
    # *.locked.yaml vs *.custom.yaml suffix). Preference: custom wins over
    # locked (the customer-edited file is the override). Without this dedup
    # the same rule fires twice per asset (you'd see e.g. OrgFinanceMember
    # appearing 2x in SIRules with identical Tier/Purpose/Category, doubling
    # match counts and inflating risk-factor probabilities).
    # Resolves the "future work" merge-semantics gap noted in the
    # file header. NOTE: only handles dedup of identical id pairs today;
    # mode: append/merge/overwrite/disable are NOT yet implemented (custom
    # currently always overrides locked, which is the most common intent).
    if ($results.Count -gt 1) {
        $deduped = New-Object System.Collections.ArrayList
        $byId    = @{}
        foreach ($r in $results) {
            $isCustom = ($r.File -like '*.custom.yaml')
            if (-not $byId.ContainsKey($r.Id)) {
                $byId[$r.Id] = $r
            } elseif ($isCustom) {
                # Custom wins -- replace the previously-seen entry.
                $byId[$r.Id] = $r
            }
            # else: locked seen after another locked, or locked-after-custom -- ignore.
        }
        foreach ($r in $byId.Values) { [void]$deduped.Add($r) }
        $dropped = $results.Count - $deduped.Count
        if ($dropped -gt 0) {
            Write-SIInfo ("Get-SIRuleSet: deduped {0} rule(s) (locked/custom pair) -- {1} unique rules remain" -f $dropped, $deduped.Count)
        }
        $results = $deduped
    }

    Write-Verbose ("Get-SIRuleSet: engine={0} loaded={1} skipped={2} folders={3}" -f $Engine, $loaded, $skipped, ($folders -join ','))
    ,$results.ToArray()
}

function Get-SIRuleSetSummary {
    <#
        Diagnostic helper. Returns a one-row-per-rule summary table:
        Id, AppliesTo, Mode, DetectionCount, KindsUsed, TierRange, Folder.

        Useful for lint runs ('how many rules per engine?') and pre-flight
        checks before the new RuleEval ships.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('endpoint','identity','azure','publicip')]
        [string]$Engine
    )

    Get-SIRuleSet -Engine $Engine | ForEach-Object {
        $kindsUsed = New-Object System.Collections.Generic.HashSet[string]
        $tiers     = New-Object System.Collections.Generic.HashSet[int]
        foreach ($d in $_.Detections) {
            if ($d.Detect) {
                $kindList = if ($d.Detect.any)  { $d.Detect.any }
                            elseif ($d.Detect.all) { $d.Detect.all }
                            else { @() }
                foreach ($k in $kindList) { if ($k.kind) { [void]$kindsUsed.Add([string]$k.kind) } }
            }
            if ($d.Set -and $null -ne $d.Set.Tier) { [void]$tiers.Add([int]$d.Set.Tier) }
        }
        [pscustomobject]@{
            Id             = $_.Id
            AppliesTo      = $_.AppliesTo
            Mode           = $_.Mode
            DetectionCount = $_.Detections.Count
            KindsUsed      = (($kindsUsed | Sort-Object) -join ',')
            TierRange      = if ($tiers.Count -gt 0) { "T$($tiers | Sort-Object | Select-Object -First 1)..T$($tiers | Sort-Object | Select-Object -Last 1)" } else { '' }
            Folder         = $_.Folder
        }
    }
}
