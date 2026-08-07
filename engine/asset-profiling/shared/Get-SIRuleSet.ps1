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
        [bool]$IncludeCustom = $true,

        # AUDIT #29 -- test seam. Overrides the solution root this function would otherwise
        # derive from $PSScriptRoot, so the rule-loading behaviour (notably the parse-failure
        # reporting below) can be exercised against a scratch folder instead of the real
        # enrichment tree. Production callers never pass it.
        [Parameter()]
        [string]$SolutionRootOverride,

        # AUDIT #34 phase 1 -- OPERATOR DATA OVERLAY.
        # An external directory holding the operator's own *.custom.yaml rules, laid out with
        # the same <engine>/ + shared/ subfolders as asset-profiling-enrichment/. When set, its
        # rules load ALONGSIDE the shipped tree and WIN on a colliding id.
        #
        # Why: today a customer's rules live INSIDE the directory the sync overwrites, and they
        # survive only because they happen to be absent from the update zip -- not because
        # anything protects them. One tracked file with a colliding name would overwrite a
        # customer's rule, and a .gitignore slip publishes their data to the public mirror.
        # An overlay puts operator data outside the code tree, so the shipped tree is pure code
        # and a fresh clone behaves identically to a real install.
        #
        # Defaults to $global:SI_EnrichmentDataRoot so config sets it once. UNSET = every
        # existing installation behaves exactly as before; this is opt-in by construction.
        [Parameter()]
        [string]$EnrichmentDataRoot
    )

    if (-not (Get-Module -Name 'powershell-yaml')) {
        Import-Module 'powershell-yaml' -Force -ErrorAction Stop
    }

    # Resolve v2.2 root from this script's location.
    # $PSScriptRoot = v2.2/engine/asset-profiling/shared -> three parents up = v2.2 root.
    $siRoot = if (-not [string]::IsNullOrWhiteSpace($SolutionRootOverride)) { $SolutionRootOverride }
              else { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }

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
    # AUDIT #29 -- parse failures tracked apart from the benign skips; see the catch below.
    $parseFailed = 0
    $parseFailedNames = New-Object System.Collections.Generic.List[string]

    # also walk rules/shared/ + rules-custom/shared/ for cross-engine rules.
    # Each rules root contributes two scan folders: <Engine>/ and shared/.
    $scanRoots = @()
    foreach ($folder in $folders) {
        foreach ($sub in @($Engine, 'shared')) {
            $p = Join-Path $siRoot (Join-Path $folder $sub)
            if (Test-Path $p) { $scanRoots += [pscustomobject]@{ Folder = $folder; Path = $p; Sub = $sub; Base = $siRoot; Source = 'tree' } }
        }
    }

    # AUDIT #34 phase 1 -- the operator data overlay, appended AFTER the shipped tree so a
    # colliding id resolves overlay-wins in the dedup below. Same <engine>/ + shared/ layout,
    # so an operator moves files across without renaming anything.
    $overlayRoot = if (-not [string]::IsNullOrWhiteSpace($EnrichmentDataRoot)) { $EnrichmentDataRoot }
                   elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_EnrichmentDataRoot)) { [string]$global:SI_EnrichmentDataRoot }
                   else { $null }
    $overlayActive = $false
    if (-not [string]::IsNullOrWhiteSpace($overlayRoot)) {
        if (-not (Test-Path -LiteralPath $overlayRoot)) {
            # Configured but absent is NOT a silent fall-back to the in-tree rules. That would be
            # #29's shape a third time: the run would look clean while every operator rule the
            # overlay was supposed to supply is missing.
            Write-Warning ("Get-SIRuleSet: SI_EnrichmentDataRoot is set to '{0}' but that path does not exist. NO overlay rules were loaded for engine '{1}' -- only the shipped tree is in force. Fix the path or clear the setting." -f $overlayRoot, $Engine)
        } else {
            $overlayActive = $true
            foreach ($sub in @($Engine, 'shared')) {
                $p = Join-Path $overlayRoot $sub
                if (Test-Path $p) { $scanRoots += [pscustomobject]@{ Folder = 'overlay'; Path = $p; Sub = $sub; Base = $overlayRoot; Source = 'overlay' } }
            }
        }
    }

    foreach ($root in $scanRoots) {
        $folder      = $root.Folder
        $engineRoot  = $root.Path
        $isShared    = ($root.Sub -eq 'shared')
        $ruleBase    = $root.Base       # #34 -- File is relative to the root the file came from
        $ruleSource  = $root.Source     # 'tree' | 'overlay'

        # Both shapes are legal:
        #   1) <engineRoot>/<MethodName>.yaml                     (single file)
        #   2) <engineRoot>/<MethodName>/<roleName>.yaml          (folder per method)
        # Walk both with one Get-ChildItem -Recurse.
        $yamls = @(Get-ChildItem -Path $engineRoot -Filter '*.yaml' -Recurse -File -ErrorAction SilentlyContinue)

        foreach ($f in $yamls) {
            # ALLOW-LIST -- a rule is *.locked.yaml (shipped) or *.custom.yaml
            # (customer override). NOTHING else in this tree is a rule: samples,
            # editor backups, "- Copy" duplicates, .gitkeep and _scratch files
            # must never load.
            #
            # This used to be a blacklist ('_*', '.*', '*.sample.*'). It let
            # 'ADDomainController.custom.sample - Copy.yaml' through, because
            # -like '*.sample.*' needs the literal '.sample.' and that name reads
            # '.sample - Copy.yaml'. The file loaded as a live rule and -- on any
            # host without its own ADDomainController.custom.yaml -- WON over the
            # shipped ADDomainController.locked.yaml, making sample content the
            # effective detection rule. Verified, and it shipped in v2.2.405.
            # A blacklist has to predict every wrong name; an allow-list does not.
            if ($f.Name -notlike '*.locked.yaml' -and $f.Name -notlike '*.custom.yaml') { $skipped++; continue }
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
                # AUDIT #29 -- counted SEPARATELY from $skipped on purpose. Most skips above are
                # deliberate and benign (sample files, foreign schemas, engine filters), so a
                # blanket "skipped=N" says nothing. A file that fails to PARSE is different: it is
                # a rule the operator wrote and believes is in force, and it is not.
                $parseFailed++
                [void]$parseFailedNames.Add($f.Name)
                continue
            }

            # Required: id (must match filename basename per ARCHITECTURE.md § 7).
            # customer files in rules-custom/ may use the .custom.yaml
            # naming convention (AssetProfileByTags.custom.yaml). Strip the .custom
            # infix from basename before id-comparison so the override file pairs
            # cleanly with the locked file's id.
            #
            # Silently skip foreign schemas that live in the same engine folder
            # but belong to other engines (e.g. AssetTagging.custom.yaml uses
            # the asset-tagging-engine shape `AssetTagging: [...]` -- not a
            # rule shape). These should not produce a noisy WARN every run.
            # ConvertFrom-Yaml returns a Hashtable, so .PSObject.Properties lists the
            # HASHTABLE's own members (IsReadOnly, Keys, Values, Count, ...) and never
            # the YAML keys -- this test was ALWAYS false. The AssetTagging files fell
            # through to the 'no id field' branch instead and emitted a misleading
            # WARNING every run, which is exactly the noise this guard exists to
            # prevent. Ask the dictionary itself.
            if ($obj -is [System.Collections.IDictionary] -and $obj.Contains('AssetTagging')) {
                $skipped++; continue
            }
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
                    File        = $f.FullName.Substring($ruleBase.Length).TrimStart('\','/')
                    Folder      = $folder
                    Source      = $ruleSource
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

                    # Per-detection asset exclusion list. Read from
                    # `excludeAssets:` on the detection (alias
                    # `excludeNames:`). Accepted shapes:
                    #   excludeAssets: ['my-old-box', '*-legacy-*']
                    #   excludeAssets:
                    #     - my-old-box
                    #     - '*-legacy-*'
                    # Comparison happens against the asset's Name field
                    # (case-insensitive) in Invoke-SIRuleEval. Wildcards
                    # supported via PowerShell -like (*, ?). Use this
                    # when you can't remove the matching software /
                    # signal from the asset itself but want the asset
                    # out-of-scope FOR THIS DETECTION only -- the rule
                    # continues to fire for every other asset.
                    $exclude = @()
                    $rawEx = if ($d.excludeAssets) { $d.excludeAssets } elseif ($d.excludeNames) { $d.excludeNames } else { $null }
                    if ($rawEx) {
                        if ($rawEx -is [System.Collections.IEnumerable] -and -not ($rawEx -is [string])) {
                            $exclude = @($rawEx | ForEach-Object { [string]$_ } | Where-Object { $_ })
                        } else {
                            $exclude = @(([string]$rawEx) -split '[,;]\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                        }
                    }

                    [void]$detections.Add([pscustomobject]@{
                        Id            = $detId
                        Detect        = $d.detect      # leave nested @{ any|all = [...]} as-is for RuleEval to consume
                        Set           = $d.set
                        ExcludeAssets = $exclude        # @() when not configured -- empty means "exclusion disabled"
                    })
                }
            }

            # osPlatformScope: optional per-rule list of OS classes the rule applies to.
            # When non-empty, Invoke-Profile.ps1 Pass 2.5 buckets the rule into ONLY
            # those OS-class buckets. When empty/missing, rule lands in EVERY bucket
            # (unscoped) and runs against every asset. Without this field on the
            # rule object, the bucketing optimization is silently disabled.
            $osScope = @()
            if ($obj.osPlatformScope) {
                if ($obj.osPlatformScope -is [System.Collections.IEnumerable] -and -not ($obj.osPlatformScope -is [string])) {
                    $osScope = @($obj.osPlatformScope | ForEach-Object { [string]$_ } | Where-Object { $_ })
                } else {
                    $osScope = @(([string]$obj.osPlatformScope) -split '[,;]\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
            }

            [void]$results.Add([pscustomobject]@{
                Id              = $id
                AppliesTo       = $appliesTo
                Mode            = $mode
                osPlatformScope = $osScope
                Purpose         = if ($obj.purpose)     { [string]$obj.purpose }     else { $null }
                Category        = if ($obj.category)    { [string]$obj.category }    else { $null }
                Description     = if ($obj.description) { [string]$obj.description } else { $null }
                Detections      = $detections.ToArray()
                File            = $f.FullName.Substring($ruleBase.Length).TrimStart('\','/')
                Folder          = $folder
                Source          = $ruleSource
                SchemaShape     = 'AssetProfileBy'
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
    # AUDIT #34 -- precedence is now RANKED rather than "custom replaces whatever came before",
    # because a third source exists. Highest rank wins; equal rank keeps the first seen:
    #   2 = overlay *.custom.yaml   (operator data root -- the most specific statement)
    #   1 = in-tree *.custom.yaml   (today's customer override, same as before)
    #   0 = *.locked.yaml           (shipped)
    # With no overlay configured this collapses to exactly the previous behaviour: every rule is
    # rank 0 or 1 and custom still beats locked.
    if ($results.Count -gt 1) {
        $deduped = New-Object System.Collections.ArrayList
        $byId    = @{}
        $rankOf  = {
            param($r)
            if ($r.File -notlike '*.custom.yaml') { return 0 }
            if ($r.Source -eq 'overlay') { return 2 }
            return 1
        }
        foreach ($r in $results) {
            if (-not $byId.ContainsKey($r.Id)) {
                $byId[$r.Id] = $r
            } elseif ((& $rankOf $r) -gt (& $rankOf $byId[$r.Id])) {
                $byId[$r.Id] = $r
            }
            # else: same or lower rank than what we already hold -- ignore.
        }
        foreach ($r in $byId.Values) { [void]$deduped.Add($r) }
        $dropped = $results.Count - $deduped.Count
        if ($dropped -gt 0) {
            Write-SIInfo ("Get-SIRuleSet: deduped {0} rule(s) (locked/custom pair) -- {1} unique rules remain" -f $dropped, $deduped.Count)
        }
        $results = $deduped
    }

    Write-Verbose ("Get-SIRuleSet: engine={0} loaded={1} skipped={2} folders={3}" -f $Engine, $loaded, $skipped, ($folders -join ','))

    # AUDIT #34 -- CUTOVER VISIBILITY. When an overlay is configured, operator rules still sitting in
    # the shipped tree are read (never ignored -- silently dropping them would be #29 a third time)
    # but they are the OLD location, and on a colliding id the overlay now outranks them. Say so once
    # per run, naming the files, so a half-finished migration cannot look like a finished one.
    if ($overlayActive) {
        $overlayRules = @($results | Where-Object { $_.Source -eq 'overlay' })
        $strayCustom  = @($results | Where-Object { $_.Source -eq 'tree' -and $_.File -like '*.custom.yaml' })
        Write-SIInfo ("Get-SIRuleSet: operator data overlay ACTIVE at '{0}' -- {1} of {2} rule(s) for engine '{3}' come from the overlay." -f `
            $overlayRoot, $overlayRules.Count, @($results).Count, $Engine)
        if ($strayCustom.Count -gt 0) {
            Write-Warning ("Get-SIRuleSet: {0} operator rule(s) for engine '{1}' are still in the SHIPPED TREE while an overlay is configured -- {2}. They ARE loaded, but they live in the directory the updater writes to and the overlay outranks them on a colliding id. Move them under '{3}\<engine>\' to complete the migration." -f `
                $strayCustom.Count, $Engine, (($strayCustom | ForEach-Object { $_.File }) -join ', '), $overlayRoot)
        }
    }

    # AUDIT #29 -- a rule file that will not PARSE must be visible on a normal run.
    #
    # Found by running the endpoint profiler live: all 8 *.custom.yaml files in this environment
    # had been unparseable since 2026-06-11 (the space after each `key:` was stripped), so every
    # customer tagging/profiling rule was inert -- while the run still reported
    # "Engine completed successfully". The per-file warnings above scroll past in a long log, and
    # the only aggregate was the Write-Verbose line above, which prints for nobody by default.
    # Same defect shape as #27: the engine knew, and never said so where anyone would look.
    #
    # Deliberately a WARNING, not a throw: a broken custom rule must not stop a security run that
    # still produces useful output -- consistent with the standing "a source failing must never
    # block the run" decision. But it must not be silent either.
    if ($parseFailed -gt 0) {
        Write-Warning ("Get-SIRuleSet: {0} of {1} rule file(s) for engine '{2}' FAILED TO PARSE and were not applied -- {3}. These rules are NOT in force for this run; classification and tagging ran without them. Fix the YAML (a common cause is a missing space after 'key:') and re-run." -f `
            $parseFailed, ($loaded + $parseFailed), $Engine, ($parseFailedNames -join ', '))
    }

    # AUDIT #36 -- a rule that LOADS with zero detections does nothing, and said so
    # to nobody. Parsing is not the only way a rule can be inert: the #29 repair left
    # asset-profiling-enrichment/azure/AssetProfileByTags.custom.yaml ending at a bare
    # `detections:` with nothing under it. It parses, it loads, it dedups -- and it
    # matches no asset, ever. There is no *.locked.yaml sibling for it, so the whole
    # Azure CMDB tag mapping was running on a rule with no rules in it.
    # `mode: disable` is the ONE legitimate zero-detection case (the customer is
    # suppressing a locked rule on purpose) and is excluded.
    $emptyRules = @($results | Where-Object { $_.Mode -ne 'disable' -and @($_.Detections).Count -eq 0 })
    if ($emptyRules.Count -gt 0) {
        Write-Warning ("Get-SIRuleSet: {0} rule(s) for engine '{1}' loaded with ZERO detections and can never match -- {2}. A rule with no detections is inert; check the file's 'detections:' block is not empty (use 'mode: disable' if suppression was intended)." -f `
            $emptyRules.Count, $Engine, (($emptyRules | ForEach-Object { $_.File }) -join ', '))
    }

    # AUDIT #35 -- a detect kind the evaluator does not know is DROPPED, silently.
    # Invoke-SIDetect logs an unknown kind with Write-Verbose (prints for nobody) and
    # then continues in any-mode / returns $false in all-mode. That is how the
    # unregistered 'nameMatches' cost 95 detections their name-pattern arm for the
    # whole v2.2 lifetime without a single visible symptom. Checked here, at load, so
    # it costs one pass over the final rule set instead of a test in the per-asset
    # hot loop -- and so a customer's typo'd kind is reported on the run that uses it,
    # not just by the lint they may never run.
    # Soft dependency: RuleEval.ps1 is dot-sourced alongside this file by the profile
    # stage, but not by every caller, so absence of the registry is not an error.
    if (Get-Command -Name 'Get-SIKindRegistry' -ErrorAction SilentlyContinue) {
        $kindRegistry = Get-SIKindRegistry
        $unknownKinds = @{}
        foreach ($r in $results) {
            foreach ($det in @($r.Detections)) {
                $dmode = if ($det.Detect.any) { 'any' } elseif ($det.Detect.all) { 'all' } else { $null }
                if (-not $dmode) { continue }
                foreach ($spec in @($det.Detect.$dmode)) {
                    $k = [string]$spec.kind
                    if ([string]::IsNullOrWhiteSpace($k)) { continue }
                    if (-not $kindRegistry.ContainsKey($k)) {
                        if (-not $unknownKinds.ContainsKey($k)) { $unknownKinds[$k] = 0 }
                        $unknownKinds[$k]++
                    }
                }
            }
        }
        if ($unknownKinds.Count -gt 0) {
            $kindDetail = (($unknownKinds.Keys | Sort-Object | ForEach-Object { '{0} ({1} detection(s))' -f $_, $unknownKinds[$_] }) -join ', ')
            Write-Warning ("Get-SIRuleSet: {0} detect kind(s) used by engine '{1}' rules are NOT in the RuleEval registry and are SKIPPED at evaluation -- {2}. Those detection arms never match, and a detection whose only arm is unknown can never fire. Check the spelling, or that the kind is registered in RuleEval.ps1." -f `
                $unknownKinds.Count, $Engine, $kindDetail)
        }
    }

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
