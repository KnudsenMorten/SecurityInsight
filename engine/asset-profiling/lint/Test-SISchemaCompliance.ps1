#Requires -Version 5.1
<#
    Test-SISchemaCompliance.ps1

    Folder lint for the AssetProfileBy* rule tree. Validates rule files and
    surfaces violations BEFORE the engine skips them at runtime with a warning.

    AUDIT #29 part 2 -- this lint was DEAD. It iterated @('rules','rules-custom'),
    two folders that have not existed since the rules moved to
    asset-profiling-enrichment/ (its own header comment already said so). Both
    Test-Path checks failed, it validated ZERO files and returned an EMPTY
    violation list -- i.e. it reported CLEAN. Same fail-open shape as #29 itself,
    one layer up. Two further traps went with it:
      * the file only DEFINED a function, so an operator running
        `.\Test-SISchemaCompliance.ps1` got no output and no exit code -- silence
        that reads exactly like "clean";
      * nothing called it at all (the only references were in docs/DESIGN.md).
    Now: it scans the real tree, it is wired into the pre-publish gate
    (tests/pester/SI-RuleSchemaCompliance.Tests.ps1), and "I validated nothing"
    is itself a violation rather than a pass.

    What counts as a rule file -- the SAME allow-list as Get-SIRuleSet (#30):
    *.locked.yaml (shipped) or *.custom.yaml (operator override), and NOTHING
    else. Samples, editor backups, '- Copy' duplicates and _scratch files are
    not rules and are not linted as rules. A lint that disagreed with the loader
    about what a rule is would validate files the engine ignores and ignore
    files the engine runs.

    Checks (in order):

      1. Parses as YAML                      -- the #29 defect itself
      2. id == filename basename             (.custom / .locked infix stripped,
                                              exactly as the loader strips it)
      3. purpose + category + appliesTo present
      4. every detection sets Tier (0..3) or at least one cmdb* field
      5. every detect.kind is in the RuleEval $script:SIKindRegistry
      6. no file name carries a version-shaped suffix (v22 / v2.2)
      7. no fields[].name in asset-profiling-schema/<engine>.schema.json
         starts with 'SI_' (columns inside a tenant-dedicated table don't
         repeat the table's namespace)
      8. the scan itself covered at least one file -- see 'scanned-nothing'

    AssetTagging*.yaml is a DIFFERENT, valid schema consumed by
    engine/asset-tagging/AssetTagging.ps1 (`AssetTagging: [...]`), not a rule.
    It is skipped by the same dictionary probe the loader uses (#31) -- but its
    YAML still has to PARSE, and check 1 covers it.

    Output: array of violation objects (empty = clean). -CI prints them and
    exits 1 on any violation, 0 when clean.

    Usage:
        .\Test-SISchemaCompliance.ps1                 # run it: prints + returns
        .\Test-SISchemaCompliance.ps1 -CustomOnly     # only MY *.custom.yaml
        .\Test-SISchemaCompliance.ps1 -CI             # exit code for automation
        . .\Test-SISchemaCompliance.ps1               # dot-source: defines only
#>

[CmdletBinding()]
param(
    [Parameter()][switch]$CI,
    # Overrides the solution root otherwise derived from $PSScriptRoot, so the
    # lint can be exercised against a scratch tree. Mirrors Get-SIRuleSet's
    # -SolutionRootOverride seam (added for #29).
    [Parameter()][string]$SolutionRoot,
    # Lint ONLY *.custom.yaml -- what an operator runs after editing their own
    # rules. Shipped *.locked.yaml files are left out of the scan.
    [Parameter()][switch]$CustomOnly,
    # Return WHAT WAS SCANNED alongside the violations, so a caller can assert
    # coverage rather than infer it from an empty violation list. #29's real
    # defect was never a wrong verdict -- it was 0 files scanned, reported as
    # clean. A caller that cannot see the denominator cannot tell those apart.
    [Parameter()][switch]$AsSummary
)

function Test-SISchemaCompliance {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$CI,
        [Parameter()][string]$SolutionRoot,
        [Parameter()][switch]$CustomOnly,
        [Parameter()][switch]$AsSummary
    )

    if (-not (Get-Module -Name 'powershell-yaml')) {
        Import-Module 'powershell-yaml' -Force -ErrorAction Stop
    }

    # $PSScriptRoot = <si>/engine/asset-profiling/lint -> three parents = solution root
    $siRoot = if (-not [string]::IsNullOrWhiteSpace($SolutionRoot)) { $SolutionRoot }
              else { Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }

    # Load the registry to validate detect.kind values.
    . (Join-Path $siRoot 'engine\asset-profiling\shared\RuleEval.ps1')
    $registry = Get-SIKindRegistry

    $violations   = New-Object System.Collections.ArrayList
    $scanned      = 0
    $scannedNames = New-Object System.Collections.Generic.List[string]

    function Add-Violation {
        param([string]$Rule, [string]$File, [string]$Detail)
        [void]$violations.Add([pscustomobject]@{
            Rule   = $Rule
            File   = $File
            Detail = $Detail
        })
    }

    $enrichRoot = Join-Path $siRoot 'asset-profiling-enrichment'
    if (Test-Path $enrichRoot) {
        $yamls = @(Get-ChildItem -Path $enrichRoot -Filter '*.yaml' -Recurse -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.FullName -notmatch '[\\/](OUTPUT|logs|staging)[\\/]' })
        foreach ($f in $yamls) {
            # Allow-list, identical to Get-SIRuleSet (#30).
            $isCustom = $f.Name -like '*.custom.yaml'
            $isLocked = $f.Name -like '*.locked.yaml'
            if (-not $isCustom -and -not $isLocked) { continue }
            if ($CustomOnly -and -not $isCustom)    { continue }

            $scanned++
            [void]$scannedNames.Add($f.Name)

            try {
                $obj = ConvertFrom-Yaml -Yaml (Get-Content -Raw $f.FullName)
            } catch {
                # The #29 defect: at RUNTIME this is a warning and the run carries
                # on without the rule. Here it is a hard violation -- that is the
                # whole point of having a lint an operator can run before a run.
                Add-Violation 'parse' $f.FullName ('YAML parse error: {0}' -f $_.Exception.Message)
                continue
            }

            # Foreign schema (asset-tagging), not a rule -- but it had to parse first.
            if ($obj -is [System.Collections.IDictionary] -and $obj.Contains('AssetTagging')) { continue }

            # Check 2: id == basename, with the loader's .custom/.locked strip.
            $id = [string]$obj.id
            $effectiveBaseName = $f.BaseName
            if ($effectiveBaseName -like '*.custom')      { $effectiveBaseName = $effectiveBaseName.Substring(0, $effectiveBaseName.Length - 7) }
            elseif ($effectiveBaseName -like '*.locked')  { $effectiveBaseName = $effectiveBaseName.Substring(0, $effectiveBaseName.Length - 7) }
            if ([string]::IsNullOrWhiteSpace($id)) {
                Add-Violation 'missing-id'  $f.FullName 'no top-level id field'
            } elseif ($id -ne $effectiveBaseName) {
                Add-Violation 'id-mismatch' $f.FullName ("id='{0}' != filename basename='{1}'" -f $id, $effectiveBaseName)
            }

            # Check 3: required top-level fields
            if (-not $obj.purpose)   { Add-Violation 'missing-purpose'   $f.FullName 'no purpose field' }
            if (-not $obj.category)  { Add-Violation 'missing-category'  $f.FullName 'no category field' }
            if (-not $obj.appliesTo) { Add-Violation 'missing-appliesTo' $f.FullName 'no appliesTo field' }

            # Skip detection-level checks for mode: disable
            if ([string]$obj.mode -eq 'disable') { continue }

            # Check 4 + 5: per-detection
            if (-not $obj.detections) {
                Add-Violation 'no-detections' $f.FullName 'no detections array (required unless mode: disable)'
                continue
            }
            foreach ($d in $obj.detections) {
                # Tier required UNLESS the detection assigns at least one cmdb* field
                # (CMDB tag-mapping rules like AssetProfileByTags are valid without Tier)
                $hasCmdb = $d.set -and (
                    $d.set.cmdbId -or $d.set.cmdbName -or $d.set.cmdbCriticality -or $d.set.cmdbDataSensitivity
                )
                if (-not $d.set -or ($null -eq $d.set.Tier -and -not $hasCmdb)) {
                    Add-Violation 'no-tier-or-cmdb' $f.FullName ("detection '{0}' must set either Tier or at least one cmdb* field" -f $d.id)
                } elseif ($null -ne $d.set.Tier) {
                    $t = [int]$d.set.Tier
                    if ($t -lt 0 -or $t -gt 3) {
                        Add-Violation 'tier-range' $f.FullName ("detection '{0}' Tier={1} (must be 0..3)" -f $d.id, $t)
                    }
                }
                $kindList = if ($d.detect.any) { $d.detect.any } elseif ($d.detect.all) { $d.detect.all } else { @() }
                foreach ($spec in $kindList) {
                    $kind = [string]$spec.kind
                    if ([string]::IsNullOrWhiteSpace($kind)) {
                        Add-Violation 'kind-missing' $f.FullName ("detection '{0}' has detect entry with no 'kind'" -f $d.id)
                        continue
                    }
                    if (-not $registry.ContainsKey($kind)) {
                        Add-Violation 'kind-unknown' $f.FullName ("detection '{0}' uses kind '{1}' not in RuleEval registry" -f $d.id, $kind)
                    }
                }
            }
        }
    }

    # Check 6: no version-shaped suffix in any shipped file name. Scoped to the
    # rule tree + schema folder; OUTPUT/logs/staging are run artefacts, not ours.
    foreach ($vroot in @('asset-profiling-enrichment','asset-profiling-schema')) {
        $vp = Join-Path $siRoot $vroot
        if (-not (Test-Path $vp)) { continue }
        $vsuffix = @(Get-ChildItem -Path $vp -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match 'v22|v2\.2' })
        foreach ($f in $vsuffix) {
            Add-Violation 'version-in-name' $f.FullName 'file name contains a version-shaped suffix (names say WHAT, not WHICH VERSION)'
        }
    }

    # Check 7: no SI_ prefix on fields[].name in the profile schemas
    foreach ($s in @('identity','endpoint','azure','public-ip')) {
        $sf = Join-Path $siRoot ('asset-profiling-schema\{0}.schema.json' -f $s)
        if (-not (Test-Path $sf)) { continue }
        try {
            $schema = Get-Content -Raw $sf | ConvertFrom-Json
            foreach ($field in @($schema.fields)) {
                if ($field.name -like 'SI_*') {
                    Add-Violation 'field-si-prefix' $sf ("field '{0}' starts with SI_ -- columns inside a tenant-dedicated table don't repeat the table's namespace" -f $field.name)
                }
            }
        } catch {
            Add-Violation 'schema-parse' $sf ('JSON parse error: {0}' -f $_.Exception.Message)
        }
    }

    # Check 8 -- the control. A lint that walked an empty or wrong tree must not
    # look identical to a lint that found nothing wrong (#32's lesson: a check
    # driven by a violation list disappears in the healthy case, so assert that
    # the scan HAPPENED). -CustomOnly is exempt: a customer who has written no
    # overrides is legitimately scanning zero files.
    if ($scanned -eq 0 -and -not $CustomOnly) {
        Add-Violation 'scanned-nothing' $enrichRoot 'lint validated 0 rule files -- wrong root, or the rule tree is missing. This is a FAILURE, not a clean result.'
    }

    if ($CI) {
        if ($violations.Count -gt 0) {
            $violations | Format-Table -AutoSize
            Write-Host ('FAIL: {0} violation(s) over {1} rule file(s)' -f $violations.Count, $scanned)
            exit 1
        }
        Write-Host ('PASS: schema compliance clean over {0} rule file(s)' -f $scanned)
        exit 0
    }

    Write-Verbose ('Test-SISchemaCompliance: scanned {0} rule file(s), {1} violation(s)' -f $scanned, $violations.Count)
    if ($AsSummary) {
        return [pscustomobject]@{
            Scanned      = $scanned
            ScannedNames = $scannedNames.ToArray()
            Violations   = $violations.ToArray()
        }
    }
    return $violations.ToArray()
}

# Run when invoked as a script; define-only when dot-sourced (Pester, callers
# that want the function). Before this, running the file did NOTHING and printed
# NOTHING -- indistinguishable from a clean lint.
if ($MyInvocation.InvocationName -ne '.') {
    if ($CI) {
        # -CI reports and calls exit from inside the function.
        Test-SISchemaCompliance @PSBoundParameters
    } else {
        # Always ask for the summary, then decide what to print. Two reasons,
        # both learned the hard way:
        #
        #   * ONE violation used to print PASS (#37). `return $violations.ToArray()`
        #     with a single element is unwrapped to a bare [pscustomobject] on the
        #     way out, and .Count on one of those is $null in PS 5.1 -- so
        #     `$result.Count -gt 0` was FALSE and the lint congratulated itself
        #     with a violation in hand. Exactly one violation is the normal case
        #     for an operator repairing their own rules, i.e. the case this
        #     command exists to serve. @() around the collection is load-bearing.
        #   * The verdict is meaningless without the DENOMINATOR (#29 part 2):
        #     "clean over 555 files" and "clean over 0 files" printed the same
        #     word. -CI has said "over N rule file(s)" all along; this path now
        #     does too.
        $p = @{}
        foreach ($k in $PSBoundParameters.Keys) { $p[$k] = $PSBoundParameters[$k] }
        $p['AsSummary'] = $true
        $summary = Test-SISchemaCompliance @p
        $found   = @($summary.Violations)
        if ($found.Count -gt 0) {
            $found | Format-Table -AutoSize
            Write-Host ('FAIL: {0} violation(s) over {1} rule file(s)' -f $found.Count, $summary.Scanned)
        } else {
            Write-Host ('PASS: schema compliance clean over {0} rule file(s)' -f $summary.Scanned)
        }
        if ($AsSummary) { $summary }
    }
}
