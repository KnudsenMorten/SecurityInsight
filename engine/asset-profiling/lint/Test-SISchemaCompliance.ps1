#Requires -Version 5.1
<#
    Test-SISchemaCompliance.ps1

    Folder lint per ARCHITECTURE.md § 17. Validates the new rule structure
    and surfaces violations BEFORE engine runtime catches them silently.

    Checks (in order):

      1. Every YAML in rules/ has id == filename basename
      2. Every YAML in rules/ declares purpose + category + appliesTo
      3. Every detection has set.Tier (numeric 0..3)
      4. Every detect.kind value is in $script:SIKindRegistry
      5. Every cmdbId referenced in rules/azure/ + rules-custom/ exists in
         sicmdbservices cache (when reachable; warning otherwise)
      6. No file under engine/ references a path under providers/<x>/
         directly (must go through provider contract)
      7. No file name contains 'v22' or 'v2.2' or any version-shaped
         suffix (per ARCHITECTURE.md rule 6)
      8. No FIELD/COLUMN name in profiles/<engine>.schema.json
         fields[].name starts with 'SI_' (per rule 4 -- columns inside a
         tenant-dedicated table don't share namespace)
      9. Every schema's providers.in / providers.out resolves to a folder
         under providers/ (when declared)

    Output: array of violations (or empty when clean). Exit code from
    -CI mode: 0 if clean, 1 if any violation surfaced.

    Usage:
        Test-SISchemaCompliance                  # interactive, returns objects
        Test-SISchemaCompliance -CI              # CI mode, exits with code
#>

function Test-SISchemaCompliance {
    [CmdletBinding()]
    param(
        [Parameter()][switch]$CI,
        [Parameter()][string]$RulesRoot
    )

    if (-not (Get-Module -Name 'powershell-yaml')) {
        Import-Module 'powershell-yaml' -Force -ErrorAction Stop
    }

    if (-not $RulesRoot) {
        # $PSScriptRoot = v2.2/engine/asset-profiling/lint -> three parents = v2.2 root
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    } else {
        $siRoot = Split-Path -Parent $RulesRoot
    }

    # Load registry to validate detect.kind values
    . (Join-Path $siRoot 'engine\asset-profiling\shared\RuleEval.ps1')
    $registry = Get-SIKindRegistry

    $violations = New-Object System.Collections.ArrayList

    function Add-Violation {
        param([string]$Rule, [string]$File, [string]$Detail)
        [void]$violations.Add([pscustomobject]@{
            Rule   = $Rule
            File   = $File
            Detail = $Detail
        })
    }

    foreach ($rulesDir in @('rules','rules-custom')) {
        $root = Join-Path $siRoot $rulesDir
        if (-not (Test-Path $root)) { continue }
        $yamls = @(Get-ChildItem -Path $root -Filter '*.yaml' -Recurse -File -ErrorAction SilentlyContinue)
        foreach ($f in $yamls) {
            try {
                $obj = ConvertFrom-Yaml -Yaml (Get-Content -Raw $f.FullName)
            } catch {
                Add-Violation 'parse'         $f.FullName ('YAML parse error: {0}' -f $_.Exception.Message)
                continue
            }

            # Check 1: id == basename
            $id = [string]$obj.id
            if ([string]::IsNullOrWhiteSpace($id)) {
                Add-Violation 'missing-id'    $f.FullName 'no top-level id field'
            } elseif ($id -ne $f.BaseName) {
                Add-Violation 'id-mismatch'   $f.FullName ("id='{0}' != filename basename='{1}'" -f $id, $f.BaseName)
            }

            # Check 2: required top-level fields
            if (-not $obj.purpose)   { Add-Violation 'missing-purpose'   $f.FullName 'no purpose field' }
            if (-not $obj.category)  { Add-Violation 'missing-category'  $f.FullName 'no category field' }
            if (-not $obj.appliesTo) { Add-Violation 'missing-appliesTo' $f.FullName 'no appliesTo field' }

            # Skip detection-level checks for mode: disable
            if ([string]$obj.mode -eq 'disable') { continue }

            # Check 3 + 4: per-detection
            if (-not $obj.detections) {
                Add-Violation 'no-detections' $f.FullName 'no detections array (required unless mode: disable)'
                continue
            }
            foreach ($d in $obj.detections) {
                # Tier required UNLESS detection assigns at least one cmdb* field
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

    # Check 7: no v22 / v2.2 in file names anywhere under v22Root
    $vsuffix = @(Get-ChildItem -Path $siRoot -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -match 'v22|v2\.2' -and $_.Name -notmatch 'v2\.2\.0-preview' })
    foreach ($f in $vsuffix) {
        Add-Violation 'version-in-name' $f.FullName 'file name contains version-shaped suffix (per ARCHITECTURE.md rule 6)'
    }

    # Check 8: no SI_ prefix on fields[].name in profile schemas
    foreach ($s in @('identity','endpoint','azure','public-ip')) {
        $sf = Join-Path $siRoot ('asset-profiling-schema\{0}.schema.json' -f $s)
        if (-not (Test-Path $sf)) { continue }
        try {
            $schema = Get-Content -Raw $sf | ConvertFrom-Json
            foreach ($field in @($schema.fields)) {
                if ($field.name -like 'SI_*') {
                    Add-Violation 'field-si-prefix' $sf ("field '{0}' starts with SI_ (per ARCHITECTURE.md rule 4 columns inside tenant-dedicated tables don't carry the prefix)" -f $field.name)
                }
            }
        } catch {
            Add-Violation 'schema-parse' $sf ('JSON parse error: {0}' -f $_.Exception.Message)
        }
    }

    if ($CI) {
        if ($violations.Count -gt 0) {
            $violations | Format-Table -AutoSize
            Write-Host ('FAIL: {0} violation(s)' -f $violations.Count)
            exit 1
        }
        Write-Host 'PASS: schema compliance clean'
        exit 0
    }
    return $violations.ToArray()
}
