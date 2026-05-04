#Requires -Version 5.1
<#
.SYNOPSIS
    Deduplicates field names across the three v2.2 Profile schema JSONs.

.DESCRIPTION
    Walks fields[] in endpoint.schema.json, identity.schema.json,
    azure.schema.json. For each field name appearing more than once:

      * If every duplicate has the same `source` value -- they're bugs (someone
        added the field twice). Keep the last definition (most recent) and
        drop the earlier ones.
      * If duplicates carry DIFFERENT `source` values -- they're legitimately
        different fields that share a name. Rename each duplicate to '<name>_<source>'.

    Writes a summary report to stdout: which schema, which name, dup count,
    sources seen, action taken (KEEP-LAST | RENAME-WITH-SOURCE).

    Schemas are written back UTF-8 no-BOM, ConvertTo-Json with -Depth 50 and
    a sane indentation.
#>

[CmdletBinding()]
param(
    [Parameter()][string]$ProfilesDir = (Join-Path $PSScriptRoot '..'),
    [Parameter()][switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$ProfilesDir = (Resolve-Path -LiteralPath $ProfilesDir).Path

function _ToJson($obj, [int]$Depth = 50) {
    # ConvertTo-Json's default indentation is fine; we write the result
    # back without BOM via System.IO.File.WriteAllText.
    return ($obj | ConvertTo-Json -Depth $Depth)
}

$report = @()
foreach ($engine in 'endpoint','identity','azure') {
    $path = Join-Path $ProfilesDir "$engine.schema.json"
    $raw  = Get-Content -Raw -LiteralPath $path
    $schema = $raw | ConvertFrom-Json

    $byName = @{}
    for ($i = 0; $i -lt $schema.fields.Count; $i++) {
        $f = $schema.fields[$i]
        if ([string]::IsNullOrWhiteSpace([string]$f.name)) {
            # `_section` divider entries (intentional grouping markers in
            # azure.schema.json) carry no `name`. Silently skip so they
            # pass through unchanged.
            continue
        }
        if (-not $byName.ContainsKey($f.name)) { $byName[$f.name] = @() }
        $byName[$f.name] += [pscustomobject]@{ Index = $i; Field = $f }
    }

    $dupNames = @($byName.Keys | Where-Object { $byName[$_].Count -gt 1 } | Sort-Object)
    if ($dupNames.Count -eq 0) {
        Write-Host "[OK] $engine -- no duplicates"
        continue
    }

    Write-Host ('[{0}] {1} duplicate field name(s) found' -f $engine, $dupNames.Count)

    # Build a *new* fields array. Walk the original in order; for any
    # entry whose name has duplicates, decide per-name what to do.
    $decided = @{}    # name -> { Action = KEEP-LAST | RENAME-WITH-SOURCE; Mapping = @{ Index -> NewName-or-DROP } }
    foreach ($name in $dupNames) {
        $entries = $byName[$name]
        $sources = @($entries | ForEach-Object { [string]$_.Field.source } | Sort-Object -Unique)

        if ($sources.Count -le 1) {
            # Same-source duplicates -> keep the LAST one, drop earlier.
            $keepIdx = ($entries[-1]).Index
            $mapping = @{}
            foreach ($e in $entries) {
                if ($e.Index -eq $keepIdx) { $mapping[$e.Index] = $name }
                else                       { $mapping[$e.Index] = '__DROP__' }
            }
            $decided[$name] = @{ Action = 'KEEP-LAST'; Mapping = $mapping; Sources = $sources -join ',' }
            $report += [pscustomobject]@{
                Schema    = $engine
                FieldName = $name
                DupCount  = $entries.Count
                Sources   = ($sources -join ',')
                Action    = ('KEEP-LAST (kept index {0}, dropped {1})' -f $keepIdx, (($entries | Where-Object { $_.Index -ne $keepIdx } | ForEach-Object { $_.Index }) -join ','))
            }
        } else {
            # Different sources -> rename each to '<name>_<source>'.
            $mapping = @{}
            foreach ($e in $entries) {
                $newName = ('{0}_{1}' -f $name, [string]$e.Field.source)
                $mapping[$e.Index] = $newName
            }
            $decided[$name] = @{ Action = 'RENAME-WITH-SOURCE'; Mapping = $mapping; Sources = $sources -join ',' }
            $report += [pscustomobject]@{
                Schema    = $engine
                FieldName = $name
                DupCount  = $entries.Count
                Sources   = ($sources -join ',')
                Action    = ('RENAME-WITH-SOURCE (' + (($entries | ForEach-Object { ('idx ' + $_.Index + ' -> ' + $mapping[$_.Index]) }) -join '; ') + ')')
            }
        }
    }

    # Apply: rebuild fields array
    $newFields = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $schema.fields.Count; $i++) {
        $f = $schema.fields[$i]
        if ($decided.ContainsKey($f.name)) {
            $newName = $decided[$f.name].Mapping[$i]
            if ($newName -eq '__DROP__') { continue }
            if ($newName -ne $f.name) {
                # Rename in place. PSObject Properties don't allow rename, so
                # rebuild as PSCustomObject preserving order.
                $newProps = [ordered]@{}
                foreach ($p in $f.PSObject.Properties) {
                    if ($p.Name -eq 'name') { $newProps['name'] = $newName }
                    else                    { $newProps[$p.Name] = $p.Value }
                }
                $newFields.Add([pscustomobject]$newProps)
            } else {
                $newFields.Add($f)
            }
        } else {
            $newFields.Add($f)
        }
    }
    # Rebuild the top-level schema with the new fields array. Using
    # Add-Member with -Force so we don't have to round-trip via OrderedDict
    # (which trips on object[] vs List<object> binding on PS 5.1).
    $newFieldsArr = $newFields.ToArray()
    $schema | Add-Member -MemberType NoteProperty -Name 'fields' -Value $newFieldsArr -Force
    $newJson = _ToJson $schema

    if ($WhatIf) {
        Write-Host ('       [WhatIf] would write {0} ({1:N0} bytes, was {2:N0})' -f $path, $newJson.Length, $raw.Length)
    } else {
        [System.IO.File]::WriteAllText($path, $newJson, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host ('       written {0} ({1:N0} bytes, was {2:N0})' -f $path, $newJson.Length, $raw.Length)
    }
}

Write-Host ''
Write-Host '=== SUMMARY ==='
$report | Format-Table -AutoSize | Out-String | Write-Host
Write-Host ('Total duplicate field names processed: {0}' -f $report.Count)
