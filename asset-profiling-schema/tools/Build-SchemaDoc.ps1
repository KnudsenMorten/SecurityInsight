#Requires -Version 5.1
<#
.SYNOPSIS
    Generates v2.2/DOCS/asset-profiling-schema.md from the three engine schema JSONs.

.DESCRIPTION
    Reads endpoint.schema.json, identity.schema.json, azure.schema.json --
    each declares a flat-column LA table (SI_<Engine>_Profile_CL) populated
    by the v2.2 collection pipeline. Emits one markdown chapter per engine
    with: header (table name, DCR, schemaVersion, lastModified, sourcesConsumed,
    field count), a sources legend, and one row per field with name, type,
    purpose, source, sourcePath, stage (writtenBy / readBy), addedIn.

    Re-run this whenever a schema JSON changes. The output is checked in
    so customers reading on GitHub see the current contract without having
    to parse JSON themselves.

.NOTES
    Generated artefact:  v2.2/DOCS/asset-profiling-schema.md
    Source of truth:     v2.2/asset-profiling-schema/{endpoint,identity,azure}.schema.json
    Developed by:        Morten Knudsen, Microsoft MVP
#>

[CmdletBinding()]
param(
    [Parameter()][string]$ProfilesDir = (Join-Path $PSScriptRoot '..'),
    [Parameter()][string]$OutputPath  = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'DOCS/asset-profiling-schema.md')
)

$ErrorActionPreference = 'Stop'
$ProfilesDir = (Resolve-Path -LiteralPath $ProfilesDir).Path

$engines = 'endpoint','identity','azure'
$schemas = @{}
foreach ($e in $engines) {
    $p = Join-Path $ProfilesDir "$e.schema.locked.json"
    if (-not (Test-Path -LiteralPath $p)) { throw "Schema file missing: $p" }
    $schemas[$e] = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
}

# Collect every distinct source value across all schemas so the legend at
# the top covers everything the reader will see in the per-field tables.
$allSources = [System.Collections.Generic.SortedSet[string]]::new()
foreach ($e in $engines) {
    foreach ($f in $schemas[$e].fields) {
        if ($f.source) { [void]$allSources.Add([string]$f.source) }
    }
}

# Friendly one-liner per source. Anything not listed here just appears with
# its raw name (still visible in the per-field tables).
$sourceLegend = @{
    'mde'           = 'Microsoft Defender for Endpoint (advanced hunting / DeviceInfo) -- machine-as-asset'
    'entra'         = 'Microsoft Entra ID (Graph users + servicePrincipals + groups + signInActivity)'
    'exposureGraph' = 'Microsoft Defender Exposure Graph (ExposureGraphNodes + ExposureGraphEdges) -- the v2.2 master discovery + property source'
    'azure'         = 'Azure Resource Graph + Az resource APIs -- one row per Azure resource'
    'arg'           = 'Azure Resource Graph -- alias for the azure source'
    'ad'            = 'On-prem Active Directory (when imported via the AD provider)'
    'cmdb'          = 'Customer CMDB (servicenow-cmdb provider, default-disabled). Folded onto Properties.collect.cmdb at Reconcile.'
    'derived'       = 'Computed in the engine -- Profile stage (drift hashes, IsEnabledActive, IsStaleAsset, AssetName, etc.) or Collect stage (PrimaryEntityId from EntityIds[0])'
    'shodan'        = 'Public-IP enrichment via Shodan API (opt-in, providers/shodan/)'
    'mdi'           = 'Microsoft Defender for Identity (on-prem AD signal sourced through MDI -- investigation priority + sensitive group membership)'
}

function _MkAnchor([string]$s) {
    return ($s.ToLowerInvariant() -replace '[^a-z0-9 _-]','' -replace ' ','-' -replace '--+','-').Trim('-')
}

function _Escape([string]$s) {
    if ($null -eq $s) { return '' }
    return ($s -replace '\|','\|' -replace "`r?`n",' ').Trim()
}

# Build the markdown
$now = [datetime]::UtcNow.ToString('yyyy-MM-dd')
$srcVersionFile = Join-Path (Split-Path -Parent $ProfilesDir) 'VERSION'
$siVersion = if (Test-Path -LiteralPath $srcVersionFile) {
    (Get-Content -Raw -LiteralPath $srcVersionFile).Trim()
} else { '<unknown>' }

$sb = [System.Text.StringBuilder]::new(1MB)
[void]$sb.AppendLine('# SecurityInsight v2.2 -- Profile schema reference')
[void]$sb.AppendLine()
[void]$sb.AppendLine(('> Auto-generated from `v2.2/asset-profiling-schema/{{endpoint,identity,azure}}.schema.json` by `v2.2/asset-profiling-schema/tools/Build-SchemaDoc.ps1`. Do not hand-edit. Re-run the generator after any schema change. Generated {0} for SI {1}.' -f $now, $siVersion))
[void]$sb.AppendLine()
[void]$sb.AppendLine('Three engines, three flat-column tables in Log Analytics. Every customer KQL goes against one of these (or joins across them). Cross-engine joins use `PrimaryEntityId` (the first member of `EntityIds[]`).')
[void]$sb.AppendLine()
[void]$sb.AppendLine('## Tables at a glance')
[void]$sb.AppendLine()
[void]$sb.AppendLine('| Engine | LA table | DCR | Field count | Schema version | Last modified |')
[void]$sb.AppendLine('|---|---|---|---:|---|---|')
foreach ($e in $engines) {
    $s = $schemas[$e]
    [void]$sb.AppendLine(('| {0} | `{1}` | `{2}` | {3} | {4} | {5} |' -f $e, $s.table, $s.dcrName, ($s.fields.Count), $s.schemaVersion, $s.lastModified))
}
[void]$sb.AppendLine()
[void]$sb.AppendLine('## Source legend')
[void]$sb.AppendLine()
[void]$sb.AppendLine('Every field carries a `source` field telling you where the value comes from. Values seen across the three schemas:')
[void]$sb.AppendLine()
[void]$sb.AppendLine('| Source | Description |')
[void]$sb.AppendLine('|---|---|')
foreach ($s in $allSources) {
    $desc = if ($sourceLegend.ContainsKey($s)) { $sourceLegend[$s] } else { '_(not in legend -- see schema JSON)_' }
    [void]$sb.AppendLine(('| `{0}` | {1} |' -f $s, $desc))
}
[void]$sb.AppendLine()
[void]$sb.AppendLine('## Stage legend')
[void]$sb.AppendLine()
[void]$sb.AppendLine('Each field has a `stage` block: which pipeline phase WROTE the column (always exactly one) and which phases later READ it. Phases:')
[void]$sb.AppendLine()
[void]$sb.AppendLine('- **collect** -- Stage 2 (Discover + Collect), pulls raw data from each provider and lands the row.')
[void]$sb.AppendLine('- **enrich** -- Stage 3, joins cross-source signal (e.g. EG edges, Entra group membership).')
[void]$sb.AppendLine('- **profile** -- Stage 5, derives flat-column verdicts (IsEnabledActive, UnsupportedOSDetected, IsStaleAsset, AssetName, ...).')
[void]$sb.AppendLine('- **classify** -- Stage 4, AI tier verdict + Properties.classify.* sub-tree.')
[void]$sb.AppendLine('- **reconcile** -- Stage 7, folds CMDB matches + cross-engine references.')
[void]$sb.AppendLine('- **posture_analyze** -- evaluates posture rules against the profiled row, emits Properties.posture.findings[].')
[void]$sb.AppendLine('- **dashboard / sentinel** -- consumed only by Power BI dataset / KQL queries (not written by the engine).')
[void]$sb.AppendLine()
[void]$sb.AppendLine('---')
[void]$sb.AppendLine()

foreach ($e in $engines) {
    $s = $schemas[$e]
    $engineTitleCase = $e.Substring(0,1).ToUpper() + $e.Substring(1)
    $title = ('## {0}  --  `{1}`' -f $engineTitleCase, $s.table)
    [void]$sb.AppendLine($title)
    [void]$sb.AppendLine()
    [void]$sb.AppendLine(('- **DCR**: `{0}`' -f $s.dcrName))
    [void]$sb.AppendLine(('- **Schema version**: `{0}` (last modified {1})' -f $s.schemaVersion, $s.lastModified))
    [void]$sb.AppendLine(('- **Sources consumed**: {0}' -f (($s.sourcesConsumed | ForEach-Object { '`' + $_ + '`' }) -join ', ')))
    if ($s.entityIds -and $s.entityIds.expectedTypes) {
        [void]$sb.AppendLine(('- **Entity-ID types** (members of `EntityIds[*]`): {0}' -f (($s.entityIds.expectedTypes | ForEach-Object { '`' + $_ + '`' }) -join ', ')))
    }
    if ($s.entityIds -and $s.entityIds.hubJoin) {
        [void]$sb.AppendLine(('- **Hub join** (master-record producer): `{0}`' -f $s.entityIds.hubJoin))
    }
    if ($s.egNodeLabelScope) {
        [void]$sb.AppendLine(('- **EG node labels in scope**: {0}' -f (($s.egNodeLabelScope | ForEach-Object { '`' + $_ + '`' }) -join ', ')))
    }
    [void]$sb.AppendLine(('- **Field count**: {0}' -f $s.fields.Count))
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('### Fields')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Name | Type | Purpose | Source | Source path | Written by | Read by | Added in |')
    [void]$sb.AppendLine('|---|---|---|---|---|---|---|---|')
    foreach ($f in $s.fields) {
        $writtenBy = if ($f.stage -and $f.stage.writtenBy) { '`' + (_Escape $f.stage.writtenBy) + '`' } else { '' }
        $readBy = if ($f.stage -and $f.stage.readBy) {
            (($f.stage.readBy | ForEach-Object { '`' + $_ + '`' }) -join ', ')
        } else { '' }
        $sourcePath = if ($f.sourcePath) { '`' + (_Escape $f.sourcePath) + '`' } else { '' }
        $purpose    = if ($f.purpose) { _Escape $f.purpose } else { '' }
        $src        = if ($f.source) { '`' + (_Escape $f.source) + '`' } else { '' }
        $type       = if ($f.type) { '`' + (_Escape $f.type) + '`' } else { '' }
        $addedIn    = if ($f.addedIn) { (_Escape $f.addedIn) } else { '' }
        [void]$sb.AppendLine(('| `{0}` | {1} | {2} | {3} | {4} | {5} | {6} | {7} |' -f $f.name, $type, $purpose, $src, $sourcePath, $writtenBy, $readBy, $addedIn))
    }
    [void]$sb.AppendLine()
}

$outDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outDir)) { $null = New-Item -Path $outDir -ItemType Directory -Force }
[System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ('asset-profiling-schema.md written: {0} ({1:N0} bytes, {2} engines, {3} fields total)' -f `
    $OutputPath, (Get-Item $OutputPath).Length, $engines.Count, ($engines | ForEach-Object { $schemas[$_].fields.Count } | Measure-Object -Sum).Sum)
