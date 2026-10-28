#Requires -Version 5.1
<#
.SYNOPSIS
    3 fixes from live RA run after reclassification:
      1. Rename `CrossEngine_*` ReportNames to use the new SecurityDomain prefix
         (Identity_/Endpoint_/Azure_) -- per user "drop crossengine".
      2. Replace `project SecurityDomain="CrossEngine"` literal in KQL with the
         report's metadata SecurityDomain -- changed the metadata
         but the project clause was untouched.
      3. Insert `| extend Subcategory = ""` before project when missing -- the
         legacy-restoration pass left some reports with project referencing
         `Subcategory` but no extend defining it (KQL: 'project' operator:
         Failed to resolve scalar expression named 'Subcategory').

.DESCRIPTION
    Idempotent: re-runs are no-ops once all 3 conditions are satisfied.
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

$raw = Get-Content -LiteralPath $Yaml -Raw
$blocks = [regex]::Split($raw, '(?m)(?=^- ReportName:)')

# Per-report mapping built dynamically from each block's metadata
$renamed   = 0
$projFixed = 0
$subFixed  = 0
$out = New-Object System.Collections.Generic.List[string]

foreach ($block in $blocks) {
    if ($block -notmatch 'ReportName:') { $out.Add($block); continue }

    $name = if ($block -match '- ReportName:\s*(\S+)') { $matches[1] } else { '' }
    $sd   = if ($block -match '(?m)^\s*SecurityDomain:\s*(\S+)') { $matches[1] } else { '' }
    if (-not $name -or -not $sd) { $out.Add($block); continue }

    $newBlock = $block

    # ---------- 1. Rename CrossEngine_* ReportNames ----------
    if ($name -like 'CrossEngine_*' -and $sd -in @('Identity','Endpoint','Azure')) {
        $newName = $name -replace '^CrossEngine_', ($sd + '_')
        $newBlock = [regex]::Replace($newBlock, "(?<=^- ReportName:\s*)$([regex]::Escape($name))\b", $newName, 1)
        $renamed++
    }

    # ---------- 2. Replace project SecurityDomain="CrossEngine" with metadata SD ----------
    # Some queries hardcode SecurityDomain="CrossEngine" in the project; align with
    # the report's actual SecurityDomain. This catches both `SecurityDomain="CrossEngine"`
    # and `SecurityDomain ="CrossEngine"` variants.
    if ($sd -ne 'CrossEngine') {
        $before = $newBlock
        $newBlock = $newBlock -replace 'SecurityDomain\s*=\s*"CrossEngine"', ('SecurityDomain="' + $sd + '"')
        if ($newBlock -ne $before) { $projFixed++ }
    }

    # ---------- 3. Insert `| extend Subcategory = ""` before project when missing ----------
    # Detect: the ReportQuery references `Subcategory` in `project` but has no
    # `| extend Subcategory =` line. Add a sentinel empty-string extend right
    # before the // __SI_CANONICAL__ marker (or before the project itself when
    # marker is absent).
    $hasSubcatExtend = $newBlock -match '(?m)^\s*\|\s*extend\s+Subcategory\s*='
    $projRefsSubcat  = $newBlock -match '(?m)^\s*\|\s*project\s.*?\bSubcategory\b'
    if ($projRefsSubcat -and -not $hasSubcatExtend) {
        $insertion = '            | extend Subcategory = ""' + "`r`n"
        if ($newBlock -match '(?m)^(\s*)// __SI_CANONICAL__') {
            $marker = $matches[0]
            $newBlock = [regex]::Replace($newBlock, [regex]::Escape($marker), { param($m) $insertion + $m.Value }, 1)
        } else {
            # Fallback: insert before the first `| project`
            if ($newBlock -match '(?ms)(ReportQuery: \|-\r?\n.*?)(\r?\n\s*\| project )') {
                $newBlock = $newBlock.Replace($matches[1] + $matches[2], $matches[1] + "`r`n" + $insertion.TrimEnd("`r","`n") + $matches[2])
            }
        }
        $subFixed++
    }

    $out.Add($newBlock)
}

Write-Host ("Renamed CrossEngine_* -> Identity_/Endpoint_/Azure_: {0}" -f $renamed) -ForegroundColor Cyan
Write-Host ("Fixed project SecurityDomain=CrossEngine literal:    {0}" -f $projFixed) -ForegroundColor Cyan
Write-Host ("Inserted missing 'extend Subcategory = """"':         {0}" -f $subFixed) -ForegroundColor Cyan

if ($WhatIfMode) {
    Write-Host '(WhatIf -- no writes)' -ForegroundColor White
    return
}
Set-Content -LiteralPath $Yaml -Value ($out -join '') -Encoding UTF8 -NoNewline
Write-Host 'YAML rewritten in place.' -ForegroundColor Green
