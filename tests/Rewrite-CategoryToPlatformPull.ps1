#Requires -Version 5.1
<#
.SYNOPSIS
    rewrite ~254 RA reports to source-derive Category and
    Subcategory from per-engine platform fields. The ~10 CVE-themed reports
    keep their static literal (per user spec).

.DESCRIPTION
    Per-engine source priority comes from risk-analysis.schema.locked.json:
      azure        Category    = EG_NodeLabel -> ResourceType -> AZ_NodeLabel
      azure        Subcategory = EG_NodeSubLabel
      endpoint     Category    = DeviceCategory -> DeviceType -> AssetType
      endpoint     Subcategory = OsPlatform -> JoinType -> ConnectivityType
      identity     Category    = IdentityType -> SecurityPrincipalType -> ObjectType
      identity     Subcategory = ServicePrincipalType -> MiAccountType -> UserType -> EmployeeType -> CreationType
      publicip     Category    = AssetType
      publicip     Subcategory = ServiceType
      crossengine  Category    = EdgeLabel
      crossengine  Subcategory = (none -- keep literal as fallback)
      hygiene      Category    = (none -- keep literal as fallback; engine-internal)

    For each non-CVE report:
      1. Insert `| extend Category = case(<priority chain>, "")` BEFORE the
         `// __SI_CANONICAL__` marker line (or before the project clause).
      2. Same for `| extend Subcategory`.
      3. In the project clause, replace `Category="<lit>"` with bare `Category`
         and `Subcategory="<lit>"` with bare `Subcategory`. The extend defines
         the columns; project just lists them.

    For CVE reports (in $cveKeep list): leave alone. They keep their static
    `Category="Vulnerabilities"` etc.

    Hygiene + RiskAnalysis SecurityDomain reports also leave alone (engine-
    internal -- no source mapping).
#>
[CmdletBinding()]
param(
    [string]$Yaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [switch]$WhatIfMode
)

# Per-engine source priority lists (mirror risk-analysis.schema.locked.json)
$catPriority = @{
    Azure       = @('EG_NodeLabel','ResourceType','AZ_NodeLabel')
    Endpoint    = @('DeviceCategory','DeviceType','AssetType')
    Identity    = @('IdentityType','SecurityPrincipalType','ObjectType')
    Publicip    = @('AssetType')
    CrossEngine = @('EdgeLabel')
}
$subPriority = @{
    Azure       = @('EG_NodeSubLabel')
    Endpoint    = @('OsPlatform','JoinType','ConnectivityType')
    Identity    = @('ServicePrincipalType','MiAccountType','UserType','EmployeeType','CreationType')
    Publicip    = @('ServiceType')
    CrossEngine = @()
}

# CVE-themed reports that KEEP their static literal Category/Subcategory.
$cveKeep = @(
    'Device_Missing_CVEs_Summary'
    'Device_Missing_CVEs_Summary_Detailed'
    'Endpoint_InternetFacing_Tier01_With_CVE'
    'Endpoint_InternetFacing_Tier01_With_CVE_Detailed'
    'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation'
    'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation_Detailed'
    'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure'
    'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure_Detailed'
    'CrossEngine_InternetExposed_VM_With_CVE_To_Tier0Sub'
    'CrossEngine_InternetExposed_VM_With_CVE_To_Tier0Sub_Detailed'
)

function Build-PlatformPullExtend {
    param([string]$Column, [string[]]$Sources)
    if (-not $Sources -or $Sources.Count -eq 0) { return $null }
    # Build line-by-line with explicit CRLFs so the inserted block has clean
    # line structure -- earlier here-string version glued the closing `"")` to
    # the next pipeline element (450 broken lines repo-wide).
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("            | extend $Column = case(")
    for ($i = 0; $i -lt $Sources.Count; $i++) {
        $s = $Sources[$i]
        $sep = if ($i -lt $Sources.Count - 1) { ',' } else { ',' }
        [void]$sb.AppendLine(("                isnotempty(tostring(column_ifexists(""{0}"", """"))), tostring({0}){1}" -f $s, $sep))
    }
    [void]$sb.AppendLine('                "")')
    return $sb.ToString()
}

# Read whole YAML, split on report boundaries, transform each report block.
$raw = Get-Content -LiteralPath $Yaml -Raw
$blocks = [regex]::Split($raw, '(?m)(?=^- ReportName:)')

$rewritten = 0
$kept = 0
$skipped = 0
$out = New-Object System.Collections.Generic.List[string]

foreach ($block in $blocks) {
    if ($block -notmatch 'ReportName:') {
        $out.Add($block)
        continue
    }

    # Extract report name + SecurityDomain
    $name = if ($block -match '- ReportName:\s*(\S+)') { $matches[1] } else { '' }
    $sd   = if ($block -match '(?m)^\s*SecurityDomain:\s*(\S+)') { $matches[1] } else { '' }

    if ($name -in $cveKeep) { $kept++; $out.Add($block); continue }
    if (-not $catPriority.ContainsKey($sd)) { $skipped++; $out.Add($block); continue }

    $catSrc = $catPriority[$sd]
    $subSrc = $subPriority[$sd]
    $catExtend = Build-PlatformPullExtend -Column 'Category'    -Sources $catSrc
    $subExtend = Build-PlatformPullExtend -Column 'Subcategory' -Sources $subSrc

    # 1. Insert platform-pull extends right before the // __SI_CANONICAL__ marker.
    #    If marker absent (some reports may not have it), insert just before the
    #    first `| project ` line.
    $newBlock = $block
    if ($newBlock -match '(?m)^(\s*)// __SI_CANONICAL__') {
        $marker = $matches[0]
        $insert = ''
        if ($catExtend) { $insert += $catExtend }
        if ($subExtend) { $insert += $subExtend }
        $newBlock = [regex]::Replace($newBlock, [regex]::Escape($marker), { param($m) $insert + $m.Value }, 1)
    } else {
        # Fallback: insert before first `| project` line in ReportQuery
        if ($newBlock -match '(?ms)(ReportQuery: \|-\r?\n.*?)(\r?\n\s*\| project )') {
            $insert = ''
            if ($catExtend) { $insert += $catExtend }
            if ($subExtend) { $insert += $subExtend }
            $newBlock = $newBlock.Replace($matches[1] + $matches[2], $matches[1] + $insert + $matches[2])
        }
    }

    # 2. In project clause, drop Category="lit" and Subcategory="lit" (replace with bare column ref).
    if ($catSrc -and $catSrc.Count -gt 0) {
        $newBlock = $newBlock -replace 'Category\s*=\s*"[^"]*"', 'Category'
    }
    if ($subSrc -and $subSrc.Count -gt 0) {
        $newBlock = $newBlock -replace 'Subcategory\s*=\s*"[^"]*"', 'Subcategory'
    }

    $rewritten++
    $out.Add($newBlock)
}

Write-Host ("Reports rewritten: {0}  CVE kept-static: {1}  No-source-mapping skipped (Hygiene/RiskAnalysis): {2}" -f $rewritten, $kept, $skipped) -ForegroundColor Cyan

if ($WhatIfMode) {
    Write-Host '(WhatIf -- no writes)' -ForegroundColor White
    return
}
Set-Content -LiteralPath $Yaml -Value ($out -join '') -Encoding UTF8 -NoNewline
Write-Host 'YAML rewritten in place.' -ForegroundColor Green
