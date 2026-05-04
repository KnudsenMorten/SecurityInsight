#Requires -Version 5.1
<#
.SYNOPSIS
    Inventories every report in v2.1 legacy yaml + v2.2 yaml by primary
    source class (CL | XDR | OTHER), so we know which v2.2 reports need
    porting from v2.1 (XDR-source) vs which can stay as-is (CL-source).

.DESCRIPTION
    Rule (per user 2026-04-30):
      - if v2.1's query touches XDR tables (ExposureGraph*, DeviceTvm*,
        DeviceInfo, AlertEvidence, etc.) -> v2.2 must port v2.1's design
      - if v2.1's query only touches CL tables (SI_*_CL) -> v2.2's
        already-redesigned query stays
      - reports that exist in v2.2 but NOT in v2.1 are NEW-IN-V22 (manual
        review)

    Outputs:
      - tests/audit/ra-source-inventory.csv  (one row per report)
      - console summary buckets

.NOTES
    Read-only. Re-runnable.
#>
[CmdletBinding()]
param(
    [string]$LegacyYaml  = (Join-Path $PSScriptRoot '..\legacy\risk-analysis\RiskAnalysis_Queries_Locked_legacy.yaml'),
    [string]$CurrentYaml = (Join-Path $PSScriptRoot '..\risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'),
    [string]$OutCsv      = (Join-Path $PSScriptRoot 'audit\ra-source-inventory.csv')
)

$xdrTables = @(
    'ExposureGraphNodes','ExposureGraphEdges',
    'DeviceInfo','DeviceTvmSecureConfigurationAssessment','DeviceTvmSecureConfigurationAssessmentKB',
    'DeviceTvmSoftwareInventory','DeviceTvmSoftwareVulnerabilities','DeviceTvmInfoGathering','DeviceTvmInfoGatheringKB',
    'AlertEvidence','AlertInfo','IdentityInfo','IdentityLogonEvents','IdentityQueryEvents','IdentityDirectoryEvents',
    'EmailEvents','EmailAttachmentInfo','EmailUrlInfo','EmailPostDeliveryEvents','UrlClickEvents',
    'DeviceProcessEvents','DeviceFileEvents','DeviceNetworkEvents','DeviceLogonEvents',
    'DeviceImageLoadEvents','DeviceRegistryEvents','DeviceEvents','CloudAppEvents'
)
$clRegex  = '\bSI_\w+_CL\b'
$xdrRegex = '\b(' + ($xdrTables -join '|') + ')\b'

function Parse-Reports {
    param([string]$Path, [string]$ReportSep)
    $raw = Get-Content -LiteralPath $Path -Raw
    $blocks = $raw -split ('(?m)^' + [regex]::Escape($ReportSep) + 'ReportName:\s*')
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -lt $blocks.Count; $i++) {
        $block = $blocks[$i]
        $name  = ($block -split "`r?`n", 2)[0].Trim()
        # Strip line comments and string literals before classification
        $clean = $block -replace '//[^\r\n]*','' -replace '"[^"]*"',''
        $hasXdr = [regex]::IsMatch($clean, $xdrRegex)
        $hasCl  = [regex]::IsMatch($clean, $clRegex)
        $class  = if ($hasXdr -and $hasCl) { 'XDR+CL' }
                  elseif ($hasXdr)         { 'XDR' }
                  elseif ($hasCl)          { 'CL' }
                  else                     { 'OTHER' }
        $out.Add([pscustomobject]@{ ReportName = $name; SourceClass = $class; HasXdr = $hasXdr; HasCl = $hasCl })
    }
    return ,$out
}

Write-Host 'Parsing legacy v2.1 yaml...' -ForegroundColor Cyan
$v21 = Parse-Reports -Path $LegacyYaml  -ReportSep '    - '
Write-Host ("  v2.1 reports: {0}" -f $v21.Count) -ForegroundColor White

Write-Host 'Parsing current v2.2 yaml...' -ForegroundColor Cyan
$v22 = Parse-Reports -Path $CurrentYaml -ReportSep '- '
Write-Host ("  v2.2 reports: {0}" -f $v22.Count) -ForegroundColor White

# Build v2.1 lookup
$v21Map = @{}
foreach ($r in $v21) { $v21Map[$r.ReportName] = $r }

# Cross-ref: for each v2.2 report, look up v2.1 by name (also try BucketFilter sibling)
$crossRef = New-Object System.Collections.Generic.List[object]
foreach ($r22 in $v22) {
    $v21Match = $null; $v21Name = ''
    $base = $r22.ReportName
    $candidates = @(
        $base,
        ($base + '_BucketFilter'),
        ($base -replace '_Summary_Detailed$', '_Detailed'),
        ($base -replace '_Summary_Detailed$', '_Detailed_BucketFilter'),
        ($base -replace '_Summary$', ''),
        ($base -replace '_Summary$', '_BucketFilter'),
        ($base -replace '_Detailed$', ''),
        ($base -replace '_Detailed$', '_BucketFilter'),
        # Handle v2.1's "_<Type>_BucketFilter_<scenario>" middle-token (e.g., Attack_Paths)
        ($base -replace '^(.+?)_Summary_(.+)$',     '$1_Summary_BucketFilter_$2'),
        ($base -replace '^(.+?)_Summary_(.+)_Detailed$', '$1_Detailed_BucketFilter_$2')
    )
    foreach ($candidate in $candidates) {
        if ($v21Map.ContainsKey($candidate)) { $v21Match = $v21Map[$candidate]; $v21Name = $candidate; break }
    }
    $action = if (-not $v21Match)                       { 'NEW_IN_V22' }
              elseif ($v21Match.SourceClass -match 'XDR'){ 'PORT_FROM_V21' }
              else                                       { 'KEEP_V22' }
    $crossRef.Add([pscustomobject]@{
        v22_ReportName       = $r22.ReportName
        v22_SourceClass      = $r22.SourceClass
        v21_ReportName_Match = $v21Name
        v21_SourceClass      = if ($v21Match) { $v21Match.SourceClass } else { '' }
        Action               = $action
    })
}

# Ensure output dir exists
$outDir = Split-Path $OutCsv -Parent
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$crossRef | Export-Csv -LiteralPath $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ("Wrote {0}" -f $OutCsv) -ForegroundColor Green

# Console buckets
Write-Host ''
Write-Host '== v2.2 reports by Action ==' -ForegroundColor Yellow
$crossRef | Group-Object Action | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-15} {1,4}" -f $_.Name, $_.Count)
}

Write-Host ''
Write-Host '== v2.1 reports by SourceClass ==' -ForegroundColor Yellow
$v21 | Group-Object SourceClass | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("  {0,-10} {1,4}" -f $_.Name, $_.Count)
}

Write-Host ''
Write-Host '== Sample of PORT_FROM_V21 (first 12) ==' -ForegroundColor Yellow
$crossRef | Where-Object Action -eq 'PORT_FROM_V21' | Select-Object -First 12 |
    ForEach-Object { Write-Host ("  {0}  (v21 class: {1})" -f $_.v22_ReportName, $_.v21_SourceClass) }

Write-Host ''
Write-Host '== Sample of NEW_IN_V22 (first 12) ==' -ForegroundColor Yellow
$crossRef | Where-Object Action -eq 'NEW_IN_V22' | Select-Object -First 12 |
    ForEach-Object { Write-Host ("  {0}  (v22 class: {1})" -f $_.v22_ReportName, $_.v22_SourceClass) }
