#Requires -Version 5.1
<#
.SYNOPSIS
    Reads or replaces ONE report's KQL (its ReportQuery |- block) in risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml,
    as plain text, keeping the YAML around it byte for byte (REQUIREMENTS #505 -- the reports were rewritten one by one).

.DESCRIPTION
    -Get                  prints the report's KQL, de-indented (what the engine runs).
    -QueryFile <path>     replaces it with the file's KQL, re-indented to the block's indentation. A CI block written as
                          `//__SI_CI_LINK_BEGIN__ <classes>` / `//__SI_CI_ASSET_BEGIN__ <classes>` on one line (classes
                          optional, comma-separated) is expanded to the canonical block (RA-CiKql.ps1), so a report never
                          carries a hand-written copy.
    Both shapes the file uses are handled: `ReportQuery: |-` and `ReportQuery:` + `- |-`.
.EXAMPLE
    .\tools\ra-ci\Set-RaReportQuery.ps1 -Report Identity_NoMFA_Summary -Get > nomfa.kql
    .\tools\ra-ci\Set-RaReportQuery.ps1 -Report Identity_NoMFA_Summary -QueryFile nomfa.kql
#>
[CmdletBinding(DefaultParameterSetName = 'get')]
param(
    [Parameter(Mandatory)][string]$Report,
    [Parameter(ParameterSetName = 'get')][switch]$Get,
    [Parameter(ParameterSetName = 'set', Mandatory)][string]$QueryFile,
    [string]$YamlPath
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $YamlPath) { $YamlPath = Join-Path $siRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml' }
. (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')

function Find-RaReportQueryBlock {
    <# PURE. -> @{ Start; End (exclusive line index of the body); Indent } for the report's query body, or $null. #>
    param([string[]]$Lines, [string]$Report)
    $at = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) { if ($Lines[$i] -match ('^\s*-\s*ReportName:\s*' + [regex]::Escape($Report) + '\s*$')) { $at = $i; break } }
    if ($at -lt 0) { return $null }
    $q = -1
    for ($i = $at + 1; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*-\s*ReportName:') { break }
        if ($Lines[$i] -match '^\s*ReportQuery:\s*\|-?\s*$') { $q = $i; break }
        if ($Lines[$i] -match '^\s*ReportQuery:\s*$' -and ($i + 1) -lt $Lines.Count -and $Lines[$i + 1] -match '^\s*-\s*\|-?\s*$') { $q = $i + 1; break }
    }
    if ($q -lt 0) { return $null }
    $start = $q + 1
    $indent = $null
    for ($i = $start; $i -lt $Lines.Count; $i++) { if ($Lines[$i].Trim()) { $indent = ([regex]::Match($Lines[$i], '^\s*')).Value; break } }
    $end = $start
    for ($i = $start; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i]
        if ($l.Trim() -and -not $l.StartsWith($indent)) { break }
        $end = $i + 1
    }
    while ($end -gt $start -and -not $Lines[$end - 1].Trim()) { $end-- }      # trailing blank lines stay outside
    return @{ Start = $start; End = $end; Indent = $indent }
}

function Expand-RaCiBlockShorthand {
    <# PURE. `//__SI_CI_LINK_BEGIN__ device,identity` (one line, no END) -> the canonical block. #>
    param([string]$Kql)
    foreach ($kind in 'link', 'asset') {
        $b = $script:RACiLinkBegin; $e = $script:RACiLinkEnd
        if ($kind -eq 'asset') { $b = $script:RACiAssetBegin; $e = $script:RACiAssetEnd }
        if ($Kql.Contains($e)) { continue }        # already a full block
        $Kql = [regex]::Replace($Kql, '(?m)^(?<ind>[ \t]*)' + [regex]::Escape($b) + '(?<cls>[ \t]+[a-z_, ]+)?[ \t]*\r?$', {
                param($m)
                $cls = @(([string]$m.Groups['cls'].Value).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                ConvertTo-RACiIndentedBlock -Block (Get-RACiKqlBlock -Kind $kind -StaleDays 30 -Classes $cls) -Indent $m.Groups['ind'].Value
            })
    }
    return $Kql
}

$raw = [IO.File]::ReadAllText($YamlPath)
$nl = "`n"; if ($raw.Contains("`r`n")) { $nl = "`r`n" }
$lines = $raw -split "`r?`n"
$blk = Find-RaReportQueryBlock -Lines $lines -Report $Report
if ($null -eq $blk) { throw "report '$Report' (or its ReportQuery block) not found in $YamlPath" }
if ($PSCmdlet.ParameterSetName -eq 'get') {
    $lines[$blk.Start..($blk.End - 1)] | ForEach-Object { if ($_.StartsWith($blk.Indent)) { $_.Substring($blk.Indent.Length) } else { $_.TrimStart() } }
    return
}
$kql = Expand-RaCiBlockShorthand ([IO.File]::ReadAllText((Resolve-Path $QueryFile)))
$kqlLines = ($kql.TrimEnd() -replace "`r", '') -split "`n"
$new = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -lt $blk.Start; $i++) { $new.Add($lines[$i]) }
foreach ($l in $kqlLines) { if ($l.Trim()) { $new.Add($blk.Indent + $l.TrimEnd()) } else { $new.Add('') } }
for ($i = $blk.End; $i -lt $lines.Count; $i++) { $new.Add($lines[$i]) }
[IO.File]::WriteAllText($YamlPath, ($new -join $nl), (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("{0}: {1} line(s) replaced by {2}" -f $Report, ($blk.End - $blk.Start), $kqlLines.Count)
