#Requires -Version 5.1
<#
.SYNOPSIS
    Regenerates, per report, the scope block (//__SI_SCOPE_BEGIN__ ... END__) and every CI block (`_ciLink` /
    `_ciAsset`) in risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml from the engine's generators
    (engine/risk-analysis/_shared/RA-ScopePreamble.ps1 + RA-CiKql.ps1, REQUIREMENTS #505 / #541) -- run it after a field
    is added to the asset block, a factor or list is added to the catalog, or a report's entry in
    data-model/report-scope.locked.json changes, so every report carries the canonical SHIPPED copy
    (tests/pester/SIv3-RaReadsCi.Tests.ps1 and SIv3-RaScopePreamble.Tests.ps1 fail otherwise).

    The YAML copy carries the shipped values (no customer setting or exclusion, 30 stale days, the report's own tier
    scope and factor set) so a query pasted into the portal runs; the engine regenerates both at run time from the
    install's settings (Resolve-RAScopePreamble).
#>
[CmdletBinding()]
param([string]$YamlPath)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $YamlPath) { $YamlPath = Join-Path $siRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml' }
. (Join-Path $siRoot 'engine\data-model\SI-DataModelTemplates.ps1')
. (Join-Path $siRoot 'engine\_shared\SI-DisabledAssets.ps1')
. (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
. (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')

$dm = Join-Path $siRoot 'data-model'
$model = Get-SIDataModel -Root $dm
$template = (Get-SIDataModelTemplate -Name 'report-scope' -Root $dm).Document
$problems = @(Test-RAReportScopeTemplate -Template $template -Factors @($model['risk-factors'].factors))
if ($problems.Count) { throw ("report-scope.locked.json: " + ($problems -join '; ')) }
$subjects = Get-RASubjectDefinitions -Template $template
$fieldClasses = @{}; foreach ($f in @($model['field-catalog'].fields)) { $fieldClasses[[string]$f.name] = @($f.classes) }
$lists = @{}; foreach ($l in @($model['lists'].lists)) { if ($l.id) { $lists[[string]$l.id] = $l } }
$factors = @{}; foreach ($f in @($model['risk-factors'].factors)) { if ($f.id) { $factors[[string]$f.id] = $f } }

function Update-RaReportChunk {
    <# One report's text (from its '    - ReportName:' line): the scope block and the CI blocks regenerated. Returns the new text. #>
    param([string]$Chunk)
    $name = [regex]::Match($Chunk, '^(\S+)').Groups[1].Value
    $known = @(@($template.reports) | Where-Object { [string]$_.id -eq $name }).Count -gt 0
    if (-not $known) { return $Chunk }
    # the query is a block scalar: '      ReportQuery:' + '      - |-' (or '- |'), or '      ReportQuery: |-'
    $q = [regex]::Match($Chunk, '(?m)^      ReportQuery:(?:\n      - \|-?| \|-?)\n')
    if (-not $q.Success) { return $Chunk }
    $labels = @()
    $tm = [regex]::Match($Chunk, '(?m)^      CriticalityTierLevelScope:\n((?:      - [^\n]*\n)+)')
    if ($tm.Success) { $labels = @([regex]::Matches($tm.Groups[1].Value, '(?m)^      - ([^\n]+)$') | ForEach-Object { $_.Groups[1].Value.Trim() }) }
    $spec = Get-RAReportScope -ReportName $name -Template $template
    $fs = @(Get-RAReportFactorSet -Spec $spec -Factors @($model['risk-factors'].factors) -Subjects $subjects -FieldClasses $fieldClasses)
    $d = Get-RAScopeDefaults -Spec $spec -TierLabels $labels -FactorSet $fs
    $d.Lists = $lists; $d.Factors = $factors
    $d.FactorNames = Get-RAFactorNameMap -Factors @($model['risk-factors'].factors) -FactorSet $fs
    $active = Get-RAScopeActive -Spec $spec -Values $d
    $headEnd = $q.Index + $q.Length
    $body = $Chunk.Substring($headEnd)
    # the query ends where the next top-level key of the entry starts (a line indented 6 spaces), else at the chunk end
    $end = [regex]::Match($body, '(?m)^      [A-Za-z]')
    $query = $body; $rest = ''
    if ($end.Success) { $query = $body.Substring(0, $end.Index); $rest = $body.Substring($end.Index) }
    # strip a previous scope block, then put the fresh one first
    $query = [regex]::Replace($query, '(?ms)^[ \t]*' + [regex]::Escape('//__SI_SCOPE_BEGIN__') + '.*?' + [regex]::Escape('//__SI_SCOPE_END__') + '[ \t]*\n', '')
    $query = Resolve-RACiBlocks -Query $query -StaleDays 30 -Scope $active
    $block = New-RAScopeBlock -Active $active -Query $query
    $ind = '        '
    $first = [regex]::Match($query, '(?m)^([ \t]+)\S')
    if ($first.Success) { $ind = $first.Groups[1].Value }
    $block = ConvertTo-RACiIndentedBlock -Block $block -Indent $ind
    return ($Chunk.Substring(0, $headEnd) + $block + "`n" + $query + $rest)
}

$raw = [IO.File]::ReadAllText($YamlPath)
$crlf = $raw.Contains("`r`n")
$lf = $raw -replace "`r`n", "`n"
$chunks = [regex]::Split($lf, '(?m)^(?=    - ReportName: )')
$sb = New-Object System.Text.StringBuilder
foreach ($c in $chunks) {
    if ($c.StartsWith('    - ReportName: ')) { [void]$sb.Append('    - ReportName: ' + (Update-RaReportChunk -Chunk $c.Substring(18))) }
    else { [void]$sb.Append($c) }
}
$new = $sb.ToString()
if ($crlf) { $new = $new -replace "`n", "`r`n" }
if ($new -ne $raw) { [IO.File]::WriteAllText($YamlPath, $new, (New-Object System.Text.UTF8Encoding($false))); Write-Host 'Scope and CI blocks regenerated.' } else { Write-Host 'Scope and CI blocks already canonical.' }
