#Requires -Version 5.1
<#
.SYNOPSIS
    #1361: writes a READ-ONLY T-SQL batch that compares the protection score of one stored collection under the OLD rule (the
    stored figures: tier-weighted share of assets in good standing) and the NEW rule (owner 2026-11-25, "Yes, this model":
    the tier-share score of the assets' health), overall and per tier, both views.

.DESCRIPTION
    The new numbers come from the engine's OWN key-figure statement (engine\pro-data\_shared\SI-DataKeyFigures.ps1,
    Get-SIDataKeyFiguresSteps) without its 'write' step: everything it builds is a #temp table, nothing is written to a user
    table (the script refuses to write the file if the batch would). The old numbers are the collection's stored
    sidata.KeyFigure rows (the score the web app shows today). Run the file against the install's Pro DATA database through
    the Invardia Support app, as one batch; hand back the one result grid.

      pwsh -NoProfile -File SOLUTIONS\SecurityInsight\diagnostics\New-SIProtectionScoreCompareSql.ps1 -CollectionId 1234 -OutFile C:\tmp\ps-compare.sql
      # the install's own grace / model settings when they differ from the defaults:
      pwsh -NoProfile -File ...\New-SIProtectionScoreCompareSql.ps1 -CollectionId 1234 -Settings @{ SI_ProtectionScore_GraceDays_Device = '14' } -OutFile ...

    -CollectionId 0 (the default) = the newest complete collection that has stored key figures.
    Columns: Model (old | new), View (technical = Actual Risks | lifecycle = Within Accepted Lifecycle), Tier ((all) = the score,
    Tier 0..3 | Unclassified = the tier's own %), Value (%), Assets (in good standing), Total (in scope).
#>
[CmdletBinding()]
param(
    [int]$CollectionId = 0,
    [hashtable]$Settings = @{},
    [int]$CatchUpDays = 30,
    [Parameter(Mandatory)][string]$OutFile
)
$ErrorActionPreference = 'Stop'
$si = Split-Path -Parent $PSScriptRoot
. (Join-Path $si 'engine\_shared\SI-ProtectionScore.ps1')
. (Join-Path $si 'engine\_shared\SI-PatchCycle.ps1')
. (Join-Path $si 'engine\pro-data\_shared\SI-DataKeyFigures.ps1')

$p = Get-SIProtectionScoreParams -Settings $Settings
$p['CollectionId'] = '0'
$steps = Get-SIDataKeyFiguresSteps -CatchUpDays $CatchUpDays
$body = New-Object System.Text.StringBuilder
[void]$body.AppendLine('SET NOCOUNT ON;')
[void]$body.AppendLine('-- #1361 READ-ONLY: the protection score of one stored collection, OLD rule (stored) vs NEW rule (computed here in #temp tables)')
[void]$body.AppendLine((ConvertTo-SIKeyFigureParamDeclare -Params $p))
# the collection: the one asked for, else the newest complete one with stored figures
[void]$body.AppendLine(("SET @CollectionId = CONVERT(nvarchar(20), {0});" -f [int]$CollectionId))
[void]$body.AppendLine("IF @CollectionId = N'0' SET @CollectionId = (SELECT TOP (1) CONVERT(nvarchar(20), c.CollectionId) FROM sidata.Collection AS c WHERE c.Status = N'Complete' AND c.Kind = N'Detailed' AND EXISTS (SELECT 1 FROM sidata.KeyFigure AS k WHERE k.CollectionId = c.CollectionId AND k.Block = N'headline' AND k.Figure = N'protection_lifecycle') ORDER BY c.CollectionTime DESC);")
[void]$body.AppendLine($steps.Prologue)
foreach ($k in $steps.Steps.Keys) {
    if ($k -eq 'write') { continue }
    [void]$body.AppendLine("-- step $k (the engine's own text)")
    [void]$body.AppendLine([string]$steps.Steps[$k])
}
[void]$body.AppendLine(@'
SELECT x.Model, x.Figure AS [View], x.Dim2 AS Tier, x.Value, x.Assets, x.Total, @c AS CollectionId, @t AS CollectionTime
FROM (
    SELECT N'new' AS Model, Figure, Dim2, Value, Assets, Total FROM #kf WHERE Block = N'protection' AND Figure IN (N'technical', N'lifecycle') AND Dim1 = N'(all)'
    UNION ALL
    SELECT N'old', Figure, Dim2, Value, Assets, Total FROM sidata.KeyFigure WHERE CollectionId = @c AND Block = N'protection' AND Figure IN (N'technical', N'lifecycle') AND Dim1 = N'(all)'
) AS x
ORDER BY x.Figure, CASE WHEN x.Dim2 = N'(all)' THEN 0 ELSE 1 END, x.Dim2, x.Model DESC;
'@)
$sql = $body.ToString()
# READ-ONLY, or no file: nothing but #temp tables is written
$writes = @([regex]::Matches($sql, '(?i)\b(INSERT\s+(INTO\s+)?|UPDATE\s+|DELETE\s+(FROM\s+)?|MERGE\s+(INTO\s+)?|TRUNCATE\s+TABLE\s+|DROP\s+TABLE\s+|ALTER\s+TABLE\s+)\[?(sidata|cfg|dbo|sicfg|snowstage)\]?\.'))
# an UPDATE by alias must update a #temp table (its FROM names it)
$writes += @([regex]::Matches($sql, '(?is)\bUPDATE\s+(\w+)\s+SET\b.{0,600}?\bFROM\s+([#\w\.]+)\s+(AS\s+)?(\w+)') | Where-Object { $_.Groups[1].Value -eq $_.Groups[4].Value -and -not $_.Groups[2].Value.StartsWith('#') })
if (@($writes).Count) { throw ('the batch would write a user table -- not written: ' + ((@($writes) | ForEach-Object { $_.Value.Trim() }) -join ' | ')) }
[IO.File]::WriteAllText($OutFile, $sql, [Text.UTF8Encoding]::new($false))
Write-Host ("read-only comparison batch written: {0} ({1:N0} characters) -- run it against the install's Pro data database through the Invardia Support app" -f $OutFile, $sql.Length)
