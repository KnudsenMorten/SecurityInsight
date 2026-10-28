#Requires -Version 5.1
<#
.SYNOPSIS
    Writes the GENERATED CONFIG JOURNAL block of sql\si-pro-settings.sql from config\config-entities.locked.json.

.DESCRIPTION
    REQUIREMENTS #404 (framework CONFIG-1.1): every configuration table carries a journal trigger and the backup reads
    cfg.vConfigSnapshot; both are generated from the ONE configuration set, so a new entity or column is a catalog change
    plus a re-run of this tool. The block sits at the end of the file between its markers and is replaced in place.
    SIv3-ConfigJournal.Tests fails when the file differs from what this tool would write. -Check: exit 1 when stale.
#>
[CmdletBinding()]
param([string]$SIRoot, [switch]$Check)

$ErrorActionPreference = 'Stop'
if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
. (Join-Path $PSScriptRoot 'SI-ConfigJournal.ps1')
$path = [System.IO.Path]::Combine($SIRoot, 'sql', 'si-pro-settings.sql')
$raw = [System.IO.File]::ReadAllText($path)
$crlf = $raw.Contains("`r`n")
$text = $raw -replace "`r`n", "`n"
$block = Get-SIConfigJournalSql -Catalog (Get-SIConfigEntityCatalog -SIRoot $SIRoot)
$start = $text.IndexOf('-- >>> GENERATED CONFIG JOURNAL')
$endMark = '-- <<< GENERATED CONFIG JOURNAL'
if ($start -ge 0) {
    $end = $text.IndexOf($endMark, $start)
    if ($end -lt 0) { throw 'the GENERATED CONFIG JOURNAL block has no end marker' }
    $new = $text.Substring(0, $start) + $block + $text.Substring($end + $endMark.Length + 1)
} else {
    $new = $text.TrimEnd("`n") + "`n`n" + $block
}
if ($Check) {
    if ($new -ne $text) { Write-Host 'si-pro-settings.sql: the GENERATED CONFIG JOURNAL block is stale -- run Build-SIConfigJournalSql.ps1'; exit 1 }
    Write-Host 'si-pro-settings.sql: the GENERATED CONFIG JOURNAL block is current'; exit 0
}
if ($crlf) { $new = $new -replace "`n", "`r`n" }
[System.IO.File]::WriteAllText($path, $new,(New-Object System.Text.UTF8Encoding($false)))
Write-Host ('si-pro-settings.sql: GENERATED CONFIG JOURNAL written ({0} entities)' -f @((Get-SIConfigEntityCatalog -SIRoot $SIRoot).entities).Count)
