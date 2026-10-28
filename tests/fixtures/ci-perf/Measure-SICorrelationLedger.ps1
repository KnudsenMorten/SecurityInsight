#Requires -Version 7.0
<#
.SYNOPSIS
    The correlation job's identity-ledger step at a large install's size, measured offline on the test VM (local SQL Server
    Express). Vendor tool: never shipped.

.DESCRIPTION
    The synthetic tenant of CiPerfFixture.ps1 (-Scale 1: ~94,000 records -> ~77,000 objects), grouped in memory, then the
    steps Invoke-SICorrelation.ps1 runs against the identity ledger in SQL, each on its own clock:
      first run   (an empty ledger: every object mints)       read, resolve, write
      next run    (the same objects: every object reuses)     read, resolve, write
    and the ledger's content after each write (every anchor and supersession), written to -LedgerFile when given -- two
    trees compared that way write the same ledger. Writes one JSON with the seconds and counts.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SIRoot,
    [double]$Scale = 1.0,
    [Parameter(Mandatory)][string]$OutFile,
    [string]$LedgerFile,
    [string]$Server = '.\SQLEXPRESS'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $SIRoot 'engine\data-model\SI-RecordCapture.ps1')
. (Join-Path $SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
. (Join-Path $PSScriptRoot 'CiPerfFixture.ps1')
$model = Get-SIDataModel -Root (Join-Path $SIRoot 'data-model')
$say = { param($m) Write-Host ('[{0:HH:mm:ss}] {1}' -f [datetime]::UtcNow, $m) }
$res = [ordered]@{ SIRoot = $SIRoot; Scale = $Scale }
$db = $null
$T = [datetime]::SpecifyKind([datetime]'2026-10-16T03:00:00', [DateTimeKind]::Utc)
try {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $w = Write-CiPerfTenant -Scale $Scale -Model $model -Collect -T $T
    $res['Records'] = $w.Records; $res['MakeSeconds'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    $sw.Restart()
    $g = Get-SICiGroups -Records @($w.Rows)
    $groups = @($g.Groups)
    $res['Groups'] = $groups.Count; $res['GroupSeconds'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    & $say ("{0:N0} records -> {1:N0} groups (grouping {2} s)" -f $w.Records, $groups.Count, $res['GroupSeconds'])
    $w = $null
    $db = New-CiPerfDatabase -SIRoot $SIRoot -Server $Server
    $prov = [pscustomobject]@{ Kind = 'sql'; Connection = (& $db.NewEngineConn) }
    foreach ($run in 'first', 'next') {
        $st = [ordered]@{}
        $sw.Restart(); $read = Read-SIObjectLedger -Provider $prov; $st['read'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $sw.Restart(); $idy = Resolve-SIObjectIdentity -Groups $groups -Ledger $read.Ledger -Now $T.AddHours(1); $st['resolve'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $sw.Restart(); $wr = Write-SIObjectLedger -Provider $prov -Decisions $idy.Decisions -Superseded $idy.Superseded -Now $T.AddHours(1) -IfMatchETag $read.ETag -CurrentLedger $read.Ledger; $st['write'] = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        $st['ledgerRows'] = $read.Ledger.Count; $st['minted'] = $idy.Minted; $st['reused'] = $idy.Reused; $st['anchorsWritten'] = $wr.AnchorsWritten
        $res[$run] = $st
        & $say ("{0} run: {1}" -f $run, (($st.Keys | ForEach-Object { '{0} {1}' -f $_, $st[$_] }) -join '; '))
    }
    if ($LedgerFile) {
        $rows = @(& $db.Seam 'SELECT IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen, LastSeen FROM si.ObjectIdentity ORDER BY IdentifierType, IdentifierValue' @{} 'rows')
        $sup = @(& $db.Seam 'SELECT OldId, NewId, SupersededAt, Reason FROM si.ObjectIdentitySuperseded ORDER BY OldId' @{} 'rows')
        $lines = @(foreach ($r in $rows) { '{0}|{1}|{2}|{3:o}|{4:o}' -f $r.IdentifierType, $r.IdentifierValue, $r.SI_CorrelationId, $r.FirstSeen, $r.LastSeen }) + @(foreach ($s in $sup) { 'SUP {0}|{1}|{2:o}|{3}' -f $s.OldId, $s.NewId, $s.SupersededAt, $s.Reason })
        [IO.File]::WriteAllLines($LedgerFile, [string[]]$lines)
        $res['LedgerRows'] = $rows.Count
    }
    try { $prov.Connection.Dispose() } catch { }
} catch {
    $res['Error'] = ('{0} @ {1}' -f $_.Exception.Message, ((($_.ScriptStackTrace -split "`n") | Select-Object -First 3) -join ' / '))
    & $say ("ERROR " + $res['Error'])
} finally {
    Remove-CiPerfDatabase -Db $db
    [IO.File]::WriteAllText($OutFile, (ConvertTo-Json -InputObject $res -Depth 6))
}
