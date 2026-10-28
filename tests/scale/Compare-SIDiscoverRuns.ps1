#Requires -Version 7.0
<#
.SYNOPSIS
    EQUIVALENCE of two producer runs (Measure-SIDiscoverMemory.ps1 -KeepFiles), e.g. the release line and #721 on the same
    generated tenant: the records the last step would publish (every bucket merged as Publish-SIRecordHandover merges it,
    the bucket count may differ) and the content of every part the workers read (staging 'Discover', per part). #727: an
    Azure record's child resources are compared IN ORDER too (the parent's 'children' list follows it; what the last step
    publishes -- Get-SICapturedRecords -- is built from exactly these parts).
    Prints the comparison; exit 0 = identical, 1 = a difference (the first ones named).
#>
param([Parameter(Mandatory)][string]$Left, [Parameter(Mandatory)][string]$Right, [int]$Show = 5)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $siRoot 'engine\_shared\SI-CollectParts.ps1')
. (Join-Path $siRoot 'engine\data-model\SI-RecordCapture.ps1')
. (Join-Path $siRoot 'engine\data-model\SI-RecordHandover.ps1')

function Get-Canon($x) {
    if ($null -eq $x) { return $null }
    if ($x -is [System.Management.Automation.PSCustomObject]) { $h = [ordered]@{}; foreach ($n in @($x.PSObject.Properties.Name | Sort-Object)) { $h[$n] = Get-Canon $x.$n }; return $h }
    if ($x -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($n in @($x.Keys | Sort-Object)) { $h[[string]$n] = Get-Canon $x[$n] }; return $h }
    if ($x -is [array]) { return , @($x | ForEach-Object { Get-Canon $_ }) }
    return $x
}
function Get-RunRecords([string]$Dir) {
    $files = @(Get-ChildItem -LiteralPath (Join-Path $Dir 'state') -Recurse -File -Filter 'bucket-*.json' | Sort-Object FullName)
    $byBucket = @{}
    foreach ($f in $files) { $b = [int]([regex]::Match($f.Name, 'bucket-(\d{5})').Groups[1].Value); if (-not $byBucket.ContainsKey($b)) { $byBucket[$b] = New-Object System.Collections.Generic.List[string] }; $byBucket[$b].Add($f.FullName) }
    $out = @{}; $pulls = @{}
    foreach ($b in $byBucket.Keys) {
        $m = $null
        foreach ($p in ($byBucket[$b] | Sort-Object)) { $m = Merge-SIRecordHandover -Documents @([IO.File]::ReadAllText($p) | ConvertFrom-Json) -Into $m }
        $null = Remove-SIRecordHandoverOrphans -State $m
        foreach ($e in $m.Records.GetEnumerator()) {
            $r = $e.Value
            # a part's JSON text compared as data (key order and number formatting of the text are not the record)
            $parts = (@($r.Parts.Keys | Sort-Object) | ForEach-Object { '{0}={1}' -f $_, (ConvertTo-Json -InputObject (Get-Canon ([string]$r.Parts[$_].SIJson | ConvertFrom-Json)) -Compress -Depth 30) }) -join ';'
            # #727 the ORDER of an Azure record's child resources is part of the record (its 'children' list follows it)
            $childOrder = (@($r.Parts.Keys) | Where-Object { ([string]$_).StartsWith('child|') }) -join ','
            $out[[string]$e.Key] = '{0}|{1}|{2}|{3}|{4}|{5}|children={6}' -f $r.Provider, $r.RecordType, $r.Key, $r.ResourceType, ((@($r.Engines | Where-Object { $_ }) | Sort-Object -Unique) -join ','), $parts, $childOrder
        }
        foreach ($p in $m.Pulls.Values) { $pulls[[string]$p.Provider] = '{0}:{1}' -f $p.Complete, $p.Error }
    }
    [pscustomobject]@{ Records = $out; Pulls = $pulls; Buckets = $byBucket.Count; Files = $files.Count }
}
function Get-RunParts([string]$Dir) {
    $root = Join-Path $Dir 'staging\Discover'
    $parts = @{}
    if (-not (Test-Path -LiteralPath $root)) { return $parts }
    foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory)) {
        $set = @{}
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -File)) {
            foreach ($line in [IO.File]::ReadLines($f.FullName)) { if ($line) { $o = ConvertFrom-Json -InputObject $line; $set[[string]$o.NormalizedKey] = (ConvertTo-Json -InputObject (Get-Canon $o) -Compress -Depth 30) } }
        }
        $parts[$d.Name] = $set
    }
    $parts
}

$diff = 0
$l = Get-RunRecords $Left; $r = Get-RunRecords $Right
Write-Host ('records: left {0:N0} in {1} bucket(s) / {2} file(s); right {3:N0} in {4} bucket(s) / {5} file(s)' -f $l.Records.Count, $l.Buckets, $l.Files, $r.Records.Count, $r.Buckets, $r.Files)
$onlyL = @($l.Records.Keys | Where-Object { -not $r.Records.ContainsKey($_) }); $onlyR = @($r.Records.Keys | Where-Object { -not $l.Records.ContainsKey($_) })
if ($onlyL.Count -or $onlyR.Count) { $diff++; Write-Host ('  only left: {0}; only right: {1}  e.g. {2} {3}' -f $onlyL.Count, $onlyR.Count, (($onlyL | Select-Object -First $Show) -join ' '), (($onlyR | Select-Object -First $Show) -join ' ')) }
$ne = @($l.Records.Keys | Where-Object { $r.Records.ContainsKey($_) -and $r.Records[$_] -cne $l.Records[$_] })
if ($ne.Count) { $diff++; Write-Host ('  {0} record(s) differ, e.g.:' -f $ne.Count); foreach ($k in ($ne | Select-Object -First $Show)) { Write-Host ('    L {0}' -f $l.Records[$k]); Write-Host ('    R {0}' -f $r.Records[$k]) } }
foreach ($k in @($l.Pulls.Keys + $r.Pulls.Keys | Sort-Object -Unique)) { if ($l.Pulls[$k] -ne $r.Pulls[$k]) { $diff++; Write-Host ('  pull {0}: {1} vs {2}' -f $k, $l.Pulls[$k], $r.Pulls[$k]) } }
$lp = Get-RunParts $Left; $rp = Get-RunParts $Right
Write-Host ('parts: left {0}, right {1}; assets {2:N0} / {3:N0}' -f $lp.Count, $rp.Count, (($lp.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum, (($rp.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum)
foreach ($p in @($lp.Keys + $rp.Keys | Sort-Object -Unique)) {
    $a = $lp[$p]; $b = $rp[$p]
    if ($null -eq $a -or $null -eq $b) { $diff++; Write-Host ('  part {0} only on one side' -f $p); continue }
    $bad = @($a.Keys | Where-Object { -not $b.ContainsKey($_) -or $b[$_] -cne $a[$_] }) + @($b.Keys | Where-Object { -not $a.ContainsKey($_) })
    if ($bad.Count) { $diff++; Write-Host ('  part {0}: {1} asset(s) differ, e.g. {2}' -f $p, $bad.Count, (($bad | Select-Object -First $Show) -join ' ')) }
}
if ($diff -eq 0) { Write-Host 'IDENTICAL: the same records (every part, engine, resource type), the same pulls, the same assets in the same parts'; exit 0 }
Write-Host ('DIFFERENT ({0} kind(s) of difference)' -f $diff); exit 1
