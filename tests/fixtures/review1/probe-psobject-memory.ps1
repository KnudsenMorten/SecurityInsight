#Requires -Version 7.0
<#
    What setting three note properties on N PSCustomObject rows costs in managed memory, by way of setting them -- measured
    inside the function that sets them (the rows and whatever the function still holds) and after it returned (the rows
    only). Read-only on nothing; prints one line per way and size.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/review1/probe-psobject-memory.ps1
#>
param([int[]]$Sizes = @(2000, 20000))
$ErrorActionPreference = 'Stop'
function New-Rows([int]$N) { $o = [object[]]::new($N); for ($i = 0; $i -lt $N; $i++) { $o[$i] = [pscustomobject]@{ MdeDeviceId = ('dev{0:D6}' -f $i); SI_AffectedVendor = 'apache'; SI_AffectedProduct = 'log4j'; SI_AffectedVersion = '2.14.1' } }; , $o }
$ways = [ordered]@{
    'read PSObject.Properties[name] only' = { param($r) $pp = $r.PSObject.Properties; $null = $pp['si_evidence_paths']; $null = $pp['si_install_kind'] }
    'PSObject.Properties.Add'             = { param($r) $pp = $r.PSObject.Properties; $pp.Add([psnoteproperty]::new('si_evidence_paths', 'C:\x\y.jar')); $pp.Add([psnoteproperty]::new('si_install_kind', 'bundled')); $pp.Add([psnoteproperty]::new('si_bundled_by', 'App')) }
    'lookup then Add (the product)'       = { param($r) $pp = $r.PSObject.Properties; foreach ($n in 'si_evidence_paths', 'si_install_kind', 'si_bundled_by') { $q = $pp[$n]; if ($q) { $q.Value = 'v' } else { $pp.Add([psnoteproperty]::new($n, 'v')) } } }
    'Add-Member -Force'                   = { param($r) $r | Add-Member -NotePropertyName si_evidence_paths -NotePropertyValue 'C:\x\y.jar' -Force; $r | Add-Member -NotePropertyName si_install_kind -NotePropertyValue 'bundled' -Force; $r | Add-Member -NotePropertyName si_bundled_by -NotePropertyValue 'App' -Force }
}
foreach ($n in $Sizes) {
    foreach ($w in $ways.Keys) {
        $rows = New-Rows $n
        [GC]::Collect(); $before = [GC]::GetTotalMemory($true)
        $inside = & {
            foreach ($r in $rows) { & $ways[$w] $r }
            [GC]::GetTotalMemory($true)
        }
        $after = [GC]::GetTotalMemory($true)
        Write-Host ('PROBE {0,7:N0} rows  {1,-38} inside {2,8:N0} B/row   after {3,8:N0} B/row' -f $n, $w, (($inside - $before) / $n), (($after - $before) / $n))
        $rows = $null
    }
}
