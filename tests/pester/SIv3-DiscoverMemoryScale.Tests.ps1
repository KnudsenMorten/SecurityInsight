#Requires -Version 7.0
<#
    #721 -- THE PRODUCERS AT THE LARGE RING-2 TENANT'S SIZE, MEASURED (tests\scale\Measure-SIDiscoverMemory.ps1: the real
    Invoke-SIDiscover + the record hand-over, the services generated page by page).

      * every gate: the harness runs a TINY tenant end to end for identity and endpoint through the same path as the large
        one -- the records stream (none held at the end of discovery), every record is handed over, the parts are written;
      * tag Scale (on demand only, never in a gate): the full size -- 152,842 users, 2,652 service principals, 296
        subscriptions, 1,565,906 + 351,500 Exposure Graph identity nodes; 195,524 endpoint assets -- within the job's
        8 GiB (SI_SCALE_FRACTION runs a fraction).
    PowerShell 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Harness = Join-Path $script:SIRoot 'tests\scale\Measure-SIDiscoverMemory.ps1'
    function script:Invoke-Harness([string]$Engine, [double]$Scale) {
        $out = Join-Path $TestDrive ("$Engine-{0}.json" -f [guid]::NewGuid().ToString('N').Substring(0, 6))
        $null = & pwsh -NoProfile -File $script:Harness -Engine $Engine -Scale $Scale -OutFile $out 2>&1
        Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
    }
}

Describe 'a tiny tenant goes through the same streaming path as the large one' {
    It '<Engine>: nothing held at the end of discovery, every record handed over, the parts written' -TestCases @(
        @{ Engine = 'identity'; Scale = 0.0005 }
        @{ Engine = 'endpoint'; Scale = 0.001 }
        # #727: an Azure estate (240 resources: machines, disks read before them, network interfaces, public IPs, a parent
        # that never arrives) -- its records stream too
        @{ Engine = 'azure'; Scale = 0.0002 }
    ) {
        $r = Invoke-Harness $Engine $Scale
        $r.Error | Should -BeNullOrEmpty
        $r.RecordsHeldAtEndOfDiscovery | Should -Be 0 -Because 'every record part was streamed (the Azure records too, #727)'
        $r.RecordsHandedOver | Should -BeGreaterThan 0
        $r.HandoverFiles | Should -BeGreaterThan 0
        $r.Discover.AssetCount | Should -BeGreaterThan 0
        $r.Parts | Should -BeGreaterOrEqual 1
    }
}

Describe 'the large ring-2 tenant within the job''s memory' -Tag 'Scale' {
    It '<Engine> at the full size: peak working set under 8 GiB, every record handed over' -TestCases @(
        @{ Engine = 'identity' }
        @{ Engine = 'endpoint' }
    ) {
        $f = 1.0; if ($env:SI_SCALE_FRACTION) { $f = [double]$env:SI_SCALE_FRACTION }
        $r = Invoke-Harness $Engine $f
        Write-Host ('SCALE {0} x{1}: peak {2:N0} MB in {3:N0} s; {4:N0} items handed over in {5} bucket(s)' -f $Engine, $f, $r.PeakWorkingSetMB, $r.Seconds, $r.RecordsHandedOver, $r.RecordBuckets)
        foreach ($s in @($r.Stages)) { Write-Host ('  {0,-55} peak {1,6:N0} MB  ({2} s)' -f $s.Stage, $s.PeakWorkingSetMB, $s.Seconds) }
        $r.Error | Should -BeNullOrEmpty
        $r.RecordsHeldAtEndOfDiscovery | Should -Be 0
        $r.PeakWorkingSetMB | Should -BeLessThan 8192
    }
}
