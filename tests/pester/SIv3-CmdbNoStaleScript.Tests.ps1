#Requires -Version 5.1
<#
    v3 NEVER RUNS A STALE 2.2 CMDB SCRIPT.

    The internal sync updates an install by extracting the new release over the old one and never deletes a file
    (measured in the 2.2.460 -> 3.0 upgrade test: 138 2.2 files stay behind). One of them is the 2.2-era
    asset-profiling-providers\servicenow-cmdb\Refresh-CmdbCache.ps1 -- and the Schedule stage used it as a FALLBACK
    whenever the shipped generic-cmdb script was missing, i.e. it would refresh the CMDB cache with 2.2 code.
    Only the shipped script may run; a missing shipped script is an incomplete install and is said out loud.
    The 2.2 CMDB.csv in that folder stays a legitimate DATA source (read by the CMDB import); only the script is out.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Real   = Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Schedule.ps1'

    function script:New-SIScheduleTree {
        param([switch]$WithShippedScript)
        $root = Join-Path ([IO.Path]::GetTempPath()) ('si-sched-' + [guid]::NewGuid().ToString('N'))
        foreach ($d in 'engine\asset-profiling\stages', 'engine\asset-profiling\shared', 'engine\asset-profiling\storage',
                       'asset-profiling-providers\servicenow-cmdb', 'asset-profiling-providers\generic-cmdb') {
            $null = New-Item -ItemType Directory -Force -Path (Join-Path $root $d)
        }
        Copy-Item -LiteralPath $script:Real -Destination (Join-Path $root 'engine\asset-profiling\stages\Invoke-Schedule.ps1')
        Set-Content -LiteralPath (Join-Path $root 'engine\asset-profiling\shared\CmdbSource.ps1') -Encoding UTF8 -Value @'
function Get-SICmdbSourceAvailability { param($SolutionRoot, $EnableCmdbProvider, $EnableServiceNowCmdb) @() }
function Resolve-SICmdbSource { param($Available) @{ Source = 'generic-csv'; Reason = "CMDB source 'generic-csv' selected"; Fatal = $false } }
'@
        Set-Content -LiteralPath (Join-Path $root 'engine\asset-profiling\storage\CmdbCache.ps1') -Encoding UTF8 -Value @'
function Get-SICmdbCacheAge { param($Context) @{ State = 'never'; HoursOld = 0 } }
'@
        # the 2.2 leftover: must never run
        Set-Content -LiteralPath (Join-Path $root 'asset-profiling-providers\servicenow-cmdb\Refresh-CmdbCache.ps1') -Encoding UTF8 -Value @'
param($StorageAccountName, [switch]$UseOAuth)
$global:SITestCmdbScriptRan = 'stale-2.2'
[pscustomobject]@{ ServicesWritten = 1 }
'@
        if ($WithShippedScript) {
            Set-Content -LiteralPath (Join-Path $root 'asset-profiling-providers\generic-cmdb\Refresh-CmdbCache.ps1') -Encoding UTF8 -Value @'
param($StorageAccountName, [switch]$UseOAuth, $Source)
$global:SITestCmdbScriptRan = 'shipped'
[pscustomobject]@{ ServicesWritten = 2 }
'@
        }
        return $root
    }

    function script:Invoke-SIScheduleIn {
        param([string]$Root)
        function global:Write-SIInfo { param($m) }
        . (Join-Path $Root 'engine\asset-profiling\stages\Invoke-Schedule.ps1')
        $ctx = [pscustomobject]@{
            WhatIf         = $false
            ForceFullRun   = $false
            StorageContext = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'stsi' }
        }
        $w = @()
        $r = Invoke-SISchedule -RunContext $ctx -WarningVariable +w -WarningAction SilentlyContinue
        return [pscustomobject]@{ Result = $r; Warnings = @($w) }
    }
}

Describe 'the CMDB refresh in the Schedule stage after an update that left 2.2 files behind' {
    BeforeEach {
        $global:SITestCmdbScriptRan = $null
        $global:SI_EnableCmdbProvider = $true
    }
    AfterAll {
        $global:SITestCmdbScriptRan = $null
        $global:SI_EnableCmdbProvider = $null
        Remove-Item Function:\Write-SIInfo -ErrorAction SilentlyContinue
    }

    It 'shipped script missing, 2.2 script present: the 2.2 script does NOT run, and the run says the install is incomplete' {
        $root = New-SIScheduleTree
        try {
            $o = Invoke-SIScheduleIn -Root $root
            $global:SITestCmdbScriptRan | Should -BeNullOrEmpty -Because 'a stale 2.2 refresh script left by an update that never deletes must never run'
            $o.Result.CmdbRefresh | Should -BeNullOrEmpty
            (@($o.Warnings) -join "`n") | Should -Match 'incomplete'
            (@($o.Warnings) -join "`n") | Should -Match 'generic-cmdb'
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'shipped script present (and the 2.2 one too): only the shipped script runs' {
        $root = New-SIScheduleTree -WithShippedScript
        try {
            $o = Invoke-SIScheduleIn -Root $root
            $global:SITestCmdbScriptRan | Should -Be 'shipped'
            $o.Result.CmdbRefresh.ServicesWritten | Should -Be 2
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the Schedule stage names no script in the old provider folder at all' {
        $src = Get-Content -Raw -LiteralPath $script:Real
        $src | Should -Not -Match 'servicenow-cmdb\\Refresh-CmdbCache'
    }
}
