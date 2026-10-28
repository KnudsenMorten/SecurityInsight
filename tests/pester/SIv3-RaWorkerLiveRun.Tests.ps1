#Requires -Version 7.0
<#
    #882 (C2) A RISK ANALYSIS WORKER OF A RUN THAT IS OVER WRITES NOTHING (live 2026-10-22, internal: the pipeline closed the
    Detailed step Interrupted at 09:40Z; its queue worker went on until 10:30 and wrote the remembered slice count the next
    run used). What these tests keep true:
      * Test-RAScaleOutRunLive (RA-ScaleOut.ps1) -- FAIL CLOSED: live only when the run is not closed, its manifest is there
        and its collection is still 'Loading'; any check that cannot be made is NOT live;
      * the bucket sizing keeps nothing while the gate says no: the remembered counts (file and Pro database), the early
        save, the history row (RA-AutoBucketing.ps1 Test-AutoBucketWriteAllowed); without a gate (a single job, a producer)
        everything is written as before;
      * the engine wiring: the worker sets the gate, asks at every query slice, late retry, smaller slice and before the
        hand-over, and the entry point keeps no counts of a worker whose run was over.
    Offline.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScaleOut.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    $script:AutoBucketConfirmedKey = '__confirmed'
    function script:New-MemStore {
        $d = @{}
        [pscustomobject]@{
            Data  = $d
            Read  = { param($Path) if ($d.ContainsKey($Path)) { $d[$Path] } else { $null } }.GetNewClosure()
            Write = { param($Path, $Text) $d[$Path] = [string]$Text }.GetNewClosure()
            List  = { param($Prefix) @($d.Keys | Where-Object { ([string]$_).StartsWith($Prefix) }) }.GetNewClosure()
        }
    }
    function script:New-LiveRun {
        $s = New-MemStore
        & $s.Write 'collect/ra-detailed/ct-1/manifest.json' '{"RunId":"ct-1"}'
        $s
    }
    $script:Engine = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $script:EngineText = [IO.File]::ReadAllText($script:Engine)
    $script:EntryText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-RiskAnalysisInContainer.ps1'))
}

AfterAll { $global:SettingsPath = $null; $script:AutoBucketWriteGate = $null }

Describe 'is this worker''s run the live one? (Test-RAScaleOutRunLive, fail closed)' {
    It 'live: not closed, the manifest is there, its collection is Loading' {
        (Test-RAScaleOutRunLive -Store (New-LiveRun) -Engine 'ra-detailed' -RunId 'ct-1' -CollectionState { 'Loading' }).Live | Should -BeTrue
        (Test-RAScaleOutRunLive -Store (New-LiveRun) -Engine 'ra-detailed' -RunId 'ct-1').Live | Should -BeTrue -Because 'before the collection is attached only the store is asked'
    }
    It 'not live: the run is closed (the pipeline ended its step) -- the reason is said' {
        $s = New-LiveRun; & $s.Write 'collect/ra-detailed/ct-1/closed.json' '{"Why":"the pipeline ended step risk-analysis-detailed"}'
        $r = Test-RAScaleOutRunLive -Store $s -Engine 'ra-detailed' -RunId 'ct-1' -CollectionState { 'Loading' }
        $r.Live | Should -BeFalse
        $r.Why | Should -Match 'closed.*pipeline ended step'
    }
    It 'not live: no manifest; a collection no longer loading (completed, failed, removed)' {
        (Test-RAScaleOutRunLive -Store (New-MemStore) -Engine 'ra-detailed' -RunId 'ct-1').Live | Should -BeFalse
        foreach ($st in 'Complete', 'Failed', '') {
            (Test-RAScaleOutRunLive -Store (New-LiveRun) -Engine 'ra-detailed' -RunId 'ct-1' -CollectionState ([scriptblock]::Create("'$st'"))).Live | Should -BeFalse
        }
    }
    It 'not live: a check that cannot be made (storage or the database) -- a worker writes nothing it cannot show is live' {
        $bad = [pscustomobject]@{ Read = { param($p) throw 'storage down' } }
        $r = Test-RAScaleOutRunLive -Store $bad -Engine 'ra-detailed' -RunId 'ct-1'
        $r.Live | Should -BeFalse
        $r.Why | Should -Match 'could not be checked.*storage down'
        (Test-RAScaleOutRunLive -Store (New-LiveRun) -Engine 'ra-detailed' -RunId 'ct-1' -CollectionState { throw 'login failed' }).Live | Should -BeFalse
    }
}

Describe 'the bucket sizing keeps nothing for a run that is over' {
    BeforeEach {
        $script:AutoBucketMemo = @{}; $script:AutoBucketSql = $null; $script:AutoBucketWriteRefusedSaid = $false
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-882-' + [guid]::NewGuid().ToString('N'))
        $script:Path = Get-AutoBucketCachePath -SettingsPath $global:SettingsPath
    }
    AfterEach { $script:AutoBucketWriteGate = $null; Remove-Item -LiteralPath $global:SettingsPath -Recurse -Force -ErrorAction SilentlyContinue }
    It 'no gate (a single job, a producer): written as before' {
        $script:AutoBucketWriteGate = $null
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 8 | Should -BeTrue
        (Read-AutoBucketCache -Path $script:Path)['R|1'] | Should -Be 8
    }
    It 'a live run: written; a run that is over: the early save and the cache write keep NOTHING (said once)' {
        $script:AutoBucketWriteGate = { [pscustomobject]@{ Live = $true; Why = '' } }
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 4 | Should -BeTrue
        $script:AutoBucketWriteGate = { [pscustomobject]@{ Live = $false; Why = 'the run ct-1 is closed' } }
        Save-AutoBucketCountEarly -QueryKey 'R|1' -Count 28 3>$null | Should -BeFalse
        Write-AutoBucketCache -Path $script:Path -CacheObject @{ 'R|1' = 64 } 3>$null
        (Read-AutoBucketCache -Path $script:Path)['R|1'] | Should -Be 4 -Because 'the count of the live run stays; the one of the run that is over is never kept'
    }
    It 'a gate that throws or answers nothing is NOT live (fail closed)' {
        $script:AutoBucketWriteGate = { throw 'storage down' }
        Test-AutoBucketWriteAllowed 3>$null | Should -BeFalse
        $script:AutoBucketWriteGate = { $null }
        Test-AutoBucketWriteAllowed 3>$null | Should -BeFalse
    }
    It 'the Pro database: no state change and no history row while the run is over' {
        $calls = New-Object System.Collections.Generic.List[string]
        $inv = { param($s, $p, $m) $calls.Add([string]$s) }.GetNewClosure()
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = $inv; Template = 'T'; RunId = 'r'; State = @{}; Saved = @{}; History = @{}; Offline = $false }
        $script:AutoBucketWriteGate = { [pscustomobject]@{ Live = $false; Why = 'closed' } }
        Write-AutoBucketCache -Path $script:Path -CacheObject @{ 'R|1' = 28 } 3>$null
        $null = Complete-AutoBucketReport -ReportName 'R' -QueryKey 'R|1' -StartCount 2 -FinalCount 28 -Source 'probe' 3>$null
        $calls.Count | Should -Be 0
        $script:AutoBucketWriteGate = { [pscustomobject]@{ Live = $true; Why = '' } }
        $null = Complete-AutoBucketReport -ReportName 'R' -QueryKey 'R|1' -StartCount 2 -FinalCount 2 -Source 'cache'
        $calls.Count | Should -BeGreaterThan 0 -Because 'a live run records its history as before'
    }
}

Describe 'the engine wiring' {
    It 'the worker sets the gate from Test-RAScaleOutRunLive with its collection''s state' {
        $script:EngineText | Should -Match ([regex]::Escape('$script:AutoBucketWriteGate = $script:RAScaleLive'))
        $script:EngineText | Should -Match 'Test-RAScaleOutRunLive -Store \$script:RAScaleStore'
        $script:EngineText | Should -Match "SELECT Status FROM sidata\.Collection WHERE CollectionId = CONVERT\(int, @CollectionId\) AND RaCompletedAt IS NULL"
    }
    It 'it asks at every query slice, late retry, smaller slice and before the hand-over -- and stops there (exit, nothing written)' {
        foreach ($w in 'before query slice', 'before the late retry of slice', 'before a smaller slice of', 'before handing report') {
            $script:EngineText | Should -Match ("Assert-RAScaleOutWorkerLive -Where \('{0}" -f [regex]::Escape($w))
        }
        $script:EngineText | Should -Match '(?s)function Assert-RAScaleOutWorkerLive.{0,1800}\$global:SI_RA_ScaleOutRunOver = \$why.{0,600}exit 0'
        # the hand-over check comes BEFORE the hand-over is written
        $i = $script:EngineText.IndexOf("Assert-RAScaleOutWorkerLive -Where ('before handing report"); $j = $script:EngineText.IndexOf('Write-RAScaleOutItemResult -Store $script:RAScaleStore')
        ($i -gt 0 -and $j -gt $i) | Should -BeTrue
    }
    It 'the entry point keeps no count of a worker whose run was over' {
        $script:EntryText | Should -Match ([regex]::Escape('$global:SI_RA_ScaleOutRunOver = '''''))
        $script:EntryText | Should -Match ([regex]::Escape('if ($bucketCachePath -and -not ($raWorker -and "$($global:SI_RA_ScaleOutRunOver)".Trim()))'))
    }
    It 'the engine parses' {
        $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$e)
        @($e).Count | Should -Be 0
    }
}
