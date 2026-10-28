#Requires -Version 5.1
<#
    #735 -- EVERY GUARD IN ONE PLACE (Operations > Guards and support).

    Before: the collection's asset-drop guard (collection.source.asset-drop) and Risk Analysis' guards (ra.bucket.count-jump,
    the row-count and column-fill guards) handed Send-SIGuardEvent NO database, so their trips reached SI_RunHealth_CL and
    the uplink but cfg.GuardEvent -- the Guards view -- only when something else in the process had happened to open the
    Pro database first. The data sync's and the connectors' guards wrote cfg.GuardEvent. Two places.

    Now (engine\_shared\SI-Guard.ps1): Send-SIGuardEvent (and the heal's Resolve-SIGuardStore) take the database from
    Resolve-SIGuardEventInvoke -- the one handed in, else the process's guard seam, else THE INSTALL'S PRO DATABASE
    (Get-SIGuardProInvoke, which loads the SQL helper itself when the engine has not). Additive: run health and the uplink
    are written exactly as before; an install without a Pro database (Community) writes none, as before.

    Offline: every database is a fake that records the statements. NOTHING is mailed or sent.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    # the guard relief turned most guards off by default; this file proves where a trip is WRITTEN, so every guard is on
    function Test-SIGuardDefaultOn { param([string]$GuardId) $true }
    function script:New-FakeDb {
        $calls = New-Object System.Collections.Generic.List[object]
        $inv = { param($sql, $p, $mode) $calls.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode })
                 if ($sql -match 'HasGuards') { return 1 }; if ($sql -match 'FROM cfg\.Guard(State|Accept)') { return @() }; if ($mode -eq 'scalar') { return 1 } }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Calls = $calls }
    }
    function script:Get-Inserts($Db) { @($Db.Calls | Where-Object { $_.Sql -match 'INSERT cfg\.GuardEvent' }) }
}

Describe 'Resolve-SIGuardEventInvoke -- which database a guard event is written to' {
    BeforeEach { $script:SavedSeam = $global:SI_GuardInvoke; $global:SI_GuardInvoke = $null }
    AfterEach { $global:SI_GuardInvoke = $script:SavedSeam }

    It 'the database a step hands in wins' {
        $mine = { param($s, $p, $m) 'mine' }
        $pro = { param($s, $p, $m) 'pro' }
        $r = Resolve-SIGuardEventInvoke -Invoke $mine -IsTest $false -ProInvoke { $pro }
        (& $r 'x' @{} 'scalar') | Should -Be 'mine'
    }
    It 'a step that hands in none gets the install''s Pro database (the collection and Risk Analysis guards)' {
        $pro = { param($s, $p, $m) 'pro' }
        $r = Resolve-SIGuardEventInvoke -IsTest $false -ProInvoke { $pro }
        $r | Should -Not -BeNullOrEmpty
        (& $r 'x' @{} 'scalar') | Should -Be 'pro'
    }
    It 'the process''s guard seam comes before opening the Pro database' {
        $global:SI_GuardInvoke = { param($s, $p, $m) 'seam' }
        $r = Resolve-SIGuardEventInvoke -IsTest $false -ProInvoke { throw 'must not be opened' }
        (& $r 'x' @{} 'scalar') | Should -Be 'seam'
    }
    It 'no Pro database (Community), or one that cannot be opened -> none, never a throw' {
        Resolve-SIGuardEventInvoke -IsTest $false -ProInvoke { $null } | Should -BeNullOrEmpty
        { Resolve-SIGuardEventInvoke -IsTest $false -ProInvoke { throw 'no sign-in' } } | Should -Not -Throw
        Resolve-SIGuardEventInvoke -IsTest $false -ProInvoke { throw 'no sign-in' } | Should -BeNullOrEmpty
    }
    It 'a test session never opens a database of its own' {
        Resolve-SIGuardEventInvoke -IsTest $true -ProInvoke { { param($s, $p, $m) 'pro' } } | Should -BeNullOrEmpty
    }
    It 'Get-SIGuardProInvoke without a Pro database configured gives none' {
        $s1 = $global:SI_ProSqlServer; $s2 = $global:SI_ProSqlDatabase
        try { $global:SI_ProSqlServer = ''; $global:SI_ProSqlDatabase = ''; Get-SIGuardProInvoke | Should -BeNullOrEmpty }
        finally { $global:SI_ProSqlServer = $s1; $global:SI_ProSqlDatabase = $s2 }
    }
}

Describe 'the wiring -- the guard event and the heal both resolve their database' {
    It 'Send-SIGuardEvent and Resolve-SIGuardStore call Resolve-SIGuardEventInvoke' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1'))
        $send = [regex]::Match($g, '(?s)function Send-SIGuardEvent \{.*?\n\}').Value
        $send | Should -Match '\$Invoke = Resolve-SIGuardEventInvoke -Invoke \$Invoke -IsTest \$isTest'
        $h = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-GuardHeal.ps1'))
        $store = [regex]::Match($h, '(?s)function Resolve-SIGuardStore \{.*?\n\}').Value
        $store | Should -Match 'Resolve-SIGuardEventInvoke -Invoke \$Invoke -IsTest \$isTest'
    }
    It 'Get-SIGuardProInvoke loads the SQL helper itself when the engine has not (a collection job)' {
        $g = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1'))
        $f = [regex]::Match($g, '(?s)function Get-SIGuardProInvoke \{.*?\n\}').Value
        $f | Should -Match "'data-sql', 'SI-DataSql\.ps1'"
        [IO.File]::Exists((Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')) | Should -BeTrue
    }
}

Describe 'a collection guard and a Risk Analysis guard reach cfg.GuardEvent -- additive' {
    BeforeEach {
        $global:SI_GuardSeenThisRun = @{}
        $global:SI_GuardTestStore = $null
        $script:Db = New-FakeDb
        $script:Health = New-Object System.Collections.Generic.List[object]
        # the step hands in no database (as in the engine); the resolver gives the install's Pro database
        $script:NoPro = $false
        Mock Resolve-SIGuardEventInvoke { if ($Invoke) { $Invoke } elseif ($script:NoPro) { $null } else { $script:Db.Invoke } }
        function script:Send-SIRunHealthRow { param($RunContext, $Phase, $AssetCount, $ExitReason, $ErrorMessage, [switch]$NoTelemetry) $script:Health.Add([pscustomobject]@{ Phase = $Phase; Exit = $ExitReason; Msg = $ErrorMessage }) }
    }
    AfterEach { Remove-Item function:Send-SIRunHealthRow -ErrorAction SilentlyContinue }

    It 'the asset-drop guard (collection.source.asset-drop): one row in cfg.GuardEvent AND its run-health row' {
        $drops = @([pscustomobject]@{ Feed = 'eg|azure_resource'; Provider = 'eg'; RecordType = 'azure_resource'; Now = 20; Baseline = 101; ChangePercent = -80.2
                                      Action = 'hold'; Event = $true; Confirmed = $false; Text = 'eg azure_resource records: 20 in this collection against 101 in the last good one (-80.2 %)'; Percent = 30 })
        Send-SIRecordFeedDropEvents -Drops $drops -Engine 'asset-profiling'
        $ins = Get-Inserts $script:Db
        $ins.Count | Should -Be 1
        $ins[0].P.GuardId | Should -Be 'collection.source.asset-drop'
        $ins[0].P.Outcome | Should -Be 'held'
        $ins[0].P.Subject | Should -Be 'eg azure_resource'
        $ins[0].P.HeldCount | Should -Be 81
        # the existing output stays: the run-health row (SI_RunHealth_CL) is written as before
        @($script:Health | Where-Object { $_.Phase -eq 'Guard' -and $_.Exit -eq 'guard-held' }).Count | Should -Be 1
    }
    It 'the bucket-jump guard of Risk Analysis (ra.bucket.count-jump): one row in cfg.GuardEvent AND its run-health row' {
        $calls = @(Get-SIRaBucketJumpGuardCalls -Jumps @([pscustomobject]@{ Report = 'Device_Missing_CVEs_Detailed'; Why = '512 buckets, usually 16'; Count = 512 }) -Template 'RiskAnalysis_Detailed')
        $null = Invoke-SIGuardCalls -Calls $calls -Common @{ Engine = 'risk-analysis'; Job = 'si-risk-analysis-detailed' }
        $ins = Get-Inserts $script:Db
        $ins.Count | Should -Be 1
        $ins[0].P.GuardId | Should -Be 'ra.bucket.count-jump'
        $ins[0].P.Outcome | Should -Be 'warning'
        @($script:Health | Where-Object { $_.Exit -eq 'guard-warning' }).Count | Should -Be 1
    }
    It 'without a Pro database the trip still reaches run health (nothing is written to SQL, nothing fails)' {
        $script:NoPro = $true
        $rh = New-Object System.Collections.Generic.List[string]
        $r = Send-SIGuardEvent -GuardId 'ra.bucket.count-jump' -Outcome warning -Engine 'risk-analysis' -Subject 'RiskAnalysis_Detailed' -RunId 'no-pro-1' `
                -StateStore (New-SIGuardMemoryStateStore) -RunHealth { param($c, $x, $m, $h) $rh.Add([string]$x) }.GetNewClosure() -Globals @{ SI_Telemetry_Enabled = $false } -NoMail -Log { param($l, $m) }
        [string]$r.Status | Should -Be 'recorded'
        [bool]$r.Stored | Should -BeFalse
        @(Get-Inserts $script:Db).Count | Should -Be 0
        $rh.Count | Should -Be 1
        $rh[0] | Should -Be 'guard-warning'
    }
}
