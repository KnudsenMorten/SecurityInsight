#Requires -Version 5.1
<#
    #1385 THE FINDING HISTORY'S PAGE INDEXES ARE QUEUED AND BUILT (owner 2026-11-25: "are the indexes done" / "and statistics").

    Live at internal (3.1.50): every data sync said "the history's page indexes are built in the index-build window (10 of 10
    not there yet)", but cfg.IndexBuild held NO row and caj-si-index-build did not exist (the runner said "the index build job
    caj-si-index-build is not there yet" every 5 minutes). Cause: the updater image did not carry
    engine/index-build/SI-IndexBuildJob.ps1, so Invoke-SIUpdaterIndexBuildJob returned 'skipped' WITHOUT A LINE before it made
    the job -- and before the history / columnstore steps that record the waiting indexes. What must hold:
      * WIRING: every file Invoke-SIUpdaterIndexBuildJob loads from the image is COPYed into the updater image (the gap itself);
      * an updater image WITHOUT the job file still records the 10 waiting rows and says so with a WARNING (never silent);
      * a run with the 10 indexes missing queues 10 rows (read back, one line); a second run queues none;
      * the index build job builds them, one per start, ONLINE + RESUMABLE (paced by its window), read back, row 'built';
      * the history's serve step then reports 0 missing and no "not there yet" line; the updater's step says 10 of 10 there.
    Offline (an in-memory database behind the Invoke seam); stubs in SCRIPT scope.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-IndexBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\index-build\SI-IndexBuildJob.ps1')
    . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataHistoryServe.ps1')
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1')
    $script:UpdLines = New-Object System.Collections.Generic.List[string]
    function script:Write-UpdLog { param([string]$m) $script:UpdLines.Add($m) }

    # ONE in-memory database: cfg.IndexBuild's rows, the member table's indexes, the catalog answers the steps read
    function script:New-Db {
        $db = [pscustomobject]@{ Rows = [ordered]@{}; Built = (New-Object System.Collections.Generic.HashSet[string]([StringComparer]::OrdinalIgnoreCase)); Creates = (New-Object System.Collections.Generic.List[string]) }
        $names = @(Get-SIHistoryIndexContract | ForEach-Object { [string]$_.Name })   # (a closure sees no dot-sourced function)
        $inv = {
            param([string]$Sql, $P, [string]$Mode)
            if ($Sql -match 'CREATE\s+INDEX') { $db.Creates.Add($Sql); throw 'an index is built only by the index build job' }
            if ($Sql -match "OBJECT_ID\(N'sidata\.FindingStateMember'\) IS NULL") {
                return , @($names | ForEach-Object { @{ Name = $_; X = $(if ($db.Built.Contains($_)) { 1 } else { 0 }); C = 0 } })
            }
            if ($Sql -match 'SELECT TableName, IndexName, Statement') {
                return , @($db.Rows.Values | ForEach-Object { @{ TableName = $_.T; IndexName = $_.I; Statement = $_.Stmt; State = $_.State; Pages = $_.Pages; EstMinutes = $null; RateSource = ''; Why = $_.Why
                                                                 SinceUtc = $_.Since; LastStartUtc = $null; LastEndUtc = $null; ForcedUtc = $null } })
            }
            if ($Sql -match 'INSERT cfg\.IndexBuild') {
                $k = '{0}|{1}' -f $P['T'], $P['I']
                $stmt = if ($P['Stmt'] -is [DBNull]) { $null } else { [string]$P['Stmt'] }
                if ($db.Rows.Contains($k)) { $r = $db.Rows[$k]; if ($stmt) { $r.Stmt = $stmt }; $r.State = [string]$P['State']; $r.Why = [string]$P['Why'] }
                else { $db.Rows[$k] = [pscustomobject]@{ T = [string]$P['T']; I = [string]$P['I']; Stmt = [string]$stmt; State = [string]$P['State']; Pages = 1000; Why = [string]$P['Why']; Since = [datetime]::UtcNow.AddMinutes(-$db.Rows.Count - 1) } }
                return $null
            }
            if ($Sql -match 'FROM sys\.indexes WHERE name = @I') { return , @(@{ N = $(if ($db.Built.Contains([string]$P['I'])) { 1 } else { 0 }) }) }
            if ($Sql -match 'sys\.allocation_units') { return , @(@{ Pages = 1000; RowCnt = 50000 }) }
            if ($Mode -eq 'scalar') { return '1' }      # the history's served objects are there
            if ($Mode -eq 'nonquery') { return $null }
            , @()
        }.GetNewClosure()
        $db | Add-Member -NotePropertyName Invoke -NotePropertyValue $inv
        $db
    }
    $script:Quiet = { param($l, $m) }
}

Describe '#1385 wiring: the updater image carries every file its index build step loads' {
    It 'each engine/ or setup/ file Invoke-SIUpdaterIndexBuildJob loads is COPYed into /si by container/updater/Dockerfile' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterDatabase.ps1'))
        $at = $src.IndexOf('function Invoke-SIUpdaterIndexBuildJob'); $at | Should -BeGreaterThan 0
        $end = $src.IndexOf("`nfunction ", $at + 10); if ($end -lt 0) { $end = $src.Length }; $fn = $src.Substring($at, $end - $at)
        $files = @([regex]::Matches($fn, "'((?:engine|setup)/[A-Za-z0-9_/.-]+\.ps1)'") | ForEach-Object { $_.Groups[1].Value }) +
                 @([regex]::Matches($fn, "Combine\(\`$SIRoot, 'engine', '_shared', '([A-Za-z0-9_.-]+\.ps1)'\)") | ForEach-Object { 'engine/_shared/' + $_.Groups[1].Value })
        $files = @($files | Select-Object -Unique)
        $files | Should -Contain 'engine/index-build/SI-IndexBuildJob.ps1'
        $files | Should -Contain 'engine/_shared/SI-IndexBuild.ps1'
        $copies = @([regex]::Matches([IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile')), '(?m)^COPY\s+(?<src>.+?)\s+/si/(?<dst>\S*)\s*$') | ForEach-Object {
            $dst = $_.Groups['dst'].Value
            foreach ($s in ($_.Groups['src'].Value -split '\s+')) { [pscustomobject]@{ Src = $s; Dst = $dst } }
        })
        foreach ($f in $files) {
            $hit = @($copies | Where-Object { ($_.Src -eq $f -and ($_.Dst -eq ($f.Substring(0, $f.LastIndexOf('/') + 1)))) -or ($_.Src.EndsWith('/') -and $f.StartsWith($_.Src) -and $_.Dst -eq $_.Src) })
            $hit.Count | Should -BeGreaterThan 0 -Because "the updater image must carry $f (3.1.50 did not carry engine/index-build/SI-IndexBuildJob.ps1)"
        }
        # the job's ENTRY point stays out of the updater (it has no index-build mode, #1111)
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Dockerfile')) | Should -Not -Match 'Invoke-SIIndexBuildJob\.ps1'
    }
}

Describe '#1385 the updater records the 10 waiting page indexes (also from an image without the job file)' {
    BeforeEach { $script:UpdLines.Clear() }
    It 'the 3.1.50 image (no engine/index-build): a WARNING says so, and the 10 rows are still recorded and read back' {
        $root = Join-Path $TestDrive 'si-image'
        New-Item -ItemType Directory -Force (Join-Path $root 'engine\_shared') | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-IndexBuild.ps1') -Destination (Join-Path $root 'engine\_shared\SI-IndexBuild.ps1')
        $db = New-Db
        $r = Invoke-SIUpdaterIndexBuildJob -SIRoot $root -Store ([pscustomobject]@{ Server = 'server.database.windows.net'; Database = 'sqldb-si-pro'; Invoke = $db.Invoke }) -SubscriptionId 's' -ResourceGroup 'rg' -Arm { $null } -Lists { @() } -Sleep { param($s) }
        $r.Action | Should -Be 'skipped'
        $all = ($script:UpdLines -join "`n")
        $all | Should -Match 'WARNING: the index build job caj-si-index-build could not be checked -- this updater image carries no (setup/_shared/SI-DbInitJob\.ps1, )?engine/index-build/SI-IndexBuildJob\.ps1; the waiting indexes are still recorded'
        @($db.Rows.Values | Where-Object { $_.T -eq 'sidata.FindingStateMember' }).Count | Should -Be 10
        @($db.Rows.Values | Where-Object { $_.State -eq 'waiting' -and $_.T -eq 'sidata.FindingStateMember' }).Count | Should -Be 10
        $all | Should -Match 'finding history indexes: 0 of 10 there, 10 waiting for the index build job \(read back\)'
        $db.Creates.Count | Should -Be 0 -Because 'the updater never builds one'
    }
    It 'a run with the 10 indexes missing queues 10 rows; the next run queues none and says 10 waiting' {
        $db = New-Db
        $r = Invoke-SIHistoryIndexStep -Invoke $db.Invoke -Log { param($m) }
        @($r.Queued).Count | Should -Be 10
        @($r.Queued) | Should -Be @(Get-SIHistoryIndexContract | ForEach-Object { $_.Name })
        foreach ($ix in Get-SIHistoryIndexContract) { $db.Rows['sidata.FindingStateMember|' + $ix.Name].Stmt | Should -Be $ix.Statement }
        ($r.Lines -join "`n") | Should -Match '0 of 10 there, 10 waiting for the index build job \(read back\)'
        $again = Invoke-SIHistoryIndexStep -Invoke $db.Invoke -Log { param($m) }
        @($again.Queued).Count | Should -Be 0
        $db.Rows.Count | Should -Be 10
        ($again.Lines -join "`n") | Should -Match '0 of 10 there, 10 waiting'
    }
    It 'a row that was not read back is a WARNING, never a silent success' {
        $db = New-Db
        $lossy = { param($s, $p, $m) if ($s -match 'INSERT cfg\.IndexBuild') { return $null }; & $db.Invoke $s $p $m }.GetNewClosure()
        $r = Invoke-SIHistoryIndexStep -Invoke $lossy -Log { param($m) }
        @($r.Queued).Count | Should -Be 10
        ($r.Lines -join "`n") | Should -Match 'WARNING: 10 recorded but not read back'
    }
}

Describe '#1385 the index build job builds them; the history then reports 0 missing' {
    It 'ten starts build the ten (online + resumable, read back, row built); the serve step and the updater''s step say all there' {
        $db = New-Db
        $null = Invoke-SIHistoryIndexStep -Invoke $db.Invoke -Log { param($m) }
        $sqls = New-Object System.Collections.Generic.List[string]
        $seams = @{
            UpdateFirst = { '' }; OtherRunning = { '' }
            Gate        = { param($h) [pscustomobject]@{ Go = $true; Reason = 'idle'; LockTaken = $true } }
            Beat        = { param($h, $w) $true }; ExitGate = { param($h) }
            ResumableOp = { param($t, $i) $null }
            Build       = { param($sql, $interrupt, $onInterrupt) $sqls.Add($sql); $n = [regex]::Match($sql, '^CREATE INDEX (\w+) ON').Groups[1].Value; $null = $db.Built.Add($n); 3.0 }.GetNewClosure()
            Rate        = { param($t, $s) }
        }
        $outcomes = for ($i = 0; $i -lt 10; $i++) {
            (Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = $db.Invoke }) -Holder 'caj-si-index-build:e1' -Request ([pscustomobject]@{ Table = ''; Index = ''; Minutes = 60; Force = $false }) -Seams $seams -Log { param($m) }).Outcome
        }
        @($outcomes) | Should -Be @(1..10 | ForEach-Object { 'built' })
        $sqls.Count | Should -Be 10
        foreach ($s in $sqls) { $s | Should -Match 'WITH \(ONLINE = ON, RESUMABLE = ON, MAX_DURATION = 60 MINUTES\)$' }
        $db.Built.Count | Should -Be 10
        @($db.Rows.Values | Where-Object { $_.State -eq 'built' }).Count | Should -Be 10
        # an eleventh start: nothing waits
        (Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = $db.Invoke }) -Holder 'caj-si-index-build:e2' -Request ([pscustomobject]@{ Table = ''; Index = ''; Minutes = 60; Force = $false }) -Seams $seams -Log { param($m) }).Outcome | Should -Be 'nothing'
        # the history phase: 0 missing, no "not there yet" line
        $lines = New-Object System.Collections.Generic.List[string]
        $sv = Invoke-SIDataHistoryServe -Invoke $db.Invoke -Mode 'on' -Log ({ param($l, $m) $lines.Add($m) }.GetNewClosure()) -Readers @()
        @($sv.IndexesMissing).Count | Should -Be 0
        ($lines -join "`n") | Should -Not -Match 'not there yet'
        (Read-SIHistoryIndexState -Invoke $db.Invoke).Missing.Count | Should -Be 0
        # the updater's next step queues nothing and says so
        $u = Invoke-SIHistoryIndexStep -Invoke $db.Invoke -Log { param($m) }
        @($u.Queued).Count | Should -Be 0
        ($u.Lines -join "`n") | Should -Match '10 of 10 there, 0 waiting for the index build job'
        $db.Creates.Count | Should -Be 0
    }
    It 'with the 10 missing the serve step still says why (the line the owner saw), and counts 10' {
        $db = New-Db
        $lines = New-Object System.Collections.Generic.List[string]
        $sv = Invoke-SIDataHistoryServe -Invoke $db.Invoke -Mode 'on' -Log ({ param($l, $m) $lines.Add($m) }.GetNewClosure()) -Readers @()
        @($sv.IndexesMissing).Count | Should -Be 10
        ($lines -join "`n") | Should -Match '\(10 of 10 not there yet\)'
    }
}
