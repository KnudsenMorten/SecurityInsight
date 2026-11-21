#Requires -Version 5.1
<#
    SecurityInsight -- ROLL-HUNG-1 (framework, Invardia 2026-11-20): A HUNG STEP NO LONGER HOLDS THE ROLL.
    What must hold:
      (a) a step of the awaited run that is Running > 10x its usual length AND >= 120 min AND wrote NO log line since its
          start (none of its own, while other executions' lines do reach the workspace, and no progress record) is STOPPED,
          the stop is read back, said in one WARNING line, raised as si.pipeline.step-hung, and the run gate is asked again;
      (b) a slow step that WRITES LOG LINES is never touched, however long it runs -- nor one that recorded progress, one
          inside its bound or under the 120-minute floor, one with no measured usual length, or one whose log lines or
          progress could not be read (silence that proves nothing);
      (c) the usual length is the median of the job's newest successful steps in other runs.
    Offline: every SQL / ARM / Log Analytics call is a seam; no sleep is real.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterHungStep.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ExecutionLiveness.ps1')
    $script:Now = [datetime]::new(2026, 11, 20, 12, 0, 0, [DateTimeKind]::Utc)
    # the awaited run R2: step asset-datasync running since -AgeMin; history: three successes of 10 / 12 / 30 min (median 12)
    function script:New-Rows([int]$AgeMin, [string]$Job = 'asset-datasync', [switch]$NoHistory) {
        $rows = @(@{ K = 'run'; FlowRunId = 'R2'; Job = $Job; State = 'Running'; Execution = 'caj-si-asset-datasync-abc12'; StartedUtc = $script:Now.AddMinutes(-$AgeMin); EndedUtc = [DBNull]::Value })
        if (-not $NoHistory) {
            $i = 0
            foreach ($m in 10, 12, 30) { $i++; $st = $script:Now.AddDays(-$i); $rows += @{ K = 'hist'; FlowRunId = "R0$i"; Job = $Job; State = 'Success'; Execution = "x$i"; StartedUtc = $st; EndedUtc = $st.AddMinutes($m) } }
        }
        $rows
    }
    # (the seams are plain script blocks, never closures: they read the $t* values of this function's scope, the scope the
    # check runs under; a closure would not see $script: of this file)
    function script:Invoke-Check($Rows, $Mine = 0, $Others = 50, $LogThrows = $false, $Progress = $null, $ProgressThrows = $false) {
        $script:stops = New-Object System.Collections.Generic.List[string]; $script:alerts = New-Object System.Collections.Generic.List[object]; $script:lines = New-Object System.Collections.Generic.List[string]
        $script:kqls = New-Object System.Collections.Generic.List[string]
        $tRows = $Rows; $tMine = $Mine; $tOthers = $Others; $tLogThrows = $LogThrows; $tProg = $Progress; $tProgThrows = $ProgressThrows
        Invoke-SIUpdaterHungStepCheck -RunId 'R2' -Sql { param($q, $p, $m) $tRows } `
            -LogQuery { param($kql) $script:kqls.Add($kql); if ($tLogThrows) { throw 'HTTP 403' }; @([pscustomobject]@{ Mine = $tMine; Others = $tOthers }) } `
            -Progress { param($k, $x, $s) if ($tProgThrows) { throw 'timeout' }; $tProg } `
            -Stop { param($k, $x) $script:stops.Add("$k/$x") } -ReadStatus { param($k, $x) 'Stopped' } `
            -Log { param($l, $m) $script:lines.Add("$l $m") } -Alert { param($ev) $script:alerts.Add($ev) } `
            -Sleep { param($s) } -Now { $script:Now }
    }
}

Describe 'ROLL-HUNG-1 (a): a silent step past its bound is stopped and the roll goes on' {
    It 'stops the one execution, reads it back, says it and raises si.pipeline.step-hung' {
        $r = Invoke-Check (New-Rows -AgeMin 333)
        @($r.Stopped).Count | Should -Be 1
        $script:stops | Should -Be @('asset-datasync/caj-si-asset-datasync-abc12')
        ($script:lines -join "`n") | Should -Match 'WARN the update stopped step asset-datasync \(execution caj-si-asset-datasync-abc12\) of run R2: it ran 333 min'
        $script:alerts.Count | Should -Be 1
        $script:alerts[0].Ended | Should -BeTrue
        $rec = ConvertTo-SIExecutionStoppedAlert -Event $script:alerts[0] -Context ([pscustomobject]@{ Mode = 'identified'; Version = '3.1.41' })
        $rec.AlertId | Should -Be 'si.pipeline.step-hung'
        # Invardia's catalog: Job = the execution kind (a step key is refused), the step in ActionText, Measured {ageMin, usualMin}
        $rec.Job | Should -Be 'flow'
        $rec.Severity | Should -Be 'warning'
        $rec.Area | Should -Be 'execution'
        @($rec.Measured.PSObject.Properties.Name) | Should -Be @('ageMin', 'usualMin')
        $rec.Measured.ageMin | Should -Be 333
        $rec.Measured.usualMin | Should -Be 12
        $rec.ActionText | Should -Match 'stopped step asset-datasync'
        $rec.ActionText | Should -Match 'wrote no log line since it started'
    }
    It 'the bound is max(10 x the median usual length, 120 min): 12 min usual -> 120 min' {
        (Invoke-Check (New-Rows -AgeMin 121)).Stopped.Count | Should -Be 1
        (Invoke-Check (New-Rows -AgeMin 119)).Stopped.Count | Should -Be 0
        $script:kqls.Count | Should -Be 0   # a step inside its bound is never asked about
    }
    It 'the log query asks for THIS execution since its start and counts other SecurityInsight lines' {
        $null = Invoke-Check (New-Rows -AgeMin 333)
        $script:kqls[0] | Should -Match "N startswith 'caj-si-asset-datasync-abc12'"
        $script:kqls[0] | Should -Match 'datetime\(2026-11-20T06:27:00Z\)'
        $script:kqls[0] | Should -Match "Others = countif\(not\(M\) and K == 'log' and N startswith 'caj-si-'\)"
    }
    It 'the run gate is asked again after the stop (the updater wiring)' {
        $f = Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\_shared\SI-UpdaterInvardia.ps1')
        $f | Should -Match "Invoke-SIUpdaterHungStepGate -Store \`$Store -RunId"
        $f | Should -Match 'run gate \(after the hung step was stopped\)'
        (Get-Content -Raw (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1')) | Should -Match "_shared/SI-UpdaterHungStep.ps1"
    }
}

Describe 'ROLL-HUNG-1 (b): a run that logs is never stopped' {
    It 'a slow step that writes log lines is untouched, however long it runs' {
        $r = Invoke-Check (New-Rows -AgeMin 3000) -Mine 4
        @($r.Stopped).Count | Should -Be 0
        $script:stops.Count | Should -Be 0
        ($r.Kept | Where-Object Key -eq 'asset-datasync').Why | Should -Match 'writes log lines'
    }
    It 'a step that recorded progress since its start is untouched' {
        (Invoke-Check (New-Rows -AgeMin 333) -Progress ($script:Now.AddMinutes(-200))).Stopped.Count | Should -Be 0
    }
    It 'silence that proves nothing is never a stop: no other lines reach the workspace, or the workspace / progress cannot be read' {
        (Invoke-Check (New-Rows -AgeMin 333) -Others 0).Stopped.Count | Should -Be 0
        (Invoke-Check (New-Rows -AgeMin 333) -LogThrows $true).Stopped.Count | Should -Be 0
        (Invoke-Check (New-Rows -AgeMin 333) -ProgressThrows $true).Stopped.Count | Should -Be 0
    }
    It 'a step with no measured usual length is never called hung' {
        $r = Invoke-Check (New-Rows -AgeMin 3000 -NoHistory)
        @($r.Stopped).Count | Should -Be 0
        ($r.Kept)[0].Why | Should -Match 'usual length is not known'
    }
    It 'a stop that fails leaves the wait as before (no alert)' {
        $tRows2 = New-Rows -AgeMin 333
        $script:alerts = New-Object System.Collections.Generic.List[object]; $script:lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIUpdaterHungStepCheck -RunId 'R2' -Sql { $tRows2 } -LogQuery { @([pscustomobject]@{ Mine = 0; Others = 9 }) } -Progress { $null } `
                -Stop { throw 'HTTP 403: AuthorizationFailed' } -Log { param($l, $m) $script:lines.Add($m) } -Alert { param($e) $script:alerts.Add($e) } -Sleep { } -Now { $script:Now }
        @($r.Stopped).Count | Should -Be 0
        $script:alerts.Count | Should -Be 0
        ($script:lines -join ' ') | Should -Match 'could not be stopped'
    }
    It 'the run''s steps that cannot be read stop nothing' {
        $r = Invoke-SIUpdaterHungStepCheck -RunId 'R2' -Sql { throw 'login failed' } -Stop { throw 'never' } -Now { $script:Now }
        @($r.Stopped).Count | Should -Be 0
        $r.Why | Should -Match 'could not be read'
    }
}

Describe 'ROLL-HUNG-1 (c): the usual length' {
    It 'is the median of the newest successful steps of other runs' {
        $u = Get-SIUpdaterUsualStepMinutes -Steps @(
            [pscustomobject]@{ FlowRunId = 'A'; Job = 'caj-si-identity'; State = 'Success'; StartedUtc = $script:Now.AddDays(-3); EndedUtc = $script:Now.AddDays(-3).AddMinutes(10) }
            [pscustomobject]@{ FlowRunId = 'B'; Job = 'identity'; State = 'Success'; StartedUtc = $script:Now.AddDays(-2); EndedUtc = $script:Now.AddDays(-2).AddMinutes(40) }
            [pscustomobject]@{ FlowRunId = 'C'; Job = 'identity'; State = 'Failed'; StartedUtc = $script:Now.AddDays(-1); EndedUtc = $script:Now.AddDays(-1).AddMinutes(900) }
            [pscustomobject]@{ FlowRunId = 'R2'; Job = 'identity'; State = 'Success'; StartedUtc = $script:Now; EndedUtc = $script:Now.AddMinutes(999) }) -ExcludeRunId 'R2'
        $u['identity'] | Should -Be 25
    }
}
