#Requires -Version 5.1
<#
    WHERE THE IDENTITY COLLECTION'S TIME GOES IS MEASURED, NOT GUESSED (one ring-2 install: 13-19 hours every run; the
    producer's log said when a phase started, never how long it took or how long it waited for Microsoft). What this keeps
    true (engine\asset-profiling\shared\SI-IdentityPhaseTime.ps1 and its callers):
      1. LINE + ROW   each phase is said once as "[timing] identity: <phase> took <s> s (...)" AND written as one
                      cfg.StepPhaseTime row (Job 'identity', the phase, its seconds and rows) through the settings seam
      2. NEVER FAILS  a failing database write, a $null timer or a missing seam never throws -- the collection goes on
      3. PER PAGE     a phase that runs per page / per principal is added up and said ONCE (its calls counted)
      4. RETRIES      the Graph pager's retries (per HTTP status) and the seconds it waited are said once per source, then
                      started again; the sign-in methods read and the Exposure Graph read say the seconds they waited
      5. WIRING       both identity discoveries time every phase named below and say the totals and the retries
      6. NO DATA      measurement only: the users' sign-in methods verdicts are the same with the timers as before
    Offline: Graph and the database are fakes behind seams; no tenant is touched.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Info = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
    function script:Write-SIWarn { param($Message) }
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-IdentityPhaseTime.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\SI-AuthMethodsRead.ps1')
    function script:RowSeam {
        $script:Rows = New-Object System.Collections.Generic.List[object]
        { param($Sql, $Params, $Mode) $script:Rows.Add(@{ Sql = $Sql; Params = $Params; Mode = $Mode }) }
    }
}

AfterAll {
    $global:SI_IdentityPhaseInvoke = $null; $global:SI_IdentityPhaseInvokeTried = $null
    $global:SI_GraphRetryCount = $null; $global:SI_GraphRetrySleptSeconds = $null; $global:SI_IdentityPhaseTotals = $null
}

Describe 'one phase: a log line and a cfg.StepPhaseTime row' {
    BeforeEach { $script:Info.Clear(); $global:SI_IdentityPhaseInvoke = RowSeam }
    It 'the line names the phase, its seconds (one decimal, invariant), the rows and the detail' {
        Format-SIIdentityPhaseLine -Phase 'users: MFA registration' -Seconds 12.345 -Rows 1500 -Detail 'x' |
            Should -Be '[timing] identity: users: MFA registration took 12.3 s (1,500 rows; x)'
        Format-SIIdentityPhaseLine -Phase 'p' -Seconds 0 | Should -Be '[timing] identity: p took 0.0 s'
    }
    It 'Start / Stop: said once, and one row with Job identity, the phase, the seconds and the rows' {
        $t = Start-SIIdentityPhase -Phase 'users: Azure RBAC'
        $s = Stop-SIIdentityPhase $t -Rows 7
        $s | Should -BeGreaterOrEqual 0
        @($script:Info | Where-Object { $_ -like '`[timing`] identity: users: Azure RBAC took *' }).Count | Should -Be 1
        $script:Rows.Count | Should -Be 1
        $script:Rows[0].Sql | Should -Match 'INSERT cfg\.StepPhaseTime'
        $script:Rows[0].Params.Job | Should -Be 'identity'
        $script:Rows[0].Params.Phase | Should -Be 'users: Azure RBAC'
        $script:Rows[0].Params.Rows | Should -Be 7
        $script:Rows[0].Mode | Should -Be 'nonquery'
    }
    It 'NEVER FAILS: a database that refuses the row, a $null timer -- no throw, the line is still said' {
        $global:SI_IdentityPhaseInvoke = { param($Sql, $Params, $Mode) throw 'database gone' }
        { Stop-SIIdentityPhase (Start-SIIdentityPhase -Phase 'p') } | Should -Not -Throw
        { Stop-SIIdentityPhase $null } | Should -Not -Throw
        @($script:Info | Where-Object { $_ -like '*identity: p took*' }).Count | Should -Be 1
    }
    It 'no seam and no job execution: only the line (nothing opened)' {
        $global:SI_IdentityPhaseInvoke = $null; $global:SI_IdentityPhaseInvokeTried = $null
        $old = $env:CONTAINER_APP_JOB_EXECUTION_NAME; $env:CONTAINER_APP_JOB_EXECUTION_NAME = ''
        try { Get-SIIdentityPhaseInvoke | Should -BeNullOrEmpty; { Stop-SIIdentityPhase (Start-SIIdentityPhase -Phase 'q') } | Should -Not -Throw }
        finally { $env:CONTAINER_APP_JOB_EXECUTION_NAME = $old; $global:SI_IdentityPhaseInvokeTried = $null }
    }
}

Describe 'a phase run per page is added up and said once' {
    BeforeEach { $script:Info.Clear(); $global:SI_IdentityPhaseInvoke = RowSeam; Reset-SIIdentityPhaseTotals }
    It 'three pages -> one line and one row with the summed seconds, rows and calls; only the prefix asked for' {
        Add-SIIdentityPhaseTotal -Phase 'users: sign-in methods' -Seconds 1.5 -Rows 999 -Calls 1
        Add-SIIdentityPhaseTotal -Phase 'users: sign-in methods' -Seconds 2.5 -Rows 999 -Calls 1
        Add-SIIdentityPhaseTotal -Phase 'users: sign-in methods' -Seconds 1.0 -Rows 2 -Calls 1
        Add-SIIdentityPhaseTotal -Phase 'service principals: application permissions' -Seconds 9 -Rows 1 -Calls 1
        Write-SIIdentityPhaseTotals -Prefix 'users:'
        $script:Info | Should -Contain '[timing] identity: users: sign-in methods took 5.0 s (2,000 rows; 3 call(s), summed over the pages)'
        $script:Rows.Count | Should -Be 1
        $script:Rows[0].Params.Seconds | Should -Be 5.0
        $script:Rows[0].Params.Rows | Should -Be 2000
        # said once: a second call says nothing more for users, the other prefix is still there
        Write-SIIdentityPhaseTotals -Prefix 'users:'; $script:Rows.Count | Should -Be 1
        Write-SIIdentityPhaseTotals -Prefix 'service principals:'; $script:Rows.Count | Should -Be 2
    }
}

Describe 'the Graph retries and the time waited' {
    BeforeEach { $script:Info.Clear(); $global:SI_IdentityPhaseInvoke = RowSeam }
    It 'PURE: per status, the total, the seconds waited; nothing asked again = no line' {
        Format-SIGraphRetrySummary -Counts @{ HTTP429 = 40; HTTP503 = 2 } -SleptSeconds 312.04 |
            Should -Be '[timing] identity: Microsoft Graph was asked again 42 time(s) (HTTP 429 40, HTTP 503 2); 312.0 s waited before asking again'
        Format-SIGraphRetrySummary -Counts @{} -SleptSeconds 0 | Should -BeNullOrEmpty
        Format-SIGraphRetrySummary -Counts $null | Should -BeNullOrEmpty
    }
    It 'from the process counters: said once with its row, then started again (the next source says only its own)' {
        $global:SI_GraphRetryCount = @{ HTTP429 = 3 }; $global:SI_GraphRetrySleptSeconds = 14.0
        Write-SIGraphRetrySummary | Should -Match 'asked again 3 time'
        $script:Rows.Count | Should -Be 1
        $script:Rows[0].Params.Phase | Should -Be 'graph retries: waited'
        $script:Rows[0].Params.Seconds | Should -Be 14.0
        $script:Rows[0].Params.Rows | Should -Be 3
        Write-SIGraphRetrySummary | Should -BeNullOrEmpty
        $script:Rows.Count | Should -Be 1
    }
    It 'the pager counts every retry and the delay it waits (source: one counter per status + the seconds)' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1'))
        $src | Should -Match ([regex]::Escape('$global:SI_GraphRetryCount[$key] = 1 + [int]$global:SI_GraphRetryCount[$key]'))
        $src | Should -Match ([regex]::Escape('$global:SI_GraphRetrySleptSeconds = [double]$global:SI_GraphRetrySleptSeconds + [double]$delay'))
        # the Exposure Graph read says what it waited
        $src | Should -Match ([regex]::Escape('& $Sleep $d; $st.Slept = [double]$st.Slept + [double]$d'))
        $src | Should -Match 'SleptSeconds = \[double\]\$st\.Slept'
    }
}

Describe 'the sign-in methods read says the seconds it waited (the verdicts are unchanged)' {
    It 'one throttled wave: the Retry-After waited is counted and said in the pace line; the users read are the same' {
        Reset-SIEntraAuthMethodsState
        $users = @(1..45 | ForEach-Object { [pscustomobject]@{ id = ('u{0:D3}' -f $_); userType = 'Member'; userPrincipalName = ('u{0}@x.test' -f $_); onPremisesSyncEnabled = $false } })
        $script:Waves = 0
        $postMany = {
            param([string[]]$Bodies)
            $script:Waves++
            @(foreach ($b in $Bodies) {
                $req = (ConvertFrom-Json $b).requests
                if ($script:Waves -eq 1) { [pscustomobject]@{ Response = $null; Status = 429; RetryAfter = 7; Error = 'throttled' } }
                else { [pscustomobject]@{ Response = [pscustomobject]@{ responses = @($req | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ value = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethod' }) } } }) }; Status = 200; RetryAfter = $null; Error = '' } }
            })
        }
        $slept = New-Object System.Collections.Generic.List[double]
        $r = Get-SIEntraPasswordlessByUser -Token 't' -Users $users -PostMany $postMany -Sleep { param($s) $slept.Add([double]$s) }
        $r.Count | Should -Be 45
        @($r.Values | Where-Object { $_.PasswordlessOnly -eq $true }).Count | Should -Be 45
        $st = Get-SIEntraAuthMethodsState
        [double]$st.SleptSeconds | Should -Be ([double](($slept | Measure-Object -Sum).Sum))
        [double]$st.SleptSeconds | Should -BeGreaterThan 0
        Get-SIAuthMethodsPaceLine -State $st | Should -Match '; \d+\.\d s waited before asking again$'
    }
    It 'nothing waited: the pace line is exactly as before (no waited part)' {
        $st = [pscustomobject]@{ Requests = 3; MaxConcurrency = 2; ThrottledWaves = 0; SleptSeconds = 0.0 }
        Get-SIAuthMethodsPaceLine -State $st | Should -Be '[perms] sign-in methods: 3 request(s) of 20 users, up to 2 at once; Microsoft asked to slow down 0 time(s)'
    }
}

Describe 'WIRING: both identity discoveries time their phases and say the totals and the retries' {
    It '<File>: every named phase is started and stopped; the totals and the retry summary are said' -ForEach @(
        @{ File = 'Get-DiscoveryFromEntraUsers.ps1'; Prefix = 'users:'; Phases = @('users: Entra roles', 'users: MFA registration', 'users: role-holding groups', 'users: Azure RBAC', 'users: IdentityInfo', 'users: Exposure Graph identities', 'users: user pages', 'users: sign-in methods') }
        @{ File = 'Get-DiscoveryFromEntraServicePrincipals.ps1'; Prefix = 'service principals:'; Phases = @('service principals: Entra roles', 'service principals: role-holding groups', 'service principals: Azure RBAC', 'service principals: sign-in activity', 'service principals: Exposure Graph identities', 'service principals: owners', 'service principals: pages', 'service principals: application permissions') }
    ) {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot ('engine\asset-profiling\discovery\' + $File)))
        foreach ($p in $Phases) { $src | Should -Match ("Phase '" + [regex]::Escape($p)) }
        $starts = ([regex]::Matches($src, 'Start-SIIdentityPhase')).Count
        $stops = ([regex]::Matches($src, 'Stop-SIIdentityPhase')).Count
        $starts | Should -BeGreaterThan 4
        $stops | Should -Be $starts
        $src | Should -Match ("Write-SIIdentityPhaseTotals -Prefix '" + [regex]::Escape($Prefix) + "'")
        $src | Should -Match 'Write-SIGraphRetrySummary'
        $src | Should -Match 'Reset-SIIdentityPhaseTotals'
    }
    It 'the fetcher loads the timing helpers (every discovery that loads it can time)' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\shared\IdentityRoleFetcher.ps1')) | Should -Match ([regex]::Escape("'SI-IdentityPhaseTime.ps1'"))
    }
}
