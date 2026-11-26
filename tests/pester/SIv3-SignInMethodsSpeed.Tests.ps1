#Requires -Version 5.1
<#
    THE BACKGROUND SIGN-IN METHODS READ, AS FAST AS MICROSOFT ALLOWS (REQUIREMENTS #1144 P2-P4, SCALE-3 #1330;
    engine\asset-profiling\shared\SI-AuthMethodsRead.ps1 + SI-SignInMethodsChoice.ps1).

    What these keep true:
      * THE RAMP       the background read doubles the requests in flight after each clean wave until Microsoft first asks to
                       slow down; then +1 per clean wave and half per throttled one (as before); the collection-side default
                       (no -Doubling) is unchanged (+1)
      * NEAR THE LIMIT Microsoft's x-ms-throttle-limit-percentage above 0.8 (on the $batch request or on one of its answers)
                       holds the pace -- no more requests next wave; counted and said
      * THE PACE       a tick starts at the pace the last tick ended on (kept in the claim row, at most 48 hours old; else
                       one request, doubling); the release hands the pace it ended on to the next tick
      * THE SLICE      the default slice is adaptive: 12 minutes while users are due (never read / report entry changed),
                       8 once only the periodic refresh is left; an install's own slice is fixed
      * SAME FIELDS    the users read with the new ramp give exactly the same results as with the old one; a user not read
                       is not saved (unknown, never no)
      * WIRING         the job's read passes the start pace and doubling
    Offline (Graph and SQL are fakes). PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    $script:Info = New-Object System.Collections.Generic.List[string]
    function script:Write-SIInfo { param($Message) $script:Info.Add([string]$Message) }
    function script:Write-SIWarn { param($Message) $script:Info.Add([string]$Message) }
    . (Join-Path $script:Shared 'SI-AuthMethodsRead.ps1')
    . (Join-Path $script:Shared 'SI-SignInMethodsChoice.ps1')

    function script:Users([int]$N) { @(1..$N | ForEach-Object { [pscustomobject]@{ id = ('u{0:D4}' -f $_); userPrincipalName = "u$_@contoso.test"; userType = 'Member' } }) }
    # the fake $batch endpoint, one wave at a time: -NearLimitWaves: waves whose answers say the tenant is at 0.9 of its
    # limit; -ThrottleWaves: waves answered 429 (Retry-After 3)
    $script:Widths = New-Object System.Collections.Generic.List[int]
    $script:NearLimitWaves = @(); $script:ThrottleWaves = @(); $script:Waves = 0
    $script:PostMany = {
        param([string[]]$Bodies)
        $script:Waves++
        $script:Widths.Add(@($Bodies).Count)
        $near = $script:NearLimitWaves -contains $script:Waves
        $thr = $script:ThrottleWaves -contains $script:Waves
        , @(foreach ($b in $Bodies) {
            if ($thr) { [pscustomobject]@{ Response = $null; Status = 429; RetryAfter = 3; Error = 'Too Many Requests'; ThrottlePercent = $null }; continue }
            $reqs = @(($b | ConvertFrom-Json).requests)
            [pscustomobject]@{ Status = 200; RetryAfter = $null; Error = ''; ThrottlePercent = $(if ($near) { 0.9 } else { $null })
                Response = [pscustomobject]@{ responses = @(foreach ($r in $reqs) { [pscustomobject]@{ id = [string]$r.id; status = 200; headers = $null
                    body = [pscustomobject]@{ value = @(
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'; id = '28c10230-6103-485e-b985-444c60001490' }
                        [pscustomobject]@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; id = ('p-' + ([string]$r.url -replace '\D', '')); phoneNumber = '+45 20000000'; phoneType = 'mobile' }
                    ) } } }) } }
        })
    }
    $script:Sleeps = New-Object System.Collections.Generic.List[int]
    $script:Sleep = { param($Seconds) $script:Sleeps.Add([int]$Seconds) }
    function script:Reset-Fake { $script:Widths.Clear(); $script:Sleeps.Clear(); $script:Waves = 0; $script:NearLimitWaves = @(); $script:ThrottleWaves = @(); Reset-SIEntraAuthMethodsState }
    function script:Snap($Map) { $o = [ordered]@{}; foreach ($k in @($Map.Keys | Sort-Object)) { $o[$k] = $Map[$k] }; ConvertTo-Json -InputObject $o -Depth 12 -Compress }
}

AfterAll { $global:SIRecordCaptureState = $null }

Describe 'the ramp: double until Microsoft first asks to slow down, then +1 / half' {
    It 'doubling: 1 -> 2 -> 4 -> 8; a throttled wave halves it and ends doubling for good; then +1' {
        $st = [pscustomobject]@{ Concurrency = 1; ThrottledWaves = 0; Doubling = $true; HeldWaves = 0 }
        (1..3 | ForEach-Object { Update-SIAuthMethodConcurrency -State $st -Throttled $false }) | Should -Be @(2, 4, 8)
        Update-SIAuthMethodConcurrency -State $st -Throttled $true | Should -Be 4
        $st.Doubling | Should -BeFalse
        Update-SIAuthMethodConcurrency -State $st -Throttled $false | Should -Be 5
    }
    It 'near the limit: the pace holds (counted); without doubling the old +1 stays' {
        $st = [pscustomobject]@{ Concurrency = 6; ThrottledWaves = 0; Doubling = $true; HeldWaves = 0 }
        Update-SIAuthMethodConcurrency -State $st -Throttled $false -Hold $true | Should -Be 6
        $st.HeldWaves | Should -Be 1
        $st.Doubling | Should -BeTrue -Because 'holding is not a throttle'
        $old = [pscustomobject]@{ Concurrency = 1; ThrottledWaves = 0 }
        Update-SIAuthMethodConcurrency -State $old -Throttled $false | Should -Be 2
        Update-SIAuthMethodConcurrency -State $old -Throttled $false | Should -Be 3
    }
    It 'Microsoft''s limit header: read as a fraction (a percent too); on the request or on one of its answers' {
        ConvertTo-SIAuthMethodThrottlePercent '0.85' | Should -Be 0.85
        ConvertTo-SIAuthMethodThrottlePercent '85' | Should -Be 0.85
        ConvertTo-SIAuthMethodThrottlePercent 'x' | Should -BeNullOrEmpty
        Test-SIAuthMethodWaveNearLimit -Outcomes @([pscustomobject]@{ ThrottlePercent = 0.9; Response = $null }) | Should -BeTrue
        $item = [pscustomobject]@{ id = '1'; status = 200; headers = [pscustomobject]@{ 'x-ms-throttle-limit-percentage' = '0.95' } }
        Test-SIAuthMethodWaveNearLimit -Outcomes @([pscustomobject]@{ ThrottlePercent = $null; Response = [pscustomobject]@{ responses = @($item) } }) | Should -BeTrue
        Test-SIAuthMethodWaveNearLimit -Outcomes @([pscustomobject]@{ ThrottlePercent = 0.5; Response = $null }, $null) | Should -BeFalse
    }
}

Describe 'the read: starts at the last pace, doubles, holds near the limit -- the same fields' {
    BeforeEach { Reset-Fake }
    It 'the old read (+1 from one): 400 users = 20 requests in waves of 1, 2, 3, 4, 5, 5' {
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 400) -PostMany $script:PostMany -Sleep $script:Sleep
        @($script:Widths) | Should -Be @(1, 2, 3, 4, 5, 5)
    }
    It 'doubling from the last pace (4): 400 users in waves of 4, 8, 8 -- three waves instead of six' {
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 400) -PostMany $script:PostMany -Sleep $script:Sleep -StartConcurrency 4 -Doubling
        @($script:Widths) | Should -Be @(4, 8, 8)
        $st = Get-SIEntraAuthMethodsState
        ($st.StartConcurrency, $st.MaxConcurrency, $st.Requests, $st.Complete) | Should -Be @(4, 8, 20, $true)
        (Get-SIAuthMethodsPaceLine -State $st) | Should -Match 'started at 4 at once \(where the last run ended\)'
    }
    It 'near the limit on every wave: the pace holds at its start, said in the pace line' {
        $script:NearLimitWaves = 1..20
        $null = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 400) -PostMany $script:PostMany -Sleep $script:Sleep -StartConcurrency 4 -Doubling
        @($script:Widths) | Should -Be @(4, 4, 4, 4, 4)
        $st = Get-SIEntraAuthMethodsState
        $st.HeldWaves | Should -Be 5
        (Get-SIAuthMethodsPaceLine -State $st) | Should -Match 'held its pace 5 time\(s\) near Microsoft''s limit'
    }
    It 'a throttled wave: halved, its Retry-After waited once, doubling ends; every user still read' {
        $script:ThrottleWaves = @(2)
        $map = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 400) -PostMany $script:PostMany -Sleep $script:Sleep -StartConcurrency 4 -Doubling
        @($script:Widths)[0..2] | Should -Be @(4, 8, 4)
        @($script:Sleeps | Where-Object { $_ -eq 3 }).Count | Should -Be 1
        (Get-SIEntraAuthMethodsState).Doubling | Should -BeFalse
        $map.Count | Should -Be 400
    }
    It 'SAME FIELDS: every user read with the new ramp has exactly the result of the old read' {
        $old = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 250) -PostMany $script:PostMany -Sleep $script:Sleep
        Reset-Fake
        $new = Get-SIEntraPasswordlessByUser -Token 't' -Users (Users 250) -PostMany $script:PostMany -Sleep $script:Sleep -StartConcurrency 6 -Doubling
        $new.Count | Should -Be 250
        (Snap $new) | Should -BeExactly (Snap $old)
    }
}

Describe 'the pace from tick to tick (the claim row)' {
    It 'the release value carries the pace; the next claim reads it back' {
        $t = [datetime]::SpecifyKind([datetime]'2026-11-23T10:00:00', [DateTimeKind]::Utc)
        $v = New-SISignInMethodsClaimValue -By 'a' -NowUtc $t -UntilUtc $t.AddMinutes(12) -Pace ([pscustomobject]@{ Concurrency = 7; Doubling = $false })
        $v.Length | Should -BeLessThan 400
        $p = ConvertFrom-SISignInMethodsPace -Previous $v -NowUtc $t.AddMinutes(15)
        ($p.Concurrency, $p.Doubling, $p.FromLastRun) | Should -Be @(7, $false, $true)
    }
    It 'no pace, a value that does not read, or one older than 48 hours: one request, doubling' {
        $t = [datetime]::SpecifyKind([datetime]'2026-11-23T10:00:00', [DateTimeKind]::Utc)
        foreach ($prev in @($null, '', 'not json', (New-SISignInMethodsClaimValue -By 'a' -NowUtc $t -UntilUtc $t))) {
            $p = ConvertFrom-SISignInMethodsPace -Previous $prev -NowUtc $t
            ($p.Concurrency, $p.Doubling, $p.FromLastRun) | Should -Be @(1, $true, $false)
        }
        $old = New-SISignInMethodsClaimValue -By 'a' -NowUtc $t -UntilUtc $t -Pace ([pscustomobject]@{ Concurrency = 9; Doubling = $false })
        (ConvertFrom-SISignInMethodsPace -Previous $old -NowUtc $t.AddHours(49)).Concurrency | Should -Be 1
    }
    It 'the end pace comes from the read''s own state' {
        $e = Get-SISignInMethodsEndPace -State ([pscustomobject]@{ Concurrency = 12; Doubling = $true })
        ($e.Concurrency, $e.Doubling) | Should -Be @(12, $true)
        Get-SISignInMethodsEndPace -State $null | Should -BeNullOrEmpty
    }
}

Describe 'the tick: the adaptive slice, the pace handed on, unread users never saved' {
    BeforeEach {
        $script:Reason = 'never'
        $script:Saved = @{}
        $script:Released = ''
        $script:SeenStart = $null
        $script:Prev = $null
        $script:N = 0
        $script:Data = { param($Sql, $Params, $Mode)
            if ($Sql -match 'UPDATE due SET LastTryAt') {
                $take = @(1..[int]$Params.n | ForEach-Object { $script:N++; ('u{0:D5}' -f $script:N) })
                return @($take | ForEach-Object { [pscustomobject]@{ UserId = $_; CurrentStamp = 's'; CurrentHash = 'h'; Privileged = 0; Reason = $script:Reason } })
            }
            if ($Sql -match 'MERGE sidata.UserSignInMethodsDetail') { foreach ($r in @([string]$Params.rows | ConvertFrom-Json)) { $script:Saved[[string]$r.UserId] = $r }; return @([pscustomobject]@{ Written = 1 }) }
        }
        $script:Pro = { param($Sql, $Params, $Mode)
            if ($Sql -match 'AS Claimed') { return @([pscustomobject]@{ Claimed = 1; Previous = $script:Prev }) }
            if ($Sql -match 'AS Released') { $script:Released = [string]$Params.Value; return @([pscustomobject]@{ Released = 1 }) }
        }
        $script:Read = { param($Users)
            if ($null -eq $script:SeenStart) { $script:SeenStart = Get-SISignInMethodsStartPace }
            $script:_SICache['AuthMethodsState'] = [pscustomobject]@{ Concurrency = 11; Doubling = $false; Refused = $false }
            $h = @{}; foreach ($u in $Users) { $h[[string]$u.id] = [pscustomobject]@{ ReadComplete = $true; Methods = @(); DevicesRead = $true } }; $h }
        $script:T0 = [datetime]::SpecifyKind([datetime]'2026-11-23T10:00:00', [DateTimeKind]::Utc)
        $script:Tick = @{ Now = $script:T0 }
        $script:Clock = { $script:Tick.Now = $script:Tick.Now.AddSeconds(30); $script:Tick.Now }
    }
    It 'users due (never read): the default slice grows to 12 minutes, said in the line' {
        $r = Invoke-SISignInMethodsFill -Choice (Get-SISignInMethodsChoice -Values @{}) -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $script:Read -BatchSize 10 -Clock $script:Clock -IsRefused { $false }
        ($r.Status, $r.SliceSeconds) | Should -Be @('budget', 720)
        $r.Line | Should -Match 'the 12-minute slice is used \(the longer slice: users are due\); the next tick carries on'
    }
    It 'users changed since their read: the longer slice too' {
        $script:Reason = 'changed'
        (Invoke-SISignInMethodsFill -Choice (Get-SISignInMethodsChoice -Values @{}) -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $script:Read -BatchSize 10 -Clock $script:Clock -IsRefused { $false }).SliceSeconds | Should -Be 720
    }
    It 'only the periodic refresh is left: the default 8 minutes' {
        $script:Reason = 'maxage'
        $r = Invoke-SISignInMethodsFill -Choice (Get-SISignInMethodsChoice -Values @{}) -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $script:Read -BatchSize 10 -Clock $script:Clock -IsRefused { $false }
        ($r.Status, $r.SliceSeconds) | Should -Be @('budget', 480)
        $r.Line | Should -Not -Match 'longer slice'
    }
    It 'an install''s own slice (5 minutes) is used always, users due or not' {
        $c = Get-SISignInMethodsChoice -Values @{ SI_Identity_SignInMethodsFillMinutes = 5 }
        $c.FillAdaptive | Should -BeFalse
        (Invoke-SISignInMethodsFill -Choice $c -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $script:Read -BatchSize 10 -Clock $script:Clock -IsRefused { $false }).SliceSeconds | Should -Be 300
        (Get-SISignInMethodsChoice -Values @{}).FillAdaptive | Should -BeTrue
    }
    It 'the read starts at the pace the last tick ended on; the release hands on the pace this tick ended on' {
        $script:Prev = New-SISignInMethodsClaimValue -By 'x' -NowUtc $script:T0.AddMinutes(-15) -UntilUtc $script:T0.AddMinutes(-3) -Pace ([pscustomobject]@{ Concurrency = 6; Doubling = $false })
        $r = Invoke-SISignInMethodsFill -Choice (Get-SISignInMethodsChoice -Values @{}) -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $script:Read -BatchSize 10 -Clock $script:Clock -IsRefused { $false }
        ($script:SeenStart.Concurrency, $script:SeenStart.Doubling) | Should -Be @(6, $false)
        ($r.StartConcurrency, $r.EndConcurrency) | Should -Be @(6, 11)
        $p = ($script:Released | ConvertFrom-Json).pace
        ([int]$p.concurrency, [bool]$p.doubling) | Should -Be @(11, $false)
        $script:_SICache.ContainsKey('SignInMethodsStartPace') | Should -BeFalse -Because 'the start pace is the tick''s own'
    }
    It 'users Microsoft did not answer are not saved: unknown, never no' {
        $none = { param($Users) @{} }
        $r = Invoke-SISignInMethodsFill -Choice (Get-SISignInMethodsChoice -Values @{}) -DataInvoke $script:Data -ProInvoke $script:Pro -ReadUsers $none -BudgetSeconds 60 -BatchSize 10 -Clock $script:Clock -IsRefused { $false }
        $r.Read | Should -Be 0
        $r.Unread | Should -BeGreaterThan 0
        $script:Saved.Count | Should -Be 0
    }
}

Describe 'wiring: the job''s read passes the start pace and doubling' {
    It 'Invoke-SISignInMethodsFillTick reads with -StartConcurrency and -Doubling from the tick''s start pace' {
        $t = [IO.File]::ReadAllText((Join-Path $script:Shared 'SI-SignInMethodsChoice.ps1'))
        $t | Should -Match ([regex]::Escape('$sp = Get-SISignInMethodsStartPace; Get-SIEntraPasswordlessByUser -Token $siSignInGraphToken -Users $Users -ReadDevices -MaxRounds 3 -MaxDelaySeconds 30 -StartConcurrency ([int]$sp.Concurrency) -Doubling:([bool]$sp.Doubling)'))
        $t | Should -Match ([regex]::Escape('SELECT @ok AS Claimed, @cur AS Previous;'))
        $a = [IO.File]::ReadAllText((Join-Path $script:Shared 'SI-AuthMethodsRead.ps1'))
        $a | Should -Match ([regex]::Escape("TryGetValues('x-ms-throttle-limit-percentage'"))
        $a | Should -Match ([regex]::Escape('-Hold (Test-SIAuthMethodWaveNearLimit -Outcomes $outcomes)'))
    }
}
