#Requires -Version 7.0
<#
    #1335 THE DATABASE TIER SIZED PER INSTALL FROM ITS OWN LOAD (SCALE-3 #1330 track D) -- the rule, its wire shape, its switch.

    What these tests keep true:
      * the capacity of a tier: DTU as it is, a vCore = 100 DTU (Business Critical 125) -- Microsoft's guidance;
      * the rule: the busy minutes' 95th percentile grown by the share at the limit, at 80 % of the new tier, the smallest step
        of Azure's ladder that covers it (Standard -> vCore General Purpose -> Hyperscale), the large-install floor (S4), never
        a step down while a minute was at the limit, keep when nothing was busy; the dimension it is bound by;
      * the wire: exactly the agreed keys and value kinds, checked before it goes out; the Database section accepts it as its
        LAST key only; the switch is OFF (Invardia's contract is closed until it accepts the key) and SecurityInsight never
        changes a tier (no write to ARM anywhere in the rule's file).
    Offline, pure. PS 7.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-HeartbeatFields.ps1')
    $script:Src = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\SI-DatabaseTierAdvice.ps1'))
    # minutes: -Busy minutes at -Load % (data IO), of them -AtLimit at 100 %, the rest of the day idle at 3 %
    function script:New-Day([int]$Busy, [int]$AtLimit, [double]$Load = 70, [string]$Dim = 'DataIo') {
        $out = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt 1440; $i++) {
            $v = if ($i -lt $AtLimit) { 100.0 } elseif ($i -lt $Busy) { $Load } else { 3.0 }
            $m = [ordered]@{ DataIo = 5.0; Log = 5.0; Cpu = 5.0; Dtu = $null }
            $m[$Dim] = $v
            $out.Add([pscustomobject]$m)
        }
        , $out.ToArray()
    }
}

Describe 'the capacity of a tier' {
    It 'DTU as it is; a vCore = 100 DTU, Business Critical 125; unknown = none' {
        Get-SIDbTierCapacity -ServiceObjective 'S3' -Edition 'Standard' | Should -Be 100
        Get-SIDbTierCapacity -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 | Should -Be 100
        Get-SIDbTierCapacity -ServiceObjective 'P1' -Edition 'Premium' -Capacity 125 | Should -Be 125
        Get-SIDbTierCapacity -ServiceObjective 'GP_Gen5_8' -Edition 'GeneralPurpose' | Should -Be 800
        Get-SIDbTierCapacity -ServiceObjective 'BC_Gen5_4' -Edition 'BusinessCritical' | Should -Be 500
        Get-SIDbTierCapacity -ServiceObjective 'HS_Gen5_80' -Edition 'Hyperscale' | Should -Be 8000
        Get-SIDbTierCapacity -ServiceObjective 'GP_S_Gen5_2' -Edition 'GeneralPurpose' -Capacity 2 | Should -Be 200
        Get-SIDbTierCapacity -ServiceObjective '' -Edition '' | Should -BeNullOrEmpty
    }
}

Describe 'the rule' {
    It 'a database at its limit for half of the run (the S3 of a mid-size install): one step up, bound by data IO' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 600 -AtLimit 300) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        # p95 100 x (1 + 300/600) = 1.5 -> 100 x 1.5 / 0.8 = 188 DTU -> S4
        $a.capacityNeeded | Should -Be 188
        $a.recommended | Should -Be 'S4'
        $a.change | Should -Be 'up'
        $a.boundBy | Should -Be 'data-io'
        $a.minutesAtLimit24h | Should -Be 300
        $a.busyMinutes24h | Should -Be 600
        $a.p95LoadPct | Should -Be 100
    }
    It 'a large install at its limit most of the day: as many steps as the measurement says (no cap)' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 1400 -AtLimit 900 -Dim 'Log') -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        $a.capacityNeeded | Should -Be ([long][Math]::Ceiling(100 * (1 + 900 / 1400.0) / 0.8))
        $a.recommended | Should -Be 'S6'
        $a.boundBy | Should -Be 'log'
        # the largest: past Standard to vCore, then Hyperscale
        (Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 1440 -AtLimit 1440) -ServiceObjective 'S12' -Edition 'Standard' -Capacity 3000).recommended | Should -Be 'GP_Gen5_80'
        (Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 1440 -AtLimit 1440) -ServiceObjective 'GP_Gen5_80' -Edition 'GeneralPurpose').recommended | Should -Be 'HS_Gen5_128'
    }
    It 'a lightly loaded database: a step down -- but never while a minute was at the limit' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 300 -AtLimit 0 -Load 30) -ServiceObjective 'S4' -Edition 'Standard' -Capacity 200
        $a.capacityNeeded | Should -Be 75
        $a.recommended | Should -Be 'S3'
        $a.change | Should -Be 'down'
        $b = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 300 -AtLimit 2 -Load 30) -ServiceObjective 'S4' -Edition 'Standard' -Capacity 200
        $b.change | Should -Be 'keep'
        $b.recommended | Should -Be 'S4'
    }
    It 'the floor: a large install (its largest table 1 million rows or more) never below S4; a floor by name' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 200 -AtLimit 0 -Load 30) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 -LargestTableRows 1450000
        $a.recommended | Should -Be 'S4'
        $a.change | Should -Be 'up'
        (Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 200 -AtLimit 0 -Load 30) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 -LargestTableRows 90000).recommended | Should -Be 'S2'
        (Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 200 -AtLimit 0 -Load 30) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 -Floor 'S6').recommended | Should -Be 'S6'
    }
    It 'nothing busy: keep the tier, the day''s own load and bound sent; nothing measured, only DTU or a capacity that cannot be told: no recommendation' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 0 -AtLimit 0) -ServiceObjective 'P1' -Edition 'Premium' -Capacity 125
        $a.change | Should -Be 'keep'
        $a.recommended | Should -Be 'P1'
        $a.busyMinutes24h | Should -Be 0
        $a.p95LoadPct | Should -Be 5
        $a.boundBy | Should -Be 'log'
        Test-SIDbTierAdvice -Value $a | Should -Be ''
        Get-SIDatabaseTierAdvice -Minutes @() -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 | Should -BeNullOrEmpty
        Get-SIDatabaseTierAdvice -Minutes @([pscustomobject]@{ DataIo = $null; Log = $null; Cpu = $null; Dtu = 80.0 }) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100 | Should -BeNullOrEmpty
        Get-SIDatabaseTierAdvice -Minutes @() -ServiceObjective '' -Edition '' | Should -BeNullOrEmpty
    }
    It 'reads Azure Monitor''s answer per minute (Maximum), every metric of the read' {
        $mk = { param($n, $vals) [pscustomobject]@{ name = [pscustomobject]@{ value = $n }; timeseries = @([pscustomobject]@{ data = @(for ($i = 0; $i -lt $vals.Count; $i++) { [pscustomobject]@{ timeStamp = ('2026-11-23T01:{0:00}:00Z' -f $i); maximum = $vals[$i] } }) }) } }
        $ans = [pscustomobject]@{ value = @((& $mk 'physical_data_read_percent' @(100, 50, $null)), (& $mk 'log_write_percent' @(10, 90, 5)), (& $mk 'cpu_percent' @(1, 2, 3))) }
        $m = ConvertFrom-SIDbTierMetrics -Metrics $ans
        $m.Count | Should -Be 3
        $m[0].DataIo | Should -Be 100; $m[1].Log | Should -Be 90; $m[2].DataIo | Should -BeNullOrEmpty; $m[2].Cpu | Should -Be 3
        $a = Get-SIDatabaseTierAdvice -Minutes $m -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        $a.busyMinutes24h | Should -Be 2
        $a.minutesAtLimit24h | Should -Be 1
        (Get-SIDbTierAdviceMetricsPath -Id '/subscriptions/x/db') | Should -Match 'timespan=P1D&interval=PT1M&aggregation=Maximum'
        (Get-SIDbTierAdviceMetricsPath -Id '/subscriptions/x/db') | Should -Match 'physical_data_read_percent'
    }
}

Describe 'the wire, the switch, no change by SecurityInsight' {
    It 'a 24-hour read of 1,441 minutes counts at most 1,440 (Invardia''s range); every key is always set' {
        $d0 = New-Day -Busy 1440 -AtLimit 1440; $day = @($d0) + @([pscustomobject]@{ DataIo = 100.0; Log = 5.0; Cpu = 5.0; Dtu = $null })
        $a = Get-SIDatabaseTierAdvice -Minutes $day -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        $a.busyMinutes24h | Should -Be 1440
        $a.minutesAtLimit24h | Should -Be 1440
        foreach ($n in 'capacityNow', 'capacityNeeded', 'p95LoadPct', 'minutesAtLimit24h', 'busyMinutes24h') { $a.$n | Should -BeOfType [long] -Because $n }
        (($a | ConvertTo-Json -Compress)) | Should -Match '"p95LoadPct":100,'
        $n2 = $a.PSObject.Copy(); $n2.boundBy = $null; Test-SIDbTierAdvice -Value $n2 | Should -Match 'boundBy'
        $n3 = $a.PSObject.Copy(); $n3.p95LoadPct = $null; Test-SIDbTierAdvice -Value $n3 | Should -Match 'p95LoadPct'
        $n4 = $a.PSObject.Copy(); $n4.busyMinutes24h = 1441L; Test-SIDbTierAdvice -Value $n4 | Should -Match 'minutes'
    }
    It 'the object passes its own check; a key more, a wrong kind or a value off the lists does not' {
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 600 -AtLimit 300) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        Test-SIDbTierAdvice -Value $a | Should -Be ''
        (@($a.PSObject.Properties.Name) -join ',') | Should -Be 'recommended,capacityNow,capacityNeeded,p95LoadPct,minutesAtLimit24h,busyMinutes24h,boundBy,change'
        $x = [pscustomobject]([ordered]@{ recommended = 'S4'; capacityNow = 100L; capacityNeeded = 188L; p95LoadPct = 100L; minutesAtLimit24h = 300L; busyMinutes24h = 600L; boundBy = 'data-io'; change = 'sideways' })
        Test-SIDbTierAdvice -Value $x | Should -Match 'change'
        $y = $a.PSObject.Copy(); $y | Add-Member -NotePropertyName note -NotePropertyValue 'free text'
        Test-SIDbTierAdvice -Value $y | Should -Match 'keys'
        $z = $a.PSObject.Copy(); $z.recommended = 'S4; DROP'
        Test-SIDbTierAdvice -Value $z | Should -Match 'tier name'
    }
    It 'Database takes it as its LAST key only, checked; the switch is ON (Invardia accepted the key)' {
        $c = Get-SIHeartbeatFieldsContract
        $c.DatabaseSendTierAdvice | Should -BeTrue -Because 'Invardia accepted the key (ee2e9fab)'
        $c.DatabaseTierAdviceField | Should -Be 'tierAdvice'
        $a = Get-SIDatabaseTierAdvice -Minutes (New-Day -Busy 600 -AtLimit 300) -ServiceObjective 'S3' -Edition 'Standard' -Capacity 100
        $db = [ordered]@{ tier = 'Standard'; dtu = 100L; maxSizeMb = 256000L; usedMb = 44000L; peakLogWritePct1h = 40L; minutesAtLimit1h = 3L }
        $o1 = [ordered]@{}; foreach ($k in $db.Keys) { $o1[$k] = $db[$k] }; $o1['tierAdvice'] = $a; $ok = [pscustomobject]$o1
        Test-SIHeartbeatField -Name 'Database' -Value $ok | Should -Be ''
        $bad = $a.PSObject.Copy(); $bad.change = 'x'
        $o2 = [ordered]@{}; foreach ($k in $db.Keys) { $o2[$k] = $db[$k] }; $o2['tierAdvice'] = $bad; Test-SIHeartbeatField -Name 'Database' -Value ([pscustomobject]$o2) | Should -Match 'tierAdvice'
        # without it, Database is exactly as before
        Test-SIHeartbeatField -Name 'Database' -Value ([pscustomobject]$db) | Should -Be ''
        $hb = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\SI-HeartbeatFields.ps1'))
        $hb | Should -Match 'if \(\$null -eq \$dbv -or -not \$c\.DatabaseSendTierAdvice'
    }
    It 'SecurityInsight never changes a tier: the rule''s file reads only' {
        $script:Src | Should -Not -Match '(?i)-Method\s+(Put|Patch|Post|Delete)'
        $script:Src | Should -Not -Match '(?i)Invoke-RestMethod|Invoke-WebRequest'
        $script:Src | Should -Not -Match '(?i)sku\s*='
    }
}
