#Requires -Version 5.1
<#
    #1107 (live 2026-11-04, a large private install: 8 attack-path reports lost because the CI lookup _ciPeer was refused by
    Log Analytics with E_LOW_MEMORY_CONDITION, in 1 part and in 2; read whole in 6 s an hour later):
      * a part refused for the SERVICE's low memory is asked again after a wait (30 / 60 / 120 s) before it counts;
      * a CI block is cut at its SOURCE (each part keeps its share of the CIs right after the core's anchor), a key two CIs
        share in different parts is kept once; any other query keeps the result cut, as before;
      * a source cut stops only after four empty refusals in a row (a result cut after two, as before).
    Proven live read-only (docs\TESTS.md): internal 11,135 rows whole = 11,135 in 4 source parts; the install 25,998 whole.
    Offline (a fake reader); PS 5.1 and 7. The fakes keep their state in SCRIPT scope and are plain blocks (no
    GetNewClosure: a closure does not see this file's functions).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'risk-analysis', '_shared', 'RA-CiKql.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'risk-analysis', '_shared', 'RA-LaPartedRead.ps1'))
    function script:Write-Info { param($m) }
    function script:Refusal([string]$Text = 'Query execution has exceeded the allowed limits', [long]$Rows = 0) {
        $ex = New-Object System.InvalidOperationException("Log Analytics returned a PARTIAL answer (x: $Text) -- Query execution has exceeded the allowed limits")
        $ex.Data['SIRALaPartial'] = 'Limit'; $ex.Data['SIRALaPartialRows'] = $Rows; $ex
    }
    $script:Peer = ((Get-RACiKqlBlock -Kind peer) -split "`r?`n" | Where-Object { $_ -notmatch '^//__' }) -join "`n"
    $script:Waits = New-Object System.Collections.Generic.List[int]
    $script:Seen = New-Object System.Collections.Generic.List[string]
    $script:Calls = 0
    $script:SleepRec = { param($s) $script:Waits.Add([int]$s) }
}

Describe 'the service''s own low memory is waited out, not called too large' {
    BeforeEach { $script:Waits.Clear(); $script:Calls = 0 }
    It 'a part refused with E_LOW_MEMORY_CONDITION is asked again after 30 s, and its rows count' {
        $read = { param($q) $script:Calls++; if ($script:Calls -eq 1) { throw (Refusal 'Partial query failure: Low memory condition (E_LOW_MEMORY_CONDITION)') }; , @(@{ _peerKey = 'a' }, @{ _peerKey = 'b' }) }
        $r = Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec
        $r.Parts | Should -Be 1
        @($r.Rows).Count | Should -Be 2
        @($script:Waits) | Should -Be @(30)
    }
    It 'three waits (30, 60, 120 s), then it counts as a refusal like any other' {
        $read = { param($q) throw (Refusal 'Low memory condition (E_LOW_MEMORY_CONDITION)') }
        { Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec } | Should -Throw '*temporarily unavailable*'
        @($script:Waits)[0..2] | Should -Be @(30, 60, 120)
    }
    It 'a read that ends on low memory is the service''s moment: never "too large", and the report ends not complete' {
        $read = { param($q) throw (Refusal 'Low memory condition (E_LOW_MEMORY_CONDITION)') }
        $err = $null; try { $null = Invoke-RALaPartedRead -Query $script:Peer -What 'the lookup ''_ciPeer''' -Read $read -Sleep $script:SleepRec } catch { $err = $_ }
        $err.Exception.Data['SIRALookupUnavailable'] | Should -BeTrue
        $err.Exception.Data.Contains('SIRALookupTooLarge') | Should -BeFalse
        $err.Exception.Message | Should -Match 'a lookup this report needs could not be read \(the lookup ''_ciPeer''\) -- Log Analytics is temporarily unavailable'
        $err.Exception.Message | Should -Not -Match '(?i)too large|exceeded the allowed|cannot make it fit|more than Log Analytics'
    }
    It 'a read that ends on a size refusal stays "more than Log Analytics can answer" (control)' {
        $read = { param($q) throw (Refusal) }
        $err = $null; try { $null = Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec } catch { $err = $_ }
        $err.Exception.Data['SIRALookupTooLarge'] | Should -BeTrue
        $err.Exception.Message | Should -Match 'more than Log Analytics can answer'
    }
    It 'a plain size refusal is never waited on' {
        $read = { param($q) if ($q -match 'hash\(') { , @(@{ x = 1 }) } else { throw (Refusal) } }
        $r = Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec
        $script:Waits.Count | Should -Be 0
        $r.Parts | Should -Be 2
    }
}

Describe 'the stop: a refusal with no rows counts unless it moved forward' {
    BeforeAll {
        # one key no part can hold: the part that holds it is always refused, every other part comes back whole
        $script:OneHeavyKey = {
            param($q)
            $script:Calls++
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            $n = [int]$Matches[1]; $i = [int]$Matches[2]
            if ($n -gt $script:Top) { $script:Top = $n }
            if (($script:Heavy % $n) -eq $i) { throw (Refusal) }
            , @(@{ _peerKey = "k$n-$i" })
        }
    }
    BeforeEach { $script:Waits.Clear(); $script:Calls = 0; $script:Top = 1 }
    It 'one key no part can hold ends as too large, wherever it lies (<Name>)' -ForEach @(
        @{ Name = 'binary digits 0101...'; Heavy = [long]0x5555555555; Calls = 11 }   # queries per count: 1 + 2 + 2 + 6
        @{ Name = 'binary digits 1111...'; Heavy = [long]0xFFFFFFFFFF; Calls = 15 }   # queries per count: 1 + 2 + 4 + 8
    ) {
        $script:Heavy = $Heavy
        $err = $null; try { $null = Invoke-RALaPartedRead -Query $script:Peer -Read $script:OneHeavyKey -Sleep $script:SleepRec } catch { $err = $_ }
        $err.Exception.Data['SIRALookupTooLarge'] | Should -BeTrue
        $err.Exception.Message | Should -Match 'read in 8 part\(s\)'
        $script:Top | Should -Be 8 -Because 'four nested refusals: the whole read, then its part of 2, 4 and 8'
        $script:Calls | Should -Be $Calls
    }
    It 'several keys too heavy for any part end as too large, though the refused part keeps changing' {
        # the first refused part is the lowest of 10, 21 and 31 modulo the count: 0 of 2, 1 of 4, 2 of 8, 5 of 16, 10 of 32. It is
        # never inside the one before from 4 parts on, so "a different region starts the count again" would keep doubling. Here:
        # 1 and 2 (the whole read, 0 of 2), 1 of 4 forward, 2 of 8 at the same position = 3, 5 of 16 forward, 10 of 32 the same = 4.
        $read = {
            param($q)
            $script:Calls++
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            $n = [int]$Matches[1]; $i = [int]$Matches[2]
            if ($n -gt $script:Top) { $script:Top = $n }
            foreach ($h in 10, 21, 31) { if (($h % $n) -eq $i) { throw (Refusal) } }
            , @(@{ _peerKey = "k$n-$i" })
        }
        $err = $null; try { $null = Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec } catch { $err = $_ }
        $err.Exception.Data['SIRALookupTooLarge'] | Should -BeTrue
        $script:Top | Should -Be 32
        $script:Calls | Should -Be 24 -Because 'queries per count: 1 + 1 + 2 + 3 + 6 + 11'
    }
    It 'a refused part that changes at random ends: it moves backward often enough' {
        # a fixed sequence (x -> (37x + 11) mod 101, from 7), so the run is the same everywhere: 68, 2, 85, 25 give part 1 of 2,
        # 0 of 4 (earlier), 6 of 8 (forward, not counted), 3 of 16 (earlier) -- four with the whole read
        $script:X = 7; $script:RefuseAt = @{}
        $read = {
            param($q)
            $script:Calls++
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            $n = [int]$Matches[1]; $i = [int]$Matches[2]
            if ($n -gt $script:Top) { $script:Top = $n }
            if (-not $script:RefuseAt.ContainsKey($n)) {
                $script:X = ($script:X * 37 + 11) % 101
                $script:RefuseAt[$n] = [int][Math]::Floor($script:X * $n / 101)
            }
            if ($i -eq $script:RefuseAt[$n]) { throw (Refusal) }
            , @(@{ _peerKey = "k$n-$i" })
        }
        $err = $null; try { $null = Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec } catch { $err = $_ }
        $err.Exception.Data['SIRALookupTooLarge'] | Should -BeTrue
        $script:Top | Should -Be 16
        $script:Calls | Should -Be 15 -Because 'queries per count: 1 + 2 + 1 + 7 + 4'
    }
    It 'a result cut ends after two nested refusals' {
        $read = {
            param($q)
            $script:Calls++
            if ($q -notmatch 'pack_all\(\)\)\) % (\d+)\) == (\d+)') { throw (Refusal) }
            if ([int]$Matches[2] -eq 1) { throw (Refusal) }
            , @(@{ x = 1 })
        }
        { Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec } | Should -Throw '*read in 2 part(s)*'
        $script:Calls | Should -Be 3
    }
    It 'a refusal that moves forward at each doubling does not count, and the read completes with every row' {
        $read = {
            param($q)
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            $n = [int]$Matches[1]; $i = [int]$Matches[2]
            $refuseAt = @{ 2 = 0; 4 = 1; 8 = 3; 16 = 7 }   # positions 0, 1/4, 3/8, 7/16: each later, none inside the one before
            if ($refuseAt.ContainsKey($n) -and $refuseAt[$n] -eq $i) { throw (Refusal) }
            , @(@{ _peerKey = "k$n-$i" })
        }
        $r = Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec
        $r.Parts | Should -Be 32
        @($r.Rows).Count | Should -Be 32
    }
    It 'seven of 8 parts whole, the last refused and readable at 16: the read completes' {
        $read = {
            param($q)
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            $n = [int]$Matches[1]; $i = [int]$Matches[2]
            if ($n -lt 8 -and $i -eq 0) { throw (Refusal) }
            if ($n -eq 8 -and $i -eq 7) { throw (Refusal) }
            , @(@{ _peerKey = "k$n-$i" })
        }
        $r = Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec
        $r.Parts | Should -Be 16
        @($r.Rows).Count | Should -Be 16
    }
}

Describe 'a CI block is cut at its source' {
    BeforeEach { $script:Seen.Clear(); $script:Calls = 0 }
    It 'the real _ciPeer block can be cut at its source, keyed on _peerKey; _ciLink on _ciKey; other queries cannot' {
        (Get-RALaSourcePartition -Query $script:Peer).Can | Should -BeTrue
        (Get-RALaSourcePartition -Query $script:Peer).DedupeColumn | Should -Be '_peerKey'
        $link = ((Get-RACiKqlBlock -Kind link) -split "`r?`n" | Where-Object { $_ -notmatch '^//__' }) -join "`n"
        (Get-RALaSourcePartition -Query $link).DedupeColumn | Should -Be '_ciKey'
        (Get-RALaSourcePartition -Query 'DeviceInfo | project DeviceId').Can | Should -BeFalse
    }
    It 'the part filter goes right after the core anchor, before the per-CI arg_max -- never at the end' {
        $q = Get-RALaSourcePartQuery -Query $script:Peer -Parts 4 -Part 2
        $q | Should -Match ([regex]::Escape('| where isnotempty(_ciId) | where abs(hash(_ciId)) % 4 == 2'))
        $q.IndexOf('abs(hash(_ciId))') | Should -BeLessThan $q.IndexOf('summarize _ciBuild')
        $q | Should -Not -Match 'pack_all\(\)'
    }
    It 'the parts are read cut at the source and a key two CIs share in different parts is kept once' {
        $read = {
            param($q)
            $script:Seen.Add($q)
            if ($q -notmatch 'abs\(hash\(_ciId\)\) % (\d+) == (\d+)') { throw (Refusal) }
            if ($Matches[2] -eq '0') { , @(@{ _peerKey = 'k1'; peer_ci_id = 'A' }, @{ _peerKey = 'shared'; peer_ci_id = 'A' }) }
            else { , @(@{ _peerKey = 'k2'; peer_ci_id = 'B' }, @{ _peerKey = 'shared'; peer_ci_id = 'B' }) }
        }
        $r = Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec
        $r.Parts | Should -Be 2
        @($r.Rows | ForEach-Object { $_['_peerKey'] } | Sort-Object) | Should -Be @('k1', 'k2', 'shared')
        @($script:Seen | Where-Object { $_ -match 'pack_all' }).Count | Should -Be 0 -Because 'a CI block is never cut on its result'
    }
    It 'a source cut gives up only after four empty refusals in a row; a result cut after two (as before)' {
        $read = { param($q) $script:Calls++; throw (Refusal) }
        { Invoke-RALaPartedRead -Query $script:Peer -Read $read -Sleep $script:SleepRec } | Should -Throw '*more than Log Analytics can answer*'
        $script:Calls | Should -Be 4 -Because '1, 2, 4 and 8 parts each refused at their first part'
        $script:Calls = 0
        { Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec } | Should -Throw
        $script:Calls | Should -Be 2
    }
}
