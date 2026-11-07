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
        { Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec } | Should -Throw '*more than Log Analytics can answer*'
        @($script:Waits)[0..2] | Should -Be @(30, 60, 120)
    }
    It 'a plain size refusal is never waited on' {
        $read = { param($q) if ($q -match 'hash\(') { , @(@{ x = 1 }) } else { throw (Refusal) } }
        $r = Invoke-RALaPartedRead -Query 'T | project x' -Read $read -Sleep $script:SleepRec
        $script:Waits.Count | Should -Be 0
        $r.Parts | Should -Be 2
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
