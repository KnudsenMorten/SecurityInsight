#Requires -Version 5.1
<#
    Fix request 2a40d950 (owner 2026-10-22: no fixed limits on SI's own work): the endpoint run gave up on its data collection
    rule after a fixed 240 s ("DCR 'dcr-si-endpoint-profile' not created in target RG after 240s") and skipped the Log
    Analytics write. Now the rule is waited for until it is READY and read back, with progress on every read; only a refusal
    (the create's own, Azure's Failed state, a refused read) ends the wait, and Microsoft's answer is said.
    OFFLINE. Every read and every pause is a seam -- nothing sleeps, nothing reaches Azure. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    $script:Pauses = New-Object System.Collections.Generic.List[int]
    $script:Lines = New-Object System.Collections.Generic.List[string]
    $script:SleepSeam = { param($s) $script:Pauses.Add([int]$s) }
    $script:LogSeam = { param($m) $script:Lines.Add([string]$m) }
    # a probe that answers from a list, one answer per read (an answer that is a string starting 'throw:' throws it)
    function script:New-Probe([object[]]$Answers) {
        $state = @{ i = 0; a = $Answers }
        {
            $x = $state.a[[Math]::Min($state.i, $state.a.Count - 1)]; $state.i++
            if ($x -is [string] -and $x.StartsWith('throw:')) { throw $x.Substring(6) }
            $x
        }.GetNewClosure()
    }
    $script:Ok = @{ ImmutableId = 'dcr-0123456789abcdef'; State = 'Succeeded' }
}

Describe 'Wait-SIDcrReady: until ready, never a fixed give-up' {
    BeforeEach { $script:Pauses.Clear(); $script:Lines.Clear() }

    It 'a rule that is already there is read at once -- no wait' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeTrue
        $r.ImmutableId | Should -Be 'dcr-0123456789abcdef'
        $r.Waited | Should -Be 0
        $script:Pauses.Count | Should -Be 0
    }
    It 'not there yet, then there without an id, then ready: progress on every read, the pause grows to its pace' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($null, @{ ImmutableId = ''; State = 'Creating' }, $script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeTrue
        @($script:Pauses) | Should -Be @(60, 30) -Because 'after a read that found no rule, the next read is a full progress pace later'
        $r.Waited | Should -Be 90
        ($script:Lines -join "`n") | Should -Match 'not there yet'
        ($script:Lines -join "`n") | Should -Match 'provisioning state Creating'
        ($script:Lines -join "`n") | Should -Match 'resolved after 90s'
    }
    It 'NO FIXED LIMIT: a rule that is there but provisioning far longer than the old 240 s is still waited for and used' {
        $answers = @(@(@{ ImmutableId = ''; State = 'Creating' }) * 200) + @($script:Ok)
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe $answers) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeTrue
        $r.Waited | Should -BeGreaterThan 240
        ($script:Pauses | Measure-Object -Maximum).Maximum | Should -Be 60 -Because 'the pace stops growing at a minute -- a pace, never a deadline'
    }
    It 'a transient read failure is said and read again' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @('throw:503 Service Unavailable', $script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeTrue
        ($script:Lines -join "`n") | Should -Match 'the read failed \(503 Service Unavailable\) -- read again'
    }
    It 'a REFUSED read (403) ends the wait with Microsoft''s answer' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($null, 'throw:403 (Forbidden) AuthorizationFailed: no read on Microsoft.Insights/dataCollectionRules')) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeFalse
        $r.Why | Should -Match 'AuthorizationFailed'
    }
    It 'Azure says the rule FAILED: the wait ends and says so' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @(@{ ImmutableId = ''; State = 'Failed' })) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeFalse
        $r.Why | Should -Match 'provisioning state Failed'
    }
    It 'a create REFUSED by Azure is not waited for -- unless the rule is there after all (read back once)' {
        $out = "creating DCR dcr-x ...`nResponse status code does not indicate success: 403 (Forbidden). AuthorizationFailed"
        Get-SIDcrCreateRefusal -CreateOutput $out | Should -Match 'AuthorizationFailed'
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -CreateOutput $out -Probe (New-Probe @($null)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeFalse
        $r.Why | Should -Match 'was refused -- .*403 \(Forbidden\)'
        $script:Pauses.Count | Should -Be 0
        $r2 = Wait-SIDcrReady -DcrName 'dcr-x' -CreateOutput $out -Probe (New-Probe @($script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r2.Ready | Should -BeTrue -Because 'a refusal of a later part never throws away a rule that is there'
        Get-SIDcrCreateRefusal -CreateOutput "Existing table+DCR already match schema -- no create/update needed." | Should -BeNullOrEmpty
    }
    It 'REVIEW S1: a create that did nothing ends the wait -- two read-backs a pace apart find no rule; Azure''s answer is said' {
        # never waits forever: 1000 answers of "no rule at all" -> stops on the second
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -CreateOutput "PUT dataCollectionRules/dcr-x`n202 Accepted" -Probe (New-Probe @(@($null) * 1000)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeFalse
        $r.Why | Should -Match "^the rule was not created; Azure answered: 202 Accepted"
        @($script:Pauses) | Should -Be @(60) -Because 'the two read-backs are spaced by the progress pace'
        # a rule seen in between resets the count: absent, there (Creating), absent, there ready -> used
        $script:Pauses.Clear()
        $r2 = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($null, @{ ImmutableId = ''; State = 'Creating' }, $null, $script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r2.Ready | Should -BeTrue
        # a read that FAILED is not a read that found nothing
        $r3 = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($null, 'throw:503 Service Unavailable', 'throw:503 Service Unavailable', $script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r3.Ready | Should -BeTrue
        # no output at all is named as such
        $r4 = Wait-SIDcrReady -DcrName 'dcr-x' -Probe (New-Probe @($null, $null)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r4.Why | Should -Match 'Azure answered: nothing \(the create returned no output\)'
    }
    It 'REVIEW S1: "skipping create" / "already exists in" another resource group is a refusal, not a wait' {
        $out = "DCR dcr-x already exists in resource group rg-other -- skipping create"
        Get-SIDcrCreateRefusal -CreateOutput $out | Should -Be $out
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -CreateOutput $out -Probe (New-Probe @($null)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeFalse
        $r.Why | Should -Match 'was refused -- .*skipping create'
        $script:Pauses.Count | Should -Be 0
    }
    It 'the location placeholder is never taken for an immutable id' {
        $r = Wait-SIDcrReady -DcrName 'dcr-x' -Location 'westeurope' -Probe (New-Probe @(@{ ImmutableId = 'westeurope'; State = 'Succeeded' }, $script:Ok)) -Sleep $script:SleepSeam -Log $script:LogSeam
        $r.Ready | Should -BeTrue
        $r.ImmutableId | Should -Be 'dcr-0123456789abcdef'
    }
    It 'WIRING: the endpoint output stage waits through Wait-SIDcrReady; the fixed 240 s is gone' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'))
        $src | Should -Match ([regex]::Escape('$_wait = Wait-SIDcrReady -DcrName $dcrName -Probe $_probe -CreateOutput ([string]$_createOutput)'))
        $src | Should -Not -Match '\$_waitMax\s*='
        $src | Should -Match ([regex]::Escape("is not ready in the target resource group -- {1}"))
    }
}
