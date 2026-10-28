#Requires -Version 5.1
<#
    A HUNTING TIMEOUT MUST THROW, AND MUST READ AS TaskCanceledException (#117).

    Task.Result is a PROPERTY GETTER, and PowerShell swallows an exception raised inside a getter:
    `$client.SendAsync($req).Result` on a timed-out request returns $null instead of throwing.
    Measured 2026-09-28 on PS 5.1 and pwsh 7. The transport then reported "0 HTTP error" and Risk
    Analysis' AutoBucket escalation -- which keys on the TaskCanceledException TEXT -- never fired on
    the 900s ceiling it exists for.

    These tests use a local TCP listener that ACCEPTS the connection and never answers, so the only
    way out is the client timeout. No network, no tenant.
#>

BeforeAll {
    $script:SIRootDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRootDir 'engine/_shared/SI-GraphRest.ps1')

    # A listener that accepts and then says nothing. Accepted sockets are kept so they are not closed.
    $script:Listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $script:Listener.Start()
    $script:Port = ([System.Net.IPEndPoint]$script:Listener.LocalEndpoint).Port
    $script:SilentUri = "http://127.0.0.1:$($script:Port)/security/runHuntingQuery"
}

AfterAll {
    if ($script:Listener) { $script:Listener.Stop() }
}

Describe 'Invoke-SIGraphHttp surfaces a client timeout' {

    It 'THROWS on timeout instead of returning a status-0 response' {
        $threw = $false; $resp = $null; $err = $null
        try {
            $resp = Invoke-SIGraphHttp -Uri $script:SilentUri -Token 'x' -Method Post `
                        -BodyBytes ([byte[]](0x7B,0x7D)) -TimeoutSec 2
        } catch { $threw = $true; $err = $_ }
        $threw | Should -BeTrue -Because 'a swallowed timeout comes back as a $null response with StatusCode 0'
        $resp  | Should -BeNullOrEmpty
    }

    It 'the thrown error carries TaskCanceledException somewhere in its chain' {
        $err = $null
        try { $null = Invoke-SIGraphHttp -Uri $script:SilentUri -Token 'x' -TimeoutSec 2 } catch { $err = $_ }
        $chain = @(); $e = $err.Exception
        while ($e) { $chain += $e.GetType().FullName; $e = $e.InnerException }
        ($chain -join ' > ') | Should -Match 'TaskCanceledException'
    }
}

Describe 'Invoke-SIHuntingQueryRest maps the timeout to the text RA escalates on' {

    BeforeAll {
        # Route the real transport at the silent listener; everything else is the production code path.
        $script:RealHttp = ${function:Invoke-SIGraphHttp}
        Set-Item -Path function:global:Invoke-SIGraphHttpForTest -Value $script:RealHttp
    }

    It 'the QUERY path throws with TaskCanceledException text' {
        Mock Invoke-SIGraphHttp { Invoke-SIGraphHttpForTest -Uri $script:SilentUri -Token $Token -Method $Method -BodyBytes $BodyBytes -TimeoutSec 2 }
        $msg = $null
        try { $null = Invoke-SIHuntingQueryRest -Query 'print 1' -Token 'x' -TimeoutSec 2 } catch { $msg = [string]$_.Exception.Message }
        $msg | Should -Match 'TaskCanceledException'
        $msg | Should -Not -Match '^0 '
    }

    It 'the PROBE path (-AsResult) still returns instead of throwing, carrying the same text' {
        Mock Invoke-SIGraphHttp { Invoke-SIGraphHttpForTest -Uri $script:SilentUri -Token $Token -Method $Method -BodyBytes $BodyBytes -TimeoutSec 2 }
        $r = $null
        { $script:r = Invoke-SIHuntingQueryRest -Query 'print 1' -Token 'x' -TimeoutSec 2 -AsResult } | Should -Not -Throw
        $script:r.Ok    | Should -BeFalse
        $script:r.Error | Should -Match 'TaskCanceledException'
    }
}

Describe 'no Task.Result getter is left on an HTTP path in the solution' {

    It 'no engine file reads .Result off an *Async() call' {
        $hits = New-Object System.Collections.ArrayList
        foreach ($f in Get-ChildItem -Path (Join-Path $script:SIRootDir 'engine') -Recurse -Include *.ps1,*.psm1 -File) {
            $text = [IO.File]::ReadAllText($f.FullName)
            $text = [regex]::Replace($text, '(?s)<#.*?#>', '')
            $n = 0
            foreach ($line in ($text -split "`r?`n")) {
                $n++
                if ($line -match '^\s*#') { continue }
                if ($line -match 'Async\([^)]*\)\s*\.Result\b' -or $line -match '^\s*\)\.Result\b') { [void]$hits.Add("$($f.Name):$n") }
            }
        }
        $hits.Count | Should -Be 0 -Because ("Task.Result swallows exceptions in PowerShell: " + ($hits -join ', '))
    }
}