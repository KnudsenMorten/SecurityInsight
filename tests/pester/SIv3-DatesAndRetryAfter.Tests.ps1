#Requires -Version 5.1
<#
    PWSH 7 + A DANISH HOST: TIMESTAMPS AND RETRY-AFTER (#123).

    Two defects that only exist where the engine actually runs:
      * Output's "active devices" filter did [datetime]::Parse([string]$v). On pwsh 7 the JSON parser has
        already made $v a [datetime]; [string] renders it INVARIANT "MM/dd/yyyy" and Parse reads it back
        in the HOST culture -- on da-DK "09/08" became 9 August (not 8 September) and any day above 12
        failed to parse. Fresh devices were dropped as inactive. EndpointViaEG stored EG_LastSeen the
        same way ([string]$dt).
      * Invoke-SIPagedRest read `$resp.Headers['Retry-After']`. On pwsh 7 the response is an
        HttpResponseMessage whose headers have no string indexer, so the server's backoff was ignored
        and a throttled source gave up after 1+2+4s with a PARTIAL snapshot. An HTTP-date Retry-After was
        parsed in the host culture, which cannot read English day names on da-DK.

    The Retry-After tests are END TO END: a local listener answers 429 with a real header, the real
    Invoke-RestMethod throws, and the parser reads what it threw -- on whichever edition runs the test.
    No network, no tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine/asset-profiling/shared/Invoke-SIPagedRest.ps1')
    $outFile = Join-Path $script:SIRoot 'engine/asset-profiling/stages/Invoke-Output.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($outFile, [ref]$null, [ref]$null)
    $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-SIUtcDateTimeOrNull' }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($fn.Extent.Text))

    function script:Invoke-InDanish([scriptblock]$Body) {
        $prev = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
            & $Body
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prev }
    }

    # A one-shot local HTTP server on its own runspace: answers ONE request with 429 + the given header.
    # 🪤 The listener is STARTED HERE, before the runspace exists, and only answered there. It used to
    # be started inside the runspace with a fixed 400 ms head start: on a slow first runspace the request
    # arrived before the listener did, came back "connection refused" -- an error with no HTTP response,
    # so no Retry-After -- and the test failed intermittently (2026-09-30, in both trees). A request sent
    # to a started HttpListener is queued until GetContext picks it up, so there is no race left.
    function script:Get-ThrottleError([string]$RetryAfter) {
        $l = $null; $prefix = $null
        foreach ($try in 1..5) {
            $prefix = 'http://127.0.0.1:{0}/' -f (Get-Random -Minimum 20000 -Maximum 40000)
            $l = New-Object System.Net.HttpListener
            $l.Prefixes.Add($prefix)
            try { $l.Start(); break } catch { $l.Close(); $l = $null }   # port taken: pick another
        }
        if (-not $l) { throw 'could not start a local HttpListener on any of 5 random ports' }
        $ps = [powershell]::Create()
        [void]$ps.AddScript({
            param($l, $ra)
            $ctx = $l.GetContext()
            $ctx.Response.StatusCode = 429
            $ctx.Response.Headers.Add('Retry-After', $ra)
            $b = [Text.Encoding]::UTF8.GetBytes('{"error":"throttled"}')
            $ctx.Response.OutputStream.Write($b, 0, $b.Length)
            $ctx.Response.Close()
        }).AddArgument($l).AddArgument($RetryAfter)
        $h = $ps.BeginInvoke()
        $err = $null
        try {
            try { $null = Invoke-RestMethod -Uri $prefix -ErrorAction Stop -TimeoutSec 10 } catch { $err = $_ }
            try { $null = $ps.EndInvoke($h) } catch { }
        } finally { $l.Stop(); $l.Close(); $ps.Dispose() }
        return $err
    }
}

Describe 'ConvertTo-SIUtcDateTimeOrNull -- the same instant on every edition and culture' {
    It 'a [datetime] is used AS-IS (8 September stays 8 September on da-DK)' {
        $dt = [datetime]::new(2026, 9, 8, 10, 0, 0, [DateTimeKind]::Utc)
        $r = Invoke-InDanish { ConvertTo-SIUtcDateTimeOrNull $dt }
        $r.Month | Should -Be 9
        $r.Day   | Should -Be 8
    }
    It 'a [datetime] with a day above 12 does not fail (it used to become $null and drop the device)' {
        $dt = [datetime]::new(2026, 9, 20, 10, 0, 0, [DateTimeKind]::Utc)
        (Invoke-InDanish { ConvertTo-SIUtcDateTimeOrNull $dt }).Day | Should -Be 20
    }
    It 'the OLD expression really did swap day and month on da-DK (the defect, demonstrated)' {
        $dt = [datetime]::new(2026, 9, 8, 10, 0, 0, [DateTimeKind]::Utc)
        $old = Invoke-InDanish { [datetime]::Parse([string]$dt) }
        $old.Month | Should -Be 8 -Because 'this is the bug the helper replaces'
    }
    It 'an ISO 8601 string parses to UTC' {
        $r = Invoke-InDanish { ConvertTo-SIUtcDateTimeOrNull '2026-09-08T10:00:00Z' }
        $r.Kind  | Should -Be ([DateTimeKind]::Utc)
        $r.Day   | Should -Be 8
        $r.Hour  | Should -Be 10
    }
    It 'blank and garbage are $null, not an exception' {
        ConvertTo-SIUtcDateTimeOrNull ''    | Should -BeNullOrEmpty
        ConvertTo-SIUtcDateTimeOrNull $null | Should -BeNullOrEmpty
        ConvertTo-SIUtcDateTimeOrNull 'soon' | Should -BeNullOrEmpty
    }
}

Describe 'Get-SIRetryAfterSeconds reads the server''s real header on THIS edition' {
    It 'delta-seconds: a 429 with Retry-After: 7 yields 7' {
        $err = Get-ThrottleError -RetryAfter '7'
        $err | Should -Not -BeNullOrEmpty
        Get-SIRetryAfterSeconds -ErrorRecord $err | Should -Be 7
    }
    It 'HTTP-date, on a da-DK thread: a date ~30s ahead yields a positive delay' {
        $when = [datetime]::UtcNow.AddSeconds(30).ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)
        $err = Get-ThrottleError -RetryAfter $when
        $err.Exception.Response | Should -Not -BeNullOrEmpty -Because 'the 429 must have been answered, not refused'
        $s = Invoke-InDanish { Get-SIRetryAfterSeconds -ErrorRecord $err }
        $s | Should -BeGreaterThan 0
        $s | Should -BeLessOrEqual 31
    }
}

Describe 'WIRING' {
    It 'Output uses the helper at BOTH freshness reads, and no culture-default Parse is left' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine/asset-profiling/stages/Invoke-Output.ps1') -Raw
        # Comments quote the old expression on purpose -- strip them before asserting it is gone.
        $code = [regex]::Replace($src, '(?s)<#.*?#>', '')
        $code = (($code -split "`r?`n") | ForEach-Object { $_ -replace '#.*$', '' }) -join "`n"
        ([regex]::Matches($code, 'ConvertTo-SIUtcDateTimeOrNull \$')).Count | Should -Be 2
        $code | Should -Not -Match '\[datetime\]::Parse\(\[string\]'
    }
    It 'EndpointViaEG stores EG_LastSeen as ISO 8601 when it is already a [datetime]' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine/asset-profiling/discovery/Get-DiscoveryFromEndpointViaEG.ps1') -Raw
        $src | Should -Match "EG_LastSeen\s+= .*-is \[datetime\].*ToString\('o'"
    }
}
