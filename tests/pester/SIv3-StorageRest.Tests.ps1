#Requires -Version 5.1
<#
    STORAGE REST: A SELF-HEAL THAT CAN FIRE, AND TEXT THAT ARRIVES INTACT (#126).

      * FingerprintCache: the PUT uses a raw HttpWebRequest, so a 400 reaches the untyped catch as a
        MethodInvocationException whose own .Response is $null -- the WebException is its
        InnerException. The status read as 0, so the InvalidInput DELETE+PUT self-heal (column-type
        drift) could never fire; every drift became a thrown write failure, and the error text carried
        no OData code.
      * TypeProfileCache sent its entities as STRING bodies: on PS 5.1 AI-written text (reasoning, app
        names) is transcoded to a single-byte encoding -- the #114 defect on a second path.

    The self-heal test produces a GENUINE MethodInvocationException: the mocked PUT performs a real
    HttpWebRequest against a local listener that answers 400 InvalidInput. No network, no tenant.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $st = Join-Path $script:SIRoot 'engine\asset-profiling\storage'
    . (Join-Path $st 'StorageContext.ps1')
    . (Join-Path $st 'FingerprintCache.ps1')
    . (Join-Path $st 'TypeProfileCache.ps1')

    # One-shot local server answering a single request with 400 + an Azure Table OData error body.
    function script:Invoke-Real400 {
        $port = Get-Random -Minimum 20000 -Maximum 40000
        $prefix = "http://127.0.0.1:$port/"
        $ps = [powershell]::Create()
        [void]$ps.AddScript({
            param($prefix)
            $l = New-Object System.Net.HttpListener
            $l.Prefixes.Add($prefix); $l.Start()
            try {
                $ctx = $l.GetContext()
                $ctx.Response.StatusCode = 400
                $b = [Text.Encoding]::UTF8.GetBytes('{"odata.error":{"code":"InvalidInput","message":{"lang":"en-US","value":"type drift"}}}')
                $ctx.Response.OutputStream.Write($b, 0, $b.Length)
                $ctx.Response.Close()
                # Stay up: pwsh 7 reads an error body LAZILY from the live connection (PS 5.1 buffers it
                # when the exception is thrown), so stopping at once resets the connection before the
                # caller's catch reads the body -- a harness artifact, not engine behaviour.
                Start-Sleep -Seconds 5
            } finally { $l.Stop() }
        }).AddArgument($prefix)
        $null = $ps.BeginInvoke()
        [void]$script:Servers.Add($ps)
        Start-Sleep -Milliseconds 400
        $req = [System.Net.HttpWebRequest]::CreateHttp($prefix)
        $req.Method = 'GET'
        $resp = $req.GetResponse()   # throws -- exactly the way _Invoke-SITablePut does
        $resp.Close()
    }
    $script:Servers = New-Object System.Collections.ArrayList
}

AfterAll {
    foreach ($s in $script:Servers) { try { $s.Stop() } catch { }; try { $s.Dispose() } catch { } }
}

Describe 'FingerprintCache -- the InvalidInput self-heal can actually fire' {
    It 'a real HttpWebRequest 400 arrives wrapped, and the helper finds the WebException inside' {
        $err = $null
        try { Invoke-Real400 } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $null -eq $err.Exception.Response | Should -BeTrue -Because 'this is why the old code read status 0'
        $http = _Get-SIHttpException -ErrorRecord $err
        [int]$http.Response.StatusCode | Should -Be 400
        (_Get-SIAzureErrorBody -ErrorRecord $err) | Should -Match '"code":"InvalidInput"'
    }

    It 'Set-SIFingerprintRecord DELETEs and re-PUTs on 400 InvalidInput instead of throwing' {
        $script:putCalls = 0; $script:deleteCalls = 0
        Mock _Invoke-SITablePut { $script:putCalls++; if ($script:putCalls -eq 1) { Invoke-Real400 } }
        Mock _Invoke-SITableDelete { $script:deleteCalls++; $true }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'acct' }
        { Set-SIFingerprintRecord -Context $ctx -TableName 't' -AssetId 'a1' -Properties @{ si_tier = 1 } } | Should -Not -Throw
        $script:deleteCalls | Should -Be 1
        $script:putCalls    | Should -Be 2
    }
}

Describe 'TypeProfileCache -- entities are sent as UTF-8 bytes' {
    It 'Set-SISignalMapRecord sends byte[] with charset=utf-8, and non-ASCII text round-trips' {
        # 'Rødgrød -- æøå' built from code points so this file stays ASCII.
        $danish = 'R' + [char]0x00F8 + 'dgr' + [char]0x00F8 + 'd ' + [char]0x2014 + ' ' + [char]0x00E6 + [char]0x00F8 + [char]0x00E5
        $script:captured = $null
        Mock ConvertTo-SIRfc1123Date { 'Mon, 28 Sep 2026 10:00:00 GMT' }
        # the table calls go through the shared retrying REST call: its one HTTP seam is captured
        Mock Get-SIAzureToken { 'x' }
        Mock Invoke-SIAzRestHttp { $script:captured = @{ Body = $Body; ContentType = $ContentType }; [pscustomobject]@{ StatusCode = 204; Content = ''; Bytes = $null; Headers = @{}; RetryAfter = $null } }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'acct' }
        Set-SISignalMapRecord -Context $ctx -TableName 't' -Engine 'azure' -AssetType 'kv' -PromptVersion 'v1' -Signals @() -Reasoning $danish
        ,$script:captured.Body | Should -BeOfType [byte[]]
        $script:captured.ContentType | Should -Match 'charset=utf-8'
        $decoded = [Text.Encoding]::UTF8.GetString($script:captured.Body) | ConvertFrom-Json
        $decoded.reasoning | Should -BeExactly $danish
    }
    It 'no string body is left on any TypeProfileCache write' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\storage\TypeProfileCache.ps1') -Raw
        $src | Should -Not -Match '-Body \$body\b'
    }
}
