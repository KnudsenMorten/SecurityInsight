#Requires -Version 5.1
<#
    AN AI-SUMMARY FAILURE NEVER ENDS A RISK ANALYSIS RUN, AND A PLATFORM FAILURE IS RETRIED (#154).

    Measured 2026-09-29 on the internal tenant: Azure OpenAI answered one request with HTTP 408
    ("The operation was timeout."). The engine reported it with Write-Error under its Stop preference, so
    the run ENDED -- after the findings were exported and ingested, but before the mail and the row-count /
    column-fill guards. Working rule 4: a platform failure (timeout / 429 / 5xx / no connection) is retried
    in-run; anything else is a request defect and is not.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
    $a = $script:Src.IndexOf('$handler = [System.Net.Http.HttpClientHandler]::new()')
    $b = $script:Src.IndexOf('# close v2.2.352 `else` (skipAIPost was $false')
    $script:AiBlock = $script:Src.Substring($a, $b - $a)
}

Describe 'the Azure OpenAI call' {
    It 'is retried on 408, 429, 5xx and a lost connection, with backoff and Retry-After honoured' {
        $script:AiBlock | Should -Match 'for \(\$__aiAtt = 1; \$__aiAtt -le \$__aiMax; \$__aiAtt\+\+\)'
        $script:AiBlock | Should -Match '\$__aiCode -eq 0 -or \$__aiCode -eq 408 -or \$__aiCode -eq 429 -or \$__aiCode -ge 500'
        $script:AiBlock | Should -Match 'RetryAfter'
        $script:AiBlock | Should -Match 'Start-Sleep -Seconds'
    }
    It 'builds a NEW request per attempt (a request message cannot be sent twice)' {
        $loop = [regex]::Match($script:AiBlock, '(?s)for \(\$__aiAtt = 1.*?Start-Sleep -Seconds').Value
        $loop | Should -Match '\[System\.Net\.Http\.HttpRequestMessage\]::new\('
    }
    It 'a request defect is NOT retried: it fails on the first attempt' {
        $script:AiBlock | Should -Match 'if \(-not \$__aiTransient -or \$__aiAtt -ge \$__aiMax\) \{ throw'
    }
    It 'a final failure is a WARNING -- the run goes on to mail and the guards' {
        $script:AiBlock | Should -Not -Match 'Write-Error "Azure OpenAI request failed'
        $script:AiBlock | Should -Match 'Write-Warn2 \("AI summary could not be generated'
    }
}
