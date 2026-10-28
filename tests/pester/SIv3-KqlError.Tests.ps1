#Requires -Version 5.1
<#
    A FRESH INSTALL'S MISSING TABLE IS RECOGNISED -- THE REASON IS IN THE RESPONSE BODY (#221).

    Az.OperationalInsights throws ErrorResponseException whose Message is only "Operation returned an invalid status
    code 'BadRequest'"; SEM0100 "Failed to resolve table ..." is in Response.Content / Body (measured 2026-10-03 on
    3.4.0 and 3.4.1, PS 5.1 and pwsh 7). The fakes below have exactly that shape.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-KqlError.ps1')
    function script:New-FakeKqlError([string]$Body, [string]$Message = "Operation returned an invalid status code 'BadRequest'") {
        [pscustomobject]@{ Message = $Message; Response = [pscustomobject]@{ Content = $Body }; Body = $null; InnerException = $null }
    }
    function script:Get-Code([string]$Rel) { Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $Rel) }
    $script:Sem0100 = '{"error":{"code":"BadArgumentError","innererror":{"code":"SemanticError","innererror":{"code":"SEM0100","message":"''take'' operator: Failed to resolve table or column expression named ''SI_PublicIP_Profile_CL''"}}}}'
}

Describe 'what a failed query said' {
    It 'the error text includes the response body, not just the bare message' {
        $t = Get-SIKqlErrorText -ErrorRecord (New-FakeKqlError -Body $script:Sem0100)
        $t | Should -Match 'BadRequest'
        $t | Should -Match 'SEM0100'
        $t | Should -Match 'SI_PublicIP_Profile_CL'
    }
    It 'a missing table is recognised from the body -- and ONLY for the table it names' {
        $e = New-FakeKqlError -Body $script:Sem0100
        Test-SIKqlTableMissing -ErrorRecord $e -TableName 'SI_PublicIP_Profile_CL' | Should -BeTrue
        Test-SIKqlTableMissing -ErrorRecord $e -TableName 'SI_Endpoint_Profile_CL' | Should -BeFalse
    }
    It 'the bare message alone (what readers used to look at) is NOT a missing table' {
        Test-SIKqlTableMissing -ErrorRecord ([pscustomobject]@{ Message = "Operation returned an invalid status code 'BadRequest'" }) -TableName 'SI_PublicIP_Profile_CL' | Should -BeFalse
    }
    It 'a throttle or timeout that quotes the query (and so the table name) is NOT a missing table (#132)' {
        $throttle = New-FakeKqlError -Message "Operation returned an invalid status code 'TooManyRequests'" -Body '{"error":{"code":"ThrottledError","message":"Too many requests for query SI_PublicIP_Profile_CL | take 1"}}'
        Test-SIKqlTableMissing -ErrorRecord $throttle -TableName 'SI_PublicIP_Profile_CL' | Should -BeFalse
        $timeout = New-FakeKqlError -Message 'The operation has timed out' -Body ''
        Test-SIKqlTableMissing -ErrorRecord $timeout -TableName 'SI_PublicIP_Profile_CL' | Should -BeFalse
    }
    It 'a typed body and an inner exception are read too; null is empty' {
        $typed = [pscustomobject]@{ Message = 'x'; Response = $null; Body = @{ Error = @{ Innererror = @{ Code = 'SEM0100'; Message = "Failed to resolve table or column expression named 'SI_RiskAnalysis_Detailed_CL'" } } }; InnerException = $null }
        Test-SIKqlTableMissing -ErrorRecord $typed -TableName 'SI_RiskAnalysis_Detailed_CL' | Should -BeTrue
        $outer = [pscustomobject]@{ Message = 'outer'; Response = $null; Body = $null; InnerException = (New-FakeKqlError -Body $script:Sem0100) }
        Test-SIKqlTableMissing -ErrorRecord $outer -TableName 'SI_PublicIP_Profile_CL' | Should -BeTrue
        Get-SIKqlErrorText -ErrorRecord $null | Should -Be ''
    }
}

Describe 'one log-ready line: the bare message plus what the service said' {
    BeforeAll {
        # The real shape of the public-IP report failure, measured 2026-10-03 through Az.OperationalInsights.
        $script:Sem0100Summarize = '{"error":{"message":"The request had some invalid properties","code":"BadArgumentError","correlationId":"x","innererror":{"code":"SemanticError","message":"A semantic error occurred.","innererror":{"code":"SEM0100","message":"''summarize'' operator: Failed to resolve scalar expression named ''AssetName''"}}}}'
    }
    It 'names the code chain and the innermost message, and keeps the bare message first' {
        $s = Get-SIKqlErrorSummary -ErrorRecord (New-FakeKqlError -Body $script:Sem0100Summarize)
        $s | Should -BeLike "Operation returned an invalid status code 'BadRequest' -- *"
        $s | Should -Match ([regex]::Escape("SemanticError/SEM0100: 'summarize' operator: Failed to resolve scalar expression named 'AssetName'"))
    }
    It 'still matches what the Risk Analysis query-defect verdict classifies on (BadRequest / semantic)' {
        $s = Get-SIKqlErrorSummary -ErrorRecord (New-FakeKqlError -Body $script:Sem0100Summarize)
        $s | Should -Match 'semantic|syntax|not compatible|BadRequest'
    }
    It 'a second copy of the same body (typed body, ErrorDetails) does not repeat the codes' {
        $e = [pscustomobject]@{ Message = "Operation returned an invalid status code 'BadRequest'"; Response = [pscustomobject]@{ Content = $script:Sem0100Summarize }; Body = $null
                                InnerException = [pscustomobject]@{ Message = 'inner'; Response = [pscustomobject]@{ Content = $script:Sem0100Summarize }; Body = $null; InnerException = $null } }
        $s = Get-SIKqlErrorSummary -ErrorRecord $e
        ([regex]::Matches($s, 'SEM0100')).Count | Should -Be 1
    }
    It 'with no service body it is exactly the bare message; null is empty' {
        Get-SIKqlErrorSummary -ErrorRecord ([pscustomobject]@{ Message = 'The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing. (TaskCanceledException)' }) |
            Should -Be 'The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing. (TaskCanceledException)'
        Get-SIKqlErrorSummary -ErrorRecord $null | Should -Be ''
    }
    It 'works on a real ErrorRecord from a catch block' {
        $s = try { throw (New-Object System.Exception "Operation returned an invalid status code 'BadRequest'") } catch { Get-SIKqlErrorSummary -ErrorRecord $_ }
        $s | Should -Be "Operation returned an invalid status code 'BadRequest'"
    }
}

Describe 'WIRING -- Risk Analysis logs what a failed query said, not only "BadRequest"' {
    BeforeAll { $script:Ra = Get-Code 'engine\risk-analysis\Invoke-RiskAnalysis.ps1' }
    It 'loads the shared helper' {
        $script:Ra | Should -Match "_shared/SI-KqlError\.ps1"
    }
    It 'the summary is built from Get-SIKqlErrorText (the response body), not from the exception message alone' {
        $c = Get-Code 'engine\_shared\SI-KqlError.ps1'
        $fn = [regex]::Match($c, '(?s)function Get-SIKqlErrorSummary \{.*?\n\}').Value
        $fn | Should -Match 'Get-SIKqlErrorText -ErrorRecord \$ErrorRecord'
    }
    It 'the AutoBucket failure line carries the service error' {
        $script:Ra | Should -Match '(?s)AutoBucket failed for report .{0,200}?Error: \{2\}" -f `\s+\$ReportName, \$effectiveBucketCount, \(Get-SIKqlErrorSummary -ErrorRecord \$_\)\)'
    }
    It 'the bucket query failure carries the service error' {
        $script:Ra | Should -Match '\$errMsg = Get-SIKqlErrorSummary -ErrorRecord \$_'
        $script:Ra | Should -Match 'Write-Err2 \("query failed for bucket \{0\}/\{1\}: \{2\}" -f \$bucketNo, \$bucketCountToUse, \$errMsg\)'
    }
}

Describe 'WIRING -- the readers that failed on a fresh install classify on the body' {
    It 'correlation skips a missing profile table through the shared helper' {
        if (-not (Test-Path -LiteralPath (Join-Path $script:SIRoot 'engine\asset-correlation'))) { Set-ItResult -Skipped -Because 'SecurityInsight Pro is not in this copy'; return }
        $c = Get-Code 'engine\asset-correlation\_shared\SI-CorrelationIngest.ps1'
        $c | Should -Match "_shared\\SI-KqlError\.ps1"
        $c | Should -Match '\$tableMissing = Test-SIKqlTableMissing -ErrorRecord \$_ -TableName \$table'
    }
    It 'trend ends cleanly when Risk Analysis has not published yet, and still refuses any other read failure' {
        $c = Get-Code 'engine\asset-trend\Invoke-SITrend.ps1'
        $c | Should -Match "_shared\\SI-KqlError\.ps1"
        $c | Should -Match 'if \(Test-SIKqlTableMissing -ErrorRecord \$_ -TableName \$sourceTable\)'
        $c | Should -Match 'Refusing to publish a rollup from a source it could not read'
    }
    It 'the close-loop reads a missing source as EMPTY (the safe direction) and throws on anything else' {
        if (-not (Test-Path -LiteralPath (Join-Path $script:SIRoot 'engine\asset-cmdb\Invoke-SIVulnLoop.ps1'))) { Set-ItResult -Skipped -Because 'SecurityInsight Pro is not in this copy'; return }
        $c = Get-Code 'engine\asset-cmdb\Invoke-SIVulnLoop.ps1'
        # (the call carries the scope fields since the connectors' scope filters: any further argument is allowed)
        $c | Should -Match "& \`$qOrEmpty \(Get-SIVulnDesiredKql -EditionMajor \`$edition[^)]*\) 'SI_RiskAnalysis_Detailed_CL'"
        $c | Should -Match "& \`$qOrEmpty \(Get-SIVulnRunHealthKql\) 'SI_RunHealth_CL'"
        $c | Should -Match "& \`$qOrEmpty \(Get-SIVulnEndpointStateKql\) 'SI_Endpoint_Profile_CL'"
        $c | Should -Match 'else \{ throw \}'
    }
}
