#Requires -Version 5.1
<#
    A FAILED STEP'S CAUSE IS THE ERROR THAT ENDED IT (#758, fix-request triage 2026-10-18 on rc11).

    Four identity / asset-correlation / asset-vulnerabilities failures reached Invardia as
    "PS>TerminatingError(ConvertFrom-Json): Unexpected character encountered while parsing value: L" -- an error the
    container's settings decode CAUGHT at start -- and one identity failure as the IdentityInfo SEM0100 warning, also
    caught. What these tests keep true:
      * a list of plain words ([LA,Excel], [mde,entra] -- az.cmd drops the quotes) is read WITHOUT ConvertFrom-Json, so no
        transcript TerminatingError line is written at container start; a JSON list (quoted, numbers) still decodes;
      * Get-SIErrorLines takes the LAST error block of the log (the one that ended the run), and a transcript
        "PS>TerminatingError(...)" marker or a WARNING: line only when the log has nothing else -- with the five samples'
        shapes, and the class each now gets.
    Offline: no tenant, no container.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    $script:Head = @('**********************', 'PowerShell transcript start', 'Start time: 20261018190000', '**********************')
    $script:Tail = @('**********************', 'PowerShell transcript end', 'End time: 20261018192500', '**********************')
    $script:JsonNoise = @(
        'PS>TerminatingError(ConvertFrom-Json): "Conversion from JSON failed with error: Unexpected character encountered while parsing value: L. Path '''', line 0, position 0."',
        '>> TerminatingError(ConvertFrom-Json): "Conversion from JSON failed with error: Unexpected character encountered while parsing value: m. Path '''', line 0, position 0."')
}

Describe 'the container settings decode writes no error record' {
    It 'a list of plain words is read as the list without ConvertFrom-Json: <Text>' -ForEach @(
        @{ Text = '[LA,Excel]'; Out = @('LA', 'Excel') }
        @{ Text = '[mde,entra,azure]'; Out = @('mde', 'entra', 'azure') }
        @{ Text = '[ *Visual Studio* , *Students* ]'; Out = @('*Visual Studio*', '*Students*') }
    ) {
        Mock ConvertFrom-Json { throw 'ConvertFrom-Json must not be called for a list of plain words' }
        $v = ConvertFrom-SIConfigEnvValue -Text $Text
        @($v) | Should -Be $Out
        Should -Invoke ConvertFrom-Json -Times 0 -Exactly
    }
    It 'an empty list is an empty list, without ConvertFrom-Json' {
        Mock ConvertFrom-Json { throw 'not expected' }
        $v = ConvertFrom-SIConfigEnvValue -Text '[]'
        @($v).Count | Should -Be 0
        Should -Invoke ConvertFrom-Json -Times 0 -Exactly
    }
    It 'a JSON list still decodes with its types (quoted strings, numbers)' {
        $j = ConvertFrom-SIConfigEnvValue -Text '["LA","Excel"]'; (@($j | ForEach-Object { $_ } | ForEach-Object { $_ }) -join ',') | Should -Be 'LA,Excel'
        $n = @(ConvertFrom-SIConfigEnvValue -Text '[1,2,3]' | ForEach-Object { $_ } | ForEach-Object { $_ })
        $n.Count | Should -Be 3; $n[0] | Should -BeOfType [long]
        $b = ConvertFrom-SIConfigEnvValue -Text '[true,false]'; (@($b | ForEach-Object { $_ } | ForEach-Object { $_ }) -join ',') | Should -Be 'True,False'
    }
}

Describe 'Get-SIErrorLines: the error that ended the run' {
    It 'start-up JSON noise, then the real error: the real error is the text (asset-correlation shape)' {
        $log = $script:Head + $script:JsonNoise + @(
            '[INFO] asset-correlation: reading the batches',
            '[ERROR] asset-correlation: the CI build failed: A single record (2001077 bytes) is larger than the 1048576-byte limit of the Log Ingestion API, so it cannot be posted.',
            'at Send-SILogIngestBatch, /app/engine/_shared/SI-LogIngest.ps1: line 1960') + $script:Tail
        $t = Get-SIErrorLines -Lines $log
        $t | Should -Match '^\[ERROR\] asset-correlation: the CI build failed'
        $t | Should -Not -Match 'TerminatingError\(ConvertFrom-Json\)'
    }
    It 'a caught WARNING early, the terminating error late: the terminating one (identity shape) -> its class' {
        $log = $script:Head + $script:JsonNoise + @(
            "WARNING: IdentityInfo query failed -- AD groups + activity signals will be empty: 'where' operator: Failed to resolve table or column expression named 'IdentityInfo' SEM0100",
            '[INFO] identity: 1.234 users read',
            '[ERROR] identity: Graph refused /users?$select=signInActivity: Response status code does not indicate success: 403 (Forbidden). Authorization_RequestDenied',
            'at Invoke-SIGraph, /app/engine/_shared/SI-AzRest.ps1: line 210') + $script:Tail
        $f = Get-SIJobFlowStepFailure -Step ([pscustomobject]@{ Job = 'identity'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'the execution ended failed' }) -LogLines $log
        $f.Text | Should -Match '^\[ERROR\] identity: Graph refused'
        $f.Text | Should -Not -Match 'IdentityInfo|ConvertFrom-Json'
        $f.ErrorClass | Should -Be 'graph-403'
    }
    It 'two real errors: the LAST block is taken (the one the step failed on), from its first line' {
        $log = @('[ERROR] asset-vulnerabilities: page 3 failed once: 429 Too Many Requests -- retried', '[INFO] page 3 read on retry',
                 'Exception: the vulnerability read stopped: 500 Internal Server Error from api.security.microsoft.com', '[ERROR] asset-vulnerabilities: the step failed')
        $t = Get-SIErrorLines -Lines $log
        $t | Should -Match '^Exception: the vulnerability read stopped: 500'
        $t | Should -Match 'the step failed'
        $t | Should -Not -Match '429'
    }
    It 'only TerminatingError markers / warnings in the log: they are still the text (never empty)' {
        $t = Get-SIErrorLines -Lines ($script:Head + $script:JsonNoise + @('[INFO] done') + $script:Tail)
        $t | Should -Match 'TerminatingError\(ConvertFrom-Json\)'
    }
    It 'no error line at all: the last lines, as before' {
        Get-SIErrorLines -Lines @('[INFO] a', '[INFO] b') | Should -Be "[INFO] a`n[INFO] b"
    }
}
