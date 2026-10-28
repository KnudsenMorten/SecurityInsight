#Requires -Version 5.1
<#
    A QUERY SLICE IS ONLY EVER MADE SMALLER -- two Risk Analysis losses of rc11 (fix-request triage 2026-10-19):

    (1) THE FUTILE-PRUNE KILLED A SPLIT THAT WAS WORKING (si-ra-0905 "too large", two large schools): the report's CL rows
        are inlined per slice (123,478 rows: 6.0 MB at 4 slices, 1.5 MB at 16). Every 16-slice child was refused for its
        REQUEST size (413) and the sub-bucket pass pruned the whole subtree "as futile" -- built for 900 s timeouts, where
        splitting does not move the work -- although 64 slices carry ~380 KB each. Test-RASplitCanStillFit says when a
        refused request still shrinks with the split; such a child never counts towards the futile-prune.
    (2) A SLICE TOO LARGE FOR THE PROCESS'S MEMORY LOST THE REPORT (si-ra-0303 OutOfMemory, a small school's 4 GiB worker:
        Device_Missing_CVEs_Detailed, a 32,757-row slice, three runs in a row). Add-RAStreamBucketGuarded takes the slice
        back (Undo-RAStreamBucket: what it stored, its retrieved count, its accounts) and the report loop asks the SAME rows
        again in smaller slices -- the main loop and the sub-bucket pass both.

    The engine is one large script: the guarded function is lifted out by AST and defined here verbatim (as
    SI-BucketLossAccounting.Tests.ps1 does), so the tests exercise the shipping text. Offline; pwsh 7 and 5.1.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis'
    . (Join-Path $ra '_shared\RA-AutoBucketing.ps1')
    . (Join-Path $ra '_shared\RA-SqlStream.ps1')
    $script:Engine = Join-Path $ra 'Invoke-RiskAnalysis.ps1'
    $script:Code = Get-Content -Raw -LiteralPath $script:Engine
    $script:CodeNC = (($script:Code -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-RAStreamBucketGuarded' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    # the memory test the guard uses (RA-ProfileAugment.ps1), lifted the same way so this suite loads nothing else of that file
    $pa = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra '_shared\RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($pa.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-RAOutOfMemoryError' }, $true)).Extent.Text))

    function New-FakeStream {
        param([bool]$Staged = $false)
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $cur = @{ Ordinal = 7; Name = 'Device_Missing_CVEs_Detailed'; Retrieved = 0L; Staged = $Staged; Account = @{} }
        [pscustomobject]@{ Grain = 'Detailed'; TimeText = '2026-10-18T22:46:38.000'; CollectionId = 42; RunKey = 'Detailed|x'; Current = $cur
            Invoke = { param($q, $p, $m) $script:Sql.Add([pscustomobject]@{ Sql = $q; P = $p }); 3 } }
    }
    $script:Warned = New-Object System.Collections.Generic.List[string]
    function global:Write-Warn2 { param([string]$m) [void]$script:Warned.Add($m) }
}
AfterAll { Remove-Item -Path Function:\global:Write-Warn2 -ErrorAction SilentlyContinue }

Describe 'a refused request that still shrinks with the split is not futile (Test-RASplitCanStillFit)' {
    It 'a 413 with CL rows inlined per slice and a remainder under the limit: a finer split can fit' {
        Test-RASplitCanStillFit -Err 'Response status code does not indicate success: 413 Request Entity Too Large' -InlineBytes 1519514 -OverheadBytes 120000 | Should -BeTrue
    }
    It 'stays futile: a 900 s timeout, a result too large, nothing inlined, or a remainder that alone is over the limit' {
        Test-RASplitCanStillFit -Err 'The request was canceled due to the configured HttpClient.Timeout of 900 seconds elapsing. TaskCanceledException' -InlineBytes 1519514 -OverheadBytes 1000 | Should -BeFalse
        Test-RASplitCanStillFit -Err 'Query execution has exceeded the allowed limits' -InlineBytes 1519514 -OverheadBytes 1000 | Should -BeFalse
        Test-RASplitCanStillFit -Err '413 Request Entity Too Large' -InlineBytes 0 -OverheadBytes 1000 | Should -BeFalse
        Test-RASplitCanStillFit -Err '413 Request Entity Too Large' -InlineBytes 500000 -OverheadBytes 1048576 | Should -BeFalse
    }
    It 'reads the error record as the classifier does (message and details)' {
        $er = $null
        try { throw [System.Exception]::new('Response status code does not indicate success: 413 Request Entity Too Large') } catch { $er = $_ }
        Test-RASplitCanStillFit -Err $er -InlineBytes 10 -OverheadBytes 10 | Should -BeTrue
    }
    It 'is wired: the sub-bucket pass asks it before a child counts towards the futile-prune, and says the split goes on' {
        $script:CodeNC | Should -Match ([regex]::Escape('$__subCanFit = ($subAction -eq ''Split'') -and (Test-RASplitCanStillFit -Err $_ -InlineBytes ([long]$script:_LastHybridInlineBytes) -OverheadBytes ([long]$script:_LastHybridQueryBodyOverheadBytes))'))
        $script:CodeNC | Should -Match ([regex]::Escape('if ($subAction -eq ''Split'' -and -not $__subCanFit) {'))
        $script:CodeNC | Should -Match 'a finer split makes it smaller -- split again \(depth'
    }
}

Describe 'a connection that failed is the platform: the slice is asked again, never lost (Get-RABucketFailureAction)' {
    It 'a part asked ahead that failed "while sending the request" is Retry (live 2026-10-19: one of 14 slices lost, the Summary NOT complete)' {
        Get-RABucketFailureAction -Err 'Exception calling "GetResult" with "0" argument(s): "An error occurred while sending the request."' | Should -Be 'Retry'
        Get-RABucketFailureAction -Err 'The response ended prematurely.' | Should -Be 'Retry'
        Get-RABucketFailureAction -Err 'An existing connection was forcibly closed by the remote host.' | Should -Be 'Retry'
        Get-RABucketFailureAction -Err 'Connection reset by peer' | Should -Be 'Retry'
    }
    It 'a query defect stays a defect and a size failure stays a split' {
        Get-RABucketFailureAction -Err 'Fix semantic errors in your query -- SemanticError' | Should -Be 'Defect'
        Get-RABucketFailureAction -Err 'Query execution has exceeded the allowed limits' | Should -Be 'Split'
    }
}

Describe 'a slice too large for memory is taken back and asked again smaller (Add-RAStreamBucketGuarded)' {
    BeforeEach { $script:Warned.Clear(); $script:RAStreamOn = $true; $script:RAProof = $null }
    It 'out of memory: what the slice stored, its retrieved rows and its accounts are removed -- $false, the caller splits' {
        $script:RAStream = New-FakeStream
        $script:RAStream.Current.Retrieved = 100L
        $script:RAStream.Current.Account['2/3'] = @{ In = 5 }; $script:RAStream.Current.Account['dfc:2/3'] = @{ Pre = 5 }; $script:RAStream.Current.Account['1/3'] = @{ In = 9 }
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) $script:RAStream.Current.Retrieved += @($Rows).Count; throw [System.OutOfMemoryException]::new() }
        $rows = @(1..40 | ForEach-Object { [pscustomobject]@{ i = $_ } })
        (Add-RAStreamBucketGuarded -Rows $rows -Bucket '2/3') | Should -BeFalse
        $script:RAStream.Current.Retrieved | Should -Be 100 -Because 'the slice''s rows leave the count -- they are asked again'
        @($script:RAStream.Current.Account.Keys) | Should -Be @('1/3') -Because 'only this slice''s accounts are taken back'
        $script:Sql.Count | Should -Be 1
        $script:Sql[0].Sql | Should -Match 'DELETE FROM sidata\.Finding'
        $script:Sql[0].P.Bucket | Should -Be '2/3' -Because 'only THIS slice''s rows, never the report''s'
        ($script:Warned -join "`n") | Should -Match 'query slice 2/3: not enough memory to process its 40 row\(s\) at once -- nothing of it is kept \(3 stored row\(s\) removed\); the same rows are asked again in smaller slices'
    }
    It 'a staged Summary slice is taken back from the stage' {
        $script:RAStream = New-FakeStream -Staged $true
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) throw 'Exception of type ''System.OutOfMemoryException'' was thrown.' }
        (Add-RAStreamBucketGuarded -Rows @(1, 2, 3) -Bucket 'sub:5/16') | Should -BeFalse
        $script:Sql[0].Sql | Should -Match 'DELETE FROM sidata\.RaStage'
        $script:Sql[0].P.Bucket | Should -Be 'sub:5/16'
    }
    It 'any other error is thrown as before; a slice in is $true; a complete-result slice or a single row is never split' {
        $script:RAStream = New-FakeStream
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) throw 'Timeout expired' }
        { Add-RAStreamBucketGuarded -Rows @(1, 2) -Bucket '1/2' } | Should -Throw '*Timeout expired*'
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) }
        (Add-RAStreamBucketGuarded -Rows @(1, 2) -Bucket '1/2') | Should -BeTrue
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) throw [System.OutOfMemoryException]::new() }
        { Add-RAStreamBucketGuarded -Rows @(1, 2) -Bucket '1/2' -Complete } | Should -Throw
        { Add-RAStreamBucketGuarded -Rows @(1) -Bucket '1/2' } | Should -Throw -Because 'one row cannot be made smaller'
        $script:Sql.Count | Should -Be 0 -Because 'nothing is taken back when the slice is not split'
    }
    It 'the bucket proof (on demand) says it cannot prove a report whose slice was taken back' {
        $script:RAStream = New-FakeStream
        $script:RAProof = @{ On = $true; Max = 20000; Sigs = (New-Object 'System.Collections.Generic.Dictionary[string,int]'); Rows = 3L; Over = $false }
        $script:RAProof.Sigs['a'] = 1
        function Add-RAStreamBucket { param($Rows, $Bucket, [switch]$Complete) throw [System.OutOfMemoryException]::new() }
        $null = Add-RAStreamBucketGuarded -Rows @(1, 2) -Bucket '1/2'
        $script:RAProof.Over | Should -BeTrue
        $script:RAProof.Sigs.Count | Should -Be 0
    }
    It 'is wired: the main loop and the sub-bucket pass write every slice through the guard; a slice taken back is split, never lost' {
        $script:CodeNC | Should -Not -Match 'Add-RAStreamBucket -Rows \$bucketResult' -Because 'the main loop goes through the guard'
        $script:CodeNC | Should -Not -Match ([regex]::Escape("Add-RAStreamBucket -Rows @(`$subConv.Rows)")) -Because 'the sub-bucket pass goes through the guard'
        $script:CodeNC | Should -Match ([regex]::Escape('$__slIn = Add-RAStreamBucketGuarded -Rows $bucketResult -Bucket'))
        $script:CodeNC | Should -Match '(?s)if \(-not \$__slIn\) \{.{0,400}\$__abSplitCause\[\[int\]\$b\] = \$true.{0,80}\[void\]\$failedBucketIndices\.Add\(\$b\).{0,40}continue'
        $script:CodeNC | Should -Match ([regex]::Escape('$__subIn = Add-RAStreamBucketGuarded -Rows @($subConv.Rows) -Bucket $subLabel'))
        # #848: a sub-slice taken back is split again until it fits (no depth cap) -- queued after its siblings
        $script:CodeNC | Should -Match '(?s)if \(-not \$__subIn\) \{.{0,700}\$__memKids\.Add\(@\{ N = \$subN; T = \$newT; RC = \$subRC; RI = \$subRI'
        $script:CodeNC | Should -Match 'too large for this worker''s memory at the finest split'
        $script:CodeNC | Should -Match ([regex]::Escape('if ($__subIn -and [int]$newT -gt [int]$__abSplitWorking)')) -Because 'a slice taken back is not a count that worked'
        $script:CodeNC | Should -Match ([regex]::Escape('-and [int]$__abMemSplit -eq 0)')) -Because 'a memory split is never skipped as a futile timeout pass'
    }
}
