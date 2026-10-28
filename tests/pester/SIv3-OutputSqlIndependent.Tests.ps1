#Requires -Version 5.1
<#
    THE DATABASE DOES NOT DEPEND ON LOG ANALYTICS (owner 2026-10-12: "Yes, make them independent").

    The records of a collection (what each provider returned) are written to the database; the CI build reads them
    there. They used to be written from INSIDE the Log Analytics function of the Output stage, after the profile post --
    so a post that failed, was skipped (no sign-in for it), returned early, or was never asked for (outputs without Log
    Analytics) meant NO records in the database for that run. What these tests keep true:
      * the Output stage has two outputs, reported apart ('LA' and 'SQL'), and neither waits for the other:
          the post throws / fails / is skipped / is not asked for -> the records are written and their collection closed;
          the database cannot be written -> the post is still made, and the collection is NOT closed;
      * the run's outcome names the one that failed (run health carries it): a failed post = success-partial; a failed
        database write = error (the step fails, the source is a dropout) whatever else was written;
      * the audit before the post is a verdict on the ROWS and holds both; a dry run and a mock run write no records;
      * the optional copy of the records to Log Analytics (SI_LaExport) never decides what the database holds;
      * a run collected in parts follows the same rule: a bucket fails only when it did not reach the database.
    The stage is run with its two outputs' edges faked (the post; the database seam) -- the record writer, the batches,
    the pins and the feed close are the real ones. Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\asset-profiling\_shared\Write-SIStyle.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordSql.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordHandover.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-RunOutcome.ps1')
    . (Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1')

    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-12T02:00:00', [DateTimeKind]::Utc)
    function script:JItems([string]$j) { $a = ConvertFrom-Json -InputObject $j; @($a | ForEach-Object { $_ }) }
    # a database seam that records every statement and answers the write's and the close's one row
    $script:FailWrites = $false
    function script:Seam {
        $script:Calls = New-Object System.Collections.Generic.List[object]
        {
            param($Sql, $Params, $Mode)
            $script:Calls.Add(@{ Sql = $Sql; Params = $Params; Mode = $Mode })
            if ($script:FailWrites -and $Params.ContainsKey('r')) { throw 'the database did not answer' }
            if ($Params.ContainsKey('r')) { return [pscustomobject]@{ Seen = @(JItems $Params.r).Count; Changed = @(JItems $Params.r).Count; Identifiers = 0 } }
            if ($Params.ContainsKey('k')) { return [pscustomobject]@{ Closed = @(JItems $Params.k).Count; Feeds = @(JItems $Params.f).Count } }
            [pscustomobject]@{ Properties = 0; Added = 0; NewContext = 0 }
        }
    }
    function script:Get-Writes { @($script:Calls | Where-Object { $_.Params.ContainsKey('r') }) }
    function script:Get-Closes { @($script:Calls | Where-Object { $_.Params.ContainsKey('k') }) }
    function script:Set-Capture([int]$Count = 5, [string]$Engine = 'publicip') {
        $null = Reset-SIRecordCapture -Engine $Engine -Clear
        foreach ($i in 1..$Count) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i"; displayName = "User $i" } }
        Set-SIRecordPull -Provider entra -Complete $true
    }
    # the run's context as the Output stage reads it (the public IP engine: no scope filter stands between the stage's
    # records and its outputs)
    function script:New-Ctx([string[]]$Sinks = @('LA'), [bool]$WhatIf = $false, [string]$Mode = 'Real') {
        [pscustomobject]@{ Engine = 'publicip'; Sinks = $Sinks; RunId = 'r1'; CollectionTime = $script:Now; WhatIf = $WhatIf
                           StorageContext = [pscustomobject]@{ Mode = $Mode }; StagingContainer = 'c'; ShardIndex = 0; ShardCount = 1 }
    }

    # ---- the stage's input and the EDGES of its two outputs ----
    # Defined INSIDE the runner (dot-sourced there), so they are the nearest definitions for the stage it then calls --
    # and nothing outside the runner sees them (the last-step tests below call the real record publish).
    $script:Order = New-Object System.Collections.Generic.List[string]
    # the database edge: the REAL record publish, given the recording seam instead of the install's database
    $script:RealPublish = (Get-Command -Name Publish-SIRecords -CommandType Function).ScriptBlock
    $script:Edges = {
        function Read-SIStageShards { @($script:StageRecords) }
        function Publish-SIRecords {
            param($RunContext, $ProfileRows, $Outcome)
            $script:Order.Add('sql'); $script:SqlGotRows = @($ProfileRows).Count
            & $script:RealPublish -RunContext $RunContext -ProfileRows $ProfileRows -Outcome $Outcome -SqlInvoke $script:TheSeam
        }
        # the Log Analytics edge: builds "rows" as the real function does (hands them over through -Built), then posts or not
        #   ok | throw (the post throws) | failed (the post answered FAILED) | skipped (no sign-in) | held (the audit stopped
        #   it) | throw-early (the row builder threw before the rows were whole)
        function Write-SIClassificationToLogAnalytics {
            param($RunContext, $Records, $Built, [switch]$RowsOnly)
            $script:Order.Add($(if ($RowsOnly) { 'rows-only' } else { 'la' }))
            $script:LaGotTable = ($Built -is [System.Collections.IDictionary])
            if ($script:LaMode -eq 'throw-early') { throw 'the row builder threw' }
            if ($script:LaMode -eq 'held') {
                if ($script:LaGotTable) { $Built['Held'] = 'the profile rows are not usable (1 critical column(s) empty: Tier) -- the records were not written, so they keep their last good state' }
                return 'FAILED: critical schema columns empty -- LA ingest skipped to prevent stale data.'
            }
            if ($script:LaGotTable) { $Built['Rows'] = @([pscustomobject]@{ PrimaryEntityId = 'u1' }, [pscustomobject]@{ PrimaryEntityId = 'u2' }); $Built['Ready'] = $true }
            if ($RowsOnly) { return $null }
            switch ($script:LaMode) {
                'throw'   { throw 'the endpoint refused the post (403)' }
                'failed'  { return 'FAILED: the endpoint refused the post (403)' }
                'skipped' { return 'SKIPPED -- no auth configured.' }
                default   { return 'OK -- 2 rows -> SI_PublicIP_Profile_CL' }
            }
        }
    }
    function script:Invoke-Stage {
        param([string]$La = 'ok', [string[]]$Sinks = @('LA'), [bool]$WhatIf = $false, [string]$Mode = 'Real', [bool]$FailSql = $false, [int]$Records = 2)
        . $script:Edges
        Set-Capture
        $script:Order.Clear(); $script:LaMode = $La; $script:LaGotTable = $null; $script:SqlGotRows = -1
        $script:TheSeam = Seam; $script:FailWrites = $FailSql
        $script:StageRecords = @(); if ($Records -gt 0) { $script:StageRecords = @(1..$Records | ForEach-Object { [pscustomobject]@{ AssetId = "a$_" } }) }
        $saved = $script:SIRecordBatchSize
        try {
            $script:SIRecordBatchSize = 2
            $r = Invoke-SIOutput -RunContext (New-Ctx -Sinks $Sinks -WhatIf $WhatIf -Mode $Mode) 3>$null 6>$null
        } finally { $script:SIRecordBatchSize = $saved; $script:FailWrites = $false }
        $r | Add-Member -NotePropertyName Outcome -NotePropertyValue (Get-SIRunOutcome -StageResults @{ Output = $r } -IngestNotes @()) -PassThru
    }
}

AfterAll {
    foreach ($n in 'SIRecordCaptureState', 'SI_LaExport') { Remove-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue }
    Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue
}

Describe 'CONTROL: both outputs written' {
    BeforeAll { $script:R = Invoke-Stage -La 'ok' }
    It 'the post is made, then the records are written in batches and their collection is closed once, last' {
        @($script:Order) | Should -Be @('la', 'sql')
        @(Get-Writes | ForEach-Object { @(JItems $_.Params.r).Count }) | Should -Be @(2, 2, 1)
        @(Get-Closes).Count | Should -Be 1
        $script:Calls.IndexOf(@(Get-Closes)[0]) | Should -BeGreaterThan $script:Calls.IndexOf(@(Get-Writes)[2])
    }
    It 'each output has its own line, and the run is a success' {
        $script:R.SinkResults['LA'] | Should -Match '^OK -- '
        $script:R.SinkResults['SQL'] | Should -Be 'OK -- 5 record(s) -> the database (5 changed), the collection is complete'
        $script:R.Outcome.ExitReason | Should -Be 'success'
        $script:SqlGotRows | Should -Be 2 -Because 'the records take their profile part from the built rows'
    }
}

Describe 'the Log Analytics post fails, is skipped or is not asked for -> the records are in the database, and closed' {
    It 'the post THROWS: records written and closed; the stage names Log Analytics; the run is partial' {
        $r = Invoke-Stage -La 'throw'
        @(Get-Writes).Count | Should -Be 3
        @(Get-Closes).Count | Should -Be 1
        $r.SinkResults['LA'] | Should -Be 'FAILED: the endpoint refused the post (403)'
        $r.SinkResults['SQL'] | Should -Match '^OK -- 5 record\(s\) -> the database'
        $r.Outcome.ExitReason | Should -Be 'success-partial'
        $r.Outcome.Message | Should -Be 'LA was not written (the endpoint refused the post (403))' -Because 'run health carries which one failed -- and only that one'
        $r.Summary | Should -Match '1/2 sink\(s\) OK'
    }
    It 'the post answers FAILED (its own error handling): the same' {
        $r = Invoke-Stage -La 'failed'
        @(Get-Closes).Count | Should -Be 1
        $r.SinkResults['SQL'] | Should -Match '^OK -- '
        $r.Outcome.ExitReason | Should -Be 'success-partial'
        $r.Outcome.Message | Should -Not -Match 'SQL'
    }
    It 'no sign-in for Log Analytics (the post is SKIPPED): the records are still written and closed' {
        $r = Invoke-Stage -La 'skipped'
        $r.SinkResults['LA'] | Should -Match '^SKIPPED -- no auth configured'
        @(Get-Writes).Count | Should -Be 3
        @(Get-Closes).Count | Should -Be 1
        $r.SinkResults['SQL'] | Should -Match '^OK -- '
    }
    It 'outputs WITHOUT Log Analytics: the rows are built for the records, nothing is posted, nothing is reported for LA' {
        $r = Invoke-Stage -La 'ok' -Sinks @('JSON')
        @($script:Order) | Should -Be @('rows-only', 'sql')
        $r.SinkResults.ContainsKey('LA') | Should -BeFalse
        $r.SinkResults['SQL'] | Should -Match '^OK -- 5 record\(s\)'
        @(Get-Closes).Count | Should -Be 1
        $r.Outcome.ExitReason | Should -Be 'success'
    }
}

Describe 'the database cannot be written -> the post is still made, the collection is NOT closed, and the step FAILS' {
    # Owner 2026-10-12: "Yes, fail the step". A collection whose records did not reach the database is a failed
    # collection in ONE process exactly as in a run collected in parts: the run is an error (the engine throws, the job
    # ends non-zero), the pipeline marks the source dropped, and nothing of that collection is closed as complete.
    BeforeAll { $script:R = Invoke-Stage -La 'ok' -FailSql $true }
    It 'the post was made first and is reported as written' {
        @($script:Order) | Should -Be @('la', 'sql')
        $script:R.SinkResults['LA'] | Should -Match '^OK -- '
    }
    It 'every batch was tried, and the close statement was never sent' {
        @(Get-Writes).Count | Should -Be 3
        @(Get-Closes).Count | Should -Be 0 -Because 'a collection that is not all in the database never counts as complete'
    }
    It 'the stage names the database, and the run is an ERROR although Log Analytics has the rows' {
        $script:R.SinkResults['SQL'] | Should -Match '^FAILED: 5 of 5 record\(s\) could not be written to the database -- this collection is NOT complete'
        $script:R.Outcome.ExitReason | Should -Be 'error'
        $script:R.Outcome.DatabaseFailed | Should -BeTrue
        $script:R.Outcome.Message | Should -Match '^SQL was not written \('
        $script:R.Outcome.Message | Should -Not -Match 'LA was not written'
    }
    It 'JSON and Excel files written next to it do NOT turn it into a success (the container''s default outputs)' {
        $r = Invoke-Stage -La 'ok' -Sinks @('JSON', 'Excel', 'LA') -FailSql $true
        $r.SinkResults.ContainsKey('JSON') | Should -BeTrue
        $r.SinkResults.ContainsKey('Excel') | Should -BeTrue
        $r.SinkResults['LA'] | Should -Match '^OK -- '
        $r.Outcome.ExitReason | Should -Be 'error'
        $r.Outcome.DatabaseFailed | Should -BeTrue
        @(Get-Closes).Count | Should -Be 0
    }
    It 'BOTH fail: an error, and it is the database''s' {
        $r = Invoke-Stage -La 'failed' -FailSql $true
        @(Get-Closes).Count | Should -Be 0
        $r.Outcome.ExitReason | Should -Be 'error'
        $r.Outcome.DatabaseFailed | Should -BeTrue
        $r.Outcome.Message | Should -Match 'LA was not written'
        $r.Outcome.Message | Should -Match 'SQL was not written'
    }
    It 'CONTROL: the post fails and the records ARE written -- still success-partial, also with the file outputs' {
        foreach ($sinks in @(, @('LA')), @(, @('JSON', 'Excel', 'LA'))) {
            $r = Invoke-Stage -La 'failed' -Sinks $sinks[0]
            $r.Outcome.ExitReason | Should -Be 'success-partial'
            $r.Outcome.DatabaseFailed | Should -BeFalse
            @(Get-Closes).Count | Should -Be 1
        }
    }
    It 'CONTROL: both written -- success' {
        $r = Invoke-Stage -La 'ok' -Sinks @('JSON', 'Excel', 'LA')
        $r.Outcome.ExitReason | Should -Be 'success'
        $r.Outcome.DatabaseFailed | Should -BeFalse
    }
    It 'the rule, pure: a failed database output is an error whatever else was written; anything else is as it was' {
        $bad = 'FAILED: 2 of 7 record(s) could not be written to the database'
        foreach ($s in @{ SQL = $bad }, @{ SQL = $bad; LA = 'OK -- 3 rows' }, @{ SQL = $bad; LA = 'OK -- 3 rows'; JSON = 'x.json'; Excel = 'x.csv' }) {
            $o = Get-SISinkOutcome -SinkResults $s
            $o.ExitReason | Should -Be 'error'
            $o.DatabaseFailed | Should -BeTrue
        }
        (Get-SISinkOutcome -SinkResults @{ SQL = 'OK -- 7 record(s)'; LA = 'FAILED: 403'; JSON = 'x.json' }).ExitReason | Should -Be 'success-partial'
        (Get-SISinkOutcome -SinkResults @{ SQL = 'OK -- 7 record(s)'; LA = 'FAILED: 403' }).ExitReason | Should -Be 'success-partial'
        (Get-SISinkOutcome -SinkResults @{ SQL = 'OK -- 7 record(s)'; LA = 'OK -- 3 rows' }).ExitReason | Should -Be 'success'
        (Get-SISinkOutcome -SinkResults @{ SQL = 'skipped (no database is configured -- the records were not kept)'; LA = 'OK -- 3 rows' }).ExitReason | Should -Be 'success'
        (Get-SISinkOutcome -SinkResults @{ SQL = 'PARTIAL: 7 record(s) are in the database'; LA = 'OK -- 3 rows' }).ExitReason | Should -Be 'success-partial'
        # no database output at all (a run that keeps no records): exactly as before
        (Get-SISinkOutcome -SinkResults @{ LA = 'FAILED: x'; Excel = 'x.csv' }).ExitReason | Should -Be 'success-partial'
        (Get-SISinkOutcome -SinkResults @{ LA = 'FAILED: x' }).ExitReason | Should -Be 'error'
        # the run's outcome carries it past another stage's partial result
        $run = Get-SIRunOutcome -StageResults @{ Output = [pscustomobject]@{ SinkResults = @{ SQL = $bad; LA = 'OK' } }; Recommendations = [pscustomobject]@{ Summary = 'INCOMPLETE -- not published' } } -IngestNotes @()
        ($run.ExitReason, $run.DatabaseFailed) | Should -Be @('error', $true)
        (Get-SIRunOutcome -StageResults @{ Output = [pscustomobject]@{ SinkResults = @{ LA = 'OK' } } } -IngestNotes @()).DatabaseFailed | Should -BeFalse
    }
    It 'WIRING: the engine throws on it, saying what it is -- so the job ends non-zero and the step fails' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $run | Should -Match "(?s)if \(\`$__outcome\.ExitReason -eq 'error'\) \{.{0,500}if \(\`$__outcome\.PSObject\.Properties\['DatabaseFailed'\] -and \`$__outcome\.DatabaseFailed\) \{\s+throw \('The records could not be written to the database -- "
        $run.IndexOf("throw ('The records could not be written to the database") | Should -BeLessThan $run.IndexOf("throw ('Nothing was published")
        # the pipeline then does the rest: a failed collection step is a dropout
        (Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1') -Raw) | Should -Match '\$good = \$SourceState\.Dropped\(\$k, \$since, \$nowU, \[string\]\$st\.Error\)'
    }
}

Describe 'what holds both, and what writes no records at all' {
    It 'the audit before the post is a verdict on the ROWS: neither output is written, each says so' {
        $r = Invoke-Stage -La 'held'
        @($script:Order) | Should -Be @('la') -Because 'the record publish is not even called'
        $script:Calls.Count | Should -Be 0
        $r.SinkResults['LA'] | Should -Match '^FAILED: critical schema columns empty'
        $r.SinkResults['SQL'] | Should -Match '^FAILED: the profile rows are not usable \(1 critical column\(s\) empty: Tier\)'
    }
    It 'and that run is a failed collection too -- its records did not reach the database -- also with file outputs written' {
        $r = Invoke-Stage -La 'held' -Sinks @('JSON', 'Excel', 'LA')
        $r.Outcome.ExitReason | Should -Be 'error'
        $r.Outcome.DatabaseFailed | Should -BeTrue
        $script:Calls.Count | Should -Be 0
    }
    It 'the row builder throws before the rows are whole: the stage fails, as it always did' {
        { Invoke-Stage -La 'throw-early' } | Should -Throw -ExpectedMessage '*the row builder threw*'
    }
    It 'a DRY RUN writes no records and reports no database output' {
        $r = Invoke-Stage -La 'ok' -Sinks @('JSON') -WhatIf $true
        $script:Order.Count | Should -Be 0
        $script:Calls.Count | Should -Be 0
        $r.SinkResults.ContainsKey('SQL') | Should -BeFalse
    }
    It 'MOCK data is never kept: the post behaves exactly as before (no table handed over), no database output' {
        $r = Invoke-Stage -La 'skipped' -Mode 'Mock'
        @($script:Order) | Should -Be @('la')
        $script:LaGotTable | Should -BeFalse -Because 'without a table the function returns at once when it has no sign-in, as it always did'
        $r.SinkResults.ContainsKey('SQL') | Should -BeFalse
        $script:Calls.Count | Should -Be 0
    }
    It 'no records at all: both outputs say so, and the run is a success' {
        $r = Invoke-Stage -La 'ok' -Records 0
        $r.SinkResults['LA'] | Should -Be 'skipped (no records to write)'
        $r.SinkResults['SQL'] | Should -Be 'skipped (no records to write)'
        $r.Outcome.ExitReason | Should -Be 'success'
    }
    It 'the reasons a run keeps no records (pure)' {
        Get-SIOutputRecordsSkipReason -RunContext (New-Ctx) -CaptureState ([pscustomobject]@{}) -Setting $null | Should -Be ''
        Get-SIOutputRecordsSkipReason -RunContext (New-Ctx -WhatIf $true) -CaptureState ([pscustomobject]@{}) -Setting $null | Should -Match 'dry run'
        Get-SIOutputRecordsSkipReason -RunContext (New-Ctx -Mode 'Mock') -CaptureState ([pscustomobject]@{}) -Setting $null | Should -Match 'mock'
        Get-SIOutputRecordsSkipReason -RunContext (New-Ctx) -CaptureState $null -Setting $null | Should -Match 'no records were captured'
        Get-SIOutputRecordsSkipReason -RunContext (New-Ctx) -CaptureState ([pscustomobject]@{}) -Setting 'off' | Should -Match 'is off'
    }
}

Describe 'the database output''s result text (pure)' {
    It 'written and closed is OK; a part of a run hands over' {
        Get-SIOutputRecordsResultText -Outcome @{ State = 'written'; Seen = 7; Changed = 3; SqlFailed = 0; Closed = $true } | Should -Be 'OK -- 7 record(s) -> the database (3 changed), the collection is complete'
        Get-SIOutputRecordsResultText -Outcome @{ State = 'handed-over'; Seen = 4 } | Should -Match '^OK -- 4 record\(s\) handed over'
    }
    It 'a batch that could not be written, or a close that failed, is FAILED' {
        Get-SIOutputRecordsResultText -Outcome @{ State = 'written'; Seen = 7; SqlFailed = 2; Closed = $false } | Should -Match '^FAILED: 2 of 7 record\(s\) could not be written to the database'
        Get-SIOutputRecordsResultText -Outcome @{ State = 'written'; Seen = 7; SqlFailed = 0; Closed = $false } | Should -Match '^FAILED: the collection could not be closed in the database'
        Get-SIOutputRecordsResultText -Outcome @{ State = 'failed'; Error = 'timeout' } | Should -Match '^FAILED: the records could not be written to the database -- timeout'
    }
    It 'only the copy to Log Analytics failed: PARTIAL -- the database is complete' {
        $t = Get-SIOutputRecordsResultText -Outcome @{ State = 'written'; Seen = 7; SqlFailed = 0; Closed = $true; ExportFailed = 2; ExportError = '403' }
        $t | Should -Match '^PARTIAL: 7 record\(s\) are in the database and the collection is complete; the copy to Log Analytics \(SI_LaExport\) failed -- 403'
        (Get-SISinkOutcome -SinkResults @{ SQL = $t }).ExitReason | Should -Be 'success-partial'
    }
    It 'nothing to write is not a failure: the run''s outcome reads it as a correct, empty publish' {
        foreach ($s in 'off', 'no-database', 'none', '') {
            $t = Get-SIOutputRecordsResultText -Outcome @{ State = $s }
            $t | Should -Match '^skipped \('
            (Get-SISinkOutcome -SinkResults @{ LA = 'OK -- 1 rows'; SQL = $t }).ExitReason | Should -Be 'success'
        }
    }
    It 'the stage''s edge never throws: a publish that throws is the database output''s own FAILED' {
        $t = Write-SIOutputRecordsToSql -RunContext (New-Ctx) -Built @{ Rows = @(); Ready = $true } -Publish { param($c, $rows, $o) throw 'no route to the database' }
        $t | Should -Match '^FAILED: the records could not be written to the database -- no route to the database'
        (Write-SIOutputRecordsToSql -RunContext (New-Ctx) -Built @{} -Why 'FAILED: row builder not found for engine "x"' -Publish { throw 'never called' }) |
            Should -Match '^FAILED: the profile rows could not be built, so the records were not written \(row builder not found for engine "x"\)'
    }
}

Describe 'the optional copy to Log Analytics (SI_LaExport) never decides what the database holds' {
    BeforeEach {
        Set-Capture -Engine 'identity'
        $global:SI_LaExport = 'records'
        $script:Posts = New-Object System.Collections.Generic.List[string]
    }
    AfterEach { Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue; Remove-Variable -Name SI_LaExport -Scope Global -ErrorAction SilentlyContinue }
    It 'the copy fails on every batch: every batch is still written to the database and the collection is closed' {
        function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) $script:Posts.Add($TableName); throw 'the rule refused the post (403)' }
        $o = @{}; $w = $null
        $saved = $script:SIRecordBatchSize
        try {
            $script:SIRecordBatchSize = 2
            $r = & $script:RealPublish -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'r1' }) -Engine 'identity' -SqlInvoke (Seam) -Outcome $o -WarningVariable w 3>$null 6>$null
        } finally { $script:SIRecordBatchSize = $saved }
        @(Get-Writes).Count | Should -Be 3 -Because 'the batches after the first failed copy are written too'
        @(Get-Closes).Count | Should -Be 1
        $r.Sql | Should -Be 5
        ($o['State'], $o['SqlFailed'], $o['Closed'], $o['ExportFailed']) | Should -Be @('written', 0, $true, 3)
        @($w | Where-Object { "$_" -match 'the copy to Log Analytics \(SI_LaExport\) failed' }).Count | Should -Be 1 -Because 'it is said once, not once per batch'
        Get-SIOutputRecordsResultText -Outcome $o | Should -Match '^PARTIAL: 5 record\(s\) are in the database and the collection is complete'
    }
    It 'the database write comes BEFORE the copy of the same batch' {
        $script:Seq = New-Object System.Collections.Generic.List[string]
        function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) $script:Seq.Add('copy'); @($Rows).Count }
        $seam = Seam
        $rec = { param($Sql, $Params, $Mode) if ($Params.ContainsKey('r')) { $script:Seq.Add('db') }; & $seam $Sql $Params $Mode }
        $null = & $script:RealPublish -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'r1' }) -Engine 'identity' -SqlInvoke $rec 3>$null 6>$null
        @($script:Seq | Select-Object -First 2) | Should -Be @('db', 'copy')
    }
    It 'CONTROL: the copy works -- nothing is counted, and the result is OK' {
        function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) @($Rows).Count }
        $o = @{}
        $null = & $script:RealPublish -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'r1' }) -Engine 'identity' -SqlInvoke (Seam) -Outcome $o 3>$null 6>$null
        $o['ExportFailed'] | Should -Be 0
        Get-SIOutputRecordsResultText -Outcome $o | Should -Match '^OK -- 5 record\(s\)'
    }
    It 'the outcome tells "nothing to write" from "written" (the return value is as it was)' {
        $o = @{}
        $null = Reset-SIRecordCapture -Engine 'identity' -Clear
        (& $script:RealPublish -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'r1' }) -Engine 'identity' -SqlInvoke (Seam) -Outcome $o 6>$null) | Should -BeNullOrEmpty
        $o['State'] | Should -Be 'none'
    }
}

Describe 'a run collected in parts follows the same rule' {
    BeforeAll {
        function script:MemStore {
            $m = @{}
            [pscustomobject]@{ Data = $m
                Write = { param($Path, $Text) $m[$Path] = [string]$Text }.GetNewClosure()
                Read  = { param($Path) $m[$Path] }.GetNewClosure()
                List  = { param($Prefix) @($m.Keys | Where-Object { $_.StartsWith($Prefix) } | Sort-Object) }.GetNewClosure() }
        }
        # the last step, with the REAL record publish (the stage tests' edges live inside their own runner)
        function script:Invoke-LastStep([bool]$FailSql = $false, [bool]$FailCopy = $false, [int]$PartsFailed = 0) {
            $s = MemStore
            $null = Reset-SIRecordCapture -Engine 'identity' -Clear
            foreach ($i in 1..30) { Add-SIRecordPart -Provider entra -RecordType user -Key "U$i" -Part user -Object @{ id = "U$i" } }
            Set-SIRecordPull -Provider entra -Complete $true
            $null = Save-SIRecordHandover -Store $s -Engine identity -RunId 'r3' -Who 'discover' -Buckets 3
            $seam = Seam; $script:FailWrites = $FailSql
            if ($FailCopy) { $global:SI_LaExport = 'records'; function global:Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) throw 'post refused' } }
            try { Publish-SIRecordHandover -Store $s -Engine identity -RunId 'r3' -RunContext ([pscustomobject]@{ CollectionTime = $script:Now; RunId = 'r3' }) -SqlInvoke $seam -PartsFailed $PartsFailed 3>$null 6>$null }
            finally { $script:FailWrites = $false; Remove-Item Function:\global:Send-SIObjectMapRows -ErrorAction SilentlyContinue; Remove-Variable -Name SI_LaExport -Scope Global -ErrorAction SilentlyContinue }
        }
    }
    It 'CONTROL: every bucket written, the run''s collection closed once' {
        $res = Invoke-LastStep
        ($res.Buckets, $res.Failed, $res.SqlFailed, $res.ExportFailed, $res.Closed) | Should -Be @(3, 0, 0, 0, $true)
        @(Get-Closes).Count | Should -Be 1
    }
    It 'the copy to Log Analytics fails: NO bucket fails -- the records are in the database and the collection is closed' {
        $res = Invoke-LastStep -FailCopy $true
        $res.Failed | Should -Be 0 -Because 'the container fails the step on Failed; a failed copy is not a failed bucket'
        $res.ExportFailed | Should -BeGreaterThan 0
        $res.Closed | Should -BeTrue
        @(Get-Writes).Count | Should -Be 3
        @(Get-Closes).Count | Should -Be 1
    }
    It '#720: a part of the run FAILED: every record that is there is written, but the collection is NOT closed (the failed part''s objects are unknown, never read as removed)' {
        $res = Invoke-LastStep -PartsFailed 6
        ($res.Buckets, $res.Failed, $res.SqlFailed) | Should -Be @(3, 0, 0) -Because 'the buckets themselves were published'
        @(Get-Writes).Count | Should -Be 3
        $res.Closed | Should -BeFalse
        @(Get-Closes).Count | Should -Be 0
    }
    It 'the database write fails: the buckets are counted as failed and the collection is NOT closed' {
        $res = Invoke-LastStep -FailSql $true
        $res.Failed | Should -Be 3
        $res.SqlFailed | Should -Be 30
        $res.Closed | Should -BeFalse
        @(Get-Closes).Count | Should -Be 0
    }
    It 'a part hands its records over from the same independent call -- whatever its own post did' {
        $out = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'))
        $cap = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1'))
        $out | Should -Match 'Publish-SIRecords -RunContext \$RunContext -ProfileRows @\(\$flat\) -Outcome \$outcome'
        $cap | Should -Match "(?s)SI_COLLECT_PHASE'\) -eq 'parts'\) \{.{0,1800}Save-SIRecordHandover.{0,700}& \`$note 'handed-over'"
    }
    It 'WIRING: the container fails the records process on the database only, and says a failed copy' {
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $c | Should -Match "(?s)\[int\]\`$res\.ExportFailed -gt 0\) \{\s+Write-Warning \('\[parts\] \{0\}: the copy of the records to Log Analytics failed.{0,200}\}\s+if \(\`$res\.Failed -gt 0\) \{ exit 1 \}\s+exit 0"
    }
}

Describe 'WIRING: the real Output stage' {
    BeforeAll {
        $script:Src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'))
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Output.ps1'), [ref]$null, [ref]$null)
        $script:LaFn = ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Write-SIClassificationToLogAnalytics' }, $true) | Select-Object -First 1)
        $script:StageFn = ($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-SIOutput' }, $true) | Select-Object -First 1)
    }
    It 'the Log Analytics function no longer writes the records (they depended on its post there)' {
        @($script:LaFn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Publish-SIRecords' }, $true)).Count | Should -Be 0
    }
    It 'it hands the built rows over BEFORE anything is posted, and only then says it has no sign-in' {
        $t = $script:LaFn.Extent.Text
        $hand = $t.IndexOf("`$Built['Rows'] = `$flat; `$Built['Ready'] = `$true")
        $hand | Should -BeGreaterThan 0
        $hand | Should -BeGreaterThan $t.IndexOf('row builder: built')
        $hand | Should -BeGreaterThan $t.IndexOf('Get-SIDeadCriticalColumns -Stats')
        $hand | Should -BeLessThan $t.IndexOf('if (-not $haveAuth) { return $noAuthResult }')
        $t.IndexOf('if (-not $haveAuth) { return $noAuthResult }') | Should -BeLessThan $t.IndexOf('$tableName = $tablePattern -f $engineCap')
        $hand | Should -BeLessThan $t.IndexOf('$null = Send-SILogData')
    }
    It 'without a caller that wants the rows it returns at once when it has no sign-in, as it always did' {
        $script:LaFn.Extent.Text | Should -Match 'if \(-not \$haveAuth -and -not \$wantRows -and -not \$RowsOnly\) \{ return \$noAuthResult \}'
    }
    It 'the audit''s halt marks the rows as not usable for the database too' {
        $script:LaFn.Extent.Text | Should -Match "(?s)if \(\`$wantRows\) \{ \`$Built\['Held'\] = .{0,300}\}\s+return 'FAILED: critical schema columns empty"
    }
    It 'the stage calls the two outputs apart: the post in its own try, then the database -- whatever the post did' {
        $t = $script:StageFn.Extent.Text
        $t | Should -Match '(?s)try \{\s+\$laResult = Write-SIClassificationToLogAnalytics -RunContext \$RunContext -Records \$records -Built \$built -RowsOnly:\(-not \$wantLa\)\s+\} catch \{'
        $t | Should -Match "if \(-not \(\`$built -and \`$built\['Ready'\]\)\) \{ throw \}"
        $t | Should -Match "if \(\`$wantSql\) \{ \`$sinkResults\['SQL'\] = Write-SIOutputRecordsToSql -RunContext \`$RunContext -Built \`$built -Why \(\[string\]\`$laResult\) \}"
        $t.IndexOf("`$sinkResults['SQL'] = Write-SIOutputRecordsToSql") | Should -BeGreaterThan $t.IndexOf('$laResult = Write-SIClassificationToLogAnalytics')
        @([regex]::Matches($t, "\`$RunContext\.Sinks -contains 'LA'")).Count | Should -Be 1 -Because 'the database output is not inside the Log Analytics branch'
    }
}
