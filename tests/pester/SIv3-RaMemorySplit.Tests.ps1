#Requires -Version 5.1
<#
    #848 -- A DETAILED SLICE TOO BIG FOR THE WORKER'S MEMORY STAYS NOT COMPLETE RUN AFTER RUN; AN ATTACK-PATH COUNT QUERY
    HITS 413 (live 2026-10-20/21, sidata.RaReportStatus).

      (1) Device_Missing_CVEs_Detailed NotComplete three runs in a row: "bucket 2/7: query failed -- advanced hunting returned
          a body that is not JSON: Exception of type 'System.OutOfMemoryException' was thrown." The worker could not hold the
          slice's answer; the classifier did not know the text and wrote the slice off ('Fail'), and the bucket learning never
          saw a split, so every run chose the same 7 slices. FIXED: running out of memory is a SIZE signal -- the slice is split
          and asked again in the same run, recursively until it fits (by its key; by the row when one key value alone carries
          the slice; no depth cap), the hunting layer never asks it again at the same size, the parts asked ahead stop for the
          rest of the report, and the next run starts from the count the worker's own answers measured. A slice that cannot be
          made smaller stays UNKNOWN (never resolved).
      (2) Three attack-path reports Unverified: "the source could not count the report's rows in one query (413 ...)" with
          every row retrieved. Cause: the bucket learning (#833) lets a report come down to ONE slice; the whole count carries
          every lookup whole (no per-slice cut) and is refused, and at one slice the rule "every slice answered below the row
          limit, so the slices' rows are the count" was skipped. FIXED: the same rule at one slice; a count that cannot be
          had at all is said "count not available" (Unverified, never NotComplete) when every slice was read whole.

    Offline. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    . (Join-Path $ra 'RA-AutoBucketing.ps1')
    . (Join-Path $ra 'RA-BucketFilters.ps1')
    # the pure verdict / count functions of the stream file, lifted out (the file needs the data model to load whole)
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-SqlStream.ps1'), [ref]$null, [ref]$null)
    foreach ($n in 'Get-RACompletenessVerdict', 'Get-RALostSliceVerdict', 'Measure-RAReportExpectedRows', 'Get-RAReportCountKql', 'Test-RACountRefusedForSize', 'Measure-RAReportExpectedRowsInParts') {
        . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)).Extent.Text))
    }
    $script:Engine = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $script:Hunting = [IO.File]::ReadAllText((Join-Path $ra 'RA-GraphHunting.ps1'))
    $script:Parts = [IO.File]::ReadAllText((Join-Path $ra 'RA-PartsInParallel.ps1'))
    # the live text, verbatim from sidata.RaReportStatus
    $script:LiveOom = "query failed -- advanced hunting returned a body that is not JSON: Exception of type 'System.OutOfMemoryException' was thrown."
    # a 32-bit hash like the query's: the first 4 bytes of SHA-256, as an unsigned number
    function script:Get-H32([string]$Text) {
        $b = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        ([long]$b[0] * 16777216L) + ([long]$b[1] * 65536L) + ([long]$b[2] * 256L) + [long]$b[3]
    }
}

Describe '(1) running out of memory reading a slice is a SIZE signal, never a query defect' {
    It 'the live text is recognised -- as text, as an exception, wrapped -- and a busy backend is not' {
        Test-RABucketOutOfMemory -Err $script:LiveOom | Should -BeTrue
        Test-RABucketOutOfMemory -Err ([System.OutOfMemoryException]::new()) | Should -BeTrue
        $wrapped = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Exception calling "GetResult"', [System.OutOfMemoryException]::new()), 'x', 'NotSpecified', $null)
        Test-RABucketOutOfMemory -Err $wrapped | Should -BeTrue
        Test-RABucketOutOfMemory -Err 'Query was preempted because of high CPU and/or memory resource consumption' | Should -BeFalse
        Test-RABucketOutOfMemory -Err '400 Bad Request -- Fix semantic errors in your query' | Should -BeFalse
        Test-RABucketOutOfMemory -Err '429 Too Many Requests' | Should -BeFalse
    }

    It 'the classifier splits it (it wrote the slice off before), and it counts as "too large" for the next run''s size' {
        Get-RABucketFailureAction -Err $script:LiveOom | Should -Be 'Split'
        Get-RABucketFailureAction -Err ([System.Management.Automation.ErrorRecord]::new([System.OutOfMemoryException]::new(), 'x', 'NotSpecified', $null)) | Should -Be 'Split'
        Test-RABucketExplicitTooLarge -Err $script:LiveOom | Should -BeTrue
        # nothing else moved: a defect is a defect, a throttle a retry, an unknown failure a failure
        Get-RABucketFailureAction -Err 'Fix syntax errors in your query' | Should -Be 'Defect'
        Get-RABucketFailureAction -Err '429 Too Many Requests' | Should -Be 'Retry'
        Get-RABucketFailureAction -Err 'something nobody has seen' | Should -Be 'Fail'
    }

    It 'the next run starts from the count the worker''s own answers measured (the live case: 7 slices, slice 2 too large)' {
        # slice 2/7 held ~14,000 rows; its 4 smaller slices of ~3,600 went through
        $s = [pscustomobject]@{ Rows = 14200L; Bytes = 0L; Seconds = 60.0; TooLarge = $true; Lost = $false; OutOfMemory = $true; MaxPartRows = 3600L }
        Get-RASliceNeed -Slice $s -Bound 4 | Should -Be 4
        Get-RACountAfterSplit -BucketCount 7 -Slices @($s) -WorkingCount 28 -FanOut 4 | Should -Be 10
        # without a measured part it is at least 2 -- never "nothing needed" (the old answer for a small-looking slice)
        $s2 = [pscustomobject]@{ Rows = 14200L; Bytes = 0L; Seconds = 60.0; TooLarge = $false; Lost = $false; OutOfMemory = $true; MaxPartRows = 0L }
        Get-RASliceNeed -Slice $s2 -Bound 4 | Should -Be 2
        # never more than the finest split that worked
        $s3 = [pscustomobject]@{ Rows = 100000L; Bytes = 0L; Seconds = 60.0; TooLarge = $true; Lost = $false; OutOfMemory = $true; MaxPartRows = 1000L }
        Get-RASliceNeed -Slice $s3 -Bound 16 | Should -Be 16
        # a slice without the flag is sized exactly as before
        $old = [pscustomobject]@{ Rows = 100L; Bytes = 0L; Seconds = 1.0; TooLarge = $false; Lost = $false }
        Get-RASliceNeed -Slice $old -Bound 4 | Should -Be 1
    }
}

Describe '(1) the split recurses until the slice fits -- by key, then by row; no depth cap' {
    It 'the next split: key while the key can split it, the row once one key value carries the slice, none only past the hash' {
        $k = Get-RAMemorySplitNext -KeyCount 7 -FanOut 4
        $k.Kind | Should -Be 'key'; $k.KeyCount | Should -Be 28
        (Get-RAMemorySplitNext -KeyCount 7 -FanOut 4 -SingleKey).Kind | Should -Be 'row'
        $r = Get-RAMemorySplitNext -KeyCount 28 -RowCount 4 -FanOut 4
        $r.Kind | Should -Be 'row'; $r.RowCount | Should -Be 16 -Because 'a row part stays a row part'
        # deep: far past the old depth cap of 6 (7 x 4^6 = 28,672) the key still splits
        (Get-RAMemorySplitNext -KeyCount (7 * [long][Math]::Pow(4, 10)) -FanOut 4).Kind | Should -Be 'key'
        # the key modulus never passes the hash's (and the filter's) range: then the row
        (Get-RAMemorySplitNext -KeyCount 1073741824 -FanOut 4).Kind | Should -Be 'row'
        # the row split ends where the hash ends: a single row cannot be made smaller
        (Get-RAMemorySplitNext -KeyCount 28 -RowCount 2147483648 -FanOut 4).Kind | Should -Be 'none'
    }

    It 'the row filter: a partition of the slice''s answer, after its last line, unchanged without a row split' {
        $q = "T | where x`n| project A, B;`n"
        Add-RARowSplitFilter -Query $q -RowCount 1 -RowIndex 0 | Should -Be $q
        $f = Add-RARowSplitFilter -Query $q -RowCount 16 -RowIndex 5
        $f | Should -Match '(?s)\| project A, B\n\| where \(tolong\(strcat\("0x", substring\(hash_sha256\(tostring\(pack_all\(\)\)\), 0, 8\)\)\) % 16\) == 5$'
        $f | Should -Not -Match ';'
        # the math: the K children of part RI of RC are RI + j*RC of RC*K -- every hash of the parent in exactly one child
        foreach ($rc in 1L, 4L, 16L) {
            foreach ($ri in 0L, ($rc - 1)) {
                foreach ($i in 0..400) {
                    $h = [long]$i
                    if (($h % $rc) -ne $ri) { continue }
                    $hit = 0
                    foreach ($j in 0..3) { if (($h % ($rc * 4)) -eq ($ri + $j * $rc)) { $hit++ } }
                    $hit | Should -Be 1
                }
            }
        }
    }

    It 'a model of the pass: a heavy device and a too-small worker -- every row read exactly once, nothing unknown' {
        # 2,000 devices x 3 findings + ONE device with 400 findings; the worker holds 150 rows at a time; 2 slices to start
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($d in 0..1999) { foreach ($f in 0..2) { $rows.Add([pscustomobject]@{ Key = "dev-$d"; Id = "dev-$d|cve-$f" }) } }
        foreach ($f in 0..399) { $rows.Add([pscustomobject]@{ Key = 'dev-heavy'; Id = "dev-heavy|cve-$f" }) }
        foreach ($r in $rows) { $r | Add-Member -NotePropertyName KH -NotePropertyValue (Get-H32 $r.Key); $r | Add-Member -NotePropertyName RH -NotePropertyValue (Get-H32 $r.Id) }
        $memory = 150
        $all = $rows.ToArray()
        $ask = { param($N, $T, $RC, $RI)
            $o = New-Object System.Collections.Generic.List[object]
            foreach ($x in $all) { if (($x.KH % $T) -eq $N -and ($x.RH % $RC) -eq $RI) { $o.Add($x) } }
            , $o.ToArray() }
        $got = @{}; $unknown = 0; $asked = 0; $rowSplits = 0
        $q = New-Object System.Collections.Generic.Queue[object]
        # the main pass: 2 slices, each too large for 150 rows
        foreach ($b in 0..1) {
            $a = & $ask $b 2 1 0; $asked++
            if ($a.Count -gt $memory) { $q.Enqueue(@{ N = $b; T = 2L; How = 'key'; RC = 1L; RI = 0L }) } else { foreach ($x in $a) { $got[$x.Id] = 1 + [int]$got[$x.Id] } }
        }
        while ($q.Count -gt 0) {
            $it = $q.Dequeue(); $kids = New-Object System.Collections.Generic.List[object]; $empty = 0
            foreach ($j in 0..3) {
                if ($it.How -eq 'row') { $cN = $it.N; $cT = $it.T; $cRC = $it.RC * 4; $cRI = $it.RI + $j * $it.RC } else { $cN = $it.N + $j * $it.T; $cT = $it.T * 4; $cRC = 1L; $cRI = 0L }
                $a = & $ask $cN $cT $cRC $cRI; $asked++
                if ($a.Count -gt $memory) { $kids.Add(@{ N = $cN; T = $cT; RC = $cRC; RI = $cRI }); continue }
                if ($a.Count -eq 0) { $empty++ }
                foreach ($x in $a) { $got[$x.Id] = 1 + [int]$got[$x.Id] }
            }
            $one = ($it.How -ne 'row' -and $kids.Count -eq 1 -and $empty -eq 3)
            foreach ($k in $kids) {
                $nx = Get-RAMemorySplitNext -KeyCount $k.T -RowCount $k.RC -FanOut 4 -SingleKey:$one
                if ($nx.Kind -eq 'none') { $unknown++; continue }
                if ($nx.Kind -eq 'row') { $rowSplits++ }
                $q.Enqueue(@{ N = $k.N; T = $k.T; How = $nx.Kind; RC = $k.RC; RI = $k.RI })
            }
            $asked | Should -BeLessThan 5000 -Because 'the pass ends'
        }
        $unknown | Should -Be 0
        $got.Count | Should -Be $rows.Count -Because 'every row is read'
        @($got.Values | Where-Object { $_ -ne 1 }).Count | Should -Be 0 -Because 'no row is read twice'
        $rowSplits | Should -BeGreaterThan 0 -Because 'the heavy device (400 rows > 150) can only be split by row'
    }

    It 'a slice that cannot be made smaller stays UNKNOWN -- the report is not complete, never resolved' {
        $v = Get-RALostSliceVerdict -Lost @("sub-bucket 5/4096 row part 3/4294967296: too large for this worker's memory at the finest split (its answer is too large for this worker's memory)")
        $v.State | Should -Be 'NotComplete'
        $v.Reason | Should -Match '^1 query slice\(s\) of the report could not be read \(sub-bucket 5/4096 row part 3/4294967296: too large for this worker''s memory at the finest split.*\) -- the rows of those slices are unknown, not resolved'
    }
}

Describe '(1) WIRING: the engine splits on memory everywhere a slice is read, and never asks it again at the same size' {
    It 'the hunting layer gives the memory back and throws at once (no retry at the same size)' {
        $i = $script:Hunting.IndexOf('(Test-RABucketOutOfMemory -Err $_)')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:Hunting.IndexOf('if ($attempt -lt $MaxRetries) {')
        $script:Hunting | Should -Match '(?s)Test-RABucketOutOfMemory -Err \$_\)\) \{\s*\[System\.GC\]::Collect\(\).{0,300}throw'
    }

    It 'the main loop, its conversion, the late retry and the sub-slices: an out-of-memory slice is split, never lost' {
        $script:Engine | Should -Match ([regex]::Escape("if (`$bucketAction -eq 'Split' -and (Test-RABucketOutOfMemory -Err `$_)) {"))
        $script:Engine | Should -Match '(?s)if \(\(Test-RABucketOutOfMemory -Err \$_\) -and -not \$bucketIsComplete\) \{.{0,900}\[void\]\$failedBucketIndices\.Add\(\$b\)\s*continue'
        $script:Engine | Should -Match ([regex]::Escape("if (-not `$conv.Ok -and `$conv.ContainsKey('OutOfMemory') -and [bool]`$conv.OutOfMemory) {"))
        $script:Engine | Should -Match ([regex]::Escape("if (-not (Add-RAStreamBucketGuarded -Rows @(`$conv.Rows) -Bucket ('late:{0}/{1}' -f `$dbNo, `$bucketCountToUse))) {"))
        $script:Engine | Should -Match ([regex]::Escape("if (-not `$subConv.Ok -and `$subConv.ContainsKey('OutOfMemory') -and [bool]`$subConv.OutOfMemory) {"))
        $script:Engine | Should -Match ([regex]::Escape("if (`$subAction -eq 'Split' -and (Test-RABucketOutOfMemory -Err `$_)) {"))
        $script:Engine | Should -Match ([regex]::Escape('OutOfMemory = $oom }'))
    }

    It 'a memory child is never judged by the no-progress stop (M), with its row split; a row part stays a row part' {
        $iMem = $script:Engine.IndexOf('$__nx = Get-RAMemorySplitNext -KeyCount ([long]$__mk.T) -RowCount ([long]$__mk.RC) -FanOut $subFanOut -SingleKey:$__oneKey')
        $iMem | Should -BeGreaterThan 0
        $script:Engine | Should -Not -Match ([regex]::Escape('[sub-bucket] FUTILE-PRUNE')) -Because 'one mechanism: the futile-prune is gone (2026-10-22)'
        $script:Engine | Should -Match ([regex]::Escape('if (-not $pAgain -and $pHow -in @(''key'', ''row'') -and -not [bool]$item.M'))
        $script:Engine | Should -Match ([regex]::Escape('$__oneKey = ($pHow -ne ''row'' -and $__memKids.Count -eq 1 -and $__emptyKids -eq ($subFanOut - 1))'))
        $script:Engine | Should -Match ([regex]::Escape('$subQuery   = Add-RARowSplitFilter -Query (Replace-BucketFilterBlock -Query $Query -BucketFilterKql $subFilter) -RowCount $subRC -RowIndex $subRI'))
        $script:Engine | Should -Match ([regex]::Escape("How = `$(if (`$subRC -gt 1) { 'row' } else { 'key' }); RC = `$subRC; RI = `$subRI; M = `$false"))
        # the slice's label in the store is unique per row part (a slice taken back removes only its own rows)
        $script:Engine | Should -Match ([regex]::Escape("('sub:{0}/{1}/row:{2}/{3}' -f `$subN, `$newT, `$subRI, `$subRC)"))
    }

    It 'the parts asked ahead stop for the rest of the report once a part did not fit (one answer in memory at a time)' {
        $script:Parts | Should -Match 'function Stop-RAPartsAheadForMemory'
        @([regex]::Matches($script:Engine, 'Stop-RAPartsAheadForMemory')).Count | Should -BeGreaterOrEqual 6 -Because 'the read, the conversion and the store of a main slice'
    }

    It 'the evidence of a report run in parts keeps what the next run is sized from' {
        $script:Engine | Should -Match ([regex]::Escape("OutOfMemory = [bool]`$__soV['OutOfMemory']; MaxPartRows = [long]`$__soV['MaxPartRows']"))
        $script:Engine | Should -Match ([regex]::Escape('$__abSplitSlices[$root].MaxPartRows = $__subRowsN'))
    }
}

Describe '(2) the report''s count when the one-query count is too large (413)' {
    BeforeAll {
        . ([scriptblock]::Create([regex]::Match($script:Engine, '(?s)function Get-RAReportExpectedRows \{.*?\n\}').Value))
        function script:Test-QueryHasBucketFilterBlock { param($Query) $true }
        function script:Replace-BucketFilterBlock { param($Query, $BucketFilterKql) $Query }
        function script:New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) '' }
        function script:Get-RASummaryMergePlan { param($Query) $null }
        function script:Get-RABucketRows { param($Resp) $Resp }
        function script:Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
            $script:__asked++
            throw '413 Request Entity Too Large -- <html><head><title>413 Request Entity Too Large</title></head><body><center><h1>413 Request Entity Too Large</h1></center><hr><center>nginx</center></body></html>' }
    }

    It 'the live case: a report run in ONE slice, every row retrieved, the whole count refused -> Complete, the rows are the count' {
        $script:__asked = 0; $script:RALakeAnswered = $false
        $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'Attack_Paths_Detailed_ServicePrincipal_Impersonates_Users' -BucketCount 1 -Retrieved 1505
        $r.Count | Should -Be 1505
        $r.Error | Should -BeNullOrEmpty
        $r.How | Should -Match '^the report''s one query slice answered whole and below the row limit, so the source holds what they returned \(the whole count could not be sent: 413 Request Entity Too Large'
        $script:__asked | Should -Be 1 -Because 'the slices are never asked twice'
        $v = Get-RACompletenessVerdict -Expected $r.Count -Retrieved 1505 -CountError $r.Error
        $v.State | Should -Be 'Complete'
        # many slices: as before, word for word
        $m = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 4 -Retrieved 37
        $m.How | Should -Match '^every one of the report''s 4 slices answered below the row limit, so the source holds what they returned'
    }

    It 'a slice that was lost: the rows are NOT the count -- the report is not complete at its own verdict (unchanged)' {
        $script:RALakeAnswered = $false
        $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 1 -Retrieved 6 -LostSlices 1
        $r.Count | Should -BeNullOrEmpty
        $r.Error | Should -Not -Match 'count not available'
    }

    It 'no count can be had at all (an answer the lake gave, one slice): "count not available" -- Unverified, never not complete' {
        $script:RALakeAnswered = $true
        $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 1 -Retrieved 6
        $script:RALakeAnswered = $false
        $r.Count | Should -BeNullOrEmpty
        # the count is first asked in parts, the way the read is split (SIv3-RaBatchedFinish); here every part is refused too
        # and nothing is inlined that a finer split could cut -- so no count, said with what was tried
        $r.Error | Should -Match '^count not available \(413 Request Entity Too Large.*\); counted in 2 parts: slice 1/2: 413 Request Entity Too Large'
        $v = Get-RACompletenessVerdict -Expected $r.Count -Retrieved 6 -CountError $r.Error
        $v.State | Should -Be 'Unverified'
        $v.State | Should -Not -Be 'NotComplete'
        $v.Reason | Should -Match '^the source''s count not available'
        # any other missing count reads as before
        (Get-RACompletenessVerdict -Expected $null -Retrieved 6 -CountError 'boom').Reason | Should -Be 'the source could not count the report''s rows in one query (boom)'
    }
}
