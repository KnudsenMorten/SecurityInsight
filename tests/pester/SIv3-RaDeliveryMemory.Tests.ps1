<#
    Risk Analysis delivery without the whole result in memory several times (a large install, 2026-10-13: a Detailed run
    of ~33,000-68,000 rows x ~320 columns ran out of memory AFTER the workbook was written -- in the Log Analytics step,
    the 'Risk factors' sheet and the storage upload).

    What these pin:
      * LOG ANALYTICS IN CHUNKS (RA-Delivery.ps1): every row and every column of the input arrives exactly once across many
        chunks, the input rows are not changed, the rows posted are counted, the key columns are judged over every chunk,
        and memory after the last chunk is about what it was after the second (nothing of a chunk outlives its post).
      * THE JSON FILE row by row: the same rows as the whole-string write (0, 1 and many rows).
      * THE SHARED STRINGS of an existing workbook are read as a stream when a sheet is added: both sheets read back
        exactly, with a read buffer of 7 characters (every tag split across buffers) and with the normal one, and the two
        workbooks hold the same parts.
      * THE STORAGE UPLOAD goes from the file in blocks, and the backup copy range by range: the blob is byte-identical,
        and no request carries more than one block.

    NO EMOJI IN THIS FILE (no BOM; Windows PowerShell 5.1 would decode it as Windows-1252).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $raShared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1')
    . (Join-Path $raShared 'RA-ColumnTypeAlign.ps1')
    . (Join-Path $raShared 'RA-IngestKeyColumns.ps1')
    . (Join-Path $raShared 'RA-Delivery.ps1')
    $script:_sheetWritten = @{}
    . (Join-Path $raShared 'RA-RunProgress.ps1')
    . (Join-Path $raShared 'RA-ExcelReport.ps1')     # dot-sources RA-XlsxWriter.ps1
    $script:_sheetWritten = @{}
    . (Join-Path $raShared 'Send-SecurityInsightExportFile.ps1')

    function script:New-WideRows {
        param([int]$Count, [int]$Columns, [switch]$Ragged)
        $out = New-Object 'System.Collections.Generic.List[object]'
        for ($i = 0; $i -lt $Count; $i++) {
            $o = [ordered]@{
                # RowKey, not Id: the ingest client renames a column called Id (Id_), as it always has
                RowKey = ('row-{0:D6}' -f $i); CollectionTime = '2026-10-13T08:00:00Z'; SolutionVersion = '3.0.0'
                ConfigurationId = ('CVE-2026-{0}' -f (1000 + ($i % 97))); SecuritySeverity = 'High'; CriticalityTier = ($i % 4); RiskScoreTotal = (100 + $i)
            }
            for ($c = 1; $c -le $Columns; $c++) {
                if ($Ragged -and (($i + $c) % 11 -eq 0)) { continue }   # a column this row does not carry
                $o[('C{0:D3}' -f $c)] = ('value {0} {1} {2}' -f $i, $c, ('x' * (($i * $c) % 23)))
            }
            if ($Ragged -and $i % 5 -eq 0) { $o['Tags'] = @('a', ('t{0}' -f $i)); $o['Nested'] = [pscustomobject]@{ k = $i; s = 'n' } }
            [void]$out.Add([pscustomobject]$o)
        }
        , $out.ToArray()
    }
}

Describe 'Log Analytics in chunks: the same rows, every column, exactly once' {
    It 'every row and every column of the input arrives exactly once across many chunks; the input rows are not changed' {
        $rows = New-WideRows -Count 900 -Columns 40 -Ragged
        $before = @($rows | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 10 })
        $got = New-Object 'System.Collections.Generic.List[object]'
        $res = Invoke-RALaChunkedPost -Rows $rows -TargetBytes 32KB -Keep -KeyColumns @(Get-RAIngestKeyColumns) `
            -Prepare { param($c) ConvertTo-RALaPostRows -Rows $c -HostName 'h1' -Fqdn 'h1.contoso' -User 'u1' } `
            -Post {
                param($p)
                $b = 0L
                foreach ($r in $p) { $j = ConvertTo-Json -InputObject $r -Depth 100 -Compress; $b += [Text.Encoding]::UTF8.GetByteCount($j); $got.Add(($j | ConvertFrom-Json)) }
                [pscustomobject]@{ RowsPosted = $p.Count; BytesPosted = $b }
            }
        $res.Chunks | Should -BeGreaterThan 4
        $res.RowsPosted | Should -Be 900
        $got.Count | Should -Be 900
        @($res.Posted).Count | Should -Be 900
        @($res.KeyGaps).Count | Should -Be 0
        $byId = @{}; foreach ($g in $got) { $byId[[string]$g.RowKey] = $g }
        $byId.Count | Should -Be 900 -Because 'no row twice'
        $bad = New-Object 'System.Collections.Generic.List[string]'
        foreach ($r in $rows) {
            $d = $byId[[string]$r.RowKey]
            if ($null -eq $d) { $bad.Add("missing $($r.RowKey)"); continue }
            foreach ($p in $r.PSObject.Properties) {
                $want = ConvertTo-Json -InputObject $p.Value -Compress -Depth 10
                $have = ConvertTo-Json -InputObject $d.($p.Name) -Compress -Depth 10
                if ($want -ne $have) { $bad.Add(('{0}.{1}: {2} <> {3}' -f $r.RowKey, $p.Name, $want, $have)) }
            }
            if ($d.Computer -ne 'h1' -or $d.ComputerFqdn -ne 'h1.contoso' -or $d.UserLoggedOn -ne 'u1') { $bad.Add("host columns $($r.RowKey)") }
        }
        ($bad | Select-Object -First 5) -join ' | ' | Should -BeNullOrEmpty
        @($rows | ForEach-Object { ConvertTo-Json -InputObject $_ -Compress -Depth 10 }) | Should -Be $before -Because 'the type alignment rounds in place, so only COPIES are prepared'
    }
    It 'the type alignment runs on every chunk and its counts are added up' {
        $rows = New-WideRows -Count 300 -Columns 5
        foreach ($r in $rows) { $r.CriticalityTier = [string]$r.CriticalityTier }   # text in a whole-number column
        $res = Invoke-RALaChunkedPost -Rows $rows -TargetBytes 8KB `
            -Prepare { param($c) ConvertTo-RALaPostRows -Rows $c -Types @{ CriticalityTier = 'int' } } `
            -Post { param($p) foreach ($x in $p) { if (-not ($x.CriticalityTier -is [int] -or $x.CriticalityTier -is [long])) { throw "not converted: $($x.RowKey)" } }; [pscustomobject]@{ RowsPosted = $p.Count } }
        $res.Chunks | Should -BeGreaterThan 3
        [long]$res.Align.Converted['CriticalityTier'] | Should -Be 300
    }
    It 'a chunk that was not posted in full throws: the other rows are unknown, not posted' {
        $rows = New-WideRows -Count 50 -Columns 3
        { Invoke-RALaChunkedPost -Rows $rows -TargetBytes 2KB -Prepare { param($c) ConvertTo-RALaPostRows -Rows $c } -Post { param($p) [pscustomobject]@{ RowsPosted = ($p.Count - 1) } } } |
            Should -Throw '*UNKNOWN, not posted*'
    }
    It 'a key column empty on every row of EVERY chunk is a gap; filled on one row of the last chunk it is not' {
        $rows = New-WideRows -Count 200 -Columns 3
        foreach ($r in $rows) { $r.SolutionVersion = '' }
        $post = { param($p) [pscustomobject]@{ RowsPosted = $p.Count } }
        $prep = { param($c) ConvertTo-RALaPostRows -Rows $c }
        $res = Invoke-RALaChunkedPost -Rows $rows -TargetBytes 4KB -KeyColumns @(Get-RAIngestKeyColumns) -Prepare $prep -Post $post
        $res.Chunks | Should -BeGreaterThan 3
        @($res.KeyGaps) | Should -Be @('SolutionVersion')
        $rows[199].SolutionVersion = '3.0.0'
        @((Invoke-RALaChunkedPost -Rows $rows -TargetBytes 4KB -KeyColumns @(Get-RAIngestKeyColumns) -Prepare $prep -Post $post).KeyGaps).Count | Should -Be 0
    }
    It 'the chunk size follows the measured bytes per row: at least one row, never more than are left' {
        Get-RALaNextChunkCount -TargetBytes 1000 -BytesPerRow 100 -Remaining 50 | Should -Be 10
        Get-RALaNextChunkCount -TargetBytes 1000 -BytesPerRow 100 -Remaining 4 | Should -Be 4
        Get-RALaNextChunkCount -TargetBytes 1000 -BytesPerRow 5000 -Remaining 4 | Should -Be 1
        Get-RALaNextChunkCount -TargetBytes 1000 -BytesPerRow 100 -Remaining 0 | Should -Be 0
        (Get-RALaChunkBytes) | Should -BeGreaterThan 1MB
    }
    It 'memory after the last chunk is about what it was after the second: nothing of a chunk outlives its post' {
        $rows = New-WideRows -Count 6000 -Columns 80
        # what ONE full copy of these rows costs, measured here
        $m0 = [GC]::GetTotalMemory($true)
        $copy = New-Object 'System.Collections.Generic.List[object]'; foreach ($r in $rows) { $copy.Add($r.PSObject.Copy()) }
        $m1 = [GC]::GetTotalMemory($true)
        $oneCopy = $m1 - $m0
        $copy = $null
        $at = @{}
        $res = Invoke-RALaChunkedPost -Rows $rows -TargetBytes 256KB `
            -Prepare { param($c) ConvertTo-RALaPostRows -Rows $c -HostName 'h' } `
            -Post { param($p) [pscustomobject]@{ RowsPosted = $p.Count } } `
            -OnChunk { param($n) if ($n -eq 2) { $at[2] = [GC]::GetTotalMemory($true) } }
        $end = [GC]::GetTotalMemory($true)
        $res.Chunks | Should -BeGreaterThan 8
        $res.RowsPosted | Should -Be 6000
        $grow = $end - $at[2]
        $grow | Should -BeLessThan ($oneCopy * 0.25) -Because ('one full copy of the rows is {0:N1} MB; delivery grew {1:N1} MB between the second and the last of {2} chunks' -f ($oneCopy / 1MB), ($grow / 1MB), $res.Chunks)
    }
}

Describe 'the JSON file, row by row' {
    It 'holds the same rows as the whole-string write did -- 0, 1 and many rows, nested values; UTF-8 without a byte-order mark' {
        $many = New-WideRows -Count 40 -Columns 4 -Ragged
        $p = Join-Path $TestDrive 'ra.json'
        foreach ($set in @(, @()) + @(, @($many[0])) + @(, $many)) {
            Write-RAJsonArrayFile -Rows $set -Path $p -Depth 20
            $text = [IO.File]::ReadAllText($p)
            $text.TrimStart() | Should -Match '^\['
            $old = ConvertTo-Json -InputObject @($set) -Depth 20
            (ConvertFrom-Json $text -NoEnumerate | ConvertTo-Json -Depth 20 -Compress) | Should -Be (ConvertFrom-Json $old -NoEnumerate | ConvertTo-Json -Depth 20 -Compress)
            $b = [IO.File]::ReadAllBytes($p)
            ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) | Should -BeFalse
        }
        Write-RAJsonArrayFile -Rows $null -Path $p
        [IO.File]::ReadAllText($p).Trim() | Should -Match '^\[\s*\]$'
    }
}

Describe 'adding a sheet to a large workbook reads its shared strings as a stream' {
    BeforeAll {
        $script:DHeader = @('Id', 'Name', 'Note')
        $script:DRows = New-Object 'System.Collections.Generic.List[object[]]'
        for ($i = 0; $i -lt 500; $i++) { $script:DRows.Add([object[]]@(('id-{0}' -f $i), ('name {0} <b> & "q" ' -f $i) + [char]0x00FC, ('note {0} {1}' -f $i, ('x' * ($i % 37))))) }
        $script:FHeader = @('Short', 'Description')
        $script:FRows = New-Object 'System.Collections.Generic.List[object[]]'
        for ($i = 0; $i -lt 30; $i++) { $script:FRows.Add([object[]]@(('F{0}' -f $i), $(if ($i -eq 3) { $script:DRows[3][1] } else { 'factor {0} <si> text' -f $i }))) }
        $script:Build = {
            param([string]$Path, [int]$ChunkChars)
            $saved = $script:SIXlsxSstChunkChars
            try {
                $script:SIXlsxSstChunkChars = $ChunkChars
                Write-SIXlsxWorksheet -Path $Path -SheetName 'Details' -Header $script:DHeader -Rows $script:DRows
                Write-SIXlsxWorksheet -Path $Path -SheetName 'Risk factors' -Header $script:FHeader -Rows $script:FRows
            } finally { $script:SIXlsxSstChunkChars = $saved }
        }
        $script:Tiny = Join-Path $TestDrive 'tiny.xlsx'; & $script:Build $script:Tiny 7
        $script:Norm = Join-Path $TestDrive 'norm.xlsx'; & $script:Build $script:Norm 65536
    }
    It 'both sheets read back exactly with a read buffer of 7 characters (every tag split across buffers)' {
        $d = Read-SIXlsxWorksheet -Path $script:Tiny -SheetName 'Details'
        $f = Read-SIXlsxWorksheet -Path $script:Tiny -SheetName 'Risk factors'
        $d.Rows.Count | Should -Be 500
        $f.Rows.Count | Should -Be 30
        for ($i = 0; $i -lt 500; $i += 37) { $d.Rows[$i].Id | Should -BeExactly $script:DRows[$i][0]; $d.Rows[$i].Name | Should -BeExactly $script:DRows[$i][1]; $d.Rows[$i].Note | Should -BeExactly $script:DRows[$i][2] }
        $d.Rows[499].Note | Should -BeExactly $script:DRows[499][2]
        for ($i = 0; $i -lt 30; $i++) { $f.Rows[$i].Short | Should -BeExactly $script:FRows[$i][0]; $f.Rows[$i].Description | Should -BeExactly $script:FRows[$i][1] }
    }
    It 'the workbook built through a 7-character buffer holds the same parts as through the normal one' {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $read = { param($p) $z = [IO.Compression.ZipFile]::OpenRead($p); try { $h = @{}; foreach ($e in $z.Entries) { $ms = New-Object IO.MemoryStream; $s = $e.Open(); try { $s.CopyTo($ms) } finally { $s.Close() }; $h[$e.FullName] = [Convert]::ToBase64String($ms.ToArray()) }; $h } finally { $z.Dispose() } }
        $a = & $read $script:Tiny; $b = & $read $script:Norm
        @($a.Keys | Sort-Object) | Should -Be @($b.Keys | Sort-Object)
        foreach ($k in $a.Keys) { $a[$k] | Should -BeExactly $b[$k] -Because $k }
    }
}

Describe 'the storage upload goes in blocks, the backup copy range by range' {
    BeforeEach {
        $script:Store = @{}; $script:Staged = @{}; $script:Calls = New-Object 'System.Collections.Generic.List[object]'
        $script:SavedBlock = $script:SIExportBlockBytes
        $script:SIExportBlockBytes = 1000
        # #744: these pin the IN-LINE path (one block at a time through Invoke-SIStorageRequest) and the range copy through
        # this machine; several blocks at once and the copy made by the service: SIv3-RaFinishSpeed.Tests.ps1
        $global:SI_ExportUpload_Parallel = 1; $global:SI_ExportServerCopy = 'off'
        Mock Invoke-SIStorageRequest {
            $len = -1; if ($Body -is [byte[]]) { $len = $Body.Length }
            $script:Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Headers = $Headers; Len = $len })
            $u = [uri]$Uri
            $blob = [uri]::UnescapeDataString($u.AbsolutePath.TrimStart('/'))
            $q = $u.Query
            if ($Method -eq 'HEAD') {
                if (-not $script:Store.ContainsKey($blob)) { return $null }
                return [pscustomobject]@{ StatusCode = 200; Headers = @{ 'Content-Length' = [string]$script:Store[$blob].Length; 'ETag' = '"e1"'; 'Content-Type' = 'application/vnd.test' } }
            }
            if ($Method -eq 'GET') {
                $m = [regex]::Match([string]$Headers['x-ms-range'], 'bytes=(\d+)-(\d+)')
                $s = [int]$m.Groups[1].Value; $e = [int]$m.Groups[2].Value
                [byte[]]$out = [byte[]]::new($e - $s + 1); [Array]::Copy($script:Store[$blob], $s, $out, 0, $out.Length)
                return [pscustomobject]@{ StatusCode = 206; Bytes = $out; Headers = @{} }
            }
            if ($q -match 'comp=block&blockid=([^&]+)') {
                if (-not $script:Staged.ContainsKey($blob)) { $script:Staged[$blob] = @{} }
                [byte[]]$copyOf = $Body.Clone()
                $script:Staged[$blob][[uri]::UnescapeDataString($Matches[1])] = $copyOf
                return [pscustomobject]@{ StatusCode = 201; Headers = @{} }
            }
            if ($q -match 'comp=blocklist') {
                $ms = New-Object IO.MemoryStream
                foreach ($x in [regex]::Matches([string]$Body, '<Latest>([^<]+)</Latest>')) { $bb = $script:Staged[$blob][$x.Groups[1].Value]; $ms.Write($bb, 0, $bb.Length) }
                $script:Store[$blob] = $ms.ToArray()
                return [pscustomobject]@{ StatusCode = 201; Headers = @{ ETag = '"n1"' } }
            }
            [byte[]]$whole = $Body
            $script:Store[$blob] = $whole
            return [pscustomobject]@{ StatusCode = 201; Headers = @{ ETag = '"w1"' } }
        }
    }
    AfterEach { $script:SIExportBlockBytes = $script:SavedBlock; Remove-Variable -Scope Global -Name SI_ExportUpload_Parallel, SI_ExportServerCopy -ErrorAction SilentlyContinue }
    It 'an upload from the file is byte-identical, and no request carries more than one block' {
        $f = Join-Path $TestDrive 'ra.xlsx'
        [byte[]]$data = [byte[]]::new(4500); (New-Object Random 7).NextBytes($data); [IO.File]::WriteAllBytes($f, $data)
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'exports' -Blob 'ra/RiskAnalysis_Detailed.xlsx' -File $f
        [Convert]::ToBase64String($script:Store['exports/ra/RiskAnalysis_Detailed.xlsx']) | Should -BeExactly ([Convert]::ToBase64String($data))
        @($script:Calls | Where-Object { $_.Uri -match 'comp=block&' }).Count | Should -Be 5
        @($script:Calls | Where-Object { $_.Len -gt 1000 }).Count | Should -Be 0
    }
    It 'a file of exactly one block, and an empty file' {
        $f = Join-Path $TestDrive 'one.bin'; [byte[]]$d = [byte[]]::new(1000); (New-Object Random 3).NextBytes($d); [IO.File]::WriteAllBytes($f, $d)
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'c' -Blob 'one.bin' -File $f
        [Convert]::ToBase64String($script:Store['c/one.bin']) | Should -BeExactly ([Convert]::ToBase64String($d))
        $e = Join-Path $TestDrive 'empty.bin'; [IO.File]::WriteAllBytes($e, [byte[]]::new(0))
        $null = Send-SIExportBlockBlob -Account 'acct' -Container 'c' -Blob 'empty.bin' -File $e
        $script:Store['c/empty.bin'].Length | Should -Be 0
    }
    It 'the backup copy is byte-identical, read range by range against the source''s ETag' {
        [byte[]]$src = [byte[]]::new(3456); (New-Object Random 11).NextBytes($src)
        $script:Store['exports/old.xlsx'] = $src
        Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'old.xlsx' -DestBlob 'old.2026-10-13_080000.xlsx.bak'
        [Convert]::ToBase64String($script:Store['exports/old.2026-10-13_080000.xlsx.bak']) | Should -BeExactly ([Convert]::ToBase64String($src))
        $gets = @($script:Calls | Where-Object { $_.Method -eq 'GET' })
        $gets.Count | Should -Be 4
        @($gets | ForEach-Object { [string]$_.Headers['x-ms-range'] }) | Should -Be @('bytes=0-999', 'bytes=1000-1999', 'bytes=2000-2999', 'bytes=3000-3455')
        @($gets | Where-Object { [string]$_.Headers['If-Match'] -ne '"e1"' }).Count | Should -Be 0
        @($script:Calls | Where-Object { $_.Len -gt 1000 }).Count | Should -Be 0
        Copy-SIExportBlobInBlocks -Account 'acct' -Container 'exports' -SrcBlob 'missing.xlsx' -DestBlob 'x.bak'
        $script:Store.ContainsKey('exports/x.bak') | Should -BeFalse
    }
    It 'block ids are base64 of one fixed length' {
        (Get-SIExportBlockId -Index 0).Length | Should -Be (Get-SIExportBlockId -Index 49999).Length
        [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((Get-SIExportBlockId -Index 12))) | Should -Be 'blk000012'
    }
}

Describe 'WIRING -- the engine delivers through these, and lets go of what built the result first' {
    BeforeAll {
        $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Exp = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\Send-SecurityInsightExportFile.ps1'))
    }
    It 'Log Analytics: chunked, nothing of a chunk kept -- the trend and the findings read the result''s own rows' {
        $script:Ra | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-Delivery.ps1')"))
        $script:Ra | Should -Match ([regex]::Escape('$__laDelivery = Invoke-RALaPagedPost -Pager $__pgL -KeyColumns'))   # #738: the pages through Invoke-RALaChunkedPost, in RA-Delivery.ps1
        $script:Ra | Should -Not -Match 'Invoke-RALaChunkedPost[^\r\n]*-Keep'
        $script:Ra | Should -Not -Match '__laDelivery\.Posted'
        $iRec = $script:Ra.IndexOf('if ($script:RAStreamOn) { $script:_RAPublishedRows = @() } else { $script:_RAPublishedRows = $global:final }')
        $iRec | Should -BeGreaterThan $script:Ra.IndexOf('if (@($__laDelivery.KeyGaps).Count -gt 0)') -Because 'recorded only once every part was posted, counted and checked'
        $script:Ra | Should -Not -Match ([regex]::Escape('@($global:final | ForEach-Object { if ($null -ne $_) { $_.PSObject.Copy() } })'))
        $i = $script:Ra.IndexOf('$__laDelivery = Invoke-RALaPagedPost')
        $script:Ra.IndexOf('Send-SILogData', $i) | Should -BeGreaterThan $i
        $script:Ra | Should -Match 'Rows posted      : \{0\} \(before the failure\)'
    }
    It 'the JSON file is written row by row' {
        $script:Ra | Should -Match ([regex]::Escape('Write-RAJsonArrayFile -Rows $global:RA_ReportRows -Path $global:OutputJson -Depth 20')); $script:Ra | Should -Match ([regex]::Escape('Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $script:RAStream -Source View -ReadAhead)'))   # #744: the next page read while one is written
        $script:Ra | Should -Not -Match ([regex]::Escape('ConvertTo-Json -InputObject @($global:RA_ReportRows)'))
    }
    It 'what built the result is let go before delivery starts' {
        $iFinal = $script:Ra.IndexOf('$global:final = $_cleanFinal.ToArray()')
        $iRel = $script:Ra.IndexOf('$global:AllShapedRows.Clear()')
        $iRel | Should -BeGreaterThan $iFinal
        $iRel | Should -BeLessThan $script:Ra.IndexOf('if (-not $script:RAStreamOn) { Invoke-RAWorkbookStep }')
        $script:Ra | Should -Match ([regex]::Escape('$ResultAll = $null; $ResultFiltered = $null; $RiskScoreArray = $null; $Shaped = $null'))
        # nothing reads the export pool after that point
        $script:Ra.IndexOf('AllShapedRows', $iRel + 30) | Should -Be -1
    }
    It 'the storage upload streams, and the shared ingest client reports the bytes it posted' {
        $script:Exp | Should -Match 'Copy-SIExportBlobInBlocks -Account \$StorageAccount -Container \$Container -SrcBlob \$blobName -DestBlob \$backupName'
        $script:Exp | Should -Match 'Send-SIExportBlockBlob -Account \$StorageAccount -Container \$Container -Blob \$blobName -File \$LocalPath'
        $script:Exp | Should -Not -Match 'Start-SIAzStorageBlobCopy -Context|Set-SIAzStorageBlobContent -Context'
        $li = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-LogIngest.ps1'))
        $li | Should -Match 'BytesPosted = \$state\.Bytes'
        $li | Should -Match '\$State\.Bytes \+= \[long\]\$rawBytes\.Length'
    }
}
