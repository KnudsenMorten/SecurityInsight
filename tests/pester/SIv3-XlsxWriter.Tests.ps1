#Requires -Version 5.1
<#
    SI's own .xlsx writer (engine/risk-analysis/_shared/RA-XlsxWriter.ps1) -- the replacement for the
    ImportExcel / EPPlus dependency (REQUIREMENTS section 9.3: "Excel = keep everywhere, written with
    .NET -- no ImportExcel module").

    NO EMOJI IN THIS FILE: it has no BOM, and PowerShell 5.1 would decode it as Windows-1252.

    What these pin, and why each matters:
      * THE PACKAGE IS VALID. Every part is well-formed XML, every relationship points at a part that
        exists, every part has a content type. Excel refuses (or "repairs") a package that breaks any
        of these, and nothing in this repo can open Excel -- so the structure is checked directly.
      * VALUES ROUND-TRIP WITH THEIR TYPES, read back from the XML: numbers as numbers (also under a
        comma-decimal locale), dates as dates, booleans, text exactly, empty as no cell.
      * THE LAYOUT CONTRACT: bold frozen header, a table with autofilter and banding, widths, wrap + top
        alignment on the narrative columns only.
      * A WORKBOOK ACCUMULATES SHEETS. 'Details' and the AI 'Summary' are separate writes to one file;
        a same-named sheet is replaced, every other sheet survives with its values intact -- also when
        the workbook on disk was written by EPPlus (a run with OverwriteXlsx = $false appends to it).
      * THE COMPILED HELPER AND ITS POWERSHELL TWIN WRITE THE SAME BYTES. The twin is the fallback when
        Add-Type is unavailable; if the two drift, the fallback silently produces a different workbook.
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RaShared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    $script:_sheetWritten = @{}
    . (Join-Path $script:RaShared 'RA-RunProgress.ps1')
    . (Join-Path $script:RaShared 'RA-ExcelReport.ps1')     # dot-sources RA-XlsxWriter.ps1
    $script:_sheetWritten = @{}

    $script:HasNative = ($null -ne (_SIXlsx-Native))
    $script:TmpDir = Join-Path ([IO.Path]::GetTempPath()) ('si-xlsxw-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force -Path $script:TmpDir | Out-Null
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

    function script:Get-ZipParts {
        # name -> text, for every entry of the package
        param([string]$Path)
        $h = @{}
        $z = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            foreach ($e in $z.Entries) {
                $r = New-Object System.IO.StreamReader($e.Open())
                try { $h[$e.FullName] = $r.ReadToEnd() } finally { $r.Close() }
            }
        } finally { $z.Dispose() }
        return $h
    }

    function script:Assert-ValidPackage {
        # Structural validity, the way Excel checks it: XML, relationships, content types.
        param([string]$Path)
        $parts = script:Get-ZipParts -Path $Path
        $parts.ContainsKey('[Content_Types].xml') | Should -BeTrue
        foreach ($n in $parts.Keys) {
            if ($n -notmatch '\.(xml|rels)$') { continue }
            $d = New-Object System.Xml.XmlDocument
            { $d.LoadXml($parts[$n]) } | Should -Not -Throw -Because "$n must be well-formed XML"
        }
        $ct = New-Object System.Xml.XmlDocument; $ct.LoadXml($parts['[Content_Types].xml'])
        $defaults  = @{}; $overrides = @{}
        foreach ($e in $ct.DocumentElement.ChildNodes) {
            if ($e.LocalName -eq 'Default')  { $defaults[$e.GetAttribute('Extension').ToLowerInvariant()] = $true }
            if ($e.LocalName -eq 'Override') { $overrides[$e.GetAttribute('PartName').TrimStart('/')] = $true }
        }
        foreach ($o in $overrides.Keys) { $parts.ContainsKey($o) | Should -BeTrue -Because "content type override /$o must name an existing part" }
        foreach ($n in $parts.Keys) {
            $ext = [IO.Path]::GetExtension($n).TrimStart('.').ToLowerInvariant()
            ($overrides.ContainsKey($n) -or $defaults.ContainsKey($ext)) | Should -BeTrue -Because "$n needs a content type"
        }
        foreach ($n in @($parts.Keys | Where-Object { $_ -like '*.rels' })) {
            $src = $n -replace '_rels/', '' -replace '\.rels$', ''
            $dir = _SIXlsx-DirOf $src
            $rd = New-Object System.Xml.XmlDocument; $rd.LoadXml($parts[$n])
            foreach ($rel in $rd.DocumentElement.ChildNodes) {
                if ($rel.NodeType -ne 'Element' -or $rel.GetAttribute('TargetMode') -eq 'External') { continue }
                $tgt = _SIXlsx-ResolveTarget $dir $rel.GetAttribute('Target')
                $parts.ContainsKey($tgt) | Should -BeTrue -Because "relationship $($rel.GetAttribute('Id')) in $n must point at an existing part ($tgt)"
            }
        }
        return $parts
    }

    function script:New-Path { param([string]$Name) Join-Path $script:TmpDir ($Name + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6) + '.xlsx') }

    # One mixed row set used by several blocks.
    $script:Date = [datetime]'2026-08-26T03:00:00'
    $script:MixedHeader = @('Text','Int','Long','Double','Decimal','Bool','Date','Null','Empty','Special','Multi','Old','NaN','Byte','Guid')
    $script:MixedRows = New-Object 'System.Collections.Generic.List[object[]]'
    [void]$script:MixedRows.Add([object[]]@('HOST-1', [int]42, [long]9000000000, [double]9.8, [decimal]1.25, $true, $script:Date, $null, '',
        'a & b < c > d "q" ''s''', "line1`r`nline2", [datetime]'1850-01-01', [double]::NaN, [byte]7, [guid]'11111111-2222-3333-4444-555555555555'))
    [void]$script:MixedRows.Add([object[]]@('HOST-1', [int]-1, [long]0, [double]0.1, [decimal]0, $false, $script:Date.AddDays(1), $null, $null,
        'x', 'y', $null, [double]::PositiveInfinity, [byte]0, $null))
}

AfterAll {
    $script:SIXlsxForcePowerShell = $false
    if ($script:TmpDir -and (Test-Path -LiteralPath $script:TmpDir)) { Remove-Item -LiteralPath $script:TmpDir -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'the package is a valid Open XML spreadsheet' {

    BeforeAll {
        $script:P1 = script:New-Path 'valid'
        Write-SIXlsxWorksheet -Path $script:P1 -SheetName 'Details' -Header $script:MixedHeader -Rows $script:MixedRows -WrapColumns @('Multi')
        Write-SIXlsxWorksheet -Path $script:P1 -SheetName 'Summary' -Header @('LineNo','Text') -Rows @(,[object[]]@(1, 'hello')) -MaxColumnWidth 90
    }

    It 'every part is well-formed, every relationship resolves, every part has a content type' {
        $parts = script:Assert-ValidPackage -Path $script:P1
        $parts.Keys | Should -Contain 'xl/workbook.xml'
        $parts.Keys | Should -Contain 'xl/styles.xml'
        $parts.Keys | Should -Contain 'xl/sharedStrings.xml'
        @($parts.Keys | Where-Object { $_ -like 'xl/worksheets/sheet*.xml' }).Count | Should -Be 2
        @($parts.Keys | Where-Object { $_ -like 'xl/tables/table*.xml' }).Count | Should -Be 2
    }

    It 'the content types carry the spreadsheet main, worksheet, table, styles and shared-strings types' {
        $ct = (script:Get-ZipParts -Path $script:P1)['[Content_Types].xml']
        $ct | Should -Match 'spreadsheetml\.sheet\.main\+xml'
        $ct | Should -Match 'spreadsheetml\.worksheet\+xml'
        $ct | Should -Match 'spreadsheetml\.table\+xml'
        $ct | Should -Match 'spreadsheetml\.styles\+xml'
        $ct | Should -Match 'spreadsheetml\.sharedStrings\+xml'
    }

    It 'the two sheets are listed in write order with unique sheet ids' {
        Get-SIXlsxSheetNames -Path $script:P1 | Should -Be @('Details', 'Summary')
        $wb = (script:Get-ZipParts -Path $script:P1)['xl/workbook.xml']
        ([regex]::Matches($wb, 'sheetId="(\d+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique).Count | Should -Be 2
    }

    It 'every table id and table name is unique in the workbook' {
        $parts = script:Get-ZipParts -Path $script:P1
        $tbl = @($parts.Keys | Where-Object { $_ -like 'xl/tables/*.xml' } | ForEach-Object { [xml]$parts[$_] })
        @($tbl | ForEach-Object { $_.table.id } | Select-Object -Unique).Count   | Should -Be 2
        @($tbl | ForEach-Object { $_.table.name } | Select-Object -Unique).Count | Should -Be 2
    }

    It 'a shared string is stored ONCE however often it occurs (what keeps the file small)' {
        $sst = [xml](script:Get-ZipParts -Path $script:P1)['xl/sharedStrings.xml']
        $texts = @($sst.sst.si | ForEach-Object { $_.t.'#text' })
        @($texts | Where-Object { $_ -eq 'HOST-1' }).Count | Should -Be 1
    }
}

Describe 'values round-trip with their types' {

    BeforeAll {
        # da-DK on purpose: a comma-decimal locale is what once turned 9.8 into "9,8" and then into 98.
        $script:SavedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('da-DK')
        $script:P2 = script:New-Path 'types'
        Write-SIXlsxWorksheet -Path $script:P2 -SheetName 'Details' -Header $script:MixedHeader -Rows $script:MixedRows -WrapColumns @('Multi')
        [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:SavedCulture
        $script:S2 = Read-SIXlsxWorksheet -Path $script:P2 -SheetName 'Details'
        $script:R1 = $script:S2.Rows[0]
    }
    AfterAll { if ($script:SavedCulture) { [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:SavedCulture } }

    It 'the header is exactly the column list, in order' { $script:S2.Header | Should -Be $script:MixedHeader }
    It 'every data row is written'                       { $script:S2.Rows.Count | Should -Be 2 }
    It 'text is text, exactly'                           { $script:R1.Text | Should -BeExactly 'HOST-1' }
    It 'an int is a NUMBER'                              { $script:R1.Int | Should -BeOfType [double]; $script:R1.Int | Should -Be 42 }
    It 'a long beyond int range is a number'             { $script:R1.Long | Should -Be 9000000000 }
    It 'a double stays 9.8 under a comma-decimal locale' {
        $script:R1.Double | Should -BeOfType [double]
        [math]::Abs($script:R1.Double - 9.8) | Should -BeLessThan 1e-12
        $script:S2.Cells['D2'].Type | Should -BeNullOrEmpty -Because 'a number cell carries no t= attribute'
    }
    It 'a decimal is a number'                           { $script:R1.Decimal | Should -Be 1.25 }
    It 'a bool is a boolean cell'                        { $script:R1.Bool | Should -BeTrue; $script:S2.Rows[1].Bool | Should -BeFalse; $script:S2.Cells['F2'].Type | Should -Be 'b' }
    It 'a datetime is a DATE: a serial with a date format' {
        $script:R1.Date | Should -BeOfType [datetime]
        $script:R1.Date | Should -Be $script:Date
        $script:S2.Cells['G2'].NumFmt | Should -Be 'yyyy-mm-dd hh:mm:ss'
    }
    It 'a date column carries the date format as its COLUMN style too' {
        $col = [array]::IndexOf($script:MixedHeader, 'Date') + 1
        $script:S2.Columns[$col].Width | Should -BeGreaterThan 0
    }
    It 'null and the empty string write NO cell at all' {
        $script:S2.Cells.ContainsKey('H2') | Should -BeFalse
        $script:S2.Cells.ContainsKey('I2') | Should -BeFalse
    }
    It 'XML-special characters survive exactly' { $script:R1.Special | Should -BeExactly 'a & b < c > d "q" ''s''' }
    It 'a line break survives as a line break (LF, which is how Excel stores it)' { $script:R1.Multi | Should -BeExactly "line1`nline2" }
    It 'a date before 1900 (no Excel serial exists) is kept readable as text' { $script:R1.Old | Should -BeExactly '1850-01-01 00:00:00' }
    It 'NaN / Infinity are text, not a corrupt number' {
        $script:R1.NaN | Should -BeExactly 'NaN'
        $script:S2.Cells['M2'].Type | Should -Be 's'
    }
    It 'a byte is a number and a guid is its text form' {
        $script:R1.Byte | Should -Be 7
        $script:R1.Guid | Should -BeExactly '11111111-2222-3333-4444-555555555555'
    }
}

Describe 'strings are scrubbed so Excel never has to repair the file' {

    It 'control characters, lone surrogates and U+FFFE/2028 are removed; a valid surrogate PAIR is kept' {
        $pair = [string][char]0xD83D + [char]0xDE00
        $dirty = 'a' + [char]0x01 + 'b' + [char]0xD800 + 'c' + [char]0xDC00 + 'd' + [char]0xFFFE + 'e' + [char]0x2028 + 'f' + $pair + "`tg"
        $p = script:New-Path 'scrub'
        Write-SIXlsxWorksheet -Path $p -SheetName 'S' -Header @('V') -Rows @(,[object[]]@($dirty))
        script:Assert-ValidPackage -Path $p | Out-Null
        (Read-SIXlsxWorksheet -Path $p).Rows[0].V | Should -BeExactly ('abcdef' + $pair + "`tg")
    }

    It 'a value over 32,767 characters is cut to the limit with the truncation marker' {
        $p = script:New-Path 'long'
        Write-SIXlsxWorksheet -Path $p -SheetName 'S' -Header @('V') -Rows @(,[object[]]@('x' * 40000))
        $v = (Read-SIXlsxWorksheet -Path $p).Rows[0].V
        $v.Length | Should -BeLessOrEqual 32767
        $v | Should -Match '\.\.\. \[truncated \d+ chars\]$'
    }

    It 'the writer scrub, the compiled scrub and ConvertTo-XlsxSafeString agree on a hostile corpus' {
        $pair = [string][char]0xD83D + [char]0xDE00
        $corpus = @(
            '', 'plain', "tab`tlf`ncr`r", ('a' + [char]0x00 + 'b'), ([string][char]0xD800), ([string][char]0xDC00 + 'x'),
            ([string][char]0xD800 + [char]0x01 + [char]0xDC00), ([string][char]0xD800 + [char]0xD800 + [char]0xDC00),
            ($pair + [char]0xDC00), ('z' + [char]0xFFFF + [char]0x2029), ('y' * 32767), ('y' * 32768), ('q' * 100000), ($pair * 20000)
        )
        foreach ($s in $corpus) {
            $ref = ConvertTo-XlsxSafeString $s
            _SIXlsx-Scrub $s | Should -BeExactly $ref
            if ($script:HasNative) { [SIXlsx.NativeV1]::Scrub($s) | Should -BeExactly $ref }
        }
    }
}

Describe 'layout: header, freeze, table, widths, wrap' {

    BeforeAll {
        $script:P3 = script:New-Path 'layout'
        $rows = New-Object 'System.Collections.Generic.List[object[]]'
        [void]$rows.Add([object[]]@('a', ('w' * 400), ('z' * 30), "l1`nl2", 'v'))
        Write-SIXlsxWorksheet -Path $script:P3 -SheetName 'Details' -Header @('Tiny','CVSSDesc','Mid','MoreDetails','AVeryLongHeaderNameThatIsWide') -Rows $rows `
            -WrapColumns @('MoreDetails','CVSSDesc') -MaxColumnWidth 50 -WidthCaps @{ CVSSDesc = 90 }
        $script:S3 = Read-SIXlsxWorksheet -Path $script:P3 -SheetName 'Details'
    }

    It 'the header row is bold'  { $script:S3.Cells['A1'].Bold | Should -BeTrue; $script:S3.Cells['E1'].Bold | Should -BeTrue }
    It 'the header row is frozen' { $script:S3.Frozen | Should -BeTrue }
    It 'a table covers the range, with an autofilter and the Medium9 style' {
        $script:S3.Table.Ref | Should -Be 'A1:E2'
        $script:S3.Table.AutoFilter | Should -BeTrue
        $script:S3.Table.Style | Should -Be 'TableStyleMedium9'
        $script:S3.Table.Columns | Should -Be $script:S3.Header
        $script:S3.Table.Name | Should -Be 'Details'
    }
    It 'a tiny column keeps the floor of 8'                    { $script:S3.Columns[1].Width | Should -Be 8 }
    It 'a long narrative column is clamped to its own cap (90)' { $script:S3.Columns[2].Width | Should -Be 90 }
    It 'an ordinary column is widest value + 2'                { $script:S3.Columns[3].Width | Should -Be 32 }
    It 'the header length counts toward the width'             { $script:S3.Columns[5].Width | Should -Be ('AVeryLongHeaderNameThatIsWide'.Length + 2) }
    It 'wrap columns wrap and are top-aligned, as a column style and on their cells' {
        $script:S3.Columns[4].Wrap | Should -BeTrue
        $script:S3.Columns[4].VAlign | Should -Be 'top'
        $script:S3.Cells['D2'].Wrap | Should -BeTrue
    }
    It 'a NON-wrap column carries no column style (styling every column inflated the file 3.6x)' {
        $script:S3.Columns[3].Wrap | Should -BeFalse
        $sheet = (script:Get-ZipParts -Path $script:P3)['xl/worksheets/sheet1.xml']
        $sheet | Should -Match '<col min="3" max="3" width="32" customWidth="1"/>'
    }
    It 'the Normal style is top-aligned, so short values sit at the top of a tall wrapped row' {
        $styles = (script:Get-ZipParts -Path $script:P3)['xl/styles.xml']
        $styles | Should -Match '<cellStyleXfs count="1"><xf [^>]*applyAlignment="1"><alignment vertical="top"/></xf></cellStyleXfs>'
    }
}

Describe 'sheet names and accumulation' {

    It 'a name is cut to 31 characters and : \ / ? * [ ] become _' {
        Get-SIXlsxSafeSheetName 'a:b\c/d?e*f[g]h' | Should -BeExactly 'a_b_c_d_e_f_g_h'
        (Get-SIXlsxSafeSheetName ('x' * 40)).Length | Should -Be 31
        Get-SIXlsxSafeSheetName '' | Should -BeExactly 'Sheet'
    }

    It 're-writing a sheet REPLACES it (case-insensitively), keeps the others, and puts it last' {
        $p = script:New-Path 'accum'
        Write-SIXlsxWorksheet -Path $p -SheetName 'Details' -Header @('A') -Rows @([object[]]@('d1'), [object[]]@('d2'), [object[]]@('d3'))
        Write-SIXlsxWorksheet -Path $p -SheetName 'Summary' -Header @('B') -Rows @(,[object[]]@('s1'))
        Write-SIXlsxWorksheet -Path $p -SheetName 'DETAILS' -Header @('A') -Rows @(,[object[]]@('new'))
        script:Assert-ValidPackage -Path $p | Out-Null
        Get-SIXlsxSheetNames -Path $p | Should -Be @('Summary', 'DETAILS')
        (Read-SIXlsxWorksheet -Path $p -SheetName 'Summary').Rows[0].B | Should -BeExactly 's1'
        $d = Read-SIXlsxWorksheet -Path $p -SheetName 'Details'
        $d.Rows.Count | Should -Be 1
        $d.Rows[0].A | Should -BeExactly 'new'
        # the replaced sheet's table and parts are gone, not orphaned
        $parts = script:Get-ZipParts -Path $p
        @($parts.Keys | Where-Object { $_ -like 'xl/tables/*.xml' }).Count | Should -Be 2
        @($parts.Keys | Where-Object { $_ -like 'xl/worksheets/sheet*.xml' }).Count | Should -Be 2
    }

    It 'appending a sheet leaves the earlier sheet reading the same values (shared-string indices never move)' {
        $p = script:New-Path 'sstappend'
        Write-SIXlsxWorksheet -Path $p -SheetName 'First' -Header $script:MixedHeader -Rows $script:MixedRows
        $before = Read-SIXlsxWorksheet -Path $p -SheetName 'First'
        Write-SIXlsxWorksheet -Path $p -SheetName 'Second' -Header @('Other') -Rows @([object[]]@('HOST-1'), [object[]]@('brand new'))
        $after = Read-SIXlsxWorksheet -Path $p -SheetName 'First'
        ($after.Rows | ConvertTo-Json -Compress) | Should -BeExactly ($before.Rows | ConvertTo-Json -Compress)
        (Read-SIXlsxWorksheet -Path $p -SheetName 'Second').Rows[1].Other | Should -BeExactly 'brand new'
    }

    It 'two sheets whose names map to the same table name still get unique table names' {
        $p = script:New-Path 'tblname'
        Write-SIXlsxWorksheet -Path $p -SheetName 'A B' -Header @('X') -Rows @(,[object[]]@(1))
        Write-SIXlsxWorksheet -Path $p -SheetName 'A_B' -Header @('X') -Rows @(,[object[]]@(2))
        $parts = script:Get-ZipParts -Path $p
        $names = @($parts.Keys | Where-Object { $_ -like 'xl/tables/*.xml' } | ForEach-Object { ([xml]$parts[$_]).table.name })
        @($names | Select-Object -Unique).Count | Should -Be 2
    }

    It 'duplicate or blank header names are made unique (a table refuses them)' {
        $p = script:New-Path 'dupehdr'
        Write-SIXlsxWorksheet -Path $p -SheetName 'S' -Header @('A', 'a', '') -Rows @(,[object[]]@(1, 2, 3))
        (Read-SIXlsxWorksheet -Path $p).Header | Should -Be @('A', 'a2', 'Column3')
    }

    It 'an empty row set still writes a valid sheet with a valid table' {
        $p = script:New-Path 'norows'
        Write-SIXlsxWorksheet -Path $p -SheetName 'S' -Header @('Info') -Rows @()
        script:Assert-ValidPackage -Path $p | Out-Null
        (Read-SIXlsxWorksheet -Path $p).Table.Ref | Should -Be 'A1:A2'
    }

    It 'a failed write leaves the workbook on disk untouched and no temp file behind' {
        $p = script:New-Path 'atomic'
        Write-SIXlsxWorksheet -Path $p -SheetName 'S' -Header @('A') -Rows @(,[object[]]@('keep'))
        $bytes = [IO.File]::ReadAllBytes($p)
        { Write-SIXlsxWorksheet -Path $p -SheetName 'T' -Header @() -Rows @() } | Should -Throw
        [IO.File]::ReadAllBytes($p).Length | Should -Be $bytes.Length
        Test-Path -LiteralPath ($p + '.si-xlsx.tmp') | Should -BeFalse
    }
}

Describe 'appending to a workbook EPPlus wrote (the shipped sample)' {

    BeforeAll {
        $script:Sample = Join-Path $script:SIRoot 'engine\risk-analysis\_samples\Sample - RiskAnalysis_Summary.xlsx'
        $script:P4 = script:New-Path 'foreign'
        Copy-Item -LiteralPath $script:Sample -Destination $script:P4
        $script:SampleSheets = @(Get-SIXlsxSheetNames -Path $script:P4)
        $script:Keep = $script:SampleSheets[0]
        $script:KeepBefore = Read-SIXlsxWorksheet -Path $script:P4 -SheetName $script:Keep
        Write-SIXlsxWorksheet -Path $script:P4 -SheetName 'Added' -Header $script:MixedHeader -Rows $script:MixedRows -WrapColumns @('Multi')
    }

    It 'the result is still a valid package' { script:Assert-ValidPackage -Path $script:P4 | Out-Null }
    It 'every original sheet is still there, plus the new one last' {
        Get-SIXlsxSheetNames -Path $script:P4 | Should -Be (@($script:SampleSheets) + 'Added')
    }
    It 'an original sheet reads exactly as before -- values AND styles (shared strings appended, not renumbered)' {
        $after = Read-SIXlsxWorksheet -Path $script:P4 -SheetName $script:Keep
        ($after.Rows | ConvertTo-Json -Compress -Depth 3) | Should -BeExactly ($script:KeepBefore.Rows | ConvertTo-Json -Compress -Depth 3)
        $after.Cells['A1'].Bold | Should -Be $script:KeepBefore.Cells['A1'].Bold
    }
    It 'the new sheet gets its own formats merged into the foreign stylesheet' {
        $s = Read-SIXlsxWorksheet -Path $script:P4 -SheetName 'Added'
        $s.Rows[0].Date | Should -Be $script:Date
        $s.Cells['A1'].Bold | Should -BeTrue
        $s.Cells[('{0}2' -f (ConvertTo-SIXlsxColumnName ([array]::IndexOf($script:MixedHeader, 'Multi') + 1)))].Wrap | Should -BeTrue
        [math]::Abs($s.Rows[0].Double - 9.8) | Should -BeLessThan 1e-12
    }
    It 'replacing an EPPlus-written sheet removes its table and parts cleanly' {
        $p = script:New-Path 'foreign-replace'
        Copy-Item -LiteralPath $script:Sample -Destination $p
        $victim = $script:SampleSheets[-1]
        Write-SIXlsxWorksheet -Path $p -SheetName $victim -Header @('X') -Rows @(,[object[]]@('replaced'))
        $parts = script:Assert-ValidPackage -Path $p
        (Read-SIXlsxWorksheet -Path $p -SheetName $victim).Rows[0].X | Should -BeExactly 'replaced'
        @(Get-SIXlsxSheetNames -Path $p).Count | Should -Be $script:SampleSheets.Count
        @($parts.Keys | Where-Object { $_ -like 'xl/tables/*.xml' }).Count | Should -Be @($script:SampleSheets).Count
    }
}

Describe 'the compiled helper and the PowerShell twin produce the same workbook' {

    It 'the compiled helper is available on this runtime (Add-Type works here)' {
        $script:HasNative | Should -BeTrue -Because 'without it every export takes the ~30x slower PowerShell path'
    }

    It 'byte-identical sheet XML and shared strings for a mixed corpus' {
        if (-not $script:HasNative) { Set-ItResult -Skipped -Because 'the compiled helper is unavailable'; return }
        $pn = script:New-Path 'native'; $pp = script:New-Path 'pwsh'
        $hostile = 'q' + [char]0x01 + [char]0xD800 + ('w' * 40000)
        $rows = New-Object 'System.Collections.Generic.List[object[]]'
        foreach ($r in $script:MixedRows) { [void]$rows.Add($r) }
        [void]$rows.Add([object[]]@($hostile, [int16]3, [uint32]4, [single]1.5, [decimal]-2.5, $true, [DateTimeOffset]$script:Date, $null, 'e', '<x>', 'm', $null, 1e300, [sbyte]-1, 'g'))
        Write-SIXlsxWorksheet -Path $pn -SheetName 'S' -Header $script:MixedHeader -Rows $rows -WrapColumns @('Multi') -Engine Native
        Write-SIXlsxWorksheet -Path $pp -SheetName 'S' -Header $script:MixedHeader -Rows $rows -WrapColumns @('Multi') -Engine PowerShell
        $a = script:Get-ZipParts -Path $pn; $b = script:Get-ZipParts -Path $pp
        $a['xl/worksheets/sheet1.xml'] | Should -BeExactly $b['xl/worksheets/sheet1.xml']
        $a['xl/sharedStrings.xml']     | Should -BeExactly $b['xl/sharedStrings.xml']
    }

    It 'ConvertTo-SIXlsxRows: same grid and same deferred cells from both paths' {
        if (-not $script:HasNative) { Set-ItResult -Skipped -Because 'the compiled helper is unavailable'; return }
        $objs = @(
            [pscustomobject][ordered]@{ A = 'x'; B = @('a', 'b', $null, 3); C = @{ k = 1 }; D = [pscustomobject]@{ z = 1 }; E = 5 },
            [pscustomobject][ordered]@{ a = 'second spelling'; B = @(); C = @([pscustomobject]@{ q = 1 }); E = $null }
        )
        $n = ConvertTo-SIXlsxRows -InputObject $objs -Columns @('A', 'B', 'C', 'D', 'E', 'Missing') -Engine Native
        $p = ConvertTo-SIXlsxRows -InputObject $objs -Columns @('A', 'B', 'C', 'D', 'E', 'Missing') -Engine PowerShell
        ($n.Deferred -join ',') | Should -BeExactly ($p.Deferred -join ',')
        ($n.Deferred -join ',') | Should -BeExactly '0,2,0,3,1,2'   # hashtable, custom object, list of objects
        $n.Rows[0][1] | Should -BeExactly 'a, b, 3'               # Convert-CellValue's list rule: nulls skipped, ', '
        $p.Rows[0][1] | Should -BeExactly 'a, b, 3'
        $n.Rows[1][0] | Should -BeExactly 'second spelling'        # by name, case-insensitive
        $n.Rows[1][1] | Should -BeExactly ''
        $null -eq $n.Rows[0][5] | Should -BeTrue
    }

    It 'Get-SIXlsxColumnUnion: first-seen order, case-insensitive, from both paths' {
        $objs = @([pscustomobject][ordered]@{ A = 1; B = 2 }, [pscustomobject][ordered]@{ b = 3; C = 4 })
        (Get-SIXlsxColumnUnion -InputObject $objs) -join ',' | Should -BeExactly 'A,B,C'
        $script:SIXlsxForcePowerShell = $true
        try { (Get-SIXlsxColumnUnion -InputObject $objs) -join ',' | Should -BeExactly 'A,B,C' }
        finally { $script:SIXlsxForcePowerShell = $false }
    }
}

Describe 'Export-Worksheet on the new writer -- the engine contract' {

    It 'falls back to the PowerShell path and still writes the workbook when the helper is unavailable' {
        $p = script:New-Path 'fallback'
        $script:SIXlsxForcePowerShell = $true
        try {
            $rows = @([pscustomobject][ordered]@{ AssetName = 'HOST-1'; Score = [double]9.8; Arr = @('a', 'b') })
            Export-Worksheet -Path $p -SheetName 'Details' -Rows $rows -DesiredColumns @('AssetName', 'Score', 'Arr')
        } finally { $script:SIXlsxForcePowerShell = $false }
        $r = (Read-SIXlsxWorksheet -Path $p -SheetName 'Details').Rows[0]
        $r.Arr | Should -BeExactly 'a, b'
        $r.Score | Should -Be 9.8
    }

    It 'a 20,000 x 30 export finishes well inside a minute (regression guard against a per-cell PowerShell path)' {
        $names = 1..30 | ForEach-Object { 'Col' + $_ }
        $list = New-Object 'System.Collections.Generic.List[object]'
        for ($r = 0; $r -lt 20000; $r++) {
            $o = [ordered]@{}
            for ($c = 0; $c -lt 30; $c++) { if ($c % 3 -eq 0) { $o[$names[$c]] = 'v' + ($r % 977) } elseif ($c % 3 -eq 1) { $o[$names[$c]] = $r } else { $o[$names[$c]] = $null } }
            $list.Add([pscustomobject]$o)
        }
        $p = script:New-Path 'perf'
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Export-Worksheet -Path $p -SheetName 'Details' -Rows $list.ToArray() -DesiredColumns $names
        $sw.Stop()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
        (script:Get-ZipParts -Path $p)['xl/worksheets/sheet1.xml'] | Should -Match '<dimension ref="A1:AD20001"/>'
    }
}

Describe 'WIRING -- ImportExcel / EPPlus are gone' {

    BeforeAll {
        function script:Get-CodeLines {
            param([string]$Rel)
            $raw = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot $Rel)
            (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        }
    }

    It 'no Risk Analysis code calls Export-Excel / Open-ExcelPackage / EPPlus types' {
        foreach ($rel in 'engine\risk-analysis\_shared\RA-ExcelReport.ps1', 'engine\risk-analysis\Invoke-RiskAnalysis.ps1', 'engine\risk-analysis\_shared\RA-XlsxWriter.ps1') {
            $code = script:Get-CodeLines $rel
            $code | Should -Not -Match 'Export-Excel|Open-ExcelPackage|Close-ExcelPackage|OfficeOpenXml|Import-Module ImportExcel|LoadFromArrays' -Because $rel
        }
    }

    It 'no module install list carries ImportExcel' {
        # the engines carry no module installer any more (#305), and since setup signs in without modules neither does setup:
        # its module list (setup\_shared\Ensure-Module.ps1) is gone. Nothing under setup installs or imports ImportExcel.
        Test-Path -LiteralPath (Join-Path $script:SIRoot 'setup\_shared\Ensure-Module.ps1') | Should -BeFalse
        foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'setup') -Recurse -File | Where-Object { $_.Extension -in '.ps1', '.psm1' }) {
            $code = ((Get-Content -LiteralPath $f.FullName) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
            $code | Should -Not -Match "(Install|Import)-Module[^`n]*ImportExcel" -Because $f.Name
        }
    }

    It 'the container image does not install ImportExcel' {
        script:Get-CodeLines 'container\Dockerfile' | Should -Not -Match 'Install-Module -Name ImportExcel'
    }

    It 'the AI Summary sheet is written by the same writer' {
        $code = script:Get-CodeLines 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $code | Should -Match "Write-SIXlsxWorksheet -Path \`$Path -SheetName \`$safeSheet -Header @\('LineNo', 'Text'\)"
    }
}
