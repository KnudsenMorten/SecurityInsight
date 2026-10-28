#Requires -Version 5.1
<#
    v2.2.445 -- THE EXCEL EXPORT MOVED FROM PER-CELL TO BULK, AND THESE PIN WHAT MUST NOT CHANGE.
    v3       -- AND THEN OFF ImportExcel / EPPlus ALTOGETHER, ONTO SI'S OWN .xlsx WRITER.

    A customer's Detailed run spent 20,051.92s (5h34m) in the Excel export alone. Measured cause:
    ImportExcel's Export-Excel writes cells ONE AT A TIME from PowerShell at ~0.55 ms/cell, and that
    single rate predicts their 121,111-row x 291-column workbook at 19,384s -- within 3.4% of the
    observed figure. v2.2.445 moved the write into EPPlus's LoadFromArrays; v3 replaces EPPlus with
    engine/risk-analysis/_shared/RA-XlsxWriter.ps1 (pure .NET, no module), whose per-cell work runs in a
    small compiled helper. Writer-level tests live in SIv3-XlsxWriter.Tests.ps1.

    SPEED IS THE EASY HALF. These tests exist for the other half -- that the workbook Export-Worksheet
    produces is INDISTINGUISHABLE from what it produced before. Two of them encode defects the v2.2.445
    rewrite actually introduced, which only running it caught:
      * a [datetime] became the raw OLE serial "46260,125" -- a date needs an explicit number format
      * the package is opened/created by the export itself, so multi-sheet accumulation had to be
        re-proven -- get it wrong and writing 'Details' silently destroys a sheet written earlier
    Every case reads the produced file back through Read-SIXlsxWorksheet, so none needs a module and
    none skips in CI.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Report = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'
    $script:Code   = Get-Content $script:Report -Raw

    # STRIP FULL-LINE COMMENTS BEFORE ANY "is this call gone?" MATCH. The block comments in
    # RA-ExcelReport.ps1 QUOTE the very calls they explain the removal of, so a naive regex over the
    # raw file counts the explanation as an occurrence and the test fails on prose.
    $script:CodeNoComments = (($script:Code -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    # DOT-SOURCE AT CONTAINER SCOPE. Doing this inside a helper function loads the definitions into
    # THAT function's scope, which is gone the moment it returns.
    $script:_sheetWritten = @{}
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RunProgress.ps1')
    . $script:Report
    $script:_sheetWritten = @{}

    function script:New-TestRows {
        param([int]$Rows = 25)
        $l = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Rows; $i++) {
            $l.Add([pscustomobject][ordered]@{
                CollectionTime          = [datetime]'2026-08-26T03:00:00'
                RiskScoreTotal_Weighted = [int]($Rows - $i)
                Score                   = [double]9.8
                AssetName               = "HOST-$i"
                MoreDetails             = "line1`r`nline2"
                CVSSDesc                = ('x' * 400)
                Tiny                    = 'a'
                Arr                     = @('a', 'b')
                Empty                   = $null
            })
        }
        , $l.ToArray()
    }
}

Describe 'WIRING -- the populated branch writes through SI''s own writer, in bulk' {

    It 'hands the whole grid to the writer in one call' {
        $script:CodeNoComments | Should -Match 'ConvertTo-SIXlsxRows -InputObject \$Data'
        $script:CodeNoComments | Should -Match 'Write-SIXlsxWorksheet -Path \$_fullPath -SheetName \$safeSheet -Header \$_names -Rows \$_grid\.Rows'
    }

    It 'no longer pipes the dataset into Export-Excel, nor uses EPPlus at all' {
        $script:CodeNoComments | Should -Not -Match 'Export-Excel|LoadFromArrays|OfficeOpenXml|Open-ExcelPackage'
    }

    It 'does NOT AutoFitColumns -- widths come from measured lengths, so Linux matches Windows' {
        $script:CodeNoComments | Should -Not -Match 'AutoFitColumns'
    }

    It 'no per-cell PowerShell loop over the rows remains in Export-Worksheet' {
        # The ~87 us/cell scrub-and-measure loop is what the compiled helper replaced.
        $script:CodeNoComments | Should -Not -Match 'foreach \(\$row in \$Data\)'
        $script:CodeNoComments | Should -Not -Match 'ConvertTo-XlsxSafeString \$v'
    }

    It 'the redundant -ColumnsToFlatten rebuild pass is gone but the PARAMETER remains' {
        $script:Code | Should -Match '\[string\[\]\]\$ColumnsToFlatten'
        $script:Code | Should -Not -Match '\$ColumnsToFlatten -contains \$p\.Name'
    }
}

Describe 'OUTPUT FIDELITY -- the workbook keeps its contract' {

    BeforeAll {
        $script:_sheetWritten = @{}
        # da-DK ON PURPOSE. A comma-decimal locale is what turned 9.8 into "9,8" and then into 98 on the
        # old string-serialising path. It has to be PROVEN safe rather than assumed safe.
        $script:SavedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('da-DK')

        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ("si-bulk-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        $rows  = script:New-TestRows -Rows 25
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out -SheetName 'Details' -Rows $rows -DesiredColumns $names `
            -ColumnsToFlatten @('Arr') -TableStyle 'Medium9'

        $script:Ws  = Read-SIXlsxWorksheet -Path $script:Out -SheetName 'Details'
        $script:Col = @{}
        for ($c = 1; $c -le $script:Ws.Header.Count; $c++) { $script:Col[$script:Ws.Header[$c - 1]] = $c }
        function script:Cell([int]$Row, [string]$Name) { $script:Ws.Cells[(ConvertTo-SIXlsxColumnName $script:Col[$Name]) + $Row] }
    }

    AfterAll {
        if ($script:Out -and (Test-Path $script:Out)) { Remove-Item $script:Out -Force }
        if ($script:SavedCulture) { [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:SavedCulture }
    }

    It 'writes every row plus a header' { $script:Ws.RowCount | Should -Be 26 }
    It 'writes every column'            { $script:Ws.Header.Count | Should -Be 9 }

    It 'a double stays a NUMBER under a comma-decimal locale' {
        $v = (script:Cell 2 'Score').Value
        $v | Should -BeOfType [double]
        [math]::Abs($v - 9.8) | Should -BeLessThan 1e-9
    }

    It 'an int stays numeric (Excel stores all numbers as double)' {
        (script:Cell 2 'RiskScoreTotal_Weighted').Value | Should -BeOfType [double]
    }

    It 'a datetime RENDERS AS A DATE, not as its OLE serial' {
        $c = script:Cell 2 'CollectionTime'
        $c.NumFmt | Should -Be 'yyyy-mm-dd hh:mm:ss'
        $c.Value | Should -Be ([datetime]'2026-08-26T03:00:00')
    }

    It 'an array is flattened to a joined string (the -ColumnsToFlatten contract)' {
        [string](script:Cell 2 'Arr').Value | Should -BeExactly 'a, b'
    }

    It 'a null stays an EMPTY cell rather than the string "null"' {
        script:Cell 2 'Empty' | Should -BeNullOrEmpty
    }

    It 'row ORDER is preserved exactly as handed in' {
        [string](script:Cell 2  'AssetName').Value | Should -BeExactly 'HOST-0'
        [string](script:Cell 26 'AssetName').Value | Should -BeExactly 'HOST-24'
    }

    It 'a long narrative column is clamped to its wide cap of 90' {
        [math]::Round($script:Ws.Columns[$script:Col['CVSSDesc']].Width) | Should -Be 90
    }

    It 'a tiny column keeps a readable floor instead of collapsing' {
        $script:Ws.Columns[$script:Col['Tiny']].Width | Should -BeGreaterOrEqual 8
    }

    It 'known multi-line columns keep WrapText' {
        $script:Ws.Columns[$script:Col['MoreDetails']].Wrap | Should -BeTrue
    }

    It 'a WRAPPED column is top-aligned -- the only place the alignment is visible' {
        $script:Ws.Columns[$script:Col['MoreDetails']].VAlign | Should -Be 'top'
    }

    It 'a NON-wrapped column is NOT styled -- styling all 291 cost 3.6x the FILE SIZE' {
        # v2.2.448: styling a column materialised a styled cell for every empty slot of a ~85%-empty
        # cross-report union. The mail attachment cap is 20 MB, so an inflated workbook can silently
        # stop being attached.
        $script:Ws.Columns[$script:Col['AssetName']].Wrap | Should -BeFalse
        $script:Ws.Columns[$script:Col['AssetName']].VAlign | Should -BeNullOrEmpty
    }

    It 'the sheet still carries a table, which is what provides the autofilter' {
        $script:Ws.Table.Name | Should -Be 'Details'
        $script:Ws.Table.AutoFilter | Should -BeTrue
        $script:Ws.Table.Style | Should -Be 'TableStyleMedium9'
    }

    It 'the header row is bold and frozen' {
        $script:Ws.Cells['A1'].Bold | Should -BeTrue
        $script:Ws.Frozen | Should -BeTrue
    }
}

Describe 'MULTI-SHEET ACCUMULATION -- writing one sheet must not destroy another' {
    # The index sheet and the AI-summary sheet are written by separate calls against the same file, so
    # a second call that started a NEW workbook would be a real destruction path.

    BeforeAll {
        $script:_sheetWritten = @{}
        $script:Out2 = Join-Path ([IO.Path]::GetTempPath()) ("si-multi-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        $rows  = script:New-TestRows -Rows 5
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out2 -SheetName 'First'  -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
        Export-Worksheet -Path $script:Out2 -SheetName 'Second' -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
    }

    AfterAll { if ($script:Out2 -and (Test-Path $script:Out2)) { Remove-Item $script:Out2 -Force } }

    It 'BOTH sheets survive' {
        $sheets = @(Get-SIXlsxSheetNames -Path $script:Out2)
        $sheets | Should -Contain 'First'
        $sheets | Should -Contain 'Second'
    }

    It 're-writing an existing sheet REPLACES it rather than appending (the -ClearSheet contract)' {
        $rows  = script:New-TestRows -Rows 3
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out2 -SheetName 'First' -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
        (Read-SIXlsxWorksheet -Path $script:Out2 -SheetName 'First').RowCount | Should -Be 4   # 3 data rows + header
        (Read-SIXlsxWorksheet -Path $script:Out2 -SheetName 'Second').RowCount | Should -Be 6
    }
}

Describe 'the empty-rows branch still works' {

    It 'writes a placeholder sheet without throwing' {
        $script:_sheetWritten = @{}
        $out = Join-Path ([IO.Path]::GetTempPath()) ("si-empty-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        try {
            { Export-Worksheet -Path $out -SheetName 'Details' -Rows @() -TableStyle 'Medium9' } | Should -Not -Throw
            Test-Path $out | Should -BeTrue
            (Read-SIXlsxWorksheet -Path $out -SheetName 'Details').Rows[0].Info | Should -BeExactly 'No rows returned'
        } finally { if (Test-Path $out) { Remove-Item $out -Force } }
    }
}

Describe 'THE EXPORT NEEDS NO MODULE -- proven in a fresh process' {
    # v2.2.450's lesson: a real run died with "Cannot find type [OfficeOpenXml.ExcelPackage]" on the
    # FINAL WRITE because the harness imported ImportExcel and the engine did not. Green offline is not
    # the same as works in production, so this runs in a CHILD PROCESS that has never loaded any Excel
    # module -- the only way to reproduce production's conditions rather than the harness's.

    It 'Export-Worksheet succeeds in a FRESH PowerShell process (the gate''s own host: pwsh 7 on v3) with no Excel module loaded' {
        $child = Join-Path ([IO.Path]::GetTempPath()) ("si-noimport-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
        $out   = Join-Path ([IO.Path]::GetTempPath()) ("si-noimport-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        $body  = @"
`$ErrorActionPreference='Stop'
if (Get-Module ImportExcel) { Write-Output 'PRELOADED'; exit 2 }
`$script:_sheetWritten=@{}
. '$($script:SIRoot)\engine\risk-analysis\_shared\RA-RunProgress.ps1'
. '$($script:SIRoot)\engine\risk-analysis\_shared\RA-ExcelReport.ps1'
`$script:_sheetWritten=@{}
`$rows=@([pscustomobject][ordered]@{ AssetName='HOST-1'; Score=[double]9.8 })
Export-Worksheet -Path '$out' -SheetName 'Details' -Rows `$rows ``
    -DesiredColumns @('AssetName','Score') -TableStyle 'Medium9'
if (Get-Module ImportExcel) { Write-Output 'IMPORTED'; exit 3 }
if ('OfficeOpenXml.ExcelPackage' -as [type]) { Write-Output 'EPPLUS-LOADED'; exit 4 }
if (Test-Path '$out') { Write-Output 'OK'; exit 0 } else { Write-Output 'NOFILE'; exit 1 }
"@
        Set-Content -Path $child -Value $body -Encoding UTF8
        try {
            $res = & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File $child 2>&1
            $code = $LASTEXITCODE
            $code | Should -Not -Be 2 -Because "the child must start WITHOUT ImportExcel loaded, or this case is vacuous"
            $code | Should -Be 0 -Because ("child output: " + ($res -join ' | '))
        } finally {
            if (Test-Path $child) { Remove-Item $child -Force }
            if (Test-Path $out)   { Remove-Item $out   -Force }
        }
    }

    It 'the export code never imports ImportExcel' {
        $script:CodeNoComments | Should -Not -Match 'Import-Module ImportExcel'
    }
}
