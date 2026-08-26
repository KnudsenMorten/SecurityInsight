#Requires -Version 5.1
<#
    v2.2.445 -- THE EXCEL EXPORT MOVED FROM PER-CELL TO BULK, AND THESE PIN WHAT MUST NOT CHANGE.

    A customer's Detailed run spent 20,051.92s (5h34m) in the Excel export alone. Measured cause:
    ImportExcel's Export-Excel writes cells ONE AT A TIME from PowerShell at ~0.55 ms/cell, and that
    single rate predicts their 121,111-row x 291-column workbook at 19,384s -- within 3.4% of the
    observed figure. Cost tracks cell SLOTS, not values: at 3,000 x 291, dropping 86% of the VALUES
    saved only 9% of the time, because every declared column is visited whether or not it holds
    anything, and the Detailed sheet is a cross-report union that is ~85% structurally empty.

    The export now hands the whole block to EPPlus via LoadFromArrays in one .NET call. Measured on
    the same data: the write 455.8s -> 3.2s, and end to end 520s -> 17.5s.

    🔑 SPEED IS THE EASY HALF. These tests exist for the other half -- that a workbook produced the
    fast way is INDISTINGUISHABLE from one produced the slow way. Two of them encode defects this
    rewrite actually introduced, which only running it caught:
      * a [datetime] became the raw OLE serial "46260,125" -- EPPlus applies no date format, and
        Export-Excel used to do it for us
      * the package is now opened/created here rather than by Export-Excel, so multi-sheet
        accumulation had to be re-proven -- get it wrong and writing 'Details' silently destroys the
        index sheet written by an earlier call to the same file
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Report = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'
    $script:Code   = Get-Content $script:Report -Raw
    $script:HasXl  = [bool](Get-Module -ListAvailable -Name ImportExcel)

    # 🪤 STRIP FULL-LINE COMMENTS BEFORE ANY "is this call gone?" MATCH. The block comments in
    # RA-ExcelReport.ps1 QUOTE the very calls they explain the removal of, so a naive regex over the
    # raw file counts the explanation as an occurrence and the test fails on prose. Caught on the
    # first run of this suite.
    $script:CodeNoComments = (($script:Code -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    # 🔑 DOT-SOURCE AT CONTAINER SCOPE. Doing this inside a helper function loads the definitions
    # into THAT function's scope, which is gone the moment it returns -- every It then fails with
    # "Export-Worksheet is not recognized". Also caught on the first run.
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

Describe 'WIRING -- the populated branch really is bulk, not per-cell' {

    It 'calls LoadFromArrays' {
        $script:Code | Should -Match 'LoadFromArrays'
    }

    It 'no longer pipes the whole dataset into Export-Excel' {
        # The empty-rows branch still uses Export-Excel for its single "No rows returned" row -- one
        # row, no cost. What must never come back is the piped BULK write.
        $script:Code | Should -Not -Match '\$Data \| Export-Excel'
    }

    It 'does NOT AutoFitColumns the full used range on the populated path' {
        # Measured at only 1% of the export, but it also drags in System.Drawing.Common, which is
        # absent on Linux containers -- where every column then fell back to width 10. Exactly ONE
        # occurrence may remain: the single-row empty branch.
        ([regex]::Matches($script:CodeNoComments, '\$ws\.Cells\.AutoFitColumns\(\)')).Count | Should -Be 1
    }

    It 'does NOT set VerticalAlignment across the full used range on the populated path' {
        ([regex]::Matches($script:CodeNoComments, '\$ws\.Cells\.Style\.VerticalAlignment')).Count | Should -Be 1
    }

    It 'the redundant -ColumnsToFlatten rebuild pass is gone but the PARAMETER remains' {
        # The parameter is still part of the signature and callers still pass it; the universal
        # flatten in the single pass is simply what does the work now.
        $script:Code | Should -Match '\[string\[\]\]\$ColumnsToFlatten'
        $script:Code | Should -Not -Match '\$ColumnsToFlatten -contains \$p\.Name'
    }
}

Describe 'OUTPUT FIDELITY -- a bulk-written workbook must be indistinguishable' -Skip:(-not [bool](Get-Module -ListAvailable -Name ImportExcel)) {

    BeforeAll {
        Import-Module ImportExcel -ErrorAction Stop
        $script:_sheetWritten = @{}
        # 🔑 da-DK ON PURPOSE. A comma-decimal locale is what turned 9.8 into "9,8" and then into 98
        # on the old string-serialising path. LoadFromArrays hands EPPlus the BOXED value, so this
        # has to be PROVEN safe rather than assumed safe.
        $script:SavedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
        [System.Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::GetCultureInfo('da-DK')

        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ("si-bulk-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        $rows  = script:New-TestRows -Rows 25
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out -SheetName 'Details' -Rows $rows -DesiredColumns $names `
            -ColumnsToFlatten @('Arr') -TableStyle 'Medium9'

        $script:Pkg = Open-ExcelPackage -Path $script:Out
        $script:Ws  = $script:Pkg.Workbook.Worksheets['Details']
        $script:Col = @{}
        for ($c = 1; $c -le $script:Ws.Dimension.Columns; $c++) {
            $script:Col[[string]$script:Ws.Cells[1, $c].Value] = $c
        }
    }

    AfterAll {
        if ($script:Pkg) { Close-ExcelPackage $script:Pkg -NoSave }
        if ($script:Out -and (Test-Path $script:Out)) { Remove-Item $script:Out -Force }
        if ($script:SavedCulture) { [System.Threading.Thread]::CurrentThread.CurrentCulture = $script:SavedCulture }
    }

    It 'writes every row plus a header' { $script:Ws.Dimension.Rows | Should -Be 26 }
    It 'writes every column'            { $script:Ws.Dimension.Columns | Should -Be 9 }

    It '🔴 a double stays a NUMBER under a comma-decimal locale' {
        $v = $script:Ws.Cells[2, $script:Col['Score']].Value
        $v | Should -BeOfType [double]
        [math]::Abs($v - 9.8) | Should -BeLessThan 1e-9
    }

    It 'an int stays numeric (Excel stores all numbers as double)' {
        $script:Ws.Cells[2, $script:Col['RiskScoreTotal_Weighted']].Value | Should -BeOfType [double]
    }

    It '🔴 a datetime RENDERS AS A DATE, not as its OLE serial' {
        # Without an explicit number format this cell reads "46260,125". A defect the rewrite
        # introduced and testing caught -- not something reading the code would have shown.
        $script:Ws.Cells[2, $script:Col['CollectionTime']].Text | Should -Match '^\d{4}-\d{2}-\d{2}'
    }

    It 'an array is flattened to a joined string (the -ColumnsToFlatten contract)' {
        [string]$script:Ws.Cells[2, $script:Col['Arr']].Value | Should -BeExactly 'a, b'
    }

    It 'a null stays an EMPTY cell rather than the string "null"' {
        $script:Ws.Cells[2, $script:Col['Empty']].Value | Should -BeNullOrEmpty
    }

    It 'row ORDER is preserved exactly as handed in' {
        [string]$script:Ws.Cells[2,  $script:Col['AssetName']].Value | Should -BeExactly 'HOST-0'
        [string]$script:Ws.Cells[26, $script:Col['AssetName']].Value | Should -BeExactly 'HOST-24'
    }

    It 'a long narrative column is clamped to its wide cap of 90' {
        [math]::Round($script:Ws.Column($script:Col['CVSSDesc']).Width) | Should -Be 90
    }

    It 'a tiny column keeps a readable floor instead of collapsing' {
        $script:Ws.Column($script:Col['Tiny']).Width | Should -BeGreaterOrEqual 8
    }

    It 'known multi-line columns keep WrapText' {
        $script:Ws.Column($script:Col['MoreDetails']).Style.WrapText | Should -BeTrue
    }

    It 'cells stay top-aligned' {
        "$($script:Ws.Column($script:Col['AssetName']).Style.VerticalAlignment)" | Should -Be 'Top'
    }

    It 'the sheet still carries a table, which is what provides the autofilter' {
        $script:Ws.Tables['Details'] | Should -Not -BeNullOrEmpty
    }

    It 'the header row is bold' {
        $script:Ws.Cells[1, 1].Style.Font.Bold | Should -BeTrue
    }
}

Describe '🔴 MULTI-SHEET ACCUMULATION -- writing one sheet must not destroy another' -Skip:(-not [bool](Get-Module -ListAvailable -Name ImportExcel)) {
    # The export now opens/creates the package itself instead of letting Export-Excel do it. Get that
    # wrong and the second call starts a NEW workbook, silently discarding the first sheet. The index
    # sheet and the AI-summary sheet are written by separate calls against the same file, so this is
    # a real destruction path, not a theoretical one.

    BeforeAll {
        Import-Module ImportExcel -ErrorAction Stop
        $script:_sheetWritten = @{}
        $script:Out2 = Join-Path ([IO.Path]::GetTempPath()) ("si-multi-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        $rows  = script:New-TestRows -Rows 5
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out2 -SheetName 'First'  -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
        Export-Worksheet -Path $script:Out2 -SheetName 'Second' -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
    }

    AfterAll { if ($script:Out2 -and (Test-Path $script:Out2)) { Remove-Item $script:Out2 -Force } }

    It 'BOTH sheets survive' {
        $p = Open-ExcelPackage -Path $script:Out2
        try {
            $sheets = @($p.Workbook.Worksheets | ForEach-Object { $_.Name })
            $sheets | Should -Contain 'First'
            $sheets | Should -Contain 'Second'
        } finally { Close-ExcelPackage $p -NoSave }
    }

    It 're-writing an existing sheet REPLACES it rather than appending (the -ClearSheet contract)' {
        $rows  = script:New-TestRows -Rows 3
        $names = @($rows[0].PSObject.Properties.Name)
        Export-Worksheet -Path $script:Out2 -SheetName 'First' -Rows $rows -DesiredColumns $names -TableStyle 'Medium9'
        $p = Open-ExcelPackage -Path $script:Out2
        try { $p.Workbook.Worksheets['First'].Dimension.Rows | Should -Be 4 }   # 3 data rows + header
        finally { Close-ExcelPackage $p -NoSave }
    }
}

Describe 'the empty-rows branch still works' -Skip:(-not [bool](Get-Module -ListAvailable -Name ImportExcel)) {

    It 'writes a placeholder sheet without throwing' {
        Import-Module ImportExcel -ErrorAction Stop
        $script:_sheetWritten = @{}
        $out = Join-Path ([IO.Path]::GetTempPath()) ("si-empty-{0}.xlsx" -f ([guid]::NewGuid().ToString('N')))
        try {
            { Export-Worksheet -Path $out -SheetName 'Details' -Rows @() -TableStyle 'Medium9' } | Should -Not -Throw
            Test-Path $out | Should -BeTrue
        } finally { if (Test-Path $out) { Remove-Item $out -Force } }
    }
}
