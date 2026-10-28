#Requires -Version 5.1
<#
    #242 -- ONE TYPE PER COLUMN in the Risk Analysis workbook (engine/risk-analysis/_shared/RA-ExcelColumnTypes.ps1).

    NO EMOJI IN THIS FILE: it has no BOM, and PowerShell 5.1 would decode it as Windows-1252.

    The operator saw RiskScore_Weight_Factor and CriticalityTier as numbers in some rows and text in others: Log
    Analytics hands every cell over as text, Advanced Hunting and the engine's own scores are real numbers, and the
    'Details' sheet unions both. These tests build the workbook through Export-Worksheet -- the engine's real export
    path -- from rows where the numeric columns arrive as a mix of real numbers, numeric text, comma-decimal text and
    blanks, then OPEN THE XLSX WITH System.IO.Compression and read the cell type (the t attribute) of every cell in the
    sheet XML. Both the compiled helper and its PowerShell twin are run.
#>

BeforeAll {
    $script:SIRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RaShared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $script:RaShared 'RA-RunProgress.ps1')
    . (Join-Path $script:RaShared 'RA-ExcelReport.ps1')     # dot-sources RA-XlsxWriter.ps1 + RA-ExcelColumnTypes.ps1
    $script:_sheetWritten = @{}
    $script:TmpDir = Join-Path ([IO.Path]::GetTempPath()) ('si-coltypes-' + [guid]::NewGuid().ToString('N').Substring(0, 10))
    New-Item -ItemType Directory -Force -Path $script:TmpDir | Out-Null
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

    function script:Get-SheetCellTypes {
        <# The 'Details' sheet read straight from the package: header name -> list of @{ Row; T; V }. T is the t
           attribute ('' for a number, 's' shared string, 'b' boolean). #>
        param([string]$Path)
        $z = [System.IO.Compression.ZipFile]::OpenRead($Path)
        try {
            $read = { param($n) $r = New-Object System.IO.StreamReader($z.GetEntry($n).Open()); try { $r.ReadToEnd() } finally { $r.Close() } }
            $sheetXml = [xml](& $read 'xl/worksheets/sheet1.xml')
            $sstXml = [xml](& $read 'xl/sharedStrings.xml')
        } finally { $z.Dispose() }
        $sst = @($sstXml.sst.si | ForEach-Object { $_.InnerText })
        $byCol = @{}; $hdr = @{}
        foreach ($row in $sheetXml.worksheet.sheetData.row) {
            foreach ($c in @($row.c)) {
                $col = ($c.r -replace '\d', '')
                $t = [string]$c.GetAttribute('t')
                $v = [string]$c.v
                if ($row.r -eq '1') { $hdr[$col] = $sst[[int]$v]; continue }
                if ($t -eq 's') { $v = $sst[[int]$v] }
                if (-not $byCol.ContainsKey($col)) { $byCol[$col] = New-Object System.Collections.Generic.List[object] }
                [void]$byCol[$col].Add([pscustomobject]@{ Row = [int]$row.r; T = $t; V = $v })
            }
        }
        $out = @{}
        foreach ($k in $hdr.Keys) { $out[$hdr[$k]] = $(if ($byCol.ContainsKey($k)) { $byCol[$k].ToArray() } else { @() }) }
        return $out
    }

    function script:New-MixedRows {
        # What the export pool looks like after a run: LA rows (text), Advanced Hunting rows (numbers), blanks.
        @(
            [pscustomobject]@{ AssetName = 'srv1'; CriticalityTier = 1;   RiskScore_Weight_Factor = 1.5;    RiskScoreTotal = 120; MaxCvssScore = 9.8;   AffectedEntityCount = 3;   cmdbId = '6';   OsVersion = '10.0'; TraceID = '5296969905e84670'; PostalCode = '2100'; Impact = 9.8 }
            [pscustomobject]@{ AssetName = 'srv2'; CriticalityTier = '0'; RiskScore_Weight_Factor = '2';    RiskScoreTotal = '80'; MaxCvssScore = '8.7'; AffectedEntityCount = '12'; cmdbId = '7';   OsVersion = '13.0'; TraceID = '1234';             PostalCode = '0800'; Impact = '7.5' }
            [pscustomobject]@{ AssetName = 'srv3'; CriticalityTier = '';  RiskScore_Weight_Factor = '0,5';  RiskScoreTotal = 40;   MaxCvssScore = '';    AffectedEntityCount = '';   cmdbId = 8;     OsVersion = '6.3';  TraceID = 99;                 PostalCode = 9000;   Impact = 'Suppressed from every report' }
            [pscustomobject]@{ AssetName = 'srv4'; CriticalityTier = '3'; RiskScore_Weight_Factor = '1.0';  RiskScoreTotal = 10;   MaxCvssScore = 5;     AffectedEntityCount = 0;    cmdbId = '';    OsVersion = '';     TraceID = 'abc';              PostalCode = '';     Impact = '' }
        )
    }
}

AfterAll {
    if ($script:TmpDir -and (Test-Path $script:TmpDir)) { Remove-Item -Recurse -Force $script:TmpDir -ErrorAction SilentlyContinue }
    $script:RAXlsxTypesForcePowerShell = $false
}

Describe 'the Risk Analysis workbook has one type per column (#242)' {

    Context 'engine: <_>' -ForEach @('Native', 'PowerShell') {
        BeforeAll {
            $script:RAXlsxTypesForcePowerShell = ($_ -eq 'PowerShell')
            $script:Path = Join-Path $script:TmpDir ("types-{0}.xlsx" -f $_)
            Export-Worksheet -Path $script:Path -SheetName 'Details' -Rows (New-MixedRows)
            $script:Cols = Get-SheetCellTypes -Path $script:Path
        }
        AfterAll { $script:RAXlsxTypesForcePowerShell = $false }

        It '<_> is numeric or blank in every row' -ForEach @('CriticalityTier', 'RiskScore_Weight_Factor', 'RiskScoreTotal', 'MaxCvssScore', 'AffectedEntityCount') {
            $cells = @($script:Cols[$_])
            $cells.Count | Should -BeGreaterThan 0
            @($cells | Where-Object { $_.T -ne '' }) | Should -BeNullOrEmpty -Because "every $_ cell must be a number (no t attribute)"
        }

        It 'numbers are written invariant: "0,5" is 0.5 and "1.0" is 1' {
            $w = @($script:Cols['RiskScore_Weight_Factor'] | ForEach-Object { [double]::Parse($_.V, [Globalization.CultureInfo]::InvariantCulture) })
            $w | Should -Be @(1.5, 2, 0.5, 1)
        }

        It 'a blank stays blank: no cell for an empty value in a numeric column' {
            @($script:Cols['CriticalityTier']).Row | Should -Be @(2, 3, 5)
            @($script:Cols['MaxCvssScore']).Row | Should -Be @(2, 3, 5)
        }

        It '<_> stays text in every row, also where the value looks numeric' -ForEach @('cmdbId', 'OsVersion', 'TraceID', 'PostalCode', 'AssetName') {
            $cells = @($script:Cols[$_])
            $cells.Count | Should -BeGreaterThan 0
            @($cells | Where-Object { $_.T -ne 's' }) | Should -BeNullOrEmpty -Because "$_ is text"
        }

        It 'an id keeps its spelling: "0800" and "5296969905e84670" are not turned into numbers' {
            @($script:Cols['PostalCode']).V | Should -Contain '0800'
            @($script:Cols['TraceID']).V | Should -Contain '5296969905e84670'
            @($script:Cols['cmdbId']).V | Should -Be @('6', '7', '8')
        }

        It 'a sentence in a numeric column stays text; its numbers are numbers' {
            $imp = @($script:Cols['Impact'])
            @($imp | Where-Object { $_.T -eq 's' }).V | Should -Be @('Suppressed from every report')
            @($imp | Where-Object { $_.T -eq '' }).Count | Should -Be 2
        }
    }
}

Describe 'how a column type is decided (#242)' {
    It 'the KQL result type decides a column the lists do not name' {
        $kql = @{ 'Score2' = 'real'; 'Label2' = 'string' }
        Get-RAExcelColumnRule -Name 'Score2' -KqlTypes $kql | Should -Be 'number'
        Get-RAExcelColumnRule -Name 'Label2' -KqlTypes $kql | Should -Be 'text'
        Get-RAExcelColumnRule -Name 'Other2' -KqlTypes $kql | Should -Be 'infer'
    }
    It 'an id column stays text even when a query declared it numeric' {
        Get-RAExcelColumnRule -Name 'MachineGroupId' -KqlTypes @{ MachineGroupId = 'long' } | Should -Be 'text'
    }
    It 'a column two reports type differently is decided from its values' {
        Reset-RAKqlColumnTypes
        Add-RAKqlColumnTypes -Columns @([pscustomobject]@{ name = 'Mixed1'; type = 'long' }, [pscustomobject]@{ name = 'Agreed1'; type = 'int' })
        Add-RAKqlColumnTypes -Columns @([pscustomobject]@{ name = 'Mixed1'; type = 'string' }, [pscustomobject]@{ name = 'Agreed1'; type = 'int' })
        $global:RA_KqlColumnTypes['Mixed1'] | Should -Be 'mixed'
        Get-RAExcelColumnRule -Name 'Mixed1' -KqlTypes $global:RA_KqlColumnTypes | Should -Be 'infer'
        Get-RAExcelColumnRule -Name 'Agreed1' -KqlTypes $global:RA_KqlColumnTypes | Should -Be 'number'
        Reset-RAKqlColumnTypes
    }
    It 'a column of only numeric-looking text, named nowhere, stays text (an id cannot be told from a count)' {
        $rows = New-Object 'object[][]' 2; $rows[0] = [object[]]@('6'); $rows[1] = [object[]]@('7')
        $r = Set-RAExcelColumnTypes -Rows $rows -Columns @('Unknown1')
        $r.Numeric | Should -BeNullOrEmpty
        $rows[0][0] | Should -BeOfType [string]
    }
    It 'a column with real numbers and numeric text, named nowhere, becomes numeric' {
        $rows = New-Object 'object[][]' 2; $rows[0] = [object[]]@(5); $rows[1] = [object[]]@('7.25')
        $r = Set-RAExcelColumnTypes -Rows $rows -Columns @('Unknown2')
        $r.Numeric | Should -Be @('Unknown2')
        $rows[1][0] | Should -Be 7.25
    }
    It 'a column with real numbers and words, named nowhere, becomes text' {
        $rows = New-Object 'object[][]' 2; $rows[0] = [object[]]@(5); $rows[1] = [object[]]@('n/a')
        $r = Set-RAExcelColumnTypes -Rows $rows -Columns @('Unknown3')
        $r.Text | Should -Be @('Unknown3')
        $rows[0][0] | Should -Be '5'
    }
    It 'a Log Analytics query result records its column types for the export' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:RaShared 'RA-LogAnalyticsQuery.ps1')
        $src | Should -Match 'Add-RAKqlColumnTypes -Columns'
        $ra = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $ra | Should -Match 'Reset-RAKqlColumnTypes'
        (Get-Content -Raw -LiteralPath (Join-Path $script:RaShared 'RA-ExcelReport.ps1')) | Should -Match 'Set-RAExcelColumnTypes -Rows \$_grid\.Rows'
    }
}
