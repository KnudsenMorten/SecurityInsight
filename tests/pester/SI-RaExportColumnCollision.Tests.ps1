#Requires -Version 5.1
<#
    v2.2.439 -- THE EXCEL EXPORT MUST NEVER BE WHAT DESTROYS A COMPLETED RUN.

    NOTE -- NO EMOJI IN THIS FILE. These .ps1 files carry no BOM, so PowerShell 5.1 decodes them as
    Windows-1252 and a four-byte emoji lands as four Latin-1 characters, several of which the parser
    treats as STRING DELIMITERS.

    WHAT HAPPENED (real customer run, v2.2.438). RiskAnalysis_Detailed ran 62 reports over ~26 minutes,
    collected 2600 rows, and then died on the very last step:

        The property cannot be processed because the property "OSPlatform" already exists.
        at Export-Worksheet, RA-ExcelReport.ps1: line 168

    Two reports spelled one column differently -- 'OsPlatform' from the endpoint reports, 'OSPlatform'
    from the DI_OSPlatform coalesce in the locked YAML. The cross-report column union used
    List[string].Contains(), which is ORDINAL, so both were admitted. PSObject property names are
    CASE-INSENSITIVE, so Select-Object then refused the list.

    WHY IT COST EVERYTHING: the Excel write is the last step AND it runs BEFORE the JSON sibling, so
    there was no surviving artifact. Every query had already succeeded.

    WHY NO EXISTING TEST CAUGHT IT: the collision cannot occur inside a single report -- the per-report
    build uses PowerShell's -notcontains, which IS case-insensitive. It requires TWO reports, spelled
    differently, in one template, unioned at run time. No offline test assembled that union, and the
    -Mock path builds no rows at all. That gap is what this file closes.
#>

# ---------------------------------------------------------------------------------------------------
# DISCOVERY-TIME, and it has to be: -Skip is evaluated during discovery, so this cannot live in a
# BeforeAll.
# 🪤 The pre-publish gate workflow installs Pester and powershell-yaml and NOTHING ELSE -- no
# ImportExcel. The first version of this file did `Import-Module ImportExcel -ErrorAction Stop` in a
# BeforeAll, which threw on the runner and took the ENTIRE FILE down: Pester reported "discovery failed
# -- 0 tests ran", so all nine tests counted as failures and the gate went red on the very release that
# fixed the bug. A test that cannot run must SKIP, loudly and locally; it must never fail the build for
# a missing optional module.
# The split below is deliberate: the ROOT CAUSE guards need no Excel at all and therefore run
# EVERYWHERE, including CI. Only the round-trip through a real workbook needs the module.
# ---------------------------------------------------------------------------------------------------
$script:HasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel -ErrorAction SilentlyContinue)

BeforeAll {
    $script:SIRoot   = Join-Path (Join-Path (Split-Path -Parent (Split-Path -Parent $PSCommandPath)) '..') ''
    $script:RaEngine = Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') 'Invoke-RiskAnalysis.ps1'
    $script:RaShared = Join-Path (Join-Path (Join-Path $script:SIRoot 'engine') 'risk-analysis') '_shared'

    $script:SampleRows = @(
        [pscustomobject]@{ AssetName='HOST-1'; OsPlatform='Windows11';         RiskScoreTotal=9 },
        [pscustomobject]@{ AssetName='HOST-2'; OsPlatform='WindowsServer2022'; RiskScoreTotal=4 }
    )
}

Describe 'the platform behaviour the fix defends against' {

    It 'Select-Object REFUSES a property list holding two case-variants of one name' {
        # Pinning this because the whole defect rests on it: the list looked fine as strings, and
        # PowerShell rejected it as properties. If a future PowerShell tolerates this, the guards
        # below become belt-and-braces rather than load-bearing -- but they must not be removed on
        # the assumption that it already does.
        $err = $null
        $script:SampleRows | Select-Object -Property @('AssetName','OsPlatform','OSPlatform') -ErrorAction SilentlyContinue -ErrorVariable err | Out-Null
        @($err).Count | Should -BeGreaterThan 0
        ([string]$err[0]) | Should -Match 'already exists'
    }
}

Describe 'Export-Worksheet survives a poisoned column list -- 2600 rows must never be lost again' -Skip:(-not $script:HasImportExcel) {

    BeforeAll {
        Import-Module ImportExcel -Force
        . (Join-Path $script:RaShared 'RA-RunProgress.ps1')
        . (Join-Path $script:RaShared 'RA-ExcelReport.ps1')
        # Normally initialised by the engine (Invoke-RiskAnalysis.ps1:96); Export-Worksheet indexes it.
        $script:_sheetWritten = @{}
        $script:OutDir = Join-Path ([System.IO.Path]::GetTempPath()) ("si-raexport-" + [guid]::NewGuid().ToString('N').Substring(0,10))
        New-Item -ItemType Directory -Force -Path $script:OutDir | Out-Null
    }

    AfterAll {
        if ($script:OutDir -and (Test-Path -LiteralPath $script:OutDir)) {
            Remove-Item -LiteralPath $script:OutDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'writes the sheet even when the list carries BOTH spellings and a blank' {
        $p = Join-Path $script:OutDir 'collision.xlsx'
        { Export-Worksheet -Path $p -SheetName 'Details' -Rows $script:SampleRows `
            -DesiredColumns @('AssetName','OsPlatform','OSPlatform','','RiskScoreTotal') `
            -SortColumn 'RiskScoreTotal' -SortDescending -TableStyle 'Medium9' `
            -WarningAction SilentlyContinue } | Should -Not -Throw
        Test-Path -LiteralPath $p | Should -BeTrue
    }

    It 'and NO DATA IS LOST -- every row and every distinct column still reaches the workbook' {
        # Surviving is not enough. A guard that silently emitted an empty sheet would also "not
        # throw", and that is the failure this whole area keeps producing.
        $p = Join-Path $script:OutDir 'collision.xlsx'
        $back = @(Import-Excel -Path $p)
        $back.Count | Should -Be 2
        $cols = @($back[0].PSObject.Properties.Name)
        $cols | Should -Contain 'AssetName'
        $cols | Should -Contain 'RiskScoreTotal'
        @($cols | Where-Object { $_ -eq 'OsPlatform' -or $_ -eq 'OSPlatform' }).Count | Should -Be 1
        # first spelling wins, and the VALUES survive the dedup
        ($back | Where-Object { $_.AssetName -eq 'HOST-1' }).OsPlatform | Should -Be 'Windows11'
    }

    It 'warns loudly, because two reports disagreeing about a column name is still a real defect' {
        $p = Join-Path $script:OutDir 'collision-warn.xlsx'
        $w = $null
        Export-Worksheet -Path $p -SheetName 'Details' -Rows $script:SampleRows `
            -DesiredColumns @('AssetName','OsPlatform','OSPlatform','RiskScoreTotal') `
            -TableStyle 'Medium9' -WarningVariable w -WarningAction SilentlyContinue
        (@($w) -join ' ') | Should -Match 'duplicate/blank column name'
    }

    It 'NEGATIVE PASS -- a clean list exports unchanged and raises no warning' {
        # Without this the tests above could pass by the guard mangling every export.
        $p = Join-Path $script:OutDir 'clean.xlsx'
        $w = $null
        Export-Worksheet -Path $p -SheetName 'Details' -Rows $script:SampleRows `
            -DesiredColumns @('AssetName','OsPlatform','RiskScoreTotal') `
            -TableStyle 'Medium9' -WarningVariable w -WarningAction SilentlyContinue
        (@($w) -join ' ') | Should -Not -Match 'duplicate/blank column name'
        $back = @(Import-Excel -Path $p)
        $back.Count | Should -Be 2
        @($back[0].PSObject.Properties.Name).Count | Should -Be 3
    }
}

Describe 'the ROOT CAUSE -- the cross-report union must compare case-insensitively' {

    BeforeAll {
        # No modules, no Excel, no tenant -- these are the guards that must run on every runner.
        $script:EngineSrc = Get-Content -Raw -LiteralPath $script:RaEngine
    }

    It 'the union no longer uses the ordinal List.Contains that admitted both spellings' {
        # This exact expression is what shipped in v2.2.438 and what let OSPlatform in beside
        # OsPlatform. It must not come back.
        $script:EngineSrc | Should -Not -Match '\$mergedCols\.Contains\('
    }

    It 'the union dedupes with an OrdinalIgnoreCase comparer' {
        $script:EngineSrc | Should -Match 'HashSet\[string\][^\r\n]*OrdinalIgnoreCase'
    }

    It 'the trace-column re-pin removes case-insensitively too' {
        # An ordinal Remove() would strand a differently-cased trace column mid-sheet AND put the
        # collision straight back.
        $script:EngineSrc | Should -Not -Match '\$mergedCols\.Remove\(\$t\)'
        $script:EngineSrc | Should -Match 'OrdinalIgnoreCase\)\) \{ \$mergedCols\.RemoveAt\(\$i\)'
    }

    It 'and the union logic itself is correct, exercised rather than only read' {
        # Same algorithm the engine now runs: first-seen order, first spelling wins.
        $merged = New-Object 'System.Collections.Generic.List[string]'
        $seen   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($c in @('AssetName','OsPlatform','Tier')) { if ($seen.Add($c)) { [void]$merged.Add($c) } }
        foreach ($c in @('AssetName','OSPlatform','CVE'))  { if ($seen.Add($c)) { [void]$merged.Add($c) } }
        ($merged -join ',') | Should -Be 'AssetName,OsPlatform,Tier,CVE'
        { $script:SampleRows | Select-Object -Property $merged.ToArray() } | Should -Not -Throw
    }
}
