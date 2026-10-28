#Requires -Version 5.1
<#
    THE ENDPOINT PROFILE'S AssetName IS ALWAYS READ AS TEXT (#151).

    `SI_Endpoint_Profile_CL.AssetName` was created `dynamic` (every other profile table has it as string),
    and a Log Analytics column type cannot change in place. A bare read works until it is used as a key:
    `summarize ... by AssetName` fails with SEM0001 ("group key 'AssetName' is of a 'dynamic' type"), a
    join or `==` fails the same way, and a union with the other profile tables renames it to
    AssetName_dynamic / AssetName_string. Measured 2026-09-28 while reconciling the CVE reports.

    Every shipped query already converts it; this pins that. In every statement that reads the endpoint
    profile, AssetName may only be read as `tostring(AssetName)` / `column_ifexists("AssetName", ...)`
    until the statement re-assigns it (`extend AssetName = ...`, `by AssetName = tostring(...)`).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    # Returns the violations in one catalog text: "<report> :: <context>".
    function script:Get-BareEndpointAssetNameReads([string]$Yaml) {
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($rep in [regex]::Matches($Yaml, '(?s)- ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)')) {
            $q = [regex]::Match($rep.Groups[2].Value, '(?s)ReportQuery:(.*)$').Groups[1].Value
            $q = [regex]::Replace($q, '//[^\r\n]*', '')
            $q = [regex]::Replace($q, 'column_ifexists\(\s*"AssetName"', 'column_ifexists(""')
            $q = [regex]::Replace($q, '"[^"\r\n]*"', '""')
            foreach ($st in ($q -split ';')) {
                if ($st -notmatch '\bSI_Endpoint_Profile_CL\b') { continue }
                $st2 = [regex]::Replace($st, 'tostring\(\s*AssetName\s*\)', 'X')
                $firstAssign = [regex]::Match($st2, '(?<![\w.])AssetName\s*=(?!=)')
                foreach ($h in [regex]::Matches($st2, '(?<![\w.])AssetName(?![\w])')) {
                    if ($firstAssign.Success -and $h.Index -ge $firstAssign.Index) { break }
                    $ctx = ($st2.Substring([Math]::Max(0, $h.Index - 40), [Math]::Min(80, $st2.Length - [Math]::Max(0, $h.Index - 40))) -replace '\s+', ' ').Trim()
                    $out.Add("$($rep.Groups[1].Value) :: $ctx")
                }
            }
        }
        $out.ToArray()
    }
}

Describe 'the shipped catalog' {
    It 'no query reads the endpoint profile''s AssetName bare before converting it' {
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $bad = @(Get-BareEndpointAssetNameReads $y)
        $bad.Count | Should -Be 0 -Because ($bad -join ' || ')
    }
    It '#505 -- the reports read the CI''s asset name, which both canonical blocks cast to text (not the endpoint profile)' {
        # The guard above has nothing left to inspect in the catalog: no report reads SI_Endpoint_Profile_CL any more.
        # The name a device report shows is the CI's si_asset_name, and the block (RA-CiKql.ps1) reads it as
        # tostring(si_asset_name) -- so it is text whatever type the column has in SI_CI_CL.
        $y = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        $code = [regex]::Replace([regex]::Replace($y, '"[^"\r\n]*"', '""'), '//[^\r\n]*', '')
        $code | Should -Not -Match '\bSI_Endpoint_Profile_CL\b'
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
        foreach ($k in 'link', 'asset') { Get-RACiKqlBlock -Kind $k | Should -Match 'si_asset_name = tostring\(si_asset_name\)' -Because "the $k block" }
        $blocks = @([regex]::Matches($y, '(?s)//__SI_CI_(LINK|ASSET)_BEGIN__(.*?)//__SI_CI_\1_END__'))
        $blocks.Count | Should -BeGreaterThan 100
        @($blocks | Where-Object { $_.Groups[2].Value -notmatch 'si_asset_name = tostring\(si_asset_name\)' }).Count | Should -Be 0
    }
}

Describe 'at run time, a report that groups by AssetName is cast -- custom reports included' {
    BeforeAll {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Add-DynamicGroupKeyCasts' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
        # the list exactly as the engine declares it
        $decl = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$script:_DynamicGroupKeyCols' }, $true) | Select-Object -First 1
        $script:_DynamicGroupKeyCols = & ([scriptblock]::Create($decl.Right.Extent.Text))
    }
    It 'the engine''s list includes AssetName' {
        $script:_DynamicGroupKeyCols | Should -Contain 'AssetName'
    }
    It 'a bare AssetName group key becomes tostring(AssetName); an already-converted one is untouched' {
        (Add-DynamicGroupKeyCasts -Query "SI_Endpoint_Profile_CL`n| summarize n = count() by AssetName, Tier") | Should -Match 'by tostring\(AssetName\), Tier'
        $q = "T`n| summarize n = count() by tostring(AssetName)"
        Add-DynamicGroupKeyCasts -Query $q | Should -BeExactly $q
    }
}

Describe 'the check itself' {
    It 'catches a bare group key, join key and comparison' {
        $y = @'
    - ReportName: A
      ReportQuery:
      - |-
          SI_Endpoint_Profile_CL | summarize n = count() by AssetName
    - ReportName: B
      ReportQuery:
      - |-
          let _ep = SI_Endpoint_Profile_CL | where AssetName == "x";
          T | join _ep on AssetName
'@
        @(Get-BareEndpointAssetNameReads $y).Count | Should -BeGreaterOrEqual 2
    }
    It 'accepts tostring(), column_ifexists(), and use after re-assignment' {
        $y = @'
    - ReportName: C
      ReportQuery:
      - |-
          let _ep = SI_Endpoint_Profile_CL | extend _n = tolower(tostring(AssetName)) | project _n, N2 = tostring(column_ifexists("AssetName", ""));
          SI_Endpoint_Profile_CL | extend AssetName = tostring(column_ifexists("AssetName", "")) | summarize by AssetName
'@
        @(Get-BareEndpointAssetNameReads $y).Count | Should -Be 0
    }
}
