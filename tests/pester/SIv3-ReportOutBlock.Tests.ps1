#Requires -Version 5.1
<#
    #692 (c) / (d) ONE REPORT STRUCTURE, THE DATA OUT GENERATED (owner 2026-10-15: "data-out is project si-fields. ability to
    extend new si-fields both in and out. we do this automatically. important that we dont chg names"; 2026-10-19: "let every
    report carry the generated output block").
      * every query report of the catalog ends in the generated data-out block, EXACTLY as engine/risk-analysis/_shared/
        RA-OutBlock.ps1 generates it (tools/ra-ci/Set-RaOutBlock.ps1 writes it -- never by hand);
      * the block lists the report's output columns in order (its OutputPropertyOrder, pinned in the output contract) and
        the SI finding fields they fill; a new field in the catalog's row-column map reaches every report that has its column;
      * comment lines only, no colon, no ';' -- the engine takes it out before it sends the query, so no row and no column
        changes; the generator is pure and byte-stable (a second run changes nothing);
      * the core map of the block is the one RA-Findings.ps1 builds the findings with (WIRING).
    pwsh 7 (the gate) and Windows PowerShell 5.1.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-OutBlock.ps1')
    $script:YamlPath = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Yaml = [IO.File]::ReadAllText($script:YamlPath)
    $script:Contract = (Get-Content (Join-Path $PSScriptRoot 'fixtures\report-output-contract.json') -Raw | ConvertFrom-Json).reports
    $script:Blocks = @{}
    foreach ($p in ([regex]::Split($script:Yaml, '(?m)^\s*- ReportName:\s*') | Select-Object -Skip 1)) {
        $n = ($p -split "`n")[0].Trim()
        if ($p -notmatch '(?m)^\s*ReportQuery:') { continue }
        $m = [regex]::Match($p, '(?s)//__SI_OUT_BEGIN__.*?//__SI_OUT_END__')
        $script:Blocks[$n] = $(if ($m.Success) { $m.Value } else { '' })
    }
}

Describe 'every Risk Analysis report carries the generated data-out block (#692)' {
    It 'every query report has exactly one block, at the end of its query (control: the catalog is read)' {
        $script:Blocks.Count | Should -BeGreaterThan 100
        @($script:Blocks.Keys | Where-Object { -not $script:Blocks[$_] }) -join ', ' | Should -BeExactly '' -Because 'run tools\ra-ci\Set-RaOutBlock.ps1'
        foreach ($p in ([regex]::Split($script:Yaml, '(?m)^\s*- ReportName:\s*') | Select-Object -Skip 1)) {
            ([regex]::Matches($p, '//__SI_OUT_BEGIN__')).Count | Should -BeLessOrEqual 1
        }
    }
    It 'every block is EXACTLY what the generator writes -- the catalog is in sync (a second run changes nothing)' {
        $r = Update-RAOutBlocksInCatalog -Yaml $script:Yaml
        @($r.Changed) -join ', ' | Should -BeExactly '' -Because 'the block is generated from the output contract and the field catalog -- run tools\ra-ci\Set-RaOutBlock.ps1'
        $r.Text | Should -BeExactly $script:Yaml -Because 'nothing else in the catalog is touched'
        @($r.Reports).Count | Should -Be $script:Blocks.Count
    }
    It 'the out lines are the report''s output columns in order -- the pinned contract' {
        $bad = foreach ($n in $script:Blocks.Keys) {
            $outs = @([regex]::Matches($script:Blocks[$n], '(?m)^\s*// out (?!= )(.+)$') | ForEach-Object { $_.Groups[1].Value.Trim() -split ',\s*' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $pin = @($script:Contract.$n)
            if (($outs -join ',') -ne ($pin -join ',')) { $n }
        }
        @($bad) -join ', ' | Should -BeExactly ''
    }
    It 'comment lines only, no colon and no semicolon in the block (the KQL rules); the engine sends the query without it' {
        foreach ($n in $script:Blocks.Keys) {
            $lines = @($script:Blocks[$n] -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            @($lines | Where-Object { -not $_.StartsWith('//') }).Count | Should -Be 0 -Because "$n -- a block line that is not a comment would change the query"
            $script:Blocks[$n] | Should -Not -Match ':' -Because "$n -- no colon in a // comment"
            $script:Blocks[$n] | Should -Not -Match ';' -Because "$n -- the hybrid pre-fetcher cuts at the first ';'"
        }
        $q = "T`n| project a, b`n    //__SI_OUT_BEGIN__`n    // out a, b`n    //__SI_OUT_END__"
        Remove-RAOutBlock -Query $q | Should -BeExactly "T`n| project a, b"
        Remove-RAOutBlock -Query 'T | project a' | Should -BeExactly 'T | project a'
    }
    It 'a NEW si field reaches the block automatically: the row-column map is the source, the first column the report has wins' {
        $rc = [ordered]@{ si_new_field = @('NoSuchColumn', 'MyColumn') }
        $l = @(Get-RAOutBlockLines -OutputColumns @('A', 'B') -Body "T | extend MyColumn = 1`n| project A, B, MyColumn" -RowColumns $rc)
        $l[0] | Should -Be '//__SI_OUT_BEGIN__'; $l[-1] | Should -Be '//__SI_OUT_END__'
        ($l -join "`n") | Should -Match ([regex]::Escape('si_new_field <- MyColumn'))
        ($l -join "`n") | Should -Match ([regex]::Escape('// out A, B'))
        # a column only an earlier step has loses to the one the report leaves with
        $l2 = @(Get-RAOutBlockLines -OutputColumns @('A') -Body "T | extend PortalLink = 'x', PortalUrl = 'y'`n| project A, PortalUrl" -RowColumns ([ordered]@{ si_portal_link = @('PortalLink', 'PortalUrl') }))
        ($l2 -join "`n") | Should -Match ([regex]::Escape('si_portal_link <- PortalUrl'))
        # the generated blocks' own text and the comments are never read as columns
        $l3 = @(Get-RAOutBlockLines -OutputColumns @('A') -Body "// MyColumn`nT | project A" -RowColumns $rc)
        ($l3 -join "`n") | Should -Not -Match 'si_new_field'
    }
    It 'WIRING: the core map is the one RA-Findings.ps1 builds a finding with; the engine loads the generator and takes the block out before anything else' {
        $rf = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Findings.ps1'))
        foreach ($f in @($script:RAOutCoreMap.Keys)) {
            $rf | Should -Match ('\b' + [regex]::Escape($f) + '\b') -Because "$f is a field RA-Findings sets"
            foreach ($c in @($script:RAOutCoreMap[$f])) { $rf | Should -Match ("'" + [regex]::Escape($c) + "'") -Because "$f is filled from $c" }
        }
        $ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape(". (Join-Path `$PSScriptRoot '_shared/RA-OutBlock.ps1')"))
        $ra | Should -Match ([regex]::Escape('$Query = Remove-RAOutBlock -Query $Query'))
    }
}
