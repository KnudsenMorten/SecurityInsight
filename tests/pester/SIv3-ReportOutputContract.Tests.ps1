#Requires -Version 7.0
# #692 -- the OUTPUT CONTRACT of every Risk Analysis report: a report's output column names may be ADDED to, never
# renamed or removed (owner 2026-10-15: "important that we dont chg names as fx integrations, connectors will break").
# The pinned names live in tests/pester/fixtures/report-output-contract.json. A new column is added there in the same
# change; a removal or rename fails here and needs the owner's word plus a migration for every connector. The same holds for
# every connector output map (data-model/outputs: ServiceNow, the SQL hand-off, Excel) -- pinned under "outputs". And every
# report has the one standard structure (ops/report-certification/SI-ReportStructure.ps1): data in -> the CI (a generated
# block) -> data out (pinned), with the scope / bucket / weighted-factor blocks and a stable key; the reports that do not yet
# are listed under "structureExceptions" and left for the owner.

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ContractDoc = Get-Content (Join-Path $PSScriptRoot 'fixtures\report-output-contract.json') -Raw | ConvertFrom-Json
    $script:Contract = $script:ContractDoc.reports
    $script:YamlText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    # The structure check (ops\report-certification) is not in the Community payload: the output contract runs everywhere,
    # the structure block is skipped there, saying why (SI-CommunityPayload lists this file among the guarded readers).
    $script:StructureScript = Join-Path $script:SIRoot 'ops\report-certification\SI-ReportStructure.ps1'
    $script:HasStructure = Test-Path -LiteralPath $script:StructureScript
    $script:Structure = @()
    if ($script:HasStructure) {
        . $script:StructureScript
        $script:Structure = @(Split-SIReportCatalog $script:YamlText | ForEach-Object { Get-SIReportStructure -Name $_.Name -Text $_.Text -Contract $script:Contract })
    }
    $script:Maps = @{}
    foreach ($f in (Get-ChildItem (Join-Path $script:SIRoot 'data-model\outputs') -Filter '*.locked.json')) {
        $j = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $script:Maps[[string]$j.id] = @($j.columns | ForEach-Object { $_.target })
    }
    $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:Now = @{}
    foreach ($p in ([regex]::Split($yaml, '(?m)^\s*- ReportName:\s*') | Select-Object -Skip 1)) {
        $n = ($p -split "`n")[0].Trim()
        $m = [regex]::Match($p, '(?s)OutputPropertyOrder:\s*\r?\n(.*?)\r?\n\s*[A-Za-z]+:')
        if ($m.Success) { $script:Now[$n] = @([regex]::Matches($m.Groups[1].Value, '(?m)^\s*-\s*(\S+)') | ForEach-Object { $_.Groups[1].Value }) }
    }
}

Describe 'the output contract of every Risk Analysis report (#692)' {
    It 'the contract still finds the catalog (control)' {
        @($script:Contract.PSObject.Properties).Count | Should -BeGreaterThan 100
        $script:Now.Count | Should -BeGreaterThan 100
    }
    It 'no pinned report is removed from the catalog' {
        $gone = @($script:Contract.PSObject.Properties.Name | Where-Object { -not $script:Now.ContainsKey($_) })
        $gone -join ', ' | Should -BeExactly '' -Because 'a report a connector reads must be retired through the retire path, not deleted'
    }
    It 'no output column is renamed or removed' {
        $diffs = foreach ($p in $script:Contract.PSObject.Properties) {
            if (-not $script:Now.ContainsKey($p.Name)) { continue }
            $missing = @(@($p.Value) | Where-Object { $_ -notin $script:Now[$p.Name] })
            if ($missing.Count) { '{0}: {1}' -f $p.Name, ($missing -join ', ') }
        }
        @($diffs) -join '; ' | Should -BeExactly '' -Because 'integrations and connectors read these names'
    }
    It 'a new output column is pinned in the same change' {
        $unpinned = foreach ($n in $script:Now.Keys) {
            $pin = if ($script:Contract.PSObject.Properties[$n]) { @($script:Contract.$n) } else { @() }
            $new = @($script:Now[$n] | Where-Object { $_ -notin $pin })
            if ($new.Count) { '{0}: {1}' -f $n, ($new -join ', ') }
        }
        @($unpinned) -join '; ' | Should -BeExactly '' -Because 'add the column to tests/pester/fixtures/report-output-contract.json'
    }
}

Describe 'the connector output maps keep their column names (#692)' {
    It 'every shipped output map is pinned (control)' {
        @($script:ContractDoc.outputs.PSObject.Properties).Count | Should -BeGreaterOrEqual 7
        foreach ($id in $script:Maps.Keys) { [bool]$script:ContractDoc.outputs.PSObject.Properties[$id] | Should -BeTrue -Because "pin $id in tests/pester/fixtures/report-output-contract.json (outputs)" }
    }
    It 'no output map is removed and no connector column is renamed or removed' {
        $diffs = foreach ($p in $script:ContractDoc.outputs.PSObject.Properties) {
            if (-not $script:Maps.ContainsKey($p.Name)) { '{0}: the map is gone' -f $p.Name; continue }
            $missing = @(@($p.Value) | Where-Object { $_ -notin $script:Maps[$p.Name] })
            if ($missing.Count) { '{0}: {1}' -f $p.Name, ($missing -join ', ') }
        }
        @($diffs) -join '; ' | Should -BeExactly '' -Because 'ServiceNow, the SQL hand-off and the Excel exports read these names'
    }
    It 'a new connector column is pinned in the same change' {
        $unpinned = foreach ($id in $script:Maps.Keys) {
            $pin = if ($script:ContractDoc.outputs.PSObject.Properties[$id]) { @($script:ContractDoc.outputs.$id) } else { @() }
            $new = @($script:Maps[$id] | Where-Object { $_ -notin $pin })
            if ($new.Count) { '{0}: {1}' -f $id, ($new -join ', ') }
        }
        @($unpinned) -join '; ' | Should -BeExactly '' -Because 'add the column to outputs in tests/pester/fixtures/report-output-contract.json'
    }
}

Describe 'one structure for every Risk Analysis report (#692): data in -> CI -> data out, the generated blocks, a stable key' {
    BeforeEach {
        if (-not $script:HasStructure) { Set-ItResult -Skipped -Because 'ops\report-certification is not in this copy (the Community payload has no report certification)' }
    }
    It 'the structure check reads the whole catalog (control)' {
        @($script:Structure | Where-Object HasQuery).Count | Should -BeGreaterThan 100
        $sample = @($script:Structure | Where-Object { $_.Report -eq 'Device_Missing_CVEs_Detailed' })[0]
        $sample.DataIn | Should -BeTrue; $sample.CiUsed | Should -BeTrue; $sample.Ordered | Should -BeTrue
    }
    It 'every query report has every part, except the listed reports left for the owner' {
        $exc = $script:ContractDoc.structureExceptions
        $bad = foreach ($r in @($script:Structure | Where-Object { $_.HasQuery -and $_.Missing.Count -gt 0 })) {
            $allowed = if ($exc.PSObject.Properties[$r.Report]) { @($exc.($r.Report)) } else { @() }
            $left = @($r.Missing | Where-Object { $_ -notin $allowed })
            if ($left.Count) { '{0}: {1}' -f $r.Report, ($left -join ', ') }
        }
        @($bad) -join '; ' | Should -BeExactly '' -Because 'a report reads its source, correlates with the CI through a generated block, carries scope / bucket / weighted factors and a stable key, and its output is pinned'
    }
    It 'an exception that now conforms is taken off the list' {
        $stale = foreach ($p in $script:ContractDoc.structureExceptions.PSObject.Properties) {
            $r = @($script:Structure | Where-Object { $_.Report -eq $p.Name })
            if (-not $r.Count) { '{0}: not in the catalog' -f $p.Name; continue }
            $still = @(@($p.Value) | Where-Object { $_ -in $r[0].Missing })
            if ($still.Count -lt @($p.Value).Count) { '{0}: {1} is no longer missing' -f $p.Name, ((@($p.Value) | Where-Object { $_ -notin $r[0].Missing }) -join ', ') }
        }
        @($stale) -join '; ' | Should -BeExactly ''
    }
    It 'no report reads a profile table past the CI (v3: the profiles reach a report through SI_CI_CL)' {
        @($script:Structure | Where-Object ProfileDirect | ForEach-Object Report) -join ', ' | Should -BeExactly ''
    }
    It 'the structure check is pure: a report with no CI block, no scope and no pinned output lists exactly those parts' {
        $t = "X_Detailed`n  ReportQuery: |-`n    DeviceTvmSoftwareVulnerabilities`n    | project DeviceId`n  ConfigurationIdInputName: CveId`n  OutputPropertyOrder:`n    - AssetId`n  SortBy: x"
        $r = Get-SIReportStructure -Name 'X_Detailed' -Text $t -Contract ([pscustomobject]@{})
        @($r.Missing) | Should -Be @('CiBlock', 'CiUsed', 'Scope', 'Bucket', 'Weighted', 'OutBlock', 'Pinned', 'Ordered')
    }
}