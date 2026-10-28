#Requires -Version 5.1
<#
    #689 -- WEEKLY CONTEXT DISCOVERY FOR RISK ANALYSIS (owner 2026-10-15: "we need to formalize this as another discovery
    process for risk analysis, where security context/columns are discovered and gets mapped up. weekly chk").

    engine\data-model\SI-ContextDiscovery.ps1 walks the chain source column -> provider mapping -> SI field -> output map
    and proposes ADDITIONS: CARRY (a filled CI field no output carries), MAP (a property the records carry that a catalog
    field of its name could read), NEW (the same with no such field), ROUTE (a graph edge label no report reads). What holds:
      * a candidate with no valid data is not proposed (fill rate 0, no records);
      * NAMES NEVER CHANGE -- no proposal renames or removes an output column or a field (Test-SIContextProposalAdditive);
      * a part that could not be read is not evaluated (its earlier proposals are not marked gone);
      * weekly -- at most once in six days, decided by the last run row; it runs at the end of every Risk Analysis Detailed
        run (every install has that job) and on the weekly schema sweep where that job is installed;
      * one write, with the owner's Decision never written by the engine; the two tables are in the data schema;
      * never throws into a run.
    Offline: the database and the graph are scriptblock seams; nothing is called.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-ContextDiscovery.ps1')
    $script:Model = Get-SIContextModel -Root $script:SIRoot
    # a small model of the same shape (the real one is checked separately)
    $script:Small = [pscustomobject]@{
        Fields = @([pscustomobject]@{ Name = 'si_tier'; Level = 'ci'; Classes = @('device') },
                   [pscustomobject]@{ Name = 'si_is_transient'; Level = 'both'; Classes = @('device') },
                   [pscustomobject]@{ Name = 'si_device_roles'; Level = 'both'; Classes = @('device') },
                   [pscustomobject]@{ Name = 'si_never_filled'; Level = 'both'; Classes = @('device') },
                   [pscustomobject]@{ Name = 'si_report_name'; Level = 'finding'; Classes = @() })
        OutputMaps = @([pscustomobject]@{ Id = 'excel-findings-detailed'; Grain = 'ci_finding'; Targets = @('CI', 'CriticalityTier', 'DeviceRoles'); Froms = @('si_tier', 'si_report_name') })
        ReportEdgeLabels = @('member of', 'has role on')
    }
    $script:Fill = @{ Total = 200.0; Pct = @{ si_tier = 100.0; si_is_transient = 12.5; si_device_roles = 40.0; si_never_filled = 0.0 } }
    $script:Gaps = @(
        [pscustomobject]@{ Source = 'mde'; RecordType = 'device'; Part = 'deviceInfo'; Property = 'IsTransient'; Records = 50; SampleValue = 'false' }
        [pscustomobject]@{ Source = 'mde'; RecordType = 'device'; Part = 'deviceInfo'; Property = 'FirmwareVersions'; Records = 20; SampleValue = '[]' }
        [pscustomobject]@{ Source = 'mde'; RecordType = 'device'; Part = 'deviceInfo'; Property = 'TenantId'; Records = 99; SampleValue = 'x' }
        [pscustomobject]@{ Source = 'entra'; RecordType = 'user'; Part = 'user'; Property = '@odata.type'; Records = 99; SampleValue = 'x' })
    $script:Edges = @{
        'member of'          = @(@{ Source = 'user'; Edge = 'member of'; Target = 'group'; SampleCount = 1734 })
        'can impersonate as' = @(@{ Source = 'serviceprincipal'; Edge = 'can impersonate as'; Target = 'user'; SampleCount = 35 })
        'Has Role On'        = @(@{ Source = 'user'; Edge = 'Has Role On'; Target = 'device'; SampleCount = 3 })
        'empty label'        = @(@{ Source = 'a'; Edge = 'empty label'; Target = 'b'; SampleCount = 0 })
    }
    # a database seam that records what it is asked and answers by statement
    function script:New-Db([object[]]$Fill, [object[]]$Gaps, [string]$LastRunAt = '', [switch]$FailFill) {
        $s = @{ Calls = New-Object System.Collections.Generic.List[object] }
        $s.Invoke = {
            param($Sql, $Params, $Mode)
            $s.Calls.Add(@{ Sql = $Sql; Params = $Params; Mode = $Mode })
            if ($Sql -match 'FROM sidata\.ContextDiscoveryRun') { return [pscustomobject]@{ LastRunAt = $LastRunAt } }
            if ($Sql -match 'OPENJSON\(c\.DocJson\)') { if ($FailFill) { throw 'timeout' }; return $Fill }
            if ($Sql -match 'FROM sidata\.SourceProperty') { return $Gaps }
            if ($Sql -match 'INSERT sidata\.ContextProposal') { return [pscustomobject]@{ Proposals = 3; NewProposals = 2 } }
            throw "unexpected statement"
        }.GetNewClosure()
        $s
    }
}

Describe 'the proposals (Get-SIContextProposals, PURE)' {
    BeforeAll { $script:P = (Get-SIContextProposals -Model $script:Small -Fill $script:Fill -SourceGaps $script:Gaps -EdgeTriples $script:Edges) }
    It 'CARRY -- a filled CI field no output carries, with a free column name; a carried, a finding-level or an empty field is not proposed' {
        $c = @($script:P.Proposals | Where-Object Kind -eq 'CARRY')
        @($c.Subject | Sort-Object) | Should -Be @('si_device_roles', 'si_is_transient')
        (@($c | Where-Object Subject -eq 'si_is_transient')[0]).Target | Should -Be 'excel-findings-detailed:IsTransient'
        (@($c | Where-Object Subject -eq 'si_is_transient')[0]).FillPct | Should -Be 12.5
    }
    It 'a CARRY whose column name is already taken leaves the name to the owner -- the existing column is never renamed' {
        $dr = @($script:P.Proposals | Where-Object { $_.Kind -eq 'CARRY' -and $_.Subject -eq 'si_device_roles' })[0]
        $dr.Target | Should -Be 'excel-findings-detailed:'
        $dr.Why | Should -Match 'already used'
    }
    It 'MAP -- a property the records carry, no SI field reads, and a catalog field has its name' {
        $m = @($script:P.Proposals | Where-Object Kind -eq 'MAP')
        @($m).Count | Should -Be 1
        $m[0].Subject | Should -Be 'mde/device/deviceInfo/IsTransient'
        $m[0].Target | Should -Be 'si_is_transient'
    }
    It 'NEW -- no field has its name: a new si_ field name for the owner''s list; noise columns are never proposed' {
        $n = @($script:P.Proposals | Where-Object Kind -eq 'NEW')
        @($n.Subject) | Should -Be @('mde/device/deviceInfo/FirmwareVersions')
        $n[0].Target | Should -Be 'si_firmware_versions'
    }
    It 'ROUTE -- an edge label no report reads (compared ignoring case); an edge with no edges is not proposed' {
        $r = @($script:P.Proposals | Where-Object Kind -eq 'ROUTE')
        @($r.Subject) | Should -Be @('can impersonate as')
        $r[0].Evidence | Should -Match 'serviceprincipal -> user \(35\)'
        $r[0].Why | Should -Not -Match '#\d' -Because 'stored text carries no internal numbers'
    }
    It 'every proposal has a unique key Kind|Subject and the kinds evaluated are said' {
        $keys = @($script:P.Proposals | ForEach-Object { $_.Key })
        $keys.Count | Should -Be (@($keys | Sort-Object -Unique).Count)
        @($script:P.Kinds) | Should -Be @('CARRY', 'MAP', 'NEW', 'ROUTE')
    }
    It 'a part not read is not evaluated: no fill rates = no CARRY; no source rows = no MAP / NEW; no graph = no ROUTE' {
        $p = Get-SIContextProposals -Model $script:Small -Fill @{ Total = $null; Pct = @{} } -SourceGaps $null -EdgeTriples $null
        @($p.Proposals).Count | Should -Be 0
        @($p.Kinds).Count | Should -Be 0
    }
}

Describe 'NAMES NEVER CHANGE -- every proposal only adds (Test-SIContextProposalAdditive)' {
    It 'refuses a CARRY onto a column the map already has, or of a field the map already carries' {
        Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = 'CARRY'; Subject = 'si_is_transient'; Target = 'excel-findings-detailed:CriticalityTier' }) | Should -BeFalse
        Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = 'CARRY'; Subject = 'si_tier'; Target = 'excel-findings-detailed:Tier2' }) | Should -BeFalse
        Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = 'CARRY'; Subject = 'si_is_transient'; Target = 'excel-findings-detailed:IsTransient' }) | Should -BeTrue
    }
    It 'refuses a NEW field that exists (that would redefine it) and a MAP onto a field that does not exist' {
        Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = 'NEW'; Subject = 'x'; Target = 'si_tier' }) | Should -BeFalse
        Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = 'MAP'; Subject = 'x'; Target = 'si_nope' }) | Should -BeFalse
    }
    It 'refuses any other kind -- there is no RENAME or REMOVE proposal' {
        foreach ($k in 'RENAME', 'REMOVE', '') { Test-SIContextProposalAdditive -Model $script:Small -Proposal ([pscustomobject]@{ Kind = $k; Subject = 'si_tier'; Target = 'x' }) | Should -BeFalse }
    }
    It 'on the SHIPPED chain, no proposal of any kind touches an existing output column name' {
        $fill = @{ Total = 10.0; Pct = @{} }; foreach ($f in @($script:Model.Fields)) { $fill.Pct[$f.Name] = 50.0 }
        $p = Get-SIContextProposals -Model $script:Model -Fill $fill -SourceGaps @() -EdgeTriples @{}
        $targets = @{}; foreach ($m in @($script:Model.OutputMaps)) { foreach ($t in @($m.Targets)) { $targets[('{0}:{1}' -f $m.Id, $t).ToLowerInvariant()] = $true } }
        foreach ($c in @($p.Proposals | Where-Object Kind -eq 'CARRY')) { $targets.ContainsKey(([string]$c.Target).ToLowerInvariant()) | Should -BeFalse -Because $c.Target }
        @($p.Proposals | Where-Object Kind -eq 'CARRY').Count | Should -BeGreaterThan 0 -Because 'control: the shipped catalog has fields no output carries'
    }
}

Describe 'the chain as shipped (Get-SIContextModel)' {
    It 'reads the field catalog, every output map and the report catalog''s edge labels' {
        @($script:Model.Fields).Count | Should -BeGreaterThan 400
        @($script:Model.OutputMaps.Id) | Should -Contain 'excel-findings-detailed'
        @($script:Model.OutputMaps.Id) | Should -Contain 'servicenow-vulnerable-item'
        @($script:Model.OutputMaps.Id) | Should -Contain 'sql-vulnerability-target'
        $script:Model.ReportEdgeLabels | Should -Contain 'can impersonate as' -Because 'the #691 impersonation report reads it, so it is no ROUTE any more'
        $script:Model.ReportEdgeLabels | Should -Contain 'member of'
    }
    It 'edge labels in comments are not read as covered' {
        Get-SIContextReportEdgeLabels -YamlText "// EdgeLabel =~ `"ghost`"`n| where EdgeLabel in~ (`"a`", `"B`")" | Should -Be @('a', 'b')
    }
    It 'the name helpers' {
        ConvertTo-SIContextPascal 'si_end_of_support_date' | Should -Be 'EndOfSupportDate'
        ConvertTo-SIContextSnake 'deviceInfo.IsTransient' | Should -Be 'si_is_transient'
        ConvertTo-SIContextSnake 'roles[*].ProductCodeCpe' | Should -Be 'si_product_code_cpe'
        ConvertTo-SIContextNorm 'si_is_transient' | Should -Be (ConvertTo-SIContextNorm 'deviceInfo.IsTransient')
    }
    It 'fill rates: the percent of the CIs, and a missing total means not read' {
        $f = ConvertTo-SIContextFillRates -Rows @([pscustomobject]@{ Field = '*'; Filled = 200 }, [pscustomobject]@{ Field = 'si_tier'; Filled = 50 })
        $f.Total | Should -Be 200
        $f.Pct['si_tier'] | Should -Be 25
        (ConvertTo-SIContextFillRates -Rows @()).Total | Should -BeNullOrEmpty
    }
    It 'edge rows from the graph become the schema job''s triples (dictionary rows, as the hunting answer gives them)' {
        $t = ConvertTo-SIContextEdgeTriples -Rows @(@{ EdgeLabel = 'x'; SourceNodeLabel = 'a'; TargetNodeLabel = 'b'; Edges = 4 })
        $t['x'][0].SampleCount | Should -Be 4
    }
}

Describe 'the step -- weekly, one write, never throws (Invoke-SIContextDiscovery / -IfDue)' {
    It 'writes once: the proposals as JSON, the kinds evaluated, the run; the owner''s Decision is never written' {
        $db = New-Db -Fill @([pscustomobject]@{ Field = '*'; Filled = 10 }) -Gaps @()
        $r = Invoke-SIContextDiscovery -SIRoot $script:SIRoot -Invoke $db.Invoke -EdgeTriples @{} -RunId 'run-1'
        $r.Written | Should -BeTrue
        $r.New | Should -Be 2
        $w = @($db.Calls | Where-Object { $_.Sql -match 'INSERT sidata\.ContextProposal' })
        $w.Count | Should -Be 1
        $w[0].Params.runId | Should -Be 'run-1'
        ($w[0].Params.kinds | ConvertFrom-Json) | Should -Be @('CARRY', 'MAP', 'NEW', 'ROUTE')
        $w[0].Sql | Should -Not -Match 'Decision\s*='
        $w[0].Sql | Should -Match 'SET StillSeen = 0' -Because 'a proposal not found again is marked, never deleted'
        $w[0].Sql | Should -Not -Match 'DELETE'
    }
    It 'a fill-rate read that fails is said, CARRY is not evaluated (its old proposals stay), the rest still runs' {
        $db = New-Db -Gaps @() -FailFill
        $r = Invoke-SIContextDiscovery -SIRoot $script:SIRoot -Invoke $db.Invoke -EdgeTriples @{}
        $r.Written | Should -BeTrue
        @($r.Lines) -join ' ' | Should -Match 'fill rates of the CIs could not be read'
        $w = @($db.Calls | Where-Object { $_.Sql -match 'INSERT sidata\.ContextProposal' })[0]
        ($w.Params.kinds | ConvertFrom-Json) | Should -Not -Contain 'CARRY'
    }
    It 'without a database nothing is written and it says so; it never throws' {
        $r = Invoke-SIContextDiscovery -SIRoot $script:SIRoot -Invoke $null -EdgeTriples @{}
        $r.Written | Should -BeFalse
        Get-SIContextDiscoverySummaryText -Result $r | Should -Match 'not saved'
        { Invoke-SIContextDiscovery -SIRoot 'C:\no\such\root' -Invoke $null } | Should -Not -Throw
    }
    It 'weekly: due with no run before, not due within six days, due again after' {
        $now = [datetime]'2026-10-18T06:00:00Z'
        Test-SIContextDiscoveryDue -Invoke (New-Db).Invoke -Now $now | Should -BeTrue
        Test-SIContextDiscoveryDue -Invoke (New-Db -LastRunAt '2026-10-15T06:00:00').Invoke -Now $now | Should -BeFalse
        Test-SIContextDiscoveryDue -Invoke (New-Db -LastRunAt '2026-10-11T06:00:00').Invoke -Now $now | Should -BeTrue
    }
    It 'the IfDue call: off by its switch, skipped when not due, never throws on a broken database' {
        Invoke-SIContextDiscoveryIfDue -SIRoot $script:SIRoot -Invoke (New-Db).Invoke -Setting 'off' | Should -BeNullOrEmpty
        $db = New-Db -LastRunAt ([datetime]::UtcNow.ToString('s'))
        Invoke-SIContextDiscoveryIfDue -SIRoot $script:SIRoot -Invoke $db.Invoke | Should -BeNullOrEmpty
        @($db.Calls | Where-Object { $_.Sql -match 'INSERT' }).Count | Should -Be 0
        $lines = New-Object System.Collections.Generic.List[string]
        { Invoke-SIContextDiscoveryIfDue -SIRoot $script:SIRoot -Invoke { throw 'no database' } -Log { param($l, $m) $lines.Add($m) } } | Should -Not -Throw
        ($lines -join ' ') | Should -Match 'was not run'
    }
}

Describe 'WIRING -- every install gets it: the Detailed run, the weekly schema sweep, the data schema' {
    BeforeAll {
        $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Sd = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-SchemaDiscover.ps1'))
        # the Pro data schema is not in the Community payload: the schema case is skipped there, saying why
        $schemaFile = Join-Path $script:SIRoot 'sql\si-data-schema.sql'
        $script:Schema = if (Test-Path -LiteralPath $schemaFile) { [IO.File]::ReadAllText($schemaFile) } else { $null }
    }
    It 'the Risk Analysis Detailed run (the coordinator, not a worker, not a what-if) calls the weekly step after the findings' {
        $i = $script:Ra.IndexOf('Invoke-SIContextDiscoveryIfDue')
        $i | Should -BeGreaterThan 0
        $script:Ra.LastIndexOf('Publish-SIFindings') | Should -BeLessThan $i
        $script:Ra.IndexOf('Write-Section "script completed"', $i) | Should -BeGreaterThan $i
        $script:Ra | Should -Match ([regex]::Escape("if ([bool]`$global:Detailed -and `$script:RAScaleRole -ne 'worker' -and -not [bool]`$script:SIWhatIf) {"))
    }
    It 'the schema sweep runs the same step with the edge labels it read' {
        $script:Sd | Should -Match 'Invoke-SIContextDiscovery -SIRoot \$siRootCd -Invoke \$cdInvoke -EdgeTriples \$edgeTriples'
    }
    It 'the two tables are in the data schema, guarded, with the owner''s Decision defaulted and never a delete path' {
        if ($null -eq $script:Schema) { Set-ItResult -Skipped -Because 'sql\si-data-schema.sql is not in this copy (the Community payload has no Pro data schema)'; return }
        $script:Schema | Should -Match "IF OBJECT_ID\('sidata\.ContextProposal'\) IS NULL\s+CREATE TABLE sidata\.ContextProposal"
        $script:Schema | Should -Match "IF OBJECT_ID\('sidata\.ContextDiscoveryRun'\) IS NULL\s+CREATE TABLE sidata\.ContextDiscoveryRun"
        $script:Schema | Should -Match "Decision\s+NVARCHAR\(16\)\s+NOT NULL CONSTRAINT DF_ContextProposal_Decision DEFAULT N'proposed'"
        $script:Schema | Should -Match "IF NOT EXISTS \(SELECT 1 FROM sys\.indexes WHERE name = 'IX_ContextProposal_Open'"
    }
    It 'the write and the reads are the module''s own statements, read only towards the sources' {
        (Get-SIContextFillRateSql) | Should -Not -Match '\b(INSERT|UPDATE|DELETE|MERGE)\b'
        (Get-SIContextSourceGapSql) | Should -Not -Match '\b(INSERT|UPDATE|DELETE|MERGE)\b'
        (Get-SIContextEdgeLabelKql) | Should -Match '^ExposureGraphEdges \| summarize'
    }
}
