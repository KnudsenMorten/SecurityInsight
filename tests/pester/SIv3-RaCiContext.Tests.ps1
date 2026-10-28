#Requires -Version 5.1
<#
    RISK ANALYSIS ON CIs (engine/risk-analysis/_shared/RA-CiContext.ps1 + the pipeline order) -- V3-DATA-MODEL part 2, P4.

      * MATCH: a finding row finds its CI through any id it carries (SI_AssetId with SI's prefixes removed, the Defender /
        Entra / Azure / Exposure Graph ids, any linked object), and only without an id through a name exactly ONE CI has.
      * CI FIELDS: the row takes the CI's tier (and the matching tier label the risk index reads), the owning CMDB's values
        where it has none, the CI's criticality factor as the weight unless the report's weighting set one, and the CI's
        production asset risk factors as tokens -- never a factor the report already computed (any spelling), never a
        testing factor.
      * OFF / EMPTY: SI_RA_CiContext = off, or no CIs yet, leaves the rows exactly as they were.
      * PIPELINE: Risk Analysis runs after asset-correlation in the shipped map; a stored pipeline that ran it before is
        migrated (said in the notes); without asset-correlation (Community) nothing moves.
      * WIRING: the context is added before Calculate-RiskScore, and the index is reset every run.
      * COMMUNITY (D2): where the correlation feature is not available Risk Analysis builds the CIs itself and indexes
        them straight from the build; SI_RA_BuildCis overrides; the identity ledger ships with the free data model.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    $script:Cis = @(
        [pscustomobject]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_asset_name = 'srv01'; si_tier = '0'; si_cmdb_id = 'SVC-7'; si_cmdb_criticality = 'High'; si_criticality_factor = '1.25'
            si_link_mde = 'abc123'; si_link_azure = '/subscriptions/s/rg/vm1'
            si_linked_objects = '[{"provider":"mde","id":"abc123"},{"provider":"eg","id":"egnode9"},{"provider":"azure","id":"/subscriptions/s/rg/vm1"}]'
            si_risk_factors = '[{"id":"internet_exposed","axis":"probability","impact":1,"stage":"production","tokens":["RF_P_InternetExposed"]},{"id":"unsupported_os","axis":"probability","impact":1,"stage":"production","tokens":["RF_P_LegacyEoS"]},{"id":"leaked_credentials","axis":"probability","impact":0,"stage":"testing","tokens":[]},{"id":"production_environment","axis":"consequence","impact":1,"stage":"production","tokens":["IsProductionEnvironment"]}]' }
        [pscustomobject]@{ si_ci_id = 'ci-2'; si_asset_name = 'pc-dup'; si_tier = '3'; si_link_mde = 'm2' }
        [pscustomobject]@{ si_ci_id = 'ci-3'; si_asset_name = 'pc-dup'; si_tier = '2'; si_link_mde = 'm3' }
    )
    $script:Index = New-RACiIndex -Cis $script:Cis
}

Describe 'Finding the CI of a finding row' {
    It 'finds it by <col>' -TestCases @(
        @{ col = 'MdeDeviceId'; val = 'ABC123' }
        @{ col = 'SI_AssetId'; val = 'eg:az:EGNODE9' }
        @{ col = 'AzureResourceId'; val = '/SUBSCRIPTIONS/S/RG/VM1' }
        @{ col = 'AssetId'; val = 'az:/subscriptions/s/rg/vm1' }
    ) {
        $row = [pscustomobject]@{ $col = $val }
        (Find-RACiForRow -Row $row -Index $script:Index).Ci.si_ci_id | Should -Be 'ci-1'
    }
    It 'uses a name only when exactly one CI has it' {
        (Find-RACiForRow -Row ([pscustomobject]@{ AssetName = 'SRV01' }) -Index $script:Index).By | Should -Be 'name'
        Find-RACiForRow -Row ([pscustomobject]@{ AssetName = 'pc-dup' }) -Index $script:Index | Should -BeNullOrEmpty
    }
}

Describe 'Taking the CI''s SI fields' {
    It 'sets the CI, its tier + label, the CMDB values and the weight, and adds the CI''s factors once' {
        $row = [pscustomobject]@{ MdeDeviceId = 'abc123'; CriticalityTier = 3; CriticalityTierLevel = 'Low - tier 3'; RiskFactor_Weight = 100
            RiskFactor_Probability_Detailed = 'Internet-Exposed;ExploitSignals'; RiskFactor_Consequence_Detailed = '' }
        $out = @(Add-RACiContext -Rows @($row) -Index $script:Index)
        $r = $out[0]
        $r.si_ci_id | Should -Be 'ci-1'
        $r.CriticalityTier | Should -Be 0
        $r.CriticalityTierLevel | Should -Be 'Critical - tier 0'
        $r.cmdbId | Should -Be 'SVC-7'
        $r.cmdbCriticality | Should -Be 'High'
        $r.RiskFactor_Weight | Should -Be 125
        @($r.RiskFactor_Probability_Detailed -split ';') | Should -Be @('Internet-Exposed', 'ExploitSignals', 'UnsupportedOS')   # the catalog's short name (#558 / #559)
        $r.RiskFactor_Consequence_Detailed | Should -Be 'Production'
    }
    It 'keeps a weight the report''s own weighting set, and a CMDB value the report carries' {
        $row = [pscustomobject]@{ MdeDeviceId = 'abc123'; RiskFactor_Weight = 150; cmdbId = 'SVC-1' }
        $r = @(Add-RACiContext -Rows @($row) -Index $script:Index)[0]
        $r.RiskFactor_Weight | Should -Be 150
        $r.cmdbId | Should -Be 'SVC-1'
    }
    It 'changes nothing when switched off, with no CIs, or for a row without a CI' {
        $row = [pscustomobject]@{ MdeDeviceId = 'abc123'; CriticalityTier = 3 }
        $global:SI_RA_CiContext = 'off'
        try { @(Add-RACiContext -Rows @($row) -Index $script:Index)[0].CriticalityTier | Should -Be 3 } finally { $global:SI_RA_CiContext = $null }
        @(Add-RACiContext -Rows @($row) -Index (New-RACiIndex -Cis @()))[0].CriticalityTier | Should -Be 3
        $other = [pscustomobject]@{ MdeDeviceId = 'nobody'; CriticalityTier = 2 }
        $o = @(Add-RACiContext -Rows @($other) -Index $script:Index)[0]
        $o.CriticalityTier | Should -Be 2
        $o.PSObject.Properties['si_ci_id'] | Should -BeNullOrEmpty
    }
}

Describe 'Community: Risk Analysis builds the CIs itself' {
    AfterEach { $global:RA_CiIndex = $null; $global:SI_RA_BuildCis = $null }
    It 'builds where the correlation feature is not available, reads SI_CI_CL where it is; the setting overrides' {
        Test-RACiBuildHere -FeatureAvailable { param($f) $f -ne 'correlation' } | Should -BeTrue
        Test-RACiBuildHere -FeatureAvailable { param($f) $true } | Should -BeFalse
        $global:SI_RA_BuildCis = 'off'; Test-RACiBuildHere -FeatureAvailable { param($f) $false } | Should -BeFalse
        $global:SI_RA_BuildCis = 'on'; Test-RACiBuildHere -FeatureAvailable { param($f) $true } | Should -BeTrue
    }
    # ADAPTED 2026-10-21 (#639): this pinned the old shape -- Get-RACiIndex built the CIs with -ReturnCis and indexed EVERY CI of
    # the tenant in memory. Get-RACiIndex now never builds (the run builds the CIs where it decides) and answers a KEYED index:
    # the CIs of each slice are looked up (the database here), once per run the index itself.
    It 'reads the CIs it needs per slice (no build, no index of every CI), the index once per run' {
        $global:RA_CiIndex = $null
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $doc = '{"si_ci_id":"ci-b","si_asset_name":"srv09","si_tier":0,"si_linked_objects":[{"provider":"mde","id":"dev-b"}]}'
        $inv = { param($Sql, $Params, $Mode)
            if ($Sql -match 'COUNT_BIG') { $script:Calls.Add('count'); return , @(@{ N = 1 }) }
            $script:Calls.Add('keyed')
            if (([string]$Params.Ids) -match 'dev-b') { return , @(@{ CiId = 'ci-b'; DocJson = $doc; Stale = 0 }) }
            , @() }
        $ix = Get-RACiIndex -Invoke $inv
        $ix.Keyed | Should -BeTrue
        $ix.Count | Should -Be 1
        $ix.ById.Count | Should -Be 0 -Because 'no CI is held before a slice asks'
        $row = [pscustomobject]@{ MdeDeviceId = 'DEV-B' }
        Use-RACiIndexSlice -Index $ix -Rows @($row) | Should -Be 1
        (Find-RACiForRow -Row $row -Index $ix).Ci.si_ci_id | Should -Be 'ci-b'
        Use-RACiIndexSlice -Index $ix -Rows @([pscustomobject]@{ MdeDeviceId = 'other' }) | Should -Be 0
        $ix.ById.Count | Should -Be 0 -Because 'the slice before is let go'
        $null = Get-RACiIndex
        @($script:Calls | Where-Object { $_ -eq 'count' }).Count | Should -Be 1
    }
    It 'is wired: the CI build lives with the free data model and loads the identity ledger from there' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $t | Should -Match "identity\\SI-ObjectIdentity\.ps1"
        $t | Should -Match "identity\\SI-ObjectLedgerProvider\.ps1"
        foreach ($f in 'SI-ObjectIdentity', 'SI-ObjectLedgerStore', 'SI-ObjectLedgerBlob', 'SI-ObjectLedgerProvider') {
            Test-Path (Join-Path $script:SIRoot "engine\data-model\identity\$f.ps1") | Should -BeTrue -Because "$f ships in both editions"
        }
    }
}

Describe 'Reading the CIs from SI_CI_CL (seen + full rows, #501)' {
    AfterEach { $global:SI_ActiveStaleDays = $null }
    It 'takes the set from the newest build and each CI''s properties from its latest full row' {
        $q = Get-RACiIndexKql
        $q | Should -Match ([regex]::Escape("let build_ = toscalar(ci_ | summarize max(si_t_));"))
        $q | Should -Match ([regex]::Escape("where si_t_ == build_"))
        $q | Should -Match ([regex]::Escape("where si_kind_ in ('full', '')")) -Because 'a row written before the row kinds counts as full'
        $q | Should -Match ([regex]::Escape("join kind=inner set_ on si_k_"))
        $q | Should -Match ([regex]::Escape("column_ifexists('si_row_kind', '')"))
        $q | Should -Match 'si_last_seen = si_seen_' -Because 'staleness comes from the newest seen row'
    }
    It 'looks back SI_ActiveStaleDays (default 30) -- one setting, never a second number' {
        Get-RACiIndexKql | Should -Match 'ago\(30d\)'
        $global:SI_ActiveStaleDays = 45
        Get-RACiIndexKql | Should -Match 'ago\(45d\)'
        Get-RACiIndexKql -LookbackDays 9 | Should -Match 'ago\(9d\)'
    }
    # ADAPTED 2026-10-21 (#639): pinned 'Invoke-SICiBuild -ReturnCis' (every CI handed to Risk Analysis); now the opposite holds
    It 'never asks the build for every CI and never builds from the index (#639)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1'))
        $t | Should -Not -Match 'Invoke-SICiBuild -ReturnCis'
        $t | Should -Not -Match '(?m)^\s*\$res = & \$Build'
    }
}

Describe '#639 the keyed CI index: a slice at a time, every CI a page at a time' {
    BeforeAll {
        # 12 CIs in the "database"; a page is 5 of them
        $script:Docs = @(for ($i = 1; $i -le 12; $i++) { [ordered]@{ CiId = ('ci-{0:D2}' -f $i); DocJson = ('{{"si_ci_id":"ci-{0:D2}","si_asset_name":"host{0:D2}","si_link_mde":"m{0}","si_tier":{1},"si_rf_unknown":["{2}"]}}' -f $i, ($i % 4), $(if ($i % 3 -eq 0) { 'patched' } else { 'none' })); Stale = 0 } })
        $script:Held = 0
        $script:Inv = { param($Sql, $Params, $Mode)
            if ($Sql -match 'COUNT_BIG') { return , @(@{ N = $script:Docs.Count }) }
            if ($Sql -match 'TOP \(CONVERT\(int, @N\)\)') {
                $page = @($script:Docs | Where-Object { [string]::CompareOrdinal($_.CiId, [string]$Params.After) -gt 0 } | Select-Object -First ([int]$Params.N))
                if ($page.Count -gt $script:Held) { $script:Held = $page.Count }
                return , $page
            }
            $ids = @(ConvertFrom-Json ([string]$Params.Ids)); $names = @(ConvertFrom-Json ([string]$Params.Names))
            , @($script:Docs | Where-Object { $d = ConvertFrom-Json $_.DocJson; ($ids -contains ([string]$d.si_link_mde)) -or ($names -contains [string]$d.si_asset_name) })
        }
    }
    AfterEach { $global:RA_CiIndex = $null; $global:SI_RA_CiIndexPageRows = $null }
    It 'ById.Values walks EVERY CI once, a page at a time -- at most one page held (a lazy reader of N pages)' {
        $global:SI_RA_CiIndexPageRows = 5
        $script:Held = 0
        $ix = Get-RACiIndex -Invoke $script:Inv
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($c in $ix.ById.Values) { $ids.Add([string]$c.si_ci_id) }
        $ids.Count | Should -Be 12
        @($ids | Select-Object -Unique).Count | Should -Be 12
        $script:Held | Should -Be 5 -Because 'one page of 5 is the most ever read at once'
    }
    It 'the unknown counts over the keyed index equal the counts over the whole index' {
        $global:SI_RA_CiIndexPageRows = 5
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-UnknownCount.ps1')
        $whole = New-RACiIndex -Cis @($script:Docs | ForEach-Object { ConvertFrom-Json $_.DocJson })
        $ix = Get-RACiIndex -Invoke $script:Inv
        $a = Get-RAUnknownCounts -Index $whole -Factors @('patched') -Tiers @(0, 1)
        $b = Get-RAUnknownCounts -Index $ix -Factors @('patched') -Tiers @(0, 1)
        $b.Total | Should -Be $a.Total
        $b.By['patched'] | Should -Be $a.By['patched']
        $a.Total | Should -BeGreaterThan 0
    }
    It 'Add-RACiContext on a slice gives the same rows as over the whole index' {
        $whole = New-RACiIndex -Cis @($script:Docs | ForEach-Object { ConvertFrom-Json $_.DocJson })
        $mk = { @([pscustomobject]@{ MdeDeviceId = 'm3' }, [pscustomobject]@{ DeviceName = 'host07' }, [pscustomobject]@{ MdeDeviceId = 'nope' }) }
        $r1 = Add-RACiContext -Rows (& $mk) -Index $whole -Mode legacy -Catalog @{ AssetKeys = @{}; Display = @{} }
        $ix = Get-RACiIndex -Invoke $script:Inv
        $r2 = Add-RACiContext -Rows (& $mk) -Index $ix -Mode legacy -Catalog @{ AssetKeys = @{}; Display = @{} }
        ($r2 | ConvertTo-Json -Compress -Depth 4) | Should -Be ($r1 | ConvertTo-Json -Compress -Depth 4)
        @($r2 | Where-Object { $_.PSObject.Properties['si_ci_id'] }).Count | Should -Be 2
    }
    It 'a lookup that fails is a WARNING of the run, said once -- the slice is scored without its CI context' {
        $script:_RAPublishFailures = New-Object System.Collections.Generic.List[string]
        $bad = { param($Sql, $Params, $Mode) if ($Sql -match 'COUNT_BIG') { return , @(@{ N = 3 }) }; throw 'Timeout expired' }
        $ix = Get-RACiIndex -Invoke $bad
        $w = @(Use-RACiIndexSlice -Index $ix -Rows @([pscustomobject]@{ MdeDeviceId = 'm1' }) 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        $w.Count | Should -Be 1
        $null = Use-RACiIndexSlice -Index $ix -Rows @([pscustomobject]@{ MdeDeviceId = 'm2' }) 3>&1
        $global:RA_CiIndexProblem | Should -Match 'could not be looked up \(Timeout expired\)'
        $global:RA_CiIndexProblem = $null
    }
    It 'the keyed SI_CI_CL query narrows the index query to the slice''s ids and names' {
        $q = Get-RACiLaKeyedKql -Ids @('m1', 'az:/x') -Names @('Host01') -StaleDays 30
        $q | Should -Match ([regex]::Escape('dynamic(["m1", "az:/x"])'))
        $q | Should -Match ([regex]::Escape('in (dynamic(["host01"]))'))
        $q | Should -Match 'let build_ = toscalar'
        (Get-RACiLaPageKql -After 'ci-5' -Take 7 -StaleDays 30) | Should -Match ([regex]::Escape('| top 7 by si_ci_id asc'))
    }
}

Describe 'Pipeline: Risk Analysis after the CIs' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-Pipeline.ps1')
        . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
        $script:Map = Get-SIJobFlowMap
    }
    It 'ships the order collect -> asset-correlation -> risk analysis' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-datasync') -Map $script:Map
        $jobs = @($d.Steps.Job)
        $jobs.IndexOf('risk-analysis') | Should -BeGreaterThan $jobs.IndexOf('asset-correlation')
        $jobs.IndexOf('risk-analysis-detailed') | Should -BeGreaterThan $jobs.IndexOf('asset-correlation')
        @($d.Steps | Where-Object Job -eq 'risk-analysis')[0].Stage | Should -Be 'correlate'
        $script:Map.Jobs['risk-analysis'].Needs | Should -Contain 'asset-correlation'
    }
    It 'migrates a stored pipeline that ran Risk Analysis before asset-correlation, and says so' {
        $json = '{"schema":2,"stages":[{"id":"collect","steps":[{"job":"ptc"},{"job":"endpoint"},{"job":"risk-analysis"},{"job":"risk-analysis-detailed"}]},{"id":"correlate","steps":[{"job":"asset-correlation"}]},{"id":"deliver","steps":[{"job":"asset-datasync"}]}]}'
        $d = ConvertFrom-SIJobFlowJson -Json $json -Map $script:Map
        @($d.Steps.Job) | Should -Be @('ptc', 'endpoint', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-datasync')
        @($d.Steps | Where-Object Job -eq 'risk-analysis-detailed')[0].Stage | Should -Be 'correlate'
        $d.Migrated | Should -BeTrue
        ($d.MigrationNotes -join ' ') | Should -Match 'risk-analysis now runs after asset-correlation: it reads its output'
    }
    It 'moves nothing without asset-correlation (Community) or when the order is already right' {
        $d = ConvertFrom-SIJobFlowJson -Json '{"schema":2,"stages":[{"id":"collect","steps":[{"job":"endpoint"},{"job":"risk-analysis"}]}]}' -Map $script:Map
        @($d.Steps.Job) | Should -Be @('endpoint', 'risk-analysis')
        $ok = ConvertFrom-SIJobFlowJson -Json '{"schema":2,"stages":[{"id":"collect","steps":[{"job":"endpoint"}]},{"id":"correlate","steps":[{"job":"asset-correlation"},{"job":"risk-analysis"}]}]}' -Map $script:Map
        ($ok.PSObject.Properties['MigrationNotes'] -and @($ok.MigrationNotes | Where-Object { $_ -match 'now runs after' }).Count) | Should -BeFalse
    }
}

Describe 'Wiring' {
    It 'adds the CI context before scoring and resets the index every run' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t.IndexOf('$ResultFiltered = Add-RACiContext -Rows @($ResultFiltered)') | Should -BeGreaterThan 0
        $t.IndexOf('$ResultFiltered = Add-RACiContext') | Should -BeLessThan $t.IndexOf('$RiskScoreArray = Calculate-RiskScore')
        $t | Should -Match '\$global:RA_CiIndex = \$null'
        $t | Should -Match "_shared/RA-CiContext\.ps1"
    }
}

Describe 'The CI index reads every optional column only if it exists (customer G 2026-10-15)' {
    # An install without a CMDB never posts si_cmdb_* to SI_CI_CL, so Log Analytics has no such column: reading it
    # directly failed the whole CI context ("Failed to resolve scalar expression named 'si_cmdb_id'") and the run
    # scored its findings without tier / criticality / exposure.
    It 'every si_cmdb_*, si_link_*, risk-factor and linked-object column goes through column_ifexists' {
        $k = Get-RACiIndexKql -Mode ci
        foreach ($c in 'si_cmdb_id', 'si_cmdb_name', 'si_cmdb_criticality', 'si_cmdb_data_sensitivity', 'si_criticality_factor', 'si_risk_factors', 'si_linked_objects', 'si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') {
            $k | Should -Match ("{0} = column_ifexists\('{0}'," -f $c) -Because "$c may not exist on an install that never had it"
        }
    }
}
