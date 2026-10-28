#Requires -Version 5.1
<#
    SI v3 -- #212. EVERY PROFILE-TABLE READER READS THIS INSTALL'S ROWS, NOT THE NEWEST OF ANY INSTALL.

    🔴 What must never happen again: two installs write one workspace (measured 2026-10-02: v3 stamps '3.0.0+v3', the
    released engine stamps nothing, and its 13:21 run was newer than this install's 06:07), and a reader's
    max(CollectionTime) / arg_max(CollectionTime, *) picks the OTHER install's rows -- its tiers, its rules.

    The fix is ONE fragment (engine/_shared/SI-InstallRows.ps1). These tests hold its rule, its KQL shape (no `;`, no
    `//`, before the arg_max), and its WIRING into every reader that had no install filter: Risk Analysis' query text,
    its two Log Analytics pre-fetches, the endpoint/azure correlation cache and the Shodan discovery.
    #505 -- the Risk Analysis reports read the CI (SI_CI_CL, v3-only) instead of the profile tables, so the catalog
    assertion is now "no report reads a profile table and the filter changes no report"; the fragment and the engine
    wiring stay held (a custom report, the pre-fetches and the profilers' readers still go through it).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-InstallRows.ps1')
    $script:V3Fam = 'tostring(column_ifexists("SolutionVersion", "")) endswith "+v3"'
}

Describe 'the rule' {
    It 'a v3 install keeps +v3 rows; a 2.x install keeps the others; no version (empty, (dev), not a version) means no filter' {
        Get-SIInstallFamilyPredicateKql -SolutionVersion '3.0.0+v3'  | Should -Be $script:V3Fam
        Get-SIInstallFamilyPredicateKql -SolutionVersion '2.2.460'   | Should -Be ('not({0})' -f $script:V3Fam)
        foreach ($v in @('', $null, '(dev)', 'AutomateIT-internal-main-abc', "3.0.0+v3'; drop", '3.0.0 +v3')) {
            Get-SIInstallFamilyPredicateKql -SolutionVersion $v | Should -BeNullOrEmpty -Because "'$v' says nothing about the install"
        }
        Add-SIInstallRowsFilter -Query 'SI_Endpoint_Profile_CL | take 1' -SolutionVersion '(dev)' | Should -Be 'SI_Endpoint_Profile_CL | take 1'
    }
    It 'keeps ONLY this install''s rows once it has one in the window (#397); none of this install there -> every row' {
        $f = Get-SIInstallRowsFilterKql -TableName 'SI_Endpoint_Profile_CL' -SolutionVersion '3.0.0+v3' -LookbackDays 8
        $f | Should -Be ('| where {0} or (toscalar(SI_Endpoint_Profile_CL | where TimeGenerated > ago(8d) | where {0} | count) == 0)' -f $script:V3Fam)
        $f | Should -Not -Match 'CollectionTime <' -Because 'the older-than-first-row carve-out is what let merged 2.2 duplicates back in (#397)'
        (Get-SIInstallRowsFilterKql -TableName 'SI_Endpoint_Profile_CL' -SolutionVersion '3.0.0+v3') | Should -Not -Match 'ago\('
    }
    It '🔴 the fragment carries no ";" and no "//" (it goes inside let-blocks other code parses), and a table name cannot inject' {
        $f = Get-SIInstallRowsFilterKql -TableName 'SI_Azure_Profile_CL' -SolutionVersion '3.0.0+v3' -LookbackDays 8
        $f | Should -Not -Match ';'
        $f | Should -Not -Match '//'
        $f | Should -Not -Match '\|\s*project'
        { Get-SIInstallRowsFilterKql -TableName 'T | union X' -SolutionVersion '3.0.0+v3' } | Should -Throw
    }
}

Describe 'rewriting a query' {
    It 'the filter lands right after the table and BEFORE the arg_max; the `let x = T | ...` shape stays' {
        $q = "let _ep =`n    SI_Endpoint_Profile_CL`n    | where TimeGenerated > ago(8d)`n    | summarize arg_max(CollectionTime, *) by PrimaryEntityId`n    | project PrimaryEntityId, Tier;`n_ep"
        $r = Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' -LookbackDays 8
        $r | Should -Match '(?s)let _ep =\s+SI_Endpoint_Profile_CL \| where tostring\(column_ifexists\("SolutionVersion"'
        $r.IndexOf('endswith "+v3"') | Should -BeLessThan $r.IndexOf('arg_max(CollectionTime')
        $r | Should -Match '\| summarize arg_max\(CollectionTime, \*\) by PrimaryEntityId'
    }
    It 'a toscalar head, a parenthesised union operand and a ; end get the filter appended; a union list and `join T on` are wrapped' {
        $v = '3.0.0+v3'
        (Add-SIInstallRowsFilter -Query 'print toscalar(SI_Identity_Profile_CL | summarize max(CollectionTime))' -SolutionVersion $v) | Should -Match '^print toscalar\(SI_Identity_Profile_CL \| where .+\) \| summarize max\(CollectionTime\)\)$'
        (Add-SIInstallRowsFilter -Query 'union isfuzzy=true (datatable(x:int)[]), (SI_Endpoint_Profile_CL)' -SolutionVersion $v) | Should -Match '\(SI_Endpoint_Profile_CL \| where .+\)\)$'
        (Add-SIInstallRowsFilter -Query 'let a = SI_Azure_Profile_CL;' -SolutionVersion $v) | Should -Match '^let a = SI_Azure_Profile_CL \| where .+\);$'
        (Add-SIInstallRowsFilter -Query 'union SI_Azure_Profile_CL, SI_Endpoint_Profile_CL' -SolutionVersion $v) | Should -Match '^union \(SI_Azure_Profile_CL \| where .+\), SI_Endpoint_Profile_CL \| where '
        (Add-SIInstallRowsFilter -Query 'X | join kind=inner SI_Azure_Profile_CL on A' -SolutionVersion $v) | Should -Match 'join kind=inner \(SI_Azure_Profile_CL \| where .+\) on A$'
    }
    It 'strings, // comments, a `let T =` definition and a member access are not reads; other tables are untouched' {
        $q = "let SI_Endpoint_Profile_CL = datatable(x:int)[];`n// reads SI_Endpoint_Profile_CL`nX | where Category == `"SI_Endpoint_Profile_CL`" | extend y = a.SI_Endpoint_Profile_CL | union SI_RunHealth_CL"
        Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' | Should -Be $q
    }
    It 'only the inner toscalar references are new -- it is not rewritten again, and a second pass changes nothing' {
        $q = "SI_Endpoint_Profile_CL`n| summarize arg_max(CollectionTime, *) by PrimaryEntityId"
        $r = Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' -LookbackDays 8
        ([regex]::Matches($r, 'SI_Endpoint_Profile_CL')).Count | Should -Be 2
        Add-SIInstallRowsFilter -Query $r -SolutionVersion '3.0.0+v3' -LookbackDays 8 | Should -Be $r
    }
    It '-TableName limits the rewrite to the tables a reader names (a reader with a configurable table name)' {
        $r = Add-SIInstallRowsFilter -Query 'My_Ep_CL | take 1 | join (SI_Azure_Profile_CL) on x' -SolutionVersion '3.0.0+v3' -TableName 'My_Ep_CL'
        $r | Should -Match '^My_Ep_CL \| where '
        $r | Should -Match 'join \(SI_Azure_Profile_CL\) on x$'
    }
}

Describe 'every Risk Analysis report query' {
    BeforeAll {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\SI-Yaml.ps1')   # SecurityInsight's own YAML reader
        $script:Yaml = ConvertFrom-SIYaml -Yaml (Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
        function Write-Info { param($m) }; function Write-Warn2 { param($m) }; function Write-Diag { param($m) }
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    }
    It '🔴 #505 -- no report reads a profile table any more, so the filter leaves every report query exactly as it is' {
        # The reports read their assets from the CI (SI_CI_CL, V3-DATA-MODEL 2.21.1), a v3-only table; the profile
        # tables two installs could both write are no longer read. The filter must therefore change nothing -- and
        # the 2-phase augment finds no profile binding to plan.
        $n = 0
        foreach ($rep in @($script:Yaml.Reports)) {
            $q = [string]$rep.ReportQuery
            if (-not $q) { continue }
            $n++
            $q | Should -Match '\bSI_CI_CL\b' -Because "$($rep.ReportName) reads its assets from the CI"
            $st = [regex]::Replace([regex]::Replace($q, '"[^"\r\n]*"', '""'), '//[^\r\n]*', '')
            $st | Should -Not -Match 'SI_[A-Za-z]+_Profile_CL' -Because "$($rep.ReportName) must not read a profile table"
            Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' -LookbackDays 8 | Should -BeExactly $q -Because $rep.ReportName
            @((Resolve-ProfileAugmentPlan -Query $q).Plans).Count | Should -Be 0 -Because $rep.ReportName
        }
        $n | Should -BeGreaterThan 100 -Because 'the check must see the catalog (control)'
    }
    It 'the real resolver input (#104 fixture): the same plans, and every plan''s Log Analytics fetch filters before its arg_max' {
        $q = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'tests\fixtures\ra-augment-input-104.kql'))
        $global:RA_SolutionVersion = '3.0.0+v3'
        try {
            $before = @((Resolve-ProfileAugmentPlan -Query $q).Plans)
            $after  = @((Resolve-ProfileAugmentPlan -Query (Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' -LookbackDays 8)).Plans)
            $after.Count | Should -Be $before.Count
            $after.Count | Should -BeGreaterThan 0
            foreach ($p in $after) {
                $pk = [string]$p['ProjectionKql']
                $pk | Should -Match ([regex]::Escape($script:V3Fam))
                $pk.IndexOf('endswith "+v3"') | Should -BeLessThan $pk.IndexOf('arg_max(CollectionTime')
            }
        } finally { Remove-Variable -Name RA_SolutionVersion -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'the CL snapshot pre-fetch (table shadow) filters before its arg_max' {
        $global:RA_SolutionVersion = '3.0.0+v3'
        $script:Captured = New-Object System.Collections.Generic.List[string]
        function Invoke-LogAnalyticsKqlQuery { [CmdletBinding()] param($WorkspaceResourceId, $Query) $script:Captured.Add($Query); ,@() }
        function Write-Err2 { param($m) }
        try {
            $script:_CLSnapshotsKql = $null
            $null = Add-CLSnapshotShadows -Query 'SI_Endpoint_Profile_CL | take 1' -WorkspaceResourceId '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z'
            $script:Captured.Count | Should -Be 1
            $script:Captured[0] | Should -Match ('^SI_Endpoint_Profile_CL \| where ' + [regex]::Escape($script:V3Fam))
            $script:Captured[0].IndexOf('endswith "+v3"') | Should -BeLessThan $script:Captured[0].IndexOf('arg_max(CollectionTime')
        } finally { Remove-Variable -Name RA_SolutionVersion -Scope Global -ErrorAction SilentlyContinue; $script:_CLSnapshotsKql = $null }
    }
    It 'WIRING -- the engine loads the fragment and runs every report query through it with its own version stamp' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $src | Should -Match ([regex]::Escape(". (Join-Path (Split-Path -Parent `$PSScriptRoot) '_shared/SI-InstallRows.ps1')"))
        $src | Should -Match ([regex]::Escape('$Query = Add-SIInstallRowsFilter -Query $Query -SolutionVersion $global:RA_SolutionVersion -LookbackDays 8'))
        # after the placeholder substitutions, before bucketing -- every route (LA direct, hunting, lake) reads this text
        $src.IndexOf('$Query = Add-SIInstallRowsFilter') | Should -BeGreaterThan $src.IndexOf('$Query = Resolve-WeightedFactorsBlock -Query $Query')
        $src.IndexOf('$Query = Add-SIInstallRowsFilter') | Should -BeLessThan $src.IndexOf('$Query = Add-DeviceKeyBeforeBucketBlock -Query $Query')
        $src.IndexOf("_shared/SI-InstallRows.ps1") | Should -BeLessThan $src.IndexOf('$global:RA_SolutionVersion = ''(dev)''') -Because 'loaded before any report runs'
    }
}

Describe 'the profilers'' readers' {
    It 'the endpoint/azure correlation cache filters before its arg_max, on its own table name' {
        $global:SI_WorkspaceResourceId = '/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z'
        $script:EpQ = $null
        function Invoke-SIHuntingQuery { [CmdletBinding()] param($Query, $QueryEngine) $script:EpQ = $Query; @() }
        try {
            . (Join-Path $script:SIRoot 'engine\asset-profiling\shared\EndpointAzureCorrelationCache.ps1')
            Reset-SIEndpointAzureCorrelationCache
            Initialize-SIEndpointAzureCorrelationCache
            $script:EpQ | Should -Match ('^SI_Endpoint_Profile_CL \| where ' + [regex]::Escape($script:V3Fam))
            $script:EpQ.IndexOf('endswith "+v3"') | Should -BeLessThan $script:EpQ.IndexOf('arg_max(CollectionTime')
        } finally { Remove-Variable -Name SI_WorkspaceResourceId -Scope Global -ErrorAction SilentlyContinue }
    }
    It 'the Shodan discovery filters both profile tables before their arg_max, in its own lookback' {
        $global:SI_WorkspaceResourceId = '/subscriptions/s/resourceGroups/r/providers/Microsoft.OperationalInsights/workspaces/w'
        $global:SI_Shodan_LookbackDays = 5
        $script:ShQ = $null
        function Write-SIWarn { param($m) }; function Write-SIInfo { param($m) }
        try {
            . (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromShodan.ps1')
            # the SI Azure wrappers (plain REST) the discovery calls, stubbed AFTER the file loaded them
            function Get-SIAzContext { [CmdletBinding()] param() [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 's' } } }
            function Get-SIAzOperationalInsightsWorkspace { [CmdletBinding()] param($ResourceGroupName, $Name) [pscustomobject]@{ CustomerId = [guid]::Empty } }
            function Invoke-SIAzOperationalInsightsQuery { [CmdletBinding()] param($WorkspaceId, $Query, $Wait, $Timespan) $script:ShQ = $Query; [pscustomobject]@{ Results = @() } }
            $null = Get-SIPublicIpsFromProfileCL
            foreach ($t in 'SI_Endpoint_Profile_CL', 'SI_Azure_Profile_CL') {
                $i = $script:ShQ.IndexOf("$t | where ")
                $i | Should -BeGreaterOrEqual 0 -Because "$t is read"
                $script:ShQ.IndexOf('ago(5d) | where', $i) | Should -BeLessThan $script:ShQ.IndexOf('arg_max(CollectionTime', $i)
            }
        } finally {
            Remove-Variable -Name SI_WorkspaceResourceId, SI_Shodan_LookbackDays -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

Describe '#397 -- after an upgrade, a 2.2 row never mixes with the 3.0 rows (mixed 2.2 / 3.0 fixture)' {
    BeforeAll {
        # The upgrade test's shape in miniature: the 2.2 run kept three records of ONE device (three PrimaryEntityIds)
        # that 3.0 merges into one row, and 3.0 no longer writes a renamed device's old id.
        $script:Now = [datetime]'2026-10-06T06:00:00Z'
        function script:New-FixtureRow { param($Id, $Ver, $HoursAgo) [pscustomobject]@{ PrimaryEntityId = $Id; SolutionVersion = $Ver; CollectionTime = $script:Now.AddHours(-$HoursAgo); TimeGenerated = $script:Now.AddHours(-$HoursAgo) } }
        $script:Rows22 = @(
            (New-FixtureRow 'dev-a' '' 30), (New-FixtureRow 'dev-b' '' 30),
            (New-FixtureRow 'dev-x1' '' 30), (New-FixtureRow 'dev-x2' '' 30), (New-FixtureRow 'dev-x3' '' 30),
            (New-FixtureRow 'dev-old-name' '' 30)
        )
        $script:Rows30 = @(
            (New-FixtureRow 'dev-a' '3.0.0+v3' 6), (New-FixtureRow 'dev-b' '3.0.0+v3' 6),
            (New-FixtureRow 'dev-x1' '3.0.0+v3' 6),
            (New-FixtureRow 'dev-new-name' '3.0.0+v3' 6)
        )

        # A REFERENCE MODEL of exactly the KQL fragment the reader gets. It first proves the fragment has this one
        # shape, so the model cannot drift from it silently:
        #   | where <fam> or (toscalar(T | where TimeGenerated > ago(<d>d) | where <fam> | count) == 0)
        # followed by the readers' own `summarize arg_max(CollectionTime, *) by PrimaryEntityId`.
        function script:Invoke-ModelRead {
            param([object[]]$Rows, [string]$SolutionVersion, [int]$LookbackDays = 8)
            $f = Get-SIInstallRowsFilterKql -TableName 'SI_Endpoint_Profile_CL' -SolutionVersion $SolutionVersion -LookbackDays $LookbackDays
            $rx = '^\| where (?<fam>.+?) or \(toscalar\(SI_Endpoint_Profile_CL \| where TimeGenerated > ago\((?<d>\d+)d\) \| where \k<fam> \| count\) == 0\)$'
            $f | Should -Match $rx
            $null = $f -match $rx
            $isV3 = $Matches['fam'] -notmatch '^not\('
            $d = [int]$Matches['d']
            $isFam = { param($r) $e = ([string]$r.SolutionVersion).EndsWith('+v3'); if ($isV3) { $e } else { -not $e } }
            $mine = @($Rows | Where-Object { $_.TimeGenerated -gt $script:Now.AddDays(-$d) -and (& $isFam $_) }).Count
            $kept = @($Rows | Where-Object { (& $isFam $_) -or $mine -eq 0 })
            @($kept | Group-Object PrimaryEntityId | ForEach-Object { @($_.Group | Sort-Object CollectionTime -Descending)[0] })
        }
    }
    It 'only the 3.0 run is read: 4 assets, without the 2.2 duplicates and the old name beside them' {
        $r = Invoke-ModelRead -Rows (@($script:Rows22) + @($script:Rows30)) -SolutionVersion '3.0.0+v3'
        @($r).Count | Should -Be 4
        @($r | ForEach-Object { $_.PrimaryEntityId } | Sort-Object) | Should -Be @('dev-a', 'dev-b', 'dev-new-name', 'dev-x1')
        @($r | Where-Object { -not ([string]$_.SolutionVersion).EndsWith('+v3') }).Count | Should -Be 0
    }
    It 'NEGATIVE CONTROL: the previous rule (also keep 2.x rows older than the first 3.0 row) returns 7 -- the defect' {
        $all = @($script:Rows22) + @($script:Rows30)
        $first = (@($all | Where-Object { ([string]$_.SolutionVersion).EndsWith('+v3') }) | Measure-Object -Property CollectionTime -Minimum).Minimum
        $old = @($all | Where-Object { ([string]$_.SolutionVersion).EndsWith('+v3') -or $_.CollectionTime -lt $first })
        @($old | Group-Object PrimaryEntityId).Count | Should -Be 7
    }
    It 'before the first 3.0 row exists every 2.2 row is still read (an upgraded install never starts empty)' {
        @(Invoke-ModelRead -Rows $script:Rows22 -SolutionVersion '3.0.0+v3').Count | Should -Be 6
    }
    It 'a 3.0 row older than the window does not switch the 2.2 rows off' {
        $stale = @($script:Rows30 | ForEach-Object { New-FixtureRow $_.PrimaryEntityId $_.SolutionVersion 240 })
        $r = Invoke-ModelRead -Rows (@($script:Rows22) + $stale) -SolutionVersion '3.0.0+v3'
        @($r | Where-Object { -not ([string]$_.SolutionVersion).EndsWith('+v3') }).Count | Should -Be 6
    }
    It 'a report-shaped profile read (let-binding + toscalar head) gets the new fragment, never the old shape' {
        # #505 -- the locked catalog no longer reads a profile table (asserted in 'every Risk Analysis report query'),
        # so the fragment is held on the shape the reports had: a let-binding over the profile and a toscalar head.
        $q = @(
            'let _ep ='
            '    SI_Endpoint_Profile_CL'
            '    | where CollectionTime == toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime))'
            '    | summarize arg_max(CollectionTime, *) by PrimaryEntityId'
            '    | project PrimaryEntityId, Tier;'
            'ExposureGraphNodes | join kind=leftouter (_ep) on $left.NodeId == $right.PrimaryEntityId'
        ) -join "`n"
        $r = Add-SIInstallRowsFilter -Query $q -SolutionVersion '3.0.0+v3' -LookbackDays 8
        $r | Should -Not -Match 'CollectionTime < toscalar\(SI_'
        ([regex]::Matches($r, [regex]::Escape(('| where {0} or (toscalar(' -f $script:V3Fam)))).Count | Should -Be 2 -Because 'both reads of the table, the binding and its toscalar'
    }
}

Describe '#397 -- the first v3 run profiles every asset (a 2.x cache record never skips on cadence)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\FingerprintCache.ps1')
    }
    It 'a record without si_edition (written by 2.x) or of another edition is not this edition''s; a v3 record is' {
        Test-SIFingerprintRecordIsThisEdition -Record $null | Should -BeFalse
        Test-SIFingerprintRecordIsThisEdition -Record ([pscustomobject]@{ si_tier = 3; last_seen_at = '2026-10-05T00:00:00Z' }) | Should -BeFalse
        Test-SIFingerprintRecordIsThisEdition -Record ([pscustomobject]@{ si_edition = 'v2'; si_tier = 3 }) | Should -BeFalse
        Test-SIFingerprintRecordIsThisEdition -Record ([pscustomobject]@{ si_edition = 'v3'; si_tier = 3 }) | Should -BeTrue
        Test-SIFingerprintRecordIsThisEdition -Record @{ si_edition = 'v3' } | Should -BeTrue
    }
    It 'the writer stamps si_edition on every record (mock store)' {
        $ctx = [pscustomobject]@{ Mode = 'Mock'; MockState = [pscustomobject]@{ Tables = @{ fp = @{} } } }
        Set-SIFingerprintRecord -Context $ctx -TableName 'fp' -AssetId 'dev-a' -Properties @{ si_tier = 3 }
        $rec = @($ctx.MockState.Tables['fp'].Values)[0]
        $rec['si_edition'] | Should -Be 'v3'
    }
    It 'WIRING -- the cadence gate drops a record of another edition before it can skip the asset' {
        $src = [System.IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1'))
        $gate = $src.IndexOf('-not (Test-SIFingerprintRecordIsThisEdition -Record $cached)) { $cached = $null }')
        $gate | Should -BeGreaterThan 0
        $gate | Should -BeLessThan $src.IndexOf('cadence-not-due (tier=')
    }
}
