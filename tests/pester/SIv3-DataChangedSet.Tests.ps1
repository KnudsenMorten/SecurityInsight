#Requires -Version 7.0
<#
    THE DATA SYNC WORKS ON WHAT CHANGED (REQUIREMENTS #1319, design note SCALE-2 #1314) -- engine\pro-data\_shared\SI-DataChangedSet.ps1
    and its two phases (SI-DataViewContext.ps1 Invoke-SIDataViewContext, SI-DataCi.ps1 Invoke-SIDataCiFindingFromDbRanged).

    What these tests keep true (prio 1: HOW a collection is built changes, never WHAT is shown or sent):
      * the setting SI_Data_ChangedSet is ON BY DEFAULT (owner 2026-11-23); only "off" / "shadow" switch it; off makes exactly
        the calls of before;
      * REAL SQL, two collections -- some findings changed, some added, some removed, the run's own time moved in every
        document, and a JOINED field (the tier) moved on findings whose document did not, plus a CI that appears for an asset
        the findings point at: the default (on) build carries the unchanged findings and ends with EXACTLY the full build's
        rows in every table it touches -- the prepared view columns, the issue context, the work rows, the findings per CI
        after the swap, and the lifecycle's input (what the close-loop, ServiceNow / CMDB and data out read);
      * an untrusted base (nothing published, a partial run), a version / settings change and the weekly rule = a full build;
      * shadow logs 0 differences on identical builds and more than 0 when the published collection's results are forced
        wrong -- and the FULL result is the one kept;
      * on + a forced difference in the sample check = the run falls back to the full build (the same rows as with the
        setting off) and the run carries a warning (the fix request), with finding ids and column names, never a value.
    Runs on the Azure test runner (TEST_SQL_*: _SITestSql.ps1); without SQL only the offline part runs.
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataKql.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataChangedSet.ps1')
    $script:List = Get-SIViewStoredColumns
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
    function script:New-FakeDb {
        param([hashtable]$Answers = @{})
        $calls = New-Object System.Collections.Generic.List[object]
        $invoke = {
            param($sql, $p, $mode)
            $calls.Add([pscustomobject]@{ Sql = [string]$sql; Mode = $mode })
            foreach ($k in $Answers.Keys) { if ([string]$sql -match $k) { $a = $Answers[$k]; if ($a -is [scriptblock]) { return (& $a $p) }; return $a } }
            if ($mode -eq 'reader') { return @() }
            return 0
        }.GetNewClosure()
        [pscustomobject]@{ Calls = $calls; Invoke = $invoke }
    }
}

Describe 'the setting: on by default, off and shadow only when said' {
    It 'reads <V> as <Want>' -ForEach @(
        @{ V = $null; Want = 'on' }, @{ V = ''; Want = 'on' }, @{ V = 'on'; Want = 'on' }, @{ V = '"ON"'; Want = 'on' }, @{ V = 'onn'; Want = 'on' }
        @{ V = 'off'; Want = 'off' }, @{ V = '"off"'; Want = 'off' }, @{ V = 'false'; Want = 'off' }, @{ V = 'shadow'; Want = 'shadow' }, @{ V = '"Shadow"'; Want = 'shadow' }
    ) {
        ConvertTo-SIDataChangedSetMode $V | Should -Be $Want
    }
    It 'not set in the database = on; a database without the tables of this build = off (built as before, said)' {
        $db = New-FakeDb -Answers ([ordered]@{ 'cfg\.Setting' = { , @() }; 'OBJECT_ID\(''sidata\.FindingHash''\)' = '1' })
        $r = Read-SIDataChangedSetMode -Invoke $db.Invoke -Value $null
        $r.Mode | Should -Be 'on'; $r.Source | Should -Be 'the default'
        $db2 = New-FakeDb -Answers ([ordered]@{ 'cfg\.Setting' = { , @(@{ ValueJson = '"shadow"' }) }; 'OBJECT_ID\(''sidata\.FindingHash''\)' = '0' })
        $r2 = Read-SIDataChangedSetMode -Invoke $db2.Invoke -Value $null
        $r2.Mode | Should -Be 'off'; $r2.Source | Should -Match 'does not have its tables yet'
        $db3 = New-FakeDb -Answers ([ordered]@{ 'cfg\.Setting' = { , @(@{ ValueJson = '"off"' }) } })
        (Read-SIDataChangedSetMode -Invoke $db3.Invoke -Value $null).Mode | Should -Be 'off'
        @($db3.Calls | Where-Object { $_.Sql -match 'sidata\.FindingHash' }).Count | Should -Be 0 -Because 'off reads nothing of this build'
        (Read-SIDataChangedSetMode -Invoke { throw 'down' } -Value 'off').Mode | Should -Be 'off'
    }
    It 'the catalog carries the setting with on as its default and the three values' {
        $cat = Get-Content -Raw (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $e = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_ChangedSet' })
        $e.Count | Should -Be 1
        @($e[0].values) | Should -Be @('on', 'shadow', 'off')
        [string]$e[0].defaultText | Should -Match '^On'
    }
}

Describe 'the hash: every field that reaches a view or a connector, never the run''s own time' {
    It 'leaves out the row''s identity, its run ordering, what later phases write and the prepared view columns' {
        $x = Get-SIDataFindingHashExcluded -List $script:List
        foreach ($c in 'FindingId', 'CollectionId', 'DetailJson', 'ImportanceRank', 'RemediationKey', 'RaSeq', 'AffectedProduct', 'DescriptionFull', 'Category') { $x.Contains($c) | Should -BeTrue -Because $c }
        foreach ($c in 'Tier', 'DepartmentId', 'ExemptionId', 'CiLifecycle', 'RiskScore', 'RaFindingKey', 'CmdbId') { $x.Contains($c) | Should -BeFalse -Because "$c reaches a view or a connector" }
        $sql = Get-SIDataFindingHashRangeSql -Columns @('AssetKey', 'Tier')
        foreach ($f in (Get-SIDataChangedSetContract).RunFields) { $sql | Should -Match ([regex]::Escape("N'$f'")) }
        $sql | Should -Not -Match '#fhd|JSON_MODIFY' -Because 'one statement: the document is never copied or rewritten (review 2026-11-23)'
        $sql | Should -Match ([regex]::Escape('FROM OPENJSON(CASE WHEN j.J = 1 THEN f.DetailJson END) AS o'))
        ([regex]::Matches($sql, 'INSERT ')).Count | Should -Be 1
        $sql | Should -Match 'f\.FindingId > CONVERT\(bigint, @After\) AND f\.FindingId <= CONVERT\(bigint, @Upto\)' -Because 'one FindingId range per statement'
        (Get-SIDataFindingHashSetId -Columns @('A', 'B')) | Should -Not -Be (Get-SIDataFindingHashSetId -Columns @('A', 'B', 'C')) -Because 'another field list is another set: a full build'
    }
    It 'nothing the prepared columns read is a field the hash leaves out' {
        $rf = (Get-SIDataChangedSetContract).RunFields
        $read = @(@($script:List.finding) | ForEach-Object { @($_.fields) + @(@($_.flags) | Where-Object { $_ } | ForEach-Object { $_.field }) } | Where-Object { $rf -contains [string]$_ })
        $read.Count | Should -Be 0
    }
    It 'the warning names ids and columns, never a value; nothing is said for a clean phase' {
        $w = Get-SIDataChangedSetWarningText -Result ([pscustomobject]@{ Phase = 'swap'; Differences = 2; Detail = 'finding 12: Component'; FellBack = $true; Problem = '' })
        $w | Should -Match 'the findings per CI'; $w | Should -Match 'built in full before anything was published'; $w | Should -Match 'finding 12: Component'
        Get-SIDataChangedSetWarningText -Result ([pscustomobject]@{ Phase = 'view-context'; Differences = 0; Detail = ''; FellBack = $false; Problem = '' }) | Should -BeNullOrEmpty
        $issues = @(Get-SIDataSyncIssues -Result @{ ChangedSet = @([pscustomobject]@{ Phase = 'view-context'; Differences = 3; Detail = 'finding 5: AffectedVendor'; FellBack = $false; Problem = '' }) })
        @($issues | Where-Object { $_.Level -eq 'WARNING' -and $_.Text -match 'differed from the full build in 3 row' }).Count | Should -Be 1
        @(Get-SIDataSyncIssues -Result @{ ChangedSet = @() }).Count | Should -Be 0
    }
}

Describe '#1331 the rolling full check: a rotating seventh of all CIs is built in full every quick build' {
    It 'every CI is in exactly one of the 7 parts, and any 7 consecutive runs take all 7 parts: every CI checked in full in 7 runs' {
        $ids = @(1..3000 | ForEach-Object { 'ci-' + [guid]::NewGuid().ToString('N') }) + @('', 'asset:dev-1', 'CI with spaces and | bars')
        $parts = @{}; foreach ($i in $ids) { $s = Get-SIDataChangedSetRollPartOf -CiId $i; $s | Should -BeIn @(0..6); $parts[$i] = $s }
        # the runs' parts: 0 after none, then the next one each run (wrapping)
        $seq = New-Object System.Collections.Generic.List[int]; $last = $null
        for ($r = 0; $r -lt 20; $r++) { $last = Get-SIDataChangedSetNextRollSlot -Last $last; $seq.Add($last) }
        $seq[0] | Should -Be 0
        for ($w = 0; $w -le $seq.Count - 7; $w++) {
            $window = @($seq[$w..($w + 6)])
            @($window | Select-Object -Unique).Count | Should -Be 7 -Because "runs $w..$($w + 6) take every part"
            $checked = @($ids | Where-Object { $window -contains $parts[$_] })
            $checked.Count | Should -Be $ids.Count -Because 'every CI is checked in full within any 7 consecutive runs'
        }
        # a seventh each (about): no part is empty or holds most of the CIs
        foreach ($s in 0..6) { $n = @($ids | Where-Object { $parts[$_] -eq $s }).Count; $n | Should -BeGreaterThan 300; $n | Should -BeLessThan 600 }
        # the part of a CI is the same every run (unseeded)
        Get-SIDataChangedSetRollPartOf -CiId 'ci-6' | Should -Be (Get-SIDataChangedSetRollPartOf -CiId 'ci-6')
    }
    It 'the sample marks the rolling part on top of the random sample; the count says the rolling CIs; the record keeps the part' {
        $s = Get-SIDataChangedSetSampleSql -Asset 'f.AssetKey'
        $s | Should -Match ([regex]::Escape('CONVERT(int, @RollSlot) >= 0 AND (CONVERT(int, SUBSTRING(HASHBYTES(''SHA2_256'', CONVERT(nvarchar(400), ISNULL(f.AssetKey, N''''))), 1, 3)) % 7) = CONVERT(int, @RollSlot)'))
        $s | Should -Match ([regex]::Escape('< CONVERT(int, @SamplePct) THEN 1'))
        Get-SIDataChangedSetPairsSql | Should -Match '@RollSlot'
        Get-SIDataChangedSetCountSql | Should -Match 'AS RC FROM'
        $src = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataChangedSet.ps1'))
        ([regex]::Matches($src, [regex]::Escape("RollSlot = `$(if (`$null -ne `$st.RollSlot) { [string]`$st.RollSlot } else { '-1' })"))).Count | Should -Be 2 -Because 'both phases hand the part to the pairs'
        $schema = $script:Schema
        $schema | Should -Match ([regex]::Escape("ALTER TABLE sidata.ChangedSetRun ADD RollingSlot TINYINT NULL"))
        $schema | Should -Match ([regex]::Escape("ALTER TABLE sidata.ChangedSetRun ADD BuildParts NVARCHAR(200) NULL"))
        # a database without the columns records as before (and the weekly full build is its fallback)
        $db = New-FakeDb -Answers ([ordered]@{ 'INSERT sidata\.ChangedSetRun' = 5 })
        $id = Start-SIDataChangedSetRun -Invoke $db.Invoke -CollectionId 2 -Decision ([pscustomobject]@{ Phase = 'swap'; Mode = 'on'; Build = 'changed-set'; Why = 'x'; Fingerprint = 'f'; Seed = 1; BaseId = 1; RollSlot = 3; RollReady = $false; BuildParts = 'm=1' })
        $id | Should -Be 5
        $db.Calls[0].Sql | Should -Not -Match 'RollingSlot'
        $db2 = New-FakeDb -Answers ([ordered]@{ 'INSERT sidata\.ChangedSetRun' = 6 })
        $null = Start-SIDataChangedSetRun -Invoke $db2.Invoke -CollectionId 2 -Decision ([pscustomobject]@{ Phase = 'swap'; Mode = 'on'; Build = 'changed-set'; Why = 'x'; Fingerprint = 'f'; Seed = 1; BaseId = 1; RollSlot = 3; RollReady = $true; BuildParts = 'm=1' })
        $db2.Calls[0].Sql | Should -Match 'RollingSlot, BuildParts'
        Get-SIDataChangedSetRollText -Slot 2 -Cis 40 | Should -Match 'part 3 of 7'
        Get-SIDataChangedSetRollText -Slot $null -Cis 0 | Should -Match 'did not run'
    }
    It 'a database that does not record the rolling check yet: the weekly full build stays as its fallback (said)' {
        $old = [datetime]::UtcNow.AddDays(-8)
        $row = @{ BaseId = 1; BasePartial = 0; BaseTime = [datetime]'2026-10-19'; BaseStatus = 'Complete'; BaseKind = 'Detailed'; BaseRetired = 0; NewTime = [datetime]'2026-10-20'
                  BaseSet = 's'; BaseBuilt = [datetime]::UtcNow; BaseRows = 10; BaseN = 10; BaseH = 10; BaseStamp = $null; BaseSame = 1; NewSet = 's'; BaseRun = 3; LastFull = $old
                  LastSlot = $null; NoRoll = $null; BaseParts = $null; NowUtc = [datetime]::UtcNow }
        $db = New-FakeDb -Answers ([ordered]@{ 'RollingSlot'' \) IS NOT NULL' = '0'; 'RetiredAt'' \) IS NULL' = '1'; 'sys\.columns' = { , @() }; 'AS BaseId' = { , @($row) } })
        $d = Resolve-SIDataChangedSetBuild -Invoke $db.Invoke -Phase 'swap' -CollectionId 2 -Mode 'on' -Fingerprint 'f' -SetId 's' -Stamps @()
        $d.Build | Should -Be 'full'
        $d.Why | Should -Match 'weekly full build is due .*the database does not record it yet'
        $row.LastFull = [datetime]::UtcNow.AddDays(-2)
        $d2 = Resolve-SIDataChangedSetBuild -Invoke $db.Invoke -Phase 'swap' -CollectionId 2 -Mode 'on' -Fingerprint 'f' -SetId 's' -Stamps @()
        $d2.Build | Should -Be 'changed-set'; $d2.RollSlot | Should -BeNullOrEmpty -Because 'no part is recorded where the database cannot keep it'
    }
}

Describe '#1331 the build fingerprint: a full build after an update ONLY when the update changes what the build produces' {
    BeforeAll {
        function script:New-BuildRoot([string]$Version, [hashtable]$Files) {
            $r = Join-Path ([IO.Path]::GetTempPath()) ('si-bfp-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            $null = New-Item -ItemType Directory -Path (Join-Path $r 'data-model\mappings') -Force
            [IO.File]::WriteAllText((Join-Path $r 'VERSION'), $Version)
            foreach ($k in $Files.Keys) { [IO.File]::WriteAllText((Join-Path $r $k), [string]$Files[$k]) }
            $r
        }
        $script:BaseFiles = @{ 'data-model\mappings\mde.locked.json' = '{"a":1}'; 'data-model\field-catalog.locked.json' = '{"f":["x"]}' }
        function script:Get-Print([string]$Root, [string]$Tpl = 'T1', [object[]]$Settings = @(@{ N = 'SI_Data_ParseAtInsert'; S = 'solution'; V = '"on"' })) {
            Reset-SIDataChangedSetRunState
            $db = New-FakeDb -Answers ([ordered]@{ 'cfg\.Template' = $Tpl; 'cfg\.Setting' = { , @($Settings) }.GetNewClosure() })
            Get-SIDataChangedSetBuildFingerprint -Invoke $db.Invoke -Root $Root
        }
    }
    It 'a version update with the same data model, typing, templates and settings = the same fingerprint (built from what changed)' {
        $a = New-BuildRoot -Version '3.1.44' -Files $script:BaseFiles
        $b = New-BuildRoot -Version '3.1.45' -Files $script:BaseFiles
        try {
            $pa = Get-Print $a; $pb = Get-Print $b
            $pb.Print | Should -Be $pa.Print
            $pb.Parts | Should -Be $pa.Parts
            (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet 'h' -PhaseText 'x' -Build $pa.Print) | Should -Be (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet 'h' -PhaseText 'x' -Build $pb.Print)
            (Get-Command Get-SIDataChangedSetFingerprint).Parameters.ContainsKey('Version') | Should -BeFalse -Because 'the version is no part of a phase''s fingerprint'
        } finally { Remove-Item -Recurse -Force $a, $b -ErrorAction SilentlyContinue }
    }
    It 'a changed <What> = another fingerprint (a full build), and the run names the part that moved' -ForEach @(
        @{ What = 'mapping file'; Part = 'the data-model files' }
        @{ What = 'template set'; Part = 'the template set' }
        @{ What = 'setting that changes outputs'; Part = 'the settings that change what the build writes' }
        @{ What = 'typing statement'; Part = 'the typing statement' }
    ) {
        $a = New-BuildRoot -Version '3.1.44' -Files $script:BaseFiles
        $files = @{} + $script:BaseFiles
        if ($What -eq 'mapping file') { $files['data-model\mappings\mde.locked.json'] = '{"a":2}' }
        $b = New-BuildRoot -Version '3.1.45' -Files $files
        try {
            $pa = Get-Print $a
            $pb = switch ($What) {
                'template set' { Get-Print $b -Tpl 'T2' }
                'setting that changes outputs' { Get-Print $b -Settings @(@{ N = 'SI_Data_ParseAtInsert'; S = 'solution'; V = '"off"' }) }
                'typing statement' { Mock Get-SIDataChangedSetTypingPrint { 'ANOTHERSTATEMENT' }; Get-Print $b }
                default { Get-Print $b }
            }
            $pb.Print | Should -Not -Be $pa.Print
            (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet 'h' -PhaseText 'x' -Build $pa.Print) | Should -Not -Be (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet 'h' -PhaseText 'x' -Build $pb.Print)
            $moved = @(Compare-SIDataChangedSetBuildParts -Base $pa.Parts -Now $pb.Parts)
            $moved.Count | Should -Be 1
            $moved[0] | Should -Match ([regex]::Escape($Part))
        } finally { Remove-Item -Recurse -Force $a, $b -ErrorAction SilentlyContinue }
    }
    It 'a changed field list is another fingerprint too (the hash set); an added data-model file is another one; a part that cannot be read = the phase built in full' {
        (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet (Get-SIDataFindingHashSetId -Columns @('A')) -PhaseText 'x' -Build 'b') | Should -Not -Be (Get-SIDataChangedSetFingerprint -Phase 'swap' -HashSet (Get-SIDataFindingHashSetId -Columns @('A', 'B')) -PhaseText 'x' -Build 'b')
        $a = New-BuildRoot -Version '1' -Files $script:BaseFiles
        try {
            $p1 = Get-SIDataChangedSetFilesPrint -Root $a
            [IO.File]::WriteAllText((Join-Path $a 'data-model\mappings\new.locked.json'), '{}')
            Get-SIDataChangedSetFilesPrint -Root $a | Should -Not -Be $p1
            # CRLF vs LF of the same file is the same print (a checkout's line ends never force a full build)
            $b = New-BuildRoot -Version '1' -Files @{ 'data-model\mappings\mde.locked.json' = "{`r`n""a"":1}"; 'data-model\field-catalog.locked.json' = '{"f":["x"]}' }
            $c = New-BuildRoot -Version '1' -Files @{ 'data-model\mappings\mde.locked.json' = "{`n""a"":1}"; 'data-model\field-catalog.locked.json' = '{"f":["x"]}' }
            Get-SIDataChangedSetFilesPrint -Root $b | Should -Be (Get-SIDataChangedSetFilesPrint -Root $c)
            Remove-Item -Recurse -Force $b, $c -ErrorAction SilentlyContinue
        } finally { Remove-Item -Recurse -Force $a -ErrorAction SilentlyContinue }
        # the shipped tree has the data model (the print is never 'none' in a real install)
        Get-SIDataChangedSetFilesPrint | Should -Not -Be 'none'
        Reset-SIDataChangedSetRunState
        $db = New-FakeDb -Answers ([ordered]@{ 'sys\.columns' = { , @(@{ N = 'AssetKey' }) }; 'cfg\.Template' = { throw 'down' } })
        $st = Start-SIDataCiWorkChangedSet -Invoke $db.Invoke -CollectionId 2 -Lo 1 -Hi 10 -Mode 'on'
        $st.Build | Should -Be 'failed' -Because 'any doubt = full: the work rows are read in full'
        $st.Problem | Should -Match 'down'
        Reset-SIDataChangedSetRunState
    }
}

Describe 'review: a malformed list fails closed, no quoted value is recorded, a moved mark makes the hashes stale' {
    It 'a prepared column that is not a plain identifier never reaches a statement: <Name>' -ForEach @(
        @{ Name = 'a bracket'; Col = 'AffectedVendor] = 1; --' }, @{ Name = 'a space'; Col = 'Affected Vendor' }, @{ Name = 'empty'; Col = '' }, @{ Name = 'a quote'; Col = "x'y" }
    ) {
        $bad = [pscustomobject]@{ finding = @([pscustomobject]@{ column = 'AffectedProduct'; fields = @('si_affected_product') }, [pscustomobject]@{ column = $Col; fields = @('si_x') }) }
        { Get-SIDataChangedSetListColumns -List $bad } | Should -Throw '*not well formed*'
        { Get-SIDataContextCarrySql -List $bad -Part copy } | Should -Throw
        { Get-SIDataContextOutHashExpr -List $bad -Alias 'f' } | Should -Throw
        { Get-SIDataFindingHashExcluded -List $bad } | Should -Throw
        { Get-SIDataChangedSetColumnPart -Alias 'f' -Column $Col } | Should -Throw
        # the phase: a full build, and not one statement of it ran
        $db = New-FakeDb
        $st = Start-SIDataViewContextChangedSet -Invoke $db.Invoke -CollectionId 2 -List $bad -SetId 'x' -Fill 'f.FindingId <= @Upto' -Mode 'on' -Lo 1 -Hi 10
        $st.Build | Should -Be 'full'
        $st.Problem | Should -Match 'not well formed'
        $db.Calls.Count | Should -Be 0
    }
    It 'the shipped list and the work-row values are plain identifiers' {
        @(Get-SIDataChangedSetListColumns -List $script:List).Count | Should -BeGreaterThan 10
        foreach ($c in (Get-SIDataChangedSetContract).WorkJson) { Test-SIDataChangedSetColumnName $c | Should -BeTrue }
        { Get-SIDataCiWorkCarrySql -Part compare } | Should -Not -Throw
    }
    It 'an error is recorded by its number and its words, never a value it quotes' {
        $e = Get-SIDataChangedSetSafeError ([System.Exception]::new("Conversion failed when converting the nvarchar value 'secret-123' to data type int."))
        $e | Should -Not -Match 'secret-123'; $e | Should -Match 'Conversion failed'
        $e2 = Get-SIDataChangedSetSafeError ([System.Exception]::new('Violation of PRIMARY KEY constraint ''PK_X''. Cannot insert duplicate key in object ''sidata.X''. The duplicate key value is (secret-456, 7).'))
        $e2 | Should -Not -Match 'secret-456'
        (Get-SIDataChangedSetSafeError ([System.Exception]::new(('x ' * 400)))).Length | Should -BeLessOrEqual 160
        $src = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataChangedSet.ps1'))
        ([regex]::Matches($src, 'Exception\.Message')).Count | Should -Be 0 -Because 'every recorded or said error goes through the safe form'
        foreach ($f in 'SI-DataViewContext.ps1', 'SI-DataCi.ps1') { [IO.File]::ReadAllText((Join-Path $script:Root "engine\pro-data\_shared\$f")) | Should -Not -Match ([regex]::Escape("its record was not written: {0}' -f `$_.Exception.Message")) }
    }
    It 'the marks recorded with the hashes include the status, the kind, the time and every rewrite mark' {
        $x = Get-SIDataChangedSetStampHashExpr -Alias 'c' -Have @('DerivedAt', 'ResolvedAt')
        foreach ($c in 'c.Status', 'c.Kind', 'c.CollectionTime', 'c.[DerivedAt]', 'c.[ResolvedAt]') { $x | Should -Match ([regex]::Escape($c)) }
        $x | Should -Match "N'-'" -Because 'a mark that is cleared is a change, never the same as before'
    }
}

Describe 'review: stability and resume' {
    It 'a collection whose hashes failed once is not hashed again in the same run (no doubled cost); a new run tries again' {
        Reset-SIDataChangedSetRunState
        $db = New-FakeDb -Answers ([ordered]@{ 'sys\.columns' = { , @() }; 'AS HRows' = { , @(@{ HashSet = $null; HRows = $null; BuiltAt = $null; Stamp = $null; Same = 0; N = 10; H = 0 }) }; 'MIN\(FindingId\) AS Lo' = { , @(@{ Lo = 1; Hi = 10 }) }; 'INSERT sidata\.FindingHash ' = { throw 'boom' } })
        { Invoke-SIDataFindingHash -Invoke $db.Invoke -CollectionId 5 -Columns @('AssetKey') -SetId 's1' } | Should -Throw '*boom*'
        $n = $db.Calls.Count
        { Invoke-SIDataFindingHash -Invoke $db.Invoke -CollectionId 5 -Columns @('AssetKey') -SetId 's1' } | Should -Throw '*failed earlier this run*'
        $db.Calls.Count | Should -Be $n -Because 'the second phase asks nothing of the database'
        Reset-SIDataChangedSetRunState
        { Invoke-SIDataFindingHash -Invoke $db.Invoke -CollectionId 5 -Columns @('AssetKey') -SetId 's1' } | Should -Throw '*boom*'
        $db.Calls.Count | Should -BeGreaterThan $n
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1')) | Should -Match 'Reset-SIDataChangedSetRunState'
    }
    It 'the hash starts small and runs its ranges at once where the database hands out connections' {
        (Get-Command Invoke-SIDataFindingHash).Parameters['FirstSize'].Attributes | Out-Null
        $d = (Get-Command Invoke-SIDataFindingHash).Definition
        $d | Should -Match 'Invoke-SIDataParallelRanges -ConnectionInfo \$ci'
        $d | Should -Match 'Get-SIDataFillRangeCount'
        ((Get-Command Invoke-SIDataFindingHash).ScriptBlock.Ast.Body.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'FirstSize' }).DefaultValue.Extent.Text | Should -Be '5000'
    }
    It 'a resume mark names its quick build; another build, base or seed is never gone on from' {
        (ConvertFrom-SIDataContextResumeMark '123').Tail | Should -BeNullOrEmpty
        $m = ConvertFrom-SIDataContextResumeMark '123;cs;changed-set;77;9'
        $m.Upto | Should -Be 123; $m.Build | Should -Be 'changed-set'; $m.Seed | Should -Be 77; $m.BaseId | Should -Be '9'
        ConvertFrom-SIDataContextResumeMark 'junk' | Should -BeNullOrEmpty
        $v = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1'))
        $v | Should -Match ([regex]::Escape('Value = ([string]$after + $vcMarkTail)'))
        $v | Should -Match ([regex]::Escape('if (-not $vcCsState.ResumeOk)'))
        # a full fill (the setting off) never goes on from a quick build's mark: it is no number
        [long]$w = 0; [long]::TryParse('123;cs;changed-set;77;9', [ref]$w) | Should -BeFalse
    }
    It 'a carried finding must hold its published finding''s columns; a pair needs the published finding''s ROW' {
        $l = $script:List
        Get-SIDataContextCarrySql -List $l -Part verify | Should -Match 'b\.FindingId IS NULL OR EXISTS'
        Get-SIDataChangedSetPairsSql | Should -Match 'JOIN sidata\.Finding AS bf ON bf\.CollectionId = b\.CollectionId AND bf\.FindingId = b\.FindingId'
    }
}

Describe 'off: exactly the calls of before' {
    It 'the prepared context makes the same statements with the setting off as without it' {
        $mk = { New-FakeDb -Answers ([ordered]@{ 'SELECT CASE WHEN COL_LENGTH' = 1; 'ContextAt IS NULL' = { @(@{ CollectionId = 9; CollectionTime = [datetime]'2026-10-17' }) }; 'MIN\(FindingId\) AS Lo' = { @(@{ Lo = 1; Hi = 12000; N = 12000 }) }; 'UPDATE f SET' = { param($p) [long]$p['Upto'] - [long]$p['After'] } }) }
        # (a first call warms what the database's own pacing reads at most every 15 s -- the two calls compared then see the same)
        $w = & $mk; $null = Invoke-SIDataViewContext -Invoke $w.Invoke -List $script:List -Log { } -TargetMs 100000000
        $a = & $mk; $b = & $mk
        $null = Invoke-SIDataViewContext -Invoke $a.Invoke -List $script:List -Log { } -TargetMs 100000000
        $r = Invoke-SIDataViewContext -Invoke $b.Invoke -List $script:List -Log { } -TargetMs 100000000 -ChangedSet 'off'
        ($b.Calls | ForEach-Object { $_.Sql }) -join "`n" | Should -Be (($a.Calls | ForEach-Object { $_.Sql }) -join "`n")
        @($r.ChangedSet).Count | Should -Be 0
    }
    It 'the work table''s fill makes the same statements with the setting off as without it' {
        $seam = {
            param($Sql, $P, $Mode)
            $script:Calls.Add([string]$Sql)
            if ($Sql -match 'SELECT MIN\(FindingId\) AS Lo') { return , @(@{ Lo = 1L; Hi = 100L }) }
            if ($Sql -match "IF OBJECT_ID\('sidata\.ViewState'\) IS NULL SELECT 0") { return 1 }
            if ($Sql -match 'INTO #w') { return ([long]$P['Upto'] - [long]$P['After']) }
            if ($Sql -match 'SELECT MAX\(x\.KeyHash\)') { return [System.DBNull]::Value }
            0
        }
        $p = Get-SIDataCiRatingBandParams; $p['CollectionId'] = '7'
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIDataCiFindingFromDbRanged -Invoke $seam -Params $p -FillTake 30 -TargetMs 100000000 -Log { }
        $one = $script:Calls.ToArray()
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIDataCiFindingFromDbRanged -Invoke $seam -Params $p -FillTake 30 -TargetMs 100000000 -Log { } -ChangedSet 'off'
        ($script:Calls -join "`n") | Should -Be ($one -join "`n")
    }
    It 'WIRING: the data sync reads the setting once and hands it to both phases; the job loads the file' {
        $s = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1'))
        ([regex]::Matches($s, 'Read-SIDataChangedSetMode -Invoke \$Invoke')).Count | Should -Be 1
        $s | Should -Match ([regex]::Escape('Invoke-SIDataViewContext -Invoke $Invoke -DryRun:$DryRun -Log $Log -ChangedSet $csMode'))
        $s | Should -Match ([regex]::Escape('-Phase $phase -ChangedSet $csMode'))
        $c = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1'))
        $c | Should -Match ([regex]::Escape('-ChangedSet $ChangedSet -ChangedSetOut $csOut }'))
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\Invoke-SIDataSync.ps1')) | Should -Match ([regex]::Escape("_shared\SI-DataChangedSet.ps1"))
    }
}

Describe 'REAL SQL: the build from what changed equals the full build' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Dbs = New-Object System.Collections.Generic.List[string]
        function script:New-TestDb {
            $name = 'si_test_cs_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $script:Dbs.Add($name)
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$name;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
            $cn.Open()
            $seam = {
                param($Sql, $Params, $Mode)
                $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
                if ($Params) { foreach ($k in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) } }
                switch ($Mode) {
                    { $_ -in 'reader', 'rows' } { $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) }; $rd.Close(); , $out.ToArray() }
                    'scalar' { $c.ExecuteScalar() }
                    default { [void]$c.ExecuteNonQuery() }
                }
            }.GetNewClosure()
            [pscustomobject]@{ Name = $name; Cn = $cn; Seam = $seam }
        }
        # collection 1: 300 findings, 260 keys, CIs and asset owners; every document carries the run's own time
        $script:SeedC1 = @'
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt) VALUES ('2026-10-19T03:00:00', 'Detailed', 'Complete', DATEADD(minute, -30, SYSUTCDATETIME()));
DECLARE @cid INT = SCOPE_IDENTITY();
INSERT sidata.Ci (CiId, Class, Name, Lifecycle, CollectionTime) SELECT CONCAT(N'ci-', n), N'device', CONCAT(N'srv', n), N'active', '2026-10-19T03:00:00' FROM (SELECT TOP (30) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS n FROM sys.all_objects) x;
;WITH n AS (SELECT TOP (300) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, DetailJson, RaSeq, RaFindingKey, RaAssetId)
SELECT @cid, CONCAT(N'ci-', i % 37), CONCAT(N'srv', i % 37), CONCAT(N'Report_', i % 3), N'Endpoint', CONCAT(N'CVE-2026-', 1000 + (i % 14)), CONCAT(N'CVE-2026-', 1000 + (i % 14)), CONCAT(N'Title ', i % 14),
       CASE i % 4 WHEN 0 THEN N'Critical' WHEN 1 THEN N'High' WHEN 2 THEN N'Medium' ELSE N'Low' END, i % 4, i * 1.5, i * 2.0,
       CONCAT(N'{"CollectionTime":"2026-10-19T03:00:00","TimeGenerated":"2026-10-19T03:05:00Z","RiskFactor_Probability_Detailed":"p', i % 5, N';q","RiskFactor_Consequence_Detailed":"c', i % 2,
              N'","si_component":"', CASE WHEN i % 6 = 0 THEN N'Other' ELSE N'Comp' + CONVERT(nvarchar(4), i % 3) END,
              N'","si_servicenow_subci":"sub', i % 4, N'","si_category":"Cat', i % 2, N'","si_subcategory":"Sub', i % 3, N'","si_cve_published":"2026-01-0', 1 + i % 9,
              N'T00:00:00Z","si_affected_product":"P', i % 7, N'","si_affected_vendor":"V', i % 3, N'","si_affected_version":"1.', i % 5,
              N'","si_description":"Description of finding ', i % 11, N'","si_epss":', CONVERT(nvarchar(8), (i % 9) / 10.0), N',"HasExploit":', CASE WHEN i % 4 = 0 THEN N'true' ELSE N'false' END,
              N',"si_fix_due_date":"2026-12-0', 1 + i % 8, N'T00:00:00Z","si_attack_path_count":', i % 3, N'}'),
       i, CASE WHEN i % 37 < 30 THEN CONCAT(N'ci-', i % 37) ELSE CONCAT(N'asset:dev-', i % 37) END + N'|' + CONCAT(N'cve-2026-', 1000 + (i % 14)) + CASE WHEN i % 23 = 0 THEN N'' ELSE CONCAT(N'-', i % 20) END,
       CONCAT(N'dev-', i % 37)
FROM n;
'@
        # collection 2: the run's own time moved in EVERY document; every 10th document changed; every 13th finding's TIER moved
        # (its document did not); every 17th gone; 25 new findings; and a CI appears for an asset the findings point at
        $script:SeedC2 = @'
DECLARE @c1 INT = (SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-19T03:00:00' AND Kind = N'Detailed');
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt) VALUES ('2026-10-20T03:00:00', 'Detailed', 'Complete', DATEADD(minute, -30, SYSUTCDATETIME()));
DECLARE @c2 INT = SCOPE_IDENTITY();
INSERT sidata.Ci (CiId, Class, Name, Lifecycle, CollectionTime) VALUES (N'dev-31', N'device', N'dev31', N'active', '2026-10-20T03:00:00');
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, DetailJson, RaSeq, RaFindingKey, RaAssetId)
SELECT @c2, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity,
       CASE WHEN RaSeq % 13 = 0 THEN (Tier + 1) % 4 ELSE Tier END, RiskScore, RiskScoreWeighted,
       REPLACE(REPLACE(CASE WHEN RaSeq % 10 = 0 THEN REPLACE(REPLACE(DetailJson, N'"si_affected_product":"P', N'"si_affected_product":"Q'), N'"si_component":"Comp', N'"si_component":"Part') ELSE DetailJson END,
               N'"CollectionTime":"2026-10-19T03:00:00"', N'"CollectionTime":"2026-10-20T03:00:00"'), N'"TimeGenerated":"2026-10-19T03:05:00Z"', N'"TimeGenerated":"2026-10-20T03:04:00Z"'),
       RaSeq, RaFindingKey, RaAssetId
FROM sidata.Finding WHERE CollectionId = @c1 AND RaSeq % 17 <> 0 ORDER BY FindingId;
;WITH n AS (SELECT TOP (25) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) + 1000 AS i FROM sys.all_objects)
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, DetailJson, RaSeq, RaFindingKey, RaAssetId)
SELECT @c2, CONCAT(N'ci-', i % 37), CONCAT(N'srv', i % 37), N'Report_0', N'Endpoint', CONCAT(N'CVE-2027-', i), CONCAT(N'CVE-2027-', i), N'New one', N'High', 1, 40, 41,
       CONCAT(N'{"CollectionTime":"2026-10-20T03:00:00","si_component":"New","si_affected_product":"N', i % 4, N'","si_description":"A new finding"}'),
       i, CONCAT(N'ci-', i % 30) + N'|' + CONCAT(N'cve-2027-', i), CONCAT(N'dev-', i % 37)
FROM n;
'@
        $script:Publish = "MERGE sidata.PublishedRun AS t USING (SELECT N'current' AS Name, CONVERT(int, @c) AS Id, (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = CONVERT(int, @c)) AS T) AS s ON t.Name = s.Name WHEN MATCHED THEN UPDATE SET DetailedCollectionId = s.Id, DetailedCollectionTime = s.T, [Partial] = 0, PublishedAt = SYSUTCDATETIME() WHEN NOT MATCHED THEN INSERT (Name, DetailedCollectionId, DetailedCollectionTime, Source) VALUES (s.Name, s.Id, s.T, N'run');"
        function script:Invoke-Steps($Db, [string]$Mode, [long]$Cid, [int]$Pct, [int]$Seed = 7) {
            $lines = New-Object System.Collections.Generic.List[string]
            $log = { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
            $vc = Invoke-SIDataViewContext -Invoke $Db.Seam -List $script:List -Workers 1 -BudgetSeconds 100000 -ChangedSet $Mode -ChangedSetSeed $Seed -ChangedSetSamplePercent $Pct -Log $log
            $p = Get-SIDataCiRatingBandParams; $p['CollectionId'] = [string]$Cid
            $o = @{}
            $n = Invoke-SIDataCiFindingFromDbRanged -Invoke $Db.Seam -Params $p -SubCi -Category -FillTake 37 -RangeTake 29 -Workers 1 -ChangedSet $Mode -ChangedSetOut $o -ChangedSetSeed $Seed -ChangedSetSamplePercent $Pct -Log $log
            $null = Invoke-SIDataCiFindingSwap -Invoke $Db.Seam -Expected ([long]$n) -SubCi -Category -ContentHash -Log $log
            $null = & $Db.Seam (Get-SIDataCiLifecycleFromStageSql) @{} 'scalar'
            [pscustomobject]@{ ViewContext = $vc; Work = $o['Result']; Staged = [long]$n; Log = ($lines -join "`n") }
        }
        function script:New-Scenario([string]$Mode, [switch]$CorruptBase, [int]$Pct = -1, [scriptblock]$BeforeStep2, [scriptblock]$Wrap) {
            $db = New-TestDb
            & $db.Seam $script:Schema @{} 'nonquery'
            & $db.Seam $script:SeedC1 @{} 'nonquery'
            $c1 = [long](& $db.Seam "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-19T03:00:00'" @{} 'scalar')
            Reset-SIDataChangedSetRunState
            $sw1 = [Diagnostics.Stopwatch]::StartNew()
            $r1 = Invoke-Steps $db $Mode $c1 $Pct
            $r1 | Add-Member -NotePropertyName Ms -NotePropertyValue $sw1.ElapsedMilliseconds
            $null = & $db.Seam $script:Publish @{ c = [string]$c1 } 'nonquery'
            if ($CorruptBase) {
                # the published collection's results made wrong where the next collection would carry them
                $null = & $db.Seam "UPDATE sidata.Finding SET AffectedVendor = N'not what the document says' WHERE CollectionId = CONVERT(int, @c) AND RaSeq % 10 <> 0 AND RaSeq % 13 <> 0 AND RaSeq % 4 = 1" @{ c = [string]$c1 } 'nonquery'
                $null = & $db.Seam "UPDATE w SET Component = N'Wrong' FROM sidata.CiFindingDbWork AS w WHERE w.RaSeq % 4 = 1" @{} 'nonquery'
            }
            & $db.Seam $script:SeedC2 @{} 'nonquery'
            $c2 = [long](& $db.Seam "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-20T03:00:00'" @{} 'scalar')
            if ($BeforeStep2) { & $BeforeStep2 $db $c1 $c2 }
            $db2 = $db
            if ($Wrap) { $inner = $db.Seam; $w = $Wrap; $db2 = [pscustomobject]@{ Name = $db.Name; Cn = $db.Cn; Seam = { param($Sql, $Params, $Mode) & $w $inner $Sql $Params $Mode }.GetNewClosure() } }
            # the second collection is the next data sync run (it reads its own build fingerprint, #1331)
            Reset-SIDataChangedSetRunState
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r2 = Invoke-Steps $db2 $Mode $c2 $Pct
            $r2 | Add-Member -NotePropertyName Ms -NotePropertyValue $sw.ElapsedMilliseconds
            [pscustomobject]@{ Db = $db; C1 = $c1; C2 = $c2; R1 = $r1; R2 = $r2 }
        }
        function script:Get-Snap($Db, [long]$Cid) {
            $cols = (@($script:List.finding) | ForEach-Object { '[{0}]' -f [string]$_.column }) -join ', '
            $q = [ordered]@{
                Context   = "SELECT FindingId, $cols FROM sidata.Finding WHERE CollectionId = $Cid"
                Issue     = "SELECT * FROM sidata.IssueContext WHERE CollectionId = $Cid"
                Work      = 'SELECT KeyHash, FindingId, RaSeq, RaFindingKey, AssetKey, RaAssetId, ConfigurationId, Title, AssetName, SecurityDomain, ReportName, Tier, RiskScore, ExemptionId, Weighted, Component, Factors, SevRank, SubCi, PatchCycle, CvePublished, Cat, SubCat FROM sidata.CiFindingDbWork'
                CiFinding = 'SELECT CiId, AssetId, FindingKey, FindingType, Title, Severity, Tier, RiskScore, WeightedRiskScore, RiskRating, SecurityDomain, DetectedBy, RiskFactors, ExemptionId, CollectionTime, DocJson, Component, SubCi, PatchCycle, CvePublished, Category, Subcategory, ContentHash FROM sidata.CiFinding'
                Lifecycle = 'SELECT Kind, OwnerKey, FindingKey, CiId, Severity, DetectedBy, ExemptionId FROM sidata.CiFindingLifecycleStage'
            }
            $out = [ordered]@{}
            foreach ($k in $q.Keys) {
                $rows = @(& $Db.Seam ("SELECT (SELECT x.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J FROM ({0}) AS x" -f $q[$k]) @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['J'] })
                [Array]::Sort($rows, [StringComparer]::Ordinal)
                $out[$k] = $rows
            }
            $out
        }
        function script:Compare-Snap($A, $B, [string]$Why) {
            foreach ($k in $A.Keys) {
                $B[$k].Count | Should -Be $A[$k].Count -Because "$Why (${k}: rows)"
                $first = $null
                for ($i = 0; $i -lt $A[$k].Count; $i++) { if ($A[$k][$i] -cne $B[$k][$i]) { $first = "$k row $i`n full: $($A[$k][$i])`n now : $($B[$k][$i])"; break } }
                $first | Should -BeNullOrEmpty -Because $Why
            }
        }
        $script:Full = New-Scenario -Mode 'off'
        $script:FullSnap = Get-Snap $script:Full.Db $script:Full.C2
    }
    AfterAll {
        foreach ($s in @($script:Full, $script:On, $script:ShadowClean, $script:ShadowBad, $script:OnBad, $script:DelFail, $script:CountBad, $script:Resume, $script:BaseGone, $script:RollBad, $script:TplMoved)) { if ($s) { try { $s.Db.Cn.Dispose() } catch { } } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        foreach ($name in $script:Dbs) {
            try {
                $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
                $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            } catch { }
        }
    }
    It 'off (the full build) writes no row of this build' {
        foreach ($t in 'FindingHash', 'FindingHashState', 'ChangedSetRun', 'ChangedSetCarry') { [long](& $script:Full.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.$t" @{} 'scalar') | Should -Be 0 -Because $t }
        $script:FullSnap.Context.Count | Should -BeGreaterThan 250
        $script:FullSnap.CiFinding.Count | Should -BeGreaterThan 200
    }
    It 'on (the default): the first collection is built in full (nothing published), the second carries the unchanged findings -- and every table equals the full build' {
        $script:On = New-Scenario -Mode 'on'
        $vc1 = @($script:On.R1.ViewContext.ChangedSet)[0]; $vc2 = @($script:On.R2.ViewContext.ChangedSet)[0]
        $vc1.Build | Should -Be 'full'; $vc1.Why | Should -Match 'nothing is published yet'
        $script:On.R1.Work.Build | Should -Be 'full'
        $vc2.Build | Should -Be 'changed-set' -Because $vc2.Why
        $vc2.Carried | Should -BeGreaterThan 100
        $vc2.Differences | Should -Be 0
        $vc2.Compared | Should -BeGreaterThan 0 -Because 'the sample check builds about one CI in ten in full every run'
        $script:On.R2.Work.Build | Should -Be 'changed-set' -Because $script:On.R2.Work.Why
        $script:On.R2.Work.Carried | Should -BeGreaterThan 100
        $script:On.R2.Work.Differences | Should -Be 0
        $script:On.R2.Staged | Should -Be $script:Full.R2.Staged
        Compare-Snap $script:FullSnap (Get-Snap $script:On.Db $script:On.C2) 'the build from what changed holds exactly the full build''s rows'
        # a finding whose TIER moved (its document did not) is never carried: its hash moved with it
        $moved = [long](& $script:On.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry AS k JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId WHERE f.RaSeq % 13 = 0 OR f.RaSeq % 10 = 0 OR f.RaSeq > 1000" @{} 'scalar')
        $moved | Should -Be 0
        # the record says why, per phase
        $runs = @(& $script:On.Db.Seam "SELECT Phase, CollectionId, Build, Outcome, Why, SampleSeed FROM sidata.ChangedSetRun ORDER BY ChangedSetRunId" @{} 'reader' | ForEach-Object { $_ })
        @($runs | Where-Object { [long]$_['CollectionId'] -eq $script:On.C2 -and $_['Build'] -eq 'changed-set' -and $_['Outcome'] -eq 'ok' }).Count | Should -Be 2
        @($runs | Where-Object { [long]$_['CollectionId'] -eq $script:On.C2 } | ForEach-Object { [int]$_['SampleSeed'] }) | Should -Be @(7, 7) -Because 'the sample''s seed is logged'
        # the hashes of the published collection and newer are kept; the rest go
        Clear-SIDataChangedSetOldHashes -Invoke $script:On.Db.Seam
        [long](& $script:On.Db.Seam "SELECT COUNT(DISTINCT CollectionId) FROM sidata.FindingHash" @{} 'scalar') | Should -Be 2
    }
    It 'an untrusted base, a version or settings change and the weekly rule each build in full' {
        $seam = $script:On.Db.Seam; $c2 = $script:On.C2
        $row = @(& $seam "SELECT TOP (1) Fingerprint FROM sidata.ChangedSetRun WHERE Phase = N'view-context' AND CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'reader' | ForEach-Object { $_ })[0]
        $fp = ([string]$row['Fingerprint']).Trim()
        $set = ([string](& $seam "SELECT HashSet FROM sidata.FindingHashState WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$c2 } 'scalar')).Trim()
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Build | Should -Be 'changed-set'
        $d = Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint ('0' * 64) -SetId $set
        $d.Build | Should -Be 'full'; $d.Why | Should -Match 'other settings'
        # #1331 the build fingerprint's parts recorded with the base name what moved
        $parts = ([string](& $seam "SELECT TOP (1) BuildParts FROM sidata.ChangedSetRun WHERE Phase = N'view-context' AND CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'scalar')).Trim()
        $parts | Should -Match '^m=[0-9A-F]{16};y=[0-9A-F]{16};t=[0-9A-F]{16};s=[0-9A-F]{16}$'
        $tMoved = $parts -replace 't=[0-9A-F]{16}', ('t=' + ('A' * 16))
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint ('0' * 64) -SetId $set -BuildParts $tMoved).Why | Should -Match 'the update changes what the build produces \(the template set\)'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint ('0' * 64) -SetId $set -BuildParts $parts).Why | Should -Match 'the field list or this phase''s own statement'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId 'ffffffffffffffff').Why | Should -Match 'no finding hashes for this field list'
        $null = & $seam "UPDATE sidata.PublishedRun SET [Partial] = 1" @{} 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Why | Should -Match 'partial'
        $null = & $seam "UPDATE sidata.PublishedRun SET [Partial] = 0" @{} 'nonquery'
        # #1331 the rolling check ran on every quick build since: no weekly full build, even 8 days after the last full one;
        # the part is the next one after the last run's (C2's runs took part 0)
        $null = & $seam "UPDATE sidata.ChangedSetRun SET StartedAt = DATEADD(day, -8, StartedAt) WHERE Build IN (N'full', N'shadow')" @{} 'nonquery'
        $dr = Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set
        $dr.Build | Should -Be 'changed-set' -Because $dr.Why
        $dr.RollSlot | Should -Be 1
        # ... the weekly full build is the fallback ONLY when the rolling check could not run (a quick build of the last 7 days ran without it)
        $null = & $seam "UPDATE sidata.ChangedSetRun SET RollingSlot = NULL WHERE Build = N'changed-set'" @{} 'nonquery'
        $dw = Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set
        $dw.Build | Should -Be 'full'; $dw.Why | Should -Match 'weekly full build is due .*the rolling full check could not run: 1 quick build'
        $dw.RollSlot | Should -BeNullOrEmpty
        $null = & $seam "UPDATE sidata.ChangedSetRun SET RollingSlot = 0 WHERE Build = N'changed-set'" @{} 'nonquery'
        $null = & $seam "UPDATE sidata.ChangedSetRun SET StartedAt = DATEADD(day, 8, StartedAt) WHERE Build IN (N'full', N'shadow')" @{} 'nonquery'
        # review (4): the web app's identity may write sidata.Collection -- a mark CLEARED (or the status changed) after the hashes
        # makes them stale, never fresher
        $keep = & $seam "SELECT CONVERT(nvarchar(40), DerivedAt, 126) FROM sidata.Collection WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'scalar'
        $null = & $seam "UPDATE sidata.Collection SET DerivedAt = NULL WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Why | Should -Match 'rewritten after their hashes'
        (Read-SIDataFindingHashState -Invoke $seam -CollectionId $script:On.C1 -SetId $set).Fresh | Should -BeFalse
        $null = & $seam "UPDATE sidata.Collection SET DerivedAt = CONVERT(datetime2(0), @d, 126) WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1; d = [string]$keep } 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Build | Should -Be 'changed-set' -Because 'the mark put back exactly as it was'
        $null = & $seam "UPDATE sidata.Collection SET Status = N'Loading' WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Build | Should -Be 'full'
        $null = & $seam "UPDATE sidata.Collection SET Status = N'Complete' WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'nonquery'
        # review (3): a real SQL error is recorded by its number, without the value it quotes
        $err = $null; try { $null = & $seam "SELECT CONVERT(int, N'secret-789')" @{} 'scalar' } catch { $err = $_ }
        $safe = Get-SIDataChangedSetSafeError $err
        $safe | Should -Match '^SQL error 245: '; $safe | Should -Not -Match 'secret-789'
        $null = & $seam "UPDATE sidata.Collection SET DerivedAt = DATEADD(minute, 5, SYSUTCDATETIME()) WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Why | Should -Match 'rewritten after their hashes'
        $null = & $seam "DELETE FROM sidata.PublishedRun" @{} 'nonquery'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'on' -Fingerprint $fp -SetId $set).Why | Should -Match 'nothing is published yet'
        (Resolve-SIDataChangedSetBuild -Invoke $seam -Phase 'view-context' -CollectionId $c2 -Mode 'off' -Fingerprint $fp -SetId $set).Build | Should -Be 'off'
    }
    It 'shadow: 0 differences when the published collection''s results are right -- the full build kept' {
        $script:ShadowClean = New-Scenario -Mode 'shadow'
        $vc2 = @($script:ShadowClean.R2.ViewContext.ChangedSet)[0]
        $vc2.Build | Should -Be 'shadow' -Because $vc2.Why
        $vc2.Compared | Should -BeGreaterThan 100
        $vc2.Differences | Should -Be 0
        $script:ShadowClean.R2.Work.Build | Should -Be 'shadow'
        $script:ShadowClean.R2.Work.Differences | Should -Be 0
        Compare-Snap $script:FullSnap (Get-Snap $script:ShadowClean.Db $script:ShadowClean.C2) 'shadow keeps the full build'
    }
    It 'shadow: more than 0 differences when they are forced wrong -- said with ids and column names only, and the full build kept' {
        $script:ShadowBad = New-Scenario -Mode 'shadow' -CorruptBase
        $vc2 = @($script:ShadowBad.R2.ViewContext.ChangedSet)[0]
        $vc2.Differences | Should -BeGreaterThan 0
        $vc2.Detail | Should -Match 'AffectedVendor'
        $vc2.Detail | Should -Not -Match 'not what the document says' -Because 'never a value'
        $script:ShadowBad.R2.Work.Differences | Should -BeGreaterThan 0
        $script:ShadowBad.R2.Work.Detail | Should -Match 'Component'
        Compare-Snap $script:FullSnap (Get-Snap $script:ShadowBad.Db $script:ShadowBad.C2) 'shadow keeps the full build even when the quick one is wrong'
        $iss = @(Get-SIDataSyncIssues -Result @{ ChangedSet = @($vc2, $script:ShadowBad.R2.Work) })
        @($iss | Where-Object { $_.Level -eq 'WARNING' -and $_.Text -match 'differed from the full build' }).Count | Should -Be 2
        [long](& $script:ShadowBad.Db.Seam "SELECT SUM(Differences) FROM sidata.ChangedSetRun WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:ShadowBad.C2 } 'scalar') | Should -BeGreaterThan 0
    }
    It 'on + a difference in the sample check: the run falls back to the full build before anything is published' {
        $script:OnBad = New-Scenario -Mode 'on' -CorruptBase -Pct 100
        $vc2 = @($script:OnBad.R2.ViewContext.ChangedSet)[0]
        $vc2.Differences | Should -BeGreaterThan 0
        $vc2.FellBack | Should -BeTrue
        $script:OnBad.R2.Work.Differences | Should -BeGreaterThan 0
        $script:OnBad.R2.Work.FellBack | Should -BeTrue
        Compare-Snap $script:FullSnap (Get-Snap $script:OnBad.Db $script:OnBad.C2) 'the fallback is the full build'
        $runs = @(& $script:OnBad.Db.Seam "SELECT Build, FellBack, Outcome FROM sidata.ChangedSetRun WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:OnBad.C2 } 'reader' | ForEach-Object { $_ })
        @($runs | Where-Object { $_['Build'] -eq 'full' -and [bool]$_['FellBack'] -and $_['Outcome'] -eq 'ok' }).Count | Should -Be 2
        $w = Get-SIDataChangedSetWarningText -Result $script:OnBad.R2.Work
        $w | Should -Match 'this run was built in full before anything was published'
        $script:OnBad.R2.Log | Should -Not -Match 'not what the document says'
    }
    It 'the first run after the update (nothing published) costs the build plus the hashes only: measured' {
        $hashMs = $script:On.R1.Ms - $script:Full.R1.Ms
        Write-Host ("first run: setting off {0} ms, on {1} ms (+{2} ms: the hashes and the records)" -f $script:Full.R1.Ms, $script:On.R1.Ms, $hashMs)
        Write-Host ("second run: setting off {0} ms, on {1} ms" -f $script:Full.R2.Ms, $script:On.R2.Ms)
        $script:On.R1.Ms | Should -BeLessThan ([long]($script:Full.R1.Ms * 3 + 15000))
    }
    It 'the hash: the same properties in another order and spacing give the same hash; a key named twice is never carried' {
        $seam = $script:On.Db.Seam
        $cid = [long](& $seam "INSERT sidata.Collection (CollectionTime, Kind, Status) VALUES ('2026-10-25T03:00:00', 'Detailed', 'Complete'); SELECT CONVERT(int, SCOPE_IDENTITY());" @{} 'scalar')
        $null = & $seam ("INSERT sidata.Finding (CollectionId, AssetKey, DetailJson) VALUES (@c, N'a', N'{""x"":1,""y"":""v"",""CollectionTime"":""t1""}'), (@c, N'a', N' {""y"" : ""v"", ""CollectionTime"":""t2"",""x"":1}'), " +
                            "(@c, N'a', N'{""x"":1,""x"":2,""y"":""v""}'), (@c, N'a', N'{""x"":1,""x"":2,""y"":""v""}'), (@c, N'a', N'{""x"":1,""y"":""w""}'), (@c, N'a', N'[1,2]'), (@c, N'a', NULL)") @{ c = $cid } 'nonquery'
        Reset-SIDataChangedSetRunState
        $null = Invoke-SIDataFindingHash -Invoke $seam -CollectionId $cid -Columns @('AssetKey') -SetId 'testset000000000'
        $h = @(& $seam "SELECT CONVERT(varchar(64), FindingHash, 2) AS H FROM sidata.FindingHash WHERE CollectionId = @c ORDER BY FindingId" @{ c = $cid } 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['H'] })
        $h.Count | Should -Be 7
        $h[1] | Should -Be $h[0] -Because 'the same properties, another order, other spacing, another run time'
        $h[3] | Should -Not -Be $h[2] -Because 'a document that names a key twice gets a hash of its own'
        $h[4] | Should -Not -Be $h[0]
        @($h | Select-Object -Unique).Count | Should -Be 6
    }
    It 'a failed delete of the published work rows is the full build (never a failure of the findings per CI)' {
        $script:DelFail = New-Scenario -Mode 'on' -Wrap { param($inner, $Sql, $Params, $Mode) if ([string]$Sql -match 'DELETE TOP \(50000\) FROM sidata\.CiFindingDbWork WHERE FindingId >=') { throw 'simulated: the delete failed' }; & $inner $Sql $Params $Mode }
        $script:DelFail.R2.Work.FellBack | Should -BeTrue
        $script:DelFail.R2.Work.Problem | Should -Match 'could not be checked'
        Compare-Snap $script:FullSnap (Get-Snap $script:DelFail.Db $script:DelFail.C2) 'a failed delete = the full build'
        (Get-SIDataChangedSetWarningText -Result $script:DelFail.R2.Work) | Should -Match 'built in full'
    }
    It 'a work-row count that does not come out is the full build' {
        $script:CountBad = New-Scenario -Mode 'on' -Wrap { param($inner, $Sql, $Params, $Mode) if ([string]$Sql -match 'COUNT_BIG\(\*\) AS W, COUNT_BIG\(DISTINCT FindingId\) AS D') { return , @(@{ W = -1L; D = -1L; O = 0 }) }; & $inner $Sql $Params $Mode }
        $script:CountBad.R2.Work.FellBack | Should -BeTrue
        Compare-Snap $script:FullSnap (Get-Snap $script:CountBad.Db $script:CountBad.C2) 'a wrong count = the full build'
    }
    It 'a resume mark of another quick build is not gone on from: the collection is filled from the start' {
        $script:Resume = New-Scenario -Mode 'on' -BeforeStep2 {
            param($db, $c1, $c2)
            $set = Get-SIViewFindingSetId -List $script:List
            $mid = [long](& $db.Seam 'SELECT MIN(FindingId) + 120 FROM sidata.Finding WHERE CollectionId = @c' @{ c = $c2 } 'scalar')
            $null = & $db.Seam (Get-SIDataContextMarkWriteSql) @{ Name = (Get-SIDataContextMarkName -CollectionId $c2 -SetId $set); Value = ('{0};cs;shadow;5;{1}' -f $mid, $c1) } 'nonquery'
        }
        @($script:Resume.R2.ViewContext.ChangedSet)[0].Build | Should -Be 'changed-set'
        Compare-Snap $script:FullSnap (Get-Snap $script:Resume.Db $script:Resume.C2) 'another quick build''s mark = filled from the start'
    }
    It 'published findings removed without a mark (a repair, a retention): not one for one -- the full build' {
        $script:BaseGone = New-Scenario -Mode 'on' -BeforeStep2 { param($db, $c1, $c2) $null = & $db.Seam 'DELETE FROM sidata.Finding WHERE CollectionId = @c AND RaSeq % 11 = 3' @{ c = $c1 } 'nonquery' }
        $vc = @($script:BaseGone.R2.ViewContext.ChangedSet)[0]
        $vc.Build | Should -Be 'full'; $vc.Why | Should -Match 'not one for one'
        $script:BaseGone.R2.Work.Build | Should -Be 'full'
        Compare-Snap $script:FullSnap (Get-Snap $script:BaseGone.Db $script:BaseGone.C2) 'the full build'
    }
    It '#1331 the rolling part in SQL is the same as worked out here; the 7 parts cover every CI of the collection exactly once; the runs record and log their part' {
        $seam = $script:On.Db.Seam
        $expr = Get-SIDataChangedSetRollExpr -Asset 'f.AssetKey'
        $rows = @(& $seam "SELECT DISTINCT f.AssetKey AS K, $expr AS S FROM sidata.Finding AS f WHERE f.CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C2 } 'reader' | ForEach-Object { $_ })
        $rows.Count | Should -BeGreaterThan 30
        foreach ($r in $rows) { [int]$r['S'] | Should -Be (Get-SIDataChangedSetRollPartOf -CiId ([string]$r['K'])) -Because ([string]$r['K']) }
        $all = @($rows | ForEach-Object { [string]$_['K'] })
        $covered = New-Object System.Collections.Generic.List[string]
        foreach ($s in 0..6) { $covered.AddRange([string[]]@($rows | Where-Object { [int]$_['S'] -eq $s } | ForEach-Object { [string]$_['K'] })) }
        $covered.Count | Should -Be $all.Count -Because 'each CI in exactly one part'
        @($covered | Select-Object -Unique).Count | Should -Be $all.Count
        # the second collection's quick builds took the first part (none before), recorded and logged
        $runs = @(& $seam "SELECT Phase, Build, RollingSlot FROM sidata.ChangedSetRun WHERE CollectionId = CONVERT(int, @c) ORDER BY ChangedSetRunId" @{ c = [string]$script:On.C2 } 'reader' | ForEach-Object { $_ })
        @($runs | ForEach-Object { if ($_['RollingSlot'] -is [System.DBNull]) { 'null' } else { [string]$_['RollingSlot'] } }) | Should -Be @('0', '0')
        @(& $seam "SELECT RollingSlot FROM sidata.ChangedSetRun WHERE CollectionId = CONVERT(int, @c)" @{ c = [string]$script:On.C1 } 'reader' | ForEach-Object { $_ } | Where-Object { -not ($_['RollingSlot'] -is [System.DBNull]) }).Count | Should -Be 0 -Because 'a build decided full records no part'
        $vc2 = @($script:On.R2.ViewContext.ChangedSet)[0]
        $vc2.RollSlot | Should -Be 0
        $vc2.RollCis | Should -BeGreaterThan 0
        $script:On.R2.Work.RollSlot | Should -Be 0
        $script:On.R2.Log | Should -Match 'the rolling full check builds part 1 of 7 of all CIs in full'
    }
    It '#1331 a forced difference in the ROTATED part (no random sample) = the run is built in full before anything is published, with the warning' {
        # the first part (0) of the fixture holds ci-6 and ci-7; their findings 81, 229, 265 are carried and forced wrong in the base
        @(0..36 | Where-Object { (Get-SIDataChangedSetRollPartOf -CiId "ci-$_") -eq 0 }).Count | Should -BeGreaterThan 0 -Because 'the fixture''s first part holds CIs'
        $script:RollBad = New-Scenario -Mode 'on' -CorruptBase -Pct 0
        $vc2 = @($script:RollBad.R2.ViewContext.ChangedSet)[0]
        $vc2.RollSlot | Should -Be 0
        $vc2.Compared | Should -BeGreaterThan 0 -Because 'the rotated part is compared even with no random sample'
        $vc2.Differences | Should -BeGreaterThan 0
        $vc2.FellBack | Should -BeTrue
        $script:RollBad.R2.Work.Differences | Should -BeGreaterThan 0
        $script:RollBad.R2.Work.FellBack | Should -BeTrue
        Compare-Snap $script:FullSnap (Get-Snap $script:RollBad.Db $script:RollBad.C2) 'a difference in the rotated part = the full build'
        (Get-SIDataChangedSetWarningText -Result $vc2) | Should -Match 'built in full before anything was published'
        @(Get-SIDataSyncIssues -Result @{ ChangedSet = @($vc2, $script:RollBad.R2.Work) } | Where-Object { $_.Level -eq 'WARNING' }).Count | Should -Be 2 -Because 'the fix-request path: the run carries the warning'
    }
    It '#1331 a changed template set between two runs = a full build, and the run says the template set moved' {
        $script:TplMoved = New-Scenario -Mode 'on' -BeforeStep2 {
            param($db, $c1, $c2)
            $null = & $db.Seam "IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg'); IF OBJECT_ID(N'cfg.Template') IS NULL CREATE TABLE cfg.Template (Kind NVARCHAR(32) NOT NULL, ItemKey NVARCHAR(128) NOT NULL, BodyJson NVARCHAR(MAX) NOT NULL, RetiredAt DATETIME2(0) NULL); INSERT cfg.Template (Kind, ItemKey, BodyJson) VALUES (N'report', N'r1', N'{""q"":1}');" @{} 'nonquery'
        }
        $vc2 = @($script:TplMoved.R2.ViewContext.ChangedSet)[0]
        $vc2.Build | Should -Be 'full'
        $vc2.Why | Should -Match 'the update changes what the build produces \(the template set\)'
        $script:TplMoved.R2.Work.Build | Should -Be 'full'
        $script:TplMoved.R2.Work.Why | Should -Match 'the template set'
        Compare-Snap $script:FullSnap (Get-Snap $script:TplMoved.Db $script:TplMoved.C2) 'the full build'
    }

    # #1354 (owner 2026-11-24, "Fix + history ON"): THE ROW'S WRITER is never in the finding hash -- the release that wrote a row
    # (RaRowSolutionVersion, the document's SolutionVersion) and how its insert typed it (TypedOnInsert, TypedStatement)
    Context '#1354 a release alone changes no finding hash' {
        BeforeAll {
            # the next collection = the previous one's findings as Risk Analysis writes them again under ANOTHER RELEASE: the same
            # seed-time columns, the run's time moved, the release and the insert's typing on every row; @Ch: one real change
            $script:Release = @'
DECLARE @src INT = CONVERT(int, @From);
DECLARE @t DATETIME2(3) = DATEADD(day, 1, (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @src));
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt) VALUES (@t, 'Detailed', 'Complete', DATEADD(minute, -30, SYSUTCDATETIME()));
DECLARE @dst INT = SCOPE_IDENTITY();
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, DetailJson, RaSeq, RaFindingKey, RaAssetId,
                       RaRowSolutionVersion, TypedOnInsert, TypedStatement)
SELECT @dst, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, CASE WHEN RaSeq = CONVERT(bigint, @Ch) THEN Title + N' (changed)' ELSE Title END, Severity, Tier, RiskScore, RiskScoreWeighted,
       JSON_MODIFY(JSON_MODIFY(DetailJson, N'$.CollectionTime', CONVERT(nvarchar(30), @t, 126)), N'$.SolutionVersion', @Ver),
       RaSeq, RaFindingKey, RaAssetId, @Ver, CONVERT(tinyint, 63), CONVERT(binary(16), HASHBYTES('MD5', @Ver))
FROM sidata.Finding WHERE CollectionId = @src ORDER BY FindingId;
SELECT @dst;
'@
            function script:Add-Release($Db, [long]$From, [string]$Ver, [long]$Ch = -1) {
                [long](@(& $Db.Seam $script:Release @{ From = [string]$From; Ver = $Ver; Ch = [string]$Ch } 'scalar') | Select-Object -Last 1)
            }
            # the findings of -Cid whose hash no finding of -Base has: the changed set
            function script:Get-Changed($Db, [long]$Cid, [long]$Base) {
                [long](& $Db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingHash AS n WHERE n.CollectionId = $Cid AND NOT EXISTS (SELECT 1 FROM sidata.FindingHash AS b WHERE b.CollectionId = $Base AND b.FindingHash = n.FindingHash)" @{} 'scalar')
            }
            # c2 = c1's findings under another release (the scenario's own second collection replaced by it)
            $script:AsRelease = { param($db, $c1, $c2) $null = & $db.Seam "DELETE FROM sidata.Finding WHERE CollectionId = CONVERT(int, @c); DELETE FROM sidata.Collection WHERE CollectionId = CONVERT(int, @c);" @{ c = [string]$c2 } 'nonquery'; $null = Add-Release $db $c1 '3.1.45+v3' }
            $script:AsReleaseOne = { param($db, $c1, $c2) $null = & $db.Seam "DELETE FROM sidata.Finding WHERE CollectionId = CONVERT(int, @c); DELETE FROM sidata.Collection WHERE CollectionId = CONVERT(int, @c);" @{ c = [string]$c2 } 'nonquery'; $null = Add-Release $db $c1 '3.1.45+v3' 5 }
            function script:New-ReleaseScenario([string]$Mode, [scriptblock]$Before) {
                $db = New-TestDb
                & $db.Seam $script:Schema @{} 'nonquery'
                & $db.Seam $script:SeedC1 @{} 'nonquery'
                $c1 = [long](& $db.Seam "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-19T03:00:00'" @{} 'scalar')
                Reset-SIDataChangedSetRunState
                $r1 = Invoke-Steps $db $Mode $c1 -1
                $null = & $db.Seam $script:Publish @{ c = [string]$c1 } 'nonquery'
                & $db.Seam $script:SeedC2 @{} 'nonquery'
                $c2x = [long](& $db.Seam "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-20T03:00:00'" @{} 'scalar')
                & $Before $db $c1 $c2x
                $c2 = [long](& $db.Seam "SELECT MAX(CollectionId) FROM sidata.Collection" @{} 'scalar')
                Reset-SIDataChangedSetRunState
                $r2 = Invoke-Steps $db $Mode $c2 -1
                [pscustomobject]@{ Db = $db; C1 = $c1; C2 = $c2; R1 = $r1; R2 = $r2 }
            }
        }
        It 'a release-only change (the same findings, another release and typing on every row): an empty changed set, every row the full build''s' {
            $script:RelFull = New-ReleaseScenario -Mode 'off' -Before $script:AsRelease
            $script:RelOn = New-ReleaseScenario -Mode 'on' -Before $script:AsRelease
            $vc2 = @($script:RelOn.R2.ViewContext.ChangedSet)[0]
            $vc2.Build | Should -Be 'changed-set' -Because $vc2.Why
            $vc2.Differences | Should -Be 0
            $script:RelOn.R2.Work.Build | Should -Be 'changed-set' -Because $script:RelOn.R2.Work.Why
            $script:RelOn.R2.Work.Differences | Should -Be 0
            [long](& $script:RelOn.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = $($script:RelOn.C2) AND RaRowSolutionVersion = N'3.1.45+v3' AND TypedOnInsert = 63 AND DetailJson LIKE N'%""SolutionVersion"":""3.1.45+v3""%'" @{} 'scalar') | Should -Be 300 -Because 'the writer moved on every row'
            Get-Changed $script:RelOn.Db $script:RelOn.C2 $script:RelOn.C1 | Should -Be 0 -Because 'a release alone changes no finding hash'
            $vc2.Carried | Should -BeGreaterThan 200
            Compare-Snap (Get-Snap $script:RelFull.Db $script:RelFull.C2) (Get-Snap $script:RelOn.Db $script:RelOn.C2) 'the served rows are the full build''s, byte for byte'
        }
        It 'one real change under a new release: exactly that finding in the changed set, every row the full build''s' {
            $full = New-ReleaseScenario -Mode 'off' -Before $script:AsReleaseOne
            $script:RelOne = New-ReleaseScenario -Mode 'on' -Before $script:AsReleaseOne
            $vc2 = @($script:RelOne.R2.ViewContext.ChangedSet)[0]
            $vc2.Build | Should -Be 'changed-set' -Because $vc2.Why
            $vc2.Differences | Should -Be 0
            Get-Changed $script:RelOne.Db $script:RelOne.C2 $script:RelOne.C1 | Should -Be 1
            [long](& $script:RelOne.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingHash AS n JOIN sidata.Finding AS f ON f.CollectionId = n.CollectionId AND f.FindingId = n.FindingId WHERE n.CollectionId = $($script:RelOne.C2) AND f.RaSeq = 5 AND NOT EXISTS (SELECT 1 FROM sidata.FindingHash AS b WHERE b.CollectionId = $($script:RelOne.C1) AND b.FindingHash = n.FindingHash)" @{} 'scalar') | Should -Be 1 -Because 'the changed one is the finding whose Title changed'
            [long](& $script:RelOne.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.ChangedSetCarry AS k JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId WHERE k.CollectionId = $($script:RelOne.C2) AND f.RaSeq = 5" @{} 'scalar') | Should -Be 0 -Because 'a changed finding is never carried'
            Compare-Snap (Get-Snap $full.Db $full.C2) (Get-Snap $script:RelOne.Db $script:RelOne.C2) 'the served rows are the full build''s, byte for byte'
            try { $full.Db.Cn.Dispose() } catch { }
        }
        It 'AN EXISTING INSTALL: hashes made under fh1 -- the first run after the update builds in full ONCE (as today''s first run after a release costs), every run after it from what changed' {
            $contract = Get-SIDataChangedSetContract
            $keep = @{ V = $contract.HashVersion; N = $contract.NotHashed; R = $contract.RunFields }
            $old = { $contract.HashVersion = 'fh1'; $contract.NotHashed = @($keep.N | Where-Object { $_ -notin 'RaRowSolutionVersion', 'TypedOnInsert', 'TypedStatement' }); $contract.RunFields = @($keep.R | Where-Object { $_ -ne 'SolutionVersion' }) }
            $new = { $contract.HashVersion = $keep.V; $contract.NotHashed = $keep.N; $contract.RunFields = $keep.R }
            $db = New-TestDb; $script:RelExisting = [pscustomobject]@{ Db = $db }
            & $db.Seam $script:Schema @{} 'nonquery'
            & $db.Seam $script:SeedC1 @{} 'nonquery'
            $c1 = [long](& $db.Seam "SELECT CollectionId FROM sidata.Collection WHERE CollectionTime = '2026-10-19T03:00:00'" @{} 'scalar')
            try {
                & $old
                Reset-SIDataChangedSetRunState; $null = Invoke-Steps $db 'on' $c1 -1
                $null = & $db.Seam $script:Publish @{ c = [string]$c1 } 'nonquery'
                # TODAY (fh1): a release alone -- every finding's hash differs, nothing is carried (the cost of a full build)
                $c2 = Add-Release $db $c1 '3.1.44+v3'
                Reset-SIDataChangedSetRunState; $r2 = Invoke-Steps $db 'on' $c2 -1
                @($r2.ViewContext.ChangedSet)[0].Build | Should -Be 'changed-set'
                Get-Changed $db $c2 $c1 | Should -Be 300 -Because 'under fh1 a release alone makes every finding changed (the defect)'
                $null = & $db.Seam $script:Publish @{ c = [string]$c2 } 'nonquery'
            } finally { & $new }
            # THE UPDATE (fh2): the published collection's hashes are of the old field list -> ONE full build, said
            $c3 = Add-Release $db $c2 '3.1.44.2+v3'
            Reset-SIDataChangedSetRunState; $r3 = Invoke-Steps $db 'on' $c3 -1
            $vc3 = @($r3.ViewContext.ChangedSet)[0]
            $vc3.Build | Should -Be 'full'; $vc3.Why | Should -Match 'no finding hashes for this field list'
            $r3.Work.Build | Should -Be 'full'
            $null = & $db.Seam $script:Publish @{ c = [string]$c3 } 'nonquery'
            # and from the next run on: a release alone = an empty changed set, built from what changed
            $c4 = Add-Release $db $c3 '3.1.45+v3'
            Reset-SIDataChangedSetRunState; $r4 = Invoke-Steps $db 'on' $c4 -1
            $vc4 = @($r4.ViewContext.ChangedSet)[0]
            $vc4.Build | Should -Be 'changed-set' -Because $vc4.Why
            $r4.Work.Build | Should -Be 'changed-set' -Because $r4.Work.Why
            $vc4.Differences | Should -Be 0; $r4.Work.Differences | Should -Be 0
            Get-Changed $db $c4 $c3 | Should -Be 0
        }
        AfterAll { foreach ($s in @($script:RelFull, $script:RelOn, $script:RelOne, $script:RelExisting)) { if ($s) { try { $s.Db.Cn.Dispose() } catch { } } } }
    }
}