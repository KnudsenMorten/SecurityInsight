#Requires -Version 5.1
<#
    THE CI BUILD MAKES THE SAME CIs, FASTER (2026-10-16, correlation speed: the asset-correlation step of a large install --
    ~100,000 directory objects, ~77,500 CIs -- took 4 h 47 min, and a rebuild of every CI after a build-version change ~520 s
    per 2,000 CIs). Almost all of it was the in-memory work per CI (assembling the fields, the rules, the risk factors, the
    classification), and most of THAT was PowerShell overhead: pipelines, a function call per compared value, the catalogs
    read again for every CI. engine/data-model was changed to do the same work with less of it.

      * THE SAME CIs: the build as it was (tests\fixtures\ci-perf\before\ci-build.d3b2fe9ed.txt, loaded under other names
        -- New-CiPerfBeforeWorld) and the build as it is run on the same synthetic tenant (tests\fixtures\ci-perf: real record
        capture and mapping, the shipped rules and catalogs) and must agree:
          - every shipped condition (rule, risk factor, coverage check, classification row) on every CI -- yes / no / unknown
            and a failure alike;
          - every CI document, database item, SI_CI_CL row and graph claim, built in memory;
          - the CIs written to the database by the whole build (real SQL Server; one build clock for both);
          - the identity ledger written by the correlation job (one statement now, one per anchor before).
      * THE THREADS SHARE THE RULES SAFELY: reading the same objects' properties for the first time on several threads at
        once failed ("Cannot index into a null array"); Initialize-SICiSharedObjects prepares them on one thread first.
      * FASTER: the CI core of the same CIs takes clearly less time than before (a generous bound -- a regression, not a
        benchmark).
      * A LARGE INSTALL'S SIZE (tag Scale -- on demand only, never in a gate): tests\fixtures\ci-perf\Measure-SICiBuildScale.ps1.
    PowerShell 7 (the runtime of every v3 job). The database cases run against the test VM's SQL Server Express and skip,
    saying so, where there is none.
#>

BeforeDiscovery {
    $script:IsPwsh = $PSVersionTable.PSVersion.Major -ge 7
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    if ($PSVersionTable.PSVersion.Major -lt 7) { return }
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    . (Join-Path $script:SIRoot 'tests\fixtures\ci-perf\CiPerfFixture.ps1')
    $script:World = New-CiPerfBeforeWorld -SIRoot $script:SIRoot -BeforeFile (Join-Path $script:SIRoot 'tests\fixtures\ci-perf\before\ci-build.d3b2fe9ed.txt')
    . ([scriptblock]::Create($script:World.Text))
    # one thread: the old enrichment's threads would load the CURRENT files (the threads are tested on their own below)
    $script:ParallelWas = $global:SI_CiParallel
    $global:SI_CiParallel = 'off'
    # #406 (CI build version 10): the build as it was had no time rule in its lifecycle -- with a seen window longer than any
    # record's age the designed lifecycle decides exactly what it decided (active / not seen / retired), so every other field
    # is compared as before; the lifecycle's own evidence (since, reason, days, a link's reason) is new and taken off
    # (Remove-CiPerfLifecycleEvidence). The time rule itself is SIv3-CiLifecycle.Tests.ps1.
    $script:SeenWas = $global:SI_Pro_CmdbSql_SeenWithinDays
    $global:SI_Pro_CmdbSql_SeenWithinDays = 100000
    function script:Remove-CiPerfLifecycleEvidence($docs) {
        foreach ($d in @($docs)) {
            if ($null -eq $d) { continue }
            foreach ($k in 'si_lifecycle_since', 'si_lifecycle_reason', 'si_not_seen_days') { if ($d.Contains($k)) { $d.Remove($k) } }
            foreach ($l in @($d['si_linked_objects'])) { if ($l -and $l.PSObject.Properties['reason']) { $l.PSObject.Properties.Remove('reason') } }
        }
    }
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:Rules = @(Get-SICiBuildRules -Log { param($l, $m) })
    # the records' times from the hour before now (the database build reads the last 30 days); the build's clock 5 minutes on
    $script:T = [datetime]::SpecifyKind([datetime]::UtcNow.Date.AddHours([datetime]::UtcNow.Hour), [DateTimeKind]::Utc).AddHours(-1)
    $script:Now = $script:T.AddMinutes(5)
    $script:Recs = @((Write-CiPerfTenant -Scale 0.005 -Model $script:Model -Collect -T $script:T).Rows)
    function script:Groups { $g = Get-SICiGroups -Records $script:Recs; @($g.Groups) }
    $script:Feeds = Get-SIFeedLatest -Records $script:Recs
    function script:Canon($x) { ConvertTo-CiPerfCanonicalJson (ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $x -Depth 20 -Compress) -AsHashtable) }
}

AfterAll { if ($PSVersionTable.PSVersion.Major -ge 7) { $global:SI_CiParallel = $script:ParallelWas; $global:SI_Pro_CmdbSql_SeenWithinDays = $script:SeenWas } }

Describe 'The CI build makes the same CIs as before its speed-up' -Skip:(-not $script:IsPwsh) {
    BeforeAll {
        # (both builds of the same CIs, timed: the speed case below reads the two times)
        # first both on a few CIs, so neither pays alone for what runs the first time (compiling, the kept patterns)
        $few = @(Groups | Select-Object -First 40)
        $null = Invoke-BeforeSICiCore -Groups $few -FeedLatest $script:Feeds -Ledger @{} -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now
        $null = Invoke-SICiCore -Groups $few -FeedLatest $script:Feeds -Ledger @{} -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $script:OldCore = Invoke-BeforeSICiCore -Groups (Groups) -FeedLatest $script:Feeds -Ledger @{} -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now -RunId 'speed'
        $script:OldSeconds = $sw.Elapsed.TotalSeconds; $sw.Restart()
        $script:NewCore = Invoke-SICiCore -Groups (Groups) -FeedLatest $script:Feeds -Ledger @{} -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now -RunId 'speed'
        $script:NewSeconds = $sw.Elapsed.TotalSeconds
        Remove-CiPerfLifecycleEvidence $script:NewCore.Docs
    }

    It 'loads the build as it was under other names, beside the current one' {
        (Get-Command -Name Test-BeforeSICondition -CommandType Function) | Should -Not -BeNullOrEmpty
        (Get-Command -Name Test-BeforeSICondition).ScriptBlock.ToString() | Should -Not -Match 'TWO TEXTS ARE COMPARED IN PLACE' -Because 'the old text, not the new one'
        (Get-Command -Name Invoke-BeforeSICiCore).ScriptBlock.ToString() | Should -Match 'New-BeforeSICiDocument'
        $script:Recs.Count | Should -BeGreaterThan 300
        @($script:NewCore.Docs | ForEach-Object { [string]$_['si_class'] } | Sort-Object -Unique) | Should -Be @('cloud_resource', 'device', 'identity')
    }

    It 'every shipped condition answers the same on every CI: rules, risk factors, coverage checks, classification rows' {
        $conds = New-Object System.Collections.Generic.List[object]
        foreach ($r in $script:Rules) { if ($null -ne $r.when) { $conds.Add([pscustomobject]@{ Where = "rule $($r.id)"; Classes = @($r.classes); C = $r.when }) } }
        foreach ($f in @($script:Model['risk-factors'].factors)) { if ($f -and $f.when) { $conds.Add([pscustomobject]@{ Where = "factor $($f.id)"; Classes = $null; C = $f.when }) } }
        foreach ($ck in @($script:Model['coverage-checks'].checks)) { if ($ck -and $ck.fail) { $conds.Add([pscustomobject]@{ Where = "check $($ck.id)"; Classes = $null; C = $ck.fail }) } }
        $idx = New-SIClassificationIndex -Dimensions $script:Model['dimensions'] -Classification $script:Model['classification']
        foreach ($t in @($idx.Targets)) { foreach ($r in $t.Rules) { if (-not $r.SourcePath) { $conds.Add([pscustomobject]@{ Where = "classification $($r.Id)"; Classes = $null; C = $r.Condition }) } } }
        $ctx = @{ Lists = (Merge-SIRiskFactorRanges -Lists (Get-SIDataModelListContext $script:Model)); Now = $script:Now }
        $answer = { param($sb) try { [string](& $sb) } catch { 'THROWS' } }
        $n = 0; $diff = New-Object System.Collections.Generic.List[string]
        $docs = @($script:NewCore.Docs)
        for ($i = 0; $i -lt $docs.Count; $i += 4) {
            $d = $docs[$i]; $cls = [string]$d['si_class']
            $unk = [string[]]@(@($d['si_unknown_fields']) | Where-Object { $_ })
            foreach ($c in $conds) {
                if ($null -ne $c.Classes -and @($c.Classes) -notcontains $cls) { continue }
                $n++
                $a1 = & $answer { Test-SICondition -Condition $c.C -Item $d -Context $ctx }
                $b1 = & $answer { Test-BeforeSICondition -Condition $c.C -Item $d -Context $ctx }
                $a2 = & $answer { $x = Test-SIConditionTri -Condition $c.C -Item $d -Context $ctx -UnknownFields $unk; if ($null -eq $x) { 'unknown' } else { $x } }
                $b2 = & $answer { $x = Test-BeforeSIConditionTri -Condition $c.C -Item $d -Context $ctx -UnknownFields $unk; if ($null -eq $x) { 'unknown' } else { $x } }
                if ($a1 -ne $b1 -or $a2 -ne $b2) { if ($diff.Count -lt 5) { $diff.Add(('{0} on {1}: now {2}/{3}, before {4}/{5}' -f $c.Where, $d['si_ci_id'], $a1, $a2, $b1, $b2)) } }
            }
        }
        Write-Host ('    {0:N0} condition evaluations compared ({1} conditions, {2} CIs)' -f $n, $conds.Count, [Math]::Ceiling($docs.Count / 4))
        $n | Should -BeGreaterThan 8000
        $diff | Should -HaveCount 0
    }

    It 'every CI comes out the same: its document, its database item, its SI_CI_CL row and its graph claims' {
        $new = @($script:NewCore.Docs); $old = @($script:OldCore.Docs)
        $new.Count | Should -Be $old.Count
        $new.Count | Should -BeGreaterThan 250
        for ($i = 0; $i -lt $new.Count; $i++) { (Canon $new[$i]) | Should -BeExactly (Canon $old[$i]) -Because ('CI {0}' -f $new[$i]['si_ci_id']) }
        ($script:NewCore.Minted, @($script:NewCore.Incomplete).Count) | Should -Be @($script:OldCore.Minted, @($script:OldCore.Incomplete).Count)
        $ni = ConvertTo-SICiSqlItems -Cis $new; $oi = ConvertTo-BeforeSICiSqlItems -Cis $old
        (Canon $ni.Cis) | Should -BeExactly (Canon $oi.Cis)
        (Canon $ni.Links) | Should -BeExactly (Canon $oi.Links)
        (Canon $ni.Map) | Should -BeExactly (Canon $oi.Map)
        (Canon @($ni.Post | ForEach-Object { $_.Row })) | Should -BeExactly (Canon @($oi.Post | ForEach-Object { $_.Row }))
        $rel = @(Get-SICiRelationRules -Model $script:Model)
        (Canon (ConvertTo-SICiGraphItems -Docs $new -Rules $rel -Only $null)) | Should -BeExactly (Canon (ConvertTo-BeforeSICiGraphItems -Docs $old -Rules $rel -Only $null))
    }

    It 'the field assembly gives the same answer for a CI of several records that disagree' {
        # a user seen by Entra and by Defender for Identity with different names, an old record and a fresh one
        $mk = { param($p, $k, $name, [datetime]$seen) [pscustomobject][ordered]@{ si_provider = $p; si_record_type = 'user'; si_class = 'identity'; si_record_key = "$p|user|$k"; si_collection_time = $script:T
                si_source_last_seen = $seen; si_collection_complete = $true; entra_object_id = 'u-1'; si_asset_name = $name; si_upn = $name; si_account_enabled = $true; si_onprem_synced = $true
                si_group_memberships = @("g-$p", 'g-shared') } }
        $recs = @((& $mk 'entra' 'u-1' 'ada@contoso.example' $script:T.AddHours(-2)), (& $mk 'mdi' 'u-1' 'ADA@contoso.example ' $script:T.AddDays(-40)), (& $mk 'ad' 'u-1' 'ada.lovelace@contoso.example' $script:T.AddHours(-1)))
        $feeds = Get-SIFeedLatest -Records $recs
        foreach ($set in @(@($recs[0]), @($recs[0], $recs[1]), $recs)) {
            $a = New-SICiDocument -CiId 'c-1' -Records $set -Catalog $script:Model['field-catalog'] -FeedLatest $feeds -Now $script:Now
            Remove-CiPerfLifecycleEvidence @($a)
            $b = New-BeforeSICiDocument -CiId 'c-1' -Records $set -Catalog $script:Model['field-catalog'] -FeedLatest $feeds -Now $script:Now
            (Canon $a) | Should -BeExactly (Canon $b)
        }
    }

    It 'the database holds the same CIs after the whole build, CI for CI (real SQL Server)' -Skip:(-not $script:HasSql) {
        $dbs = @()
        try {
            $digests = @{}
            foreach ($which in 'now', 'before') {
                $db = New-CiPerfDatabase -SIRoot $script:SIRoot -Prefix 'si_test_cispeed_'
                $dbs += $db
                $w = Write-CiPerfTenant -Scale 0.002 -Invoke $db.Seam -Model $script:Model -T $script:T
                $w.Failed | Should -Be 0
                $posted = New-Object System.Collections.Generic.List[object]
                $lc = & $db.NewEngineConn
                $bargs = @{ SqlInvoke = $db.Seam; LockOpen = $db.NewEngineConn; LedgerProvider = ([pscustomobject]@{ Kind = 'sql'; Connection = $lc }); Rules = $script:Rules; CmdbIndex = (New-SICiCmdbIndex)
                    Post = { param($Rows) foreach ($x in $Rows) { if ([string]$x.si_row_kind -eq 'full') { $posted.Add($x) } }; @($Rows).Count }.GetNewClosure(); LookbackDays = 30; WorkbookMaxCis = 0; RunId = 'speed'; BuildTime = $script:Now; Log = { param($l, $m) } }
                if ($which -eq 'now') { $r = Invoke-SICiBuild @bargs } else { $r = Invoke-BeforeSICiBuild @bargs }
                $r.Failed | Should -BeFalse -Because ([string]$r.Reason)
                $d = Get-CiPerfCiDigest -Invoke $db.Seam -Epoch $script:T -Volatile @('si_collection_time', 'si_run_id', 'si_ci_built', 'si_last_build', 'si_lifecycle_since', 'si_lifecycle_reason', 'si_not_seen_days')
                $rows = @(foreach ($p in ($posted | Sort-Object { [string]$_.si_ci_id })) { Canon $p })
                $digests[$which] = @{ Cis = $d; Posted = $rows; Count = $r.CiCount }
            }
            $digests['now'].Count | Should -Be $digests['before'].Count
            $cmp = Compare-CiPerfDigest -Before $digests['before'].Cis -After $digests['now'].Cis
            Write-Host ('    {0:N0} CIs compared in the database: {1} different, {2} only before, {3} only now' -f $cmp.Cis, $cmp.Different, $cmp.OnlyBefore, $cmp.OnlyAfter)
            foreach ($x in $cmp.Examples) { Write-Host ('    {0}: before {1} / now {2}' -f $x.CiId, $x.Before, $x.After) }
            $cmp.Same | Should -BeTrue
            ($digests['now'].Posted -join "`n") | Should -BeExactly ($digests['before'].Posted -join "`n")
        } finally { foreach ($db in $dbs) { Remove-CiPerfDatabase -Db $db } }
    }

    It 'the correlation job''s ledger write lands the same rows in one statement (real SQL Server)' -Skip:(-not $script:HasSql) {
        $groups = Groups
        $idy = Resolve-SIObjectIdentity -Groups $groups -Ledger @{} -Now $script:Now
        # a duplicate anchor (the last id written wins) and supersessions (the first new id written wins)
        $dec = @($idy.Decisions) + @([pscustomobject]@{ CorrelationId = 'dup'; NewIdentifiers = @([pscustomobject]@{ Type = 'AadObjectId'; Value = 'dup-1'; CorrelationId = 'first' }, [pscustomobject]@{ Type = 'AadObjectId'; Value = 'dup-1'; CorrelationId = 'second' }) })
        $sup = @([pscustomobject]@{ OldId = 'old-1'; NewId = 'new-a' }, [pscustomobject]@{ OldId = 'old-1'; NewId = 'new-b' }, [pscustomobject]@{ OldId = 'old-2'; NewId = 'new-c' })
        $dbs = @(); $content = @{}; $counts = @{}
        try {
            foreach ($which in 'now', 'before') {
                $db = New-CiPerfDatabase -SIRoot $script:SIRoot -Prefix 'si_test_cispeed_'
                $dbs += $db
                $cn = & $db.NewEngineConn
                if ($which -eq 'now') { $w = Save-SIObjectLedger -Connection $cn -Decisions $dec -Superseded $sup -Now $script:Now }
                else { $w = Save-BeforeSIObjectLedger -Connection $cn -Decisions $dec -Superseded $sup -Now $script:Now }
                $counts[$which] = '{0}/{1}' -f $w.AnchorsWritten, $w.SupersededWritten
                $rows = @(& $db.Seam 'SELECT IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen, LastSeen FROM si.ObjectIdentity ORDER BY IdentifierType, IdentifierValue' @{} 'rows')
                $s = @(& $db.Seam 'SELECT OldId, NewId, SupersededAt, Reason FROM si.ObjectIdentitySuperseded ORDER BY OldId' @{} 'rows')
                $content[$which] = (@($rows | ForEach-Object { '{0}|{1}|{2}|{3:o}|{4:o}' -f $_.IdentifierType, $_.IdentifierValue, $_.SI_CorrelationId, $_.FirstSeen, $_.LastSeen }) + @($s | ForEach-Object { 'SUP {0}|{1}|{2:o}|{3}' -f $_.OldId, $_.NewId, $_.SupersededAt, $_.Reason })) -join "`n"
            }
            $counts['now'] | Should -Be $counts['before']
            $content['now'] | Should -BeExactly $content['before']
            $content['now'] | Should -Match 'aadobjectid\|dup-1\|second|AadObjectId\|dup-1\|second'
            $content['now'] | Should -Match 'SUP old-1\|new-a'
        } finally { foreach ($db in $dbs) { Remove-CiPerfDatabase -Db $db } }
    }
}

Describe 'The enrichment''s threads share the rules and the catalogs safely' -Skip:(-not $script:IsPwsh) {
    It 'reads objects no thread has read before on 8 threads without a failure once they are prepared on one thread' {
        $fails = 0
        for ($r = 0; $r -lt 10; $r++) {
            $objs = @(1..2000 | ForEach-Object { '{"field":"f' + $_ + '","op":"eq","value":"x","any":null}' } | ConvertFrom-Json)
            $null = Initialize-SICiSharedObjects -Roots @(, $objs)
            $res = @(1..8 | ForEach-Object -ThrottleLimit 8 -Parallel {
                    try { foreach ($o in $using:objs) { foreach ($k in 'all', 'any', 'field', 'op', 'value') { $p = $o.PSObject.Properties[$k]; if ($p) { $null = $p.Value } } } } catch { 'ERR ' + $_.Exception.Message }
                })
            if (@($res | Where-Object { $_ -like 'ERR*' }).Count) { $fails++ }
        }
        $fails | Should -Be 0
    }

    It 'enriches on 4 threads exactly as on one' {
        # the CI documents before enrichment, twice over (the threads start from 500 CIs -- Get-SICiParallelism), in two copies
        $raw = New-Object System.Collections.Generic.List[object]
        $plan = @(Get-SICiFieldPlan -Catalog $script:Model['field-catalog'])
        foreach ($k in 1, 2) {
            $n = 0
            foreach ($g in (Groups)) {
                $n++
                $raw.Add((New-SICiDocument -CiId ('c{0}-{1}' -f $k, $n) -Records @($g.Members | ForEach-Object { $_.Record }) -Catalog $script:Model['field-catalog'] -FeedLatest $script:Feeds -Now $script:Now -FieldPlan $plan))
            }
        }
        $copy = { @(foreach ($x in $raw) { ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $x -Depth 20 -Compress) -AsHashtable }) }
        $a = & $copy; $b = & $copy
        $a.Count | Should -BeGreaterOrEqual 500
        $global:SI_CiParallel = 'off'
        $null = Invoke-SICiEnrichment -Cis $a -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now
        $global:SI_CiParallel = '4'
        try { $null = Invoke-SICiEnrichment -Cis $b -Model $script:Model -Rules $script:Rules -CmdbIndex (New-SICiCmdbIndex) -Now $script:Now }
        finally { $global:SI_CiParallel = 'off' }
        for ($i = 0; $i -lt $a.Count; $i++) { (Canon $b[$i]) | Should -BeExactly (Canon $a[$i]) }
    }
}
Describe 'The CI build is faster than before on the same CIs (a generous bound)' -Skip:(-not $script:IsPwsh) {
    It 'builds the same CIs in clearly less time than the build as it was' {
        # the two builds of the first block, on one thread each (its BeforeAll)
        Write-Host ('    MEASURE CI core, {0} records on one thread: before {1:N1} s, now {2:N1} s ({3:N1}x)' -f $script:Recs.Count, $script:OldSeconds, $script:NewSeconds, ($script:OldSeconds / [Math]::Max(0.001, $script:NewSeconds)))
        $script:NewSeconds | Should -BeGreaterThan 0
        $script:NewSeconds | Should -BeLessThan ($script:OldSeconds * 0.8)
    }
}
Describe 'The CI build at a large install''s size (on demand only)' -Tag 'Scale' -Skip:(-not $script:IsPwsh -or -not $script:HasSql) {
    It 'builds ~77,000 CIs from ~94,000 records and says how long each stage took' {
        $out = Join-Path ([IO.Path]::GetTempPath()) ('ci-scale-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.json')
        & (Join-Path $script:SIRoot 'tests\fixtures\ci-perf\Measure-SICiBuildScale.ps1') -SIRoot $script:SIRoot -Scale 1 -Cpus 2 -OutFile $out
        $r = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
        $r.PSObject.Properties['Error'] | Should -BeNullOrEmpty
        $r.Build.Failed | Should -BeFalse
        [int]$r.Build.CiCount | Should -BeGreaterThan 70000
    }
}
