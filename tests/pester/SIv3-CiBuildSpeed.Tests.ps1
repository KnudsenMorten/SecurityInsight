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
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    . (Join-Path $PSScriptRoot '_SIv3CiBuildSpeedSetup.ps1')
}

AfterAll { Restore-CiPerfSpeedGlobals }

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

    # (its two real-SQL cases are SIv3-CiBuildSpeedSql.Tests.ps1, its threads SIv3-CiBuildSpeedThreads.Tests.ps1 -- split 2026-11-08)
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
