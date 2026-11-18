#Requires -Version 7.0
<#
    THE ATTACK-PATH GRAPH AT SCALE (REQUIREMENTS #1275 stage 2; Tag 'Scale': on demand only, never in a gate). A synthetic
    Exposure Graph of about SI_RAGS_EDGES edges (default 5,000,000) and 690,000 nodes -- 200,000 devices (60,000 vulnerable),
    200,000 users in 10,000 groups, service principals, secrets, 40 subscriptions, 2,000 resource groups, 400,000 resources,
    edges to 200,000 nodes outside the node table -- generated part by part (never held whole), read through the port's
    loader in the parts it asks for, written to the runner's SQL Server, walked, and sliced 128 ways. Measured and printed
    (RAGS-SCALE lines): the time of each phase, the requests, the rows of each scratch table and their size, tempdb used by
    the walk and by one slice, the process's memory (the working set at its highest, the managed heap after the load).
    Asserted: every node and edge stored; the 128 slices together hold exactly the unsliced rows (each device in one slice);
    on two whole slices (about 940 vulnerable devices) every path equals an INDEPENDENT reading of the query's graph-match
    over the same generator (no SQL, no code of the port); the rest of the query runs on those slices.
    Run on the test runner:
      . ./SOLUTIONS/SecurityInsight/tests/pester/_SITestSql.ps1; Initialize-SITestSqlEnv
      Invoke-Pester -Path ./SOLUTIONS/SecurityInsight/tests/pester/SIv3-RaGraphStageScale.Tests.ps1 -TagFilter Scale -Output Detailed
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

Describe 'the attack-path graph at five million edges' -Tag 'Scale' -Skip:(-not $script:HasSql) {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_RaGraphStageTest.ps1')
        $f = 1.0; if ($env:SI_RAGS_EDGES -match '^\d+$') { $f = [double]$env:SI_RAGS_EDGES / 5000000.0 }
        # the node ordinals: [vulnerable devices][other devices][users][groups][service principals][secrets][subscriptions][resource groups][resources][outside the node table]
        $C = [ordered]@{ VD = [int](60000 * $f); PD = [int](140000 * $f); U = [int](200000 * $f); G = [int](10000 * $f); SP = [int](20000 * $f); SEC = [int](30000 * $f); SUB = 40; RG = 2000; RES = [int](400000 * $f); GH = [int](200000 * $f) }
        $script:Base = @{}; $o = 0; foreach ($k in $C.Keys) { $script:Base[$k] = $o; $o += $C[$k] }
        $script:N = $o; $script:C = $C
        $script:ResLabels = @('microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.compute/disks', 'microsoft.authorization/roleassignments')
        $script:SecLabels = @('azure-active-directory-app-secret', 'entra-userCookie', 'user-azure-cli-secret', 'some-new-secret-kind')
        function script:Rnd([long]$o, [long]$k, [long]$m) { [long](((($o * 2654435761) + ($k * 40503) + 12345) % 4294967291) % $m) }
        function script:Kind([long]$o) { foreach ($k in 'GH', 'RES', 'RG', 'SUB', 'SEC', 'SP', 'G', 'U', 'PD', 'VD') { if ($o -ge $script:Base[$k]) { return $k } } }
        function script:Ord([string]$k, [long]$i) { [long]$script:Base[$k] + $i }
        # every key once (the first 32 hex digits of SHA-256 over the id, as hash_sha256 gives it)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $script:Kx = [string[]]::new($script:N)
        for ($i = 0; $i -lt $script:N; $i++) { $script:Kx[$i] = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes("n$i"))).Substring(0, 32).ToLowerInvariant() }
        Write-Host ("RAGS-SCALE keys: {0:N0} in {1:N1}s" -f $script:N, $sw.Elapsed.TotalSeconds)
        function script:Out([long]$o) {
            # the edges leaving node o: @( @(target ordinal, label) )
            $k = Kind $o; $e = New-Object System.Collections.Generic.List[object]
            switch ($k) {
                { $_ -in 'VD', 'PD' } { for ($i = 0; $i -lt 4; $i++) { $e.Add(@((Ord 'U' (Rnd $o $i $script:C.U)), 'frequently logged in by')) }; if ((Rnd $o 9 2) -eq 0) { $e.Add(@((Ord 'SEC' (Rnd $o 10 $script:C.SEC)), 'contains')) } }
                'U' { for ($i = 0; $i -lt 10; $i++) { $e.Add(@((Ord 'G' (Rnd $o $i $script:C.G)), 'member of')) }; $e.Add(@((Ord 'GH' (Rnd $o 20 $script:C.GH)), 'member of'))
                      if ((Rnd $o 21 5) -eq 0) { $e.Add(@((Ord 'SP' (Rnd $o 22 $script:C.SP)), 'can authenticate as')) }
                      if ((Rnd $o 23 2) -eq 0) { $e.Add(@((Ord 'U' (Rnd $o 24 $script:C.U)), 'can authenticate as')) }
                      if ((Rnd $o 25 20) -eq 0) { $e.Add(@((Ord 'RES' (Rnd $o 26 $script:C.RES)), 'has role on')) } }
                'G' { for ($i = 0; $i -lt 2; $i++) { $e.Add(@((Ord 'G' (Rnd $o $i $script:C.G)), 'member of')) }
                      $gi = $o - $script:Base.G
                      if ($gi -lt 100) { $e.Add(@((Ord 'RES' (Rnd $o 30 $script:C.RES)), 'has role on')) } elseif ($gi -lt 102) { $e.Add(@((Ord 'RG' (Rnd $o 31 $script:C.RG)), 'has role on')) } }
                'SP' { $e.Add(@((Ord 'RES' (Rnd $o 40 $script:C.RES)), 'has role on')) }
                'SEC' { $e.Add(@((Ord 'SP' (Rnd $o 41 $script:C.SP)), 'can authenticate as')) }
                'SUB' { $si = $o - $script:Base.SUB; for ($i = 0; $i -lt 50; $i++) { $e.Add(@((Ord 'RG' ($si * 50 + $i)), 'contains')) } }
                'RG' { $ri = $o - $script:Base.RG; $per = [long][Math]::Floor($script:C.RES / $script:C.RG); for ($i = 0; $i -lt $per; $i++) { $e.Add(@((Ord 'RES' ($ri * $per + $i)), 'contains')) } }
                'RES' { for ($i = 0; $i -lt 3; $i++) { $e.Add(@((Ord 'RES' (Rnd $o (50 + $i) $script:C.RES)), 'contains')) } }
            }
            , $e
        }
        function script:Node([long]$o) {
            # the node row of o (the S1 row), $null when o is not in the node table
            $k = Kind $o
            if ($k -in 'PD', 'GH') { return $null }
            $cats = switch ($k) { 'VD' { if ($o % 7 -eq 0) { @('device', 'environmentAzure') } else { @('device') } } 'U' { @('identity') } 'G' { @('identity') } 'SP' { @('identity') } 'SEC' { @('secret') } default { @('environmentAzure') } }
            $label = switch ($k) { 'VD' { if ($o % 7 -eq 0) { 'microsoft.compute/virtualmachines' } else { 'device' } } 'U' { 'user' } 'G' { 'group' } 'SP' { 'serviceprincipal' } 'SEC' { $script:SecLabels[$o % 4] } 'SUB' { 'subscriptions' } 'RG' { 'resourcegroups' } default { $script:ResLabels[$o % 5] } }
            $fl = 0; if ($cats -contains 'secret') { $fl += 1 }; if ($cats -contains 'identity') { $fl += 2 }; if ($cats -contains 'environmentAzure') { $fl += 4 }; if ($cats -contains 'device') { $fl += 8 }
            if ($k -eq 'VD') { $fl += 16 }
            if ($label -eq 'microsoft.storage/storageaccounts') { $fl += 32 }; if ($label -in 'subscriptions', 'resourcegroups') { $fl += 64 }
            if ($label.StartsWith('microsoft.') -and -not $label.StartsWith('microsoft.authorization/')) { $fl += 128 }
            $dk = ''; $bh = $null; $rf = $null; $cv = $null
            if ($k -eq 'VD') { $dk = "mde-n$o"; $bh = Get-RAGsHash8 $dk; $rf = @('internet_exposed'); $cv = [double](5 + ($o % 5)) }
            @{ K = $script:Kx[$o]; NodeId = "n$o"; NodeName = "name$o"; NodeLabel = $label; Fl = $fl; DeviceKey = $dk; RiskFactorSet = $rf; Cvss = $cv; Bh = $bh; _Cats = $cats; _V = ($k -eq 'VD') }
        }
        $script:Sources = [long]$script:Base.GH     # every node but those outside the node table has edges to give
        $sw.Restart(); $script:EdgeTotal = 0L
        for ($o = 0L; $o -lt $script:Sources; $o++) { $script:EdgeTotal += (Out $o).Count }
        $script:NodeTotal = 0L; foreach ($k in 'VD', 'U', 'G', 'SP', 'SEC', 'SUB', 'RG', 'RES') { $script:NodeTotal += $script:C[$k] }
        $script:NodeTotal += [long][Math]::Ceiling($script:C.VD / 7.0)   # the VM's second row (the Azure node table) -- see Node rows below
        Write-Host ("RAGS-SCALE graph: {0:N0} edges, {1:N0} node rows, counted in {2:N1}s" -f $script:EdgeTotal, $script:NodeTotal, $sw.Elapsed.TotalSeconds)
        # the node ordinals that give node rows, the VMs twice (their vulnerable-device row and their Azure row)
        $script:NodeOrds = New-Object System.Collections.Generic.List[long]
        for ($o = 0L; $o -lt $script:Sources; $o++) { $k = Kind $o; if ($k -ne 'PD') { $script:NodeOrds.Add($o); if ($k -eq 'VD' -and $o % 7 -eq 0) { $script:NodeOrds.Add(-$o - 1) } } }
        $script:Hunt = {
            param($Kql)
            $edges = $Kql.TrimStart().StartsWith('ExposureGraphEdges')
            if ($Kql -match '\| count$') { return , @(@{ Count = $(if ($edges) { $script:EdgeTotal } else { [long]$script:NodeOrds.Count }) }) }
            $mod = 1L; $idx = 0L; $m = [regex]::Match($Kql, '\) % (?<n>\d+)\) == (?<i>\d+)'); if ($m.Success) { $mod = [long]$m.Groups['n'].Value; $idx = [long]$m.Groups['i'].Value }
            $out = New-Object System.Collections.Generic.List[object]
            if ($edges) {
                for ($o = $idx; $o -lt $script:Sources; $o += $mod) {
                    foreach ($x in (Out $o)) { $low = $x[1]; $L = 3; if ($low -eq 'has role on') { $L = 1 } elseif ($low -in 'contains', 'has credentials of', 'frequently logged in by') { $L = 2 }
                                              $out.Add(@{ S = $script:Kx[$o]; T = $script:Kx[$x[0]]; L = $L; Lt = $(if ($L -eq 2) { $low } else { '' }) }) }
                }
            } else {
                for ($j = $idx; $j -lt $script:NodeOrds.Count; $j += $mod) {
                    $oo = $script:NodeOrds[[int]$j]
                    if ($oo -ge 0) { $n = Node $oo; $h = @{}; foreach ($k in $n.Keys) { if (-not $k.StartsWith('_')) { $h[$k] = $n[$k] } }; $out.Add($h) }
                    else { $n = Node (-$oo - 1); $out.Add(@{ K = $n.K; NodeId = $n.NodeId; NodeName = $n.NodeName; NodeLabel = $n.NodeLabel; Fl = ($n.Fl - 16); DeviceKey = ''; RiskFactorSet = $null; Cvss = $null; Bh = $null }) }
                }
            }
            , $out.ToArray()
        }
        $script:Db = New-RAGsDatabase -Prefix 'si_test_gpsscale_'
        $script:Stream = @{ Invoke = $script:Db.Seam; Grain = 'Detailed'; RunKey = 'Detailed|2026-11-18T04:00:00.000' }
        # tempdb pages this connection allocated so far (the engine's grant cannot read the view: read as the test login, then back)
        function script:Tempdb() { try { [long](& $script:Db.Scalar "REVERT; DECLARE @mb bigint = (SELECT (user_objects_alloc_page_count + internal_objects_alloc_page_count) * 8 / 1024 FROM sys.dm_db_session_space_usage WHERE session_id = @@SPID); EXECUTE AS USER = N'si_engine'; SELECT @mb;") } catch { -1L } }
    }
    AfterAll { Remove-RAGsDatabase $script:Db }

    It 'reads it once in parts, walks it, slices it 128 ways losslessly, and gives the query''s paths on two whole slices' {
        Reset-RAGsState
        [GC]::Collect(); $heap0 = [GC]::GetTotalMemory($true)
        $tb = Tempdb
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt $script:Hunt -Pause { }
        $load = $sw.Elapsed.TotalSeconds
        $tw = (Tempdb) - $tb
        [GC]::Collect(); $heap1 = [GC]::GetTotalMemory($true)
        $set.Nodes | Should -Be $script:NodeOrds.Count
        $set.Edges | Should -Be $script:EdgeTotal
        Write-Host ("RAGS-SCALE load: {0:N0} nodes, {1:N0} edges, {2} parts, {3} requests, {4:N1}s (read, written, walked); credential->principal {5:N0}, scope->target {6:N0}" -f $set.Nodes, $set.Edges, $set.Parts, $set.Calls, $load, $set.Cp, $set.St)
        Write-Host ("RAGS-SCALE tempdb: {0:N0} MB allocated by the load and the walk (this session); managed heap after the load {1:N0} MB above the start (the test's own key table is outside it)" -f $tw, (($heap1 - $heap0) / 1MB))
        foreach ($t in 'RaGraphNode', 'RaGraphEdge', 'RaGraphCP', 'RaGraphST') {
            $r = (Get-RAGpsRows (& $script:Db.Seam "EXEC sp_spaceused N'sidata.$t'" @{} 'reader'))[0]
            Write-Host ("RAGS-SCALE table {0}: {1} rows, reserved {2}" -f $t, $r['rows'], $r['reserved'])
        }
        # 128 slices together = the whole (each device in one slice), counted in SQL
        $q1 = Get-RAGpsSliceSql -RunNo $set.RunNo -Count 1 -Index 0
        $whole = 0L
        $null = & $script:Db.Seam '' @{} 'session' { param($Run) $null = & $Run $q1.Build 'nonquery'; $script:WholeDT = [long](& $Run 'SELECT COUNT_BIG(*) FROM (SELECT DISTINCT D, T FROM #x) AS q;' 'scalar'); $null = & $Run $q1.Done 'nonquery' }
        $whole = $script:WholeDT
        $sum = 0L; $sw.Restart(); $ts = 0L
        for ($i = 0; $i -lt 128; $i++) {
            $qi = Get-RAGpsSliceSql -RunNo $set.RunNo -Count 128 -Index $i
            $null = & $script:Db.Seam '' @{} 'session' { param($Run) $null = & $Run $qi.Build 'nonquery'; $script:SliceDT = [long](& $Run 'SELECT COUNT_BIG(*) FROM (SELECT DISTINCT D, T FROM #x) AS q;' 'scalar'); $null = & $Run $qi.Done 'nonquery' }
            $sum += $script:SliceDT
        }
        Write-Host ("RAGS-SCALE slices: {0:N0} paths unsliced, {1:N0} in 128 slices together ({2:N1}s for the 128 slice joins in SQL)" -f $whole, $sum, $sw.Elapsed.TotalSeconds)
        $sum | Should -Be $whole
        $whole | Should -BeGreaterThan 100000
        # two whole slices against the independent reading of the generator
        $script:CurNodes = @()
        foreach ($i in 0, 64) {
            $sw.Restart(); $t0 = Tempdb
            $data = Get-RAGpsSliceData -Stream $script:Stream -RunNo $set.RunNo -Count 128 -Index $i
            $pr = ConvertTo-RAGpsPathRows -Data $data -Grain Detailed -Count 128 -Index $i
            $sliceSql = $sw.Elapsed.TotalSeconds
            $rows = ConvertTo-RAGpsDetailedRows -Paths $pr.Rows -Enrich $data.Enrich -Link (New-RAGpsCiIndex -Key '_ciKey' -Rows @()) -Peer (New-RAGpsCiIndex -Key '_peerKey' -Rows @()) -Weights $null
            $tail = $sw.Elapsed.TotalSeconds - $sliceSql
            # the reference: every vulnerable device of this slice, walked over the generator itself
            $devs = @(0..($script:C.VD - 1) | ForEach-Object { Ord 'VD' $_ } | Where-Object { ((Get-RAGsHash8 "mde-n$_") % 128) -eq $i })
            $ref = @{}
            foreach ($d in $devs) {
                foreach ($e1 in (Out $d)) {
                    $c = Node $e1[0]; if ($null -eq $c -or -not (($c._Cats -contains 'secret') -or ($c._Cats -contains 'identity'))) { continue }
                    $ps = New-Object 'System.Collections.Generic.HashSet[long]'; [void]$ps.Add($e1[0]); $front = @($e1[0])
                    for ($s = 1; $s -le 3; $s++) { $nx = New-Object 'System.Collections.Generic.HashSet[long]'; foreach ($x in $front) { if ((Kind $x) -ne 'GH') { foreach ($y in (Out $x)) { [void]$nx.Add($y[0]) } } }; foreach ($x in $nx) { [void]$ps.Add($x) }; $front = @($nx) }
                    foreach ($p in $ps) {
                        if ((Kind $p) -eq 'GH') { continue }
                        foreach ($rl in (Out $p)) {
                            if ($rl[1] -ne 'has role on') { continue }
                            $sc = Node $rl[0]
                            $ts = New-Object 'System.Collections.Generic.HashSet[long]'; [void]$ts.Add($rl[0]); $front = @($rl[0])
                            for ($s = 1; $s -le 2; $s++) { $nx = New-Object 'System.Collections.Generic.HashSet[long]'; foreach ($x in $front) { if ((Kind $x) -ne 'GH') { foreach ($y in (Out $x)) { [void]$nx.Add($y[0]) } } }; foreach ($x in $nx) { [void]$ts.Add($x) }; $front = @($nx) }
                            foreach ($t in $ts) {
                                $tn = Node $t; if ($null -eq $tn -or $tn._Cats -notcontains 'environmentAzure') { continue }
                                $ok = ($tn.NodeLabel -eq 'microsoft.storage/storageaccounts') -or ($sc -and $sc.NodeLabel -in 'subscriptions', 'resourcegroups' -and $tn.NodeLabel.StartsWith('microsoft.') -and -not $tn.NodeLabel.StartsWith('microsoft.authorization/'))
                                if (-not $ok) { continue }
                                $key = "n$d|n$t"
                                if (-not $ref.ContainsKey($key)) { $ref[$key] = @{ P = (New-Object 'System.Collections.Generic.HashSet[string]'); E = (New-Object 'System.Collections.Generic.HashSet[string]') } }
                                $pn = Node $p; [void]$ref[$key].P.Add($(if ($pn) { $pn.NodeName } else { '' })); [void]$ref[$key].E.Add($e1[1])
                            }
                        }
                    }
                }
            }
            $got = @{}; foreach ($r in $pr.Rows) { $got[$r.EntryPointDeviceId + '|' + $r.TargetAzureAssetId] = $r }
            $bad = 0
            foreach ($k in $ref.Keys) {
                if (-not $got.ContainsKey($k)) { $bad++; continue }
                $g = $got[$k]
                if ((@($g.ReachedIdentities | Sort-Object) -join '|') -ne (@($ref[$k].P | Sort-Object) -join '|')) { $bad++ }
                if ((@($g.DeviceEdges | Sort-Object) -join '|') -ne (@($ref[$k].E | Sort-Object) -join '|')) { $bad++ }
            }
            Write-Host ("RAGS-SCALE slice {0}/128: {1:N0} devices, {2:N0} paths (reference {3:N0}), {4} different; SQL + paths {5:N1}s, rest of the query {6:N1}s ({7:N0} rows/s), tempdb {8:N0} MB" -f $i, $devs.Count, $pr.Rows.Count, $ref.Count, $bad, $sliceSql, $tail, ($rows.Count / [Math]::Max(0.001, $tail)), ((Tempdb) - $t0))
            $bad | Should -Be 0
            $pr.Rows.Count | Should -Be $ref.Count
            $rows.Count | Should -Be $pr.Rows.Count
        }
        $peak = [Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64
        Write-Host ("RAGS-SCALE memory: working set at its highest {0:N0} MB (the whole test process, the generator's key table of {1:N0} keys included)" -f ($peak / 1MB), $script:N)
        $script:RAStreamOn = $true; $script:RAStream = $script:Stream
        Complete-RAGraphStageRun
        [long](& $script:Db.Scalar 'SELECT (SELECT COUNT_BIG(*) FROM sidata.RaGraphNode) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphEdge) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphCP) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphST)') | Should -Be 0
    }
}
