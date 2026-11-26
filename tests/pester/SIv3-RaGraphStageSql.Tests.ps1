#Requires -Version 7.0
<#
    THE ATTACK-PATH GRAPH IN REAL SQL (REQUIREMENTS #1275 stage 2, engine\risk-analysis\_shared\RA-GraphPathStage.ps1), on the
    runner's SQL Server with the shipped schema, as the engine is granted (read + write, no DDL):
      * EQUIVALENCE, SYNTHETIC: a graph with every case the query's semantics turn on, read in parts and joined in SQL, gives
        exactly the paths an INDEPENDENT reading of the query's graph-match gives -- unsliced, at 3 and at 8 slices (each
        device in exactly one slice), for Detailed and for Summary.
      * EQUIVALENCE, RECORDED (internal, 2026-11-18, one graph snapshot; names and ids replaced by one-way tokens): the new
        path's rows against the rows today's query returned on that same input, column for column -- unsliced, with
        weights, at 8 slices (Detailed); per slice and unsliced (Summary). The scope picked for a row is checked by
        membership: it, and the one today's query gave, are both scopes of that row.
      * FAILURE: a part answered 504 twice is read as two halves; a part too large is split; a short read, or a graph that
        keeps changing, fails the load and leaves nothing behind; a graph that changed once is read again.
      * SCRATCH TABLES: an earlier run's graph (one that stopped half way) is swept by the next load of the same grain; the
        other grain's current graph is not touched; the run's end removes its own.
    Prints RAGS-EQUIV lines: rows compared and differences, for the report.
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    . (Join-Path $PSScriptRoot '_RaGraphStageTest.ps1')
    function script:Assert-RAGsPaths {
        <# The port's Detailed _Paths rows against the independent reference, set for set. Returns the rows compared. #>
        param([object[]]$Rows, [hashtable]$Ref, [hashtable]$IdOf)
        $vec = @{ 'entra-userCookie' = 'Entra session cookie'; 'azure-active-directory-app-secret' = 'AAD app secret'; 'azure-active-directory-user-credentials' = 'Cached AAD user credentials'
                  'azure-storage-shared-access-signature' = 'SAS token'; 'azure-storage-connection-string' = 'Storage connection string'; 'azure-database-connection-string' = 'DB connection string'
                  'azure-app-configuration-key' = 'App Configuration key'; 'github-personal-access-token' = 'GitHub PAT'; 'openai-api-key' = 'OpenAI API key'; 'user-azure-cli-secret' = 'Cached Azure CLI token' }
        $seen = @{}
        $nodes = @{}; foreach ($n in $script:CurNodes) { if (-not $nodes.ContainsKey($n.NodeId) -or $n._V) { $nodes[$n.NodeId] = $n } }
        foreach ($r in $Rows) {
            $key = $(if ($IdOf) { $IdOf[$r.EntryPointDeviceId] + '|' + $IdOf[$r.TargetAzureAssetId] } else { $r.EntryPointDeviceId + '|' + $r.TargetAzureAssetId })
            $Ref.ContainsKey($key) | Should -BeTrue -Because "the port found $key"
            $seen.ContainsKey($key) | Should -BeFalse -Because "$key is one row"
            $seen[$key] = $true
            $x = $Ref[$key]
            $pairs = @($x.Pairs | ForEach-Object { $i = $_.LastIndexOf('|'); @{ Lt = $_.Substring(0, $i); C = $nodes[$_.Substring($i + 1)] } })
            $expVec = @($pairs | ForEach-Object {
                $l = [string]$_.C.NodeLabel; $e = $_.Lt.ToLowerInvariant()
                if ($e -eq 'contains') { if ($vec.ContainsKey($l) -and @($vec.Keys | Where-Object { $_ -ceq $l }).Count) { $vec[$l] } else { 'Other secret: ' + $l } }
                elseif ($e -eq 'has credentials of') { 'Owner / cached credential' } elseif ($e -eq 'frequently logged in by') { 'Interactive logon' } else { $_.Lt } } | Sort-Object -Unique -CaseSensitive)
            @($r.EntryVectors | Sort-Object -CaseSensitive) | Should -Be @($expVec | Sort-Object -CaseSensitive)
            @($r.DeviceEdges | Sort-Object -CaseSensitive) | Should -Be @($pairs | ForEach-Object { $_.Lt } | Sort-Object -Unique -CaseSensitive)
            @($r.FirstHopLabels | Sort-Object -CaseSensitive) | Should -Be @($pairs | ForEach-Object { [string]$_.C.NodeLabel } | Sort-Object -Unique -CaseSensitive)
            @($r.ReachedIdentities | Sort-Object -CaseSensitive) | Should -Be @($x.Principals | Sort-Object -CaseSensitive)
            $creds = @($pairs | Where-Object { $_.C._Cats -contains 'secret' -and [string]$_.C.NodeName -ne '' } | ForEach-Object { [string]$_.C.NodeName } | Sort-Object -Unique -CaseSensitive)
            @($r.CredentialNodes).Count | Should -Be ([Math]::Min(10, $creds.Count))
            foreach ($c in @($r.CredentialNodes)) { $creds | Should -Contain $c }
            ($x.Scopes -contains ([string]$r.ViaRoleScope + '|' + [string]$r.ViaRoleScopeType)) | Should -BeTrue -Because 'the scope picked is a scope of this path'
            $r.MaxCvssScore | Should -Be $x.D.Cvss
        }
        $seen.Count | Should -Be $Ref.Count
        $seen.Count
    }
}

Describe 'the attack-path graph in SQL' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = New-RAGsDatabase
        $script:Stream = @{ Invoke = $script:Db.Seam; Grain = 'Detailed'; RunKey = 'Detailed|2026-11-18T02:00:00.000' }
        $script:G = New-RAGsGraph -Devices 40 -Seed 11
        $script:CurNodes = $script:G.Nodes
        $script:Ref = Get-RAGsReference -Graph $script:G
        function script:Count-Run([int]$RunNo) { [long](& $script:Db.Scalar "SELECT (SELECT COUNT_BIG(*) FROM sidata.RaGraphNode WHERE RunNo = $RunNo) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphEdge WHERE RunNo = $RunNo) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphCP WHERE RunNo = $RunNo) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphST WHERE RunNo = $RunNo)") }
    }
    AfterAll { Remove-RAGsDatabase $script:Db }
    BeforeEach { Reset-RAGsState }

    It 'gives exactly the query''s paths -- unsliced, at 3 and at 8 slices' {
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $script:G) -TargetRows 50 -Pause { }
        $set.Nodes | Should -Be $script:G.Nodes.Count; $set.Edges | Should -Be $script:G.Edges.Count
        $set.Parts | Should -BeGreaterThan 2
        $script:Ref.Count | Should -BeGreaterThan 50
        foreach ($n in 1, 3, 8) {
            $p = Get-RAGsSlicePaths -Stream $script:Stream -RunNo $set.RunNo -Count $n
            $c = Assert-RAGsPaths -Rows $p.Rows.ToArray() -Ref $script:Ref
            Write-Host ("RAGS-EQUIV synthetic Detailed paths at {0} slice(s): {1} rows compared with the independent reading, 0 different" -f $n, $c)
        }
        # the principal that is a vulnerable device: in another slice it is named now, where the query left it empty
        $p8 = Get-RAGsSlicePaths -Stream $script:Stream -RunNo $set.RunNo -Count 8
        $p8.OtherPart | Should -BeGreaterThan 0
        @($p8.Rows | Where-Object { $_.ReachedIdentities -contains 'PC-3' }).Count | Should -BeGreaterThan 0
    }
    It 'Summary: one row per device, target, first hop label and device edge, as the query''s match rows' {
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $script:G) -TargetRows 50 -Pause { }
        $p = Get-RAGsSlicePaths -Stream $script:Stream -RunNo $set.RunNo -Count 4 -Grain Summary
        $nodes = @{}; foreach ($n in $script:G.Nodes) { if (-not $nodes.ContainsKey($n.NodeId) -or $n._V) { $nodes[$n.NodeId] = $n } }
        $exp = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($k in $script:Ref.Keys) { foreach ($pr in $script:Ref[$k].Pairs) { $i = $pr.LastIndexOf('|'); [void]$exp.Add($k + '|' + $nodes[$pr.Substring($i + 1)].NodeLabel + '|' + $pr.Substring(0, $i)) } }
        $got = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($r in $p.Rows) { [void]$got.Add($r.EntryPointDeviceId + '|' + $r.TargetAzureAssetId + '|' + $r.FirstHopLabel + '|' + $r.DeviceEdge) }
        $got.SetEquals($exp) | Should -BeTrue
        $p.Rows.Count | Should -Be $exp.Count
        Write-Host ("RAGS-EQUIV synthetic Summary match rows at 4 slices: {0} compared, 0 different" -f $exp.Count)
    }
    It 'answers a rendered slice of the report end to end (rows, its count, its groups), and says the named principals once' {
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $script:G) -TargetRows 50 -Pause { }
        $script:RAStreamOn = $true; $script:RAStream = $script:Stream
        $link = New-RAGpsCiIndex -Key '_ciKey' -Columns @('_ciKey', 'si_ci_id', 'si_in_scope_') -Rows @()
        $peer = New-RAGpsCiIndex -Key '_peerKey' -Columns @('_peerKey', 'peer_tier') -Rows @()
        $q = Get-RAGsCatalogQuery Detailed
        $total = 0L
        for ($i = 0; $i -lt 8; $i++) {
            $plan = Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query $q -Count 8 -Index $i)
            $plan | Should -Not -BeNullOrEmpty
            $a = Invoke-RAGraphStageAnswer -Plan $plan -ReportName 'Detailed' -Link $link -Peer $peer
            $cnt = Invoke-RAGraphStageAnswer -Plan (Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query $q -Count 8 -Index $i -AsCount)) -Link $link -Peer $peer
            [long]$cnt._SIDirectRows[0].Count | Should -Be @($a._SIDirectRows).Count
            $total += @($a._SIDirectRows).Count
        }
        $total | Should -Be $script:Ref.Count
        $qs = Get-RAGsCatalogQuery Summary
        $g = Invoke-RAGraphStageAnswer -Plan (Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query $qs -AsCount -GroupKeys @('Subcategory', 'CriticalityTier'))) -Link $link
        @($g._SIDirectRows).Count | Should -Be 2   # storage account / Azure resource, no tier (no CI)
        Write-RAGraphStageNote; Write-RAGraphStageNote
        @($script:RAGsLog | Where-Object { $_ -match 'that are themselves vulnerable devices' }).Count | Should -Be 1
    }
    It '#1310: a WHOLE count is counted in the report''s slices -- the same number as one build of every path, and it beats after each slice' {
        # live at a large install 2026-11-22 (SUP-2026-00674): one build of the whole graph for the count took 7,039 s and wrote nothing
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $script:G) -TargetRows 50 -Pause { }
        $script:RAStreamOn = $true; $script:RAStream = $script:Stream
        $link = New-RAGpsCiIndex -Key '_ciKey' -Columns @('_ciKey', 'si_ci_id', 'si_in_scope_') -Rows @()
        $peer = New-RAGpsCiIndex -Key '_peerKey' -Columns @('_peerKey', 'peer_tier') -Rows @()
        $whole = Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query (Get-RAGsCatalogQuery Detailed) -AsCount)
        $whole | Should -Not -BeNullOrEmpty
        [long]$whole.Count | Should -Be 1
        # as before: no slices given -- one build of every path
        $script:RAGpsCountSlices = 0
        $one = [long](Invoke-RAGraphStageAnswer -Plan $whole -Link $link -Peer $peer)._SIDirectRows[0].Count
        $one | Should -Be $script:Ref.Count
        # the count asked whole while the report reads in 8 slices: counted slice by slice, the same number
        $beats = New-Object System.Collections.Generic.List[string]
        $sliced = Invoke-RAGraphStageSlicedCount -Plan $whole -Slices 8 -Link $link -Peer $peer -OnSlice { param($d, $t) $beats.Add(('{0}/{1}' -f $d, $t)) }.GetNewClosure() -Log { }
        [long]$sliced._SIDirectRows[0].Count | Should -Be $one
        @($beats) | Should -Be @(1..8 | ForEach-Object { '{0}/8' -f $_ })
        $script:RAGpsCountFromStage | Should -BeTrue
        # and the hook takes that way by itself when Invoke-RAReadCount has set the report's slices
        $script:RAGpsCountSlices = 8; $script:RAGpsCountFromStage = $false
        try { $hooked = [long](Invoke-RAGraphStageAnswer -Plan $whole -Link $link -Peer $peer)._SIDirectRows[0].Count } finally { $script:RAGpsCountSlices = 0 }
        $hooked | Should -Be $one
        $script:RAGpsCountFromStage | Should -BeTrue
        # a slice's own count, a row read and a group count are not touched by it
        $script:RAGpsCountSlices = 8
        try {
            $s3 = Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query (Get-RAGsCatalogQuery Detailed) -Count 8 -Index 3 -AsCount)
            $r3 = Get-RAGraphStagePlan -Query (Get-RAGsRendered -Query (Get-RAGsCatalogQuery Detailed) -Count 8 -Index 3)
            [long](Invoke-RAGraphStageAnswer -Plan $s3 -Link $link -Peer $peer)._SIDirectRows[0].Count | Should -Be @((Invoke-RAGraphStageAnswer -Plan $r3 -Link $link -Peer $peer)._SIDirectRows).Count
        } finally { $script:RAGpsCountSlices = 0 }
        Write-Host ("RAGS-EQUIV #1310 whole count in 8 slices: {0} = {1} (one build), 8 beats" -f [long]$sliced._SIDirectRows[0].Count, $one)
    }
    It 'a part answered 504 twice is read as two halves, and a part too large too -- every row once' {
        $first = @{}
        $hunt = New-RAGsHunt -Graph $script:G -OnPart {
            param($s, $m, $i, $c)
            if (-not $first.ContainsKey($s)) { $first[$s] = $m }
            if ($s -eq 'Edges' -and $m -eq $first[$s] -and $i -eq 0) { throw '504 Gateway Timeout' }
            if ($s -eq 'Nodes' -and $m -eq $first[$s] -and $i -eq 1) { throw 'advanced hunting returned 100000 rows -- its row limit, so the answer may be cut: Query execution has exceeded the allowed limits' }
        }.GetNewClosure()
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -TargetRows 50 -Pause { }
        $set.Nodes | Should -Be $script:G.Nodes.Count; $set.Edges | Should -Be $script:G.Edges.Count
        @($script:RAGsLog | Where-Object { $_ -match 'read as two halves' }).Count | Should -Be 2
        $p = Get-RAGsSlicePaths -Stream $script:Stream -RunNo $set.RunNo -Count 1
        $null = Assert-RAGsPaths -Rows $p.Rows.ToArray() -Ref $script:Ref
    }
    It 'a short read fails the load and leaves nothing behind' {
        $hunt = New-RAGsHunt -Graph $script:G -OnPart { param($s, $m, $i, $c) if ($s -eq 'Edges' -and $i -eq 0) { return , @() } }
        $e = $null; try { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -TargetRows 50 -Pause { } } catch { $e = $_ }
        Test-RALookupUnavailableError -Err $e | Should -BeTrue
        $e.Exception.Message | Should -Match 'could not be read whole'
        [long](& $script:Db.Scalar "SELECT COUNT_BIG(*) FROM sidata.RaGraphRun WHERE RunKey = N'$($script:Stream.RunKey)'") | Should -Be 0
        [long](& $script:Db.Scalar 'SELECT (SELECT COUNT_BIG(*) FROM sidata.RaGraphNode) + (SELECT COUNT_BIG(*) FROM sidata.RaGraphEdge)') | Should -Be 0
    }
    It 'a graph that changed once while it was read is read again; one that keeps changing fails' {
        $script:Bump = 1
        $hunt = New-RAGsHunt -Graph $script:G -CountDelta { param($s, $c) if ($s -eq 'Nodes' -and ($script:RAGsCalls -contains 'Nodes rows') -and $script:Bump -gt 0) { $script:Bump--; 1 } else { 0 } }
        $set = Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -TargetRows 50 -Pause { }
        $set.Nodes | Should -Be $script:G.Nodes.Count
        @($script:RAGsLog | Where-Object { $_ -match 'changed while it was read' }).Count | Should -Be 1
        Reset-RAGsState
        $hunt = New-RAGsHunt -Graph $script:G -CountDelta { param($s, $c) if ($s -eq 'Edges' -and ($script:RAGsCalls -contains 'Edges rows')) { 2 } else { 0 } }
        { Sync-RAGraphStage -Stream $script:Stream -Hunt $hunt -TargetRows 50 -Pause { } } | Should -Throw
    }
    It 'sweeps what an earlier run of the same grain left, keeps the other grain''s graph, and the run''s end removes its own' {
        $old = @{ Invoke = $script:Db.Seam; Grain = 'Detailed'; RunKey = 'Detailed|2026-11-17T02:00:00.000' }
        $sum = @{ Invoke = $script:Db.Seam; Grain = 'Summary'; RunKey = 'Summary|2026-11-18T02:00:00.000' }
        $a = Sync-RAGraphStage -Stream $old -Hunt (New-RAGsHunt -Graph $script:G) -Pause { }; Reset-RAGsState
        $b = Sync-RAGraphStage -Stream $sum -Hunt (New-RAGsHunt -Graph $script:G) -Pause { }; Reset-RAGsState
        (Count-Run $a.RunNo) | Should -BeGreaterThan 0
        $c = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $script:G) -Pause { }
        (Count-Run $a.RunNo) | Should -Be 0                                  # the stopped run of this grain
        (Count-Run $b.RunNo) | Should -BeGreaterThan 0                      # the other grain's run goes on
        @($script:RAGsLog | Where-Object { $_ -match 'an earlier run left in the database were removed' }).Count | Should -Be 1
        $script:RAStreamOn = $true; $script:RAStream = $script:Stream
        Complete-RAGraphStageRun
        (Count-Run $c.RunNo) | Should -Be 0
        [long](& $script:Db.Scalar "SELECT COUNT_BIG(*) FROM sidata.RaGraphRun WHERE RunNo = $($c.RunNo)") | Should -Be 0
    }
}

Describe 'the recorded input: the new path against today''s query, row for row' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $path = Join-Path $script:RAGsRoot 'tests\fixtures\ra-graph-stage\internal-ab.json.gz'
        $fs = [IO.File]::OpenRead($path); $gz = [IO.Compression.GZipStream]::new($fs, [IO.Compression.CompressionMode]::Decompress); $sr = [IO.StreamReader]::new($gz)
        try { $script:Fx = $sr.ReadToEnd() | ConvertFrom-Json -AsHashtable } finally { $sr.Dispose(); $gz.Dispose(); $fs.Dispose() }
        # advanced hunting writes a typed null as {} -- read as null, as the engine reads it
        $fix = { param($rows) foreach ($r in @($rows)) { if ($r -is [System.Collections.IDictionary]) { foreach ($k in @($r.Keys)) { if ($r[$k] -is [System.Collections.IDictionary] -and $r[$k].Count -eq 0) { $r[$k] = $null } } } } }
        foreach ($n in 'S1', 'OldDetailed', 'OldDetailedWeighted', 'OldDetailedSliced', 'OldSummary') { & $fix $script:Fx[$n] }
        foreach ($k in @($script:Fx.OldSummarySliced.Keys)) { & $fix $script:Fx.OldSummarySliced[$k] }
        $script:Db = New-RAGsDatabase
        $script:Stream = @{ Invoke = $script:Db.Seam; Grain = 'Detailed'; RunKey = 'Detailed|2026-11-18T03:00:00.000' }
        $graph = @{ Nodes = $script:Fx.S1; Edges = $script:Fx.S2 }
        Reset-RAGsState
        $script:Set = Sync-RAGraphStage -Stream $script:Stream -Hunt (New-RAGsHunt -Graph $graph) -Pause { }
        # an independent reading of the same graph (nodes by their key) for the scope membership
        $bits = { param($fl) $c = @(); if ($fl -band 1) { $c += 'secret' }; if ($fl -band 2) { $c += 'identity' }; if ($fl -band 4) { $c += 'environmentAzure' }; if ($fl -band 8) { $c += 'device' }; $c }
        $rg = @{ Nodes = @($script:Fx.S1 | ForEach-Object { [ordered]@{ NodeId = $_.K; NodeName = $_.NodeName; NodeLabel = $_.NodeLabel; Cvss = $_.Cvss; _Cats = (& $bits ([int]$_.Fl)); _V = (([int]$_.Fl -band 16) -eq 16) } })
                 Edges = @($script:Fx.S2 | ForEach-Object { [ordered]@{ _S = $_.S; _T = $_.T; _L = $($lt = [string]$_.Lt; switch ([int]$_.L) { 1 { 'has role on' } 2 { $lt } default { 'member of' } }) } }) }
        $script:CurNodes = $rg.Nodes
        $script:Ref = Get-RAGsReference -Graph $rg
        $script:KeyOf = @{}; foreach ($n in $script:Fx.S1) { $script:KeyOf[[string]$n.NodeId] = [string]$n.K }
        function script:New-Ci([hashtable]$Set, [string]$Key) { New-RAGpsCiIndex -Key $Key -Columns @($Set.Columns) -Rows @($Set.Rows | ForEach-Object { [pscustomobject]$_ }) }
        $script:LinkD = New-Ci $script:Fx.CiLinkDetailed '_ciKey'
        $script:Peer = New-Ci $script:Fx.CiPeer '_peerKey'
        $script:LinkS = New-Ci $script:Fx.CiLinkSummary '_ciKey'
        function script:Get-New([string]$Grain, [long]$Count, [long]$Index, $Weights) {
            $data = Get-RAGpsSliceData -Stream $script:Stream -RunNo $script:Set.RunNo -Count $Count -Index $Index
            $pr = ConvertTo-RAGpsPathRows -Data $data -Grain $Grain -Count $Count -Index $Index
            if ($Grain -eq 'Detailed') { $rows = ConvertTo-RAGpsDetailedRows -Paths $pr.Rows -Enrich $data.Enrich -Link $script:LinkD -Peer $script:Peer -Weights $Weights; $paths = $pr.Rows }
            else { $rows = ConvertTo-RAGpsSummaryRows -Paths $pr.Rows -Enrich $data.Enrich -Link $script:LinkS -Weights $Weights; $paths = $pr.Rows }
            @{ Rows = @($rows); Paths = @($paths) }
        }
        function script:Compare-Detailed([object[]]$New, [object[]]$Old, [object[]]$Paths) {
            # the scopes of each (device name, target name): every path of that name pair (for the scope membership)
            $scopesOf = @{}
            foreach ($p in $Paths) {
                $nk = [string]$p.EntryPointDevice + '|' + [string]$p.TargetAzureAsset
                if (-not $scopesOf.ContainsKey($nk)) { $scopesOf[$nk] = New-Object 'System.Collections.Generic.HashSet[string]' }
                $rk = $script:KeyOf[[string]$p.EntryPointDeviceId] + '|' + $script:KeyOf[[string]$p.TargetAzureAssetId]
                if ($script:Ref.ContainsKey($rk)) { foreach ($s in $script:Ref[$rk].Scopes) { [void]$scopesOf[$nk].Add($s) } }
            }
            $by = @{}
            foreach ($o in $Old) { $k = [string]$o.ConfigurationId + '|' + [string]$o.AssetId; if (-not $by.ContainsKey($k)) { $by[$k] = New-Object System.Collections.Generic.List[object] }; $by[$k].Add($o) }
            $diff = New-Object System.Collections.Generic.List[string]
            $scalar = 'SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'AssetName', 'AssetId', 'AssetType', 'SecuritySeverity', 'CriticalityTier', 'CriticalityTierLevel',
                      'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactor_Probability_Detailed', 'RiskFactorIds', 'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight',
                      'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'EntryPointDevice', 'TargetAzureAsset'
            foreach ($n in $New) {
                $k = [string]$n.ConfigurationId + '|' + [string]$n.AssetId
                if (-not $by.ContainsKey($k) -or $by[$k].Count -eq 0) { $diff.Add("only new: $k"); continue }
                $o = $by[$k][0]; $by[$k].RemoveAt(0)
                foreach ($c in $scalar) { if ([string]$n.$c -cne [string]$o[$c]) { $diff.Add(("{0}: {1} new '{2}' old '{3}'" -f $k, $c, $n.$c, $o[$c])) } }
                foreach ($c in 'Impact', 'MaxCvssScore') { if (($null -eq $n.$c) -ne ($null -eq $o[$c]) -or ($null -ne $n.$c -and [Math]::Abs([double]$n.$c - [double]$o[$c]) -gt 1e-9)) { $diff.Add("${k}: $c") } }
                foreach ($c in 'EntryVectors', 'ReachedIdentities') { if ((@($n.$c | Sort-Object -CaseSensitive) -join "`u{1f}") -cne (@($o[$c] | Sort-Object -CaseSensitive) -join "`u{1f}")) { $diff.Add("${k}: $c") } }
                $oc = @($o['CredentialNodes']); $nc = @($n.CredentialNodes)
                if ($oc.Count -lt 9) { if ((@($nc | Sort-Object -CaseSensitive) -join '|') -cne (@($oc | Sort-Object -CaseSensitive) -join '|')) { $diff.Add("${k}: CredentialNodes") } }
                $sc = $scopesOf[([string]$n.EntryPointDevice + '|' + [string]$n.TargetAzureAsset)]
                if ($null -eq $sc) { $sc = @() }
                if (-not ($sc -contains ([string]$n.ViaRoleScope + '|' + [string]$n.ViaRoleScopeType))) { $diff.Add("${k}: new scope not a scope of the path") }
                if (-not ($sc -contains ([string]$o['ViaRoleScope'] + '|' + [string]$o['ViaRoleScopeType']))) { $diff.Add("${k}: old scope not a scope of the path") }
            }
            foreach ($k in $by.Keys) { foreach ($x in $by[$k]) { $diff.Add("only old: $k") } }
            , $diff.ToArray()
        }
        function script:Compare-Summary([object[]]$New, [object[]]$Old) {
            $keyOf = { param($r, [switch]$H) $g = { param($c) if ($H) { $r[$c] } else { $r.$c } }; (@('SecurityDomain', 'Category', 'Subcategory', 'ConfigurationName', 'ConfigurationId', 'CriticalityTier', 'CriticalityTierLevel', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity') | ForEach-Object { [string](& $g $_) }) -join '|' }
            $by = @{}; foreach ($o in $Old) { $by[(& $keyOf $o -H)] = $o }
            $diff = New-Object System.Collections.Generic.List[string]
            if ($New.Count -ne $Old.Count) { $diff.Add(('rows: new {0} old {1}' -f $New.Count, $Old.Count)) }
            foreach ($n in $New) {
                $k = & $keyOf $n
                if (-not $by.ContainsKey($k)) { $diff.Add("only new: $k"); continue }
                $o = $by[$k]
                # AssetId is min() over the group's asset ids: the tokens of the recorded input do not keep the order of the
                # real ids, so both values are checked to be one of the group's asset ids (the new one is their ordinal minimum)
                $ids = @(@($n.ImpactedAssetPairs) | ForEach-Object { ([string]$_).Substring(([string]$_).IndexOf('|') + 1) })
                if ($ids -cnotcontains [string]$o['AssetId']) { $diff.Add("${k}: old AssetId not an asset of the group") }
                if ($ids -cnotcontains [string]$n.AssetId) { $diff.Add("${k}: new AssetId not an asset of the group") }
                foreach ($c in 'AssetType', 'SecuritySeverity', 'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskFactorIds', 'RiskScore_Weight_Detailed', 'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'ImpactedAssetCount', 'UniqueIssues') { if ([string]$n.$c -cne [string]$o[$c]) { $diff.Add(("{0}: {1} new '{2}' old '{3}'" -f $k, $c, $n.$c, $o[$c])) } }
                if (($null -eq $n.Impact) -ne ($null -eq $o['Impact']) -or ($null -ne $n.Impact -and [double]$n.Impact -ne [double]$o['Impact'])) { $diff.Add("${k}: Impact") }
                if ((@(([string]$n.AssetName) -split '; ' | Sort-Object -CaseSensitive) -join '|') -cne (@(([string]$o['AssetName']) -split '; ' | Sort-Object -CaseSensitive) -join '|')) { $diff.Add("${k}: AssetName") }
                if ((@(([string]$n.RiskFactor_Probability_Detailed) -split ';' | Sort-Object -CaseSensitive) -join '|') -cne (@(([string]$o['RiskFactor_Probability_Detailed']) -split ';' | Sort-Object -CaseSensitive) -join '|')) { $diff.Add("${k}: RiskFactor_Probability_Detailed") }
                foreach ($c in 'ImpactedAssetsList', 'ImpactedAssetPairs', 'IssueList') { if ((@($n.$c | Sort-Object -CaseSensitive) -join "`u{1f}") -cne (@($o[$c] | Sort-Object -CaseSensitive) -join "`u{1f}")) { $diff.Add("${k}: $c") } }
            }
            , $diff.ToArray()
        }
    }
    AfterAll { Remove-RAGsDatabase $script:Db }

    It 'read the recorded graph whole (the source counts)' {
        $script:Set.Nodes | Should -Be $script:Fx.S1.Count
        $script:Set.Edges | Should -Be $script:Fx.S2.Count
    }
    It 'Detailed, unsliced: every row and column as today''s query gave them' {
        $n = Get-New Detailed 1 0 $null
        $d = Compare-Detailed -New $n.Rows -Old @($script:Fx.OldDetailed) -Paths $n.Paths
        Write-Host ("RAGS-EQUIV recorded Detailed unsliced: {0} new rows, {1} rows today, {2} different{3}" -f $n.Rows.Count, $script:Fx.OldDetailed.Count, $d.Count, $(if ($d.Count) { ' -- ' + (($d | Select-Object -First 5) -join ' ; ') } else { '' }))
        $d.Count | Should -Be 0
        $n.Rows.Count | Should -Be $script:Fx.OldDetailed.Count
    }
    It 'Detailed with weights: the weight columns as today''s query computed them' {
        $w = $script:Fx.Weights
        $cfg = [pscustomobject]@{ Combine = $w.Combine; MaxMultiplier = [double]$w.MaxMultiplier; Fields = @($w.Fields | ForEach-Object { [pscustomobject]@{ field = $_.field; valueMap = [pscustomobject]$_.valueMap; default = $_.default } }) }
        $n = Get-New Detailed 1 0 $cfg
        $d = Compare-Detailed -New $n.Rows -Old @($script:Fx.OldDetailedWeighted) -Paths $n.Paths
        Write-Host ("RAGS-EQUIV recorded Detailed weighted: {0} rows compared, {1} different" -f $n.Rows.Count, $d.Count)
        $d.Count | Should -Be 0
    }
    It 'Detailed, 8 slices: together exactly today''s sliced rows' {
        $rows = New-Object System.Collections.Generic.List[object]; $paths = New-Object System.Collections.Generic.List[object]; $other = 0L
        for ($i = 0; $i -lt 8; $i++) { $n = Get-New Detailed 8 $i $null; foreach ($r in $n.Rows) { $rows.Add($r) }; foreach ($p in $n.Paths) { $paths.Add($p) } }
        $d = Compare-Detailed -New $rows.ToArray() -Old @($script:Fx.OldDetailedSliced) -Paths $paths.ToArray()
        Write-Host ("RAGS-EQUIV recorded Detailed 8 slices: {0} new rows, {1} rows today, {2} different" -f $rows.Count, $script:Fx.OldDetailedSliced.Count, $d.Count)
        $d.Count | Should -Be 0
    }
    It 'Summary: each slice''s groups and the unsliced groups as today''s query gave them' {
        $tot = 0
        for ($i = 0; $i -lt 8; $i++) {
            $n = Get-New Summary 8 $i $null
            $d = Compare-Summary -New $n.Rows -Old @($script:Fx.OldSummarySliced["$i"])
            if ($d.Count) { Write-Host ("RAGS-DIFF Summary slice {0}: {1}" -f $i, (($d | Select-Object -First 5) -join ' ; ')) }
            $d.Count | Should -Be 0
            $tot += $n.Rows.Count
        }
        $u = Get-New Summary 1 0 $null
        $d = Compare-Summary -New $u.Rows -Old @($script:Fx.OldSummary)
        Write-Host ("RAGS-EQUIV recorded Summary: {0} slice group rows and {1} unsliced groups compared, {2} different" -f $tot, $u.Rows.Count, $d.Count)
        $d.Count | Should -Be 0
    }
}
