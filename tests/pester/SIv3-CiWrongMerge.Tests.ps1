#Requires -Version 5.1
<#
    #642 -- ONE CI ID FOR SEVERAL OBJECTS (found read-only at a ring 1 install 2026-10-13).

    Every batch of the CI build warned "N group(s) of batch B resolved to an id another group of it already has -- kept
    once". One ledger id held 11 DIFFERENT service principals (one Defender service principal per subscription, all with the
    same display name): 11 object ids, 11 app ids, 11 Exposure Graph nodes, all written in one run. Their records share no
    identifier. The cause: the identity Exposure Graph enrichment matched a node BY DISPLAY NAME (first node of the name
    wins) and handed its node id -- a strong identifier -- to every same-named service principal, so the correlation fused
    them and the ledger kept the fusion. The CI build then kept the first group of a batch and rewrote the same id in every
    batch, so the CI ended with only the last group's two links.

    Proven here:
      * distinct service principals with one name stay distinct (no name ever gives a node id; a name two nodes share is no key)
      * an existing wrong merge is split ONCE -- the object the id was minted from keeps it -- and not again on the next run
      * a split needs proof (two types an object holds once, other values written in the same run): a single shared type
        or values written in different runs are never split
      * the CI build never keeps one group and drops the others: an id several groups share is built once from all their
        records, and the build says so as a warning with counts in its run record
      * a cloud CI's last seen is filled (sidata.Ci.LastSeen was empty for every cloud CI)
    The real-SQL test runs against the local SQL Server Express of the test VM and skips, saying so, where there is none.
#>

BeforeDiscovery {
    $script:HasSql = [bool]((Get-Command sqlcmd -ErrorAction SilentlyContinue) -and (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running'))
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1')
    if (-not (Get-Command -Name Sort-SIOrdinal -ErrorAction SilentlyContinue)) { . (Join-Path $script:SIRoot 'engine\_shared\SI-AssetIdentity.ps1') }
    $script:Model = Get-SIDataModel -Root (Join-Path $script:SIRoot 'data-model')
    $script:T = [datetime]::SpecifyKind([datetime]'2026-10-12T21:40:27', [DateTimeKind]::Utc)

    # the pure functions of the collect stage, lifted from the engine file by AST (the shipped code, not a copy)
    $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1'))
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
    foreach ($name in 'Find-SIIdentityEgHit', 'Get-SIIdentityEgFields') {
        $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
        if (-not $fn) { throw "function $name not found in Invoke-Collect.ps1" }
        . ([scriptblock]::Create($fn.Extent.Text))
    }

    function script:Id([string]$t, [string]$v) { [pscustomobject]@{ Type = $t; Value = $v } }
    # one service principal = one group: its object id, app id and Exposure Graph node
    function script:SpGroup([int]$i) {
        [pscustomobject]@{ Members = @([pscustomobject]@{ Engine = 'identity'; SIAssetId = "sp$i"; Identifiers = @((Id 'AadObjectId' "o$i"), (Id 'AadAppId' "a$i"), (Id 'ExposureGraphNodeId' "n$i")) }) }
    }
    # THE RING 1 SHAPE: every anchor of N service principals under ONE id, minted from the first one's node, all in one run
    function script:WrongLedger([int]$N, [datetime]$At = $script:T) {
        $x = (New-SIObjectUuidV5 -Name 'exposuregraphnodeid|n1').ToString()
        $l = @{}
        for ($i = 1; $i -le $N; $i++) {
            foreach ($k in "aadobjectid|o$i", "aadappid|a$i", "exposuregraphnodeid|n$i") { $l[$k] = @{ CorrelationId = $x; FirstSeen = $At } }
        }
        [pscustomobject]@{ Ledger = $l; Id = $x }
    }
    # what the ledger write does with a run's decisions (upsert by key, FirstSeen kept)
    function script:Apply([hashtable]$Ledger, [object[]]$Decisions, [datetime]$Now) {
        foreach ($d in $Decisions) {
            foreach ($n in @($d.NewIdentifiers)) {
                $k = Get-SILedgerKey -Type $n.Type -Value $n.Value
                if ($Ledger.ContainsKey($k)) { $Ledger[$k].CorrelationId = $n.CorrelationId } else { $Ledger[$k] = @{ CorrelationId = $n.CorrelationId; FirstSeen = $Now } }
            }
        }
        $Ledger
    }
    function script:Rec([string]$p, [string]$rt, [string]$cls, [string]$key, [hashtable]$f, [datetime]$coll = $script:T) {
        $o = [ordered]@{ si_provider = $p; si_record_type = $rt; si_class = $cls; si_record_key = "${p}|${rt}|$key"; si_collection_time = $coll
            si_source_last_seen = $coll.AddHours(-1); si_collection_complete = $true }
        foreach ($k in $f.Keys) { $o[$k] = $f[$k] }
        [pscustomobject]$o
    }
    function script:SpRecords([int]$i) {
        (Rec entra service_principal identity "o$i" @{ entra_object_id = "o$i"; entra_app_id = "a$i"; si_asset_name = 'SqlVmAndArcSqlServersProtection' })
        (Rec eg service_principal identity "n$i" @{ eg_node_id = "n$i"; entra_object_id = "o$i"; si_asset_name = 'SqlVmAndArcSqlServersProtection' })
    }
}

Describe '#642 the cause: a name never gives an Exposure Graph node id' {
    It 'an identity matched by its own object id takes the node id; one matched by display name takes the values but NOT the node id' {
        $node = @{ EG_NodeId = 'n1'; EG_AccountObjectId = 'o1'; ENTRA_IsActive = $true; EG_NodeLabel = 'serviceprincipal' }
        $map = @{ 'o1' = $node; 'sqlvmandarcsqlserversprotection' = $node }
        $byId = Find-SIIdentityEgHit -Map $map -Asset ([pscustomobject]@{ ENTRA_SPObjectId = 'O1'; ENTRA_DisplayName = 'SqlVmAndArcSqlServersProtection' })
        $byId.ByName | Should -BeFalse
        (Get-SIIdentityEgFields -Hit $byId.Hit -ByName $byId.ByName)['EG_NodeId'] | Should -Be 'n1'
        # another service principal of the same name (another subscription): its own id is not in the map
        $byName = Find-SIIdentityEgHit -Map $map -Asset ([pscustomobject]@{ ENTRA_SPObjectId = 'o2'; ENTRA_DisplayName = 'SqlVmAndArcSqlServersProtection' })
        $byName.ByName | Should -BeTrue
        $f = Get-SIIdentityEgFields -Hit $byName.Hit -ByName $byName.ByName
        $f.Contains('EG_NodeId') | Should -BeFalse -Because 'a node id from a name match fused 11 service principals into one asset'
        $f.Contains('EG_AccountObjectId') | Should -BeFalse
        $f['ENTRA_IsActive'] | Should -BeTrue
    }

    It 'exact identifiers are tried before names, and no hit is no hit' {
        $map = @{ 'o1' = @{ EG_NodeId = 'n1' }; 'shared' = @{ EG_NodeId = 'nX' } }
        (Find-SIIdentityEgHit -Map $map -Asset ([pscustomobject]@{ ENTRA_SPObjectId = 'o1'; ENTRA_DisplayName = 'shared' })).Hit.EG_NodeId | Should -Be 'n1'
        (Find-SIIdentityEgHit -Map $map -Asset ([pscustomobject]@{ ENTRA_SPObjectId = 'o9'; ENTRA_DisplayName = 'nothing' })).Hit | Should -BeNullOrEmpty
        (Find-SIIdentityEgHit -Map @{} -Asset ([pscustomobject]@{ ENTRA_SPObjectId = 'o1' })).Hit | Should -BeNullOrEmpty
    }

    It 'the identity and Azure Exposure Graph maps keep a name only when exactly one node has it; the Azure name match hands on no node id' {
        foreach ($f in 'engine\asset-profiling\discovery\Get-DiscoveryFromIdentityExposureGraph.ps1', 'engine\asset-profiling\discovery\Get-DiscoveryFromAzureExposureGraph.ps1') {
            $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f))
            $s | Should -Match '\[int\]\$nameCount\[\$key\] -eq 1' -Because "$f must drop a name two nodes share"
        }
        $c = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\stages\Invoke-Collect.ps1'))
        $c | Should -Not -Match "\`$metadata\['EG_NodeId'\]\s*=\s*\`$egHit\.NodeId" -Because 'the Azure Exposure Graph match is by short name only'
        $c | Should -Match 'Find-SIIdentityEgHit -Map \$identityEgMap'
    }
}

Describe '#642 the identity ledger: distinct objects stay distinct, a wrong merge is split once' {
    It 'distinct service principals with the same name get distinct ids on a first run' {
        $r = Resolve-SIObjectIdentity -Groups @((SpGroup 1), (SpGroup 2), (SpGroup 3)) -Ledger @{} -Now $script:T
        @($r.Decisions | ForEach-Object { $_.CorrelationId } | Sort-Object -Unique).Count | Should -Be 3
        $r.WrongMergeSplit | Should -Be 0
    }

    It 'an existing wrong merge (11 service principals under one id) is split: the object the id was minted from keeps it' {
        $w = WrongLedger 11
        $groups = @(for ($i = 1; $i -le 11; $i++) { SpGroup $i })
        $r = Resolve-SIObjectIdentity -Groups $groups -Ledger $w.Ledger -Now $script:T.AddDays(1)
        $r.WrongMergeSplit | Should -Be 10
        $ids = @($r.Decisions | ForEach-Object { [string]$_.CorrelationId })
        @($ids | Sort-Object -Unique).Count | Should -Be 11
        $ids[0] | Should -Be $w.Id -Because 'the first service principal holds the anchor the id was minted from'
        for ($i = 2; $i -le 11; $i++) {
            $d = $r.Decisions[$i - 1]
            $d.Action | Should -Be 'split'
            $d.CorrelationId | Should -Be ((New-SIObjectUuidV5 -Name "exposuregraphnodeid|n$i").ToString())
            @($d.NewIdentifiers | Where-Object { $_.CorrelationId -eq $d.CorrelationId }).Count | Should -Be 3 -Because 'every anchor of the split object is re-pointed'
        }
        $s = @($r.Splits | Where-Object { $_.Kind -eq 'wrong-merge' })
        $s.Count | Should -Be 10
        @($s[0].Types) | Should -Contain 'aadobjectid'
        @($s[0].Types) | Should -Contain 'aadappid'
    }

    It 'is split ONCE: the next run reuses the new ids and splits nothing' {
        $w = WrongLedger 3
        $groups = @((SpGroup 1), (SpGroup 2), (SpGroup 3))
        $r1 = Resolve-SIObjectIdentity -Groups $groups -Ledger $w.Ledger -Now $script:T.AddDays(1)
        $first = @($r1.Decisions | ForEach-Object { [string]$_.CorrelationId })
        $ledger = Apply -Ledger $w.Ledger -Decisions $r1.Decisions -Now $script:T.AddDays(1)
        $r2 = Resolve-SIObjectIdentity -Groups $groups -Ledger $ledger -Now $script:T.AddDays(2)
        $r2.WrongMergeSplit | Should -Be 0
        $r2.Split | Should -Be 0
        @($r2.Decisions | ForEach-Object { [string]$_.CorrelationId }) | Should -Be $first
        @($r2.Decisions | Where-Object { $_.Action -ne 'reuse' }).Count | Should -Be 0
    }

    It 'a batch that holds only some of the objects decides the same (the CI build resolves batch by batch)' {
        $w = WrongLedger 3
        $alone = Resolve-SIObjectIdentity -Groups @((SpGroup 2)) -Ledger $w.Ledger -Now $script:T.AddDays(1)
        $alone.Decisions[0].CorrelationId | Should -Be ((New-SIObjectUuidV5 -Name 'exposuregraphnodeid|n2').ToString())
        $keeper = Resolve-SIObjectIdentity -Groups @((SpGroup 1)) -Ledger $w.Ledger -Now $script:T.AddDays(1)
        $keeper.Decisions[0].CorrelationId | Should -Be $w.Id
        $keeper.Decisions[0].Action | Should -Be 'reuse'
    }

    It 'without a minting anchor the oldest anchor''s object keeps the id' {
        $l = @{
            'aadobjectid|o1' = @{ CorrelationId = 'OLD-ID'; FirstSeen = $script:T }; 'aadappid|a1' = @{ CorrelationId = 'OLD-ID'; FirstSeen = $script:T }
            'aadobjectid|o2' = @{ CorrelationId = 'OLD-ID'; FirstSeen = $script:T }; 'aadappid|a2' = @{ CorrelationId = 'OLD-ID'; FirstSeen = $script:T }
            'exposuregraphnodeid|n0' = @{ CorrelationId = 'OLD-ID'; FirstSeen = $script:T.AddDays(-3) }
        }
        $g1 = [pscustomobject]@{ Members = @([pscustomobject]@{ Identifiers = @((Id 'AadObjectId' 'o1'), (Id 'AadAppId' 'a1'), (Id 'ExposureGraphNodeId' 'n0')) }) }
        $g2 = [pscustomobject]@{ Members = @([pscustomobject]@{ Identifiers = @((Id 'AadObjectId' 'o2'), (Id 'AadAppId' 'a2')) }) }
        $r = Resolve-SIObjectIdentity -Groups @($g1, $g2) -Ledger $l -Now $script:T.AddDays(1)
        $r.Decisions[0].CorrelationId | Should -Be 'OLD-ID'
        $r.Decisions[1].Action | Should -Be 'split'
    }

    It 'NO PROOF, NO SPLIT: one conflicting type, or values written in different runs, stay on the id (reported)' {
        # one type only (two Entra object ids): could be one object whose sources disagree -- reported, never split
        $l = @{ 'aadobjectid|o1' = @{ CorrelationId = 'X'; FirstSeen = $script:T }; 'aadobjectid|o2' = @{ CorrelationId = 'X'; FirstSeen = $script:T } }
        $g = @([pscustomobject]@{ Members = @([pscustomobject]@{ Identifiers = @((Id 'AadObjectId' 'o1')) }) }, [pscustomobject]@{ Members = @([pscustomobject]@{ Identifiers = @((Id 'AadObjectId' 'o2')) }) })
        $r = Resolve-SIObjectIdentity -Groups $g -Ledger $l -Now $script:T
        $r.WrongMergeSplit | Should -Be 0
        @($r.Decisions | ForEach-Object { $_.CorrelationId } | Sort-Object -Unique) | Should -Be @('X')
        @($r.Splits | Where-Object { -not $_.Resolved -and $_.Kind -eq 'collision' }).Count | Should -Be 1
        # values written in different runs (an object whose ids changed over time): never two objects
        $l2 = @{
            'aadobjectid|o1' = @{ CorrelationId = 'Y'; FirstSeen = $script:T }; 'aadappid|a1' = @{ CorrelationId = 'Y'; FirstSeen = $script:T }
            'aadobjectid|o2' = @{ CorrelationId = 'Y'; FirstSeen = $script:T.AddDays(5) }; 'aadappid|a2' = @{ CorrelationId = 'Y'; FirstSeen = $script:T.AddDays(5) }
        }
        $g2 = [pscustomobject]@{ Members = @([pscustomobject]@{ Identifiers = @((Id 'AadObjectId' 'o2'), (Id 'AadAppId' 'a2')) }) }
        (Resolve-SIObjectIdentity -Groups @($g2) -Ledger $l2 -Now $script:T.AddDays(6)).Decisions[0].CorrelationId | Should -Be 'Y'
        # a Defender device id rotates: never a proof
        $l3 = @{ 'mdedeviceid|m1' = @{ CorrelationId = 'Z'; FirstSeen = $script:T }; 'mdedeviceid|m2' = @{ CorrelationId = 'Z'; FirstSeen = $script:T } }
        (Test-SILedgerWrongMerge -Ids @((Id 'MdeDeviceId' 'm2')) -Ledger $l3 -AnchorKeys @('mdedeviceid|m1', 'mdedeviceid|m2')).Proven | Should -BeFalse
    }
}

Describe '#642 the CI build never keeps one group and drops the others' {
    It 'groups that share an id without proof are built as ONE CI from all their records, counted as a collision' {
        $recs = @(
            (Rec mde device device 'm1' @{ mde_device_id = 'm1'; si_hostname = 'pc1' }),
            (Rec mde device device 'm2' @{ mde_device_id = 'm2'; si_hostname = 'pc2' })
        )
        $g = Get-SICiGroups -Records $recs
        $l = @{ 'mdedeviceid|m1' = @{ CorrelationId = 'SHARED'; FirstSeen = $script:T }; 'mdedeviceid|m2' = @{ CorrelationId = 'SHARED'; FirstSeen = $script:T } }
        $core = Invoke-SICiCore -Groups @($g.Groups) -FeedLatest (Get-SIFeedLatest -Records $recs) -Ledger $l -Model $script:Model -Rules @() -CmdbIndex (New-SICiCmdbIndex) -Now $script:T.AddHours(1)
        @($core.Docs).Count | Should -Be 1
        $core.Docs[0]['si_link_count'] | Should -Be 2 -Because 'both groups'' records are linked -- none is dropped'
        @($core.Collisions).Count | Should -Be 1
        $core.Collisions[0].Groups | Should -Be 2
        $items = ConvertTo-SICiSqlItems -Cis $core.Docs
        @($items.Duplicates).Count | Should -Be 0
    }

    It 'a proven wrong merge comes out as one CI per object, each with its own links' {
        $recs = @(SpRecords 1) + @(SpRecords 2) + @(SpRecords 3)
        $w = WrongLedger 3
        $g = Get-SICiGroups -Records $recs
        $core = Invoke-SICiCore -Groups @($g.Groups) -FeedLatest (Get-SIFeedLatest -Records $recs) -Ledger $w.Ledger -Model $script:Model -Rules @() -CmdbIndex (New-SICiCmdbIndex) -Now $script:T.AddDays(1)
        @($core.Docs).Count | Should -Be 3
        foreach ($d in $core.Docs) { $d['si_link_count'] | Should -Be 2 }
        $core.WrongMergeSplit | Should -Be 2
        @($core.Collisions).Count | Should -Be 0
    }

    It 'the build''s lines name the counts; nothing is said when there is nothing' {
        @(Format-SICiWrongMergeLines).Count | Should -Be 0
        $l = @(Format-SICiWrongMergeLines -Split 10 -SplitIds @('x -> y') -SharedGroups 4 -SharedIds @('z'))
        $l.Count | Should -Be 2
        $l[0] | Should -Match '^CIs: 10 asset\(s\) were split off a CI id'
        $l[1] | Should -Match '^CIs: 4 group\(s\) of records resolved to a CI id another group also has'
        $r = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $r | Should -Not -Match 'kept once; check the identity ledger'
    }
}

Describe '#642 a cloud CI has a last seen' {
    It 'a cloud resource without a source last-seen takes the time its source listed it; an identity never does' {
        $az = Rec azure azure_resource cloud_resource 'vm1' @{ azure_resource_id = '/subscriptions/s/vm1' }
        $doc = New-SICiDocument -CiId 'c1' -Records @($az) -Catalog $script:Model['field-catalog'] -FeedLatest (Get-SIFeedLatest -Records @($az)) -Now $script:T.AddHours(1)
        $doc['si_last_seen'] | Should -Be $script:T.AddHours(-1)
        $doc['si_field_sources']['si_last_seen'].from | Should -Be 'listed_by_source'
        $doc['si_days_inactive'] | Should -Be 0
        $id = Rec entra user identity 'u1' @{ entra_object_id = 'u1' }
        $d2 = New-SICiDocument -CiId 'c2' -Records @($id) -Catalog $script:Model['field-catalog'] -FeedLatest (Get-SIFeedLatest -Records @($id)) -Now $script:T.AddHours(1)
        $d2.Contains('si_last_seen') | Should -BeFalse -Because 'an account that never signs in must not look active'
    }

    It 'a source last-seen the records carry still wins' {
        $az = Rec azure azure_resource cloud_resource 'vm2' @{ azure_resource_id = '/subscriptions/s/vm2' }
        $eg = Rec eg azure_resource cloud_resource 'n9' @{ eg_node_id = 'n9'; azure_resource_id = '/subscriptions/s/vm2'; si_last_seen = $script:T.AddDays(-2) }
        $doc = New-SICiDocument -CiId 'c3' -Records @($az, $eg) -Catalog $script:Model['field-catalog'] -FeedLatest (Get-SIFeedLatest -Records @($az, $eg)) -Now $script:T
        (ConvertTo-SIUtcOrNull $doc['si_last_seen']) | Should -Be $script:T.AddDays(-2)
    }
}

Describe '#642 the repair in a real database: an install''s wrong merge is split by the next build, once (real SQL Server)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        function script:New-EngineConn {
            $e = New-Object System.Data.SqlClient.SqlConnection ($script:AdminConn.ConnectionString + ';Pooling=false')
            $e.Open()
            $c = $e.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
            $e
        }
        $script:Db = $null; $script:DbError = ''
        try {
            # the database schema is Pro: Test-Path first, the Community copy skips this block (says so)
            foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') {
                if (-not (Test-Path -LiteralPath (Join-Path $script:SIRoot $f))) { throw "the Pro database schema ($f) is not in this copy" }
            }
            $name = 'si_test_ciwm_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
            $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $script:AdminConn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30")
            $script:AdminConn.Open()
            foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') {
                $c = $script:AdminConn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery()
            }
            $c = $script:AdminConn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
            $script:Conn = New-EngineConn
            $script:Db = $name
        } catch { $script:DbError = $_.Exception.Message }
        $script:Seam = {
            param($Sql, $Params, $Mode)
            $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 90
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            $c.ExecuteNonQuery()
        }
        function script:Q([string]$Sql) { @(& $script:Seam $Sql @{} 'rows') }
        $script:LockOpen = { New-EngineConn }
        function script:Build([switch]$Full) {
            $script:LogLines = New-Object System.Collections.Generic.List[string]
            $lc = New-EngineConn
            Invoke-SICiBuild -SqlInvoke $script:Seam -LockOpen $script:LockOpen -LedgerProvider ([pscustomobject]@{ Kind = 'sql'; Connection = $lc }) -Rules @() -CmdbIndex (New-SICiCmdbIndex) `
                -Post { param($Rows) @($Rows).Count } -BatchCis 2 -LookbackDays 30 -WorkbookMaxCis 0 -FullReconcile:$Full `
                -Log { param($l, $m) $script:LogLines.Add(($l + ' ' + $m)) }
        }
        if ($script:Db) {
            # the records of today's collection: three same-named service principals (an Entra record and an Exposure Graph node
            # each) and one Azure resource
            $now = [datetime]::UtcNow.AddMinutes(-30)
            $recs = New-Object System.Collections.Generic.List[object]
            for ($i = 1; $i -le 3; $i++) {
                $recs.Add((Rec entra service_principal identity "o$i" @{ entra_object_id = "o$i"; entra_app_id = "a$i"; si_asset_name = 'SqlVmAndArcSqlServersProtection' } $now))
                $recs.Add((Rec eg service_principal identity "n$i" @{ eg_node_id = "n$i"; entra_object_id = "o$i"; si_asset_name = 'SqlVmAndArcSqlServersProtection' } $now))
            }
            $recs.Add((Rec azure azure_resource cloud_resource 'kv1' @{ azure_resource_id = '/subscriptions/s/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1' } $now))
            $w = Write-SIRecordsToSql -Rows $recs.ToArray() -Invoke $script:Seam -Now $now
            if ($w.Failed) { throw "records could not be written ($($w.Failed))" }
            # THE INSTALL'S LEDGER: every anchor of the three under one id, minted from the first one's node, one run
            $script:X = (New-SIObjectUuidV5 -Name 'exposuregraphnodeid|n1').ToString()
            $ins = New-Object System.Text.StringBuilder
            for ($i = 1; $i -le 3; $i++) {
                foreach ($p in @(@('AadObjectId', "o$i"), @('AadAppId', "a$i"), @('ExposureGraphNodeId', "n$i"))) {
                    [void]$ins.AppendFormat("INSERT si.ObjectIdentity (IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen, LastSeen) VALUES (N'{0}', N'{1}', N'{2}', '2026-10-12T21:40:27', '2026-10-12T21:40:27');`n", $p[0], $p[1], $script:X)
                }
            }
            $c = $script:AdminConn.CreateCommand(); $c.CommandText = $ins.ToString(); [void]$c.ExecuteNonQuery()
        }
    }
    AfterAll {
        if ($script:Db) {
            try { $script:Conn.Dispose() } catch { }
            try { $script:AdminConn.Dispose() } catch { }
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
            $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        }
    }
    BeforeEach { if (-not $script:Db) { Set-ItResult -Skipped -Because ('the local SQL Server did not answer: ' + $script:DbError) } }

    It 'the next build splits the wrong merge: three CIs with two links each, the first keeps the id, the ledger is re-pointed, the run record counts it' {
        $b = Build
        $b.Failed | Should -BeFalse
        $b.WrongMergeSplit | Should -Be 2
        $cis = @(Q "SELECT CiId, LinkCount FROM sidata.Ci WHERE Class = N'identity'")
        $cis.Count | Should -Be 3
        foreach ($c in $cis) { [int]$c.LinkCount | Should -Be 2 -Because 'each service principal keeps its own Entra record and node' }
        @($cis | ForEach-Object { [string]$_.CiId }) | Should -Contain $script:X
        (Q "SELECT r.CiId FROM sidata.CiRecord r WHERE r.RecordKey = N'entra|service_principal|o1'")[0].CiId | Should -Be $script:X
        $n2 = (New-SIObjectUuidV5 -Name 'exposuregraphnodeid|n2').ToString()
        @(Q "SELECT SI_CorrelationId FROM si.ObjectIdentity WHERE IdentifierValue IN (N'o2', N'a2', N'n2')" | ForEach-Object { [string]$_.SI_CorrelationId } | Sort-Object -Unique) | Should -Be @($n2)
        (Q "SELECT Value FROM sidata.CiBuildState WHERE Name = N'WrongMergesSplit'")[0].Value | Should -Be '2'
        @($script:LogLines | Where-Object { $_ -match '^WARN CIs: 2 asset\(s\) were split off a CI id' }).Count | Should -Be 1
        @($script:LogLines | Where-Object { $_ -match 'kept once' }).Count | Should -Be 0
    }

    It 'a cloud CI has its last seen in sidata.Ci' {
        $r = @(Q "SELECT LastSeen FROM sidata.Ci WHERE Class = N'cloud_resource'")
        $r.Count | Should -Be 1
        $r[0].LastSeen | Should -Not -BeNullOrEmpty
    }

    It 'the build after it splits nothing again: the same CI ids, nothing to report' {
        $before = @(Q "SELECT CiId FROM sidata.Ci" | ForEach-Object { [string]$_.CiId } | Sort-Object)
        $b = Build -Full
        $b.Failed | Should -BeFalse
        $b.WrongMergeSplit | Should -Be 0
        $b.SharedIdGroups | Should -Be 0
        @(Q "SELECT CiId FROM sidata.Ci" | ForEach-Object { [string]$_.CiId } | Sort-Object) | Should -Be $before
        (Q "SELECT Value FROM sidata.CiBuildState WHERE Name = N'WrongMergesSplit'")[0].Value | Should -Be '0'
    }
}
