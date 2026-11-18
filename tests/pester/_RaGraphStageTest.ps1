#Requires -Version 7.0
<#
    Shared by SIv3-RaGraphStage*.Tests.ps1 (the attack-path reports from vulnerable devices to Azure, read once per run and
    joined in SQL -- engine\risk-analysis\_shared\RA-GraphPathStage.ps1). Dot-source it at the suite's script scope (BeforeAll):
      * the engine files the port uses, with the log functions stubbed (what they said is in $script:RAGsLog);
      * New-RAGsGraph: a synthetic Exposure Graph (nodes and edges as the two reads answer them) with the cases the query's
        semantics turn on -- label case, edges to nodes outside the node table, cycles, a vulnerable device that is a
        principal, a VM that is a device and an Azure target, the subscription / resource group labels, labels that are no
        target, more than ten secrets on a device, empty names;
      * New-RAGsHunt: advanced hunting as the reads see it -- counts and parts (the part filter read from the KQL), with a
        hook per part to throw (504, a defect) or change the answer;
      * Get-RAGsReference: an INDEPENDENT reading of the query's graph-match (no SQL, no code of the port): per device and
        target the (device edge, credential / identity) pairs, the principals' names and the role scopes;
      * New-RAGsDatabase: a real SQL Server database with the shipped schema, used as the engine is granted (read + write,
        no DDL), and a data seam that answers 'reader' / 'scalar' / 'nonquery' / 'session' like production's.
#>

$script:RAGsRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:RAGsLog = New-Object System.Collections.Generic.List[string]
function script:Write-Info  { param($m) $script:RAGsLog.Add('INFO ' + [string]$m) }
function script:Write-Warn2 { param($m) $script:RAGsLog.Add('WARN ' + [string]$m) }
function script:Write-Err2  { param($m) $script:RAGsLog.Add('ERR ' + [string]$m) }
function script:Write-Ok    { param($m) }
function script:Write-Diag  { param($m) }
function script:Invoke-SIArm { throw 'not used in these tests' }
$__ra = Join-Path $script:RAGsRoot 'engine\risk-analysis\_shared'
foreach ($__f in 'RA-ProfileAugment.ps1', 'RA-AutoBucketing.ps1', 'RA-BucketStore.ps1', 'RA-BucketFilters.ps1', 'RA-WeightedFactors.ps1', 'RA-ScopePreamble.ps1', 'RA-SqlStream.ps1', 'RA-GraphPathStage.ps1') { . (Join-Path $__ra $__f) }
foreach ($__f in 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1', 'engine\_shared\SI-Yaml.ps1') { . (Join-Path $script:RAGsRoot $__f) }
Remove-Variable -Name __ra, __f -ErrorAction SilentlyContinue

function script:Get-RAGsCatalogQuery {
    <# The report's query as the engine reads it from the locked catalog (the engine's own YAML reader). #>
    param([Parameter(Mandatory)][ValidateSet('Detailed', 'Summary')][string]$Grain)
    if ($null -eq $script:RAGsCatalog) { $script:RAGsCatalog = Get-Content -Raw -LiteralPath (Join-Path $script:RAGsRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml }
    $n = "Attack_Paths_${Grain}_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure"
    [string]($script:RAGsCatalog.Reports | Where-Object ReportName -eq $n).ReportQuery
}

function script:Get-RAGsRendered {
    <# The query as the engine sends one slice: the weights block generated (Build-WeightedFactorsKql), the slice filter
       (New-BucketFilterKql), optionally the excluded configuration ids, a row split and a count. #>
    param([Parameter(Mandatory)][string]$Query, $Weights, [long]$Count = 1, [long]$Index = 0, [string[]]$FinalIds = @(), [long]$RowCount = 1, [long]$RowIndex = 0, [switch]$AsCount, [string[]]$GroupKeys, [object[]]$CrossDomain = @())
    if ($null -eq $Weights) { $Weights = [pscustomobject]@{ Path = ''; Engine = 'endpoint'; Combine = 'product'; MaxMultiplier = 0.0; Fields = @() } }
    $m = [regex]::Match($Query, '(?s)//__WEIGHTED_FACTORS_BEGIN__.*?//__WEIGHTED_FACTORS_END__')
    $q = $Query.Replace($m.Value, ("//__WEIGHTED_FACTORS_BEGIN__`n" + (Build-WeightedFactorsKql -Config $Weights) + "`n//__WEIGHTED_FACTORS_END__"))
    if ($FinalIds.Count) { $q = Add-RAFinalScopeFilter -Query $q -Active @{ ExcludedConfigurationIds = @($FinalIds); Apply = $null } }
    $script:_CrossDomainBucketCoalesce = @($CrossDomain)
    $bf = New-BucketFilterKql -BucketCount $Count -BucketIndex $Index
    $b = [regex]::Match($q, '(?s)//__BUCKET_FILTER_BEGIN__.*?//__BUCKET_FILTER_END__')
    if ($Count -gt 1) { $q = $q.Replace($b.Value, "//__BUCKET_FILTER_BEGIN__`n$($bf.TrimEnd())`n//__BUCKET_FILTER_END__") }
    $script:_CrossDomainBucketCoalesce = @()
    if ($RowCount -gt 1) { $q = Add-RARowSplitFilter -Query $q -RowCount $RowCount -RowIndex $RowIndex }
    if ($AsCount) { $q = Get-RAReportCountKql -Query $q -GroupKeys $GroupKeys }
    $q
}

function script:Get-RAGsHash8 { param([string]$Text) [Convert]::ToInt64((Get-RAGpsHex -Text $Text).Substring(0, 8), 16) }

function script:New-RAGsGraph {
    <#
        A synthetic graph. Returns @{ Nodes (the S1 rows: K, NodeId, NodeName, NodeLabel, Fl, DeviceKey, RiskFactorSet, Cvss,
        Bh; plus _Cats / _V for the reference); Edges (the S2 rows: S, T, L, Lt; plus _S / _T / _L the ids and the label as
        written) }. -Devices vulnerable devices, -Seed the random seed.
    #>
    param([int]$Devices = 40, [int]$Seed = 11)
    $rnd = New-Object System.Random $Seed
    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $devLabels = @('contains', 'has credentials of', 'frequently logged in by', 'Contains', 'Frequently Logged In By')
    $addNode = {
        param([string]$Id, [string]$Name, [string]$Label, [string[]]$Cats, [bool]$Vuln = $false, $Cvss = $null, [string[]]$Rf = @())
        $l = [string]$Label
        $fl = 0
        if ($Cats -contains 'secret') { $fl += 1 }; if ($Cats -contains 'identity') { $fl += 2 }; if ($Cats -contains 'environmentAzure') { $fl += 4 }; if ($Cats -contains 'device') { $fl += 8 }
        if ($Vuln) { $fl += 16 }
        if ([string]::Equals($l, 'microsoft.storage/storageaccounts', 'OrdinalIgnoreCase')) { $fl += 32 }
        if (@('subscriptions', 'resourcegroups', 'microsoft.resources/subscriptions', 'microsoft.resources/resourcegroups') -contains $l.ToLowerInvariant()) { $fl += 64 }
        $ll = $l.ToLowerInvariant(); if ($ll.StartsWith('microsoft.') -and -not $ll.StartsWith('microsoft.resources/') -and -not $ll.StartsWith('microsoft.authorization/')) { $fl += 128 }
        $dk = ''; $bh = $null
        if ($Vuln) { $dk = ('mde-' + $Id).ToLowerInvariant(); $bh = Get-RAGsHash8 $dk }
        $nodes.Add([ordered]@{ K = (Get-RAGpsHex -Text $Id).Substring(0, 32); NodeId = $Id; NodeName = $Name; NodeLabel = $l; Fl = $fl; DeviceKey = $dk
                               RiskFactorSet = $(if ($Vuln) { [object[]]$Rf } else { $null }); Cvss = $Cvss; Bh = $bh; _Cats = $Cats; _V = $Vuln })
        if ($Vuln -and ($Cats -contains 'environmentAzure')) {
            # #401: the VM's other row (the Azure node table), which the vulnerable-device row wins over
            $nodes.Add([ordered]@{ K = (Get-RAGpsHex -Text $Id).Substring(0, 32); NodeId = $Id; NodeName = $Name; NodeLabel = $l; Fl = ($fl - 16); DeviceKey = ''; RiskFactorSet = $null; Cvss = $null; Bh = $null; _Cats = $Cats; _V = $false })
        }
    }
    $addEdge = {
        param([string]$S, [string]$T, [string]$Label)
        $low = $Label.ToLowerInvariant()
        $L = 3; if ($low -eq 'has role on') { $L = 1 } elseif ($low -in 'contains', 'has credentials of', 'frequently logged in by') { $L = 2 }
        $edges.Add([ordered]@{ S = (Get-RAGpsHex -Text $S).Substring(0, 32); T = (Get-RAGpsHex -Text $T).Substring(0, 32); L = $L; Lt = $(if ($L -eq 2) { $Label } else { '' }); _S = $S; _T = $T; _L = $Label })
    }
    # Azure: 3 subscriptions, 3 resource groups each, 4 resources each (VMs, storage, web, a role assignment, a deployment)
    $resLabels = @('Microsoft.Compute/virtualMachines', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.authorization/roleassignments', 'microsoft.resources/deployments', 'Microsoft.KeyVault/vaults')
    $rgs = New-Object System.Collections.Generic.List[string]; $res = New-Object System.Collections.Generic.List[string]
    for ($s = 0; $s -lt 3; $s++) {
        $sid = "sub-$s"; & $addNode $sid "Subscription $s" $(if ($s -eq 2) { 'microsoft.resources/subscriptions' } else { 'subscriptions' }) @('environmentAzure')
        for ($g = 0; $g -lt 3; $g++) {
            $gid = "rg-$s-$g"; $rgs.Add($gid); & $addNode $gid "rg$s$g" $(if ($g -eq 1) { 'ResourceGroups' } else { 'resourcegroups' }) @('environmentAzure'); & $addEdge $sid $gid 'contains'
            for ($r = 0; $r -lt 4; $r++) { $rid = "res-$s-$g-$r"; $res.Add($rid); & $addNode $rid "res$s$g$r" $resLabels[($s + $g + $r) % $resLabels.Count] @('environmentAzure'); & $addEdge $gid $rid 'contains' }
        }
    }
    # identities: users, groups (nested, with a cycle), service principals; one identity with an empty name
    for ($u = 0; $u -lt 30; $u++) { & $addNode "user-$u" $(if ($u -eq 7) { '' } else { "User $u" }) 'user' @('identity') }
    for ($g = 0; $g -lt 8; $g++) { & $addNode "grp-$g" "Group $g" 'group' @('identity') }
    for ($p = 0; $p -lt 6; $p++) { & $addNode "sp-$p" "App $p" 'serviceprincipal' @('identity') }
    for ($u = 0; $u -lt 30; $u++) { & $addEdge "user-$u" ("grp-{0}" -f ($u % 8)) $(if ($u % 5 -eq 0) { 'MEMBER OF' } else { 'member of' }) }
    for ($g = 0; $g -lt 7; $g++) { & $addEdge "grp-$g" ("grp-{0}" -f ($g + 1)) 'member of' }
    & $addEdge 'grp-7' 'grp-0' 'member of'                                        # a cycle
    & $addEdge 'user-3' 'sp-1' 'can authenticate as'
    & $addEdge 'sp-1' 'ghost-identity-1' 'can authenticate as'                   # an edge to a node outside the node table
    & $addEdge 'ghost-identity-1' 'rg-1-1' 'has role on'                         # ... which holds a role: a principal without a name
    # roles: groups / service principals on subscriptions, resource groups, resources
    & $addEdge 'grp-2' 'sub-0' 'has role on'; & $addEdge 'grp-5' 'rg-1-2' 'Has Role On'; & $addEdge 'sp-1' 'rg-2-0' 'has role on'
    & $addEdge 'grp-7' $res[5] 'has role on'; & $addEdge 'user-11' $res[17] 'has role on'; & $addEdge 'sp-4' 'sub-2' 'has role on'
    & $addEdge 'grp-3' 'ghost-scope-1' 'has role on'                             # a scope outside the node table
    & $addEdge 'ghost-scope-1' $res[3] 'contains'
    # secrets: app secrets, cookies, an unknown kind, each able to act as an identity
    $secLabels = @('azure-active-directory-app-secret', 'entra-userCookie', 'user-azure-cli-secret', 'some-new-secret-kind', 'azure-storage-connection-string')
    for ($k = 0; $k -lt 25; $k++) { & $addNode "sec-$k" "Secret $k" $secLabels[$k % $secLabels.Count] @('secret'); & $addEdge "sec-$k" ("sp-{0}" -f ($k % 6)) 'can authenticate as' }
    # devices: vulnerable (some also an Azure VM), not vulnerable; one vulnerable device holds a role itself
    for ($d = 0; $d -lt $Devices; $d++) {
        $vm = ($d % 9 -eq 0)
        $cats = @('device'); if ($vm) { $cats += 'environmentAzure' }
        $rf = @(); if ($d % 3 -eq 0) { $rf = @('internet_exposed', 'unsupported_os') } elseif ($d % 3 -eq 1) { $rf = @('internet_exposed') }
        & $addNode "dev-$d" $(if ($d -eq 5) { '' } else { "PC-$d" }) $(if ($vm) { 'microsoft.compute/virtualmachines' } else { 'device' }) $cats $true $(if ($d % 4 -eq 0) { $null } else { [double](5 + ($d % 5)) }) $rf
        $logons = 1 + $rnd.Next(3)
        for ($i = 0; $i -lt $logons; $i++) { & $addEdge "dev-$d" ("user-{0}" -f $rnd.Next(30)) $devLabels[$rnd.Next($devLabels.Count)] }
        if ($d % 4 -eq 1) { for ($i = 0; $i -lt 2; $i++) { & $addEdge "dev-$d" ("sec-{0}" -f $rnd.Next(25)) 'contains' } }
        if ($d -eq 2) { for ($i = 0; $i -lt 25; $i++) { & $addEdge "dev-$d" "sec-$i" 'contains' } }   # more than ten secrets on one device
        if ($d -eq 4) { & $addEdge "dev-$d" 'ghost-secret' 'contains' }                                 # a first hop outside the node table
    }
    & $addEdge 'user-1' 'dev-3' 'can authenticate as'                            # a vulnerable device as a principal ...
    & $addEdge 'dev-3' 'rg-0-1' 'has role on'                                    # ... with a role
    # devices that are not vulnerable are not in the node table the query reads (their edges are, as edges to unknown nodes)
    for ($d = 0; $d -lt 10; $d++) { & $addEdge "plain-$d" ("user-{0}" -f $d) 'frequently logged in by' }
    @{ Nodes = $nodes; Edges = $edges }
}

function script:New-RAGsHunt {
    <# Advanced hunting over -Graph as the two reads ask it: a count, or one part (the part filter's modulus and index read
       from the KQL; a row's part = its position modulo the part count -- the reads never depend on how parts are cut, only
       that they cover every row once). -OnPart { param($Step, $Mod, $Idx, $Call) } may throw, or return rows to answer
       instead. -CountDelta { param($Step, $Call) } adds to a count. Every call is recorded in $script:RAGsCalls. #>
    param([Parameter(Mandatory)][hashtable]$Graph, [scriptblock]$OnPart, [scriptblock]$CountDelta)
    $calls = New-Object System.Collections.Generic.List[string]
    $script:RAGsCalls = $calls
    $g = $Graph; $op = $OnPart; $cd = $CountDelta
    {
        param($Kql)
        $step = if ($Kql.TrimStart().StartsWith('ExposureGraphEdges')) { 'Edges' } else { 'Nodes' }
        $rows = if ($step -eq 'Edges') { $g.Edges } else { $g.Nodes }
        $calls.Add(('{0} {1}' -f $step, $(if ($Kql -match '\| count$') { 'count' } else { 'rows' })))
        if ($Kql -match '\| count$') {
            $n = [long]$rows.Count
            if ($cd) { $n += [long](& $cd $step $calls.Count) }
            return , @(@{ Count = $n })
        }
        $mod = 1L; $idx = 0L
        $m = [regex]::Match($Kql, '\) % (?<n>\d+)\) == (?<i>\d+)')
        if ($m.Success) { $mod = [long]$m.Groups['n'].Value; $idx = [long]$m.Groups['i'].Value }
        if ($op) { $alt = & $op $step $mod $idx $calls.Count; if ($null -ne $alt) { return , @($alt) } }
        $out = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $rows.Count; $i++) {
            if (($i % $mod) -ne $idx) { continue }
            $r = $rows[$i]; $h = @{}
            foreach ($k in $r.Keys) { if (-not $k.StartsWith('_')) { $h[$k] = $r[$k] } }
            $out.Add($h)
        }
        , $out.ToArray()
    }.GetNewClosure()
}

function script:Get-RAGsReference {
    <#
        THE QUERY'S graph-match, read independently (no SQL, no code of the port), over the graph AS ONE NODE TABLE: every
        edge of the six labels (an edge to a node outside the node table kept -- that node has no name, label or category);
        (Device)-[devEdge]->(CredOrIdent)-[bridge*0..3]->(Principal)-[role]->(RoleScope)-[inherit*0..2]->(AzureAsset) with
        the query's tests (=~ / in~ / startswith case-insensitive, == case-sensitive). Returns, keyed '<device id>|<target
        id>': @{ D; T; Pairs (set of "<device edge as written>|<credential id>"); Principals (set of names); Scopes (set of
        "<name>|<label>") }.
    #>
    param([Parameter(Mandatory)][hashtable]$Graph)
    $props = @{}
    foreach ($n in $Graph.Nodes) { if (-not $props.ContainsKey($n.NodeId) -or $n._V) { if (-not $props.ContainsKey($n.NodeId) -or -not $props[$n.NodeId]._V) { $props[$n.NodeId] = $n } } }
    $adj = @{}
    foreach ($e in $Graph.Edges) { if (-not $adj.ContainsKey($e._S)) { $adj[$e._S] = New-Object System.Collections.Generic.List[object] }; $adj[$e._S].Add($e) }
    $reach = {
        param([string]$From, [int]$Max)
        $all = New-Object 'System.Collections.Generic.HashSet[string]'; [void]$all.Add($From)
        $front = @($From)
        for ($k = 1; $k -le $Max; $k++) {
            $next = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($x in $front) { if ($adj.ContainsKey($x)) { foreach ($e in $adj[$x]) { [void]$next.Add($e._T) } } }
            foreach ($x in $next) { [void]$all.Add($x) }
            $front = @($next)
        }
        , @($all)
    }
    $ci = [System.StringComparison]::OrdinalIgnoreCase
    $out = @{}
    foreach ($d in @($props.Values | Where-Object { $_._V })) {
        if (-not $adj.ContainsKey($d.NodeId)) { continue }
        foreach ($e1 in $adj[$d.NodeId]) {
            if (@('contains', 'has credentials of', 'frequently logged in by') -notcontains $e1._L.ToLowerInvariant()) { continue }
            $c = $props[$e1._T]
            if ($null -eq $c -or -not (($c._Cats -contains 'secret') -or ($c._Cats -contains 'identity'))) { continue }
            foreach ($prinId in (& $reach $c.NodeId 3)) {
                if (-not $adj.ContainsKey($prinId)) { continue }
                foreach ($er in $adj[$prinId]) {
                    if (-not [string]::Equals($er._L, 'has role on', $ci)) { continue }
                    $sid = $er._T; $s = $props[$sid]
                    foreach ($tid in (& $reach $sid 2)) {
                        $t = $props[$tid]
                        if ($null -eq $t -or $t._Cats -notcontains 'environmentAzure') { continue }
                        $tl = [string]$t.NodeLabel; $sl = $(if ($s) { [string]$s.NodeLabel } else { '' })
                        $ok = [string]::Equals($tl, 'microsoft.storage/storageaccounts', $ci) -or (
                              (@('subscriptions', 'resourcegroups', 'microsoft.resources/subscriptions', 'microsoft.resources/resourcegroups') -contains $sl.ToLowerInvariant()) -and
                              $tl.StartsWith('microsoft.', $ci) -and -not $tl.StartsWith('microsoft.resources/', $ci) -and -not $tl.StartsWith('microsoft.authorization/', $ci))
                        if (-not $ok) { continue }
                        $key = $d.NodeId + '|' + $tid
                        if (-not $out.ContainsKey($key)) { $out[$key] = @{ D = $d; T = $t; Pairs = (New-Object 'System.Collections.Generic.HashSet[string]'); Principals = (New-Object 'System.Collections.Generic.HashSet[string]'); Scopes = (New-Object 'System.Collections.Generic.HashSet[string]') } }
                        [void]$out[$key].Pairs.Add($e1._L + '|' + $c.NodeId)
                        $p = $props[$prinId]; [void]$out[$key].Principals.Add($(if ($p) { [string]$p.NodeName } else { '' }))
                        [void]$out[$key].Scopes.Add(($(if ($s) { [string]$s.NodeName } else { '' })) + '|' + $sl)
                    }
                }
            }
        }
    }
    $out
}

function script:New-RAGsDatabase {
    <# A real SQL Server database with the shipped data schema, the engine's grant (read + write, no DDL: EXECUTE AS a user of
       db_datareader / db_datawriter), and a data seam that answers like production's (a 'session' runs its batches on one
       connection). Returns @{ Db; Seam; Conn; Scalar }. Remove it with Remove-RAGsDatabase. #>
    param([string]$Prefix = 'si_test_gps_')
    $db = $Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
    $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$db]; ALTER DATABASE [$db] SET RECOVERY SIMPLE;"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    $conn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
    $conn.Open()
    foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $conn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:RAGsRoot $f)); [void]$c.ExecuteNonQuery() }
    $c = $conn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
    $c = $conn.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
    $cn = $conn
    $seam = {
        param($Sql, $Params, $Mode, $OnRow)
        $exec = {
            param([string]$Text, $P, [string]$M)
            $c = $cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
            if ($P) { foreach ($k in $P.Keys) { $v = $P[$k]; [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
            switch ($M) {
                { $_ -in 'reader', 'rows' } {
                    $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } finally { $rd.Close() }
                    , $out.ToArray()
                }
                'scalar' { $v = $c.ExecuteScalar(); if ($v -is [System.DBNull]) { $null } else { $v } }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
        if ($Mode -eq 'session') { $run = { param([string]$StepSql, [string]$StepMode) & $exec $StepSql $null $StepMode }; return (& $OnRow $run) }
        & $exec $Sql $Params $Mode
    }.GetNewClosure()
    $seam | Add-Member -NotePropertyName SISqlSession -NotePropertyValue $true
    $scalar = { param([string]$Sql) $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 0; $v = $c.ExecuteScalar(); if ($v -is [System.DBNull]) { $null } else { $v } }.GetNewClosure()
    @{ Db = $db; Seam = $seam; Conn = $conn; Scalar = $scalar }
}

function script:Remove-RAGsDatabase {
    param($Database)
    if ($null -eq $Database) { return }
    try { $Database.Conn.Dispose() } catch { }
    [System.Data.SqlClient.SqlConnection]::ClearAllPools()
    $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
    $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($Database.Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($Database.Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
}

function script:Reset-RAGsState {
    $script:RAGpsSet = $null; $script:RAGpsSetFailed = $null; $script:RAGpsWorker = $false; $script:RAGpsRun = $null; $script:RAGpsShapeSaid = @{}
    $script:RAGsLog.Clear()
}

function script:Get-RAGsSlicePaths {
    <# The port's _Paths rows of every slice of -Count, from the run's graph in SQL. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][int]$RunNo, [long]$Count = 1, [ValidateSet('Detailed', 'Summary')][string]$Grain = 'Detailed')
    $all = New-Object System.Collections.Generic.List[object]; $other = 0L
    for ($i = 0L; $i -lt $Count; $i++) {
        $data = Get-RAGpsSliceData -Stream $Stream -RunNo $RunNo -Count $Count -Index $i
        $pr = ConvertTo-RAGpsPathRows -Data $data -Grain $Grain -Count $Count -Index $i
        foreach ($r in $pr.Rows) { $r['_Slice'] = $i; $r['_Data'] = $data; $all.Add($r) }
        $other += [long]$pr.OtherPart
    }
    @{ Rows = $all; OtherPart = $other }
}
