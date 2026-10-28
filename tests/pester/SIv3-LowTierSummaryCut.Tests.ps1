#Requires -Version 5.1
<#
    #751 -- Identity_Admin_LogonTo_LowTierDevice_Summary ENDED NotComplete: "the lookup _deviceTierOwn (12,580 rows, 1.4 MB) is
    needed whole in every part of the query -- with the query text that is 1.4 MB in every part, more than a query to
    Microsoft Defender can carry (1.0 MB) ..." (live 2026-10-18, a large install, rc7; seen before at another install with
    27,174 rows, 1.2 MB). #741 (2) had made _deviceTierOwn one row per device link key and declared it under
    LookupNeededKeys, so it is cut per query slice -- and the Detailed report ran.

    ROOT CAUSE: the cut of a declared lookup is switched on per RUN and per declaration (Lookup | Column | key lines,
    $script:_RALookupReductionOn). _ciPeer is declared with the SAME device-key lines by seven other reports, so when an
    earlier report of the run had already proved _ciPeer too large, this report's first slice found _ciPeer cut and
    _deviceTierOwn not yet cut. The slice first asked the graph for _ciPeer's keys (Invoke-RALookupKeyDiscovery) -- and that
    key query emptied ONLY the lookups asked for: _deviceTierOwn went into it WHOLE. The key query's own size check
    (Assert-RAHybridQueryFits) then refused it as "needed whole in every part" BEFORE the engine reached the step that sees
    _deviceTierOwn does not fit and cuts it too (RA-GraphHunting.ps1, the turn-on after the first inlining). So the
    report ended in one decision, at every slice count. A fresh run (both lookups whole on the first slice) turned both on
    at once and worked -- which is why the Summary was Complete at the installs where _ciPeer still fit.

    FIX: the key query carries EVERY lookup the report declares for that query empty (they are, by the declaration's
    contract, not read before the cut point), not only the ones asked for. The one that is not cut yet goes whole only into
    the report query, where the size decision turns its cut on; the second ask is the same text and is answered from the
    first (one ask per slice).

    This suite runs the REAL Summary report text through the REAL Invoke-GraphHuntingQuery, with Log Analytics a stub and
    advanced hunting a stand-in that answers each request from what is INSIDE it (the inlined _ciPeer and _deviceTierOwn
    rows), and compares every slice count with the unsliced answer. OFFLINE. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')

    function script:Write-Info  { param($m) $script:Info += , [string]$m }
    function script:Write-Diag  { param($m) }
    function script:Write-Ok    { param($m) }
    function script:Write-Err2  { param($m) }
    function script:Write-Warn2 { param($m) $script:Warned += , [string]$m }
    function script:Add-DynamicGroupKeyCasts { param($Query) $Query }
    function script:Reset-SupersededAttempts { }
    function script:Add-SupersededAttempt { param($Path, $Message) }
    function script:Resolve-SupersededOnSuccess { param($WinningPath) }
    function script:Flush-SupersededAttempts { }
    function script:Save-RARenderedQuery { param($Query, $Tag) }
    function script:Ensure-GraphAuth { param($MaxAgeMinutes) }
    function script:Start-Sleep { param($Seconds, $Milliseconds) }
    function script:Invoke-LogAnalyticsKqlQuery { param($WorkspaceResourceId, $Query) }
    function script:Invoke-SIHuntingQueryRest { param($Query, $Token, $TimeoutSec) }

    $script:Ws = '/subscriptions/x/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
    $script:Name = 'Identity_Admin_LogonTo_LowTierDevice_Summary'

    # ---- the report as the engine loads it: its query text and its LookupNeededKeys ----
    $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''
    $s = $yaml.IndexOf("    - ReportName: $script:Name`n"); $e = $yaml.IndexOf("`n    - ReportName: ", $s + 10)
    $script:Report = $yaml.Substring($s, $e - $s)
    $qs = $script:Report.IndexOf("      ReportQuery:`n      - |-`n")
    $script:Q = ((($script:Report.Substring($qs) -split "`n") | Select-Object -Skip 2 | ForEach-Object { if ($_.StartsWith('        ')) { $_.Substring(8) } else { $_.TrimStart() } }) -join "`n").TrimEnd()
    $script:DeviceKeys = "| extend DeviceCiKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(DeviceNodeId))`n| project __siNeeded = pack_array(DeviceCiKey)"
    $script:Decl = @(@{ Lookup = '_ciPeer'; Column = '_peerKey'; Keys = $script:DeviceKeys }, @{ Lookup = '_deviceTierOwn'; Column = '_dtKey'; Keys = $script:DeviceKeys })

    function script:Get-Hex { param([string]$Seed, [int]$Len = 40)
        $sha = [System.Security.Cryptography.SHA1]::Create()
        try { (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)) | ForEach-Object { $_.ToString('x2') })).Substring(0, $Len) } finally { $sha.Dispose() }
    }
    # The rows of one inlined `let <Var> = datatable(...) [ ... ];` in the request text: what that slice's KQL joins against.
    function script:Read-Datatable { param([string]$Text, [string]$Var)
        $m = [regex]::Match($Text, '(?s)let ' + [regex]::Escape($Var) + ' = datatable\((?<schema>[^)]*)\)\s*\[(?<body>.*?)\];')
        if (-not $m.Success) { throw "no inlined $Var" }
        $cols = @($m.Groups['schema'].Value -split ',' | ForEach-Object { ($_ -split ':')[0].Trim() })
        $toks = @([regex]::Matches($m.Groups['body'].Value, '"(?:[^"\\]|\\.)*"|[a-z]+\(null\)|-?\d+') | ForEach-Object { $_.Value })
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i + $cols.Count -le $toks.Count; $i += $cols.Count) {
            $o = [ordered]@{}
            for ($c = 0; $c -lt $cols.Count; $c++) {
                $t = $toks[$i + $c]
                $o[$cols[$c]] = $(if ($t -match '\(null\)$') { $null } elseif ($t.StartsWith('"')) { $t.Substring(1, $t.Length - 2) } else { [long]$t })
            }
            $rows.Add([pscustomobject]$o)
        }
        , $rows.ToArray()
    }
    # The report's device side, as its KQL does it after the cut point: DeviceCiKey -> _ciPeer (the device's CI) ->
    # _deviceTierOwn of that CI, one row per CI (min of its rows' tiers) -> DeviceCritLvl = coalesce(own, peer_tier);
    # kept when null or > 0. One line per account and device (what the Summary then counts).
    function script:Invoke-DeviceSide { param([object[]]$Pairs, [object[]]$Peer, [object[]]$Own)
        $pk = @{}; foreach ($r in $Peer) { $pk[[string]$r._peerKey] = $r }
        $ow = @{}
        foreach ($r in $Own) { $k = [string]$r._dtCiId; if ($null -ne $r._dtTier) { if (-not $ow.ContainsKey($k) -or $null -eq $ow[$k] -or [long]$r._dtTier -lt [long]$ow[$k]) { $ow[$k] = [long]$r._dtTier } } elseif (-not $ow.ContainsKey($k)) { $ow[$k] = $null } }
        $out = New-Object System.Collections.Generic.List[string]
        foreach ($p in $Pairs) {
            $ck = $(if ($p.Mde) { $p.Mde } else { $p.Node.ToLowerInvariant() })
            $peerRow = $pk[$ck]
            $ci = $(if ($peerRow) { [string]$peerRow.peer_ci_id } else { '' })
            $own = $null; if ($ci -and $ow.ContainsKey($ci)) { $own = $ow[$ci] }
            $lvl = $own; if ($null -eq $lvl -and $peerRow -and $null -ne $peerRow.peer_tier) { $lvl = [long]$peerRow.peer_tier }
            if ($null -eq $lvl -or $lvl -gt 0) { $out.Add(('{0}|{1}|{2}|{3}' -f $p.User, $ck, $ci, $(if ($null -eq $lvl) { 'null' } else { $lvl }))) }
        }
        , @($out.ToArray() | Sort-Object)
    }

    # ---- the fixture: 1,200 device CIs with three link keys each; 2,400 account-device pairs, sliced on the ACCOUNT ----
    $script:Dev = @(0..1199 | ForEach-Object {
        [pscustomobject]@{ I = $_; Ci = "ci-dev-$_"; Mde = $(if ($_ % 3 -ne 0) { Get-Hex "m$_" } else { '' }); Node = (Get-Hex "n$_" 32).ToUpperInvariant(); Entra = Get-Hex "e$_" 36
            PeerTier = ($_ % 4); OwnTier = $(switch ($_ % 5) { 0 { $null } 1 { 0 } 2 { 1 } 3 { 2 } default { 3 } }) } })
    $script:Pairs = @(0..2399 | ForEach-Object { $d = $script:Dev[$_ % 1200]; [pscustomobject]@{ User = Get-Hex "u$_" 36; Mde = $d.Mde; Node = $d.Node; I = $d.I } })
    # every 20th device has no CI at all (no _ciPeer row)
    $script:PeerRows = @($script:Dev | Where-Object { $_.I % 20 -ne 7 } | ForEach-Object {
        $d = $_; $keys = @($d.Node.ToLowerInvariant(), $d.Entra); if ($d.Mde) { $keys += $d.Mde }
        foreach ($k in $keys) { [pscustomobject]@{ _peerKey = $k; peer_ci_id = $d.Ci; peer_tier = $d.PeerTier } } })
    # a key two CIs claim: _ciPeer gives it to ONE -- the other CI's own-tier row of it must not change anything
    $script:Shared = $script:Dev[5].Node.ToLowerInvariant()
    $script:OwnOld = @($script:Dev | ForEach-Object { [pscustomobject]@{ _dtCiId = $_.Ci; _dtTier = $_.OwnTier } })
    $script:OwnNew = @($script:Dev | ForEach-Object {
        $d = $_; $keys = @($d.Node.ToLowerInvariant(), $d.Entra); if ($d.Mde) { $keys += $d.Mde }
        foreach ($k in $keys) { [pscustomobject]@{ _dtKey = $k; _dtCiId = $d.Ci; _dtTier = $d.OwnTier } } }) + @([pscustomobject]@{ _dtKey = $script:Shared; _dtCiId = 'ci-dev-other'; _dtTier = 0 })
    # the answer, worked out directly with the OLD one-row-per-CI lookup, unsliced
    $script:Expected = Invoke-DeviceSide -Pairs $script:Pairs -Peer $script:PeerRows -Own $script:OwnOld

    $script:SliceCache = @{}
    function script:Get-SlicePairs {
        $n = [int]$script:_CurrentBucketCount; if ($n -lt 1) { $n = 1 }
        if (-not $script:SliceCache.ContainsKey($n)) {
            $by = @{}
            foreach ($p in $script:Pairs) {
                $b = $(if ($n -le 1) { 0 } else { [int](Get-SISha256Bucket -Key $p.User -BucketCount $n) })
                if (-not $by.ContainsKey($b)) { $by[$b] = New-Object System.Collections.Generic.List[object] }
                $by[$b].Add($p)
            }
            $script:SliceCache[$n] = $by
        }
        $i = [int]$script:_CurrentBucketIndex
        if ($script:SliceCache[$n].ContainsKey($i)) { $script:SliceCache[$n][$i].ToArray() }
    }
    function script:Invoke-FakeHunting {
        # ADVANCED HUNTING, as far as this report's device side needs it -- answered from the request text alone
        param([string]$Query)
        $mine = @(Get-SlicePairs)
        if ($Query -match 'summarize by __siNeeded') {
            [void]$script:KeyQueries.Add($Query)
            $keys = @($mine | ForEach-Object { if ($_.Mde) { $_.Mde } else { $_.Node.ToLowerInvariant() } } | Sort-Object -Unique)
            return [pscustomobject]@{ Results = @($keys | ForEach-Object { [pscustomobject]@{ AdditionalProperties = @{ '__siNeeded' = $_ } } }) }
        }
        $peer = Read-Datatable $Query '_ciPeer'; $own = Read-Datatable $Query '_deviceTierOwn'
        [void]$script:Requests.Add(@{ Slice = [int]$script:_CurrentBucketIndex; Of = [int]$script:_CurrentBucketCount; Bytes = [long](Get-RARequestWireBytes -Text $Query); OwnRows = $own.Count })
        $rows = Invoke-DeviceSide -Pairs $mine -Peer $peer -Own $own
        return [pscustomobject]@{ Results = @($rows | ForEach-Object { [pscustomobject]@{ AdditionalProperties = @{ Row = $_ } } }) }
    }
    function script:Invoke-Report {
        # every slice of the report, as the bucket loop sends them; returns the rows that came back
        param([int]$Slices)
        $got = New-Object System.Collections.Generic.List[string]
        foreach ($b in 0..($Slices - 1)) {
            $script:_CurrentBucketCount = $(if ($Slices -gt 1) { $Slices } else { 0 }); $script:_CurrentBucketIndex = $b
            # the bucket loop writes the slice's own filter into the bucket-filter block (so each part is its own text)
            $q = $script:Q
            if ($Slices -gt 1) { $q = $q.Replace("//__BUCKET_FILTER_BEGIN__`n| where 1 == 1`n//__BUCKET_FILTER_END__", ("//__BUCKET_FILTER_BEGIN__`n| where SIBucketOf(DeviceKey, {0}) == {1}`n//__BUCKET_FILTER_END__" -f $Slices, $b)) }
            $r = Invoke-GraphHuntingQuery -Query $q -MaxRetries 1
            foreach ($row in @($r.Results)) { $got.Add([string]$row.AdditionalProperties['Row']) }
        }
        $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
        return , @($got.ToArray() | Sort-Object)
    }
    function script:Reset-State {
        $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
        $script:_HybridColumnTypesCache = @{}; $script:_HybridKeyIndexCache = @{}; $script:_CLSnapshotsKql = @{}
        $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false; $script:_RACrossDomainReplicated = $false
        $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0; $script:_LastHybridSnapshotRowCount = 0
        $script:_RAHybridLookups = $null; $script:_RAHybridLastRequest = $null
        $script:_RALookupNeededKeySets = $null; $script:_RALookupReductionOn = @{}; $script:_RALookupKeyAnswerMemo = $null; $script:_RALookupKeyQueryBuilding = $false
        $script:_RALookupNeededKeys = $script:Decl
        $script:_SentinelLakeUnavailable = $true; $script:_RAHuntingNotProvisioned = $false; $script:_LakeTipShown = $true
        $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
        $script:Warned = @(); $script:Info = @()
        $script:Requests = New-Object System.Collections.Generic.List[object]; $script:KeyQueries = New-Object System.Collections.Generic.List[string]
        $global:SI_WorkspaceResourceId = $script:Ws
        $global:SI_RA_DumpAugmentInput = $false
        $global:SI_HuntingRequestCapBytes = $null
    }
    # The request cap scaled to this fixture, as at the live install: the key query that carried _deviceTierOwn whole is AT
    # the cap (refused), the slices with both lookups cut are far below it.
    function script:Set-FixtureCap {
        $script:_RALookupNeededKeySets = @{ '_ciPeer' = @{ Column = '_peerKey'; KeySet = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)) } }
        $script:_RALookupKeyQueryBuilding = $true
        try { $res = Resolve-ProfileCLLetBlocks -Query $script:Q -WorkspaceResourceId $script:Ws -BucketCount 8 -BucketIndex 0 } finally { $script:_RALookupKeyQueryBuilding = $false }
        $script:_RALookupNeededKeySets = $null
        $script:OldKeyQuery = Get-RALookupKeyQuery -ResolvedQuery $res -KeysKql $script:DeviceKeys
        # what no slice count can shrink in that key query (the empty _ciPeer is the only part that does) -- the cap a little
        # under it, so every slice's own filter line (a few bytes longer than the fixture's) is refused the same way
        $fixed = [long](Get-RAHybridRequestShape -Query $script:OldKeyQuery -BucketCount 8).FixedBytes
        $global:SI_HuntingRequestCapBytes = [int]($fixed - 64)
        # (the lookups that key query inlined stay recorded: its size check names them)
    }
    # an earlier report of the run (any of the seven others that declare _ciPeer with the same device-key lines) proved
    # _ciPeer too large: from then on it is cut for the run, _deviceTierOwn is not (yet)
    function script:Set-CiPeerCutByEarlierReport {
        $script:_RALookupReductionOn[(Get-RALookupReductionId -Declaration @{ Lookup = '_ciPeer'; Column = '_peerKey'; KeysKql = $script:DeviceKeys })] = $true
    }
}

AfterAll {
    $global:SI_HuntingRequestCapBytes = $null
}

Describe '#751 the report as the engine loads it' {
    BeforeEach { Reset-State }

    It 'the Summary declares _ciPeer and _deviceTierOwn with the same device-key lines, and both apply to its query' {
        $script:Report | Should -Match '(?m)^      - Lookup: _ciPeer\n        Column: _peerKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$'
        $script:Report | Should -Match '(?m)^      - Lookup: _deviceTierOwn\n        Column: _dtKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$'
        @(Get-RALookupNeededKeyDeclarations -Query $script:Q).Count | Should -Be 2
        $script:Q | Should -Match '//__SI_LOOKUP_KEYS_HERE__'
    }

    It 'other reports declare _ciPeer with the SAME key lines -- so its cut can already be on when this report starts' {
        $yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''
        $same = [regex]::Matches($yaml, '(?m)^      - Lookup: _ciPeer\n        Column: _peerKey\n        Keys: \|-\n          \| extend DeviceCiKey = iif\(isnotempty\(MdeDeviceId\), MdeDeviceId, tolower\(DeviceNodeId\)\)\n          \| project __siNeeded = pack_array\(DeviceCiKey\)$')
        $same.Count | Should -BeGreaterThan 2
    }
}

Describe '#751 the failing shape: _ciPeer already cut for the run, _deviceTierOwn larger than one request' {
    BeforeEach {
        Reset-State
        Mock Invoke-LogAnalyticsKqlQuery { if ($Query -match '_dtKey') { $script:OwnNew } elseif ($Query -match '_peerKey') { $script:PeerRows } else { @() } }
        Mock Resolve-ProfileAugmentPlan { @{ Query = $Query; Plans = @() } }
        Mock Invoke-SIHuntingQueryRest { Invoke-FakeHunting -Query $Query }
    }

    It 'the key query of the old code -- _ciPeer empty, _deviceTierOwn WHOLE -- is refused as the live run was' {
        Set-FixtureCap
        { Assert-RAHybridQueryFits -Query $script:OldKeyQuery -BucketCount 8 } | Should -Throw '*_deviceTierOwn*needed whole in every part*more than a query to Microsoft Defender can carry*'
    }

    It 'unsliced (1 part, whole lookups): the answer is the old one-row-per-CI answer' {
        $got = Invoke-Report -Slices 1
        $got | Should -Be $script:Expected
        $script:KeyQueries.Count | Should -Be 0
    }

    It 'cut to <N> slices: no part is refused, every part fits, and the rows are IDENTICAL to the unsliced answer' -ForEach @(@{ N = 8 }, @{ N = 32 }) {
        Set-FixtureCap
        $cap = [long]$global:SI_HuntingRequestCapBytes
        Set-CiPeerCutByEarlierReport
        $got = Invoke-Report -Slices $N
        $got | Should -Be $script:Expected
        $script:Requests.Count | Should -Be $N
        foreach ($rq in $script:Requests) { $rq.Bytes | Should -BeLessThan $cap }
        foreach ($kq in $script:KeyQueries) { [long](Get-RARequestWireBytes -Text $kq) | Should -BeLessThan $cap }
        # _deviceTierOwn's cut is on now, for the rest of the run
        $script:_RALookupReductionOn.ContainsKey((Get-RALookupReductionId -Declaration @{ Lookup = '_deviceTierOwn'; Column = '_dtKey'; KeysKql = $script:DeviceKeys })) | Should -BeTrue
        # each part is asked for its keys ONCE (both lookups have the same key lines -- the second uses the first's answer)
        $script:KeyQueries.Count | Should -Be $N
        # every key query carries both declared lookups EMPTY
        # (assigned first: Read-Datatable returns ONE array, which @() would wrap)
        foreach ($kq in $script:KeyQueries) {
            $kOwn = Read-Datatable $kq '_deviceTierOwn'; $kPeer = Read-Datatable $kq '_ciPeer'
            $kOwn.Count | Should -Be 0; $kPeer.Count | Should -Be 0
        }
        # over all parts only the keys the graph has travel, never every key of every CI
        ($script:Requests | Measure-Object -Property OwnRows -Sum).Sum | Should -BeLessThan $script:OwnNew.Count
    }

    It 'a fresh run (nothing cut yet): both are cut on the first part, the rows are identical' {
        Set-FixtureCap
        $got = Invoke-Report -Slices 8
        $got | Should -Be $script:Expected
        $script:_RALookupReductionOn.Count | Should -Be 2
    }

    It 'the other way round (_deviceTierOwn cut by an earlier run of this report, _ciPeer not): the rows are identical' {
        Set-FixtureCap
        $script:_RALookupReductionOn[(Get-RALookupReductionId -Declaration @{ Lookup = '_deviceTierOwn'; Column = '_dtKey'; KeysKql = $script:DeviceKeys })] = $true
        $got = Invoke-Report -Slices 8
        $got | Should -Be $script:Expected
    }

    It 'where the lookups fit whole, nothing is asked and nothing is cut (whole while it fits)' {
        Set-CiPeerCutByEarlierReport
        $got = Invoke-Report -Slices 8
        $got | Should -Be $script:Expected
        $script:_RALookupReductionOn.Count | Should -Be 1 -Because '_deviceTierOwn fits the default request size, so its cut is never switched on'
        foreach ($rq in $script:Requests) { $rq.OwnRows | Should -Be $script:OwnNew.Count }
    }
}

Describe '#751 WIRING: the key query empties every lookup the report declares for that query' {
    It 'Invoke-RALookupKeyDiscovery takes the declarations of the query, not only the ones asked for' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ProfileAugment.ps1'))
        $fn = [regex]::Match($src, '(?s)function Invoke-RALookupKeyDiscovery \{.*?\n\}').Value
        $fn | Should -Match ([regex]::Escape('$__allDecl = @(@($Declarations) + @(Get-RALookupNeededKeyDeclarations -Query $Query))'))
        $fn.IndexOf('$__allDecl') | Should -BeLessThan $fn.IndexOf('Resolve-ProfileCLLetBlocks') -Because 'emptied before the key query is built'
    }
}
