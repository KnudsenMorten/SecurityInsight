#Requires -Version 5.1
<#
    The shared harness of SIv3-LowTierDetailedCut.Tests.ps1 and SIv3-LowTierDetailedCut500k.Tests.ps1 (dot-sourced in their
    BeforeAll): the real Detailed report text and its LookupNeededKeys, the real engine files, the fixtures, and a stand-in
    for advanced hunting that answers each request from what is INSIDE it. Split 2026-10-22 so the 500,000-row case runs in
    its own process (its own gate time); the assertions live in the suites. Not a test file. NO EMOJI IN THIS FILE.
#>

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
$script:Name = 'Identity_Admin_LogonTo_LowTierDevice_Detailed'
$script:Cap = [long]1MB

# ---- the report as the engine loads it: its query text and its LookupNeededKeys ----
$yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) -replace "`r", ''
$s = $yaml.IndexOf("    - ReportName: $script:Name`n"); $e = $yaml.IndexOf("`n    - ReportName: ", $s + 10)
$script:Report = $yaml.Substring($s, $e - $s)
$qs = $script:Report.IndexOf("      ReportQuery:`n      - |-`n")
$script:Q = ((($script:Report.Substring($qs) -split "`n") | Select-Object -Skip 2 | ForEach-Object { if ($_.StartsWith('        ')) { $_.Substring(8) } else { $_.TrimStart() } }) -join "`n").TrimEnd()
$script:DeviceKeys = "| extend DeviceCiKey = iif(isnotempty(MdeDeviceId), MdeDeviceId, tolower(DeviceNodeId))`n| project __siNeeded = pack_array(DeviceCiKey)"
$script:Decl = @(@{ Lookup = '_ciPeer'; Column = '_peerKey'; Keys = $script:DeviceKeys }, @{ Lookup = '_deviceTierOwn'; Column = '_dtKey'; Keys = $script:DeviceKeys })

# (one hasher for the whole fixture: 100,000 rows need about 170,000 ids)
$script:Sha1 = [System.Security.Cryptography.SHA1]::Create()
function script:Get-Hex { param([string]$Seed, [int]$Len = 40)
    ([System.BitConverter]::ToString($script:Sha1.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed))) -replace '-', '').ToLowerInvariant().Substring(0, $Len)
}
# a GUID-shaped id from a seed (36 characters, as the Entra object ids and the CI ids of a real install)
function script:Get-Guid { param([string]$Seed) $h = Get-Hex $Seed 32; '{0}-{1}-{2}-{3}-{4}' -f $h.Substring(0, 8), $h.Substring(8, 4), $h.Substring(12, 4), $h.Substring(16, 4), $h.Substring(20, 12) }
# The rows of one inlined `let <Var> = datatable(...) [ ... ];` in the request text: what that part's KQL joins against.
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
# _deviceTierOwn of that CI, one row per CI (min of its rows' tiers) -> DeviceCritLvl = coalesce(own, peer_tier); kept
# when null or > 0. One line per account and device (what the rest of the Detailed then turns into findings).
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

# ---- a fixture of -Devices device CIs, three link keys each (+ one key two CIs claim): 3 x Devices + 1 _deviceTierOwn
# rows. One account per device, and every 4th device has a second account; sliced on the ACCOUNT. ----
# built once per process and device count (the fixtures are read, never changed, by the suites): a suite that needs the same
# graph in several Describes pays its ids once
$script:FixtureCache = @{}
function script:New-Fixture { param([int]$Devices)
    if (-not $script:FixtureCache.ContainsKey($Devices)) { $script:FixtureCache[$Devices] = New-FixtureBuild -Devices $Devices }
    $script:FixtureCache[$Devices]
}
function script:New-FixtureBuild { param([int]$Devices)
    $dev = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $Devices; $i++) {
        $dev.Add([pscustomobject]@{ I = $i; Ci = 'ci-device-' + (Get-Guid "c$i"); Mde = $(if ($i % 3 -ne 0) { Get-Hex "m$i" } else { '' }); Node = (Get-Hex "n$i" 32).ToUpperInvariant(); Entra = Get-Guid "e$i"
            PeerTier = ($i % 4); OwnTier = $(switch ($i % 5) { 0 { $null } 1 { 0 } 2 { 1 } 3 { 2 } default { 3 } }) })
    }
    $pairs = New-Object System.Collections.Generic.List[object]
    foreach ($d in $dev) {
        $pairs.Add([pscustomobject]@{ User = Get-Guid "u$($d.I)"; Mde = $d.Mde; Node = $d.Node })
        if ($d.I % 4 -eq 1) { $pairs.Add([pscustomobject]@{ User = Get-Guid "v$($d.I)"; Mde = $d.Mde; Node = $d.Node }) }
    }
    $peer = New-Object System.Collections.Generic.List[object]; $own = New-Object System.Collections.Generic.List[object]; $old = New-Object System.Collections.Generic.List[object]
    foreach ($d in $dev) {
        $keys = @($d.Node.ToLowerInvariant(), $d.Entra); if ($d.Mde) { $keys += $d.Mde } else { $keys += ('ad-' + (Get-Guid "a$($d.I)")) }
        # every 20th device has no CI at all (no _ciPeer row)
        if ($d.I % 20 -ne 7) { foreach ($k in $keys) { $peer.Add([pscustomobject]@{ _peerKey = $k; peer_ci_id = $d.Ci; peer_tier = $d.PeerTier }) } }
        foreach ($k in $keys) { $own.Add([pscustomobject]@{ _dtKey = $k; _dtCiId = $d.Ci; _dtTier = $d.OwnTier }) }
        $old.Add([pscustomobject]@{ _dtCiId = $d.Ci; _dtTier = $d.OwnTier })
    }
    # a key two CIs claim: _ciPeer gives it to ONE -- the other CI's own-tier row of it must not change anything
    $own.Add([pscustomobject]@{ _dtKey = $dev[5].Node.ToLowerInvariant(); _dtCiId = 'ci-device-other'; _dtTier = 0 })
    [pscustomobject]@{ Devices = $dev.ToArray(); Pairs = $pairs.ToArray(); PeerRows = $peer.ToArray(); OwnNew = $own.ToArray(); OwnOld = $old.ToArray() }
}

$script:SliceCache = @{}
function script:Get-SlicePairs {
    $n = [int]$script:_CurrentBucketCount; if ($n -lt 1) { $n = 1 }
    if (-not $script:SliceCache.ContainsKey($n)) {
        $by = @{}
        foreach ($p in $script:F.Pairs) {
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
    # ADVANCED HUNTING, as far as this report's device side needs it -- answered from the request text alone. A request
    # over the limit is refused as the service does (413).
    param([string]$Query)
    $bytes = [long](Get-RARequestWireBytes -Text $Query)
    if ($bytes -ge $script:Cap) { throw ('Response status code does not indicate success: 413 (Request Entity Too Large) -- {0} bytes' -f $bytes) }
    $mine = @(Get-SlicePairs)
    if ($Query -match 'summarize by __siNeeded') {
        [void]$script:KeyQueries.Add($bytes)
        $keys = @($mine | ForEach-Object { if ($_.Mde) { $_.Mde } else { $_.Node.ToLowerInvariant() } } | Sort-Object -Unique)
        return [pscustomobject]@{ Results = @($keys | ForEach-Object { [pscustomobject]@{ AdditionalProperties = @{ '__siNeeded' = $_ } } }) }
    }
    $peer = Read-Datatable $Query '_ciPeer'; $own = Read-Datatable $Query '_deviceTierOwn'
    [void]$script:Requests.Add(@{ Slice = [int]$script:_CurrentBucketIndex; Of = [int]$script:_CurrentBucketCount; Bytes = $bytes; OwnRows = $own.Count })
    $rows = Invoke-DeviceSide -Pairs $mine -Peer $peer -Own $own
    return [pscustomobject]@{ Results = @($rows | ForEach-Object { [pscustomobject]@{ AdditionalProperties = @{ Row = $_ } } }) }
}
function script:Invoke-Part {
    # one part of the report, as the bucket loop sends it (its own slice filter in the bucket-filter block)
    param([int]$Slices, [int]$Index)
    $script:_CurrentBucketCount = $Slices; $script:_CurrentBucketIndex = $Index
    $q = $script:Q.Replace("//__BUCKET_FILTER_BEGIN__`n| where 1 == 1`n//__BUCKET_FILTER_END__", ("//__BUCKET_FILTER_BEGIN__`n| where SIBucketOf(DeviceKey, {0}) == {1}`n//__BUCKET_FILTER_END__" -f $Slices, $Index))
    $r = Invoke-GraphHuntingQuery -Query $q -MaxRetries 1
    $got = @(@($r.Results) | ForEach-Object { [string]$_.AdditionalProperties['Row'] })
    $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
    , @($got | Sort-Object)
}
function script:Get-PartExpected { param([int]$Slices, [int]$Index)
    $script:_CurrentBucketCount = $Slices; $script:_CurrentBucketIndex = $Index
    $mine = @(Get-SlicePairs)
    $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
    Invoke-DeviceSide -Pairs $mine -Peer $script:F.PeerRows -Own $script:F.OwnOld
}
function script:Reset-State {
    $script:_HybridRowsCache = @{}; $script:_HybridSnapshotCache = @{}; $script:_HybridBucketGroupsCache = @{}; $script:_HybridBucketGroupsWhole = @{}
    $script:_HybridColumnTypesCache = @{}; $script:_HybridKeyIndexCache = @{}; $script:_CLSnapshotsKql = @{}
    $script:_CrossDomainBucketCoalesce = @(); $script:_SkipEGBucketForCrossDomain = $false; $script:_RACrossDomainReplicated = $false
    $script:_LastHybridQueryBodyOverheadBytes = 0; $script:_LastHybridBytesPerRow = 0; $script:_LastHybridSnapshotRowCount = 0
    $script:_RAHybridLookups = $null; $script:_RAHybridLastRequest = $null
    $script:_RALookupNeededKeySets = $null; $script:_RALookupReductionOn = @{}; $script:_RALookupKeyAnswerMemo = $null; $script:_RALookupKeyQueryBuilding = $false; $script:_RALookupCutWanted = @{}
    $script:_RALookupNeededKeys = $script:Decl
    $script:_SentinelLakeUnavailable = $true; $script:_RAHuntingNotProvisioned = $false; $script:_LakeTipShown = $true
    $script:_CurrentBucketCount = 0; $script:_CurrentBucketIndex = 0
    $script:Warned = @(); $script:Info = @()
    $script:Requests = New-Object System.Collections.Generic.List[object]; $script:KeyQueries = New-Object System.Collections.Generic.List[long]
    $global:SI_WorkspaceResourceId = $script:Ws
    $global:SI_RA_DumpAugmentInput = $false
    $global:SI_HuntingRequestCapBytes = $null
}
# an earlier report of the run (any of the seven others that declare _ciPeer with the same device-key lines) proved _ciPeer
# too large: from then on it is cut for the run, _deviceTierOwn is not (yet) -- the order of the live failure
function script:Set-CiPeerCutByEarlierReport {
    $script:_RALookupReductionOn[(Get-RALookupReductionId -Declaration @{ Lookup = '_ciPeer'; Column = '_peerKey'; KeysKql = $script:DeviceKeys })] = $true
}
function script:Get-OwnCutId { Get-RALookupReductionId -Declaration @{ Lookup = '_deviceTierOwn'; Column = '_dtKey'; KeysKql = $script:DeviceKeys } }
