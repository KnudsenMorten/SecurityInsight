#Requires -Version 5.1
<#
    STREAMING DISCOVERY (#475). In a run collected in parts, Discover used to hold the whole tenant before splitting it
    (customer H 2026-10-08: 23,142 identities = 3.85 GB in use, 4.96 GB peak; ~45,000 objects is the ceiling of an 8 GiB job,
    and a tenant can have 512,000 users, an Azure estate millions of resources).

    The merge is the hard part: one device is seen by several sources under different names and ids, and one process
    folds its rows by name, then by AadDeviceId, then by the Defender device id (Merge-SIDiscoveredAssets). Streaming keeps
    that merge EXACT by making sure every row of one device ends up in the same part, in three steps:

      A. STREAM   each page a source reads goes straight to a RAW bucket (by its name key) in staging, and its LINK IDS --
                  name key, AadDeviceIds, Defender ids, graph node ids -- join one group in a small index of ids only
                  (union-find over strings; no rows are kept).
      B. ROUTE    each raw bucket is read back and every row moves to the part of its GROUP (the group's smallest id,
                  hashed) -- so rows that any merge could join are in one part. Joining too much is harmless (the merge
                  still applies its own rules inside the part); joining too little would split a device, and cannot
                  happen: every id a merge reads is a link id.
      C. MERGE    each part is read and merged by Merge-SIDiscoveredAssets -- the one-process code -- and written as the
                  part's Discover records, where its worker reads.

    The part count is decided BEFORE anything is read (the sources' counts). Memory: one page, the bounded buffers, the
    index of ids, and in B / C one bucket / one part -- never the tenant.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SICollectPartIndex -ErrorAction SilentlyContinue)) {
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-CollectParts.ps1')
}

$script:SIDiscoverZeroGuid = '00000000-0000-0000-0000-000000000000'

function Get-SIDiscoverLinkIds {
    <#
        PURE. The ids a merge can join a source row on, as 'n:' name key, 'a:' AadDeviceId, 'm:' Defender device id, 'g:'
        graph node id (lower case; the zero GUID is no id). The name key comes first.
    #>
    param([Parameter(Mandatory)]$Row)
    $get = { param($f) if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($f)) { $Row[$f] } else { $null } } else { $p = $Row.PSObject.Properties[$f]; if ($p) { $p.Value } else { $null } } }
    $out = New-Object System.Collections.Generic.List[string]
    $name = [string](& $get 'NormalizedKey'); if ([string]::IsNullOrWhiteSpace($name)) { $name = [string](& $get 'AssetId') }
    $out.Add('n:' + $name.Trim().ToLowerInvariant())
    foreach ($pair in @(@('a:', @('MDE_AadDeviceId', 'EG_AadDeviceId', 'ENTRA_AadDeviceId')), @('m:', @('MDE_DeviceId', 'EG_MdeDeviceId')), @('g:', @('EG_NodeId', 'EgNodeId')))) {
        foreach ($f in $pair[1]) {
            $v = ([string](& $get $f)).Trim().ToLowerInvariant()
            if ($v -and $v -ne $script:SIDiscoverZeroGuid) { $out.Add($pair[0] + $v) }
        }
    }
    return , $out.ToArray()
}

function Find-SIDiscoverGroup {
    <# The group (smallest id) an id belongs to; path halving. #>
    param([Parameter(Mandatory)]$Parent, [Parameter(Mandatory)][string]$Id)
    if (-not $Parent.ContainsKey($Id)) { $Parent[$Id] = $Id; return $Id }
    $x = $Id
    while ($true) {
        $p = $Parent[$x]
        if ($p -ceq $x) { return $x }
        $gp = $Parent[$p]
        $Parent[$x] = $gp
        $x = $gp
    }
}

function Join-SIDiscoverGroup {
    <# One group for both ids; the ordinally smallest id leads it (the same leader whatever the order rows came in). #>
    param([Parameter(Mandatory)]$Parent, [Parameter(Mandatory)][string]$A, [Parameter(Mandatory)][string]$B)
    $ra = Find-SIDiscoverGroup -Parent $Parent -Id $A
    $rb = Find-SIDiscoverGroup -Parent $Parent -Id $B
    if ($ra -ceq $rb) { return }
    if ([string]::CompareOrdinal($ra, $rb) -lt 0) { $Parent[$rb] = $ra } else { $Parent[$ra] = $rb }
}

function ConvertTo-SIDiscoverRow {
    <# PURE. A row read back from staging (an object) -> the hashtable the merge works on (top level; values unchanged). #>
    param($Row)
    if ($null -eq $Row -or $Row -is [System.Collections.IDictionary]) { return $Row }
    $h = @{}
    foreach ($p in $Row.PSObject.Properties) { $h[$p.Name] = $p.Value }
    $h
}

function New-SIDiscoverStream {
    <#
        The stream of one run. -Store @{ Write = { param($Stage, $Part, $Chunk, $Records) }; Read = { param($Stage, $Part) } }
        is the staging seam (default: this run's staging blobs, stages DiscoverRaw / DiscoverRouted / Discover).
    #>
    param(
        [Parameter(Mandatory)]$RunContext,
        [Parameter(Mandatory)][int]$Parts,
        [Parameter(Mandatory)][hashtable]$SourcePriority,
        [Parameter(Mandatory)][string[]]$ReservedKeys,
        [int]$ShardSize = 2000,
        [int]$FlushTotal = 10000,
        $Store
    )
    $P = [Math]::Max(1, $Parts)
    $buf = @{}; $chunk = @{}
    for ($i = 0; $i -lt $P; $i++) { $buf[$i] = New-Object System.Collections.Generic.List[object]; $chunk[$i] = 0 }
    [pscustomobject]@{
        Parts = $P; RunContext = $RunContext; SourcePriority = $SourcePriority; ReservedKeys = $ReservedKeys
        ShardSize = $ShardSize; FlushTotal = $FlushTotal; Store = $Store
        Buffers = $buf; Chunks = $chunk; Buffered = 0; RawRows = 0
        Parent = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::Ordinal)
    }
}

function Write-SIDiscoverStreamChunk {
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][int]$Part, [Parameter(Mandatory)][int]$Chunk, [Parameter(Mandatory)][object[]]$Records)
    if ($Stream.Store) { & $Stream.Store.Write $Stage $Part $Chunk $Records; return }
    $ctx = $Stream.RunContext
    Write-SIStageShard -Context $ctx.StorageContext -ContainerName $ctx.StagingContainer -RunId $ctx.RunId -Stage $Stage -ShardIndex $Chunk -ReplicaIndex $Part -Records $Records | Out-Null
}

function Read-SIDiscoverStreamPart {
    <# One part of -Stage, whole (step C merges a part as one process does) -- or, with -OnRecord, record by record: each
       record is handed to it as it is read and nothing is kept (step B, #721). #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][int]$Part, [scriptblock]$OnRecord)
    if ($OnRecord) {
        if ($Stream.Store) { foreach ($r in (& $Stream.Store.Read $Stage $Part)) { & $OnRecord $r }; return }
        $ctx = $Stream.RunContext
        $null = Read-SIStageShards -Context $ctx.StorageContext -ContainerName $ctx.StagingContainer -RunId $ctx.RunId -Stage $Stage -ReplicaIndex $Part -OnRecord $OnRecord
        return
    }
    if ($Stream.Store) { return @(& $Stream.Store.Read $Stage $Part) }
    $ctx = $Stream.RunContext
    @(Read-SIStageShards -Context $ctx.StorageContext -ContainerName $ctx.StagingContainer -RunId $ctx.RunId -Stage $Stage -ReplicaIndex $Part)
}

function Write-SIDiscoverStreamBuffer {
    <# One buffer -> one chunk of -Stage, the buffer emptied. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][int]$Part)
    $b = $Stream.Buffers[$Part]
    if ($b.Count -eq 0) { return }
    Write-SIDiscoverStreamChunk -Stream $Stream -Stage $Stage -Part $Part -Chunk ([int]$Stream.Chunks[$Part]) -Records $b.ToArray()
    $Stream.Chunks[$Part] = [int]$Stream.Chunks[$Part] + 1
    $Stream.Buffered -= $b.Count
    $b.Clear()
}

function Add-SIDiscoverStreamRow {
    <# One row into buffer -Bucket; a full buffer, or -FlushTotal rows waiting, is written to -Stage. #>
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][int]$Bucket, [Parameter(Mandatory)]$Row)
    $Stream.Buffers[$Bucket].Add($Row); $Stream.Buffered++
    if ($Stream.Buffers[$Bucket].Count -ge $Stream.ShardSize) { Write-SIDiscoverStreamBuffer -Stream $Stream -Stage $Stage -Part $Bucket }
    if ($Stream.Buffered -ge $Stream.FlushTotal) { for ($i = 0; $i -lt $Stream.Parts; $i++) { Write-SIDiscoverStreamBuffer -Stream $Stream -Stage $Stage -Part $i } }
}

function Reset-SIDiscoverStreamBuffers {
    param([Parameter(Mandatory)]$Stream, [Parameter(Mandatory)][string]$Stage)
    for ($i = 0; $i -lt $Stream.Parts; $i++) { Write-SIDiscoverStreamBuffer -Stream $Stream -Stage $Stage -Part $i; $Stream.Chunks[$i] = 0 }
}

function Add-SIDiscoverStreamAssets {
    <# STEP A: one page of source rows -> their raw buckets; their link ids join one group each. Returns the rows taken. #>
    param([Parameter(Mandatory)]$Stream, [AllowEmptyCollection()][object[]]$Assets = @())
    $n = 0
    foreach ($a in $Assets) {
        if ($null -eq $a) { continue }
        $ids = Get-SIDiscoverLinkIds -Row $a
        for ($i = 1; $i -lt $ids.Count; $i++) { Join-SIDiscoverGroup -Parent $Stream.Parent -A $ids[0] -B $ids[$i] }
        if ($ids.Count -eq 1) { $null = Find-SIDiscoverGroup -Parent $Stream.Parent -Id $ids[0] }
        Add-SIDiscoverStreamRow -Stream $Stream -Stage 'DiscoverRaw' -Bucket (Get-SICollectPartIndex -Key $ids[0] -Parts $Stream.Parts) -Row $a
        $Stream.RawRows++
        $n++
    }
    $n
}

function Complete-SIDiscoverStream {
    <#
        STEPS B + C after the last source: every raw row routed to its group's part, every part merged by the one-process
        merge and written as its Discover records. Returns @{ Parts; RawRows; Written; Chunks; EmptyParts; LargestGroup }.
    #>
    param([Parameter(Mandatory)]$Stream)
    Reset-SIDiscoverStreamBuffers -Stream $Stream -Stage 'DiscoverRaw'
    # B -- route by group
    $groupRows = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    # #721: a raw bucket is read row by row -- each row is routed (into a bounded buffer) as it is read; the bucket is never held
    $route = {
        param($r)
        if ($null -eq $r) { return }
        $g = Find-SIDiscoverGroup -Parent $Stream.Parent -Id ((Get-SIDiscoverLinkIds -Row $r)[0])
        $c = 0; if ($groupRows.TryGetValue($g, [ref]$c)) { $groupRows[$g] = $c + 1 } else { $groupRows[$g] = 1 }
        Add-SIDiscoverStreamRow -Stream $Stream -Stage 'DiscoverRouted' -Bucket (Get-SICollectPartIndex -Key $g -Parts $Stream.Parts) -Row $r
    }
    for ($b = 0; $b -lt $Stream.Parts; $b++) {
        Read-SIDiscoverStreamPart -Stream $Stream -Stage 'DiscoverRaw' -Part $b -OnRecord $route
    }
    Reset-SIDiscoverStreamBuffers -Stream $Stream -Stage 'DiscoverRouted'
    $largest = 0; foreach ($v in $groupRows.Values) { if ($v -gt $largest) { $largest = $v } }
    $groupRows = $null
    # C -- merge each part as one process merges, and write it
    $written = 0; $chunks = 0; $empty = 0
    for ($p = 0; $p -lt $Stream.Parts; $p++) {
        $rows = @(Read-SIDiscoverStreamPart -Stream $Stream -Stage 'DiscoverRouted' -Part $p | ForEach-Object { ConvertTo-SIDiscoverRow $_ })
        if ($rows.Count -eq 0) { $empty++; continue }
        $byKey = Merge-SIDiscoveredAssets -RawAssets $rows -SourcePriority $Stream.SourcePriority -ReservedKeys $Stream.ReservedKeys
        $rows = $null
        $recs = @((Get-SIOrdinalSortedEntries -Table $byKey) | ForEach-Object { $_.Value })
        $byKey = $null
        $c = 0
        for ($i = 0; $i -lt $recs.Count; $i += $Stream.ShardSize) {
            Write-SIDiscoverStreamChunk -Stream $Stream -Stage 'Discover' -Part $p -Chunk $c -Records @($recs[$i..([Math]::Min($i + $Stream.ShardSize, $recs.Count) - 1)])
            $c++
        }
        $written += $recs.Count; $chunks += $c
        $recs = $null
        [System.GC]::Collect()
    }
    [pscustomobject]@{ Parts = $Stream.Parts; RawRows = $Stream.RawRows; Written = $written; Chunks = $chunks; EmptyParts = $empty; LargestGroup = $largest }
}

function Get-SIGraphObjectCount {
    <#
        The number of objects behind a Graph collection (users, servicePrincipals): GET /<collection>/$count with
        ConsistencyLevel: eventual. $null when it cannot be read (then the caller does not stream). -Invoke is the HTTP seam.
    #>
    param([Parameter(Mandatory)][string]$Collection, [Parameter(Mandatory)][string]$Token, [scriptblock]$Invoke)
    if (-not $Invoke) { $Invoke = { param($Uri, $Headers) Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop } }
    try {
        $r = & $Invoke ('https://graph.microsoft.com/v1.0/{0}/$count' -f $Collection) @{ Authorization = ('Bearer ' + $Token); ConsistencyLevel = 'eventual' }
        $n = 0L
        if ([long]::TryParse(([string]$r).Trim(), [ref]$n) -and $n -ge 0) { return $n }
        return $null
    } catch { return $null }
}

function Get-SIHuntingCount {
    <# The single number an advanced hunting '| count' query returns, or $null when it cannot be read. -Invoke is the seam. #>
    param([Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][string]$Query, [scriptblock]$Invoke)
    if (-not $Invoke) {
        $Invoke = { param($Q, $T) $r = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Headers @{ Authorization = ('Bearer ' + $T); 'Content-Type' = 'application/json' } -Body (@{ Query = $Q } | ConvertTo-Json -Compress) -ErrorAction Stop
            if ($r.results) { $r.results } elseif ($r.Results) { $r.Results } else { @() } }
    }
    try {
        $c = @(& $Invoke $Query $Token)
        $n = 0L
        if ($c.Count -gt 0 -and [long]::TryParse([string]$c[0].Count, [ref]$n)) { return $n }
    } catch { }
    return $null
}
function Get-SIIdentityDiscoverCount {
    <#
        The identity engine's objects before it reads them: users + service principals ($count). $null when either cannot
        be read -- the run then keeps the whole-set path. Soft-deleted users are not counted (a few at most; they still go
        into their parts).
    #>
    param([Parameter(Mandatory)][string]$Token, [scriptblock]$Invoke)
    $pa = @{ Token = $Token }; if ($Invoke) { $pa['Invoke'] = $Invoke }
    $u = Get-SIGraphObjectCount -Collection 'users' @pa
    $s = Get-SIGraphObjectCount -Collection 'servicePrincipals' @pa
    if ($null -eq $u -or $null -eq $s) { return $null }
    [pscustomobject]@{ Users = $u; ServicePrincipals = $s; Objects = ($u + $s) }
}

function Test-SIDiscoverStreamWanted {
    <#
        PURE. Whether this Discover streams: only the 'discover' phase of a run collected in parts, never with an asset limit
        (a test run keeps the whole-set path), never with full asset properties (that pull keeps the whole set itself), and
        not when SI_DiscoverStreaming = off. Returns @{ Stream; Reason }.
    #>
    param($RunContext, $Setting = $global:SI_DiscoverStreaming, [bool]$FullProperties = $false)
    $phase = ''
    if ($RunContext -and $RunContext.PSObject.Properties['Phase']) { $phase = [string]$RunContext.Phase }
    if ($phase -ne 'discover') { return [pscustomobject]@{ Stream = $false; Reason = 'not the discover phase of a run in parts' } }
    if ([string]$Setting -and ([string]$Setting).Trim().ToLowerInvariant() -in 'off', 'false', '0', 'no') { return [pscustomobject]@{ Stream = $false; Reason = 'SI_DiscoverStreaming = off' } }
    if ($RunContext.AssetLimit -gt 0) { return [pscustomobject]@{ Stream = $false; Reason = 'an asset limit is set' } }
    if ($FullProperties) { return [pscustomobject]@{ Stream = $false; Reason = 'full asset properties are on (that pull keeps the whole set)' } }
    [pscustomobject]@{ Stream = $true; Reason = '' }
}
