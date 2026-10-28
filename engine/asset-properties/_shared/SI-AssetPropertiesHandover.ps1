#Requires -Version 5.1
<#
    SecurityInsight Pro -- FULL ASSET METADATA OF A RUN COLLECTED IN PARTS (KEDA producer / workers, or one job in parts).

    Ring 1, 2026-10-11: the identity producer logged "[asset properties] full -- each source is read once and kept whole"
    and its workers did too, but SI_AssetProperties_CL never got a user or a service principal. The whole objects are kept
    by DISCOVERY (Add-SIFullSourceObject), and in a run collected in parts discovery is the producer -- a process that ends
    after Discover and never reaches Output. The workers reach Output but hold none of the kept objects, and the resolution
    to the profile rows (the anchor -> SI_AssetId) needs the rows the WORKERS built. Nobody held both, so nothing was posted.

    The same answer the records have (SI-RecordHandover.ps1): nobody publishes as it goes.
      * the producer (discover) SAVES the objects it kept + its pull records:  collect/<engine>/<runId>/assetprops/discover/chunk-NNNNN.json
      * every part SAVES the identity of the profile rows it built (SI_AssetId, SI_AssetName, the anchor columns -- a few
        hundred bytes a row) and any object it kept itself:                    collect/<engine>/<runId>/assetprops/part-NNNNN/...
      * the run's LAST step (the process that publishes the records once) reads them all and publishes the full metadata
        ONCE (Publish-SIProfilerAssetProperties), with the run's CollectionTime -- the same as every part's profile rows.

    ONCE PER RUN, NOT ONCE PER PART -- decided on purpose: the collection-change guard (#301) compares this run's
    collection per (profiler, source) with the previous one; a part holds a slice, so a per-part publish could not be
    guarded (every part would look like a 90 % drop) and the asset page would see one run's metadata arrive in pieces.
    The rows are posted by Send-SIAssetPropertyRows in its own batches; that is transport, not a second publish.

    PS 5.1 + 7. No PowerShell modules. NO Set-StrictMode.
#>

function Get-SIAssetPropsHandoverPath {
    <# PURE. Where one process's piece of the run's full asset metadata is kept. #>
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [string]$Who = '', [string]$Kind = 'chunk', [int]$Chunk = 0)
    $base = 'collect/{0}/{1}/assetprops' -f $Engine.ToLowerInvariant(), $RunId
    if (-not $Who) { return "$base/" }
    if ($Kind -eq 'rows') { return ('{0}/{1}/rows-{2:D5}.json' -f $base, $Who, $Chunk) }
    '{0}/{1}/chunk-{2:D5}.json' -f $base, $Who, $Chunk
}

function Get-SIAssetPropsAnchorColumns {
    <# The profile columns a kept object resolves through (+ SI_AssetId / SI_AssetName) -- all a part hands over of a row. #>
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($c in 'SI_AssetId', 'SI_AssetName') { $cols.Add($c) }
    foreach ($a in @($script:SIAssetPropertyAnchors)) { $pc = [string]$a.ProfileColumn; if ($pc -and -not $cols.Contains($pc)) { $cols.Add($pc) } }
    $cols.ToArray()
}

function ConvertTo-SIAssetPropsIdentityRows {
    <# PURE. Profile rows -> only what the resolution reads (SI_AssetId, SI_AssetName, the anchor columns that have a value). #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [string[]]$Columns = @(Get-SIAssetPropsAnchorColumns))
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $o = [ordered]@{}
        foreach ($c in $Columns) {
            $v = $null
            if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($c)) { $v = $r[$c] } }
            else { $p = $r.PSObject.Properties[$c]; if ($p) { $v = $p.Value } }
            if ($null -ne $v -and [string]$v -ne '') { $o[$c] = [string]$v }
        }
        if ($o.Contains('SI_AssetId')) { [pscustomobject]$o }
    }
}

function Save-SIAssetPropsHandover {
    <#
        This process's piece of the full asset metadata -> the state store, in chunks (never one huge write):
          -Entries (the kept objects) + -Pulls  -> chunk-NNNNN.json       (discover, and a part that kept objects itself)
          -ProfileRows (identity columns only)  -> rows-NNNNN.json        (a part)
        Returns @{ Entries; Rows } saved. Throws on a failed write (the caller says it; the profile is unaffected).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$Who,
          [AllowEmptyCollection()][object[]]$Entries = @(), [hashtable]$Pulls = @{}, [AllowEmptyCollection()][object[]]$ProfileRows = @(), [int]$ChunkSize = 1000)
    $pullList = @(foreach ($k in @($Pulls.Keys)) { $Pulls[$k] })
    $nE = 0; $c = 0
    $buf = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Entries)) {
        if ($null -eq $e -or $null -eq $e.Object) { continue }
        $buf.Add([ordered]@{ SourceSystem = [string]$e.SourceSystem; AnchorColumn = [string]$e.AnchorColumn; AnchorValue = [string]$e.AnchorValue; Object = $e.Object })
        $nE++
        if ($buf.Count -ge $ChunkSize) {
            & $Store.Write (Get-SIAssetPropsHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Chunk $c) (ConvertTo-Json -InputObject ([ordered]@{ Schema = 1; Who = $Who; Pulls = $pullList; Entries = $buf.ToArray() }) -Compress -Depth 30)
            $c++; $buf.Clear()
        }
    }
    # the pulls travel in every chunk; a process that kept nothing but read a source still says so (one chunk)
    if ($buf.Count -gt 0 -or ($c -eq 0 -and $pullList.Count -gt 0)) {
        & $Store.Write (Get-SIAssetPropsHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Chunk $c) (ConvertTo-Json -InputObject ([ordered]@{ Schema = 1; Who = $Who; Pulls = $pullList; Entries = $buf.ToArray() }) -Compress -Depth 30)
        $c++; $buf.Clear()
    }
    $nR = 0; $rc = 0
    $rbuf = New-Object System.Collections.Generic.List[object]
    foreach ($r in @(ConvertTo-SIAssetPropsIdentityRows -Rows $ProfileRows)) {
        $rbuf.Add($r); $nR++
        if ($rbuf.Count -ge ($ChunkSize * 10)) {
            & $Store.Write (Get-SIAssetPropsHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Kind rows -Chunk $rc) (ConvertTo-Json -InputObject ([ordered]@{ Schema = 1; Who = $Who; Rows = $rbuf.ToArray() }) -Compress -Depth 4)
            $rc++; $rbuf.Clear()
        }
    }
    if ($rbuf.Count -gt 0) { & $Store.Write (Get-SIAssetPropsHandoverPath -Engine $Engine -RunId $RunId -Who $Who -Kind rows -Chunk $rc) (ConvertTo-Json -InputObject ([ordered]@{ Schema = 1; Who = $Who; Rows = $rbuf.ToArray() }) -Compress -Depth 4) }
    [pscustomobject]@{ Entries = $nE; Rows = $nR }
}

function Read-SIAssetPropsHandover {
    <#
        Every piece of the run's full asset metadata -> @{ Entries; Pulls; ProfileRows; Files }. A pull is complete only when
        it was complete in every process that read the source (a source read twice is narrowed when either was).
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId)
    $entries = New-Object System.Collections.Generic.List[object]
    $rows = New-Object System.Collections.Generic.List[object]
    $pulls = @{}
    $files = @(& $Store.List (Get-SIAssetPropsHandoverPath -Engine $Engine -RunId $RunId)) | Where-Object { $_ } | Sort-Object
    foreach ($f in $files) {
        $txt = & $Store.Read $f
        if (-not $txt) { continue }
        $doc = $txt | ConvertFrom-Json
        foreach ($p in @($doc.Pulls)) {
            if ($null -eq $p -or -not $p.SourceSystem) { continue }
            $k = ([string]$p.SourceSystem).ToLowerInvariant()
            $prev = $pulls[$k]
            if ($prev) {
                $pulls[$k] = [pscustomobject]@{ SourceSystem = $k; Complete = ([bool]$prev.Complete -and [bool]$p.Complete); Error = $(if ($prev.Error) { [string]$prev.Error } else { [string]$p.Error }); Skipped = $(if ($prev.Skipped -and $p.Skipped) { [string]$prev.Skipped } else { '' }); Narrowed = ([bool]$prev.Narrowed -or [bool]$p.Narrowed) }
            } else { $pulls[$k] = [pscustomobject]@{ SourceSystem = $k; Complete = [bool]$p.Complete; Error = [string]$p.Error; Skipped = [string]$p.Skipped; Narrowed = [bool]$p.Narrowed } }
        }
        foreach ($e in @($doc.Entries)) { if ($null -ne $e -and $null -ne $e.Object) { $entries.Add([pscustomobject]@{ SourceSystem = [string]$e.SourceSystem; Object = $e.Object; AnchorColumn = [string]$e.AnchorColumn; AnchorValue = [string]$e.AnchorValue }) } }
        foreach ($r in @($doc.Rows)) { if ($null -ne $r) { $rows.Add($r) } }
    }
    [pscustomobject]@{ Entries = $entries.ToArray(); Pulls = $pulls; ProfileRows = $rows.ToArray(); Files = @($files).Count }
}

function Publish-SIAssetPropsHandover {
    <#
        The run's last step: everything the producer and the parts handed over -> ONE publish of the run's full asset
        metadata (Publish-SIProfilerAssetProperties: the guard per (profiler, source), the post, the retention) with the
        run's CollectionTime and run id. Nothing handed over (the run was not at the full level) = nothing, silently.
        -Publish: test seam { param($RunContext, $ProfileRows, $Entries, $Pulls) }. Returns the publish result or $null.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][datetime]$CollectionTime, [scriptblock]$Publish)
    $h = Read-SIAssetPropsHandover -Store $Store -Engine $Engine -RunId $RunId
    if ($h.Files -eq 0) { return $null }
    $ctx = [pscustomobject]@{ Engine = $Engine.ToLowerInvariant(); RunId = $RunId; CollectionTime = $CollectionTime.ToUniversalTime(); ShardCount = 1; ShardIndex = 0 }
    Write-Host ('[INFO] full asset metadata of a run collected in parts: {0} object(s) from discovery and the parts, {1} profile row(s) from the parts -- published once' -f @($h.Entries).Count, @($h.ProfileRows).Count)
    if ($Publish) { return (& $Publish $ctx @($h.ProfileRows) @($h.Entries) $h.Pulls) }
    Publish-SIProfilerAssetProperties -RunContext $ctx -ProfileRows @($h.ProfileRows) -Entries @($h.Entries) -Pulls $h.Pulls
}

function Invoke-SIAssetPropsHandoverPublish {
    <#
        The container's call in the run's last step (after the records). Loads the Pro publisher (a fresh process, or a
        worker whose engine run has ended), publishes once. NEVER throws -- the profiles and records are already out.
    #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][datetime]$CollectionTime)
    try { return (Publish-SIAssetPropsHandover -Store $Store -Engine $Engine -RunId $RunId -CollectionTime $CollectionTime) }
    catch {
        Write-Warning ('full asset metadata of this run could not be published -- {0}. The profiles and records are unaffected; the asset page keeps the previous full metadata until the next run.' -f $_.Exception.Message)
        return $null
    }
}
