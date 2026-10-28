#Requires -Version 5.1
<#
    Risk Analysis -- DELIVERY WITHOUT THE WHOLE RESULT IN MEMORY SEVERAL TIMES.

    A large install, 2026-10-13: a Detailed run built ~33,000-68,000 rows of ~320 columns in 108 minutes, wrote the
    workbook, and then ran out of memory delivering them. The Log Analytics step copied EVERY row (PSObject.Copy) and then
    rebuilt every row again to align it with the schema -- three full sets of the result alive at once; the JSON file was
    one string of the whole result; the storage upload read the previous workbook into memory to back it up.

    Here:
      * Invoke-RALaChunkedPost -- the rows go to Log Analytics in CHUNKS, each prepared (copies, the run's collection time,
        the host columns, legal names, the chunk's columns on every row, every value in its column's type) and posted
        before the next one is built. A chunk is sized by MEASURED bytes (working rule 5: no row count): the first from
        the rows' own JSON size, every later one from the bytes the ingest client actually posted per row. Nothing is
        left out: the rows posted are counted against the rows given, and a shortfall throws.
      * Write-RAJsonArrayFile -- the JSON sibling written row by row to the file, never as one string.
    The same rows and the same columns are delivered as before; only how many are in memory at once changed.

    PS 5.1 + 7. Shipped in both editions.
#>

# the ingest client's wrappers (Add-SICollectionTime, Add-SIColumnData, Repair-SILogColumnName, Format-SILogRowsToSchema)
if (-not (Get-Command -Name Format-SILogRowsToSchema -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-LogIngest.ps1')) }

function Get-RALaChunkBytes {
    <#
        The JSON size one chunk is built to (bytes): what one chunk's prepared rows hold in memory is a few times this. A
        size budget for memory, not a row count -- the number of rows per chunk follows from the measured size of the rows.
        32 MB: a few posts of the Log Ingestion API (1 MB each, compressed) per chunk, so the per-chunk work (one lookup of
        the rule) stays small next to the posting.
    #>
    32MB
}

function Get-RALaRowBytes {
    <# The JSON size of one row as the ingest client serialises it (ConvertTo-Json -Depth 100 -Compress, UTF-8). #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return 0 }
    [System.Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -Depth 100 -InputObject $Row -Compress))
}

function Get-RALaNextChunkCount {
    <# PURE. Rows in the next chunk: the byte budget over the measured bytes per row -- at least one, never more than are left. #>
    param([long]$TargetBytes, [double]$BytesPerRow, [int]$Remaining)
    if ($Remaining -le 0) { return 0 }
    if ($BytesPerRow -le 0) { return 1 }
    $n = [Math]::Floor([double]$TargetBytes / $BytesPerRow)
    if ($n -lt 1) { $n = 1 }
    [int][Math]::Min([double]$Remaining, $n)
}

function ConvertTo-RALaPostRows {
    <#
        The rows of ONE chunk, ready to post -- the steps the whole set used to go through, on this chunk:
          1. COPIES: the type alignment converts and ROUNDS in place, and nothing after the post (the AI summary, the mail)
             may see a rounded value;
          2. the run's collection time (rows stamped upstream keep theirs);
          3. the host columns (Computer, ComputerFqdn, UserLoggedOn);
          4. legal column names (the ingest client's rules);
          5. every column of the chunk on every row of it (missing = empty), in schema order;
          6. every value to its column's type in the table (-Types; the companions keep what the column cannot hold).
        Returns @{ Rows; Align } -- Align is Set-RALaColumnTypes's report for this chunk ($null without -Types).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
          [AllowEmptyString()][string]$HostName = '', [AllowEmptyString()][string]$Fqdn = '', [AllowEmptyString()][string]$User = '',
          [hashtable]$Types, [string[]]$DecimalCompanions = @(), [string[]]$TextCompanions = @(), [string[]]$NumberCompanions = @(),
          [switch]$OneCore)
    # #744: a large chunk on several cores (RA-ParallelScore.ps1: the same steps, the same rows in the same order); $null =
    # one pass, here
    if (-not $OneCore -and (Get-Command -Name Invoke-RAParallelLaPrepare -ErrorAction SilentlyContinue)) {
        $par = Invoke-RAParallelLaPrepare -Rows $Rows -HostName $HostName -Fqdn $Fqdn -User $User -Types $Types `
            -DecimalCompanions $DecimalCompanions -TextCompanions $TextCompanions -NumberCompanions $NumberCompanions
        if ($null -ne $par) { return $par }
    }
    $copies = New-Object 'System.Collections.Generic.List[object]' ($Rows.Count)
    foreach ($r in $Rows) { if ($null -ne $r) { [void]$copies.Add($r.PSObject.Copy()) } }
    if ($copies.Count -eq 0) { return @{ Rows = @(); Align = $null } }
    $data = $copies.ToArray(); $copies = $null
    $data = @(Add-SICollectionTime -Data $data -Verbose:$false 4>$null)
    $data = @(Add-SIColumnData -Data $data -Column1Name Computer -Column1Data $HostName -Column2Name ComputerFqdn -Column2Data $Fqdn `
                                -Column3Name UserLoggedOn -Column3Data $User -Verbose:$false 4>$null)
    $data = @(Repair-SILogColumnName -Data $data -Verbose:$false 4>$null)
    $data = @(Format-SILogRowsToSchema -Data $data -Verbose:$false 4>$null)
    $align = $null
    if ($Types -and $Types.Count -gt 0) {
        $align = Set-RALaColumnTypes -Rows $data -Types $Types -DecimalCompanions $DecimalCompanions -TextCompanions $TextCompanions -NumberCompanions $NumberCompanions
    }
    @{ Rows = $data; Align = $align }
}

function New-RALaAlignReport {
    <# An empty, merged type-alignment report (the shape Set-RALaColumnTypes returns). #>
    @{ Converted = @{}; Failed = @{}; Rounded = @{}; MovedToText = @{}; MovedToNumber = @{} }
}

function Merge-RALaAlignReport {
    <# PURE. Adds one chunk's type-alignment counts into -Into (per kind, per column). #>
    param([Parameter(Mandatory)][hashtable]$Into, $Align)
    if ($null -eq $Align) { return }
    foreach ($k in @('Converted', 'Failed', 'Rounded', 'MovedToText', 'MovedToNumber')) {
        $src = $null
        if ($Align -is [System.Collections.IDictionary]) { $src = $Align[$k] } elseif ($Align.PSObject.Properties[$k]) { $src = $Align.$k }
        if ($null -eq $src) { continue }
        if (-not $Into.ContainsKey($k) -or $null -eq $Into[$k]) { $Into[$k] = @{} }
        foreach ($c in @($src.Keys)) { $Into[$k][$c] = [long]$Into[$k][$c] + [long]$src[$c] }
    }
}

function Invoke-RALaChunkedPost {
    <#
        Posts -Rows in chunks: each chunk is built by -Prepare (param($rows) -> @{ Rows; Align }) and handed to -Post
        (param($prepared) -> the ingest client's result: RowsPosted, BytesPosted) before the next one is built.
          * Chunk size: the first chunk takes rows until their measured JSON size reaches -TargetBytes; every later chunk
            -TargetBytes over the bytes per row the posts so far measured (the first chunk's measurement until a post
            reports its bytes).
          * Counted: a chunk whose post reports fewer rows than it was given throws -- the other rows are UNKNOWN, not posted.
          * -KeyColumns: which of them are empty on every row of EVERY chunk (.KeyGaps, decided over the prepared rows).
          * -Keep: the prepared rows of every chunk are kept and returned (.Posted) -- the rows Log Analytics received, for
            the trend row and the findings. Without it nothing of a chunk outlives its post.
          * -OnChunk param($chunkNo, $rowsPostedSoFar, $rowsTotal): after each chunk (the progress, the rows posted so far).
        Returns @{ RowsPosted; Chunks; Posted; Align; KeyGaps }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
          [Parameter(Mandatory)][scriptblock]$Prepare,
          [Parameter(Mandatory)][scriptblock]$Post,
          [long]$TargetBytes = 0,
          [string[]]$KeyColumns = @(),
          [switch]$Keep,
          [scriptblock]$OnChunk)
    if ($TargetBytes -le 0) { $TargetBytes = Get-RALaChunkBytes }
    $total = $Rows.Count
    $kept = $null; if ($Keep) { $kept = New-Object 'System.Collections.Generic.List[object]' }
    $align = New-RALaAlignReport
    $open = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in @($KeyColumns)) { if ($c -and -not $open.Contains($c)) { [void]$open.Add($c) } }
    $i = 0; $chunks = 0; $posted = 0L; $bytes = 0L; $perRow = 0.0
    while ($i -lt $total) {
        if ($chunks -eq 0) {
            $sum = 0L; $j = $i
            while ($j -lt $total -and ($j -eq $i -or $sum -lt $TargetBytes)) { $sum += [long](Get-RALaRowBytes $Rows[$j]); $j++ }
            $n = $j - $i
            if ($n -gt 0) { $perRow = [double]$sum / $n }
        } else {
            $n = Get-RALaNextChunkCount -TargetBytes $TargetBytes -BytesPerRow $perRow -Remaining ($total - $i)
        }
        $slice = New-Object 'object[]' $n
        [Array]::Copy($Rows, $i, $slice, 0, $n)
        $p = & $Prepare $slice
        $slice = $null
        $pr = @()
        if ($null -ne $p) { if ($p -is [System.Collections.IDictionary]) { $pr = @($p['Rows']) } else { $pr = @($p.Rows) } }
        $pr = @($pr | Where-Object { $null -ne $_ })
        if ($null -ne $p) { Merge-RALaAlignReport -Into $align -Align $(if ($p -is [System.Collections.IDictionary]) { $p['Align'] } else { $p.Align }) }
        if ($open.Count -gt 0 -and $pr.Count -gt 0) {
            $gaps = @(Get-RAIngestKeyColumnGaps -Rows $pr -Columns $open.ToArray())
            foreach ($c in @($open.ToArray())) { if ($gaps -notcontains $c) { [void]$open.Remove($c) } }
        }
        $rp = [long]$pr.Count
        if ($pr.Count -gt 0) {
            $res = @(& $Post $pr) | Where-Object { $null -ne $_ -and $_.PSObject.Properties['RowsPosted'] } | Select-Object -Last 1
            if ($null -ne $res) {
                $rp = [long]$res.RowsPosted
                if ($res.PSObject.Properties['BytesPosted'] -and [long]$res.BytesPosted -gt 0) { $bytes += [long]$res.BytesPosted }
            }
            if ($rp -ne $pr.Count) { throw ("Posted {0} of {1} row(s) of one part of the result -- the other rows are UNKNOWN, not posted." -f $rp, $pr.Count) }
        }
        $posted += $rp
        if ($bytes -gt 0 -and $posted -gt 0) { $perRow = [double]$bytes / $posted }
        if ($Keep) { foreach ($x in $pr) { [void]$kept.Add($x) } }
        $pr = $null; $p = $null
        $chunks++; $i += $n
        if ($OnChunk) { & $OnChunk $chunks $posted $total }
    }
    [pscustomobject]@{
        RowsPosted = $posted
        Chunks     = $chunks
        Posted     = $(if ($Keep) { $kept.ToArray() } else { $null })
        Align      = $align
        KeyGaps    = $open.ToArray()
    }
}

function Invoke-RALaPagedPost {
    <#
        #738: the whole result to Log Analytics -- -Pager's pages (New-RARowPager: from SQL, read ahead while a page is
        posted; or the rows in memory as one page), each through Invoke-RALaChunkedPost exactly as before (the same chunks,
        the same prepared rows, the same JSON per row), with the posts made by a SENDER for -TableName
        (Start-SILogIngestSender: each POST filled close to the API's limit, up to 4 in flight, 429 / Retry-After honoured).
          * -OnChunk param($partNo, $rowsHandedOver, $rowsConfirmed): after each part.
          * -OnStopped param($rowsConfirmed): when it fails -- the rows that DID reach Log Analytics (posts in flight answered).
        Returns @{ RowsPosted (CONFIRMED by the service); RowsHandedOver; Chunks; Align; KeyGaps; Posts; Sender (its counts) }.
        A post that failed, or fewer rows confirmed than handed over, throws -- the run-level verdict, as before.
        No -TableName (or Get-SILogIngestPostDegree = 1 and nothing else wanted): the posts are made in line, as before.
    #>
    param([Parameter(Mandatory)]$Pager,
          [Parameter(Mandatory)][scriptblock]$Prepare,
          [Parameter(Mandatory)][scriptblock]$Post,
          [string[]]$KeyColumns = @(),
          [string]$TableName = '',
          [int]$Degree = 0,
          [long]$MaxPayloadBytes = 1MB,
          [scriptblock]$OnChunk,
          [scriptblock]$OnStopped)
    $all = [pscustomobject]@{ RowsPosted = 0L; RowsHandedOver = 0L; Chunks = 0; Align = (New-RALaAlignReport); KeyGaps = @($KeyColumns); Posts = 0; Sender = $null }
    $sender = $null
    if ($TableName) { $sender = Start-SILogIngestSender -TableName $TableName -Degree $Degree -MaxPayloadBytes $MaxPayloadBytes }
    # (names of their own: the progress block runs inside Invoke-RALaChunkedPost, which has an -OnChunk of its own)
    $__pgOnChunk = $OnChunk; $__pgSender = $sender
    try {
        while ($null -ne ($page = $Pager.Next())) {
            $__pgBase = $all.Chunks; $__pgBefore = $all.RowsHandedOver
            $d = Invoke-RALaChunkedPost -Rows @($page) -KeyColumns @($all.KeyGaps) -Prepare $Prepare -Post $Post -OnChunk {
                param($__n, $__p, $__t)
                if ($__pgOnChunk) { & $__pgOnChunk ($__pgBase + $__n) ($__pgBefore + $__p) $(if ($__pgSender) { [long]$__pgSender.Confirmed } else { $__pgBefore + $__p }) }
            }
            $all.RowsHandedOver += [long]$d.RowsPosted; $all.Chunks += [int]$d.Chunks
            Merge-RALaAlignReport -Into $all.Align -Align $d.Align
            $all.KeyGaps = @($d.KeyGaps)
            $page = $null; $d = $null
        }
        if ($sender) {
            $c = Complete-SILogIngestSender -TableName $TableName
            $sender = $null
            $all.RowsPosted = [long]$c.RowsPosted; $all.Posts = [int]$c.Posts; $all.Sender = $c
        } else { $all.RowsPosted = $all.RowsHandedOver }
    } catch {
        # (the sender's own count: Complete-SILogIngestSender may have closed it already when its last posts failed)
        $confirmed = $all.RowsHandedOver
        if ($__pgSender) { $null = Stop-SILogIngestSender -TableName $TableName; $confirmed = [long]$__pgSender.Confirmed }
        if ($OnStopped) { try { & $OnStopped ([long]$confirmed) } catch { } }
        throw
    } finally {
        if ($Pager.PSObject.Methods['Close']) { try { $Pager.Close() } catch { } }
    }
    $all
}

# the JSON file's bytes are written (and handed to its upload) in pieces of about this size
$script:RAJsonFlushBytes = 1MB

function Write-RAJsonArrayFile {
    <#
        The JSON sibling, row by row: '[' + each row (ConvertTo-Json -Depth -InputObject) separated by ',' + ']', UTF-8
        without a byte-order mark (what Out-File -Encoding UTF8 writes on PowerShell 7). Always an array: no rows -> [],
        one row -> a one-element array (#121). Only one page's text is in memory at a time.
        #744 (a large customer, 1,138,554 Detailed rows, 2026-10-17):
          * the rows' JSON text is made on several cores (Invoke-RAParallelJsonText, RA-ParallelScore.ps1) -- the same text
            per row, in the same order; one core when that is not available (said once);
          * -Upload (New-SIExportStagedUpload, Send-SecurityInsightExportFile.ps1): every byte written to the file is also
            sent, in order, as blocks of the export blob while the file is written (committed at the upload step);
          * a line at least every minute: "export: rows X of Y" (-Total = the rows expected; -ProgressSeconds).
        The bytes are those of the StreamWriter this function wrote with before (the same separators, the same newline,
        the same UTF-8): tests\pester\SIv3-RaFinishSpeed compares the file's hash with that writer's.
    #>
    # -Pager (#638): the rows a page at a time (New-RARowPager) instead of -Rows -- one page in memory.
    param([AllowEmptyCollection()][AllowNull()][object[]]$Rows, [Parameter(Mandatory)][string]$Path, [int]$Depth = 20, $Pager,
          $Upload, [long]$Total = -1, [int]$ProgressSeconds = 60, [switch]$OneCore)
    $full = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { [System.IO.Path]::Combine((Get-Location).Path, $Path) }
    $enc = New-Object System.Text.UTF8Encoding($false)
    $nl = [Environment]::NewLine
    $sepFirst = $enc.GetBytes($nl); $sepNext = $enc.GetBytes(',' + $nl)
    $fs = New-Object System.IO.FileStream($full, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read, 65536)
    # the bytes since the last flush (to the file, and to -Upload in the same order)
    $buf = New-Object System.IO.MemoryStream
    $clock = [System.Diagnostics.Stopwatch]::StartNew(); $said = 0.0; $written = 0L
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    try {
        $b = $enc.GetBytes('['); $buf.Write($b, 0, $b.Length)
        $first = $true
        if ($null -eq $Rows) { $Rows = @() }
        while ($true) {
            if ($null -ne $Pager) { $Rows = $Pager.Next(); if ($null -eq $Rows) { break } }
            $texts = $null
            if (-not $OneCore -and $Rows.Count -gt 0 -and (Get-Command -Name Invoke-RAParallelJsonText -ErrorAction SilentlyContinue)) { $texts = Invoke-RAParallelJsonText -Rows $Rows -Depth $Depth }
            for ($i = 0; $i -lt $Rows.Count; $i++) {
                if ($first) { $buf.Write($sepFirst, 0, $sepFirst.Length); $first = $false } else { $buf.Write($sepNext, 0, $sepNext.Length) }
                $txt = if ($null -ne $texts) { $texts[$i] } else { ConvertTo-Json -Depth $Depth -InputObject $Rows[$i] }
                $b = $enc.GetBytes([string]$txt); $buf.Write($b, 0, $b.Length)
                $written++
                if ($buf.Length -ge $script:RAJsonFlushBytes) {
                    $fs.Write($buf.GetBuffer(), 0, [int]$buf.Length)
                    if ($null -ne $Upload) { Add-SIExportStagedBytes -Upload $Upload -Bytes $buf.GetBuffer() -Count ([int]$buf.Length) }
                    $buf.SetLength(0)
                }
                if ($ProgressSeconds -gt 0 -and ($clock.Elapsed.TotalSeconds - $said) -ge $ProgressSeconds) {
                    $said = $clock.Elapsed.TotalSeconds
                    $line = if ($Total -ge 0) { [string]::Format($inv, '  export: rows {0:N0} of {1:N0} written to the JSON file', $written, $Total) } else { [string]::Format($inv, '  export: rows {0:N0} written to the JSON file', $written) }
                    if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $line } else { Write-Host $line }
                }
            }
            $texts = $null
            if ($null -eq $Pager) { break }
        }
        if (-not $first) { $buf.Write($sepFirst, 0, $sepFirst.Length) }
        $b = $enc.GetBytes(']' + $nl); $buf.Write($b, 0, $b.Length)
        $fs.Write($buf.GetBuffer(), 0, [int]$buf.Length)
        if ($null -ne $Upload) { Add-SIExportStagedBytes -Upload $Upload -Bytes $buf.GetBuffer() -Count ([int]$buf.Length) }
        $buf.SetLength(0)
        if ($ProgressSeconds -gt 0 -and $said -gt 0) {
            $line = [string]::Format($inv, '  export: rows {0:N0} of {1:N0} written to the JSON file', $written, $(if ($Total -ge 0) { $Total } else { $written }))
            if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $line } else { Write-Host $line }
        }
    } finally { $fs.Dispose(); $buf.Dispose() }
}

function Get-RARunEndVerdict {
    <#
        PURE. #882 -- A REPORT THAT FAILS FAILS ALONE (owner 2026-10-22: "if a report fails, then let it fail so job completes so we
        can fix issue"; coordinator-approved rule). Does THIS run end FAILED? Only when nothing of it can be trusted as stored:
          * -Broken         rows of a report could not be removed AND could not be recorded as held back (#877): a part of a
                            report could be read as the report;
          * -CompleteError  the result is in the database but the collection could not be marked complete;
          * a run WITHOUT a database (-StreamOn $false): Log Analytics refused the post (-LaRefused) or did not receive it in
            full (-LaNotDelivered) -- Log Analytics is then its only store;
          * NOTHING COULD BE STORED: the run has a database (-StreamWanted) and its result could not go there (-StreamOn
            $false), and no copy reached Log Analytics (-LaSent $false) -- not in a dry run (-WhatIf).
        Every other failure -- a report that threw, ended NOT COMPLETE, lost slices, was held back, or a Log Analytics COPY of a
        run WITH a database -- is a warning: that report keeps its last complete result (#877), the run is partial, the job
        completes. Returns @{ Fail; Why }.
    #>
    param([bool]$StreamWanted = $false, [bool]$StreamOn = $false, [bool]$WhatIf = $false, [AllowEmptyString()][string]$Broken = '',
          [AllowEmptyString()][string]$CompleteError = '', [AllowEmptyCollection()][string[]]$LaRefused = @(),
          [AllowEmptyCollection()][string[]]$LaNotDelivered = @(), [bool]$LaSent = $false, [AllowEmptyString()][string]$StreamWhy = '')
    $o = { param($f, $w) [pscustomobject]@{ Fail = [bool]$f; Why = [string]$w } }
    if ("$Broken".Trim()) { return (& $o $true ("the result in the database is not complete: {0}" -f $Broken)) }
    if ("$CompleteError".Trim()) { return (& $o $true ("the result could not be marked complete in the database: {0}" -f $CompleteError)) }
    if (-not $StreamOn) {
        $la = @(@($LaRefused) + @($LaNotDelivered) | Where-Object { "$_".Trim() })
        if ($la.Count) { return (& $o $true ('this run has no database and Log Analytics did not take its result: {0}' -f ($la -join ' | '))) }
        if ($StreamWanted -and -not $WhatIf -and -not $LaSent) {
            return (& $o $true ('nothing of this run could be stored: its result could not go to the database{0} and no copy reached Log Analytics' -f $(if ("$StreamWhy".Trim()) { ' (' + $StreamWhy + ')' } else { '' })))
        }
    }
    & $o $false ''
}
