#Requires -Version 5.1
<#
    SecurityInsight -- a Log Analytics read IN PARTS, so a large install never meets the service's limit on one answer
    (#639 lane 4, owner 2026-10-21: "memory issues must not be a problem in any step. env must work in millions of assets
    env"). Loaded by SI-AzRest.ps1, and guarded by every caller, so it loads on its own (tests).

    WHY. One Log Analytics answer carries at most ~500,000 rows / ~64 MB. Invoke-SILaQuery REFUSES an answer the service
    cut (New-SILaCutAnswerError) -- a cut answer is never taken as whole. A reader whose result can outgrow one answer
    (a profile snapshot, the correlation map, a customer's rule query) therefore reads in PARTS:

      * The query is first asked AS IT IS -- a small result costs exactly what it cost before (one query, unchanged).
      * Refused as cut (or too large, or this process ran out of memory on it): the query is MEASURED once (rows and
        bytes of its result) and read again in that many parts: each part is the query's own result, filtered on a hash
        of each result row (or of a key the caller names). The parts never overlap and together are every row --
        whatever the query does, because the filter is applied to its RESULT.
      * A part still refused is cut in two (only that part; on a hash of its own, so the pieces never overlap); a part
        far larger than planned cuts every part still to read by the measured factor. The size of a part follows what
        was measured, never a fixed number (working rule 5).
      * MEASURED stop, never a cap: a refused part that held NO row at all, twice in a row, is the query's own work
        hitting a limit (every part repeats it) -- more parts cannot help, and the read fails saying so.
      * A part that fails for any other reason fails THE READ: what was read is not the whole, so it is UNKNOWN -- never
        handed out as the result (working rule 4). The caller's own handling of a failed read applies unchanged.

    A query whose rows differ between two runs of it (take / limit / sample) is never cut into parts: its refusal is passed
    on as it is. The rows of a read in parts come in no particular order.

    PowerShell 5.1-safe: no ternary, no null-conditional. NO Set-StrictMode here (it leaks into the caller's scope).
    A caller's -Read / -OnRows / -Log block runs INSIDE Read-SILaParts: a variable it reads must not share a name with
    this function's own (Query, WorkspaceId, Wait, Key, Read, OnRows, What, Log, rows, got, page, queue ...).
#>

# Azure access: plain REST, no PowerShell modules (SI-AzRest.ps1 loads this file last, so this never loads it twice).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot './SI-AzRest.ps1') }

function Get-SILaPartFilter {
    <#
        PURE. The KQL that keeps ONE part of a query's result: -Cuts = @( @{ Parts; Part } ...) -- the first cut is the
        planned part ("bucket Part of Parts" of the row's hash); each later cut divides that part again on a hash of its own
        (the depth in front of the value), so the pieces of a part never overlap and together are that part. -Key: a KQL
        expression on the result's columns to hash (e.g. 'SI_AssetId'); '' = the whole result row (pack_all()). '' = no cut.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Cuts = @(), [string]$Key = '')
    $terms = New-Object System.Collections.Generic.List[string]
    for ($d = 0; $d -lt @($Cuts).Count; $d++) {
        $parts = [long]$Cuts[$d].Parts; $part = [long]$Cuts[$d].Part
        if ($parts -lt 1 -or $part -lt 0 -or $part -ge $parts) { throw ('Get-SILaPartFilter: part {0} is outside 0..{1}' -f $part, ($parts - 1)) }
        if ($parts -eq 1) { continue }
        if ($d -eq 0) { $terms.Add(('hash(_siPart, {0}) == {1}' -f $parts, $part)) }
        else { $terms.Add(('hash(strcat("{0}|", _siPart), {1}) == {2}' -f $d, $parts, $part)) }
    }
    if ($terms.Count -eq 0) { return '' }
    $k = 'tostring(pack_all())'
    if ($Key) { $k = 'tostring({0})' -f $Key }
    ('| extend _siPart = {0} | where {1} | project-away _siPart' -f $k, ($terms -join ' and '))
}

function Get-SILaPartQuery {
    <#
        PURE. -Query with -Filter after its LAST tabular statement: trailing blank / comment lines and semicolons are taken
        off first, so the filter follows the result. '' -Filter = the query unchanged.
    #>
    param([Parameter(Mandatory)][string]$Query, [AllowEmptyString()][string]$Filter = '')
    if (-not $Filter) { return $Query }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($l in ($Query -split "`r?`n")) { $lines.Add($l) }
    while ($lines.Count -gt 0) {
        $t = $lines[$lines.Count - 1].Trim()
        if ($t -eq '' -or $t.StartsWith('//')) { $lines.RemoveAt($lines.Count - 1); continue }
        if ($t.EndsWith(';')) { $lines[$lines.Count - 1] = $lines[$lines.Count - 1].TrimEnd().TrimEnd(';'); continue }
        break
    }
    (($lines -join "`n") + "`n" + $Filter)
}

function Get-SILaMeasureQuery {
    <# PURE. How many rows -Query's result holds and about how many bytes (one small answer: SIRows, SIBytes). #>
    param([Parameter(Mandatory)][string]$Query)
    Get-SILaPartQuery -Query $Query -Filter '| summarize SIRows = count(), SIBytes = sum(estimate_data_size(*))'
}

function Test-SILaQueryPartable {
    <# PURE. May -Query be read in parts? Not when its rows differ between two runs of it (take / limit / sample): the parts
       of two runs would not be one result. #>
    param([AllowEmptyString()][string]$Query)
    -not ([string]$Query -match '(?im)\|\s*(take|limit|sample|sample-distinct)\b')
}

function Get-SILaPartFailure {
    <#
        PURE. What a failed read of one part says: @{ Cut = $true when a SMALLER part fixes it -- an answer the service cut
        for a limit (Invoke-SILaQuery's refusal, Risk Analysis' own), an answer refused as too large, or this process out of
        memory on it; Rows = the rows the short answer held (-1 unknown) }. Anything else: Cut = $false (passed on as it is).
    #>
    param([AllowNull()][object]$Err)
    $ex = $null; $texts = New-Object System.Collections.Generic.List[string]
    if ($Err -is [System.Management.Automation.ErrorRecord]) {
        $ex = $Err.Exception
        if ($Err.ErrorDetails -and $Err.ErrorDetails.Message) { $texts.Add([string]$Err.ErrorDetails.Message) }
    } elseif ($Err -is [System.Exception]) { $ex = $Err }
    elseif ($null -ne $Err) { $texts.Add([string]$Err) }
    $e = $ex
    while ($null -ne $e) {
        if ($e -is [System.OutOfMemoryException] -or $e -is [System.InsufficientExecutionStackException]) { return @{ Cut = $true; Rows = -1L; Why = 'too large for this job''s memory' } }
        if ($e.Data) {
            foreach ($k in 'SILaPartial', 'SIRALaPartial') {
                if ($e.Data.Contains($k)) {
                    $rows = -1L
                    if ($e.Data.Contains('SIRALaPartialRows')) { try { $rows = [long]$e.Data['SIRALaPartialRows'] } catch { $rows = -1L } }
                    return @{ Cut = ([string]$e.Data[$k] -eq 'Limit'); Rows = $rows; Why = 'cut by the service''s limit' }
                }
            }
        }
        $texts.Add([string]$e.Message)
        try { if ($e.PSObject.Properties['Response'] -and $e.Response -and $e.Response.PSObject.Properties['Content']) { $texts.Add([string]$e.Response.Content) } } catch { }
        $e = $e.InnerException
    }
    $all = ($texts -join ' ')
    if ($all -match '(?i)E_QUERY_RESULT_SET_TOO_LARGE|ResponsePayloadTooLarge|ResponseSizeError|result set (is )?too large|exceeds? the (maximum )?(response|result) size|response size .*exceed') {
        return @{ Cut = $true; Rows = -1L; Why = 'too large to read in one answer' }
    }
    @{ Cut = $false; Rows = -1L; Why = '' }
}

function ConvertTo-SILaPartRows {
    <# PURE. Rows however a reader handed them over -- one array (`, @(rows)`), an array holding that array, or rows on the
       pipeline -- as ONE flat object[] without nulls. #>
    param([AllowNull()][object]$Answer)
    $l = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y) { $l.Add($y) } } } else { $l.Add($x) }
    }
    , $l.ToArray()
}

function Get-SILaPartPlan {
    <#
        PURE. How many parts a result of -Rows rows / about -Bytes bytes is read in: each part well under one answer's
        limits -- at most half the service's own row limit, and -TargetBytes of answer (the JSON answer is -Expansion times
        the data's own size). At least 2 (the result was refused whole). Follows the measurement; no ceiling.
    #>
    param([long]$Rows = -1, [double]$Bytes = -1, [long]$TargetRows = 0, [double]$TargetBytes = 16MB, [double]$Expansion = 2.5)
    if ($TargetRows -le 0) {
        $limit = 500000L
        if (Get-Command -Name Get-SILaServiceRowLimit -ErrorAction SilentlyContinue) { $limit = [long](Get-SILaServiceRowLimit) }
        $TargetRows = [long][Math]::Max(1, [Math]::Floor($limit / 2))
    }
    $n = 2L
    if ($Rows -gt 0) { $n = [long][Math]::Max($n, [Math]::Ceiling([double]$Rows / [double]$TargetRows)) }
    if ($Bytes -gt 0 -and $TargetBytes -gt 0) { $n = [long][Math]::Max($n, [Math]::Ceiling(($Bytes * $Expansion) / $TargetBytes)) }
    $n
}

function Read-SILaParts {
    <#
        ONE Log Analytics read, in parts when one answer cannot carry it (see the header of this file). Every row once.
          -Query      the KQL (asked as it is first)
          -Key        a KQL expression on the result's columns that the parts hash on ('' = the whole result row). A key
                      that is the same for many rows cannot divide them -- '' always can.
          -Read       { param($Kql) rows } -- the reader (the seam for tests). Default: Invoke-SIAzOperationalInsightsQuery
                      on -WorkspaceId (with -Wait), its .Results.
          -OnRows     { param($Rows) } -- each part's rows as soon as that part is read whole (then not collected; memory is
                      one part). The parts handed on are only the result when this call RETURNS: a later part that fails
                      throws, and the caller treats the whole read as failed. Without -OnRows the rows are collected.
          -What       what is read, for the lines it says; -Log { param($Level, $Message) }
        Returns @{ Rows (without -OnRows); RowCount; Pages; Parts (planned); Cuts }. Throws when the read is not whole.
    #>
    param(
        [Parameter(Mandatory)][string]$Query,
        [string]$WorkspaceId = '',
        [int]$Wait = 0,
        [string]$Key = '',
        [scriptblock]$Read,
        [scriptblock]$OnRows,
        [string]$What = 'the Log Analytics read',
        [scriptblock]$Log,
        [long]$TargetRows = 0,
        [double]$TargetBytes = 16MB,
        [int]$MaxDepth = 24
    )
    if (-not $Read) {
        if (-not $WorkspaceId) { throw 'Read-SILaParts: -WorkspaceId or -Read is needed' }
        # (-Wait only when given: the same call the readers made before, so a reader's own stand-in still answers it)
        $Read = {
            param($k)
            $__p = @{ WorkspaceId = $WorkspaceId; Query = $k; ErrorAction = 'Stop' }
            if ($Wait -gt 0) { $__p['Wait'] = $Wait }
            $__a = Invoke-SIAzOperationalInsightsQuery @__p
            if ($__a) { , @($__a.Results) } else { , @() }
        }
    }
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    if ($TargetRows -le 0) {
        $limit = 500000L
        if (Get-Command -Name Get-SILaServiceRowLimit -ErrorAction SilentlyContinue) { $limit = [long](Get-SILaServiceRowLimit) }
        $TargetRows = [long][Math]::Max(1, [Math]::Floor($limit / 2))
    }
    $partable = Test-SILaQueryPartable -Query $Query
    $acc = $null
    if (-not $OnRows) { $acc = New-Object System.Collections.Generic.List[object] }
    $queue = New-Object 'System.Collections.Generic.Queue[object]'
    $queue.Enqueue([pscustomobject]@{ Cuts = @() })
    $pages = 0L; $rowsRead = 0L; $cutsMade = 0L; $planned = 1L; $measured = $false; $emptyRefusals = 0
    while ($queue.Count -gt 0) {
        $page = $queue.Dequeue()
        $kql = Get-SILaPartQuery -Query $Query -Filter (Get-SILaPartFilter -Cuts @($page.Cuts) -Key $Key)
        $rows = $null; $fail = $null
        try {
            # assigned first: the reader answers ONE array (`, @(rows)`) -- @() around the call would hold it as one row
            $got = & $Read $kql
            $rows = ConvertTo-SILaPartRows $got
            $got = $null
        } catch {
            $f = Get-SILaPartFailure -Err $_
            if (-not $f.Cut -or -not $partable) { throw }
            $fail = $f; $failErr = $_
        }
        if ($fail) {
            $rows = $null
            if (@($page.Cuts).Count -ge $MaxDepth) {
                throw ('{0} is more than Log Analytics can answer: a part cut {1} times is still {2} -- the read is not whole and nothing of it is used' -f $What, @($page.Cuts).Count, $fail.Why)
            }
            if ([long]$fail.Rows -eq 0) { $emptyRefusals++ } else { $emptyRefusals = 0 }
            if ($emptyRefusals -ge 2) {
                throw ('{0} is more than Log Analytics can answer: a part stopped at the service''s limit before it returned a row, twice, so reading it in more parts cannot make it fit -- the read is not whole and nothing of it is used ({1})' -f $What, (([string]$failErr.Exception.Message -split "`n") | Select-Object -First 1))
            }
            if (@($page.Cuts).Count -eq 0 -and -not $measured) {
                # the whole query was refused: measured ONCE, then read in that many parts
                $measured = $true
                $mRows = -1L; $mBytes = -1.0
                try {
                    $mr = ConvertTo-SILaPartRows (& $Read (Get-SILaMeasureQuery -Query $Query)); $m = $null; if ($mr.Count -gt 0) { $m = $mr[0] }
                    if ($m) {
                        if ($m.PSObject.Properties['SIRows'] -and "$($m.SIRows)" -ne '') { $mRows = [long][double]::Parse([string]$m.SIRows, [Globalization.CultureInfo]::InvariantCulture) }
                        if ($m.PSObject.Properties['SIBytes'] -and "$($m.SIBytes)" -ne '') { $mBytes = [double]::Parse([string]$m.SIBytes, [Globalization.CultureInfo]::InvariantCulture) }
                    }
                } catch { $mRows = -1L; $mBytes = -1.0 }
                $planned = Get-SILaPartPlan -Rows $mRows -Bytes $mBytes -TargetRows $TargetRows -TargetBytes $TargetBytes
                for ($p = 0L; $p -lt $planned; $p++) { $queue.Enqueue([pscustomobject]@{ Cuts = @([pscustomobject]@{ Parts = $planned; Part = $p }) }) }
                $cutsMade++
                $sizeText = ''
                if ($mRows -ge 0) { $sizeText = [string]::Format([Globalization.CultureInfo]::InvariantCulture, ' (measured: {0:N0} row(s){1})', $mRows, $(if ($mBytes -ge 0) { [string]::Format([Globalization.CultureInfo]::InvariantCulture, ', about {0:N0} MB', ($mBytes / 1MB)) } else { '' })) }
                & $Log 'INFO' ('{0} is larger than one Log Analytics answer can carry ({1}) -- it is read in {2} parts{3}; nothing of the short answer is kept' -f $What, $fail.Why, $planned, $sizeText)
            } else {
                foreach ($half in 0, 1) { $queue.Enqueue([pscustomobject]@{ Cuts = @($page.Cuts) + @([pscustomobject]@{ Parts = 2L; Part = [long]$half }) }) }
                $cutsMade++
                & $Log 'INFO' ('{0}: a part was {1} -- it is read again in two smaller parts' -f $What, $fail.Why)
            }
            continue
        }
        $emptyRefusals = 0
        $n = $rows.Count
        $pages++; $rowsRead += $n
        if ($OnRows) { $null = & $OnRows $rows } else { $acc.AddRange([object[]]$rows) }
        $rows = $null
        # measured, not assumed: a part far larger than planned -> every part still to read is cut by that factor
        if (@($page.Cuts).Count -gt 0 -and $n -gt (2 * $TargetRows) -and $queue.Count -gt 0) {
            $factor = [long][Math]::Ceiling([double]$n / [double]$TargetRows)
            $rest = $queue.ToArray(); $queue.Clear()
            foreach ($rp in $rest) { for ($piece = 0L; $piece -lt $factor; $piece++) { $queue.Enqueue([pscustomobject]@{ Cuts = @($rp.Cuts) + @([pscustomobject]@{ Parts = $factor; Part = $piece }) }) } }
            $cutsMade++
            & $Log 'INFO' ('{0}: its parts are larger than measured -- the {1} part(s) still to read are read as {2}' -f $What, $rest.Count, $queue.Count)
        }
    }
    if ($pages -gt 1) { & $Log 'INFO' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}: read whole in {1} part(s), {2:N0} row(s)', $What, $pages, $rowsRead)) }
    $out = [ordered]@{ Rows = @(); RowCount = $rowsRead; Pages = $pages; Parts = $planned; Cuts = $cutsMade }
    if ($acc) { $out.Rows = $acc.ToArray() }
    [pscustomobject]$out
}
