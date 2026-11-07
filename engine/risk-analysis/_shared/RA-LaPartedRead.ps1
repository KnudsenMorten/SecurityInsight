#Requires -Version 5.1
#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  #690 (37): a Log Analytics partial answer read for what it says, and a result too large for one answer read in parts.
#  Loaded by RA-LogAnalyticsQuery.ps1 (which uses the verdict) and by RA-ProfileAugment.ps1 / RA-GraphHunting.ps1 (which
#  read through Invoke-LogAnalyticsKqlQueryParted), each guarded, so every file still loads on its own (tests).
#  PowerShell 5.1-safe: no ternary, no null-conditional.
#######################################################################################################

# ---------------------------------------------------------------------------------------------------------------------
# #690 (37) -- A PARTIAL ANSWER FROM LOG ANALYTICS, READ FOR WHAT IT SAYS; A RESULT TOO LARGE FOR ONE ANSWER, READ IN PARTS.
# ---------------------------------------------------------------------------------------------------------------------
function Get-RALaPartialVerdict {
    <#
        PURE. What a Log Analytics partial answer (the "error" object of an HTTP 200 answer) says. Its LEAVES (the innermost
        error objects, under details[] / innererror) carry the real cause; the outer ones are generic ("There were some errors
        when processing your query." / "Something went wrong processing your query on the server."). Returns
        @{ Kind; Code; Detail; Tables }:
          Unresolved -- every leaf is "Failed to resolve table or column expression named 'SI_..._CL'": a `union isfuzzy=true`
                        leg over a SecurityInsight table this workspace does not have (proven on internal Log Analytics
                        2026-10-15: PartialError, innererror severity Warning, the other legs' rows in the answer). The
                        answer is the WHOLE result -- the missing table has no rows. Tables = the names.
          Limit      -- a leaf (or the error) names a limit: a result over the row / size limit, a part that ran out of time
                        or memory. The answer is short: the slice is made smaller / the read is cut into parts.
          Other      -- anything else. The answer is short and the cause is not one a smaller slice fixes.
    #>
    param([AllowNull()][object]$ErrorObject)
    $leaves = New-Object System.Collections.Generic.List[string]
    $all = New-Object System.Collections.Generic.List[string]
    $codes = New-Object System.Collections.Generic.List[string]
    $get = {
        param($o, $n)
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { return $o[$n] }; return $null }
        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value }; return $null
    }
    $stack = New-Object System.Collections.Stack
    if ($null -ne $ErrorObject -and $ErrorObject -isnot [string]) { $stack.Push($ErrorObject) }
    $visited = 0
    while ($stack.Count -gt 0 -and $visited -lt 256) {
        $o = $stack.Pop(); $visited++
        if ($null -eq $o -or $o -is [string]) { continue }
        $m = [string](& $get $o 'message'); $c = [string](& $get $o 'code')
        if ($c -and $codes.Count -lt 3 -and -not $codes.Contains($c)) { $codes.Add($c) }
        if ($m) { $all.Add($m) }
        $children = New-Object System.Collections.Generic.List[object]
        $ie = & $get $o 'innererror'; if ($null -ne $ie -and $ie -isnot [string]) { $children.Add($ie) }
        $ds = & $get $o 'details'
        if ($null -ne $ds) { foreach ($d in @($ds)) { if ($null -ne $d -and $d -isnot [string]) { $children.Add($d) } } }
        if ($children.Count -eq 0) { if ($m) { $leaves.Add($m) } }
        else { for ($i = $children.Count - 1; $i -ge 0; $i--) { $stack.Push($children[$i]) } }
    }
    if ($null -ne $ErrorObject -and $ErrorObject -is [string]) { $leaves.Add([string]$ErrorObject); $all.Add([string]$ErrorObject) }
    $generic = '^(There were some errors when processing your query\.?|Something went wrong processing your query on the server\.?)$'
    $specific = @($all | Where-Object { $_ -notmatch $generic } | Select-Object -Unique)
    $detail = (@($specific) -join '; ')
    if (-not $detail) { $detail = (@($all | Select-Object -Unique) -join '; ') }
    if ($detail.Length -gt 400) { $detail = $detail.Substring(0, 400) + '...' }
    $code = (@($codes) -join '/')
    # a 'union' leaf says "table expression", a 'where' leaf "table or column expression" (both: the table is not there)
    $rx = "Failed to resolve table (?:or column )?expression named '(?<t>SI_[A-Za-z0-9_]+_CL)'"
    $tables = New-Object System.Collections.Generic.List[string]
    $leafSpecific = @($leaves | Where-Object { $_ -notmatch $generic })
    $allResolve = ($leafSpecific.Count -gt 0)
    foreach ($l in $leafSpecific) {
        $mm = [regex]::Match($l, $rx)
        if (-not $mm.Success) { $allResolve = $false; break }
        if (-not $tables.Contains($mm.Groups['t'].Value)) { $tables.Add($mm.Groups['t'].Value) }
    }
    if ($allResolve) { return @{ Kind = 'Unresolved'; Code = $code; Detail = $detail; Tables = $tables.ToArray() } }
    $limitRx = '(?i)limit|exceeded|too large|E_QUERY_RESULT_SET_TOO_LARGE|timed out|timeout|E_RUNAWAY|out of memory|memory|truncat|cancell?ed|preempted'
    if (@($all | Where-Object { $_ -match $limitRx }).Count -gt 0) { return @{ Kind = 'Limit'; Code = $code; Detail = $detail; Tables = @() } }
    return @{ Kind = 'Other'; Code = $code; Detail = $detail; Tables = @() }
}

function New-RALaPartialError {
    <# The error a refused partial answer becomes. Limit: worded "Query execution has exceeded the allowed limits" -- the
       text the bucket logic makes the slice SMALLER on (Test-IsBucketOverflowError). Other: the service's own words, never
       that text (a smaller slice does not fix it). Marked in its Data: SIRALaPartial = the kind, SIRALaPartialRows = the
       rows the short answer held (what Invoke-RALaPartedRead measures). #>
    param([Parameter(Mandatory)][hashtable]$Verdict, [long]$Rows = 0)
    $msg = if ($Verdict.Kind -eq 'Limit') {
        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- Query execution has exceeded the allowed limits; the rows it returned are not the whole result" -f $Verdict.Code, $Verdict.Detail
    } else {
        "Log Analytics returned a PARTIAL answer ({0}: {1}) -- the rows it returned are not the whole result" -f $Verdict.Code, $Verdict.Detail
    }
    $ex = New-Object System.InvalidOperationException($msg)
    $ex.Data['SIRALaPartial'] = [string]$Verdict.Kind
    $ex.Data['SIRALaPartialRows'] = [long]$Rows
    return $ex
}

function Write-RALaUnresolvedNote {
    <# Once per table and run: the SI table a query reads where it exists is not in this workspace -- read as no rows. #>
    param([string[]]$Tables = @())
    if (-not $script:_RALaUnresolvedSaid) { $script:_RALaUnresolvedSaid = @{} }
    foreach ($t in @($Tables)) {
        if (-not $t -or $script:_RALaUnresolvedSaid.ContainsKey($t)) { continue }
        $script:_RALaUnresolvedSaid[$t] = $true
        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
            Write-Info ("{0} does not exist in Log Analytics yet -- the queries that read it where it exists read it as no rows" -f $t)
        }
    }
}

function Test-RALaLimitPartialError {
    <# PURE. True for a partial answer refused as too large (New-RALaPartialError, kind Limit), as an ErrorRecord, an
       exception or its text. #>
    param([AllowNull()][object]$Err)
    if ($null -eq $Err) { return $false }
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('SIRALaPartial')) { return ([string]$ex.Data['SIRALaPartial'] -eq 'Limit') }
        $ex = $ex.InnerException
    }
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { [string]$Err.Exception.Message } else { [string]$Err }
    return ($msg -match 'Log Analytics returned a PARTIAL answer.*Query execution has exceeded the allowed limits')
}

function Get-RALaPartialRowCount {
    <# PURE. The rows the refused short answer held (-1 when not known). #>
    param([AllowNull()][object]$Err)
    $ex = $null
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $ex = $Err.Exception } elseif ($Err -is [System.Exception]) { $ex = $Err }
    while ($null -ne $ex) {
        if ($ex.Data -and $ex.Data.Contains('SIRALaPartialRows')) { return [long]$ex.Data['SIRALaPartialRows'] }
        $ex = $ex.InnerException
    }
    return -1L
}

function Get-RALaPartQuery {
    <# PURE. Part -Part of -Parts of a query's RESULT: the query, then one filter on a hash of each whole result row. The
       parts are disjoint and together hold every row of the query (a row is in exactly one part). Trailing comment lines
       and semicolons are taken off first, so the filter follows the last tabular statement. #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][int]$Parts, [Parameter(Mandatory)][int]$Part)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($l in ($Query -split "`r?`n")) { $lines.Add($l) }
    while ($lines.Count -gt 0) {
        $t = $lines[$lines.Count - 1].Trim()
        if ($t -eq '' -or $t.StartsWith('//')) { $lines.RemoveAt($lines.Count - 1); continue }
        if ($t.EndsWith(';')) { $lines[$lines.Count - 1] = $lines[$lines.Count - 1].TrimEnd().TrimEnd(';'); continue }
        break
    }
    $nl = [Environment]::NewLine
    return (($lines -join $nl) + $nl + ('| where abs(hash(tostring(pack_all())) % {0}) == {1}' -f $Parts, $Part))
}

function Get-RALaSourcePartition {
    <#
        PURE. #1107 (live 2026-11-04, a large install: the CI lookup _ciPeer ran Log Analytics out of memory --
        E_LOW_MEMORY_CONDITION -- in 1 part and in 2, because Get-RALaPartQuery cuts a query's RESULT: every part built the
        whole lookup before its filter, so more parts could not help). A CI block (RA-CiKql.ps1) can be cut at its SOURCE:
        right after the core's `| where isnotempty(_ciId)` each part keeps only its share of the CIs, so it builds 1/N of
        the lookup. The core keeps the CIs of the newest build only, so every CI has the same _ciBuild and the block's
        last `arg_max(_ciBuild, *) by _ciKey` is a tie among them: a key two CIs share in different parts is kept ONCE
        after the parts are merged (the first one), which is what the whole query keeps. Returns @{ Can; Anchor;
        DedupeColumn } -- Can = $false for any other query (it keeps the result cut).
    #>
    param([AllowEmptyString()][string]$Query = '')
    $anchor = '| where isnotempty(_ciId)'
    $no = [pscustomobject]@{ Can = $false; Anchor = ''; DedupeColumn = '' }
    if (-not "$Query".Contains($anchor)) { return $no }
    # one CI core only (a query with two cores is not cut at the source -- each would need its own filter)
    if (([regex]::Matches($Query, [regex]::Escape($anchor))).Count -ne 1) { return $no }
    $dedupe = ''
    if ($Query -match '\|\s*project\s+_peerKey\s*=\s*_ciKey\b') { $dedupe = '_peerKey' }
    elseif ($Query -match '\|\s*project\s+_ciKey\s*,') { $dedupe = '_ciKey' }
    elseif ($Query -match '\|\s*project\s+si_ci_id\s*=\s*_ciId\b') { $dedupe = 'si_ci_id' }
    else { return $no }   # a CI core whose output key is not known here: the result cut, as before
    [pscustomobject]@{ Can = $true; Anchor = $anchor; DedupeColumn = $dedupe }
}

function Get-RALaSourcePartQuery {
    <# PURE. Part -Part of -Parts of a CI block cut at its SOURCE (Get-RALaSourcePartition): the filter on a hash of the
       CI id goes right after the core's anchor line. Every CI is in exactly one part. #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][int]$Parts, [Parameter(Mandatory)][int]$Part)
    $anchor = '| where isnotempty(_ciId)'
    $i = $Query.IndexOf($anchor)
    if ($i -lt 0) { throw 'not a CI block: no source to cut' }
    $end = $i + $anchor.Length
    $Query.Substring(0, $end) + (' | where abs(hash(_ciId)) % {0} == {1}' -f $Parts, $Part) + $Query.Substring($end)
}

function New-RALaTooLargeError {
    <# si-ra-0302 (too-large): no number of parts makes the read fit. Marked like the "no slice count can make this report
       fit" error (Data SIRALookupTooLarge), so the bucket loop ends the report at once -- not complete, its findings
       unknown, never fewer rows stored as whole -- and the run goes on. #>
    param([Parameter(Mandatory)][string]$Message)
    $ex = New-Object System.InvalidOperationException($Message)
    $ex.Data['SIRALookupTooLarge'] = $true
    $ex.Data['SIRACode'] = 'si-ra-0302'
    return $ex
}

function Invoke-RALaPartedRead {
    <#
        #690 (37). A Log Analytics read whose answer comes back SHORT for a limit (Test-RALaLimitPartialError) is read again
        in parts (Get-RALaPartQuery): 2, then 4, 8 ... -- every part must come back whole, and the rows of all parts are the
        result. MEASURED stop, never a cap: when two counts in a row each had a part refused with NO rows at all, the limit
        is the work of the query itself, which every part repeats -- more parts cannot help, and the read fails as too large
        (si-ra-0302). A short answer that held rows is a result over the size limit, which more parts do shrink.
        Any other error is passed on as it is. -Read { param($Kql) rows } is the reader (and the seam for tests).
        Returns @{ Rows; Parts }.
    #>
    param([Parameter(Mandatory)][string]$Query, [Parameter(Mandatory)][scriptblock]$Read, [string]$What = 'the query', [int]$Parts = 1,
          # #1107: the wait before a part refused for the SERVICE's low memory is asked again (the seam for tests)
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $n = [Math]::Max(1, $Parts)
    # #1107 (live 2026-11-04, a large install: the CI lookup refused with E_LOW_MEMORY_CONDITION during a run, and read
    # whole in 6 s an hour later): Log Analytics' OWN low-memory condition is the service's state at that moment, not the
    # size of the query -- the same part is asked again after a wait (30 s, 60 s, 120 s) before it counts as a refusal
    $busyWaits = @(30, 60, 120)
    $busyRx = '(?i)E_LOW_MEMORY_CONDITION|Low memory condition'
    $emptyRefusals = 0
    # #1107: a CI block is cut at its SOURCE (each part builds 1/N of it, so more parts DO shrink the work); any other query
    # keeps the result cut. The measured stop follows: a result cut repeats the whole work in every part, so two counts in a
    # row refused with no rows end it; a source cut halves the work with every doubling, so it ends only after FOUR such
    # doublings in a row -- the work then is not the CIs' (measured, never a cap on the parts)
    $src = Get-RALaSourcePartition -Query $Query
    $stopAfter = if ($src.Can) { 4 } else { 2 }
    while ($true) {
        $acc = New-Object System.Collections.Generic.List[object]
        $refused = $null
        for ($i = 0; $i -lt $n; $i++) {
            $q = if ($n -eq 1) { $Query } elseif ($src.Can) { Get-RALaSourcePartQuery -Query $Query -Parts $n -Part $i } else { Get-RALaPartQuery -Query $Query -Parts $n -Part $i }
            $got = $null; $busy = 0
            while ($true) {
                try { $got = & $Read $q; break }
                catch {
                    if (-not (Test-RALaLimitPartialError -Err $_)) { throw }
                    if ("$($_.Exception.Message)" -match $busyRx -and $busy -lt $busyWaits.Count) {
                        $w = $busyWaits[$busy]; $busy++
                        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
                            Write-Info ("{0}: Log Analytics was short of memory for it -- asked again in {1} s ({2} of {3})" -f $What, $w, $busy, $busyWaits.Count)
                        }
                        & $Sleep $w
                        continue
                    }
                    $refused = $_; break
                }
            }
            if ($null -ne $refused) { break }
            foreach ($x in @($got)) { if ($null -eq $x) { continue }; if ($x -is [array]) { foreach ($y in $x) { if ($null -ne $y) { $acc.Add($y) } } } else { $acc.Add($x) } }
        }
        if ($null -eq $refused) {
            # a source cut: a key two CIs share in different parts came back once from each -- kept ONCE (see the header of
            # Get-RALaSourcePartition: those rows are a tie the whole query also resolves to one)
            if ($n -gt 1 -and $src.Can -and $src.DedupeColumn) {
                $seen = New-Object 'System.Collections.Generic.HashSet[string]'
                $kept = New-Object System.Collections.Generic.List[object]
                foreach ($r in $acc) {
                    $k = if ($r -is [System.Collections.IDictionary]) { [string]$r[$src.DedupeColumn] } elseif ($r.PSObject.Properties[$src.DedupeColumn]) { [string]$r.($src.DedupeColumn) } else { $null }
                    if ($null -eq $k -or $seen.Add($k)) { $kept.Add($r) }
                }
                $acc = $kept
            }
            if ($n -gt 1 -and (Get-Command -Name Write-Info -ErrorAction SilentlyContinue)) {
                Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0} was read in {1} parts ({2:N0} row(s)) -- one answer could not carry it", $What, $n, $acc.Count))
            }
            return @{ Rows = $acc.ToArray(); Parts = $n }
        }
        if ((Get-RALaPartialRowCount -Err $refused) -le 0) { $emptyRefusals++ } else { $emptyRefusals = 0 }
        if ($emptyRefusals -ge $stopAfter) {
            throw (New-RALaTooLargeError -Message ("{0} is more than Log Analytics can answer: read in {1} part(s), a part still stopped at the service's limit before it returned a row, so reading it in more parts cannot make it fit -- {2}" -f $What, $n, (($refused.Exception.Message -split "`n") | Select-Object -First 1)))
        }
        $n = $n * 2
        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
            Write-Info ("{0} is larger than one Log Analytics answer can carry -- reading it again in {1} parts (nothing of the short answer is kept)" -f $What, $n)
        }
    }
}

function Invoke-LogAnalyticsKqlQueryParted {
    <# Invoke-LogAnalyticsKqlQuery, read in parts when one answer is too short for a limit (Invoke-RALaPartedRead). The
       same return shape: the rows array, comma-protected (assign it, never wrap the call in @()). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$Query, [string]$What = 'the query')
    $__laWs = $WorkspaceResourceId
    # (assigned, then handed on as ONE array: the reader answers `,@(rows)`)
    $r = Invoke-RALaPartedRead -Query $Query -What $What -Read { param($q) $laRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $__laWs -Query $q; , $laRows }
    return , @($r.Rows)
}
