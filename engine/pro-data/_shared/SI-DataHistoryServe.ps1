#Requires -Version 5.1
<#
    THE READERS ON THE FINDING HISTORY (REQUIREMENTS #1332; docs\DESIGN.md "Finding history model", "The readers"). Owner
    2026-11-23: the NEW model serves, the old model (sidata.Finding, the full builds) is built every run as the check.

    Every reader -- the web app's pages and views, the MCP server, data out, the vulnerability close-loop, the exempted and
    current-findings views -- reads the findings through sidata.vFinding (sql\si-data-schema.sql), which gives a collection back
    from its HISTORY only when this step said so (sidata.HistoryRun.Serves), else from its stored rows. This step, right after
    the history step of the data sync, for every kept collection whose history is 'verified' this run (the collection compared
    row for row, What changed and the summary groups from the change set compared with their full builds):
      1. the page indexes of the history are there (SI-IndexBuild.ps1 $script:SIHistoryIndexes, built in the index-build
         window) -- else the stored rows serve, said, so a page never reads slower than today;
      2. WHAT EACH READER RETURNS is compared: the reader's own statement run twice on the same connection, once forced to the
         stored rows and once to the history (SESSION_CONTEXT 'si.finding.source'), every row as JSON, hashed (SHA-256, byte
         exact, case sensitive) and compared as a multiset -- recorded in sidata.HistoryCompare (Reader 'reader: <name>');
      3. all the same = Serves 1 (the readers read the history); ANY difference = Serves 0, the history row 'differs', a WARNING
         of the run (the fix request; ids, reader names and counts only, never a value) -- that collection's readers read the
         stored rows, and a published run's pointer (PublishedRun.FindingSource) says 'stored'. A difference never publishes
         unverified rows.
    Mode shadow = nothing is served from the history (every Serves 0); off = nothing of this runs (sidata.FindingSourceOf also
    reads the setting, so the readers go back to the stored rows at once). Never fails the data sync.
    PowerShell 5.1 and 7 (no ?. / ??). No PowerShell module.
#>

if (-not (Get-Command -Name ConvertTo-SIFindingSourceSql -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'data-sql', 'SI-FindingSource.ps1')) }
if (-not (Get-Command -Name Get-SIHistoryIndexContract -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-IndexBuild.ps1')) }
# the engine readers whose OWN statements are compared: data out's carried keys (loaded here); the vulnerability close-loop's
# typed page when its file is loaded (the data sync loads it)
$script:SIDataHistoryReaderFiles = @(
    @{ Fn = 'Get-SIDataOutCarryKeysSql';      Path = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-out', 'SI-DataOut.ps1') }
)
$script:SIDataHistoryReaderLoad = @()
foreach ($__f in $script:SIDataHistoryReaderFiles) {
    if (Get-Command -Name $__f.Fn -ErrorAction SilentlyContinue) { continue }
    try { if (Test-Path -LiteralPath $__f.Path) { . $__f.Path } } catch { $script:SIDataHistoryReaderLoad += ('{0} ({1})' -f $__f.Fn, $_.Exception.Message) }
}

function Get-SIDataHistoryRowValue {
    <# One column of a row (hashtable / IDictionary / object), $null when absent. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name]; if ($v -is [System.DBNull]) { return $null }; return $v }; return $null }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { $v = $p.Value; if ($v -is [System.DBNull]) { return $null }; return $v }
    $null
}

function Get-SIDataHistoryReaders {
    <#
        THE READERS WHOSE OUTPUT IS COMPARED EVERY RUN (stored vs history, row for row). Each: Name (<= 23 characters: the
        compare row's Reader is 'reader: <name>'), Surface (who reads it), and EITHER Sql -- a SELECT that can stand as a
        derived table (compared in SQL, any size) -- OR Batch + Params (a reader's own multi-statement batch, compared here
        row by row; only for a bounded reader). Every statement is the reader's OWN text where the reader is engine code (the
        vulnerability close-loop's typed page, data out's carried keys), and the web app's statement shape where it is C#.
        Every one names sidata.Finding / sidata.vExemptedFinding as the reader does: routed exactly as the reader's seam routes it.
    #>
    $out = New-Object System.Collections.Generic.List[object]
    # the web app's raw findings grid, its opening page (CollectionViewSql.Rows + the #812 keyset on the risk score)
    $out.Add([pscustomobject]@{ Name = 'findings page'; Surface = 'web app / MCP: the findings grid'; Sql = @'
SELECT TOP (50) f.FindingId, f.AssetKey, f.AssetName, f.Tier, f.Severity, f.RiskRating, f.RiskScore, f.RiskScoreWeighted, f.Cvss, f.HasExploit,
       f.SecurityDomain, f.ReportName, f.Cve, f.ConfigurationId, f.Title, f.MitreTactics, f.ComplianceTags, f.Category, f.Subcategory, f.DepartmentName, f.ExemptionId
FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId ORDER BY f.RiskScore DESC, f.FindingId
'@ })
    # the CI page: every CI's findings by its key (the one-CI page's seek, for every CI at once)
    $out.Add([pscustomobject]@{ Name = 'CI page'; Surface = 'web app: the CI page, the device page'; Sql = @'
SELECT f.AssetKey, f.FindingId, f.Title, f.Severity, f.Tier, f.RiskScore, f.Cve, f.ConfigurationId, f.ExemptionId, f.CiLifecycle
FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL
'@ })
    # EVERY column the history serves from the member's copies (the page keys and the shown columns): the run's own compare of
    # the collection reconstructs from the states, so this is what proves the copies a page reads
    $keys = @((Get-SIDataHistoryContract).PageKeys | ForEach-Object { 'f.[{0}]' -f $_ }) -join ', '
    $out.Add([pscustomobject]@{ Name = 'served columns'; Surface = 'every page: the columns read from the history''s narrow rows'; Sql = "SELECT f.FindingId, $keys FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId" })    # the key figures and counts a page shows live (by severity, tier, exempted)
    $out.Add([pscustomobject]@{ Name = 'key figures'; Surface = 'web app / MCP: counts by severity and tier'; Sql = @'
SELECT f.Severity, f.Tier, CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END AS Exempted, COUNT_BIG(*) AS Findings, COUNT_BIG(DISTINCT f.AssetKey) AS Assets, MAX(f.RiskScore) AS MaxRisk
FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId GROUP BY f.Severity, f.Tier, CASE WHEN f.ExemptionId IS NULL THEN 0 ELSE 1 END
'@ })
    # the shared exempted view (web app Exempted.cs, the department mails)
    $out.Add([pscustomobject]@{ Name = 'exempted'; Surface = 'web app: the exempted findings'; Sql = 'SELECT x.* FROM sidata.vExemptedFinding AS x WHERE x.CollectionId = @CollectionId' })
    # the vulnerability close-loop's typed page (SI-VulnDesired.ps1, its own statement: every row of the collection)
    if (Get-Command -Name Get-SIVulnSnapshotTypedPageSql -ErrorAction SilentlyContinue) {
        $v = (Get-SIVulnSnapshotTypedPageSql).Trim().TrimEnd(';')
        $out.Add([pscustomobject]@{ Name = 'vuln close-loop'; Surface = 'the vulnerability close-loop (ServiceNow / CMDB items)'; Sql = $v; Params = @{ Take = '2000000000'; After = '0' } })
    }
    # data out's carried keys (SI-DataOut.ps1, its own batch): every report of the collection taken as carried from it
    if (Get-Command -Name Get-SIDataOutCarryKeysSql -ErrorAction SilentlyContinue) {
        $out.Add([pscustomobject]@{ Name = 'data out carry'; Surface = 'data out (the findings outputs: ServiceNow and every connector)'; Batch = (Get-SIDataOutCarryKeysSql); Params = @{ AfterId = '0'; Take = '100000' }; Src = $true })
    }
    $out.ToArray()
}

function Get-SIDataHistoryReaderCompareSql {
    <# PURE. One reader (its Sql) run forced to the stored rows and forced to the history on ONE connection, every row as JSON
       hashed, compared as a multiset. Answers @{ Rows; RowsHistory; Differences }. The source is freed whatever happens. #>
    param([Parameter(Mandatory)][string]$ReaderSql, [long]$CollectionId = 0)
    $r = ConvertTo-SIFindingSourceSql -Sql $ReaderSql
    $one = '[{0}]' -f $CollectionId; $st = Get-SIFindingSourceContextSql -Served '[]' -Stored $one -MaxId $CollectionId; $hi = Get-SIFindingSourceContextSql -Served $one -Stored '[]' -MaxId $CollectionId; $fr = Get-SIFindingSourceContextSql -Clear
    @"
SET NOCOUNT ON;
BEGIN TRY
$st
SELECT * INTO #ra FROM (
$r
) AS q;
$hi
SELECT * INTO #rb FROM (
$r
) AS q;
$fr
END TRY
BEGIN CATCH
$fr
THROW;
END CATCH;
SELECT HASHBYTES('SHA2_256', (SELECT a.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)) AS H INTO #ha FROM #ra AS a;
SELECT HASHBYTES('SHA2_256', (SELECT b.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)) AS H INTO #hb FROM #rb AS b;
SELECT (SELECT COUNT_BIG(*) FROM #ha) AS [Rows], (SELECT COUNT_BIG(*) FROM #hb) AS RowsHistory,
       (SELECT COUNT_BIG(*) FROM (SELECT H, COUNT_BIG(*) AS N FROM #ha GROUP BY H) AS x
        FULL JOIN (SELECT H, COUNT_BIG(*) AS N FROM #hb GROUP BY H) AS y ON y.H = x.H
        WHERE x.H IS NULL OR y.H IS NULL OR x.N <> y.N) AS Differences;
"@
}

function ConvertTo-SIDataHistoryRowText {
    <# PURE. One result row as ordinal text (column names sorted, each value with its type) -- the batch readers' compare. #>
    param($Row)
    $keys = if ($Row -is [System.Collections.IDictionary]) { @($Row.Keys | ForEach-Object { [string]$_ }) } else { @($Row.PSObject.Properties | ForEach-Object { $_.Name }) }
    $a = [string[]]$keys; [Array]::Sort($a, [StringComparer]::Ordinal)
    $sb = New-Object System.Text.StringBuilder
    foreach ($k in $a) {
        $v = Get-SIDataHistoryRowValue $Row $k
        $t = if ($null -eq $v) { 'null' } elseif ($v -is [byte[]]) { 'bin:' + [Convert]::ToBase64String($v) } elseif ($v -is [datetime]) { 'dt:' + $v.ToString('o', [Globalization.CultureInfo]::InvariantCulture) } elseif ($v -is [double] -or $v -is [single]) { 'f:' + ([double]$v).ToString('R', [Globalization.CultureInfo]::InvariantCulture) } elseif ($v -is [IFormattable]) { $v.GetType().Name + ':' + $v.ToString($null, [Globalization.CultureInfo]::InvariantCulture) } else { 's:' + [string]$v }
        [void]$sb.Append($k).Append([char]31).Append($t).Append([char]30)
    }
    $sb.ToString()
}

function Invoke-SIDataHistoryReaderCompare {
    <# Every reader of Get-SIDataHistoryReaders for one collection: stored vs history. Records sidata.HistoryCompare
       'reader: <name>' per reader. Returns @{ Readers = [@{ Name; Rows; Differences; Outcome; Detail }]; Differences }. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [object[]]$Readers)
    if ($null -eq $Readers) { $Readers = @(Get-SIDataHistoryReaders) }
    $c = [string]$CollectionId; $res = New-Object System.Collections.Generic.List[object]; $total = 0L
    foreach ($rd in $Readers) {
        $rows = 0L; $d = 0L; $detail = $null; $outcome = 'same'
        try {
            $p = @{ CollectionId = [int]$CollectionId }
            if ($rd.PSObject.Properties['Params'] -and $rd.Params) { foreach ($k in $rd.Params.Keys) { $p[$k] = $rd.Params[$k] } }
            if ($rd.PSObject.Properties['Src'] -and $rd.Src) {
                $p['src'] = [string](& $Invoke "SET NOCOUNT ON; SELECT (SELECT x.ReportName, CONVERT(int, @C) AS FromId FROM (SELECT DISTINCT f.ReportName FROM sidata.Finding AS f WHERE f.CollectionId = CONVERT(int, @C) AND f.ReportName IS NOT NULL) AS x FOR JSON PATH);" @{ C = $c } 'scalar')
                if (-not $p['src']) { $p['src'] = '[]' }
            }
            if ($rd.PSObject.Properties['Sql'] -and $rd.Sql) {
                $r = @(@(& $Invoke (Get-SIDataHistoryReaderCompareSql -ReaderSql $rd.Sql -CollectionId $CollectionId) $p 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
                $rows = [long](Get-SIDataHistoryRowValue $r 'Rows'); $rh = [long](Get-SIDataHistoryRowValue $r 'RowsHistory'); $d = [long](Get-SIDataHistoryRowValue $r 'Differences')
                if ($d -gt 0) { $detail = ('{0:N0} row(s) stored, {1:N0} from the history, {2:N0} differing' -f $rows, $rh, $d) }
            } else {
                $b = ConvertTo-SIFindingSourceSql -Sql ([string]$rd.Batch)
                $one = '[{0}]' -f $CollectionId; $ctxOf = @{ stored = (Get-SIFindingSourceContextSql -Served '[]' -Stored $one -MaxId $CollectionId); history = (Get-SIFindingSourceContextSql -Served $one -Stored '[]' -MaxId $CollectionId) }
                $run = { param($src) @(@(& $Invoke ($ctxOf[$src] + "`n" + $b) $p 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SIDataHistoryRowText $_ }) }
                try { $sa = [string[]](& $run 'stored'); $sb = [string[]](& $run 'history') }
                finally { try { $null = & $Invoke (Get-SIFindingSourceContextSql -Clear) @{} 'nonquery' } catch { } }
                if ($null -eq $sa) { $sa = [string[]]@() }; if ($null -eq $sb) { $sb = [string[]]@() }
                [Array]::Sort($sa, [StringComparer]::Ordinal); [Array]::Sort($sb, [StringComparer]::Ordinal)
                $rows = $sa.Count
                $i = 0; $j = 0
                while ($i -lt $sa.Count -or $j -lt $sb.Count) {
                    if ($i -ge $sa.Count) { $d++; $j++; continue }; if ($j -ge $sb.Count) { $d++; $i++; continue }
                    $cmp = [string]::CompareOrdinal($sa[$i], $sb[$j])
                    if ($cmp -eq 0) { $i++; $j++ } elseif ($cmp -lt 0) { $d++; $i++ } else { $d++; $j++ }
                }
                if ($d -gt 0) { $detail = ('{0:N0} row(s) stored, {1:N0} from the history, {2:N0} differing' -f $sa.Count, $sb.Count, $d) }
            }
            if ($d -gt 0) { $outcome = 'differs' }
        } catch {
            # a reader that cannot be compared is NOT the same: the collection is not served from its history
            $outcome = 'failed'; $d = [Math]::Max(1L, $d)
            $detail = if (Get-Command -Name Get-SIDataChangedSetSafeError -ErrorAction SilentlyContinue) { Get-SIDataChangedSetSafeError $_ } else { 'the compare could not run' }
        }
        $total += $d
        $name = ('reader: ' + [string]$rd.Name); if ($name.Length -gt 32) { $name = $name.Substring(0, 32) }
        try { $null = & $Invoke "SET NOCOUNT ON; INSERT sidata.HistoryCompare (CollectionId, Reader, [Rows], Differences, Outcome, Detail) VALUES (CONVERT(int, @C), @R, CONVERT(bigint, @N), CONVERT(bigint, @D), @O, @T);" @{ C = $c; R = $name; N = [string]$rows; D = [string]$d; O = $outcome; T = $detail } 'nonquery' } catch { }
        $res.Add([pscustomobject]@{ Name = [string]$rd.Name; Surface = [string]$rd.Surface; Rows = $rows; Differences = $d; Outcome = $outcome; Detail = $detail })
    }
    [pscustomobject]@{ Readers = $res.ToArray(); Differences = $total }
}

function Get-SIDataHistoryServeCandidatesSql {
    <# The kept collections whose history is 'verified' with its marks unmoved (sidata.HistoryStampOf), with whether they are
       served now and whether they were compared since (VerifiedAt after ServedAt = compare its readers again). #>
    @'
SET NOCOUNT ON;
SELECT h.CollectionId, c.CollectionTime, ISNULL(h.Serves, 0) AS Serves,
       CASE WHEN h.ServedAt IS NULL OR h.VerifiedAt > h.ServedAt THEN 1 ELSE 0 END AS Fresh
FROM sidata.HistoryRun AS h
JOIN sidata.Collection AS c ON c.CollectionId = h.CollectionId
CROSS APPLY sidata.HistoryStampOf(h.CollectionId) AS st
WHERE h.State = N'verified' AND h.StampHash = st.Stamp
  AND c.Kind = N'Detailed' AND c.Status = N'Complete' AND c.RetiredAt IS NULL
ORDER BY c.CollectionTime, h.CollectionId;
'@
}

function Get-SIDataHistoryServeSchemaSql {
    "SELECT CASE WHEN OBJECT_ID(N'sidata.vFinding') IS NOT NULL AND OBJECT_ID(N'sidata.FindingSourceOf') IS NOT NULL AND OBJECT_ID(N'sidata.HistoryStampOf') IS NOT NULL AND COL_LENGTH(N'sidata.HistoryRun', N'Serves') IS NOT NULL AND OBJECT_ID(N'sidata.FindingAt') IS NOT NULL THEN 1 ELSE 0 END"
}

function Invoke-SIDataHistoryServe {
    <#
    .SYNOPSIS  After the data sync's history step: which kept collection the readers read from its history (see the file's
               head). Never throws. Returns @{ Status; Mode; Served = [collection ids]; Fallback = [@{ When; Reader; Differences;
               Detail }]; IndexesMissing; Lines }.
    .NOTES     -Readers: the compare's readers (a test passes its own); -Indexes: the page-index state (a test's seam).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Mode = 'on', [scriptblock]$Log, [object[]]$Readers, $Indexes)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $res = [ordered]@{ Status = 'ok'; Mode = $Mode; Served = @(); Fallback = @(); IndexesMissing = @(); Error = $null }
    if ($Mode -eq 'off') { $res.Status = 'off'; return [pscustomobject]$res }
    try {
        if ([string](& $Invoke (Get-SIDataHistoryServeSchemaSql) @{} 'scalar') -ne '1') { $res.Status = 'no-schema'; return [pscustomobject]$res }
        if ($Mode -ne 'on') {
            $null = & $Invoke "SET NOCOUNT ON; EXEC (N'UPDATE sidata.HistoryRun SET Serves = 0 WHERE Serves = 1');" @{} 'nonquery'
            & $Log 'INFO' 'history     : shadow -- the readers read the stored rows (the history is written and compared, never served)'
            $res.Status = 'shadow'; return [pscustomobject]$res
        }
        # a collection whose history is no longer verified or whose marks moved is not served (sidata.FindingSourceOf checks
        # both on every read too; this keeps the flag honest)
        $null = & $Invoke @'
SET NOCOUNT ON;
EXEC (N'UPDATE h SET Serves = 0 FROM sidata.HistoryRun AS h WHERE h.Serves = 1 AND (h.State <> N''verified'' OR NOT EXISTS (SELECT 1 FROM sidata.HistoryStampOf(h.CollectionId) AS st WHERE st.Stamp = h.StampHash))');
'@ @{} 'nonquery'
        if ($null -eq $Indexes) { $Indexes = Read-SIHistoryIndexState -Invoke $Invoke }
        $cands = @(@(& $Invoke (Get-SIDataHistoryServeCandidatesSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $Indexes.Known -or @($Indexes.Missing).Count) {
            $res.IndexesMissing = @($Indexes.Missing)
            $null = & $Invoke "SET NOCOUNT ON; EXEC (N'UPDATE sidata.HistoryRun SET Serves = 0 WHERE Serves = 1');" @{} 'nonquery'
            & $Log 'INFO' ("history     : the readers read the stored rows until the history's page indexes are built in the index-build window ({0} of {1} not there yet) -- a page never reads slower than today" -f @($Indexes.Missing).Count, @(Get-SIHistoryIndexContract).Count)
            return [pscustomobject]$res
        }
        $served = New-Object System.Collections.Generic.List[long]; $fall = New-Object System.Collections.Generic.List[object]
        foreach ($cd in $cands) {
            $cid = [long](Get-SIDataHistoryRowValue $cd 'CollectionId'); $when = Get-SIDataHistoryRowValue $cd 'CollectionTime'
            $whenText = if ($when -is [datetime]) { $when.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { [string]$when }
            if ([int](Get-SIDataHistoryRowValue $cd 'Serves') -eq 1 -and [int](Get-SIDataHistoryRowValue $cd 'Fresh') -eq 0) { $served.Add($cid); continue }
            $cmp = Invoke-SIDataHistoryReaderCompare -Invoke $Invoke -CollectionId $cid -Readers $Readers
            if ($cmp.Differences -eq 0) {
                $null = & $Invoke "SET NOCOUNT ON; EXEC sys.sp_executesql N'UPDATE sidata.HistoryRun SET Serves = 1, ServedAt = SYSUTCDATETIME() WHERE CollectionId = CONVERT(int, @C) AND State = N''verified''', N'@C nvarchar(20)', @C = @C;" @{ C = [string]$cid } 'nonquery'
                $served.Add($cid)
                & $Log 'OK' ("history     : the collection of {0} is read from its history -- what {1} reader(s) return compared with the stored rows: the same ({2})" -f $whenText, @($cmp.Readers).Count, ((@($cmp.Readers) | ForEach-Object { '{0} {1:N0}' -f $_.Name, $_.Rows }) -join ', '))
            } else {
                $bad = @($cmp.Readers | Where-Object { $_.Differences -gt 0 })
                $text = ((@($bad) | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Detail }) -join '; '); if ($text.Length -gt 900) { $text = $text.Substring(0, 897) + '...' }
                $null = & $Invoke "SET NOCOUNT ON; EXEC sys.sp_executesql N'UPDATE sidata.HistoryRun SET Serves = 0, State = N''differs'', Differences = ISNULL(Differences, 0) + CONVERT(bigint, @D), Diff = LEFT(CONCAT(Diff, N'' readers: '', @T), 1000) WHERE CollectionId = CONVERT(int, @C)', N'@C nvarchar(20), @D nvarchar(20), @T nvarchar(1000)', @C = @C, @D = @D, @T = @T;" @{ C = [string]$cid; D = [string]$cmp.Differences; T = $text } 'nonquery'
                $fall.Add([pscustomobject]@{ When = $whenText; Reader = ((@($bad) | ForEach-Object { $_.Name }) -join ', '); Differences = $cmp.Differences; Detail = $text })
                & $Log 'WARN' ("history     : the collection of {0}: what its readers return differed between the history and the stored rows ({1}) -- its readers read the stored rows; nothing different was published" -f $whenText, $text)
            }
        }
        $res.Served = $served.ToArray(); $res.Fallback = $fall.ToArray()
    } catch {
        $res.Status = 'failed'
        $res.Error = if (Get-Command -Name Get-SIDataChangedSetSafeError -ErrorAction SilentlyContinue) { Get-SIDataChangedSetSafeError $_ } else { 'the step could not run' }
        try { $null = & $Invoke "SET NOCOUNT ON; IF COL_LENGTH(N'sidata.HistoryRun', N'Serves') IS NOT NULL EXEC (N'UPDATE sidata.HistoryRun SET Serves = 0 WHERE Serves = 1');" @{} 'nonquery' } catch { }
        & $Log 'WARN' ("history     : which collection the readers read from the history was not decided this run ({0}) -- they read the stored rows" -f $res.Error)
    }
    [pscustomobject]$res
}

function Get-SIDataHistoryServeWarningText {
    <# PURE. The run's warnings for the serve step (the fix request): reader names, counts and ids only, never a value. #>
    param($Result)
    if ($null -eq $Result) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($f in @(Get-SIDataHistoryRowValue $Result 'Fallback')) {
        if (-not $f) { continue }
        $out.Add(('what the readers return from the finding history of the collection of {0} differed from the stored rows ({1} -- {2:N0} difference(s): {3}) -- that collection''s pages, connectors and views read the stored rows; nothing different was published' -f (Get-SIDataHistoryRowValue $f 'When'), (Get-SIDataHistoryRowValue $f 'Reader'), [long](Get-SIDataHistoryRowValue $f 'Differences'), (Get-SIDataHistoryRowValue $f 'Detail')))
    }
    if ([string](Get-SIDataHistoryRowValue $Result 'Status') -eq 'failed') {
        $out.Add(('which collection the readers read from the finding history was not decided this run ({0}) -- they read the stored rows' -f (Get-SIDataHistoryRowValue $Result 'Error')))
    }
    $out.ToArray()
}
