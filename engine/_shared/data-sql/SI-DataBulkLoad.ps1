#Requires -Version 5.1
<#
    SecurityInsight Pro -- BULK LOAD (#1336, SCALE-3 #1330 track D; the unbuilt part of #1322).

    The large writes -- Risk Analysis' rows (sidata.Finding, sidata.SummaryRow / SummaryAsset, the Summary stage
    sidata.RaStage), the staging of the findings per CI before the swap (sidata.CiFindingStage), the data out's summary
    staging (sidata.DataOutSummaryStage) -- travel to the database through SqlBulkCopy instead of one large JSON parameter
    per chunk:

      * ONE MAPPING, NEVER A SECOND. The rows are the SAME JSON object texts the JSON path sends, bulk-copied into a session
        table (#SIBulkRows: Seq, J -- in tempdb, TABLOCK, minimally logged), and the SAME insert statement reads them:
        "FROM OPENJSON(@j) WITH (...) x" becomes "FROM #SIBulkRows AS sib CROSS APPLY OPENJSON(sib.J) WITH (...) x" and an
        INSERT keeps the items' order (ORDER BY sib.Seq). Every column is worked out by exactly the statement of before
        (ConvertTo-SIDataBulkSql), so the stored rows are the same rows.
      * ONE TRANSACTION PER BATCH. A batch is copied, its COUNT and CONTENT HASH read back from the session table and
        compared with what was sent (the sum of the first 4 bytes of SHA-256 over "<seq>|<text>" per row -- the database's
        HASHBYTES of the same UTF-16 text), then the statement runs and its own count must equal the batch's; only then is
        the batch committed. Any difference rolls the batch back and it is REDONE once; a second difference FAILS the load
        (the caller's step fails as with the JSON path) -- never a part of a batch, never a partial load said to be whole.
      * THE BATCH SIZE IS MEASURED, never fixed: the characters per batch follow the measured time of the last batch
        (Get-SIDataNextSize, at most double per batch, smaller at once when slow), and the database's own load paces them
        (SI-SqlPacing.ps1) -- the rules of the JSON path.
      * THE HASH AND THE ROWS IN COMPILED .NET (COMPILED-HOT-PATH-1: compiled from SI's own source by Add-Type inside SI's
        image, no package, no module, no binary in git); where it cannot be compiled, a PowerShell twin works out the same
        hash (tested equal).

    SETTING SI_Data_BulkLoad: on (the default -- the same statement over the same texts, checked per batch) | shadow (the
    batch is copied and its count and hash checked, then rolled back, and the rows are written the JSON way; a difference
    is a WARNING line -- the run's report opens a fix request -- and the JSON way serves) | off (the JSON way, as before).
    A seam that cannot copy in bulk (a test's fake database; a statement not in the OPENJSON shape) writes the JSON way.

    PS 5.1 safe (the compiled part is C# 5).
#>

$script:SIDataBulkHashSql = "SELECT COUNT_BIG(*) AS N, ISNULL(SUM(CAST(CAST(SUBSTRING(HASHBYTES('SHA2_256', CONCAT(CONVERT(nvarchar(20), Seq), N'|', J)), 1, 4) AS int) AS bigint)), 0) AS H FROM #SIBulkRows;"
$script:SIDataBulkTableSql = "IF OBJECT_ID('tempdb..#SIBulkRows') IS NULL CREATE TABLE #SIBulkRows (Seq int NOT NULL PRIMARY KEY CLUSTERED, J nvarchar(max) NOT NULL);"
# the batch key (sidata.ViewState 'bulk:<32 hex>', written in the batch's transaction); its read after a commit that did not answer;
# its removal; the keys older than a day
$script:SIDataBulkMarkSql = "INSERT sidata.ViewState (Name, Value) VALUES (@Name, @Value);"
$script:SIDataBulkMarkReadSql = "SELECT COUNT_BIG(*) FROM sidata.ViewState WHERE Name = @Name;"
$script:SIDataBulkMarkDeleteSql = "DELETE FROM sidata.ViewState WHERE Name = @Name;"
$script:SIDataBulkMarkReadySql = "SELECT CASE WHEN OBJECT_ID('sidata.ViewState') IS NOT NULL THEN 1 ELSE 0 END;"
$script:SIDataBulkMarkPurgeSql = "IF OBJECT_ID('sidata.ViewState') IS NOT NULL DELETE TOP (1000) FROM sidata.ViewState WHERE Name LIKE N'bulk:%' AND UpdatedAt < DATEADD(day, -1, SYSUTCDATETIME());"

function Get-SIDataBulkSource {
    <# The compiled helper's source (C# 5): the content hash of a batch and the batch as a table for SqlBulkCopy. #>
    @'
namespace SecurityInsight.Bulk {
    public static class SIBulkRows {
        // the sum of the first 4 bytes (big-endian, signed) of SHA-256 over the UTF-16 text "<seq>|<item>", seq 1-based
        public static long HashSum(string[] items, int offset, int count) {
            long sum = 0;
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create()) {
                for (int i = 0; i < count; i++) {
                    string it = items[offset + i];
                    if (it == null) { throw new System.ArgumentException("a row to load is empty"); }
                    string t = (i + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + "|" + it;
                    byte[] h = sha.ComputeHash(System.Text.Encoding.Unicode.GetBytes(t));
                    int v = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
                    sum += v;
                }
            }
            return sum;
        }
        public static System.Data.DataTable ToTable(string[] items, int offset, int count) {
            System.Data.DataTable dt = new System.Data.DataTable("SIBulkRows");
            dt.Columns.Add("Seq", typeof(int));
            dt.Columns.Add("J", typeof(string));
            dt.BeginLoadData();
            for (int i = 0; i < count; i++) { dt.Rows.Add(i + 1, items[offset + i]); }
            dt.EndLoadData();
            return dt;
        }
    }
}
'@
}

function Import-SIDataBulkHelper {
    <# Compiles the helper once per process. $true when the compiled helper is there; $false = the PowerShell twin. Never throws. #>
    if ('SecurityInsight.Bulk.SIBulkRows' -as [type]) { return $true }
    if ($script:SIDataBulkCompileFailed) { return $false }
    try { Add-Type -TypeDefinition (Get-SIDataBulkSource) -Language CSharp -ErrorAction Stop; return [bool]('SecurityInsight.Bulk.SIBulkRows' -as [type]) }
    catch { $script:SIDataBulkCompileFailed = $true; return $false }
}

function Get-SIDataBulkEngine {
    <# 'compiled' (the C# helper) or 'powershell' (its twin) -- what this process works the hash and rows out with. #>
    if (Import-SIDataBulkHelper) { 'compiled' } else { 'powershell' }
}

function Get-SIDataBulkHashSum {
    <# The content hash of -Count items from -Offset (see the header). -Engine powershell: the twin (tests compare the two). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [int]$Offset = 0, [int]$Count = -1, [ValidateSet('', 'compiled', 'powershell')][string]$Engine = '')
    if ($Count -lt 0) { $Count = $Items.Count - $Offset }
    $useCompiled = $(if ($Engine) { $Engine -eq 'compiled' } else { Import-SIDataBulkHelper })
    if ($useCompiled) { if (-not (Import-SIDataBulkHelper)) { throw 'the compiled bulk helper is not available' }; return [long][SecurityInsight.Bulk.SIBulkRows]::HashSum($Items, $Offset, $Count) }
    $sum = 0L
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            $it = $Items[$Offset + $i]
            if ($null -eq $it) { throw 'a row to load is empty' }
            $h = $sha.ComputeHash([System.Text.Encoding]::Unicode.GetBytes(([string]($i + 1)) + '|' + $it))
            $v = [int][System.BitConverter]::ToInt32([byte[]]@($h[3], $h[2], $h[1], $h[0]), 0)
            $sum += [long]$v
        }
    } finally { $sha.Dispose() }
    $sum
}

function ConvertTo-SIDataBulkTable {
    <# -Count items from -Offset as the table SqlBulkCopy writes (Seq 1-based, J the text). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [int]$Offset = 0, [int]$Count = -1)
    if ($Count -lt 0) { $Count = $Items.Count - $Offset }
    if (Import-SIDataBulkHelper) { return , ([SecurityInsight.Bulk.SIBulkRows]::ToTable($Items, $Offset, $Count)) }
    $dt = New-Object System.Data.DataTable 'SIBulkRows'
    [void]$dt.Columns.Add('Seq', [int]); [void]$dt.Columns.Add('J', [string])
    $dt.BeginLoadData()
    for ($i = 0; $i -lt $Count; $i++) { [void]$dt.Rows.Add(($i + 1), $Items[$Offset + $i]) }
    $dt.EndLoadData()
    , $dt
}

function Get-SIDataBulkLoadMode {
    <# PURE. SI_Data_BulkLoad: on (the default, and anything unknown) | shadow | off. #>
    param($Value = $global:SI_Data_BulkLoad)
    if ($Value -is [bool]) { if ($Value) { return 'on' } else { return 'off' } }
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -in 'off', 'false', '0', 'no') { return 'off' }
    if ($v -eq 'shadow') { return 'shadow' }
    'on'
}

function ConvertTo-SIDataBulkSql {
    <#
        PURE. -Sql (a writer that reads its rows as "FROM OPENJSON(@<JsonParam>) WITH (...) <alias>", the parameter used
        exactly once) as the same statement over the session table: "FROM #SIBulkRows AS sib CROSS APPLY OPENJSON(sib.J)
        WITH (...) <alias>"; an INSERT keeps the items' order ("ORDER BY sib.Seq" before the statement's end). $null when the
        statement is not in that shape (it is then written the JSON way).
    #>
    param([Parameter(Mandatory)][string]$Sql, [ValidatePattern('^\w+$')][string]$JsonParam = 'j')
    $needle = 'FROM OPENJSON(@' + $JsonParam + ') WITH ('
    if (([regex]::Matches($Sql, '@' + $JsonParam + '\b')).Count -ne 1) { return $null }
    $at = $Sql.IndexOf($needle, [StringComparison]::Ordinal)
    if ($at -lt 0) { return $null }
    $open = $at + $needle.Length - 1
    # the WITH list's closing bracket (quotes skipped)
    $depth = 0; $i = $open; $close = -1; $inQ = $false
    while ($i -lt $Sql.Length) {
        $ch = $Sql[$i]
        if ($inQ) { if ($ch -eq "'") { $inQ = $false } }
        elseif ($ch -eq "'") { $inQ = $true }
        elseif ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') { $depth--; if ($depth -eq 0) { $close = $i; break } }
        $i++
    }
    if ($close -lt 0) { return $null }
    # the statement's end: the next ';' outside quotes, brackets and line comments
    $depth = 0; $i = $close + 1; $end = -1; $inQ = $false
    while ($i -lt $Sql.Length) {
        $ch = $Sql[$i]
        if (-not $inQ -and $ch -eq '-' -and $i + 1 -lt $Sql.Length -and $Sql[$i + 1] -eq '-') {
            $nl = $Sql.IndexOf("`n", $i); if ($nl -lt 0) { break }; $i = $nl + 1; continue
        }
        if ($inQ) { if ($ch -eq "'") { $inQ = $false } }
        elseif ($ch -eq "'") { $inQ = $true }
        elseif ($ch -eq '(') { $depth++ }
        elseif ($ch -eq ')') { $depth-- }
        elseif ($ch -eq ';' -and $depth -eq 0) { $end = $i; break }
        $i++
    }
    if ($end -lt 0) { return $null }
    # an INSERT: the statement that holds the FROM starts with INSERT (after the previous ';')
    $prev = $Sql.LastIndexOf(';', $at)
    $head = $Sql.Substring($prev + 1, $at - $prev - 1)
    $isInsert = [regex]::IsMatch($head, '\A\s*INSERT\b', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $out = $Sql.Substring(0, $at) + 'FROM #SIBulkRows AS sib CROSS APPLY OPENJSON(sib.J) WITH (' + $Sql.Substring($at + $needle.Length, $end - $at - $needle.Length)
    if ($isInsert) { $out = $out.TrimEnd() + ' ORDER BY sib.Seq' }
    $out + $Sql.Substring($end)
}

function Test-SIDataBulkSeam {
    <# The seam can copy in bulk: it hands out an open connection (New-SIDataSqlInvoke's SIBulkOpen; a test's own). #>
    param($Invoke)
    [bool]($null -ne $Invoke -and $Invoke.PSObject.Properties['SIBulkOpen'] -and $Invoke.SIBulkOpen -is [scriptblock])
}

function Invoke-SIDataBulkBatch {
    <#
        ONE batch in ONE transaction on -Connection: copied into #SIBulkRows, count + hash read back and compared, then
        (-Verify not set) -BulkSql run and its count compared; committed only when all agree, else rolled back. Returns
        @{ Ok; Why; Rows }. Errors of the database are thrown (the caller decides on a redo).
        -TestHook { param($Connection, $Transaction) }: tests only (runs after the copy, before the read-back).
        THE BATCH KEY (-BatchKey, 32 hex): written in the batch's own transaction (sidata.ViewState 'bulk:<key>'), so after a
        commit that did not answer (a dropped connection may already have committed on the server) the caller asks whether
        THIS batch is stored before it loads it again -- a batch is never written twice. A commit that throws is thrown
        tagged SIBulkCommitUnknown (+ SIBulkKey). -CommitHook { }: tests only (runs right after the commit; what it throws
        reads as a commit that did not answer).
    #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [int]$Offset, [int]$Count,
          [string]$BulkSql, [hashtable]$Params = @{}, [string]$JsonParam = 'j', [switch]$VerifyOnly, [scriptblock]$TestHook, [int]$TimeoutSec = 0,
          [string]$BatchKey = '', [scriptblock]$CommitHook)
    $c0 = $Connection.CreateCommand(); $c0.CommandText = $script:SIDataBulkTableSql; $c0.CommandTimeout = $TimeoutSec; [void]$c0.ExecuteNonQuery()
    $want = Get-SIDataBulkHashSum -Items $Items -Offset $Offset -Count $Count
    $tx = $Connection.BeginTransaction()
    $done = $false
    try {
        $dt = ConvertTo-SIDataBulkTable -Items $Items -Offset $Offset -Count $Count
        $bc = New-Object System.Data.SqlClient.SqlBulkCopy($Connection, [System.Data.SqlClient.SqlBulkCopyOptions]::TableLock, $tx)
        try {
            $bc.DestinationTableName = '#SIBulkRows'; $bc.BulkCopyTimeout = $TimeoutSec; $bc.BatchSize = 0
            [void]$bc.ColumnMappings.Add('Seq', 'Seq'); [void]$bc.ColumnMappings.Add('J', 'J')
            $bc.WriteToServer($dt)
        } finally { $bc.Close(); $dt.Dispose() }
        if ($TestHook) { & $TestHook $Connection $tx }
        $rc = $Connection.CreateCommand(); $rc.Transaction = $tx; $rc.CommandText = $script:SIDataBulkHashSql; $rc.CommandTimeout = $TimeoutSec
        $rd = $rc.ExecuteReader(); $gotN = -1L; $gotH = 0L
        try { if ($rd.Read()) { $gotN = [long]$rd.GetValue(0); $gotH = [long]$rd.GetValue(1) } } finally { $rd.Close() }
        if ($gotN -ne [long]$Count -or $gotH -ne $want) {
            $tx.Rollback(); $done = $true
            return [pscustomobject]@{ Ok = $false; Why = ('the database holds {0} of {1} row(s) sent, content {2}' -f $gotN, $Count, $(if ($gotH -eq $want) { 'the same' } else { 'different' })); Rows = 0L }
        }
        if ($VerifyOnly) { $tx.Rollback(); $done = $true; return [pscustomobject]@{ Ok = $true; Why = ''; Rows = [long]$Count } }
        $ic = $Connection.CreateCommand(); $ic.Transaction = $tx; $ic.CommandText = $BulkSql; $ic.CommandTimeout = $TimeoutSec
        foreach ($k in $Params.Keys) { if ($k -eq $JsonParam) { continue }; [void]$ic.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) }
        $v = $ic.ExecuteScalar()
        $n = -1L; if ($null -ne $v -and $v -isnot [System.DBNull]) { $n = [long]$v }
        if ($n -ne [long]$Count) {
            $tx.Rollback(); $done = $true
            return [pscustomobject]@{ Ok = $false; Why = ('the statement wrote {0} of {1} row(s)' -f $n, $Count); Rows = 0L }
        }
        $dc = $Connection.CreateCommand(); $dc.Transaction = $tx; $dc.CommandText = 'DELETE FROM #SIBulkRows;'; $dc.CommandTimeout = $TimeoutSec; [void]$dc.ExecuteNonQuery()
        # the batch's key, in its own transaction: stored exactly when the batch is
        if ($BatchKey) {
            $mk = $Connection.CreateCommand(); $mk.Transaction = $tx; $mk.CommandText = $script:SIDataBulkMarkSql; $mk.CommandTimeout = $TimeoutSec
            [void]$mk.Parameters.AddWithValue('@Name', ('bulk:' + $BatchKey)); [void]$mk.Parameters.AddWithValue('@Value', [string]$n)
            [void]$mk.ExecuteNonQuery()
        }
        try { $tx.Commit(); if ($CommitHook) { & $CommitHook } }
        catch {
            $done = $true
            $ex = New-Object System.Exception(('the commit of a bulk batch did not answer ({0})' -f ((([string]$_.Exception.Message) -split "`n")[0].Trim())), $_.Exception)
            $ex.Data['SIBulkCommitUnknown'] = $true; $ex.Data['SIBulkKey'] = $BatchKey
            throw $ex
        }
        $done = $true
        # the key is not needed once the commit answered (best effort; a key left behind is removed after a day)
        if ($BatchKey) { try { $dk = $Connection.CreateCommand(); $dk.CommandText = $script:SIDataBulkMarkDeleteSql; $dk.CommandTimeout = $TimeoutSec; [void]$dk.Parameters.AddWithValue('@Name', ('bulk:' + $BatchKey)); [void]$dk.ExecuteNonQuery() } catch { } }
        [pscustomobject]@{ Ok = $true; Why = ''; Rows = $n }
    } finally {
        if (-not $done) { try { $tx.Rollback() } catch { } }
        $tx.Dispose()
    }
}

function Write-SIDataBulkRows {
    <#
        Writes JSON object texts through SqlBulkCopy (see the header): -Sql is the JSON path's statement (Write-SIDataJsonRows)
        -- it must convert (ConvertTo-SIDataBulkSql), the seam must copy in bulk (Test-SIDataBulkSeam). Batches sized from
        the measured time (-ChunkChars carries the size between calls, as the JSON path's), each in its own transaction,
        count + hash read back; a batch that does not agree is redone once, then the load FAILS (throws). A passing Azure SQL
        answer (Test-SISqlStatementTransient) reconnects and redoes the batch (the statement retry's pauses). -VerifyOnly:
        every batch is copied and checked, then rolled back (shadow) -- answers the rows checked. Returns the rows written.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [hashtable]$Params = @{},
          [ref]$ChunkChars, [long]$TargetMs = 10000, [string]$What = 'rows', [string]$JsonParam = 'j', [switch]$VerifyOnly,
          [scriptblock]$TestHook, [int[]]$Waits, [scriptblock]$Sleep,
          # the time limit of each command (seconds; 0 = none): -1 = the seam's own (its CommandTimeout), else none
          [int]$TimeoutSec = -1,
          # tests only: { param($BatchNo, $Attempt) } runs right after a batch's commit (what it throws = a commit that did not answer)
          [scriptblock]$CommitHook)
    if (-not (Test-SIDataBulkSeam $Invoke)) { throw 'Write-SIDataBulkRows: this database connection cannot copy in bulk' }
    if ($TimeoutSec -lt 0) {
        $TimeoutSec = 0
        try { $ciP = $Invoke.PSObject.Properties['SIConnectionInfo']; if ($ciP -and $ciP.Value -is [scriptblock]) { $ci = & $ciP.Value; if ($ci -and $null -ne $ci.CommandTimeout) { $TimeoutSec = [int]$ci.CommandTimeout } } } catch { $TimeoutSec = 0 }
    }
    $bulkSql = ConvertTo-SIDataBulkSql -Sql $Sql -JsonParam $JsonParam
    if (-not $bulkSql) { throw 'Write-SIDataBulkRows: the statement does not read its rows in the shape a bulk copy can feed' }
    if (-not $PSBoundParameters.ContainsKey('Waits')) { $Waits = $(if (Get-Command -Name Get-SISqlStatementRetryWaits -ErrorAction SilentlyContinue) { @(Get-SISqlStatementRetryWaits) } else { @(5, 15, 30) }) }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $isTransient = $(if (Get-Command -Name Test-SISqlStatementTransient -ErrorAction SilentlyContinue) { ${function:Test-SISqlStatementTransient} } else { { param($e) $false } })
    $total = 0L
    $target = [long]2000000; if ($ChunkChars -and $ChunkChars.Value -gt 0) { $target = [long]$ChunkChars.Value }
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
    $cn = $null; $i = 0; $batchNo = 0
    # the batch keys need the mark table: without it a commit that did not answer cannot be told apart -- the load then FAILS
    # on such an error instead of loading the batch again (never twice)
    $keyed = $false
    try { $keyed = ([string](& $Invoke $script:SIDataBulkMarkReadySql @{} 'scalar') -eq '1') } catch { $keyed = $false }
    # the keys a run left behind (a commit that answered after all, a run that stopped), once per process
    if ($keyed -and -not $VerifyOnly -and -not $script:SIDataBulkPurged) { $script:SIDataBulkPurged = $true; try { $null = & $Invoke $script:SIDataBulkMarkPurgeSql @{} 'nonquery' } catch { } }
    try {
        while ($i -lt $Items.Count) {
            if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $target = [Math]::Max(50000L, [long][Math]::Floor($target / 2)) } }
            $from = $i; $len = 0L
            while ($i -lt $Items.Count -and ($i -eq $from -or ($len + $Items[$i].Length + 1) -le $target)) { $len += $Items[$i].Length + 1; $i++ }
            $count = $i - $from; $batchNo++
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $redo = 0; $retry = 0; $r = $null; $attempt = 0
            while ($true) {
                $key = $(if ($keyed -and -not $VerifyOnly) { [guid]::NewGuid().ToString('N') } else { '' })
                try {
                    if ($null -eq $cn) { $cn = & $Invoke.SIBulkOpen }
                    $hook = $null; if ($TestHook) { $bn = $batchNo; $an = $redo; $th = $TestHook; $hook = { param($c, $t) & $th $c $t $bn $an }.GetNewClosure() }
                    $chook = $null; if ($CommitHook) { $bn2 = $batchNo; $an2 = $attempt; $ch = $CommitHook; $chook = { & $ch $bn2 $an2 }.GetNewClosure() }
                    $attempt++
                    $r = Invoke-SIDataBulkBatch -Connection $cn -Items $Items -Offset $from -Count $count -BulkSql $bulkSql -Params $Params -JsonParam $JsonParam -VerifyOnly:$VerifyOnly -TestHook $hook -TimeoutSec $TimeoutSec -BatchKey $key -CommitHook $chook
                } catch {
                    $err = $_
                    try { if ($cn) { $cn.Dispose() } } catch { }; $cn = $null
                    # a commit that did not answer: is THIS batch stored? (its key, on a new connection) -- stored = done, never twice
                    $cu = $err.Exception; while ($cu -and -not $cu.Data['SIBulkCommitUnknown']) { $cu = $cu.InnerException }
                    if ($cu) {
                        if (-not $key) { throw ("{0}: the commit of batch {1} did not answer and the database cannot tell whether it is stored (no mark table) -- the load stops rather than store it twice" -f $What, $batchNo) }
                        $stored = $null; $ck = 0
                        while ($null -eq $stored) {
                            try {
                                $vc = & $Invoke.SIBulkOpen
                                try { $q = $vc.CreateCommand(); $q.CommandText = $script:SIDataBulkMarkReadSql; $q.CommandTimeout = $TimeoutSec; [void]$q.Parameters.AddWithValue('@Name', ('bulk:' + $key)); $stored = ([long]$q.ExecuteScalar() -gt 0)
                                      if ($stored) { $d2 = $vc.CreateCommand(); $d2.CommandText = $script:SIDataBulkMarkDeleteSql; [void]$d2.Parameters.AddWithValue('@Name', ('bulk:' + $key)); try { [void]$d2.ExecuteNonQuery() } catch { } } }
                                finally { $vc.Dispose() }
                            } catch {
                                if ($ck -ge @($Waits).Count) { throw ("{0}: the commit of batch {1} did not answer and whether it is stored could not be read ({2}) -- the load stops rather than store it twice" -f $What, $batchNo, $_.Exception.Message) }
                                $w = [int]@($Waits)[$ck]; $ck++; if ($w -gt 0) { & $Sleep $w }
                            }
                        }
                        if ($stored) {
                            Write-Host ('       {0}: the commit of batch {1} did not answer, but the batch is stored -- it is not loaded again' -f $What, $batchNo) -ForegroundColor DarkYellow
                            $r = [pscustomobject]@{ Ok = $true; Why = ''; Rows = [long]$count }
                            break
                        }
                        # not stored: the batch is loaded again (counted as one retry)
                        if ($retry -ge @($Waits).Count) { throw ("{0}: the commit of batch {1} did not answer, again -- the load stops; the batch is not stored" -f $What, $batchNo) }
                        $w = [int]@($Waits)[$retry]; $retry++
                        Write-Host ('       {0}: the commit of batch {1} did not answer and the batch is not stored -- it is loaded again in {2} s ({3}/{4})' -f $What, $batchNo, $w, $retry, @($Waits).Count) -ForegroundColor DarkYellow
                        if ($w -gt 0) { & $Sleep $w }
                        continue
                    }
                    if ((& $isTransient $err) -and $retry -lt @($Waits).Count) {
                        $w = [int]@($Waits)[$retry]; $retry++
                        Write-Host ('       the database answered a temporary Azure SQL error while {0} were loaded ({1}) -- connecting again and loading the batch again in {2} s ({3}/{4})' -f $What, (([string]$err.Exception.Message) -split "`n")[0].Trim(), $w, $retry, @($Waits).Count) -ForegroundColor DarkYellow
                        if ($w -gt 0) { & $Sleep $w }
                        continue
                    }
                    throw
                }
                if ($r.Ok) { break }
                if ($VerifyOnly) { break }
                $redo++
                if ($redo -ge 2) { throw ("{0}: batch {1} ({2} row(s)) did not load as sent twice ({3}) -- the load stops; nothing of this batch is kept." -f $What, $batchNo, $count, $r.Why) }
                Write-Host ('       {0}: batch {1} did not load as sent ({2}) -- it was rolled back and is loaded again' -f $What, $batchNo, $r.Why) -ForegroundColor DarkYellow
            }
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            if ($VerifyOnly -and -not $r.Ok) { throw ("{0}: the bulk copy of batch {1} did not arrive as sent ({2})" -f $What, $batchNo, $r.Why) }
            $total += [long]$r.Rows
            $next = Get-SIDataNextSize -Current ([Math]::Max(1L, $len)) -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 50000
            if ($len -ge $target -or $i -lt $Items.Count) { $target = $next } elseif ($next -lt $len) { $target = $next }
        }
    } finally { if ($cn) { try { $cn.Dispose() } catch { } } }
    if ($ChunkChars) { $ChunkChars.Value = $target }
    $total
}

function Write-SIDataLoadRows {
    <#
        THE ONE CALL of the large writers (#1336): SI_Data_BulkLoad on + a seam that copies in bulk + a statement in the
        OPENJSON shape -> Write-SIDataBulkRows; shadow -> the batches are copied and checked, then rolled back, and the rows
        written the JSON way (a difference is a WARNING line through -Log: the run's report opens a fix request; the JSON
        way serves); anything else -> Write-SIDataJsonRows exactly as before. Same parameters, same answer (rows written).
        -Fallback { }: the earlier way of a writer that is not Write-SIDataJsonRows (it answers what that writer answers).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql,
          [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Items, [hashtable]$Params = @{},
          [ref]$ChunkChars, [long]$TargetMs = 10000, [string]$What = 'rows', [string]$JsonParam = 'j', [scriptblock]$Log, [string]$Mode = '',
          [scriptblock]$Fallback)
    if (-not $Mode) { $Mode = Get-SIDataBulkLoadMode }
    $can = ($Mode -ne 'off') -and $Items.Count -gt 0 -and (Test-SIDataBulkSeam $Invoke) -and $null -ne (ConvertTo-SIDataBulkSql -Sql $Sql -JsonParam $JsonParam)
    $jsonArgs = @{ Invoke = $Invoke; Sql = $Sql; Items = $Items; Params = $Params; TargetMs = $TargetMs; What = $What }
    if ($ChunkChars) { $jsonArgs['ChunkChars'] = $ChunkChars }
    $earlier = { if ($Fallback) { & $Fallback } else { Write-SIDataJsonRows @jsonArgs } }
    if (-not $can) { return (& $earlier) }
    $bulkArgs = @{ Invoke = $Invoke; Sql = $Sql; Items = $Items; Params = $Params; TargetMs = $TargetMs; What = $What; JsonParam = $JsonParam }
    if ($ChunkChars) { $bulkArgs['ChunkChars'] = $ChunkChars }
    if ($Mode -eq 'on') { return (Write-SIDataBulkRows @bulkArgs) }
    # shadow: checked, then the earlier way serves
    try { $null = Write-SIDataBulkRows @bulkArgs -VerifyOnly }
    catch { if ($Log) { & $Log 'WARN' ("bulk load check: {0} did not arrive as sent through the bulk copy ({1}) -- they are written the earlier way" -f $What, $_.Exception.Message) } }
    & $earlier
}
