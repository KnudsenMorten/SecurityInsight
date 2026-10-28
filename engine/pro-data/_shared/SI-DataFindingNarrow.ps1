#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE NARROW FINDINGS (2026-10-25, owner: "i need the performance improvement, but no loosing of data").

    Measured at the largest install (1.39 million findings a collection): the derived steps after the view context each scanned
    the collection's WIDE rows of sidata.Finding (DetailJson ~3 KB a row) -- the remediations' #k alone 36.6 min, IO-bound
    (521k physical page reads, 5.6 min CPU), the findings per CI's work fill 20.5 min. sidata.FindingNarrow (sql/
    si-data-schema.sql) holds the typed columns those statements read, under the SAME names and types, and every value they
    read out of the document as a column of its own (Dj_<field>; DjIsJson). It is filled ONCE per collection per run -- the
    first time a step of this run asks for it (Use-SIDataFindingNarrow), which is after the view context, the last step that
    writes those columns -- and emptied at the run's end (Clear-SIDataFindingNarrow): it is never read across runs, so it
    cannot be older than the rows it was made from. The statements read it through ConvertTo-SIDataNarrowSql: the same
    statement, sidata.Finding AS f -> sidata.FindingNarrow AS f, each JSON_VALUE(f.DetailJson, '$.<field>') -> f.[Dj_<field>].
    No table, a fill that fails or does not come out whole: the statement as it was, on sidata.Finding. PS 5.1 safe.
#>

$script:SIDataNarrowColumns = @('AssetKey', 'AssetName', 'ReportName', 'SecurityDomain', 'ConfigurationId', 'Cve', 'Title', 'Severity', 'Tier', 'RiskScore',
    'RiskScoreWeighted', 'RiskRating', 'ExemptionId', 'RemediationEffort', 'FixOwner', 'DepartmentId', 'HasExploit', 'FixRemediation', 'CiLifecycle',
    'FixRecommendedUpdateId', 'FixRecommendedUpdate', 'AffectedVendor', 'AffectedProduct', 'RaFindingKey', 'RaSeq', 'RaAssetId',
    # the summary groupings' fields (data-model\summary-groupings.locked.json)
    'Category', 'Subcategory', 'ComplianceTags', 'Cvss', 'MitreTactics', 'MitreTechniques', 'SourceFirstDetected')
$script:SIDataNarrowJsonFields = @('si_remediation_type', 'RiskScoreTotal_Weighted', 'si_component', 'RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed',
    'si_servicenow_subci', 'si_patch_cycle', 'si_cve_published', 'si_category', 'Category', 'si_subcategory', 'Subcategory')
# the collections filled in THIS process (run): CollectionId -> $true
$script:SIDataNarrowReady = @{}
# #904: the collections whose fill FAILED in this process (run): CollectionId -> the error. A fill that failed is a part of the
# data sync that failed (Get-SIDataFindingNarrowState) -- the steps still read the wide rows, but the failure is reported.
$script:SIDataNarrowFailed = @{}

function Get-SIDataFindingNarrowState {
    <# #904: @{ Status = ok | failed; Error; Collections } of this run's narrow findings -- 'failed' when a fill threw (a
       full database, a timeout, ...). A fill that did not come out whole is said as before and is not a failure. #>
    $f = @($script:SIDataNarrowFailed.Keys | Sort-Object)
    if (-not $f.Count) { return [pscustomobject]@{ Status = 'ok'; Error = ''; Collections = @() } }
    [pscustomobject]@{ Status = 'failed'; Collections = $f
                       Error = ((@($f | ForEach-Object { 'collection {0}: {1}' -f $_, $script:SIDataNarrowFailed[$_] })) -join '; ') }
}

function Get-SIDataNarrowCheckSql {
    <# 1 when the database has sidata.FindingNarrow, else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.FindingNarrow') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataNarrowFillSql {
    <# ONE FindingId range (@After < FindingId <= @Upto) of collection @CollectionId into sidata.FindingNarrow. Answers the rows added. #>
    $cols = (@($script:SIDataNarrowColumns | ForEach-Object { '[{0}]' -f $_ })) -join ', '
    $fcols = (@($script:SIDataNarrowColumns | ForEach-Object { 'f.[{0}]' -f $_ })) -join ', '
    $dj = (@($script:SIDataNarrowJsonFields | ForEach-Object { '[Dj_{0}]' -f $_ })) -join ', '
    $djv = (@($script:SIDataNarrowJsonFields | ForEach-Object { "CASE WHEN j.J = 1 THEN JSON_VALUE(f.DetailJson, '`$.{0}') END" -f $_ })) -join ', '
    @"
SET NOCOUNT ON;
INSERT sidata.FindingNarrow (CollectionId, FindingId, $cols, DjIsJson, $dj)
SELECT f.CollectionId, f.FindingId, $fcols, j.J, $djv
FROM sidata.Finding AS f
CROSS APPLY (SELECT CASE WHEN f.DetailJson IS NULL THEN CAST(NULL AS bit) ELSE CONVERT(bit, ISJSON(f.DetailJson)) END AS J) AS j
WHERE f.CollectionId = CONVERT(int, @CollectionId) AND f.FindingId > CONVERT(bigint, @After) AND f.FindingId <= CONVERT(bigint, @Upto);
SELECT @@ROWCOUNT;
"@
}

function ConvertTo-SIDataNarrowSql {
    <#
        PURE. A statement over sidata.Finding AS f -> the same statement over sidata.FindingNarrow AS f: the table, each
        JSON_VALUE(f.DetailJson, '$.<field>') -> f.[Dj_<field>], the document's "is it JSON" guard -> f.DjIsJson. THROWS when
        anything of the document is left (a statement this cannot carry over exactly is never run on the narrow table), or a
        field is not one the table holds.
    #>
    param([Parameter(Mandatory)][string]$Sql)
    $out = [regex]::Replace($Sql, 'FROM sidata\.Finding( AS)? f\b', 'FROM sidata.FindingNarrow AS f')
    if ($out -eq $Sql) { throw 'the statement does not read sidata.Finding AS f' }
    $out = $out.Replace('f.DetailJson IS NOT NULL AND ISJSON(f.DetailJson) = 1', 'f.DjIsJson = 1')
    $bad = New-Object System.Collections.Generic.List[string]
    $out = [regex]::Replace($out, "JSON_VALUE\(f\.DetailJson, '\$\.([A-Za-z_][A-Za-z0-9_]*)'\)", {
        param($m)
        $fld = $m.Groups[1].Value
        if ($script:SIDataNarrowJsonFields -notcontains $fld) { $bad.Add($fld) }
        'f.[Dj_' + $fld + ']'
    })
    if ($bad.Count) { throw ('the narrow findings do not hold the document field(s) {0}' -f ($bad -join ', ')) }
    if ($out -match 'DetailJson') { throw 'the statement reads the finding''s document in a way the narrow findings do not carry' }
    # STATIC: every column the statement names for f, in each statement that reads the narrow table, must be one the table
    # holds -- checked here, before anything runs (a statement that reads a #temp table of its batch is compiled only when it
    # is reached, so an unknown column would fail mid-batch). The string literals and comments are blanked first (a ';' inside
    # one is not a statement's end).
    $held = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @('CollectionId', 'FindingId', 'DjIsJson') + @($script:SIDataNarrowColumns) + @($script:SIDataNarrowJsonFields | ForEach-Object { 'Dj_' + $_ })) { [void]$held.Add($c) }
    $plain = [regex]::Replace($out, "N?'(?:[^']|'')*'", "''")
    $plain = [regex]::Replace($plain, '(?m)--[^\r\n]*', '')
    $plain = [regex]::Replace($plain, '(?s)/\*.*?\*/', '')
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($stmt in ($plain -split ';')) {
        if ($stmt -notmatch 'FROM sidata\.FindingNarrow AS f\b') { continue }
        foreach ($m in [regex]::Matches($stmt, '(?<![\w.#@\]])f\.\[?([A-Za-z_][A-Za-z0-9_]*)\]?')) {
            $col = $m.Groups[1].Value
            if (-not $held.Contains($col) -and -not $missing.Contains($col)) { $missing.Add($col) }
        }
    }
    if ($missing.Count) { throw ('the narrow findings do not hold the column(s) {0}' -f ($missing -join ', ')) }
    $out
}

function Use-SIDataFindingNarrow {
    <#
        The narrow findings of ONE collection, for this run: $true when they are there (filled now, or earlier in this run), $false
        when the steps must read sidata.Finding (no table, or the fill failed / did not come out whole -- said once). Filled in
        FindingId ranges sized from the measured time of the one before, paced by the database's own load. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [long]$FirstSize = 50000, [long]$TargetMs = 5000,
          [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Phase)
    if ($script:SIDataNarrowReady.ContainsKey($CollectionId)) { return [bool]$script:SIDataNarrowReady[$CollectionId] }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        if ([string](& $Invoke (Get-SIDataNarrowCheckSql) @{} 'scalar') -ne '1') { $script:SIDataNarrowReady[$CollectionId] = $false; return $false }
        $cidText = [string]$CollectionId
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingNarrow WHERE CollectionId = CONVERT(int, @CollectionId); SELECT @@ROWCOUNT;' @{ CollectionId = $cidText } 'scalar') -gt 0) { }
        $b = @(@(& $Invoke 'SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi, COUNT_BIG(*) AS N FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = $cidText } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        $get = { param($n) if ($null -eq $b) { $null } elseif ($b -is [System.Collections.IDictionary]) { $b[$n] } else { $b.$n } }
        $lo = & $get 'Lo'; $hi = & $get 'Hi'; $want = & $get 'N'
        $n = 0L
        if ($null -ne $lo -and $lo -isnot [System.DBNull]) {
            $sql = Get-SIDataNarrowFillSql
            $after = [long]$lo - 1; $top = [long]$hi; $size = [Math]::Max(1L, $FirstSize); $lastMs = 0L
            $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
            while ($after -lt $top) {
                if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log; if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)) } }
                $upto = [long][Math]::Min([double]$top, [double]$after + [double]$size)
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $n += [long](& $Invoke $sql @{ CollectionId = $cidText; After = [string]$after; Upto = [string]$upto } 'scalar')
                $lastMs = $sw.ElapsedMilliseconds; $after = $upto
                if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 1 }
            }
        }
        # whole, or not used: the rows made must be the collection's rows, counted again in both tables
        $have = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.FindingNarrow WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = $cidText } 'scalar')
        $now = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = $cidText } 'scalar')
        if ($have -ne $n -or $have -ne $now -or ($null -ne $want -and $want -isnot [System.DBNull] -and [long]$want -ne $now)) {
            & $Log 'WARN' ("narrow      : the narrow findings of collection {0} did not come out whole ({1:N0} made, {2:N0} in the collection) -- the steps read the findings as before" -f $CollectionId, $have, $now)
            $script:SIDataNarrowReady[$CollectionId] = $false; return $false
        }
        & $Log 'INFO' ("narrow      : collection {0} -- {1:N0} finding(s) read once into the narrow findings ({2:N1} s)" -f $CollectionId, $n, $clock.Elapsed.TotalSeconds)
        if ($Phase) { try { & $Phase ('narrow findings fill (collection {0})' -f $CollectionId) $n } catch { } }
        $script:SIDataNarrowReady[$CollectionId] = $true
        return $true
    } catch {
        & $Log 'WARN' ("narrow      : the narrow findings of collection {0} were not made ({1}) -- the steps read the findings as before" -f $CollectionId, $_.Exception.Message)
        $script:SIDataNarrowReady[$CollectionId] = $false
        $script:SIDataNarrowFailed[$CollectionId] = [string]$_.Exception.Message
        return $false
    }
}

function Clear-SIDataFindingNarrow {
    <# The run's end: the narrow findings emptied in chunks (never read by another run) and this run's list forgotten. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($l, $m) })
    $script:SIDataNarrowReady = @{}
    # #904: the run's fill failures were taken by the data sync (Get-SIDataFindingNarrowState) before this
    $script:SIDataNarrowFailed = @{}
    try {
        if ([string](& $Invoke (Get-SIDataNarrowCheckSql) @{} 'scalar') -ne '1') { return }
        while ([long](& $Invoke 'SET NOCOUNT ON; DELETE TOP (50000) FROM sidata.FindingNarrow; SELECT @@ROWCOUNT;' @{} 'scalar') -gt 0) { }
    } catch { & $Log 'WARN' ("narrow      : the narrow findings were not emptied ({0}) -- the next run empties a collection before it fills it" -f $_.Exception.Message) }
}

function Invoke-SIDataNarrowOrWide {
    <#
        ONE statement of one collection over this run's narrow findings when they can be made, else over sidata.Finding: the
        statement carried over (ConvertTo-SIDataNarrowSql) and run; a statement that names a column the narrow table does not
        hold fails when it is compiled -- BEFORE it writes anything -- and is then run as it was, on the wide rows (said once).
        Any other failure is the statement's own and is thrown as before. Answers what the statement answers.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{}, [string]$Mode = 'scalar',
          [Parameter(Mandatory)][long]$CollectionId, [string]$What = 'a step', [scriptblock]$Log = { param($l, $m) })
    $narrow = $null
    try { $narrow = ConvertTo-SIDataNarrowSql -Sql $Sql } catch { $narrow = $null }
    if ($narrow -and (Use-SIDataFindingNarrow -Invoke $Invoke -CollectionId $CollectionId -Log $Log)) {
        try { return (& $Invoke $narrow $Params $Mode) }
        catch {
            # LAST RESORT (the static check in ConvertTo-SIDataNarrowSql is the rule): run again on the wide rows ONLY a batch whose
            # every permanent write is inside one XACT_ABORT transaction -- its failure has written nothing; anything else is thrown
            if ($_.Exception.Message -notmatch "Invalid column name|Invalid object name 'sidata\.FindingNarrow'" -or -not (Test-SIDataNarrowRetrySafe -Sql $narrow)) { throw }
            & $Log 'INFO' ("narrow      : {0} could not read the narrow findings ({1}) -- it reads the findings as before" -f $What, $_.Exception.Message)
        }
    }
    & $Invoke $Sql $Params $Mode
}

function Test-SIDataNarrowRetrySafe {
    <# PURE. $true when the batch is SET XACT_ABORT ON and every write to a permanent table (sidata. / cfg. / vuln.) comes after its
       BEGIN TRAN -- a failure before COMMIT has written nothing, so the batch may be run again on the wide rows. #>
    param([Parameter(Mandatory)][string]$Sql)
    $plain = [regex]::Replace($Sql, "N?'(?:[^']|'')*'", "''")
    $plain = [regex]::Replace([regex]::Replace($plain, '(?m)--[^\r\n]*', ''), '(?s)/\*.*?\*/', '')
    if ($plain -notmatch '(?i)SET XACT_ABORT ON') { return $false }
    $tran = [regex]::Match($plain, '(?i)\bBEGIN TRAN(SACTION)?\b')
    $write = [regex]::Match($plain, '(?i)\b(INSERT(\s+INTO)?|UPDATE|DELETE(\s+FROM)?|MERGE(\s+INTO)?)\s+(\w+\s+FROM\s+)?(sidata|cfg|vuln)\.')
    if (-not $write.Success) { return $true }
    return ($tran.Success -and $tran.Index -lt $write.Index)
}
