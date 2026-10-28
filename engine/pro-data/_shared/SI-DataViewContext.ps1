#Requires -Version 7.0
<#
    SecurityInsight Pro -- WHAT A VIEW SHOWS BY DEFAULT IS PREPARED IN SQL (owner 2026-10-11: "dont foget the caching in sql
    so performance works flawless", "indexing", "again all views must be having the new requirement and performance fast").

    A column of a data view's default layout is a stored column this file fills -- the web app then reads a page of 50 rows
    by key from columns, and never works a value out of a JSON document (sidata.Ci.DocJson, sidata.Finding.DetailJson).

    THE LIST of those columns is ONE file, read by this script AND by the web app (embedded there):
        pro-management/src/SI.Management.Core/ProData/DataModel/view-stored-columns.json
    Adding a field = one entry in that file + its guarded column in sql/si-data-schema.sql (a test names a missing line).

    WHAT IS FILLED
      sidata.Finding   the finding context of each finding (affected product / vendor / version, description, fix, remediation,
                       more details, published, exploit words, category, subcategory, impact, CMDB group) -- per collection,
                       once, from DetailJson, in measured FindingId ranges
      sidata.IssueContext   one row per collection + CVE / issue key: the DISTINCT values over every finding of the key, the
                       first affected asset names and the exact number of affected assets -- set-based from the columns above
      sidata.Collection.ContextAt   when a collection got both (NULL = not yet: the web app reads its context as before)
      sidata.Ci        the CI context of the list (scalar fields, list fields as their JSON text) for every CI whose content
                       hash moved or that was filled for an older list; the identifier values and the linked object ids of
                       every CI, written only where they changed

    EXISTING INSTALLS: the schema adds the columns (the updater applies it); the next data sync fills every collection that
    has no ContextAt (newest first, within a time budget per run -- the rest follow on the next runs) and every CI.
    Never fails the data sync: a failure is said, and the web app keeps reading what is not prepared the way it did.
    No PowerShell module: the statements run through the data sync's own SQL seam.
#>

$script:SIViewStoredColumnsPath = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))),
    'pro-management', 'src', 'SI.Management.Core', 'ProData', 'DataModel', 'view-stored-columns.json')

function Get-SIViewStoredColumns {
    <#
        THE list (view-stored-columns.json) as an object with .ci and .finding -- or $null when the file is not there or an
        entry is not well formed (a column / field name is a plain identifier: it becomes SQL text). PURE apart from the read.
    #>
    param([string]$Path = $script:SIViewStoredColumnsPath)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $doc = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $ci = @($doc.ci); $fi = @($doc.finding)
    foreach ($e in $ci) {
        if ([string]$e.column -notmatch '^[A-Za-z][A-Za-z0-9]{0,60}$') { return $null }
        if ([string]$e.type -cnotmatch '^(NVARCHAR\((?:[1-9][0-9]{0,2}|[1-3][0-9]{3}|4000)\)|JSON|LIST|INT|FLOAT|BIT|DATETIME2\(3\))$') { return $null }
        if ([string]$e.key -notmatch '^(ci\.f\.[a-z][a-z0-9_]{0,80}|ci\.i\.[A-Za-z0-9_]{1,64}|ci\.links)$') { return $null }
    }
    foreach ($e in $fi) {
        if ([string]$e.column -notmatch '^[A-Za-z][A-Za-z0-9]{0,60}$') { return $null }
        if ([string]$e.issue -and [string]$e.issue -notmatch '^[A-Za-z][A-Za-z0-9]{0,60}$') { return $null }
        if ([string]$e.type -cnotmatch '^(NVARCHAR\((?:[1-9][0-9]{0,2}|[1-3][0-9]{3}|4000|MAX)\)|INT|FLOAT|DATETIME2\(3\))$') { return $null }
        foreach ($f in @($e.fields)) { if ([string]$f -notmatch '^[A-Za-z][A-Za-z0-9_]{0,80}$') { return $null } }
        foreach ($g in @($e.flags)) { if ($g -and [string]$g.field -notmatch '^[A-Za-z][A-Za-z0-9_]{0,80}$') { return $null } }
    }
    [pscustomobject]@{ ci = $ci; finding = $fi }
}

function Get-SIViewFindingSetId {
    <#
        PURE. The identity of the FINDING list, as Get-SIViewCiSetId is the CI list's: the first 8 bytes (hex) of the SHA-256
        of "key|column|issue|type|fields|flags" per entry (fields ','-joined; flags as field=words, ','-joined), one per
        line. Stored on every collection the list was prepared for (sidata.Collection.ContextSet); the web app computes the
        same from its copy of the file, so a changed list makes every collection count as not prepared until the next data
        sync prepared it again -- an added field reaches the collections already stored.
    #>
    param([Parameter(Mandatory)]$List)
    $text = (@($List.finding) | ForEach-Object {
        $fields = (@($_.fields) | Where-Object { $_ } | ForEach-Object { [string]$_ }) -join ','
        $flags = (@($_.flags) | Where-Object { $_ } | ForEach-Object { '{0}={1}' -f [string]$_.field, [string]$_.words }) -join ','
        '{0}|{1}|{2}|{3}|{4}|{5}' -f [string]$_.key, [string]$_.column, [string]$_.issue, [string]$_.type, $fields, $flags
    }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    [System.BitConverter]::ToString($hash, 0, 8).Replace('-', '')
}

function Get-SIViewDateSql {
    <#
        PURE. A date text (ISO 8601, as the sources and Risk Analysis write it) as DATETIME2(3) in UTC: the plain and the 'Z'
        forms directly, a form with an offset moved to UTC; anything else is no date (NULL) -- never a guess.
    #>
    param([Parameter(Mandatory)][string]$Expr)
    "COALESCE(TRY_CONVERT(datetime2(3), LEFT($Expr, 23), 127), TRY_CONVERT(datetime2(3), SWITCHOFFSET(TRY_CONVERT(datetimeoffset(3), $Expr), N'+00:00')))"
}

function Get-SIViewCiSetId {
    <#
        PURE. The identity of the CI list: the first 8 bytes (hex) of the SHA-256 of "key|column|type" per entry, one per
        line. Stored on every CI the list was filled for (sidata.Ci.CtxSet); the web app computes the same from its copy of
        the file, so a changed list makes every CI count as not filled until the next data sync filled it again.
    #>
    param([Parameter(Mandatory)]$List)
    $text = (@($List.ci) | ForEach-Object { '{0}|{1}|{2}' -f [string]$_.key, [string]$_.column, [string]$_.type }) -join "`n"
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text)) } finally { $sha.Dispose() }
    [System.BitConverter]::ToString($hash, 0, 8).Replace('-', '')
}

function Get-SIViewTypeLength {
    <# PURE. 'NVARCHAR(400)' -> 400. #>
    param([Parameter(Mandatory)][string]$Type)
    [int]([regex]::Match($Type, '\((\d+)\)').Groups[1].Value)
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE FINDING CONTEXT (sidata.Finding columns) AND THE ISSUE CONTEXT (sidata.IssueContext), per collection
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataFindingContextSchemaCheckSql {
    <# 1 when the database carries every finding context column, Collection.ContextAt and sidata.IssueContext; else 0. #>
    param([Parameter(Mandatory)]$List)
    $parts = @(@($List.finding) | ForEach-Object { "COL_LENGTH('sidata.Finding', '{0}') IS NOT NULL" -f [string]$_.column })
    $parts += "COL_LENGTH('sidata.Collection', 'ContextAt') IS NOT NULL"
    $parts += "COL_LENGTH('sidata.Collection', 'ContextSet') IS NOT NULL"
    $parts += "OBJECT_ID('sidata.IssueContext') IS NOT NULL"
    $parts += @(@($List.finding) | Where-Object { [string]$_.issue } | ForEach-Object { "COL_LENGTH('sidata.IssueContext', '{0}') IS NOT NULL" -f [string]$_.issue })
    'SELECT CASE WHEN ' + ($parts -join ' AND ') + ' THEN 1 ELSE 0 END'
}

function Get-SIDataUncontextedSql {
    <#
        Complete collections whose context is not prepared -- new loads and, once, every collection loaded before the
        columns existed; a collection prepared for ANOTHER list (@Set = Get-SIViewFindingSetId: a field was added -- every
        collection once more); and a collection whose views' columns were derived again after its context (the derive
        rewrites the fix columns). Newest first.
    #>
    # #717: never a collection whose finding rows the retention removed
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter }
    "SELECT CollectionId, CollectionTime FROM sidata.Collection WHERE Status = 'Complete' AND (ContextAt IS NULL OR ContextSet IS NULL OR ContextSet <> @Set OR (DerivedAt IS NOT NULL AND DerivedAt > ContextAt))$live ORDER BY CollectionTime DESC"
}

function Get-SIDataFindingContextSql {
    <#
        One FindingId range of one collection: every finding context column from DetailJson (the whole Risk Analysis row),
        parsed ONCE per finding (OPENJSON: its properties, only the list's kept). A column is the FIRST of its field names that has a value -- the same
        rule the web app applies to the row itself (an empty text and an empty list are passed over; a list is kept as its
        items, '; '-joined) -- cut at the column's length. The exploit column is words: each flag that is set, else 'no' when
        a flag is known. Re-running a range writes the same values.
    #>
    param([Parameter(Mandatory)]$List)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($List.finding)) {
        foreach ($f in @($e.fields)) { if ($f -and -not $names.Contains([string]$f)) { $names.Add([string]$f) } }
        foreach ($g in @($e.flags)) { if ($g -and -not $names.Contains([string]$g.field)) { $names.Add([string]$g.field) } }
    }
    # #740 (a large customer 2026-10-17: 1,138,554 findings, 3 h+ silent): the fill read each finding's JSON as ~170 typed
    # NVARCHAR(MAX) columns (OPENJSON ... WITH, a text and an AS JSON column per field name) and worked every value out in
    # nested COALESCEs that SQL Server expands into repeated evaluations -- millions of pages per batch. Now each finding's
    # JSON is read ONCE as its own properties (OPENJSON without a schema: key, value, type), only the properties of the list
    # are kept, the value of each is worked out ONCE per property (a list joined only when it is a list), and the per-name
    # values are taken in ONE aggregate per finding. The same value as before for every field (key matched exactly, as the
    # path did; the scalar = a text / number / true-false; a list = its items; an object = its JSON text).
    $flagNames = New-Object System.Collections.Generic.HashSet[string]
    $fieldNames = New-Object System.Collections.Generic.HashSet[string]
    foreach ($e in @($List.finding)) {
        foreach ($g in @($e.flags)) { if ($g) { [void]$flagNames.Add([string]$g.field) } }
        foreach ($f in @($e.fields)) { if ($f) { [void]$fieldNames.Add([string]$f) } }
    }
    $agg = New-Object System.Collections.Generic.List[string]
    $keys = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $names.Count; $i++) {
        $lit = "N'" + $names[$i].Replace("'", "''") + "'"
        $keys.Add($lit)
        if ($fieldNames.Contains($names[$i])) { $agg.Add(("MAX(CASE WHEN o.[key] = {1} THEN p.V END) AS v{0}" -f $i, $lit)) }
        if ($flagNames.Contains($names[$i])) { $agg.Add(("MAX(CASE WHEN o.[key] = {1} THEN p.S END) AS s{0}" -f $i, $lit)) }
    }
    # the value of one field: its text; a list as its items; an object as its JSON text; nothing for '' and []
    $value = { param([int]$i) ('j.v{0}' -f $i) }
    # a value as a number, or none: a text longer than any number is none -- SQL Server answers TRY_CONVERT of a very long
    # text with "String or binary data would be truncated" instead of NULL, and that failed the fill of the whole collection
    $num = { param([string]$x) "TRY_CONVERT(float, CASE WHEN LEN($x) <= 4000 THEN CONVERT(nvarchar(4000), $x) END)" }
    # each column's new value (n.[column]), what it is set from, and how it is compared with what the row holds
    $set = New-Object System.Collections.Generic.List[string]
    $newv = New-Object System.Collections.Generic.List[string]
    $cmpNew = New-Object System.Collections.Generic.List[string]
    $cmpOld = New-Object System.Collections.Generic.List[string]
    # compared EXACTLY: a text as its bytes (never by the collation -- 'A' and 'a', 'x' and 'x ' are different values), a
    # number as its 8 bytes, a whole number and a date as they are
    $cmp = {
        param([string]$col, [string]$type)
        $how = '{0}.[' + $col + ']'
        if ($type -like 'NVARCHAR*') { $how = 'CONVERT(varbinary(max), {0}.[' + $col + '])' }
        elseif ($type -eq 'FLOAT') { $how = 'CONVERT(binary(8), {0}.[' + $col + '])' }
        $cmpNew.Add(($how -f 'n')); $cmpOld.Add(($how -f 'f'))
        $set.Add(("    [{0}] = n.[{0}]" -f $col))
    }
    foreach ($e in @($List.finding)) {
        $type = [string]$e.type
        $len = 0; if ($type -match '^NVARCHAR\(\d+\)$') { $len = Get-SIViewTypeLength -Type $type }
        $flags = @(@($e.flags) | Where-Object { $_ })
        if ($flags.Count -gt 0) {
            $on = New-Object System.Collections.Generic.List[string]
            $known = New-Object System.Collections.Generic.List[string]
            foreach ($g in $flags) {
                $i = $names.IndexOf([string]$g.field)
                $on.Add(("CASE WHEN LOWER(j.s{0}) = N'true' OR {2} <> 0 THEN N'{1}' END" -f $i, ([string]$g.words).Replace("'", "''"), (& $num ("j.s{0}" -f $i))))
                $known.Add(("j.s{0} IS NOT NULL" -f $i))
            }
            $newv.Add(("LEFT(COALESCE(NULLIF(CONCAT_WS(N'; ', {1}), N''), CASE WHEN {2} THEN N'no' END), {3}) AS [{0}]" -f [string]$e.column, ($on -join ', '), ($known -join ' OR '), $len))
            & $cmp ([string]$e.column) $type
            continue
        }
        $vals = @(@($e.fields) | Where-Object { $_ } | ForEach-Object { & $value ($names.IndexOf([string]$_)) })
        if ($vals.Count -eq 0) { continue }
        $expr = if ($vals.Count -eq 1) { $vals[0] } else { 'COALESCE(' + ($vals -join ', ') + ')' }
        # a text is cut at its column's length -- a column that holds the whole text (NVARCHAR(MAX): description,
        # remediation, evidence) is never cut; a number and a date are stored as such (a value that is none stays empty)
        $stored = "LEFT($expr, $len)"
        if ($type -eq 'NVARCHAR(MAX)') { $stored = $expr }
        elseif ($type -eq 'FLOAT') { $stored = & $num $expr }
        elseif ($type -eq 'INT') { $stored = "TRY_CONVERT(int, $(& $num $expr))" }
        elseif ($type -eq 'DATETIME2(3)') { $stored = Get-SIViewDateSql -Expr "CONVERT(nvarchar(64), $expr)" }
        $newv.Add(("{1} AS [{0}]" -f [string]$e.column, $stored))
        & $cmp ([string]$e.column) $type
    }
    # LOG VOLUME (2026-10-18: the database's log write at 100 % for hours of a full run): a finding whose prepared values are
    # already exactly these is NOT written again -- a collection prepared once more (a field was added to the list, its views
    # were derived again) rewrote every column of every finding, the same values, and an update is what the log is made of.
    # The values written are the same as before; the number returned is the findings of the range (written or not).
    @"
UPDATE f SET
$($set -join ",`r`n")
FROM sidata.Finding AS f
OUTER APPLY (
    SELECT $($agg -join ",`r`n           ")
    FROM OPENJSON(CASE WHEN ISJSON(f.DetailJson) = 1 AND LEFT(LTRIM(f.DetailJson), 1) = N'{' THEN f.DetailJson END) AS o
    CROSS APPLY (SELECT CASE WHEN o.[type] IN (1, 2, 3) THEN o.[value] END AS S,
                        CASE WHEN o.[type] IN (1, 2, 3) THEN NULLIF(o.[value], N'')
                             WHEN o.[type] = 4 THEN (SELECT STRING_AGG(CONVERT(nvarchar(max), e.[value]), N'; ') WITHIN GROUP (ORDER BY CONVERT(int, e.[key])) FROM OPENJSON(o.[value]) AS e WHERE e.[value] IS NOT NULL AND LTRIM(RTRIM(e.[value])) <> N'')
                             WHEN o.[type] = 5 THEN o.[value] END AS V) AS p
    WHERE o.[key] IN ($($keys -join ', '))
) AS j
CROSS APPLY (SELECT $($newv -join ",`r`n                    ")) AS n
WHERE f.CollectionId = @CollectionId AND f.FindingId > @After AND f.FindingId <= @Upto
  AND EXISTS (SELECT $($cmpNew -join ', ') EXCEPT SELECT $($cmpOld -join ', '));
SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @CollectionId AND FindingId > @After AND FindingId <= @Upto;
"@
}

# How many affected asset names an issue row carries inline (the most risky first); the number of affected assets is exact.
$script:SIDataIssueAssetNames = 20

function Get-SIDataIssueContextSql {
    <#
        ONE collection: sidata.IssueContext, replacing what the collection held, and Collection.ContextAt / ContextSet (the
        list it was prepared for, @Set) -- one transaction.
        A key is a CVE id or a configuration id; a finding belongs to the key it carries in EITHER column (what the views
        match: Cve = key OR ConfigurationId = key). Each context column is the DISTINCT items over every finding of the key
        (an item = a ';'-separated part of the finding's value), the most risky finding's first; the software is each
        finding's own list, else "product version (vendor)". A NUMBER column is the HIGHEST over the key's findings (the
        highest EPSS, the most attack paths) and a DATE column the EARLIEST (the earliest end of support, the earliest due
        date) -- what a person prioritises on. A text is never cut. Reads the finding context COLUMNS (never DetailJson).
        Returns the number of issue rows.
    #>
    param([Parameter(Mandatory)]$List)
    $by = @{}; foreach ($e in @($List.finding)) { $by[[string]$e.key] = [string]$e.column }
    $all = @(@($List.finding) | Where-Object { [string]$_.issue })
    $cols = @($all | Where-Object { [string]$_.type -like 'NVARCHAR*' })
    $typed = @($all | Where-Object { [string]$_.type -notlike 'NVARCHAR*' })
    $typedDecl = ''; $typedCols = ''; $typedAgg = ''; $typedSel = ''
    foreach ($e in $typed) {
        $agg = 'MAX'; if ([string]$e.type -eq 'DATETIME2(3)') { $agg = 'MIN' }
        $typedDecl += (", [{0}] {1} NULL" -f [string]$e.issue, [string]$e.type)
        $typedCols += (", [{0}]" -f [string]$e.issue)
        $typedAgg += (", {0}(f.[{1}]) AS [{2}]" -f $agg, [string]$e.column, [string]$e.issue)
        $typedSel += (", a.[{0}]" -f [string]$e.issue)
    }
    $values = New-Object System.Collections.Generic.List[string]
    $pivot = New-Object System.Collections.Generic.List[string]
    $n = 0
    foreach ($e in $cols) {
        $n++
        $src = "f.[{0}]" -f [string]$e.column
        if ([string]$e.key -eq 'fc.software' -and $by.ContainsKey('fc.software#product') -and $by.ContainsKey('fc.version') -and $by.ContainsKey('fc.vendor')) {
            $src = ("COALESCE(f.[{0}], f.[{1}] + CASE WHEN NULLIF(f.[{2}], N'') IS NOT NULL THEN N' ' + f.[{2}] ELSE N'' END + CASE WHEN NULLIF(f.[{3}], N'') IS NOT NULL THEN N' (' + f.[{3}] + N')' ELSE N'' END)" -f
                [string]$e.column, $by['fc.software#product'], $by['fc.version'], $by['fc.vendor'])
        }
        $values.Add(("({0}, CONVERT(nvarchar(max), {1}))" -f $n, $src))
        $pivot.Add(("MAX(CASE WHEN g.Col = {0} THEN g.T END) AS [{1}]" -f $n, [string]$e.issue))
    }
    $names = ($cols | ForEach-Object { '[{0}]' -f [string]$_.issue }) -join ', '
    $pnames = ($cols | ForEach-Object { 'p.[{0}]' -f [string]$_.issue }) -join ', '
    # LOG VOLUME (2026-10-18): a row that is already exactly this is kept, not removed and written again (a collection prepared
    # once more rewrote every issue row, the same values). Compared EXACTLY: a text as its bytes, a number as its 8 bytes.
    # Every column the table has is one of these -- else (a column this list does not know) the collection's rows are all
    # replaced, as before, so what the table holds is always exactly what was worked out.
    $known = @('CollectionId', 'IssueKey', 'Findings', 'Assets', 'AssetNamesShown', 'AssetNames') + @($all | ForEach-Object { [string]$_.issue })
    $knownSql = ($known | ForEach-Object { "N'$_'" }) -join ', '
    $cmpX = New-Object System.Collections.Generic.List[string]; $cmpT = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(@('IssueKey', 'NVARCHAR'), @('Findings', 'INT'), @('Assets', 'INT'), @('AssetNamesShown', 'INT'), @('AssetNames', 'NVARCHAR')) + @($all | ForEach-Object { , @([string]$_.issue, [string]$_.type) })) {
        $how = '{0}.[' + $c[0] + ']'
        if ($c[1] -like 'NVARCHAR*') { $how = 'CONVERT(varbinary(max), {0}.[' + $c[0] + '])' } elseif ($c[1] -eq 'FLOAT') { $how = 'CONVERT(binary(8), {0}.[' + $c[0] + '])' }
        $cmpX.Add(($how -f 'x')); $cmpT.Add(($how -f 't'))
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #k (K NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, FindingId BIGINT NOT NULL, Rn INT NOT NULL, PRIMARY KEY (K, FindingId));
WITH m AS (
    SELECT f.Cve AS K, f.FindingId, f.RiskScore FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.Cve IS NOT NULL AND f.Cve <> N''
    UNION
    SELECT f.ConfigurationId, f.FindingId, f.RiskScore FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.ConfigurationId IS NOT NULL AND f.ConfigurationId <> N''
)
INSERT #k (K, FindingId, Rn)
SELECT m.K, m.FindingId, ROW_NUMBER() OVER (PARTITION BY m.K ORDER BY m.RiskScore DESC, m.FindingId) FROM m;
CREATE TABLE #v (K NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, Col TINYINT NOT NULL, Item NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NOT NULL, Rn INT NOT NULL);
INSERT #v (K, Col, Item, Rn)
SELECT k.K, c.Col, LTRIM(RTRIM(s.[value])), k.Rn
FROM #k AS k
JOIN sidata.Finding AS f ON f.CollectionId = @CollectionId AND f.FindingId = k.FindingId
CROSS APPLY (VALUES $($values -join ",`r`n                    ")) AS c (Col, V)
CROSS APPLY STRING_SPLIT(c.V, N';') AS s
WHERE c.V IS NOT NULL AND LTRIM(RTRIM(s.[value])) <> N'';
CREATE TABLE #a (K NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Findings INT NOT NULL, Assets INT NOT NULL$typedDecl);
INSERT #a (K, Findings, Assets$typedCols)
SELECT k.K, COUNT(*), COUNT(DISTINCT f.AssetKey)$typedAgg
FROM #k AS k JOIN sidata.Finding AS f ON f.CollectionId = @CollectionId AND f.FindingId = k.FindingId
GROUP BY k.K;
CREATE TABLE #n (K NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Shown INT NOT NULL, Names NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NULL);
WITH nm AS (
    SELECT k.K, f.AssetName, MIN(k.Rn) AS Rn
    FROM #k AS k JOIN sidata.Finding AS f ON f.CollectionId = @CollectionId AND f.FindingId = k.FindingId
    WHERE f.AssetName IS NOT NULL AND LTRIM(RTRIM(f.AssetName)) <> N''
    GROUP BY k.K, f.AssetName
), r AS (
    SELECT nm.K, nm.AssetName, nm.Rn, ROW_NUMBER() OVER (PARTITION BY nm.K ORDER BY nm.Rn, nm.AssetName) AS P FROM nm
)
INSERT #n (K, Shown, Names)
SELECT r.K, COUNT(*), STRING_AGG(CONVERT(nvarchar(max), r.AssetName), N', ') WITHIN GROUP (ORDER BY r.P)
FROM r WHERE r.P <= $($script:SIDataIssueAssetNames)
GROUP BY r.K;
SELECT TOP (0) CollectionId, IssueKey, Findings, Assets, AssetNamesShown, AssetNames, $names$typedCols INTO #ic FROM sidata.IssueContext;
WITH d AS (
    SELECT v.K, v.Col, v.Item, MIN(v.Rn) AS Rn FROM #v AS v GROUP BY v.K, v.Col, v.Item
), g AS (
    SELECT d.K, d.Col, STRING_AGG(CONVERT(nvarchar(max), d.Item), N'; ') WITHIN GROUP (ORDER BY d.Rn, d.Item) AS T
    FROM d GROUP BY d.K, d.Col
), p AS (
    SELECT g.K, $($pivot -join ",`r`n           ")
    FROM g GROUP BY g.K
)
INSERT #ic (CollectionId, IssueKey, Findings, Assets, AssetNamesShown, AssetNames, $names$typedCols)
SELECT @CollectionId, a.K, a.Findings, a.Assets, ISNULL(nn.Shown, 0), nn.Names, $pnames$typedSel
FROM #a AS a
LEFT JOIN #n AS nn ON nn.K = a.K
LEFT JOIN p ON p.K = a.K;
DECLARE @n INT = @@ROWCOUNT;
DECLARE @whole bit = CASE WHEN EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID(N'sidata.IssueContext') AND name NOT IN ($knownSql)) THEN 1 ELSE 0 END;
BEGIN TRAN;
IF @whole = 1
    DELETE FROM sidata.IssueContext WHERE CollectionId = @CollectionId;
ELSE
    DELETE t FROM sidata.IssueContext AS t
    WHERE t.CollectionId = @CollectionId
      AND NOT EXISTS (SELECT 1 FROM #ic AS x WHERE x.IssueKey = t.IssueKey
                      AND NOT EXISTS (SELECT $($cmpX -join ', ') EXCEPT SELECT $($cmpT -join ', ')));
INSERT sidata.IssueContext (CollectionId, IssueKey, Findings, Assets, AssetNamesShown, AssetNames, $names$typedCols)
SELECT x.CollectionId, x.IssueKey, x.Findings, x.Assets, x.AssetNamesShown, x.AssetNames, $(($cols | ForEach-Object { 'x.[{0}]' -f [string]$_.issue }) -join ', ')$($typedCols.Replace(', [', ', x.['))
FROM #ic AS x
WHERE NOT EXISTS (SELECT 1 FROM sidata.IssueContext AS t WHERE t.CollectionId = @CollectionId AND t.IssueKey = x.IssueKey);
UPDATE sidata.Collection SET ContextAt = SYSUTCDATETIME(), ContextSet = @Set WHERE CollectionId = @CollectionId;
COMMIT;
SELECT @n;
"@
}

function Get-SIDataFindingContextBoundsSql {
    <#
        The FindingId range of one collection and its number of findings (for the progress line). Reads the clustered key
        (sidata.Finding PK_Finding = CollectionId, FindingId): a seek, never a scan of other collections.
    #>
    "SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi, COUNT_BIG(*) AS N FROM sidata.Finding WHERE CollectionId = @CollectionId"
}

function Format-SIDataFillProgress {
    <#
        PURE. The progress of a field fill in plain words: "field fill: rows 120,000 of 1,138,554, about 25 min left". The
        time left is the pace so far; under a minute it says "less than a minute left", with nothing done yet "working".
    #>
    param([long]$Done, [long]$Total, [double]$Seconds)
    if ($Total -lt $Done) { $Total = $Done }
    $text = 'field fill: rows {0:N0} of {1:N0}' -f $Done, $Total
    if ($Done -le 0 -or $Seconds -le 0) { return "$text, working" }
    $left = ($Total - $Done) * ($Seconds / $Done)
    if ($left -lt 60) { return "$text, less than a minute left" }
    '{0}, about {1:N0} min left' -f $text, [Math]::Ceiling($left / 60)
}

function Get-SIDataContextMarkName {
    <# PURE. The resume mark of one collection's field fill for one list (sidata.ViewState.Name, at most 64). #>
    param([Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string]$SetId)
    ('ctx:{0}:{1}' -f $CollectionId, $SetId)
}

function Get-SIDataContextMarkReadSql {
    <#
        The FindingId up to which a collection's field fill is complete, or nothing. A mark written BEFORE the collection's
        views were derived again (Collection.DerivedAt after it) is not used: the derive rewrote the columns the fill reads.
    #>
    "IF OBJECT_ID('sidata.ViewState') IS NOT NULL SELECT TOP (1) v.Value FROM sidata.ViewState AS v JOIN sidata.Collection AS c ON c.CollectionId = @CollectionId WHERE v.Name = @Name AND (c.DerivedAt IS NULL OR c.DerivedAt <= v.UpdatedAt);"
}

function Get-SIDataContextMarkWriteSql {
    <# Keep the resume mark (@Name, @Value = the FindingId up to which every range is filled). #>
    "IF OBJECT_ID('sidata.ViewState') IS NOT NULL BEGIN UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = @Name; IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (@Name, @Value); END"
}

function Get-SIDataContextMarkClearSql {
    <# The collection is prepared: its resume mark goes. #>
    "IF OBJECT_ID('sidata.ViewState') IS NOT NULL DELETE FROM sidata.ViewState WHERE Name = @Name;"
}

function Get-SIDataFillWorkers {
    <#
        How many field-fill ranges run at once: the database's own cores (sys.dm_user_db_resource_governance.cpu_limit --
        what a vCore tier gives it), else the schedulers the database sees (a DTU tier answers cpu_limit 0: measured at a
        large customer's S7, 2026-10-22: 12 schedulers, max DOP 8), else 2. A measurement of the database, never a fixed
        count; the fill gives one back each time the database is saturated (SI-SqlPacing.ps1).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    # #881 each view read on its own, each refusal its own: an identity without VIEW DATABASE PERFORMANCE STATE (a data sync
    # failed on it at one install) is refused the first at compile time -- the whole statement, past its TRY -- so the
    # schedulers are asked separately, and a refusal of both is the default, never a failure
    $reads = @(
        'SELECT MAX(cpu_limit) FROM sys.dm_user_db_resource_governance WHERE database_id = DB_ID();'
        "SELECT COUNT(*) FROM sys.dm_os_schedulers WHERE status = N'VISIBLE ONLINE';"
    )
    $n = 0
    foreach ($sql in $reads) {
        try { $v = & $Invoke $sql @{} 'scalar'; if ($null -ne $v -and -not ($v -is [System.DBNull])) { $n = [int]$v } } catch { $n = 0 }
        if ($n -ge 1) { break }
    }
    if ($n -lt 1) { $n = 2 }
    [Math]::Max(1, $n)
}

function Invoke-SIDataParallelRanges {
    <#
        Runs -Sql (parameters @CollectionId, @After, @Upto; answers a row count) for every range of -Ranges (@(after, upto)
        pairs) AT ONCE, each on its own connection (-ConnectionInfo: the seam's SIConnectionInfo -- connection string and a
        current token), with no command time limit; waits for all of them. Answers @{ N; Ms } per range; the first error of
        any range is thrown after every range has ended (a range is idempotent: the next run fills it again).
        -Params: more parameters every range's statement takes (the findings per CI: the rating bands); -UpperName: the
        name the range's upper bound goes by (the findings per CI's key ranges call it @Upper).
    #>
    param([Parameter(Mandatory)][scriptblock]$ConnectionInfo, [Parameter(Mandatory)][string]$Sql, [Parameter(Mandatory)][long]$CollectionId,
          [Parameter(Mandatory)][object[]]$Ranges, [hashtable]$Params, [string]$UpperName = 'Upto')
    $info = & $ConnectionInfo
    $more = @{}; if ($Params) { foreach ($k in $Params.Keys) { if ([string]$k -notin 'CollectionId', 'After', $UpperName) { $more[[string]$k] = $Params[$k] } } }
    $work = {
        param([string]$Cs, [string]$Token, [string]$Text, [long]$Cid, [long]$After, [long]$Upto, [hashtable]$More, [string]$UpName)
        $cn = New-Object System.Data.SqlClient.SqlConnection($Cs)
        # (no token: a connection string that signs in by itself -- the tests' local server)
        if ($Token) { $cn.AccessToken = $Token }
        try {
            $cn.Open()
            $c = $cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
            [void]$c.Parameters.AddWithValue('@CollectionId', $Cid); [void]$c.Parameters.AddWithValue('@After', $After); [void]$c.Parameters.AddWithValue('@' + $UpName, $Upto)
            if ($More) { foreach ($k in $More.Keys) { $v = $More[$k]; if ($null -eq $v) { $v = [System.DBNull]::Value }; [void]$c.Parameters.AddWithValue('@' + $k, $v) } }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $v = $c.ExecuteScalar()
            [pscustomobject]@{ N = $(if ($null -eq $v -or $v -is [System.DBNull]) { 0L } else { [long]$v }); Ms = $sw.ElapsedMilliseconds }
        } finally { $cn.Dispose() }
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Ranges.Count))
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($r in $Ranges) {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            $null = $ps.AddScript($work.ToString()).AddArgument([string]$info.ConnectionString).AddArgument([string]$info.AccessToken).AddArgument($Sql).AddArgument($CollectionId).AddArgument([long]$r[0]).AddArgument([long]$r[1]).AddArgument($more).AddArgument($UpperName)
            $jobs.Add(@($ps, $ps.BeginInvoke()))
        }
        $out = New-Object System.Collections.Generic.List[object]; $err = $null
        foreach ($j in $jobs) {
            try {
                $res = @($j[0].EndInvoke($j[1]))
                if ($j[0].Streams.Error.Count -gt 0 -and $null -eq $err) { $err = $j[0].Streams.Error[0].Exception }
                if ($res.Count) { $out.Add($res[-1]) }
            } catch { if ($null -eq $err) { $err = $_.Exception } }
        }
        if ($err) { throw $err }
        , $out.ToArray()
    } finally {
        foreach ($j in $jobs) { try { $j[0].Dispose() } catch { } }
        $pool.Close(); $pool.Dispose()
    }
}

function Invoke-SIDataViewContext {
    <#
    .SYNOPSIS  Prepares the finding context and the issue context of every complete collection that has none. Never throws.
    .NOTES     Newest collection first. -BudgetSeconds: when the collections of an existing install take longer than this in
               one run, the rest follow on the next runs (said); a collection without its context is read by the web app the
               way it was before, so nothing is wrong meanwhile. A pace, not a limit on the data.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 1200, [long]$TargetMs = 5000, $List,
        # #740: how often a long field fill says how far it is (seconds; a line only while rows are left)
        [double]$ProgressSeconds = 60,
        # ranges filled at once: 0 = the database's cores (Get-SIDataFillWorkers); 1 = one after another
        [int]$Workers = 0)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (-not $List) { $List = Get-SIViewStoredColumns }
        if (-not $List) {
            & $Log 'WARN' 'context     : the list of prepared view columns (view-stored-columns.json) is not in this install or not well formed -- nothing is prepared; the views read their context from the finding rows.'
            return [pscustomobject]@{ Status = 'no-list'; Collections = 0 }
        }
        if (([int](& $Invoke (Get-SIDataFindingContextSchemaCheckSql -List $List) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' 'context     : the database does not have the views'' prepared columns yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the views read their context from the finding rows until then.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        # the list the collections are prepared for: one prepared for another list (a field was added) is prepared once more
        $setId = Get-SIViewFindingSetId -List $List
        $pendRaw = & $Invoke (Get-SIDataUncontextedSql) @{ Set = $setId } 'reader'
        $pending = @(@($pendRaw) | Where-Object { $_ })
        if ($DryRun) {
            & $Log 'INFO' ("context     : {0} collection(s) would get their prepared context; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0 } }
        $fill = Get-SIDataFindingContextSql -List $List
        $issue = Get-SIDataIssueContextSql -List $List
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $size = [long]5000; $done = 0; $rows = [long]0; $issues = [long]0
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            $cid = [int]$p['CollectionId']
            $bRaw = & $Invoke (Get-SIDataFindingContextBoundsSql) @{ CollectionId = $cid } 'reader'
            $b = @($bRaw) | Select-Object -First 1
            if ($b -and $null -ne $b['Lo'] -and -not ($b['Lo'] -is [System.DBNull])) {
                $hi = [long]$b['Hi']; $lo = [long]$b['Lo']; $after = $lo - 1
                # NO LIMITS (owner 2026-10-22, a large install: hours serial while the database sat at 4 % CPU): ONLY THE ROWS NOT YET
                # FILLED -- a fill that a run left half done goes on from the last range it finished (sidata.ViewState
                # 'ctx:<collection>:<list>', kept after every wave) instead of reading every finding's JSON again
                $mark = Get-SIDataContextMarkName -CollectionId $cid -SetId $setId
                try {
                    $wm = & $Invoke (Get-SIDataContextMarkReadSql) @{ Name = $mark; CollectionId = $cid } 'scalar'
                    if ($null -ne $wm -and -not ($wm -is [System.DBNull])) { $w = 0L; if ([long]::TryParse([string]$wm, [ref]$w) -and $w -gt $after -and $w -le $hi) { & $Log 'INFO' ("context     : collection {0} goes on where the last run left its field fill" -f $cid); $after = $w } }
                } catch { }
                # #740: a long fill is never silent -- one plain line about once a minute: the rows so far, of how many, and
                # about how long is left (from the pace so far)
                $total = $hi - $lo + 1
                $nv = $b['N']; if ($null -ne $nv -and -not ($nv -is [System.DBNull])) { $total = [long]$nv }
                $mine = [long]0; $fillClock = [Diagnostics.Stopwatch]::StartNew(); $said = [double]0
                # PARALLEL RANGES, SIZED TO THE DATABASE: as many ranges at once as the database has cores (its own
                # resource governance), one fewer each time the database is saturated (SI-SqlPacing.ps1), one more again
                # when it is not -- disjoint FindingId ranges, each on its own connection, no command time limit. A seam
                # without a connection to hand out (a test's fake) fills the ranges one after another, as before.
                $ci = $null; if ($Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) { $ci = $Invoke.SIConnectionInfo }
                $maxWorkers = 1
                if ($ci -and $Workers -ne 1) { $maxWorkers = $(if ($Workers -gt 1) { $Workers } else { Get-SIDataFillWorkers -Invoke $Invoke }) }
                $workersNow = $maxWorkers
                if ($maxWorkers -gt 1) { & $Log 'INFO' ("context     : collection {0} -- the field fill runs {1} range(s) at a time (the database's cores)" -f $cid, $maxWorkers) }
                while ($after -lt $hi) {
                    # the database's own load paces the ranges (SI-SqlPacing.ps1): a pause, a smaller range and fewer ranges
                    # at once only while it is saturated -- every range is still filled, with the same values
                    if ($paced) {
                        $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log
                        if ($pace.Shrink) { $size = [Math]::Max(500L, [long][Math]::Floor($size / 2)); $workersNow = [Math]::Max(1, $workersNow - 1) }
                        elseif ($workersNow -lt $maxWorkers -and [string]$pace.State -eq 'normal') { $workersNow++ }
                    }
                    $wave = New-Object System.Collections.Generic.List[object]
                    $from = $after
                    for ($k = 0; $k -lt $workersNow -and $from -lt $hi; $k++) { $to = [Math]::Min($hi, $from + $size); $wave.Add(@($from, $to)); $from = $to }
                    $sw = [Diagnostics.Stopwatch]::StartNew()
                    if ($wave.Count -gt 1) {
                        $res = Invoke-SIDataParallelRanges -ConnectionInfo $ci -Sql $fill -CollectionId $cid -Ranges $wave.ToArray()
                        $n = [long]0; $ms = [long]0
                        foreach ($r in $res) { $n += [long]$r.N; if ([long]$r.Ms -gt $ms) { $ms = [long]$r.Ms } }
                    } else {
                        $n = [long](& $Invoke $fill @{ CollectionId = $cid; After = $wave[0][0]; Upto = $wave[0][1] } 'scalar')
                        $ms = $sw.ElapsedMilliseconds
                    }
                    $sw.Stop(); $lastMs = $ms
                    $rows += $n; $mine += $n
                    $after = $from
                    # the wave is whole: everything up to $after is filled -- the next run starts from there
                    try { $null = & $Invoke (Get-SIDataContextMarkWriteSql) @{ Name = $mark; Value = [string]$after } 'nonquery' } catch { }
                    $size = Get-SIDataNextSize -Current $size -ElapsedMs $ms -TargetMs $TargetMs -Minimum 500
                    $now = $fillClock.Elapsed.TotalSeconds
                    if ($after -lt $hi -and ($now - $said) -ge $ProgressSeconds) {
                        $said = $now
                        & $Log 'INFO' ("context     : " + (Format-SIDataFillProgress -Done $mine -Total $total -Seconds $now))
                    }
                }
            }
            $issues += [long](& $Invoke $issue @{ CollectionId = $cid; Set = $setId } 'scalar')
            # the collection is prepared (its ContextAt is set): its resume mark is no longer needed
            try { $null = & $Invoke (Get-SIDataContextMarkClearSql) @{ Name = (Get-SIDataContextMarkName -CollectionId $cid -SetId $setId) } 'nonquery' } catch { }
            $done++
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("context     : {0} collection(s) got their prepared context ({1} finding row(s), {2} CVE / issue row(s))" -f $done, $rows, $issues)
        if ($left -gt 0) { & $Log 'INFO' ("context     : {0} older collection(s) follow on the next run(s) -- their views read the context from the finding rows until then" -f $left) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Findings = $rows; Issues = $issues; Pending = $left }
    } catch {
        & $Log 'WARN' ("context     : the views' prepared context was not completed this run -- {0}. It is tried again on the next run; the views read what is not prepared from the finding rows." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE CI CONTEXT (sidata.Ci columns)
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataCiContextSchemaCheckSql {
    <# 1 when sidata.Ci carries every column of the list and the two markers, and the tables the identifiers come from exist. #>
    param([Parameter(Mandatory)]$List)
    $parts = @(@($List.ci) | ForEach-Object { "COL_LENGTH('sidata.Ci', '{0}') IS NOT NULL" -f [string]$_.column })
    $parts += "COL_LENGTH('sidata.Ci', 'CtxHash') IS NOT NULL"
    $parts += "COL_LENGTH('sidata.Ci', 'CtxSet') IS NOT NULL"
    foreach ($t in 'AssetIdentifier', 'CiRecord', 'RecordIdentifier', 'CiLink') { $parts += ("OBJECT_ID('sidata.{0}') IS NOT NULL" -f $t) }
    'SELECT CASE WHEN ' + ($parts -join ' AND ') + ' THEN 1 ELSE 0 END'
}

function Get-SIDataCiIdentifierColumnsSql {
    <#
        The identifier VALUES and the linked object ids of every CI as columns (the LIST entries), SET-BASED: the collection's
        identifiers of the CI (sidata.AssetIdentifier), the identifiers of each of its records (sidata.RecordIdentifier) and
        every native id it links (sidata.CiLink) -- what the web app read per page before. A value once, sorted, '; '-joined.
        Only a CI whose values moved is written. Answers the number of CIs written; '' when the list has no such entry.
    #>
    param([Parameter(Mandatory)]$List)
    $lists = @(@($List.ci) | Where-Object { [string]$_.type -eq 'LIST' })
    if ($lists.Count -eq 0) { return '' }
    $sel = New-Object System.Collections.Generic.List[string]
    $set = New-Object System.Collections.Generic.List[string]
    $diff = New-Object System.Collections.Generic.List[string]
    foreach ($e in $lists) {
        $col = [string]$e.column
        if ([string]$e.key -eq 'ci.links') {
            $sel.Add(("MAX(CASE WHEN g.T = N'#links' THEN g.Vs END) AS [{0}]" -f $col))
        } else {
            $sel.Add(("MAX(CASE WHEN g.T = N'{0}' THEN g.Vs END) AS [{1}]" -f ([string]$e.key).Substring(5), $col))
        }
        $set.Add(("[{0}] = p.[{0}]" -f $col))
        $diff.Add(("ISNULL(c.[{0}], N'') <> ISNULL(p.[{0}], N'')" -f $col))
    }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #i (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, T NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, V NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL);
INSERT #i (CiId, T, V)
SELECT c.CiId, ai.IdentifierType, ai.IdentifierValue FROM sidata.Ci AS c JOIN sidata.AssetIdentifier AS ai ON ai.AssetKey = c.CiId
UNION
SELECT r.CiId, ri.IdType, ri.IdValue FROM sidata.CiRecord AS r JOIN sidata.RecordIdentifier AS ri ON ri.RecordKey = r.RecordKey WHERE r.CiId IS NOT NULL
UNION
SELECT l.CiId, N'#link', l.NativeId FROM sidata.CiLink AS l;
CREATE TABLE #g (CiId NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, T NVARCHAR(64) COLLATE DATABASE_DEFAULT NOT NULL, Vs NVARCHAR(MAX) COLLATE DATABASE_DEFAULT NULL);
INSERT #g (CiId, T, Vs)
SELECT d.CiId, d.T, STRING_AGG(CONVERT(nvarchar(max), d.V), N'; ') WITHIN GROUP (ORDER BY d.V)
FROM (SELECT DISTINCT i.CiId, i.T, i.V FROM #i AS i WHERE i.T <> N'#link') AS d
GROUP BY d.CiId, d.T;
INSERT #g (CiId, T, Vs)
SELECT d.CiId, N'#links', STRING_AGG(CONVERT(nvarchar(max), d.V), N'; ') WITHIN GROUP (ORDER BY d.T0, d.V)
FROM (SELECT i.CiId, i.V, MIN(i.T) AS T0 FROM #i AS i WHERE i.T IN (N'#link', N'SI_AssetId') GROUP BY i.CiId, i.V) AS d
GROUP BY d.CiId;
SELECT g.CiId, $($sel -join ', ')
INTO #p
FROM #g AS g GROUP BY g.CiId;
UPDATE c SET $($set -join ', ')
FROM sidata.Ci AS c LEFT JOIN #p AS p ON p.CiId = c.CiId
WHERE $($diff -join ' OR ');
SELECT @@ROWCOUNT;
"@
}

function Get-SIDataCiContextFieldsSql {
    <#
        The CI document fields of the list as columns of sidata.Ci -- SET-BASED, for the CIs whose content hash moved since
        their columns were filled (CtxHash <> ContentHash) or that were filled for another list (CtxSet <> @Set: a field was
        added -- every CI once more, without a CI build). The document is parsed ONCE per CI (OPENJSON ... WITH), in batches
        of -BatchSize so no transaction holds the table long. A text field is cut at its column's length; a number (INT /
        FLOAT), a yes / no (BIT) and a date (DATETIME2(3), UTC) are stored typed; a list / object field (JSON) is kept as its
        JSON text, a scalar in such a field as its text. Answers the number of CIs filled.
    #>
    param([Parameter(Mandatory)]$List, [int]$BatchSize = 2000)
    $set = New-Object System.Collections.Generic.List[string]
    $with = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($List.ci)) {
        $key = [string]$e.key; $col = [string]$e.column; $type = [string]$e.type
        if (-not $key.StartsWith('ci.f.')) { continue }
        $field = $key.Substring(5)
        if ($type -eq 'JSON') {
            $set.Add(("[{0}] = COALESCE(j.[{0}], j.[{0}__s])" -f $col))
            $with.Add(("[{0}] NVARCHAR(MAX) '$.{1}' AS JSON" -f $col, $field))
            $with.Add(("[{0}__s] NVARCHAR(4000) '$.{1}'" -f $col, $field))
        } elseif ($type -ne 'LIST') {
            # a text is cut at its column's length; a number, a yes / no and a date are stored as such, so a filter or a
            # sort compares values (a value that is not one stays empty -- never a guess)
            $src = "j.[$col]"
            if ($type -eq 'INT') { $set.Add(("[{0}] = TRY_CONVERT(int, TRY_CONVERT(float, {1}))" -f $col, $src)) }
            elseif ($type -eq 'FLOAT') { $set.Add(("[{0}] = TRY_CONVERT(float, {1})" -f $col, $src)) }
            elseif ($type -eq 'BIT') { $set.Add(("[{0}] = CASE LOWER({1}) WHEN N'true' THEN 1 WHEN N'false' THEN 0 WHEN N'1' THEN 1 WHEN N'0' THEN 0 END" -f $col, $src)) }
            elseif ($type -eq 'DATETIME2(3)') { $set.Add(("[{0}] = {1}" -f $col, (Get-SIViewDateSql -Expr $src))) }
            else { $set.Add(("[{0}] = LEFT({1}, {2})" -f $col, $src, (Get-SIViewTypeLength -Type $type))) }
            $with.Add(("[{0}] NVARCHAR(4000) '$.{1}'" -f $col, $field))
        }
    }
    $fill = ''
    if ($set.Count -gt 0) { $fill = ($set -join ', ') + ', ' }
    $apply = ''
    if ($with.Count -gt 0) { $apply = "OUTER APPLY OPENJSON(CASE WHEN ISJSON(c.DocJson) = 1 AND LEFT(LTRIM(c.DocJson), 1) = N'{' THEN c.DocJson END) WITH ($($with -join ', ')) AS j" }
    @"
SET NOCOUNT ON;
DECLARE @b INT = 1, @t INT = 0;
WHILE @b > 0
BEGIN
    UPDATE TOP ($BatchSize) c SET ${fill}CtxHash = ISNULL(c.ContentHash, 0x00), CtxSet = @Set
    FROM sidata.Ci AS c
    $apply
    WHERE c.CtxHash IS NULL OR c.CtxHash <> ISNULL(c.ContentHash, 0x00) OR c.CtxSet IS NULL OR c.CtxSet <> @Set;
    SET @b = @@ROWCOUNT; SET @t += @b;
END
SELECT @t;
"@
}

function Invoke-SIDataCiViewColumns {
    <#
    .SYNOPSIS  Fills the CI context columns of the list (identifier values and linked object ids, then the document fields).
               Never throws.
    .NOTES     The identifiers first: a CI is marked filled (CtxHash / CtxSet) only by the second statement, so a run that
               stops between the two leaves every CI read from its document by the web app -- never half-filled columns shown.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log, $List)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (-not $List) { $List = Get-SIViewStoredColumns }
        if (-not $List) {
            & $Log 'WARN' 'v3 model    : the list of prepared view columns (view-stored-columns.json) is not in this install or not well formed -- the CI context columns are not filled; the views read it from the CI document.'
            return [pscustomobject]@{ Status = 'no-list' }
        }
        if (([int](& $Invoke (Get-SIDataCiContextSchemaCheckSql -List $List) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' 'v3 model    : the database does not have the CI context columns yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the views read the CI context from the CI document until then.'
            return [pscustomobject]@{ Status = 'no-schema' }
        }
        $nI = 0
        $idSql = Get-SIDataCiIdentifierColumnsSql -List $List
        if ($idSql) { $nI = [int](& $Invoke $idSql @{} 'scalar') }
        $nF = [int](& $Invoke (Get-SIDataCiContextFieldsSql -List $List) @{ Set = (Get-SIViewCiSetId -List $List) } 'scalar')
        & $Log 'OK' ("v3 model    : the CI context columns filled on {0} CI(s); identifier values and linked objects written on {1} CI(s)" -f $nF, $nI)
        return [pscustomobject]@{ Status = 'ok'; Fields = $nF; Identifiers = $nI }
    } catch {
        & $Log 'WARN' ("v3 model    : the CI context columns were not filled this run ({0}) -- the views read the CI context from the CI document until the next run" -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  WHAT THE DATA SYNC LAST STORED, AS ONE VALUE (sidata.ViewState 'data')
#  The web app keeps the pages it read for its data views until this value moves (and asks a few narrow counts beside it,
#  so data stored by anything else is noticed too) -- a result is never kept by time alone.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataViewVersionSql {
    <#
        Sets sidata.ViewState 'data' to @Value and takes the "a data sync is running" row away in the SAME transaction (the
        web app sees the end mark and the end of the run together, so its kept pages move once); answers 1, or 0 on a
        database without the table (nothing is written).
    #>
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('sidata.ViewState') IS NULL
    SELECT 0;
ELSE
BEGIN
    BEGIN TRAN;
    UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = N'data';
    IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (N'data', @Value);
    DELETE FROM sidata.ViewState WHERE Name = N'sync';
    COMMIT;
    SELECT 1;
END
"@
}

# ---------------------------------------------------------------------------------------------------------------------
#  "A DATA SYNC IS RUNNING" (sidata.ViewState 'sync')
#  One row the data sync writes when it starts to write (Value = its start time, UTC; UpdatedAt = the same moment by the
#  database's clock) and takes away when it ends -- with its end mark (above), or by itself when the run fails. While the
#  row is there and younger than the web app's limit, the web app keeps serving the pages it has (the figures a data sync
#  moves while it runs do not move its result cache) and says "data is being refreshed" in its header. A row older than the
#  limit is a run that died: it is ignored. A database without the table: nothing is written, everything is as before.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataSyncRunningSql {
    <# Writes the 'sync' row (@Value = the start time); answers 1, or 0 on a database without the table. #>
    @"
SET NOCOUNT ON;
IF OBJECT_ID('sidata.ViewState') IS NULL
    SELECT 0;
ELSE
BEGIN
    UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = N'sync';
    IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (N'sync', @Value);
    SELECT 1;
END
"@
}

function Get-SIDataSyncEndedSql {
    <# Takes the 'sync' row away; answers the rows removed (0 or 1), or 0 on a database without the table. #>
    @"
SET NOCOUNT ON;
IF OBJECT_ID('sidata.ViewState') IS NULL
    SELECT 0;
ELSE
BEGIN
    DELETE FROM sidata.ViewState WHERE Name = N'sync';
    SELECT @@ROWCOUNT;
END
"@
}

function Set-SIDataSyncRunning {
    <#
    .SYNOPSIS  Says "a data sync is running" (sidata.ViewState 'sync'). Never throws.
    .NOTES     Called once, before the first write of a data sync that writes. Without it (a database without the table, or
               a failure here) the web app behaves as before: its kept pages move with every figure the run changes.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$Now = [datetime]::UtcNow, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        $value = $Now.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $done = ([string](& $Invoke (Get-SIDataSyncRunningSql) @{ Value = $value } 'scalar')) -eq '1'
        return [pscustomobject]@{ Status = $(if ($done) { 'ok' } else { 'no-schema' }); Value = $value }
    } catch {
        & $Log 'WARN' ("views       : the web app could not be told that a data sync is running ({0}) -- its pages are read again whenever this run stores something, as before." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

function Clear-SIDataSyncRunning {
    <#
    .SYNOPSIS  Takes "a data sync is running" away (sidata.ViewState 'sync'). Never throws.
    .NOTES     The end mark (Set-SIDataViewVersion) takes it away itself; this is for a run that ends without one -- it failed,
               or the mark could not be set. A run that is killed leaves the row: the web app ignores it once it is older
               than its limit.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        $n = 0; $a = & $Invoke (Get-SIDataSyncEndedSql) @{} 'scalar'; if ("$a" -match '^\d+$') { $n = [int]"$a" }
        return [pscustomobject]@{ Status = 'ok'; Removed = $n }
    } catch {
        & $Log 'WARN' ("views       : the web app could not be told that the data sync ended ({0}) -- it shows 'data is being refreshed' and keeps its pages until its own limit passes." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  ONE ROW PER CVE, PRE-COMPUTED PER COLLECTION (sidata.CveSummary / CveSummaryCounted / CveSummaryState)
#  A large customer, 2026-10-19 (1,117,524 finding rows): Security recommendations > Summary > Vulnerabilities (CVE) "keeps loading and
#  hangs for minutes", then "This view took too long and was stopped: the Pro database did not answer within 90 seconds."
#  The page grouped every finding of the collection by CVE (distinct assets, highest CVSS, most critical severity and tier)
#  on each request -- and again for every filter's counts. The aggregate is now worked out HERE, once per collection, and
#  the page pages, sorts and filters its typed, indexed rows (one row per CVE: thousands, not a million).
#  ONE pass over the collection's CVE findings, grouped by (CVE, asset, counted) into a narrow temp table; both variants are
#  rolled up from it -- every finding (CveSummary) and the findings without an exemption mark (CveSummaryCounted, the #264
#  twin the pages read when exempted findings are left out) -- and written with the state row in ONE transaction, so a page
#  sees the old rows or the new ones, never half. Every finding is counted: no cap, no sample, the same statement at every
#  size. The severity rank and the tier words are the web app's own (SeverityOrder.SqlRank, ProDataSql.TierExpr -- a test
#  holds this text to them).
#  EXISTING INSTALLS: the schema adds the tables (the updater applies sql\si-data-schema.sql); the next data sync fills every
#  complete collection, newest first, within a time budget (the rest follow on the next runs). Until a collection has its
#  rows the page says they are being prepared -- it never groups the finding rows itself. Never fails the data sync.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataCveSummarySchemaCheckSql {
    <# 1 when the database carries the three tables and the finding columns they are built from; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.CveSummary') IS NOT NULL AND OBJECT_ID('sidata.CveSummaryCounted') IS NOT NULL AND OBJECT_ID('sidata.CveSummaryState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Cvss') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'HasExploit') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCveSummaryPendingSql {
    <#
        Complete Detailed collections whose views' columns are derived (the CVSS and the exploit flag come from there) and
        whose per-CVE rows are missing -- new loads and, once, every collection stored before the tables existed -- or older
        than the derive (an asset merge or a repair derived the collection again). Newest first. Never a retired collection.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.CveSummaryState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt)$live ORDER BY c.CollectionTime DESC"
}

# the web app's own expressions (SeverityOrder.SqlRank("f.Severity"), ProDataSql.TierExpr("b.BestTier")) -- the C# tests
# compare these strings with the web app's, so the page and the rows it reads rank and word severity and tier alike
$script:SIDataCveSeverityRank = "CASE LOWER(REPLACE(REPLACE(REPLACE(LTRIM(RTRIM(COALESCE(f.Severity, N''))), N' ', N''), N'-', N''), N'_', N'')) WHEN N'veryhigh' THEN 0 WHEN N'critical' THEN 0 WHEN N'high' THEN 1 WHEN N'mediumhigh' THEN 2 WHEN N'medium' THEN 3 WHEN N'moderate' THEN 3 WHEN N'low' THEN 4 WHEN N'informational' THEN 5 WHEN N'info' THEN 5 WHEN N'information' THEN 5 WHEN N'' THEN 7 WHEN N'none' THEN 7 WHEN N'(none)' THEN 7 ELSE 6 END"
$script:SIDataCveTierWords = "CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), b.BestTier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), b.BestTier), N'Tier', N''))) ELSE N'Unclassified' END"

function Get-SIDataCveSummarySql {
    <#
        ONE collection (@CollectionId): its per-CVE rows in both variants and its state row, replacing what it held -- one
        transaction. Answers the number of CVE rows (every finding). Reads the narrow finding columns only (never DetailJson).
        A row: the CVE, its title, the most critical severity (and its rank), the highest CVSS, whether any finding has a
        known exploit, the exact number of distinct assets, the findings, the highest and the total risk score, the most
        critical tier and the findings on tier 0 -- exactly what the page computed per request before.
    #>
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #g (Cve NVARCHAR(100) COLLATE DATABASE_DEFAULT NOT NULL, AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NULL, Counted BIT NOT NULL,
                 N INT NOT NULL, Title NVARCHAR(1000) NULL, SevKey NVARCHAR(40) NULL, Cvss FLOAT NULL, X INT NOT NULL,
                 MaxRisk FLOAT NULL, TotalRisk FLOAT NULL, BestTier TINYINT NULL, T0 INT NOT NULL);
INSERT #g (Cve, AssetKey, Counted, N, Title, SevKey, Cvss, X, MaxRisk, TotalRisk, BestTier, T0)
SELECT f.Cve, f.AssetKey, CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END,
       COUNT(*), MAX(f.Title), MIN(CONCAT({RANK}, N'|', f.Severity)), MAX(f.Cvss), MAX(CASE WHEN f.HasExploit = 1 THEN 1 ELSE 0 END),
       MAX(f.RiskScore), SUM(f.RiskScore), MIN(f.Tier), SUM(CASE WHEN f.Tier = 0 THEN 1 ELSE 0 END)
FROM sidata.Finding AS f
-- #855: the CVEs of ACTIVE CIs only (a finding no CI carries, or of a collection stored before the lifecycle, counts as active):
-- the page says so; the key (CollectionId, Cve) cannot take the lifecycle in an additive schema
WHERE f.CollectionId = @CollectionId AND f.Cve IS NOT NULL AND (f.CiLifecycle IS NULL OR f.CiLifecycle = N'active')
GROUP BY f.Cve, f.AssetKey, CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END;
CREATE TABLE #s (Counted BIT NOT NULL, Cve NVARCHAR(100) COLLATE DATABASE_DEFAULT NOT NULL, Title NVARCHAR(1000) NULL, Severity NVARCHAR(30) NULL,
                 SeverityRank INT NOT NULL, Cvss FLOAT NULL, HasExploit BIT NOT NULL, Assets INT NOT NULL, Findings INT NOT NULL,
                 MaxRisk FLOAT NULL, TotalRisk FLOAT NULL, Tier NVARCHAR(12) NOT NULL, Tier0Findings INT NOT NULL, PRIMARY KEY (Counted, Cve));
WITH b AS (
    SELECT CONVERT(bit, 0) AS Counted, g.Cve, MAX(g.Title) AS Title, MIN(g.SevKey) AS SevKey, MAX(g.Cvss) AS Cvss, MAX(g.X) AS X,
           COUNT(DISTINCT g.AssetKey) AS Assets, SUM(g.N) AS Findings, MAX(g.MaxRisk) AS MaxRisk, SUM(g.TotalRisk) AS TotalRisk,
           MIN(g.BestTier) AS BestTier, SUM(g.T0) AS T0
    FROM #g AS g GROUP BY g.Cve
    UNION ALL
    SELECT CONVERT(bit, 1), g.Cve, MAX(g.Title), MIN(g.SevKey), MAX(g.Cvss), MAX(g.X),
           COUNT(DISTINCT g.AssetKey), SUM(g.N), MAX(g.MaxRisk), SUM(g.TotalRisk), MIN(g.BestTier), SUM(g.T0)
    FROM #g AS g WHERE g.Counted = 1 GROUP BY g.Cve
)
INSERT #s (Counted, Cve, Title, Severity, SeverityRank, Cvss, HasExploit, Assets, Findings, MaxRisk, TotalRisk, Tier, Tier0Findings)
SELECT b.Counted, b.Cve, b.Title, NULLIF(SUBSTRING(b.SevKey, CHARINDEX(N'|', b.SevKey) + 1, 30), N''), ISNULL(TRY_CONVERT(int, LEFT(b.SevKey, 1)), 7),
       b.Cvss, CONVERT(bit, b.X), b.Assets, b.Findings, b.MaxRisk, b.TotalRisk, {TIER}, b.T0
FROM b;
DECLARE @cves INT = (SELECT COUNT(*) FROM #s WHERE Counted = 0);
DECLARE @counted INT = (SELECT COUNT(*) FROM #s WHERE Counted = 1);
DECLARE @findings BIGINT = (SELECT ISNULL(SUM(CONVERT(bigint, g.N)), 0) FROM #g AS g);
BEGIN TRAN;
DELETE FROM sidata.CveSummary WHERE CollectionId = @CollectionId;
INSERT sidata.CveSummary (CollectionId, Cve, Title, Severity, SeverityRank, Cvss, HasExploit, Assets, Findings, MaxRisk, TotalRisk, Tier, Tier0Findings)
SELECT @CollectionId, s.Cve, s.Title, s.Severity, s.SeverityRank, s.Cvss, s.HasExploit, s.Assets, s.Findings, s.MaxRisk, s.TotalRisk, s.Tier, s.Tier0Findings FROM #s AS s WHERE s.Counted = 0;
DELETE FROM sidata.CveSummaryCounted WHERE CollectionId = @CollectionId;
INSERT sidata.CveSummaryCounted (CollectionId, Cve, Title, Severity, SeverityRank, Cvss, HasExploit, Assets, Findings, MaxRisk, TotalRisk, Tier, Tier0Findings)
SELECT @CollectionId, s.Cve, s.Title, s.Severity, s.SeverityRank, s.Cvss, s.HasExploit, s.Assets, s.Findings, s.MaxRisk, s.TotalRisk, s.Tier, s.Tier0Findings FROM #s AS s WHERE s.Counted = 1;
DELETE FROM sidata.CveSummaryState WHERE CollectionId = @CollectionId;
INSERT sidata.CveSummaryState (CollectionId, BuiltAt, Cves, CountedCves, Findings) VALUES (@CollectionId, SYSUTCDATETIME(), @cves, @counted, @findings);
COMMIT;
SELECT @cves;
'@).Replace('{RANK}', $script:SIDataCveSeverityRank).Replace('{TIER}', $script:SIDataCveTierWords)
}

function Invoke-SIDataCveSummary {
    <#
    .SYNOPSIS  Writes the per-CVE rows of every complete collection that has none (or older than its derive). Never throws.
    .NOTES     Newest collection first, so the collection the page opens by default is the first one written. -BudgetSeconds:
               when the collections of an existing install take longer than this in one run, the rest follow on the next
               runs (said); the page says a collection's list is being prepared until then. A pace, not a limit on the data:
               every finding of a collection is counted. Paced by the database's own load (SI-SqlPacing.ps1) when loaded.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        if (([int](& $Invoke (Get-SIDataCveSummarySchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' 'cves        : the database does not have the per-CVE tables yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); Security recommendations > Summary > Vulnerabilities (CVE) says its list is being prepared until then.'
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke (Get-SIDataCveSummaryPendingSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
        if ($DryRun) {
            & $Log 'INFO' ("cves        : {0} collection(s) would get their per-CVE rows; nothing is written." -f $pending.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0; Cves = 0 } }
        $sql = Get-SIDataCveSummarySql
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $done = 0; $cves = [long]0
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            if ($paced) { $null = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $n = & $Invoke $sql @{ CollectionId = [int]$p['CollectionId'] } 'scalar'
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            if ("$n" -match '^\d+$') { $cves += [long]"$n" }
            $done++
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("cves        : {0} collection(s) got their per-CVE rows ({1} CVE row(s)) -- Security recommendations > Summary > Vulnerabilities (CVE) reads them" -f $done, $cves)
        if ($left -gt 0) { & $Log 'INFO' ("cves        : {0} older collection(s) follow on the next run(s) -- their Vulnerabilities list says it is being prepared until then" -f $left) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Cves = $cves; Pending = $left }
    } catch {
        & $Log 'WARN' ("cves        : the per-CVE rows were not completed this run -- {0}. They are tried again on the next run; until then Security recommendations > Summary > Vulnerabilities (CVE) says the collection's list is being prepared." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  ONE ROW PER CI, AND THE DOMAIN -> CATEGORY PAIRS, PRE-COMPUTED PER COLLECTION (2026-10-19, the same rule as the per-CVE
#  rows above: "SI views: SQL-cached + indexed columns" -- a large customer, 1,117,524 finding rows / ~3,000 CIs).
#  (1) sidata.AssetRiskSummary / AssetRiskSummaryCounted / AssetRiskSummaryState: Assets & services > Risk scores, the Weighted risk
#      score's distribution tab and Assets (CIs) at risk grouped every finding of the collection by CI on each request
#      (#284 measured 1.5 s on ring 1). ONE pass over the collection's findings, grouped by CI with both variants side by
#      side (every finding / the findings without an exemption mark -- the #264 twin), written with the state row in ONE
#      transaction. Exactly the aggregate the pages computed before (a real-SQL test holds the two equal).
#  (2) sidata.DomainCategory / DomainCategoryState: the Security owners page read the Category of EVERY finding's DetailJson
#      of the newest collection on each page open. The distinct pairs are written once per collection.
#  EXISTING INSTALLS: the schema adds the tables (the updater applies sql\si-data-schema.sql); the next data sync fills every
#  complete collection, newest first, within a time budget (the rest follow on the next runs). Until a collection has its
#  rows the pages say they are being prepared -- they never group the finding rows themselves. Never fails the data sync.
# ---------------------------------------------------------------------------------------------------------------------

function Invoke-SIDataCollectionSummary {
    <#
    .SYNOPSIS  The shared runner of a per-collection summary: schema check, the pending collections (newest first), one build
               statement per collection within a time budget. Never throws. Used by Invoke-SIDataAssetRiskSummary and
               Invoke-SIDataDomainCategory.
    .NOTES     -BudgetSeconds is a pace, not a limit on the data: every finding of a collection is read. Paced by the
               database's own load (SI-SqlPacing.ps1) when loaded.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$Rows,
        [Parameter(Mandatory)][string]$Page, [Parameter(Mandatory)][string]$SchemaSql, [Parameter(Mandatory)][string]$PendingSql,
        [Parameter(Mandatory)][string]$BuildSql, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900
    )
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $label = $Tag.PadRight(12)
    try {
        if (([int](& $Invoke $SchemaSql @{} 'scalar')) -ne 1) {
            & $Log 'WARN' ("{0}: the database does not have the {1} tables yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); {2} says its list is being prepared until then." -f $label, $Rows, $Page)
            return [pscustomobject]@{ Status = 'no-schema'; Collections = 0 }
        }
        $pending = @(@(& $Invoke $PendingSql @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
        if ($DryRun) {
            & $Log 'INFO' ("{0}: {1} collection(s) would get their {2}; nothing is written." -f $label, $pending.Count, $Rows)
            return [pscustomobject]@{ Status = 'dry-run'; Collections = 0; Pending = $pending.Count }
        }
        if ($pending.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Collections = 0; Pending = 0; Rows = 0 } }
        $clock = [Diagnostics.Stopwatch]::StartNew()
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $done = 0; $written = [long]0
        foreach ($p in $pending) {
            if ($done -gt 0 -and $clock.Elapsed.TotalSeconds -gt $BudgetSeconds) { break }
            if ($paced) { $null = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $n = & $Invoke $BuildSql @{ CollectionId = [int]$p['CollectionId'] } 'scalar'
            $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
            if ("$n" -match '^\d+$') { $written += [long]"$n" }
            $done++
        }
        $left = $pending.Count - $done
        & $Log 'OK' ("{0}: {1} collection(s) got their {2} ({3} row(s)) -- {4} reads them" -f $label, $done, $Rows, $written, $Page)
        if ($left -gt 0) { & $Log 'INFO' ("{0}: {1} older collection(s) follow on the next run(s) -- {2} says its list is being prepared until then" -f $label, $left, $Page) }
        return [pscustomobject]@{ Status = 'ok'; Collections = $done; Rows = $written; Pending = $left }
    } catch {
        & $Log 'WARN' ("{0}: the {1} were not completed this run -- {2}. They are tried again on the next run; until then {3} says the collection's list is being prepared." -f $label, $Rows, $_.Exception.Message, $Page)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

function Get-SIDataAssetRiskSummarySchemaCheckSql {
    <# 1 when the database carries the three tables and the finding columns they are built from; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.AssetRiskSummary') IS NOT NULL AND OBJECT_ID('sidata.AssetRiskSummaryCounted') IS NOT NULL AND OBJECT_ID('sidata.AssetRiskSummaryState') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskScoreWeighted') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RiskRating') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataAssetRiskSummaryPendingSql {
    <#
        Complete Detailed collections whose views' columns are derived (the weighted score and the risk rating come from
        there) and whose per-CI rows are missing -- new loads and, once, every collection stored before the tables existed --
        or older than the derive (an asset merge or a repair derived the collection again). Newest first. Never retired.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.AssetRiskSummaryState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.DerivedAt IS NOT NULL AND (s.CollectionId IS NULL OR s.BuiltAt < c.DerivedAt)$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataAssetRiskSummarySql {
    <#
        ONE collection (@CollectionId): its per-CI rows in both variants and its state row, replacing what it held -- one
        transaction. Answers the number of CI rows (every finding). Reads the narrow finding columns only (never DetailJson).
        A row: the CI key, its findings' asset name (MAX) and most critical tier (MIN), the findings, those with a CVE, the
        total / highest / average risk score and weighted score, the findings rated critical and high -- exactly what Risk
        score (CollectionViewSql.AssetRiskLive) and Assets (CollectionViewSql.AssetsLive) computed per request before. The
        counted variant is every column over the findings without an exemption mark (a CI with none of those has no row).
        The state row also carries the Tier board's "Unclassified findings" line (ProDataSql.UnclassifiedFindingsText before).
    #>
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #a (AssetKey NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY,
                 AssetName NVARCHAR(400) NULL, Tier TINYINT NULL, Findings BIGINT NOT NULL, Vulnerabilities BIGINT NOT NULL,
                 TotalRisk FLOAT NULL, MaxRisk FLOAT NULL, AvgRisk FLOAT NULL, TotalWeighted FLOAT NULL, MaxWeighted FLOAT NULL, AvgWeighted FLOAT NULL,
                 CriticalRated INT NOT NULL, HighRated INT NOT NULL,
                 cAssetName NVARCHAR(400) NULL, cTier TINYINT NULL, cFindings BIGINT NOT NULL, cVulnerabilities BIGINT NOT NULL,
                 cTotalRisk FLOAT NULL, cMaxRisk FLOAT NULL, cAvgRisk FLOAT NULL, cTotalWeighted FLOAT NULL, cMaxWeighted FLOAT NULL, cAvgWeighted FLOAT NULL,
                 cCriticalRated INT NOT NULL, cHighRated INT NOT NULL, Uncl BIGINT NOT NULL, cUncl BIGINT NOT NULL, Wr FLOAT NULL, cWr FLOAT NULL,
                 Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL);
-- #855: each CI row carries its CI's lifecycle (every finding of one CI has the same) and its unclassified findings, so a view
-- counts the lifecycle a person chose (default: active) -- the Tier board's unclassified line too
INSERT #a
SELECT f.AssetKey,
       MAX(f.AssetName), MIN(f.Tier), COUNT_BIG(*), SUM(CASE WHEN f.Cve IS NOT NULL THEN 1 ELSE 0 END),
       SUM(f.RiskScore), MAX(f.RiskScore), AVG(f.RiskScore), SUM(f.RiskScoreWeighted), MAX(f.RiskScoreWeighted), AVG(f.RiskScoreWeighted),
       SUM(CASE WHEN f.RiskRating = N'Critical' THEN 1 ELSE 0 END), SUM(CASE WHEN f.RiskRating = N'High' THEN 1 ELSE 0 END),
       MAX(CASE WHEN f.ExemptionId IS NULL THEN f.AssetName END), MIN(CASE WHEN f.ExemptionId IS NULL THEN f.Tier END),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END), SUM(CASE WHEN f.ExemptionId IS NULL AND f.Cve IS NOT NULL THEN 1 ELSE 0 END),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScore END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScore END), AVG(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScore END),
       SUM(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScoreWeighted END), MAX(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScoreWeighted END), AVG(CASE WHEN f.ExemptionId IS NULL THEN f.RiskScoreWeighted END),
       SUM(CASE WHEN f.ExemptionId IS NULL AND f.RiskRating = N'Critical' THEN 1 ELSE 0 END), SUM(CASE WHEN f.ExemptionId IS NULL AND f.RiskRating = N'High' THEN 1 ELSE 0 END),
       SUM(CASE WHEN {UNCL} THEN 1 ELSE 0 END), SUM(CASE WHEN f.ExemptionId IS NULL AND {UNCL} THEN 1 ELSE 0 END),
       SUM(COALESCE(f.RiskScoreWeighted, f.RiskScore)), SUM(CASE WHEN f.ExemptionId IS NULL THEN COALESCE(f.RiskScoreWeighted, f.RiskScore) END),
       MAX(f.CiLifecycle)
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NOT NULL
GROUP BY f.AssetKey;
DECLARE @assets INT = (SELECT COUNT(*) FROM #a);
DECLARE @counted INT = (SELECT COUNT(*) FROM #a WHERE cFindings > 0);
DECLARE @findings BIGINT = (SELECT ISNULL(SUM(a.Findings), 0) FROM #a AS a);
-- the Tier board's unclassified line: the findings without a CI key are a seek on (CollectionId, AssetKey IS NULL)
DECLARE @nk BIGINT = 0, @cnk BIGINT = 0;
SELECT @nk = COUNT_BIG(*), @cnk = ISNULL(SUM(CASE WHEN f.ExemptionId IS NULL THEN 1 ELSE 0 END), 0)
FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.AssetKey IS NULL AND {UNCL};
DECLARE @uf BIGINT = (SELECT ISNULL(SUM(a.Uncl), 0) FROM #a AS a) + @nk;
DECLARE @ua BIGINT = (SELECT COUNT_BIG(*) FROM #a AS a WHERE a.Uncl > 0);
DECLARE @cuf BIGINT = (SELECT ISNULL(SUM(a.cUncl), 0) FROM #a AS a) + @cnk;
DECLARE @cua BIGINT = (SELECT COUNT_BIG(*) FROM #a AS a WHERE a.cUncl > 0);
BEGIN TRAN;
DELETE FROM sidata.AssetRiskSummary WHERE CollectionId = @CollectionId;
INSERT sidata.AssetRiskSummary (CollectionId, AssetKey, AssetName, Tier, Findings, Vulnerabilities, TotalRisk, MaxRisk, AvgRisk, TotalWeighted, MaxWeighted, AvgWeighted, CriticalRated, HighRated, TotalWeightedOrRisk, CiLifecycle, Unclassified)
SELECT @CollectionId, a.AssetKey, a.AssetName, a.Tier, a.Findings, a.Vulnerabilities, a.TotalRisk, a.MaxRisk, a.AvgRisk, a.TotalWeighted, a.MaxWeighted, a.AvgWeighted, a.CriticalRated, a.HighRated, a.Wr, a.Lc, a.Uncl FROM #a AS a;
DELETE FROM sidata.AssetRiskSummaryCounted WHERE CollectionId = @CollectionId;
INSERT sidata.AssetRiskSummaryCounted (CollectionId, AssetKey, AssetName, Tier, Findings, Vulnerabilities, TotalRisk, MaxRisk, AvgRisk, TotalWeighted, MaxWeighted, AvgWeighted, CriticalRated, HighRated, TotalWeightedOrRisk, CiLifecycle, Unclassified)
SELECT @CollectionId, a.AssetKey, a.cAssetName, a.cTier, a.cFindings, a.cVulnerabilities, a.cTotalRisk, a.cMaxRisk, a.cAvgRisk, a.cTotalWeighted, a.cMaxWeighted, a.cAvgWeighted, a.cCriticalRated, a.cHighRated, a.cWr, a.Lc, a.cUncl FROM #a AS a WHERE a.cFindings > 0;
DELETE FROM sidata.AssetRiskSummaryState WHERE CollectionId = @CollectionId;
INSERT sidata.AssetRiskSummaryState (CollectionId, BuiltAt, Assets, CountedAssets, Findings, UnclassifiedFindings, UnclassifiedAssets, UnclassifiedWithoutAsset,
                                     CountedUnclassifiedFindings, CountedUnclassifiedAssets, CountedUnclassifiedWithoutAsset)
VALUES (@CollectionId, SYSUTCDATETIME(), @assets, @counted, @findings, @uf, @ua, @nk, @cuf, @cua, @cnk);
COMMIT;
SELECT @assets;
'@).Replace('{UNCL}', "$($script:SIDataAssetTierWords) = N'Unclassified'")
}

# the web app's own tier words over the finding (ProDataSql.TierExpr("f.Tier")) -- the C# tests compare this string with the
# web app's, so the Tier board's unclassified line counts exactly what it counted per request before
$script:SIDataAssetTierWords = "CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), f.Tier), N'Tier', N''))) ELSE N'Unclassified' END"

function Invoke-SIDataAssetRiskSummary {
    <# .SYNOPSIS Writes the per-CI rows of every complete collection that has none (or older than its derive). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'assetrisk' -Rows 'per-CI rows' -Page 'Assets & services > Risk scores / Assets (CIs) at risk' `
        -SchemaSql (Get-SIDataAssetRiskSummarySchemaCheckSql) -PendingSql (Get-SIDataAssetRiskSummaryPendingSql) -BuildSql (Get-SIDataAssetRiskSummarySql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}

function Get-SIDataDomainCategorySchemaCheckSql {
    <# 1 when the database carries the two tables; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.DomainCategory') IS NOT NULL AND OBJECT_ID('sidata.DomainCategoryState') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataDomainCategoryPendingSql {
    <# Complete Detailed collections without their pairs (or with pairs older than a re-derive). Newest first. Never retired. #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.DomainCategoryState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND (s.CollectionId IS NULL OR (c.DerivedAt IS NOT NULL AND s.BuiltAt < c.DerivedAt))$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataDomainCategorySql {
    <#
        ONE collection (@CollectionId): its distinct Domain -> Category pairs (the finding's SecurityDomain, the Category of
        its Risk Analysis row -- an invalid JSON row has none, never a failure) and its state row, replacing what it held --
        one transaction. Every pair (no TOP: the page reads the first 500 in name order, as it did). Answers the number.
        Exactly the expression ExemptionStore.CategoryPairsSql read per request before.
        #834 (measured at internal 2026-10-20, a small database: this one SELECT DISTINCT over every finding's DetailJson took
        239 s per collection): a collection whose views' columns were derived with the Category stored (sidata.Finding.RaCategory,
        the same expression -- Get-SIDataDeriveFindingSql) reads the pairs from its narrow index (IX_Finding_RaCategory, one
        range of the collection); a collection derived before the column existed (it is empty) reads DetailJson as before.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #p (Domain NVARCHAR(128) COLLATE DATABASE_DEFAULT NOT NULL, Category NVARCHAR(128) COLLATE DATABASE_DEFAULT NOT NULL);
DECLARE @stored bit = 0;
IF COL_LENGTH('sidata.Finding', 'RaCategory') IS NOT NULL
   AND EXISTS (SELECT 1 FROM sidata.Collection AS c WHERE c.CollectionId = @CollectionId AND c.DerivedAt IS NOT NULL)
    EXEC sp_executesql N'SELECT @s = CASE WHEN EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = @c AND f.RaCategory IS NOT NULL) THEN 1 ELSE 0 END;
IF @s = 1
    INSERT #p (Domain, Category)
    SELECT DISTINCT f.SecurityDomain, f.RaCategory FROM sidata.Finding AS f
    WHERE f.CollectionId = @c AND f.SecurityDomain IS NOT NULL AND f.RaCategory IS NOT NULL;', N'@c int, @s bit OUTPUT', @c = @CollectionId, @s = @stored OUTPUT;
IF @stored = 0
INSERT #p (Domain, Category)
SELECT DISTINCT x.Domain, x.Category
FROM (SELECT f.SecurityDomain AS Domain, LEFT(CASE WHEN ISJSON(f.DetailJson) = 1 THEN JSON_VALUE(f.DetailJson, '$.Category') END, 128) AS Category
      FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId AND f.SecurityDomain IS NOT NULL) AS x
WHERE x.Category IS NOT NULL;
DECLARE @n INT = (SELECT COUNT(*) FROM #p);
BEGIN TRAN;
DELETE FROM sidata.DomainCategory WHERE CollectionId = @CollectionId;
INSERT sidata.DomainCategory (CollectionId, Domain, Category) SELECT @CollectionId, p.Domain, p.Category FROM #p AS p;
DELETE FROM sidata.DomainCategoryState WHERE CollectionId = @CollectionId;
INSERT sidata.DomainCategoryState (CollectionId, BuiltAt, Pairs) VALUES (@CollectionId, SYSUTCDATETIME(), @n);
COMMIT;
SELECT @n;
'@
}

function Invoke-SIDataDomainCategory {
    <# .SYNOPSIS Writes the Domain -> Category pairs of every complete collection that has none. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'categories' -Rows 'domain/category pairs' -Page 'the Security owners page' `
        -SchemaSql (Get-SIDataDomainCategorySchemaCheckSql) -PendingSql (Get-SIDataDomainCategoryPendingSql) -BuildSql (Get-SIDataDomainCategorySql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}
# ---- Reports > Outputs' preview counts (sidata.ReportPreviewCount / ReportPreviewState) ---------------------------------
# The findings of a collection per (report, domain, severity, tier, CVE or not) -- exactly the group SqlReportStore.PreviewSql
# computed from every finding on each open of the Outputs page. Every finding (the page has no exempted toggle).

function Get-SIDataReportPreviewSchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.ReportPreviewCount') IS NOT NULL AND OBJECT_ID('sidata.ReportPreviewState') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataReportPreviewPendingSql {
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c LEFT JOIN sidata.ReportPreviewState AS s ON s.CollectionId = c.CollectionId WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND (s.CollectionId IS NULL OR (c.DerivedAt IS NOT NULL AND s.BuiltAt < c.DerivedAt))$live ORDER BY c.CollectionTime DESC"
}

function Get-SIDataReportPreviewSql {
    <# ONE collection (@CollectionId): its preview groups and state row, replacing what it held -- one transaction. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #p (RowId INT IDENTITY(1, 1) NOT NULL, ReportName NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, SecurityDomain NVARCHAR(128) COLLATE DATABASE_DEFAULT NULL,
                 Severity NVARCHAR(30) COLLATE DATABASE_DEFAULT NULL, Tier TINYINT NULL, IsCve BIT NOT NULL, Findings BIGINT NOT NULL);
INSERT #p (ReportName, SecurityDomain, Severity, Tier, IsCve, Findings)
SELECT f.ReportName, f.SecurityDomain, f.Severity, f.Tier, CASE WHEN f.Cve IS NULL OR f.Cve = N'' THEN 0 ELSE 1 END, COUNT_BIG(*)
FROM sidata.Finding AS f WHERE f.CollectionId = @CollectionId
GROUP BY f.ReportName, f.SecurityDomain, f.Severity, f.Tier, CASE WHEN f.Cve IS NULL OR f.Cve = N'' THEN 0 ELSE 1 END;
DECLARE @n INT = (SELECT COUNT(*) FROM #p);
DECLARE @findings BIGINT = (SELECT ISNULL(SUM(Findings), 0) FROM #p);
BEGIN TRAN;
DELETE FROM sidata.ReportPreviewCount WHERE CollectionId = @CollectionId;
INSERT sidata.ReportPreviewCount (CollectionId, RowId, ReportName, SecurityDomain, Severity, Tier, IsCve, Findings)
SELECT @CollectionId, p.RowId, p.ReportName, p.SecurityDomain, p.Severity, p.Tier, p.IsCve, p.Findings FROM #p AS p;
DELETE FROM sidata.ReportPreviewState WHERE CollectionId = @CollectionId;
INSERT sidata.ReportPreviewState (CollectionId, BuiltAt, Groups, Findings) VALUES (@CollectionId, SYSUTCDATETIME(), @n, @findings);
COMMIT;
SELECT @n;
'@
}

function Invoke-SIDataReportPreview {
    <# .SYNOPSIS Writes the Outputs page's preview counts of every complete collection that has none. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'preview' -Rows 'preview counts' -Page 'Reports > Outputs' `
        -SchemaSql (Get-SIDataReportPreviewSchemaCheckSql) -PendingSql (Get-SIDataReportPreviewPendingSql) -BuildSql (Get-SIDataReportPreviewSql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}

# ---- Assets (CIs) > Findings per finding key (sidata.CiFindingSummary / CiFindingSummaryState) ---------------------------
# One row per finding x tier x severity x CMDB group of sidata.CiFinding -- exactly CiSql.SummaryLiveSpec, which grouped every
# CI finding on each request. sidata.CiFinding holds the findings of ONE collection (its CollectionTime), replaced by each CI
# build: the summary is written under that collection, after the CI build of the run, and again when the CI build replaced
# the rows (their count differs). The page reads the summary of the collection the run published.

function Get-SIDataCiFindingSummarySchemaCheckSql {
    "SELECT CASE WHEN OBJECT_ID('sidata.CiFindingSummary') IS NOT NULL AND OBJECT_ID('sidata.CiFindingSummaryState') IS NOT NULL AND OBJECT_ID('sidata.CiFinding') IS NOT NULL AND OBJECT_ID('sidata.Ci') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCiFindingSummaryPendingSql {
    # #855: a summary built before it carried the CIs' lifecycle (a row without it) is built again once
    "SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c WHERE c.Status = 'Complete' AND c.Kind = 'Detailed' AND c.CollectionTime = (SELECT MAX(cf.CollectionTime) FROM sidata.CiFinding AS cf) AND (NOT EXISTS (SELECT 1 FROM sidata.CiFindingSummaryState AS s WHERE s.CollectionId = c.CollectionId AND s.CiFindings = (SELECT COUNT_BIG(*) FROM sidata.CiFinding)) OR EXISTS (SELECT 1 FROM sidata.CiFindingSummary AS x WHERE x.CollectionId = c.CollectionId AND x.CiLifecycle IS NULL))"
}

function Get-SIDataCiFindingSummarySql {
    <# The CI findings' summary under @CollectionId, replacing what it held -- one transaction. #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #s (RowId INT IDENTITY(1, 1) NOT NULL, RowKey NVARCHAR(600) COLLATE DATABASE_DEFAULT NOT NULL, Domain NVARCHAR(128) COLLATE DATABASE_DEFAULT NULL,
                 FindingKey NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, Title NVARCHAR(1000) NULL, Tier TINYINT NULL, Severity NVARCHAR(16) COLLATE DATABASE_DEFAULT NULL,
                 CmdbId NVARCHAR(256) COLLATE DATABASE_DEFAULT NULL, CmdbName NVARCHAR(400) NULL, CiCount BIGINT NOT NULL, MaxRiskScore FLOAT NULL, WeightedTotal FLOAT NULL,
                 RiskRating NVARCHAR(16) NULL, Lc NVARCHAR(16) COLLATE DATABASE_DEFAULT NOT NULL);
-- #855: the CI's lifecycle is a KEY of every row (a CI without a lifecycle, or a finding without a CI, is active) -- the page
-- reads the lifecycle a person chose (default: active); the RowKey stays the grid's key per lifecycle
INSERT #s (RowKey, Domain, FindingKey, Title, Tier, Severity, CmdbId, CmdbName, CiCount, MaxRiskScore, WeightedTotal, RiskRating, Lc)
SELECT CONCAT(f.FindingKey, N'|', COALESCE(CONVERT(nvarchar(4), f.Tier), N''), N'|', COALESCE(f.Severity, N''), N'|', COALESCE(c.CmdbId, N'')),
       MAX(f.SecurityDomain), f.FindingKey, MAX(f.Title), f.Tier, f.Severity, c.CmdbId, MAX(c.CmdbName), COUNT_BIG(DISTINCT COALESCE(f.CiId, f.AssetId)),
       MAX(f.RiskScore), SUM(ISNULL(f.WeightedRiskScore, 0)), MAX(f.RiskRating), ISNULL(NULLIF(c.Lifecycle, N''), N'active')
FROM sidata.CiFinding AS f
LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
GROUP BY ISNULL(NULLIF(c.Lifecycle, N''), N'active'), f.FindingKey, f.Tier, f.Severity, c.CmdbId;
DECLARE @n INT = (SELECT COUNT(*) FROM #s);
DECLARE @rows BIGINT = (SELECT COUNT_BIG(*) FROM sidata.CiFinding);
BEGIN TRAN;
DELETE FROM sidata.CiFindingSummary WHERE CollectionId = @CollectionId;
INSERT sidata.CiFindingSummary (CollectionId, RowId, RowKey, Domain, FindingKey, Title, Tier, Severity, CmdbId, CmdbName, CiCount, MaxRiskScore, WeightedTotal, RiskRating, CiLifecycle)
SELECT @CollectionId, s.RowId, s.RowKey, s.Domain, s.FindingKey, s.Title, s.Tier, s.Severity, s.CmdbId, s.CmdbName, s.CiCount, s.MaxRiskScore, s.WeightedTotal, s.RiskRating, s.Lc FROM #s AS s;
DELETE FROM sidata.CiFindingSummaryState WHERE CollectionId = @CollectionId;
INSERT sidata.CiFindingSummaryState (CollectionId, BuiltAt, Groups, CiFindings) VALUES (@CollectionId, SYSUTCDATETIME(), @n, @rows);
COMMIT;
SELECT @n;
'@
}

function Invoke-SIDataCiFindingSummary {
    <# .SYNOPSIS Writes the CI findings' summary of the collection sidata.CiFinding holds, when it has none or an older one. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log, [int]$BudgetSeconds = 900)
    Invoke-SIDataCollectionSummary -Invoke $Invoke -Tag 'cisummary' -Rows 'CI findings summary' -Page 'Assets (CIs) > Findings per finding key' `
        -SchemaSql (Get-SIDataCiFindingSummarySchemaCheckSql) -PendingSql (Get-SIDataCiFindingSummaryPendingSql) -BuildSql (Get-SIDataCiFindingSummarySql) `
        -DryRun:$DryRun -Log $Log -BudgetSeconds $BudgetSeconds
}


# ---------------------------------------------------------------------------------------------------------------------
#  A COLLECTION IS SHOWN BY THE VIEWS WHEN ITS VIEW DATA IS READY (sidata.Collection.ViewsReadyAt)
#  'Complete' says every finding row of a collection is loaded -- minutes before its views' aggregates, its prepared
#  context, its departments and its counted aggregates are written. The collection views list on this mark instead, so a
#  page never opens a collection it would have to work out row by row. Every OTHER reader keeps reading 'Complete'.
#  Set for EVERY complete collection that has no mark yet, on every run: a run that died before this step leaves its
#  collection out of the views (the previous one stays the newest shown), and the next run finishes and marks it.
# ---------------------------------------------------------------------------------------------------------------------

function Get-SIDataViewsReadySql {
    <#
        Marks the complete collections whose view data is written. -Views: the database has the views' columns -- a Detailed
        collection counts only once its aggregates exist (DerivedAt); without it every complete collection is marked (the
        views have nothing prepared to wait for). Answers the collections marked, or -1 on a database without the column
        (nothing is written; the web app then lists on 'Complete' as before). Run from text, so it compiles there too.
    #>
    param([switch]$Views)
    $ready = ''
    if ($Views) { $ready = " AND (Kind <> N''Detailed'' OR DerivedAt IS NOT NULL)" }
    # #717: a collection whose finding rows the retention removed stays out of the collection views' list
    if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $ready += (Get-SIDataLiveFilter) }
    @"
SET NOCOUNT ON;
IF COL_LENGTH('sidata.Collection', 'ViewsReadyAt') IS NULL BEGIN SELECT -1; RETURN; END
DECLARE @n INT;
EXEC sp_executesql N'
UPDATE sidata.Collection SET ViewsReadyAt = SYSUTCDATETIME() WHERE Status = N''Complete'' AND ViewsReadyAt IS NULL$ready;
SET @n = @@ROWCOUNT;', N'@n INT OUTPUT', @n = @n OUTPUT;
SELECT @n;
"@
}

function Set-SIDataViewsReady {
    <#
    .SYNOPSIS  Makes the collections whose view data is written visible to the collection views. Never throws.
    .NOTES     Called by the data sync after the views' aggregates, the prepared context, the departments and the counted
               aggregates -- a step of those that failed has said so itself and does not keep a collection hidden.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$Views, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        # (an answer that is not a number -- a database that answered nothing -- is "none marked", never an error)
        $n = 0; $a = & $Invoke (Get-SIDataViewsReadySql -Views:$Views) @{} 'scalar'; if ("$a" -match '^-?\d+$') { $n = [int]"$a" }
        if ($n -lt 0) { return [pscustomobject]@{ Status = 'no-schema'; Marked = 0 } }
        if ($n -gt 0) { & $Log 'OK' ("views       : {0} collection(s) are now shown by the collection views -- their view data is written" -f $n) }
        return [pscustomobject]@{ Status = 'ok'; Marked = $n }
    } catch {
        & $Log 'WARN' ("views       : the collections of this run could not be marked ready for the views ({0}) -- the collection views keep showing the previous collection until the next run." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}

function Set-SIDataViewVersion {
    <#
    .SYNOPSIS  Marks that the data sync stored data: a new value in sidata.ViewState 'data'. Never throws.
    .NOTES     Called once at the end of a data sync that writes. Without it (a database without the table, or a failure
               here) the web app still notices new data by its own counts -- nothing is shown stale because of this.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    try {
        $value = [guid]::NewGuid().ToString('N')
        $done = [int](& $Invoke (Get-SIDataViewVersionSql) @{ Value = $value } 'scalar')
        if ($done -ne 1) { & $Log 'INFO' 'views       : the database does not have the views'' data mark yet (setup\Initialize-SIDataSql.ps1 adds it; the updater runs it) -- the web app notices new data by its own counts.' }
        return [pscustomobject]@{ Status = $(if ($done -eq 1) { 'ok' } else { 'no-schema' }); Value = $value }
    } catch {
        & $Log 'WARN' ("views       : the views' data mark was not set this run ({0}) -- the web app notices new data by its own counts." -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
    }
}
