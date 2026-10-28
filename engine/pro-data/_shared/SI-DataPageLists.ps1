#Requires -Version 5.1
<#
    WHAT TWO PAGES OPEN WITH, PRE-COMPUTED BY THE DATA SYNC (REQUIREMENTS #839, measured on a small Azure SQL database after a
    restart, 2026-10-20: the time went to reading the data from disk, not to the processor).

    (1) THE COLUMN CHOOSER'S LISTS. Every data view with extra columns (Assets & services > Assets (CIs) first) listed the CI
        document fields, the identifier types, the source properties and the finding fields from samples of the data on its
        first open after every restart or release -- 9.9 s, 6.1 s and up to 60 s on a cold database, one after the other, and
        the page failed after 47 s. The data sync now writes each list (the SAME sample statements, DataColumnSql in the web
        app; a test holds the texts equal) into sidata.ColumnChoice with its state row (sidata.ColumnChoiceState: when, how
        many, and the mark of the data it was read from). A list is written again only when that mark moved. The web app
        reads the stored lists in one small read; a list that is not stored yet is left out of the chooser, which says so.
    (2) THE OPEN VULNERABILITIES BY SEVERITY AND ASSET TIER (Changes & trends > Vulnerabilities over time): the page joined
        every open close-loop item to a key -> tier map of every asset and identifier (and, leaving exempted findings out, to
        the exempted findings of the newest collection) on each open -- 39 s on a cold database, the page failed after 40 s.
        After the close-loop's statistics the data sync now writes the counts per source, severity and tier, every item and
        the counted variant, into sidata.VulnOpenCount with sidata.VulnOpenCountState -- exactly the page's statements
        (ProDataSql.OpenVulnerabilities / OpenVulnerabilitiesCounted), with the map and the exempted keys built ONCE into
        indexed temp tables. The page reads the stored counts.
    EXISTING INSTALLS: the schema adds the tables (the updater applies sql\si-data-schema.sql); the next data sync writes them.
    Until then the chooser offers the columns without the lists and says they appear after the next data sync, and the page
    counts the open items itself under a time limit (a plain line when that runs out, never an error page).
    Never fails the data sync.
#>

Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------------------------------
#  THE COLUMN CHOOSER'S LISTS
# ---------------------------------------------------------------------------------------------------------------------

# The published Detailed collection (PublishedRun.DetailedId in the web app) -- the finding sample's collection, read first.
$script:SIDataChoicePublishedId = "(SELECT TOP (1) pc.CollectionId FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed')"

# The sample statements, word for word as the web app carries them (DataColumnSql.CiFieldSample, IdentifierTypes,
# SourcePropertySample, FindingFieldSample -- a C# test holds them equal). Each answers one column, Name.
$script:SIDataChoiceLists = @(
    [pscustomobject]@{ List = 'ci'; Words = 'CI fields'; Sql = @'
SELECT DISTINCT p.[key] AS Name
FROM (SELECT TOP (300) c.DocJson FROM sidata.Ci AS c) AS s
CROSS APPLY OPENJSON(CASE WHEN ISJSON(s.DocJson) = 1 AND LEFT(LTRIM(s.DocJson), 1) = N'{' THEN s.DocJson END) AS p;
'@ }
    [pscustomobject]@{ List = 'id'; Words = 'identifier types'; Sql = @'
SELECT DISTINCT ai.IdentifierType AS Name FROM sidata.AssetIdentifier AS ai
UNION
SELECT DISTINCT ri.IdType AS Name FROM sidata.RecordIdentifier AS ri;
'@ }
    [pscustomobject]@{ List = 'source'; Words = 'source properties'; Sql = @'
WITH src AS (SELECT DISTINCT a.SourceSystem FROM sidata.AssetMetadata AS a)
SELECT DISTINCT (LOWER(x.SourceSystem) COLLATE Latin1_General_BIN2) + N'.' + p.[key] + CASE WHEN c.[key] IS NULL THEN N'' ELSE N'.' + c.[key] END AS Name
FROM src
CROSS APPLY (SELECT TOP (100) a.SourceSystem, a.PropertiesJson FROM sidata.AssetMetadata AS a
             WHERE a.SourceSystem = src.SourceSystem AND a.Dropped = 0 ORDER BY a.AssetMetadataId DESC) AS x
CROSS APPLY OPENJSON(CASE WHEN LEFT(LTRIM(x.PropertiesJson), 1) = N'{' THEN x.PropertiesJson END) AS p
OUTER APPLY (SELECT q.[key] FROM OPENJSON(CASE WHEN p.[type] = 5 THEN p.[value] END) AS q) AS c;
'@ }
    [pscustomobject]@{ List = 'finding'; Words = 'finding fields'; Sql = @'
SELECT DISTINCT p.[key] AS Name
FROM (SELECT TOP (300) f.DetailJson FROM sidata.Finding AS f WHERE f.CollectionId = @c ORDER BY f.FindingId) AS s
CROSS APPLY OPENJSON(CASE WHEN ISJSON(s.DetailJson) = 1 AND LEFT(LTRIM(s.DetailJson), 1) = N'{' THEN s.DetailJson END) AS p;
'@ }
)

function Get-SIDataColumnChoiceLists {
    <# PURE. The chooser's lists: List (the stored key), Words (said in the log), Sql (the sample statement). #>
    $script:SIDataChoiceLists
}

function Get-SIDataColumnChoiceSchemaCheckSql {
    <# 1 when the database carries the stored lists and every table the samples read; else 0. #>
    "SELECT CASE WHEN OBJECT_ID('sidata.ColumnChoice') IS NOT NULL AND OBJECT_ID('sidata.ColumnChoiceState') IS NOT NULL AND OBJECT_ID('sidata.Ci') IS NOT NULL AND OBJECT_ID('sidata.CiRecord') IS NOT NULL AND OBJECT_ID('sidata.AssetIdentifier') IS NOT NULL AND OBJECT_ID('sidata.RecordIdentifier') IS NOT NULL AND OBJECT_ID('sidata.vPublishedCollection') IS NOT NULL AND COL_LENGTH('sidata.AssetMetadata', 'Dropped') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DetailJson') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataColumnChoiceMarkSql {
    <#
        The mark of the data the lists are read from: the published collection, the newest CI build and how many CIs, the
        newest source object, the newest provider records and the newest identifier. Narrow reads (an index end, a count).
        A list whose stored mark equals it is not read again.
    #>
    @"
SELECT CONCAT(N'c=', $($script:SIDataChoicePublishedId),
              N'|b=', CONVERT(nvarchar(30), (SELECT MAX(c.CollectionTime) FROM sidata.Ci AS c), 126),
              N'|n=', (SELECT COUNT_BIG(*) FROM sidata.Ci AS c2),
              N'|m=', (SELECT MAX(m.AssetMetadataId) FROM sidata.AssetMetadata AS m),
              N'|r=', CONVERT(nvarchar(30), (SELECT MAX(r.CollectionTime) FROM sidata.CiRecord AS r), 126),
              N'|i=', (SELECT MAX(ai.AssetIdentifierId) FROM sidata.AssetIdentifier AS ai));
"@
}

function Get-SIDataColumnChoiceStateSql {
    <# What is stored: one row per written list (List, DataMark). #>
    'SELECT s.List, s.DataMark FROM sidata.ColumnChoiceState AS s;'
}

function Get-SIDataColumnChoiceSql {
    <#
        ONE list (@List): its sample statement (@Q, run as it is -- the finding sample with @c, the published collection) into
        a temp table, the distinct names that fit, then the list and its state row replaced in ONE transaction. Answers the
        number of names. A name longer than the stored column is left out of the chooser (a layout may still hold it).
    #>
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c INT = $($script:SIDataChoicePublishedId);
CREATE TABLE #raw (Name NVARCHAR(MAX) NULL);
IF @List <> N'finding' OR @c IS NOT NULL
    INSERT #raw (Name) EXEC sp_executesql @Q, N'@c int', @c = @c;
CREATE TABLE #n (Name NVARCHAR(400) COLLATE Latin1_General_BIN2 NOT NULL PRIMARY KEY);
INSERT #n (Name)
SELECT DISTINCT CONVERT(nvarchar(400), r.Name) COLLATE Latin1_General_BIN2
FROM #raw AS r
WHERE r.Name IS NOT NULL AND r.Name <> N'' AND LEN(r.Name) <= 400;
DECLARE @n INT = (SELECT COUNT(*) FROM #n);
BEGIN TRAN;
DELETE FROM sidata.ColumnChoice WHERE List = @List;
INSERT sidata.ColumnChoice (List, Name) SELECT @List, n.Name FROM #n AS n;
DELETE FROM sidata.ColumnChoiceState WHERE List = @List;
INSERT sidata.ColumnChoiceState (List, BuiltAt, Names, DataMark) VALUES (@List, SYSUTCDATETIME(), @n, @Mark);
COMMIT;
SELECT @n;
"@
}

function Invoke-SIDataColumnChoices {
    <#
    .SYNOPSIS  Writes the column chooser's lists that are missing or were read from older data. Never throws.
    .NOTES     Each list on its own: one that fails keeps what it stored before (or stays missing) and is tried again on the
               next run; the others are written. Paced by the database's own load (SI-SqlPacing.ps1) when loaded.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $label = 'columns     '
    try {
        if (([int](& $Invoke (Get-SIDataColumnChoiceSchemaCheckSql) @{} 'scalar')) -ne 1) {
            & $Log 'WARN' ("{0}: the database does not have the column lists' tables yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the column chooser lists its extra columns after the next data sync that writes them." -f $label)
            return [pscustomobject]@{ Status = 'no-schema'; Lists = 0 }
        }
        $mark = [string](& $Invoke (Get-SIDataColumnChoiceMarkSql) @{} 'scalar')
        $have = @{}
        foreach ($r in @(@(& $Invoke (Get-SIDataColumnChoiceStateSql) @{} 'reader') | ForEach-Object { $_ })) {
            if ($null -eq $r) { continue }
            $m = $r['DataMark']; if ($m -is [System.DBNull]) { $m = $null }
            $have[[string]$r['List']] = [string]$m
        }
        $due = @(Get-SIDataColumnChoiceLists | Where-Object { -not $have.ContainsKey($_.List) -or -not $mark -or $have[$_.List] -ne $mark })
        if ($DryRun) {
            & $Log 'INFO' ("{0}: {1} of the column chooser's lists would be written; nothing is written." -f $label, $due.Count)
            return [pscustomobject]@{ Status = 'dry-run'; Lists = 0; Pending = $due.Count }
        }
        if ($due.Count -eq 0) { return [pscustomobject]@{ Status = 'ok'; Lists = 0; Pending = 0 } }
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        $wrote = New-Object System.Collections.Generic.List[string]
        $failed = 0; $done = 0
        foreach ($l in $due) {
            try {
                if ($paced) { $null = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log }
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $n = & $Invoke (Get-SIDataColumnChoiceSql) @{ List = $l.List; Q = $l.Sql; Mark = $(if ($mark) { $mark } else { $null }) } 'scalar'
                $sw.Stop(); $lastMs = $sw.ElapsedMilliseconds
                $wrote.Add(('{0} {1}' -f $l.Words, $(if ("$n" -match '^\d+$') { "$n" } else { '?' })))
                $done++
            } catch {
                $failed++
                & $Log 'WARN' ("{0}: the list of {1} was not written this run -- {2}. It is tried again on the next run; the column chooser keeps what it listed before." -f $label, $l.Words, $_.Exception.Message)
            }
        }
        if ($done -gt 0) { & $Log 'OK' ("{0}: the column chooser's lists were written ({1}) -- the data views list their extra columns from them" -f $label, ($wrote -join ', ')) }
        [pscustomobject]@{ Status = $(if ($failed -gt 0) { 'partial' } else { 'ok' }); Lists = $done; Failed = $failed; Pending = 0 }
    } catch {
        & $Log 'WARN' ("{0}: the column chooser's lists were not written this run -- {1}. They are tried again on the next run." -f $label, $_.Exception.Message)
        [pscustomobject]@{ Status = 'failed'; Lists = 0; Error = $_.Exception.Message }
    }
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE OPEN VULNERABILITIES BY SEVERITY AND ASSET TIER
# ---------------------------------------------------------------------------------------------------------------------

# The pages' tier words over the map's tier (ProDataSql.TierExpr("t.Tier") -- a C# test holds them equal).
$script:SIDataOpenTierWords = "CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), t.Tier), N'Tier', N'')) BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), t.Tier), N'Tier', N''))) ELSE N'Unclassified' END"

function Get-SIDataVulnOpenCountSql {
    <#
        Every open close-loop item per source, severity and asset tier -- every item, and leaving out the items whose finding
        the newest complete Detailed collection marks exempted -- with the state row, ONE transaction. Exactly
        ProDataSql.OpenVulnerabilities / OpenVulnerabilitiesCounted per source: the key -> tier map (the asset key wins over
        an identifier) and the exempted keys (the CI key and every identifier of an exempted finding's CI, with its CVE) are
        built ONCE into indexed temp tables and joined. Answers the open items (every source); -1 when the close-loop or the
        stored tables are not installed.
    #>
    $live = ''; if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { $live = Get-SIDataLiveFilter -Alias 'c' }
    (@'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID('vuln.VulnerabilityItem') IS NULL OR OBJECT_ID('sidata.VulnOpenCount') IS NULL OR OBJECT_ID('sidata.VulnOpenCountState') IS NULL
   OR OBJECT_ID('sidata.vExemptedFinding') IS NULL BEGIN SELECT CAST(-1 AS BIGINT); RETURN; END;
DECLARE @c INT = (SELECT TOP (1) c.CollectionId FROM sidata.Collection AS c WHERE c.Status = 'Complete' AND c.Kind = 'Detailed'{LIVE} ORDER BY c.CollectionTime DESC);
-- the key -> tier map, ONCE: the asset key wins over an identifier
CREATE TABLE #t (K NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Tier TINYINT NULL);
WITH keyed AS (
    SELECT a.AssetKey AS K, a.Tier, 0 AS Pri FROM sidata.Asset AS a
    UNION ALL
    SELECT ai.IdentifierValue, a.Tier, 1 FROM sidata.AssetIdentifier AS ai JOIN sidata.Asset AS a ON a.AssetKey = ai.AssetKey
), t AS (
    SELECT K, Tier, ROW_NUMBER() OVER (PARTITION BY K ORDER BY Pri) AS rn FROM keyed
)
INSERT #t (K, Tier) SELECT t.K, t.Tier FROM t WHERE t.rn = 1;
-- the exempted keys of the newest collection, ONCE: the CI key and every identifier of an exempted finding's CI, with its CVE
CREATE TABLE #x (K NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL, Cve NVARCHAR(100) COLLATE DATABASE_DEFAULT NOT NULL, PRIMARY KEY (K, Cve));
INSERT #x (K, Cve)
SELECT DISTINCT k.K, xa.Cve
FROM (SELECT DISTINCT v.AssetKey, v.Cve FROM sidata.vExemptedFinding AS v WHERE v.CollectionId = @c AND v.Cve IS NOT NULL) AS xa
JOIN (SELECT a.AssetKey, a.AssetKey AS K FROM sidata.Asset AS a UNION SELECT ai.AssetKey, ai.IdentifierValue FROM sidata.AssetIdentifier AS ai) AS k ON k.AssetKey = xa.AssetKey;
CREATE TABLE #r (Source NVARCHAR(60) COLLATE DATABASE_DEFAULT NOT NULL, Counted BIT NOT NULL, Severity NVARCHAR(30) COLLATE DATABASE_DEFAULT NOT NULL, Tier NVARCHAR(12) NOT NULL, Items BIGINT NOT NULL);
INSERT #r (Source, Counted, Severity, Tier, Items)
SELECT i.Source, 0, COALESCE(i.Severity, N'(none)'), {TIER}, COUNT_BIG(*)
FROM vuln.VulnerabilityItem AS i
LEFT JOIN #t AS t ON t.K = i.CorrelationId
WHERE i.State = N'Open'
GROUP BY i.Source, COALESCE(i.Severity, N'(none)'), {TIER};
INSERT #r (Source, Counted, Severity, Tier, Items)
SELECT i.Source, 1, COALESCE(i.Severity, N'(none)'), {TIER}, COUNT_BIG(*)
FROM vuln.VulnerabilityItem AS i
LEFT JOIN #t AS t ON t.K = i.CorrelationId
LEFT JOIN #x AS x ON x.K = i.CorrelationId AND x.Cve = i.Cve
WHERE i.State = N'Open' AND x.K IS NULL
GROUP BY i.Source, COALESCE(i.Severity, N'(none)'), {TIER};
DECLARE @open BIGINT = (SELECT COALESCE(SUM(r.Items), 0) FROM #r AS r WHERE r.Counted = 0);
BEGIN TRAN;
DELETE FROM sidata.VulnOpenCount;
INSERT sidata.VulnOpenCount (Source, Counted, Severity, Tier, Items) SELECT r.Source, r.Counted, r.Severity, r.Tier, r.Items FROM #r AS r;
DELETE FROM sidata.VulnOpenCountState;
INSERT sidata.VulnOpenCountState (Name, BuiltAt, CollectionId, OpenItems) VALUES (N'current', SYSUTCDATETIME(), @c, @open);
COMMIT;
SELECT @open;
'@).Replace('{LIVE}', $live).Replace('{TIER}', $script:SIDataOpenTierWords)
}

function Invoke-SIDataVulnOpenCounts {
    <# .SYNOPSIS Writes the open vulnerabilities per source, severity and asset tier (both variants). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $label = 'open now    '
    try {
        $n = & $Invoke (Get-SIDataVulnOpenCountSql) @{} 'scalar'
        $open = if ("$n" -match '^-?\d+$') { [long]"$n" } else { [long]-1 }
        if ($open -lt 0) {
            & $Log 'INFO' ("{0}: the vulnerability close-loop or the stored counts are not installed in this database -- Vulnerabilities over time counts the open items itself." -f $label)
            return [pscustomobject]@{ Status = 'no-schema'; OpenItems = 0 }
        }
        & $Log 'OK' ("{0}: {1} open vulnerability item(s) counted by severity and asset tier -- Vulnerabilities over time reads them" -f $label, $open)
        [pscustomobject]@{ Status = 'ok'; OpenItems = $open }
    } catch {
        & $Log 'WARN' ("{0}: the open vulnerabilities were not counted this run -- {1}. They are counted again on the next run; until then Vulnerabilities over time shows the counts of the run before." -f $label, $_.Exception.Message)
        [pscustomobject]@{ Status = 'failed'; OpenItems = 0; Error = $_.Exception.Message }
    }
}
