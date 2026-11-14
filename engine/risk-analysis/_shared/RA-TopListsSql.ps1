#Requires -Version 5.1
<#
    THE TOP 50 LISTS AND THE KEY FIGURES, WORKED OUT IN THE DATABASE (#1212, owner 2026-11-12 "Start #1212 now").

    WHY. After the last report the coordinator of a Detailed run read EVERY stored row of the result back into PowerShell (the
    AI summary's pass, "the AI summary and key figures read the rows"): ~4 KB of DetailJson per row decoded, then ~15 look-ups
    per row for the Top 50 risky assets, the Top 50 critical findings and the key figures. Live 2026-11-12 on a large ring-2
    install: ~5,400 rows a minute, ~4 h for 1.35 M rows (another install: 3.5 h for 1.6 M). Every number it makes is a sum, a
    count or a "first seen" -- what a database does set-based.

    WHAT IS READ AND BY WHOM (searched 2026-11-12; nothing else reads these):
      * Top 50 risky assets / Top 50 critical findings -> $script:_RAExecTop* -> the executive view (RA-ExecView.ps1 ->
        sidata.RiskExecView -> the web app: Executive Risk Analysis, Top assets / Top risks pages, the deck); the shared AI
        snapshot (AI on only); the AI prompt (AI on only). The view reads per asset: name, key, tier, the two sums, findings,
        domains, the first 12 items, cmdb name + criticality; per finding: id, name, category, subcategory, severity, domain,
        affected assets, the two sums, its 5 hottest assets.
      * the key figures (severity x domain, the per-domain secure score, the patch cycle) -> $global:RA_KPI -> the report mail
        and the executive view.
      * READ ONLY BY THE AI PROMPT: the reference links per asset / finding, the cmdb id and data sensitivity, and how many
        assets a finding has in all ("[+N more of M total]"). With the AI summary off these are NOT worked out at all.

    HOW. On ONE connection (the seam's mode 'session', as the data sync's key figures): the run's View rows are read a
    FindingId range at a time (the clustered key) into a narrow work table (#ra) -- only the values the lists and figures
    read, out of DetailJson by OPENJSON, never the JSON itself -- each range paced by the database's own load (SI-SqlPacing)
    with the progress tick (#1180). Then GROUP BY / ORDER BY / TOP work out the lists and the figures; only the results come
    back. Where PowerShell decides a value's meaning (a number's text, a tier's text, a severity, the patch cycle), the
    DISTINCT values go to the very same PowerShell function and its answer comes back as a small table -- one copy of every
    rule, never a second one written in SQL.

    THE SAME RESULT (the fixture test SIv3-RaTop50SetBased: the row-by-row pass and this one on the same stored rows):
      * the same assets / findings in the same order, ties included: ties (equal on every sort key) are ordered by where
        each first appears in the result (score, then write order) -- the row-by-row pass now does the same (before, a
        hashtable's order decided, random per process in PowerShell 7);
      * the same sums, counts, first-seen values, items, domains, hottest assets, links and key figures. Sums of scores are
        exact for whole numbers and binary fractions (every shipped score); scores with other decimals may differ in the last
        binary digit (the order of adding), never in a shown or rounded figure in practice;
      * ONLY where the stored rows are of the shape this form mirrors -- otherwise the row-by-row pass runs as before
        ("declined", one plain line): a row with an asset LIST (ImpactedAssetsList & co, ImpactedAssetIds), a value that is
        a list / object where the lists read a single value, a report whose column differs only in case from a read column,
        a Protection Score counted in the run (not the stored one), a row count different from the run's, or any error.
    No module, PS 5.1 and 7. NO EMOJI IN THIS FILE.
#>

# ------------------------------------------------------------------------------------------------------------------
#  WHAT THE LISTS AND THE FIGURES READ -- the engine's own look-up chains (Get-RowValue: the first that is not blank)
# ------------------------------------------------------------------------------------------------------------------

# the AI rollup's chains (Invoke-RiskAnalysis.ps1, its row loop). A lower-case twin in the engine's list (securityseverity, ...)
# is the same column to PowerShell (case-insensitive) -- a report whose column has another case is declined (Test-RATopListsColumns).
$script:RATopChains = [ordered]@{
    WT     = @('RiskScoreTotal_Weighted')
    UT     = @('RiskScoreTotal', 'RiskScore')
    Sev    = @('SecuritySeverity', 'Severity')
    Tier   = @('CriticalityTierLevel', 'CriticalityTier', 'Tier')
    Dom    = @('SecurityDomain', 'Domain')
    Cat    = @('Category')
    Sub    = @('Subcategory', 'SubCategory')
    CName  = @('ConfigurationName', 'RecommendationName', 'FindingName', 'Title', 'Name')
    CId    = @('ConfigurationId', 'RecommendationId', 'FindingId', 'Id')
    CmName = @('cmdbName', 'CmdbName')
    CmCrit = @('cmdbCriticality', 'CmdbCriticality')
    ANr    = @('AssetName', 'DeviceName', 'Device', 'MachineName', 'Computer', 'HostName', 'DnsName', 'FQDN', 'Endpoint', 'Asset')
    AId    = @('AssetId')
}
# read only by the AI prompt -- with the AI summary off these are not read at all
$script:RATopAiChains = [ordered]@{
    CmId = @('cmdbId', 'CmdbId')
    CmSens = @('cmdbDataSensitivity', 'CmdbDataSensitivity')
    MD = @('MoreDetails')
}
# an asset LIST on a row (Resolve-AssetNamesForRow's list path, Get-RARowAssetKeys' id list): not mirrored -> declined
$script:RATopListCols = @('ImpactedAssetsList', 'ImpactedAssets', 'Assets', 'AffectedAssets', 'Machines', 'ImpactedAssetIds')
# the key figures (Add-RAKpiRowFigures reads each by its own name, the raw value)
$script:RATopKpiCols = [ordered]@{ KSev = 'SecuritySeverity'; KDom = 'SecurityDomain'; KRep = 'Report'; KKpi = 'RiskScoreKPI'; KTier = 'CriticalityTier'; KIac = 'ImpactedAssetCount' }
# the patch cycle (Add-SIPatchCycleRow: the first value that is not blank, trimmed)
$script:RATopPatchChains = [ordered]@{
    PCveT  = @('si_cve', 'Cve', 'CveId')
    PCfgT  = @('ConfigurationId')
    PUid   = @('si_fix_recommended_update_id', 'RecommendedSecurityUpdateId')
    PUpd   = @('si_fix_recommended_update', 'RecommendedSecurityUpdate')
    PGiven = @('si_patch_cycle')
    PDev   = @('si_ci_id', 'SI_AssetId', 'AssetId', 'AssetName')
}

function Get-RATopReadNames {
    <# PURE. Every column name the set-based form reads (exact case, each once, in a stable order). -WithAi adds the AI-only ones. #>
    param([bool]$WithAi)
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $out = New-Object 'System.Collections.Generic.List[string]'
    $add = { param($n) if ($seen.Add([string]$n)) { $out.Add([string]$n) } }
    foreach ($k in $script:RATopChains.Keys) { foreach ($n in $script:RATopChains[$k]) { & $add $n } }
    if ($WithAi) { foreach ($k in $script:RATopAiChains.Keys) { foreach ($n in $script:RATopAiChains[$k]) { & $add $n } } }
    foreach ($n in $script:RATopListCols) { & $add $n }
    foreach ($k in $script:RATopKpiCols.Keys) { & $add $script:RATopKpiCols[$k] }
    foreach ($k in $script:RATopPatchChains.Keys) { foreach ($n in $script:RATopPatchChains[$k]) { & $add $n } }
    , $out.ToArray()
}

function Test-RATopListsColumns {
    <#
        PURE. '' when every report's columns can be read by their exact names; otherwise why not. PowerShell finds a column
        whatever its case; OPENJSON only by its exact name -- a report whose column is a read column in ANOTHER case (e.g.
        'securityseverity') is declined, never read as absent. -Reports: the stream's report entries (their Columns).
    #>
    param($Reports, [bool]$WithAi)
    $names = Get-RATopReadNames -WithAi $WithAi
    $exact = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $loose = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $names) { [void]$exact.Add($n); [void]$loose.Add($n) }
    if ($null -eq $Reports) { return '' }
    foreach ($k in @($Reports.Keys)) {
        $r = $Reports[$k]
        foreach ($c in @($r.Columns)) {
            $c = [string]$c
            if ($loose.Contains($c) -and -not $exact.Contains($c)) { return ("the report '{0}' names its column '{1}' in another case" -f [string]$k, $c) }
        }
    }
    ''
}

# ------------------------------------------------------------------------------------------------------------------
#  THE STATEMENTS (PURE text; every value in them is a whole number the caller made -- a session batch has no parameters)
# ------------------------------------------------------------------------------------------------------------------

function Get-RATopWsDeclare {
    <# PURE. @ws: every character .NET's Trim() / IsNullOrWhiteSpace treat as white space (Char.IsWhiteSpace). #>
    $codes = @(9, 10, 11, 12, 13, 32, 133, 160, 5760, 8192, 8193, 8194, 8195, 8196, 8197, 8198, 8199, 8200, 8201, 8202, 8232, 8233, 8239, 8287, 12288)
    'DECLARE @ws nvarchar(64) = ' + ((@($codes | ForEach-Object { 'NCHAR({0})' -f $_ })) -join ' + ') + ';'
}

function Get-RATopKeyExpr {
    <# PURE. ONE binary key over several texts, NULL and '' and trailing spaces told apart (each text with its length). #>
    param([Parameter(Mandatory)][string[]]$Cols)
    $parts = foreach ($c in $Cols) { "ISNULL(CONVERT(nvarchar(20), LEN($c + N'.') - 1) + N':' + $c, N'-')" }
    "HASHBYTES('SHA2_256', CONCAT(" + ($parts -join ", N'|', ") + '))'
}

function Get-RATopSetupSql {
    <# PURE. The narrow work table: the values the lists and figures read, one row per View row of the run. #>
    @'
IF OBJECT_ID('tempdb..#ra') IS NOT NULL DROP TABLE #ra;
CREATE TABLE #ra (
    FindingId bigint NOT NULL PRIMARY KEY, RaSort float NULL, RaSeq bigint NOT NULL,
    WT nvarchar(max) NULL, UT nvarchar(max) NULL, W float NULL, U float NULL,
    Sev nvarchar(max) NULL, Tier nvarchar(max) NULL, Dom nvarchar(max) NULL, Cat nvarchar(max) NULL, Sub nvarchar(max) NULL,
    CName nvarchar(max) NULL, CId nvarchar(max) NULL, CmName nvarchar(max) NULL, CmCrit nvarchar(max) NULL,
    CmId nvarchar(max) NULL, CmSens nvarchar(max) NULL, MD nvarchar(max) NULL,
    AName nvarchar(max) NULL, AKey nvarchar(max) NULL, AKeyH binary(32) NULL, ANH binary(32) NULL, ANUH binary(32) NULL,
    CKeyH binary(32) NULL, BucketH binary(32) NULL, Kept bit NOT NULL DEFAULT (0),
    KSev nvarchar(max) NULL, KDom nvarchar(max) NULL, KRep nvarchar(max) NULL, KKpi nvarchar(max) NULL, KTier nvarchar(max) NULL,
    KIac nvarchar(max) NULL, KIacStr bit NOT NULL DEFAULT (0), KH binary(32) NULL,
    PCve bit NOT NULL DEFAULT (0), PGiven nvarchar(max) NULL, PUid nvarchar(max) NULL, PUpd nvarchar(max) NULL, PDev nvarchar(max) NULL,
    PTripleH binary(32) NULL, PUidUH binary(32) NULL, PDevUH binary(32) NULL,
    Odd bit NOT NULL DEFAULT (0)
);
'@
}

function Get-RATopRangeSql {
    <#
        PURE. ONE FindingId range (Lo, Hi] of the run's View rows into #ra: each value out of DetailJson by OPENJSON (one parse
        per row), blank = NULL ("" + value).Trim() -eq '' as Get-RowValue), the chains as COALESCE in the engine's order, the
        keys as binary hashes (exact text; the case-insensitive ones over UPPER). Answers N (rows) and Odd (rows not of the
        mirrored shape). -Collapse: the *_Detailed (asset x ConfigBucket) collapse key. -WithAi: the AI-only values too.
    #>
    param([Parameter(Mandatory)][int]$CollectionId, [long]$Lo, [long]$Hi, [int[]]$Held = @(), [bool]$WithAi)
    $names = Get-RATopReadNames -WithAi $WithAi
    # ORDINAL: 'Subcategory' and 'SubCategory' are two JSON keys (a PowerShell @{} would make them one)
    $idx = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([StringComparer]::Ordinal)
    for ($i = 0; $i -lt $names.Count; $i++) { $idx[$names[$i]] = $i }
    $with = New-Object 'System.Collections.Generic.List[string]'
    $blank = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 0; $i -lt $names.Count; $i++) {
        $path = '$."' + $names[$i] + '"'
        $with.Add(("s{0} nvarchar(max) '{1}'" -f $i, $path))
        $with.Add(("q{0} nvarchar(max) '{1}' AS JSON" -f $i, $path))
        $blank.Add(("CASE WHEN TRIM(@ws FROM j.s{0}) = N'' THEN NULL ELSE j.s{0} END AS n{0}" -f $i))
    }
    $chain = { param([string[]]$Ns) $e = @($Ns | ForEach-Object { 'b.n{0}' -f $idx[$_] }); if ($e.Count -eq 1) { $e[0] } else { 'COALESCE(' + ($e -join ', ') + ')' } }
    $c = New-Object 'System.Collections.Generic.List[string]'
    foreach ($k in $script:RATopChains.Keys) { $c.Add(('{0} AS {1}' -f (& $chain $script:RATopChains[$k]), $k)) }
    foreach ($k in $script:RATopAiChains.Keys) { if ($WithAi) { $c.Add(('{0} AS {1}' -f (& $chain $script:RATopAiChains[$k]), $k)) } else { $c.Add(('CONVERT(nvarchar(max), NULL) AS {0}' -f $k)) } }
    foreach ($k in $script:RATopPatchChains.Keys) { $c.Add(('TRIM(@ws FROM {0}) AS {1}' -f (& $chain $script:RATopPatchChains[$k]), $k)) }
    $listAny = 'COALESCE(' + ((@($script:RATopListCols | ForEach-Object { 'b.n{0}, j.q{0}' -f $idx[$_] })) -join ', ') + ')'
    $anyJson = 'COALESCE(' + ((@(0..($names.Count - 1) | ForEach-Object { 'j.q{0}' -f $_ })) -join ', ') + ')'
    $k = $script:RATopKpiCols
    $iacS = 'j.s{0}' -f $idx[$k.KIac]
    # (its own name: $held IS the [int[]] -Held parameter -- PowerShell names are case-insensitive)
    $heldWhere = [string](Get-RAStreamHeldFilter -Held $Held) -replace 'RaReport', 'f.RaReport'
    $bucket = @"
CASE WHEN c.CId IS NULL THEN N''
     WHEN LEN(c.CId + N'.') - 1 >= 10 AND SUBSTRING(c.CId, 1, 4) COLLATE Latin1_General_CI_AS = N'CVE-'
          AND SUBSTRING(c.CId, 5, 4) COLLATE Latin1_General_BIN2 LIKE N'[0-9][0-9][0-9][0-9]' AND SUBSTRING(c.CId, 9, 1) = N'-'
          AND SUBSTRING(c.CId, 10, 4000) COLLATE Latin1_General_BIN2 NOT LIKE N'%[^0-9]%' THEN N'CVE'
     ELSE c.CId END
"@
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
$(Get-RATopWsDeclare)
INSERT #ra (FindingId, RaSort, RaSeq, WT, UT, Sev, Tier, Dom, Cat, Sub, CName, CId, CmName, CmCrit, CmId, CmSens, MD,
            AName, AKey, AKeyH, ANH, ANUH, CKeyH, BucketH, KSev, KDom, KRep, KKpi, KTier, KIac, KIacStr,
            PCve, PGiven, PUid, PUpd, PDev, Odd)
SELECT f.FindingId, f.RaSort, f.RaSeq, c.WT, c.UT, c.Sev, c.Tier, c.Dom, c.Cat, c.Sub, c.CName, c.CId, c.CmName, c.CmCrit, c.CmId, c.CmSens, c.MD,
       d.AName, d.AKey, HASHBYTES('SHA2_256', d.AKey), HASHBYTES('SHA2_256', d.AName), HASHBYTES('SHA2_256', UPPER(d.AName)),
       HASHBYTES('SHA2_256', UPPER(c.CId)), HASHBYTES('SHA2_256', $bucket),
       j.s$($idx[$k.KSev]), j.s$($idx[$k.KDom]), j.s$($idx[$k.KRep]), j.s$($idx[$k.KKpi]), j.s$($idx[$k.KTier]), $iacS,
       CASE WHEN $iacS IS NOT NULL AND CHARINDEX(N'"ImpactedAssetCount":"', f.DetailJson) > 0 THEN 1 ELSE 0 END,
       CASE WHEN ISNULL(c.PCveT, N'') <> N'' OR ISNULL(c.PCfgT, N'') COLLATE Latin1_General_CI_AS LIKE N'CVE-%' THEN 1 ELSE 0 END,
       ISNULL(c.PGiven, N''), ISNULL(c.PUid, N''), ISNULL(c.PUpd, N''), ISNULL(c.PDev, N''),
       CASE WHEN $listAny IS NOT NULL OR $anyJson IS NOT NULL OR f.DetailJson IS NULL THEN 1 ELSE 0 END
FROM sidata.Finding f
OUTER APPLY OPENJSON(f.DetailJson) WITH (
    $($with -join ",`n    ")
) j
CROSS APPLY (SELECT
    $($blank -join ",`n    ")
) b
CROSS APPLY (SELECT
    $($c -join ",`n    ")
) c
CROSS APPLY (SELECT TRIM(@ws FROM c.ANr) AS AName,
    CASE WHEN c.ANr IS NULL THEN NULL WHEN c.AId IS NOT NULL THEN N'id:' + LOWER(TRIM(@ws FROM c.AId)) ELSE N'name:' + LOWER(TRIM(@ws FROM c.ANr)) END AS AKey) d
WHERE f.CollectionId = $([int]$CollectionId) AND f.FindingId > $([long]$Lo) AND f.FindingId <= $([long]$Hi) AND f.RaSeq IS NOT NULL AND f.RaInView = 1$heldWhere;
DECLARE @n bigint = @@ROWCOUNT;
SELECT @n AS N, (SELECT COUNT_BIG(*) FROM #ra WHERE FindingId > $([long]$Lo) AND FindingId <= $([long]$Hi) AND Odd = 1) AS Odd;
"@
}

function Get-RATopPrepareSql {
    <#
        PURE. After the last range: the key-figure and patch keys, the (asset x ConfigBucket) collapse of a *_Detailed report
        (the first row of a pair in the final order -- score highest first, then the write order -- the representative the
        row loop keeps), and the indexes the lists read through.
    #>
    param([bool]$Collapse)
    $kh = Get-RATopKeyExpr -Cols @('KSev', 'KDom', 'KRep', 'KKpi', 'KTier', 'KIac', 'CONVERT(nvarchar(1), KIacStr)')
    $ph = Get-RATopKeyExpr -Cols @('PGiven', 'PUid', 'PUpd')
    $kept = if ($Collapse) {
        @'
;WITH k AS (SELECT Kept, ROW_NUMBER() OVER (PARTITION BY AKeyH, BucketH ORDER BY RaSort DESC, RaSeq) AS Rn FROM #ra WHERE AKeyH IS NOT NULL)
UPDATE k SET Kept = CASE WHEN Rn = 1 THEN 1 ELSE 0 END;
'@
    } else { 'UPDATE #ra SET Kept = 1 WHERE AKeyH IS NOT NULL;' }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
UPDATE #ra SET KH = $kh,
    PTripleH = CASE WHEN PCve = 1 THEN $ph END,
    PUidUH = CASE WHEN PCve = 1 AND PUid <> N'' THEN HASHBYTES('SHA2_256', UPPER(PUid)) END,
    PDevUH = CASE WHEN PCve = 1 AND PDev <> N'' THEN HASHBYTES('SHA2_256', UPPER(PDev)) END;
$kept
CREATE INDEX IX_ra_Asset ON #ra (AKeyH, RaSort DESC, RaSeq) INCLUDE (W, U, Dom) WHERE Kept = 1;
CREATE INDEX IX_ra_Conf ON #ra (CKeyH, RaSort DESC, RaSeq) INCLUDE (W, U, ANH, ANUH) WHERE Kept = 1;
SELECT COUNT_BIG(*) AS AllRows, SUM(CONVERT(bigint, Kept)) AS Kept, SUM(CASE WHEN AKeyH IS NULL THEN 1 ELSE 0 END) AS NoAsset FROM #ra;
"@
}

function Get-RATopNumberTextsSql {
    <# PURE. The distinct score texts (weighted and total) -- each is turned into its number by ConvertTo-RADouble. #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
SELECT CONVERT(varchar(64), x.H, 2) AS H, MIN(x.T) AS T FROM (
    SELECT HASHBYTES('SHA2_256', WT) AS H, WT AS T FROM #ra WHERE WT IS NOT NULL
    UNION ALL SELECT HASHBYTES('SHA2_256', UT), UT FROM #ra WHERE UT IS NOT NULL) x
GROUP BY x.H;
'@
}

function ConvertTo-RATopExactDouble {
    <# PURE. A finite double as @{ M (whole, |M| < 2^53); E } with Value = M x 2^E exactly (trailing zero bits taken out of M).
       Throws on NaN / infinity (the pass then declines: the row loop keeps them). #>
    param([double]$Value)
    if ([double]::IsNaN($Value) -or [double]::IsInfinity($Value)) { throw 'a score that is not a finite number' }
    $bits = [System.BitConverter]::DoubleToInt64Bits($Value)
    $neg = $bits -lt 0
    $exp = [int](($bits -shr 52) -band 0x7FF)
    $frac = [long]($bits -band 0xFFFFFFFFFFFFF)
    if ($exp -eq 0) { $m = $frac; $e = -1074 } else { $m = $frac -bor 0x10000000000000; $e = $exp - 1075 }
    if ($m -eq 0) { return @{ M = [long]0; E = 0 } }
    while (($m -band 1) -eq 0) { $m = $m -shr 1; $e++ }
    if ($neg) { $m = -$m }
    @{ M = [long]$m; E = [int]$e }
}

function Get-RATopMapInsertSql {
    <#
        PURE. A mapping PowerShell made (-Pairs: @(@{ H = '<hex>'; V = <value> }) ...) as a work table: #<Table>(H binary(32),
        V <SqlType>), sent as ONE JSON text. -Bits: V is a [double] carried as its 64 bits (exact, no decimal text between).
    #>
    param([Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$SqlType, [AllowEmptyCollection()][object[]]$Pairs, [switch]$Bits)
    if ($Table -notmatch '^[A-Za-z]+$') { throw 'a work table name is letters only' }
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($Pairs)) {
        if ($null -eq $p) { continue }
        $h = ([string]$p.H) -replace '[^0-9A-Fa-f]', ''
        if ($Bits) { $me = ConvertTo-RATopExactDouble -Value ([double]$p.V); $items.Add(('{{"h":"{0}","m":{1},"e":{2}}}' -f $h, $me.M.ToString([System.Globalization.CultureInfo]::InvariantCulture), $me.E.ToString([System.Globalization.CultureInfo]::InvariantCulture))); continue }
        elseif ($p.V -is [string]) { $v = [Newtonsoft.Json.JsonConvert]::ToString([string]$p.V) }
        else { $v = ([long]$p.V).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        $items.Add(('{{"h":"{0}","v":{1}}}' -f $h, $v))
    }
    $json = ('[' + ($items -join ',') + ']').Replace("'", "''")
    # -Bits: the double as m x 2^e (whole m, |m| < 2^53) -- CONVERT(float, bigint) and a power of two are exact, so the product is
    # exactly the double PowerShell made (SQL Server converts no binary to float, and a decimal text is a second rounding)
    $sel = if ($Bits) { 'CONVERT(float, m.m) * POWER(CONVERT(float, 2), m.e)' } else { 'm.v' }
    $cols = if ($Bits) { "h varchar(64) '$.h', m bigint '$.m', e int '$.e'" } else { "h varchar(64) '$.h', v $SqlType '$.v'" }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
IF OBJECT_ID('tempdb..#$Table') IS NOT NULL DROP TABLE #$Table;
CREATE TABLE #$Table (H binary(32) NOT NULL PRIMARY KEY, V $SqlType NULL);
INSERT #$Table (H, V) SELECT CONVERT(binary(32), m.h, 2), $sel FROM OPENJSON(N'$json') WITH ($cols) m;
"@
}

function Get-RATopApplyNumbersSql {
    <# PURE. Each row's two scores from the mapping; no text = ConvertTo-RADouble's default (0). #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
UPDATE r SET W = ISNULL(w.V, 0.0), U = ISNULL(u.V, 0.0)
FROM #ra r
LEFT JOIN #num w ON w.H = HASHBYTES('SHA2_256', r.WT)
LEFT JOIN #num u ON u.H = HASHBYTES('SHA2_256', r.UT);
'@
}

function Get-RATopAssetAggSql {
    <# PURE. Every asset: its kept rows' count and sums, its first row (the tier text, the name, the key) -- and the distinct tier texts. #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
IF OBJECT_ID('tempdb..#aa') IS NOT NULL DROP TABLE #aa;
SELECT a.AKeyH, a.Findings, a.SumU, a.SumW, f.RaSort AS FSort, f.RaSeq AS FSeq, f.AName, f.AKey, f.Tier,
       HASHBYTES('SHA2_256', ISNULL(f.Tier, N'')) AS TierH, CONVERT(int, NULL) AS TierKey
INTO #aa
FROM (SELECT AKeyH, COUNT_BIG(*) AS Findings, SUM(U) AS SumU, SUM(W) AS SumW FROM #ra WHERE Kept = 1 GROUP BY AKeyH) a
JOIN (SELECT AKeyH, RaSort, RaSeq, AName, AKey, Tier, ROW_NUMBER() OVER (PARTITION BY AKeyH ORDER BY RaSort DESC, RaSeq) AS Rn FROM #ra WHERE Kept = 1) f
  ON f.AKeyH = a.AKeyH AND f.Rn = 1;
SELECT CONVERT(varchar(64), TierH, 2) AS H, MIN(ISNULL(Tier, N'')) AS T FROM #aa GROUP BY TierH;
'@
}

function Get-RATopAssetsSql {
    <#
        PURE. The Top -N assets, ranked as the row loop ranks them: tier (its text's number, else 99) ascending, weighted sum,
        total sum, findings descending -- then where each first appears (score highest first, then the write order). With
        their first-seen cmdb values (-WithAi: the id and the data sensitivity too) and the number of assets in all.
    #>
    param([int]$N = 50, [bool]$WithAi)
    $ai = if ($WithAi) {
        @'
, (SELECT TOP (1) r.CmId FROM #ra r WHERE r.AKeyH = t.AKeyH AND r.Kept = 1 AND r.CmId IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS CmId
, (SELECT TOP (1) r.CmSens FROM #ra r WHERE r.AKeyH = t.AKeyH AND r.Kept = 1 AND r.CmSens IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS CmSens
'@
    } else { ', CONVERT(nvarchar(max), NULL) AS CmId, CONVERT(nvarchar(max), NULL) AS CmSens' }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
UPDATE a SET TierKey = ISNULL(m.V, 99) FROM #aa a LEFT JOIN #tier m ON m.H = a.TierH;
IF OBJECT_ID('tempdb..#ta') IS NOT NULL DROP TABLE #ta;
SELECT TOP ($([int]$N)) ROW_NUMBER() OVER (ORDER BY TierKey, SumW DESC, SumU DESC, Findings DESC, FSort DESC, FSeq) AS Rk, *
INTO #ta FROM #aa ORDER BY TierKey, SumW DESC, SumU DESC, Findings DESC, FSort DESC, FSeq;
SELECT t.Rk, t.AKey, t.AName, t.Tier, t.Findings, t.SumU, t.SumW, (SELECT COUNT_BIG(*) FROM #aa) AS Total
, (SELECT TOP (1) r.CmName FROM #ra r WHERE r.AKeyH = t.AKeyH AND r.Kept = 1 AND r.CmName IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS CmName
, (SELECT TOP (1) r.CmCrit FROM #ra r WHERE r.AKeyH = t.AKeyH AND r.Kept = 1 AND r.CmCrit IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS CmCrit
$ai
FROM #ta t ORDER BY t.Rk;
"@
}

function Get-RATopAssetItemsSql {
    <#
        PURE. Per Top asset, in its rows' order: its distinct domains (first appearance), its first 12 items, and (-WithAi) its
        distinct reference texts with a link in them (first appearance) -- one result, told apart by Kind.
    #>
    param([bool]$WithAi)
    $md = if ($WithAi) {
        @'
UNION ALL
SELECT 'L', x.Rk, x.RaSort, x.RaSeq, x.MD, CONVERT(nvarchar(max), NULL), CONVERT(nvarchar(max), NULL), CONVERT(nvarchar(max), NULL) FROM (
    SELECT t.Rk, r.RaSort, r.RaSeq, r.MD, ROW_NUMBER() OVER (PARTITION BY t.Rk, HASHBYTES('SHA2_256', r.MD) ORDER BY r.RaSort DESC, r.RaSeq) AS Rn
    FROM #ta t JOIN #ra r ON r.AKeyH = t.AKeyH AND r.Kept = 1
    WHERE r.MD IS NOT NULL AND CHARINDEX(N'http', r.MD COLLATE Latin1_General_BIN2) > 0) x WHERE x.Rn = 1
'@
    } else { '' }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
SELECT y.Kind, y.Rk, y.A, y.B, y.C, y.D FROM (
SELECT 'D' AS Kind, x.Rk, x.RaSort, x.RaSeq, x.Dom AS A, CONVERT(nvarchar(max), NULL) AS B, CONVERT(nvarchar(max), NULL) AS C, CONVERT(nvarchar(max), NULL) AS D FROM (
    SELECT t.Rk, r.RaSort, r.RaSeq, r.Dom, ROW_NUMBER() OVER (PARTITION BY t.Rk, HASHBYTES('SHA2_256', r.Dom) ORDER BY r.RaSort DESC, r.RaSeq) AS Rn
    FROM #ta t JOIN #ra r ON r.AKeyH = t.AKeyH AND r.Kept = 1 WHERE r.Dom IS NOT NULL) x WHERE x.Rn = 1
UNION ALL
SELECT 'I', x.Rk, x.RaSort, x.RaSeq, x.CName, x.CId, x.Cat, x.Sub FROM (
    SELECT t.Rk, r.RaSort, r.RaSeq, r.CName, r.CId, r.Cat, r.Sub, ROW_NUMBER() OVER (PARTITION BY t.Rk ORDER BY r.RaSort DESC, r.RaSeq) AS Rn
    FROM #ta t JOIN #ra r ON r.AKeyH = t.AKeyH AND r.Kept = 1) x WHERE x.Rn <= 12
$md
) y ORDER BY y.Rk, y.Kind, y.RaSort DESC, y.RaSeq;
"@
}

function Get-RATopFindingsSql {
    <#
        PURE. The Top -N findings (by configuration id, case-insensitive as the row loop's hashtable): weighted sum, total sum,
        distinct assets (exact name) descending, then where each first appears. With their first-seen values.
    #>
    param([int]$N = 50)
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
IF OBJECT_ID('tempdb..#fa') IS NOT NULL DROP TABLE #fa;
SELECT a.CKeyH, a.SumU, a.SumW, a.Aac, f.RaSort AS FSort, f.RaSeq AS FSeq, f.CId
INTO #fa
FROM (SELECT CKeyH, SUM(U) AS SumU, SUM(W) AS SumW, COUNT(DISTINCT ANH) AS Aac FROM #ra WHERE Kept = 1 AND CKeyH IS NOT NULL GROUP BY CKeyH) a
JOIN (SELECT CKeyH, RaSort, RaSeq, CId, ROW_NUMBER() OVER (PARTITION BY CKeyH ORDER BY RaSort DESC, RaSeq) AS Rn FROM #ra WHERE Kept = 1 AND CKeyH IS NOT NULL) f
  ON f.CKeyH = a.CKeyH AND f.Rn = 1;
IF OBJECT_ID('tempdb..#tf') IS NOT NULL DROP TABLE #tf;
SELECT TOP ($([int]$N)) ROW_NUMBER() OVER (ORDER BY SumW DESC, SumU DESC, Aac DESC, FSort DESC, FSeq) AS Rk, *
INTO #tf FROM #fa ORDER BY SumW DESC, SumU DESC, Aac DESC, FSort DESC, FSeq;
SELECT t.Rk, t.CId, t.SumU, t.SumW, t.Aac
, (SELECT TOP (1) r.CName FROM #ra r WHERE r.CKeyH = t.CKeyH AND r.Kept = 1 AND r.CName IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS CName
, (SELECT TOP (1) r.Cat FROM #ra r WHERE r.CKeyH = t.CKeyH AND r.Kept = 1 AND r.Cat IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS Cat
, (SELECT TOP (1) r.Sub FROM #ra r WHERE r.CKeyH = t.CKeyH AND r.Kept = 1 AND r.Sub IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS Sub
, (SELECT TOP (1) r.Sev FROM #ra r WHERE r.CKeyH = t.CKeyH AND r.Kept = 1 AND r.Sev IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS Sev
, (SELECT TOP (1) r.Dom FROM #ra r WHERE r.CKeyH = t.CKeyH AND r.Kept = 1 AND r.Dom IS NOT NULL ORDER BY r.RaSort DESC, r.RaSeq) AS Dom
FROM #tf t ORDER BY t.Rk;
"@
}

function Get-RATopFindingItemsSql {
    <#
        PURE. Per Top finding: its assets' weighted sums by name (case-insensitive, the name as first seen) -- every asset tied
        into the 5 highest sums (the caller sorts them exactly as before) -- how many assets it has in all, and (-WithAi) its
        distinct reference texts with a link (first appearance). Told apart by Kind.
    #>
    param([bool]$WithAi)
    $md = if ($WithAi) {
        @'
UNION ALL
SELECT 'L', x.Rk, x.RaSort, x.RaSeq, x.MD, CONVERT(float, NULL), CONVERT(int, NULL) FROM (
    SELECT t.Rk, r.RaSort, r.RaSeq, r.MD, ROW_NUMBER() OVER (PARTITION BY t.Rk, HASHBYTES('SHA2_256', r.MD) ORDER BY r.RaSort DESC, r.RaSeq) AS Rn
    FROM #tf t JOIN #ra r ON r.CKeyH = t.CKeyH AND r.Kept = 1
    WHERE r.MD IS NOT NULL AND CHARINDEX(N'http', r.MD COLLATE Latin1_General_BIN2) > 0) x WHERE x.Rn = 1
'@
    } else { '' }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
;WITH s AS (
    SELECT t.Rk, r.ANUH, SUM(r.W) AS S FROM #tf t JOIN #ra r ON r.CKeyH = t.CKeyH AND r.Kept = 1 GROUP BY t.Rk, r.ANUH),
n AS (
    SELECT t.Rk, r.ANUH, r.AName, ROW_NUMBER() OVER (PARTITION BY t.Rk, r.ANUH ORDER BY r.RaSort DESC, r.RaSeq) AS Rn FROM #tf t JOIN #ra r ON r.CKeyH = t.CKeyH AND r.Kept = 1),
d AS (
    SELECT s.Rk, s.S, n.AName, DENSE_RANK() OVER (PARTITION BY s.Rk ORDER BY s.S DESC) AS Dr, COUNT(*) OVER (PARTITION BY s.Rk) AS Cnt
    FROM s JOIN n ON n.Rk = s.Rk AND n.ANUH = s.ANUH AND n.Rn = 1)
SELECT y.Kind, y.Rk, y.A, y.B, y.C FROM (
SELECT 'A' AS Kind, d.Rk, CONVERT(float, NULL) AS RaSort, CONVERT(bigint, NULL) AS RaSeq, d.AName AS A, d.S AS B, d.Cnt AS C FROM d WHERE d.Dr <= 5
$md
) y ORDER BY y.Rk, y.Kind, y.RaSort DESC, y.RaSeq;
"@
}

function Get-RATopKpiGroupsSql {
    <# PURE. The key figures' six values of every row, each distinct combination once with its count. #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
SELECT MIN(KSev) AS KSev, MIN(KDom) AS KDom, MIN(KRep) AS KRep, MIN(KKpi) AS KKpi, MIN(KTier) AS KTier, MIN(KIac) AS KIac,
       MAX(CONVERT(int, KIacStr)) AS KIacStr, COUNT_BIG(*) AS N
FROM #ra GROUP BY KH;
'@
}

function Get-RATopPatchTriplesSql {
    <# PURE. The patch cycle's distinct (given cycle, update id, update name) of the CVE rows -- each decided by Get-SIPatchCycle. #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
SELECT CONVERT(varchar(64), PTripleH, 2) AS H, MIN(PGiven) AS G, MIN(PUid) AS I, MIN(PUpd) AS U FROM #ra WHERE PCve = 1 GROUP BY PTripleH;
'@
}

function Get-RATopPatchSql {
    <#
        PURE. The patch cycle from the decided triples (#cyc): findings and distinct devices (case-insensitive) per group and in
        all, and the catch-up fixes by update id (case-insensitive; the id and the name of the first row in the final order).
    #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
SELECT 'G' AS Kind, CONVERT(nvarchar(max), c.V) AS A, CONVERT(nvarchar(max), NULL) AS B, COUNT_BIG(*) AS N, COUNT(DISTINCT r.PDevUH) AS D
FROM #ra r JOIN #cyc c ON c.H = r.PTripleH WHERE r.PCve = 1 GROUP BY c.V
UNION ALL
SELECT 'T', CONVERT(nvarchar(max), NULL), CONVERT(nvarchar(max), NULL), COUNT_BIG(*), COUNT(DISTINCT PDevUH) FROM #ra WHERE PCve = 1
UNION ALL
SELECT 'F', f.PUid, f.PUpd, a.N, a.D FROM (
    SELECT r.PUidUH, COUNT_BIG(*) AS N, COUNT(DISTINCT r.PDevUH) AS D FROM #ra r JOIN #cyc c ON c.H = r.PTripleH
    WHERE r.PCve = 1 AND c.V = N'catchup' AND r.PUid <> N'' GROUP BY r.PUidUH) a
JOIN (SELECT r.PUidUH, r.PUid, r.PUpd, ROW_NUMBER() OVER (PARTITION BY r.PUidUH ORDER BY r.RaSort DESC, r.RaSeq) AS Rn FROM #ra r JOIN #cyc c ON c.H = r.PTripleH
      WHERE r.PCve = 1 AND c.V = N'catchup' AND r.PUid <> N'') f ON f.PUidUH = a.PUidUH AND f.Rn = 1;
'@
}

# ------------------------------------------------------------------------------------------------------------------
#  THE VALUES POWERSHELL DECIDES (the engine's own functions, each distinct value once)
# ------------------------------------------------------------------------------------------------------------------

function ConvertFrom-RATopStoredValue {
    <#
        PURE. A stored value's text as the row decoder hands it to the engine: a JSON number (-IsNumberText) comes back as a
        long / double (Newtonsoft, as ConvertFrom-RAStreamJson reads it), anything else stays text. $null stays $null.
    #>
    param($Text, [bool]$AsJsonNumber)
    if ($null -eq $Text) { return $null }
    $t = [string]$Text
    if ($AsJsonNumber -and $t -match '^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$') {
        try {
            $sr = New-Object System.IO.StringReader($t)
            $jr = New-Object Newtonsoft.Json.JsonTextReader($sr)
            $jr.FloatParseHandling = [Newtonsoft.Json.FloatParseHandling]::Double
            try { $tok = [Newtonsoft.Json.Linq.JToken]::ReadFrom($jr) } finally { $jr.Close() }
            return $tok.ToObject([object])
        } catch { return $t }
    }
    $t
}

function Get-RATopTierSortKey {
    <# PURE. The row loop's tier sort key of an asset's tier text: 'tier <n>' -> n, anything else 99. #>
    param([string]$Text)
    $t = [string]$Text
    if ($t -match 'tier\s*(\d+)') { [int]$Matches[1] } else { 99 }
}

function Add-RATopLinks {
    <# The row loop's link harvest (the first 6 distinct URLs) over texts in their order. #>
    param([System.Collections.Generic.HashSet[string]]$Links, [object[]]$Texts)
    foreach ($md in @($Texts)) {
        if ([string]::IsNullOrWhiteSpace([string]$md) -or $Links.Count -ge 6) { continue }
        foreach ($urlMatch in ([regex]::Matches([string]$md, 'https?://[^\s,;<>"`)\]]+'))) {
            if ($Links.Count -ge 6) { break }
            $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
            [void]$Links.Add($u)
        }
    }
}

# ------------------------------------------------------------------------------------------------------------------
#  THE PASS
# ------------------------------------------------------------------------------------------------------------------

function Invoke-RATopListsInSql {
    <#
        The Top -TopAssetsN assets, the Top -TopFindingsN findings and the key figures of the run's View rows, set-based in the
        database (see the file's head). -KpiState: a fresh New-RAKpiState (its Prot must be $null: the Protection Score is the
        stored one); it comes back filled and marked Complete -- what Invoke-RAKpiPass takes instead of reading the rows.
        -ViewRows: the run's View row count (a different count read = declined). -Collapse: the *_Detailed collapse.
        -WithAi: the AI summary is on (the AI-only values are worked out too). -Progress: a #1180 ticker.
        NEVER THROWS. Returns @{ Status 'ok' | 'declined'; Why; Rows; Assets; Kept; NoAsset; TopAssets; TopFindings;
        KpiState; Seconds; Ranges }. 'declined' = nothing of it is used: the row-by-row pass runs as before.
    #>
    param([Parameter(Mandatory)]$Stream, [long]$ViewRows = -1, [bool]$Collapse, [bool]$WithAi, [int]$TopAssetsN = 50, [int]$TopFindingsN = 50,
          [Parameter(Mandatory)][hashtable]$KpiState, $Progress = $null, [scriptblock]$Log, [double]$TargetSeconds = 20, [long]$FirstSpan = 200000)
    if (-not $Log) { $Log = { param($l, $m) } }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $out = [ordered]@{ Status = 'declined'; Why = ''; Rows = 0L; Assets = 0L; Kept = 0L; NoAsset = 0L; TopAssets = @(); TopFindings = @(); KpiState = $null; Seconds = 0.0; Ranges = 0 }
    try {
        if ($null -eq $Stream -or -not ($Stream.Invoke -is [scriptblock])) { $out.Why = 'no database seam'; return [pscustomobject]$out }
        if ([string]$Stream.Grain -ne 'Detailed' -or [int]$Stream.CollectionId -le 0) { $out.Why = 'not a Detailed run with a collection'; return [pscustomobject]$out }
        if ($null -ne $KpiState.Prot) { $out.Why = 'the Protection Score is counted in this run'; return [pscustomobject]$out }
        $why = Test-RATopListsColumns -Reports $Stream.Reports -WithAi $WithAi
        if ($why) { $out.Why = $why; return [pscustomobject]$out }
        $cid = [int]$Stream.CollectionId
        $held = @(Get-RAStreamHeldOrdinals -Stream $Stream)
        $inv = $Stream.Invoke
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
        $tick = ($null -ne $Progress) -and [bool](Get-Command -Name Step-SIStepProgressTicker -ErrorAction SilentlyContinue)
        $res = @{}
        $onSession = {
            param($Run)
            $rd = { param([string]$Sql) @(& $Run $Sql 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } }
            $null = & $Run (Get-RATopSetupSql) 'nonquery'
            # ---- the rows, a FindingId range at a time (two seeks on the clustered key, never a count of the rows) ----
            $rg = @(& $rd ("SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = {0};" -f $cid)) | Select-Object -First 1
            $lo = $null; $hi = $null
            if ($rg) { $lo = $rg['Lo']; $hi = $rg['Hi']; if ($lo -is [System.DBNull]) { $lo = $null }; if ($hi -is [System.DBNull]) { $hi = $null } }
            $rows = 0L; $odd = 0L
            if ($null -ne $lo -and $null -ne $hi) {
                $from = [long]$lo - 1; $top = [long]$hi; $span = [Math]::Max(1L, $FirstSpan); $lastMs = 0L
                while ($from -lt $top) {
                    if ($paced) {
                        $pace = Invoke-SISqlPacing -Invoke $inv -LastBatchMs $lastMs -Log $Log
                        if ($pace -and $pace.Shrink) { $span = [Math]::Max(1L, [long]($span / 2)) }
                    }
                    $to = [long][Math]::Min([double]$top, [double]$from + $span)
                    $sw = [System.Diagnostics.Stopwatch]::StartNew()
                    $r1 = @(& $rd (Get-RATopRangeSql -CollectionId $cid -Lo $from -Hi $to -Held $held -WithAi $WithAi)) | Select-Object -First 1
                    $sec = [Math]::Max(0.05, $sw.Elapsed.TotalSeconds); $lastMs = [long]$sw.ElapsedMilliseconds
                    $res.Ranges = [int]$res.Ranges + 1
                    if ($r1) { $rows += [long]$r1['N']; $odd += [long]$r1['Odd'] }
                    $from = $to
                    if ($tick) { $null = Step-SIStepProgressTicker -Ticker $Progress -Done $rows }
                    if ($odd -gt 0) { break }
                    # the next range from the measured pace (at most twice / half the last one)
                    $span = [long][Math]::Max(1, [Math]::Round($span * [Math]::Min(2.0, [Math]::Max(0.5, $TargetSeconds / $sec))))
                }
            }
            $res.Rows = $rows
            if ($odd -gt 0) { $res.Why = 'a stored row carries an asset list or a list / object value the lists read as one value'; return }
            if ($ViewRows -ge 0 -and $rows -ne $ViewRows) { $res.Why = ('{0} rows read, the run counted {1} (collection {2}, finding ids {3}..{4}, {5} range(s))' -f $rows, $ViewRows, $cid, $lo, $hi, [int]$res.Ranges); return }
            # ---- the scores: each distinct text through ConvertTo-RADouble ----
            $nums = @(& $rd (Get-RATopNumberTextsSql))
            $pairs = @(foreach ($x in $nums) { @{ H = [string]$x['H']; V = (ConvertTo-RADouble -Value (ConvertFrom-RATopStoredValue -Text $x['T'] -AsJsonNumber $true) -Default 0.0) } })
            $null = & $Run (Get-RATopMapInsertSql -Table 'num' -SqlType 'float' -Pairs $pairs -Bits) 'nonquery'
            $null = & $Run (Get-RATopApplyNumbersSql) 'nonquery'
            $p = @(& $rd (Get-RATopPrepareSql -Collapse $Collapse)) | Select-Object -First 1
            if ($p) { $res.Kept = [long]$p['Kept']; $res.NoAsset = [long]$p['NoAsset'] }
            # ---- the assets ----
            $tiers = @(& $rd (Get-RATopAssetAggSql))
            $tp = @(foreach ($x in $tiers) { @{ H = [string]$x['H']; V = [long](Get-RATopTierSortKey -Text ([string]$x['T'])) } })
            $null = & $Run (Get-RATopMapInsertSql -Table 'tier' -SqlType 'int' -Pairs $tp) 'nonquery'
            $res.TA = @(& $rd (Get-RATopAssetsSql -N $TopAssetsN -WithAi $WithAi))
            $res.TAI = @(& $rd (Get-RATopAssetItemsSql -WithAi $WithAi))
            # ---- the findings ----
            $res.TF = @(& $rd (Get-RATopFindingsSql -N $TopFindingsN))
            $res.TFI = @(& $rd (Get-RATopFindingItemsSql -WithAi $WithAi))
            # ---- the key figures ----
            $res.K = @(& $rd (Get-RATopKpiGroupsSql))
            $tri = @(& $rd (Get-RATopPatchTriplesSql))
            $ct = $KpiState.Patch.CollectionTime; $cd = [int]$KpiState.Patch.CatchUpDays
            $cp = @(foreach ($x in $tri) { @{ H = [string]$x['H']; V = [string](Get-SIPatchCycle -Given ([string]$x['G']) -UpdateId ([string]$x['I']) -UpdateName ([string]$x['U']) -CollectionTime $ct -CatchUpDays $cd) } })
            $null = & $Run (Get-RATopMapInsertSql -Table 'cyc' -SqlType 'nvarchar(16)' -Pairs $cp) 'nonquery'
            $res.P = @(& $rd (Get-RATopPatchSql))
            $res.Done = $true
            $null
        }
        $null = & $inv $null $null 'session' $onSession
        $out.Rows = [long]$res.Rows; $out.Ranges = [int]$res.Ranges; $out.Kept = [long]$res.Kept; $out.NoAsset = [long]$res.NoAsset
        if (-not $res.Done) { $out.Why = $(if ($res.Why) { [string]$res.Why } else { 'the database pass did not finish' }); return [pscustomobject]$out }

        # ---- the Top assets, shaped as the row loop's aggregates (Add-AssetAgg) ----
        $itemsBy = @{}
        foreach ($x in $res.TAI) { $k = [int]$x['Rk']; if (-not $itemsBy.ContainsKey($k)) { $itemsBy[$k] = New-Object 'System.Collections.Generic.List[object]' }; $itemsBy[$k].Add($x) }
        $assets = New-Object 'System.Collections.Generic.List[object]'
        foreach ($x in $res.TA) {
            $rk = [int]$x['Rk']; $out.Assets = [long]$x['Total']
            $doms = New-Object 'System.Collections.Generic.HashSet[string]'
            $items = New-Object 'System.Collections.Generic.List[string]'
            $links = New-Object 'System.Collections.Generic.HashSet[string]'
            $mdTexts = New-Object 'System.Collections.Generic.List[object]'
            $its = $null; if ($itemsBy.ContainsKey($rk)) { $its = $itemsBy[$rk].ToArray() } else { $its = @() }
            foreach ($it in $its) {
                if ($null -eq $it) { continue }
                $kind = [string]$it['Kind']
                if ($kind -eq 'D') { [void]$doms.Add([string]$it['A']) }
                elseif ($kind -eq 'I') { $items.Add([string]::Format('{0} [{1}] ({2}/{3})', [string]$it['A'], [string]$it['B'], [string]$it['C'], [string]$it['D'])) }
                elseif ($kind -eq 'L') { $mdTexts.Add([string]$it['A']) }
            }
            if ($WithAi) { Add-RATopLinks -Links $links -Texts $mdTexts.ToArray() }
            $assets.Add([pscustomobject]@{
                Asset = [string]$x['AName']; AssetKey = [string]$x['AKey']; TierLevel = [string]$x['Tier']; Findings = [int]$x['Findings']
                TotalRiskScore = [double]$x['SumU']; TotalRiskScore_Weighted = [double]$x['SumW']
                CmdbId = [string]$x['CmId']; CmdbName = [string]$x['CmName']; CmdbCriticality = [string]$x['CmCrit']; CmdbDataSensitivity = [string]$x['CmSens']
                Domains = $doms; TopItems = $items; Links = $links; FirstSeen = ($rk - 1)
            })
        }
        if ($res.TA.Count -eq 0) { $out.Assets = 0L }
        # ---- the Top findings, shaped as the row loop's aggregates (Add-FindingAgg) ----
        $fiBy = @{}
        foreach ($x in $res.TFI) { $k = [int]$x['Rk']; if (-not $fiBy.ContainsKey($k)) { $fiBy[$k] = New-Object 'System.Collections.Generic.List[object]' }; $fiBy[$k].Add($x) }
        $findings = New-Object 'System.Collections.Generic.List[object]'
        foreach ($x in $res.TF) {
            $rk = [int]$x['Rk']
            $cand = New-Object 'System.Collections.Generic.List[object]'; $arsN = 0
            $links = New-Object 'System.Collections.Generic.HashSet[string]'
            $mdTexts = New-Object 'System.Collections.Generic.List[object]'
            $its = $null; if ($fiBy.ContainsKey($rk)) { $its = $fiBy[$rk].ToArray() } else { $its = @() }
            foreach ($it in $its) {
                if ($null -eq $it) { continue }
                $kind = [string]$it['Kind']
                if ($kind -eq 'A') { $cand.Add([pscustomobject]@{ Asset = [string]$it['A']; W = [double]$it['B'] }); $arsN = [int]$it['C'] }
                elseif ($kind -eq 'L') { $mdTexts.Add([string]$it['A']) }
            }
            if ($WithAi) { Add-RATopLinks -Links $links -Texts $mdTexts.ToArray() }
            # the hottest assets in the executive view's own order (RA-ExecView.ps1: weighted sum, then the name)
            $ars = [ordered]@{}
            foreach ($c in @($cand | Sort-Object -Property @{ e = 'W'; Descending = $true }, @{ e = 'Asset'; Descending = $false })) { $ars[$c.Asset] = $c.W }
            $findings.Add([pscustomobject]@{
                ConfId = [string]$x['CId']; ConfName = [string]$x['CName']; Category = [string]$x['Cat']; Subcategory = [string]$x['Sub']
                Severity = [string]$x['Sev']; Domain = [string]$x['Dom']
                TotalRiskScore = [double]$x['SumU']; TotalRiskScore_Weighted = [double]$x['SumW']; AffectedAssetCount = [int]$x['Aac']
                AssetRiskScores = $ars; AssetRiskScoreCount = $arsN; Links = $links; FirstSeen = ($rk - 1)
            })
        }
        # ---- the key figures into the state (Add-RAKpiRowFigures, the per-row tally's own code, once per combination) ----
        $total = 0L
        foreach ($g in $res.K) {
            $n = [long]$g['N']; $total += $n
            $row = [pscustomobject]@{
                SecuritySeverity = $g['KSev']; SecurityDomain = $g['KDom']; Report = $g['KRep']; RiskScoreKPI = $g['KKpi']; CriticalityTier = $g['KTier']
                ImpactedAssetCount = (ConvertFrom-RATopStoredValue -Text $g['KIac'] -AsJsonNumber ([int]$g['KIacStr'] -eq 0))
            }
            Add-RAKpiRowFigures -State $KpiState -Row $row -Count $n
        }
        $pt = $KpiState.Patch
        foreach ($x in $res.P) {
            switch ([string]$x['Kind']) {
                'T' { $pt.Findings = [long]$x['N']; $pt.Devices = [pscustomobject]@{ Count = [int]$x['D'] } }
                'G' { $c = [string]$x['A']; $pt.Groups[$c] = [long]$x['N']; $pt.GroupDevices[$c] = [pscustomobject]@{ Count = [int]$x['D'] } }
                'F' {
                    $id = [string]$x['A']; $nm = [string]$x['B']
                    $pt.CatchUpFixes[$id] = [pscustomobject]@{ Id = $id; Name = $nm; Findings = [long]$x['N']; Devices = [pscustomobject]@{ Count = [int]$x['D'] }; Month = (Get-SIPatchCycleMonth -UpdateName $nm) }
                }
            }
        }
        $KpiState.Rows = $total
        if ($total -ne $out.Rows) { $out.Why = ('the key figures counted {0} rows of {1}' -f $total, $out.Rows); return [pscustomobject]$out }
        $KpiState.Complete = $true
        $out.TopAssets = $assets.ToArray(); $out.TopFindings = $findings.ToArray(); $out.KpiState = $KpiState
        $out.Status = 'ok'
    } catch {
        $at = ''; try { if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber -gt 0) { $at = (' (at {0}:{1}: {2})' -f [IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName), $_.InvocationInfo.ScriptLineNumber, ([string]$_.InvocationInfo.Line).Trim()) } } catch { }
        $out.Status = 'declined'; $out.Why = ('the database pass failed: {0}{1}' -f (([string]$_.Exception.Message -split "`n")[0]).Trim(), $at)
    } finally {
        $out.Seconds = $clock.Elapsed.TotalSeconds
    }
    [pscustomobject]$out
}

function Format-RATopListsLine {
    <# PURE. The one plain line of the pass: what it did and the time it took (invariant culture). #>
    param([Parameter(Mandatory)]$Result)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    if ([string]$Result.Status -eq 'ok') {
        return [string]::Format($inv, 'Top 50 lists and key figures: worked out in the database in {0:N0} s ({1:N0} rows read in {2} range(s); {3} asset(s), {4} on the list; {5} finding(s) on the list)',
            [double]$Result.Seconds, [long]$Result.Rows, [int]$Result.Ranges, [long]$Result.Assets, @($Result.TopAssets).Count, @($Result.TopFindings).Count)
    }
    [string]::Format($inv, 'Top 50 lists and key figures: read row by row as before ({0}; the database pass took {1:N0} s)', [string]$Result.Why, [double]$Result.Seconds)
}
