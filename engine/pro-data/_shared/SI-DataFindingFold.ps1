#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE MEANING RULES IN THE DATABASE (REQUIREMENTS #1364; owner 2026-11-25: "you cannot have 2 identical
    recommendations; only one ... we cannot have 2 similar tasks").

    The fold rules of the recommendation equivalence (#693: data-model/recommendation-equivalence.locked.json, match "fold" --
    e.g. Defender for Cloud's "Update <software>" on a server is evidence on that server's Defender for Endpoint CVE findings for
    that software) were applied ONLY where findings are made from SI_Finding_CL (RA-Findings.ps1 Merge-SIFindingFolds) and in
    the ServiceNow close-loop (SI-VulnLinked.ps1). The findings per CI made from the database -- the NORMAL path since #829 (the
    copy to SI_Finding_CL is off by default) -- and the remediation tasks (always built from sidata.Finding) never applied them:
    the same weakness was a second finding and a second task ("Update openssl", configuration) next to the CVE-based ones.

    HERE THE SAME RULES ARE APPLIED TO THE STORED RESULT, ONCE PER COLLECTION, before anything reads it (owner 2026-11-25, "what
    is the best way to solve this" -> the row is MOVED): an evidence finding's rows are moved OUT of sidata.Finding into
    sidata.FindingEvidence (the whole row kept, with the key of the canonical finding it is evidence on -- the FIRST canonical by
    ordinal lower-cased key, as Merge-SIFindingFolds names it -- and the rule). #693: "the evidence finding is NOT a finding of
    its own" -- so every reader of sidata.Finding (the security recommendation views and exports, key figures, summary groups,
    tasks, data out, the history ...) shows and counts ONE finding without a change of its own. What reads the evidence: the
    findings per CI (detected by + si_finding_evidence on the canonical finding), the lifecycle (the evidence finding's row is
    carried onto the canonical key as an alias, never closed as fixed), the remediation tasks (its old task closes as "task
    changed"), the data quality counts (a report's rows = its findings + its evidence rows: never fewer than the source).
    UN-FOLD: an evidence row whose fold no longer holds (its CVE findings are gone) is moved BACK as its own finding (the same
    row, the same key; a new FindingId). Idempotent: worked out again, only what changed moves.

    THE RULE IS THE TEMPLATE'S, evaluated by the engine's OWN functions (Test-SIFindingFoldSide, ConvertTo-SIFindingMatchValue)
    over the DISTINCT values of the fields it names (never per finding); SQL only joins the rows to those values by CI. A rule
    naming a field the stored findings do not carry is not applied (said once). Writes only sidata.Finding / FindingEvidence of
    that collection. Never fails the data sync. No PowerShell module. PowerShell 5.1 and 7.
#>

$script:SIFoldRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command -Name Test-SIFindingFoldSide -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIFoldRoot, 'data-model', 'SI-RecommendationEquivalence.ps1')) }
if (-not (Get-Command -Name Get-SIDataFullListSql -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIFoldRoot, '_shared', 'data-sql', 'SI-FullListSql.ps1')) }

function Get-SIDataFoldColumns {
    <# PURE. The SI fields a fold rule may read in the database -> their expression over a finding row f (bk = its own key parts). #>
    [ordered]@{
        si_finding_type     = "CASE WHEN bk.FKey LIKE N'CVE-[0-9][0-9][0-9][0-9]-%' THEN N'cve' ELSE N'recommendation' END"
        si_finding_key      = 'bk.FKey'
        si_cve              = 'f.Cve'
        si_title            = 'f.Title'
        si_report_name      = 'f.ReportName'
        si_security_domain  = 'f.SecurityDomain'
        si_category         = 'f.Category'
        si_subcategory      = 'f.Subcategory'
        si_component        = 'f.Component'
        si_affected_product = 'f.AffectedProduct'
        si_affected_vendor  = 'f.AffectedVendor'
        si_affected_version = 'f.AffectedVersion'
    }
}

function Get-SIDataFoldApplySql {
    <# PURE. A row's OWN key (before any fold): its owner and finding key, as the findings per CI make them. #>
    @'
CROSS APPLY (SELECT f.RaFindingKey AS BK) AS b
CROSS APPLY (SELECT CHARINDEX(N'|', b.BK) AS P) AS sp
CROSS APPLY (SELECT LEFT(b.BK, CASE WHEN sp.P > 1 THEN sp.P - 1 ELSE 0 END) AS Own, SUBSTRING(b.BK, sp.P + 1, 900) AS KeyPart) AS o
CROSS APPLY (SELECT LEFT(CASE WHEN LOWER(f.ConfigurationId) = o.KeyPart THEN f.ConfigurationId ELSE o.KeyPart END, 256) AS FKey) AS bk
'@
}

function Get-SIDataFoldWidth {
    <# PURE. #1403 the width a fold value is compared at: an affected list in full (max), any other value 4000 as before. #>
    param([string]$Field)
    if ($Field -like 'si_affected_*' -or $Field -like 'Affected*') { return 'max' }
    '4000'
}

function Get-SIDataFoldSourceSql {
    <# PURE. The rows a rule is worked out over, alias f: the collection's (@c) findings and its evidence rows (their stored row);
       EvidenceId is NULL for a finding. #>
    $flds = 'ConfigurationId', 'Cve', 'Title', 'ReportName', 'SecurityDomain', 'Category', 'Subcategory', 'Component', 'AffectedProduct', 'AffectedVendor', 'AffectedVersion'
    # #1403 the affected lists read in FULL (a list that fills its NVARCHAR(400) column, from the finding's document)
    $a = (@($flds | ForEach-Object {
                if ($_ -like 'Affected*') { '{0} AS {1}' -f (Get-SIDataFullListSql -Column ('f0.' + $_) -Bytes 800 -Keys ('si_affected_' + $_.Substring(8).ToLowerInvariant()), ('SI_' + $_) -Json 'f0.DetailJson'), $_ }
                else { "f0.$_" } })) -join ', '
    $b = (@($flds | ForEach-Object { if ($_ -in 'ConfigurationId', 'Title', 'ReportName') { "COALESCE(j0.$_, e0.$_)" } else { "j0.$_" } })) -join ', '
    $w = (@($flds | ForEach-Object { "$_ nvarchar($(Get-SIDataFoldWidth $_)) '$.$_'" })) -join ', '
@"
(SELECT f0.FindingId, CAST(NULL AS bigint) AS EvidenceId, f0.RaFindingKey, $a
 FROM sidata.Finding AS f0 WHERE f0.CollectionId = @c AND f0.RaFindingKey IS NOT NULL
 UNION ALL
 SELECT CAST(NULL AS bigint), e0.EvidenceId, e0.OwnKey, $b
 FROM sidata.FindingEvidence AS e0 CROSS APPLY OPENJSON(e0.RowJson) WITH ($w) AS j0 WHERE e0.CollectionId = @c) AS f
"@
}

function Get-SIDataFoldRuleFields {
    <# PURE. The SI fields one side of a rule reads: its conditions' fields and its side of the 'on' pairs (captures left out). #>
    param([Parameter(Mandatory)]$Rule, [ValidateSet('Evidence', 'Canonical')][string]$Side)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Rule.$Side)) { $f = [string]$c.Field; if ($f -and -not $l.Contains($f)) { $l.Add($f) } }
    $caps = New-Object System.Collections.Generic.List[string]
    if ($Side -eq 'Evidence') { foreach ($c in @($Rule.Evidence)) { if ($null -ne $c.Regex) { foreach ($n in $c.Regex.GetGroupNames()) { if ($n -notmatch '^\d+$') { $caps.Add($n) } } } } }
    foreach ($p in @($Rule.On)) { $f = [string]$p.$Side; if ($f -and -not $caps.Contains($f) -and -not $l.Contains($f)) { $l.Add($f) } }
    , $l.ToArray()
}

function Get-SIDataFoldValuesSql {
    <# One rule side: the DISTINCT values of its fields over the collection's rows (@CollectionId). c0..cn = the fields in order. #>
    param([Parameter(Mandatory)][string[]]$Fields)
    $cols = Get-SIDataFoldColumns
    $sel = @(for ($i = 0; $i -lt $Fields.Count; $i++) { "CONVERT(nvarchar({2}), {0}) AS c{1}" -f $cols[$Fields[$i]], $i, (Get-SIDataFoldWidth $Fields[$i]) })
    @"
SET NOCOUNT ON;
DECLARE @c INT = CONVERT(int, @CollectionId);
SELECT DISTINCT $($sel -join ', ')
FROM $(Get-SIDataFoldSourceSql)
$(Get-SIDataFoldApplySql)
WHERE sp.P > 1;
"@
}

function ConvertTo-SIDataFoldMatches {
    <#
        PURE. One rule side over its distinct values (-Rows: c0..cn of -Fields) -> the values that meet the side, each with the
        values it is matched on (one per 'on' pair, joined by U+001F; a list field gives one per item): @( @{ V = @(c0..cn); M } ).
        The engine's own rule functions decide (Test-SIFindingFoldSide, ConvertTo-SIFindingMatchValue) -- the same as at publish.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [Parameter(Mandatory)][string[]]$Fields, [Parameter(Mandatory)]$Rule, [ValidateSet('Evidence', 'Canonical')][string]$Side)
    $out = New-Object System.Collections.Generic.List[object]
    $sep = [string][char]31
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $vals = @(for ($i = 0; $i -lt $Fields.Count; $i++) { $x = $r[('c{0}' -f $i)]; if ($x -is [System.DBNull]) { $null } else { $x } })
        $item = [ordered]@{}
        for ($i = 0; $i -lt $Fields.Count; $i++) {
            $v = $vals[$i]
            # a stored list (';'-separated) is its items, as the finding carries them
            if ($null -ne $v -and $Fields[$i] -in 'si_affected_product', 'si_affected_vendor', 'si_affected_version' -and [string]$v -match ';') { $v = @(([string]$v).Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            $item[$Fields[$i]] = $v
        }
        $caps = Test-SIFindingFoldSide -Finding ([pscustomobject]$item) -Conditions @($Rule.$Side)
        if ($null -eq $caps) { continue }
        $parts = New-Object System.Collections.Generic.List[object]
        $ok = $true
        foreach ($p in @($Rule.On)) {
            $n = [string]$p.$Side
            $pv = if ($Side -eq 'Evidence' -and $caps.ContainsKey($n)) { @($caps[$n]) } else { @(Get-SIFindingFieldValues ([pscustomobject]$item) $n | ForEach-Object { ConvertTo-SIFindingMatchValue $_ }) }
            $pv = @($pv | Where-Object { $_ } | Select-Object -Unique)
            if ($pv.Count -eq 0) { $ok = $false; break }
            $parts.Add($pv)
        }
        if (-not $ok) { continue }
        # every combination of the pairs' values (one pair: its values)
        $combos = @('')
        $firstPart = $true
        foreach ($pv in $parts) {
            $combos = @(foreach ($c in $combos) { foreach ($x in $pv) { if ($firstPart) { [string]$x } else { $c + $sep + [string]$x } } })
            $firstPart = $false
        }
        if (@($Rule.On).Count -eq 0) { $combos = @('*') }
        foreach ($m in $combos) { $out.Add(@{ V = $vals; M = $m }) }
    }
    , $out.ToArray()
}

function Get-SIDataFoldApplySqlText {
    <#
        THE FOLD of collection @CollectionId, ONE transaction: @ev / @cv (JSON) = the evidence / canonical values of every rule
        (r = the rule's order, m = the value matched on, v0.. = the side's field values), -EvFields / -CvFields per rule. Per CI,
        by rule order: an evidence finding (a finding, or an evidence row already moved) that is not canonical-side ITSELF is
        evidence on the FIRST canonical FINDING (by ordinal lower-cased key) of that CI with the same value. Then: an evidence
        row whose fold no longer holds is moved BACK into sidata.Finding (its whole row, its own key); one whose canonical changed
        names the new one; a finding newly folded is moved OUT into sidata.FindingEvidence. Answers: Evidence (rows held as
        evidence now), Findings (evidence findings), Restored (rows moved back), Moved (rows moved out).
    #>
    param([AllowEmptyCollection()][object[]]$Rules = @())
    $cols = Get-SIDataFoldColumns
    $parts = New-Object System.Collections.Generic.List[string]
    $names = New-Object System.Collections.Generic.List[string]
    $ri = 0
    foreach ($r in $Rules) {
        $ri++
        $names.Add(("WHEN {0} THEN N'{1}'" -f $ri, ([string]$r.Group).Replace("'", "''")))
        foreach ($side in 'ev', 'cv') {
            $flds = if ($side -eq 'ev') { $r.EvFields } else { $r.CvFields }
            $with = @("r int '$.r'", "m nvarchar(4000) '$.m'") + @(for ($i = 0; $i -lt $flds.Count; $i++) { "v$i nvarchar($(Get-SIDataFoldWidth $flds[$i])) '$.v$i'" })
            $on = @(for ($i = 0; $i -lt $flds.Count; $i++) { "ISNULL(CONVERT(nvarchar($(Get-SIDataFoldWidth $flds[$i])), $($cols[$flds[$i]])), N'') = ISNULL(j.v$i, N'') COLLATE DATABASE_DEFAULT" })
            $tbl = if ($side -eq 'ev') { '#e' } else { '#c' }
            # a canonical is a FINDING (never an evidence row)
            $only = if ($side -eq 'cv') { ' AND f.EvidenceId IS NULL' } else { '' }
            $parts.Add(@"
INSERT $tbl (R, Own, BaseKey, M)
SELECT DISTINCT $ri, LEFT(o.Own, 450), b.BK, j.m
FROM $(Get-SIDataFoldSourceSql)
$(Get-SIDataFoldApplySql)
JOIN OPENJSON(@$side) WITH ($($with -join ', ')) AS j ON j.r = $ri AND $($on -join ' AND ')
WHERE sp.P > 1$only;
"@)
        }
    }
    $ruleName = if ($names.Count) { 'CASE @r ' + ($names -join ' ') + ' END' } else { "N''" }
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c INT = CONVERT(int, @CollectionId);
CREATE TABLE #e (R INT NOT NULL, Own NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, BaseKey NVARCHAR(900) COLLATE DATABASE_DEFAULT NOT NULL, M NVARCHAR(4000) COLLATE DATABASE_DEFAULT NOT NULL);
CREATE TABLE #c (R INT NOT NULL, Own NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, BaseKey NVARCHAR(900) COLLATE DATABASE_DEFAULT NOT NULL, M NVARCHAR(4000) COLLATE DATABASE_DEFAULT NOT NULL);
$($parts -join "`n")
CREATE INDEX IX_c ON #c (R, Own, M) INCLUDE (BaseKey);
-- the canonical of each evidence finding (its own key), rule by rule: the first canonical finding (ordinal, lower-cased key) of
-- its CI with the same value, never itself; a finding that is canonical-side for that rule is never folded (no chain)
CREATE TABLE #t (BaseKey NVARCHAR(900) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY, Target NVARCHAR(900) COLLATE DATABASE_DEFAULT NOT NULL, RuleId NVARCHAR(128) NULL);
DECLARE @r INT = 1, @rn INT = (SELECT ISNULL(MAX(R), 0) FROM (SELECT R FROM #e UNION ALL SELECT R FROM #c) AS x);
WHILE @r <= @rn
BEGIN
    INSERT #t (BaseKey, Target, RuleId)
    SELECT e.BaseKey, MIN(LOWER(c.BaseKey) COLLATE Latin1_General_BIN2), $ruleName
    FROM (SELECT DISTINCT BaseKey, Own, M FROM #e WHERE R = @r) AS e
    JOIN #c AS c ON c.R = @r AND c.Own = e.Own AND c.M = e.M AND c.BaseKey <> e.BaseKey
    WHERE NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.BaseKey = e.BaseKey OR t.Target = e.BaseKey)
      AND NOT EXISTS (SELECT 1 FROM #c AS s WHERE s.R = @r AND s.BaseKey = e.BaseKey)
      AND NOT EXISTS (SELECT 1 FROM #t AS t2 WHERE t2.BaseKey = c.BaseKey)
    GROUP BY e.BaseKey;
    SET @r = @r + 1;
END
-- the row as sidata.Finding holds it now (every stored column but the identity): the move back reads the kept row by it
DECLARE @cols NVARCHAR(MAX), @with NVARCHAR(MAX);
SELECT @cols = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name)), N', ') WITHIN GROUP (ORDER BY c.column_id),
       @with = STRING_AGG(CONVERT(nvarchar(max), QUOTENAME(c.name) + N' '
                 + CASE WHEN t.name IN (N'nvarchar', N'nchar') THEN t.name + N'(' + CASE WHEN c.max_length = -1 THEN N'max' ELSE CONVERT(nvarchar(10), c.max_length / 2) END + N')'
                        WHEN t.name IN (N'varchar', N'char', N'varbinary', N'binary') THEN t.name + N'(' + CASE WHEN c.max_length = -1 THEN N'max' ELSE CONVERT(nvarchar(10), c.max_length) END + N')'
                        WHEN t.name IN (N'decimal', N'numeric') THEN t.name + N'(' + CONVERT(nvarchar(5), c.precision) + N', ' + CONVERT(nvarchar(5), c.scale) + N')'
                        WHEN t.name IN (N'datetime2', N'time', N'datetimeoffset') THEN t.name + N'(' + CONVERT(nvarchar(5), c.scale) + N')'
                        ELSE t.name END
                 + N' ''$."' + c.name + N'"'''), N', ') WITHIN GROUP (ORDER BY c.column_id)
FROM sys.columns AS c JOIN sys.types AS t ON t.user_type_id = c.user_type_id
WHERE c.object_id = OBJECT_ID(N'sidata.Finding') AND c.is_identity = 0 AND c.is_computed = 0 AND t.name NOT IN (N'timestamp', N'rowversion');
CREATE TABLE #back (EvidenceId BIGINT NOT NULL PRIMARY KEY, RowJson NVARCHAR(MAX) NOT NULL);
INSERT #back (EvidenceId, RowJson)
SELECT e.EvidenceId, e.RowJson FROM sidata.FindingEvidence AS e
WHERE e.CollectionId = @c AND NOT EXISTS (SELECT 1 FROM #t AS t WHERE t.BaseKey = e.OwnKey COLLATE DATABASE_DEFAULT)
  AND ISJSON(e.RowJson) = 1 AND JSON_VALUE(e.RowJson, '$.CollectionId') IS NOT NULL AND JSON_VALUE(e.RowJson, '$.RaFindingKey') IS NOT NULL;
-- the evidence of a collection the retention removed goes with it
DELETE e FROM sidata.FindingEvidence AS e WHERE NOT EXISTS (SELECT 1 FROM sidata.Collection AS x WHERE x.CollectionId = e.CollectionId);
DECLARE @restored INT = 0, @moved INT = 0;
DECLARE @ins NVARCHAR(MAX) = N'INSERT sidata.Finding (' + @cols + N') SELECT j.* FROM #back AS b CROSS APPLY OPENJSON(b.RowJson) WITH (' + @with + N') AS j;';
BEGIN TRAN;
-- (1) a fold that no longer holds: the row back as its own finding (the same row, the same key)
IF EXISTS (SELECT 1 FROM #back)
BEGIN
    EXEC sp_executesql @ins;
    SET @restored = @@ROWCOUNT;
    DELETE e FROM sidata.FindingEvidence AS e JOIN #back AS b ON b.EvidenceId = e.EvidenceId;
END
-- (2) evidence whose canonical changed names the new one
UPDATE e SET CanonicalKey = t.Target, RuleId = t.RuleId
FROM sidata.FindingEvidence AS e JOIN #t AS t ON t.BaseKey = e.OwnKey COLLATE DATABASE_DEFAULT
WHERE e.CollectionId = @c AND (e.CanonicalKey <> t.Target COLLATE DATABASE_DEFAULT OR ISNULL(e.RuleId, N'') <> ISNULL(t.RuleId, N''));
-- (3) the new folds: the whole row kept as evidence, then out of the findings
INSERT sidata.FindingEvidence (CollectionId, FindingId, OwnKey, CanonicalKey, RuleId, ReportName, ConfigurationId, Title, Severity, CarriedFrom, MovedAt, RowJson)
SELECT @c, f.FindingId, f.RaFindingKey, t.Target, t.RuleId, f.ReportName, f.ConfigurationId, f.Title,
       CASE LOWER(LTRIM(RTRIM(f.Severity))) WHEN N'very high' THEN N'critical' WHEN N'critical' THEN N'critical' WHEN N'high' THEN N'high' WHEN N'medium-high' THEN N'medium'
            WHEN N'medium' THEN N'medium' WHEN N'moderate' THEN N'medium' WHEN N'low' THEN N'low' ELSE N'info' END,
       f.CarriedFrom, SYSUTCDATETIME(),
       (SELECT x.* FROM sidata.Finding AS x WHERE x.CollectionId = f.CollectionId AND x.FindingId = f.FindingId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES)
FROM sidata.Finding AS f JOIN #t AS t ON t.BaseKey = f.RaFindingKey COLLATE DATABASE_DEFAULT
WHERE f.CollectionId = @c;
SET @moved = @@ROWCOUNT;
DELETE f FROM sidata.Finding AS f JOIN #t AS t ON t.BaseKey = f.RaFindingKey COLLATE DATABASE_DEFAULT WHERE f.CollectionId = @c /* one-statement-ok: only the folded rows (#t), in the same transaction as their evidence rows and checked against that count */;
IF @@ROWCOUNT <> @moved THROW 51364, N'the evidence rows moved and the finding rows removed differ -- nothing is changed', 1;
COMMIT;
SELECT (SELECT COUNT(*) FROM sidata.FindingEvidence WHERE CollectionId = @c) AS Evidence, (SELECT COUNT(*) FROM #t) AS Findings,
       @restored AS Restored, @moved AS Moved;
"@
}

function Get-SIDataFoldSchemaCheckSql { "SELECT CASE WHEN OBJECT_ID('sidata.FindingEvidence') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'RaFindingKey') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'AffectedProduct') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Component') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'Category') IS NOT NULL THEN 1 ELSE 0 END" }

function Get-SIDataFoldAliasStageSql {
    <#
        The lifecycle's key changes of the evidence of collection @CollectionId into sidata.CiFindingLifecycleStage (Kind a: o =
        owner, a = the evidence finding's own key, c = the canonical finding's key as the findings per CI name it) -- the lifecycle
        carries the evidence finding's row onto the canonical key (Get-SIDataFindingStateSql -WithEquivalence), never closing it.
    #>
    @'
SET NOCOUNT ON;
INSERT sidata.CiFindingLifecycleStage (Kind, OwnerKey, FindingKey, Canonical)
SELECT DISTINCT N'a', LEFT(o.Own, 450), LEFT(bk.FKey, 256), LEFT(ck.CKey, 256)
FROM sidata.FindingEvidence AS e
CROSS APPLY (SELECT CHARINDEX(N'|', e.OwnKey) AS P) AS sp
CROSS APPLY (SELECT LEFT(e.OwnKey, CASE WHEN sp.P > 1 THEN sp.P - 1 ELSE 0 END) AS Own, SUBSTRING(e.OwnKey, sp.P + 1, 900) AS KeyPart) AS o
CROSS APPLY (SELECT LEFT(CASE WHEN LOWER(e.ConfigurationId) = o.KeyPart THEN e.ConfigurationId ELSE o.KeyPart END, 256) AS FKey) AS bk
CROSS APPLY (SELECT SUBSTRING(e.CanonicalKey, CHARINDEX(N'|', e.CanonicalKey) + 1, 900) AS TPart) AS tp
OUTER APPLY (SELECT TOP (1) x.ConfigurationId FROM sidata.Finding AS x
             WHERE x.CollectionId = e.CollectionId AND x.RaFindingKey = e.CanonicalKey AND LOWER(x.ConfigurationId) = tp.TPart) AS cx
CROSS APPLY (SELECT COALESCE(cx.ConfigurationId, tp.TPart) AS CKey) AS ck
WHERE e.CollectionId = CONVERT(int, @CollectionId) AND sp.P > 1 AND CHARINDEX(N'|', e.CanonicalKey) > 1;
SELECT @@ROWCOUNT;
'@
}

function Invoke-SIDataFindingFold {
    <#
    .SYNOPSIS  The fold rules of the run's recommendation equivalence applied to collection -CollectionId in the database (see the
               header). Returns @{ Status (ok | none | no-schema | failed); Rules; Folded; Findings; Restored; Error }. Never throws.
    .PARAMETER Equivalence  the index (ConvertTo-SIRecommendationEquivalenceIndex; default: the run's, Get-SIRecommendationEquivalence)
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, $Equivalence, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $res = [pscustomobject]@{ Status = 'ok'; Rules = 0; Folded = 0L; Findings = 0L; Restored = 0L; Moved = 0L; Error = '' }
    try {
        if (([string](& $Invoke (Get-SIDataFoldSchemaCheckSql) @{} 'scalar')) -ne '1') { $res.Status = 'no-schema'; return $res }
        $idx = $Equivalence
        if ($null -eq $idx) { $idx = Get-SIRecommendationEquivalence }
        $cols = Get-SIDataFoldColumns
        $rules = New-Object System.Collections.Generic.List[object]
        $ev = New-Object System.Collections.Generic.List[object]; $cv = New-Object System.Collections.Generic.List[object]
        foreach ($rule in @(if ($null -ne $idx) { $idx.Folds })) {
            if ($null -eq $rule) { continue }
            $ef = Get-SIDataFoldRuleFields -Rule $rule -Side Evidence; $cf = Get-SIDataFoldRuleFields -Rule $rule -Side Canonical
            $miss = @(@($ef) + @($cf) | Where-Object { -not $cols.Contains($_) } | Select-Object -Unique)
            if ($miss.Count) { & $Log 'INFO' ("linked findings: the rule '{0}' reads {1}, which the stored findings do not carry -- it is applied where the findings are published, not here" -f $rule.Group, ($miss -join ', ')); continue }
            if (@($ef).Count -eq 0 -or @($cf).Count -eq 0) { continue }
            $n = $rules.Count + 1
            $p = @{ CollectionId = [string]$CollectionId }
            $eRows = @(@(& $Invoke (Get-SIDataFoldValuesSql -Fields $ef) $p 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $cRows = @(@(& $Invoke (Get-SIDataFoldValuesSql -Fields $cf) $p 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $em = ConvertTo-SIDataFoldMatches -Rows $eRows -Fields $ef -Rule $rule -Side Evidence
            $cm = ConvertTo-SIDataFoldMatches -Rows $cRows -Fields $cf -Rule $rule -Side Canonical
            # only the canonical values some evidence is matched on (the statement joins few values, never every product)
            $want = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal); foreach ($x in $em) { [void]$want.Add([string]$x.M) }
            $cm = @($cm | Where-Object { $want.Contains([string]$_.M) })
            if ($em.Count -eq 0 -or $cm.Count -eq 0) { continue }
            foreach ($x in $em) { $o = [ordered]@{ r = $n; m = $x.M }; for ($i = 0; $i -lt $ef.Count; $i++) { $o["v$i"] = $(if ($null -eq $x.V[$i]) { $null } else { [string]$x.V[$i] }) }; $ev.Add($o) }
            foreach ($x in $cm) { $o = [ordered]@{ r = $n; m = $x.M }; for ($i = 0; $i -lt $cf.Count; $i++) { $o["v$i"] = $(if ($null -eq $x.V[$i]) { $null } else { [string]$x.V[$i] }) }; $cv.Add($o) }
            $rules.Add([pscustomobject]@{ Group = $rule.Group; EvFields = [string[]]$ef; CvFields = [string[]]$cf })
        }
        $res.Rules = $rules.Count
        # no rule with anything to fold: the statement only gives an earlier fold of this collection its own key back
        $sql = Get-SIDataFoldApplySqlText -Rules $rules.ToArray()
        $j = { param($l) $t = ConvertTo-Json -InputObject @($l.ToArray()) -Compress -Depth 4; if (-not $t -or $t -eq 'null') { '[]' } else { $t } }
        $r = @(@(& $Invoke $sql @{ CollectionId = [string]$CollectionId; ev = (& $j $ev); cv = (& $j $cv) } 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
        if ($null -ne $r) {
            $g = { param($n) $x = $r[$n]; if ($null -eq $x -or $x -is [System.DBNull]) { 0L } else { [long]$x } }
            $res.Folded = & $g 'Evidence'; $res.Findings = & $g 'Findings'; $res.Restored = & $g 'Restored'; $res.Moved = & $g 'Moved'
        }
        if ($res.Moved -gt 0 -or $res.Restored -gt 0) {
            & $Log 'OK' ('linked findings: {0:N0} finding(s) that restate another finding of the same CI are evidence on it ({1:N0} row(s) moved out of the findings this run; rules: {2}){3}' -f $res.Findings, $res.Moved, (@($rules | Where-Object { $_.Group } | ForEach-Object { $_.Group }) -join ', '), $(if ($res.Restored -gt 0) { (' -- {0:N0} row(s) are their own finding again' -f $res.Restored) } else { '' }))
        }
        return $res
    } catch {
        $res.Status = 'failed'; $res.Error = $_.Exception.Message
        & $Log 'WARN' ('linked findings: the meaning rules were not applied in the database this run -- {0}. The findings are kept as each report gives them.' -f $_.Exception.Message)
        return $res
    }
}
