#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE DUPLICATE CHECK IN THE DATA SYNC (REQUIREMENTS #1365, #693 (6) / (9), #688; the design principle
    #1366). After the findings per CI (sidata.CiFinding) and the remediation tasks (sidata.RemediationTask) are written, it
    counts what is still TWO where the merge rules make ONE -- and says it. It WARNS, it never blocks (owner: a field problem
    never blocks), it never changes a finding or a task.

    THE FINDINGS (the rules of engine\data-model\SI-DuplicateCheck.ps1 -- fold:<group> / key / link / same-cve -- worked out by
    the SAME pure function the release gate runs, Find-SIDuplicateFindings, over the stored findings):
      1. CANDIDATES, set-based, a range of CIs per statement (keyset on the clustered CiId): the CIs that hold a finding a fold
         rule's evidence side may meet (its conditions on the stored columns -- finding type, title, key, severity -- an exact
         value or a pattern's literal start; the other conditions are not narrowed: a superset), two findings of one
         equivalence group or one manual link, or one CVE in two findings. Nothing else of a CI is read.
      2. THE FACTS a published finding's document may not carry (the findings made from the database, #774, carry no
         si_affected_product): for the candidate CIs only, ONE pass over the collection's sidata.Finding rows in FindingId
         ranges (its clustered key) into the work table sidata.DuplicateCheckWork -- the stored column of each si field a rule
         reads (si_affected_product -> AffectedProduct, ...). Only when a rule reads such a field.
      3. PER PAGE OF CANDIDATE CIs: every finding of those CIs with the si fields the rules read (the document first, then the
         fact), through Find-SIDuplicateFindings. Memory = one page.
    THE TASKS (task-update-restates-software, one set-based statement over the newest built collection): an OPEN task that is
      not a software / security update and is named "Update <software>" on a CI that has an open software / security update
      task for that software (its product, or the affected product of one of its findings) -- e.g. "Update openssl" next to
      "Update GitHub Desktop (bundles openssl 3.5.5.0)".
    WHAT IS WRITTEN: sidata.DuplicateCheck, one row per run x rule (counts, CIs, up to SI_Pro_DuplicateExamples examples, 10),
      kept 90 days; the work rows of a run are removed when it ends (a left-over row is removed after a day). The counts are
      the data-quality key numbers 'dup.*' (kind dup: stored with the run for the trend, never compared), the WARN line of
      the run log, and a WARNING of the run (counts only).
    No PowerShell module: every statement through the data sync's SQL seam (-Invoke sql params mode). PowerShell 5.1 and 7.
#>

$script:SIDupRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not (Get-Command -Name Find-SIDuplicateFindings -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($script:SIDupRoot, 'data-model', 'SI-DuplicateCheck.ps1')) }

function Get-SIDupColumns {
    <# PURE. The si fields that are a column of sidata.CiFinding (c) -> the column. #>
    [ordered]@{ si_finding_type = 'c.FindingType'; si_title = 'c.Title'; si_finding_key = 'c.FindingKey'; si_severity = 'c.Severity' }
}

function Get-SIDupFactColumns {
    <# PURE. The si fields a published finding's document may lack -> their stored column on sidata.Finding (f). #>
    [ordered]@{
        si_affected_product = 'f.AffectedProduct'; si_affected_vendor = 'f.AffectedVendor'; si_affected_version = 'f.AffectedVersion'
        si_cve = 'f.Cve'; si_component = 'f.Component'; si_category = 'f.Category'; si_subcategory = 'f.Subcategory'
        si_fix_recommended_update = 'f.FixRecommendedUpdate'; si_fix_recommended_update_id = 'f.FixRecommendedUpdateId'; si_report_name = 'f.ReportName'
    }
}

function Get-SIDupNormSql {
    <# PURE. A text as the merge rules compare it, in T-SQL: lower case, trimmed, tabs / line breaks / underscores a space,
       runs of spaces one (up to 16). The finding fold's ConvertTo-SIFindingMatchValue does the same in PowerShell. #>
    param([Parameter(Mandatory)][string]$Expr)
    "LOWER(LTRIM(RTRIM(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(ISNULL($Expr, N''), NCHAR(9), N' '), NCHAR(10), N' '), NCHAR(13), N' '), N'_', N' '), N'        ', N' '), N'    ', N' '), N'  ', N' '), N'  ', N' '))))"
}

function ConvertTo-SIDupSqlText {
    <# PURE. A value as a T-SQL N'' literal. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    "N'" + ([string]$Value).Replace("'", "''") + "'"
}

function Get-SIDupPatternPrefix {
    <# PURE. The literal start of a pattern anchored with ^ (lower case), '' when it has none -- a LIKE '<prefix>%' that every
       value the pattern accepts passes (case-insensitively): letters, digits, spaces, - and : only, up to the first other
       character; a character a quantifier follows is left out. #>
    param([string]$Pattern)
    if (-not $Pattern -or -not $Pattern.StartsWith('^')) { return '' }
    $sb = New-Object System.Text.StringBuilder
    $p = $Pattern.Substring(1)
    for ($i = 0; $i -lt $p.Length; $i++) {
        $ch = $p[$i]
        if ($ch -match '[A-Za-z0-9 :\-]') {
            if ($i + 1 -lt $p.Length -and $p[$i + 1] -match '[\?\*\{]') { break }
            [void]$sb.Append($ch)
        } else { break }
    }
    $sb.ToString().ToLowerInvariant()
}

function Get-SIDupFoldPrefilterSql {
    <#
        PURE. The candidate test of the fold rules' evidence sides over a finding row c (OR over the rules; '1 = 0' when there is
        none): per rule the AND of its conditions on a stored COLUMN (equals: the normalised column; pattern: its literal start);
        a condition on any other field is not narrowed here (the page read decides).
    #>
    param([object[]]$Folds = @())
    $ors = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Folds)) {
        # #1369 a rule that joins two findings on the SAME stored column (e.g. si_title = si_title) is narrowed by that value
        # instead (Get-SIDupFoldSameOnSql): its evidence side alone would make nearly every CI a candidate
        if (Get-SIDupFoldSameOnField -Rule $r) { continue }
        $ands = Get-SIDupConditionSql -Conditions @($r.Evidence)
        if ($ands) { $ors.Add('(' + $ands + ')') } else { $ors.Add('1 = 1') }
    }
    if ($ors.Count -eq 0) { return '1 = 0' }
    '(' + ($ors -join ' OR ') + ')'
}

function Get-SIDupConditionSql {
    <# PURE. The AND of a rule side's conditions on a stored COLUMN of a finding row c (equals: the normalised column; pattern:
       its literal start); '' when none of them is on a column (not narrowed). #>
    param([object[]]$Conditions = @())
    $cols = Get-SIDupColumns
    $ands = New-Object System.Collections.Generic.List[string]
    foreach ($c in @($Conditions)) {
        if ($null -eq $c -or -not $cols.Contains([string]$c.Field)) { continue }
        $col = $cols[[string]$c.Field]
        if ($null -ne $c.Regex) {
            $px = Get-SIDupPatternPrefix ([string]$c.Regex.ToString())
            if ($px) { $ands.Add(("LOWER(LTRIM({0})) LIKE {1}" -f $col, (ConvertTo-SIDupSqlText (($px -replace '([\[%_])', '[$1]') + '%')))) }
        } else {
            $ands.Add(("{0} = {1}" -f (Get-SIDupNormSql $col), (ConvertTo-SIDupSqlText ([string]$c.EqualsValue))))
        }
    }
    $ands -join ' AND '
}

function Get-SIDupFoldSameOnField {
    <# PURE. #1369 the si field a fold rule joins its two sides on when both sides name the SAME stored column (an 'on' pair
       { evidence: si_title, canonical: si_title }); '' when it has none. #>
    param($Rule)
    $cols = Get-SIDupColumns
    foreach ($p in @($Rule.On)) {
        if ($null -eq $p) { continue }
        $e = [string]$p.Evidence
        if ($e -and $e -eq [string]$p.Canonical -and $cols.Contains($e)) { return $e }
    }
    ''
}

function Get-SIDupFoldSameOnSql {
    <#
        PURE. #1369 the candidate test of the fold rules that join on one stored column (Get-SIDupFoldSameOnField), over the
        candidate statement's rows: @{ Columns = the extra columns of #r (S0, S1 ... = the normalised value of a row that may
        be on either side, else NULL); Selects = per rule, the owners with two findings (two keys) of the same value }. A
        superset of what the rule folds (either side, any value shared) -- the page read decides; nothing when there is none.
    #>
    param([object[]]$Folds = @())
    $cols = Get-SIDupColumns
    $c = New-Object System.Collections.Generic.List[string]; $s = New-Object System.Collections.Generic.List[string]
    $i = 0
    foreach ($r in @($Folds)) {
        $f = Get-SIDupFoldSameOnField -Rule $r
        if (-not $f) { continue }
        $ev = Get-SIDupConditionSql -Conditions @($r.Evidence); $cv = Get-SIDupConditionSql -Conditions @($r.Canonical)
        $side = $(if ($ev -and $cv) { "($ev) OR ($cv)" } else { '1 = 1' })
        $c.Add(("CASE WHEN {0} THEN {1} END AS S{2}" -f $side, (Get-SIDupNormSql $cols[$f]), $i))
        $s.Add(("SELECT r.Owner FROM #r AS r WHERE r.S{0} IS NOT NULL AND r.S{0} <> N'' GROUP BY r.Owner, r.S{0} HAVING COUNT(DISTINCT r.FindingKey) > 1" -f $i))
        $i++
    }
    @{ Columns = $c.ToArray(); Selects = $s.ToArray() }
}

function Get-SIDupMembers {
    <# PURE. The equivalence's key members and manual links as rows the candidate statement joins: @{ k = id | title | link;
       o = owner (links); v = the key / the title key; g = the group }. #>
    param($Index)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Index) { return @() }
    foreach ($k in @($Index.ById.Keys)) { $out.Add([ordered]@{ k = 'id'; o = ''; v = [string]$k; g = [string]$Index.ById[$k].Group }) }
    foreach ($k in @($Index.ByTitle.Keys)) { $out.Add([ordered]@{ k = 'title'; o = ''; v = [string]$k; g = [string]$Index.ByTitle[$k].Group }) }
    if ($Index.ByOwner) {
        foreach ($k in @($Index.ByOwner.Keys)) { $i = ([string]$k).IndexOf('|'); if ($i -lt 1) { continue }
            $out.Add([ordered]@{ k = 'link'; o = ([string]$k).Substring(0, $i); v = ([string]$k).Substring($i + 1); g = [string]$Index.ByOwner[$k].Group }) }
    }
    $out.ToArray()
}

function Get-SIDupFields {
    <# PURE. The si fields the page read returns: the ones every rule needs and every field the fold rules name. #>
    param([object[]]$Folds = @())
    $f = New-Object System.Collections.Generic.List[string]
    foreach ($n in 'si_cve', 'si_report_name', 'si_detected_by') { $f.Add($n) }
    foreach ($r in @($Folds)) {
        foreach ($c in @($r.Evidence) + @($r.Canonical)) { $x = [string]$c.Field; if ($x -match '^si_[a-z0-9_]+$' -and -not $f.Contains($x)) { $f.Add($x) } }
        foreach ($p in @($r.On)) { foreach ($x in @([string]$p.Evidence, [string]$p.Canonical)) { if ($x -match '^si_[a-z0-9_]+$' -and -not $f.Contains($x)) { $f.Add($x) } } }
    }
    @($f | Where-Object { -not (Get-SIDupColumns).Contains($_) })
}

function Get-SIDuplicateCheckSql {
    <#
        PURE. The statements. -Part:
          schema      1 when the tables are there (sidata.CiFinding, sidata.DuplicateCheck, sidata.DuplicateCheckWork)
          collection  the collection the published findings are of (@cid) and the time; the newest built task collection
          upper       the last CI id of the next range (@After, @Take CIs)
          candidates  the candidate owners of one range (@After / @Upper; -AssetBlock: the findings no CI holds); @Members JSON
          stage       the owners of a run into the work table (@Check, @Owners JSON)
          bounds      the FindingId range of the collection (@cid)
          facts       one FindingId range (@Lo / @Hi) of facts for the staged owners (-FactFields)
          page        every finding of a page of owners (@Owners JSON) with -Fields (-Facts: the work table's facts)
          tasks       the task rule over the newest built collection (@Take examples)
          store       one row per rule (@j JSON)
          clear       the run's work rows, and work rows a run left behind a day ago
          retention   the rows of sidata.DuplicateCheck older than 90 days
    #>
    param([Parameter(Mandatory)][ValidateSet('schema', 'collection', 'upper', 'candidates', 'stage', 'bounds', 'facts', 'page', 'tasks', 'store', 'clear', 'retention')][string]$Part,
          [string]$FoldFilter = '1 = 0', $SameOn = $null, [switch]$AssetBlock, [string[]]$Fields = @(), [string[]]$FactFields = @(), [switch]$Facts,
          # the page read of the read-only diagnostics: these fields' facts from #fx, a temporary table of the same batch
          [string[]]$InlineFacts = @(),
          # schema: the read-only diagnostics need only the findings (they write no table of the check)
          [switch]$ReadOnlyCheck)
    $norm = { param($e) Get-SIDupNormSql $e }
    switch ($Part) {
        'schema' { if ($ReadOnlyCheck) { return "SELECT CASE WHEN OBJECT_ID('sidata.CiFinding') IS NOT NULL THEN 1 ELSE 0 END" }; return "SELECT CASE WHEN OBJECT_ID('sidata.CiFinding') IS NOT NULL AND OBJECT_ID('sidata.DuplicateCheck') IS NOT NULL AND OBJECT_ID('sidata.DuplicateCheckWork') IS NOT NULL THEN 1 ELSE 0 END" }
        'collection' {
            return @'
SET NOCOUNT ON;
DECLARE @ct DATETIME2(3) = (SELECT MAX(CollectionTime) FROM sidata.CiFinding);
SELECT CONVERT(nvarchar(30), @ct, 126) AS CollectionTime,
       (SELECT TOP (1) c.CollectionId FROM sidata.Collection AS c WHERE c.Kind = N'Detailed' AND c.CollectionTime = @ct ORDER BY c.CollectionId DESC) AS CollectionId,
       CASE WHEN COL_LENGTH('sidata.Collection', 'RemediationTasksAt') IS NOT NULL AND OBJECT_ID('sidata.RemediationTask') IS NOT NULL THEN 1 ELSE 0 END AS HasTasks,
       (SELECT COUNT_BIG(*) FROM sidata.CiFinding) AS Findings;
'@
        }
        'upper' {
            return @'
SET NOCOUNT ON;
DECLARE @a NVARCHAR(64) = @After;
SELECT MAX(x.CiId) FROM (SELECT DISTINCT TOP (CONVERT(int, @Take)) f.CiId FROM sidata.CiFinding AS f WHERE f.CiId > @a ORDER BY f.CiId) AS x;
'@
        }
        'candidates' {
            $range = $(if ($AssetBlock) { 'f.CiId IS NULL' } else { 'f.CiId > @a AND f.CiId <= @u' })
            $text = @'
SET NOCOUNT ON;
DECLARE @a NVARCHAR(64) = @After, @u NVARCHAR(64) = @Upper;
DECLARE @m TABLE (K NVARCHAR(8) NOT NULL, O NVARCHAR(450) NULL, V NVARCHAR(1000) NOT NULL, G NVARCHAR(200) NOT NULL);
INSERT @m SELECT k, o, v, g FROM OPENJSON(@Members) WITH (k nvarchar(8), o nvarchar(450), v nvarchar(1000), g nvarchar(200));
IF OBJECT_ID('tempdb..#r') IS NOT NULL DROP TABLE #r;
SELECT CASE WHEN f.CiId IS NULL THEN N'asset:' + ISNULL(f.AssetId, N'') ELSE f.CiId END AS Owner, f.FindingKey, {TITLE} AS TitleKey,
       CASE WHEN {FOLD} THEN 1 ELSE 0 END AS FoldHit,{SAMECOLS}
       CASE WHEN f.FindingKey LIKE N'CVE-[0-9][0-9][0-9][0-9]-%' THEN UPPER(f.FindingKey)
            WHEN ISJSON(f.DocJson) = 1 THEN UPPER(JSON_VALUE(f.DocJson, N'$.si_cve')) END AS Cve
INTO #r
FROM sidata.CiFinding AS f
WHERE {RANGE};
SELECT DISTINCT x.Owner FROM (
    SELECT r.Owner FROM #r AS r WHERE r.FoldHit = 1{SAMESEL}
    UNION ALL
    SELECT y.Owner FROM (
        SELECT r.Owner, m.G, r.FindingKey FROM #r AS r JOIN @m AS m ON m.K = N'id' AND r.FindingKey = m.V
        UNION ALL SELECT r.Owner, m.G, r.FindingKey FROM #r AS r JOIN @m AS m ON m.K = N'title' AND r.TitleKey = m.V
        UNION ALL SELECT r.Owner, m.G, r.FindingKey FROM #r AS r JOIN @m AS m ON m.K = N'link' AND r.Owner = m.O AND r.FindingKey = m.V
    ) AS y GROUP BY y.Owner, y.G HAVING COUNT(DISTINCT y.FindingKey) > 1
    UNION ALL
    SELECT r.Owner FROM #r AS r WHERE r.Cve LIKE N'CVE-%' GROUP BY r.Owner, r.Cve HAVING COUNT(DISTINCT r.FindingKey) > 1
) AS x;
DROP TABLE #r;
'@
            # the title as the equivalence keys it (lower case, spaces made one): the same normalisation without the underscores
            $title = "LOWER(LTRIM(RTRIM(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(ISNULL(f.Title, N''), NCHAR(9), N' '), NCHAR(10), N' '), NCHAR(13), N' '), N'        ', N' '), N'    ', N' '), N'  ', N' '), N'  ', N' '))))"
            # #1369 the rules that join on one stored column: the owners with two findings of the same value
            $sc = ''; $ss = ''
            if ($null -ne $SameOn -and @($SameOn.Columns).Count) {
                $sc = (@($SameOn.Columns | ForEach-Object { "`n       " + ($_ -replace '\bc\.', 'f.') + ',' }) -join '')
                $ss = (@($SameOn.Selects | ForEach-Object { "`n    UNION ALL`n    " + $_ }) -join '')
            }
            return $text.Replace('{RANGE}', $range).Replace('{FOLD}', ($FoldFilter -replace '\bc\.', 'f.')).Replace('{TITLE}', $title).Replace('{SAMECOLS}', $sc).Replace('{SAMESEL}', $ss)
        }
        'stage' {
            return @'
SET NOCOUNT ON;
INSERT sidata.DuplicateCheckWork (CheckId, Kind, KeyHash, Owner)
SELECT DISTINCT CONVERT(uniqueidentifier, @Check), 0, HASHBYTES('SHA2_256', CONVERT(nvarchar(450), j.[value])), CONVERT(nvarchar(450), j.[value])
FROM OPENJSON(@Owners) AS j
WHERE NOT EXISTS (SELECT 1 FROM sidata.DuplicateCheckWork AS w WHERE w.CheckId = CONVERT(uniqueidentifier, @Check) AND w.Kind = 0
                  AND w.KeyHash = HASHBYTES('SHA2_256', CONVERT(nvarchar(450), j.[value])));
'@
        }
        'bounds' { return "SET NOCOUNT ON; SELECT MIN(FindingId) AS Lo, MAX(FindingId) AS Hi FROM sidata.Finding WHERE CollectionId = CONVERT(int, @cid);" }
        'facts' {
            $fc = Get-SIDupFactColumns
            $agg = @(for ($i = 0; $i -lt $FactFields.Count; $i++) { "MAX(CONVERT(nvarchar(4000), {0})) AS F{1}" -f $fc[$FactFields[$i]], $i })
            $js = @(for ($i = 0; $i -lt $FactFields.Count; $i++) { "g.F{0} AS [{1}]" -f $i, $FactFields[$i] })
            return @"
SET NOCOUNT ON;
DECLARE @id UNIQUEIDENTIFIER = CONVERT(uniqueidentifier, @Check), @c INT = CONVERT(int, @cid), @rlo BIGINT = CONVERT(bigint, @Lo), @rhi BIGINT = CONVERT(bigint, @Hi);
INSERT sidata.DuplicateCheckWork (CheckId, Kind, KeyHash, Owner, FieldsJson)
SELECT @id, 1, g.H, g.Owner, (SELECT $($js -join ', ') FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM (SELECT HASHBYTES('SHA2_256', o.Owner + N'|' + o.KeyPart) AS H, MAX(o.Owner) AS Owner, $($agg -join ', ')
      FROM sidata.Finding AS f
      CROSS APPLY (SELECT CHARINDEX(N'|', f.RaFindingKey) AS P) AS sp
      CROSS APPLY (SELECT CONVERT(nvarchar(450), LEFT(f.RaFindingKey, sp.P - 1)) AS Owner, LOWER(SUBSTRING(f.RaFindingKey, sp.P + 1, 900)) AS KeyPart) AS o
      JOIN sidata.DuplicateCheckWork AS w ON w.CheckId = @id AND w.Kind = 0 AND w.KeyHash = HASHBYTES('SHA2_256', o.Owner)
      WHERE f.CollectionId = @c AND f.FindingId BETWEEN @rlo AND @rhi AND f.RaFindingKey IS NOT NULL AND sp.P > 1
      GROUP BY HASHBYTES('SHA2_256', o.Owner + N'|' + o.KeyPart)) AS g
-- one-statement-ok: one FindingId key range per command (BETWEEN @rlo AND @rhi), the caller walks the ranges
WHERE NOT EXISTS (SELECT 1 FROM sidata.DuplicateCheckWork AS x WHERE x.CheckId = @id AND x.Kind = 1 AND x.KeyHash = g.H);
"@
        }
        'page' {
            $cols = Get-SIDupColumns
            $sel = New-Object System.Collections.Generic.List[string]
            foreach ($f in @($Fields | Where-Object { $_ -match '^si_[a-z0-9_]+$' } | Select-Object -Unique)) {
                $parts = New-Object System.Collections.Generic.List[string]
                $parts.Add("CASE WHEN ISJSON(c.DocJson) = 1 THEN COALESCE(JSON_QUERY(c.DocJson, N'`$.$f'), JSON_VALUE(c.DocJson, N'`$.$f')) END")
                if ($Facts) { $parts.Add("CASE WHEN ISJSON(x.FieldsJson) = 1 THEN JSON_VALUE(x.FieldsJson, N'`$.$f') END") }
                elseif ($InlineFacts -contains $f) { $parts.Add("(SELECT TOP (1) z.[$f] FROM #fx AS z WHERE z.Owner = w.Owner AND z.KeyPart = LOWER(c.FindingKey))") }
                if ($parts.Count -eq 1) { $sel.Add(("{0} AS [{1}]" -f $parts[0], $f)) } else { $sel.Add(("COALESCE({0}) AS [{1}]" -f ($parts -join ', '), $f)) }
            }
            $extra = $(if ($sel.Count) { ",`n       " + ($sel -join ",`n       ") } else { '' })
            $join = $(if ($Facts) { "LEFT JOIN sidata.DuplicateCheckWork AS x ON x.CheckId = CONVERT(uniqueidentifier, @Check) AND x.Kind = 1 AND x.KeyHash = HASHBYTES('SHA2_256', w.Owner + N'|' + LOWER(c.FindingKey))" } else { '' })
            $body = @"
SELECT w.Owner, c.CiId, c.AssetId, c.FindingKey, c.FindingType, c.Title, c.Severity, ci.Name AS CiName,
       CASE WHEN ISJSON(c.DocJson) = 1 AND EXISTS (SELECT 1 FROM OPENJSON(JSON_QUERY(c.DocJson, N'`$.si_finding_evidence')) WITH (r nvarchar(200) N'`$.rule') AS e WHERE e.r IS NOT NULL) THEN 1 ELSE 0 END AS FoldTarget$extra
FROM @o AS w
JOIN sidata.CiFinding AS c ON {OWNER}
LEFT JOIN sidata.Ci AS ci ON ci.CiId = c.CiId
$join
WHERE {SIDE}
"@
            $a = $body.Replace('{OWNER}', 'c.CiId = w.Owner').Replace('{SIDE}', "w.Owner NOT LIKE N'asset:%'")
            $b = $body.Replace('{OWNER}', "c.CiId IS NULL AND c.AssetId = SUBSTRING(w.Owner, 7, 400)").Replace('{SIDE}', "w.Owner LIKE N'asset:%'")
            return "SET NOCOUNT ON;`nDECLARE @o TABLE (Owner NVARCHAR(450) NOT NULL PRIMARY KEY);`nINSERT @o SELECT DISTINCT CONVERT(nvarchar(450), [value]) FROM OPENJSON(@Owners);`n$a`nUNION ALL`n$b;"
        }
        'tasks' {
            $sw = "N'security-update', N'software-upgrade', N'bundled-upgrade'"
            return (@'
SET NOCOUNT ON;
DECLARE @c INT = (SELECT TOP (1) CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND RemediationTasksAt IS NOT NULL ORDER BY CollectionTime DESC);
IF OBJECT_ID('tempdb..#d') IS NOT NULL DROP TABLE #d;
CREATE TABLE #d (OwnerKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL, AssetName NVARCHAR(400) NULL, TaskName NVARCHAR(MAX) NULL, Software NVARCHAR(4000) NULL, OntoName NVARCHAR(MAX) NULL, N INT NOT NULL);
IF @c IS NOT NULL
INSERT #d
SELECT t.OwnerKey, t.AssetName, t.TaskName, sw.Software, d.OntoName, d.N
FROM sidata.RemediationTask AS t
CROSS APPLY (SELECT {NORM_SW} AS Software) AS sw
CROSS APPLY (SELECT COUNT(*) AS N, MIN(t2.TaskName) AS OntoName
             FROM sidata.RemediationTask AS t2
             WHERE t2.CollectionId = @c AND t2.OwnerKey = t.OwnerKey AND t2.State = N'open' AND t2.TaskId <> t.TaskId AND t2.Kind IN ({SW})
               AND ({NORM_P} = sw.Software
                    OR EXISTS (SELECT 1 FROM sidata.RemediationTaskFinding AS l
                               JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId
                               CROSS APPLY STRING_SPLIT(ISNULL(f.AffectedProduct, N''), N';') AS s
                               WHERE l.CollectionId = @c AND l.TaskId = t2.TaskId AND {NORM_S} = sw.Software))) AS d
WHERE t.CollectionId = @c AND t.State = N'open' AND t.Kind NOT IN ({SW}) AND LOWER(LTRIM(t.TaskName)) LIKE N'update %'
  AND LEN(LTRIM(t.TaskName)) > 7 AND d.N > 0;
SELECT @c AS CollectionId, (SELECT COUNT(*) FROM #d) AS Duplicates, (SELECT COUNT(DISTINCT OwnerKey) FROM #d) AS Owners,
       (SELECT TOP (CONVERT(int, @Take)) d.OwnerKey AS o, d.AssetName AS n, d.TaskName AS t, d.OntoName AS x, d.N AS c, d.Software AS v FROM #d AS d ORDER BY d.AssetName, d.TaskName FOR JSON PATH) AS Examples;
DROP TABLE #d;
'@).Replace('{SW}', $sw).Replace('{NORM_SW}', (& $norm 'SUBSTRING(LTRIM(t.TaskName), 8, 4000)')).Replace('{NORM_P}', (& $norm 't2.Product')).Replace('{NORM_S}', (& $norm 's.[value]'))
        }
        'store' {
            return @'
SET NOCOUNT ON;
INSERT sidata.DuplicateCheck (CheckId, CheckedAt, CollectionTime, RuleId, RuleKind, Label, Duplicates, Owners, Status, ExamplesJson)
SELECT CONVERT(uniqueidentifier, @Check), SYSUTCDATETIME(), TRY_CONVERT(datetime2(3), @ct, 126), r, k, l, d, o, s, x
FROM OPENJSON(@j) WITH (r nvarchar(200), k nvarchar(16), l nvarchar(400), d int, o int, s nvarchar(16), x nvarchar(max) AS JSON);
'@
        }
        'clear' { return "SET NOCOUNT ON; DELETE FROM sidata.DuplicateCheckWork WHERE CheckId = CONVERT(uniqueidentifier, @Check) OR CreatedAt < DATEADD(day, -1, SYSUTCDATETIME());" }
        'retention' { return "SET NOCOUNT ON; DELETE FROM sidata.DuplicateCheck WHERE CheckedAt < DATEADD(day, -90, SYSUTCDATETIME());" }
    }
}

function Get-SIDupRowValue {
    <# PURE. A reader row's value (dictionary, data row or object); DBNull = $null. #>
    param($Row, [string]$Name)
    Get-SIDuplicateValue $Row $Name
}

function ConvertTo-SIDupFinding {
    <# PURE. One page row -> the SI finding Find-SIDuplicateFindings reads (a JSON list as a list; an affected value 'a;b' split). #>
    param($Row, [string[]]$Fields = @())
    $o = [ordered]@{
        si_ci_id = [string](Get-SIDupRowValue $Row 'CiId'); si_asset_id = [string](Get-SIDupRowValue $Row 'AssetId')
        si_finding_key = [string](Get-SIDupRowValue $Row 'FindingKey'); si_finding_type = [string](Get-SIDupRowValue $Row 'FindingType')
        si_title = [string](Get-SIDupRowValue $Row 'Title'); si_severity = [string](Get-SIDupRowValue $Row 'Severity')
        _ci_name = [string](Get-SIDupRowValue $Row 'CiName'); _si_fold_target = ([int](Get-SIDupRowValue $Row 'FoldTarget') -eq 1)
    }
    foreach ($f in @($Fields)) {
        $v = Get-SIDupRowValue $Row $f
        if ($v -is [string]) {
            $t = $v.Trim()
            if ($t.StartsWith('[')) { try { $v = @(($t | ConvertFrom-Json) | ForEach-Object { $_ }) } catch { } }
            elseif ($f -like 'si_affected_*' -and $t.Contains(';')) { $v = @($t.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        }
        $o[$f] = $v
    }
    [pscustomobject]$o
}

function Get-SIDuplicateExampleCount {
    <# The examples kept per rule (SI_Pro_DuplicateExamples, default 10, at least 1). #>
    $n = 10
    $sv = Get-Variable -Name SI_Pro_DuplicateExamples -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    $x = 0; if ($null -ne $sv -and [int]::TryParse([string]$sv, [ref]$x) -and $x -ge 1) { $n = $x }
    $n
}

function Get-SIDuplicateCheckSummary {
    <#
        PURE. The run's result from the duplicates found (-Items: Find-SIDuplicateFindings' items) and the task rule's row
        (-Tasks: @{ Duplicates; Owners; Examples }): @{ Rules (one per rule that was checked: Id, Kind, Label, Duplicates,
        Owners, Examples); Total; Lines; Issue; Metrics (dup.* kind dup) }. -Checked: the rules checked (a rule checked with
        nothing found is 0, never missing).
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), $Tasks, [string[]]$Checked = @(), [int]$Examples = 10)
    $rules = [ordered]@{}
    foreach ($r in @($Checked)) { $rules[$r] = $null }
    foreach ($i in @($Items)) { if (-not $rules.Contains([string]$i.Rule)) { $rules[[string]$i.Rule] = $null } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rules.Keys)) {
        $its = @($Items | Where-Object { [string]$_.Rule -eq $r })
        $kind = $(if ($its.Count) { [string]$its[0].Kind } elseif ($r -like 'fold:*') { 'fold' } elseif ($r -eq 'same-cve') { 'cve' } else { $r })
        $ex = @($its | Sort-Object CiName, Owner, Title | Select-Object -First $Examples | ForEach-Object {
                [ordered]@{ ci = $(if ($_.CiName) { $_.CiName } else { $_.Owner }); owner = $_.Owner; key = $_.Key; title = $_.Title; report = $_.Report; ontoKey = $_.OntoKey; ontoTitle = $_.OntoTitle; onto = $_.Onto; value = $_.Value; text = (Format-SIDuplicateExample $_) } })
        $out.Add([pscustomobject][ordered]@{ Id = $r; Kind = $kind; Label = (Get-SIDuplicateRuleLabel $r); Duplicates = $its.Count
            Owners = @($its | ForEach-Object { $_.Owner } | Select-Object -Unique).Count; Examples = $ex })
    }
    if ($null -ne $Tasks) {
        $tx = @(@($Tasks.Examples) | Where-Object { $null -ne $_ } | Select-Object -First $Examples | ForEach-Object {
                $n = [string](Get-SIDuplicateValue $_ 'n'); if (-not $n) { $n = [string](Get-SIDuplicateValue $_ 'o') }
                $c = [int](Get-SIDuplicateValue $_ 'c')
                [ordered]@{ ci = $n; owner = [string](Get-SIDuplicateValue $_ 'o'); title = [string](Get-SIDuplicateValue $_ 't'); ontoTitle = [string](Get-SIDuplicateValue $_ 'x'); onto = $c; value = [string](Get-SIDuplicateValue $_ 'v')
                    text = ("{0}: '{1}' next to '{2}'{3}" -f $n, [string](Get-SIDuplicateValue $_ 't'), [string](Get-SIDuplicateValue $_ 'x'), $(if ($c -gt 1) { ' (+{0} more)' -f ($c - 1) } else { '' })) } })
        $out.Add([pscustomobject][ordered]@{ Id = 'task-update-restates-software'; Kind = 'task'; Label = (Get-SIDuplicateRuleLabel 'task-update-restates-software')
            Duplicates = [int]$Tasks.Duplicates; Owners = [int]$Tasks.Owners; Examples = $tx })
    }
    $total = (@($out | ForEach-Object { [int]$_.Duplicates }) | Measure-Object -Sum).Sum
    $hit = @($out | Where-Object { $_.Duplicates -gt 0 })
    $lines = New-Object System.Collections.Generic.List[string]
    if ($hit.Count) {
        foreach ($r in $hit) {
            $e = @($r.Examples | Select-Object -First 3 | ForEach-Object { $_.text })
            $lines.Add(("duplicates  : {0} duplicate(s) on {1} asset(s) were not merged -- rule {2}: {3}; e.g. {4}" -f $r.Duplicates, $r.Owners, $r.Id, $r.Label.Replace('Duplicates not merged: ', ''), ($e -join ' | ')))
        }
    }
    $issue = ''
    if ($total -gt 0) {
        $issue = ('{0} duplicate finding(s) / task(s) were not merged although the merge rules make them one ({1}) -- a data-quality defect; nothing was blocked' -f [long]$total,
            ((@($hit | ForEach-Object { '{0} {1}' -f $_.Id, $_.Duplicates })) -join ', '))
    }
    $metrics = @($out | ForEach-Object { [pscustomobject]@{ Key = (Get-SIDuplicateMetricKey $_.Id); Kind = 'dup'; Label = $_.Label; Value = [double]$_.Duplicates; Step = 'data-sync' } })
    [pscustomobject]@{ Rules = $out.ToArray(); Total = [long]$total; Lines = $lines.ToArray(); Issue = $issue; Metrics = $metrics }
}

function Invoke-SIDataDuplicateCheck {
    <#
    .SYNOPSIS  The duplicate check over the published findings and the newest built tasks (see the file header). Never throws:
               a failure is one WARN line and Status 'failed'. -ReadOnly (the diagnostics script): writes nothing -- the facts
               are read per page in the page's own statement instead of the work table, and nothing is stored.
    .PARAMETER Index        the equivalence index (default: the run's merged template, Get-SIRecommendationEquivalence)
    .PARAMETER CisPerRange  CIs per candidate statement (default 2000)
    .PARAMETER OwnersPerPage candidate CIs per page read (default 200)
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [switch]$ReadOnly, [scriptblock]$Log, $Index,
          [int]$CisPerRange = 2000, [int]$OwnersPerPage = 200, [long]$FindingIdsPerRange = 500000, [switch]$NoStore)
    if (-not $Log) { $Log = { param($l, $m) Write-Host ('[{0}] {1}' -f $l, $m) } }
    $check = [guid]::NewGuid().ToString()
    $staged = $false
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $one = { param($sql, $p, $mode) @(@(& $Invoke $sql $p $mode) | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    try {
        if (([int](& $Invoke (Get-SIDuplicateCheckSql -Part 'schema' -ReadOnlyCheck:$ReadOnly) @{} 'scalar')) -ne 1) {
            & $Log 'INFO' 'duplicates  : the database does not have the duplicate check''s tables yet (the updater adds them) -- not checked this run.'
            return [pscustomobject]@{ Status = 'no-schema' }
        }
        $idx = $Index
        if ($null -eq $idx) { $idx = Get-SIRecommendationEquivalence }
        $folds = @(); if ($null -ne $idx -and $idx.Folds) { $folds = @($idx.Folds) }
        $col = (& $one (Get-SIDuplicateCheckSql -Part 'collection') @{} 'reader') | Select-Object -First 1
        $ctText = [string](Get-SIDupRowValue $col 'CollectionTime'); $cid = Get-SIDupRowValue $col 'CollectionId'; $hasTasks = ([int](Get-SIDupRowValue $col 'HasTasks') -eq 1)
        $members = @(Get-SIDupMembers -Index $idx)
        $mj = ConvertTo-Json -InputObject @($members) -Compress -Depth 3; if (-not $mj -or $mj -eq 'null') { $mj = '[]' }
        $filter = Get-SIDupFoldPrefilterSql -Folds $folds
        $sameOn = Get-SIDupFoldSameOnSql -Folds $folds
        $fields = @(Get-SIDupFields -Folds $folds)
        $factFields = @($fields | Where-Object { (Get-SIDupFactColumns).Contains($_) })
        $checked = New-Object System.Collections.Generic.List[string]
        foreach ($r in $folds) { $checked.Add('fold:' + [string]$r.Group) }
        if (@($idx.ById.Keys).Count -or @($idx.ByTitle.Keys).Count) { $checked.Add('key') }
        if ($idx.ByOwner -and @($idx.ByOwner.Keys).Count) { $checked.Add('link') }
        $checked.Add('same-cve')
        # 1. the candidate CIs, a range at a time (then the findings no CI holds)
        $owners = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        $after = ''; $ranges = 0
        while ($true) {
            $upper = & $Invoke (Get-SIDuplicateCheckSql -Part 'upper') @{ After = $after; Take = [string]$CisPerRange } 'scalar'
            if ($null -eq $upper -or $upper -is [System.DBNull] -or -not [string]$upper) { break }
            $ranges++
            foreach ($r in (& $one (Get-SIDuplicateCheckSql -Part 'candidates' -FoldFilter $filter -SameOn $sameOn) @{ After = $after; Upper = [string]$upper; Members = $mj } 'reader')) { $o = [string](Get-SIDupRowValue $r 'Owner'); if ($o -and $seen.Add($o)) { $owners.Add($o) } }
            $after = [string]$upper
        }
        foreach ($r in (& $one (Get-SIDuplicateCheckSql -Part 'candidates' -FoldFilter $filter -SameOn $sameOn -AssetBlock) @{ After = ''; Upper = ''; Members = $mj } 'reader')) { $o = [string](Get-SIDupRowValue $r 'Owner'); if ($o -and $seen.Add($o)) { $owners.Add($o) } }
        $candSec = $clock.Elapsed.TotalSeconds
        # 2. the facts of the candidate CIs (one pass over the collection's rows), unless read-only
        $useFacts = ($factFields.Count -gt 0 -and $null -ne $cid -and $owners.Count -gt 0 -and -not $ReadOnly -and -not $DryRun)
        if ($useFacts) {
            $staged = $true
            for ($i = 0; $i -lt $owners.Count; $i += 1000) {
                $chunk = $owners.GetRange($i, [Math]::Min(1000, $owners.Count - $i)).ToArray()
                $null = & $Invoke (Get-SIDuplicateCheckSql -Part 'stage') @{ Check = $check; Owners = (ConvertTo-Json -InputObject @($chunk) -Compress) } 'nonquery'
            }
            $b = (& $one (Get-SIDuplicateCheckSql -Part 'bounds') @{ cid = [string]$cid } 'reader') | Select-Object -First 1
            $lo = Get-SIDupRowValue $b 'Lo'; $hi = Get-SIDupRowValue $b 'Hi'
            if ($null -ne $lo -and $null -ne $hi) {
                for ($x = [long]$lo; $x -le [long]$hi; $x += $FindingIdsPerRange) {
                    $null = & $Invoke (Get-SIDuplicateCheckSql -Part 'facts' -FactFields $factFields) @{ Check = $check; cid = [string]$cid; Lo = [string]$x; Hi = [string]([long]$x + $FindingIdsPerRange - 1) } 'nonquery'
                }
            }
        }
        $factSec = $clock.Elapsed.TotalSeconds
        # 3. every finding of a page of candidate CIs, through the pure detector
        $items = New-Object System.Collections.Generic.List[object]
        $pageSql = $(if ($ReadOnly -and $factFields.Count -and $null -ne $cid) { Get-SIDuplicateCheckReadOnlyPageSql -Fields $fields -FactFields $factFields } else { Get-SIDuplicateCheckSql -Part 'page' -Fields $fields -Facts:$useFacts })
        for ($i = 0; $i -lt $owners.Count; $i += $OwnersPerPage) {
            $chunk = $owners.GetRange($i, [Math]::Min($OwnersPerPage, $owners.Count - $i)).ToArray()
            $rows = & $one $pageSql @{ Check = $check; cid = [string]$cid; Owners = (ConvertTo-Json -InputObject @($chunk) -Compress) } 'reader'
            $page = @($rows | ForEach-Object { ConvertTo-SIDupFinding -Row $_ -Fields $fields })
            foreach ($d in @(Find-SIDuplicateFindings -Findings $page -Index $idx)) { $items.Add($d) }
        }
        # the tasks
        $tasks = $null
        if ($hasTasks) {
            $tr = (& $one (Get-SIDuplicateCheckSql -Part 'tasks') @{ Take = [string](Get-SIDuplicateExampleCount) } 'reader') | Select-Object -First 1
            $tex = @(); $tj = [string](Get-SIDupRowValue $tr 'Examples'); if ($tj) { try { $tex = @($tj | ConvertFrom-Json) } catch { $tex = @() } }
            $tasks = [pscustomobject]@{ Duplicates = [int](Get-SIDupRowValue $tr 'Duplicates'); Owners = [int](Get-SIDupRowValue $tr 'Owners'); Examples = $tex }
        }
        $sum = Get-SIDuplicateCheckSummary -Items $items.ToArray() -Tasks $tasks -Checked $checked.ToArray() -Examples (Get-SIDuplicateExampleCount)
        $res = [pscustomobject][ordered]@{ Status = 'ok'; CheckId = $check; CollectionTime = $ctText; Candidates = $owners.Count; Ranges = $ranges; Rules = $sum.Rules
            Total = $sum.Total; Lines = $sum.Lines; Issue = $sum.Issue; Metrics = $sum.Metrics; Items = $items.ToArray()
            Seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1); Phases = ('candidates={0:N1} s; facts={1:N1} s; pages={2:N1} s' -f $candSec, ($factSec - $candSec), ($clock.Elapsed.TotalSeconds - $factSec)) }
        if (-not $ReadOnly -and -not $DryRun -and -not $NoStore) {
            $rj = ConvertTo-Json -Compress -Depth 6 -InputObject @(@($sum.Rules) | ForEach-Object { [ordered]@{ r = $_.Id; k = $_.Kind; l = $_.Label; d = [int]$_.Duplicates; o = [int]$_.Owners; s = 'ok'; x = @($_.Examples) } })
            $null = & $Invoke (Get-SIDuplicateCheckSql -Part 'store') @{ Check = $check; ct = $ctText; j = $rj } 'nonquery'
            $null = & $Invoke (Get-SIDuplicateCheckSql -Part 'retention') @{} 'nonquery'
        }
        if ($sum.Total -gt 0) { foreach ($l in $sum.Lines) { & $Log 'WARN' $l } }
        else { & $Log 'OK' ('duplicates  : no duplicate finding or task that the merge rules make one -- {0} rule(s) checked over {1} candidate asset(s) ({2} s)' -f (@($sum.Rules).Count), $owners.Count, $res.Seconds) }
        return $res
    } catch {
        & $Log 'WARN' ('duplicates  : the duplicate check was not completed this run -- {0}. Nothing was blocked; it runs again on the next run.' -f $_.Exception.Message)
        return [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message; Metrics = @(); Issue = '' }
    } finally {
        if ($staged) { try { $null = & $Invoke (Get-SIDuplicateCheckSql -Part 'clear') @{ Check = $check } 'nonquery' } catch { } }
    }
}

function Get-SIDuplicateCheckReadOnlyPageSql {
    <# PURE. The page read without the work table (the read-only diagnostics): the facts of the page's CIs are read in the same
       statement (one pass over the collection's rows per page -- fine for a diagnostic run, never the nightly path). #>
    param([string[]]$Fields = @(), [string[]]$FactFields = @())
    $fc = Get-SIDupFactColumns
    $agg = @(for ($i = 0; $i -lt $FactFields.Count; $i++) { "MAX(CONVERT(nvarchar(4000), {0})) AS [{1}]" -f $fc[$FactFields[$i]], $FactFields[$i] })
    $page = Get-SIDuplicateCheckSql -Part 'page' -Fields $Fields -InlineFacts $FactFields
    $fx = @"
IF OBJECT_ID('tempdb..#fx') IS NOT NULL DROP TABLE #fx;
SELECT o.Owner, o.KeyPart, $($agg -join ', ')
INTO #fx
FROM sidata.Finding AS f
CROSS APPLY (SELECT CHARINDEX(N'|', f.RaFindingKey) AS P) AS sp
CROSS APPLY (SELECT CONVERT(nvarchar(450), LEFT(f.RaFindingKey, sp.P - 1)) AS Owner, CONVERT(nvarchar(900), LOWER(SUBSTRING(f.RaFindingKey, sp.P + 1, 900))) AS KeyPart) AS o
WHERE f.CollectionId = CONVERT(int, @cid) AND f.RaFindingKey IS NOT NULL AND sp.P > 1 AND o.Owner IN (SELECT Owner FROM @o)
GROUP BY o.Owner, o.KeyPart;
"@
    $page.Replace("INSERT @o SELECT DISTINCT CONVERT(nvarchar(450), [value]) FROM OPENJSON(@Owners);", ("INSERT @o SELECT DISTINCT CONVERT(nvarchar(450), [value]) FROM OPENJSON(@Owners);`n" + $fx))
}
