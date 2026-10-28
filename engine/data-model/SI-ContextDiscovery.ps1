#Requires -Version 5.1
<#
    SecurityInsight WEEKLY CONTEXT DISCOVERY FOR RISK ANALYSIS -- the security context the sources hold is discovered and
    mapped up the chain, every week, as PROPOSALS (REQUIREMENTS #689).

    Owner 2026-10-15: "remember the output field mapper. we need to formalize this as another discovery process for risk
    analysis, where security context/columns are discovered and gets mapped up. weekly chk" / "similar to discovery in the
    data collection of new fields" / "remember each report must use si generic names from the data collection phase" /
    "si fields keeps reporting consistent ... important for cmdb and connectors integr".

    THE CHAIN it walks: SOURCE column -> provider mapping (data-model\mappings\<provider>.locked.json) -> generic si_* field
    (data-model\field-catalog.locked.json) -> OUTPUT map (data-model\outputs\*.locked.json -- the Excel sheets, the ServiceNow
    CI and vulnerable item, the SQL hand-off) -> the report rows. The collection side already keeps, per source property,
    which SI fields read it (sidata.SourceProperty, SI-SourceDiscovery.ps1, the "New context available" page). This step
    reads that and adds the Risk Analysis side:

      MAP    a source property the records carry (seen in real records) that no SI field reads, and whose name matches a
             catalog field -- the provider mapping can fill that field (a mapping row, the field exists).
      NEW    the same, with no catalog field of that name -- a NEW si_* field to propose to the owner (one list).
      CARRY  a catalog field FILLED on the CIs (fill rate > 0, read from sidata.Ci) that no output map carries -- the
             output map can carry it (a NEW column of that map; the name is checked free).
      ROUTE  an Exposure Graph edge label the graph holds that no Risk Analysis report reads -- a route candidate for a new
             attack-path report (REQUIREMENTS #691 re-checks this weekly, as Microsoft adds edges over time).
    A candidate with no valid data is not proposed (owner rule (5)): MAP / NEW need records that carried the property,
    CARRY a fill rate above zero.

    NAMES NEVER CHANGE (owner 2026-10-15: "important that we dont chg names as fx integrations, connectors will break"):
    every proposal is an ADDITION -- a new mapping row, a new field, a new output column, a new report. Nothing here ever
    proposes a rename or a removal; Test-SIContextProposalAdditive refuses any proposal that would touch an existing output
    column name or an existing field, and every proposal passes through it.

    WHEN: weekly. The Risk Analysis Detailed run calls Invoke-SIContextDiscoveryIfDue at its end (every install has that
    job, a new one and an existing one alike, so nothing has to be created by setup or the updater): at most once in six
    days, decided by the last row of sidata.ContextDiscoveryRun. Where the weekly schema job is installed it runs the same
    step on its sweep (with the edge labels it already read), and the Detailed run then finds it done.
    WHERE THE PROPOSALS SHOW: sidata.ContextProposal (one row per proposal: kind, subject, target, why, fill rate, evidence,
    first / last seen, StillSeen; Decision is the owner's -- 'proposed' until someone sets it, the engine never writes it)
    and one line in the run's log. sidata.ContextDiscoveryRun keeps one row per run.

    READ ONLY towards every source and every customer system. Never throws into a run: a part that cannot be read is said
    (and its kind is not evaluated this week, so its earlier proposals are not marked gone). PowerShell 5.1 + 7. No modules.
#>

$script:SIContextNoise = @('tenantid', 'sourcesystem', 'type', 'timegenerated', 'timestamp', 'reportid', 'id', '@odata.type', '@odata.context', 'etag')

function Test-SIContextDiscoveryOn {
    <# PURE. On by default (it reads only). -Setting (tests): off / false / 0 / no turns it off. #>
    param([AllowNull()]$Setting = $null)
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    return (-not ($s -in 'off', 'false', '0', 'no'))
}

function Get-SIContextValue {
    <# PURE. A property of a row, whatever its shape (a dictionary from a hunting answer, an object from SQL or JSON). #>
    param([AllowNull()]$Row, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return $Row[$Name] }; foreach ($k in @($Row.Keys)) { if ([string]$k -ieq $Name) { return $Row[$k] } }; return $null }
    $p = $Row.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-SIContextNorm {
    <# PURE. A name for matching: the last part of a property path, letters and digits only, lower-case ("deviceInfo.IsTransient" -> "istransient", "si_is_transient" -> "istransient"). #>
    param([AllowNull()][string]$Name)
    $n = [string]$Name
    if ($n.StartsWith('si_')) { $n = $n.Substring(3) }
    $n = ($n -replace '\[\*\]', '')
    $leaf = @($n -split '\.')[-1]
    return (($leaf -replace '[^A-Za-z0-9]', '').ToLowerInvariant())
}

function ConvertTo-SIContextPascal {
    <# PURE. An SI field as an output column name: si_end_of_support_date -> EndOfSupportDate. #>
    param([Parameter(Mandatory)][string]$Field)
    $n = $Field; if ($n.StartsWith('si_')) { $n = $n.Substring(3) }
    return ((@($n -split '_') | Where-Object { $_ } | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1) }) -join '')
}

function ConvertTo-SIContextSnake {
    <# PURE. A source property as a proposed SI field name: deviceInfo.IsTransient -> si_is_transient. #>
    param([Parameter(Mandatory)][string]$Property)
    $leaf = @(($Property -replace '\[\*\]', '') -split '\.')[-1]
    $s = [regex]::Replace($leaf, '(?<=[a-z0-9])(?=[A-Z])', '_')
    $s = ($s -replace '[^A-Za-z0-9_]', '_').ToLowerInvariant().Trim('_')
    $s = [regex]::Replace($s, '_+', '_')
    return ('si_' + $s)
}

function Get-SIContextModel {
    <#
        The chain's own files: the field catalog (name, level, classes) and every output map (its targets and the SI
        fields it reads). -Root = the SecurityInsight root. Customer overrides are not read: the proposals are about what
        SecurityInsight ships.
    #>
    param([Parameter(Mandatory)][string]$Root)
    $dm = [System.IO.Path]::Combine($Root, 'data-model')
    $cat = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($dm, 'field-catalog.locked.json')) | ConvertFrom-Json
    $fields = @(@($cat.fields) | Where-Object { $_ -and $_.name } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.name; Level = [string]$_.level; Classes = @($_.classes) } })
    $maps = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-ChildItem -LiteralPath ([System.IO.Path]::Combine($dm, 'outputs')) -Filter '*.locked.json' | Sort-Object Name)) {
        $o = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
        $targets = @(@($o.columns) | ForEach-Object { [string]$_.target } | Where-Object { $_ })
        $froms = @(@($o.columns) | ForEach-Object { [string]$_.from } | Where-Object { $_ -like 'si_*' })
        $maps.Add([pscustomobject]@{ Id = [string]$o.id; Grain = [string]$o.grain; Targets = $targets; Froms = $froms })
    }
    $yaml = ''
    $yp = [System.IO.Path]::Combine($Root, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml')
    if (Test-Path -LiteralPath $yp) { $yaml = [System.IO.File]::ReadAllText($yp) }
    [pscustomobject]@{ Fields = $fields; OutputMaps = $maps.ToArray(); ReportEdgeLabels = @(Get-SIContextReportEdgeLabels -YamlText $yaml) }
}

function Get-SIContextReportEdgeLabels {
    <# PURE. Every Exposure Graph edge label the report catalog compares EdgeLabel with (in / in~ / == / =~), lower-case. #>
    param([AllowNull()][string]$YamlText)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $code = (([string]$YamlText) -split "`r?`n" | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n"
    foreach ($m in [regex]::Matches($code, '\bEdgeLabel\s*(?:in~|in|!in~|!in)\s*\(([^)]*)\)')) {
        foreach ($v in [regex]::Matches($m.Groups[1].Value, '["'']([^"'']+)["'']')) { [void]$set.Add($v.Groups[1].Value.Trim()) }
    }
    foreach ($m in [regex]::Matches($code, '\bEdgeLabel\s*(?:==|=~)\s*["'']([^"'']+)["'']')) { [void]$set.Add($m.Groups[1].Value.Trim()) }
    return @($set | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
}

function Get-SIContextFillRateSql {
    <# PURE. How many CIs carry each SI field with a value (sidata.Ci DocJson, retired CIs left out), plus one '*' row = the CIs. #>
@'
SET NOCOUNT ON;
SELECT j.[key] AS Field, COUNT_BIG(*) AS Filled
FROM sidata.Ci c CROSS APPLY OPENJSON(c.DocJson) j
WHERE ISJSON(c.DocJson) = 1 AND ISNULL(c.Lifecycle, N'') <> N'retired'
  AND j.[type] <> 0
  AND NOT (j.[type] = 1 AND LTRIM(RTRIM(j.[value])) = N'')
  AND NOT (j.[type] IN (4, 5) AND j.[value] IN (N'[]', N'{}'))
GROUP BY j.[key]
UNION ALL
SELECT N'*', COUNT_BIG(*) FROM sidata.Ci c WHERE ISJSON(c.DocJson) = 1 AND ISNULL(c.Lifecycle, N'') <> N'retired';
'@
}

function ConvertTo-SIContextFillRates {
    <# PURE. The fill-rate rows -> @{ Total; Pct = @{ field = percent } } (null Total = not read). #>
    param([AllowNull()][object[]]$Rows)
    $pct = @{}; $total = $null
    foreach ($r in @($Rows)) { if ([string](Get-SIContextValue $r 'Field') -eq '*') { $total = [double](Get-SIContextValue $r 'Filled') } }
    if ($null -eq $total) { return @{ Total = $null; Pct = $pct } }
    foreach ($r in @($Rows)) {
        $f = [string](Get-SIContextValue $r 'Field'); if (-not $f -or $f -eq '*') { continue }
        $pct[$f] = $(if ($total -gt 0) { [math]::Round(100.0 * [double](Get-SIContextValue $r 'Filled') / $total, 1) } else { 0.0 })
    }
    @{ Total = $total; Pct = $pct }
}

function Get-SIContextSourceGapSql {
    <# PURE. The source properties the records carried that no SI field reads (the collection side's own rows, sidata.SourceProperty). #>
@'
SET NOCOUNT ON;
SELECT p.Source, p.RecordType, p.Part, p.Property, p.Records, p.SampleValue
FROM sidata.SourceProperty p
WHERE p.Records > 0 AND (p.MappedFields IS NULL OR LTRIM(RTRIM(p.MappedFields)) = N'');
'@
}

function Get-SIContextEdgeLabelKql {
    <# PURE. The Exposure Graph's edge labels with their source and target node labels and counts. #>
    'ExposureGraphEdges | summarize Edges = count() by EdgeLabel, SourceNodeLabel, TargetNodeLabel'
}

function ConvertTo-SIContextEdgeTriples {
    <# PURE. Hunting rows (EdgeLabel, SourceNodeLabel, TargetNodeLabel, Edges) -> @{ label = @( @{ Source; Edge; Target; SampleCount } ) } (the schema job's shape). #>
    param([AllowNull()][object[]]$Rows)
    $t = @{}
    foreach ($r in @($Rows)) {
        $el = [string](Get-SIContextValue $r 'EdgeLabel'); if (-not $el) { continue }
        if (-not $t.ContainsKey($el)) { $t[$el] = New-Object System.Collections.Generic.List[object] }
        $t[$el].Add(@{ Source = [string](Get-SIContextValue $r 'SourceNodeLabel'); Edge = $el; Target = [string](Get-SIContextValue $r 'TargetNodeLabel'); SampleCount = [int64](Get-SIContextValue $r 'Edges') })
    }
    $o = @{}; foreach ($k in $t.Keys) { $o[$k] = $t[$k].ToArray() }
    $o
}

function Test-SIContextProposalAdditive {
    <#
        PURE. TRUE when the proposal only ADDS: a CARRY names an output map and a column that map does not have yet (an
        empty column = the owner names it); a MAP names a field that exists (a new mapping row onto it); a NEW names a field
        that does not exist; a ROUTE names an edge label (a new report). Anything else -- a rename, a removal, a column that
        exists -- is refused (owner 2026-10-15: names never change).
    #>
    param([Parameter(Mandatory)]$Proposal, [Parameter(Mandatory)]$Model)
    $names = @{}; foreach ($f in @($Model.Fields)) { $names[[string]$f.Name] = $true }
    switch ([string]$Proposal.Kind) {
        'CARRY' {
            $parts = ([string]$Proposal.Target) -split ':', 2
            $map = @($Model.OutputMaps | Where-Object { $_.Id -eq $parts[0] })[0]
            if (-not $map -or -not $names.ContainsKey([string]$Proposal.Subject)) { return $false }
            if ($map.Froms -contains [string]$Proposal.Subject) { return $false }
            if ($parts.Count -lt 2 -or -not $parts[1]) { return $true }
            return (-not (@($map.Targets) | Where-Object { $_ -ieq $parts[1] }))
        }
        'MAP'   { return $names.ContainsKey([string]$Proposal.Target) }
        'NEW'   { return ([string]$Proposal.Target -like 'si_*' -and -not $names.ContainsKey([string]$Proposal.Target)) }
        'ROUTE' { return ([string]$Proposal.Subject).Length -gt 0 }
        default { return $false }
    }
}

function Get-SIContextProposals {
    <#
        PURE. The week's proposals. -Fill: ConvertTo-SIContextFillRates (null Total = not read -> no CARRY); -SourceGaps:
        rows of Get-SIContextSourceGapSql ($null = not read -> no MAP / NEW); -EdgeTriples: the graph's labels ($null = not
        read -> no ROUTE). Returns @{ Proposals; Kinds = the kinds evaluated }.
    #>
    param([Parameter(Mandatory)]$Model, [AllowNull()]$Fill, [AllowNull()][object[]]$SourceGaps, [AllowNull()]$EdgeTriples, [AllowNull()][hashtable]$Read)
    $out = New-Object System.Collections.Generic.List[object]
    $kinds = New-Object System.Collections.Generic.List[string]
    if (-not $Read) { $Read = @{ Fill = ($null -ne $Fill -and $null -ne $Fill.Total); Gaps = ($null -ne $SourceGaps); Edges = ($null -ne $EdgeTriples) } }
    $byNorm = @{}; foreach ($f in @($Model.Fields)) { $n = ConvertTo-SIContextNorm $f.Name; if ($n -and -not $byNorm.ContainsKey($n)) { $byNorm[$n] = $f.Name } }

    # CARRY -- a filled CI field no output map carries
    if ($Read.Fill) {
        [void]$kinds.Add('CARRY')
        $carried = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($m in @($Model.OutputMaps)) { foreach ($x in @($m.Froms)) { [void]$carried.Add($x) } }
        $detailed = @($Model.OutputMaps | Where-Object { $_.Id -eq 'excel-findings-detailed' })[0]
        foreach ($f in @($Model.Fields | Where-Object { $_.Level -in 'ci', 'both' })) {
            if ($carried.Contains($f.Name)) { continue }
            $p = $null; if ($Fill.Pct.ContainsKey($f.Name)) { $p = [double]$Fill.Pct[$f.Name] }
            if ($null -eq $p -or $p -le 0) { continue }
            $col = ConvertTo-SIContextPascal $f.Name
            $taken = $detailed -and (@($detailed.Targets) | Where-Object { $_ -ieq $col })
            $target = 'excel-findings-detailed:' + $(if ($taken) { '' } else { $col })
            $why = 'Filled on {0}% of the CIs and carried by no output -- the Detailed findings, the CMDB and the connectors could show it.' -f $p
            if ($taken) { $why += ' The column name ' + $col + ' is already used by another column, so the owner names the new one.' }
            $out.Add([pscustomobject]@{ Kind = 'CARRY'; Subject = $f.Name; Target = $target; Why = $why; FillPct = $p; Evidence = ('{0} of {1} CIs' -f [math]::Round($p * $Fill.Total / 100), $Fill.Total) })
        }
    }

    # MAP / NEW -- a property the records carry that no SI field reads
    if ($Read.Gaps) {
        [void]$kinds.Add('MAP'); [void]$kinds.Add('NEW')
        foreach ($g in @($SourceGaps)) {
            $prop = [string](Get-SIContextValue $g 'Property'); if (-not $prop) { continue }
            $leaf = @(($prop -replace '\[\*\]', '') -split '\.')[-1]
            if ($leaf.StartsWith('@') -or $script:SIContextNoise -contains $leaf.ToLowerInvariant()) { continue }
            $src = [string](Get-SIContextValue $g 'Source'); $rt = [string](Get-SIContextValue $g 'RecordType'); $part = [string](Get-SIContextValue $g 'Part')
            $subject = '{0}/{1}/{2}/{3}' -f $src, $rt, $part, $prop
            $recs = [int64](Get-SIContextValue $g 'Records')
            $sample = [string](Get-SIContextValue $g 'SampleValue'); if ($sample.Length -gt 120) { $sample = $sample.Substring(0, 120) }
            $ev = '{0} records; sample {1}' -f $recs, $sample
            $n = ConvertTo-SIContextNorm $prop
            if ($n -and $byNorm.ContainsKey($n)) {
                $out.Add([pscustomobject]@{ Kind = 'MAP'; Subject = $subject; Target = $byNorm[$n]; Why = ('The records carry it and no SI field reads it; the field {0} has its name -- one mapping row in the {1} provider mapping fills it.' -f $byNorm[$n], $src); FillPct = $null; Evidence = $ev })
            } else {
                $new = ConvertTo-SIContextSnake $prop
                $out.Add([pscustomobject]@{ Kind = 'NEW'; Subject = $subject; Target = $new; Why = 'The records carry it and no SI field reads it, and no field has its name -- a new SI field for the owner''s list (only where it helps to act on a finding).'; FillPct = $null; Evidence = $ev })
            }
        }
    }

    # ROUTE -- an edge label of the graph no report reads
    if ($Read.Edges) {
        [void]$kinds.Add('ROUTE')
        $readLabels = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($l in @($Model.ReportEdgeLabels)) { [void]$readLabels.Add($l) }
        foreach ($el in @($EdgeTriples.Keys | Sort-Object)) {
            if ($readLabels.Contains([string]$el)) { continue }
            $tr = @(@($EdgeTriples[$el]) | Sort-Object { - [int64]$_.SampleCount })
            $total = [int64](($tr | ForEach-Object { [int64]$_.SampleCount } | Measure-Object -Sum).Sum)
            if ($total -le 0) { continue }
            $ev = (@($tr | Select-Object -First 5 | ForEach-Object { '{0} -> {1} ({2})' -f $_.Source, $_.Target, $_.SampleCount }) -join '; ')
            $out.Add([pscustomobject]@{ Kind = 'ROUTE'; Subject = [string]$el; Target = ''; Why = ('The Exposure Graph holds {0} "{1}" edges and no Risk Analysis report reads them -- a candidate route for a new attack-path report (check first whether Microsoft''s own attack paths already provide it).' -f $total, $el); FillPct = $null; Evidence = $ev })
        }
    }

    # every proposal only ADDS (names never change) -- and one row per key
    $seen = @{}
    $final = New-Object System.Collections.Generic.List[object]
    foreach ($p in $out) {
        if (-not (Test-SIContextProposalAdditive -Proposal $p -Model $Model)) { continue }
        $key = ('{0}|{1}' -f $p.Kind, $p.Subject); if ($key.Length -gt 400) { $key = $key.Substring(0, 400) }
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $p | Add-Member -NotePropertyName Key -NotePropertyValue $key -Force
        $final.Add($p)
    }
    @{ Proposals = $final.ToArray(); Kinds = $kinds.ToArray() }
}

function Get-SIContextDueSql { "SET NOCOUNT ON; SELECT CONVERT(NVARCHAR(30), MAX(RunAt), 126) AS LastRunAt FROM sidata.ContextDiscoveryRun;" }

function Test-SIContextDiscoveryDue {
    <# At most once in -Days (6) days. No table or no answer = not due (the step says why elsewhere; it never guesses). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$Now = [datetime]::UtcNow, [int]$Days = 6)
    $rows = @(& $Invoke (Get-SIContextDueSql) @{} 'rows')
    $last = [string](Get-SIContextValue $rows[0] 'LastRunAt')
    if ([string]::IsNullOrWhiteSpace($last)) { return $true }
    $t = [datetime]::MinValue
    if (-not [datetime]::TryParse($last, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$t)) { return $true }
    return (($Now.ToUniversalTime() - $t).TotalDays -ge $Days)
}

function Get-SIContextProposalWriteSql {
    <#
        PURE. ONE write: the week's proposals upserted by key (Kind, Subject, Target, Why, fill rate, evidence; FirstSeen kept),
        the evaluated kinds' proposals NOT found this week marked StillSeen = 0 (never deleted), and the run's own row.
        Decision is the owner's and is never written here. Parameters: @rows (JSON), @kinds (JSON), @runId, @at, @fill, @edges, @note.
    #>
@'
SET NOCOUNT ON;
DECLARE @now DATETIME2(0) = ISNULL(TRY_CONVERT(DATETIME2(0), @at, 126), SYSUTCDATETIME());
DECLARE @r TABLE (ProposalKey NVARCHAR(400) NOT NULL PRIMARY KEY, Kind NVARCHAR(16) NOT NULL, Subject NVARCHAR(300) NOT NULL, Target NVARCHAR(300) NULL,
                  Why NVARCHAR(1000) NULL, FillPct DECIMAL(5,1) NULL, Evidence NVARCHAR(1000) NULL);
INSERT @r (ProposalKey, Kind, Subject, Target, Why, FillPct, Evidence)
SELECT LEFT(j.k, 400), LEFT(j.kind, 16), LEFT(j.subject, 300), LEFT(j.target, 300), LEFT(j.why, 1000), TRY_CONVERT(DECIMAL(5,1), j.fill), LEFT(j.evidence, 1000)
FROM OPENJSON(@rows) WITH (k NVARCHAR(400) '$.Key', kind NVARCHAR(16) '$.Kind', subject NVARCHAR(300) '$.Subject', target NVARCHAR(300) '$.Target',
                          why NVARCHAR(1000) '$.Why', fill NVARCHAR(16) '$.FillPct', evidence NVARCHAR(1000) '$.Evidence') j
WHERE j.k IS NOT NULL AND j.kind IS NOT NULL AND j.subject IS NOT NULL;
DECLARE @new INT = (SELECT COUNT(*) FROM @r r WHERE NOT EXISTS (SELECT 1 FROM sidata.ContextProposal p WHERE p.ProposalKey = r.ProposalKey));
UPDATE p SET p.Target = r.Target, p.Why = r.Why, p.FillPct = r.FillPct, p.Evidence = r.Evidence, p.StillSeen = 1, p.LastSeen = @now, p.RunId = @runId
FROM sidata.ContextProposal p JOIN @r r ON r.ProposalKey = p.ProposalKey;
INSERT sidata.ContextProposal (ProposalKey, Kind, Subject, Target, Why, FillPct, Evidence, StillSeen, FirstSeen, LastSeen, RunId)
SELECT r.ProposalKey, r.Kind, r.Subject, r.Target, r.Why, r.FillPct, r.Evidence, 1, @now, @now, @runId
FROM @r r WHERE NOT EXISTS (SELECT 1 FROM sidata.ContextProposal p WHERE p.ProposalKey = r.ProposalKey);
UPDATE sidata.ContextProposal SET StillSeen = 0
WHERE StillSeen = 1 AND RunId <> @runId AND Kind IN (SELECT CONVERT(NVARCHAR(16), [value]) FROM OPENJSON(@kinds));
INSERT sidata.ContextDiscoveryRun (RunId, RunAt, Proposals, NewProposals, FillRateRead, EdgesRead, Note)
VALUES (LEFT(@runId, 64), @now, (SELECT COUNT(*) FROM @r), @new, TRY_CONVERT(BIT, @fill), TRY_CONVERT(BIT, @edges), LEFT(@note, 1000));
SELECT (SELECT COUNT(*) FROM @r) AS Proposals, @new AS NewProposals;
'@
}

function Invoke-SIContextDiscovery {
    <#
        The step. Reads the chain's files, the CIs' fill rates and the collection side's unread properties (the database,
        -Invoke: param($Sql, $Params, $Mode)), the graph's edge labels (-EdgeTriples from the schema job, else -Hunting:
        param($Kql) -> rows), builds the proposals and writes them in one statement. Returns @{ Written; Proposals; New;
        ByKind; Lines; Reason }. Never throws.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [AllowNull()][scriptblock]$Invoke, [AllowNull()][scriptblock]$Hunting, [AllowNull()]$EdgeTriples,
          [string]$RunId = '', [datetime]$Now = [datetime]::UtcNow)
    $lines = New-Object System.Collections.Generic.List[string]
    $res = @{ Written = $false; Proposals = 0; New = 0; ByKind = @{}; Lines = $lines; Reason = '' }
    try {
        if (-not $RunId) { $RunId = 'context-' + $Now.ToUniversalTime().ToString('yyyyMMddHHmmss') }
        $model = Get-SIContextModel -Root $SIRoot
        $fill = $null; $gaps = $null
        if ($Invoke) {
            try { $fill = ConvertTo-SIContextFillRates -Rows @(& $Invoke (Get-SIContextFillRateSql) @{} 'rows') } catch { $lines.Add('The fill rates of the CIs could not be read this week -- ' + $_.Exception.Message) }
            try { $gaps = @(& $Invoke (Get-SIContextSourceGapSql) @{} 'rows') } catch { $gaps = $null; $lines.Add('The source properties no SI field reads could not be read this week -- ' + $_.Exception.Message) }
        } else { $lines.Add('No database is configured: the fill rates and the source properties are not read.') }
        if ($null -eq $EdgeTriples -and $Hunting) {
            try { $EdgeTriples = ConvertTo-SIContextEdgeTriples -Rows @(& $Hunting (Get-SIContextEdgeLabelKql)) } catch { $EdgeTriples = $null; $lines.Add('The Exposure Graph''s edge labels could not be read this week -- ' + $_.Exception.Message) }
        }
        $p = Get-SIContextProposals -Model $model -Fill $fill -SourceGaps $gaps -EdgeTriples $EdgeTriples
        foreach ($k in 'CARRY', 'MAP', 'NEW', 'ROUTE') { $res.ByKind[$k] = @($p.Proposals | Where-Object { $_.Kind -eq $k }).Count }
        $res.Proposals = @($p.Proposals).Count
        if (-not $Invoke) { $res.Reason = 'no database'; return $res }
        $json = ConvertTo-Json -InputObject @($p.Proposals | Select-Object Key, Kind, Subject, Target, Why, @{ n = 'FillPct'; e = { if ($null -ne $_.FillPct) { ([double]$_.FillPct).ToString([System.Globalization.CultureInfo]::InvariantCulture) } else { $null } } }, Evidence) -Depth 4 -Compress
        if (@($p.Proposals).Count -eq 0) { $json = '[]' }
        $kindsJson = ConvertTo-Json -InputObject @($p.Kinds) -Compress; if (@($p.Kinds).Count -eq 0) { $kindsJson = '[]' }
        $params = @{ rows = $json; kinds = $kindsJson; runId = $RunId; at = $Now.ToUniversalTime().ToString('s'); fill = $(if ($null -ne $fill -and $null -ne $fill.Total) { '1' } else { '0' })
                     edges = $(if ($null -ne $EdgeTriples) { '1' } else { '0' }); note = (@($lines) -join ' | ') }
        $ans = @(& $Invoke (Get-SIContextProposalWriteSql) $params 'rows')
        $res.Written = $true
        $res.New = [int](Get-SIContextValue $ans[0] 'NewProposals')
    } catch { $res.Reason = $_.Exception.Message }
    return $res
}

function Get-SIContextDiscoverySummaryText {
    <# PURE. One plain line for the run's log. #>
    param([Parameter(Mandatory)]$Result)
    $k = $Result.ByKind
    $counts = '{0} to carry to an output, {1} to map, {2} new fields, {3} new routes' -f [int]$k['CARRY'], [int]$k['MAP'], [int]$k['NEW'], [int]$k['ROUTE']
    if (-not $Result.Written) { return ('Weekly context discovery: {0} proposals ({1}) -- not saved: {2}.' -f [int]$Result.Proposals, $counts, [string]$Result.Reason) }
    ('Weekly context discovery: {0} proposals ({1}), {2} new this week -- saved for review (additions only; no output name changes).' -f [int]$Result.Proposals, $counts, [int]$Result.New)
}

function Invoke-SIContextDiscoveryIfDue {
    <#
        The Risk Analysis Detailed run's call: at most once in six days, the step above. -Invoke defaults to the install's
        database (SI_ProSqlServer / SI_ProSqlDatabase, else the Pro data database). Never throws, never fails the run.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [AllowNull()][scriptblock]$Invoke, [AllowNull()][scriptblock]$Hunting, [datetime]$Now = [datetime]::UtcNow,
          [AllowNull()]$Setting = $null, [scriptblock]$Log)
    try {
        if (-not (Test-SIContextDiscoveryOn -Setting $Setting)) { return $null }
        if (-not $Invoke) {
            $dm = [System.IO.Path]::Combine($SIRoot, 'engine', 'data-model')
            if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($dm, 'SI-RecordSql.ps1')) }
            if (-not (Get-Command -Name Get-SIObjectLedgerConnection -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($dm, 'identity', 'SI-ObjectLedgerStore.ps1')) }
            $srv = [string]$global:SI_ProSqlServer; $db = [string]$global:SI_ProSqlDatabase
            if (-not $srv -or -not $db) { $srv = [string]$global:SI_Pro_DataSqlServer; $db = [string]$global:SI_Pro_DataSqlDatabase }
            $Invoke = New-SIRecordSqlInvoke -Server $srv -Database $db
        }
        if (-not $Invoke) { return $null }
        if (-not (Test-SIContextDiscoveryDue -Invoke $Invoke -Now $Now)) { return $null }
        $r = Invoke-SIContextDiscovery -SIRoot $SIRoot -Invoke $Invoke -Hunting $Hunting -Now $Now
        if ($Log) { & $Log 'INFO' (Get-SIContextDiscoverySummaryText -Result $r); foreach ($l in @($r.Lines)) { & $Log 'INFO' $l } }
        return $r
    } catch { if ($Log) { & $Log 'INFO' ('The weekly context discovery was not run -- ' + $_.Exception.Message) }; return $null }
}
