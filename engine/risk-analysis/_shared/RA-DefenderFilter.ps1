#Requires -Version 5.1
<#
    #673 PLAN B FOR THE AZURE RECOMMENDATION REPORTS -- THE DEFENDER DE-DUPLICATION MOVES OUT OF THE HUNTING QUERY.

    Azure_Recommendations_Summary / _Detailed drop every (resource, recommendation) the Defender recommendation reports
    already carry (#147 / #200 / #349): three `join kind=leftanti (_dfcPairs)` on three pair keys. _dfcPairs is read from
    SI's own workspace and has no key the query slices are cut on, so it travels whole (or, since 2026-10-13, cut to the
    keys each slice can match) in every request to Microsoft Defender -- and grows with the size of the Defender list.

    Between the CI join and the final summarize / project, every step of those queries is a per-row extend / where /
    mv-apply or a leftouter join on a unique key (_subTierG by subscription). So the three anti-joins are a pure row
    filter: removing the rows at the END gives the same rows as removing them where they are. Plan B:
      * the YAML keeps the anti-joins between //__SI_DFC_ANTIJOIN_BEGIN__ / _END__ markers (pasted into Log Analytics the
        query still de-duplicates on its own);
      * with SI_RA_DefenderFilterInEngine on, the engine cuts them out, empties the hand-off lookup (nothing of the
        Defender list travels with the query any more), and adds the three keys (+ the asset, for Summary) to the final
        summarize-by and project (ConvertTo-RADefenderFilterQuery);
      * the Defender list is loaded ONCE PER RUN into SQL (sidata.RaDefenderKey, keyed by run, one BIGINT per key -- the
        first 8 bytes of the SHA-256 of the pair text, see below) from SI's own workspace over the Log Analytics API, in pages -- the same in the
        three set-ups (Defender XDR only / + Sentinel / + Sentinel data lake);
      * every answer is filtered against it IN SQL (Get-RADefenderKeyMatches: the answer's distinct keys go in, the ones
        on the list come back), the keys are taken off, and a Summary answer's partial groups are combined with the
        existing merge, its plan built from the ORIGINAL query text;
      * completeness: the rows retrieved BEFORE the filter are counted, and the rows the filter removed are a named
        category, "handed to the Defender recommendation report" (Add-RADfcAccount, Get-RAStoredVerdict -Handed).
    SI_RA_DefenderFilterCompare on runs BOTH paths for every answer and writes a comparison (Detailed rows exact; Summary
    groups equal after lists are compared as sets; rows removed per key kind) -- for the live side by side on internal.
    SI_RA_DefenderFilterInEngine is ON by default since rc2 (owner 2026-10-16: "we need all out now"; not set = on, 'off'
    turns it off -- Test-RADefenderFilterInEngineOn); SI_RA_DefenderFilterCompare stays OFF by default.
    REMOVE-ME: the settings, once plan B has held live and the query's own anti-joins can go.

    🔴 THE KEYS ARE SHA-256, NOT KQL hash() (2026-10-16, after build 1938 on internal: Azure_Recommendations_Detailed 51 ->
    865 rows, _Summary 29 -> 439 -- plan B handed 13 rows where plan A's anti-joins remove ~830). Plan A compares
    hash(text) of the row with hash(text) of the Defender list INSIDE ONE QUERY (on the data lake route the list is read in
    the same query; on the advanced hunting route it is a string list inlined into that query). Plan B kept hash() numbers
    from a SEPARATE Log Analytics query in SQL and compared them with the hunting query's hash() -- and KQL's hash() is
    documented as guaranteed the same only WITHIN a single query (the algorithm may differ between engines / versions; the
    documentation says to use hash_sha256() for values kept outside the query). Now both sides key the SAME pair texts with
    hash_sha256 (a defined algorithm over the UTF-8 text -- the bucketing already relies on KQL and .NET agreeing on it):
    the cut query's three key columns become "x" + the first 16 hex digits of hash_sha256(<the text plan A hashes>), the
    list's query returns the same 16 hex digits of the same texts, and both read as one signed 64-bit number. Two rows /
    list entries then match exactly when their texts are equal -- plan A's rule. A key the engine cannot read ends the
    answer as not complete (never a silent "no match").

    PowerShell 5.1-safe: no ternary, no null-conditional.
#>

$script:RADfcKeyColumns  = @('_dfcKey', '_dfcIdKey', '_dfcAkKey')
$script:RADfcPartColumn  = '_dfcPart'
$script:RADfcBegin       = '//__SI_DFC_ANTIJOIN_BEGIN__'
$script:RADfcEnd         = '//__SI_DFC_ANTIJOIN_END__'
$script:RADfcLast        = $null      # the numbers of the last answer the filter handled (Add-RADfcAccount books them)
$script:RADfcSet         = $null      # the run's Defender list in SQL: @{ RunKey; Keys; Verdict }
$script:RADfcCompare     = $null      # SI_RA_DefenderFilterCompare: report -> totals
$script:RADfcSetFailed   = $null      # #742: the producer's load of the list failed -- the reason, for the workers' reports
$script:RADfcWorker      = $false     # #742: this process is a queue worker -- it uses the producer's list, never loads one

function Test-RADefenderFilterSetting {
    <# PURE. A REMOVE-ME switch read as on / off; anything but on / true / 1 / yes is off. #>
    param([AllowNull()][object]$Value)
    return (([string]$Value).Trim().ToLowerInvariant() -in 'on', 'true', '1', 'yes')
}

function Test-RADefenderFilterInEngineOn {
    <# PURE. Plan B (SI_RA_DefenderFilterInEngine) is ON BY DEFAULT since rc2 (owner 2026-10-16: "we need all out now"):
       not set (or blank) = on; set = read as on / off (Test-RADefenderFilterSetting) -- 'off' turns it off for an install
       (a custom value, or the job's SI_CFG_SI_RA_DefenderFilterInEngine). #>
    param([AllowNull()][object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $true }
    return (Test-RADefenderFilterSetting $Value)
}

function ConvertFrom-RADfcHex {
    <# PURE. 16 hex digits (the first 8 bytes of a SHA-256) -> the signed 64-bit number they are (two's complement);
       anything else -> $null. #>
    param([AllowNull()][object]$Hex)
    $s = [string]$Hex
    if ($s -notmatch '^[0-9a-fA-F]{16}$') { return $null }
    return [Convert]::ToInt64($s, 16)
}

function Get-RADfcTextKey {
    <# PURE. The key of one pair text, as KQL `tolower(substring(hash_sha256(<text>), 0, 16))` gives it, read as a signed
       64-bit number: the first 8 bytes of SHA-256 over the UTF-8 text. The reference both sides are proven against. #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$Text)) } finally { $sha.Dispose() }
    $sb = New-Object System.Text.StringBuilder 16
    for ($i = 0; $i -lt 8; $i++) { [void]$sb.Append($h[$i].ToString('x2')) }
    return (ConvertFrom-RADfcHex -Hex $sb.ToString())
}

function Get-RADfcPageRange {
    <# PURE. Part -Page of -Pages of the Defender list, cut on the key itself: the range of its first 4 hex digits
       (0000-ffff, SHA-256 spreads them evenly). @{ Lo; Hi } -- Hi $null on the last part. Every key is in exactly one part. #>
    param([int]$Pages = 1, [int]$Page = 0)
    $p = [Math]::Min(65536, [Math]::Max(1, $Pages)); $i = [Math]::Min($p - 1, [Math]::Max(0, $Page))
    $lo = [int][Math]::Floor($i * 65536.0 / $p)
    $hi = $null; if ($i -lt $p - 1) { $hi = ([int][Math]::Floor(($i + 1) * 65536.0 / $p)).ToString('x4') }
    return @{ Lo = $lo.ToString('x4'); Hi = $hi }
}

function ConvertTo-RADfcShaKeyQuery {
    <#
        PURE. The three key columns of the cut query keyed with hash_sha256 instead of hash(): in every
        `| extend _dfcKey|_dfcIdKey|_dfcAkKey = ...` the expression `strcat("h", tostring(hash(<text>)))` becomes
        `strcat("x", tolower(substring(hash_sha256(<text>), 0, 16)))` -- the SAME <text>, so a key still stands for exactly
        the pair plan A compares. Nothing in a comment or a string is touched. Returns @{ Query; Count; Names }; the caller
        applies the cut only when all three keys were converted once each.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $masked = Get-RAKqlMaskedText -Query $Query
    $rx = [regex]'strcat\(\s*"h"\s*,\s*tostring\(\s*hash\('
    $edits = New-Object System.Collections.Generic.List[object]
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($m in $rx.Matches($Query)) {
        if ($masked[$m.Index] -cne 's') { continue }                       # inside a comment or a string
        $ls = $Query.LastIndexOf("`n", $m.Index) + 1
        $lm = [regex]::Match($masked.Substring($ls, $m.Index - $ls), '^\s*\|\s*extend\s+(?<k>_dfcKey|_dfcIdKey|_dfcAkKey)\s*=')
        if (-not $lm.Success) { continue }
        $open = $m.Index + $m.Length - 1                                    # the "(" of hash(
        $depth = 0; $close = -1
        for ($i = $open; $i -lt $masked.Length; $i++) {
            $c = $masked[$i]
            if ($c -eq '(') { $depth++ } elseif ($c -eq ')') { $depth--; if ($depth -eq 0) { $close = $i; break } }
        }
        if ($close -lt 0) { return @{ Query = $Query; Count = 0; Names = @() } }
        $j = $close + 1
        for ($k = 0; $k -lt 2; $k++) {                                     # the ")" of tostring( and of strcat(
            while ($j -lt $masked.Length -and [char]::IsWhiteSpace($masked[$j])) { $j++ }
            if ($j -ge $masked.Length -or $masked[$j] -ne ')') { return @{ Query = $Query; Count = 0; Names = @() } }
            $j++
        }
        $inner = $Query.Substring($open + 1, $close - $open - 1)
        $edits.Add(@{ At = $m.Index; Len = ($j - $m.Index); Text = ('strcat("x", tolower(substring(hash_sha256({0}), 0, 16)))' -f $inner) })
        $names.Add($lm.Groups['k'].Value)
    }
    $q = $Query
    foreach ($e in @($edits | Sort-Object { [int]$_.At } -Descending)) { $q = $q.Remove([int]$e.At, [int]$e.Len).Insert([int]$e.At, [string]$e.Text) }
    return @{ Query = $q; Count = $edits.Count; Names = $names.ToArray() }
}

function Get-RAKqlMaskedText {
    <# PURE. The query with every // comment and string literal replaced by spaces of the SAME length, so positions in
       it are positions in the query -- what the scanner below reads (a "|" or "(" inside a comment or a string is not one). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    # ONE pass, whichever starts first: a comment, a "..." or a '...' literal (so @'"id"...' is one literal, and the "//"
    # of a URL inside a literal is not a comment). No match crosses a line break, so nothing moves.
    $blank = { param($m) ' ' * $m.Value.Length }
    $rx = '//[^\r\n]*|@?"(?:[^"\\\r\n]|\\.)*"|' + "@?'(?:[^'\\\r\n]|\\.)*'"
    return [regex]::Replace($Query, $rx, $blank)
}

function Get-RAKqlTopLevelOperators {
    <# PURE. Every top-level pipe after -From in the masked text: @{ At (index of the '|'); Op (the operator word,
       e.g. 'summarize', 'project', 'project-away'); End (index where its segment ends: the next top-level '|' or ';'
       or the end) }. Depth counts () and []. #>
    param([Parameter(Mandatory)][string]$Masked, [int]$From = 0)
    $out = New-Object System.Collections.Generic.List[object]
    $depth = 0; $cur = $null
    for ($i = $From; $i -lt $Masked.Length; $i++) {
        $ch = $Masked[$i]
        if ($ch -eq '(' -or $ch -eq '[') { $depth++; continue }
        if ($ch -eq ')' -or $ch -eq ']') { $depth--; continue }
        if ($depth -ne 0) { continue }
        if ($ch -eq '|' -or $ch -eq ';') {
            if ($null -ne $cur) { $cur.End = $i; $out.Add($cur); $cur = $null }
            if ($ch -eq ';') { continue }
            $m = [regex]::Match($Masked.Substring($i + 1), '^\s*([A-Za-z][A-Za-z0-9_-]*)')
            $cur = @{ At = $i; Op = $(if ($m.Success) { $m.Groups[1].Value.ToLowerInvariant() } else { '' }); End = $Masked.Length }
        }
    }
    if ($null -ne $cur) { $cur.End = $Masked.Length; $out.Add($cur) }
    return , $out.ToArray()
}

function ConvertTo-RADefenderFilterQuery {
    <#
        PURE. The hunting query of plan B from a report query: the anti-join blocks cut out, the hand-off lookup emptied,
        the cut point of the per-slice lookup reduction taken out (nothing of the list travels any more), and the keys
        added to the FINAL summarize-by (Summary: the three keys and the asset, so a partial group never spans two
        slices) and to the FINAL project. Returns @{ Applied; Query; Grain ('Summary' | 'Detailed'); Reason }.
        Not applied (the query is used as it is) when the markers are not there, the hand-off is not active (#278: the
        receiving report is not in the run -- nothing is handed off, nothing is filtered), or the query does not have the
        shape the cut needs. Never a comment inside an argument list: the keys are added after the last item.
        The three key columns are keyed with hash_sha256 of the texts plan A hashes (ConvertTo-RADfcShaKeyQuery); a query
        whose keys cannot all be converted is not cut.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $no = { param($why) @{ Applied = $false; Query = $Query; Grain = ''; Reason = $why } }
    if ([string]::IsNullOrEmpty($Query) -or $Query.IndexOf($script:RADfcBegin) -lt 0) { return (& $no 'the query has no Defender anti-join markers') }
    if ($null -eq (Get-RAHandoffLookupBinding -Query $Query)) { return (& $no 'the hand-off is not active in this run (the Defender recommendation report is not in it)') }
    $rx = '(?ms)^[ \t]*' + [regex]::Escape($script:RADfcBegin) + '.*?' + [regex]::Escape($script:RADfcEnd) + '[ \t]*\r?\n?'
    $ms = [regex]::Matches($Query, $rx)
    if ($ms.Count -ne 3) { return (& $no ('the query has {0} Defender anti-join block(s), not 3' -f $ms.Count)) }
    $cutAt = $ms[0].Index
    $q = [regex]::Replace($Query, $rx, '')
    if ((Get-RAKqlMaskedText -Query $q) -match '\(\s*_dfcPairs\s*\)') { return (& $no 'the query still joins the hand-off lookup outside the markers') }

    $masked = Get-RAKqlMaskedText -Query $q
    $opsRaw = Get-RAKqlTopLevelOperators -Masked $masked -From $cutAt    # (one array, assigned: @() around the call would nest it)
    $ops = @($opsRaw)
    # a completeness count appended to the report's query (`| count`, or `| project SIGroupHash = ... | distinct SIGroupHash`)
    # is not the report's: the keys go into the report's own final summarize / project, before it
    $suffixAt = $masked.Length
    if ($ops.Count -gt 0 -and $ops[$ops.Count - 1].Op -eq 'count') { $suffixAt = $ops[$ops.Count - 1].At }
    elseif ($ops.Count -gt 1 -and $ops[$ops.Count - 1].Op -eq 'distinct' -and $ops[$ops.Count - 2].Op -eq 'project' -and
            $masked.Substring($ops[$ops.Count - 2].At, $ops[$ops.Count - 2].End - $ops[$ops.Count - 2].At) -match '\bSIGroupHash\b') { $suffixAt = $ops[$ops.Count - 2].At }
    $ops = @($ops | Where-Object { $_.At -lt $suffixAt })
    $sum = @($ops | Where-Object { $_.Op -eq 'summarize' }) | Select-Object -Last 1
    $prj = @($ops | Where-Object { $_.Op -eq 'project' }) | Select-Object -Last 1
    if ($null -eq $prj) { return (& $no 'the query has no final project after the anti-joins') }
    if ($null -ne $sum -and $prj.At -lt $sum.At) { return (& $no 'the final project comes before the final summarize') }
    $edits = New-Object System.Collections.Generic.List[object]
    $keys = ($script:RADfcKeyColumns -join ', ')
    $grain = 'Detailed'
    if ($null -ne $sum) {
        $seg = $masked.Substring($sum.At, $sum.End - $sum.At)
        $byM = [regex]::Matches($seg, '\bby\b')
        if ($byM.Count -eq 0) { return (& $no 'the final summarize has no by clause') }
        $grain = 'Summary'
        $last = $sum.At + $seg.TrimEnd().Length
        $edits.Add(@{ At = $last; Text = (', ' + $keys + ', ' + $script:RADfcPartColumn + ' = tostring(DeviceKey)') })
    }
    $pseg = $masked.Substring($prj.At, $prj.End - $prj.At)
    $pcols = $keys; if ($grain -eq 'Summary') { $pcols = $keys + ', ' + $script:RADfcPartColumn }
    $edits.Add(@{ At = ($prj.At + $pseg.TrimEnd().Length); Text = (', ' + $pcols) })
    foreach ($e in @($edits | Sort-Object { [int]$_.At } -Descending)) { $q = $q.Insert([int]$e.At, [string]$e.Text) }

    # the hand-off lookup: empty (it is no longer read by the query), the block and its markers kept
    $hm = [regex]::Match($q, '//__DEFENDER_HANDOFF_BEGIN__(?<block>.*?)//__DEFENDER_HANDOFF_END__', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if ($hm.Success) {
        $var = '_dfcPairs'; if ($hm.Groups['block'].Value -match 'let\s+(\w+)\s*=') { $var = $Matches[1] }
        $nl = [Environment]::NewLine
        $q = $q.Remove($hm.Index, $hm.Length).Insert($hm.Index, ('//__DEFENDER_HANDOFF_BEGIN__' + $nl + ('let {0} = datatable(_dfcKey:string)[];' -f $var) + $nl + '//__DEFENDER_HANDOFF_END__'))
    }
    # no per-slice key discovery for a lookup that no longer travels
    $q = [regex]::Replace($q, '(?m)^[ \t]*//__SI_LOOKUP_KEYS_HERE__[ \t]*\r?\n', '')
    # the keys as SHA-256 of the same texts (hash() is the same only within one query -- see the header). Last, so the
    # positions used above are the query's own.
    $sk = ConvertTo-RADfcShaKeyQuery -Query $q
    if ($sk.Count -ne 3 -or @($sk.Names | Sort-Object -Unique).Count -ne 3) { return (& $no ('the query''s Defender keys could not be keyed with SHA-256 ({0} of the 3 converted)' -f $sk.Count)) }
    $q = $sk.Query
    return @{ Applied = $true; Query = $q; Grain = $grain; Reason = '' }
}

function Test-RACountQuery {
    <# PURE. A completeness count of a report (Get-RAReportCountKql, Test-RABucketRowCount): its last operator is
       `count` or `distinct SIGroupHash`. Its answer carries no rows to filter. #>
    param([AllowEmptyString()][string]$Query)
    $t = [regex]::Replace([string]$Query, '//[^\r\n]*', '').TrimEnd().TrimEnd(';').TrimEnd()
    return ($t -match '\|\s*count\s*$' -or $t -match '\|\s*distinct\s+SIGroupHash\s*$')
}

function Get-RADefenderSetKql {
    <#
        PURE. The Defender list as Log Analytics holds it, one key per pair -- the same three pair TEXTS and the same
        "latest list within 8 days" as the YAML's _dfcPairs, keyed as the cut query keys its rows: the first 16 hex digits
        of hash_sha256(<text>) (never hash(): it is the same only within one query). No make_set (it stops at 1,048,576
        values): one row per key, read in -Pages parts cut on the key's first 4 hex digits (Get-RADfcPageRange).
        -Count: the number of keys.
    #>
    param([int]$Pages = 1, [int]$Page = 0, [switch]$Count, [string]$Table = 'SI_AzureRecommendation_CL')
    $head = @"
let _siT = toscalar($Table | where TimeGenerated > ago(8d) | summarize max(CollectionTime));
$Table
| where TimeGenerated > ago(8d) and CollectionTime == _siT
| extend _akL = tolower(tostring(column_ifexists("AssessmentKey", "")))
| project _t1 = strcat(tolower(tostring(ResourceName)), "|", tolower(tostring(Recommendation))),
          _t2 = iff(isnotempty(ResourceIdLower), strcat(tolower(tostring(ResourceIdLower)), "|", tolower(tostring(Recommendation))), ""),
          _t3 = iff(isnotempty(ResourceIdLower) and isnotempty(_akL), strcat(tolower(tostring(ResourceIdLower)), "|", _akL), "")
| mv-expand _t = pack_array(_t1, _t2, _t3) to typeof(string)
| where isnotempty(_t)
| summarize by K = tolower(substring(hash_sha256(_t), 0, 16))
"@
    if ($Count) { return ($head + '| count') }
    if ($Pages -le 1) { return $head.TrimEnd() }
    $r = Get-RADfcPageRange -Pages $Pages -Page $Page
    $w = '| where strcmp(substring(K, 0, 4), "{0}") >= 0' -f $r.Lo
    if ($null -ne $r.Hi) { $w += (' and strcmp(substring(K, 0, 4), "{0}") < 0' -f $r.Hi) }
    return ($head + $w)
}

function ConvertTo-RADfcKey {
    <# PURE. "x" + 16 hex digits (a key the cut hunting query returns) -> the signed 64-bit number; "-", empty or anything
       else -> $null (Test-RADfcNoKey tells "no key" apart from a key that cannot be read). #>
    param([AllowNull()][object]$Value)
    $s = [string]$Value
    if ($s.Length -ne 17 -or $s[0] -ne 'x') { return $null }
    return (ConvertFrom-RADfcHex -Hex $s.Substring(1))
}

function Test-RADfcNoKey {
    <# PURE. The row has no key of this kind ("-", empty, missing) -- as opposed to a key that cannot be read. #>
    param([AllowNull()][object]$Value)
    $s = [string]$Value
    return ($s -eq '' -or $s -eq '-')
}

function ConvertTo-RAFlatRows {
    <# PURE. Rows however a reader handed them over: one array (`return ,@(rows)`), an array holding that array, or rows. #>
    param([AllowNull()][object]$Answer)
    return @(@($Answer) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}

function Get-RADefenderKeyTableSql {
    @{
        Exists = "SELECT CASE WHEN OBJECT_ID('sidata.RaDefenderKey') IS NULL THEN 0 ELSE 1 END;"
        Clear  = "DELETE FROM sidata.RaDefenderKey WHERE RunKey = @RunKey OR CreatedAt < DATEADD(day, -2, SYSUTCDATETIME()); SELECT @@ROWCOUNT;"
        Insert = "INSERT sidata.RaDefenderKey (RunKey, K) SELECT @RunKey, CONVERT(bigint, j.[value]) FROM OPENJSON(@j) j; SELECT @@ROWCOUNT;"
        Count  = "SELECT COUNT_BIG(*) FROM sidata.RaDefenderKey WHERE RunKey = @RunKey;"
        Match  = "SELECT v.K FROM (SELECT DISTINCT CONVERT(bigint, j.[value]) AS K FROM OPENJSON(@j) j) v WHERE EXISTS (SELECT 1 FROM sidata.RaDefenderKey d WHERE d.RunKey = @RunKey AND d.K = v.K);"
        Drop   = "DELETE FROM sidata.RaDefenderKey WHERE RunKey = @RunKey; SELECT @@ROWCOUNT;"
    }
}

function Sync-RADefenderKeySet {
    <#
        The run's Defender list into SQL, ONCE per run: counted, read in parts of at most -PageKeys keys, written, and the
        written count checked against the count (a part that came back short fails the load -- never a shorter list). An
        empty list is told apart as in #674 (Get-RAHandoffSourceVerdict): no table / only older lists = empty and right;
        a table whose rows cannot be read yet, or a count that fails = the "lookup unavailable" error (the report is not
        complete). -Query: the Log Analytics seam { param($Kql) rows } (default Invoke-LogAnalyticsKqlQuery).
    #>
    param([Parameter(Mandatory)]$Stream, [string]$WorkspaceResourceId = '', [scriptblock]$Query, [int]$PageKeys = 200000, [string]$Table = 'SI_AzureRecommendation_CL')
    if ($null -ne $script:RADfcSet -and [string]$script:RADfcSet.RunKey -eq [string]$Stream.RunKey) { return $script:RADfcSet }
    # #742: a queue worker never loads the list itself (each load clears it -- two workers at once would empty it under each
    # other): the producer loaded it once; when that load failed, the worker's report fails with the producer's reason
    if ($script:RADfcSetFailed) { throw (New-RALookupUnavailableError -Message ([string]$script:RADfcSetFailed)) }
    if ($script:RADfcWorker) { throw (New-RALookupUnavailableError -Message 'a lookup this report needs could not be read -- the Defender recommendation list of this run was not loaded by its producer') }
    # (assigned, then returned: the reader answers ONE array -- @() around the call would hold that array as one row)
    if (-not $Query) { $Query = { param($Kql) $laRows = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $Kql; $laRows } }
    $sql = Get-RADefenderKeyTableSql
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if ([int](Invoke-RAStreamSql -Stream $Stream -Sql $sql.Exists -Mode 'scalar') -ne 1) {
        throw (New-RALookupUnavailableError -Message 'a lookup this report needs could not be read -- the database does not have the table for the Defender recommendation list yet (sidata.RaDefenderKey; the updater adds it with the data schema)')
    }
    $null = Invoke-RAStreamSql -Stream $Stream -Sql $sql.Clear -Params @{ RunKey = $Stream.RunKey } -Mode 'scalar'
    $n = 0L; $verdict = $null
    try {
        $cr = ConvertTo-RAFlatRows (& $Query (Get-RADefenderSetKql -Count -Table $Table))
        if ($cr.Count -gt 0 -and $null -ne $cr[0]) { foreach ($c in 'Count', 'count_') { $pp = $cr[0].PSObject.Properties[$c]; if ($pp -and $null -ne $pp.Value) { $n = [long]$pp.Value; break } } }
    } catch {
        $v = Get-RAHandoffSourceVerdict -Rows $null -CountError ([string]$_.Exception.Message) -Table $Table
        if ($v.State -ne 'Absent') { throw (New-RALookupUnavailableError -Message ('a lookup this report needs could not be read -- {0}' -f $v.Reason)) }
        $verdict = $v
    }
    if ($n -eq 0 -and $null -eq $verdict) {
        # empty: right (no current list) or not (a table whose rows cannot be read yet) -- #674, one count per table and run
        $lookback = 90; $lb = 0
        if ([int]::TryParse([string]$global:SI_RA_HandoffSourceLookbackDays, [ref]$lb) -and $lb -gt 8) { $lookback = $lb }
        $older = $null; $err = ''
        try {
            $or = ConvertTo-RAFlatRows (& $Query ("{0}`n| where TimeGenerated > ago({1}d)`n| summarize SIRows = count()" -f $Table, $lookback))
            $older = 0L; if ($or.Count -gt 0 -and $null -ne $or[0] -and $or[0].PSObject.Properties['SIRows']) { $older = [long]$or[0].SIRows }
        } catch { $err = [string]$_.Exception.Message; if (-not $err) { $err = 'the count failed' } }
        $verdict = Get-RAHandoffSourceVerdict -Rows $older -CountError $err -Table $Table
        if ($verdict.State -notin 'Absent', 'Stale') { throw (New-RALookupUnavailableError -Message ('a lookup this report needs could not be read -- {0}' -f $verdict.Reason)) }
    }
    $pages = [int][Math]::Min(65536, [Math]::Max(1, [Math]::Ceiling([double]$n / [double][Math]::Max(1, $PageKeys))))
    $written = 0L
    if ($n -gt 0) {
        $chunk = [long]0
        for ($p = 0; $p -lt $pages; $p++) {
            $rows = ConvertTo-RAFlatRows (& $Query (Get-RADefenderSetKql -Pages $pages -Page $p -Table $Table))
            $items = New-Object System.Collections.Generic.List[string]
            foreach ($r in $rows) {
                if ($null -eq $r) { continue }
                $kp = $r.PSObject.Properties['K']; if (-not $kp -or $null -eq $kp.Value) { continue }
                # 16 hex digits of hash_sha256 -> the number; a value that is not one is not written (the count check
                # below then fails the load: never a shorter list)
                $kv = ConvertFrom-RADfcHex -Hex $kp.Value
                if ($null -eq $kv) { continue }
                $items.Add(([long]$kv).ToString([System.Globalization.CultureInfo]::InvariantCulture))
            }
            if ($items.Count -gt 0) {
                $cref = [ref]$chunk
                $written += [long](Write-SIDataJsonRows -Invoke $Stream.Invoke -Sql $sql.Insert -Items $items.ToArray() -Params @{ RunKey = $Stream.RunKey } -ChunkChars $cref -What 'the Defender recommendation list')
                $chunk = $cref.Value
            }
        }
    }
    $stored = [long](Invoke-RAStreamSql -Stream $Stream -Sql $sql.Count -Params @{ RunKey = $Stream.RunKey } -Mode 'scalar')
    if ($stored -ne $n -or $written -ne $n) {
        $null = Invoke-RAStreamSql -Stream $Stream -Sql $sql.Drop -Params @{ RunKey = $Stream.RunKey } -Mode 'scalar'
        throw (New-RALookupUnavailableError -Message ("a lookup this report needs could not be read -- Log Analytics counts {0} key(s) in the Defender recommendation list, {1} were read and stored; a shorter list would leave duplicates" -f $n, $stored))
    }
    $sw.Stop()
    $script:RADfcSet = @{ RunKey = [string]$Stream.RunKey; Keys = $n; Pages = $pages; Verdict = $verdict }
    if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
        Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "the Defender recommendation list is in the database for this run: {0:N0} key(s), read in {1} part(s) in {2:F1}s -- the Azure recommendation reports are filtered against it there, nothing of it travels with their queries", $n, $pages, $sw.Elapsed.TotalSeconds))
    }
    return $script:RADfcSet
}

function Get-RADefenderKeyMatches {
    <# The keys of -Keys that are on the run's Defender list, asked in SQL in chunks (-ChunkKeys). Returns a HashSet[long]. #>
    param([Parameter(Mandatory)]$Stream, [AllowEmptyCollection()][long[]]$Keys = @(), [int]$ChunkKeys = 20000)
    $hit = New-Object 'System.Collections.Generic.HashSet[long]'
    if ($Keys.Count -eq 0) { return , $hit }
    $sql = (Get-RADefenderKeyTableSql).Match
    for ($i = 0; $i -lt $Keys.Count; $i += $ChunkKeys) {
        $n = [Math]::Min($ChunkKeys, $Keys.Count - $i)
        $part = New-Object 'string[]' $n
        for ($k = 0; $k -lt $n; $k++) { $part[$k] = $Keys[$i + $k].ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        $rows = @(Invoke-RAStreamSql -Stream $Stream -Sql $sql -Params @{ RunKey = $Stream.RunKey; j = ('[' + ($part -join ',') + ']') } -Mode 'reader')
        foreach ($x in $rows) { foreach ($h in @($x)) { if ($h) { [void]$hit.Add([long]$h['K']) } } }
    }
    return , $hit
}

function Invoke-RADefenderRowFilter {
    <#
        One answer's rows against the Defender list: a row is removed when ANY of its three keys is on the list -- in the
        order the query removed them (name + recommendation, then resource id + recommendation, then the assessment), which
        is the kind it is counted under. The keys (and the asset column of a Summary answer) are taken off the rows kept.
        -Match { param([long[]]$Keys) HashSet[long] } -- SQL in the engine (Get-RADefenderKeyMatches).
        Returns @{ Rows; Pre; Handed; Name; Id; Ak }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][scriptblock]$Match)
    $rowsIn = @($Rows | Where-Object { $null -ne $_ })
    $keySets = New-Object 'System.Collections.Generic.List[object]'
    $distinct = New-Object 'System.Collections.Generic.HashSet[long]'
    $bad = 0L; $badSample = ''
    foreach ($r in $rowsIn) {
        $ks = New-Object 'object[]' 3
        for ($c = 0; $c -lt 3; $c++) {
            $p = $r.PSObject.Properties[$script:RADfcKeyColumns[$c]]
            $k = $null; if ($p) { $k = ConvertTo-RADfcKey -Value $p.Value }
            # a key that is there but cannot be read could never match: counted, so the answer is refused (never "kept")
            if ($null -eq $k -and $p -and -not (Test-RADfcNoKey -Value $p.Value)) { $bad++; if (-not $badSample) { $badSample = ('{0}={1}' -f $script:RADfcKeyColumns[$c], [string]$p.Value) } }
            $ks[$c] = $k
            if ($null -ne $k) { [void]$distinct.Add([long]$k) }
        }
        $keySets.Add($ks)
    }
    $arr = New-Object 'long[]' $distinct.Count; $distinct.CopyTo($arr)
    $hit = & $Match $arr
    if ($null -eq $hit) { $hit = New-Object 'System.Collections.Generic.HashSet[long]' }
    $kept = New-Object System.Collections.Generic.List[object]
    $byKind = @(0L, 0L, 0L)
    $strip = @($script:RADfcKeyColumns) + $script:RADfcPartColumn
    for ($i = 0; $i -lt $rowsIn.Count; $i++) {
        $ks = $keySets[$i]; $removedBy = -1
        for ($c = 0; $c -lt 3; $c++) { if ($null -ne $ks[$c] -and $hit.Contains([long]$ks[$c])) { $removedBy = $c; break } }
        if ($removedBy -ge 0) { $byKind[$removedBy]++; continue }
        $o = [ordered]@{}
        foreach ($p in $rowsIn[$i].PSObject.Properties) { if ($strip -notcontains $p.Name) { $o[$p.Name] = $p.Value } }
        $kept.Add([pscustomobject]$o)
    }
    return @{ Rows = $kept.ToArray(); Pre = [long]$rowsIn.Count; Handed = [long]($byKind[0] + $byKind[1] + $byKind[2]); Name = [long]$byKind[0]; Id = [long]$byKind[1]; Ak = [long]$byKind[2]; Bad = $bad; BadSample = $badSample }
}

function Get-RADefenderFilterPlan {
    <# Whether THIS hunting call goes plan B (or both, to compare): $null = as it is. Loads the run's Defender list into
       SQL on first use (Sync-RADefenderKeySet; its "lookup unavailable" error ends the report as not complete). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query)
    $inEngine = Test-RADefenderFilterInEngineOn $global:SI_RA_DefenderFilterInEngine
    $compare  = Test-RADefenderFilterSetting $global:SI_RA_DefenderFilterCompare
    if (-not $inEngine -and -not $compare) { return $null }
    if ($Query.IndexOf($script:RADfcBegin) -lt 0) { return $null }
    $cut = ConvertTo-RADefenderFilterQuery -Query $Query
    if (-not $cut.Applied) { return $null }
    if (-not $script:RAStreamOn -or $null -eq $script:RAStream) {
        if (-not $script:RADfcNoSqlSaid -and (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue)) {
            $script:RADfcNoSqlSaid = $true
            Write-Warn2 'the Defender de-duplication stays in the query in this run: removing it in the engine needs the result in the database, and this run keeps it in memory'
        }
        return $null
    }
    $ws = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) { [string]$global:SI_WorkspaceResourceId } else { [string]$global:WorkspaceResourceId }
    $null = Sync-RADefenderKeySet -Stream $script:RAStream -WorkspaceResourceId $ws
    return @{ Original = $Query; Cut = $cut; InEngine = $inEngine; Compare = $compare; IsCount = (Test-RACountQuery -Query $Query) }
}

function Get-RAHuntingAnswerRows {
    <# The rows of a hunting answer in the form the report loop reads them (Get-RABucketRows' rules): the direct rows
       as they are, a Graph-shaped answer converted the same way. @{ Ok; Rows; Error } #>
    param($Resp)
    if ($null -eq $Resp) { return @{ Ok = $true; Rows = @(); Error = $null } }
    if ($Resp -is [pscustomobject] -and $Resp.PSObject.Properties['_SIDirectRows']) { return @{ Ok = $true; Rows = @($Resp._SIDirectRows); Error = $null } }
    if ($null -eq $Resp.Results -or $null -eq $Resp.Results.AdditionalProperties) { return @{ Ok = $true; Rows = @(); Error = $null } }
    try { return @{ Ok = $true; Rows = @(ConvertTo-PSObjectDeep $Resp.Results.AdditionalProperties -StripOData -CastPrimitiveArrays); Error = $null } }
    catch { return @{ Ok = $false; Rows = @(); Error = [string]$_.Exception.Message } }
}

function Complete-RADefenderFilterAnswer {
    <# Plan B's answer as the report loop expects it: filtered in SQL, keys taken off, a Summary answer's partial groups
       combined (plan from the ORIGINAL query). Records the answer's numbers for Add-RADfcAccount. A count answer (no keys
       on its rows) is returned as it is. -Match is a seam for tests. #>
    param($Resp, [Parameter(Mandatory)][hashtable]$Plan, [scriptblock]$Match)
    $conv = Get-RAHuntingAnswerRows -Resp $Resp
    if (-not $conv.Ok) { throw ("the answer could not be read: {0}" -f $conv.Error) }
    $rows = @($conv.Rows | Where-Object { $null -ne $_ })
    if ($Plan.IsCount) { return $Resp }
    if ($rows.Count -gt 0 -and -not $rows[0].PSObject.Properties[$script:RADfcKeyColumns[0]]) { return $Resp }
    if (-not $Match) { $Match = { param($k) Get-RADefenderKeyMatches -Stream $script:RAStream -Keys $k } }
    $f = Invoke-RADefenderRowFilter -Rows $rows -Match $Match
    if ([long]$f.Bad -gt 0) {
        # a key in a form the list is not kept in matches nothing -- every recommendation the Defender report lists would be
        # listed twice (2026-10-15, build 1938). Refused: the report is not complete, never Complete with the duplicates.
        $msg = ('a lookup this report needs could not be read -- {0} Defender key(s) in the answer are not in the form the Defender recommendation list is kept in (e.g. {1}); without them the report would list the recommendations the Defender recommendation report lists' -f [long]$f.Bad, [string]$f.BadSample)
        if (Get-Command -Name New-RALookupUnavailableError -ErrorAction SilentlyContinue) { throw (New-RALookupUnavailableError -Message $msg) }
        throw $msg
    }
    $out = @($f.Rows)
    if ($Plan.Cut.Grain -eq 'Summary' -and $out.Count -gt 1 -and (Get-Command -Name Merge-RASummaryBucketRows -ErrorAction SilentlyContinue)) {
        $m = Merge-RASummaryBucketRows -Rows $out -Query $Plan.Original
        if ($m.Applied) { $out = @($m.Rows) }
    }
    $script:RADfcLast = @{ Pre = $f.Pre; Handed = $f.Handed; Name = $f.Name; Id = $f.Id; Ak = $f.Ak; Rows = [long]$out.Count }
    return [pscustomobject]@{ _SIDirectRows = $out }
}

function Add-RADfcAccount {
    <# Books the numbers of the answer the report loop just accepted for slice -Bucket (a slice taken again replaces its
       own). Called where a slice's rows are accepted (Add-RAStreamBucket), also for a slice that came back empty. #>
    param([Parameter(Mandatory)][string]$Bucket)
    $d = $script:RADfcLast
    $script:RADfcLast = $null
    if ($null -eq $d -or -not $script:RAStreamOn -or $null -eq $script:RAStream) { return }
    Set-RAStreamAccount -Stream $script:RAStream -Bucket ('dfc:' + $Bucket) -Values @{ Pre = $d.Pre; Handed = $d.Handed; HandedName = $d.Name; HandedId = $d.Id; HandedAk = $d.Ak }
}

function Get-RADfcCountedRows {
    <# The rows a slice's answer is checked against the source's own count with: under plan B the rows retrieved BEFORE the
       Defender filter (the count is of the query without the anti-joins); otherwise the rows as returned (-Rows). #>
    param([long]$Rows)
    if ($null -ne $script:RADfcLast) { return [long]$script:RADfcLast.Pre }
    return $Rows
}

function Test-RADfcAccountActive {
    <# PURE. Plan B ran for this report: its account has a slice booked by Add-RADfcAccount. #>
    param([hashtable]$Account)
    if ($null -eq $Account) { return $false }
    return (@($Account.Keys | Where-Object { ([string]$_).StartsWith('dfc:') }).Count -gt 0)
}

function Get-RADfcReportedExpected {
    <#
        PURE. #734: the report's expected count AS THE REPORT HOLDS IT -- what the mails, the heartbeat, the run reports page
        and sidata.RaReportStatus.ExpectedRows read next to StoredRows. Under plan B the source is counted WITHOUT the
        Defender anti-joins (-Expected; Get-RAReportExpectedRows), so that count still holds the rows handed to the Defender
        recommendation report (live 2026-10-17: Azure_Recommendations_Summary ExpectedRows 12,398 / StoredRows 276 -- 276 was
        right). The completeness check itself keeps comparing like with like (the source's count with what the slices
        retrieved BEFORE the filter, -Pre); only the reported number is taken after the de-duplication:
          Detailed:  Expected - Handed;
          Summary:   Expected - Handed - the partial groups the merge combined into their group ((Pre - Handed) - Retrieved:
                     its groups were asked split by the Defender keys and the asset, and are one row each after the merge).
        $null stays $null (the source could not say); never below 0.
    #>
    param([AllowNull()]$Expected, [long]$Pre = 0, [long]$Handed = 0, [long]$Retrieved = 0, [switch]$Summary)
    if ($null -eq $Expected) { return $null }
    $after = [long]$Expected - [long]$Handed
    if ($Summary) {
        $combined = ([long]$Pre - [long]$Handed) - [long]$Retrieved
        if ($combined -gt 0) { $after -= $combined }
    }
    if ($after -lt 0) { $after = 0L }
    return [long]$after
}

function Get-RADfcHandedText {
    <# PURE. "120 handed to the Defender recommendation report (by name 80, by resource id 30, by assessment 10)". #>
    param([hashtable]$Total)
    if ($null -eq $Total -or [long]$Total.Handed -le 0) { return '' }
    return ('{0} handed to the Defender recommendation report (by name {1}, by resource id {2}, by assessment {3})' -f [long]$Total.Handed, [long]$Total.HandedName, [long]$Total.HandedId, [long]$Total.HandedAk)
}

# ------------------------------------------------------------------------------------------------------------------
#  SI_RA_DefenderFilterCompare -- BOTH paths in one run, compared answer by answer (REMOVE-ME with the setting)
# ------------------------------------------------------------------------------------------------------------------
function ConvertTo-RADfcCompareText {
    <# PURE. A value as the comparison reads it: a list (an array or JSON array text) as its sorted distinct items, a
       number in invariant form, everything else as text. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $items = $null
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t.StartsWith('[')) { try { $items = @((ConvertFrom-Json -InputObject $t) | ForEach-Object { $_ }) } catch { $items = $null } }
        if ($null -eq $items) { return $Value }
    } elseif ($Value -is [System.Collections.IEnumerable]) { $items = @($Value) }
    if ($null -ne $items) { return ('[' + ((@($items | ForEach-Object { [string]$_ } | Sort-Object -Unique)) -join [char]30) + ']') }
    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function Get-RADfcRowSignature {
    <# PURE. One row as the comparison sees it: every column (sorted by name), lists as sets. -Skip: columns not compared. #>
    param([Parameter(Mandatory)]$Row, [string[]]$Skip = @())
    $parts = foreach ($n in @($Row.PSObject.Properties.Name | Sort-Object)) { if ($Skip -contains $n) { continue }; $n + '=' + (ConvertTo-RADfcCompareText -Value $Row.$n) }
    return (@($parts) -join [char]31)
}

function Compare-RADefenderFilterAnswer {
    <#
        PURE. One answer of both paths: -Old (the query with its own anti-joins), -New (plan B, filtered and combined).
        Detailed: rows compared exactly (as multisets of signatures). Summary: groups (the final summarize-by of the
        ORIGINAL query) compared after lists are compared as sets. Returns @{ Old; New; Missing; Extra; Samples }.
    #>
    param([AllowEmptyCollection()][object[]]$Old = @(), [AllowEmptyCollection()][object[]]$New = @(), [string]$Grain = 'Detailed', [string]$OriginalQuery = '', [int]$MaxSamples = 5)
    $plan = $null
    if ($Grain -eq 'Summary' -and $OriginalQuery -and (Get-Command -Name Get-RASummaryMergePlan -ErrorAction SilentlyContinue)) { $plan = Get-RASummaryMergePlan -Query $OriginalQuery }
    $sig = {
        param($r)
        if ($null -ne $plan) {
            $g = (@($plan.Keys | ForEach-Object { [string]$r.PSObject.Properties[$_].Value }) -join [char]29).ToLowerInvariant()
            return ($g + [char]28 + (Get-RADfcRowSignature -Row $r))
        }
        Get-RADfcRowSignature -Row $r
    }
    $a = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    foreach ($r in @($Old | Where-Object { $null -ne $_ })) { $s = & $sig $r; if ($a.ContainsKey($s)) { $a[$s]++ } else { $a[$s] = 1 } }
    $b = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    foreach ($r in @($New | Where-Object { $null -ne $_ })) { $s = & $sig $r; if ($b.ContainsKey($s)) { $b[$s]++ } else { $b[$s] = 1 } }
    $missing = 0L; $extra = 0L; $samples = New-Object System.Collections.Generic.List[string]
    foreach ($k in $a.Keys) { $n = 0; if ($b.ContainsKey($k)) { $n = $b[$k] }; if ($a[$k] -gt $n) { $missing += ($a[$k] - $n); if ($samples.Count -lt $MaxSamples) { $samples.Add('only in the query path: ' + $k) } } }
    foreach ($k in $b.Keys) { $n = 0; if ($a.ContainsKey($k)) { $n = $a[$k] }; if ($b[$k] -gt $n) { $extra += ($b[$k] - $n); if ($samples.Count -lt $MaxSamples) { $samples.Add('only in the engine path: ' + $k) } } }
    return @{ Old = [long]@($Old).Count; New = [long]@($New).Count; Missing = $missing; Extra = $extra; Samples = $samples.ToArray() }
}

function Add-RADefenderFilterComparison {
    <# Adds one answer's comparison to the run's totals for the current report and says it when it differs. #>
    param([Parameter(Mandatory)][hashtable]$Cmp, [hashtable]$Filter, [string]$ReportName = '')
    if (-not $ReportName) { $ReportName = [string](Get-Variable -Name ReportName -ValueOnly -ErrorAction SilentlyContinue) }
    if (-not $ReportName) { $ReportName = '(unknown report)' }
    if ($null -eq $script:RADfcCompare) { $script:RADfcCompare = [ordered]@{} }
    if (-not $script:RADfcCompare.Contains($ReportName)) { $script:RADfcCompare[$ReportName] = [ordered]@{ Answers = 0; Old = 0L; New = 0L; Missing = 0L; Extra = 0L; Pre = 0L; Handed = 0L; HandedName = 0L; HandedId = 0L; HandedAk = 0L; Samples = (New-Object System.Collections.Generic.List[string]) } }
    $t = $script:RADfcCompare[$ReportName]
    $t.Answers++; $t.Old += $Cmp.Old; $t.New += $Cmp.New; $t.Missing += $Cmp.Missing; $t.Extra += $Cmp.Extra
    if ($Filter) { $t.Pre += [long]$Filter.Pre; $t.Handed += [long]$Filter.Handed; $t.HandedName += [long]$Filter.Name; $t.HandedId += [long]$Filter.Id; $t.HandedAk += [long]$Filter.Ak }
    foreach ($s in @($Cmp.Samples)) { if ($t.Samples.Count -lt 20) { $t.Samples.Add($s) } }
    if (($Cmp.Missing + $Cmp.Extra) -gt 0 -and (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue)) {
        Write-Warn2 ("Defender hand-off comparison, {0}: the two paths DIFFER in this answer -- query path {1} row(s), engine path {2}; {3} only in the query path, {4} only in the engine path" -f $ReportName, $Cmp.Old, $Cmp.New, $Cmp.Missing, $Cmp.Extra)
    }
}

function Write-RADefenderFilterComparison {
    <# At the end of the run: one line per report and the comparison as JSON (-Path; default the run's staging folder). #>
    param([string]$Path = '')
    if ($null -eq $script:RADfcCompare -or $script:RADfcCompare.Count -eq 0) { return $null }
    foreach ($k in $script:RADfcCompare.Keys) {
        $t = $script:RADfcCompare[$k]
        $verdict = if (($t.Missing + $t.Extra) -eq 0) { 'EQUAL' } else { 'DIFFERENT' }
        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
            Write-Info ("Defender hand-off comparison, {0}: {1} -- {2} answer(s); query path {3} row(s), engine path {4}; {5} only in the query path, {6} only in the engine path; the engine retrieved {7} row(s) and handed {8} to the Defender recommendation report (by name {9}, by resource id {10}, by assessment {11})" -f $k, $verdict, $t.Answers, $t.Old, $t.New, $t.Missing, $t.Extra, $t.Pre, $t.Handed, $t.HandedName, $t.HandedId, $t.HandedAk)
        }
    }
    if (-not $Path) {
        $dir = if ($global:SI_StagingPath) { Join-Path $global:SI_StagingPath 'risk-analysis' } elseif ($global:OutputPath) { Join-Path $global:OutputPath 'staging\risk-analysis' } else { Join-Path ([IO.Path]::GetTempPath()) 'si-ra' }
        try { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null } catch { }
        $Path = Join-Path $dir ('ra-defender-handoff-compare-{0}.json' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    }
    $doc = [ordered]@{ Written = (Get-Date).ToUniversalTime().ToString('o'); Reports = [ordered]@{} }
    foreach ($k in $script:RADfcCompare.Keys) { $t = $script:RADfcCompare[$k]; $doc.Reports[$k] = [ordered]@{ Verdict = $(if (($t.Missing + $t.Extra) -eq 0) { 'EQUAL' } else { 'DIFFERENT' }); Answers = $t.Answers; QueryPathRows = $t.Old; EnginePathRows = $t.New; OnlyInQueryPath = $t.Missing; OnlyInEnginePath = $t.Extra; EngineRetrieved = $t.Pre; Handed = $t.Handed; HandedByName = $t.HandedName; HandedByResourceId = $t.HandedId; HandedByAssessment = $t.HandedAk; Samples = @($t.Samples) } }
    try { [IO.File]::WriteAllText($Path, (ConvertTo-Json -InputObject $doc -Depth 6), (New-Object System.Text.UTF8Encoding($false))) } catch { return $null }
    return $Path
}

function Complete-RADefenderFilterRun {
    <# The run's end: the comparison is said and written (SI_RA_DefenderFilterCompare), and the run's Defender list is
       removed from SQL (a list a failed run leaves behind is removed by the next load, after two days). #>
    $path = Write-RADefenderFilterComparison
    if ($path -and (Get-Command -Name Write-Info -ErrorAction SilentlyContinue)) { Write-Info ("Defender hand-off comparison written: {0}" -f $path) }
    if ($null -ne $script:RADfcSet -and $script:RAStreamOn -and $null -ne $script:RAStream) {
        $null = Invoke-RAStreamSql -Stream $script:RAStream -Sql (Get-RADefenderKeyTableSql).Drop -Params @{ RunKey = $script:RAStream.RunKey } -Mode 'scalar'
    }
    $script:RADfcSet = $null
    return $path
}

function Invoke-RADefenderFilterAnswer {
    <#
        The hunting call under plan B: -Core runs ONE query (the hunting layer, Invoke-GraphHuntingQueryCore). In-engine
        only: the cut query, filtered. Compare: BOTH, compared; the answer returned is the engine path's when
        SI_RA_DefenderFilterInEngine is on, else the query path's (the run's result stays what it was). A count runs one
        path only (the in-engine one when on).
    #>
    param([Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][scriptblock]$Core, [scriptblock]$Match)
    if ($Plan.IsCount) {
        if ($Plan.InEngine) { return (& $Core $Plan.Cut.Query) }
        return (& $Core $Plan.Original)
    }
    if (-not $Plan.Compare) { return (Complete-RADefenderFilterAnswer -Resp (& $Core $Plan.Cut.Query) -Plan $Plan -Match $Match) }
    $oldResp = & $Core $Plan.Original
    $newResp = Complete-RADefenderFilterAnswer -Resp (& $Core $Plan.Cut.Query) -Plan $Plan -Match $Match
    $filterNumbers = $script:RADfcLast
    $old = Get-RAHuntingAnswerRows -Resp $oldResp
    $cmp = Compare-RADefenderFilterAnswer -Old @($old.Rows) -New @($newResp._SIDirectRows) -Grain $Plan.Cut.Grain -OriginalQuery $Plan.Original
    Add-RADefenderFilterComparison -Cmp $cmp -Filter $filterNumbers
    if ($Plan.InEngine) { return $newResp }
    $script:RADfcLast = $null      # the run's result is the query path's: nothing was handed in the engine
    return $oldResp
}
