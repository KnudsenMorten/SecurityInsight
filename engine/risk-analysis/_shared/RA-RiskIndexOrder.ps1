#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  The risk index: FIRST MATCH WINS, in row order (operator decision 2026-10-04).
#
#  WHAT A ROW MEANS
#    Matchers  SecurityDomain, Category, SubCategory, ConfigurationId   -- blank = any
#              SecuritySeverity      (consulted for the CONSEQUENCE score only)
#              CriticalityTierLevel  (consulted for the PROBABILITY score only)
#    Scores    RiskConsequenceScore_SecuritySeverity, RiskProbablityScore_CriticialityTierLevel
#              -- a blank score means "this row does not set that score": the search goes on.
#    Order     Precedence (1 = checked first). A file without the Precedence column is a v2.2 index.
#
#  HOW A FINDING IS SCORED
#    Consequence base = the score of the FIRST row, top-down, that has a consequence score and whose
#    filled matchers among Domain/Category/SubCategory/ConfigurationId/SecuritySeverity all equal the
#    finding's values (case-insensitive). The probability base is found the same way with
#    CriticalityTierLevel in place of SecuritySeverity. No row -> 0. The two lookups are independent,
#    exactly as they were in v2.2. The scoring contract is unchanged:
#      RiskScoreTotal = (consBase + rfCons) x (probBase + rfProb)
#
#  WHY THE TWO LOOKUPS STAY INDEPENDENT
#    v2.2 never took both scores from one row: the consequence came from the best row for the
#    finding's SEVERITY and the probability from the best row for its TIER. Making one row supply both
#    would need a row for every severity x tier x matcher combination to give the same scores
#    (measured on the shipped index: thousands of rows), so it is not done.
#
#  v2.2 -> v3 (ConvertTo-SIRiskIndexFirstMatch)
#    v2.2 did NOT use the order of the file. It walked a FIXED ladder of column patterns, most specific
#    first (domain-qualified before not; severity/tier-qualified before configuration-only), and per
#    pattern took the first row in the file that had every pattern column filled -- IGNORING that row's
#    other columns. Converting a v2.2 file writes one row per (pattern, value) the ladder could ever
#    pick, in ladder order, so first-match over the converted rows returns exactly the v2.2 score for
#    every finding (proved in tests/pester/SIv3-RiskIndexOrder.Tests.ps1 over every matcher
#    combination). The C# preview (SI.Management.Core RiskIndexScoring) mirrors this file 1:1.
#
#  PowerShell 5.1 compatible. Pure functions; no I/O.
#######################################################################################################

$script:SIRiskIndexMatchColumns = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId')
$script:SIRiskIndexOutColumns   = @('SecurityDomain', 'Category', 'SubCategory', 'ConfigurationId', 'SecuritySeverity',
    'RiskConsequenceScore_SecuritySeverity', 'CriticalityTierLevel', 'RiskProbablityScore_CriticialityTierLevel', 'Comments', 'Precedence')

function Get-SIRiskIndexLadder {
    <# PURE. The v2.2 pattern ladder (RA-ExcelReport.ps1 New-RiskIndex before v3), most specific first.
       D C S I = SecurityDomain Category SubCategory ConfigurationId; V = SecuritySeverity (consequence) or
       CriticalityTierLevel (probability). #>
    @(
        @('D','C','S','I','V'), @('D','C','S','V'), @('D','C','V'), @('D','V'),
        @('D','C','S','I'),     @('D','C','S'),     @('D','C'),     @('D'),
        @('C','S','I','V'),     @('C','S','V'),     @('C','V'),     @('V'),
        @('C','S','I'),         @('C','S'),         @('C')
    )
}

function Get-SIRiskIndexCell {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return [string]$Row[$Name] } else { return '' } }
    $p = $Row.PSObject.Properties[$Name]
    if ($null -eq $p -or $null -eq $p.Value) { return '' }
    [string]$p.Value
}

function ConvertTo-SIRiskIndexNumber {
    <# PURE. A score the way the engine always parsed it: invariant, anything else -> 0. #>
    param([string]$Text)
    $n = 0.0
    [void][double]::TryParse([string]$Text, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)
    $n
}

function Get-SIRiskIndexLogicalColumn {
    param([string]$Letter, [string]$Kind)
    switch ($Letter) {
        'D' { 'SecurityDomain' } 'C' { 'Category' } 'S' { 'SubCategory' } 'I' { 'ConfigurationId' }
        'V' { if ($Kind -eq 'Consequence') { 'SecuritySeverity' } else { 'CriticalityTierLevel' } }
    }
}

function Get-SIRiskIndexScoreColumn {
    param([string]$Kind)
    if ($Kind -eq 'Consequence') { 'RiskConsequenceScore_SecuritySeverity' } else { 'RiskProbablityScore_CriticialityTierLevel' }
}

function Get-SIRiskIndexLadderScore {
    <#
        PURE. The v2.2 rule, kept as the REFERENCE the conversion is proved against (and for the impact
        measurement). -Rows in file order; -Finding a hashtable with SecurityDomain, Category, SubCategory,
        ConfigurationId, SecuritySeverity, CriticalityTierLevel. Returns the base score (0 when nothing matches).
    #>
    param([object[]]$Rows, [hashtable]$Finding, [ValidateSet('Consequence','Probability')][string]$Kind, [hashtable]$Index)
    if (-not $Index) { $Index = New-SIRiskIndexLadderIndex -Rows $Rows }
    $maps = $Index[$Kind]
    $hasDomain = -not [string]::IsNullOrWhiteSpace([string]$Finding['SecurityDomain'])
    $ladder = Get-SIRiskIndexLadder
    for ($g = 0; $g -lt $ladder.Count; $g++) {
        $pat = $ladder[$g]
        if ($g -lt 8 -and -not $hasDomain) { continue }
        $fk = New-Object System.Collections.Generic.List[string]; $ok = $true
        foreach ($l in $pat) { $v = [string]$Finding[(Get-SIRiskIndexLogicalColumn $l $Kind)]; if ([string]::IsNullOrWhiteSpace($v)) { $ok = $false; break }; $fk.Add($v) }
        if (-not $ok) { continue }
        $fkey = ($fk.ToArray() -join '|').ToLowerInvariant()
        if ($maps[$g].ContainsKey($fkey)) { return $maps[$g][$fkey] }
    }
    0.0
}

function New-SIRiskIndexLadderIndex {
    <# PURE. The v2.2 lookup maps (per kind, per ladder pattern: key -> score of the FIRST row in the file with that key). #>
    param([object[]]$Rows)
    $ladder = Get-SIRiskIndexLadder
    $res = @{}
    foreach ($kind in 'Consequence', 'Probability') {
        $scoreCol = Get-SIRiskIndexScoreColumn $kind
        $maps = @()
        foreach ($pat in $ladder) {
            $map = @{}
            foreach ($r in @($Rows)) {
                $rk = New-Object System.Collections.Generic.List[string]; $rok = $true
                foreach ($l in $pat) { $v = Get-SIRiskIndexCell $r (Get-SIRiskIndexLogicalColumn $l $kind); if ([string]::IsNullOrWhiteSpace($v)) { $rok = $false; break }; $rk.Add($v) }
                if (-not $rok) { continue }
                $k = ($rk.ToArray() -join '|').ToLowerInvariant()
                if (-not $map.ContainsKey($k)) { $map[$k] = (ConvertTo-SIRiskIndexNumber (Get-SIRiskIndexCell $r $scoreCol)) }
            }
            $maps += , $map
        }
        $res[$kind] = $maps
    }
    $res
}

function ConvertTo-SIRiskIndexFirstMatch {
    <#
        PURE. A v2.2 index (rows in file order) -> the same index as first-match rows, in precedence order, with
        Precedence 1..n. First-match over the result scores every finding exactly as the v2.2 ladder scored the
        input. Rows are [ordered] dictionaries with the ten columns of $script:SIRiskIndexOutColumns.
        One row per (ladder pattern, value) the v2.2 ladder could pick. A severity row carries only the
        consequence score and a tier row only the probability score; a pattern without severity / tier writes its
        consequence and probability entry (same domain/category/subcategory/configuration) as one row.
    #>
    param([AllowEmptyCollection()][object[]]$Rows)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    $ladder = Get-SIRiskIndexLadder
    $groups = New-Object System.Collections.Generic.List[object]   # per pattern: ordered groups of (cons list, prob list)
    for ($g = 0; $g -lt $ladder.Count; $g++) {
        $pat = $ladder[$g]
        $byKey = @{}; $order = New-Object System.Collections.Generic.List[string]
        foreach ($kind in 'Consequence', 'Probability') {
            $seen = @{}
            $scoreCol = Get-SIRiskIndexScoreColumn $kind
            foreach ($r in $rows) {
                $vals = New-Object System.Collections.Generic.List[string]; $ok = $true
                foreach ($l in $pat) { $v = Get-SIRiskIndexCell $r (Get-SIRiskIndexLogicalColumn $l $kind); if ([string]::IsNullOrWhiteSpace($v)) { $ok = $false; break }; $vals.Add($v) }
                if (-not $ok) { continue }
                $key = ($vals.ToArray() -join '|').ToLowerInvariant()
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true
                # the group: the pattern's columns without V
                $gk = New-Object System.Collections.Generic.List[string]
                for ($i = 0; $i -lt $pat.Count; $i++) { if ($pat[$i] -ne 'V') { $gk.Add($vals[$i]) } }
                $gkey = ($gk.ToArray() -join '|').ToLowerInvariant()
                if (-not $byKey.ContainsKey($gkey)) { $byKey[$gkey] = @{ Cons = (New-Object System.Collections.Generic.List[object]); Prob = (New-Object System.Collections.Generic.List[object]) }; $order.Add($gkey) }
                $raw = (Get-SIRiskIndexCell $r $scoreCol).Trim()
                $d = 0.0
                $score = if ($raw -ne '' -and [double]::TryParse($raw, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $raw } else { '0' }
                # the row's note travels only to a row that matches what the row itself matched (not to the wider
                # patterns v2.2 also filed it under)
                $wider = $false
                foreach ($l in 'D', 'C', 'S', 'I', 'V') { if ($pat -notcontains $l -and -not [string]::IsNullOrWhiteSpace((Get-SIRiskIndexCell $r (Get-SIRiskIndexLogicalColumn $l $kind)))) { $wider = $true } }
                $entry = @{ Vals = $vals.ToArray(); Score = $score; Comment = $(if ($wider) { '' } else { Get-SIRiskIndexCell $r 'Comments' }) }
                if ($kind -eq 'Consequence') { $byKey[$gkey].Cons.Add($entry) } else { $byKey[$gkey].Prob.Add($entry) }
            }
        }
        $groups.Add(@{ Pattern = $pat; ByKey = $byKey; Order = $order })
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($grp in $groups) {
        $pat = $grp.Pattern
        foreach ($gkey in $grp.Order) {
            $c = $grp.ByKey[$gkey].Cons; $p = $grp.ByKey[$gkey].Prob
            # A pattern WITH a severity / tier column: one row per score (a severity row sets the consequence, a tier
            # row the probability -- so no row reads as "severity AND tier"). Without one: at most one entry of each
            # kind, written as one row with both scores.
            $pairs = New-Object System.Collections.Generic.List[object]
            if ($pat -contains 'V') {
                foreach ($e in $c) { $pairs.Add(@($e, $null)) }
                foreach ($e in $p) { $pairs.Add(@($null, $e)) }
            } else {
                $pairs.Add(@($(if ($c.Count) { $c[0] } else { $null }), $(if ($p.Count) { $p[0] } else { $null })))
            }
            foreach ($pair in $pairs) {
                $o = [ordered]@{}; foreach ($col in $script:SIRiskIndexOutColumns) { $o[$col] = '' }
                $ce = $pair[0]
                $pe = $pair[1]
                $src = if ($ce) { $ce } else { $pe }
                for ($j = 0; $j -lt $pat.Count; $j++) {
                    $l = $pat[$j]
                    if ($l -eq 'V') {
                        if ($ce) { $o['SecuritySeverity'] = $ce.Vals[$j] }
                        if ($pe) { $o['CriticalityTierLevel'] = $pe.Vals[$j] }
                    } else { $o[(Get-SIRiskIndexLogicalColumn $l 'Consequence')] = $src.Vals[$j] }
                }
                if ($ce) { $o['RiskConsequenceScore_SecuritySeverity'] = $ce.Score }
                if ($pe) { $o['RiskProbablityScore_CriticialityTierLevel'] = $pe.Score }
                $o['Comments'] = $(if ($ce -and $ce.Comment) { $ce.Comment } elseif ($pe) { $pe.Comment } else { '' })
                $out.Add($o)
            }
        }
    }
    $k = 0; foreach ($o in $out) { $k++; $o['Precedence'] = [string]$k }
    # the rows, one by one, to the pipeline (callers collect them with @())
    $out.ToArray()
}

function Test-SIRiskIndexFirstMatchForm {
    <# PURE. $true when the rows carry the Precedence column (a v3 first-match index), $false for a v2.2 index. #>
    param([AllowEmptyCollection()][object[]]$Rows)
    $first = @($Rows | Where-Object { $null -ne $_ } | Select-Object -First 1)
    if (-not $first.Count) { return $false }
    $r = $first[0]
    if ($r -is [System.Collections.IDictionary]) { return [bool]$r.Contains('Precedence') }
    [bool]$r.PSObject.Properties['Precedence']
}

function Get-SIRiskIndexOrderedRows {
    <#
        PURE. The rows of an index in the order first-match walks them. A v3 index: stable sort by Precedence
        (a number; a row without one goes after the numbered rows, in file order). A v2.2 index: converted.
    #>
    param([AllowEmptyCollection()][object[]]$Rows)
    $rows = @($Rows | Where-Object { $null -ne $_ })
    if (-not (Test-SIRiskIndexFirstMatchForm $rows)) { return @(ConvertTo-SIRiskIndexFirstMatch -Rows $rows) }
    if ($rows.Count -eq 0) { return }
    $keys = New-Object 'System.Collections.Generic.List[double]'
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $t = (Get-SIRiskIndexCell $rows[$i] 'Precedence').Trim(); $d = 0.0
        if ($t -ne '' -and [double]::TryParse($t, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $keys.Add($d) } else { $keys.Add([double]::MaxValue) }
    }
    $idx = [int[]](0..($rows.Count - 1))
    # stable: sort by (precedence, original position); the rows go to the pipeline one by one (callers use @())
    $sorted = @($idx | Sort-Object -Property @{ Expression = { $keys[$_] } }, @{ Expression = { $_ } })
    foreach ($i in $sorted) { $rows[$i] }
}

function New-SIRiskIndexRules {
    <#
        PURE. Ordered rows -> the two rule lists first-match walks: @{ Consequence = rules; Probability = rules }.
        A rule: @{ M = string[5] (D, C, S, I, V lowercased; $null = any); Score = double; Position = 1-based row }.
        A row without a score for a kind is not a rule of that kind.
    #>
    param([AllowEmptyCollection()][object[]]$OrderedRows)
    $res = @{}
    foreach ($kind in 'Consequence', 'Probability') {
        $scoreCol = Get-SIRiskIndexScoreColumn $kind
        $list = New-Object System.Collections.Generic.List[object]
        $pos = 0
        foreach ($r in @($OrderedRows)) {
            $pos++
            $s = Get-SIRiskIndexCell $r $scoreCol
            if ([string]::IsNullOrWhiteSpace($s)) { continue }
            $m = New-Object 'object[]' 5
            $i = 0
            foreach ($l in 'D', 'C', 'S', 'I', 'V') {
                $v = Get-SIRiskIndexCell $r (Get-SIRiskIndexLogicalColumn $l $kind)
                $m[$i] = $(if ([string]::IsNullOrWhiteSpace($v)) { $null } else { $v.ToLowerInvariant() })
                $i++
            }
            $list.Add(@{ M = $m; Score = (ConvertTo-SIRiskIndexNumber $s); Position = $pos })
        }
        $res[$kind] = $list.ToArray()
    }
    $res
}

function Find-SIRiskIndexRule {
    <#
        PURE. The first rule whose filled matchers all equal the finding's values. -Values: string[5] in D C S I V
        order (the finding's; blank = the finding has no value, which a filled matcher never matches).
        Returns the rule, or $null.
    #>
    param([object[]]$Rules, [string[]]$Values)
    $lv = New-Object 'object[]' 5
    for ($i = 0; $i -lt 5; $i++) { $lv[$i] = $(if ([string]::IsNullOrWhiteSpace($Values[$i])) { $null } else { $Values[$i].ToLowerInvariant() }) }
    foreach ($rule in $Rules) {
        $m = $rule.M; $fit = $true
        for ($i = 0; $i -lt 5; $i++) {
            if ($null -ne $m[$i] -and $m[$i] -cne $lv[$i]) { $fit = $false; break }
        }
        if ($fit) { return $rule }
    }
    $null
}

function Get-SIRiskIndexFirstMatchScore {
    <# PURE. The base score of one finding under first-match (0 when no rule matches). For tests and tools. #>
    param([hashtable]$Rules, [hashtable]$Finding, [ValidateSet('Consequence','Probability')][string]$Kind)
    $vals = @(foreach ($l in 'D', 'C', 'S', 'I', 'V') { [string]$Finding[(Get-SIRiskIndexLogicalColumn $l $Kind)] })
    $r = Find-SIRiskIndexRule -Rules $Rules[$Kind] -Values $vals
    if ($null -eq $r) { 0.0 } else { [double]$r.Score }
}

function ConvertTo-SIRiskIndexCsvText {
    <# PURE. Ordered rows -> the CSV text the engine reads (v3: with Precedence, renumbered 1..n in this order). #>
    param([AllowEmptyCollection()][object[]]$OrderedRows)
    $q = { param([string]$s) if ($s -match '[",\r\n]' -or $s -ne $s.Trim()) { '"' + $s.Replace('"', '""') + '"' } else { $s } }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(($script:SIRiskIndexOutColumns -join ','))
    $k = 0
    foreach ($r in @($OrderedRows)) {
        $k++
        $lines.Add((@(foreach ($c in $script:SIRiskIndexOutColumns) { if ($c -eq 'Precedence') { [string]$k } else { & $q (Get-SIRiskIndexCell $r $c) } }) -join ','))
    }
    ($lines.ToArray() -join "`r`n") + "`r`n"
}
