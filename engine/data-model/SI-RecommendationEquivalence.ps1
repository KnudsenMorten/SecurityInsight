#Requires -Version 5.1
<#
    SecurityInsight -- THE SAME RECOMMENDATION ACROSS PROVIDERS (#464, V3-DATA-MODEL 2.8.2 phase 2).

    One recommendation reported by several providers (Defender for Endpoint and Defender for Cloud, Exposure Management,
    ...) is ONE finding on the CI with every provider as evidence -- not one finding per provider.

    TEMPLATE  data-model/recommendation-equivalence.locked.json (kind 'recommendation-equivalence', items 'groups'):
                { "id": "<group id>", "canonicalId": "<the finding key the group is known by>", "canonicalTitle": "...",
                  "stage": "production" | "testing" | "not_used",            (default production; only production merges)
                  "members": [ { "provider": "mde", "id": "scid-..." }, { "provider": "mdc", "title": "..." } ] }
              A member names the provider's recommendation id (the Risk Analysis row's ConfigurationId) or its exact title
              (ConfigurationName, compared case-insensitively, spaces collapsed). An id or a title belongs to ONE group.
              Keep the canonical id = the id the oldest provider already reports: its existing findings keep their key.
    CUSTOMER  Pro: one cfg.ItemOverride row per group ('recommendation-equivalence:<id>' -- override, disable or add);
              Community: data-model/recommendation-equivalence.custom.json, the same shape, only the groups that differ.
              Both through the data-model merge (Get-SIDataModelTemplate), like every other data-model template.
    APPLIED   Risk Analysis' finding keys (RA-Findings.ps1: the CI's finding key becomes the canonical id, the reports'
              own keys are kept in si_finding_aliases and every report's key + severity in si_finding_evidence) and the
              finding lifecycle (SI-DataCiLifecycle.ps1: an existing lifecycle row under an alias key is carried onto the
              canonical key -- FirstDetected kept, never closed and reopened because the key changed).

    #693 GENERALISED -- link two findings into one, for every finding type. A group has a "match" (default "key"):
      key   (above) the same recommendation under each provider's id or title -- per row, any CI.
      link  a MANUAL link an operator made on ONE owner (CI id, or asset:<id>): "owner", two or more "members" (finding
            keys -- any provider, the same provider or report twice is allowed), "canonicalId" = the member that stays,
            "linkedBy" + "reason" (+ "linkedAt") recorded. Unlink = stage "not_used" (the record stays: reversible, audited).
            Per row, like key, so it reaches the database's finding key, the pager and the lifecycle unchanged.
      fold  a MEANING rule over the generic SI finding fields AFTER mapping and value normalisation (never a provider's
            raw column): "evidence" and "canonical" = conditions { field: si_*, pattern: <regex, named captures> | equals },
            "on" = pairs { evidence: <si field or capture name>, canonical: <si field> } compared normalised (lower case,
            spaces / underscores made one). On one CI, a finding matching "evidence" whose "on" values meet a finding
            matching "canonical" is NOT a finding of its own: it is evidence on every such canonical finding (its key an
            alias of the first, so its history carries over), its reports added to their si_detected_by. Applied to the
            CI's findings (Merge-SIFindingFolds); the report rows themselves are never touched (no row is lost).
    Only production groups apply; a shipped fold rule starts as "testing" until it is proven on an internal run.

    PURE except Get-SIRecommendationEquivalence (reads the template). PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-SIEqMatch {
    <# PURE. A group's match: key (default) | link | fold | the unknown value as given. #>
    param($Group)
    $m = ([string](Get-SIEqValue $Group 'match')).Trim().ToLowerInvariant()
    if (-not $m) { return 'key' }
    $m
}

function ConvertTo-SIFindingMatchValue {
    <# PURE. A value as a link rule compares it: lower case, runs of spaces / underscores made one space, trimmed. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not $Value) { return '' }
    (($Value.Trim().ToLowerInvariant()) -replace '[\s_]+', ' ').Trim()
}

function Test-SIFindingFoldCondition {
    <# PURE. The reasons one fold condition is not accepted; adds its pattern's named captures to -Captures. #>
    param($Condition, [string]$Group, [string]$Side, [System.Collections.Generic.List[string]]$Captures)
    $why = New-Object System.Collections.Generic.List[string]
    $f = [string](Get-SIEqValue $Condition 'field')
    if ($f -notmatch '^si_[a-z0-9_]+$') { $why.Add(("group '{0}': a {1} condition's field '{2}' -- a generic SI field (si_...), never a provider column" -f $Group, $Side, $f)) }
    $pat = Get-SIEqValue $Condition 'pattern'; $eqv = Get-SIEqValue $Condition 'equals'
    if (($null -eq $pat) -eq ($null -eq $eqv)) { $why.Add(("group '{0}': a {1} condition on '{2}' has exactly one of pattern / equals" -f $Group, $Side, $f)) }
    if ($null -ne $pat) {
        try {
            $rx = New-Object System.Text.RegularExpressions.Regex ([string]$pat), 'IgnoreCase'
            if ($null -ne $Captures) { foreach ($n in $rx.GetGroupNames()) { if ($n -notmatch '^\d+$' -and -not $Captures.Contains($n)) { $Captures.Add($n) } } }
        } catch { $why.Add(("group '{0}': the {1} pattern on '{2}' is not a valid regular expression" -f $Group, $Side, $f)) }
    }
    $why.ToArray()
}

function Get-SIRecommendationTitleKey {
    <# PURE. A title as the equivalence compares it: lower case, spaces collapsed, trimmed. '' for none. #>
    param([AllowNull()][AllowEmptyString()][string]$Title)
    if (-not $Title) { return '' }
    (($Title.Trim().ToLowerInvariant()) -replace '\s+', ' ')
}

function Get-SIEqValue {
    <# PURE. A named value of a dictionary / object, or $null (this file stands alone: no other helper needed). #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { foreach ($k in $Item.Keys) { if ([string]$k -ieq $Name) { return $Item[$k] } }; return $null }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function Test-SIRecommendationEquivalenceGroup {
    <# PURE. The reasons one group is not accepted (empty = accepted). #>
    param($Group)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Group) { $why.Add('a group is empty'); return $why.ToArray() }
    $id = [string](Get-SIEqValue $Group 'id')
    if ($id -notmatch '^[a-z0-9][a-z0-9_\-\.]{0,99}$') { $why.Add(("group id '{0}': lower-case letters, digits, - _ . (at most 100)" -f $id)) }
    $st = [string](Get-SIEqValue $Group 'stage')
    $match = Get-SIEqMatch $Group
    if ($match -notin 'key', 'link', 'fold') { $why.Add(("group '{0}': match '{1}' (key | link | fold)" -f $id, $match)); return $why.ToArray() }
    if ($match -eq 'fold') {
        # #693 a meaning rule: conditions on generic SI fields, joined on SI fields / captures
        if ($st -and $st -notin 'production', 'testing', 'not_used') { $why.Add(("group '{0}': stage '{1}' (production | testing | not_used)" -f $id, $st)) }
        $caps = New-Object System.Collections.Generic.List[string]
        foreach ($side in 'evidence', 'canonical') {
            $conds = @(Get-SIEqValue $Group $side) | Where-Object { $null -ne $_ }
            if (@($conds).Count -lt 1) { $why.Add(("group '{0}': at least one {1} condition" -f $id, $side)) }
            $c2 = $null; if ($side -eq 'evidence') { $c2 = $caps }
            foreach ($c in @($conds)) { foreach ($x in (Test-SIFindingFoldCondition -Condition $c -Group $id -Side $side -Captures $c2)) { $why.Add([string]$x) } }
        }
        $on = @(Get-SIEqValue $Group 'on') | Where-Object { $null -ne $_ }
        if (@($on).Count -lt 1) { $why.Add(("group '{0}': at least one 'on' pair -- what the two findings share" -f $id)) }
        foreach ($p in @($on)) {
            $e = [string](Get-SIEqValue $p 'evidence'); $c = [string](Get-SIEqValue $p 'canonical')
            if ($e -notmatch '^si_[a-z0-9_]+$' -and -not $caps.Contains($e)) { $why.Add(("group '{0}': on.evidence '{1}' is an SI field or a named capture of an evidence pattern" -f $id, $e)) }
            if ($c -notmatch '^si_[a-z0-9_]+$') { $why.Add(("group '{0}': on.canonical '{1}' is an SI field" -f $id, $c)) }
        }
        return $why.ToArray()
    }
    if ($match -eq 'link') {
        # #693 (3) a manual link on one owner: who and why are recorded; unlink = stage not_used
        if ($st -and $st -notin 'production', 'testing', 'not_used') { $why.Add(("group '{0}': stage '{1}' (production | testing | not_used)" -f $id, $st)) }
        $own = ([string](Get-SIEqValue $Group 'owner')).Trim()
        if (-not $own -or $own.Length -gt 400) { $why.Add(("group '{0}': owner is required -- the CI id (or asset:<id>) the two findings are on" -f $id)) }
        foreach ($n in 'linkedBy', 'reason') { if (-not ([string](Get-SIEqValue $Group $n)).Trim()) { $why.Add(("group '{0}': {1} is required -- a link records who made it and why" -f $id, $n)) } }
        $members = @(Get-SIEqValue $Group 'members') | Where-Object { $null -ne $_ }
        $keys = @($members | ForEach-Object { ([string](Get-SIEqValue $_ 'id')).Trim() })
        if (@($members).Count -lt 2) { $why.Add(("group '{0}': at least two members -- the findings linked into one" -f $id)) }
        if (@($keys | Where-Object { -not $_ }).Count -gt 0) { $why.Add(("group '{0}': every member names its finding key (id)" -f $id)) }
        $cid = ([string](Get-SIEqValue $Group 'canonicalId')).Trim()
        if (-not $cid -or -not (@($keys | Where-Object { $_ -ieq $cid }).Count)) { $why.Add(("group '{0}': canonicalId is one of the members -- the finding that stays" -f $id)) }
        return $why.ToArray()
    }
    $cid = [string](Get-SIEqValue $Group 'canonicalId')
    if (-not $cid.Trim() -or $cid.Length -gt 256) { $why.Add(("group '{0}': canonicalId is required (at most 256 characters) -- the finding key the group is known by" -f $id)) }
    if (-not ([string](Get-SIEqValue $Group 'canonicalTitle')).Trim()) { $why.Add(("group '{0}': canonicalTitle is required" -f $id)) }
    if ($st -and $st -notin 'production', 'testing', 'not_used') { $why.Add(("group '{0}': stage '{1}' (production | testing | not_used)" -f $id, $st)) }
    $members = @(Get-SIEqValue $Group 'members') | Where-Object { $null -ne $_ }
    if (@($members).Count -lt 2) { $why.Add(("group '{0}': at least two members -- one recommendation from two or more providers" -f $id)) }
    $providers = @{}
    foreach ($m in @($members)) {
        $p = [string](Get-SIEqValue $m 'provider'); $mi = [string](Get-SIEqValue $m 'id'); $mt = [string](Get-SIEqValue $m 'title')
        if ($p -notmatch '^[a-z][a-z0-9_\-]{0,40}$') { $why.Add(("group '{0}': a member's provider '{1}' (lower-case name)" -f $id, $p)) }
        if (-not $mi.Trim() -and -not $mt.Trim()) { $why.Add(("group '{0}': a member of {1} names neither an id nor a title" -f $id, $p)) }
        if ($p) { $providers[$p] = 1 }
    }
    if (@($members).Count -ge 2 -and $providers.Count -lt 2) { $why.Add(("group '{0}': its members come from one provider -- the same recommendation across providers needs two" -f $id)) }
    $why.ToArray()
}

function Test-SIRecommendationEquivalence {
    <# PURE. Every group valid, every id / title in one group only. Returns the problems. #>
    param($Document)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Document) { return $why.ToArray() }
    $ids = @{}; $keys = @{}
    foreach ($g in @(Get-SIEqValue $Document 'groups')) {
        if ($null -eq $g) { continue }
        foreach ($x in (Test-SIRecommendationEquivalenceGroup -Group $g)) { $why.Add([string]$x) }
        $gid = [string](Get-SIEqValue $g 'id')
        if ($ids.ContainsKey($gid)) { $why.Add(("recommendation-equivalence: group '{0}' is defined twice" -f $gid)) }; $ids[$gid] = 1
        $gm = Get-SIEqMatch $g
        if ($gm -eq 'fold') { continue }
        if ($gm -eq 'link') {
            # #693 a finding key on one owner is in one ACTIVE manual link (an unlinked one -- not_used -- is history)
            if ([string](Get-SIEqValue $g 'stage') -in 'not_used', 'testing') { continue }
            $own = ([string](Get-SIEqValue $g 'owner')).Trim().ToLowerInvariant()
            foreach ($m in @(Get-SIEqValue $g 'members')) {
                $k = 'link:' + $own + '|' + ([string](Get-SIEqValue $m 'id')).Trim().ToLowerInvariant()
                if ($keys.ContainsKey($k) -and $keys[$k] -ne $gid) { $why.Add(("recommendation-equivalence: {0} is in link '{1}' and in link '{2}' -- a finding is linked once" -f $k, $keys[$k], $gid)) }
                $keys[$k] = $gid
            }
            continue
        }
        foreach ($m in @(Get-SIEqValue $g 'members')) {
            foreach ($k in @(('id:' + ([string](Get-SIEqValue $m 'id')).Trim().ToLowerInvariant()), ('title:' + (Get-SIRecommendationTitleKey ([string](Get-SIEqValue $m 'title')))))) {
                if ($k -in 'id:', 'title:') { continue }
                if ($keys.ContainsKey($k) -and $keys[$k] -ne $gid) { $why.Add(("recommendation-equivalence: {0} is in group '{1}' and in group '{2}' -- a recommendation belongs to one group" -f $k, $keys[$k], $gid)) }
                $keys[$k] = $gid
            }
        }
    }
    $why.ToArray()
}

function ConvertTo-SIRecommendationEquivalenceIndex {
    <#
        PURE. The template (merged) -> @{ ById; ByTitle } (lower-case id / title key -> @{ Group; CanonicalId; CanonicalTitle }).
        Only production groups (no stage = production) merge; testing and not_used groups are left out. A group that is not
        valid is left out (the template check reports it).
    #>
    param($Document)
    $byId = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    $byTitle = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    $byOwner = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)   # #693 manual links: 'owner|key'
    $folds = New-Object System.Collections.Generic.List[object]                                # #693 meaning rules
    foreach ($g in @(Get-SIEqValue $Document 'groups')) {
        if ($null -eq $g) { continue }
        $st = [string](Get-SIEqValue $g 'stage'); if ($st -and $st -ne 'production') { continue }
        if (@(Test-SIRecommendationEquivalenceGroup -Group $g).Count -gt 0) { continue }
        $gm = Get-SIEqMatch $g
        if ($gm -eq 'fold') {
            $cv = { param($list) @(foreach ($c in @($list)) { if ($null -eq $c) { continue }
                        $p = Get-SIEqValue $c 'pattern'
                        @{ Field = [string](Get-SIEqValue $c 'field')
                           Regex = $(if ($null -ne $p) { New-Object System.Text.RegularExpressions.Regex ([string]$p), 'IgnoreCase' } else { $null })
                           EqualsValue = $(if ($null -eq $p) { ConvertTo-SIFindingMatchValue ([string](Get-SIEqValue $c 'equals')) } else { $null }) } }) }
            $folds.Add(@{ Group = [string](Get-SIEqValue $g 'id'); Evidence = (& $cv (Get-SIEqValue $g 'evidence')); Canonical = (& $cv (Get-SIEqValue $g 'canonical'))
                          On = @(foreach ($p in @(Get-SIEqValue $g 'on')) { if ($null -ne $p) { @{ Evidence = [string](Get-SIEqValue $p 'evidence'); Canonical = [string](Get-SIEqValue $p 'canonical') } } }) })
            continue
        }
        if ($gm -eq 'link') {
            $own = ([string](Get-SIEqValue $g 'owner')).Trim()
            $e = @{ Group = [string](Get-SIEqValue $g 'id'); CanonicalId = ([string](Get-SIEqValue $g 'canonicalId')).Trim(); CanonicalTitle = ([string](Get-SIEqValue $g 'canonicalTitle')).Trim()
                    Manual = $true; LinkedBy = [string](Get-SIEqValue $g 'linkedBy'); Reason = [string](Get-SIEqValue $g 'reason') }
            foreach ($m in @(Get-SIEqValue $g 'members')) {
                $k = $own + '|' + ([string](Get-SIEqValue $m 'id')).Trim()
                if (-not $byOwner.ContainsKey($k)) { $byOwner[$k] = $e }
            }
            continue
        }
        $e = @{ Group = [string](Get-SIEqValue $g 'id'); CanonicalId = ([string](Get-SIEqValue $g 'canonicalId')).Trim(); CanonicalTitle = ([string](Get-SIEqValue $g 'canonicalTitle')).Trim() }
        # the canonical id itself maps onto its group (a provider that already reports it)
        if (-not $byId.ContainsKey($e.CanonicalId)) { $byId[$e.CanonicalId] = $e }
        foreach ($m in @(Get-SIEqValue $g 'members')) {
            $mi = ([string](Get-SIEqValue $m 'id')).Trim(); $mt = Get-SIRecommendationTitleKey ([string](Get-SIEqValue $m 'title'))
            if ($mi -and -not $byId.ContainsKey($mi)) { $byId[$mi] = $e }
            if ($mt -and -not $byTitle.ContainsKey($mt)) { $byTitle[$mt] = $e }
        }
    }
    @{ ById = $byId; ByTitle = $byTitle; ByOwner = $byOwner; Folds = $folds.ToArray() }
}

function Resolve-SIRecommendationKey {
    <#
        PURE. A finding key + title -> its group entry (@{ Group; CanonicalId; CanonicalTitle }) or $null. The id wins over
        the title. #693 -Owner (the CI id or asset:<id>): an operator's manual link on that owner wins over both.
    #>
    param($Index, [AllowEmptyString()][string]$Key, [AllowEmptyString()][AllowNull()][string]$Title, [AllowEmptyString()][AllowNull()][string]$Owner = '')
    if ($null -eq $Index) { return $null }
    if ($Owner -and $Key -and $Index.ByOwner -and $Index.ByOwner.Count -gt 0) {
        $ok = $Owner + '|' + $Key.Trim()
        if ($Index.ByOwner.ContainsKey($ok)) { return $Index.ByOwner[$ok] }
    }
    if ($Key -and $Index.ById.ContainsKey($Key.Trim())) { return $Index.ById[$Key.Trim()] }
    $t = Get-SIRecommendationTitleKey $Title
    if ($t -and $Index.ByTitle.ContainsKey($t)) { return $Index.ByTitle[$t] }
    $null
}

function Get-SIFindingFieldValues {
    <# PURE. A finding's generic SI field as a list of raw text values (an array field gives each element; '' left out). #>
    param($Finding, [string]$Field)
    $v = Get-SIEqValue $Finding $Field
    if ($null -eq $v) { return @() }
    $vals = if ($v -is [string]) { @($v) } elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [System.Collections.IDictionary])) { @($v) } else { @([string]$v) }
    @($vals | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
}

function Test-SIFindingFoldSide {
    <#
        PURE. Does a finding meet every condition of one side of a fold rule? Returns $null (no) or a hashtable of the
        normalised named captures of its patterns (yes; empty when the side captures nothing).
    #>
    param($Finding, [object[]]$Conditions)
    $caps = @{}
    foreach ($c in @($Conditions)) {
        $vals = @(Get-SIFindingFieldValues $Finding $c.Field)
        $hit = $false
        foreach ($v in $vals) {
            if ($null -ne $c.Regex) {
                $m = $c.Regex.Match($v)
                if ($m.Success) {
                    $hit = $true
                    foreach ($n in $c.Regex.GetGroupNames()) { if ($n -notmatch '^\d+$' -and $m.Groups[$n].Success) { $caps[$n] = ConvertTo-SIFindingMatchValue $m.Groups[$n].Value } }
                    break
                }
            } elseif ((ConvertTo-SIFindingMatchValue $v) -eq $c.EqualsValue) { $hit = $true; break }
        }
        if (-not $hit) { return $null }
    }
    $caps
}

function Merge-SIFindingFolds {
    <#
        PURE. #693 (7) / (8) -- the meaning rules (the index's Folds) over one batch of SI findings (ConvertTo-SIFindingRows'
        output; every finding of a CI in the same batch). Per owner (si_ci_id, else asset:<si_asset_id>): a finding meeting
        a rule's evidence side whose 'on' values meet a canonical-side finding (not itself) is folded -- it is no finding of
        its own; on EVERY canonical it met: si_finding_evidence gains it (report, key, title, severity, rule) after the
        canonical's own entry, si_detected_by gains its reports; on the FIRST canonical (by key) its key and its aliases are
        aliases, so its lifecycle row carries over. A finding that received evidence is never folded itself (no chain). The
        canonical's key, title, severity and exemption stay its own. Returns the findings left, in their order.
    #>
    param([AllowEmptyCollection()][object[]]$Findings = @(), [object[]]$Folds = @())
    if (@($Folds).Count -eq 0 -or @($Findings).Count -lt 2) { return @($Findings) }
    $byOwner = [ordered]@{}
    for ($i = 0; $i -lt $Findings.Count; $i++) {
        $f = $Findings[$i]; if ($null -eq $f) { continue }
        $o = [string](Get-SIEqValue $f 'si_ci_id'); if (-not $o) { $o = 'asset:' + [string](Get-SIEqValue $f 'si_asset_id') }
        if (-not $byOwner.Contains($o)) { $byOwner[$o] = New-Object System.Collections.Generic.List[int] }
        $byOwner[$o].Add($i)
    }
    $folded = New-Object 'System.Collections.Generic.HashSet[int]'
    $target = New-Object 'System.Collections.Generic.HashSet[int]'
    $ev = { param($x) [ordered]@{ report = [string](Get-SIEqValue $x 'si_report_name'); key = [string](Get-SIEqValue $x 'si_finding_key'); title = [string](Get-SIEqValue $x 'si_title'); severity = [string](Get-SIEqValue $x 'si_severity') } }
    foreach ($o in $byOwner.Keys) {
        $ix = $byOwner[$o]; if ($ix.Count -lt 2) { continue }
        foreach ($rule in @($Folds)) {
            $canon = @(foreach ($i in $ix) { if ($folded.Contains($i)) { continue }; $c = Test-SIFindingFoldSide -Finding $Findings[$i] -Conditions $rule.Canonical; if ($null -ne $c) { $i } })
            if ($canon.Count -eq 0) { continue }
            $canon = @($canon | Sort-Object { [string](Get-SIEqValue $Findings[$_] 'si_finding_key') })
            foreach ($i in $ix) {
                if ($folded.Contains($i) -or $target.Contains($i)) { continue }
                $caps = Test-SIFindingFoldSide -Finding $Findings[$i] -Conditions $rule.Evidence
                if ($null -eq $caps) { continue }
                $hits = @(foreach ($t in $canon) {
                        if ($t -eq $i -or $folded.Contains($t)) { continue }
                        $ok = $true
                        foreach ($p in @($rule.On)) {
                            $left = if ($caps.ContainsKey($p.Evidence)) { @($caps[$p.Evidence]) } else { @(Get-SIFindingFieldValues $Findings[$i] $p.Evidence | ForEach-Object { ConvertTo-SIFindingMatchValue $_ }) }
                            $right = @(Get-SIFindingFieldValues $Findings[$t] $p.Canonical | ForEach-Object { ConvertTo-SIFindingMatchValue $_ })
                            if (@($left | Where-Object { $_ -and $_ -in $right }).Count -eq 0) { $ok = $false; break }
                        }
                        if ($ok) { $t }
                    })
                if ($hits.Count -eq 0) { continue }
                [void]$folded.Add($i)
                $e = $Findings[$i]
                $eEntry = & $ev $e; $eEntry['rule'] = $rule.Group
                $first = $true
                foreach ($t in $hits) {
                    [void]$target.Add($t)
                    $c = $Findings[$t]
                    $list = New-Object System.Collections.Generic.List[object]
                    $cur = @(Get-SIEqValue $c 'si_finding_evidence') | Where-Object { $null -ne $_ }
                    if (@($cur).Count -eq 0) { $list.Add((& $ev $c)) } else { foreach ($x in $cur) { $list.Add($x) } }
                    foreach ($x in @(Get-SIEqValue $e 'si_finding_evidence') | Where-Object { $null -ne $_ }) { if ([string](Get-SIEqValue $x 'key') -ne $eEntry.key) { $list.Add($x) } }
                    $list.Add($eEntry)
                    $c | Add-Member -NotePropertyName 'si_finding_evidence' -NotePropertyValue $list.ToArray() -Force
                    $det = New-Object System.Collections.Generic.List[string]
                    foreach ($d in @(Get-SIFindingFieldValues $c 'si_detected_by') + @(Get-SIFindingFieldValues $e 'si_detected_by')) { if (-not $det.Contains($d)) { $det.Add($d) } }
                    $c | Add-Member -NotePropertyName 'si_detected_by' -NotePropertyValue $det.ToArray() -Force
                    if ($first) {
                        $al = New-Object System.Collections.Generic.List[string]
                        foreach ($a in @(Get-SIFindingFieldValues $c 'si_finding_aliases') + @($eEntry.key) + @(Get-SIFindingFieldValues $e 'si_finding_aliases')) { if ($a -and $a -ne [string](Get-SIEqValue $c 'si_finding_key') -and -not $al.Contains($a)) { $al.Add($a) } }
                        $c | Add-Member -NotePropertyName 'si_finding_aliases' -NotePropertyValue $al.ToArray() -Force
                        $first = $false
                    }
                }
            }
        }
    }
    if ($folded.Count -eq 0) { return @($Findings) }
    @(for ($i = 0; $i -lt $Findings.Count; $i++) { if (-not $folded.Contains($i)) { $Findings[$i] } })
}

function Get-SIRecommendationEquivalence {
    <#
        The merged template (shipped + the customer's: Pro's exported data model or Community's custom file) as an index;
        $null when there is none or it cannot be read -- findings are then keyed as the providers report them (never fails).
    #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot)
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $r = Get-SIDataModelRoot $Root
        if (-not (Test-Path -LiteralPath (Join-Path $r 'recommendation-equivalence.locked.json'))) {
            # Pro: an exported data model from before this template was published -- the shipped template (no override yet)
            $shipped = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
            if (-not (Test-Path -LiteralPath (Join-Path $shipped 'recommendation-equivalence.locked.json'))) { return $null }
            $r = $shipped
        }
        $t = Get-SIDataModelTemplate -Name 'recommendation-equivalence' -Root $r -OverlayRoot $OverlayRoot
        foreach ($p in (Test-SIRecommendationEquivalence -Document $t.Document)) { Write-Warning ("recommendation equivalence: {0} -- that group is not applied" -f $p) }
        return (ConvertTo-SIRecommendationEquivalenceIndex -Document $t.Document)
    } catch {
        Write-Warning ("recommendation equivalence could not be read -- {0}. Findings are keyed as each provider reports them." -f $_.Exception.Message)
        return $null
    }
}
