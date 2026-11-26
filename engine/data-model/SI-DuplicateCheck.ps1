#Requires -Version 5.1
<#
    SecurityInsight -- THE DUPLICATE CHECK (REQUIREMENTS #693 (6) / (9), #688 the overlap check; owner 2026-11-25: "you cannot
    have 2 identical recommendations; only one" / "we cannot have 2 similar tasks" / "this is in the category data quality and
    very bad as it creates redundant tasks everywhere").

    One weakness reported by two providers or two reports is ONE finding (the recommendation equivalence, #464 / #693:
    SI-RecommendationEquivalence.ps1). A weakness that is still TWO findings after the findings were folded and linked is a
    DEFECT -- this check makes it visible. It never merges, changes or removes anything itself, and it never blocks a run.

    THE RULES -- the SAME rules the findings are merged by, read from the same template (only production groups), compared on
    the generic si_* fields after mapping (#693 (7b): never a provider's column):
      fold:<group>   a finding the meaning rule <group> would fold (its evidence side meets a canonical finding of the same CI)
                     is still a finding of its own -- e.g. Defender for Cloud "Update openssl" next to the CVE findings whose
                     si_affected_product is openssl. Worked out by the engine's own Merge-SIFindingFolds on a copy: whatever it
                     would still fold is a duplicate, so the check can never disagree with the fold.
      key            two findings of one CI whose keys / titles belong to the same equivalence group (the same control from
                     two providers) are still two findings.
      link           two findings an operator linked into one (a manual link on that CI) are still two findings.
      same-cve       one CI carries the same CVE (si_cve, or the key when it is a CVE id) in two findings.
    The remediation tasks have their own rule (task-update-restates-software, the Pro data sync: SI-DataDuplicateCheck.ps1).

    A finding that is a canonical finding of a fold already (it carries fold evidence) is never counted as a duplicate of
    another fold: the fold does not chain.

    PURE. PowerShell 5.1 and 7: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Merge-SIFindingFolds -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-RecommendationEquivalence.ps1') }

function Get-SIDuplicateValue {
    <# PURE. A named value of a finding (object, dictionary or data row); DBNull = $null. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    $x = $null
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { $x = $Item[$Name] } }
    elseif ($Item -is [System.Data.DataRow]) { if ($Item.Table.Columns.Contains($Name)) { $x = $Item[$Name] } }
    else { $p = $Item.PSObject.Properties[$Name]; if ($p) { $x = $p.Value } }
    if ($x -is [System.DBNull]) { return $null }
    $x
}

function Get-SIDuplicateOwner {
    <# PURE. The owner a finding belongs to: its CI id, else 'asset:<asset id>' (the finding lifecycle's owner). #>
    param($Finding)
    $o = [string](Get-SIDuplicateValue $Finding 'si_ci_id')
    if ($o) { return $o }
    'asset:' + [string](Get-SIDuplicateValue $Finding 'si_asset_id')
}

function Get-SIDuplicateCve {
    <# PURE. The CVE a finding is about: si_cve, else its key when the key is a CVE id; '' for none. Upper case. #>
    param($Finding)
    $c = ([string](Get-SIDuplicateValue $Finding 'si_cve')).Trim()
    if (-not $c) { $k = ([string](Get-SIDuplicateValue $Finding 'si_finding_key')).Trim(); if ($k -match '^(?i)CVE-\d{4}-\d+$') { $c = $k } }
    if ($c -notmatch '^(?i)CVE-\d{4}-\d+$') { return '' }
    $c.ToUpperInvariant()
}

function Test-SIDuplicateFoldTarget {
    <# PURE. Does a stored finding already carry fold evidence (an evidence entry with a rule) -- a canonical finding of a fold? #>
    param($Finding)
    $flag = Get-SIDuplicateValue $Finding '_si_fold_target'
    if ($null -ne $flag) { return [bool]$flag }
    foreach ($e in @(Get-SIDuplicateValue $Finding 'si_finding_evidence')) { if ($null -ne $e -and [string](Get-SIDuplicateValue $e 'rule')) { return $true } }
    $false
}

function New-SIDuplicateItem {
    <# PURE. One duplicate: the rule, the CI, the finding that should not be one of its own, and what it duplicates. #>
    param([string]$Rule, [string]$Kind, $Finding, [object[]]$Onto = @(), [string]$Value = '')
    $first = $null; if (@($Onto).Count) { $first = @($Onto)[0] }
    [pscustomobject][ordered]@{
        Rule = $Rule; Kind = $Kind; Owner = (Get-SIDuplicateOwner $Finding)
        CiName = [string](Get-SIDuplicateValue $Finding '_ci_name')
        Key = [string](Get-SIDuplicateValue $Finding 'si_finding_key'); Title = [string](Get-SIDuplicateValue $Finding 'si_title')
        Report = [string](Get-SIDuplicateValue $Finding 'si_report_name')
        OntoKey = $(if ($first) { [string](Get-SIDuplicateValue $first 'si_finding_key') } else { '' })
        OntoTitle = $(if ($first) { [string](Get-SIDuplicateValue $first 'si_title') } else { '' })
        Onto = @($Onto).Count; Value = $Value
    }
}

function Find-SIDuplicateFindings {
    <#
    .SYNOPSIS  PURE. The findings that are still two where the merge rules make one (see the file header). -Findings: SI findings
               (si_ci_id / si_asset_id, si_finding_key, si_title, si_finding_type, si_cve and the si fields the rules read) --
               EVERY finding of a CI in the same call. -Index: ConvertTo-SIRecommendationEquivalenceIndex of the merged
               template (production groups only). Returns one item per duplicate (New-SIDuplicateItem); nothing is changed.
    #>
    param([AllowEmptyCollection()][object[]]$Findings = @(), $Index)
    $out = New-Object System.Collections.Generic.List[object]
    $list = @($Findings | Where-Object { $null -ne $_ })
    if ($list.Count -lt 2) { return @() }

    # fold:<group> -- what the engine's own fold would STILL fold on these findings
    if ($null -ne $Index -and $Index.Folds -and @($Index.Folds).Count) {
        $copies = @(for ($i = 0; $i -lt $list.Count; $i++) {
                $c = [pscustomobject]@{}
                if ($list[$i] -is [System.Collections.IDictionary]) { foreach ($k in $list[$i].Keys) { $c | Add-Member -NotePropertyName ([string]$k) -NotePropertyValue $list[$i][$k] -Force } }
                else { foreach ($p in $list[$i].PSObject.Properties) { $c | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force } }
                $c | Add-Member -NotePropertyName _dup_i -NotePropertyValue $i -Force
                $c })
        $left = @(Merge-SIFindingFolds -Findings $copies -Folds @($Index.Folds))
        if ($left.Count -lt $copies.Count) {
            $keep = New-Object 'System.Collections.Generic.HashSet[int]'
            foreach ($x in $left) { [void]$keep.Add([int]$x._dup_i) }
            # per folded finding: the findings whose NEW evidence names it (the canonical side it met)
            $onto = @{}
            foreach ($x in $left) {
                foreach ($e in @(Get-SIEqValue $x 'si_finding_evidence')) {
                    if ($null -eq $e) { continue }
                    $r = [string](Get-SIEqValue $e 'rule'); if (-not $r) { continue }
                    $k = (Get-SIDuplicateOwner $x) + [char]31 + [string](Get-SIEqValue $e 'key')
                    if (-not $onto.ContainsKey($k)) { $onto[$k] = @{ Rule = $r; List = (New-Object System.Collections.Generic.List[object]) } }
                    if (-not $onto[$k].List.Contains($list[[int]$x._dup_i])) { $onto[$k].List.Add($list[[int]$x._dup_i]) }
                }
            }
            for ($i = 0; $i -lt $list.Count; $i++) {
                if ($keep.Contains($i)) { continue }
                $f = $list[$i]
                # a canonical finding of a fold already is never folded again (no chain), whatever this pass does with it
                if (Test-SIDuplicateFoldTarget $f) { continue }
                $k = (Get-SIDuplicateOwner $f) + [char]31 + [string](Get-SIDuplicateValue $f 'si_finding_key')
                if (-not $onto.ContainsKey($k)) { continue }
                $out.Add((New-SIDuplicateItem -Rule ('fold:' + $onto[$k].Rule) -Kind 'fold' -Finding $f -Onto $onto[$k].List.ToArray()))
            }
        }
    }

    # key / link -- two findings of one CI that the equivalence makes one, still two
    if ($null -ne $Index) {
        $groups = @{}
        foreach ($f in $list) {
            $own = Get-SIDuplicateOwner $f
            $e = Resolve-SIRecommendationKey -Index $Index -Key ([string](Get-SIDuplicateValue $f 'si_finding_key')) -Title ([string](Get-SIDuplicateValue $f 'si_title')) -Owner $own
            if ($null -eq $e) { continue }
            $gk = $own + '|' + [string]$e.Group
            if (-not $groups.ContainsKey($gk)) { $groups[$gk] = @{ Entry = $e; Findings = (New-Object System.Collections.Generic.List[object]) } }
            $groups[$gk].Findings.Add($f)
        }
        foreach ($gk in @($groups.Keys | Sort-Object)) {
            $g = $groups[$gk]
            $byKey = [ordered]@{}
            foreach ($f in $g.Findings) { $k = ([string](Get-SIDuplicateValue $f 'si_finding_key')).Trim().ToLowerInvariant(); if (-not $byKey.Contains($k)) { $byKey[$k] = $f } }
            if ($byKey.Count -lt 2) { continue }
            $cid = ([string]$g.Entry.CanonicalId).Trim().ToLowerInvariant()
            $stay = $(if ($byKey.Contains($cid)) { $byKey[$cid] } else { $byKey[@($byKey.Keys | Sort-Object)[0]] })
            $kind = $(if ($g.Entry.Manual) { 'link' } else { 'key' })
            foreach ($k in @($byKey.Keys)) {
                if ([object]::ReferenceEquals($byKey[$k], $stay)) { continue }
                $out.Add((New-SIDuplicateItem -Rule $kind -Kind $kind -Finding $byKey[$k] -Onto @($stay) -Value ([string]$g.Entry.Group)))
            }
        }
    }

    # same-cve -- one CI, one CVE, two findings
    $cves = @{}
    foreach ($f in $list) {
        $c = Get-SIDuplicateCve $f; if (-not $c) { continue }
        $ck = (Get-SIDuplicateOwner $f) + '|' + $c
        if (-not $cves.ContainsKey($ck)) { $cves[$ck] = [ordered]@{} }
        $k = ([string](Get-SIDuplicateValue $f 'si_finding_key')).Trim().ToLowerInvariant()
        if (-not $cves[$ck].Contains($k)) { $cves[$ck][$k] = $f }
    }
    foreach ($ck in @($cves.Keys | Sort-Object)) {
        $m = $cves[$ck]; if ($m.Count -lt 2) { continue }
        $c = $ck.Substring($ck.LastIndexOf('|') + 1)
        # the finding keyed by the CVE itself stays; every other one is the duplicate
        $stay = $(if ($m.Contains($c.ToLowerInvariant())) { $m[$c.ToLowerInvariant()] } else { $m[@($m.Keys | Sort-Object)[0]] })
        foreach ($k in @($m.Keys)) { if (-not [object]::ReferenceEquals($m[$k], $stay)) { $out.Add((New-SIDuplicateItem -Rule 'same-cve' -Kind 'cve' -Finding $m[$k] -Onto @($stay) -Value $c)) } }
    }
    $out.ToArray()
}

function Get-SIDuplicateRuleLabel {
    <# PURE. A rule as a person reads it. #>
    param([string]$Rule)
    if ($Rule -like 'fold:*') { return ('Duplicates not merged: a finding the rule ''{0}'' folds into another finding of the same asset is still a finding of its own' -f $Rule.Substring(5)) }
    switch ($Rule) {
        'key' { return 'Duplicates not merged: the same recommendation from two providers is still two findings on one asset' }
        'link' { return 'Duplicates not merged: findings an operator linked into one are still two findings on one asset' }
        'same-cve' { return 'Duplicates not merged: the same CVE is two findings on one asset' }
        'task-update-restates-software' { return 'Duplicates not merged: an "Update <software>" task next to the task that updates that software on the same asset' }
    }
    'Duplicates not merged: ' + $Rule
}

function Get-SIDuplicateMetricKey {
    <# PURE. The data-quality key number of a rule: 'dup.<rule>' (a fold rule: 'dup.fold.<group>'). #>
    param([string]$Rule)
    'dup.' + ($Rule -replace ':', '.')
}

function Format-SIDuplicateExample {
    <# PURE. One duplicate as a person reads it: "<CI>: '<title>' [<key>] next to '<title>' [<key>] (+N more)". #>
    param($Item)
    $ci = $(if ($Item.CiName) { [string]$Item.CiName } else { [string]$Item.Owner })
    $more = $(if ([int]$Item.Onto -gt 1) { (' (+{0} more)' -f ([int]$Item.Onto - 1)) } else { '' })
    "{0}: '{1}' [{2}] next to '{3}' [{4}]{5}" -f $ci, $Item.Title, $Item.Key, $Item.OntoTitle, $Item.OntoKey, $more
}
