#Requires -Version 5.1
<#
    M4's PROOF (V3-DATA-MODEL 2.15 "same day scored old vs new; deltas explained"): the same finding rows scored in the
    'legacy' data model (the CI context on top of the report's own values) and in the 'ci' data model (the CI decides tier,
    asset risk factors, criticality factor and CMDB values), row by row, with EVERY difference explained:

      tier            the CI's tier replaced the report's (probability base)
      asset factors   a factor the report derived from provider columns, replaced by the CI's evaluation (dropped), or a
                      CI factor the report did not compute (added) -- incl. a factor counted twice under two names
      weight          the CI's criticality factor replaced the report's own weighting
      CMDB values     the CI's owning-CMDB values replaced the report's

    A score that moved with none of these is UNEXPLAINED -- the comparison fails on it. Needs Add-RACiContext
    (RA-CiContext.ps1) and a -Score scriptblock that runs Calculate-RiskScore with the report's parameters.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

function ConvertTo-RAModelTokenSet {
    param([string]$Text)
    $h = @{}
    foreach ($t in @(([string]$Text) -split '\s*;\s*' | Where-Object { $_ })) { $h[(ConvertTo-RATokenKey $t)] = $t }
    return $h
}

function Compare-RADataModelScores {
    <#
    .SYNOPSIS  Rows scored legacy vs ci -> one result per row: scores, weighted scores, tiers, the reasons, Unexplained.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Index,
        [Parameter(Mandatory)][hashtable]$Catalog,
        # param($Rows) -> the scored rows (Calculate-RiskScore with the report's input names; keep the input order)
        [Parameter(Mandatory)][scriptblock]$Score
    )
    $legacyIn = New-Object System.Collections.Generic.List[object]
    $ciIn = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $n++
        $a = $r.PSObject.Copy(); Add-Member -InputObject $a -NotePropertyName 'si_cmp_row' -NotePropertyValue $n -Force; $legacyIn.Add($a)
        $b = $r.PSObject.Copy(); Add-Member -InputObject $b -NotePropertyName 'si_cmp_row' -NotePropertyValue $n -Force; $ciIn.Add($b)
    }
    $legacyCtx = Add-RACiContext -Rows $legacyIn.ToArray() -Index $Index -Mode legacy -Catalog $Catalog      # returns the array whole (, @($Rows))
    $ciCtx = Add-RACiContext -Rows $ciIn.ToArray() -Index $Index -Mode ci -Catalog $Catalog
    $ls = @{}; foreach ($x in @(& $Score $legacyCtx)) { $ls[[int]$x.si_cmp_row] = $x }
    $cs = @{}; foreach ($x in @(& $Score $ciCtx)) { $cs[[int]$x.si_cmp_row] = $x }
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 1; $i -le $n; $i++) {
        $lr = $ls[$i]; $cr = $cs[$i]
        if ($null -eq $lr -or $null -eq $cr) { continue }
        $reasons = New-Object System.Collections.Generic.List[string]
        $tierL = [string]$lr.CriticalityTierLevel; $tierC = [string]$cr.CriticalityTierLevel
        if ($tierL -ne $tierC) { $reasons.Add(('tier: {0} -> {1} (the CI''s tier)' -f $tierL, $tierC)) }
        foreach ($axis in 'Probability', 'Consequence') {
            $tl = ConvertTo-RAModelTokenSet ([string]$lr.('RiskFactor_{0}_Detailed' -f $axis))
            $tc = ConvertTo-RAModelTokenSet ([string]$cr.('RiskFactor_{0}_Detailed' -f $axis))
            foreach ($k in @($tl.Keys)) {
                if ($tc.ContainsKey($k)) { continue }
                $why = 'not set on the CI'
                if ($Catalog.AssetKeys.ContainsKey($k)) {
                    $fid = $Catalog.AssetKeys[$k]
                    $twin = @($tc.Keys | Where-Object { $Catalog.AssetKeys.ContainsKey($_) -and $Catalog.AssetKeys[$_] -eq $fid })
                    if ($twin.Count) { $why = ('the same factor ({0}) is counted once' -f $fid) }
                }
                $reasons.Add(('{0} factor dropped: {1} -- {2}' -f $axis.ToLowerInvariant(), $tl[$k], $why))
            }
            foreach ($k in @($tc.Keys)) { if (-not $tl.ContainsKey($k)) { $reasons.Add(('{0} factor added: {1} -- the CI''s evaluation' -f $axis.ToLowerInvariant(), $tc[$k])) } }
        }
        $wl = [string]$lr.RiskFactor_Weight; $wc = [string]$cr.RiskFactor_Weight
        if ($wl -ne $wc) { $reasons.Add(('weight: {0} -> {1} (the CI''s criticality factor)' -f $(if ($wl) { $wl } else { '100' }), $(if ($wc) { $wc } else { '100' }))) }
        foreach ($f in 'cmdbId', 'cmdbCriticality', 'cmdbDataSensitivity') {
            if ([string]$lr.$f -ne [string]$cr.$f) { $reasons.Add(('{0}: {1} -> {2} (the owning CMDB''s value on the CI)' -f $f, [string]$lr.$f, [string]$cr.$f)) }
        }
        $moved = ([double]$lr.RiskScoreTotal -ne [double]$cr.RiskScoreTotal) -or ([double]$lr.RiskScoreTotal_Weighted -ne [double]$cr.RiskScoreTotal_Weighted)
        $out.Add([pscustomobject][ordered]@{
                Row = $i; Asset = [string]$(if ($cr.AssetName) { $cr.AssetName } else { $cr.SI_AssetName }); Report = [string]$cr.AssetDetectedInReportName
                CiId = [string]$cr.si_ci_id
                LegacyScore = [double]$lr.RiskScoreTotal; CiScore = [double]$cr.RiskScoreTotal
                LegacyWeighted = [double]$lr.RiskScoreTotal_Weighted; CiWeighted = [double]$cr.RiskScoreTotal_Weighted
                LegacyRating = [string]$lr.RiskRating; CiRating = [string]$cr.RiskRating
                Moved = $moved; Reasons = $reasons.ToArray(); Unexplained = ($moved -and $reasons.Count -eq 0)
            })
    }
    return $out.ToArray()      # unrolled: callers wrap in @()
}

function ConvertTo-RAModelCompareMarkdown {
    <# PURE. The comparison as a report: totals, every moved row with its reasons, and any unexplained one. #>
    param([AllowEmptyCollection()][object[]]$Results = @(), [string]$Title = 'Risk Analysis: legacy vs CI data model')
    $moved = @($Results | Where-Object { $_.Moved })
    $unexpl = @($Results | Where-Object { $_.Unexplained })
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("# $Title").AppendLine()
    [void]$sb.AppendLine(('{0} row(s) compared; {1} moved; {2} unexplained.' -f @($Results).Count, $moved.Count, $unexpl.Count)).AppendLine()
    if ($moved.Count) {
        [void]$sb.AppendLine('| row | asset | CI | score legacy -> ci | weighted legacy -> ci | rating | why |').AppendLine('|---|---|---|---|---|---|---|')
        foreach ($m in $moved) {
            [void]$sb.AppendLine(('| {0} | {1} | {2} | {3} -> {4} | {5} -> {6} | {7} -> {8} | {9} |' -f $m.Row, $m.Asset, $m.CiId, $m.LegacyScore, $m.CiScore, $m.LegacyWeighted, $m.CiWeighted, $m.LegacyRating, $m.CiRating, ((@($m.Reasons) -join '; ') -replace '\|', '/')))
        }
    }
    return $sb.ToString()
}
