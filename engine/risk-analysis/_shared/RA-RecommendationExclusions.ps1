#Requires -Version 5.1
<#
    #546 (5) -- known false positives of a provider's recommendation, suppressed by the data model's default rules
    (data-model/recommendation-exclusions.locked.json, engine/data-model/SI-RecommendationExclusions.ps1), after each row is
    tied to its CI (Add-RACiContext sets si_ci_id). A suppressed row is left out of the report and counted per rule, with
    the rule's reason, in the run log. A row whose CI is not known is never suppressed. No rule = rows pass unchanged.
    PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Find-SIRecommendationExclusion -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'data-model', 'SI-RecommendationExclusions.ps1'))
}

function Get-RARecommendationExclusionIndex {
    <# The run's rule index (read once, cached). #>
    if ($null -eq $script:_RARecExclIndex) { $script:_RARecExclIndex = Get-SIRecommendationExclusions }
    return $script:_RARecExclIndex
}

function Select-RARecommendationExclusions {
    <#
    .SYNOPSIS  PURE given -Index and -CiIndex. Rows -> @{ Rows = kept rows; Suppressed = ordered rule id -> @{ Count; Reason } }.
    .PARAMETER ConfigurationColumn  the report's ConfigurationId column (ConfigurationIdInputName)
    .PARAMETER CiIndex  the run's CI index (Get-RACiIndex): the row's si_ci_id -> its CI
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [string]$ReportName, [string]$ConfigurationColumn = 'ConfigurationId',
          [hashtable]$Index, [hashtable]$CiIndex)
    $sup = [ordered]@{}
    if ($null -eq $Index -or $Index.Count -eq 0 -or $null -eq $CiIndex -or $null -eq $CiIndex.ById) { return @{ Rows = @($Rows); Suppressed = $sup } }
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $cidP = $r.PSObject.Properties[$ConfigurationColumn]; $ciP = $r.PSObject.Properties['si_ci_id']
        $ci = $null
        if ($ciP -and $ciP.Value) { $k = ([string]$ciP.Value).Trim().ToLowerInvariant(); if ($CiIndex.ById.ContainsKey($k)) { $ci = $CiIndex.ById[$k] } }
        $rule = $null
        if ($cidP -and $ci) { $rule = Find-SIRecommendationExclusion -Index $Index -ConfigurationId ([string]$cidP.Value) -ReportName $ReportName -Ci $ci }
        if ($null -eq $rule) { $kept.Add($r); continue }
        if (-not $sup.Contains($rule.Id)) { $sup[$rule.Id] = @{ Count = 0; Reason = $rule.Reason } }
        $sup[$rule.Id].Count++
    }
    return @{ Rows = $kept.ToArray(); Suppressed = $sup }
}

function Format-RARecommendationExclusionLines {
    <# PURE. One run-log line per rule that suppressed findings in this report. #>
    param([string]$ReportName, $Suppressed)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Suppressed) { return $out.ToArray() }
    foreach ($id in @($Suppressed.Keys)) {
        $out.Add(('{0}: {1} finding(s) left out by the default exclusion rule {2} -- {3}' -f $ReportName, $Suppressed[$id].Count, $id, $Suppressed[$id].Reason))
    }
    return $out.ToArray()
}
