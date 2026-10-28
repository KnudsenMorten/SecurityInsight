#Requires -Version 5.1
<#
    SecurityInsight -- KNOWN FALSE POSITIVES OF A PROVIDER'S RECOMMENDATION (#546 (5)).

    A Microsoft-sourced recommendation that is wrong in a stated situation (the customer case: a password recommendation
    for accounts whose password lives in Active Directory) is suppressed by a DEFAULT RULE in the data model, with its
    reason -- never by disabling the report, never by a hand-made exclusion list.

    TEMPLATE  data-model/recommendation-exclusions.locked.json (kind 'recommendation-exclusion', items 'rules'):
                { "id": "<rule id>",
                  "configurationIds": [ "<the Risk Analysis row's ConfigurationId>", ... ],   (one or more, exact, case-insensitive)
                  "reports": [ "<ReportName>", ... ],                                         (optional; none = every report)
                  "when": { <condition over the finding's CI, SI fields only> },               (SI-Conditions.ps1 language)
                  "reason": "<why the recommendation is wrong in that situation>",             (required -- it is logged)
                  "reference": "<the provider's documentation>",                              (optional)
                  "stage": "production" | "testing" | "not_used" }                            (default production)
    CUSTOMER  Pro: one cfg.ItemOverride row per rule ('recommendation-exclusions:<id>' -- override, disable or add);
              Community: data-model/recommendation-exclusions.custom.json, the same shape, only the rules that differ.
              Both through the data-model merge (Get-SIDataModelTemplate).
    APPLIED   Risk Analysis, after each row is tied to its CI (RA-RecommendationExclusions.ps1): a row whose ConfigurationId
              a production rule names, in a report the rule covers, whose CI meets the rule's condition, is left out and
              counted per rule (with the reason) in the run log. A row without a known CI is never suppressed: an
              exclusion that cannot be checked must not hide a finding.

    PURE except Get-SIRecommendationExclusions (reads the template). PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Test-SICondition -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

function Test-SIRecommendationExclusionRule {
    <# PURE. The reasons one rule is not accepted (empty = accepted). #>
    param($Rule)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Rule) { $why.Add('a rule is empty'); return $why.ToArray() }
    $id = [string](Get-SIItemValue $Rule 'id')
    if ($id -notmatch '^[a-z0-9][a-z0-9_\-\.]{0,99}$') { $why.Add(("rule id '{0}': lower-case letters, digits, - _ . (at most 100)" -f $id)) }
    $ids = @(@(Get-SIItemValue $Rule 'configurationIds') | Where-Object { $_ -and ([string]$_).Trim() })
    if ($ids.Count -eq 0) { $why.Add(("rule '{0}': configurationIds names at least one recommendation id" -f $id)) }
    if (-not ([string](Get-SIItemValue $Rule 'reason')).Trim()) { $why.Add(("rule '{0}': a reason is required -- it is what the run log says" -f $id)) }
    $st = [string](Get-SIItemValue $Rule 'stage')
    if ($st -and $st -notin 'production', 'testing', 'not_used') { $why.Add(("rule '{0}': stage '{1}' (production | testing | not_used)" -f $id, $st)) }
    $when = Get-SIItemValue $Rule 'when'
    if ($null -eq $when) { $why.Add(("rule '{0}': a condition (when) is required -- a rule states the situation it holds in" -f $id)) }
    else {
        $ops = Get-SIConditionOps
        foreach ($leafField in (Get-SIConditionFields $when)) {
            if ($leafField -notmatch '^si_[a-z0-9_]+$') { $why.Add(("rule '{0}': reads '{1}' -- a rule reads SI fields (si_*) only" -f $id, $leafField)) }
        }
        $stack = New-Object System.Collections.Generic.Stack[object]; $stack.Push($when)
        while ($stack.Count -gt 0) {
            $c = $stack.Pop()
            $isGroup = $false
            foreach ($k in 'all', 'any') {
                $has = ($c -is [System.Collections.IDictionary] -and $c.Contains($k)) -or ($null -ne $c -and $c.PSObject.Properties[$k])
                if ($has) { $isGroup = $true; foreach ($x in (Get-SIValueList (Get-SIItemValue $c $k))) { $stack.Push($x) } }
            }
            if (-not $isGroup) { $op = [string](Get-SIItemValue $c 'op'); if ($ops -notcontains $op) { $why.Add(("rule '{0}': unknown condition operation '{1}'" -f $id, $op)) } }
        }
    }
    $why.ToArray()
}

function Test-SIRecommendationExclusions {
    <# PURE. Every rule valid, every id once. Returns the problems. #>
    param($Document)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Document) { return $why.ToArray() }
    $ids = @{}
    foreach ($r in @(Get-SIItemValue $Document 'rules')) {
        if ($null -eq $r) { continue }
        foreach ($x in (Test-SIRecommendationExclusionRule -Rule $r)) { $why.Add([string]$x) }
        $rid = [string](Get-SIItemValue $r 'id')
        if ($ids.ContainsKey($rid)) { $why.Add(("recommendation-exclusions: rule '{0}' is defined twice" -f $rid)) }; $ids[$rid] = 1
    }
    $why.ToArray()
}

function ConvertTo-SIRecommendationExclusionIndex {
    <#
        PURE. The merged template -> lower-case ConfigurationId -> [ @{ Id; Reports (lower-case, empty = every); When; Reason } ].
        Only valid production rules (no stage = production).
    #>
    param($Document)
    $idx = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @(Get-SIItemValue $Document 'rules')) {
        if ($null -eq $r) { continue }
        $st = [string](Get-SIItemValue $r 'stage'); if ($st -and $st -ne 'production') { continue }
        if (@(Test-SIRecommendationExclusionRule -Rule $r).Count -gt 0) { continue }
        $e = @{ Id = [string](Get-SIItemValue $r 'id'); When = (Get-SIItemValue $r 'when'); Reason = ([string](Get-SIItemValue $r 'reason')).Trim()
            Reports = @(@(Get-SIItemValue $r 'reports') | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim() }) }
        foreach ($cid in @(Get-SIItemValue $r 'configurationIds')) {
            $k = ([string]$cid).Trim(); if (-not $k) { continue }
            if (-not $idx.ContainsKey($k)) { $idx[$k] = New-Object System.Collections.Generic.List[object] }
            $idx[$k].Add($e)
        }
    }
    foreach ($k in @($idx.Keys)) { $idx[$k] = $idx[$k].ToArray() }
    $idx
}

function Find-SIRecommendationExclusion {
    <#
    .SYNOPSIS  PURE. The rule that suppresses one finding, or $null: a production rule naming its ConfigurationId, covering the
               report, whose condition the finding's CI meets. No CI = never suppressed.
    #>
    param([hashtable]$Index, [AllowEmptyString()][string]$ConfigurationId, [AllowEmptyString()][string]$ReportName, $Ci, [hashtable]$Context)
    if ($null -eq $Index -or $Index.Count -eq 0 -or -not $ConfigurationId -or $null -eq $Ci) { return $null }
    $k = $ConfigurationId.Trim()
    if (-not $Index.ContainsKey($k)) { return $null }
    foreach ($e in @($Index[$k])) {
        if (@($e.Reports).Count -gt 0 -and -not (@($e.Reports) | Where-Object { [string]::Equals($_, $ReportName, [StringComparison]::OrdinalIgnoreCase) })) { continue }
        $ok = $false
        try { $ok = [bool](Test-SICondition -Condition $e.When -Item $Ci -Context $Context) } catch { $ok = $false }
        if ($ok) { return $e }
    }
    return $null
}

function Get-SIRecommendationExclusions {
    <#
        The merged template (shipped + the customer's) as an index; an empty index when there is none or it cannot be read
        (nothing is suppressed -- never fails).
    #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot)
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $r = Get-SIDataModelRoot $Root
        if (-not (Test-Path -LiteralPath (Join-Path $r 'recommendation-exclusions.locked.json'))) {
            # Pro: an exported data model from before this template was published -- the shipped template (no override yet)
            $shipped = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
            if (-not (Test-Path -LiteralPath (Join-Path $shipped 'recommendation-exclusions.locked.json'))) { return @{} }
            $r = $shipped
        }
        $t = Get-SIDataModelTemplate -Name 'recommendation-exclusions' -Root $r -OverlayRoot $OverlayRoot
        foreach ($p in (Test-SIRecommendationExclusions -Document $t.Document)) { Write-Warning ("recommendation exclusions: {0} -- that rule is not applied" -f $p) }
        return (ConvertTo-SIRecommendationExclusionIndex -Document $t.Document)
    } catch {
        Write-Warning ("recommendation exclusions could not be read -- {0}. No finding is suppressed by them." -f $_.Exception.Message)
        return @{}
    }
}
