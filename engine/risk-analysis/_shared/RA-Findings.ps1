#Requires -Version 5.1
<#
    SI FINDINGS (V3-DATA-MODEL part 2, P4 / 2.8.2): the Detailed rows one Risk Analysis run published, DE-DUPLICATED per
    CI and finding key -> SI_Finding_CL. The same CVE that Defender vulnerability management, Exposure Graph and the public
    IP scan each report on one CI is ONE finding here, with every report that found it in si_detected_by.

      key        (si_ci_id, finding key); a row without a CI is keyed on its asset id ('asset:<id>'), never dropped
      severity   the highest of the rows (critical > high > medium > low > info)
      scores     the highest risk score and weighted score of the rows; si_risk_rating banded from the score
      factors    every risk-factor token of the rows (probability + consequence), once
      exemption  marked when any row carried an exemption (the rows keep theirs)
      equivalent #464: one recommendation several providers report under their own ids (data-model/recommendation-equivalence)
                 is ONE finding under the group's canonical id; the providers' ids in si_finding_aliases, each report's id,
                 title and severity in si_finding_evidence (SI-RecommendationEquivalence.ps1)
      linked     #693: an operator's manual link on one CI is keyed the same way (who and why on the evidence); a meaning
                 rule (fold) makes a finding that restates another of the same CI evidence on it, not a finding of its own

    The report sheets and SI_RiskAnalysis_Detailed_CL are unchanged: this is an extra, CI-level view of the same run.
    Runs at the end of a Detailed run that published its rows; never fails Risk Analysis.
    #829 (owner 2026-10-20): "Copy findings per CI to Log Analytics (SI_Finding_CL)" is an OPTIONAL output, OFF BY DEFAULT in
    every install -- SI_RA_Findings (Test-SIFindingsCopyOn). Risk Analysis Detailed, its result in the database and its report
    rows (SI_RiskAnalysis_Detailed_CL) are not changed by it: the data sync makes the findings per CI from the database.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

function Test-SIFindingsCopyOn {
    <#
        PURE. #829 Is the copy of the findings per CI to Log Analytics (SI_Finding_CL) on? ON only for an explicit $true / 'on' /
        'true' / '1' / 'yes'; anything else -- not set (the default), $false, 'off', 'false', '0', a typo -- is OFF. The ONE rule:
        Risk Analysis (Publish-SIFindings) and the data sync (Invoke-SIDataCiSync) read the setting through it.
    #>
    param([AllowNull()]$Value = $global:SI_RA_Findings)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    return (([string]$Value).Trim().ToLowerInvariant() -in 'on', 'true', '1', 'yes')
}

function Test-SIRaReportCopyOn {
    <#
        PURE. #830 Is the copy of the Risk Analysis REPORT ROWS to Log Analytics on ("Copy Risk Analysis report rows to Log
        Analytics (SI_RiskAnalysis_Detailed_CL)", the setting SendToLogAnalytics -- SI_RiskAnalysis_Summary_CL too when the
        Summary report runs, and the day's trend row in SI_Trend_CL)? An optional output, OFF by default in every install
        (owner 2026-10-20). The same rule as Test-SIFindingsCopyOn: ON only for an explicit $true / 'on' / 'true' / '1' /
        'yes'; anything else -- not set, $false, 'off', a typo -- is OFF. Risk Analysis (the copy, the trend row) and the data
        sync (its Log Analytics fallback) read the setting through it.
    #>
    param([AllowNull()]$Value = $global:SendToLogAnalytics)
    Test-SIFindingsCopyOn -Value $Value
}

function ConvertTo-SIFindingSeverity {
    <# PURE. Risk Analysis' severity words -> the SI vocabulary. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    switch -Regex (([string]$Value).Trim()) {
        '^(?i)(very high|critical)$' { 'critical'; break }
        '^(?i)high$' { 'high'; break }
        '^(?i)(medium-high|medium|moderate)$' { 'medium'; break }
        '^(?i)low$' { 'low'; break }
        default { 'info' }
    }
}

function Get-SIFindingCiId {
    <#
        PURE. The CI a published row belongs to: its si_ci_id, else its AssetId when AssetIdSource says that id IS the CI
        ('SecurityInsight CI', set by the engine for the reports on SI_CI_CL, or 'ci'). The reports project the CI's id as
        AssetId and the published row keeps only the report's columns, so without the fallback no finding was ever keyed
        to its CI.
    #>
    param($Row)
    if ($null -eq $Row) { return '' }
    $p = $Row.PSObject.Properties['si_ci_id']
    if ($p -and -not [string]::IsNullOrWhiteSpace([string]$p.Value)) { return [string]$p.Value }
    $src = $Row.PSObject.Properties['AssetIdSource']
    $aid = $Row.PSObject.Properties['AssetId']
    if ($src -and $aid -and -not [string]::IsNullOrWhiteSpace([string]$aid.Value) -and ([string]$src.Value).Trim() -match '^(?i)(ci|SecurityInsight CI)$') { return [string]$aid.Value }
    return ''
}

function Get-SIFindingSeverityRank { param([string]$S) switch ($S) { 'critical' { 4 } 'high' { 3 } 'medium' { 2 } 'low' { 1 } default { 0 } } }

function Get-SIFindingGroupKey {
    <#
        PURE. The SI finding a published row belongs to: '<CI or asset:<id>>|<finding key, lower-cased>' (an equivalence
        group's canonical id when the key is a member). $null when the row has no finding key or no CI / asset. -Full also
        returns the equivalence entry: @{ Key; Eq }.
    #>
    param([Parameter(Mandatory)]$Row, $Equivalence, [switch]$Full)
    $g = { param($r, $n) $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $key = [string](& $g $Row 'ConfigurationId')
    if (-not $key) { return $null }
    $owner = Get-SIFindingCiId $Row
    if (-not $owner) { $aid = [string](& $g $Row 'AssetId'); if (-not $aid) { $aid = [string](& $g $Row 'SI_AssetId') }; if (-not $aid) { return $null }; $owner = 'asset:' + $aid.ToLowerInvariant() }
    $eq = $null
    if ($null -ne $Equivalence) { $eq = Resolve-SIRecommendationKey -Index $Equivalence -Key $key -Title ([string](& $g $Row 'ConfigurationName')) -Owner $owner }
    $fk = $key; if ($null -ne $eq) { $fk = [string]$eq.CanonicalId }
    $k = $owner + '|' + $fk.ToLowerInvariant()
    if ($Full) { return @{ Key = $k; Eq = $eq } }
    $k
}

function Get-SIPatchCycleRank {
    <# PURE. #772 how urgent a patch-cycle value is when the rows of one finding disagree: Catch-up first, then In monthly
       cycle, then No fix available; anything else (Unknown, a customer's own value) last but kept over nothing. #>
    param([AllowEmptyString()][string]$V)
    if (-not $V) { return 0 }
    if ($V -like 'Catch-up*') { return 4 }
    switch ($V) { 'In monthly cycle' { 3 } 'No fix available' { 2 } default { 1 } }
}

function ConvertTo-SIFindingRows {
    <#
        PURE. Published Detailed rows -> one SI_Finding_CL row per (CI, finding key).
        #464 -Equivalence (ConvertTo-SIRecommendationEquivalenceIndex): a row whose ConfigurationId (or exact title) is a
        member of an equivalence group is keyed on the group's canonical id -- the same recommendation from several
        providers is ONE finding; the reports' own keys are kept in si_finding_aliases and every report's key, title and
        severity in si_finding_evidence; the severity is the highest of them.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [datetime]$CollectionTime = [datetime]::UtcNow, [string]$RunId = '', $Equivalence,
          # #560 the finding-text catalog (Get-SIFindingTextCatalog): the generic SI finding fields from the rows' columns and the reports' data
          $FindingTexts)
    $g = { param($r, $n) $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $by = [ordered]@{}
    $canon = @{}   # group key -> the equivalence entry it was merged under
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $gk = Get-SIFindingGroupKey -Row $r -Equivalence $Equivalence -Full
        if ($null -eq $gk) { continue }
        $k = $gk.Key; $eq = $gk.Eq
        if (-not $by.Contains($k)) { $by[$k] = New-Object System.Collections.Generic.List[object] }
        $by[$k].Add($r)
        if ($null -ne $eq) { $canon[$k] = $eq }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in $by.Keys) {
        $rs = $by[$k].ToArray()
        $first = $rs[0]
        $sev = 'info'; $score = $null; $weighted = $null; $cvss = $null; $tier = $null
        $sevBy = [ordered]@{}   # #464 report -> severity: kept as evidence when the reports disagree
        $reports = New-Object System.Collections.Generic.List[string]
        $tokens = New-Object System.Collections.Generic.List[string]
        $exempt = ''
        $comp = ''; $aff = [ordered]@{}; $txt = [ordered]@{}; $subci = ''; $subciFromComp = $false; $patch = ''; $cvePub = ''; $fixRel = ''
        foreach ($r in $rs) {
            $s = ConvertTo-SIFindingSeverity ([string](& $g $r 'SecuritySeverity'))
            if ((Get-SIFindingSeverityRank $s) -gt (Get-SIFindingSeverityRank $sev)) { $sev = $s }
            $rnS = [string](& $g $r 'ReportName'); if (-not $rnS) { $rnS = [string](& $g $r 'AssetDetectedInReportName') }; if ($rnS -and -not $sevBy.Contains($rnS)) { $sevBy[$rnS] = $s }
            $rn = [string](& $g $r 'ReportName'); if (-not $rn) { $rn = [string](& $g $r 'AssetDetectedInReportName') }
            if ($rn -and -not $reports.Contains($rn)) { $reports.Add($rn) }
            foreach ($n in 'RiskScoreTotal', 'RiskScoreTotal_Weighted', 'MaxCvssScore', 'CriticalityTier') {
                $v = & $g $r $n
                $d = 0.0
                if ($null -eq $v -or -not [double]::TryParse(([string]$v), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { continue }
                switch ($n) {
                    'RiskScoreTotal' { if ($null -eq $score -or $d -gt $score) { $score = $d } }
                    'RiskScoreTotal_Weighted' { if ($null -eq $weighted -or $d -gt $weighted) { $weighted = $d } }
                    'MaxCvssScore' { if ($null -eq $cvss -or $d -gt $cvss) { $cvss = $d } }
                    'CriticalityTier' { if ($null -eq $tier -or $d -lt $tier) { $tier = $d } }
                }
            }
            foreach ($c in 'RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed') {
                foreach ($t in (([string](& $g $r $c)) -split '\s*;\s*')) { if ($t -and -not $tokens.Contains($t)) { $tokens.Add($t) } }
            }
            $ex = [string](& $g $r 'SI_ExemptionId'); if ($ex -and -not $exempt) { $exempt = $ex }
            # #561 the component (SI-Classification.ps1 set it on the row): a specific value wins over Other
            $cp = [string](& $g $r 'si_component'); if ($cp -and (-not $comp -or ($comp -eq 'Other' -and $cp -ne 'Other'))) { $comp = $cp; $subciFromComp = $true }
            # #772 the ServiceNow sub-CI goes with the component chosen (the row the component came from), else the first row's
            $sc = [string](& $g $r 'si_servicenow_subci'); if ($sc -and (-not $subci -or $subciFromComp)) { $subci = $sc }; $subciFromComp = $false
            # #772 the patch cycle: the most urgent the rows say (Catch-up, then In monthly cycle, then No fix available, then Unknown)
            $pc = [string](& $g $r 'si_patch_cycle'); if ($pc -and (Get-SIPatchCycleRank $pc) -gt (Get-SIPatchCycleRank $patch)) { $patch = $pc }
            # #772 the CVE's published date (the earliest) and the fix's release date (the latest) the rows give
            $cvp = [string](& $g $r 'si_cve_published'); if ($cvp -and (-not $cvePub -or [string]::CompareOrdinal($cvp, $cvePub) -lt 0)) { $cvePub = $cvp }
            $frd = [string](& $g $r 'si_fix_release_date'); if ($frd -and (-not $fixRel -or [string]::CompareOrdinal($frd, $fixRel) -gt 0)) { $fixRel = $frd }
            # #560 the generic SI finding fields: the row's own columns, then its report's data (first row that says wins)
            if ($null -ne $FindingTexts) {
                $tf = ConvertTo-SIFindingTextFields -Row $r -Catalog $FindingTexts -ReportName $rnS
                foreach ($tk in @($tf.Keys)) { if (-not $txt.Contains($tk)) { $txt[$tk] = $tf[$tk] } }
            }
            foreach ($an in 'si_affected_product', 'si_affected_vendor', 'si_affected_version', 'si_affected_cpe') { $av = [string](& $g $r $an); if ($av -and -not $aff.Contains($an)) { $aff[$an] = @($av.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } }
        }
        $key = [string](& $g $first 'ConfigurationId')
        $title = [string](& $g $first 'ConfigurationName')
        # #464 the same recommendation across providers: the canonical key and title; the reports' own keys as aliases and
        # every report's key / title / severity as evidence (a provider's own severity is never lost)
        $aliases = @(); $evidence = @()
        if ($canon.ContainsKey($k)) {
            $eq = $canon[$k]
            $orig = @($rs | ForEach-Object { [string](& $g $_ 'ConfigurationId') } | Where-Object { $_ } | Sort-Object -Unique)
            $aliases = @($orig | Where-Object { $_ -ne [string]$eq.CanonicalId })
            $key = [string]$eq.CanonicalId
            $title = [string]$eq.CanonicalTitle
            # #693 a manual link may name no title: the title of the finding that stays (its own row), else the first row's
            if (-not $title) { $cr = @($rs | Where-Object { [string](& $g $_ 'ConfigurationId') -ieq $key }); $title = $(if ($cr.Count) { [string](& $g $cr[0] 'ConfigurationName') } else { [string](& $g $first 'ConfigurationName') }) }
            $seenEv = @{}
            $evidence = @(foreach ($r in $rs) {
                    $rk = [string](& $g $r 'ConfigurationId'); $rn = [string](& $g $r 'ReportName'); if (-not $rn) { $rn = [string](& $g $r 'AssetDetectedInReportName') }
                    $ek = '{0}|{1}' -f $rn, $rk
                    if ($seenEv.ContainsKey($ek)) { continue }; $seenEv[$ek] = 1
                    $evo = [ordered]@{ report = $rn; key = $rk; title = [string](& $g $r 'ConfigurationName'); severity = (ConvertTo-SIFindingSeverity ([string](& $g $r 'SecuritySeverity'))) }
                    if ($eq.Manual -and $rk -ine [string]$eq.CanonicalId) { $evo['rule'] = [string]$eq.Group; $evo['linkedBy'] = [string]$eq.LinkedBy; $evo['reason'] = [string]$eq.Reason }
                    $evo
                })
        }
        $rating = 'low'
        # #559: the bands of the risk factor model v2 -- ONE definition (RA-RiskScore.ps1 Get-SIRiskRating); the same
        # thresholds inline when it is not loaded
        if ($null -ne $score) {
            if (Get-Command -Name Get-SIRiskRating -ErrorAction SilentlyContinue) { $rating = Get-SIRiskRating -Score $score -Lower }
            elseif ($score -ge 50) { $rating = 'critical' } elseif ($score -ge 30) { $rating = 'high' } elseif ($score -ge 15) { $rating = 'moderate' }
        }
        $o = [ordered]@{
            si_ci_id               = (Get-SIFindingCiId $first)
            si_finding_key         = $key
            si_finding_type        = $(if ($key -match '^(?i)CVE-\d{4}-\d+$') { 'cve' } else { 'recommendation' })
            si_cve                 = $(if ($key -match '^(?i)CVE-\d{4}-\d+$') { $key.ToUpperInvariant() } else { '' })
            si_title               = $title
            si_asset_name          = [string](& $g $first 'AssetName')
            si_security_domain     = [string](& $g $first 'SecurityDomain')
            si_report_name         = $reports[0]
            si_detected_by         = $reports.ToArray()
            si_severity            = $sev
            si_risk_score          = $(if ($null -ne $score) { [long][Math]::Round($score) } else { $null })
            si_weighted_risk_score = $(if ($null -ne $weighted) { [long][Math]::Round($weighted) } else { $null })
            si_risk_rating         = $rating
            si_finding_risk_factors = $tokens.ToArray()
            si_finding_rows        = $rs.Count
            si_collection_time     = $CollectionTime.ToUniversalTime()
        }
        if ($null -ne $tier) { $o['si_tier'] = [long]$tier }
        if ($null -ne $cvss) { $o['si_cvss'] = $cvss.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture) }   # a decimal goes as text
        if ($exempt) { $o['si_exemption_id'] = $exempt }
        # #561 / #560 the finding's component and affected software (one value; Other when no classification row matched)
        if ($comp) { $o['si_component'] = $comp }
        if ($subci) { $o['si_servicenow_subci'] = $subci }
        if ($patch) { $o['si_patch_cycle'] = $patch }   # #772 the patch cycle (one value)
        if ($cvePub) { $o['si_cve_published'] = $cvePub }
        if ($fixRel) { $o['si_fix_release_date'] = $fixRel }   # #772 the ServiceNow sub-CI (one value; the fallback bucket when no row placed it)
        foreach ($an in @($aff.Keys)) { $o[$an] = $aff[$an] }
        # #560 the generic finding fields (a value the finding already has -- title, CVSS, severity -- is kept); the factors
        # applied also as si_risk_factors (the generic name; si_finding_risk_factors keeps its readers); the exemption as an object
        foreach ($tk in @($txt.Keys)) { if (-not $o.Contains($tk)) { $o[$tk] = $txt[$tk] } }
        # #590 the fix shown with the finding (si_fix_remediation) and the generic HOW field (si_remediation) say the same
        # when only one of them was filled -- a report's how-to-fix text fills both
        if ($o.Contains('si_fix_remediation') -and -not $o.Contains('si_remediation')) { $o['si_remediation'] = $o['si_fix_remediation'] }
        elseif ($o.Contains('si_remediation') -and -not $o.Contains('si_fix_remediation')) { $o['si_fix_remediation'] = $o['si_remediation'] }
        $o['si_risk_factors'] = $tokens.ToArray()
        if ($exempt) { $o['si_exemption'] = [ordered]@{ id = $exempt } }
        if (@($sevBy.Values | Select-Object -Unique).Count -gt 1) { $o['si_severity_sources'] = @(foreach ($k2 in $sevBy.Keys) { [ordered]@{ report = $k2; severity = $sevBy[$k2] } }) }
        if ($aliases.Count -gt 0) { $o['si_finding_aliases'] = $aliases }
        if ($evidence.Count -gt 1) { $o['si_finding_evidence'] = $evidence }
        if (-not $o.si_ci_id) { $o['si_asset_id'] = ($k.Split('|')[0]).Substring(6) }
        if ($RunId) { $o['si_run_id'] = $RunId }
        $out.Add([pscustomobject]$o)
    }
    # #693 the meaning rules (fold): a finding that only restates another of the same CI is evidence on it, not its own
    $res = $out.ToArray()
    if ($null -ne $Equivalence -and $Equivalence.Folds -and @($Equivalence.Folds).Count -gt 0) { $res = @(Merge-SIFindingFolds -Findings $res -Folds @($Equivalence.Folds)) }
    # plain output, one finding per item (callers write @(...)): a ", array" return nests inside a caller's @()
    $res
}

function Get-SIFindingsSkipNote {
    <#
        #774 (a customer install, 2026-10-19): a Detailed run that will NOT publish its findings says so -- one plain sentence for the log
        (WARN) and the run record, never a silent skip. '' = nothing to say (a Summary run, a dry run, findings switched
        off, or the rows were published). A run that already ended in failure says its failure instead. Never changes the
        exit: the data sync fills the findings per CI from the database (Invoke-SIDataCiSync) when SI_Finding_CL is missing.
        #829: only when the copy is on (Test-SIFindingsCopyOn) -- with it off (the default) there is nothing to say.
    #>
    param([bool]$Detailed, [bool]$Published, [bool]$WhatIfRun, [bool]$SentToLogAnalytics, [bool]$EndFailed)
    if (-not $Detailed -or $Published -or $WhatIfRun -or $EndFailed) { return '' }
    # #829 the copy is off (the default): nothing is skipped -- the findings per CI come from the database
    if (-not (Test-SIFindingsCopyOn)) { return '' }
    $why = $(if (-not $SentToLogAnalytics) { 'the run does not send to Log Analytics' } else { 'the run''s rows did not reach Log Analytics in full' })
    return ('the findings of this Detailed run were not published to SI_Finding_CL ({0}) -- the data sync fills the findings per CI from the database' -f $why)
}

function Publish-SIFindings {
    <# The end of a Detailed run: its published rows -> SI_Finding_CL. Returns the number posted; never throws. #>
    # -Pager (#638): the run's rows from SQL a page at a time, grouped by finding (New-RARowPager -Source FindingKey) -- a
    # finding's rows are never split over two posts; what is held is one page.
    param([AllowEmptyCollection()][object[]]$Rows = @(), [datetime]$CollectionTime = [datetime]::UtcNow, [string]$RunId = '', [switch]$WhatIfRun, $Pager)
    try {
        # #829 an optional output, off by default (SI_RA_Findings): nothing is posted
        if (-not (Test-SIFindingsCopyOn)) { return 0 }
        # #464 the same recommendation across providers (data-model/recommendation-equivalence; none = keyed per provider)
        $eqIdx = $null
        try {
            if (-not (Get-Command -Name Get-SIRecommendationEquivalence -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'data-model', 'SI-RecommendationEquivalence.ps1')) }
            $eqIdx = Get-SIRecommendationEquivalence
        } catch { Write-Warning ('recommendation equivalence not applied -- {0}' -f $_.Exception.Message) }
        # #560 the generic SI finding fields (data-model/finding-texts; none = the rows' own columns only)
        $ftCat = $null
        try {
            if (-not (Get-Command -Name Get-SIFindingTextCatalog -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'data-model', 'SI-FindingTexts.ps1')) }
            $ftCat = Get-SIFindingTextCatalog
        } catch { Write-Warning ('finding texts not applied -- {0}' -f $_.Exception.Message) }
        if (-not (Get-Command -Name Send-SIObjectMapRows -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-LogIngest.ps1') }
        $dcr = $(if ($global:SI_Finding_DcrName) { [string]$global:SI_Finding_DcrName } else { 'dcr-si-finding' })
        $byCi = ($null -ne $eqIdx -and $eqIdx.Folds -and @($eqIdx.Folds).Count -gt 0)
        $waitKey = { param($row) $k = Get-SIFindingGroupKey -Row $row -Equivalence $eqIdx; if ($byCi -and $null -ne $k) { $k = $k.Substring(0, $k.IndexOf('|')) }; $k }
        if ($null -eq $Pager) { $Pager = [pscustomobject]@{ Rows = @($Rows); Done = $false } | Add-Member -MemberType ScriptMethod -Name Next -Value { if ($this.Done) { return $null }; $this.Done = $true; return , @($this.Rows) } -PassThru }
        $nIn = 0L; $nF = 0L; $nCi = 0L; $nPosted = 0L
        $carry = New-Object System.Collections.Generic.List[object]
        while ($true) {
            $page = $Pager.Next()
            $last = ($null -eq $page)
            $batch = New-Object System.Collections.Generic.List[object]
            foreach ($x in $carry) { $batch.Add($x) }
            $carry.Clear()
            if (-not $last) { foreach ($x in $page) { if ($null -ne $x) { $batch.Add($x) } } }
            $page = $null
            if (-not $last -and $batch.Count -gt 0) {
                # the rows of the page's LAST finding wait for the next page: that finding may go on there (#693 with a meaning
                # rule on: the LAST CI's rows -- its findings are linked with each other, so a CI is never split over two
                # posts; the pager orders by the finding key, which starts with the CI)
                $lk = & $waitKey $batch[$batch.Count - 1]
                while ($batch.Count -gt 0 -and $null -ne $lk -and (& $waitKey $batch[$batch.Count - 1]) -eq $lk) { $carry.Insert(0, $batch[$batch.Count - 1]); $batch.RemoveAt($batch.Count - 1) }
            }
            if ($batch.Count -gt 0) {
                $nIn += $batch.Count
                $f = @(ConvertTo-SIFindingRows -Rows $batch.ToArray() -CollectionTime $CollectionTime -RunId $RunId -Equivalence $eqIdx -FindingTexts $ftCat)
                $nF += $f.Count; $nCi += @($f | Where-Object { $_.si_ci_id }).Count
                if (-not $WhatIfRun -and $f.Count -gt 0) { $nPosted += [long](Send-SIObjectMapRows -Rows @($f) -TableName 'SI_Finding' -DcrName $dcr) }
                $f = $null
            }
            if ($last) { break }
        }
        if ($nF -eq 0) { return 0 }
        if ($WhatIfRun) { Write-Host ('[INFO] findings: {0} de-duplicated from {1} row(s) ({2} on a CI) -- dry run, not posted' -f $nF, $nIn, $nCi); return 0 }
        Write-Host ('[INFO] findings: {0} de-duplicated from {1} row(s) ({2} on a CI) -> SI_Finding_CL' -f $nPosted, $nIn, $nCi)
        return $nPosted
    } catch {
        Write-Warning ('findings could not be published -- {0}. The Risk Analysis tables are unaffected.' -f $_.Exception.Message)
        return 0
    }
}
