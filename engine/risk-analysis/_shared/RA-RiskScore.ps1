#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  The risk-scoring calculation.
#
#  Calculate-RiskScore alone, and it is ~1,085 lines - the single largest function in the engine and
#  the reason the file needed splitting at all. Moved verbatim; breaking it up is a SEPARATE change
#  that must not ride along with a structural move.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Calculate-RiskScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [object[]] $Rows,
        [Parameter(Mandatory=$true)] [psobject] $RiskIndex,
        [string] $SecurityDomain,
        [Parameter(Mandatory=$true)] [string] $CategoryInputName,
        [Parameter(Mandatory=$true)] [string] $SubCategoryInputName,
        [Parameter(Mandatory=$true)] [string] $ConfigurationIdInputName,
        [Parameter(Mandatory=$true)] [string] $SecuritySeverityInputName,
        [Parameter(Mandatory=$true)] [string] $CriticalityTierLevelInputName,
        [string] $SecurityDomainInputName,
        [string[]] $OutputPropertyOrder,
        [string[]] $SortBy,
        [switch]   $Descending,

        [string] $RiskConsequenceScoreOutputName  = 'RiskConsequenceScore_SecuritySeverity',
        [string] $RiskProbabilityScoreOutputName  = 'RiskProbablityScore_CriticialityTierLevel',
        [string] $RiskScoreOutputName             = 'RiskScore',

        # ReportName from the YAML -- stamped into every row as
        # AssetDetectedInReportName so operators can hunt back which report
        # produced which finding. Auto-added (no need to list in OutputPropertyOrder).
        [string] $ReportName,

        # Risk factor columns (KQL can output these; treat 0/1/true/false/yes/no)
        [string] $RiskFactorConsequenceInputName  = 'riskfactor_consequence',
        [string] $RiskFactorProbabilityInputName  = 'riskfactor_probability',

        [switch] $Trace
    )

    function _get([object]$o,[string]$n) {
        if ($null -eq $o -or [string]::IsNullOrWhiteSpace([string]$n)) { return $null }
        $p = $o.PSObject.Properties[$n]
        if ($null -eq $p) { return $null }
        $p.Value
    }

    function _mkKey([hashtable]$kv,[string[]]$pattern) {
        $vals = foreach ($c in $pattern) {
            $v = $kv[$c]
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    function _asBit([object]$v) {
        if ($null -eq $v) { return 0 }
        if ($v -is [bool]) { return [int]($v -eq $true) }
        $s = ([string]$v).Trim().ToLowerInvariant()
        if ($s -in @('1','true','yes','y')) { return 1 }
        0
    }

    # ---- ONE safe-math helper for ALL profilers ----------------------------
    # Single source of truth for: RiskConsequenceScore = consBase + rfCons,
    # RiskProbabilityScore = probBase + rfProb, RiskScoreTotal = product,
    # RiskScoreTotal_Weighted = product * weight/100. Defensive against null
    # inputs (cast via _toDouble or default 0). Sets ALL 4 stamps atomically
    # so rows can never be in a partial state. Called ONCE per row, after
    # token enrichment has updated rfCons/rfProb. NO other code path stamps
    # these columns.
    function _setScores {
        param(
            [Parameter(Mandatory)] $tmp,
            $ConsBase, $ProbBase, $RfCons, $RfProb, $WeightPct
        )
        # Normalize every input to a usable number. PS5.1 [double] cast on $null
        # returns 0; on a string parses InvariantCulture. Belt-and-suspenders.
        $cb = if ($null -eq $ConsBase) { 0.0 } elseif ($ConsBase -is [double]) { [double]$ConsBase } else { try { [double]$ConsBase } catch { 0.0 } }
        $pb = if ($null -eq $ProbBase) { 0.0 } elseif ($ProbBase -is [double]) { [double]$ProbBase } else { try { [double]$ProbBase } catch { 0.0 } }
        $rc = if ($null -eq $RfCons)   { 0.0 } else { try { [double]$RfCons } catch { 0.0 } }
        $rp = if ($null -eq $RfProb)   { 0.0 } else { try { [double]$RfProb } catch { 0.0 } }
        $wp = if ($null -eq $WeightPct -or [double]$WeightPct -le 0) { 100.0 } else { [double]$WeightPct }

        $consAdj  = $cb + $rc
        $probAdj  = $pb + $rp
        $risk     = $consAdj * $probAdj
        $weighted = $risk * $wp / 100.0

        # HARDCODED canonical column names. Per-report YAML override fields
        # (RiskConsequenceScoreOutputName etc.) are LEGACY -- always write to
        # the same canonical columns so every domain (Endpoint / Identity /
        # Azure / PublicIP) gets consistent column shape in Excel.
        $tmp['RiskConsequenceScore']    = [double]$consAdj
        $tmp['RiskProbabilityScore']    = [double]$probAdj
        $tmp['RiskScoreTotal']          = [double]$risk
        $tmp['RiskScoreTotal_Weighted'] = [int][math]::Floor([double]$weighted)
        # RiskRating -- the banded form of RiskScoreTotal, so a security team can filter without
        # memorising what 20 means (operator, 2026-08-10).
        #
        # 🔑 NAMED 'RiskRating', NOT 'RiskLevel' (operator, 2026-08-10). 'RiskLevel' was the first
        # name and it collides twice over:
        #   1. INTERNALLY -- $global:RA_KPI.RiskLevel already exists (Invoke-RiskAnalysis.ps1:5137)
        #      and means something DIFFERENT: the tenant-wide KPI level banded from GlobalScore,
        #      which is higher-is-better. This column bands RiskScoreTotal, which is higher-is-WORSE.
        #      Two columns, the same four words ('Critical'/'High'/'Moderate'/'Low'), opposite
        #      directions -- and both surface in RA output. That is #52's defect class exactly.
        #   2. EXTERNALLY -- Entra ID Protection user/sign-in risk and MDE device risk level both
        #      use it, and SI_Endpoint_Profile_CL already carries MDE's own RiskScore.
        # 'Rating' was verified unused anywhere in SI (0 occurrences) before being chosen; 'Band',
        # 'Tier', 'Level', 'Severity', 'Category', 'Priority' and 'Score' were all already taken.
        #
        # 🔑 STAMPED HERE ON PURPOSE, in the same atomic block as the score it derives from.
        # A band computed anywhere else could disagree with the score printed beside it -- which is
        # exactly audit #52, where one column carried three definitions and was wrong on 21% of rows.
        # Derived, never supplied: a report YAML must not set RiskRating.
        #
        # Banded on RiskScoreTotal, NOT RiskScoreTotal_Weighted -- measured 2026-08-10, the two are
        # identical on all 1,818 rows of the Detailed export (the weight applies to KPI aggregation,
        # not the row), so the unweighted score is the honest input.
        #
        # ⚠️ The bands are coarse because the SCORE is coarse: only 15 distinct values exist in 0..28
        # (it is a product of small integers), and 897 of 1,818 rows sit at exactly 20 -- which is
        # also the High threshold. So High is ~51% of findings, Moderate only ~3.5%, and a small
        # scoring change flips ~900 rows across the boundary at once. Banding cannot fix that;
        # widening the score's granularity would. Recorded so the thresholds are not "tuned" in
        # response to a symptom whose cause is upstream.
        $tmp['RiskRating'] = if     ($risk -ge 25) { 'Critical' }
                             elseif ($risk -ge 20) { 'High'     }
                             elseif ($risk -ge 12) { 'Moderate' }
                             else                  { 'Low'      }
    }

    function _toDouble([object]$v) {
        if ($null -eq $v) { return 0.0 }
        if ($v -is [double]) { return [double]$v }
        if ($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [single]) { return [double]$v }
        # CRITICAL: parse with InvariantCulture. On da-DK and other comma-decimal
        # locales, default TryParse reads "1.0" as 10 (period treated as thousands
        # separator). Backend KQL/JSON always emits invariant ("1.0" never "1,0"),
        # so we MUST parse invariant to round-trip correctly.
        $n = 0.0
        [void][double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)
        $n
    }

    function _findScore {
        param(
            [ValidateSet('Consequence','Probability')] [string] $Kind,
            [hashtable] $kv,
            [psobject]  $Index,
            [switch]    $TraceLocal
        )

        $hasDomain = -not [string]::IsNullOrWhiteSpace([string]$kv[$Index.SecurityDomainColumn])

        if ($Kind -eq 'Consequence') {
            $patWith  = $Index.Conseq_WithDomainPatterns
            $mapWith  = $Index.Conseq_WithDomainMaps
            $patNo    = $Index.Conseq_NoDomainPatterns
            $mapNo    = $Index.Conseq_NoDomainMaps
            $scoreCol = $Index.ConseqScoreColumn
            $valCol   = $Index.SevValueColumn
        } else {
            $patWith  = $Index.Prob_WithDomainPatterns
            $mapWith  = $Index.Prob_WithDomainMaps
            $patNo    = $Index.Prob_NoDomainPatterns
            $mapNo    = $Index.Prob_NoDomainMaps
            $scoreCol = $Index.ProbScoreColumn
            $valCol   = $Index.TierValueColumn
        }

        if ($hasDomain) {
            for ($i=0; $i -lt $patWith.Count; $i++) {
                $key = _mkKey -kv $kv -pattern $patWith[$i]
                if ($key -and $mapWith[$i].ContainsKey($key)) {
                    $row = $mapWith[$i][$key]
                    $num = _toDouble $row.$scoreCol
                    if ($TraceLocal) { Write-Host ("[{0}] matched WITH-domain #{1}: {2} -> {3}" -f $Kind, ($i+1), $key, $num) -ForegroundColor Yellow }
                    return @{ Score=$num; PatternIndex=($i+1); ValueColumnUsed=$valCol }
                }
                if ($TraceLocal -and $key) { Write-Host ("[{0}] tried WITH-domain #{1}: {2} -> no match" -f $Kind, ($i+1), $key) -ForegroundColor White }
            }
        }

        for ($j=0; $j -lt $patNo.Count; $j++) {
            $key = _mkKey -kv $kv -pattern $patNo[$j]
            if ($key -and $mapNo[$j].ContainsKey($key)) {
                $row = $mapNo[$j][$key]
                $num = _toDouble $row.$scoreCol
                if ($TraceLocal) { Write-Host ("[{0}] matched NO-domain #{1}: {2} -> {3}" -f $Kind, ($j+1), $key, $num) -ForegroundColor Yellow }
                return @{ Score=$num; PatternIndex=($j+1); ValueColumnUsed=$valCol }
            }
            if ($TraceLocal -and $key) { Write-Host ("[{0}] tried NO-domain #{1}: {2} -> no match" -f $Kind, ($j+1), $key) -ForegroundColor White }
        }

        if ($TraceLocal) { Write-Host ("[{0}] no match -> 0" -f $Kind) -ForegroundColor Red }
        @{ Score=0.0; PatternIndex=0; ValueColumnUsed=$valCol }
    }

    if ([string]::IsNullOrWhiteSpace($SecurityDomainInputName)) {
        $SecurityDomainInputName = $RiskIndex.SecurityDomainColumn
    }

    if ($null -eq $Rows) { return @() }
    $rowsArr = @()
    foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
    if ($rowsArr.Count -eq 0) { return @() }

    # row dedup by FULL DIMENSIONAL KEY.
    # Original (.189) used (ConfigurationName, ConfigurationId) only -- too narrow:
    # collapsed legitimate tier x severity buckets (e.g. summary reports that
    # produce one row per (Name, Id, Tier, Severity) bucket lost N-1 of N rows).
    # Now dedups by every dimension column the report's `summarize ... by` clause
    # would emit: SecurityDomain, Category, Subcategory, ConfigurationName,
    # ConfigurationId, CriticalityTier, SecuritySeverity. mv-expand/join inflation
    # still collapses correctly because duplicated rows match on ALL these columns.
    $deduped = New-Object System.Collections.Generic.List[object]
    $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    $cnInName = if ($PSBoundParameters.ContainsKey('ConfigurationIdInputName') -and $ConfigurationIdInputName) { $ConfigurationIdInputName } else { 'ConfigurationId' }
    # Bucket-level dimensions (Summary reports) PLUS optional per-row identity columns.
    # Detailed reports carry AssetName/AadDeviceId -- absent on Summary rows so they
    # contribute empty-string and don't change Summary dedup. cmdbCriticality / cmdbDataSensitivity
    # added so cmdb-bucketed Summary rows survive (previously collapsed because key omitted them).
    # ConfigurationId is already in the key via $cnInName -- when each Detailed row carries a
    # unique ConfigurationId (CVE id, scid-*, recommendation id, etc.) the Asset+ConfigurationId
    # pair is the per-row identity. No report-specific columns (CVE_ID, etc.) -- keep generic.
    $keyCols = @('SecurityDomain','Category','Subcategory','ConfigurationName',$cnInName,'CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity','AssetName','AadDeviceId')
    foreach ($r in $rowsArr) {
        $cn = if ($r.PSObject.Properties['ConfigurationName']) { [string]$r.ConfigurationName } else { '' }
        $ci = if ($r.PSObject.Properties[$cnInName])           { [string]$r.PSObject.Properties[$cnInName].Value } else { '' }
        if ([string]::IsNullOrWhiteSpace($cn) -and [string]::IsNullOrWhiteSpace($ci)) {
            [void]$deduped.Add($r)   # no name/id key -> keep all (defensive)
            continue
        }
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($col in $keyCols) {
            $v = if ($r.PSObject.Properties[$col]) { [string]$r.PSObject.Properties[$col].Value } else { '' }
            [void]$parts.Add($v)
        }
        $key = ($parts -join '|').ToLowerInvariant()
        if ($seenKeys.Add($key)) { [void]$deduped.Add($r) }
    }
    $dedupRemoved = $rowsArr.Count - $deduped.Count
    if ($dedupRemoved -gt 0) {
        Write-Info ("dedup'd {0} duplicate row(s) by ({1}) -- {2} unique row(s) remaining (mv-expand / join collapse)" -f $dedupRemoved, ($keyCols -join ', '), $deduped.Count)
        $rowsArr = @($deduped.ToArray())
    }

    $out   = New-Object System.Collections.Generic.List[object]
    $total = $rowsArr.Count
    $done  = 0

    foreach ($r in $rowsArr) {
        $done++
        Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Status "Row $done of $total" -PercentComplete ([math]::Floor(($done/[math]::Max($total,1))*100))

        $domainValue = if ([string]::IsNullOrWhiteSpace($SecurityDomain)) { _get $r $SecurityDomainInputName } else { $SecurityDomain }

        $kv = @{
            ($RiskIndex.SecurityDomainColumn) = $domainValue
            ($RiskIndex.CategoryColumn)       = _get $r $CategoryInputName
            ($RiskIndex.SubCategoryColumn)    = _get $r $SubCategoryInputName
            ($RiskIndex.ConfigIdColumn)       = _get $r $ConfigurationIdInputName
            ($RiskIndex.SevValueColumn)       = _get $r $SecuritySeverityInputName
            ($RiskIndex.TierValueColumn)      = _get $r $CriticalityTierLevelInputName
        }

        # RiskFactor_Consequence is derived dynamically from RiskFactor_Consequence_Detailed:
        # count of ;-separated non-empty entries. Mirrors the probability convention
        # ("each fired factor adds +1"). Defaults to 0 when Detailed is empty.
        # This count flows into both Layer 2 risk-scoring (consAdj = consBase + rfCons)
        # AND the displayed RiskFactor_Consequence column so they stay in lock-step.
        #
        # TIER 1 -- universal engine fallback: when YAML did NOT extend
        # RiskFactor_Consequence_Detailed, derive a baseline from generic asset signals
        # that genuinely describe IMPACT-IF-COMPROMISED (not likelihood). These signals
        # are universal across every report so a baseline always exists. YAML reports
        # can override with finding-specific factors via `| extend RiskFactor_Consequence_Detailed = "..."`.
        $rfConsDetailedRaw = [string](_get $r 'RiskFactor_Consequence_Detailed')
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) {
            $derivedFactors = New-Object System.Collections.Generic.List[string]
            $tierVal = _toDouble (_get $r 'CriticalityTier')
            if ($tierVal -ge 0 -and $tierVal -lt 1) { [void]$derivedFactors.Add('Tier0BlastRadius') }   # Tier 0 only
            $cmdbCrit = [string](_get $r 'cmdbCriticality')
            if ($cmdbCrit -ieq 'Critical') { [void]$derivedFactors.Add('BusinessCriticalAsset') }
            $cmdbSens = [string](_get $r 'cmdbDataSensitivity')
            if     ($cmdbSens -ieq 'Restricted')   { [void]$derivedFactors.Add('RestrictedDataAccess') }
            elseif ($cmdbSens -ieq 'Confidential') { [void]$derivedFactors.Add('ConfidentialDataAccess') }
            $rfConsDetailedRaw = ($derivedFactors -join ';')
        }
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) {
            $rfCons = 0
        } else {
            $rfCons = @($rfConsDetailedRaw -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        }
        $rfProb = [int](_toDouble (_get $r $RiskFactorProbabilityInputName))

        $consBase = _findScore -Kind 'Consequence' -kv $kv -Index $RiskIndex -TraceLocal:$Trace
        $probBase = _findScore -Kind 'Probability' -kv $kv -Index $RiskIndex -TraceLocal:$Trace

        $consAdj = ([double]$consBase.Score) + ([double]$rfCons)
        $probAdj = ([double]$probBase.Score) + ([double]$rfProb)
        $risk    = $consAdj * $probAdj

        # Layer 3 -- business-criticality multiplier in BASIS-100.
        # RiskFactor_Weight is now an INTEGER on the basis-100 scale: Critical=150
        # (1.5x), High=125 (1.25x), Medium=110 (1.1x), Low=105 (1.05x cmdb-tracked
        # uplift), default=100 (1.0x = no amplification when CMDB is OFF or
        # cmdbCriticality is empty). Integer arithmetic dodges all locale-decimal
        # traps (1.5 -> "1,5" -> 15 on da-DK). Engine divides by 100 to apply.
        $rfWeightPct = 100
        if ($r.PSObject.Properties['RiskFactor_Weight']) {
            $w = _toDouble (_get $r 'RiskFactor_Weight')
            if ($w -gt 0) { $rfWeightPct = [int]$w }
        }
        $riskWeighted = [double]$risk * [double]$rfWeightPct / 100.0

        $tmp = [ordered]@{}
        foreach ($p in $r.PSObject.Properties) { $tmp[$p.Name] = $p.Value }

        $tmp[$SecurityDomainInputName] = $domainValue
        # Score stamping deferred to ONE call to _setScores after token enrichment
        # below -- so per-report YAMLs that don't project RiskFactor_*_Detailed
        # inline (Identity reports etc.) still get the post-enrichment counts
        # reflected in the final score. NO other path stamps these columns.

        # Force-cast known numeric columns from string -> double using InvariantCulture.
        # Az.OperationalInsightsQuery returns every cell as string; Excel + ImportExcel
        # then re-parse using the OS locale. On da-DK that turns "7.8" into 78
        # (`.` interpreted as thousands separator). Pre-coercing to [double] makes Excel
        # store the value as a real numeric and respect locale only on display.
        $__numericCols = @('Impact','CvssScore','MaxImpact','AvgImpact','ConfigurationImpact','CredentialExpiryDays','LastSignInDays','DaysInactive')
        foreach ($__nc in $__numericCols) {
            if ($tmp.Contains($__nc) -and $null -ne $tmp[$__nc] -and -not ([string]::IsNullOrWhiteSpace([string]$tmp[$__nc]))) {
                $__v = $tmp[$__nc]
                if ($__v -isnot [double] -and $__v -isnot [int] -and $__v -isnot [long]) {
                    $__d = 0.0
                    if ([double]::TryParse([string]$__v, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$__d)) {
                        $tmp[$__nc] = $__d
                    }
                }
            }
        }

        if (-not $tmp.Contains('RiskFactor_Probability'))          { $tmp['RiskFactor_Probability']          = [int]$rfProb }
        if (-not $tmp.Contains('RiskFactor_Weight'))               { $tmp['RiskFactor_Weight']               = [double]$rfWeight }
        # Guarantee the *Detailed companion columns exist on every row. YAML may
        # populate them (e.g. RiskFactor_Probability_Detailed = "ExploitSignals;Internet-Exposed");
        # when not, the column is still present (empty) so dashboards / mail templates
        # always find it. Consequence_Detailed documents what drives the Consequence
        # score (severity tier, business impact, blast radius) -- populated per-report
        # via `| extend RiskFactor_Consequence_Detailed = "..."`. Engine derives the
        # numeric count above (lock-step with the entry list).
        if (-not $tmp.Contains('RiskFactor_Consequence_Detailed')) { $tmp['RiskFactor_Consequence_Detailed'] = '' }
        if (-not $tmp.Contains('RiskFactor_Probability_Detailed')) { $tmp['RiskFactor_Probability_Detailed'] = '' }

        # Engine-level RiskFactor_*_Detailed token enrichment (audit Tier D).
        # Reads flat columns already in Profile_CL via row join (MDE_*, EG_*) and
        # appends standard tokens to the existing semicolon-list. Tokens are
        # ADD-only -- engine never removes YAML-emitted tokens. Idempotent: a
        # token only appears once even if the source column is set on multiple
        # joined sources.
        $rfProbExisting = [string]$tmp['RiskFactor_Probability_Detailed']
        $rfConsExisting = [string]$tmp['RiskFactor_Consequence_Detailed']
        $probTokens = [System.Collections.Generic.HashSet[string]]::new()
        $consTokens = [System.Collections.Generic.HashSet[string]]::new()
        if (-not [string]::IsNullOrWhiteSpace($rfProbExisting)) {
            foreach ($t in $rfProbExisting -split ';') { $tt = $t.Trim(); if ($tt) { [void]$probTokens.Add($tt) } }
        }
        if (-not [string]::IsNullOrWhiteSpace($rfConsExisting)) {
            foreach ($t in $rfConsExisting -split ';') { $tt = $t.Trim(); if ($tt) { [void]$consTokens.Add($tt) } }
        }
        function _rowHas { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $true } } return $false }
        function _rowVal { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $r.$c } } return $null }
        # ---- Probability tokens (likelihood amplifiers) ----
        $isCompromised = _rowVal @('IsCompromisedRecently','EG_IsCompromisedRecently')
        if ($isCompromised -eq $true -or $isCompromised -eq 1 -or [string]$isCompromised -eq 'true') { [void]$probTokens.Add('IsCompromisedRecently') }
        $machineRisk = [string](_rowVal @('MachineRiskState','EG_MachineRiskState'))
        if ($machineRisk -in 'High','high','High Risk') { [void]$probTokens.Add('HighMachineRisk') }
        $avStatus = [string](_rowVal @('DefenderAvStatus','MDE_DefenderAvStatus'))
        if ($avStatus -in 'Disabled','Off') { [void]$probTokens.Add('DefenderAvDisabled') }
        if ($avStatus -in 'OutOfDate','Expired') { [void]$probTokens.Add('DefenderAvOutOfDate') }
        $onboard = [string](_rowVal @('OnboardingStatus','MDE_OnboardingStatus'))
        if (-not [string]::IsNullOrWhiteSpace($onboard) -and $onboard -ne 'Onboarded') { [void]$probTokens.Add('Unonboarded') }
        $mgmtType = [string](_rowVal @('DeviceManagementType','MDE_DeviceManagementType'))
        if ($mgmtType -in 'Unknown','Unmanaged','None','MdmContainerOnly') { [void]$probTokens.Add('Unmanaged') }
        $isExcl = _rowVal @('IsExcluded','MDE_IsExcluded','EG_IsExcluded')
        if ($isExcl -eq $true -or $isExcl -eq 1 -or [string]$isExcl -eq 'true') { [void]$probTokens.Add('Excluded') }
        $hasInetSig = _rowVal @('HasInternetExposureSignal','EG_HasInternetExposureSignal')
        if ($hasInetSig -eq $true -or $hasInetSig -eq 1 -or [string]$hasInetSig -eq 'true') { [void]$probTokens.Add('InternetExposureSignal') }
        # ---- Consequence tokens (blast radius amplifiers) ----
        $msCrit = [string](_rowVal @('MsCriticalityLevel','EG_MsCriticalityLevel'))
        if ($msCrit -in 'High','VeryHigh','high','very_high') { [void]$consTokens.Add('MsCriticalityHigh') }
        $isProd = _rowVal @('IsProductionEnvironment','EG_IsProductionEnvironment')
        if ($isProd -eq $true -or $isProd -eq 1 -or [string]$isProd -eq 'true') { [void]$consTokens.Add('IsProductionEnvironment') }
        $isAdfs = _rowVal @('IsAdfsServer','EG_IsAdfsServer')
        if ($isAdfs -eq $true -or $isAdfs -eq 1 -or [string]$isAdfs -eq 'true') { [void]$consTokens.Add('IsAdfsServer') }
        $isExch = _rowVal @('IsExchangeServer','EG_IsExchangeServer')
        if ($isExch -eq $true -or $isExch -eq 1 -or [string]$isExch -eq 'true') { [void]$consTokens.Add('IsExchangeServer') }
        $isExo = _rowVal @('IsExchangeOnlineMailbox','EG_IsExchangeOnlineMailbox')
        if ($isExo -eq $true -or $isExo -eq 1 -or [string]$isExo -eq 'true') { [void]$consTokens.Add('IsExchangeOnlineMailbox') }
        # Re-stamp the *_Detailed columns + recount the numeric pair (lock-step).
        # CANONICAL RULE: RiskFactor_{Consequence,Probability} is ALWAYS the
        # count of ;-separated tokens in the *_Detailed column, otherwise 0.
        # The post-enrichment token block above merges YAML-emitted tokens with
        # engine-derived ones; we recount from that merged set so any legacy
        # YAML literal value is overridden. Final stamp into $tmp happens at
        # the canonical re-stamp block further down (single write site).
        if ($probTokens.Count -gt 0) {
            $tmp['RiskFactor_Probability_Detailed'] = ($probTokens -join ';')
            $rfProb = $probTokens.Count
        }
        if ($consTokens.Count -gt 0) {
            $tmp['RiskFactor_Consequence_Detailed'] = ($consTokens -join ';')
            $rfConsDetailedRaw = ($consTokens -join ';')
            $rfCons = $consTokens.Count
        }

        # ---- ONE safe-math call -- stamps all 4 score columns atomically ----
        # Uses post-enrichment rfCons/rfProb (lock-step with displayed
        # RiskFactor_Consequence/Probability counts). Replaces the v2.2 dual-write
        # path. Same call works for Endpoint / Identity / Azure / PublicIP --
        # there is NO other code path that stamps these columns.
        _setScores -tmp $tmp `
            -ConsBase     $consBase.Score `
            -ProbBase     $probBase.Score `
            -RfCons       $rfCons `
            -RfProb       $rfProb `
            -WeightPct    $rfWeightPct

        # Provenance: stamp ReportName into every row so operators can hunt back
        # which report produced which finding. Auto-added (no need to list in
        # OutputPropertyOrder; engine appends to the column set).
        if ($ReportName) {
            $tmp['AssetDetectedInReportName'] = [string]$ReportName
        }

        # CANONICAL re-stamp -- RiskFactor_{Consequence,Probability} = count of
        # tokens in *_Detailed (or 0). YAML-emitted literal values from KQL
        # `| extend RiskFactor_X = N` are overridden here with the derived count
        # so the displayed number ALWAYS matches the displayed token list.
        $tmp['RiskFactor_Consequence']          = [int]$rfCons
        $tmp['RiskFactor_Consequence_Detailed'] = $rfConsDetailedRaw
        $tmp['RiskFactor_Probability']          = [int]$rfProb
        # _Probability_Detailed already stamped above when probTokens fired;
        # otherwise the source row's value (or empty) survives.

        # MoreDetails: collect raw URLs (one per line, no labels) so the cell
        # renders as a stacked clickable list in Excel + a readable list in LA.
        # Three sources, accumulated in order:
        #   1) Auto-harvest -- scan every column on this row for http(s):// values
        #      (skipped when YAML pre-populated MoreDetails, e.g. Device_Missing_CVEs_*
        #      writes "CVE-XXX => URL" pairs that are more informative than raw URLs)
        #   2) Portal links -- Defender / Entra / Azure portal URLs computed from
        #      MdeDeviceId / EntraObjectId / AzureResourceId when present on the row
        #   3) MITRE links -- attack.mitre.org URLs derived from MITRE_Tactics /
        #      MITRE_Techniques semicolon-lists when present on the row
        # Final cap: 4000 chars / 25 URLs total (Excel-readable, LA-friendly).
        $sep = "`r`n"   # Excel renders this as a line-break inside a cell; LA accepts as-is
        $mdLines = New-Object System.Collections.Generic.List[string]

        # 1) Auto-harvest (skipped if YAML pre-populated MoreDetails)
        $existingMd = if ($tmp.Contains('MoreDetails')) { [string]$tmp['MoreDetails'] } else { '' }
        if ([string]::IsNullOrWhiteSpace($existingMd)) {
            $seen = New-Object System.Collections.Generic.HashSet[string]
            foreach ($p in $r.PSObject.Properties) {
                $v = $p.Value
                if ($null -eq $v) { continue }
                $items = if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { @($v) } else { @($v) }
                foreach ($item in $items) {
                    $s = [string]$item
                    if ([string]::IsNullOrWhiteSpace($s)) { continue }
                    if ($s.Length -gt 4096) { continue }   # cell guard: skip oversized blobs
                    if ($s -notmatch 'https?://') { continue }
                    # Pull out EVERY URL from the field. Prior version used $s -match '^https?://'
                    # which kept the WHOLE string as one entry -- if a YAML rollup had
                    # concatenated two URLs without a separator (e.g.
                    # 'https://nvd.nist.gov/vuln/detail/CVE-2016-9535https://nvd.nist.gov/...')
                    # the cell rendered as one un-clickable run-on. Iterate matches instead.
                    foreach ($urlMatch in ([regex]::Matches($s, 'https?://[^\s,;<>"`)\]]+'))) {
                        $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                        if ($seen.Add($u)) { [void]$mdLines.Add($u) }
                    }
                }
            }
        } else {
            # Preserve YAML-populated MoreDetails as line-per-URL. Some vuln reports
            # build entries like 'CVE-2026-33824 => https://nvd.nist.gov/vuln/detail/CVE-2026-33824'
            # in KQL via strcat. KQL strcat without an explicit separator can also produce
            # 'https://...CVE-X-Yhttps://...' run-ons -- iterate every URL match instead of
            # splitting on a single delimiter so concatenated pairs land as separate lines.
            $seenY = New-Object System.Collections.Generic.HashSet[string]
            foreach ($piece in ($existingMd -split '\s*;\s*')) {
                $pTrim = $piece.Trim()
                if ([string]::IsNullOrWhiteSpace($pTrim)) { continue }
                # Extract every URL embedded in the piece (handles 'label => URL' AND
                # 'URL1URL2URL3' run-ons). Falls back to the literal piece if no URL is
                # found (preserves rare non-URL labels for downstream consumers).
                $urlMatches = [regex]::Matches($pTrim, 'https?://[^\s,;<>"`)\]]+')
                if ($urlMatches.Count -eq 0) {
                    if ($seenY.Add($pTrim)) { [void]$mdLines.Add($pTrim) }
                    continue
                }
                foreach ($urlMatch in $urlMatches) {
                    $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                    if ($seenY.Add($u)) { [void]$mdLines.Add($u) }
                }
            }
        }

        # 2) Portal/security links removed by request -- MoreDetails now contains
        # ONLY harvested URLs (CVE / NVD / external references). Operators told us
        # the portal.azure.com and security.microsoft.com links were noise, not
        # navigation aids: the asset name + AssetType already tell you where to go,
        # and the portal blade URLs broke when assets moved tenants. Re-enable per
        # report by adding the URL into the YAML rollup directly.

        # 2b) CVE links -- harvest CVE-YYYY-NNNNN from any field on the row and append
        # NVD detail URLs. Mostly populates from IssueList / Issues / IssuesList /
        # Recommendations columns where the YAML KQL rolls up `mv-expand` CVEs.
        $cveSeen = New-Object System.Collections.Generic.HashSet[string]
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            if ($null -eq $v) { continue }
            $items = if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { @($v) } else { @($v) }
            foreach ($item in $items) {
                $s = [string]$item
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                foreach ($cveMatch in ([regex]::Matches($s, 'CVE-\d{4}-\d{4,}'))) {
                    $cve = $cveMatch.Value.ToUpperInvariant()
                    if ($cveSeen.Add($cve)) {
                        [void]$mdLines.Add('https://nvd.nist.gov/vuln/detail/{0}' -f $cve)
                    }
                }
            }
        }

        # 3) MITRE links derived from MITRE_Tactics / MITRE_Techniques
        foreach ($mitreCol in 'MITRE_Tactics','MITRE_Techniques') {
            if (-not $r.PSObject.Properties[$mitreCol]) { continue }
            $raw = [string]$r.$mitreCol
            if ([string]::IsNullOrWhiteSpace($raw)) { continue }
            foreach ($id in ($raw -split ';')) {
                $idTrim = $id.Trim()
                if ([string]::IsNullOrWhiteSpace($idTrim)) { continue }
                if ($idTrim -match '^TA\d+$')             { [void]$mdLines.Add('https://attack.mitre.org/tactics/{0}/'    -f $idTrim) }
                elseif ($idTrim -match '^T\d+(\.\d+)?$')  { [void]$mdLines.Add('https://attack.mitre.org/techniques/{0}/' -f ($idTrim -replace '\.','/')) }
            }
        }

        # 4) Portal links per asset (v2.2.235). Three sources, all gated on
        # $global:SI_SPN_TenantId being set (the {tid} parameter in every URL).
        # - MDE Endpoint   : requires MdeDeviceId
        # - MDE Identity   : requires AccountSID OR EntraAccountObjectId (3 shapes
        #                    based on which is present:
        #                      both     -> synced  (aad + sid)
        #                      AAD only -> cloud   (aad)
        #                      SID only -> AD-only (sid))
        # - Azure resource : requires AzureResourceId (uses $global:SI_TenantDomain
        #                    if set; falls back to TenantId in the #@<...> anchor)
        # Grace-skip per row when the identifier or tenant ID is missing -- the
        # cell stays focused on CVE / MITRE links instead of dumping useless
        # /overview?tid= placeholders.
        $tid = [string]$global:SI_SPN_TenantId
        if (-not [string]::IsNullOrWhiteSpace($tid)) {
            $mdeIdVal = if ($r.PSObject.Properties['MdeDeviceId']) { [string]$r.MdeDeviceId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($mdeIdVal)) {
                [void]$mdLines.Add(('https://security.microsoft.com/machines/v2/{0}/overview?tid={1}' -f $mdeIdVal, $tid))
            }

            $aadIdVal = if ($r.PSObject.Properties['EntraAccountObjectId']) { [string]$r.EntraAccountObjectId } else { '' }
            $sidVal   = if ($r.PSObject.Properties['AccountSID'])           { [string]$r.AccountSID }           else { '' }
            $hasAad   = -not [string]::IsNullOrWhiteSpace($aadIdVal)
            $hasSid   = -not [string]::IsNullOrWhiteSpace($sidVal)
            if ($hasAad -and $hasSid) {
                # Synced (AD + Entra linked)
                [void]$mdLines.Add(('https://security.microsoft.com/user?aad={0}&sid={1}&tab=overview&tid={2}' -f $aadIdVal, $sidVal, $tid))
            } elseif ($hasAad) {
                # Cloud-only (Entra ID only)
                [void]$mdLines.Add(('https://security.microsoft.com/user?aad={0}&tab=overview&tid={1}' -f $aadIdVal, $tid))
            } elseif ($hasSid) {
                # AD-only (no Entra sync)
                [void]$mdLines.Add(('https://security.microsoft.com/user?sid={0}&tab=overview&tid={1}' -f $sidVal, $tid))
            }

            $azResIdVal = if ($r.PSObject.Properties['AzureResourceId']) { [string]$r.AzureResourceId } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($azResIdVal)) {
                $tdom = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_TenantDomain)) { [string]$global:SI_TenantDomain } else { $tid }
                [void]$mdLines.Add(('https://portal.azure.com/#@{0}/resource{1}/overview' -f $tdom, $azResIdVal))

                # v2.2.314 -- surface Subscription Id + Name when the asset is an
                # Azure resource. Customer ask: "i need to have subscription
                # name id/subscription name in the more details if the asset is
                # an azure resource". Sub Id comes from the AzureResourceId path
                # (segment [2] after /subscriptions/); Sub Name from the row's
                # AZ_SubscriptionName / SubscriptionName column when the
                # profiler stamped it (Azure-engine rows have it; cross-domain
                # rows where AzureResourceId came from EG traversal may not).
                $azParts = $azResIdVal -split '/'
                if ($azParts.Count -ge 3 -and $azParts[1] -eq 'subscriptions' -and -not [string]::IsNullOrWhiteSpace($azParts[2])) {
                    $subId = $azParts[2]
                    $subNm = ''
                    foreach ($candidate in 'AZ_SubscriptionName','SubscriptionName','AzureSubscriptionName') {
                        if ($r.PSObject.Properties[$candidate]) {
                            $v = [string]$r.$candidate
                            if (-not [string]::IsNullOrWhiteSpace($v)) { $subNm = $v; break }
                        }
                    }
                    if ($subNm) {
                        [void]$mdLines.Add(('Subscription: {0} ({1})' -f $subNm, $subId))
                    } else {
                        [void]$mdLines.Add(('Subscription: {0}' -f $subId))
                    }
                }
            }
        }

        # Dedupe (preserves order), cap at 25 URLs, then join with line-break and cap at 4000 chars.
        if ($mdLines.Count -gt 0) {
            $deduped = [System.Collections.Generic.List[string]]::new()
            $seen2 = New-Object System.Collections.Generic.HashSet[string]
            foreach ($u in $mdLines) { if ($seen2.Add($u)) { [void]$deduped.Add($u) } }
            $arr = @($deduped | Select-Object -First 25)
            $joined = ($arr -join $sep)
            if ($joined.Length -gt 4000) { $joined = $joined.Substring(0, 3990) + '...' }
            $tmp['MoreDetails'] = $joined
        }

        if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
            $h = [ordered]@{}
            foreach ($name in $OutputPropertyOrder) {
                if ($tmp.Contains($name)) { $h[$name] = $tmp[$name] }
            }
            foreach ($k in $tmp.Keys) { if (-not $h.Contains($k)) { $h[$k] = $tmp[$k] } }
            # YAML's OutputPropertyOrder is the SINGLE source of truth for column
            # order (canonical Detailed/Summary shape standardized v2.2.175). No
            # engine post-hoc reorder -- it would override YAML curation.
            $out.Add([pscustomobject]$h) | Out-Null
        } else {
            $out.Add([pscustomobject]$tmp) | Out-Null
        }
    }

    Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Completed

    # per-report aggregates emitted under canonical OutputPropertyOrder names:
    #   ImpactedAssetCount        = length of ImpactedAssetsList (audit #25)     (int, scalar)
    #   UniqueIssues              = distinct ConfigurationName count             (int, scalar)
    #   (TotalIssuesImpactedAssets REMOVED -- audit #52: three conflicting definitions,
    #    disagreed with ImpactedAssetCount on 21% of live rows. Do not re-add.)
    #   ImpactedAssetsList        = distinct AssetName(s) across all rows         (array of string)
    #   IssueList                 = distinct ConfigurationName(s) across all rows (array of string)
    # Per user spec:
    #   - LA sink: emit as dynamic (JSON array of names)
    #   - Excel sink: flatten to comma-joined string downstream
    # The engine emits a [string[]] -- AzLogDcrIngestPS serializes as dynamic for LA,
    # Excel writer joins with ', ' for the human-readable cell.
    # AssetName is standardized across SI_*_Profile_CL (set by every row builder); fall
    # back through DisplayName / Hostname / Name / ConfigurationName for legacy rows.
    # Re-apply OutputPropertyOrder so the new columns slot into the canonical position.
    if ($out.Count -gt 0) {
        $totalIssues = $out.Count
        $assetIds    = New-Object System.Collections.Generic.HashSet[string]
        $assetNames  = New-Object System.Collections.Generic.HashSet[string]
        $issueRefs   = New-Object System.Collections.Generic.HashSet[string]
        foreach ($row in $out) {
            $cid = $row.PSObject.Properties[$ConfigurationIdInputName]
            if ($cid -and -not [string]::IsNullOrWhiteSpace([string]$cid.Value)) {
                [void]$assetIds.Add([string]$cid.Value)
            }
            foreach ($candidate in @('AssetName','DisplayName','Hostname','Name','ConfigurationName')) {
                $prop = $row.PSObject.Properties[$candidate]
                if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                    [void]$assetNames.Add([string]$prop.Value)
                    break
                }
            }
            # Issues_Details collects per-row finding identifier so summary
            # rows can show which CVEs / which configuration items / which rules made up
            # the count. Try ConfigurationName first (human-readable like 'CVE-2025-49708'),
            # fall back to ConfigurationId if name absent.
            foreach ($candidate in @('ConfigurationName','ConfigurationId')) {
                $prop = $row.PSObject.Properties[$candidate]
                if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                    [void]$issueRefs.Add([string]$prop.Value)
                    break
                }
            }
        }
        $configIdCount  = $assetIds.Count      # distinct ConfigurationId -- NOT an asset count
        # Ordered, distinct array -- LA dynamic + Excel join both look stable across runs.
        $impactedAssets = @($assetNames | Sort-Object -Unique)
        $issuesDetails  = @($issueRefs  | Sort-Object -Unique)

        # AUDIT #25 -- the count must come from the SET THAT IS DISPLAYED.
        #
        # This used to be $assetIds.Count (distinct ConfigurationId) while the list beside it,
        # ImpactedAssetsList, is built from $assetNames (distinct AssetName). Two different
        # columns, so "ImpactedAssetCount: 12" could sit next to a list of 7 names and neither
        # number was wrong on its own -- they simply measured different things. ConfigurationId
        # identifies the FINDING/configuration item, not the asset, so the old value was closer
        # to an issue count than an asset count despite the name.
        #
        # Blast radius is much wider than audit #25 recorded. #25 named the KQL
        # (`dcount(DeviceKey)` vs `make_set(AssetName)`) and 5 reports. This engine path fills
        # the columns for every Summary report whose KQL does NOT emit them -- 55 of them --
        # because the injection below is "only when the YAML did not provide it".
        #
        # Fallback: if no row carried a resolvable AssetName / DisplayName / Hostname / Name /
        # ConfigurationName, $impactedAssets is empty; keep the old value rather than reporting
        # 0 impacted assets for a report that clearly has findings.
        $assetCount = if ($impactedAssets.Count -gt 0) { $impactedAssets.Count } else { $configIdCount }

        # Aggregate counters apply ONLY to Summary reports (whole-report scalars
        # don't make sense per-asset in Detailed reports). ReportName suffix
        # `_Summary` is the canonical signal. Detailed reports leave these
        # columns alone -- the YAML projects per-asset variants if needed.
        $isSummaryReport = $ReportName -and ($ReportName.EndsWith('_Summary', [StringComparison]::OrdinalIgnoreCase))
        $uniqueIssues   = $issueRefs.Count

        $reordered = New-Object System.Collections.Generic.List[object]
        foreach ($row in $out) {
            $tmp2 = [ordered]@{}
            foreach ($p in $row.PSObject.Properties) { $tmp2[$p.Name] = $p.Value }
            # Preserve YAML-computed aggregates (Summary KQL often summarizes with the
            # correct DisplayName/UserPrincipalName coalesce that engine cannot
            # reconstruct from post-summarize columns). Only inject engine values when
            # the YAML did not provide them, and ONLY for Summary reports.
            # AUDIT #25 -- remember whether the REPORT computed its own count, before we inject
            # ours. The list-scope correction further below must not overwrite a count the KQL
            # deliberately produced; it may only correct one this engine supplied.
            $yamlSuppliedCount = ($tmp2.Contains('ImpactedAssetCount') -and -not [string]::IsNullOrWhiteSpace([string]$tmp2['ImpactedAssetCount']))
            if ($isSummaryReport) {
                if (-not $yamlSuppliedCount) {
                    $tmp2['ImpactedAssetCount'] = [int]$assetCount
                }
                if (-not $tmp2.Contains('UniqueIssues') -or [string]::IsNullOrWhiteSpace([string]$tmp2['UniqueIssues'])) {
                    $tmp2['UniqueIssues'] = [int]$uniqueIssues
                }
                # AUDIT #52 -- TotalIssuesImpactedAssets is GONE. Do not re-add it.
                # It carried THREE different definitions at once: the KQL computed count() of
                # source rows, this engine computed ImpactedAssetCount when the KQL supplied
                # nothing, and the column name promises issues x assets. Measured in the live
                # workspace 2026-08-10: it disagreed with ImpactedAssetCount on 64 of 311 rows
                # (21%), with ratios from 0.125 to 2048.5 -- and a customer saw 102 against a
                # three-asset list. Neither report grain needs it: ImpactedAssetCount +
                # ImpactedAssetsList express the per-issue blast radius, UniqueIssues + IssueList
                # express the per-asset one. A raw finding count, if ever wanted, must be a new
                # and honestly-named column computed in exactly one place.
            }
            # ImpactedAssetsList + IssueList: Summary-only aggregate lists. YAML
            # may project them already (per-summary-group); otherwise engine fills
            # with whole-report aggregates. For Detailed reports, leave alone --
            # YAML projects per-asset variants if applicable.
            if ($isSummaryReport) {
                $existingImpacted = $null
                if ($tmp2.Contains('ImpactedAssetsList'))   { $existingImpacted = $tmp2['ImpactedAssetsList'] }
                elseif ($tmp2.Contains('ImpactedAssets'))   { $existingImpacted = $tmp2['ImpactedAssets'] }
                $hasYamlImpacted = $false
                if ($existingImpacted -is [System.Collections.IEnumerable] -and -not ($existingImpacted -is [string])) {
                    foreach ($x in $existingImpacted) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $hasYamlImpacted = $true; break }
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$existingImpacted)) {
                    $hasYamlImpacted = $true
                }
                if ($hasYamlImpacted) {
                    # YAML projects either semicolon-joined string (strcat_array) or
                    # dynamic array (make_set). Normalize to ordered/unique array.
                    if ($existingImpacted -is [string]) {
                        $existingImpacted = @($existingImpacted -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                    }
                } else {
                    $existingImpacted = $impactedAssets
                }
                $tmp2['ImpactedAssetsList'] = $existingImpacted

                # AUDIT #25, THIRD SHAPE -- found by measuring a completed run, not by reading code.
                #
                # When the YAML supplies the LIST but not the COUNT, the two end up on different
                # SCOPES: the list is per-summarize-group (this row's assets) while the injected
                # count is a whole-report aggregate. Live example from run 20260806T133950Z --
                # Identity_SPN_RoleManagementWrite_Summary showed ImpactedAssetCount = 1 next to a
                # list of 5 SPNs, because that report's KQL emits `ImpactedAssets` per group and no
                # count at all, so the engine filled the count from its own one-row asset set.
                # 14 of 99 rows across the run disagreed this way.
                #
                # Whenever the list on THIS row came from the YAML, the count must describe THAT
                # list. Only override a count the engine itself just injected -- a count the report
                # explicitly computed still wins, which is the same precedence rule used above.
                if ($hasYamlImpacted -and -not $yamlSuppliedCount) {
                    $tmp2['ImpactedAssetCount'] = [int]@($existingImpacted).Count
                }
                if ($tmp2.Contains('ImpactedAssets')) { $tmp2.Remove('ImpactedAssets') }
                if (-not $tmp2.Contains('IssueList') -or $null -eq $tmp2['IssueList']) {
                    # Per-row scope: use THIS row's ConfigurationId. Pre-v2.2.311
                    # stamped $issuesDetails (whole-report aggregate of distinct
                    # ConfigurationName values), which produced multi-KB cells of
                    # every recommendation name on every row. ConfigurationId is
                    # the stable identifier operators asked for; ConfigurationName
                    # still ships in its own column.
                    $rowCfgId = if ($tmp2.Contains('ConfigurationId')) { [string]$tmp2['ConfigurationId'] } else { '' }
                    $tmp2['IssueList'] = if ([string]::IsNullOrWhiteSpace($rowCfgId)) { @() } else { @($rowCfgId) }
                }
            } else {
                # Detailed report: IssueList = single ConfigurationName for THIS row's
                # asset. Per-asset list (one finding per row), not a whole-report
                # aggregate. Keeps the Detailed canonical OPO column populated
                # (operators expect to see WHICH issue this row represents).
                if (-not $tmp2.Contains('IssueList') -or $null -eq $tmp2['IssueList']) {
                    $cfgName = if ($tmp2.Contains('ConfigurationName')) { [string]$tmp2['ConfigurationName'] } else { '' }
                    if (-not [string]::IsNullOrWhiteSpace($cfgName)) {
                        $tmp2['IssueList'] = @($cfgName)
                    } else {
                        $cfgId = if ($tmp2.Contains('ConfigurationId')) { [string]$tmp2['ConfigurationId'] } else { '' }
                        $tmp2['IssueList'] = if ([string]::IsNullOrWhiteSpace($cfgId)) { @() } else { @($cfgId) }
                    }
                }
            }

            # Guarantee cross-cutting columns exist on every report (empty if the
            # per-report YAML didn't populate them) so downstream readers / dashboards
            # / mail-template consumers always find them with a stable schema.
            #   MoreDetails                       -- harvested URLs + portal links + MITRE links
            #   RiskFactor_Consequence_Detailed   -- engine-derived consequence breakdown
            #   MITRE_Tactics / Techniques        -- inferred from SecurityDomain + Subcategory
            #   ComplianceTags                    -- benchmark / framework tags (rare in YAML; usually empty)
            # STRICT-mode reorder below also force-injects all of these into the
            # output when YAML's OutputPropertyOrder doesn't list them explicitly.
            if (-not $tmp2.Contains('MoreDetails'))                     { $tmp2['MoreDetails']                     = '' }
            if (-not $tmp2.Contains('RiskFactor_Consequence_Detailed')) { $tmp2['RiskFactor_Consequence_Detailed'] = '' }

            # MITRE inference: priority order
            #   1. YAML-projected MITRE_Tactics + MITRE_Techniques  (already filled -- skip)
            #   2. Defender-native fields on the row:
            #        - 'Categories' / 'AlertCategories' (AlertInfo / AlertEvidence)  -> name->TA#### lookup
            #        - 'AttackTechniques' (AlertInfo / DeviceEvents / EG edges)      -> already T#### IDs
            #   3. Keyword regex over SecurityDomain + Subcategory + ConfigurationName.
            #   4. SecurityDomain-level fallback (broad TA-tactic).
            #
            # Categories -> Tactic ID lookup (MITRE ATT&CK 14 enterprise tactics).
            # Defender XDR's 'Categories' column carries human-readable tactic names
            # like "Credential Access", "Lateral Movement". Customers want TA#### IDs
            # for downstream tooling, so engine maps once.
            $mitreCategoryToTactic = @{
                'reconnaissance'         = 'TA0043'
                'resource development'   = 'TA0042'
                'initial access'         = 'TA0001'
                'execution'              = 'TA0002'
                'persistence'            = 'TA0003'
                'privilege escalation'   = 'TA0004'
                'defense evasion'        = 'TA0005'
                'credential access'      = 'TA0006'
                'discovery'              = 'TA0007'
                'lateral movement'       = 'TA0008'
                'collection'             = 'TA0009'
                'command and control'    = 'TA0011'
                'exfiltration'           = 'TA0010'
                'impact'                 = 'TA0040'
            }

            $mitreTactics    = if ($tmp2.Contains('MITRE_Tactics'))    { [string]$tmp2['MITRE_Tactics']    } else { '' }
            $mitreTechniques = if ($tmp2.Contains('MITRE_Techniques')) { [string]$tmp2['MITRE_Techniques'] } else { '' }

            # Step 2: Defender-native columns. Read regardless of MITRE_Tactics state --
            # if YAML projected RAW Categories/AttackTechniques but no MITRE_Tactics, we can
            # still translate. If YAML projected MITRE_Tactics directly, we honor that.
            if ([string]::IsNullOrWhiteSpace($mitreTactics)) {
                $catRaw = ''
                foreach ($colName in 'Categories','AlertCategories','MITRE_Categories') {
                    if ($tmp2.Contains($colName) -and -not [string]::IsNullOrWhiteSpace([string]$tmp2[$colName])) {
                        $catRaw = [string]$tmp2[$colName]; break
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($catRaw)) {
                    # Comma- or semicolon- separated tactic names. Map each to TA####.
                    $tids = @($catRaw -split '[,;]' | ForEach-Object {
                        $name = $_.Trim().ToLowerInvariant()
                        if ($mitreCategoryToTactic.ContainsKey($name)) { $mitreCategoryToTactic[$name] }
                    } | Where-Object { $_ } | Sort-Object -Unique)
                    if ($tids.Count -gt 0) { $mitreTactics = ($tids -join ';') }
                }
            }
            if ([string]::IsNullOrWhiteSpace($mitreTechniques)) {
                foreach ($colName in 'AttackTechniques','MITRE_AttackTechniques') {
                    if ($tmp2.Contains($colName) -and -not [string]::IsNullOrWhiteSpace([string]$tmp2[$colName])) {
                        # Already T#### IDs (Defender's shape). Normalize comma/space/semicolon to ';'.
                        $raw = [string]$tmp2[$colName]
                        $tlist = @($raw -split '[,;\s]+' | Where-Object { $_ -match '^T\d+(\.\d+)?$' } | Sort-Object -Unique)
                        if ($tlist.Count -gt 0) { $mitreTechniques = ($tlist -join ';'); break }
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($mitreTactics) -and [string]::IsNullOrWhiteSpace($mitreTechniques)) {
                $secDomain  = if ($tmp2.Contains('SecurityDomain'))  { [string]$tmp2['SecurityDomain']  } else { '' }
                $subcat     = if ($tmp2.Contains('Subcategory'))     { [string]$tmp2['Subcategory']     } else { '' }
                $cfgName    = if ($tmp2.Contains('ConfigurationName')){[string]$tmp2['ConfigurationName']} else { '' }
                $blob       = ($secDomain + ' ' + $subcat + ' ' + $cfgName).ToLowerInvariant()

                # Match most-specific keywords first, then broader domain defaults.
                $tactics    = $null
                $techniques = $null
                switch -Regex ($blob) {
                    'mfa|conditional access|multi.factor'                 { $tactics = 'TA0006';        $techniques = 'T1078;T1110';            break }
                    'brute.?force|password spray'                         { $tactics = 'TA0006';        $techniques = 'T1110;T1110.003';        break }
                    'impossible travel|nontrusted location|risky.sign'    { $tactics = 'TA0006;TA0001'; $techniques = 'T1078;T1078.004';        break }
                    'permanent.*role|privileged.*role|never.*expire'      { $tactics = 'TA0004;TA0003'; $techniques = 'T1078;T1098.003';        break }
                    'shadow admin|nested.*group|stale.*group'             { $tactics = 'TA0004';        $techniques = 'T1078;T1484.001';        break }
                    'guest|external user|departed|stale'                  { $tactics = 'TA0006';        $techniques = 'T1078;T1078.004';        break }
                    'spn|service principal|app registration|mailbox'      { $tactics = 'TA0004;TA0003'; $techniques = 'T1078.004;T1098.001';    break }
                    'cve|vulnerab|recommendation|patch'                   { $tactics = 'TA0001';        $techniques = 'T1190';                  break }
                    'public.*ip|exposed|open port|public.*facing'         { $tactics = 'TA0001;TA0007'; $techniques = 'T1190;T1133';            break }
                    'lateral|exploitable.*device|logon.*to'               { $tactics = 'TA0008';        $techniques = 'T1021;T1078';            break }
                    'attack path'                                          { $tactics = 'TA0008;TA0004'; $techniques = 'T1078;T1021';            break }
                    'data sensitivity|sensitive data|key vault'            { $tactics = 'TA0009;TA0010'; $techniques = 'T1213;T1530';            break }
                }
                # Domain-level fallback if no specific keyword hit.
                if ($null -eq $tactics) {
                    switch ($secDomain) {
                        'Identity'   { $tactics = 'TA0006';        $techniques = 'T1078'             }
                        'Endpoint'   { $tactics = 'TA0001;TA0008'; $techniques = 'T1190;T1021'      }
                        'Azure'      { $tactics = 'TA0004;TA0001'; $techniques = 'T1078.004;T1190'  }
                        'PublicIp'   { $tactics = 'TA0001;TA0007'; $techniques = 'T1190;T1133'      }
                        'AttackPath' { $tactics = 'TA0008;TA0004'; $techniques = 'T1078;T1021'      }
                        default      { $tactics = '';              $techniques = ''                 }
                    }
                }
                $tmp2['MITRE_Tactics']    = $tactics
                $tmp2['MITRE_Techniques'] = $techniques
            } else {
                # At least one of mitreTactics/mitreTechniques came from row data
                # (Step 2 Defender-native). Persist whatever we resolved; fill the
                # missing side with empty string so downstream readers can rely on
                # the column existing.
                $tmp2['MITRE_Tactics']    = if ($mitreTactics)    { $mitreTactics }    else { '' }
                $tmp2['MITRE_Techniques'] = if ($mitreTechniques) { $mitreTechniques } else { '' }
            }

            # ComplianceTags inference: when YAML didn't pre-populate, derive a sensible
            # default from the same SecurityDomain + Subcategory + ConfigurationName blob.
            # Lists the most common control framework anchors per finding type so customers
            # can map to their compliance evidence pack. YAML overrides win when set.
            $compTags = if ($tmp2.Contains('ComplianceTags')) { [string]$tmp2['ComplianceTags'] } else { '' }
            if ([string]::IsNullOrWhiteSpace($compTags)) {
                $secDomain  = if ($tmp2.Contains('SecurityDomain'))   { [string]$tmp2['SecurityDomain']   } else { '' }
                $subcat     = if ($tmp2.Contains('Subcategory'))      { [string]$tmp2['Subcategory']      } else { '' }
                $cfgName    = if ($tmp2.Contains('ConfigurationName')){ [string]$tmp2['ConfigurationName']} else { '' }
                $blob       = ($secDomain + ' ' + $subcat + ' ' + $cfgName).ToLowerInvariant()

                # Each keyword now anchors against:
                #   - NIST 800-53 (US federal)        - NIST CSF 2.0     (US framework)
                #   - ISO 27001 Annex A (international) - CIS Controls v8 (community)
                #   - PCI DSS 4.0 (payments)          - HIPAA Security Rule (US healthcare)
                #   - SOC 2 Trust Services Criteria   - NIS2 (EU) / DORA (EU finance)
                #   - GDPR (EU privacy, data sensitivity only)
                # Customers refine via per-report YAML; these defaults are best-fit anchors.
                $tags = $null
                switch -Regex ($blob) {
                    'mfa|conditional access|multi.factor' {
                        $tags = 'NIST 800-53 IA-2(1);NIST CSF PR.AA-3;ISO 27001 A.9.4.2;CIS 5.1;PCI DSS 8.4;HIPAA 164.312(a)(1);SOC 2 CC6.1;NIS2 Art.21(2)(d)'
                        break }
                    'brute.?force|password spray' {
                        $tags = 'NIST 800-53 AC-7;NIST CSF DE.CM-1;ISO 27001 A.9.4.2;CIS 5.2;HIPAA 164.308(a)(5)(ii)(D);SOC 2 CC6.6'
                        break }
                    'impossible travel|nontrusted location|risky.sign' {
                        $tags = 'NIST 800-53 AC-17,SI-4;NIST CSF DE.AE-3;ISO 27001 A.9.4.2;CIS 6.5;SOC 2 CC7.2'
                        break }
                    'permanent.*role|privileged.*role|never.*expire' {
                        $tags = 'NIST 800-53 AC-2,AC-5,AC-6;NIST CSF PR.AC-4;ISO 27001 A.9.2.3;CIS 5.4;SOC 2 CC6.2;NIS2 Art.21(2)(i);DORA Art.9'
                        break }
                    'shadow admin|nested.*group|stale.*group' {
                        $tags = 'NIST 800-53 AC-2;NIST CSF PR.AC-1;ISO 27001 A.9.2.5;CIS 5.4;SOC 2 CC6.2'
                        break }
                    'guest|external user|departed|stale.*user|stale.*account' {
                        $tags = 'NIST 800-53 AC-2(2),AC-2(3);NIST CSF PR.AC-1;ISO 27001 A.9.2.5,A.9.2.6;CIS 5.3;HIPAA 164.308(a)(3)(ii)(C);SOC 2 CC6.3'
                        break }
                    'spn|service principal|app registration|mailbox' {
                        $tags = 'NIST 800-53 IA-3,IA-9;NIST CSF PR.AA-1;ISO 27001 A.9.4.5;CIS 5.5;SOC 2 CC6.1'
                        break }
                    'cve|vulnerab|recommendation|patch' {
                        $tags = 'NIST 800-53 SI-2,RA-5;NIST CSF ID.RA-1,PR.IP-12;ISO 27001 A.12.6.1;CIS 7.1;PCI DSS 6.2;HIPAA 164.308(a)(1)(ii)(B);SOC 2 CC7.1;NIS2 Art.21(2)(e);DORA Art.10'
                        break }
                    'public.*ip|exposed|open port|public.*facing' {
                        $tags = 'NIST 800-53 SC-7,CA-3;NIST CSF PR.AC-5;ISO 27001 A.13.1;CIS 12.1;PCI DSS 1.1;HIPAA 164.312(e)(1);SOC 2 CC6.6;NIS2 Art.21(2)(c)'
                        break }
                    'lateral|exploitable.*device|logon.*to' {
                        $tags = 'NIST 800-53 SC-7(13),AC-4;NIST CSF PR.AC-5;ISO 27001 A.13.1.3;CIS 12.4;SOC 2 CC6.6'
                        break }
                    'attack path' {
                        $tags = 'NIST 800-53 RA-3,SC-7;NIST CSF ID.RA-3;ISO 27001 A.12.6.1;SOC 2 CC3.1;NIS2 Art.21(2)(b);DORA Art.8'
                        break }
                    'data sensitivity|sensitive data|key vault' {
                        $tags = 'NIST 800-53 SC-12,SC-13,MP-2;NIST CSF PR.DS-1,PR.DS-5;ISO 27001 A.8.2,A.10.1;GDPR Art.32;PCI DSS 3;HIPAA 164.312(a)(2)(iv);SOC 2 CC6.7;DORA Art.9'
                        break }
                    'firewall|defender' {
                        $tags = 'NIST 800-53 SC-7,SI-3;NIST CSF PR.PT-4,DE.CM-4;ISO 27001 A.13.1.1;CIS 9.2;PCI DSS 1;SOC 2 CC6.6'
                        break }
                    'tls|encryption|unencrypted' {
                        $tags = 'NIST 800-53 SC-8,SC-13;NIST CSF PR.DS-2;ISO 27001 A.10.1;PCI DSS 4;HIPAA 164.312(e)(2)(ii);SOC 2 CC6.7'
                        break }
                }
                if ($null -eq $tags) {
                    switch ($secDomain) {
                        'Identity'   { $tags = 'NIST 800-53 AC-2,IA-2;NIST CSF PR.AA-1;ISO 27001 A.9;SOC 2 CC6.1' }
                        'Endpoint'   { $tags = 'NIST 800-53 SI-2,SI-3;NIST CSF DE.CM-4;ISO 27001 A.12.6;SOC 2 CC7.1' }
                        'Azure'      { $tags = 'NIST 800-53 AC-3,AC-6;NIST CSF PR.AC-4;ISO 27001 A.9.4;SOC 2 CC6.1' }
                        'PublicIp'   { $tags = 'NIST 800-53 SC-7;NIST CSF PR.AC-5;ISO 27001 A.13.1;SOC 2 CC6.6' }
                        'AttackPath' { $tags = 'NIST 800-53 RA-3,SC-7;NIST CSF ID.RA-3;ISO 27001 A.12.6;SOC 2 CC3.1' }
                        default      { $tags = '' }
                    }
                }
                $tmp2['ComplianceTags'] = $tags
            } else {
                if (-not $tmp2.Contains('ComplianceTags')) { $tmp2['ComplianceTags'] = '' }
            }

            # =====================================================================
            # NEW (v2.2.89): RiskScoreDomainKPI + RiskScoreKPI
            # =====================================================================
            # Two new per-row columns that feed the management-facing reporting
            # rollups (global Risk Score KPI + per-domain breakdown). The existing
            # math model (RiskFactor_Consequence x RiskFactor_Probability x
            # RiskScore_Weight_Factor = RiskScoreTotal[_Weighted]) is left
            # untouched -- customer dashboards built on those columns keep
            # working. These two NEW columns are designed to be easy to explain
            # to management:
            #
            #   RiskScoreDomainKPI = SeverityWeight x AssetTierMultiplier
            #   RiskScoreKPI       = RiskScoreDomainKPI x GlobalWeight[<domain>]
            #
            # Sum RiskScoreDomainKPI by SecurityDomain -> domain raw score.
            # Sum RiskScoreKPI across all rows -> global raw score.
            # Both normalized to 0-100 in the run-end aggregation block (~line 6045).
            $sevName  = if ($tmp2.Contains('SecuritySeverity')) { [string]$tmp2['SecuritySeverity'] } else { '' }
            $tierVal  = $null
            if ($tmp2.Contains('CriticalityTier'))      { [void][int]::TryParse([string]$tmp2['CriticalityTier'], [ref]$tierVal) }
            $domName  = if ($tmp2.Contains('SecurityDomain')) { [string]$tmp2['SecurityDomain'] } else { '' }

            $sevWeight = switch -Regex ($sevName) {
                '^(?i)(critical|very high)$' { if ($null -ne $global:SI_RiskReport_SeverityWeight_Critical) { [double]$global:SI_RiskReport_SeverityWeight_Critical } else { 10.0 }; break }
                '^(?i)high$'                 { if ($null -ne $global:SI_RiskReport_SeverityWeight_High)     { [double]$global:SI_RiskReport_SeverityWeight_High }     else {  5.0 }; break }
                '^(?i)medium-?high$'         { if ($null -ne $global:SI_RiskReport_SeverityWeight_High)     { [double]$global:SI_RiskReport_SeverityWeight_High }     else {  5.0 }; break }
                '^(?i)medium$'               { if ($null -ne $global:SI_RiskReport_SeverityWeight_Medium)   { [double]$global:SI_RiskReport_SeverityWeight_Medium }   else {  2.0 }; break }
                '^(?i)low$'                  { if ($null -ne $global:SI_RiskReport_SeverityWeight_Low)      { [double]$global:SI_RiskReport_SeverityWeight_Low }      else {  1.0 }; break }
                default                      { 1.0 }
            }
            $tierMult = switch ($tierVal) {
                0       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T0) { [double]$global:SI_RiskReport_TierMultiplier_T0 } else { 4.0 } }
                1       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T1) { [double]$global:SI_RiskReport_TierMultiplier_T1 } else { 2.0 } }
                2       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T2) { [double]$global:SI_RiskReport_TierMultiplier_T2 } else { 1.0 } }
                3       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T3) { [double]$global:SI_RiskReport_TierMultiplier_T3 } else { 0.5 } }
                default { 1.0 }
            }
            $globalWeight = switch ($domName) {
                'Endpoint'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_Endpoint) { [double]$global:SI_RiskReport_GlobalWeight_Endpoint } else { 0.30 } }
                'Identity'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_Identity) { [double]$global:SI_RiskReport_GlobalWeight_Identity } else { 0.30 } }
                'Azure'      { if ($null -ne $global:SI_RiskReport_GlobalWeight_Azure)    { [double]$global:SI_RiskReport_GlobalWeight_Azure }    else { 0.20 } }
                'PublicIP'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 } }
                'PublicIp'   { if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 } }
                'AttackPath' { 0.0 }   # attack-path rows already counted in their target domain
                default      { 0.20 }
            }
            # v2.2.96: per-row KPI is a SECURE SCORE (HIGHER = BETTER, 0-100),
            # inspired by Microsoft Cloud Secure Score. The original RiskScore
            # math (Severity x Probability x Weight = RiskScoreTotal) is left
            # untouched -- the OG number people are fans of stays on every row.
            #
            # Per-row formula:
            #   sevPenalty = SeverityWeight / 10        (0..1, 1.0 = critical)
            #   RiskScoreKPI = round((1 - sevPenalty) * 100)
            #     -> Critical 0 | High 50 | Medium 80 | Low 90 | Other 95
            #   RiskScoreDomainKPI = RiskScoreKPI x TierWeight / 4
            #     -> normalized 0..100 with T0 carrying full weight (4/4),
            #        T1 half weight (2/4), T2 quarter (1/4), T3 eighth (0.5/4)
            #     -> aggregator: DomainScore = sum(RiskScoreDomainKPI) / sum(TierWeight/4) -> mgmt KPI
            $sevPenalty   = [Math]::Min(1.0, $sevWeight / 10.0)
            $rowKpi       = [int][Math]::Round((1.0 - $sevPenalty) * 100.0, 0)
            $tierFraction = $tierMult / 4.0   # T0 1.00, T1 0.50, T2 0.25, T3 0.125
            $rowDomainKpi = [int][Math]::Round((1.0 - $sevPenalty) * $tierFraction * 100.0, 0)
            $tmp2['RiskScoreKPI']       = $rowKpi
            $tmp2['RiskScoreDomainKPI'] = $rowDomainKpi

            if ($OutputPropertyOrder -and $OutputPropertyOrder.Count -gt 0) {
                # STRICT mode -- when OutputPropertyOrder is declared, emit ONLY those
                # columns. The legacy engine-injected aggregates
                # (AssetCount/TotalIssues/ImpactedAssets/Issues_Details + the
                # RiskFactor_Weight engine-alias) are dropped because their data lives
                # in YAML-declared columns under the new names (ImpactedAssetCount /
                # ImpactedAssetsList / IssueList /
                # RiskScore_Weight_Factor). MoreDetails + RiskFactor_Consequence_Detailed
                # + MITRE_* + ComplianceTags are force-included regardless of whether the
                # per-report YAML lists them, so the schema stays stable across reports.
                # RiskFactor_Consequence_Detailed is then re-positioned to sit right
                # after RiskFactor_Consequence.
                $h2 = [ordered]@{}
                foreach ($name in $OutputPropertyOrder) {
                    # Treat 'ImpactedAssets' and 'ImpactedAssetsList' as aliases. The engine
                    # canonicalizes on 'ImpactedAssetsList' a few lines above; YAMLs that
                    # still list the legacy 'ImpactedAssets' name in OutputPropertyOrder
                    # remap here so column-name parity is preserved for Excel + LA.
                    $effectiveName = if ($name -eq 'ImpactedAssets') { 'ImpactedAssetsList' } else { $name }
                    if ($tmp2.Contains($effectiveName)) { $h2[$effectiveName] = $tmp2[$effectiveName] }
                }
                foreach ($forceCol in 'RiskFactor_Consequence_Detailed','MITRE_Tactics','MITRE_Techniques','ComplianceTags','MoreDetails','RiskScoreDomainKPI','RiskScoreKPI') {
                    if (-not $h2.Contains($forceCol)) { $h2[$forceCol] = $tmp2[$forceCol] }
                }
                # v2.2.225 -- carry-through extra YAML-projected columns. Previously
                # OutputPropertyOrder was a strict whitelist: any column projected by
                # the YAML KQL but missing from OutputPropertyOrder got silently
                # dropped. That made CVE Detailed lose HasExploit / IsExploitVerified /
                # IsInExploitKit / IsZeroDay / CVELastModified / CVSSDesc / CveUrl
                # which the operator wants visible without inflating the canonical
                # OutputPropertyOrder. Now: OutputPropertyOrder defines the LEADING
                # canonical column block; any additional row-level columns from the
                # KQL get appended in row-natural order. Blacklist below skips legacy
                # engine-aliases + internal helpers.
                $extraColBlacklist = @{
                    'AssetCount'        = $true   # legacy alias -> ImpactedAssetCount
                    'TotalIssues'       = $true   # legacy alias, retired with audit #52
                    # AUDIT #52 -- blacklisted so it cannot come back through the side door.
                    # It was removed from every OutputPropertyOrder, which means a KQL still
                    # emitting it would no longer be a declared column -- it would be APPENDED
                    # as an "extra row-level column" and reappear in exports looking legitimate.
                    # A customer .custom.yaml could do exactly that.
                    'TotalIssuesImpactedAssets' = $true
                    # AUDIT #52 (completed v2.2.417) -- IssueList came back through the SAME side
                    # door, and the pre-publish gate caught it. #52 removed IssueList from 112
                    # OutputPropertyOrders, but the ENGINE still injects it a few hundred lines
                    # above (Detailed -> @(ConfigurationName); Summary -> @(ConfigurationId)) when
                    # the KQL supplies none. Undeclared + engine-injected = appended here as an
                    # "extra row-level column", so it reappeared on 1,777 of 1,777 Detailed rows.
                    # 🔑 Blacklisting is SAFE for the 6 reports that legitimately KEEP IssueList --
                    # a declared column is already in $h2 and returns on the first check above, so
                    # this line can only ever drop the UNDECLARED, engine-injected copies.
                    # Filtering here rather than deleting the injection on purpose -- $tmp2's
                    # IssueList is still read upstream when building NVD/CVE detail URLs.
                    'IssueList'         = $true
                    'ImpactedAssets'    = $true   # legacy alias -> ImpactedAssetsList
                    'Issues_Details'    = $true   # legacy alias -> MoreDetails
                    'RiskFactor_Weight' = $true   # legacy alias -> RiskScore_Weight_Factor
                    'DeviceKey'         = $true   # internal join key
                    'EpJoinKey'         = $true   # internal join key (v2.2.221)
                    'EdgeLabels'        = $true   # internal trace set (v2.2.215)
                    'FindingNodeId'     = $true   # internal join key
                    'FindingLabel'      = $true   # internal raw-EG label (kept inside Finding* scalars)
                    'FindingCategories' = $true   # internal raw-EG categories
                    'EG_IsCustomerFacing' = $true # internal raw flag (consumed by RF_P_InternetExposed)
                    'EG_IsExcluded'     = $true   # internal raw flag (filtered upstream)
                    'AadDeviceId1'      = $true   # leftouter-join right-side rename
                }
                foreach ($k in $tmp2.Keys) {
                    if ($h2.Contains($k))            { continue }   # already emitted in canonical block
                    if ($k.StartsWith('_'))          { continue }   # internal/temp columns (e.g. _AssetTagsLower, _AssetTierFilter)
                    if ($k.StartsWith('__'))         { continue }   # bucket-filter internals (__bucket_key, __bucket)
                    if ($extraColBlacklist.ContainsKey($k)) { continue }
                    if ($k -like '*_From_CL')        { continue }   # leftouter-side raw cols (consumed by AssetName/AssetId/AssetType extends)
                    $h2[$k] = $tmp2[$k]
                }
                # YAML OutputPropertyOrder is the LEADING column-order authority;
                # extras appended above sit AFTER the canonical block.
                [void]$reordered.Add([pscustomobject]$h2)
            } else {
                [void]$reordered.Add([pscustomobject]$tmp2)
            }
        }
        $out = $reordered
    }

    $finalOut = $null
    try {
        $finalOut = [object[]]$out.ToArray()
    } catch {
        $tmpList = New-Object System.Collections.Generic.List[object]
        foreach ($x in $out) { $tmpList.Add($x) | Out-Null }
        $finalOut = [object[]]$tmpList.ToArray()
    }

    if ($SortBy -and $SortBy.Count -gt 0) {
        if ($Descending) { $finalOut = @($finalOut | Sort-Object -Property $SortBy -Descending) }
        else             { $finalOut = @($finalOut | Sort-Object -Property $SortBy) }
    }

    return @($finalOut)
}
