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

function ConvertTo-RADouble {
    <#
        A number from whatever the backend, a YAML value or a config file handed us -- parsed
        INVARIANT, on every host.

        Why this exists (#121): the engine runs on da-DK hosts, where a culture-default
        [double]::TryParse reads "12.5" as 125 (the period is a thousands separator there), and several
        call sites "helped" by first doing -replace ',', '.' -- which turns a Danish "12,5" into "12.5"
        and then misreads THAT. Invariant first; a lone decimal comma (a hand-typed config value like
        "7,5") is accepted as a fallback. Returns -Default when the value is blank or not a number.
    #>
    param([object]$Value, [double]$Default = 0.0)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [double] -or $Value -is [int] -or $Value -is [long] -or $Value -is [decimal] -or $Value -is [single]) { return [double]$Value }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $Default }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $sty = [System.Globalization.NumberStyles]::Float
    $n = 0.0
    if ([double]::TryParse($s, $sty, $inv, [ref]$n)) { return $n }
    if ($s -match '^[+-]?\d+,\d+$' -and [double]::TryParse(($s -replace ',', '.'), $sty, $inv, [ref]$n)) { return $n }
    return $Default
}

function ConvertTo-RATierOrNull {
    <#
        A criticality tier (0..n) -- or $null when it is UNKNOWN.

        NEVER [int]::TryParse into a sentinel (#121). TryParse writes 0 into its out-variable when it
        fails, so a `$tier = -1; TryParse(blank, [ref]$tier)` turns an UNKNOWN tier into TIER 0 -- the
        heaviest weight in the KPI (4.0 by default) and the Tier0BlastRadius consequence factor, both
        for an asset nobody classified. Unknown must stay unknown.
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $d = ConvertTo-RADouble -Value $s -Default ([double]::NaN)
    if ([double]::IsNaN($d)) { return $null }
    return [int][Math]::Floor($d)
}

function Get-SIRiskRating {
    <#
        PURE. #559 the banded RiskScoreTotal (RiskRating / si_risk_rating) -- ONE definition, used by the row score and the
        findings table. Risk factor model v2: each side = base (1..5) + the sum of its factors' impacts (1..5 each, no
        cap), so a finding with no factor scores 1..25 and the owner's example -- (Tier 0 base 5 + PortOpenInternet 5) x
        (very high 5 + ExploitKit 4) -- scores 90.
            Critical  >= 50    e.g. (5 + 5) x (5 + 4) = 90; a Tier 0 asset with a critical vulnerability, 14 x 4 = 56
            High      >= 30    e.g. a Tier 0 critical finding with one factor: (4 + 4) x 4 = 32
            Moderate  >= 15    e.g. Tier 0 x critical with no factor: 4 x 4 = 16
            Low       below
        The thresholds are DATA, not code: the data-model list risk_rating_bands (owner 2026-10-11: 50 / 30 / 15; the customer
        may override it), read by Get-RARiskRatingBands; the values above are the shipped ones and the fallback.
        -Bands: @(critical, high, moderate) (a test seam); -Lower: the lowercase SI vocabulary (si_risk_rating).
    #>
    param([double]$Score, [switch]$Lower, [double[]]$Bands)
    if (-not $Bands -or $Bands.Count -ne 3) {
        $Bands = @(50.0, 30.0, 15.0)
        if (Get-Command -Name Get-RARiskRatingBands -ErrorAction SilentlyContinue) { try { $Bands = [double[]]@(Get-RARiskRatingBands) } catch { $Bands = @(50.0, 30.0, 15.0) } }
    }
    $r = if ($Score -ge $Bands[0]) { 'Critical' } elseif ($Score -ge $Bands[1]) { 'High' } elseif ($Score -ge $Bands[2]) { 'Moderate' } else { 'Low' }
    if ($Lower) { return $r.ToLowerInvariant() }
    return $r
}

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
    # #559 RISK FACTOR MODEL V2 (owner 2026-10-10: "(5+5) x (5+4) = 90", "Sum, no cap"):
    #   RiskConsequenceScore = the ASSET side         = AssetBase (risk index: finding x asset class x tier)
    #                                                   + SUM of the enabled asset factors' impacts   (ConsBase + RfCons)
    #   RiskProbabilityScore = the VULNERABILITY side = VulnerabilityBase (risk index: finding type / category /
    #                                                   subcategory / severity) + SUM of the enabled finding factors'
    #                                                   impacts                                       (ProbBase + RfProb)
    #   RiskScoreTotal = asset side x vulnerability side -- no cap; tier counts ONCE (in AssetBase).
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
        # #559: the score is no longer a product of small counts -- each side is a base (1..5) plus the SUM of its
        # factors' impacts (1..5 each, no cap), so the range widened (the owner's example scores 90). The bands moved
        # with it, in ONE place (Get-SIRiskRating, below), shared with the findings table (RA-Findings.ps1).
        # (the bands are read once per call, above the row loop, exactly as Get-SIRiskRating reads them when given none)
        $tmp['RiskRating'] = Get-SIRiskRating -Score $risk -Bands $__bands
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
        # #559 FIRST MATCH WINS over the index keyed by the SI generic fields (_shared/RA-RiskIndexSi.ps1): the ASSET base
        # (finding x asset class x tier) or the VULNERABILITY base (finding type / category / subcategory / severity).
        # 2.2-keyed rows were translated by New-RiskIndex, so their base values are the 2.2 ones. Memoised on the index
        # per value set: a run scores ~100k findings over a few thousand distinct value sets.
        param(
            [ValidateSet('Asset','Vulnerability')] [string] $Kind,
            [string[]] $Values,
            [psobject] $Index,
            [switch]   $TraceLocal
        )
        $res = Get-SIRiskIndexSiScore -Index $Index -Kind $Kind -Values $Values
        if ($TraceLocal) { Write-Host ("[{0}] {1} -> row {2}, base {3}" -f $Kind, ($Values -join '|'), $res.Position, $res.Score) -ForegroundColor Yellow }
        $res
    }

    if ([string]::IsNullOrWhiteSpace($SecurityDomainInputName)) {
        $SecurityDomainInputName = $RiskIndex.SecurityDomainColumn
    }

    if ($null -eq $Rows) { return @() }
    # a list, never += on an array (a 43,000-row slice copied the whole array once per row)
    $rowsList = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rows) { if ($null -ne $r) { $rowsList.Add($r) } }
    $rowsArr = $rowsList.ToArray()
    $rowsList = $null
    if ($rowsArr.Count -eq 0) { return @() }

    # row dedup by FULL DIMENSIONAL KEY.
    # Original (.189) used (ConfigurationName, ConfigurationId) only -- too narrow:
    # collapsed legitimate tier x severity buckets (e.g. summary reports that
    # produce one row per (Name, Id, Tier, Severity) bucket lost N-1 of N rows).
    # Now dedups by every dimension column the report's `summarize ... by` clause
    # would emit: SecurityDomain, Category, Subcategory, ConfigurationName,
    # ConfigurationId, CriticalityTier, SecuritySeverity. mv-expand/join inflation
    # still collapses correctly because duplicated rows match on ALL these columns.
    $deduped = [System.Collections.Generic.List[object]]::new()
    $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]'
    # Per-report counter for the 4096-char URL-harvest skip; reported after the row loop.
    $script:_mdOversizeSkipped = 0
    $cnInName = if ($PSBoundParameters.ContainsKey('ConfigurationIdInputName') -and $ConfigurationIdInputName) { $ConfigurationIdInputName } else { 'ConfigurationId' }
    # Bucket-level dimensions (Summary reports) PLUS optional per-row identity columns.
    # Detailed reports carry AssetName/AadDeviceId -- absent on Summary rows so they
    # contribute empty-string and don't change Summary dedup. cmdbCriticality / cmdbDataSensitivity
    # added so cmdb-bucketed Summary rows survive (previously collapsed because key omitted them).
    # ConfigurationId is already in the key via $cnInName -- when each Detailed row carries a
    # unique ConfigurationId (CVE id, scid-*, recommendation id, etc.) the Asset+ConfigurationId
    # pair is the per-row identity. No report-specific columns (CVE_ID, etc.) -- keep generic.
    # 🔴 SI_AssetId / AssetId ADDED 2026-08-28. The key contained AssetName -- which is NOT unique --
    # and no asset ID at all, which IS. So two genuinely DIFFERENT assets that share a name and carry
    # the same finding collapsed into ONE row. The catalog records the symptom in its own comment:
    # "the engine's per-row dedup keys on AssetName, so 296 rows collapsed to 12."
    # 🔑 This is the same rule the profile layer now enforces (operator, 2026-08-28: "all assets must
    # have a unique name and identifier") applied one layer up: dedup on the unique field, not the
    # human one. AssetName STAYS in the key, so nothing that deduplicates correctly today changes.
    # ⏱️ ORDER MATTERS AND SI_AssetId IS THE LOAD-BEARING ONE. Calculate-RiskScore runs at
    # Invoke-RiskAnalysis.ps1:3279; the AssetId backfill runs later, at :3385-3408. So `AssetId` is
    # still EMPTY here for every report that does not project it itself, while `SI_AssetId` arrives
    # straight off the query for reports that read the profile join. Both are listed so whichever is
    # populated at THIS point contributes; when neither is, the key is unchanged from today.
    # 🔴 #690 (3) THE FINDING'S TARGET IS PART OF ITS IDENTITY. A finding about an asset AND another resource (a service
    # principal's role on an exposed resource, an attack path from a source to a target) is one finding per target: the key
    # had no target column, so every resource of one service principal collapsed into ONE row (measured on internal
    # 2026-10-15: stored 3 of 20 retrieved -- an SP with a role on 19 exposed resources stored once). The target columns a
    # report carries (TargetAssetId on the attack paths -- the target's CI id, else its graph node id -- and LinkedAzureResourceId on the identity-on-resource
    # reports) are now in the key, appended only when the row carries one -- a row without them has EXACTLY the key text
    # it had before, so nothing changes for any other report, and a true duplicate (an exact copy: the same target too) is
    # still kept once. Same rule as RA-SqlStream.ps1 (Get-RARowDedupKey, $script:RAStreamDedupTargetCols), pinned by
    # SIv3-RaDedupTarget.Tests.ps1.
    $keyCols = @('SecurityDomain','Category','Subcategory','ConfigurationName',$cnInName,'CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity','AssetName','SI_AssetId','AssetId','AadDeviceId')
    $targetKeyCols = @('TargetAssetId','LinkedAzureResourceId')
    # 🔴 #152 -- A SUMMARY ROW IS ALREADY ONE ROW PER GROUP, so only an EXACT copy may be dropped. The key above
    # has no asset list and no cmdbId / cmdbName, so for Summary rows it collapsed two different groups (same
    # tier + severity, different CMDB service) and two bucket halves of one group -- keeping the first and
    # discarding every asset the other listed. Measured 2026-09-28: 74 Summary rows lost across 5 reports in
    # one run. Bucket halves are now merged upstream (Merge-RASummaryBucketRows); here a Summary row is keyed
    # on EVERY column, so nothing distinct is ever dropped.
    $isSummaryReport = ([string]$ReportName -like '*_Summary*')
    foreach ($r in $rowsArr) {
        $rp = $r.PSObject.Properties
        if ($isSummaryReport) {
            # every column, as text (a list's items joined by [char]30) -- a loop, not a pipeline per row
            $fullParts = [System.Collections.Generic.List[string]]::new()
            foreach ($fp in $rp) {
                $v = $fp.Value
                $s = if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { (@(foreach ($e in @($v)) { [string]$e })) -join [char]30 } else { [string]$v }
                $fullParts.Add(('{0}={1}' -f $fp.Name, $s))
            }
            $full = $fullParts -join [char]31
            if ($seenKeys.Add($full)) { [void]$deduped.Add($r) }
            continue
        }
        $cnp = $rp['ConfigurationName']; $cn = if ($cnp) { [string]$cnp.Value } else { '' }
        $cip = $rp[$cnInName];           $ci = if ($cip) { [string]$cip.Value } else { '' }
        if ([string]::IsNullOrWhiteSpace($cn) -and [string]::IsNullOrWhiteSpace($ci)) {
            [void]$deduped.Add($r)   # no name/id key -> keep all (defensive)
            continue
        }
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($col in $keyCols) {
            $kp = $rp[$col]
            $v = if ($kp) { [string]$kp.Value } else { '' }
            [void]$parts.Add($v)
        }
        # the finding's target (#690 (3)): appended only when the row carries one
        $t1 = $rp['TargetAssetId']; $t3 = $rp['LinkedAzureResourceId']
        if (($t1 -and [string]$t1.Value) -or ($t3 -and [string]$t3.Value)) {
            $tparts = [System.Collections.Generic.List[string]]::new()
            foreach ($col in $targetKeyCols) {
                $kp = $rp[$col]
                if ($kp -and $null -ne $kp.Value -and ([string]$kp.Value) -ne '') { [void]$tparts.Add(('{0}={1}' -f $col, [string]$kp.Value)) }
            }
            [void]$parts.Add(('target:' + ($tparts -join ';')))
        }
        $key = ($parts -join '|').ToLowerInvariant()
        if ($seenKeys.Add($key)) { [void]$deduped.Add($r) }
    }
    $dedupRemoved = $rowsArr.Count - $deduped.Count
    if ($dedupRemoved -gt 0) {
        Write-Info ("dedup'd {0} duplicate row(s) by ({1}) -- {2} unique row(s) remaining (mv-expand / join collapse)" -f $dedupRemoved, ($keyCols -join ', '), $deduped.Count)
        $rowsArr = @($deduped.ToArray())
    }

    # PERFORMANCE: a non-Summary slice's rows, de-duplicated above, are scored on several cores (RA-ParallelScore.ps1):
    # each row's output depends only on that row there, so the parts are scored by this same function and put back in
    # order, then sorted once below -- the result of one call over all the rows. $null = scored here, on one core.
    # ON by default (SI_RA_ScoringThreads; 1 = one core). Every slice says how many cores scored it and how long it took.
    $__scoreSw = [System.Diagnostics.Stopwatch]::StartNew()
    if (-not $Trace -and -not $isSummaryReport -and -not $global:RA_ParallelWorker -and (Get-Command -Name Invoke-RAParallelScoring -ErrorAction SilentlyContinue)) {
        $__par = Invoke-RAParallelScoring -Rows $rowsArr -Bound $PSBoundParameters -RiskIndex $RiskIndex
        if ($null -ne $__par) {
            if ([int]$__par.Oversize -gt 0) {
                Write-Info ("MoreDetails: skipped URL harvesting on {0} oversized field value(s) (>4096 chars); links in those fields are NOT in the MoreDetails cell" -f $__par.Oversize)
            }
            $finalOut = [object[]]$__par.Rows
            if ($SortBy -and $SortBy.Count -gt 0) {
                if ($Descending) { $finalOut = @($finalOut | Sort-Object -Property $SortBy -Descending) }
                else             { $finalOut = @($finalOut | Sort-Object -Property $SortBy) }
            }
            if (Get-Command -Name Format-RAScoringLine -ErrorAction SilentlyContinue) { Write-Info (Format-RAScoringLine -Rows $finalOut.Count -Cores ([int]$__par.Cores) -Seconds $__scoreSw.Elapsed.TotalSeconds) }
            return @($finalOut)
        }
    }

    $out   = [System.Collections.Generic.List[object]]::new()
    $total = $rowsArr.Count
    $done  = 0

    # ONE FACTOR, COUNTED ONCE (_shared/RA-FactorKeys.ps1): a token the engine adds (its signals, the asset baseline) is
    # skipped when the row already carries the same catalog factor under another name -- RF_P_InternetExposed,
    # InternetExposureSignal and internet_exposed are one factor. Without the catalog file: letters-only keys.
    $__fkMap = $null
    if (Get-Command -Name Get-RAFactorAliasMap -ErrorAction SilentlyContinue) { $__fkMap = Get-RAFactorAliasMap }
    function _factorKey([string]$t) {
        $k = (([string]$t) -replace '^(?i)RF_[PC]_', '' -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
        if ($__fkMap -and $k -and $__fkMap.ContainsKey($k)) { return [string]$__fkMap[$k] }
        $k
    }

    function _addTok($set, $keys, [string]$tok) {
        $k = _factorKey $tok
        if ($k -and $keys.Contains($k)) { return }
        if ($k) { [void]$keys.Add($k) }
        [void]$set.Add($tok)
    }
    # the row's first column of a list of names (the engine's signal columns, read below). Defined ONCE, here: they read
    # the loop's current row ($r) from this function's scope. (They used to be defined again inside the loop, per row.)
    function _rowHas { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $true } } return $false }
    function _rowVal { param($colNames) foreach ($c in $colNames) { if ($r.PSObject.Properties[$c]) { return $r.$c } } return $null }

    # ---- PERFORMANCE (a query slice is tens of thousands of rows) --------------------------------------------------
    # What is the same for every row of this call is worked out ONCE, here; what repeats across rows (the same CVE's
    # finding factors, the same factor lists) is worked out once per distinct value set and reused. Every value written
    # is the one the per-row work wrote (tests\pester\SIv3-RaRowPerformance.Tests.ps1 compares them with the version
    # before this change, row by row and column by column).
    $__hasCiMode = [bool](Get-Command -Name Select-RACiModeTokens -ErrorAction SilentlyContinue)
    # the catalog's FINDING factors and the fields their conditions read (RA-FactorKeys.ps1, New-RAFindingFactorPlan)
    $__findPlan = $null
    if (Get-Command -Name Get-RAFindingFactorTokens -ErrorAction SilentlyContinue) {
        try {
            if ($null -eq $script:RAFindingFactorList) {
                $script:RAFindingFactorList = @()
                if (Get-Command -Name Get-RAFactorCatalogFactors -ErrorAction SilentlyContinue) { $script:RAFindingFactorList = @(Get-RAFactorCatalogFactors | Where-Object { $_ -and [string]$_.appliesTo -eq 'finding' }) }
            }
            if (Get-Command -Name New-RAFindingFactorPlan -ErrorAction SilentlyContinue) { $__findPlan = New-RAFindingFactorPlan -Factors $script:RAFindingFactorList }
        } catch { $__findPlan = $null }
    }
    $__findMemo = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $__mfMemo = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $__baseMemoA = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    $__baseMemoV = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
    # the RiskRating bands, read as Get-SIRiskRating reads them when it is given none
    $__bands = @(50.0, 30.0, 15.0)
    if (Get-Command -Name Get-RARiskRatingBands -ErrorAction SilentlyContinue) { try { $__bands = [double[]]@(Get-RARiskRatingBands) } catch { $__bands = @(50.0, 30.0, 15.0) } }
    $__numericCols = @('Impact','CvssScore','MaxImpact','AvgImpact','ConfigurationImpact','CredentialExpiryDays','LastSignInDays','DaysInactive')
    $__rxUrl = [regex]::new('https?://[^\s,;<>"`)\]]+')
    $__rxHasUrl = [regex]::new('https?://', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $__rxCve = [regex]::new('CVE-\d{4}-\d{4,}')
    $__rxTokSplit = [regex]::new('\s*;\s*')
    $__progressEvery = [Math]::Max(1, [int][Math]::Floor($total / 200))
    $__prog = $null
    if (Get-Command -Name New-RAProgress -ErrorAction SilentlyContinue) { $__prog = New-RAProgress -What 'risk scores worked out for' -Total $total }

    foreach ($r in $rowsArr) {
        $done++
        # a long scoring is never silent: '<n> of <total> rows' at most every 30 s (RA-RowShaping.ps1, Step-RAProgress)
        if ($null -ne $__prog -and ($done % 200) -eq 0) { Step-RAProgress $__prog $done }
        # progress is shown about 200 times a slice, not once per row
        if ($done -eq 1 -or $done -eq $total -or ($done % $__progressEvery) -eq 0) {
            Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Status "Row $done of $total" -PercentComplete ([math]::Floor(($done/[math]::Max($total,1))*100))
        }

        $domainValue = if ([string]::IsNullOrWhiteSpace($SecurityDomain)) { _get $r $SecurityDomainInputName } else { $SecurityDomain }

        # #559 the values the SI-keyed index compares (RA-RiskIndexSi.ps1): finding type, category, subcategory, component,
        # finding key, asset class (the CI context's si_asset_class, else the row's class / domain) + tier | severity
        $ixVals = Get-SIRiskIndexFindingValues -Row $r -CategoryInputName $CategoryInputName -SubCategoryInputName $SubCategoryInputName `
            -ConfigurationIdInputName $ConfigurationIdInputName -SecuritySeverityInputName $SecuritySeverityInputName `
            -CriticalityTierLevelInputName $CriticalityTierLevelInputName -DomainValue ([string]$domainValue)

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
        #
        # #469 -- THE BASELINE IS ADDED, NEVER A FALLBACK. It used to apply only when the report's Detailed was EMPTY, so
        # a report that named a finding factor (Device_Missing_CVEs: RemoteCodeExecutionRisk) LOST the baseline -- an
        # exploitable CVE scored BELOW the same asset's non-exploitable CVE. The baseline tokens now join the report's tokens (one factor counted once, by the
        # catalog key), so a factor can only ever raise a score. The CI context (RA-CiContext.ps1) already added the
        # catalog's data-sensitivity factors on top of the report's tokens; this makes the no-CI path agree with it.
        $rfConsDetailedRaw = [string](_get $r 'RiskFactor_Consequence_Detailed')
        $derivedFactors = [System.Collections.Generic.List[string]]::new()
        # #527 (5), owner 2026-10-10: "we cannot have tier in risk factor also" -- NO Tier0BlastRadius: tier is its own
        # dimension (the risk index's probability base, the tier multiplier) and a factor never restates it.
        # The baseline that stays is DATA SENSITIVITY (a fact the tier does not carry).
        # #527 (5): no BusinessCriticalAsset -- CMDB criticality is already the weighted-score multiplier
        $cmdbSens = [string](_get $r 'cmdbDataSensitivity')
        if     ($cmdbSens -ieq 'Restricted')   { [void]$derivedFactors.Add('RestrictedDataAccess') }
        elseif ($cmdbSens -ieq 'Confidential') { [void]$derivedFactors.Add('ConfidentialDataAccess') }
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) { $rfConsDetailedRaw = ($derivedFactors -join ';') }
        if ([string]::IsNullOrWhiteSpace($rfConsDetailedRaw)) {
            $rfCons = 0
        } else {
            $rfCons = 0
            foreach ($__e in ($rfConsDetailedRaw -split '\s*;\s*')) { if (-not [string]::IsNullOrWhiteSpace($__e)) { $rfCons++ } }
        }
        $rfProb = [int](_toDouble (_get $r $RiskFactorProbabilityInputName))
        # the report's own NUMBER (a report that names no factor gives its count as a number only) -- #559: each such
        # unnamed factor counts the report_scoped impact on the asset side (Measure-RARowFactors, below)
        $rfProbReportNumber = [int]$rfProb

        # #559 the two bases: the ASSET base (finding x asset class x tier) and the VULNERABILITY base (finding type /
        # category / subcategory / severity). The old names stay for the one stamping call below:
        # $consBase = the asset side's base, $probBase = the vulnerability side's base.
        if ($Trace) {
            $consBase = _findScore -Kind 'Asset' -Values $ixVals.Asset -Index $RiskIndex -TraceLocal:$Trace
            $probBase = _findScore -Kind 'Vulnerability' -Values $ixVals.Vulnerability -Index $RiskIndex -TraceLocal:$Trace
        } else {
            # the same lookup _findScore makes, without its wrapper (it only adds the -Trace line); PURE over the values, so
            # the same values are looked up once per call
            $__ak = $ixVals.Asset -join [char]31
            $consBase = $null
            if (-not $__baseMemoA.TryGetValue($__ak, [ref]$consBase)) { $consBase = Get-SIRiskIndexSiScore -Index $RiskIndex -Kind 'Asset' -Values $ixVals.Asset; $__baseMemoA[$__ak] = $consBase }
            $__vk = $ixVals.Vulnerability -join [char]31
            $probBase = $null
            if (-not $__baseMemoV.TryGetValue($__vk, [ref]$probBase)) { $probBase = Get-SIRiskIndexSiScore -Index $RiskIndex -Kind 'Vulnerability' -Values $ixVals.Vulnerability; $__baseMemoV[$__vk] = $probBase }
        }

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
        foreach ($__nc in $__numericCols) {   # the list is set once, above the loop
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
        # $rfWeightPct, not $rfWeight -- the latter never existed, so with strict mode off every row
        # without a KQL-supplied weight silently published RiskFactor_Weight = 0 instead of 100 (#121).
        if (-not $tmp.Contains('RiskFactor_Weight'))               { $tmp['RiskFactor_Weight']               = [double]$rfWeightPct }
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
        # the factor keys already on the row: a token ADDED below is skipped when its factor is here under another name
        $probKeys = [System.Collections.Generic.HashSet[string]]::new()
        $consKeys = [System.Collections.Generic.HashSet[string]]::new()
        # the tokens the CI context added (RA-CiContext.ps1 marks them): they are ADDED factors, not the report's own
        $ciAdded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($ct in @(_get $r 'si_ci_factor_tokens')) { foreach ($c1 in ([string]$ct -split ';')) { if ($c1.Trim()) { [void]$ciAdded.Add($c1.Trim()) } } }
        if ($tmp.Contains('si_ci_factor_tokens')) { $tmp.Remove('si_ci_factor_tokens') }
        $probReportTokens = 0
        if (-not [string]::IsNullOrWhiteSpace($rfProbExisting)) {
            foreach ($t in $rfProbExisting -split ';') { $tt = $t.Trim(); if ($tt) { if ($probTokens.Add($tt) -and -not $ciAdded.Contains($tt)) { $probReportTokens++ }; [void]$probKeys.Add((_factorKey $tt)) } }
        }
        if (-not [string]::IsNullOrWhiteSpace($rfConsExisting)) {
            foreach ($t in $rfConsExisting -split ';') { $tt = $t.Trim(); if ($tt) { [void]$consTokens.Add($tt); [void]$consKeys.Add((_factorKey $tt)) } }
        }
        # the asset baseline (#469): always added, once per factor
        foreach ($dt in $derivedFactors) { _addTok $consTokens $consKeys $dt }
        # (_rowHas / _rowVal are defined once, above the loop)
        # ---- Probability tokens (likelihood amplifiers) ----
        $isCompromised = _rowVal @('IsCompromisedRecently','EG_IsCompromisedRecently')
        if ($isCompromised -eq $true -or $isCompromised -eq 1 -or [string]$isCompromised -eq 'true') { _addTok $probTokens $probKeys 'IsCompromisedRecently' }
        $machineRisk = [string](_rowVal @('MachineRiskState','EG_MachineRiskState'))
        if ($machineRisk -in 'High','high','High Risk') { _addTok $probTokens $probKeys 'HighMachineRisk' }
        $avStatus = [string](_rowVal @('DefenderAvStatus','MDE_DefenderAvStatus'))
        if ($avStatus -in 'Disabled','Off') { _addTok $probTokens $probKeys 'DefenderAvDisabled' }
        if ($avStatus -in 'OutOfDate','Expired') { _addTok $probTokens $probKeys 'DefenderAvOutOfDate' }
        $onboard = [string](_rowVal @('OnboardingStatus','MDE_OnboardingStatus'))
        if (-not [string]::IsNullOrWhiteSpace($onboard) -and $onboard -ne 'Onboarded') { _addTok $probTokens $probKeys 'Unonboarded' }
        $mgmtType = [string](_rowVal @('DeviceManagementType','MDE_DeviceManagementType'))
        if ($mgmtType -in 'Unknown','Unmanaged','None','MdmContainerOnly') { _addTok $probTokens $probKeys 'Unmanaged' }
        $isExcl = _rowVal @('IsExcluded','MDE_IsExcluded','EG_IsExcluded')
        if ($isExcl -eq $true -or $isExcl -eq 1 -or [string]$isExcl -eq 'true') { _addTok $probTokens $probKeys 'Excluded' }
        $hasInetSig = _rowVal @('HasInternetExposureSignal','EG_HasInternetExposureSignal')
        if ($hasInetSig -eq $true -or $hasInetSig -eq 1 -or [string]$hasInetSig -eq 'true') { _addTok $probTokens $probKeys 'InternetExposureSignal' }
        # ---- Consequence tokens (blast radius amplifiers) ----
        $msCrit = [string](_rowVal @('MsCriticalityLevel','EG_MsCriticalityLevel'))
        if ($msCrit -in 'High','VeryHigh','high','very_high') { _addTok $consTokens $consKeys 'MsCriticalityHigh' }
        $isProd = _rowVal @('IsProductionEnvironment','EG_IsProductionEnvironment')
        if ($isProd -eq $true -or $isProd -eq 1 -or [string]$isProd -eq 'true') { _addTok $consTokens $consKeys 'IsProductionEnvironment' }
        # #527 (5): no ADFS / Exchange token -- the tier rules already make those servers Tier 0, and tier counts once (the risk index)
        $isExo = _rowVal @('IsExchangeOnlineMailbox','EG_IsExchangeOnlineMailbox')
        if ($isExo -eq $true -or $isExo -eq 1 -or [string]$isExo -eq 'true') { _addTok $consTokens $consKeys 'IsExchangeOnlineMailbox' }
        # M4 (V3-DATA-MODEL 2.21), data model 'ci': the CI decides the ASSET risk factors. Every asset-catalog token the
        # report's KQL or the engine derived above from provider columns is dropped unless the CI set it (Add-RACiContext,
        # si_ci_factor_tokens) -- one definition per factor, never counted twice. Finding / report-scoped tokens stay.
        # Then BOTH axes are re-stamped from the kept tokens (also when they are now empty).
        $ciRestamped = $false
        if ([string](_rowVal @('si_data_model')) -eq 'ci' -and $__hasCiMode) {
            $ciRestamped = $true
            $ciCat = Get-RAFactorCatalog
            $ciTok = @(foreach ($__t in (([string](_rowVal @('si_ci_factor_tokens'))) -split '\s*;\s*')) { if ($__t) { $__t } })
            $keepP = [System.Collections.Generic.List[string]]::new(); foreach ($__t in @(Select-RACiModeTokens -Tokens @($probTokens) -Catalog $ciCat -CiTokens $ciTok)) { $keepP.Add($__t) }
            $keepC = [System.Collections.Generic.List[string]]::new(); foreach ($__t in @(Select-RACiModeTokens -Tokens @($consTokens) -Catalog $ciCat -CiTokens $ciTok)) { $keepC.Add($__t) }
            # the CI's own tokens always count (the fallback derivation above may not have produced them)
            foreach ($ciT in $ciTok) {
                $isCons = $false
                $ciK = ConvertTo-RATokenKey $ciT
                if ($ciCat.AssetKeys.ContainsKey($ciK) -and $ciCat.Axis.ContainsKey($ciCat.AssetKeys[$ciK])) { $isCons = ($ciCat.Axis[$ciCat.AssetKeys[$ciK]] -eq 'consequence') }
                $ciList = $keepP; if ($isCons) { $ciList = $keepC }
                $__found = $false
                foreach ($__t in $ciList) { if ((ConvertTo-RATokenKey $__t) -eq $ciK) { $__found = $true; break } }
                if (-not $__found) { $ciList.Add($ciT) }
            }
            $probTokens.Clear(); foreach ($ciT in $keepP) { [void]$probTokens.Add($ciT) }
            $consTokens.Clear(); foreach ($ciT in $keepC) { [void]$consTokens.Add($ciT) }
            $tmp['RiskFactor_Probability_Detailed'] = ($probTokens -join ';'); $rfProb = $probTokens.Count
            $tmp['RiskFactor_Consequence_Detailed'] = ($consTokens -join ';'); $rfConsDetailedRaw = ($consTokens -join ';'); $rfCons = $consTokens.Count
        }
        # ---- #559 RISK FACTOR MODEL V2: each factor ONCE, on its side, with its impact (1..5), summed, no cap ----
        # The tokens gathered above (the report's own, the asset baseline, the engine's signals, the CI's factors) plus the
        # catalog's FINDING factors evaluated on the row's SI fields (KnownExploited, ExploitKit, NetworkNoUserAction,
        # ZeroDay, Overdue, OldVuln ... -- unknown when the row does not carry the field, never a finding, #546) go through
        # Measure-RARowFactors (_shared/RA-FactorKeys.ps1):
        #   * a catalog factor counts on ITS side: an asset factor on the asset side, a finding factor on the vulnerability
        #     side -- whatever column it arrived in; disabled factors are dropped; shown by its SHORT name
        #   * a token the catalog does not know (the report's own question) counts the report_scoped impact on the side its
        #     column always put it: RiskFactor_Probability_Detailed -> asset side (it added to the tier base),
        #     RiskFactor_Consequence_Detailed -> vulnerability side (it added to the severity base)
        #   * one factor counts once (any name, any column); a retired token (break glass, #559) counts nothing
        #   * a report that named NO token and gave a number counts that many unnamed factors on the asset side; data model
        #     'ci' drops that number (the CI decides the asset factors)
        # A factor never lowers a score (every impact is >= 1); the old per-token count and its tier double count are gone.
        $findTok = @()
        if ($null -ne $__findPlan) {
            # the finding factors depend only on the fields their conditions read: the same values (the same CVE) are
            # evaluated once per call (Get-RAFindingFactorPlanKey; $null = a value it cannot key -> evaluated for this row)
            try {
                $__fk = Get-RAFindingFactorPlanKey -Row $r -Plan $__findPlan
                $__hit = $null
                if ($null -ne $__fk -and $__findMemo.TryGetValue($__fk, [ref]$__hit)) { $findTok = $__hit }
                else {
                    $findTok = @(Get-RAFindingFactorTokens -Row $r -Plan $__findPlan)
                    if ($null -ne $__fk) { $__findMemo[$__fk] = $findTok }
                }
            } catch { $findTok = @() }
        }
        $unnamed = 0
        if (-not $ciRestamped -and $probReportTokens -eq 0 -and $rfProbReportNumber -gt 0) { $unnamed = $rfProbReportNumber }
        # Measure-RARowFactors is PURE over its three inputs (and the run's factor map): the same token lists are measured once
        $__aT = @($probTokens); $__vT = (@($consTokens) + @($findTok))
        $__mk = [string]$unnamed + [char]0 + $__aT.Count + [char]0 + ($__aT -join [char]0) + [char]0 + [char]0 + ($__vT -join [char]0)
        $mf = $null
        if (-not $__mfMemo.TryGetValue($__mk, [ref]$mf)) {
            $mf = Measure-RARowFactors -AssetTokens $__aT -VulnerabilityTokens $__vT -UnnamedAssetCount $unnamed
            $__mfMemo[$__mk] = $mf
        }
        # the asset side is the CONSEQUENCE side, the vulnerability side the PROBABILITY side (owner 2026-10-10, #559):
        #   RiskFactor_Consequence_Detailed / RiskFactor_Consequence = the asset factors' short names / their impact sum
        #   RiskFactor_Probability_Detailed / RiskFactor_Probability = the vulnerability factors' short names / their sum
        $rfConsDetailedRaw = (@($mf.AssetTokens) -join ';')
        $rfProbDetailedRaw = (@($mf.VulnerabilityTokens) -join ';')
        $rfCons = [int]$mf.AssetImpact
        $rfProb = [int]$mf.VulnerabilityImpact

        # ---- ONE safe-math call -- stamps all 4 score columns atomically ----
        # asset side = AssetBase + asset impacts (RiskConsequenceScore); vulnerability side = VulnerabilityBase + finding
        # impacts (RiskProbabilityScore); RiskScoreTotal = their product. There is NO other code path that stamps these.
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

        # CANONICAL re-stamp -- the displayed factors and their impact sums, in lock-step with the score. A number a report
        # sets (`| extend RiskFactor_X = N`) is scaffolding and is overridden here.
        $tmp['RiskFactor_Consequence']          = [int]$rfCons
        $tmp['RiskFactor_Consequence_Detailed'] = $rfConsDetailedRaw
        $tmp['RiskFactor_Probability']          = [int]$rfProb
        $tmp['RiskFactor_Probability_Detailed'] = $rfProbDetailedRaw
        # the catalog ids that counted (machines and exports), when the report did not publish its own RiskFactorIds
        if (-not $tmp.Contains('RiskFactorIds') -or [string]::IsNullOrWhiteSpace([string]$tmp['RiskFactorIds'])) {
            $tmp['RiskFactorIds'] = ((@($mf.AssetIds) + @($mf.VulnerabilityIds)) -join ';')
        }

        # #910 THE EXPLAINED SCORE -- additive, nothing above changes: each side's base and each counted factor's impact,
        # so a reader sees base + factors = side and side x side = score. RiskConsequenceBase / RiskProbabilityBase = the
        # bases _setScores used (its normalisation); RiskFactor_*_Impacts = "Name=impact;..." in the order of the _Detailed
        # names, then one "ReportFactor=<impact>" per factor a report gave as a number only. base + sum(impacts) = the side.
        $__xb = $consBase.Score
        $tmp['RiskConsequenceBase'] = $(if ($null -eq $__xb) { 0.0 } elseif ($__xb -is [double]) { [double]$__xb } else { try { [double]$__xb } catch { 0.0 } })
        $__xb = $probBase.Score
        $tmp['RiskProbabilityBase'] = $(if ($null -eq $__xb) { 0.0 } elseif ($__xb -is [double]) { [double]$__xb } else { try { [double]$__xb } catch { 0.0 } })
        $tmp['RiskFactor_Consequence_Impacts'] = (@($mf.AssetImpacts) -join ';')
        $tmp['RiskFactor_Probability_Impacts'] = (@($mf.VulnerabilityImpacts) -join ';')

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
        $mdLines = [System.Collections.Generic.List[string]]::new()

        # 1) Auto-harvest (skipped if YAML pre-populated MoreDetails) and 2b) CVE links -- ONE pass over the row's columns
        # (PERFORMANCE: it was two passes per row). The lines land in the same order as before: the harvested URLs (or the
        # YAML's MoreDetails), then the CVE links.
        $existingMd = if ($tmp.Contains('MoreDetails')) { [string]$tmp['MoreDetails'] } else { '' }
        $__harvest = [string]::IsNullOrWhiteSpace($existingMd)
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $cveSeen = [System.Collections.Generic.HashSet[string]]::new()
        $__cveLines = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $r.PSObject.Properties) {
            $v = $p.Value
            if ($null -eq $v) { continue }
            # a list is walked item by item; a single value once
            $items = if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { @($v) } else { $v }
            foreach ($item in $items) {
                $s = [string]$item
                if ([string]::IsNullOrWhiteSpace($s)) { continue }
                if ($__harvest) {
                    # 🔒 COUNTED, NOT SILENT. A field over 4096 chars is skipped for URL harvesting --
                    # and the fields most likely to exceed it are exactly the CVE/recommendation
                    # rollups whose links matter most. It used to `continue` with no trace, so an
                    # asset could show zero links while its data carried dozens. The skip stands
                    # (scanning multi-MB blobs per row per report is the cost this guard avoids),
                    # but the run now reports how many fields it passed over.
                    if ($s.Length -gt 4096) {
                        $script:_mdOversizeSkipped = 1 + [int]$script:_mdOversizeSkipped
                    }
                    elseif ($s.IndexOf('://', [System.StringComparison]::Ordinal) -ge 0 -and $__rxHasUrl.IsMatch($s)) {   # (the 'https?://' test, compiled once)
                        # Pull out EVERY URL from the field. Prior version used $s -match '^https?://'
                        # which kept the WHOLE string as one entry -- if a YAML rollup had
                        # concatenated two URLs without a separator (e.g.
                        # 'https://nvd.nist.gov/vuln/detail/CVE-2016-9535https://nvd.nist.gov/...')
                        # the cell rendered as one un-clickable run-on. Iterate matches instead.
                        foreach ($urlMatch in $__rxUrl.Matches($s)) {
                            $u = $urlMatch.Value.TrimEnd('.', ',', ';', ')', ']', '"', "'")
                            if ($seen.Add($u)) { [void]$mdLines.Add($u) }
                        }
                    }
                }
                # 2b) CVE links -- harvest CVE-YYYY-NNNNN from any field on the row and append NVD detail URLs (after the
                # lines above). Mostly populates from IssueList / Issues / IssuesList / Recommendations columns where the
                # YAML KQL rolls up `mv-expand` CVEs.
                if ($s.IndexOf('CVE-', [System.StringComparison]::Ordinal) -ge 0) {
                    foreach ($cveMatch in $__rxCve.Matches($s)) {
                        $cve = $cveMatch.Value.ToUpperInvariant()
                        if ($cveSeen.Add($cve)) { [void]$__cveLines.Add(('https://nvd.nist.gov/vuln/detail/{0}' -f $cve)) }
                    }
                }
            }
        }
        if (-not $__harvest) {
            # Preserve YAML-populated MoreDetails as line-per-URL. Some vuln reports
            # build entries like 'CVE-2026-33824 => https://nvd.nist.gov/vuln/detail/CVE-2026-33824'
            # in KQL via strcat. KQL strcat without an explicit separator can also produce
            # 'https://...CVE-X-Yhttps://...' run-ons -- iterate every URL match instead of
            # splitting on a single delimiter so concatenated pairs land as separate lines.
            $seenY = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($piece in ($existingMd -split '\s*;\s*')) {
                $pTrim = $piece.Trim()
                if ([string]::IsNullOrWhiteSpace($pTrim)) { continue }
                # Extract every URL embedded in the piece (handles 'label => URL' AND
                # 'URL1URL2URL3' run-ons). Falls back to the literal piece if no URL is
                # found (preserves rare non-URL labels for downstream consumers).
                $urlMatches = $__rxUrl.Matches($pTrim)
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

        foreach ($__l in $__cveLines) { [void]$mdLines.Add($__l) }

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
        # 🔒 A CAP MUST SAY WHAT IT DROPPED. Both limits below are real data loss in the cell an
        # operator reads, and both used to be silent: 112 links became 25 with a bare "..." and no
        # way to know 87 were missing, so the cell looked complete. An operator cannot audit a number
        # they were never shown. The counts are now part of the value itself.
        if ($mdLines.Count -gt 0) {
            $deduped = [System.Collections.Generic.List[string]]::new()
            $seen2 = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($u in $mdLines) { if ($seen2.Add($u)) { [void]$deduped.Add($u) } }

            $mdTotal = $deduped.Count
            $arr     = @(for ($__i = 0; $__i -lt [Math]::Min(25, $deduped.Count); $__i++) { $deduped[$__i] })   # the first 25 -- no pipeline per row
            $joined  = ($arr -join $sep)
            if ($mdTotal -gt $arr.Count) {
                $joined += ($sep + ('[+{0} more link(s) not shown -- {1} total]' -f ($mdTotal - $arr.Count), $mdTotal))
            }
            if ($joined.Length -gt 4000) {
                $cutMarker = '... [truncated at 4000 chars]'
                $joined = $joined.Substring(0, [Math]::Max(0, 4000 - $cutMarker.Length)) + $cutMarker
            }
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
            [void]$out.Add([pscustomobject]$h)   # [void], not | Out-Null (a pipeline per row)
        } else {
            [void]$out.Add([pscustomobject]$tmp)
        }
    }

    Write-Progress -Id 2 -Activity "Calculating Risk Scores" -Completed

    # 🔒 The 4096-char URL-harvest skip is real loss in MoreDetails, so the run says how often it fired.
    # Silence here previously meant an asset could show no links while its data carried dozens.
    if ([int]$script:_mdOversizeSkipped -gt 0) {
        Write-Info ("MoreDetails: skipped URL harvesting on {0} oversized field value(s) (>4096 chars); links in those fields are NOT in the MoreDetails cell" -f $script:_mdOversizeSkipped)
    }

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
        $assetIds    = [System.Collections.Generic.HashSet[string]]::new()
        $assetNames  = [System.Collections.Generic.HashSet[string]]::new()
        $issueRefs   = [System.Collections.Generic.HashSet[string]]::new()
        # name -> its own row's id. ORDINAL, matching Log Analytics: KQL compares case-sensitively, so
        # two names differing only in case are two distinct assets and must not share an entry.
        $idByName    = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::Ordinal)

        # 🔒 PER-GROUP, NOT PER-REPORT. Operator, 2026-08-28: "each summary group by criticality and
        # severity and list assets and ids. as detailed show each row."
        # 🔴 THE DEFECT THIS REPLACES. The maps above are built ONCE over every row of $out, so the
        # injected list was the WHOLE REPORT's assets pasted onto every row. Measured on snapshot
        # 2026-08-28T18:30:48Z: Identity_*_Summary showed 8 rows / 192 names -- the same 24-asset list
        # repeated 8 times -- beside 8 ids. That is not "the assets in this group"; it is "every asset
        # in the report", and it is wrong for the Summary grain on all 54 reports that rely on the
        # engine to aggregate (only 7 build the list in their own KQL).
        # 🔑 THE GROUPING KEY ALREADY EXISTS: it is the dimension key the per-row dedup uses at the top
        # of this function -- SecurityDomain, Category, Subcategory, ConfigurationName, ConfigurationId,
        # CriticalityTier, SecuritySeverity, cmdb* -- i.e. exactly "criticality and severity and
        # category". Re-using it means the pair follows the report's own grain instead of a second
        # definition of what a group is.
        $grpDimCols  = @('SecurityDomain','Category','Subcategory','ConfigurationName',$cnInName,'CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity')
        $grpNames    = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]' ([System.StringComparer]::Ordinal)
        $grpIdByName = New-Object 'System.Collections.Generic.Dictionary[string,System.Collections.Generic.Dictionary[string,string]]' ([System.StringComparer]::Ordinal)
        $grpKeyOf = {
            param($r)
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($col in $grpDimCols) {
                $v = if ($r.PSObject.Properties[$col]) { [string]$r.PSObject.Properties[$col].Value } else { '' }
                [void]$parts.Add($v)
            }
            ($parts -join '|')
        }
        foreach ($row in $out) {
            $cid = $row.PSObject.Properties[$ConfigurationIdInputName]
            if ($cid -and -not [string]::IsNullOrWhiteSpace([string]$cid.Value)) {
                [void]$assetIds.Add([string]$cid.Value)
            }
            # 🔒 SI_AssetName FIRST -- this is the SUMMARY half of the v3 fill (operator, 2026-08-28:
            # "si_assetname and si_assetid must be 100% populated ... in the old columns"). Summary
            # reports do not publish AssetName at all; the asset shows up here, inside
            # ImpactedAssetsList, so the Detailed-side backfill in Invoke-RiskAnalysis.ps1 cannot
            # reach them. Same value, same precedence, different column -- and still no rename.
            # 📌 Ordered, not coalesced: the first NON-EMPTY candidate wins, so a blank SI_AssetName
            # falls through to the legacy chain instead of blanking the entry.
            # 🔒 THE NAME AND ITS ID ARE RESOLVED IN ONE PASS, ON THE SAME ROW -- operator, 2026-08-28:
            # "they must be consistent". Before this they were TWO independent walks over $out, each
            # into its own HashSet -- and a HashSet is UNORDERED by definition, then each was sorted
            # separately. So the Nth entry of ImpactedAssetsList had no relationship to the Nth entry of
            # ImpactedAssetIds, and the two lists were different LENGTHS (measured live: 555 names
            # against 50 ids). A consumer could not take a row back to the asset it names.
            # 📌 KEYED BY NAME, which keeps ImpactedAssetsList and therefore ImpactedAssetCount
            # BYTE-IDENTICAL to today (audit #25 derives the count from the list). Only ImpactedAssetIds
            # changes: it becomes the SAME LENGTH and POSITIONALLY ALIGNED, carrying an empty string
            # where a row genuinely has no id rather than silently shortening the list.
            $_rowName = ''
            foreach ($candidate in @('SI_AssetName','AssetName','DisplayName','Hostname','Name','ConfigurationName')) {
                $prop = $row.PSObject.Properties[$candidate]
                if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                    $_rowName = [string]$prop.Value
                    [void]$assetNames.Add($_rowName)
                    break
                }
            }
            if ($_rowName) {
                # Same precedence as the Detailed-side backfill in Invoke-RiskAnalysis.ps1, so an asset
                # gets the same identifier whichever report grain it appears in.
                # 🪤 ConfigurationId is deliberately NOT a candidate: it identifies the FINDING, not the
                # asset. Audit #25 exists because those two were confused once already.
                $_rowId = ''
                foreach ($candidate in @('SI_AssetId','AssetId','PrimaryEntityId','MdeDeviceId','AzureResourceId','EntraAccountObjectId')) {
                    $prop = $row.PSObject.Properties[$candidate]
                    if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) {
                        $_rowId = [string]$prop.Value
                        break
                    }
                }
                # First id wins for a given name; a later row may FILL one that was blank, never replace
                # a known id -- so a single row missing the column cannot blank an asset already keyed.
                # 🔴 ContainsKey, NOT Contains. $idByName is a Dictionary[string,string], whose
                # .Contains() takes a KeyValuePair -- so .Contains($name) throws "Cannot find an
                # overload for Contains and the argument count: 1". A HASHTABLE has .Contains($key),
                # which is why the wrong method reads as correct. MEASURED: it failed EVERY Summary
                # report on a live run ("report failed -- skipping" x61) and produced ZERO rows, while
                # the offline suite was 3068/0 green -- nothing there calls Calculate-RiskScore with
                # real rows, so the whole block was unexecuted by the tests that "covered" it.
                if (-not $idByName.ContainsKey($_rowName)) { $idByName[$_rowName] = $_rowId }
                elseif ([string]::IsNullOrWhiteSpace([string]$idByName[$_rowName]) -and $_rowId) { $idByName[$_rowName] = $_rowId }

                # ...and the SAME name/id, filed under THIS ROW'S dimension group, so the injected list
                # is the group's assets rather than the whole report's.
                # (the group key of $grpKeyOf, read inline: this runs once per row)
                $_gkParts = [System.Collections.Generic.List[string]]::new()
                foreach ($col in $grpDimCols) { $_gp = $row.PSObject.Properties[$col]; [void]$_gkParts.Add($(if ($_gp) { [string]$_gp.Value } else { '' })) }
                $_gk = ($_gkParts -join '|')
                if (-not $grpNames.ContainsKey($_gk)) {
                    $grpNames[$_gk]    = [System.Collections.Generic.List[string]]::new()
                    $grpIdByName[$_gk] = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::Ordinal)
                }
                if (-not $grpIdByName[$_gk].ContainsKey($_rowName)) {
                    $grpIdByName[$_gk][$_rowName] = $_rowId
                    [void]$grpNames[$_gk].Add($_rowName)      # distinct per group, first appearance
                } elseif ([string]::IsNullOrWhiteSpace([string]$grpIdByName[$_gk][$_rowName]) -and $_rowId) {
                    $grpIdByName[$_gk][$_rowName] = $_rowId
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

        # 🔑 ImpactedAssetIds -- the ID counterpart of ImpactedAssetsList (operator, 2026-08-28:
        # "impactedassetids ... then they can export ids to find the assets").
        # A Summary row names the impacted assets but, until now, published NO identifier for any of
        # them -- verified across all 55 Summary reports, whose only asset columns are
        # ImpactedAssetsList, ImpactedAssetCount and AssetDetectedInReportName. A name is ambiguous
        # and not joinable; an id lets an operator take the Summary row straight back to the assets.
        #
        # 🪤 DELIBERATELY NOT $assetIds. That set is built from ConfigurationId, which identifies the
        # FINDING, not the asset -- the code above says so in as many words, and audit #25 exists
        # because those two were once confused. ConfigurationId is therefore absent from the chain
        # below: a finding id in a column called ImpactedAssetIds would repeat that exact mistake.
        #
        # Same precedence as the Detailed-side backfill in Invoke-RiskAnalysis.ps1, so an asset gets
        # the same identifier whichever report grain it appears in.
        # 🔴 THE SEPARATE ID WALK IS GONE. It iterated $out a SECOND time into its own HashSet, so the
        # two lists were built independently, were unordered, were sorted separately and came out
        # DIFFERENT LENGTHS (measured live: 555 names, 50 ids). The id is now captured beside its own
        # row's name in the single pass above, and emitted in the SAME ORDER as the names below.
        #
        # 🔴 ORDINAL, NOT Sort-Object. `Sort-Object` compares strings using the CURRENT CULTURE, and this
        # machine runs da-DK where "aa" collates as "å" -- the LAST letter -- so the ORDER of these
        # customer-facing lists differed between a Danish host and an English one for the same estate.
        # SI ships to ~6,000 installs whose locale we do not choose. Same defect already recorded for
        # SI_CorrelationId's seed and hit again in the SI_AssetName collision pass; the rule now lives
        # once, in engine/_shared/SI-AssetIdentity.ps1, rather than being re-derived per caller.
        if (-not (Get-Command Sort-SIOrdinal -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot '..\..\_shared\SI-AssetIdentity.ps1')
        }
        # Ordered, distinct array -- LA dynamic + Excel join both look stable across runs.
        # UNCHANGED by the pairing: same set, same ordering, so ImpactedAssetCount (audit #25 derives it
        # from this list's length) is byte-identical to before.
        $impactedAssets = @(Sort-SIOrdinal -Value ([string[]]@($assetNames)))
        # 🔑 THE IDS FOLLOW THE NAMES, POSITION BY POSITION. Same length, always -- an asset with no
        # resolvable id contributes an EMPTY STRING rather than shortening the list and silently
        # destroying the alignment. That empty is honest: it says "this asset has no id", which is a
        # fact an operator can act on, where a shorter list said nothing at all.
        $impactedAssetIds = @(foreach ($_n in $impactedAssets) {
            if ($idByName.ContainsKey([string]$_n)) { [string]$idByName[[string]$_n] } else { '' }
        })
        $issuesDetails  = @(Sort-SIOrdinal -Value ([string[]]@($issueRefs)))

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
        # don't make sense per-asset in Detailed reports). Detailed reports leave these
        # columns alone -- the YAML projects per-asset variants if needed.
        #
        # 🔴 THE SUFFIX TEST ALONE MISSED SIX REPORTS FOR AS LONG AS THEY HAVE EXISTED.
        # Most reports are named `<Topic>_Summary`, but the attack-path family puts the grain in the
        # MIDDLE -- `Attack_Paths_Summary_Github_to_Azure_Resources`, and `Attack_Paths_Detailed_...`
        # for its counterpart. EndsWith('_Summary') is false for all six, so every Summary-only
        # injection below silently skipped them: they DECLARE ImpactedAssetCount and
        # ImpactedAssetsList in their OutputPropertyOrder and their KQL projects neither, so both
        # columns shipped EMPTY. Declared, never filled -- the same family as the never-wired
        # AssetName / SI_AssetId / tier-aggregator defects.
        #
        # 🪤 WHY MATCHING '_Summary_' IS SAFE AND NOT A GUESS: the catalog was enumerated first. Six
        # report names contain `_Summary` without ending in it, and all six are the attack-path
        # summaries. Their Detailed siblings are named `_Detailed_`, so no Detailed report can match.
        # Verified 2026-08-28 against all 122 reports.
        # 📌 Strictly additive for those six -- the columns are empty today, so there is no existing
        # value for this to change.
        $isSummaryReport = $ReportName -and (
            $ReportName.EndsWith('_Summary', [StringComparison]::OrdinalIgnoreCase) -or
            $ReportName.IndexOf('_Summary_', [StringComparison]::OrdinalIgnoreCase) -ge 0
        )
        $uniqueIssues   = $issueRefs.Count

        $reordered = [System.Collections.Generic.List[object]]::new()
        # PERFORMANCE: built / looked up once per call, not once per row (same values -- see the note above the row loop)
        $mitreCategoryToTactic = $null
        $extraColBlacklist = $null
        $__mitreMemo = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::Ordinal)
        $__compMemo = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::Ordinal)
        $__fixText = $null
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
                    #
                    # AUDIT #25, FOURTH SHAPE -- measured on run 20260813T204314Z, not read.
                    # A `make_set` list does NOT arrive in one shape: it depends on which ROUTE
                    # the query took. The XDR Advanced Hunting path materializes a dynamic column
                    # as an object[]; the LA-direct path (any report reading a *_CL table) returns
                    # it as JSON TEXT. Splitting that text on ';' finds no separator, so the whole
                    # JSON document became a SINGLE list element -- the list rendered as
                    # [["a","b",...17 items...]] and its length read 1 next to a KQL-computed count
                    # of 17. Endpoint_ExcludedAssets_Summary was the one report hitting it, because
                    # it is the one whose Summary reads a CL table.
                    # Parsed AS-IS on purpose: no blank-filtering and no re-sorting on this path,
                    # so the array the engine publishes is exactly the one `array_length` counted
                    # in KQL. Filtering here would recreate the mismatch from the other direction.
                    # 🔴 ASSIGN FIRST, THEN WRAP. NEVER `@($s | ConvertFrom-Json)`.
                    # This is the v2.2.439 correction to the v2.2.438 fix, and the difference is the
                    # HOST, not the data. Windows PowerShell 5.1 -- which is what every SI engine
                    # actually runs on -- writes a deserialized JSON array to the pipeline as ONE
                    # object, so `@($s | ConvertFrom-Json)` collects a single element containing the
                    # whole array. PowerShell 7 enumerates it and yields the items. Measured on this
                    # machine, same string, same second:
                    #     PS 5.1  @($j | ConvertFrom-Json).Count = 1
                    #     pwsh 7  @($j | ConvertFrom-Json).Count = 4
                    # So the fourth-shape fix was correct in pwsh 7 and INERT in production: the list
                    # kept collapsing to a single element beside a KQL count of 69, which is exactly
                    # the defect #25 was opened for -- reintroduced by the fix that closed it.
                    # Assigning to a variable bypasses the pipeline write entirely, so `@()` then sees
                    # a real array and behaves identically on both hosts.
                    # 🪤 SUCCESS IS A FLAG, NOT A NULL CHECK -- the hosts disagree about null here too.
                    # For '[]': PS 5.1 returns a non-null EMPTY array, pwsh 7 returns NULL. So
                    # `if ($null -ne $parsed)` reads "parse failed" on pwsh for a perfectly good empty
                    # array, falls through to the semicolon split, and republishes '[]' as a
                    # one-element list -- the very shape this block exists to prevent. Caught by the
                    # existing empty-array test, which is the only reason it is not in this release.
                    if ($existingImpacted -is [string] -and $existingImpacted.TrimStart().StartsWith('[')) {
                        $parsedImpacted = $null
                        $parsedOk       = $false
                        try { $parsedImpacted = ConvertFrom-Json -InputObject $existingImpacted; $parsedOk = $true }
                        catch { $parsedOk = $false }
                        if ($parsedOk) {
                            $existingImpacted = if ($null -eq $parsedImpacted) { @() } else { @($parsedImpacted) }
                        }
                    }
                    if ($existingImpacted -is [string]) {
                        # ORDINAL -- the same list, re-parsed from the YAML-supplied string form, so it
                        # must order identically to the engine-built branch above or the two paths
                        # produce different orders for the same set.
                        # 🔴 AND IT MUST STILL DEDUPE. `Sort-Object -Unique` did both; Sort-SIOrdinal
                        # only sorts. Dropping the dedupe here put DUPLICATE names into the customer's
                        # ImpactedAssetsList -- caught by SI-ImpactedAssetCount.Tests.ps1 ("expected 3,
                        # but got 4"), which is exactly the audit-#25 invariant that the list and its
                        # count agree. Ordinal set, so the dedupe matches the sort's own comparison.
                        $_split = @($existingImpacted -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                        $_uniq  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                        foreach ($_s in $_split) { [void]$_uniq.Add([string]$_s) }
                        $existingImpacted = @(Sort-SIOrdinal -Value ([string[]]@($_uniq)))
                    }
                } else {
                    # 🔒 THIS ROW'S GROUP, not the whole report. See the note where $grpNames is built:
                    # the injected list must be the assets of this (criticality x severity x category)
                    # group, which is what a Summary row means. Falling back to the report-wide list
                    # only when the row carries no dimension group at all -- that is a report with a
                    # single implicit group, where the two are the same thing anyway.
                    $_gkRow = & $grpKeyOf $row
                    if ($grpNames.ContainsKey($_gkRow) -and $grpNames[$_gkRow].Count -gt 0) {
                        $existingImpacted = @(Sort-SIOrdinal -Value ([string[]]@($grpNames[$_gkRow].ToArray())))
                    } else {
                        $existingImpacted = $impactedAssets
                    }
                }
                # ---- ImpactedAssetPairs: ONE aggregation carrying BOTH halves ------------------------
                # 🔑 A report that emits `make_set(strcat(AssetName,"|",AssetId))` has kept the name and
                # its id TOGETHER through its own summarize. That is the only place the correspondence
                # still exists: afterwards the per-asset rows are gone, so nothing downstream can
                # re-associate them. Splitting here yields two lists of equal length in matching order
                # BY CONSTRUCTION, and both overwrite whatever the separate paths produced.
                # 🪤 SPLIT ON THE LAST '|'. Asset NAMES contain arbitrary punctuation in this estate
                # ("192.168.1.217---Sonos-Play:1---RINCON_..."); asset IDs are GUIDs, ARM paths or MDE
                # ids and contain no pipe. Last-separator is safe where first-separator is not.
                # 📌 The helper column is REMOVED after use -- the engine appends projected-but-
                # undeclared columns automatically, so leaving it would ship a new customer-visible
                # column that is merely an implementation detail of these two.
                # 🔴 THE REMOVAL IS UNCONDITIONAL, and it was not always. It used to sit INSIDE the
                # `$null -ne $_pairsRaw` branch, so a row where the column was PRESENT BUT NULL -- a
                # report that returned no set for that group, or a bucket whose result lacked the
                # column -- skipped the removal and shipped `ImpactedAssetPairs` as a customer-visible
                # column of nulls. That was survivable while 7 reports emitted it; it now applies to
                # all 61 Summary reports, which is exactly the kind of blast-radius change that turns
                # a latent hole into a certainty.
                # 🪤 PER ROW, not per report -- a stale $true here would recount every later row's
                # list even on rows the pair route never touched.
                $_pairReplacedList = $false
                $_pairsRaw = $null
                $_hasPairsCol = $tmp2.Contains('ImpactedAssetPairs')
                if ($_hasPairsCol) { $_pairsRaw = $tmp2['ImpactedAssetPairs'] }
                if ($null -ne $_pairsRaw) {
                    $_pairList = @()
                    if ($_pairsRaw -is [string]) {
                        # LA-direct returns a dynamic as JSON TEXT; XDR returns a real array. Audit #25's
                        # "two shapes" -- handle both or one route silently yields a single element.
                        # 🔴 AND THERE IS A THIRD SHAPE: a BARE STRING. Measured 2026-08-29 on a real
                        # advanced-hunting run -- a `make_set` that produced exactly ONE element arrived
                        # as `mgmt1.2linkit.local|fa6a7a3b-...`, with no brackets and no quotes. That is
                        # not JSON, so ConvertFrom-Json threw, the catch emptied the list, and the row
                        # fell back to the engine aggregate -- i.e. the id went missing again, but ONLY
                        # for groups holding a single asset. Silent, data-dependent, and invisible to any
                        # test that fixtures a multi-element set.
                        # 📌 Bracket test, not try/catch alone: a bare token must NOT be split on ';'
                        # either, because an asset name may legitimately contain one. One element in,
                        # one element out.
                        $_pairStr = [string]$_pairsRaw
                        if ($_pairStr.TrimStart().StartsWith('[')) {
                            try { $_pairList = @((ConvertFrom-Json $_pairStr) | ForEach-Object { [string]$_ }) } catch { $_pairList = @() }
                        } else {
                            $_pairList = @($_pairStr)
                        }
                    } elseif ($_pairsRaw -is [System.Collections.IEnumerable]) {
                        $_pairList = @($_pairsRaw | ForEach-Object { [string]$_ })
                    }
                    $_pairList = @($_pairList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    if ($_pairList.Count -gt 0) {
                        # Ordinal sort so the row reads the same on every host -- Sort-Object is culture
                        # sensitive and this machine is da-DK, where 'aa' collates last.
                        $_pairList = @(Sort-SIOrdinal -Value ([string[]]$_pairList))
                        $_names = [System.Collections.Generic.List[string]]::new()
                        $_ids   = [System.Collections.Generic.List[string]]::new()
                        foreach ($_pr in $_pairList) {
                            $_cut = $_pr.LastIndexOf('|')
                            if ($_cut -lt 0) { [void]$_names.Add($_pr); [void]$_ids.Add('') }
                            else { [void]$_names.Add($_pr.Substring(0, $_cut)); [void]$_ids.Add($_pr.Substring($_cut + 1)) }
                        }
                        $existingImpacted    = @($_names.ToArray())
                        $tmp2['ImpactedAssetIds'] = @($_ids.ToArray())
                        # the count below must describe THIS list, not the one the KQL counted
                        $_pairReplacedList = $true
                    }
                }
                # ...whether or not it parsed, and whether or not it was null.
                if ($_hasPairsCol) { [void]$tmp2.Remove('ImpactedAssetPairs') }

                $tmp2['ImpactedAssetsList'] = $existingImpacted

                # ImpactedAssetIds -- same grain and same rule as the list beside it. YAML wins if a
                # report already projects it per summarize-group; otherwise the engine fills the
                # whole-report aggregate. Additive: a NEW column, so nothing bound to the existing
                # ones changes, which is what makes it safe to ship to every install.
                $existingImpactedIds = $null
                if ($tmp2.Contains('ImpactedAssetIds')) { $existingImpactedIds = $tmp2['ImpactedAssetIds'] }
                $hasYamlImpactedIds = $false
                if ($existingImpactedIds -is [System.Collections.IEnumerable] -and -not ($existingImpactedIds -is [string])) {
                    foreach ($x in $existingImpactedIds) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $hasYamlImpactedIds = $true; break }
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace([string]$existingImpactedIds)) {
                    $hasYamlImpactedIds = $true
                }
                if (-not $hasYamlImpactedIds) {
                    # 🔴 DERIVE THE IDS FROM *THIS ROW'S* NAMES, not from the whole-report aggregate.
                    # THE GRAIN MISMATCH THIS FIXES, measured on snapshot 2026-08-28T18:30:48Z:
                    #   Azure_Recommendations_Summary   356 rows · 525 names · 76,896 ids
                    #   Identity_*_Summary                8 rows · 192 names ·      8 ids
                    # ImpactedAssetsList is built PER ROW by the report's own `summarize ... by`, while
                    # $impactedAssetIds above is built ONCE PER REPORT over all of $out and injected
                    # into every row. So a 2-name row received the report's entire 216-id set, and an
                    # 8-row report received a 1-id set -- the two columns could never align, because
                    # they were never the same grain.
                    # 🔑 $idByName is the report-level name -> id map, so walking THE ROW'S OWN names
                    # through it yields exactly one id per name, in the row's own order. Alignment
                    # becomes structural instead of coincidental.
                    # 📌 A name with no resolvable id contributes an EMPTY STRING at its own position
                    # rather than shortening the list -- an empty says "this asset has no id", which an
                    # operator can act on; a short list says nothing at all.
                    $_rowNames = $existingImpacted
                    if ($_rowNames -is [System.Collections.IEnumerable] -and -not ($_rowNames -is [string])) {
                        # 🔑 Resolve each name against THIS ROW'S GROUP map first. A name can appear in
                        # several groups of the same report carrying a different id (the same host under
                        # two findings), and the report-wide map would hand back whichever was seen
                        # first -- silently attributing one group's id to another group's asset.
                        # The report-wide map stays as the fallback for rows with no group.
                        $_gkIds = $null
                        $_gkRow2 = & $grpKeyOf $row
                        if ($grpIdByName.ContainsKey($_gkRow2)) { $_gkIds = $grpIdByName[$_gkRow2] }
                        $existingImpactedIds = @(foreach ($_rn in $_rowNames) {
                            $_k = [string]$_rn
                            if ($_gkIds -and $_gkIds.ContainsKey($_k)) { [string]$_gkIds[$_k] }
                            elseif ($idByName.ContainsKey($_k))        { [string]$idByName[$_k] }
                            else { '' }
                        })
                    } else {
                        # No per-row name list to key off (the engine supplied the whole-report
                        # aggregate above) -- the report-level pair is already aligned to it.
                        $existingImpactedIds = $impactedAssetIds
                    }
                }
                elseif ($existingImpactedIds -is [string]) {
                    # ORDINAL **and still deduping** -- see the matching note on the names list above.
                    $_splitI = @($existingImpactedIds -split '\s*;\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
                    $_uniqI  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                    foreach ($_s in $_splitI) { [void]$_uniqI.Add([string]$_s) }
                    $existingImpactedIds = @(Sort-SIOrdinal -Value ([string[]]@($_uniqI)))
                }
                # 🔑 THE ONE RESOLVER, LAST. Everything above is the report's OWN chain -- its KQL
                # pair, its profile join, its group map. Whatever is STILL empty is looked up in the
                # run-wide asset-identity map, which is built once from the profile tables and shared
                # by every report.
                # 🔴 THIS IS THE GENERIC MODEL, and it exists because the catalog does not have one:
                # measured 2026-08-30, 84 reports resolve an identity across NINE different
                # hand-written chain variants. Nine dialects cannot be kept in step across ~6,000
                # customer estates -- every fix this session had to be applied to "these four sites
                # but not those six", and twice it was applied to a report that lacked the columns.
                # 📌 Additive and last, so a report that already resolved an id keeps it; this only
                # fills blanks. A name with no identity anywhere still yields '' -- an ExposureGraph
                # subscription node SHOULD report no id rather than borrow one.
                if ((Get-Command Resolve-SIAssetIdentity -ErrorAction SilentlyContinue) -and $isSummaryReport) {
                    $_rn2 = @($existingImpacted)
                    $_ri2 = @($existingImpactedIds)
                    if ($_rn2.Count -gt 0 -and $_ri2.Count -eq $_rn2.Count) {
                        $_anyBlank = $false
                        foreach ($_v in $_ri2) { if ([string]::IsNullOrWhiteSpace([string]$_v)) { $_anyBlank = $true; break } }
                        if ($_anyBlank) {
                            $existingImpactedIds = @(for ($_z = 0; $_z -lt $_rn2.Count; $_z++) {
                                if (-not [string]::IsNullOrWhiteSpace([string]$_ri2[$_z])) { [string]$_ri2[$_z] }
                                else {
                                    $_hit = Resolve-SIAssetIdentity -Name ([string]$_rn2[$_z])
                                    if ($_hit) { [string]$_hit.Id } else { '' }
                                }
                            })
                        }
                    }
                }
                $tmp2['ImpactedAssetIds'] = $existingImpactedIds
                # ONE ASSET, ONE IDENTITY: a resolved id names its asset (the profile's own name), and an Azure VM id that a
                # device carries becomes that device -- so one machine is one entry in this row, in the Top 50 and in the
                # AI rollup, whatever each source calls it. Only changes what the map knows; the count follows the list.
                if ((Get-Command ConvertTo-SICanonicalAssetPairs -ErrorAction SilentlyContinue) -and $isSummaryReport) {
                    $_canon = ConvertTo-SICanonicalAssetPairs -Names ([string[]]@($existingImpacted)) -Ids ([string[]]@($existingImpactedIds))
                    if ($_canon.Changed) {
                        $existingImpacted = @($_canon.Names); $existingImpactedIds = @($_canon.Ids)
                        $tmp2['ImpactedAssetsList'] = $existingImpacted; $tmp2['ImpactedAssetIds'] = $existingImpactedIds
                        $_pairReplacedList = $true
                    }
                }

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
                # 🔴 ...AND WHEN THE PAIR ROUTE REPLACED THE LIST, THE COUNT MUST FOLLOW IT TOO --
                # even if the report computed its own. Measured 2026-08-29 on a full run:
                # Device_Recommendations_Summary published 232 names against 250 ids. The KQL sets
                # `ImpactedAssetCount = array_length(ImpactedAssetsList)` BEFORE the engine overwrites
                # that list from ImpactedAssetPairs, so the count described a list that no longer
                # exists. One asset carrying two different ids is legitimate -- the same host under two
                # findings -- and make_set keeps both, so the pair list is genuinely longer than the
                # name-only set it replaced.
                # 📌 This does not weaken the "a count the report computed wins" rule; it applies it.
                # Audit #25's actual invariant is that the count describes THE SET THAT IS DISPLAYED,
                # and after the pair route the displayed set is the pair-derived one.
                if ($_pairReplacedList -or ($hasYamlImpacted -and -not $yamlSuppliedCount)) {
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

            # 🔴 THE HELPER COLUMN NEVER SHIPS -- ON EITHER GRAIN. The pair block above lives inside
            # `if ($isSummaryReport)`, so its removal only ever ran for Summary reports. A DETAILED
            # report that builds ImpactedAssetPairs therefore shipped it straight to the customer:
            # caught 2026-08-30 on the first Detailed run of this session --
            # `helper columns leaked? ImpactedAssetPairs=True` in a 311-column workbook, from
            # Attack_Paths_Detailed_Credential_Based_Lateral_Movement.
            # 📌 Unconditional, outside the grain gate, because "which grain am I?" is exactly the
            # question that got this wrong once. The column is an implementation detail of
            # ImpactedAssetsList/ImpactedAssetIds and is never a customer-facing column on any report.
            if ($tmp2.Contains('ImpactedAssetPairs')) { [void]$tmp2.Remove('ImpactedAssetPairs') }

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
            if ($null -eq $mitreCategoryToTactic) { $mitreCategoryToTactic = @{   # built once per call (reset above the loop)
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
            } }

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

                # #560 the report's own MITRE references (data-model/finding-texts.locked.json -- SI's own reports carry them as
                # data), else the inference rows of the same template: the first keyword row over SecurityDomain + Subcategory
                # + ConfigurationName, then the security domain's default. No catalog = nothing is guessed.
                # (worked out once per distinct blob + domain in this call: the catalog and the report are the same for every row)
                $__tk = $blob + [char]0 + $secDomain
                $__tres = $null
                if (-not $__mitreMemo.TryGetValue($__tk, [ref]$__tres)) {
                    $tactics    = ''
                    $techniques = ''
                    $raFt = $null
                    if (${function:Get-SIFindingTextCatalog}) { $raFt = Get-SIFindingTextCatalog }
                    if ($null -ne $raFt) {
                        $raRep = Get-SIFindingTextReport -Catalog $raFt -ReportName ([string]$ReportName)
                        if ($null -ne $raRep) {
                            $tactics    = (((Get-SIValueList (Get-SIItemValue $raRep 'si_mitre_tactics')).ToArray() | Where-Object { $_ }) -join ';')
                            $techniques = (((Get-SIValueList (Get-SIItemValue $raRep 'si_mitre_techniques')).ToArray() | Where-Object { $_ }) -join ';')
                        }
                        if (-not $tactics -and -not $techniques) {
                            $inf = Resolve-SIFindingTextInference -Catalog $raFt -Kind mitre -Blob $blob -Domain $secDomain
                            $tactics = [string]$inf.Tactics; $techniques = [string]$inf.Techniques
                        }
                    }
                    $__tres = @($tactics, $techniques)
                    $__mitreMemo[$__tk] = $__tres
                }
                $tmp2['MITRE_Tactics']    = $__tres[0]
                $tmp2['MITRE_Techniques'] = $__tres[1]
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

                # #560 the report's own compliance references (data-model/finding-texts.locked.json), else the template's
                # inference rows (first keyword row, then the security domain's default). No catalog = nothing is guessed.
                # (worked out once per distinct blob + domain in this call)
                $__ck = $blob + [char]0 + $secDomain
                $tags = $null
                if (-not $__compMemo.TryGetValue($__ck, [ref]$tags)) {
                    $tags = ''
                    $raFt = $null
                    if (${function:Get-SIFindingTextCatalog}) { $raFt = Get-SIFindingTextCatalog }
                    if ($null -ne $raFt) {
                        $raRep = Get-SIFindingTextReport -Catalog $raFt -ReportName ([string]$ReportName)
                        if ($null -ne $raRep) { $tags = (((Get-SIValueList (Get-SIItemValue $raRep 'si_compliance_tags')).ToArray() | Where-Object { $_ }) -join ';') }
                        if (-not $tags) { $tags = [string](Resolve-SIFindingTextInference -Catalog $raFt -Kind compliance -Blob $blob -Domain $secDomain).Tags }
                    }
                    $__compMemo[$__ck] = $tags
                }
                $tmp2['ComplianceTags'] = $tags
            } else {
                if (-not $tmp2.Contains('ComplianceTags')) { $tmp2['ComplianceTags'] = '' }
            }

            # #590 HOW TO FIX, on every row (owner 2026-10-11: "i cannot see what app it is related. no remediation, nothing"):
            # the row's own fix (the report's KQL sets si_fix_remediation from the source -- Defender configuration
            # RemediationOptions, Defender for Cloud remediation, the recommended security update of a CVE) wins; a row
            # without one takes its report's how-to-fix text (data-model/finding-texts.locked.json, si_fix_remediation).
            # No catalog or no text = the column stays as the row has it (never guessed).
            $fixNow = ''
            if ($tmp2.Contains('si_fix_remediation')) { $fixNow = [string]$tmp2['si_fix_remediation'] }
            if ([string]::IsNullOrWhiteSpace($fixNow) -and ${function:Get-SIFindingTextCatalog}) {
                # the report's how-to-fix text is the same for every row of the call: read once ('' = none)
                if ($null -eq $__fixText) {
                    $__fixText = ''
                    $raFtFix = Get-SIFindingTextCatalog
                    if ($null -ne $raFtFix) {
                        $raRepFix = Get-SIFindingTextReport -Catalog $raFtFix -ReportName ([string]$ReportName)
                        if ($null -ne $raRepFix) {
                            $fixTxt = [string](Get-SIItemValue $raRepFix 'si_fix_remediation')
                            if (-not [string]::IsNullOrWhiteSpace($fixTxt)) { $__fixText = $fixTxt.Trim() }
                        }
                    }
                }
                if ($__fixText) { $tmp2['si_fix_remediation'] = $__fixText }
            }

            # #561 / #562 THE FINDING'S DIMENSIONS (data-model/classification.locked.json, SI-Classification.ps1): si_component
            # (OS, SQL, Network, ...) and every later finding dimension, from the row's own finding fields -- the title, category,
            # affected product / vendor / CPE and the Azure type of the asset it is on. One value per dimension, never blank.
            if (${function:Set-SIRaRowDimensions}) { $null = Set-SIRaRowDimensions -Row $tmp2 }

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
            # Unknown stays $null and takes the switch's default weight -- a failed TryParse used to
            # write 0 here and weight an unclassified asset as Tier 0 (#121).
            $tierVal  = $null
            if ($tmp2.Contains('CriticalityTier'))      { $tierVal = ConvertTo-RATierOrNull $tmp2['CriticalityTier'] }
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
                foreach ($forceCol in 'RiskFactor_Consequence_Detailed','MITRE_Tactics','MITRE_Techniques','ComplianceTags','MoreDetails','RiskScoreDomainKPI','RiskScoreKPI','si_component','si_servicenow_subci','si_patch_cycle') {
                    # #561 / #772 the finding's dimensions (component, ServiceNow sub-CI): forced only when the classification set them
                    if (-not $h2.Contains($forceCol) -and (($forceCol -notin 'si_component', 'si_servicenow_subci', 'si_patch_cycle') -or $tmp2.Contains($forceCol))) { $h2[$forceCol] = $tmp2[$forceCol] }
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
                if ($null -eq $extraColBlacklist) { $extraColBlacklist = @{   # built once per call (reset above the loop)
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
                } }
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
        $tmpList = [System.Collections.Generic.List[object]]::new()
        foreach ($x in $out) { $tmpList.Add($x) | Out-Null }
        $finalOut = [object[]]$tmpList.ToArray()
    }

    if ($SortBy -and $SortBy.Count -gt 0) {
        if ($Descending) { $finalOut = @($finalOut | Sort-Object -Property $SortBy -Descending) }
        else             { $finalOut = @($finalOut | Sort-Object -Property $SortBy) }
    }

    # the slice's line (one core here): a worker's part says nothing (the main run says the slice's line)
    if (-not $global:RA_ParallelWorker -and (Get-Command -Name Format-RAScoringLine -ErrorAction SilentlyContinue)) {
        $__why = ''
        if ($Trace) { $__why = 'trace' } elseif (Get-Command -Name Get-RAOneCoreReason -ErrorAction SilentlyContinue) { $__why = Get-RAOneCoreReason -Count $rowsArr.Count -Summary ([bool]$isSummaryReport) }
        if (-not $__why) { $__why = 'the several-core step did not run -- see the line before' }
        Write-Info (Format-RAScoringLine -Rows $finalOut.Count -Cores 1 -Seconds $__scoreSw.Elapsed.TotalSeconds -Why $__why)
    }
    return @($finalOut)
}
