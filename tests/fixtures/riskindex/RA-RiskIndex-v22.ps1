#######################################################################################################
#  TEST FIXTURE -- the v2.2 risk index lookup, VERBATIM (git: engine/risk-analysis/_shared/RA-ExcelReport.ps1
#  New-RiskIndex and RA-RiskScore.ps1 Calculate-RiskScore's _mkKey / _toDouble / _findScore, before the
#  first-match change of 2026-10-04). Only the function name New-RiskIndex -> New-RiskIndexV22 changed, and the
#  three nested helpers are wrapped in Get-RiskScoreV22. Never edit the bodies: they are the rule v3 must equal.
#######################################################################################################
function New-RiskIndexV22 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]] $CsvRows,
        [Parameter(Mandatory=$true)][string] $ColSecurityDomain,
        [Parameter(Mandatory=$true)][string] $ColCategory,
        [Parameter(Mandatory=$true)][string] $ColSubCategory,
        [Parameter(Mandatory=$true)][string] $ColConfigId,
        [Parameter(Mandatory=$true)][string] $ColSevValue,
        [Parameter(Mandatory=$true)][string] $ColTierValue,
        [Parameter(Mandatory=$true)][string] $ColConseqScore,
        [Parameter(Mandatory=$true)][string] $ColProbScore
    )

    # StrictMode-safe normalization
    $CsvRows = @($CsvRows)
    if ($CsvRows.Count -eq 0) { throw "Risk definitions CSV is empty." }

    $firstCols = @($CsvRows[0].PSObject.Properties.Name)

    # Validate required columns (StrictMode-safe even when only 1 is missing)
    $required = @(
        $ColCategory,
        $ColSubCategory,
        $ColConfigId,
        $ColSevValue,
        $ColTierValue,
        $ColConseqScore,
        $ColProbScore
    )

    $missing = @($required | Where-Object { $firstCols -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "CSV missing required columns: $($missing -join ', ')"
    }

    function _MakeKey {
        param(
            [Parameter(Mandatory=$true)][object] $Row,
            [Parameter(Mandatory=$true)][string[]] $Pattern
        )

        $vals = foreach ($c in @($Pattern)) {
            $v = $Row.$c
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    # Matching sequences (ordered from most-specific to least-specific)
    $seqWithDomain_Conseq = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSevValue),
        @($ColSecurityDomain,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Conseq = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColCategory,$ColSubCategory,$ColSevValue),
        @($ColCategory,$ColSevValue),
        @($ColSevValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    $seqWithDomain_Prob = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColTierValue),
        @($ColSecurityDomain,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Prob = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColCategory,$ColSubCategory,$ColTierValue),
        @($ColCategory,$ColTierValue),
        @($ColTierValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    # Maps per pattern (StrictMode-safe creation)
    $mapsConseq_With = @()
    foreach ($pat in $seqWithDomain_Conseq) { $mapsConseq_With += ,@{} }

    $mapsConseq_No = @()
    foreach ($pat in $seqNoDomain_Conseq) { $mapsConseq_No += ,@{} }

    $mapsProb_With = @()
    foreach ($pat in $seqWithDomain_Prob) { $mapsProb_With += ,@{} }

    $mapsProb_No = @()
    foreach ($pat in $seqNoDomain_Prob) { $mapsProb_No += ,@{} }

    foreach ($row in $CsvRows) {

        for ($i = 0; $i -lt @($seqWithDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_With[$i].ContainsKey($k)) { $mapsConseq_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_No[$i].ContainsKey($k)) { $mapsConseq_No[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqWithDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Prob[$i]
            if ($k -and -not $mapsProb_With[$i].ContainsKey($k)) { $mapsProb_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Prob[$i]
            if ($k -and -not $mapsProb_No[$i].ContainsKey($k)) { $mapsProb_No[$i][$k] = $row }
        }
    }

    [pscustomobject]@{
        SecurityDomainColumn = $ColSecurityDomain
        CategoryColumn       = $ColCategory
        SubCategoryColumn    = $ColSubCategory
        ConfigIdColumn       = $ColConfigId
        SevValueColumn       = $ColSevValue
        TierValueColumn      = $ColTierValue
        ConseqScoreColumn    = $ColConseqScore
        ProbScoreColumn      = $ColProbScore

        Conseq_WithDomainPatterns = $seqWithDomain_Conseq
        Conseq_NoDomainPatterns   = $seqNoDomain_Conseq
        Prob_WithDomainPatterns   = $seqWithDomain_Prob
        Prob_NoDomainPatterns     = $seqNoDomain_Prob

        Conseq_WithDomainMaps = $mapsConseq_With
        Conseq_NoDomainMaps   = $mapsConseq_No
        Prob_WithDomainMaps   = $mapsProb_With
        Prob_NoDomainMaps     = $mapsProb_No
    }
}

function Get-RiskScoreV22 {
    param([psobject]$RiskIndex, [hashtable]$kv, [ValidateSet('Consequence','Probability')][string]$Kind, [switch]$Trace)
    function _mkKey([hashtable]$kv,[string[]]$pattern) {
        $vals = foreach ($c in $pattern) {
            $v = $kv[$c]
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
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
    (_findScore -Kind $Kind -kv $kv -Index $RiskIndex -TraceLocal:$Trace).Score
}
