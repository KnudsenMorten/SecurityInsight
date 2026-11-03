#Requires -Version 5.1
<#
    THE KEY FIGURES' TALLY -- the run-end KPI rollup of Risk Analysis (the per-row secure score, the severity counts, the
    patch cycle and the Protection Score's findings), as ONE copy of the logic that two places use (2026-10-31).

    WHY THIS IS ITS OWN FILE. After the reports, the AI summary's pass and the key figures' pass each read every View row
    of the result from SQL. At the largest install that was 1.57 M rows twice at ~93 rows/s (16,880 s and 13,667 s), and
    the cost is the volume of DetailJson per row (~4 KB), not the read order. So the key figures' per-row tally now runs
    INSIDE the AI summary's pass, on the same rows, and the key figures' own pass reads the rows only when that did not
    happen. Both use the functions below -- there is exactly one copy of the setup, the per-row tally and the result.

      New-RAKpiState       the setup: the domain / severity accumulators, the patch-cycle tally and the Protection Score's
                           tally with its CI inventory (sets $script:RAProtectionReason / $script:RAProtectionFromStore as
                           the inline block did). Complete = $false.
      Add-RAKpiRow         one row into the state (the per-row tally, as the inline loop was).
      Get-RAKpiAiPassState the AI summary's pass after its last page: its state marked Complete, or $null.
      Complete-RAKpiState  the result: the per-domain weighted average, the global score, the band -- the $global:RA_KPI
                           object (PURE over the state).
      Test-RAKpiStateComplete  a state that may be used: it went over every View row to the end. NEVER a half-filled one.
      Invoke-RAKpiPass     the key figures' block: takes the AI summary's state when it is complete, otherwise reads every
                           row itself (a fresh state and its own pager), exactly as before.

    DATA TRUST FIRST. The AI summary's pass marks its state Complete only after its pager returned its last page; a pass
    that threw, stopped early, or did not run at all leaves no complete state, and the key figures read everything
    themselves. A partial key figure is never used. The in-memory path (no stream) is not merged at all.
    PS 5.1 and 7; no module. NO EMOJI IN THIS FILE.
#>

# the patch cycle and the Protection Score are the engine's own functions (engine\_shared), loaded here at the file's load
# so that a state made inside a function never loses them to that function's scope
foreach ($__kpiDep in @('SI-PatchCycle.ps1', 'SI-ProtectionScore.ps1')) {
    $__kpiDepCmd = $(if ($__kpiDep -eq 'SI-PatchCycle.ps1') { 'New-SIPatchCycleTally' } else { 'New-SIProtectionTally' })
    if (-not (Get-Command -Name $__kpiDepCmd -ErrorAction SilentlyContinue)) {
        $__kpiDepPath = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', $__kpiDep)
        if ([System.IO.File]::Exists($__kpiDepPath)) { . $__kpiDepPath }
    }
}
Remove-Variable -Name __kpiDep, __kpiDepCmd, __kpiDepPath -ErrorAction SilentlyContinue

function Get-RAKpiTierWeight {
    <# The tier weight of a row (T0..T3 from the SI_RiskReport_TierMultiplier_* settings; unknown = 1.0). #>
    param([int]$Tier)
    switch ($Tier) {
        0       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T0) { [double]$global:SI_RiskReport_TierMultiplier_T0 } else { 4.0 } }
        1       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T1) { [double]$global:SI_RiskReport_TierMultiplier_T1 } else { 2.0 } }
        2       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T2) { [double]$global:SI_RiskReport_TierMultiplier_T2 } else { 1.0 } }
        3       { if ($null -ne $global:SI_RiskReport_TierMultiplier_T3) { [double]$global:SI_RiskReport_TierMultiplier_T3 } else { 0.5 } }
        default { 1.0 }
    }
}

function Get-RAKpiDomainFromReportName {
    <#
        PURE. v2.2.404 -- derive SecurityDomain from report name when the per-row field is empty. Most YAML reports don't
        declare a top-level SecurityDomain (it's optional), so the per-row field ends up blank on the majority of rows and
        the KPI table's Total cells stop matching the per-domain row sums (the Total uses unfiltered counts, per-domain uses
        only canonical SecurityDomain hits). Matching report-name prefixes back to one of the 4 canonical domains restores
        arithmetic invariance.
    #>
    param([string]$ReportName)
    if ([string]::IsNullOrWhiteSpace($ReportName)) { return '' }
    $rn = $ReportName.ToLowerInvariant()
    # Endpoint-specific Attack_Paths_* patterns FIRST (more specific than the
    # PublicIP family below). Public_IP_to_VM is a path from internet -> VM:
    # the VM is the target and classifies as Endpoint, not PublicIP.
    if ($rn -match 'public_ip_to_vm')                                  { return 'Endpoint' }
    if ($rn -match 'device_with_high_severity_vulnerabilities')        { return 'Endpoint' }
    # PublicIP family (anchored to prefix only -- avoids matching Public_IP_to_VM)
    if ($rn -match '^publicip_')                                       { return 'PublicIP' }
    # Endpoint family (prefix)
    if ($rn -match '^(device|endpoint)_')                              { return 'Endpoint' }
    # Identity family
    if ($rn -match '^identity_')                                       { return 'Identity' }
    if ($rn -match 'credential_based_lateral_movement')                { return 'Identity' }
    if ($rn -match 'identity_group_membership')                        { return 'Identity' }
    if ($rn -match 'data_sensitivity_to_exposed_credentials')          { return 'Identity' }
    # Azure family (catch-all for remaining Attack_Paths_* targeting Azure)
    if ($rn -match '^azure_')                                          { return 'Azure' }
    if ($rn -match 'github_to_azure')                                  { return 'Azure' }
    if ($rn -match 'to_azure_resources')                               { return 'Azure' }
    return ''
}

function New-RAKpiState {
    <#
        The key figures' setup, before the first row: the accumulators, the patch-cycle tally and the Protection Score's
        tally (with the run's CI inventory). -Now is "now" for the patch cycle and the protection ages (the caller's clock).
        Throws only where the inline setup threw (the patch cycle's functions missing); the Protection Score's own problems
        are caught here and said, as before.
    #>
    param([datetime]$Now = [datetime]::UtcNow)
    # #638: the rows a page at a time (from SQL; or the result in memory as one page) -- the KPI is a running sum
    $st = @{
        DomainSet   = @('Endpoint','Identity','Azure','PublicIP')
        SevCount    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0 }
        SevByDomain = @{
            Endpoint = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
            Identity = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
            Azure    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
            PublicIP = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Other = 0; Total = 0 }
        }
        # Per-domain weighted-avg accumulators (numerator = sum(rowKpi * tierWeight),
        # denominator = sum(tierWeight)). Plus a per-domain row counter.
        DomainAcc   = @{
            Endpoint = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
            Identity = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
            Azure    = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
            PublicIP = @{ Numer = 0.0; Denom = 0.0; Rows = 0 }
        }
        Patch       = $null
        Prot        = $null
        Rows        = 0L
        # set ONLY by the pass that fed the state every row to the end (Test-RAKpiStateComplete)
        Complete    = $false
    }

    # #636 (owner 2026-10-19: "include both angles with gaps vs. monthly lifecycle"): the missing patches by PATCH CYCLE -- in the
    # monthly cycle, catch-up, no single update -- tallied in the same pass (engine\_shared\SI-PatchCycle.ps1); the mail shows
    # the three groups instead of a raw total
    $__patchDays = 30; if ($global:SI_PatchCycle_CatchUpDays -and [int]$global:SI_PatchCycle_CatchUpDays -gt 0) { $__patchDays = [int]$global:SI_PatchCycle_CatchUpDays }
    $st.Patch = New-SIPatchCycleTally -CollectionTime $Now -CatchUpDays $__patchDays
    # #636 (owner 2026-10-19): the PROTECTION SCORE replaces the old 0-100 KPI in the mail, the kept view and the pages -- ONE
    # engine function for both editions (engine\_shared\SI-ProtectionScore.ps1), fed here by the Detailed run's findings and the
    # run's CI index; Pro also stores it per collection (the data sync, the same rules in SQL). A Summary run has no
    # per-asset findings: it takes the Detailed run's score from the shared cache, else its mail says (one plain line) that the
    # score is in the Detailed report. Without a score the mail always says WHY ($script:RAProtectionReason).
    $__prot = $null
    $script:RAProtectionReason = ''
    # PRO (owner 2026-10-22: "one computation, never two that can differ"): the score of a Detailed run that writes its result
    # to the Pro database is the STORED one -- the data sync's key figures of this collection, the number the web app shows.
    # This run does not count it at all (no walk over every CI); its mail waits for the stored figures in sidata.RaMailOutbox
    # and the data sync sends it with them (engine\_shared\data-sql\SI-RaMailOutbox.ps1). Community counts it here.
    $script:RAProtectionFromStore = $false
    try {
        $script:RAProtectionFromStore = (Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)) -ne 'Summary' -and
            -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSettingsVersion) -and [bool]$script:RAStreamOn -and $null -ne $script:RAStream -and
            $null -ne $script:RAStream.Invoke -and [int]$script:RAStream.CollectionId -gt 0 -and -not [bool]$script:SIWhatIf -and $script:RAScaleRole -ne 'worker'
    } catch { $script:RAProtectionFromStore = $false }
    try {
        if ($script:RAProtectionFromStore) {
            Write-Info '[SCORE] Protection Score: taken from this run''s stored figures once the data sync has computed them -- the mail waits for them (the numbers the web app shows)'
        } elseif ((Get-RAReportGrainLabel -ReportTemplate ([string]$global:ReportTemplate)) -eq 'Summary') {
            $script:RAProtectionReason = Get-SIProtectionReason 'summary'
        } else {
            $__ciIdxP = $global:RA_CiIndex
            if ($null -eq $__ciIdxP -and (Get-Command -Name Get-RACiIndex -ErrorAction SilentlyContinue)) { $__ciIdxP = Get-RACiIndex }
            if ($global:RA_CiIndexProblem) { $script:RAProtectionReason = 'the CIs could not be read: ' + ([string]$global:RA_CiIndexProblem) }
            elseif ($null -eq $__ciIdxP -or -not $__ciIdxP.ById -or $__ciIdxP.Count -le 0) { $script:RAProtectionReason = Get-SIProtectionReason 'no-cis' }
            if ($null -ne $__ciIdxP -and $__ciIdxP.ById -and $__ciIdxP.Count -gt 0) {
                $__prot = New-SIProtectionTally -CollectionTime $Now
                $__seenCi = @{}
                foreach ($__c in $__ciIdxP.ById.Values) {
                    $__cid = [string]$__c.si_ci_id
                    if (-not $__cid -or $__seenCi.ContainsKey($__cid)) { continue }
                    $__seenCi[$__cid] = $true
                    $__at = ''; if ($__c.PSObject.Properties['si_asset_type']) { $__at = [string]$__c.si_asset_type }
                    # the stale flag is TEXT from the database ('true' / 'false', ConvertFrom-RACiSqlRows) and a bool from Log
                    # Analytics -- read as text: [bool]'false' is $true, and every CI counted as inactive (live 2026-10-20..22:
                    # "0 assets in scope" on every Detailed run)
                    $__stale = $false; if ($__c.PSObject.Properties['si_stale_']) { $__stale = ([string]$__c.si_stale_).Trim() -in 'true', '1' }
                    Add-SIProtectionAsset -Tally $__prot -Id $__cid -Class ([string]$__c.si_class) -AssetType $__at -Tier $__c.si_tier -Active (-not $__stale)
                }
                $__seenCi = $null
            }
        }
    } catch { Write-Warn2 ("Protection score: not computed in this run -- {0}" -f $_.Exception.Message); $__prot = $null; $script:RAProtectionReason = ('it could not be computed: ' + $_.Exception.Message) }
    $st.Prot = $__prot
    $st
}

function Add-RAKpiRow {
    <# One row into the key figures' state -- the per-row tally (the patch cycle, the protection findings, the severity
       counts, the per-domain weighted secure score). #>
    param([Parameter(Mandatory)][hashtable]$State, $Row)
    $r = $Row
    $State.Rows++
    Add-SIPatchCycleRow -Tally $State.Patch -Row $r
    if ($null -ne $State.Prot) { Add-SIProtectionRow -Tally $State.Prot -Row $r }
    $dom = ''
    if ($r.PSObject.Properties['SecurityDomain']) { $dom = [string]$r.SecurityDomain }
    if ($dom -eq 'PublicIp') { $dom = 'PublicIP' }
    # v2.2.404 -- fallback derivation from report name when per-row field is empty.
    # Without this, rows from YAML reports that don't declare a top-level
    # SecurityDomain end up uncounted in the per-domain rows of the KPI
    # table, while the Total row counts them. Customer-reported bug:
    # Detailed-template Total cells showed 71,278 / 8218 crit while per-domain
    # rows summed to 1122 / 53 crit -- 98% of rows had blank SecurityDomain.
    if ([string]::IsNullOrWhiteSpace($dom) -and $r.PSObject.Properties['Report']) {
        $dom = Get-RAKpiDomainFromReportName ([string]$r.Report)
    }

    # Severity tally (used by the email's Domain x Severity table)
    $sevText = ''
    if ($r.PSObject.Properties['SecuritySeverity']) { $sevText = [string]$r.SecuritySeverity }
    $sevBucket = switch -Regex ($sevText) {
        '^(?i)(critical|very high)$' { 'Critical'; break }
        '^(?i)high$'                 { 'High';     break }
        '^(?i)medium-?high$'         { 'High';     break }
        '^(?i)medium$'               { 'Medium';   break }
        '^(?i)low$'                  { 'Low';      break }
        default                      { 'Other' }
    }
    $State.SevCount[$sevBucket]++
    if ($State.SevByDomain.ContainsKey($dom)) {
        $State.SevByDomain[$dom][$sevBucket]++
        $State.SevByDomain[$dom]['Total']++
    }

    if (-not ($State.DomainSet -contains $dom)) { return }

    # Pull the per-row RiskScoreKPI (already computed upstream)
    $rowKpi = 100.0
    if ($r.PSObject.Properties['RiskScoreKPI']) { $rowKpi = ConvertTo-RADouble -Value $r.RiskScoreKPI -Default 100.0 }

    # Tier weight for this row
    # Unknown stays -1 (the default weight). A failed [int]::TryParse wrote 0 here and weighted an
    # unclassified asset as Tier 0 -- 4x in the headline KPI (#121).
    $tierVal = -1
    if ($r.PSObject.Properties['CriticalityTier']) { $__t = ConvertTo-RATierOrNull $r.CriticalityTier; if ($null -ne $__t) { $tierVal = [int]$__t } }
    $tw = Get-RAKpiTierWeight $tierVal

    # v2.2.314 -- per-row population weight. Summary rows represent N
    # asset-findings collapsed into one row; Detailed rows are one-finding-per-asset
    # (weight = 1). Multiplying by population converges Summary KPI to Detailed KPI on the
    # same underlying data -- pre-v2.2.314 the two reports diverged by 1-9 points purely
    # from per-row vs per-asset-finding averaging. Customer ask: "my customers cannot
    # understand why the risk score is not same % between summary and detailed".
    #
    # AUDIT #52 -- the population is now ImpactedAssetCount. It was
    # TotalIssuesImpactedAssets, which has been removed as incorrect: it disagreed with
    # ImpactedAssetCount on 64 of 311 live rows, with ratios from 0.125 to 2048.5.
    # THAT WAS NOT COSMETIC. This weight feeds the headline risk score, so a row whose
    # count was inflated 2048x dominated its domain's KPI, and rows whose count was too
    # low (ratio 0.125) were under-counted. The scores this converged were converging on a
    # distorted population.
    # ImpactedAssetCount is the honest population for a Summary row: array_length of the
    # asset list actually shown beside it, so the weight and the evidence agree. It is also
    # what the engine already substituted whenever the KQL supplied nothing -- so for the
    # 247 of 311 rows that were already consistent, the weighting is unchanged.
    $rowWeight = 1.0
    if ($r.PSObject.Properties['ImpactedAssetCount']) {
        $iac = 0
        if ([int]::TryParse([string]$r.ImpactedAssetCount, [ref]$iac) -and $iac -gt 0) {
            $rowWeight = [double]$iac
        }
    }

    $State.DomainAcc[$dom].Numer += $rowKpi * $tw * $rowWeight
    $State.DomainAcc[$dom].Denom += $tw * $rowWeight
    $State.DomainAcc[$dom].Rows++
}

function Test-RAKpiStateComplete {
    <# PURE. $true only for a state that went over every row to the end (Complete set by the pass that filled it). #>
    param($State)
    ($State -is [hashtable]) -and ($State['Complete'] -eq $true) -and ($null -ne $State['Patch'])
}

function Get-RAKpiAiPassState {
    <#
        The AI summary's pass, after its last page: the state it filled, marked Complete, when every View row went in --
        its pager returned its last page (-PagerDone) and the state counted exactly the rows the pass read (-Rows).
        Anything else -- no state (the setup or a row failed), a pager not at its end, a count that differs -- is $null,
        and the key figures read the rows themselves. Never a half-filled state.
    #>
    param($State, [bool]$PagerDone, [long]$Rows)
    if (-not ($State -is [hashtable]) -or $null -eq $State['Patch']) { return $null }
    if (-not $PagerDone -or [long]$State['Rows'] -ne $Rows) { return $null }
    $State['Complete'] = $true
    $State
}

function Complete-RAKpiState {
    <# PURE over the state. The key figures as the $global:RA_KPI object (the per-domain weighted average, the global
       score as the weighted average of the domain scores, the band, the counts and the patch cycle). #>
    param([Parameter(Mandatory)][hashtable]$State)
    $DomainSet = $State.DomainSet; $domainAcc = $State.DomainAcc; $sevCount = $State.SevCount; $sevByDomain = $State.SevByDomain
    # ----- per-domain weighted average -----
    $domainScore = @{}
    foreach ($d in $DomainSet) {
        if ($domainAcc[$d].Denom -gt 0) {
            $domainScore[$d] = [int][Math]::Round($domainAcc[$d].Numer / $domainAcc[$d].Denom, 0)
        } else {
            $domainScore[$d] = 100   # no findings -> Very Good
        }
    }

    # ----- global = weighted average of domain scores by domain weight -----
    $domainWeights = @{
        Endpoint = if ($null -ne $global:SI_RiskReport_GlobalWeight_Endpoint) { [double]$global:SI_RiskReport_GlobalWeight_Endpoint } else { 0.30 }
        Identity = if ($null -ne $global:SI_RiskReport_GlobalWeight_Identity) { [double]$global:SI_RiskReport_GlobalWeight_Identity } else { 0.30 }
        Azure    = if ($null -ne $global:SI_RiskReport_GlobalWeight_Azure)    { [double]$global:SI_RiskReport_GlobalWeight_Azure }    else { 0.20 }
        PublicIP = if ($null -ne $global:SI_RiskReport_GlobalWeight_PublicIP) { [double]$global:SI_RiskReport_GlobalWeight_PublicIP } else { 0.20 }
    }
    $gNumer = 0.0; $gDenom = 0.0
    foreach ($d in $DomainSet) {
        $w = $domainWeights[$d]
        $gNumer += $domainScore[$d] * $w
        $gDenom += $w
    }
    $globalScore = if ($gDenom -gt 0) { [int][Math]::Round($gNumer / $gDenom, 0) } else { 100 }

    # ----- band (mirrors Microsoft Cloud Secure Score bands) -----
    # the bands are ONE definition (data-model\protection-score-bands.locked.json, also the web app's) -- built-in if it is not loaded
    $band = if (Get-Command -Name Get-SIProtectionBand -ErrorAction SilentlyContinue) { (Get-SIProtectionBand -Score $globalScore).Name }
            elseif ($globalScore -ge 90) { 'Very Good' }
            elseif ($globalScore -ge 75) { 'Good' }
            elseif ($globalScore -ge 50) { 'Moderate' }
            else                         { 'At Risk' }

    # Back-compat alias for code that still reads RiskLevel from the old shape.
    $bcRiskLevel = if     ($band -eq 'Very Good') { 'Low' }
                   elseif ($band -eq 'Good')      { 'Moderate' }
                   elseif ($band -eq 'Moderate')  { 'Elevated' }
                   elseif ($band -eq 'At Risk')   { if ($globalScore -lt 25) { 'Critical' } else { 'High' } }
                   else                            { 'Unknown' }

    # the rows the KPI counted: every page's rows went into one severity bucket each (Other included). #638 pages the rows,
    # so the old `$rows` of the in-memory loop no longer exists -- its .Count was 0 and every report mail said "Total: 0".
    $__kpiRows = [long](@($sevCount.Values) | Measure-Object -Sum).Sum
    [pscustomobject]@{
        GlobalScore  = $globalScore
        Band         = $band
        RiskLevel    = $bcRiskLevel
        DomainScore  = $domainScore
        SevCount     = $sevCount
        SevByDomain  = $sevByDomain
        TotalRows    = $__kpiRows
        Direction    = 'higher-is-better'
        PatchCycle   = (Complete-SIPatchCycleTally -Tally $State.Patch)
    }
}

function Invoke-RAKpiPass {
    <#
        The key figures' pass. -FromAiPass: the state the AI summary's pass filled (or $null). When it is complete
        (Test-RAKpiStateComplete) it IS the tally -- no row is read again. Otherwise the pass runs exactly as it always did:
        a fresh state (New-RAKpiState) and its own pager (-NewPager returns New-RARowPager ...) over every row.
        Returns @{ State; FromAiPass; Rows; FetchSec; DecodeSec } (FetchSec / DecodeSec = -1 when no row was read here).
    #>
    param($FromAiPass, [Parameter(Mandatory)][scriptblock]$NewPager, [datetime]$Now = [datetime]::UtcNow)
    $out = @{ State = $null; FromAiPass = $false; Rows = 0L; FetchSec = -1.0; DecodeSec = -1.0 }
    if (Test-RAKpiStateComplete -State $FromAiPass) {
        $out.State = $FromAiPass; $out.FromAiPass = $true; $out.Rows = [long]$FromAiPass.Rows
        return $out
    }
    $st = New-RAKpiState -Now $Now
    $pager = & $NewPager
    while ($null -ne ($page = $pager.Next())) {
        foreach ($r in $page) { Add-RAKpiRow -State $st -Row $r }
        $page = $null
    }
    $st.Complete = $true
    $out.State = $st; $out.Rows = [long]$st.Rows
    if ($pager.PSObject.Properties['State'] -and $pager.State -is [hashtable]) {
        if ($pager.State.ContainsKey('FetchSec')) { $out.FetchSec = [double]$pager.State.FetchSec }
        if ($pager.State.ContainsKey('DecodeSec')) { $out.DecodeSec = [double]$pager.State.DecodeSec }
    }
    $pager = $null
    $out
}
