#Requires -Version 5.1
<#
    Get-SIDefenderRecommendationContext -- the context Defender for Cloud holds AROUND a recommendation, read once per
    run from Resource Graph `securityresources` and put on the recommendation rows (SI_AzureRecommendation_CL) by
    ConvertTo-SIDefenderRecommendationRows (Get-SIDefenderRecommendations.ps1):

      governance      who owns the fix and when it is due (microsoft.security/assessments/governanceassignments):
                      owner, remediation due date, grace period
      compliance      the regulatory standards and controls a failed recommendation belongs to
                      (regulatorycomplianceassessments, state Failed), summarised per subscription and recommendation
                      INSIDE the query
      secure score    the secure score control a recommendation counts in and the points that control can still gain
                      (securescores/securescorecontrols)
      attack paths    the attack paths a recommendation is part of (microsoft.security/attackpaths), by the references
                      the recommendation carries (properties.risk.attackPathsReferences)

    READ ONLY. BEST EFFORT, NEVER BLOCKING: each read that cannot be completed leaves its columns empty for this run and
    says so once in plain words -- the recommendations themselves are published as before (their own two reads decide
    that). An empty value is "not known", never "none".

    NO DATA. Governance, risk levels and attack paths come with Defender CSPM. When the tenant shows no sign of it
    (no recommendation carries a risk level, no attack path, no governance assignment), those cells say
    "no data (licence missing or not collected yet)" instead of staying blank -- a blank would read as "no owner /
    no attack path". Empty reads are the only evidence, so the licence is not claimed missing.

    PURE except Get-SIDefenderRecommendationContext (the reads). PowerShell 7, REST only (Invoke-SIArgPaged).
#>

$script:SI_DfcNoDataCspm = 'no data (licence missing or not collected yet)'

function Get-SIDefenderGovernanceKql {
    @'
securityresources
| where type == 'microsoft.security/assessments/governanceassignments'
| order by id asc
| project
    GovernanceId       = tostring(id),
    AssessmentId       = tostring(split(tolower(tostring(id)), '/governanceassignments/')[0]),
    Owner              = tostring(properties.owner),
    DueDate            = tostring(properties.remediationDueDate),
    IsGracePeriod      = tostring(properties.isGracePeriod)
'@
}

function Get-SIDefenderComplianceKql {
    @'
securityresources
| where type == 'microsoft.security/regulatorycompliancestandards/regulatorycompliancecontrols/regulatorycomplianceassessments'
| where tostring(properties.state) == 'Failed'
| extend Standard = extract(@'(?i)/regulatorycompliancestandards/([^/]+)/', 1, tostring(id)), Control = extract(@'(?i)/regulatorycompliancecontrols/([^/]+)/', 1, tostring(id))
| where isnotempty(Standard)
| summarize Controls = make_set(strcat(Standard, ' ', Control), 60) by SubscriptionId = tolower(subscriptionId), AssessmentKey = tolower(name)
| order by SubscriptionId asc, AssessmentKey asc
| project SubscriptionId, AssessmentKey, ComplianceTags = strcat_array(Controls, ';')
'@
}

function Get-SIDefenderSecureScoreKql {
    @'
securityresources
| where type == 'microsoft.security/securescores/securescorecontrols'
| extend ScoreMax = todouble(properties.score.max), ScoreCurrent = todouble(properties.score.current)
| mv-expand Def = properties.definition.properties.assessmentDefinitions
| extend AssessmentKey = tolower(tostring(split(tolower(tostring(Def.id)), '/assessmentmetadata/')[1]))
| where isnotempty(AssessmentKey)
| order by id asc, AssessmentKey asc
| project SubscriptionId = tolower(subscriptionId), AssessmentKey, ControlName = tostring(properties.displayName), ScoreMax, ScoreCurrent
'@
}

function Get-SIDefenderAttackPathKql {
    @'
securityresources
| where type == 'microsoft.security/attackpaths'
| order by id asc
| project
    AttackPathId   = tolower(tostring(id)),
    AttackPathKey  = tolower(tostring(name)),
    AttackPathName = tostring(properties.displayName),
    AttackPathRisk = tostring(properties.riskLevel)
'@
}

function ConvertTo-SIDefenderIsoTime {
    <# PURE. A timestamp as ISO UTC text ('' when there is none); a [datetime] the JSON reader made is never rendered in the host's culture. #>
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    return ([string]$Value).Trim()
}

function ConvertTo-SIDefenderRecommendationContext {
    <#
    .SYNOPSIS  PURE. The four reads' rows as lookups for the row builder:
               @{ Governance = assessment id (lower) -> @{ Owner; DueDate; GracePeriod };
                  Compliance = '<subscription>|<assessment key>' (lower) -> 'standard control;standard control';
                  SecureScore = '<subscription>|<assessment key>' (lower) -> @{ Control; Gain };
                  AttackPaths = attack path id / key (lower) -> name;
                  Read = @{ Governance; Compliance; SecureScore; AttackPaths } (bool: the read completed) }
    #>
    param([AllowEmptyCollection()][object[]]$Governance = @(), [AllowEmptyCollection()][object[]]$Compliance = @(),
          [AllowEmptyCollection()][object[]]$SecureScore = @(), [AllowEmptyCollection()][object[]]$AttackPaths = @(),
          [hashtable]$Read = @{})
    $gov = @{}
    foreach ($g in @($Governance)) {
        if ($null -eq $g) { continue }
        $aid = ([string]$g.AssessmentId).Trim().ToLowerInvariant()
        if (-not $aid -or $gov.ContainsKey($aid)) { continue }
        $grace = ''
        $gp = ([string]$g.IsGracePeriod).Trim().ToLowerInvariant()
        if ($gp -eq 'true') { $grace = 'Yes' } elseif ($gp -eq 'false') { $grace = 'No' }
        $gov[$aid] = @{ Owner = ([string]$g.Owner).Trim(); DueDate = (ConvertTo-SIDefenderIsoTime $g.DueDate); GracePeriod = $grace }
    }
    $comp = @{}
    foreach ($c in @($Compliance)) {
        if ($null -eq $c) { continue }
        $k = ('{0}|{1}' -f ([string]$c.SubscriptionId).Trim().ToLowerInvariant(), ([string]$c.AssessmentKey).Trim().ToLowerInvariant())
        $v = ([string]$c.ComplianceTags).Trim()
        if ($k -ne '|' -and $v) { $comp[$k] = $v }
    }
    $score = @{}
    foreach ($s in @($SecureScore)) {
        if ($null -eq $s) { continue }
        $k = ('{0}|{1}' -f ([string]$s.SubscriptionId).Trim().ToLowerInvariant(), ([string]$s.AssessmentKey).Trim().ToLowerInvariant())
        if ($k -eq '|' -or $score.ContainsKey($k)) { continue }
        $gain = ''
        $mx = 0.0; $cur = 0.0
        $inv = [System.Globalization.CultureInfo]::InvariantCulture
        $okMax = [double]::TryParse(([string]$s.ScoreMax), [System.Globalization.NumberStyles]::Float, $inv, [ref]$mx)
        $okCur = [double]::TryParse(([string]$s.ScoreCurrent), [System.Globalization.NumberStyles]::Float, $inv, [ref]$cur)
        if ($s.ScoreMax -is [double] -or $s.ScoreMax -is [int] -or $s.ScoreMax -is [long] -or $s.ScoreMax -is [decimal]) { $mx = [double]$s.ScoreMax; $okMax = $true }
        if ($s.ScoreCurrent -is [double] -or $s.ScoreCurrent -is [int] -or $s.ScoreCurrent -is [long] -or $s.ScoreCurrent -is [decimal]) { $cur = [double]$s.ScoreCurrent; $okCur = $true }
        if ($okMax -and $okCur) { $gain = ([Math]::Max(0.0, [Math]::Round($mx - $cur, 2))).ToString('0.##', $inv) }
        $score[$k] = @{ Control = ([string]$s.ControlName).Trim(); Gain = $gain }
    }
    $paths = @{}
    foreach ($p in @($AttackPaths)) {
        if ($null -eq $p) { continue }
        $n = ([string]$p.AttackPathName).Trim(); if (-not $n) { continue }
        foreach ($k in @(([string]$p.AttackPathId).Trim().ToLowerInvariant(), ([string]$p.AttackPathKey).Trim().ToLowerInvariant())) { if ($k -and -not $paths.ContainsKey($k)) { $paths[$k] = $n } }
    }
    $rd = @{ Governance = $false; Compliance = $false; SecureScore = $false; AttackPaths = $false }
    foreach ($k in @($Read.Keys)) { $rd[[string]$k] = [bool]$Read[$k] }
    return @{ Governance = $gov; Compliance = $comp; SecureScore = $score; AttackPaths = $paths; Read = $rd }
}

function Get-SIDefenderRowContext {
    <#
    .SYNOPSIS  PURE. The context columns of ONE recommendation row (every column, every row, text -- the table's schema
               never drifts): GovernanceOwner, GovernanceDueDate, GovernanceGracePeriod, ComplianceTags,
               SecureScoreControl, SecureScoreGain, AttackPathCount (text), AttackPaths.
    .PARAMETER CspmSeen  $true when the tenant shows Defender CSPM data (a risk level on any recommendation, an attack
               path, a governance assignment); $false = the governance and attack path cells say "no data (...)"; $null =
               not known (cells stay empty).
    #>
    param([hashtable]$Context, [AllowEmptyCollection()][string[]]$AssessmentIds = @(), [string]$SubscriptionId = '', [string]$AssessmentKey = '',
          [AllowEmptyString()][string]$AttackPathRefs = '', $CspmSeen = $null)
    $o = [ordered]@{ GovernanceOwner = ''; GovernanceDueDate = ''; GovernanceGracePeriod = ''; ComplianceTags = ''; SecureScoreControl = ''; SecureScoreGain = ''; AttackPathCount = ''; AttackPaths = '' }
    if ($null -eq $Context) { $Context = @{} }
    $gov = $Context['Governance']; $comp = $Context['Compliance']; $score = $Context['SecureScore']; $paths = $Context['AttackPaths']
    if ($gov) {
        foreach ($a in @($AssessmentIds)) {
            $k = ([string]$a).Trim().ToLowerInvariant()
            if ($k -and $gov.ContainsKey($k)) { $g = $gov[$k]; $o.GovernanceOwner = [string]$g.Owner; $o.GovernanceDueDate = [string]$g.DueDate; $o.GovernanceGracePeriod = [string]$g.GracePeriod; break }
        }
    }
    $sk = ('{0}|{1}' -f ([string]$SubscriptionId).Trim().ToLowerInvariant(), ([string]$AssessmentKey).Trim().ToLowerInvariant())
    if ($comp -and $comp.ContainsKey($sk)) { $o.ComplianceTags = [string]$comp[$sk] }
    if ($score -and $score.ContainsKey($sk)) { $o.SecureScoreControl = [string]$score[$sk].Control; $o.SecureScoreGain = [string]$score[$sk].Gain }
    $refs = @(([string]$AttackPathRefs) -split '\s*;\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($refs.Count -gt 0) {
        $o.AttackPathCount = [string]$refs.Count
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($r in $refs) {
            $rk = $r.ToLowerInvariant()
            $last = @($rk.TrimEnd('/') -split '/')[-1]
            $n = ''
            if ($paths) { if ($paths.ContainsKey($rk)) { $n = [string]$paths[$rk] } elseif ($paths.ContainsKey($last)) { $n = [string]$paths[$last] } }
            if ($n -and -not $names.Contains($n)) { $names.Add($n) }
        }
        $o.AttackPaths = (@($names | Sort-Object) -join '; ')
    }
    if ($CspmSeen -eq $false) {
        if (-not $o.GovernanceOwner) { $o.GovernanceOwner = $script:SI_DfcNoDataCspm }
        if (-not $o.AttackPaths) { $o.AttackPaths = $script:SI_DfcNoDataCspm }
    }
    return $o
}

function Get-SIDefenderRecommendationContext {
    <#
    .SYNOPSIS  The four reads (see the header). Never throws; a read that does not complete leaves its lookup empty and is
               said once. Returns the lookups of ConvertTo-SIDefenderRecommendationContext.
    #>
    [CmdletBinding()]
    param([string[]]$SubscriptionIds = @(), [scriptblock]$PageFetcher)
    if (-not (Get-Command Invoke-SIArgPaged -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1') }
    $reads = [ordered]@{
        Governance  = @{ Kql = (Get-SIDefenderGovernanceKql);  Label = 'recommendation owners and due dates' }
        Compliance  = @{ Kql = (Get-SIDefenderComplianceKql);  Label = 'regulatory compliance of the recommendations' }
        SecureScore = @{ Kql = (Get-SIDefenderSecureScoreKql); Label = 'secure score controls' }
        AttackPaths = @{ Kql = (Get-SIDefenderAttackPathKql);  Label = 'attack paths' }
    }
    $rows = @{}; $ok = @{}
    foreach ($name in $reads.Keys) {
        $rows[$name] = @(); $ok[$name] = $false
        try {
            $a = @{ Query = $reads[$name].Kql; SourceLabel = $reads[$name].Label; SubscriptionIds = $SubscriptionIds }
            if ($PageFetcher) { $a['PageFetcher'] = $PageFetcher }
            # the pager's own warning speaks of missing assets; missing context loses no recommendation, so say what it means
            $r = Invoke-SIArgPaged @a -WarningAction SilentlyContinue
            if ($r -and $r.Complete) { $rows[$name] = @($r.Rows); $ok[$name] = $true }
            else { Write-Warning ('Defender for Cloud: the {0} could not be read to the end -- those columns stay empty on the recommendations of this run.' -f $reads[$name].Label) }
        } catch {
            Write-Warning ('Defender for Cloud: the {0} could not be read ({1}) -- those columns stay empty on the recommendations of this run.' -f $reads[$name].Label, $_.Exception.Message)
        }
    }
    return (ConvertTo-SIDefenderRecommendationContext -Governance $rows['Governance'] -Compliance $rows['Compliance'] -SecureScore $rows['SecureScore'] -AttackPaths $rows['AttackPaths'] -Read $ok)
}
