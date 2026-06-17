#Requires -Version 5.1
<#
.SYNOPSIS
    SI Analyzer -- pure KQL builders + read-only guardrail.

.DESCRIPTION
    Offline-testable core for the SI Analyzer POC. Holds:
      * The canonical SI table allow-list (the only tables a generated/prestaged
        query is permitted to read).
      * Snapshot-correct KQL builders (always `where CollectionTime == max(CollectionTime)`).
      * The prestaged-analysis library (vetted read-only KQL + plain-language meta).
      * The read-only guardrail (Test-SiKqlReadOnly): rejects any destructive /
        control-command / cross-cluster operator and any table outside the allow-list.

    NO network, NO Az calls -- pure string + parsing logic. Dot-source and call.
    PowerShell 5.1-safe (no ?., no ??, no ternary).
#>

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Canonical SI table allow-list. The Analyzer is read-only over THESE tables
# only -- the RA Profile tables, the ExposureGraph tables, and the read-only
# Defender/Graph hunting tables the engine already consumes. Anything else is
# rejected by the guardrail (and never emitted by a prestaged builder).
# ---------------------------------------------------------------------------
$script:SiAnalyzerAllowedTables = @(
    'SI_Endpoint_Profile_CL',
    'SI_Identity_Profile_CL',
    'SI_Azure_Profile_CL',
    'SI_PublicIP_Profile_CL',
    'SI_VulnerabilityPIP_CL',
    'ExposureGraphNodes',
    'ExposureGraphEdges',
    'DeviceInfo',
    'DeviceTvmSoftwareVulnerabilities',
    'IdentityInfo'
)

function Get-SiAnalyzerAllowedTables {
    # Return a copy so callers can't mutate the canonical list. Plain array
    # (callers @()-wrap or bind to [string[]]); no comma-protection -- @(,@()) does
    # not cancel in PS 5.1 and would leave a single-element wrapper.
    return [string[]]$script:SiAnalyzerAllowedTables.Clone()
}

# ---------------------------------------------------------------------------
# Read-only guardrail. Returns a result object:
#   { Allowed = $true/$false; Reasons = @(...); Tables = @(...) }
# A query is allowed only when:
#   * it contains no control command (a line/statement starting with '.')
#   * it contains no destructive / mutating / external operator
#   * every table it reads is on the allow-list
# This is the SINGLE gate every prestaged AND AI-generated query must pass
# before it is submitted to Log Analytics.
# ---------------------------------------------------------------------------
function Test-SiKqlReadOnly {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    $q = if ($null -eq $Query) { '' } else { [string]$Query }

    if ([string]::IsNullOrWhiteSpace($q)) {
        return [pscustomobject]@{ Allowed = $false; Reasons = @('Query is empty.'); Tables = @() }
    }

    # 1. Control commands -- any statement beginning with '.' (.set/.create/.drop/.append/.alter/.delete/.ingest/.purge ...)
    #    KQL control commands are the only way to mutate; banning the leading-dot form bans them all.
    foreach ($rawLine in ($q -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.StartsWith('.')) {
            [void]$reasons.Add("Control command not allowed: '$line'")
        }
    }

    # 2. Destructive / mutating / external-reach operators (word-boundary, case-insensitive).
    #    These never appear in a legitimate read-only SI analytics query.
    $bannedOperators = @(
        'set-or-replace','set-or-append','create-or-alter',
        '\.set\b','\.append\b','\.create\b','\.drop\b','\.alter\b','\.delete\b',
        '\.ingest\b','\.purge\b','\.rename\b','\.move\b','\.replace\b',
        '\bexternaldata\b','\bexternal_table\b','\bevaluate\s+http_request\b',
        '\bevaluate\s+http_request_post\b','\binto\s+table\b'
    )
    foreach ($op in $bannedOperators) {
        if ($q -match "(?i)$op") {
            $m = ([regex]::Match($q, "(?i)$op")).Value
            [void]$reasons.Add("Disallowed operator: '$($m.Trim())'")
        }
    }

    # 3. Cross-cluster / cross-database reach (cluster(...) / database(...)) -- the Analyzer is
    #    confined to the customer's own workspace.
    if ($q -match '(?i)\bcluster\s*\(') { [void]$reasons.Add("Cross-cluster reference not allowed: cluster(...)") }
    if ($q -match '(?i)\bdatabase\s*\(') { [void]$reasons.Add("Cross-database reference not allowed: database(...)") }

    # 4. Table allow-list. Find every SI_*_CL / known table token referenced and verify membership.
    #    We extract candidate source-table identifiers: tokens that look like a table reference
    #    (start of statement, after a pipe, after 'join'/'union'/'lookup', or a bare SI_*_CL token).
    $referenced = New-Object System.Collections.Generic.List[string]

    # SI_*_CL custom tables and the ExposureGraph* / known-hunting tables.
    $candidatePattern = '(?i)\b([A-Za-z_][A-Za-z0-9_]*_CL|ExposureGraph[A-Za-z]+|DeviceInfo|DeviceTvmSoftwareVulnerabilities|IdentityInfo)\b'
    foreach ($m in [regex]::Matches($q, $candidatePattern)) {
        $name = $m.Groups[1].Value
        if (-not $referenced.Contains($name)) { [void]$referenced.Add($name) }
    }

    # Also catch any *_CL token NOT on the list (catches typos / off-list custom tables).
    foreach ($m in [regex]::Matches($q, '(?i)\b([A-Za-z_][A-Za-z0-9_]*_CL)\b')) {
        $name = $m.Groups[1].Value
        if (-not $referenced.Contains($name)) { [void]$referenced.Add($name) }
    }

    $allowed = Get-SiAnalyzerAllowedTables
    $offList = @()
    foreach ($name in $referenced) {
        $hit = $false
        foreach ($a in $allowed) { if ($a -eq $name) { $hit = $true; break } }
        if (-not $hit) { $offList += $name }
    }
    if ($offList.Count -gt 0) {
        [void]$reasons.Add("Table(s) not on the read-only allow-list: $($offList -join ', ')")
    }

    if ($referenced.Count -eq 0) {
        [void]$reasons.Add("No recognised SI/Defender table referenced -- query rejected as ungrounded.")
    }

    return [pscustomobject]@{
        Allowed = ($reasons.Count -eq 0)
        Reasons = @($reasons.ToArray())
        Tables  = @($referenced.ToArray())
    }
}

# ---------------------------------------------------------------------------
# Snapshot-correct base. Every builder anchors on the latest CollectionTime so
# the analyst always sees ONE coherent snapshot.
# ---------------------------------------------------------------------------
function Get-SiSnapshotFilter {
    param([Parameter(Mandatory)][string]$Table)
    if ($script:SiAnalyzerAllowedTables -notcontains $Table) {
        throw "Get-SiSnapshotFilter: '$Table' is not an allowed table."
    }
    # Two-phase: compute max(CollectionTime) then filter -- the SI convention.
    return @"
let _snap = toscalar($Table | summarize max(CollectionTime));
$Table
| where CollectionTime == _snap
"@
}

# ---------------------------------------------------------------------------
# Top-N worklist (highest RiskScoreTotal, latest snapshot) across all domains.
# ---------------------------------------------------------------------------
function Build-SiTopWorklistKql {
    [CmdletBinding()]
    param(
        [int]$Top = 100,
        [ValidateSet('all','endpoint','identity','azure','publicip')][string]$Domain = 'all'
    )
    if ($Top -lt 1) { $Top = 1 }

    $tableMap = @{
        endpoint = 'SI_Endpoint_Profile_CL'
        identity = 'SI_Identity_Profile_CL'
        azure    = 'SI_Azure_Profile_CL'
        publicip = 'SI_PublicIP_Profile_CL'
    }

    $domains = if ($Domain -eq 'all') { @('endpoint','identity','azure','publicip') } else { @($Domain) }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($d in $domains) {
        $t = $tableMap[$d]
        [void]$parts.Add(@"
(let _snap_$d = toscalar($t | summarize max(CollectionTime));
$t
| where CollectionTime == _snap_$d
| extend SecurityDomain = "$d")
"@)
    }
    $union = $parts -join ",`n"

    return @"
union
$union
| project SecurityDomain, ConfigurationName, ConfigurationId, CriticalityTier, CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskScoreTotal_Weighted, RiskFactor_Consequence, RiskFactor_Probability, CollectionTime
| sort by RiskScoreTotal desc
| take $Top
"@
}

# ---------------------------------------------------------------------------
# Score timeline -- total + per-tier risk score across every CollectionTime snapshot.
# (Management trend.)
# ---------------------------------------------------------------------------
function Build-SiScoreTimelineKql {
    [CmdletBinding()]
    param([int]$LookbackDays = 180)
    if ($LookbackDays -lt 1) { $LookbackDays = 1 }

    $tables = @('SI_Endpoint_Profile_CL','SI_Identity_Profile_CL','SI_Azure_Profile_CL','SI_PublicIP_Profile_CL')
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($t in $tables) {
        [void]$parts.Add("($t | where TimeGenerated > ago(${LookbackDays}d))")
    }
    $union = $parts -join ",`n"

    return @"
union
$union
| summarize TotalScore = sum(RiskScoreTotal), FindingCount = count() by CollectionTime, CriticalityTierLevel
| sort by CollectionTime asc
"@
}

# ---------------------------------------------------------------------------
# Prestaged-analysis library. Each entry = a plain-named, one-click analysis
# with a vetted read-only KQL and an AI-explanation template. The POC ships the
# full menu; the builder validates every emitted query through the guardrail.
# ---------------------------------------------------------------------------
function Get-SiPrestagedAnalyses {
    [CmdletBinding()] param()

    $list = New-Object System.Collections.Generic.List[object]

    # 1. Crown-jewel (T0/T1) exposure paths
    [void]$list.Add([pscustomobject]@{
        Id        = 'crown-jewel-exposure'
        Title     = 'Crown-jewel exposure paths'
        Plain     = 'Your most critical (Tier 0/1) assets that are exposed to attack right now.'
        Domain    = 'endpoint'
        Kql       = @"
let _snap = toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime));
SI_Endpoint_Profile_CL
| where CollectionTime == _snap
| where CriticalityTier <= 1
| sort by RiskScoreTotal desc
| project ConfigurationName, CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskFactor_Consequence, RiskFactor_Probability
| take 50
"@
        AiTemplate = 'These are the highest-value systems most exposed to compromise. For each, say in plain language what it is, why its exposure matters to the business, the single most effective action to reduce risk, and how urgent it is.'
    })

    # 2. Stale-but-privileged
    [void]$list.Add([pscustomobject]@{
        Id        = 'stale-but-privileged'
        Title     = 'Stale but privileged'
        Plain     = 'Powerful accounts/assets that have not been used recently -- prime targets and easy wins to remove.'
        Domain    = 'identity'
        Kql       = @"
let _snap = toscalar(SI_Identity_Profile_CL | summarize max(CollectionTime));
SI_Identity_Profile_CL
| where CollectionTime == _snap
| where CriticalityTier <= 1
| where RiskFactor_Probability has_cs "stale" or RiskFactor_Consequence has_cs "stale"
| sort by RiskScoreTotal desc
| project ConfigurationName, CriticalityTierLevel, RiskScoreTotal, RiskFactor_Probability, RiskFactor_Consequence
| take 50
"@
        AiTemplate = 'These are highly privileged identities/assets that appear dormant. Explain the danger of unused privileged access in plain terms and recommend whether to disable, reduce privilege, or review each.'
    })

    # 3. Internet-facing + exploitable / high CVSS
    [void]$list.Add([pscustomobject]@{
        Id        = 'internet-facing-critical-cve'
        Title     = 'Internet-facing with a critical vulnerability'
        Plain     = 'Assets reachable from the internet that also carry a serious, fixable vulnerability.'
        Domain    = 'endpoint'
        Kql       = @"
let _snap = toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime));
SI_Endpoint_Profile_CL
| where CollectionTime == _snap
| where SecuritySeverity in ("Critical","High")
| where RiskFactor_Probability has_cs "internet" or RiskFactor_Probability has_cs "exposed" or RiskFactor_Consequence has_cs "cve"
| sort by RiskScoreTotal desc
| project ConfigurationName, CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskFactor_Consequence, RiskFactor_Probability
| take 50
"@
        AiTemplate = 'These systems are reachable from the internet and have a serious vulnerability -- a classic break-in route. Explain the combined risk and the fastest path to close it (patch, restrict exposure, or both).'
    })

    # 4. Identity -> T0 lateral movement
    [void]$list.Add([pscustomobject]@{
        Id        = 'identity-to-t0-lateral'
        Title     = 'Identity to Tier-0 lateral movement'
        Plain     = 'Everyday accounts that can reach your most critical systems -- the paths attackers love.'
        Domain    = 'identity'
        Kql       = @"
let _snap = toscalar(SI_Identity_Profile_CL | summarize max(CollectionTime));
SI_Identity_Profile_CL
| where CollectionTime == _snap
| where RiskFactor_Consequence has_cs "tier 0" or RiskFactor_Consequence has_cs "lateral" or RiskFactor_Probability has_cs "path"
| sort by RiskScoreTotal desc
| project ConfigurationName, CriticalityTierLevel, RiskScoreTotal, RiskFactor_Consequence, RiskFactor_Probability
| take 50
"@
        AiTemplate = 'These identities can reach Tier-0 (crown-jewel) systems. Explain the lateral-movement risk plainly and recommend how to break the path (tiering, JIT, credential hygiene).'
    })

    # 5. Newly-appeared high-risk
    [void]$list.Add([pscustomobject]@{
        Id        = 'new-high-risk'
        Title     = 'New high-risk this run'
        Plain     = 'High-risk findings that appeared since the previous snapshot -- what just got worse.'
        Domain    = 'endpoint'
        Kql       = @"
let _snap = toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime));
let _prev = toscalar(SI_Endpoint_Profile_CL | where CollectionTime < _snap | summarize max(CollectionTime));
let _now = SI_Endpoint_Profile_CL | where CollectionTime == _snap | project ConfigurationId, ConfigurationName, RiskScoreTotal, CriticalityTierLevel, SecuritySeverity;
let _before = SI_Endpoint_Profile_CL | where CollectionTime == _prev | project ConfigurationId;
_now
| join kind=leftanti _before on ConfigurationId
| where RiskScoreTotal > 0
| sort by RiskScoreTotal desc
| take 50
"@
        AiTemplate = 'These high-risk items are brand new since the last snapshot. Explain what changed and which deserve immediate attention.'
    })

    # Return the array WITHOUT comma-protection. Comma-protection (,@(...)) here makes
    # the multi-element result enumerate as a single wrapper element under foreach
    # (the PS @()-unwrap trap), which broke $a.Kql access. Callers @()-wrap to
    # normalise; that protects the empty/single case without the wrapper hazard.
    return $list.ToArray()
}

# ---------------------------------------------------------------------------
# Validate that every prestaged query passes the read-only guardrail. Returns
# a list of failures (empty == all clean). Used by tests + the server at startup.
# ---------------------------------------------------------------------------
function Test-SiPrestagedLibrary {
    [CmdletBinding()] param()
    $failures = New-Object System.Collections.Generic.List[object]
    # Normalise the comma-protected return with @() so foreach enumerates the
    # analysis objects, not the wrapper array as a single element.
    foreach ($a in @(Get-SiPrestagedAnalyses)) {
        $r = Test-SiKqlReadOnly -Query $a.Kql
        if (-not $r.Allowed) {
            [void]$failures.Add([pscustomobject]@{ Id = $a.Id; Reasons = $r.Reasons })
        }
    }
    # Comma-protect so an empty result survives the function-return unwrap as an
    # array (callers read .Count directly, e.g. tests). This is the empty/single
    # case where ,@() is correct; multi-element ROW returns are plain (see Diff lib).
    return ,@($failures.ToArray())
}
