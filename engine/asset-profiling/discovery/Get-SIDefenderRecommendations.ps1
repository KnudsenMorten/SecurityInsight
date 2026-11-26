#Requires -Version 5.1
<#
    Get-SIDefenderRecommendations -- every Defender for Cloud (Secure Score) recommendation, as SI rows.

    WHY (#147). The Azure recommendation reports read ONLY what the Exposure Graph carries. Measured on the
    internal tenant 2026-09-28: Defender for Cloud held 9,618 unhealthy recommendations on 369 resources;
    323 of those resources (9,368 recommendations) were absent from the graph, so the reports could never
    show them -- recommendations a customer sees in the portal, missing from the exposure view. Operator:
    "we can not lose recommendations, as people use this for exposure management".

    WHAT. Resource Graph `securityresources`, type microsoft.security/assessments, status Unhealthy, across
    every subscription the identity can read -- paged to the end and throttle-safe (Invoke-SIArgPaged).
    Rows land in SI_AzureRecommendation_CL, which the Defender recommendation reports read as their BASE;
    the Exposure Graph only enriches them.

    ROLL-UP (operator, 2026-09-28: "roll up the container images"). Most assessments are SUB-ENTITIES
    (`.../securityentitydata/...`): one row per package per container image, or per identity for the cloud
    posture (CIEM) findings -- 8,819 of 9,618 measured. They are rolled up to their PARENT resource
    (the registry; the subscription for cloud-posture entities) x recommendation, with the affected
    entities LISTED and COUNTED, so nothing is dropped and the report stays readable.

    NEVER PARTIAL (working rule 4). If Resource Graph cannot be read to the end, Complete=$false and the
    caller publishes NOTHING -- the previous complete snapshot stays the latest, because a shorter list
    would read as "fixed" downstream.
#>

# #1399 the disk buckets the roll-up is worked out in (Get-SIDefenderRecommendations)
if (-not (Get-Command -Name New-SIDiskBuckets -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-DiskLookup.ps1')) }

$script:SI_DfcSeverityRank = @{ 'critical' = 4; 'high' = 3; 'medium' = 2; 'low' = 1 }

# A finding list is exact in its COUNT; its TEXT stops short of the 32,767-character cell limit of the
# workbook, and says how many it did not print.
$script:SI_DfcSubFindingsMaxChars = 30000

# The query SORTS (order by id). Resource Graph pages an unsorted result inconsistently: measured on the
# internal tenant, unsorted reads repeated 222-226 assessments across pages AND therefore skipped as many --
# 226 recommendations silently missing behind a total that looked right (#149).
function Get-SIDefenderRecommendationKql {
    @'
securityresources
| where type == 'microsoft.security/assessments'
| where tostring(properties.status.code) == 'Unhealthy'
| extend _add = parse_json(tostring(properties.resourceAdditionalData))
| order by id asc
| project
    AssessmentId           = tostring(id),
    AssessmentKey          = name,
    SubscriptionId         = subscriptionId,
    ResourceGroup          = resourceGroup,
    ResourceId             = tostring(properties.resourceDetails.Id),
    ResourceName           = tostring(properties.resourceDetails.ResourceName),
    ResourceType           = tostring(properties.resourceDetails.ResourceType),
    ResourceSource         = tostring(properties.resourceDetails.Source),
    Recommendation         = tostring(properties.displayName),
    Severity               = tostring(properties.metadata.severity),
    RecommendationCategory = tostring(properties.metadata.recommendationCategory),
    SecurityIssue          = tostring(properties.metadata.securityIssue),
    Categories             = strcat_array(properties.metadata.categories, '; '),
    Tactics                = strcat_array(properties.metadata.tactics, '; '),
    Threats                = strcat_array(properties.metadata.threats, '; '),
    Description            = tostring(properties.metadata.description),
    Remediation            = tostring(properties.metadata.remediationDescription),
    ImplementationEffort   = tostring(properties.metadata.implementationEffort),
    UserImpact             = tostring(properties.metadata.userImpact),
    PortalLink             = tostring(properties.links.azurePortal),
    RiskLevel              = tostring(properties.risk.level),
    RiskFactors            = strcat_array(properties.risk.riskFactors, '; '),
    FirstEvaluated         = tostring(properties.status.firstEvaluationDate),
    StatusChanged          = tostring(properties.status.statusChangeDate),
    MaxCvssScore           = tostring(properties.additionalData.MaxCvssScore),
    ImageUri               = tostring(_add.ImageUri),
    Techniques             = strcat_array(properties.metadata.techniques, '; '),
    PolicyDefinitionId     = tostring(properties.metadata.policyDefinitionId),
    StatusCause            = tostring(properties.status.cause),
    StatusDescription      = tostring(properties.status.description),
    AttackPathRefs         = strcat_array(properties.risk.attackPathsReferences, '; '),
    ImageDigest            = tostring(_add.ImageDigest),
    ImageRepository        = tostring(_add.RepositoryName)
'@
}

# SUB-ASSESSMENTS -- the findings BEHIND a recommendation (a VM's individual vulnerabilities from a
# vulnerability scanner, a SQL database's vulnerability-assessment rules, ...). Tenants on Defender's newer
# model expose that detail as `securityentitydata` assessments instead (collected and rolled up below; the
# internal tenant has 8,817 of those and no sub-assessments at all); tenants on the older model carry it
# ONLY here, so without this read their recommendation rows would say "fix this" with no list of what.
function Get-SIDefenderSubAssessmentKql {
    @'
securityresources
| where type == 'microsoft.security/assessments/subassessments'
| where tostring(properties.status.code) == 'Unhealthy'
| order by id asc
| project
    SubAssessmentId    = tostring(id),
    ParentAssessmentId = tostring(split(tolower(tostring(id)), '/subassessments/')[0]),
    FindingName        = tostring(properties.displayName),
    FindingId          = tostring(properties.id),
    FindingSeverity    = tostring(properties.status.severity),
    FindingCategory    = tostring(properties.category),
    ResourceId         = tostring(properties.resourceDetails.id),
    SubscriptionId     = subscriptionId,
    ResourceGroup      = resourceGroup,
    FindingRemediation  = tostring(properties.remediation),
    FindingProduct      = strcat(tostring(properties.additionalData.softwareDetails.softwareName), tostring(properties.additionalData.softwareDetails.packageName), tostring(properties.additionalData.softwareName)),
    FindingVendor       = strcat(tostring(properties.additionalData.softwareDetails.vendor), tostring(properties.additionalData.softwareVendor)),
    FindingVersion      = strcat(tostring(properties.additionalData.softwareDetails.version), tostring(properties.additionalData.softwareVersion)),
    FindingFixedVersion = strcat(tostring(properties.additionalData.softwareDetails.fixedVersion), tostring(properties.additionalData.fixedVersion)),
    FindingPatchable    = tostring(properties.additionalData.patchable),
    FindingImageDigest  = strcat(tostring(properties.additionalData.imageDigest), tostring(properties.additionalData.artifactDetails.digest)),
    FindingRepository   = strcat(tostring(properties.additionalData.repositoryName), tostring(properties.additionalData.artifactDetails.repositoryName))
'@
}

function ConvertFrom-SIDefenderHtml {
    <#
      Defender writes a recommendation's description and remediation as HTML (<ol>, <li>, <a href>, <br/>,
      &emsp;). Stored as-is it reached the workbook and the mail as markup (#189). PURE: HTML -> plain text,
      keeping what the markup meant -- a link becomes "text (url)", a list item a "- " line, a break a new line.
      Text without a tag passes through unchanged apart from entity decoding and whitespace tidying.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Html)
    if ([string]::IsNullOrWhiteSpace($Html)) { return [string]$Html }
    $t = [string]$Html
    $t = [regex]::Replace($t, '(?is)<a\b[^>]*?href\s*=\s*["'']([^"'']*)["''][^>]*>(.*?)</a>', {
        param($m)
        $url = $m.Groups[1].Value.Trim(); $txt = [regex]::Replace($m.Groups[2].Value, '(?s)<[^>]+>', '').Trim()
        if (-not $txt -or $txt -eq $url) { $url } elseif (-not $url) { $txt } else { '{0} ({1})' -f $txt, $url }
    })
    $t = [regex]::Replace($t, '(?i)<br\s*/?>', "`n")
    $t = [regex]::Replace($t, '(?i)<li\b[^>]*>', "`n- ")
    $t = [regex]::Replace($t, '(?i)</?(p|div|ol|ul|li|h[1-6]|tr|table)\b[^>]*>', "`n")
    $t = [regex]::Replace($t, '(?s)<[^>]+>', '')
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    # nbsp, en / em / thin space and tab become a plain space (written as char codes: this file has no BOM).
    $t = [regex]::Replace($t, ('[' + [char]0x00A0 + [char]0x2002 + [char]0x2003 + [char]0x2009 + "`t" + ']'), ' ')
    $lines = foreach ($l in ($t -split "\r?\n")) { ($l -replace ' {2,}', ' ').Trim() }
    $t = (@($lines) -join "`n")
    $t = [regex]::Replace($t, "\n{3,}", "`n`n")
    return $t.Trim()
}

function Get-SIDefenderRecommendationParent {
    <#
      The resource a recommendation row is reported against. A sub-entity (container image, cloud-posture
      identity) rolls up to its parent: the part of the id before '/securityentitydata/', and for the
      cloud-posture plan ('/providers/microsoft.security/pricings/cloudposture') the subscription itself.
      AZURE CHILD RESOURCES (owner 2026-10-11): a resource that is a part of its parent CI (a VM extension, a disk, a
      network interface, a subnet, a SQL database or firewall rule, an AI deployment -- data-model collection-scope
      rollUpInto, SI-AzureChildren.ps1) rolls up to that parent: ONE row per parent and recommendation, the children in
      AffectedEntities (EntityKind 'AzureChildResource'). -Scope: the Azure CI scope (Get-SIAzureCiScope; none = no
      child roll-up); -ChildParents: child id -> parent id the record capture knows (a disk's VM, a NIC's VM).
      Returns @{ ParentId; IsEntity; EntityKind }.
    #>
    param([string]$ResourceId, [string]$ResourceType, $Scope, [hashtable]$ChildParents)
    $rid = [string]$ResourceId
    $i = $rid.IndexOf('/securityentitydata/', [StringComparison]::OrdinalIgnoreCase)
    if ($i -lt 0) {
        if ($null -ne $Scope -and (Test-Path -Path 'function:Resolve-SIAzurePlacement')) {
            $pl = Resolve-SIAzurePlacement -Id $rid -Type '' -Object $null -Scope $Scope -KnownParents $ChildParents
            if ($pl.Action -eq 'child' -and $pl.ParentId) {
                # the parent as the id spells it when it is a prefix of the child's (the path parent), else as found
                $parent = [string]$pl.ParentId
                if ($rid.Length -gt $parent.Length -and $rid.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) { $parent = $rid.Substring(0, $parent.Length) }
                return @{ ParentId = $parent; IsEntity = $true; EntityKind = 'AzureChildResource' }
            }
        }
        return @{ ParentId = $rid; IsEntity = $false; EntityKind = '' }
    }
    $parent = $rid.Substring(0, $i)
    # #500 a resource in ANOTHER CLOUD (AWS / GCP, under a Defender for Cloud multicloud connector) is a CI of its own
    # (mdc multicloud_resource, keyed by this id) -- it is never rolled up to its connector
    if ($parent.IndexOf('/providers/microsoft.security/securityconnectors/', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return @{ ParentId = $rid; IsEntity = $false; EntityKind = '' }
    }
    $kind = if ($ResourceType -ieq '.containerimage') { 'ContainerImage' } else { 'Entity' }
    $cp = $parent.IndexOf('/providers/microsoft.security/pricings/', [StringComparison]::OrdinalIgnoreCase)
    if ($cp -ge 0) {
        $parent = $parent.Substring(0, $cp)
        if ($kind -eq 'Entity') { $kind = 'CloudPostureEntity' }
    }
    @{ ParentId = $parent; IsEntity = $true; EntityKind = $kind }
}

# #202 -- SUBSCRIPTION DISPLAY NAMES. A recommendation scoped to a subscription carries the subscription GUID as
# its resource name, and a Defender plan row (microsoft.security/pricings) carries only the plan ("ai", "arm"), so
# the Top 50 ranked a bare GUID. Resolved here from Resource Graph, never from the report.
function Get-SISubscriptionNameKql {
    @'
resourcecontainers
| where type == 'microsoft.resources/subscriptions'
| order by subscriptionId asc
| project subscriptionId, name, tenantId, Chain = properties.managementGroupAncestorsChain
'@
}

function ConvertTo-SIDefenderSubscriptionContext {
    <#
      PURE. The subscription rows (Get-SISubscriptionNameKql) -> @{ <subscription id, lower> = @{ ManagementGroupId;
      ManagementGroupName; ManagementGroupPath } }: the management group the subscription sits in (id AND name) and the
      chain as names, root first. The chain comes leaf first. A subscription without a chain is left out.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($s in @($Rows)) {
        if ($null -eq $s -or -not $s.PSObject.Properties['subscriptionId'] -or -not $s.subscriptionId) { continue }
        $chain = $null; if ($s.PSObject.Properties['Chain']) { $chain = $s.Chain }
        if ($chain -is [string]) { try { $chain = $chain | ConvertFrom-Json } catch { $chain = $null } }
        $names = New-Object System.Collections.Generic.List[string]; $ids = New-Object System.Collections.Generic.List[string]
        foreach ($c in @($chain)) {
            if ($null -eq $c) { continue }
            $id = ([string]$c.name).Trim(); $dn = ([string]$c.displayName).Trim()
            if (-not $dn) { $dn = $id }; if (-not $id) { $id = $dn }
            if ($dn) { $names.Add($dn); $ids.Add($id) }
        }
        if ($names.Count -eq 0) { continue }
        $n = $names.ToArray(); [array]::Reverse($n)
        $map[([string]$s.subscriptionId).ToLowerInvariant()] = @{ ManagementGroupId = $ids[0]; ManagementGroupName = $names[0]; ManagementGroupPath = ($n -join '/') }
    }
    return $map
}

function Get-SIDefenderAssetLabel {
    <#
      PURE. The name a recommendation's asset is shown under. A subscription is named by its display name; a
      Defender plan by "<subscription> - Defender plan <plan>"; anything else keeps its resource name. A
      subscription whose name is not known keeps its id -- never a blank, never a guess.
    #>
    param([string]$ResourceId, [string]$ResourceName, [string]$SubscriptionId, [hashtable]$SubscriptionNames)
    $rid = [string]$ResourceId
    $subId = [string]$SubscriptionId
    if (-not $subId -and $rid -match '^/subscriptions/([^/]+)') { $subId = $Matches[1] }
    $subName = ''
    if ($SubscriptionNames -and $subId -and $SubscriptionNames.ContainsKey($subId.ToLowerInvariant())) { $subName = [string]$SubscriptionNames[$subId.ToLowerInvariant()] }
    if ($rid -match '^/subscriptions/[^/]+/?$') {
        if ($subName) { return $subName }
        if ($ResourceName) { return [string]$ResourceName }
        return $subId
    }
    if ($rid -match '/providers/microsoft\.security/pricings/([^/]+)/?$') {
        $plan = $Matches[1]
        $who = if ($subName) { $subName } else { $subId }
        return ('{0} - Defender plan {1}' -f $who, $plan)
    }
    [string]$ResourceName
}

function ConvertTo-SIDefenderRecommendationRows {
    <#
      Raw assessment rows -> SI_AzureRecommendation_CL rows. Resource / subscription rows pass through one
      to one; sub-entity rows roll up per (parent, recommendation) with the entities counted and listed.
      EVERY row carries EVERY column with a stable type (strings, one int, one bool), so the table's
      schema never drifts (#148). Pure -- no I/O.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Raw,
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        # Unhealthy sub-assessments (Get-SIDefenderSubAssessmentKql). Each is attached to the row of its
        # PARENT recommendation (counted, highest severity, listed) -- never a row of its own, so a
        # recommendation is not counted twice. One whose parent is not among these recommendations gets a
        # row of its own rather than being dropped.
        [AllowEmptyCollection()][object[]]$SubAssessments = @(),
        # #202 lower-case subscription id -> display name (Get-SISubscriptionNameKql). Empty: ids stay as they are.
        [hashtable]$SubscriptionNames = @{},
        # names next to ids: lower-case subscription id -> @{ ManagementGroupId; ManagementGroupName; ManagementGroupPath }
        # (ConvertTo-SIDefenderSubscriptionContext). Empty: the columns stay empty.
        [hashtable]$SubscriptionContext = @{},
        # Azure child resources roll up into their parent (Get-SIDefenderRecommendationParent): the Azure CI scope and the
        # child -> parent ids the record capture knows. No scope: no child roll-up.
        $Scope,
        [hashtable]$ChildParents,
        # RICH CONTEXT (Defender lane): owners and due dates, regulatory compliance, secure score controls and attack paths
        # (Get-SIDefenderRecommendationContext.ps1). Empty: those columns are carried empty.
        [hashtable]$Context = @{},
        # #1399 the rows are worked out a bucket at a time (Get-SIDefenderRecommendations): whether ANY assessment of the whole
        # read carries a risk level -- $null = from -Raw itself, as before
        [AllowNull()][object]$RiskLevelSeen = $null
    )
    $out = New-Object System.Collections.Generic.List[object]
    $groups = [ordered]@{}

    $subsByParent = @{}
    $subSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($SubAssessments)) {
        if ($null -eq $s) { continue }
        $sid = [string]$s.SubAssessmentId
        if ($sid -and -not $subSeen.Add($sid)) { continue }    # a paging overlap is one finding
        $pk = ([string]$s.ParentAssessmentId).ToLowerInvariant()
        if (-not $subsByParent.ContainsKey($pk)) { $subsByParent[$pk] = New-Object System.Collections.Generic.List[object] }
        $subsByParent[$pk].Add($s)
    }
    $usedParents = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    # count / highest severity / listed text over the sub-findings of the given assessment ids
    function _subs([string[]]$assessmentIds) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($a in @($assessmentIds)) {
            $k = ([string]$a).ToLowerInvariant()
            if ($subsByParent.ContainsKey($k)) { [void]$usedParents.Add($k); $list.AddRange($subsByParent[$k]) }
        }
        $rank = 0; $sevText = ''
        foreach ($s in $list) { $r = [int]$script:SI_DfcSeverityRank[([string]$s.FindingSeverity).ToLowerInvariant()]; if ($r -gt $rank) { $rank = $r; $sevText = [string]$s.FindingSeverity } }
        $labels = @($list | ForEach-Object {
            $l = [string]$_.FindingName
            if ($_.FindingId) { $l += (' [{0}]' -f $_.FindingId) }
            if ($_.FindingSeverity) { $l += (' ({0})' -f $_.FindingSeverity) }
            $l
        } | Sort-Object -Unique)
        $text = ''; $shown = 0
        foreach ($l in $labels) {
            $next = if ($text) { $text + '; ' + $l } else { $l }
            if ($next.Length -gt $script:SI_DfcSubFindingsMaxChars) { break }
            $text = $next; $shown++
        }
        if ($shown -lt $labels.Count) { $text += (' ... (+{0} more -- SubFindingCount is exact)' -f ($labels.Count - $shown)) }
        # RICH CONTEXT (Defender lane): what the findings are ABOUT -- the affected software with its version, the version
        # that fixes it, the finding's own fix text, and for a container image its digest and repository. Each value once,
        # sorted; a long list says how many it did not print (_capList).
        $prod = New-Object System.Collections.Generic.List[string]; $fix = New-Object System.Collections.Generic.List[string]
        $rem = New-Object System.Collections.Generic.List[string]; $dig = New-Object System.Collections.Generic.List[string]; $repo = New-Object System.Collections.Generic.List[string]
        foreach ($s in $list) {
            $pn = ''; if ($s.PSObject.Properties['FindingProduct']) { $pn = ([string]$s.FindingProduct).Trim() }
            $pv = ''; if ($s.PSObject.Properties['FindingVersion']) { $pv = ([string]$s.FindingVersion).Trim() }
            $pvd = ''; if ($s.PSObject.Properties['FindingVendor']) { $pvd = ([string]$s.FindingVendor).Trim() }
            $fv = ''; if ($s.PSObject.Properties['FindingFixedVersion']) { $fv = ([string]$s.FindingFixedVersion).Trim() }
            if ($pn) {
                $d = (($pn + ' ' + $pv).Trim()); if ($pvd) { $d += (' ({0})' -f $pvd) }
                if (-not $prod.Contains($d)) { $prod.Add($d) }
                if ($fv) { $f = ('{0} {1}' -f $pn, $fv); if (-not $fix.Contains($f)) { $fix.Add($f) } }
            } elseif ($fv -and -not $fix.Contains($fv)) { $fix.Add($fv) }
            foreach ($pair in @(@('FindingRemediation', $rem), @('FindingImageDigest', $dig), @('FindingRepository', $repo))) {
                if (-not $s.PSObject.Properties[$pair[0]]) { continue }
                $v = ConvertFrom-SIDefenderHtml ([string]$s.($pair[0]))
                if ($v -and -not $pair[1].Contains($v)) { $pair[1].Add($v) }
            }
        }
        @{ Count = [int]$list.Count; Severity = $sevText; Text = $text
           Products = (_capList $prod); FixedVersions = (_capList $fix); Remediation = (_capList $rem 4000); Digests = (_capList $dig); Repositories = (_capList $repo) }
    }

    # a list of values as one text: sorted, '; '-joined, cut before the cell limit with the number left out said
    function _capList($values, [int]$maxChars = 8000) {
        $xs = @(@($values) | Where-Object { $_ } | Sort-Object -Unique)
        $text = ''; $shown = 0
        foreach ($x in $xs) {
            $next = if ($text) { $text + '; ' + $x } else { [string]$x }
            if ($next.Length -gt $maxChars) { break }
            $text = $next; $shown++
        }
        if ($shown -lt $xs.Count) { $text += (' ... (+{0} more)' -f ($xs.Count - $shown)) }
        $text
    }

    # Defender CSPM seen in this tenant? (a risk level on any recommendation, an attack path, a governance assignment);
    # $false only when the context reads completed and found none; $null = not known
    $cspmSeen = $null
    if ($null -ne $Context -and $Context.Count -gt 0) {
        $anyRisk = if ($null -ne $RiskLevelSeen) { [bool]$RiskLevelSeen } else { @(@($Raw) | Where-Object { $null -ne $_ -and $_.PSObject.Properties['RiskLevel'] -and ([string]$_.RiskLevel).Trim() }).Count -gt 0 }
        $govN = 0; if ($Context['Governance']) { $govN = $Context['Governance'].Count }
        $apN = 0; if ($Context['AttackPaths']) { $apN = $Context['AttackPaths'].Count }
        $rd = $Context['Read']
        if ($anyRisk -or $govN -gt 0 -or $apN -gt 0) { $cspmSeen = $true }
        elseif ($rd -and $rd['Governance'] -and $rd['AttackPaths']) { $cspmSeen = $false }
    }

    # The JSON reader turns an ISO timestamp into a [datetime], and [string] on that renders it in the
    # current culture ("05/31/2025 07:19:24") -- ambiguous, and unparseable on a da-DK host. Always ISO UTC.
    function _isoTime($v) {
        if ($v -is [datetime]) { return $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
        [string]$v
    }

    function _row($src, [string]$resourceId, [string]$kind, [int]$count, [string]$entities, [string[]]$assessmentIds = @()) {
        $rid = [string]$resourceId
        $sub = _subs $assessmentIds
        $segs = @($rid.TrimEnd('/') -split '/' | Where-Object { $_ })
        # RICH CONTEXT (Defender lane): the recommendation's own extra facts and what Defender for Cloud holds around it
        # (Get-SIDefenderRecommendationContext.ps1) -- every column on every row, as text
        $rx = [ordered]@{ GovernanceOwner = ''; GovernanceDueDate = ''; GovernanceGracePeriod = ''; ComplianceTags = ''; SecureScoreControl = ''; SecureScoreGain = ''; AttackPathCount = ''; AttackPaths = '' }
        if (Get-Command -Name Get-SIDefenderRowContext -ErrorAction SilentlyContinue) {
            $apRefs = ''; if ($src.PSObject.Properties['AttackPathRefs']) { $apRefs = [string]$src.AttackPathRefs }
            $rx = Get-SIDefenderRowContext -Context $Context -AssessmentIds $assessmentIds -SubscriptionId ([string]$src.SubscriptionId) -AssessmentKey ([string]$src.AssessmentKey) -AttackPathRefs $apRefs -CspmSeen $cspmSeen
        }
        $own = @{}
        foreach ($n in 'Techniques', 'PolicyDefinitionId', 'StatusCause', 'StatusDescription', 'ImageDigest', 'ImageRepository') { $own[$n] = ''; if ($src.PSObject.Properties[$n]) { $own[$n] = ([string]$src.$n).Trim() } }
        $rowCols = [ordered]@{
            CollectionTime         = $CollectionTime.ToUniversalTime()   # a real UTC datetime, exactly as the profile rows carry it
            RunId                  = $RunId
            # One stable key per (resource, recommendation). RA's CL shadow fetch -- the path that feeds a
            # hybrid (graph + SI table) query -- reads every SI_*_CL table as "latest row per PrimaryEntityId";
            # without the column it failed and the graph report's de-duplication silently removed nothing.
            PrimaryEntityId        = ('{0}|{1}' -f $rid.ToLowerInvariant(), ([string]$src.Recommendation).ToLowerInvariant())
            ResourceId             = $rid
            ResourceIdLower        = $rid.ToLowerInvariant()
            ResourceName           = Get-SIDefenderAssetLabel -ResourceId $rid -SubscriptionId ([string]$src.SubscriptionId) -SubscriptionNames $SubscriptionNames `
                                         -ResourceName $(if ($kind -in 'RolledUpEntities') { [string]($segs | Select-Object -Last 1) } else { [string]$src.ResourceName })
            # a roll-up of Azure child resources is a row of its PARENT resource: the parent's type
            ResourceType           = if ($kind -in 'RolledUpEntities') { [string]$src._ParentType } else { [string]$src.ResourceType }
            ResourceSource         = [string]$src.ResourceSource
            SubscriptionId         = [string]$src.SubscriptionId
            # names next to ids: the subscription's display name and its management group (id + name + path); '' when not known
            SubscriptionName       = $(if ($SubscriptionNames -and [string]$src.SubscriptionId -and $SubscriptionNames.ContainsKey(([string]$src.SubscriptionId).ToLowerInvariant())) { [string]$SubscriptionNames[([string]$src.SubscriptionId).ToLowerInvariant()] } else { '' })
            ManagementGroupId      = $(if ($SubscriptionContext -and [string]$src.SubscriptionId -and $SubscriptionContext.ContainsKey(([string]$src.SubscriptionId).ToLowerInvariant())) { [string]$SubscriptionContext[([string]$src.SubscriptionId).ToLowerInvariant()].ManagementGroupId } else { '' })
            ManagementGroupName    = $(if ($SubscriptionContext -and [string]$src.SubscriptionId -and $SubscriptionContext.ContainsKey(([string]$src.SubscriptionId).ToLowerInvariant())) { [string]$SubscriptionContext[([string]$src.SubscriptionId).ToLowerInvariant()].ManagementGroupName } else { '' })
            ManagementGroupPath    = $(if ($SubscriptionContext -and [string]$src.SubscriptionId -and $SubscriptionContext.ContainsKey(([string]$src.SubscriptionId).ToLowerInvariant())) { [string]$SubscriptionContext[([string]$src.SubscriptionId).ToLowerInvariant()].ManagementGroupPath } else { '' })
            ResourceGroup          = [string]$src.ResourceGroup
            RowKind                = $kind
            Recommendation         = [string]$src.Recommendation
            AssessmentKey          = [string]$src.AssessmentKey
            Severity               = [string]$src.Severity
            RecommendationCategory = [string]$src.RecommendationCategory
            SecurityIssue          = [string]$src.SecurityIssue
            Categories             = [string]$src.Categories
            Tactics                = [string]$src.Tactics
            Threats                = [string]$src.Threats
            Description            = ConvertFrom-SIDefenderHtml ([string]$src.Description)
            Remediation            = ConvertFrom-SIDefenderHtml ([string]$src.Remediation)
            ImplementationEffort   = [string]$src.ImplementationEffort
            UserImpact             = [string]$src.UserImpact
            PortalLink             = [string]$src.PortalLink
            RiskLevel              = [string]$src.RiskLevel
            RiskFactors            = [string]$src.RiskFactors
            FirstEvaluated         = _isoTime $src.FirstEvaluated
            StatusChanged          = _isoTime $src.StatusChanged
            MaxCvssScore           = [string]$src.MaxCvssScore
            AffectedEntityKind     = if ($kind -eq 'RolledUpEntities') { [string]$src._EntityKind } else { '' }
            AffectedEntityCount    = [int]$count
            AffectedEntities       = [string]$entities
            SubFindingCount        = [int]$sub.Count
            SubFindingMaxSeverity  = [string]$sub.Severity
            SubFindings            = [string]$sub.Text
            # RICH CONTEXT (Defender lane) -- one contiguous block, all text
            Techniques             = [string]$own['Techniques']
            PolicyDefinitionId     = [string]$own['PolicyDefinitionId']
            StatusCause            = [string]$own['StatusCause']
            StatusDescription      = [string]$own['StatusDescription']
            ImageDigest            = $(if ($sub.Digests) { [string]$sub.Digests } else { [string]$own['ImageDigest'] })
            ImageRepository        = $(if ($sub.Repositories) { [string]$sub.Repositories } else { [string]$own['ImageRepository'] })
            SubFindingProducts     = [string]$sub.Products
            SubFindingFixedVersions = [string]$sub.FixedVersions
            SubFindingRemediation  = [string]$sub.Remediation
            GovernanceOwner        = [string]$rx.GovernanceOwner
            GovernanceDueDate      = [string]$rx.GovernanceDueDate
            GovernanceGracePeriod  = [string]$rx.GovernanceGracePeriod
            ComplianceTags         = [string]$rx.ComplianceTags
            SecureScoreControl     = [string]$rx.SecureScoreControl
            SecureScoreGain        = [string]$rx.SecureScoreGain
            AttackPathCount        = [string]$rx.AttackPathCount
            AttackPaths            = [string]$rx.AttackPaths
        }
        [pscustomobject]$rowCols
    }

    # One assessment is one finding. The same assessment id twice (a paging overlap) must never become two.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($Raw)) {
        if ($null -eq $r) { continue }
        $aid = if ($r.PSObject.Properties['AssessmentId'] -and $r.AssessmentId) { [string]$r.AssessmentId } else { '{0}|{1}' -f $r.ResourceId, $r.AssessmentKey }
        if (-not $seen.Add($aid)) { continue }
        $p = Get-SIDefenderRecommendationParent -ResourceId ([string]$r.ResourceId) -ResourceType ([string]$r.ResourceType) -Scope $Scope -ChildParents $ChildParents
        if (-not $p.IsEntity) {
            $kind = if ([string]$r.ResourceId -match '^/subscriptions/[^/]+/?$') { 'Subscription' } else { 'Resource' }
            $out.Add((_row $r ([string]$r.ResourceId) $kind 0 '' @($aid)))
            continue
        }
        $key = ('{0}|{1}' -f $p.ParentId.ToLowerInvariant(), ([string]$r.Recommendation).ToLowerInvariant())
        if (-not $groups.Contains($key)) {
            $groups[$key] = @{ First = $r; Parent = $p.ParentId; Kind = $p.EntityKind; Entities = New-Object System.Collections.Generic.List[string]; Sev = 0; SevText = [string]$r.Severity; Cvss = -1.0; Ids = New-Object System.Collections.Generic.List[string] }
        }
        $g = $groups[$key]
        $g.Ids.Add($aid)
        $label = if ($r.ImageUri) { [string]$r.ImageUri } elseif ($r.ResourceName) { [string]$r.ResourceName } else { [string]$r.ResourceId }
        if (-not $g.Entities.Contains($label)) { $g.Entities.Add($label) }
        $rank = [int]$script:SI_DfcSeverityRank[([string]$r.Severity).ToLowerInvariant()]
        if ($rank -gt $g.Sev) { $g.Sev = $rank; $g.SevText = [string]$r.Severity }
        $cv = 0.0
        if ([double]::TryParse([string]$r.MaxCvssScore, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$cv) -and $cv -gt $g.Cvss) { $g.Cvss = $cv }
    }
    foreach ($k in $groups.Keys) {
        $g = $groups[$k]
        $src = $g.First.PSObject.Copy()
        $src | Add-Member -NotePropertyName _EntityKind -NotePropertyValue $g.Kind -Force
        $ptype = ''
        if ($g.Kind -eq 'AzureChildResource' -and (Test-Path -Path 'function:Get-SIArmIdInfo')) { $pi = Get-SIArmIdInfo $g.Parent; if ($pi) { $ptype = [string]$pi.Type } }
        $src | Add-Member -NotePropertyName _ParentType -NotePropertyValue $ptype -Force
        $src.Severity = $g.SevText
        if ($g.Cvss -ge 0) { $src.MaxCvssScore = $g.Cvss.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
        $sorted = @($g.Entities | Sort-Object)
        $out.Add((_row $src $g.Parent 'RolledUpEntities' $sorted.Count ($sorted -join '; ') $g.Ids.ToArray()))
    }

    # Sub-findings whose parent recommendation is not in this list (e.g. the parent is not reported
    # unhealthy): their own row, per parent assessment, so no finding is dropped.
    foreach ($pk in @($subsByParent.Keys | Sort-Object)) {
        if ($usedParents.Contains($pk)) { continue }
        $first = $subsByParent[$pk][0]
        $aKey = ($pk -split '/assessments/')[-1]
        $rid = if ($first.ResourceId) { [string]$first.ResourceId } else { ($pk -split '/providers/microsoft.security/assessments/')[0] }
        $src = [pscustomobject]@{
            Recommendation = ('Defender for Cloud findings ({0})' -f $aKey); AssessmentKey = $aKey
            ResourceName = [string](@($rid.TrimEnd('/') -split '/')[-1]); ResourceType = ''; ResourceSource = 'Azure'
            SubscriptionId = [string]$first.SubscriptionId; ResourceGroup = [string]$first.ResourceGroup; Severity = ''
        }
        $row = _row $src $rid 'SubAssessments' 0 '' @($pk)
        $row.Severity = $row.SubFindingMaxSeverity
        $out.Add($row)
    }
    return $out.ToArray()
}

function Get-SIDefenderRecommendationBucketKey {
    <#
      PURE. #1399 The key a raw row is grouped under for the bucketed roll-up: the lower-case PARENT resource its row is reported
      against (Get-SIDefenderRecommendationParent) -- every assessment of one (parent, recommendation) group and every finding
      of those assessments share it, so a bucket always holds whole groups. -SubAssessment: the row is a finding; its parent
      assessment's resource is the part of ParentAssessmentId before '/providers/microsoft.security/assessments/'.
    #>
    param($Row, [switch]$SubAssessment, $Scope, [hashtable]$ChildParents)
    if ($SubAssessment) {
        $pk = ([string]$Row.ParentAssessmentId).ToLowerInvariant()
        $i = $pk.IndexOf('/providers/microsoft.security/assessments/', [StringComparison]::Ordinal)
        $rid = if ($i -ge 0) { $pk.Substring(0, $i) } else { $pk }
        return ([string](Get-SIDefenderRecommendationParent -ResourceId $rid -ResourceType '' -Scope $Scope -ChildParents $ChildParents).ParentId).ToLowerInvariant()
    }
    ([string](Get-SIDefenderRecommendationParent -ResourceId ([string]$Row.ResourceId) -ResourceType ([string]$Row.ResourceType) -Scope $Scope -ChildParents $ChildParents).ParentId).ToLowerInvariant()
}

function Get-SIDefenderRecommendations {
    <#
      Read + roll up. Returns @{ Rows; Complete; RawCount; SubCount; RowCount; ByKind; Entities; Error }. Never throws;
      Complete=$false means the caller must NOT publish (see header).
      #1399 STREAMED, THE SAME METHOD AT EVERY SIZE (owner 2026-11-26: "env must work in millions of assets env"): both reads are
      paged (-OnPage) into disk buckets by the row's parent resource (Get-SIDefenderRecommendationBucketKey), so a bucket holds
      whole (parent, recommendation) groups and every finding of them; each bucket is then rolled up on its own by the same
      ConvertTo-SIDefenderRecommendationRows. Memory is one bucket (a bucket larger than -BucketRows is spread again), never the
      tenant. -OnRows { param($Rows) }: each bucket's rows are handed on and not kept (Rows comes back empty) -- only after BOTH
      reads completed, so an incomplete read still publishes nothing. Without -OnRows the rows are collected (tests).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$RunId,
        [string[]]$SubscriptionIds = @(),
        [scriptblock]$PageFetcher,
        # Azure child resources roll up into their parent (ConvertTo-SIDefenderRecommendationRows)
        $Scope,
        [hashtable]$ChildParents,
        [scriptblock]$OnRows,
        [int]$Buckets = 64,
        [long]$BucketRows = 20000,
        # rows held before the buffered rows go to their bucket files
        [int]$FlushRows = 5000
    )
    if (-not (Get-Command Invoke-SIArgPaged -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Invoke-SIArgPaged.ps1')
    }
    $raw = New-SIDiskBuckets -Name 'defender-assessments' -Count $Buckets
    $subB = New-SIDiskBuckets -Name 'defender-findings' -Count $Buckets
    $st = @{ AnyRisk = $false; Buf = @{}; BufRows = 0; Target = $null; Rows = (New-Object System.Collections.Generic.List[object])
             RowCount = 0L; ByKind = [ordered]@{}; Entities = 0L; Redirect = @{} }
    $flush = {
        foreach ($bk in @($st.Buf.Keys)) { Add-SIDiskBucketRows -Buckets $st.Target -Bucket $bk -Rows $st.Buf[$bk].ToArray() }
        $st.Buf = @{}; $st.BufRows = 0
    }
    $put = {
        param([int]$bk, $row)
        if (-not $st.Buf.ContainsKey($bk)) { $st.Buf[$bk] = New-Object System.Collections.Generic.List[object] }
        $st.Buf[$bk].Add($row); $st.BufRows++
        if ($st.BufRows -ge $FlushRows) { & $flush }
    }
    try {
        $args2 = @{ Query = (Get-SIDefenderRecommendationKql); SourceLabel = 'Defender for Cloud recommendations'; SubscriptionIds = $SubscriptionIds }
        if ($PageFetcher) { $args2['PageFetcher'] = $PageFetcher }
        $st.Target = $raw
        $res = Invoke-SIArgPaged @args2 -OnPage {
            param($Rows)
            foreach ($r in $Rows) {
                if ($null -eq $r) { continue }
                if (-not $st.AnyRisk -and $r.PSObject.Properties['RiskLevel'] -and ([string]$r.RiskLevel).Trim()) { $st.AnyRisk = $true }
                $key = Get-SIDefenderRecommendationBucketKey -Row $r -Scope $Scope -ChildParents $ChildParents
                $bk = Get-SIDiskBucketIndex -Key $key -Count $Buckets
                # an assessment whose own id names another resource than its resourceDetails: its findings follow it
                if ($r.PSObject.Properties['AssessmentId'] -and $r.AssessmentId) {
                    $idk = Get-SIDefenderRecommendationBucketKey -Row ([pscustomobject]@{ ParentAssessmentId = [string]$r.AssessmentId }) -SubAssessment -Scope $Scope -ChildParents $ChildParents
                    if ((Get-SIDiskBucketIndex -Key $idk -Count $Buckets) -ne $bk) { $st.Redirect[([string]$r.AssessmentId).ToLowerInvariant()] = $bk }
                }
                & $put $bk $r
            }
        }
        & $flush
        # The findings behind the recommendations. Both reads must COMPLETE: a partial list of findings would
        # show fewer on a recommendation than exist, which reads as "fixed" exactly like a missing row does.
        $args3 = @{ Query = (Get-SIDefenderSubAssessmentKql); SourceLabel = 'Defender for Cloud recommendation findings'; SubscriptionIds = $SubscriptionIds }
        if ($PageFetcher) { $args3['PageFetcher'] = $PageFetcher }
        $st.Target = $subB
        $sub = if ($res.Complete) {
            Invoke-SIArgPaged @args3 -OnPage {
                param($Rows)
                foreach ($s in $Rows) {
                    if ($null -eq $s) { continue }
                    $pk = ([string]$s.ParentAssessmentId).ToLowerInvariant()
                    $bk = if ($st.Redirect.ContainsKey($pk)) { [int]$st.Redirect[$pk] } else { Get-SIDiskBucketIndex -Key (Get-SIDefenderRecommendationBucketKey -Row $s -SubAssessment -Scope $Scope -ChildParents $ChildParents) -Count $Buckets }
                    & $put $bk $s
                }
            }
        } else { [pscustomobject]@{ Rows = @(); RowCount = 0L; Complete = $false; Error = $null } }
        & $flush
        # #202 subscription display names -- best effort: a failed read leaves the ids in place and never blocks the publish.
        $subNames = @{}
        if ($res.Complete) {
            $args4 = @{ Query = (Get-SISubscriptionNameKql); SourceLabel = 'subscription names'; SubscriptionIds = $SubscriptionIds }
            if ($PageFetcher) { $args4['PageFetcher'] = $PageFetcher }
            # The pager's own warning speaks of missing assets; a missing NAME loses nothing, so say what it does mean.
            $names = Invoke-SIArgPaged @args4 -WarningAction SilentlyContinue
            if (-not $names.Complete) { Write-Warning 'Subscription names could not be read -- subscriptions are shown by their id in this run.' }
            foreach ($s in @($names.Rows)) {
                if ($null -eq $s -or -not $s.PSObject.Properties['subscriptionId'] -or -not $s.PSObject.Properties['name']) { continue }
                if ($s.subscriptionId -and $s.name) { $subNames[([string]$s.subscriptionId).ToLowerInvariant()] = [string]$s.name }
            }
            # the same rows carry each subscription's management-group chain: id + name + path next to the subscription
            try { $subContext = ConvertTo-SIDefenderSubscriptionContext -Rows @($names.Rows) } catch { $subContext = @{} }
        }
        if ($null -eq $subContext) { $subContext = @{} }
        # RICH CONTEXT (Defender lane): owners and due dates, regulatory compliance, secure score controls, attack paths --
        # best effort, read only when the recommendations themselves are complete; a failed read never blocks the publish.
        $ctx = @{}
        if ($res.Complete -and $sub.Complete) {
            try {
                if (-not (Get-Command -Name Get-SIDefenderRecommendationContext -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Get-SIDefenderRecommendationContext.ps1') }
                $ctxArgs = @{ SubscriptionIds = $SubscriptionIds }
                if ($PageFetcher) { $ctxArgs['PageFetcher'] = $PageFetcher }
                $ctx = Get-SIDefenderRecommendationContext @ctxArgs
            } catch {
                Write-Warning ('Defender for Cloud: the context of the recommendations could not be read ({0}) -- those columns stay empty in this run.' -f $_.Exception.Message)
                $ctx = @{}
            }
        }
        $complete = ([bool]$res.Complete -and [bool]$sub.Complete)
        if ($complete) {
            $conv = @{ CollectionTime = $CollectionTime; RunId = $RunId; SubscriptionNames = $subNames; SubscriptionContext = $subContext; Scope = $Scope; ChildParents = $ChildParents; Context = $ctx; RiskLevelSeen = [bool]$st.AnyRisk }
            # one bucket (its raw rows and its findings) -> its rows; a bucket larger than -BucketRows is spread again over new
            # buckets by the same key (a new salt) -- a single (parent) group is never split
            $work = $null
            $work = {
                param([object[]]$rRows, [object[]]$sRows, [int]$depth)
                if (($rRows.Count + $sRows.Count) -gt $BucketRows -and $depth -lt 3) {
                    $n = 16; $salt = ('d{0}:' -f ($depth + 1))
                    $r2 = New-SIDiskBuckets -Name 'defender-assessments-split' -Count $n; $s2 = New-SIDiskBuckets -Name 'defender-findings-split' -Count $n
                    try {
                        $keyOf = @{}
                        foreach ($pair in @(@($rRows, $r2, $false), @($sRows, $s2, $true))) {
                            $lists = @{}
                            foreach ($x in @($pair[0])) {
                                if ($null -eq $x) { continue }
                                $k = if ($pair[2]) {
                                    $pk = ([string]$x.ParentAssessmentId).ToLowerInvariant()
                                    if ($keyOf.ContainsKey($pk)) { $keyOf[$pk] } else { Get-SIDefenderRecommendationBucketKey -Row $x -SubAssessment -Scope $Scope -ChildParents $ChildParents }
                                } else {
                                    $kk = Get-SIDefenderRecommendationBucketKey -Row $x -Scope $Scope -ChildParents $ChildParents
                                    if ($x.PSObject.Properties['AssessmentId'] -and $x.AssessmentId) { $keyOf[([string]$x.AssessmentId).ToLowerInvariant()] = $kk }
                                    $kk
                                }
                                $b = Get-SIDiskBucketIndex -Key $k -Count $n -Salt $salt
                                if (-not $lists.ContainsKey($b)) { $lists[$b] = New-Object System.Collections.Generic.List[object] }
                                $lists[$b].Add($x)
                            }
                            foreach ($b in @($lists.Keys)) { Add-SIDiskBucketRows -Buckets $pair[1] -Bucket $b -Rows $lists[$b].ToArray() }
                        }
                        $rRows = $null; $sRows = $null; $keyOf = $null
                        for ($j = 0; $j -lt $n; $j++) {
                            & $work (Read-SIDiskBucketRows -Buckets $r2 -Bucket $j) (Read-SIDiskBucketRows -Buckets $s2 -Bucket $j) ($depth + 1)
                            Close-SIDiskBucket -Buckets $r2 -Bucket $j; Close-SIDiskBucket -Buckets $s2 -Bucket $j
                        }
                    } finally { Remove-SIDiskBuckets $r2; Remove-SIDiskBuckets $s2 }
                    return
                }
                if ($rRows.Count -eq 0 -and $sRows.Count -eq 0) { return }
                $out = @(ConvertTo-SIDefenderRecommendationRows -Raw $rRows -SubAssessments $sRows @conv)
                foreach ($o in $out) {
                    $kd = [string]$o.RowKind
                    if ($st.ByKind.Contains($kd)) { $st.ByKind[$kd]++ } else { $st.ByKind[$kd] = 1L }
                    if ($kd -eq 'RolledUpEntities') { $st.Entities += [long]$o.AffectedEntityCount }
                }
                $st.RowCount += $out.Count
                if ($out.Count) { if ($OnRows) { $null = & $OnRows $out } else { $st.Rows.AddRange([object[]]$out) } }
            }
            for ($b = 0; $b -lt $Buckets; $b++) {
                & $work (Read-SIDiskBucketRows -Buckets $raw -Bucket $b) (Read-SIDiskBucketRows -Buckets $subB -Bucket $b) 0
                Close-SIDiskBucket -Buckets $raw -Bucket $b; Close-SIDiskBucket -Buckets $subB -Bucket $b
            }
        }
        $err = if ($res.Error) { $res.Error } else { $sub.Error }
        [pscustomobject]@{ Rows = $st.Rows.ToArray(); Complete = $complete; RawCount = [long]$res.RowCount; SubCount = [long]$sub.RowCount
                           RowCount = [long]$st.RowCount; ByKind = $st.ByKind; Entities = [long]$st.Entities; Error = $err }
    } catch {
        # NEVER THROWS (#1399 review): a failure anywhere -- a page handler, a disk bucket, a hand-on (-OnRows) -- is an INCOMPLETE
        # result; the caller publishes nothing and says why
        $why = [string]$_.Exception.Message
        Write-Warning ('Defender for Cloud recommendations: the roll-up could not be completed -- {0}' -f $why)
        [pscustomobject]@{ Rows = @(); Complete = $false; RawCount = $(if ($res) { [long]$res.RowCount } else { 0L }); SubCount = $(if ($sub) { [long]$sub.RowCount } else { 0L })
                           RowCount = [long]$st.RowCount; ByKind = $st.ByKind; Entities = [long]$st.Entities; Error = $why }
    } finally {
        Remove-SIDiskBuckets $raw; Remove-SIDiskBuckets $subB
    }
}

function Get-SIDefenderStoredChildParentSql {
    <#
        PURE. #1399 the child -> parent map from the STORED Azure records (sidata.CiRecord: every part's records of the run, and the
        records kept from earlier runs): each Azure resource record lists its child resources (si_child_resources: { id, type,
        name }) -- as an array or as JSON text, of any length (OPENJSON, never JSON_VALUE's 4,000 characters). Answers ChildId,
        ParentId, both lower case. Read-only.
    #>
    @"
SET NOCOUNT ON;
SELECT LOWER(CONVERT(nvarchar(450), CASE WHEN ISJSON(c.[value]) = 1 THEN JSON_VALUE(c.[value], '$.id') END)) AS ChildId,
       LOWER(SUBSTRING(r.RecordKey, LEN(N'azure|azure_resource|') + 1, 450)) AS ParentId
FROM sidata.CiRecord AS r
CROSS APPLY OPENJSON(CASE WHEN ISJSON(r.DocJson) = 1 THEN r.DocJson ELSE N'{}' END) AS t
CROSS APPLY OPENJSON(CASE WHEN t.[key] = N'si_child_resources' AND t.[type] IN (1, 4) AND ISJSON(t.[value]) = 1 THEN t.[value] ELSE N'[]' END) AS c
WHERE r.Provider = N'azure' AND r.RecordType = N'azure_resource' AND r.RecordKey LIKE N'azure|azure_resource|%' AND ISJSON(r.DocJson) = 1
  AND t.[key] = N'si_child_resources';   -- (the key is tested inside the CASE too: a scalar top-level value is never opened)
"@
}

function Read-SIDefenderStoredChildParents {
    <# #1399 the stored map (Get-SIDefenderStoredChildParentSql) a row at a time -> @{ child id = parent id }. Throws when it cannot be read. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $__cpMap = @{}
    $on = { param($r) $c = [string]$r['ChildId']; $p = [string]$r['ParentId']; if ($c -and $p -and $c -ne $p) { $__cpMap[$c] = $p } }
    if (Get-Command -Name Invoke-SIDataSqlStream -ErrorAction SilentlyContinue) { $null = Invoke-SIDataSqlStream -Invoke $Invoke -Sql (Get-SIDefenderStoredChildParentSql) -Params @{} -OnRow $on }
    else { $ans = & $Invoke (Get-SIDefenderStoredChildParentSql) @{} 'reader'; foreach ($a in @($ans)) { foreach ($r in @($a)) { if ($null -ne $r) { & $on $r } } } }
    $__cpMap
}

function New-SIDefenderSnapshotMarker {
    <#
        PURE. #1399 the row that says a snapshot is COMPLETE, posted after every row of it: RowKind 'SnapshotComplete', the number
        of rows it holds in AffectedEntityCount, every other column of -Template present and empty (the table's schema never
        drifts, #148). The readers take the newest snapshot that has its marker and at least that many rows.
    #>
    param([Parameter(Mandatory)]$Template, [Parameter(Mandatory)][long]$Rows, [Parameter(Mandatory)][string]$RunId)
    $o = [ordered]@{}
    foreach ($p in $Template.PSObject.Properties) {
        $v = $p.Value
        $o[$p.Name] = if ($v -is [datetime]) { $v } elseif ($v -is [int] -or $v -is [long]) { 0 } elseif ($v -is [bool]) { $false } else { '' }
    }
    $o['RunId'] = $RunId; $o['RowKind'] = 'SnapshotComplete'; $o['PrimaryEntityId'] = ('snapshot|{0}' -f $RunId); $o['AffectedEntityCount'] = [int]$Rows
    [pscustomobject]$o
}
