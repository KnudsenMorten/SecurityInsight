#Requires -Version 5.1
<#
    SecurityInsight Pro -- the data sync's Log Analytics queries (REQUIREMENTS §9.3.3 phase B).

    Every builder here is PURE: it returns KQL text, so the shape of each query is provable without a workspace.
    Two rules from earlier findings shape every one of them:
      * FILTER THEN SUMMARIZE (#83). Both editions write the same tables; picking the newest snapshot before the
        edition filter selects the other edition's snapshot and every v3 column reads empty.
      * EVERY COLUMN THROUGH column_ifexists. A plain reference to a column a table does not carry fails the whole
        query instead of degrading to an empty value.

    PS 5.1 safe. No Set-StrictMode (it leaks into the caller's scope).
#>

function ConvertTo-SIDataKqlTime {
    <# PURE. A UTC KQL datetime literal for a [datetime] (seconds and fractions kept, so == matches the stored value). #>
    param([Parameter(Mandatory)][datetime]$Time)
    'datetime({0})' -f $Time.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SIDataEditionFilter {
    <# PURE. The same edition filter the vulnerability close-loop uses: rows stamped by this edition's major version. #>
    param([Parameter(Mandatory)][string]$EditionMajor)
    '| where tostring(column_ifexists("SolutionVersion", "")) startswith "{0}."' -f $EditionMajor
}

function Get-SIDataCollectionsKql {
    <#
        PURE. Every Risk Analysis collection of THIS edition in the look-back window, one row per CollectionTime, with
        its row count and its estimated size (what the reader partitions on). Oldest first, so a missed day is
        caught up in order.
    #>
    param(
        [Parameter(Mandatory)][string]$EditionMajor,
        [int]$LookbackDays = 3,
        [string]$TableName = 'SI_RiskAnalysis_Detailed_CL'
    )
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
$(Get-SIDataEditionFilter -EditionMajor $EditionMajor)
| where isnotnull(CollectionTime)
| summarize Rows = count(), Bytes = sum(estimate_data_size(*)), SolutionVersion = take_any(tostring(column_ifexists("SolutionVersion", ""))),
            NoConfigurationId = countif(isempty(tostring(column_ifexists("ConfigurationId", "")))) by CollectionTime
| order by CollectionTime asc
"@
}

function Get-SIDataRunHealthKql {
    <#
        PURE. The END records of recent Risk Analysis runs -- the close-loop's columns (Get-SIVulnRunHealthKql: StartedAt,
        DurationSec, ExitReason, RunId) PLUS the run's own message (Detail), so a collection held because its run ended
        'success-partial' can say WHAT was incomplete (which report, which bucket) on the Guards page and in the mail.
    #>
    param([int]$LookbackDays = 3)
    @"
SI_RunHealth_CL
| where TimeGenerated > ago($($LookbackDays)d)
| where Engine == "risk-analysis" and Phase == "End"
| project StartedAt = CollectionTime, DurationSec = toint(DurationSec), ExitReason = tostring(ExitReason), RunId = tostring(RunId), Detail = tostring(column_ifexists("ErrorMessage", ""))
"@
}

function Get-SIDataUntimedRowsKql {
    <#
        PURE (#294). Rows in the look-back window WITHOUT a CollectionTime, per hour they arrived. Such rows belong to no
        collection, so the collections query never lists them -- without this they would vanish silently. No edition
        filter: a row that lost its CollectionTime lost its SolutionVersion the same way (measured on ring 1, 2026-10-05).
    #>
    param([int]$LookbackDays = 3, [string]$TableName = 'SI_RiskAnalysis_Detailed_CL')
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| where isnull(CollectionTime)
| summarize UntimedRows = count(), FirstAt = min(TimeGenerated), LastAt = max(TimeGenerated) by Hour = bin(TimeGenerated, 1h)
| order by Hour asc
"@
}

function Get-SIDataPageFilter {
    <#
        PURE. The where-clause of ONE PAGE of a large read: every cut (@{ Parts; Part }) keeps one hash bucket of the
        rows' own key (_pk), and a page is the rows every one of its cuts keeps. The first cut is the planned page
        ("bucket Part of Parts"); each later cut divides that page again, on a hash of its own (the key with the cut's
        depth in front), so the pieces of a page never overlap and together are that page -- whatever the hash does.
        That is what lets ONE page be made smaller without reading any other page again. '' = no cut: everything.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Cuts = @())
    $terms = New-Object System.Collections.Generic.List[string]
    for ($d = 0; $d -lt @($Cuts).Count; $d++) {
        $parts = [long]$Cuts[$d].Parts; $part = [long]$Cuts[$d].Part
        if ($parts -lt 1 -or $part -lt 0 -or $part -ge $parts) { throw ('Get-SIDataPageFilter: part {0} is outside 0..{1}' -f $part, ($parts - 1)) }
        if ($parts -eq 1) { continue }
        if ($d -eq 0) { $terms.Add(('hash(_pk, {0}) == {1}' -f $parts, $part)) }
        else { $terms.Add(('hash(strcat("{0}|", _pk), {1}) == {2}' -f $d, $parts, $part)) }
    }
    if ($terms.Count -eq 0) { return '' }
    '| where ' + ($terms -join ' and ')
}

function Get-SIDataFindingsKql {
    <#
        PURE. The rows of ONE collection, narrow, with the whole row packed as DetailJson. -Partitions > 1 reads one
        PAGE of it: one hash bucket (-Partition 0..Partitions-1) of the rows' own key. A Detailed collection can be far
        larger than one query may return or one job can hold, so the reader takes it a page at a time, and every row
        lands in exactly one page. -PageFilter (Get-SIDataPageFilter) is a page the reader cut further.
        The key is the ROW's (the record's own id, with its asset, configuration and report), not the asset's: pages
        then hold about the same number of rows. Keyed by asset, every row without an asset id -- and every row of an
        asset with thousands of findings -- landed in ONE page, however many pages there were.
        -CountOnly: not the rows, but how many rows that page holds (PageRows) and whether one key is all it holds
        (OneKey) -- what tells a page that can be split from a single row too large to read.
        The asset id is SI_AssetId when the row carries one, else AssetId (the id the close-loop keys on).
    #>
    param(
        [Parameter(Mandatory)][datetime]$CollectionTime,
        [Parameter(Mandatory)][string]$EditionMajor,
        [long]$Partition = 0,
        [long]$Partitions = 1,
        [int]$LookbackDays = 3,
        [string]$TableName = 'SI_RiskAnalysis_Detailed_CL',
        [string]$PageFilter = '',
        [switch]$CountOnly
    )
    if ($Partitions -lt 1) { throw 'Get-SIDataFindingsKql: -Partitions must be 1 or more' }
    if ($Partition -lt 0 -or $Partition -ge $Partitions) { throw ('Get-SIDataFindingsKql: -Partition {0} is outside 0..{1}' -f $Partition, ($Partitions - 1)) }
    $part = if ($PageFilter) { $PageFilter } elseif ($Partitions -gt 1) { "| where hash(_pk, $Partitions) == $Partition" } else { '' }
    if ($CountOnly) {
        return @"
$TableName
| where TimeGenerated > ago($($LookbackDays + 1)d)
| where CollectionTime == $(ConvertTo-SIDataKqlTime -Time $CollectionTime)
$(Get-SIDataEditionFilter -EditionMajor $EditionMajor)
| extend _sid = tostring(column_ifexists("SI_AssetId", "")), _lid = tostring(column_ifexists("AssetId", ""))
| extend _aid = iff(isnotempty(_sid), _sid, _lid)
| extend _cfg = tostring(column_ifexists("ConfigurationId", ""))
| extend _pk = strcat(tostring(column_ifexists("_ItemId", "")), "|", _aid, "|", _cfg, "|", tostring(column_ifexists("AssetDetectedInReportName", "")))
$part
| summarize PageRows = count(), KeyMin = min(_pk), KeyMax = max(_pk)
| project PageRows, OneKey = (KeyMin == KeyMax)
"@
    }
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays + 1)d)
| where CollectionTime == $(ConvertTo-SIDataKqlTime -Time $CollectionTime)
$(Get-SIDataEditionFilter -EditionMajor $EditionMajor)
| extend DetailJson = tostring(pack_all(true))
| extend _sid = tostring(column_ifexists("SI_AssetId", "")), _lid = tostring(column_ifexists("AssetId", ""))
| extend _aid = iff(isnotempty(_sid), _sid, _lid)
| extend _cfg = tostring(column_ifexists("ConfigurationId", ""))
| extend _pk = strcat(tostring(column_ifexists("_ItemId", "")), "|", _aid, "|", _cfg, "|", tostring(column_ifexists("AssetDetectedInReportName", "")))
$part
| project
    SI_AssetId      = _aid,
    AssetName       = tostring(column_ifexists("AssetName", "")),
    ReportName      = coalesce(tostring(column_ifexists("AssetDetectedInReportName", "")), tostring(column_ifexists("ReportName", ""))),
    SecurityDomain  = tostring(column_ifexists("SecurityDomain", "")),
    ConfigurationId = _cfg,
    Cve             = iff(_cfg startswith "CVE-", toupper(_cfg), ""),
    Title           = tostring(column_ifexists("ConfigurationName", "")),
    Severity        = tostring(column_ifexists("SecuritySeverity", "")),
    Tier            = toint(tostring(column_ifexists("CriticalityTier", ""))),
    // #297: an attack-path row is keyed to its SOURCE asset, its CriticalityTier is the path's TARGET tier
    SourceTier      = toint(tostring(column_ifexists("SourceCriticalityTier", ""))),
    IsPath          = tostring(column_ifexists("AssetDetectedInReportName", "")) startswith "Attack_Paths" or tostring(column_ifexists("Category", "")) startswith "AttackPath" or tostring(column_ifexists("Category", "")) == "Attack Paths",
    RiskScore       = todouble(tostring(column_ifexists("RiskScoreTotal", ""))),
    ExemptionId     = tostring(column_ifexists("SI_ExemptionId", "")),
    ExemptedUntil   = tostring(column_ifexists("SI_ExemptedUntil", "")),
    ExemptionRequestId = tostring(column_ifexists("SI_ExemptionRequestId", "")),
    DetailJson
"@
}

function Get-SIDataProfileKql {
    <#
        PURE. Each v3 asset's NEWEST profile row in the window (name, tier, when it was last profiled, and WHO SET
        THE TIER: SI_TierSetBy / SI_TierReason / SI_TierClaims, #244). Not "the newest snapshot": low tiers are
        re-profiled weekly, so the newest run holds only part of the estate.
        v3 rows are the ones carrying SI_AssetId (v2.2 emits none) -- filtered BEFORE arg_max (#83).
        The attribution columns go through column_ifexists: a table written before a profiler recorded them reads
        them as empty, and an empty source is shown as "not recorded", never invented.
    #>
    param([Parameter(Mandatory)][string]$TableName, [int]$LookbackDays = 8,
          # #533: also each asset's AccountEnabled on its newest row (the identity column, else an endpoint row's Entra
          # device state in Properties.collect.entra) -- '' = not said. For the connectors that leave disabled assets out.
          [switch]$WithAccountEnabled)
    if ($WithAccountEnabled) {
        return @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend SI_AssetId = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(SI_AssetId)
| extend _en = tostring(column_ifexists("AccountEnabled", ""))
| extend _en = iff(isempty(_en), tostring(todynamic(column_ifexists("Properties", dynamic(null))).collect.entra.AccountEnabled), _en)
| project SI_AssetId, SI_AssetName = tostring(column_ifexists("SI_AssetName", "")), Tier = toint(tostring(column_ifexists("Tier", ""))), CollectionTime,
          SI_TierSetBy = tostring(column_ifexists("SI_TierSetBy", "")), SI_TierReason = tostring(column_ifexists("SI_TierReason", "")),
          SI_TierClaims = tostring(column_ifexists("SI_TierClaims", "")), AccountEnabled = _en
| summarize arg_max(CollectionTime, SI_AssetName, Tier, SI_TierSetBy, SI_TierReason, SI_TierClaims, AccountEnabled) by SI_AssetId
"@
    }
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend SI_AssetId = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(SI_AssetId)
| project SI_AssetId, SI_AssetName = tostring(column_ifexists("SI_AssetName", "")), Tier = toint(tostring(column_ifexists("Tier", ""))), CollectionTime,
          SI_TierSetBy = tostring(column_ifexists("SI_TierSetBy", "")), SI_TierReason = tostring(column_ifexists("SI_TierReason", "")),
          SI_TierClaims = tostring(column_ifexists("SI_TierClaims", ""))
| summarize arg_max(CollectionTime, SI_AssetName, Tier, SI_TierSetBy, SI_TierReason, SI_TierClaims) by SI_AssetId
"@
}

function Get-SIDataObjectMapKql {
    <#
        PURE. The newest correlation map: per SI_AssetId its SI_CorrelationId, whether that id is the ledger's
        (durable) or derived (provisional), and every identifier of the member.
    #>
    param([int]$LookbackDays = 8)
    @"
let src = SI_ObjectMap_CL | where TimeGenerated > ago($($LookbackDays)d);
let snap = toscalar(src | summarize max(CollectionTime));
src
| where CollectionTime == snap
| project SI_AssetId = tostring(column_ifexists("SI_AssetId", "")),
          SI_CorrelationId = tostring(column_ifexists("SI_CorrelationId", "")),
          SI_IdSource = tostring(column_ifexists("SI_IdSource", "")),
          SI_MemberEngine = tostring(column_ifexists("SI_MemberEngine", "")),
          SI_IdentifierType = tostring(column_ifexists("SI_IdentifierType", "")),
          SI_IdentifierValue = tostring(column_ifexists("SI_IdentifierValue", "")),
          SI_IsJoinBasis = tostring(column_ifexists("SI_IsJoinBasis", "")),
          SI_JoinConfidence = tostring(column_ifexists("SI_JoinConfidence", ""))
| where isnotempty(SI_AssetId)
| distinct SI_AssetId, SI_CorrelationId, SI_IdSource, SI_MemberEngine, SI_IdentifierType, SI_IdentifierValue, SI_IsJoinBasis, SI_JoinConfidence
"@
}

function Get-SIDataEvidenceProfileKql {
    <#
        PURE. #299 -- what each source record says about ITSELF, for the correlation evidence: every key it carries with the
        source system that reported it (EntityIds: [{source, type, id}]), the values sources can disagree on (host name,
        OS, domain), when Defender and the Exposure Graph last saw it, and how the CMDB / ServiceNow reconcile matched it.
        The newest row per asset, v3 rows only, filtered BEFORE arg_max (#83). Every column through column_ifexists, so a
        profile table without one (identity has no OS, azure no CMDB columns before reconcile ran) reads it as empty.
        A separate read from Get-SIDataProfileKql on purpose: that one is shared with the SQL CMDB connector, and the
        evidence must never change what it reads.
    #>
    param([Parameter(Mandatory)][string]$TableName, [int]$LookbackDays = 8)
    @"
$TableName
| where TimeGenerated > ago($($LookbackDays)d)
| extend SI_AssetId = tostring(column_ifexists("SI_AssetId", ""))
| where isnotempty(SI_AssetId)
| project SI_AssetId, CollectionTime,
          EntityIds = tostring(column_ifexists("EntityIds", "")),
          Hostname = tostring(column_ifexists("Hostname", "")),
          OsPlatform = tostring(column_ifexists("OsPlatform", "")),
          OnPremDomainName = tostring(column_ifexists("OnPremDomainName", "")),
          OnPremSid = tostring(column_ifexists("OnPremSid", "")),
          OnPremObjectGuid = tostring(column_ifexists("OnPremObjectGuid", "")),
          MdeLastSeen = tostring(column_ifexists("LastSeen", "")),
          EgLastSeen = tostring(column_ifexists("EgLastSeen", "")),
          CmdbId = tostring(column_ifexists("cmdbId", "")),
          CmdbSource = tostring(column_ifexists("CmdbSource", "")),
          CmdbMatchState = tostring(column_ifexists("CmdbMatchState", "")),
          CmdbMatchPhase = tostring(column_ifexists("CmdbMatchPhase", ""))
| summarize arg_max(CollectionTime, EntityIds, Hostname, OsPlatform, OnPremDomainName, OnPremSid, OnPremObjectGuid, MdeLastSeen, EgLastSeen,
                    CmdbId, CmdbSource, CmdbMatchState, CmdbMatchPhase) by SI_AssetId
"@
}

function Get-SIDataAssetPropertiesKql {
    <#
        PURE. The newest SI_AssetProperties_CL snapshot as ONE property bag per asset: { "<source system>": {...} }.
        A row whose payload was replaced by the oversize marker carries no metadata and is left out.
        #301: the bag carries "_siPropertiesAt" (the snapshot's CollectionTime) -- what the SQL retention step
        (SI_AssetProperties_RetentionDays, default 3) prunes the stored copy by.
    #>
    param([int]$LookbackDays = 8)
    # #412: each profiler publishes its own sources with its own CollectionTime -- the newest snapshot PER (profiler,
    # source), not the table's newest CollectionTime (that would be one profiler's only). "snap" = the newest of them.
    @"
let src = SI_AssetProperties_CL | where TimeGenerated > ago($($LookbackDays)d)
| extend _key = strcat(tostring(column_ifexists("Engine", "")), "|", tostring(column_ifexists("SourceSystem", "")));
let snap = toscalar(src | summarize max(CollectionTime));
src
| join kind=inner (src | summarize _snap = max(CollectionTime) by _key) on _key
| where CollectionTime == _snap
| where tobool(column_ifexists("PropertiesDropped", false)) != true
| project SI_AssetId = tostring(column_ifexists("SI_AssetId", "")),
          SourceSystem = tostring(column_ifexists("SourceSystem", "")),
          ItemName = tostring(column_ifexists("ItemName", "")),
          Properties = parse_json(tostring(column_ifexists("Properties", "")))
| where isnotempty(SI_AssetId)
| extend SourceSystem = iff(isempty(SourceSystem), "default", SourceSystem)
| extend BagKey = iff(isempty(ItemName), SourceSystem, strcat(SourceSystem, "/", ItemName))
| summarize Bag = make_bag(bag_pack(BagKey, Properties)) by SI_AssetId
| project SI_AssetId, PropertiesJson = tostring(bag_merge(Bag, bag_pack("_siPropertiesAt", snap)))
"@
}

function Get-SIDataRecommendationsKql {
    <#
        PURE. The Defender for Cloud recommendations in force at -AsOf: the newest SI_AzureRecommendation_CL snapshot
        taken at or before the collection time (so loading an older collection pairs it with its own recommendations).
        A large tenant's snapshot is larger than one query may return, so it is read in pages exactly as the findings
        are (Get-SIDataFindingsKql): -Partitions > 1 = one hash bucket of the rows' own key, -PageFilter = a page the
        reader cut further; -Measure = the snapshot's row count and size (PageRows, PageBytes), what the number of pages
        is planned from; -CountOnly = how many rows one page holds and whether one key is all it holds.
    #>
    param([Parameter(Mandatory)][datetime]$AsOf, [int]$LookbackDays = 8, [long]$Partition = 0, [long]$Partitions = 1, [string]$PageFilter = '', [switch]$Measure, [switch]$CountOnly)
    if ($Partitions -lt 1) { throw 'Get-SIDataRecommendationsKql: -Partitions must be 1 or more' }
    if ($Partition -lt 0 -or $Partition -ge $Partitions) { throw ('Get-SIDataRecommendationsKql: -Partition {0} is outside 0..{1}' -f $Partition, ($Partitions - 1)) }
    $part = if ($PageFilter) { $PageFilter } elseif ($Partitions -gt 1) { "| where hash(_pk, $Partitions) == $Partition" } else { '' }
    $head = @"
let src = SI_AzureRecommendation_CL
    | where TimeGenerated > ago($($LookbackDays)d)
    | where CollectionTime <= $(ConvertTo-SIDataKqlTime -Time $AsOf);
let snap = toscalar(src | summarize max(CollectionTime));
src
| where CollectionTime == snap
"@
    $key = '| extend _pk = strcat(tostring(column_ifexists("_ItemId", "")), "|", tolower(tostring(column_ifexists("ResourceId", ""))), "|", tostring(column_ifexists("AssessmentKey", "")))'
    if ($Measure) {
        return @"
$head
| summarize PageRows = count(), PageBytes = sum(estimate_data_size(*))
"@
    }
    if ($CountOnly) {
        return @"
$head
$key
$part
| summarize PageRows = count(), KeyMin = min(_pk), KeyMax = max(_pk)
| project PageRows, OneKey = (KeyMin == KeyMax)
"@
    }
    @"
$head
| extend DetailJson = tostring(pack_all(true))
$key
$part
| project ResourceId = tolower(tostring(column_ifexists("ResourceId", ""))),
          RecommendationId = tostring(column_ifexists("AssessmentKey", "")),
          Name = tostring(column_ifexists("Recommendation", "")),
          Severity = tostring(column_ifexists("Severity", "")),
          DetailJson
"@
}

# The run-health read and the completeness verdict are the close-loop's own (engine\asset-cmdb\_shared\SI-VulnDesired.ps1:
# Get-SIVulnRunHealthKql, Test-SIVulnSnapshotComplete) -- loaded, not copied, so "complete" means one thing in Pro.
