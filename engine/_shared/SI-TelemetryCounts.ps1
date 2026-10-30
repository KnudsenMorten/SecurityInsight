#Requires -Version 5.1
<#
    SecurityInsight -- the TENANT COUNTS on the daily heartbeat (#424, owner 2026-10-07: "we need a counter in the telemetry
    by tenant from both pro, users for stat purpose"). Invardia stores Counts per environment (= per tenant); PIM sends
    the same three keys with the same definitions, so the two products can be added up and compared.

    THE DEFINITIONS (identical in PIM -- change them in both products or in neither; the one exception is users' AD part):
      users    ENABLED MEMBER users, CLOUD AND ON-PREM AD (owner 2026-10-10: "users include both cloud and ad local",
               "from exposuregraph"), each real person once:
                 Entra part   Entra user objects with accountEnabled = true AND userType = Member (cloud-only AND
                              AD-synced users -- a synced user is one Entra object);
                 + AD part    AD-ONLY enabled user accounts from the Exposure Graph: 'user' nodes with rawData
                              primaryProvider = ActiveDirectory AND identityType = User (AD service accounts and
                              computers are NOT users) AND enabled (rawData accountEnabled, else isEnabled -- the two
                              names SI's EG mapping reads for si_account_enabled -- else isActive when EG carries
                              neither), whose adSid is NOT the OnPremSid of ANY Entra user in the latest identity
                              collection (a synced user is already in the Entra part and counts once).
               The AD part runs through Advanced Hunting (Invoke-SIHuntingQueryRest, the run's Graph token). When it
               cannot be read (no permission, no Defender, an error, a truncated answer) users = the Entra part only and
               the run log says so once, plainly -- never a guessed number, never 0 for the AD part. No Entra part = no
               users key at all (the AD part is never sent alone). PIM's users is Entra-only; SI's adds AD-only accounts
               because SI sees AD through the Exposure Graph.
      guests   GUEST users: Entra user objects with userType = Guest, ENABLED OR NOT (a disabled guest is still a guest
               object in the tenant; the stat is "how many guests does this tenant carry").
      devices  the 7-DAY MAXIMUM of the daily count of unique CORRELATED devices: endpoints and servers (Defender machines
               and Entra devices), ONE per real machine however many sources see it (the correlation object id, so a
               machine seen by Defender and by Entra counts once). IoT and network devices are not devices here. Per UTC
               day the latest correlation run of that day is counted; the heartbeat carries the highest of the last 7
               days. This is also the unit of the future Pro Business device cap -- Get-SIDeviceCount is the one place
               it is computed.

    WHERE THE NUMBERS COME FROM: only what SecurityInsight already reads -- no new permission.
      users / guests  the latest collection in SI_Identity_Profile_CL (AccountEnabled, UserType, IdentityType = User,
                      OnPremSid); users' AD part from ExposureGraphNodes over Advanced Hunting -- the same read the
                      identity engine's Exposure Graph discovery already makes with the same Graph identity
      devices         SI_ObjectMap_CL (the correlation map: SI_CorrelationId per endpoint member), with the device
                      category from SI_Endpoint_Profile_CL

    A COUNT THAT CANNOT BE COMPUTED IS OMITTED, never sent as 0 by guess: no table, no rows, a failed query, no UserType
    column filled at all, no correlation run in the last 7 days -- each leaves its key out.

    PRO ONLY: Send-SITelemetryRunEnd asks for these counts only for an IDENTIFIED heartbeat (a Pro / trial install with
    its install key). Community and an anonymous Pro install send nothing new. Telemetry switched off computes nothing.

    PS 5.1 and 7. Never throws to its caller.
#>

function Get-SITelemetryCountNamesState {
    <# The value of $script:SITelemetryCountNames, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SITelemetryCountNames) { $script:SITelemetryCountNames = @('users', 'guests', 'devices', 'sqlUsedMb', 'sqlMaxMb', 'servicePrincipals', 'azureResources', 'servers', 'clientDevices',
    # #719 (owner 2026-10-16 via Invardia: "add relevant. i want data") -- the Risk Analysis result and the CI estate, from the
    # Pro database (Get-SIRaTelemetryCounts; each key's definition in data-model/telemetry-counts.locked.json)
    'raReportsTotal', 'raReportsComplete', 'raRowsDetailed', 'cveDevicePairs', 'cveDevices', 'cves', 'cvesCritical', 'cvesHigh',
    # owner 2026-10-16 ("Yes, change the report"): the distinct CVE ids with a known exploit, from the CVE Summary rows
    'cvesExploited',
    'recommendations', 'recommendationDevicePairs', 'eosSoftwareDevices', 'azureRecommendations', 'attackPaths', 'usersWithoutMfa',
    'staleUsers180d', 'privilegedPermanent', 'guestsPrivileged', 'spnsExpiringCredentials', 'cis', 'cisTier0',
    # owner 2026-10-16 ("Add, permission REQUIRED"): Microsoft Secure Score and the Defender exposure score (Get-SISecurityScoreCounts)
    'secureScore', 'secureScoreMax', 'exposureScore',
    # owner 2026-10-13 ("si must send objects for each of the security domains"; Invardia's adoption dashboard): the current
    # CIs per security domain and the close-loop's real remediations -- same read (Get-SIRaTelemetryCountSql)
    'domainEndpoint', 'domainIdentity', 'domainAzure', 'domainPublicIp', 'fixedLast30Days') }
    , $script:SITelemetryCountNames
}
$script:SITelemetryCountNames = $null; $null = Get-SITelemetryCountNamesState

# #719: Invardia refuses the WHOLE record above 40 Counts keys; SI stays at or under 38 (two spare), every value a whole number
# >= 0. The framework client (AitUplink.ps1, byte-identical to sync/) keeps the first 40 keys by name (it kept 10 before
# main's 2026-10-13 copy) -- SI still shapes the heartbeat's Counts itself, by priority, at most 38
# (ConvertTo-SITelemetryCountsWire, called by ConvertTo-SITelemetryWire) -- the safe path.
function Get-SITelemetryCountMaxKeysState {
    <# The value of $script:SITelemetryCountMaxKeys, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SITelemetryCountMaxKeys) { $script:SITelemetryCountMaxKeys = 38 }
    , $script:SITelemetryCountMaxKeys
}
$script:SITelemetryCountMaxKeys = $null; $null = Get-SITelemetryCountMaxKeysState

<#
    THE ASSET INVENTORY (owner 2026-10-10, via Invardia: "updated numbers both total and per customer and per tenant of
    users, spns, azure objects, servers, client devices"), each from the LATEST collection of its profile table:
      servicePrincipals  service principals + managed identities (SI_Identity_Profile_CL, IdentityType)
      azureResources     distinct Azure resources in the scopes SI covers (SI_Azure_Profile_CL, AzureResourceId)
      servers            endpoints whose DeviceType is Server or whose OS is a server OS (SI_Endpoint_Profile_CL)
      clientDevices      workstations / mobile devices (DeviceType or a client OS); IoT, network devices and unknown
                         devices are neither
    The OS is the profile's column OsPlatform (the name the endpoint profile writes; column names are case-sensitive in
    KQL), OSPlatform only as a fallback: reading only 'OSPlatform' made the OS fallback dead, so an endpoint collection
    whose rows carried no DeviceType counted 0 servers and 0 clients (a large school 2026-10-18 / 10-19: "servers fell to
    0", "client devices fell to 0" while 1,977 devices were profiled).
    A table with no collection in the last 8 days leaves its keys OUT (never a guessed 0).
#>
function Get-SIInventoryCountQuery {
    # #712 (Invardia watcher 2026-10-16, customer C: clientDevices 26 -> 618, servers 0 -> 23 between two heartbeats
    # while the collection itself was identical): the NEWEST collection was counted while Log Analytics was still taking it
    # in (rows arrive over 10-20 minutes). Only a collection whose rows stopped arriving 30 minutes ago is counted; a newer
    # one still arriving waits for the next heartbeat, the one before it is counted meanwhile.
    # A collection IN PARTS publishes part by part under one collection time, its parts' rows minutes or hours apart: a
    # quiet half hour between two parts is not its end. So where the install's database says when each source last
    # collected COMPLETELY (sidata.SourceState, Get-SICountCompleteBy), a newer collection is never counted.
    param([System.Collections.IDictionary]$CompleteBy = (Get-SICountCompleteByState))
    $q = @'
let idt = SI_Identity_Profile_CL | where TimeGenerated > ago(8d);
let idl = toscalar(idt{{IDB}} | summarize _in = max(ingestion_time()) by CollectionTime | where _in < ago(30m) | summarize max(CollectionTime));
let azt = SI_Azure_Profile_CL | where TimeGenerated > ago(8d);
let azl = toscalar(azt{{AZB}} | summarize _in = max(ingestion_time()) by CollectionTime | where _in < ago(30m) | summarize max(CollectionTime));
let ept = SI_Endpoint_Profile_CL | where TimeGenerated > ago(8d);
let epl = toscalar(ept{{EPB}} | summarize _in = max(ingestion_time()) by CollectionTime | where _in < ago(30m) | summarize max(CollectionTime));
union isfuzzy=true
 (idt | where CollectionTime == idl | extend _id = tostring(column_ifexists("SI_AssetId", "")), _t = tostring(column_ifexists("IdentityType", ""))
      | where isnotempty(_id) | summarize Spns = dcountif(_id, _t in~ ("ServicePrincipal", "ManagedIdentity")), IdRows = count()),
 (azt | where CollectionTime == azl | extend _r = tolower(tostring(column_ifexists("AzureResourceId", "")))
      | summarize Azure = dcountif(_r, isnotempty(_r)), AzRows = count()),
 (ept | where CollectionTime == epl | extend _a = tostring(column_ifexists("SI_AssetId", "")), _c = tolower(tostring(column_ifexists("DeviceCategory", ""))),
        _d = tolower(tostring(column_ifexists("DeviceType", ""))), _o = tolower(coalesce(tostring(column_ifexists("OsPlatform", "")), tostring(column_ifexists("OSPlatform", ""))))
      | where isnotempty(_a) | summarize arg_max(CollectionTime, _c, _d, _o) by _a
      | extend _srv = (_d == "server" or _o contains "server")
      | extend _cli = (not(_srv) and not(_c in ("iot", "networkdevice")) and (_d in ("workstation", "mobile", "tablet", "smartphone") or _o matches regex @"^(windows(10|11)?|macos.*|ios|ipados|android)$"))
      | summarize Servers = countif(_srv), Clients = countif(_cli), EpRows = count())
| summarize Spns = max(Spns), IdRows = max(IdRows), Azure = max(Azure), AzRows = max(AzRows), Servers = max(Servers), Clients = max(Clients), EpRows = max(EpRows)
'@
    $q.Replace('{{IDB}}', (Get-SICountCompleteFilter -Source identity -CompleteBy $CompleteBy)).Replace('{{AZB}}', (Get-SICountCompleteFilter -Source azure -CompleteBy $CompleteBy)).Replace('{{EPB}}', (Get-SICountCompleteFilter -Source endpoint -CompleteBy $CompleteBy))
}

# source -> when it last collected completely, for the counts of ONE heartbeat (Get-SITelemetryHeartbeatCounts sets it)
function Get-SICountCompleteByState {
    <# The value of $script:SICountCompleteBy, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SICountCompleteBy) { $script:SICountCompleteBy = @{} }
    , $script:SICountCompleteBy
}
$script:SICountCompleteBy = $null; $null = Get-SICountCompleteByState

function Get-SICountCompleteFilter {
    <# PURE. The KQL filter that keeps a source's counts off a collection newer than its last COMPLETE one:
       ' | where CollectionTime <= datetime(<last complete + 10 minutes>)' (the minutes absorb the difference between the
       database's and Log Analytics' stamp of one collection; the next collection starts hours later). '' when not known.
       A source the database knows but that has NEVER collected completely ('never', Get-SICountCompleteBy): no collection
       of it is counted ('| where false') -- its keys are left out until its first complete collection, never a part's
       number (a large install 2026-10-19: identity never ended well, so the heartbeat counted a part -- 6,827 users,
       115 service principals -- for two days, then the real 107,441 / 1,604 arrived as a "3x jump"). #>
    param([Parameter(Mandatory)][string]$Source, [System.Collections.IDictionary]$CompleteBy)
    if (-not $CompleteBy -or -not $CompleteBy.Contains($Source) -or $null -eq $CompleteBy[$Source]) { return '' }
    if ($CompleteBy[$Source] -is [string] -and [string]$CompleteBy[$Source] -eq 'never') { return ' | where false' }
    $t = $null; try { $t = ([datetime]$CompleteBy[$Source]).ToUniversalTime().AddMinutes(10) } catch { return '' }
    ' | where todatetime(CollectionTime) <= datetime({0})' -f $t.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SICountCompleteSql {
    <# READS ONLY. When each collecting source last collected COMPLETELY (sidata.SourceState.LastGoodAt, written by the
       pipeline when a collection -- every part of it -- ended well). No table = no rows. #>
    "IF OBJECT_ID(N'sidata.SourceState') IS NULL SELECT CAST(NULL AS NVARCHAR(32)) AS Source, CAST(NULL AS DATETIME2(3)) AS LastGoodAt WHERE 1 = 0; ELSE SELECT Source, LastGoodAt FROM sidata.SourceState WHERE Source IN (N'identity', N'azure', N'endpoint');"
}

function Get-SICountCompleteBy {
    <# source -> when it last collected completely (UTC), from Get-SICountCompleteSql through -SqlRows { param($Sql) rows }
       (default Invoke-SITelemetrySqlRows). A source with a row but no LastGoodAt has never collected completely: 'never'
       (Get-SICountCompleteFilter counts none of its collections). A source without a row is not known: absent (the
       settled rule alone). Empty when it cannot be read: the counts then use the settled rule alone, as before. Never
       throws. #>
    param([scriptblock]$SqlRows)
    $out = @{}
    try {
        if (-not $SqlRows) { $SqlRows = { param($Sql) Invoke-SITelemetrySqlRows -Sql $Sql } }
        foreach ($r in @(& $SqlRows (Get-SICountCompleteSql))) {
            if ($null -eq $r) { continue }
            $src = ''; $at = $null
            if ($r -is [System.Collections.IDictionary]) { $src = [string]$r['Source']; $at = $r['LastGoodAt'] } else { $src = [string]$r.Source; $at = $r.LastGoodAt }
            $src = $src.Trim().ToLowerInvariant()
            if (-not $src) { continue }
            if ($null -eq $at -or $at -is [System.DBNull] -or "$at".Trim() -eq '') { $out[$src] = 'never'; continue }
            $t = $null
            if ($at -is [datetime]) { $t = [datetime]::SpecifyKind($at, [DateTimeKind]::Utc) }
            else {
                $p = [datetime]::MinValue
                if ([datetime]::TryParse([string]$at, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal), [ref]$p)) { $t = $p }
            }
            if ($null -ne $t) { $out[$src] = $t }
        }
    } catch { return @{} }
    $out
}

function Get-SIInventoryCounts {
    <# PURE. The inventory query's one row -> the keys whose table HAD a collection (its row count > 0). #>
    param([AllowNull()]$Row)
    $out = [ordered]@{}
    if ($null -eq $Row) { return $out }
    $has = { param($n) $v = ConvertTo-SITelemetryCount $Row.$n; $null -ne $v -and $v -gt 0 }
    if (& $has 'IdRows') { $v = ConvertTo-SITelemetryCount $Row.Spns; if ($null -ne $v) { $out['servicePrincipals'] = $v } }
    if (& $has 'AzRows') { $v = ConvertTo-SITelemetryCount $Row.Azure; if ($null -ne $v) { $out['azureResources'] = $v } }
    if (& $has 'EpRows') {
        $v = ConvertTo-SITelemetryCount $Row.Servers; if ($null -ne $v) { $out['servers'] = $v }
        $v = ConvertTo-SITelemetryCount $Row.Clients; if ($null -ne $v) { $out['clientDevices'] = $v }
    }
    $out
}

function Get-SITelemetryHeartbeatCountNames { (Get-SITelemetryCountNamesState) }

function Get-SITelemetryCountMaxKeys { (Get-SITelemetryCountMaxKeysState) }

function ConvertTo-SITelemetryCountsWire {
    <#
        PURE. The heartbeat's Counts as they go on the wire (#719): only the agreed names, each key ^[a-z][A-Za-z0-9]{0,30}$,
        each value a whole number >= 0 ([long]), at most 38 keys (the agreed order). $null when nothing is left.
    #>
    param([AllowNull()][System.Collections.IDictionary]$Counts)
    if ($null -eq $Counts -or $Counts.Count -eq 0) { return $null }
    $o = [ordered]@{}
    foreach ($k in (Get-SITelemetryCountNamesState)) {
        if ($o.Count -ge (Get-SITelemetryCountMaxKeysState)) { break }
        if ($k -cnotmatch '^[a-z][A-Za-z0-9]{0,30}$' -or -not $Counts.Contains($k)) { continue }
        $v = ConvertTo-SITelemetryCount $Counts[$k]
        if ($null -ne $v) { $o[$k] = [long]$v }
    }
    if ($o.Count -eq 0) { return $null }
    [pscustomobject]$o
}

<#
    THE RISK ANALYSIS RESULT AND THE CI ESTATE (#719, owner 2026-10-16: "add relevant. i want data"; the names agreed with
    Invardia). Read from the Pro database in ONE batch (Get-SIRaTelemetryCountSql), each key from the LATEST COMPLETE
    Detailed collection (sidata.Collection Kind 'Detailed' Status 'Complete'), and only when ITS report's verdict there
    (sidata.RaReportStatus) is Complete. A report that is not Complete leaves its key OUT, never 0.
    #636 (owner 2026-10-19: "i prefer to switch so detailed becomes the engine default and summary is optional"): the counts
    came from the Summary report's rows (sidata.SummaryRow / SummaryAsset); the Summary step is now off by default, so every
    count comes from the DETAILED findings -- through the stored groupings the data sync writes per collection
    (sidata.SummaryGroup, grouping 'report': per report its distinct assets, distinct recommendations / CVEs, of them Very High
    / High / with a known exploit -- engine\_shared\SI-SummaryGroupings.ps1). #871 (found 2026-10-21: five installs whose
    run stopped before the data sync sent no grouped keys for a day, and the dashboard's users without MFA fell from 22,136
    to 3,444): those keys come from the NEWEST complete collection that HAS its groupings, decided by that collection's own
    verdicts; its date goes out as Security.collectionUtc and the heartbeat's Warnings say si-data-1402 while the newest
    collection is not grouped yet (SI-HeartbeatFields.ps1). Only an install that has never grouped a collection leaves them
    out. Cheap by design: sidata.RaReportStatus (one row per report), the 'report' grouping of ONE
    collection (by its index) and sidata.Ci. sidata.Finding is NEVER read (30 GB at a large install).
    The definitions -- one line each -- are in data-model/telemetry-counts.locked.json (handed to Invardia with the release).
    Every "how many assets" key counts the DISTINCT assets of the report's findings; every "how many recommendations / CVEs"
    key the distinct configuration ids.
    THE SECURITY DOMAINS (owner 2026-10-13: "si must send objects for each of the security domains"; built 2026-10-13 on
    si-v3-scale/telemetry-counts-from-sql, ported onto rc11): the CURRENT CIs (not retired, as cis) of each class -- the
    web app's domain of a CI is its class (device = Endpoint, identity = Identity, cloud_resource = Azure, public_ip =
    PublicIP). Sent once sidata.Ci holds any CI (as cis); a domain without a CI is then a real 0.
      domainEndpoint / domainIdentity / domainAzure / domainPublicIp
    THE CLOSE-LOOP'S REAL REMEDIATIONS (the 2026-10-13 adoption numbers, Invardia's adoption dashboard):
      fixedLast30Days  vuln.VulnerabilityItem items CLOSED in the last 30 days with reason Remediated (the reason's first
                       word -- never AssetRetired / NoLongerMonitored / an engineer's other reason). Read on the Pro database
                       through IX_VulnerabilityItem_UpdatedAt (a close sets UpdatedAt); left out when the close-loop holds
                       no item there (not in use, or its own database elsewhere).
    The other 2026-10-13 adoption numbers are covered here already or by the heartbeat's own fields: assetsProfiled = cis;
    findingsOpen / Critical / High = Security.domains[].findings / findingsCritical / findingsHigh (the Detailed findings'
    domain grouping -- sidata.Finding is never read); vulnerabilitiesOpen = cves + recommendations + azureRecommendations;
    dataSources = Sources.
#>
function Get-SIRaCountAssetReportsState {
    <# The value of $script:SIRaCountAssetReports, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIRaCountAssetReports) { $script:SIRaCountAssetReports = [ordered]@{
    cveDevices              = 'Device_Missing_CVEs_Detailed'
    eosSoftwareDevices      = 'Device_EndOfSupport_Software_Detailed'
    usersWithoutMfa         = 'Identity_NoMFA_Detailed'
    staleUsers180d          = 'Identity_StaleUser_NoLogin180Days_Detailed'
    privilegedPermanent     = 'Identity_PermanentPrivilegedRole_Detailed'
    guestsPrivileged        = 'Identity_GuestWithPrivilegedRole_Detailed'
    spnsExpiringCredentials = 'Identity_SPN_ExpiringCredentials_Detailed'
} }
    , $script:SIRaCountAssetReports
}
$script:SIRaCountAssetReports = $null; $null = Get-SIRaCountAssetReportsState
# the distinct recommendations / CVEs of a report (the 'report' grouping's Recommendations and its Very High / High / exploited twins)
function Get-SIRaCountRecommendationReportsState {
    <# The value of $script:SIRaCountRecommendationReports, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIRaCountRecommendationReports) { $script:SIRaCountRecommendationReports = [ordered]@{
    cves                 = @('Device_Missing_CVEs_Detailed', 'recs')
    cvesCritical         = @('Device_Missing_CVEs_Detailed', 'recsCritical')
    cvesHigh             = @('Device_Missing_CVEs_Detailed', 'recsHigh')
    cvesExploited        = @('Device_Missing_CVEs_Detailed', 'recsExploited')
    recommendations      = @('Device_Recommendations_Detailed', 'recs')
    azureRecommendations = @('Azure_DefenderRecommendations_Detailed', 'recs')
} }
    , $script:SIRaCountRecommendationReports
}
$script:SIRaCountRecommendationReports = $null; $null = Get-SIRaCountRecommendationReportsState
# sidata.Ci Class -> the Counts key of its security domain (the web app: device = Endpoint, identity = Identity,
# cloud_resource = Azure, public_ip = PublicIP)
function Get-SITelemetryDomainKeysState {
    <# The value of $script:SITelemetryDomainKeys, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SITelemetryDomainKeys) { $script:SITelemetryDomainKeys = [ordered]@{ device = 'domainEndpoint'; identity = 'domainIdentity'; cloud_resource = 'domainAzure'; public_ip = 'domainPublicIp' } }
    , $script:SITelemetryDomainKeys
}
$script:SITelemetryDomainKeys = $null; $null = Get-SITelemetryDomainKeysState
function Get-SIRaCountDetailedPairsState {
    <# The value of $script:SIRaCountDetailedPairs, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SIRaCountDetailedPairs) { $script:SIRaCountDetailedPairs = [ordered]@{
    cveDevicePairs            = 'Device_Missing_CVEs_Detailed'
    recommendationDevicePairs = 'Device_Recommendations_Detailed'
} }
    , $script:SIRaCountDetailedPairs
}
$script:SIRaCountDetailedPairs = $null; $null = Get-SIRaCountDetailedPairsState

function Get-SIRaTelemetryCountSql {
    <#
        The one read: a result set of (K, R, G, S, N) rows --
          status       R = report, G = grain, S = verdict, N = StoredRows   (sidata.RaReportStatus, the latest Detailed collection)
          assets / recs / recsCritical / recsHigh / recsExploited
                       R = report, N = its distinct assets / distinct recommendations (configuration ids) / of them Very High /
                       High / with a known exploit -- the 'report' grouping of the Detailed findings (sidata.SummaryGroup)
                       of the newest complete collection whose groupings are written (sidata.SummaryGroupState, #871)
          groupedOlder N = 1 when that collection is OLDER than the newest complete one
          gstatus      as status, for that older collection (its verdicts decide its grouped figures)
          cis / cisTier0                    N = current CIs (not retired) / of them tier 0   (sidata.Ci)
          domain       R = class (device / identity / cloud_resource / public_ip), N = current CIs of that class (sidata.Ci)
          vulnItems    N = 1 when the close-loop holds any item (vuln.VulnerabilityItem), else 0
          fixedLast30Days                   N = close-loop items closed Remediated in the last 30 days
        Every part guarded: a database without a table / column answers without that part.
    #>
@"
SET NOCOUNT ON;
DECLARE @o TABLE (K nvarchar(32) NOT NULL, R nvarchar(256) NULL, G nvarchar(16) NULL, S nvarchar(16) NULL, N bigint NULL);
DECLARE @dt datetime2(3), @dc int, @gt datetime2(3), @gc int;
IF OBJECT_ID(N'sidata.Collection') IS NOT NULL
    SELECT TOP (1) @dt = CollectionTime, @dc = CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC;
IF OBJECT_ID(N'sidata.RaReportStatus') IS NOT NULL AND @dt IS NOT NULL
    INSERT @o (K, R, G, S, N)
    SELECT N'status', ReportName, Grain, State, StoredRows FROM sidata.RaReportStatus
    WHERE Grain = N'Detailed' AND CollectionTime = @dt;
-- #871: the grouped figures come from the NEWEST complete collection that HAS its groupings -- a run that stopped before the
-- data sync never drops them; that collection's own verdicts decide them (gstatus) when it is not the newest
IF @dc IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroupState') IS NOT NULL
    EXEC sp_executesql N'SELECT TOP (1) @gt = c.CollectionTime, @gc = c.CollectionId FROM sidata.Collection AS c
WHERE c.Kind = N''Detailed'' AND c.Status = N''Complete'' AND EXISTS (SELECT 1 FROM sidata.SummaryGroupState AS s WHERE s.CollectionId = c.CollectionId)
ORDER BY c.CollectionTime DESC;', N'@gt datetime2(3) OUTPUT, @gc int OUTPUT', @gt = @gt OUTPUT, @gc = @gc OUTPUT;
IF @gc IS NOT NULL AND @gc <> @dc
BEGIN
    INSERT @o (K, N) VALUES (N'groupedOlder', 1);
    IF OBJECT_ID(N'sidata.RaReportStatus') IS NOT NULL
        INSERT @o (K, R, G, S, N)
        SELECT N'gstatus', ReportName, Grain, State, StoredRows FROM sidata.RaReportStatus
        WHERE Grain = N'Detailed' AND CollectionTime = @gt;
END
IF @gc IS NOT NULL
    INSERT @o (K, R, N)
    EXEC sp_executesql N'
IF EXISTS (SELECT 1 FROM sidata.SummaryGroupState WHERE CollectionId = @dc)
SELECT N''grouped'', CONVERT(nvarchar(256), NULL), CONVERT(bigint, 1)
UNION ALL
SELECT x.K, g.Key1, x.N
FROM sidata.SummaryGroup AS g
CROSS APPLY (VALUES (N''assets'', CONVERT(bigint, g.Assets)), (N''recs'', CONVERT(bigint, g.Recommendations)), (N''recsCritical'', CONVERT(bigint, g.CriticalRecommendations)),
                    (N''recsHigh'', CONVERT(bigint, g.HighRecommendations)), (N''recsExploited'', CONVERT(bigint, g.ExploitedRecommendations))) AS x(K, N)
WHERE g.CollectionId = @dc AND g.GroupingId = ''report'';', N'@dc int', @dc = @gc;
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL
    INSERT @o (K, N)
    SELECT N'cis', COUNT_BIG(*) FROM sidata.Ci WHERE ISNULL(Lifecycle, N'') <> N'retired'
    UNION ALL
    SELECT N'cisTier0', COUNT_BIG(*) FROM sidata.Ci WHERE Tier = 0 AND ISNULL(Lifecycle, N'') <> N'retired';
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL AND COL_LENGTH(N'sidata.Ci', N'Class') IS NOT NULL
    INSERT @o (K, R, N)
    EXEC sp_executesql N'SELECT N''domain'', Class, COUNT_BIG(*) FROM sidata.Ci
WHERE ISNULL(Lifecycle, N'''') <> N''retired'' AND Class IN (N''device'', N''identity'', N''cloud_resource'', N''public_ip'')
GROUP BY Class;';
IF OBJECT_ID(N'vuln.VulnerabilityItem') IS NOT NULL
    INSERT @o (K, N)
    SELECT N'vulnItems', CASE WHEN EXISTS (SELECT 1 FROM vuln.VulnerabilityItem) THEN 1 ELSE 0 END
    UNION ALL
    SELECT N'fixedLast30Days', COUNT_BIG(*) FROM vuln.VulnerabilityItem
    WHERE UpdatedAt >= DATEADD(day, -30, SYSUTCDATETIME()) AND State = N'Closed' AND ClosedAt >= DATEADD(day, -30, SYSUTCDATETIME())
      AND LEFT(ISNULL(CloseReason, N''), CHARINDEX(N':', ISNULL(CloseReason, N'') + N':') - 1) = N'Remediated';
SELECT K, R, G, S, N FROM @o;
"@
}


function ConvertFrom-SIRaTelemetryCountRows {
    <#
        PURE. The read's rows (K, R, G, S, N) -> the #719 keys that are KNOWN: a key whose report is not Complete in the
        latest complete collection of its grain, or whose number is missing, is left out (never 0 by guess).
    #>
    param([AllowNull()][object[]]$Rows)
    $out = [ordered]@{}
    $status = @{}; $gstatus = @{}; $agg = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string]$r.K
        if ($k -eq 'status') { $status[('{0}|{1}' -f $r.G, $r.R)] = @{ S = [string]$r.S; N = (ConvertTo-SITelemetryCount $r.N) } }
        elseif ($k -eq 'gstatus') { $gstatus[('{0}|{1}' -f $r.G, $r.R)] = @{ S = [string]$r.S; N = (ConvertTo-SITelemetryCount $r.N) } }
        elseif ($k) { $agg[('{0}|{1}' -f $k, [string]$r.R)] = ConvertTo-SITelemetryCount $r.N }
    }
    $done = { param($g, $n) $x = $status["$g|$n"]; ($null -ne $x -and $x.S -eq 'Complete') }
    # #871: the grouped figures are decided by the verdicts of the collection they come from -- an OLDER one when the newest
    # complete collection has no groupings yet (a run that stopped before the data sync); its date rides Security.collectionUtc
    $older = ($null -ne $agg['groupedOlder|'] -and $agg['groupedOlder|'] -gt 0)
    $gv = $status; if ($older) { $gv = $gstatus }
    $gdone = { param($g, $n) $x = $gv["$g|$n"]; ($null -ne $x -and $x.S -eq 'Complete') }
    if ($status.Count) {
        $out['raReportsTotal'] = [long]$status.Count
        $out['raReportsComplete'] = [long]@($status.Values | Where-Object { $_.S -eq 'Complete' }).Count
        $det = @($status.Keys | Where-Object { $_ -like 'Detailed|*' } | ForEach-Object { $status[$_].N } | Where-Object { $null -ne $_ })
        if ($det.Count) { $s = [long]0; foreach ($v in $det) { $s += [long]$v }; $out['raRowsDetailed'] = $s }
    }
    foreach ($key in (Get-SIRaCountDetailedPairsState).Keys) {
        $rn = (Get-SIRaCountDetailedPairsState)[$key]
        if ((& $done 'Detailed' $rn) -and $null -ne $status["Detailed|$rn"].N) { $out[$key] = [long]$status["Detailed|$rn"].N }
    }
    # #636: the distinct assets / CVEs / recommendations of a Complete report, from the Detailed findings' 'report' grouping; a
    # report without a group row (no finding) is a real 0 once the collection's groupings were read
    $grouped = [bool](@($agg.Keys | Where-Object { $_ -like 'recs|*' -or $_ -like 'assets|*' -or $_ -eq 'grouped|' }).Count)
    foreach ($key in (Get-SIRaCountAssetReportsState).Keys) {
        $rn = (Get-SIRaCountAssetReportsState)[$key]
        if (-not (& $gdone 'Detailed' $rn)) { continue }
        if ($agg.ContainsKey("assets|$rn") -and $null -ne $agg["assets|$rn"]) { $out[$key] = [long]$agg["assets|$rn"] }
        elseif ($grouped) { $out[$key] = [long]0 }
    }
    foreach ($key in (Get-SIRaCountRecommendationReportsState).Keys) {
        $rn = (Get-SIRaCountRecommendationReportsState)[$key][0]; $k = (Get-SIRaCountRecommendationReportsState)[$key][1]
        if (-not (& $gdone 'Detailed' $rn)) { continue }
        if ($agg.ContainsKey("$k|$rn") -and $null -ne $agg["$k|$rn"]) { $out[$key] = [long]$agg["$k|$rn"] }
        elseif ($grouped) { $out[$key] = [long]0 }
    }
    # attack paths: every Attack_Paths_Detailed_* report of the run Complete, each with its stored rows (the path findings)
    $ap = @($status.Keys | Where-Object { $_ -like 'Detailed|Attack_Paths_Detailed_*' })
    if ($ap.Count -and -not @($ap | Where-Object { $status[$_].S -ne 'Complete' -or $null -eq $status[$_].N }).Count) {
        $s = [long]0; foreach ($x in $ap) { $s += [long]$status[$x].N }; $out['attackPaths'] = $s
    }
    # the CI estate: a database without any CI yet has nothing to say (no key, not 0)
    if ($null -ne $agg['cis|'] -and $agg['cis|'] -gt 0) {
        $out['cis'] = [long]$agg['cis|']
        if ($null -ne $agg['cisTier0|']) { $out['cisTier0'] = [long]$agg['cisTier0|'] }
        # the security domains: once the class was read at all (a domain row came back), a domain without a CI is a real 0
        if (@($agg.Keys | Where-Object { $_ -like 'domain|*' }).Count) {
            foreach ($d in (Get-SITelemetryDomainKeysState).Keys) {
                $v = $agg["domain|$d"]
                $out[(Get-SITelemetryDomainKeysState)[$d]] = $(if ($null -ne $v) { [long]$v } else { [long]0 })
            }
        }
    }
    # the close-loop's real remediations: only where the close-loop holds items (none = not in use here: no key)
    if ($null -ne $agg['vulnItems|'] -and $agg['vulnItems|'] -gt 0 -and $null -ne $agg['fixedLast30Days|']) {
        $out['fixedLast30Days'] = [long]$agg['fixedLast30Days|']
    }
    $out
}

function Invoke-SITelemetrySqlRows {
    <#
        One read on the install's Pro database (SI_ProSqlServer / SI_ProSqlDatabase) as the job, closed after; the rows as
        objects. $null when no database is configured or this is a test session (never a connection there). Throws on a
        failed read (the caller leaves the keys out).
    #>
    param([Parameter(Mandatory)][string]$Sql, [string]$Server = [string]$global:SI_ProSqlServer, [string]$Database = [string]$global:SI_ProSqlDatabase)
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { return $null }
    if (Get-Module -Name Pester) { return $null }
    if (-not (Get-Command -Name Get-SIObjectLedgerConnection -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'identity', 'SI-ObjectLedgerStore.ps1'))
    }
    $cn = Get-SIObjectLedgerConnection -Server $Server -Database $Database -MaxAttempts 2
    if (-not $cn) { return $null }
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $cmd = $cn.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 0
        $rd = $cmd.ExecuteReader()
        try {
            while ($rd.Read()) {
                $o = [ordered]@{}
                for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }
                $rows.Add([pscustomobject]$o)
            }
        } finally { $rd.Dispose() }
    } finally { $cn.Dispose() }
    , $rows.ToArray()
}

function Get-SIRaTelemetryCounts {
    <#
        The #719 keys of this install (an ordered dictionary, possibly empty). -SqlRows { param($Sql) rows } is the seam
        (default Invoke-SITelemetrySqlRows). A failed read leaves EVERY #719 key out and says so in ONE plain line per process
        (-Log, default Write-Host). Never throws.
    #>
    param([scriptblock]$SqlRows, [scriptblock]$Log)
    if (-not $SqlRows) { $SqlRows = { param($Sql) Invoke-SITelemetrySqlRows -Sql $Sql } }
    try {
        $rows = & $SqlRows (Get-SIRaTelemetryCountSql)
        if ($null -eq $rows) { return [ordered]@{} }
        return (ConvertFrom-SIRaTelemetryCountRows -Rows @($rows))
    } catch {
        if (-not $script:SIRaCountsWarned) {
            $script:SIRaCountsWarned = $true
            $m = ("$($_.Exception.Message)".Trim() -replace '\s+', ' '); if ($m.Length -gt 160) { $m = $m.Substring(0, 160) + '...' }
            $line = (" [INFO] Today's status report leaves out the report and CI numbers -- the database could not be read ({0})." -f $m)
            try { if ($Log) { & $Log $line } else { Write-Host $line } } catch { }
        }
        return [ordered]@{}
    }
}

<#
    SQL SPACE (#512, owner 2026-10-09: "telemetry must collect available sql db space remaining in health telemetry";
    framework §8.10 SQL-SPACE, the same two keys PIM sends): the install's Pro database (SI_ProSqlServer /
    SI_ProSqlDatabase), in MB --
      sqlUsedMb  the space its data files USE (FILEPROPERTY SpaceUsed, 8 KB pages)
      sqlMaxMb   its maximum size (DATABASEPROPERTYEX MaxSizeInBytes)
    Both readable with data rights only. Invardia warns on space left; a maximum under 250 GB is flagged (#511).
#>
function Get-SISqlSpaceQuery {
    # ONE value, 'used|max' -- read as a scalar
    "SET NOCOUNT ON; SELECT CONCAT((SELECT SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint)) * 8 / 1024 FROM sys.database_files WHERE type_desc = 'ROWS'), '|', CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS bigint) / 1048576);"
}

function ConvertFrom-SISqlSpaceValue {
    <# PURE. 'used|max' -> @{ sqlUsedMb; sqlMaxMb } with only the parts that are whole numbers >= 0 (sqlMaxMb > 0). #>
    param($Value)
    $c = @{}
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $c }
    $p = ([string]$Value).Split('|')
    $n = [long]0
    if ($p.Count -ge 1 -and [long]::TryParse($p[0].Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -ge 0) { $c['sqlUsedMb'] = $n }
    if ($p.Count -ge 2 -and [long]::TryParse($p[1].Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -gt 0) { $c['sqlMaxMb'] = $n }
    $c
}

function Get-SISqlSpaceCounts {
    <#
        sqlUsedMb / sqlMaxMb of the install's Pro database; an empty hashtable when there is no database or it could not be
        read. -Scalar { param($Sql) } is the seam (default: one connection as the job, closed after). Never throws.
    #>
    param([scriptblock]$Scalar, [string]$Server = [string]$global:SI_ProSqlServer, [string]$Database = [string]$global:SI_ProSqlDatabase)
    try {
        if ($Scalar) { return (ConvertFrom-SISqlSpaceValue -Value (& $Scalar (Get-SISqlSpaceQuery))) }
        if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { return @{} }
        # (no closure seam here: a GetNewClosure() runs in its own module scope and does not see the connection helper)
        if (-not (Get-Command -Name Get-SIObjectLedgerConnection -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'identity', 'SI-ObjectLedgerStore.ps1'))
        }
        $cn = Get-SIObjectLedgerConnection -Server $Server -Database $Database -MaxAttempts 2
        if (-not $cn) { return @{} }
        try { $cmd = $cn.CreateCommand(); $cmd.CommandText = (Get-SISqlSpaceQuery); $cmd.CommandTimeout = 0; $v = $cmd.ExecuteScalar() } finally { $cn.Dispose() }
        ConvertFrom-SISqlSpaceValue -Value $v
    } catch { @{} }
}

function Get-SIIdentityCountQuery {
    <# The KQL for users / guests: the latest identity collection, one row per user object. Typed = how many users carry
       a UserType at all -- 0 means the column is not filled, and then nothing is reported. #>
    param([System.Collections.IDictionary]$CompleteBy = (Get-SICountCompleteByState))
    $q = @'
let t = SI_Identity_Profile_CL | where TimeGenerated > ago(8d);
let lastColl = toscalar(t{{IDB}} | summarize _in = max(ingestion_time()) by CollectionTime | where _in < ago(30m) | summarize max(CollectionTime));
t
| where CollectionTime == lastColl
| extend _id = tostring(column_ifexists("SI_AssetId", "")), _type = tostring(column_ifexists("IdentityType", "")), _ut = tostring(column_ifexists("UserType", "")), _en = tostring(column_ifexists("AccountEnabled", ""))
| where isnotempty(_id) and _type =~ "User"
| summarize _ut = take_any(_ut), _en = take_any(_en) by _id
| summarize Users = countif(_ut =~ "Member" and _en =~ "true"), Guests = countif(_ut =~ "Guest"), Typed = countif(isnotempty(_ut)), Total = count()
'@
    $q.Replace('{{IDB}}', (Get-SICountCompleteFilter -Source identity -CompleteBy $CompleteBy))
}

function Get-SIAdOnlyUserHuntingQuery {
    <# The Advanced Hunting KQL for users' AD part: the distinct adSid of every enabled AD USER account in the Exposure
       Graph (field names as Get-DiscoveryFromIdentityExposureGraph and data-model/mappings/eg.locked.json read them).
       Total = how many there are, so a truncated answer is detected (rows < Total) and never sent as a count. #>
    @'
let u = ExposureGraphNodes
| where NodeLabel =~ "user"
| extend _p = tostring(NodeProperties.rawData.primaryProvider), _t = tostring(NodeProperties.rawData.identityType), _sid = toupper(tostring(NodeProperties.rawData.adSid)), _en = tostring(NodeProperties.rawData.accountEnabled), _en2 = tostring(NodeProperties.rawData.isEnabled), _act = tostring(NodeProperties.rawData.isActive)
| extend _enabled = iff(isnotempty(_en), _en, iff(isnotempty(_en2), _en2, _act))
| where _p =~ "ActiveDirectory" and _t =~ "User" and isnotempty(_sid) and _enabled =~ "true"
| distinct AdSid = _sid;
u | extend Total = toscalar(u | count)
'@
}

function Get-SIEntraOnPremSidQuery {
    <# The KQL for the SIDs of every Entra user in the latest identity collection that came from on-prem AD (OnPremSid),
       enabled or not -- a synced AD account belongs to the Entra part either way (counted there, or deliberately not
       when disabled in Entra), so it is never added again from AD. #>
    param([System.Collections.IDictionary]$CompleteBy = (Get-SICountCompleteByState))
    $q = @'
let t = SI_Identity_Profile_CL | where TimeGenerated > ago(8d);
let lastColl = toscalar(t{{IDB}} | summarize _in = max(ingestion_time()) by CollectionTime | where _in < ago(30m) | summarize max(CollectionTime));
t
| where CollectionTime == lastColl
| extend _type = tostring(column_ifexists("IdentityType", "")), _sid = toupper(tostring(column_ifexists("OnPremSid", "")))
| where _type =~ "User" and isnotempty(_sid)
| distinct OnPremSid = _sid
'@
    $q.Replace('{{IDB}}', (Get-SICountCompleteFilter -Source identity -CompleteBy $CompleteBy))
}

function Get-SIAdOnlyUserCountFromRows {
    <#
        PURE. users' AD part from the hunting rows (AdSid, Total) and the Entra OnPremSids. Returns @{ Count; Reason }:
        Count = the AD-only enabled users (a SID that is an Entra user's OnPremSid is not counted), or $null with a plain
        Reason when the hunting answer was cut short (fewer rows than its Total).
    #>
    param([AllowNull()][object[]]$EgRows, [AllowNull()][object[]]$EntraSids)
    $ad = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $total = $null
    foreach ($r in @($EgRows)) {
        if ($null -eq $r) { continue }
        $sid = "$($r.AdSid)".Trim()
        if ($sid) { [void]$ad.Add($sid) }
        $t = ConvertTo-SITelemetryCount $r.Total
        if ($null -ne $t -and ($null -eq $total -or $t -gt $total)) { $total = $t }
    }
    if ($null -ne $total -and $ad.Count -lt $total) {
        return @{ Count = $null; Reason = ('the Exposure Graph answer was cut short ({0} of {1} AD users)' -f $ad.Count, $total) }
    }
    $n = [long]0
    if ($ad.Count -gt 0) {
        $entra = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($e in @($EntraSids)) {
            if ($null -eq $e) { continue }
            $v = if ($e -is [string]) { $e } else { "$($e.OnPremSid)" }
            if ($v.Trim()) { [void]$entra.Add($v.Trim()) }
        }
        foreach ($s in $ad) { if (-not $entra.Contains($s)) { $n++ } }
    }
    @{ Count = $n; Reason = '' }
}

function Invoke-SITelemetryHuntingQuery {
    <#
        One Advanced Hunting query for the counts, as the run's Graph identity (Get-SIGraphToken -Resource Graph -- the token
        the identity engine's Exposure Graph discovery uses) through Invoke-SIHuntingQueryRest (v1.0, 120 s, -AsResult).
        Returns the rows as plain objects; throws a plain reason when it cannot be read. A test session never calls out.
    #>
    param([Parameter(Mandatory)][string]$Query)
    if (Get-Module -Name Pester) { throw 'a test session does not query Advanced Hunting' }
    if (-not (Get-Command -Name Invoke-SIHuntingQueryRest -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-GraphRest.ps1')) }
    if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) {
        . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'auth', 'Get-SIGraphToken.ps1'))
    }
    $token = Get-SIGraphToken -Resource Graph
    if ([string]::IsNullOrWhiteSpace([string]$token)) { throw 'no Graph token for Advanced Hunting' }
    $r = Invoke-SIHuntingQueryRest -Query $Query -Token $token -TimeoutSec 120 -ApiVersion 'v1.0' -AsResult
    if (-not $r.Ok) { throw ([string]$r.Error) }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($r.Results)) { if ($null -ne $x) { $rows.Add([pscustomobject]$x.AdditionalProperties) } }
    , $rows.ToArray()
}

function Get-SIAdOnlyUserCount {
    <#
        users' AD part: @{ Count; Reason } -- Count $null (with a plain Reason) when it cannot be read. -RunHunting
        { param($Kql) rows } and -RunQuery { param($Kql) rows } are the seams (defaults: Invoke-SITelemetryHuntingQuery /
        Invoke-SITelemetryLaQuery). Never throws.
    #>
    param([scriptblock]$RunHunting, [scriptblock]$RunQuery)
    if (-not $RunHunting) { $RunHunting = { param($Kql) Invoke-SITelemetryHuntingQuery -Query $Kql } }
    if (-not $RunQuery) { $RunQuery = { param($Kql) Invoke-SITelemetryLaQuery -Query $Kql } }
    $why = { param($e) $m = ("$e".Trim() -replace '\s+', ' '); if ($m.Length -gt 160) { $m = $m.Substring(0, 160) + '...' }; $m }
    try {
        $eg = & $RunHunting (Get-SIAdOnlyUserHuntingQuery)
        if ($null -eq $eg) { return @{ Count = $null; Reason = 'the Exposure Graph could not be read' } }
        $eg = @($eg)
        $sids = @()
        if ($eg.Count -gt 0) {
            # the dedupe needs the Entra SIDs; without them an AD number could count synced users twice, so none is sent
            try { $sids = & $RunQuery (Get-SIEntraOnPremSidQuery) }
            catch { return @{ Count = $null; Reason = ('the Entra on-prem SIDs to match synced users could not be read: {0}' -f (& $why $_.Exception.Message)) } }
            if ($null -eq $sids) { return @{ Count = $null; Reason = 'the Entra on-prem SIDs to match synced users could not be read' } }
        }
        return (Get-SIAdOnlyUserCountFromRows -EgRows $eg -EntraSids @($sids))
    } catch { return @{ Count = $null; Reason = ('the Exposure Graph could not be read: {0}' -f (& $why $_.Exception.Message)) } }
}

function Get-SIDeviceCountQuery {
    <# The KQL for devices: per UTC day of the last 7, the latest correlation run of that day, the number of distinct
       correlation objects with an endpoint member that is not an IoT or network device. #>
    @'
let rows = SI_ObjectMap_CL
| where TimeGenerated > ago(8d)
| where CollectionTime > ago(7d)
| where tostring(SI_MemberEngine) == "endpoint"
| extend Day = startofday(CollectionTime);
let lastPerDay = rows | summarize CollectionTime = max(CollectionTime) by Day;
let cats = SI_Endpoint_Profile_CL
| where TimeGenerated > ago(8d)
| extend _aid = tostring(column_ifexists("SI_AssetId", "")), _cat = tolower(tostring(column_ifexists("DeviceCategory", "")))
| where isnotempty(_aid)
| summarize arg_max(CollectionTime, _cat) by _aid
| project SI_AssetId = _aid, _cat;
rows
| join kind=inner (lastPerDay) on Day, CollectionTime
| join kind=leftouter (cats) on SI_AssetId
| where not(_cat in ("iot", "networkdevice"))
| summarize Devices = count_distinct(SI_CorrelationId) by Day
| order by Day asc
'@
}

function ConvertTo-SITelemetryCount {
    <# PURE. A non-negative whole number, or $null (unknown). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $d = 0.0
    if (-not [double]::TryParse([string]$Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ($d -lt 0 -or [double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
    [long][Math]::Floor($d)
}

function Get-SIIdentityCounts {
    <#
        PURE. users / guests from the identity query's one result row (Users, Guests, Typed, Total). Returns an ordered
        dictionary with the keys it could compute -- EMPTY when there are no users or no UserType was collected at all.
    #>
    param([AllowNull()]$Row)
    $out = [ordered]@{}
    if ($null -eq $Row) { return $out }
    $total = ConvertTo-SITelemetryCount $Row.Total
    $typed = ConvertTo-SITelemetryCount $Row.Typed
    if ($null -eq $total -or $total -eq 0 -or $null -eq $typed -or $typed -eq 0) { return $out }
    $u = ConvertTo-SITelemetryCount $Row.Users
    $g = ConvertTo-SITelemetryCount $Row.Guests
    if ($null -ne $u) { $out['users'] = $u }
    if ($null -ne $g) { $out['guests'] = $g }
    $out
}

function Get-SIDeviceCountMax {
    <#
        PURE. The 7-day maximum of daily device counts. -DailyCounts: rows with Day (a date) and Devices. Only the UTC days
        from (today - 6) to today count; an older or future day, or a row without a number, is ignored. $null when no day
        is left (no correlation run in the last 7 days) -- never 0 by guess.
    #>
    param([AllowNull()][object[]]$DailyCounts, [datetime]$NowUtc = [datetime]::UtcNow)
    $today = $NowUtc.ToUniversalTime().Date
    $first = $today.AddDays(-6)
    $max = $null
    foreach ($r in @($DailyCounts)) {
        if ($null -eq $r) { continue }
        $n = ConvertTo-SITelemetryCount $r.Devices
        if ($null -eq $n) { continue }
        $day = $null
        try {
            $dv = $r.Day
            $day = if ($dv -is [datetime]) { $dv.ToUniversalTime().Date }
                   else { ([datetime]::Parse([string]$dv, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')).Date }
        } catch { continue }
        if ($day -lt $first -or $day -gt $today) { continue }
        if ($null -eq $max -or $n -gt $max) { $max = $n }
    }
    $max
}

function Invoke-SITelemetryLaQuery {
    <#
        One KQL query on the install's workspace, for the counts: the Log Analytics resource-centric data plane
        (api.loganalytics.io/v1<workspace resource id>/query) as the run's identity, through the run's own REST helper.
        Short: 2 attempts, 60 s. Returns the primary table as objects, or $null when the REST helper is not loaded in this
        process (no signed-in engine) or there is no workspace. Throws on a refused query (the caller omits the count).
    #>
    # -MayBeMissing: tables of the query this workspace may not have (Test-SILaAnswerWhole): their legs answer nothing, the rest is whole
    param([Parameter(Mandatory)][string]$Query, [AllowEmptyString()][string]$WorkspaceResourceId = [string]$global:SI_WorkspaceResourceId, [string[]]$MayBeMissing = @())
    $ws = "$WorkspaceResourceId".Trim().TrimEnd('/')
    if ($ws -notmatch '^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$') { return $null }
    if (-not (Get-Command -Name Invoke-SIAzRestRequest -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name ConvertFrom-SILaQueryJson -ErrorAction SilentlyContinue)) { return $null }
    $uri = 'https://api.loganalytics.io/v1{0}/query' -f $ws
    $r = Invoke-SIAzRestRequest -Method POST -Uri $uri -Audience LaQuery -Body (@{ query = $Query } | ConvertTo-Json -Compress) `
             -TimeoutSec 60 -MaxAttempts 2 -What 'telemetry count query'
    $parsed = ConvertFrom-SILaQueryJson -Json ([string]$r.Content)
    # #639 lane 4: a count from an answer the service CUT (a part that timed out) is a wrong count -- refused like every
    # Log Analytics read (Test-SILaAnswerWhole); the caller omits the count, never sends a short one
    if ($null -ne $parsed.Error -and (Get-Command -Name Test-SILaAnswerWhole -ErrorAction SilentlyContinue)) {
        $v = Test-SILaAnswerWhole -ErrorObject $parsed.Error -Rows 0 -MayBeMissing $MayBeMissing
        if (-not $v.Whole) { throw (New-SILaCutAnswerError -Verdict $v -ErrorObject $parsed.Error) }
    }
    $t = @($parsed.Tables) | Select-Object -First 1
    $rows = New-Object System.Collections.Generic.List[object]
    if ($t) {
        $names = @($t.Columns | ForEach-Object { [string]$_.name })
        foreach ($row in @($t.Rows)) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = $row[$i] }
            $rows.Add([pscustomobject]$o)
        }
    }
    , $rows.ToArray()
}

function Get-SIDeviceCount {
    <#
        THE device count of this install: the 7-day maximum of unique correlated devices (endpoints + servers, one per
        real machine). $null when it cannot be computed. The reusable unit for the heartbeat AND the future Pro Business
        device cap. -RunQuery { param($Kql) rows } is the test seam (default: Invoke-SITelemetryLaQuery). Never throws.
    #>
    param([scriptblock]$RunQuery, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not $RunQuery) { $RunQuery = { param($Kql) Invoke-SITelemetryLaQuery -Query $Kql } }
    try {
        $rows = & $RunQuery (Get-SIDeviceCountQuery)
        if ($null -eq $rows) { return $null }
        return (Get-SIDeviceCountMax -DailyCounts @($rows) -NowUtc $NowUtc)
    } catch { return $null }
}

<#
    THE SECURITY SCORES (owner 2026-10-16: "Add, permission REQUIRED"), three Counts keys, whole numbers >= 0 (rounded):
      secureScore / secureScoreMax  Microsoft Secure Score, the LATEST daily score of the tenant: Graph
                                    GET /v1.0/security/secureScores?$top=1 -> currentScore / maxScore
                                    (application permission Microsoft Graph SecurityEvents.Read.All, read only)
      exposureScore                 the Defender for Endpoint exposure score: GET https://api.securitycenter.microsoft.com/api/exposureScore
                                    -> score (application permission WindowsDefenderATP Score.Read.All, read only)
    Both permissions are REQUIRED (config/permissions.locked.json): setup grants them on a new install, an existing install's
    update names them (setup/_shared/SI-PermissionNote.ps1). Until granted, a 401 / 403 leaves the keys OUT and the heartbeat's
    Warnings carry si-perm-1004 (Get-SISecurityScoreState -> SI-HeartbeatFields.ps1, Get-SIHeartbeatWarnings). Any other
    failure (no Defender for Endpoint, a timeout, a 5xx, no token) leaves the keys out, says one line, raises no warning.
    CHEAP: one call each, at most once an hour per process (the answer is kept for -CacheMinutes), and only in the hourly
    status report job (SI_ENGINE heartbeat) unless -WithScores says otherwise. Never throws.
#>
function Get-SISecurityScoreTable {
    <# The value of $script:SISecurityScore, made on first use in the scope that reads it: a function loaded by an outer script and called from an engine's script finds it set (the lists never depend on the caller's scope). #>
    if ($null -eq $script:SISecurityScore) { $script:SISecurityScore = @{
    GraphUri     = 'https://graph.microsoft.com/v1.0/security/secureScores?$top=1'
    DefenderUri  = 'https://api.securitycenter.microsoft.com/api/exposureScore'
    GraphRole    = 'SecurityEvents.Read.All'
    DefenderRole = 'Score.Read.All'
    TimeoutSec   = 30
    CacheMinutes = 55
} }
    , $script:SISecurityScore
}
$script:SISecurityScore = $null; $null = Get-SISecurityScoreTable

function Get-SISecurityScoreContract { (Get-SISecurityScoreTable) }

function Invoke-SISecurityScoreGet {
    <#
        One GET as the run's identity (Get-SIGraphToken -Resource Graph | Defender). Returns @{ Status (int; 0 = no answer);
        Body; Error } and NEVER throws. A test session never calls out (Status 0).
    #>
    param([Parameter(Mandatory)][ValidateSet('Graph', 'Defender')][string]$Resource, [Parameter(Mandatory)][string]$Uri)
    if (Get-Module -Name Pester) { return @{ Status = 0; Body = $null; Error = 'a test session does not read the security scores' } }
    try {
        if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) {
            . ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'auth', 'Get-SIGraphToken.ps1'))
        }
        $token = Get-SIGraphToken -Resource $Resource
        if ([string]::IsNullOrWhiteSpace([string]$token)) { return @{ Status = 0; Body = $null; Error = ('no {0} token' -f $Resource) } }
        $body = Invoke-RestMethod -Method Get -Uri $Uri -Headers @{ Authorization = ('Bearer ' + $token) } -TimeoutSec (Get-SISecurityScoreTable).TimeoutSec -ErrorAction Stop
        return @{ Status = 200; Body = $body; Error = '' }
    } catch {
        $code = 0
        try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch { $code = 0 }
        $m = ("$($_.Exception.Message)".Trim() -replace '\s+', ' '); if ($m.Length -gt 160) { $m = $m.Substring(0, 160) + '...' }
        return @{ Status = $code; Body = $null; Error = $m }
    }
}

function ConvertFrom-SISecurityScoreAnswers {
    <#
        PURE. The two answers (@{ Status; Body; Error }, or $null = not asked) -> @{ Counts (ordered); Refused (the permissions a
        401 / 403 names); Problems (plain reasons, not a permission) }. A value that is not a number >= 0 is left out.
    #>
    param([AllowNull()]$Graph, [AllowNull()]$Defender)
    $c = (Get-SISecurityScoreTable)
    $counts = [ordered]@{}; $refused = New-Object System.Collections.Generic.List[string]; $problems = New-Object System.Collections.Generic.List[string]
    $num = { param($v) if ($null -eq $v) { return $null }; $d = 0.0
        if (-not [double]::TryParse([string]$v, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d) -or $d -lt 0) { return $null }
        [long][Math]::Round($d, [MidpointRounding]::AwayFromZero) }
    $prop = { param($o, $n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    if ($null -ne $Graph) {
        $s = [int]$Graph.Status
        if ($s -in 401, 403) { $refused.Add($c.GraphRole) }
        elseif ($s -ge 200 -and $s -lt 300) {
            $latest = @(& $prop $Graph.Body 'value') | Where-Object { $null -ne $_ } | Select-Object -First 1
            if ($null -eq $latest) { $problems.Add('Microsoft Secure Score has no score yet') }
            else {
                $cur = & $num (& $prop $latest 'currentScore'); $max = & $num (& $prop $latest 'maxScore')
                if ($null -ne $cur) { $counts['secureScore'] = $cur }
                if ($null -ne $max) { $counts['secureScoreMax'] = $max }
                if ($null -eq $cur -and $null -eq $max) { $problems.Add('Microsoft Secure Score answered without a score') }
            }
        } else { $problems.Add(('Microsoft Secure Score could not be read ({0})' -f $(if ("$($Graph.Error)".Trim()) { "$($Graph.Error)".Trim() } else { "status $s" }))) }
    }
    if ($null -ne $Defender) {
        $s = [int]$Defender.Status
        if ($s -in 401, 403) { $refused.Add($c.DefenderRole) }
        elseif ($s -ge 200 -and $s -lt 300) {
            $sc = & $num (& $prop $Defender.Body 'score')
            if ($null -ne $sc) { $counts['exposureScore'] = $sc } else { $problems.Add('the Defender exposure score answered without a score') }
        } else { $problems.Add(('the Defender exposure score could not be read ({0})' -f $(if ("$($Defender.Error)".Trim()) { "$($Defender.Error)".Trim() } else { "status $s" }))) }
    }
    @{ Counts = $counts; Refused = $refused.ToArray(); Problems = $problems.ToArray() }
}

function Reset-SISecurityScoreCache { $global:SI_SecurityScoreCache = $null; $global:SI_SecurityScoreState = $null; $global:SI_SecurityScoreSaid = $false }

function Get-SISecurityScoreState {
    <# The permission state of the last score read in this process: @{ Refused = string[]; SinceUtc } -- $null when nothing was
       read, or nothing was refused. Read by the heartbeat's Warnings (si-perm-1004). #>
    $s = $global:SI_SecurityScoreState
    if ($null -eq $s -or -not @($s.Refused).Count) { return $null }
    $s
}

function Get-SISecurityScoreCounts {
    <#
        The three score keys of this install (an ordered dictionary, possibly empty). -GraphGet / -DefenderGet
        { param($Uri) } -> @{ Status; Body; Error } are the seams (default Invoke-SISecurityScoreGet). The answer is kept for
        -CacheMinutes (55): a second call within the hour reads nothing. Sets the permission state (Get-SISecurityScoreState)
        and says ONE plain line per process when a score could not be read (-Log, default Write-Host). Never throws.
    #>
    param([scriptblock]$GraphGet, [scriptblock]$DefenderGet, [datetime]$NowUtc = [datetime]::UtcNow, [int]$CacheMinutes = (Get-SISecurityScoreTable).CacheMinutes,
          [scriptblock]$Log)
    try {
        $now = $NowUtc.ToUniversalTime()
        $cache = $global:SI_SecurityScoreCache
        if ($null -ne $cache -and $CacheMinutes -gt 0 -and ($now - [datetime]$cache.AtUtc).TotalMinutes -lt $CacheMinutes -and ($now -ge [datetime]$cache.AtUtc)) {
            $o = [ordered]@{}; foreach ($k in @($cache.Counts.Keys)) { $o[$k] = $cache.Counts[$k] }; return $o
        }
        if (-not $GraphGet) { $GraphGet = { param($Uri) Invoke-SISecurityScoreGet -Resource Graph -Uri $Uri } }
        if (-not $DefenderGet) { $DefenderGet = { param($Uri) Invoke-SISecurityScoreGet -Resource Defender -Uri $Uri } }
        $g = $null; $d = $null
        try { $g = & $GraphGet (Get-SISecurityScoreTable).GraphUri } catch { $g = @{ Status = 0; Body = $null; Error = "$($_.Exception.Message)" } }
        try { $d = & $DefenderGet (Get-SISecurityScoreTable).DefenderUri } catch { $d = @{ Status = 0; Body = $null; Error = "$($_.Exception.Message)" } }
        $r = ConvertFrom-SISecurityScoreAnswers -Graph $g -Defender $d
        $prev = $global:SI_SecurityScoreState
        $since = if ($prev -and @($prev.Refused).Count -and $prev.SinceUtc) { $prev.SinceUtc } else { $now }
        $global:SI_SecurityScoreState = @{ Refused = @($r.Refused); SinceUtc = $(if (@($r.Refused).Count) { $since } else { $null }) }
        $global:SI_SecurityScoreCache = @{ AtUtc = $now; Counts = $r.Counts }
        $why = @(@($r.Refused | ForEach-Object { 'the permission {0} is not granted' -f $_ }) + @($r.Problems))
        if ($why.Count -and -not $global:SI_SecurityScoreSaid) {
            $global:SI_SecurityScoreSaid = $true
            $line = (" [INFO] The status report leaves out a security score -- {0}." -f ($why -join '; '))
            try { if ($Log) { & $Log $line } else { Write-Host $line } } catch { }
        }
        $o = [ordered]@{}; foreach ($k in @($r.Counts.Keys)) { $o[$k] = $r.Counts[$k] }
        return $o
    } catch { return [ordered]@{} }
}

function Get-SITelemetryHeartbeatCounts {
    <#
        The Counts of an identified heartbeat: users, guests, devices -- each only when it could be computed. Returns a
        hashtable (possibly empty). -RunQuery as Get-SIDeviceCount; -RunHunting as Get-SIAdOnlyUserCount; -Log
        { param($Line) } gets the one plain line when users carries the Entra part only (default: Write-Host). Never throws.
    #>
    # -SqlRows: the #719 read's seam (Get-SIRaTelemetryCounts)
    # -WithScores: read the security scores (default: only in the hourly status report job, SI_ENGINE heartbeat -- an engine's
    # end-of-run heartbeat never calls the score APIs); -GraphGet / -DefenderGet: their seams (Get-SISecurityScoreCounts)
    param([scriptblock]$RunQuery, [datetime]$NowUtc = [datetime]::UtcNow, [scriptblock]$SqlScalar, [scriptblock]$RunHunting, [scriptblock]$Log, [scriptblock]$SqlRows,
          [AllowNull()]$WithScores, [scriptblock]$GraphGet, [scriptblock]$DefenderGet)
    if (-not $RunQuery) { $RunQuery = { param($Kql) Invoke-SITelemetryLaQuery -Query $Kql } }
    $c = @{}
    $s = Get-SISqlSpaceCounts -Scalar $SqlScalar
    foreach ($k in @($s.Keys)) { $c[$k] = $s[$k] }
    # #712: a collection newer than its source's last COMPLETE one (a collection in parts, still running) is never counted
    $script:SICountCompleteBy = Get-SICountCompleteBy -SqlRows $SqlRows
    try {
        $rows = & $RunQuery (Get-SIIdentityCountQuery)
        if ($null -ne $rows) {
            $ic = Get-SIIdentityCounts -Row (@($rows) | Select-Object -First 1)
            foreach ($k in @($ic.Keys)) { $c[$k] = $ic[$k] }
        }
    } catch { }
    if ($c.ContainsKey('users')) {
        # users' AD part (AD-only enabled user accounts from the Exposure Graph); unreadable = Entra only + one plain line
        $ad = $null
        try { $ad = Get-SIAdOnlyUserCount -RunHunting $RunHunting -RunQuery $RunQuery } catch { $ad = $null }
        if ($null -ne $ad -and $null -ne $ad.Count) { $c['users'] = [long]$c['users'] + [long]$ad.Count }
        else {
            $why = if ($ad -and $ad.Reason) { $ad.Reason } else { 'the Exposure Graph could not be read' }
            $line = (" [INFO] Today's status report counts Entra users only -- on-prem AD users are not included ({0})." -f $why)
            try { if ($Log) { & $Log $line } else { Write-Host $line } } catch { }
        }
    }
    $d =Get-SIDeviceCount -RunQuery $RunQuery -NowUtc $NowUtc
    if ($null -ne $d) { $c['devices'] = $d }
    try {
        $inv = & $RunQuery (Get-SIInventoryCountQuery)
        if ($null -ne $inv) { $ic = Get-SIInventoryCounts -Row (@($inv) | Select-Object -First 1); foreach ($k in @($ic.Keys)) { $c[$k] = $ic[$k] } }
    } catch { }
    try { $ra = Get-SIRaTelemetryCounts -SqlRows $SqlRows -Log $Log; foreach ($k in @($ra.Keys)) { $c[$k] = $ra[$k] } } catch { }
    $scores = if ($null -ne $WithScores) { [bool]$WithScores } else { "$([Environment]::GetEnvironmentVariable('SI_ENGINE'))".Trim() -eq 'heartbeat' }
    if ($scores) {
        try { $sc = Get-SISecurityScoreCounts -GraphGet $GraphGet -DefenderGet $DefenderGet -NowUtc $NowUtc -Log $Log; foreach ($k in @($sc.Keys)) { $c[$k] = $sc[$k] } } catch { }
    }
    foreach ($k in @($c.Keys)) { if ((Get-SITelemetryCountNamesState) -notcontains $k) { $c.Remove($k) } }
    $c
}
