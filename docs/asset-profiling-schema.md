# SecurityInsight v2.2 -- Profile schema reference

> Auto-generated from `v2.2/asset-profiling-schema/{endpoint,identity,azure}.schema.json` by `v2.2/asset-profiling-schema/tools/Build-SchemaDoc.ps1`. Do not hand-edit. Re-run the generator after any schema change. Generated 2026-04-29 for SI 2.2.0.

Three engines, three flat-column tables in Log Analytics. Every customer KQL goes against one of these (or joins across them). Cross-engine joins use `PrimaryEntityId` (the first member of `EntityIds[]`).

## Tables at a glance

| Engine | LA table | DCR | Field count | Schema version | Last modified |
|---|---|---|---:|---|---|
| endpoint | `SI_Endpoint_Profile_CL` | `dcr-si-endpoint-profile` | 160 | 2.3.6 | 2026-04-29 |
| identity | `SI_Identity_Profile_CL` | `dcr-si-identity-profile` | 154 | 2.3.6 | 2026-04-29 |
| azure | `Azure_Profile_CL` | `dcr-si-azure-profile` | 314 | 2.3.6 | 2026-04-29 |

## Source legend

Every field carries a `source` field telling you where the value comes from. Values seen across the three schemas:

| Source | Description |
|---|---|
| `azure` | Azure Resource Graph + Az resource APIs -- one row per Azure resource |
| `cmdb` | Customer CMDB (servicenow-cmdb provider, default-disabled). Folded onto Properties.collect.cmdb at Reconcile. |
| `derived` | Computed in the engine -- Profile stage (drift hashes, IsEnabledActive, IsStaleAsset, AssetName, etc.) or Collect stage (PrimaryEntityId from EntityIds[0]) |
| `entra` | Microsoft Entra ID (Graph users + servicePrincipals + groups + signInActivity) |
| `exposureGraph` | Microsoft Defender Exposure Graph (ExposureGraphNodes + ExposureGraphEdges) -- the v2.2 master discovery + property source |
| `mde` | Microsoft Defender for Endpoint (advanced hunting / DeviceInfo) -- machine-as-asset |
| `mdi` | Microsoft Defender for Identity (on-prem AD signal sourced through MDI -- investigation priority + sensitive group membership) |

## Stage legend

Each field has a `stage` block: which pipeline phase WROTE the column (always exactly one) and which phases later READ it. Phases:

- **collect** -- Stage 2 (Discover + Collect), pulls raw data from each provider and lands the row.
- **enrich** -- Stage 3, joins cross-source signal (e.g. EG edges, Entra group membership).
- **profile** -- Stage 5, derives flat-column verdicts (IsEnabledActive, UnsupportedOSDetected, IsStaleAsset, AssetName, ...).
- **classify** -- Stage 4, AI tier verdict + Properties.classify.* sub-tree.
- **reconcile** -- Stage 7, folds CMDB matches + cross-engine references.
- **posture_analyze** -- evaluates posture rules against the profiled row, emits Properties.posture.findings[].
- **dashboard / sentinel** -- consumed only by Power BI dataset / KQL queries (not written by the engine).

---

## Endpoint  --  `SI_Endpoint_Profile_CL`

- **DCR**: `dcr-si-endpoint-profile`
- **Schema version**: `2.3.6` (last modified 2026-04-29)
- **Sources consumed**: `mde`, `exposureGraph`, `entra`, `azure`, `derived`
- **Entity-ID types** (members of `EntityIds[*]`): `MdeDeviceId`, `AadDeviceId`, `IntuneDeviceId`, `AzureResourceId`, `HardwareUuid`, `AzureVmId`, `AwsResourceName`, `GcpFullResourceName`, `Hostname`
- **Hub join** (master-record producer): `exposureGraph`
- **EG node labels in scope**: `device`, `microsoft.compute/virtualmachines`, `microsoft.compute/virtualmachines/extensions`
- **Field count**: 160

### Fields

| Name | Type | Purpose | Source | Source path | Written by | Read by | Added in |
|---|---|---|---|---|---|---|---|
| `PrimaryEntityId` | `string` | identity | `derived` | `EntityIds[0].id` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard`, `sentinel` | 2.3.0 |
| `PrimaryEntityType` | `string` | identity | `derived` | `EntityIds[0].type` | `collect` | `enrich`, `posture_analyze`, `classify` | 2.3.0 |
| `EntityIds` | `dynamic` | correlation | `derived` | `merged from all sources (mde+exposureGraph+azure+derived)` | `collect` | `enrich`, `posture_analyze`, `classify`, `sentinel` | 2.3.0 |
| `RunId` | `string` | identity | `derived` | `UUID per orchestrator run` | `bootstrap` | `all` | 2.3.0 |
| `CollectionTime` | `datetime` | freshness | `derived` | `now() at output` | `classify` | `all` | 2.3.0 |
| `MdeDeviceId` | `string` | correlation | `mde` | `mde.machine.id (also DeviceInfo.DeviceId)` | `collect` | `enrich`, `classify`, `sentinel` | 2.3.0 |
| `AadDeviceId` | `string` | correlation | `mde` | `mde.machine.aadDeviceId` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AzureResourceId` | `string` | correlation | `azure` | `arm.virtualMachines.id (when Azure-hosted)` | `collect` | `enrich`, `classify`, `sentinel` | 2.3.0 |
| `AssetName` | `string` | pivot | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.2.0 |
| `Hostname` | `string` | correlation | `mde` | `mde.machine.computerDnsName` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `DisplayName` | `string` | identity | `derived` |  | `collect` | `enrich`, `classify`, `dashboard` | 2.3.1 |
| `HardwareUuid` | `string` | correlation | `mde` | `DeviceInfo.HardwareUuid` | `collect` | `enrich` | 2.3.0 |
| `AzureVmId` | `string` | correlation | `mde` | `DeviceInfo.AzureVmId` | `collect` | `enrich` | 2.3.0 |
| `AzureVmSubscriptionId` | `string` | correlation | `mde` | `DeviceInfo.AzureVmSubscriptionId` | `collect` | `enrich` | 2.3.0 |
| `AwsResourceName` | `string` | correlation | `mde` | `DeviceInfo.AwsResourceName` | `collect` | `enrich` | 2.3.0 |
| `GcpFullResourceName` | `string` | correlation | `mde` | `DeviceInfo.GcpFullResourceName` | `collect` | `enrich` | 2.3.0 |
| `HostDeviceId` | `string` | correlation | `mde` | `DeviceInfo.HostDeviceId (WSL → Windows host)` | `collect` | `enrich` | 2.3.0 |
| `MergedDeviceIds` | `dynamic` | correlation | `mde` | `DeviceInfo.MergedDeviceIds (kept in EntityIds with relation: merged_predecessor)` | `collect` | `enrich` | 2.3.0 |
| `MergedToDeviceId` | `string` | correlation | `mde` | `DeviceInfo.MergedToDeviceId` | `collect` | `enrich` | 2.3.0 |
| `CollectHash` | `string` | identity | `derived` | `SHA256 over collect-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `EnrichHash` | `string` | identity | `derived` | `SHA256 over enrich-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `PostureHash` | `string` | identity | `derived` | `SHA256 over posture-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `ClassifyHash` | `string` | identity | `derived` | `SHA256 over classify-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `OnboardingStatus` | `string` | posture | `mde` | `mde.machine.onboardingStatus` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `HealthStatus` | `string` | posture | `mde` | `mde.machine.healthStatus` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsExcluded` | `bool` | posture | `mde` | `mde.machine.isExcluded` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsDomainController` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsCustomerFacing` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isCustomerFacing (BYOD/IoT shadow IT signal)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `FirstSeen` | `datetime` | lifecycle | `mde` | `mde.machine.firstSeen` | `collect` | `enrich` | 2.3.0 |
| `LastSeen` | `datetime` | freshness | `mde` | `mde.machine.lastSeen` | `collect` | `enrich`, `classify`, `sentinel` | 2.3.0 |
| `SensorHealthState` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.sensorHealthState (Active/InactiveRecent)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `SenseClientVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.senseClientVersion` | `collect` | `enrich` | 2.3.0 |
| `RiskScore` | `string` | risk | `mde` | `mde.machine.riskScore (None/Low/Medium/High)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposureLevel` | `string` | risk | `mde` | `mde.machine.exposureLevel` | `collect` | `enrich`, `classify` | 2.3.0 |
| `DeviceValue` | `string` | risk | `mde` | `mde.machine.deviceValue` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AssetValue` | `string` | risk | `mde` | `DeviceInfo.AssetValue (Defender for Cloud)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposedToInternet` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.type == 'InternetExposure'` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposureSourceCidrs` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.effectiveRules[*].sourceCidr` | `collect` | `enrich` | 2.3.0 |
| `VulnerabilityCount` | `int` | risk | `mde` | `mde.machine.vulnerabilityCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MissingKbCount` | `int` | risk | `mde` | `mde.machine.missingKbCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `CriticalCveCount30d` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IdentifiedResourceUsersCount` | `int` | risk | `exposureGraph` | `array_length(eg.node.NodeProperties.rawData.identifiedResourceUsers)` | `collect` | `enrich` | 2.3.0 |
| `HighPrivIdentifiedUsers` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasGuardMisconfigurations` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.hasGuardMisconfigurations[*]` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MachineSid` | `string` | correlation | `exposureGraph` | `eg.node.NodeProperties.rawData.machineSid (local Windows SID)` | `collect` | `enrich` | 2.3.0 |
| `LoggedOnUsersCount_derived` | `int` | attribution | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `JoinType` | `string` | pivot | `mde` | `DeviceInfo.JoinType (Domain/Azure/Workgroup)` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `DefenderAvStatus` | `string` | posture | `mde` | `DeviceInfo.DefenderAvStatus (Updated/OutOfDate/Disabled/Unknown)` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `DefenderAvMode` | `string` | posture | `mde` | `DeviceInfo.DefenderAvMode (Active/Passive)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EdrMode` | `string` | posture | `mde` | `DeviceInfo.EdrMode (Block/Audit/Disabled)` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `MitigationStatus` | `string` | posture | `mde` | `DeviceInfo.MitigationStatus (Block/Audit/Disabled etc.)` | `collect` | `enrich` | 2.3.0 |
| `IsInternetFacing` | `bool` | risk | `mde` | `DeviceInfo.IsInternetFacing` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsTransient` | `bool` | lifecycle | `mde` | `DeviceInfo.IsTransient (short-lived asset, e.g. CI runner)` | `collect` | `enrich` | 2.3.0 |
| `IsPotentialDuplication` | `bool` | correlation | `mde` | `DeviceInfo.IsPotentialDuplication` | `collect` | `enrich` | 2.3.0 |
| `ExclusionReason` | `string` | lifecycle | `mde` | `DeviceInfo.ExclusionReason` | `collect` | `enrich` | 2.3.0 |
| `OnboardedDateTime` | `datetime` | lifecycle | `mde` | `DeviceInfo.OnboardedDateTime` | `collect` | `dashboard` | 2.3.0 |
| `OffboardedDateTime` | `datetime` | lifecycle | `mde` | `DeviceInfo.OffboardedDateTime` | `collect` | `dashboard` | 2.3.0 |
| `LastSeenDays` | `int` | freshness | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EffectiveIpAddresses_mde` | `dynamic` | correlation | `mde` | `DeviceInfo.IPAddresses (most recent observed IP set)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `CriticalityConfidenceHigh` | `dynamic` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityConfidenceHigh[*] (high-confidence rule labels)` | `collect` | `dashboard` | 2.3.0 |
| `VulnerableSoftwareCount` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.vulnerableSoftwareCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `InternetExposedReasons` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.reasons[*] (when ExposedToInternet=true)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `WeeklyActiveUsersCount` | `int` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.weeklyActiveUsersCount (rough usage signal)` | `collect` | `dashboard` | 2.3.0 |
| `LastDailyDeviceUsageDate` | `datetime` | freshness | `exposureGraph` | `eg.node.NodeProperties.rawData.lastDailyDeviceUsageDate` | `collect` | `dashboard` | 2.3.0 |
| `InactivityPeriod` | `string` | freshness | `exposureGraph` | `eg.node.NodeProperties.rawData.inactivityPeriod (D{n} format)` | `collect` | `dashboard` | 2.3.0 |
| `MostFrequentUserTier` | `int` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `MostFrequentUsers` | `dynamic` | attribution | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `CriticalityLevel` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityLevel.criticalityLevel (effective tier 0-3, manual wins over rule)` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `RuleBasedCriticalityLevel` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel (tier from EG rule engine, before manual override)` | `collect` | `enrich` | 2.3.0 |
| `ManualCriticalityLevel` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.manualCriticalityLevel (operator-set override)` | `collect` | `enrich` | 2.3.0 |
| `CriticalityRuleNames` | `dynamic` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityLevel.ruleNames[*] (which EG rules / manual tags fired)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `HasAuthorityMisConfigurations` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.hasAuthorityMisConfigurations[*] (OS-level / authority misconfigs distinct from Guard misconfigs)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `PotentialDuplicateOf` | `string` | correlation | `exposureGraph` | `eg.node.NodeProperties.rawData.potentialDuplicateOf (NodeId of likely-duplicate device record)` | `collect` | `enrich` | 2.3.0 |
| `GraphInternalLabel` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.graphInternalLabel (workstation/audioAndVideo/smartAppliance/networkPhysicalDevice/mobile/printer/unclassifiedDevice)` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard` | 2.3.0 |
| `FirstSeenByInventory` | `datetime` | freshness | `exposureGraph` | `eg.node.NodeProperties.rawData.firstSeenByInventory` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `EgLastSeen` | `datetime` | freshness | `exposureGraph` | `eg.node.NodeProperties.rawData.lastSeen (EG-side; complements MDE LastSeen)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `DiscoverySourceProducts` | `dynamic` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.discoverySources-udi.sources[*].productName (Defender for Endpoint, MDI, Azure Arc, etc.)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `DeviceRegistryTags` | `dynamic` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceRegistryTags[*] (key/value pairs from registry-based MDE tagging)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `RegistryDeviceTag_exposureGraph` | `string` | attribution | `exposureGraph` | `eg.node.NodeProperties.rawData.registryDeviceTag (single-value registry tag form)` | `collect` | `enrich` | 2.3.0 |
| `NsgEffectiveRules` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `OpenInboundPortsFromInternet` | `dynamic` | risk | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `OpenInboundPortsFromExternalIps` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `OpenInboundPortsFromVnet` | `dynamic` | enrichment | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasInternetExposedRdp` | `bool` | risk | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `HasInternetExposedSsh` | `bool` | risk | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `HasInternetExposedSmb` | `bool` | risk | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `HasInternetExposedWinRm` | `bool` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasInternetExposedDbPort` | `bool` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasNarrowAdminAllow` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `PortExposureFindings` | `dynamic` | risk | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `HighestPortRiskScore` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `OpenOutboundDestinations` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `NicCount` | `int` | enrichment | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EffectiveIpAddresses_derived` | `dynamic` | correlation | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `LoggedOnUsersCount_mde` | `int` | risk | `mde` | `array_length(parse_json(DeviceInfo.LoggedOnUsers))` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LoggedOnUsers` | `dynamic` | risk | `mde` | `parse_json(DeviceInfo.LoggedOnUsers) -- [{UserName, DomainName, Sid}]` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LoggedOnUserSids` | `dynamic` | correlation | `mde` | `LoggedOnUsers[*].Sid (cross-engine join key to Identity_Profile_CL.OnPremSid)` | `collect` | `enrich`, `classify`, `sentinel` | 2.3.0 |
| `CloudPlatforms` | `string` | pivot | `mde` | `DeviceInfo.CloudPlatforms (Azure\|AWS\|GCP\|Azure Arc)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `ConnectivityType` | `string` | pivot | `mde` | `DeviceInfo.ConnectivityType` | `collect` | `dashboard` | 2.3.0 |
| `Site` | `string` | pivot | `mde` | `DeviceInfo.Site (physical location)` | `collect` | `dashboard` | 2.3.0 |
| `RegistryDeviceTag_mde` | `string` | enrichment | `mde` | `DeviceInfo.RegistryDeviceTag` | `collect` | `enrich`, `classify` | 2.3.0 |
| `OsBuildRevision` | `string` | pivot | `mde` | `DeviceInfo.OsBuildRevision` | `collect` | `dashboard` | 2.3.0 |
| `OsVersionInfo` | `string` | pivot | `mde` | `DeviceInfo.OsVersionInfo` | `collect` | `dashboard` | 2.3.0 |
| `DeviceCategory` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceCategory (Endpoint/IoT/Unknown)` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard` | 2.3.0 |
| `DeviceType` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceType` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard` | 2.3.0 |
| `DeviceSubtype` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceSubtype` | `collect` | `enrich`, `posture_analyze`, `classify` | 2.3.0 |
| `DeviceRole` | `dynamic` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceRole[*]` | `collect` | `enrich`, `posture_analyze`, `classify` | 2.3.0 |
| `OsPlatform` | `string` | pivot | `mde` | `mde.machine.osPlatform` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard` | 2.3.0 |
| `OsVersion` | `string` | pivot | `mde` | `mde.machine.osVersion` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `OsBuild` | `string` | pivot | `mde` | `mde.machine.osBuild` | `collect` | `dashboard` | 2.3.0 |
| `OsProcessor` | `string` | pivot | `mde` | `mde.machine.osProcessor` | `collect` | `dashboard` | 2.3.0 |
| `OsArchitecture` | `string` | pivot | `mde` | `DeviceInfo.OSArchitecture` | `collect` | `dashboard` | 2.3.0 |
| `RbacGroupName` | `string` | pivot | `mde` | `mde.machine.rbacGroupName` | `collect` | `dashboard` | 2.3.0 |
| `MachineGroup` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.machineGroup` | `collect` | `dashboard` | 2.3.0 |
| `MachineTags` | `dynamic` | pivot | `mde` | `mde.machine.machineTags[*]` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `DeviceDynamicTags` | `dynamic` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceDynamicTags[*]` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `DeviceManualTags` | `dynamic` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.deviceManualTags[*]` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `Vendor` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.vendor` | `collect` | `posture_analyze`, `dashboard` | 2.3.0 |
| `Model` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.model` | `collect` | `posture_analyze`, `dashboard` | 2.3.0 |
| `PublicIp` | `string` | risk | `mde` | `mde.machine.publicIp (or DeviceInfo.PublicIP)` | `collect` | `enrich`, `sentinel` | 2.3.0 |
| `PrimaryUser` | `string` | attribution | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `Owner` | `string` | attribution | `azure` | `arm.virtualMachines.tags.owner (when Azure-hosted)` | `collect` | `dashboard` | 2.3.0 |
| `Region` | `string` | pivot | `azure` | `arm.virtualMachines.location (when Azure-hosted)` | `collect` | `dashboard` | 2.3.0 |
| `IsApplicableForDefenderForServers` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isApplicableForMdeThroughDefenderForServers.isApplicable` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsApplicableForDefenderForServersReason` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isApplicableForMdeThroughDefenderForServers.reason` | `collect` | `enrich` | 2.3.0 |
| `IsUsiServer` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isUsiServer` | `collect` | `enrich`, `classify` | 2.3.0 |
| `Extensions` | `dynamic` | enrichment | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsHybridAzureADJoined` | `bool` | posture | `mde` | `DeviceInfo / EG (isHybridAzureADJoined)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsAzureADJoined` | `bool` | posture | `mde` | `DeviceInfo.IsAzureADJoined` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AzureADJoinType` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.azureADJoinType` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `TpmSupported` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.tpmData.supported` | `collect` | `enrich`, `classify` | 2.3.0 |
| `TpmActivated` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.tpmData.activated` | `collect` | `enrich`, `classify` | 2.3.0 |
| `TpmEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.tpmData.enabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `TpmVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.tpmData.version` | `collect` | `enrich` | 2.3.0 |
| `SmbEnableSmb1Protocol` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.smb.enableSmb1Protocol` | `collect` | `enrich`, `classify` | 2.3.0 |
| `SmbRequireSecuritySignature` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.smb.requireSecuritySignature` | `collect` | `enrich`, `classify` | 2.3.0 |
| `SmbEncryptData` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.smb.encryptData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `RdpAllowConnections` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.rdp.allowConnections` | `collect` | `enrich`, `classify` | 2.3.0 |
| `RdpNlaRequired` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.rdp.nlaRequired` | `collect` | `enrich`, `classify` | 2.3.0 |
| `RdpServiceRunning` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.rdp.serviceRunning` | `collect` | `enrich`, `classify` | 2.3.0 |
| `WinRmServiceRunning` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.remoteServicesInfo.winRm.serviceRunning` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AssetType` | `string` | pivot | `derived` |  | `posture_analyze` | `classify`, `dashboard` | 2.3.0 |
| `AssetSubtype` | `string` | pivot | `derived` |  | `posture_analyze` | `classify`, `dashboard` | 2.3.0 |
| `AssetGroup` | `string` | pivot | `derived` |  | `posture_analyze` | `classify`, `dashboard` | 2.3.0 |
| `Tier` | `int` | kpi | `derived` |  | `classify` | `dashboard`, `sentinel` | 2.3.0 |
| `SIRules` | `dynamic` | audit | `derived` |  | `profile` | `dashboard`, `sentinel`, `audit` | 2.3.2 |
| `IsEnabledActive` | `bool` | freshness | `derived` |  | `profile` | `dashboard`, `sentinel` | 2.3.3 |
| `Group` | `string` | kpi | `derived` |  | `classify` | `dashboard` | 2.3.0 |
| `UnsupportedOSDetected` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `sentinel`, `risk_analysis` | 2.3.4 |
| `UnsupportedOSReason` | `string` | audit | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `DefenderAvOutOfDate` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `DaysInactive` | `int` | freshness | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsStaleAsset` | `bool` | freshness | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsCmdbOrphan` | `bool` | audit | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `cmdbId` | `string` | correlation | `cmdb` | `cmdb.id (CMDB row primary key when matched at Reconcile)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbName` | `string` | correlation | `cmdb` | `cmdb.name (display name from CMDB)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbCriticality` | `string` | audit | `cmdb` | `cmdb.criticality (Critical / High / Medium / Low)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbDataSensitivity` | `string` | audit | `cmdb` | `cmdb.dataSensitivity (Restricted / Confidential / Internal / Public)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchPhase` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchState` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |

## Identity  --  `SI_Identity_Profile_CL`

- **DCR**: `dcr-si-identity-profile`
- **Schema version**: `2.3.6` (last modified 2026-04-29)
- **Sources consumed**: `entra`, `mdi`, `exposureGraph`, `signInLogs`, `derived`
- **Entity-ID types** (members of `EntityIds[*]`): `AadObjectId`, `Upn`, `Mail`, `SecurityIdentifier`, `ActiveDirectoryObjectGuid`
- **Hub join** (master-record producer): `exposureGraph`
- **EG node labels in scope**: `user`, `group`, `serviceprincipal`, `managedidentity`
- **Field count**: 154

### Fields

| Name | Type | Purpose | Source | Source path | Written by | Read by | Added in |
|---|---|---|---|---|---|---|---|
| `PrimaryEntityId` | `string` | identity | `derived` | `EntityIds[0].id` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard`, `sentinel` | 2.3.0 |
| `PrimaryEntityType` | `string` | identity | `derived` | `EntityIds[0].type` | `collect` | `enrich`, `posture_analyze`, `classify` | 2.3.0 |
| `EntityIds` | `dynamic` | correlation | `derived` | `merged from all sources (entra+mdi+exposureGraph+derived)` | `collect` | `enrich`, `posture_analyze`, `classify`, `sentinel` | 2.3.0 |
| `RunId` | `string` | identity | `derived` | `UUID per orchestrator run` | `bootstrap` | `all` | 2.3.0 |
| `CollectionTime` | `datetime` | freshness | `derived` | `now() at output` | `classify` | `all` | 2.3.0 |
| `Upn` | `string` | correlation | `entra` | `graph.user.userPrincipalName` | `collect` | `enrich`, `classify`, `sentinel` | 2.3.0 |
| `Mail` | `string` | correlation | `entra` | `graph.user.mail` | `collect` | `enrich`, `classify` | 2.3.0 |
| `OnPremSid` | `string` | correlation | `entra` | `graph.user.onPremisesSecurityIdentifier` | `collect` | `enrich`, `classify` | 2.3.0 |
| `OnPremSamAccountName` | `string` | correlation | `entra` | `graph.user.onPremisesSamAccountName` | `collect` | `enrich`, `classify` | 2.3.0 |
| `OnPremObjectGuid` | `string` | correlation | `mdi` | `mdi.identity.objectGuid (also EG ActiveDirectoryObjectGuid)` | `collect` | `enrich` | 2.3.0 |
| `EmployeeId` | `string` | correlation | `entra` | `graph.user.employeeId` | `collect` | `enrich` | 2.3.0 |
| `CollectHash` | `string` | identity | `derived` | `SHA256 over collect-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `EnrichHash` | `string` | identity | `derived` | `SHA256 over enrich-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `PostureHash` | `string` | identity | `derived` | `SHA256 over posture-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `ClassifyHash` | `string` | identity | `derived` | `SHA256 over classify-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `AccountEnabled` | `bool` | posture | `entra` | `graph.user.accountEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `UserType` | `string` | posture | `entra` | `graph.user.userType` | `collect` | `enrich`, `classify` | 2.3.0 |
| `CreationType` | `string` | posture | `entra` | `graph.user.creationType` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExternalUserState` | `string` | posture | `entra` | `graph.user.externalUserState` | `collect` | `enrich`, `classify` | 2.3.0 |
| `OnPremisesSyncEnabled` | `bool` | posture | `entra` | `graph.user.onPremisesSyncEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsManagementRestricted` | `bool` | posture | `entra` | `graph.user.isManagementRestricted` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsBreakGlass` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasLeakedCredentials` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasLeakedCredentials` | `collect` | `classify` | 2.3.0 |
| `HasAdLeakedCredentials` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasAdLeakedCredentials` | `collect` | `classify` | 2.3.0 |
| `MdiIsLockedOut` | `bool` | posture | `mdi` | `mdi.identity.isLockedOut` | `collect` | `classify` | 2.3.0 |
| `MdiIsSensitive` | `bool` | posture | `mdi` | `mdi.identity.sensitivity.isSensitive` | `collect` | `classify` | 2.3.0 |
| `IsAdSensitiveFlagged` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isSensitive (AD-side ≠ MDI's)` | `collect` | `classify` | 2.3.0 |
| `CreatedDateTime` | `datetime` | lifecycle | `entra` | `graph.user.createdDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `DeletedDateTime` | `datetime` | lifecycle | `entra` | `graph.user.deletedDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EmployeeHireDate` | `datetime` | lifecycle | `entra` | `graph.user.employeeHireDate` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EmployeeLeaveDateTime` | `datetime` | lifecycle | `entra` | `graph.user.employeeLeaveDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LastSignInDateTime` | `datetime` | freshness | `entra` | `graph.user.signInActivity.lastSignInDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LastNonInteractiveSignInDateTime` | `datetime` | freshness | `entra` | `graph.user.signInActivity.lastNonInteractiveSignInDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LastSuccessfulSignInDateTime` | `datetime` | freshness | `entra` | `graph.user.signInActivity.lastSuccessfulSignInDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `LastSignInDays` | `int` | freshness | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `LastPasswordChangeDateTime` | `datetime` | freshness | `entra` | `graph.user.lastPasswordChangeDateTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MfaIsRegistered` | `bool` | posture | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isMfaRegistered (BULK fetched once per run)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MfaIsCapable` | `bool` | posture | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isMfaCapable` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsPasswordlessCapable` | `bool` | posture | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isPasswordlessCapable (FIDO2 / Windows Hello)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsSsprRegistered` | `bool` | posture | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isSsprRegistered` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsSsprCapable` | `bool` | posture | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isSsprCapable` | `collect` | `enrich` | 2.3.0 |
| `IsSsprEnabled` | `bool` | policy | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.isSsprEnabled` | `collect` | `enrich` | 2.3.0 |
| `MfaMethods` | `dynamic` | attribution | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.methodsRegistered[*] (excludes 'password')` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `MfaMethodCount` | `int` | posture | `entra` | `array_length(MfaMethods)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MfaDefaultMethod` | `string` | attribution | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.defaultMfaMethod` | `collect` | `dashboard` | 2.3.0 |
| `MfaSystemPreferredMethods` | `dynamic` | attribution | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.systemPreferredAuthenticationMethods[*]` | `collect` | `dashboard` | 2.3.0 |
| `MfaPreferredSecondary` | `string` | attribution | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.userPreferredMethodForSecondaryAuthentication` | `collect` | `dashboard` | 2.3.0 |
| `MfaLastUpdatedDateTime` | `datetime` | freshness | `entra` | `graph.reports.authenticationMethods.userRegistrationDetails.lastUpdatedDateTime` | `collect` | `enrich` | 2.3.0 |
| `OnPremLastSyncDateTime` | `datetime` | freshness | `entra` | `graph.user.onPremisesLastSyncDateTime` | `collect` | `enrich` | 2.3.0 |
| `MdiLastSeenActivity` | `datetime` | freshness | `mdi` | `mdi.identity.lastSeenActivity` | `collect` | `enrich` | 2.3.0 |
| `EntraRoles_Permanent` | `dynamic` | risk | `entra` | `graph.roleManagement.directory.roleAssignments[?principalId==user]` | `collect` | `enrich` | 2.3.0 |
| `EntraRoles_Eligible` | `dynamic` | risk | `entra` | `graph.roleManagement.directory.roleEligibilitySchedules[?principalId==user]` | `collect` | `enrich` | 2.3.0 |
| `EntraAppPermissions_Application` | `dynamic` | risk | `entra` | `graph.servicePrincipal.appRoleAssignments` | `collect` | `enrich` | 2.3.0 |
| `EntraAppPermissions_Delegated` | `dynamic` | risk | `entra` | `graph.oauth2PermissionGrants` | `collect` | `enrich` | 2.3.0 |
| `NestedGroups` | `dynamic` | risk | `entra` | `graph.user.transitiveMemberOf (filtered to groups)` | `collect` | `enrich` | 2.3.0 |
| `AdNestedGroupNames` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.nestedAdGroupNames[*]` | `collect` | `enrich` | 2.3.0 |
| `AdNestedCriticalGroups` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.nestedCriticalAdGroups[*]` | `collect` | `enrich` | 2.3.0 |
| `AzureRoles_Assignments` | `dynamic` | risk | `azure` | `arm.roleAssignments[?principalId==user]` | `collect` | `enrich` | 2.3.0 |
| `AdminCount` | `int` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.adminCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `UserAccountControl` | `dynamic` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.userAccountControl[*]` | `collect` | `enrich`, `classify` | 2.3.0 |
| `SidHistory` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.sidHistory[*]` | `collect` | `enrich`, `classify` | 2.3.0 |
| `HasSidHistory` | `bool` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EntraRolesPermanentVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EntraRolesPermanentVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EntraRolesPermanentVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EntraRolesPermanentVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraRolesEligibleVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EntraRolesEligibleVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EntraRolesEligibleVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraRolesEligibleVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraApiPermsApplicationVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EntraApiPermsApplicationVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EntraApiPermsApplicationVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraApiPermsApplicationVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraApiPermsDelegatedVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EntraApiPermsDelegatedVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `EntraApiPermsDelegatedVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `EntraApiPermsDelegatedVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `AdBuiltinGroupsVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `AdBuiltinGroupsVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `AdBuiltinGroupsVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `AdBuiltinGroupsVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `AzureRolesVerdict_Tier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `AzureRolesVerdict_TopMatch` | `string` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `AzureRolesVerdict_MatchCount` | `int` | risk | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `AzureRolesVerdict_MissCount` | `int` | freshness | `derived` |  | `enrich` | `dashboard` | 2.3.0 |
| `IdentityTieringCatalogVersion` | `string` | freshness | `derived` |  | `enrich` | `sentinel`, `dashboard` | 2.3.0 |
| `EgCriticalityLevel` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityLevel.criticalityLevel` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EgRuleBasedCriticalityLevel` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalityLevel.ruleBasedCriticalityLevel` | `collect` | `classify` | 2.3.0 |
| `EgCriticalityRuleNamesPredefined` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `EgCriticalityRuleNamesCustom` | `dynamic` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `MdiInvestigationPriority` | `int` | risk | `mdi` | `mdi.identity.investigationPriority` | `collect` | `classify` | 2.3.0 |
| `AppId` | `string` | correlation | `entra` | `graph.servicePrincipal.appId` | `collect` | `enrich` | 2.3.0 |
| `AppOwnerOrganizationId` | `string` | posture | `entra` | `graph.servicePrincipal.appOwnerOrganizationId` | `collect` | `enrich` | 2.3.0 |
| `PublisherName` | `string` | pivot | `entra` | `graph.servicePrincipal.publisherName` | `collect` | `dashboard` | 2.3.0 |
| `ServicePrincipalType` | `string` | pivot | `entra` | `graph.servicePrincipal.servicePrincipalType` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsFirstPartyMicrosoftSpn` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsHomeTenantSpn` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsThirdPartyMultiTenantSpn` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsLegacySpn` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `MiAccountType` | `string` | pivot | `exposureGraph` | `eg.node.NodeProperties.rawData.managedIdentityMetadata.accountType` | `collect` | `enrich`, `classify` | 2.3.0 |
| `IsSystemAssignedManagedIdentity` | `bool` | pivot | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsUserAssignedManagedIdentity` | `bool` | pivot | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsExplicitManagedIdentity` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `AttachedAzureResourceId` | `string` | correlation | `derived` |  | `enrich` | `classify`, `sentinel` | 2.3.0 |
| `AttachedResourceType` | `string` | pivot | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `AttachedResourceTier` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `AttachedResourceCount` | `int` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsManagedServiceAccount` | `bool` | posture | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `IsDomainControllerAccount` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.isDomainController` | `collect` | `classify` | 2.3.0 |
| `IsExchangeServerAccount` | `bool` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `HasServicePrincipalName` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasServicePrincipalName` | `collect` | `classify` | 2.3.0 |
| `DisplayName` | `string` | pivot | `entra` | `coalesce(graph.user.displayName, graph.servicePrincipal.displayName, graph.group.displayName)` | `collect` | `dashboard` | 2.3.0 |
| `AssetName` | `string` | pivot | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.2.0 |
| `IdentityType` | `string` | pivot | `derived` |  | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `ObjectType` | `string` | pivot | `derived` |  | `collect` | `enrich`, `classify`, `dashboard` | 2.3.5 |
| `CSA` | `string` | audit | `entra` | `Concatenation of customSecurityAttributes assignments as 'set/attribute=value' pairs (e.g. 'SecurityInsight/AssetTier=tier-0; SecurityInsight/RegulatoryScope=PCI'). Source: graph.user.customSecurityAttributes / graph.servicePrincipal.customSecurityAttributes. Asset-tagging KQL parses the CSA string with extract(@"tier-(\d+)", 1, tostring(CSA)).` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.5 |
| `SecurityPrincipalType` | `string` | pivot | `derived` |  | `collect` | `enrich`, `classify` | 2.3.0 |
| `PrimaryProvider` | `string` | pivot | `derived` |  | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `Department` | `string` | pivot | `entra` | `graph.user.department` | `collect` | `dashboard` | 2.3.0 |
| `EmployeeType` | `string` | pivot | `entra` | `graph.user.employeeType` | `collect` | `dashboard` | 2.3.0 |
| `JobTitle` | `string` | pivot | `entra` | `graph.user.jobTitle` | `collect` | `dashboard` | 2.3.0 |
| `Country` | `string` | pivot | `entra` | `graph.user.country` | `collect` | `dashboard` | 2.3.0 |
| `OnPremDomainName` | `string` | pivot | `entra` | `graph.user.onPremisesDomainName` | `collect` | `dashboard` | 2.3.0 |
| `Manager` | `string` | attribution | `entra` | `graph.user.manager/$ref` | `collect` | `dashboard` | 2.3.0 |
| `ManagerUpn` | `string` | attribution | `entra` | `graph.user.manager/userPrincipalName` | `collect` | `dashboard` | 2.3.0 |
| `UsageLocation` | `string` | compliance | `entra` | `graph.user.usageLocation` | `collect` | `dashboard` | 2.3.0 |
| `PasswordPolicies` | `string` | policy | `entra` | `graph.user.passwordPolicies` | `collect` | `classify` | 2.3.0 |
| `LicenseSkuIds` | `dynamic` | compliance | `entra` | `graph.user.assignedLicenses[*].skuId` | `collect` | `dashboard` | 2.3.0 |
| `Tags` | `dynamic` | pivot | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `ExtensionAttributes` | `dynamic` | enrichment | `entra` | `graph.user.onPremisesExtensionAttributes (whole object)` | `collect` | `dashboard` | 2.3.0 |
| `CustomSecurityAttributes` | `dynamic` | compliance | `entra` | `graph.user.customSecurityAttributes` | `collect` | `dashboard` | 2.3.0 |
| `AssetSubtypeAI` | `string` | pivot | `derived` |  | `posture_analyze` | `classify`, `dashboard` | 2.3.0 |
| `AssetGroupAI` | `string` | pivot | `derived` |  | `posture_analyze` | `classify`, `dashboard` | 2.3.0 |
| `Tier` | `int` | kpi | `derived` |  | `classify` | `dashboard`, `sentinel` | 2.3.0 |
| `SIRules` | `dynamic` | audit | `derived` |  | `profile` | `dashboard`, `sentinel`, `audit` | 2.3.2 |
| `IsEnabledActive` | `bool` | freshness | `derived` |  | `profile` | `dashboard`, `sentinel` | 2.3.3 |
| `AssetGroup` | `string` | kpi | `derived` |  | `classify` | `dashboard` | 2.3.0 |
| `IsOrphanSPN` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `HasExpiringCredentials` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `CredentialExpiryDays` | `int` | freshness | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `HasNoMfa` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `HasPasswordNeverExpires` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsExternalIdentity` | `bool` | audit | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsHighRiskPermissionGrant` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `DaysInactive` | `int` | freshness | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsCmdbOrphan` | `bool` | audit | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `cmdbId` | `string` | correlation | `cmdb` | `cmdb.id (CMDB row primary key when matched at Reconcile)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbName` | `string` | correlation | `cmdb` | `cmdb.name (display name from CMDB)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbCriticality` | `string` | audit | `cmdb` | `cmdb.criticality (Critical / High / Medium / Low)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbDataSensitivity` | `string` | audit | `cmdb` | `cmdb.dataSensitivity (Restricted / Confidential / Internal / Public)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchPhase` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchState` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |

## Azure  --  `Azure_Profile_CL`

- **DCR**: `dcr-si-azure-profile`
- **Schema version**: `2.3.6` (last modified 2026-04-29)
- **Sources consumed**: `azure`, `exposureGraph`, `derived`
- **Entity-ID types** (members of `EntityIds[*]`): `AzureResourceId`, `ExposureGraphNodeId`, `AadObjectId`
- **Hub join** (master-record producer): `exposureGraph`
- **EG node labels in scope**: `microsoft.storage/storageaccounts`, `microsoft.containerregistry/registries`, `microsoft.operationalinsights/workspaces`, `microsoft.cognitiveservices/accounts`, `microsoft.cognitiveservices/accounts_openai`, `microsoft.compute/virtualmachines`, `microsoft.network/virtualnetworks`, `microsoft.network/networksecuritygroups`, `microsoft.network/applicationgateways`, `microsoft.web/serverfarms`, `microsoft.web/sites_webapp`, `microsoft.web/sites_azurefunction`, `microsoft.logic/workflows`, `microsoft.sql/servers`, `microsoft.keyvault/vaults`
- **Field count**: 314

### Fields

| Name | Type | Purpose | Source | Source path | Written by | Read by | Added in |
|---|---|---|---|---|---|---|---|
| `PrimaryEntityId` | `string` | identity | `derived` | `EntityIds[0].id (always AzureResourceId)` | `collect` | `enrich`, `posture_analyze`, `classify`, `dashboard`, `sentinel` | 2.3.0 |
| `PrimaryEntityType` | `string` | identity | `derived` | `always 'AzureResourceId'` | `collect` | `enrich`, `posture_analyze`, `classify` | 2.3.0 |
| `EntityIds` | `dynamic` | correlation | `derived` | `merged from all sources (azure + exposureGraph + derived)` | `collect` | `enrich`, `posture_analyze`, `classify`, `sentinel` | 2.3.0 |
| `RunId` | `string` | identity | `derived` | `UUID per orchestrator run` | `bootstrap` | `all` | 2.3.0 |
| `CollectionTime` | `datetime` | freshness | `derived` | `now() at output` | `classify` | `all` | 2.3.0 |
| `AzureResourceId` | `string` | correlation | `azure` | `arm.<resource>.id` | `collect` | `enrich`, `posture_analyze`, `classify`, `sentinel` | 2.3.0 |
| `AssetName` | `string` | pivot | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.2.0 |
| `AzureResourceId_Guid` | `string` | correlation | `derived` |  | `profile` | `enrich`, `classify`, `dashboard` | 2.2.0 |
| `AzSubscriptionId` | `string` | correlation | `azure` | `arm.<resource>.subscriptionId` | `collect` | `enrich`, `classify`, `dashboard` | 2.2.0 |
| `ManagementGroupId` | `string` | correlation | `azure` | `walked from parent path of subscription` | `collect` | `enrich`, `classify`, `dashboard` | 2.3.0 |
| `AzResourceGroup` | `string` | correlation | `azure` | `arm.<resource>.resourceGroup` | `collect` | `enrich`, `classify`, `dashboard` | 2.2.0 |
| `ManagedIdentityPrincipalId` | `string` | correlation | `azure` | `arm.<resource>.identity.principalId` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposureGraphNodeId` | `string` | correlation | `exposureGraph` | `eg.node.NodeId` | `collect` | `enrich`, `classify` | 2.3.0 |
| `HierarchyIdentifier` | `string` | correlation | `exposureGraph` | `eg.node.NodeProperties.rawData.hierarchyIdentifier (subscription ID for Azure)` | `collect` | `enrich`, `dashboard` | 2.3.0 |
| `CollectHash` | `string` | identity | `derived` | `SHA256 over collect-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `EnrichHash` | `string` | identity | `derived` | `SHA256 over enrich-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `PostureHash` | `string` | identity | `derived` | `SHA256 over posture-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `ClassifyHash` | `string` | identity | `derived` | `SHA256 over classify-stage fields` | `classify` | `sentinel` | 2.3.0 |
| `PublicNetworkAccess` | `string` | posture | `azure` | `arm.<resource>.properties.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `MinimumTlsVersion` | `string` | posture | `azure` | `arm.<resource>.properties.minimumTlsVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `SupportsHttpsTrafficOnly` | `bool` | posture | `azure` | `arm.storageAccounts.properties.supportsHttpsTrafficOnly` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AllowBlobPublicAccess` | `bool` | posture | `azure` | `arm.storageAccounts.properties.allowBlobPublicAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AllowSharedKeyAccess` | `bool` | posture | `azure` | `arm.storageAccounts.properties.allowSharedKeyAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EncryptionAtRestEnabled` | `bool` | posture | `azure` | `arm.<resource>.properties.encryption.* (varies per RP)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EnablePurgeProtection` | `bool` | posture | `azure` | `arm.keyVaults.properties.enablePurgeProtection` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EnableSoftDelete` | `bool` | posture | `azure` | `arm.keyVaults.properties.enableSoftDelete` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EnableRbacAuthorization` | `bool` | posture | `azure` | `arm.keyVaults.properties.enableRbacAuthorization` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AdminUserEnabled` | `bool` | posture | `azure` | `arm.containerRegistries.properties.adminUserEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AnonymousPullEnabled` | `bool` | posture | `azure` | `arm.containerRegistries.properties.anonymousPullEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `DisableLocalAuth` | `bool` | posture | `azure` | `arm.cognitiveServices.properties.disableLocalAuth` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ChangedTime` | `datetime` | freshness | `azure` | `arm.<resource>.changedTime` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposedToInternet` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.type == 'InternetExposure'` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ExposureEvidenceNodeIds` | `dynamic` | forensic | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.evidence.nodeIds[*] (graph-traversal proof for inherited exposure)` | `collect` | `classify`, `sentinel` | 2.3.0 |
| `ExposureEvidenceEdgeIds` | `dynamic` | forensic | `exposureGraph` | `eg.node.NodeProperties.rawData.exposedToInternet.evidence.edgeIds[*]` | `collect` | `classify`, `sentinel` | 2.3.0 |
| `IdentifiedResourceUsersHighPrivCount` | `int` | risk | `derived` |  | `enrich` | `classify`, `dashboard` | 2.3.0 |
| `HighestRiskRbacRole` | `string` | risk | `derived` |  | `enrich` | `classify` | 2.3.0 |
| `NetworkAclMode` | `string` | risk | `azure` | `arm.<resource>.properties.networkAcls.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `AllowsPublicAccess` | `string` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.allowsPublicAccess (Enabled/Disabled)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `ServerlessAppServicePlan` | `string` | correlation | `exposureGraph` | `eg.node.NodeProperties.rawData.azureComputeServerlessMetadata.appServicePlan (parent ASP ARM ID)` | `collect` | `enrich` | 2.3.0 |
| `ServerlessIdentityProvider` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.azureComputeServerlessMetadata.identityProvider (empty = anonymous = posture risk)` | `collect` | `enrich`, `classify` | 2.3.0 |
| `VmId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.vmId (used to join MDE)` | `collect` | `enrich`, `classify` | 2.3.1 |
| `OsDiskEncryptionAtHost` | `bool` | posture | `azure` | `arm.virtualMachines.properties.securityProfile.encryptionAtHost` | `collect` | `classify` | 2.3.1 |
| `OsDiskEncryptionDiskSetId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.storageProfile.osDisk.managedDisk.diskEncryptionSet.id` | `collect` | `enrich` | 2.3.1 |
| `SecurityType` | `string` | posture | `azure` | `arm.virtualMachines.properties.securityProfile.securityType (TrustedLaunch/ConfidentialVM)` | `collect` | `classify` | 2.3.1 |
| `SecureBootEnabled` | `bool` | posture | `azure` | `arm.virtualMachines.properties.securityProfile.uefiSettings.secureBootEnabled` | `collect` | `classify` | 2.3.1 |
| `VTpmEnabled` | `bool` | posture | `azure` | `arm.virtualMachines.properties.securityProfile.uefiSettings.vTpmEnabled` | `collect` | `classify` | 2.3.1 |
| `AdminUsername` | `string` | risk | `azure` | `arm.virtualMachines.properties.osProfile.adminUsername (well-known names = brute-force surface)` | `collect` | `classify` | 2.3.1 |
| `AssignedHostId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.host.id (dedicated host)` | `collect` | `enrich` | 2.3.1 |
| `ProximityPlacementGroupId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.proximityPlacementGroup.id` | `collect` | `enrich` | 2.3.1 |
| `AvailabilitySetId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.availabilitySet.id` | `collect` | `enrich` | 2.3.1 |
| `VirtualMachineScaleSetId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.virtualMachineScaleSet.id` | `collect` | `enrich` | 2.3.1 |
| `HostGroupId` | `string` | correlation | `azure` | `arm.virtualMachines.properties.hostGroup.id` | `collect` | `enrich` | 2.3.1 |
| `PatchModeWindows` | `string` | posture | `azure` | `arm.virtualMachines.properties.osProfile.windowsConfiguration.patchSettings.patchMode` | `collect` | `classify` | 2.3.1 |
| `PatchModeLinux` | `string` | posture | `azure` | `arm.virtualMachines.properties.osProfile.linuxConfiguration.patchSettings.patchMode` | `collect` | `classify` | 2.3.1 |
| `DisablePasswordAuthentication` | `bool` | posture | `azure` | `arm.virtualMachines.properties.osProfile.linuxConfiguration.disablePasswordAuthentication` | `collect` | `classify` | 2.3.1 |
| `Tier` | `int` | kpi | `derived` |  | `classify` | `dashboard`, `sentinel` | 2.3.0 |
| `SIRules` | `dynamic` | audit | `derived` |  | `profile` | `dashboard`, `sentinel`, `audit` | 2.3.2 |
| `IsEnabledActive` | `bool` | freshness | `derived` |  | `profile` | `dashboard`, `sentinel` | 2.3.3 |
| `Verdict` | `string` | kpi | `derived` |  | `classify` | `dashboard`, `sentinel` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_VmJustInTimeAccessEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.justInTimeAccess.enabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_VmJustInTimeAccessStatus` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.justInTimeAccess.status` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_VmVulnerableSoftwareCount` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.vulnerableSoftwareCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_VmHighSeverityVulnCount` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.highSeverityVulnerabilityCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_VmCriticalSeverityVulnCount` | `int` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.criticalSeverityVulnerabilityCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_VmHandlesSensitiveData` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.handlesSensitiveData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_SubnetPrivateEndpointNetworkPolicies` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.privateEndpointNetworkPolicies` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_LawPublicNetworkAccessForIngestion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccessForIngestion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_LawPublicNetworkAccessForQuery` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccessForQuery` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_LawDisableLocalAuth` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.features.disableLocalAuth` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_VnetEnableDdosProtection` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enableDdosProtection` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_SqlDbTransparentDataEncryption` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.transparentDataEncryption.state` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlDbHandlesSensitiveData` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.handlesSensitiveData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlDbDataClassificationLabels` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.dataSensitivity.classificationLabels` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_KvPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnableRbacAuthorization` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enableRbacAuthorization` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnableSoftDelete` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enableSoftDelete` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnablePurgeProtection` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enablePurgeProtection` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnabledForDeployment` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enabledForDeployment` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnabledForTemplateDeployment` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enabledForTemplateDeployment` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvEnabledForDiskEncryption` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.enabledForDiskEncryption` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_KvNetworkAclDefaultAction` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.networkAcls.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_LogicAppHttpTriggerExposed` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasExposedHttpTrigger` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_NsgInboundSshOpenToInternet` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasInboundSshOpenToInternet` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_NsgInboundRdpOpenToInternet` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasInboundRdpOpenToInternet` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_CogDepRaiPolicyName` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.raiPolicyName` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_StPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StAllowBlobPublicAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.allowBlobPublicAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StAllowSharedKeyAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.allowSharedKeyAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StSupportsHttpsTrafficOnly` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.supportsHttpsTrafficOnly` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StMinimumTlsVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.minimumTlsVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StIsHnsEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isHnsEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StIsSftpEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isSftpEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StIsLocalUserEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isLocalUserEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StNetworkAclDefaultAction` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.networkAcls.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StBlobAnonymousContainerCount` | `int` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.blobAnonymousContainerCount` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StRequireInfrastructureEncryption` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.encryption.requireInfrastructureEncryption` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StHandlesSensitiveData` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.handlesSensitiveData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_StDataClassificationLabels` | `dynamic` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.dataSensitivity.classificationLabels` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_AoaiPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AoaiDisableLocalAuth` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.disableLocalAuth` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AoaiNetworkAclDefaultAction` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.networkAcls.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AoaiHandlesSensitiveData` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.handlesSensitiveData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_SqlFwIsAllowAllAzureServices` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isAllowAllAzureServices` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlFwIsOpenToInternet` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.isOpenToInternet` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_FuncIdentityProvider` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.azureComputeServerlessMetadata.identityProvider` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncHttpsOnly` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.httpsOnly` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncMinTlsVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.siteConfig.minTlsVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncFtpsState` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.siteConfig.ftpsState` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncAuthEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.authSettings.enabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_FuncAllowsPublicAccess` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.allowsPublicAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_SqlSrvAzureADOnlyAuthentication` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.administrators.azureADOnlyAuthentication` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlSrvPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlSrvMinimalTlsVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.minimalTlsVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_SqlSrvRestrictOutboundNetworkAccess` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.restrictOutboundNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_WebIdentityProvider` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.azureComputeServerlessMetadata.identityProvider` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebHttpsOnly` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.httpsOnly` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebMinTlsVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.siteConfig.minTlsVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebFtpsState` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.siteConfig.ftpsState` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebClientCertEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.clientCertEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebClientCertMode` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.clientCertMode` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebAuthEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.authSettings.enabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_WebAllowsPublicAccess` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.allowsPublicAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_CogPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_CogDisableLocalAuth` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.disableLocalAuth` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_CogNetworkAclDefaultAction` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.networkAcls.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_CogHandlesSensitiveData` | `bool` | risk | `exposureGraph` | `eg.node.NodeProperties.rawData.handlesSensitiveData` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_AcrAdminUserEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.adminUserEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrAnonymousPullEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.anonymousPullEnabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrPublicNetworkAccess` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.publicNetworkAccess` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrNetworkRuleSetDefaultAction` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.networkRuleSet.defaultAction` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrPolicyExportPolicyStatus` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.policies.exportPolicy.status` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrPolicyTrustPolicyStatus` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.policies.trustPolicy.status` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AcrEncryptionStatus` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.encryption.status` | `collect` | `enrich`, `classify` | 2.3.0 |
| `` |  |  |  |  |  |  |  |
| `EG_AgwWafEnabled` | `bool` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.webApplicationFirewallConfiguration.enabled` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AgwWafFirewallMode` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.webApplicationFirewallConfiguration.firewallMode` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AgwSslPolicyMinProtocolVersion` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.sslPolicy.minProtocolVersion` | `collect` | `enrich`, `classify` | 2.3.0 |
| `EG_AgwHasPublicFrontendIp` | `string` | posture | `exposureGraph` | `eg.node.NodeProperties.rawData.hasPublicFrontendIp` | `collect` | `enrich`, `classify` | 2.3.0 |
| `PipAddress` | `string` | risk | `azure` | `arm.publicIPAddresses.properties.ipAddress` | `collect` | `enrich`, `classify` | 2.3.1 |
| `PipDdosProtectionMode` | `string` | posture | `azure` | `arm.publicIPAddresses.properties.ddosSettings.protectionMode` | `collect` | `classify` | 2.3.1 |
| `PipDdosPlanId` | `string` | correlation | `azure` | `arm.publicIPAddresses.properties.ddosSettings.ddosProtectionPlan.id` | `collect` | `enrich` | 2.3.1 |
| `PipAttachedResourceId` | `string` | correlation | `azure` | `arm.publicIPAddresses.properties.ipConfiguration.id` | `collect` | `enrich`, `classify` | 2.3.1 |
| `PipNatGatewayId` | `string` | correlation | `azure` | `arm.publicIPAddresses.properties.natGateway.id` | `collect` | `enrich` | 2.3.1 |
| `PipPublicIPPrefixId` | `string` | correlation | `azure` | `arm.publicIPAddresses.properties.publicIPPrefix.id` | `collect` | `enrich` | 2.3.1 |
| `PipServicePublicIPAddress` | `string` | correlation | `azure` | `arm.publicIPAddresses.properties.servicePublicIPAddress.id` | `collect` | `enrich` | 2.3.1 |
| `NicEnableIPForwarding` | `bool` | posture | `azure` | `arm.networkInterfaces.properties.enableIPForwarding` | `collect` | `classify` | 2.3.1 |
| `NicNsgId` | `string` | correlation | `azure` | `arm.networkInterfaces.properties.networkSecurityGroup.id` | `collect` | `enrich`, `classify` | 2.3.1 |
| `NicVirtualMachineId` | `string` | correlation | `azure` | `arm.networkInterfaces.properties.virtualMachine.id` | `collect` | `enrich`, `classify` | 2.3.1 |
| `NicMacAddress` | `string` | correlation | `azure` | `arm.networkInterfaces.properties.macAddress` | `collect` | `enrich` | 2.3.1 |
| `NicHasPublicIp` | `bool` | risk | `azure` | `isnotnull(arm.networkInterfaces.properties.ipConfigurations[0].properties.publicIPAddress.id)` | `collect` | `classify` | 2.3.1 |
| `NicPublicIpIds` | `dynamic` | correlation | `azure` | `arm.networkInterfaces.properties.ipConfigurations[*].properties.publicIPAddress.id` | `collect` | `enrich` | 2.3.1 |
| `NicSubnetIds` | `dynamic` | correlation | `azure` | `arm.networkInterfaces.properties.ipConfigurations[*].properties.subnet.id` | `collect` | `enrich` | 2.3.1 |
| `NicPrivateIpAddresses` | `dynamic` | correlation | `azure` | `arm.networkInterfaces.properties.ipConfigurations[*].properties.privateIPAddress` | `collect` | `enrich` | 2.3.1 |
| `ExtType` | `string` | pivot | `azure` | `arm.virtualMachines/extensions.properties.type (e.g. MDE.Windows)` | `collect` | `enrich`, `classify` | 2.3.1 |
| `ExtSettingsJson` | `string` | forensic | `azure` | `arm.virtualMachines/extensions.properties.settings (non-secret config only)` | `collect` | `enrich` | 2.3.1 |
| `ExtParentVmId` | `string` | correlation | `azure` | `derived: ARM-id prefix of the extension` | `collect` | `enrich` | 2.3.1 |
| `SubnetNsgId` | `string` | correlation | `azure` | `arm.subnets.properties.networkSecurityGroup.id` | `collect` | `enrich`, `classify` | 2.3.1 |
| `SubnetRouteTableId` | `string` | correlation | `azure` | `arm.subnets.properties.routeTable.id` | `collect` | `enrich` | 2.3.1 |
| `SubnetNatGatewayId` | `string` | correlation | `azure` | `arm.subnets.properties.natGateway.id` | `collect` | `enrich` | 2.3.1 |
| `SubnetDefaultOutboundAccess` | `bool` | posture | `azure` | `arm.subnets.properties.defaultOutboundAccess` | `collect` | `classify` | 2.3.1 |
| `SubnetParentVnetId` | `string` | correlation | `azure` | `derived: ARM-id prefix of the subnet` | `collect` | `enrich` | 2.3.1 |
| `LawCustomerId` | `string` | correlation | `azure` | `arm.workspaces.properties.customerId` | `collect` | `enrich`, `classify` | 2.3.1 |
| `LawRetentionInDays` | `int` | posture | `azure` | `arm.workspaces.properties.retentionInDays` | `collect` | `classify` | 2.3.1 |
| `LawPublicNetworkAccessForIngestion` | `string` | posture | `azure` | `arm.workspaces.properties.publicNetworkAccessForIngestion` | `collect` | `classify` | 2.3.1 |
| `LawPublicNetworkAccessForQuery` | `string` | posture | `azure` | `arm.workspaces.properties.publicNetworkAccessForQuery` | `collect` | `classify` | 2.3.1 |
| `LawDisableLocalAuth` | `bool` | posture | `azure` | `arm.workspaces.properties.features.disableLocalAuth` | `collect` | `classify` | 2.3.1 |
| `LawCmkKeyVaultUri` | `string` | correlation | `azure` | `arm.workspaces.properties.features.clusterResourceId` | `collect` | `enrich` | 2.3.1 |
| `LawModifiedDate` | `datetime` | freshness | `azure` | `arm.workspaces.properties.modifiedDate` | `collect` | `enrich` | 2.3.1 |
| `VnetEnableDdosProtection` | `bool` | posture | `azure` | `arm.virtualNetworks.properties.enableDdosProtection` | `collect` | `classify` | 2.3.1 |
| `VnetDdosProtectionPlanId` | `string` | correlation | `azure` | `arm.virtualNetworks.properties.ddosProtectionPlan.id` | `collect` | `enrich` | 2.3.1 |
| `VnetPeeringIds` | `dynamic` | correlation | `azure` | `arm.virtualNetworks.properties.virtualNetworkPeerings[*].properties.remoteVirtualNetwork.id` | `collect` | `enrich` | 2.3.1 |
| `VnetEncryptionEnabled` | `bool` | posture | `azure` | `arm.virtualNetworks.properties.encryption.enabled` | `collect` | `classify` | 2.3.1 |
| `SqlDbDatabaseId` | `string` | correlation | `azure` | `arm.servers/databases.properties.databaseId` | `collect` | `enrich` | 2.3.1 |
| `SqlDbRequestedBackupStorageRedundancy` | `string` | posture | `azure` | `arm.servers/databases.properties.requestedBackupStorageRedundancy` | `collect` | `classify` | 2.3.1 |
| `SqlDbMaintenanceConfigurationId` | `string` | correlation | `azure` | `arm.servers/databases.properties.maintenanceConfigurationId` | `collect` | `enrich` | 2.3.1 |
| `SqlDbElasticPoolId` | `string` | correlation | `azure` | `arm.servers/databases.properties.elasticPoolId` | `collect` | `enrich` | 2.3.1 |
| `SqlDbSourceDatabaseId` | `string` | correlation | `azure` | `arm.servers/databases.properties.sourceDatabaseId` | `collect` | `enrich` | 2.3.1 |
| `SqlDbParentServerId` | `string` | correlation | `azure` | `derived: ARM-id prefix of the database` | `collect` | `enrich` | 2.3.1 |
| `KvPublicNetworkAccess` | `string` | posture | `azure` | `arm.vaults.properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `KvNetworkAclsDefaultAction` | `string` | posture | `azure` | `arm.vaults.properties.networkAcls.defaultAction` | `collect` | `classify` | 2.3.1 |
| `KvEnableRbacAuthorization` | `bool` | posture | `azure` | `arm.vaults.properties.enableRbacAuthorization` | `collect` | `classify` | 2.3.1 |
| `KvEnableSoftDelete` | `bool` | posture | `azure` | `arm.vaults.properties.enableSoftDelete` | `collect` | `classify` | 2.3.1 |
| `KvEnablePurgeProtection` | `bool` | posture | `azure` | `arm.vaults.properties.enablePurgeProtection` | `collect` | `classify` | 2.3.1 |
| `KvTenantId` | `string` | correlation | `azure` | `arm.vaults.properties.tenantId` | `collect` | `enrich` | 2.3.1 |
| `KvVaultUri` | `string` | correlation | `azure` | `arm.vaults.properties.vaultUri` | `collect` | `enrich` | 2.3.1 |
| `KvHsmPoolResourceId` | `string` | correlation | `azure` | `arm.vaults.properties.hsmPoolResourceId` | `collect` | `enrich` | 2.3.1 |
| `LaIntegrationAccountId` | `string` | correlation | `azure` | `arm.workflows.properties.integrationAccount.id` | `collect` | `enrich` | 2.3.1 |
| `LaIntegrationServiceEnvId` | `string` | correlation | `azure` | `arm.workflows.properties.integrationServiceEnvironment.id` | `collect` | `enrich` | 2.3.1 |
| `LaAccessControlActionsAllowed` | `string` | posture | `azure` | `arm.workflows.properties.accessControl.actions.allowedCallerIpAddresses` | `collect` | `classify` | 2.3.1 |
| `LaAccessControlTriggers` | `string` | posture | `azure` | `arm.workflows.properties.accessControl.triggers.allowedCallerIpAddresses` | `collect` | `classify` | 2.3.1 |
| `LaEndpointsConnector` | `string` | correlation | `azure` | `arm.workflows.properties.endpointsConfiguration.connector.outgoingIpAddresses` | `collect` | `enrich` | 2.3.1 |
| `LaParameters` | `string` | forensic | `azure` | `arm.workflows.properties.parameters (parameter shape only; values may be redacted)` | `collect` | `enrich` | 2.3.1 |
| `LaChangedTime` | `datetime` | freshness | `azure` | `arm.workflows.properties.changedTime` | `collect` | `enrich` | 2.3.1 |
| `NsgInboundAllowAnyCount` | `int` | risk | `azure` | `derived: count(securityRules[direction=Inbound,access=Allow,source=Any])` | `collect` | `classify` | 2.3.1 |
| `NsgInboundAllowInternetCount` | `int` | risk | `azure` | `derived: count(securityRules[direction=Inbound,access=Allow,source=Internet])` | `collect` | `classify` | 2.3.1 |
| `NsgInboundAllowRdpCount` | `int` | risk | `azure` | `derived: count(securityRules[direction=Inbound,access=Allow,destinationPortRange contains 3389])` | `collect` | `classify` | 2.3.1 |
| `NsgInboundAllowSshCount` | `int` | risk | `azure` | `derived: count(securityRules[direction=Inbound,access=Allow,destinationPortRange contains 22])` | `collect` | `classify` | 2.3.1 |
| `NsgAttachedNicIds` | `dynamic` | correlation | `azure` | `arm.networkSecurityGroups.properties.networkInterfaces[*].id` | `collect` | `enrich` | 2.3.1 |
| `NsgAttachedSubnetIds` | `dynamic` | correlation | `azure` | `arm.networkSecurityGroups.properties.subnets[*].id` | `collect` | `enrich` | 2.3.1 |
| `NsgSecurityRulesJson` | `string` | forensic | `azure` | `arm.networkSecurityGroups.properties.securityRules (full rule set as JSON)` | `collect` | `enrich`, `classify` | 2.3.1 |
| `DeplRaiPolicyName` | `string` | posture | `azure` | `arm.accounts/deployments.properties.raiPolicyName` | `collect` | `classify` | 2.3.1 |
| `DeplParentAccountId` | `string` | correlation | `azure` | `derived: ARM-id prefix of the deployment` | `collect` | `enrich` | 2.3.1 |
| `StPublicNetworkAccess` | `string` | posture | `azure` | `arm.storageAccounts.properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `StAllowBlobPublicAccess` | `bool` | posture | `azure` | `arm.storageAccounts.properties.allowBlobPublicAccess` | `collect` | `classify` | 2.3.1 |
| `StAllowSharedKeyAccess` | `bool` | posture | `azure` | `arm.storageAccounts.properties.allowSharedKeyAccess` | `collect` | `classify` | 2.3.1 |
| `StAllowCrossTenantReplication` | `bool` | posture | `azure` | `arm.storageAccounts.properties.allowCrossTenantReplication` | `collect` | `classify` | 2.3.1 |
| `StMinimumTlsVersion` | `string` | posture | `azure` | `arm.storageAccounts.properties.minimumTlsVersion` | `collect` | `classify` | 2.3.1 |
| `StSupportsHttpsTrafficOnly` | `bool` | posture | `azure` | `arm.storageAccounts.properties.supportsHttpsTrafficOnly` | `collect` | `classify` | 2.3.1 |
| `StNetworkAclsDefaultAction` | `string` | posture | `azure` | `arm.storageAccounts.properties.networkAcls.defaultAction` | `collect` | `classify` | 2.3.1 |
| `StEncryptionKeySource` | `string` | posture | `azure` | `arm.storageAccounts.properties.encryption.keySource (Microsoft.Storage/Microsoft.Keyvault)` | `collect` | `classify` | 2.3.1 |
| `StEncryptionKeyVaultUri` | `string` | correlation | `azure` | `arm.storageAccounts.properties.encryption.keyvaultproperties.keyvaulturi` | `collect` | `enrich` | 2.3.1 |
| `StEncryptionKeyName` | `string` | correlation | `azure` | `arm.storageAccounts.properties.encryption.keyvaultproperties.keyname` | `collect` | `enrich` | 2.3.1 |
| `StEncryptionKeyVersion` | `string` | correlation | `azure` | `arm.storageAccounts.properties.encryption.keyvaultproperties.keyversion` | `collect` | `enrich` | 2.3.1 |
| `StIsNfsV3Enabled` | `bool` | posture | `azure` | `arm.storageAccounts.properties.isNfsV3Enabled` | `collect` | `classify` | 2.3.1 |
| `StIsSftpEnabled` | `bool` | posture | `azure` | `arm.storageAccounts.properties.isSftpEnabled` | `collect` | `classify` | 2.3.1 |
| `StKeyPolicyExpirationDays` | `int` | posture | `azure` | `arm.storageAccounts.properties.keyPolicy.keyExpirationPeriodInDays` | `collect` | `classify` | 2.3.1 |
| `AoaiPublicNetworkAccess` | `string` | posture | `azure` | `arm.cognitiveServices(OpenAI).properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `AoaiDisableLocalAuth` | `bool` | posture | `azure` | `arm.cognitiveServices(OpenAI).properties.disableLocalAuth` | `collect` | `classify` | 2.3.1 |
| `AoaiEncryptionKeySource` | `string` | posture | `azure` | `arm.cognitiveServices.properties.encryption.keySource` | `collect` | `classify` | 2.3.1 |
| `AoaiEncryptionKeyVaultUri` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.encryption.keyVaultProperties.keyVaultUri` | `collect` | `enrich` | 2.3.1 |
| `AoaiEncryptionKeyName` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.encryption.keyVaultProperties.keyName` | `collect` | `enrich` | 2.3.1 |
| `AoaiApiProperties` | `string` | forensic | `azure` | `arm.cognitiveServices.properties.apiProperties (kind-specific configuration)` | `collect` | `enrich` | 2.3.1 |
| `AoaiEndpoint` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.endpoint` | `collect` | `enrich` | 2.3.1 |
| `AoaiEndpoints` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.endpoints (per-feature endpoint map)` | `collect` | `enrich` | 2.3.1 |
| `SqlFwAllowsAllAzureIPs` | `bool` | posture | `azure` | `derived: start=0.0.0.0 AND end=0.0.0.0` | `collect` | `classify` | 2.3.1 |
| `SqlFwAllowsAllIPv4` | `bool` | risk | `azure` | `derived: start=0.0.0.0 AND end=255.255.255.255` | `collect` | `classify` | 2.3.1 |
| `SqlFwParentServerId` | `string` | correlation | `azure` | `derived: ARM-id prefix of the firewall rule` | `collect` | `enrich` | 2.3.1 |
| `FuncHttpsOnly` | `bool` | posture | `azure` | `arm.sites(functionapp).properties.httpsOnly` | `collect` | `classify` | 2.3.1 |
| `FuncPublicNetworkAccess` | `string` | posture | `azure` | `arm.sites(functionapp).properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `FuncMinTlsVersion` | `string` | posture | `azure` | `arm.sites(functionapp).properties.siteConfig.minTlsVersion` | `collect` | `classify` | 2.3.1 |
| `FuncFtpsState` | `string` | posture | `azure` | `arm.sites(functionapp).properties.siteConfig.ftpsState` | `collect` | `classify` | 2.3.1 |
| `FuncRemoteDebuggingEnabled` | `bool` | posture | `azure` | `arm.sites(functionapp).properties.siteConfig.remoteDebuggingEnabled` | `collect` | `classify` | 2.3.1 |
| `FuncVnetSubnetId` | `string` | correlation | `azure` | `arm.sites(functionapp).properties.virtualNetworkSubnetId` | `collect` | `enrich`, `classify` | 2.3.1 |
| `FuncManagedEnvironmentId` | `string` | correlation | `azure` | `arm.sites(functionapp).properties.managedEnvironmentId` | `collect` | `enrich` | 2.3.1 |
| `FuncKeyVaultReferenceIdentity` | `string` | correlation | `azure` | `arm.sites(functionapp).properties.keyVaultReferenceIdentity` | `collect` | `enrich` | 2.3.1 |
| `FuncServerFarmId` | `string` | correlation | `azure` | `arm.sites(functionapp).properties.serverFarmId` | `collect` | `enrich` | 2.3.1 |
| `FuncCorsAllowedOrigins` | `dynamic` | posture | `azure` | `arm.sites(functionapp).properties.siteConfig.cors.allowedOrigins` | `collect` | `classify` | 2.3.1 |
| `FuncAuthEnabled` | `bool` | posture | `azure` | `arm.sites(functionapp).properties.siteAuthEnabled` | `collect` | `classify` | 2.3.1 |
| `SqlSrvMinimalTlsVersion` | `string` | posture | `azure` | `arm.servers.properties.minimalTlsVersion` | `collect` | `classify` | 2.3.1 |
| `SqlSrvPublicNetworkAccess` | `string` | posture | `azure` | `arm.servers.properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `SqlSrvAdminAzureADOnlyAuth` | `bool` | posture | `azure` | `arm.servers.properties.administrators.azureADOnlyAuthentication` | `collect` | `classify` | 2.3.1 |
| `SqlSrvAdminLogin` | `string` | correlation | `azure` | `arm.servers.properties.administrators.login` | `collect` | `enrich` | 2.3.1 |
| `SqlSrvAdminSid` | `string` | correlation | `azure` | `arm.servers.properties.administrators.sid` | `collect` | `enrich` | 2.3.1 |
| `SqlSrvAdminTenantId` | `string` | correlation | `azure` | `arm.servers.properties.administrators.tenantId` | `collect` | `enrich` | 2.3.1 |
| `SqlSrvFederatedClientId` | `string` | correlation | `azure` | `arm.servers.properties.federatedClientId` | `collect` | `enrich` | 2.3.1 |
| `SqlSrvPrimaryUserAssignedId` | `string` | correlation | `azure` | `arm.servers.properties.primaryUserAssignedIdentityId` | `collect` | `enrich` | 2.3.1 |
| `SqlSrvFqdn` | `string` | correlation | `azure` | `arm.servers.properties.fullyQualifiedDomainName` | `collect` | `enrich` | 2.3.1 |
| `WebHttpsOnly` | `bool` | posture | `azure` | `arm.sites(webapp).properties.httpsOnly` | `collect` | `classify` | 2.3.1 |
| `WebPublicNetworkAccess` | `string` | posture | `azure` | `arm.sites(webapp).properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `WebMinTlsVersion` | `string` | posture | `azure` | `arm.sites(webapp).properties.siteConfig.minTlsVersion` | `collect` | `classify` | 2.3.1 |
| `WebFtpsState` | `string` | posture | `azure` | `arm.sites(webapp).properties.siteConfig.ftpsState` | `collect` | `classify` | 2.3.1 |
| `WebRemoteDebuggingEnabled` | `bool` | posture | `azure` | `arm.sites(webapp).properties.siteConfig.remoteDebuggingEnabled` | `collect` | `classify` | 2.3.1 |
| `WebVnetSubnetId` | `string` | correlation | `azure` | `arm.sites(webapp).properties.virtualNetworkSubnetId` | `collect` | `enrich`, `classify` | 2.3.1 |
| `WebSiteAuthEnabled` | `bool` | posture | `azure` | `arm.sites(webapp).properties.siteAuthEnabled` | `collect` | `classify` | 2.3.1 |
| `WebManagedEnvironmentId` | `string` | correlation | `azure` | `arm.sites(webapp).properties.managedEnvironmentId` | `collect` | `enrich` | 2.3.1 |
| `WebKeyVaultReferenceIdentity` | `string` | correlation | `azure` | `arm.sites(webapp).properties.keyVaultReferenceIdentity` | `collect` | `enrich` | 2.3.1 |
| `WebServerFarmId` | `string` | correlation | `azure` | `arm.sites(webapp).properties.serverFarmId` | `collect` | `enrich` | 2.3.1 |
| `WebCorsAllowedOrigins` | `dynamic` | posture | `azure` | `arm.sites(webapp).properties.siteConfig.cors.allowedOrigins` | `collect` | `classify` | 2.3.1 |
| `CogPublicNetworkAccess` | `string` | posture | `azure` | `arm.cognitiveServices(non-OpenAI).properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `CogDisableLocalAuth` | `bool` | posture | `azure` | `arm.cognitiveServices(non-OpenAI).properties.disableLocalAuth` | `collect` | `classify` | 2.3.1 |
| `CogEncryptionKeyVaultUri` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.encryption.keyVaultProperties.keyVaultUri` | `collect` | `enrich` | 2.3.1 |
| `CogApiProperties` | `string` | forensic | `azure` | `arm.cognitiveServices.properties.apiProperties` | `collect` | `enrich` | 2.3.1 |
| `CogEndpoint` | `string` | correlation | `azure` | `arm.cognitiveServices.properties.endpoint` | `collect` | `enrich` | 2.3.1 |
| `AcrAdminUserEnabled` | `bool` | posture | `azure` | `arm.registries.properties.adminUserEnabled` | `collect` | `classify` | 2.3.1 |
| `AcrPublicNetworkAccess` | `string` | posture | `azure` | `arm.registries.properties.publicNetworkAccess` | `collect` | `classify` | 2.3.1 |
| `AcrAnonymousPullEnabled` | `bool` | posture | `azure` | `arm.registries.properties.anonymousPullEnabled` | `collect` | `classify` | 2.3.1 |
| `AcrNetworkRuleSetDefaultAction` | `string` | posture | `azure` | `arm.registries.properties.networkRuleSet.defaultAction` | `collect` | `classify` | 2.3.1 |
| `AcrTrustPolicyStatus` | `string` | posture | `azure` | `arm.registries.properties.policies.trustPolicy.status` | `collect` | `classify` | 2.3.1 |
| `AcrSoftDeletePolicyStatus` | `string` | posture | `azure` | `arm.registries.properties.policies.softDeletePolicy.status` | `collect` | `classify` | 2.3.1 |
| `AcrEncryptionStatus` | `string` | posture | `azure` | `arm.registries.properties.encryption.status` | `collect` | `classify` | 2.3.1 |
| `AcrEncryptionKeyVaultId` | `string` | correlation | `azure` | `arm.registries.properties.encryption.keyVaultProperties.keyIdentifier` | `collect` | `enrich` | 2.3.1 |
| `AcrDedicatedDataEndpoints` | `dynamic` | correlation | `azure` | `arm.registries.properties.dataEndpointHostNames` | `collect` | `enrich` | 2.3.1 |
| `AcrLoginServer` | `string` | correlation | `azure` | `arm.registries.properties.loginServer` | `collect` | `enrich` | 2.3.1 |
| `AiProjDefaultProject` | `string` | correlation | `azure` | `arm.cognitiveServices(Hub).properties.defaultProject` | `collect` | `enrich` | 2.3.1 |
| `AiProjAssociatedProjects` | `dynamic` | correlation | `azure` | `arm.cognitiveServices(Hub).properties.associatedProjects` | `collect` | `enrich` | 2.3.1 |
| `AiProjEncryptionKeyVaultUri` | `string` | correlation | `azure` | `arm.cognitiveServices(AIServices/Hub/Project).properties.encryption.keyVaultProperties.keyVaultUri` | `collect` | `enrich` | 2.3.1 |
| `AiProjEndpoint` | `string` | correlation | `azure` | `arm.cognitiveServices(AIServices/Hub/Project).properties.endpoint` | `collect` | `enrich` | 2.3.1 |
| `AiProjEndpoints` | `string` | correlation | `azure` | `arm.cognitiveServices(AIServices/Hub/Project).properties.endpoints` | `collect` | `enrich` | 2.3.1 |
| `AgwSkuTier` | `string` | posture | `azure` | `arm.applicationGateways.properties.sku.tier (Standard_v2 = no WAF)` | `collect` | `classify` | 2.3.1 |
| `AgwWafEnabled` | `bool` | posture | `azure` | `arm.applicationGateways.properties.webApplicationFirewallConfiguration.enabled` | `collect` | `classify` | 2.3.1 |
| `AgwWafFirewallMode` | `string` | posture | `azure` | `arm.applicationGateways.properties.webApplicationFirewallConfiguration.firewallMode (Detection vs Prevention)` | `collect` | `classify` | 2.3.1 |
| `AgwFirewallPolicyId` | `string` | correlation | `azure` | `arm.applicationGateways.properties.firewallPolicy.id` | `collect` | `enrich` | 2.3.1 |
| `AgwSslMinProtocolVersion` | `string` | posture | `azure` | `arm.applicationGateways.properties.sslPolicy.minProtocolVersion` | `collect` | `classify` | 2.3.1 |
| `AgwFrontendPublicIpCount` | `int` | risk | `azure` | `derived: count(frontendIPConfigurations where publicIPAddress != null)` | `collect` | `classify` | 2.3.1 |
| `IsPubliclyExposed` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `HasNoSoftDelete` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `UnencryptedTraffic` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `HasOpenAdminPort` | `bool` | risk | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `IsCmdbOrphan` | `bool` | audit | `derived` |  | `profile` | `dashboard`, `risk_analysis` | 2.3.4 |
| `cmdbId` | `string` | correlation | `cmdb` | `cmdb.id (CMDB row primary key when matched at Reconcile)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbName` | `string` | correlation | `cmdb` | `cmdb.name (display name from CMDB)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbCriticality` | `string` | audit | `cmdb` | `cmdb.criticality (Critical / High / Medium / Low)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `cmdbDataSensitivity` | `string` | audit | `cmdb` | `cmdb.dataSensitivity (Restricted / Confidential / Internal / Public)` | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchPhase` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |
| `CmdbMatchState` | `string` | audit | `derived` |  | `reconcile` | `risk_analysis`, `dashboard` | 2.3.6 |

