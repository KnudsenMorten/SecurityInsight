---
typora-root-url: ./Images
---

# SecurityInsight
Rethink Secure Score into a new risk-based security risk score, based on consequence, probability and risk factors. Solution includes critical asset tagging, ready-to-use reports (based on Defender Exposure Graph and Azure Resource Graphs), automation-scripts, risk index and more



## The Challenge: Too Many Security Recommendations

Modern security platforms such as Microsoft Defender generate a very large number of security recommendations, vulnerabilities, and configuration findings.

Security teams are often faced with:

- thousands of vulnerabilities
- hundreds of security recommendations
- many findings marked as High or Critical

Although these tools are effective at identifying problems, they rarely answer the most important question: **Which issues should be addressed first?**

In practice, remediation work is often prioritized according to:

·     technical severity

·     number of affected systems

·     ease of remediation

 

This often leads organizations to spend resources resolving issues with limited real risk while more critical exposures remain unaddressed.



## A Risk-Based Prioritization Model

The **Security Insight** framework introduces a risk-based prioritization model that evaluates security findings based on both consequence and probability.

 

**Risk Score = Consequence Score × Probability Score**

 

**Consequence Score** represents the potential impact if a vulnerability is exploited.

**Probability Score** represents the likelihood that the vulnerability will actually be exploited.

 

The model can also be influenced by **contextual risk factors** such as:

·     internet exposure

·     known exploits

·     legacy systems.



## Challenges with Traditional Vulnerability Prioritization

Traditional vulnerability management often focuses on CVSS scores or severity classifications.

This approach creates several challenges:

·     the same vulnerability is evaluated equally regardless of the asset

·     business impact is not considered

·     attack chains and relationships are not identified.

 

## Exposure Graph Architecture

The **Security Insight framework** uses data from Microsoft Defender Exposure Graph including:

·     ExposureGraphNodes

·     ExposureGraphEdges

·     Defender Vulnerability Management findings

·     configuration assessments

 

These datasets allow analysis of relationships between systems and security findings.

 

## Step 1: Setting Asset Tier Level using tagging

**Assets** are automatically classified using tagging rules based on system roles. Examples include:

- Domain Controllers
- Entra synchronization services
- employee devices
- IoT devices



**Asset tagging** is done using asset taging engine that queries resources against **Defender Graph** or **Azure Resource Graph** using **Kusto KQL**. 

Each query also includes the Asset Tag to set. 

Query shows only deltas (missing assets). 

Asset Tagging runs with defined frequency like every 4 hours.



#### Structure of query in YAML-file

| Property                                                     | Purpose                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| AssetTagName                                                 | Description                                                  |
| Mode                                                         | Implementation scope <br />(can be defined in launcher or commandline)<br /><br />Supported:<br />Prod<br />Test |
| QueryEngine                                                  | Select query engine<br /><br />Sopported:<br />DefenderGraph = ExposureGraph<br />AzureResourceGraph = Azure Resource Graph |
| Query structure<br /><br />Step 1: Scoping - what to find ?<br />Step 2: Get existing Tags "as-is"<br />Step 3: Define Value for tag to set "to-be"<br />Step 4: Write resources<br />Step 5: Filter resources to show only resources in scope with missing tag (delta) | Query the Graph<br /><br />AssetTagType supported values: <br />AssetTier--SI = shows asset is in-scope with tier-info<br />Asset--Excluded--SI = shows asset must be excluded<br /><br />AssetTag = any value that makes the asset unique<br /><br />AssetTierLevel = 0,1,2,3 |



#### Asset Tagging files

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTagging.ps1) | Engine Launcher for Asset Tagging<br />Includes parameters for starting asset tagging engine | No (custom file)                                   |
| [CriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTagging.ps1) | Main Engine for Asset Tagging<br />Uses YAML-files as data repo | Yes <br />                                         |
| [SecurityInsight_CriticalAssetTagging_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Custom.yaml) | Data file (custom tags)<br />Kusto queries against graph-engines | No <br />(custom asset tags)                       |
| [SecurityInsight_CriticalAssetTagging_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Locked.yaml) | Data file (recommended tags)<br />Kusto queries against graph-engines | Yes                                                |



#### Example of recommended query to detect Sentinel resources

```
  - AssetTagName: AzPlatformManagementResources--tier0--SI
    Mode: Prod
    QueryEngine: AzureResourceGraph
    Query:
      - |
        resourcecontainers
        | where type == "microsoft.resources/subscriptions"
        | join kind=inner (
            resources
            | where type == "microsoft.operationsmanagement/solutions"
            | where name startswith "SecurityInsights("
            | project subscriptionId
            | distinct subscriptionId
        ) on subscriptionId
        | extend
            Tag_AssetTier = tostring(tags["AssetTier--SI"])
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "AzPlatformManagementSub",
            AssetTierLevel = 0
        | extend
            AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        | project
            subscriptionId,
            subscriptionName = name,
            Tag_AssetTier,
            AssetTagType,
            AssetTag,
            AssetTierLevel,
            AssetTagName,
            id
        | order by subscriptionId asc
        | where Tag_AssetTier != AssetTagName
```



#### Example of recommended query to detect Domain controller resources

```
  - AssetTagName: DomainControllerDNS--tier0--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
           or NodeLabel has "microsoft.compute/virtualmachines"
           or NodeLabel has "microsoft.hybridcompute/machines"

        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Server"
        | where tolower(tostring(rawData.onboardingStatus)) == "onboarded"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds
        | extend
            confidenceHigh = iff(isnull(rawData.criticalityConfidenceHigh), dynamic([]), todynamic(rawData.criticalityConfidenceHigh)),
            confidenceLow  = iff(isnull(rawData.criticalityConfidenceLow),  dynamic([]), todynamic(rawData.criticalityConfidenceLow))
        | extend
            DetectedRoles  = strcat_array(array_concat(confidenceHigh, confidenceLow), ";"),
            osPlatform     = tostring(rawData.osPlatform),
            osVersion      = tostring(rawData.osVersion),
            onboardingStatus = tostring(rawData.onboardingStatus)

        | where DetectedRoles has "DomainController"
            or DetectedRoles has "Dns"

        // Output Required Columns
        | extend
            deviceManualTags = iff(isnull(rawData.deviceManualTags), dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags = iff(isnull(rawData.tags.tags), dynamic([]), todynamic(rawData.tags.tags))
        | extend
             AssetTags  = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "DomainControllerDNS",
            AssetTierLevel = 0
        | extend    
            AssetTagName   = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        // Tagging END -----------------

        // Show only Assets in the output, which doesn't have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))
        | where array_index_of(AssetTagsArray, AssetTagName) == -1

```



#### Example of recommended query to detect Employee Workstations

```
- AssetTagName: EmployeeWorkstations--tier2--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
            or NodeLabel has "microsoft.compute/virtualmachines"
            or NodeLabel has "microsoft.hybridcompute/machines"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Workstation"
        | where tolower(tostring(rawData.onboardingStatus)) == "onboarded"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds

        // Output Required Columns
        | extend
            deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
        | extend
            AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "AssetTier--SI",
            AssetTag       = "EmployeeWorkstations",
            AssetTierLevel = 2
        | extend
            AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
        // Tagging END -----------------

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Exclude devices already marked Tier 0 or Tier 1 (--tier0--SI & --tier1--SI)
        | where AssetTags !has "--tier0--SI"
        | where AssetTags !has "--tier1--SI"

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1

```



#### Example of custom query to backbone network switch

```
  - AssetTagName: Network_Backbone_Switch--tier0--SI
    Mode: Test
    QueryEngine: DefenderGraph
    Query:
      - |
        let TargetSubnet = "192.168.1.0/24";

        let SwitchNodes =
            ExposureGraphNodes
            // Filter
            | where NodeLabel has "device"
            | extend rawData = todynamic(NodeProperties).rawData
            | where tobool(rawData.isExcluded) == false
            | where tostring(rawData.deviceSubtype) == "Switch"
            | project NodeId, NodeName, NodeLabel, rawData, EntityIds

            // Output Required Columns
            | extend
                deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
                deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
                tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
            | extend
                AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")

            // Extract device IDs
            | extend entityIds_dyn = todynamic(EntityIds)
            | mv-apply e = entityIds_dyn on (
                summarize
                    DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                    SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                    AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
            )
            | extend AzureResourceId = strcat_array(AzureResourceId, ";")

            // Normalize DeviceId for join
            | extend DeviceId = DeviceInventoryId
            | where isnotempty(DeviceId)

            // Tagging logic
            | extend
                AssetTagType   = "AssetTier--SI",
                AssetTag       = "Network_Backbone_Switch",
                AssetTierLevel = 0
            | extend
                AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI");

        SwitchNodes
        | join kind=inner (
            DeviceNetworkInfo
            | mv-expand ip = IPAddresses
            | extend
                IPAddress    = tostring(ip.IPAddress),
                AddressType  = tostring(ip.AddressType),
                SubnetPrefix = tostring(ip.SubnetPrefix)
            | where isnotempty(IPAddress)
            | where AddressType =~ "Private"
            | where ipv4_is_in_range(IPAddress, TargetSubnet)
            | project DeviceId, DeviceName, NetworkAdapterName, IPAddress, AddressType, SubnetPrefix
        ) on DeviceId

        | project
            NodeName,
            NodeLabel,
            DeviceId,
            DeviceInventoryId = DeviceId,
            IPAddress,
            NetworkAdapterName,
            AssetTagName,
            AssetTags
        | distinct NodeName, NodeLabel, DeviceId, DeviceInventoryId, IPAddress, NetworkAdapterName, AssetTagName, AssetTags

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1

```



#### Example of custom query to tag temporary autopilot objects that should be excluded, as they will be renamed

```
  - AssetTagName: Temp-Client-Devices--excluded--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes

        // Filter
        | where NodeLabel has "device"
            or NodeLabel has "microsoft.compute/virtualmachines"
            or NodeLabel has "microsoft.hybridcompute/machines"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tobool(rawData.isExcluded) == false
        | where tostring(rawData.deviceType) == "Workstation"
        | where NodeName startswith "fvf-"
        | where NodeName !has "cloud"
        | project NodeId, NodeName, NodeLabel, rawData, EntityIds

        // Output Required Columns
        | extend
            deviceManualTags  = iff(isnull(rawData.deviceManualTags),  dynamic([]), todynamic(rawData.deviceManualTags)),
            deviceDynamicTags = iff(isnull(rawData.deviceDynamicTags), dynamic([]), todynamic(rawData.deviceDynamicTags)),
            tags              = iff(isnull(rawData.tags.tags),         dynamic([]), todynamic(rawData.tags.tags))
        | extend
            AssetTags = strcat_array(array_concat(deviceManualTags, deviceDynamicTags), ";")
        | extend entityIds_dyn = todynamic(EntityIds)
        | mv-apply e = entityIds_dyn on (
            summarize
                DeviceInventoryId = anyif(tostring(e.id), tostring(e.type) == "DeviceInventoryId"),
                SenseDeviceId     = anyif(tostring(e.id), tostring(e.type) == "SenseDeviceId"),
                AzureResourceId   = make_list_if(tostring(e.id), tostring(e.type) == "AzureResourceId")
        )
        | extend AzureResourceId = strcat_array(AzureResourceId, ";")

        // Tagging BEGIN ---------------
        | extend
            AssetTagType   = "Asset--Excluded--SI",
            AssetTag       = "Temp-Client-Devices"
        | extend
            AssetTagName = strcat(AssetTag, "--Excluded--SI")
        // Tagging END -----------------

        // Show only assets that don't already have the tag
        | extend AssetTagsArray = iff(isempty(AssetTags), dynamic([]), split(AssetTags, ";"))

        // Only assets missing the intended Tier 1 tag
        | where array_index_of(AssetTagsArray, AssetTagName) == -1

```



## Step 2: Setting Asset Criticality Level Classification

Not all systems in an organization are equally important. Assets are therefore classified into **4 criticality tiers**.

Not all types of resources in Defender Critical Asset Management supports 'Criticality Tier'. The tags are used in the risk model when native criticality data is not available.

| **Criticality Level** **(Defender)** | **Tier** | **Category**              | **Examples of systems**                                      |
| ------------------------------------ | -------- | ------------------------- | ------------------------------------------------------------ |
| Critical / Very high                 | Tier-0   | Identity Control          | Domain Controllers, Entra / Azure AD Sync, core  authentication systems |
| High                                 | Tier-1   | Privileged Infrastructure | Infrastructure servers, authentication systems,  management platforms |
| Medium                               | Tier-2   | Business Systems          | Employee workstations, application servers,  collaboration systems |
| Low                                  | Tier-3   | Low‑Trust Systems         | IoT devices, testing environments and specialized  systems   |

 

Assets are classified using 2 methods in Defender Critical Asset Management:

- **Automatic classification** “Predefined classifications”
- **Custom classification** using tags in Defender & Azure. 



**Custom classification in Defender Critical Asset Management**

- AzPlatformManagementResources--tier0--SI
- DomainControllerDNS--tier0--SI
- ADCertificateService--tier0--SI
- EntraSyncService--tier0--SI
- EmployeeWorkstations--tier2--SI
- EmployeeMobile--tier2--SI
- IoT--tier3--SI
- AzHubPlatformManagementSub--tier0--SI
- AzHubPlatformSecuritySub--tier0--SI
- AzLZDatacenterSub--tier0--SI
- AutomationServer--tier0--SI
- ServerBusinessServices--tier1--SI
- PAWDevices--tier0--SI
- Network_Backbone_Switch--tier0--SI
- Network_Backbone_Router--tier0--SI
- Network_Backbone_Management--tier0--SI
- Network_WLANAccessPoint--tier2--SI
- Temp-Client-Devices--excluded--SI



![CriticalityLevel-Defender-overview](/CriticalityLevel-Defender-overview.png)

 

The tags are used in the risk model when native criticality data is not available.



## Risk Score Model

**Risk Score** is calculated using two dimensions:

**Consequence Score** – the potential impact if exploitation occurs.

**Probability Score** – the likelihood of exploitation based on asset tier and exposure context.



**Probability Score** may be adjusted using **contextual risk indicators (risk factors)**, that increase the likelihood of exploitation. such as:

- exploit availability

- internet exposure

- legacy systems


 Each of these influence the score by increasing the probability score with +1 due to the risk factor



The **final risk score** is calculated as:

#### **Risk Score = Consequence Score × Probability Score**

This score is used to prioritize remediation activities.

 

## Reporting

The framework generates both summary and detailed reports.

**Summary reports** include number of findings per tier, overall risk levels, configuration status

**Detailed reports** include affected assets, vulnerability identifiers and remediation guidance.



| File Name                                                    | Purpose                                         |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file               |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary  |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file                |



## Implementation Architecture

The solution consists of three main components:

| Data collection (Input)                                      | Analysis                                                     | Reporting (Output)               |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------- |
| Microsoft Defender<br />Exposure Graph<br />Azure Resource Graph | Kusto queries<br />YAML report definitions<br />Risk score calculations | Excel reports<br />Summary Email |



## Governance and Compliance

The model supports several regulatory and security frameworks including:

·     NIS2 Directive

·     CIS Critical Security Controls

·     ISO 27001 risk management principles.

 

## Operational Benefits

Organizations implementing the model gain:

·     improved vulnerability prioritization

·     reduced remediation backlog

·     improved visibility into attack paths.

 

## Future Opportunities

Potential future developments include:

·     automated attack path analysis

·     integration with threat intelligence

·     integration with ticketing and risk management platforms.

 

## Transparency and Flexibility

The Security Insight architecture is fully open and transparent and is based on:

​     PowerShell automation

·     Kusto Queries for data analysis

·     CSV files defining scoring models

·     YAML report definitions

·     asset tagging

 

This ensures the prioritization model can be inspected, validated and adapted to organizational requirements.

 

## Collaboration with Microsoft

The development of the Security Insight model is conducted in close dialogue with Microsoft.

Morten Knudsen collaborates with Microsoft, including Raviv Tamir, Corporate Vice President for Microsoft Defender, and his team to explore how the risk‑based prioritization concepts can influence the future strategy of the Microsoft Defender platform.



## How to setup SecurityInsight in your environment ?



Step 1: 



## Files Overview (Asset Tagging)

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTagging.ps1) | Engine Launcher for Asset Tagging<br />Includes parameters for starting asset tagging engine | No (custom file)                                   |
| [CriticalAssetTagging.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTagging.ps1) | Main Engine for Asset Tagging<br />Uses YAML-files as data repo | Yes <br />                                         |
| [SecurityInsight_CriticalAssetTagging_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Custom.yaml) | Data file (custom tags)<br />Kusto queries against graph-engines | No <br />(individual asset tags)                   |
| [SecurityInsight_CriticalAssetTagging_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_CriticalAssetTagging_Locked.yaml) | Data file (recommended tags)<br />Kusto queries against graph-engines | Yes                                                |



## Files Overview (Asset Tagging Maintenance - Clean-up/Remove orphaned tags)

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunCriticalAssetTaggingMaintenance.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunCriticalAssetTaggingMaintenance.ps1) | Maintenance Launcher<br />Includes parameters for starting maintenance engine | No (custom file)                                   |
| [CriticalAssetTaggingMaintenance.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/CriticalAssetTaggingMaintenance.ps1) | Main Engine for Asset Tag Maintenance<br /><br />Note: <br />Samples are provided that can be run after modifcation to your needs, like which tags to remove | Yes                                                |



## Files Overview (Risk Analysis)

| File Name                                                    | Purpose                                                      | Continues Updates via UpdateSecurityInsight-script |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| [RunSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/RunSecurityInsight.ps1) | Engine Launcher<br />Includes parameters for starting risk analysis engine | No (custom file)                                   |
| [SecurityInsight_RiskAnalysis.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis.ps1) | Main Engine <br />Engine file for Risk Analysis<br />Uses YAML-files as data repo<br />Uses RiskIndex-file to prioritize score | Yes <br />                                         |
| [SecurityInsight_RiskIndex.csv](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskIndex.csv) | Risk Index data file                                         | No (*)<br />(custom priority file)                 |
| [SecurityInsight_RiskAnalysis_Queries_Custom.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Custom.yaml) | Report data file (custom tags)<br />Kusto queries against graph-engine | No <br />(custom queries)                          |
| [SecurityInsight_RiskAnalysis_Queries_Locked.yaml](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/SecurityInsight_RiskAnalysis_Queries_Locked.yaml) | Report data file (recommended tags)<br />Kusto queries against graph-engine | Yes                                                |

(*) If you don't make custom changes in RiskIndex file, you can add the file into UpdateSecurityInsight.ps1 script to subscribe to my recommendations in priority.



## Files Overview (Support file)

| File Name                                                    | Purpose                                                      | Comment                        |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------ |
| [UpdateSecurityInsight.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/UpdateSecurityInsight.ps1) | Update Engine<br />Backup local files + Update files from Github repo<br />https://github.com/KnudsenMorten/SecurityInsight | Can be modified to your needs  |
| [Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1](https://raw.githubusercontent.com/KnudsenMorten/SecurityInsight/refs/heads/main/Deploy_OpenAI_PAYG_Instance_SecurityInsights.ps1) | Deploy OpenAI PAYG instance (optional)<br />Used for AI summary based on context from risk analysis | Must be modified to your needs |



## Files Overview (Sample Output files)

| File Name                                                    | Purpose                                         |
| ------------------------------------------------------------ | ----------------------------------------------- |
| [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) | Sample mail for Detailed report with AI summary |
| [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) | Sample detailed output Excel file               |
| [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) | Sample mail for Summary report with AI summary  |
| [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/blob/main/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) | Sample summary output Excel file                |
