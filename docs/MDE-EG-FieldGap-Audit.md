# MDE / Exposure Graph field-gap audit — built-in tables only

**Scope.** Built-in Defender XDR + Entra Log Analytics tables actually referenced by the v2.2 RA queries. Custom `SI_*_CL` tables are out of scope (they're our own).

**Goal.** Identify high-value fields that exist in Microsoft built-in tables but are **not currently** projected into our Profile_CL schemas or surfaced in RA report rows / `MoreDetails`. Read-only research — no code changes in this document.

**Method.** Grep'd `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` + the Endpoint/Azure Profile builders + the schema JSONs for which fields are currently in use. Cross-referenced against documented MDE / Exposure Graph schemas.

---

## 0. Inventory of built-in tables actually referenced

| Table | Where used | RA reports that touch it |
|---|---|---|
| `DeviceInfo` | `Device_*` reports — joined as `DI_*` | `Device_Recommendations_*`, `Device_Missing_CVEs_*`, `Identity_Admin_LogonTo_*`, attack-paths involving devices |
| `DeviceTvmSecureConfigurationAssessment` | `Device_Recommendations_*` — primary source | 2 reports (Summary + Detailed) |
| `DeviceTvmSecureConfigurationAssessmentKB` | `Device_Recommendations_*` — joined as `KB_*` | 2 reports (Summary + Detailed) |
| `ExposureGraphNodes` | EG-primary RA pattern — every report joins for asset enrichment | ~30+ reports |
| `ExposureGraphEdges` | Attack-path reports | 6 attack-path Summary + 6 Detailed |
| `SigninLogs` | Identity sign-in reports — `Identity_PrivilegedUser_SignIn_NonTrustedLocation_*`, etc. | ~6 reports |
| `AADNonInteractiveUserSignInLogs` | Same family of identity reports | ~3 reports |

Not used (but in tenant schema): `DeviceTvmSoftwareInventory`, `DeviceTvmSoftwareVulnerabilities*`, `DeviceProcessEvents`, `DeviceLogonEvents`, `DeviceNetworkInfo`, `IdentityInfo`, `IdentityLogonEvents`, `AADSignInEventsBeta`, `AADSpnSignInEventsBeta`, `AlertInfo`, `AlertEvidence`, `AuditLogs`, `EmailEvents`, `CloudAppEvents`, `BehaviorInfo`. Many would be high-value future additions; flagged where relevant.

---

## 1. `DeviceInfo` (MDE)

### Currently projected into `SI_Endpoint_Profile_CL`

The Endpoint Profile builder (`Build-EndpointProfileRow.ps1`) maps **57 `MDE_*`** fields. The schema (`endpoint.schema.locked.json`, 186 columns total) exposes most as **unprefixed** column names. Coverage is **strong** — including IsExcluded, IsInternetFacing, OnboardingStatus, JoinType, Model, Vendor, DefenderAvStatus, EdrMode, LoggedOnUsers, etc.

### Available in `DeviceInfo` but NOT in current Profile_CL

| MDE field | Type | Why valuable | Suggested Profile column |
|---|---|---|---|
| `IsAzureADJoined` (raw) | bool | `IsAzureADJoined` IS exposed; verify population | already mapped — verify |
| `OSDistribution` | string | Linux distro (Ubuntu / RHEL / etc.) — currently rolled up under OsPlatform | `OsDistribution` |
| `DeviceObjectId` | string | The Entra device object ID (not AAD device ID) — direct join key for Entra / CA reports | `EntraDeviceObjectId` |
| `AdditionalFields` | dynamic | Vendor-specific extras (BIOS version, secure-boot state) — varies by tenant | `MDE_AdditionalFields` (json passthrough) |
| `DeviceManagementType` | string | Intune / SCCM / unmanaged — drives "is-managed" risk factor | `DeviceManagementType` |
| `MdeMachineId` | string | Different from MdeDeviceId in some scenarios | `MdeMachineId` |

### Available in `DeviceInfo` but NOT used in current RA queries (could enrich `MoreDetails`)

| MDE field | Why valuable for MoreDetails |
|---|---|
| `OnboardingStatus` | Distinguishes Onboarded vs Insufficient info vs Can be onboarded. Rows surfacing as "needs MDE coverage" are easy to action. |
| `ExposureLevel` | "Low" / "Medium" / "High" — a Defender-computed verdict. Could feed `RiskFactor_Probability_Detailed`. |
| `IsExcluded` + `ExclusionReason` | An asset excluded from MDE enforcement is a known risk. Surface in MoreDetails for visibility. |
| `DefenderAvStatus` + `DefenderAvMode` + `SensorHealthState` | If AV is Disabled/Outdated, that's a probability-amplifier for any vulnerability finding. |
| `LoggedOnUsers` | Per-row "who was on this device when?" — operationally useful for ticket assignment. |

---

## 2. `DeviceTvmSecureConfigurationAssessment` (MDE)

### Currently projected

Just join-keys: `DeviceId`, `ConfigurationId`, `IsApplicable`, `IsCompliant`, `ConfigurationImpact`, `Timestamp`. The KB join provides the human-readable enrichment.

### Available but NOT used

| Field | Why valuable |
|---|---|
| `ConfigurationCategory` (raw) | KB has a synthesized one — but per-device value can differ |
| `ConfigurationSubcategory` | Same — slight precision gain |
| `IsExpectedUserImpact` | Boolean: "fixing this will produce visible user friction". Material for change-window prioritization. |
| `RecommendedFixId` | Stable ID — useful as a join key to track remediation programs over time |
| `Context` (`AdditionalFields` if present) | Per-device context (e.g. policy GUID applied) |

---

## 3. `DeviceTvmSecureConfigurationAssessmentKB` (MDE) — biggest gap

### Currently projected

`KB_RiskDescription`, `KB_Description`, `KB_Remediation`, `KB_ConfigurationName`, `KB_ConfigurationCategory`, `KB_ConfigurationSubcategory`, `KB_Impact`. Lifted as `RiskDescription` / `Remediation` etc. into RA rows.

### Available but UNUSED — high-value gap

| Field | Type | Why valuable | Where to surface |
|---|---|---|---|
| **`RelatedMitreTactics`** | dynamic (string array) | Maps each finding to MITRE ATT&CK tactics (e.g. `["TA0006:Credential Access"]`). **Zero current usage** in v2.2. | `MITRE_Tactics` column on row + `MoreDetails` link to `https://attack.mitre.org/tactics/<id>/` |
| **`RelatedMitreTechniques`** | dynamic (string array) | Same for techniques (e.g. `["T1003:OS Credential Dumping"]`). **Zero current usage**. | `MITRE_Techniques` column + per-technique URL in `MoreDetails` |
| **`Tags`** | dynamic | Topical tags (CIS, NIST, ISO27001, PCI). Quick framework filter. | `ComplianceTags` column |
| **`ConfigurationBenchmarks`** | dynamic | Explicit benchmark-control mapping (e.g. `["CIS Windows Server 2019 1.1.1"]`). Used 5x in YAML — could be expanded. | `Benchmarks` column on row |

**MITRE alone** would substantially upgrade the `Device_Recommendations_*` reports — every row could link to attack.mitre.org with the relevant tactic/technique.

---

## 4. `ExposureGraphNodes` (Defender XDR / Exposure Mgmt)

### Currently projected

Endpoint side: `EG_AadDeviceId`, `EG_IsCustomerFacing`, `EG_IsExcluded`, `EG_AssetLabel` (= `NodeLabel`).

Azure side: **80 `EG_*` fields** in `azure.schema.locked.json` — comprehensive per-resource-type properties (ACR_*, AGW_*, AOAI_*, KV_*, SQL_*, ST_*, etc.).

### Available in `NodeProperties.rawData` but NOT projected

These are the high-value asset-level signals that Microsoft's Exposure Graph computes and which we are **not currently** lifting into Profile_CL:

| `rawData.<field>` | Type | Why valuable | Suggested Profile column |
|---|---|---|---|
| **`hasInternetExposureSignal`** | bool | Continuous signal vs static `isInternetFacing` boolean. Detects pivots in exposure even when `isInternetFacing` hasn't flipped. | `HasInternetExposureSignal` |
| **`criticalityLevel`** | string ("Low"/"Medium"/"High"/"VeryHigh") | **Microsoft's own per-asset criticality from Exposure Mgmt.** Could short-circuit our SIRules tier engine for assets MS already classified. Note feedback memory: tier source is CL only — but MoreDetails / RiskFactor_Consequence_Detailed could still surface this. | `EG_MsCriticalityLevel` |
| **`isCompromisedRecently`** | bool | Defender-computed "this asset shows post-compromise indicators in the last N days". HUGE risk signal. | `IsCompromisedRecently` |
| **`machineRiskState`** | string | Defender's per-device risk verdict — Low / Medium / High / Informational. | `MachineRiskState` |
| **`isAdfsServer`** | bool | Rich role marker — feeds Tier 0 classification. | `IsAdfsServer` |
| **`isExchangeOnlineMailbox`** | bool | Distinguishes EXO mailbox from on-prem Exchange. | `IsExchangeOnlineMailbox` |
| **`isProductionEnvironment`** | bool | Prod vs dev classification — feeds prioritization. | `IsProductionEnvironment` |
| **`hardwareVendor`** + **`hardwareModel`** | string | Asset inventory richness. Already pulled from MDE; EG is fallback when MDE is sparse. | `HardwareVendor` / `HardwareModel` |
| **`dnsNames`** | dynamic (string array) | Multiple DNS names per asset (a.k.a. SAN entries on certs, A-record aliases). | `DnsNames` |
| **`ipAddresses`** | dynamic (string array) | All IPs (not just primary). For NSG / firewall correlation. | `EgIpAddresses` |
| **`accountObjectId`** + **`accountUpn`** | string | For user nodes — direct Entra link. | `EntraAccountObjectId` (Identity Profile) |
| **`isMfaCapable`** + **`isMfaRegistered`** | bool | More granular than current MFA tracking — capable ≠ registered ≠ enforced. | `IsMfaCapable` / `IsMfaRegistered` |
| **`onPremSyncEnabled`** | bool | For users — hybrid identity signal. | `OnPremSyncEnabled` |
| **`externalUser`** | bool | B2B guest indicator — different threat model than internal. | `IsExternalUser` |
| **`lastSeen`** + **`classificationLastSeen`** | datetime | Two distinct freshness signals. Already have `IsStaleAsset` derived from a different source. | `EgLastSeen` (already in schema!) / `EgClassificationLastSeen` |

### What we DO use in queries: only 4 of these (`aadDeviceId`, `isCustomerFacing`, `isExcluded`, `deviceCategory`)

Adding the gap fields above to the **Endpoint Profile builder** + **Endpoint Profile schema** would make them queryable from RA without modifying the EG-primary RA pattern itself.

---

## 5. `ExposureGraphEdges` (Defender XDR)

### Currently projected

`SourceNodeId`, `TargetNodeId`, `EdgeLabel`, `EdgeProperties` (passthrough) — used heavily in attack-path queries.

### Available but underused

| Field | Why valuable |
|---|---|
| `EdgeProperties.<various>` | Edge-level metadata (e.g. for `canAuthenticateAs` edges: which auth method, which token TTL) — currently passed through as opaque JSON; no per-property extraction. |

Limited additional surface here — edge data is already used heavily.

---

## 6. `SigninLogs` + `AADNonInteractiveUserSignInLogs` (Entra / LA)

### Currently projected

Mostly: `UserPrincipalName`, `IPAddress`, `Location`, `NetworkLocationDetails.networkType` (for trustedNamedLocation check), `TimeGenerated`. Aggregated as count + dcount.

### Available but UNUSED — significant gap

| Field | Type | Why valuable |
|---|---|---|
| **`DeviceDetail.IsCompliant`** | bool (in dynamic) | Per-signin Intune-compliance verdict |
| **`DeviceDetail.IsManaged`** | bool | Per-signin managed-device verdict |
| **`DeviceDetail.TrustType`** | string | AzureAdJoined / WorkplaceJoined / Hybrid — auth-trust signal |
| **`DeviceDetail.OperatingSystem`** | string | OS at signin time — divergence from inventory is a signal |
| **`DeviceDetail.Browser`** | string | Anomalous browser per user is a signal |
| **`RiskLevelDuringSignIn`** | string | Entra ID Protection's per-signin risk verdict |
| **`RiskLevelAggregated`** | string | Aggregated across the user's session |
| **`RiskState`** | string | atRisk / confirmedSafe / dismissed |
| **`RiskEventTypes_V2`** | dynamic (array) | Specific risk types — anonymizedIPAddress, leakedCredentials, atypicalTravel, etc. **Direct RiskFactor_Probability_Detailed signal.** |
| **`ConditionalAccessStatus`** | string | success / failure / notApplied — surfaces CA evaluation |
| **`AuthenticationDetails`** | dynamic (array) | Per-step auth method (Password, FIDO2, AuthenticatorApp, SMS) |
| **`AuthenticationRequirement`** | string | singleFactorAuthentication vs multiFactorAuthentication required |
| **`HomeTenantId`** + **`ResourceTenantId`** | string | Cross-tenant signin pattern — material for B2B abuse and OAuth attacks |
| **`TokenIssuerType`** | string | AzureAD / OnPremiseAD / etc. |
| **`ServicePrincipalId`** + **`ServicePrincipalName`** | string | For SP signins — drives the SP_* report family |
| **`AppDisplayName`** + **`AppId`** | string | Which app the signin was against — combined with risk level identifies "risky signin to Exchange Online" |
| **`OriginalRequestId`** | string | Trace correlation across multi-hop auth |
| **`AlternateSignInName`** | string | UPN aliases / proxy addresses |

### Highest-value additions for the Identity reports

If you could only add 5 columns:

1. `DeviceDetail.IsCompliant` (per-signin compliance)
2. `RiskLevelDuringSignIn` + `RiskEventTypes_V2` (Entra ID Protection signals)
3. `ConditionalAccessStatus` (was MFA actually required this signin?)
4. `AuthenticationRequirement` (what factor was used?)
5. `HomeTenantId != ResourceTenantId` (cross-tenant pattern)

These would substantially upgrade the `Identity_PrivilegedUser_SignIn_*` and `Identity_BreakGlass_*` reports.

---

## 7. Suggested next-action priority

If you want to act on this audit (separate work, not in this doc):

### Tier 1 — high impact, low scope (one-shot file edits)

1. **Project MITRE tactics + techniques** from `DeviceTvmSecureConfigurationAssessmentKB` into `Device_Recommendations_*` rows. Add 2 columns + per-row MoreDetails URL formatter. Touches: 1 YAML file (KB join), 0 schema changes (RA-only column).
2. **Surface `OnboardingStatus`, `ExposureLevel`, `DefenderAvStatus`, `SensorHealthState`** in MoreDetails for `Device_*` reports. Already in Profile_CL — just KQL projection in RA YAML.
3. **Add EG `criticalityLevel`** to Endpoint Profile_CL as `EG_MsCriticalityLevel` — Microsoft's own asset criticality, useful as a comparison column even if we don't drive tier from it (per `feedback_si_ra_tier_source` memory).

### Tier 2 — medium impact, broader scope (schema + builder updates)

4. **Add EG signals to Endpoint Profile_CL**: `HasInternetExposureSignal`, `IsCompromisedRecently`, `MachineRiskState`, `IsProductionEnvironment`. Touches: `endpoint.schema.locked.json` (4 new columns), `Build-EndpointProfileRow.ps1` (4 mapping entries), DCR re-provision on next bootstrap.
5. **Project `DeviceDetail.*` from SigninLogs** into the identity sign-in reports. Adds 3-4 columns to `Identity_*_SignIn_*` reports + Risk_Probability_Detailed enrichment when `RiskLevelDuringSignIn != "none"`.

### Tier 3 — high impact, significant scope (new tables)

6. **Add `IdentityInfo` as a source** — currently we synthesize identity profile from Entra Graph + EG; `IdentityInfo` is Defender's own consolidated view (department, manager, account creation date, IsEnabled). Currently zero usage.
7. **Add `AlertEvidence` for cross-correlation** — every RA finding could carry "any active alerts referencing this asset?" as a `RiskFactor_Probability_Detailed` entry (`HasActiveDefenderAlert`).
8. **Add `DeviceTvmSoftwareVulnerabilities` + `KB`** — currently we use `DeviceTvmSecureConfigurationAssessment` for misconfigurations. The vulnerability table has CVE-level data including `IsExploitVerified`, `IsInExploitKit`, `IsZeroDay` (currently we get these elsewhere — verify completeness).

---

## Summary

| Source table | Fields exposed in Profile_CL today | High-value gaps |
|---|---|---|
| `DeviceInfo` | ~57 (good coverage) | `OSDistribution`, `DeviceObjectId`, `DeviceManagementType` |
| `DeviceTvmSecureConfigurationAssessment` | 5 (join keys) | `IsExpectedUserImpact`, `RecommendedFixId` |
| `DeviceTvmSecureConfigurationAssessmentKB` | 6 (descriptions) | **`RelatedMitreTactics`, `RelatedMitreTechniques`, `Tags`** |
| `ExposureGraphNodes` | 4 endpoint-side; 80 azure-side | **`hasInternetExposureSignal`, `criticalityLevel`, `isCompromisedRecently`, `machineRiskState`, `isProductionEnvironment`, `isAdfsServer`, `dnsNames`** |
| `ExposureGraphEdges` | All used | none material |
| `SigninLogs` / `AADNonInteractiveUserSignInLogs` | 5–6 (basic) | **`DeviceDetail.IsCompliant`, `RiskLevelDuringSignIn`, `RiskEventTypes_V2`, `ConditionalAccessStatus`, `AuthenticationRequirement`** |

**Biggest unrealized value:** MITRE mapping (zero current use), EG `criticalityLevel` + `isCompromisedRecently` (Microsoft-computed risk signals we ignore), and SigninLogs `DeviceDetail` + `RiskLevelDuringSignIn` (Entra ID Protection signals we don't surface).
