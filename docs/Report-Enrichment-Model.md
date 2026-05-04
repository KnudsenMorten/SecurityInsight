# Generic report-enrichment model — what to put in MoreDetails / new columns

**Purpose.** A single shared enrichment vocabulary that applies across all RA reports, sourced from the field gaps in `MDE-EG-FieldGap-Audit.md`. Removes per-report bespoke columns; lets any report opt into the enrichment that's relevant.

> ⚠️ **v2.2 status**: `MITRE_Tactics`, `MITRE_Techniques`, `ComplianceTags` are emitted as always-exists columns on every report row, but **only the two `Device_Missing_CVEs_*` reports populate them today** (their KQL projects from `DeviceTvmSecureConfigurationAssessmentKB.RelatedMitre*` + `Tags` + `ConfigurationBenchmarks`). The other 134 reports query Profile tables / Identity sources that don't carry equivalent fields, so the columns are present-but-empty. Broader coverage requires a per-`ConfigurationId` lookup table — slated for v2.3 (Tier B + F per § E rollout).
>
> `MoreDetails` is now built per row from harvested URLs + Defender / Entra / Azure portal links + MITRE links. v2.2 also injects `MdeDeviceId` / `EntraAccountObjectId` / `AzureResourceId` into every `summarize ... by` block (via `any(column_ifexists(...))`) so the engine can build portal links even on Summary aggregates that previously dropped these IDs.

**Design principles.**
1. **Generic over bespoke** — one column per signal family, not one column per report.
2. **Separate WHERE from HOW** — *new column* for hard data, *MoreDetails* for human-readable links + descriptions.
3. **Extend existing patterns** — don't invent new shapes if `RiskFactor_*_Detailed` semicolon-list pattern already covers it.
4. **Always-emitted, ever-empty** — every report row has every column (even if empty); KQL filters and downstream consumers don't have to handle "missing".
5. **Engine-derived, not YAML-hardcoded** — the engine's per-row enrichment pass populates these from row-level signals; YAML doesn't have to know.

---

## A. New columns to add (per-row, all reports)

These become first-class columns in the report row, alongside `RiskFactor_*` and `cmdb*`.

| Column | Type | Source | Sample value | Used when |
|---|---|---|---|---|
| **`MITRE_Tactics`** | string (`;`-list) | `DeviceTvmSecureConfigurationAssessmentKB.RelatedMitreTactics` | `TA0006;TA0007` | Endpoint config / vulnerability reports |
| **`MITRE_Techniques`** | string (`;`-list) | `DeviceTvmSecureConfigurationAssessmentKB.RelatedMitreTechniques` | `T1003;T1110.003` | Same |
| **`ComplianceTags`** | string (`;`-list) | `KB.Tags` + `KB.ConfigurationBenchmarks` | `CIS;NIST 800-53;PCI-DSS` | Endpoint config reports |
| **`MsCriticalityLevel`** | string | `EG NodeProperties.rawData.criticalityLevel` | `High` | All reports (every asset has a node) |
| **`MachineRiskState`** | string | `EG NodeProperties.rawData.machineRiskState` | `High` | Endpoint reports |
| **`Defender_Alert_Active`** | int (0/1) | `AlertEvidence` (new source) joined on AssetId / DeviceId | `1` | All reports |
| **`Defender_Alert_Count_30d`** | int | `AlertEvidence` aggregated 30d | `3` | All reports |
| **`LastSeen_Days`** | int | `MDE_LastSeen` or `EG.lastSeen` → `now() - lastSeen` in days | `12` | All reports (already `IsStaleAsset` boolean — this is the underlying number) |
| **`RecommendedAction`** | string (short imperative) | Per-report engine logic | `Patch CVE-2025-15556 on dc1.2linkit.local` | All reports |
| **`MoreDetails`** | string (newline-separated raw URLs) | Engine-built per row from: harvested `http(s)://` values across all columns + Defender/Entra/Azure portal URLs computed from `MdeDeviceId` / `EntraObjectId` / `AzureResourceId` + `attack.mitre.org` URLs from `MITRE_*` | `https://security.microsoft.com/machines/<id>/overview\r\nhttps://portal.azure.com/...` | All reports (always emitted, empty when no source IDs present) |

### Notes
- `RecommendedAction` is short (≤120 chars). Long remediation steps go in `MoreDetails`.
- `MoreDetails` collects all per-row URLs (raw URL columns, portal links, MITRE links) into one cell, one URL per line (`\r\n`-separated, no label prefix). Deduped, capped at 25 URLs / 4000 chars to stay Excel-readable.
- `MITRE_*` are semicolon-lists same as `RiskFactor_*_Detailed` — for grep/filter consistency.

---

## B. New tokens to add to existing `RiskFactor_*_Detailed`

Don't add new columns for these — extend the existing semicolon-list vocabulary. Keeps the count column meaningful (more tokens = higher score).

### `RiskFactor_Probability_Detailed` — likelihood amplifiers

| New token | Source | When emitted |
|---|---|---|
| `IsCompromisedRecently` | EG `rawData.isCompromisedRecently` | Active threat indicator from MS — STRONG signal |
| `HighMachineRisk` | EG `rawData.machineRiskState == "High"` | Per-device Defender verdict |
| `EntraRisk:HighSignIn` | SigninLogs `RiskLevelDuringSignIn == "high"` | Per-signin ID Protection |
| `EntraRisk:LeakedCredentials` | SigninLogs `RiskEventTypes_V2 contains "leakedCredentials"` | ID Protection signal |
| `EntraRisk:AtypicalTravel` | SigninLogs `RiskEventTypes_V2 contains "atypicalTravel"` | ID Protection signal |
| `EntraRisk:AnonymizedIP` | SigninLogs `RiskEventTypes_V2 contains "anonymizedIPAddress"` | TOR / proxy |
| `DefenderAvDisabled` | `MDE_DefenderAvStatus in ("Disabled","Off")` | AV not running |
| `DefenderAvOutOfDate` | `MDE_DefenderAvStatus == "OutOfDate"` | Signatures stale |
| `Unonboarded` | `MDE_OnboardingStatus != "Onboarded"` | MDE not protecting |
| `Unmanaged` | `MDE_DeviceManagementType in ("Unknown","Unmanaged")` | Not in Intune/SCCM |
| `Excluded` | `MDE_IsExcluded == true` | Manually excluded from MDE |
| `ConditionalAccessNotApplied` | SigninLogs `ConditionalAccessStatus == "notApplied"` | CA bypass |
| `SingleFactorAuthRequired` | SigninLogs `AuthenticationRequirement == "singleFactorAuthentication"` | No MFA was needed |
| `CrossTenantSignIn` | SigninLogs `HomeTenantId != ResourceTenantId` | B2B/cross-tenant pattern |
| `HasActiveAlert` | `Defender_Alert_Active == 1` | Existing Defender alert |
| `IsZeroDay` (already used) | KB `IsZeroDay == true` | — |
| `HasExploit` (already used) | KB `HasExploit == true` | — |
| `IsExploitVerified` (already used) | KB `IsExploitVerified == true` | — |
| `IsInternetExposed` (already used) | profile `IsInternetFacing` or EG signal | — |

### `RiskFactor_Consequence_Detailed` — consequence amplifiers

| New token | Source | When emitted |
|---|---|---|
| `MsCriticalityHigh` | EG `rawData.criticalityLevel in ("High","VeryHigh")` | MS-flagged critical asset |
| `IsProductionEnvironment` | EG `rawData.isProductionEnvironment == true` | Prod blast radius |
| `IsAdfsServer` | EG `rawData.isAdfsServer == true` | Federated identity = catastrophic |
| `IsExchangeServer` | profile `IsExchangeServer` (existing) | Mail compromise |
| `IsExchangeOnlineMailbox` | EG `rawData.isExchangeOnlineMailbox == true` | EXO mailbox |
| `IsDomainController` (already used) | profile `IsDomainController` | — |
| `Tier0BlastRadius` (already used) | tier == 0 | — |
| `BusinessCriticalAsset` (already used) | cmdb match Critical | — |
| `RestrictedDataAccess` / `ConfidentialDataAccess` (already used) | cmdb data sensitivity | — |
| `HostedOnHypervisor` | `MDE_HostDeviceId is not empty` and host is identified DC/critical | Inherits host criticality |

---

## C. `MoreDetails` URL-list extensions

Currently auto-harvests `^https?://` from row columns. Extend with these formatters when source data present:

| URL pattern | Generated when | Example |
|---|---|---|
| `https://attack.mitre.org/tactics/<TAID>/` | `MITRE_Tactics` populated, one URL per tactic | `https://attack.mitre.org/tactics/TA0006/` |
| `https://attack.mitre.org/techniques/<TID>/` | `MITRE_Techniques` populated, one per technique | `https://attack.mitre.org/techniques/T1003/` |
| `https://nvd.nist.gov/vuln/detail/<CVE>` | `ConfigurationId` matches `^CVE-\d{4}-\d+$` | `https://nvd.nist.gov/vuln/detail/CVE-2025-15556` |
| `https://security.microsoft.com/machines/<MdeDeviceId>/overview` | Endpoint report + `MdeDeviceId` present | (current) |
| `https://security.microsoft.com/machines/<MdeDeviceId>/timeline` | Same — direct timeline link for IR | (current) |
| `https://security.microsoft.com/securityrecommendations?recommendationId=<RecommendedFixId>` | Endpoint config report + `RecommendedFixId` | direct rec page |
| `https://portal.azure.com/#view/Microsoft_AAD_IAM/UserDetailsMenuBlade/~/Profile/userId/<EntraObjectId>` | Identity report + `EntraObjectId` | (current) |
| `https://portal.azure.com/#@<TenantId>/resource<AzureResourceId>` | Azure report + `AzureResourceId` | (current) |
| `https://security.microsoft.com/alerts?id=<AlertId>` | When `Defender_Alert_Active == 1` and AlertId is known | direct alert link |

---

## D. Mapping: which source fields populate which target

| Source table | Source field | Target column / token | Direction |
|---|---|---|---|
| `DeviceTvmSecureConfigurationAssessmentKB` | `RelatedMitreTactics` | `MITRE_Tactics` (new col) + `MoreDetails` URL per tactic | Endpoint config reports |
| | `RelatedMitreTechniques` | `MITRE_Techniques` (new col) + `MoreDetails` URL per technique | Same |
| | `Tags` + `ConfigurationBenchmarks` | `ComplianceTags` (new col) | Endpoint config reports |
| | `RecommendedFixId` | `MoreDetails` URL to security recommendations page | Same |
| | `IsExpectedUserImpact` | New token: `RiskFactor_Probability_Detailed` += `HasUserImpact` (lower priority for change) | Same |
| `ExposureGraphNodes` | `criticalityLevel` | `MsCriticalityLevel` col + token `MsCriticalityHigh` in Consequence | All reports |
| | `machineRiskState` | `MachineRiskState` col + token `HighMachineRisk` in Probability | Endpoint |
| | `isCompromisedRecently` | Token `IsCompromisedRecently` in Probability | Endpoint |
| | `isProductionEnvironment` | Token `IsProductionEnvironment` in Consequence | All |
| | `isAdfsServer` | Token `IsAdfsServer` in Consequence | Endpoint |
| | `isExchangeOnlineMailbox` | Token `IsExchangeOnlineMailbox` in Consequence | Identity |
| | `lastSeen` | `LastSeen_Days` col | All |
| | `dnsNames` | (Profile column only — too verbose for row) | Endpoint Profile |
| `DeviceInfo` | `OnboardingStatus` | Token `Unonboarded` in Probability when != "Onboarded" | Endpoint |
| | `DefenderAvStatus` / `DefenderAvMode` | Tokens `DefenderAvDisabled` / `DefenderAvOutOfDate` | Endpoint |
| | `IsExcluded` | Token `Excluded` in Probability | Endpoint |
| | `DeviceManagementType` | Token `Unmanaged` in Probability when in (Unknown,Unmanaged) | Endpoint |
| `SigninLogs` / `AADNonInteractiveUserSignInLogs` | `RiskLevelDuringSignIn` | Token `EntraRisk:HighSignIn` when high | Identity |
| | `RiskEventTypes_V2` | Tokens `EntraRisk:LeakedCredentials`, `:AtypicalTravel`, `:AnonymizedIP` (one per event type) | Identity |
| | `ConditionalAccessStatus` | Token `ConditionalAccessNotApplied` when notApplied | Identity |
| | `AuthenticationRequirement` | Token `SingleFactorAuthRequired` | Identity |
| | `HomeTenantId vs ResourceTenantId` | Token `CrossTenantSignIn` when differ | Identity |
| | `DeviceDetail.IsCompliant` | (raw passthrough col `SigninDeviceCompliant`) | Identity |
| `AlertEvidence` (new source) | `AlertId`, `Severity`, `Title`, `EntityType`, `EntityName` | `Defender_Alert_Active` (1/0), `Defender_Alert_Count_30d`, `MoreDetails` URL per alert | All |

---

## E. Implementation cost (rough estimate)

| Tier | Scope | Files touched | Effort |
|---|---|---|---|
| **A** Add MITRE projection in 1 RA report | Pilot — `Device_Recommendations_Detailed` only. Adds 2 cols + URL formatter. | 1 YAML + 1 engine helper | ~30 min |
| **B** Roll MITRE across all `Device_*` reports | Same pattern, 8 reports | 1 YAML edit per report | ~1 hr |
| **C** Add 4 EG signals to Endpoint Profile (`MsCriticalityLevel`, `MachineRiskState`, `IsCompromisedRecently`, `IsProductionEnvironment`) | Schema + builder + DCR re-provision | 2 files; bootstrap re-runs DCR | ~1 hr |
| **D** Add new RiskFactor_Probability tokens (Defender AV, OnboardingStatus, ExclusionReason, DeviceManagementType) | Engine `Get-SIRiskFactors.ps1` adds emit logic | 1 file | ~1 hr |
| **E** Add `Defender_Alert_Active` + `Defender_Alert_Count_30d` (new source) | New AlertEvidence pull in Stage Enrich + new RA columns | 2 engine files + per-report YAML | ~3 hr |
| **F** Roll SigninLogs enrichment across Identity reports | Per-report YAML extends — 6 reports | 6 YAML edits | ~2 hr |
| **G** Auto-generate Portal URLs based on row Asset* fields | Engine `MoreDetails` enrichment block extension | 1 engine file | ~1 hr |

**Total to ship the whole model: ~10 hours of coding spread across schemas, engine, YAMLs.**

---

## F. Suggested incremental rollout

1. **First commit** — Tier A + Tier G (MITRE pilot + Portal URLs). Visible win in `Device_Recommendations_*` and immediate utility (every row gets clickable portal links).
2. **Second commit** — Tier C (EG signals to schema). Bootstrap re-runs DCR; new columns visible in next RA run.
3. **Third commit** — Tier D (RiskFactor_Probability tokens for AV / Onboarding / Mgmt).
4. **Fourth commit** — Tier B + Tier F (mass-roll MITRE across Device_* + SigninLogs enrichment across Identity_*).
5. **Fifth commit** — Tier E (AlertEvidence — new source, biggest scope).

This sequence puts the highest-visibility, lowest-risk changes first and defers the biggest scope (new source table) to last.

---

## G. What's NOT in this model (deliberate exclusions)

- **CVE description / scoring** — already covered by existing `CVSSDesc` + `HasExploit` / `IsExploitVerified` / `IsZeroDay` / `IsInExploitKit` columns
- **Tier-driving signals** — per `feedback_si_ra_tier_source` memory: tier ALWAYS sources from `SI_*_Profile_CL.Tier`, never from EG `criticalityLevel`. We surface MS criticality as a comparison column (`MsCriticalityLevel`) but don't use it to derive `Tier`.
- **Per-report bespoke columns** — keep each report's column shape predictable; reports that don't have a signal emit empty.
- **Bidirectional updates** — read-only consumption of source tables. Never write back to MDE / Entra / EG (per `feedback_si_v22_readonly` memory).
