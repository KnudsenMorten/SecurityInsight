# SecurityInsight v2.2 — Operations Guide

How to **monitor**, **diagnose**, and **right-size** SecurityInsight asset-profiling
runs after they're deployed. Engine code and architecture live in `README.md` /
`PREVIEW.md`; this document is for the operator after first run.

---

## 1. Per-shard heartbeat — `SI_RunHealth_CL`

Every replica of `Invoke-SIEngineRun.ps1` writes two rows to
`SI_RunHealth_CL` in the customer's Log Analytics workspace:

| Phase   | Emitted at        | Carries                                                           |
|---------|-------------------|-------------------------------------------------------------------|
| `Start` | top of run        | `RunId`, `Engine`, `ShardIndex`, `ShardCount`, `Computer`         |
| `End`   | `finally` block   | adds `AssetCount`, `PeakWorkingSetMB`, `DurationSec`, `ExitReason`, `ErrorMessage` |

Both rows carry the shared `CollectionTime` so they join cleanly with the engine's
own output rows.

**Critical property:** a `Start` row with no matching `End` row is the signal that the
replica was *killed* before it could finish (OOM, container kill, infrastructure
timeout). This is the only way to detect those — Container Apps Job execution
status alone won't tell you which shard died, only that *something* did.

The heartbeat is best-effort: if the LA ingest itself fails, the warning is
swallowed (verbose only). Telemetry never kills the run it's measuring.

The table + DCR (`dcr-si-run-health`) auto-provision on first ingest via
`AzLogDcrIngestPS`. No bootstrap step required.

---

## 2. Monitoring — three layers

Pick the layer that matches your operational posture. Most setups use Layer 1 daily
+ Layer 2 on production tenants.

### Layer 1 — CLI: `Show-SIRunHealth.ps1`

The day-to-day tool. Reads `SI_RunHealth_CL` and prints three tables: failed
replicas, memory warnings, and a planned-vs-completed run summary.

```powershell
# Last 24h, all engines (default)
.\LAUNCHERS\SecurityInsight_AssetProfiling\Show-SIRunHealth.ps1

# Last week, identity engine only
.\Show-SIRunHealth.ps1 -Hours 168 -Engine identity

# Inspect one specific run end-to-end
.\Show-SIRunHealth.ps1 -RunId 20260426T144109Z-identity-7d8c743d

# Tighter memory threshold for 2 GB containers
.\Show-SIRunHealth.ps1 -MemoryWarnMB 1500
```

Output sections:

- **FAILED replicas** — Start with no End. If non-empty, check the Container App
  Job execution logs for the matching replica's exit reason (OOM kill, timeout).
- **WARNING** — End rows with `PeakWorkingSetMB > MemoryWarnMB` (default 3072
  = 75% of a 4 GB Consumption-profile container). These predict the next OOM.
- **RUN SUMMARY** — one line per run: planned `ShardCount` vs `Completed` vs
  `Missing`, total assets across shards, max peak memory, duration.

Run after every test deploy and once a month per tenant.

### Layer 2 — Azure Monitor scheduled alert

For tenants you can't manually inspect. Wire one alert per workspace; the alert
fires when any replica from the last 6h has no End row.

```bash
az monitor scheduled-query create \
  --name "SI-RunHealth-MissingEnd" \
  --resource-group "$rg" \
  --scopes "$workspaceResourceId" \
  --condition "count > 0" \
  --condition-query "let r = SI_RunHealth_CL | where TimeGenerated > ago(6h); r | where Phase == 'Start' | join kind=leftanti (r | where Phase == 'End') on RunId, ShardIndex" \
  --evaluation-frequency 30m --window-size 6h \
  --severity 2 --action "$actionGroupId"
```

Optional companion alert for chronic memory pressure (fires before the OOM):

```bash
az monitor scheduled-query create \
  --name "SI-RunHealth-MemoryPressure" \
  --resource-group "$rg" \
  --scopes "$workspaceResourceId" \
  --condition "count > 3" \
  --condition-query "SI_RunHealth_CL | where TimeGenerated > ago(24h) and Phase == 'End' and PeakWorkingSetMB > 3072" \
  --evaluation-frequency 6h --window-size 24h \
  --severity 3 --action "$actionGroupId"
```

Per-tenant config; not deployed by the engine bootstrap.

### Layer 3 — Workbook tab

Add a section to the existing SecurityInsight Workbook with the same three KQL
queries from Layer 1. Visual surface for stakeholders who don't run PowerShell.
~20 minutes of Workbook editing, no engine code change.

---

## 3. Diagnostic KQL — copy/paste

Use these directly in the LA query blade when triaging a specific incident.

```kql
// Replicas that started but never finished (OOM / killed / infra timeout)
let r = SI_RunHealth_CL | where TimeGenerated > ago(24h);
r | where Phase == 'Start'
| join kind=leftanti (r | where Phase == 'End') on RunId, ShardIndex
| project TimeGenerated, RunId, Engine, ShardIndex, ShardCount, Computer
```

```kql
// Memory pressure — flag at 75% of container limit
SI_RunHealth_CL
| where TimeGenerated > ago(24h)
| where Phase == 'End' and PeakWorkingSetMB > 3072
| project TimeGenerated, RunId, Engine, ShardIndex, AssetCount, PeakWorkingSetMB, DurationSec
| order by PeakWorkingSetMB desc
```

```kql
// Run summary — did all expected shards finish?
let r = SI_RunHealth_CL | where TimeGenerated > ago(24h);
let s = r | where Phase == 'Start' | summarize Started = count(), ShardCount = max(ShardCount) by RunId, Engine;
let e = r | where Phase == 'End' | summarize Completed = count(), Errors = countif(ExitReason == 'error') by RunId, Engine;
s | join kind=leftouter e on RunId, Engine
| extend Missing = ShardCount - coalesce(Completed, 0)
| project RunId, Engine, ShardCount, Completed = coalesce(Completed, 0), Missing, Errors = coalesce(Errors, 0)
| where Missing > 0 or Errors > 0
```

```kql
// Per-shard duration distribution — uneven shards = bad partition function
SI_RunHealth_CL
| where TimeGenerated > ago(7d) and Phase == 'End' and Engine == 'identity'
| summarize avg(DurationSec), max(DurationSec), avg(AssetCount) by ShardIndex
| order by ShardIndex asc
```

---

## 4. Right-sizing — when to bump `ParallelismIdentity`

ShardCount is set at bootstrap time per engine via `Bootstrap-ContainerAppJob.ps1
-ParallelismIdentity N` (or `-ParallelismEndpoint`, `-ParallelismAzure`). Changing it
later requires a redeploy and invalidates the partition map (hash buckets shift).

Use the heartbeat to decide N rather than guessing:

| Signal observed in `SI_RunHealth_CL`           | Action                                                 |
|------------------------------------------------|--------------------------------------------------------|
| Failed replicas (no End row) > 0               | **Bump ShardCount immediately.** Replica was killed.   |
| `PeakWorkingSetMB > 3072` consistently         | Bump ShardCount at next deploy window.                 |
| `MaxDurationSec > 30 min` for any shard        | Bump ShardCount; wall-clock budget is the constraint.  |
| All shards green, peak <50% of limit           | Current N is fine; consider lowering on next refresh.  |

Rough guidance:

| Tenant size (identities) | Suggested `ParallelismIdentity` |
|---|---|
| ≤ 50,000   | 1   (single-replica scale-up) |
| 50k–200k   | 4–8                           |
| 200k–1M    | 16–32                         |
| > 1M       | 32+ + per-page Graph filter (not yet built — see PREVIEW.md) |

---

## 5. Other operational signals to watch

Beyond the heartbeat itself, surface these in the Workbook or weekly review:

- **`Identity_Profile_CL`** — row count per `RunId`; sudden drop = upstream
  Discovery regression.
- **`ExitReason == 'error'` rate** — if > 0% over a week, an engine bug is
  shipping silent half-runs (the heartbeat fires but the work errored).
- **Cadence skip ratio** — Stage Collect logs `N cadence-skipped`. A first run
  is 0% skipped, steady state should be 80–95% skipped (only T0 + due-cadence
  identities re-process). If steady state shows < 50% skipped, fingerprint
  cache writes are failing — see `Set-SIFingerprintRecord` warnings.
- **EG enrichment rate** — Stage Collect logs `EG-enriched: N`. Should match
  `[perms] EG identity nodes: M entries indexed by AadObjectId` from Discover.
  If EG-enriched is 0 but EG nodes > 0, the join key extraction broke (see
  `Get-SIExposureGraphIdentities` in `IdentityRoleFetcher.ps1`).

---

## 6. Reference — table schema

```
SI_RunHealth_CL
├── TimeGenerated         (ingest time, automatic)
├── CollectionTime        (run-level shared timestamp; same for both rows of one shard)
├── RunId                 (e.g. 20260426T144109Z-identity-7d8c743d)
├── Engine                (endpoint | identity | azure | schema-discovery)
├── ShardIndex            (0-based replica index)
├── ShardCount            (total shards planned for this run)
├── Phase                 (Start | End)
├── AssetCount            (-1 on Start row; populated on End from Discover stage)
├── PeakWorkingSetMB      (process peak working set at End)
├── DurationSec           (UtcNow - StartedAt at End)
├── ExitReason            ('' on Start; 'success' or 'error' on End)
├── ErrorMessage          (exception text if ExitReason == 'error')
└── Computer              (replica hostname)
```

The heartbeat helper lives at
`v2.2/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1` and is invoked from
`Invoke-SIEngineRun.ps1` (Start before stages, End in `finally`).

---

## 7. Locked + Custom override pattern

Every authority file in v2.2 ships in a "locked" version (auto-updates from upstream
GitHub releases) PLUS an optional "custom" override the customer owns and that
SURVIVES upgrades. The merge happens at engine load time. Same model everywhere:

| Authority | Locked (ships) | Custom override (customer-owned) |
|---|---|---|
| Identity schema | `profiles/identity.schema.json` | `profiles-custom/identity.schema.custom.json` |
| Endpoint schema | `profiles/endpoint.schema.json` | `profiles-custom/endpoint.schema.custom.json` |
| Azure schema | `profiles/azure.schema.json` | `profiles-custom/azure.schema.custom.json` |
| Identity tier catalog | `DATA/privilege-tier-catalog.locked.json` | `identity-catalog-custom/PrivilegeTierClassifier.json` |
| Endpoint asset-class catalog | `endpoint-catalog/endpoint-tiering.json` | `endpoint-catalog-custom/endpoint-tiering.json` |
| Endpoint application catalog | `endpoint-catalog/server-applications.json` | `endpoint-catalog-custom/server-applications.json` |
| Posture rules per engine | `posture-rules-locked/<engine>/*.yaml` | `posture-rules-custom/<engine>/*.yaml` |

### Schema-merge semantics (handled by `Get-SISchemaWithCustomMerge.ps1`)

| Element | Merge rule |
|---|---|
| `fields[*]` with same `name` as locked | Custom REPLACES locked |
| `fields[*]` with new `name` | Custom APPENDS |
| `aggregator.contributors[*]` with same `id` | Custom REPLACES (override a tier weight) |
| `aggregator.contributors[*]` with new `id` | Custom APPENDS (add a tenant-specific tier rule) |
| `rawPayload.sources.<src>.includePaths[*]` | UNION (de-duped, locked first) |
| `rawPayload.sources.<new-src>` | New source bucket → ADD entirely |
| `hashes`, `entityIds`, `aiEligibility`, top-level meta | UNCHANGED — engine invariants, cannot be overridden |

### Catalog merge semantics (handled by per-engine catalog computer)

- Same `Name`/`Id` → custom REPLACES locked entry
- New `Name`/`Id` → custom APPENDS to that tier's array
- Tier-specific arrays (`Custom_PrivilegedGroups_Tier2`, `AD_BuiltInPermissionGroups_Tier2`, etc.) merged by name

### Customer use cases

**Identity custom-groups (`identity-catalog-custom/PrivilegeTierClassifier.json`)** — tag tenant-specific groups as privileged:
```json
{
  "AD_CustomGroups_Tier1": [
    { "Name": "IT-Admins",   "Reason": "IT operations -- elevated rights" }
  ],
  "AD_CustomGroups_Tier2": [
    { "Name": "ORG-FINANCE", "Reason": "Finance power users -- sensitive data" },
    { "Name": "ORG-HR",      "Reason": "HR power users -- PII access" }
  ]
}
```
After this, ORG-FINANCE members get Tier=2 in `Identity_Profile_CL`. Devices those users frequent get user-based-tier=2 too (cross-engine join).

**Custom posture rule (`posture-rules-custom/endpoint/OTSubnet_Tier0.yaml`)** — see live example shipping with v2.2.

**Schema field override (`profiles-custom/azure.schema.custom.json`)** — add a tenant-specific tier contributor:
```json
{
  "aggregator": {
    "contributors": [
      { "id": "tenant_pci_scope", "weight": 1.0,
        "algorithm": "tag_based_tier",
        "signalField": "Tags",
        "tagPattern": "(?i)pci-scope=true",
        "trueTier": 0 }
    ]
  }
}
```

---

## 8. Identity engine — recent additions

### MFA registration (preview after MDE pass-through fix)

Identity Discovery now bulk-fetches MFA + SSPR + passwordless registration via
`/reports/authenticationMethods/userRegistrationDetails` (one paged call per run).
12 new flat columns in `Identity_Profile_CL`:

| Column | Source | Use |
|---|---|---|
| `MfaIsRegistered` | bool | "User has MFA?" — primary risk signal |
| `MfaIsCapable` | bool | Could register MFA but hasn't |
| `IsPasswordlessCapable` | bool | FIDO2 / Windows Hello |
| `IsSsprRegistered` / `IsSsprCapable` / `IsSsprEnabled` | bool | SSPR posture |
| `MfaMethods` | dynamic | Array of registered method names (excludes 'password') |
| `MfaMethodCount` | int | Quick filter for "no MFA" / "MFA but only one method" |
| `MfaDefaultMethod` | string | Phone / authenticator / etc. |
| `MfaSystemPreferredMethods` | dynamic | What MS recommends for this user |
| `MfaPreferredSecondary` | string | User's chosen secondary |
| `MfaLastUpdatedDateTime` | datetime | When the user last touched MFA settings |

KQL example — find privileged users without MFA:
```kql
Identity_Profile_CL
| where Tier <= 1 and MfaIsRegistered == false
| project Upn, Tier, IdentityType, MfaIsCapable, EntraRoles_Permanent
```

### PIM-for-Groups expansion

`IdentityRoleFetcher.ps1` now also pulls
`identityGovernance/privilegedAccess/group/eligibilitySchedules` + `assignmentSchedules`.
Recursive walker (`Get-SIRolesViaPimGroupChain`) handles nested chains:
`User → PIM Group A (eligible) → PIM Group B (eligible) → Role`.
Eligible roles inherited via PIM-for-Groups now flow into `EntraRoles_Eligible`.

### Per-source verdict split

Catalog matching now produces SEPARATE `EntraRolesPermanentVerdict_*` and
`EntraRolesEligibleVerdict_*` flat columns. Was previously combined (and Eligible
hardcoded to 0).

---

## 9. Endpoint engine — recent additions

### MDE pass-through fix

MDE Discovery now emits `MDE_*`-prefixed keys (was unprefixed). Stage Collect
has an explicit `elseif ($a.MDE_DeviceId)` branch BEFORE the Entra-device fallback.
Without this, MDE-discovered devices fell into the wrong branch and `Hostname` /
`OsPlatform` / `OsVersion` / `MachineGroup` / `LastSeen` etc. all landed empty.

### Asset-class catalog (`endpoint-tiering.json`)

128 entries from §4.4 of the SecurityInsight GitHub README (T0=27, T1=41, T2=32, T3=28).
Each entry has `{Name, Tier, Category, Reason, Detection: { TvmSoftwareNames[], EgSignals[], NamePatterns[], MachineTagPatterns[] }}`.
Per-device matcher (`Get-SITierFromEndpointDevice`) walks all 4 detection channels.

### Server-application catalog (`server-applications.json`)

500 entries (T0=89, T1=186, T2=212, T3=13) — vendor + name pairs. Stage Enrich
does ONE bulk `DeviceTvmSoftwareInventory` query per run (NOT per posture rule!),
populates `$asset.Metadata.TvmSoftware`, then in-process matches against the
500-entry catalog. ~99% reduction in Defender hunting calls vs naive
one-rule-per-product.

### Cross-engine user-based tier

Per device, find top-5 most-frequent logon users (3-day window via
`DeviceLogonEvents`) → look up their tier in `Identity_Profile_CL` → MIN tier
across them = `MostFrequentUserTier`. Three new flat columns:
`MostFrequentUserTier`, `MostFrequentUsers`, `MostFrequentUsersCount`.
Aggregator contributor `endpoint_user_based_tier` weight 0.9.

KQL example — devices used by Tier-0 admins:
```kql
Endpoint_Profile_CL
| where MostFrequentUserTier == 0
| project Hostname, MostFrequentUserTier, MostFrequentUsers, OsPlatform, MachineGroup
```

### Posture rule grammar v2

Rules now declare `RuleType: KqlHunting | AssetMetadata`. AssetMetadata supports
dotted-path `Field: EgRawData.isDomainController` and operators `RegexMatch`,
`ContainsAny`. KqlHunting uses `Query:` block with `{{ParamName}}` substitution
from in-file `Parameters:` block.

Custom rules (e.g., OT subnet detection): drop in `posture-rules-custom/endpoint/`.
Locked rules at `posture-rules-locked/endpoint/`.

---

## 10. Schema-as-source-of-truth contract

The `*.schema.json` files are KING. Every engine code path reads from them:

| Reads schema for... | Function / file |
|---|---|
| LA output column list | `Build-<Engine>ProfileRow.ps1` iterates `$schema.fields` |
| Per-source verdicts | Same row builder, `_SI<Engine>KeyMap` resolves `source: entra/mde/eg/azure/derived` |
| Hashes (CollectHash, EnrichHash, etc.) | `_SIHashBag` uses `$schema.fields` filtered by `stage.writtenBy` |
| Population audit (sentinel cols) | `Invoke-Output.ps1` `$engineDispatch[$engine].AuditCols` |
| Aggregator weights | `$schema.aggregator.contributors[*]` (still partially-honored — Stage Classify aggregator wire-up in flight) |
| Raw payload allowlist | `$schema.rawPayload.sources.<src>.includePaths[*]` (drives include-only collection) |

**Adding a new schema field always lands in the schema file FIRST.** Engine code follows
the schema, never the other way around. Customer overlays via `profiles-custom/`
get merged at load time (see §7).

---

## 11. Tenant schema-drift detection (planned)

For Azure engine: at start of every run, query
`ExposureGraphNodes | where NodeLabel startswith "microsoft." | distinct NodeLabel`
and diff against the (locked + custom) catalog of known types.

- **Tenant has + catalog has** → run the per-type EG + ARG queries
- **Tenant has + catalog missing** → log to `schema-discovery-pending/azure/<type>.sample.json`
  with a real NodePropertiesJson sample for the operator to review and promote into
  `profiles-custom/azure.schema.custom.json`
- **Catalog has + tenant doesn't** → skip (query returns 0 rows)

The schema-discovery engine already
handles this drift loop for endpoint hunting tables; the same pattern extends to
Azure resource types when the locked Azure catalog reaches stable coverage.
