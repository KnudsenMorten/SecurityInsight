# SecurityInsight -- Asset-profiling rule reference

This is the **single source of truth** for the `*.locked.yaml` / `*.custom.yaml` rule grammar used by the asset-profiling engines (Identity, Endpoint, Azure, PublicIP).

Every rule file under `asset-profiling-enrichment/` follows this shape. The annotated canonical example lives in [`_TEMPLATE.custom.sample.yaml`](./_TEMPLATE.custom.sample.yaml) -- copy-paste from there, then refer back here when you need to know what a field means.

> **Authority**: this document is generated from reading the engine source — `engine/asset-profiling/shared/RuleEval.ps1` (the kind handlers) and `engine/asset-profiling/shared/Get-SIRuleSet.ps1` (the loader). If something here disagrees with the code, the code wins and this doc is the bug.

---

## File-level fields

| Field | Required | Allowed values | Meaning |
|---|---|---|---|
| `id` | yes | string (`PascalCase`, no spaces) | Rule identity. **Must equal the file basename** (stripped of `.locked` / `.custom`). The engine deduplicates rules by `id` -- a `*.custom.yaml` with the same `id` as a `*.locked.yaml` overrides it. |
| `appliesTo` | yes | `endpoint` / `identity` / `azure` / `publicip` / a list `[endpoint, identity, azure]` | Engine(s) that evaluate this rule. Cross-engine rules live under `shared/`. |
| `mode` | no (default `locked`) | `locked` / `disable` | `locked` = rule loads normally. `disable` = engine skips the rule entirely (`Invoke-SIRuleEval` returns `$null` immediately). Any other value is treated as `locked`. |
| `purpose` | recommended | string | Free-text description of what this rule is for. Surfaces in run logs. |
| `category` | recommended | string | Grouping label (`Server Roles`, `CMDB Mapping`, `Group Membership`, …). Surfaces in `SIRules` array on each profile row. |
| `description` | recommended | YAML literal block (`\|`) | Multi-line operator notes. Anything you want a future maintainer to know. |
| `detections` | yes | list of detection blocks (see below) | One or more detect→set blocks. The engine walks them in array order; the **first** detection whose `detect` block matches wins (per-rule first-match). |

**Override semantics for custom files**: a `*.custom.yaml` always wins the dedup pass against its `*.locked.yaml` sibling with the same `id:`. The `append` / `merge` / `overwrite` modes are NOT implemented — your custom file fully replaces the locked one.

---

## Detection-block fields (one entry per `detections:` list item)

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Detection identity. Globally unique within the rule. Surfaces as `DetectionId` in `SIRules[]`. |
| `detect` | yes | The match condition (see Detect kinds below). |
| `set` | yes | What to stamp on the row when `detect` is true. |
| `excludeAssets` | no | List of asset names / `-like` wildcards. When the asset's `Name` matches any entry (CI), this detection is SKIPPED for that asset even if `detect` would otherwise fire -- rule evaluation continues with the next detection. Use when a legacy device matches a `tvmSoftwareNames` signal you can't remove (compat-blocking software installed), but you want that specific device out-of-scope for THIS detection only. Alias `excludeNames`. |

#### Worked example -- exclude one legacy box from the System Center detection

```yaml
# File: asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/MicrosoftSystemCenter.custom.yaml
# Path is gitignored under .custom.*; copy from .locked.yaml then add excludeAssets.
id:        MicrosoftSystemCenter
appliesTo: endpoint
mode:      locked
purpose:   'System Center role detection (with legacy-box exclusion)'
category:  'Application Service'

detections:
  - id: MicrosoftSystemCenter
    detect:
      any:
        - kind: hasSoftwareInstalled
          tvmSoftwareNames:
            - 'microsoft/system_center'
    excludeAssets:
      - 'oldlegacybox01'            # exact name match (CI)
      - 'finance-svr-*'             # wildcard match (CI)
    set:
      Tier:     0
      Purpose:  'System Center role (excluded boxes get default tier)'
      Category: 'Application Service'
```

Combine the same `excludeAssets:` block on every relevant rule when you have multiple detections firing on the same legacy device.

### `detect` -- combine semantics

```yaml
detect:
  any:                  # OR -- fires if ANY child kind matches
    - kind: ...
    - kind: ...
  # OR
  all:                  # AND -- fires only if EVERY child kind matches
    - kind: ...
    - kind: ...
```

- Use `any:` for "match if asset shows EITHER fingerprint A OR fingerprint B".
- Use `all:` for "match only if asset shows BOTH fingerprint A AND fingerprint B".
- An unknown `kind:` inside `all:` causes the whole `all:` block to fail (AND-failure). Inside `any:` it's silently skipped.

---

## Detect kinds — exhaustive registry (12 total)

Everything below is straight from `engine/asset-profiling/shared/RuleEval.ps1` `$script:SIKindRegistry`. These are the **only** kinds the engine knows. Anything else in your YAML is silently ignored.

### 1. `nameMatches` — *all engines*

Regex against the asset's display-name fields.

| Param | Type | Notes |
|---|---|---|
| `namePatterns:` | `[regex,...]` | Required. Any one matches → fires. Aliased as `patterns:`. |

Fields scanned (first non-empty wins per pattern): `Name`, `Hostname`, `DisplayName`, `Fqdn`, `MDE_DeviceName`, `ENTRA_DisplayName`, `AZ_Name`.

```yaml
- kind: nameMatches
  namePatterns:
    - '(?i)^dc\d'
    - '(?i)domain.controller'
```

---

### 2. `osPlatform` — *endpoint*

Regex against the asset's OS-platform fields.

| Param | Type | Notes |
|---|---|---|
| `osPatterns:` | `[regex,...]` | Required. Any one matches → fires. Aliased as `patterns:`. |

Fields scanned: `MDE_OSPlatform`, `ENTRA_OS`, `EG_OS`.

```yaml
- kind: osPlatform
  osPatterns:
    - '(?i)^Windows10$'
    - '(?i)^Windows11$'
```

---

### 3. `hasMdeMachineGroupTag` — *endpoint*

Regex against the asset's MDE Machine-Group string.

| Param | Type | Notes |
|---|---|---|
| `machineTagPatterns:` | `[regex,...]` | Required. Any one matches → fires. Aliased as `patterns:`. |

Field scanned: `MDE_MachineGroup` (single string; can be comma- or semicolon-separated when the device is in multiple groups — your regex sees the joined string).

```yaml
- kind: hasMdeMachineGroupTag
  machineTagPatterns:
    - '(?i)domain.controller'
    - '(?i)tier.?0'
```

---

### 4. `egDetectedRoles` — *endpoint, identity*

Matches against ExposureGraph role signals.

| Param | Type | Notes |
|---|---|---|
| `egSignals:` | `[string,...]` | Required. Aliased as `roles:`. Any one matches → fires. |

Two match modes:
1. **Substring** match against the joined `EG_DetectedRoles` string (sourced from EG `confidenceHigh`/`confidenceLow` arrays).
2. **Boolean property** match against `EG_RawData` — e.g. `egSignals: ['isDomainController']` matches when EG_RawData has `isDomainController: true`.

```yaml
- kind: egDetectedRoles
  egSignals: ['isDomainController','DomainController']
```

---

### 5. `hasEntraExtensionAttributeTag` — *identity*

Matches an Entra extensionAttribute against an exact value.

| Param | Type | Notes |
|---|---|---|
| `attribute:` | string | Required. e.g. `extensionAttribute6`. |
| `value:` | string | Required. The expected value. |
| `match:` | `exact` / anything-else | Optional, default `exact`. `exact` = case-sensitive full-string match (`-ceq`). Anything else (e.g. `like`) falls back to case-insensitive substring (`-like '*value*'`). |

Reads (in order): top-level `ENTRA_<attribute>`, then nested `ENTRA_ExtensionAttributes.<attribute>`, `ExtensionAttributes.<attribute>`, `extensionAttributes.<attribute>`.

```yaml
- kind: hasEntraExtensionAttributeTag
  attribute: extensionAttribute6
  value:     'Internal_User'
  match:     exact
```

---

### 6. `hasSoftwareInstalled` — *endpoint*

Matches against MDE TVM software inventory (per-device → list of `vendor/name` pairs).

| Param | Type | Notes |
|---|---|---|
| `tvmSoftwareNames:` | `[glob,...]` | Required. PowerShell `-like` globs. Match shape: `vendor/name` OR `*/name`. |

Examples: `microsoft/windows server 2019`, `*/sql server*`, `apache/tomcat*`.

Requires the `tvmSoftware` bulk index — built once per run by `Build-SIRuleIndexes`. Without the index, the kind silently returns `$false`.

```yaml
- kind: hasSoftwareInstalled
  tvmSoftwareNames:
    - 'microsoft/sql server*'
    - '*/apache cassandra*'
```

---

### 7. `groupMembership` — *identity*

Exact (case-insensitive) group-name match against the identity's groups index. Walks Entra direct + transitive memberships sourced from `ENTRA_Groups`.

| Param | Type | Notes |
|---|---|---|
| `group:` | string | Required. Single group name (no list — repeat the kind under `any:` for OR-of-groups). |

Short-circuits to `false` for non-user assets (SP / MI). Requires the `GroupMembership` bulk index.

```yaml
detect:
  any:
    - kind: groupMembership
      group: 'Domain Admins'
    - kind: groupMembership
      group: 'Tier0-Admins'
```

---

### 8. `hasAzureTagDirectOrParent` — *azure (also works on endpoint when EndpointAzureCorrelation has linked the row)*

ARM tag check. Walks the parent chain: resource → resource group → subscription → management group. Matches if **any** level carries the tag.

| Param | Type | Notes |
|---|---|---|
| `tag:` | string | Required. Tag KEY (always exact, case-insensitive). |
| `value:` | string / list | Optional. Without it, the kind is **presence-only** (any non-empty value for that key matches). |
| `match:` | operator | Optional, default `equal`. See operator list below. |

Requires the `parentChain` bulk index. Looks up the resource id from `AZ_ResourceId` (or `PrimaryEntityId` as fallback).

```yaml
- kind: hasAzureTagDirectOrParent
  tag:   'criticality'
  value: 'tier0'
  match: 'equal'

# Presence-only (matches any non-empty value):
- kind: hasAzureTagDirectOrParent
  tag: 'businessOwner'

# Match a list of acceptable values:
- kind: hasAzureTagDirectOrParent
  tag:   'environment'
  value: ['prod','production','PRD']
  match: 'in'
```

---

### 9. `egKustoQuery` — *endpoint, identity, azure (escape hatch)*

Pre-fetched per-rule asset id sets. The engine builds these once at run start by submitting the rule's `kql:` to ExposureGraph and caching the resulting node IDs into `$script:SIRuleIndexes.kustoSets[<RuleId>]`. The per-asset call then just checks set membership against `PrimaryEntityId` / `EG_NodeId` / `MDE_DeviceId` / `AccountObjectId`.

| Param | Type | Notes |
|---|---|---|
| `kql:` | string | Required. Raw KQL run against the EG endpoint. Must return a column whose values are asset IDs (NodeId / DeviceId / AccountObjectId). |

Per-asset evaluation does NOT submit KQL — only a hashtable lookup. Cost is paid once per rule per run.

```yaml
- kind: egKustoQuery
  kql: |
    ExposureGraphNodes
    | where NodeProperties has 'someCustomProperty'
    | project NodeId
```

---

### 10. `mostFrequentUserTier` — *endpoint*

Endpoint inherits its tier verdict from the most-frequent interactive user (logon-graph inheritance). Reads `Metadata.MostFrequentUserTier` (stamped by `Get-SIBulkDeviceUserCorrelation` at Enrich, sourced from logon graph + `SI_Identity_Profile_CL`).

| Param | Type | Notes |
|---|---|---|
| `tierValues:` | `[int,...]` | Required. List of tier numbers. Match if the device's most-frequent user tier is in this list. |

```yaml
# Workstation of a Tier-0 user → workstation gets pulled up to T1
- kind: mostFrequentUserTier
  tierValues: [0]
```

---

### 11. `ipInRange` — *endpoint, azure*

Asset IP address falls inside one of the supplied CIDR ranges. Cross-source: walks ALL known IP-bearing fields (MDE / EG / Entra / ARM / AD / CMDB).

| Param | Type | Notes |
|---|---|---|
| `cidrs:` | `[CIDR,...]` | Required. IPv4 or IPv6 CIDR strings (`a.b.c.d/N`). Aliased as `cidr:`. |
| `fields:` | `[string,...]` | Optional. Restrict which Metadata fields to scan. Default = all known IP carriers. |

Default fields scanned: `MDE_EffectiveIpAddresses`, `MDE_PublicIp`, `MDE_LastIpAddress`, `EG_PublicIp`, `EG_PrivateIp`, `EG_LastIpAddress`, `EG_InternalIpAddresses`, `ENTRA_PrivateIp`, `ENTRA_PublicIp`, `ENTRA_IpAddress`, `AZ_PrivateIp`, `AZ_PrivateIpAddresses`, `AZ_PublicIp`, `AD_IpAddress`, `AD_IpAddresses`, `CMDB_PrivateIp`, `CMDB_IpAddresses`, `CMDB_ip`, `CMDB_private_ip`. Plus the engine parses `AZ_PropertiesJson` to pull `ipAddress` / `ipConfigurations[*].properties.privateIPAddress`.

```yaml
- kind: ipInRange
  cidrs: ['10.100.1.0/24', '10.100.2.0/24', '2001:db8::/32']
```

---

### 12. `hasTag` — *endpoint, identity, azure (cross-source convenience)*

Single matcher that walks every tag carrier on the asset (MDE / EG / Entra / ARM / CMDB / AD) and fires if any pair satisfies the spec.

| Param | Type | Notes |
|---|---|---|
| `tag:` | string | Optional* | Tag KEY (exact, case-insensitive). |
| `value:` | string / list | Optional* | Tag VALUE; type depends on `match:` operator. |
| `match:` | operator | Optional, default `equal`. See operator list below. |
| `sources:` | `[string,...]` | Optional. Restrict to a subset of carriers: any of `mde`, `eg`, `entra`, `arm`, `cmdb`, `ad`. Default = all. |

*At least one of `tag:` / `value:` is required. Three modes:

- **Mode 1 — key presence** (`tag:` only): any source has that key with a non-empty value.
- **Mode 2 — value presence** (`value:` only, requires `match: in`/`regex`/`like`/`has` — plain `equal` value-only is REFUSED to prevent over-broad matches).
- **Mode 3 — exact pair** (`tag:` + `value:`): key:value match. Also matches literal `key:value` / `key=value` strings inside value-only carriers like MDE machineTags.

Carriers walked:

| Source | Shape | Origin |
|---|---|---|
| `mde` | value-only list | `MDE_MachineTags` |
| `eg` | value-only + key:value | `EG_RawData.deviceDynamicTags`, `deviceManualTags`, `tags` |
| `entra` | key:value | `ENTRA_ExtensionAttribute1..15` + `ENTRA_OnPremisesExtensionAttributes` |
| `arm` | key:value | `AZ_TagsJson` (direct) + parent-chain inheritance (RG / sub / MG) |
| `cmdb` | key:value | `Metadata.CMDB_<col>` (folded by Reconcile from CMDB.csv columns) |
| `ad` | value-only list | `AD_GroupMemberships` (placeholder) |

```yaml
# Mode 1 - "this asset is tagged 'critical' anywhere"
- kind: hasTag
  tag: 'critical'

# Mode 2 - "this asset has any tag value containing 'finance'"
- kind: hasTag
  value: '(?i)finance'
  match: regex

# Mode 3 - exact pair
- kind: hasTag
  tag:   'environment'
  value: 'production'

# Mode 3, list of acceptable values
- kind: hasTag
  tag:   'environment'
  value: ['prod','production']
  match: in

# Restrict to ARM tags only
- kind: hasTag
  tag:   'criticality'
  value: 'high'
  sources: ['arm']
```

---

## `match:` operators (used by `hasTag`, `hasAzureTagDirectOrParent`)

All operator names are case-insensitive on both name AND value. Comparisons are case-insensitive throughout.

| Operator | Behavior | Example |
|---|---|---|
| `equal` (default) | Exact string match (`-ieq`) | `value: 'production'` matches `'PRODUCTION'`. |
| `like` | PowerShell `-ilike` wildcards | `value: '*-prod-*'` matches `'app-prod-01'`. |
| `has` | Substring presence (regex-escaped) | `value: 'finance'` matches `'finance-2026'`. |
| `regex` | .NET regex (`-imatch`) | `value: '(?i)^prod[-_]'` |
| `matches` | Alias for `regex` | (same) |
| `in` | Value appears in a list | `value: ['prod','prd']` |
| `startswith` | Prefix match | `value: 'prod'` matches `'prod-app-01'` |
| `endswith` | Suffix match | `value: '-prod'` matches `'app-prod'` |

---

## `set` -- what to stamp on the row

| Field | Type | Purpose |
|---|---|---|
| `Tier` | int 0..3 | The engine's tier verdict for this asset. **0=Critical, 1=High, 2=Medium, 3=Low**. Engine reduces `min(Tier)` across all matching rules. |
| `Purpose` | string | Human-readable role label (e.g. `'Domain Controller'`). Surfaces on the profile row. |
| `Category` | string | Grouping label (e.g. `'Server Roles'`, `'CMDB Mapping'`). |
| `Tags` | list of strings | Free-form tags. Aggregated across rule matches. |
| `cmdbId` | string | **OPTIONAL.** Foreign key into `asset-profiling-providers/servicenow-cmdb/CMDB.csv`. When set, the engine looks up service `cmdbId` in the CSV at Reconcile and **auto-stamps** `cmdbName` + `cmdbCriticality` + `cmdbDataSensitivity` from the CSV row onto the profile row. |

> **DO NOT set `cmdbName`, `cmdbCriticality`, `cmdbDataSensitivity` inline.** They come from the CMDB CSV via the `cmdbId` lookup. Setting them inline overrides the CSV (single-source-of-truth violation; values drift between rule and CSV).

---

## Locked vs. custom -- file naming + override semantics

| File suffix | Purpose | Edited by | Survives release upgrade? |
|---|---|---|---|
| `<RuleId>.locked.yaml` | Shipped baseline (universal logic) | Maintainer | No -- overwritten on update |
| `<RuleId>.custom.sample.yaml` | Shipped starter template | Maintainer | No -- overwritten on update |
| `<RuleId>.custom.yaml` | Customer override | Customer | **Yes** -- gitignored, never overwritten |

**Override workflow**: copy the `.locked.yaml` to `.custom.yaml`, keep the same `id:`, edit the `set:` block (and optionally `detections:`). Engine deduplicates by `id`; the `.custom.yaml` wins.

When **only the `.custom.yaml`** exists (no `.locked.yaml` sibling) -- typical for inherently tenant-specific rules like `AssetProfileByCmdbTag`, `AssetProfileByIPSubnet`, `AssetProfileByExtensionAttributes`, `AssetProfileByGroupMembership` -- the rule still loads fine; there's nothing to override.

### How-to: full override of a shipped rule (worked example)

You want to keep the engine's `ADDomainController` detection logic but stamp **your** `cmdbId` (`SVC-AD-PROD`) onto every matched DC, and add a tag for your CAB workflow. Two-step:

1. Copy the locked file next to itself with a `.custom.yaml` suffix:
   ```
   asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/
     ADDomainController.locked.yaml    (shipped baseline -- DO NOT edit)
     ADDomainController.custom.yaml    (NEW -- your override, gitignored)
   ```
2. Inside `ADDomainController.custom.yaml`, keep the **exact same `id:`**, paste the full rule body, then change only what you want:
   ```yaml
   id:        ADDomainController          # MUST match the locked id
   appliesTo: endpoint
   osPlatformScope: [WindowsServer, Linux]
   mode:      locked
   purpose:   'Domain Controller'
   category:  'Server Roles'
   description: |
     Customer override -- keeps shipped detection, adds CMDB stamp + DC-CAB tag.

   detections:
     - id: ADDomainController
       detect:
         any:
           # ... paste the same `any:` list from the .locked.yaml verbatim ...
       set:
         Tier:     0
         Purpose:  'Domain Controller'
         Category: 'Server Roles'
         Tags:     [ 'cab:domain-controllers' ]
         cmdbId:   'SVC-AD-PROD'           # your CMDB foreign key
   ```

**Result on the next run**: the locked rule is suppressed, the custom rule fires for the same DCs, asset gets `Tier=0` + `Tags=['cab:domain-controllers']` + `cmdbId='SVC-AD-PROD'` (and Reconcile auto-stamps `cmdbName` / `cmdbCriticality` / `cmdbDataSensitivity` from your CMDB CSV). The `.custom.yaml` is gitignored so your override survives every release upgrade.

> **`cmdbId` is silently ignored when CMDB is not configured.** The engine gates `set.cmdbId` / `set.cmdbName` propagation on `$global:SI_EnableCmdbProvider`. So a community customer running without ServiceNow / a CSV provider can leave the cmdb fields in custom rules — they're inert. Flip the global on and they activate.

---

## Loading order + dedup

1. Engine scans every `*.yaml` under `asset-profiling-enrichment/<engine>/` (recursively).
2. Files ending in `.sample.yaml` are **skipped** -- they're documentation only.
3. Each remaining file is parsed; rules are tagged with their source folder (`locked` / `custom`).
4. Dedup pass -- rules with the same `id:` collapse; `custom` wins over `locked`.
5. Rules with `mode: disable` are dropped.
6. Final ruleset is evaluated against every asset; **first-match-wins per rule**, every matching rule contributes one entry to `SIRules[]` on the profile row.

---

## See also

- [`_TEMPLATE.custom.sample.yaml`](./_TEMPLATE.custom.sample.yaml) -- annotated canonical example showing every kind + every operator
- [`../asset-profiling-providers/servicenow-cmdb/`](../asset-profiling-providers/servicenow-cmdb/) -- CMDB CSV provider (where `cmdbId` lookups resolve)
- Engine code: `engine/asset-profiling/shared/RuleEval.ps1` -- the per-detection evaluator (every kind handler)
- Engine code: `engine/asset-profiling/shared/Get-SIRuleSet.ps1` -- the rule loader
- Engine code: `engine/asset-profiling/shared/RuleIndexes.ps1` -- the bulk-index builders for kinds that need pre-fetched data
