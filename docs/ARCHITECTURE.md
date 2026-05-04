# SecurityInsight v2.2 — Architecture

> Spec for the SecurityInsight v2.2 engine. This is the source of truth for
> folder layout, phase boundaries, plugin contracts, and performance rules.
> Code that does not match this document is wrong; either the code changes or
> the document changes — never both at once silently.

---

## 1. Goals

1. **One way to add a provider** (Entra, MDE, ServiceNow, Shodan, anything new).
2. **One way to add a detection rule** without touching engine code.
3. **One way for a customer to override locked content** without forking — the
   `.locked.<ext>` / `.custom.<ext>` filename infix lets shipped + customer
   files sit side-by-side in the same folder.
4. **Bulk-fetch by default.** No per-asset network calls inside the rule loop.
5. **Read-only on customer assets at run time.** Engine never writes to
   MDE / Entra / ARM during a collection run. Tagging rules emit
   WOULD-APPLY intent only. Bootstrap is opt-in and out-of-band.
6. **No version numbers in code paths or table names.** The repo carries the
   version; the runtime should look the same a year from now.

---

## 2. Top-level layout

```
v2.2/
  VERSION
  Bootstrap-Auth.ps1              one-shot bootstrap (KV / SPN / RBAC)
  Bootstrap-ContainerAppJob.ps1   one-shot ACR + Container Apps Env + jobs
  Bootstrap-Storage.ps1           one-shot storage account + containers + queues
  Get-FingerprintEngine.ps1       per-engine fingerprint helper
  auth/                           Get-SIGraphToken.ps1, Get-SIShodanKey.ps1
  container/                      Dockerfile + container entrypoints

  asset-profiling-schema/         schemas — locked + customer overrides side-by-side
  asset-profiling-enrichment/     detection-rule yamls — locked + customer side-by-side
  asset-profiling-providers/      provider plugins (entra, servicenow-cmdb, ...)
  staging/                        AI-built / shipped staging artefacts
  risk-analysis-detection/        consolidated KQL catalog + customer-editable scoring data

  engine/                         all engine code (do not edit unless fixing engine)
    asset-profiling/              profile pipeline + entry point
    risk-analysis/                RA engine + tools
  launcher/                       customer-facing entry points (one folder per engine)

  legacy/                         archived, do not use (asset-tagging, RA v2.1 yamls)
  Tests/                          static test battery
  DOCS/                           this file + Operations + reference docs
```

The five customer-facing trees are the four `asset-profiling-*` directories
plus `risk-analysis-detection/`. Everything underneath `engine/`, `launcher/`,
`auth/`, `container/`, and the bootstrap scripts is shipped code; customers
edit only the `*.custom.*` siblings inside the five customer-facing trees.

### What changed vs. early-preview shape

Preview.157 collapsed every `*-custom/` shadow folder and renamed the four
asset-profiling roots:

| Old (early preview)              | New                              |
|----------------------------------|-------------------------------------------------|
| `profiles/` + `profiles-custom/` | `asset-profiling-schema/`                       |
| `rules/` + `rules-custom/`       | `asset-profiling-enrichment/`                   |
| `providers/` + `providers-custom/` | `asset-profiling-providers/`                  |
| `risk-analysis/locked/` + `…/custom/` | `risk-analysis-detection/`                 |
| `discovery/` (top level)         | `engine/asset-profiling/discovery/` |
| `storage/` + `engine/lint` + `engine/shared` + `engine/stages` | `engine/asset-profiling/{storage,lint,shared,stages}/` |
| `privilege-tier-classifier/privilege-tier-catalog.custom.json` | `staging/asset-profiling/identity.tier.classification.json` |
| `asset-tagging/` engine          | `legacy/asset-tagging/` (retired)               |
| `*.md` (besides README)          | `DOCS/`                                         |

Locked / custom co-existence is now an **infix on the file name**, not a
sibling folder:

```
asset-profiling-schema/
  identity.schema.locked.json           shipped
  identity.schema.custom.json           customer (gitignored)
  identity.schema.custom.sample.json    starter shipped next to it
asset-profiling-enrichment/endpoint/
  ADDomainControllers.locked.yaml       shipped
  ADDomainControllers.custom.yaml       customer (gitignored)
```

Loaders skip `*.sample.*` and pair each `*.locked.<ext>` with its optional
`*.custom.<ext>` sibling at merge time.

---

## 3. Naming rules

These are non-negotiable. Lint should reject violations.

1. **No `SI` prefix in file names.** The repo lives in a folder called
   `SecurityInsight`; prefixing every file is noise.
2. **Keep `SI` prefix in PowerShell function names** (`Get-SIIdentityTierMap`,
   `Test-SIAIEnabled`). Functions are global once dot-sourced; the prefix
   prevents collisions with the user's other 200+ scripts.
3. **Keep `SI_` / `si-` prefix on Azure resource names**:
   - LA tables (`SI_Identity_Profile_CL`, `SI_RunHealth_CL`, …)
   - DCRs (`dcr-si-identity-profile`, …)
   - KV secrets (`SI_SPN_AppId`, `SI_SPN_Secret`, …)
   - Storage tables / containers / queues (`sitypeprofiles`, `sifingerprint`,
     `sistaging`, `si-<engine>-<stage>`)
   - Container App Jobs (`caj-si-<engine>-*`), UAMI (`uami-si-<engine>`),
     ACR image (`si-orchestrator`)

   The prefix is real collision protection — these resources share namespaces
   with everything else in the customer's tenant.
4. **Drop `SI_` / `SI` prefix from FIELD names within table definitions**:
   columns inside an LA table use unprefixed names (`Tier`, `Upn`, `DisplayName`,
   `PrimaryEntityId`, `Hostname`, `AssetName`, …). Inside a tenant-dedicated
   table the columns aren't sharing namespace with anything; the prefix is
   pure noise. Schema-driven row builders (`Build-IdentityProfileRow`, etc.)
   emit columns directly from `<engine>.schema.locked.json` `fields[].name`
   and already comply.
5. **Keep `SI_` prefix on `$global:` variables** (`$global:SI_EnableAI`,
   `$global:SI_SPN_AppId`). These DO share a global PowerShell namespace
   with the user's other 200+ scripts.
6. **No version numbers anywhere** — not in file names, table names, function
   names, container tags, schema `$id`. Version lives in `VERSION` and
   `git tag` only.

---

## 4. The four phases

```
   ┌──────────┐   ┌──────────┐   ┌─────────────┐   ┌────────┐
   │ DISCOVER │──▶│ COLLECT/ │──▶│  PROFILE    │──▶│ OUTPUT │
   │  who    │   │ ENRICH +  │   │  +TAGGING   │   │ write  │
   │ exists?  │   │ index     │   │  classify   │   │ rows   │
   └──────────┘   └──────────┘   └─────────────┘   └────────┘
                       │                  │
                       └─── RECONCILE ────┘
                            (CMDB join, after every engine done)
```

| Phase     | Folder                              | What it does                                                   |
|-----------|-------------------------------------|----------------------------------------------------------------|
| DISCOVER  | `engine/asset-profiling/discovery/` | One file per source — `Get-DiscoveryFromMDE.ps1`, `…FromARG`, `…FromEntra`, `…FromExposureGraph`, `…FromShodan` |
| COLLECT/ENRICH | `engine/asset-profiling/stages/Invoke-Collect.ps1` + `Invoke-Enrich.ps1` | Per-source bulk-pull, normalise into schema rows, build per-`detect.kind` indexes |
| PROFILE / TAGGING | `engine/asset-profiling/stages/Invoke-Profile.ps1` + `Invoke-Classify.ps1` + `Invoke-Tagging.ps1` | Run rules from `asset-profiling-enrichment/`, attach verdicts and standard fields. Tagging logs WOULD-APPLY intent (read-only). |
| RECONCILE | `engine/asset-profiling/stages/Invoke-Reconcile.ps1` | CMDB join + gap report (§ 13)                                  |
| OUTPUT    | `engine/asset-profiling/stages/Invoke-Output.ps1` | Sends each row to its `outputTo` targets (LA table, JSON, Excel, …) |

The orchestrator entry point is **`engine/asset-profiling/Invoke-SIEngineRun.ps1`**,
called with `-Engine endpoint|identity|azure|publicip`. Risk Analysis has its
own entry point (§ 7).

---

## 5. Schemas as the only contract

Every asset-profiling engine has exactly one locked schema in
`asset-profiling-schema/`:

```
asset-profiling-schema/
  endpoint.schema.locked.json
  identity.schema.locked.json
  azure.schema.locked.json
  public-ip.schema.locked.json
  SCHEMA.locked.json                           common-fields fragment
  tools/Build-SchemaDoc.ps1                    auto-generates DOCS/asset-profiling-schema.md
```

Customers drop a sibling `*.custom.json` (gitignored) using the same merge
modes (§ 5.1). A `*.custom.sample.json` ships next to each locked file as a
copy-paste starter.

A schema is the contract for one engine. It declares:

```jsonc
{
  "engine": "identity",
  "table":  "Identity_Profile_CL",
  "providers": {
    "in":  ["entra", "exposureGraph", "mde-identity"],
    "out": ["loganalytics", "servicenow-cmdb"]
  },
  "fields": [
    {
      "name":     "PrimaryEntityId",
      "phase":    "in",
      "source":   { "kind": "providerField", "provider": "entra", "field": "id" },
      "required": true
    },
    {
      "name":     "AssetName",
      "phase":    "in",
      "source":   { "kind": "alias", "of": ["DisplayName","Hostname","Name"] },
      "purpose":  "cross-engine display alias"
    },
    {
      "name":     "Tier",
      "phase":    "profile",
      "source":   { "kind": "rule", "id": "identity.tier" },
      "outputTo": ["loganalytics", "servicenow-cmdb"]
    }
  ]
}
```

Three things matter:

- **`providers.in` / `providers.out`** — declares which plugins this engine
  uses. The engine refuses to run if a listed provider is missing.
- **`fields[].phase`** — `in` = collect, `profile` = enrich/classify, `out` =
  derived at write time. The engine uses this to decide which stage owns the
  field.
- **`fields[].outputTo`** — empty = local-only. Non-empty = ship to those
  output providers. Lets a customer add a column that exists only in their
  ServiceNow write-back without polluting the LA table.

### 5.1 Locked + custom merge

`Get-SISchemaWithCustomMerge` (in
`engine/asset-profiling/shared/Get-SISchemaWithCustomMerge.ps1`) merges
`<engine>.schema.locked.json` with `<engine>.schema.custom.json`. Custom
files use `mode` per top-level key:

- `append`    — add to the array (default for `fields`)
- `merge`     — deep-merge object (default for `providers`)
- `overwrite` — replace wholesale
- `disable`   — drop the named entry from the locked file

Same pattern applies to rules (§ 8).

### 5.2 Cross-engine standard fields

These are present on every asset-profiling row across every engine:

| Field                    | Notes                                                                |
|--------------------------|----------------------------------------------------------------------|
| `PrimaryEntityId`        | the engine's primary key                                             |
| `AssetName`              | cross-engine alias of `DisplayName` / `Hostname` / `Name` |
| `CollectionTime`         | identical across every shard/replica of one execution                |
| `CollectHash`            | hash over every `phase: in` field                                    |
| `ProfileHash`            | hash over every `phase: profile` field + rule-set hash               |
| `RunId`                  | run identifier (one per orchestrator invocation)                     |

`RiskFactorCount` was removed from all schemas in — count is now
re-derived in queries from the `RiskFactors_*` boolean columns.
`MostFrequentUsersCount` was removed from `endpoint` in .

Engine-specific deltas worth knowing:

- **endpoint**: `IsDomainController` derived from multiple
  sources (EG roles ∪ MDE rbacGroupName ∪ name pattern); `IsStaleAsset`
  simplified; `AzureResourceId` falls back to EG when MDE doesn't have it.
- **azure**: dropped meaningless `Engine` / `Group` / `AssetId`
  columns. Added `AzureResourceId_Guid`. Renamed `SubscriptionId` →
  `AzSubscriptionId` and `ResourceGroup` → `AzResourceGroup`. The
  `properties` JSON bag is reorganised into:
  `properties.azure` (ARG row), `properties.exposuregraph` (EG node),
  `properties.azure.tags` (direct tag dict), `properties.collect.cmdb`
  (CMDB join, populated at Reconcile).
- **identity**: rule kind `adGroupMember` renamed to
  `groupMembership`; `ENTRA_ADGroups` field renamed `ENTRA_Groups`;
  `HasNoMfa` precedence bug fixed.

---

## 6. Providers

A provider is a folder under `asset-profiling-providers/`:

```
asset-profiling-providers/
  _manifest.schema.locked.json                provider-manifest JSON-Schema
  entra/
    manifest.locked.json
    Read.ps1                                  bulk pull
    Test-Connection.ps1
  servicenow-cmdb/
    manifest.locked.json
    Refresh-CmdbCache.ps1                     daily cache refresh
    CMDB.csv                                  customer drop-in (gitignored)
    sample/
      CMDB.csv                                shipped sample
```

`manifest.locked.json` (one per provider — never `manifest.json`):

```jsonc
{
  "id":        "entra",
  "kind":      "in",                 // in | out | both
  "engines":   ["identity"],
  "auth":      { "type": "spn", "scopes": ["Directory.Read.All"] },
  "bulk":      true,
  "rateLimit": { "calls": 1000, "per": "60s" }
}
```

Functions a provider must export:

| Function                       | Required when         |
|--------------------------------|-----------------------|
| `Get-ProviderManifest`         | always                |
| `Test-ProviderConnection`      | always                |
| `Read-ProviderData -Engine X`  | `kind` includes `in`  |
| `Write-ProviderData -Engine X -Rows`  | `kind` includes `out` |

The engine only ever calls those four. Adding a new provider is a new
folder; no engine code changes.

Provider list at v2.2:

| Provider          | Kind | Engines                        | Notes                         |
|-------------------|------|--------------------------------|-------------------------------|
| `entra`           | in   | identity                       | Graph                         |
| `mde`             | in   | endpoint                       | Defender XDR Hunting          |
| `mde-identity`    | in   | identity                       | IdentityInfo + LogonEvents    |
| `azure-arg`       | in   | azure, public-ip               | Resource Graph                |
| `exposure-graph`  | in   | identity, endpoint, azure      | XDR ExposureGraph*            |
| `shodan`          | in   | public-ip                      | External REST + cache         |
| `loganalytics`    | out  | all                            | DCR via AzLogDcrIngestPS      |
| `servicenow-cmdb` | both | endpoint, identity, azure      | CMDB read (CSV) + write-back  |
| `local-files`     | out  | all                            | JSON / CSV / XLSX dump        |

---

## 7. Engines and entry points

Two engine families ship in v2.2:

| Family             | Entry point                                              | Engines under it                       |
|--------------------|----------------------------------------------------------|----------------------------------------|
| asset-profiling    | `engine/asset-profiling/Invoke-SIEngineRun.ps1 -Engine <name>` | `endpoint`, `identity`, `azure`, `publicip` |
| risk-analysis      | `engine/risk-analysis/Invoke-RiskAnalysis.ps1`           | one — produces `RiskAnalysis_*_CL`     |

The asset-profiling tree (`engine/asset-profiling/`) holds:

```
asset-profiling/
  Invoke-SIEngineRun.ps1            entry point
  discovery/                        one Get-DiscoveryFrom*.ps1 per source
  stages/                           Invoke-{Discover,Collect,Enrich,Profile,Classify,Tagging,Reconcile,Output}.ps1
                                     + Invoke-{SchemaDiscover,SchemaPropose,SchemaDiff,SchemaOutput,Schedule}.ps1
  shared/                           row builders, rule evaluators, tier computers
  storage/                          StorageContext, StagingBlob, WorkerQueue, FingerprintCache, CmdbCache, ShodanCache, TypeProfileCache
  lint/                             Test-SISchemaCompliance.ps1
```

Risk Analysis (`engine/risk-analysis/`) is self-contained:

```
risk-analysis/
  Invoke-RiskAnalysis.ps1           v2.2-local RA engine
  _shared/                          Ensure-Module, Ensure-SecurityInsightInfra, Send-SecurityInsightExportFile
  _source/                          authoring sources — 5 *_Locked.yaml + 5 *_Detailed_Locked.yaml + 1 sample
  tools/
    Build-RiskAnalysis.ps1          consolidator — emits RiskAnalysis_Queries_Locked.yaml
    Build-QueriesDoc.ps1            auto-generates DOCS/risk-analysis-detection.md
    Fix-CollectionTimeWhere.ps1
  _samples/                         sample Excel + email PDFs
  README.md
```

The RA engine reads from `risk-analysis-detection/` at run time; the
consolidator in `tools/` is the **build-time** path that turns the five
`_source/` yamls into one `_Locked.yaml` shipped artefact.

---

## 8. Detection rules

`asset-profiling-enrichment/` holds the locked detection logic. Files are
grouped per engine and named after the **detection method** they implement
(`AssetProfileBy<X>`):

```
asset-profiling-enrichment/
  endpoint/
    AssetProfileByApplicationServiceDetection/      # folder, one file per role
      ADDomainControllers.locked.yaml
      ADDomainControllers.custom.yaml               # optional, customer
      ExchangeServers.locked.yaml
      …                                             # 589 role files
    AssetProfileByDeviceType.locked.yaml
  identity/
    AssetProfileByExtensionAttributes.locked.yaml
    AssetProfileByGroupMembership.locked.yaml
  azure/
    AssetProfileByTags.locked.yaml
  shared/
    AssetProfileByCmdbTag.locked.yaml               # cross-engine — `appliesTo:` list
```

Two file shapes are supported, both legal:

- **Single file** under `<engine>/` — when one method covers all variants
  in one place (typically a Tier-0/1/2 chain).
- **Folder** under `<engine>/<MethodName>/` — when a method has many
  domain-specific entries that benefit from per-entry override (one role
  per file).

### 8.1 File contract

Lint rules:

- **`id` MUST equal the file basename minus `.locked` / `.custom`.** No long
  namespaced ids — the file IS the id. `ADDomainControllers.locked.yaml` →
  `id: ADDomainControllers`.
- Every file declares `id`, `appliesTo`, `mode`, `purpose`, `category`, and
  at least one detection that resolves to a numeric `Tier`.
- `purpose` is the **specific role** the asset performs, in business terms:
  `Domain Controller`, `File service`, `Print service`, `frontend-intranet`,
  `erp-backend`, `nsg-frontend`.
- `category` is the **higher-level grouping** drawn from a small fixed
  vocabulary: `infrastructure`, `hypervisor`, `network`, `management`,
  `fileserver`, `intranet`, `application`, `database`, `web-frontend`,
  `paw`. Lint validates against the locked vocabulary.

The locked file ships **one detection per file**, with all the methods that
identify this role combined into a single `any:` block:

```yaml
id:        ADDomainControllers
appliesTo: endpoint
mode:      locked
purpose:   Domain Controller
category:  infrastructure

detections:
  - id: ADDomainControllers
    detect:
      any:
        - kind: nameMatches
          pattern: '^(dc|adc|adds)\d*$'
        - kind: hasMdeMachineGroupTag
          value: 'DomainController'
        - kind: egDetectedRoles
          roles: ['DomainController', 'ActiveDirectoryDomainServices']
        - kind: hasSoftwareInstalled
          product: 'Active Directory Domain Services'
    set:
      Tier:     0
      Purpose:  Domain Controller
      Category: infrastructure
```

The single inner detection's `id` matches the file `id` — that's the
convention when there's only one. Multi-detection files need distinct
inner ids (e.g. the FrequentUserLogon family carries Tier-1/2/3 detections
in one file with `tier1-…`, `tier2-…`, `tier3-…` ids).

Within a file, detections are evaluated in order; **first match wins** per
asset. Files within an engine folder are evaluated in lexical order.

### 8.2 Custom override

Customer overrides live next to the locked file with the same basename, as
`<id>.custom.yaml`. The custom file's `id` matches the locked file's `id`
(i.e. same basename). `mode` controls the merge:

| `mode`      | Effect                                                    |
|-------------|-----------------------------------------------------------|
| `append`    | adds detections to the locked file's `detections:` array  |
| `merge`     | deep-merges (matched by detection `id` — extends `any:`)  |
| `overwrite` | replaces the locked file wholesale                        |
| `disable`   | drops the locked file (or named detection) from the run   |

Example — customer adds their own DC naming pattern to the locked
`ADDomainControllers` detection:

```yaml
# asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/ADDomainControllers.custom.yaml
id:   ADDomainControllers
mode: merge

detections:
  - id: ADDomainControllers      # same id as locked → merge into its any:
    detect:
      any:
        - kind: nameMatches
          pattern: '^(srv-dc|legacy-dc)\d*$'
        - kind: hasAzureTag
          tag:   'role'
          value: 'domain-controller'
```

The result at runtime is one detection whose `any:` contains the four
locked entries plus the two customer entries.

`disable` lets a customer turn off a locked detection without forking
anything.

### 8.3 Cross-engine rules (`shared/`)

Files under `asset-profiling-enrichment/shared/` declare `appliesTo:` as a
list and are evaluated against multiple engines in one pass. Example:
`AssetProfileByCmdbTag.locked.yaml` reads `properties.collect.cmdb.tier`
on every endpoint / identity / azure row and sets the matching `Tier`.

---

## 9. Standard output fields

Every row in every asset-profiling engine carries the fields below (declared
in `asset-profiling-schema/SCHEMA.locked.json`, included by reference from
each engine schema). Two groups: **rule-set** (what we *deduce*) and
**cmdb-set** (what the business *says*, copied from cache during
reconciliation).

| Field                  | Phase     | Source                                            |
|------------------------|-----------|---------------------------------------------------|
| `Tier`                 | profile   | rule-set (`AssetProfileBy*` rules)                |
| `Purpose`              | profile   | rule-set (`AssetProfileBy*` rules)                |
| `Category`             | profile   | rule-set (`AssetProfileBy*` rules)                |
| `LifecycleState`       | profile   | rule-set                                          |
| `cmdbId`               | reconcile | cache lookup or grouping rule (§§ 11–13)          |
| `cmdbName`             | reconcile | cache lookup (`cmdbcis`)                          |
| `cmdbCriticality`      | reconcile | cache lookup (`cmdbservices`)                     |
| `cmdbDataSensitivity`  | reconcile | cache lookup (`cmdbservices`)                     |

Plus `PrimaryEntityId`, `AssetName`, `CollectionTime`, `CollectHash`,
`ProfileHash`, `RunId` (cross-engine, § 5.2). Reconciliation appends four
more — `CmdbMatchState`, `CmdbMatchRule`, `CmdbMatchConfidence`, `LastSeenInCmdb` (§ 13).

**Why split rule-set vs cmdb-set?** Two different authorities. Rule-set is
*us* asserting what we found; cmdb-set is the *business* asserting what they
own. Keeping them in distinct field-name groups (`Tier` vs `cmdb*`) makes
the source obvious in any downstream report.

---

## 10. Performance contract

The single biggest design rule: **rules never make external calls.** All
external data is fetched once during DISCOVER + COLLECT, indexed, and
looked up in O(1) inside the rule loop.

### 10.1 Rule kinds → bulk source

| `detect.kind`                     | What it checks                                 | Bulk source (built once in COLLECT) |
|-----------------------------------|------------------------------------------------|-------------------------------------|
| `nameMatches`                     | regex on asset name                            | asset row                           |
| `osPlatform`                      | OS family / version                            | asset row                           |
| `hasAzureTag`                     | `key:value` tag on the Azure resource itself   | asset row (Tags field)              |
| `hasAzureTagDirectOrParent`       | Azure tag on resource OR inherited from any parent (RG → sub → MG). Operators: `equal` (default) / `like` / `has` / `regex` / `matches` / `in` / `startswith` / `endswith`. Omit `value:` for presence-only check. | sub/MG hierarchy + resource tag index |
| `hasEntraExtensionAttributeTag`   | `extensionAttributeN:value` on Entra object    | Entra extension-attribute index     |
| `hasMdeMachineGroupTag`           | MDE Machine Group name                         | MDE machine-group index             |
| `hasMdeTag`                       | MDE custom tag value                           | MDE tag index                       |
| `entraGroupMember`                | Entra group membership (recursive)             | Entra group-member index            |
| `groupMembership`                 | on-prem AD group membership (recursive). Renamed from `adGroupMember` in . | AD group-member index |
| `recentLogon7days`                | logons in last 7d from a source asset/tier     | DeviceLogonEvents pre-aggregated, last 7d  |
| `recentLogon30days`               | logons in last 30d                             | DeviceLogonEvents pre-aggregated, last 30d |
| `recentLogon90days`               | logons in last 90d                             | DeviceLogonEvents pre-aggregated, last 90d |
| `hasSoftwareInstalled`            | software/product present on the asset          | EG `installedSoftware` ∪ MDE software inventory |
| `egDetectedRoles`                 | role(s) detected by Defender Exposure Graph    | EG roles index                      |
| `IPSubnetMatch`                   | asset IP within one of N CIDRs                 | CIDR trie                           |
| `egKustoQuery`                    | escape hatch — raw KQL against Defender XDR    | per-rule, run once at COLLECT, cached as id list |
| `entraKustoQuery`                 | escape hatch — raw Graph batch                 | per-rule, run once at COLLECT, cached as id list |

The two `*KustoQuery` kinds are escape hatches for detections nothing else
can express. They run **once per rule at COLLECT** (not per asset), return
a list of matching `PrimaryEntityId`s, and are stored in an index for the
per-asset loop. They preserve the bulk-fetch contract — a rule that wraps
one asset id at a time in `entraKustoQuery` is a lint failure.

Adding a new `kind` requires (a) declaring its bulk source, (b) adding the
index build in `Invoke-Collect`, (c) adding the lookup in
`engine/asset-profiling/shared/RuleEval.ps1`. Three files. No exceptions —
a rule that wants to "just call Graph from inside the loop" is a bug.

### 10.2 Three-pass execution

```
COMPILE      load all rules, group by `kind`, produce required-index list
BULK FETCH   one provider call per index, store in $script:Indexes
PER-ASSET    foreach row { foreach rule { eval against $script:Indexes } }
```

For 500 endpoints × 50 rules:

- Naive (per-asset call): 25,000 external requests.
- This design: ~5 external requests during BULK FETCH; the rule loop is pure CPU.

### 10.3 Run summary

Every run prints:

```
DISCOVER    entra=1.2s mde=4.8s eg=12.1s shodan=cache-hit=180/180
INDEX       eg.modules=4823 entries  mde.tags=512  logon.recent=18491
PROFILE     500 endpoints × 50 rules = 25,000 evals in 0.9s
OUTPUT      loganalytics=500 rows  servicenow=412 rows  json=500 rows
TOTAL       18.0s    external-calls=14    cache-hits=180
```

`external-calls` is the lint metric. If it scales with asset count, a rule
violated the contract.

---

## 11. Risk-score model — three layers

Risk Analysis builds one `RiskScore` per finding inside KQL, then the engine
multiplies by a per-finding weight to produce `RiskScoreTotal_Weighted`.
Three layers, three sources of authority:

| Layer | What                          | Where it comes from                                      | Edited by      |
|-------|-------------------------------|----------------------------------------------------------|----------------|
| 1     | Severity → Consequence        | `risk-analysis-detection/riskscore.index.custom.csv`     | customer       |
| 1     | CriticalityTier → Probability | same CSV                                                 | customer       |
| 2     | `RiskScore = Consequence × Probability`  (computed inside the KQL of every report) | engine — query-time |
| 3     | `RiskFactor_Weight` per finding type | `risk-analysis-detection/riskscore_weighted.schema.custom.json` (CMDB-driven; default `1.0`) | customer |
| 3     | `RiskScoreTotal_Weighted = RiskScore × RiskFactor_Weight` | engine — at row build time |

The shipped `riskscore.index.custom.csv` uses a 1–5 scale for each dimension
(scores run 1–25). Bumping to 1–10 is a one-file edit; the product
`Consequence × Probability` follows directly. The weight file
(`riskscore_weighted.schema.custom.json`) lets a customer say "for THIS
finding type on THIS CMDB service, multiply the score by 1.5" without
touching the CSV or the queries.

Files (all gitignored except the locked yaml + `.sample` siblings):

```
risk-analysis-detection/
  RiskAnalysis_Queries_Locked.yaml      shipped, consolidator output
  RiskAnalysis_Queries_Custom.yaml      customer (gitignored)
  RiskAnalysis_Queries_Custom.sample.yaml
  riskscore.index.custom.csv                            customer-editable
  riskscore_weighted.schema.custom.json                 customer-editable
  riskscore_weighted.schema.custom.sample.json
```

**Worked example**:

```
Finding          : Endpoint missing critical CVE patch
Severity         : Very High
Consequence      : 4   (mapped from "Very High" in riskscore.index.custom.csv)
Asset            : internet-facing web server, Tier 1
Probability base : 3   (Tier 1 base in CSV)
RiskFactor +1    : InternetExposed  → Probability = 4
                                                    ─────────
RiskScore (KQL)              = 4 × 4 = 16
RiskFactor_Weight (CMDB-driven) = 1.5  (this finding type on payroll service)
RiskScoreTotal_Weighted          = 16 × 1.5 = 24
```

The KQL of every report emits `RiskScore` (and the inputs needed to derive
it: `SecuritySeverity`, `CriticalityTierLevel`, the `RiskFactors_*`
booleans). The engine multiplies by the weight at row-build time — one
multiplication, one column.

---

## 12. CMDB / business-service mapping — overview

Bridging dynamic discovery (left) with the business CMDB (right) is its
own subsystem. Four independent pieces, each with a different update
cadence and ownership model:

| Piece                       | Section | Source                                | Cadence  | Edited by       |
|-----------------------------|---------|---------------------------------------|----------|-----------------|
| Service inventory           | § 13    | ServiceNow CSV drop                   | daily    | nobody (cached) |
| Direct CI relationships     | § 13    | ServiceNow CSV drop                   | daily    | nobody (cached) |
| Membership (grouping rules) | § 14    | `asset-profiling-enrichment/shared/`  | on edit  | customer        |
| Reconciliation + gaps       | § 15    | engine (RECONCILE)                    | per run  | nobody          |

Provider `asset-profiling-providers/servicenow-cmdb/` (`kind: both`) is the
only thing that talks to ServiceNow. The shipped flow is **CSV drop**:
customer drops a `CMDB.csv` into the provider folder (or points
`$global:SI_CmdbCsvPath` at a UNC path), and `Refresh-CmdbCache.ps1`
loads it into the cache tables. Per-run reconciliation reads from cached
tables only — never from the live CMDB. `Write-ProviderData` is the
optional write-back path for patching discovered assets back to CMDB CIs.

The four `cmdb*` standard output fields (§ 9) are populated by this
subsystem, plus four reconciliation fields from § 15.

---

## 13. CMDB cache (cached content)

Business services and CI-to-service relationships are *data*, not rules.
A local copy lives in storage tables, refreshed by a separate scheduled
job. Engine runs read from the cache only.

| Table              | Contents                                                                                       |
|--------------------|------------------------------------------------------------------------------------------------|
| `cmdbservices`     | id, name, criticality, dataSensitivity, owner, environment, last_sync                          |
| `cmdbmembership`   | cmdb_ci_id → cmdbId (the relationships ServiceNow already knows)                               |
| `cmdbcis`          | id, name, fqdn, azure_resource_id, entra_object_id, ip_addresses, tags, environment, last_seen |

CSV lookup order at refresh time:

1. `-CsvPath` parameter to `Refresh-CmdbCache.ps1`
2. `$global:SI_CmdbCsvPath` (set in customer config — typically a UNC share)
3. `asset-profiling-providers/servicenow-cmdb/CMDB.csv` (customer drop-in, gitignored)
4. `asset-profiling-providers/servicenow-cmdb/sample/CMDB.csv` (shipped sample)

Refresh job: `asset-profiling-providers/servicenow-cmdb/Refresh-CmdbCache.ps1`.
Runs daily as a separate Container App Job (or scheduled task).

Three content categories now coexist:

| Category | Lives in                                           | Edited by    | Refreshed by    |
|----------|----------------------------------------------------|--------------|-----------------|
| Locked   | `*.locked.<ext>` siblings everywhere               | repo author  | git commit      |
| Custom   | `*.custom.<ext>` siblings everywhere               | customer     | customer edit   |
| Cached   | storage tables (CMDB)                              | nobody       | scheduled job   |

### 13.1 Staleness contract

| Cache age   | Engine behaviour                                                 |
|-------------|------------------------------------------------------------------|
| < 24h       | silent, business as usual                                        |
| 24h–7d      | warning printed, proceed with cached data                        |
| > 7d        | error printed, every row tagged `CmdbMatchState=stale-cache`, gap report suppressed |

### 13.2 Lint

Every `cmdbId` referenced in customer enrichment yamls must exist in the
cached CMDB (`cmdbservices`). Checked at rule-load time, not in the
per-asset loop. A typo in a customer rule fails the run immediately.

---

## 14. Grouping rules (custom membership)

ServiceNow's CI relationships only cover assets the CMDB already knows.
Customer-defined grouping rules in
`asset-profiling-enrichment/shared/cmdb-membership.custom.yaml` fill the
gap by mapping discovered assets to a `cmdbId` using metadata the CMDB
never carried.

```yaml
id:        cmdb-membership
appliesTo: [endpoint, identity, azure]
mode:      append

membership:
  - cmdbId: CI-PAYROLL-001
    match:
      any:
        - kind: hasAzureTagDirectOrParent
          tag:   'CostCenter'
          value: 'CC-7842'
        - kind: nameMatches
          pattern: '^(payroll|salary)-.*'
        - kind: hasAzureTag
          tag:   'BusinessService'
          value: 'Payroll'
        - kind: IPSubnetMatch
          cidrs: ['10.42.0.0/16', '10.43.0.0/16']

  - cmdbId: CI-EMAIL-001
    match:
      any:
        - kind: nameMatches
          pattern: '^(exch|smtp|mail)-.*'
        - kind: hasMdeMachineGroupTag
          value: 'ExchangeServers'
```

Match kinds reuse the standard `detect.kind` set from § 10 — no special
match vocabulary. First match wins. Customer pins priority by reordering.

### 14.1 Manual escape hatch

`asset-profiling-enrichment/shared/cmdb-pins.custom.yaml`:

```yaml
pins:
  - asset_id: 'az:/subscriptions/.../resourcegroups/rg-shared/...'
    cmdbId:   CI-PAYROLL-001
    reason:   'Wrong RG, but actually a payroll AVD pool'
```

Pins beat membership rules and direct CMDB relationships. They are the
only way to override an authoritative CMDB record, and they require a
written `reason` (lint enforces it).

---

## 15. Reconciliation & gap-finding

`Invoke-Reconcile.ps1` runs once per orchestrator invocation, after every
asset-profiling engine has produced its profile rows. Two outputs:

- a `CmdbMatchState` field on every profile row (forward direction)
- a separate `Reconciliation_Gap_CL` table for CMDB CIs that nothing
  discovered (reverse direction)

### 15.1 Match priority chain

Per asset, in order — first match wins:

| Order | Source                                                                       | `CmdbMatchState`        |
|-------|------------------------------------------------------------------------------|---------------------|
| 1     | Pin (`cmdb-pins.custom.yaml`)                                                | `matched-pinned`    |
| 2     | Direct CMDB relationship (`cmdbmembership`)                                  | `matched-exact`     |
| 3     | Identity match (azure_resource_id, entra_object_id, fqdn against `cmdbcis`)  | `matched-exact`     |
| 4     | Custom grouping rule (`cmdb-membership.custom.yaml`)                         | `matched-rule`      |
| 5     | Fuzzy (name + environment heuristic, confidence ≥ 0.8)                       | `matched-fuzzy`     |
| 6     | No match                                                                     | `orphan-discovered` |

Each step records `CmdbMatchRule` (the id of the rule or relationship that
fired) and `CmdbMatchConfidence` (1.0 for exact, 0.0–1.0 for fuzzy). Customers
can debug "why did this asset map there" without reading engine code.

### 15.2 Gap table

`Reconciliation_Gap_CL` — one row per CMDB CI that did not match any
discovered asset:

| Column             | Source                                                     |
|--------------------|------------------------------------------------------------|
| `cmdbId`           | `cmdbcis.id`                                               |
| `cmdbName`         | `cmdbcis.name`                                             |
| `cmdbCriticality`  | `cmdbservices.criticality`                                 |
| `ExpectedEngine`   | inferred from CI type / tags (endpoint / identity / azure) |
| `LastSeenInCmdb`   | `cmdbcis.last_seen`                                        |
| `Reason`           | `never-seen` / `last-seen-30d` / `expected-provider-down`  |
| `CollectionTime`   | run timestamp                                              |

`Reason=expected-provider-down` is set when the engine that should have
found this CI didn't run successfully — prevents false-positive gap
reports during partial outages.

### 15.3 Reverse gap

The mirror direction (discovered asset with no CMDB CI) is captured by
`CmdbMatchState=orphan-discovered` on the per-engine profile rows:

```kql
Endpoint_Profile_CL
| where CollectionTime == toscalar(Endpoint_Profile_CL | summarize max(CollectionTime))
| where CmdbMatchState == 'orphan-discovered'
```

If only one engine runs (`-Engine endpoint`), reconciliation runs but the
gap table is suppressed (incomplete picture). Customer can opt back in
with `-ForceReconcile` and accept the noise.

---

## 16. Launchers

Customer-facing entry points live in `launcher/` — separate from
`engine/` so the customer config story is independent of engine code:

```
launcher/
  identity/                                same shape as the other 3
  endpoint/
  azure/
  publicip/
    launcher.community-vm.ps1              invokes engine/asset-profiling/Invoke-SIEngineRun.ps1 -Engine <name>
    launcher.internal-vm.ps1
    launcher.manifest.json
    LauncherConfig.defaults.ps1              shipped baseline
    LauncherConfig.custom.ps1              customer overrides (gitignored)
    LauncherConfig.custom.sample.ps1
  risk-analysis/
    launcher.community-vm.ps1              invokes engine/risk-analysis/Invoke-RiskAnalysis.ps1
    launcher.internal-vm.ps1
    launcher.manifest.json
    LauncherConfig.defaults.ps1
    LauncherConfig.custom.ps1
    LauncherConfig.custom.sample.ps1
```

Renames in `LauncherConfig.defaults.ps1` → `LauncherConfig.defaults.ps1`
- `LauncherConfig.sample.ps1` → `LauncherConfig.custom.sample.ps1`
- `launcher.*-vm.template.ps1` → `launcher.*-vm.ps1` (drop `.template`)

The launcher tree is deliberately **flat** (one file per flavour, no nested
`_lib/`). Cross-engine helpers live under `engine/` and are dot-sourced by
the launchers when needed.

---

## 17. AI

AI is **off by default for every engine**. Opt-in via:

```powershell
$global:SI_EnableAI            = $true   # all engines
$global:SI_EnableAI_endpoint   = $true   # one engine
```

Identity is **hard-disabled** regardless of the flag — identity tier is
fully rule-driven, AI on identities is a footgun (cost + drift).
`Test-SIAIEnabled -Engine <name>` is the only gate; rules and stages must
not check `$env:OPENAI_API_KEY` directly.

When AI is on, it can only be invoked from **profile-phase** rules whose
`detect.kind` is `aiClassify`. AI never runs inside the per-asset loop
naively — the rule batches assets and submits one call per N. The same
external-calls lint applies.

---

## 18. Read-only invariant

The engine **never** writes to customer assets at run time:

- No `Set-`, `New-`, `Remove-` calls against MDE / Entra / ARM in any stage.
- Tagging rules emit a "WOULD-APPLY" log row only.
- `Bootstrap-*.ps1` is the only place that writes (creates KV secret, DCR,
  RBAC, container app job). Bootstrap is opt-in and out-of-band.

The single allowed write-back path at run time is via `kind: out` providers
like `servicenow-cmdb` — and those are off unless the engine's schema
lists them in `providers.out`.

---

## 19. Hashes

Two hashes per row:

| Hash          | Inputs                                                 |
|---------------|--------------------------------------------------------|
| `CollectHash` | every `phase: in` field                                |
| `ProfileHash` | every `phase: profile` field, plus rule-set hash       |

`ProfileHash` lets KQL `summarize arg_max(CollectionTime, *) by PrimaryEntityId, ProfileHash` show only verdict-changing snapshots. `CollectHash` does the same for raw drift.

`CollectionTime` is identical across every shard / replica of one
execution, so `where CollectionTime == toscalar(... | summarize max(CollectionTime))` always returns one consistent snapshot.

---

## 20. Folder-level lint

A pre-commit / CI check enforces:

- No file under `engine/` references a path under
  `asset-profiling-providers/<x>/` directly (must go through
  `Invoke-Provider <id>`).
- No rule file uses a `detect.kind` not registered in
  `engine/asset-profiling/shared/RuleEval.ps1`.
- No file name starts with `SI`. No file name, table name, function name,
  or schema `$id` contains `v22` / `v2.2` or any version-shaped suffix.
- No FIELD/COLUMN name in `<engine>.schema.locked.json` `fields[].name`
  starts with `SI_`. Resource names themselves (LA table, DCR, KV secret,
  storage table, CAJ, UAMI, ACR image) DO retain the `SI_` / `si-` prefix.
- Every schema's `providers.in`/`providers.out` resolves to a folder under
  `asset-profiling-providers/`.
- Every rule file declares `id`, `purpose`, `category`, and every
  detection's `set:` block produces a numeric `Tier`.
- Every `cmdbId` referenced in customer enrichment yamls exists in
  `cmdbservices` (loaded from cache at lint time).
- Every `cmdb-pins.custom.yaml` entry includes a non-empty `reason`.
- `external-calls` from a smoke-test run does not scale with asset count.

The static test battery in `Tests/Test-Restructure.ps1` runs nine of these
checks on every commit (PowerShell parse, JSON parse, YAML parse, schema
merge, rule load, sample-file isolation, consolidator, stale-path absence,
schema-doc generation).

---

## 21. Migration shape

Single-commit reorganisation per preview. No two-versions-side-by-side
period inside v2.2. Resource names keep their `SI_` / `si-` prefix; only
field/column names within table definitions are unprefixed. Tags
`v2.2.x-preview.N` continue.

---

## 22. Diagram

```
                   ┌──────────────────────────────────────────────┐
                   │         engine/asset-profiling/              │
                   │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────┐ │
                   │  │Discover │▶│ Collect │▶│ Profile │▶│Out  │ │
                   │  └─────────┘ └─────────┘ └─────────┘ └─────┘ │
                   │       ▲           ▲           ▲         │    │
                   └───────┼───────────┼───────────┼─────────┼────┘
                           │           │           │         │
        ┌──────────────────┘           │           │         ▼
        │                              │           │   ┌─────────────────┐
   ┌────┴───────────────┐  ┌──────────────────┐  ┌──┴────────────────┐  │ asset-profiling-│
   │ asset-profiling-   │  │ asset-profiling- │  │ asset-profiling-  │  │  providers/     │
   │  providers/ (in)   │  │  schema/         │  │  enrichment/      │  │  (out)          │
   │  entra, mde, ...   │  │  *.locked.json   │  │  *.locked.yaml    │  │  loganalytics,  │
   │                    │  │  *.custom.json   │  │  *.custom.yaml    │  │  servicenow,    │
   └────────────────────┘  └──────────────────┘  └───────────────────┘  │  local-files    │
                                                                         └─────────────────┘
```

Three shipped trees the engine knows about: providers, schemas, enrichment
rules. Adding any of those three never requires changing `engine/`. A
fourth — `risk-analysis-detection/` — is read by the separate Risk
Analysis engine in `engine/risk-analysis/`.

---

*Last updated: 2026-04-29.*
