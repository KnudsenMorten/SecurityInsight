# SecurityInsight — design

This is the **single design document** for SecurityInsight: the architecture and how the
**built** system works — the engine pipeline, the asset-profiling data model and per-engine
schemas, the privilege-tier catalog, the enrichment/detection-rule model, the provider plugin
contract, the risk-score model, the Risk Analysis query/report catalog, the report-enrichment
vocabulary, the MDE/ExposureGraph field-gap analysis, CMDB reconciliation, hosting on VM and
Azure Container Apps Jobs (with KEDA), the Power BI dashboard, operations/runbook and
troubleshooting, and the preview/release model.

It **absorbs and de-duplicates** what used to live across many separate topic/reference docs
(`ARCHITECTURE.md`, `PROVIDER_CONTRACT.md`, `Report-Enrichment-Model.md`,
`asset-profiling-schema.md`, `SCHEMA-REFERENCE.md`, `CATALOG-REFERENCE.md`,
`QUERIES-REFERENCE.md`, `RULE-REFERENCE.md`, `RISKSCORE-REFERENCE.md`,
`risk-analysis-detection.md`, `MDE-EG-FieldGap-Audit.md`, `PowerBI-dashboard-spec.md`,
`Operations.md`, `Container-Deploy-Guide.md`, `CMDB-customer-drop.md`, `PREVIEW.md`,
`Publish-Inventory.md`, and the design parts of `README.PLAN.md`). The **backlog / requirements**
(every want, idea, constraint, out-of-scope item and its `◻`/`🟡` status) lives in
[REQUIREMENTS.md](REQUIREMENTS.md) — *not here*. The customer-facing **delivered-feature
catalog** lives in [FEATURES.md](FEATURES.md). **Test procedures and the test-suite inventory**
live in [TESTS.md](TESTS.md) — this doc only points at them.

> **Source-of-truth note.** Several portions of this design (the per-field schema tables, the
> Risk Analysis report KQL, and the per-engine column docs) are generated from authority files
> in the repo by `asset-profiling-schema/tools/Build-SchemaDoc.ps1`,
> `engine/risk-analysis/tools/Build-QueriesDoc.ps1`. When code disagrees with this doc, **code
> wins** — the authority files (`*.schema.locked.json`, `RiskAnalysis_Queries_Locked.yaml`,
> `privilege-tier-catalog.locked.json`) are the contract. This document describes the model;
> re-run the generators after structural changes.

---

## Quick facts

- **Two engine families.** *Asset Profiling* (four engines: `endpoint`, `identity`, `azure`,
  `publicip`) emits one flat-column Profile table per engine; *Risk Analysis* turns those Profile
  tables into ~100+ prioritized findings via KQL reports. A foundational
  `privilege-tier-classifier` builds the role/permission tier catalog the profilers consume.
- **Read-only at collection time.** Engine runs never write back to MDE / Entra / ARM. Bootstrap
  (workspace / DCE / DCR / RBAC / storage / container jobs) is the only write path and is opt-in,
  out-of-band. Tagging rules log WOULD-APPLY intent only.
- **PowerShell 5.1 runtime.** Engines run on Windows PowerShell 5.1 (no `?.`/`??`, no
  `RSA.ImportFromPem`; `Set-Content` defaults to UTF-16; culture-safe DateTime parsing).
- **Ingestion via AzLogDcrIngestPS.** Custom-log tables are created and fed through the author's
  own DCR ingestion module; rows carry an unprefixed `CollectionTime`, identical across all
  shards/replicas of one execution, so `where CollectionTime == max(CollectionTime)` selects the
  latest snapshot.
- **Locked + custom everywhere.** Every authority file ships as `*.locked.<ext>` and accepts an
  optional customer `*.custom.<ext>` sibling (gitignored) that survives upgrades; a
  `*.custom.sample.<ext>` ships as a copy-paste starter. The locked file auto-updates from GitHub
  releases; the custom overlay is merged at load time.
- **Bulk-fetch contract.** Detection rules never make external calls in the per-asset loop — all
  external data is fetched once during Discover/Collect, indexed, and looked up O(1). `external-calls`
  must not scale with asset count (lint-enforced).
- **Hosts.** A plain Windows VM (Task Scheduler) or Azure Container Apps Jobs with KEDA
  queue auto-scaling for large tenants. Same code on both.

---

## Table of contents

1. [Architecture overview](#architecture-overview)
2. [Engine pipeline & stages](#engine-pipeline--stages)
3. [Provider plugin contract](#provider-plugin-contract)
4. [Asset-profiling data model & schema](#asset-profiling-data-model--schema)
5. [Privilege-tier catalog](#privilege-tier-catalog)
6. [Enrichment / detection rule model](#enrichment--detection-rule-model)
7. [Risk-score model](#risk-score-model)
8. [Risk-analysis queries & report structure](#risk-analysis-queries--report-structure)
9. [Risk Analysis report catalog (model & inventory)](#risk-analysis-report-catalog-model--inventory)
10. [Report enrichment model](#report-enrichment-model)
11. [MDE / ExposureGraph field-gap audit](#mde--exposuregraph-field-gap-audit)
12. [Power BI dashboard](#power-bi-dashboard)
13. [Container & KEDA deployment](#container--keda-deployment)
14. [Preview channel & release model](#preview-channel--release-model)
15. [Operations & runbook](#operations--runbook)
16. [Troubleshooting](#troubleshooting)
17. [SI Analyzer (SIA) — hosted .NET web app](#si-analyzer-sia--hosted-net-web-app)
18. [Publish layout — what ships vs stays internal](#publish-layout--what-ships-vs-stays-internal)

---


## Architecture overview

> Source of truth for the SecurityInsight v2.2 engine: folder layout, phase boundaries, plugin contracts, and performance rules. Code that does not match this document is wrong — either the code changes or the document changes, never both at once silently.

### Goals

1. **One way to add a provider** (Entra, MDE, ServiceNow, Shodan, anything new).
2. **One way to add a detection rule** without touching engine code.
3. **One way for a customer to override locked content** without forking — the `.locked.<ext>` / `.custom.<ext>` filename infix lets shipped and customer files sit side-by-side in the same folder.
4. **Bulk-fetch by default.** No per-asset network calls inside the rule loop.
5. **Read-only on customer assets at run time.** Engine never writes to MDE / Entra / ARM during a collection run. Tagging rules emit WOULD-APPLY intent only. Bootstrap is opt-in and out-of-band.
6. **No version numbers in code paths or table names.** The repo carries the version; the runtime should look the same a year from now.

### Top-level layout

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
  asset-profiling-providers/      provider plugins (entra, generic-cmdb, ...)
  staging/                        AI-built / shipped staging artefacts
  risk-analysis-detection/        consolidated KQL catalog + customer-editable scoring data

  engine/                         all engine code (do not edit unless fixing engine)
    asset-profiling/              profile pipeline + entry point
    risk-analysis/                RA engine + tools
      _shared/RA-*.ps1            engine code dot-sourced by Invoke-RiskAnalysis.ps1 (audit #16)
  launcher/                       customer-facing entry points (one folder per engine)

  legacy/                         archived, do not use (asset-tagging, RA v2.1 yamls)
  Tests/                          static test battery
  DOCS/                           this file + Operations + reference docs
```

The five customer-facing trees are the four `asset-profiling-*` directories plus `risk-analysis-detection/`. Everything underneath `engine/`, `launcher/`, `auth/`, `container/`, and the bootstrap scripts is shipped code; customers edit only the `*.custom.*` siblings inside the five customer-facing trees.

### What changed vs. early-preview shape

Preview.157 collapsed every `*-custom/` shadow folder and renamed the four asset-profiling roots:

| Old (early preview)              | New                              |
|----------------------------------|-------------------------------------------------|
| `profiles/` + `profiles-custom/` | `asset-profiling-schema/`                       |
| `rules/` + `rules-custom/`       | `asset-profiling-enrichment/`                   |
| `providers/` + `providers-custom/` | `asset-profiling-providers/`                  |
| `risk-analysis/locked/` + `…/custom/` | `risk-analysis-detection/`                 |
| `discovery/` (top level)         | `engine/asset-profiling/discovery/` |
| `storage/` + `engine/lint` + `engine/shared` + `engine/stages` | `engine/asset-profiling/{storage,lint,shared,stages}/` |
| `privilege-tier-classifier/privilege-tier-catalog.locked.json` | `staging/asset-profiling/identity.tier.classification.json` |
| `asset-tagging/` engine          | `legacy/asset-tagging/` (retired)               |
| `*.md` (besides README)          | `DOCS/`                                         |

Locked / custom co-existence is now an **infix on the file name**, not a sibling folder:

```
asset-profiling-schema/
  identity.schema.locked.json           shipped
  identity.schema.custom.json           customer (gitignored)
  identity.schema.custom.sample.json    starter shipped next to it
asset-profiling-enrichment/endpoint/
  ADDomainControllers.locked.yaml       shipped
  ADDomainControllers.custom.yaml       customer (gitignored)
```

Loaders skip `*.sample.*` and pair each `*.locked.<ext>` with its optional `*.custom.<ext>` sibling at merge time.

### Naming rules

These are non-negotiable. Lint should reject violations.

1. **No `SI` prefix in file names.** The repo lives in a folder called `SecurityInsight`; prefixing every file is noise.
2. **Keep `SI` prefix in PowerShell function names** (`Get-SIIdentityTierMap`, `Test-SIAIEnabled`). Functions are global once dot-sourced; the prefix prevents collisions with the user's other 200+ scripts.
3. **Keep `SI_` / `si-` prefix on Azure resource names**:
   - LA tables (`SI_Identity_Profile_CL`, `SI_RunHealth_CL`, …)
   - DCRs (`dcr-si-identity-profile`, …)
   - KV secrets (`SI_SPN_AppId`, `SI_SPN_Secret`, …)
   - Storage tables / containers / queues (`sitypeprofiles`, `sifingerprint`, `sistaging`, `si-<engine>-<stage>`)
   - Container App Jobs (`caj-si-<engine>-*`), UAMI (`uami-si-<engine>`), ACR image (`si-orchestrator`)

   The prefix is real collision protection — these resources share namespaces with everything else in the customer's tenant.
4. **Drop `SI_` / `SI` prefix from FIELD names within table definitions**: columns inside an LA table use unprefixed names (`Tier`, `Upn`, `DisplayName`, `PrimaryEntityId`, `Hostname`, `AssetName`, …). Inside a tenant-dedicated table the columns aren't sharing namespace with anything; the prefix is pure noise. Schema-driven row builders (`Build-IdentityProfileRow`, etc.) emit columns directly from `<engine>.schema.locked.json` `fields[].name` and already comply.
5. **Keep `SI_` prefix on `$global:` variables** (`$global:SI_EnableAI`, `$global:SI_SPN_AppId`). These DO share a global PowerShell namespace with the user's other 200+ scripts.
6. **No version numbers anywhere** — not in file names, table names, function names, container tags, schema `$id`. Version lives in `VERSION` and `git tag` only.

### Schemas as the only contract

Every asset-profiling engine has exactly one locked schema in `asset-profiling-schema/`:

```
asset-profiling-schema/
  endpoint.schema.locked.json
  identity.schema.locked.json
  azure.schema.locked.json
  public-ip.schema.locked.json
  SCHEMA.locked.json                           common-fields fragment
  tools/Build-SchemaDoc.ps1                    auto-generates DOCS/asset-profiling-schema.md
```

Customers drop a sibling `*.custom.json` (gitignored) using the same merge modes (see "Locked + custom merge" below). A `*.custom.sample.json` ships next to each locked file as a copy-paste starter.

A schema is the contract for one engine. It declares:

```jsonc
{
  "engine": "identity",
  "table":  "SI_Identity_Profile_CL",
  "providers": {
    "in":  ["entra", "exposureGraph", "mde-identity"],
    "out": ["loganalytics", "generic-cmdb"]
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
      "outputTo": ["loganalytics", "generic-cmdb"]
    }
  ]
}
```

Three things matter:

- **`providers.in` / `providers.out`** — declares which plugins this engine uses. The engine refuses to run if a listed provider is missing.
- **`fields[].phase`** — `in` = collect, `profile` = enrich/classify, `out` = derived at write time. The engine uses this to decide which stage owns the field.
- **`fields[].outputTo`** — empty = local-only. Non-empty = ship to those output providers. Lets a customer add a column that exists only in their ServiceNow write-back without polluting the LA table.

The `*.schema.json` files are **KING**. Every engine code path reads from them:

| Reads schema for... | Function / file |
|---|---|
| LA output column list | `Build-<Engine>ProfileRow.ps1` iterates `$schema.fields` |
| Per-source verdicts | Same row builder, `_SI<Engine>KeyMap` resolves `source: entra/mde/eg/azure/derived` |
| Hashes (CollectHash, EnrichHash, etc.) | `_SIHashBag` uses `$schema.fields` filtered by `stage.writtenBy` |
| Population audit (sentinel cols) | `Invoke-Output.ps1` `$engineDispatch[$engine].AuditCols` |
| Aggregator weights | `$schema.aggregator.contributors[*]` (still partially-honored — Stage Classify aggregator wire-up in flight) |
| Raw payload allowlist | `$schema.rawPayload.sources.<src>.includePaths[*]` (drives include-only collection) |

**Adding a new schema field always lands in the schema file FIRST.** Engine code follows the schema, never the other way around. Customer overlays via the `*.custom.json` sibling get merged at load time.

### Cross-engine standard fields

These are present on every asset-profiling row across every engine (declared in `asset-profiling-schema/SCHEMA.locked.json`, included by reference from each engine schema):

| Field                    | Notes                                                                |
|--------------------------|----------------------------------------------------------------------|
| `PrimaryEntityId`        | the engine's primary key                                             |
| `AssetName`              | cross-engine alias of `DisplayName` / `Hostname` / `Name`            |
| `CollectionTime`         | identical across every shard/replica of one execution                |
| `CollectHash`            | hash over every `phase: in` field                                    |
| `ProfileHash`            | hash over every `phase: profile` field + rule-set hash               |
| `RunId`                  | run identifier (one per orchestrator invocation)                     |

`RiskFactorCount` was removed from all schemas — count is now re-derived in queries from the `RiskFactors_*` boolean columns. `MostFrequentUsersCount` was removed from `endpoint`.

Engine-specific deltas worth knowing:

- **endpoint**: `IsDomainController` derived from multiple sources (EG roles ∪ MDE rbacGroupName ∪ name pattern); `IsStaleAsset` simplified; `AzureResourceId` falls back to EG when MDE doesn't have it.
- **azure**: dropped meaningless `Engine` / `Group` / `AssetId` columns. Added `AzureResourceId_Guid`. Renamed `SubscriptionId` → `AzSubscriptionId` and `ResourceGroup` → `AzResourceGroup`. The `properties` JSON bag is reorganised into: `properties.azure` (ARG row), `properties.exposuregraph` (EG node), `properties.azure.tags` (direct tag dict), `properties.collect.cmdb` (CMDB join, populated at Reconcile).
- **identity**: rule kind `adGroupMember` renamed to `groupMembership`; `ENTRA_ADGroups` field renamed `ENTRA_Groups`; `HasNoMfa` precedence bug fixed.

### Locked + custom merge

`Get-SISchemaWithCustomMerge` (in `engine/asset-profiling/shared/Get-SISchemaWithCustomMerge.ps1`) merges `<engine>.schema.locked.json` with `<engine>.schema.custom.json`. Custom files use `mode` per top-level key:

- `append`    — add to the array (default for `fields`)
- `merge`     — deep-merge object (default for `providers`)
- `overwrite` — replace wholesale
- `disable`   — drop the named entry from the locked file

The same locked + custom override pattern applies to every authority file in v2.2. The locked version auto-updates from upstream GitHub releases; the optional custom override is customer-owned and SURVIVES upgrades. The merge happens at engine load time:

| Authority | Locked (ships) | Custom override (customer-owned) |
|---|---|---|
| Identity schema | `asset-profiling-schema/identity.schema.locked.json` | `asset-profiling-schema/identity.schema.custom.json` |
| Endpoint schema | `asset-profiling-schema/endpoint.schema.locked.json` | `asset-profiling-schema/endpoint.schema.custom.json` |
| Azure schema | `asset-profiling-schema/azure.schema.locked.json` | `asset-profiling-schema/azure.schema.custom.json` |
| PublicIP schema | `asset-profiling-schema/public-ip.schema.locked.json` | `asset-profiling-schema/public-ip.schema.custom.json` |
| Cross-engine schema fragments | `asset-profiling-schema/SCHEMA.locked.json` | (locked-only) |
| Privilege tier catalog | `privilege-tier-catalog/privilege-tier-catalog.locked.json` | `privilege-tier-catalog/privilege-tier-catalog.custom.json` |
| Risk-score weighted factors | `risk-analysis-detection/riskscore_weighted.schema.locked.json` | `risk-analysis-detection/riskscore_weighted.schema.custom.json` |
| Risk Analysis queries | `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` | `risk-analysis-detection/RiskAnalysis_Queries_Custom.yaml` |
| Posture rules (per engine) | `asset-profiling-rules/<engine>/*.locked.yaml` | `asset-profiling-rules/<engine>/*.custom.yaml` |

**Detailed schema-merge semantics** (handled by `Get-SISchemaWithCustomMerge.ps1`):

| Element | Merge rule |
|---|---|
| `fields[*]` with same `name` as locked | Custom REPLACES locked |
| `fields[*]` with new `name` | Custom APPENDS |
| `aggregator.contributors[*]` with same `id` | Custom REPLACES (override a tier weight) |
| `aggregator.contributors[*]` with new `id` | Custom APPENDS (add a tenant-specific tier rule) |
| `rawPayload.sources.<src>.includePaths[*]` | UNION (de-duped, locked first) |
| `rawPayload.sources.<new-src>` | New source bucket → ADD entirely |
| `hashes`, `entityIds`, `aiEligibility`, top-level meta | UNCHANGED — engine invariants, cannot be overridden |

**Catalog merge semantics** (handled by per-engine catalog computer):

- Same `Name`/`Id` → custom REPLACES locked entry
- New `Name`/`Id` → custom APPENDS to that tier's array
- Tier-specific arrays (`Custom_PrivilegedGroups_Tier2`, `AD_BuiltInPermissionGroups_Tier2`, etc.) merged by name

Customer use cases:

**Identity custom-groups** (`identity-catalog-custom/PrivilegeTierClassifier.json`) — tag tenant-specific groups as privileged:
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
After this, ORG-FINANCE members get Tier=2 in `SI_Identity_Profile_CL`. Devices those users frequent get user-based-tier=2 too (cross-engine join).

**Custom posture rule** (`posture-rules-custom/endpoint/OTSubnet_Tier0.yaml`) — live example ships with v2.2.

**Schema field override** (`profiles-custom/azure.schema.custom.json`) — add a tenant-specific tier contributor:
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

### Standard output fields

Every row in every asset-profiling engine carries the fields below. Two groups: **rule-set** (what we *deduce*) and **cmdb-set** (what the business *says*, copied from cache during reconciliation).

| Field                  | Phase     | Source                                            |
|------------------------|-----------|---------------------------------------------------|
| `Tier`                 | profile   | rule-set (`AssetProfileBy*` rules)                |
| `Purpose`              | profile   | rule-set (`AssetProfileBy*` rules)                |
| `Category`             | profile   | rule-set (`AssetProfileBy*` rules)                |
| `LifecycleState`       | profile   | rule-set                                          |
| `cmdbId`               | reconcile | cache lookup or grouping rule                     |
| `cmdbName`             | reconcile | cache lookup (`cmdbcis`)                          |
| `cmdbCriticality`      | reconcile | cache lookup (`cmdbservices`)                     |
| `cmdbDataSensitivity`  | reconcile | cache lookup (`cmdbservices`)                     |

Plus `PrimaryEntityId`, `AssetName`, `CollectionTime`, `CollectHash`, `ProfileHash`, `RunId` (cross-engine). Reconciliation appends four more — `CmdbMatchState`, `CmdbMatchRule`, `CmdbMatchConfidence`, `LastSeenInCmdb`.

**Why split rule-set vs cmdb-set?** Two different authorities. Rule-set is *us* asserting what we found; cmdb-set is the *business* asserting what they own. Keeping them in distinct field-name groups (`Tier` vs `cmdb*`) makes the source obvious in any downstream report.

### Hashes

Two hashes per row:

| Hash          | Inputs                                                 |
|---------------|--------------------------------------------------------|
| `CollectHash` | every `phase: in` field                                |
| `ProfileHash` | every `phase: profile` field, plus rule-set hash       |

`ProfileHash` lets KQL `summarize arg_max(CollectionTime, *) by PrimaryEntityId, ProfileHash` show only verdict-changing snapshots. `CollectHash` does the same for raw drift.

`CollectionTime` is identical across every shard / replica of one execution, so `where CollectionTime == toscalar(... | summarize max(CollectionTime))` always returns one consistent snapshot.

### Read-only invariant

The engine **never** writes to customer assets at run time:

- No `Set-`, `New-`, `Remove-` calls against MDE / Entra / ARM in any stage.
- Tagging rules emit a "WOULD-APPLY" log row only.
- `Bootstrap-*.ps1` is the only place that writes (creates KV secret, DCR, RBAC, container app job). Bootstrap is opt-in and out-of-band.

The single allowed write-back path at run time is via `kind: out` providers like `generic-cmdb` — and those are off unless the engine's schema lists them in `providers.out`.

### AI

AI is **off by default for every engine**. Opt-in via:

```powershell
$global:SI_EnableAI            = $true   # all engines
$global:SI_EnableAI_endpoint   = $true   # one engine
```

Identity is **hard-disabled** regardless of the flag — identity tier is fully rule-driven, AI on identities is a footgun (cost + drift). `Test-SIAIEnabled -Engine <name>` is the only gate; rules and stages must not check `$env:OPENAI_API_KEY` directly.

When AI is on, it can only be invoked from **profile-phase** rules whose `detect.kind` is `aiClassify`. AI never runs inside the per-asset loop naively — the rule batches assets and submits one call per N. The same external-calls lint applies.

### Provider contract (connectors)

> 📌 `asset-profiling-providers/_manifest.schema.locked.json` refers to a `_PROVIDER_CONTRACT.md`.
> **That file does not exist** — this section is the contract, per the one-doc-set rule. Anyone adding
> a provider should read this rather than reverse-engineering `entra/`.

A **provider** is a connector: a folder under `asset-profiling-providers/<id>/` holding a manifest plus
the functions below. The engine never reaches into a provider folder directly — it goes through the
provider id (see the lint rule below), so providers stay swappable.

**`manifest.json` / `manifest.locked.json`** — validated against the locked JSON schema, and now
enforced by `tests/pester/SI-ProviderContract.Tests.ps1` rather than by eye:

| Key | Required | Meaning |
|---|---|---|
| `id` | ✅ | lowercase + dashes, and **must equal the folder name** — the engine resolves provider → directory through it |
| `kind` | ✅ | `in` (read), `out` (write) or `both` |
| `engines` | ✅ | which engines it feeds — `identity` / `endpoint` / `azure` / `publicip`; non-empty |
| `auth` | ✅ | `spn` / `umi` / `api-key` / `none` (+ optional `scopes`) |
| `bulk` | ✅ | `true` when a read returns all assets in N pages rather than per-asset calls. A real boolean, not `"true"` |
| `rateLimit` | — | `{ calls, per }`, e.g. `1000` per `1h`. **Declared today, not yet enforced** |
| `description`, `schemaFragment` | — | documentation; optional schema fragment path |

**Functions** (PowerShell, dot-sourced; `<X>` is the provider's Pascal-case name):

| Function | Returns | Notes |
|---|---|---|
| `Read-<X>ProviderData -Engine -RunContext` | array of `[hashtable]` asset rows | the shape the COLLECT stage already consumes. Return `@()` for an engine this provider does not serve — do not throw |
| `Test-<X>ProviderConnection` | `@{ Ok; Error; Detail }` | `Detail` should name the *fix* (which scope or setting is missing), not just restate the failure |
| `Get-<X>ProviderManifest` | the parsed manifest | |

**Rules for a well-behaved provider**
- **Bulk, not per-asset.** A per-asset call pattern will not survive a large estate; that is what `bulk`
  advertises.
- **Page + retry through `Invoke-SIPagedRest`** (below) — never hand-roll retry.
- **Read-only at collection time.** A `kind: out`/`both` provider's write path must not run inside a
  collection run; writing belongs to a separate engine with its own gate, on the `asset-tagging`
  pattern.
- **Fail loudly, not open.** A provider that cannot reach its source must say so; a silently-empty
  result becomes silently-missing enrichment, which is the hardest defect class to notice.

### Paged REST + transient-fault retry — `Invoke-SIPagedRest`

`engine/asset-profiling/shared/Invoke-SIPagedRest.ps1` is the **one** retry implementation; discovery
modules and providers share it so retry behaviour cannot diverge between sources.

| Parameter | Meaning |
|---|---|
| `-Url`, `-Token` | first page, and the bearer token. `-ExtraHeaders` is applied **after** the `Authorization` header and therefore **overrides** it — which is how a non-bearer scheme (basic / api-key) is supplied |
| `-SourceLabel` | names the source in log lines |
| `-MaxAttempts` (4) | attempts **per page** |
| `-MaxDelaySeconds` (60) | ceiling on a single honoured `Retry-After`, so a pathological value cannot park a run |

**Behaviour:** retries `429`, `502`, `503`, `504` and network-level errors with exponential backoff,
**honouring the server's `Retry-After`** when one is sent (Graph and MDE both do). Returns
`Pages` / `Retries` / `Complete` / `Error`, so a caller can distinguish *"all pages read"* from
*"partial, and here is why"* — partial pages are preserved rather than discarded.

⚠️ **Pagination is currently OData-specific**: the loop advances on `@odata.nextLink`. Sources that page
differently (offset/limit, a `Link` header, a keyset predicate) need the advance step parameterised —
the retry half is source-agnostic and should be reused as-is rather than forked, so that there is never
more than one retry implementation to keep correct.

### Folder-level lint

A pre-commit / CI check enforces:

- No file under `engine/` references a path under `asset-profiling-providers/<x>/` directly (must go through `Invoke-Provider <id>`).
- No rule file uses a `detect.kind` not registered in `engine/asset-profiling/shared/RuleEval.ps1`.
- No file name starts with `SI`. No file name, table name, function name, or schema `$id` contains `v22` / `v2.2` or any version-shaped suffix.
- No FIELD/COLUMN name in `<engine>.schema.locked.json` `fields[].name` starts with `SI_`. Resource names themselves (LA table, DCR, KV secret, storage table, CAJ, UAMI, ACR image) DO retain the `SI_` / `si-` prefix.
- Every schema's `providers.in`/`providers.out` resolves to a folder under `asset-profiling-providers/`.
- Every rule file declares `id`, `purpose`, `category`, and every detection's `set:` block produces a numeric `Tier`.
- Every `cmdbId` referenced in customer enrichment yamls exists in `cmdbservices` (loaded from cache at lint time).
- Every `cmdb-pins.custom.yaml` entry includes a non-empty `reason`.
- `external-calls` from a smoke-test run does not scale with asset count.

The static test battery in `Tests/Test-Restructure.ps1` runs nine of these checks on every commit (PowerShell parse, JSON parse, YAML parse, schema merge, rule load, sample-file isolation, consolidator, stale-path absence, schema-doc generation).

### Migration shape

Single-commit reorganisation per preview. No two-versions-side-by-side period inside v2.2. Resource names keep their `SI_` / `si-` prefix; only field/column names within table definitions are unprefixed. Tags `v2.2.x-preview.N` continue.

### High-level diagram

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

Three shipped trees the engine knows about: providers, schemas, enrichment rules. Adding any of those three never requires changing `engine/`. A fourth — `risk-analysis-detection/` — is read by the separate Risk Analysis engine in `engine/risk-analysis/`.

---

## Engine pipeline & stages

### Engines and entry points

Two engine families ship in v2.2:

| Family             | Entry point                                              | Engines under it                       |
|--------------------|----------------------------------------------------------|----------------------------------------|
| asset-profiling    | `engine/asset-profiling/Invoke-SIEngineRun.ps1 -Engine <name>` | `endpoint`, `identity`, `azure`, `publicip` |
| risk-analysis      | `engine/risk-analysis/Invoke-RiskAnalysis.ps1`           | one — produces `RiskAnalysis_*_CL`     |

**The RA engine is being split out of its single file (audit #16), and the rule for doing so is
narrow.** A moved block must be (1) a **contiguous span**, (2) dot-sourced **at the exact position it
occupied**, and (3) free of `$PSScriptRoot` / `$PSCommandPath` / `$MyInvocation`.

Rules 1 and 2 together are what preserve behaviour, and they are why the audit's own phrasing —
"split along the existing banner-comment seams" — is not safe as stated. Those seams interleave
executable top-level statements with declarations (16 of them in the `FUNCTIONS` region alone). Move
a seam's *functions* to a file dot-sourced somewhere else, and that interleaved code now runs at a
different point in the load — silently, with no parse error. Keep the span contiguous and the
dot-source in place, and the statements still execute in the same order relative to the same
neighbours, so an interleaved assignment can travel with the block safely (`RA-AutoBucketing.ps1`
carries `$script:AutoBucketConfirmedKey` for exactly this reason).

🔒 **Never put `$PSScriptRoot`-dependent code in `_shared/`.** The engine derives `$siRoot` as
`Split-Path -Parent (Split-Path -Parent $PSScriptRoot)`; inside a `_shared/` file that resolves one
directory deeper and silently yields a different root. Three functions
(`Get-WeightedFactorsConfig`, `Invoke-SISentinelLakeQuery`, `Save-RARenderedQuery`) stay in the main
script for exactly this reason. `tests/Get-EngineFunctionInventory.ps1` reports which functions are
pinned, and proves a move was byte-for-byte.

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
  tools/
    Build-QueriesDoc.ps1            auto-generates DOCS/risk-analysis-detection.md FROM the catalog
    Fix-CollectionTimeWhere.ps1
  _samples/                         sample Excel + email PDFs
  README.md
```

🔒 **`risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` IS the source of truth. It is
hand-maintained, not generated — edit it directly.**

**Audit #28 (2026-08-06) — `_source/` and `tools/Build-RiskAnalysis.ps1` were RETIRED and deleted.**
This section used to describe a build-time path turning five `_source/` yamls into the shipped
`_Locked.yaml`. That path had been dead for months: `_source/` and the consolidator went untouched
since commit `536e1405` (the v2.2.0 flatten) while the catalog was edited continuously — cross-domain
re-keys, scope trims, per-report hotfixes. Regenerating would have produced **264 reports instead of
118**, dropped 57 shipped reports, added 203 that never shipped, and renamed the templates to
`*_Bucket` — so the launcher's `RiskAnalysis_Summary` would not exist and the engine would **throw on
every run**. Recover from git if ever needed:
`git show 536e1405:SOLUTIONS/SecurityInsight/engine/risk-analysis/_source/`.
A swap-in is now caught by `tests/pester/SI-OutputColumnUnion.Tests.ps1` ("audit #28").

### The four phases

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
| RECONCILE | `engine/asset-profiling/stages/Invoke-Reconcile.ps1` | CMDB join + gap report                                          |
| OUTPUT    | `engine/asset-profiling/stages/Invoke-Output.ps1` | Sends each row to its `outputTo` targets (LA table, JSON, Excel, …) |

The orchestrator entry point is **`engine/asset-profiling/Invoke-SIEngineRun.ps1`**, called with `-Engine endpoint|identity|azure|publicip`. Risk Analysis has its own entry point.

#### Cross-source correlation — recognising ONE device across MDE / Exposure Graph / Entra

`Invoke-Discover.ps1` runs a **second pass** after the name-based merge, whose whole job is to
recognise that three sources are describing the same physical device. **The merge key is
`AadDeviceId`** — the one identifier all three expose (`MDE_AadDeviceId`, `EG_AadDeviceId`,
`ENTRA_AadDeviceId`).

The rules, and each exists for a reason:

| rule | why |
|---|---|
| Key is **lower-cased** before comparison | the three sources disagree on GUID casing |
| The **zero GUID is skipped** | it is a placeholder, not an identity — merging on it would collapse unrelated devices into one |
| A record whose sources carry **CONFLICTING** ids is **NOT merged on any of them** | `MDE=X` and `EG=Y` is a data-quality problem; merging would assert "same device" on contradictory evidence |
| Two records with **wildly different names** sharing an id are **not collapsed** | an id collision from upstream corruption must not fuse two real devices |

⚠️ **The outcome of all of this is currently INVISIBLE on a normal run (audit #27).** The counters —
how many records were collapsed (`aadMergeCount`), how many refused for conflicting ids
(`conflictSkipCount`), how many had no usable key — are logged through `Write-SIDiag`, which prints
**only** when `$global:SI_Verbose` or `-Verbose` is set. **Correlation can therefore be failing across
most of the estate while the run looks completely clean.** Treat correlation coverage as a
data-quality metric to be reported every run, not as a debug detail.

### Detection rules

`asset-profiling-enrichment/` holds the locked detection logic. Files are grouped per engine and named after the **detection method** they implement (`AssetProfileBy<X>`):

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

- **Single file** under `<engine>/` — when one method covers all variants in one place (typically a Tier-0/1/2 chain).
- **Folder** under `<engine>/<MethodName>/` — when a method has many domain-specific entries that benefit from per-entry override (one role per file).

#### File contract

Lint rules:

- **`id` MUST equal the file basename minus `.locked` / `.custom`.** No long namespaced ids — the file IS the id. `ADDomainControllers.locked.yaml` → `id: ADDomainControllers`.
- Every file declares `id`, `appliesTo`, `mode`, `purpose`, `category`, and at least one detection that resolves to a numeric `Tier`.
- `purpose` is the **specific role** the asset performs, in business terms: `Domain Controller`, `File service`, `Print service`, `frontend-intranet`, `erp-backend`, `nsg-frontend`.
- `category` is the **higher-level grouping** drawn from a small fixed vocabulary: `infrastructure`, `hypervisor`, `network`, `management`, `fileserver`, `intranet`, `application`, `database`, `web-frontend`, `paw`. Lint validates against the locked vocabulary.

The locked file ships **one detection per file**, with all the methods that identify this role combined into a single `any:` block:

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

The single inner detection's `id` matches the file `id` — that's the convention when there's only one. Multi-detection files need distinct inner ids (e.g. the FrequentUserLogon family carries Tier-1/2/3 detections in one file with `tier1-…`, `tier2-…`, `tier3-…` ids).

Within a file, detections are evaluated in order; **first match wins** per asset. Files within an engine folder are evaluated in lexical order.

#### Custom override

Customer overrides live next to the locked file with the same basename, as `<id>.custom.yaml`. The custom file's `id` matches the locked file's `id` (i.e. same basename). `mode` controls the merge:

| `mode`      | Effect                                                    |
|-------------|-----------------------------------------------------------|
| `append`    | adds detections to the locked file's `detections:` array  |
| `merge`     | deep-merges (matched by detection `id` — extends `any:`)  |
| `overwrite` | replaces the locked file wholesale                        |
| `disable`   | drops the locked file (or named detection) from the run   |

Example — customer adds their own DC naming pattern to the locked `ADDomainControllers` detection:

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

The result at runtime is one detection whose `any:` contains the four locked entries plus the two customer entries. `disable` lets a customer turn off a locked detection without forking anything.

#### Cross-engine rules (`shared/`)

Files under `asset-profiling-enrichment/shared/` declare `appliesTo:` as a list and are evaluated against multiple engines in one pass. Example: `AssetProfileByCmdbTag.locked.yaml` reads `properties.collect.cmdb.tier` on every endpoint / identity / azure row and sets the matching `Tier`.

#### Posture rule grammar v2

Rules declare `RuleType: KqlHunting | AssetMetadata`. AssetMetadata supports dotted-path `Field: EgRawData.isDomainController` and operators `RegexMatch`, `ContainsAny`. KqlHunting uses a `Query:` block with `{{ParamName}}` substitution from an in-file `Parameters:` block. Custom rules (e.g. OT subnet detection) drop into `posture-rules-custom/endpoint/`; locked rules live at `posture-rules-locked/endpoint/`.

### Performance contract

The single biggest design rule: **rules never make external calls.** All external data is fetched once during DISCOVER + COLLECT, indexed, and looked up in O(1) inside the rule loop.

#### Rule kinds → bulk source

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
| `groupMembership`                 | on-prem AD group membership (recursive). Renamed from `adGroupMember`. | AD group-member index |
| `recentLogon7days`                | logons in last 7d from a source asset/tier     | DeviceLogonEvents pre-aggregated, last 7d  |
| `recentLogon30days`               | logons in last 30d                             | DeviceLogonEvents pre-aggregated, last 30d |
| `recentLogon90days`               | logons in last 90d                             | DeviceLogonEvents pre-aggregated, last 90d |
| `hasSoftwareInstalled`            | software/product present on the asset          | EG `installedSoftware` ∪ MDE software inventory |
| `egDetectedRoles`                 | role(s) detected by Defender Exposure Graph    | EG roles index                      |
| `IPSubnetMatch`                   | asset IP within one of N CIDRs                 | CIDR trie                           |
| `egKustoQuery`                    | escape hatch — raw KQL against Defender XDR    | per-rule, run once at COLLECT, cached as id list |
| `entraKustoQuery`                 | escape hatch — raw Graph batch                 | per-rule, run once at COLLECT, cached as id list |

The two `*KustoQuery` kinds are escape hatches for detections nothing else can express. They run **once per rule at COLLECT** (not per asset), return a list of matching `PrimaryEntityId`s, and are stored in an index for the per-asset loop. They preserve the bulk-fetch contract — a rule that wraps one asset id at a time in `entraKustoQuery` is a lint failure.

Adding a new `kind` requires (a) declaring its bulk source, (b) adding the index build in `Invoke-Collect`, (c) adding the lookup in `engine/asset-profiling/shared/RuleEval.ps1`. Three files. No exceptions — a rule that wants to "just call Graph from inside the loop" is a bug.

#### Three-pass execution

```
COMPILE      load all rules, group by `kind`, produce required-index list
BULK FETCH   one provider call per index, store in $script:Indexes
PER-ASSET    foreach row { foreach rule { eval against $script:Indexes } }
```

For 500 endpoints × 50 rules:

- Naive (per-asset call): 25,000 external requests.
- This design: ~5 external requests during BULK FETCH; the rule loop is pure CPU.

#### Run summary

Every run prints:

```
DISCOVER    entra=1.2s mde=4.8s eg=12.1s shodan=cache-hit=180/180
INDEX       eg.modules=4823 entries  mde.tags=512  logon.recent=18491
PROFILE     500 endpoints × 50 rules = 25,000 evals in 0.9s
OUTPUT      loganalytics=500 rows  servicenow=412 rows  json=500 rows
TOTAL       18.0s    external-calls=14    cache-hits=180
```

`external-calls` is the lint metric. If it scales with asset count, a rule violated the contract.

### Risk-score model — three layers

Risk Analysis builds one `RiskScore` per finding inside KQL, then the engine multiplies by a per-finding weight to produce `RiskScoreTotal_Weighted`. Three layers, three sources of authority:

| Layer | What                          | Where it comes from                                      | Edited by      |
|-------|-------------------------------|----------------------------------------------------------|----------------|
| 1     | Severity → Consequence        | `risk-analysis-detection/riskscore.index.custom.csv`     | customer       |
| 1     | CriticalityTier → Probability | same CSV                                                 | customer       |
| 2     | `RiskScore = Consequence × Probability`  (computed inside the KQL of every report) | engine — query-time |
| 3     | `RiskFactor_Weight` per finding type | `risk-analysis-detection/riskscore_weighted.schema.custom.json` (CMDB-driven; default `1.0`) | customer |
| 3     | `RiskScoreTotal_Weighted = RiskScore × RiskFactor_Weight` | engine — at row build time |

The shipped `riskscore.index.custom.csv` uses a 1–5 scale for each dimension (scores run 1–25). Bumping to 1–10 is a one-file edit; the product `Consequence × Probability` follows directly. The weight file (`riskscore_weighted.schema.custom.json`) lets a customer say "for THIS finding type on THIS CMDB service, multiply the score by 1.5" without touching the CSV or the queries.

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

The KQL of every report emits `RiskScore` (and the inputs needed to derive it: `SecuritySeverity`, `CriticalityTierLevel`, the `RiskFactors_*` booleans). The engine multiplies by the weight at row-build time — one multiplication, one column.

### CMDB / business-service mapping

Bridging dynamic discovery (left) with the business CMDB (right) is its own subsystem. Four independent pieces, each with a different update cadence and ownership model:

| Piece                       | Source                                | Cadence  | Edited by       |
|-----------------------------|---------------------------------------|----------|-----------------|
| Service inventory           | ServiceNow CSV drop                   | daily    | nobody (cached) |
| Direct CI relationships     | ServiceNow CSV drop                   | daily    | nobody (cached) |
| Membership (grouping rules) | `asset-profiling-enrichment/shared/`  | on edit  | customer        |
| Reconciliation + gaps       | engine (RECONCILE)                    | per run  | nobody          |

Provider `asset-profiling-providers/generic-cmdb/` (`kind: both`) is the only thing that talks to ServiceNow. The shipped flow is **CSV drop**: customer drops a `CMDB.csv` into the provider folder (or points `$global:SI_CmdbCsvPath` at a UNC path), and `Refresh-CmdbCache.ps1` loads it into the cache tables. Per-run reconciliation reads from cached tables only — never from the live CMDB. `Write-ProviderData` is the optional write-back path for patching discovered assets back to CMDB CIs.

> 📌 **The manifest declares more than the implementation currently does.** `manifest.locked.json` says
> `kind: both`, `auth: api-key`, `bulk: true` — that describes the *intended* live REST integration
> (read CIs / services / relationships, optional write-back). **What ships today is the CSV reader
> above**: there is no HTTP call in the provider at all. Read the manifest as the contract the
> provider is being built toward, not as a description of what runs. A live REST read is planned; the
> write-back half will be a separately gated capability, because writing into a customer's CMDB is a
> materially different trust decision from reading it.

#### CMDB cache (cached content)

Business services and CI-to-service relationships are *data*, not rules. A local copy lives in storage tables, refreshed by a separate scheduled job. Engine runs read from the cache only.

| Table              | Contents                                                                                       |
|--------------------|------------------------------------------------------------------------------------------------|
| `cmdbservices`     | id, name, criticality, dataSensitivity, owner, environment, last_sync                          |
| `cmdbmembership`   | cmdb_ci_id → cmdbId (the relationships ServiceNow already knows)                               |
| `cmdbcis`          | id, name, fqdn, azure_resource_id, entra_object_id, ip_addresses, tags, environment, last_seen |

CSV lookup order at refresh time:

1. `-CsvPath` parameter to `Refresh-CmdbCache.ps1`
2. `$global:SI_CmdbCsvPath` (set in customer config — typically a UNC share)
3. `asset-profiling-providers/generic-cmdb/CMDB.csv` (customer drop-in, gitignored)
4. `asset-profiling-providers/generic-cmdb/sample/CMDB.csv` (shipped sample)

Refresh job: `asset-profiling-providers/generic-cmdb/Refresh-CmdbCache.ps1`. Runs daily as a separate Container App Job (or scheduled task), and is also invoked by the SCHEDULE stage when the cached snapshot is older than the configured interval.

> ⚠️ **Known limitation — the auto-refresh is a no-op when storage uses OAuth (the default since
> v2.2.314).** `Refresh-CmdbCache.ps1` signs its Table Storage calls with a **shared key**, and an
> OAuth-mode run carries no storage key, so the SCHEDULE stage logs that it is skipping the refresh
> and falls through to the existing cached snapshot. The run still completes successfully — the CMDB
> cache simply stops ageing forward. Until the helper is reworked to use OAuth bearer tokens against
> the Table Storage REST API, refresh the cache by running the job **directly** with an account key,
> or accept that the cache is only as fresh as the last key-authenticated refresh. A CMDB cache that
> is stale rather than absent still reconciles; it just reflects an older CI/service picture.

Three content categories now coexist:

| Category | Lives in                                           | Edited by    | Refreshed by    |
|----------|----------------------------------------------------|--------------|-----------------|
| Locked   | `*.locked.<ext>` siblings everywhere               | repo author  | git commit      |
| Custom   | `*.custom.<ext>` siblings everywhere               | customer     | customer edit   |
| Cached   | storage tables (CMDB)                              | nobody       | scheduled job   |

**Staleness contract:**

| Cache age   | Engine behaviour                                                 |
|-------------|------------------------------------------------------------------|
| < 24h       | silent, business as usual                                        |
| 24h–7d      | warning printed, proceed with cached data                        |
| > 7d        | error printed, every row tagged `CmdbMatchState=stale-cache`, gap report suppressed |

**Lint:** Every `cmdbId` referenced in customer enrichment yamls must exist in the cached CMDB (`cmdbservices`). Checked at rule-load time, not in the per-asset loop. A typo in a customer rule fails the run immediately.

#### Grouping rules (custom membership)

ServiceNow's CI relationships only cover assets the CMDB already knows. Customer-defined grouping rules in `asset-profiling-enrichment/shared/cmdb-membership.custom.yaml` fill the gap by mapping discovered assets to a `cmdbId` using metadata the CMDB never carried.

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

Match kinds reuse the standard `detect.kind` set from the performance contract — no special match vocabulary. First match wins. Customer pins priority by reordering.

**Manual escape hatch** — `asset-profiling-enrichment/shared/cmdb-pins.custom.yaml`:

```yaml
pins:
  - asset_id: 'az:/subscriptions/.../resourcegroups/rg-shared/...'
    cmdbId:   CI-PAYROLL-001
    reason:   'Wrong RG, but actually a payroll AVD pool'
```

Pins beat membership rules and direct CMDB relationships. They are the only way to override an authoritative CMDB record, and they require a written `reason` (lint enforces it).

#### Reconciliation & gap-finding

`Invoke-Reconcile.ps1` runs once per orchestrator invocation, after every asset-profiling engine has produced its profile rows. Two outputs:

- a `CmdbMatchState` field on every profile row (forward direction)
- a separate `Reconciliation_Gap_CL` table for CMDB CIs that nothing discovered (reverse direction)

**Match priority chain** — per asset, in order, first match wins:

| Order | Source                                                                       | `CmdbMatchState`        |
|-------|------------------------------------------------------------------------------|---------------------|
| 1     | Pin (`cmdb-pins.custom.yaml`)                                                | `matched-pinned`    |
| 2     | Direct CMDB relationship (`cmdbmembership`)                                  | `matched-exact`     |
| 3     | Identity match (azure_resource_id, entra_object_id, fqdn against `cmdbcis`)  | `matched-exact`     |
| 4     | Custom grouping rule (`cmdb-membership.custom.yaml`)                         | `matched-rule`      |
| 5     | Fuzzy (name + environment heuristic, confidence ≥ 0.8)                       | `matched-fuzzy`     |
| 6     | No match                                                                     | `orphan-discovered` |

Each step records `CmdbMatchRule` (the id of the rule or relationship that fired) and `CmdbMatchConfidence` (1.0 for exact, 0.0–1.0 for fuzzy). Customers can debug "why did this asset map there" without reading engine code.

##### 🔑 CMDB column naming — `cmdb*` vs `Cmdb*` is deliberate, and it tells you where the value came from

**Log Analytics column names are case-sensitive in KQL**, so this matters before you write a query or bind a dashboard. The CMDB family splits into two namespaces:

| namespace | means | columns |
|---|---|---|
| **`cmdb…`** (lower-case first letter) | **a value copied verbatim from the CMDB record.** SI does not compute or interpret it — what your CMDB said is what you get | `cmdbId`, `cmdbName`, `cmdbCriticality`, `cmdbDataSensitivity` |
| **`Cmdb…`** (capital first letter) | **SI's own metadata about the match** — how, whether, and from which source the asset was reconciled. Computed by SI, not present in your CMDB | `CmdbSource`, `CmdbMatchPhase`, `CmdbMatchState`, `CmdbMatchRule`, `CmdbMatchConfidence`, `IsCmdbOrphan` |

The practical consequence: **`cmdbCriticality` is your CMDB's opinion; every `Cmdb*` column is SI's account of how it got there.** When an asset's criticality looks wrong, `cmdb*` tells you what was read and `Cmdb*` tells you why that record was chosen.

> ⚠️ **One documented exception: `LastSeenInCmdb`.** It carries a CMDB *value* (the matched record's `last_seen`), so by the rule above it would be `cmdbLastSeen`. It pre-dates the convention, and renaming a live column would split query history — Log Analytics retention is finite and there is no backfill, so old rows would keep the old name and no single query would see both. It is therefore left as-is and listed as an explicit exception in SI's own test suite rather than quietly tolerated.

> 📌 **This convention is local to the CMDB family.** Every other data source SI reads — Defender for Endpoint, Entra, Exposure Graph, Shodan, Defender for Identity — uses capitalised column names throughout, because those sources have no equivalent value-versus-metadata split. Do not infer a general casing rule from `cmdb*`.

**Gap table** — `Reconciliation_Gap_CL`, one row per CMDB CI that did not match any discovered asset:

| Column             | Source                                                     |
|--------------------|------------------------------------------------------------|
| `cmdbId`           | `cmdbcis.id`                                               |
| `cmdbName`         | `cmdbcis.name`                                             |
| `cmdbCriticality`  | `cmdbservices.criticality`                                 |
| `ExpectedEngine`   | inferred from CI type / tags (endpoint / identity / azure) |
| `LastSeenInCmdb`   | `cmdbcis.last_seen`                                        |
| `Reason`           | `never-seen` / `last-seen-30d` / `expected-provider-down`  |
| `CollectionTime`   | run timestamp                                              |

`Reason=expected-provider-down` is set when the engine that should have found this CI didn't run successfully — prevents false-positive gap reports during partial outages.

**Reverse gap** — the mirror direction (discovered asset with no CMDB CI) is captured by `CmdbMatchState=orphan-discovered` on the per-engine profile rows:

```kql
SI_Endpoint_Profile_CL
| where CollectionTime == toscalar(SI_Endpoint_Profile_CL | summarize max(CollectionTime))
| where CmdbMatchState == 'orphan-discovered'
```

If only one engine runs (`-Engine endpoint`), reconciliation runs but the gap table is suppressed (incomplete picture). Customer can opt back in with `-ForceReconcile` and accept the noise.

### Launchers

Customer-facing entry points live in `launcher/` — separate from `engine/` so the customer config story is independent of engine code:

```
launcher/
  identity/                                same shape as the other 3
  endpoint/
  azure/
  publicip/
    launcher.community-vm.ps1              invokes engine/asset-profiling/Invoke-SIEngineRun.ps1 -Engine <name>
    launcher.internal-vm.ps1
    launcher.manifest.json
    LauncherConfig.defaults.ps1            shipped baseline
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

The launcher tree is deliberately **flat** (one file per flavour, no nested `_lib/`). Cross-engine helpers live under `engine/` and are dot-sourced by the launchers when needed.

### Engine-specific recent additions

#### Identity engine

**MFA registration** — Identity Discovery bulk-fetches MFA + SSPR + passwordless registration via `/reports/authenticationMethods/userRegistrationDetails` (one paged call per run). 12 new flat columns in `SI_Identity_Profile_CL`:

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

KQL example — privileged users without MFA:
```kql
SI_Identity_Profile_CL
| where Tier <= 1 and MfaIsRegistered == false
| project Upn, Tier, IdentityType, MfaIsCapable, EntraRoles_Permanent
```

**PIM-for-Groups expansion** — `IdentityRoleFetcher.ps1` also pulls `identityGovernance/privilegedAccess/group/eligibilitySchedules` + `assignmentSchedules`. Recursive walker (`Get-SIRolesViaPimGroupChain`) handles nested chains: `User → PIM Group A (eligible) → PIM Group B (eligible) → Role`. Eligible roles inherited via PIM-for-Groups now flow into `EntraRoles_Eligible`.

**Per-source verdict split** — Catalog matching produces SEPARATE `EntraRolesPermanentVerdict_*` and `EntraRolesEligibleVerdict_*` flat columns. Was previously combined (and Eligible hardcoded to 0).

#### Endpoint engine

**MDE pass-through fix** — MDE Discovery emits `MDE_*`-prefixed keys (was unprefixed). Stage Collect has an explicit `elseif ($a.MDE_DeviceId)` branch BEFORE the Entra-device fallback. Without this, MDE-discovered devices fell into the wrong branch and `Hostname` / `OsPlatform` / `OsVersion` / `MachineGroup` / `LastSeen` etc. all landed empty.

**Asset-class catalog** (`endpoint-tiering.json`) — 128 entries from §4.4 of the SecurityInsight GitHub README (T0=27, T1=41, T2=32, T3=28). Each entry has `{Name, Tier, Category, Reason, Detection: { TvmSoftwareNames[], EgSignals[], NamePatterns[], MachineTagPatterns[] }}`. Per-device matcher (`Get-SITierFromEndpointDevice`) walks all 4 detection channels.

**Server-application catalog** (`server-applications.json`) — 500 entries (T0=89, T1=186, T2=212, T3=13), vendor + name pairs. Stage Enrich does ONE bulk `DeviceTvmSoftwareInventory` query per run (NOT per posture rule), populates `$asset.Metadata.TvmSoftware`, then in-process matches against the 500-entry catalog. ~99% reduction in Defender hunting calls vs naive one-rule-per-product.

**Cross-engine user-based tier** — per device, find top-5 most-frequent logon users (3-day window via `DeviceLogonEvents`) → look up their tier in `SI_Identity_Profile_CL` → MIN tier across them = `MostFrequentUserTier`. Three new flat columns: `MostFrequentUserTier`, `MostFrequentUsers`, `MostFrequentUsersCount`. Aggregator contributor `endpoint_user_based_tier` weight 0.9.

KQL example — devices used by Tier-0 admins:
```kql
SI_Endpoint_Profile_CL
| where MostFrequentUserTier == 0
| project Hostname, MostFrequentUserTier, MostFrequentUsers, OsPlatform, MachineGroup
```

### Run-integrity guards — making absence loud

A Risk Analysis run that produces *less* data than yesterday still exits 0, still writes a workbook and
still looks successful. Absence reads as good news. Two guards run at the end of every run and compare
this run against the previous one for the same report template. **Both WARN; neither ever fails a run** —
a customer who genuinely remediates everything should reach zero, and a guard that cries wolf on success
gets switched off.

| Guard | Question it answers | State file |
|---|---|---|
| **Row-count guard** | did a report stop returning rows? | `OUTPUT/RowCountHistory.json` |
| **Column-fill guard** | did the rows stay while their *content* drained? | `OUTPUT/ColumnFillHistory.json` |

Both are keyed **template → report** (the same report legitimately returns different counts under a
Summary vs a Detailed template, so keying by report alone would corrupt both baselines). The column
guard adds a third level, **→ column**, storing the populated-row count per column plus `__rows` as the
denominator.

**Row-count guard** reports `WENT-TO-ZERO` (produced rows before, none now) and `LARGE-DROP` (fell by
more than 80%).

**Column-fill guard** reports, in descending severity:

| Finding | Meaning |
|---|---|
| `COLUMN-VANISHED` | the column was populated before and is no longer in the schema at all |
| `COLUMN-EMPTIED` | the column still ships and is blank on every row |
| `FILL-DROP` | still populated, but its fill rate fell by more than 80% |

Two properties are worth knowing when reading the output:

- **Comparison is on fill *fraction*, not raw filled count.** Row counts move between runs for ordinary
  reasons. A column that stays fully populated while its report legitimately halves is not a loss, and
  is reported as nothing.
- **A report that produced no rows is skipped by the column guard**, which defers to the row-count
  guard. Every column in an empty report is trivially empty; reporting each one would bury the single
  accurate message under dozens of derived ones.

Both guards are advisory signals for the operator, not gates. A finding means *investigate before
trusting this export* — most often an upstream property was renamed or reshaped, or an enrichment
source stopped supplying data, neither of which produces an error anywhere else.

---

## Provider plugin contract

> A provider is a self-contained plugin folder under `v2.2/asset-profiling-providers/<name>/`. The engine talks to providers via 4 well-known PowerShell functions. Adding a new data source = new folder; no engine code changes.

### Folder layout

```
v2.2/asset-profiling-providers/<name>/
  manifest.locked.json         Required. Conforms to _manifest.schema.locked.json.
  Test-Connection.ps1          Required. Exports Test-<Name>ProviderConnection.
  Read.ps1                     Required when manifest.kind includes 'in'.
                               Exports Read-<Name>ProviderData -Engine X.
  Write.ps1                    Required when manifest.kind includes 'out'.
                               Exports Write-<Name>ProviderData -Engine X -Rows.
  Connect.ps1                  Optional helper exposing connection setup.
  schema-fragment.json         Optional. Provider-specific schema additions.
  sample/                      Optional. Sample data for offline testing.
```

A worked layout for a read+write provider:

```
asset-profiling-providers/
  _manifest.schema.locked.json                provider-manifest JSON-Schema
  entra/
    manifest.locked.json
    Read.ps1                                  bulk pull
    Test-Connection.ps1
  generic-cmdb/
    manifest.locked.json
    Refresh-CmdbCache.ps1                     daily cache refresh
    CMDB.csv                                  customer drop-in (gitignored)
    sample/
      CMDB.csv                                shipped sample
```

### manifest.locked.json

One per provider — never `manifest.json`. Conforms to `_manifest.schema.locked.json`.

| Field          | Type    | Required | Notes                                                                  |
|----------------|---------|----------|------------------------------------------------------------------------|
| `id`           | string  | yes      | Lowercase, dash-separated. Matches the folder name.                    |
| `kind`         | string  | yes      | `in` (read-only data source), `out` (sink), or `both` (read + write).  |
| `engines`      | array   | yes      | Engines this provider serves (`identity`, `endpoint`, `azure`, `publicip`). |
| `auth`         | object  | yes      | `{ type: spn|umi|api-key|none, scopes: [...] }`                         |
| `bulk`         | bool    | yes      | `true` when `Read-...` returns all assets in N pages (no per-asset calls). |
| `rateLimit`    | object  | optional | `{ calls: N, per: '60s' }` for hint-only client throttle.              |
| `description`  | string  | optional | One-line summary.                                                      |

Example:

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

### Required functions

Every provider MUST export these (regardless of `kind`):

```powershell
function Get-<Name>ProviderManifest { <# returns manifest.json content as a hashtable #> }

function Test-<Name>ProviderConnection {
    <# Returns @{ Ok=<bool>; Error=<string?>; Detail=<string?> }.
       Must NOT throw on transport errors -- swallow + report via Ok=false.
       Should make ONE lightweight call (e.g. /me, $top=1, count=...).
    #>
}
```

When `kind` includes `in`:

```powershell
function Read-<Name>ProviderData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter()]$RunContext
    )
    <# Returns array of [hashtable] / [pscustomobject] asset rows for $Engine.
       Use the engine's profile schema (profiles/<engine>.schema.json) field
       names. Bulk-fetch in pages; do NOT loop per-asset.
    #>
}
```

When `kind` includes `out`:

```powershell
function Write-<Name>ProviderData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter()]$RunContext
    )
    <# Pushes $Rows to the destination. Idempotent (same rows twice = same
       end state). Returns @{ Sent=<int>; Failed=<int>; Errors=[...] }.
    #>
}
```

The contract restated in table form — the engine only ever calls these four functions:

| Function                              | Required when         |
|---------------------------------------|-----------------------|
| `Get-ProviderManifest`                | always                |
| `Test-ProviderConnection`             | always                |
| `Read-ProviderData -Engine X`         | `kind` includes `in`  |
| `Write-ProviderData -Engine X -Rows`  | `kind` includes `out` |

Adding a new provider is a new folder; no engine code changes.

### Engine integration

Stage Profile (and the Reconcile phase) discovers providers by scanning `providers/*/manifest.json`. For each manifest:

1. Filters by `engines` matching the current engine.
2. Calls `Test-<Name>ProviderConnection` (skips on Ok=false).
3. For `kind` in (`in`, `both`): calls `Read-<Name>ProviderData -Engine X`.
4. For `kind` in (`out`, `both`): calls `Write-<Name>ProviderData -Engine X -Rows $finalRows`.

The schema declares which providers each engine USES via `providers.in[]` / `providers.out[]`. Engine refuses to run if a declared provider is missing.

A folder-level lint rule enforces that no file under `engine/` references a path under `asset-profiling-providers/<x>/` directly — all access goes through `Invoke-Provider <id>`.

### Provider list at v2.2

| Provider          | Kind | Engines                        | Notes                         |
|-------------------|------|--------------------------------|-------------------------------|
| `entra`           | in   | identity                       | Graph                         |
| `mde`             | in   | endpoint                       | Defender XDR Hunting          |
| `mde-identity`    | in   | identity                       | IdentityInfo + LogonEvents    |
| `azure-arg`       | in   | azure, public-ip               | Resource Graph                |
| `exposure-graph`  | in   | identity, endpoint, azure      | XDR ExposureGraph*            |
| `shodan`          | in   | public-ip                      | External REST + cache         |
| `loganalytics`    | out  | all                            | DCR via AzLogDcrIngestPS      |
| `generic-cmdb` | both | endpoint, identity, azure      | CMDB read (CSV) + write-back  |
| `local-files`     | out  | all                            | JSON / CSV / XLSX dump        |

### Reference implementation

See `providers/entra/` for a working example. It wraps the existing `discovery/Get-DiscoveryFromEntra*.ps1` functions in the provider contract.

---


---

## Asset-profiling data model & schema

> Consolidated from the machine-generated per-engine column reference (`docs/asset-profiling-schema.md`, generated by `asset-profiling-schema/tools/Build-SchemaDoc.ps1`) and the JSON authoring/loader reference (`SCHEMA-REFERENCE.md`). The single source of truth for the per-engine schema files is `engine/asset-profiling/shared/Get-SISchemaWithCustomMerge.ps1` — if a key isn't read there, the engine doesn't read it. Validated against `Get-SISchemaWithCustomMerge.ps1` (loader+merger, lines 86-170), `Build-EndpointProfileRow.ps1` (consumer, lines 699-810), `Test-SISchemaCompliance.ps1` (linter), and `SCHEMA.locked.json` (meta-schema). When code disagrees with this doc, code wins.

### Overview

SecurityInsight runs **four asset-profiling engines** (endpoint, identity, azure, publicip), each emitting one **flat-column table** in Log Analytics. Every customer KQL goes against one of these tables (or joins across them). Cross-engine joins use `PrimaryEntityId` (the first member of `EntityIds[]`).

| Engine | LA table | DCR | Field count | Schema version | Last modified |
|---|---|---|---:|---|---|
| endpoint | `SI_Endpoint_Profile_CL` | `dcr-si-endpoint-profile` | 160 | 2.3.6 | 2026-04-29 |
| identity | `SI_Identity_Profile_CL` | `dcr-si-identity-profile` | 154 | 2.3.6 | 2026-04-29 |
| azure | `SI_Azure_Profile_CL` | `dcr-si-azure-profile` | 314 | 2.3.6 | 2026-04-29 |
| publicip | `SI_PublicIP_Profile_CL` | (publicip DCR) | — | 2.3.6 | — |

### Source legend

Every field carries a `source` telling you where the value comes from:

| Source | Description |
|---|---|
| `azure` | Azure Resource Graph + Az resource APIs — one row per Azure resource |
| `cmdb` | Customer CMDB (generic-cmdb provider, default-disabled). Folded onto `Properties.collect.cmdb` at Reconcile. |
| `derived` | Computed in the engine — Profile stage (drift hashes, IsEnabledActive, IsStaleAsset, AssetName, etc.) or Collect stage (PrimaryEntityId from EntityIds[0]) |
| `entra` | Microsoft Entra ID (Graph users + servicePrincipals + groups + signInActivity) |
| `exposureGraph` | Microsoft Defender Exposure Graph (ExposureGraphNodes + ExposureGraphEdges) — the v2.2 master discovery + property source |
| `mde` | Microsoft Defender for Endpoint (advanced hunting / DeviceInfo) — machine-as-asset |
| `mdi` | Microsoft Defender for Identity (on-prem AD signal — investigation priority + sensitive group membership) |
| `signInLogs` | Entra sign-in logs |
| `shodan` | Shodan REST (publicip engine) |
| `ad` | On-prem Active Directory |

### Stage legend

Each field has a `stage` block: which pipeline phase WROTE the column (always exactly one) and which phases later READ it.

- **collect** — Stage 2 (Discover + Collect), pulls raw data from each provider and lands the row.
- **enrich** — Stage 3, joins cross-source signal (EG edges, Entra group membership).
- **profile** — Stage 5, derives flat-column verdicts (IsEnabledActive, UnsupportedOSDetected, IsStaleAsset, AssetName, …).
- **classify** — Stage 4, AI tier verdict + `Properties.classify.*` sub-tree.
- **reconcile** — Stage 7, folds CMDB matches + cross-engine references.
- **posture_analyze** — evaluates posture rules against the profiled row, emits `Properties.posture.findings[]`.
- **dashboard / sentinel** — consumed only by the Power BI dataset / KQL queries (not written by the engine).

### Schema file pairs

| File pattern | Purpose | Edited by |
|---|---|---|
| `<engine>.schema.locked.json` | Shipped baseline column inventory for `SI_<Engine>_Profile_CL` | Maintainer |
| `<engine>.schema.custom.json` | Customer overlay (gitignored) | Customer |
| `SCHEMA.locked.json` | Meta-schema — vocabularies, DAG rules, contract for the per-engine files | Maintainer |
| `tools/Dedup-SchemaFields.ps1` | Linter / cleanup helper | Maintainer |

`<engine>` = `endpoint` / `identity` / `azure` / `publicip`.

### Top-level structure of a per-engine schema file

Each per-engine schema file is one JSON object:

```json
{
  "$schema":         "...",
  "engine":          "endpoint",
  "table":           "SI_Endpoint_Profile_CL",
  "dcrName":         "<dcr-name>",
  "extends":         "SCHEMA.locked.json",
  "sourcesConsumed": ["mde","entra","exposureGraph","cmdb","ad"],
  "entityIds":       { "primaryPriority": [...], "expectedTypes": [...], "hubJoin": "..." },
  "hashes":          { "CollectHash": {...}, "ProfileHash": {...}, ... },
  "rawPayload":      { "storageColumn": "...", "sources": {...} },
  "fields":          [ ... ],
  "aggregator":      { "contributors": [...] }
}
```

| Top-level key | Type | Required | Purpose |
|---|---|---|---|
| `$schema` | string | recommended | JSON-Schema draft URL. Documentation-only; loader doesn't validate. |
| `engine` | string | yes | One of `endpoint` / `identity` / `azure` / `publicip`. Used by the loader to key its cache. |
| `table` | string | yes | Target LA table (e.g. `SI_Endpoint_Profile_CL`). Read by `Invoke-Output.ps1` to route DCR ingest. |
| `dcrName` | string | yes | DCR name. Read by `Invoke-Output.ps1`. |
| `extends` | string | yes | Reference to `SCHEMA.locked.json`. Documentation-only — loader doesn't auto-load the meta-schema. |
| `sourcesConsumed` | `[string,...]` | yes | Discovery providers this engine pulls from. Lints against the source vocabulary in `SCHEMA.locked.json`. |
| `entityIds` | object | yes | Cross-engine join keys. `primaryPriority` = order tried when joining; `expectedTypes` lints incoming asset types; `hubJoin` = canonical id used in cross-engine lookups. |
| `hashes` | object | yes | Per-stage content hashes for cache invalidation. Engine doesn't write these; they're generated. |
| `rawPayload` | object | yes | Where source JSON blobs land. `storageColumn` = LA column; `sources.<src>.includePaths` = JSON-pointer list of fields kept in the blob; truncation strategy if the blob exceeds the LA cell limit. |
| **`fields`** | `[object,...]` | yes | **The big one.** One entry per LA column. See "Per-field shape". |
| `aggregator` | object | optional | Tier-roll-up rules: `contributors[]` lists the inputs the engine reduces over (one entry per AssetProfileBy* rule family + per CMDB source). |

### `fields[]` — per-field shape

Every column the engine ever emits to LA appears here exactly once.

| Key | Type | Required | Code (consumer) | Meaning |
|---|---|---|---|---|
| `name` | string | yes | `Build-EndpointProfileRow.ps1:709` | LA column name. PascalCase, no `SI_` prefix. |
| `type` | string | yes | `:709` | LA type: `string` / `int` / `bool` / `datetime` / `real` / `dynamic`. |
| `purpose` | string | yes | `:701` (filter) | Semantic role — one of `identity`, `correlation`, `risk`, `posture`, `lifecycle`, `freshness`, `pivot`, `kpi`, `compliance`, `attribution`, `policy`, `enrichment`, `forensic`, `raw`. Drives which RA reports auto-include the column. |
| `source` | string | yes | `:704` | Origin: `mde`, `entra`, `azure`, `exposureGraph`, `derived`, `cmdb`, `signInLogs`, `shodan`, `ad`. Routes value resolution to `Resolve-SISourceValue` (or `Get-SIDerivedValue` for `derived`). |
| `sourcePath` | string | optional | docs only | Human-readable pointer into the source blob (e.g. `mde.machine.id`). Surfaces in `docs/asset-profiling-schema.md`. |
| `stage` | object `{writtenBy, readBy[]}` | yes | `:783-786` (hash bucketing); `SCHEMA.locked.json:111-119` (DAG validation) | `writtenBy` = single phase that emits the value (`collect`, `enrich`, `posture_analyze`, `classify`, `profile`, `reconcile`). `readBy` = list of consumers (`classify`, `dashboard`, `risk-analysis`). |
| `default` | any | optional | `:709` (implicit when source returns null) | Fallback. Type must match `type`. |
| `addedIn` | string | optional | docs only | Semantic version when the field landed (e.g. `2.2.0`). |
| `description` | string | optional | docs only | One-liner of what the column means. |
| `derivation` | object | required when `source: derived` | `:705` (dispatcher) | `algorithm` (e.g. `min_tier_over_catalog_match`, `pass_through`, `coalesce_then_default`); optional `inputs[]` listing field names the derivation consumes (DAG-validated — inputs MUST be `writtenBy` an earlier stage). |
| `emit` | bool | optional, default `true` | `:700` | When `false`, the field is computed but NOT written to LA. Internal-only artifacts. |
| `usedBy` | `[string,...]` | optional | linter | Which posture rules / aggregator contributors reference this field. Helps detect orphans. |
| `algorithm` | string | optional (in `aggregator.contributors[]`) | `SCHEMA.locked.json:203-222` | Tier-reduction algorithm for an aggregator contributor (e.g. `min_tier_over_catalog_match`). |
| `required` | bool | optional | not consumed | LA enforces nullability client-side; the engine does not. |

### Custom-overlay merge semantics

The engine loads BOTH `<engine>.schema.locked.json` AND `<engine>.schema.custom.json` (when present) and merges them via `Get-SISchemaWithCustomMerge.ps1` lines 86-170. The merged result is cached in `$script:_SISchemaMergeCache[$Engine]`.

| Section | Merge rule | Example |
|---|---|---|
| `fields[]` | by `name`: same name → custom **REPLACES** locked; new name → **APPENDED** | Override `OsPlatform.default`, or add a brand-new `MyCustomTag`. |
| `aggregator.contributors[]` | by `id`: same id → **REPLACES**; new id → **APPENDED** | Bump weight on an existing contributor or add a new tier-source rule family. |
| `rawPayload.sources.<src>.includePaths[]` | **UNION** (locked first, then custom additions, deduped) | Add extra MDE `DeviceInfo` fields without removing locked ones. |
| `rawPayload.sources.<new-src>` | new source bucket → **ADDED** | Add a custom source bucket like `tanium`, with its own `includePaths`. |
| `hashes`, `entityIds`, engine metadata, `extends`, `aiEligibility` | **NOT mergeable** — engine invariants | If you set them in custom, the loader ignores them. |

### Adding a new column / overriding an existing column

Add a column by creating `<engine>.schema.custom.json` with a new `fields[]` entry, then implement the value computation in the matching stage (e.g. `Invoke-Enrich.ps1`, routed via `Get-SIDerivedValue` because `source: derived`). The DCR needs an explicit update for the new column to flow into LA — the engine logs `SchemaDiff` each run (`Invoke-SchemaDiff.ps1`).

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "fields": [
    {
      "name": "MyCustomTag",
      "type": "string",
      "purpose": "enrichment",
      "source": "derived",
      "stage": { "writtenBy": "enrich", "readBy": ["classify", "dashboard"] },
      "default": "",
      "description": "Tenant-custom tag injected via overlay for segmentation.",
      "addedIn": "2.2.0"
    }
  ]
}
```

To override an existing column, repeat the locked entry's `name` in the custom file. The custom entry FULLY REPLACES the locked entry — copy the locked block, edit, paste (e.g. change `OsPlatform.default` from `""` to `"Unknown"`).

### Engine consumers (where the schema is read)

| File | Lines | What it reads |
|---|---|---|
| `Get-SISchemaWithCustomMerge.ps1` | 34-180 | Loads + merges + caches |
| `Build-EndpointProfileRow.ps1` | 699-810 | `fields[*]` (name, type, source, purpose, stage, emit, derivation) — emits flat columns + the Properties JSON blob |
| `Build-IdentityProfileRow.ps1` | similar pattern | Identity row builder |
| `Build-AzureProfileRow.ps1` | similar pattern | Azure row builder |
| `Build-PublicIpProfileRow.ps1` | similar pattern | PublicIP row builder |
| `Invoke-Output.ps1` | output stage | `table`, `dcrName` — routes the row batch to the right LA table / DCR |
| `Test-SISchemaCompliance.ps1` | rule + schema lint | Lints the rule tree (`*.locked.yaml` / `*.custom.yaml`) and checks no `fields[].name` in a profile schema carries an `SI_` prefix. Run it directly: `.\Test-SISchemaCompliance.ps1` (add `-CustomOnly` for just your own rules, `-CI` for an exit code) |
| `Invoke-SchemaDiff.ps1` | DAG analysis | Compares schema between runs to detect breaking column changes |
| `tools/Dedup-SchemaFields.ps1` | maintainer-only | Detects duplicate `name` entries inside one file |

---

### Endpoint — `SI_Endpoint_Profile_CL`

- **DCR**: `dcr-si-endpoint-profile` · **Schema version**: `2.3.6` (2026-04-29) · **Field count**: 160
- **Sources consumed**: `mde`, `exposureGraph`, `entra`, `azure`, `derived`
- **Entity-ID types** (members of `EntityIds[*]`): `MdeDeviceId`, `AadDeviceId`, `IntuneDeviceId`, `AzureResourceId`, `HardwareUuid`, `AzureVmId`, `AwsResourceName`, `GcpFullResourceName`, `Hostname`
- **Hub join** (master-record producer): `exposureGraph`
- **EG node labels in scope**: `device`, `microsoft.compute/virtualmachines`, `microsoft.compute/virtualmachines/extensions`

**Identity / correlation / hashing**: `PrimaryEntityId` (=`EntityIds[0].id`), `PrimaryEntityType` (=`EntityIds[0].type`), `EntityIds` (merged mde+exposureGraph+azure+derived), `RunId` (UUID per orchestrator run, written by `bootstrap`), `CollectionTime` (`now()` at output, written by `classify`, read by all), `MdeDeviceId` (`mde.machine.id`), `AadDeviceId`, `AzureResourceId` (`arm.virtualMachines.id` when Azure-hosted), `Hostname` (`mde.machine.computerDnsName`), `DisplayName`, `HardwareUuid`, `AzureVmId`, `AzureVmSubscriptionId`, `AwsResourceName`, `GcpFullResourceName`, `HostDeviceId` (WSL→Windows host), `MergedDeviceIds` (kept in EntityIds with relation `merged_predecessor`), `MergedToDeviceId`, `MachineSid` (local Windows SID), `PotentialDuplicateOf` (NodeId of likely-duplicate record), `IsPotentialDuplication`. Per-stage SHA256 hashes: `CollectHash`, `EnrichHash`, `PostureHash`, `ClassifyHash` (all written by `classify`, read by `sentinel`). `AssetName` (derived, `profile`, read by dashboard + risk_analysis, addedIn 2.2.0).

**MDE posture / health**: `OnboardingStatus`, `HealthStatus`, `IsExcluded`, `ExclusionReason`, `IsDomainController` (derived at enrich), `IsCustomerFacing` (EG `isCustomerFacing` — BYOD/IoT shadow-IT signal), `SensorHealthState` (Active/InactiveRecent), `SenseClientVersion`, `DefenderAvStatus` (Updated/OutOfDate/Disabled/Unknown), `DefenderAvMode` (Active/Passive), `EdrMode` (Block/Audit/Disabled), `MitigationStatus`, `OnboardedDateTime`, `OffboardedDateTime`, `IsTransient` (short-lived asset, e.g. CI runner).

**Risk signals**: `RiskScore` (mde None/Low/Medium/High), `ExposureLevel`, `DeviceValue`, `AssetValue` (Defender for Cloud), `ExposedToInternet` (EG `exposedToInternet.type == 'InternetExposure'`), `ExposureSourceCidrs`, `InternetExposedReasons`, `IsInternetFacing`, `VulnerabilityCount`, `MissingKbCount`, `CriticalCveCount30d` (derived), `VulnerableSoftwareCount`, `IdentifiedResourceUsersCount`, `HighPrivIdentifiedUsers` (derived), `HasGuardMisconfigurations`, `HasAuthorityMisConfigurations`, `PublicIp`. Criticality (EG): `CriticalityLevel` (effective tier 0-3, manual wins over rule), `RuleBasedCriticalityLevel`, `ManualCriticalityLevel` (operator override), `CriticalityRuleNames`, `CriticalityConfidenceHigh`.

**Network/port exposure (all derived at enrich)**: `NsgEffectiveRules`, `OpenInboundPortsFromInternet`, `OpenInboundPortsFromExternalIps`, `OpenInboundPortsFromVnet`, `HasInternetExposedRdp`, `HasInternetExposedSsh`, `HasInternetExposedSmb`, `HasInternetExposedWinRm`, `HasInternetExposedDbPort`, `HasNarrowAdminAllow`, `PortExposureFindings`, `HighestPortRiskScore`, `OpenOutboundDestinations`, `NicCount`, `EffectiveIpAddresses_mde` (DeviceInfo.IPAddresses), `EffectiveIpAddresses_derived`.

**User attribution / logon graph**: `LoggedOnUsers` (`[{UserName,DomainName,Sid}]`), `LoggedOnUsersCount_mde`, `LoggedOnUsersCount_derived`, `LoggedOnUserSids` (cross-engine join key to `SI_Identity_Profile_CL.OnPremSid`), `MostFrequentUserTier` (derived), `MostFrequentUsers`, `PrimaryUser`, `Owner` (ARM `tags.owner`), `WeeklyActiveUsersCount`.

**Lifecycle / freshness**: `FirstSeen`, `LastSeen`, `EgLastSeen`, `FirstSeenByInventory`, `LastSeenDays`, `LastDailyDeviceUsageDate`, `InactivityPeriod` (D{n}), `DaysInactive` (derived, profile), `IsStaleAsset` (derived, profile), `IsEnabledActive` (derived, profile, addedIn 2.3.3).

**Pivots / classification (EG + MDE)**: `JoinType` (Domain/Azure/Workgroup), `CloudPlatforms`, `ConnectivityType`, `Site`, `GraphInternalLabel` (workstation/audioAndVideo/smartAppliance/networkPhysicalDevice/mobile/printer/unclassifiedDevice), `DeviceCategory` (Endpoint/IoT/Unknown), `DeviceType`, `DeviceSubtype`, `DeviceRole`, `OsPlatform`, `OsVersion`, `OsBuild`, `OsBuildRevision`, `OsVersionInfo`, `OsProcessor`, `OsArchitecture`, `RbacGroupName`, `MachineGroup`, `Vendor`, `Model`, `Region` (ARM location), `DiscoverySourceProducts`. Tags: `MachineTags`, `DeviceDynamicTags`, `DeviceManualTags`, `DeviceRegistryTags`, `RegistryDeviceTag_mde`, `RegistryDeviceTag_exposureGraph`.

**Join / Defender-for-Servers / TPM / remote-services posture (EG)**: `IsHybridAzureADJoined`, `IsAzureADJoined`, `AzureADJoinType`, `IsApplicableForDefenderForServers` (+`...Reason`), `IsUsiServer`, `Extensions`, `TpmSupported`/`TpmActivated`/`TpmEnabled`/`TpmVersion`, SMB: `SmbEnableSmb1Protocol`/`SmbRequireSecuritySignature`/`SmbEncryptData`, RDP: `RdpAllowConnections`/`RdpNlaRequired`/`RdpServiceRunning`, `WinRmServiceRunning`.

**Derived asset taxonomy + verdicts (posture_analyze / classify / profile)**: `AssetType`, `AssetSubtype`, `AssetGroup` (posture_analyze), `Tier` (kpi, classify), `Group` (kpi, classify), `SIRules` (audit, profile, addedIn 2.3.2), `UnsupportedOSDetected` + `UnsupportedOSReason` (profile, addedIn 2.3.4), `DefenderAvOutOfDate`, `IsCmdbOrphan`.

**CMDB (reconcile, addedIn 2.3.6)**: `cmdbId`, `cmdbName`, `cmdbCriticality` (Critical/High/Medium/Low), `cmdbDataSensitivity` (Restricted/Confidential/Internal/Public), `CmdbMatchPhase`, `CmdbMatchState`.

---

### Identity — `SI_Identity_Profile_CL`

- **DCR**: `dcr-si-identity-profile` · **Schema version**: `2.3.6` (2026-04-29) · **Field count**: 154
- **Sources consumed**: `entra`, `mdi`, `exposureGraph`, `signInLogs`, `derived`
- **Entity-ID types**: `AadObjectId`, `Upn`, `Mail`, `SecurityIdentifier`, `ActiveDirectoryObjectGuid`
- **Hub join**: `exposureGraph` · **EG node labels in scope**: `user`, `group`, `serviceprincipal`, `managedidentity`

**Identity / correlation / hashing**: `PrimaryEntityId`, `PrimaryEntityType`, `EntityIds` (merged entra+mdi+exposureGraph+derived), `RunId`, `CollectionTime`, `Upn`, `Mail`, `OnPremSid` (`onPremisesSecurityIdentifier`), `OnPremSamAccountName`, `OnPremObjectGuid` (mdi/EG ActiveDirectoryObjectGuid), `EmployeeId`, `CollectHash`/`EnrichHash`/`PostureHash`/`ClassifyHash`, `AssetName` (derived, profile, addedIn 2.2.0).

**Account posture (entra/EG/mdi)**: `AccountEnabled`, `UserType`, `CreationType`, `ExternalUserState`, `OnPremisesSyncEnabled`, `IsManagementRestricted`, `IsBreakGlass` (derived), `HasLeakedCredentials`, `HasAdLeakedCredentials`, `MdiIsLockedOut`, `MdiIsSensitive`, `IsAdSensitiveFlagged` (AD-side, ≠ MDI's), `AdminCount`, `UserAccountControl`, `SidHistory`, `HasSidHistory` (derived).

**Lifecycle / freshness**: `CreatedDateTime`, `DeletedDateTime`, `EmployeeHireDate`, `EmployeeLeaveDateTime`, `LastSignInDateTime`, `LastNonInteractiveSignInDateTime`, `LastSuccessfulSignInDateTime`, `LastSignInDays` (derived), `LastPasswordChangeDateTime`, `OnPremLastSyncDateTime`, `MdiLastSeenActivity`, `DaysInactive` (derived, profile).

**MFA / auth methods (`graph.reports.authenticationMethods.userRegistrationDetails.*`, bulk-fetched once per run)**: `MfaIsRegistered`, `MfaIsCapable`, `IsPasswordlessCapable` (FIDO2 / Windows Hello), `IsSsprRegistered`, `IsSsprCapable`, `IsSsprEnabled`, `MfaMethods` (excludes `'password'`), `MfaMethodCount`, `MfaDefaultMethod`, `MfaSystemPreferredMethods`, `MfaPreferredSecondary`, `MfaLastUpdatedDateTime`.

**Privilege signals (raw)**: `EntraRoles_Permanent` (roleAssignments where principal=user), `EntraRoles_Eligible` (roleEligibilitySchedules), `EntraAppPermissions_Application` (appRoleAssignments), `EntraAppPermissions_Delegated` (oauth2PermissionGrants), `NestedGroups` (transitiveMemberOf filtered to groups), `AdNestedGroupNames`, `AdNestedCriticalGroups`, `AzureRoles_Assignments`.

**Privilege verdicts (derived at enrich)** — each family emits a `_Tier` / `_TopMatch` / `_MatchCount` / `_MissCount` quad: `EntraRolesPermanentVerdict_*`, `EntraRolesEligibleVerdict_*`, `EntraApiPermsApplicationVerdict_*`, `EntraApiPermsDelegatedVerdict_*`, `AdBuiltinGroupsVerdict_*`, `AzureRolesVerdict_*`. Plus `IdentityTieringCatalogVersion` (freshness). EG criticality: `EgCriticalityLevel`, `EgRuleBasedCriticalityLevel`, `EgCriticalityRuleNamesPredefined`, `EgCriticalityRuleNamesCustom`. `MdiInvestigationPriority`.

**Service principal / managed identity**: `AppId`, `AppOwnerOrganizationId`, `PublisherName`, `ServicePrincipalType`, `IsFirstPartyMicrosoftSpn`, `IsHomeTenantSpn`, `IsThirdPartyMultiTenantSpn`, `IsLegacySpn`, `MiAccountType`, `IsSystemAssignedManagedIdentity`, `IsUserAssignedManagedIdentity`, `IsExplicitManagedIdentity`, `AttachedAzureResourceId`, `AttachedResourceType`, `AttachedResourceTier`, `AttachedResourceCount`, `IsManagedServiceAccount`, `IsDomainControllerAccount`, `IsExchangeServerAccount`, `HasServicePrincipalName`.

**Pivots / directory attributes**: `DisplayName` (coalesce user/SP/group), `IdentityType`, `ObjectType` (addedIn 2.3.5), `SecurityPrincipalType`, `PrimaryProvider`, `Department`, `EmployeeType`, `JobTitle`, `Country`, `OnPremDomainName`, `Manager`, `ManagerUpn`, `UsageLocation` (compliance), `PasswordPolicies` (policy), `LicenseSkuIds` (compliance), `Tags` (derived), `ExtensionAttributes`, `CustomSecurityAttributes`, `AssetSubtypeAI`, `AssetGroupAI`. **`CSA`** (audit, addedIn 2.3.5): concatenation of customSecurityAttributes assignments as `set/attribute=value` pairs (e.g. `'SecurityInsight/AssetTier=tier-0; SecurityInsight/RegulatoryScope=PCI'`); asset-tagging KQL parses it with `extract(@"tier-(\d+)", 1, tostring(CSA))`.

**Derived verdicts / risk flags (classify / profile)**: `Tier` (kpi, classify), `SIRules` (audit, profile 2.3.2), `IsEnabledActive` (profile 2.3.3), `AssetGroup` (kpi, classify), `IsOrphanSPN`, `HasExpiringCredentials`, `CredentialExpiryDays`, `HasNoMfa`, `HasPasswordNeverExpires`, `IsExternalIdentity`, `IsHighRiskPermissionGrant`, `IsCmdbOrphan` (all profile, 2.3.4).

**CMDB (reconcile, 2.3.6)**: `cmdbId`, `cmdbName`, `cmdbCriticality`, `cmdbDataSensitivity`, `CmdbMatchPhase`, `CmdbMatchState`.

---

### Azure — `SI_Azure_Profile_CL`

- **DCR**: `dcr-si-azure-profile` · **Schema version**: `2.3.6` (2026-04-29) · **Field count**: 314
- **Sources consumed**: `azure`, `exposureGraph`, `derived`
- **Entity-ID types**: `AzureResourceId`, `ExposureGraphNodeId`, `AadObjectId` · **Hub join**: `exposureGraph`
- **EG node labels in scope**: `microsoft.storage/storageaccounts`, `microsoft.containerregistry/registries`, `microsoft.operationalinsights/workspaces`, `microsoft.cognitiveservices/accounts`, `microsoft.cognitiveservices/accounts_openai`, `microsoft.compute/virtualmachines`, `microsoft.network/virtualnetworks`, `microsoft.network/networksecuritygroups`, `microsoft.network/applicationgateways`, `microsoft.web/serverfarms`, `microsoft.web/sites_webapp`, `microsoft.web/sites_azurefunction`, `microsoft.logic/workflows`, `microsoft.sql/servers`, `microsoft.keyvault/vaults`

**Identity / correlation / hierarchy**: `PrimaryEntityId` (=`EntityIds[0].id`, always AzureResourceId), `PrimaryEntityType` (always `'AzureResourceId'`), `EntityIds` (merged azure+exposureGraph+derived), `RunId`, `CollectionTime`, `AzureResourceId` (`arm.<resource>.id`), `AssetName` (derived, profile 2.2.0), `AzureResourceId_Guid` (derived, profile 2.2.0), `AzSubscriptionId`, `ManagementGroupId` (walked from parent path of subscription), `AzResourceGroup`, `ManagedIdentityPrincipalId` (`identity.principalId`), `ExposureGraphNodeId` (`eg.node.NodeId`), `HierarchyIdentifier` (subscription ID for Azure), `CollectHash`/`EnrichHash`/`PostureHash`/`ClassifyHash`.

**Cross-RP posture (ARM-sourced)**: `PublicNetworkAccess`, `MinimumTlsVersion`, `SupportsHttpsTrafficOnly`, `AllowBlobPublicAccess`, `AllowSharedKeyAccess`, `EncryptionAtRestEnabled`, `EnablePurgeProtection`, `EnableSoftDelete`, `EnableRbacAuthorization`, `AdminUserEnabled`, `AnonymousPullEnabled`, `DisableLocalAuth`, `ChangedTime`.

**Exposure / RBAC / network**: `ExposedToInternet` (EG), `ExposureEvidenceNodeIds` + `ExposureEvidenceEdgeIds` (forensic — graph-traversal proof for inherited exposure), `IdentifiedResourceUsersHighPrivCount` (derived), `HighestRiskRbacRole` (derived), `NetworkAclMode` (`networkAcls.defaultAction`), `AllowsPublicAccess` (EG Enabled/Disabled), `ServerlessAppServicePlan` (parent ASP ARM id), `ServerlessIdentityProvider` (empty = anonymous = posture risk).

**Verdicts / tier (derived classify)**: `Tier` (kpi), `SIRules` (audit, profile 2.3.2), `IsEnabledActive` (profile 2.3.3), `Verdict` (kpi).

**VM-specific (ARM)**: `VmId` (used to join MDE), `OsDiskEncryptionAtHost`, `OsDiskEncryptionDiskSetId`, `SecurityType` (TrustedLaunch/ConfidentialVM), `SecureBootEnabled`, `VTpmEnabled`, `AdminUsername` (well-known names = brute-force surface), `AssignedHostId`, `ProximityPlacementGroupId`, `AvailabilitySetId`, `VirtualMachineScaleSetId`, `HostGroupId`, `PatchModeWindows`, `PatchModeLinux`, `DisablePasswordAuthentication`.

**EG mirror fields** (per-RP, prefixed `EG_*`) cover VM, subnet, Log Analytics workspace, vnet, SQL DB/server, Key Vault, Logic App, NSG, Cognitive deployment, storage, Azure OpenAI, Function/Web apps, ACR, App Gateway — e.g. `EG_VmJustInTimeAccessEnabled`/`...Status`, `EG_VmVulnerableSoftwareCount`, `EG_VmHighSeverityVulnCount`, `EG_VmCriticalSeverityVulnCount`, `EG_VmHandlesSensitiveData`; `EG_SubnetPrivateEndpointNetworkPolicies`; `EG_LawPublicNetworkAccessForIngestion`/`...ForQuery`/`EG_LawDisableLocalAuth`; `EG_VnetEnableDdosProtection`; `EG_SqlDbTransparentDataEncryption`/`EG_SqlDbHandlesSensitiveData`/`EG_SqlDbDataClassificationLabels`; `EG_Kv*` (PublicNetworkAccess, EnableRbacAuthorization, EnableSoftDelete, EnablePurgeProtection, EnabledForDeployment, EnabledForTemplateDeployment, EnabledForDiskEncryption, NetworkAclDefaultAction); `EG_LogicAppHttpTriggerExposed`; `EG_NsgInboundSshOpenToInternet`/`...RdpOpenToInternet`; `EG_CogDepRaiPolicyName`; `EG_St*` (PublicNetworkAccess, AllowBlobPublicAccess, AllowSharedKeyAccess, SupportsHttpsTrafficOnly, MinimumTlsVersion, IsHnsEnabled, IsSftpEnabled, IsLocalUserEnabled, NetworkAclDefaultAction, BlobAnonymousContainerCount, RequireInfrastructureEncryption, HandlesSensitiveData, DataClassificationLabels); `EG_Aoai*`; `EG_SqlFwIsAllowAllAzureServices`/`EG_SqlFwIsOpenToInternet`; `EG_Func*`; `EG_SqlSrv*`; `EG_Web*`; `EG_Cog*`; `EG_Acr*`; `EG_Agw*`.

**ARM resource-specific fields (collect 2.3.1)** — Public IP (`Pip*`: Address, DdosProtectionMode, DdosPlanId, AttachedResourceId, NatGatewayId, PublicIPPrefixId, ServicePublicIPAddress); NIC (`Nic*`: EnableIPForwarding, NsgId, VirtualMachineId, MacAddress, HasPublicIp, PublicIpIds, SubnetIds, PrivateIpAddresses); VM extension (`Ext*`: Type e.g. `MDE.Windows`, SettingsJson non-secret only, ParentVmId); subnet (`Subnet*`: NsgId, RouteTableId, NatGatewayId, DefaultOutboundAccess, ParentVnetId); Log Analytics (`Law*`: CustomerId, RetentionInDays, PublicNetworkAccessForIngestion/Query, DisableLocalAuth, CmkKeyVaultUri, ModifiedDate); vnet (`Vnet*`: EnableDdosProtection, DdosProtectionPlanId, PeeringIds, EncryptionEnabled); SQL DB (`SqlDb*`: DatabaseId, RequestedBackupStorageRedundancy, MaintenanceConfigurationId, ElasticPoolId, SourceDatabaseId, ParentServerId); Key Vault (`Kv*`: PublicNetworkAccess, NetworkAclsDefaultAction, EnableRbacAuthorization, EnableSoftDelete, EnablePurgeProtection, TenantId, VaultUri, HsmPoolResourceId); Logic App (`La*`: IntegrationAccountId, IntegrationServiceEnvId, AccessControlActionsAllowed, AccessControlTriggers, EndpointsConnector, Parameters, ChangedTime); NSG (`Nsg*`: InboundAllowAnyCount, InboundAllowInternetCount, InboundAllowRdpCount [port 3389], InboundAllowSshCount [port 22], AttachedNicIds, AttachedSubnetIds, SecurityRulesJson); Cognitive deployment (`Depl*`: RaiPolicyName, ParentAccountId); storage (`St*`: PublicNetworkAccess, AllowBlobPublicAccess, AllowSharedKeyAccess, AllowCrossTenantReplication, MinimumTlsVersion, SupportsHttpsTrafficOnly, NetworkAclsDefaultAction, EncryptionKeySource [Microsoft.Storage/Microsoft.Keyvault], EncryptionKeyVaultUri/KeyName/KeyVersion, IsNfsV3Enabled, IsSftpEnabled, KeyPolicyExpirationDays); Azure OpenAI (`Aoai*`); SQL firewall (`SqlFw*`: AllowsAllAzureIPs [0.0.0.0–0.0.0.0], AllowsAllIPv4 [0.0.0.0–255.255.255.255], ParentServerId); Function app (`Func*`); SQL server (`SqlSrv*`); Web app (`Web*`); Cognitive non-OpenAI (`Cog*`); ACR (`Acr*`); AI project/hub (`AiProj*`); App Gateway (`Agw*`: SkuTier [Standard_v2 = no WAF], WafEnabled, WafFirewallMode [Detection vs Prevention], FirewallPolicyId, SslMinProtocolVersion, FrontendPublicIpCount).

**Derived risk flags (profile 2.3.4)**: `IsPubliclyExposed`, `HasNoSoftDelete`, `UnencryptedTraffic`, `HasOpenAdminPort`, `IsCmdbOrphan`.

**CMDB (reconcile 2.3.6)**: `cmdbId`, `cmdbName`, `cmdbCriticality`, `cmdbDataSensitivity`, `CmdbMatchPhase`, `CmdbMatchState`.

---

## Privilege-tier catalog

> Source of truth: `privilege-tier-catalog/privilege-tier-catalog.locked.json` — the AI-classified inventory of every AD group, Entra role, Graph API permission, and Azure RBAC role, scored on the attacker-centric Tier 0..3 scale. Validated against `engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` (producer) and `engine/asset-profiling/shared/IdentityCatalogTierComputer.ps1` (consumer, lines 84-496). When code disagrees with this doc, code wins.

### File pair

| File | Purpose | Edited by |
|---|---|---|
| `privilege-tier-catalog/privilege-tier-catalog.locked.json` | Classifier output (AI-generated baseline) | `Invoke-PrivilegeTierClassifier.ps1` regenerates it |
| `asset-profiling-enrichment/identity/PrivilegeTierClassifier.json` (optional) | Customer overlay — adds tenant-custom AD groups, Entra/Azure custom roles | Customer |

The overlay is loaded by `IdentityCatalogTierComputer.ps1` lines 118-147 if present; absence is silent.

### Tier scale (attacker-centric)

| Tier | Means | Examples |
|---|---|---|
| **0** | One-step compromise of the identity plane / tenant | Domain Admins; Global Administrator; Privileged Role Administrator; Directory.ReadWrite.All |
| **1** | Privilege-escalation path (multi-step) | Backup Operators; Server Operators; Helpdesk Administrator; Owner (subscription) |
| **2** | Workload / data impact, no direct identity-plane path | Hyper-V Administrators; DnsAdmins; Reports Reader; Contributor on a single resource |
| **3** | Standard accounts — no escalation path | Users; Authenticated Users; Domain Users; Reader |

`Get-SIMinTier` (consumer lines 489-496) reduces over all signal sources for one identity and returns the **lowest tier number** (= highest privilege). When all sources return `$null`, default is **Tier 3**.

### Top-level structure

```json
{
  "Metadata": { ... },
  "AD_BuiltInPermissionGroups_Tier0":  [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "AD_CustomGroups_Tier0":             [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_BuiltInRoles_Tier0":        [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_CustomRoles_Tier0":         [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "EntraID_APIPermissions_Tier0":      [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "Azure_BuiltInRoles_Tier0":          [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...],
  "Azure_CustomRoles_Tier0":           [ ... ],   "...Tier1": [...], "...Tier2": [...], "...Tier3": [...]
}
```

### `Metadata` envelope

| Field | Type | Required | Read by |
|---|---|---|---|
| `GeneratedAt` | string (ISO 8601) | yes | `IdentityCatalogTierComputer.ps1:55` (freshness check) |
| `GeneratedBy` | string | yes | docs only |
| `TenantId` | string (GUID) | yes | docs only — sanitize to `<tenant-id>` in shared docs |
| `TieringModel` | string | yes | docs only |
| `AICallsUsed` | int | yes | docs only — one Azure OpenAI batch per provider category (typically 4) |

### Per-entry shape (per section)

Different sections use different key fields; the locked+custom merge uses these keys (case-insensitive).

**AD groups (`AD_*Groups_Tier*`)** — `Name` (string, required, **merge key**, lowercased lookup at `IdentityCatalogTierComputer.ps1:248,354`), `Tier` (int 0..3, required, line 356), `Reason` (string, required, shown in audit logs line 427).

**Entra roles (`EntraID_*Roles_Tier*`)** — `DisplayName` (string, required, **merge key**, line 177), `Tier` (int 0..3, required, line 379), `Description` (optional, AI classifier context).

**API permissions (`EntraID_APIPermissions_Tier*`)** — `Value` (string, required, **merge key**, HashSet O(1) lookup lines 203,341), `Tier` (int 0..3, required, line 341), `Description` (optional). Example `Value`s: `Directory.ReadWrite.All`, `Mail.Send`, `RoleManagement.ReadWrite.Directory`.

**Azure roles (`Azure_*Roles_Tier*`)** — `Name` (string, required, **merge key**, line 282), `Tier` (int 0..3, required, line 407), `Description` (optional).

### Default tier behaviour (no-match)

| Provider | Lookup miss with non-empty input | Lookup miss with empty input |
|---|---|---|
| Entra roles | **Tier 2** (line 335) | `$null` |
| API permissions | **Tier 2** (line 345) | `$null` |
| AD groups | `$null` (line 369) | `$null` |
| Azure roles | **Tier 2** (line 369) | `$null` |

`Get-SIMinTier` (lines 489-496): excludes `$null` and `-1`; returns the smallest remaining number; if every signal is `$null`, returns **3** (safest fallback).

### Customer overlay — adding tenant-custom roles

Create `asset-profiling-enrichment/identity/PrivilegeTierClassifier.json` (the canonical path the consumer looks up first). Same shape as the catalog; only include the sections you want to add to:

```json
{
  "AD_CustomGroups_Tier0": [
    { "Name": "<org>-DomainBreakGlass", "Tier": 0,
      "Reason": "Custom break-glass group with domain-wide reset rights." }
  ],
  "AD_CustomGroups_Tier1": [
    { "Name": "<org>-PrintOps", "Tier": 1,
      "Reason": "Print-spooler service control -- known PrintNightmare escalation surface." }
  ],
  "EntraID_CustomRoles_Tier1": [
    { "DisplayName": "Custom Compliance Officer", "Tier": 1,
      "Description": "Tenant-custom role; limited audit scope but can read sensitive policies." }
  ],
  "Azure_CustomRoles_Tier0": [
    { "Name": "<org>-OnCallTenantOwner", "Tier": 0,
      "Description": "Custom role with Owner+UserAccessAdministrator at tenant root." }
  ]
}
```

**Merge** (lines 118-147): same merge key in same section → custom **REPLACES** locked; new key → **APPENDED**; sections you don't list are untouched.

### How the catalog is generated

`engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` outputs `privilege-tier-catalog/privilege-tier-catalog.locked.json`. Runs in 4 stages, one batched Azure OpenAI call per stage:

1. **Stage A** — enumerate AD built-in groups (no member collection).
2. **Stage B** — enumerate Entra role definitions (built-in + custom).
3. **Stage C** — enumerate Microsoft Graph API permissions from well-known service principals.
4. **Stage D** — enumerate Azure RBAC role definitions (built-in + custom).

Each stage POSTs name + description to Azure OpenAI with the attacker-centric framework prompt; the classifier returns `Tier` (0..3) and an optional `Reasoning`, written into the appropriate `*_Tier{0..3}` arrays. Re-run when: a new custom AD group / Entra role / Azure RBAC role is created; new tenant onboarding; Microsoft adds new built-in roles. Requires Azure OpenAI credentials — defaults `AI_ChunkSize=50`, `AI_MaxRetries=3`, `AI_MaxTokens=16384` (set silently at script top).

### Engine consumers

| File | Lines | Reads |
|---|---|---|
| `IdentityCatalogTierComputer.ps1` | 84-496 | All sections; computes per-identity `Get-SITierFromEntraRoles`, `Get-SITierFromEntraAPIPerms`, `Get-SITierFromADGroups`, `Get-SITierFromAzureRoles`; reduces via `Get-SIMinTier` |
| `Build-IdentityProfileRow.ps1` | per-identity emit | Reads computed tier + writes `Tier` column |

Endpoints don't read this catalog directly — they use a separate `EndpointCatalogTierComputer.ps1` keyed on machine roles. The `Tier` column lives in `SI_Identity_Profile_CL` per `identity.schema.locked.json`.

---

## Enrichment / detection rule model

> Source of truth for the `*.locked.yaml` / `*.custom.yaml` rule grammar used by the asset-profiling engines (Identity, Endpoint, Azure, PublicIP). Generated from `engine/asset-profiling/shared/RuleEval.ps1` (the kind handlers) and `Get-SIRuleSet.ps1` (the loader). Annotated canonical example: `_TEMPLATE.custom.sample.yaml`. If this doc disagrees with the code, the code wins.

### File-level fields

| Field | Required | Allowed values | Meaning |
|---|---|---|---|
| `id` | yes | string (PascalCase, no spaces) | Rule identity. **Must equal the file basename** (stripped of `.locked` / `.custom`). Engine deduplicates rules by `id` — a `*.custom.yaml` with the same `id` as a `*.locked.yaml` overrides it. |
| `appliesTo` | yes | `endpoint` / `identity` / `azure` / `publicip` / a list | Engine(s) that evaluate this rule. Cross-engine rules live under `shared/`. |
| `mode` | no (default `locked`) | `locked` / `disable` | `locked` = rule loads normally. `disable` = engine skips entirely (`Invoke-SIRuleEval` returns `$null` immediately). Any other value treated as `locked`. |
| `purpose` | recommended | string | Free-text description; surfaces in run logs. |
| `category` | recommended | string | Grouping label (`Server Roles`, `CMDB Mapping`, `Group Membership`, …); surfaces in `SIRules` array on each profile row. |
| `description` | recommended | YAML literal block (`|`) | Multi-line operator notes. |
| `detections` | yes | list of detection blocks | One or more detect→set blocks, walked in array order; the **first** detection whose `detect` matches wins (per-rule first-match). |

**Override semantics for custom files**: a `*.custom.yaml` always wins the dedup pass against its `*.locked.yaml` sibling with the same `id:`. `append` / `merge` / `overwrite` modes are NOT implemented — the custom file fully replaces the locked one.

### Detection-block fields (one per `detections:` item)

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Detection identity, globally unique within the rule. Surfaces as `DetectionId` in `SIRules[]`. |
| `detect` | yes | The match condition (see detect kinds). |
| `set` | yes | What to stamp on the row when `detect` is true. |
| `excludeAssets` | no | List of asset names / `-like` wildcards. When the asset's `Name` matches any entry (CI), this detection is SKIPPED even if `detect` would fire — evaluation continues with the next detection. Alias `excludeNames`. Use to exempt one legacy box from a single detection (e.g. compat-blocking software you can't remove). |

```yaml
id:        MicrosoftSystemCenter
appliesTo: endpoint
mode:      locked
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

### `detect` — combine semantics

```yaml
detect:
  any:                  # OR -- fires if ANY child kind matches
    - kind: ...
  # OR
  all:                  # AND -- fires only if EVERY child kind matches
    - kind: ...
```

- `any:` = "match if asset shows EITHER fingerprint A OR B". `all:` = "match only if BOTH A AND B".
- An unknown `kind:` inside `all:` fails the whole `all:` block (AND-failure); inside `any:` that arm is skipped and the other arms still decide.
- **It is no longer silent.** `Get-SIRuleSet` reports every unknown kind once per run, with the number of detections affected — a typo in a `kind:` used to cost the detection an arm with no visible symptom at all. (Audit #35: an unregistered `nameMatches` did exactly that to 95 detections for the whole v2.2 lifetime.) The loader also names any rule that loads with **zero detections** (audit #36) and any rule file that fails to parse (audit #29). `mode: disable` is excluded from the zero-detection report — suppressing a locked rule is the one legitimate empty case.

### Detect kinds — exhaustive registry (12 total)

Straight from `RuleEval.ps1` `$script:SIKindRegistry`. These are the **only** kinds the engine knows; anything else in YAML is silently ignored.

1. **`nameMatches`** *(all engines)* — regex against display-name fields. `namePatterns:` `[regex,...]` (required; aliased `patterns:`). Fields scanned (first non-empty wins per pattern): `Name`, `Hostname`, `DisplayName`, `Fqdn`, `MDE_DeviceName`, `ENTRA_DisplayName`, `AZ_Name`.
2. **`osPlatform`** *(endpoint)* — regex against OS-platform fields. `osPatterns:` `[regex,...]` (aliased `patterns:`). Fields scanned: `MDE_OSPlatform`, `ENTRA_OS`, `EG_OS`.
3. **`hasMdeMachineGroupTag`** *(endpoint)* — regex against MDE machine-group string. `machineTagPatterns:` `[regex,...]` (aliased `patterns:`). Field scanned: `MDE_MachineGroup` (single string; can be comma/semicolon-separated when multi-group — regex sees the joined string).
4. **`egDetectedRoles`** *(endpoint, identity)* — `egSignals:` `[string,...]` (aliased `roles:`). Two match modes: (1) substring against joined `EG_DetectedRoles` (sourced from EG `confidenceHigh`/`confidenceLow` arrays); (2) boolean property against `EG_RawData` (e.g. `egSignals: ['isDomainController']` matches when `EG_RawData.isDomainController: true`).
5. **`hasEntraExtensionAttributeTag`** *(identity)* — `attribute:` (e.g. `extensionAttribute6`), `value:`, `match:` (`exact` default = case-sensitive full match `-ceq`; anything else = case-insensitive substring `-like '*value*'`). Reads in order: top-level `ENTRA_<attribute>`, then nested `ENTRA_ExtensionAttributes.<attribute>`, `ExtensionAttributes.<attribute>`, `extensionAttributes.<attribute>`.
6. **`hasSoftwareInstalled`** *(endpoint)* — `tvmSoftwareNames:` `[glob,...]` (PowerShell `-like`; shape `vendor/name` OR `*/name`, e.g. `microsoft/windows server 2019`, `*/sql server*`, `apache/tomcat*`). Requires the `tvmSoftware` bulk index (built once per run by `Build-SIRuleIndexes`); without it the kind silently returns `$false`.
7. **`groupMembership`** *(identity)* — `group:` (single name; no list — repeat under `any:` for OR-of-groups). Exact CI match against Entra direct+transitive memberships from `ENTRA_Groups`. Short-circuits to `false` for non-user assets (SP/MI). Requires the `GroupMembership` bulk index.
8. **`hasAzureTagDirectOrParent`** *(azure; also endpoint when EndpointAzureCorrelation has linked the row)* — `tag:` (KEY, exact CI), `value:` (string/list; omit = presence-only), `match:` (default `equal`). Walks parent chain: resource → RG → subscription → MG; matches if any level carries the tag. Requires the `parentChain` bulk index; looks up id from `AZ_ResourceId` (or `PrimaryEntityId` fallback).
9. **`egKustoQuery`** *(endpoint, identity, azure — escape hatch)* — `kql:` (raw KQL run against the EG endpoint; must return a column of asset IDs: NodeId/DeviceId/AccountObjectId). The engine submits the KQL once at run start and caches the resulting node IDs into `$script:SIRuleIndexes.kustoSets[<RuleId>]`; per-asset evaluation does NOT submit KQL — it's a hashtable lookup against `PrimaryEntityId`/`EG_NodeId`/`MDE_DeviceId`/`AccountObjectId`. Cost paid once per rule per run.
10. **`mostFrequentUserTier`** *(endpoint)* — `tierValues:` `[int,...]`. Endpoint inherits its tier verdict from the most-frequent interactive user (logon-graph inheritance). Reads `Metadata.MostFrequentUserTier` (stamped by `Get-SIBulkDeviceUserCorrelation` at Enrich, sourced from logon graph + `SI_Identity_Profile_CL`). Matches if device's most-frequent user tier is in the list.
11. **`ipInRange`** *(endpoint, azure)* — `cidrs:` `[CIDR,...]` (IPv4/IPv6, aliased `cidr:`), `fields:` (optional; restrict which Metadata fields to scan, default = all known carriers). Default fields: `MDE_EffectiveIpAddresses`, `MDE_PublicIp`, `MDE_LastIpAddress`, `EG_PublicIp`, `EG_PrivateIp`, `EG_LastIpAddress`, `EG_InternalIpAddresses`, `ENTRA_PrivateIp`, `ENTRA_PublicIp`, `ENTRA_IpAddress`, `AZ_PrivateIp`, `AZ_PrivateIpAddresses`, `AZ_PublicIp`, `AD_IpAddress`, `AD_IpAddresses`, `CMDB_PrivateIp`, `CMDB_IpAddresses`, `CMDB_ip`, `CMDB_private_ip`. Also parses `AZ_PropertiesJson` for `ipAddress` / `ipConfigurations[*].properties.privateIPAddress`.
12. **`hasTag`** *(endpoint, identity, azure — cross-source convenience)* — `tag:` (KEY, exact CI), `value:` (string/list), `match:` (default `equal`), `sources:` (restrict to `mde`/`eg`/`entra`/`arm`/`cmdb`/`ad`, default all). At least one of `tag:`/`value:` required. Three modes: **Mode 1 key presence** (`tag:` only — any source has that key with non-empty value); **Mode 2 value presence** (`value:` only, requires `match: in`/`regex`/`like`/`has` — plain `equal` value-only is REFUSED to prevent over-broad matches); **Mode 3 exact pair** (`tag:`+`value:` — also matches literal `key:value`/`key=value` strings inside value-only carriers like MDE machineTags).

   **Carriers walked**: `mde` (value-only list, `MDE_MachineTags`); `eg` (value-only + key:value, `EG_RawData.deviceDynamicTags`/`deviceManualTags`/`tags`); `entra` (key:value, `ENTRA_ExtensionAttribute1..15` + `ENTRA_OnPremisesExtensionAttributes`); `arm` (key:value, `AZ_TagsJson` direct + parent-chain inheritance RG/sub/MG); `cmdb` (key:value, `Metadata.CMDB_<col>` folded by Reconcile from CMDB.csv columns); `ad` (value-only list, `AD_GroupMemberships` placeholder).

### `match:` operators (used by `hasTag`, `hasAzureTagDirectOrParent`)

All operator names case-insensitive on name AND value; comparisons case-insensitive throughout.

| Operator | Behavior | Example |
|---|---|---|
| `equal` (default) | Exact string match (`-ieq`) | `value: 'production'` matches `'PRODUCTION'` |
| `like` | PowerShell `-ilike` wildcards | `value: '*-prod-*'` matches `'app-prod-01'` |
| `has` | Substring presence (regex-escaped) | `value: 'finance'` matches `'finance-2026'` |
| `regex` | .NET regex (`-imatch`) | `value: '(?i)^prod[-_]'` |
| `matches` | Alias for `regex` | (same) |
| `in` | Value appears in a list | `value: ['prod','prd']` |
| `startswith` | Prefix match | `value: 'prod'` matches `'prod-app-01'` |
| `endswith` | Suffix match | `value: '-prod'` matches `'app-prod'` |

### `set` — what to stamp on the row

| Field | Type | Purpose |
|---|---|---|
| `Tier` | int 0..3 | Engine's tier verdict. **0=Critical, 1=High, 2=Medium, 3=Low**. Engine reduces `min(Tier)` across all matching rules. |
| `Purpose` | string | Human-readable role label (e.g. `'Domain Controller'`). Surfaces on the profile row. |
| `Category` | string | Grouping label (e.g. `'Server Roles'`, `'CMDB Mapping'`). |
| `Tags` | list of strings | Free-form tags, aggregated across rule matches. |
| `cmdbId` | string | **OPTIONAL.** Foreign key into `asset-profiling-providers/generic-cmdb/CMDB.csv`. When set, the engine looks up `cmdbId` in the CSV at Reconcile and **auto-stamps** `cmdbName` + `cmdbCriticality` + `cmdbDataSensitivity` from the CSV row. |

> **DO NOT set `cmdbName`/`cmdbCriticality`/`cmdbDataSensitivity` inline.** They come from the CMDB CSV via the `cmdbId` lookup — setting them inline overrides the CSV (single-source-of-truth violation). `cmdbId` is silently ignored when CMDB is not configured (gated on `$global:SI_EnableCmdbProvider`), so community customers can leave cmdb fields inert in custom rules and flip the global to activate them.

### Locked vs. custom — naming + override

| File suffix | Purpose | Edited by | Survives release upgrade? |
|---|---|---|---|
| `<RuleId>.locked.yaml` | Shipped baseline (universal logic) | Maintainer | No — overwritten on update |
| `<RuleId>.custom.sample.yaml` | Shipped starter template | Maintainer | No — overwritten |
| `<RuleId>.custom.yaml` | Customer override | Customer | **Yes** — gitignored, never overwritten |

**Override workflow**: copy `.locked.yaml` to `.custom.yaml`, keep the same `id:`, edit the `set:` block (and optionally `detections:`). Engine deduplicates by `id`; the `.custom.yaml` wins. When **only** the `.custom.yaml` exists (typical for inherently tenant-specific rules like `AssetProfileByCmdbTag`, `AssetProfileByIPSubnet`, `AssetProfileByExtensionAttributes`, `AssetProfileByGroupMembership`) the rule loads fine — nothing to override.

Worked example (keep shipped `ADDomainController` detection but stamp your own `cmdbId` + add a CAB tag): copy `ADDomainController.locked.yaml` → `ADDomainController.custom.yaml`, keep the exact same `id:`, paste the full rule body, then set:

```yaml
set:
  Tier:     0
  Purpose:  'Domain Controller'
  Category: 'Server Roles'
  Tags:     [ 'cab:domain-controllers' ]
  cmdbId:   'SVC-AD-PROD'           # your CMDB foreign key
```

Result on the next run: the locked rule is suppressed, the custom rule fires for the same DCs, the asset gets `Tier=0` + the tag + `cmdbId`, and Reconcile auto-stamps `cmdbName`/`cmdbCriticality`/`cmdbDataSensitivity` from the CSV. The `.custom.yaml` is gitignored so the override survives every release upgrade.

### Loading order + dedup

1. Engine scans every `*.yaml` under `asset-profiling-enrichment/<engine>/` (recursively).
2. Files ending in `.sample.yaml` are **skipped** (documentation only).
3. Each remaining file is parsed; rules are tagged with their source folder (`locked` / `custom`).
4. Dedup pass — rules with the same `id:` collapse; `custom` wins over `locked`.
5. Rules with `mode: disable` are dropped.
6. Final ruleset is evaluated against every asset; **first-match-wins per rule**; every matching rule contributes one entry to `SIRules[]` on the profile row.

Engine code: `RuleEval.ps1` (per-detection evaluator / every kind handler), `Get-SIRuleSet.ps1` (loader), `RuleIndexes.ps1` (bulk-index builders for kinds that need pre-fetched data). The `aggregator.contributors[]` in the schema reference the same AssetProfileBy* rule families.

---

## Risk-score model

> Source of truth for `riskscore_weighted.schema.custom.json` and its `.sample` companion. Grounded in `engine/risk-analysis/Invoke-RiskAnalysis.ps1` — `Get-WeightedFactorsConfig` (loads the JSON), `Build-WeightedFactorsKql` (emits the per-field `case()` + `RiskScore_Weight_Factor` + `RiskScore_Weight_Detailed` columns), and the Layer-3 application loop (multiplies `RiskScoreTotal` by `RiskFactor_Weight`). When code disagrees with this doc, code wins.
>
> **v2.2.228 loader behaviour**: `Get-WeightedFactorsConfig` no longer requires `$global:SettingsPath`. It walks up from the engine's `$PSScriptRoot` looking for a `risk-analysis-detection/` sibling at every level (depth cap 6). Per-report `<ReportName>.weighted.custom.json` overrides the solution-wide `riskscore_weighted.schema.custom.json`. Each successful load emits `[INFO] [weight] <Report> (engine=<x>): N field(s), source=<path>`; a miss emits a `[WARN]` naming the searched dirs.

### File pair

| File | Purpose | Edited by |
|---|---|---|
| `riskscore_weighted.schema.custom.json` | Active config consumed by every report | Customer (or maintainer pre-shipped) |
| `riskscore_weighted.schema.custom.sample.json` | Annotated starter copy | Maintainer |

There is no `.locked.json`. The custom file IS the source of truth — no merge.

### Three-layer risk model

The engine computes a single `RiskScoreTotal_Weighted` per row in three stages. Every section in this JSON tunes one stage.

| Layer | Formula | What this JSON tunes |
|---|---|---|
| **1. Base** | `consBase = lookup(...,SecuritySeverity)` and `probBase = lookup(...,CriticalityTierLevel)` from `riskscore.index.custom.csv` | `impactNormalizer`, `severityMapper`, `tierMapper` (label translation that drives the lookup) |
| **2. Additive adjustment** | `consAdj = consBase + RiskFactor_Consequence`; `probAdj = probBase + RiskFactor_Probability`; `RiskScoreTotal = consAdj * probAdj` | `riskFactorDetailedMapper`, `riskFactorProbabilityMapper` (which bools count) |
| **3. Multiplicative business multiplier** | `RiskScoreTotal_Weighted = floor(RiskScoreTotal * RiskFactor_Weight / 100.0)` | `weightedRiskFactors` (the big one) |

All Layer-3 multipliers are stored as **basis-100 integers**: `100 = 1.0x`, `150 = 1.5x`, `262 = 2.62x`. This dodges locale-decimal traps (da-DK parses `"1.5"` as `15`).

### Top-level fields

| Field | Type | Default | Code | Meaning |
|---|---|---|---|---|
| `outputColumn` | string | `RiskScoreTotal_Weighted` | line 14 | Final weighted-score column name. |
| `baseColumn` | string | `RiskScoreTotal` | line 14 | Unweighted column the multiplier feeds on. |
| `combiner` | string | `RiskScoreTotal * (1.0 + sum(weight_i * factor_i))` | line 15, doc-only | Documents the combine formula. Engine math hardcoded at line 3132. |
| `rounding` | string | `toint(round(<result>))` | line 16, doc-only | Documents rounding. Engine uses `[int][math]::Floor()` at line 3144. |
| `kqlSafetyNote` | string | n/a | line 17 | Documents the `column_ifexists()` wrap the consolidator uses when generating KQL. |

The two `*Column` strings ARE consumed (they decide which row property the engine reads/writes). `combiner`/`rounding`/`kqlSafetyNote` are documentation only.

### `impactNormalizer` — raw severity → 0..10 numeric

Converts string severities (`"High"`, `"Sev1"`, `"informational"`) and free text into 0..10, the input to `severityMapper`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `Impact` | KQL column read |
| `outputColumn` | string | `Impact` | KQL column written (usually same as source, in-place) |
| `stringMap` | object {string:number} | (below) | Case-insensitive value → numeric |
| `default` | number | `0.0` | Used when input null OR missing OR no key match |

Default `stringMap`: `{ "critical": 10.0, "very high": 10.0, "high": 8.0, "medium": 5.0, "moderate": 5.0, "low": 2.0, "informational": 1.0, "info": 1.0 }`. Use case: add `"sev1": 10.0, "sev2": 7.0` when ingesting ServiceNow incidents that ship sev numbers.

### `severityMapper` — numeric Impact → human label

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `Impact` | numeric input |
| `outputColumn` | string | `SecuritySeverity` | label output |
| `thresholds` | `[{min,label}, ...]` | (below) | Descending min → label. First match wins. |
| `default` | string | `Low` | When no threshold matched |

Default `thresholds`: `[ {min:9.0,"Very High"}, {min:7.0,"High"}, {min:4.0,"Medium"}, {min:0.1,"Low"} ]`. Use case: lower `High` to 6.5 so borderline CVEs trigger High routing.

### `tierMapper` — numeric tier → human label

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `CriticalityTier` | integer 0..3 input |
| `outputColumn` | string | `CriticalityTierLevel` | label output, fed into the Layer-1 lookup |
| `valueMap` | object {"0".."3":string} | (below) | Tier number → label |
| `default` | string | `Low - tier 3` | When tier null or missing |

Default `valueMap`: `{ "0":"Critical - tier 0", "1":"High - tier 1", "2":"Medium - tier 2", "3":"Low - tier 3" }`. Labels must match `riskscore.index.custom.csv`.

### `criticalityMultiplierMapper` — legacy single-field weight (deprecated)

Old single-column weighting, superseded by `weightedRiskFactors`. Only fires when `weightedRiskFactors` has no entry for the active engine. Defaults: `sourceColumn=cmdbCriticality`, `outputColumn=RiskFactor_Weight`, `valueMap={ "Critical":1.50,"High":1.25,"Medium":1.10,"Low":1.00 }`, `default=1.00`. Note: legacy uses **decimal** multipliers, not basis-100.

### `weightedRiskFactors` — Layer 3 multi-field business multiplier (the important one)

Cross-engine, multi-field weighting on basis-100 integers. **The engine's primary CMDB amplification mechanism.**

```json
"weightedRiskFactors": {
  "endpoint": { "combine": "...", "maxMultiplier": <int>, "fields": [...] },
  "identity": { "combine": "...", "maxMultiplier": <int>, "fields": [...] },
  "azure":    { "combine": "...", "maxMultiplier": <int>, "fields": [...] }
}
```

**Per-engine sub-object**: `combine` (`product`/`max`/`sum-of-deltas`, default `product` — how per-field multipliers fold together); `maxMultiplier` (int basis-100, default `0` = no cap; set `500` to cap at 5.0x); `fields` (`[{field,valueMap,default}, ...]`, required).

**Per-field entry**: `field` (column name, e.g. `cmdbCriticality`, `cmdbDataSensitivity`); `valueMap` (object {string:int}, case-insensitive value → basis-100 multiplier); `default` (int, default `100` = no amplification, used when value not in map or column missing/null).

**Combine modes** (worked over `cmdbCriticality=Critical (150)` + `cmdbDataSensitivity=Restricted (175)`):

| Mode | Math | Result |
|---|---|---|
| `product` | `(150/100) * (175/100) * 100 = 262` | **262** (2.62x) |
| `max` | `max(150, 175)` | **175** (1.75x) |
| `sum-of-deltas` | `100 + (150-100) + (175-100)` | **225** (2.25x) |

**Default endpoint config**:

```json
"endpoint": {
  "combine": "product",
  "maxMultiplier": 0,
  "fields": [
    { "field": "cmdbCriticality",
      "valueMap": { "Critical": 150, "High": 125, "Medium": 110, "Low": 105 }, "default": 100 },
    { "field": "cmdbDataSensitivity",
      "valueMap": { "Restricted": 175, "Confidential": 150, "Internal": 125, "Public": 110 }, "default": 100 }
  ]
}
```

Use cases: add a third axis (e.g. cost-centre — drop a new `{field,valueMap,default}` into `fields[]`, no code change); cap runaway multiplication (`maxMultiplier: 500`); switch to conservative additive (`combine: sum-of-deltas`); disable Layer 3 (omit the engine's section — engine reads `RiskFactor_Weight = 100`, so `RiskScoreTotal_Weighted == RiskScoreTotal`).

✅ **Nothing to rebuild after editing.** This used to say "re-run `Build-RiskAnalysis.ps1` so the
consolidator regenerates the `__WEIGHTED_FACTORS__` blocks inside report KQL". That was **wrong even
before the tool was retired (#28)**: the catalog ships the `//__WEIGHTED_FACTORS_BEGIN__` /
`__END__` markers (120 of them) as a no-op default, and **the ENGINE substitutes the generated KQL
chain at run time** from the customer JSON — `Invoke-RiskAnalysis.ps1:2430`, helpers at `:1254`. The
JSON edit takes effect on the next run, with no build step. Following the old instruction would have
rebuilt the whole catalog destructively.

### `riskFactorDetailedMapper` / `riskFactorProbabilityMapper`

- **`riskFactorDetailedMapper`** — `outputColumn` default `RiskFactor_Probability_Detailed`; `perEngineFields` default `{ endpoint:["IsStaleAsset"], identity:["IsExternalIdentity"], azure:[] }`. The consolidator AUTOMATICALLY includes every `bool` column in the profile schema with `purpose: risk` (no need to list those); `perEngineFields` is for **non-risk-purposed** bools you want to count anyway. Output is a semicolon-joined string like `"IsStaleAsset; OutdatedOS"`.
- **`riskFactorProbabilityMapper`** — `outputColumn` default `RiskFactor_Probability`. The integer count of `true` risk-factor bools per row; added to `probBase` (line 3118).

### End-to-end worked example

**Asset**: server, `cmdbCriticality=Critical`, `cmdbDataSensitivity=Restricted`, `SecuritySeverity=High`, `CriticalityTier=0`, two risk-factor bools fired (`IsStaleAsset`, `OutdatedOS`).

**Layer 1**: `Impact` = `impactNormalizer("High")` → 8.0; `SecuritySeverity` = `severityMapper(8.0)` → `"High"`; `CriticalityTierLevel` = `tierMapper(0)` → `"Critical - tier 0"`; `consBase = lookup(Endpoint,Cat,SubCat,"High")` → **3**; `probBase = lookup(Endpoint,Cat,SubCat,"Critical - tier 0")` → **4**.

**Layer 2**: `RiskFactor_Consequence` = 0 (placeholder) → `consAdj = 3+0 = 3`; `RiskFactor_Probability` = count(true) = 2 → `probAdj = 4+2 = 6`; `RiskScoreTotal = 3*6 = 18`.

**Layer 3** (`product`): `cmdbCriticality(Critical)→150`, `cmdbDataSensitivity(Restricted)→175`; `RiskFactor_Weight = floor((150/100)*(175/100)*100) = 262`; `RiskScoreTotal_Weighted = floor(18 * 262 / 100) = 47`.

So this row, raw 18, surfaces in the Excel sort at **47** — ahead of un-amplified Critical-but-non-Restricted assets.

Consumers: `engine/risk-analysis/Invoke-RiskAnalysis.ps1` (lines 2231-2409 build KQL, 3043-3145 apply Layer 3, `:2430` substitutes the `__WEIGHTED_FACTORS__` block **at run time**); `risk-analysis-detection/riskscore.index.custom.csv` (the Layer-1 lookup table). *(The retired `Build-RiskAnalysis.ps1` used to be listed here as a consumer — see #28; the substitution is entirely a run-time step, so there is no build consumer.)*

---

## Risk-analysis queries & report structure

> Source of truth for `RiskAnalysis_Queries_Locked.yaml` and its `_Custom.yaml` companion. Grounded in `engine/risk-analysis/Invoke-RiskAnalysis.ps1` (consumer) and `risk-analysis-detection/risk-analysis.schema.locked.json` (the JSON-schema describing the YAML). When code disagrees with this doc, code wins.

### File pair + merge semantics

| File | Purpose | Edited by | Survives release upgrade? |
|---|---|---|---|
| `RiskAnalysis_Queries_Locked.yaml` | Shipped 132+ reports + templates | Maintainer | No |
| `RiskAnalysis_Queries_Custom.yaml` | Customer overrides + new reports | Customer | Yes |

**Merge rule** (`Merge-ByReportName`, `Invoke-RiskAnalysis.ps1` lines 4095-4192): same `ReportName` → custom **fully replaces** locked (no partial merge); new `ReportName` → appended at end; locked order preserved, matching custom entries overwrite in-place; ReportTemplates merge by template `ReportName` with the same rules. Merge log line at 4271-4275: `YAML merge: Locked Reports={...}, Custom={...}, Merged={...}`.

### Top-level structure

```yaml
Reports:                     # list -- one entry per report (one Excel sheet / LA write)
  - ReportName: ...
ReportTemplates:             # list -- groups of reports run together
  - ReportName: ...
    ReportsIncluded: [...]
```

Both keys are required; the engine errors if either is missing or empty.

### `Reports[]` — field reference

Every entry maps to ONE Excel sheet / LA write. All fields required unless flagged optional.

| Field | Type | Code | Meaning |
|---|---|---|---|
| `ReportName` | string | line 4320 lookup | Unique id. Referenced from `ReportTemplates[].ReportsIncluded[].Name`. |
| `ReportPurpose` | string | informational | Human description; surfaces in run logs. |
| `SecurityDomain` | string | `Calculate-RiskScore` (1844) | One of `Endpoint`, `Identity`, `Azure`, `Publicip`, `Hygiene`, `RiskAnalysis`. Selects the static Impact lookup table when the row has no `Impact` column. |
| `CategoryInputName` | string | column resolver (1824) | KQL column carrying the risk category. |
| `SubcategoryInputName` | string | column resolver | KQL column carrying the sub-category. |
| `ConfigurationIdInputName` | string | column resolver | KQL column carrying the asset id (DeviceId / UserObjectId / ResourceId). |
| `SecuritySeverityInputName` | string | column resolver | KQL column carrying severity (`Very High`, `High`, `Medium`, `Low`, …). |
| `CriticalityTierLevelInputName` | string | column resolver | KQL column carrying the tier label (`Critical - tier 0` etc.). |
| `RiskConsequenceScoreOutputName` | string | output naming | Excel column for consequence score. |
| `RiskProbabilityScoreOutputName` | string | output naming | Excel column for probability score. |
| `RiskScoreOutputName` | string | output naming | Excel column for the raw `RiskScoreTotal`. |
| `CriticalityTierLevelScope` | `[string,...]` | scoring filter | Allowed tier labels. Rows outside this set are dropped. |
| `SecuritySeverityScope` | `[string,...]` | scoring filter | Allowed severity labels. Rows outside this set are dropped. |
| `OutputPropertyOrder` | `[string,...]` | strict-mode column projection (1844) | Canonical 21-col order from `risk-analysis.schema.locked.json` plus report-specific extras (CMDB, EG, …). Engine emits exactly these columns in exactly this order; extras appended after the 21 canonical columns. ⚠️ **A column NOT listed here is not guaranteed to be exported at all — see "How a column reaches the .xlsx" below (audit #26). Declare anything you need.** |
| `SortBy` | `[string,...]` | Excel sort | Optional. Sort key(s) — prefer `RiskScoreTotal_Weighted`. |
| `ReportQuery` | `[string]` (one-element list, multi-line KQL) | submitted via `Invoke-GraphHuntingQuery` | The KQL itself. Engine auto-routes pure-LA queries to Log Analytics; mixed XDR queries to advanced hunting. |

#### Submission-path normalization (applies to every routing branch)

`Invoke-GraphHuntingQuery` is the single chokepoint all report queries pass through before
the Sentinel-lake / advanced-hunting / Log-Analytics-direct branches. Two behaviours are
enforced there:

- **Dynamic group-key cast (SEM0001 guard).** Log Analytics refuses to `summarize … by` a
  column of `dynamic` type. The CMDB columns (`cmdbName`, `cmdbId`, `cmdbCriticality`,
  `cmdbDataSensitivity`) are projected with `column_ifexists(…)` and arrive as `dynamic`
  whenever the source column is absent (and the PublicIP open-port / vuln reports surface
  `cmdbName` straight off `SI_VulnerabilityPIP_CL`). Before submission, `Add-DynamicGroupKeyCasts`
  wraps any such column appearing as a **bare group key** in `tostring(…)`. It is list-driven
  (never touches numeric columns such as `RiskScore*` / `*Tier`, so ordering and scoring stay
  numeric), idempotent, and skips alias-form keys (`cmdbX = ""`) and already-cast keys. This
  mirrors the `tostring(cmdbName)` cast baked into the catalog's KQL (originally emitted by the
  now-retired `Build-RiskAnalysis.ps1`, #28 — the cast lives in the catalog and stays), so the runtime
  summarize path cannot regress relative to the built template. It covers the PublicIP reports
  and the cross-domain Attack-Path Summary reports, all of which group by `cmdb*`.
- **Deferred multi-path fallback logging.** When the engine tries several routes to the same
  data (Sentinel data lake → EG-hybrid → advanced hunting → LA-direct) and a later route
  **succeeds**, the earlier failed attempts are no longer logged as `[WARN]`/`[ERR]` — they
  were superseded by the success. Each failed attempt is stashed silently (full detail kept at
  `[DIAG]` + in the `ra-laerr-*.txt` dumps); a successful path then emits at most one `[INFO]`
  (`auth/data via <path> (after N superseded fallback attempts)`), and only a **total** failure
  flushes a single consolidated `[WARN]`. This stops operators from reading a successful report
  run as failed.

### Allowed `SecurityDomain` values + their `byCategory` keys

(from `risk-analysis.schema.locked.json → domains.<Domain>.impact`)

- **Endpoint** — Vulnerabilities, CVEs, Application, OS, Security controls, Firmware, Network, Accounts, Endpoint Hygiene, Sensor Health, Onboarding, EDR, Antivirus, Bitlocker, TPM / Secure Boot, Attack Paths
- **Identity** — Authentication, Account Lifecycle, Privileged Access, Workload Identities, Password Policy, Identity Hygiene, Conditional Access, Multi-Factor, Privileged SPN, Stale Identity, Service Account, Guest / External, Shadow Admin, Break Glass, Sign-in Risk, Role Assignment, Mailbox Access, Attack Paths, Admin Account Hygiene, Identity Lifecycle, Privilege Escalation Paths, Sign-in Behaviour, Threat Intelligence
- **Azure** — Public exposure + data sensitivity, Encryption at rest, Encryption in transit, Network exposure, Authentication, DDoS protection, Soft-delete / recovery, RBAC / least privilege, Logging / retention, Workload identity, mdcSecurityRecommendation, mdcManagementRecommendation, Attack Paths, AttackPath_GitHubToAzure
- **Publicip** — Exposed service, Open admin port, Vulnerability, Geo anomaly
- **Hygiene** — Coverage drop, Cmdb orphan, Drift, Pipeline, Stale Asset, Unsupported OS

Categories not present in `byCategory` fall back to `domains.<Domain>.impact.default` (usually 5.0).

### `ReportTemplates[]` — field reference

Templates group reports for a single run. The launcher selects a template via `$global:ReportTemplate`.

| Field | Type | Required | Code | Meaning |
|---|---|---|---|---|
| `ReportName` | string | yes | line 4280 lookup | Template id, e.g. `RiskAnalysis_Detailed`, `RiskAnalysis_Summary`. |
| `ReportPurpose` | string | no | informational | Label like `Detailed` / `Summary`. |
| `ReportsIncluded` | `[{Name: <string>}, ...]` | yes | `Resolve-ReportInclude` (4320) | Ordered list of report ids to run when this template is selected. |
| `Mail_To` | `[string,...]` | no | lines 4306-4310 | Per-template recipient override (see Email). |
| `Mail_SendMail` | bool | no | lines 4313-4315 | Per-template send toggle. |

### Email / notification surface

**Recipient-resolution precedence (highest wins)**:

1. **Per-template YAML override** (`Mail_To` / `Mail_SendMail` on the active `ReportTemplates[]` entry) — lines 4292-4316.
2. **Per-runmode globals** — `$global:RiskAnalysis_Detailed_To` / `RiskAnalysis_Summary_To` (and legacy `$global:Mail_SecurityInsight_Detailed_To` / `_Summary_To`) — lines 3884-3910 (AutomationFramework branch) / 3979-4003 (community branch).
3. **Global** — `$global:SendMail` + `$global:MailTo` — lines 4002-4003.

When a per-template override applies, the engine logs: `Mail recipients overridden by template '<TemplateName>': <a@x.com,b@x.com>` or `Mail send-flag overridden by template '<TemplateName>': SendMail=<true|false>`.

**Override caveat**: because the merge is **full-replace by ReportName**, putting only `Mail_To` in the custom file loses the entire `ReportsIncluded` list from the locked entry. To override mail without losing reports, repeat the full `ReportsIncluded` list verbatim in the custom template alongside `Mail_To`. To suppress mail for one template, set `Mail_SendMail: false` (overrides global `SendMail=true`).

**Other mail globals (set in `LauncherConfig.custom.ps1`)**: `$global:SendMail` (master on/off), `$global:MailTo` (default recipients), `$global:SMTPFrom` (sender), `$global:SmtpServer` (relay host), `$global:SMTPPort`, `$global:SMTP_UseSSL`. Validation at line 241-243: if `SendMail=true` but no recipient source resolves, the engine throws.

### Token substitutions inside `ReportQuery`

The engine recognises these markers and substitutes them at run time. None are valid KQL on their own — they MUST live in the YAML, never in a hand-run AH portal copy.

| Token | What's substituted | Source | Use when |
|---|---|---|---|
| `__BUCKET_FILTER__` | `where <hash-bucket-clause>` — e.g. `where hash(DeviceId, N) in (0,1)` | `AutoBucketCount` probe (~line 4000) | Query may exceed AH 30k-row ceiling. Engine probes 1→2→4→…→`AutoBucketMax` to find the largest size that fits. Cached per (`ReportName`, queryHash) in `$SettingsPath/OUTPUT/AutoBucketCache.json`. |
| `__EXCLUDED_CVES_BEGIN__` … `__EXCLUDED_CVES_END__` | Per-report CVE blacklist injected as `\| where CveId !in (...)` | `risk-analysis-detection/SecurityInsight_RiskAnalysis_Excludes_Custom.json` | Suppress known false positives for ONE report without touching the locked KQL. |
| `__EXCLUDED_CONFIGURATION_IDS_BEGIN__` … `__EXCLUDED_CONFIGURATION_IDS_END__` | Per-report config-id blacklist | same exclude file | Suppress noisy config IDs for ONE report. |
| `__WEIGHTED_FACTORS_BEGIN__` … `__WEIGHTED_FACTORS_END__` | KQL `case()` chain mapping cmdb columns to `RiskFactor_Weight` integer (basis-100) | `riskscore_weighted.schema.custom.json` (see Risk-score model) | Always present in modern reports; substituted from the weighted-factor JSON. |

`AutoBucketCount` controls: `$global:AutoBucketCount` (default `$true`), `$global:AutoBucketMax` (default `64`), `$global:AutoBucketCache` (default `$true`), `$global:ResetCache` (forces re-probe).

### Cross-domain query shape — EG-native bucket re-key

The cross-domain **Attack-Path Summary** reports walk ExposureGraph (nodes + edges) to detect a path, then enrich the final target (and, for the vulnerable-device report, the source device) with CMDB metadata from a `SI_*_Profile_CL` snapshot inlined as a KQL `datatable`. The CL enrichment is a **leftouter join on an identity key** (e.g. `… on $left.FinalTargetId == $right.Target_AzureResourceId_Guid`), where the CL projection's join column **equals the EG NodeId hex** for matched rows — CL contributes only `cmdbName` / `cmdbCriticality` / `cmdbDataSensitivity` / `cmdbId`; EG owns path detection, tier and scoring.

Bucketing splits a too-large query into N hash partitions. For the partition to actually **bound the ExposureGraph work** (the expensive side), the `__BUCKET_FILTER__` block must hash on a column that exists *on the EG scan*, before the joins — an **EG-native** column such as `NodeId`. If, instead, the engine partitions on the CL-side enrichment key (a `cmdb*` / `Target_*` column that only exists *after* the joins), the EG scan runs in full for every bucket and the report hits the **900s advanced-hunting HttpClient ceiling** at large-tenant scale.

Each cross-domain Summary report therefore declares a per-report **`crossDomainBucketCoalesce`** block that maps its CL bucket-key column to the EG-native column it equals:

```yaml
- ReportName: Attack_Paths_Summary_Github_to_Azure_Resources
  crossDomainBucketCoalesce:
  - ClColumn: Target_AzureResourceId_Guid   # CL-side enrichment join key
    EgNativeKey: NodeId                       # the EG column it equals (NodeId hex)
```

Given this declaration the engine:

1. Keeps the **EG-side `__BUCKET_FILTER__` active** (it no longer suppresses it as "cross-domain lossy"), and leads the EG `__bucket_key` coalesce with the declared `EgNativeKey` — so the ExposureGraph scan is genuinely partitioned to ~1/N of nodes per bucket (a real partition that **bounds** EG work, not a row cap or sample).
2. Buckets the inlined CL snapshot on the matching `ClColumn`, whose value is the same EG NodeId hex, using the **same SHA256-modulo math** — so the EG subset and CL subset of each bucket align, and the per-bucket leftouter joins keep **every** match (lossless). Across all N buckets the union is identical to the un-bucketed result; only the query path changed.

The CL enrichment columns (`cmdbName`, …) are still projected by the report exactly as before — the re-key changes only *which column the partition hashes on*, never the output. The vulnerable-device report declares two entries: `Source_AadDeviceId → AadDeviceId` (the source-device node, where the bucket filter sits, surfaces `AadDeviceId` so it can hash the same value the CL source row carries) and `Target_AzureResourceId_Guid` (target enrichment, applied downstream). Reports **without** a `crossDomainBucketCoalesce` block keep the prior conservative behaviour (EG bucket filter suppressed when a CL let carries a non-EG key) — correct, just slower; the declaration is the opt-in that makes the EG side bounded.

### Three-layer risk computation (where these YAML values feed)

Every row that survives the report's `Scope` filters goes through:

1. **Layer 1 — base** (lines 3114-3115): `consBase = lookup(SecurityDomain,Category,SubCategory,SecuritySeverity)` and `probBase = lookup(...,CriticalityTierLevel)` — index lives in `risk-analysis-detection/riskscore.index.custom.csv`.
2. **Layer 2 — additive risk-factor adjustment** (lines 3117-3119): `consAdj = consBase + RiskFactor_Consequence` (today always 0); `probAdj = probBase + RiskFactor_Probability` (count of true risk-factor bools); `RiskScoreTotal = consAdj * probAdj`.
3. **Layer 3 — multiplicative business multiplier** (lines 3122-3144): `RiskScoreTotal_Weighted = floor(RiskScoreTotal * RiskFactor_Weight / 100.0)`, where `RiskFactor_Weight` is a basis-100 integer from the weighted-factor JSON.

Excel sort uses `RiskScoreTotal_Weighted` (preferred) — `Invoke-RiskAnalysis.ps1` lines 5289-5297. The `__WEIGHTED_FACTORS__` blocks are substituted into report KQL **at run time** by the engine (`Invoke-RiskAnalysis.ps1:2430`), not by a build step.
---

## Risk Analysis report catalog (model & inventory)

The full per-report catalog (every report's purpose, mode, severity/tier scope, source tables,
output columns, bucketing flag, and full KQL) is **auto-generated** from the single authority file
`risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` by
`engine/risk-analysis/tools/Build-QueriesDoc.ps1`. **That YAML is the authority itself — it is
hand-maintained, not consolidated from anything** (audit #28: `_source/` +
`Build-RiskAnalysis.ps1` were retired and deleted 2026-08-06; regenerating would have replaced the
118-report catalog with an incompatible 264-report one and broken every run). The
`__WEIGHTED_FACTORS__` and `__BUCKET_FILTER__` placeholders live in the catalog and are substituted
by the **engine at run time**, not at build time. This section documents the **model** — how the
catalog is organised and how to read a report block.

### Catalog shape

- Reports are grouped into four **security domains**: `Identity`, `Endpoint`, `Azure`, `PublicIP`.
- Each domain has paired **Summary** and **Detailed** reports. Summary = one row per finding type;
  Detailed = one row per affected asset.
- Every report runs against the `SI_*_Profile_CL` Profile tables (latest snapshot via
  `summarize max(CollectionTime)`), with cross-domain Attack-Path reports additionally reading
  `ExposureGraphNodes` / `ExposureGraphEdges`.
- Each report carries a `__BUCKET_FILTER__` placeholder so the engine can split queries that would
  exceed Defender Advanced Hunting's ~30k-row ceiling (see [bucketing](#container--keda-deployment)
  and [troubleshooting](#troubleshooting)).
- The catalog summary line (counts per domain, Summary vs Detailed splits) is recomputed by the
  generator each release; the README teaser table and §6.9 inventory are re-counted from the YAML
  on every README touch — never quote stale numbers.

### How to read a generated report block

Each report block in the generated catalog has:

- **Purpose** — verbatim `ReportPurpose` from the YAML (one-line summary of what it flags).
- **Mode** — `Summary` or `Detailed`.
- **Severity scope** — which `SecuritySeverity` bands the report includes (Very High / High /
  Medium-High / Medium / Low / Informational).
- **Tier scope** — which `CriticalityTierLevel` rows are included (Critical-tier-0 / High-tier-1 /
  Medium-tier-2 / Low-tier-3). Engine post-filter at collection time drops any non-blank value
  outside the report's `CriticalityTierLevelScope` / `SecuritySeverityScope`; never emit "Unknown"
  defaults — use an in-scope value or blank.
- **Source tables** — the `*_CL` and Defender-XDR hunting tables the KQL reads.
- **Output columns** — the projected columns, in XLSX/JSON output order.
- **Sort by** — usually `RiskScoreTotal_Weighted`.
- **Bucketing** — whether the engine auto-splits the query (`enabled`/`disabled`, with the
  starting bucket count; AutoBucket grows to fit the ceiling).
- **KQL** — the full query, with `__BUCKET_FILTER__` substituted at runtime.

### Report-authoring rules (lint-enforced)

The pre-publish gate validates report structure (`RAReportStructure` / `TemplateCoverage` checks):

- Every report has the required fields; `ReportName` is unique across the catalog.
- `SecurityDomain` is in the allowed set (`Identity` / `Endpoint` / `Azure` / `PublicIP`).
- `ReportPurpose` is ≥ 80 characters (forces a meaningful description).
- Every report appears in at least one `ReportTemplate.ReportsIncluded` (no orphan reports, no
  ghost references to non-existent reports).
- **RA sources risk/finding signals from ExposureGraph** (nodes + edges) as the primary source;
  `*_Profile_CL` Profile tables join in only for tenant correlation (Tier, UnsupportedOsDetected,
  `cmdb*`, `IsStaleAsset`). `CriticalityTier` ALWAYS sources from `SI_*_Profile_CL.Tier`
  (engine-computed) — never coalesce in EG `criticalityLevel`.
- KQL comment hygiene: no inline `//` comments between expressions in a `project`/`extend` body
  (breaks LA's parser even when XDR tolerates it); `// Step X:` headers inside `|-` blocks drop the
  colon. Put doc comments above the `let`.

### Report templates (orchestrators)

`ReportTemplate` entries name the set of reports to run for a given launch mode (e.g. a Summary
template and a Detailed template, plus focused/complex test templates). The launcher's CLI flags
(`-ReportTemplate`, `-Detailed`, `-Summary`) win over config-set `RiskAnalysis_*_Override` values.
Override flags only BUMP a mode flag to `$true`; they never force it to `$false`.

---

## Report enrichment model

**Purpose.** A single shared enrichment vocabulary that applies across all RA (RiskAnalysis) reports, sourced from the field gaps in the MDE/ExposureGraph field-gap audit. Removes per-report bespoke columns; lets any report opt into the enrichment that's relevant.

> **v2.2 status:** `MITRE_Tactics`, `MITRE_Techniques`, `ComplianceTags` are emitted as always-exists columns on every report row, but **only the two `Device_Missing_CVEs_*` reports populate them today** (their KQL projects from `DeviceTvmSecureConfigurationAssessmentKB.RelatedMitre*` + `Tags` + `ConfigurationBenchmarks`). The other 134 reports query Profile tables / Identity sources that don't carry equivalent fields, so the columns are present-but-empty. Broader coverage requires a per-`ConfigurationId` lookup table — slated for v2.3 (Tier B + F per the rollout below).
>
> `MoreDetails` is now built per row from harvested URLs + Defender / Entra / Azure portal links + MITRE links. v2.2 also injects `MdeDeviceId` / `EntraAccountObjectId` / `AzureResourceId` into every `summarize ... by` block (via `any(column_ifexists(...))`) so the engine can build portal links even on Summary aggregates that previously dropped these IDs.

### Design principles

1. **Generic over bespoke** — one column per signal family, not one column per report.
2. **Separate WHERE from HOW** — *new column* for hard data, *MoreDetails* for human-readable links + descriptions.
3. **Extend existing patterns** — don't invent new shapes if the `RiskFactor_*_Detailed` semicolon-list pattern already covers it.
4. **Always-emitted, ever-empty** — every report row has every column (even if empty); KQL filters and downstream consumers don't have to handle "missing".
5. **Engine-derived, not YAML-hardcoded** — the engine's per-row enrichment pass populates these from row-level signals; YAML doesn't have to know.

### A. New columns to add (per-row, all reports)

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
| **`RecommendedAction`** | string (short imperative) | Per-report engine logic | `Patch CVE-2025-15556 on <hostname>` | All reports |
| **`MoreDetails`** | string (newline-separated raw URLs) | Engine-built per row from: harvested `http(s)://` values across all columns + Defender/Entra/Azure portal URLs computed from `MdeDeviceId` / `EntraObjectId` / `AzureResourceId` + `attack.mitre.org` URLs from `MITRE_*` | `https://security.microsoft.com/machines/<id>/overview\r\nhttps://portal.azure.com/...` | All reports (always emitted, empty when no source IDs present) |

#### Notes

- `RecommendedAction` is short (≤120 chars). Long remediation steps go in `MoreDetails`.
- `MoreDetails` collects all per-row URLs (raw URL columns, portal links, MITRE links) into one cell, one URL per line (`\r\n`-separated, no label prefix). Deduped, capped at 25 URLs / 4000 chars to stay Excel-readable.
- `MITRE_*` are semicolon-lists same as `RiskFactor_*_Detailed` — for grep/filter consistency.

#### `ImpactedAssetCount` vs `ImpactedAssetsList` — currently NOT the same population (audit #25)

A reader seeing a number beside a list assumes the number counts that list. **Today it does not.**
Every Summary report computes them independently, over **different columns**:

```kql
| summarize
    ImpactedAssetCount = dcount(DeviceKey),          // distinct DEVICE KEYS, and dcount is ESTIMATED
    ImpactedAssetsList = make_set(AssetName)         // distinct ASSET NAMES, exact
```

They diverge **by construction**, not by rounding: two DeviceKeys sharing one AssetName, or a device
whose AssetName is null (`make_set` drops nulls), gives count > list; inconsistent name casing gives
list > count. Kusto's `dcount` is HyperLogLog-**estimated** on top of that, so it need not be exact
even over one column.

🔒 **Intended contract, for whoever fixes it:** the count must be **derived from the set that is
displayed** — `ImpactedAssetCount = array_length(ImpactedAssetsList)` — so the two cannot disagree.
✏️ **Corrected 2026-08-06 (#28): fix it in `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml`
directly.** This used to say the YAML is *generated* and the fix belongs in `_source/` — it is not,
and `_source/` has been retired and deleted. Two practical notes from re-verification: the count and
the list sit in the **same `summarize`**, so the fix is a FOLLOWING `| extend`, not an in-place swap;
and `Endpoint_ActiveCompromise_Detected_Summary` has **no `ImpactedAssetsList` at all**
(`dcount(PrimaryEntityId)` only), so `array_length` cannot apply there — decide that one separately.

#### How the workbook is WRITTEN — one bulk load, not a cell at a time (v2.2.445)

The export used to pipe the finished rows into `Export-Excel`, which walks each row's properties in
PowerShell and writes cells individually. Measured on the 5.1 runtime that is **~0.55 ms per cell**,
and a Detailed workbook of 121,111 rows × 291 columns is **35.2 million cells** — the rate alone
predicts a **5 h 34 m** export to within 3.4% of the observed figure.

🔑 **Cost tracks cell SLOTS, not values.** At 3,000 × 291, dropping **86% of the values** saved **9%**
of the time (455.8 s populated vs 413.0 s mostly-empty). Every declared column is visited whether or
not it holds anything, and the `Details` sheet is the cross-report **union** of ~60 reports' columns —
so a CVE row carries ~40 real values in 291 slots and the sheet is ~85% structurally empty.

`Export-Worksheet` now makes **one pass** over the data, which simultaneously:

1. flattens non-scalars and scrubs XML-illegal characters,
2. records the widest rendered value per column (replacing `AutoFitColumns`), and
3. notes which columns hold `[datetime]`,

emitting each row as a preallocated `object[]`. The whole block then goes to EPPlus via a single
**`LoadFromArrays`** call, after which the table style, autofilter, frozen bold header, column widths,
wrap targets, vertical alignment and date formats are applied per column.

| measured | before | after |
|---|---|---|
| write only, 3,000 × 291 | 455.8 s | **3.2 s** |
| end to end, 3,000 × 291 | ~520 s | **17.5 s** |
| end to end, 20,000 × 291 | — | **148.9 s** |
| end to end, **121,111 × 291** (a real customer shape) | **20,051.92 s** observed in production | **1,261.6 s** measured |

| at 20,000 × 291, like for like | old path | bulk path |
|---|---|---|
| time | 3,472.09 s | **107.17 s**  (32×) |
| peak memory | 10,032 MB | **1,887 MB**  (5.3× less) |
| file size | 4.44 MB | **4.44 MB**  (identical) |

🔑 **The bulk path also uses ~5× LESS memory**, because a row held as a preallocated `object[]` is far
lighter than the `[pscustomobject]` rebuild it replaced. The faster export is also the one less likely
to exhaust a collection host.

🪤 **STYLING A COLUMN MATERIALISES A CELL IN EVERY EMPTY SLOT OF IT** (v2.2.448). `LoadFromArrays`
correctly writes NO cell for a null, and this sheet is ~85% structurally empty — so applying vertical
alignment to all 291 columns inflated the workbook **3.6×**: 0.67 MB → 2.40 MB at 3,000 × 291, and
4.44 MB → 16.03 MB at 20,000 × 291. **Nulls themselves cost nothing** — 0.56 MB with 251 null columns,
0.56 MB without. Range-based styling is **not** cheaper (2.41 MB, measured); the saving comes from
styling **7 columns instead of 291**. Top alignment is therefore set only where `WrapText` is, which
is the only place it is visible — in a normal-height single-line row `Top` and the default `Center`
are indistinguishable. ⚠️ Not merely a disk concern: the mail attachment cap is 20 MB, so an inflated
workbook can silently stop being attached for a customer who was previously under it.

**Nothing observable about the workbook changes.** Rows, columns, order, table, filter, header,
widths, wrapping and alignment are all identical — pinned by `SI-ExcelBulkExport.Tests.ps1`.

⚠️ **Three traps this path carries, all found by running it:**
- **A `[datetime]` has no format of its own.** EPPlus stores it as an OLE serial, so without an
  explicit number format the cell reads `46260,125`. Hence step 3 above.
- **The package is opened/created here**, not by `Export-Excel`. A workbook accumulates sheets across
  calls (index sheet, `Details`, AI summary), so an existing file must be **opened** and the target
  sheet deleted — creating a new package instead silently destroys the earlier sheets.
- **PS 5.1 cannot parse a multi-argument indexer nested inside a method-call argument.**
  `$ws.Tables.Add($ws.Cells[1,1,$r,$c], $n)` is a *parse* error, not a runtime one, so it fails before
  a line executes and looks nothing like a type problem. Hoist the range into its own variable.

🔑 **The InvariantCulture swap around the write is no longer load-bearing, and is kept anyway.**
`LoadFromArrays` hands EPPlus the **boxed** .NET value, so a `[double]` is never stringified and the
comma-decimal hazard (`9.8` → `"9,8"` → `98`) cannot arise on this path at all. Verified under `da-DK`.
A side effect worth having: dropping `AutoFitColumns` also drops the `System.Drawing.Common`
dependency, so Linux containers stop falling back to a default width of 10 and now produce the same
workbook as Windows.

#### How a column reaches the .xlsx — and how it silently does not (audit #26)

⚠️ **Emitting a column from KQL is NOT enough to get it into the output.** The export column list is
built in `Invoke-RiskAnalysis.ps1` (~3319) and everything outside it is discarded by a single
`Select-Object -Property $DesiredColumns`, which feeds **all three sinks at once — the .xlsx, the
JSON sibling and the Log Analytics ingest.** The list is assembled from three sources:

1. **`OutputPropertyOrder`** from the report's YAML — *declared*, therefore reliable. A declared
   column that is missing on a row still appears, empty.
2. **`$ComputedCols`** — engine-added columns (scores, `AssetDetectedInReportName`, …).
3. **Everything else discovered from `$RiskScoreArray | Select-Object -First 1`** — i.e. **the FIRST
   ROW ONLY**.

🔴 **Step 3 is why columns disappear.** Advanced-Hunting rows are rebuilt from
`$r.AdditionalProperties.Keys`, and that bag **omits null-valued columns**. So a column that happens
to be empty on the first row is simply *absent from that object*, never enters `$DesiredColumns`, and
is then dropped for **every** row of that report — from Excel, JSON and LA together. The loss is
intermittent and data-dependent, which is exactly why it reads as "columns sometimes go missing"
rather than as a broken report.

**Consequence for report authors:** `MoreDetails` is declared in `OutputPropertyOrder` (120 uses) and
is safe. `RemediationOptions`, `RecommendedAction` and `Recommendation` are **declared nowhere**, so
they survive only when the first row happens to have a value. 🔒 **If a column matters, DECLARE IT in
`OutputPropertyOrder` — do not rely on discovery.**

**Trace columns** (`CollectionTime`, `SolutionVersion`, `TraceName`, `TraceID`) are deliberately kept
out of every YAML `OutputPropertyOrder` and pinned last by the engine.

### B. New tokens to add to existing `RiskFactor_*_Detailed`

Don't add new columns for these — extend the existing semicolon-list vocabulary. Keeps the count column meaningful (more tokens = higher score).

#### `RiskFactor_Probability_Detailed` — likelihood amplifiers

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

#### `RiskFactor_Consequence_Detailed` — consequence amplifiers

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

### C. `MoreDetails` URL-list extensions

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

### D. Mapping: which source fields populate which target

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

### E. Implementation cost (rough estimate)

| Tier | Scope | Files touched | Effort |
|---|---|---|---|
| **A** Add MITRE projection in 1 RA report | Pilot — `Device_Recommendations_Detailed` only. Adds 2 cols + URL formatter. | 1 YAML + 1 engine helper | ~30 min |
| **B** Roll MITRE across all `Device_*` reports | Same pattern, 8 reports | 1 YAML edit per report | ~1 hr |
| **C** Add 4 EG signals to Endpoint Profile (`MsCriticalityLevel`, `MachineRiskState`, `IsCompromisedRecently`, `IsProductionEnvironment`) | Schema + builder + DCR re-provision | 2 files; bootstrap re-runs DCR | ~1 hr |
| **D** Add new RiskFactor_Probability tokens (Defender AV, OnboardingStatus, ExclusionReason, DeviceManagementType) | Engine `Get-SIRiskFactors.ps1` adds emit logic | 1 file | ~1 hr |
| **E** Add `Defender_Alert_Active` + `Defender_Alert_Count_30d` (new source) | New AlertEvidence pull in Stage Enrich + new RA columns | 2 engine files + per-report YAML | ~3 hr |
| **F** Roll SigninLogs enrichment across Identity reports | Per-report YAML extends — 6 reports | 6 YAML edits | ~2 hr |
| **G** Auto-generate Portal URLs based on row Asset* fields | Engine `MoreDetails` enrichment block extension | 1 engine file | ~1 hr |

**Total to ship the whole model:** ~10 hours of coding spread across schemas, engine, YAMLs.

### F. Suggested incremental rollout

1. **First commit** — Tier A + Tier G (MITRE pilot + Portal URLs). Visible win in `Device_Recommendations_*` and immediate utility (every row gets clickable portal links).
2. **Second commit** — Tier C (EG signals to schema). Bootstrap re-runs DCR; new columns visible in next RA run.
3. **Third commit** — Tier D (RiskFactor_Probability tokens for AV / Onboarding / Mgmt).
4. **Fourth commit** — Tier B + Tier F (mass-roll MITRE across Device_* + SigninLogs enrichment across Identity_*).
5. **Fifth commit** — Tier E (AlertEvidence — new source, biggest scope).

This sequence puts the highest-visibility, lowest-risk changes first and defers the biggest scope (new source table) to last.

### G. What's NOT in this model (deliberate exclusions)

- **CVE description / scoring** — already covered by existing `CVSSDesc` + `HasExploit` / `IsExploitVerified` / `IsZeroDay` / `IsInExploitKit` columns.
- **Tier-driving signals** — per the `feedback_si_ra_tier_source` memory: tier ALWAYS sources from `SI_*_Profile_CL.Tier`, never from EG `criticalityLevel`. We surface MS criticality as a comparison column (`MsCriticalityLevel`) but don't use it to derive `Tier`.
- **Per-report bespoke columns** — keep each report's column shape predictable; reports that don't have a signal emit empty.
- **Bidirectional updates** — read-only consumption of source tables. Never write back to MDE / Entra / EG (per the `feedback_si_v22_readonly` memory).

---

## MDE / ExposureGraph field-gap audit

**Scope.** Built-in Defender XDR + Entra Log Analytics tables actually referenced by the v2.2 RA queries. Custom `SI_*_CL` tables are out of scope (they're our own).

**Goal.** Identify high-value fields that exist in Microsoft built-in tables but are **not currently** projected into our Profile_CL schemas or surfaced in RA report rows / `MoreDetails`. Read-only research — no code changes implied by this section.

**Method.** Grep'd `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` + the Endpoint/Azure Profile builders + the schema JSONs for which fields are currently in use. Cross-referenced against documented MDE / Exposure Graph schemas.

### 0. Inventory of built-in tables actually referenced

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

### 1. `DeviceInfo` (MDE)

#### Currently projected into `SI_Endpoint_Profile_CL`

The Endpoint Profile builder (`Build-EndpointProfileRow.ps1`) maps **57 `MDE_*`** fields. The schema (`endpoint.schema.locked.json`, 186 columns total) exposes most as **unprefixed** column names. Coverage is **strong** — including IsExcluded, IsInternetFacing, OnboardingStatus, JoinType, Model, Vendor, DefenderAvStatus, EdrMode, LoggedOnUsers, etc.

#### Available in `DeviceInfo` but NOT in current Profile_CL

| MDE field | Type | Why valuable | Suggested Profile column |
|---|---|---|---|
| `IsAzureADJoined` (raw) | bool | `IsAzureADJoined` IS exposed; verify population | already mapped — verify |
| `OSDistribution` | string | Linux distro (Ubuntu / RHEL / etc.) — currently rolled up under OsPlatform | `OsDistribution` |
| `DeviceObjectId` | string | The Entra device object ID (not AAD device ID) — direct join key for Entra / CA reports | `EntraDeviceObjectId` |
| `AdditionalFields` | dynamic | Vendor-specific extras (BIOS version, secure-boot state) — varies by tenant | `MDE_AdditionalFields` (json passthrough) |
| `DeviceManagementType` | string | Intune / SCCM / unmanaged — drives "is-managed" risk factor | `DeviceManagementType` |
| `MdeMachineId` | string | Different from MdeDeviceId in some scenarios | `MdeMachineId` |

#### Available in `DeviceInfo` but NOT used in current RA queries (could enrich `MoreDetails`)

| MDE field | Why valuable for MoreDetails |
|---|---|
| `OnboardingStatus` | Distinguishes Onboarded vs Insufficient info vs Can be onboarded. Rows surfacing as "needs MDE coverage" are easy to action. |
| `ExposureLevel` | "Low" / "Medium" / "High" — a Defender-computed verdict. Could feed `RiskFactor_Probability_Detailed`. |
| `IsExcluded` + `ExclusionReason` | An asset excluded from MDE enforcement is a known risk. Surface in MoreDetails for visibility. |
| `DefenderAvStatus` + `DefenderAvMode` + `SensorHealthState` | If AV is Disabled/Outdated, that's a probability-amplifier for any vulnerability finding. |
| `LoggedOnUsers` | Per-row "who was on this device when?" — operationally useful for ticket assignment. |

### 2. `DeviceTvmSecureConfigurationAssessment` (MDE)

#### Currently projected

Just join-keys: `DeviceId`, `ConfigurationId`, `IsApplicable`, `IsCompliant`, `ConfigurationImpact`, `Timestamp`. The KB join provides the human-readable enrichment.

#### Available but NOT used

| Field | Why valuable |
|---|---|
| `ConfigurationCategory` (raw) | KB has a synthesized one — but per-device value can differ |
| `ConfigurationSubcategory` | Same — slight precision gain |
| `IsExpectedUserImpact` | Boolean: "fixing this will produce visible user friction". Material for change-window prioritization. |
| `RecommendedFixId` | Stable ID — useful as a join key to track remediation programs over time |
| `Context` (`AdditionalFields` if present) | Per-device context (e.g. policy GUID applied) |

### 3. `DeviceTvmSecureConfigurationAssessmentKB` (MDE) — biggest gap

#### Currently projected

`KB_RiskDescription`, `KB_Description`, `KB_Remediation`, `KB_ConfigurationName`, `KB_ConfigurationCategory`, `KB_ConfigurationSubcategory`, `KB_Impact`. Lifted as `RiskDescription` / `Remediation` etc. into RA rows.

#### Available but UNUSED — high-value gap

| Field | Type | Why valuable | Where to surface |
|---|---|---|---|
| **`RelatedMitreTactics`** | dynamic (string array) | Maps each finding to MITRE ATT&CK tactics (e.g. `["TA0006:Credential Access"]`). **Zero current usage** in v2.2. | `MITRE_Tactics` column on row + `MoreDetails` link to `https://attack.mitre.org/tactics/<id>/` |
| **`RelatedMitreTechniques`** | dynamic (string array) | Same for techniques (e.g. `["T1003:OS Credential Dumping"]`). **Zero current usage**. | `MITRE_Techniques` column + per-technique URL in `MoreDetails` |
| **`Tags`** | dynamic | Topical tags (CIS, NIST, ISO27001, PCI). Quick framework filter. | `ComplianceTags` column |
| **`ConfigurationBenchmarks`** | dynamic | Explicit benchmark-control mapping (e.g. `["CIS Windows Server 2019 1.1.1"]`). Used 5x in YAML — could be expanded. | `Benchmarks` column on row |

**MITRE alone** would substantially upgrade the `Device_Recommendations_*` reports — every row could link to attack.mitre.org with the relevant tactic/technique.

### 4. `ExposureGraphNodes` (Defender XDR / Exposure Mgmt)

#### Currently projected

Endpoint side: `EG_AadDeviceId`, `EG_IsCustomerFacing`, `EG_IsExcluded`, `EG_AssetLabel` (= `NodeLabel`).

Azure side: **80 `EG_*` fields** in `azure.schema.locked.json` — comprehensive per-resource-type properties (ACR_*, AGW_*, AOAI_*, KV_*, SQL_*, ST_*, etc.).

#### Available in `NodeProperties.rawData` but NOT projected

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

#### What we DO use in queries: only 4 of these (`aadDeviceId`, `isCustomerFacing`, `isExcluded`, `deviceCategory`)

Adding the gap fields above to the **Endpoint Profile builder** + **Endpoint Profile schema** would make them queryable from RA without modifying the EG-primary RA pattern itself.

### 5. `ExposureGraphEdges` (Defender XDR)

#### Currently projected

`SourceNodeId`, `TargetNodeId`, `EdgeLabel`, `EdgeProperties` (passthrough) — used heavily in attack-path queries.

#### Available but underused

| Field | Why valuable |
|---|---|
| `EdgeProperties.<various>` | Edge-level metadata (e.g. for `canAuthenticateAs` edges: which auth method, which token TTL) — currently passed through as opaque JSON; no per-property extraction. |

Limited additional surface here — edge data is already used heavily.

### 6. `SigninLogs` + `AADNonInteractiveUserSignInLogs` (Entra / LA)

#### Currently projected

Mostly: `UserPrincipalName`, `IPAddress`, `Location`, `NetworkLocationDetails.networkType` (for trustedNamedLocation check), `TimeGenerated`. Aggregated as count + dcount.

#### Available but UNUSED — significant gap

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

#### Highest-value additions for the Identity reports

If you could only add 5 columns:

1. `DeviceDetail.IsCompliant` (per-signin compliance)
2. `RiskLevelDuringSignIn` + `RiskEventTypes_V2` (Entra ID Protection signals)
3. `ConditionalAccessStatus` (was MFA actually required this signin?)
4. `AuthenticationRequirement` (what factor was used?)
5. `HomeTenantId != ResourceTenantId` (cross-tenant pattern)

These would substantially upgrade the `Identity_PrivilegedUser_SignIn_*` and `Identity_BreakGlass_*` reports.

### 7. Suggested next-action priority

If you want to act on this audit (separate work):

#### Tier 1 — high impact, low scope (one-shot file edits)

1. **Project MITRE tactics + techniques** from `DeviceTvmSecureConfigurationAssessmentKB` into `Device_Recommendations_*` rows. Add 2 columns + per-row MoreDetails URL formatter. Touches: 1 YAML file (KB join), 0 schema changes (RA-only column).
2. **Surface `OnboardingStatus`, `ExposureLevel`, `DefenderAvStatus`, `SensorHealthState`** in MoreDetails for `Device_*` reports. Already in Profile_CL — just KQL projection in RA YAML.
3. **Add EG `criticalityLevel`** to Endpoint Profile_CL as `EG_MsCriticalityLevel` — Microsoft's own asset criticality, useful as a comparison column even if we don't drive tier from it (per `feedback_si_ra_tier_source` memory).

#### Tier 2 — medium impact, broader scope (schema + builder updates)

4. **Add EG signals to Endpoint Profile_CL**: `HasInternetExposureSignal`, `IsCompromisedRecently`, `MachineRiskState`, `IsProductionEnvironment`. Touches: `endpoint.schema.locked.json` (4 new columns), `Build-EndpointProfileRow.ps1` (4 mapping entries), DCR re-provision on next bootstrap.
5. **Project `DeviceDetail.*` from SigninLogs** into the identity sign-in reports. Adds 3-4 columns to `Identity_*_SignIn_*` reports + Risk_Probability_Detailed enrichment when `RiskLevelDuringSignIn != "none"`.

#### Tier 3 — high impact, significant scope (new tables)

6. **Add `IdentityInfo` as a source** — currently we synthesize identity profile from Entra Graph + EG; `IdentityInfo` is Defender's own consolidated view (department, manager, account creation date, IsEnabled). Currently zero usage.
7. **Add `AlertEvidence` for cross-correlation** — every RA finding could carry "any active alerts referencing this asset?" as a `RiskFactor_Probability_Detailed` entry (`HasActiveDefenderAlert`).
8. **Add `DeviceTvmSoftwareVulnerabilities` + `KB`** — currently we use `DeviceTvmSecureConfigurationAssessment` for misconfigurations. The vulnerability table has CVE-level data including `IsExploitVerified`, `IsInExploitKit`, `IsZeroDay` (currently we get these elsewhere — verify completeness).

### Summary

| Source table | Fields exposed in Profile_CL today | High-value gaps |
|---|---|---|
| `DeviceInfo` | ~57 (good coverage) | `OSDistribution`, `DeviceObjectId`, `DeviceManagementType` |
| `DeviceTvmSecureConfigurationAssessment` | 5 (join keys) | `IsExpectedUserImpact`, `RecommendedFixId` |
| `DeviceTvmSecureConfigurationAssessmentKB` | 6 (descriptions) | **`RelatedMitreTactics`, `RelatedMitreTechniques`, `Tags`** |
| `ExposureGraphNodes` | 4 endpoint-side; 80 azure-side | **`hasInternetExposureSignal`, `criticalityLevel`, `isCompromisedRecently`, `machineRiskState`, `isProductionEnvironment`, `isAdfsServer`, `dnsNames`** |
| `ExposureGraphEdges` | All used | none material |
| `SigninLogs` / `AADNonInteractiveUserSignInLogs` | 5–6 (basic) | **`DeviceDetail.IsCompliant`, `RiskLevelDuringSignIn`, `RiskEventTypes_V2`, `ConditionalAccessStatus`, `AuthenticationRequirement`** |

**Biggest unrealized value:** MITRE mapping (zero current use), EG `criticalityLevel` + `isCompromisedRecently` (Microsoft-computed risk signals we ignore), and SigninLogs `DeviceDetail` + `RiskLevelDuringSignIn` (Entra ID Protection signals we don't surface).

---

## Power BI dashboard

This describes the `.pbix` built **once** in Power BI Desktop. Once saved, the Step 4 launcher deploys the same `.pbix` to every customer's Power BI tenant fully automatically.

### Parameters (set at `.pbix` open time)

Customers get prompted for these on first open. The Step 4 launcher patches them via the REST API on upload.

| Parameter name | Type | Example |
|---|---|---|
| `LA_WorkspaceId` | Text | `<workspace-guid>` (LA Workspace ID, GUID only — not the Resource ID) |
| `LA_TenantId` | Text | `<tenant-guid>` |
| `StalenessDays` | Decimal nbr | `30` |
| `TopNFindings` | Decimal nbr | `25` |

In Power BI Desktop:

1. **Transform data → Manage parameters → New Parameter** for each.
2. For every KQL query, `Home → Advanced Editor →` replace the hard-coded workspace GUID with `Source = AzureDataExplorer.Contents("https://ade.loganalytics.io/subscriptions/.../workspaces/" & LA_WorkspaceId, ...)` — or use the Azure Monitor Logs connector and set the workspace via the parameter.

### Data model

Eight queries, all powered by KQL against the customer's LA workspace:

| Table name | KQL file | Grain |
|---|---|---|
| `RiskSummary` | `queries/01-RiskAnalysis-Summary-LatestRun.kql` | One row per TraceID at latest CollectionTime |
| `RiskSummaryTrend` | `queries/02-RiskAnalysis-Summary-Trend.kql` | One row per (CollectionTime, TraceID) |
| `NewVsResolved` | `queries/03-RiskAnalysis-NewVsResolved-PerRun.kql` | One row per CollectionTime |
| `TopN` | `queries/04-RiskAnalysis-TopN-CurrentRun.kql` | One row per TraceID (top-N only) |
| `Stale` | `queries/05-RiskAnalysis-StaleFindings.kql` | One row per TraceID (long-open) |
| `TenantTrend` | `queries/06-RiskAnalysis-RiskScoreTrend-Aggregated.kql` | One row per CollectionTime |
| `DomainTrend` | `queries/07-RiskAnalysis-BySecurityDomain-Trend.kql` | One row per (CollectionTime, SecurityDomain) |
| `IdentityLatest` | `queries/08-IdentityAssets-LatestCollection.kql` | One row per identity (latest collection) |

Load all eight as separate queries. No relationships are strictly required — each table answers a different question. Optional: relate `RiskSummary[TraceID]` → `Stale[TraceID]` and `RiskSummary[TraceID]` → `RiskSummaryTrend[TraceID]` for drill-through.

### Measures

Paste every line from `measures.dax` into **Modeling → New measure**.

Key ones to expose on the canvas:

- `Total Risk Score (Latest)`
- `Risk Score Delta % vs Prev Run`
- `Open Findings (Latest)`
- `Critical Findings (Latest)`
- `New Findings (Latest Run)` / `Resolved Findings (Latest Run)` / `Net Finding Movement`

### Page layout

Three pages. Design for a 16:9 exec deck (1920x1080) so screenshots look good.

#### Page 1 — Executive summary

```
+----------------------------------------------------------------------------------+
|  SecurityInsight — Risk Overview                        Last run: {CollectionTime}|
+----------------------------------------------------------------------------------+
| [ Total Risk  ] [ Open         ] [ Critical     ] [ Δ vs prev    ]              |
| [   Score     ] [ Findings     ] [ Findings     ] [ run (%)      ]              |
| [   1,234     ] [   87         ] [   12         ] [   -8.4%  ↓   ]              |
+----------------------------------------------------------------------------------+
|                                                                                  |
|     Total risk score over time (line chart, TenantTrend[CollectionTime] vs      |
|     TenantTrend[TotalRiskScore])                                                |
|                                                                                  |
+----------------------------------------------------------------------------------+
|  Risk by SecurityDomain over time (stacked area, DomainTrend)                   |
+----------------------------------------------------------------------------------+
```

**Cards:** `Total Risk Score (Latest)`, `Open Findings (Latest)`, `Critical Findings (Latest)`, `Risk Score Delta % vs Prev Run`.

**Line chart:** X = `TenantTrend[CollectionTime]`, Y = `TenantTrend[TotalRiskScore]`.

**Stacked area:** X = `DomainTrend[CollectionTime]`, Y = `DomainTrend[DomainRiskScore]`, Legend = `DomainTrend[SecurityDomain]`.

#### Page 2 — Top findings (operational)

```
+----------------------------------------------------------------------------------+
| Slicer: SecurityDomain / SecuritySeverity / CriticalityTier                     |
+----------------------------------------------------------------------------------+
|                                                                                  |
|     Top 25 findings by risk score (table, TopN)                                 |
|     Columns: TraceName | Severity | Tier | RiskScore | Assets | Issues         |
|                                                                                  |
+----------------------------------------------------------------------------------+
|     Velocity (combo chart, NewVsResolved)                                       |
|     Bars = New (green) / Resolved (blue) per CollectionTime                     |
|     Line  = Net movement                                                         |
+----------------------------------------------------------------------------------+
```

#### Page 3 — Stale findings (chase list)

```
+----------------------------------------------------------------------------------+
|  Findings open for 30+ days (table, Stale sorted by DaysOpen desc)              |
|  Columns: TraceName | Config | Severity | FirstSeen | DaysOpen | MaxRiskScore   |
|                                                                                  |
|  Click a row → drill-through to RiskSummaryTrend filtered by TraceID            |
+----------------------------------------------------------------------------------+
|  Drill-through page: line of RiskScoreTotal vs CollectionTime for the clicked   |
|  TraceID. Shows the history of ONE finding over time.                           |
+----------------------------------------------------------------------------------+
```

### Colour + formatting

- **Severity palette** (use a calculation group or conditional formatting on `SecuritySeverity`):
  - `Very High` / `Critical` → `#A83275` (danger pink)
  - `High` → `#E57373` (muted red)
  - `Medium` → `#B07A00` (amber)
  - `Low` → `#1A7A1A` (green)
- **CriticalityTier palette:**
  - `Tier 0` → `#0D1117` (near-black)
  - `Tier 1` → `#2A6592` (accent blue)
  - `Tier 2` → `#656D76` (muted grey)
- Dates formatted `yyyy-MM-dd HH:mm UTC` so customers can't misinterpret timezones.

### Save → ship

1. **File → Save as → `SecurityInsight-RiskAnalysis.pbix`** in `SOLUTIONS\SecurityInsight\TOOLS\PowerBI\`.
2. **File → Export → Power BI template (`.pbit`)** to the same folder.
3. Commit both to the monorepo. The Step 4 launcher uploads the `.pbix`; the `.pbit` is the "customer-edits-a-copy" artefact for offline tinkering.

That's the one-time Desktop work. Once the `.pbix` is in the monorepo, every new customer onboarding just runs Step 4 and the dashboard lands in their Power BI tenant automatically.

---

## Container & KEDA deployment

End-to-end recipe for a **VM-less** SecurityInsight install: everything runs as Azure Container App Jobs (ACR image + KEDA-scaled per-engine jobs). No launcher VM required. This is the procedure used for `rg-<suffix>` (Community flavour).

### 1. Prerequisites (one-time)

| Requirement | Notes |
|---|---|
| Azure subscription with Owner / RBAC Admin | Needed to grant SPN RBAC and create Container Apps Env + ACR |
| Tenant Global Admin (or Privileged Role Admin) | For `New-SISpn` Graph admin-consent step |
| `az` CLI installed | `Bootstrap-ContainerAppJob` shells out to `az acr build` |
| `Az` PowerShell + `Microsoft.Graph` modules | PS 5.1 or pwsh 7 |
| Key Vault `kv-<suffix>` in target RG | Pre-create with **RBAC mode** (modern default); operator must have `Key Vault Administrator` on it |

Pre-create the KV:

```powershell
function global:New-Guid { [System.Guid]::NewGuid() }   # PS 5.1 shim
New-AzKeyVault -VaultName 'kv-<suffix>' `
               -ResourceGroupName 'rg-<suffix>' `
               -Location 'westeurope' `
               -Sku Standard `
               -EnablePurgeProtection `
               -SoftDeleteRetentionInDays 7
# Operator RBAC
$me = (Get-AzADServicePrincipal -ApplicationId (Get-AzContext).Account.Id).Id
New-AzRoleAssignment -ObjectId $me `
                     -RoleDefinitionName 'Key Vault Administrator' `
                     -Scope (Get-AzKeyVault -VaultName 'kv-<suffix>').ResourceId
```

### 2. Author `config/setup-unattended.json`

Copy `config/setup-unattended.sample.json` → `config/setup-unattended.json` and edit. Minimum **cloud-only Community + Container** shape:

```jsonc
{
  "Flavour": "Community",
  "Sub": {
    "TenantId":       "<tenant-guid>",
    "SubscriptionId": "<sub-guid>",
    "Location":       "westeurope"
  },
  "Resources": {
    "ResourceGroupName":  "rg-<suffix>",
    "WorkspaceName":      "log-<suffix>",
    "DceName":            "dce-<suffix>",
    "StorageAccountName": "st<suffix>",
    "NamingSuffix":       null
  },
  "Auth_Community": {
    "DisplayName":  "sp-securityinsight",
    "CredKind":     "Secret",
    "CredStorage":  "KeyVault",
    "KeyVaultName": "kv-<suffix>"
  },
  "Container": {
    "Enabled":         true,
    "AcrName":         "acr<suffix>",
    "EnvName":         "cae-<suffix>",
    "UseKEDA":         true,
    "KedaMaxReplicas": 30
  }
}
```

Storage account names must be ≤24 chars, lowercase alphanumeric. Workspace and DCE names follow the standard rules.

### 3. Run the unattended deploy

Two ways to call `Setup-SecurityInsight-Unattended.ps1`:

#### A. Interactive Community (browser auth) — the original path

```powershell
Connect-AzAccount -Tenant <tenant> -Subscription <sub>
Connect-MgGraph   -TenantId <tenant>
az login --tenant <tenant>
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled
```

#### B. Non-interactive Community (reuse existing SPN context) — container-test path

Pre-connect Az PS + Mg Graph + az CLI with any high-privilege SPN, then call the unattended script with no extra flags. The script's Community block now detects an existing matching Az+Mg context and reuses it.

```powershell
function global:New-Guid { [System.Guid]::NewGuid() }
Import-Module 'C:\SCRIPTS\AutomateIT\FUNCTIONS\AutomateITPS\AutomateITPS.psd1' -Force
Connect-Platform  # connects Modern SPN to Az + Mg via the v1 KV

az login --service-principal --tenant $global:AzureTenantId `
         --username $global:HighPriv_Modern_ApplicationID_Azure `
         --password $global:HighPriv_Modern_Secret_Azure --output none
az account set --subscription '<sub-guid>'

cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled
```

The script runs 5 phases:

| Phase | Cmdlet | What it does |
|---|---|---|
| 1 | `New-SISpn` | Creates/reuses SPN + rotates client secret + grants Graph/MTP/MDE perms + tenant-root Reader RBAC + stores secret in KV |
| 2 | `Initialize-SIInfra` | Log Analytics workspace + DCE + Storage account + DCR per Profile table + RBAC for SPN |
| 2.5 | (Internal only) | Seed v1 KV with `SI-Shodan-ApiKey` + `OpenAI-ApiKey` |
| 3 | `Write-SICustomConfig` | Renders `config/SecurityInsight.custom.ps1` (Community = inline values) |
| 4 | `Set-SIEntraDiagnosticSetting` | Skipped unless `EntraDiag.Enabled = true` |
| 5 | `Initialize-SIContainerInfra` | Provisions ACR, builds image via `az acr build`, creates Container Apps Env, creates 1-2 jobs per engine, sets up KEDA queue scalers |

End state: 1 ACR + 1 CAE + per-engine Container App Jobs in the RG.

### 4. Jobs created (KEDA mode, default)

Each engine gets two jobs (except the two RA jobs, which are single-replica report builds):

| Engine | Producer (cron-triggered) | Worker (KEDA queue-scaled) | Default cron (UTC) |
|---|---|---|---|
| endpoint | `caj-si-endpoint-producer` | `caj-si-endpoint-worker` | 04:00 daily |
| identity | `caj-si-identity-producer` | `caj-si-identity-worker` | 04:30 daily |
| azure | `caj-si-azure-producer` | `caj-si-azure-worker` | 05:00 daily |
| schema-discovery | `caj-si-schema-discovery-producer` | `caj-si-schema-discovery-worker` | 03:00 every Sunday |
| risk-analysis (Summary) | `caj-si-risk-analysis` (single, no worker) | — | 06:00 daily |
| risk-analysis (Detailed) | `caj-si-risk-analysis-detailed` (single, no worker) | — | 08:00 daily |
| privilege-tier-classifier | `caj-si-ptc-producer` | `caj-si-ptc-worker` | 04:00 daily |
| publicip | `caj-si-publicip-producer` | `caj-si-publicip-worker` | 04:00 daily |

**Why two RA jobs?** Summary is the daily exec-friendly roll-up (small, ~1–10K rows). Detailed is the per-asset finding inventory the SecOps team actually drills into (much larger, ~100K+ rows). Both share the same engine + image; they differ only in `SI_RA_MODE` env (`Summary` vs `Detailed`) and `SI_RA_REPORT_TEMPLATE` (`RiskAnalysis_Summary` vs `RiskAnalysis_Detailed_Bucket`). Detailed runs 2h after Summary so the LA workspace isn't double-loaded.

The producer drops shard messages onto `si-<engine>-shards` Storage Queue. KEDA scales the worker from 0 to `KedaMaxReplicas` (default 30) based on queue depth, then scales back to zero when the queue drains.

### 5. How to **start** a job manually (no waiting for cron)

```powershell
# Start one engine right now
az containerapp job start --name caj-si-endpoint-producer --resource-group rg-<suffix>
az containerapp job start --name caj-si-risk-analysis    --resource-group rg-<suffix>

# Or via PowerShell wrapper
Invoke-AzRestMethod -Method POST `
  -Path "/subscriptions/<sub>/resourceGroups/rg-<suffix>/providers/Microsoft.App/jobs/caj-si-endpoint-producer/start?api-version=2024-03-01"
```

For a full Profilers + RA chain (run in order, wait between):

```powershell
$rg = 'rg-<suffix>'
foreach ($e in 'endpoint','identity','azure','publicip') {
    az containerapp job start --name "caj-si-$e-producer" --resource-group $rg
}
# wait until the worker queues drain (see § 6), then:
az containerapp job start --name 'caj-si-ptc-producer'             --resource-group $rg
az containerapp job start --name 'caj-si-risk-analysis'            --resource-group $rg   # Summary
az containerapp job start --name 'caj-si-risk-analysis-detailed'   --resource-group $rg   # Detailed
```

### 6. How to **monitor** an execution

```powershell
# List recent executions of a job
az containerapp job execution list --name caj-si-endpoint-worker --resource-group rg-<suffix> --query '[].{name:name, status:properties.status, started:properties.startTime}' -o table

# Stream logs of latest execution
$exec = az containerapp job execution list --name caj-si-endpoint-worker --resource-group rg-<suffix> --query '[0].name' -o tsv
az containerapp job logs show --name caj-si-endpoint-worker --resource-group rg-<suffix> --execution $exec --container caj-si-endpoint-worker --follow

# Queue depth (drives KEDA scale-up)
az storage message peek --queue-name si-endpoint-shards --account-name st<suffix> --num-messages 5 --auth-mode login
```

In Log Analytics:

```kql
ContainerAppConsoleLogs_CL
| where ContainerAppName_s startswith "caj-si-"
| order by TimeGenerated desc
```

### 7. How to **change the schedule**

Two paths. Both are no-rebuild — the cron lives on the Container App Job, not in the image.

#### A. Edit `config/SecurityInsight.custom.ps1` then re-run Bootstrap

Set any of these globals (all are pure cron strings, UTC):

```powershell
$global:SI_Bootstrap_ScheduleEndpoint             = '0 */6 * * *'   # every 6h
$global:SI_Bootstrap_ScheduleIdentity             = '15 */6 * * *'
$global:SI_Bootstrap_ScheduleAzure                = '30 */6 * * *'
$global:SI_Bootstrap_ScheduleRiskAnalysis         = '0 6 * * *'     # 06:00 UTC daily Summary
$global:SI_Bootstrap_ScheduleRiskAnalysisDetailed = '0 8 * * *'     # 08:00 UTC daily Detailed
$global:SI_Bootstrap_ScheduleSchemaDiscovery      = '0 3 * * 0'
```

Then re-run the bootstrap (it's idempotent; only touches the cron field on existing jobs):

```powershell
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Bootstrap-ContainerAppJob.ps1
```

#### B. One-off `az` update on a single job

```powershell
az containerapp job update --name caj-si-endpoint-producer --resource-group rg-<suffix> --cron-expression "0 */4 * * *"
```

#### Disable a schedule (run only on demand)

```powershell
az containerapp job update --name caj-si-risk-analysis --resource-group rg-<suffix> --cron-expression ""
```

(blank cron disables auto-trigger; `az containerapp job start` still works)

### 8. How to **scale up** under load

KEDA scales workers based on queue depth. Adjust the cap:

```powershell
az containerapp job update --name caj-si-endpoint-worker --resource-group rg-<suffix> --max-executions 60
```

Or globally on next bootstrap:

```powershell
$global:SI_Bootstrap_KedaMaxReplicas = 60
.\Bootstrap-ContainerAppJob.ps1
```

### 9a. How PowerShell modules are pre-staged in the image

`container/Dockerfile` has one `RUN pwsh ... Install-Module -RequiredVersion ...` layer that installs every module the engines need, pinned to exact versions:

```dockerfile
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04
RUN pwsh -NoProfile -Command \
    "Install-Module -Name Az.Accounts            -RequiredVersion 5.4.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Resources           -RequiredVersion 9.0.3 -Force -Scope AllUsers; \
     Install-Module -Name Az.Storage             -RequiredVersion 9.6.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.Monitor             -RequiredVersion 7.0.0 -Force -Scope AllUsers; \
     Install-Module -Name Az.ResourceGraph       -RequiredVersion 1.2.1 -Force -Scope AllUsers; \
     Install-Module -Name Az.OperationalInsights -RequiredVersion 3.4.0 -Force -Scope AllUsers; \
     Install-Module -Name powershell-yaml        -RequiredVersion 0.4.12 -Force -Scope AllUsers; \
     Install-Module -Name AzLogDcrIngestPS       -MinimumVersion 1.7.0 -Force -Scope AllUsers; \
     Install-Module -Name ImportExcel            -RequiredVersion 7.8.10 -Force -Scope AllUsers"
COPY . /app/
ENTRYPOINT ["pwsh","-NoProfile","-File","/app/container/Start-SIInContainer.ps1"]
```

**Why pinned:** every container in every customer tenant runs the same binary surface. Drift between Dockerfile and PSGallery latest is the #1 source of "works locally, breaks in container" bugs.

**Maintenance via `container/Sync-ContainerModules.ps1`** — unattended, scriptable:

```powershell
# Audit only — no writes; prints current pin vs PSGallery latest for each
.\container\Sync-ContainerModules.ps1 -Audit

# Bump only one module (security patch)
.\container\Sync-ContainerModules.ps1 -BumpModule @{ 'ImportExcel' = '7.8.11' } `
                                       -Build -Roll `
                                       -AcrName acr<suffix> -ResourceGroupName rg-<suffix>

# Bump everything to latest, rebuild image, roll all caj-si-* jobs (monthly)
.\container\Sync-ContainerModules.ps1 -BumpAll -Build -Roll `
                                       -AcrName acr<suffix> -ResourceGroupName rg-<suffix>
```

What the script does, in order:

1. Parse `container/Dockerfile` for `Install-Module -RequiredVersion` lines.
2. Query PSGallery for the latest version of each — print the drift report.
3. (Optional) Apply `-BumpAll` or `-BumpModule` rewrites in place.
4. (Optional) `az acr build` the image with tag `yyyyMMddHHmm` AND `latest`.
5. (Optional) `az containerapp job update --image` on every `caj-si-*` job in the RG so they all pick up the new tag.

In-flight job executions finish on the old image; the next trigger pulls the new one. **No downtime.**

**Drift policy (encoded in the script's help block):**

| Bump type | Auto-roll OK? | Action |
|---|---|---|
| Patch (z) | Yes | `-BumpAll -Build -Roll` directly |
| Minor (y) | After test | Bump + Build on a container-test deployment first, validate, then Roll customer RGs |
| Major (x) | After test | Same as minor; expect breaking-change surface |
| `AzLogDcrIngestPS` | Owner-controlled | **Not pinned — `Ensure-Module.ps1` lists it in `-KeepLatest`, so every engine run probes PSGallery and installs a newer version; `-MinimumVersions` holds a hard floor (`1.6.7`) that fails fast instead of surfacing a confusing "parameter not found".** ⚠️ **v1.7.0 (2026-08-26) is the floor that matters in practice** — below it, ingest data-shaping costs ~1.360s instead of ~24s at 6,339×299, and any column the module has to rename is written with a `$null` value (audit #66). |

**CI hook (optional):** add a weekly scheduled action that runs `-Audit` and opens an issue if the drift count is non-zero. The repo's GitHub Actions already has the credentials for ACR; add a job calling the script with `-Audit` and grepping for `*` rows.

### 9b. How to update the image (after engine code change)

Two equivalent paths — both server-side via `az acr build`, both zero-downtime:

```powershell
# Path A: full bootstrap (also reconciles cron, env vars, KEDA caps)
cd C:\SCRIPTS\AutomateIT\SOLUTIONS\SecurityInsight
.\Bootstrap-ContainerAppJob.ps1

# Path B: image-only roll (faster — skips KEDA/cron reconcile, just rebuilds + rolls)
.\container\Sync-ContainerModules.ps1 -Build -Roll `
    -AcrName acr<suffix> -ResourceGroupName rg-<suffix>
```

Path B is the right one when only engine code changed (no Dockerfile / module bump). Path A is the right one when the change also touches cron, env vars, KEDA caps, or any param exposed via `$global:SI_Bootstrap_*`.

### 9c. How the entrypoint dispatcher works (SI_ROLE)

Every job in the fleet uses the **same** Dockerfile ENTRYPOINT (`pwsh -NoProfile -File /app/container/Start-SIInContainer.ps1`). The script branches on `$env:SI_ROLE` at the very top:

| `SI_ROLE` | What runs | Set by Bootstrap on |
|---|---|---|
| `worker` | `Start-SIInContainer.ps1` continues to collection path | `caj-si-<engine>-worker` and legacy `caj-si-<engine>` |
| `producer` | dispatches to `Invoke-ShardProducer.ps1` | `caj-si-<engine>-producer` |
| `ra` | dispatches to `Start-RiskAnalysisInContainer.ps1` | `caj-si-risk-analysis` |

**Why not `--command`/`--args`?** The az CLI uses argparse `nargs='+'` for both, which stops consuming tokens at any leading-dash arg. PowerShell flags all lead with `-` (`-NoProfile`, `-File`), so `--args -NoProfile -File /app/...` gets parsed as `--args` (empty) plus unknown globals `-NoProfile -File`. The SI_ROLE env-var dispatch sidesteps this entirely — same ENTRYPOINT for every job, different code path inside.

### 10. Common issues

| Symptom | Fix |
|---|---|
| `Key Vault '<name>' not found` | Pre-create KV before running Setup. See § 1. |
| `New-Guid : The term 'New-Guid' is not recognized` | Az SDK's autorest path calls it in a constrained child runspace. Define the shim before any Az cmdlet — see § 3. |
| `az login (interactive) failed` | Container phase requires az CLI signed in. Pre-`az login` or pass SPN secret env vars. |
| `az acr build` fails with `denied: requested access to the resource is denied` | ACR admin user is disabled. Caller's SPN needs `AcrPush` on the registry. |
| Worker scale stuck at 0 | Queue isn't getting messages — check producer execution log for crash. |
| Engine throws `AuthorizationPermissionMismatch` on Storage | SPN missing `Storage Blob Data Contributor` on `st<suffix>` (Phase 2 should have granted it). |
| `Required global $global:SI_StorageKey is empty in ...custom.ps1` | **Engine side (v2.2.314+) doesn't need this** — OAuth-only enforced everywhere on the VM/launcher path. **Container side (`Bootstrap-ContainerAppJob.ps1`) still injects `--secrets si-storage-key=` for the KEDA queue scaler** because the scaler accepts only key auth (no OAuth scaler path yet). Workaround for now: fetch the key inline before invoking bootstrap — `$global:SI_StorageKey = (Get-AzStorageAccountKey -ResourceGroupName <rg> -Name <sa>)[0].Value`. Container-side OAuth refactor is queued (would require switching to a UAMI-on-CAJ KEDA scaler config). |
| `Required global $global:OpenAI_apiKey is empty in ...custom.ps1` | Community `Write-SICustomConfig` only emits the KV-pull line, not the 4 OpenAI globals. Workaround: set `$global:OpenAI_endpoint/_deployment/_apiVersion/_apiKey` inline before invoking bootstrap (same shape as `platform-defaults.ps1` OpenAI globals block). Long-term fix: bootstrap should treat OpenAI as optional when `$global:SI_EnableAI` is false. |
| Container App Job execution `Failed` with `-NoProfile -File` not recognised | Old bootstrap put `--command pwsh --args "-NoProfile ..."` per-job. argparse can't pass leading-dash strings as values. Fix: pull new image (SI_ROLE dispatcher landed in v2.3) AND re-run `Bootstrap-ContainerAppJob.ps1` so UPDATE clears stale `command/args`. |
| `caj-si-schema-discovery-*` jobs fail with no orchestrator | schema-discovery is a stage inside asset-profiling, not a standalone engine. Remove from `$Engines` (bootstrap default does this since the fix) and delete dangling jobs: `az containerapp job delete --name caj-si-schema-discovery-{producer,worker} --resource-group <rg> --yes`. |

### 11. Teardown

```powershell
# Stop all auto-runs, keep data
foreach ($e in 'endpoint','identity','azure','schema-discovery','risk-analysis','privilege-tier-classifier','asset-tagging','publicip') {
    az containerapp job update --name "caj-si-$e-producer" --resource-group rg-<suffix> --cron-expression "" 2>$null
    az containerapp job update --name "caj-si-$e"          --resource-group rg-<suffix> --cron-expression "" 2>$null
}

# Full delete
Remove-AzResourceGroup -Name rg-<suffix> -Force
```

---

## Preview channel & release model

**Status:** preview-only. Side-by-side with v2.1.x stable. No data migration. Customers opt in per-engine.
**First tag:** `v2.2.0-preview.1`
**Branch:** `preview/v2.2` (cut from `dev` at v2.1.214)
**Stable channel (`dev` / v2.1.x):** continues with bug fixes + small features only — no architectural changes.

### 1. Why a v2.2

v2.1 writes Defender asset tags as the source of truth. v2.2 inverts that: **zero footprint on the asset itself**, all state lives in our own LA tables + storage account. Same value (tier, classification, posture proofs) — none of the tag pollution, no clash with the customer's own tagging, works on assets Defender can't tag (Azure resources, on-prem-only servers).

### 2. Engine roster

| Engine | Scope | Status |
|---|---|---|
| **endpoint** | servers + workstations from MDE + EG + Intune | **build first** (proves framework) |
| **identity** | users + service accounts from Entra + MDI | refactor of v2.1 IdentityAssets onto v2.2 framework |
| **azure** | Azure resources via ARG + ARM | new |

All three share one framework. Engine = a folder with its own `catalog/`, YAML rules, AI prompts, and `<engine>_*_CL` table names. Adding a fourth engine later (network, SaaS, OT) = copy folder, fill in.

### 3. Pipeline (6 stages)

```
[0 Schedule] -> [1 Discover] -> [2 Collect] -> [3 Enrich] -> [4 Classify] -> [5 Output]
```

| # | Stage | Owns | Skip-gate |
|---|---|---|---|
| 0 | **Schedule** | tier-driven cadence (T0=4h, T1=24h, T3=7d, TE=30d) | — |
| 1 | **Discover** | enumerate in-scope assets, hand off shards to workers | — |
| 2 | **Collect** | source tables (MDE Device*, installed apps, OS/HW/owner/tags), write `<engine>_Metadata_CL`, compute `fp_meta` from vital props + existing tier checksum | if `fp_meta` unchanged AND prior tier still valid → write "revalidated" row, skip stages 3 + 4 |
| 3 | **Enrich** | "has-access-to" + sign-ins, locked + custom YAML KQL posture rules, external REST + external LA tables, write `<engine>_Enrichment_CL`, compute `fp_enrich` | if `fp_enrich` unchanged → reuse cached AI verdict, skip stage 4 |
| 4 | **Classify** | AI: ServiceName, ServiceType (WebApp/Intranet/ExchangeServer/...), effective tier + tier proofs, external-risk severity tags, grouping (ip / rg / sub / servername-pattern), write `<engine>_Classification_CL` | — |
| 5 | **Output** | sinks: LA (default), JSON, Excel, optional Microsoft Fabric Eventhouse | — |

**Risks live in the separate RiskAnalysis engine** — it joins back via `AssetId` against `<engine>_Classification_CL`. RA stays unchanged.

### 4. Skip model — fingerprints

Two fingerprints, two skip-gates. ~85% of endpoints day-to-day will have unchanged `fp_meta` AND `fp_enrich` → "revalidated" row only, zero AI spend.

```
fp_meta    = sha256(OS, owner, subnet, naming, hardware, mgmt-state, installed-apps-set)
fp_enrich  = sha256(logon-set, primary-user, posture-rule-hits, external-enrichment-output)
```

Cached verdict TTL (force re-judge after N days even if `fp_enrich` unchanged) is the safety net for prompt-template evolution.

Fingerprint cache: Azure Table Storage, `PartitionKey=AssetId`, `RowKey=current`, columns `fp_meta / fp_enrich / si_tier / si_verdict / verdict_expires_at / stable_run_count`.

### 5. Storage stack — one Azure Storage account

| Concern | Service | Layout | Approx cost @ 1M endpoints |
|---|---|---|---|
| Fingerprint cache (hot) | **Azure Table Storage** | `PartitionKey=AssetId, RowKey=current` | ~$5–10/mo |
| Stage payload staging (warm, intra-run handoffs across collector workers) | **Azure Blob (block blob, JSONL)** | `staging/{runId}/{stage}/shard-NNN.jsonl`, 7-day lifecycle rule | ~$30/mo |
| Worker coordination | **Azure Storage Queue** | one queue per stage, lease-based, 7-day TTL | <$1/mo |
| Query sink (default) | **Azure Log Analytics** | `<engine>_Metadata_CL`, `<engine>_Enrichment_CL`, `<engine>_Classification_CL` | LA ingest cost (per-customer existing) |

Output stage also supports **JSON file dump** (file system) and **Excel summary** as additional sinks. Optional Eventhouse sink for customers on Microsoft Fabric — see § 9.

Multi-writer-safe by design (each shard writes its own blob / its own `PartitionKey`). No locks.

### 6. Column-naming convention — source-prefixed

Every column carries its provenance in the prefix. Makes joins, debugging, and graph-edge extraction mechanical.

| Prefix | Source |
|---|---|
| `EG_*` | ExposureGraph |
| `MDE_*` | Defender for Endpoint |
| `MDI_*` | Defender for Identity |
| `INTUNE_*` | Microsoft Intune |
| `ENTRA_*` | Entra ID |
| `SHODAN_*` | Shodan (when external enrichment enabled) |
| `SI_*` | SecurityInsight-derived (tier, verdict, grouping, fingerprints) |

`AssetId` and `TimeGenerated` are unprefixed — they're the join keys.

Snapshot semantics: one row per asset per run; downstream queries use `arg_max(TimeGenerated, *) by AssetId`.

### 7. Asset Mapping YAML — replaces Critical Asset Tagging

Two folders per engine: `posture-rules-locked/<engine>/` (shipped) and `posture-rules-custom/<engine>/` (customer-owned, survives upgrades).

```yaml
Name: ExchangeServerDetection
AppliesTo: endpoint            # endpoint | identity | azure
ProofLabel: ServiceType=ExchangeServer
ProofWeight: 90                # 0-100, fed to Classify AI as confidence hint
Query: |
  DeviceTvmSoftwareInventory
  | where SoftwareVendor == "microsoft" and SoftwareName startswith "exchange_server"
  | distinct DeviceId
```

Many existing v2.1 Critical Asset Tag rules port over 1:1 — same KQL, just emitted as a `ProofLabel` row in Enrich rather than as a Defender tag.

### 8. AI cost ceiling

`$global:MaxAiSpendPerRun` (USD, soft cap) baked into Classify from preview.1. Run aborts Classify when reached, Output still writes a partial classification with `SI_Classify_Status='budget-capped'`. Operator sees it in the daily Excel summary.

### 9. Optional output sink — Microsoft Fabric Eventhouse

Customers already on Fabric can opt-in to an additional Output sink that writes the same `<engine>_Classification_CL` snapshots into a Fabric **Eventhouse**. Eventhouse is the managed Kusto/ADX engine inside Fabric; data physically lands as Delta Parquet in OneLake (ADLS Gen2 underneath), and the same files are reachable from Power BI, Spark, T-SQL endpoint, and Python without copies.

The win for customers who turn it on: native KQL **graph operators** (`make-graph`, `graph-match`, `graph-shortest-paths`) over the snapshots — no separate graph DB needed. Source-prefix column convention (§ 6) makes node/edge extraction mechanical.

For everyone else: LA remains the default sink. Eventhouse adds zero cost when not enabled.

**Deferred from preview.1:** Eventhouse sink implementation — lands in preview.2 once the snapshot shape is stable. preview.1 ships LA + JSON + Excel sinks.

### 10. Branch + build plan

| Phase | Deliverable |
|---|---|
| **A** | Framework scaffolding: `catalog/`, `posture-rules-locked/`, `findings-schema/`, fingerprint engine, storage adapters (Table / Blob / Queue), orchestrator skeleton |
| **B** | **Endpoint engine** end-to-end with LA + JSON + Excel sinks |
| **C** | **Identity engine** refactored onto v2.2 framework |
| **D** | **Azure engine** new |
| **E** | Optional **Eventhouse sink** for Fabric customers + first `make-graph` queries on snapshots |

External enrichment plug-ins (MS EASM, Shodan, etc.): architecture supports from Phase A, all disabled by default in preview.1.

### 11. Out of scope / explicitly NOT in v2.2

- Risk scoring (stays in RiskAnalysis engine; joins via `AssetId`)
- Tag-removal cleanup script (handled by user's own maintenance script)
- Migration tooling (side-by-side, no data move)
- Cosmos Gremlin / Neo4j (any future graph use rides Eventhouse's `make-graph` over the same snapshots)
- v2.1 architectural changes (stable channel = bug-fixes + small features only)

### 12. preview.1 contents

This commit ships:
- `PREVIEW.md` — this document
- `catalog/endpoint/MDE-DeviceLogonEvents.yaml` — sample source-table catalog entry
- `posture-rules-locked/endpoint/ExchangeServerDetection.yaml` — sample posture rule (Asset-Mapping-YAML schema in production form)
- `findings-schema/endpoint-classification.yaml` — stable schema contract for `Endpoint_Classification_CL`
- `Get-FingerprintEngine.ps1` — PS 5.1 fingerprint helper (used by Collect + Enrich stages)

No runnable orchestrator yet — preview.1 is design + contracts + one helper. Phase A code lands in preview.2.
---

## Delivery limits — what the run will trim, and how it tells you

> Added v2.2.441. Three places bound how much data leaves a run. **None of them is silent any more**:
> every one states what it dropped, because a limit an operator cannot see is indistinguishable from
> "that was all the data there was".

**The row path itself is uncapped.** No shipped report query limits rows (the only `take` statements
are `take 0` / `take 1` existence probes); `AssetLimit` defaults to `0 = no limit` and prints as such
in the config snapshot; whole-report dedup is disabled; and paged REST never discards pages it has
already collected. The per-row dedup that *does* drop rows only ever removes rows indistinguishable
across every column in its key, and it reports the count it removed.

| limit | default | behaviour |
|---|---|---|
| **Excel worksheet rows** | 1,000,000 (`$global:SI_ExcelMaxDataRows`) | A sheet holds 1,048,576 rows *including* the header. The workbook keeps the **top N by the sort column** — the cut is applied **after** the sort, so the highest-risk rows survive — and the warning names how many were left out. **Nothing is lost from the run:** the `.json` sibling and the Log Analytics ingest still carry every row. |
| **Mail attachment** | **24 MB of message** (`$global:SI_MaxMailAttachmentMB`) | Measured **base64-encoded**, which is how relays measure it: attachments inflate ~37%, so 24 MB of budget admits a workbook of roughly **17 MB on disk**, and an on-disk check would pass while the send still failed. Over budget the report is sent **without the attachment** and the body gives the file's location, so the summary always arrives. 🔑 **The default is sized for the RELAY, not for the report.** Most relays cap a message at 25 MB (Exchange Online's default; on-premises is often lower) and that cap covers the whole message — body and headers as well as the attachment — so 24 leaves about 1.7 MB of headroom. ⚠️ **Lowering it is always safe; raising it is only safe against a known relay limit**, because a budget above what the relay accepts means the relay rejects the *entire* message and the recipient loses the summary too — strictly worse than dropping the attachment alone. Raised to 34 in v2.2.458 and corrected to 24 in v2.2.459 for exactly that reason. Documented in the sample config (section 9) and the README so it is discoverable rather than reference-only |
| **MoreDetails cell** | 25 links, 4,000 chars | Both now state the remainder — `[+87 more link(s) not shown -- 112 total]` and `... [truncated at 4000 chars]`. A field larger than 4,096 chars is skipped during URL harvesting and the run reports how many fields it passed over. |

Two further caps announce themselves rather than trimming quietly: the schema-audit and tag-activity
rows sent to Log Analytics are capped (`$global:SI_SchemaAuditRowCap` / `$global:SI_TagActivityRowCap`,
default 50) and warn with the exact number not ingested; and the AI prompt's per-finding asset/link
slices carry `[+N more of M total]` so the model is never handed a partial list as if it were complete.

⚠️ **Outside SI's control:** `AzLogDcrIngestPS` performs its own row-size handling on ingest (the
256 KB `drop_largest_field` behaviour). SI does not audit or report that.

## Operations & runbook

> How to **monitor**, **diagnose**, and **right-size** SecurityInsight asset-profiling runs after they are deployed. This is for the operator after first run.

### Per-shard heartbeat — `SI_RunHealth_CL`

Every replica of `Invoke-SIEngineRun.ps1` writes two rows to `SI_RunHealth_CL` in the customer's Log Analytics workspace:

| Phase   | Emitted at        | Carries                                                           |
|---------|-------------------|-------------------------------------------------------------------|
| `Start` | top of run        | `RunId`, `Engine`, `ShardIndex`, `ShardCount`, `Computer`         |
| `End`   | `finally` block   | adds `AssetCount`, `PeakWorkingSetMB`, `DurationSec`, `ExitReason`, `ErrorMessage` |

Both rows carry the shared `CollectionTime` so they join cleanly with the engine's own output rows.

**Critical property:** a `Start` row with no matching `End` row is the signal that the replica was *killed* before it could finish (OOM, container kill, infrastructure timeout). This is the only way to detect those — Container Apps Job execution status alone won't tell you which shard died, only that *something* did.

The heartbeat is best-effort: if the LA ingest itself fails, the warning is swallowed (verbose only). Telemetry never kills the run it's measuring.

The table + DCR (`dcr-si-run-health`) auto-provision on first ingest via `AzLogDcrIngestPS`. No bootstrap step required.

**Table schema** (`SI_RunHealth_CL`):

```
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

The heartbeat helper lives at `v2.2/engine/asset-profiling/shared/Send-SIRunHealthRow.ps1` and is invoked from `Invoke-SIEngineRun.ps1` (Start before stages, End in `finally`).

### Run transcripts — every run keeps its own log

The heartbeat above says *whether* a run finished. The transcript says *what it did*. Every launcher
wraps its run in `Start-Transcript` via `launcher/_lib/Start-LauncherTranscript.ps1`, and this is **on
by default** — nothing needs enabling.

| | |
|---|---|
| **Path** | `<root>/logs/<engine>_<flavour>[_<simulation>][_<template>]_<yyyyMMddTHHmmssZ>.log` |
| **Layout** | one `logs/` folder per install (deliberate — easier to grep than a tree), UTC stamp so the folder sorts chronologically |
| **Retention** | 30 days, pruned at the start of each run; override with `$global:SI_LogRetentionDays` |
| **Kill switch** | `$global:SI_DisableTranscript` — both knobs are documented in `config/SecurityInsight.custom.reference.ps1` |

The helper is layout-aware: it resolves `SOLUTIONS/SecurityInsight/logs` in the monorepo and
`<root>/logs` in the flat community layout, so a community install does not end up writing its
transcripts somewhere its operator cannot find them.

#### The container host publishes its transcript to blob storage

A container filesystem is ephemeral, so a log written inside one dies with the replica. The three
container entrypoints — `Start-SIInContainer.ps1` (worker + privilege-tier-classifier branches),
`Start-RiskAnalysisInContainer.ps1` and `Invoke-ShardProducer.ps1` — start a transcript with
`-Flavour container` and hand it to `launcher/_lib/Publish-LauncherTranscript.ps1` at run end, which
uploads it to the staging account under `run-logs/<engine>/<file name>`.

The **dispatch** branches deliberately start no transcript: they hand off to a child `pwsh` that starts
its own, and two transcripts for one run is worse than one. Each leaf branch captures `$LASTEXITCODE`
**before** publishing, because publishing runs commands — without that, a Container Apps Job would
report the publish's exit code rather than the engine's.

Three properties of the publisher, in priority order:

- **It never throws.** Every failure path warns and returns `$null`. Failing a collection run because
  its log could not be uploaded trades the customer's inventory for their audit trail, which is the
  wrong way round.
- **It stops the transcript before reading the file.** `Start-Transcript` buffers, so uploading an open
  transcript ships a file missing exactly the tail an operator wants — the error at the end of a failed
  run.
- **It prunes its own blobs** at `$global:SI_LogRetentionDays` (30), matching local retention. Run logs
  sit **outside** `staging/` on purpose: the staging lifecycle rule is prefix-scoped to `staging/` and
  its 7 days would silently disagree with the 30-day retention everywhere else.

**Known limit, stated rather than hidden:** anything that throws *before* `Connect-AzAccount` succeeds
cannot be published, because there are no credentials to upload with. A container that dies on a missing
environment variable still leaves nothing behind. Everything after that point is covered.

### Monitoring — three layers

Pick the layer that matches your operational posture. Most setups use Layer 1 daily + Layer 2 on production tenants.

#### Layer 1 — CLI: `Show-SIRunHealth.ps1`

> 🔴 **NOT YET SHIPPED — this section describes the intended tool, not one you can run.**
> `Show-SIRunHealth.ps1` does not currently exist in the solution. The **data it reads is real** —
> `SI_RunHealth_CL` is emitted by every asset-profiling and risk-analysis run — so the KQL further
> down this chapter works today and can be run directly in the workspace. Two related gaps to know
> about while this stands: the run-health **DCR is not created by setup** (so the heartbeat has
> nowhere to land until it is provisioned), and heartbeat delivery is deliberately best-effort and
> **swallows its own failures**, which means an absent row does not by itself prove a run failed.
> Use the raw queries below in the meantime.

The day-to-day tool. Reads `SI_RunHealth_CL` and prints three tables: failed replicas, memory warnings, and a planned-vs-completed run summary.

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

- **FAILED replicas** — Start with no End. If non-empty, check the Container App Job execution logs for the matching replica's exit reason (OOM kill, timeout).
- **WARNING** — End rows with `PeakWorkingSetMB > MemoryWarnMB` (default 3072 = 75% of a 4 GB Consumption-profile container). These predict the next OOM.
- **RUN SUMMARY** — one line per run: planned `ShardCount` vs `Completed` vs `Missing`, total assets across shards, max peak memory, duration.

Run after every test deploy and once a month per tenant.

#### Layer 2 — Azure Monitor scheduled alert

For tenants you can't manually inspect. Wire one alert per workspace; the alert fires when any replica from the last 6h has no End row.

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

#### Layer 3 — Workbook tab

Add a section to the existing SecurityInsight Workbook with the same three KQL queries from Layer 1. Visual surface for stakeholders who don't run PowerShell. ~20 minutes of Workbook editing, no engine code change.

### Diagnostic KQL — copy/paste

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

### Right-sizing — when to bump `ParallelismIdentity`

ShardCount is set at bootstrap time per engine via `Bootstrap-ContainerAppJob.ps1 -ParallelismIdentity N` (or `-ParallelismEndpoint`, `-ParallelismAzure`). Changing it later requires a redeploy and invalidates the partition map (hash buckets shift).

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

### Other operational signals to watch

Beyond the heartbeat itself, surface these in the Workbook or weekly review:

- **`SI_Identity_Profile_CL`** — row count per `RunId`; sudden drop = upstream Discovery regression.
- **`ExitReason == 'error'` rate** — if > 0% over a week, an engine bug is shipping silent half-runs (the heartbeat fires but the work errored).
- **Cadence skip ratio** — Stage Collect logs `N cadence-skipped`. A first run is 0% skipped, steady state should be 80–95% skipped (only T0 + due-cadence identities re-process). If steady state shows < 50% skipped, fingerprint cache writes are failing — see `Set-SIFingerprintRecord` warnings.
- **EG enrichment rate** — Stage Collect logs `EG-enriched: N`. Should match `[perms] EG identity nodes: M entries indexed by AadObjectId` from Discover. If EG-enriched is 0 but EG nodes > 0, the join key extraction broke (see `Get-SIExposureGraphIdentities` in `IdentityRoleFetcher.ps1`).

### Tenant schema-drift detection (planned)

For the Azure engine: at start of every run, query `ExposureGraphNodes | where NodeLabel startswith "microsoft." | distinct NodeLabel` and diff against the (locked + custom) catalog of known types.

- **Tenant has + catalog has** → run the per-type EG + ARG queries.
- **Tenant has + catalog missing** → log to `schema-discovery-pending/azure/<type>.sample.json` with a real NodePropertiesJson sample for the operator to review and promote into `profiles-custom/azure.schema.custom.json`.
- **Catalog has + tenant doesn't** → skip (query returns 0 rows).

The schema-discovery engine already handles this drift loop for endpoint hunting tables; the same pattern extends to Azure resource types when the locked Azure catalog reaches stable coverage.

---

## Troubleshooting

### DCE / DCR provisioning failures

LA ingest goes through three Azure resources: the **Log Analytics workspace**, a **Data Collection Endpoint (DCE)**, and one **Data Collection Rule (DCR)** per profile table. The DCR is auto-created/auto-updated on the first ingest of every table by `AzLogDcrIngestPS\CheckCreateUpdate-TableDcr-Structure`. Four failure modes recur in real tenants.

> **Key invariant** — `AzLogDcrIngestPS.psm1` line 1725 sets the new DCR's `location` field from `$DceInfo.location` (the DCE's location), **not** from `$global:SI_Location`. The engine's `SI_Location` global is engine-intent only; once the DCE exists, that DCE's location wins for every DCR pinned to it. Recreating the DCR in a different location is impossible — DCR `location` is immutable post-create.

#### `RequestDisallowedByPolicy` — DCE in wrong region

**Symptom**: `[ERR] Body : RequestDisallowedByPolicy ... target dcr-si-<engine>-profile ... policyDefinition Allowed locations ... targetValue ["global","westeurope"], operator NotIn`. HTTP 403 on the DCR PUT, ingest aborts.

**Root cause**: An Azure Policy assigned at the management-group / subscription scope denies any resource location not in its allowlist. The DCE the engine resolved isn't in that allowlist — so the DCR PUT body that inherits its location is denied.

**Diagnose** (v2.2.42+ logs the picked DCE's location explicitly):
```
DCR pre-create  : SI_Location        = westeurope  (engine intent; NOT used by module for new DCR)
DCR pre-create  : DceLocation        = northeurope  (THIS becomes new DCR location)
DCR pre-create  : LOCATION MISMATCH -- SI_Location='westeurope' but DCE is in 'northeurope'.
```

**Fix**: Delete the DCE and any DCRs pinned to it (their location is immutable), then recreate the DCE in an allowed region:

```powershell
# 1. Confirm the wrong-location DCE
Get-AzDataCollectionEndpoint -ResourceGroupName $global:SI_DceResourceGroup `
                              -Name              $global:SI_DceName |
  Format-List Name, Location, Id

# 2. Drop dependent DCRs (any auto-created dcr-si-*-profile pinned to it)
Get-AzDataCollectionRule -ResourceGroupName $global:SI_DcrResourceGroup |
  Where-Object { $_.Name -like 'dcr-si-*-profile' } |
  Remove-AzDataCollectionRule -Confirm:$false

# 3. Drop and recreate the DCE in the allowed location
Remove-AzDataCollectionEndpoint -ResourceGroupName $global:SI_DceResourceGroup `
                                 -Name              $global:SI_DceName -Confirm:$false
New-AzDataCollectionEndpoint    -ResourceGroupName $global:SI_DceResourceGroup `
                                 -Name              $global:SI_DceName `
                                 -Location          $global:SI_Location `
                                 -NetworkAclsPublicNetworkAccess Enabled

# 4. Re-run any one engine; CheckCreateUpdate will recreate every DCR auto-pinned
#    to the new DCE.
```

#### `LinkedAuthorizationFailed: invalid types 'Array'` — DCE name collision

**Symptom**: `LinkedAuthorizationFailed ... properties.dataCollectionEndpointId has values which are of invalid types 'Array'`. HTTP 4xx on DCR PUT.

**Root cause**: Two DCEs share `$global:SI_DceName` across subs/RGs (legacy install + new install on the same long-lived tenant). AzLogDcrIngestPS line 1575 does a name-only lookup — `$global:AzDceDetails | Where { $_.name -eq $DceName }` — which returns BOTH records when names collide. `$DceInfo.id` becomes `string[]`, gets serialized as a JSON array, ARM rejects.

**Fix (engine-side, v2.2.41+)**: Engine pre-filters `$global:AzDceDetails` to a single entry by name + RG before the module's name-only lookup runs. Set `$global:SI_DceResourceGroup` in `SecurityInsight.custom.ps1` to disambiguate when the DCE lives in a different RG than the DCRs.

When the guard fires, the engine logs:
```
DCE collision guard: 2 DCEs named '<dce-name>' visible -- pinned to RG '<rg-name>' (/subscriptions/.../<dce-name>)
```

If the wrong DCE is being picked, either:
1. Set `$global:SI_DceResourceGroup` explicitly to the desired RG, or
2. Delete the unwanted duplicate DCE.

#### Wrong `SI_DceName` — silent lookup miss

**Symptom**: `RequestDisallowedByPolicy` (most likely) or generic ARM 400. Often mistaken for the wrong-region case because the policy denial fires on the empty/null location field too.

**Root cause**: `$global:SI_DceName` doesn't match any DCE the SPN can see in ARG. Module's name lookup returns `$null`; `$DceLocation = $null`; DCR PUT body has `location = null`; ARM either rejects or the policy treats null as a disallowed location.

**Diagnose** (v2.2.42+ logs the empty-cache case):
```
DCR pre-create  : DceLocation        = <no DCE in cache>
```
Or: the `DCE collision guard` line is **absent** from the log entirely (no DCEs matched the name, so the guard had nothing to filter).

**Fix**: Verify the actual DCE name in Azure and update `SecurityInsight.custom.ps1`:

```powershell
# List every DCE the SPN can read across the tenant
Get-AzDataCollectionEndpoint | Format-Table Name, ResourceGroupName, Location, Id

# Or scoped to the security-insight RG
Get-AzDataCollectionEndpoint -ResourceGroupName '<rg-name>' |
  Format-Table Name, Location
```

Then in `SecurityInsight.custom.ps1`:
```powershell
$global:SI_DceName          = '<dce-name>'    # match what Azure actually has
$global:SI_DceResourceGroup = '<rg-name>'     # belt-and-suspenders disambiguation
$global:SI_Location         = '<region>'      # documents intent; only used when bootstrap creates a NEW DCE
```

#### `403 OperationFailed -- does not have access to ingest` — RBAC gap on DCR

**Symptom**: DCR was created successfully (`CheckCreateUpdate-TableDcr-Structure` returned clean), then on the first `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` call:
```
HTTP 403 OperationFailed: The authentication token provided does not have access
to ingest data for the data collection rule with immutable Id 'dcr-<32hex>'.
```
Engine retries 3 times with 30s/60s sleeps + cache refresh; all three fail identically. Sink reports `LA=FAIL JSON=OK Excel=OK`.

**Root cause**: SPN is missing the **`Monitoring Metrics Publisher`** role on the DCR (or on a parent scope with propagation still in flight). Two sub-cases:
1. **Bootstrap never granted it** — `Setup-SecurityInsight.ps1` was skipped or this DCR was created post-bootstrap by a different engine. Pre-flight catches this.
2. **RG-scope grant exists but hasn't propagated to a freshly-created DCR** — Azure RBAC inheritance can take 5–30 min for newly-created DCRs to become visible to the data plane even though the grant lives at the parent RG. v2.2.42's resource-scope grant in Setup avoids this by granting directly on the DCR (sub-60s propagation).

**Diagnose** (v2.2.42+ engine pre-flight emits one of these lines per run, per DCR):
```
RBAC pre-flight  : SPN has 'Monitoring Metrics Publisher' at DCR RG (/subscriptions/.../resourceGroups/<rg-name>)
```
Or:
```
RBAC pre-flight  : SPN <objectId> has NO 'Monitoring Metrics Publisher' at /subscriptions/.../resourceGroups/<rg-name>
RBAC pre-flight  : ingest may 403 if no inherited grant exists. Fix:
RBAC pre-flight  :   New-AzRoleAssignment -ObjectId <objectId> -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope '/subscriptions/.../resourceGroups/<rg-name>'
```

**Auto-fix (engine self-heal, v2.2.42+)**: The 3-attempt retry detects the 403 RBAC pattern and attempts `New-AzRoleAssignment` on the DCR resource scope between attempts. **Requires the engine SPN to have `User Access Administrator` or `Owner` somewhere in the scope hierarchy** (it usually doesn't — runtime SPNs are typically read+ingest-only). If the grant call itself fails, the engine logs a `[WARN]` and falls through. The 403 surfaces unchanged on the final attempt.

**Manual fix** (when self-heal can't grant):
```powershell
$spnObjectId = $global:SI_SPN_ObjectId
$dcrId       = (Get-AzDataCollectionRule -ResourceGroupName $global:SI_DcrResourceGroup `
                                          -Name              'dcr-si-identity-profile').Id

# Resource-scope grant -- propagates in <60s vs 5-30 min for RG-scope
New-AzRoleAssignment -ObjectId $spnObjectId `
                     -RoleDefinitionName 'Monitoring Metrics Publisher' `
                     -Scope              $dcrId

# Belt-and-suspenders: also grant at RG (covers future auto-created DCRs)
New-AzRoleAssignment -ObjectId $spnObjectId `
                     -RoleDefinitionName 'Monitoring Metrics Publisher' `
                     -Scope "/subscriptions/$($global:SI_AzSubscriptionId)/resourceGroups/$($global:SI_DcrResourceGroup)"

Start-Sleep -Seconds 60   # propagation
```

**Why two roles, not one**: `Monitoring Contributor` lets you read+write monitoring resources (DCEs, DCRs themselves); `Monitoring Metrics Publisher` lets you ingest data INTO a DCR. They're orthogonal — bootstrap needs Contributor (to create the DCR), runtime needs MMP (to send rows to it). Setup grants both at RG scope; v2.2.42 also grants MMP at the DCR resource scope per-DCR.

#### Quick-reference — DCE/DCR location decision table

| Scenario | What governs DCR location |
|---|---|
| First-ever DCE create (via `Setup-SecurityInsight.ps1`) | `$global:SI_Location` (bootstrap honours it) |
| First-ever DCR create (via engine ingest) | `$DceInfo.location` (whatever location the DCE was created in) |
| Subsequent DCR updates (schema drift) | DCR location is immutable — module sends `location = $DceLocation` again, ARM no-ops the field |
| Recreating DCR in a new location | Impossible without delete + recreate. DCE delete + recreate first if you also want to move the DCE. |

### Engine-level diagnostic signals (cross-reference)

These run-summary log lines double as troubleshooting entry points:

- **Failed replica (Start with no End)** → killed mid-run (OOM / container kill / infra timeout). Bump ShardCount. See heartbeat section.
- **`PeakWorkingSetMB > 3072`** → memory pressure, predicts the next OOM. Bump ShardCount at next deploy window.
- **Cadence skip ratio < 50% in steady state** → fingerprint cache writes failing; check `Set-SIFingerprintRecord` warnings.
- **`EG-enriched: 0` while EG nodes > 0** → ExposureGraph join-key extraction broke; check `Get-SIExposureGraphIdentities` in `IdentityRoleFetcher.ps1`.
- **MDE-discovered devices with empty `Hostname`/`OsPlatform`/`MachineGroup`** → MDE pass-through branch ordering regressed; Stage Collect must hit the `elseif ($a.MDE_DeviceId)` branch before the Entra-device fallback.
---

> **SIA's design lives in THIS doc**, in the chapter *"SI Analyzer (SIA) — hosted .NET web app"* at
> the end of the file. SIA is a separate product (a central, hosted ASP.NET Core app behind Entra SSO
> on its own Azure infra, modeled on CEH — not a SecurityInsight PowerShell engine), but it shares
> this ONE doc set. **There is no `analyzer-web/docs/` — it was merged here and deleted 2026-08-05**
> (operator directive: one doc set, same structure as CEH). Everything above this line covers the
> SecurityInsight ENGINES.

---

## Publish layout — what ships vs stays internal

SecurityInsight publishes to its public mirror through the monorepo's shared
`.github/workflows/publish.yml` (flat layout). The workflow mirrors the entire
`SOLUTIONS/SecurityInsight/` tree into the staged public output **except** the internal/runtime
folders and docs listed below. The publish mechanics are shared and already correct — this section
documents the model; do not hand-maintain a divergent list.

### Ships to the public mirror

The customer entrypoints (`Bootstrap-Auth.ps1`, `Bootstrap-Storage.ps1`,
`Bootstrap-ContainerAppJob.ps1`, `Setup-SecurityInsight*.ps1`, `Get-FingerprintEngine.ps1`,
`VERSION`), `README.md`, `RELEASENOTES.md`, and the engine/runtime trees: `auth/`, `engine/`,
`launcher/` (community + internal-vm flavours), `setup/`, `container/`, `data/`, `tools/`,
`tests/`, `preview/`, `privilege-tier-catalog/`. Plus the customer-facing authority files and
their samples:

- `asset-profiling-schema/*.locked.json` + `*.custom.sample.json`
- `asset-profiling-providers/_manifest.schema.locked.json`, the built-in `entra/` provider, and
  `generic-cmdb/Refresh-CmdbCache.ps1` + `sample/CMDB.csv`
- `asset-profiling-enrichment/**/*.locked.yaml` + `**/*.custom.sample.yaml`
- `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml`, `risk-analysis.schema.locked.json`,
  `riskscore_weighted.schema.custom.sample.json`, `*.exclude.json.sample`
- The canonical public docs: `docs/FEATURES.md` and `docs/DESIGN.md`.
- The bundled shared library (`FUNCTIONS/AutomateITPS*`) is inlined at publish time for community
  customers who don't have the monorepo.

### Stripped at publish (never public)

- **Internal-only docs:** `docs/REQUIREMENTS.md`, `docs/TESTS.md`, `CLAUDE.md`, and the entire
  `internal/` folder (real onboarding playbooks, per-tenant runbooks, customer notes,
  `ENGINE-IDENTITY.md`).
- **Internal launcher flavours:** `launcher.internal-(vm|azure).*` and
  `launcher.internal-*.template.ps1`.
- **Runtime/transient:** `logs/`, `staging/`, `output/` (and `risk-analysis-detection/OUTPUT/`),
  `demo/`, plus `solution.publish.json` and `README.PLAN.md`.

### Never enter the monorepo (gitignored)

Customer-owned files that may carry secrets or tenant-specific overrides are gitignored so they
cannot be committed and therefore cannot leak through publish:

- `config/SecurityInsight.custom.ps1` and every `launcher/*/LauncherConfig.custom.ps1` (may hold
  SPN secrets)
- `asset-profiling-enrichment/**/*.custom.yaml` / `*.custom.yml`
- `asset-profiling-schema/*.custom.json` (excluding `*.sample.`)
- `asset-profiling-providers/**/CMDB.csv` (the real CMDB extract — the `sample/CMDB.csv` ships)
- `risk-analysis-detection/*.exclude.custom.json`, `riskscore_weighted.schema.custom.json`,
  `riskscore.index.custom.csv`, `RiskAnalysis_Queries_Custom.yaml`

`*.custom.sample.*` files are explicitly negated (they ARE documentation and DO ship). The
pre-publish gate (`RepoHygiene` check) fails the build if any customer-only/secret file is tracked.

---

*Real environment values (engine SPN appId, certificate thumbprint, tenant/subscription IDs,
workspace/RG/Key-Vault names) live only under `internal/` — see `internal/ENGINE-IDENTITY.md`,
which is stripped from every public publish.*

## SI Analyzer (SIA) — hosted .NET web app

> Merged here 2026-08-05 from the former `analyzer-web/docs/DESIGN.md`. SIA is a recently added
> **extension** of SecurityInsight (ASP.NET Core, `analyzer-web/SIAnalyzer.sln`, added 2026-06-17) —
> **not the main program**: the PowerShell engines documented above are, and SIA reads their
> Risk-Analysis output. It shares this ONE doc set — there is no second DESIGN/FEATURES/TESTS
> anywhere under `analyzer-web/`, and that folder holds code only.

### 1. What SIA is

The **SecurityInsight Analyzer (SIA)** is an executive-grade, **hosted** analyzer over the
SecurityInsight Risk-Analysis (RA) data. It gives **executives** a plain-language "are we getting
safer?" view (risk score over time, what's new/closed, an AI exec summary + recommendations) and gives
**analysts** a worklist that explains the top risk rows (the KQL facts plus an AI verdict). It adds no
new data plane and no new AI infrastructure — it reuses what SecurityInsight already has, read-only.

SIA is a **separate solution on its own dedicated Azure infrastructure: a hosted .NET web app
(ASP.NET Core), behind Entra SSO, modeled on CEH.** The earlier PowerShell/localhost POC is **retired**
(a non-technical exec cannot run a script; the timeline/AI/exec functionality demands a real .NET app).

> 🔑 **"Hosted" means a service, NOT a shared instance — one deployment per environment.** Each
> environment runs **its own** SIA: its own Container Apps environment, registry, storage and Entra app
> registration, in its own tenant, reading **only that tenant's** workspace through its own Managed
> Identity. There is no multi-tenant instance and no central service anyone depends on at runtime;
> `Deploy-SIAnalyzer.ps1` builds the image in **that environment's own registry** from the synced
> source. The word "hosted" is here to rule out the retired localhost model — a browser URL with Entra
> sign-in rather than a script on someone's laptop — not to imply a single shared deployment. A
> consequence worth stating: because no instance ever sees more than one tenant's data, there is no
> cross-tenant isolation surface to get wrong.
Its proven logic — the read-only KQL guardrail, the snapshot diff + score timeline, the grounded AI
prompts — was **ported to C#** and lives in `SIAnalyzer.Core`. Only `../analyzer/seed/demo-snapshot.json`
survives, as the .NET app's demo-fallback seed.

The UI **matches the PIM Manager** (same blue `#0969da` colour scheme, light layout, and a tab-strip menu
with a blue active-underline) so SIA reads as a sibling product; the exec/board/analyst/governance surfaces
share one chrome (`ExecHtmlRenderer.NavChrome` + `ThemeCss`). It is mobile-first (~360px) + accessible —
see REQUIREMENTS.md Phases 5/6 for the (still-backlog-until-hosted-gate) status.

### 2. Project shape (`analyzer-web/`)

```
analyzer-web/
  SIAnalyzer.sln
  Directory.Build.props          dll-only across every project (UseAppHost=false; Defender ASR safe)
  src/SIAnalyzer.Core/                  host-agnostic ported logic (pure, fully unit-testable):
    Kql/KqlGuardrail.cs            read-only guardrail (Test-SiKqlReadOnly)
    Kql/KqlBuilders.cs             snapshot-correct query builders
    Kql/PrestagedLibrary.cs        the prestaged analyses (+ a "why did our score change?" analysis)
    Analysis/SnapshotDiff.cs       snapshot diff + score timeline
    Analysis/PeriodComparison.cs   period-over-period baseline ("since last board meeting")
    Ai/GroundedPrompt.cs           grounded prompt assembly + templated fail-soft fallback
    Exec/ExecDashboard.cs          the board-ready exec rollup (headline/donuts/quick-wins/coverage/forecast)
    Exec/ExecHeadline.cs           the one-sentence "if you read one thing" verdict
    Exec/FrameworkLens.cs          control-area rollup (NIST CSF / CIS Controls / ISO 27001)
    Exec/AgingAnalysis.cs          time-open / accountability from the snapshot history
    Exec/RiskConcentration.cs      risk-by-area breakdown (share + direction + top contributor)
    Exec/TopMovers.cs              trends & top movers (biggest improvements/increases by area/severity/tier)
    Exec/BusinessImpact.cs         "so what" business-impact framing
    Exec/Drilldown.cs              clean-by-default, drill-down-on-demand (grounded evidence behind a number)
    Exec/RemediationPlan.cs        prioritised "next N actions" ranked by risk-removed-per-effort
    Exec/Glossary.cs               plain-language "what these terms mean" layer (grounded examples)
    Exec/OrgCoaching.cs            missing-processes / org coaching (maturity gaps from finding patterns)
    Exec/MaturityScorecard.cs      maturity scorecard + roadmap (rule-based 0-100 per leadership dimension)
    Exec/ExecEmail.cs              the grounded exec-summary EMAIL renderer (HTML + plain-text)
    Exec/EmailCadence.cs           pure cadence scheduling maths (daily/weekly/monthly, is-due/next-fire)
    Configuration/WorkspaceResolver.cs  internal-env-is-default-base resolution
    Governance/                    the ONLY write path: rules (store) + register + audit + expiry + the HARD-LOCKED platform-sync capability
    Governance/IGovernancePersistence.cs  where the register LIVES (Azure Table in the Web layer; in-memory here for demo/tests)
    Scheduling/ISendMarkerStore.cs   the cross-replica "this window was sent" interlock (Azure Table in the Web layer)
  src/SIAnalyzer.Web/                   ASP.NET Core app: exec + board-deck + analyst + governance Razor pages, JSON API, /mcp, /health
    Auth/ClientPrincipal.cs          end-to-end X-MS-CLIENT-PRINCIPAL (Easy Auth) parser + the /mcp auth gate
    Rendering/ExecHtmlRenderer.cs    the interactive exec dashboard (PIM-blue theme, shared NavChrome, charts, drill-downs)
    Rendering/GovernanceRenderer.cs  the governance register/audit + the record/renew forms + the visible-but-dimmed (disabled-until-tested) sync controls
    Services/TableGovernancePersistence.cs  the DURABLE register: Azure Table Storage via MI (thin mapping only; all rules stay in Core)
    Services/GovernanceExpirySweepService.cs  hourly expiry sweep (idempotent, deliberately unleased)
    Rendering/BoardDeckRenderer.cs   the clean one-page print/PDF board-deck export handout
    Services/ExecEmailService.cs     composes the grounded exec view -> email -> sender (fail-soft)
    Services/ExecEmailSender.cs      IExecEmailSender + SMTP transport (config-driven, fail-soft)
    Services/ScheduledExecEmailHostedService.cs  in-host scheduler (BackgroundService) on the cadence; claims each window
    Services/TableSendMarkerStore.cs  the DURABLE per-window send marker: one Azure Table row per job, ETag-claimed
    Mcp/                             the read-only JSON-RPC MCP endpoint
                                     + the read-only Log-Analytics data plane (MI) + demo fallback + the Azure OpenAI service
  tools/SIAnalyzer.Preview/             renders the exec dashboard + board-deck to static preview HTML (committed at preview/)
  tests/SIAnalyzer.Tests/               xunit offline suite (TESTS.md)
  preview/                       committed static exec-dashboard.html + board-deck.html (open locally, no server)
  deploy/                        Dockerfile + Deploy-SIAnalyzer.ps1 + README-DEPLOY.md (placeholder-only)
```

SIA targets **net8.0** and is **dll-only** (`UseAppHost=false` in `Directory.Build.props`) — the build
never emits a native apphost `.exe` (Defender ASR on the build machine blocks freshly-built native exes).
Everything runs via `dotnet <dll>`; the container ENTRYPOINT is `dotnet SIAnalyzer.Web.dll`.

### 3. Data plane — read-only via Managed Identity

SIA reads the RA outputs already in the customer's Log Analytics workspace via the **Azure Monitor Query
SDK** (`LogsQueryClient`), authenticated with the hosted app's **Managed Identity** granted **Log
Analytics Reader** — **READ-ONLY**. It introduces no new connector and no write path. The scored
findings come from the RA output table **`SI_RiskAnalysis_Summary_CL`** (+ `…_Detailed_CL`) — the
worklist/exec rollup — **not** the attribute-only `SI_*_Profile_CL` tables. It is **snapshot-correct**:
analyst views key on `where CollectionTime == max(CollectionTime)` so they read one coherent latest
snapshot; the management timeline/diff intentionally span multiple `CollectionTime` snapshots, using the
latest-snapshot pattern (`where CollectionTime == toscalar(... | summarize max(CollectionTime))`).

The **internal env is the default base**: `SIAnalyzer.Core/Configuration/WorkspaceResolver.cs` resolves the
configured workspace from the `SIAnalyzer__WorkspaceId` app setting (the workspace **customerId GUID** the SDK
queries) and uses it live; demo data is the **explicit fallback** only (no workspace id, or
`SIAnalyzer__UseDemoData=true`), serving the seeded `demo-snapshot.json` so the surfaces and cores can be
exercised entirely offline.

**A read carries how complete it was.** Log Analytics answers `PartialFailure` — truncated rows PLUS an
error — at its 500,000-row / 100 MB caps, and the rollup asks for up to 500,000 rows across the lookback
window. Every read therefore returns a `RiskSnapshot` (rows + `DataQuality`), and a partial read is stated
on **every surface that shows a figure**: the exec page above the score dial, the board deck above the
score badge, the analyst page, `/api/exec`, and the scheduled email (subject prefix, HTML body and
plain-text twin), all from one shared constant so the wording cannot drift. This is not cosmetic: the
system resolves `max(CollectionTime)` and SUMS scores, so a truncated read means fewer findings and a
LOWER score — it renders as an improvement unless the surface says otherwise.

**One rollup, shared.** `CachedRiskDataSource` decorates the live source with a short TTL
(`SIAnalyzer:RollupCacheSeconds`, default 300; 0 disables), because eight `AnalyzerService` entry points
each asked for that 500k-row query independently. Three rules matter more than the caching itself: a
**partial result is never cached** (and evicts any earlier complete one, so stale-but-complete data cannot
mask a workspace that has begun truncating); **ad-hoc/prestaged queries bypass the cache** entirely; and
reads are **single-flight**, since without that N cold requests would each launch the same query and the
cache would make the worst case worse. The query also sets an explicit `ServerTimeout`.

### 4. Read-only KQL guardrail

Every query SIA runs — prestaged, builder-generated, AI-composed from an ad-hoc prompt, or invoked via
MCP — is first vetted by the ported read-only guardrail (`KqlGuardrail` / `Test-SiKqlReadOnly`). It
rejects mutating/control commands (`.set` / `.create` / `.append` / `.ingest` / `.drop` / `.purge`),
`externaldata` / `into table`, cross-cluster / cross-database / cross-workspace access (`cluster()` /
`database()` / `workspace()` / `app()` / `table()`), whole-workspace scans (`union *`, unscoped
`search`, `find`), any table outside the canonical SI allow-list, and ungrounded or empty queries; it
reports the tables a query read. This keeps the engine's read-only invariant intact even for
AI-generated KQL. (The one deliberate write exception — governance/exemption sync — is Phase-6
backlog and is not part of the analysis path.)

**It is a whitelist of SOURCES, not a scan of mentioned names.** Comments and string literals are
blanked first, then a tokenizer walks the query and validates every identifier that lands in a source
position — query start, the RHS of a `let`, each `union` operand, the `join` operand, and inside
`toscalar()` / `materialize()`. An identifier there that is neither `let`-defined nor allow-listed is
refused, so a table does not have to *look* like an SI table to be caught; conversely column names and
function arguments are never treated as tables, so `summarize max(CollectionTime)` passes untouched.
The design rule behind it: **deciding what a query reads by pattern-matching identifiers anywhere in
its text is not a whitelist** — the same "the gate only knows a hardcoded handful of names" shape that
produced the publish-strip and resource-group findings. Fail-closed by construction, but still a
text-level control over a language it does not fully parse: one layer, not a licence to widen the
query identity's permissions.

### 5. AI — grounded and AI-optional

AI uses **Azure OpenAI** (the same configuration the SI privilege-tier-classifier and RA summaries use).
It is **grounded**: the model is always handed the actual KQL result rows as context and asked to explain
*those rows* (the prompt embeds the rows + a no-invention contract), so a verdict or summary traces back
to real findings rather than inventing data. It is **AI-on by default** in the hosted internal env
(endpoint + deployment configured; MI or key auth), and **fail-soft**: if OpenAI is unreachable the
Analyzer degrades to the grounded templated summary, logs a warning, and never hard-fails.
Projections/forecasts and benchmarks are clearly labelled; the AI never supplies a number — every figure
on the exec surface is computed from the rows.

**Every AI call is bounded (audit #15)** — its own deadline (`SIAnalyzer:AiTimeoutSeconds`, 45s) and
an output cap (`SIAnalyzer:AiMaxOutputTokens`, 900). The deadline is *independent of the caller* on
purpose: the dangerous path is not a slow page but the **scheduled exec email**, which passes the
host's `stoppingToken` (cancelled only at shutdown) and calls the AI **after claiming the send
window** (§ audit #9) — an unbounded hang there consumed the window and delivered nothing.

Two rules keep that fix from creating new problems:
- **Caller cancellation and our deadline are handled differently**, though both arrive as
  `OperationCanceledException`. A cancelled caller propagates (nothing to fall back *for*); our
  deadline degrades to the templated summary. Treating them alike would make a stopping host log
  spurious AI failures.
- **Truncated output is discarded, never shown.** A completion stopped at the cap is cut off
  mid-sentence, and this prose goes in front of an executive; a cut-off KQL is worse still, since it
  can parse while meaning something other than what was asked. Both fall back rather than render.

### 6. Auth

**Entra / Easy Auth** is enforced by the platform in front of the container (Container Apps built-in auth
or App Service Easy Auth). A hosted analyzer of security findings is never anonymous. The app trusts the
authenticated principal the platform injects in the `X-MS-CLIENT-PRINCIPAL` header.

`SIAnalyzer.Web/Auth/ClientPrincipal.cs` validates that header **end-to-end**: it base64-decodes the JSON, reads
the auth type + claims and exposes the display name — fail-soft, so a missing, empty or malformed header
reads as *anonymous* rather than throwing. `EasyAuth.RequireAuthenticated` is the allow/deny gate; it backs
the `/mcp` endpoint (the MCP tool surface is **gated behind the same authenticated principal as the UI** —
never anonymous), the `/api/me` identity endpoint, and the governance write endpoints. The gate is
controlled by `SIAnalyzer:Auth:RequireClientPrincipal` (ON in the hosted env; OFF by default so local/demo/test run
without a platform proxy in front). When on, an anonymous call to a gated endpoint gets `401` — defense-in-
depth on top of the platform's own Easy Auth gate. The whole exec/board/analyst read surface continues to be
fronted by the platform sign-in.

### 7. Surfaces

The **executive management view is the default landing surface** (`/` → `/exec`): plain-language,
chart-led, mobile-friendly + accessible + print/PDF-friendly, with **no KQL/jargon**. It leads with:

- a **one-sentence headline verdict** ("if you read one thing" — the posture band + its direction + how
  many of the actual highest-scoring findings would have to be remediated to cross into the next-better
  band, e.g. "Your security posture is Elevated and improving; 2 actions would move you to Moderate"; the
  count is derived by walking the real rows highest-first, never guessed; verdict + action count only —
  no invented cost/probability/date; AI narrates on top, fail-soft);
- a **headline risk-score dial** + direction;
- a **trend line** with a clearly **labelled forecast** point;
- **severity / area donuts**;
- **top risks + recent wins**;
- a **quick-wins / ROI** remediation plan ("your next moves" — actions ranked by
  risk-removed-per-effort: each groups all of one asset's findings into a single fix with its projected
  score drop (the exact amount the headline falls if the asset is fully remediated), an effort estimate
  (Low/Medium/High, derived from the asset's grounded drivers + tier, explicitly an estimate — never
  hours/cost), a plain recommendation, and the running cumulative score + band after doing it; a summary
  line states how many actions reach the next-better band; served on demand from `/api/remediation`);
- a **framework lens** (rolls the posture into NIST CSF / CIS Controls / ISO 27001 control areas — each
  finding mapped once, the area scores partition the headline number);
- an **aging / time-open** accountability panel (how long the top risks have been open, derived from the
  snapshot history, with average/longest-open + carried-over vs new counts);
- a **risk-by-area concentration** panel (where risk concentrates — identity vs endpoint vs cloud vs
  internet-facing — with each area's share of the total, period direction and biggest contributor, as a
  "where to invest" steer);
- a **trends & top movers** panel ("what moved the most?" — which areas improved the most and which got
  worse the most since the baseline snapshot, with a by-area / by-severity / by-tier breakdown; each
  number is the change in summed risk score for that group; honest "only one snapshot so far" when there
  is nothing to compare against);
- a **period-over-period "since last board meeting"** panel (a configurable look-back — previous / month
  / quarter / half-year / year — that picks a REAL baseline snapshot and reports
  new/resolved/worse/improved since it, with a `?period=` selector);
- a **"so what" business-impact panel** (each top risk re-stated as a board-level consequence — data
  exposure / downtime / compliance / reputation — with the grounded driver behind it, plus a
  per-category rollup; the consequence KIND only, never an invented cost or likelihood);
- a **clean-by-default drill-down** (a collapsed "show me the detail behind the score" reveal of the
  actual findings that SUM to the headline number — no black-box claims; per-slice drill-downs — overall
  / area / severity / tier — served on demand from `/api/drilldown`);
- a **plain-language glossary** (a collapsed "what do these terms mean?" reveal decoding every security
  term on the page in one non-technical sentence each, with a GROUNDED example from a real row where the
  concept is present and an honest "not seen in your current data" note where absent; present-now terms
  first; served from `/api/glossary`; kept off the one-page board deck);
- a **"processes worth strengthening" org-coaching panel** (the leadership-level maturity / process gaps
  the finding PATTERNS imply — privileged-access reviews, internet-exposure reviews, patch & lifecycle
  cadence, asset onboarding/visibility, asset ownership, crown-jewel protection — each surfaced ONLY when
  real rows cross a small evidence threshold; the affected-asset count + example asset names come from
  the rows; framed as a recurring process, never a per-asset ticket; honest "the findings look like
  one-offs" when no systemic gap stands out; served from `/api/coaching`);
- a **maturity scorecard + roadmap** ("where do we need to mature?" — a leader-facing capability rating
  across six fixed dimensions: Tiering, Privileged Access, Identity Hygiene, Exposure Management,
  Visibility & Coverage, Operating Discipline — each a rule-based 0–100 maturity score = the SHARE of
  in-scope assets WITHOUT a weakness signal in that discipline, with a plain band
  (Initial/Developing/Defined/Managed), the weak-asset count over the in-scope denominator, and grounded
  example asset names; "not enough data" when a dimension has no in-scope asset; a prioritised "mature
  here next" roadmap lists only the below-bar dimensions with real evidence, most room-to-improve first;
  served from `/api/maturity`; kept off the board deck);
- a **coverage & confidence banner** and **period-over-period KPIs**.

Every exec panel is **pure grounded aggregation** (no AI, no invented numbers); the AI narrates on top,
fail-soft. Charts use a **self-contained Chart.js** (bundled under `wwwroot/lib`, no CDN).

The **analyst surface** (`/analyst`) is secondary: the prompt box (exec/analyst tone), a top-100
worklist (highest `RiskScoreTotal` in the latest snapshot, each row expandable to the *why* and the
blast radius and a plain-language AI verdict), a library of one-click prestaged analyses (each a vetted
read-only KQL + an explanation template), an ad-hoc prompt mode (free text → guardrail-checked read-only
KQL → run → explain), a guarded raw-KQL box, and drill-down.

### 8. MCP server

> 🔑 **Where it runs:** `POST /mcp` is served **by the SIA app process itself** — it is not a separate
> service, has no separate deployment, and is not centrally hosted. Because each environment runs its
> own SIA (§1), the MCP endpoint lives inside **that environment's** container, on its private ingress,
> behind that environment's Entra sign-in, exposing only that tenant's data. An MCP client reaches it
> the same way a browser reaches the UI: over the private network, authenticated.
>
> 📌 **Not to be confused with Microsoft's own security MCP server.** Microsoft hosts an MCP server for
> the Sentinel data lake and Defender; it requires no infrastructure and authenticates with Entra. That
> is a *source* SI could consume as a provider (an outbound HTTPS client — nothing to deploy), whereas
> `/mcp` here is SI **publishing its own** analysis to agents. Two opposite directions; they are
> independent, and neither implies the other.

`POST /mcp` is a minimal **JSON-RPC 2.0** MCP endpoint exposing tools that mirror the prestaged
analyses + a **guarded query** + snapshot-diff / score-timeline / **exec_headline** /
**exec-summary** / **period_comparison** / **risk_by_area** / **top_movers** / **business_impact** /
**drilldown** / **remediation_plan** / **glossary** / **org_coaching** / **maturity_scorecard**.
Every query tool routes through the **same guardrail**; it sits behind the same Easy Auth as the UI, and
the `/mcp` endpoint itself is gated behind an authenticated client principal (§6) when the gate is on —
the tool surface is never anonymous.

**The contract is "read-only EXCEPT exactly one declared side-effecting tool."** That one is
**`send_exec_summary_email`**, which transmits the grounded digest to the configured executive
recipients — an effect outside this app, and MCP is the surface an *agent* talks to. So it is:
declared (`annotations.readOnlyHint=false` plus a `SIDE EFFECT:` prefix, while every other tool states
`readOnlyHint=true` — "unannotated" must not read as "safe"); **off by default**
(`SIAnalyzer:Mcp:AllowEmailSend`); and **refused when off, not merely unlisted**, because hiding a tool
from a listing is not a control. Humans keep the capability through the UI, `POST /api/email/send` and
the scheduler. This file previously claimed there were "no write tools" while shipping that one — the
claim, not the tool, was the defect (audit #11).

**Protocol details that bite real clients:** a JSON-RPC **notification** (no `id`) gets **no response at
all** — HTTP 204, since serialising `null` with a 200 is not silence — which matters because every
spec-compliant MCP client sends `notifications/initialized` immediately after `initialize`. And an
unexpected exception is logged server-side but returned as a generic `-32603`; only deliberate
caller-facing errors (a rejected query, a bad argument) come back verbatim.

### 8a. Governance — the ONLY sanctioned write path

Everything else in SIA is strictly read-only; governance is the single deliberate exception. It lives in
`SIAnalyzer.Core/Governance/` (`GovernanceStore` — the register + an append-only audit trail + expiry/renewal;
`GovernanceCapabilities` — the enable flags; the record model) and surfaces on the PIM-blue `/governance`
page (+ `/api/governance` read and the `/api/governance/risk-accept` & `/api/governance/exemption` writes,
gated behind the authenticated principal).

Three capabilities, each plain-language:
- **Risk-accept comments** — an owner marks a finding risk-accepted with a justification; the accepted state
  is reflected (a read, always available) without deleting the finding. Recording one is a write to SIA's
  OWN store only — it never touches MDE/Entra/ARM.
- **Exemptions** — a scoped, expiring exemption is recorded in SIA's register and, once enabled, synced to
  **Defender for Cloud / Azure Policy / Defender XDR** exemptions (and platform exemptions surface back).
- **Register + audit + expiry/renewal** — a central who/why/scope/expiry register, a who/what/when audit
  trail, an expiry sweep and a renewal workflow with a mandatory future expiry.

**The no-auto-revoke guarantee.** A platform exemption SUPPRESSES/removes a finding on the platform — a
write that takes a finding away — so the platform-sync surface is the gated part. It ships **OFF by default
AND hard-locked**: `GovernanceCapabilities.PlatformSyncLocked` is a compile-time constant, so even with
`SIAnalyzer:Governance:EnablePlatformSync=true` in config the effective `PlatformSyncEnabled` stays false and the
build **cannot ship an enable-able platform write**. The `/governance` page renders the sync toggle + the
three target buttons **visible but dimmed and `disabled`**, with a "Disabled until tested" note; the write
path refuses every platform push while locked (the audit records `exemption-sync-skipped`). Local
recording (risk-accept comments / exemptions without platform sync) is separately gated by
`SIAnalyzer:Governance:LocalRegisterEnabled`, which is **ON by default** — it writes to SIA's own
table and never to a platform, which is exactly why it can default on while the sync stays locked.
The deploy sets it explicitly so the live value is readable in `az containerapp show`. The lock
is lifted only by a deliberate, reviewed code change after the hosted sync test passes — never a config
toggle.

**Where the register lives.** `GovernanceStore` holds the RULES — capability gates, validation, the
audit trail, the lifecycle — and delegates storage to `IGovernancePersistence`, so those rules are
identical wherever the records sit. Two implementations: **Azure Table Storage** via the app's
Managed Identity (`SIAnalyzer:Governance:TableEndpoint`; one table, three partitions —
`riskaccept` / `exemption` / `audit`) and an in-memory one for demo, local development and the
offline tests. Audit rows are inserted and never updated, with a reverse-ticks RowKey so ascending
key order is newest-first; a same-tick collision retries rather than overwriting someone's trail.
Reads go through to storage every time — deliberately no cached working set, because a cache is how
two replicas start disagreeing about what the register says, and the register is tens-to-hundreds of
rows. With no endpoint configured (or an unreachable one) the app falls back to in-memory, logs it,
and the page + `/api/governance` both say **the records are not durable** — a volatile list must
never be presented as a register of record.

**Governance marks a finding; it never hides one.** A risk-accepted or exempt finding stays on the
worklist and keeps counting toward the score, badged with its owner, reason and expiry
(`/api/worklist` returns `{finding, governance}` per row). Dropping governed findings would make the
exec number improve for a governance decision rather than a security one. Suppression state is
decided by comparing the record's expiry to now, not by the lifecycle flag — the hourly expiry sweep
updates what the register DISPLAYS, and an acceptance stops applying on time even if that sweep never
runs.

### 9. Hosting / export / board deck

SIA is a **separate solution on its own dedicated Azure infrastructure** (its own resource group + ACA
environment / App Service plan + ACR + Entra app registration) — it must NOT be co-located in PIM's
resource group (where the container currently wrongly sits; the move to SIA's own infra is Phase 1, see
REQUIREMENTS.md). Preferred host is **Azure Container Apps** (private ingress + MI) in the internal env;
App Service *for Containers* also works (the same image + env vars apply).

The exec dashboard is **print/PDF-friendly** (a "Print / Save as PDF" action), and a dedicated
**board-deck export** (`/board`, linked from the exec view; `?period=` honoured) renders a **clean
single-page handout** from the same grounded exec view — the headline verdict, score+band,
direction/period KPIs, top risks, recent wins, where risk concentrates, the business-consequence KINDS,
the recommended next actions and the "processes worth strengthening" org-coaching gaps — in a light,
print-first, page-break-safe, self-contained theme (no charts/JS, inline CSS, no CDN). `GET /api/board`
returns the same handout as HTML so an emailer can attach/inline it.

### 10. Scheduled exec-summary email

A send-hook delivers the grounded exec summary on a cadence "so the CIO gets it without opening the
tool". `ExecEmailService` builds the SAME grounded exec view the dashboard + board deck use (AI-narrated
when AI is on, templated when off); `ExecEmail` (Core) turns it into an email message — subject +
inline-CSS, table-based HTML body (mail-client-safe) + a plain-text twin — leading with the one-sentence
verdict, the score/band badge, the period KPIs, the top risks, the recommended actions, and (only when
configured) a **link to the full board deck**. Every figure is the same grounded number; consequence KIND
only, no invented cost/likelihood. Cadence is pure, testable maths (`EmailCadence`: daily/weekly/monthly
+ send-hour, is-due/next-fire); the in-host `ScheduledExecEmailHostedService` (a `BackgroundService`)
fires at each genuine boundary. **Which windows are already done is durable and shared, not a field:**
`ISendMarkerStore` keeps one Azure Table row per job, claimed with ETag optimistic concurrency, so
exactly one replica wins a window — and because the baseline is read from that marker rather than
re-anchored to "now", a restart inside an unsent window still sends instead of skipping it. A
first-ever start claims the elapsed window WITHOUT firing, which is what keeps a fresh deploy from
mailing the CIO immediately. With no marker table configured it falls back to a process-local marker
and warns at startup that a double-send and a skipped window are both still possible. Everything is
**fail-soft**: with no recipients or no SMTP transport it renders but never sends or crashes. A manual
**"send now"** trigger (`POST /api/email/send`), an HTML **preview** (`GET /api/email/preview`), and the
`send_exec_summary_email` MCP tool all funnel through the same service.

The SMTP transport is config-driven via the `SIAnalyzer:Email` section (recipients, cadence, send-hour, period,
base URL, org label, SMTP host/port/ssl/user/password/from); the host/from are operator-completed
(Key-Vault-backed app settings in the hosted env), and the transport is swappable for a Graph sender
without touching the orchestration.

### 11. Health

`GET /health` is a liveness endpoint, used by the deploy health-gate — both the per-revision warm-up gate
(PROD blue/green) and the post-deploy gate on the public FQDN (§13).

### 12. Run / build / test / preview (local)

```powershell
dotnet build SIAnalyzer.sln -c Release
dotnet test  SIAnalyzer.sln -c Release

# Live local preview (demo data, AI-off):
dotnet run --project src/SIAnalyzer.Web                 # then open http://localhost:5xxx/

# Regenerate the committed static preview (no server, no browser auto-open):
dotnet run --project tools/SIAnalyzer.Preview           # writes preview/exec-dashboard.html + preview/board-deck.html
```

### 13. Deploy (hosting runtime)

> The deploy command + the Managed-Identity → Log Analytics Reader grant + the Easy Auth setup live in
> `deploy/README-DEPLOY.md` (placeholder-only, public). **The real workspace customerId / resource id /
> subscription / RG / tenant / app-registration ids live ONLY in `../internal/ENGINE-IDENTITY.md`** —
> copy them from there when you run the command. The agent that builds SIA does **not** deploy; the
> **main session** (which holds Azure creds) runs the deploy.

What the app needs at runtime:
- **Data plane** — `SIAnalyzer__WorkspaceId` = the internal SI Log Analytics workspace **customerId (GUID)**,
  queried READ-ONLY via the app's **Managed Identity** (granted **Log Analytics Reader** on the workspace
  resource id). Leave `SIAnalyzer__WorkspaceId` empty (or set `SIAnalyzer__UseDemoData=true`) for the demo fallback.
  `SIAnalyzer__RollupCacheSeconds` (default 300, 0 = off) is how long one rollup read is reused across the
  eight surfaces that need it; a partial read is never cached (§3).
- **AI (on by default)** — `SIAnalyzer__OpenAiEndpoint` + `SIAnalyzer__OpenAiDeployment` = the SI Azure OpenAI
  deployment; the MI (or a key, `SIAnalyzer__OpenAiApiKey`) authenticates; grounded + fail-soft.
- **Auth** — **Entra / Easy Auth** in front of the app; set `SIAnalyzer__Auth__RequireClientPrincipal=true` so the
  app also gates `/mcp` + the governance writes behind the authenticated principal (defense-in-depth, §6).
- **MCP surface** — `SIAnalyzer__Mcp__AllowEmailSend` (default false) is the only way an MCP client can reach
  the one tool with an external side effect (§8). Leave it off and the agent-facing catalogue is read-only.
- **Governance (the only write path, fail-soft)** — `SIAnalyzer__Governance__LocalRegisterEnabled` (**ON by
  default**, and set explicitly by the deploy) allows local risk-accept/exemption recording in SIA's own
  store; no platform is written. `SIAnalyzer__Governance__TableEndpoint` +
  `SIAnalyzer__Governance__TableName` point at the Azure Table that makes the register durable — without
  them it runs in-memory and the page says so (§8a). Platform exemption sync is **hard-locked off** in this
  build and cannot be enabled by config. Set `LocalRegisterEnabled=false` for a fully read-only deploy.
- **Scheduled exec-summary email (optional, fail-soft)** — OFF until configured, never crashes when
  half-configured. Set via the `SIAnalyzer__Email__*` app settings (SMTP secrets are Key-Vault-backed):
  `Enabled`, `Recipients__0/1/…`, `Cadence` (daily/weekly/monthly, default monthly), `SendAtHour` (0–23),
  `Period` (previous/month/quarter/half/year, default quarter), `BaseUrl` (→ links to `{BaseUrl}/board`),
  `OrgLabel`, and `SmtpHost` / `SmtpPort` (587) / `SmtpUseSsl` (true) / `SmtpUser` / `SmtpPassword` /
  `FromAddress`. Verify without waiting for the cadence: `GET /api/email/preview` (renders, no send) and
  `POST /api/email/send` (manual "send now"; returns `{sent, recipientCount, detail}`).
- **Scheduler send markers** — `SIAnalyzer__Schedule__TableEndpoint` + `SIAnalyzer__Schedule__TableName`
  (default `sischedule`) point at the table that records which cadence windows have been sent, so
  replicas cannot double-send and a restart cannot skip a window (§8b). Same storage account as the
  governance register; the deploy derives both endpoints from one `-StorageAccountId`. Unset ⇒ a
  process-local marker, and the scheduler warns at startup.

`deploy/Deploy-SIAnalyzer.ps1` finalizes the whole runtime in one pass with a **CEH-parity `-Env dev|prod`
split** (modelled on CEH's `tools/deploy-app.ps1`), always targeting **SecurityInsight's own resource
group — never another solution's**. Two hard guards run before anything is deployed:

- **Resource group** — the RG is derived from `-WorkspaceResourceId` (`/resourceGroups/<rg>/`, which
  *is* SI's resource group) and `-ResourceGroup` must equal it. This is an allow-list, not a
  block-list of known-bad names: any other solution's resource group is rejected, not just the one
  mistake already made. Override with `-AllowResourceGroupMismatch` only when the SI workspace
  genuinely lives in a different RG.
- **Ingress exposure** — the deploy **fails** when `ingress.external` is `true`. SIA serves
  security-posture data and must be reachable only from trusted Azure private networks; an
  internet-facing ingress stops the release. Override with `-AllowPublicIngress` for a deliberate,
  temporary public deployment. Note `external=false` requires a VNet-integrated, internal-only
  Container Apps **environment**, which is fixed at environment creation — so this gate detects and
  refuses; provisioning that environment is part of the dedicated-infra cutover.
- **Listen port** — the deploy reads `ingress.targetPort` and **refuses a mismatch with the port the
  image binds**, before the ACR build. This is a contract between two files and nothing used to check
  it: **Container Apps injects no port** (it routes ingress to the container's `--target-port`;
  `WEBSITES_PORT` is an App Service setting and does not apply), and SIA reads neither variable — it
  binds a fixed `ASPNETCORE_URLS=http://+:8080`. The deploy only ever *updates* the app, never creates
  it, so the target-port came from whatever the resource was created with, out-of-band. A mismatch was
  already caught by the health gate above, but only *after* a build and a revision, looking like an
  app fault; asserting it up front names the real cause. `$ContainerListenPort` in the deploy script is
  the single source of truth, pinned against the Dockerfile by `tests/pester/SIA-Container.Tests.ps1`.

- **Plain HTTP** — the deploy **fails** when `ingress.allowInsecure` is `true` (audit #13). This is
  where HTTPS enforcement lives, and deliberately not in the app: Container Apps terminates TLS and
  forwards plain HTTP to the container, so `UseHttpsRedirection` inside the app would see every
  request as insecure and redirect forever. Same escape hatch as the ingress gate.
- **Host filtering** — `-AllowedHosts` is always written to the app (audit #13), default `*`.
  `auto` derives `<app fqdn>;*.<parent domain>`. ⚠️ The wildcard is not optional: the prod path
  health-gates the **per-revision** fqdn (`<app>--<suffix>.<parent>`), a different host, so pinning
  to the app fqdn alone would 400 the health check and refuse the swap.

**Container identity.** The image runs as **non-root** (`USER $APP_UID`, the user the .NET 8 base
images ship). SIA writes nothing to the filesystem at run time and 8080 is unprivileged, so nothing
depends on root. The ASP.NET DataProtection key ring is the one thing that wants a writable home, and
it is ephemeral in a container either way — so cookie/antiforgery keys do not survive a restart and
are not shared between replicas. That is unchanged by this, but it is a real constraint on anything
that would later depend on them (see #14's CSRF work).

**Response security headers + CSP (audit #13).** The pipeline order is deliberate and each step
depends on the one before it:

1. **`UseForwardedHeaders` first.** Everything that asks "is this request HTTPS?" is wrong without
   it, because ACA hands the container plain HTTP plus `X-Forwarded-Proto`. This is what makes HSTS
   able to fire at all — without it `UseHsts()` emits nothing, silently.
2. **Security headers + CSP**, before the auth gate, so even a 401 carries them.
3. **`UseHsts`**, which now sees HTTPS in the hosted environment and correctly stays silent locally.

The CSP is **nonce-based**: `script-src 'self' 'nonce-<per-request>'`, plus `default-src 'self'`,
`object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, `frame-ancestors 'none'`. The nonce is
**128 bits of hex** — hex rather than base64 because base64's `+` and `/` HTML-encode to character
references, which makes the attribute differ textually from the header.

Two consequences worth stating because they constrain future work:
- **No inline `on*` handlers, anywhere.** A nonce does not whitelist them, so one returning handler
  would force `'unsafe-inline'` and make the whole policy decorative. All twelve were replaced with
  `data-` attributes and delegated listeners (which also closed #19). `SecurityHeadersTests.cs` pins
  this per surface.
- **`style-src` keeps `'unsafe-inline'`** because the pages use `style=` ATTRIBUTES, which no nonce
  can cover. Tightening it means moving every inline style into a served stylesheet.

**CSRF guard (audit #14).** State-changing requests are checked before the auth gate, because
authentication is not the control CSRF needs — and here it actively misleads: **Easy Auth sits in
front of the container**, so a signed-in victim's browser makes the platform authenticate a forged
cross-site POST and inject a valid `X-MS-CLIENT-PRINCIPAL`. The gate would pass it.

The guard is **stateless on purpose**. Antiforgery tokens are signed with the DataProtection key
ring, which is ephemeral in this container (no persisted keys, no shared storage), so tokens would
break across replicas and across every restart. Instead, in order: safe methods pass; `Origin`, if
present, must equal this request's own origin; else `Sec-Fetch-Site` must be `same-origin`/`none`;
and with no browser signals at all the request must carry a content type an HTML form cannot produce
(or an explicit `X-SIA-Request` header, for a non-browser caller that sends no body). MCP agents send
JSON and are unaffected.

⚠️ **This depends on the forwarded headers above.** `Origin` is compared against `Request.Scheme`;
behind TLS-terminating ingress the browser sends `https` while an app without `UseForwardedHeaders`
believes it is serving `http`, so removing that middleware would reject **every** same-origin POST.
The two are one design, not two independent fixes.

Real resource names live in `../internal/ENGINE-IDENTITY.md`, never in a public doc:
- **DEV** (`-Env dev`) — direct revision deploy (`az acr build` + `az containerapp update`), then the grants
  + auth + a post-deploy `/health` gate.
- **PROD** (`-Env prod`) — a **blue/green REVISION swap** (Container Apps has no App-Service slots, so the
  slot-swap is a revision swap): multiple-revision mode keeps the live revision serving while a NEW revision
  is created with 0% traffic; that revision is **warmed and HEALTH-GATED** on its per-revision FQDN — the
  script **refuses to shift traffic unless `/health` returns 200** (retrying the warm loop once on a
  transient cold-start) — then shifts 100% traffic to the healthy revision, keeping the old one for instant
  rollback. A post-deploy `/health` gate on the public FQDN follows.

Both paths then ensure the system-assigned MI, grant it **Log Analytics Reader** on the workspace,
optionally grant **Cognitive Services OpenAI User** on the AOAI account, and configure Entra Easy Auth
(`-SkipGrant` / `-SkipAuth` to run those by hand). The script prints the URL + `/health` + the live-verify
checklist. The live infra-create + the hosted run remain the main session's job (Phases 1 & 4).

### 14. Guardrail / dimension contract (shared by every surface incl. MCP)

Read-only over the canonical SI table allow-list only, enforced as a whitelist of query SOURCES (§4);
no control commands / external / cross-cluster / cross-workspace, no whole-workspace scans;
snapshot-correct (`max(CollectionTime)`); grounded AI; AI-optional / fail-soft.

### 15. Deploy command reference (placeholder-only)

> Merged here 2026-08-05 from the former `analyzer-web/deploy/README-DEPLOY.md`, which was the last
> markdown left under `analyzer-web/` — that folder now holds **code only**.
> 🔴 **This chapter is PUBLIC. Every `<...>` stays a placeholder** — the real workspace customerId,
> resource ids, subscription, resource groups, tenant and app-registration ids live ONLY in
> `../internal/ENGINE-IDENTITY.md` (stripped from every publish). Copy the values from there at run
> time; never commit them here.
> The agent that builds SIA does **not** deploy — the main session (which holds Azure credentials)
> runs these.

**One command does build + deploy + MI grant + Easy Auth.** `deploy/Deploy-SIAnalyzer.ps1` builds and
deploys the image, ensures the system-assigned Managed Identity, grants it **Log Analytics Reader**
(read-only) on the workspace, optionally grants **Cognitive Services OpenAI User** on the Azure OpenAI
account, configures Entra Easy Auth, and runs a `/health` gate. See §13 for the DEV/PROD semantics.

```powershell
# from SOLUTIONS/SecurityInsight/analyzer-web
# fill EVERY <...> from internal/ENGINE-IDENTITY.md
.\deploy\Deploy-SIAnalyzer.ps1 `
    -Env prod `
    -ResourceGroup <sia-resource-group> `
    -AcrName <acr-name> `
    -AppName <container-app-name> `
    -WorkspaceId <workspace-customerId-guid> `
    -WorkspaceResourceId "/subscriptions/<sub>/resourceGroups/<sia-resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>" `
    -OpenAiEndpoint https://<aoai-name>.openai.azure.com `
    -OpenAiDeployment <deployment-name> `
    -OpenAiAccountId "/subscriptions/<sub>/resourceGroups/<aoai-rg>/providers/Microsoft.CognitiveServices/accounts/<aoai-name>" `
    -AuthClientId <app-registration-client-id> `
    -AuthTenantId <tenant-id>
```

- `-WorkspaceId` is the **customerId GUID** the SDK queries; `-WorkspaceResourceId` is the **ARM
  resource id** of the same workspace, used as the role-grant scope. **Both are required.**
- Omit `-OpenAiAccountId` if Azure OpenAI uses a key (set `SIAnalyzer__OpenAiApiKey` as a secret env
  var instead of MI).
- `-SkipGrant` / `-SkipAuth` run those steps by hand — see below.
- The script prints the URL, `/health`, and the live-verify checklist (the release gate is
  [TESTS.md](TESTS.md) §9).
- **PROD rollback** — traffic is a revision weight, so reverting is one command:
  `az containerapp ingress traffic set -g <sia-resource-group> -n <container-app-name> --revision-weight <old-revision>=100`

**Manual MI → Log Analytics Reader** (only if you used `-SkipGrant`):

```powershell
az containerapp identity assign -g <sia-resource-group> -n <container-app-name> --system-assigned
$pid = az containerapp identity show -g <sia-resource-group> -n <container-app-name> --query principalId -o tsv
az role assignment create `
    --assignee-object-id $pid --assignee-principal-type ServicePrincipal `
    --role "Log Analytics Reader" `
    --scope "/subscriptions/<sub>/resourceGroups/<sia-resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace-name>"
# If Azure OpenAI uses MI (no key), also:
az role assignment create --assignee-object-id $pid --assignee-principal-type ServicePrincipal `
    --role "Cognitive Services OpenAI User" `
    --scope "/subscriptions/<sub>/resourceGroups/<aoai-rg>/providers/Microsoft.CognitiveServices/accounts/<aoai-name>"
```

**Manual Easy Auth (Entra)** (only if you used `-SkipAuth`):

```powershell
az containerapp auth microsoft update -g <sia-resource-group> -n <container-app-name> `
    --client-id <app-registration-client-id> `
    --issuer https://login.microsoftonline.com/<tenant-id>/v2.0
az containerapp auth update -g <sia-resource-group> -n <container-app-name> `
    --unauthenticated-client-action RedirectToLoginPage --redirect-provider azureactivedirectory
```

Register an Entra app for the Analyzer and restrict sign-in to the appropriate group. A hosted
analyzer of security findings is **never anonymous**.

**Local build / test / preview:**

```powershell
dotnet build SIAnalyzer.sln -c Release
dotnet test  SIAnalyzer.sln -c Release
dotnet run --project src/SIAnalyzer.Web    # local preview (demo data, AI-off)
```
