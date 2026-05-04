# SecurityInsight -- Asset-profiling schema JSON reference

This is the **single source of truth** for the per-engine schema files (`endpoint.schema.locked.json`, `identity.schema.locked.json`, `azure.schema.locked.json`, `publicip.schema.locked.json`) and their `.custom.json` overlay siblings. Every field below is grounded in `engine/asset-profiling/shared/Get-SISchemaWithCustomMerge.ps1` -- if a key isn't here, the engine doesn't read it.

> **Authority**: validated against `Get-SISchemaWithCustomMerge.ps1` (the loader+merger, lines 86-170), `Build-EndpointProfileRow.ps1` (the consumer, lines 699-810), `Test-SISchemaCompliance.ps1` (the linter, lines 242-256), and `SCHEMA.locked.json` (the meta-schema). When code disagrees with this doc, code wins.

---

## File pairs

| File pattern | Purpose | Edited by |
|---|---|---|
| `<engine>.schema.locked.json` | Shipped baseline column inventory for `SI_<Engine>_Profile_CL` | Maintainer |
| `<engine>.schema.custom.json` | Customer overlay (gitignored) | Customer |
| `SCHEMA.locked.json` | Meta-schema -- vocabularies, DAG rules, contract for the per-engine files | Maintainer |
| `tools/Dedup-SchemaFields.ps1` | Linter / cleanup helper | Maintainer |

`<engine>` = `endpoint` / `identity` / `azure` / `publicip`.

---

## Top-level structure

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
| `table` | string | yes | Target Log Analytics table (e.g. `SI_Endpoint_Profile_CL`). Read by `Invoke-Output.ps1` to route DCR ingest. |
| `dcrName` | string | yes | DCR name. Read by `Invoke-Output.ps1`. |
| `extends` | string | yes | Reference to `SCHEMA.locked.json`. Documentation-only -- the loader doesn't auto-load the meta-schema. |
| `sourcesConsumed` | `[string,...]` | yes | Discovery providers this engine pulls from. Lints against the source vocabulary in `SCHEMA.locked.json`. |
| `entityIds` | object | yes | Cross-engine join keys. `primaryPriority` is the order tried when joining; `expectedTypes` lints incoming asset types; `hubJoin` is the canonical id used in cross-engine lookups. |
| `hashes` | object | yes | Per-stage content hashes for cache invalidation. Engine doesn't write these; they're generated. |
| `rawPayload` | object | yes | Where the source JSON blobs land. `storageColumn` = LA column name; `sources.<src>.includePaths` = JSON pointer list of fields kept in the blob; truncation strategy if the blob exceeds the LA cell limit. |
| **`fields`** | `[object,...]` | yes | **The big one.** One entry per LA column. See "Per-field shape" below. |
| `aggregator` | object | optional | Tier-roll-up rules: `contributors[]` lists the inputs the engine reduces over (one entry per AssetProfileBy* rule family + per CMDB source). |

---

## `fields[]` -- per-field shape

Every column the engine ever emits to LA appears here exactly once.

| Key | Type | Required | Code (consumer) | Meaning |
|---|---|---|---|---|
| `name` | string | yes | `Build-EndpointProfileRow.ps1:709` | LA column name. PascalCase, no `SI_` prefix. |
| `type` | string | yes | `Build-EndpointProfileRow.ps1:709` | LA type: `string` / `int` / `bool` / `datetime` / `real` / `dynamic`. |
| `purpose` | string | yes | `Build-EndpointProfileRow.ps1:701` (filter), `Test-SISchemaCompliance.ps1:244` (vocabulary lint) | Semantic role -- one of `identity`, `correlation`, `risk`, `posture`, `lifecycle`, `freshness`, `pivot`, `kpi`, `compliance`, `attribution`, `policy`, `enrichment`, `forensic`, `raw`. Drives which RA reports auto-include the column. |
| `source` | string | yes | `Build-EndpointProfileRow.ps1:704` | Origin: `mde`, `entra`, `azure`, `exposureGraph`, `derived`, `cmdb`, `signInLogs`, `shodan`, `ad`. Routes value resolution to `Resolve-SISourceValue` (or `Get-SIDerivedValue` for `derived`). |
| `sourcePath` | string | optional | docs only | Human-readable pointer into the source blob (e.g. `mde.machine.id`). Surfaces in `docs/asset-profiling-schema.md`. |
| `stage` | object `{writtenBy, readBy[]}` | yes | `Build-EndpointProfileRow.ps1:783-786` (hash bucketing); `SCHEMA.locked.json:111-119` (DAG validation) | `writtenBy` is the single phase that emits the value (`collect`, `enrich`, `posture_analyze`, `classify`, `profile`, `reconcile`). `readBy` is the list of consumers (`classify`, `dashboard`, `risk-analysis`). |
| `default` | any | optional | `Build-EndpointProfileRow.ps1:709` (implicit when source returns null) | Fallback. Type must match `type`. |
| `addedIn` | string | optional | docs only | Semantic version when the field landed (e.g. `2.2.0`). |
| `description` | string | optional | docs only | One-liner of what the column means. |
| `derivation` | object | required when `source: derived` | `Build-EndpointProfileRow.ps1:705` (dispatcher) | `algorithm` (e.g. `min_tier_over_catalog_match`, `pass_through`, `coalesce_then_default`); optional `inputs[]` listing the field names the derivation consumes (used for DAG validation -- inputs MUST be `writtenBy` an earlier stage). |
| `emit` | bool | optional, default `true` | `Build-EndpointProfileRow.ps1:700` | When `false`, the field is computed but NOT written to LA. Use for internal-only schema artifacts. |
| `usedBy` | `[string,...]` | optional | linter | Which posture rules / aggregator contributors reference this field. Helps the linter detect orphans. |
| `algorithm` | string | optional (in `aggregator.contributors[]`) | `SCHEMA.locked.json:203-222` | Tier-reduction algorithm for an aggregator contributor (e.g. `min_tier_over_catalog_match`). |
| `required` | bool | optional | not consumed | LA enforces nullability client-side; the engine does not. |

---

## Custom-overlay merge semantics

The engine loads BOTH `<engine>.schema.locked.json` AND `<engine>.schema.custom.json` (when the latter exists) and merges them via `Get-SISchemaWithCustomMerge.ps1` lines 86-170. The merged result is cached in `$script:_SISchemaMergeCache[$Engine]`.

| Section | Merge rule | Example |
|---|---|---|
| `fields[]` | by `name`: same name -> custom **REPLACES** the locked entry; new name -> **APPENDED** | Override `OsPlatform.default`, or add a brand-new `MyCustomTag`. |
| `aggregator.contributors[]` | by `id`: same id -> **REPLACES**; new id -> **APPENDED** | Bump the weight on an existing contributor or add a new tier-source rule family. |
| `rawPayload.sources.<src>.includePaths[]` | **UNION** (locked first, then custom additions, deduped) | Add extra MDE `DeviceInfo` fields without removing locked ones. |
| `rawPayload.sources.<new-src>` | new source bucket -> **ADDED** | Add a custom source bucket like `tanium`, with its own `includePaths`. |
| `hashes`, `entityIds`, engine metadata, `extends`, `aiEligibility` | **NOT mergeable** -- engine invariants | If you set them in custom, the loader ignores them. |

---

## How to add a new column to `SI_Endpoint_Profile_CL`

Create `asset-profiling-schema/endpoint.schema.custom.json` (if it doesn't exist) and add the field:

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

Then implement the value computation in the `enrich` stage:

- `engine/asset-profiling/stages/Invoke-Enrich.ps1` (or a dedicated helper)
- Routed via `Get-SIDerivedValue` because `source: derived`.

Re-run the engine. The DCR will need an explicit update for the new column to flow into LA -- the engine logs `SchemaDiff` on each run; see `engine/asset-profiling/stages/Invoke-SchemaDiff.ps1`.

---

## How to override an existing column

Repeat the locked entry's `name` in the custom file. The custom entry FULLY REPLACES the locked entry -- copy the locked block, edit what you want, paste:

```json
{
  "fields": [
    {
      "name": "OsPlatform",
      "type": "string",
      "purpose": "identity",
      "source": "mde",
      "stage": { "writtenBy": "collect", "readBy": ["classify","dashboard"] },
      "default": "Unknown"          // <-- changed from "" to "Unknown"
    }
  ]
}
```

---

## Engine consumers (where the schema is read)

| File | Lines | What it reads |
|---|---|---|
| `Get-SISchemaWithCustomMerge.ps1` | 34-180 | Loads + merges + caches |
| `Build-EndpointProfileRow.ps1` | 699-810 | `fields[*]` (name, type, source, purpose, stage, emit, derivation) -- emits flat columns + the Properties JSON blob |
| `Build-IdentityProfileRow.ps1` | similar pattern | Identity row builder |
| `Build-AzureProfileRow.ps1` | similar pattern | Azure row builder |
| `Build-PublicIpProfileRow.ps1` | similar pattern | PublicIP row builder |
| `Invoke-Output.ps1` | output stage | `table`, `dcrName` -- routes the row batch to the right LA table / DCR |
| `Test-SISchemaCompliance.ps1` | 242-256 | Lints `fields[*]`, `aggregator`, references |
| `Invoke-SchemaDiff.ps1` | DAG analysis | Compares schema between runs to detect breaking column changes |
| `tools/Dedup-SchemaFields.ps1` | maintainer-only | Detects duplicate `name` entries inside one file |

---

## See also

- `SCHEMA.locked.json` -- meta-schema with the source / purpose / stage vocabularies
- `docs/asset-profiling-schema.md` -- machine-generated per-engine column list (regenerated on schema change)
- [`../asset-profiling-enrichment/RULE-REFERENCE.md`](../asset-profiling-enrichment/RULE-REFERENCE.md) -- AssetProfileBy* rule grammar (the rules that `aggregator.contributors[]` references)
- [`../privilege-tier-catalog/CATALOG-REFERENCE.md`](../privilege-tier-catalog/CATALOG-REFERENCE.md) -- tier catalog consumed by aggregator algorithms
