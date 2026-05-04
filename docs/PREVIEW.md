# SecurityInsight v2.2 — Preview Architecture

**Status:** preview-only. Side-by-side with v2.1.x stable. No data migration. Customers opt in per-engine.
**First tag:** `v2.2.0-preview.1`
**Branch:** `preview/v2.2` (cut from `dev` at v2.1.214)
**Stable channel (`dev` / v2.1.x):** continues with bug fixes + small features only — no architectural changes.

---

## 1. Why a v2.2

v2.1 writes Defender asset tags as the source of truth. v2.2 inverts that: **zero footprint on the asset itself**, all state lives in our own LA tables + storage account. Same value (tier, classification, posture proofs) — none of the tag pollution, no clash with the customer's own tagging, works on assets Defender can't tag (Azure resources, on-prem-only servers).

---

## 2. Engine roster

| Engine | Scope | Status |
|---|---|---|
| **endpoint** | servers + workstations from MDE + EG + Intune | **build first** (proves framework) |
| **identity** | users + service accounts from Entra + MDI | refactor of v2.1 IdentityAssets onto v2.2 framework |
| **azure** | Azure resources via ARG + ARM | new |

All three share one framework. Engine = a folder with its own `catalog/`, YAML rules, AI prompts, and `<engine>_*_CL` table names. Adding a fourth engine later (network, SaaS, OT) = copy folder, fill in.

---

## 3. Pipeline (6 stages)

```
[0 Schedule] -> [1 Discover] -> [2 Collect] -> [3 Enrich] -> [4 Classify] -> [5 Output]
```

| # | Stage | Owns | Skip-gate |
|---|---|---|---|
| 0 | **Schedule** | tier-driven cadence (T0=4h, T1=24h, T3=7d, TE=30d) | — |
| 1 | **Discover** | enumerate in-scope assets, hand off shards to workers | — |
| 2 | **Collect** | source tables (MDE Device*, installed apps, OS/HW/owner/tags), write `<engine>_Metadata_CL`, compute `fp_meta` from vital props + existing tier checksum | if `fp_meta` unchanged AND prior tier still valid -> write "revalidated" row, skip stages 3 + 4 |
| 3 | **Enrich** | "has-access-to" + sign-ins, locked + custom YAML KQL posture rules, external REST + external LA tables, write `<engine>_Enrichment_CL`, compute `fp_enrich` | if `fp_enrich` unchanged -> reuse cached AI verdict, skip stage 4 |
| 4 | **Classify** | AI: ServiceName, ServiceType (WebApp/Intranet/ExchangeServer/...), effective tier + tier proofs, external-risk severity tags, grouping (ip / rg / sub / servername-pattern), write `<engine>_Classification_CL` | — |
| 5 | **Output** | sinks: LA (default), JSON, Excel, optional Microsoft Fabric Eventhouse | — |

**Risks live in the separate RiskAnalysis engine** — it joins back via `AssetId` against `<engine>_Classification_CL`. RA stays unchanged.

---

## 4. Skip model — fingerprints

Two fingerprints, two skip-gates. ~85% of endpoints day-to-day will have unchanged `fp_meta` AND `fp_enrich` -> "revalidated" row only, zero AI spend.

```
fp_meta    = sha256(OS, owner, subnet, naming, hardware, mgmt-state, installed-apps-set)
fp_enrich  = sha256(logon-set, primary-user, posture-rule-hits, external-enrichment-output)
```

Cached verdict TTL (force re-judge after N days even if `fp_enrich` unchanged) is the safety net for prompt-template evolution.

Fingerprint cache: Azure Table Storage, `PartitionKey=AssetId`, `RowKey=current`, columns `fp_meta / fp_enrich / si_tier / si_verdict / verdict_expires_at / stable_run_count`.

---

## 5. Storage stack — one Azure Storage account

| Concern | Service | Layout | Approx cost @ 1M endpoints |
|---|---|---|---|
| Fingerprint cache (hot) | **Azure Table Storage** | `PartitionKey=AssetId, RowKey=current` | ~$5–10/mo |
| Stage payload staging (warm, intra-run handoffs across collector workers) | **Azure Blob (block blob, JSONL)** | `staging/{runId}/{stage}/shard-NNN.jsonl`, 7-day lifecycle rule | ~$30/mo |
| Worker coordination | **Azure Storage Queue** | one queue per stage, lease-based, 7-day TTL | <$1/mo |
| Query sink (default) | **Azure Log Analytics** | `<engine>_Metadata_CL`, `<engine>_Enrichment_CL`, `<engine>_Classification_CL` | LA ingest cost (per-customer existing) |

Output stage also supports **JSON file dump** (file system) and **Excel summary** as additional sinks.

Optional Eventhouse sink for customers on Microsoft Fabric — see § 9.

Multi-writer-safe by design (each shard writes its own blob / its own `PartitionKey`). No locks.

---

## 6. Column-naming convention — source-prefixed

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

---

## 7. Asset Mapping YAML — replaces Critical Asset Tagging

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

---

## 8. AI cost ceiling

`$global:MaxAiSpendPerRun` (USD, soft cap) baked into Classify from preview.1. Run aborts Classify when reached, Output still writes a partial classification with `SI_Classify_Status='budget-capped'`. Operator sees it in the daily Excel summary.

---

## 9. Optional output sink — Microsoft Fabric Eventhouse

Customers already on Fabric can opt-in to an additional Output sink that writes the same `<engine>_Classification_CL` snapshots into a Fabric **Eventhouse**. Eventhouse is the managed Kusto/ADX engine inside Fabric; data physically lands as Delta Parquet in OneLake (ADLS Gen2 underneath), and the same files are reachable from Power BI, Spark, T-SQL endpoint, and Python without copies.

The win for customers who turn it on: native KQL **graph operators** (`make-graph`, `graph-match`, `graph-shortest-paths`) over the snapshots — no separate graph DB needed. Source-prefix column convention (§ 6) makes node/edge extraction mechanical.

For everyone else: LA remains the default sink. Eventhouse adds zero cost when not enabled.

**Deferred from preview.1:** Eventhouse sink implementation — lands in preview.2 once the snapshot shape is stable. preview.1 ships LA + JSON + Excel sinks.

---

## 10. Branch + build plan

| Phase | Deliverable |
|---|---|
| **A** | Framework scaffolding: `catalog/`, `posture-rules-locked/`, `findings-schema/`, fingerprint engine, storage adapters (Table / Blob / Queue), orchestrator skeleton |
| **B** | **Endpoint engine** end-to-end with LA + JSON + Excel sinks |
| **C** | **Identity engine** refactored onto v2.2 framework |
| **D** | **Azure engine** new |
| **E** | Optional **Eventhouse sink** for Fabric customers + first `make-graph` queries on snapshots |

External enrichment plug-ins (MS EASM, Shodan, etc.): architecture supports from Phase A, all disabled by default in preview.1.

---

## 11. Out of scope / explicitly NOT in v2.2

- Risk scoring (stays in RiskAnalysis engine; joins via `AssetId`)
- Tag-removal cleanup script (handled by user's own maintenance script)
- Migration tooling (side-by-side, no data move)
- Cosmos Gremlin / Neo4j (any future graph use rides Eventhouse's `make-graph` over the same snapshots)
- v2.1 architectural changes (stable channel = bug-fixes + small features only)

---

## 12. preview.1 contents

This commit ships:
- `PREVIEW.md` — this document
- `catalog/endpoint/MDE-DeviceLogonEvents.yaml` — sample source-table catalog entry
- `posture-rules-locked/endpoint/ExchangeServerDetection.yaml` — sample posture rule (Asset-Mapping-YAML schema in production form)
- `findings-schema/endpoint-classification.yaml` — stable schema contract for `Endpoint_Classification_CL`
- `Get-FingerprintEngine.ps1` — PS 5.1 fingerprint helper (used by Collect + Enrich stages)

No runnable orchestrator yet — preview.1 is design + contracts + one helper. Phase A code lands in preview.2.
