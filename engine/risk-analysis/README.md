# SecurityInsight v2.2 — Risk Analysis Queries

## Engine contract (matches today)

The `SecurityInsight_RiskAnalysis` engine reads **exactly two files** from `risk-analysis-detection/`:

| File | Purpose |
|---|---|
| `RiskAnalysis_Queries_Locked.yaml`   | Curated set, ships in repo |
| `RiskAnalysis_Queries_Custom.yaml`   | Customer additions / overrides |

**v2.2.228+** — `$global:SettingsPath` is no longer required. The engine walks up from its own `$PSScriptRoot` looking for a `risk-analysis-detection/` sibling (depth cap 6) and finds the YAMLs there. Same walk-up applies to `riskscore_weighted.schema.custom.json` (the weighted-factors config used by `Get-WeightedFactorsConfig`). Set `$global:SettingsPath` explicitly only when shipping the YAML / JSON outside the standard `SOLUTIONS/SecurityInsight/risk-analysis-detection/` layout — the launcher then honors the override.

## Folder layout

```
SOLUTIONS/SecurityInsight/
├── risk-analysis-detection/                      <- the catalog the engine READS
│   ├── RiskAnalysis_Queries_Locked.yaml     (118 reports, 4 templates -- SOURCE OF TRUTH)
│   ├── RiskAnalysis_Queries_Dev.yaml        (developer-only, gitignored)
│   └── RiskAnalysis_Queries_Custom.sample.yaml   (customer override, wins last)
└── engine/risk-analysis/
    ├── Invoke-RiskAnalysis.ps1               <- the engine
    ├── _shared/                              <- RA-*.ps1, dot-sourced in place (audit #16)
    ├── tools/                                <- helpers; NONE of them rebuild the catalog
    │   ├── Build-QueriesDoc.ps1              <- generates DOCS from the catalog
    │   └── Fix-CollectionTimeWhere.ps1
    ├── _samples/
    └── README.md
```

🔒 **Authoring loop: edit `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` directly.**
It is hand-maintained and is the source of truth. Nothing generates it.

**Audit #28 (2026-08-06) — the old authoring loop this README described was retired, and its inputs
and tool deleted.** It said: *"edit Summary YAML in `_source/`, then run `Build-RiskAnalysis.ps1`
once — it regenerates Detailed siblings and rebuilds the locked file."* That had been dead for
months: `_source/` and the consolidator went untouched since commit `536e1405` (the v2.2.0 flatten)
while the catalog was edited continuously. Rebuilding would have produced **264 reports instead of
118**, dropped 57 shipped reports, added 203 that never shipped, and renamed the templates to
`*_Bucket` — leaving the launcher's `RiskAnalysis_Summary` undefined and making the engine **throw on
every run**.
*(This file was doubly stale: it also described `locked/`, `custom/` and `_legacy/` folders that no
longer exist, and named `Build-DetailedCompanions.ps1` and `Build-RiskAnalysisV22Consolidated.ps1`,
neither of which existed. Corrected against the tree above.)*
Recover the old inputs from git if ever needed:
`git show 536e1405:SOLUTIONS/SecurityInsight/engine/risk-analysis/_source/`

**Per-report bucket metadata** (preserves the v2.1 `UseQueryBucketing=true` pattern for heavy reports). Add a `ReportTemplate:` block on any source-yaml Report to opt in:

```yaml
- ReportName: Endpoint_Missing_CVEs_Detailed_v22
  ReportTemplate:
    UseQueryBucketing:      true
    DefaultBucketCount:     2
    BucketPlaceholderToken: __BUCKET_FILTER__
  ReportPurpose: ...
```

Without the block, defaults to `UseQueryBucketing=false / DefaultBucketCount=1`. Hand-edits to `ReportTemplates[]` in the locked file are NOT preserved across rebuilds — put bucket settings in the source yaml's per-report block (it's the source of truth).

## Catalog summary

| Wave | What | Count |
|---|---|---|
| 0  | Sample reference queries | 3 |
| 1  | Identity (16) | 16 |
| 2  | Endpoint (12) | 12 |
| 3  | Azure (12) | 12 |
| 4  | Cross-engine + Hygiene (10) | 10 |
| 5  | NEW findings (Identity 8 + Endpoint 6 + Azure 10 + CrossEngine 4 + Hygiene 2) | 30 |
| 6  | Detailed companions (auto-generated, 1:1 with Summary) | 80 |
| **Total in `locked/RiskAnalysis_Queries_Locked.yaml`** | | **160** |

## v2.1 → v2.2

| | v2.1 | v2.2 |
|---|---|---|
| Total reports | 106 | **160** |
| Unique findings | 53 | **80** |
| Source-of-truth columns | tag arrays + EG rawData | **typed flat columns (169 endpoint, 146 identity, 308 azure)** |
| Cross-engine joins | manual | **schema-driven** |
| `MoreInfoUrl` / `Links` | none | **on every Wave-5 report**; Wave-1-4 inherit via Detailed projection |
| Tag-string parsing in queries | yes | **none** (tags absorbed at profile time → typed columns) |
| Risk-factor pre-derivation | none | **23 derived flat cols** (`UnsupportedOSDetected`, `IsOrphanSPN`, `HasOpenAdminPort`, `RiskFactorCount`, …) |
| Schema declaration | implicit | `schemaVersion 2.3.4` |

## Cross-engine join keys

| Key | Endpoint | Identity | Azure |
|---|---|---|---|
| `AzureResourceId` | when device is Azure VM | n/a | primary |
| `AadDeviceId` | yes | yes (device-bound MFA) | n/a |
| `Upn` / `AppId` | n/a | yes | RBAC `assignedIdentity` |
| `cmdbId` | yes | yes | yes |
| `MachineGroup` (MDE) | yes | n/a | n/a |

## Conventions

- Latest snapshot per query: `where CollectionTime == toscalar(<table> | summarize max(CollectionTime))`
- 100% zero-footprint: typed columns + `ExposureGraph*` joins only. Raw tag arrays are absorbed at profile time via `hasTag` and surface as typed columns (`cmdbId`, `cmdbName`, `SIRules`, …) — queries never re-parse them.
- Standard `OutputPropertyOrder` shape so PowerBI / Workbook / CSV templates stay unchanged.
- `MoreInfoUrl` (string) + `Links` (dynamic `[{label,url}]`) on Wave-5 reports for clickable remediation references in dashboards.
