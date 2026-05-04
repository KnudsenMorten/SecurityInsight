# SecurityInsight v2.2 — Risk Analysis Queries

## Engine contract (matches today)

The `SecurityInsight_RiskAnalysis` engine reads **exactly two files** from `$global:SettingsPath`:

| File | Purpose |
|---|---|
| `RiskAnalysis_Queries_Locked.yaml`   | Curated set, ships in repo |
| `RiskAnalysis_Queries_Custom.yaml`   | Customer additions / overrides |

No code change to the engine. Operator flips from v2.1 → v2.2 by re-pointing `$global:SettingsPath`:

```powershell
# in config/SecurityInsight.custom.ps1
$global:SettingsPath = '<repo>/SOLUTIONS/SecurityInsight/risk-analysis-detection'
# (custom yaml in v2.2/risk-analysis-detection/ is picked up via $global:ReportSettingsFileCustom default name)
```

## Folder layout

```
v2.2/engine/risk-analysis/
├── locked/                                       <- engine reads ONE file from here
│   └── RiskAnalysis_Queries_Locked.yaml   (160 reports, auto-built)
├── custom/                                       <- engine reads ONE file from here
│   └── RiskAnalysis_Queries_Custom.yaml   (customer-edited)
├── _source/                                      <- per-domain authoring source files
│   ├── SecurityInsight_RiskAnalysis_Azure_Locked.yaml          (12 Summary)
│   ├── SecurityInsight_RiskAnalysis_Azure_Detailed_Locked.v22.yaml   (12 Detailed, auto)
│   ├── SecurityInsight_RiskAnalysis_CrossEngine_Locked.yaml    (10 Summary)
│   ├── ... (one Summary + one Detailed per domain)
│   └── SecurityInsight_RiskAnalysis_NewFindings_Locked.yaml    (30 Wave-5 Summary)
├── _legacy/                                      <- frozen v2.1 snapshot
│   ├── RiskAnalysis_Queries_Locked.v2_1.yaml   (104 reports, ref only)
│   └── RiskAnalysis_Queries_Custom.v2_1.yaml
├── tools/                                        <- build helpers
│   ├── Build-DetailedCompanions.ps1                            <- run after editing _source/
│   └── Build-RiskAnalysisV22Consolidated.ps1                   <- writes the locked/ file
└── README.md
```

**Authoring loop**: edit Summary YAML in `_source/`, then run `tools\Build-RiskAnalysis.ps1` once — it (1) regenerates Detailed siblings and (2) rebuilds the single locked file with `Reports[]` + auto-generated `ReportTemplates[]` (Summary + Detailed buckets) at the bottom. Operator never touches `_source/` directly; the engine only sees `locked/` + `custom/`.

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
