# SecurityInsight -- Risk-score weighted-factor JSON reference

This is the **single source of truth** for `riskscore_weighted.schema.custom.json` and its `.sample` companion. Every field below is grounded in `engine/risk-analysis/Invoke-RiskAnalysis.ps1` -- if a field isn't here, the engine doesn't read it.

> **Authority**: validated against `engine/risk-analysis/Invoke-RiskAnalysis.ps1` — `Get-WeightedFactorsConfig` (loads `riskscore_weighted.schema.custom.json`), `Build-WeightedFactorsKql` (emits the per-field case() + `RiskScore_Weight_Factor` + `RiskScore_Weight_Detailed` columns), and the Layer-3 application loop (multiplies `RiskScoreTotal` by `RiskFactor_Weight`). When code disagrees with this doc, code wins.
>
> **v2.2.228**: `Get-WeightedFactorsConfig` no longer requires `$global:SettingsPath`. It walks up from the engine's `$PSScriptRoot` looking for a `risk-analysis-detection/` sibling at every level (depth cap 6). Per-report `<ReportName>.weighted.custom.json` overrides the solution-wide `riskscore_weighted.schema.custom.json`. Each successful load emits `[INFO] [weight] <Report> (engine=<x>): N field(s), source=<path>`; a miss emits a `[WARN]` naming the searched dirs so misconfigs are visible at runtime.

---

## File pair

| File | Purpose | Edited by |
|---|---|---|
| `riskscore_weighted.schema.custom.json` | Active config consumed by every report | Customer (or maintainer pre-shipped) |
| `riskscore_weighted.schema.custom.sample.json` | Annotated starter copy | Maintainer |

There is no `.locked.json`. The custom file IS the source of truth -- there's no merge.

---

## Three-layer risk model (the big picture)

The engine computes a single `RiskScoreTotal_Weighted` per row in three stages. Every section in this JSON tunes one stage.

| Layer | Formula | What this JSON tunes |
|---|---|---|
| **1. Base** | `consBase = lookup(...,SecuritySeverity)` and `probBase = lookup(...,CriticalityTierLevel)` from `riskscore.index.custom.csv` | `impactNormalizer`, `severityMapper`, `tierMapper` (label translation that drives the lookup) |
| **2. Additive adjustment** | `consAdj = consBase + RiskFactor_Consequence`; `probAdj = probBase + RiskFactor_Probability`; `RiskScoreTotal = consAdj * probAdj` | `riskFactorDetailedMapper`, `riskFactorProbabilityMapper` (which bools count) |
| **3. Multiplicative business multiplier** | `RiskScoreTotal_Weighted = floor(RiskScoreTotal * RiskFactor_Weight / 100.0)` | `weightedRiskFactors` (this is the big one) |

All multipliers in Layer 3 are stored as **basis-100 integers**: `100 = 1.0x`, `150 = 1.5x`, `262 = 2.62x`. This dodges locale-decimal traps (da-DK parses `"1.5"` as `15`).

---

## Top-level fields

| Field | Type | Default | Code | Meaning |
|---|---|---|---|---|
| `outputColumn` | string | `RiskScoreTotal_Weighted` | line 14 | Final weighted-score column name. |
| `baseColumn` | string | `RiskScoreTotal` | line 14 | Unweighted column the multiplier feeds on. |
| `combiner` | string | `RiskScoreTotal * (1.0 + sum(weight_i * factor_i))` | line 15, doc-only | Documents the combine formula. Engine math is hardcoded at line 3132. |
| `rounding` | string | `toint(round(<result>))` | line 16, doc-only | Documents rounding. Engine uses `[int][math]::Floor()` at line 3144. |
| `kqlSafetyNote` | string | n/a | line 17 | Documents the `column_ifexists()` wrap pattern used by the consolidator when generating KQL. |

The two `*Column` strings ARE consumed (they decide which row property the engine reads / writes). The `combiner` / `rounding` / `kqlSafetyNote` strings are documentation only.

---

## `impactNormalizer` -- raw severity -> 0..10 numeric

Converts string severities (`"High"`, `"Sev1"`, `"informational"`) and free-text into a numeric 0..10 scale, the input to `severityMapper`.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `Impact` | KQL column read |
| `outputColumn` | string | `Impact` | KQL column written (usually same as source, in-place) |
| `stringMap` | object {string:number} | (see below) | Case-insensitive value -> numeric |
| `default` | number | `0.0` | Used when input is null OR missing OR doesn't match any key |

**Default `stringMap`**:

```json
{ "critical": 10.0, "very high": 10.0, "high": 8.0, "medium": 5.0, "moderate": 5.0, "low": 2.0, "informational": 1.0, "info": 1.0 }
```

**Use case**: add `"sev1": 10.0, "sev2": 7.0` etc. when ingesting ServiceNow incidents that ship sev numbers, not labels.

---

## `severityMapper` -- numeric Impact -> human label

Converts the normalised 0..10 number into the labels used in Excel + filtering.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `Impact` | numeric input |
| `outputColumn` | string | `SecuritySeverity` | label output |
| `thresholds` | `[{min:number,label:string}, ...]` | (see below) | Descending min -> label rules. First match wins. |
| `default` | string | `Low` | Used when no threshold matched |

**Default `thresholds`**:

```json
[ { "min": 9.0, "label": "Very High" }, { "min": 7.0, "label": "High" },
  { "min": 4.0, "label": "Medium" },    { "min": 0.1, "label": "Low" } ]
```

**Use case**: lower the `High` threshold to 6.5 so borderline-high CVEs trigger High routing.

---

## `tierMapper` -- numeric tier -> human label

| Field | Type | Default | Meaning |
|---|---|---|---|
| `sourceColumn` | string | `CriticalityTier` | integer 0..3 input |
| `outputColumn` | string | `CriticalityTierLevel` | label output, fed into the Layer-1 lookup |
| `valueMap` | object {"0":string,"1":string,"2":string,"3":string} | (see below) | Tier number -> label |
| `default` | string | `Low - tier 3` | Used when tier null or missing |

**Default `valueMap`**:

```json
{ "0": "Critical - tier 0", "1": "High - tier 1", "2": "Medium - tier 2", "3": "Low - tier 3" }
```

**Use case**: rename to internal terminology like `"Crown Jewel (T0)"`. Make sure your `riskscore.index.custom.csv` agrees -- the labels must match.

---

## `criticalityMultiplierMapper` -- legacy single-field weight (deprecated)

Old single-column weighting. Superseded by `weightedRiskFactors` below. Only fires when `weightedRiskFactors` has no entry for the active engine.

| Field | Default |
|---|---|
| `sourceColumn` | `cmdbCriticality` |
| `outputColumn` | `RiskFactor_Weight` |
| `valueMap` | `{ "Critical": 1.50, "High": 1.25, "Medium": 1.10, "Low": 1.00 }` |
| `default` | `1.00` |

Note: legacy uses **decimal** multipliers, not basis-100. Use `weightedRiskFactors` for new work.

---

## `weightedRiskFactors` -- Layer 3 multi-field business multiplier (the important one)

Cross-engine, multi-field weighting on basis-100 integers. **This is the engine's primary CMDB amplification mechanism.**

### Top-level shape

```json
"weightedRiskFactors": {
  "endpoint": { "combine": "...", "maxMultiplier": <int>, "fields": [...] },
  "identity": { "combine": "...", "maxMultiplier": <int>, "fields": [...] },
  "azure":    { "combine": "...", "maxMultiplier": <int>, "fields": [...] }
}
```

### Per-engine sub-object

| Field | Type | Default | Meaning |
|---|---|---|---|
| `combine` | `product` / `max` / `sum-of-deltas` | `product` | How per-field multipliers fold together. |
| `maxMultiplier` | int (basis-100) | `0` (no cap) | Safety ceiling. Set to `500` to cap at 5.0x. |
| `fields` | `[{field,valueMap,default}, ...]` | required | Per-column lookups (see next). |

### Per-field entry

| Field | Type | Required | Meaning |
|---|---|---|---|
| `field` | string | yes | Column name on the row (e.g. `cmdbCriticality`, `cmdbDataSensitivity`). |
| `valueMap` | object {string:int} | yes | Case-insensitive value -> basis-100 integer multiplier. |
| `default` | int | no (default `100`) | Used when value not in map or column missing/null. `100` = no amplification. |

### Combine modes (worked over `cmdbCriticality=Critical (150)` + `cmdbDataSensitivity=Restricted (175)`)

| Mode | Math | Result |
|---|---|---|
| `product` | `(150/100) * (175/100) * 100 = 262` | **262** (2.62x) |
| `max` | `max(150, 175)` | **175** (1.75x) |
| `sum-of-deltas` | `100 + (150-100) + (175-100)` | **225** (2.25x) |

### Default endpoint config (lines 91-117 of the active JSON)

```json
"endpoint": {
  "combine": "product",
  "maxMultiplier": 0,
  "fields": [
    { "field": "cmdbCriticality",
      "valueMap": { "Critical": 150, "High": 125, "Medium": 110, "Low": 105 },
      "default": 100 },
    { "field": "cmdbDataSensitivity",
      "valueMap": { "Restricted": 175, "Confidential": 150, "Internal": 125, "Public": 110 },
      "default": 100 }
  ]
}
```

### Use cases

- **Add a third axis** (e.g. cost-centre): drop a new `{field, valueMap, default}` into `fields[]`. No engine code change.
- **Cap runaway multiplication**: set `maxMultiplier: 500` (5.0x cap).
- **Switch to conservative additive math**: change `combine` to `sum-of-deltas`.
- **Disable Layer 3 entirely**: omit the engine's section -- the engine reads `RiskFactor_Weight = 100` and `RiskScoreTotal_Weighted == RiskScoreTotal`.

After editing this JSON, re-run `engine/risk-analysis/tools/Build-RiskAnalysis.ps1` so the consolidator regenerates the `__WEIGHTED_FACTORS__` blocks inside the report KQL.

---

## `riskFactorDetailedMapper` -- which bools surface in the per-row "why" string

| Field | Default |
|---|---|
| `outputColumn` | `RiskFactor_Probability_Detailed` |
| `perEngineFields` | `{ endpoint: ["IsStaleAsset"], identity: ["IsExternalIdentity"], azure: [] }` |

The consolidator AUTOMATICALLY includes every `bool` column in the profile schema with `purpose: risk` (no need to list those). `perEngineFields` is for **non-risk-purposed** bools you want to count anyway. Output is a semicolon-joined string like `"IsStaleAsset; OutdatedOS"`.

---

## `riskFactorProbabilityMapper` -- counter that feeds Layer 2

| Field | Default |
|---|---|
| `outputColumn` | `RiskFactor_Probability` |

Just the integer count of `true` risk-factor bools on each row. Added to `probBase` (line 3118).

---

## End-to-end worked example

**Asset**: server, `cmdbCriticality=Critical`, `cmdbDataSensitivity=Restricted`, `SecuritySeverity=High`, `CriticalityTier=0`, two risk-factor bools fired (`IsStaleAsset`, `OutdatedOS`).

**Layer 1**:

| Step | Computation | Result |
|---|---|---|
| `Impact` | `impactNormalizer`: `"High"` -> 8.0 | **8.0** |
| `SecuritySeverity` | `severityMapper`: 8.0 -> `"High"` | `"High"` |
| `CriticalityTierLevel` | `tierMapper`: 0 -> `"Critical - tier 0"` | `"Critical - tier 0"` |
| `consBase` | `lookup(Endpoint, Cat, SubCat, "High")` | **3** |
| `probBase` | `lookup(Endpoint, Cat, SubCat, "Critical - tier 0")` | **4** |

**Layer 2**:

| Step | Computation | Result |
|---|---|---|
| `RiskFactor_Consequence` | always 0 (placeholder) | 0 |
| `consAdj` | 3 + 0 | **3** |
| `RiskFactor_Probability` | count(true bools) = 2 | 2 |
| `probAdj` | 4 + 2 | **6** |
| `RiskScoreTotal` | 3 * 6 | **18** |

**Layer 3** (`product` combine):

| Step | Computation | Result |
|---|---|---|
| `cmdbCriticality` mult | `Critical` -> 150 | 150 |
| `cmdbDataSensitivity` mult | `Restricted` -> 175 | 175 |
| `RiskFactor_Weight` | `(150/100) * (175/100) * 100` floor | **262** |
| `RiskScoreTotal_Weighted` | `floor(18 * 262 / 100)` | **47** |

So this row, raw 18, surfaces in the Excel sort at **47** -- ahead of un-amplified Critical-but-non-Restricted assets.

---

## See also

- [`QUERIES-REFERENCE.md`](./QUERIES-REFERENCE.md) -- where these multipliers feed (Reports + ReportTemplates)
- `engine/risk-analysis/Invoke-RiskAnalysis.ps1` -- consumer (lines 2231-2409 build KQL, lines 3043-3145 apply Layer 3)
- `engine/risk-analysis/tools/Build-RiskAnalysis.ps1` -- regenerates `__WEIGHTED_FACTORS__` blocks after this JSON changes
- `risk-analysis-detection/riskscore.index.custom.csv` -- the Layer-1 lookup table
