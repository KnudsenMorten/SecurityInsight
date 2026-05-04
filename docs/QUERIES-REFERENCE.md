# SecurityInsight -- Risk-Analysis queries YAML reference

This is the **single source of truth** for `RiskAnalysis_Queries_Locked.yaml` and its `_Custom.yaml` companion. Every field below is grounded in `engine/risk-analysis/Invoke-RiskAnalysis.ps1` -- if a field isn't here, the engine doesn't read it.

> **Authority**: validated against `engine/risk-analysis/Invoke-RiskAnalysis.ps1` (the consumer) and `risk-analysis-detection/risk-analysis.schema.locked.json` (the JSON-schema describing this YAML). When code disagrees with this doc, code wins.

---

## File pair + merge semantics

| File | Purpose | Edited by | Survives release upgrade? |
|---|---|---|---|
| `RiskAnalysis_Queries_Locked.yaml` | Shipped 132+ reports + templates | Maintainer | No |
| `RiskAnalysis_Queries_Custom.yaml` | Customer overrides + new reports | Customer | Yes |

**Merge rule** (`Merge-ByReportName`, `Invoke-RiskAnalysis.ps1` lines 4095-4192):

- Same `ReportName` -> custom **fully replaces** locked entry (no partial merge)
- New `ReportName` -> appended at end
- Order: locked order preserved; matching custom entries overwrite in-place
- ReportTemplates merge by template `ReportName` with the same rules
- Merge log line: `Write-Info ("YAML merge: Locked Reports={...}, Custom={...}, Merged={...}")` (lines 4271-4275)

---

## Top-level structure

```yaml
Reports:                     # list -- one entry per report
  - ReportName: ...
    ...
ReportTemplates:             # list -- groups of reports run together
  - ReportName: ...
    ReportsIncluded: [...]
    ...
```

Both keys are required. The engine errors if either is missing or empty.

---

## `Reports[]` -- field reference

Every entry in `Reports:` maps to ONE Excel sheet / LA write. All fields are **required** unless flagged optional.

| Field | Type | Code (`Invoke-RiskAnalysis.ps1`) | Meaning |
|---|---|---|---|
| `ReportName` | string | line 4320 lookup | Unique id. Referenced from `ReportTemplates[].ReportsIncluded[].Name`. |
| `ReportPurpose` | string | informational | Human description. Surfaces in run logs. |
| `SecurityDomain` | string | `Calculate-RiskScore` (line 1844) | One of `Endpoint`, `Identity`, `Azure`, `Publicip`, `Hygiene`, `RiskAnalysis`. Selects the static Impact lookup table when the row has no `Impact` column. |
| `CategoryInputName` | string | column resolver (1824) | KQL column carrying the risk category. |
| `SubcategoryInputName` | string | column resolver | KQL column carrying the sub-category. |
| `ConfigurationIdInputName` | string | column resolver | KQL column carrying the asset id (DeviceId / UserObjectId / ResourceId). |
| `SecuritySeverityInputName` | string | column resolver | KQL column carrying severity (`Very High`, `High`, `Medium`, `Low`, ...). |
| `CriticalityTierLevelInputName` | string | column resolver | KQL column carrying the tier label (`Critical - tier 0` etc.). |
| `RiskConsequenceScoreOutputName` | string | output naming | Excel column name for consequence score. |
| `RiskProbabilityScoreOutputName` | string | output naming | Excel column name for probability score. |
| `RiskScoreOutputName` | string | output naming | Excel column name for the raw `RiskScoreTotal`. |
| `CriticalityTierLevelScope` | `[string,...]` | scoring filter | Allowed tier labels. Rows outside this set are dropped. |
| `SecuritySeverityScope` | `[string,...]` | scoring filter | Allowed severity labels. Rows outside this set are dropped. |
| `OutputPropertyOrder` | `[string,...]` | strict-mode column projection (1844) | Canonical 21-col order from `risk-analysis.schema.locked.json` plus any report-specific extras (CMDB, EG, ...). Engine emits exactly these columns in exactly this order. Extras are appended after the 21 canonical columns. |
| `SortBy` | `[string,...]` | Excel sort | Optional. Sort key(s) for the Excel sheet -- prefer `RiskScoreTotal_Weighted`. |
| `ReportQuery` | `[string]` (one-element list, KQL multi-line) | submitted via `Invoke-GraphHuntingQuery` (~4760) | The KQL itself. Engine auto-routes pure-LA queries to Log Analytics; mixed XDR queries to advanced hunting. |

### Allowed `SecurityDomain` values + their `byCategory` keys

(from `risk-analysis-detection/risk-analysis.schema.locked.json -> domains.<Domain>.impact`)

- **Endpoint** -- Vulnerabilities, CVEs, Application, OS, Security controls, Firmware, Network, Accounts, Endpoint Hygiene, Sensor Health, Onboarding, EDR, Antivirus, Bitlocker, TPM / Secure Boot, Attack Paths
- **Identity** -- Authentication, Account Lifecycle, Privileged Access, Workload Identities, Password Policy, Identity Hygiene, Conditional Access, Multi-Factor, Privileged SPN, Stale Identity, Service Account, Guest / External, Shadow Admin, Break Glass, Sign-in Risk, Role Assignment, Mailbox Access, Attack Paths, Admin Account Hygiene, Identity Lifecycle, Privilege Escalation Paths, Sign-in Behaviour, Threat Intelligence
- **Azure** -- Public exposure + data sensitivity, Encryption at rest, Encryption in transit, Network exposure, Authentication, DDoS protection, Soft-delete / recovery, RBAC / least privilege, Logging / retention, Workload identity, mdcSecurityRecommendation, mdcManagementRecommendation, Attack Paths, AttackPath_GitHubToAzure
- **Publicip** -- Exposed service, Open admin port, Vulnerability, Geo anomaly
- **Hygiene** -- Coverage drop, Cmdb orphan, Drift, Pipeline, Stale Asset, Unsupported OS

Categories not present in `byCategory` fall back to `domains.<Domain>.impact.default` (usually 5.0).

---

## `ReportTemplates[]` -- field reference

Templates group reports for a single run. The launcher selects a template via `$global:ReportTemplate`.

| Field | Type | Required | Code | Meaning |
|---|---|---|---|---|
| `ReportName` | string | yes | line 4280 lookup | Template id, e.g. `RiskAnalysis_Detailed`, `RiskAnalysis_Summary`. |
| `ReportPurpose` | string | no | informational | Label like `Detailed` / `Summary`. |
| `ReportsIncluded` | `[{Name: <string>}, ...]` | yes | `Resolve-ReportInclude` (4320) | Ordered list of report ids to run when this template is selected. |
| **`Mail_To`** | `[string,...]` | no | **lines 4306-4310** | **Per-template recipient override** (see "Email override" below). |
| **`Mail_SendMail`** | bool | no | **lines 4313-4315** | **Per-template send toggle** (see below). |

---

## Email / notification surface

### Recipient-resolution precedence (highest wins)

1. **Per-template YAML override** (`Mail_To` / `Mail_SendMail` on the active `ReportTemplates[]` entry) -- `Invoke-RiskAnalysis.ps1` **lines 4292-4316**
2. **Per-runmode globals** -- `$global:RiskAnalysis_Detailed_To` / `RiskAnalysis_Summary_To` (and the legacy `$global:Mail_SecurityInsight_Detailed_To` / `_Summary_To`) -- lines 3884-3910 (AutomationFramework branch) / 3979-4003 (community branch)
3. **Global** -- `$global:SendMail` + `$global:MailTo` -- lines 4002-4003

When the engine applies a per-template override, you'll see one of these log lines:

```
Mail recipients overridden by template '<TemplateName>': <a@x.com,b@x.com>
Mail send-flag overridden by template '<TemplateName>': SendMail=<true|false>
```

### How to override the recipient for ONE specific template

Add `Mail_To` (and optionally `Mail_SendMail`) to that template in `RiskAnalysis_Queries_Custom.yaml`:

```yaml
ReportTemplates:
  - ReportName: RiskAnalysis_Detailed       # MUST match the locked id exactly
    Mail_To:                                 # this template only
      - audit-team@yourdomain.com
      - security-lead@yourdomain.com
    Mail_SendMail: true                      # optional; omit to inherit global SendMail
    # ReportsIncluded: [...] is OPTIONAL when overriding -- the merge is by
    # ReportName so omitting it does NOT empty the report list (custom entry
    # replaces the locked entry, which means you DO need to repeat the
    # ReportsIncluded list if you want to keep it).
```

Because the merge is **full-replace by ReportName** (line 4095-4192), if you only put `Mail_To` in your custom file, you would lose the entire `ReportsIncluded` list from the locked entry. To safely override mail without losing reports:

```yaml
ReportTemplates:
  - ReportName: RiskAnalysis_Detailed
    ReportPurpose: Detailed
    ReportsIncluded:
      # Copy the full list verbatim from the locked file
      - Name: Device_Missing_CVEs_Detailed
      - Name: Identity_AdminAccount_HasMailbox_Detailed
      # ... all the other Name: entries from the locked template ...
    Mail_To:
      - audit-team@yourdomain.com
    Mail_SendMail: true
```

### How to suppress mail for one template

```yaml
ReportTemplates:
  - ReportName: RiskAnalysis_Detailed
    ReportsIncluded: [...]                   # full list as above
    Mail_SendMail: false                     # global SendMail=true is overridden to false here
```

### Other mail-related globals (set in `LauncherConfig.custom.ps1`)

| Global | Purpose |
|---|---|
| `$global:SendMail` | Master on/off |
| `$global:MailTo` | Default recipient list |
| `$global:SMTPFrom` | Sender address |
| `$global:SmtpServer` | SMTP relay hostname |
| `$global:SMTPPort` | Port |
| `$global:SMTP_UseSSL` | TLS toggle |

Validation at line 241-243: if `SendMail=true` but no recipient source resolves, the engine throws.

---

## Token substitutions inside `ReportQuery`

The engine recognises these markers and substitutes them at run time. None of them are valid KQL on their own; they MUST live in the YAML and never in a hand-run AH portal copy.

| Token | What's substituted | Source | Use when |
|---|---|---|---|
| `__BUCKET_FILTER__` | `where <hash-bucket-clause>` -- e.g. `where hash(DeviceId, N) in (0,1)` | `AutoBucketCount` probe (line ~4000) | Query may exceed AH 30k row ceiling. Engine probes 1->2->4->...->`AutoBucketMax` buckets to find the largest size that fits. Cached per (`ReportName`, queryHash) in `$SettingsPath/OUTPUT/AutoBucketCache.json`. |
| `__EXCLUDED_CVES_BEGIN__` ... `__EXCLUDED_CVES_END__` | Per-report CVE blacklist injected as `\| where CveId !in (...)` | `risk-analysis-detection/SecurityInsight_RiskAnalysis_Excludes_Custom.json` | Suppress known false positives for ONE report without touching the locked KQL. |
| `__EXCLUDED_CONFIGURATION_IDS_BEGIN__` ... `__EXCLUDED_CONFIGURATION_IDS_END__` | Per-report config-id blacklist | same exclude file | Suppress noisy config IDs for ONE report. |
| `__WEIGHTED_FACTORS_BEGIN__` ... `__WEIGHTED_FACTORS_END__` | KQL `case()` chain mapping cmdb columns to `RiskFactor_Weight` integer (basis-100) | `riskscore_weighted.schema.custom.json` -- see `RISKSCORE-REFERENCE.md` | Always present in modern reports; substituted from the weighted-factor JSON. |

`AutoBucketCount` is controlled by:
- `$global:AutoBucketCount` (default `$true`)
- `$global:AutoBucketMax` (default `64`)
- `$global:AutoBucketCache` (default `$true`)
- `$global:ResetCache` (forces re-probe)

---

## Three-layer risk computation (where these YAML values feed)

Every row that survives the report's `Scope` filters goes through:

1. **Layer 1 -- base** (line 3114-3115): `consBase = lookup(SecurityDomain,Category,SubCategory,SecuritySeverity)` and `probBase = lookup(...,CriticalityTierLevel)` -- index lives in `risk-analysis-detection/riskscore.index.custom.csv`.
2. **Layer 2 -- additive risk-factor adjustment** (line 3117-3119): `consAdj = consBase + RiskFactor_Consequence` (today always 0); `probAdj = probBase + RiskFactor_Probability` (count of true risk-factor bools); `RiskScoreTotal = consAdj * probAdj`.
3. **Layer 3 -- multiplicative business multiplier** (line 3122-3144): `RiskScoreTotal_Weighted = floor(RiskScoreTotal * RiskFactor_Weight / 100.0)`. `RiskFactor_Weight` is a basis-100 integer from the weighted-factor JSON.

Excel sort uses `RiskScoreTotal_Weighted` (preferred) -- see `Invoke-RiskAnalysis.ps1` line 5289-5297.

For the full Layer 3 grammar, see `RISKSCORE-REFERENCE.md`.

---

## See also

- [`RISKSCORE-REFERENCE.md`](./RISKSCORE-REFERENCE.md) -- weighted-factor JSON grammar (Layer 3)
- [`risk-analysis.schema.locked.json`](./risk-analysis.schema.locked.json) -- JSON-schema describing the YAML
- `engine/risk-analysis/Invoke-RiskAnalysis.ps1` -- the engine that consumes everything here
- `engine/risk-analysis/tools/Build-RiskAnalysis.ps1` -- consolidator that injects `__WEIGHTED_FACTORS__` blocks into report KQL
