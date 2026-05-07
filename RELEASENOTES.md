# Release notes for SecurityInsight

## v2.2.100

Latest 30 commits touching SOLUTIONS/SecurityInsight/ in the upstream monorepo monorepo:

- release: SecurityInsight v2.2.100 - README headline blurb rewrite (930776df)
- release: SecurityInsight v2.2.99 - AI summary: Total + Weighted Risk Score per asset + reference links (c89d113a)
- release: SecurityInsight v2.2.98 - README: drop "See § 10 What's New" pointer (2ea0d016)
- release: SecurityInsight v2.2.97 - README: KPI bullet to last + add 2 mail screenshots (f7648270)
- release: SecurityInsight v2.2.96 - RiskScoreKPI: MS-inspired secure score (higher=better) (c45fd1c3)
- release: SecurityInsight v2.2.95 - Risk Score re-tuned + viewer column UX (554afe84)
- release: SecurityInsight v2.2.94 - email: dark-mode tolerance + total at the bottom (7e38cd7a)
- release: SecurityInsight v2.2.93 - email exec summary: severity-by-domain table (e6200d26)
- release: SecurityInsight v2.2.92 - KPI strict-mode fix + MoreDetails URL split + nicer AI summary (89ac38bd)
- release: SecurityInsight v2.2.91 - move viewer/ to top-level (5a0bbb9f)
- release: SecurityInsight v2.2.90 - Risk Analysis viewer (localhost test rig) (cc7bdaf7)
- release: SecurityInsight v2.2.89 - Risk Score KPI + redesigned mgmt email (a6af34b4)
- release: SecurityInsight v2.2.88 - defensive column_ifexists on Identity reports (858d75a5)
- release: SecurityInsight v2.2.87 - transient retry + re-auth on RA bucket fails (940aad7e)
- release: SecurityInsight v2.2.86 - refresh sample xlsx + README appendix update (e1e8a154)
- release: SecurityInsight v2.2.85 - Defender-native MITRE plumbing + 9-framework Compliance (27eb6162)
- release: SecurityInsight v2.2.84 - RA Summary MoreDetails strip CVE prefix (17991209)
- release: SecurityInsight v2.2.83 - RA ComplianceTags inference (44353168)
- release: SecurityInsight v2.2.82 - revert missing-table silencing (cbcc77a9)
- release: SecurityInsight v2.2.81 - PublicIP sample with verifiable Shodan data (8a90c3eb)
- release: SecurityInsight v2.2.80 - quiet launcher startup + PublicIP project fix (d83f0173)
- release: SecurityInsight v2.2.79 - output folder + storage OAuth auto-detect (e0dab35e)
- release: SecurityInsight v2.2.78 - AI summary lookup chain reads ImpactedAssetsList (3b23c3c1)
- release: SecurityInsight v2.2.77 - RA MITRE_Tactics/Techniques inference (c880bcbd)
- release: SecurityInsight v2.2.76 - RA visible-noise fixes (placeholder/URLs/CVEs) (279fcba7)
- release: SecurityInsight v2.2.75 - Send-SIRunHealthRow DCR collision guard (d67c9ceb)
- release: SecurityInsight v2.2.74 - internal-vm launchers honor SI_UseStorageOAuth (0e77ae7d)
- release: SecurityInsight v2.2.73 - asset-tagging idempotent framework init (4ea70e43)
- release: SecurityInsight v2.2.72 - asset-tagging rename + RA fixes (a2727e42)
- release: SecurityInsight v2.2.71 - RA \$laDceRg resolution honors \$global:SI_DceResourceGroup (was hardcoded rg-dce-securityinsight fallback) (58d5e600)

---

# Release notes — SecurityInsight v2.2

> **Curated changelog**. The publish workflow auto-prepends the last 30 commits from the upstream monorepo as a raw activity log; this file is the human-friendly narrative on top.

---

## v2.2.100 — README: rewrite the headline blurb (broaden scope, attribution at the end)

Updated the top-of-page introductory paragraph. Old copy framed SecurityInsight as a Defender-only add-on and led with the MVP attribution; new copy:

- Names every data provider (Defender, Entra ID, AD, Azure, ExposureGraph) so readers see the true integration scope on first glance
- Adds Public IPs to the scored-domain list (matches the four engines that actually run)
- Moves the MVP attribution to a closing sentence that also surfaces "open for community contributions"

---

## v2.2.99 — AI summary: real Total + Weighted Risk Score per asset, plus inline reference links

The AI summary's per-asset line was emitting two confusing numbers — `MaxRiskScore` (max single-row score) and `RiskScoreTotal` (sum of whichever score was the active sort target, often `RiskScoreTotal_Weighted`). Operators couldn't reconcile them with the per-row columns they know.

Replaced both with the two real totals, summed per asset across that asset's findings:

- **Total Risk Score** — sum of per-row `RiskScoreTotal` for findings impacting this asset
- **Weighted Risk Score** — sum of per-row `RiskScoreTotal_Weighted` for findings impacting this asset

New per-asset line in the AI rollup:

```
1. dc1.2linkit.local | Tier 0 | Total Risk Score 950 | Weighted Risk Score 1,065 | Findings 17 | Domains: Endpoint
```

Sort key updated to `WeightedRiskScore` (descending), then `TotalRiskScore`, then `Findings`.

**Reference links inline.** Each per-asset rollup row now also carries up to 6 unique URLs harvested from the `MoreDetails` column of that asset's findings (CVE NVD pages, MITRE technique pages, etc.). The AI prompt instructs the model to render up to 3 of them per asset as inline markdown links `[label](url)`. The email's markdown→HTML renderer was extended to convert both `[text](url)` and bare URLs into proper `<a>` tags so the links land clickable in the recipient's mailbox.

---

## v2.2.98 — README: drop the "See § 10 What's New…" pointer line at the top

Removed the introductory pointer paragraph that linked to § 10 What's New / § 7.8 Locked catalog. It was clutter above the "Why you need SecurityInsight" section — readers find the appendices via the TOC.

---

## v2.2.97 — README: Risk Score KPI bullet moved to last + screenshots

Architecture section: moved the Management-friendly Risk Score KPI bullet to the last position (so it sits next to the visuals). Updated copy to "Quick overview using overall Risk Score (KPI) and a Risk Score breakdown per security domain in email summary. Data is also stored in LogAnalytics for trend reporting." Added two screenshots beneath the bullet showing the email's KPI block and the top-risky-assets table.

---

## v2.2.96 — Risk Score KPI: Microsoft-inspired secure-score model (higher = better)

`RiskScoreTotal` and `RiskScoreTotal_Weighted` are **untouched** — the OG Risk Score people are big fans of stays the same.

What changes is the **per-row KPI** columns and the run-end aggregation. Rebuilt to mirror Microsoft's Cloud Secure Score shape: scale-independent, easy to explain, **higher = better**.

**Per-row math (new):**

```
sevPenalty         = SeverityWeight / 10                                (0..1)
RiskScoreKPI       = round((1 - sevPenalty) * 100)                      (0..100)
RiskScoreDomainKPI = round((1 - sevPenalty) * TierFraction * 100)       (0..100)
                     TierFraction = TierWeight / 4                       (T0=1.00, T1=0.50, T2=0.25, T3=0.125)
```

Per row: Critical = 0, High = 50, Medium = 80, Low = 90.

**Run-end rollup (new) — tier-weighted average, like MS Cloud Secure Score:**

```
DomainScore = sum(RiskScoreKPI × TierWeight) / sum(TierWeight)
GlobalScore = sum(DomainScore × DomainWeight) / sum(DomainWeight)
```

Independent of asset count by construction — a 10-machine lab and a 150k-machine bank produce directly comparable scores.

**Bands (mirrors Microsoft):**

| Band       | Range  | Color        |
|------------|-------:|--------------|
| Very Good  | 90–100 | dark green   |
| Good       |  75–89 | light green  |
| Moderate   |  50–74 | orange       |
| At Risk    |   0–49 | red          |

**Email + viewer flipped to match:**
- Hero label changed from "GLOBAL RISK SCORE" to "RISK SCORE KPI" with "(higher = better)" subtitle.
- Big number is colored by band (green at the top, red at the bottom).
- Domain tiles use the new band colors so green = healthy, red = needs work.
- `[SCORE]` log line annotates direction explicitly: `Direction: HIGHER = BETTER (Microsoft-inspired)`.

The old per-row `RiskScoreKPI` formula (Severity × Tier sum) emitted by v2.2.89–v2.2.95 is replaced. If a customer KQL dashboard reads `SI_RiskAnalysis_*_CL.RiskScoreKPI`, the values will look different starting v2.2.96 — they're now 0–100 secure-score numbers (higher = better) instead of unbounded sums.

---

## v2.2.95 — Risk Score: re-tuned ceilings + raw-numbers log + viewer column UX

**Score model re-tuned.** The prior defaults (`DomainCeiling=1000`, `GlobalCeiling=500`) saturated to 100/Critical with only ~125 endpoint findings on a small internal lab — that's not "Critical" for any real CISO conversation. Defaults bumped to:

- `$global:SI_RiskReport_DomainCeiling = 2500`  (was 1000)
- `$global:SI_RiskReport_GlobalCeiling = 1000`  (was 500)

Same 11 Critical / 55 High scenario now lands around **Endpoint 40 (Elevated)** and **Global 50 (Elevated)** — defensible to leadership and leaves headroom for a real "Critical" event. Customers still tune via the `$global:SI_RiskReport_*` overrides.

**New `[SCORE-RAW]` log line.** The engine now emits both the normalized scores and the raw sums + ceilings used so operators can see the math and pick informed ceilings:

```
[SCORE]     Global=50 (Elevated) Endpoint=40 Identity=23 Azure=12 PublicIP=0 | Sev: C=24 H=75 M=69 L=29 | Rows=197
[SCORE-RAW] GlobalRaw=504 / GlobalCeiling=1000 | EndpointRaw=988 IdentityRaw=570 AzureRaw=310 PublicIPRaw=0 / DomainCeiling=2500
```

**What's still NOT in the score** (transparency, not a regression): `AssetCount` per row (the "1 finding affects 1000 machines" gap), recency, and exploitability signals. AssetCount weighting with `sqrt(min(N, 100))` is the next step.

**Viewer column UX.** Operator feedback: the grid was hard to read because every column had `flex:1`, so headers truncated and the most-useful columns (issue + where) got squashed by less-useful neighbors. Rebuilt:

- Column order is now **issue + where first, score after**: `Domain → Category → Subcategory → Severity → Tier → Configuration → ConfigId → Asset → AssetType → ImpactedAssets → AssetCount → Issues → KPI → DomainKPI → RiskScoreTotal → Compliance → MITRE → Recommendation → Links → CollectionTime`.
- Explicit per-column widths (no more `flex:1`) so headers don't truncate and important columns stay readable. Horizontal scroll is acceptable.
- Header text wraps to a second line instead of clipping with "...".
- New **Columns** dropdown in the toolbar with checkboxes for every column + four presets: **Issue focus / Score focus / Compact / All**.
- `CollectionTime` now formats `/Date(1714986423000)/` JSON dates as locale strings.
- `MoreDetails` cell renders multi-line URL bundles as separate `link 1 · link 2 · link 3` anchors.
- Long text columns (ImpactedAssets / IssueList / Recommendation / ConfigurationName) ellipsis with hover tooltip showing full content.
- Severity / Tier cells use saturated bg + fg color pairs so the encoding survives client auto-invert.

---

## v2.2.94 — RA email: dark-mode tolerance + grand total moved to the bottom

**Layout polish.** Moved the `All` row from the top of the severity-by-domain table to the bottom and renamed it `Total`. Reads spreadsheet-style now — per-domain rows first, then a bold totals row at the foot with a thicker top border to visually separate it from the per-domain rows above.

**Dark-mode tolerance.** Some recipients read mail in clients that auto-invert colors in dark mode (Outlook desktop dark, Yahoo dark) while others honor explicit color hints (Apple Mail, modern Outlook). Two changes so the email reads cleanly in both:

- **Color-scheme hints** — added `<meta name="color-scheme" content="light only">` and `<meta name="supported-color-schemes" content="light only">` plus an MSO conditional `color-scheme: light only !important` to opt out of dark-mode inversion in clients that respect those signals.
- **Cells encode severity with both bg and text color** — every severity cell in the breakdown table now uses a tinted background (red/orange/yellow/green) AND a saturated text color, so even when a client force-inverts colors the cells stay visually distinct (the semantic encoding doesn't depend on a single color attribute).

| Domain    | Total | Critical | High | Medium | Low |
|-----------|------:|---------:|-----:|-------:|----:|
| Endpoint  |   142 |       18 |   58 |     52 |  14 |
| Identity  |    31 |        4 |   12 |     11 |   4 |
| Azure     |    18 |        2 |    4 |      5 |   7 |
| Public IP |     6 |        0 |    1 |      1 |   4 |
| **Total** | **197** | **24** | **75** | **69** | **29** |

---

## v2.2.93 — RA email: severity-by-domain breakdown table in the exec summary

The right side of the executive summary section in the email is now a proper severity-by-domain breakdown table instead of a flat severity tally. Reading left-to-right:

| Domain    | Total | Critical | High | Medium | Low |
|-----------|------:|---------:|-----:|-------:|----:|
| **All**   |   197 |       24 |   75 |     69 |  29 |
| Endpoint  |   142 |       18 |   58 |     52 |  14 |
| Identity  |    31 |        4 |   12 |     11 |   4 |
| Azure     |    18 |        2 |    4 |      5 |   7 |
| Public IP |     6 |        0 |    1 |      1 |   4 |

Total column comes first (left), followed by the four severity columns. The "All" row is shaded and bolded so the total reads first; per-domain rows below break down where the findings actually live. Colors match the rest of the report (Critical=red, High=orange, Medium=yellow, Low=green).

Engine side: the run-end KPI rollup now also tracks `SevByDomain` per the four canonical buckets (Endpoint / Identity / Azure / PublicIP) and exposes it on `$global:RA_KPI.SevByDomain` so the same data can drive Workbook tiles or Power BI cards later.

---

## v2.2.92 — RA: KPI columns now survive strict mode + MoreDetails URL split + nicer AI summary

Three fixes that were visible in the v2.2.91 output:

**1. Risk Score KPI showed 0/100 in the email.** The new `RiskScoreDomainKPI` and `RiskScoreKPI` columns were getting computed per-row but **stripped at output time** because every report runs in strict-mode `OutputPropertyOrder` (only declared columns survive). The KPI rollup downstream then summed zeroes. Added both columns to the strict-mode force-include list (alongside `MoreDetails`, `MITRE_Tactics`, `ComplianceTags`, etc).

**2. MoreDetails URLs concatenated without line break.** Two paths were broken:
- *Auto-harvest* — used `^https?://` to detect URL fields, which kept the WHOLE field value as a single line. When a YAML rollup `strcat`'d two URLs without a separator (e.g. `https://nvd.../CVE-2016-9535https://nvd.../CVE-2025-15556`), the cell rendered as one un-clickable run-on.
- *YAML-populated* — split on `;` only, missing the same run-on case.

Both paths now extract every URL via `regex::Matches('https?://[^\s,;<>"`)\]]+')` so each URL becomes its own line. Trailing punctuation is stripped.

Removed the four portal/security blade auto-links (Defender machine page, Entra User profile, Entra App Registration, Azure resource blade) — operators reported them as noise rather than navigation. MoreDetails now contains only harvested URLs (mostly NVD CVE links + external references). Reports that need a portal link can put it in the YAML rollup directly.

Also dropped the "Risk Score model: Severity × Asset Tier × Domain weight…" footer line from the email — it duplicated what's already obvious from the KPI tiles.

**3. AI summary in the email is now nicely formatted.** The AI prompt was producing a plain bulleted list that rendered as a wall of dashes. Updated the prompt to emit strict markdown (`##` section headers, `###` subheaders, `**bold**` field labels, `_italic_` references), and added a small markdown-to-HTML renderer for the email body so the result lands as proper `<h3>` headers + `<ul>`/`<li>` lists + `<strong>` labels.

---

## v2.2.91 — Viewer: move from `tools/viewer/` to top-level `viewer/`

Path-only change — the viewer is a customer-facing tool, not an internal repo helper, so it lives at the same level as `engine/`, `launcher/`, `output/` rather than buried under `tools/`. Update any shortcuts that pointed at the old location.

---

## v2.2.90 — Risk Analysis Viewer (test rig: localhost web UI for the JSON output)

A self-contained, internal-only web viewer for the Risk Analysis JSON. **No IIS, no auth, no cloud — just a PowerShell HttpListener bound to `localhost`.** Built to evaluate the experience before deciding whether to host it under IIS with Entra ID.

Lives at `viewer/` inside the SecurityInsight solution. Run `.\Start-SIViewer.ps1` and it:

- spins up `http://localhost:8765/` and opens the browser
- auto-discovers every `RiskAnalysis_*.json` in `<solution>/output/` (override via `-OutputDir`)
- serves a single-page UI with two tabs:
  - **Grid** — ag-Grid Community: per-column filters, drag-to-group panel, severity/tier color coding, paginated, links rendered live in `MoreDetails`
  - **Pivot** — PivotTable.js: drag any column to rows/cols, switch aggregator (Count / Sum / Avg / etc), heatmap renderer
- shows a top KPI strip: Global Risk Score (0–100) with color-coded level pill + 4 domain tiles (Endpoint / Identity / Azure / PublicIP). Math mirrors the engine.
- top-bar filters: Domain / Severity / Tier dropdowns + a global search box piped into ag-Grid's filter model
- file picker shows size + age (newest first)

Security model: listener binds **`localhost` only**, so anyone on the VM can use it but nothing on the network can. Don't put it on a multi-user box without auth.

Path forward: when you're ready for shared access, move `web/` under IIS, drop in MSAL.js for Entra sign-in, and delete `Start-SIViewer.ps1`.

---

## v2.2.89 — RA: management-friendly Risk Score KPI + redesigned email report

Two changes that make the Risk Analysis output far easier to land with leadership.

**1. Risk Score KPI (per-row + per-run rollups).** Every Risk Analysis row now carries two new columns:

- `RiskScoreDomainKPI` = `SeverityWeight × AssetTierMultiplier`
- `RiskScoreKPI`       = `RiskScoreDomainKPI × DomainGlobalWeight`

These are independent of the existing `RiskScoreTotal` / `RiskScoreTotal_Weighted` math (customer dashboards built on those columns keep working). At run end the engine aggregates them into one global Risk Score (0–100) plus a per-domain breakdown for Endpoint / Identity / Azure / PublicIP, with a risk level label (Low / Moderate / Elevated / High / Critical). Logged as `[SCORE] Global=NN (Level) Endpoint=NN Identity=NN Azure=NN PublicIP=NN` and exposed on `$global:RA_KPI` for downstream code.

All weights and ceilings are tunable via `$global:SI_RiskReport_*` overrides:
- `SeverityWeight_{Critical|High|Medium|Low}` — defaults `10 / 5 / 2 / 1`
- `TierMultiplier_{T0|T1|T2|T3}` — defaults `4 / 2 / 1 / 0.5`
- `GlobalWeight_{Endpoint|Identity|Azure|PublicIP}` — defaults `0.30 / 0.30 / 0.20 / 0.20`
- `DomainCeiling` (default `1000`) and `GlobalCeiling` (default `500`) — divisors used to normalize raw sums to 0–100

**2. Redesigned mgmt-friendly email.** The Risk Analysis email body has been rebuilt as a polished HTML report:

- Banner with report name, tenant, and generated timestamp
- **Executive summary hero** — big global Risk Score with color-coded level pill (green → purple), total findings, severity breakdown
- **Risk by domain** — 4 KPI tiles (Endpoint / Identity / Azure / PublicIP) with score, score bar, and color-coded background per threshold
- AI-generated narrative (when `$global:BuildSummaryByAI = $true`)
- Footer with **engine build version** stamped from `VERSION` so support can confirm what build produced the output

Bonus: VERSION-file lookup now finds both `VERSION` and `VERSION.txt`, fixing the long-standing `(dev)` stamping in logs and Log Analytics.

---

## v2.2.88 — RA: defensive `column_ifexists` on `DisabledPrivilegedUser` + `RiskFactorCount` (real query bugs)

Two report KQLs referenced columns directly that may not exist on the customer's `SI_Identity_Profile_CL`. Result: 400 BadRequest with `"'where' operator: Failed to resolve column or scalar expression named 'X'"` from LA — both Summary and Detailed variants of:

- `Identity_DisabledPrivilegedUser_*` — referenced `DisabledPrivilegedUser` (boolean verdict the identity engine emits when an account is `accountEnabled=false` AND still has a privileged role assigned). Column is absent on profile rows where the verdict didn't fire.
- `Identity_HighRiskFactorComposite4Plus_*` — referenced `RiskFactorCount` (aggregate count of risk-factor flags on the identity). Absent until the engine has aggregated.

Fix: pre-extend each missing column with `column_ifexists('<col>', <default>)` before the `where` filter, so KQL evaluates the predicate against `false`/`0` instead of failing the query. Pattern matches the existing `__SI_CMDB_DEFENSIVE__` block above each report. Applied at 4 sites (each report's Detailed + Summary):

```kql
| extend DisabledPrivilegedUser = tobool(column_ifexists('DisabledPrivilegedUser', false))
| where DisabledPrivilegedUser == true

| extend RiskFactorCount = toint(column_ifexists('RiskFactorCount', 0))
| where RiskFactorCount >= 4
```

Reports now return 0 rows on tenants where the column is missing (correct — there are no findings to report) instead of erroring out.

---

## v2.2.87 — RA: separate transient-platform errors from row-overflow; add re-auth + same-bucket retry

**Customer-side fail observed 2026-05-07** (kv-evida-automation-p / AUTOSENTINEL01): a single Attack_Paths_Summary report escalated `64 → 128 → 256 → 512` buckets because every bucket hit `A task was canceled`. With ~15s per bucket × 512 buckets, that's **~2 hours JUST for one report**, blocking every other report queued behind it. The xlsx never produced.

**Root cause**: `Test-IsBucketOverflowError` matched `"a task was canceled"` / `"timeout"` / `"timed out"` and treated them as "row-overflow → escalate buckets". But Defender Graph Hunting API also throws `TaskCanceledException` when:
- An access token expired mid-run (long RA jobs commonly outlive 1h tokens)
- Defender Graph backend hiccups (502/503/504, gateway timeout)
- The SPN gets throttled

In all those cases, **escalating bucket count makes things worse** (more buckets = more API calls = more throttle = more cancels = more escalation = death spiral).

**Fix**:

1. Split classifiers — `Test-IsBucketOverflowError` now only matches TRUE overflow signals (`exceeded the allowed result size`, `too many`, `request entity too large`, `payload too large`, `result limit`). New `Test-IsTransientPlatformError` covers `task was canceled` / `timeout` / `429`/`503`/`502`/`504` / `service unavailable` / `bad gateway` / `gateway timeout` / `InvalidAuthenticationToken` / `401` / `unauthorized`.
2. Outer bucket-loop catch handles each class differently:
   - **TRUE overflow** → escalate bucket count (existing behavior, 1→2→4→8→16→…→`$global:AutoBucketMax`).
   - **Transient platform** → sleep with exponential backoff (30s, 60s, 120s), **re-auth BOTH Graph (`Connect-GraphHighPriv`) AND Azure (`Connect-AzAccount`)**, retry SAME bucket. Default 3 outer retries; tunable via `$global:SI_BucketTransientRetries`.
   - **Other** → log + skip the bucket (existing behavior, no escalation).

The Az re-auth uses your existing `$global:SpnClientId` / `SpnClientSecret` / `SpnTenantId` (or `SpnCertificateThumbprint` if configured). If the reconnect itself fails, engine logs a non-fatal warning and the bucket continues with whatever Graph creds it has.

**What you'll see in logs now** when a token expires mid-run or Defender hiccups:

```
[WARN] bucket 49/64: transient platform error (likely token expiry / 503 / throttle).
       Re-auth + retry attempt 1/3 after 30s. Error: A task was canceled.
... (re-auths Graph + Az) ...
[INFO] bucket 49/64: running query (auto-routed: ...)
[INFO] hunting query bucket 49/64 completed in 14,28s
[INFO] bucket 49/64: 142 rows
```

…instead of escalating into 128/256/512 buckets and burning hours.

Knobs (`SecurityInsight.custom.ps1`):
- `$global:SI_BucketTransientRetries = 3` — how many re-auth+retry cycles before giving up the bucket
- `$global:GraphReconnectMaxAgeMinutes = 45` (existing) — proactive Graph reconnect cadence
- `$global:GraphQueryMaxRetries = 4` (existing) — inner per-call retries inside `Invoke-GraphHuntingQuery`

---

## v2.2.86 — Refresh sample xlsx + README pointers

Two housekeeping items every release should carry:

1. **Sample xlsx refreshed** — `engine/risk-analysis/_samples/Sample - RiskAnalysis_Detailed.xlsx` and `_Summary.xlsx` regenerated from the latest internal-env run. Each row now carries the v2.2.85 enrichment: AssetType-aware portal URLs, CVE → NVD links, MITRE_Tactics + MITRE_Techniques, ComplianceTags anchored to NIST 800-53 / NIST CSF 2.0 / ISO 27001 Annex A / CIS Controls v8 / PCI DSS 4.0 / HIPAA Security Rule / SOC 2 Trust Services / NIS2 / DORA. Replaces the legacy `_Bucket`-suffix samples.

2. **README pointers updated** — sample-link table now points at `engine/risk-analysis/_samples/Sample - RiskAnalysis_*.xlsx` (the canonical v2.2.79+ path), with a note about what each xlsx demonstrates. Output-folder bullet in the file-tree section now mentions `output/` and the `SI_RiskAnalysis_OutputDir` override.

This is the first release where samples will be refreshed automatically on every tag from now on. Bootstrap pulls from `KnudsenMorten/SecurityInsight` so customers see the latest sample artifacts straight from the public mirror.

---

## v2.2.85 — RA: Defender-native MITRE plumbing + ComplianceTags expanded to 9 frameworks

Two related changes shipped together; engine groundwork for v2.2.86's report-by-report YAML migration.

### MITRE: read Defender-native fields when projected

The MITRE inference (added v2.2.77) only worked on `SecurityDomain + Subcategory + ConfigurationName` keyword regex. But many reports query `AlertInfo` / `AlertEvidence` / `ExposureGraphEdges` which carry MITRE data **natively**:

| Defender column | Format | Source tables |
|---|---|---|
| `Categories` | comma-separated tactic names ("Credential Access,Defense Evasion") | AlertInfo, AlertEvidence |
| `AttackTechniques` | comma-separated `T####` IDs | AlertInfo, DeviceEvents |
| `EdgeProperties.rawData.attackTechniqueIds` | JSON array of `T####` | ExposureGraphEdges |

Engine now reads these columns when present on the row and prefers them over keyword inference. New resolution priority:

1. YAML-projected `MITRE_Tactics` / `MITRE_Techniques` (already filled — wins)
2. Defender native: `Categories` / `AlertCategories` / `MITRE_Categories` → mapped to `TA####` IDs via the static 14-tactic lookup baked into the engine
3. Defender native: `AttackTechniques` / `MITRE_AttackTechniques` → kept as-is (already `T####`)
4. Keyword regex (v2.2.77 inference)
5. SecurityDomain-level fallback

For v2.2.86 to actually wire this up, the 26 alert/EG-querying reports need a small KQL addition like:

```kql
| extend MITRE_Categories       = tostring(Categories)
| extend MITRE_AttackTechniques = tostring(AttackTechniques)
```

…which will be the next commit. Until then the engine's groundwork is in but inference still drives most rows.

### ComplianceTags: expanded to 9 frameworks

Defender XDR doesn't ship a unified compliance-tag column, so this stays engine-side. Extended every keyword + domain-fallback entry with **HIPAA Security Rule, SOC 2 Trust Services, NIST CSF 2.0, NIS2 (EU), DORA (EU finance)** alongside the existing NIST 800-53 / ISO 27001 Annex A / CIS Controls / PCI DSS / GDPR coverage.

Examples (each row in any RA Summary now shows ~6-9 framework anchors instead of ~3):

| Trigger keywords | ComplianceTags (expanded) |
|---|---|
| MFA / Conditional Access | NIST 800-53 IA-2(1); NIST CSF PR.AA-3; ISO 27001 A.9.4.2; CIS 5.1; PCI DSS 8.4; HIPAA 164.312(a)(1); SOC 2 CC6.1; NIS2 Art.21(2)(d) |
| CVE / vulnerability / patch | NIST 800-53 SI-2,RA-5; NIST CSF ID.RA-1,PR.IP-12; ISO 27001 A.12.6.1; CIS 7.1; PCI DSS 6.2; HIPAA 164.308(a)(1)(ii)(B); SOC 2 CC7.1; NIS2 Art.21(2)(e); DORA Art.10 |
| Privileged role / permanent | NIST 800-53 AC-2,AC-5,AC-6; NIST CSF PR.AC-4; ISO 27001 A.9.2.3; CIS 5.4; SOC 2 CC6.2; NIS2 Art.21(2)(i); DORA Art.9 |
| Public IP / open port / exposure | NIST 800-53 SC-7,CA-3; NIST CSF PR.AC-5; ISO 27001 A.13.1; CIS 12.1; PCI DSS 1.1; HIPAA 164.312(e)(1); SOC 2 CC6.6; NIS2 Art.21(2)(c) |
| Data sensitivity / key vault | NIST 800-53 SC-12,SC-13,MP-2; NIST CSF PR.DS-1,PR.DS-5; ISO 27001 A.8.2,A.10.1; GDPR Art.32; PCI DSS 3; HIPAA 164.312(a)(2)(iv); SOC 2 CC6.7; DORA Art.9 |

YAML-supplied tags still win; engine fills only when empty.

---

## v2.2.84 — RA Summary MoreDetails: strip 'CVE-XXX => ' prefix on YAML-supplied URLs

Several vulnerability YAMLs build MoreDetails entries in KQL with the format `CVE-2026-33824 => https://nvd.nist.gov/vuln/detail/CVE-2026-33824` (semicolon-separated when multiple CVEs roll up into one Summary row). The engine's YAML-passthrough path preserved the `CVE-XXX => ` label prefix verbatim, while the auto-harvested Detailed side emitted clean URLs only. Two different shapes for the same data.

Fix: in the YAML-passthrough split (`Invoke-RiskAnalysis.ps1:3308`), if an entry matches `^.*?=> https?://...$`, keep only the URL portion. Each CVE keeps its own line (the existing `\r\n` join after dedup gives one URL per line in the Excel cell).

Result: Summary MoreDetails now formats consistently with Detailed — clickable URLs only, one per line, no `CVE-XXX =>` prefix.

YAMLs that already emit URL-only entries are unaffected (regex doesn't match if there's no `=>`).

---

## v2.2.83 — RA: ComplianceTags inference (paired with v2.2.77 MITRE inference)

`ComplianceTags` was always empty for the same reason `MITRE_Tactics`/`Techniques` were before v2.2.77 — YAML reports never hand-authored the values, and the engine forced `''` as the fallback at `Invoke-RiskAnalysis.ps1:3549`.

Same approach as the MITRE inference: derive from `SecurityDomain + Subcategory + ConfigurationName` when YAML didn't pre-populate. Keyword-first (specific framework references), domain-fallback when no keyword hits.

| Trigger keywords | ComplianceTags |
|---|---|
| MFA / Conditional Access | NIST 800-53 IA-2(1); ISO 27001 A.9.4.2; CIS 5.1; PCI DSS 8.4 |
| Brute force / password spray | NIST 800-53 AC-7; ISO 27001 A.9.4.2; CIS 5.2 |
| Privileged role / permanent | NIST 800-53 AC-2,AC-5,AC-6; ISO 27001 A.9.2.3; CIS 5.4 |
| Stale account / departed / guest | NIST 800-53 AC-2(2),AC-2(3); ISO 27001 A.9.2.5; CIS 5.3 |
| ServicePrincipal / app registration | NIST 800-53 IA-3; ISO 27001 A.9.4.5; CIS 5.5 |
| CVE / vulnerability / patch | NIST 800-53 SI-2,RA-5; ISO 27001 A.12.6.1; CIS 7.1; PCI DSS 6.2 |
| Public IP / open port / exposure | NIST 800-53 SC-7,CA-3; ISO 27001 A.13.1; CIS 12.1; PCI DSS 1.1 |
| Lateral / logon-to / exploitable | NIST 800-53 SC-7(13),AC-4; ISO 27001 A.13.1.3; CIS 12.4 |
| Data sensitivity / key vault | NIST 800-53 SC-12,SC-13,MP-2; ISO 27001 A.8.2,A.10.1; GDPR Art.32; PCI DSS 3 |
| Firewall / Defender | NIST 800-53 SC-7,SI-3; ISO 27001 A.13.1.1; CIS 9.2 |
| TLS / encryption | NIST 800-53 SC-8,SC-13; ISO 27001 A.10.1; PCI DSS 4 |

Domain fallbacks (when no keyword hits) cover Identity / Endpoint / Azure / PublicIp / AttackPath. YAML-supplied tags still win — engine only fills when the column is empty.

Customers wanting a different framework set (HIPAA, SOC 2, NIS2, DORA) can either author per-report `ComplianceTags` in custom YAML, or open an issue with the framework controls they want bolted on.

---

## v2.2.82 — Revert v2.2.80 missing-table silencing (keep the warnings loud)

v2.2.80's "table not found → 0 rows + Write-Verbose" graceful skip in `Invoke-LogAnalyticsKqlQuery` was wrong policy. `Failed to resolve table or column expression named 'SI_<Engine>_Profile_CL'` (or `SI_VulnerabilityPIP_CL`) is a **report-design bug**, not transient state — it means a report is shipping with a hard dependency on a source table that the customer's environment hasn't satisfied. Hiding it means report authors don't see when their KQL has invalid source-table references, and customers don't know which collector engine they need to run first.

Reverted: the engine surfaces the LA `Failed to resolve table` error loudly as before — diagnostic body dump + `[WARN] LA query failed` per bucket. Same for the AdvancedHunting probe path (no `2>$null`).

NOT reverted (different category — these are real config defaults, not query bugs):
- `Initialize-PlatformLegacyIdentity` Write-Verbose under -IgnoreMissing (v2.2.80 #1)
- LauncherConfig auto-init passes `-IgnoreMissingSecrets` (v2.2.80 #2)
- PublicIP_*_Detailed duplicate-AssetName project fix (v2.2.80 #3)

Forward-looking proper fix: each report YAML should declare `SourceTables: [SI_Identity_Profile_CL, SI_Endpoint_Profile_CL, ...]`. Engine pre-flights table existence at run start, skips reports whose source tables are missing with `[SKIP] <ReportName> -- requires <table> (asset-profiling <engine> hasn't ingested yet)`. That's a data-driven skip with intent in the message, not a hidden error.

Failing reports observed on the 2026-05-07 04:05 customer run (for the SourceTables manifest follow-up):

| Report | Missing source |
|---|---|
| Identity_AdNestedCriticalGroup_NoEntraRole_Detailed | SI_Identity_Profile_CL |
| Identity_Departed_AccountStillEnabled_Detailed | SI_Identity_Profile_CL |
| Identity_DisabledPrivilegedUser_Detailed | SI_Identity_Profile_CL |
| Identity_HighRiskFactorComposite4Plus_Detailed | multiple SI_*_Profile_CL |
| PublicIP_Vulnerabilities_Detailed | SI_VulnerabilityPIP_CL |

---

## v2.2.81 — PublicIP sample: more public test IPs with known open ports + CVEs

`public-ip.schema.custom.sample.json` shipped with one test IP (`scanme.nmap.org`). Customers verifying the PublicIP / Shodan pipeline end-to-end after first install often want to see the open-port and vulnerability detection paths actually fire — single Nmap target only proves the open-ports half.

Added three more well-known public test endpoints, each with the safety / consent context spelled out in `_comment`:

| IP | Hostname | What it demonstrates |
|---|---|---|
| 44.228.249.3 | testphp.vulnweb.com | Acunetix's official vulnerable PHP demo — reliably reports a long CVE list in Shodan, exercises `PublicIP_Vulnerabilities_Detailed`. |
| 65.61.137.117 | demo.testfire.net | IBM AppScan / Altoro Mutual demo bank — outdated TLS / web-server CVEs, useful for high-severity categorization on a banking-style asset. |
| 104.131.0.69 | shodan demo MongoDB | Exposed MongoDB on port 27017 — exercises the high-risk-port flagging path; flagged Very High when paired with a Tier-0 asset. |

All four entries are tagged `tier: 3` / `cmdbCriticality: Low` so they don't pollute the Tier 0/1 risk reports. Customers should remove the test entries once SI_VulnerabilityPIP_CL contains real production data.

---

## v2.2.80 — Quiet launcher startup + PublicIP_*_Detailed KQL fix + table-not-found skip

Four small fixes that flush warning noise from RA runs.

### 1. Initialize-PlatformLegacyIdentity quiet under -IgnoreMissing

`Initialize-PlatformLegacyIdentity` was emitting `Write-Warning` for every missing legacy KV secret even when called with `-IgnoreMissing` — meaning every launcher start logged something like:

```
WARNING: Initialize-PlatformLegacyIdentity: 'Legacy.ProvisionVMLocalAdmin' failed:
Get-PlatformSecretKeyVault: secret 'Azure-VM-LocalAdmin-UserName' not found in vault 'kv-2linkit-automation-p'.
```

Most v2 cloud-only deployments don't carry the legacy on-prem creds (Azure-VM-LocalAdmin-*, Legacy-*-Internal/DMZ-Prod). Demoted to `Write-Verbose`, so `-Verbose` still surfaces the per-key skip when diagnosing.

### 2. Initialize-LauncherConfig auto-init now passes -IgnoreMissingSecrets

The launcher's auto-init at Layer 1.5/5 (`Initialize-LauncherConfig.ps1:454`) called `Initialize-PlatformAutomationFramework` without `-IgnoreMissingSecrets`. Combined with #1, that produced:

```
WARNING: Initialize-PlatformLegacyIdentity failed (legacy creds unavailable): ...
WARNING: SMTP credentials not found in KV (secrets 'SMTPuser' / 'SMTPpassword'). ...
```

…on every launcher startup whose customer KV didn't carry those optional secrets. Now passes `-IgnoreMissingSecrets` so the framework treats missing legacy + SMTP secrets as expected. Customers who DO require strict SMTP/legacy can call `Initialize-PlatformAutomationFramework` upstream without the switch.

### 3. PublicIP_*_Detailed reports: duplicate `AssetName` in `project`

`PublicIP_OpenPorts_Detailed` and `PublicIP_Vulnerabilities_Detailed` had `AssetName` listed TWICE in the final `| project ...` clause. KQL rejects duplicate column names → 400 BadRequest on every run, even when `SI_VulnerabilityPIP_CL` had data:

```
[WARN] LA query failed -- full detail dumped to ...\ra-laerr-...txt
[WARN] AutoBucket failed for report 'PublicIP_OpenPorts_Detailed'. Falling back to configured BucketCount=2.
[ERR]  query failed for bucket 1/2: Operation returned an invalid status code 'BadRequest'
[ERR]  query failed for bucket 2/2: Operation returned an invalid status code 'BadRequest'
```

Fix: dropped the duplicate `AssetName` from the project list in both reports. Summary variants were already correct (no duplicate). Now Detailed actually returns rows when Shodan has data.

### 4. LA query: graceful skip on "table not found"

`Invoke-LogAnalyticsKqlQuery` now catches the LA semantic error pattern `Failed to resolve table or column expression named '<table>'` (or `isn't a known table`) and returns 0 rows + a `Write-Verbose` line — instead of dumping a diagnostic error file and surfacing a `[WARN]` per bucket.

Triggered by reports that query an SI_*_CL table that hasn't been ingested yet (e.g., RA running before the matching collector engine has produced data). Customers see a clean "No rows returned from query" instead of the "BadRequest x N buckets" cascade.

---

## v2.2.79 — RA output folder + storage OAuth auto-detect

Two operator-facing changes bundled.

### Output folder moved out of `risk-analysis-detection/OUTPUT/`

`RiskAnalysis_Detailed.xlsx` and `_Summary.xlsx` were buried under `SOLUTIONS/SecurityInsight/risk-analysis-detection/OUTPUT/` — annoying to find. New default:

```
SOLUTIONS/SecurityInsight/output/
├── RiskAnalysis_Detailed.xlsx
├── RiskAnalysis_Detailed.json
├── RiskAnalysis_Summary.xlsx
└── RiskAnalysis_Summary.json
```

`Invoke-RiskAnalysis.ps1` now resolves `$global:OutputDir` to `<solutionRoot>/output/`. Customers who had automation pinned to the old path can override with `$global:SI_RiskAnalysis_OutputDir = '<your-path>'` in `SecurityInsight.custom.ps1`. The old folder is left in place for any in-flight artifacts; `.gitignore` excludes both paths.

### Storage auth auto-defaults to OAuth when no SharedKey is configured

The asset-profiling engine (`Invoke-SIEngineRun.ps1`) now picks the auth method based on what's available:

1. **Explicit `$global:SI_UseStorageOAuth = $true`** → OAuth
2. **No `$global:SI_StorageKey` set** → OAuth (sensible default since v2.2.55 prestage grants Storage Blob/Table/Queue Data Contributor on the SA)
3. **Otherwise** → SharedKey (back-compat for installs that already have a working key in KV)

Force SharedKey on a customer with both globals set: explicitly `$global:SI_UseStorageOAuth = $false`.

This avoids the need for customers to either rotate keys into KV, or set `SI_UseStorageOAuth=$true` manually after the prestage. New installs Just Work.

Edge cases not affected:
- SPN missing Storage *_Data Contributor RBAC → 403 (already broken; rerun prestage to grant)
- Network-restricted SA without VNet line of sight → both methods fail equally
- AzLogDcrIngestPS module's DCR ingest path uses Bearer tokens directly; storage auth flag only affects blob staging + fingerprint table operations

### Status of original spreadsheet bug findings

| Finding | Status | Tag |
|---|---|---|
| `(engine-substituted at runtime)` placeholder text leaking into Excel | Fixed | v2.2.76 (YAML edit, 122 occurrences) |
| MoreDetails URL always Entra User-profile blade (wrong for SP/Endpoint/Azure) | Fixed | v2.2.76 (AssetType-aware URL builder) |
| CVE strings in IssueList not hyperlinked in MoreDetails | Fixed | v2.2.76 (CVE harvester → nvd.nist.gov links) |
| MITRE_Tactics + MITRE_Techniques empty | Fixed | v2.2.77 (engine-side inference from SecurityDomain + keywords) |
| AI summary collapsed to 1 asset | Fixed | v2.2.78 (lookup chain stale post-v2.2.72 column rename) |
| RunHealth 404 `'westeurope'` immutableId | Fixed | v2.2.75 (DCR collision guard + cache prefetch) |
| Identity Summary `RiskScoreTotal=0` rows | **Not fixed (data/scoping)** | Report scoping issue: e.g. `Identity_PrivilegedUser_NoMFA_*` doesn't filter `where IsPrivileged == true`, so non-privileged users land in the report with `Probability=0`, `Total=Consequence×0=0`. Per-report YAML fix needed; flag specific reports if you want them tightened. |
| `cmdbId` empty for many Identity rows | **Not fixed (data)** | Customer KV/CMDB feed not populating cmdb columns in `SI_Identity_Profile_CL` for those PrimaryEntityIds. Engine join is correct; data is missing. |
| All `RiskScore_Weight_Factor=100` (no per-row weighting) | **Not fixed (config)** | By design when no `riskscore_weighted.schema.custom.json` is set. v2.2.76 dropped the misleading "(engine-substituted at runtime)" text; values still default to 100 (basis-100 = 1.0x = no lift). Customer needs to author the JSON to get differential weighting. |

---

## v2.2.78 — RA AI summary collapsed to one asset (lookup chain stale post-v2.2.72 column rename)

The AI summary email and Excel Summary sheet only listed ONE asset (the first endpoint that happened to have a per-row `AssetName` populated), even when Detailed had hundreds of rows across endpoint + identity + azure domains.

Root cause: v2.2.72 unified `ImpactedAssets` → `ImpactedAssetsList` as the canonical column on Summary rows, then dropped `ImpactedAssets` from `tmp2`. The AI rollup at `Invoke-RiskAnalysis.ps1:6465` still read the legacy name only:

```powershell
$assetsText = Get-RowValue -Row $r -Names @("ImpactedAssets", "Assets", "AffectedAssets", "Machines")
```

For every Summary row whose only asset list lived in `ImpactedAssetsList`, `$assetsText` came back empty. `Resolve-AssetNamesForRow` then fell through to per-row `AssetName` — which on Summary rows is the engine's aggregate reconstruction, often empty for Identity / Azure. `Add-AssetAgg` returned early on empty Asset, the row was dropped from the per-asset rollup, and the AI got a one-asset universe.

Fix: prepend `ImpactedAssetsList` to the lookup chain. Legacy `ImpactedAssets` stays for back-compat with any old YAMLs that still emit the singular name.

Result: AI summary should now see the full asset population — Top 25 will list the actual top-25 ranked by `MaxRiskScore × RiskScoreTotal × Findings` instead of collapsing to one.

---

## v2.2.77 — RA: MITRE_Tactics / MITRE_Techniques inference

`MITRE_Tactics` and `MITRE_Techniques` columns were always blank — YAMLs hadn't been hand-authored with MITRE coverage and the engine forced them to `''` as a fallback at `Invoke-RiskAnalysis.ps1:3486-3487`.

Fix: when YAML doesn't pre-populate either column, the engine now infers a sensible default from `SecurityDomain + Subcategory + ConfigurationName`. Keyword regex first (specific), then SecurityDomain-level fallback. Coverage is intentionally broad — TA-tactic IDs + the most common technique IDs — so customers can still refine per-report in custom YAML and have those overrides win.

Examples:

| Trigger keywords | MITRE_Tactics | MITRE_Techniques |
|---|---|---|
| MFA / Conditional Access | TA0006 | T1078;T1110 |
| Brute force / password spray | TA0006 | T1110;T1110.003 |
| Privileged role / permanent role | TA0004;TA0003 | T1078;T1098.003 |
| ServicePrincipal / app registration | TA0004;TA0003 | T1078.004;T1098.001 |
| CVE / vulnerability / recommendation | TA0001 | T1190 |
| Public IP / open port / exposure | TA0001;TA0007 | T1190;T1133 |
| Lateral / logon-to / exploitable device | TA0008 | T1021;T1078 |
| Attack path | TA0008;TA0004 | T1078;T1021 |
| Data sensitivity / key vault | TA0009;TA0010 | T1213;T1530 |

Domain fallbacks (when no keyword hits) cover Identity / Endpoint / Azure / PublicIp / AttackPath. The MITRE link harvester at line 3343-3353 then turns those IDs into `https://attack.mitre.org/...` URLs in MoreDetails — completing the loop.

If a report's MITRE tagging looks wrong, set explicit `MITRE_Tactics` / `MITRE_Techniques` in your custom YAML for that report; engine treats existing values as authoritative and skips inference.

This release does NOT touch: Identity Summary `RiskScoreTotal=0` rows (root cause is conceptual — non-privileged users without MFA in a "PrivilegedUser_NoMFA" report; report scoping needs a `where IsPrivileged == true` filter, deferred), missing `cmdbId` (root cause is data — customer KV/CMDB feed not populated for those PrimaryEntityIds; not an engine bug).

---

## v2.2.76 — RA spreadsheet visible-noise fixes: placeholder text, MoreDetails URLs, CVE links

Three cosmetic-but-confusing bugs in the Detailed/Summary spreadsheet output:

**1. `(engine-substituted at runtime)` placeholder text leaking into Excel.** The YAML `__WEIGHTED_FACTORS_BEGIN__` ... `__WEIGHTED_FACTORS_END__` block carried a default fallback that spelled out `"cmdbCriticality=Critical (engine-substituted at runtime)"` so authors knew the engine was supposed to substitute it. The substitution only fires when `riskscore_weighted.schema.custom.json` has a per-engine `weightedRiskFactors.<engine>.fields[]` block; without that, the fallback text reached Excel as-is — confusing customers into thinking the engine had failed.

Fix: rewrite the YAML defaults to emit a clean value with no diagnostic text:
- Endpoint/Azure/PublicIP reports: `iff(isnotempty(cmdbCriticality), strcat("cmdbCriticality=", tostring(cmdbCriticality)), "")` — shows the value when cmdb-enriched, empty otherwise.
- Identity reports (which aggregate above per-row cmdb): `""` — no per-row factor data anyway.
- Replaced 122 occurrences across the YAML.

**2. MoreDetails URL only ever pointed at Entra User Profile blade — even for ServicePrincipals, Endpoints, and Azure resources.** `Invoke-RiskAnalysis.ps1:3326` walked a fallback chain ending in `'AssetId'` and emitted the `Microsoft_AAD_IAM/UserDetailsMenuBlade/.../userId/<oid>` URL whenever any candidate matched a 36-char GUID — so SP rows (where AssetId is the AppId) and Endpoint rows (where AssetId is the MdeDeviceId) all got a malformed userId blade URL.

Fix: the URL builder is now AssetType-aware:
- `AssetType='Endpoint'` → `https://security.microsoft.com/machines/<MdeDeviceId>/overview` only
- `AssetType='User'` / `'Identity'` → User Profile blade only
- `AssetType` matches `*SP*` / `'ServicePrincipal'` / `'AppRegistration'` → `Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/<AppId>`
- `AzureResourceId` or AssetId starting with `/subscriptions/` → portal resource blade
- Endpoint MdeDeviceId fallback also fires when AssetType is empty (legacy rows without AssetType set).

**3. CVE links missing from MoreDetails despite CVE strings in `IssueList`.** The harvester scanned for `^https?://` only; CVE-IDs in the row's columns never got hyperlinked.

Fix: added CVE regex harvest (`CVE-\d{4}-\d{4,}` across every column on the row), each unique CVE appended as `https://nvd.nist.gov/vuln/detail/<CVE>`. Dedupe + 25-URL cap + 4000-char cell cap still apply.

This release does NOT touch: Identity Summary `RiskScoreTotal=0`, missing `cmdbId` projection, missing `MITRE_Tactics`/`Techniques`. Those are queued for v2.2.77+.

---

## v2.2.75 — Send-SIRunHealthRow: DCR collision guard + cache prefetch

The `Send-SIRunHealthRow.ps1` heartbeat helper called `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` directly without:

1. Re-syncing `$global:AzDcrDetails` after `CheckCreateUpdate-TableDcr-Structure` provisioned a fresh DCR (the new DCR's immutableId wasn't in the cache yet).
2. The DCR collision guard (filter `$global:AzDcrDetails` to the strict `name + sub + RG` match) that the v2.2.65 fix added to `Invoke-Output.ps1` and `Invoke-RiskAnalysis.ps1`.

Result: AzLogDcrIngestPS's name-only DCR lookup fell back to the DCE's `location` field as the immutableId, and the Log Ingestion API rejected the heartbeat with:

```
Log Ingestion API request failed. HTTP Status: 404 Response: {"error":{"code":"NotFound",
"message":"Data collection rule with immutable Id 'westeurope' not found."}}
```

Fix: add the cache-prefetch (`Ensure-SecurityInsightAzDceDcrCache -Force`) and the DCR collision guard (filter to sub + RG) before `Post-*`. Same pattern Invoke-Output.ps1 has been running since v2.2.65. RunHealth telemetry was already best-effort (try/catch swallows + Write-Verbose), but the noisy 404 appearing as the FIRST line of every RA run was misleading.

---

## v2.2.74 — internal-vm launchers honor `$global:SI_UseStorageOAuth` from custom.ps1

The four asset-profiling internal-vm launchers (`launcher/{azure,endpoint,identity,publicip}/launcher.internal-vm.ps1`) only read `-UseStorageOAuth` from the CLI switch — `$global:SI_UseStorageOAuth = $true` set in `SecurityInsight.custom.ps1` was silently ignored. Customers running shared-key with stale `SI_StorageKey` got 403 `AuthenticationFailed` from Azure Table REST in `Initialize-SIFingerprintTable` (`storage/FingerprintCache.ps1:46`) and had no obvious way to flip to OAuth without re-running the launcher with the explicit switch.

Fix: each launcher now resolves `UseStorageOAuth` with the same CLI-wins-then-global pattern as `Sinks` / `AssetLimit` / `ForceFullRun`:

```powershell
$effectiveUseStorageOAuth = $false
if ($cliBound.ContainsKey('UseStorageOAuth')) {
    $effectiveUseStorageOAuth = [bool]$UseStorageOAuth
} elseif ($global:SI_UseStorageOAuth) {
    $effectiveUseStorageOAuth = [bool]$global:SI_UseStorageOAuth
}
```

The `[LAUNCHER] ... UseStorageOAuth=` log line + the engine passthrough now both reflect the resolved value, so customers can drop `$global:SI_UseStorageOAuth = $true` in their `custom.ps1` once and never touch the launcher CLI again. Engine-side OAuth handling (`storage/StorageContext.ps1` -- bearer token from `Get-AzAccessToken -ResourceUrl 'https://storage.azure.com/'`) was already in place.

community-vm launchers untouched (different param flow; community customers typically pass `-UseStorageOAuth` interactively and don't have a layered solution-wide custom.ps1 to inherit from).

---

## v2.2.73 — Asset-Tagging: skip Initialize-PlatformAutomationFramework re-init when launcher already ran it

When invoked through `launcher.internal-vm.ps1`, the launcher's `Initialize-LauncherConfig` auto-runs `Initialize-PlatformAutomationFramework` at Layer 1.5/5 (when `$global:Context` is null). The asset-tagging engine then ran the same call AGAIN at `AssetTagging.ps1:1220`, producing duplicate `WARNING: Initialize-PlatformLegacyIdentity ... failed` lines (one from each call) when the customer KV is missing the optional `Legacy-*` / `Azure-VM-LocalAdmin-*` secrets.

Fix: guard the engine's call with `if (-not $global:Context -or -not $global:AzureTenantId -or -not $global:HighPriv_Modern_ApplicationID_Azure)`. The SPN-alias assignments (`SpnTenantId` / `SpnClientId` / `SpnClientSecret`) still run unconditionally — they're idempotent and cheap.

The engine still bootstraps the framework when called directly without a launcher (the guard's globals are null in that case). Same engine, half the warning noise when run through the launcher.

---

## v2.2.72 — Asset-Tagging: rename engine folder + RA fixes (DCE-RG priority, ImpactedAssetsList unification)

Three fixes shipped together:

**1. Asset-Tagging engine folder rename: `engine/asset-tagging-endpoint-exclusions/` → `engine/asset-tagging/`.** The old name was a misnomer — the engine tags ANY asset type (endpoint, identity, azure), not just endpoint exclusions. Launcher (`launcher/asset-tagging/launcher.internal-vm.ps1`) updated to dot-source the new path.

If your VisualCron / scheduler currently invokes `engine/asset-tagging-endpoint-exclusions/AssetTagging.ps1` directly, it will throw `Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret)` at line 50 — the engine's SPN-globals guard fires when called outside `$global:AutomationFramework=$true` context. Fix: point the scheduler at the launcher instead:
```
-file <repo>\SOLUTIONS\SecurityInsight\launcher\asset-tagging\launcher.internal-vm.ps1
```
The launcher sets `$global:AutomationFramework=$true`, resolves `$global:SettingsPath` to `<repo>\SOLUTIONS\SecurityInsight\asset-tagging-rules\` automatically, and applies the v2.2 short YAML names (`AssetTagging.locked.yaml` / `AssetTagging.custom.yaml`).

**2. RA: `$laDceRg` resolution priority fix.** The `Invoke-RiskAnalysis.ps1` collision guard read `$global:DceResourceGroup` (legacy Layer-0 default `'rg-dce-securityinsight'`) BEFORE the canonical `$global:SI_DceResourceGroup` set by customers, so the customer's RG override was masked and the collision guard tripped on every Summary ingest:
```
[WARN] DCE collision guard: '<dce>' NOT in sub '...' / RG 'rg-dce-securityinsight'
```
Fix: flipped priority — `SI_DceResourceGroup` (customer-only) wins over `DceResourceGroup` (legacy / Layer-0).

**3. RA: `ImpactedAssetsList` unification across endpoint + identity Summary reports.** Endpoint Summary KQL emitted column `ImpactedAssetsList` (make_set array); Identity Summary KQL emitted column `ImpactedAssets` (semicolon string). Excel union-merged both columns; rows from one report family populated only one of them, so the screenshot column `ImpactedAssetsList` was empty for every Identity row even when `IAssets` count was non-zero.

Fix: engine `Invoke-RiskAnalysis.ps1` post-process now canonicalizes on `ImpactedAssetsList`:
- Reads value from whichever column the YAML emitted (`ImpactedAssets` or `ImpactedAssetsList`)
- Splits semicolon-strings to arrays + dedupes/sorts
- Stores under canonical `ImpactedAssetsList` key, drops `ImpactedAssets` alias
- OutputPropertyOrder loop remaps `ImpactedAssets` → `ImpactedAssetsList` so YAMLs that still list the legacy name in OutputPropertyOrder slot the value into the canonical column

YAMLs unchanged — the fix is engine-side, so all 50+ Identity Summary reports populate the same column in Excel from now on.

---

## v2.2.71 — RA: `$laDceRg` resolution now honors `$global:SI_DceResourceGroup` (was hardcoded fallback to `rg-dce-securityinsight`)

The RA engine resolved its DCE RG from `$global:DceResourceGroup` (legacy name) and fell back to the hardcoded default `'rg-dce-securityinsight'` when that wasn't set. Customers using the canonical SI globals (`$global:SI_DceResourceGroup = 'rg-securityinsight-community-v22'`) had RA's collision guard look in the wrong RG, log:

```
[WARN] DCE collision guard: 'dce-securityinsight-community-v22' NOT in sub '...' / RG 'rg-dce-securityinsight'
```

…then fall through to the module's name-only lookup, which picked a wrong record → 404 / Array bug.

Fix: extend `$laDceRg` resolution to a 3-tier fallback chain:
1. `$global:DceResourceGroup` (legacy explicit override)
2. `$global:SI_DceResourceGroup` (asset-profiling canonical — shared by RA when set in custom.ps1)
3. `'rg-dce-securityinsight'` (hardcoded default — last resort)

Same global, single source of truth across all SI engines.

---

## v2.2.70 — PublicIP: cast `AssetTier` to `[int]` (`InvalidTransformOutput: AssetTier produced 'String' output 'Int'`)

Same root cause as v2.2.61's `DaysInactive` cast bump. PublicIP row emission at `Invoke-PublicIpScanner.ps1:512` did `AssetTier = $t.AssetTier` without explicit cast. The upstream targets carry int values from KQL `toint(coalesce(Tier, 99))` (line 181 endpoint, line 199 azure) and `[int]$tier` (line 779 ExtraIPs), but PowerShell deserialization through the target enumeration loses the type, so the row arrives as String. The existing `dcr-si-publicip` DCR has `AssetTier` as `Int`, ARM rejects the PUT.

Fix: `AssetTier = [int]$t.AssetTier` at line 512. Forward-compatible (new DCRs land as Int too); back-compatible (existing Int DCR accepts Int input).

If you keep hitting this on other columns, the pattern is the same — find the row builder that emits the column, add an explicit `[int]` / `[int64]` / `[bool]` / `[string]` cast at the emission point.

---

## v2.2.69 — PrivilegeTierClassifier: truncate file to first clean copy (was tripled with corruption fragments between)

`engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1` was 3,228 lines containing **three concatenated copies of itself** with corruption fragments between each:
- Copy 1: lines 1-1221 (clean, ends with `Main` invocation)
- Glue garbage: `siRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)` (missing `$` → PowerShell tried to invoke `siRoot` as a cmdlet) + `$OutputFolder = Join-Path #Requires -Version 5.1` (truncated assignment swallowed by start of next copy's `#Requires` line)
- Copies 2 + 3: full re-emissions of the same script with similar glue between them

Symptom on direct invocation:
```
The term 'siRoot' is not recognized as a name of a cmdlet, function, script file, or executable program.
At Invoke-PrivilegeTierClassifier.ps1:1222 char:1
+ siRoot     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
```

Fix: truncate to lines 1-1221, the first complete + clean copy. Parse-check passes. The other two copies + glue fragments deleted.

Likely cause: an editor / sync tool / merge gone wrong appended the file to itself twice. No content lost — copies 2 and 3 were byte-for-byte duplicates of copy 1 (modulo the glue fragments).

---

## v2.2.68 — AssetTagging: v2.2 launcher + Ensure-Module copy (engine no longer fails on direct invocation)

The legacy `engine/asset-tagging-endpoint-exclusions/AssetTagging.ps1` failed when invoked directly with two errors:
1. `_shared\Ensure-Module.ps1 not recognized` — the helper folder didn't exist next to the engine
2. `Missing SPN globals (SpnTenantId/SpnClientId/SpnClientSecret)` — no launcher had set them

Migration to v2.2 entry-point pattern:

**1. Copied `engine/publicip/_shared/Ensure-Module.ps1` to `engine/asset-tagging-endpoint-exclusions/_shared/`** so the engine's `. (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')` line resolves cleanly.

**2. New launcher: `launcher/asset-tagging/launcher.internal-vm.ps1`** (mirrors `launcher/azure/launcher.internal-vm.ps1` pattern):
- Resolves repo root + version
- Loads layered config (Layers 1-5)
- Sets `$global:AutomationFramework = $true` so the SPN check in the engine skips (auth comes from AF + Bootstrap-Auth)
- Defaults `$global:SettingsPath` to `<repo>/SOLUTIONS/SecurityInsight/asset-tagging-rules/`; falls back to the existing `asset-profiling-enrichment/endpoint/` when the dedicated folder isn't present (where today's `AssetTagging.custom.yaml` lives)
- Overrides `$global:LockedYamlFile = 'AssetTagging.locked.yaml'` and `$global:CustomYamlFile = 'AssetTagging.custom.yaml'` to use the v2.2 short names instead of the legacy `SecurityInsight_CriticalAssetTagging_*.yaml`
- Dot-sources `engine/asset-tagging-endpoint-exclusions/AssetTagging.ps1`
- Standard transcript + override-file hooks

**Operator ergonomics:**
- Run `launcher/asset-tagging/launcher.internal-vm.ps1` instead of invoking the engine directly
- Tag-rule YAMLs go in `asset-tagging-rules/AssetTagging.custom.yaml` (or stay in the existing `asset-profiling-enrichment/endpoint/` location — launcher auto-detects)
- Override anything via `SecurityInsight.custom.ps1` or `launcher/asset-tagging/LauncherConfig.custom.ps1`

Engine code unchanged — same 1300-line script, same YAML schema, same merge semantics. Just a clean entry path.

Community-vm launcher + per-engine LauncherConfig samples are TODO for a follow-up — the internal-vm pattern is enough to unblock the immediate use case.

---

## v2.2.67 — Prestage: also create the `securityinsight` blob container (RA xlsx/json export upload target)

The RA engine writes its run artefacts (xlsx + json) to `$global:ExportDestination` — typically `https://<storage>.blob.core.windows.net/securityinsight/`. v2.2.54-66 prestage only created the `sistaging` container (engine staging blobs), leaving RA's export upload to fail with `ContainerNotFound` until the operator created the container by hand.

Prestage now creates BOTH containers in one loop:
- `sistaging` — engine shard blobs (Discover/Collect/Enrich/Classify/Output)
- `securityinsight` — RA xlsx/json export upload target

Logged as:
```
[OK]   Storage container      : sistaging  [exists]
[OK]   Storage container      : securityinsight  [exists]
```

(or `[CREATED]` on first run.)

Operators who use a different export-container name should set `$global:SI_ExportContainer` and compose `$global:ExportDestination` from `$global:SI_StorageAccount` in `custom.ps1` (see updated config sample). The hardcoded `securityinsight` is still always created — additional named containers are operator-managed for now.

Custom config now composes the URL automatically, mirroring the `SI_WorkspaceResourceId` pattern:
```powershell
$global:SI_ExportContainer = 'securityinsight'
$global:ExportDestination  = "https://$($global:SI_StorageAccount).blob.core.windows.net/$($global:SI_ExportContainer)/"
```

---

## v2.2.66 — Prestage: writeback `SI_StorageKey` whenever the file lacks it (drop too-narrow `$saCreated` gate)

The v2.2.57 writeback was gated on `$saCreated -and -not $global:SI_StorageKey` — i.e. only fired when `New-AzStorageAccount` actually ran in this prestage call. Wrong gate: if a PRIOR run created the storage account (so `$saCreated=$true` then) but the writeback was unavailable / failed for any reason, every subsequent run sees `$saCreated=$false` and never re-attempts. The custom.ps1 file never gets the key, and `FingerprintCache.ps1` 403s on every run with `AuthenticationFailed: signature malformed` (empty key in the auth header).

Fix: drop the `$saCreated` requirement. Writeback now fires whenever the in-memory backfill happens AND the file doesn't already have `$global:SI_StorageKey`. Idempotent — once persisted, the in-memory backfill at the top of the function skips (the global is already set from custom.ps1), and writeback skips too.

Operator opt-outs (unchanged):
- Existing plaintext line in custom.ps1 → `$hasKey` check skips writeback
- KV-fetch line (`if (-not $global:SI_StorageKey) { Get-PlatformSecret ... }`) → `$hasKvFetch` check skips writeback

Comment in the appended block now distinguishes "first-create of storage account" (account just created) from "first-fetch (account pre-existed)" so operators can see why it landed.

---

## v2.2.65 — Output: DCR collision guard (mirrors DCE one) -- fixes `404 'westeurope'` from indexed-return shift

The v2.2.63 DCR-immutableId poll resolved the right DCR (`dcr-41f7cad...`), but the ingest still 404'd with `'westeurope'`. Root cause: AzLogDcrIngestPS line 5457 calls `Get-AzDcrDceDetails`, which internally does its OWN name-only `Where-Object` lookup against `$global:AzDcrDetails` (line 3548). When same-named DCRs exist in OTHER subs/RGs (typically previous installs the SPN can still read), `$DcrInfo` becomes an ARRAY → `$DcrImmutableId` becomes ARRAY → PowerShell unrolls them into the implicit return stream → indexes shift → caller's `$azDcrDceDetails[6]` ends up being `DcrLocation` from the second match (`westeurope`) instead of the real immutableId.

Identical bug shape to the DCE collision but for DCRs. Fix: mirror the DCE collision guard. Pre-filter `$global:AzDcrDetails` to remove same-named DCRs that aren't in the expected sub + RG, leave the right one in the cache.

```
DCR collision guard: 3 DCRs named 'dcr-si-endpoint' visible -- pinned to /subscriptions/<sub>/resourceGroups/rg-securityinsight/providers/microsoft.insights/dataCollectionRules/dcr-si-endpoint
```

The poll-for-immutableId loop from v2.2.63 still runs (handles the ARG-propagation lag for fresh DCRs) — this guard handles the OTHER source of the same 404.

---

## v2.2.64 — PublicIP: prefetch DCE/DCR cache before collision guard (was silently no-op'ing)

The v2.2.60 DCE collision guard in `engine/publicip/Invoke-PublicIpScanner.ps1` was gated on `if ($global:AzDceDetails -and ...)` — but the PublicIP engine has its own ingest path that doesn't share state with asset-profiling. On the typical greenfield first-engine run (PublicIP triggered before any asset-profiling engine populates the cache), `$global:AzDceDetails` was `$null`, the guard silently skipped, and the module's internal `Get-AzDceListAll` returned BOTH same-named DCEs → `LinkedAuthorizationFailed: dataCollectionEndpointId 'Array'`.

Fix: explicitly call `Get-AzDceListAll` + `Get-AzDcrListAll` right before the guard so the cache is always populated when the guard runs. Same canonical helpers, same auth params, just explicit.

```powershell
$global:AzDceDetails = Get-AzDceListAll -AzAppId ... -AzAppSecret ... -TenantId ... 4>$null
$global:AzDcrDetails = Get-AzDcrListAll -AzAppId ... -AzAppSecret ... -TenantId ... 4>$null

# DCE collision guard (now actually fires)
if ($global:AzDceDetails -and $global:SI_DceName -and ...) {
    ...
}
```

Asset-profiling Output stage already prefetches the cache (Step 1 of the canonical pattern in `Invoke-Output.ps1`), so this regression was PublicIP-only.

---

## v2.2.63 — Output: poll for DCR `immutableId` in ARG (fix `404 NotFound 'westeurope'` on first ingest)

When `CheckCreateUpdate-TableDcr-Structure` creates a fresh DCR, Azure Resource Graph (ARG) takes 15-120s to index it. During the gap:

- `Get-AzDcrListAll` returns the DCR row, but `properties.immutableId` is empty
- `AzLogDcrIngestPS` falls back to substituting the DCE's location string (`westeurope`) as the URL path segment
- The ingest PUT goes to `.../dataCollectionRules/westeurope/...`
- ARM 404s: `Data collection rule with immutable Id 'westeurope' not found`

The v2.2.51 fix was a hardcoded `Start-Sleep -Seconds 15`. That works on small tenants but loses the race on slow ARG-indexing days.

Replaced with a poll loop:

```
Step 4: re-sync caches after DCR provisioning. Poll up to 120s for the
DCR's immutableId to land in ARG.
  waiting for DCR 'dcr-si-endpoint' immutableId in ARG (15s/120s) ...
  waiting for DCR 'dcr-si-endpoint' immutableId in ARG (30s/120s) ...
  DCR immutableId resolved after 30s: dcr-abc123def456...
```

15s polling interval, 120s ceiling. On most runs the immutableId resolves in 15-30s and the loop exits early. If it never lands, log a `[WARN]` and let the ingest attempt proceed (will surface the 404 with the original error).

Detects "fake" immutableIds (the DCE's location string fallback) so the loop doesn't accept e.g. `westeurope` as a valid id and proceed to a 404.

---

## v2.2.62 — Prestage: tidier `[OK]` log format (fixed 22-char label, status in brackets)

The v2.2.60 log format had alignment problems — padded role names inside quotes (`'Contributor                    '`) and inconsistent column widths between labels. Rewritten with a single `'{0,-22} : {1}'` template and `[exists]` / `[CREATED]` / `[GRANTED]` / `[already granted]` status suffixes:

```
[STEP] Infrastructure check (workspace + DCE/DCR RGs + RBAC + DCE + storage -- idempotent)
 [INFO]   sub          : 54468121-...
 [INFO]   workspace    : log-platform-management-securityinsight  (rg=rg-securityinsight)
 [INFO]   DCE          : dce-securityinsight  (rg=rg-securityinsight)
 [INFO]   DCR RG       : rg-securityinsight
 [INFO]   Location     : westeurope

 [OK]   Az context             : 54468121-98ba-48ba-ba59-ba10a9711ed3
 [OK]   Workspace RG           : rg-securityinsight  [exists]
 [OK]   LA workspace           : log-platform-management-securityinsight  [exists]
 [OK]   DCE RG                 : rg-securityinsight  [exists]
 [OK]   DCR RG                 : rg-securityinsight  [same as DCE RG]
 [OK]   RBAC workspace         : Contributor  [already granted]
 [OK]   RBAC RG rg-securityinsight : Contributor  [already granted]
 [OK]   RBAC RG rg-securityinsight : Monitoring Metrics Publisher  [already granted]
 [OK]   DCE                    : dce-securityinsight  (westeurope)  [exists]
 [OK]   Storage RG             : rg-securityinsight  [exists]
 [OK]   Storage account        : st2linkitsi  [exists]
 [OK]   RBAC storage           : Storage Blob Data Contributor  [already granted]
 [OK]   RBAC storage           : Storage Table Data Contributor  [already granted]
 [OK]   RBAC storage           : Storage Queue Data Contributor  [already granted]
 [OK]   Storage container      : sistaging  [exists]
```

First-run lines show `[CREATED]` / `[GRANTED]` instead. Same idempotent behaviour as v2.2.60, just a readable diff between exists vs created.

---

## v2.2.61 — Profile: cast `DaysInactive` to `[int64]` to match existing DCR `Long` stream type

`Get-SIRiskFactors.ps1` was casting `DaysInactive = [int]$days` (Int32 → Kusto `Int`). When the DCR was originally created from a sample where `$days` happened to fit `Int64` storage, the stream's column type landed as `Long`. Subsequent runs producing `Int` triggered:

```
"InvalidTransformOutput","message":"Types of transform output columns do not match the ones defined by the output stream:
  DaysInactive [produced:'Int', output:'Long']"
```

ARM rejects with `400 BadRequest` because `CheckCreateUpdate-TableDcr-Structure` can ADD columns but can't change a column TYPE on an existing DCR/stream.

Fix: cast `[int64]$days` in both row-builder code paths (endpoint risk factors line 194, identity risk factors line 278). Now produced type is always `Long`, matching whatever the DCR has. Forward-compatible (new DCRs land as `Long` too). Same flow, same canonical AzLogDcrIngestPS pattern — just one type-coercion line per call site.

---

## v2.2.60 — Prestage: per-step `[OK]` infrastructure-check log + DCE collision guard added to PublicIP + RiskAnalysis engines

**1. Verbose `[OK]` infrastructure check.** The prestage helper was mostly silent on success — only logging when something was created or failed. Now each idempotent check emits a line:

```
[STEP] Infrastructure check (workspace + DCE/DCR RGs + RBAC + DCE + storage -- idempotent)
 [INFO]   sub          : <sub-id>
 [INFO]   workspace    : log-platform-management-securityinsight  (rg=rg-securityinsight)
 [INFO]   DCE          : dce-securityinsight  (rg=rg-securityinsight)
 [INFO]   DCR RG       : rg-securityinsight
 [INFO]   Location     : westeurope

 [OK]   Az context already on sub '<sub-id>'
 [OK]   Resource group exists for workspace : 'rg-securityinsight'
 [OK]   LA workspace exists                 : 'log-platform-management-securityinsight'
 [OK]   Resource group exists for DCE       : 'rg-securityinsight'
 [OK]   Resource group for DCR              : same as DCE RG ('rg-securityinsight')
 [OK]   Permission 'Contributor' on workspace        : already granted
 [OK]   Permission 'Contributor                    ' on RG 'rg-securityinsight' : already granted
 [OK]   Permission 'Monitoring Metrics Publisher   ' on RG 'rg-securityinsight' : already granted
 [OK]   DCE exists                          : 'dce-securityinsight' (location=westeurope)
```

When a step actually creates/grants something, the line says `CREATED` / `GRANTED` instead of `exists` / `already granted`, so first-run vs steady-state is visible at a glance.

**2. DCE collision guard added to PublicIP + RiskAnalysis engines.** The v2.2.58/59 strict guard only lived in `engine/asset-profiling/stages/Invoke-Output.ps1`. The PublicIP engine (`engine/publicip/Invoke-PublicIpScanner.ps1`) and RiskAnalysis engine (`engine/risk-analysis/Invoke-RiskAnalysis.ps1`) have their own ingest paths and were still hitting `LinkedAuthorizationFailed: dataCollectionEndpointId 'Array'` on tenants with same-named DCEs across scopes. Same strict `name + sub + RG` guard now lives in both, right before each `CheckCreateUpdate-TableDcr-Structure` call.

---

## v2.2.59 — Output: DCE collision guard now strict (sub + RG only, no waterfall fallback)

v2.2.58 reintroduced the collision guard with the v2.2.47 most-specific-match-first waterfall (`name+sub+RG` → `name+RG` → `name`). On reflection that's wrong for this case — silently picking a same-named DCE in the wrong scope masks a config bug.

Now strict: pin to the entry that matches `name + sub + RG` (using `$global:SI_DceName` + `$global:SI_AzSubscriptionId` + `$global:SI_DceResourceGroup`). If nothing matches, leave the cache alone and emit a loud `[WARN]`:

```
DCE collision guard: 'dce-securityinsight' NOT in sub '<sub-id>' / RG 'rg-securityinsight'.
3 same-named DCE(s) visible in other scopes -- module name-only lookup will pick wrong record.
Verify SI_DceName / SI_AzSubscriptionId / SI_DceResourceGroup.
```

The downstream PUT will still fail (or pick a wrong record), but the operator sees exactly what's wrong and where to fix it. No silent picks.

Guard is gated on all four globals being set (`AzDceDetails`, `SI_DceName`, `SI_AzSubscriptionId`, `SI_DceResourceGroup`) — single-DCE tenants without sub/RG explicitly set get the canonical AzLogDcrIngestPS path unchanged.

---

## v2.2.58 — Output: restore DCE name-collision guard (regression from v2.2.51 simplification)

The v2.2.41 DCE collision guard was inadvertently dropped when v2.2.51 stripped the LA-ingest function down to the canonical AzLogDcrIngestPS pattern. Customers with multiple DCEs sharing a name across subs/RGs (legacy + new install on long-lived tenants) hit the same `LinkedAuthorizationFailed: properties.dataCollectionEndpointId has values which are of invalid types 'Array'` failure that originally motivated v2.2.41.

Root cause unchanged: `AzLogDcrIngestPS.psm1:1575` resolves `$global:SI_DceName` via name-only `Where-Object` lookup. Two matches → `$DceInfo.id` is `string[]` → JSON serializes as array → ARM rejects the DCR PUT.

Fix re-added as Step 1b in `Write-SIClassificationToLogAnalytics` (right after `Get-AzDceListAll`) and again after Step 4 (post-CheckCreateUpdate cache refresh). Pre-filters `$global:AzDceDetails` to ONE entry by name + (optional) sub + RG using the same most-specific-match-first strategy as v2.2.47:

1. `name + sub + RG` (using `$global:SI_AzSubscriptionId` + `$global:SI_DceResourceGroup`)
2. fall back to `name + RG`
3. fall back to `name` only

Logs `DCE collision guard: N DCEs named 'X' visible -- pinned to <id>` only when collision actually fires. Silent in single-DCE tenants.

Smaller than the v2.2.42-50 versions (no diagnostic block, no SCOPE MISMATCH warning, no fallback-to-DcrRg quirks). Just the guard.

---

## v2.2.57 — Prestage: writeback `SI_StorageKey` to custom.ps1 ONLY on first-create of the storage account

v2.2.56 wrote the key on every cold start where `$global:SI_StorageKey` happened to be unset — including cases where the operator deleted the auto-persisted block intentionally (e.g. mid key-rotation, custom-secrets pattern, or just to test re-fetch). That re-wrote the file uninvited.

Tighter gate: a new local `$saCreated` flag is set only when `New-AzStorageAccount` actually fired in this prestage call. The custom.ps1 writeback is gated on `$saCreated -and -not $global:SI_StorageKey`. So:

| State | In-memory backfill | Writeback to custom.ps1 |
|---|---|---|
| First run, account missing → created | ✅ from key1 | ✅ first-time only |
| Subsequent run, account exists, key in custom.ps1 | skipped (already set) | skipped |
| Subsequent run, account exists, key NOT in custom.ps1 (operator deleted block) | ✅ from key1 | ❌ skipped — operator gesture respected |
| Internal-vm with KV-fetch line | skipped (KV wins) | skipped |

When the account exists but the key isn't persisted, the engine logs:
```
storage account already existed -- key in-memory only, not persisted (set $global:SI_StorageKey manually for cold-start)
```

So operators who deleted the block know the engine isn't writing it back, and operators who rotated the key know they need to drop a fresh `$global:SI_StorageKey = '...'` line themselves.

---

## v2.2.56 — Prestage: persist auto-fetched `SI_StorageKey` back to `SecurityInsight.custom.ps1` for cold-start runs

v2.2.54+ prestage backfills `$global:SI_StorageKey` in-memory from `Get-AzStorageAccountKey` on first run, but the value vanished at process exit. Every subsequent cold-start paid the same ARM round-trip (and required the SPN to keep `Microsoft.Storage/storageAccounts/listkeys/action`).

Now the prestage also **writes the key back** into the loaded `SecurityInsight.custom.ps1` so future runs read it from disk.

**How it works:**

1. `Initialize-LauncherConfig.ps1` records the loaded layer-3 path in `$global:SI_LoadedCustomConfigPath` (whether the file exists or not — supports CREATE-on-first-run too)
2. After `Get-AzStorageAccountKey` succeeds in prestage, the helper:
   - Reads the file content
   - Skips the writeback if the file already has a non-empty `$global:SI_StorageKey = '...'` line (operator-set wins)
   - Skips the writeback if the file has the canonical `if (-not $global:SI_StorageKey) { $global:SI_StorageKey = Get-PlatformSecret ... }` KV-fetch line (internal-vm pattern)
   - Otherwise appends:
     ```
     # Auto-persisted by SI v2.2.56+ prestage (first-run storage account key1).
     # Remove this block to force re-fetch from Azure on next run.
     $global:SI_StorageKey = '<key1>'
     ```

**Operator escape hatches:**

- Delete the auto-persisted block in `custom.ps1` → next run re-fetches and re-persists (use after a key rotation)
- Set `$global:SI_StorageKey = '...'` manually → wins, writeback skipped
- Use the KV-fetch line (internal-vm pattern) → wins, writeback skipped

**Idempotent:** the writeback runs at most once per file. Subsequent runs see the value in custom.ps1, the in-memory `$global:SI_StorageKey` is already set, and the prestage skips both the ARM call and the writeback.

**Security note:** the key lands in plaintext on disk. The SecurityInsight `.gitignore` already excludes `config/SecurityInsight.custom.ps1` — but operators with stricter handling requirements should set `$global:SI_StorageKey = '...'` manually from a vault-backed source instead.

---

## v2.2.55 — Prestage moved from Stage 8 (Output) to engine entry — fixes chicken-and-egg with `SI_StorageKey`

The v2.2.54 prestage lived in `Write-SIClassificationToLogAnalytics` (Stage 8 / Output stage), so the storage account creation + `SI_StorageKey` backfill happened LATE in the run. But `Invoke-SIEngineRun.ps1` validates `$global:SI_StorageKey` at engine entry (line ~158) — long before Stage 8. Greenfield runs threw `StorageAccountKey is required` and never reached prestage.

Fix: prestage call now lives in `Invoke-SIEngineRun.ps1` BEFORE the storage validation switch. Order is now:
1. Parse params + resolve CollectionTime
2. **Prestage** (creates RGs + workspace + DCE + storage account + RBAC, backfills `SI_StorageKey` from key1)
3. Storage validation (passes — SI_StorageKey is now set)
4. Stages 1-9 run normally

Gated by:
- `$PSCmdlet.ParameterSetName -ne 'Mock'` — no Azure in mock mode
- `$Sinks -contains 'LA'` — no infra needed for JSON/Excel-only runs
- `$global:SI_PrestageInfra -ne $false` — operator opt-out
- `$global:SI_AzSubscriptionId` AND `$global:SI_SPN_ObjectId` non-empty (otherwise WARN + skip)

The Stage 8 prestage block is removed (was running twice). Backfilled globals (`SI_WorkspaceResourceId`, `SI_DceName`, `SI_DcrResourceGroup`, `SI_DceResourceGroup`, `SI_AzSubscriptionId`) are visible to every downstream stage including Stage 8 ingest.

Greenfield community first-run sequence now works cleanly:
- Operator sets only auth + 4 names: `SI_AzSubscriptionId`, `SI_WorkspaceName`, `SI_DceName`, `SI_StorageAccount`
- Engine creates 3 RGs + workspace + DCE + storage account + sistaging container + grants 7 role assignments
- `SI_StorageKey` backfilled from key1
- All stages proceed; LA ingest succeeds on first try

---

## v2.2.54 — Prestage: also create storage account + sistaging container + grant Storage Data RBAC + backfill SI_StorageKey

Extension to the v2.2.53 pre-stage helper. When `$global:SI_StorageAccount` is set, the engine now also creates the storage account if missing, grants the SPN the three Storage Data Contributor roles (Blob/Table/Queue), creates the `sistaging` container, and backfills `$global:SI_StorageKey` from the storage account's `key1` when the global is empty.

Order of `SI_StorageKey` resolution (first non-empty wins):
1. Operator's `custom.ps1` (`$global:SI_StorageKey = '...'`)
2. Lazy KV-fetch line in `custom.ps1` (`Get-PlatformSecret -Name 'SI-StorageKey'`) — internal-vm pattern
3. Prestage backfill from `Get-AzStorageAccountKey` — zero-config / community pattern

Internal-vm operators who store the key in Key Vault keep their existing flow (KV-fetch wins, prestage sees `SI_StorageKey` set and skips). Community / zero-config operators get the key auto-populated on first run with no manual KV step.

**New steps in `Invoke-SIPrestageInfra` (gated by non-empty `-StorageAccountName`):**

9a. Create storage RG if missing (defaults to workspace RG)
9b. Create storage account if missing (Standard_LRS, StorageV2, HTTPS only, TLS 1.2+, public blob access disabled)
9c. Grant `Storage Blob Data Contributor` + `Storage Table Data Contributor` + `Storage Queue Data Contributor` on the storage account scope
9d. Backfill `$global:SI_StorageKey` from `key1` if not already set
9e. Create `sistaging` container if missing (private)

**New optional global:**
- `$global:SI_StorageResourceGroup` — defaults to workspace RG when unset

**Required global** (unchanged):
- `$global:SI_StorageAccount` — must be set for the storage block to run; lowercase + digits, 3-24 chars, globally unique

If `SI_StorageAccount` is empty, the storage block is skipped entirely (LA-only deployments still work but staging features will fail downstream when the engine actually tries to use blob storage).

**Storage RBAC requirement (operator-side):** the engine SPN needs `User Access Administrator` OR `Owner` somewhere up the scope chain to grant the three Storage Data roles. Same as v2.2.53; one bootstrap, runs forever.

**Other infra not pre-staged** (separate solutions or out of scope):
- Azure OpenAI (separate solution; key in `$global:OpenAI_apiKey`)
- Power BI workspace (separate solution; deployed via Step 4)
- Container App job + ACR + KEDA (only when `$global:SI_HostMode = 'container'`)
- Defender XDR licensing (Microsoft-managed, not pre-stageable)
- SMTP relay (external service)
- ServiceNow CMDB CSV (file path)

---

## v2.2.53 — Output: idempotent infra pre-stage (LA workspace + DCE + DCR RGs + RBAC) before LA ingest

After v2.2.51 stripped the engine's RBAC self-heal, customers hit the well-known propagation lag: a freshly-auto-created DCR's RG-scoped `Monitoring Metrics Publisher` grant doesn't reach the data plane in time, so the very first ingest 403s on it. Older DCRs in the same RG worked fine because their grants had propagated long ago.

New `engine/asset-profiling/shared/Invoke-SIPrestageInfra.ps1` runs once per ingest, BEFORE `Get-AzDceListAll`, gated by `$global:SI_PrestageInfra` (default ON). Read-then-write idempotent — existing resources / role assignments are no-ops.

**Steps (each isolated in its own try/catch — one failure doesn't kill the rest):**

1. Set Az subscription context
2. Create **workspace RG** if missing (default: `rg-securityinsight`)
3. Create **LA workspace** if missing (default: `log-platform-management-securityinsight`, SKU PerGB2018, retention 90d)
4. Create **DCE RG** if missing (default: `rg-securityinsight`)
5. Create **DCR RG** if missing (default: `rg-securityinsight`)
6. Grant `Contributor` on **workspace** (table create/update needs it)
7. Grant `Contributor` + `Monitoring Metrics Publisher` on **DCE RG**
8. Grant `Contributor` + `Monitoring Metrics Publisher` on **DCR RG**
9. Create **DCE** if missing (default: `dce-si-securityinsight`, public network access enabled)
10. Sleep 30s for ARM/RBAC propagation IF anything was actually created/granted

**New globals (all optional — sensible defaults baked in):**

| Global | Default | Purpose |
|---|---|---|
| `$global:SI_PrestageInfra` | `$true` | Skip the entire pre-stage (set `$false` for IaC-managed deployments) |
| `$global:SI_AzSubscriptionId` | parsed from `SI_WorkspaceResourceId` | Sub for all created resources |
| `$global:SI_WorkspaceName` | `log-platform-management-securityinsight` | LA workspace name |
| `$global:SI_WorkspaceResourceGroup` | `rg-securityinsight` | LA workspace RG |
| `$global:SI_DceName` | `dce-si-securityinsight` | DCE name (was previously required) |
| `$global:SI_DceResourceGroup` | `rg-securityinsight` | DCE RG |
| `$global:SI_DcrResourceGroup` | `rg-securityinsight` | DCR RG (was previously required) |
| `$global:SI_Location` | `westeurope` | Region for any newly-created resource |

If `SI_WorkspaceResourceId` is set, the workspace name + RG + sub are parsed from it (canonical source). Resolved values are written back to `$global:` so downstream code (CheckCreateUpdate, Post-*) sees them. The **previously-required** trio (`SI_WorkspaceResourceId`, `SI_DceName`, `SI_DcrResourceGroup`) are now optional — engine will derive defaults and create resources.

**RBAC requirement (operator-side, one-time):**

The engine SPN now needs `User Access Administrator` OR `Owner` SOMEWHERE in the scope hierarchy (sub or higher) to perform the role grants. If the SPN can't grant, individual steps log a `WARN` and continue; ingest may still 403 if MMP propagation hasn't finished, but the operator sees WHY in the transcript.

**Zero-config first run:** an operator with only SPN auth set in `custom.ps1` can now run the engine end-to-end — pre-stage creates everything, ingest succeeds.

---

## v2.2.52 — Profile: silently skip `AssetTagging.custom.yaml` foreign-schema files in the rule loader

`Get-SIRuleSet` recursively scans `asset-profiling-enrichment/<engine>/` for `*.yaml` files and treats every match as a posture rule. When customers drop `AssetTagging.custom.yaml` (asset-tagging-engine shape: top-level key `AssetTagging: [...]`, no `id:`) into the same folder, the loader emits a noisy `WARNING: Get-SIRuleSet: skipping AssetTagging.custom.yaml (no id field)` on every run.

The file is legitimate — it's consumed by the asset-tagging engine, just shares the folder. Loader now detects the asset-tagging shape (`obj.PSObject.Properties.Name -contains 'AssetTagging'`) and skips silently before the `id` check fires. Other malformed yaml files still get the `(no id field)` warning so genuine schema breakage is still surfaced.

---

## v2.2.51 — Output: rewrite LA ingest with the canonical AzLogDcrIngestPS pattern (drop ~300 lines of guards/diagnostics/self-heal)

`Write-SIClassificationToLogAnalytics` had grown to ~590 lines of layered safety (DCE collision guard, DCR pre-create diagnostic, RBAC pre-flight check, `SI_SkipDcrAutoCreate` opt-out, 3-attempt retry with self-heal `New-AzRoleAssignment` on 403). Each fix made sense in isolation, but the cumulative complexity was fighting the canonical pattern instead of reinforcing it — and the self-heal kept failing because RBAC propagation can outlast 3×60s.

Rewrite: the entire ingest block now mirrors the v2.1 RA engine (`Invoke-RiskAnalysis.ps1` lines 5914-6000) — six steps, no retries, no self-heal:

1. `Get-AzDceListAll` + `Get-AzDcrListAll` — full caches fresh
2. Schema sample (full dataset, CollectionTime stamped)
3. `CheckCreateUpdate-TableDcr-Structure` — provision DCR + table
4. `Start-Sleep 15s` + re-fetch caches (lets new DCR's immutableId land in ARG)
5. Standard 4-step prep: CollectionTime / Add-Column (Computer/Fqdn/User) / ValidateFix / Build-DataArray
6. `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` — single attempt, no retry

File shrunk 786 → 489 lines.

**What's required in `SecurityInsight.custom.ps1`** (all of these are non-negotiable; engine fails loud if missing):

```powershell
# Workspace + DCE/DCR identity
$global:SI_WorkspaceResourceId = '/subscriptions/<sub>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<ws>'
$global:SI_DceName             = 'dce-si-securityinsight'
$global:SI_DcrResourceGroup    = 'rg-securityinsight'    # where DCRs live (auto-created if absent)

# SPN auth (Bootstrap-Auth.ps1 populates these from KV)
$global:SI_SPN_TenantId = '<tenant-id>'
$global:SI_SPN_AppId    = '<spn-app-id>'
$global:SI_SPN_Secret   = '<spn-client-secret>'
$global:SI_SPN_ObjectId = '<spn-object-id>'   # SP ObjectId, NOT AppId
```

**What's required in Azure** (Bootstrap-Auth or Setup-SecurityInsight handles this once):
- DCE exists at `$global:SI_DceName`
- SPN has: `Contributor` + `Monitoring Metrics Publisher` on the DCR RG, `Reader` on the DCE RG, `Contributor` on the workspace

If RBAC is missing, the ingest 403s. The engine no longer tries to grant — that's the bootstrap's job. Fix once, run forever.

**Removed config knobs** (no longer honored, all were band-aids on the broken pattern):
- `$global:SI_SkipDcrAutoCreate` — engine always provisions
- `$global:SI_DcrMergeDiagnostic` — DCR-merge auditing dropped (use Azure Monitor's own audit logs)
- `$global:SI_DceResourceGroup` — DCE RG is now derived from the cache lookup; engine doesn't need it told twice
- `$global:SI_AzSubscriptionId` — derived from workspace ARM id

The simplification deliberately gives up the multi-DCE collision guard. If a tenant has two DCEs with the same name across subs/RGs, the canonical module's name lookup will return both and the DCR PUT fails with `LinkedAuthorizationFailed: invalid types Array`. Fix that at the source: rename one DCE.

---

## v2.2.50 — Output: drop SCOPE-MISMATCH false positive when DCE lives in a different RG by design

v2.2.47 added a `SCOPE MISMATCH` warning when the DCE picker fell back from `name+sub+RG` to `name+RG` or `name`-only matching. v2.2.46/47 also kept the pre-existing fallback `SI_DceResourceGroup ?? SI_DcrResourceGroup` for the DCE-RG expectation. Combined, this fired a false-positive warning on **split-RG community layouts** where:
- DCE lives in `rg-dce-securityinsight-community` (its own RG, by design)
- DCRs live in `rg-securityinsight-community` (different RG)
- `SI_DceResourceGroup` unset (community config relies on the DCE name being globally unique)

The diagnostic incorrectly compared the DCE's actual RG against the DCR's RG (via the fallback), saw mismatch, fired:
```
WARNING: SCOPE MISMATCH -- expected sub='' RG='rg-securityinsight-community' but picked DCE is in sub='ef830ec3-...' RG='rg-dce-securityinsight-community'.
```
The picker found the right DCE — the warning was just wrong.

Fix:
1. **Drop the DcrRg fallback** in both the v2.2.41 collision guard and the v2.2.46 diagnostic. DCE has its own home; using DcrRg as a substitute is a conventional shortcut that breaks split-RG layouts. When `SI_DceResourceGroup` is unset, the picker now degrades cleanly to name-only matching.
2. **Only warn on EXPLICIT mismatch.** New picker considers `SI_AzSubscriptionId` and `SI_DceResourceGroup` independently:
   - If both set: try `name+sub+RG`; on miss try `name+RG` (warn: sub mismatch) → `name+sub` (warn: RG mismatch) → `name` only (warn: both mismatch)
   - If only one set: try that one; degrade silently to name-only when not satisfiable
   - If neither set: name-only matching, no warnings

Net effect: the warning still fires when an operator explicitly told us where the DCE should live and the picker had to fall back. It no longer fires when the operator didn't specify expectations.

To suppress this specific false positive without upgrading: set `$global:SI_DceResourceGroup = 'rg-dce-securityinsight-community'` (the DCE's actual RG) in `SecurityInsight.custom.ps1`.

---

## v2.2.49 — Catalog: delete 13 unscoped workstation/IoT rules + scope `TestSandboxServer` to `[WindowsServer, Linux]`

Endpoint catalog had 16 unscoped rules (no `osPlatformScope` → ran against every asset class). v2.2.44 + v2.2.45 made the bucketing optimization actually work but only for properly-scoped rules — the 16 unscoped ones still bloated every per-asset bucket. Pruning them down:

**Deleted (13 rules + 13 .custom.sample.yaml companions = 26 files)** — all from `asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/`:

*Workstation/PAW classification (8)* — better handled by the asset-tagging engine's `PAWDevices--tier0--SI` / `BYODPersonalDevice--tier3--SI` tag rules (which classify device cohorts upstream of profiling):
- `PrivilegedAccessWorkstationPAWForTier0Admins`
- `PrivilegedAccessWorkstationPAWForTier1Admins`
- `AdminWorkstationUsedByTier1StaffWithoutPAWControls`
- `PowerUserWorkstationFinanceLegalHR`
- `ProductionWorkstation`
- `PersonallyOwnedBYODDevice`
- `SharedDevice`
- `SharedClassroomLibraryComputer`

*IoT / non-traditional endpoints (5)* — too narrow / too brittle for app-detection patterns; better handled via MDE machine groups + tag-engine rules:
- `ConsumerIoTDeviceIsolatedGuestVLAN`
- `NonNetworkedOrAirGappedSensor`
- `USBOnlyPeripheralWithFirmwareUpdateCapability`
- `VendingMachineCoffeeMachineWithNetworkConnectivity`
- `WearableSmartBadgeNoDomainIntegration`

**Scope-tagged (1)** — `TestSandboxServer.locked.yaml` + companion sample now declare `osPlatformScope: [WindowsServer, Linux]`. Was unscoped (running against every asset class) but conceptually server-only — workstations don't get a "Test/Sandbox Server" tier.

**Net effect on rule counts:**
| Bucket | Before | After |
|---|---|---|
| Total rules | 559 | 546 |
| Unscoped | 16 | **2** (just the two top-level catalogs `AssetProfileByDeviceType` + `AssetProfileByLogonUser`) |
| WindowsClient bucket | 16 | **2** (8x fewer rules per workstation) |
| WindowsServer bucket | 559 | 546 |
| Linux bucket | 559 | 546 |

Per-asset eval cost on workstation-heavy fleets drops further — workstations now scan only 2 rules instead of 16, on top of v2.2.44's 35x reduction.

The two top-level catalogs (`AssetProfileByDeviceType` + `AssetProfileByLogonUser`) remain unscoped by design — they classify by cross-OS device-type signals and logon-user patterns that genuinely apply to every endpoint class.

---

## v2.2.48 — Output: rebuild `$global:AzDceDetails` + `$global:AzDcrDetails` fresh on every ingest (canonical AzLogDcrIngestPS pattern)

Engine was using `if (-not $global:AzDceDetails) { Get-AzDceListAll }` — a "fetch only when empty" guard added to avoid extra ARG calls. Two problems with that approach:

1. **Stale state across ingests in one run.** v2.2.41's collision guard prunes `$global:AzDceDetails` to a single entry. The next ingest in the same engine run still sees the pruned cache (only one DCE), so collision logic can't re-evaluate against the full tenant view. After a multi-ingest run (multiple Profile tables), only the FIRST one had accurate cache state.
2. **Deviates from the canonical `AzLogDcrIngestPS` pattern.** The module's docs and example scripts always call `Get-AzDceListAll` + `Get-AzDcrListAll` fresh before each ingest. The "fetch only when empty" gate skipped that refresh, missing newly-bootstrapped DCEs/DCRs created by other engine runs that happened between this engine's iterations.

Fix: at the top of `Write-SIClassificationToLogAnalytics`, the engine now ALWAYS calls `Get-AzDceListAll` + `Get-AzDcrListAll` fresh (SPN auth path). The collision guard then runs against fresh full-tenant data, prunes if needed, and the NEXT ingest starts the cycle over with another fresh fetch — undoing any prior prune. MI-auth path keeps the "fetch when empty" gate (the helper signature for MI is different and the canonical IMDS scope handles refresh elsewhere).

Cost: 1-3 extra seconds per ingest call (two ARG queries). Acceptable given the correctness gain. Also matches the canonical pattern, so future operators reading the engine code see the same flow they see in `AzLogDcrIngestPS` examples.

Existing post-`CheckCreateUpdate-TableDcr-Structure` refresh of `$global:AzDcrDetails` (around line 410) is preserved — it's still needed to discover the just-created DCR's `immutableId` for the immediate `Post-*` call.

---

## v2.2.47 — Output: DCE picker now correlates by sub + RG + name (not just name)

Both the v2.2.41 collision guard AND the v2.2.46 diagnostic only correlated DCEs by **name + RG**. Generic RG names (`rg-securityinsight`) often exist in multiple subs the SPN can read across the tenant, so a DCE named `dce-si-securityinsight` in the wrong sub's `rg-securityinsight` could still be picked.

Fix: both code paths now use the **most-specific match first** strategy:
1. `name + sub + RG` (full match — `$global:SI_AzSubscriptionId` + `$global:SI_DceResourceGroup` + `$global:SI_DceName`)
2. fall back to `name + RG` (sub mismatch)
3. fall back to `name` only (RG mismatch — last resort, almost certainly wrong)

When the picker falls back to a less-specific match (i.e., the most-specific lookup found nothing), the diagnostic now logs:
```
DCR pre-create  : SCOPE MISMATCH -- expected sub='<sub-id>' RG='rg-securityinsight' but picked DCE is in sub='<other-sub>' RG='rg-other'.
DCR pre-create  : Likely cause: the DCE name is reused across multiple subs/RGs in this tenant and the engine picked a same-named DCE the SPN can read. Set $global:SI_DceResourceGroup + $global:SI_AzSubscriptionId to disambiguate.
```

Diagnostic also now logs `DceSubscription` line so operator sees all three coordinates (sub / RG / name) without parsing the resource id by hand.

Companion to v2.2.46 — both rely on `$global:SI_AzSubscriptionId` being set in `SecurityInsight.custom.ps1` (it usually is, sourced from `$global:MainLogAnalyticsWorkspaceSubId` in the canonical sample).

---

## v2.2.46 — Output: fix v2.2.42 DCR diagnostic showing wrong DCE + new `SI_SkipDcrAutoCreate` opt-out

**1. v2.2.42 DCR pre-create diagnostic showed the WRONG DCE.** Bug: the diagnostic took `@($global:AzDceDetails)[0]` instead of filtering by name. On tenants where the SPN can read DCEs from other tools (Azure Monitor starter pack, etc.), the cache contains many DCEs and `[0]` returned a random unrelated record — typically logging `DceLocation = westeurope, DceResourceId = .../AMP-prod-DCE-westeurope` while `DceName = dce-si-securityinsight`. Operators saw inconsistent output and (correctly) thought the engine was about to use the wrong DCE.

The MODULE wasn't actually picking the wrong DCE — its lookup at `AzLogDcrIngestPS.psm1:1575` is name-based and correctly returned `$null` when the configured name didn't exist. But the diagnostic was misleading.

Fix: diagnostic now filters `$global:AzDceDetails | Where { $_.name -eq $global:SI_DceName } | Select -First 1`. When no match found, logs:
```
DceLocation        = <NOT FOUND in cache -- name does not match any DCE the SPN can read>
DceResourceId      = <NOT FOUND in cache>
[WARN] DCE 'dce-si-securityinsight' NOT visible to SPN. Module will fail with null location/id.
[WARN] Fix: verify the DCE name in Azure (Get-AzDataCollectionEndpoint), or check SPN has Reader on the DCE RG.
[WARN] Cache size: 47 DCEs visible. None named 'dce-si-securityinsight'.
```
Also adds `DceResourceGroup` line (parsed from id) so operator can confirm the DCE lives in the expected RG.

**2. New global: `$global:SI_SkipDcrAutoCreate`.** Opt-out for the engine's auto-provision of DCR shape via `CheckCreateUpdate-TableDcr-Structure`. When `$true`, the engine assumes DCE + DCR + table already exist with the right schema and skips the ARM PUT entirely. Useful when:
- operator manages DCE/DCR via IaC (Bicep/Terraform) and doesn't want the engine touching ARM
- SPN has Reader-only on the DCR scope (can ingest but can't create/update DCR shape)
- schema is known-stable and operator wants to skip the 5-15s round-trip per ingest

Trade-off: schema drift in the data array (new column emitted upstream) won't auto-migrate the DCR — operator must update DCR by hand or re-enable for one run. Logged as `CheckCreateUpdate-TableDcr-Structure : SKIPPED ($global:SI_SkipDcrAutoCreate = $true)` so it's obvious from transcripts.

Set in `SecurityInsight.custom.ps1`: `$global:SI_SkipDcrAutoCreate = $true`.

---

## v2.2.45 — Profile: skip kustoSets KQL for rules whose `osPlatformScope` can't match any loaded asset

`Build-SIEgKustoQuerySets` (Pass 2 BULK FETCH index builder) ran the per-rule Defender Advanced Hunting KQL for every rule with `kind: egKustoQuery`, regardless of whether any loaded asset could possibly match that rule's `osPlatformScope`. On a workstation-only smoke test the AD/DC rule (`osPlatformScope: [WindowsServer, Linux]`) still cost 11s of cold-query round-trip even though zero loaded assets were servers — pure waste.

Fix: `Build-SIRuleIndexes` now computes the set of OS classes actually represented in `$Assets` (using the same `Get-SIAssetOsClass` helper Pass 3 uses) and passes it to `Build-SIEgKustoQuerySets`. The builder now pre-filters: rules with non-empty `osPlatformScope` whose scope doesn't intersect any present class are skipped without running KQL. Unscoped rules (empty `osPlatformScope`) always run.

Build stat now includes `SkippedByOsClass=N` when any rule was filtered. Today there's only one `egKustoQuery` rule (`ADDomainController.locked.yaml`), so the win is binary: workstation-only runs save the full 11s; mixed-OS runs are unchanged. As more rules adopt `egKustoQuery`, the savings compound.

Companion to v2.2.44 — relies on `osPlatformScope` actually being on the rule object (the v2.2.44 fix). Cumulative effect on small/scoped runs: Pass 2 + Pass 3 ~10-15x faster.

---

## v2.2.44 — Profile: revive v2.2.40 OS-class bucketing (rule loader was dropping `osPlatformScope`)

The v2.2.40 optimization (pre-bucket rules by OS class so workstations skip 543/559 server-only rule iterations) was silently dead for ~4 releases. Symptom: log line `rule buckets: unscoped=559 | WindowsServer=559 WindowsClient=559 Linux=559 ...` — every OS class showed all 559 rules as if every rule were unscoped, so per-asset evaluation iterated all 559 rules regardless of OS. On 4523 endpoints that's ~2.5M rule evals per run vs the ~150K the bucketing was designed to deliver (~17x slowdown). Live tenant ran at ~0.9 assets/sec.

Root cause: `Get-SIRuleSet.ps1` Pass-1 rule loader (line 216-227) built the compiled rule object with `Id, AppliesTo, Mode, Purpose, Category, Description, Detections, File, Folder, SchemaShape` — but **never copied `osPlatformScope`** from the source YAML. Invoke-Profile.ps1's bucketing pass at line 88 reads `$rule.osPlatformScope`, got `$null` for every rule, classified all 559 as unscoped.

Fix: rule loader now reads `$obj.osPlatformScope` from the YAML (handles both array and CSV-string forms; case-insensitive class names), normalizes to a string array, and emits it as `osPlatformScope` on the rule object. Compatible with the existing `osPlatformScope: [WindowsServer, Linux]` shape used by the 557 AppService rules tagged in v2.2.34.

Expected impact next run: `unscoped` count drops from 559 to ~2 (the small set of truly cross-OS rules); `WindowsClient` bucket drops from 559 to ~20-50 (unscoped + client-tagged); `WindowsServer` bucket stays near 559. Per-asset eval rate should jump 5-15x for non-server fleets.

No behaviour change beyond performance — same matches, same tier results, same `ScopeSkipped` counter (which was always 0 because the inline-skip path never ran with bucketing on).

---

## v2.2.43 — Identity: gate EG sample-dump diagnostics behind `$global:SI_Verbose`

`IdentityRoleFetcher.ps1` `Resolve-IdentityRoleAssignments` was unconditionally
emitting two `[INFO]` lines per EG node label (group / user / serviceprincipal /
managedidentity) on every run — sample EntityIds + sample rawData keys.
Useful for first-time schema diagnosis but pure noise on stable tenants.

Now gated behind `$global:SI_Verbose` (the same flag used by other
diagnostic-only blocks across the engine). Always-on counters
(`[perms] EG identity nodes ... rows=N skip-no-aadOid=M` + per-type
`total/kept/skip-no-aadOid` table) are unchanged — those are needed to spot
coverage drift run-over-run.

To re-enable for one run: `$global:SI_Verbose = $true` in
`SecurityInsight.custom.ps1` or per-launcher `LauncherConfig.custom.ps1`.

---

## v2.2.42 — Output: DCR pre-create diagnostic + RBAC self-heal + PublicIP AssetId/AssetType + Setup hardening

Five fixes bundled, all targeting the bootstrap-and-first-ingest path.

**1. DCR pre-create diagnostic (`engine/asset-profiling/stages/Invoke-Output.ps1`).**
After the v2.2.41 collision guard, customers still hit `RequestDisallowedByPolicy` when an Allowed-locations Azure Policy denies DCR creation. Symptom is opaque because AzLogDcrIngestPS sets the new DCR's `location` field from `$DceInfo.location` (module line 1725), not from `$global:SI_Location` — so a misnamed/misplaced DCE silently mints DCRs in the wrong region and the policy denies the PUT.

New diagnostic block runs once per DCR, immediately before `CheckCreateUpdate-TableDcr-Structure`. Logs six lines:

```
DCR pre-create  : DcrName            = dcr-si-identity-profile
DCR pre-create  : DcrResourceGroup   = rg-securityinsight
DCR pre-create  : SI_Location        = westeurope  (engine intent; NOT used by module for new DCR)
DCR pre-create  : DceName            = dce-si-securityinsight
DCR pre-create  : DceLocation        = northeurope  (THIS becomes new DCR location -- AzLogDcrIngestPS.psm1 line ~1725)
DCR pre-create  : DceResourceId      = /subscriptions/.../dce-si-securityinsight
```

Emits a 3-line `[WARN]` block when `SI_Location ≠ DceLocation` calling out the mismatch, what the new DCR location will be, and the fix (recreate the DCE in the allowed location). Also handles the wrong-name case — when the lookup misses, logs `<no DCE in cache>` so the operator immediately sees the name mismatch instead of chasing a phantom policy denial.

Always-on; no flag. One-time per DCR per run, low noise.

**2. RBAC pre-flight check (`engine/asset-profiling/stages/Invoke-Output.ps1`).**
Before the first ingest of every DCR, the engine queries `Get-AzRoleAssignment` for `Monitoring Metrics Publisher` at the DCR RG scope. If missing, logs a loud `[WARN]` block with the exact `New-AzRoleAssignment` to copy/paste. Cheap (one ARM call), one-time per run, catches the silent-RBAC-gap case where the bootstrap forgot to grant or the grant lives at a higher scope and hasn't propagated.

**3. RBAC self-heal on 403 ingest (`engine/asset-profiling/stages/Invoke-Output.ps1`).**
Existing 3-attempt retry loop only matched `404|NotFound|immutable Id` (DCR-cache transient). Now also matches `403 + 'does not have access to ingest'` (RBAC). On RBAC match, the engine attempts `New-AzRoleAssignment -RoleDefinitionName 'Monitoring Metrics Publisher' -Scope <DCR resource id>` (resource scope = sub-60s propagation vs 5-30 min for RG-scope), sleeps 60s, retries. Idempotent — checks for existing assignment first. Requires the engine SPN to have User Access Administrator or Owner somewhere in scope hierarchy; if the grant call itself fails, surfaces a clear `[WARN]` and falls through to the next retry.

**4. Setup hardening: resource-scope MMP grant per DCR (`Setup-SecurityInsight.ps1`).**
After `CheckCreateUpdate-TableDcr-Structure` succeeds, Setup now grants `Monitoring Metrics Publisher` directly on the just-created DCR's resource id (in addition to the existing RG-scope grant a few lines later). The RG grant covers future auto-created DCRs via inheritance, but propagation to a specific DCR can lag and stalls the very first ingest. Resource-scope grant is fast (<60s) and idempotent — checks `Get-AzRoleAssignment` first.

**5. PublicIP engine emits `AssetId` + `AssetType` (`engine/publicip/Invoke-PublicIpScanner.ps1`).**
Shodan/PublicIP rows in `SI_VulnerabilityPIP_CL` were missing two columns the locked RA queries project:
- `AssetId` — schema declared it (`alias of PrimaryEntityId = the public IP itself`) but the row builder never emitted it
- `AssetType` — cross-engine identity field (`'PublicIP'` for this engine), missing entirely

Result: 4 RA report queries (`PublicIP_OpenPorts_Summary/Detailed`, `PublicIP_Vulnerabilities_Summary/Detailed`) failed with KQL `SEM0100 -- Failed to resolve scalar expression named 'AssetId'`, even though the engine ran clean and ingested rows. Engine now emits both fields on every row; queries resolve and return the expected per-IP findings. No schema/DCR change required (existing DCR auto-merges the new columns on next run).

---

## v2.2.41 — Output: DCE name-collision guard (fix LA ingest LinkedAuthorizationFailed)

Live customer hit `LinkedAuthorizationFailed: properties.dataCollectionEndpointId has values which are of invalid types 'Array'` on every DCR auto-create. Root cause: AzLogDcrIngestPS line 1575 resolves `$global:SI_DceName` via `$global:AzDceDetails | Where-Object { $_.name -eq $DceName }` — when two DCEs share that name across subs/RGs (legacy + new shape on long-lived tenants), the lookup returns BOTH records. `$DceInfo.id` becomes `string[]`, gets serialized as JSON array into the DCR PUT body, ARM rejects.

Engine-side fix in `Invoke-Output.ps1` `Write-SIClassificationToLogAnalytics`: before calling `CheckCreateUpdate-TableDcr-Structure`, pre-filter `$global:AzDceDetails` to a single entry by name + RG. Honors new optional `$global:SI_DceResourceGroup` (falls back to `$global:SI_DcrResourceGroup` if not set). When the cache is empty, queries Azure Resource Graph via `Get-AzDceListAll` first.

Logs `DCE collision guard: N DCEs named 'X' visible -- pinned to RG 'Y' (id)` only when collision detected — silent pass-through when there's a clean single match.

No customer config required to benefit; setting `$global:SI_DceResourceGroup` makes the disambiguation explicit when the DCE lives in a different RG than the DCRs.

---

## v2.2.40 — Profile: pre-bucket rules by OS class (skip 543/559 inner-loop iterations per workstation)

Phase 6 Profile inner loop iterated all 559 rules per asset and `continue`d when the rule's `osPlatformScope` didn't match the asset's OS class. On 5275 assets × 543 server-scoped rules that's ~2.86M wasted iterations + per-iteration `@($scope) -notin` allocs.

New: **Pass 2.5 BUCKET RULES BY OS CLASS** runs once between BULK FETCH and PER-ASSET. Builds `$rulesByOsClass = @{ WindowsServer=...; WindowsClient=...; Linux=...; ... }` where each bucket = (rules with no `osPlatformScope`, run on every asset) + (rules whose scope contains that class). Unscoped rules are pointer-shared across buckets (no data duplication).

Per-asset loop now iterates `$rulesByOsClass[$assetOsClass]` directly — drops the inline scope check from the hot path. `$skipScope` stat preserved for visibility (computed as `$_totalRules - $bucketSize` per asset).

Logged at startup: `rule buckets: unscoped=N | WindowsServer=X WindowsClient=Y Linux=Z ...` — operator can immediately see how big each bucket is.

Behaviour unchanged: same matches, same tier results, same `ScopeSkipped` count in the return object.

---

## v2.2.39 — Endpoint filter: flip default back to MIXED (MDE + EG + Entra)

v2.2.38's strict MDE-only default dropped real Azure VMs visible only in ARG/EG and stripped cross-source enrichment for non-MDE devices. Mixed mode is the right default for the broad asset view; strict is now opt-in.

New default: **mixed-source freshness** (the v2.2.32-v2.2.37 behaviour, restored). Keep if NOT MDE-offboarded AND any of:
- MDE sensor Active/Impaired,
- `MDE_LastSeen` < `SI_ActiveStaleDays`,
- `EG_LastSeen` < `SI_ActiveStaleDays`,
- `ENTRA_ApproximateLastSignInDateTime` < `SI_ActiveStaleDays`.

| Setting | Mode |
|---|---|
| (no globals set -- DEFAULT) | Mixed (MDE + EG + Entra). Preserves Azure-VM / BYOD / IoT visibility and cross-source correlation. |
| `$global:SI_RequireMdeActive_Endpoint = $true` | Strict MDE-only. Matches MDE portal `Sensor health state: Active` filter. Drops EG-only and Entra-only devices. |
| `$global:SI_IncludeInactive_Endpoint = $true` | Disable filter entirely. Emit everything. |

Backwards compat: the v2.2.38 `SI_AllowNonMdeDevices_Endpoint` global is now ignored (mixed either way) -- no error, just no-op. Customers who previously set it to `$true` get the same behaviour they wanted (now as default). Customers who relied on v2.2.38's strict default need to add `SI_RequireMdeActive_Endpoint = $true` to keep the narrower view.

---

## v2.2.38 — Endpoint filter: flip default to STRICT MDE-only

v2.2.32-v2.2.37 default was the mixed-source filter ("alive in any Microsoft surface" — MDE + EG + Entra). Customer feedback: too permissive in real tenants. BYOD phones sign in to Entra daily, so the mixed filter still kept them. Customers expected the count to match MDE portal "Active" view (their ground-truth fleet number) but saw multiples.

New default: **strict MDE-only**. Matches the MDE portal `Sensor health state: Active` filter exactly:
- Keep if NOT MDE-offboarded AND (MDE sensor Active/Impaired OR `MDE_LastSeen` < `SI_ActiveStaleDays`).
- Drops EG-only and Entra-only devices.

| Setting | Mode |
|---|---|
| (no globals set -- DEFAULT) | Strict MDE-only |
| `$global:SI_AllowNonMdeDevices_Endpoint = $true` | Mixed mode (MDE + EG + Entra). Use when you want BYOD/IoT/non-MDE-onboarded device visibility. |
| `$global:SI_IncludeInactive_Endpoint = $true` | Disable filter entirely. Emit everything. |

Backwards compat: the old `SI_RequireMdeActive_Endpoint` global is now ignored (strict either way) -- no error, just no-op. Customers who previously set it to `$true` get the same behaviour they wanted (now as default). Customers who relied on the implicit mixed default need to add `SI_AllowNonMdeDevices_Endpoint = $true` to keep the broader view.

> Superseded by v2.2.39 — strict was too narrow; mixed is the default again.

---

## v2.2.37 — Run-AllEngines: 3 subset switches for partial reruns

`Run-AllEngines.ps1` now has 3 new mutually-exclusive switches alongside the existing `-PrivilegeTierClassifier`. Picks a subset of the 6-launcher fanout instead of always firing all six:

| Switch | Fires | Use case |
|---|---|---|
| `-InitialProfilersOnly` | Endpoint + Identity + Azure | First-run on a fresh customer. Get the three core Profile_CL tables populated BEFORE PublicIP (which needs tier signals from the others) or RA (which queries all four). |
| `-ProfilersOnly` | Endpoint + Identity + Azure + PublicIP | Refresh all 4 Profile tables when RA output is still current. |
| `-RiskAnalysisOnly` | RA Detailed + RA Summary | Rerun just RA when Profile tables are fresh (~5 min vs the full ~hour fanout). |

All 4 subset switches (`-PrivilegeTierClassifier`, `-InitialProfilersOnly`, `-ProfilersOnly`, `-RiskAnalysisOnly`) are mutually exclusive — passing more than one fails fast with an error before anything launches.

Default (no subset switch): all 6 launchers fire as before.

---

## v2.2.36 — Endpoint filter: PS 5.1 TryParse crash in Stage Output

v2.2.32's endpoint asset filter called `[datetime]::TryParse([string]$x, [ref]$ts)` with `$ts` initialized as `$null`. On PowerShell 5.1 the runtime can't bind the 2-arg `out DateTime` overload when the ref target is `[object]` rather than `[datetime]` -- the call fails with `Cannot find an overload for "TryParse" and the argument count: "2"`. Crashed Phase 8 OUTPUT after every other phase (1-7) had completed -- so a 1.8h Phase 6 Profile run was wasted on each retry.

Switched to a try/catch + `[datetime]::Parse(...)` wrapper. Works on PS 5.1 and PS 7+ identically; no typed-ref dance.

Identity filter wasn't affected (it uses integer `ENTRA_LastSignInDays`, no datetime parsing).

---

## v2.2.35 — Profile: narrow `osPlatformScope` tagging to TVM-driven rules only

v2.2.34 tagged ALL 557 `AssetProfileByApplicationServiceDetection/*.locked.yaml` rules with `[WindowsServer, Linux]`. That was over-broad: ~14 rules in that folder are actually workstation / PAW / BYOD / IoT detectors that match by name pattern or MachineGroup tag, not by installed-software TVM signal. Tagging those server-only would silently miss them on the actual workstations they target.

Re-tagging logic for v2.2.35:
- Rule contains `kind: hasSoftwareInstalled` (TVM-driven) -> `osPlatformScope: [WindowsServer, Linux]`. Software-installed signals only make sense for the OS that hosts them, and AppService-folder TVM rules detect server stacks (3CX, AD, Exchange, IIS, SQL, Apache, MySQL, Nginx, etc.).
- Otherwise -> NO scope. Name-pattern + MachineGroup detections are OS-agnostic; let them run on every asset.

Result: 543 rules tagged, 14 left untagged (PAW, BYOD, ProductionWorkstation, ConsumerIoTDevice, USBOnlyPeripheral, VendingMachine, etc.).

Caveat: client-installed software like Adobe Reader / Office / browsers, IF they end up in the AppService folder as TVM rules, will currently be tagged WindowsServer+Linux — wrong for those. Fix per-rule when a customer reports it. Better long-term: split AppService folder into `appservices/` (server stacks) vs `clientapps/` (workstation software).

---

## v2.2.34 — Profile: per-rule `osPlatformScope` + tag 557 AppService rules WindowsServer/Linux

### Engine support (Phase 1)

`Invoke-Profile.ps1` rule-eval loop now honors an optional top-level `osPlatformScope` field on each rule:

```yaml
id:               ADDomainController
appliesTo:        endpoint
osPlatformScope:  [WindowsServer, Linux]   # NEW -- skip rule entirely when asset OS class not in list
detections: ...
```

When set, the evaluator computes the asset's OS class once per asset (via new `Get-SIAssetOsClass` helper in `RuleEval.ps1`) and skips the rule for any asset whose class isn't listed. Rules without the field run on every asset (backwards compatible).

OS class values: `WindowsServer`, `WindowsClient`, `Linux`, `macOS`, `iOS`, `Android`, `IoT`, `Other`. Reads same `MDE_OSPlatform` / `ENTRA_OS` / `EG_OS` fields the existing `osPlatform` rule kind uses.

Profile stage `[DONE]` line now also reports `N rule-evals skipped via osPlatformScope` so operators can see the perf gain.

### Rule content (Phase 2)

All 557 `AssetProfileByApplicationServiceDetection/*.locked.yaml` rules tagged with `osPlatformScope: [WindowsServer, Linux]`. These cover server roles (3CX, AD, Exchange, IIS, SQL, Apache, MySQL, Nginx, etc.) which by definition only run on server OS. Workstations, IoT, mobile, macOS now skip these 557 rules entirely.

### Effect

Rough math on a 5260-device tenant where ~3000 are non-server (workstations + Entra-only + IoT + mobile):
- Before: 5260 assets × 559 rules = ~2.94M rule evals
- After:  3000 non-server assets × 557 = ~1.67M evals SKIPPED via scope; 5260 × 2 (DeviceType + LogonUser) = ~10K + 2260 server assets × 557 = ~1.26M still evaluated
- ~57% fewer rule evals; Phase 6 should drop from ~1 hour to ~25-30 min on this tenant

Customers with custom rules in `AssetProfileByApplicationServiceDetection/*.custom.yaml` should add `osPlatformScope` to their custom files manually if the rule targets a server-only stack. Custom files are not auto-tagged (we never touch customer files).

---

## v2.2.33 — RA: skip "0 findings" emails

`Invoke-RiskAnalysis.ps1` used to send the empty-report email when `Report_SendMail=$true` and the run produced 0 rows. SOC operators learned to ignore SI mail because most days the report was empty -- which meant they also missed the days that DID have findings. Now the engine suppresses the dispatch when `$global:final.Count -eq 0`:

```
WARNING: mail dispatch suppressed: 0 rows produced this run. Set $global:RA_MailEvenIfEmpty=$true to receive empty-report emails as a heartbeat.
```

Opt-out: `$global:RA_MailEvenIfEmpty = $true` keeps the old behavior (useful when the customer wants the "yes, the run completed" heartbeat -- e.g. on Monday-morning ops review).

XLSX + JSON artifacts are still written to `$global:OutputXlsx` (placeholder sheet) and ingested to LA when `SendToLogAnalytics=$true` -- only the email is suppressed.

---

## v2.2.32 — Endpoint + Identity: flip "active assets only" to DEFAULT ON

v2.2.31 made the active-only filter opt-in. Customer feedback was immediate: they want clean active-fleet view by default; let them opt OUT if they specifically need stale-asset cleanup. Now applies to BOTH endpoint and identity engines.

### Endpoint

| Setting | Behavior |
|---|---|
| (no globals set -- DEFAULT) | Mixed-source filter: keep if NOT MDE-offboarded AND any of MDE Active / MDE_LastSeen / EG.lastSeen / ENTRA_ApproximateLastSignInDateTime within `SI_ActiveStaleDays` (default 30). |
| `$global:SI_IncludeInactive_Endpoint = $true` | Disable filter. Emit every asset including stale registrations + offboarded devices. Use when stale-asset cleanup IS the use-case. |
| `$global:SI_RequireMdeActive_Endpoint = $true` | Strict MDE-only. Drops EG-only and Entra-only devices. Matches the MDE portal "Sensor health state: Active" filter exactly. |

### Identity (NEW in v2.2.32)

| Setting | Behavior |
|---|---|
| (no globals set -- DEFAULT) | Filter: keep if `ENTRA_Enabled=$true` AND `0 <= ENTRA_LastSignInDays <= SI_ActiveStaleDays`. Same logic as `Build-IdentityProfileRow.ps1`'s `IsEnabledActive`. |
| `$global:SI_IncludeInactive_Identity = $true` | Disable filter. Emit every identity including disabled accounts and ghost SPs that never signed in. |

`SI_ExcludeInactive_Endpoint` from v2.2.31 is now redundant -- ignored if set, no-op.

Engine prints one INFO line per run so operators can see what happened:
```
asset filter [ExcludeInactive (MDE+EG+Entra), 30d]: 4452 -> 487 (dropped 3965 inactive). Set $global:SI_IncludeInactive_Endpoint=$true to disable.
asset filter [ExcludeInactive (Identity), 30d]: 4057 -> 1284 (dropped 2773 disabled/stale). Set $global:SI_IncludeInactive_Identity=$true to disable.
```

### Performance note

Filter runs at Stage Output (post-Classify), so it shrinks LA ingest + JSON/Excel output + downstream RA query cost. **Stage Collect / Enrich / Classify still process all rows** -- the per-asset Graph/MDE/EG fetches and 5851-row Profile rule evaluation aren't shortcut by this filter. A Stage-Discover-time filter that cuts the upstream work too is a separate future change (bigger surface; this filter ships first because it's safe + immediately useful for LA ingest cost + report cleanliness).

---

## v2.2.31 — Endpoint: opt-in "active devices only" filter (MDE + EG + Entra)

### What

Two new opt-in globals on the **endpoint engine** for customers who want LA + RA reports trimmed to live-fleet only (defaults OFF -- engine still surfaces stale assets unless customer asks):

| Global | Meaning |
|---|---|
| `$global:SI_ExcludeInactive_Endpoint = $true` | Keep a device if NOT MDE-offboarded AND any of: MDE sensor Active, MDE_LastSeen<staleDays, EG.lastSeen<staleDays, ENTRA_ApproximateLastSignInDateTime<staleDays. "Alive in at least one Microsoft surface." |
| `$global:SI_RequireMdeActive_Endpoint = $true` | Strict MDE-only: keep ONLY MDE Active sensor or fresh MDE_LastSeen. Drops EG-only and Entra-only devices. Matches the MDE portal "Sensor health state: Active" filter exactly. |

`$global:SI_ActiveStaleDays` (default 30) controls the freshness window for both modes.

### Why

Customer with 500 actual managed Windows boxes was seeing 4452 endpoint records in LA -- the dedup is correct but the engine surfaces every Entra registration, EG IoT node, and Arc-onboarded Linux server. MDE portal shows ~46 in this customer's tenant (sample); the rest are stale registrations or non-MDE devices. Customer wanted a live-fleet view in LA without giving up the full discovery the engine does.

Filter runs at Stage Output BEFORE all sinks, so LA / JSON / Excel see the same filtered set.

### Engine change

`Get-DiscoveryFromEntra.ps1` now also $select's `approximateLastSignInDateTime` from `/v1.0/devices`. Emitted as `ENTRA_ApproximateLastSignInDateTime`, used by the new filter as the Entra freshness signal. Existing `ENTRA_RegisteredAt` field unchanged.

### Not in scope

Identity / Azure / PublicIp engines are unaffected. Identity already surfaces enabled+staleness via `IsEnabledActive` in the projected row -- a parallel filter there can come later if customers ask.

---

## v2.2.30 — Run-AllEngines: skip git on non-git installs + fix flavour-aware kill

### `git pull` crash on non-git installs

`F:\automateit` (and any install deployed via `AutomateIT_InstallUpdate.ps1`) is a stream-extract, not a git clone. Run-AllEngines unconditionally invoked `git pull` and crashed with `CommandNotFoundException` on hosts where git isn't on PATH, OR `fatal: not a git repository` on hosts where it is. Now:
- Probe `Get-Command git` AND `Test-Path .git` first.
- If either is missing, print one DarkGray hint pointing at `AutomateIT_InstallUpdate.ps1` and continue.
- If both present, behave as before.

### Stale-process kill ignored `-Flavour internal`

The `Get-CimInstance ... -match 'launcher\.community-vm\.ps1'` filter was hardcoded — internal-vm fanout reruns never matched, so every prior window stacked on top of the new one (screenshot showed N copies of each engine). Pattern is now built from `$Flavour`: `launcher\.{Flavour}-vm\.ps1`. Internal customers re-running `Run-AllEngines.ps1 -Flavour internal` get the same clean-slate behaviour community demos already had.

---

## v2.2.29 — FingerprintCache: 400 Bad Request on AssetIds with `'`

`Get-SIFingerprintRecord` / `Set-SIFingerprintRecord` interpolated the PartitionKey raw into an OData literal (`PartitionKey='$pk'`). `ConvertTo-SISafeKey` strips control chars + slash/hash/?, but does NOT escape single quotes — any AssetId containing a `'` (Azure resource named `O'Brien-vm`, tag value with apostrophe, etc.) broke the OData literal and Azure Tables returned `400 Bad Request`. Engine crashed mid-Collect with no indication which row caused it.

**Fix:**
- Both call sites now OData-escape the PK (double `'` -> `''`) AND URL-encode via `[Uri]::EscapeDataString`. `+ & %` and friends now also flow through cleanly.
- Get-side error path now surfaces the AssetId + Azure JSON body (was bare `400 Bad Request`).

Repro: any tenant with an Azure resource whose name contains `'`. Crash always fires at the same row across reruns (deterministic).

---

## v2.2.28 — Run-AllEngines.ps1: `-Flavour` mandatory

`-Flavour` no longer defaults to `community`. Internal customers who forgot the switch were silently firing `launcher.community-vm.ps1`, which skips `Initialize-PlatformAutomationFramework` and the KV-backed secret fetch — auth then fell back to the missing `$Spn*` plaintext block in custom.ps1 and crashed mid-run with confusing errors. Forcing an explicit choice surfaces the decision at parameter-binding time.

PowerShell will prompt interactively if `-Flavour` is omitted; pipelines / VisualCron / scheduled jobs that don't pass it will fail fast with a parameter-binding error instead of running the wrong flavour.

---

## v2.2.27 — RA SettingsPath overshoot + Run-AllEngines polish

### RA launcher: `RiskAnalysis_Queries_Locked.yaml not found`

`launcher.community-vm.ps1` and `launcher.internal-vm.ps1` for risk-analysis had a stray second `Split-Path -Parent $siRoot` line — a leftover from the v2.2.25 `$v22Root` -> `$siRoot` rename where two distinct variables collapsed onto the same name. Result: `$siRoot` overshot by one folder (`C:\Demo` instead of `C:\Demo\SecurityInsight`), the `risk-analysis-detection/` candidate path missed, `$global:SettingsPath` fell back to `$PSScriptRoot`, and the engine threw `Locked YAML not found`. Removed the extra walk.

### Run-AllEngines.ps1

- **Auto-redirect when `-Root` points at AutomateIT install root**: if `<Root>/engine` doesn't exist but `<Root>/SOLUTIONS/SecurityInsight/engine` does, silently rewrite `$Root` to the SI dir. Internal callers can now run `.\Run-AllEngines.ps1 -Root D:\AutomateIT -Flavour internal` without remembering the `SOLUTIONS\SecurityInsight` suffix.
- **Default for `-Root`**: derives from `$PSScriptRoot` instead of the hardcoded `C:\Demo\SecurityInsight` demo path. Running `.\Run-AllEngines.ps1` from inside any install's `tools/` folder works without `-Root`. Explicit `-Root` still wins.
- **Banner**: dropped `(demo helper)` — the script ships and runs in production internal installs too, the label was misleading.

---

## v2.2.25 — Privilege-tier catalog: locked + custom merge model + `$v22Root` rename

### Privilege-tier catalog: locked + custom merge model

PTC engine used to overwrite the shipped `.locked.json` on every run, which meant:
1. Customer ran PTC once -> their tenant-specific catalog clobbered the baseline.
2. Next `git pull` brought a NEW shipped `.locked.json` -> customer's tenant tweaks were wiped.
3. Customer who DIDN'T re-run PTC after baseline updates fell behind on new Microsoft roles.

New layered model:

| File | Owner | Updated via | Engine reads |
|---|---|---|---|
| `privilege-tier-catalog.locked.json` | us (shipped) | `git pull` / AutomateIT_InstallUpdate | baseline |
| `privilege-tier-catalog.custom.json` | customer (gitignored) | PTC engine OR hand-edit | overlay (wins on overlap) |

Engine load order = both supported, baseline updates always flow:
1. Load `.locked.json` -> full baseline.
2. Load `.custom.json` -> customer overlay.
3. Merge by key. Custom wins on conflicts; locked-only keys still apply.

### Code changes

- `IdentityCatalogTierComputer.ps1` -- `$CustomPath` default switched from the
  legacy `asset-profiling-enrichment\identity\PrivilegeTierClassifier.json`
  (which never received PTC output) to the canonical sibling
  `privilege-tier-catalog\privilege-tier-catalog.custom.json`. Existing
  custom-overlay merge logic now actually receives PTC's output.
- `Invoke-PrivilegeTierClassifier.ps1` -- output switched from
  `privilege-tier-catalog.locked.json` to `privilege-tier-catalog.custom.json`.
  Shipped baseline never overwritten.

### Effect

- **Most customers (no customisation)**: nothing changes -- engine reads only
  `.locked.json`, gets baseline updates via `git pull`.
- **Customised customers (re-ran PTC)**: their PTC output becomes the overlay
  in `.custom.json`. Baseline updates still flow through for keys not
  shadowed in custom.
- **Future quarterly refresh**: customer re-runs PTC every 3-6 months to
  refresh their tenant snapshot; baseline updates apply between refreshes.

### Variable rename: `$v22Root` -> `$siRoot` (33 files, 117 occurrences)

`$v22Root` and `$_v22Root` had the version number baked into the variable name -- violates the project's "no version numbers in identifiers" rule. Renamed to `$siRoot` / `$_siRoot` (semantic, version-independent). 33 source files touched, 117 occurrences replaced. No behavior change; all 33 parse OK.

---

## v2.2.24 — Run-AllEngines.ps1: -Flavour internal|community switch

`tools/Run-AllEngines.ps1` was hardcoded to fire `launcher.community-vm.ps1` files. Internal customers (FVF-style, AutomationFramework + cert+KV auth) had no parallel-windows orchestrator.

Added `-Flavour internal|community` switch (default `community`, so existing demo callers don't break). Launcher path now resolves to `launcher.$Flavour-vm.ps1`.

```powershell
# Default (community demo VMs)
.\tools\Run-AllEngines.ps1

# Internal env (FVF, 2linkit, etc. -- requires Initialize-PlatformAutomationFramework upstream)
.\tools\Run-AllEngines.ps1 -Flavour internal

# Internal + standalone PTC
.\tools\Run-AllEngines.ps1 -Flavour internal -PrivilegeTierClassifier
```

---

## v2.2.23 — PublicIP: drop redundant DCE URI lookup (was failing on split DCE/DCR RGs)

`Invoke-PublicIpScanner.ps1` had a manual `Get-AzDataCollectionEndpoint -ResourceGroupName $SI_DcrResourceGroup -Name $SI_DceName` block that computed `$dceUri` and threw when the DCE wasn't in the same RG as DCRs. But `$dceUri` was **never actually used** -- the downstream `CheckCreateUpdate-TableDcr-Structure` and `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` calls (both from AzLogDcrIngestPS) resolve DCE/DCR by name themselves via `Get-AzDcrListAll`, which scans the SPN's visible scope across all subs/RGs.

Removed the dead lookup. Engine now succeeds whether DCE lives in the same RG as DCRs or a different one (e.g. `rg-dce-securityinsight-community` next to `rg-securityinsight-community`).

Mirrors how the asset-profiling Output stage handles this -- consistent ingest behavior across all 4 collection engines.

---

## v2.2.22 — SP sign-in: actually query the Defender workspace + visible target log

`Invoke-SIHuntingQuery` always queried `$global:SI_WorkspaceResourceId` on the LA route -- ignored `$global:SI_DefenderWorkspaceResourceId` even when callers had set it. The SP sign-in fetcher (`IdentityRoleFetcher.ps1` `Get-SISpnSignInActivity`) announced "fetching from Log Analytics (separate Defender workspace)" but the implementation actually targeted the SI workspace, where `AADServicePrincipalSignInLogs` / `AADManagedIdentitySignInLogs` don't live. Result: 0 rows on every run for tenants with hundreds of active SPs.

Two fixes:

1. **`Invoke-SIHuntingQuery` adds `-WorkspaceResourceId` parameter**. When set, the LA route queries that workspace instead of the global default. Verbose log line surfaces the chosen target on every call.

2. **`Get-SISpnSignInActivity` passes `-WorkspaceResourceId $global:SI_DefenderWorkspaceResourceId`** for the LA-route attempt (with fallback to `SI_WorkspaceResourceId` when the Defender variable isn't set). Also surfaces the chosen workspace in the trace's "trying ..." line so operators can see exactly where the query went without `-Verbose`.

Trace before:
```
[INFO] [perms] SP sign-in source: trying AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA)...
[INFO] [perms] SP sign-in source: OK -- 0 rows from AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA)
```

Trace after:
```
[INFO] [perms] SP sign-in source: trying AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA) (workspace=/subscriptions/.../log-platform-management-srvnetworkcloud-p)...
[INFO] [perms] SP sign-in source: OK -- 1247 rows from AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA)
```

---

## v2.2.21 — Quiet down Graph 429-retry warnings

PIM scans across 80+ role-bearing groups can fire 50+ HTTP 429 throttle responses, each currently emitting a `WARNING: Graph transient error (HTTP 429) on https://graph.microsoft.com/...` line. All auto-recovered by the existing 3-attempt exponential backoff -- pure noise that drowned the launcher trace.

`engine/asset-profiling/shared/IdentityRoleFetcher.ps1` now demotes the per-retry message to `Write-Verbose` and bumps a counter (`$script:_SIGraphRetryCount`) for an end-of-phase summary. Pass `-Verbose` to the launcher when you actually need per-call detail (e.g. diagnosing a stuck request).

Engine behavior unchanged -- only the log surface is quieter.

---

## v2.2.20 — Capture Context return value from auto-init

v2.2.19's auto-init called `Initialize-PlatformAutomationFramework -ErrorAction Stop | Out-Null` -- which discarded the returned Context. The function RETURNS `$ctx` (line 389) and the caller is responsible for assigning it to `$global:Context`. So Layer 3 customer files still saw `$global:Context` as null and `Get-PlatformSecret` calls still failed.

Fixed: `$global:Context = Initialize-PlatformAutomationFramework -ErrorAction Stop` (capture, not discard).

The function ALSO sets `$global:HighPriv_*` and a handful of other v1-contract globals as side effects internally; those worked already in v2.2.19. Only the typed Context object was missing.

---

## v2.2.19 — Auto-init AutomationFramework + install-relative platform-config.json

### Auto-init `Initialize-PlatformAutomationFramework` in internal mode

`Initialize-LauncherConfig` (the layered-config loader inside every launcher) now auto-calls `Initialize-PlatformAutomationFramework` when `$Mode -eq 'internal'` and `$global:Context` is still null. This populates `$global:Context` + `$global:HighPriv_*` BEFORE Layer 3 (customer custom.ps1) dot-sources, so `Get-PlatformSecret -Context $global:Context -Name 'SI-StorageKey'` calls in custom.ps1 succeed on first run. Previously the launcher's `.NOTES` warned that the caller had to run init manually upstream; SYSTEM-context jobs (VisualCron, Task Scheduler as SYSTEM) skipped that step and got cryptic "Cannot bind argument to parameter 'Context' because it is null" bubbled up from the customer file.

Idempotent — if `$global:Context` already exists (caller did init manually), the auto-init is skipped. Failure to auto-init logs an INFO line + suggests next steps; doesn't throw.

### Install-relative `platform-config.json` lookup

`Initialize-PlatformAutomationFramework` previously only checked `$env:USERPROFILE\.automateit\platform-config.json` — useless for SYSTEM-context jobs. Now also checks `<install>\SOLUTIONS\PlatformConfiguration\config\platform-config.json` (derived from the script's own location). Same folder as `platform-defaults.ps1`, same gitignore semantics, same update-in-place lifecycle.

Lookup order: `-ConfigPath` param → `<install>/SOLUTIONS/PlatformConfiguration/config/platform-config.json` → `$env:USERPROFILE/.automateit/platform-config.json` → PLATFORM_* env vars.

### Combined effect

For internal customer onboarding:
1. Drop `platform-config.json` at `<install>\SOLUTIONS\PlatformConfiguration\config\platform-config.json` (TenantId, SubscriptionId, KeyVaultName, BootstrapAppId, BootstrapThumbprint).
2. Drop `platform-defaults.ps1` in same folder.
3. Drop `SecurityInsight.custom.ps1` with `Get-PlatformSecret` calls for runtime KV fetch.
4. Fire `launcher.internal-vm.ps1` — the launcher auto-inits the platform context, secrets land from KV, engine runs.

No upstream wrapper script needed; works under SYSTEM context out of the box.

---

## v2.2.18 — Banner shows SI version on internal monorepo installs

`Get-PublishedVersion.ps1` was checking `<install>/VERSION.txt` first, which on internal monorepo / `AutomateIT_InstallUpdate` installs holds the AutomateIT install marker (`AutomateIT-internal-main-<sha> ...`) rather than the SI release tag. Operators saw the install SHA but couldn't tell which SI version a customer was running.

New resolution order:
1. `<install>/SOLUTIONS/<Solution>/VERSION` — per-solution version file (e.g. `SecurityInsight-v2.2.18`). Canonical for monorepo + internal installs.
2. `<install>/VERSION.txt` — community installs (publish workflow stamps the SI tag here).
3. `git describe --tags --match <Solution>-v*` — dev clones with no VERSION files.
4. `(dev)`.

Banner now reads `SecurityInsight-v2.2.18` on every internal customer VM, regardless of how they pulled the code.

---

## v2.2.17 — Make SI_RunHealth DCR overridable (cross-tenant SPN name-collision fix, part 2)

`Send-SIRunHealthRow.ps1` had `$dcrName = 'dcr-si-run-health'` HARDCODED. Same name-based-lookup bug as v2.2.16 fixed for RA: with one cross-tenant SPN, the run-health heartbeat would silently route to the wrong DCR (whichever sub's `dcr-si-run-health` enumerates first).

Now overridable:
```powershell
$global:SI_RunHealth_DcrName = 'dcr-si-run-health-community'
```
Falls back to `dcr-si-run-health` when unset. Table name stays `SI_RunHealth` (workspace-scoped, no collision possible).

### Override coverage map -- where each DCR comes from

| Source | Default DCR | Override global | Status |
|---|---|---|---|
| Asset-profiling (Endpoint/Identity/Azure) | `dcr-si-{0}-profile` | `$SI_DcrNamePattern` | shipped |
| PublicIP / Shodan | `dcr-si-publicip-profile` | `$SI_Shodan_DcrName` | shipped |
| RA Detailed | `dcr-si-risk-analysis-detailed` | `$SI_RiskAnalysis_DcrName_Detailed` | v2.2.16 |
| RA Summary | `dcr-si-risk-analysis-summary` | `$SI_RiskAnalysis_DcrName_Summary` | v2.2.16 |
| **SI_RunHealth heartbeat** | `dcr-si-run-health` | `$SI_RunHealth_DcrName` | **v2.2.17 (NEW)** |
| Schema-catalog audit | `dcr-si-schema-catalog` | `$SI_SchemaCatalogDcr` | shipped |
| Asset-tag-activity audit | `dcr-si-assettag-activity` | `$SI_AssetTagActivityDcr` | shipped |

All DCRs ingest into the SAME workspace via the same DCE (`$SI_DceName`), all in the same RG (`$SI_DcrResourceGroup`).

---

## v2.2.16 — Make RA DCR names overridable (cross-tenant SPN name-collision fix)

`Invoke-RiskAnalysis.ps1` had `$RiskAnalysis_DcrName_Summary` and `$RiskAnalysis_DcrName_Detailed` HARDCODED to `dcr-si-risk-analysis-summary` / `dcr-si-risk-analysis-detailed`. Customers running the same SPN against BOTH internal AND community subscriptions hit a silent ingest-routing bug: AzLogDcrIngestPS does name-based DCR lookup across **all visible subscriptions** and picks the first match, often routing community-engine ingest to the internal DCR (or vice versa). Triggers the `404 NotFound: Data collection rule with immutable Id 'westeurope' not found` symptom we already partially papered over with retries in v2.2.14.

Now overridable via globals:
```powershell
$global:SI_RiskAnalysis_DcrName_Summary  = 'dcr-si-risk-analysis-summary-community'
$global:SI_RiskAnalysis_DcrName_Detailed = 'dcr-si-risk-analysis-detailed-community'
```

Falls back to the original hardcoded names when not set, so existing internal deployments are unaffected.

The asset-profiling engines already had `SI_DcrNamePattern` for the same purpose (`dcr-si-{0}-profile` template); this brings RA to parity.

---

## v2.2.15 — Privilege-tier catalog renamed: `.custom.json` -> `.locked.json`

The shipped catalog was named `privilege-tier-catalog.custom.json` for historical reasons (it was originally generated per-customer by PrivilegeTierClassifier). v2.2.13 made it a tracked baseline shipped in the repo, but the `.custom.*` filename clashed with the codebase's convention:

- `*.locked.*` = shipped baseline, never customer-edited (e.g. `RiskAnalysis_Queries_Locked.yaml`, `endpoint.schema.locked.json`)
- `*.custom.*` = customer-owned override, gitignored, optional (e.g. `RiskAnalysis_Queries_Custom.yaml`, `LauncherConfig.custom.ps1`)

Renamed to `privilege-tier-catalog.locked.json` for full consistency. A sibling `*.custom.json` is now reserved (and gitignored) for tenant-specific overrides — for now PrivilegeTierClassifier still writes the locked file (it regenerates the baseline) but the override slot is in place for future merge support.

### Files updated (28 references across 14 files)

- File rename: `git mv privilege-tier-catalog/privilege-tier-catalog.custom.json -> .locked.json`
- Engine read paths: `IdentityCatalogTierComputer.ps1`, `Build-IdentityProfileRow.ps1`
- PrivilegeTierClassifier output: `Invoke-PrivilegeTierClassifier.ps1` (now writes `.locked.json`)
- Launcher manifests + .NOTES blocks (community + internal flavours)
- `Setup-SecurityInsight.ps1` PrivilegeTier phase
- Schema reference: `asset-profiling-schema/SCHEMA.locked.json`
- Docs: `README.md`, `docs/CATALOG-REFERENCE.md`, `docs/ARCHITECTURE.md`, `docs/Operations.md`, `internal/onboard-internal-AutomateIT.md`
- Sample file comment: `privilege-tier-catalog.custom.sample.json` (file kept under `.custom.sample.json` — it documents what an OVERRIDE would look like)
- AutomateIT root `.gitignore`: restored `*.custom.json` ignore for this folder so customer overrides are properly hidden
- Pre-Publish Gate `RepoHygiene` test: dropped the v2.2.14 per-file exception (no longer needed)

### Manual step on existing demo VMs

If you have a demo VM that pulled v2.2.13 / v2.2.14 (which had the old `.custom.json` name), after `git pull` you'll see:
- New file landed: `privilege-tier-catalog/privilege-tier-catalog.locked.json`
- Old file removed by git: `privilege-tier-catalog/privilege-tier-catalog.custom.json`

If you locally regenerated the catalog (ran `-PrivilegeTierClassifier` after the v2.2.13 pull), git will leave your `.custom.json` alone (it became untracked when v2.2.15 deleted it). Rename it to `.locked.json` to keep your tenant-specific catalog, OR delete it and use the shipped one.

---

## v2.2.14 — Asset-profiling Output: retry on transient DCR-cache 404 + Pre-Publish Gate exception

### Asset-profiling Output stage now retries on transient DCR-cache failures

A freshly auto-created DCR can land in `$global:AzDcrDetails` with an empty / unresolved `ImmutableId`. AzLogDcrIngestPS's URL builder then falls back to a non-GUID string (commonly the DCE's `Location`, e.g. `'westeurope'`) and the Log Ingestion API rejects the call with:

> 404 NotFound: Data collection rule with immutable Id 'westeurope' not found.

`engine/asset-profiling/stages/Invoke-Output.ps1` now wraps the `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` call in a 3-attempt retry loop. On any 404 / `NotFound` / `immutable Id` error pattern it sleeps (30s, then 60s), re-calls `Get-AzDcrListAll` to refresh the cache, and retries. Non-transient errors throw immediately (preserves existing diagnostics).

In practice the DCR's immutableId populates in ARG within 30-90s, so the second attempt usually succeeds. Eliminates the "first run on a fresh community workspace fails ingest, run completes successfully when re-fired" pattern.

### Pre-Publish Gate: allow tracked privilege-tier-catalog.custom.json

The `RepoHygiene / No customer .custom.json files tracked` test in `tests/pester/SI-PrePublish.Tests.ps1` failed v2.2.13 publish because the catalog JSON was now intentionally tracked. Added an explicit exception path so the gate ignores `privilege-tier-catalog/privilege-tier-catalog.custom.json` (the only `.custom.json` we allow in the repo).

---

## v2.2.13 — Ship privilege-tier-catalog.custom.json + 10-step setup docs refresh

### Privilege-tier catalog now ships in the repo

Previously gitignored as a "customer-generated artifact", but the JSON contents are actually generic — Microsoft built-in roles → tier mappings (`AD_BuiltInPermissionGroups_Tier0`, etc.). The only tenant-specific bit was a `Metadata.TenantId` field used purely for audit; not a secret.

The 6.5 MB JSON is now tracked in the repo. Customers get tier-definition updates via `git pull` and the **Identity engine works on first run** with no extra steps. Customers who want to customise tier assignments can still re-run `tools\Run-AllEngines.ps1 -PrivilegeTierClassifier` to regenerate the file locally — it'll show as modified in `git status` (expected; pull conflicts are the customer's call).

The `.gitignore` line that previously hid the catalog has been removed.

### README §3.5 ten-step setup — updated with hard-won lessons

Step 8 now mentions `tools\Run-AllEngines.ps1` as the one-shot orchestrator option (vs. running each launcher individually) and explains that the `-PrivilegeTierClassifier` switch is advanced/optional now that the catalog ships.

The "When something doesn't work" troubleshooting table gained 5 new rows for errors we hit during demo-VM debugging:
- Identity: "SI identity catalog not found" → `git pull` (catalog now ships) or `-PrivilegeTierClassifier` to regenerate
- PublicIP: `BadRequest` from LA → asset-profiling tables don't exist yet (v2.2.12+ uses `union isfuzzy=true`)
- PublicIP: `ResourceGroupNotFound` for the workspace's RG → SPN context (auto-handled in v2.2.10+)
- Shodan: `Missing $global:SI_Shodan_ApiKey` → use canonical SI-prefixed name (v2.2.7+ also accepts legacy `SHODAN_ApiKey`)
- `config\SecurityInsight.custom.ps1` keeps disappearing → upgrade to v2.2.8+ which protects it via shipped `.gitignore`

### Upgrade

```powershell
cd <your SI install>
git pull origin main
# verify the catalog landed
Test-Path .\privilege-tier-catalog\privilege-tier-catalog.custom.json   # True
```

---

## v2.2.12 — PublicIP: tolerate missing Profile tables (union isfuzzy=true)

The PublicIP discovery KQL queried `SI_Endpoint_Profile_CL` AND `SI_Azure_Profile_CL` via two `let` statements + `union`. KQL parses table refs at submit time, so if EITHER table didn't exist (common on fresh workspaces where one engine has ingested but the other hasn't), the whole query failed with `BadRequest`.

Switched to `union isfuzzy=true ( ... ), ( ... )` — non-existent tables are silently skipped, and discovery proceeds against whichever tables ARE present. Now you can run PublicIP after just Endpoint has ingested, even before Azure has its first run.

---

## v2.2.11 — PublicIP: surface KQL error body + missing-table hint

The PublicIP scanner's KQL error path was logging only the HTTP status (`Operation returned an invalid status code 'BadRequest'`) — useless for diagnosing whether the cause was a missing table, a syntax error, or a permissions gap.

`engine/publicip/Invoke-PublicIpScanner.ps1` now also logs `$_.ErrorDetails.Message` (the JSON body from `Invoke-AzOperationalInsightsQuery`, which carries the actual KQL error message), and prints a hint that BadRequest usually means `SI_Endpoint_Profile_CL` / `SI_Azure_Profile_CL` don't exist yet in the workspace — run the endpoint + azure engines first.

---

## v2.2.10 — PublicIP Set-AzContext + shared Use-SIAzContext helper

### PublicIP: Set-AzContext to workspace subscription before LA query

PublicIP scanner threw `ResourceGroupNotFound` when the SPN's default Az context was on a different subscription than the one that owns `SI_WorkspaceResourceId`. Common in lab/community tenants where one SPN has access to multiple subscriptions but lands on the "wrong" one by default.

`engine/publicip/Invoke-PublicIpScanner.ps1` now extracts the subscription ID from the workspace ARM resource id and calls `Set-AzContext -SubscriptionId <wsSub>` before `Get-AzOperationalInsightsWorkspace`. Defensive: only switches when the current context's subscription differs from the workspace's.

### New shared helper: `auth/Use-SIAzContext.ps1`

Engines querying SI_WorkspaceResourceId AND SI_DefenderWorkspaceResourceId need to switch Az context per query (the two workspaces can live in different subscriptions). The new helper `Use-SIAzContext -WorkspaceResourceId <id>` parses the sub from an ARM ResourceId and calls `Set-AzContext` only when a switch is needed.

Audit confirmed the other engines were already doing this inline (HuntingQuery.ps1, RA's Resolve-WorkspaceCustomerId, Invoke-Enrich.ps1, IdentityRoleFetcher.ps1, RA's Ensure-SecurityInsightInfra). PublicIP was the only callsite missing the context-switch. New helper is for future engines / refactors.

### Upgrade

```powershell
cd <your SI install>
git pull origin main
```

---

## v2.2.9 — Fix RA Summary template name in Run-AllEngines

`tools/Run-AllEngines.ps1` was passing `-ReportTemplate "RiskAnalysis"` for the Summary window, but the YAML defines two templates with explicit names: `RiskAnalysis_Detailed` and `RiskAnalysis_Summary`. The Summary launcher threw:

> ReportTemplate 'RiskAnalysis' not found in YAML under ReportTemplates.

Now passes `RiskAnalysis_Summary`. Detailed window was already correct.

### Upgrade

```powershell
cd <your SI install>
git pull origin main
```

---

## v2.2.8 — Add .gitignore to public repo (protect customer secrets)

The public repo never had a `.gitignore`, leaving customer-owned files like `config/SecurityInsight.custom.ps1` (which holds Shodan key, SPN secret, OpenAI key) in an unprotected state:

- `git pull` left them alone (only modifies tracked files), but
- `git clean -fd` would silently delete them (untracked + not-ignored), and
- `git add .` followed by `git commit -am` would publish secrets to the public repo (you'd have to actively notice and skip them)

This release ships a `.gitignore` at the SI repo root that explicitly protects:
- `config/SecurityInsight.custom.ps1`
- `launcher/*/LauncherConfig.custom.ps1`
- `logs/`, `OUTPUT/`, `DATA/`, `staging/` (run output)
- `privilege-tier-catalog/privilege-tier-catalog.custom.json` (rebuilt by PTC)
- IDE / OS noise (`.vs/`, `.DS_Store`, etc.)

After upgrading: customer config files survive `git clean -fd`, and accidental `git add .` won't stage them.

### Upgrade

```powershell
cd <your SI install>
git pull origin main
```

---

## v2.2.7 — Shodan key: unify on canonical name, accept legacy alias

The PublicIP engine refused to start when the Shodan key was set under the legacy v1 name `$global:SHODAN_ApiKey`, even though one of the per-engine sample configs documented exactly that variable. The engine throw-gate at `Invoke-PublicIpScanner.ps1:84` only checked the SI-prefixed `$global:SI_Shodan_ApiKey` form.

Three places aligned on the canonical name (`$global:SI_Shodan_ApiKey`):
- **Engine**: now accepts either name. If `SI_Shodan_ApiKey` is empty but `SHODAN_ApiKey` is set, the engine bridges them at startup and continues. The throw message now mentions both names.
- **`auth/Get-SIShodanKey.ps1` helper**: lookup order is now `SI_Shodan_ApiKey` -> `SHODAN_ApiKey` -> `$env:SHODAN_API_KEY`.
- **Per-engine samples** (`launcher/publicip/LauncherConfig.custom.sample.ps1` and `LauncherConfig.defaults.ps1`): now show the canonical SI-prefixed name in their commented-out template, with a note that the legacy form still works.

No engine logic, no schema changes. Pure config-name compatibility patch. Set `$global:SI_Shodan_ApiKey` in `config/SecurityInsight.custom.ps1` (recommended -- one place, all engines see it).

### Upgrade

```powershell
cd <your SI install>
git pull origin main
```

---

## v2.2.6 — Run-AllEngines: PTC opt-in, no longer kills siblings in PTC mode

PrivilegeTierClassifier (PTC) was added to the default plan in v2.2.5 with a `WaitForFile` gate. In practice that gate slowed every demo by 30-90s because PTC rebuilds the entire tier-definitions JSON via Azure OpenAI on every run, even when the catalog hasn't changed. Demos waited on a slow first window before the visually impressive 6-window fan-out started.

This version moves PTC OUT of the default plan and into a new `-PrivilegeTierClassifier` switch:

```powershell
# Default: 6 windows (Endpoint, Azure, Identity, PublicIP, RA Detailed, RA Summary)
.\tools\Run-AllEngines.ps1

# Standalone: just PTC, in its own window. Use this once on fresh installs
# (Identity needs the catalog) or whenever you want to refresh the tier defs.
.\tools\Run-AllEngines.ps1 -PrivilegeTierClassifier
```

`-PrivilegeTierClassifier` mode also **skips the stale-process kill block** so it can run alongside an in-flight fan-out without terminating sibling collector windows. Default mode kills stale launchers as before.

Fresh-install ordering: run `-PrivilegeTierClassifier` once, wait for the catalog JSON to land at `<root>\privilege-tier-catalog\privilege-tier-catalog.custom.json`, then run the default plan.

### Upgrade

```powershell
cd <your SI install>
git pull origin main
```

---

## v2.2.5 — Run-AllEngines now public + race fix + better Identity error message

Three small fixes, all surfaced by demo VM runs against the public stable repo. Recommended upgrade for anyone using the demo orchestrator or running the Identity engine for the first time.

### Run-AllEngines.ps1 moved to `tools/` (public)

Previously lived in `demo/` (internal-only, excluded from publish), so demo VMs needed manual file drops to receive fixes. Now ships under `tools/Run-AllEngines.ps1` — public users get it via `git pull`, no workarounds.

The `-Install` path-math was updated to walk one level up (`tools/` → `<SI root>` → `demo/community/`) instead of treating `<SI root>` as the script's parent. Public installs (no `demo/` folder) get a friendly hint pointing to `Setup-SecurityInsight.ps1 -Wizard` instead of crashing on a missing snapshot.

### PrivilegeTierClassifier no longer races the other 6 collectors

First-ever runs were failing on Identity discovery with:

> SI identity catalog not found at `<root>\privilege-tier-catalog\privilege-tier-catalog.custom.json`

Root cause: parallel-window mode fired all 7 launchers within seconds, but Identity needs the JSON catalog that PrivilegeTierClassifier produces — the file simply didn't exist yet on first run.

Fix: PrivilegeTierClassifier is now position 1 in the launch plan with a `WaitForFile` gate (timeout 600s). The orchestrator polls for `privilege-tier-catalog.custom.json` to appear before fanning out the other 6 collectors. Subsequent runs (where the file already exists) gate-through immediately.

Also removed a stale `} else { ... }` block left over from a prior refactor in `tools/Run-AllEngines.ps1` — would have parse-errored on `-Install` mode runs (silent on default mode because that branch was unreachable).

PrivilegeTierClassifier was also passed the wrong arg in v2.2.4: `-ForceFullRun` — which the launcher rejects (it always rebuilds the full tier-definitions JSON by design; no cadence skip exists to bypass). Now passes empty args.

### Identity engine error message points to the right script

`engine/asset-profiling/shared/IdentityCatalogTierComputer.ps1:128` was throwing:

> Run SCRIPTS\Build_Tier_Definitions_JSON_File.ps1 to generate.

That script was deleted during the v2 → v2.2 migration. Updated to:

> Run launcher\privilege-tier-classifier\launcher.community-vm.ps1 (community) or launcher.internal-vm.ps1 (internal) once to generate it; the identity engine cannot classify users without this catalog.

### Upgrade

```powershell
cd <your SI install>
git pull origin main
# OR pin to v2.2.5:
git fetch --tags
git checkout v2.2.5
```

---

## v2.2.4 — Demo orchestrator: silence git-stderr noise

Tiny patch — only touches `demo/Run-AllEngines.ps1` (internal-only). When the script runs `git pull` (default mode) or `git clone` (-Install mode), git writes its progress messages to stderr. PowerShell's "native command stderr = error" behavior renders these as red `RemoteException / NativeCommandError` blocks even though the command succeeded.

Fix: pipe through `ForEach-Object { Write-Host $_ }` instead of `| Out-Host`. PowerShell now sees each line as data and prints it normally — no more scary red blocks for what is just `From https://...` informational text.

No engine, schema, README, or workflow changes.

---

## v2.2.3 — Pre-Publish Gate fixes + demo orchestrator

Two unrelated fixes bundled together. **No engine changes** — same Profile schemas, same RA reports, same launchers as v2.2.2.

### Pre-Publish Gate (`tests/pester/SI-PrePublish.Tests.ps1`) fixes

The gate had been failing on every push since the v2.2 flatten — three test failures, all caused by the path-resolution math being one level too deep:

- **`$_repo` calculation**: `tests/pester/<file>.ps1` walks up 3 levels to `SecurityInsight` (not `v2.2/` anymore), so `$_repo` only needs **2** more ups (`SecurityInsight → SOLUTIONS → AutomateIT`), not 3. Previously was resolving to `C:\SCRIPTS\` instead of `C:\SCRIPTS\AutomateIT\`, which broke `WorkflowSyntax` tests that look for `.github/workflows/*.yml` under `$RepoRoot`.
- **`DocConsistency` README report-count check**: now uses a regex-derived count (`^- ReportName:` line count) instead of `ConvertFrom-Yaml | .Reports.Count`. The latter undercounts on the Linux GitHub Actions runner due to a `powershell-yaml` parser quirk (returned 134 vs the actual 136 entries). The regex pattern matches the same authoritative source the README itself documents.

After this patch the gate goes from `1375/1385 PASS` (3 failures + 6 skip) to **green**.

### Demo orchestrator (`demo/Run-AllEngines.ps1`)

Internal-only helper for demo VMs. **Not published to the public stable repo** (lives in `demo/` which is excluded from publish). Distribute manually to demo VMs that need it.

Two modes:

- **Default**: assumes `-Root` is an existing SI install. `git pull` to refresh, kill any stale launcher processes, fire 7 PowerShell windows in parallel — one per engine + 2 RA passes (Detailed + Summary).
- **`-Install`**: fresh-VM setup. Clones the public repo to `-Root` if missing, drops customer config from `demo/community/` snapshot, then fires the 7 windows.

Uses `cmd /c start "title" powershell.exe -NoExit -File <launcher>` for window spawning — much more reliable than `Start-Process powershell` for parallel multi-window scenarios on Windows (avoids AV / Defender SmartScreen rate-limiting that silently dropped windows when 7+ powershell.exe processes spawn within ~1 second).

Switches:
- `-Sequential` — wait for each window to close before opening the next (CI-friendly)
- `-NoForceFullRun` — respect tier cadence (faster on warm runs)
- `-Tag v2.2.x` — pin a specific tag during `-Install`
- `-StaggerSeconds N` — delay between window launches (default 2s; bump to 3-4 if AV still drops some)

### Upgrade

```powershell
cd <your SI install>
git fetch origin
git pull origin main
# OR pin to v2.2.3:
git fetch --tags
git checkout v2.2.3
```

---

## v2.2.2 — README cosmetic fixes

Doc-only patch. No engine changes, no schema changes, no script changes.

- **"Whole product in one picture" Mermaid diagram** redrawn with `flowchart TB` (top-bottom) outer layout + `direction LR` inside the SOURCES + OUTPUTS subgraphs. Fits on a normal-width screen and the node text is actually readable. Old `flowchart LR` with 5 horizontal subgraphs was getting squeezed to ~1/4 of the screen width on standard rendering, making node text unreadable.
- **Report count corrected** in the diagram: `134 attacker-centric KQL reports` → `136`. Also added PublicIP to the report-domain list.
- **TOC**: removed orphaned `0. [Capabilities]` entry that was pointing at the old section moved into § 10 What's New & Capabilities during the v2.2.0 restructure.

### Upgrade

Just `git pull` — no schema/config touch needed.

```powershell
cd <your SI install>
git fetch origin
git pull origin main
# OR pin to v2.2.2:
git fetch --tags
git checkout v2.2.2
```

---

## v2.2.1 — Patch release (publish-pipeline + Reconcile fixes)

Cumulative patch covering issues surfaced during the v2.2.0 stable cut. No engine semantics changed; same architecture, same Profile schemas, same RA report set as v2.2.0.

### Engine fix

- **`Invoke-Reconcile.ps1`** now skips its `Write-SIStageShard` re-write call when the records array is empty (Phase 7 RECONCILE crashed with `Cannot bind argument to parameter 'Records' because it is an empty array` whenever Phase 3 COLLECT cadence-skipped every asset — a legitimate state when nothing's due this cycle).

### Publish-pipeline fixes (operator-facing, no customer-visible change unless re-pulling)

- **`*.internal-vm.*` files stripped from public stable + preview builds.** The 6 maintainer-only `launcher.internal-vm.ps1` files (azure / endpoint / identity / privilege-tier-classifier / publicip / risk-analysis) assume the AutomateIT monorepo path conventions. Public customers use `launcher.community-vm.ps1`.
- **`demo/` folder excluded** from public publish. `demo/community/*` carries 2linkit-internal customer values; `demo/Install-DemoConfig.ps1` is a maintainer's demo-VM refresh helper. Stays in the upstream monorepo, never published.
- **README chain skipped on flat layout** when `SecurityInsight/README.md` was already copied verbatim during the layout-mirror step. The fallback chain (`DOCS/README.public.md` → public-marker extraction → auto-stub) was running unconditionally and crashing on `Join-Path $docsSrc 'README.public.md'` when `$docsSrc` was nulled.
- **Stage step trimmed under GitHub Actions' 21K expression limit** (was 24,785 chars after the v2.2 flat-layout rewrite; stripped 62 comment lines to land at 20,536). Tag-triggered runs were silently rejected by GitHub before this. Follow-up TODO: extract the Stage step to a separate `_publish-stage.ps1` so the limit is moot.
- **Duplicate `dependencies if-block` removed** from `publish.yml` (merge artifact from v2.2.0 stable cut — both branches added similar logic).

### Repo hygiene

- **Submodule `M (new commits)` noise silenced** via `ignore = all` in `.gitmodules` for `DefenderRepo`, `IntuneRepo`, `Purview-Goodies`. The submodule HEADs occasionally drift from the superproject pin; `git status` no longer flags them. Explicit `git submodule update` commands still work normally.

### Upgrade

```powershell
cd <your SI install>
git fetch origin
git checkout main
git pull origin main
```

The `v2.2.0` GitHub Release tag is **frozen at the first publish** and does not include these fixes. Pin to `v2.2.1` (or pull `main`) to get the cumulative state.

---

## v2.2.0 — Stable release (promoted from preview)

After ~200 preview tags, v2.2 ships stable. **Same architecture as the preview series** — read-only engine, layered config, AI signal-map, EG-primary RA, dynamic bucketing — plus structural cleanup and a focused round of audit-driven RA fixes.

### Breaking change — folder layout flattened

The `v2.2/` subfolder is gone. The whole solution lives at `SOLUTIONS/SecurityInsight/` (engine, auth, launcher, setup, container, etc., as direct children). Every customer path drops the `v2.2/` segment:

- `SOLUTIONS/SecurityInsight/v2.2/Setup-SecurityInsight.ps1` → `SOLUTIONS/SecurityInsight/Setup-SecurityInsight.ps1`
- `SOLUTIONS/SecurityInsight/v2.2/launcher/risk-analysis/...` → `SOLUTIONS/SecurityInsight/launcher/risk-analysis/...`
- `SOLUTIONS/SecurityInsight/v2.2/config/SecurityInsight.custom.ps1` → `SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1`

The legacy v2.1 root folders (`CUSTOMDATA/`, `LAUNCHERS/`, `SCRIPTS/`, `DATA/`, `DOCS/`, `TOOLS/` + `InitialDeployment_Latest_Version_SecurityInsight.ps1`) are also removed. Customers who pulled from the public stable repo before today should expect their entire `SOLUTIONS/SecurityInsight/` tree to be replaced on the next git pull. Take a backup before pulling.

**Container customers**: `Bootstrap-ContainerAppJob.ps1` rebuilds with the new `--file container/Dockerfile` (no `v2.2/` prefix). Run a fresh bootstrap to repoint the Container App Jobs at the new image entrypoints (`/app/container/Start-SIInContainer.ps1`, `/app/container/Start-RiskAnalysisInContainer.ps1`).

### Major RA report fixes (audit pass)

A thorough field-name audit between RA YAML expectations and Profile schema reality surfaced + fixed several systemic issues:

- **KQL semantic errors fixed**:
  - `Identity_SPN_OwnerMismatch_Detailed/Summary` — bare `where isnotempty(Owner)` referenced a column that doesn't exist; reordered so `where` operates on the `column_ifexists`-wrapped alias.
  - `Identity_PrivilegedUser_NoConditionalAccess_Detailed/Summary` — `join ... on Upn` failed because `Upn` is dynamic on `SI_Identity_Profile_CL`; added explicit `tostring(Upn)` cast in the projection.
- **32 bare `where isnotempty(<bareCol>)` patterns wrapped in `column_ifexists`** across `EG_AadDeviceId`, `AzureResourceId_Guid`, `Severity`, `Target_AzureResourceId_Guid`, `NodeId`, `Location`, `Mail`, `UserUPN` — no more "Failed to resolve scalar expression" failures from these reports.
- **107 `summarize ... by` blocks now preserve identifier columns** (`MdeDeviceId`, `EntraAccountObjectId`, `AzureResourceId`, `AssetId`) via `any(column_ifexists(...))` so the engine's MoreDetails enrichment can build portal links even on Summary aggregates that previously aggregated away every per-row ID.
- **MITRE/Compliance preserved through summarize** — `Device_Recommendations_*` reports compute MITRE/Compliance pre-summarize from the `DeviceTvmSecureConfigurationAssessmentKB` join but were dropping them at the aggregation step. Now propagated through.

### MoreDetails consolidation

- **`PortalUrl_Defender` / `PortalUrl_Entra` / `PortalUrl_Azure` columns dropped.** They were noisy + empty on most reports because the source ID columns weren't carried through aggregations. Their content is now folded into `MoreDetails` as raw URLs separated by `\r\n` (Excel renders as in-cell line breaks).
- **`MoreDetails` is now a single newline-separated URL list** — auto-harvested URLs across every column + Defender/Entra/Azure portal links + MITRE attack.mitre.org links. Deduped, capped at 25 URLs / 4000 chars.
- **Engine column-name fix** — Identity portal links were silently empty for every report because the engine looked for `EntraObjectId` (which doesn't exist in `identity.schema.locked.json`) instead of `EntraAccountObjectId` (the actual schema column). Lookup order now puts the schema column first, with the older alias as fallback.

### Always-exists columns on every report

Three columns now appear on every RA row (empty when source data isn't available):

- `MITRE_Tactics`, `MITRE_Techniques` — populated by the `Device_*` reports via the `DeviceTvmSecureConfigurationAssessmentKB` join (semicolon-list of `TA*` / `T*` IDs). Empty for Identity / Azure / PublicIP / Attack-Path reports until v2.3 ships the static `ConfigurationId → MITRE` lookup.
- `ComplianceTags` — populated by the same KB join (CIS / NIST / PCI-DSS bench tags).

The schema is now stable across all 136 reports — downstream Power BI / Workbook consumers can map these columns once and they'll always be present.

### Email + transport

- **Tenant tag in RA email subject** — `Security Insights | Risk Analysis | <ReportTemplate> | <tenant>`. Resolved from `$global:TenantShort` → `$global:TenantNameOrganization` → `$global:AzureTenantID`/`SpnTenantId`. Multi-tenant operators can now separate incoming reports at a glance.
- **Graph 5xx/429 retry** — `Invoke-SIGraphPaged` retries transient backend errors (429 throttle, 502/503/504 gateway) up to 3 attempts with exponential backoff (1s, 2s, 4s). Permanent errors (401/403/404) propagate immediately so the caller can emit a domain-specific warning.
- **PIM eligible fetch** — failure messaging classified by HTTP status (`403` = "no Entra ID P2 license, or token missing RoleManagement.Read.Directory"; `5xx` = "Graph backend transient after 3 retries"; etc.). Was previously always blaming "no P2 license" even when the actual error was a 504 Gateway Timeout.

### Setup / wizard

- **One entry-point**: `Setup-SecurityInsight.ps1` is now the single orchestrator. New `-Wizard` switch opens the offline web GUI (`setup/ConfigWizard/Setup-SecurityInsight.html`) in your default browser; no more separate `Config-SecurityInsight.ps1` wrapper.
- **Wizard renamed** from `index.html` to `Setup-SecurityInsight.html` (more discoverable when browsing the folder).
- **Defaults shown in generated snippets** — when an input field has a `data-default` attribute and the user hasn't typed anything, the snippet shows the default value with a trailing `# default` marker so customers see exactly what they get if they leave the field untouched.
- **Demo refresh kit** at `demo/`: `Install-DemoConfig.ps1` copies `demo/community/*` into the live config paths (or back, with `-Direction FromLive`) so the community demo VM can be refreshed in one command.

### Customer config sample rewrite

- `config/SecurityInsight.custom.sample.ps1` — full v2.2 surface area (528 → 580 lines, 118 → 226 globals). 4-engine split (`SI_AssetLimit_*`, `SI_Sinks_*`, `SI_ForceFullRun_*`, `SI_EnableAI_*`), single-SPN model (`SI_SPN_*`), Identity sign-in enrichment, AI per-engine disable, 16 `SI_Bootstrap_*` container knobs. Organized in 15 sections.

### Counts

| Metric | Preview | Stable |
|---|---:|---:|
| Risk Analysis reports | 134 | **136** (+2 — `Endpoint_ActiveCompromise_Detected_*` pair landed) |
| Profile schema fields | 672 | **697** (+25 across all 4 tables) |
| Asset-classification rules | 559 | **594** (+35) |
| AI tier catalog entries | 2,297 | **2,311** (+14) |

### Documentation

- README intro restructured: removed the duplicated "headline" block; added a "Why you need / What we deliver / Outcome / Architecture" narrative; moved the Detection-queries / AI-tier-catalog inventory tables into § 7.8 (Locked catalog reference).
- New: `setup/ConfigWizard/README.md`, `demo/README.md`, `internal/side-by-side-install-from-v1.md` (internal-only), `docs/Report-Enrichment-Model.md` v2.2 status note.

### Internal-only (NOT published to public stable repo)

These ship in the source monorepo but are excluded from the public `KnudsenMorten/SecurityInsight` stable mirror:

- `internal/Migrate-FromV1.ps1` — migrates customers from the old v1 automation framework (`c:\scripts\functions\Automation-*.psm1`) over to a fresh SI v2.2 install. Contains 2linkit-specific KV secret-name conventions, so kept private.
- `internal/side-by-side-install-from-v1.md` — companion install guide.

### Publish workflow change (operator-facing)

The publish pipeline (`.github/workflows/publish.yml`) now uses **flat-layout detection** (presence of `engine/` at the solution root) instead of the old "is preview channel + has v2.2/ subfolder" gate. Both stable and preview channels publish from the same layout. Excludes `internal/`, `logs/`, `OUTPUT/`, `staging/`, and `solution.publish.json` from the staged output.

---

## v2.2.0-preview — Initial preview

The first cut of the v2.2 architecture. **Read-only at collection time, no agent, no tag prep required.** The whole product in one sentence: connect to Defender + Entra + Azure via API, profile every asset into a tier (0–3), score every finding by attacker-centric impact, deliver a ranked list to operators / SOC / executives in their preferred sink (Excel, KQL, JSON, Power BI).

### Headline capabilities

- 🌟 **Zero-footprint** — engine never writes back to MDE / Entra / ARM. Asset tags are *read* when present, derived from rules + AI signal-map when not. Works on a fresh tenant with no prep.
- ☁️ **Cloud-native execution** — ACR image + one Container Apps Job per engine, schedule-triggered (cron) or KEDA-event-driven (queue scaler). Single bootstrap deploys the whole pipeline.
- 🧬 **Profile data model** — 4 flat-column LA tables (`SI_Endpoint_Profile_CL`, `SI_Identity_Profile_CL`, `SI_Azure_Profile_CL`, `SI_PublicIp_Profile_CL`), 672 fields total. KQL queries read flat columns — no `parse_json` on hot path.
- 🎯 **134 Risk Analysis reports** (67 Summary + 67 Detailed, fully paired -- one row per asset on Detailed, one row per finding type on Summary) across 4 domains (Endpoint, Identity, Azure, PublicIP). EG-primary RA pattern: queries source from Microsoft Exposure Graph nodes/edges, join `SI_*_Profile_CL` only for Tier / CMDB enrichment.
- 🔗 **Cross-source asset mapping** — same asset can show in MDE + ARG + EG + CMDB; SecurityInsight normalizes to one row per asset (`PrimaryEntityId` from `EntityIds[0]`), every alias appended to `EntityIds[]`.
- 📋 **CMDB integration** — opt-in `servicenow-cmdb` provider folds an external CSV onto every Profile row at the Reconcile stage. Read-only: CMDB stays the source of truth.
- 🤖 **AI signal-map cache** — learns per-engine property weights once, caches the verdict for cadence-bound re-classification. Off by default; opt in via `$global:SI_EnableAI`.
- 📐 **Enrichment rules system** — 559 locked rules (mostly endpoint application-detection) merged with customer overrides. Per-rule `id`-based merge: customer wins on conflict, additions allowed.

### What's new in this preview vs the prior published cut

#### Engine

- **EG-as-source for endpoints + Azure** — Exposure Graph is the primary discovery for these engines (Entra still primary for identity). Cross-engine joins use shared `EntityIds[?type=='AzureResourceId']` value so historical Sentinel queries still resolve assets after re-merge.
- **Tier engine — pure MIN-of-SIRules** — no static defaults, no derivedType→tier maps. Every signal (catalog, software, tags, logon, CMDB) becomes a rule entry; engine reduces by `min(Tier)` across matched entries.
- **3-layer score model** — every report's KQL emits `RiskScore`. Engine multiplies by per-finding-type weight to produce `RiskScoreTotal_Weighted` (the actual remediation priority signal). xlsx orders columns: `RiskScoreTotal → RiskScore_Weight_Factor → RiskScore_Weight_Detailed → RiskScoreTotal_Weighted`.
- **Dynamic bucketing** — heaviest reports auto-shard from `BucketCount=1` upward (1 → 2 → 4 → 8 → 16 → … up to 1024) only when the query exceeds the 30k advanced-hunting ceiling. Discovered count caches per-report in `OUTPUT/AutoBucketCache.json`; subsequent runs skip the probe.
- **Per-report try/catch in the RA foreach** — one bad report (KQL parse fail, empty filter input, missing source table) no longer kills the whole run. Filter-loop empty-array guard prevents the upstream "table doesn't exist" pattern from cascading.
- **`$global:final` reset at script start** — prevents stale-data leak from prior run into JSON / LA / AI summary when current run produces zero rows.
- **RunHealth heartbeat** — Start row at script init + End row at script tail to `SI_RunHealth_CL`. Missing End row IS the failure signal (KQL: `where Phase=='Start' | join kind=leftanti (… Phase=='End') on RunId, ShardIndex`).

#### Reports

- **MITRE projection in `Device_Recommendations_*`** — KB join now lifts `RelatedMitreTactics`, `RelatedMitreTechniques`, `Tags`, `ConfigurationBenchmarks`. New columns `MITRE_Tactics`, `MITRE_Techniques`, `ComplianceTags` per row. Engine appends `attack.mitre.org` URLs into `MoreDetails`.
- **`PortalUrl_Defender` / `PortalUrl_Entra` / `PortalUrl_Azure`** — engine auto-generates clickable portal URLs per row from `MdeDeviceId` / `EntraObjectId` / `AzureResourceId`. Force-included on every report (no per-YAML opt-in needed).
- **`RiskFactor_Probability_Detailed` engine tokens** — Defender AV state (`DefenderAvDisabled`, `DefenderAvOutOfDate`), MDE coverage (`Unonboarded`, `Unmanaged`, `Excluded`), EG signals (`HighMachineRisk`, `IsCompromisedRecently`, `InternetExposureSignal`).
- **`RiskFactor_Consequence_Detailed` engine tokens** — `MsCriticalityHigh`, `IsProductionEnvironment`, `IsAdfsServer`, `IsExchangeServer`, `IsExchangeOnlineMailbox`.
- **NEW report `Endpoint_ActiveCompromise_Detected_Tier01`** (Summary + Detailed) — Tier 0/1 endpoints flagged by Microsoft Exposure Mgmt as recently compromised. Uses the new `IsCompromisedRecently` signal.
- **12 NEW Identity reports** (one-row-per-asset) ported from the legacy v2.1 Identity catalog: `Identity_Departed_AccountStillEnabled` (HR off-boarding gap via `EmployeeLeaveDateTime`), `Identity_DisabledPrivilegedUser`, `Identity_DisabledUser_StillInCriticalGroup`, `Identity_GuestWithPrivilegedRole`, `Identity_Identity_NoMfa_OnTier01_Resource` (cross-engine join `SI_Identity × SI_Azure`), `Identity_PrivilegedRole_PermanentNotEligible`, `Identity_PrivilegedUser_NoConditionalAccess`, `Identity_SPN_MailboxImpersonation`, `Identity_SPN_OwnerMismatch`, `Identity_SPN_OwnsResourcePublicAccess`, `Identity_AdNestedCriticalGroup_NoEntraRole`, `Identity_HighRiskFactorComposite4Plus`. All ship in the `RiskAnalysis_Detailed` template. **Plus 12 matching `_Summary` siblings** (aggregated rollups -- one row per finding type with AssetCount / TotalIssues / ImpactedAssets) shipped in `RiskAnalysis_Summary` -- so every newly-ported report exists in both per-asset Detailed and per-finding Summary form.
- **`Device_Recommendations_*` MITRE columns hardened** — wrapped `RelatedMitreTactics` / `RelatedMitreTechniques` in `column_ifexists()` so the reports degrade gracefully on tenants whose XDR Advanced Hunting `DeviceTvmSecureConfigurationAssessmentKB` schema is missing those fields (avoids 4-attempt retry burn observed in preview.196).

#### Profile schemas

- **Endpoint** — added 7 EG-derived columns: `MsCriticalityLevel`, `MachineRiskState`, `IsCompromisedRecently`, `IsProductionEnvironment`, `IsAdfsServer`, `HasInternetExposureSignal`, `IsExcluded`. Plus `AssetType` fallback in the classifier (was always `"Unknown"` when AI off + no rule match; now derives from MDE / EG signals).
- **Azure** — added 4 EG signals (parity with endpoint): `MsCriticalityLevel`, `IsCompromisedRecently`, `IsProductionEnvironment`, `HasInternetExposureSignal`.
- **Identity** — added 7 EG signals: `MsCriticalityLevel`, `IsCompromisedRecently`, `IsExternalUser`, `OnPremSyncEnabled`, `IsMfaCapable`, `IsMfaRegistered`, `EntraAccountObjectId`.

#### Asset profiling

- **Tier-driven cadence** — Stage Collect skips re-classification when `last_seen_at + cadence(cached_tier) > now`. Tier 0 refreshes hourly; Tier 3 weekly.
- **AssetProfileBy* rule merge** — Locked + Custom dedup by `id`. Custom wins on conflict.
- **EG identity coverage gap fix** — second-pass JSON parse on `EntityIds` elements; `ENTRA_UserId` keying.

#### Distribution

- **Two launcher flavours per engine, both shipped together**:
  - `launcher.community-vm.ps1` — `FUNCTIONS/AutomateITPS*` inlined under solution folder
  - `launcher.internal-vm.ps1` — `FUNCTIONS/` is sibling of solution (monorepo layout)
- **`tools/Push-PreviewBundle.ps1`** — bundles dev tree + `AutomateITPS` modules in either layout (Community / Internal / Zip). Offline customer hand-off helper.

### Documentation

- **Audit + design docs** authored alongside the engine:
  - `docs/MDE-EG-FieldGap-Audit.md` — gap analysis of every Microsoft built-in table referenced by the RA queries vs what we currently project to Profile_CL.
  - `docs/Report-Enrichment-Model.md` — generic enrichment model: which new columns / `RiskFactor_*_Detailed` tokens / portal URLs to add, per-tier rollout plan.
- **Auto-generated reference** alongside the source-of-truth files:
  - `docs/asset-profiling-schema.md` — every Profile-table column with type, source, source-path, written-by-stage, read-by-stages, `addedIn`. Generated by `asset-profiling-schema/tools/Build-SchemaDoc.ps1`.
  - `docs/risk-analysis-detection.md` — every Risk Analysis report with purpose, source tables, severity / tier scope, output columns, KQL.

### Known limitations in this preview

- **PublicIP / Shodan engine**: source table `SI_VulnerabilityPIP_CL` not yet populated. The 2 `PublicIP_*` reports (`PublicIP_OpenPorts_*`, `PublicIP_Vulnerabilities_*`) skip cleanly when the table is empty (filter guard handles it).
- **AlertEvidence as new RA source**: designed in `Report-Enrichment-Model.md` (Tier E), not yet wired. `Defender_Alert_Active` + `Defender_Alert_Count_30d` columns are pending.
- **SigninLogs `DeviceDetail` enrichment in Identity reports**: designed (Tier F), not yet rolled across the 6 `Identity_*_SignIn_*` reports.
- **Some single-tenant scale issues**: sign-in enrichment may time out on very large tenants (>100K identities) — hash-bucket sharding fix is queued.

### Migration / Upgrade

This is the first published preview of v2.2. There is no prior v2.2 to upgrade from. To try the preview alongside stable:

```powershell
# 1. Clone the preview branch
git clone -b preview https://github.com/KnudsenMorten/SecurityInsight.git C:\SecurityInsightPreview

# 2. Or bundle the dev tree to a customer machine (offline drop)
.\tools\Push-PreviewBundle.ps1 -TargetRoot C:\Demo\SecurityInsightPreview -Layout Community

# 3. Run the launcher
C:\Demo\SecurityInsightPreview\launcher\risk-analysis\launcher.community-vm.ps1 -Summary
```

Stable customers: keep your current install untouched. The preview ships under `C:\SecurityInsightPreview` (or wherever you clone it) and operates against the same Defender / Entra / Azure tenants in read-only mode.

---

_For the raw commit log of every change since the prior tag, see the auto-generated section appended below by the publish workflow._

