# SecurityInsight v2.2 README — rewrite plan (v2)

**Status**: PLAN ONLY. No README written yet. This is the **revised** plan after reviewing the existing root README structure + the MMS MOA 2026 PPT (155 slides) + 6 LA-portal screenshots.

**Where it lands**: `SOLUTIONS/SecurityInsight/README.md` (new v2.2-scoped doc; root SI `README.md` keeps its marketing/teaser role).

---

## 1. What changed from v1 of this plan

User feedback that drove the rewrite:

1. **Open story-first like the PPT** — Goal → Why → Concept → Risk Model → Engines → Operations. Not "TOC-first then chapters".
2. **Define the 4 key terms early** — Providers (input), Detection rules (enrichment), Schema (data model), Sinks (output). An IT admin should know these by page 3.
3. **"What are you trying to do?" pattern** — task-oriented chapter that maps a user goal to which other chapters to read. Not a feature catalog.
4. **IT-admin friendly tone** — no jargon without first defining it. Keep the file-format / schema-deep-dive material in an appendix where curious operators dig in voluntarily.
5. **Include Shodan / PublicIP engine** — task #111 is still pending but the slot exists in the engine roster.

---

## 2. Proposed TOC (revised)

### Front matter (one printable page worth of content)
- Tagline + one-paragraph value proposition (steal from existing root: "Think like the hacker, act like the defender")
- v2.1 → v2.2 at-a-glance comparison table (zero footprint, no tagging, etc.)
- Numbers table — what ships in v2.2 (engines × tables × fields × reports × rules × AI tier catalog)
- TL;DR Quick-start ("3 steps to your first risk-analysis report") — links into Chapter 4

### Chapter 1 — The Story  *(concept-first, no commands)*
- 1.1 The problem: too many recommendations, no priority *(slides 5-6 GOAL)*
- 1.2 The hacker's view — graphs not lists *(slides 8-17 ExposureGraph + attack-path examples)*
- 1.3 The defender's answer — tier every asset by criticality, score every finding by impact
- 1.4 **The 4 building blocks** *(NEW — defined here, used everywhere after)*
  - **Providers** = where raw data comes from (Defender XDR, ExposureGraph, Microsoft Graph, Azure Resource Graph, Shodan, on-prem AD, CMDB CSV)
  - **Detection rules** = how an asset gets a tier verdict (YAML rules with `detect.kind: hasMdeMachineGroupTag / hasAzureTag / entraGroupMember / nameMatches / IPSubnetMatch / hasSoftwareInstalled / egDetectedRoles / …`)
  - **Schema** = the columns that end up in your Log Analytics tables (locked JSON + customer overlay)
  - **Sinks** = where the output lands (Log Analytics, Excel, JSON, mail, blob, Power BI, Azure Workbook)
- 1.5 The 5 engines — one-line each
  - `privilege-tier-classifier` — AI-tiers every Entra/AD/Azure role + API permission (foundation; runs first)
  - `asset-profiling-identity` — one row per identity in `SI_Identity_Profile_CL`
  - `asset-profiling-endpoint` — one row per endpoint in `SI_Endpoint_Profile_CL`
  - `asset-profiling-azure` — one row per Azure resource in `SI_Azure_Profile_CL`
  - `asset-profiling-publicip` — one row per public IP in `SI_VulnerabilityPIP_CL` (Shodan-driven)
  - `risk-analysis` — turns Profile tables into ~104 prioritized findings via KQL reports
- 1.6 End-to-end data flow (Mermaid diagram: Providers → Profile_CL tables → Risk Analysis → Sinks)

### Chapter 2 — The Risk Score Model  *(slides 26-32, 75-79)*
- 2.1 Why a risk score (vs. raw severity)
- 2.2 The formula in 3 layers
  - Layer 1: `Consequence × Probability = RiskScore` (raw)
  - Layer 2: `RiskScoreTotal` (aggregated per asset)
  - Layer 3: `RiskScoreTotal_Weighted = RiskScoreTotal × WeightFactor` (CMDB-amplified — sorts your Excel)
- 2.3 Where each input comes from
  - Consequence ← Severity (Defender) + your `riskscore.index.custom.csv`
  - Probability ← CriticalityTier (engine-derived) + your `riskscore.index.custom.csv`
  - WeightFactor ← `riskscore_weighted.schema.custom.json` × cmdbCriticality + cmdbDataSensitivity
- 2.4 **cmdbCriticality multipliers** (Critical=150 / High=125 / Medium=110 / Low=105 / default=100)
- 2.5 **cmdbDataSensitivity multipliers** (Restricted=175 / Confidential=150 / Internal=125 / Public=110)
- 2.6 Worked example — same finding on a Tier 0 critical asset vs Tier 3 sandbox
- 2.7 Tier definitions (Tier 0 → Tier 3 — what each means in practice) *(slides 75-79)*
- 2.8 Severity definitions

### Chapter 3 — What are you trying to do?  *(NEW — task-oriented index)*
This chapter is the **only place that takes the operator's perspective**. Each entry: 1 sentence problem statement → 2-3 sentences answer → link to the deep chapter.
- 3.1 *I want to install SecurityInsight on a fresh tenant* → Chapter 4
- 3.2 *I want to schedule it to run daily* → Chapter 5
- 3.3 *I want to add a new detection rule* (e.g. "tag any device named DC* as Tier 0") → recipe in 3.3.1 + Chapter 8
- 3.4 *I want to mark our Finance team as Tier 2 power users* (custom YAML overlay) → recipe in 3.4.1 *(matches the screenshot `asset-profiling-identity-enrichment-tier 2 groupmember.png`)*
- 3.5 *I want to integrate my CMDB so business-criticality shows up in the reports* → Chapter 6 + recipe in 3.5.1
- 3.6 *I want to add a custom column to the Profile table* (e.g. `BusinessOwnerEmail`) → recipe in 3.6.1
- 3.7 *I want to suppress some findings* (excluded CVEs / configurations) → recipe in 3.7.1
- 3.8 *I want to scan our public IPs for open ports + vulnerabilities* → Chapter 6.6 (Shodan / PublicIP engine)
- 3.9 *I want to send results to a SIEM other than Sentinel* → Chapter 6.7 (JSON sink)
- 3.10 *I want to extend SecurityInsight with my own engine* → Appendix A.4 (engine fork)

### Chapter 4 — Setup
- 4.1 Prerequisites (subscription roles, MG admin, Defender XDR access, KV)
- 4.2 Layered config model (Layer 0 platform → Layer 3 solution → Layer 5 per-engine → CLI args)
- 4.3 Pick an authentication method (SPN+cert / SPN+KV / Managed Identity / SPN+plaintext)
- 4.4 **Bootstrap Log Analytics infrastructure** *(was scattered — now one chapter)*
  - 4.4.1 What gets created (workspace, DCE, DCRs per engine, custom-log tables, RBAC)
  - 4.4.2 Staging container (`sistaging`) — what it holds + why
  - 4.4.3 First-run checklist
- 4.5 **Bootstrap Container App Job infrastructure**
  - 4.5.1 What gets created (ACR, Container App Environment, one Container App Job per engine, image build via `az acr build`)
  - 4.5.2 KEDA queue auto-scale (heavy-tenant pattern)
- 4.6 Azure OpenAI provisioning (optional; powers `privilege-tier-classifier` + RA exec summary)
- 4.7 Smoke test (Test-Smoke.ps1)

### Chapter 5 — Daily run plan & scheduling  *(NEW — explicit walkthroughs)*
- 5.1 Recommended cadence + dependency order
  ```
  Prio 1  17:00  privilege-tier-classifier   (foundational; catalog must exist before profilers)
  Prio 2  20:00  asset-profiling-identity
  Prio 2  20:00  asset-profiling-endpoint
  Prio 2  20:00  asset-profiling-azure
  Prio 2  20:00  asset-profiling-publicip    (Shodan)
  Prio 3  03:00  risk-analysis-summary       (reads all Profile_CL tables)
  Prio 3  03:30  risk-analysis-detailed
  ```
- 5.2 Engine launcher catalog (table — engine → `SOLUTIONS/SecurityInsight/launcher/<engine>/launcher.<flavour>-vm.ps1`)
- 5.3 **Windows Task Scheduler walkthrough** — exact `schtasks /create` per engine, run-as account guidance, transcript path
- 5.4 **Azure Container App Jobs walkthrough** — cron expression per engine, image-tag pinning, secrets wiring
- 5.5 Logs + transcripts (where they land, retention)
- 5.6 Run-overlap protection (cache freshness gate, RunId)

### Chapter 6 — Integrations
- 6.1 **CMDB integration** *(promoted to first-class)*
  - 6.1.1 Why a CSV (no live CMDB API call — read-only snapshot)
  - 6.1.2 Where the file lands
  - 6.1.3 Required columns: `id`, `name`, `criticality`, `dataSensitivity`, `azure_resource_id`, `entra_object_id`, `fqdn`, `last_seen`
  - 6.1.4 Optional columns flow to `Metadata.CMDB_*` automatically
  - 6.1.5 How rules consume cmdbId (rule sets `cmdbId='1'` → engine looks up service `1` → auto-fills cmdbName/cmdbCriticality/cmdbDataSensitivity)
  - 6.1.6 Two matching phases (Phase 1 rule-driven, Phase 2 identity-match fallback)
- 6.2 ServiceNow CMDB exporter helper (Refresh-CmdbCache.ps1)
- 6.3 **Shodan / PublicIP engine** *(covers task #111)* — input flow, scope (Tier 0/1 public IPs only), output table, RA queries (open-port + vulnerabilities)
- 6.4 Power BI dataset refresh (per-run, opt-in)
- 6.5 Azure Workbook import
- 6.6 Mail dispatch (Brevo / SendGrid / Postmark / M365 — verified-sender requirement)
- 6.7 Generic JSON sink (forward to non-Sentinel SIEM)

### Chapter 7 — Operations
- 7.1 Reading the launcher transcript (path, key markers, what to grep for)
- 7.2 Common errors + fixes (table)
  - `BadRequest: Failed to resolve scalar expression named X` → wrap with `column_ifexists`
  - `413 Request Entity Too Large` → AH 1MB body cap, scoped pre-fetch
  - `Expected: ;` / `Expected: ,` → KQL parse error in rendered query (paste rendered file path → portal)
  - `AutoBucket failed` → escalate bucket count
  - `between(): argument #1 - invalid data type: dynamic` → `toint(column_ifexists(...))`
- 7.3 Reset / re-bootstrap (Reset-CmdbCache, Reset-AutoBucketCache)
- 7.4 Performance tuning (AutoBucket / AssetLimit / KEDA / fingerprint cache / tier cadence)

### Chapter 8 — How-to recipes  *(extends Chapter 3 with the actual step-by-step)*
- 8.1 **Add a new RA detection rule** (Summary + Detailed pair)
  - The 5 KQL motifs every report uses (CL pre-fetch let-block / EG primary join / bucket markers / weighted-factors markers / cmdb post-extend)
  - Adding the report to `ReportTemplate.ReportsIncluded`
  - Test locally with Test-Smoke.ps1
- 8.2 **Add a new asset-profiling rule** (custom YAML overlay)
  - The shape: `RuleId / DetectionId / appliesTo / detect.kind / set.{Tier, Purpose, Category, cmdbId}`
  - Locked + custom merge modes (`append` / `merge` / `overwrite` / `disable`)
  - Restart engine, verify rule fires in `SIRules` array on a row
- 8.3 **Add a custom Profile column** (schema overlay)
  - Pick `source: entra | mdi | exposureGraph | azure | derived`
  - Add to `*.custom.json` overlay (no locked-file edit)
  - Verify it lands in `SI_*_Profile_CL` after run
- 8.4 **Add a custom CMDB column** that surfaces in RA reports
- 8.5 **Add a new weighted-factor** to `riskscore_weighted.schema.custom.json`
- 8.6 **Suppress a finding** (`<ReportName>.exclude.json` recipe)
- 8.7 **Tag your Finance team as Tier 2** *(matches the screenshot — full walkthrough)*

### Appendix
- A.1 Engine catalog (full table — name, script, launcher path, output table, cadence, dependencies)
- A.2 Globals catalog (every `$global:SI_*` and `$global:HighPriv_*` — purpose, default, layer)
- A.3 Permissions catalog (per engine: minimum + recommended Graph / Defender / Azure RBAC)
- A.4 **Schema files reference** *(file-format deep-dive — moved here per request)*
  - A.4.1 `asset-profiling-schema/identity.schema.locked.json` — column anatomy (`name / source / sourcePath / type / purpose / stage.writtenBy / stage.readBy / emit`)
  - A.4.2 `asset-profiling-schema/endpoint.schema.locked.json`
  - A.4.3 `asset-profiling-schema/azure.schema.locked.json`
  - A.4.4 `asset-profiling-schema/SCHEMA.locked.json` (the index)
  - A.4.5 `*.custom.json` overlay merge contract
- A.5 **YAML files reference**
  - A.5.1 `asset-profiling-enrichment/<engine>/AssetProfileBy*.locked.yaml` — rule shape
  - A.5.2 `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` — report shape
  - A.5.3 `riskscore_weighted.schema.custom.json` — weighted-factor declarations
  - A.5.4 `riskscore.index.custom.csv` — per-finding consequence/probability scores
  - A.5.5 `<ReportName>.exclude.json` — exclusion lists
- A.6 **Architecture diagram** (end-to-end Mermaid + the PPT slide-94 architecture for download)
- A.7 RA report inventory (~104 reports — auto-regenerated)
- A.8 What changed v2.1 → v2.2 (migration notes for existing customers — drop list)
- A.9 Glossary (CMDB, EG, MDI, MDE, MDVM, PIM, AH, LA, DCE, DCR, CL, KEDA, SPN, MI, MG)
- A.10 Companion materials — link to PPT (`docs/MMS-MOA-2026-deck.pptx`), video walkthroughs, support channels

---

## 3. What gets DELETED from the current root README

| Section | Why delete |
|---|---|
| §3.11 "Step 5a — Endpoint & Azure asset tagging" | Tagging not required — drop wholesale |
| §3.12 "Step 5b — Azure asset tagging" | Same |
| §5.6 "CriticalAssetTagging — `Mode:` (rule) + `$global:Scope` (launcher)" | Tagging engine retired from active path |
| §5.7 "`AssetTagName` naming convention" | Same |
| Any text in §1/§2 implying tagging is required for tier verdicts | Replace with: "CMDB integration via rules — see Chapter 6" |
| References to `SI_IdentityAssets_CL` as the primary identity table | Replaced by `SI_Identity_Profile_CL` (keep one mention as legacy bridge in A.8 migration notes) |
| All `identity-tiering` references | Renamed to `privilege-tier-classifier` (this session) |
| §10 "Schema-discovery meta-engine" — IF still shipped | Verify before keeping |
| The huge §3.5 "Pre-requisite configuration" wall of code | Split into 4.4 (LA bootstrap) + 4.5 (container bootstrap) + 4.6 (OpenAI) — much smaller |

---

## 4. Visual + content assets we'll use

### 4.1 PNG screenshots (already copied to `v2.2/docs/screenshots/`)

| File | Embed in section |
|---|---|
| `asset-profiling-endpoint-tier0-dc-cmdb.png` | §1.5 Endpoint engine intro + §2.6 worked example (DC=Tier 0+Critical) + §6.1.5 CMDB-driven tier (proof) |
| `asset-profiling-azure-tier-parent.png` | §1.5 Azure engine intro + §6.1 (ParentMG_Structure resolved) |
| `asset-profiling-identity-find-no-mfa-registered.png` | §1.5 Identity engine intro (table is queryable directly) + §3.3 detection-rule recipe motivation |
| `asset-profiling-identity-api-permissions.png` | §1.5 Identity engine intro + §2.3 (Verdict_TopMatch column shows tier traceability) + §A.4 schema field anatomy |
| `asset-profiling-identity-topmatches-tier-decission.png` | §2.3 + §A.4 (tier verdicts are fully introspectable) |
| `asset-profiling-identity-enrichment-tier 2 groupmember.png` | §3.4 / §8.7 (Finance team Tier 2 — direct visual answer to the recipe) |

### 4.2 PPT slides (155-slide MMS MOA 2026 deck)

I'll paraphrase concepts into prose (no copy-paste of slide text). Slide-to-chapter map:

| Slide range | Topic | Chapter |
|---|---|---|
| 1-7 | Title + GOAL + Why SI | Front matter + §1.1 |
| 8-17 | ExposureGraph + Lists vs Graphs + Attack Path examples (×6) | §1.2 The hacker's view |
| 26-32 | Risk-based Approach + Risk Score Formula with Weight + RiskIndex | §2 entire chapter |
| 33-37 | Profile every asset + Asset Profiling intro | §1.4 + §1.5 |
| 39-49 | Endpoint + Azure Classification + DEMOs + Profile_CL tables | §1.5 + §A.4 |
| 50-61 | Identity Classification + Scale + SI_Identity_Profile_CL examples | §1.5 + §A.4 |
| 62-66 | Risk Analysis + 126 reports | §1.5 risk-analysis engine |
| 72-74 | CMDB ServiceNow integration + Sources Feeding RA | §6.1-§6.2 |
| 75-79 | Tier Definitions + Severity + Criticality classification | §2.7-§2.8 |
| 94-103 | Implementation Architecture + Inputs + Data Model + JSON Files + Schema + Output Tables | §1.6 (data flow) + §A.4 + §A.5 + §A.6 |
| 104-105 | Deployment Options + Container Launch | §4.5 + §5.4 |
| 106-107 | Operations & Monitoring | §7 |
| 109-114 | Hash Bucketing + Shard Sizing + KEDA + Fingerprint Cache + Per-Stage Hashing + Per-Tier Scheduling | §7.4 + §4.5.2 |
| 115-117 | What You Need to Run + License Shopping List | §4.1 |
| 123-153 | Demo 1-11 (escalating EG queries) | §8.1 detection-rule recipe walkthrough motif |
| 154 | MS Security Posture Management Lifecycle | §1.6 framing diagram |

### 4.3 Diagrams to recreate as Mermaid (1 of)

- §1.6 End-to-end data flow (Providers → Profile_CL tables → Risk Analysis → Sinks) — Mermaid flowchart
- §1.5 5-engine dependency graph — Mermaid graph
- §2.2 Risk score 3-layer formula — Mermaid sequence
- §5.1 Daily run plan timeline — Mermaid Gantt

---

## 5. Open questions for you (must answer before I write)

1. **Audience** — confirm IT-admin first (the rewrite assumes this)? Or split into "operator" vs "detection-author" docs?
2. **Single doc or split?** — The new TOC has Chapter 1-7 + Chapter 8 + Appendix. Want it as ONE `v2.2/README.md` (long but searchable) or `v2.2/README.md` (1-7) + `v2.2/docs/howto.md` (8) + `v2.2/docs/reference.md` (Appendix)?
3. **Companion PPT** — embed selected slide images (e.g. slide 9 "Lists vs Graphs", slide 31 "Risk Score Formula") as PNGs, or link the full PPT only?
4. **Container-job detail level** — full ARM/Bicep snippets for the bootstrap, or just `az containerapp job create` one-liners?
5. **Globals catalog (A.2)** — auto-generated from a code-scanner script or hand-maintained?
6. **Schema-discovery meta-engine** (current §10) — still shipping in v2.2? If no, drop the references entirely.
7. **RA report inventory (A.7)** — auto-regenerated each release or hand-curated top-N?
8. **Shodan / PublicIP** (task #111 still pending) — document as "ships with v2.2" (and gate the recipes "coming next preview"), or omit until the engine is built?
9. **Old YAML in `legacy/`** — mention as historical reference or hide?
10. **Tagging chapter** — fully delete (current plan), or keep a 5-line "if you used the old asset-tagging engine, here's the migration path" callout in A.8?

---

## 6. Recommended next step

Answer the 10 questions above (one-line answers OK) — or just **"proceed with defaults"** and I'll write Pass 1 (Front matter + Chapters 1-3) for your review, then Pass 2 (Chapters 4-7), then Pass 3 (Chapter 8 + Appendix).

Estimated final length: **~1800-2200 lines** (vs current 2900 — leaner because the tagging chapters are gone, file-format walls move to appendix where curious readers dig in voluntarily, and the story-first opening replaces the kitchen-sink "what's new in v2.2" deep-dive).
