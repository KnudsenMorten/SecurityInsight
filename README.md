<!-- public:start -->
<a id="top"></a>

[![Releases](https://img.shields.io/github/v/release/KnudsenMorten/SecurityInsight?label=latest%20release&color=blue)](https://github.com/KnudsenMorten/SecurityInsight/releases)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell)](https://learn.microsoft.com/powershell/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Author**: [Morten Knudsen](https://mortenknudsen.net) — Microsoft MVP
**Support**: [GitHub Issues](https://github.com/KnudsenMorten/SecurityInsight/issues) · [mok@mortenknudsen.net](mailto:mok@mortenknudsen.net)
**Watch**: [Video walkthroughs](#video-walkthroughs)

---

**What you see on your Defender dashboard isn't what attackers see on their target list.** One is sorted by severity; the other is sorted by opportunity. Microsoft Defender surfaces every vulnerability, misconfiguration, and exposure in your environment — but deciding which one to address *first* is where most teams get stuck. Closing that gap is the difference between staying busy and actually reducing risk.

**SecurityInsight** is a free, community-built add-on to Microsoft Defender — created by a Microsoft MVP — that helps you see risk the way a hacker would, and act on it the way a defender must. Every recommendation across Endpoint, Azure, and Identity is scored on four dimensions: **consequence**, **Tier 0–3 asset criticality**, **risk factors** (Internet Exposure, Verified Secret, Lateral Movement, ExploitSignals, and more), and a **customizable Risk Index**.

**ExposureGraph** correlates assets, relationships, and attack paths across endpoints and Azure. SecurityInsight uses that data to classify assets and expose risks. Hundreds of ready-made queries and a built-in classification framework get you tagging servers, clients, and Azure resources from day one. For users, service principals, and managed identities, tiers are derived from **actual assigned permissions** — no static tags — and **AI** categorizes new Entra, Graph, and Azure roles automatically.

### 🎯 Think like the hacker. Act like the defender. Fix what matters — first.

> See [§ 10 What's New](#whats-new) for the full capability deep-dive — read-only engine, layered config, AI signal-map, multi-source asset correlation, and 11 more. Detection-query + tagging-rule + AI-tier-catalog inventory tables live in [§ 7.8 Locked catalog](#locked-catalog).

### Why you need SecurityInsight

- Thousands of observations — *"set & forget"* dashboards that never get acted on
- No tiering of users, devices, or workloads — every finding looks equally urgent
- Exposure data scattered across tools and consoles
- Prioritization challenges — crown jewels / business priority vs. attack paths for tenant takeover
- Compliance requires asset profiling and risk analysis:
  - **NIS2** (Art. 21): risk-management measures, asset inventory
  - **DORA**: ICT risk register, criticality classification
  - **ISO 27001** (A.5.9 / 8.8): asset register + risk treatment
  - **GDPR** Art. 32: risk-appropriate security of processing

### What SecurityInsight delivers

- Take **better decisions on what to fix** first
- **Risk Analysis** computes a Risk Score — with Risk Factors that amplify *severity × criticality*
- **Weighted Risk Score** when you enable CMDB integration (Criticality, DataSensitivity)
- **Automatic Asset Profiling** using a dynamic approach — e.g. tiering based on *actual permissions*, not on tags
- Picks up **new telemetry** (e.g. `IsAccountLeaked`, new roles, new API permissions) without redeploy
- **AI integrated** in profiling & classification

### Outcome for business

- Fix what matters most — criticality, risk, business priority, data sensitivity
- Detect drifts faster — re-focus
- Faster audits with traceable evidence
- Permission snapshots — diff two snapshots
- Prioritize mini-projects — baseline security
- Culture, awareness, guidance — the *why* behind every action
- Establish lifecycle processes — who, what, when, how

### Architecture

👉 **Zero footprint** — only requires read permissions. No tagging of resources (except if you want to *exclude* endpoints in MDE — no API for exclusion, so we use tags)

👉 **Two primary engines**: Asset Profiling (Endpoint, Azure, Identity, Public IP) + Risk Analysis. Collects data from 6 providers (Entra, ExposureGraph, MDE, MDI, AD, Azure) and sends enriched data into Log Analytics

👉 **Enriched data** comes from 700+ fields — supported providers + calculated fields like Tier, API permissions, Role permissions

👉 **100% dynamic detection** based on 20+ detection rules + app catalog (500+ known server apps). Mapping gives tier + CMDB-mapping
- Dynamic detection of **client endpoints** based on permissions (tier) of the users who use the device the most
- Dynamic detection of **servers** using software installed, detected modules, tagging, IP subnet and more
- Dynamic detection of **Azure** using tags (incl. parent tagging), subscription details and more
- Dynamic detection of **identities** based on AI-qualified detection of actual permissions for all identities

👉 **Asset mapping** — SecurityInsight can also push asset mapping back to CMDB (optional)

👉 **External Public IP scanning** of CVEs + open ports using Shodan against all detected public IPs. Automatic mapping of results into Risk Analysis reports with CMDB / tier information

👉 **136+ Risk Analysis reports**, covering Identity, Azure, Endpoints, CVEs, Public IPs

👉 **Data model** includes schema files (JSON) for fields, exclusions, detection rules + YAML files

👉 **Dynamic scaling** with Azure Container Apps Jobs to support large enterprises. Built-in performance includes KEDA scaling, fingerprint caching, hash caching, tier schedules and more

---

<a id="toc"></a>
<a id="toc"></a>
## 📑 Table of Contents

0. [Capabilities](#v22-whats-new) — what it does at a glance (11 capability deep-dives)
1. [Introduction](#introduction) — outputs, use-cases, agents, sample output
2. [Understanding the Framework](#understanding-the-framework) — the risk model concept (start here if new)
   - 2.1 [Why a graph, not a list](#why-a-graph-not-a-list)
   - 2.2 [Risk Score model](#risk-score-model)
   - 2.3 [Risk Factors](#risk-factors)
   - 2.4 [Risk Index (customizable scoring)](#risk-index-customizable-scoring)
   - 2.5 [Outputs at a glance](#outputs-at-a-glance)
3. [What's supported — Inputs, Enrichment, Outputs](#supported-inputs-enrichment-outputs)
   - 3.1 [Inputs — supported data providers](#31-inputs)
   - 3.2 [Enrichment — joining external context](#32-enrichment)
   - 3.3 [Outputs — supported sinks](#33-outputs)
   - 3.4 [Setup file checklist — which sample files to copy](#34-setup-file-checklist)
4. [How to Implement (Quick Start)](#how-to-implement-quick-start)
   - 4.1 [High-level overview](#high-level-overview)
   - 4.2 [Try out a preview release](#try-out-a-preview-release)
   - 4.3 [Pre-requisite configuration](#pre-requisite-configuration)
   - 4.4 [Connectivity — SPN or Managed Identity](#connectivity-spn-or-managed-identity)
   - 4.5 [Identity infrastructure — Workspace + DCE + DCR](#identity-infrastructure-workspace--dce--dcr)
   - 4.6 [Azure OpenAI (optional)](#azure-openai-optional)
   - 4.7 [LauncherConfig files](#understand-the-launcherconfig-files)
   - 4.8 [Run the Risk Analysis](#run-the-risk-analysis)
   - 4.9 [Distribution model — community + internal launchers](#39-distribution-model)
   - 4.10 [Asset-profiling engine catalog](#310-asset-profiling-engine-catalog)
   - 4.11 [Container & KEDA host-mode](#311-container-keda)
5. [Severity & Criticality Definitions](#severity--criticality-definitions)
   - 5.1 [Severity definitions](#severity-definitions)
   - 5.2 [Criticality definitions](#criticality-definitions)
   - 5.3 [Asset classification: Identity](#asset-classification-identity)
   - 5.4 [Asset classification: Endpoint](#asset-classification-endpoint)
   - 5.5 [Asset classification: Azure](#asset-classification-azure)
6. [The YAML Concept (Locked + Custom)](#the-yaml-concept-locked--custom)
   - 6.1 [Two files per topic](#two-files-per-topic)
   - 6.2 [Merge flow](#merge-flow)
   - 6.3 [Three things you do in Custom](#three-things-you-do-in-custom)
   - 6.4 [Concrete example](#concrete-example)
   - 6.5 [What a release upgrade does to your YAML](#what-a-release-upgrade-does-to-your-yaml)
   - 6.6 [`AssetTagName` naming convention](#assettagname-naming-convention)
7. [Appendix](#appendix) — reference + technical detail
   - 7.1 [Permissions catalog](#permissions-catalog)
   - 7.2 [Bucketing — beating the 30k row ceiling](#bucketing--beating-the-30k-row-ceiling)
   - 7.3 [Output destinations](#output-destinations)
   - 7.4 [Per-template mail recipient override (YAML)](#per-template-mail-recipient-override-yaml)
   - 7.5 [Cross-subscription workspace support](#cross-subscription-workspace-support)
   - 7.6 [Layered config flow](#layered-config-flow)
   - 7.7 [End-to-end architecture](#end-to-end-architecture)
   - 7.8 [Locked catalog — Detection queries + Tagging rules + Profile schema + AI tier catalog](#locked-catalog)
8. [Video walkthroughs](#video-walkthroughs)
9. [Support](#support)
10. [What's New](#whats-new)

## 📘 1. Introduction

[⤴ Back to top](#top)

#### 🖼️ The whole product in one picture

```mermaid
flowchart LR
    subgraph SOURCES ["Microsoft data sources<br/>(read-only API)"]
        S1[Defender for Endpoint<br/>devices, vulnerabilities]
        S2[Defender Exposure Graph<br/>nodes + edges]
        S3[Entra ID<br/>users, SPNs, roles]
        S4[Azure Resource Graph<br/>resources + tags]
        S5[Optional: ServiceNow CMDB CSV]
    end
    subgraph PROFILE ["1️⃣ Asset profiling"]
        P1[Collect → Classify → Tier 0–3<br/>per asset, with proofs]
    end
    subgraph RA ["2️⃣ Risk Analysis"]
        R1[134 attacker-centric KQL reports<br/>across Endpoint, Identity, Azure]
    end
    subgraph OUT ["3️⃣ Outputs"]
        O1[📧 Excel + AI summary email]
        O2[📊 Power BI / Workbook]
        O3[🗃️ Log Analytics tables]
        O4[📦 JSON to UNC / blob]
    end
    SOURCES --> PROFILE --> RA --> OUT
    style SOURCES fill:#e8f4fd,stroke:#2a6592
    style PROFILE fill:#fff4e6,stroke:#a86a00
    style RA fill:#ffe6f0,stroke:#a8005c
    style OUT fill:#e8ffe8,stroke:#1a7a1a
```

> 🎯 **The headline**: SecurityInsight **never writes back** to your tenant. It reads, scores, and reports. No agent, no tag prep, no schema changes to your existing assets.

Defender will happily tell you about every vulnerability, misconfiguration, and exposure in your environment. What it won't tell you is which one an attacker would reach for first. **That's the prioritization gap — and it's where most security teams lose the battle.**

**SecurityInsight** is a free, community-built add-on to Microsoft Defender that applies a tier-based risk scoring model designed to think like a hacker and act like a defender. Every finding across Endpoint, Azure, and Identity is evaluated on four dimensions:

- the **security consequence** of the missing control,
- the **criticality tier** (0–3) of the affected asset,
- the **risk factors** that amplify exposure (Internet Exposure, Verified Secret, Critical Resource, Lateral Movement, Sensitive Data, LegacyEndOfSupport, ExploitSignals),
- and a **customizable Risk Index** that lets you adapt the model to your organization.

The solution is built on **Microsoft Defender ExposureGraph**, which gives it the contextual view attackers already have: what runs where, what's connected to what, which device hosts a domain controller, which VM has a managed identity with high-privilege access. SecurityInsight uses ExposureGraph to detect roles and relationships across endpoints and Azure resources and tag them automatically — without depending on someone remembering to label them.

On top of that, the solution ships with a detailed classification framework — an initial tier definition library already mapped across identity, endpoint, and cloud — and a large set of ExposureGraph-powered detection and tagging queries for Azure and endpoints that help you classify resources in your own environment quickly. You know your estate better than anyone; the queries give you a running start. Everything is continuously updated and fully customizable, so you can extend or replace any detection with your own as your environment changes.

A core focus is the **Identity collection** — users, service principals, and managed identities. Rather than relying on admins to tag accounts as "privileged" (a process that is always out of date), the model derives tier level automatically from the actual effective permissions each identity holds across AD, Entra ID roles, Microsoft Graph / API application permissions, and Azure RBAC. When Microsoft introduces a new role — as they do constantly — AI evaluates the permissions it grants and slots it into the right tier without human intervention.

#### What you'll get from this document

- Why "sort by severity, fix the biggest pile first" is the wrong instinct
- How consequence, criticality, risk factors, and a customizable Risk Index combine into one score
- How Tier 0–3 prioritization works across Endpoint, Azure, and Identity
- How ExposureGraph drives automatic role and resource detection
- How the built-in classification framework and tagging query library accelerate rollout
- How to classify user, SPN, and managed identity criticality from permissions — not tags
- How AI-driven classification keeps pace with Microsoft's ever-expanding role catalog

What this gives you is a concrete, reproducible framework — free and community-maintained — and a repeatable way to answer *"what should we fix first?"* with confidence.

> **Risk Score = Consequence (severity) × Probability (criticality + risk factors)**

The output is a ranked list — not 4,000 recommendations, but the small set of fixes that meaningfully reduce attacker dwell-time, lateral movement, and tenant takeover risk. Same Defender data, different framing: **attacker-centric instead of tool-centric.**

> [!TIP]
> **Talk track for execs**: SecurityInsight tells your CISO *"if we patch these 12 things this week, we cut the realistic blast radius of a successful phishing attack by 60%."* It does NOT add another portal — it consumes your existing Defender + Entra + Azure data via API.

<a id="outputs"></a>

### Outputs

The same ranked dataset is fan-out to multiple sinks so every stakeholder gets it in their preferred shape — ops in Excel, SOC in KQL, execs in Power BI, automation in JSON.

| Output | Purpose | Status |
|---|---|---|
| **Excel spreadsheet via email** | Operator-friendly XLSX of ranked findings, optionally with an AI-generated exec summary as the first sheet. Sent per run to configurable distribution lists (summary / detailed, per-recipient). | **Available** |
| **Log Analytics custom tables** (`SI_RiskAnalysis_Summary_CL`, `SI_RiskAnalysis_Detailed_CL`, `SI_IdentityAssets_CL`) | Durable time-series store for Kusto queries, Azure Monitor alerts, cross-run trending, compliance diffs. Every row carries a deterministic `TraceID` + `CollectionTime` so findings are stable across runs. | **Available** |
| **JSON upload to UNC share** | Automatic publish of each run's Summary JSON to a `\\server\share\...` path. Drop-in feed for on-prem BI / file-based integrations. | **Available** |
| **JSON upload to Azure Storage blob** | Automatic publish to `https://<acct>.blob.core.windows.net/<container>/`. Container auto-created + RBAC granted; ideal for cross-tenant reporting or Logic Apps / Power Automate pickup. | **Available** |
| **Power BI management dashboard** | `.pbix` pushed into the customer's Power BI tenant via REST API. Trend line, stacked domain chart, top-N, stale findings, velocity. Per-run dataset refresh via `$global:SendToPowerBI`. See [§ 3.5](#pre-requisite-configuration) Step 4 + [`DOCS/PowerBI-Prerequisites.md`](DOCS/PowerBI-Prerequisites.md). | **Beta** |
| **Azure Workbooks** | Native Azure Monitor workbook over `SI_RiskAnalysis_*_CL` + `SI_IdentityAssets_CL` — 8 pills (time range, latest-run toggle, domain, severity, tier, subcategory, search, Top-N) + KPI tiles + trend / domain / tier charts + velocity + Top-N + stale + identity inventory. Import from `TOOLS/AzureWorkbook/SecurityInsight-RiskAnalysis.workbook.json` via Portal → Azure Monitor → Workbooks → Advanced Editor; full guide in [`DOCS/AzureWorkbook-Import.md`](DOCS/AzureWorkbook-Import.md). | **Available** |

<a id="use-cases"></a>

### Use-cases

Real-world patterns customers run this against. Every one of them is cheap to light up because the data is already in LA with stable identifiers (`TraceID` + `CollectionTime`):

| Use-case | How |
|---|---|
| **Daily Security Prioritization Meetings — top risks** | Run RiskAnalysis on a 4×/day cron; agenda = the Top-25 tile in Power BI / Workbook / the XLSX email. No more "what do we focus on this week" arguments. |
| **ServiceNow ticket lifecycle (open / close)** | SOC subscribes to `SI_RiskAnalysis_Summary_CL`. `TraceID` (deterministic SHA-256 hash of `TraceName`) is the external correlation key — open on first appearance, auto-close when the `TraceID` disappears from the latest `CollectionTime`. |
| **Alerting on significant changes** | Azure Monitor alerts on Kusto: e.g. *"open critical findings jumped 30% vs last run"* or *"a new Tier-0 asset appeared in the stale list"*. Paged to the on-call channel, not buried in a report. |
| **Management reporting** | Execs open Power BI / Workbook → trend of total risk score, closed tickets, velocity of fix, domain breakdown. The numbers do the talking — no narration required. |
| **Compliance reporting** | Two `CollectionTime` snapshots of `SI_IdentityAssets_CL` diffed in Kusto → *what permissions changed?* Answers audit questions about access drift between two fixed dates. |
| **Baseline new security + Just-In-Time delegations** | First-time scan establishes the baseline tier for every identity + resource. Anything spikier on a later run is JIT-flagged for review. |
| **Disable / clean up legacy identity assets** | `SI_IdentityAssets_CL | where IsStale == true and ObjectType in ('ServicePrincipal','ManagedIdentity')` surfaces orphan / unused SPNs + MIs for bulk deprovisioning. |
| **Detect Shadow IT delegations** | Cross-tenant SPNs, unverified publishers, high-permission grants flagged on first appearance in `SI_IdentityAssets_CL` — catches delegations business units stood up without IT's knowledge. |

<a id="sample-output"></a>

### Sample output

#### Asset profiling — Identity (find users with no MFA registered)

![Identity asset profile — find users with no MFA registered](./docs/screenshots/asset-profiling-identity-find-no-mfa-registered.png)

#### Asset profiling — Endpoint (Tier 0 Domain Controller with CMDB enrichment)

![Endpoint asset profile — Tier 0 DC with CMDB join](./docs/screenshots/asset-profiling-endpoint-tier0-dc-cmdb.png)

#### Asset profiling — Azure (resource criticality inherited from parent subscription)

![Azure asset profile — tier inheritance from parent](./docs/screenshots/asset-profiling-azure-tier-parent.png)

#### Asset profiling — Identity (top-matches drive tier decision)

![Identity tier decision — top-matches breakdown](./docs/screenshots/asset-profiling-identity-topmatches-tier-decission.png)

#### Asset profiling — Identity (API-permission-driven tier)

![Identity tier — API permissions drive tier verdict](./docs/screenshots/asset-profiling-identity-api-permissions.png)

#### Sample reports + AI exec-summary email

| File | Link |
|---|---|
| Sample Summary report (XLSX) | [Sample - RiskAnalysis_Summary_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/data/_samples/Sample%20-%20RiskAnalysis_Summary_Bucket.xlsx) |
| Sample Detailed report (XLSX) | [Sample - RiskAnalysis_Detailed_Bucket.xlsx](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/data/_samples/Sample%20-%20RiskAnalysis_Detailed_Bucket.xlsx) |
| Sample Summary email (PDF, with AI exec summary) | [Sample mail - Summary report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Summary%20report%20with%20AI%20summary.pdf) |
| Sample Detailed email (PDF, with AI exec summary) | [Sample mail - Detailed report with AI summary.pdf](https://github.com/KnudsenMorten/SecurityInsight/blob/main/data/_samples/Sample%20mail%20-%20Detailed%20report%20with%20AI%20summary.pdf) |

---

<a id="2-understanding-the-framework"></a><a id="understanding-the-framework"></a>
<a id="2-understanding-the-framework"></a><a id="understanding-the-framework"></a>
## 🧠 2. Understanding the Framework

### 2.1 Why a graph, not a list

[⤴ Back to top](#top)

**Defenders typically think in lists** — devices, users, vulnerabilities, recommendations. Lists are good for inventory and reporting. They are useless for prioritization, because they hide *how systems connect to each other.*

**Attackers think in relationships.** A typical compromise rarely targets the most critical system directly:

```mermaid
flowchart LR
    A[🧑 End-user<br/>device<br/><i>phishing</i>] -->|lateral<br/>move| B[🖥️ Application<br/>server]
    B -->|service<br/>account abuse| C[🔑 Service<br/>account]
    C -->|credential<br/>theft / DCSync| D[🏛️ Domain<br/>Controller]
    style A fill:#e8f4fd,stroke:#2a6592
    style B fill:#fff4e1,stroke:#b07a00
    style C fill:#fff0f0,stroke:#b03030
    style D fill:#ffd6d6,stroke:#8b0000
```

The path goes through 4 systems. Three of them look *low-risk* in isolation. Their relationships are what makes the path catastrophic. SecurityInsight uses **Microsoft Defender Exposure Graph** + **Azure Resource Graph** to score recommendations the way an attacker would weigh them: *can this finding put me one step closer to a Tier-0 asset?*

> [!NOTE]
> The technical underpinning is `ExposureGraphNodes` + `ExposureGraphEdges` (Defender) and Azure Resource Graph KQL — same data your SOC already has, framed as a graph instead of a flat table.

<a id="22-risk-score-model"></a><a id="risk-score-model"></a>
### 2.2 Risk Score model

[⤴ Back to top](#top)

Two dimensions, one formula:

> **Risk Score = Consequence × Probability**

```mermaid
flowchart LR
    SEV[📛 Severity<br/>from Defender] --> CONS[Consequence Score<br/>typically 1–5<br/>customizable]
    CRIT[🏷️ Criticality tier<br/>from Tagging] --> PROB[Probability Score<br/>typically 1–5<br/>customizable]
    RF[⚡ Risk factors<br/>internet-exposed,<br/>public exploit,<br/>active-exploitation,<br/>lateral-move path, ...] -->|+1 each| PROB
    CONS --> MULT[× ]
    PROB --> MULT
    MULT --> SCORE[🎯 Risk Score<br/>Consequence × Probability<br/>unbounded]
    style SCORE fill:#e8ffe8,stroke:#1a7a1a,stroke-width:2px
```

| Dimension | Where it comes from |
|---|---|
| **Consequence Score** | Defender's `Severity` rating of the recommendation (Very High → Low). Reflects *how bad it is if this gets exploited.* |
| **Probability Score** | The asset's **criticality tier** (Tier 0–3) modulated by **risk factors** (see [§ 2.3](#risk-factors)). Reflects *how likely it is to actually be exploited on THIS asset, in THIS environment.* |

Both scores are positive integers from the **Risk Index CSV** ([§ 2.4](#risk-index-customizable-scoring)) — a fully customizable mapping that organizations tune to their own risk appetite. The shipped CSV uses 1–5 for each dimension (so scores run 1–25), but there's **no hardcoded ceiling** — customers who want finer-grained ranking can bump the scale to 1–10 or beyond and the product `Consequence × Probability` follows directly.

**Worked example**:

```
Finding          : "Endpoint missing critical CVE patch"
Severity         : Very High
Consequence      : 4   (mapped from "Very High" in the Risk Index)
Asset            : An internet-facing web server tagged "Tier 1 (High)"
Criticality base : 3   (Tier 1 base score from the Risk Index)
Risk factor +1   : because the asset has the "InternetExposed" tag → Probability = 4
                                                                  ─────────
Risk Score = 4 × 4 = 16  →  ranks above a Tier-3 internal-only finding
```

<a id="23-risk-factors"></a><a id="risk-factors"></a>
### 2.3 Risk Factors

[⤴ Back to top](#top)

Probability is bumped up by **+1 per matching risk factor**. Each represents a real-world attribute that materially raises the chance of exploitation:

| Risk factor | Why it bumps probability |
|---|---|
| **Active exploitation** | The vulnerability is being weaponized in the wild today. |
| **Public exploit code** | Proof-of-concept is freely available. |
| **Internet exposure** | The asset is reachable from outside your perimeter. |
| **Legacy / unsupported** | No security updates available. |
| **Contains verified secret** | A real credential is sitting in the asset (Defender Secret Scanning hit). |
| **Critical resource** | Defender flags the asset as foundational to your tenant. |
| **Lateral movement** | The asset sits on a known attack path. |
| **Sensitive data** | The asset stores classified, PII, or regulated content. |

Each factor contributes +1 to the Probability score, capped per the Risk Index.

<details>
<summary>📌 <b>Future risk factors under consideration</b></summary>

- **Large attack surface** — many open services / APIs / ports
- **Third-party exposure** — partner / vendor reach
- **Shared infrastructure** — multi-tenant / multi-team blast radius
- **Weak network segmentation** — flat L2 / VLAN sprawl
- **Credential exposure risk** — shared accounts, weak MFA
- **Remote access enabled** — VPN / RDP / SSH / management UIs

PRs welcome to extend the engine with these — the scoring math stays the same, only the bump count changes.
</details>

<a id="24-risk-index-customizable-scoring"></a><a id="risk-index-customizable-scoring"></a>
### 2.4 Risk Index (customizable scoring)

[⤴ Back to top](#top)

The mapping `Severity → Consequence` and `Criticality → Probability` lives in **`SecurityInsight_RiskIndex.csv`** ([download](https://github.com/KnudsenMorten/SecurityInsight/raw/refs/heads/main/SecurityInsight_RiskIndex.csv)). Customers edit this file to reflect their own risk appetite — the engine reads it on every run.

| SecuritySeverity | Consequence | CriticalityTierLevel | Probability | Comments |
|---|---|---|---|---|
| Very High | 4 | Critical (tier 0) | 4 | Top of the matrix |
| Very High | 4 | High (tier 1) | 3 | |
| High | 3 | Critical (tier 0) | 4 | |
| Medium-High | 2 | Critical (tier 0) | 4 | |
| Low | 1 | Low (tier 3) | 1 | Bottom of the matrix |

Want a different scoring matrix for a regulated business unit? Edit the CSV. Want to penalize Tier-0 findings more aggressively? Bump the Probability column for Tier-0 rows. Want certain `ConfigurationId`s to score harder regardless of severity? Add a row with that exact ConfigurationId — it overrides the generic mapping.

<a id="25-outputs-at-a-glance"></a><a id="outputs-at-a-glance"></a>
### 2.5 Outputs at a glance

[⤴ Back to top](#top)

Every Risk Analysis run produces all of these from a single in-memory dataset (no double work):

| Output | Default | Toggle |
|---|---|---|
| 📗 Excel (.xlsx) | always | — |
| 📄 JSON sibling (.json) | on | `$global:WriteJsonOutput` |
| 📊 Log Analytics ingest (2 tables: `SI_RiskAnalysis_Summary_CL` / `_Detailed_CL`) | off | `$global:SendToLogAnalytics` |
| ☁️ Upload to UNC share OR Azure Storage | off | `$global:ExportDestination` |
| 📧 Email with HTML body + .xlsx attachment | off | `$global:SendMail` (community) / `$global:Mail_*_SendMail` (internal) |
| 🤖 Azure OpenAI executive summary embedded in Excel + email | off | `$global:BuildSummaryByAI` |

> [!IMPORTANT]
> Once the data is in Log Analytics it is queryable from Sentinel, Defender XDR, Power BI, Logic Apps, Workbooks, and Security Copilot. That's the long-term home — the .xlsx and email are convenience outputs.

---

<a id="3-how-to-implement-quick-start"></a><a id="how-to-implement-quick-start"></a>

[⤴ Back to top](#top)

<a id="41-severity-definitions"></a><a id="severity-definitions"></a>
<a id="3-supported-inputs-enrichment-outputs"></a><a id="supported-inputs-enrichment-outputs"></a>
## 🔌 3. What's supported — Inputs, Enrichment, Outputs

[⤴ Back to top](#top)

Before you set up, here's the data SecurityInsight reads (Inputs), what it joins with (Enrichment), and where it ships the results (Outputs). Everything is opt-in — start with the minimum, layer on the rest.

> 📚 **Deep-dive references** (auto-generated from source-of-truth files; permanent docs maintained alongside the engine):
> - [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — overall solution architecture: stage pipeline, asset-profile flow, RA execution model
> - [`docs/PROVIDER_CONTRACT.md`](./docs/PROVIDER_CONTRACT.md) — provider plug-in contract; how to write your own
> - [`docs/asset-profiling-schema.md`](./docs/asset-profiling-schema.md) — every Profile-table column with type, source, source-path, written-by-stage, read-by-stages
> - [`docs/risk-analysis-detection.md`](./docs/risk-analysis-detection.md) — every Risk Analysis report with purpose, source tables, severity / tier scope, output columns, KQL
> - [`docs/QUERIES-REFERENCE.md`](./docs/QUERIES-REFERENCE.md) — YAML schema reference for `RiskAnalysis_Queries_Locked.yaml` (every field the engine reads, with line refs to `Invoke-RiskAnalysis.ps1`); use when authoring `_Custom.yaml` overrides
> - [`docs/RISKSCORE-REFERENCE.md`](./docs/RISKSCORE-REFERENCE.md) — JSON schema reference for `riskscore_weighted.schema.custom.json` (per-report weight overrides)
> - [`docs/Operations.md`](./docs/Operations.md) — day-2 operations: monitoring, run-health KQL, cadence tuning, troubleshooting
> - [`docs/CMDB-customer-drop.md`](./docs/CMDB-customer-drop.md) — ServiceNow CMDB CSV format walk-through with column-by-column reference

```mermaid
flowchart LR
    subgraph IN ["🔵 Inputs (read-only API)"]
        I1[Defender for Endpoint]
        I2[Defender Exposure Graph]
        I3[Entra ID + Graph]
        I4[Azure Resource Graph]
        I5[Sentinel SigninLogs<br/>+ AADNonInteractive]
        I6[Defender Vulnerabilities KB]
    end
    subgraph ENRICH ["🟡 Enrichment (optional)"]
        E1[ServiceNow CMDB CSV]
        E2[Azure OpenAI<br/>(role/permission tiering)]
        E3[Customer .custom.yaml<br/>(per-rule overrides + adds)]
        E4[Shodan<br/>(public-IP exposure)]
    end
    subgraph OUT ["🟢 Outputs (sinks — pick any combo)"]
        O1[Excel + email]
        O2[Log Analytics tables]
        O3[JSON sibling]
        O4[Azure blob upload]
        O5[UNC share upload]
        O6[Power BI dataset refresh]
        O7[Azure Workbook]
    end
    IN --> CORE[SecurityInsight engines]
    ENRICH --> CORE
    CORE --> OUT
    style IN fill:#e8f4fd,stroke:#2a6592
    style ENRICH fill:#fff4e6,stroke:#a86a00
    style CORE fill:#ffe6f0,stroke:#a8005c
    style OUT fill:#e8ffe8,stroke:#1a7a1a
```

<a id="31-inputs"></a>
### 3.1 Inputs — supported data providers

| Provider | What it gives us | Engine that reads it | Required? |
|---|---|---|---|
| **Microsoft Defender for Endpoint** (XDR + advanced hunting) | Devices, vulnerabilities, secure-config posture | `endpoint`, `risk-analysis` | ✅ Yes |
| **Microsoft Defender Exposure Graph** (`ExposureGraphNodes`, `ExposureGraphEdges`) | Asset graph: nodes (devices/users/azure resources), edges (relationships, attack paths) | `endpoint`, `azure`, `identity`, `risk-analysis` | ✅ Yes |
| **Entra ID + Microsoft Graph** | Users, service principals, groups, role assignments, app permissions, MFA registration | `identity`, `risk-analysis` | ✅ Yes |
| **Azure Resource Graph (ARG)** | Subscriptions, resource groups, every Azure resource + tags + properties | `azure`, `risk-analysis` | ✅ Yes |
| **Sentinel `SigninLogs` + `AADNonInteractiveUserSignInLogs`** (Log Analytics) | Per-signin events: location, device, risk, conditional access | `risk-analysis` (Identity reports) | ⚠️ Required if you want sign-in reports — needs Entra diagnostic settings → LA |
| **Defender Vulnerabilities KB** (`DeviceTvmSecureConfigurationAssessmentKB`) | CVE descriptions, MITRE ATT&CK mapping, compliance benchmarks (CIS / NIST / PCI) | `risk-analysis` (Device_Recommendations) | ✅ Yes (auto from MDE) |
| **Shodan API** (optional) | Public-IP exposure: open ports, CVEs on internet-facing assets | `publicip` | Optional (Tier 0/1 only) |
| **Provider connectors** (`asset-profiling-providers/<provider>/`) | Pluggable. Today: `entra` (built-in), `servicenow-cmdb` (CSV pull) | All asset-profiling engines | Optional |

> 🔒 **All inputs are read-only.** SecurityInsight never writes back to MDE / Entra / ARM during a collection run. The optional `CriticalAssetTagging` engine ships separately for customers who want active tag writes.

<a id="32-enrichment"></a>
### 3.2 Enrichment — joining external context

| Enrichment | What it does | Where you configure |
|---|---|---|
| **ServiceNow CMDB CSV** | Folds `cmdbId`, `cmdbName`, `cmdbCriticality` (`Critical`/`Important`/`Standard`), `cmdbDataSensitivity` (`Public`/`Internal`/`Confidential`/`Restricted`) onto every asset row at the Reconcile stage. Drives `RiskFactor_Consequence_Detailed` tokens (`BusinessCriticalAsset`, `RestrictedDataAccess`). | `asset-profiling-providers/servicenow-cmdb/CMDB.csv` (drop your file; gitignored) — see `sample/CMDB.csv` for column shape |
| **Azure OpenAI** (role/permission tier classification) | When a Microsoft role / permission isn't in the locked tier catalog, AI evaluates the permissions it grants and slots it into Tier 0–3. Off by default; opt in via `$global:SI_EnableAI = $true`. | Step 4 of bootstrap — `Validate-SIOpenAI.ps1` |
| **Custom asset-profiling rules** (`*.custom.yaml`) | Override or add to the 559 locked enrichment rules. Customer wins on conflict (merge by `id`). | Drop `<RuleName>.custom.yaml` next to the matching `<RuleName>.locked.yaml` in `asset-profiling-enrichment/<domain>/` |
| **Custom RA report exclusions** (`*.exclude.custom.json`) | Per-report exclusions (e.g. "exclude these ConfigurationIds from `Device_Recommendations_Summary` because we accept this risk"). | `risk-analysis-detection/<ReportName>.exclude.custom.json` |
| **Custom Risk Index** (`riskscore_weighted.schema.custom.json`) | Customer-tunable scoring matrix (Severity × CriticalityTier × per-engine multipliers). | `risk-analysis-detection/riskscore_weighted.schema.custom.json` (copy from `*.sample.json`) |
| **Custom asset-profile schemas** (`*.schema.custom.json`) | Add tenant-specific columns to a Profile_CL table. | `asset-profiling-schema/<engine>.schema.custom.json` (copy from `*.sample.json`) |

<a id="33-outputs"></a>
### 3.3 Outputs — supported sinks (pick any combo)

| Sink | Purpose | Toggle | Status |
|---|---|---|---|
| **📧 Excel + AI summary email** | Operator-friendly XLSX of ranked findings (optional AI exec summary as first sheet). Per-template recipients via `Mail_<ReportName>_To` in YAML. | `$global:Report_SendMail = $true` + `$global:Report_To = @('a@b.com')` | ✅ Available |
| **🗃️ Log Analytics custom tables** | Durable time-series store. Tables: `SI_RiskAnalysis_Summary_CL`, `SI_RiskAnalysis_Detailed_CL`, `SI_*_Profile_CL`, `SI_RunHealth_CL`. Auto-created via DCR. | `$global:SendToLogAnalytics = $true` | ✅ Available |
| **📦 JSON sibling** | One-line-per-row JSON next to every XLSX. Drop-in feed for downstream tools. | `$global:WriteJsonOutput = $true` (default ON) | ✅ Available |
| **☁️ Azure blob upload** | Auto-publish each run's xlsx + json to a blob container. Backup-then-overwrite semantics so re-runs never lose data. | `$global:RiskAnalysis_ExportDestination` set to `https://<acct>.blob.core.windows.net/<container>/` | ✅ Available |
| **📁 UNC share upload** | Same as blob, to `\\server\share\path`. Caller's Windows identity needs share write. | `$global:RiskAnalysis_ExportDestination` set to UNC path | ✅ Available |
| **📊 Power BI dataset refresh** | Triggers a refresh of the Power BI dataset deployed via `Deploy-SIPowerBI.ps1` after each run. | `$global:SendToPowerBI = $true` | ✅ Available |
| **📓 Azure Monitor Workbook** | Pre-built Workbook JSON for visual exploration. One-time import, queries `SI_*_CL` tables. | Import `data/workbooks/SecurityInsight.json` | ✅ Available |
| **🔔 Run-health KQL alert** | Alert when a Start row has no matching End row in 1 hour (= crashed run). | KQL on `SI_RunHealth_CL` (sample query in `docs/Operations.md`) | ✅ Available |

<a id="34-setup-file-checklist"></a>
### 3.4 Setup file checklist — which sample files to copy

For a fresh install, you'll copy these sample files to their `.custom.` siblings (gitignored — your copy is yours, never overwritten by upgrades).

#### 🟢 Required (everyone copies these)

| Step | Copy from | To | Edit |
|---|---|---|---|
| 1 | `config/SecurityInsight.custom.sample.ps1` | `config/SecurityInsight.custom.ps1` | SPN credentials, Workspace name, mail-relay settings |
| 2 | `launcher/<engine>/LauncherConfig.custom.sample.ps1` | `launcher/<engine>/LauncherConfig.custom.ps1` | Per-engine overrides (often empty if defaults work) |

#### 🟡 Optional (copy only if you use the feature)

| Feature | Copy from | To | Edit |
|---|---|---|---|
| **ServiceNow CMDB enrichment** | `asset-profiling-providers/servicenow-cmdb/sample/CMDB.csv` | `asset-profiling-providers/servicenow-cmdb/CMDB.csv` | Drop your CMDB extract (columns: `id,name,criticality,dataSensitivity,...`) |
| **Custom Risk Index weights** | `risk-analysis-detection/riskscore_weighted.schema.custom.sample.json` | `risk-analysis-detection/riskscore_weighted.schema.custom.json` | Adjust per-domain weight multipliers |
| **Custom enrichment rule** (e.g. add a Tier 0 marker for your bastion hosts) | `asset-profiling-enrichment/endpoint/AssetProfileByApplicationServiceDetection/<App>.custom.sample.yaml` | Same name, drop `.sample.` segment | Set `id`, `match` criteria, `tier`, `tags` |
| **Custom Azure-tag rule** | `asset-profiling-enrichment/azure/AssetProfileByTags.custom.sample.yaml` | `asset-profiling-enrichment/azure/AssetProfileByTags.custom.yaml` | Map your Azure-tag keys/values to tier verdicts |
| **Per-report exclusion** | (no sample — create from scratch) | `risk-analysis-detection/<ReportName>.exclude.custom.json` | Array of `{ConfigurationId, AssetId, reason}` |
| **Public-IP test list** | `asset-profiling-schema/public-ip.schema.custom.sample.json` | `asset-profiling-schema/public-ip.schema.custom.json` | Add IPs you want Shodan-scanned beyond the auto-discovered Tier 0/1 set |

#### 🔵 Generated / managed by bootstrap (don't hand-edit)

- `staging/asset-profiling/identity.tier.classification.json` — AI verdict catalog (regenerated on AI re-classification)
- `risk-analysis-detection/OUTPUT/AutoBucketCache.json` — per-report bucket-count cache
- `logs/<engine>_<flavor>_<timestamp>.log` — per-run transcripts

> 💡 **Naming convention rule of thumb**: any file with `.sample.` in the name is documentation. Drop `.sample.` to make it active. Files ending in `.custom.<ext>` (no `.sample.`) are gitignored and yours to keep across upgrades.

<a id="35-ten-step-newbie-setup"></a>
### 3.5 Ten-step newbie setup — first run, end to end

Never seen SecurityInsight before? Follow these 10 steps in order. Estimated time: **45–60 min** the first time (most of it is waiting for Azure resource provisioning).

> ✅ **Before you start**
> - Windows machine with **PowerShell 7+** (`pwsh`) installed
> - **Az CLI** (`az --version` works) and **Azure PowerShell** (`Install-Module Az`)
> - **Global Administrator** OR **Privileged Role Administrator** in the target Entra tenant (one-time, for the bootstrap)
> - **Owner** at the tenant-root management group (one-time, for the bootstrap RBAC)
> - An **Azure subscription** to host the Storage Account + Container Apps Job + Log Analytics workspace

#### Step 1 — Get the code

```powershell
# Pick ONE:

# Option A: clone the public preview branch
git clone -b preview https://github.com/KnudsenMorten/SecurityInsight.git C:\SecurityInsight

# Option B: download the zip
Invoke-WebRequest -Uri 'https://github.com/KnudsenMorten/SecurityInsight/archive/refs/heads/preview.zip' -OutFile $env:TEMP\si.zip
Expand-Archive $env:TEMP\si.zip -DestinationPath C:\SecurityInsight -Force

cd C:\SecurityInsight
```

#### Step 2 — Install required PowerShell modules

```powershell
Install-Module Az, AutomateITPS, AutomateITPS.AD, AutomateITPS.Compat, `
                AzLogDcrIngestPS, MicrosoftGraphPS, ImportExcel `
                -Scope CurrentUser -Force -AllowClobber
```

> ℹ️ The `community-vm` launcher flavour expects `FUNCTIONS\AutomateITPS*` to be inlined under your install root. If you cloned from the public preview branch, those modules are already bundled at `FUNCTIONS\`. Otherwise run the install above.

#### Step 3 — Create your customer config (the ONLY file you must edit)

```powershell
# Folder lives at <install-root>\config\
Copy-Item .\config\SecurityInsight.custom.sample.ps1 .\config\SecurityInsight.custom.ps1
notepad .\config\SecurityInsight.custom.ps1
```

Edit and fill in:
- `$global:SI_SPN_AppId` / `$global:SI_SPN_Secret` / `$global:SI_SPN_TenantId` (you'll get these from Step 4)
- `$global:SI_WorkspaceName` (e.g. `log-securityinsight`)
- `$global:SI_DcrResourceGroup` (e.g. `rg-securityinsight`)
- `$global:SI_StorageAccount` (e.g. `stsecurityinsight001` — must be globally unique)
- `$global:SMTPFrom`, `$global:Report_To` (mail relay sender + recipients)

> 🔒 **`config\` is gitignored.** Your secrets stay yours. Releases never overwrite your customer file.

#### Step 4 — Bootstrap auth (creates SPN + permissions)

```powershell
.\Bootstrap-Auth.ps1
```

Interactively signs you in (browser pops up), creates an Entra app registration `sp-securityinsight` if missing, generates a client secret, and grants:
- Microsoft Graph: Defender + Entra read permissions
- Azure: `Reader` at tenant-root management group + `Tag Contributor` for the optional asset-tagging engine

The script prints a **ready-to-paste `$global:SI_SPN_*` block** at the end. Copy it into `config\SecurityInsight.custom.ps1` and save.

#### Step 5 — Bootstrap storage (Workspace + DCE + DCR + Storage Account)

```powershell
.\Bootstrap-Storage.ps1
```

Provisions in your subscription:
- A Log Analytics **workspace** (named per `$global:SI_WorkspaceName`)
- A **Data Collection Endpoint (DCE)** + **Data Collection Rules (DCRs)** for ingest
- A **Storage Account** for transient state (queue, blob, table)
- RBAC: `Storage Blob/Table/Queue Data Contributor` for the SPN

#### Step 6 — *(Optional)* Bootstrap container execution

```powershell
# Skip if you'll run on-VM only. Required for cloud-native scheduled runs.
.\Bootstrap-ContainerAppJob.ps1
```

Provisions:
- Azure Container Registry (`acrsecurityinsight`)
- Container Apps Environment (`cae-securityinsight`, Consumption profile = $0 idle)
- One Container Apps Job per engine (cron-scheduled)
- *(With `-UseKEDA`)*: queue-depth scaler for the heaviest collection engine

#### Step 7 — Copy launcher config for each engine you'll run

```powershell
# Identity asset-profiling
Copy-Item .\launcher\identity\LauncherConfig.custom.sample.ps1 .\launcher\identity\LauncherConfig.custom.ps1

# Endpoint asset-profiling
Copy-Item .\launcher\endpoint\LauncherConfig.custom.sample.ps1 .\launcher\endpoint\LauncherConfig.custom.ps1

# Azure asset-profiling
Copy-Item .\launcher\azure\LauncherConfig.custom.sample.ps1 .\launcher\azure\LauncherConfig.custom.ps1

# Risk Analysis
Copy-Item .\launcher\risk-analysis\LauncherConfig.custom.sample.ps1 .\launcher\risk-analysis\LauncherConfig.custom.ps1
```

Most defaults are fine — `LauncherConfig.custom.ps1` only needs edits when you want per-engine overrides (different mail recipients, different Workspace, etc.).

#### Step 8 — Run asset-profiling first (populates `SI_*_Profile_CL` tables)

```powershell
# Identity (most important — drives every Identity report)
.\launcher\identity\launcher.community-vm.ps1

# Endpoint (drives every Endpoint report)
.\launcher\endpoint\launcher.community-vm.ps1

# Azure (drives every Azure report)
.\launcher\azure\launcher.community-vm.ps1
```

Each launcher takes 5–15 min depending on tenant size. They populate `SI_Identity_Profile_CL`, `SI_Endpoint_Profile_CL`, and `SI_Azure_Profile_CL` in your Log Analytics workspace.

> 🔍 **Verify in LA**: open Azure Portal → your Log Analytics workspace → Logs, run `SI_Identity_Profile_CL | summarize count()`. Should show >0 rows.

#### Step 9 — Run Risk Analysis (the headline output)

```powershell
# Summary mode — aggregated rows, suitable for execs
.\launcher\risk-analysis\launcher.community-vm.ps1 -Summary

# Detailed mode — per-asset rows, suitable for ops triage
.\launcher\risk-analysis\launcher.community-vm.ps1 -Detailed
```

Each takes 15–30 min. The engine emits:
- `risk-analysis-detection\OUTPUT\RiskAnalysis_Summary.xlsx` + `.json`
- `risk-analysis-detection\OUTPUT\RiskAnalysis_Detailed.xlsx` + `.json`
- LA tables `SI_RiskAnalysis_Summary_CL` + `_Detailed_CL`
- *(If mail enabled)* email to `$global:Report_To` with the xlsx attached + AI exec summary

#### Step 10 — Verify outputs + iterate

| Check | Where | What to expect |
|---|---|---|
| **Excel** | `risk-analysis-detection\OUTPUT\` | Open `RiskAnalysis_Detailed.xlsx`. The **Details** sheet is sorted by `RiskScoreTotal_Weighted` desc — top rows are your highest-priority findings. |
| **Email** | Your inbox | Subject: `Security Insights \| Risk Analysis \| RiskAnalysis_Detailed`. Body has an AI exec summary; xlsx is attached. |
| **Log Analytics** | Azure Portal → Logs | `SI_RiskAnalysis_Detailed_CL \| where CollectionTime == toscalar(SI_RiskAnalysis_Detailed_CL \| summarize max(CollectionTime)) \| count` |
| **Run health** | LA | `SI_RunHealth_CL \| where Phase=='Start' \| join kind=leftanti (SI_RunHealth_CL \| where Phase=='End') on RunId, ShardIndex` — should be empty (any rows = crashed runs) |
| **Power BI** *(if enabled)* | `app.powerbi.com` | Dataset `SecurityInsight` refreshed; report `SecurityInsight Dashboard` shows top findings tile |

#### When something doesn't work

| Symptom | Likely cause | Fix |
|---|---|---|
| `Get-PlatformSecretKeyVault: secret '...' not found` | Pre-launch helper looks for an old KV secret name | Cosmetic; the run continues. Update LauncherConfig if persistent. |
| RA reports return 0 rows | Asset profiling hasn't been run yet | Run Step 8 launchers first |
| `Failed to resolve table 'SI_*_Profile_CL'` | DCR not provisioned for that table | Re-run `Bootstrap-Storage.ps1` |
| AI summary skipped | `BuildSummaryByAI` not enabled OR no Azure OpenAI configured | Set `$global:BuildSummaryByAI = $true` + run `setup\Validate-SIOpenAI.ps1` |
| Mail not sent | SMTP From address not verified at relay | Set `$global:SMTPFrom` to a verified-sender address (Brevo / SendGrid / Postmark / M365 reject mail with non-verified From) |

That's the full first-run loop. Once it works once, schedule the launchers (Windows Task Scheduler, or Container Apps Job cron) for daily / hourly / on-demand cadence.

---

## 🚀 4. How to Implement (Quick Start)

[⤴ Back to top](#top)

<a id="31-high-level-overview"></a><a id="high-level-overview"></a>
### 🗺️ 3.1 High-level overview

[⤴ Back to top](#top)

```mermaid
flowchart TD
    S1["1 · Get / Update SecurityInsight<br/><i>Setup-SecurityInsight (Github phase)_OnboardUpdate from GitHub</i>"] --> S2["2 · Bootstrap auth<br/><i>Bootstrap-Auth.ps1</i><br/>SPN + cert (default) or UAMI"]
    S2 --> S3["3 · Bootstrap LA + Storage<br/><i>Bootstrap-Storage.ps1</i><br/>Workspace + DCE + DCR + container"]
    S3 --> S4["4 · <i>(optional)</i> Bootstrap container<br/><i>Bootstrap-ContainerAppJob.ps1</i><br/>ACR + KEDA-scaled Job"]
    S4 --> S5["5 · Profile assets<br/><i>launcher/identity</i><br/><i>launcher/endpoint</i><br/><i>launcher/azure</i>"]
    S5 --> S6["6 · <i>(optional)</i> Scan public IPs<br/><i>launcher/publicip</i><br/>(Shodan)"]
    S6 --> S7["7 · Run Risk Analysis<br/><i>launcher/risk-analysis</i><br/>-Summary / -Detailed"]
    style S1 fill:#e8f4fd,stroke:#2a6592
    style S7 fill:#e8ffe8,stroke:#1a7a1a,stroke-width:2px
```

**Cadence.** Steps 2–4 are once-per-tenant setup (Bootstrap-Auth → Bootstrap-Storage → optional Bootstrap-ContainerAppJob — run in order, then forget about them). Step 1 re-runs whenever you want to pull a newer release; `config/SecurityInsight.custom.ps1` and `*.custom.yaml` files are preserved. Step 5 (asset profiling — identity + endpoint + azure) typically runs daily; tier-driven cadence lets Tier 0 refresh hourly while Tier 3 refreshes weekly. Step 6 (Shodan public-IP scan) runs daily for Tier 0/1 IPs. Step 7 (Risk Analysis Summary + Detailed) runs daily / weekly / on-demand. Container mode + KEDA queue-depth scaling auto-scales replicas based on the shard queue.

<a id="32-install-fresh-machine"></a><a id="install-fresh-machine"></a>
### 🧪 3.2 Try out a preview release

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

The `preview` channel tracks the HEAD of the `preview` branch — bleeding-edge features that haven't shipped in a tagged release. Use a **separate folder** from stable.

```powershell
$SI_InstallPath = 'C:\SCRIPTS\SecurityInsight-preview'
& (Join-Path $SI_InstallPath 'SCRIPTS\Setup-SecurityInsight.ps1 -Phase Github') -DestinationPath $SI_InstallPath -Channel preview
```

> [!NOTE]
> Preview = uncut, unrewindable. Bugs may exist that don't exist in `stable`. File issues at [KnudsenMorten/SecurityInsight](https://github.com/KnudsenMorten/SecurityInsight/issues). When a preview feature stabilizes it's cut to a new `stable` release — update via § 3.3.

</details>

<a id="35-pre-requisite-configuration"></a><a id="pre-requisite-configuration"></a>
### 🔧 3.3 Pre-requisite configuration

[⤴ Back to top](#top)

Before you can run any launcher, the solution needs to know **your** values — tenant / subscription IDs, SPN credentials, workspace names, mail recipients, OpenAI endpoint. You provide these through PowerShell config files next to each launcher.

<a id="config-file-model"></a>

#### 🧱 3.5.1 Config-file model — `.defaults.ps1` vs `.custom.ps1`

| Filename pattern | Who owns it | Gets overwritten on update? | When to edit |
|---|---|---|---|
| `*.defaults.ps1` | **Us** — shipped with the solution | **Yes** — replaced on every Step 1 update | **Never.** Treat as read-only. |
| `*.custom.ps1` | **You** — created from a `.sample.ps1` | **Never** — gitignored, preserved by Step 1 | **Yes.** This is the only file you ever edit. |

You'll see both names repeated at three scopes (tenant / solution / engine). That's the **5-layer config stack** — the launcher loads them in order, and each layer overrides the previous (closest wins):

```mermaid
flowchart TD
    L1["<b>Layer 1 — tenant scope</b><br/><i>platform-defaults.ps1</i><br/>SOLUTIONS/PlatformConfiguration/config/<br/><sub>(customer-owned; internal mode only)</sub>"]
    L2["<b>Layer 2 — solution baseline</b><br/><i>SecurityInsight.shared-defaults.ps1</i><br/>launcher/_lib/<br/><sub>(shipped by us — don't edit)</sub>"]
    L3["<b>Layer 3 — solution customer</b> ⭐<br/><i>SecurityInsight.custom.ps1</i><br/>config/<br/><sub>(customer-owned; covers every SI engine)</sub>"]
    L4["<b>Layer 4 — engine baseline</b><br/><i>LauncherConfig.defaults.ps1</i><br/>launcher/&lt;engine&gt;/<br/><sub>(shipped by us — don't edit)</sub>"]
    L5["<b>Layer 5 — engine customer</b> (closest wins)<br/><i>LauncherConfig.custom.ps1</i><br/>launcher/&lt;engine&gt;/<br/><sub>(customer-owned; per-engine override)</sub>"]
    L1 --> L2 --> L3 --> L4 --> L5
    style L2 fill:#f0f0f0,stroke:#888
    style L4 fill:#f0f0f0,stroke:#888
    style L3 fill:#e8ffe8,stroke:#1a7a1a,stroke-width:2px
    style L5 fill:#e8ffe8,stroke:#1a7a1a
    style L1 fill:#fff4e1,stroke:#b07a00
```

**Legend.** Grey = shipped by us (`.defaults.`, never edit). Green = customer files (`.custom.`, edit here). Orange = internal-mode tenant layer (absent in community-vm installs).

⭐ **Layer 3 (`config\SecurityInsight.custom.ps1`) is where 90% of customers put everything.** It's solution-wide — every SI engine picks it up automatically. You only drop down to Layer 5 if one specific engine needs a different value (e.g. a different mail recipient for Critical-only reports).

> **Example — community-vm customer configures once, runs 10 engines.**
> 1. Copy `config\SecurityInsight.custom.sample.ps1` → `SecurityInsight.custom.ps1` in the same folder.
> 2. Uncomment the SPN block, fill in `$global:SpnTenantId` / `SpnClientId` / `SpnClientSecret`.
> 3. Set `$global:MailTo = @('soc@contoso.com')`.
> 4. Done. RiskAnalysis, CriticalAssetTagging, IdentityAssets, Step 2 / 3 / 4 — all 10 engines inherit these values on their next run.

<a id="setup-configurator"></a>

#### ⭐ 3.5.2 Setup Configurator — GUI that writes your `.custom.ps1` files

The solution ships an **offline, single-file HTML tool** that generates the `SecurityInsight.custom.ps1` + per-engine `LauncherConfig.custom.ps1` files for you. Form fields + live preview + one-click copy-to-clipboard. Zero dependencies; all processing stays in your browser — no data leaves your machine.

```powershell
Start-Process .\TOOLS\SetupConfigurator\index.html
```

![Setup Configurator — offline HTML tool that generates every SecurityInsight .custom.ps1 with form fields + live preview + copy-to-clipboard](DOCS/Images/SetupConfigurator-tool.png)

Each tab corresponds to one launcher or the solution-wide `SecurityInsight.custom.ps1`. Re-use the 4 auth values (Tenant / ClientId / Secret / Subscription) across every tab and you're done in a minute. Prefer hand-editing? The `.sample.ps1` files next to each launcher are copy-paste templates — see the worked example above.

> [!TIP]
> **Internal (AF) / community-azure flavours don't need a customer config file at all** — they pull auth from the platform bootstrap (`Initialize-PlatformAutomationFramework`) or a Managed Identity + Key Vault. Only the **community-vm** flavour reads credentials from customer files. This whole section (layered config + Setup Configurator) is for community-vm operators.

<a id="solution-component-overview"></a>

#### 🧩 3.5.3 Solution component overview

Every SI component ships as its own launcher folder under `launcher/`. Two groups: **Steps** (once per tenant, during onboarding) and **Engines** (on a schedule after onboarding).

**Onboarding Steps — one-time, run in order:**

| Component | Purpose |
|---|---|
| **Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions** | Creates the Entra SPN, grants API permissions + Azure RBAC. Idempotent (re-run = validation pass). |
| **Validate-SILogAnalytics_OnboardValidate-SecurityInsight-LogAnalytics** | Provisions the Workspace + DCE + DCR + custom tables the engines ingest into. |
| **Validate-SIOpenAI_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure** *(opt.)* | Provisions PAYG Azure OpenAI + model deployment for the RiskAnalysis AI summary. |
| **Deploy-SIPowerBI_Deploy-SecurityInsight-PowerBI-Dashboard** *(opt.)* | Publishes the RiskAnalysis `.pbix` dashboard to the customer's Power BI tenant. |
| **Setup-SecurityInsight-CustomSecurityAttributes** | One-time provisioning of the Entra Custom Security Attribute schema used by the tagging pipeline. |
| **Build_Tier_Definitions_JSON_File** | Uses Azure OpenAI to classify Entra roles / Graph permissions / AD groups / Azure built-in roles into Tier 0–3. Re-run only when tier rules change. |

**Ingestion engines — run on a schedule:**

| Component | Purpose |
|---|---|
| **SecurityInsight_RiskAnalysis** | Main analyzer — ranked Excel + JSON + LA ingest + email + AI executive summary. |
| **IdentityAssetsCollectDefineTierIngestLog** | Iterates every Entra user / SPN / MI; ingests into `SI_IdentityAssets_CL`. |
| **CriticalAssetTagging** (+ `CriticalAssetTaggingMaintenance` + `CAT_FixConflictingTags`) | Auto-tags every device / Azure resource with its criticality tier (0–3). |

> [!NOTE]
> **`Build_Tier_Definitions_JSON_File` does not enumerate AD members.** The engine uses Azure OpenAI to tier the hardcoded `$BuiltInADGroups` list (Domain Admins, Enterprise Admins, DnsAdmins, Account Operators, …) **by name alone**, then writes `AD_BuiltInPermissionGroups_Tier0..3` into `data/SecurityInsight_IdentityTiering.json`. Actual group-membership analysis ("does user X have access to Domain Admins?") happens at query time inside `IdentityAssetsCollectDefineTierIngestLog` via the Exposure Graph — no RSAT, no on-prem AD PowerShell module, no domain-joined VM required. Works identically on cloud-only community VMs and hybrid/on-prem VMs.

**Unattended (hands-off) operation** — Steps 2-4 and every engine launcher support the same four auth methods, so a pipeline / scheduled task can run the whole chain with one identity. The launcher picks a method by **priority chain** (first row whose fields are populated wins, regardless of which config layer set them):

| # | Auth method | Set the following globals | Use when |
|---|---|---|---|
| 1 | Managed Identity | `$global:UseManagedIdentity = $true` + `$global:SpnTenantId` | Azure VM / Function / Logic App / Hybrid Runbook Worker |
| 2 | SPN + secret in Key Vault | `$global:SpnKeyVaultName`, `$global:SpnSecretName`, `$global:SpnTenantId`, `$global:SpnClientId` | Production VM with MI that has Key Vault Secrets User |
| 3 | SPN + certificate | `$global:SpnCertificateThumbprint`, `$global:SpnTenantId`, `$global:SpnClientId` | Production VM with cert in local store |
| 4 | SPN + plaintext secret | `$global:SpnClientSecret`, `$global:SpnTenantId`, `$global:SpnClientId` | Lab / testing only |

> [!IMPORTANT]
> **Mixing methods across layers — the higher-priority method wins.** If your tenant-level `platform-defaults.ps1` (Layer 1) defines `$global:SpnCertificateThumbprint` and your `SecurityInsight.custom.ps1` (Layer 3) adds `$global:SpnClientSecret`, **certificate wins** — it's higher in the chain. "Closer layer wins" applies at the *variable* level (Layer 3 overrides TenantId/ClientId/etc. if different), but the *method* is chosen by the priority table above.
> To force a lower-priority method, null out the higher-priority field in the closer layer:
> ```powershell
> # in SecurityInsight.custom.ps1 — force plaintext secret even though platform ships a cert
> $global:UseManagedIdentity       = $false
> $global:SpnKeyVaultName          = $null
> $global:SpnCertificateThumbprint = $null
> $global:SpnClientSecret          = '<your-secret>'
> ```

**Step 0** defaults to `Interactive` (browser sign-in by a human admin). To run it unattended, also set `$global:OnboardValidate_AuthMethod = 'SpnSecret'` (or `'SpnCertificate'` / `'ManagedIdentity'`). The SPN/MI needs **Privileged Role Administrator** (or **Global Administrator**) to create app registrations + grant admin consent.

**Step 4** accepts `-ValidateOnly` — turns it into a hands-off health check. No resources are created, but the engine still reports `CREATED` / `REUSED` / `MISSING` status per resource + exits non-zero if anything is missing. Good for monitoring that your Azure OpenAI deployment hasn't drifted.

---

<a id="354-defender-xdr-licensing--onboarding-requirements"></a><a id="defender-xdr-licensing"></a>
#### 🛡️ 3.5.4 Defender XDR licensing & onboarding requirements

[⤴ Back to top](#top)

The RiskAnalysis engine submits KQL queries through Microsoft Graph advanced hunting (`/security/runHuntingQuery`). That endpoint is a **federated view** over every Defender service the tenant has licensed + onboarded — and each Defender service exposes its own table family. **A query that references a table from a service the tenant doesn't have will fail with `Failed to resolve table or column expression named 'X'`** — there's no way around it; the data simply doesn't exist in that tenant.

**v2.1.198+** the engine recognises these errors as deterministic, **stops retrying immediately** (saves ~12s per failed report), and logs one clear classification line telling you which Defender service / SKU is missing. The outer report loop continues, so other reports still run.

**Table-family → service map** the engine uses to classify schema errors:

| Table prefix | Owner service | Required SKU |
|---|---|---|
| `Device*` (DeviceInfo, DeviceProcessEvents, DeviceLogonEvents, …) | **Microsoft Defender for Endpoint** EDR | **MDE Plan 2** / M365 E5 Security / M365 E5 |
| `DeviceTvm*` (TvmInfoGathering, TvmSecureConfigurationAssessment, TvmSoftwareInventory, TvmSoftwareVulnerabilities) | **Defender Vulnerability Management** | MDVM standalone add-on, **OR** MDE Plan 2 (bundled) |
| `Identity*` (IdentityInfo, IdentityLogonEvents, IdentityDirectoryEvents, IdentityQueryEvents) | **Defender for Identity** | MDI / EMS E5 / M365 E5 + sensor on DCs/AD FS/Entra Connect |
| `AADSignInEvents`, `EntraIdSignInEvents`, `EntraIdSpnSignInEvents`, `GraphAPIAuditEvents`, `IdentityAccountInfo` | **Microsoft Entra** | Entra ID P1/P2 with diagnostic-settings forwarding |
| `ExposureGraphNodes`, `ExposureGraphEdges` | **Defender Exposure Management (MDEM)** | M365 E5 Security / M365 E5 / standalone Exposure Management |
| `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `Message*`, `UrlClickEvents` | **Defender for Office 365 P2** | MDO P2 / M365 E5 / E5 Security / MDO P2 standalone |
| `CloudAppEvents`, `AppFileEvents` | **Defender for Cloud Apps** | MDA / M365 E5 / EMS E5 / MDA standalone |
| `Cloud(Audit\|Dns\|Process\|Storage)*` | **Defender for Cloud** | Workload protection plans for Servers / Storage / DNS |
| `AlertEvidence`, `AlertInfo`, `BehaviorEntities`, `BehaviorInfo` | **Defender XDR** (alert/behavior aggregation) | At least one Defender plan generating alerts |
| `*_CL` (e.g. `SI_IdentityAssets_CL`) | **Your Log Analytics workspace** | The matching SI ingestion engine has run + written rows; **the engine auto-bridges this case** (see § 3.10 / § 6.x) |

**The MDE Plan 1 vs Plan 2 trap** ⚠️ — the most subtle case, surfaced by a real customer onboarding in v2.1.198:

> The Defender portal **Devices Inventory** page (and Risk Level / Exposure Level columns) renders for both **MDE Plan 1**, **Defender for Business**, and **MDE Plan 2** customers — so seeing your devices listed there does NOT prove you have advanced-hunting access to the EDR `Device*` tables. Those tables are **MDE Plan 2 only**. If you've recently upgraded from MDE P1 / Defender for Business to MDE P2, the tables typically appear within **minutes to ~24 hours** while the tenant's advanced-hunting backend re-provisions.

**What you'll see in logs when a service is missing:**

```
[WARN] Table 'DeviceInfo' not present in this tenant's advanced hunting schema.
       Owned by Microsoft Defender for Endpoint (MDE Plan 2 / M365 E5 Security / M365 E5).
       Devices may already be onboarded for inventory + risk + exposure (Defender for Business /
       MDE Plan 1 also support those), but the EDR advanced-hunting schema (Device*, DeviceInfo,
       DeviceProcessEvents, DeviceLogonEvents, etc.) requires Plan 2. Newly upgraded tenants
       typically see the tables appear within minutes to ~24h while the backend re-provisions.
[WARN] Not retrying (deterministic schema failure -- retries cannot conjure a missing table).
```

**Recommendation:** before onboarding RiskAnalysis to a new tenant, use **Defender XDR portal → Hunting → Advanced hunting → Schema** to confirm the table groups you expect to query are present. If a group is missing, either provision the corresponding licence + onboard the service, OR exclude reports that depend on it via your `*_Custom.yaml` overrides (see § 5).

---

<a id="355-no-sentinel-routing-and-entra-diagnostics"></a><a id="no-sentinel-setup"></a>
#### 🛰️ 3.5.5 No Sentinel? Routing model + Entra diagnostic-settings setup

[⤴ Back to top](#top)

You don't need Microsoft Sentinel to run SecurityInsight. The engine adapts based on what you have. This section explains the **routing model** at a high level and walks you through the one piece of setup you DO need when Sentinel isn't in play: **forwarding Entra sign-in + audit logs to your Log Analytics workspace**.

##### Three routing modes (high-level)

When the RiskAnalysis engine submits a KQL query, it picks one of three paths automatically per query:

| Mode | When it fires | Where the query runs | Failure modes you might see |
|---|---|---|---|
| 🟢 **Pure-LA** | Query references ONLY `*_CL` tables (e.g. `SI_IdentityAssets_CL`) and any LA-side tables (`SigninLogs`, `AuditLogs`, `IdentityInfo` if mirrored, etc.) | Direct call to Log Analytics REST (`api.loganalytics.io`) via your existing SPN session. **No advanced-hunting round trip, no body cap, no nginx 413.** Result-set cap is LA's native ~64 MB / 500k rows. | Missing custom table → empty result. Missing LA-side Entra table → see "Entra diagnostic-settings" below. |
| 🟠 **Mixed** | Query joins `SI_IdentityAssets_CL` with a Defender XDR table (`DeviceInfo`, `IdentityInfo`, `ExposureGraph*`, `EmailEvents`, etc. — XDR-only data not in LA) | Engine fetches `SI_IdentityAssets_CL` from LA once, builds an inline `let SI_IdentityAssets_CL = datatable(...) [...]` block, prepends to the KQL, sends through Microsoft Graph advanced hunting (`/security/runHuntingQuery`). | nginx **413 Request Entity Too Large** on big tenants — the let-block payload exceeds advanced hunting's body cap (~1 MB). Recommendation: enable Sentinel data lake + table mirroring for `SI_IdentityAssets_CL` so the let-block becomes unnecessary, OR forward the relevant XDR data into LA so the query can run pure-LA. |
| 🔵 **Pure-XDR** | Query references ONLY Defender XDR tables, no `*_CL` | Direct submit to advanced hunting unchanged | Missing service / SKU → see § 3.5.4. |

**Engine picks the mode automatically** by inspecting each query's KQL body (with string literals stripped to avoid false positives like `"Identity"` as a column value). You don't configure routing — you just need to make sure the data the queries need is reachable. The console log shows which path was taken per report:

```
[INFO] Query touches only Log Analytics tables (no Defender XDR tables);
       routing entire query directly to LA workspace -- no let-block, no
       advanced-hunting round trip, no body-size limit.
```

vs.

```
[INFO] running advanced hunting query against Defender Exposure Management Graph ... Please wait !
[INFO] SI_IdentityAssets_CL not present in advanced hunting -- engine will inline-bridge from Log Analytics.
```

##### Caveats by setup style

| Your tenant | What works out of the box | What you need to configure |
|---|---|---|
| **Sentinel + data lake mirroring of `SI_IdentityAssets_CL`** | Everything — pure-LA, mixed, and pure-XDR all run cleanly. No size limits. Best experience. | Just enable mirroring on the custom table. |
| **Sentinel without data lake mirroring** | Pure-LA + pure-XDR fine. Mixed queries use the let-block bridge — works on small/medium estates but can hit nginx 413 on tenants with many privileged users + heavy `CSA` / `TierSources` JSON columns. | Optional: enable data lake mirroring to remove the size cap. |
| **No Sentinel, Entra logs forwarded to LA** | Pure-LA reports work. Mixed reports work via the let-block (subject to body cap). Sign-in / audit reports run pure-LA against `SigninLogs` / `AuditLogs`. | **Set up Entra diagnostic settings → Log Analytics** (steps below). This is THE prerequisite. |
| **No Sentinel, no Entra log forwarding** | Pure-LA reports against `SI_IdentityAssets_CL` only. Mixed-XDR reports work but go through advanced hunting (let-block bridge). Sign-in / audit reports against LA-side tables fail (table not present). | Forward Entra logs to LA — same steps below. |

##### How to forward Entra ID sign-in + audit logs to Log Analytics

This is a one-time tenant configuration. Once enabled, the LA-side tables `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs` (and a few others) start receiving data within minutes. SecurityInsight's sign-in / audit reports then route pure-LA against them and bypass advanced hunting entirely.

**Two ways to do it:**

**Option A — via Microsoft Sentinel (recommended for retention + analytic-rule coverage):**
1. Open the Sentinel workspace you want the logs in
2. **Content hub → "Microsoft Entra ID" data connector → Open connector page**
3. Tick the log streams you want forwarded (at minimum: SigninLogs, AuditLogs, AADNonInteractiveUserSignInLogs)
4. **Apply Changes** — Sentinel writes the diagnostic setting to Entra automatically

**Option B — directly via Entra (no Sentinel SKU needed):**
1. **Entra admin center → Monitoring & health → Diagnostic settings → + Add diagnostic setting**
2. Name it (e.g. `entra-to-log-analytics`)
3. Tick the categories you need:
   - `SignInLogs` (interactive user sign-ins)
   - `NonInteractiveUserSignInLogs` (background / token-refresh sign-ins)
   - `ServicePrincipalSignInLogs` (SPN sign-ins)
   - `ManagedIdentitySignInLogs` (MI sign-ins)
   - `AuditLogs` (admin actions, group membership changes, role assignments)
   - Optional: `ProvisioningLogs`, `RiskyUsers`, `UserRiskEvents` if you want PIM / Identity Protection data
4. **Send to Log Analytics workspace** → pick your workspace
5. **Save**

**Required licence**: Entra ID **P1** (or higher) for `SignInLogs` / `AuditLogs`. P2 for the risk-event categories. Without P1, the diagnostic-settings page won't even let you enable the sign-in categories.

**Validation** (a few minutes after enabling):
```kql
SigninLogs | where TimeGenerated > ago(15m) | count
AuditLogs  | where TimeGenerated > ago(15m) | count
```
Both should return non-zero.

##### MDE Plan 1 vs Plan 2 vs Defender for Business — quick-reference

A common confusion that comes up alongside this:

| You have | `Device*` tables in advanced hunting? | What works in SecurityInsight |
|---|---|---|
| **MDE Plan 2** / M365 E5 Security / M365 E5 | ✅ Yes (full EDR schema) | All Endpoint reports work (Device_Recommendations, vulnerability reports, attack-paths, etc.) |
| **MDE Plan 1** | ❌ No | Endpoint reports that join `Device*` fail. The Defender portal's Device Inventory page still works (renders for both P1 + P2) — easy to think P1 is "enough" but advanced hunting is P2-only. |
| **Defender for Business** (DfB) | ❌ No | Same as P1 — limited / no advanced hunting access on `Device*`. |
| **MDVM** standalone add-on | Only `DeviceTvm*` (TVM tables) | Vulnerability + secure-config reports work; raw EDR reports don't. |
| **Just upgraded** P1 / DfB → P2 | ✅ Yes — within minutes to ~24h | Wait for the tenant's advanced-hunting backend to re-provision. Re-run the engine once the propagation completes. |

If you only have P1 / DfB and don't plan to upgrade, you can still get value from SecurityInsight on the **Identity** + **Azure** + **Exposure Graph** report families — just exclude the Endpoint-EDR ones via `*_Custom.yaml` overrides (see § 5).

---

<a id="351-connectivity-spn-or-managed-identity"></a><a id="connectivity-spn-or-managed-identity"></a>
### 🔐 3.4 Connectivity — SPN or Managed Identity

[⤴ Back to top](#top)

SecurityInsight engines authenticate to Entra (Microsoft Graph) and Azure (Resource Graph + Log Analytics + Storage). **Pick ONE** authentication model:

| # | Method | Best for | Setup |
|---|---|---|---|
| 1 | **Entra SPN + Secret** | Lab / testing | Create app, set client secret |
| 2 | **Entra SPN + Certificate** | Production on a VM where you control the cert store | Create app, upload cert, install private key on the VM |
| 3 | **System-Assigned Managed Identity** | Azure VM / Function App / Logic App / Hybrid Worker | Enable system-assigned MI on the host |
| 4 | **User-Assigned Managed Identity** | Multiple Azure hosts sharing one identity | Create UAMI, assign to host(s) |

**Either way, the identity needs the same permissions.** Use the included one-shot utility:

```powershell
# Interactive (you sign in as a Privileged Role Admin), creates 'sp-securityinsight' if missing,
# grants Graph + Defender + ATP API permissions + Azure Reader + Tag Contributor at tenant-root MG:
.\launcher\Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions\launcher.community-vm.template.ps1

# Dry-run preview first:
.\launcher\Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions\launcher.community-vm.template.ps1 -WhatIfMode

# Optional: also grant Log Analytics Reader on a Defender workspace + Monitoring Metrics Publisher on a DCR:
.\launcher\Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions\launcher.community-vm.template.ps1 `
    -DefenderWorkspaceResourceId '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<defender-ws>' `
    -DcrResourceId               '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/<dcr>'
```

The OnboardValidate engine is **idempotent** — re-run it any time as a validation pass. Adding permissions later? Edit the catalog at the top of `SCRIPTS/Validate-SIPermissions.ps1` and re-run; only the missing grants are applied.

**End-of-run summary block (v2.1.64+)** prints the App display name, App (client) ID, SPN Object ID, tenant ID, per-category grant counts, a **ready-to-paste `$global:Spn*` block** for your `LauncherConfig.custom.ps1`, and verification KQL for after your first ingest. No scrolling through the log to find the AppId.

> [!IMPORTANT]
> **What OnboardValidate DOES cover (via RBAC grants):**
> - Graph + Defender + ATP API permissions on the SPN
> - Azure `Reader` at tenant-root MG (default — for Azure Resource Graph enumeration across every sub)
> - Azure `Tag Contributor` at tenant-root MG (needed by `CriticalAssetTagging` to write tier tags on subs / RGs / resources)
> - Falls back to per-subscription if the onboarding identity lacks UAA at tenant root (or if you pick `-AzureRbacScope PerSubscription` explicitly)
> - Optional: `Log Analytics Reader` on a Defender workspace (`-DefenderWorkspaceResourceId`)
> - Optional: `Monitoring Metrics Publisher` on a specific DCR (`-DcrResourceId`)
>
> **What OnboardValidate does NOT cover:**
> - Creating the Log Analytics workspace / DCE / DCR — that's either done by the `Validate-SILogAnalytics_OnboardValidate-SecurityInsight-LogAnalytics` launcher (§3.5.2) OR auto-created by the engines themselves on first run (v2.1.54+).
> - Granting the SPN `Owner` or `Contributor + User Access Administrator` — which is what the engines' auto-provisioning needs for **first-run** workspace/DCE creation + container RBAC grants. On `Reader`-only subs, auto-provision will fail cleanly with a `403 AuthorizationFailed` warning and you'll need to provision manually via §3.5.2 or grant higher perms.
>
> **Required permissions** are listed in [§ 7.1](#permissions-catalog).

<a id="352-identity-infrastructure-workspace--dce--dcr"></a><a id="identity-infrastructure-workspace--dce--dcr"></a>
### 🏗️ 3.5 Identity infrastructure — Workspace + DCE + DCR

[⤴ Back to top](#top)

The `IdentityAssetsCollect` and `RiskAnalysis` engines ingest into Log Analytics via a Data Collection Rule (DCR) and Data Collection Endpoint (DCE).

> [!TIP]
> **You have two options** (v2.1.54+). Pick one:
>
> **Option A — let the ingestion engines auto-provision on first run** *(recommended for labs / single-tenant demos)*: the first time `IdentityAssetsCollect` or `RiskAnalysis` runs, they look for the workspace / DCE / DCE RG / DCR RG and **create anything missing** — then grant the SPN `Monitoring Metrics Publisher` on the RGs and `Storage Blob Data Contributor` on an export blob container if one is configured. **Requires `Owner` (or `Contributor + User Access Administrator`) on the target subscription for the first run.** After that, the engines can run with just `Reader` + `Monitoring Metrics Publisher`.
>
> **Option B — provision explicitly up-front** *(recommended for production / locked-down tenants where the ingestion SPN is `Reader`-only)*: run the dedicated onboarding launcher once as a privileged admin, then hand the SPN a read-only role. Details below.

**Option A — zero-touch auto-provision (v2.1.54+)**

Just run `IdentityAssetsCollect` or `RiskAnalysis` directly. You'll see lines like:
```
[OK]   Workspace exists: log-platform-management-securityinsight (rg=rg-securityinsight)
[OK]   DCE exists: dce-securityinsight (rg=rg-dce-securityinsight, location=westeurope)
[INFO] RG exists: rg-dcr-securityinsight (westeurope)
```
…or — if missing — `[STEP] DCE '...' not found -- auto-provisioning` followed by `[OK] Created DCE` and `[OK] Assigned 'Monitoring Metrics Publisher' at ...`. The canonical names live in **Layer 0** (`launcher/_lib/SecurityInsight.shared-defaults.ps1`) — see [§ 3.7](#understand-the-launcherconfig-files). Override any of them in your `LauncherConfig.custom.ps1` if you deviate from the defaults.

**Option B — explicit provisioning**

```powershell
.\launcher\Validate-SILogAnalytics_OnboardValidate-SecurityInsight-LogAnalytics\launcher.community-vm.template.ps1
```

This creates (or re-uses if they exist):
- Resource Group `rg-securityinsight` (workspace RG — override with `$global:ResourceGroup`)
- Resource Group `rg-dce-securityinsight` (DCE RG — override with `$global:DceResourceGroup`)
- Resource Group `rg-dcr-securityinsight` (DCR RG — override with `$global:DcrResourceGroup`)
- Log Analytics workspace `log-platform-management-securityinsight`
- DCE `dce-securityinsight`
- DCR `dcr-si-identity-assets`
- Custom table `SI_IdentityAssets_CL`
- `Monitoring Metrics Publisher` + `Contributor` RBAC on the DCE RG + DCR RG (granted to the ingestion SPN)
- `Contributor` on the Log Analytics workspace (granted to the ingestion SPN)

At the end of the run, the engine prints a **mode-aware cheat-sheet** with the exact globals to copy into your `LauncherConfig.custom.ps1`. You don't have to memorize the URIs.

> **Which option do I need?** Run `Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions` (§ 3.5.1) first. If it grants `Owner` or `Contributor + UAA` on the target sub, Option A Just Works™. If your SPN ends up with `Reader`-only, use Option B.

<a id="353-azure-openai-optional"></a><a id="azure-openai-optional"></a>
### 🤖 3.6 Azure OpenAI (optional)

[⤴ Back to top](#top)

The AI executive summary is a separate opt-in. Helper script provisions a PAYG Azure OpenAI account + model deployment:

```powershell
.\launcher\Validate-SIOpenAI_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure\launcher.community-vm.template.ps1
```

Then enable in any engine's `LauncherConfig.custom.ps1`:

```powershell
$global:BuildSummaryByAI  = $true
$global:OpenAI_endpoint   = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_deployment = 'gpt-4o-mini'
$global:OpenAI_apiKey     = '<your-azure-openai-key>'
```

> [!TIP]
> AI summary is appended both to the **Excel report** (as a 'Summary' worksheet) and the **email body**. Token budget is configurable via `$global:OpenAI_MaxTokensPerRequest` (default 16384).

<a id="37-understand-the-launcherconfig-files"></a><a id="understand-the-launcherconfig-files"></a>
### 📂 3.7 LauncherConfig files

[⤴ Back to top](#top)

Every engine launcher uses a **layered config** model. You only ever edit `LauncherConfig.custom.ps1`; everything else is shipped by us and replaced safely on every release.

```
launcher/<engine>/
├── launcher.*.template.ps1            ← engine wrapper (ours, replaced on update)
├── LauncherConfig.defaults.ps1        ← every supported $global:* with our default (ours, replaced on update)
├── LauncherConfig.sample.ps1          ← copy-paste starter (ours, replaced on update)
├── LauncherConfig.custom.ps1          ← YOUR overrides — gitignored, NEVER overwritten
└── launcher.manifest.json             ← publish metadata (ours)
```

Visual load order (each layer's `$global:*` overrides the previous — a diagram of how the layers merge lives in [§ 7.7](#layered-config-flow)):

| # | File | Owner | Purpose |
|---|---|---|---|
| 0 | `launcher/_lib/SecurityInsight.shared-defaults.ps1` | us | **Solution-wide canonical names** — `$global:WorkspaceName`, `$global:DceName`, `$global:DceResourceGroup`, `$global:DcrResourceGroup`, `$global:Location`, `$global:SubscriptionId` (v2.1.55). Shared by every SI engine so you don't have to repeat them. |
| 1 | `LauncherConfig.defaults.ps1` | us | Engine baseline — table names, DCR name, mode flags |
| 2 | `SOLUTIONS/PlatformConfiguration/config/platform-defaults.ps1` | you (internal mode only) | Shared across every solution on the platform (SMTP, tenant, KV) |
| 3 | `SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1` | you | Solution-wide overrides (DCR / workspace / exclude patterns) |
| 4 | `launcher/<engine>/LauncherConfig.custom.ps1` | you | Per-engine overrides (auth, per-engine mail) |
| 5 | CLI args | per-invocation | Last word |

> [!TIP]
> **Auto-provision, auto-resolve (v2.1.54+)**: missing Workspace / DCE / DCE RG / DCR RG are auto-created on first run, and `DceIngestionUri` is resolved from `DceName` at runtime — you don't have to hardcode endpoint URIs any more. See [§ 5](#whats-new-v21x-highlights) for the full v2.1.53–v2.1.64 feature matrix.

**Quickstart**:

```powershell
# 1. Copy the sample to your custom file (gitignored, never overwritten):
Copy-Item launcher\SecurityInsight_RiskAnalysis\LauncherConfig.sample.ps1 `
          launcher\SecurityInsight_RiskAnalysis\LauncherConfig.custom.ps1

# 2. Edit LauncherConfig.custom.ps1 — uncomment the values you want to set.
#    Bare minimum is the auth method (e.g. SPN + cert thumbprint).

# 3. Run:
.\launcher\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1 -Summary
```

<details>
<summary>📧 <b>Example: enable email + AI summary</b></summary>

In `LauncherConfig.custom.ps1`:

```powershell
# Auth (pick ONE method; SPN+cert shown)
$global:SpnTenantId              = '<your-tenant-id-guid>'
$global:SpnClientId              = '<your-app-client-id-guid>'
$global:SpnCertificateThumbprint = '<cert thumbprint, hex, no spaces>'

# Mail (community mode short names)
# NOTE: $SMTPFrom must be a VERIFIED sender in your relay (Brevo/SendGrid/Postmark/M365
# all reject mail where From != verified sender). $SMTPUser is just the relay login.
$global:SendMail        = $true
$global:MailTo          = @('soc@yourdomain.com','exec-summary@yourdomain.com')
$global:SmtpServer      = 'smtp.yourdomain.com'
$global:SMTPPort        = 587
$global:SMTP_UseSSL     = $true
$global:SMTPUser        = '<smtp-login-username>'        # relay login (e.g. 'NNNNN@smtp-brevo.com')
$global:SMTPPassword    = '<smtp-password>'
$global:SMTPFrom        = 'noreply@yourdomain.com'       # verified sender -- appears in From header

# AI executive summary
$global:BuildSummaryByAI  = $true
$global:OpenAI_endpoint   = 'https://aoai-securityinsight.openai.azure.com'
$global:OpenAI_deployment = 'gpt-4o-mini'
$global:OpenAI_apiKey     = '<your-azure-openai-key>'
```

That's it. Re-run the launcher.
</details>

<details>
<summary>📊 <b>Example: ingest results into Log Analytics</b></summary>

In `LauncherConfig.custom.ps1`:

```powershell
$global:SendToLogAnalytics               = $true
$global:SI_RiskAnalysis_DcrResourceGroup = 'rg-securityinsight'
# DCE / Workspace / DceName fall back to the IAC values automatically when present
```

The two DCRs (`dcr-si-risk-analysis-summary` + `dcr-si-risk-analysis-detailed`) and the two custom tables (`SI_RiskAnalysis_Summary_CL` + `SI_RiskAnalysis_Detailed_CL`) are auto-created by [AzLogDcrIngestPS](https://www.powershellgallery.com/packages/AzLogDcrIngestPS) on first ingest.
</details>

<details>
<summary>☁️ <b>Example: upload .xlsx + .json to UNC share or Azure Storage</b></summary>

```powershell
# UNC (caller's Windows identity needs share write):
$global:ExportDestination = '\\fileserver\reports\SecurityInsight\'

# OR Azure Storage (SPN needs 'Storage Blob Data Contributor' on the container):
$global:ExportDestination = 'https://mystg.blob.core.windows.net/securityinsight/'
```

Type is auto-detected from the prefix. Existing files are renamed to `<name>.<yyyy-MM-dd_HHmmss>.<ext>.bak` before the new file is written, so the canonical path always holds the latest run with backups next to it. For Azure Storage the container is auto-created if missing and the SPN is granted `Storage Blob Data Contributor` at container scope (best-effort — requires caller Owner / UAA on the storage account for the grant).
</details>

<details>
<summary>🧪 <b>Example: launcher-level Summary/Detailed flip (v2.1.57+)</b></summary>

Leave `$global:ReportTemplate` unset and let the override switches pick the template + mode. Lets testers toggle modes with a single line.

```powershell
# Flip to Detailed for this run (no other changes):
$global:RiskAnalysis_Detailed_Override = $true

# Default template names used when ReportTemplate is not explicit:
$global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# Per-template mail (wins over the flat MailTo below):
$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('soc@yourdomain.com')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('exec-summary@yourdomain.com')
```
</details>

<details>
<summary>📄 <b>Full RiskAnalysis LauncherConfig.custom.ps1 (community mode, copy-paste)</b></summary>

Minimal ceremony; all placeholders in `<...>`. Everything past section 1 is optional — defaults come from Layer 0 (`launcher/_lib/SecurityInsight.shared-defaults.ps1`).

```powershell
# --- Auth: SPN + plaintext secret (TESTING ONLY) ---
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'

# --- Infrastructure (overrides Layer 0 shared defaults) ---
$global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
$global:DceResourceGroup = 'rg-dce-securityinsight-community'
$global:DceName          = 'dce-securityinsight-community'
$global:WorkspaceName    = 'log-platform-management-si-community'
$global:SubscriptionId   = '<your-target-subscription-id-guid>'

# --- Ingest + reporting mode ---
$global:SendToLogAnalytics = $true
$global:ReportTemplate     = 'RiskAnalysis_Summary_Bucket'

# --- Mail: flat (fallback) + per-template (preferred) ---
# $SMTPFrom MUST be a verified-sender address in your relay. Common relays
# (Brevo, SendGrid, Postmark, M365) reject mail whose From header is not verified.
$global:SendMail        = $true
$global:MailTo          = @('fallback@yourdomain.com')
$global:SmtpServer      = 'smtp-relay.brevo.com'
$global:SmtpPort        = 587
$global:SMTP_UseSSL     = $true
$global:SMTPUser        = '<smtp-login-username>'       # e.g. 'NNNNN@smtp-brevo.com'
$global:SMTPPassword    = '<smtp-login-password>'
$global:SMTPFrom        = 'noreply@yourdomain.com'      # verified sender in your relay

$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('soc@yourdomain.com')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('exec-summary@yourdomain.com')

# --- Output: JSON sibling + upload to blob (container auto-created) ---
$global:WriteJsonOutput    = $true
$global:ExportDestination  = 'https://<your-storacct>.blob.core.windows.net/riskanalysis-summary/'

# --- Launcher mode overrides (flip Summary/Detailed without editing ReportTemplate) ---
$global:RiskAnalysis_Summary_Override                = $null
$global:RiskAnalysis_Detailed_Override               = $true
$global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# --- Behaviour tuning ---
$global:TroubleshootingMode              = $true
$global:CsaAttributeSet                  = 'SecurityInsight'
$global:SubscriptionNameExcludePatterns  = @('*Azure for Students*')

# --- AI executive summary (Azure OpenAI) ---
$global:OpenAI_apiKey              = '<your-azure-openai-key>'
$global:OpenAI_endpoint            = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<your-deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
```
</details>

<details>
<summary>📄 <b>Real-world RiskAnalysis LauncherConfig.custom.ps1 (annotated, sensitive values redacted)</b></summary>

A working config as actually deployed on a community box — full ingest to Log Analytics, JSON + XLSX uploaded to Azure Blob, per-template mail routing via a Brevo relay with a verified sender, and AI executive summary via Azure OpenAI. All credentials / GUIDs / keys replaced with `xxxxx` placeholders; substitute your own.

```powershell
# --- Auth: SPN + plaintext secret ---
$global:SpnTenantId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# --- Infrastructure (auto-provisioned on first run if missing) ---
$global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
$global:DceResourceGroup = 'rg-dce-securityinsight-community'
$global:DceName          = 'dce-securityinsight-community'
$global:WorkspaceName    = 'log-platform-management-si-community'
$global:SubscriptionId   = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# --- Ingest ---
# $global:ReportTemplate is deliberately unset -- the Override flags below
# drive which template(s) run. This is the cleanest pattern for scheduled runs.
$global:SendToLogAnalytics = $true

# --- Mail: Brevo relay, verified sender, per-template recipients ---
$global:SendMail        = $true
$global:MailTo          = @('fallback@yourdomain.com')
$global:SmtpServer      = 'smtp-relay.brevo.com'
$global:SmtpPort        = 587
$global:SMTP_UseSSL     = $true
$global:SMTPUser        = 'xxxxxxxxx@smtp-brevo.com'       # Brevo relay login
$global:SMTPPassword    = 'xxxxxxxxxxxxxxxx'
$global:SMTPFrom        = 'svc-automation@yourdomain.com'  # verified sender in Brevo console

# --- Output: JSON sibling + upload to Azure Blob (container auto-created) ---
$global:WriteJsonOutput    = $true
$global:ExportDestination  = 'https://<your-storacct>.blob.core.windows.net/riskanalysis-summary/'

# --- Launcher mode overrides (drive mode without setting $ReportTemplate) ---
# Override flags only BUMP a mode flag to $true; they never force it to $false.
# Pattern below: Summary ON, Detailed OFF -- only the Summary template runs
# on scheduled invocations. Flip Detailed to $true to run both.
$global:RiskAnalysis_Summary_Override                = $true
$global:RiskAnalysis_Detailed_Override               = $false
$global:RiskAnalysis_ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$global:RiskAnalysis_ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# --- Per-template mail recipients (win over the flat $MailTo above) ---
$global:RiskAnalysis_Detailed_SendMail = $true
$global:RiskAnalysis_Detailed_To       = @('IT-Alerts-Identity@yourdomain.com')
$global:RiskAnalysis_Summary_SendMail  = $true
$global:RiskAnalysis_Summary_To        = @('IT-Alerts-Identity@yourdomain.com')

# --- Behaviour tuning ---
$global:TroubleshootingMode              = $false
$global:CsaAttributeSet                  = 'SecurityInsight'
$global:SubscriptionNameExcludePatterns  = @(
    '*Azure for Students*'
)

# --- AI executive summary (Azure OpenAI) ---
$global:OpenAI_apiKey              = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
$global:OpenAI_endpoint            = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<your-deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
```
</details>

<details>
<summary>📄 <b>Full Identity-collection LauncherConfig.custom.ps1 (community mode)</b></summary>

For `launcher/IdentityAssetsCollectDefineTierIngestLog/LauncherConfig.custom.ps1`:

```powershell
# --- Auth: SPN + plaintext secret (TESTING ONLY) ---
$global:SpnTenantId     = '<your-tenant-id-guid>'
$global:SpnClientId     = '<your-app-client-id-guid>'
$global:SpnClientSecret = '<your-client-secret>'

# --- Infrastructure (overrides Layer 0 shared defaults) ---
$global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
$global:DceResourceGroup = 'rg-dce-securityinsight-community'
$global:DceName          = 'dce-securityinsight-community'
$global:WorkspaceName    = 'log-platform-management-si-community'
$global:SubscriptionId   = '<your-target-subscription-id-guid>'

# --- Behaviour tuning ---
$global:BatchSize                        = 200
$global:TroubleshootingMode              = $true
$global:CsaAttributeSet                  = 'SecurityInsight'
$global:SubscriptionNameExcludePatterns  = @('*Azure for Students*')

# --- Cross-workspace Defender/Sentinel IdentityInfo reads ---
# Set when IdentityInfo lives in a DIFFERENT workspace than the identity-assets
# ingestion workspace. Accepts three names: $global:Defender_WorkspaceNameResourceId
# (canonical), $global:DefenderWorkspaceResourceId, $global:SecurityInsight_Defender_WorkspaceResourceId.
$global:DefenderWorkspaceResourceId = '/subscriptions/<defender-sub-guid>/resourcegroups/<rg>/providers/microsoft.operationalinsights/workspaces/<defender-ws>'

# --- Output: JSON sibling (.jsonl -> .json array) + upload ---
$global:WriteJsonOutput    = $true
$global:ExportDestination  = 'https://<your-storacct>.blob.core.windows.net/identityassets/'
```
</details>

<details>
<summary>📄 <b>Real-world Identity-collection LauncherConfig.custom.ps1 (annotated, sensitive values redacted)</b></summary>

Minimal real-world `launcher/IdentityAssetsCollectDefineTierIngestLog/LauncherConfig.custom.ps1` as actually deployed on a community box. Ingests identities into the local platform workspace (`$WorkspaceName`) but reads `IdentityInfo` rows from a **different** workspace via `$DefenderWorkspaceResourceId` — common split between a customer-managed SecurityInsight workspace and a platform-owned Defender-for-Identity workspace.

```powershell
# --- Auth: SPN + plaintext secret ---
$global:SpnTenantId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# --- Infrastructure (auto-provisioned on first run if missing) ---
$global:DcrResourceGroup = 'rg-dcr-securityinsight-community'
$global:DceResourceGroup = 'rg-dce-securityinsight-community'
$global:DceName          = 'dce-securityinsight-community'
$global:WorkspaceName    = 'log-platform-management-si-community'
$global:SubscriptionId   = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'

# --- Behaviour tuning ---
$global:BatchSize                       = 200
$global:TroubleshootingMode             = $false
$global:SubscriptionNameExcludePatterns = @( '*Azure for Students*' )

# --- Cross-workspace Defender IdentityInfo reads ---
# When the 'IdentityInfo' table lives in a SEPARATE Log Analytics workspace
# from the ingestion workspace above -- e.g. a platform-owned Defender-for-
# Identity workspace -- point the engine at it with a full resource ID.
# The SPN needs Log Analytics Reader on that workspace too.
$global:DefenderWorkspaceResourceId = '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourcegroups/rg-log-platform-management-security-p/providers/microsoft.operationalinsights/workspaces/log-platform-management-security-p'
```
</details>

<details>
<summary>📄 <b>Real-world Build_Tier_Definitions_JSON_File LauncherConfig.custom.ps1 (annotated, sensitive values redacted)</b></summary>

For `launcher/Build_Tier_Definitions_JSON_File/LauncherConfig.custom.ps1` — only auth + Azure OpenAI are required; nothing else needs to be set. The engine tiers the hardcoded `$BuiltInADGroups` list via AI and writes `data/SecurityInsight_IdentityTiering.json`. Run this once per tenant (or whenever you want a fresh AI verdict); the shipped release already contains a curated catalog so most customers don't need to run it at all.

```powershell
# --- Auth: SPN + plaintext secret ---
$global:SpnTenantId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientId     = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
$global:SpnClientSecret = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

# --- Azure OpenAI (required; engine tiers every role/permission/group via AI) ---
$global:OpenAI_apiKey              = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
$global:OpenAI_endpoint            = 'https://<your-aoai-account>.openai.azure.com'
$global:OpenAI_deployment          = '<your-deployment-name>'
$global:OpenAI_apiVersion          = '2025-01-01-preview'
$global:OpenAI_MaxTokensPerRequest = 16384
```

> [!NOTE]
> No `$SubscriptionId` / `$WorkspaceName` / `$DcrResourceGroup` needed — this engine doesn't ingest to Log Analytics or touch Azure resources beyond reading Entra role definitions + Azure built-in roles. Graph reads use the SPN above; Azure role reads use `Get-AzRoleDefinition` which is read-only and works against any subscription the SPN has `Reader`.
</details>

<a id="36-run-the-risk-analysis"></a><a id="run-the-risk-analysis"></a>
### ▶️ 3.8 Run the Risk Analysis

[⤴ Back to top](#top)

Two report templates ship out of the box:

| Template | Audience | What it has |
|---|---|---|
| `RiskAnalysis_Summary_Bucket` | Executives, weekly cadence | Aggregated findings per tier, overall risk rollups |
| `RiskAnalysis_Detailed_Bucket` | Vulnerability / remediation team | Per-asset rows with CVE IDs and remediation guidance |

**Run as Summary**:

```powershell
.\launcher\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1 -Summary
```

**Run as Detailed**:

```powershell
.\launcher\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1 -Detailed
```

**Run a custom report template**:

```powershell
.\launcher\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1 `
    -ReportTemplate 'RiskAnalysis_Detailed_Bucket_Test'
```

**Dry-run (no Excel / mail / LA writes)**:

```powershell
.\launcher\SecurityInsight_RiskAnalysis\launcher.community-vm.template.ps1 -Summary -WhatIfMode
```

<details>
<summary>🎛️ <b>Full CLI parameter list</b></summary>

| Switch | Purpose |
|---|---|
| `-Summary` / `-Detailed` | Pick the report template (mutually exclusive). |
| `-ReportTemplate '<name>'` | Force a specific template (overrides Summary/Detailed). |
| `-BuildSummaryByAI` | Generate AI executive summary (requires OpenAI globals). |
| `-AutoBucketCount` / `-AutoBucketCache` / `-AutoBucketMax <n>` | Adaptive bucketing controls (see [§ 7.3](#bucketing--beating-the-30k-row-ceiling)). |
| `-ResetCache` | Wipe the AutoBucket cache before this run. |
| `-DebugQueryHash` | Log the hash + cache key per KQL query (debugging). |
| `-ShowConfig` | Dump the resolved config and exit. |
| `-WhatIfMode` | Dry run — no Excel / mail / LA / upload writes. |
| `-LauncherConfigPath '<path>'` | Override the customer config file location (default sibling). |

</details>

<a id="38-endpoint-asset-tagging"></a><a id="endpoint-asset-tagging"></a>
<a id="39-distribution-model"></a>
### 🚚 3.9 Distribution model — community + internal launchers

[⤴ Back to top](#top)

**Two launcher flavours per engine, both shipped together:**

| Flavour | When to use | Where FUNCTIONS lib lives |
|---|---|---|
| `launcher.community-vm.ps1` | Public / community customers, your laptop, demo VMs | Inlined under solution folder: `SecurityInsight/FUNCTIONS/AutomateITPS*` |
| `launcher.internal-vm.ps1` | 2linkit-style internal customers with monorepo layout | One level UP: `<repo-root>/FUNCTIONS/AutomateITPS*` (sibling of `SecurityInsight/`) |

Both flavours live in every engine folder (`launcher/<engine>/`). Same engine code, different launcher wiring — the `Resolve-RepoRoot` helper walks up looking for `FUNCTIONS\AutomateITPS\AutomateITPS.psd1` (monorepo / internal) or lowercase `scripts/+launchers/` (community published) sentinels and picks the right path automatically.

**Three ways to get the code on a customer machine:**

```powershell
# 1. Clone the public repo
git clone https://github.com/KnudsenMorten/SecurityInsight.git

# 2. Preview channel (latest)
git clone -b preview https://github.com/KnudsenMorten/SecurityInsight.git

# 3. Bundle the dev tree to a customer machine (offline drop / no internet)
#    Pick the layout that matches the customer's existing FUNCTIONS placement:
.\tools\Push-PreviewBundle.ps1 -TargetRoot C:\Demo\SecurityInsightPreview -Layout Community
.\tools\Push-PreviewBundle.ps1 -TargetRoot C:\Demo                        -Layout Internal
.\tools\Push-PreviewBundle.ps1 -TargetRoot C:\Temp                        -Layout Zip
```

The `Push-PreviewBundle.ps1` helper bundles the dev tree + `AutomateITPS` / `AutomateITPS.AD` / `AutomateITPS.Compat` modules in either layout, ready for an offline customer hand-off (USB drive, email, internal share). The Zip layout produces a single `SI-Preview.zip` with the Internal directory shape inside.

<a id="310-asset-profiling-engine-catalog"></a>
### 📐 3.10 Asset-profiling engine catalog

[⤴ Back to top](#top)

**Four engines, each running independently against the same Profile data model:**

| Engine | Folder | Purpose | Output table(s) |
|---|---|---|---|
| **asset-profiling** | `engine/asset-profiling/` | Identity + Endpoint + Azure → flat-column LA Profile tables. **559** enrichment rules merged from `*.locked.yaml` + `*.custom.yaml` per domain. Tier engine = pure MIN-of-SIRules (no static defaults — every signal becomes a rule entry; engine reduces). | `SI_IdentityAssets_Profile_CL`, `SI_EndpointAssets_Profile_CL`, `SI_AzureAssets_Profile_CL` |
| **privilege-tier-classifier** | `engine/privilege-tier-classifier/` | AI-driven classifier for ambiguous Entra roles / scopes / app permissions. Reads `privilege-tier-catalog/privilege-tier-catalog.custom.json`. | Updates `Tier` on Identity profile rows |
| **publicip** | `engine/publicip/` | Shodan scanner for Tier 0/1 public IPs. Detects open ports + CVEs on internet-exposed assets. | `SI_VulnerabilityPIP_CL` |
| **risk-analysis** | `engine/risk-analysis/` | **134 reports** (67 Summary + 67 Detailed, fully paired) across 4 security domains (Endpoint, Identity, Azure, PublicIP). EG-primary RA pattern: queries source from Microsoft Exposure Graph (nodes + edges), join `SI_*_Profile_CL` only for Tier / CMDB enrichment. 3-layer score model (RiskScoreTotal → RiskScore_Weight_Factor → RiskScoreTotal_Weighted). | `SI_RiskAnalysis_Summary_CL`, `SI_RiskAnalysis_Detailed_CL` |

**Configuration pattern across all engines:** every rule YAML has a `.locked.yaml` (engine-shipped, never edited by customer) and matching `.custom.yaml` (customer-owned, gitignored). The two merge by `id`; Custom wins on conflict and adds new entries. Provider connectors are pluggable under `asset-profiling-providers/<provider>/` — currently `entra/` (built-in) and `servicenow-cmdb/` (read-only CSV pull).

<a id="311-container-keda"></a>
### 🐳 3.11 Container & KEDA host-mode

[⤴ Back to top](#top)

**Pick the host mode by setting `$global:SI_HostMode` in your `config/SecurityInsight.custom.ps1`:**

| Mode | Where it runs | When to use |
|---|---|---|
| `vm` (default) | Windows / Linux VM, scheduled task, ad-hoc PowerShell | Manual runs, on-prem-only scenarios, demo / dev |
| `container` | Azure Container Apps Job (KEDA-scaled) | Production scheduled cadence at scale, multi-tenant fan-out, OOM-resilient replicas |

**Container path components:**

| File | Purpose |
|---|---|
| `Bootstrap-ContainerAppJob.ps1` | One-shot bootstrap: provisions ACR + Container Apps Environment + Job + KEDA queue-depth scale rule |
| `container/Dockerfile` | Base image with PowerShell 7 + `AutomateITPS` + `AzLogDcrIngestPS` pre-installed |
| `container/Start-RiskAnalysisInContainer.ps1` | RA entrypoint: pulls customer config from Storage, runs the engine, ships outputs back to blob |
| `container/Start-SIInContainer.ps1` | Generic entrypoint for the 3 asset-profiling engines (identity / endpoint / azure) |
| `container/Invoke-ShardProducer.ps1` | Discover-stage shard producer — emits N shards onto an Azure Storage Queue, KEDA scales replicas accordingly |

**KEDA auto-scale:** queue-depth-based. Discover stage probes asset count, computes shard count, emits one queue message per shard. KEDA scales replicas up to `$global:SI_KEDA_MaxReplicas` (default 32) and back to 0 when the queue drains. Per-shard heartbeat to `SI_RunHealth_CL` lets you spot OOM'd replicas (Start row but no End row).

**Same `config/SecurityInsight.custom.ps1` works in both modes** — engine reads `$global:SI_HostMode` to pick path. No CLI args required (layered config).

<a id="4-severity--criticality-definitions"></a><a id="severity--criticality-definitions"></a>
## 5. Severity & Criticality Definitions

### 5.1 Severity definitions

[⤴ Back to top](#top)


**Severity** comes from Defender / vendor scoring. SecurityInsight maps the canonical bands to the Consequence score:

| Defender score | SI label | Attack impact |
|---|---|---|
| **10** | **Very High** | Absence of this control gives attackers an immediate and decisive advantage. Either a critical attack path is left fully exposed, or a single exploitation leads directly to full environment compromise with no further steps required. |
| **9** | **High** | This control addresses weaknesses that are actively weaponized in the wild by ransomware operators, credential theft campaigns, and advanced persistent threat actors. Exploitation is well-documented, tooling is widely available, and remediation should be treated as urgent. |
| **8** | **Medium-High** | This control is a foundational hardening measure that meaningfully shrinks the attack surface and disrupts common lateral movement techniques. While not immediately catastrophic if missing, its absence creates conditions that attackers routinely chain together to escalate privileges or move laterally. |
| **5–7** | **Medium** | This control reflects established security best practice and reduces exposure to known attack patterns. Exploitation is possible but less consistent, typically requiring specific environmental conditions or attacker patience. Prioritize after higher-severity items are addressed. |
| **1–4** | **Low** | This control contributes to security hygiene and long-term posture improvement. Missing controls in this range are unlikely to be directly targeted but may marginally increase the cost or noise for an attacker operating in the environment. |


<a id="42-criticality-definitions"></a><a id="criticality-definitions"></a>

### 5.2 Criticality definitions

[⤴ Back to top](#top)


**Criticality** is set per-asset by `CriticalAssetTagging` and reflects "how bad it is if THIS asset is compromised":

| Tier | Label | Attack impact | Defender Portal | API value |
|---|---|---|---|---|
| **0** | **Critical** | **Immediate full environment compromise if taken.** Compromise of a Domain Controller, krbtgt account, or Global Administrator yields unrestricted control over every identity, credential, and resource in the environment. An attacker can forge Kerberos tickets, replicate the entire AD database, assign any Entra role, and persist indefinitely without detection. Recovery requires full forest rebuild. | Very High - tier 0 | 0 |
| **1** | **High** | **High impact, one or two pivots to full compromise.** Compromise of an Exchange server, Authentication Administrator, or jump server provides credential material, token abuse opportunities, or lateral movement paths that lead to tier 0 within one or two steps. An attacker can reset MFA, intercept authentication flows, abuse unconstrained delegation, or exploit ADCS misconfigurations to escalate without direct access to tier 0 assets. | High - tier 1 | 1 |
| **2** | **Medium** | **Significant workload impact, conditional path to escalation.** Compromise of a file server, developer workstation, or SharePoint environment enables mass data exfiltration, credential harvesting from application configs, and abuse of scoped service accounts. Escalation to tier 0 is possible but requires chaining multiple weaknesses such as finding reused credentials, misconfigured delegation, or an over-permissioned service principal. | Medium - tier 2 | 2 |
| **3** | **Low** | **Low blast radius, limited lateral movement potential.** Compromise of a standard employee workstation, guest PC, or read-only service account yields limited immediate value. An attacker gains a foothold for phishing, internal reconnaissance, or credential capture via keylogging, but cannot directly access sensitive systems or escalate without exploiting additional misconfigurations elsewhere in the environment. | Low - tier 3 | 3 |

<a id="tier-0-3-at-a-glance"></a>


#### 4.2.1 Tier 0–3 at a glance

```mermaid
flowchart TD
    T0["<b>Tier 0 — Critical</b><br/>Domain Controllers · krbtgt · Global Admin<br/><i>one-step full environment compromise</i>"]
    T1["<b>Tier 1 — High</b><br/>Exchange · Auth Admin · Jump server · Privileged MI<br/><i>1–2 pivots to Tier 0</i>"]
    T2["<b>Tier 2 — Medium</b><br/>File server · Dev workstation · SharePoint · Scoped SPN<br/><i>significant impact, conditional escalation</i>"]
    T3["<b>Tier 3 — Low</b><br/>Standard workstation · Guest PC · Read-only SPN<br/><i>small blast radius, lateral-only foothold</i>"]
    T0 --> T1 --> T2 --> T3
    style T0 fill:#ffd6d6,stroke:#8b0000,stroke-width:3px
    style T1 fill:#fff0f0,stroke:#b03030,stroke-width:2px
    style T2 fill:#fff4e1,stroke:#b07a00
    style T3 fill:#e8f4fd,stroke:#2a6592
```

Tier 0 sits at the top because one compromise there is a full-environment compromise — the blast radius shrinks rapidly as you go down. The tables in §§ 4.3 – 4.5 show how these tiers map concretely to **Identity**, **Endpoint**, and **Azure** assets.

<a id="43-asset-classification-identity"></a><a id="asset-classification-identity"></a>
### 5.3 Asset classification: Identity

[⤴ Back to top](#top)



**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate Domain Takeover | **Entra ID Roles (built-in) – users/managed identities:** Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Partner / GDAP Delegated Admin, Directory Synchronization Accounts, Hybrid Identity Administrator (when Entra Connect is in password hash sync mode)<br /><br />**Application Permissions (Graph / API):** RoleManagement.ReadWrite.Directory, Directory.ReadWrite.All, AppRoleAssignment.ReadWrite.All, Policy.ReadWrite.AuthenticationMethod, PrivilegedAccess.ReadWrite.AzureAD, RoleManagement.ReadWrite.CloudPC, Organization.ReadWrite.All, Domain.ReadWrite.All, CrossTenantUserProfileSharing.ReadWrite.All, OnPremDirectorySynchronization.ReadWrite.All<br /><br />**Azure Built-in Roles:** Owner (root management group), User Access Administrator (root management group), Owner (tenant root subscription)<br /><br />**Azure Permissions:** Contributor + blueprint assign (root MG), Managed Identity Contributor (root scope), Entra ID joined device with Global Admin token cache, Subscription Owner with Az AD write federation<br/><br/>**AD Built-in Groups:** Domain Admins, Enterprise Admins, Schema Admins, Administrators (builtin), Group Policy Creator Owners, Cert Publishers, Domain Controllers group<br/><br/>**AD Permissions:** Replication rights (DCSync), DnsAdmins (with DC write), SYSTEM on any DC<br /><br />**Accounts (list not complete):** krbtgt account, SYSTEM on DC, Entra Connect sync account (MSOL_), ADConnect service account, Break-glass emergency access accounts, Service accounts with DCSync rights, Accounts with AdminSDHolder propagated ACLs |
| **High<br />(Tier-1)**<br /><br />Fast-Track Takeover (Abusable Privileges) | **Entra ID Roles (built-in) – users/managed identities:** Authentication Administrator, Hybrid Identity Administrator, Exchange Administrator, Cloud App Administrator, Application Administrator, Security Administrator, Intune Administrator, Identity Governance Administrator, External Identity Provider Administrator, B2C IEF Policy Administrator, Domain Name Administrator, Password Administrator (when targeting admins), Helpdesk Administrator (when targeting admins), Billing Administrator, Azure DevOps Administrator, Windows 365 Administrator<br/><br/>**Application Permissions (Graph / API):** Application.ReadWrite.All, Mail.ReadWrite (app all users), User.ReadWrite.All, Group.ReadWrite.All, Sites.FullControl.All, DeviceManagementServiceConfig.ReadWrite.All, DeviceManagementApps.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, ServicePrincipalEndpoint.ReadWrite.All, Policy.ReadWrite.ConditionalAccess, Policy.ReadWrite.PermissionGrant, EntitlementManagement.ReadWrite.All, PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, AuthenticationContext.ReadWrite.All, TrustFrameworkKeySet.ReadWrite.All, UserAuthenticationMethod.ReadWrite.All, IdentityProvider.ReadWrite.All, Organization.ReadWrite.All, Domain.ReadWrite.All, AccessReview.ReadWrite.All, Agreement.ReadWrite.All, RoleEligibilitySchedule.ReadWrite.Directory, RoleAssignmentSchedule.ReadWrite.Directory<br /><br />**Azure Built-in Roles (list not complete):** Owner (subscription or resource group), User Access Administrator (subscription scope), Key Vault Administrator, Azure Kubernetes Service Cluster Admin, Managed Identity Operator (on high-privilege MIs), Virtual Machine Contributor, Automation Account Contributor, Logic App Contributor<br/><br/>**Azure Permissions (list not complete):** Contributor on Key Vault (with access policy model), Azure Arc onboarding with connected machine agent, Storage Account Contributor (with Entra-integrated storage), Azure DevOps project admin (with service connection to high-priv MI), Defender for Cloud admin, IMDS token theft via VM access, Runbook execution as managed identity<br /><br />**AD Built-in Groups:** Account Operators, Backup Operators, Server Operators, Print Operators<br/><br/>**AD Permissions (list not complete):** GPO edit rights on tier 0 OUs, AdminSDHolder write access, msDS-KeyCredentialLink write, WriteOwner on domain root, WriteDACL on domain root, GenericAll on tier 0 groups, GenericWrite on Domain Controllers OU, AllExtendedRights on domain root, ForceChangePassword on admin accounts, Manage CA (AD CS), Certificate enrollment agents, ESC1–ESC8 vulnerable certificate templates, SeBackupPrivilege holders, SeRestorePrivilege holders, SeTakeOwnershipPrivilege holders, SeDebugPrivilege on DC, SeImpersonatePrivilege on DC, Unconstrained delegation computers, Unconstrained delegation service accounts, Shadow Credentials write on admin accounts, SID History injection rights, Trust account manipulation rights, GPO link rights on tier 0 OUs, OU owner on Domain Controllers OU<br /><br />**Accounts (list not complete):** Entra Connect service account, High-privilege service principals with T0 Graph permissions, Admin-consented OAuth apps with T1 permissions, AD CS enrollment agent accounts, Service accounts with unconstrained delegation, Accounts with GenericAll on tier 0 objects, Federated identity credentials on high-privilege app registrations, Managed identities with Owner or UAA at subscription scope, Workload identities bound to high-privilege Azure RBAC roles, Azure Automation Run As accounts, Service principals with client secrets stored in Key Vault accessible to lower-trust identities |
| **Medium<br />(Tier-2)**<br /><br />Conditional Takeover (Needs Chaining / Misconfig) | **Entra ID Roles (built-in) – users/managed identities (list not complete):** User Administrator, Groups Administrator, Conditional Access Administrator, SharePoint Administrator, Teams Administrator, Lifecycle Workflows Administrator<br/><br/>**Application Permissions (Graph / API) (list not complete):** Mail.Read (app all users), Calendars.ReadWrite, Files.ReadWrite.All, AuditLog.Read.All, IdentityRiskyUser.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All<br/><br/>**Azure Built-in Roles (list not complete):** Network Contributor, Log Analytics Contributor, Automation Operator, Azure DevOps stakeholder, Azure Kubernetes Service Cluster User<br /><br />**Azure Permissions (list not complete):** Contributor (single non-sensitive resource group), Storage Blob Data Reader (scoped to non-sensitive storage), Log Analytics Reader, Monitoring Reader, Security Reader (Defender for Cloud), Managed Identity on low-privilege workload, Service principal scoped to single resource group<br/><br />**AD Built-in Groups:** DNS Admins<br/><br />**AD Permissions (list not complete):** OU-scoped write ACLs, LAPS read rights, Constrained delegation (msDS-AllowedToDelegateTo), RBCD write rights, Kerberoastable high-priv SAs<br/><br />**Accounts (list not complete):** High-privilege service principals scoped to workload, Admin-consented OAuth apps with scoped permissions, Automation accounts with limited RBAC, Azure DevOps service connections scoped to single subscription |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Entra ID Roles (built-in) – users/managed identities:** Global Reader, Security Reader, Reports Reader, Message Center Reader, Usage Summary Reports Reader, Directory Readers, Guest User (default)<br/><br/>**Application Permissions (Graph / API) (list not complete):** User.Read (delegated), Mail.Read (delegated self), Calendars.Read (delegated), Directory.Read.All, AuditLog.Read.All (delegated), IdentityRiskEvent.Read.All<br/><br/>**Azure Built-in Roles (list not complete):** Reader (subscription or resource group), Billing Reader, Cost Management Reader, Tag Contributor, Azure DevOps Basic user (no pipeline access)<br /><br />**Azure Permissions (list not complete):** Storage Blob Data Reader (scoped, non-sensitive), Managed Identity with Reader only, Service principal with Reader on isolated resource group<br/><br/>**AD Built-in Groups:** Domain Users (default), Read-only DC (RODC)<br/><br/>**AD Permissions (list not complete):** Scoped helpdesk OU read, GenericRead on non-priv objects<br /><br />**Accounts (list not complete):** Standard user accounts, Guest accounts, Read-only service accounts, Managed identities with no RBAC assignments, Expired or disabled service principals |


<a id="44-asset-classification-endpoint"></a><a id="asset-classification-endpoint"></a>

### 5.4 Asset classification: Endpoint

[⤴ Back to top](#top)



**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate full environment compromise if taken | **Server Roles:** Domain Controllers (Primary/Additional), Read-Only Domain Controllers (RODC), AD CS servers (Certificate Authority — root and subordinate), Entra Connect / AD Connect servers, Federation servers (AD FS primary)<br/><br/>**Management:** Privileged Access Workstations (PAW) used by tier 0 admins, Backup servers with DC/CA backup data, Monitoring servers with domain-level agent credentials, Key Management Services (KMS) servers with domain-joined credential store<br/><br/>**Infrastructure:** HSM-attached servers (storing root CA private keys), SAN / storage controllers backing tier 0 VMs<br/><br/>**Hypervisor:** Hypervisor hosts running tier 0 guest VMs (VMware ESXi, Hyper-V, KVM), vCenter / SCVMM management servers (managing tier 0 hypervisors)<br/><br/>**Network Equipment:** Core routers (BGP, MPLS backbone), Core switches (spanning all VLANs), Firewall clusters (perimeter and internal segmentation), Out-of-band management network devices (iDRAC, iLO, IPMI), Network management servers (Cisco DNA, SolarWinds — full network write access), SD-WAN controllers, Load balancers (handling auth traffic)<br/><br/>**IoT / OT:** Building management systems (BMS) controllers with domain integration, Physical security controllers (badge access, CCTV management) with domain integration, OT / ICS controllers with direct network adjacency to tier 0 systems |
| **High<br />(Tier-1)**<br /><br />High impact, one or two pivots to full compromise | **Server Roles:** Exchange servers, MFA / RADIUS servers, PKI subordinate CA servers, DNS servers (non-DC hosted), Active Directory Federation Services (AD FS) proxy servers<br/><br/>**Management:** Privileged Access Workstations (PAW) used by tier 1 admins, Jump servers / bastion hosts, SIEM servers, Endpoint Detection and Response (EDR) management servers, SCCM / MECM primary site servers, Privileged Identity Management (PIM) approval workflow servers, Secret management servers (HashiCorp Vault, Azure Key Vault private endpoints), Password managers with admin credential stores, Patch management servers (WSUS), Admin workstations used by tier 1 staff without PAW controls<br/><br/>**Infrastructure:** Network Access Control (NAC) servers, VPN concentrators / remote access servers, Azure Arc-connected servers with high-privilege managed identity, Privileged developer machines with production secrets or pipeline credentials<br/><br/>**Hypervisor:** Hypervisor hosts running tier 1 guest VMs, vCenter / SCVMM management servers (managing tier 1 hypervisors)<br/><br/>**Network Equipment:** Distribution switches, Wireless LAN controllers (WLC), Proxy servers (SSL inspection — credential visibility), RADIUS / TACACS+ network authentication servers, Network packet brokers / TAP aggregators, Remote access concentrators (Citrix ADC, F5 BIG-IP), DNS resolvers (internal recursive), DHCP servers (domain-integrated), Network time protocol (NTP) primary servers<br/><br/>**IoT / OT:** SCADA / ICS servers (non-tier 0 adjacent), Industrial IoT gateways with network bridging, UPS management controllers (power disruption potential), HVAC controllers (data center environment impact), Building automation system (BAS) servers, Medical device management servers, Surveillance / CCTV management servers (non-domain integrated)<br/><br/>**Client Devices:** IT staff personal workstations (helpdesk, sysadmin, network engineers — cached credentials, admin tools, RDP session history), IT management laptops (used for remote administration without formal PAW controls), Security operations workstations (SOC analyst machines with SIEM and EDR console access), Senior IT personal workstations (IT managers, architects — broad access scope) |
| **Medium<br />(Tier-2)**<br /><br />Significant workload impact, conditional path to escalation | **Server Roles:** File servers, SharePoint servers, SQL servers hosting sensitive databases, Citrix / RDS session hosts, Web application servers with Entra integrated auth, API gateway servers, Collaboration servers (Teams on-prem, Skype for Business), HR and identity lifecycle management servers, Internal certificate registration authority (RA) servers, IT service management servers (ServiceNow, Jira)<br/><br/>**Management:** Log aggregation servers, DevOps / CI-CD build agents, Container orchestration nodes (Kubernetes worker nodes)<br/><br />**Hypervisor:** Hypervisor hosts running tier 2 guest VMs<br/><br/>**Network Equipment:** Access layer switches (user-facing VLANs), Wireless access points (managed), Network monitoring appliances (read-only), Standalone DHCP servers (non-domain integrated), Content filtering / web proxy appliances, VoIP / SIP gateways<br/><br/>**IoT / OT:** Smart meeting room devices (displays, conferencing systems), Environmental sensors (temperature, humidity — data center), Badge readers (non-domain integrated, isolated), Laboratory equipment with network interfaces, IP cameras (isolated VLAN, no domain integration), Industrial sensors (read-only, no control plane access), Retail / POS terminals (isolated network segment)<br/><br/>**Client Devices:** Production workstations, Lab workstations, Shared devices, Developer workstations, Power user workstations (finance, legal, HR) |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Server Roles:** Print servers, DHCP servers, Time servers (NTP), VoIP servers, Internal wiki / intranet servers, Archival / cold storage servers, Physical access control servers, Test / sandbox servers<br/><br/>**Management:** Network monitoring probes<br/><br/>**Network Equipment:** Unmanaged access switches, Consumer-grade wireless access points, Out-of-band console servers (isolated, read-only access), Standalone print servers (network-connected, no domain join)<br/><br/>**IoT / OT:** Smart lighting controllers (isolated network), Consumer IoT devices (isolated guest VLAN), Non-networked or air-gapped sensors, Vending machines / coffee machines with network connectivity, Digital signage players (isolated, read-only content), Wearables / smart badges (no domain integration), USB-only peripheral devices with firmware update capability<br/><br/>**Client Devices:** Standard employee workstations, Student workstations, Kiosk machines, Guest PCs, Shared classroom / library computers, Development workstations (non-privileged, isolated, no production access), Personally-owned BYOD devices, Retired / decommissioned machines |


<a id="45-asset-classification-azure"></a><a id="asset-classification-azure"></a>

### 5.5 Asset classification: Azure

[⤴ Back to top](#top)



**Disclaimer:** The asset criticality classifications and attacker-centric tiering presented here are based on my own professional judgment and experience working with identity, endpoint, and cloud security environments. Actual tier assignments may vary depending on each organization's specific architecture, hybrid connectivity model, existing compensating controls, risk tolerance, regulatory requirements, and operational priorities. Classifications should be used as a strategic prioritization framework, not as a definitive or exhaustive measure of asset risk. List is not complete.

| Criticality Level | Typical Assets |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Critical<br />(Tier-0)**<br /><br />Immediate full environment compromise if taken | **Compute:** Virtual Machines hosting tier 0 workloads (DC, ADCS, Entra Connect), Virtual Machines with privileged tokens or highly privileged managed identities assigned, VM Scale Sets running privileged workloads, Azure Bastion hosts (gateway to tier 0 VMs), Confidential compute instances handling key material<br/><br/>**Storage:** Storage accounts containing DC/CA backup data, Storage accounts containing Entra Connect configuration, Azure Blob Storage backing tier 0 audit and log pipelines, Storage accounts with Entra-integrated RBAC and tier 0 data, Immutable and locked Azure Storage holding identity bootstrap data<br/><br/>**Identity & Access:** Entra ID tenant root, Management group root (tenant root group), Subscriptions containing tier 0 workloads, Azure Key Vault storing root CA private keys, Azure Key Vault storing tenant-wide secrets and certificates, Azure Key Vaults storing tenant root keys or certificate authorities, Managed Identity with Owner or User Access Administrator at subscription or MG scope, App registrations with RoleManagement.ReadWrite.Directory or Directory.ReadWrite.All, Service principals with tenant-wide privileged Graph API permissions<br/><br/>**Networking:** Virtual Networks hosting tier 0 VMs, Network Security Groups governing tier 0 subnet traffic, Azure Firewall (central hub — controls all east-west and north-south traffic), ExpressRoute circuits (direct on-prem to cloud bridge), Azure Private DNS zones (name resolution for tier 0 services), VPN Gateways (site-to-site tunnels into on-prem tier 0 networks), Azure DDoS Protection plans, Azure Network and Security Policy control plane resources<br/><br/>**Management & Governance:** Azure Management Groups with root tenant-level access, Azure Subscription Owner roles over security-critical subscriptions, Azure Policy assignments at root MG scope, Azure Blueprints assigned at root MG scope, Microsoft Defender for Cloud, Azure Monitor (Log Analytics workspaces ingesting tier 0 signals), Microsoft Sentinel workspace, Azure Automation accounts running as high-privilege managed identity, Azure Automation / Runbook accounts with privileged role assignments, Azure DevOps organizations with service connections to tier 0 subscriptions, Azure Arc control plane (manages on-prem servers as Azure resources), Azure Arc / Hybrid management orchestrators<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 0 VMs, Azure VMware Solution (AVS) management clusters, Azure Stack HCI clusters running tier 0 guest VMs |
| **High<br />(Tier-1)**<br /><br />High impact, one or two pivots to full compromise | **Compute:** Virtual Machines hosting Exchange, ADFS, MFA, or SIEM workloads, Virtual Machines with scoped privileged tokens or identities, Azure Kubernetes Service (AKS) clusters with privileged workloads, Azure Container Apps running privileged services, Azure Batch accounts with high-privilege managed identity<br/><br/>**Storage:** Storage accounts backing SIEM and log aggregation, Storage accounts containing application secrets or config, Azure File shares mounted by privileged VMs, Azure Data Lake storing sensitive identity or security telemetry, Highly active Azure Key Vaults with large number of operations<br/><br/>**Identity & Access:** App registrations with Application.ReadWrite.All or User.ReadWrite.All, Service principals with Exchange, Intune, or Security Administrator equivalent permissions, Managed Identities with Contributor or Key Vault Administrator at subscription scope, Azure AD B2C tenants federated to production tenant, Federated identity credentials on privileged app registrations<br/><br/>**Networking:** Hub Virtual Networks (peered to tier 0 VNets), Azure Application Gateway (WAF — handles auth traffic), Azure Front Door (global entry point — SSL termination), Azure Load Balancer (fronting tier 1 workloads), Network Virtual Appliances (NVA — routing and inspection), Azure Private Endpoints for tier 1 services, Azure DNS resolvers (recursive — name resolution for all workloads)<br/><br/>**Management & Governance:** Azure Automation accounts with scoped privileged runbooks, Azure Automation / Runbook accounts with scoped role assignments, Log Analytics workspaces ingesting tier 1 signals, Azure DevOps pipelines deploying to tier 1 environments, Azure Key Vault storing tier 1 application secrets, Microsoft Defender for Endpoint, Azure Update Manager, Azure Lighthouse delegations with privileged access, Azure Arc / Hybrid management orchestrators (scoped to tier 1 systems)<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 1 VMs, Azure Stack HCI clusters running tier 1 guest VMs, Azure VMware Solution (AVS) workload clusters |
| **Medium<br />(Tier-2)**<br /><br />Significant workload impact, conditional path to escalation | **Compute:** Virtual Machines hosting file, SharePoint, SQL, or collaboration workloads, Azure Kubernetes Service (AKS) worker nodes (non-privileged workloads), Azure App Service plans hosting internal applications, Azure Functions with scoped managed identity, Azure Logic Apps with limited connector scope, Azure Virtual Desktop (AVD) / Windows 365 for non-admin users, Dev/Test virtual machines without production data<br/><br/>**Storage:** Storage accounts hosting application data (non-sensitive), Azure SQL databases (non-sensitive schemas), Azure Cosmos DB instances (application data), Azure File shares mounted by standard workload VMs, Azure Blob Storage for application asset delivery<br/><br/>**Identity & Access:** App registrations with scoped delegated permissions, Service principals scoped to single resource group, Managed Identities with Contributor on isolated resource group, App registrations with Mail.Read or Files.ReadWrite.All<br/><br/>**Networking:** Spoke Virtual Networks (workload-specific, peered to hub), Azure Application Gateway (non-auth workloads), Network Security Groups on workload subnets, Azure Traffic Manager profiles, Azure Content Delivery Network (CDN) endpoints<br/><br/>**Management & Governance:** Dev/Test subscriptions and resource groups, Non-production workloads (dev, test, QA, staging) without production data, Azure DevOps pipelines deploying to tier 2 environments, Log Analytics workspaces (workload-scoped), Azure Key Vault storing tier 2 application secrets, Azure Monitor alert rules (workload-scoped), Azure Backup vaults (tier 2 workload data)<br/><br/>**Hypervisor / Fabric:** Azure Dedicated Hosts running tier 2 VMs, Azure Stack HCI clusters running tier 2 guest VMs |
| **Low<br />(Tier-3)**<br /><br />Low blast radius, limited lateral movement potential | **Compute:** Virtual Machines hosting non-sensitive workloads (print, NTP, intranet), Azure App Service (public-facing, no internal integration), Azure Static Web Apps, Azure Container Instances (isolated, ephemeral), Sandbox subscriptions designed for experimentation, Proof-of-concept / pilot workloads with no sensitive data, Lab resource groups intended to be wiped/reset<br/><br/>**Storage:** Storage accounts hosting public or non-sensitive content, Azure Blob Storage for static asset delivery, Azure Archive storage (cold, no active credentials)<br/><br/>**Identity & Access:** App registrations with User.Read delegated only, Service principals with Reader on isolated resource group, Managed Identities with no RBAC assignments, Expired or disabled service principals, Guest user accounts with default permissions, Personal / sandbox resources with no privileged role assignments<br/><br/>**Networking:** Azure CDN endpoints (public content delivery), Azure DNS public zones (external name resolution only), Network Security Groups on isolated low-trust subnets, Azure Virtual WAN branches (read-only monitoring)<br/><br/>**Management & Governance:** Azure Cost Management (read-only), Azure Policy (read-only assignments), Azure Monitor (read-only, non-sensitive workloads), Azure Advisor (recommendations only), Azure Service Health alerts (read-only), Sandbox subscriptions for experimentation, Proof-of-concept and pilot resource groups with no sensitive data<br/><br/>**Hypervisor / Fabric:** Azure Sandbox / dev-test dedicated hosts, Non-production Azure Stack HCI clusters |

---


<a id="6-the-yaml-concept-locked--custom"></a><a id="the-yaml-concept-locked--custom"></a>

## 📜 6. The YAML Concept (Locked + Custom)

[⤴ Back to top](#top)

SecurityInsight is **data-driven**. Engines (`SecurityInsight_RiskAnalysis`, asset-profiling) read their behaviour from YAML at run time. Custom files live alongside their Locked siblings in the same folder (e.g. `asset-profiling-enrichment/azure/AssetProfileByTags.locked.yaml` + `AssetProfileByTags.custom.yaml`; `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml` + per-report `*.exclude.custom.json`). This means:

- You can add a new report template, a new tagging rule, or a new KQL query **without touching PowerShell**.
- Releases update the curated "Locked" content in-place, while your environment-specific content lives alongside it in a sibling "Custom" file that a release **never overwrites**.

### 6.1 Two files per topic

For every engine that reads YAML, there are exactly two files:

| Topic | Locked (ours) | Custom (yours) |
|---|---|---|
| Risk Analysis queries | `DATA/SecurityInsight_RiskAnalysis_Queries_Locked.yaml` | `DATA/SecurityInsight_RiskAnalysis_Queries_Custom.yaml` |
| Asset Tagging rules | `DATA/SecurityInsight_CriticalAssetTagging_Locked.yaml` | `DATA/SecurityInsight_CriticalAssetTagging_Custom.yaml` |

### 6.2 Merge flow

```mermaid
flowchart LR
    L[📘 <b>Locked.yaml</b><br/>curated content,<br/>replaced on every release] --> M{Engine<br/>merges<br/>by name}
    C[📗 <b>Custom.yaml</b><br/>your content,<br/><u>never</u> overwritten] --> M
    M -->|same ReportName<br/>or AssetTagName?| OVR[<i>Custom wins</i>]
    M -->|new name<br/>only in Custom?| ADD[<i>Added to runtime</i>]
    M -->|only in Locked?| KEEP[<i>Shipped default<br/>used as-is</i>]
    OVR --> R[✅ Effective ruleset<br/>for this run]
    ADD --> R
    KEEP --> R
    style L fill:#e8f4fd,stroke:#2a6592
    style C fill:#e8ffe8,stroke:#1a7a1a
    style R fill:#fff9c4,stroke:#b07a00,stroke-width:2px
```

Precedence rule (same for every topic): **Custom entries with the same `ReportName` / `AssetTagName` as a Locked entry OVERRIDE the Locked entry. New entries in Custom are ADDED.**

### 6.3 Three things you do in Custom

| What | Example | Why |
|---|---|---|
| **Add** new entries | A new tagging rule for your org's `PAWDevices` | Most common. Your environment has things ours doesn't. |
| **Override** a Locked entry | Redefine `RiskAnalysis_Detailed_Bucket` with your own `ReportQuery` | Rare. Customize the shipped behaviour without editing a tracked file. |
| **Disable** a Locked entry | Re-declare the name with `Mode: Disabled` in Custom | Rare. Skip a shipped template that doesn't apply to your environment. |

### 6.4 Concrete example

<details open>
<summary>📋 <b>Asset tagging — adding a custom rule</b></summary>

**`DATA/SecurityInsight_CriticalAssetTagging_Custom.yaml`** (your file):

```yaml
AssetTagging:
  # Your environment-specific Tier-0 endpoints
  - AssetTagName: PAWDevices--tier0--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes
        | where NodeLabel has "device"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tostring(rawData.deviceName) startswith "paw-"
        | extend AssetTagType   = "AssetTier--SI"
        | extend AssetTag       = "PAWDevices"
        | extend AssetTierLevel = 0
        | extend AssetTagName   = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")

  # Exclude guest workstations from tagging
  - AssetTagName: GuestDevices--excluded--SI
    Mode: Prod
    QueryEngine: DefenderGraph
    Query:
      - |
        ExposureGraphNodes
        | where NodeLabel has "device"
        | extend rawData = todynamic(NodeProperties).rawData
        | where tostring(rawData.deviceName) contains "-guest"
        | extend AssetTagType   = "Asset--Excluded--SI"
        | extend AssetTag       = "GuestDevices"
        | extend AssetTagName   = strcat(AssetTag, "--excluded--SI")
```

On the next run, `CriticalAssetTagging` will:

1. Read both Locked + Custom, merge them.
2. Execute your KQL in Defender Exposure Graph.
3. Apply `PAWDevices--tier0--SI` to every device starting with `paw-`.
4. Apply `GuestDevices--excluded--SI` to every device containing `-guest`.
5. Skip any device without an in-scope tag.

No PowerShell touched. Add more rules the same way.
</details>

<details open>
<summary>📋 <b>Risk Analysis — per-template mail override</b></summary>

**`DATA/SecurityInsight_RiskAnalysis_Queries_Custom.yaml`** (your file):

```yaml
ReportTemplates:
  # Override the Locked Detailed_Bucket template to route to the vuln team
  - ReportName: RiskAnalysis_Detailed_Bucket
    Mail_To:
      - vuln-team@yourdomain.com
      - audit@yourdomain.com
    Mail_SendMail: true
    # When Mail_To / Mail_SendMail are set on a template, they win over the
    # global mail recipients for that template's run only.
```

Running `-Detailed` now sends the email to `vuln-team@` and `audit@` regardless of what `$global:MailTo` says.
</details>

### 6.5 What a release upgrade does to your YAML

```mermaid
flowchart TB
    subgraph Before [Before upgrade]
        B1[📘 Locked v2.1.40<br/>12 templates]
        B2[📗 Custom your-file<br/>3 templates you added]
    end
    subgraph After [After upgrade to v2.1.42]
        A1[📘 Locked v2.1.42<br/>13 templates <i>+1 new shipped</i>]
        A2[📗 Custom your-file<br/>3 templates you added <i>untouched</i>]
    end
    Before -->|release zip<br/>extracted over top| After
    style B1 fill:#e8f4fd,stroke:#2a6592
    style A1 fill:#e8f4fd,stroke:#2a6592
    style B2 fill:#e8ffe8,stroke:#1a7a1a
    style A2 fill:#e8ffe8,stroke:#1a7a1a,stroke-width:2px
```

**Locked is replaced; Custom is sacred.** Your edits survive every upgrade. The only time you touch Custom during an upgrade is if the RELEASE NOTES point out that a template you overrode has an updated schema — then you re-apply your override against the new Locked definition.

<a id="66-critical-asset-tagging-mode-and-scope"></a><a id="critical-asset-tagging-mode-and-scope"></a>
### 6.6 `AssetTagName` naming convention — `<stem>--tier<N>--SI` + stem-based merge

[⤴ Back to top](#top)

Every `AssetTagName` in both Locked and Custom YAML **must** match the convention:

```
<stem>--tier<N>--SI
```

Examples: `DomainControllerDNS--tier0--SI`, `BackupOperators--tier1--SI`, `AzHubPlatformManagementSub--tier0--SI`.

- **`<stem>`** — a short, human-readable asset-class name (no spaces, no `--tier` / `--SI` inside).
- **`<N>`** — integer 0..3, the CriticalityTierLevel the rule tags the asset with.
- **`--SI`** — mandatory suffix identifying the tag as produced by this SecurityInsight solution. Downstream consumers (Defender queries, Power BI, aggregators) filter by `--SI` to isolate SI-produced tags from other tagging sources.

**Merge semantics — identity = stem + `--SI`, tier = overridable data.**

The engine normalises every `AssetTagName` to its stem+suffix (upper-cased) and uses THAT as the merge key. The tier integer between is a value the customer can change without disturbing the identity:

```
  Locked.yaml : 'BackupOperators--tier1--SI'   merge key -> BACKUPOPERATORS--SI
  Custom.yaml : 'BackupOperators--tier0--SI'   merge key -> BACKUPOPERATORS--SI   (same!)
  -> Custom wins. Backup Operators is tagged at tier 0 on the next run.
```

This means a customer can re-tier a shipped rule by dropping ONE Custom entry, without having to copy or re-author the Locked query. The Custom record replaces the Locked one wholesale (query included), so the customer can also change the KQL in the same drop-in.

**Malformed `AssetTagName` throws.** A name that doesn't match `<stem>--tier<N>--SI` (e.g. missing `--SI` suffix, or missing tier segment) stops the engine at YAML merge time with:

```
AssetTagName 'MyBadName' in Custom.yaml does not match the required
'<stem>--tier<N>--SI' convention. Fix the YAML entry -- malformed tag
names cannot participate in the Locked/Custom merge.
```

No silent fallback to full-string matching — that path was intentionally rejected because it made collision behaviour hard to predict.

<details>
<summary>📖 <b>Use case 1 — promote an asset class from Tier 1 to Tier 0</b></summary>

Shipped Locked entry:

```yaml
- AssetTagName: BackupOperators--tier1--SI
  Mode: Prod
  QueryEngine: DefenderGraph
  Query:
    - |
      IdentityInfo
      | where GroupMembership has "Backup Operators"
      ...
```

Customer Custom.yaml override — **same stem, different tier**, query can be unchanged or modified:

```yaml
- AssetTagName: BackupOperators--tier0--SI    # tier bumped from 1 to 0
  Mode: Prod
  QueryEngine: DefenderGraph
  Query:
    - |
      IdentityInfo
      | where GroupMembership has "Backup Operators"
      ...
```

Effective on next run: the Backup Operators asset class tags at tier 0. Step 0 upgrades never touch Custom.yaml, so the override persists.

</details>

<details>
<summary>📖 <b>Use case 2 — force a full re-tag (drop the delta filter)</b></summary>

Many shipped Locked queries end with a delta filter like:

```kql
| where isempty(Tag_AssetTier)
    or (Tag_AssetTier != AssetTagName
        and (isnull(ExistingTierNumber) or ExistingTierNumber > AssetTierLevel))
```

…so the rule only fires on assets whose current tag is missing / wrong / lower-tier. When you've changed the `AssetTierLevel` (or want to force every in-scope asset to be re-tagged once), drop the trailing `| where ...` from your Custom.yaml copy:

```yaml
- AssetTagName: AzHubPlatformManagementSub--tier0--SI
  Mode: Prod
  QueryEngine: AzureResourceGraph
  Query:
    - |
      resourcecontainers
      | where type == "microsoft.resources/subscriptions"
      | where properties.managementGroupAncestorsChain has "mg-platform-management"
      | extend AssetTagType = "AssetTier--SI",
               AssetTag     = "AzHubPlatformManagementSub",
               AssetTierLevel = 0
      | extend AssetTagName = strcat(AssetTag, "--tier", tostring(AssetTierLevel), "--SI")
      | project subscriptionId, subscriptionName = name, AssetTagType, AssetTag, AssetTierLevel, AssetTagName, id
      | order by subscriptionId asc
      # NO trailing '| where isempty(Tag_AssetTier) or ...' -- every in-scope asset is re-tagged this run.
```

Run with `$global:Scope = @('TEST')` first to confirm the row set, then flip to `$global:Scope = @('PROD')` for the real write. After a successful force re-tag, you can remove the Custom entry (next run picks Locked's delta-filtered query again, which is a no-op on already-correctly-tagged assets).

</details>

---

<a id="7-appendix"></a><a id="appendix"></a>
<a id="5-concepts"></a><a id="concepts"></a>
## 📎 7. Appendix

[⤴ Back to top](#top)

<a id="71-permissions-catalog"></a><a id="permissions-catalog"></a>
### 7.1 Permissions catalog

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

The exact set the `Validate-SIPermissions.ps1` utility grants (and validates on re-run):

<details open>
<summary><b>Microsoft Graph (Application permissions, admin consent required)</b></summary>

| Permission | Used by |
|---|---|
| `User.Read.All` | IdentityAssetsCollect (user inventory) |
| `Group.Read.All` | IdentityAssetsCollect (group memberships) |
| `Directory.Read.All` | All engines (directory metadata) |
| `Application.Read.All` | IdentityAssetsCollect (SPN + MI inventory) |
| `AuditLog.Read.All` | IdentityAssetsCollect (sign-in logs) |
| `Policy.Read.All` | Risk Analysis (CA policy enumeration) |
| `RoleManagement.Read.All` | All engines (role assignments) |
| `RoleManagement.Read.Directory` | All engines (role definitions) |
| `RoleManagementPolicy.Read.Directory` | All engines (PIM policies) |
| `RoleEligibilitySchedule.Read.Directory` | All engines (PIM eligible) |
| `RoleAssignmentSchedule.Read.Directory` | All engines (PIM active) |
| `IdentityRiskyUser.Read.All` | Risk Analysis (risky user signal) |
| `IdentityRiskEvent.Read.All` | Risk Analysis (risk event signal) |
| `IdentityRiskyServicePrincipal.Read.All` | Risk Analysis (risky SPN signal) |
| `ThreatHunting.Read.All` | IdentityAssetsCollect + Risk Analysis (Exposure Graph) |

</details>

<details>
<summary><b>Microsoft Threat Protection</b></summary>

| Permission | Used by |
|---|---|
| `AdvancedHunting.Read.All` | Risk Analysis (Defender Advanced Hunting KQL) |

</details>

<details>
<summary><b>Microsoft Defender for Endpoint (WindowsDefenderATP)</b></summary>

| Permission | Used by |
|---|---|
| `Machine.ReadWrite.All` | CriticalAssetTagging (set tags on devices) |

</details>

<details>
<summary><b>Azure RBAC</b></summary>

| Role | Scope | Used by |
|---|---|---|
| `Reader` | **tenant-root Management Group** (preferred) or every subscription | All engines — sub enumeration via Resource Graph; **`Build_Tier_Definitions_JSON_File` uses this to enumerate the ~800+ Azure built-in role definitions via `Get-AzRoleDefinition`** |
| `Log Analytics Reader` | Defender / Sentinel workspace | Risk Analysis + IAC (cross-workspace IdentityInfo) |
| `Monitoring Metrics Publisher` | each DCR (`dcr-si-identity-assets`, `dcr-si-risk-analysis-summary`, `dcr-si-risk-analysis-detailed`) | IAC + Risk Analysis (LA ingest) |
| `Storage Blob Data Contributor` | Azure Storage container if `$global:ExportDestination` points to one | Risk Analysis (export upload) |
| `Tag Contributor` | tenant root MG | CriticalAssetTagging |

> [!NOTE]
> **If `Azure_BuiltInRoles_Tier0..3` / `Azure_Roles_Catalog` come back empty in `SecurityInsight_IdentityTiering.json`:** the SPN has no subscription it can read. `Get-AzRoleDefinition` needs a subscription scope. Fix by granting **Reader at tenant-root MG** (preferred — `Validate-SIPermissions.ps1` already does this by default) or at least Reader on one subscription. The engine auto-selects the first subscription it can see after `Connect-AzAccount` (v2.1.175+); before that release the call silently returned empty when no subscription context was set.

</details>

</details>

<a id="72-files-deep-dive"></a><a id="files-deep-dive"></a>

### 7.2 Bucketing — beating the 30k row ceiling

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

<details>
<summary><b>The problem</b></summary>

Azure Resource Graph and Defender Exposure Graph both cap query results at **30,000 rows per call**. Some Risk Analysis queries (especially wide exposure joins across large estates) legitimately return more than that. If a query overflows, Kusto / ARG returns one of a small family of errors (`exceeded the allowed result size`, `exceeded the allowed limits`, `preempted`, etc.). Without intervention, the engine would lose rows silently and skew the risk scoring.

</details>

<details>
<summary><b>The bucketing pattern</b></summary>

The bucketing pattern solves this by splitting the query into **N deterministic partitions** that each stay under the row cap. The engine then unions the N partial results back into one logical dataset before scoring.

**1. Placeholder in the KQL.** Each bucketable query has a single placeholder string (default `__BUCKET_FILTER__`) where the bucketing predicate will be injected at runtime:

```kql
ExposureGraphNodes
| where NodeLabel has "device"
__BUCKET_FILTER__
| ...rest of the query...
```

**2. Bucket predicate generation.** At query-prep time the engine substitutes `__BUCKET_FILTER__` with a deterministic hash-based filter:

```kql
| extend __bucket_key = coalesce(NodeId, NodeName, ...)
| where isnotempty(__bucket_key)
| extend __bucket = abs(hash(__bucket_key)) % <BucketCount>
| where __bucket == <BucketIndex>
```

With `BucketCount = 8`, one query becomes eight queries — each processing roughly an eighth of the dataset, all well under 30,000 rows.

**3. Union & dedupe.** Results from all N buckets are concatenated into one array; the scoring pipeline runs unchanged on the unioned dataset.

</details>

<details>
<summary><b>Auto-bucketing — the engine picks the bucket count itself</b></summary>

Manually guessing the right `BucketCount` for every query is brittle. The engine includes an **adaptive probe** that:

1. **Probes.** Runs the query with `BucketCount = 1` (unbucketed). If Kusto returns an overflow error, retries with `2`, `4`, `8`, ... up to `$global:AutoBucketMax` (default 64).
2. **Caches the winning bucket count.** Once a bucket size succeeds, the engine caches the discovered value in `OUTPUT/AutoBucketCache.json` keyed by a **checksum of the query body**. The checksum guarantees the cache is invalidated automatically if the query is edited.
3. **Reuses on the next run.** Subsequent runs of the same query read the cache first and skip probing entirely.

| Variable | Default | Purpose |
|---|---|---|
| `$global:UseQueryBucketing` | `$false` | Master switch (per-query value in YAML overrides). |
| `$global:DefaultBucketCount` | `2` | Starting bucket count if not overridden per-query. |
| `$global:BucketPlaceholderToken` | `__BUCKET_FILTER__` | Token in the KQL that gets replaced. |
| `$global:AutoBucketCount` | `$false` | Enable adaptive probing. |
| `$global:AutoBucketMax` | `64` | Safety cap on probe size. |
| `$global:AutoBucketCache` | `$true` | Persist discovered bucket counts to disk. |

</details>

</details>

<a id="74-output-destinations"></a><a id="output-destinations"></a>

### 7.3 Output destinations

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

<details>
<summary><b>Local files (always)</b></summary>

```
DATA/OUTPUT/<ReportTemplate>.xlsx           ← Excel report
DATA/OUTPUT/<ReportTemplate>.json           ← JSON sibling (Phase 1, on by default)
```

Filename mirrors the report template — running `-Summary` produces `RiskAnalysis_Summary_Bucket.xlsx` + `.json`; `-Detailed` produces `RiskAnalysis_Detailed_Bucket.xlsx` + `.json`.

</details>

<details>
<summary><b>Log Analytics (opt-in)</b></summary>

When `$global:SendToLogAnalytics = $true`, the engine POSTs the in-memory dataset to one of two custom tables via DCRs auto-created by [AzLogDcrIngestPS](https://www.powershellgallery.com/packages/AzLogDcrIngestPS):

| Run mode | DCR (hardcoded) | LA table |
|---|---|---|
| `-Summary` | `dcr-si-risk-analysis-summary` | `SI_RiskAnalysis_Summary_CL` |
| `-Detailed` | `dcr-si-risk-analysis-detailed` | `SI_RiskAnalysis_Detailed_CL` |

Customer only configures the **Resource Group** that holds the DCRs (everything else falls back to the IAC engine's settings). DCR / table provisioning is automatic on first ingest.

</details>

<details>
<summary><b>UNC share OR Azure Storage (opt-in)</b></summary>

When `$global:ExportDestination` is set, the engine uploads BOTH `.xlsx` and `.json` after the local writes finish. **Type is auto-detected from the prefix:**

| Value pattern | Backend | Auth |
|---|---|---|
| `\\server\share\path\` | UNC (`Copy-Item`) | caller's Windows identity needs share write |
| `https://<acct>.blob.core.windows.net/<container>/` | Azure Storage (`Set-AzStorageBlobContent`) | SPN needs `Storage Blob Data Contributor` on the container |

**Backup-then-overwrite**: if a file with the same name already exists at the destination, it is RENAMED to `<name>.<yyyy-MM-dd_HHmmss>.<ext>.bak` BEFORE the new file is written. So the canonical path always holds the latest run; older copies are timestamped backups next to it. No data loss on re-runs.

</details>

<details>
<summary><b>Email (opt-in)</b></summary>

HTML email with .xlsx attachment + AI summary in the body. Routing differs by mode:

| Mode | Recipient globals |
|---|---|
| **Community** | `$global:SendMail`, `$global:MailTo` (one list, used regardless of Summary/Detailed) |
| **Internal (Automation Framework)** | `$global:Mail_SecurityInsight_Summary_SendMail` / `_To` and `_Detailed_SendMail` / `_To` (per-mode routing) |

Per-template override: see [§ 7.5](#per-template-mail-recipient-override-yaml).

</details>

</details>

<a id="75-per-template-mail-recipient-override-yaml"></a><a id="per-template-mail-recipient-override-yaml"></a>

### 7.4 Per-template mail recipient override (YAML)

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

In `SecurityInsight_RiskAnalysis_Queries_Custom.yaml` you can override mail recipients **per template**, independent of the global mail config. Useful for routing a specific report to specific stakeholders.

```yaml
ReportTemplates:
  - ReportName: RiskAnalysis_Detailed_Bucket
    Mail_To:
      - vuln-team@yourdomain.com
      - audit@yourdomain.com
    Mail_SendMail: true                 # optional; overrides the global toggle
    # ...rest of the template definition
```

When present on the chosen template, `Mail_To` overrides `$global:Report_To` and `Mail_SendMail` overrides `$global:Report_SendMail` for that template's run. Logged on stdout:

```
[INFO] Mail recipients overridden by template 'RiskAnalysis_Detailed_Bucket': vuln-team@..., audit@...
```

</details>

<a id="76-cross-subscription-workspace-support"></a><a id="cross-subscription-workspace-support"></a>

### 7.5 Cross-subscription workspace support

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

If your Defender / Sentinel workspace lives in a **different Azure subscription** than the one your SPN is currently authenticated against (typical when a Sentinel team owns its own sub), the engine handles it transparently. Set `$global:DefenderWorkspaceResourceId` to the full resource ID of the workspace; the engine uses ARM REST directly so the call works regardless of the SPN's current `Set-AzContext`.

The SPN still needs `Log Analytics Reader` on the cross-sub workspace — granted automatically by `OnboardValidate-Permissions` when you pass `-DefenderWorkspaceResourceId`.

</details>

<a id="77-layered-config-flow"></a><a id="layered-config-flow"></a>

### 7.6 Layered config flow

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

How the 5 layers merge at engine startup:

```mermaid
flowchart TB
    subgraph Us [Shipped by us]
        L1[📘 <b>Layer 1</b><br/>LauncherConfig.defaults.ps1<br/><i>every supported $global:* with our default</i>]
    end
    subgraph You [Your edits -- gitignored, survive every update]
        L2[📒 <b>Layer 2</b> <i>internal mode only</i><br/>platform-defaults.ps1<br/><i>shared across ALL solutions</i><br/><small>SMTP, primary tenant, KV, paths</small>]
        L3[📗 <b>Layer 3</b><br/>SecurityInsight.custom.ps1<br/><i>solution-wide</i><br/><small>DCR URIs, exclude patterns</small>]
        L4["📙 <b>Layer 4</b><br/>launcher/&lt;engine&gt;/LauncherConfig.custom.ps1<br/><i>per-engine</i><br/><small>auth, per-engine deviations</small>"]
    end
    L5[⌨️ <b>Layer 5</b><br/>CLI args<br/><i>last word, per-invocation</i>]

    L1 --> L2
    L2 --> L3
    L3 --> L4
    L4 --> L5
    L5 --> EFF[✅ Effective<br/>$global:* state<br/>for this run]
    style L1 fill:#e8f4fd,stroke:#2a6592
    style L2 fill:#fff4e1,stroke:#b07a00
    style L3 fill:#e8ffe8,stroke:#1a7a1a
    style L4 fill:#fce4ec,stroke:#a83275
    style L5 fill:#ede7f6,stroke:#512da8
    style EFF fill:#fff9c4,stroke:#b07a00,stroke-width:2px
```

Each layer only writes the values it cares about. If you don't set anything at Layer 4, Layer 3 values pass through. If you don't have Layer 3 either, Layer 1 defaults apply. This is why a working community install can be as small as a 3-line `LauncherConfig.custom.ps1` containing only the SPN auth.

</details>

<a id="78-end-to-end-architecture"></a><a id="end-to-end-architecture"></a>

### 7.7 End-to-end architecture

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

```mermaid
flowchart LR
    subgraph Sources [Microsoft data sources]
        DEF[Defender XDR<br/>Exposure Graph]
        ENT[Entra ID<br/>Microsoft Graph]
        AZ[Azure<br/>Resource Graph]
        SEN[Sentinel /<br/>LA workspace]
    end

    subgraph Engine [SecurityInsight engines]
        TAG[CriticalAssetTagging]
        IDC[IdentityAssetsCollect]
        RA[RiskAnalysis]
        TIER[Build_Tier_Definitions<br/>+ Azure OpenAI]
    end

    subgraph Outputs [Outputs]
        XLSX[📗 .xlsx]
        JSON[📄 .json]
        LA[📊 LA tables<br/>SI_RiskAnalysis_*_CL]
        UPLOAD[☁️ UNC / Az Storage]
        MAIL[📧 Email + AI summary]
    end

    DEF --> RA
    DEF --> TAG
    DEF --> IDC
    ENT --> IDC
    ENT --> RA
    ENT --> TIER
    AZ --> RA
    AZ --> TAG
    AZ --> IDC
    SEN --> IDC

    TAG --> RA
    IDC --> RA
    TIER --> IDC
    TIER --> RA

    RA --> XLSX
    RA --> JSON
    RA --> LA
    RA --> UPLOAD
    RA --> MAIL
    IDC --> LA
```

---

<a id="locked-catalog-full-inventory"></a>

<a id="locked-catalog"></a>
### 7.8 Locked catalog — full query / rule inventory

Inventory snapshot (auto-derived from the current `risk-analysis-detection/`, `asset-profiling-enrichment/`, `asset-profiling-schema/`, and `privilege-tier-catalog/` trees):

| 📦 Detection queries + tagging rules — included | Count |
|---|---:|
| 🎯 **Risk Analysis reports** — attacker-centric KQL across Endpoint, Identity, Azure, PublicIP. Auto-generated from `risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml`. | **136** (Identity 110 + Endpoint/Device 6 + Azure 2 + Attack Paths 12 + PublicIP/Shodan 4 + Engine self-meta 2) |
| 🏷️ **Asset-classification rules** — `hasMdeMachineGroupTag` / `hasAzureTag` / `egDetectedRoles` / `nameMatches` / `IPSubnetMatch` / `entraGroupMember` / `groupMembership` / `hasSoftwareInstalled` across Identity, Endpoint, Azure PaaS. Each is a `.locked.yaml` in `asset-profiling-enrichment/`. | **594** (1 azure + 590 endpoint + 2 identity + 1 cross-engine `shared/`) |
| 🧬 **Profile schema** — flat-column LA columns the engine emits per asset | **697** fields total across 4 tables (`SI_Endpoint_Profile_CL` 168 + `SI_Identity_Profile_CL` 162 + `SI_Azure_Profile_CL` 321 + `SI_PublicIp_Profile_CL` 46) |
| 📚 **Schema definitions** | **4** — `asset-profiling-schema/{azure,endpoint,identity,public-ip}.schema.locked.json` |
| 👑 **Privilege tier catalog** | **1** — `privilege-tier-catalog/privilege-tier-catalog.custom.json` |
| 🔌 **Provider connectors** | **2** — `asset-profiling-providers/{entra, servicenow-cmdb}` |

**🤖 AI-classified tier catalog** — every role / permission slotted into Tier 0–3 by the AI integration in SecurityInsight:

| Category | Tier 0 | Tier 1 | Tier 2 | Tier 3 | **Total** |
|---|---:|---:|---:|---:|---:|
| **AD built-in groups** | 9 | 6 | 3 | 51 | **69** |
| **Entra built-in roles** | 5 | 23 | 20 | 95 | **143** |
| **Entra / Graph API permissions** | 2 | 59 | 138 | 1,027 | **1,226** |
| **Azure built-in roles** | 3 | 14 | 130 | 726 | **873** |
| **All categories — grand total** | **19** | **102** | **291** | **1,899** | **2,311** |

Run `tests/Test-Smoke.ps1 -Inventory` for the live count.

[⤴ Back to top](#top)

<details>
<summary><b>Show details (expand)</b></summary>

Every name + one-line purpose of every report and tagging rule that ships in `DATA/*_Locked.yaml` — force-refreshed on every Step 0 update. The full KQL behind each entry lives in the YAML next to this README.

#### Risk Analysis — 104 Locked reports (sorted by SecurityDomain)

| # | Domain | Report name | Purpose |
|---:|---|---|---|
| 1 | Azure | `Attack_Paths_Detailed_BucketFilter_Credential_Based_Lateral_Movement` | Identify credential driven attack paths in Exposure Graph and prioritize them by the business impact of the final target. |
| 2 | Azure | `Attack_Paths_Detailed_BucketFilter_Data_Sensitivity_to_Exposed_Credentials` | Attack Paths with Data Sensitivity to Exposed Credentials. Sensitive Data -> Storage -> Exposed Credential. Key detection -> Data exfiltration risk |
| 3 | Azure | `Attack_Paths_Detailed_BucketFilter_Github_to_Azure_Resources` | Attack Paths - Github to Azure resources. GitHub -> Secret -> Azure Resource. Key Detection -> Supply chain compromise |
| 4 | Azure | `Attack_Paths_Detailed_BucketFilter_Identity_Group_Membership_to_Privileged_Resources` | Identify identities that are members of groups and where those groups have permissions or roles on privileged Azure targets. Enrich each path with the standard node context and prioritize by the business impact of the FINAL TARGET. |
| 5 | Azure | `Attack_Paths_Detailed_BucketFilter_Public_IP_to_VM_with_CVE_Exploitation` | Attack Paths with focus on Public IP to VM with CVE Exploitation. Public IP -> Vulnerable VM/Device. Key detection -> Internet-exposed vulnerabilities |
| 6 | Azure | `Attack_Paths_Summary_BucketFilter_Credential_Based_Lateral_Movement` | Identify credential driven attack paths in Exposure Graph and prioritize them by the business impact of the final target. |
| 7 | Azure | `Attack_Paths_Summary_BucketFilter_Data_Sensitivity_to_Exposed_Credentials` | Attack Paths with Data Sensitivity to Exposed Credentials. Sensitive Data -> Storage -> Exposed Credential. Key detection -> Data exfiltration risk |
| 8 | Azure | `Attack_Paths_Summary_BucketFilter_Github_to_Azure_Resources` | Identify credentials stored in GitHub workflows or repositories and trace credential driven attack paths into Azure targets. Paths are prioritized by the business impact of the FINAL TARGET. |
| 9 | Azure | `Attack_Paths_Summary_BucketFilter_Identity_Group_Membership_to_Privileged_Resources` | Attack Paths based on Identity Group Membership to Privileged Resources. Identity -> Group -> Privileged Resource. Key Detection -> Group-based attacks |
| 10 | Azure | `Attack_Paths_Summary_BucketFilter_Public_IP_to_VM_with_CVE_Exploitation` | Attack Paths with focus on Public IP to VM with CVE Exploitation. Public IP -> Vulnerable VM/Device. Key detection -> Internet-exposed vulnerabilities |
| 11 | Azure | `Azure_Recommendations_Detailed_BucketFilter` | Summarize Azure exposure graph findings per asset and recommendation with tier fallback from tags and probability scoring from all risk factors |
| 12 | Azure | `Azure_Recommendations_Summary_BucketFilter` | Summarize Azure exposure graph findings per asset and recommendation with tier fallback from tags and probability scoring from all risk factors |
| 13 | Endpoint | `Attack_Paths_Detailed_BucketFilter_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure` | Attack Paths with Device with high severity vulnerabilities allows lateral movement |
| 14 | Endpoint | `Attack_Paths_Summary_BucketFilter_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure` | Attack Paths with Device with high severity vulnerabilities allows lateral movement |
| 15 | Endpoint | `Device_Missing_CVEs_Detailed_BucketFilter` | This report highlights overdue endpoint CVEs older than 40 days, excluding out-of-scope assets, and prioritizes them using asset criticality, tag-based tiering, and exploit and exposure risk factors to focus remediation on the most critical and likely exploitable vulnerabilities. |
| 16 | Endpoint | `Device_Missing_CVEs_Summary_BucketFilter` | This report highlights overdue endpoint CVEs older than 40 days, excluding out-of-scope assets, and prioritizes them using asset criticality, tag-based tiering, and exploit and exposure risk factors to focus remediation on the most critical and likely exploitable vulnerabilities. |
| 17 | Endpoint | `Device_Recommendations_Detailed_BucketFilter` | Show non-compliant TVM secure configuration controls for endpoints, enriched with Exposure Graph criticality and tags, and add a probability score based on Internet-Exposed (EG CustomerFacing) and LegacyEndOfSupport OS detection |
| 18 | Endpoint | `Device_Recommendations_Summary_BucketFilter` | Identify non-compliant TVM secure configuration controls on endpoints, enriched with Exposure Graph criticality and risk context, and scored with a probability model that includes Internet-Exposed (from EG CustomerFacing) and LegacyEndOfSupport based on OS platform |
| 19 | Identity | `Identity_Admin_LogonTo_InternetExposedDevice_Detailed` | Per-identity detail view for Admin LogonTo InternetExposedDevice Summary. |
| 20 | Identity | `Identity_Admin_LogonTo_InternetExposedDevice_Summary` | Privileged users (Tier 0/1) authenticated to internet-facing devices. Privileged sessions should never occur on internet-exposed assets as these devices have a significantly higher chance of being compromised remotely. Even without CVEs, internet-exposed devices face constant attack attempts. An attacker who breaches an internet-exposed device gains access to any privileged credential or token present on that device. Severity: High (fixed). |
| 21 | Identity | `Identity_Admin_LogonTo_LowTierDevice_Detailed` | Per-identity detail view for Admin LogonTo LowTierDevice Summary. |
| 22 | Identity | `Identity_Admin_LogonTo_LowTierDevice_Summary` | Tier 0 privileged users (Global Admin, Domain Admin etc) authenticating to devices that are NOT classified as Tier 0 assets. Tier 0 admins should only use Tier 0 Privileged Access Workstations (PAWs). Logging on to a standard workstation, developer machine, or shared device exposes Tier 0 credentials to a device with a broader attack surface and potentially lower security controls. Severity: Very High (fixed) - Tier 0 admin on non-PAW device is a tiering violation. |
| 23 | Identity | `Identity_Admin_LogonTo_VulnerableDevice_Detailed` | Per-pair detail: privileged admin and the specific vulnerable device they can authenticate to. Includes CVE score, internet exposure and device risk. |
| 24 | Identity | `Identity_Admin_LogonTo_VulnerableDevice_Summary` | Privileged users (permanent or PIM-eligible Tier 0/1 roles) who are observed authenticating to devices that have high or critical severity CVEs outstanding. When an admin logs on to a vulnerable device, their privileged token/credential is exposed on that device. An attacker who exploits the CVE could harvest the admin credential via memory dumps, token theft, or keylogging. Severity: Very High (fixed) - privileged credential exposure on vulnerable device. |
| 25 | Identity | `Identity_AdminAccount_HasMailbox_Detailed` | Per-admin detail: privileged accounts (Tier 0/1) with a primary mailbox. |
| 26 | Identity | `Identity_AdminAccount_HasMailbox_Summary` | Privileged admin accounts (Tier 0/1) that have a primary mailbox (MailAddress populated). Admin accounts should be mail-disabled, dedicated accounts used only for privileged tasks. A mailbox on an admin account makes it a phishing target and widens the attack surface significantly — one phishing email can directly compromise a privileged session. |
| 27 | Identity | `Identity_AdminAccount_NeverUsed_Detailed` | Per-identity detail view for AdminAccount NeverUsed Summary. |
| 28 | Identity | `Identity_AdminAccount_NeverUsed_Summary` | Privileged accounts (Tier 0/1) created more than 14 days ago that have never signed in. Unused privileged accounts represent dormant attack surface - they hold permissions but have no operational owner actively monitoring them. Common cause: accounts created for a project that never started, or provisioned for a consultant who never onboarded. Severity: High (fixed). |
| 29 | Identity | `Identity_AdminAccount_OnPremSynced_Detailed` | Per-identity detail view for AdminAccount OnPremSynced Summary. |
| 30 | Identity | `Identity_AdminAccount_OnPremSynced_Summary` | Privileged admin accounts (Tier 0/1) that are synchronised from on-premises AD rather than being cloud-only. Admin accounts should be cloud-native to avoid on-prem compromise pivoting to cloud. A compromised AD environment (e.g. via ransomware) can directly take over cloud admin accounts that are synced from AD. Severity: Very High - on-prem sync of privileged accounts breaks cloud/AD separation. |
| 31 | Identity | `Identity_AnyUser_NoMFA_Detailed` | Per-identity detail view for AnyUser NoMFA Summary. |
| 32 | Identity | `Identity_AnyUser_NoMFA_Summary` | All enabled users with no MFA registration, across all tiers. Excludes accounts created within the last 7 days. Severity scales with tier. |
| 33 | Identity | `Identity_BreakGlass_Anomaly_Detailed` | Per-identity detail view for BreakGlass Anomaly Summary. |
| 34 | Identity | `Identity_BreakGlass_Anomaly_Summary` | Break-glass emergency access accounts with anomalous sign-in patterns. Detects two opposite problems: (1) Break-glass account used recently (< 30 days) WITHOUT an incident - possible misuse (2) Break-glass account has never been tested OR last test was > 180 days ago Break-glass accounts should only be used in genuine emergencies and tested periodically. Severity: Very High (fixed) - any break-glass anomaly is a critical governance failure. |
| 35 | Identity | `Identity_BreakGlass_SignIn_Detected_Detailed` | Per-identity detail view for BreakGlass SignIn Detected Summary. |
| 36 | Identity | `Identity_BreakGlass_SignIn_Detected_Summary` | Any successful sign-in by an account flagged as a break-glass emergency account. Break-glass accounts are only valid for use during genuine catastrophic failures where normal admin access is unavailable. Every sign-in by a break-glass account must be investigated to confirm it was authorised and justified. This is an operational alert that should trigger an immediate review process. Severity: Very High (fixed) — all break-glass usage is critical regardless of context. |
| 37 | Identity | `Identity_DisabledAccount_ActivePIMAssignment_Detailed` | Per-identity detail view for DisabledAccount ActivePIMAssignment Summary. |
| 38 | Identity | `Identity_DisabledAccount_ActivePIMAssignment_Summary` | Disabled user accounts that still have PIM eligible role assignments active. When an account is disabled (e.g. employee leaving), all role assignments should be removed as part of the offboarding process. An eligible assignment on a disabled account means the account could be re-enabled and immediately used to activate privileged access — a common post-compromise technique. Severity: High (fixed). |
| 39 | Identity | `Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed` | Per-identity detail view for EligibleAdmin LogonTo ExploitableDevice Summary. |
| 40 | Identity | `Identity_EligibleAdmin_LogonTo_ExploitableDevice_Summary` | Users with PIM-eligible Tier 0/1 roles authenticated to devices that have vulnerabilities with known exploits available (isExploitVerified or isInExploitKit). Even if the PIM role is not currently activated, the credential harvested from an exploitable device could be used to activate PIM and gain full admin access. Severity: Very High (fixed) - eligible admin credential on actively exploitable device. |
| 41 | Identity | `Identity_ExternalUser_PrivilegedRole_Detailed` | Per-identity detail view for ExternalUser PrivilegedRole Summary. |
| 42 | Identity | `Identity_ExternalUser_PrivilegedRole_Summary` | External/B2B guest users with Tier 0/1 Entra ID roles. External identities should never hold privileged directory roles. Their accounts are governed by their home tenant's security posture which may be significantly lower than yours. A compromised partner account with Global Admin in your tenant is a catastrophic risk. |
| 43 | Identity | `Identity_HighMDIInvestigationPriority_Detailed` | Per-identity detail view for HighMDIInvestigationPriority Summary. |
| 44 | Identity | `Identity_HighMDIInvestigationPriority_Summary` | Active accounts with MDI Investigation Priority Percentile in the top 10% (MDI_InvestigationPriorityPct >= 90). MDI calculates this score based on observed anomalous behaviours, lateral movement signals, unusual access patterns, and UEBA risk scoring. A high investigation priority means MDI has observed behaviour that warrants review. When this is combined with a privileged identity, it represents a potentially active threat that requires immediate attention. Severity: High (fixed). |
| 45 | Identity | `Identity_HighValueTarget_MDIRisk_Detailed` | Per-identity detail view for HighValueTarget MDIRisk Summary. |
| 46 | Identity | `Identity_HighValueTarget_MDIRisk_Summary` | Identities flagged by Microsoft Defender for Identity as high or critical risk, cross-referenced with our asset tier classification. MDI risk signals include observed lateral movement, credential exposure, anomalous behaviour, and UEBA scoring. When a Tier 0/1 identity has elevated MDI risk, it indicates an active or recent threat that requires immediate investigation. |
| 47 | Identity | `Identity_MultiTenant_HighPermission_SPN_Detailed` | Per-identity detail view for MultiTenant HighPermission SPN Summary. |
| 48 | Identity | `Identity_MultiTenant_HighPermission_SPN_Summary` | Multi-tenant service principals (accessible from external tenants) with Tier 0/1 permissions. Multi-tenant apps expose credentials and permissions to external party control. If a partner tenant is compromised, the SPN can be leveraged to attack your tenant with full privileges. |
| 49 | Identity | `Identity_NewAccount_ImmediateTier0Role_Detailed` | Per-identity detail view for NewAccount ImmediateTier0Role Summary. |
| 50 | Identity | `Identity_NewAccount_ImmediateTier0Role_Summary` | User accounts created within the last 24 hours that already have a Tier 0 Entra ID role assigned. In a healthy environment, newly created accounts go through a provisioning workflow and role assignments require approval. Immediate Tier 0 role on a brand-new account indicates either a provisioning process bypass, a compromised privileged account creating rogue admin accounts, or a misconfigured automation script with excessive initial permissions. Severity: Very High (fixed) — immediate Tier 0 access on new account. |
| 51 | Identity | `Identity_PasswordNeverExpires_Privileged_Detailed` | Per-identity detail view for PasswordNeverExpires Privileged Summary. |
| 52 | Identity | `Identity_PasswordNeverExpires_Privileged_Summary` | Privileged accounts with password-never-expires flag set. While passwordless and MFA mitigate this, a non-expiring password on a privileged account means a compromised credential remains valid indefinitely. Combined with no MFA or stale sign-in, this represents a critical unmanaged risk. |
| 53 | Identity | `Identity_PermanentPrivilegedRole_Detailed` | Per-identity detail view for PermanentPrivilegedRole Summary. |
| 54 | Identity | `Identity_PermanentPrivilegedRole_Summary` | Privileged users with permanent (non-PIM) role assignments. Best practice requires all Tier 0/1 roles to be assigned via PIM (just-in-time) to reduce the standing attack surface. Permanent assignments mean the role is always active, even when not in use, providing a persistent target for attackers. |
| 55 | Identity | `Identity_PIM_DuplicateRoleAssignment_Detailed` | Per-identity detail view for PIM DuplicateRoleAssignment Summary. |
| 56 | Identity | `Identity_PIM_DuplicateRoleAssignment_Summary` | Users who have the same Entra ID role assigned both permanently AND as PIM eligible. This is a misconfiguration: the permanent assignment makes the PIM eligible one redundant and indicates the PIM policy was not followed. The permanent assignment should be removed and only the PIM eligible retained. Severity: Medium-High (fixed) - redundant permanent assignment defeats PIM purpose. |
| 57 | Identity | `Identity_PIM_EligibleNeverActivated_Detailed` | Per-identity detail view for PIM EligibleNeverActivated Summary. |
| 58 | Identity | `Identity_PIM_EligibleNeverActivated_Summary` | Users with PIM-eligible Tier 0/1 role assignments that have never been activated (no interactive sign-in with the role active). Eligible roles that are never used suggest the assignment is unnecessary and should be removed to reduce blast radius. This also applies to identities with eligible roles but no sign-in at all. Severity: Medium (fixed) - eligible roles are safer than permanent but unused assignments still represent unnecessary standing access that should be cleaned up. |
| 59 | Identity | `Identity_PrivilegedSPN_NoLogin180Days_Detailed` | Per-SPN/MI detail for privileged workloads inactive for 180+ days. Includes permission details, credential info, and owner status. |
| 60 | Identity | `Identity_PrivilegedSPN_NoLogin180Days_Summary` | Service Principals and Managed Identities with Tier 0/1 permissions (high-privilege app roles or directory roles) that have not authenticated for 180+ days. Dormant privileged workload identities are attractive targets as they may retain permissions long after the business use case has ended. |
| 61 | Identity | `Identity_PrivilegedUser_BruteForceSuccess_Detailed` | Per-identity detail view for PrivilegedUser BruteForceSuccess Summary. |
| 62 | Identity | `Identity_PrivilegedUser_BruteForceSuccess_Summary` | Privileged accounts (Tier 0/1) where multiple failed sign-in attempts were followed by a successful sign-in within a 1-hour window. This pattern is consistent with password spraying or brute-force attack that succeeded. Even with MFA, a brute-forced account can be used to trigger MFA fatigue. A confirmed brute-force success on a privileged account is one of the highest risk signals available from sign-in logs. Severity: Very High (fixed). |
| 63 | Identity | `Identity_PrivilegedUser_ImpossibleTravel_Detailed` | Per-identity detail view for PrivilegedUser ImpossibleTravel Summary. |
| 64 | Identity | `Identity_PrivilegedUser_ImpossibleTravel_Summary` | Privileged users with successful sign-ins from two or more different countries within a 4-hour window — physically impossible travel time. Impossible travel is one of the highest-confidence signals for account compromise, as it is not explainable by VPN (VPN would show consistent exit country) or time zones. Any impossible travel on a Tier 0 identity should be treated as an active incident. Severity: Very High (fixed). |
| 65 | Identity | `Identity_PowerUser_NoMFA_Detailed` | Per-user detail for the PowerUser NoMFA Summary -- one row per Tier 2 user with no MFA registration. Includes department / job title / on-prem-sync state / last sign-in / Entra role memberships so the SOC can prioritise outreach. |
| 66 | Identity | `Identity_PowerUser_NoMFA_Summary` | Power users (Tier 2) with no MFA registration. Tier 2 covers intermediate-sensitivity accounts -- business owners, app owners, finance, HR, developers with elevated app access -- where a single-credential compromise can pivot into sensitive business data even without classic admin roles. Excludes guest / B2B (handled separately) and accounts younger than 7 days (provisioning grace period). |
| 71 | Identity | `Identity_PrivilegedUser_NoMFA_Detailed` | Detailed view of privileged users (Tier 0/1) with no MFA registration. Per-user record with role details, last sign-in, and tier information. |
| 72 | Identity | `Identity_PrivilegedUser_NoMFA_Summary` | Identifies privileged users (Tier 0/1) who have not registered any MFA method. A privileged account without MFA is a single-credential compromise away from full domain/tenant takeover. Excludes accounts created within the last 7 days (grace period for new provisioning). |
| 73 | Identity | `Identity_RegularUser_NoMFA_Detailed` | Per-user detail for the RegularUser NoMFA Summary -- one row per Tier 3 user with no MFA registration. Volume is typically high here; sort + filter in Excel by department / last-sign-in / on-prem-sync state to scope rollout campaigns. |
| 74 | Identity | `Identity_RegularUser_NoMFA_Summary` | Regular users (Tier 3) with no MFA registration. While individual impact is lower than for privileged or power users, regular users without MFA are the most common initial-access vector in phishing + password-spray campaigns. Volume here often dwarfs the higher tiers; even a single compromised regular user is a foothold for lateral movement, internal phishing, and BEC. Excludes guest / B2B (handled separately) and accounts younger than 7 days (provisioning grace period). |
| 71 | Identity | `Identity_PrivilegedUser_SignIn_HighRiskCountry_Detailed` | Per-identity detail view for PrivilegedUser SignIn HighRiskCountry Summary. |
| 72 | Identity | `Identity_PrivilegedUser_SignIn_HighRiskCountry_Summary` | Privileged users (Tier 0/1) who have successfully signed in from countries classified as high-risk (outside expected operational countries). The country list should be tuned to your organisation's footprint. Admin sign-ins from unexpected countries are a strong indicator of credential compromise, VPN circumvention, or use of a third-party device in a foreign location. Severity: Very High (fixed). |
| 73 | Identity | `Identity_PrivilegedUser_SignIn_NonTrustedLocation_Detailed` | Per-user detail: privileged accounts with non-trusted location sign-ins. Shows sign-in count, IPs, countries, and last occurrence. |
| 74 | Identity | `Identity_PrivilegedUser_SignIn_NonTrustedLocation_Summary` | Privileged users (Tier 0/1) who have successfully signed in from a network location that is NOT defined as a trusted named location in Conditional Access. Admin accounts should only authenticate from managed, trusted networks (corporate VPN, PAW networks, known office IPs). Sign-in from an untrusted location on a privileged account is a strong indicator of credential compromise, policy bypass, or an admin using personal devices/networks for privileged tasks. Severity: Very High (fixed). |
| 75 | Identity | `Identity_PrivilegedUser_StalePassword_Detailed` | Per-identity detail view for PrivilegedUser StalePassword Summary. |
| 76 | Identity | `Identity_PrivilegedUser_StalePassword_Summary` | Privileged accounts whose password has not been changed in over 365 days. Long-lived passwords increase the window of exploitation if credentials were exposed in a breach that was never detected. Applies to accounts where password authentication is still a factor (non-passwordless-only accounts). |
| 77 | Identity | `Identity_ServiceAccount_InteractiveSignIn_Detailed` | Per-identity detail view for ServiceAccount InteractiveSignIn Summary. |
| 78 | Identity | `Identity_ServiceAccount_InteractiveSignIn_Summary` | Accounts classified by MDI as service accounts (MDI_IsServiceAccount = true) that have interactive human sign-ins recorded in SigninLogs. Service accounts should authenticate exclusively via non-interactive flows (daemon credentials, managed identity, service principal). Interactive logins indicate the service account credentials are being used by a human — either a shared password problem, a developer using service credentials to bypass controls, or a threat actor who harvested the credentials and is performing hands-on-keyboard activity. Severity: High (fixed). |
| 79 | Identity | `Identity_ServiceAccount_SignIn_NonTrustedLocation_Detailed` | Per-identity detail view for ServiceAccount SignIn NonTrustedLocation Summary. |
| 80 | Identity | `Identity_ServiceAccount_SignIn_NonTrustedLocation_Summary` | Accounts classified as service accounts by MDI (MDI_IsServiceAccount = true) that have successfully authenticated from non-trusted network locations. Service accounts are expected to authenticate exclusively from known, trusted infrastructure (application servers, automation agents). Authentication from an untrusted location strongly suggests the service account credentials have been harvested and are being used by a threat actor. Severity: High (fixed). |
| 81 | Identity | `Identity_ShadowAdmin_Detailed` | Per-identity detail view for ShadowAdmin Summary. |
| 82 | Identity | `Identity_ShadowAdmin_Summary` | Users classified as shadow admins: they hold Tier 0/1 AD group membership (e.g. Domain Admins inherited via group nesting) but have no visible Entra ID role assignments. These accounts exercise privileged AD access that may not be tracked by standard Entra ID governance tooling, creating a blind spot in access reviews and PIM coverage. |
| 83 | Identity | `Identity_SPN_AppRoleAssignmentWrite_Detailed` | Per-identity detail view for SPN AppRoleAssignmentWrite Summary. |
| 84 | Identity | `Identity_SPN_AppRoleAssignmentWrite_Summary` | Service Principals with AppRoleAssignment.ReadWrite.All permission. This allows the SPN to grant any Graph application permission to any other SPN, including granting itself Global Admin-equivalent permissions such as RoleManagement.ReadWrite.Directory or Directory.ReadWrite.All. A compromised SPN with this permission can bootstrap full tenant takeover in two API calls: grant itself dangerous permissions, then use them. Severity: Very High (fixed). |
| 85 | Identity | `Identity_SPN_ExpiringCredentials_Detailed` | Per-identity detail view for SPN ExpiringCredentials Summary. |
| 86 | Identity | `Identity_SPN_ExpiringCredentials_Summary` | Service Principals with client secrets or certificates that have expired or will expire within 30 days. Expired credentials cause service outages. Credentials expiring on privileged SPNs are especially urgent as emergency secret rotation under pressure increases risk of mistakes or insecure handling. |
| 87 | Identity | `Identity_SPN_MailboxAccess_Detailed` | Per-identity detail view for SPN MailboxAccess Summary. |
| 88 | Identity | `Identity_SPN_MailboxAccess_Summary` | Service Principals with mailbox-level Microsoft Graph permissions (Mail.ReadWrite, Mail.Send, MailboxSettings.ReadWrite or equivalent). These permissions allow an app to read all email in the organisation or send as any user - a high-value target for data exfiltration and business email compromise (BEC). SPNs with mailbox access and no active usage are especially concerning. |
| 89 | Identity | `Identity_SPN_Orphan_NoOwner_Detailed` | Per-identity detail view for SPN Orphan NoOwner Summary. |
| 90 | Identity | `Identity_SPN_Orphan_NoOwner_Summary` | Service Principals with no registered owner. Ownerless SPNs have no accountability for credential rotation, permission review, or decommissioning. Privileged orphaned SPNs are critical: no one is responsible for monitoring or revoking access. |
| 91 | Identity | `Identity_SPN_OverCredentialed_Detailed` | Per-identity detail view for SPN OverCredentialed Summary. |
| 92 | Identity | `Identity_SPN_OverCredentialed_Summary` | Service Principals that have both a client secret AND a certificate registered. Over-credentialed SPNs increase the credential attack surface - two different authentication paths must both be managed and rotated. Often indicates legacy credentials were not cleaned up when the SPN was migrated to certificate auth. Severity: Medium (fixed). |
| 93 | Identity | `Identity_SPN_PrivilegedAccessWrite_Detailed` | Per-identity detail view for SPN PrivilegedAccessWrite Summary. |
| 94 | Identity | `Identity_SPN_PrivilegedAccessWrite_Summary` | Service Principals with PrivilegedAccess.ReadWrite.AzureAD permission. This allows the SPN to directly create, modify, or remove PIM role eligibility and assignment schedules. A compromised SPN with this permission can make any account permanently eligible for Global Administrator with no approval workflow, or remove existing PIM assignments to cover tracks. Severity: Very High (fixed) — direct PIM manipulation capability. |
| 95 | Identity | `Identity_SPN_RoleManagementWrite_Detailed` | Per-identity detail view for SPN RoleManagementWrite Summary. |
| 96 | Identity | `Identity_SPN_RoleManagementWrite_Summary` | Service Principals with the RoleManagement.ReadWrite.Directory Graph permission. This permission allows the SPN to assign ANY Entra ID role to ANY principal, including Global Administrator. A compromised SPN with this permission can immediately elevate any account to full tenant administrator — the equivalent of a skeleton key to the entire Entra ID tenant. This is arguably the most dangerous single Graph permission that exists. Severity: Very High (fixed). |
| 97 | Identity | `Identity_SPN_UnverifiedPublisher_HighPermission_Detailed` | Per-identity detail view for SPN UnverifiedPublisher HighPermission Summary. |
| 98 | Identity | `Identity_SPN_UnverifiedPublisher_HighPermission_Summary` | Service Principals with Tier 0/1 permissions whose publisher has not been verified by Microsoft. Unverified publishers are anonymous — there is no accountability for the code running in your tenant. High-privilege unverified apps represent a supply chain risk: the app developer could push malicious updates, and there is no way to validate the publisher's identity or intent. Severity: High (fixed). |
| 99 | Identity | `Identity_StaleGuest_NoLogin90Days_Detailed` | Per-identity detail view for StaleGuest NoLogin90Days Summary. |
| 100 | Identity | `Identity_StaleGuest_NoLogin90Days_Summary` | B2B guest/external collaborator accounts with no sign-in for 90+ days. Guests have a shorter stale threshold than internal users as they represent external access that should be regularly re-validated. Stale guest accounts are a common vector for supply chain and partner-related compromises. |
| 101 | Identity | `Identity_StaleUser_NoLogin180Days_Detailed` | Per-user detail for enabled accounts with no sign-in for 180+ days. Excludes guest/B2B. Includes last sign-in dates, role details, and tier. |
| 102 | Identity | `Identity_StaleUser_NoLogin180Days_Summary` | Enabled user accounts with no interactive or non-interactive sign-in for 180+ days. Excludes guest/B2B accounts (handled separately). Stale privileged accounts are particularly dangerous as they may be forgotten but still retain active permissions. |
| 103 | Identity | `Identity_TooManyGlobalAdmins_Detailed` | Per-identity detail view for TooManyGlobalAdmins Summary. |
| 104 | Identity | `Identity_TooManyGlobalAdmins_Summary` | Detects when the organisation has more than 5 active Global Administrator accounts. Microsoft recommends 2-5 Global Admins maximum. Each additional Global Admin increases the attack surface proportionally. Organisations with 10+ Global Admins typically have role assignment hygiene problems and lack a formal review process. Severity: High (fixed) - excessive Global Admin count is always a significant risk. |

#### Risk Analysis — 2 Locked report templates (orchestrators)

Templates bundle multiple reports into one launcher run (the Summary / Detailed flavours).

| # | Template name | Includes | Purpose |
|---:|---|---:|---|
| 1 | `RiskAnalysis_Detailed_Bucket` | 50 | Detailed |
| 2 | `RiskAnalysis_Summary_Bucket` | 50 | Overview |

#### Critical Asset Tagging — 180 Locked detection rules

Tier / excluded marker is encoded in the tag name as the suffix `--tier<N>--SI` or `--excluded--SI`. Stem = everything before that suffix (Custom overrides match by stem).

| # | Tag name | Tier | Mode | Engine |
|---:|---|:-:|:-:|:-:|
| 1 | `DomainControllerDNS--tier0--SI` | 0 | Prod | DefenderGraph |
| 2 | `ADCertificateService--tier0--SI` | 0 | Prod | DefenderGraph |
| 3 | `EntraSyncService--tier0--SI` | 0 | Prod | DefenderGraph |
| 4 | `AzHubPlatformManagementSub--tier0--SI` | 0 | Test | AzureResourceGraph |
| 5 | `AzHubPlatformManagementResources--tier0--SI` | 0 | Test | AzureResourceGraph |
| 6 | `AzHubPlatformSecuritySub--tier0--SI` | 0 | Test | AzureResourceGraph |
| 7 | `AzHubPlatformSecurityResources--tier0--SI` | 0 | Test | AzureResourceGraph |
| 8 | `AzLZDatacenterSub--tier0--SI` | 0 | Test | AzureResourceGraph |
| 9 | `AzLZDatacenterSub--tier1--SI` | 1 | Test | AzureResourceGraph |
| 10 | `AutomationServer--tier0--SI` | 0 | Test | DefenderGraph |
| 11 | `ServerBusinessServices--tier2--SI` | 2 | Test | DefenderGraph |
| 12 | `PAWDevices--tier0--SI` | 0 | Test | DefenderGraph |
| 13 | `Network_Backbone_Switch--tier0--SI` | 0 | Test | DefenderGraph |
| 14 | `Network_Backbone_Router--tier0--SI` | 0 | Test | DefenderGraph |
| 15 | `Network_Backbone_Management--tier0--SI` | 0 | Test | DefenderGraph |
| 16 | `Network_WLANAccessPoint--tier2--SI` | 2 | Test | DefenderGraph |
| 17 | `Temp-Client-Devices--excluded--SI` | excl. | Test | DefenderGraph |
| 18 | `EmployeeWorkstations--tier3--SI` | 3 | Test | DefenderGraph |
| 19 | `EmployeeMobile--tier3--SI` | 3 | Test | DefenderGraph |
| 20 | `IoT--tier3--SI` | 3 | Test | DefenderGraph |
| 21 | `ADFederationService--tier0--SI` | 0 | Test | DefenderGraph |
| 22 | `PTAAuthBroker--tier0--SI` | 0 | Test | DefenderGraph |
| 23 | `SecurityMgmtServer--tier1--SI` | 1 | Test | DefenderGraph |
| 24 | `HypervisorHost--tier0--SI` | 0 | Test | DefenderGraph |
| 25 | `AzKeyVaultHSM--tier0--SI` | 0 | Test | AzureResourceGraph |
| 26 | `AzManagedHSM--tier0--SI` | 0 | Test | AzureResourceGraph |
| 27 | `AzureADDS--tier0--SI` | 0 | Test | AzureResourceGraph |
| 28 | `EndpointMgmtAdminServer--tier1--SI` | 1 | Test | DefenderGraph |
| 29 | `RADIUSNPSServer--tier1--SI` | 1 | Test | DefenderGraph |
| 30 | `BackupMgmtServer--tier0--SI` | 0 | Test | DefenderGraph |
| 31 | `PatchMgmtServer--tier1--SI` | 1 | Test | DefenderGraph |
| 32 | `FirewallProxyMgmt--tier1--SI` | 1 | Test | DefenderGraph |
| 33 | `SSOGatewayOAuthBroker--tier1--SI` | 1 | Test | DefenderGraph |
| 34 | `PrintSpoolerElevated--tier1--SI` | 1 | Test | DefenderGraph |
| 35 | `AzProductionDatabase--tier2--SI` | 2 | Test | AzureResourceGraph |
| 36 | `AzAPIManagement--tier1--SI` | 1 | Test | AzureResourceGraph |
| 37 | `AzBackupVault_Production--tier1--SI` | 1 | Test | AzureResourceGraph |
| 38 | `AzProductionAppService--tier2--SI` | 2 | Test | AzureResourceGraph |
| 39 | `AzApplicationGateway--tier1--SI` | 1 | Test | AzureResourceGraph |
| 40 | `AzDevTestVM--tier2--SI` | 2 | Test | AzureResourceGraph |
| 41 | `InternalWikiDocServer--tier3--SI` | 3 | Test | DefenderGraph |
| 42 | `KioskSharedTerminal--tier3--SI` | 3 | Test | DefenderGraph |
| 43 | `SharedKioskMobile--tier3--SI` | 3 | Test | DefenderGraph |
| 44 | `AzKeyVaultRootCA--tier0--SI` | 0 | Test | AzureResourceGraph |
| 45 | `AzImmutableStorageIdentity--tier0--SI` | 0 | Test | AzureResourceGraph |
| 46 | `AzKeyVaultHighActivity--tier1--SI` | 1 | Test | AzureResourceGraph |
| 47 | `AzAutomationRunbook--tier1--SI` | 1 | Test | AzureResourceGraph |
| 48 | `AzNetworkSecurityControlPlane--tier1--SI` | 1 | Test | AzureResourceGraph |
| 49 | `AzDevTestSubscription--tier2--SI` | 2 | Test | AzureResourceGraph |
| 50 | `AzDevTestResourceGroup--tier2--SI` | 2 | Test | AzureResourceGraph |
| 51 | `AzAVDSessionHost--tier2--SI` | 2 | Test | AzureResourceGraph |
| 52 | `AzPersonalSandboxResource--tier2--SI` | 2 | Test | AzureResourceGraph |
| 53 | `AzSandboxSubscription--tier3--SI` | 3 | Test | AzureResourceGraph |
| 54 | `AzPoCPilotWorkload--tier3--SI` | 3 | Test | AzureResourceGraph |
| 55 | `AzLabResourceGroup--tier3--SI` | 3 | Test | AzureResourceGraph |
| 56 | `Identity_EntraGlobalAdmin--tier0--SI` | 0 | Test | DefenderGraph |
| 57 | `Identity_SPNGraphPerms--tier0--SI` | 0 | Test | DefenderGraph |
| 58 | `Identity_ADGroupMember--tier0--SI` | 0 | Test | DefenderGraph |
| 59 | `Identity_DCSync_DnsAdmin_Rights--tier0--SI` | 0 | Test | DefenderGraph |
| 60 | `Identity_CriticalServiceAccount_krbtgt--tier0--SI` | 0 | Test | DefenderGraph |
| 61 | `Identity_BreakGlassAccount--tier0--SI` | 0 | Test | DefenderGraph |
| 62 | `Identity_EntraConnectSyncAccount--tier0--SI` | 0 | Test | DefenderGraph |
| 63 | `Identity_DeviceWithGlobalAdminTokenCache--tier0--SI` | 0 | Test | DefenderGraph |
| 64 | `Identity_EntraRole--tier1--SI` | 1 | Test | DefenderGraph |
| 65 | `Identity_SPNGraphPerms--tier1--SI` | 1 | Test | DefenderGraph |
| 66 | `Identity_ADGroupMember--tier1--SI` | 1 | Test | DefenderGraph |
| 67 | `Identity_FederatedCredentialHighPrivApp--tier1--SI` | 1 | Test | DefenderGraph |
| 68 | `Identity_EntraRole--tier2--SI` | 2 | Test | DefenderGraph |
| 69 | `Identity_SPNGraphPerms--tier2--SI` | 2 | Test | DefenderGraph |
| 70 | `Identity_DNSAdminsGroupMember--tier2--SI` | 2 | Test | DefenderGraph |
| 71 | `Identity_ScopedHighPrivSPN--tier2--SI` | 2 | Test | DefenderGraph |
| 72 | `Identity_AzDevOpsServiceConnection--tier2--SI` | 2 | Test | AzureResourceGraph |
| 73 | `Identity_StandardUserAccount--tier3--SI` | 3 | Test | DefenderGraph |
| 74 | `Identity_GuestAccount--tier3--SI` | 3 | Test | DefenderGraph |
| 75 | `Identity_ManagedIdentityNoRBAC--tier3--SI` | 3 | Test | DefenderGraph |
| 76 | `Identity_DisabledExpiredSPN--tier3--SI` | 3 | Test | DefenderGraph |
| 77 | `ITDeptClientPC--tier1--SI` | 1 | Test | DefenderGraph |
| 78 | `DeveloperWorkstation--tier2--SI` | 2 | Test | DefenderGraph |
| 79 | `ReadOnlyDomainController--tier0--SI` | 0 | Test | DefenderGraph |
| 80 | `KMSServer--tier0--SI` | 0 | Test | DefenderGraph |
| 81 | `vCenterSCVMMServer--tier0--SI` | 0 | Test | DefenderGraph |
| 82 | `OOBMgmt_iDRAC_iLO_IPMI--tier0--SI` | 0 | Test | DefenderGraph |
| 83 | `NetworkMgmtServer--tier0--SI` | 0 | Test | DefenderGraph |
| 84 | `SDWANController--tier0--SI` | 0 | Test | DefenderGraph |
| 85 | `AuthLoadBalancer--tier0--SI` | 0 | Test | DefenderGraph |
| 86 | `IoT_OT_DomainIntegrated--tier0--SI` | 0 | Test | DefenderGraph |
| 87 | `JumpServerBastionHost--tier1--SI` | 1 | Test | DefenderGraph |
| 88 | `ExchangeMessagingServer--tier1--SI` | 1 | Test | DefenderGraph |
| 89 | `SecretMgmtServer--tier1--SI` | 1 | Test | DefenderGraph |
| 90 | `NACServer--tier1--SI` | 1 | Test | DefenderGraph |
| 91 | `VPNConcentrator--tier1--SI` | 1 | Test | DefenderGraph |
| 92 | `InternalDNSResolver--tier1--SI` | 1 | Test | DefenderGraph |
| 93 | `DHCPServer_DomainIntegrated--tier1--SI` | 1 | Test | DefenderGraph |
| 94 | `NTPPrimaryServer--tier1--SI` | 1 | Test | DefenderGraph |
| 95 | `PrivilegedDeveloperMachine--tier1--SI` | 1 | Test | DefenderGraph |
| 96 | `Network_DistributionSwitch--tier1--SI` | 1 | Test | DefenderGraph |
| 97 | `Network_WirelessLANController--tier1--SI` | 1 | Test | DefenderGraph |
| 98 | `Network_SSLInspectionProxy--tier1--SI` | 1 | Test | DefenderGraph |
| 99 | `IoT_OT_Industrial--tier1--SI` | 1 | Test | DefenderGraph |
| 100 | `SOCAnalystWorkstation--tier1--SI` | 1 | Test | DefenderGraph |
| 101 | `CommonServiceServer--tier2--SI` | 2 | Test | DefenderGraph |
| 102 | `DevOpsCICDBuildAgent--tier2--SI` | 2 | Test | DefenderGraph |
| 103 | `PowerUserWorkstation_FinLegalHR--tier2--SI` | 2 | Test | DefenderGraph |
| 104 | `Network_AccessSwitch--tier2--SI` | 2 | Test | DefenderGraph |
| 105 | `Network_VoIPSIPGateway--tier2--SI` | 2 | Test | DefenderGraph |
| 106 | `IoT_OfficeEnv--tier2--SI` | 2 | Test | DefenderGraph |
| 107 | `LowImpactInfraServer--tier3--SI` | 3 | Test | DefenderGraph |
| 108 | `Network_UnmanagedLowTrust--tier3--SI` | 3 | Test | DefenderGraph |
| 109 | `IoT_Consumer--tier3--SI` | 3 | Test | DefenderGraph |
| 110 | `BYODPersonalDevice--tier3--SI` | 3 | Test | DefenderGraph |
| 111 | `AzVMWorkload--tier0--SI` | 0 | Test | AzureResourceGraph |
| 112 | `AzBastionHost--tier0--SI` | 0 | Test | AzureResourceGraph |
| 113 | `AzStorageData--tier0--SI` | 0 | Test | AzureResourceGraph |
| 114 | `AzFirewall_CentralHub--tier0--SI` | 0 | Test | AzureResourceGraph |
| 115 | `AzExpressRouteCircuit--tier0--SI` | 0 | Test | AzureResourceGraph |
| 116 | `AzPrivateDNSZone--tier0--SI` | 0 | Test | AzureResourceGraph |
| 117 | `AzVPNGateway--tier0--SI` | 0 | Test | AzureResourceGraph |
| 118 | `AzSentinelWorkspace--tier0--SI` | 0 | Test | AzureResourceGraph |
| 119 | `AzLogAnalytics--tier0--SI` | 0 | Test | AzureResourceGraph |
| 120 | `AzDevOpsConnection--tier0--SI` | 0 | Test | AzureResourceGraph |
| 121 | `AzDedicatedHost--tier0--SI` | 0 | Test | AzureResourceGraph |
| 122 | `AzVMWorkload--tier1--SI` | 1 | Test | AzureResourceGraph |
| 123 | `AzAKS_PrivilegedWorkload--tier1--SI` | 1 | Test | AzureResourceGraph |
| 124 | `AzStorage_SIEMSecrets--tier1--SI` | 1 | Test | AzureResourceGraph |
| 125 | `AzFrontDoor--tier1--SI` | 1 | Test | AzureResourceGraph |
| 126 | `AzLoadBalancer--tier1--SI` | 1 | Test | AzureResourceGraph |
| 127 | `AzDNSResolver--tier1--SI` | 1 | Test | AzureResourceGraph |
| 128 | `AzLogAnalytics--tier1--SI` | 1 | Test | AzureResourceGraph |
| 129 | `AzKeyVaultAppSecrets--tier1--SI` | 1 | Test | AzureResourceGraph |
| 130 | `AzLighthouseDelegation_Privileged--tier1--SI` | 1 | Test | AzureResourceGraph |
| 131 | `AzVMWorkload--tier2--SI` | 2 | Test | AzureResourceGraph |
| 132 | `AzAppServicePlan_Internal--tier2--SI` | 2 | Test | AzureResourceGraph |
| 133 | `AzSpokeVNet--tier2--SI` | 2 | Test | AzureResourceGraph |
| 134 | `AzDataStore_AppData--tier2--SI` | 2 | Test | AzureResourceGraph |
| 135 | `AzTrafficMgrCDN--tier2--SI` | 2 | Test | AzureResourceGraph |
| 136 | `AzNonProdWorkload--tier2--SI` | 2 | Test | AzureResourceGraph |
| 137 | `AzVM_LowImpact--tier3--SI` | 3 | Test | AzureResourceGraph |
| 138 | `AzAppService_PublicFacing--tier3--SI` | 3 | Test | AzureResourceGraph |
| 139 | `AzStorage_PublicNonSensitive--tier3--SI` | 3 | Test | AzureResourceGraph |
| 140 | `AzCDN_PublicDNS--tier3--SI` | 3 | Test | AzureResourceGraph |
| 141 | `AzVMScaleSet--tier0--SI` | 0 | Test | AzureResourceGraph |
| 142 | `AzConfidentialCompute--tier0--SI` | 0 | Test | AzureResourceGraph |
| 143 | `AzBlobStorageAuditPipeline--tier0--SI` | 0 | Test | AzureResourceGraph |
| 144 | `AzDDoSProtection--tier0--SI` | 0 | Test | AzureResourceGraph |
| 145 | `AzVNetHub--tier0--SI` | 0 | Test | AzureResourceGraph |
| 146 | `AzNSGSubnet--tier0--SI` | 0 | Test | AzureResourceGraph |
| 147 | `AzAutomation_HighPrivMI--tier0--SI` | 0 | Test | AzureResourceGraph |
| 148 | `AzArcControlPlane--tier0--SI` | 0 | Test | AzureResourceGraph |
| 149 | `AzStackHCI--tier0--SI` | 0 | Test | AzureResourceGraph |
| 150 | `AzContainerApps_Privileged--tier1--SI` | 1 | Test | AzureResourceGraph |
| 151 | `AzBatch_HighPrivMI--tier1--SI` | 1 | Test | AzureResourceGraph |
| 152 | `AzStackHCI--tier1--SI` | 1 | Test | AzureResourceGraph |
| 153 | `AzDedicatedHost--tier1--SI` | 1 | Test | AzureResourceGraph |
| 154 | `AzFileShare_PrivilegedVMs--tier1--SI` | 1 | Test | AzureResourceGraph |
| 155 | `AzB2CTenant_Federated--tier1--SI` | 1 | Test | AzureResourceGraph |
| 156 | `AzVNetHub--tier1--SI` | 1 | Test | AzureResourceGraph |
| 157 | `AzNVA_RoutingInspection--tier1--SI` | 1 | Test | AzureResourceGraph |
| 158 | `AzPrivateEndpoint--tier1--SI` | 1 | Test | AzureResourceGraph |
| 159 | `AzDevOpsPipeline--tier1--SI` | 1 | Test | AzureResourceGraph |
| 160 | `AzUpdateManager--tier1--SI` | 1 | Test | AzureResourceGraph |
| 161 | `AzAutomation_ScopedRunbook--tier1--SI` | 1 | Test | AzureResourceGraph |
| 162 | `AzFunctions_ScopedMI--tier2--SI` | 2 | Test | AzureResourceGraph |
| 163 | `AzLogicApps_LimitedScope--tier2--SI` | 2 | Test | AzureResourceGraph |
| 164 | `AzAKS_WorkerNodes--tier2--SI` | 2 | Test | AzureResourceGraph |
| 165 | `AzStackHCI--tier2--SI` | 2 | Test | AzureResourceGraph |
| 166 | `AzDedicatedHost--tier2--SI` | 2 | Test | AzureResourceGraph |
| 167 | `AzFileShare_StandardWorkload--tier2--SI` | 2 | Test | AzureResourceGraph |
| 168 | `AzAppGateway_NonAuth--tier2--SI` | 2 | Test | AzureResourceGraph |
| 169 | `AzNSG_WorkloadSubnet--tier2--SI` | 2 | Test | AzureResourceGraph |
| 170 | `AzDevOpsPipeline--tier2--SI` | 2 | Test | AzureResourceGraph |
| 171 | `AzKeyVaultAppSecrets--tier2--SI` | 2 | Test | AzureResourceGraph |
| 172 | `AzMonitorAlert_WorkloadScoped--tier2--SI` | 2 | Test | AzureResourceGraph |
| 173 | `AzBackupVault--tier2--SI` | 2 | Test | AzureResourceGraph |
| 174 | `AzLogAnalytics_WorkloadScoped--tier2--SI` | 2 | Test | AzureResourceGraph |
| 175 | `AzContainerInstance_Isolated--tier3--SI` | 3 | Test | AzureResourceGraph |
| 176 | `AzStaticWebApp--tier3--SI` | 3 | Test | AzureResourceGraph |
| 177 | `AzStackHCI_NonProd--tier3--SI` | 3 | Test | AzureResourceGraph |
| 178 | `AzDedicatedHost_Sandbox--tier3--SI` | 3 | Test | AzureResourceGraph |
| 179 | `AzNSG_IsolatedLowTrust--tier3--SI` | 3 | Test | AzureResourceGraph |
| 180 | `AzVirtualWAN_ReadOnly--tier3--SI` | 3 | Test | AzureResourceGraph |



</details>

---
</details>

<a id="video-walkthroughs"></a>

<a id="8-support"></a><a id="support-chapter"></a>
## 📺 8. Video walkthroughs

[⤴ Back to top](#top)

| Topic | Link |
|---|---|
| Summary Excel output | [▶ Watch](https://youtu.be/Txno9r2pJj4) |
| Summary AI output mail | [▶ Watch](https://youtu.be/kFhrkB0KHvg) |
| Detailed Excel output | [▶ Watch](https://youtu.be/kDrWDzOuWos) |
| Collect / Build Risk Analytics (Summary) | [▶ Watch](https://youtu.be/taW7k4uY9Qo) |
| RiskAnalytics Risk Index | [▶ Watch](https://youtu.be/YzPIUqU9vJU) |
| Risk Analytics Queries Locked YAML | [▶ Watch](https://youtu.be/OImndAACTy0) |
| Run Tagging | [▶ Watch](https://youtu.be/erIS68DaaB8) |
| Tagging Custom YAML | [▶ Watch](https://youtu.be/_WzIVRe0YxU) |
| Tagging Locked YAML | [▶ Watch](https://youtu.be/ndTiLZzcl58) |

---

<a id="9-support"></a><a id="support"></a>
## 💬 9. Support

[⤴ Back to top](#top)

| Channel | When |
|---|---|
| **🐛 Bugs / incidents** | [Open a GitHub Issue](https://github.com/KnudsenMorten/SecurityInsight/issues/new) — include the launcher banner (so we know your version), the failing command, and the [STEP] / [ERROR] lines from stdout. |
| **🔧 Pull requests** | Welcome — especially Custom YAML rules from your environment that could promote to Locked, or new risk factors. Fork → branch → PR. |
| **💬 Direct contact** | [mok@mortenknudsen.net](mailto:mok@mortenknudsen.net) — for sensitive reports or commercial engagement. |
| **📰 Blog / announcements** | [mortenknudsen.net](https://mortenknudsen.net) (alias [aka.ms/morten](https://aka.ms/morten)) |
| **📺 YouTube** | [@KnudsenMorten](https://www.youtube.com/@KnudsenMorten) |

---

---

<a id="5-whats-new-v21x-highlights"></a><a id="whats-new-v21x-highlights"></a><a id="whats-new"></a>
## 🆕 10. What's New

[⤴ Back to top](#top)

| Area | Capability | Tag |
|---|---|---|
| 🎯 **Outputs** | JSON sibling of every XLSX (default ON) | v2.1.40 |
| 📊 **Outputs** | Direct ingest to two Log Analytics tables (`SI_RiskAnalysis_Summary_CL` + `_Detailed_CL`) via auto-created DCRs (no manual table provisioning) | v2.1.41 |
| ☁️ **Outputs** | Optional upload of `.xlsx` + `.json` to UNC share OR Azure Storage, type auto-detected, **backup-then-overwrite** semantics so re-runs never lose data | v2.1.42 / v2.1.44 |
| 📧 **Mail routing** | Per-template recipient override in YAML (`Mail_To` / `Mail_SendMail` per `ReportName`) | v2.1.38 |
| 🔐 **Permissions** | New `Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions` admin utility — idempotent, data-driven catalog, supports interactive / SPN+secret / SPN+cert / MI auth | v2.1.32 / v2.1.33 |
| 🧱 **Layered config** | Defaults vs. customer overrides cleanly separated. Customer file is gitignored, never overwritten by an upgrade | v2.1.24 / v2.1.26 |
| 🩹 **Resilience** | MSAL token cache auto-recovery in `Build_Tier_Definitions_JSON_File` — no more silently empty Section B/C tier files | v2.1.34 |
| 🌍 **Multi-sub** | Cross-subscription Defender / Sentinel workspace queries (resource ID embeds the sub — no Set-AzContext required) | v2.1.28 |
| 🚫 **Scope filter** | `$global:SubscriptionNameExcludePatterns` wildcard filter for Azure-side enumeration | v2.1.21 |
| 🏷️ **Banner** | Version-stamped banner across all 40 launcher templates — easy to confirm what's running | v2.1.31 / v2.1.36 |
| 🤖 **Auth log** | `[INFO] Auth method (Graph) : SPN + Secret (clientId=..., tenant=...)` printed on every connect | v2.1.34 |
| 📧 **SMTP fallback** | `$global:SecureCredentialsSMTP` can now be assembled from 9 global-name variants (`SMTPUser/SMTPPassword`, `Mail_SmtpUser/Password`, legacy `Mail_SecurityInsight_Username/Password`, …). Refuses interactive prompt under unattended runs. | v2.1.53 / v2.1.56 |
| 🏗️ **Auto-provision infra** | Ingestion engines self-heal: if Log Analytics workspace / DCE / DCE RG / DCR RG is missing, create it and assign the SecurityInsight SPN the roles it needs. `DceIngestionUri` is auto-resolved from the DCE name (no longer required in the custom file). | v2.1.54 / v2.1.62 |
| 🔀 **Layered defaults** | New **Layer 0** shared-defaults file (`launcher/_lib/SecurityInsight.shared-defaults.ps1`) holds the canonical `$global:WorkspaceName`, `$global:DceName`, `$global:DceResourceGroup`, `$global:DcrResourceGroup`, `$global:Location`, and `$global:SubscriptionId`. Shared by every SI engine; customer overrides on top. | v2.1.55 |
| 🧪 **Launcher mode override** | `$global:RiskAnalysis_Detailed_Override` / `_Summary_Override` lets a launcher flip Summary vs Detailed runs without touching `$global:ReportTemplate`. | v2.1.57 |
| 📬 **Per-template mail (community)** | Community-mode mail now supports the same `RiskAnalysis_Detailed_To` / `_Summary_To` splits as AF mode — falls back to flat `$global:MailTo` when per-template vars aren't set. | v2.1.57 |
| 📦 **IAC JSON + upload** | Identity collection engine now writes a `.json` array sibling of its `.jsonl` stream and optionally uploads both to UNC / Azure Storage (same pattern RiskAnalysis uses). Four unified behaviour globals (`TroubleshootingMode`, `CsaAttributeSet`, `Defender_WorkspaceNameResourceId`, `SubscriptionNameExcludePatterns`) work in both AF and community mode. | v2.1.58 |
| 📁 **Auto-create container** | When `$global:ExportDestination` points at an Azure Storage URL and the container doesn't exist, the upload helper creates it and (best-effort) grants the SPN `Storage Blob Data Contributor` at the container scope. | v2.1.60 |
| 🎯 **Sub-scoped DCE/DCR cache** | `$global:AzDceDetails` / `$global:AzDcrDetails` now filtered to the target subscription, so duplicate-named DCRs in other tenant subs can't poison `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output` (fixes spurious 403 "DCE FQDN not associated with DCR immutable Id"). | v2.1.61 / v2.1.62 |
| 🔑 **SubscriptionId honored** | Both IAC and RiskAnalysis self-heal blocks now read `$global:SubscriptionId` first, parsed from `$WorkspaceResourceId` second, Az context last. Ends the silent "wrong subscription" behaviour when only `$global:WorkspaceName` + `$global:SubscriptionId` are set. | v2.1.59 / v2.1.63 |
| 📋 **OnboardValidate summary** | `Validate-SIPermissions_OnboardValidate-SecurityInsight-Permissions` now emits a final copy-paste-ready summary block (App (client) ID, SPN ObjectId, Tenant ID, counts, ready-to-paste `$global:Spn*` block, verification KQL). | v2.1.64 |
| 🎯 **Deterministic TraceID / TraceName** | Every RiskAnalysis row carries a `TraceName` (e.g. `Update vulnerable software--Very High--Critical - tier 0`) + a SHA-256-derived `TraceID` that stays stable across runs. Group-by TraceID in KQL to track the same finding across time. Separator bumped to `--` so severities containing a hyphen don't collide. | v2.1.88 / v2.1.93 |
| ⏱️ **CollectionTime stamping** | RiskAnalysis ingest pipeline now mirrors the identity engine: `Add-CollectionTimeToAllEntriesInArray` → `Add-ColumnDataToAllEntriesInArray` → `ValidateFix-AzLogAnalyticsTableSchemaColumnNames` → `Build-DataArrayToAlignWithSchema` → `Post-AzLogAnalyticsLogIngestCustomLogDcrDce-Output`. One `CollectionTime` per run, so `\| where CollectionTime == toscalar(...max(CollectionTime))` gives the latest slice. | v2.1.92 |
| 🧮 **`$global:SolutionVersion` on every row** | VERSION.txt walk-up from `$PSScriptRoot`; stamped as a column on both `SI_RiskAnalysis_*_CL` and `SI_IdentityAssets_CL`. Tells you which engine version wrote which batch of rows. Surfaced in the Workbook "Data powered by" footer tile. | v2.1.96 |
| 📊 **Azure Monitor Workbook** | Drop-in workbook template `TOOLS/AzureWorkbook/SecurityInsight-RiskAnalysis.workbook.json` with workspace pill (ARG-backed), time-range, multi-select filters (SecurityDomain / SecuritySeverity / CriticalityTier / Subcategory), trends, velocity (new vs resolved), Top-N, stale findings, identity inventory, Data-powered-by footer. Version badge visible in the GUI. | v2.1.99 / v2.1.106 |
| 📤 **Power BI dataset refresh (community)** | New `$global:SendToPowerBI` toggle in the RiskAnalysis engine; when `$true`, acquires an OAuth2 token via SPN client-credentials and POSTs to the dataset's `/refreshes` endpoint so the customer's Power BI workspace picks up the latest KQL-ingested data on each scheduled run. Paired with a new Deploy-SIPowerBI one-time deploy engine for fully-automated `.pbix` upload + parameter rebind. | v2.1.98 / v2.1.102 |
| 🗂️ **Step folders renumbered 0–4** | Bootstrap is now `Setup-SecurityInsight (Github phase)` (install / update from GitHub); engines are `Validate-SIPermissions` Permissions → `Validate-SILogAnalytics` Log Analytics → `Validate-SIOpenAI` Azure OpenAI → `Deploy-SIPowerBI` Power BI (BETA). Setup Configurator tabs + launcher folder names + docs all aligned. | v2.1.103 |
| 🧰 **Workbook multi-select fix** | Dropdowns now preselect `*` as a synthetic first option (`union (print Col='*'), (<query>)`); KQL guard is `'*' in ({Param}) or Col in ({Param})` so an empty pill never produces `Col in ()` and parse errors on fresh import. | v2.1.107 |
| 📧 **`$global:SMTPFrom` (verified sender)** | Separate the SMTP login username from the `From` header. Brevo / SendGrid / Postmark / M365 all reject mail whose `From` isn't a verified sender — the relay login is NOT a valid `From`. Engine resolves `$SMTPFrom` → `$MailFrom` → `$SMTPUser` (legacy fallback) and throws if all three are empty. Configurator, sample, defaults, and README updated in lock-step. | v2.1.108 |
| 🩹 **Setup-SecurityInsight (Github phase) bootstrap: `iwr -OutFile`, not `irm \| Out-File`** | `Invoke-RestMethod` on PS 5.1 returns a string that includes the UTF-8 BOM as a content character, then `Out-File`'s default Unicode encoding writes a UTF-16 BOM + that stray FEFF — the parser then trips on `[CmdletBinding()]` with "Unexpected attribute". Switch to `Invoke-WebRequest -OutFile` (raw bytes). | v2.1.108 |
| 📦 **One canonical PowerShell module set auto-installed on first run** | `Ensure-SecurityInsightModules` in `_shared/Ensure-Module.ps1` installs `Az`, `Az.ResourceGraph`, `Microsoft.Graph`, `Microsoft.Graph.Beta`, `AzLogDcrIngestPS`, `MicrosoftGraphPS`, `ImportExcel`, `powershell-yaml` — the superset any SI engine could need. Default `-Scope AllUsers` with fail-fast elevation check so installs land machine-wide and are visible to the daily scheduled task SYSTEM account. Directory-first module probe keeps warm-VM checks under 1 second even with 70+ Az.* submodules installed. | v2.1.113 / v2.1.114 / v2.1.122 / v2.1.125 |
| 🗓️ **Daily auto-refresh scheduled task** | New `SCRIPTS/Register-SecurityInsightDailyUpdate.ps1` helper registers a Windows Scheduled Task that runs Step 0 every day at 03:00 as SYSTEM. New Locked YAML + engine code + launcher templates + workbook JSON land automatically while `LauncherConfig.custom.ps1` + `*_Custom.yaml` stay untouched. One-time admin setup, idempotent, `-Unregister` for clean removal. See [§ 3.3.1](#automate-daily-update). | v2.1.116 |
| 🧰 **DCE/DCR cache filter: sub + RG** | `Ensure-SecurityInsightAzDceDcrCache` filters `$global:AzDcrDetails` / `$global:AzDceDetails` by both `-SubscriptionId` and `-DcrResourceGroup` / `-DceResourceGroup`. Stops the module's name-only lookup picking a neighbour DCR in a different RG (manifested as the cryptic `"Data collection rule with immutable Id 'westeurope' not found"` 404 on customer VMs with duplicate-named DCRs across RGs). | v2.1.129 |

---


<sub>Developed by **Morten Knudsen** — Microsoft MVP. Licensed under MIT. PRs welcome.</sub>

[⤴ Back to top](#top)
<!-- public:end -->
