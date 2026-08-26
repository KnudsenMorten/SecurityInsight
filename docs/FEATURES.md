# SecurityInsight — delivered feature catalog

This is the delivered feature set of **SecurityInsight**, written in plain language for IT
admins, security teams and decision-makers. Everything listed here is built and in production
use. It is grouped by area and is safe to share publicly. (Status as of 2026-06-14.)

SecurityInsight turns your Microsoft security telemetry into a **risk-based, prioritized** view
of what to fix first. It profiles every asset (endpoint, identity, Azure resource, public IP),
tiers it by business criticality, scores every finding by consequence × probability, and ships
the result as ranked reports, Log Analytics tables, Excel + an executive email summary, and
optional dashboards — all **read-only**, with no agents and no schema changes to your tenant.

Chapter numbering matches [REQUIREMENTS.md](REQUIREMENTS.md) (the internal backlog) so a feature
keeps its chapter as it moves from planned → delivered.

---

## 1. Risk-based prioritization

- **Risk Score, not just severity.** Every finding gets a Risk Score that combines *consequence*
  (severity) with *probability* (the asset's Tier 0–3 criticality) and amplifying *risk factors*
  (internet exposure, leaked credentials, legacy OS, and more). You fix what an attacker would
  reach for first, not what is alphabetically next on a flat dashboard.
- **Weighted Risk Score for your crown jewels.** When you connect a CMDB, business criticality
  and data sensitivity multiply the score, so the same finding ranks higher on a payroll server
  than on a sandbox — and your Excel sorts the way the business actually cares.
- **A management-friendly KPI.** A single overall Risk Score plus a per-domain breakdown lands in
  the summary email and in Log Analytics, so leadership sees one headline number and the trend
  over time.
- **Customizable scoring matrix.** The consequence/probability index and the per-finding weights
  are plain editable files — tune the scale (1–5 or 1–10), the multipliers, and the CMDB weighting
  to match your own risk appetite without touching code.

## 2. Asset profiling — four engines

- **Endpoints.** Servers are classified dynamically from installed software, detected roles,
  Defender machine-group tags, IP subnet and naming — matched against a built-in catalog of
  500+ known server applications. Clients inherit a tier from the most-privileged users who
  actually log on to them.
- **Identities.** Users, service principals and managed identities are tiered from their
  **actual assigned permissions** — Entra roles, Graph/API permissions, group memberships,
  PIM-eligible roles (including nested PIM-for-Groups chains) — not from static tags. MFA / SSPR /
  passwordless registration posture is captured per identity.
- **Azure resources.** Every resource is profiled from Azure Resource Graph and tags, including
  **parent-inherited tags** (resource → resource group → subscription → management group), so
  criticality flows down the hierarchy automatically.
- **Public IPs.** Internet-facing Tier 0/1 assets are scanned (via Shodan) for open ports and
  CVEs, and the results map straight back to the owning asset with its tier and CMDB context.
- **One queryable table per engine.** Each engine emits a flat, easy-to-query Log Analytics table
  with 700+ fields across all engines — supported-provider data plus calculated fields like Tier,
  resolved API/role permissions, and risk signals. Query them directly, or let Risk Analysis turn
  them into ranked findings.
- **Picks up new telemetry automatically.** New signals (a new Entra/Graph/Azure role, a new
  field like leaked-credential status) flow through without a redeploy; unknown roles are tiered
  by AI on the fly.

- **Excluding a device actually excludes it — and you can see what was excluded.** ✅ 2026-08-12 —
  tagging a device `--Excluded--SI` in the Defender portal now removes it from Risk Analysis, and a
  dedicated report lists every suppressed asset with the exact tag that did it, so an exclusion can
  never quietly hide an asset forever.
- **A failed data source no longer looks like a shrinking estate.** ✅ 2026-08-13 — if a discovery
  source returns nothing, the run says so. Previously your inventory simply got smaller, which is
  indistinguishable from assets genuinely going away.
- **When a device cannot be matched across MDE, Exposure Graph and Entra, the run names it.**
  ✅ 2026-08-12 — conflicting device identifiers are reported per asset with the source that claimed
  each one, instead of the asset silently splitting in two.
- **Reading an exclusion tag can no longer cost you a profiling run.** ✅ 2026-08-12
- **Container runs keep a log.** ✅ 2026-08-13 — runs in containers now write a transcript and upload
  it alongside the VM runs, with the same 30-day retention.

## 3. Dynamic detection & classification

- **100% dynamic, rule-driven detection.** 20+ detection methods (name patterns, installed
  software, detected roles, Azure tags incl. parent inheritance, Entra/AD group membership,
  extension attributes, MDE tags, IP-subnet match, recent-logon windows, and KQL/Graph escape
  hatches) decide an asset's tier and purpose — no manual tagging required.
- **AI-assisted role tiering.** When a Microsoft role or permission isn't in the curated catalog,
  AI evaluates what it actually grants and slots it into Tier 0–3. Off by default; opt-in per
  engine. Identity tiering stays fully rule-driven by design.
- **Fully customizable without forking.** Every detection rule ships "locked" and accepts an
  optional customer override file that survives upgrades — add your own rule, extend a shipped
  one, or disable it, all in plain YAML next to the original.
- **Rules that cannot work are reported, never silently skipped.** ✅ 2026-08-07 — each run names
  any match type the engine does not recognise, with how many detections it affects, and any rule
  that loads with an empty detection block. A mistake in one of your own rules surfaces on the run
  that uses it instead of staying invisible. A rule you deliberately switched off is not flagged —
  suppression is a legitimate reason to have no detections.

- **Your own rules can live outside the folder we update.** ✅ 2026-08-07 — point the engine at your
  own rule directory and updates can never overwrite your work.
- **The example rules we ship are checked before they reach you.** ✅ 2026-08-07 — a broken sample
  propagates by instruction, so shipped samples are now validated in the build.
- **Okta identity servers are tiered, and an SCCM console no longer reports as a site server.**
  ✅ 2026-08-13

## 4. Inputs — supported data providers

- **Read-only, zero footprint.** SecurityInsight reads from Microsoft Defender for Endpoint
  (XDR + advanced hunting), Defender Exposure Graph, Defender for Identity, Entra ID + Microsoft
  Graph, on-prem Active Directory, Azure Resource Graph, Sentinel sign-in logs, and the Defender
  Vulnerabilities KB. No agents, no writes to your tenant during a run.
- **Pluggable provider model.** Data sources are plugins with a simple contract — adding a new
  source is a new folder, not an engine change. Built-in providers cover Entra and a CMDB CSV
  pull; you can write your own.
- **Optional external attack-surface intel.** Shodan adds open-port and CVE data for your public
  IPs.

## 5. Enrichment — joining external context

- **CMDB integration.** Drop a CSV (e.g. exported from ServiceNow) and SecurityInsight folds
  business criticality, data sensitivity, owner and any extra columns onto every matched asset —
  and uses them to weight the Risk Score. A reconciliation pass also reports CMDB items that
  nothing discovered, and discovered assets with no CMDB record.
- **Optional asset write-back to CMDB.** SecurityInsight can push asset mapping back to the CMDB
  when you want it (opt-in).
- **Tenant-specific overlays.** Custom detection rules, custom Profile-table columns, custom Risk
  Index weights, and per-report finding exclusions are all customer-owned overlay files merged at
  load time.

- **CMDB enrichment: one source is in charge, and every row says which.** ✅ 2026-08-11 — criticality
  and data-sensitivity come from a single defined CMDB source per asset, the column names state what
  they mean, and each row records where its CMDB data came from.

## 6. Outputs — pick any combination

- **Excel + executive email.** A ranked XLSX of findings with an optional AI-written executive
  summary as the first sheet, sent to per-report recipients. The top-risky-assets list ranks by
  criticality tier first (Tier 0 at the top), then by weighted Risk Score within tier.
- **Log Analytics tables.** Durable, queryable time-series tables for Profile snapshots, Risk
  Analysis Summary/Detailed findings, and run health.
- **JSON sibling files.** One-line-per-row JSON next to every Excel — a drop-in feed for any other
  SIEM or downstream tool.
- **Azure blob and UNC upload.** Auto-publish each run's output to a blob container or file share,
  with backup-then-overwrite so re-runs never lose data.
- **Power BI dataset refresh** and a pre-built **Azure Monitor Workbook** for visual exploration.
- **Run-health alerting.** A simple KQL alert fires when a run starts but never finishes.

- **Your Risk Analysis data reaches Log Analytics complete.** ✅ 2026-08-08 — every column produced by
  a report is included in the ingest schema, so nothing is dropped between the report and the table.
- **Detailed results land in the Detailed table.** ✅ 2026-08-07 — Detailed and Summary runs are routed
  to their own destinations rather than sharing one.
- **A finished run can no longer be lost at the final write.** ✅ 2026-08-18 — a column-naming clash
  between two reports used to discard a completed run's entire output at the last step. The workbook
  is now written regardless, and the accompanying `.json` and Log Analytics data are unaffected.

## 7. Risk Analysis reports

- **100+ ready-to-use reports** across Identity, Azure, Endpoint and Public IP domains, paired as
  Summary (one row per finding type) and Detailed (one row per affected asset).
- **Attack-path reports built on Exposure Graph.** Cross-domain reports trace credential-driven
  and lateral-movement paths to sensitive data and Tier 0 targets, prioritized by the business
  impact of the final target.
- **Findings carry full context.** Every row includes severity, criticality tier, the risk
  factors that amplified it, the weighted score, CMDB business context, and deep links to the
  Defender / Entra / Azure portal and MITRE ATT&CK.
- **Tunable per tenant.** Add reports, override a shipped report's query, narrow severity/tier
  scope, or exclude specific findings/CVEs/configurations per report — via overlay files.

- **SecurityInsight notices when a report quietly stops finding things.** ✅ 2026-08-10 — every report
  is compared against the previous run and a drop in findings is reported, so a report that breaks
  cannot look like an environment that improved.
- **The engine tells you when a column quietly stops carrying data.** ✅ 2026-08-11
- **Large reports are split so they finish, and both halves of the split stay correct.** ✅ 2026-08-12
  — oversized queries are divided automatically, and the CVE reports now split the work instead of
  computing all of it and discarding most.
- **The excluded-assets report exists in Summary as well as Detailed**, and Summary/Detailed parity is
  enforced so the two views cannot drift apart. ✅ 2026-08-12
- **An impacted-asset count always matches the list printed beside it.** ✅ 2026-08-18

## 8. Severity, criticality & the tier model

- **A clear Tier 0–3 model.** Every asset lands in a tier with a documented meaning (Tier 0 =
  highest-impact / crown-jewel, down to Tier 3 = low impact), driving the probability side of the
  Risk Score and the scope of each report.
- **Traceable verdicts.** Tier decisions are fully introspectable — you can see which signals and
  top matches drove an asset's tier, so the "why" behind every classification is auditable.
- **Compliance-aligned.** The asset inventory + risk-classification model supports NIS2, DORA,
  ISO 27001 and GDPR Art. 32 evidence needs.

## 9. Configuration model

- **Layered config.** Settings resolve through clear layers — shared platform defaults → solution
  defaults → per-engine launcher config → CLI flags — with CLI flags always winning, so a one-off
  run never requires editing files.
- **Locked + custom everywhere.** Schemas, catalogs, detection rules, queries and scoring all ship
  "locked" with an optional gitignored customer override that survives upgrades; a sample file
  ships next to each as a starter.
- **No secrets in config.** Authentication uses an SPN with a certificate, a Key Vault pointer, or
  a managed identity; storage uses OAuth/RBAC by default (no shared key), and customer secrets
  never live in shipped files.

## 10. Setup & onboarding

- **Browser-based Setup Wizard.** A local wizard walks you through tenant identity, workspace +
  ingestion, optional mail/CMDB/OpenAI/Shodan, and output sinks, then provisions the service
  principal, permissions, Log Analytics + DCE + DCRs and storage, and writes your config file —
  no copy/paste.
- **Unattended, JSON-driven setup.** The same provisioning runs headless from a JSON config for
  repeatable, scripted onboarding (Internal and Community flavours).
- **Idempotent and re-runnable.** Every setup phase is safe to re-run; partial completion is fine
  and you can re-run just the failed phase.
- **Least-privilege footprint.** The wizard grants exactly the read scopes the engines need
  (Reader at the management-group root + Contributor on the target subscription, never Owner),
  and soft-fails optional Defender API grants when a tenant isn't licensed for them.

## 11. Hosting & scheduling

- **Run on a VM or in containers.** The same engines run on a plain Windows VM (Task Scheduler) or
  as Azure Container Apps Jobs — pick what fits your environment.
- **Built for large enterprises.** Container Apps Jobs with KEDA queue auto-scaling, plus
  performance machinery (row bucketing to beat the Advanced Hunting row ceiling, fingerprint
  caching, hash caching, per-tier scheduling) keep very large tenants tractable.
- **Recommended cadence built in.** A documented run order (tier catalog → profilers → Risk
  Analysis) with staggered scheduling; Risk Analysis never crashes on stale profile data — it
  reports the prior snapshot time instead.
- **Per-run transcripts + run health.** Every run writes a transcript and a Start/End health row,
  so failed or hung runs are easy to spot.

- **SecurityInsight states which platform version it needs**, and is declared as a code update, so an
  update cannot half-apply. ✅ 2026-08-09

## 12. Performance & scale

- **Bulk-fetch, never per-asset.** All external data is fetched once and indexed; the rule loop is
  pure CPU, so processing thousands of assets doesn't mean thousands of API calls.
- **Self-correcting bucketing.** The engine measures real row sizes and auto-sizes query buckets
  to fit Defender's request limits, escalating intelligently instead of brute-forcing.
- **Empirical, no artificial caps.** Scale tuning is measure-adapt-prune — no arbitrary "max N"
  limits that hide real problems.
- **Shared caches across replicas.** The AI executive summary and top-asset ranking are cached and
  shared across hosts within a freshness window, so parallel Summary and Detailed runs produce
  identical headline conclusions.

- **The workbook is written in one bulk operation, not cell by cell.** ✅ 2026-08-26 — spreadsheet
  libraries normally write one cell at a time, which is fine for a few thousand cells and painful for
  tens of millions: a large Detailed export measured **5 hours 34 minutes**. The whole sheet is now
  handed to the spreadsheet engine in a single call, taking that to a measured **21 minutes** at that exact size with the
  same rows, columns, order, table, filter, frozen header, widths and formatting. Two related wins:
  numbers are passed as numbers rather than converted to text, so on comma-decimal systems a value
  like `9.8` can no longer be misread as `98`; and container runs now produce the same column widths
  as Windows runs instead of falling back to a narrow default.

## 13. Operations & day-2

- **Documented runbook.** Run-health KQL, cadence tuning, cache reset, and a troubleshooting
  table mapping the common Advanced-Hunting / KQL errors to their fix.
- **Latest-snapshot semantics.** Every row carries a consistent collection timestamp so KQL
  always selects one coherent snapshot, even across shards.
- **On-demand rule check that shows its denominator.** ✅ 2026-08-07 — validate your rule tree
  whenever you like; the verdict is printed together with **how many rule files were examined**, so
  a clean result can never mean "looked at nothing". Examining nothing is reported as a failure.

- **Certificate authentication is a first-class path.** ✅ 2026-08-12 — both Risk Analysis API tokens
  and Asset Tagging authenticate with a certificate instead of stopping at a sign-in prompt.
- **Limits announce themselves.** ✅ 2026-08-18 — where a run has to bound what it produces (links in
  a cell, rows in a worksheet, the size of an emailed report) it now states what was left out and
  where the complete data still is, rather than trimming silently.

## 14. Documentation

- **A clear documentation set.** A single design document describes how the system works and this
  catalog describes what it does for you — plus a detailed README front door, curated release notes,
  and video walkthroughs.

---

*Items still in progress or planned are tracked internally in the backlog. Only delivered, in-use
capabilities appear in this catalog.*

## SI Analyzer (SIA)

### Status — nothing is "delivered" yet (by design)

SIA is **built but NOT yet live-verified.** Per the documentation model, a feature is only listed here
once it has passed the **hosted live-verify release gate** — a real hosted run behind Entra SSO against
the real internal SecurityInsight workspace, with AI on, on SIA's own dedicated Azure infrastructure
(see [TESTS.md](TESTS.md) for the exact gate). That run has **not** been executed.

Until it passes, the full SIA capability set — the executive risk view, the risk-over-time timeline, the
AI exec narrative, the board-deck export + scheduled exec email, the analyst worklist, and the read-only
MCP endpoint — is **built and offline-tested** but stays on the **backlog** in
[the shared REQUIREMENTS.md](REQUIREMENTS.md) (`◻`/`🟡`), not claimed as delivered here. The offline xunit suite is
green (216 tests, demo data, AI-off); offline-green is necessary but not sufficient for "delivered".

**When the hosted live-verify gate passes,** each verified capability moves here from REQUIREMENTS.md
(same wording, in customer language, with a delivery date), DESIGN.md is updated, and TESTS.md records the
gate result.

_No features have been promoted to this file yet._
